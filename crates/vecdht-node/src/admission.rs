//! Admission-контроль publish/find (§11.3), вытеснение по достигнутым битам PoW (§11.3.3)
//! и denylist ключа (§11.4, пункт ii).
//!
//! Модуль живёт отдельно от `node` по той же причине, по какой §11.3 переехал на узел: лимиты
//! — это локальная политика приёма, а не протокольное состояние. Ни одно её решение не попадает
//! в WAL, не реплицируется и не меняет байты `InsertOp`. Отсюда два следствия, и оба существенны:
//!
//! * это единственное место, которому разрешено смотреть на `Clock::sec` (§9.6 запрещает такое
//!   в replicated-пути); primary и реплика могут разойтись в секундах и всё равно сойтись в
//!   один индекс;
//! * состояние делится на *узел*, а не на шард: §11.3.4 говорит «100 admits/с на узел», а
//!   процесс держит восемь шардов. Поэтому [`Admission`] живёт в [`SharedAdmission`] и
//!   передаётся всем `ShardNode` одного процесса.
//!
//! ## Порядок проверок — это и есть защита
//!
//! §11.3.5 требует, чтобы опс попадал в durable WAL только после резервирования квоты. В коде
//! это частный случай более общего правила: сначала самая дешёвая проверка и самый дешёвый
//! отказ. Порядок в `handle_publish`: denylist (поиск по множеству) → бакет ключа → verify PoW
//! (один blake3) → узловой бюджет → вместимость шарда → WAL. Если переставить бакет за PoW,
//! узел будет верифицировать работу, которую заведомо не примет; при 16 ядрах и default 20 бит
//! это ~106 проверок/с (§11.4) — немного, но ровно те самые 106/с, ради которых квота и
//! введена.
//!
//! ## Почему таблица ключей ограничена, а не бесконечна
//!
//! Растёт она не от легитимных агентов, а от sybil-флуда. Для publish скорость роста уже
//! ограничена PoW: строка появляется вместе с кадром, а кадр стоит 2^bits хешей под конкретный
//! `owner_ed25519` (§11.1). Для find строка ограничена числом аутентифицированных пиров, то
//! есть соединениями транспорта. Дальше работает правило: бакет, досчитавшийся до потолка,
//! неотличим от отсутствующего ключа, поэтому при переполнении узел забывает именно такие
//! строки — это ровно ничего не меняет в будущих решениях. Активные ключи не вытесняются
//! никогда: забыть ключ с пустым бакетом означало бы подарить ему полный burst, то есть sybil
//! сбрасывал бы собственную квоту переполнением таблицы. Потолок 65 536 строки ≈ 3,7 МБ —
//! это ~20 секунд флуда с 16 ядер с новыми ключами, то есть резервуар на пике, а не на среднем.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use vecdht_wire::constants::CLUSTERS_PER_SHARD;
use vecdht_wire::messages::err_code;

use crate::config::Params;
use crate::net::Addr;

/// Потолок строк per-key бакетов (§11.3.1); см. абзац «почему таблица ограничена».
pub const MAX_TRACKED_PEERS: usize = 65_536;
/// Обход таблицы стоит O(limit), поэтому он отрабатывает не на каждой вставке, а раз в
/// столько вставок: иначе само переполнение стало бы CPU-усилением флуда.
pub const PRUNE_EVERY: usize = 8_192;
/// Сколько дешёвых кандидатов держит [`Evictor`] (§11.3.3). 64 — не «запас», а цена: вытеснение
/// обязано стоить узлу O(log) на publish, а не O(M).
pub const EVICT_RESERVOIR: usize = 64;
/// Живых записей за один пополняющий проход резервуара. 256 — тот же бюджет, что и секундный
/// потолок admission'а (§11.3.4): один publish не обходит больше записей, чем узел принимает за
/// секунду.
pub const EVICT_SCAN_BUDGET: usize = 256;

// Гейт «память узла плоская» (§18.6) начинается с размера таблиц: 65 536 строк по ~56 Б ≈
// 3,7 МБ, и ни байтом больше, независимо от M. Проверка стоит на компиляции, а не в тесте:
// константа, нарушившая бюджет, не должна дожить до прогона.
const _: () = assert!(MAX_TRACKED_PEERS * 56 < 8 << 20);
const _: () = assert!(EVICT_RESERVOIR <= MAX_TRACKED_PEERS);
const _: () = assert!(EVICT_SCAN_BUDGET <= 1_000, "скан на publish не дороже секундного бюджета");

/// Множитель `c` относительного капа ячейки (§14.4 (iv), `ADR-0044` решение 5).
///
/// Это не новая ручка: §8.6 уже требует от балансировки при построении артефакта «cap 2×N/NLIST
/// на кластер», то есть «не больше двух средних». `E-0079` измерил, что на уже принятые записи
/// то правило не влияет вовсе, поэтому `ADR-0044` переносит тот же множитель на приём.
pub const CELL_CAP_NUM: u64 = 2;
/// Пол капа ячейки по умолчанию: самая большая длина ячейки, чью **цену** мы измерили сами.
/// Это дефолт параметра [`Params::cell_cap_min`], а не константа решения: `ADR-0044` требует,
/// чтобы число капа было параметром (форма `⌈c·m/n⌉` при этом одна на всех).
///
/// `E-0079` (debug) и `E-0081` (release) считают лестницу 16…4096; верхняя точка — 4096 записей,
/// 0,05542…0,059815 мкс на запись скана и живой `Find` 1534…1547 мс при 65 ответах против
/// серверного бюджета §12.6 (≤ 50 мс). Нижче измеренной длины кап ставить нельзя: он начал бы
/// вытеснять записи ради размера ячейки, цена которого нам неизвестна. Верхняя граница капа при
/// этом относительная, и на референсном `max_live_per_shard = 2 000 000` она даёт
/// ⌈2·2 000 000/16⌉ = 250 000 записей ≈ 14,95 мс скана — по обе стороны clamp бюджет §12.6
/// держится, и обе ветки опираются на наш замер, а не на чужой.
pub const CELL_CAP_MIN: u64 = 4_096;

/// Верхняя граница `live_in_shard`, ниже которой `CELL_CAP_NUM * live_in_shard` в [`cell_cap_limit`]
/// не переполняет `u64`.
///
/// Числа здесь не «мелочи»: `(2⁶⁴ − 1 − n) / c` при `c = 2`, `n = 16` даёт 9 223 372 036 854 775 799,
/// то есть граница лежит на половине диапазона `u64`, и ни одна реальная конфигурация шарда до неё не
/// доходит (`max_live_per_shard` по умолчанию — 2 000 000). Причина, по которой константа всё-таки
/// названа: до `E-0099` это условие существовало только в комментарии про `m ≤ 1e9`, а умножение
/// в release-профиле переполняется по кольцу, то есть при `live > 2⁶³` кап стал бы МЕНЬШЕ, чем при
/// нулевой загрузке, и ветка `.max(min)` уже не спасала бы. Verus поймал это как недоказуемый
/// пост-условием `cap >= min` случай (`lab/proofs/verus/cap_math.rs`, снятое `requires` даёт
/// `errors=1`) — предпосылка была не задокументирована, а не выполнена.
///
/// Граница сознательно на один шаг уже острой (`live ≤ (2⁶⁴ − 16) / 2`) — ровно как предпосылка
/// `requires` в Verus-модели `lab/proofs/verus/cap_math.rs`. Расходиться разрешено только в безопасную
/// сторону, и обе версии дают одно и то же число, поэтому сверка констант в `lab/verus-check.sh`
/// работает без исключений.
pub const CELL_CAP_MAX_LIVE: u64 = (u64::MAX - (CLUSTERS_PER_SHARD as u64 + 1)) / CELL_CAP_NUM;

/// Предел живых записей одной ячейки шарда — форма `⌈c·m/n⌉` от средней загрузки (`L-0001`,
/// [arXiv:1608.01350](https://arxiv.org/abs/1608.01350)), где `m` — живые записи шарда, а `n` —
/// число ячеек в шарде. Взят максимумом с `min` (пол [`CELL_CAP_MIN`] по умолчанию): у пустого
/// шарда средняя загрузка меньше одной записи, и относительная форма там обязывает ячейку
/// хранить ноль записей.
///
/// Оговорка переносимости, записанная в `ADR-0045`: у автора балансировщик сам перекладывает
/// шарики между ячейками, наш узел вправе только вытеснить или отказать. От их теоремы нам
/// достаются форма предела и единица цены (переезды), но не гарантия максимальной загрузки.
#[inline]
pub fn cell_cap_limit(live_in_shard: u64, min: u64) -> u64 {
    let per = u64::from(CLUSTERS_PER_SHARD);
    // Предпосылка, названная [`CELL_CAP_MAX_LIVE`]: вне неё умножение идёт по кольцу.
    debug_assert!(live_in_shard <= CELL_CAP_MAX_LIVE, "кап вне области определения формы ⌈c·m/n⌉");
    // ⌈c·m/n⌉ целыми: (c·m + n − 1) / n. При m ≤ 1e9 произведение не переполняет u64.
    ((CELL_CAP_NUM * live_in_shard).saturating_add(per - 1) / per).max(min)
}

// Кап обязан ограничивать именно концентрацию: при `c ≥ n` относительная ветка никогда не
// связывает ячейку, которая держит весь шард, и whole clamp вырождается в константу.
const _: () = assert!(CELL_CAP_NUM < CLUSTERS_PER_SHARD as u64);

/// Результат локальной проверки приёма. [`Verdict::code`] отдаёт ровно тот код, который уходит
/// в `Error`/`PublishAck`, чтобы тест сверял политику с протоколом, а не с литералом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Ключ в denylist'е (§11.4, ii).
    Denied,
    /// Per-key квота publish исчерпана (§11.3.1).
    PublishQuota { retry_after_ms: u32 },
    /// Per-key квота find исчерпана (§11.3.6).
    FindQuota { retry_after_ms: u32 },
    /// Узловой бюджет admission'а исчерпан (§11.3.4).
    NodeBusy { retry_after_ms: u32 },
}

impl Verdict {
    #[inline]
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    #[inline]
    pub fn is_rejected(&self) -> bool {
        !self.is_allow()
    }

    /// Код протокола для ответа агенту; у `Allow` кода нет.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Verdict::Allow => None,
            Verdict::Denied => Some(err_code::DENIED),
            Verdict::PublishQuota { .. } => Some(err_code::QUOTA_PUBLISH),
            Verdict::FindQuota { .. } => Some(err_code::QUOTA_FIND),
            Verdict::NodeBusy { .. } => Some(err_code::BUSY),
        }
    }

    pub fn retry_after_ms(&self) -> u32 {
        match self {
            Verdict::Allow | Verdict::Denied => 0,
            Verdict::PublishQuota { retry_after_ms }
            | Verdict::FindQuota { retry_after_ms }
            | Verdict::NodeBusy { retry_after_ms } => *retry_after_ms,
        }
    }
}

/// Счётчики, по которым тест и CLI отличают «узел пуст» от «узел давит» (§19.3 требует видеть
/// отказы, а не выводить их из молчания). Протокольной нагрузки не несут.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub publishes_allowed: u64,
    pub finds_allowed: u64,
    pub denied_by_denylist: u64,
    /// Внесений, отвергнутых пределом списка (§11.4, ii): оператор хотел наложить запрет, а
    /// список полон и вытеснять нечего. Отказ — политика, а не авария: `H-0092` и модель Lean
    /// перебором оставили ровно её (вытеснение живого запрета открывает дыру дешевле рестарта).
    pub denylist_refused_at_bound: u64,
    /// Попыток записи `denylist.bin`, закончившихся ошибкой ФС. Запрет при этом НЕ наложен:
    /// держать его только в RAM значило бы оставить ровно ту дыру, которую цикл закрывает.
    pub denylist_save_errors: u64,
    pub rejected_publish_quota: u64,
    pub rejected_find_quota: u64,
    pub rejected_node_busy: u64,
    /// Строк per-key таблицы, удалённых при prune (§11.3.1).
    pub forgotten_peers: u64,
    /// Вытеснений, сделанных ради капа ячейки (§14.4 iv, `ADR-0044` решение 5). Это и есть
    /// единица цены капа — «переезды», а не отказы: `L-0001` измеряет цену ограничения
    /// ожиданием перемещений, и у нас перемещение = чужая удалённая запись.
    pub cell_cap_moves: u64,
    /// Отказов приёма, к которым привёл кап ячейки: в ячейке некого вытеснить дешевле новичка
    /// (§11.3.3 запрещает вытеснять запись дороже принятой). Наружу уходит `SHARD_FULL` —
    /// отдельного кода на проводе нет по `ADR-0044` решение 3.
    pub cell_cap_rejections: u64,
    /// Кадров, чей `cluster_id` узел пересчитал по центроидам и положил в **свою** ячейку
    /// (§7.3): подсказка издателя разошлась с присваиванием, но осталась в этом шарде.
    pub cluster_reassigned: u64,
    /// Отказов `SHARD_MISMATCH` из-за того, что пересчитанный кластер принадлежит другому шарду:
    /// принять такой кадр значило бы спрятать запись от зондирования её шарда (§7.3, `H-0103`).
    pub cluster_cross_shard: u64,
    /// Принятых кадров при `centroids = None`: узел верил `cluster_id` издателя. Счётчик — не
    /// украшение: он делает fail-open развёртывания наблюдаемым, а не молчаливым.
    pub cluster_unverified: u64,
}

/// Token bucket: уровень в целых токенах, refill — целыми токенами в секунду.
///
/// Дробная часть не нужна ни одной квоте артефакта (1, 5, 100 токенов/с), а целые токены дают
/// детерминизм локальной политики: на одной последовательности `(ключ, секунда)` любой узел
/// ответит одинаково.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    capacity: u32,
    refill: u32,
    level: u32,
    /// Последняя секунда, на которую бакет пересчитан. Назад не отматывается: отмотанные часы
    /// не должны добавлять токенов (§11.3 не описывает их сдвиг как легитимное состояние).
    last_sec: u64,
}

impl Bucket {
    fn new(capacity: u32, refill: u32) -> Self {
        Bucket { capacity, refill: refill.max(1), level: capacity, last_sec: 0 }
    }

    fn refill_to(&mut self, now_sec: u64) {
        if now_sec <= self.last_sec {
            return;
        }
        self.level = self.level_at(now_sec);
        self.last_sec = now_sec;
    }

    /// Уровень, который был бы в `now_sec`, без мутации — по нему prune судит «ключ молчит».
    fn level_at(&self, now_sec: u64) -> u32 {
        let add = now_sec.saturating_sub(self.last_sec).saturating_mul(self.refill as u64);
        if add >= self.capacity as u64 {
            self.capacity
        } else {
            (self.level as u64 + add).min(self.capacity as u64) as u32
        }
    }

    /// Взять один токен. Ошибка — миллисекунды до появления следующего.
    fn try_take(&mut self, now_sec: u64) -> Result<(), u32> {
        self.refill_to(now_sec);
        if self.level == 0 {
            return Err(self.wait_ms(1));
        }
        self.level -= 1;
        Ok(())
    }

    /// Сколько ждать `need` токенов, округляя вверх: при 1/с это ровно 1000 мс, при 5/с — 200,
    /// при 100/с — 10. Агент получает честный `retry_after_ms`, а не «попробуй когда-нибудь».
    fn wait_ms(&self, need: u32) -> u32 {
        let deficit = need.saturating_sub(self.level) as u64;
        let ms = deficit.saturating_mul(1000);
        ms.div_ceil(self.refill as u64).min(u32::MAX as u64) as u32
    }

    /// Бакет, досчитавшийся до потолка: его состояние неотличимо от состояния нового ключа,
    /// поэтому строку можно выбросить, не изменив ни одного будущего ответа.
    fn is_idle(&self, now_sec: u64) -> bool {
        self.capacity == 0 || self.level_at(now_sec) == self.capacity
    }
}

/// Два per-key бакета: publish (§11.3.1) и find (§11.3.6).
#[derive(Debug, Clone)]
struct Peer {
    publish: Bucket,
    find: Bucket,
    /// Последняя секунда запроса: по ней считается «самый молчаливый» при prune.
    seen_sec: u64,
}

impl Peer {
    fn new(p: &Params, now_sec: u64) -> Self {
        Peer {
            publish: Bucket::new(p.per_peer_publish_burst, p.per_peer_publish_rps),
            // Burst find равен его же скорости: агент шлёт по одному запросу на шард (§12.2),
            // поэтому «веер» на одном узле не виден вовсе, а пять запросов в секунду на один
            // ключ уже выше бюджета §12.6 — запас был бы поблажкой, а не защитой.
            find: Bucket::new(p.per_peer_find_rps, p.per_peer_find_rps),
            seen_sec: now_sec,
        }
    }

    fn idle(&self, now_sec: u64) -> bool {
        self.publish.is_idle(now_sec) && self.find.is_idle(now_sec)
    }
}

/// Локальная политика приёма одного узла, общая для всех его шардов.
pub struct Admission {
    params: Params,
    per_peer: BTreeMap<Addr, Peer>,
    node: Bucket,
    denylist: BTreeSet<Addr>,
    /// Предел списка (§11.4, ii). Число из `ADR-0047`; политика при упоре — отказ внесению
    /// (`denylist`), а не вытеснение уже внесённого запрета.
    denylist_limit: usize,
    /// Каталог шарда, в который пишется `denylist.bin`. `None` — список живёт только в RAM
    /// (юнит-тесты, процесс без диска); узел задаёт его при `open`.
    denylist_dir: Option<std::path::PathBuf>,
    peer_limit: usize,
    prune_every: usize,
    since_prune: usize,
    pub stats: Stats,
}

impl Admission {
    pub fn new(params: &Params) -> Self {
        Self::with_limits(params, MAX_TRACKED_PEERS, PRUNE_EVERY)
    }

    /// Тот же конструктор с другой ёмкостью таблицы — для тестов: переполнение 65 536 строк
    /// проверяло бы память, а не правило.
    pub fn with_limits(params: &Params, peer_limit: usize, prune_every: usize) -> Self {
        Admission {
            params: *params,
            per_peer: BTreeMap::new(),
            // Burst узла равен одной секунде работы (100 admits/с, §11.3.4): «100 сразу, потом
            // молчание» и есть смысл посекундного лимита, а не накопленное право на взрыв.
            node: Bucket::new(params.node_admits_per_s, params.node_admits_per_s),
            denylist: BTreeSet::new(),
            denylist_limit: crate::denylist::MAX_DENYLIST,
            denylist_dir: None,
            peer_limit: peer_limit.max(1),
            prune_every: prune_every.max(1),
            since_prune: 0,
            stats: Stats::default(),
        }
    }

    #[inline]
    pub fn tracked_peers(&self) -> usize {
        self.per_peer.len()
    }

    #[inline]
    pub fn denylist_len(&self) -> usize {
        self.denylist.len()
    }

    /// §11.4, ii: запрет держит ключ, а не состав, поэтому смену эпизоды он переживает.
    /// С 2026-10-23 он переживает и перезапуск: внесение пишется в `denylist.bin` сразу, а при
    /// упоре в предел **отказывается** (`false`), не вытесняя ни одного уже внесённого ключа.
    ///
    /// `false` означает «запрета нет», а случаев три: ключ уже внесён (идемпотентность), список
    /// полон (`denylist_refused_at_bound`), или запись на диск не удалась (`denylist_save_errors`)
    /// — в последнем случае вставленный ключ откачен обратно, потому что запрет, исчезающий при
    /// рестарте, это ровно та дыра, которую этот API обязан закрывать.
    pub fn deny(&mut self, key: Addr) -> bool {
        if self.denylist.contains(&key) {
            return false;
        }
        if self.denylist.len() >= self.denylist_limit {
            self.stats.denylist_refused_at_bound += 1;
            return false;
        }
        self.denylist.insert(key);
        if let Err(_e) = self.persist_denylist() {
            self.denylist.remove(&key);
            self.stats.denylist_save_errors += 1;
            return false;
        }
        true
    }

    /// Снять запрет. Тоже durable: снятие, переживающее только RAM, вернулось бы на следующий
    /// рестарт вместе с файлом. Если запись не удалась, запрет остаётся наложенным (файл ведь
    /// не изменился) и вызывающий получает `false`.
    pub fn undeny(&mut self, key: &Addr) -> bool {
        if !self.denylist.remove(key) {
            return false;
        }
        if let Err(_e) = self.persist_denylist() {
            self.denylist.insert(*key);
            self.stats.denylist_save_errors += 1;
            return false;
        }
        true
    }

    #[inline]
    pub fn is_denied(&self, key: &Addr) -> bool {
        self.denylist.contains(key)
    }

    /// Предел списка, действующий в этом admission'е.
    #[inline]
    pub fn denylist_limit(&self) -> usize {
        self.denylist_limit
    }

    /// Тот же список с другим пределом — для тестов и для встраивателя, у которого своё
    /// представление о запасе до заморозки. Число меньше 1 бессмысленно, поэтому `max(1)`.
    #[must_use]
    pub fn with_denylist_limit(mut self, limit: usize) -> Self {
        self.denylist_limit = limit.max(1);
        self
    }

    /// Привязать каталог шарда: прочитать `denylist.bin` и включить запись при каждом изменении.
    ///
    /// Вызывается из `ShardNode::open_with_admission`, то есть **до** того, как узел вообще
    /// начнёт принимать кадры. Нечитаемый файл — ошибка открытия узла, а не «пустой список»:
    /// `L-0007` выбирает на битой базе молчаливое снятие всех запретов, и для нас это ровно та
    /// дыра, которую закрыли (`E-0042` измерил снятие рестартом, а этот путь измеряет снятие
    /// порчей файла).
    ///
    /// Загрузка никогда ничего не вытесняет (`load_never_evicts` в модели Lean): если файл принёс
    /// больше предела — например, предел понизили в новой сборке, — внесённое сохраняется целиком,
    /// а новые внесения до `undeny` отказываются. Молча обрезать список означало бы снять чужие
    /// запреты сменой версии.
    ///
    /// Для процесса с несколькими шардами (`§11.3.4`: узел — процесс, а не шард) привязка
    /// идемпотентна по тому же каталогу и сохраняет первый каталог при другом: список делится на
    /// процесс, а каталог у процесса один, и второй `open` не обязан ничего перетирать.
    pub fn attach_store(&mut self, dir: &std::path::Path) -> Result<(), crate::denylist::DenylistError> {
        if self.denylist_dir.is_some() {
            // Уже привязан (процесс открыл второй шард тем же общим admission'ом): список
            // делится на процесс, поэтому ничего не переносим и не перечитываем.
            return Ok(());
        }
        if let Some(loaded) = crate::denylist::load(dir)? {
            let before = self.denylist.len();
            self.denylist.extend(loaded);
            // RAM уже мог содержать запреты, наложенные до открытия шарда: union обязан стать
            // durable, иначе он исчезнет при первом же рестарте.
            if self.denylist.len() != before {
                crate::denylist::save(dir, &self.denylist)?;
            }
        }
        self.denylist_dir = Some(dir.to_path_buf());
        Ok(())
    }

    /// Записать текущий список, если каталог привязан. Без привязки — успешное ничего: та же
    /// семантика, что у юнит-тестов политики, где диск не участвует.
    fn persist_denylist(&self) -> Result<(), crate::denylist::DenylistError> {
        match &self.denylist_dir {
            Some(dir) => crate::denylist::save(dir, &self.denylist),
            None => Ok(()),
        }
    }

    /// Квота publish (§11.3.1) вместе с denylist'ом (§11.4, ii).
    ///
    /// Бакет берут оба ключа — аутентифицированный `from` и заявленный `owner_ed25519`. Спека
    /// называет `owner_ed25519`, и он обязателен: в нём цена sybil'а. Но подпись в `Publish`
    /// опциональна (§5.3), поэтому заявленный owner можно переписывать в каждом кадре, и бакета
    /// только по нему хватило бы, чтобы квота обнулялась сменой литерала. `from` обнуляется
    /// только новым соединением, `owner` — новой фармингой PoW, а пересечение двух бакетов — то,
    /// что бесплатно не сбрасывается.
    ///
    /// Один запрос с `from == owner` (нормальный случай) списывает один токен, а не два.
    ///
    /// Токен тратится на *запрос*, а не на принятый опс: отказ дешевле принятия, но не
    /// бесплатный. Следствие честнее, чем выглядит — при `BUSY` у ключа уже списан токен, и
    /// легитимный агент увидит `retry_after_ms`. Возврат токена при занятом узле открыл бы
    /// атакующему бесплатный повтор, поэтому это политика, а не «забыли вернуть».
    pub fn check_publish(&mut self, from: &Addr, owner: &Addr, now_sec: u64) -> Verdict {
        if self.denylist.contains(from) || self.denylist.contains(owner) {
            self.stats.denied_by_denylist += 1;
            return Verdict::Denied;
        }
        if let Err(ms) = self.peer_mut(from, now_sec).publish.try_take(now_sec) {
            self.stats.rejected_publish_quota += 1;
            return Verdict::PublishQuota { retry_after_ms: ms };
        }
        if owner != from {
            if let Err(ms) = self.peer_mut(owner, now_sec).publish.try_take(now_sec) {
                self.stats.rejected_publish_quota += 1;
                return Verdict::PublishQuota { retry_after_ms: ms };
            }
        }
        self.stats.publishes_allowed += 1;
        Verdict::Allow
    }

    /// Квота find (§11.3.6). Ключ — аутентифицированный `from`, а не `requester_ed25519` из
    /// тела: второй в неподписанном кадре свободен атакующему, и бакет по нему обнулялся бы
    /// сменой байта, а таблица росла бы быстрее, чем её успевает почистить PoW.
    pub fn check_find(&mut self, from: &Addr, now_sec: u64) -> Verdict {
        if self.denylist.contains(from) {
            self.stats.denied_by_denylist += 1;
            return Verdict::Denied;
        }
        match self.peer_mut(from, now_sec).find.try_take(now_sec) {
            Ok(()) => {
                self.stats.finds_allowed += 1;
                Verdict::Allow
            }
            Err(ms) => {
                self.stats.rejected_find_quota += 1;
                Verdict::FindQuota { retry_after_ms: ms }
            }
        }
    }

    /// Зарезервировать один admission из узлового бюджета (§11.3.4). Вызывается после всей
    /// дешёвой работы и до WAL, поэтому `BUSY` не оставляет за собой ни опса, ни уже
    /// вытесненной чужой записи.
    pub fn reserve_admit(&mut self, now_sec: u64) -> Verdict {
        match self.node.try_take(now_sec) {
            Ok(()) => Verdict::Allow,
            Err(ms) => {
                self.stats.rejected_node_busy += 1;
                Verdict::NodeBusy { retry_after_ms: ms }
            }
        }
    }

    /// Бакеты ключа: вставка с соблюдением потолка таблицы и отметка активности.
    ///
    /// Отмечается только `seen_sec` (monotone): prune по нему выбирает «молчаливый» ключ, а
    /// порядок бакетов — целиком забота [`Bucket`].
    fn peer_mut(&mut self, key: &Addr, now_sec: u64) -> &mut Peer {
        if !self.per_peer.contains_key(key) {
            self.since_prune += 1;
            if self.since_prune >= self.prune_every {
                self.since_prune = 0;
                // `pending = 1` — строка, которую вставляем следом. Prune после вставки удалил бы
                // ровно её: новый ключ начинается с полных бакетов, то есть по определению
                // idle. Это не ошибка политики (строка всё равно неотличима от отсутствующей),
                // но `peer_mut` обязан вернуть бакет, у которого сейчас спишут токен.
                self.prune_idle(now_sec, 1);
            }
            self.per_peer.insert(*key, Peer::new(&self.params, now_sec));
        } else if let Some(peer) = self.per_peer.get_mut(key) {
            peer.seen_sec = now_sec.max(peer.seen_sec);
        }
        self.per_peer.get_mut(key).expect("ключ вставлен выше и не мог быть забыт")
    }

    /// Забыть ключи, чьи бакеты уже полны (§11.3.1). Активные не трогаются никогда: их забыли
    /// бы — и sybil получил бы полный burst ценой переполнения таблицы. Если idle-ключей не
    /// хватает, чтобы вернуться под потолок, таблица временно выше потолка: это память, а не
    /// квота, и узловой бюджет от неё не двигается.
    fn prune_idle(&mut self, now_sec: u64, pending: usize) {
        let over = (self.per_peer.len() + pending).saturating_sub(self.peer_limit);
        if over == 0 {
            return;
        }
        let mut idle: Vec<Addr> = Vec::new();
        for (key, peer) in self.per_peer.iter() {
            if peer.idle(now_sec) {
                idle.push(*key);
                if idle.len() >= over {
                    break;
                }
            }
        }
        let forgotten = idle.len();
        for key in idle {
            self.per_peer.remove(&key);
        }
        self.stats.forgotten_peers += forgotten as u64;
    }
}

/// Admission одного узла, разделяемый всеми его шардами (§11.3.4: лимит «на узел»).
pub type SharedAdmission = Rc<RefCell<Admission>>;

/// Создать разделяемый admission узла.
pub fn shared(params: &Params) -> SharedAdmission {
    Rc::new(RefCell::new(Admission::new(params)))
}

/// Кандидат на вытеснение (§11.3.3).
///
/// Порядок полей = порядок сравнения: сначала биты, потом свежесть, потом slot. Нужен именно
/// лексикографический порядок, а не «произведение», которое упоминает спека: произведение
/// `bits · published_bucket` вытеснило бы обратное — свежая дешёвая запись (18 × 10⁸)
/// затмила бы дорогую старую (24 × 10⁸), и щит начал бы выкидывать защитников вместо спама,
/// что прямо противоречит §11.4(i): «дешёвые записи вытесняются первыми». Slot в конце —
/// детерминированный разрыв ничьих, не более.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Candidate {
    /// Достигнутые биты PoW на момент приёма: требуемые объявляет §11.2, принятые могут быть
    /// больше — агент вправе переплатить.
    pub bits: u32,
    /// `published_bucket` записи: при равных битах жертва — более старая публикация.
    pub published_bucket: u32,
    pub slot: u32,
}

impl Candidate {
    /// Кандидат новичка: его slot ещё не назначен, поэтому в конце `u32::MAX`. Это не «ничья
    /// невыигрышна», а «новичок — самый новый в своём бакете»: при равных битах и равном
    /// `published_bucket` вытесняется существующая запись, потому что её slot детерминированно
    /// меньше. Запись из более свежего бакета не вытесняется никогда — `published_bucket` старше
    /// в порядке сравнения, и это ровно recency из §11.3.3.
    pub fn newcomer(bits: u32, published_bucket: u32) -> Self {
        Candidate { bits, published_bucket, slot: u32::MAX }
    }
}

/// Резервуар дешёвых кандидатов и таблица достигнутых битов (§11.3.3).
///
/// Оба состояния — RAM, и оба ограничены: таблица по байту на slot (то есть высотой арены,
/// которая после §8.3 переиспользует дыры и потому плоская), резервуар ровно `limit` записей.
/// Почему не множество по всему живому индексу: при M = 2 000 000 это ещё ~50 МБ на шард и
/// O(log M) на каждую экспирацию, а «память узла плоская» (§18.6) требует, чтобы цена
/// admission'а не зависела от заполненности шарда.
///
/// Чего резервуар не гарантирует: вытеснить глобально самую дешёвую запись. Гарантия другая, и
/// её достаточно: новичок проходит, только если дороже кого-то из уже виденных узлом записей
/// (при равных битах — старше них). Дешёвый спам узел принимает постоянно, поэтому кандидат в
/// резервуаре есть всегда, а легитимная запись с высоким `pow_bits` под угрозой не оказывается
/// никогда.
#[derive(Debug)]
pub struct Evictor {
    /// slot → достигнутые биты; `0` = «не знаем». Неизвестную цену не вытесняем: оценка «запись
    /// дорогая» ошибается в сторону, которую исправляет TTL (§9.6), тогда как «вытеснить
    /// легитимную запись дешевле, чем она стоила» не исправляется ничем.
    bits: Vec<u8>,
    /// slot → кандидат: нужно, чтобы снять кандидата при перепубликации (§6.5) и при вытеснении,
    /// не перебирая резервуар.
    by_slot: BTreeMap<u32, Candidate>,
    ranked: BTreeSet<Candidate>,
    limit: usize,
    scan_from: u32,
    /// slot, с которого начнётся следующий оконный проход **внутри ячейки** (`H-0102`). Отдельный
    /// от `scan_from` курсор: обход арены и обход ячейки — разные множества, и общий курсор
    /// сдвигал бы один проход другим. Словарь по `u16` ограничен числом ячеек шарда (256),
    /// поэтому растёт не с шардом, а с числом ячеек, в которые узел принимал записи.
    cell_scan: BTreeMap<u16, u32>,
    pub scanned: u64,
    /// Сколько живых слотов осмотрел оконный проход внутри ячейки. Не входит в `scanned`:
    /// глобальная арена этим механизмом не обходится, и смешивать две цены нельзя.
    pub cell_scanned: u64,
    pub evicted: u64,
    pub stale_dropped: u64,
}

impl Evictor {
    pub fn new(limit: usize) -> Self {
        Evictor {
            bits: Vec::new(),
            by_slot: BTreeMap::new(),
            ranked: BTreeSet::new(),
            limit: limit.max(1),
            scan_from: 0,
            cell_scan: BTreeMap::new(),
            scanned: 0,
            cell_scanned: 0,
            evicted: 0,
            stale_dropped: 0,
        }
    }

    #[inline]
    pub fn candidates(&self) -> usize {
        self.ranked.len()
    }

    #[inline]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Слот, с которого начинается очередной пополняющий проход. Зовётся вместе с
    /// `IvfIndex::live_slots_from`, иначе «ограниченный скан» останется полным сканом с
    /// фильтром.
    #[inline]
    pub fn scan_from(&self) -> u32 {
        self.scan_from
    }

    /// Запомнить цену записи и выставить её кандидатом. Зовётся на primary после приёма
    /// publish, когда slot уже известен (§11.3.3).
    pub fn observe(&mut self, slot: u32, bits: u8, published_bucket: u32) {
        self.set_bits(slot, bits);
        self.drop_candidate(slot);
        if bits == 0 {
            return;
        }
        let c = Candidate { bits: bits as u32, published_bucket, slot };
        self.by_slot.insert(slot, c);
        self.ranked.insert(c);
        if self.ranked.len() > self.limit {
            // Из полного резервуара уходит самый дорогой: держим дешёвых.
            if let Some(&worst) = self.ranked.iter().next_back() {
                self.ranked.remove(&worst);
                self.by_slot.remove(&worst.slot);
            }
        }
    }

    /// Снять запись из кандидатов (вытеснение, удаление, перепубликация). Цену (байт в `bits`)
    /// оставляем: slot может быть переиспользован (§8.3), и тогда `observe` перезапишет её, а
    /// до тех пор «цена известна, кандидата нет» безвредно.
    pub fn forget(&mut self, slot: u32) {
        self.drop_candidate(slot);
    }

    fn drop_candidate(&mut self, slot: u32) {
        if let Some(c) = self.by_slot.remove(&slot) {
            self.ranked.remove(&c);
        }
    }

    #[inline]
    pub fn bits_of(&self, slot: u32) -> Option<u8> {
        self.bits.get(slot as usize).copied().filter(|b| *b != 0)
    }

    fn set_bits(&mut self, slot: u32, bits: u8) {
        let idx = slot as usize;
        if idx >= self.bits.len() {
            // Ёмкость удваивается: точная подгонка под каждый новый slot переписывала бы вектор
            // на каждой записи, то есть O(M²) байт трафика памяти на M publish'ей.
            let cap = self.bits.len().max(1);
            self.bits.resize((cap * 2).max(idx + 1).max(1024), 0);
        }
        self.bits[idx] = bits;
    }

    /// Жертва для новичка, если есть: самый дешёвый живой кандидат строго дешевле новичка.
    /// `live` — вопрос индексу «запись ещё жива»: резервуар живёт в RAM и не знает о TTL,
    /// поэтому проверка обязательна, иначе вытеснение стало бы либо удалением уже удалённого,
    /// либо отказом там, где жертва на самом деле есть.
    pub fn victim<L: FnMut(u32) -> bool>(&mut self, newcomer: Candidate, mut live: L) -> Option<Candidate> {
        loop {
            let best = *self.ranked.iter().next()?;
            if best >= newcomer {
                // Дешевле новичка никого: §11.3.3 не разрешает вытеснять запись дороже принятой,
                // значит это `SHARD_FULL`, а не «найдём хоть кого-нибудь».
                return None;
            }
            if live(best.slot) {
                return Some(best);
            }
            self.stale_dropped += 1;
            self.forget(best.slot);
        }
    }

    /// Жертва **внутри одной ячейки** (§14.4 (iv), `ADR-0044` решение 5).
    ///
    /// Тот же порядок цен, что у [`Evictor::victim`] — биты, затем свежесть, затем slot, — но
    /// кандидат обязан лежать в целевой ячейке: вытеснение из соседней ячейки место здесь не
    /// освобождает. Решение «вытеснять, а не отказывать» принято владельцем именно потому, что
    /// жёсткое «отказать новым» выбрасывает честных новичков и не трогает уже принятое множество.
    ///
    /// Чего этот выбор не гарантирует, и это названо: резервуар держит 64 самых дешёвых
    /// *увиденных* узлом записей шарда, а не 64 самых дешёвых обитателей ячейки. Если в ячейке
    /// лежат записи, принятые другим узлом после handoff'а или до рестарта (их цены узел не
    /// знает — §11.3.3), и в шарде достаточно дешёвых записей из других ячеек, жертвы не будет,
    /// и новинку откажут. Цена такого отказа — [`Stats::cell_cap_rejections`]; она ошибается в
    /// сторону «не трогать чужое», а не «освободить место любой ценой».
    pub fn cell_victim<L, C>(
        &mut self,
        newcomer: Candidate,
        mut live: L,
        mut in_cell: C,
    ) -> Option<Candidate>
    where
        L: FnMut(u32) -> bool,
        C: FnMut(u32) -> bool,
    {
        // Снимок резервуара нужен затем, чтобы снимать кандидатов можно было, перебирая его же:
        // `ranked` под итератором менять нельзя. 64 элемента — это весь резервуар, а не индекс.
        let ranked: Vec<Candidate> = self.ranked.iter().copied().collect();
        let mut stale: Vec<Candidate> = Vec::new();
        let mut victim = None;
        for cand in ranked {
            if cand >= newcomer {
                // Дальше только дороже: §11.3.3 не разрешает вытеснять запись дороже принятой.
                break;
            }
            if !live(cand.slot) {
                self.stale_dropped += 1;
                stale.push(cand);
                continue;
            }
            if !in_cell(cand.slot) {
                continue;
            }
            victim = Some(cand);
            break;
        }
        for c in stale {
            self.forget(c.slot);
        }
        victim
    }

    /// Жертва внутри ячейки по ограниченному окну её живых слотов (`H-0102`, хвост `E-0088`).
    ///
    /// Зачем рядом с [`Evictor::cell_victim`], а не вместо неё: резервуар держит 64 самых дешёвых
    /// записей **шарда**, поэтому в большом шарде его занимают записи чужих ячеек, и горячая
    /// ячейка остаётся без «знакомой» жертвы — кап уходил в отказ при живых дешёвых обитателях
    /// (`E-0088`, ДИАГНОЗ-3: `g5_branch=refuse` при `live = 34 286`). Здесь источник жертвы —
    /// сама ячейка.
    ///
    /// Цена прохода ограничена: не больше `scan` слотов, а не размер ячейки. Курсор
    /// [`Evictor::cell_scan`] хранит следующий непросмотренный slot, поэтому отказ на одном окне
    /// не запирает дешёвую запись навсегда: следующий заход в ту же ячейку продолжит список, а
    /// дойдя до конца — обернётся в начало. Обёртка происходит **между** вызовами, а не внутри
    /// одного: иначе проход стоил бы бюджета на хвосте и на начале сразу и измеренное число
    /// перестало бы быть верхней границей.
    ///
    /// `slots` — живые слоты ячейки по возрастанию (их держит индекс, это срез, а не сборка);
    /// `bucket_of` — свежесть записи, нужна только для ничьих по битам. Записи с неизвестной
    /// ценой (`bits = 0`, принятые другим узлом или до рестарта, §11.3.3) пропускаются: сделать
    /// их жертвой значило бы вытеснить запись дешевле, чем она стоила, а это не исправляется
    /// ничем. Отказ для них — осознанная ошибка в безопасную сторону, названная в `H-0102`.
    ///
    /// Порядок цен тот же, что у [`Evictor::victim`]: биты, затем свежесть, затем slot. Жертвой
    /// может стать только запись строго дешевле новичка; иначе `None` (§11.3.3).
    pub fn cell_victim_scan<B>(
        &mut self,
        cluster: u16,
        slots: &[u32],
        newcomer: Candidate,
        mut bucket_of: B,
        scan: usize,
    ) -> Option<Candidate>
    where
        B: FnMut(u32) -> Option<u32>,
    {
        if scan == 0 || slots.is_empty() {
            return None;
        }
        let cursor = self.cell_scan.get(&cluster).copied().unwrap_or(0);
        // Курсор — это slot, а не индекс: слоты ячейки меняются (TTL, вытеснение, переезд), и
        // индекс, сохранённый между заходами, указывал бы на другую запись молча.
        let mut start = slots.partition_point(|s| *s < cursor);
        if start >= slots.len() {
            // Ячейка сжалась под курсором — проход начинается сначала, а не отказывает навсегда.
            start = 0;
        }
        let end = (start + scan).min(slots.len());
        let mut best: Option<Candidate> = None;
        for &slot in &slots[start..end] {
            self.cell_scanned += 1;
            let Some(bits) = self.bits_of(slot) else { continue };
            if (bits as u32) > newcomer.bits {
                continue;
            }
            let Some(published_bucket) = bucket_of(slot) else { continue };
            let cand = Candidate { bits: bits as u32, published_bucket, slot };
            if cand >= newcomer {
                continue;
            }
            if best.map_or(true, |b| cand < b) {
                best = Some(cand);
            }
        }
        let next = if end < slots.len() { slots[end - 1].saturating_add(1) } else { 0 };
        self.cell_scan.insert(cluster, next);
        best
    }

    /// Долить кандидатов, обойдя не больше `scan` живых записей, начиная с [`Evictor::scan_from`]
    /// (§11.3.3). Итератор обязан идти по возрастанию slot'ов и начинаться не раньше курсора —
    /// за это отвечает вызывающий (`live_slots_from`), иначе «ограниченный» проход стоил бы O(M).
    pub fn refill<I: Iterator<Item = (u32, u32)>>(&mut self, entries: I, arena_end: u32, scan: usize) {
        let mut last = None;
        for (taken, (slot, published_bucket)) in entries.enumerate() {
            if taken >= scan {
                break;
            }
            last = Some(slot);
            self.scanned += 1;
            if let Some(bits) = self.bits_of(slot) {
                self.observe(slot, bits, published_bucket);
            }
        }
        // Дошли до конца арены (или арена пуста) — следующий проход с нуля.
        self.scan_from = match last {
            Some(s) if s + 1 < arena_end => s + 1,
            _ => 0,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    fn params() -> Params {
        testing::params(8)
    }

    fn key(i: u8) -> Addr {
        [i; 32]
    }

    #[test]
    fn reference_quotas_are_the_spec_numbers() {
        let p = params();
        // §11.3.1, §11.3.4, §11.3.6 — один набор чисел и в спеке, и в артефакте.
        assert_eq!((p.per_peer_publish_burst, p.per_peer_publish_rps), (20, 1));
        assert_eq!(p.per_peer_find_rps, 5);
        assert_eq!(p.node_admits_per_s, 100);
    }

    #[test]
    fn publish_bucket_gives_a_burst_then_one_per_second() {
        let mut a = Admission::new(&params());
        let k = key(1);
        // Burst 20 в одну секунду: стартовая пачка интентов проходит целиком (§11.3.1).
        for i in 0..20 {
            assert_eq!(a.check_publish(&k, &k, 0), Verdict::Allow, "токен №{i} из burst");
        }
        assert_eq!(
            a.check_publish(&k, &k, 0),
            Verdict::PublishQuota { retry_after_ms: 1000 },
            "burst исчерпан ⇒ ровно 1 токен в секунду"
        );
        assert_eq!(a.check_publish(&k, &k, 1), Verdict::Allow, "через секунду refill выдал токен");
        assert_eq!(a.check_publish(&k, &k, 1), Verdict::PublishQuota { retry_after_ms: 1000 });
    }

    #[test]
    fn one_token_per_publish_even_when_from_equals_owner() {
        let mut a = Admission::new(&params());
        let k = key(2);
        // Агент публикует от своего имени: `from == owner`. Двойное списание съедало бы burst
        // пополам, и 20 интентов стартовой пачки превращались бы в 10.
        assert_eq!(a.check_publish(&k, &k, 0), Verdict::Allow);
        assert_eq!(a.peer_mut(&k, 0).publish.level, 19);
    }

    #[test]
    fn a_spoofed_owner_pays_on_its_own_bucket_too() {
        let mut a = Admission::new(&params());
        let attacker = key(3);
        let victim = key(4);
        // §11.3.1 называет owner, но подпись в Publish опциональна (§5.3): только бакет owner
        // обнулился бы сменой литерала, поэтому проверяются оба.
        assert_eq!(a.check_publish(&attacker, &victim, 0), Verdict::Allow);
        assert_eq!(a.peer_mut(&attacker, 0).publish.level, 19);
        assert_eq!(a.peer_mut(&victim, 0).publish.level, 19, "заявленный owner тоже заплатил токен");
    }

    #[test]
    fn find_bucket_is_five_per_second_and_keyed_by_the_transport_identity() {
        let mut a = Admission::new(&params());
        let k = key(5);
        for i in 0..5 {
            assert_eq!(a.check_find(&k, 0), Verdict::Allow, "find №{i}");
        }
        assert_eq!(a.check_find(&k, 0), Verdict::FindQuota { retry_after_ms: 200 }, "5/с ⇒ 200 мс");
        assert_eq!(a.check_find(&k, 1), Verdict::Allow);
    }

    #[test]
    fn node_budget_is_one_hundred_admits_per_second_for_all_its_keys() {
        let mut a = Admission::new(&params());
        // Разные ключи — общий бюджет: 101-й admission не появляется от того, что у каждого
        // своего токена полон бакет (§11.3.4: лимит «на узел»).
        for i in 0..100u8 {
            assert!(a.reserve_admit(0).is_allow(), "admit №{i}");
        }
        assert_eq!(a.reserve_admit(0), Verdict::NodeBusy { retry_after_ms: 10 });
        assert_eq!(a.reserve_admit(0), Verdict::NodeBusy { retry_after_ms: 10 });
        assert!(a.reserve_admit(1).is_allow(), "прошла секунда ⇒ бюджет восполнился");
        assert_eq!(a.stats.rejected_node_busy, 2);
    }

    #[test]
    fn denylist_survives_the_epoch_and_blocks_both_roles() {
        let mut a = Admission::new(&params());
        let bad = key(6);
        assert!(a.deny(bad));
        assert!(!a.deny(bad), "повторный deny идемпотентен");
        assert_eq!(a.check_publish(&bad, &bad, 0), Verdict::Denied);
        assert_eq!(a.check_find(&bad, 0), Verdict::Denied);
        // Список держит ключ, поэтому смена состава его не снимает (§11.4, ii).
        assert_eq!(a.denylist_len(), 1);
        assert!(a.undeny(&bad));
        assert_eq!(a.check_publish(&bad, &bad, 0), Verdict::Allow);
    }

    #[test]
    fn verdict_codes_are_the_wire_codes() {
        // Политика сверяется с протоколом: код из `Verdict` обязан существовать в §5.5.
        assert_eq!(Verdict::NodeBusy { retry_after_ms: 1 }.code(), Some(err_code::BUSY));
        assert_eq!(Verdict::PublishQuota { retry_after_ms: 1 }.code(), Some(err_code::QUOTA_PUBLISH));
        assert_eq!(Verdict::FindQuota { retry_after_ms: 1 }.code(), Some(err_code::QUOTA_FIND));
        assert_eq!(Verdict::Denied.code(), Some(err_code::DENIED));
        assert_eq!(Verdict::Allow.code(), None);
        assert_eq!(Verdict::Allow.retry_after_ms(), 0);
        assert!(Verdict::Denied.is_rejected());
    }

    #[test]
    fn the_peer_table_forgets_idle_keys_without_changing_any_decision() {
        let mut a = Admission::with_limits(&params(), 4, 1);
        // Четыре ключа потратили по токену и замолчали: их бакеты досчитались до потолка,
        // значит состояние строки = состояние новой строки, и prune ничего не смягчает.
        for i in 1..=4 {
            assert!(a.check_publish(&key(i), &key(i), 0).is_allow());
        }
        assert!(a.check_publish(&key(5), &key(5), 1_000).is_allow(), "пятый ключ запускает prune");
        assert!(a.tracked_peers() <= 4, "таблица обязана вернуться под потолок");
        // Забытый ключ обязан повести себя ровно как новый: полный burst.
        assert!(a.check_publish(&key(1), &key(1), 1_000).is_allow());
        assert!(a.stats.forgotten_peers >= 1);
    }

    #[test]
    fn prune_among_idle_rows_picks_the_smallest_address_not_the_quietest() {
        // E-0040, порог (1). Комментарий поля обещает «самый молчаливый при prune», но
        // `prune_idle` `seen_sec` не читает: жертва — первые `over` idle-строк в порядке
        // `BTreeMap`. Подбираем расхождение правил: X молчит дольше всех (seen 0), но адрес у
        // него наибольший; Y молчит меньше (seen 1), зато адрес наименьший. Отбор по адресу
        // удалит Y, обещание комментария удалило бы X.
        let mut a = Admission::with_limits(&params(), 3, 1);
        let x = key(0xF0);
        let y = key(0x01);
        let z = key(0x02);
        let w = key(0x70);
        for _ in 0..5 {
            assert!(a.check_find(&x, 0).is_allow());
        }
        assert!(a.check_find(&x, 0).is_rejected(), "burst find X исчерпан при t=0");
        for k in [&y, &z] {
            for _ in 0..5 {
                assert!(a.check_find(k, 1).is_allow());
            }
            assert!(a.check_find(k, 1).is_rejected(), "burst исчерпан и у {k:?} при t=1");
        }
        // При t=2 все три строки idle (refill 5/с добирает бакет за секунду),
        // seen: X=0, Y=Z=1. Вставка W — четвёртая строка, over = 1.
        assert!(a.check_find(&w, 2).is_allow(), "четвёртая строка запускает prune");
        assert_eq!(a.tracked_peers(), 3);
        assert_eq!(a.stats.forgotten_peers, 1);
        assert_eq!(a.per_peer.get(&x).map(|p| p.seen_sec), Some(0), "молчаливый X выжил");
        assert!(a.per_peer.contains_key(&z), "Z не жертва");
        assert!(!a.per_peer.contains_key(&y), "жертва — Y: наименьший адрес среди idle, не самый молчаливый");
    }

    #[test]
    fn the_peer_table_never_forgets_a_key_with_an_empty_bucket() {
        let mut a = Admission::with_limits(&params(), 4, 1);
        // Активный ключ (бакет пуст) не вытесняется: иначе sybil сбрасывал бы квоту переполнением
        // таблицы, и лимит §11.3.1 переставал бы что-либо значить.
        for i in 1..=3 {
            for _ in 0..20 {
                assert!(a.check_publish(&key(i), &key(i), 0).is_allow());
            }
            assert!(a.check_publish(&key(i), &key(i), 0).is_rejected());
        }
        for i in 4..=8 {
            assert!(a.check_publish(&key(i), &key(i), 0).is_allow());
        }
        for i in 1..=3 {
            assert!(
                a.check_publish(&key(i), &key(i), 0).is_rejected(),
                "ключ {i} с пустым бакетом пережил prune"
            );
        }
        assert_eq!(a.stats.forgotten_peers, 0, "забывать было нечего: idle-строк нет");
    }

    #[test]
    fn evict_prefers_the_cheapest_pow_then_the_oldest() {
        let mut e = Evictor::new(8);
        e.observe(0, 20, 100);
        e.observe(1, 18, 90);
        e.observe(2, 24, 50);
        // Новичок с 21 битом: дешевле него только slot 1 (18 бит) — его и вытесняем.
        assert_eq!(e.victim(Candidate::newcomer(21, 200), |_| true).map(|c| c.slot), Some(1));
        // Новичок дешевле всех ⇒ вытеснять некого: §11.3.3 означает `SHARD_FULL`, а не «кого-нибудь».
        assert_eq!(e.victim(Candidate::newcomer(17, 200), |_| true), None);
        // При равных битах жертва — более старая публикация.
        e.observe(3, 18, 50);
        assert_eq!(e.victim(Candidate::newcomer(19, 200), |_| true).map(|c| c.slot), Some(3));
        // Равные биты и равный бакет: ничью разрешает slot, и `u32::MAX` у новичка означает
        // «я самый новый в этом бакете» — вытесняется запись с меньшим slot'ом.
        assert_eq!(e.victim(Candidate::newcomer(18, 50), |_| true).map(|c| c.slot), Some(3));
        // А запись из более свежего бакета не вытесняется даже при равных битах: recency старше
        // slot'а в порядке сравнения.
        assert_eq!(e.victim(Candidate::newcomer(18, 49), |_| true), None);
    }

    #[test]
    fn unknown_bits_are_never_candidates() {
        let mut e = Evictor::new(8);
        // Запись пришла из снапшота: битов мы не знаем (§11.3.3 не хранит их в 424-байтной
        // раскладке, и в WAL их тоже нет). Цену не выдумываем — в резервуаре её нет.
        assert_eq!(e.bits_of(7), None);
        e.refill([(7u32, 100u32), (8, 101)].into_iter(), 9, 64);
        assert_eq!(e.candidates(), 0, "refill не выдумывает цену");
        assert_eq!(e.victim(Candidate::newcomer(30, 1_000), |_| true), None);
        // Стоило записи быть принятой publish'ем этого узла — цена появляется.
        e.observe(7, 19, 100);
        assert_eq!(e.victim(Candidate::newcomer(20, 1_000), |_| true).map(|c| c.slot), Some(7));
    }

    #[test]
    fn refill_walks_the_arena_in_bounded_steps_and_wraps() {
        let mut e = Evictor::new(64);
        for slot in 0..1_000u32 {
            e.observe(slot, 18, slot);
        }
        for slot in 0..1_000u32 {
            e.forget(slot);
        }
        assert_eq!(e.candidates(), 0);
        e.refill((0..1_000u32).map(|s| (s, s)), 1_000, 256);
        assert_eq!(e.scanned, 256, "проход стоит ровно бюджет, а не всю арену");
        assert_eq!(e.scan_from(), 256, "курсор двигается, а не ползёт с нуля");
        e.refill((256..1_000u32).map(|s| (s, s)), 1_000, 256);
        assert_eq!(e.scanned, 512);
        assert_eq!(e.scan_from(), 512);
        // Последний проход доходит до конца арены и возвращается к нулю.
        e.refill((768..1_000u32).map(|s| (s, s)), 1_000, 256);
        assert_eq!(e.scan_from(), 0);
    }

    #[test]
    fn a_stale_candidate_is_dropped_and_the_next_one_wins() {
        let mut e = Evictor::new(8);
        e.observe(0, 18, 100);
        e.observe(1, 19, 100);
        // slot 0 истёк по TTL: индекс говорит «не жив», и резервуар обязан узнать это сам.
        assert_eq!(e.victim(Candidate::newcomer(20, 200), |s| s != 0).map(|c| c.slot), Some(1));
        assert_eq!(e.stale_dropped, 1);
        assert_eq!(e.candidates(), 1);
    }

    #[test]
    fn republish_replaces_the_candidate_instead_of_doubling_it() {
        let mut e = Evictor::new(8);
        e.observe(5, 18, 100);
        e.observe(5, 24, 120); // перепубликация того же slot'а (§6.5)
        assert_eq!(e.candidates(), 1, "у slot'а ровно один кандидат");
        assert_eq!(e.bits_of(5), Some(24), "цена берётся из последней публикации");
        // Дешёвый слот стал дорогим — вытеснять его уже нельзя.
        assert_eq!(e.victim(Candidate::newcomer(20, 200), |_| true), None);
    }

    #[test]
    fn the_reservoir_keeps_the_cheapest_when_it_overflows() {
        let mut e = Evictor::new(4);
        for (slot, bits) in [(0u32, 24u8), (1, 18), (2, 20), (3, 22), (4, 19), (5, 21)] {
            e.observe(slot, bits, 100);
        }
        assert_eq!(e.candidates(), 4, "потолок резервуара");
        let mut slots: Vec<u32> = e.ranked.iter().map(|c| c.slot).collect();
        slots.sort_unstable();
        // Выживают самые дешёвые: 18, 19, 20, 21.
        assert_eq!(slots, vec![1, 2, 4, 5]);
    }

    #[test]
    fn the_bits_table_grows_by_powers_not_by_one_slot() {
        let mut e = Evictor::new(4);
        e.observe(0, 18, 1);
        let first = e.bits.len();
        e.observe(first as u32, 18, 2);
        assert!(e.bits.len() >= first * 2, "ёмкость удваивается, иначе O(M²) на переписывание");
        assert_eq!(e.bits_of(0), Some(18), "рост не трогает уже записанные цены");
    }

    #[test]
    fn buckets_do_not_refill_on_a_clock_that_goes_backwards() {
        let mut a = Admission::new(&params());
        let k = key(7);
        for _ in 0..20 {
            assert!(a.check_publish(&k, &k, 100).is_allow());
        }
        assert!(a.check_publish(&k, &k, 100).is_rejected());
        // Часы отмотались: токены не появляются, иначе `retry_after_ms` был бы советом сдвинуть
        // часы, а не подождать.
        assert!(a.check_publish(&k, &k, 50).is_rejected());
        assert!(a.check_publish(&k, &k, 101).is_allow());
    }

    /// Плечо формы: пока шард разрежен, связан пол; выше `16·min/c` связана средняя загрузка.
    #[test]
    fn cell_cap_is_a_floor_while_the_shard_is_sparse_and_the_mean_above_it() {
        // Порог переключения: ⌈2·m/16⌉ > 4096 ⟺ m > 32 768.
        assert_eq!(cell_cap_limit(0, CELL_CAP_MIN), 4_096);
        assert_eq!(cell_cap_limit(32_768, CELL_CAP_MIN), 4_096);
        assert_eq!(cell_cap_limit(32_769, CELL_CAP_MIN), 4_097);
        assert_eq!(cell_cap_limit(80_000, CELL_CAP_MIN), 10_000);
        assert_eq!(cell_cap_limit(2_000_000, CELL_CAP_MIN), 250_000);
    }

    /// Относительность — не косметика: кап обязан связывать ячейку, которая держит весь шард,
    /// как только шард больше пола. Иначе это была бы константа, а `ADR-0044` требует параметр.
    #[test]
    fn cell_cap_always_binds_a_cell_that_holds_the_whole_shard() {
        for live in [CELL_CAP_MIN + 1, 100_000, 2_000_000] {
            let limit = cell_cap_limit(live, CELL_CAP_MIN);
            assert!(limit < live, "ячейка всего шарда ({live}) обязана быть выше капа {limit}");
        }
        // Монотонность по live: рост корпуса не может делать предел меньше.
        let mut prev = 0u64;
        for live in (0..200_000u64).step_by(997) {
            let limit = cell_cap_limit(live, CELL_CAP_MIN);
            assert!(limit >= prev, "кап убыл при live={live}");
            prev = limit;
        }
    }

    /// Пол — параметр (`Params::cell_cap_min`), форма при этом не меняется: ниже пола связана
    /// константа, выше — средняя загрузка.
    #[test]
    fn lowering_the_floor_keeps_the_relative_shape() {
        assert_eq!(cell_cap_limit(41, 8), 8, "⌈82/16⌉ = 6 ниже пола 8");
        assert_eq!(cell_cap_limit(64, 8), 8, "ровно на переключении: ⌈128/16⌉ = 8 = пол");
        assert_eq!(cell_cap_limit(65, 8), 9, "выше — связана средняя загрузка");
        assert_eq!(cell_cap_limit(1_000, 8), 125);
    }

    #[test]
    fn cell_victim_takes_the_cheapest_of_the_target_cell_only() {
        let mut e = Evictor::new(8);
        e.observe(1, 18, 100); // самая дешёвая, но в чужой ячейке
        e.observe(2, 20, 100);
        e.observe(3, 22, 100);
        let in_cell = |s: u32| s != 1;
        let live = |_s: u32| true;
        // Новичок дороже обеих: берёт самую дешёвую **в своей ячейке**, а не самую дешёвую вообще.
        assert_eq!(
            e.cell_victim(Candidate::newcomer(21, 100), live, in_cell).map(|c| c.slot),
            Some(2)
        );
        // Ровно та же цена, что у записи в ячейке: разрыв ничьих — slot, и у новичка он
        // `u32::MAX`, поэтому вытесняется существующая запись (§11.3.3 «новичок — самый новый»).
        assert_eq!(
            e.cell_victim(Candidate::newcomer(20, 100), live, in_cell).map(|c| c.slot),
            Some(2)
        );
        // Новичок дешевле всех знакомых в своей ячейке (дешёвая запись лежит в чужой) — жертвы
        // нет (§11.3.3), и это отказ, а не вытеснение дорогой записи.
        assert_eq!(e.cell_victim(Candidate::newcomer(19, 100), live, in_cell), None);
    }

    #[test]
    fn cell_victim_drops_dead_slots_it_walks_past() {
        let mut e = Evictor::new(8);
        e.observe(1, 18, 100);
        e.observe(2, 20, 100);
        let before = e.candidates();
        assert_eq!(
            e.cell_victim(
                Candidate::newcomer(21, 100),
                |s| s != 1,
                |_s| true,
            )
            .map(|c| c.slot),
            Some(2)
        );
        assert_eq!(e.candidates(), before - 1, "мёртвый slot снят с резервуара");
        assert_eq!(e.stale_dropped, 1);
    }

    // --- переживаемость и предел denylist'а (`H-0092`, `ADR-0047`) -------------------------------

    /// Каталог, снимаемый при выходе из области видимости: тест политики падает на assert'е, и
    /// ручное `remove` в последней строке оставило бы осевший каталог (`E-0085` ДИАГНОЗ-2).
    struct D(std::path::PathBuf);

    impl Drop for D {
        fn drop(&mut self) {
            vecdht_index::testing::remove(&self.0);
        }
    }

    fn tmp(tag: &str) -> D {
        D(vecdht_index::testing::dir(tag))
    }

    #[test]
    fn a_denied_key_comes_back_from_the_directory() {
        let d = tmp("deny-attach");
        let mut a = Admission::new(&params());
        a.attach_store(&d.0).expect("первое открытие: файла нет");
        for i in [1u8, 2, 3] {
            assert!(a.deny(key(i)), "внесение {i}");
        }
        // Цена переживаемости измеряется в байтах, а не «есть ли файл»: 18 + 32·3.
        assert_eq!(
            std::fs::metadata(crate::denylist::path(&d.0)).unwrap().len(),
            114,
            "ровно заголовок и три ключа"
        );
        let mut b = Admission::new(&params());
        b.attach_store(&d.0).expect("повторное открытие того же каталога");
        assert_eq!(b.denylist_len(), 3, "список поднялся с диска");
        assert!(b.is_denied(&key(2)));
        assert_eq!(b.check_publish(&key(2), &key(2), 0), Verdict::Denied);
        assert_eq!(b.check_publish(&key(9), &key(9), 0), Verdict::Allow, "чистый ключ чист");
    }

    #[test]
    fn an_unreadable_denylist_refuses_the_node_instead_of_emptying_it() {
        let d = tmp("deny-corrupt");
        let mut seed = Admission::new(&params());
        seed.attach_store(&d.0).expect("чистый каталог");
        assert!(seed.deny(key(1)));
        assert!(seed.deny(key(2)));
        let p = crate::denylist::path(&d.0);
        let good = std::fs::read(&p).expect("файл записан");
        // Дыра `E-0042` снимала запреты рестартом; этот путь снимал бы их порчей двух байт.
        std::fs::write(&p, &good[..good.len() - 6]).expect("обрезанный файл");
        let mut b = Admission::new(&params());
        let e = b.attach_store(&d.0).expect_err("обрезанный список нельзя открыть молча");
        assert!(matches!(e, crate::denylist::DenylistError::Corrupt(_)), "{e}");
        assert_eq!(b.denylist_len(), 0, "на отказе RAM-состояние не изменилось");
    }

    #[test]
    fn at_the_bound_the_list_refuses_and_freezes_instead_of_evicting() {
        // Те же две теоремы модели Lean (`frozen_at_cap`, `undeny_makes_room`), что выбранная
        // политика, только на реальном пределе кода — гейт (6) оракула с числом 4096.
        let mut a = Admission::new(&params()).with_denylist_limit(3);
        for i in [1u8, 2, 3] {
            assert!(a.deny(key(i)));
        }
        assert!(!a.deny(key(4)), "полный список отказывает новому внесению");
        assert_eq!(a.denylist_len(), 3, "отказ не изменил множество");
        for i in [1u8, 2, 3] {
            assert!(a.is_denied(&key(i)), "ни один внесённый запрет не исчез");
        }
        assert_eq!(a.stats.denylist_refused_at_bound, 1);
        assert!(!a.deny(key(1)), "повтор того же ключа — идемпотентный отказ");
        assert!(a.undeny(&key(2)), "снятие работает при полном списке");
        assert!(a.deny(key(4)), "снятие вернуло место");
        assert_eq!(a.denylist_len(), 3);
    }

    #[test]
    fn loading_a_file_larger_than_the_bound_keeps_every_entry() {
        let d = tmp("deny-over-bound");
        let written: std::collections::BTreeSet<Addr> = [1u8, 2, 3, 4, 5].map(key).into_iter().collect();
        crate::denylist::save(&d.0, &written).expect("файл на пять ключей");
        let mut a = Admission::new(&params()).with_denylist_limit(2);
        a.attach_store(&d.0).expect("файл читается");
        assert_eq!(a.denylist_len(), 5, "загрузка ничего не вытесняет");
        assert!(!a.deny(key(9)), "сверх предела не входит");
        assert_eq!(a.denylist_len(), 5, "и не счищается");
        // Файл остаётся файлом: предел — политика новых внесений, а не причина портить запись.
        assert_eq!(std::fs::metadata(crate::denylist::path(&d.0)).unwrap().len(), 18 + 32 * 5);
    }

    #[test]
    fn a_ban_that_cannot_be_written_is_not_applied() {
        let d = tmp("deny-io-fail");
        let mut a = Admission::new(&params());
        a.attach_store(&d.0).expect("привязка к существующему каталогу");
        // Каталог исчезает после привязки: путь, на котором «запрет есть в RAM, но его нет на
        // диске» перестаёт быть возможен.
        vecdht_index::testing::remove(&d.0);
        assert!(!a.deny(key(7)), "нельзя записать — значит не внесено");
        assert_eq!(a.denylist_len(), 0, "RAM--only запрета не остаётся");
        assert_eq!(a.stats.denylist_save_errors, 1);
        assert_eq!(a.check_publish(&key(7), &key(7), 0), Verdict::Allow);
    }
}

// Прибор формального контура №3 (Kani, bounded model checking). Модуль compile-ется только под
// `cargo kani` (`--cfg kani`), поэтому обычная сборка и `cargo test` его не видят — см. `ADR-0053`.
// Смысл не в том, чтобы повторить юнит-тесты: Kani перебирает достижимые состояния функции на
// ограниченном домене и обязан подтверждать ∀-утверждения, которые тест на трёх точках только
// иллюстрируют. Окно 2⁶⁴ недостижимо для bounded-перебора, поэтому домен сужен ассумпциями, и
// именно это сужение честно названо в каждом харнесе.
#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    /// Пол: при любой загрузке шарда кап не ниже заявленного минимума.
    #[kani::proof]
    #[kani::unwind(2)]
    fn cap_is_never_below_floor() {
        let live: u64 = kani::any();
        let min: u64 = kani::any();
        kani::assume(live <= CELL_CAP_MAX_LIVE);
        let cap = cell_cap_limit(live, min);
        assert!(cap >= min);
    }

    /// Монотонность по загрузке: больше живых записей — не меньше предел ячейки.
    #[kani::proof]
    #[kani::unwind(2)]
    fn cap_is_monotone_in_live() {
        let l1: u64 = kani::any();
        let l2: u64 = kani::any();
        let min: u64 = kani::any();
        kani::assume(l1 <= l2);
        kani::assume(l2 <= CELL_CAP_MAX_LIVE);
        assert!(cell_cap_limit(l1, min) <= cell_cap_limit(l2, min));
    }

    /// Мост к математической форме ⌈c·m/n⌉: пока слагаемые влезают в `u128`, тело обязано совпадать
    /// с ceil-арифметикой, посчитанной независимо. Числа фикстуры берутся из замера `E-0088`
    /// (4096 при `max_live_per_shard = 2 000 000` и 4286 при live 34 286), чтобы проверка была про
    /// те же точки, что измерены, а не только про абстракцию.
    #[kani::proof]
    #[kani::unwind(2)]
    fn cap_matches_ceiling_formula() {
        let live: u64 = kani::any();
        let min: u64 = kani::any();
        kani::assume(live <= 1_000_000_000);
        let per: u128 = u64::from(CLUSTERS_PER_SHARD).into();
        let exact: u128 = (u128::from(CELL_CAP_NUM) * u128::from(live) + per - 1) / per;
        let floor: u128 = u128::from(min);
        let want = if exact > floor { exact } else { floor };
        assert!(u128::from(cell_cap_limit(live, min)) == want);
    }

    /// Покрываемость: ветка `saturating_add` (та, где `c·m` уже влезает, а `c·m + n − 1` — нет)
    /// достижима на объявленной границе. Если она не достижима вовсе, `.saturating_add` в теле —
    /// украшение, и тогда её надо либо убрать, либо сузить [`CELL_CAP_MAX_LIVE`].
    #[kani::proof]
    #[kani::unwind(2)]
    fn saturating_branch_is_reachable() {
        let live: u64 = kani::any();
        kani::assume(live <= CELL_CAP_MAX_LIVE);
        kani::assume(CELL_CAP_NUM * live > u64::MAX - u64::from(CLUSTERS_PER_SHARD) + 1);
        kani::cover!(true);
    }
}
