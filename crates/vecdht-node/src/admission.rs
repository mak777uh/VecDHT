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
    pub rejected_publish_quota: u64,
    pub rejected_find_quota: u64,
    pub rejected_node_busy: u64,
    /// Строк per-key таблицы, удалённых при prune (§11.3.1).
    pub forgotten_peers: u64,
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
    /// `false` — ключ уже был в списке.
    pub fn deny(&mut self, key: Addr) -> bool {
        self.denylist.insert(key)
    }

    pub fn undeny(&mut self, key: &Addr) -> bool {
        self.denylist.remove(key)
    }

    #[inline]
    pub fn is_denied(&self, key: &Addr) -> bool {
        self.denylist.contains(key)
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
    pub scanned: u64,
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
            scanned: 0,
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

}
