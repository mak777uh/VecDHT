//! H-0084 / `E-0084`: §19.4 — последняя незамеренная строка таблицы целей,
//! «find end-to-end, p50 / p95 | ≤ 1,5 с / ≤ 4 с».
//!
//! В `E-0083` она не измерялась и была вынесена сюда явно: ей нужен настоящий транспорт, а не
//! однопоточный харнес `vecdht-index`. Рецепт — `crates/vecdht-net/tests/transport.rs`: libp2p
//! QUIC loopback, `current_thread` + `LocalSet`, настоящие `NetService` узлов и настоящий `Agent`.
//! Мок-транспорта нет: не сошёлся handshake или провайдер-запись — `find` не вернёт результат.
//!
//! Что меряется и почему это не одно число. Строка спеки не определяет, где начинается интервал
//! «end-to-end», а на стенде это разница в порядок величины, поэтому замеряются обе читаемые
//! формы и их раскладка по фазам:
//!
//! * `new_ms` — конструкция агента (`NetService::new`: сборка swarm + dial bootstrap-списку);
//! * `setup_ms` — от начала конструкции до состояния, в котором `Agent::candidates()` обязан
//!   вернуть кандидата на каждый шард запроса (предикат повторяется снаружи через публичный API:
//!   `authenticated_peers` + `peer_identity().covers_shard`);
//! * `cold_ms` = `new_ms + find_ms` — поиск «холодным процессом»: вызов `find` на агенте, который
//!   после создания ещё ни разу не шагнул, то есть вся discovery-работа внутри вызова;
//! * `warm_ms` — тот же запрос следующими заходами, когда соединения, handshake и таблица
//!   провайдеров уже есть;
//! * `fanout13_*` — то же, но запрос идёт по 13 шардам (столько, сколько §19.5 насчитывает при
//!   `nprobe = 16` на замороженных центроидах артефакта: 12,7 → 13), каждый шард — отдельный
//!   узел на отдельном QUIC-слушателе;
//! * `scanlight` / `scanheavy` — доля узловой арифметики в сетевом времени: чередующиеся замеры
//!   по лёгкой (1 запись) и тяжёлой (1 100 записей = фикстура строки «search, 1.1k записей/узел»
//!   из `E-0083`) ячейке одного узла, плюс прямой `ShardStore::search` на том же векторе.
//!
//! Ограничения стенда названы до чисел: loopback без WAN-RTT; узлы — задачи одного
//! `current_thread`-рантайма на одном ядре, то есть узловая арифметика и сетевая половина делят
//! один CPU; записи положены ЖИВЫМ путём `Publish` → `ShardNode::on_frame` (тот же приём, что в
//! `transport.rs` и `E-0079`), а не прямым вызовом индекса, потому что иначе оракул мерил бы
//! `find` по индексу, который боевой узел никогда не строит; цена публикации с PoW и `fsync`
//! измерена `E-0079`/`E-0081` и в интервал строки `find` не входит. Узел стенда создаётся
//! ОТДЕЛЬНЫЙ на каждый заход и закрывается по его конце: один узел на все заходы накапливал
//! мёртвые соединения и провайдер-записи Kademlia, из-за чего фазовая раскладка оказывалась
//! медленнее холодного find (пилот `E-0084`: `setup1 = 8,26 мс > cold1 = 6,29 мс`), то есть
//! медиана меряла положение захода в тесте, а не строку спеки.
//!
//! Временные гейты живут только в release-профиле (правило 6: профиль — часть заморозки); в debug
//! печатается тот же набор чисел, а проверяются только структура, корректность и независимое от
//! профиля. Цикл не трогает продуктовый код, wire, крипто и спеку.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use tokio::task::LocalSet;
use vecdht_artifact::{reference_artifact, reference_manifest};
use vecdht_crypto::{intent_id, pow_input};
use vecdht_net::{keys, Agent, AgentConfig, FindQuery, NetConfig, NetService, NetworkParams};
use vecdht_node::{candidates, testing, Clock, ShardNode};
use vecdht_wire::messages::{Codec, ProtocolError, Publish, Role};
use vecdht_wire::{decode_frame, Kind};

/// Шард фикстуры: `shard_of_cluster` делит `nlist` на 64, и «удобный ноль» скрыл бы ошибку
/// маршрута (тот же урок, что в `E-0079`).
const SHARD: u16 = 7;
const CLUSTER: u16 = SHARD * 16;
/// Дешёвый PoW: стенду нужна живая запись, а не политический пол 18…24 (он измерен `E-0079`).
const POW: u32 = 8;
const TTL: u16 = 225;
/// Число шардов во fan-out-половине стенда: §19.5 при `nprobe = 16` даёт 12,7 шарда.
const FANOUT: u16 = 13;
/// Выборки заморожены вместе с порогами. `p95` по nearest-rank при `K = 21` — 20-й порядок,
/// при `K = 11` — 11-й, то есть максимум: граница «в малой выборке p95 ≡ max» заявлена как
/// ограничение инструмента, а не как свойство строки.
const K_COLD: usize = 21;
const K_FANOUT: usize = 11;
const K_PHASE: usize = 9;
/// Тёплых заходов после каждого холодного (выборка `warm` = `K_COLD × K_WARM` = 63).
const K_WARM: usize = 3;
const K_SCAN: usize = 15;
/// Прямых `store.search` на половину узлового замера (без сети и без квоты find).
const K_DIRECT: usize = 25;
/// Пауза между парами сетевого замера, мс: держит темп под квотой §11.3.6 (5 find'ов/с на ключ).
const SCAN_PACE_MS: u64 = 500;
/// Ячейка «1.1k записей/узел» из §19.4.
const HEAVY: usize = 1_100;

// --- Замороженные пороги `E-0084`. Двигать задним числом нельзя; уточнение — только новым
// блоком «Поправка» в `lab/logs/e0084-all.log` и новым прогоном. Окна по отношениям выбраны так,
// чтобы предел воспроизводимости (правило 7) был ЗАМЕТНО уже окна: фактический разброс трёх
// калибровочных release-прогонов одного бинаря записан в блоке «КАЛИБРОВКА» того же лога и
// пересчитывается helper'ом на двух замороженных прогонах; ни одно окно не подгонялось под него.
//
// (3)…(8) — сама строка §19.4: «find end-to-end, p50 / p95 ≤ 1,5 с / ≤ 4 с»: (3)/(4) для
// fan-out 1, (7)/(8) для fan-out 13.
const ROW_P50_MS: f64 = 1_500.0;
const ROW_P95_MS: f64 = 4_000.0;
/// (5а)/(5б) — правило 7 (г): запас до гейта обязан быть не меньше удвоенного разброса ТОЙ
/// статистики, против которой стоит гейт (то же для fan-out 13 в (6а)/(6б)).
const MARGIN_VS_SPREAD_X: f64 = 2.0;
/// (9) цена холодного захода против тёплого того же фан-аута: интервал, в котором «discovery
/// дороже самого запроса» ещё не означает «discovery нелепо дорога».
const COLD_TO_WARM_MIN_X: f64 = 4.0;
const COLD_TO_WARM_MAX_X: f64 = 30.0;
/// (10) предельная цена дополнительного шарда, мс. Границы — `[0,5; 2,0] × poll_interval узла`
// (5 мс): иначе «фан-аут бесплатен» (поиск по 1 100 записей = 0,055 мс) или «цена линейна по
// числу шардов × RTT» не различались бы замером.
const MARGINAL_MIN_MS: f64 = 2.5;
const MARGINAL_MAX_MS: f64 = 10.0;
/// (11) отношение холодного фан-аута 13 к холодному фан-ауту 1: «13 RPC» по §19.5 — это не «13
/// последовательных RTT» (тогда было бы ≫ 13) и не «1 RPC» (тогда ≈ 1).
const FANOUT_RATIO_MIN_X: f64 = 6.0;
const FANOUT_RATIO_MAX_X: f64 = 13.0;
/// (12) доля внешней discovery в цене холодного фан-аута (доля, не промиле).
const SETUP_SHARE_MIN: f64 = 0.5;
const SETUP_SHARE_MAX: f64 = 1.0;
/// (15) доля узловой арифметики (`store.search` по 1 100 записей) в сетевом времени захода.
const SEARCH_SHARE_MAX: f64 = 0.05;
/// (14) отношение тяжёлой ячейки к лёгкой end-to-end (тот же агент, тот же узел, чередование).
const SCAN_RATIO_MIN_X: f64 = 1.4;
const SCAN_RATIO_MAX_X: f64 = 3.0;
/// (13) дрейф положения захода в тесте, промиле: больше — и числа описывают тест, а не строку.
const DRIFT_PROMIL_MAX: f64 = 200.0;

/// Временные гейты (`3`…`13`, `14`/`15`) применяются только в release — правило 6: профиль
/// является частью заморозки. В debug те же числа печатаются и только печатаются.
fn temporal_gates() -> bool {
    !cfg!(debug_assertions)
}

/// Один проверенный порог: имя, факт, истинность; в release истинность обязательна.
fn gate(name: &str, ok: bool) -> bool {
    println!("МЕРЕНО gate_{name}={}", if ok { 1 } else { 0 });
    if temporal_gates() {
        assert!(ok, "порог ({name}) не выполнен");
    }
    ok
}
/// Сид владельца записи шарда `s`. Различность обязательна: `Agent::find` склеивает ответы
/// шардов и дедуплицирует находки ПО ВЛАДЕЛЬЦУ (§11.3.2: живая запись у владельца одна), поэтому
/// три стенда с одним владельцем дали бы «1 находка из 13» при честных ответах всех узлов
/// (пилот `E-0084`). 160..=172 не заняты ни сидами узлов, ни агентами замеров.
fn owner_seed(shard: u16) -> u8 {
    160 + shard as u8
}
/// Узел шарда `s` подписан сидом `STAND_SEED_BASE + s`. Тринадцать узлов обязаны иметь
/// тринадцать РАЗНЫХ ключей: `handshake::verify` требует `cert.owner_ed25519 ==` ключ,
/// восстановленный из PeerId, поэтому два узла с одним сидом для агента — один и тот же пирам,
/// и «fan-out 13» сворачивается в фан-аут по трём соединениям (пилот `E-0084`: из 13 узлов
/// авторизовались ровно 3, а запросы к остальным уходили в таймаут и `NOT_OWNER`).
const STAND_SEED_BASE: u8 = 30;
/// Пул соседей по составу эпохи 1: не пересекается ни с сидами узлов, ни с авторитетами (1…5),
/// ни с владельцем записи.
const COMPANION_LOW: u8 = 100;
const COMPANION_HIGH: u8 = 250;

/// Каталог, удаляемый при выходе из scope (прецедент `DirGuard` из `E-0082`/`E-0083`).
struct DirGuard(PathBuf);

impl DirGuard {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("vecdht-net-e0084-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("временный каталог теста");
        Self(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

/// Конфиг сервиса узла — дословно как в `transport.rs`. Эти числа входят в структурный порог
/// (1), потому что именно они задают квант сетевой половины замера.
fn node_cfg(listen: Multiaddr) -> NetConfig {
    NetConfig {
        listen: vec![listen],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-net-e0084/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
    }
}

/// Конфиг агента — дефолты `AgentConfig` по таймаутам, кроме `call_timeout`: харнес
/// `transport.rs` ставит 40 с, и стенд обязан оставаться тем же стендом, иначе 4 с из строки
/// сравнивались бы с другим предельным терпением клиента.
fn agent_cfg(bootstrap: Vec<Multiaddr>) -> AgentConfig {
    AgentConfig {
        bootstrap,
        listen: vec![quic_addr()],
        call_timeout: Duration::from_secs(40),
        ..AgentConfig::default()
    }
}

fn agent_network() -> NetworkParams {
    NetworkParams::from_artifact(&reference_artifact()).expect("параметры артефакта")
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

fn now_bucket() -> u32 {
    Clock::at(now_sec()).bucket
}

/// Primary шарда стенда: свой ключ на каждый шард (см. `STAND_SEED_BASE`).
fn stand_seed(shard: u16) -> u8 {
    STAND_SEED_BASE + shard as u8
}

/// Состав эпохи 1, в котором `stand_seed(shard)` первый в порядке §9.3. Перебор детерминирован:
/// первые два соседа из пула, при которых `candidates::ordered` ставит нужный ключ на нулевую
/// позицию; `genesis_members` берёт roster целиком, поэтому состав = roster и `r` здесь 3.
fn stand_roster(shard: u16) -> [u8; 3] {
    let me = stand_seed(shard);
    let want = testing::identity(me).pubkey();
    for a in COMPANION_LOW..COMPANION_HIGH {
        for b in (a + 1)..=COMPANION_HIGH {
            let roster = [me, a, b];
            let order = candidates::ordered(1, shard, &testing::holders(&roster));
            if order[0].owner_ed25519 == want {
                return roster;
            }
        }
    }
    panic!("не найден состав шарда {shard}, где primary — сид {me}");
}

/// Узел шарда, принявший genesis эпохи 1 на текущем бакете, с `light`/`heavy` записями в
/// ячейках `shard * 16` и `shard * 16 + 1`.
fn open_node(shard: u16, dir: &Path, heavy: bool) -> ShardNode {
    let roster = stand_roster(shard);
    let id = testing::identity(stand_seed(shard));
    let peer = keys::peer_id(&id);
    let mut node = ShardNode::open(
        dir,
        shard,
        id,
        peer.to_bytes(),
        testing::params(POW),
        testing::authority_set(),
        testing::holders(&roster),
    )
    .expect("открыть узел шарда");
    let bucket = now_bucket();
    node.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(shard, &roster, 0)),
        testing::clock(bucket),
    )
    .expect("genesis");
    assert!(node.is_primary(), "узел стенда обязан быть primary своего шарда");
    // Порядок закладки — не косметика: бюджет приёма у узла ОДИН на все шарды (100 admits/с,
    // §11.3.4), и первая же heavy-секунда съедала токен лёгкой записи, из-за чего одна из 1100
    // отвергалась с `BUSY` (пилот `E-0084`: «ячейка 113 заполнена не ровно 1099/1100»).
    // Лёгкая запись уходит на секунду ПОСЛЕ тяжёлой ячейки.
    let base_sec = now_sec();
    if heavy {
        put(&mut node, shard, shard * 16 + 1, HEAVY, 0, base_sec);
        put(&mut node, shard, shard * 16, 1, owner_seed(shard), base_sec + (HEAVY as u64 / 100) + 1);
    } else {
        put(&mut node, shard, shard * 16, 1, owner_seed(shard), base_sec);
    }
    node
}

/// Живой путь приёма: кадр `Publish` (неподписанный — подпись в `Publish` опциональна, §5.3) в
/// `ShardNode::on_frame`. Владельцы тяжёлой ячейки синтетические: у `testing::identity` только
/// 256 ключей, а различие обязательно — `insert` дедуплицирует по `(owner, shard)` и при повторе
/// переезжает (ДИАГНОЗ-1 из `E-0079`). Секунда виртуальных часов растёт каждые 100 кадров, чтобы
/// узловой бюджет 100 admits/с (§11.3.4) не подменил собой измеряемую картину.
fn put(node: &mut ShardNode, shard: u16, cluster: u16, count: usize, owner_seed: u8, base_sec: u64) {
    for i in 0..count {
        let owner = if owner_seed != 0 {
            testing::identity(owner_seed).pubkey()
        } else {
            let mut o = [0u8; 32];
            o[0..8].copy_from_slice(&(((shard as u64) << 40) + i as u64).to_le_bytes());
            o[31] = 0xE8;
            o
        };
        let vec_q = if owner_seed != 0 {
            testing::vector(3)
        } else {
            let mut v = [0i8; vecdht_wire::DIM];
            // Первые две координаты кодируют `i` однозначно для `i < 1152`: без этого шаблон
            // `(k + i) mod 200` повторялся бы через 200 записей и «1 100 разных записей» были бы
            // 200 разными векторами (пилот `E-0084` потерял ровно одну запись без имени причины).
            for (k, x) in v.iter_mut().enumerate().skip(2) {
                *x = ((k as i32 + i as i32) % 200 - 100) as i8;
            }
            v[0] = (i % 128) as i8;
            v[1] = (i / 128) as i8;
            v
        };
        let sec = base_sec + (i as u64 / 100);
        let bucket = Clock::at(sec).bucket;
        let expires = bucket.saturating_add(TTL as u32);
        let intent = intent_id(&vec_q, testing::PREPROCESSING_VERSION);
        let input = pow_input(&owner, shard, 1, &intent, expires);
        let msg = Publish {
            preprocessing_version: testing::PREPROCESSING_VERSION,
            cluster_id: cluster,
            vec_q,
            owner_ed25519: owner,
            ttl_buckets: TTL,
            published_bucket: bucket,
            pow_bits: POW as u8,
            pow_nonce: testing::mine(&input, POW),
            intent_id: intent,
            tlv: Vec::new(),
        };
        let out = node
            .on_frame(owner, &msg.encode_unsigned(), Clock::at(sec))
            .expect("publish стенда принят");
        // `.expect()` ловит только `NodeError`; отказ протокола приходит КАДРОМ ошибки внутри
        // `Ok(..)` и иначе превращается в «записи не хватает» без имени причины (пилот `E-0084`:
        // 1099 из 1100 без объяснения).
        if let Some(e) = out
            .iter()
            .find(|e| decode_frame(&e.frame).map(|f| f.header.kind).ok() == Some(Kind::Error))
        {
            let err = ProtocolError::decode(&e.frame).expect("кадр ProtocolError разбирается");
            panic!(
                "publish #{i} в ячейку {cluster} отвергнут: {} (retry {} мс, шард {})",
                err.code, err.retry_after_ms, err.shard
            );
        }
    }
    assert_eq!(
        node.store.index.cluster_len(cluster),
        count,
        "ячейка {cluster} заполнена не ровно"
    );
}

/// Сервис узла поверх готового `ShardNode` (роль, кредашиал на свой шард, конфиг харнеса).
fn service_of(node: ShardNode, shard: u16) -> NetService {
    let seed = stand_seed(shard);
    assert_eq!(
        node.id.pubkey(),
        testing::identity(seed).pubkey(),
        "узел шарда {shard} открыт не тем ключом, который стенд ставит его primary"
    );
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let cert = testing::node_cert(seed, peer.to_bytes(), vec![shard], Role::IndexNode, 0, u32::MAX);
    NetService::new(
        id,
        Role::IndexNode,
        Some(cert),
        vec![node],
        testing::authority_set(),
        node_cfg(quic_addr()),
    )
    .expect("сервис узла")
}

/// Шагать каждый сервис, пока не поднимется слушатель; вернуть фактические адреса (порт выбирает
/// ОС). Делается ДО засечки: конструкция слушателей вне измеряемых интервалов.
async fn listen_of(services: &mut [NetService]) -> Vec<Multiaddr> {
    let mut out = Vec::with_capacity(services.len());
    for s in services.iter_mut() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(a) = s.listen_addrs().first() {
                out.push(a.clone());
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "слушатель узла не поднялся за 20 с; ошибки: {:?}",
                s.take_errors()
            );
            s.step().await;
        }
    }
    out
}

/// Внешняя копия предиката `Agent::covers` + `Agent::candidates` через публичный API: истинна
/// ровно тогда, когда `candidates(shard)` обязан вернуть непустой список, не дожидаясь Kademlia.
fn usable(net: &NetService, shard: u16) -> bool {
    net.authenticated_peers().into_iter().any(|p| {
        net.peer_identity(&p)
            .map(|w| w.role == Role::IndexNode && w.covers_shard(shard))
            .unwrap_or(false)
    })
}

async fn wait_usable(net: &mut NetService, shards: &[u16]) -> Duration {
    let t0 = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !shards.iter().all(|s| usable(net, *s)) {
        assert!(
            Instant::now() < deadline,
            "кандидаты не появились за 60 с; закрыты шарды {:?}, а всего authenticated {:?}",
            shards.iter().copied().filter(|s| !usable(net, *s)).collect::<Vec<_>>(),
            net.authenticated_peers().len()
        );
        net.step().await;
    }
    t0.elapsed()
}

/// Узел стенда на ОДИН заход: свой каталог, свой ключ, свой слушатель и своя задача `LocalSet`.
/// Узел закрывается (`close`) сразу после захода: при одном узле на все 21+9 заходов к концу
/// теста копились мёртвые соединения агентов и таблица приёма, и фазовая раскладка становилась
/// медленнее холодного find (`setup1 = 8,26 мс > cold1 = 6,29 мс` в пилоте) — то есть медиана
/// измеряла положение захода в тесте, а не строку спеки.
struct Episode {
    addrs: Vec<Multiaddr>,
    handle: tokio::task::JoinHandle<()>,
    dir: DirGuard,
}

impl Episode {
    async fn open(shard: u16, heavy: bool, name: &str) -> Self {
        let dir = DirGuard::new(name);
        let node = open_node(shard, dir.path(), heavy);
        let mut svc = service_of(node, shard);
        let addrs = listen_of(std::slice::from_mut(&mut svc)).await;
        let handle = tokio::task::spawn_local(svc.run());
        Self { addrs, handle, dir }
    }

    fn close(self) {
        self.handle.abort();
        let _ = std::fs::remove_dir_all(self.dir.path());
    }
}

/// Сколько шардов стенда агент видит держателями — диагностика фан-аута: если их меньше 13,
/// «fan-out 13» был бы фан-аутом по меньшему числу узлов (см. `STAND_SEED_BASE`).
fn covered_shards(net: &NetService, shards: &[u16]) -> Vec<u16> {
    shards.iter().copied().filter(|s| usable(net, *s)).collect()
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn sorted(v: &[Duration]) -> Vec<Duration> {
    let mut o = v.to_vec();
    o.sort();
    o
}

/// Квантиль по nearest-rank (`ceil(p·K)`): при малом K это максимум выборки.
fn quantile(v: &[Duration], p: f64) -> Duration {
    assert!(!v.is_empty(), "пустая выборка");
    let s = sorted(v);
    let rank = (p * s.len() as f64).ceil() as usize;
    s[rank.clamp(1, s.len()) - 1]
}

fn median(v: &[Duration]) -> Duration {
    quantile(v, 0.5)
}

/// Внутренний разброс выборки, промиле: `(max − min) / median`.
fn spread_promil(v: &[Duration]) -> f64 {
    let s = sorted(v);
    let m = median(&s).as_secs_f64().max(1e-12);
    (s[s.len() - 1].as_secs_f64() - s[0].as_secs_f64()) / m * 1000.0
}

fn rel_spread(v: &[Duration]) -> f64 {
    spread_promil(v) / 1000.0
}

/// Одна строка чисел: ключи ascii, единица в имени ключа (урок `E-0082` — экстрактор helper'а
/// не должен разбирать прозу). `argmax` — заход, отдавший максимум: без него нельзя отличить
/// «хвост распределения» от «первый заход платит за инициализацию».
fn print_row(label: &str, v: &[Duration]) {
    let s = sorted(v);
    let argmax = v
        .iter()
        .enumerate()
        .max_by_key(|(_, d)| *d)
        .map(|(i, _)| i)
        .unwrap_or(0);
    println!(
        "МЕРЕНО {label}_p50_ms={:.3} {label}_p95_ms={:.3} {label}_min_ms={:.3} {label}_max_ms={:.3} \
         {label}_spread_promil={:.1} {label}_k={} {label}_argmax={}",
        ms(median(&s)),
        ms(quantile(&s, 0.95)),
        ms(s[0]),
        ms(s[s.len() - 1]),
        spread_promil(&s),
        s.len(),
        argmax
    );
}

/// Медиана первой половины выборки против второй: положение захода в тесте не должно двигать
/// число (дрейф > 100 ‰ читается как «измеряется не строка спеки»).
fn drift_promil(v: &[Duration]) -> f64 {
    let half = v.len() / 2;
    (ms(median(&v[half..])) - ms(median(&v[..half]))) / ms(median(v)).max(1e-9) * 1000.0
}

/// (1) Структурный порог: величины, определяющие квант сетевой половины, берутся из того же
/// конфига, которым поднят стенд, а не из текста спеки. Профиль не влияет — гейт держится и в
/// debug, и в release.
#[test]
fn s19_structural_shape_of_the_stand() {
    let net = agent_network();
    let cfg = agent_cfg(Vec::new());
    let ncfg = node_cfg(quic_addr());
    println!(
        "МЕРЕНО nlist={} shards={} clusters_per_shard={} top_k_max={} nprobe_default={} \
         pow_bits_default={} agent_poll_ms={:.1} agent_call_timeout_ms={:.1} \
         agent_request_timeout_ms={:.1} node_poll_ms={:.1} node_request_timeout_ms={:.1} \
         stand_pow={POW} k_cold={K_COLD} k_fanout={K_FANOUT} k_phase={K_PHASE} k_warm={K_WARM} \
         k_scan={K_SCAN} heavy={HEAVY} fanout={FANOUT}",
        net.nlist,
        net.shards,
        net.clusters_per_shard,
        net.top_k_max,
        net.nprobe_default,
        net.pow_bits_default,
        ms(cfg.poll_interval),
        ms(cfg.call_timeout),
        ms(cfg.request_timeout),
        ms(ncfg.poll_interval),
        ms(ncfg.request_timeout),
    );
    // (1а) Маршрут: 13 кластеров, взятых по одному из начала разных шардов, обязаны распасться
    // ровно на 13 шардов — иначе «fan-out 13» был бы fan-out 1 под другим именем.
    let clusters: Vec<u16> = (0..FANOUT).map(|s| s * 16).collect();
    let shards: Vec<u16> = clusters
        .iter()
        .map(|c| net.shard_of_cluster(*c).expect("кластер внутри nlist"))
        .collect();
    let mut distinct = shards.clone();
    distinct.dedup();
    println!("МЕРЕНО query_clusters={} query_shards_distinct={}", clusters.len(), distinct.len());
    assert_eq!(distinct.len(), FANOUT as usize, "13 кластеров легли не в 13 шардов: {shards:?}");
    assert_eq!(net.nlist, 1024, "nlist артефакта уехал из-под строки §19.4");
    assert_eq!(net.shards, 64, "S артефакта уехал из-под строки §19.4");
    assert_eq!(net.clusters_per_shard, 16, "clusters_per_shard обязан оставаться 16 (§7.4.1)");
    // (1б) Кванты стенда: если дефолт уедет, числа этого оракула станут про другого клиента —
    // об этом должна крикнуть сборка, а не отчёт.
    assert_eq!(cfg.poll_interval, Duration::from_millis(25), "poll_interval агента уехал из харнеса");
    assert_eq!(cfg.call_timeout, Duration::from_millis(40_000), "call_timeout стенда уехал");
    assert_eq!(cfg.request_timeout, Duration::from_millis(10_000), "request_timeout агента уехал");
    assert_eq!(ncfg.poll_interval, Duration::from_millis(5), "poll_interval узла уехал");
    assert_eq!(ncfg.request_timeout, Duration::from_secs(5), "request_timeout узла уехал");
    // (1в) Квоты приёма узла — это темп стенда, а не предмет замера: зная их, видно, сколько
    // заходов в секунду оракул имеет право делать на одном ключевом агенте.
    let p = testing::params(POW);
    println!(
        "МЕРЕНО per_peer_find_rps={} per_peer_publish_rps={} per_peer_publish_burst={} \
         node_admits_per_s={} top_k_max_param={} lease_buckets={}",
        p.per_peer_find_rps,
        p.per_peer_publish_rps,
        p.per_peer_publish_burst,
        p.node_admits_per_s,
        p.top_k_max,
        p.lease_buckets
    );
    assert_eq!(p.per_peer_find_rps, 5, "квота find на ключ уехала — темп стенда пересчитать");
    assert_eq!(p.node_admits_per_s, 100, "узловой бюджет приёма уехал — закладка ячеек пересчитать");
    assert_eq!(p.lease_buckets, 6, "lease уехал — виртуальные секунды закладки могут в него не влезть");
    println!("МЕРЕНО e2e_struct_ok=1");
}

/// (2а), (3)…(5б), (13) Холодный и тёплый `find` при fan-out 1 плюс раскладка по фазам.
#[test]
fn s19_cold_and_warm_find_fanout1() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let local = LocalSet::new();
        local
            .run_until(async {
                let mut cold = Vec::new();
                let mut find_only = Vec::new();
                let mut new_only = Vec::new();
                let mut setup = Vec::new();
                let mut find_after_setup = Vec::new();
                let mut warm = Vec::new();
                let mut provider_seen = Vec::new();

                for i in 0..K_COLD {
                    let ep = Episode::open(SHARD, false, &format!("cold-{i}")).await;
                    let seed = 200 + (i as u8) % 50;
                    let q = FindQuery::new(testing::vector(3), vec![CLUSTER], 16);
                    let t0 = Instant::now();
                    let mut finder =
                        Agent::new(testing::identity(seed), agent_network(), agent_cfg(ep.addrs.clone()))
                            .expect("агент");
                    let t_new = t0.elapsed();
                    let t1 = Instant::now();
                    let outcome = finder.find(&q).await.expect("холодный find");
                    let t_find = t1.elapsed();
                    assert!(outcome.failures.is_empty(), "отказы шардов: {:?}", outcome.failures);
                    assert_eq!(outcome.matches.len(), 1, "запись стенда обязана найтись");
                    assert!(outcome.matches[0].grant.is_some(), "приём на найденную запись выдан");
                    provider_seen.push(finder.net().provider_peers(SHARD).len());
                    cold.push(t_new + t_find);
                    find_only.push(t_find);
                    new_only.push(t_new);

                    for w in 0..K_WARM {
                        let t = Instant::now();
                        let o = finder.find(&q).await.expect("тёплый find");
                        assert!(o.failures.is_empty(), "тёплый заход {w} отвергнут: {:?}", o.failures);
                        assert_eq!(o.matches.len(), 1, "тёплый заход {w} потерял запись");
                        warm.push(t.elapsed());
                    }
                    drop(finder);
                    ep.close();
                }

                // Фазовая раскладка: конструкция + discovery до кандидата, затем отдельный
                // запрос уже разогретого агента. Это не тот же агент, что в тёплой ветви выше:
                // там после холодного find прогрет и кеш `known_epoch`, и узловая таблица приёма.
                for i in 0..K_PHASE {
                    let ep = Episode::open(SHARD, false, &format!("phase-{i}")).await;
                    let q = FindQuery::new(testing::vector(3), vec![CLUSTER], 16);
                    let t0 = Instant::now();
                    let mut f = Agent::new(
                        testing::identity(150 + i as u8),
                        agent_network(),
                        agent_cfg(ep.addrs.clone()),
                    )
                    .expect("агент для фазового замера");
                    let t_setup = wait_usable(f.net_mut(), &[SHARD]).await;
                    setup.push(t0.elapsed() + t_setup);
                    let t = Instant::now();
                    let o = f.find(&q).await.expect("find после discovery");
                    assert!(o.failures.is_empty(), "find после discovery отвергнут: {:?}", o.failures);
                    assert_eq!(o.matches.len(), 1);
                    find_after_setup.push(t.elapsed());
                    drop(f);
                    ep.close();
                }

                print_row("cold1", &cold);
                print_row("find1", &find_only);
                print_row("new1", &new_only);
                print_row("setup1", &setup);
                print_row("phasewarm1", &find_after_setup);
                print_row("warm1", &warm);
                // Контроль дрейфа: медиана первой и второй половины одних и тех же заходов. Если
                // положение в тесте двигает число, отношения ниже читать нельзя (правило 7).
                let half = cold.len() / 2;
                println!(
                    "МЕРЕНО cold1_first_half_p50_ms={:.3} cold1_second_half_p50_ms={:.3} \
                     cold1_drift_promil={:.1} warm1_drift_promil={:.1} setup1_drift_promil={:.1}",
                    ms(median(&cold[..half])),
                    ms(median(&cold[half..])),
                    drift_promil(&cold),
                    drift_promil(&warm),
                    drift_promil(&setup)
                );
                let c50 = ms(median(&cold));
                let w50 = ms(median(&warm));
                println!(
                    "МЕРЕНО provider_seen_min={} provider_seen_max={} cold1_to_warm1_x={:.3} \
                     setup1_to_cold1_x={:.3} warm1_to_cold1_x={:.3} phasewarm1_to_cold1_x={:.3} \
                     new1_share_promil={:.1} rel_spread_cold1={:.4} rel_spread_warm1={:.4} \
                     rel_spread_setup1={:.4}",
                    provider_seen.iter().min().copied().unwrap_or(0),
                    provider_seen.iter().max().copied().unwrap_or(0),
                    c50 / w50,
                    ms(median(&setup)) / c50,
                    w50 / c50,
                    ms(median(&find_after_setup)) / c50,
                    ms(median(&new_only)) / c50 * 1000.0,
                    rel_spread(&cold),
                    rel_spread(&warm),
                    rel_spread(&setup)
                );
                // Правило 7 (г): запас обязан сравниваться с разбросом ТОЙ статистики, против
                // которой стоит гейт.
                let margin_p50 = ROW_P50_MS / c50 - 1.0;
                let margin_p95 = ROW_P95_MS / ms(quantile(&cold, 0.95)) - 1.0;
                let rs = rel_spread(&cold);
                println!(
                    "МЕРЕНО cold1_margin_p50_x={margin_p50:.3} cold1_margin_p95_x={margin_p95:.3} \
                     row_p50_ms={ROW_P50_MS} row_p95_ms={ROW_P95_MS} margin_vs_spread_x={MARGIN_VS_SPREAD_X} \
                     drift_promil_max={DRIFT_PROMIL_MAX}"
                );
                // (3) строка §19.4 по p50 на холодном заходе одного шарда;
                // (4) то же по p95; (5а) правило 7; (13) дрейф положения захода.
                gate("3_cold1_p50_le_row", c50 <= ROW_P50_MS);
                gate("4_cold1_p95_le_row", ms(quantile(&cold, 0.95)) <= ROW_P95_MS);
                gate("5a_cold1_margin_p50", margin_p50 >= MARGIN_VS_SPREAD_X * rs);
                gate(
                    "5b_cold1_margin_p95",
                    margin_p95 >= MARGIN_VS_SPREAD_X * rel_spread(&cold),
                );
                gate("13a_drift_cold1", drift_promil(&cold).abs() <= DRIFT_PROMIL_MAX);
                gate("13b_drift_warm1", drift_promil(&warm).abs() <= DRIFT_PROMIL_MAX);
                // (2а) ОГРАНИЧЕНИЕ СТЕНДА, а не свойство кода: `provider_seen` обязан остаться
                // нулём, иначе «цена find» на этом стенде включала бы Kademlia-поиск провайдеров,
                // которого в бою может не быть (и наоборот — стенд перестал бы быть стендом).
                gate("2a_provider_seen_zero", provider_seen.iter().max().copied().unwrap_or(0) == 0);
                // (6-одна) холоднее тёплого ровно на discovery: отношение для одного шарда
                // вне замороженного окна фан-аута, поэтому только печатается.
            })
            .await;
    });
}

/// (14)/(15) Доля узловой арифметики: чередующиеся лёгкий и тяжёлый заходы на одном агенте и одном
/// узле; чередование убирает дрейф хоста из отношения (правило 7).
#[test]
fn s19_scan_share_in_end_to_end_time() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    // Медианы сетевого захода нужны и после `block_on`: порог (15) сравнивает узловую арифметику
    // с сетевым временем этого же окна, а не с числом из соседнего теста.
    let mut net_light_p50_ms = 0.0f64;
    let mut net_heavy_p50_ms = 0.0f64;
    rt.block_on(async {
        let local = LocalSet::new();
        local
            .run_until(async {
                let d = DirGuard::new("scan-share");
                let node = open_node(SHARD, d.path(), true);
                let mut svc = service_of(node, SHARD);
                let addrs = listen_of(std::slice::from_mut(&mut svc)).await;
                local.spawn_local(svc.run());

                let light_q = FindQuery::new(testing::vector(3), vec![CLUSTER], 16);
                let heavy_q = FindQuery::new(testing::vector(3), vec![CLUSTER + 1], 16);
                let mut finder =
                    Agent::new(testing::identity(199), agent_network(), agent_cfg(addrs)).expect("агент");
                let _ = finder.find(&light_q).await.expect("разогрев лёгкий");
                let _ = finder.find(&heavy_q).await.expect("разогрев тяжёлый");

                // Квота §11.3.6 — 5 find'ов в секунду на транспортный ключ узла. Замеры идут
                // парами (лёгкий/тяжёлый) с паузой: без неё четвёртый и пятый заход той же секунды
                // получали `QUOTA_FIND`, а `find` отдаёт пустой список НЕ как ошибку — в пилоте
                // это выглядело как «тяжёлая ячейка отдала 0 из 16». Темп части стенда, а не
                // предмета замера; длительность захода измеряется внутри `t.elapsed()`.
                let mut light = Vec::new();
                let mut heavy = Vec::new();
                for _ in 0..K_SCAN {
                    tokio::time::sleep(Duration::from_millis(SCAN_PACE_MS)).await;
                    let t = Instant::now();
                    let o = finder.find(&light_q).await.expect("лёгкий find");
                    assert!(o.failures.is_empty(), "лёгкий find отвергнут: {:?}", o.failures);
                    assert_eq!(o.matches.len(), 1, "лёгкая ячейка отдала не одну запись");
                    light.push(t.elapsed());

                    let t = Instant::now();
                    let o = finder.find(&heavy_q).await.expect("тяжёлый find");
                    assert!(o.failures.is_empty(), "тяжёлый find отвергнут: {:?}", o.failures);
                    assert_eq!(o.matches.len(), 16, "тяжёлая ячейка не отдала потолок top_k");
                    heavy.push(t.elapsed());
                }
                print_row("scanlight", &light);
                print_row("scanheavy", &heavy);
                net_light_p50_ms = ms(median(&light));
                net_heavy_p50_ms = ms(median(&heavy));
                println!(
                    "МЕРЕНО scan_ratio_x={:.4} scan_delta_ms={:.3} rel_spread_scanlight={:.4} \
                     rel_spread_scanheavy={:.4}",
                    ms(median(&heavy)) / ms(median(&light)),
                    ms(median(&heavy)) - ms(median(&light)),
                    rel_spread(&light),
                    rel_spread(&heavy)
                );
            })
            .await;
    });

    // Узловая половина без сети: `ShardStore::search` тем же вектором по той же ячейке.
    let d = DirGuard::new("scan-direct");
    let node = open_node(SHARD, d.path(), true);
    let q = testing::vector(3);
    let mut light = Vec::new();
    let mut heavy = Vec::new();
    for _ in 0..K_DIRECT {
        let t = Instant::now();
        let hits = node.store.search(&q, &[CLUSTER], 16);
        assert_eq!(hits.len(), 1, "прямой скан лёгкой ячейки");
        light.push(t.elapsed());

        let t = Instant::now();
        let hits = node.store.search(&q, &[CLUSTER + 1], 16);
        assert_eq!(hits.len(), 16, "прямой скан тяжёлой ячейки упёрся в top_k");
        heavy.push(t.elapsed());
    }
    let share = us(median(&heavy)) / 1000.0 / net_heavy_p50_ms;
    println!(
        "МЕРЕНО direct_search_light_p50_us={:.3} direct_search_heavy_p50_us={:.3} \
         direct_search_ratio_x={:.1} heavy_cell={HEAVY} direct_per_record_us={:.5} \
         direct_light_below_clock_us={} net_heavy_p50_ms={:.3} search_share={:.5}",
        us(median(&light)),
        us(median(&heavy)),
        us(median(&heavy)) / us(median(&light)),
        us(median(&heavy)) / HEAVY as f64,
        // Лёгкий прямой скан лежит на разрешении таймера (доли микросекунды): его отношение
        // печатается, но порогом не является — иначе окно воспроизводилось бы квантом часов.
        if us(median(&light)) < 1.0 { 1 } else { 0 },
        net_heavy_p50_ms,
        share
    );
    // (14) тяжёлая ячейка end-to-end дороже лёгкой, но не в разы: сеть и кванты опроса шумят
    // сильнее, чем 1 100 записей.
    gate(
        "14_scan_ratio_window",
        net_heavy_p50_ms / net_light_p50_ms >= SCAN_RATIO_MIN_X
            && net_heavy_p50_ms / net_light_p50_ms <= SCAN_RATIO_MAX_X,
    );
    // (15) арифметика узла — малая доля end-to-end времени: строка §19.4 «find» на этом стенде
    // не про поиск по векторам, а про транспорт и discovery.
    gate("15_search_share_le", share <= SEARCH_SHARE_MAX);
}

/// (2б), (6)…(13) Fan-out 13: 13 узлов на 13 шардов, один запрос по 13 кластерам.
#[test]
fn s19_fanout13_find_price() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let local = LocalSet::new();
        local
            .run_until(async {
                // Различность ключей стенда — условие, а не деталь: два узла с одним сидом для
                // агента один пирам (handshake привязывает кредашиал к транспортному ключу).
                let mut seeds: Vec<u8> = (0..FANOUT).map(stand_seed).collect();
                let n_seeds = seeds.len();
                seeds.sort_unstable();
                seeds.dedup();
                println!("МЕРЕНО stand_nodes={n_seeds} stand_seeds_distinct={}", seeds.len());
                assert_eq!(seeds.len(), FANOUT as usize, "узлы стенда не различаются ключом");
                let mut dirs = Vec::new();
                let mut services = Vec::new();
                let mut shards = Vec::new();
                for s in 0..FANOUT {
                    let shard = s;
                    dirs.push(DirGuard::new(&format!("fan13-{shard}")));
                    let node = open_node(shard, dirs.last().unwrap().path(), false);
                    services.push(service_of(node, shard));
                    shards.push(shard);
                }
                let addrs = listen_of(&mut services).await;
                for svc in services {
                    local.spawn_local(svc.run());
                }

                let clusters: Vec<u16> = (0..FANOUT).map(|s| s * 16).collect();
                let q = FindQuery::new(testing::vector(3), clusters.clone(), 16);

                let mut cold = Vec::new();
                let mut find_only = Vec::new();
                let mut new_only = Vec::new();
                let mut warm = Vec::new();
                let mut answers = Vec::new();
                for i in 0..K_FANOUT {
                    let t0 = Instant::now();
                    let mut finder =
                        Agent::new(testing::identity(120 + i as u8), agent_network(), agent_cfg(addrs.clone()))
                            .expect("агент");
                    let t_new = t0.elapsed();
                    let t1 = Instant::now();
                    let outcome = finder.find(&q).await.expect("холодный fan-out find");
                    let t_find = t1.elapsed();
                    assert!(outcome.failures.is_empty(), "отказы шардов: {:?}", outcome.failures);
                    assert_eq!(outcome.answers.len(), FANOUT as usize, "не все шарды ответили");
                    assert_eq!(outcome.matches.len(), FANOUT as usize, "не все записи нашлись");
                    answers.push(outcome.answers.len());
                    cold.push(t_new + t_find);
                    find_only.push(t_find);
                    new_only.push(t_new);
                    for w in 0..K_WARM {
                        let t = Instant::now();
                        let o = finder.find(&q).await.expect("тёплый fan-out find");
                        assert!(o.failures.is_empty(), "тёплый заход {w} отвергнут: {:?}", o.failures);
                        assert_eq!(o.matches.len(), FANOUT as usize, "тёплый заход {w} потерял запись");
                        warm.push(t.elapsed());
                    }
                }

                // Один шард в том же тесте — знаменатель отношения фан-аута, чтобы оно
                // считалось внутри одного окна хоста, а не из соседнего теста.
                let q1 = FindQuery::new(testing::vector(3), vec![CLUSTER], 16);
                let mut one = Vec::new();
                for i in 0..K_FANOUT {
                    let t0 = Instant::now();
                    let mut f = Agent::new(
                        testing::identity(60 + i as u8),
                        agent_network(),
                        agent_cfg(vec![addrs[SHARD as usize].clone()]),
                    )
                    .expect("агент одного шарда");
                    let o = f.find(&q1).await.expect("find одного шарда");
                    assert!(o.failures.is_empty(), "референс одного шарда отвергнут: {:?}", o.failures);
                    assert_eq!(o.matches.len(), 1);
                    one.push(t0.elapsed());
                }

                // Фазовая раскладка фан-аута: 13 handshake'ей до первого кандидата.
                let mut setup = Vec::new();
                let mut covered = Vec::new();
                for i in 0..K_PHASE.min(K_FANOUT) {
                    let t0 = Instant::now();
                    let mut f = Agent::new(
                        testing::identity(90 + i as u8),
                        agent_network(),
                        agent_cfg(addrs.clone()),
                    )
                    .expect("агент фазы");
                    let _ = wait_usable(f.net_mut(), &shards).await;
                    covered.push(covered_shards(f.net(), &shards).len());
                    setup.push(t0.elapsed());
                    drop(f);
                }

                print_row("cold13", &cold);
                print_row("find13", &find_only);
                print_row("warm13", &warm);
                print_row("one13ref", &one);
                print_row("setup13", &setup);
                let h13 = cold.len() / 2;
                println!(
                    "МЕРЕНО cold13_first_half_p50_ms={:.3} cold13_second_half_p50_ms={:.3} \
                     cold13_drift_promil={:.1} warm13_drift_promil={:.1} one13_drift_promil={:.1} \
                     covered_shards_min={} covered_shards_max={}",
                    ms(median(&cold[..h13])),
                    ms(median(&cold[h13..])),
                    drift_promil(&cold),
                    drift_promil(&warm),
                    drift_promil(&one),
                    covered.iter().min().copied().unwrap_or(0),
                    covered.iter().max().copied().unwrap_or(0),
                );
                let c13 = ms(median(&cold));
                let c1 = ms(median(&one));
                println!(
                    "МЕРЕНО answers_min={} answers_max={} fanout13_to_one_x={:.3} \
                     per_shard_marginal_ms={:.3} cold13_to_warm13_x={:.3} setup13_to_cold13_x={:.3} \
                     rel_spread_cold13={:.4} rel_spread_warm13={:.4} rel_spread_cold1_ref={:.4} \
                     fanout13_p95_is_max={}",
                    answers.iter().min().copied().unwrap_or(0),
                    answers.iter().max().copied().unwrap_or(0),
                    c13 / c1,
                    (c13 - c1) / (FANOUT as f64 - 1.0),
                    c13 / ms(median(&warm)),
                    ms(median(&setup)) / c13,
                    rel_spread(&cold),
                    rel_spread(&warm),
                    rel_spread(&one),
                    if K_FANOUT < 20 { 1 } else { 0 }
                );
                let margin_p50 = ROW_P50_MS / c13 - 1.0;
                let margin_p95 = ROW_P95_MS / ms(quantile(&cold, 0.95)) - 1.0;
                let rs = rel_spread(&cold);
                let ratio = c13 / c1;
                let marginal = (c13 - c1) / (FANOUT as f64 - 1.0);
                let setup_share = ms(median(&setup)) / c13;
                let cold_warm = c13 / ms(median(&warm));
                println!(
                    "МЕРЕНО cold13_margin_p50_x={margin_p50:.3} cold13_margin_p95_x={margin_p95:.3}"
                );
                // (2б) стенд честен: все 13 шардов ответили и все 13 видны держателями.
                gate(
                    "2b_all_shards_answered",
                    answers.iter().min().copied().unwrap_or(0) == FANOUT as usize
                        && covered.iter().min().copied().unwrap_or(0) == FANOUT as usize
                        && covered.iter().max().copied().unwrap_or(0) == FANOUT as usize,
                );
                // (7)/(8) строка §19.4 на том фан-ауте, который под ней подразумевается (§19.5:
                // ~13 RPC на запрос), плюс правило 7 к её же разбросу.
                gate("7_cold13_p50_le_row", c13 <= ROW_P50_MS);
                gate("8_cold13_p95_le_row", ms(quantile(&cold, 0.95)) <= ROW_P95_MS);
                gate("6a_cold13_margin_p50", margin_p50 >= MARGIN_VS_SPREAD_X * rs);
                gate(
                    "6b_cold13_margin_p95",
                    margin_p95 >= MARGIN_VS_SPREAD_X * rel_spread(&cold),
                );
                // (9) холод дороже тёплого в окно `[4; 30]`: ниже — discovery не доминирует (и
                // строка измеряется один раз, а не дважды), выше — стенд разваливается.
                gate(
                    "9_cold13_to_warm13_window",
                    (COLD_TO_WARM_MIN_X..=COLD_TO_WARM_MAX_X).contains(&cold_warm),
                );
                // (10) предельная цена шарда в окне «квант опроса узла», а не «поиск» и не «RTT».
                gate(
                    "10_marginal_per_shard_window",
                    (MARGINAL_MIN_MS..=MARGINAL_MAX_MS).contains(&marginal),
                );
                // (11) отношение фан-аута 13 к фан-ауту 1.
                gate(
                    "11_fanout_ratio_window",
                    (FANOUT_RATIO_MIN_X..=FANOUT_RATIO_MAX_X).contains(&ratio),
                );
                // (12) discovery-помпа обязана объяснять бо́льшую часть cold13, но не превышать
                // его (помпа грубее событийного цикла `find`, и это граница инструмента).
                gate(
                    "12_setup_share_window",
                    (SETUP_SHARE_MIN..=SETUP_SHARE_MAX).contains(&setup_share),
                );
                // (13) дрейф положения захода.
                gate("13a_drift_cold13", drift_promil(&cold).abs() <= DRIFT_PROMIL_MAX);
                gate("13b_drift_warm13", drift_promil(&warm).abs() <= DRIFT_PROMIL_MAX);
                gate("13c_drift_one_ref", drift_promil(&one).abs() <= DRIFT_PROMIL_MAX);
            })
            .await;
    });
}
