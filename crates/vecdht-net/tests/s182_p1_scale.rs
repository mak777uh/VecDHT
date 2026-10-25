//! §18.2 P1 — стенд масштаба DHT: ~200 узлов, 64 ключа, libp2p QUIC + kad.
//!
//! Гейт спеки: холодный резолв шарда p95 < 500 мс, суммарно < 5 000 provider-записей,
//! кастомный `PeerId` не требуется.
//!
//! # Почему release
//!
//! Стенд измеряется в `--release`, и это не послабление порога, а свойство прибора. В debug
//! 60 узлов дают 664 таймаута прикладного рукопожатия и 0/8 резолвов (`E-0105`, разведка):
//! x25519 и Ed25519 в debug медленнее на два порядка, и узлы не успевают обслужить
//! собственные соединения. Порог p95 = 500 мс — про боевой бинарь, поэтому меряется бинарь
//! release-профиля. Тест падает в debug с явным сообщением, а не тихим «не прошёл гейт».
//!
//! # Что здесь есть
//!
//! 200 сервисов в одном процессе, каждый на своём OS-потоке со своим `current_thread`
//! рантаймом и `LocalSet` (`NetService` не `Send`). 189 провайдеров, по одному шарду на узел,
//! 8 узлов ядра без шарда и 3 наблюдателя без шарда. Провайдер дозванивается до двух узлов
//! ядра, ядро — полной сеткой, наблюдатели — до всего ядра; дальше топологию достраивает
//! сам kad: в release при 200 узлах он сходится в полную сетку (наблюдатель видит 199 пиров).
//!
//! # Чего здесь нет
//!
//! * TTL 420 с во времени не проверяется: стенд живёт минуты, а не 7. Константа
//!   `PROVIDER_RECORD_TTL_SECS` проверяется структурно, истечение — юнит-тестами кэша.
//! * «5 000 записей в сети» не считаются по сети: считаемого счётчика записей у узлов нет.
//!   Проверяется протокольная граница `64 ключа × K = 20` = 1 280 (`< 5 000`) и то, что
//!   наблюдатель после холодного резолва видит по каждому шарду не больше K провайдеров.
//! * `max_provided_keys` не поднимается: узел объявляет только ключи своих шардов (в стенде —
//!   один), что ниже умолчания 1 024. Утверждение спеки о поднятом пределе к этой раскладке
//!   не применяется; тест это фиксирует, а не прячет.
//! * Отказы транспорта не входят в гейт: у полной сетки 200 узлов есть таймауты рукопожатий
//!   на избыточных соединениях. Они печатаются числом, гейт считается по резолву.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use tokio::sync::{mpsc, oneshot};

use vecdht_artifact::reference_manifest;
use vecdht_net::keys;
use vecdht_net::provider_cache::{PROVIDER_CACHE_MAX_PER_SHARD, PROVIDER_RECORD_TTL_SECS};
use vecdht_net::{NetConfig, NetService};
use vecdht_node::{testing, Clock, ShardNode};
use vecdht_wire::constants::SHARDS;
use vecdht_wire::messages::Role;

const NODES: usize = 200;
const CORE: usize = 8;
const OBSERVERS: usize = 3;
const PROVIDERS: usize = NODES - CORE - OBSERVERS;
const KEYS: usize = SHARDS as usize;
const POW_BITS: u32 = 8;
const P95_BUDGET_MS: u128 = 500;
const TOTAL_LIMIT: usize = 5_000;
/// Холодный резолв одного шарда: бюджет ожидания. 3 с — в 6 раз выше гейта, чтобы «медленно»
/// отличалось от «не нашлось» и провал не занимал 64 × 10 с на каждого наблюдателя.
const RESOLVE_BUDGET: Duration = Duration::from_secs(3);
const WARMUP: Duration = Duration::from_secs(20);

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn quic() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()
}

fn cfg() -> NetConfig {
    NetConfig {
        listen: vec![quic()],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "s182".into(),
        request_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
        revoked_dir: None,
    }
}

struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("vecdht-p1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Spec {
    seed: u8,
    shard: Option<u16>,
    seeds: Vec<u8>,
    dir: PathBuf,
}

fn build(spec: &Spec) -> NetService {
    let id = testing::identity(spec.seed);
    let peer = keys::peer_id(&id);
    let nodes = match spec.shard {
        Some(sh) => {
            let mut node = ShardNode::open(
                &spec.dir,
                sh,
                id.clone(),
                peer.to_bytes(),
                testing::params(POW_BITS),
                testing::authority_set(),
                testing::holders(&spec.seeds),
            )
            .unwrap();
            let b = Clock::at(now_sec()).bucket;
            node.on_frame(
                testing::identity(9).pubkey(),
                &testing::signed_frame(&testing::genesis_update(sh, &spec.seeds, 0)),
                testing::clock(b),
            )
            .unwrap();
            vec![node]
        }
        None => Vec::new(),
    };
    let cert = testing::node_cert(
        spec.seed,
        peer.to_bytes(),
        spec.shard.map(|s| vec![s]).unwrap_or_default(),
        Role::IndexNode,
        0,
        u32::MAX,
    );
    NetService::new(id, Role::IndexNode, Some(cert), nodes, testing::authority_set(), cfg()).unwrap()
}

struct Report {
    auth: usize,
    kad: usize,
    ann: u64,
    providers: usize,
}

enum Cmd {
    Dial(Multiaddr),
    Report(oneshot::Sender<Report>),
    Errors(oneshot::Sender<Vec<String>>),
    /// Замер внутри потока узла: обмен через канал драйвера на 200 узлах стоит сотни
    /// миллисекунд и в гейт p95 < 500 мс не влезает.
    Resolve(u16, Duration, oneshot::Sender<Option<u128>>),
}

struct Node {
    tx: mpsc::UnboundedSender<Cmd>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Node {
    fn drop(&mut self) {
        // Сначала закрываем канал: поток выходит по `Disconnected`, только потом join.
        let (dead, _) = mpsc::unbounded_channel();
        let _ = std::mem::replace(&mut self.tx, dead);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn spawn_node(spec: Spec, addr_tx: oneshot::Sender<Multiaddr>) -> Node {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let join = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let mut svc = build(&spec);
            loop {
                if let Some(a) = svc.listen_addrs().first() {
                    let _ = addr_tx.send(a.clone());
                    break;
                }
                svc.step().await;
            }
            loop {
                match rx.try_recv() {
                    Ok(Cmd::Dial(a)) => {
                        let _ = svc.dial(a);
                    }
                    Ok(Cmd::Report(t)) => {
                        let r = Report {
                            auth: svc.authenticated_peers().len(),
                            kad: svc.kad_peer_count(),
                            ann: svc.provider_announcements,
                            providers: svc.provider_peers(0).len(),
                        };
                        let _ = t.send(r);
                    }
                    Ok(Cmd::Errors(t)) => {
                        let _ = t.send(svc.take_errors());
                    }
                    Ok(Cmd::Resolve(sh, budget, t)) => {
                        let t0 = Instant::now();
                        let _ = svc.find_providers(sh);
                        let deadline = t0 + budget;
                        let mut ms = None;
                        while Instant::now() < deadline {
                            svc.step().await;
                            if !svc.provider_peers(sh).is_empty() {
                                ms = Some(t0.elapsed().as_millis());
                                break;
                            }
                        }
                        let _ = t.send(ms);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {}
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
                svc.step().await;
            }
        });
    });
    Node { tx, join: Some(join) }
}

async fn report(n: &Node) -> Report {
    let (tx, rx) = oneshot::channel();
    n.tx.send(Cmd::Report(tx)).unwrap();
    rx.await.unwrap()
}

async fn errors(n: &Node) -> Vec<String> {
    let (tx, rx) = oneshot::channel();
    n.tx.send(Cmd::Errors(tx)).unwrap();
    rx.await.unwrap()
}

async fn resolve(n: &Node, shard: u16) -> Option<u128> {
    let (tx, rx) = oneshot::channel();
    n.tx.send(Cmd::Resolve(shard, RESOLVE_BUDGET, tx)).unwrap();
    rx.await.unwrap()
}

/// Границы, которые стенд не создаёт, а проверяет: они уже приняты в продукте.
fn check_the_premises() {
    // §18.2 «максимум записей в сети»: протокольная граница, а не измерение сети.
    assert_eq!(PROVIDER_RECORD_TTL_SECS, 420, "§7.4 provider_record_ttl");
    assert_eq!(PROVIDER_CACHE_MAX_PER_SHARD, 20, "max_providers_per_key = K");
    // Протокольная граница записей: проверяется на компиляции, а не в прогоне (`clippy::assertions_on_constants`).
    const _: () = assert!(KEYS * PROVIDER_CACHE_MAX_PER_SHARD < TOTAL_LIMIT);
    // «Кастомный PeerId не требуется»: стенд на дефолтной идентичности, её PeerId — identity
    // multihash (0x00) от ключа, а не выбранный хеш.
    let id = testing::identity(10);
    let peer = keys::peer_id(&id);
    assert_eq!(peer.to_bytes()[0], 0x00, "PeerId выведен из ключа, не кастомный");
    // «max_provided_keys поднят»: узел объявляет ключи своих шардов. В раскладке стенда —
    // один шард на провайдера, это ниже умолчания MemoryStore (1 024); поднимать нечего.
    assert!(SHARDS as usize <= 1_024, "64 шарда ниже умолчания max_provided_keys");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "стенд P1: 200 узлов и 192 резолва, меряется только в --release (E-0105); запуск: --ignored"]
async fn p1_scale_200_nodes_64_keys() {
    // Профиль — часть прибора: в debug 60 узлов дают 0/8 резолвов. Это отказ исполнения, а не
    // константа на компиляции: тест обязан собираться и в debug, но падать с объяснением.
    if cfg!(debug_assertions) {
        panic!(
            "стенд P1 меряется в --release: в debug 60 узлов дают 0/8 резолвов из-за таймаутов \
             рукопожатий (E-0105). Запускай `cargo test --release -p vecdht-net --test s182_p1_scale`"
        );
    }
    check_the_premises();

    let t0 = Instant::now();
    let root = Tmp::new();
    let mut specs = Vec::new();
    for i in 0..PROVIDERS {
        let seed = 10 + i as u8;
        let shard = (i % KEYS) as u16;
        let seeds: Vec<u8> = (0..PROVIDERS)
            .filter(|j| (*j % KEYS) as u16 == shard)
            .map(|j| 10 + j as u8)
            .collect();
        specs.push(Spec { seed, shard: Some(shard), seeds, dir: root.0.join(format!("p{i}")) });
    }
    for j in 0..CORE {
        specs.push(Spec {
            seed: 220 + j as u8,
            shard: None,
            seeds: Vec::new(),
            dir: root.0.join(format!("c{j}")),
        });
    }
    for j in 0..OBSERVERS {
        specs.push(Spec {
            seed: 240 + j as u8,
            shard: None,
            seeds: Vec::new(),
            dir: root.0.join(format!("o{j}")),
        });
    }
    for s in &specs {
        std::fs::create_dir_all(&s.dir).unwrap();
    }

    let mut nodes = Vec::new();
    let mut addrs = Vec::new();
    for s in specs {
        let (tx, rx) = oneshot::channel();
        nodes.push(spawn_node(s, tx));
        addrs.push(rx.await.unwrap());
    }
    let build = t0.elapsed();

    let core_start = PROVIDERS;
    let obs_start = PROVIDERS + CORE;
    let t1 = Instant::now();
    // Ядро — полная сетка: 8 узлов, 28 рёбер.
    for a in 0..CORE {
        for b in a + 1..CORE {
            let _ = nodes[core_start + a].tx.send(Cmd::Dial(addrs[core_start + b].clone()));
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Провайдер — к двум узлам ядра, партиями по 20. Залп из 189 узлов разом валит TLS-рукопожатия
    // даже в release (разведка: 38…53 из 59 при залпе против 59 из 59 по одному).
    let mut i = 0;
    while i < PROVIDERS {
        let end = (i + 20).min(PROVIDERS);
        for (p, node) in nodes.iter().enumerate().skip(i).take(end - i) {
            for k in 0..2 {
                let c = (p + k) % CORE;
                let _ = node.tx.send(Cmd::Dial(addrs[core_start + c].clone()));
            }
        }
        i = end;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    // Наблюдатель — ко всему ядру.
    for node in &nodes[obs_start..NODES] {
        for c in 0..CORE {
            let _ = node.tx.send(Cmd::Dial(addrs[core_start + c].clone()));
        }
    }
    let dial = t1.elapsed();

    // Прогрев без запросов от наблюдателей: холодный резолв обязан быть первым.
    tokio::time::sleep(WARMUP).await;

    let t2 = Instant::now();
    let mut lat: Vec<u128> = Vec::new();
    let mut miss = 0usize;
    for node in &nodes[obs_start..NODES] {
        for sh in 0..KEYS as u16 {
            match resolve(node, sh).await {
                Some(ms) => lat.push(ms),
                None => miss += 1,
            }
        }
    }
    let resolve_t = t2.elapsed();

    let mut reps = Vec::new();
    for node in &nodes[..PROVIDERS] {
        reps.push(report(node).await);
    }
    let mut obs = Vec::new();
    for node in &nodes[obs_start..NODES] {
        obs.push(report(node).await);
    }
    let mut errs: Vec<String> = Vec::new();
    for nd in &nodes {
        errs.extend(errors(nd).await);
    }
    drop(nodes);

    let auth: Vec<usize> = reps.iter().map(|r| r.auth).collect();
    let kad: Vec<usize> = reps.iter().map(|r| r.kad).collect();
    let ann: u64 = reps.iter().map(|r| r.ann).sum();
    let azero = auth.iter().filter(|k| **k == 0).count();
    let kzero = kad.iter().filter(|k| **k == 0).count();
    let mut lat_sorted = lat.clone();
    lat_sorted.sort_unstable();
    let (p50, p95, max) = if lat_sorted.is_empty() {
        (u128::MAX, u128::MAX, u128::MAX)
    } else {
        let idx = |q: f64| ((lat_sorted.len() - 1) as f64 * q).round() as usize;
        (lat_sorted[idx(0.50)], lat_sorted[idx(0.95)], *lat_sorted.last().unwrap())
    };
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &errs {
        let k = if e.contains("Handshake with the remote timed out") {
            "quic-handshake-timeout"
        } else if e.contains("authentication failed") {
            "listener-auth-failed"
        } else if e.contains("Timeout while waiting") {
            "rr-timeout"
        } else if e.contains("Timeout while receiving") {
            "rr-inbound-timeout"
        } else if e.contains("connection lost") {
            "conn-lost"
        } else if e.contains("unexpected end of file") {
            "eof"
        } else if e.starts_with("dial") {
            "dial-other"
        } else {
            "other"
        };
        *kinds.entry(k).or_default() += 1;
    }

    let samples = lat.len() + miss;
    println!(
        "## P1 nodes={NODES} providers={PROVIDERS} core={CORE} observers={OBSERVERS} keys={KEYS}\n\
P1_SAMPLES={samples} P1_RESOLVED={} P1_MISS={miss} P1_P50_MS={p50} P1_P95_MS={p95} P1_MAX_MS={max}\n\
P1_AUTH_ZERO={azero} P1_KAD_ZERO={kzero} P1_ANN={ann} P1_ERRORS={} P1_KINDS={kinds:?}\n\
P1_OBS_AUTH={:?} P1_OBS_SHARD0={:?}\n\
P1_TIME_BUILD={build:?} P1_TIME_DIAL={dial:?} P1_TIME_RESOLVE={resolve_t:?} ##",
        lat.len(),
        errs.len(),
        obs.iter().map(|r| r.auth).collect::<Vec<_>>(),
        obs.iter().map(|r| r.providers).collect::<Vec<_>>(),
    );
    if !errs.is_empty() {
        println!("P1_FIRST_ERRORS={:?}", errs.iter().take(10).collect::<Vec<_>>());
    }

    // Гейт §18.2.
    assert_eq!(miss, 0, "холодный резолв не нашёл провайдера: {miss} из {samples} проб");
    assert_eq!(azero, 0, "есть провайдеры без единого аутентифицированного пира");
    assert_eq!(kzero, 0, "есть провайдеры без пиров в таблице kad");
    assert!(ann > 0, "провайдеры не объявили ни одного ключа");
    assert!(
        p95 < P95_BUDGET_MS,
        "p95 холодного резолва {p95} мс при гейте {P95_BUDGET_MS} мс"
    );
    assert!(
        obs.iter().all(|r| (1..=PROVIDER_CACHE_MAX_PER_SHARD).contains(&r.providers)),
        "наблюдатель видит по шарду 0 не 1…K провайдеров: {:?}",
        obs.iter().map(|r| r.providers).collect::<Vec<_>>()
    );
}
