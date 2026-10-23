//! H-0087 / E-0087 · оракул: у gossip-пути те же права, что у прямого (ADR-0043).
//!
//! `E-0076` и `E-0085` измерели фикцию: пир, которому дверь отказала, терял прямой путь
//! (`DENIED`), но его `Publish` продолжал ложиться в индекс шарда по gossip (`gate6d_stored=1`
//! при `gate6a_refused=1`). Этот файл — обратный оракул к тем двум: он предсказывает поведение
//! **после** правки и потому обязан падать на дереве до неё (прецедент `ADR-0016`, где
//! `future_epoch_lease_freeze.rs` был помечен `#[ignore]` с причиной, а действующий контракт
//! описал новый файл).
//!
//! Единица измерения — факт (`store.len()`, `is_authenticated`, код `Error`, presence строки в
//! логах), а не время: временных гейтов здесь нет, поэтому правило 7 к циклу не применяется, а
//! воспроизводимость сверяется blake3-свёрткой таблицы фактов между прогонами n=2 (порог (6)).
//!
//! Стенд тот же, что у `E-0085`: один процесс, настоящий QUIC на loopback, `current_thread`,
//! реальные настенные часы, `poll_interval` 5 мс.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::{Multiaddr, PeerId};
use vecdht_artifact::reference_manifest;
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::{candidates, testing, Clock};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{domain, Codec, ProtocolError, Role};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
/// Носитель кредашиала вне тройки ростера — тот же, что у `E-0085`, чтобы контраст
/// «отказано / пройдено» был одной и той же личностью, а не разными ключами.
const PEER_SEED: u8 = 77;
/// Маркер нового фильтра в локальных логах узла.
const GATE_MARK: &str = "без пройденной двери";

/// Временный каталог с Drop-гардом: `E-0085` ДИАГНОЗ-2 оставил 13 осевших каталогов именно
/// потому, что `dir()` чистился руками в конце теста, а паника в середине обходила очистку.
struct Tmp(PathBuf);

impl Tmp {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("vecdht-gdp-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("временный каталог теста");
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

fn cfg(listen: Multiaddr) -> NetConfig {
    NetConfig {
        listen: vec![listen],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-e0087/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
    }
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

fn digest(rows: &[String]) -> String {
    hex::encode(vecdht_crypto::ids::content_hash(rows.join("\n").as_bytes()))
}

fn primary_seed(shard: u16) -> u8 {
    let order = candidates::ordered(1, shard, &testing::holders(&SEEDS));
    *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("primary — один из тестовых сидов")
}

/// Узел одного шарда с принятой genesis-эпохой.
fn index_service_shard(seed: u8, shard: u16, dir: &Path, listen: Multiaddr) -> NetService {
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let mut node = vecdht_node::ShardNode::open(
        dir,
        shard,
        id.clone(),
        peer.to_bytes(),
        testing::params(POW),
        testing::authority_set(),
        testing::holders(&SEEDS),
    )
    .expect("открыть узел шарда");
    let now_bucket = Clock::at(now_sec()).bucket;
    node.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(shard, &SEEDS, 0)),
        testing::clock(now_bucket),
    )
    .expect("genesis");
    let cert = testing::node_cert(seed, peer.to_bytes(), vec![shard], Role::IndexNode, 0, u32::MAX);
    NetService::new(
        id,
        Role::IndexNode,
        Some(cert),
        vec![node],
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис узла")
}

fn agent_service(seed: u8, listen: Multiaddr) -> NetService {
    NetService::new(
        testing::identity(seed),
        Role::Agent,
        None,
        Vec::new(),
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис агента")
}

/// Пир-носитель кредашиала с заданным окном действия; шардов не держит (роль узла).
fn cert_service(seed: u8, listen: Multiaddr, valid_from: u32, valid_until: u32) -> NetService {
    let peer = keys::peer_id(&testing::identity(seed));
    let cert = testing::node_cert(
        seed,
        peer.to_bytes(),
        vec![SHARD],
        Role::IndexNode,
        valid_from,
        valid_until,
    );
    NetService::new(
        testing::identity(seed),
        Role::IndexNode,
        Some(cert),
        Vec::new(),
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис с кредашиалом")
}

async fn wait_listen(s: &mut NetService) -> Multiaddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(a) = s.listen_addrs().first() {
            return a.clone();
        }
        assert!(tokio::time::Instant::now() < deadline, "listener не поднялся за 10 с");
        s.step().await;
    }
}

async fn pump_until<F>(a: &mut NetService, b: &mut NetService, secs: u64, mut done: F)
where
    F: FnMut(&NetService, &NetService) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if done(a, b) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "состояние не наступило за {secs} с; ошибки A={:?} B={:?}",
            a.take_errors(),
            b.take_errors()
        );
        a.step().await;
        b.step().await;
    }
}

async fn settle(a: &mut NetService, b: &mut NetService, secs: u64) {
    let until = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < until {
        a.step().await;
        b.step().await;
    }
}

fn error_of(frames: &[(PeerId, Vec<u8>)]) -> Option<ProtocolError> {
    frames.iter().find_map(|(_, f)| {
        let k = decode_frame(f).ok()?;
        (k.header.kind == Kind::Error).then(|| ProtocolError::decode(f).ok())?
    })
}

async fn ask_code(
    node: &mut NetService,
    peer: &mut NetService,
    target: PeerId,
    frame: Vec<u8>,
    label: &str,
) -> Option<String> {
    let _ = peer.take_inbox();
    assert!(peer.send_frame(target, frame), "{label}: пир не может отправить кадр");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut frames = Vec::new();
    while tokio::time::Instant::now() < deadline {
        node.step().await;
        peer.step().await;
        frames.extend(peer.take_inbox());
        if let Some(e) = error_of(&frames) {
            return Some(e.code);
        }
    }
    None
}

fn signed_publish(seed: u8, bucket: u32) -> Vec<u8> {
    let agent = testing::identity(seed);
    let spec = testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(3),
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch: 1,
        published_bucket: bucket,
        ttl_buckets: 225,
        bits: POW,
    };
    let msg = spec.msg(Vec::new());
    let sig = agent.sign_body(domain::PUBLISH, Kind::Publish, &msg.body_bytes());
    msg.encode_signed(&sig)
}

fn find_frame(seed: u8, salt: u64) -> Vec<u8> {
    testing::find_frame(&testing::identity(seed), &testing::vector(3), &[CLUSTER], 5, salt)
}

/// Сколько записей в индексе шарда у узла (0, если узел шарда не держит).
fn stored(node: &NetService, shard: u16) -> usize {
    node.node(shard).map(|n| n.store.len()).unwrap_or(usize::MAX)
}

/// Публиковать кадр в тему шарда до тех пор, пока либо не наступит `done`, либо не пройдёт
/// `secs`. Возвращает, наступило ли состояние: gossipsub строит mesh на heartbeat, поэтому
/// одиночный выпуск кадр мог и не донести (урок `transport.rs:575`).
async fn gossip_until<F>(
    publisher: &mut NetService,
    node: &mut NetService,
    frame: Vec<u8>,
    secs: u64,
    mut done: F,
) -> bool
where
    F: FnMut(&NetService) -> bool,
{
    let until = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let _ = publisher.publish_gossip(SHARD, frame.clone());
        for _ in 0..10 {
            publisher.step().await;
            node.step().await;
        }
        if done(node) {
            return true;
        }
        if tokio::time::Instant::now() >= until {
            return false;
        }
    }
}

// --- (О1), пороги (1)/(2): отказанный пир теряет и прямой, и gossip-путь ----------------------

#[test]
fn a_peer_refused_at_the_door_loses_the_gossip_publish_path() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let t = Tmp::new("denied");
        let mut node = index_service_shard(primary_seed(SHARD), SHARD, t.path(), quic_addr());
        let now = now_sec() as u32;
        let mut peer = cert_service(PEER_SEED, quic_addr(), now + 3_600, now + 7_200);
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut peer).await;
        peer.dial(addr).expect("dial узла");
        let (np, pp) = (node.peer_id(), peer.peer_id());

        // Инициатор принял узла; узел пира — нет. Ждём именно этого состояния, а не «появились
        // ошибки» (ДИАГНОЗ-2 из `E-0076`).
        pump_until(&mut node, &mut peer, 30, |_, y| y.is_authenticated(&np)).await;
        let refused = !node.is_authenticated(&pp);
        println!("МЕРЕНО o1_refused={}", if refused { 1 } else { 0 });
        assert!(refused, "(О1) узел аутентифицировал недействующий кредашиал");

        // Прямой путь: тот же замороженный факт `E-0085` гейт (6c) — отказ обязан остаться.
        let code = ask_code(&mut node, &mut peer, np, find_frame(PEER_SEED, 4244), "denied-find")
            .await
            .expect("(О1) ответа на прямой кадр нет");
        println!("МЕРЕНО o1_direct_code={code}");
        assert_eq!(code, "DENIED", "(О1) прямой кадр от отказанного пира ответил не `DENIED`");

        // Gossip-путь: подпись корректна, покласть в индекс её больше некому.
        peer.subscribe(SHARD).expect("подписка на тему шарда");
        let bucket = Clock::at(now_sec()).bucket;
        let publish = signed_publish(PEER_SEED, bucket);
        let landed = gossip_until(&mut peer, &mut node, publish, 20, |n| stored(n, SHARD) > 0)
            .await;
        let after_publish = node.take_errors();
        let gate_after_publish = after_publish.iter().filter(|e| e.contains(GATE_MARK)).count();

        // `Find` того же пира: он не пишет индекс, но тратит rendezvous-приёмы и получает
        // ответы, то есть ровно та стоимость, ради которой дверь и ставится.
        let _ = gossip_until(&mut peer, &mut node, find_frame(PEER_SEED, 4245), 6, |_| false).await;
        let after_find = node.take_errors();
        let gate_after_find = after_find.iter().filter(|e| e.contains(GATE_MARK)).count();
        let find_dropped = gate_after_find > gate_after_publish;
        let stored_after = stored(&node, SHARD);
        println!(
            "МЕРЕНО o2_gossip_landed={} o2_stored={} o2_gate_publish={gate_after_publish} o2_gate_find={gate_after_find} o2_find_gated={}",
            if landed { 1 } else { 0 },
            stored_after,
            if find_dropped { 1 } else { 0 }
        );
        assert!(!landed, "(О2) `Publish` отказанного пира лёг в индекс по gossip");
        assert_eq!(stored_after, 0, "(О2) индекс содержит {stored_after} записей после отказа");
        assert!(gate_after_publish > 0, "(О2) фильтр не записал себе причину отказа");
        assert!(find_dropped, "(О2) `Find` отказанного пира не был отброшен фильтром");
        println!(
            "МЕРЕНО o12_digest={}",
            digest(&[
                format!("refused={}", refused as u8),
                format!("direct_code={code}"),
                format!("gossip_landed={}", landed as u8),
                format!("stored={stored_after}"),
                format!("find_gated={}", find_dropped as u8),
            ])
        );
    });
}

// --- (О3), порог (3): положительный контроль — легитимный путь не сломан ---------------------

#[test]
fn the_same_identity_lands_once_the_door_is_passed() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let t = Tmp::new("valid");
        let mut node = index_service_shard(primary_seed(SHARD), SHARD, t.path(), quic_addr());
        // Та же личность, что в (О1), но с действующим окном: контраст — дверь, а не ключ.
        let mut peer = cert_service(PEER_SEED, quic_addr(), 0, u32::MAX);
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut peer).await;
        peer.dial(addr).expect("dial узла");
        let (np, pp) = (node.peer_id(), peer.peer_id());
        pump_until(&mut node, &mut peer, 30, |x, y| {
            x.is_authenticated(&y.peer_id()) && y.is_authenticated(&np)
        })
        .await;
        assert!(node.is_authenticated(&pp), "(О3) узел не принял действующий кредашиал");
        peer.subscribe(SHARD).expect("подписка на тему шарда");
        let bucket = Clock::at(now_sec()).bucket;
        let landed =
            gossip_until(&mut peer, &mut node, signed_publish(PEER_SEED, bucket), 20, |n| {
                stored(n, SHARD) == 1
            })
            .await;
        println!("МЕРЕНО o3_stored={} o3_gate_hits={}", stored(&node, SHARD), {
            node.take_errors().iter().filter(|e| e.contains(GATE_MARK)).count()
        });
        assert!(landed, "(О3) запись легитимного пира не дошла по gossip");
    });
}

#[test]
fn an_agent_without_a_credential_still_lands() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let t = Tmp::new("agent");
        let mut node = index_service_shard(primary_seed(SHARD), SHARD, t.path(), quic_addr());
        // Агент — роль без кредашиала (§4.2): дверь он проходит, и фильтр обязан его пускать.
        let mut agent = agent_service(9, quic_addr());
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, 30, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;
        agent.subscribe(SHARD).expect("подписка агента на тему шарда");
        let bucket = Clock::at(now_sec()).bucket;
        let landed =
            gossip_until(&mut agent, &mut node, signed_publish(9, bucket), 20, |n| {
                stored(n, SHARD) == 1
            })
            .await;
        let gate_hits = node.take_errors().iter().filter(|e| e.contains(GATE_MARK)).count();
        println!("МЕРЕНО o3_agent_stored={} o3_agent_gate_hits={gate_hits}", stored(&node, SHARD));
        assert!(landed, "(О3) агент без кредашиала потерял gossip-путь — правка ломает §12.1");
        assert_eq!(gate_hits, 0, "(О3) фильтр сработал на аутентифицированном агенте");
    });
}

// --- (О4), порог (4): кадры, которые самовалидируются, под фильтр не попадают ----------------

#[test]
fn membership_style_gossip_is_not_gated() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let t = Tmp::new("membership");
        let mut node = index_service_shard(primary_seed(SHARD), SHARD, t.path(), quic_addr());
        let now = now_sec() as u32;
        let mut peer = cert_service(PEER_SEED, quic_addr(), now + 3_600, now + 7_200);
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut peer).await;
        peer.dial(addr).expect("dial узла");
        let np = node.peer_id();
        pump_until(&mut node, &mut peer, 30, |_, y| y.is_authenticated(&np)).await;
        assert!(!node.is_authenticated(&peer.peer_id()), "(О4) пир должен быть отказан");
        peer.subscribe(SHARD).expect("подписка на тему шарда");
        // Кадр членства: его авторитет — порог подписей авторитетов, а не факт handshake.
        let frame = testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 1));
        let _ = peer.publish_gossip(SHARD, frame);
        settle(&mut peer, &mut node, 6).await;
        let errs = node.take_errors();
        let gated = errs.iter().any(|e| e.contains(GATE_MARK));
        println!("МЕРЕНО o4_gated={} o4_errors={:?}", if gated { 1 } else { 0 }, errs);
        assert!(!gated, "(О4) фильтр отбросил кадр, который не пишет индекс и не тратит приёмы");
    });
}
