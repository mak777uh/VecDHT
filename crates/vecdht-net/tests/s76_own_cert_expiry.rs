//! H-0098 / E-0098: политика просроченного **собственного** кредашиала.
//!
//! §4.2 проверяет кредашиал встречной стороны (`door.rs` отвечает `CertExpired`), а о своём
//! сервис знает только `own_cert_nonce` и `self_revoked`. Поля `valid_until` в `service.rs`
//! до правки нет: узел с закрытым окном продолжает подписывать, публиковать и обслуживать
//! кадры, и молчание наступает у соседей, а не у него.
//!
//! Гейты:
//!   (1) сервис с уже просроченным кредашиалом не строится (до правки — строится);
//!   (2) узел, у которого окно закрылось на ходу, перестаёт обслуживать Find (до правки —
//!       продолжает);
//!   (3) годный кредашиал ведёт себя как прежде: handshake и обслуживание Find работают,
//!       ложного молчания нет.
//!
//! Один процесс, настоящий QUIC на loopback, ручная доставка, реальные часы. Файл компилируется
//! и на дереве до правки: он не трогает новых имён API, поэтому PRE_FIX — это его красный прогон
//! на базовом продукте, а не пересказ.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use vecdht_artifact::reference_manifest;
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::{testing, Clock, ShardNode};
use vecdht_wire::messages::{ProtocolError, Role};
use vecdht_wire::Codec;

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const AGENT_SEED: u8 = 77;

fn dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("vecdht-s76-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("временный каталог теста");
    p
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
        agent_version: "vecdht-net-test/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
        revoked_dir: None,
    }
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

/// Primary шарда по порядку §9.3: тест не вправе назначить его произвольно.
fn primary_seed() -> u8 {
    let order = vecdht_node::candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("primary — один из тестовых сидов")
}

/// Узел шарда с кредашиалом заданного окна. `valid_until` — единственное, что отличает
/// сценарии (1)…(3); всё остальное — настоящий `ShardNode` с genesis-эпохой.
fn node_with_window(name: &str, valid_until: u32) -> (NetService, PathBuf) {
    let d = dir(name);
    let seed = primary_seed();
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let mut node = ShardNode::open(
        &d,
        SHARD,
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
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(now_bucket),
    )
    .expect("genesis");
    let cert = testing::node_cert(seed, peer.to_bytes(), vec![SHARD], Role::IndexNode, 0, valid_until);
    let service = NetService::new(
        id,
        Role::IndexNode,
        Some(cert),
        vec![node],
        testing::authority_set(),
        cfg(quic_addr()),
    )
    .expect("сервис узла");
    (service, d)
}

/// Сервис без шардов и без genesis: нужен только факт постройки. Так гейт (1) не зависит от
/// того, успел ли `ShardNode` открыться.
fn cert_only_service(valid_until: u32) -> Result<NetService, String> {
    let seed = 1;
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let cert = testing::node_cert(seed, peer.to_bytes(), vec![SHARD], Role::IndexNode, 0, valid_until);
    NetService::new(
        id,
        Role::IndexNode,
        Some(cert),
        Vec::new(),
        testing::authority_set(),
        cfg(quic_addr()),
    )
    .map_err(|e| e.to_string())
}

fn agent_service() -> NetService {
    NetService::new(
        testing::identity(AGENT_SEED),
        Role::Agent,
        None,
        Vec::new(),
        testing::authority_set(),
        cfg(quic_addr()),
    )
    .expect("сервис агента")
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

async fn pump_until<F>(a: &mut NetService, b: &mut NetService, mut done: F)
where
    F: FnMut(&NetService, &NetService) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if done(a, b) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "состояние не наступило за 20 с; ошибки A={:?} B={:?}",
            a.take_errors(),
            b.take_errors()
        );
        a.step().await;
        b.step().await;
    }
}

fn error_of(frames: &[(libp2p::PeerId, Vec<u8>)]) -> Option<ProtocolError> {
    frames.iter().find_map(|(_, f)| {
        let k = vecdht_wire::frame::decode_frame(f).ok()?;
        (k.header.kind == vecdht_wire::frame::Kind::Error)
            .then(|| ProtocolError::decode(f).ok())
            .flatten()
    })
}

/// Отправить Find и собрать ответы агента до первого кадра или до таймаута.
async fn find_and_collect(
    node: &mut NetService,
    agent: &mut NetService,
    np: libp2p::PeerId,
    query_id: u64,
    wait: Duration,
) -> Vec<(libp2p::PeerId, Vec<u8>)> {
    let find = testing::find_frame(
        &testing::identity(AGENT_SEED),
        &testing::vector(3),
        &[CLUSTER],
        5,
        query_id,
    );
    assert!(agent.send_frame(np, find), "агент аутентифицирован и может спросить");
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    while tokio::time::Instant::now() < deadline && frames.is_empty() {
        node.step().await;
        agent.step().await;
        frames.extend(agent.take_inbox());
    }
    frames
}

/// Гейт (1): закрытое окно до старта — сервис не строится, а не «строится и молчит у соседей».
#[test]
fn g1_an_expired_own_cert_is_not_constructed() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let past = (now_sec() as u32).saturating_sub(5);
        let built = cert_only_service(past);
        println!("G1_CONSTRUCTED={}", u8::from(built.is_ok()));
        if let Err(e) = &built {
            println!("G1_ERROR={e}");
        }
        assert!(
            built.is_err(),
            "(1) сервис с просроченным собственным кредашиалом построен: ошибка обязана быть отказом"
        );
    });
}

/// Гейт (3): годный кредашиал обслуживает Find — контроль против ложного молчания.
#[test]
fn g3_a_fresh_own_cert_serves_find() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let until = (now_sec() as u32) + 300;
        let (mut node, d) = node_with_window("fresh", until);
        let mut agent = agent_service();
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;
        let frames = find_and_collect(&mut node, &mut agent, np, 7_001, Duration::from_secs(20)).await;
        let served = !frames.is_empty() && error_of(&frames).is_none();
        println!("G3_FRESH_SERVED={}", u8::from(served));
        assert!(
            served,
            "(3) годный кредашиал обязан обслуживать Find; кадры={frames:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Гейт (2): окно закрылось на ходу — узел перестаёт обслуживать кадры сам, а не только
/// становится недостижимым для новых handshake'ей.
#[test]
fn g2_a_running_node_stops_when_its_window_closes() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let until = (now_sec() as u32) + 10;
        let (mut node, d) = node_with_window("crossing", until);
        let mut agent = agent_service();
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;

        let before = find_and_collect(&mut node, &mut agent, np, 7_101, Duration::from_secs(20)).await;
        let served_before = !before.is_empty() && error_of(&before).is_none();
        println!("G2_BEFORE_EXPIRY_SERVED={}", u8::from(served_before));
        assert!(served_before, "(2) до истечения узел обязан обслуживать: {before:?}");

        // Ждём на тех же часах, что и сервис: `now_sec` — источник времени обоих.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        while now_sec() as u32 <= until {
            assert!(tokio::time::Instant::now() < deadline, "(2) часы не пошли");
            node.step().await;
            agent.step().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let after = find_and_collect(&mut node, &mut agent, np, 7_102, Duration::from_secs(10)).await;
        let still_served = !after.is_empty() && error_of(&after).is_none();
        println!("G2_AFTER_EXPIRY_SERVED={}", u8::from(still_served));
        assert!(
            !still_served,
            "(2) после закрытия окна узел продолжил обслуживать Find: кадры={after:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}
