//! H-0076 / E-0076: §5.3/§4.2 — handshake: код отказа, жизнь кеша и вторая дверь в индекс.
//!
//! Юнит-тесты двери есть (`handshake.rs`), транспортные тесты есть (`transport.rs`), но шов
//! §4.2 не мерялся:
//!
//! * §4.2 (строка 148) обещает кеш аутентификации «по `remote PeerId` **до `valid_until`**»;
//! * §6.7 (строка 430) и §15.3 (строка 1450) обещают при расхождении `preprocessing_version`
//!   `Error{code:"MODEL_MISMATCH"}` и **закрытие соединения**;
//! * §5.3 (строка 230) называет `0x01 Handshake` дверью обоих концов, а §5.3 (строка 169)
//!   требует подпись отправителя в gossip-потоке.
//!
//! Здесь меряется, что дверь говорит при отказе, сколько живёт выданное ею разрешение и —
//! главное — является ли handshake единственным входом в данные: gossip-путь уходит в шард,
//! не спрашивая таблицу handshake.
//!
//! Один процесс, настоящий QUIC на loopback, ручная доставка, реальные часы.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::{Multiaddr, PeerId};
use vecdht_artifact::reference_manifest;
use vecdht_crypto::cert::{verify_cert, CertError};
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::{testing, Clock, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{domain, Codec, Handshake, MatchResult, ProtocolError, Role};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
/// Пир вне тройки сидов: агент или носитель кредашиала.
const PEER_SEED: u8 = 77;

fn dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("vecdht-s5-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("временный каталог теста");
    p
}

fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

/// Конфигурация нормальной сети: модель и preprocessing — контракт handshake (§4.2), а не
/// константа теста, поэтому берутся из того же эталонного манифеста, что и `genesis_hash`.
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
    }
}

/// Та же сеть, но с чужим `preprocessing_version` — «другая модель» из §6.7.
fn foreign_cfg(listen: Multiaddr) -> NetConfig {
    let mut c = cfg(listen);
    c.preprocessing_version = testing::PREPROCESSING_VERSION + 1;
    c
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

/// Primary шарда по порядку §9.3: узел выводит его из ростера, и тест не вправе назначить
/// primary первым сидом — иначе публикация получила бы `NOT_OWNER`.
fn primary_seed() -> u8 {
    let order = vecdht_node::candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("primary — один из тестовых сидов")
}

fn signed_publish(agent: &vecdht_crypto::Identity, bucket: u32) -> Vec<u8> {
    let spec = testing::PublishSpec {
        agent,
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

/// Узел шарда с genesis-эпохой: lease эпохи 1 привязан к моменту применения, поэтому узел
/// открывается «в текущей секунде».
fn index_service(seed: u8, dir: &Path, listen: Multiaddr) -> NetService {
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let mut node = ShardNode::open(
        dir,
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
    let cert = testing::node_cert(seed, peer.to_bytes(), vec![SHARD], Role::IndexNode, 0, u32::MAX);
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

/// Агент «из другой сети»: то же самое, но с чужим `preprocessing_version` (§6.7).
fn foreign_agent_service(seed: u8, listen: Multiaddr) -> NetService {
    NetService::new(
        testing::identity(seed),
        Role::Agent,
        None,
        Vec::new(),
        testing::authority_set(),
        foreign_cfg(listen),
    )
    .expect("сервис иносетевого агента")
}

/// Пир с кредашиалом заданного окна действия. Шардов не держит: ему нужен только вход в
/// транспорт, чтобы предъявить этот кредашиал.
fn cert_service(seed: u8, listen: Multiaddr, valid_from: u32, valid_until: u32) -> NetService {
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let cert = testing::node_cert(
        seed,
        peer.to_bytes(),
        vec![SHARD],
        Role::IndexNode,
        valid_from,
        valid_until,
    );
    NetService::new(
        id,
        Role::IndexNode,
        Some(cert),
        Vec::new(),
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис с кредашиалом")
}

/// Приветствие с чужим `preprocessing_version` — ровно то, что прислала бы другая сеть.
fn foreign_greeting() -> Vec<u8> {
    Handshake {
        role: Role::Agent,
        preprocessing_version: testing::PREPROCESSING_VERSION + 1,
        model_version: reference_manifest().model_version,
        genesis_hash: testing::genesis_hash(),
        cert: Vec::new(),
        tlv: Vec::new(),
    }
    .encode_unsigned()
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

/// Крутить два сервиса, пока предикат не станет истинным. Предикат проверяется до шага.
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

fn error_of(frames: &[(PeerId, Vec<u8>)]) -> Option<ProtocolError> {
    frames.iter().find_map(|(_, f)| {
        let k = decode_frame(f).ok()?;
        (k.header.kind == Kind::Error).then(|| ProtocolError::decode(f).ok())?
    })
}

fn match_result_of(frames: &[(PeerId, Vec<u8>)]) -> Option<MatchResult> {
    frames.iter().find_map(|(_, f)| {
        (decode_frame(f).ok()?.header.kind == Kind::MatchResult)
            .then(|| MatchResult::decode(f).ok())
            .flatten()
    })
}

/// (0) Нормальный handshake сходится с обеих сторон, и личность в таблице — ровно та.
#[test]
fn a_normal_handshake_binds_both_sides() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("s5-base");
        let mut node = index_service(primary_seed(), &d, quic_addr());
        let mut agent = agent_service(PEER_SEED, quic_addr());
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;

        let who = node.peer_identity(&ap).expect("(0) агент в таблице handshake");
        assert_eq!(who.role, Role::Agent, "(0) роль пришла из приветствия");
        assert_eq!(who.owner, testing::identity(PEER_SEED).pubkey());
        assert!(who.cert.is_none(), "(0) агент не несёт кредашиал (§4.2)");
        assert_eq!(who.valid_until, None, "(0) у агента срока нет");

        let mine = agent.peer_identity(&np).expect("(0) узел в таблице агента");
        assert_eq!(mine.role, Role::IndexNode, "(0) роль узла");
        assert!(mine.cert.is_some(), "(0) узел несёт кредашиал");
        assert_eq!(mine.valid_until, Some(u32::MAX), "(0) срок узла сохранён");
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// (1) Пир из другой сети отвергнут на handshake, и причина отказа до него не доходит.
#[test]
fn a_foreign_network_is_refused_and_the_reason_never_reaches_the_peer() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("s5-foreign");
        let mut node = index_service(primary_seed(), &d, quic_addr());
        let mut foreign = foreign_agent_service(PEER_SEED, quic_addr());
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut foreign).await;
        foreign.dial(addr).expect("dial узла");
        let (np, fp) = (node.peer_id(), foreign.peer_id());

        // Ждём **завершённого** обмена, а не первого признака разговора: ошибка handshake на
        // стороне узла означает, что иносетевой агент уже разобрал встречное приветствие и
        // ответил отказом (ДИАГНОЗ-2: порядка между потоками QUIC нет, и «ошибка появилась»
        // ещё не значит «состояние наступило»).
        let mut node_errs = Vec::new();
        let mut peer_errs = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while tokio::time::Instant::now() < deadline {
            node.step().await;
            foreign.step().await;
            node_errs.extend(node.take_errors());
            peer_errs.extend(foreign.take_errors());
            let node_settled = node_errs.iter().any(|e| e.contains("handshake"));
            let peer_settled = peer_errs.iter().any(|e| e.contains("кредашиал не разобран"));
            if node_settled && peer_settled {
                break;
            }
        }
        let errs: Vec<String> = node_errs.iter().chain(peer_errs.iter()).cloned().collect();
        assert!(!node.is_authenticated(&fp), "(1) узел не аутентифицировал иносетевого пира");
        assert!(!foreign.is_authenticated(&np), "(1) иносетевый агент не принял узел");
        assert!(
            errs.iter().any(|e| e.contains("handshake")),
            "(1) отказ handshake не зафиксирован: {errs:?}"
        );
        assert!(
            errs.iter().any(|e| e.contains("кредашиал не разобран")),
            "(1) ответ на handshake — не приветствие, а Error: код до инициатора не доходит: {errs:?}"
        );
        assert!(
            !errs.iter().any(|e| e.contains("MODEL_MISMATCH")),
            "(1) инициатор узнал код отказа — обещание §6.7 не нарушено: {errs:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// (2) Код отказа на проводе — `CERT_INVALID`, а не `MODEL_MISMATCH`.
/// (3) Отказ не вытесняет прежнюю личность и не закрывает соединение.
#[test]
fn the_refusal_speaks_cert_invalid_and_keeps_the_old_identity() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("s5-refusal");
        let mut node = index_service(primary_seed(), &d, quic_addr());
        let mut agent = agent_service(PEER_SEED, quic_addr());
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;

        // Повторное приветствие с чужим preprocessing_version: тот же шов, что и на живой сети.
        assert!(
            agent.send_frame(np, foreign_greeting()),
            "(2) агент аутентифицирован и может говорить"
        );
        let mut frames = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while tokio::time::Instant::now() < deadline {
            node.step().await;
            agent.step().await;
            frames.extend(agent.take_inbox());
            if error_of(&frames).is_some() {
                break;
            }
        }
        let err = error_of(&frames).expect("(2) узел ответил Error-кадром: {frames:?}");
        assert_eq!(err.code, "CERT_INVALID", "(2) код отказа на проводе");
        assert_ne!(
            err.code, "MODEL_MISMATCH",
            "(2) §6.7 обещает MODEL_MISMATCH при расхождении preprocessing_version"
        );

        // (3) Прежняя личность на месте, соединение живо, прикладной кадр обслуживается.
        assert!(node.is_authenticated(&ap), "(3) отказ не вытеснил прежнюю личность");
        let who = node.peer_identity(&ap).expect("(3) личность на месте");
        assert_eq!(who.owner, testing::identity(PEER_SEED).pubkey(), "(3) владелец прежний");
        let find = testing::find_frame(
            &testing::identity(PEER_SEED),
            &testing::vector(3),
            &[CLUSTER],
            5,
            4242,
        );
        assert!(agent.send_frame(np, find), "(3) агент аутентифицирован");
        let mut served = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while tokio::time::Instant::now() < deadline {
            node.step().await;
            agent.step().await;
            served.extend(agent.take_inbox());
            if match_result_of(&served).is_some() {
                break;
            }
        }
        assert!(
            match_result_of(&served).is_some(),
            "(3) Find после отказа не обслужен: {served:?}"
        );
        assert!(
            error_of(&served).is_none(),
            "(3) соединение закрыто — прикладной кадр получил отказ: {served:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// (4) Кеш аутентификации не имеет срока: просроченный кредашиал остаётся аутентифицированным.
#[test]
fn the_authentication_cache_outlives_valid_until() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("s5-cache");
        let mut node = index_service(primary_seed(), &d, quic_addr());
        let valid_until = now_sec() as u32 + 10;
        let mut peer = cert_service(PEER_SEED, quic_addr(), 0, valid_until);
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut peer).await;
        peer.dial(addr).expect("dial узла");
        let (np, pp) = (node.peer_id(), peer.peer_id());
        pump_until(&mut node, &mut peer, |x, y| {
            x.is_authenticated(&pp) && y.is_authenticated(&np)
        })
        .await;
        assert_eq!(
            node.peer_identity(&pp).and_then(|w| w.valid_until),
            Some(valid_until),
            "(4) срок кредашиала сохранён в личности"
        );

        // Ждём истечения срока на тех же часах, что и дверь.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        while now_sec() as u32 <= valid_until {
            assert!(tokio::time::Instant::now() < deadline, "(4) часы не пошли");
            node.step().await;
            peer.step().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Дверь на тех же байтах говорит Expired.
        let cert = testing::node_cert(
            PEER_SEED,
            pp.to_bytes(),
            vec![SHARD],
            Role::IndexNode,
            0,
            valid_until,
        );
        let err = verify_cert(
            &cert,
            &testing::authority_set(),
            &testing::genesis_hash(),
            now_sec() as u32,
            |_| false,
        )
        .expect_err("(4) дверь обязана отвергнуть просроченный кредашиал");
        assert!(
            matches!(err, CertError::Expired { .. }),
            "(4) причина отказа — срок: {err:?}"
        );

        // А кеш — нет: пир остался аутентифицированным и его кадры обслуживаются.
        assert!(
            node.is_authenticated(&pp),
            "(4) кеш аутентификации не имеет срока: просроченный кредашиал до сих пор допущен"
        );
        let find = testing::find_frame(
            &testing::identity(PEER_SEED),
            &testing::vector(3),
            &[CLUSTER],
            5,
            4243,
        );
        assert!(peer.send_frame(np, find), "(4) пир аутентифицирован");
        let mut served = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while tokio::time::Instant::now() < deadline {
            node.step().await;
            peer.step().await;
            served.extend(peer.take_inbox());
            if match_result_of(&served).is_some() {
                break;
            }
        }
        assert!(
            match_result_of(&served).is_some(),
            "(4) просроченный пир не обслужен: {served:?}"
        );
        assert!(
            error_of(&served).is_none(),
            "(4) просроченный пир получил отказ: {served:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// (5) Вторая дверь: gossip-путь уходит в шард, не спрашивая таблицу handshake.
#[test]
#[ignore = "поведение дерева до ADR-0043: «gossip-дверь открыта отказанному пиру» — зафиксированная фикция (E-0076); живой контракт — crates/vecdht-net/tests/gossip_door_parity.rs (E-0087)"]
fn the_gossip_door_is_open_to_a_peer_the_handshake_refused() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("s5-gossip");
        let mut node = index_service(primary_seed(), &d, quic_addr());
        // Кредашиал, просроченный до handshake: дверь обязана его отвергнуть.
        let expired_at = now_sec() as u32 - 1;
        let mut peer = cert_service(PEER_SEED, quic_addr(), 0, expired_at);
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut peer).await;
        peer.dial(addr).expect("dial узла");
        let (np, pp) = (node.peer_id(), peer.peer_id());

        // Ждём положительного условия: пир принял узла. ДИАГНОЗ-2 (первый замер): цикл
        // выходил по появлению ошибки handshake, а это событие наступает РАНЬШЕ, чем пир
        // разберёт встречное приветствие — отказ и приветствие идут разными потоками QUIC,
        // и порядка между ними нет. Условие «ошибка появилась» — не «состояние наступило».
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut errs = Vec::new();
        while !peer.is_authenticated(&np) && tokio::time::Instant::now() < deadline {
            node.step().await;
            peer.step().await;
            errs.extend(node.take_errors());
            errs.extend(peer.take_errors());
        }
        assert!(
            peer.is_authenticated(&np),
            "(5) пир принял узла — прямой путь для проверки доступен; ошибки={errs:?}"
        );
        assert!(
            !node.is_authenticated(&pp),
            "(5) узел аутентифицировал просроченный кредашиал; ошибки={errs:?}"
        );

        // Прямая дверь закрыта.
        let bucket = Clock::at(now_sec()).bucket;
        let publish = signed_publish(&testing::identity(PEER_SEED), bucket);
        assert!(
            peer.send_frame(np, publish.clone()),
            "(5) пир аутентифицировал узла и может говорить"
        );
        let mut frames = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while tokio::time::Instant::now() < deadline {
            node.step().await;
            peer.step().await;
            frames.extend(peer.take_inbox());
            if error_of(&frames).is_some() {
                break;
            }
        }
        let denied = error_of(&frames).expect("(5) прямой путь обязан ответить отказом");
        assert_eq!(denied.code, "DENIED", "(5) прямая дверь закрыта");

        // Gossip-дверь открыта: тот же кадр в тему шарда.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let _ = peer.publish_gossip(SHARD, publish.clone());
            for _ in 0..10 {
                peer.step().await;
                node.step().await;
            }
            if node.node(SHARD).is_some_and(|n| n.store.len() == 1) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "(5) gossip-публикация не дошла за 30 с; ошибки узла={:?}",
                node.take_errors()
            );
        }
        assert!(
            !node.is_authenticated(&pp),
            "(5) пир по-прежнему не аутентифицирован — запись пришла мимо handshake"
        );
        let stored = node.node(SHARD).expect("(5) шард узла");
        assert_eq!(stored.store.len(), 1, "(5) запись легла в индекс");
        assert!(
            stored
                .store
                .index
                .owner_slot(&testing::identity(PEER_SEED).pubkey())
                .is_some(),
            "(5) запись принадлежит именно неаутентифицированному пиру"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}
