//! Транспорт §4.1/§4.2/§5.3 на настоящем libp2p: QUIC, встречный handshake с `NodeCert`,
//! кадры publish/find и provider-записи шардов §7.4.
//!
//! Тесты поднимают два-три `NetService` в одном `current_thread`-рантайме, как это делает
//! узел в бою (`SharedAdmission` намеренно `Rc`). Никакой мок-транспорт не участвует: если
//! handshake не сойдётся в QUIC-соединении, тест это увидит.
//!
//! Время здесь реальное (приём §11.3 и тики §9.6 считаются секундами), поэтому ожидания идут
//! циклом `step` с дедлайном, а не фиксированным `sleep`.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::{Multiaddr, PeerId};
use vecdht_artifact::reference_manifest;
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::{testing, Clock, ShardNode};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{domain, Codec, MatchResult, PublishAck, ProtocolError, Role};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("vecdht-net-{}-{name}", std::process::id()));
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
        // Модель и preprocessing — контракт handshake (§4.2), а не константа теста: берём их
        // из того же эталонного манифеста, что даёт genesis_hash.
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-net-test/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
    }
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

/// Primary шарда по порядку §9.3. Тест не вправе «назначить» primary первым сидом: узел
/// выводит его из ростера, и публикация на не-primary получила бы `NOT_OWNER` — это отказ
/// маршрута, а не транспорта.
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

/// Узел шарда с genesis-эпохой. Genesis применяется на текущем бакете: lease эпохи 1 привязан
/// к моменту применения, и узел, открытый «в 1970-м», к реальному времени уже не обслуживает
/// шард.
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

/// Ждать, пока сервис откроет слушателя, и вернуть фактический адрес: порт 0 выбирает ОС.
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

/// Крутить два сервиса, пока предикат не станет истинным. Предикат проверяется до шага,
/// поэтому вызывающая сторона не обязана ловить событие «на лету».
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

/// То же для трёх сервисов: публикация с W=2 ждёт ack реплики, и без её шагов цепочка
/// «primary → реплика → primary → агент» не сдвинется.
async fn pump_until3<F>(a: &mut NetService, b: &mut NetService, c: &mut NetService, mut done: F)
where
    F: FnMut(&NetService, &NetService, &NetService) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if done(a, b, c) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "состояние не наступило за 20 с; ошибки A={:?} B={:?} C={:?}",
            a.take_errors(),
            b.take_errors(),
            c.take_errors()
        );
        a.step().await;
        b.step().await;
        c.step().await;
    }
}

fn error_of(frames: &[(PeerId, Vec<u8>)]) -> Option<ProtocolError> {
    frames.iter().find_map(|(_, f)| {
        let k = decode_frame(f).ok()?;
        (k.header.kind == Kind::Error).then(|| ProtocolError::decode(f).ok())?
    })
}

fn publish_ack_of(frames: &[(PeerId, Vec<u8>)]) -> Option<PublishAck> {
    frames.iter().find_map(|(_, f)| {
        (decode_frame(f).ok()?.header.kind == Kind::PublishAck)
            .then(|| PublishAck::decode(f).ok())
            .flatten()
    })
}

fn match_result_of(frames: &[(PeerId, Vec<u8>)]) -> Option<MatchResult> {
    frames.iter().find_map(|(_, f)| {
        (decode_frame(f).ok()?.header.kind == Kind::MatchResult)
            .then(|| MatchResult::decode(f).ok())
            .flatten()
    })
}

/// Шаги, пока в inbox агента не появится кадр нужного вида. Кадры не выбрасываются: `Find`
/// отвечает батчем (`MatchResult` + приёмы §12.3), и «нашли первый» не значит «батч пуст».
async fn collect_from_agent<F>(
    agent: &mut NetService,
    a: &mut NetService,
    b: &mut NetService,
    mut found: F,
) -> Vec<(PeerId, Vec<u8>)>
where
    F: FnMut(&[(PeerId, Vec<u8>)]) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut frames = Vec::new();
    loop {
        agent.step().await;
        a.step().await;
        b.step().await;
        frames.extend(agent.take_inbox());
        if let Some(err) = error_of(&frames) {
            panic!("узел отказал: {} (retry {} мс)", err.code, err.retry_after_ms);
        }
        if found(&frames) {
            return frames;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "агент не получил кадр за 20 с; ошибки агента={:?}, A={:?}, B={:?}",
            agent.take_errors(),
            a.take_errors(),
            b.take_errors()
        );
    }
}

#[test]
fn quic_handshake_binds_the_cert_to_the_transport_key() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("handshake");
        let mut node = index_service(primary_seed(), &d, quic_addr());
        let mut agent = agent_service(77, quic_addr());
        let node_addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(node_addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;

        let who = node.peer_identity(&agent.peer_id()).expect("агент в таблице handshake");
        assert_eq!(who.role, Role::Agent, "роль пришла из Handshake, не из ключа");
        assert_eq!(who.owner, testing::identity(77).pubkey());
        assert!(who.cert.is_none(), "агент не несёт кредашиал (§4.2)");
        let _ = std::fs::remove_dir_all(&d);
    });
}

#[test]
fn a_cert_whose_owner_is_not_the_transport_key_is_rejected() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("badcert");
        let mut node = index_service(primary_seed(), &d, quic_addr());
        let node_addr = wait_listen(&mut node).await;

        // Ключ 5 подписывает кредашиал, но в транспорте стоит ключ 4. Подпись авторитетов
        // настоящая — именно поэтому проверка обязана смотреть на владельца, а не только
        // на порог (§4.2, правило 3).
        let thief_id = testing::identity(4);
        let thief_peer = keys::peer_id(&thief_id);
        let stolen: NodeCert = testing::node_cert(
            5,
            thief_peer.to_bytes(),
            vec![SHARD],
            Role::IndexNode,
            0,
            u32::MAX,
        );
        let mut thief = NetService::new(
            thief_id,
            Role::IndexNode,
            Some(stolen),
            Vec::new(),
            testing::authority_set(),
            cfg(quic_addr()),
        )
        .expect("сервис с чужим кредашиалом собирается; проверка — на handshake");
        let _ = wait_listen(&mut thief).await;
        thief.dial(node_addr).expect("dial узла");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            node.step().await;
            thief.step().await;
        }
        assert!(
            !node.is_authenticated(&thief_peer),
            "чужой owner не должен аутентифицироваться"
        );
        let errors = node.take_errors();
        assert!(
            errors.iter().any(|e| e.contains("handshake")),
            "ожидалась ошибка handshake, получено: {errors:?}"
        );
        // Обратное направление асимметрично by design: вор видит подлинный кредашиал узла и
        // может считать его аутентифицированным, но узел кадров вора не принимает. Проверяем
        // именно авторизацию, а не симметрию таблиц.
        assert!(
            thief.is_authenticated(&node.peer_id()),
            "вор проверил кредашиал узла — это не даёт ему прав"
        );
        let probe = testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0));
        assert!(thief.send_frame(node.peer_id(), probe));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut denied = None;
        while tokio::time::Instant::now() < deadline && denied.is_none() {
            node.step().await;
            thief.step().await;
            for (_, f) in thief.take_inbox() {
                if let Ok(err) = ProtocolError::decode(&f) {
                    denied = Some(err);
                }
            }
        }
        assert_eq!(
            denied.map(|e| e.code),
            Some("DENIED".to_string()),
            "кадр неаутентифицированного пира обязан получить DENIED"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Публикация и поиск по настоящему QUIC.
///
/// Реплика здесь не декорация: `PublishAck` в v8 выпускается только после `w=2` подтверждений
/// (§9.4), и узел с одним диском честно молчит. Поэтому в тесте три процесса — primary,
/// реплика и агент, — и все три крутят event loop.
#[test]
fn publish_and_find_travel_over_the_real_transport() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d_primary = dir("publish-primary");
        let d_replica = dir("publish-replica");
        let primary_id = primary_seed();
        let replica_id = *SEEDS.iter().find(|s| **s != primary_id).expect("второй тестовый сид");
        let mut primary = index_service(primary_id, &d_primary, quic_addr());
        let mut replica = index_service(replica_id, &d_replica, quic_addr());
        let mut agent = agent_service(77, quic_addr());
        let primary_addr = wait_listen(&mut primary).await;
        let _ = wait_listen(&mut replica).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(primary_addr.clone()).expect("dial primary");
        replica.dial(primary_addr).expect("dial primary репликой");

        let (pp, rp, ap) = (primary.peer_id(), replica.peer_id(), agent.peer_id());
        pump_until3(&mut primary, &mut replica, &mut agent, |p, r, a| {
            p.is_authenticated(&rp)
                && p.is_authenticated(&ap)
                && r.is_authenticated(&pp)
                && a.is_authenticated(&pp)
        })
        .await;
        assert!(
            primary.node(SHARD).is_some_and(|n| n.is_primary()),
            "публикация принимается только primary"
        );

        let bucket = Clock::at(now_sec()).bucket;
        let publish = signed_publish(&testing::identity(77), bucket);
        assert!(agent.send_frame(pp, publish), "агент аутентифицирован");

        let frames =
            collect_from_agent(&mut agent, &mut primary, &mut replica, |f| publish_ack_of(f).is_some())
                .await;
        let ack = publish_ack_of(&frames).expect("PublishAck в ответе");
        assert_eq!(ack.shard, SHARD);
        // Успех в `PublishAck` — это литерал "OK", а не пустой код: поле обязательное (§5.5).
        assert_eq!(ack.error_code, "OK");
        assert_eq!(
            replica.node(SHARD).expect("шард реплики").store.len(),
            1,
            "реплика применила опс primary до ack"
        );

        let find = testing::find_frame(
            &testing::identity(99),
            &testing::vector(3),
            &[CLUSTER],
            5,
            4242,
        );
        assert!(agent.send_frame(pp, find));
        let frames = collect_from_agent(&mut agent, &mut primary, &mut replica, |f| {
            match_result_of(f).is_some()
        })
        .await;
        let res = match_result_of(&frames).expect("MatchResult в ответе");
        assert_eq!(res.shard, SHARD);
        assert_eq!(res.query_id, 4242);
        assert_eq!(res.matches.len(), 1, "опубликованный вектор обязан найтись");
        assert_eq!(res.matches[0].slot, ack.slot);
        assert_eq!(
            frames.iter().filter(|(_, f)| {
                decode_frame(f).map(|x| x.header.kind) == Ok(Kind::RendezvousAccept)
            }).count(),
            1,
            "на каждый match §12.3 выдаёт ровно один приём"
        );
        let _ = std::fs::remove_dir_all(&d_primary);
        let _ = std::fs::remove_dir_all(&d_replica);
    });
}

/// Обрыв соединения обязан дойти до узла как `peer_lost` (§9.8), а не раствориться в
/// транспорте.
///
/// Иначе primary узнал бы о смерти реплики только по истечении lease (90 с), и выборы
/// начинались бы после простоя шарда. Тест проверяет именно второе звено: узел помечает
/// ушедшего недоступным. Сами выборы здесь не форсируются — их тайминг (rank × 4 бакета)
/// проверяет P4 на модельной сети, где часы можно двигать.
#[test]
fn a_closed_connection_reaches_peer_lost_in_the_shard() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d_primary = dir("lost-primary");
        let d_a = dir("lost-a");
        let d_b = dir("lost-b");
        let primary_id = primary_seed();
        let replicas: Vec<u8> = SEEDS.iter().copied().filter(|s| *s != primary_id).collect();
        let (a_id, b_id) = (replicas[0], replicas[1]);
        let mut primary = index_service(primary_id, &d_primary, quic_addr());
        let mut a = index_service(a_id, &d_a, quic_addr());
        let mut b = index_service(b_id, &d_b, quic_addr());
        let primary_addr = wait_listen(&mut primary).await;
        let _ = wait_listen(&mut a).await;
        let _ = wait_listen(&mut b).await;
        a.dial(primary_addr.clone()).expect("dial A");
        b.dial(primary_addr).expect("dial B");

        let (pp, ap, bp) = (primary.peer_id(), a.peer_id(), b.peer_id());
        pump_until3(&mut primary, &mut a, &mut b, |p, x, y| {
            p.is_authenticated(&ap)
                && p.is_authenticated(&bp)
                && x.is_authenticated(&pp)
                && y.is_authenticated(&pp)
        })
        .await;

        let lost = testing::identity(a_id).pubkey();
        assert!(
            !primary.node(SHARD).expect("шард primary").is_unreachable(&lost),
            "до обрыва A не может считаться мёртвым"
        );
        drop(a);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            primary.step().await;
            b.step().await;
            if primary.node(SHARD).is_some_and(|n| n.is_unreachable(&lost)) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "обрыв не дошёл до узла за 20 с; ошибки={:?}",
                primary.take_errors()
            );
        }
        assert!(
            primary.is_authenticated(&bp),
            "закрытие соединения с A не должно вычищать живого B"
        );
        let _ = std::fs::remove_dir_all(&d_primary);
        let _ = std::fs::remove_dir_all(&d_a);
        let _ = std::fs::remove_dir_all(&d_b);
    });
}

/// Агент-клиент находит провайдера шарда через Kademlia §7.4.
///
/// Провайдер объявляет шард на первом тике; его собственная provider-запись лежит в локальном
/// store и отдаётся на `FIND_PROVIDER`, как только у агента появляется запись о нём в таблице
/// маршрутизации. Повторные запросы раз в секунду — не «молитва», а честная реакция на то, что
/// identify и объявление асинхронны.
#[test]
fn an_agent_discovers_the_shard_provider_through_kademlia() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("provider");
        let mut provider = index_service(primary_seed(), &d, quic_addr());
        let mut agent = agent_service(77, quic_addr());
        let provider_addr = wait_listen(&mut provider).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(provider_addr).expect("dial провайдера");
        let (pp, ap) = (provider.peer_id(), agent.peer_id());
        pump_until(&mut provider, &mut agent, |p, a| {
            p.is_authenticated(&ap) && a.is_authenticated(&pp)
        })
        .await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut found = Vec::new();
        let mut last_query = 0u64;
        while tokio::time::Instant::now() < deadline {
            provider.step().await;
            agent.step().await;
            let now = now_sec();
            if now != last_query {
                last_query = now;
                agent.find_providers(SHARD).expect("kad-запрос провайдеров");
            }
            found = agent.provider_peers(SHARD);
            if found.contains(&pp) {
                break;
            }
        }
        assert!(
            found.contains(&pp),
            "провайдер шарда {SHARD} не найден: {found:?}, kad-пиров={}, объявлений={}, ошибки={:?}",
            agent.kad_peer_count(),
            provider.provider_announcements,
            agent.take_errors()
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Gossip §5.3/§7.4: подписанный `Publish` доходит до primary без прямого request-response.
///
/// Ack здесь не ожидается: реплик в этом тесте нет, а v8 не подтверждает запись, которую
/// держит один диск. Проверяемое утверждение — кадр прошёл проверку подписи автора и лёг в
/// индекс узла. Повторная публикация того же кадра — попытка доставить его, пока mesh
/// gossipsub строится на heartbeat, а не спам: узел заменяет запись на месте.
#[test]
fn gossip_delivers_a_signed_publish_to_the_primary() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("gossip");
        let mut node = index_service(primary_seed(), &d, quic_addr());
        let mut agent = agent_service(77, quic_addr());
        let node_addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(node_addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;
        assert!(node.node(SHARD).is_some_and(|n| n.is_primary()));
        agent.subscribe(SHARD).expect("подписка агента на тему шарда");

        let agent_id = testing::identity(77);
        let bucket = Clock::at(now_sec()).bucket;
        let frame = signed_publish(&agent_id, bucket);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut delivered = false;
        while tokio::time::Instant::now() < deadline {
            let _ = agent.publish_gossip(SHARD, frame.clone());
            for _ in 0..10 {
                agent.step().await;
                node.step().await;
            }
            delivered = node.node(SHARD).is_some_and(|n| n.store.len() == 1);
            if delivered {
                break;
            }
        }
        assert!(
            delivered,
            "gossip-публикация не дошла; ошибки узла={:?}",
            node.take_errors()
        );
        let stored = node.node(SHARD).expect("шард узла");
        assert!(
            stored.store.index.owner_slot(&agent_id.pubkey()).is_some(),
            "в индексе лежит запись именно автора кадра"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}
