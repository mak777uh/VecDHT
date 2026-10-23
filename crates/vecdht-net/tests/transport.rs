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
use tokio::sync::oneshot;
use tokio::task::LocalSet;
use vecdht_artifact::{reference_artifact, reference_manifest};
use vecdht_crypto::sign_revoke_identity;
use vecdht_net::{
    keys, Agent, AgentConfig, FindQuery, NetConfig, NetService, NetworkParams, PublishRequest,
};
use vecdht_node::{testing, Clock, ShardNode};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{
    domain, CertRevoke, Codec, MatchResult, PublishAck, ProtocolError, Role,
};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
/// Сложность эталонного артефакта: её умеет майнить `mine_pow` (18..=24, §11.1).
const POW_ARTIFACT: u32 = 20;

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
        revoked_dir: None,
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
    index_service_with_pow(seed, dir, listen, POW)
}

/// Тот же узел, но со сложностью артефакта: `mine_pow` принимает только 18..=24 (§11.1), и
/// клиентский путь обязан проверяться на сложности, которую умеет считать реальный майнер.
fn index_service_with_pow(seed: u8, dir: &Path, listen: Multiaddr, pow: u32) -> NetService {
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let mut node = ShardNode::open(
        dir,
        SHARD,
        id.clone(),
        peer.to_bytes(),
        testing::params(pow),
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

/// Отзыв §4.2, подписанный первыми `signers` ключами эталонного набора 3-of-5. Тест играет
/// авторитетом; сеть не получает приватных ключей и проверяет только порог.
fn revoke_for(nonce: [u8; 16], signers: usize) -> CertRevoke {
    let mut r = CertRevoke {
        nonce,
        revoked_at: now_sec() as u32,
        reason: "тестовый отзыв".to_string(),
        authority_sigs: Vec::new(),
    };
    for a in testing::authorities().iter().take(signers) {
        r = sign_revoke_identity(&r, a);
    }
    r
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

// --- клиент §12 ----------------------------------------------------------------

/// Параметры агента: та же сеть и та же сложность, что у тестового узла. Не константа клиента:
/// genesis/модель/TTL/PoW выводятся из манифеста, иначе агент публиковал бы в другую сеть.
fn agent_network() -> NetworkParams {
    NetworkParams::from_artifact(&reference_artifact()).expect("параметры артефакта")
}

fn agent_cfg(bootstrap: Vec<Multiaddr>) -> AgentConfig {
    AgentConfig {
        bootstrap,
        listen: vec![quic_addr()],
        call_timeout: Duration::from_secs(40),
        ..AgentConfig::default()
    }
}

/// Крутить узлы, пока фоновая задача агента не вернёт результат. Агент шагает своё соединение
/// сам (внутри `publish`/`find`/`open_session`); узлы обязаны шагать извне, иначе ack W=2 и
/// handshake не сдвинутся.
async fn pump_nodes_until<T>(
    primary: &mut NetService,
    replica: &mut NetService,
    rx: &mut oneshot::Receiver<T>,
) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(50);
    loop {
        if let Ok(v) = rx.try_recv() {
            return v;
        }
        assert!(
            !rx.is_terminated(),
            "задача агента завершилась без результата; ошибки P={:?} R={:?}",
            primary.take_errors(),
            replica.take_errors()
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "агент не получил результат за 50 с; ошибки P={:?} R={:?}",
            primary.take_errors(),
            replica.take_errors()
        );
        primary.step().await;
        replica.step().await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// §12 целиком на настоящем транспорте: агент публикует запись через DHT-провайдера, второй
/// агент находит её, проверяет подписи и приём, затем открывает прямой аутентифицированный канал
/// к владельцу записи.
///
/// Сессия здесь — именно канал, а не обмен текстами: `IntentTextRequest` в `ShardNode` v1 не
/// обслуживается, и тест не изображает то, чего нет. Зато он проверяет то, что есть: приём
/// выписан на настоящего владельца, подпись издателя сходится с handshake, а `PeerId` цели
/// соответствует её Ed25519-ключу.
#[test]
fn an_agent_publishes_finds_and_opens_a_direct_session() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let local = LocalSet::new();
        local
            .run_until(async {
                let d_primary = dir("agent-e2e-primary");
                let d_replica = dir("agent-e2e-replica");
                let primary_id = primary_seed();
                let replica_id =
                    *SEEDS.iter().find(|s| **s != primary_id).expect("второй тестовый сид");
                let mut primary = index_service_with_pow(primary_id, &d_primary, quic_addr(), POW_ARTIFACT);
                let mut replica = index_service_with_pow(replica_id, &d_replica, quic_addr(), POW_ARTIFACT);
                let primary_addr = wait_listen(&mut primary).await;
                let _ = wait_listen(&mut replica).await;
                replica.dial(primary_addr.clone()).expect("dial primary репликой");

                let publisher_id = testing::identity(77);
                let finder_id = testing::identity(99);
                let finder_owner = finder_id.pubkey();
                let mut publisher = Agent::new(
                    publisher_id.clone(),
                    agent_network(),
                    agent_cfg(vec![primary_addr.clone()]),
                )
                .expect("агент-издатель");
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                while publisher.listen_addrs().is_empty() {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "listener агента не поднялся"
                    );
                    publisher.net_mut().step().await;
                    primary.step().await;
                }
                let publisher_addr = publisher.listen_addrs()[0].clone();
                let publisher_peer = publisher.peer_id();
                let publish_req = PublishRequest::new(
                    testing::vector(3),
                    CLUSTER,
                    225,
                    testing::PREPROCESSING_VERSION,
                );
                let (tx, mut rx) = oneshot::channel();
                // После publish тот же агент обязан остаться на связи: приём цели предъявляется
                // уже открытому каналу, а входящий handshake принимает только шагающий
                // `NetService`. Поэтому не `publish`, а `publish`, затем вечный `run`.
                local.spawn_local(async move {
                    let r = publisher.publish(&publish_req).await;
                    let _ = tx.send(r);
                    publisher.run().await;
                });
                let receipt = pump_nodes_until(&mut primary, &mut replica, &mut rx)
                    .await
                    .expect("публикация через агента");
                assert_eq!(receipt.shard, SHARD);
                assert_eq!(receipt.ttl_buckets, 225);
                assert_eq!(receipt.expires_bucket, receipt.published_bucket + 225);
                assert_eq!(receipt.intent_id, publish_req.intent_id);
                assert_eq!(receipt.primary, primary.peer_id(), "аккаунт durable-записи — primary");
                assert!(
                    primary.node(SHARD).is_some_and(|n| n
                        .store
                        .index
                        .owner_slot(&publisher_id.pubkey())
                        .is_some()),
                    "primary обязан держать запись автора, а не копию"
                );

                let mut finder = Agent::new(
                    finder_id,
                    agent_network(),
                    agent_cfg(vec![primary_addr, publisher_addr]),
                )
                .expect("агент-искатель");

                let query = FindQuery::new(testing::vector(3), vec![CLUSTER], 5);
                let (tx, mut rx) = oneshot::channel();
                local.spawn_local(async move {
                    let r = finder.find(&query).await;
                    let _ = tx.send((finder, r));
                });
                let (mut finder, outcome) =
                    pump_nodes_until(&mut primary, &mut replica, &mut rx).await;
                let outcome = outcome.expect("поиск через агента");
                assert!(outcome.failures.is_empty(), "отказы шардов: {:?}", outcome.failures);
                assert_eq!(outcome.matches.len(), 1, "опубликованный вектор обязан найтись");
                let found = &outcome.matches[0];
                assert_eq!(found.owner_ed25519, publisher_id.pubkey());
                assert_eq!(found.slot, receipt.slot);
                assert_eq!(found.shard, SHARD);
                let grant = found.grant.clone().expect("приём на найденную запись");
                assert_eq!(grant.accept.target, publisher_id.pubkey());
                assert_eq!(grant.accept.seeker, finder_owner);
                assert_eq!(grant.accept.slot, receipt.slot);
                assert_eq!(grant.issuer, outcome.answers[0].owner);

                let (tx, mut rx) = oneshot::channel();
                let grant_for_session = grant.clone();
                let grant_issuer = grant.issuer;
                local.spawn_local(async move {
                    let r = finder.open_session(&grant_for_session).await;
                    let _ = tx.send((finder, r));
                });
                let (_finder, session) =
                    pump_nodes_until(&mut primary, &mut replica, &mut rx).await;
                let session = session.expect("прямая сессия к владельцу записи");
                assert_eq!(session.peer, publisher_peer);
                assert_eq!(session.owner, publisher_id.pubkey());
                assert_eq!(session.issuer, grant_issuer);
                assert_eq!(session.role, Role::Agent);
                assert_eq!(session.shard, SHARD);
                assert_eq!(session.slot, receipt.slot);
                assert!(session.direct, "relay-путь в v1 не поднят, и это не должно скрываться");
                assert!(
                    session.expires_bucket >= session.issued_bucket,
                    "граница жизни приёма считается тем же ceil, что у цели"
                );

                let _ = std::fs::remove_dir_all(&d_primary);
                let _ = std::fs::remove_dir_all(&d_replica);
            })
            .await;
    });
}

// --- отзыв кредашиала §4.2 ---------------------------------------------------

/// §4.2 на живом транспорте: отзыв, подписанный порогом, сбрасывает соединения с носителем
/// `nonce` и закрывает ему путь назад. Рассылает третья сторона, потому что gossipsub не
/// возвращает автору его собственное сообщение, а потерять надо обоих собеседников.
#[test]
fn a_threshold_revoke_drops_connections_and_blocks_reconnect() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d_a = dir("revoke-a");
        let d_b = dir("revoke-b");
        let seed_a = primary_seed();
        let seed_b = *SEEDS.iter().find(|s| **s != seed_a).expect("второй тестовый сид");
        let mut a = index_service(seed_a, &d_a, quic_addr());
        let mut b = index_service(seed_b, &d_b, quic_addr());
        let mut relay = agent_service(88, quic_addr());
        let addr_a = wait_listen(&mut a).await;
        let addr_b = wait_listen(&mut b).await;
        let _ = wait_listen(&mut relay).await;
        b.dial(addr_a.clone()).expect("B → A");
        relay.dial(addr_a.clone()).expect("relay → A");
        relay.dial(addr_b.clone()).expect("relay → B");
        let (pa, pb, pr) = (a.peer_id(), b.peer_id(), relay.peer_id());
        pump_until3(&mut a, &mut b, &mut relay, |x, y, z| {
            x.is_authenticated(&pb)
                && x.is_authenticated(&pr)
                && y.is_authenticated(&pa)
                && y.is_authenticated(&pr)
                && z.is_authenticated(&pa)
                && z.is_authenticated(&pb)
        })
        .await;

        let revoke = revoke_for([seed_b; 16], 3);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut errors = Vec::new();
        loop {
            // Gossip собирает mesh на heartbeat: повторная публикация — это доставка, а не
            // «отзыв с вероятностью». Получатель идемпотентен по nonce.
            let _ = relay.publish_revoke(&revoke);
            for _ in 0..10 {
                relay.step().await;
                a.step().await;
                b.step().await;
            }
            errors.extend(a.take_errors());
            errors.extend(b.take_errors());
            if a.is_revoked_nonce(&revoke.nonce) && b.is_self_revoked() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "отзыв не применён за 20 с; ошибки: {errors:?}"
            );
        }
        assert_eq!(a.revocation_count(), 1, "один отзыв — одна запись по nonce");
        assert!(a.peer_identity(&pb).is_none(), "A сбросил соединение с отозванным B");
        assert!(b.authenticated_peers().is_empty(), "B, отозвав себя, замолчал целиком");

        // Путь назад закрыт: B отклоняет handshake, а A не принимает его за живого.
        a.dial(addr_b).expect("повторный dial отозванного узла");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            a.step().await;
            b.step().await;
            relay.step().await;
        }
        assert!(!a.is_authenticated(&pb), "отозванный кредашиал не проходит handshake повторно");
        assert!(b.is_self_revoked());
        let _ = std::fs::remove_dir_all(&d_a);
        let _ = std::fs::remove_dir_all(&d_b);
    });
}

/// Порог проверяется на приёме, а не на рассылке: 2-of-5 доходит до узла, логируется как
/// отвергнутый и не трогает ни nonce, ни соединения. Затем тот же отзыв с третьей подписью
/// применяется — значит, отвергнут был именно порог, а не канал доставки.
#[test]
fn a_revoke_below_threshold_is_rejected_before_it_can_revoke() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d_a = dir("revoke-weak-a");
        let d_b = dir("revoke-weak-b");
        let seed_a = primary_seed();
        let seed_b = *SEEDS.iter().find(|s| **s != seed_a).expect("второй тестовый сид");
        let mut a = index_service(seed_a, &d_a, quic_addr());
        let mut b = index_service(seed_b, &d_b, quic_addr());
        let mut relay = agent_service(89, quic_addr());
        let addr_a = wait_listen(&mut a).await;
        let addr_b = wait_listen(&mut b).await;
        let _ = wait_listen(&mut relay).await;
        b.dial(addr_a.clone()).expect("B → A");
        relay.dial(addr_a.clone()).expect("relay → A");
        relay.dial(addr_b.clone()).expect("relay → B");
        let (pa, pb, pr) = (a.peer_id(), b.peer_id(), relay.peer_id());
        pump_until3(&mut a, &mut b, &mut relay, |x, y, z| {
            x.is_authenticated(&pb)
                && x.is_authenticated(&pr)
                && y.is_authenticated(&pa)
                && y.is_authenticated(&pr)
                && z.is_authenticated(&pa)
                && z.is_authenticated(&pb)
        })
        .await;

        let weak = revoke_for([seed_b; 16], 2);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut errors = Vec::new();
        loop {
            let _ = relay.publish_revoke(&weak);
            for _ in 0..10 {
                relay.step().await;
                a.step().await;
                b.step().await;
            }
            errors.extend(a.take_errors());
            if errors.iter().any(|e| e.contains("отзыв отвергнут")) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "ослабленный отзыв не дошёл до проверки за 20 с; ошибки: {errors:?}"
            );
        }
        assert!(!a.is_revoked_nonce(&weak.nonce), "2-of-5 не отзывает nonce");
        assert!(!b.is_self_revoked());
        assert_eq!(a.revocation_count(), 0);
        assert!(
            a.is_authenticated(&pb) && b.is_authenticated(&pa),
            "ослабленный отзыв не сбрасывает соединения"
        );

        let strong = revoke_for([seed_b; 16], 3);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let _ = relay.publish_revoke(&strong);
            for _ in 0..10 {
                relay.step().await;
                a.step().await;
                b.step().await;
            }
            if a.is_revoked_nonce(&strong.nonce) && b.is_self_revoked() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "тот же отзыв с третьей подписью не применён за 20 с"
            );
        }
        let _ = std::fs::remove_dir_all(&d_a);
        let _ = std::fs::remove_dir_all(&d_b);
    });
}

/// Отзыв — управляющий кадр, а не данные шарда. Валидный `CertRevoke` в shard-теме обязан
/// быть отвергнут по адресу: иначе отзыв увидели бы только подписчики одного шарда, а nonce
/// может покрывать несколько.
#[test]
fn a_valid_revoke_on_a_shard_topic_is_refused() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d_a = dir("revoke-topic-a");
        let d_b = dir("revoke-topic-b");
        let seed_a = primary_seed();
        let seed_b = *SEEDS.iter().find(|s| **s != seed_a).expect("второй тестовый сид");
        let mut a = index_service(seed_a, &d_a, quic_addr());
        let mut b = index_service(seed_b, &d_b, quic_addr());
        let mut relay = agent_service(90, quic_addr());
        let addr_a = wait_listen(&mut a).await;
        let addr_b = wait_listen(&mut b).await;
        let _ = wait_listen(&mut relay).await;
        b.dial(addr_a.clone()).expect("B → A");
        relay.dial(addr_a.clone()).expect("relay → A");
        relay.dial(addr_b.clone()).expect("relay → B");
        let (pa, pb, pr) = (a.peer_id(), b.peer_id(), relay.peer_id());
        pump_until3(&mut a, &mut b, &mut relay, |x, y, z| {
            x.is_authenticated(&pb)
                && x.is_authenticated(&pr)
                && y.is_authenticated(&pa)
                && y.is_authenticated(&pr)
                && z.is_authenticated(&pa)
                && z.is_authenticated(&pb)
        })
        .await;

        let revoke = revoke_for([seed_b; 16], 3);
        // Подпись кадра здесь ни на что не влияет: авторитетность `CertRevoke` — это порог
        // в теле. Кадровый `signed()` нужен только потому, что `publish_gossip` не пускает
        // неподписанные прикладные кадры.
        let frame = revoke.encode_signed(&[0x11; 64]);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut errors = Vec::new();
        loop {
            let _ = relay.publish_gossip(SHARD, frame.clone());
            for _ in 0..10 {
                relay.step().await;
                a.step().await;
                b.step().await;
            }
            errors.extend(a.take_errors());
            if errors.iter().any(|e| e.contains("CertRevoke вне control-темы")) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "отзыв в shard-теме не дошёл за 20 с; ошибки: {errors:?}"
            );
        }
        assert!(!a.is_revoked_nonce(&revoke.nonce));
        assert!(!b.is_self_revoked());
        assert_eq!(a.revocation_count(), 0);
        assert!(a.is_authenticated(&pb) && b.is_authenticated(&pa));
        let _ = std::fs::remove_dir_all(&d_a);
        let _ = std::fs::remove_dir_all(&d_b);
    });
}
