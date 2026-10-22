//! H-0077 / E-0077: §13/§14 — приватность (pad, джиттер) и проверяемость ответа.
//!
//! §13.3 (строка 1351) обещает митигацию метаданных: «соединение с владельцами шардов не
//! коррелирует по времени (параллельный fan-out с джиттером 0–150 мс), pad до фиксированного
//! `Find`-размера (384+2·nprobe+~40 ≈ круглое 512 байт)», а через семь строк (1353–1358) —
//! «полный скан … кадр несёт 256 `u16` … pad-цель становится 384+2·256+~40 ≈ круглые 1024
//! байта» и «pad-цель в коде должна быть параметром политики, а не константой».
//!
//! §14.2 (строки 1381–1384) обещает проверяемость ответа: «расхождение в пересечении … —
//! сигнал», «verifiable re-computation … пересчитать `l2_sq(q, v)` сам по int8-байтам»,
//! «owner попадает в локальный reputation table и исключается из display», «штрафуется».
//!
//! Наблюдатель — «сниффер»: настоящий libp2p-пир с валидным `NodeCert` (роль `IndexNode`,
//! подписан порогом эталонного набора), который отвечает на приветствие агента и **записывает
//! байты входящих `Find` вместе с моментом прихода**. Так видно тело запроса на проводе
//! целиком: `NetService` отдаёт запрос в шард (`route_app_frame`), а в `inbox` попадают
//! только кадры без шарда и ответы (`route_inbound`).
//!
//! Один процесс, настоящий QUIC на loopback, реальные часы.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::futures::StreamExt;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder};
use tokio::sync::oneshot;
use tokio::task::LocalSet;
use vecdht_artifact::{reference_artifact, reference_manifest};
use vecdht_crypto::Identity;
use vecdht_net::codec::FrameCodec;
use vecdht_net::{
    keys, Agent, AgentConfig, AgentError, FindOutcome, FindQuery, NetConfig, NetService, NetworkParams,
};
use vecdht_node::{testing, Clock, ShardNode};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::constants::shard_of;
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{domain, Codec, Find, Handshake, Match, MatchResult, Role};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
/// Сид сниффера: отдельный ключ, не совпадающий ни с сидами сети, ни с ключом агента.
const SNIFFER_SEED: u8 = 41;
/// Сид агента.
const AGENT_SEED: u8 = 77;

/// Исходник агента: проверка «пересчёта `l2_sq` в агенте нет» — по исходнику, а не по
/// впечатлению.
const AGENT_SRC: &str = include_str!("../src/agent.rs");

fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

/// Сеть агента: та же, что у узла, — genesis, модель и preprocessing берутся из артефакта.
fn agent_network() -> NetworkParams {
    NetworkParams::from_artifact(&reference_artifact()).expect("параметры артефакта")
}

fn agent_cfg(bootstrap: Vec<Multiaddr>, call_timeout: Duration) -> AgentConfig {
    AgentConfig {
        bootstrap,
        listen: vec![quic_addr()],
        call_timeout,
        request_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(5),
        ..AgentConfig::default()
    }
}

fn cfg(listen: Multiaddr, bootstrap: Vec<Multiaddr>) -> NetConfig {
    NetConfig {
        listen: vec![listen],
        bootstrap,
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

// --- сниффер ----------------------------------------------------------------

#[derive(NetworkBehaviour)]
struct SnifferBehaviour {
    frames: request_response::Behaviour<FrameCodec>,
}

/// Index-node без шарда: он честно проходит handshake (кредашиал подлинный, роль настоящая),
/// но **не держит** шард, поэтому и не отвечает на `Find` сам — а просто наблюдает байты.
struct Sniffer {
    swarm: Swarm<SnifferBehaviour>,
    id: Identity,
    greeting: Vec<u8>,
    /// Пойманные `Find`: момент прихода и байты кадра.
    caught: Vec<(Instant, Vec<u8>)>,
    /// `d2`, который index-node объявляет в ответе. 0 — «идеальное совпадение».
    d2: u32,
}

impl Sniffer {
    fn new(seed: u8, shards: Vec<u16>, d2: u32) -> Self {
        let id = testing::identity(seed);
        let peer = keys::peer_id(&id);
        let cert = testing::node_cert(seed, peer.to_bytes(), shards, Role::IndexNode, 0, u32::MAX);
        let greeting = Handshake {
            role: Role::IndexNode,
            preprocessing_version: testing::PREPROCESSING_VERSION,
            model_version: reference_manifest().model_version,
            genesis_hash: testing::genesis_hash(),
            cert: NodeCert::encode(&cert),
            tlv: Vec::new(),
        }
        .encode_unsigned();
        let swarm = SwarmBuilder::with_existing_identity(keys::keypair(&id))
            .with_tokio()
            .with_quic()
            .with_behaviour(|_key| {
                let protocols = std::iter::once((
                    StreamProtocol::new("/vecdht/v8/frame"),
                    ProtocolSupport::Full,
                ));
                SnifferBehaviour {
                    frames: request_response::Behaviour::<FrameCodec>::new(
                        protocols,
                        request_response::Config::default()
                            .with_request_timeout(Duration::from_secs(10)),
                    ),
                }
            })
            .expect("собрать поведение сниффера")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        Self { swarm, id, greeting, caught: Vec::new(), d2 }
    }

    async fn step(&mut self) {
        tokio::select! {
            ev = self.swarm.select_next_some() => self.on_event(ev),
            _ = tokio::time::sleep(Duration::from_millis(2)) => {}
        }
    }

    fn on_event(&mut self, ev: SwarmEvent<SnifferBehaviourEvent>) {
        let SwarmEvent::Behaviour(SnifferBehaviourEvent::Frames(ev)) = ev else { return };
        let request_response::Event::Message { message, .. } = ev else { return };
        let request_response::Message::Request { request, channel, .. } = message else { return };
        let kind = decode_frame(&request).map(|f| f.header.kind).ok();
        let reply = match kind {
            Some(Kind::Handshake) => vec![self.greeting.clone()],
            Some(Kind::Find) => {
                self.caught.push((Instant::now(), request.clone()));
                vec![self.answer(&request)]
            }
            _ => Vec::new(),
        };
        self.swarm.behaviour_mut().frames.send_response(channel, reply).ok();
    }

    /// Ответ index-node'а: подписанный `MatchResult` с одной записью. Владелец записи —
    /// отдельный ключ (не ответчик): в жизни запись принадлежит автору, а отвечает узел.
    fn answer(&self, find_bytes: &[u8]) -> Vec<u8> {
        let q = Find::decode(find_bytes).expect("агент шлёт разбираемый Find");
        let cluster = *q.clusters.first().expect("Find без кластеров");
        let res = MatchResult {
            shard: shard_of(cluster),
            epoch: 1,
            query_id: q.query_id,
            responder_ed25519: self.id.pubkey(),
            matches: vec![Match {
                owner_ed25519: record_owner(shard_of(cluster)),
                cluster_id: cluster,
                d2: self.d2,
                slot: 0,
            }],
        };
        res.check_sort_contract().expect("контракт сортировки §8.4");
        let body = res.body_bytes();
        let sig = self.id.sign_body(domain::MATCH, Kind::MatchResult, &body);
        res.encode_signed(&sig)
    }

    fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }
}

/// Ключ «автора записи» для шарда: отдельный от ответчика, чтобы дедупликация агента по
/// владельцу (§12.2, шаг 6) не схлопнула ответы разных шардов в один.
fn record_owner(shard: u16) -> [u8; 32] {
    testing::identity(90 + shard as u8).pubkey()
}

/// Длина подписанного `Find` по коду: заголовок 8 + тело (430 + 2n) + подпись 65.
const FIND_OVERHEAD: usize = 503;

/// Ждать, пока сниффер поднимет слушателя.
async fn wait_listen(s: &mut Sniffer) -> Multiaddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(a) = s.swarm.listeners().next().cloned() {
            return a;
        }
        assert!(tokio::time::Instant::now() < deadline, "listener сниффера не поднялся за 10 с");
        s.step().await;
    }
}

/// Крутить агента и сниффера, пока handshake не состоится с обеих сторон.
async fn pump_handshake(agent: &mut Agent, sniffer: &mut Sniffer) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        agent.net_mut().step().await;
        sniffer.step().await;
        if agent.net().is_authenticated(&sniffer.peer_id()) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "handshake не сошёлся за 20 с; ошибки агента={:?}",
            agent.net_mut().take_errors()
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Крутить сниффера, пока агент не закончит `find`.
async fn pump_until_outcome(
    sniffer: &mut Sniffer,
    rx: &mut oneshot::Receiver<Result<FindOutcome, AgentError>>,
) -> Result<FindOutcome, AgentError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(v) = rx.try_recv() {
            return v;
        }
        assert!(!rx.is_terminated(), "задача агента завершилась без результата");
        assert!(
            tokio::time::Instant::now() < deadline,
            "агент не закончил find за 60 с; ошибки={:?}",
            sniffer.caught.len()
        );
        sniffer.step().await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Дожаться конца потока: сниффер мог получить последний `Find` уже после возврата агента.
async fn drain(sniffer: &mut Sniffer) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while tokio::time::Instant::now() < deadline {
        sniffer.step().await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Длина пойманного `Find` и число запрошенных кластеров.
fn caught_shapes(sniffer: &Sniffer) -> Vec<(usize, u16)> {
    let mut out: Vec<(usize, u16)> = sniffer
        .caught
        .iter()
        .map(|(_, bytes)| {
            let q = Find::decode(bytes).expect("пойманный Find разбирается");
            (bytes.len(), q.clusters.len() as u16)
        })
        .collect();
    out.sort();
    out
}

// --- (0)(1)(2)(4) ------------------------------------------------------------

/// (0) база, (1) закон длины, (2) недостижимость pad-цели, (4) отсутствие джиттера.
#[test]
fn a_find_frame_has_a_fixed_overhead_and_carries_no_pad() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let local = LocalSet::new();
        local
            .run_until(async {
                // Сниффер покрывает три шарда: 5 (16 кластеров), 6 (2 кластера), 7 (1 кластер).
                let mut sniffer = Sniffer::new(SNIFFER_SEED, vec![5, 6, 7], 1234);
                let addr = wait_listen(&mut sniffer).await;
                let mut agent = Agent::new(
                    testing::identity(AGENT_SEED),
                    agent_network(),
                    agent_cfg(vec![addr], Duration::from_secs(20)),
                )
                .expect("агент");
                pump_handshake(&mut agent, &mut sniffer).await;

                let clusters: Vec<u16> = (80..=95).chain([96, 97]).chain([112]).collect();
                let query = FindQuery::new(testing::vector(3), clusters, 10);
                let (tx, mut rx) = oneshot::channel();
                local.spawn_local(async move {
                    let r = agent.find(&query).await;
                    let _ = tx.send(r);
                });
                let outcome = pump_until_outcome(&mut sniffer, &mut rx)
                    .await
                    .expect("поиск завершился отказом");
                drain(&mut sniffer).await;

                // (0) база: ответы приняты, отказов нет.
                assert!(outcome.failures.is_empty(), "отказы шардов: {:?}", outcome.failures);
                assert_eq!(outcome.answers.len(), 3, "ответов шардов: {:?}", outcome.answers);
                assert_eq!(outcome.matches.len(), 3, "записей в шортлисте: {:?}", outcome.matches);
                for m in &outcome.matches {
                    assert_eq!(m.d2, 1234, "агент принял чужое d2");
                }

                // (1) закон длины: len == 503 + 2n, TLV пуст.
                let shapes = caught_shapes(&sniffer);
                assert_eq!(shapes.len(), 3, "поймано кадров: {:?}", shapes);
                let lengths: Vec<usize> = shapes.iter().map(|(l, _)| *l).collect();
                let counts: Vec<u16> = shapes.iter().map(|(_, n)| *n).collect();
                assert_eq!(counts, vec![1, 2, 16], "число кластеров в кадрах: {:?}", counts);
                assert_eq!(lengths, vec![505, 507, 535], "длины `Find` на проводе: {:?}", lengths);
                for (len, n) in shapes.iter() {
                    assert_eq!(*len, FIND_OVERHEAD + 2 * *n as usize, "длина `Find`: {len} при n={n}");
                }
                for (_, bytes) in &sniffer.caught {
                    let q = Find::decode(bytes).expect("пойманный Find разбирается");
                    assert!(q.tlv.is_empty(), "TLV-хвост непуст: {:?}", q.tlv);
                }
                // Разности длин равны ровно 2·Δn: 2 (n: 1→2), 28 (2→16), 30 (1→16).
                let len_of = |n: u16| -> usize {
                    lengths
                        .iter()
                        .zip(counts.iter())
                        .find(|(_, c)| **c == n)
                        .map(|(l, _)| *l)
                        .expect("кадр с таким числом кластеров")
                };
                for (a, b) in [(1u16, 2u16), (2, 16), (1, 16)] {
                    let dl = len_of(b) - len_of(a);
                    let dn = b as usize - a as usize;
                    assert_eq!(dl, 2 * dn, "разность длин {a}→{b}: {dl} против 2·Δn = {}", 2 * dn);
                }

                // (2) обещанные pad-цели: ни одна длина не 512/1024, максимум 535.
                assert!(!lengths.contains(&512), "длина 512 достигнута: {lengths:?}");
                assert!(!lengths.contains(&1024), "длина 1024 достигнута: {lengths:?}");
                assert!(lengths.iter().all(|l| *l <= 535), "кадр длиннее 535: {lengths:?}");
                assert!(!AGENT_SRC.contains("512"), "в агенте появилась константа pad-цели");
                assert!(!AGENT_SRC.contains("pad"), "в агенте появился pad");

                // (4) джиттера нет: разброс прихода мал.
                let first = sniffer.caught.iter().map(|(t, _)| *t).min().expect("кадры есть");
                let last = sniffer.caught.iter().map(|(t, _)| *t).max().expect("кадры есть");
                let spread = last.duration_since(first);
                assert!(
                    spread < Duration::from_millis(20),
                    "разброс прихода `Find` = {spread:?} — джиттер есть"
                );
            })
            .await;
    });
}

// --- (3) ---------------------------------------------------------------------

/// (3) «полный скан» — это 16 кадров по 535 байт, а не один кадр на 1024 байта.
#[test]
fn a_full_scan_is_sixteen_frames_not_one_long_one() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let local = LocalSet::new();
        local
            .run_until(async {
                let mut sniffer = Sniffer::new(SNIFFER_SEED, (0..16).collect(), 777);
                let addr = wait_listen(&mut sniffer).await;
                let mut agent = Agent::new(
                    testing::identity(AGENT_SEED),
                    agent_network(),
                    agent_cfg(vec![addr], Duration::from_secs(20)),
                )
                .expect("агент");
                pump_handshake(&mut agent, &mut sniffer).await;

                let clusters: Vec<u16> = (0..256).collect();
                let query = FindQuery::new(testing::vector(3), clusters, 10);
                let (tx, mut rx) = oneshot::channel();
                local.spawn_local(async move {
                    let r = agent.find(&query).await;
                    let _ = tx.send(r);
                });
                let outcome = pump_until_outcome(&mut sniffer, &mut rx)
                    .await
                    .expect("поиск завершился отказом");
                drain(&mut sniffer).await;

                assert!(outcome.failures.is_empty(), "отказы шардов: {:?}", outcome.failures);
                let shapes = caught_shapes(&sniffer);
                assert_eq!(shapes.len(), 16, "кадров полного скана: {:?}", shapes.len());
                for (len, n) in &shapes {
                    assert_eq!(*n, 16, "в кадре не 16 кластеров: {n}");
                    assert_eq!(*len, 535, "длина кадра полного скана: {len}");
                }
                assert!(
                    shapes.iter().all(|(l, _)| *l < 1024),
                    "появился кадр ≥1024 байт: {shapes:?}"
                );
                let total: usize = shapes.iter().map(|(l, _)| *l).sum();
                assert_eq!(total, 16 * 535, "суммарный объём полного скана: {total}");
            })
            .await;
    });
}

// --- (5) ---------------------------------------------------------------------

/// (5) фан-аут последователен: вторая группа ждёт разрешения первой.
#[test]
fn the_second_shard_waits_for_the_first() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let local = LocalSet::new();
        local
            .run_until(async {
                // Сниффер покрывает только шард 7: у шарда 3 владельца нет, и его разрешение
                // съедает весь `call_timeout`.
                let mut sniffer = Sniffer::new(SNIFFER_SEED, vec![SHARD], 4321);
                let addr = wait_listen(&mut sniffer).await;
                let call_timeout = Duration::from_secs(2);
                let mut agent = Agent::new(
                    testing::identity(AGENT_SEED),
                    agent_network(),
                    agent_cfg(vec![addr], call_timeout),
                )
                .expect("агент");
                pump_handshake(&mut agent, &mut sniffer).await;

                // Кластеры шарда 3 (48) и шарда 7 (112): группы идут по возрастанию шарда,
                // первая — без владельца.
                let query = FindQuery::new(testing::vector(3), vec![48, 112], 10);
                let (tx, mut rx) = oneshot::channel();
                let start = Instant::now();
                local.spawn_local(async move {
                    let r = agent.find(&query).await;
                    let _ = tx.send(r);
                });
                let outcome = pump_until_outcome(&mut sniffer, &mut rx)
                    .await
                    .expect("поиск завершился отказом");
                drain(&mut sniffer).await;

                assert!(
                    outcome.failures.iter().any(|f| f.shard == 3),
                    "шард 3 должен остаться без владельца: {:?}",
                    outcome.failures
                );
                let caught: Vec<&(Instant, Vec<u8>)> = sniffer
                    .caught
                    .iter()
                    .filter(|(_, bytes)| {
                        let q = Find::decode(bytes).expect("Find разбирается");
                        shard_of(q.clusters[0]) == SHARD
                    })
                    .collect();
                assert_eq!(caught.len(), 1, "поймано `Find` по шарду 7: {:?}", caught.len());
                let delay = caught[0].0.duration_since(start);
                assert!(
                    delay >= Duration::from_millis(1600),
                    "`Find` второй группы ушёл через {delay:?} — ожидалось ≥1,6 с (последовательно)"
                );
            })
            .await;
    });
}

// --- (6)(7)(8) ----------------------------------------------------------------

/// (6) §14.2 re-computation невыполнимо: лжец в `d2` неотличим от честного ответа.
/// (7) «расхождение в пересечении» невозможно по построению.
/// (8) reputation table и штраф отсутствуют.
#[test]
fn a_lying_node_can_fabricate_a_distance_and_nobody_checks_it() {
    // (7) Множества кластеров разных шардов не пересекаются: `shard_of(c) = c/16`.
    let mut intersections = 0usize;
    for a in 0..64u16 {
        for b in 0..64u16 {
            if a == b {
                continue;
            }
            for c in 0..1024u16 {
                if shard_of(c) == a && shard_of(c) == b {
                    intersections += 1;
                }
            }
        }
    }
    assert_eq!(intersections, 0, "пересечения множеств кластеров разных шардов");

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let local = LocalSet::new();
        local
            .run_until(async {
                let mut sniffer = Sniffer::new(SNIFFER_SEED, vec![SHARD], 0);
                let addr = wait_listen(&mut sniffer).await;
                let mut agent = Agent::new(
                    testing::identity(AGENT_SEED),
                    agent_network(),
                    agent_cfg(vec![addr], Duration::from_secs(20)),
                )
                .expect("агент");
                pump_handshake(&mut agent, &mut sniffer).await;

                let query = FindQuery::new(testing::vector(3), vec![CLUSTER], 10);
                let (tx, mut rx) = oneshot::channel();
                local.spawn_local(async move {
                    let r = agent.find(&query).await;
                    let _ = tx.send(r);
                });
                let outcome = pump_until_outcome(&mut sniffer, &mut rx)
                    .await
                    .expect("поиск завершился отказом");
                drain(&mut sniffer).await;

                // (6) Выдуманный `d2 = 0` принят: подпись, шард, роль и сортировка сошлись,
                // а расстояние проверить нечем.
                assert!(outcome.failures.is_empty(), "отказы шардов: {:?}", outcome.failures);
                assert_eq!(outcome.matches.len(), 1, "шортлист: {:?}", outcome.matches);
                let m = &outcome.matches[0];
                assert_eq!(m.d2, 0, "агент принял выдуманное расстояние");
                assert_eq!(m.cluster_id, CLUSTER);
                assert_ne!(m.owner_ed25519, sniffer.id.pubkey(), "владелец записи — не ответчик");
                assert!(
                    (m.similarity() - 1.0).abs() < f32::EPSILON,
                    "сходство выдуманной записи: {}",
                    m.similarity()
                );
                // Тело ответа не несёт байтов записи: 94 байта на одну запись (int8-вектор — 384).
                let probe = MatchResult {
                    shard: SHARD,
                    epoch: 1,
                    query_id: 1,
                    responder_ed25519: sniffer.id.pubkey(),
                    matches: vec![Match {
                        owner_ed25519: record_owner(SHARD),
                        cluster_id: CLUSTER,
                        d2: 0,
                        slot: 0,
                    }],
                };
                assert_eq!(probe.body_bytes().len(), 94, "тело `MatchResult` с одной записью");
                // (6) Пересчёта в агенте нет: функция расстояния не вызывается ни разу.
                assert!(!AGENT_SRC.contains("l2_sq"), "в агенте появился пересчёт `l2_sq`");
                assert!(!AGENT_SRC.contains("quant::"), "в агенте появился вызов `quant::`");

                // (8) Таблицы репутации нет: слово не встречается ни разу.
                assert!(!AGENT_SRC.contains("reputation"), "в агенте появилась reputation table");
                assert!(!AGENT_SRC.contains("penalty"), "в агенте появился штраф");
            })
            .await;
    });
}

// --- (9) ---------------------------------------------------------------------

/// (9) TLV-хвост — переноситель pad'а: узел принимает `Find` с непустым хвостом и отвечает.
#[test]
fn a_node_accepts_a_find_with_a_pad_tail() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let dir = std::env::temp_dir()
            .join(format!("vecdht-s13-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("временный каталог теста");

        let node_id = testing::identity(1);
        let node_peer = keys::peer_id(&node_id);
        let mut node = ShardNode::open(
            &dir,
            SHARD,
            node_id.clone(),
            node_peer.to_bytes(),
            testing::params(POW),
            testing::authority_set(),
            testing::holders(&SEEDS),
        )
        .expect("открыть узел шарда");
        node.on_frame(
            testing::identity(9).pubkey(),
            &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
            testing::clock(Clock::at(now_sec()).bucket),
        )
        .expect("genesis");
        let cert = testing::node_cert(1, node_peer.to_bytes(), vec![SHARD], Role::IndexNode, 0, u32::MAX);
        let mut node_svc = NetService::new(
            node_id,
            Role::IndexNode,
            Some(cert),
            vec![node],
            testing::authority_set(),
            cfg(quic_addr(), Vec::new()),
        )
        .expect("сервис узла");
        let node_addr = wait_listen_service(&mut node_svc).await;

        let agent_id = testing::identity(AGENT_SEED);
        let mut agent_svc = NetService::new(
            agent_id.clone(),
            Role::Agent,
            None,
            Vec::new(),
            testing::authority_set(),
            cfg(quic_addr(), vec![node_addr]),
        )
        .expect("сервис агента");

        // Дождаться handshake: без него узел отвечает `DENIED` (§4.2).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !agent_svc.is_authenticated(&node_peer) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "handshake не сошёлся; ошибки={:?}",
                agent_svc.take_errors()
            );
            agent_svc.step().await;
            node_svc.step().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // `Find` с pad-хвостом: неизвестный тег, 7 байт набивки.
        let pad: Vec<u8> = vec![0u8; 7];
        let query = Find {
            preprocessing_version: testing::PREPROCESSING_VERSION,
            query_vector: testing::vector(3),
            clusters: vec![CLUSTER],
            top_k: 5,
            query_id: 4242,
            requester_ed25519: agent_id.pubkey(),
            tlv: vec![(0x0100, pad.clone())],
        };
        let body = query.body_bytes();
        let sig = agent_id.sign_body(domain::FIND, Kind::Find, &body);
        let frame = query.encode_signed(&sig);
        assert_eq!(frame.len(), FIND_OVERHEAD + 2 + 4 + pad.len(), "длина `Find` с pad");
        assert!(agent_svc.send_frame(node_peer, frame), "кадр не отправлен");

        // Ответ узла: `MatchResult` по шарду 7.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut answer = None;
        while answer.is_none() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "узел не ответил; ошибки={:?}",
                node_svc.take_errors()
            );
            agent_svc.step().await;
            node_svc.step().await;
            for (_, bytes) in agent_svc.take_inbox() {
                let Ok(frame) = decode_frame(&bytes) else { continue };
                if frame.header.kind == Kind::MatchResult {
                    answer = MatchResult::decode(&bytes).ok();
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let answer = answer.expect("ответ узла");
        assert_eq!(answer.shard, SHARD, "ответ по другому шарду");
        assert_eq!(answer.query_id, 4242, "query_id не эхом");
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// Ждать, пока сервис поднимет слушателя.
async fn wait_listen_service(s: &mut NetService) -> Multiaddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(a) = s.listen_addrs().first() {
            return a.clone();
        }
        assert!(tokio::time::Instant::now() < deadline, "listener не поднялся за 10 с");
        s.step().await;
    }
}
