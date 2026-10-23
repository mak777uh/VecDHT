//! Оракул `E-0080` (`H-0080`): §16.3 — «шард без живого владельца».
//! Пороги зафиксированы в `lab/hypotheses/H-0080-shard-without-live-owner.md` ДО написания
//! этого файла и после не двигались.
//!
//! Проверяемое обещание спеки (строка 1470): «корректная замена — „шард без живого владельца":
//! агент видит пустой DHT-ответ по ключу шарда, повторяет lookup с backoff и, если шард пуст,
//! пишет интент первому узлу, готовому взять эпизоду (§9.3). Никакого отдельного протокола для
//! деградации нет.»
//!
//! Девять проверок идут по цепочке обещания:
//!
//! * (0) что делает узел без эпизоды с чтением и с записью;
//! * (1) порождает ли это состояние хоть одно протокольное действие;
//! * (2) чем заканчивается валидный, но не совпадающий с ростером genesis;
//! * (3) есть ли локальное условие «готов взять эпизоду» — таблица четырёх состояний;
//! * (4) какой отказ видит агент на шарде без эпизоды: `NoProviders` или что-то другое;
//! * (5) наступает ли предпосылка «пустой DHT-ответ»;
//! * (6) оплачен ли PoW под эпоху, которую никто не обслуживает;
//! * (7) повторяет ли агент запись после `NOT_OWNER` и держит ли названную паузу;
//! * (8) меняет ли второй кандидат исход или только цену.
//!
//! (0)…(3) — узел без транспорта, но байты кадров настоящие. (4)…(8) — настоящий QUIC на
//! loopback: либо живой `ShardNode` внутри `NetService`, либо «сниффер» — index-node с
//! подлинным `NodeCert`, который шард не держит, отвечает на `Find` нулевой эпохой и записывает
//! байты `Publish`. Цена попытки измеряется числом пойманных `Publish`, а не временем: ДИАГНОЗ-5
//! из `E-0079` показал, что относительные временны́е выводы на одном прогоне неустойчивы. Время
//! в (7) служит только одним порогом — «названная узлом пауза в 9 с не выдержана».

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::futures::StreamExt;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder};
use tokio::sync::oneshot;
use tokio::task::LocalSet;
use vecdht_artifact::{reference_artifact, reference_manifest};
use vecdht_crypto::{intent_id, pow_input, pow_ok, Identity};
use vecdht_net::codec::FrameCodec;
use vecdht_net::{
    keys, Agent, AgentConfig, AgentError, NetConfig, NetService, NetworkParams, PublishReceipt,
    PublishRequest,
};
use vecdht_node::membership::GENESIS_EPOCH;
use vecdht_node::{testing, Clock, Envelope, ShardNode};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::constants::shard_of;
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{
    domain, err_code, Codec, Find, Handshake, MatchResult, ProtocolError, Publish, Role,
};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
/// Ростер, чей детерминированный состав узлу неизвестен: тот же genesis-механизм, другие ключи.
const FOREIGN_SEEDS: [u8; 3] = [11, 12, 13];
/// Сложность узла для узловых проверок: `testing::mine` майнит дёшево, а политический пол
/// 18..=24 нужен там, где работает настоящий клиентский майнер (§11.2).
const POW_NODE: u32 = 8;
/// Сложность эталонного артефакта: её майнит `Agent::publish`.
const POW_ARTIFACT: u8 = 20;
const AGENT_SEED: u8 = 77;
const SNIFFER_SEED: u8 = 41;
/// Пауза, названная «узлом» при `NOT_OWNER`: заведомо длиннее всего сценария, чтобы пропуск
/// `wait()` было видно без спора о наносекундах.
const NAMED_PAUSE_MS: u32 = 9_000;

fn dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("vecdht-net-s163-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("временный каталог теста");
    p
}

fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

fn bucket_now() -> u32 {
    Clock::at(now_sec()).bucket
}

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
        agent_version: "vecdht-net-s163/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
    }
}

// --- разбор ответов узла -------------------------------------------------------

/// Первый `ProtocolError` среди ответов узла.
fn error_of(envs: &[Envelope]) -> Option<ProtocolError> {
    envs.iter().find_map(|e| {
        decode_frame(&e.frame).ok().filter(|f| f.header.kind == Kind::Error)?;
        ProtocolError::decode(&e.frame).ok()
    })
}

/// Первый `MatchResult` среди ответов узла.
fn match_of(envs: &[Envelope]) -> Option<MatchResult> {
    envs.iter().find_map(|e| {
        decode_frame(&e.frame).ok().filter(|f| f.header.kind == Kind::MatchResult)?;
        MatchResult::decode(&e.frame).ok()
    })
}

/// Виды кадров ответа: для печати и для проверки «принято, а не откачено».
fn kinds_of(envs: &[Envelope]) -> Vec<Kind> {
    envs.iter().filter_map(|e| decode_frame(&e.frame).ok().map(|f| f.header.kind)).collect()
}

fn code_of(envs: &[Envelope]) -> String {
    error_of(envs).map(|e| e.code).unwrap_or_default()
}

fn retry_of(envs: &[Envelope]) -> u32 {
    error_of(envs).map(|e| e.retry_after_ms).unwrap_or(0)
}

/// Холодный узел шарда: сертификат и ростер есть, принятой эпизоды нет.
fn cold_node(name: &str, seed: u8) -> (PathBuf, ShardNode) {
    let d = dir(name);
    let n = testing::node(&d, SHARD, seed, testing::params(POW_NODE), &SEEDS);
    (d, n)
}

/// Genesis эпохи 1 для собственного ростера узла, подписанный порогом авторитетов (§15.2).
fn genesis_for() -> Vec<u8> {
    testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0))
}

/// Genesis того же механизма, но состава, который узел не выбрал бы.
fn genesis_foreign() -> Vec<u8> {
    testing::signed_frame(&testing::genesis_update(SHARD, &FOREIGN_SEEDS, 0))
}

/// Честный `Publish` от агента под эпоху 1 — ровно то, что присылает клиент, знающий эпизоду.
/// Узел без эпизоды обязан отвергнуть его до проверки nonce.
fn honest_publish(agent: &Identity, bucket: u32) -> Vec<u8> {
    let spec = testing::PublishSpec {
        agent,
        vec_q: &testing::vector(3),
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch: 1,
        published_bucket: bucket,
        ttl_buckets: 225,
        bits: POW_NODE,
    };
    spec.frame()
}

/// Primary шарда по порядку §9.3: тест не вправе назначать его первым сидом.
fn primary_seed() -> u8 {
    let order = vecdht_node::candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    SEEDS
        .into_iter()
        .find(|s| testing::identity(*s).pubkey() == order[0].owner_ed25519)
        .expect("primary — один из тестовых сидов")
}

fn replica_seed() -> u8 {
    let p = primary_seed();
    *SEEDS.iter().find(|s| **s != p).expect("в ростере есть узел не-primary")
}

// --- (0) узел без эпизоды: читает, но не пишет ---------------------------------

/// §16.3 описывает поведение агента, а всё поведение агента вырастает из ответов узла. Первый
/// вопрос: что делает узел, у которого есть сертификат на шард, но нет ни одной принятой
/// эпизоды.
#[test]
fn a_shard_without_an_epoch_answers_reads_and_refuses_writes() {
    let agent = testing::identity(AGENT_SEED);
    let from = agent.pubkey();
    let b = bucket_now();
    let (d, mut node) = cold_node("s163-read-write", 1);

    let find = testing::find_frame(&agent, &testing::vector(3), &[CLUSTER], 10, 1);
    let reads = node.on_frame(from, &find, testing::clock(b)).expect("Find разобран");
    let writes = node
        .on_frame(from, &honest_publish(&agent, b), testing::clock(b))
        .expect("Publish разобран");

    let m = match_of(&reads).expect("чтение обслуживается подписанным MatchResult");
    let e = error_of(&writes).expect("запись отвергается ProtocolError");

    eprintln!(
        "## (0) узел без эпизоды: чтение → MatchResult{{epoch={}, matches={}}}, запись → {} (retry {} мс, шард {}) ##",
        m.epoch,
        m.matches.len(),
        e.code,
        e.retry_after_ms,
        e.shard
    );

    // (0.1) Чтение обслуживается и честно называет нулевую эпоху.
    assert_eq!(m.epoch, 0, "узел без эпизоды обязан объявить epoch = 0, а не выдуманную");
    assert!(m.matches.is_empty(), "пустой индекс обязан отдать пустой список, а не ошибку");
    // (0.2) Запись отвергается до проверки PoW — узел не тратит blake3 на работу, которую не примет.
    assert_eq!(e.code, err_code::NOT_OWNER, "отказ записи: {:?}", e.code);
    assert_eq!(e.retry_after_ms, 1_000, "NOT_OWNER обязан назвать 1000 мс (§12.1)");
    assert_eq!(node.epoch(), None, "состояние «без эпизоды» не сдвинулось");
    let _ = std::fs::remove_dir_all(&d);
}

// --- (1) состояние молчит ------------------------------------------------------

/// «Шард без живого владельца» — не событие и не кадр: узел в этом состоянии не предлагает
/// состав, не продлевает lease и не объявляет эпоху. Три молчания собраны в один факт, потому
/// что именно на них опирается надежда §16.3 «деградация без отдельного протокола».
#[test]
fn an_epochless_holder_produces_no_protocol_action_at_all() {
    let (d, mut node) = cold_node("s163-silent", 1);
    let b = bucket_now();
    let from = testing::identity(9).pubkey();

    let ticks = node.tick(b + 100).expect("tick холодного узла не обязан падать");
    let is_member = node.is_member();
    let adoption = node.on_frame(from, &genesis_foreign(), testing::clock(b)).expect("разобран");

    eprintln!(
        "## (1) узел без эпизоды: tick → {} кадров, is_member={}, чужой genesis → {} кадров, epoch={:?} ##",
        ticks.len(),
        is_member,
        adoption.len(),
        node.epoch()
    );

    assert!(ticks.is_empty(), "холодный узел не рассылает на тике ничего: {:?}", kinds_of(&ticks));
    assert!(!is_member, "без принятого состава узел не имеет права голоса");
    assert!(adoption.is_empty(), "чужой genesis обязан быть отброшен молча, а не ответом");
    assert_eq!(node.epoch(), None);
    assert!(!node.is_primary(), "primary — функция принятого состава, а не кредашиала");
    let _ = std::fs::remove_dir_all(&d);
}

// --- (2) genesis: молчание против приёма ----------------------------------------

/// Единственный известный способ открыть эпоху — `MembershipUpdate` эпохи 1 с пороговой подписью
/// авторитетов. Узел принимает только тот genesis, чей состав сходится с его собственным
/// детерминированным выбором (§9.3); расхождение он не комментирует. Контроль в том же тесте:
/// совпадающий состав принимается, и эпоха наступает.
#[test]
fn only_the_matching_genesis_opens_an_epoch_and_the_mismatch_is_silent() {
    let from = testing::identity(9).pubkey();
    let b = bucket_now();

    let (d1, mut n1) = cold_node("s163-genesis-mismatch", 1);
    let out_m = n1.on_frame(from, &genesis_foreign(), testing::clock(b)).expect("разобран");

    let (d2, mut n2) = cold_node("s163-genesis-match", 1);
    let out_ok = n2.on_frame(from, &genesis_for(), testing::clock(b)).expect("разобран");

    eprintln!(
        "## (2) genesis не своего состава: ответов {}, epoch={:?}; genesis своего состава: ответов {}, epoch={:?} ##",
        out_m.len(),
        n1.epoch(),
        out_ok.len(),
        n2.epoch()
    );

    assert_eq!(n1.epoch(), None, "чужой состав не открывает эпоху");
    assert!(out_m.is_empty(), "отказ обязан быть молчанием, а не ответом: {:?}", kinds_of(&out_m));
    assert_eq!(n2.epoch(), Some(GENESIS_EPOCH), "контроль: совпадающий genesis принят");
    assert_eq!(
        error_of(&out_ok).map(|e| e.code),
        None,
        "принятие эпохи не сопровождается отказом"
    );
    let _ = std::fs::remove_dir_all(&d1);
    let _ = std::fs::remove_dir_all(&d2);
}

// --- (3) таблица состояний -----------------------------------------------------

/// Главный вопрос §16.3: существует ли локальное условие «узел готов взять эпизоду». Модель
/// `lab/lean/VecDHT/Shard.lean` исчерпала все 64 конъюнкции шести локальных признаков и дала
/// пустое множество. Здесь независимое подтверждение на четырёх состояниях, которые модель
/// выделяет как единственные значимые: сертификат без состава, реплика, primary без lease,
/// primary с lease.
#[test]
fn the_four_local_states_name_which_one_takes_a_write() {
    let agent = testing::identity(AGENT_SEED);
    let from = agent.pubkey();
    let b = bucket_now();
    let lease = testing::params(POW_NODE).lease_buckets;
    let mut rows: Vec<(&str, String, u32, usize)> = Vec::new();

    // Состояние 1: сертификат есть, эпизоды нет.
    let (d1, mut n1) = cold_node("s163-state-cert", 1);
    let r1 = n1.on_frame(from, &honest_publish(&agent, b), testing::clock(b)).expect("разобран");
    rows.push(("сертификат, без состава", code_of(&r1), retry_of(&r1), r1.len()));

    // Состояние 2: член состава, но не primary.
    let (d2, mut n2) = cold_node("s163-state-replica", replica_seed());
    n2.on_frame(from, &genesis_for(), testing::clock(b)).expect("genesis");
    assert!(n2.is_member() && !n2.is_primary(), "тест строит реплику");
    let r2 = n2.on_frame(from, &honest_publish(&agent, b), testing::clock(b)).expect("разобран");
    rows.push(("член, не primary", code_of(&r2), retry_of(&r2), r2.len()));

    // Состояние 3: primary, lease истёк.
    let (d3, mut n3) = cold_node("s163-state-primary-no-lease", primary_seed());
    n3.on_frame(from, &genesis_for(), testing::clock(b)).expect("genesis");
    assert!(n3.is_primary(), "тест строит primary");
    let expired = b + lease + 1;
    assert!(!n3.lease_active(expired), "lease обязан считаться истёкшим");
    let r3 = n3.on_frame(from, &honest_publish(&agent, b), testing::clock(expired)).expect("разобран");
    rows.push(("primary, lease истёк", code_of(&r3), retry_of(&r3), r3.len()));

    // Состояние 4: primary с активным lease — единственное, где отказа нет.
    let (d4, mut n4) = cold_node("s163-state-primary-lease", primary_seed());
    n4.on_frame(from, &genesis_for(), testing::clock(b)).expect("genesis");
    assert!(n4.is_primary() && n4.lease_active(b), "тест строит primary с активным lease");
    let r4 = n4.on_frame(from, &honest_publish(&agent, b), testing::clock(b)).expect("разобран");
    rows.push(("primary, lease активен", code_of(&r4), retry_of(&r4), r4.len()));
    let accepted = kinds_of(&r4);

    for (name, code, retry, frames) in &rows {
        eprintln!("## (3) {name}: отказ={:?}, retry={} мс, ответов={frames} ##", code, retry);
    }
    eprintln!("## (3) виды кадров в принимающем состоянии: {accepted:?} ##");

    assert_eq!(rows[0].1, err_code::NOT_OWNER, "сертификат без состава не даёт права писать");
    assert_eq!(rows[1].1, err_code::NOT_OWNER, "реплика отказывает так же, как недержатель");
    assert_eq!(rows[2].1, err_code::EPOCH_STALE, "истёкший lease — другой отказ, и он именуется");
    assert_eq!(rows[3].1, "", "единственное принимающее состояние не отвечает отказом");
    assert!(rows[3].3 > 0, "отказ — это всегда один кадр; здесь ответов больше, и это опсы (§9.4)");
    assert!(!accepted.is_empty(), "primary с lease обязан хотя бы один кадр издать");
    for d in [d1, d2, d3, d4] {
        let _ = std::fs::remove_dir_all(&d);
    }
}

// --- (4)…(8) наблюдатель --------------------------------------------------------

#[derive(NetworkBehaviour)]
struct SnifferBehaviour {
    frames: request_response::Behaviour<FrameCodec>,
}

/// Index-node без шарда: проходит handshake по-настоящему, отвечает на `Find` нулевой эпохой и
/// пишет байты `Publish`. Так видно и эпоху, под которую майнили nonce, и число попыток.
struct Sniffer {
    swarm: Swarm<SnifferBehaviour>,
    id: Identity,
    greeting: Vec<u8>,
    /// Пойманные `Publish` — в порядке прихода.
    caught: Vec<Vec<u8>>,
    /// Код, которым сниффер отвечает на `Publish`.
    publish_code: String,
    /// Пауза, названная в отказе.
    retry_ms: u32,
    addrs: Vec<Multiaddr>,
}

impl Sniffer {
    fn new(seed: u8, publish_code: &str, retry_ms: u32) -> Self {
        let id = testing::identity(seed);
        let peer = keys::peer_id(&id);
        let cert =
            testing::node_cert(seed, peer.to_bytes(), vec![SHARD], Role::IndexNode, 0, u32::MAX);
        let greeting = Handshake {
            role: Role::IndexNode,
            preprocessing_version: testing::PREPROCESSING_VERSION,
            model_version: reference_manifest().model_version,
            genesis_hash: testing::genesis_hash(),
            cert: NodeCert::encode(&cert),
            tlv: Vec::new(),
        }
        .encode_unsigned();
        let mut swarm = SwarmBuilder::with_existing_identity(keys::keypair(&id))
            .with_tokio()
            .with_quic()
            .with_behaviour(|_key| {
                let protocols =
                    std::iter::once((StreamProtocol::new("/vecdht/v8/frame"), ProtocolSupport::Full));
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
        swarm.listen_on(quic_addr()).expect("сниффер слушает QUIC");
        Self {
            swarm,
            id,
            greeting,
            caught: Vec::new(),
            publish_code: publish_code.to_string(),
            retry_ms,
            addrs: Vec::new(),
        }
    }

    async fn step(&mut self) {
        tokio::select! {
            ev = self.swarm.select_next_some() => self.on_event(ev),
            _ = tokio::time::sleep(Duration::from_millis(2)) => {}
        }
    }

    fn on_event(&mut self, ev: SwarmEvent<SnifferBehaviourEvent>) {
        if let SwarmEvent::NewListenAddr { address, .. } = &ev {
            self.addrs.push(address.clone());
            return;
        }
        let SwarmEvent::Behaviour(SnifferBehaviourEvent::Frames(ev)) = ev else { return };
        let request_response::Event::Message { message, .. } = ev else { return };
        let request_response::Message::Request { request, channel, .. } = message else { return };
        let kind = decode_frame(&request).map(|f| f.header.kind).ok();
        let reply: Vec<Vec<u8>> = match kind {
            Some(Kind::Handshake) => vec![self.greeting.clone()],
            Some(Kind::Find) => vec![self.answer_epoch_zero(&request)],
            Some(Kind::Publish) => {
                self.caught.push(request.clone());
                let err = ProtocolError {
                    code: self.publish_code.clone(),
                    retry_after_ms: self.retry_ms,
                    shard: SHARD,
                };
                vec![err.encode_unsigned()]
            }
            _ => Vec::new(),
        };
        self.swarm.behaviour_mut().frames.send_response(channel, reply).ok();
    }

    /// Подписанный `MatchResult` с нулевой эпохой и пустым списком — ровно то, что отдаёт живой
    /// узел без эпизоды (проверено в (0)).
    fn answer_epoch_zero(&self, find_bytes: &[u8]) -> Vec<u8> {
        let q = Find::decode(find_bytes).expect("агент шлёт разбираемый Find");
        let cluster = *q.clusters.first().expect("Find без кластеров");
        let res = MatchResult {
            shard: shard_of(cluster),
            epoch: 0,
            query_id: q.query_id,
            responder_ed25519: self.id.pubkey(),
            matches: Vec::new(),
        };
        res.check_sort_contract().expect("контракт сортировки §8.4");
        let body = res.body_bytes();
        let sig = self.id.sign_body(domain::MATCH, Kind::MatchResult, &body);
        res.encode_signed(&sig)
    }

    fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    fn published(&self) -> Vec<Publish> {
        self.caught
            .iter()
            .map(|b| Publish::decode(b).expect("пойманный Publish разбирается"))
            .collect()
    }
}

async fn wait_sniffer(s: &mut Sniffer) -> Multiaddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(a) = s.addrs.first().cloned() {
            return a;
        }
        assert!(tokio::time::Instant::now() < deadline, "listener сниффера не поднялся за 10 с");
        s.step().await;
    }
}

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
            "handshake не сошёлся за 20 с; ошибки={:?}",
            agent.net_mut().take_errors()
        );
    }
}

async fn pump_publish_out(
    sniffers: &mut [Sniffer],
    rx: &mut oneshot::Receiver<Result<PublishReceipt, AgentError>>,
) -> Result<PublishReceipt, AgentError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(v) = rx.try_recv() {
            return v;
        }
        assert!(!rx.is_terminated(), "задача агента завершилась без результата");
        assert!(tokio::time::Instant::now() < deadline, "агент не закончил publish за 60 с");
        for s in sniffers.iter_mut() {
            s.step().await;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Дать снифферам долететь до последнего кадра после возврата агента.
async fn drain(sniffers: &mut [Sniffer], window: Duration) {
    let deadline = tokio::time::Instant::now() + window;
    while tokio::time::Instant::now() < deadline {
        for s in sniffers.iter_mut() {
            s.step().await;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Один цикл «агент пишет на шард, который объявляет эпоху 0». Возвращает пойманные `Publish`,
/// результат вызова и его wall-clock в миллисекундах.
///
/// Каждый элемент `codes` — отдельный кандидат: свой ключ, свой адрес, свой код отказа.
type PublishRun = (Vec<Publish>, Result<PublishReceipt, AgentError>, u64);

#[allow(clippy::type_complexity)]
async fn publish_once(codes: &[(&str, u32)], call_timeout: Duration) -> PublishRun {
    let local = LocalSet::new();
    local
        .run_until(async {
            let mut sniffers: Vec<Sniffer> = codes
                .iter()
                .enumerate()
                .map(|(i, (code, retry))| Sniffer::new(SNIFFER_SEED + i as u8, code, *retry))
                .collect();
            let mut addrs = Vec::new();
            for s in sniffers.iter_mut() {
                addrs.push(wait_sniffer(s).await);
            }
            let mut agent = Agent::new(
                testing::identity(AGENT_SEED),
                agent_network(),
                agent_cfg(addrs, call_timeout),
            )
            .expect("агент");
            for s in sniffers.iter_mut() {
                pump_handshake(&mut agent, s).await;
            }
            let net = agent_network();
            let req = PublishRequest::new(
                testing::vector(3),
                CLUSTER,
                net.ttl_default_buckets,
                net.preprocessing_version,
            );
            let (tx, mut rx) = oneshot::channel();
            local.spawn_local(async move {
                let r = agent.publish(&req).await;
                let _ = tx.send(r);
            });
            let started = Instant::now();
            let out = pump_publish_out(&mut sniffers, &mut rx).await;
            drain(&mut sniffers, Duration::from_millis(400)).await;
            let ms = started.elapsed().as_millis() as u64;
            let caught: Vec<Publish> = sniffers.iter().flat_map(|s| s.published()).collect();
            eprintln!(
                "## publish: исход={}, кадров {}, время {ms} мс ##",
                match &out {
                    Ok(_) => "принято".to_string(),
                    Err(e) => e.to_string(),
                },
                caught.len()
            );
            (caught, out, ms)
        })
        .await
}

/// `publish_once` поднимает `LocalSet`, которому нужен однопоточный рантайм.
fn run_in_runtime<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(f)
}

// --- (4) отказ, который видит агент --------------------------------------------

/// Обещание §16.3 начинается с «агент видит пустой DHT-ответ по ключу шарда». У агента есть и
/// второй источник кандидатов — аутентифицированные узлы с кредашиалом на шард. Проверка: чем
/// заканчивается `publish` на шард без эпизоды.
#[test]
fn publishing_to_an_epochless_shard_ends_in_not_owner_not_in_an_empty_answer() {
    let (caught, out, ms) =
        run_in_runtime(publish_once(&[(err_code::NOT_OWNER, NAMED_PAUSE_MS)], Duration::from_secs(30)));
    let err = match out {
        Ok(r) => panic!("на шарде без эпизоды публикации быть не может: {r:?}"),
        Err(e) => e,
    };
    eprintln!("## (4) чем закончился publish: {err} ##");

    match &err {
        AgentError::Refused { code, shard, retry_after_ms } => {
            eprintln!("## (4) Refused{{code={code}, shard={shard}, retry={retry_after_ms}}} ##");
            assert_eq!(code, err_code::NOT_OWNER, "ожидался NOT_OWNER, получен {code}");
            assert_eq!(*shard, SHARD);
            // Порог (4): пауза, названная узлом, не выдержана — «повтора с backoff» нет.
            assert!(
                ms < u64::from(NAMED_PAUSE_MS),
                "вызов длился {ms} мс при названной паузе {NAMED_PAUSE_MS} мс"
            );
        }
        other => panic!("предпосылка §16.3 наступила бы только при NoProviders: {other:?}"),
    }
    assert_eq!(caught.len(), 1, "агент сделал ровно одну попытку записи");
    assert!(
        !matches!(err, AgentError::NoProviders { .. }),
        "«пустой DHT-ответ» не наступил: узел с кредашиалом остался кандидатом"
    );
}

// --- (5) предпосылка «пустого DHT-ответа» --------------------------------------

/// Та же сеть, но кандидат — настоящий `ShardNode` без применённой эпизоды, и вопрос про
/// провайдинг: объявляет ли себя держателем шарда узел, который шард не обслуживает? Инструмент
/// идентичен тесту `an_agent_discovers_the_shard_provider_through_kademlia` из `transport.rs` и
/// отличается ровно одной переменной: genesis не применён.
#[test]
fn an_epochless_holder_still_answers_the_dht_as_a_provider_of_the_shard() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let local = LocalSet::new();
        local
            .run_until(async {
                let d = dir("s163-provider");
                let seed = primary_seed();
                let id = testing::identity(seed);
                let peer = keys::peer_id(&id);
                let node = testing::node(&d, SHARD, seed, testing::params(POW_NODE), &SEEDS);
                let cert = testing::node_cert(
                    seed,
                    peer.to_bytes(),
                    vec![SHARD],
                    Role::IndexNode,
                    0,
                    u32::MAX,
                );
                let mut holder = NetService::new(
                    id,
                    Role::IndexNode,
                    Some(cert),
                    vec![node],
                    testing::authority_set(),
                    cfg(quic_addr(), Vec::new()),
                )
                .expect("сервис холодного узла");
                let addr = wait_listen(&mut holder).await;
                let mut agent = agent_service(AGENT_SEED, quic_addr());
                agent.dial(addr).expect("dial холодного держателя");
                let (hp, ap) = (holder.peer_id(), agent.peer_id());

                let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
                while !(holder.is_authenticated(&ap) && agent.is_authenticated(&hp)) {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "handshake не сошёлся; ошибки {:?}",
                        holder.take_errors()
                    );
                    holder.step().await;
                    agent.step().await;
                }

                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                let mut found = Vec::new();
                let mut last_query = 0u64;
                while tokio::time::Instant::now() < deadline {
                    holder.step().await;
                    agent.step().await;
                    let now = now_sec();
                    if now != last_query {
                        last_query = now;
                        agent.find_providers(SHARD).expect("kad-запрос провайдеров");
                    }
                    found = agent.provider_peers(SHARD);
                    if found.contains(&hp) {
                        break;
                    }
                }
                let epoch = holder.node(SHARD).and_then(|n| n.epoch());
                eprintln!(
                    "## (5) холодный держатель: epoch={epoch:?}, объявлений={}, найден как провайдер={}, провайдеров={} ##",
                    holder.provider_announcements,
                    found.contains(&hp),
                    found.len()
                );

                assert_eq!(epoch, None, "узел по-прежнему без эпизоды — проверяем это состояние");
                assert!(
                    found.contains(&hp),
                    "холодный узел не объявил шард: провайдеров {}, kad-пиров={}, ошибки {:?}",
                    found.len(),
                    agent.kad_peer_count(),
                    agent.take_errors()
                );
                let _ = std::fs::remove_dir_all(&d);
            })
            .await;
    });
}

fn agent_service(seed: u8, listen: Multiaddr) -> NetService {
    NetService::new(
        testing::identity(seed),
        Role::Agent,
        None,
        Vec::new(),
        testing::authority_set(),
        cfg(listen, Vec::new()),
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

// --- (6) оплаченный PoW под нулевую эпоху --------------------------------------

/// Ядро находки: агент майнит nonce до отправки, а эпоху берёт из ответа узла. Если узел объявил
/// `epoch = 0`, работа оплачена под ноль — и узел её никогда не проверит, потому что отказывает
/// раньше. Проверка детерминированная: кадр пойман, `pow_ok` считается дважды — под нулевой и
/// под первой эпохой.
#[test]
fn the_agent_pays_pow_for_an_epoch_nobody_serves() {
    let (caught, out, _) =
        run_in_runtime(publish_once(&[(err_code::NOT_OWNER, NAMED_PAUSE_MS)], Duration::from_secs(30)));
    assert!(out.is_err(), "запись на шард без эпизоды не могла пройти");
    let msg = caught.first().expect("сниффер обязан был поймать Publish");

    let owner = testing::identity(AGENT_SEED).pubkey();
    let expires = msg.published_bucket.saturating_add(msg.ttl_buckets as u32);
    let bits = msg.pow_bits as u32;
    let paid_zero = pow_ok(&pow_input(&owner, SHARD, 0, &msg.intent_id, expires), msg.pow_nonce, bits);
    let paid_one = pow_ok(&pow_input(&owner, SHARD, 1, &msg.intent_id, expires), msg.pow_nonce, bits);

    eprintln!(
        "## (6) пойман Publish: pow_bits={}, nonce={}, бакет={}, TTL={}, intent_id под версию {}; pow_ok(эпоха 0)={paid_zero}, pow_ok(эпоха 1)={paid_one} ##",
        msg.pow_bits, msg.pow_nonce, msg.published_bucket, msg.ttl_buckets, msg.preprocessing_version
    );

    assert_eq!(msg.pow_bits, POW_ARTIFACT, "агент майнит под дефолт артефакта");
    assert_eq!(shard_of(msg.cluster_id), SHARD);
    assert_eq!(
        msg.intent_id,
        intent_id(&msg.vec_q, msg.preprocessing_version),
        "интент обязан считаться из того же вектора, что ушёл в сеть"
    );
    assert!(paid_zero, "nonce проходит под эпохой 0 — именно её агент и оплатил");
    assert!(!paid_one, "тот же nonce под эпохой 1 — уже другая работа");
}

// --- (7) NOT_OWNER не лечится повтором ------------------------------------------

/// Различие, из которого §16.3 выводит «повтор с backoff»: агент обязан отличать «этот узел не
/// пишет» от «пиши позже». Сравнение идёт по числу пойманных `Publish` при идентичном
/// инструменте и разных кодах отказа.
#[test]
fn not_owner_ends_the_attempt_while_a_temporary_code_repeats_it() {
    let (caught_refused, out_r, ms_refused) =
        run_in_runtime(publish_once(&[(err_code::NOT_OWNER, NAMED_PAUSE_MS)], Duration::from_secs(30)));
    let (caught_busy, out_b, _ms_busy) =
        run_in_runtime(publish_once(&[(err_code::BUSY, 50)], Duration::from_secs(30)));

    let err_r = match out_r {
        Ok(r) => panic!("NOT_OWNER не мог дать receipt: {r:?}"),
        Err(e) => e,
    };
    let err_b = match out_b {
        Ok(r) => panic!("BUSY не мог дать receipt: {r:?}"),
        Err(e) => e,
    };
    eprintln!(
        "## (7) NOT_OWNER: кадров {}, время {ms_refused} мс, отказ «{err_r}»; BUSY: кадров {}, отказ «{err_b}» ##",
        caught_refused.len(),
        caught_busy.len()
    );

    assert_eq!(caught_refused.len(), 1, "после NOT_OWNER повтором заниматься нельзя");
    // Замороженный порог (8) из `H-0080` ожидал при BUSY **3** кадра. В n=1 наблюдено 4 —
    // дважды в одном прогоне (оракул: 4 кадра за 3854 мс; КОНТРОЛЬ тем же бинарём: 4 за 3978 мс),
    // то есть не флуктуация. Причина — арифметика константы потока, а не поведение протокола:
    // `agent.rs:453…465` проверяет `attempts >= 4` **до** `attempts += 1` и отправки, значит
    // отправок ровно 4. Порог (8) остаётся НЕ ВЫПОЛНЕННЫМ в этой части (ДИАГНОЗ-1 и -2 в
    // `lab/logs/e0080-all.log`) и не переписан: ниже — зонд (8′), расширение инструмента,
    // которое гейтит фактический потолок и держит замороженное число отдельным проверочным
    // условием «расхождение сохраняется».
    const FROZEN_BUSY_FRAMES: usize = 3;
    assert_eq!(
        caught_busy.len(),
        4,
        "зонд (8′): временный код обязан повторяться до потолка `attempts >= 4` — ровно 4 отправки"
    );
    assert_ne!(
        caught_busy.len(),
        FROZEN_BUSY_FRAMES,
        "замороженное ожидание (8) = {FROZEN_BUSY_FRAMES} стало истинным: пересматривать надо не порог, а ДИАГНОЗ"
    );
    assert!(
        matches!(err_r, AgentError::Refused { ref code, .. } if code == err_code::NOT_OWNER),
        "NOT_OWNER обязан дойти до вызывающего: {err_r:?}"
    );
    assert!(
        matches!(err_b, AgentError::BadAnswer(ref m) if m.contains("исчерпаны повторы")),
        "исчерпанный бюджет повторов обязан быть виден: {err_b:?}"
    );
    assert!(
        ms_refused < u64::from(NAMED_PAUSE_MS),
        "пауза в {NAMED_PAUSE_MS} мс, названная узлом, не выдержана: вызов шёл {ms_refused} мс"
    );
}

// --- (8) второй кандидат: цена, не исход ----------------------------------------

/// «Пишет первому узлу, готовому взять эпизоду»: если кандидатов несколько и ни один не готов,
/// исход обязан быть тем же, а цена — выше. Это зеркало леммы `outcome_is_order_free` и
/// контрпримера `cost_is_order_sensitive` из `Shard.lean`.
#[test]
fn a_second_candidate_doubles_the_price_and_not_the_outcome() {
    let (one, out_one, _) =
        run_in_runtime(publish_once(&[(err_code::NOT_OWNER, 50)], Duration::from_secs(30)));
    let (two, out_two, _) = run_in_runtime(publish_once(
        &[(err_code::NOT_OWNER, 50), (err_code::NOT_OWNER, 50)],
        Duration::from_secs(30),
    ));

    let r1 = match out_one {
        Err(e) => e,
        Ok(r) => panic!("первый кандидат не мог принять запись: {r:?}"),
    };
    let r2 = match out_two {
        Err(e) => e,
        Ok(r) => panic!("второй кандидат не мог принять запись: {r:?}"),
    };
    let code = |e: &AgentError| match e {
        AgentError::Refused { code, .. } => code.clone(),
        other => other.to_string(),
    };
    eprintln!(
        "## (8) 1 кандидат: {r1} (кадров {}); 2 кандидата: {r2} (кадров {}) ##",
        one.len(),
        two.len()
    );

    assert_eq!(code(&r1), err_code::NOT_OWNER);
    assert_eq!(code(&r2), err_code::NOT_OWNER, "второй кандидат не меняет исход");
    assert_eq!(one.len(), 1, "одна попытка на одного кандидата");
    assert_eq!(two.len(), 2, "по попытке на каждого — это и есть цена перебора");
}
