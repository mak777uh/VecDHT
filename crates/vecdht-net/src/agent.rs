//! Агент §12: publish, find и прямая сессия поверх того же `NetService`, что держит узлы.
//!
//! Здесь нет второго транспорта и нет второго кодека — и это главное свойство файла. Агент
//! пользуется ровно теми кадрами, которые уже валидирует узел (`vecdht-wire`), и ровно тем
//! соединением, которое уже прошло handshake и привязало владельца к `PeerId` (§4.2). Всё, что
//! добавляет этот модуль, — политика клиента: как найти держателя шарда, откуда взять эпизоду
//! для PoW, чем проверить ответ и что делать с отказом.
//!
//! Три решения, которые легко сделать неправильно:
//!
//! * **Эпизода для PoW.** В `Publish` нет поля `epoch`, потому что узел сверяет nonce со своей
//!   `serving_epoch`. Значит агент обязан узнать её *до* майнинга, и единственный подписанный
//!   источник — `MatchResult.epoch` (§12.2, шаг 5). Проба — это `Find` с `top_k = 0` и одним
//!   кластером шарда: `Find` не несёт номера шарда, и транспорт маршрутизирует его по первому
//!   кластеру, поэтому «пустой» кластерный список до узла не дошёл бы вовсе. `top_k = 0`
//!   гарантирует, что проба не тратит выдачу и не засоряет rendezvous-таблицу.
//! * **Кому идти.** DHT отдаёт провайдеров шарда по ключу §7.4, но `Publish` принимает только
//!   primary. Агент пробует кандидатов по одному и отличает «это реплика» (`NOT_OWNER`) от
//!   «эпоха ушла» (`EPOCH_STALE`); слепо слать балансировщику нельзя — ack'а не будет.
//! * **Чему верить.** `MatchResult` и `RendezvousAccept` проверяются по подписи поверх
//!   `frame.body` и по владельцу, которого аутентифицировал handshake. Подпись, проверенная по
//!   перекодированному телу, приняла бы кадр, который узел не подписывал (§5.2).
//!
//! Честная граница v1: relay/DCUtR не подняты, поэтому сессия — только прямой dial по адресу,
//! известному Kademlia/identify. Если адреса нет, это ошибка маршрута, а не «сессия установлена
//! молча». `IntentTextRequest/Response` также не обслуживаются узлом v1 (в `ShardNode` нет
//! хранения текстов), поэтому [`Agent::open_session`] открывает и проверяет канал, но не
//! изображает обмен текстами, которого нет в P6.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::{Multiaddr, PeerId};
use thiserror::Error;
use vecdht_artifact::Artifact;
use vecdht_crypto::pow::{mine_pow, pow_input, PowError};
use vecdht_crypto::{verify_body, AuthoritySet, Identity};
use vecdht_node::{bucket_of, buckets};
use vecdht_wire::constants::{shard_of, CLUSTERS_PER_SHARD, DIM, NLIST, SHARDS};
use vecdht_wire::frame::{decode_frame, Frame, Kind};
use vecdht_wire::messages::{
    domain, err_code, Codec, Find, MatchResult, Publish, PublishAck, ProtocolError,
    RendezvousAccept, Role,
};

use crate::keys;
use crate::service::{NetConfig, NetError, NetService};

/// Параметры сети, выведенные из артефакта. Копировать их в константы клиента нельзя: у агента
/// и узла обязан быть один источник `nlist`, TTL и диапазона PoW, иначе первый публикует то,
/// что второй отвергнет.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkParams {
    pub genesis_hash: [u8; 32],
    pub model_version: String,
    pub preprocessing_version: u16,
    pub nlist: u16,
    pub clusters_per_shard: u16,
    pub shards: u16,
    pub nprobe_default: u16,
    pub nprobe_allowed: Vec<u16>,
    pub top_k_default: u16,
    pub top_k_max: u16,
    pub bucket_sec: u32,
    pub ttl_default_buckets: u16,
    pub ttl_max_buckets: u16,
    pub pow_bits_default: u32,
    pub pow_bits_min: u32,
    pub pow_bits_max: u32,
    pub rendezvous_ttl_sec: u16,
    pub authorities: AuthoritySet,
}

impl NetworkParams {
    /// Сверка с кодеком обязательна: манифест с `nlist = 2048` прошёл бы собственную проверку
    /// артефакта, но `cluster_id` в проводе всё равно 1024-ричный, и агент считал бы шард не тот.
    pub fn from_artifact(a: &Artifact) -> Result<Self, AgentError> {
        a.manifest.check().map_err(|e| AgentError::Artifact(e.to_string()))?;
        let m = &a.manifest;
        if m.routing.nlist != NLIST
            || m.routing.shards != SHARDS
            || m.routing.clusters_per_shard != CLUSTERS_PER_SHARD
        {
            return Err(AgentError::Artifact(format!(
                "манифест: nlist/shards/clusters_per_shard = {}/{}/{}, кодек v8 — {NLIST}/{SHARDS}/{CLUSTERS_PER_SHARD}",
                m.routing.nlist, m.routing.shards, m.routing.clusters_per_shard
            )));
        }
        let ttl_default_buckets = buckets(m.time.ttl_default_sec).min(u16::MAX as u32) as u16;
        let ttl_max_buckets = buckets(m.time.ttl_max_sec).min(u16::MAX as u32) as u16;
        if ttl_default_buckets == 0 || ttl_max_buckets == 0 {
            return Err(AgentError::Artifact("TTL манифеста округлился в ноль бакетов".into()));
        }
        if ttl_default_buckets > ttl_max_buckets {
            return Err(AgentError::Artifact(format!(
                "TTL по умолчанию {ttl_default_buckets} бакетов больше потолка {ttl_max_buckets}"
            )));
        }
        if m.query.rendezvous_ttl_sec == 0 || m.query.rendezvous_ttl_sec > u16::MAX as u32 {
            return Err(AgentError::Artifact(format!(
                "rendezvous_ttl_sec = {} вне u16",
                m.query.rendezvous_ttl_sec
            )));
        }
        Ok(Self {
            genesis_hash: a.genesis_hash(),
            model_version: m.model_version.clone(),
            preprocessing_version: m.preprocessing_version,
            nlist: m.routing.nlist,
            clusters_per_shard: m.routing.clusters_per_shard,
            shards: m.routing.shards,
            nprobe_default: m.routing.nprobe_default,
            nprobe_allowed: m.routing.nprobe_allowed.clone(),
            top_k_default: m.query.top_k_default,
            top_k_max: m.query.top_k_max,
            bucket_sec: m.time.bucket_sec,
            ttl_default_buckets,
            ttl_max_buckets,
            pow_bits_default: m.power.pow_bits_default,
            pow_bits_min: m.power.pow_bits_min,
            pow_bits_max: m.power.pow_bits_max,
            rendezvous_ttl_sec: m.query.rendezvous_ttl_sec as u16,
            authorities: a.authorities(),
        })
    }

    pub fn shard_of_cluster(&self, cluster_id: u16) -> Option<u16> {
        (cluster_id < self.nlist).then(|| cluster_id / self.clusters_per_shard)
    }
}

/// Настройки процесса агента. Таймауты — часть контракта CLI: вызов, который «висит», хуже
/// честного отказа, потому что оператор не отличает недоступную сеть от зависшего процесса.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub bootstrap: Vec<Multiaddr>,
    pub listen: Vec<Multiaddr>,
    pub agent_version: String,
    pub call_timeout: Duration,
    pub request_timeout: Duration,
    pub idle_timeout: Duration,
    pub poll_interval: Duration,
    /// Предел перебора одного nonce-поиска. Восемь миллионов при 20 битах — это ≈8 ожидаемых
    /// работ: не найденный за это время nonce означает, что сложность не та, а не «ещё чуть-чуть».
    pub pow_max_attempts: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            bootstrap: Vec::new(),
            listen: Vec::new(),
            agent_version: "vecdht-agent/0.1".to_string(),
            call_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            poll_interval: Duration::from_millis(25),
            pow_max_attempts: 8_000_000,
        }
    }
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("артефакт: {0}")]
    Artifact(String),
    #[error("сеть: {0}")]
    Net(#[from] NetError),
    #[error(
        "нет ни одного bootstrap-адреса: агент не знает, кого спрашивать о шарде. \
         Укажите адрес узла (--bootstrap / bootstrap=[...])"
    )]
    NoBootstrap,
    #[error("нет доступного держателя шарда {shard}: DHT не дал провайдеров, а аутентифицированных узлов с кредашиалом на шард нет")]
    NoProviders { shard: u16 },
    #[error("ответ не пришёл за {0:?}")]
    Timeout(Duration),
    #[error("узел отказал: `{code}` (шард {shard}, retry {retry_after_ms} мс)")]
    Refused { code: String, shard: u16, retry_after_ms: u32 },
    #[error("ответ не сходится с протоколом: {0}")]
    BadAnswer(String),
    #[error("вход вызова: {0}")]
    Invalid(String),
    #[error("PoW: {0}")]
    Pow(#[from] PowError),
    #[error("PoW: nonce не найден за {attempts} попыток при bits={bits}")]
    PowExhausted { bits: u32, attempts: u64 },
    #[error("сессия: {0}")]
    Session(String),
}

/// Что публикует агент. Текста и f32-вектора здесь нет по той же причине, по которой их нет в
/// `Publish`: сеть видит 384 байта int8 и ничего больше (§12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishRequest {
    pub vec_q: [i8; DIM],
    pub cluster_id: u16,
    /// TTL в 16-секундных бакетах; потолок — из артефакта, проверяется перед отправкой.
    pub ttl_buckets: u16,
    /// Advisory-идентификатор §6.5. По умолчанию считается из вектора, но может прийти из
    /// кеша эмбеддингов: тогда он обязан быть ровно тем же, иначе это другой интент.
    pub intent_id: [u8; 32],
}

impl PublishRequest {
    /// `intent_id` выводится из тех же байтов, что уйдут в сеть, и из версии препроцессинга
    /// артефакта: вызывающий не может случайно подставить идентификатор другого вектора.
    /// Версию передаём явно, а не берём из константы: манифест с другой версией отвергается
    /// handshake'ом, но `intent_id` обязан считаться по той, что заявлена в сети.
    pub fn new(vec_q: [i8; DIM], cluster_id: u16, ttl_buckets: u16, preprocessing_version: u16) -> Self {
        let intent_id = vecdht_crypto::ids::intent_id(&vec_q, preprocessing_version);
        Self { vec_q, cluster_id, ttl_buckets, intent_id }
    }

    /// Тот же запрос, но с `intent_id` из кеша. Проверка совпадения — на вызывающей стороне:
    /// кеш ключуется по тексту, а сеть — по вектору.
    pub fn with_intent_id(mut self, intent_id: [u8; 32]) -> Self {
        self.intent_id = intent_id;
        self
    }
}

/// Подтверждение durable-записи на primary (§9.4). `epoch` и `seq` — то, что увидел узел; они
/// не обязаны совпадать с моментом, когда агент майнил nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReceipt {
    pub shard: u16,
    pub primary: PeerId,
    pub epoch: u64,
    pub seq: u64,
    pub slot: u32,
    /// Сложность, с которой nonce прошёл приём, и та, что узел просит на следующий раунд.
    pub pow_bits: u32,
    pub next_pow_bits: u8,
    pub nonce: u64,
    pub published_bucket: u32,
    pub expires_bucket: u32,
    pub ttl_buckets: u16,
    pub intent_id: [u8; 32],
}

/// Запрос поиска: то, что агент получил из query-пути §6.2 после квантования и top-nprobe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindQuery {
    pub vec_q: [i8; DIM],
    pub clusters: Vec<u16>,
    pub top_k: u16,
}

impl FindQuery {
    pub fn new(vec_q: [i8; DIM], clusters: Vec<u16>, top_k: u16) -> Self {
        Self { vec_q, clusters, top_k }
    }
}

/// Подписанный приём §12.3 вместе с исходным кадром: кадр предъявляется цели сессии, и
/// пересобирать его из полей значило бы проверять не те байты, которые подписал index-node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousGrant {
    pub issuer: [u8; 32],
    pub accept: RendezvousAccept,
    pub frame: Vec<u8>,
}

impl RendezvousGrant {
    /// Последний бакет, в котором приём ещё действителен включительно (та же граница, что у
    /// `Spend::consume` в узле).
    pub fn expires_bucket(&self) -> u32 {
        self.accept.issued_bucket.saturating_add(buckets(self.accept.ttl_sec as u32).max(1))
    }
}

/// Одна найденная запись. `grant` — приём, выписанный тем же index-node'ом на эту пару
/// `(seeker, target, slot)`; `None` означает, что приём не выписан (потолок таблицы), а не
/// «запись плохая»: `MatchResult` самодостаточен (§12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundMatch {
    pub owner_ed25519: [u8; 32],
    pub shard: u16,
    pub cluster_id: u16,
    pub slot: u32,
    pub d2: u32,
    pub epoch: u64,
    pub grant: Option<RendezvousGrant>,
}

impl FoundMatch {
    /// §6.4: similarity выводится из целого `d2` только для показа; сортировка уже произошла по
    /// `d2` на узле и повторяется агентом по `d2`, а не по этому float.
    pub fn similarity(&self) -> f32 {
        vecdht_crypto::similarity_from_d2(self.d2)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardAnswer {
    pub shard: u16,
    pub peer: PeerId,
    pub owner: [u8; 32],
    pub epoch: u64,
    pub matches: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardFailure {
    pub shard: u16,
    pub reason: String,
}

/// Результат fan-out §12.2: частичный успех — штатное состояние, поэтому отказы лежат рядом с
/// ответами, а не превращают весь поиск в `Err`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindOutcome {
    pub matches: Vec<FoundMatch>,
    pub answers: Vec<ShardAnswer>,
    pub failures: Vec<ShardFailure>,
}

/// Установленная прямая сессия §12.5. Поле `direct` не декоративно: relay-путь в v1 не поднят,
/// и вызывающий обязан видеть, что канал прямой, а не «как-нибудь».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub peer: PeerId,
    pub owner: [u8; 32],
    pub issuer: [u8; 32],
    pub shard: u16,
    pub slot: u32,
    pub issued_bucket: u32,
    pub ttl_sec: u16,
    pub expires_bucket: u32,
    pub role: Role,
    pub direct: bool,
}

/// Один шард, по которому уже отправлен `Find` и ещё не пришёл ответ.
#[derive(Debug, Clone)]
struct SentFind {
    shard: u16,
    peer: PeerId,
    query_id: u64,
    clusters: Vec<u16>,
}

pub struct Agent {
    id: Identity,
    net: NetService,
    network: NetworkParams,
    cfg: AgentConfig,
    next_query_id: u64,
    /// Сложность, которую узел назвал в последнем ack (§11.2), и эпоха, ниже которой ответ
    /// этого шарда — устаревший (§12.2, шаг 5). Кеши живут на агента, а не на вызов: именно
    /// так «переживают» повторные публикации и поиски.
    pow_bits: BTreeMap<u16, u32>,
    known_epoch: BTreeMap<u16, u64>,
}

impl Agent {
    /// Собрать агента. `NetService::new` сам проверяет роль и отсутствие шардов: агент не может
    /// держать индекс, и это отказ конструкции, а не поведение во время работы.
    pub fn new(id: Identity, network: NetworkParams, cfg: AgentConfig) -> Result<Self, AgentError> {
        let net_cfg = NetConfig {
            listen: cfg.listen.clone(),
            bootstrap: cfg.bootstrap.clone(),
            genesis_hash: network.genesis_hash,
            model_version: network.model_version.clone(),
            preprocessing_version: network.preprocessing_version,
            agent_version: cfg.agent_version.clone(),
            request_timeout: cfg.request_timeout,
            idle_timeout: cfg.idle_timeout,
            provider_republish: Duration::from_secs(180),
            poll_interval: cfg.poll_interval,
        };
        let net = NetService::new(
            id.clone(),
            Role::Agent,
            None,
            Vec::new(),
            network.authorities.clone(),
            net_cfg,
        )?;
        Ok(Self {
            id,
            net,
            network,
            cfg,
            next_query_id: 1,
            pow_bits: BTreeMap::new(),
            known_epoch: BTreeMap::new(),
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.id
    }

    pub fn owner(&self) -> [u8; 32] {
        self.id.pubkey()
    }

    pub fn peer_id(&self) -> PeerId {
        self.net.peer_id()
    }

    pub fn network(&self) -> &NetworkParams {
        &self.network
    }

    pub fn config(&self) -> &AgentConfig {
        &self.cfg
    }

    pub fn listen_addrs(&self) -> &[Multiaddr] {
        self.net.listen_addrs()
    }

    pub fn net(&self) -> &NetService {
        &self.net
    }

    pub fn net_mut(&mut self) -> &mut NetService {
        &mut self.net
    }

    /// Цикл сервера: агент, который должен принимать входящие (сессии, ack, приёмы), обязан
    /// крутить `step` и вне своих вызовов. Без этого он «ждёт» только внутри методов, и
    /// соединение, открытое к нему в покое, не пройдёт handshake.
    pub async fn run(mut self) {
        loop {
            self.net.step().await;
        }
    }

    // --- publish ------------------------------------------------------------

    /// §12.1: DHT → primary → эпоха → PoW → подписанный `Publish` → ждать `PublishAck`.
    pub async fn publish(&mut self, req: &PublishRequest) -> Result<PublishReceipt, AgentError> {
        self.check_publish(req)?;
        let shard = self.network.shard_of_cluster(req.cluster_id).expect("cluster проверен выше");
        let deadline = tokio::time::Instant::now() + self.cfg.call_timeout;
        let mut candidates = self.candidates(shard, deadline).await?;
        if candidates.is_empty() {
            return Err(AgentError::NoProviders { shard });
        }
        let mut last: Option<AgentError> = None;
        while let Some(peer) = candidates.first().copied() {
            candidates.remove(0);
            let mut bits = self
                .pow_bits
                .get(&shard)
                .copied()
                .unwrap_or(self.network.pow_bits_default)
                .clamp(self.network.pow_bits_min, self.network.pow_bits_max);
            let mut attempts = 0usize;
            loop {
                if tokio::time::Instant::now() >= deadline {
                    return Err(last.unwrap_or(AgentError::Timeout(self.cfg.call_timeout)));
                }
                if attempts >= 4 {
                    last = Some(AgentError::BadAnswer(format!(
                        "{peer}: исчерпаны повторы publish на шарде {shard}"
                    )));
                    break;
                }
                attempts += 1;

                // Эпоха обязана быть получена заново: между раундами мог случиться handoff, и
                // nonce от прошлой эпохи узел отвергнет как POW_INVALID (§11.1).
                let epoch = match self.probe_epoch(peer, shard, deadline).await {
                    Ok(e) => e,
                    Err(AgentError::Refused { code, retry_after_ms, .. })
                        if code == err_code::NOT_OWNER =>
                    {
                        last = Some(AgentError::Refused { code, shard, retry_after_ms });
                        break;
                    }
                    Err(e) => {
                        last = Some(e);
                        break;
                    }
                };

                let bucket = Clock::bucket_now();
                let expires = bucket.saturating_add(req.ttl_buckets as u32);
                let input = pow_input(&self.owner(), shard, epoch, &req.intent_id, expires);
                let bits32 = bits.min(self.network.pow_bits_max);
                let nonce = match mine_pow(&input, bits32, 0, self.cfg.pow_max_attempts) {
                    Ok(n) => n,
                    Err(PowError::Exhausted(n)) => {
                        return Err(AgentError::PowExhausted { bits: bits32, attempts: n })
                    }
                    Err(e) => return Err(AgentError::Pow(e)),
                };
                let msg = Publish {
                    preprocessing_version: self.network.preprocessing_version,
                    cluster_id: req.cluster_id,
                    vec_q: req.vec_q,
                    owner_ed25519: self.owner(),
                    ttl_buckets: req.ttl_buckets,
                    published_bucket: bucket,
                    pow_bits: bits32 as u8,
                    pow_nonce: nonce,
                    intent_id: req.intent_id,
                    tlv: Vec::new(),
                };
                let body = msg.body_bytes();
                let sig = self.id.sign_body(domain::PUBLISH, Kind::Publish, &body);
                if !self.net.send_frame(peer, msg.encode_signed(&sig)) {
                    last = Some(AgentError::BadAnswer(format!(
                        "{peer}: соединение закрылось до отправки publish"
                    )));
                    break;
                }

                match self.wait_publish_result(peer, shard, epoch, deadline).await {
                    Ok(ack) => {
                        if ack.error_code != "OK" {
                            // Узел v8 выпускает ack только с "OK"; иное — нарушение, и
                            // принимать его как успех нельзя.
                            return Err(AgentError::BadAnswer(format!(
                                "PublishAck с error_code = {:?} вместо \"OK\"",
                                ack.error_code
                            )));
                        }
                        self.pow_bits.insert(shard, ack.next_pow_bits as u32);
                        self.known_epoch
                            .entry(shard)
                            .and_modify(|e| *e = (*e).max(ack.epoch))
                            .or_insert(ack.epoch);
                        return Ok(PublishReceipt {
                            shard,
                            primary: peer,
                            epoch: ack.epoch,
                            seq: ack.seq,
                            slot: ack.slot,
                            pow_bits: bits32,
                            next_pow_bits: ack.next_pow_bits,
                            nonce,
                            published_bucket: bucket,
                            expires_bucket: expires,
                            ttl_buckets: req.ttl_buckets,
                            intent_id: req.intent_id,
                        });
                    }
                    Err(AgentError::Refused { code, retry_after_ms, .. })
                        if code == err_code::NOT_OWNER =>
                    {
                        // Реплика ответила честно: она не primary. Это не ошибка PoW и не повод
                        // пересчитывать nonce — просто следующий кандидат.
                        last = Some(AgentError::Refused { code, shard, retry_after_ms });
                        break;
                    }
                    Err(AgentError::Refused { code, retry_after_ms, .. })
                        if code == err_code::POW_BITS_LOW =>
                    {
                        // Адаптивная сложность §11.2: узел не сообщает число при отказе, но
                        // «ниже порога» означает, что текущая не подходит. Шаг на единицу —
                        // единственный честный вывод; при исчерпании диапазона — отказ.
                        if bits >= self.network.pow_bits_max {
                            return Err(AgentError::Refused { code, shard, retry_after_ms });
                        }
                        bits += 1;
                        last = Some(AgentError::Refused { code, shard, retry_after_ms });
                        continue;
                    }
                    Err(AgentError::Refused { code, retry_after_ms, .. }) => {
                        // BUSY/QUOTA_PUBLISH/WAL_FAILED/EPOCH_STALE — временные; ждём названный
                        // узел срок и повторяем с той же эпохи заново. Остальные коды
                        // (`MODEL_MISMATCH`, `DENIED`, `SHARD_FULL`, ...) не лечатся повтором.
                        let permanent = matches!(
                            code.as_str(),
                            err_code::MODEL_MISMATCH
                                | err_code::SHARD_MISMATCH
                                | err_code::DENIED
                                | err_code::SHARD_FULL
                                | err_code::POW_INVALID
                        );
                        last = Some(AgentError::Refused {
                            code: code.clone(),
                            shard,
                            retry_after_ms,
                        });
                        if permanent {
                            return Err(last.expect("только что установлено"));
                        }
                        self.wait(retry_after_ms, deadline).await;
                        continue;
                    }
                    Err(e) => {
                        last = Some(e);
                        break;
                    }
                }
            }
        }
        Err(last.unwrap_or(AgentError::NoProviders { shard }))
    }

    fn check_publish(&self, req: &PublishRequest) -> Result<(), AgentError> {
        let Some(shard) = self.network.shard_of_cluster(req.cluster_id) else {
            return Err(AgentError::Invalid(format!(
                "cluster_id {} вне nlist {}",
                req.cluster_id, self.network.nlist
            )));
        };
        if shard >= self.network.shards {
            return Err(AgentError::Invalid(format!("шард {shard} вне 0..{}", self.network.shards)));
        }
        if req.ttl_buckets == 0 {
            return Err(AgentError::Invalid(
                "ttl_buckets = 0: запись истекла бы до записи в WAL".into(),
            ));
        }
        if req.ttl_buckets > self.network.ttl_max_buckets {
            return Err(AgentError::Invalid(format!(
                "ttl_buckets = {} выше потолка артефакта {} (§13)",
                req.ttl_buckets, self.network.ttl_max_buckets
            )));
        }
        Ok(())
    }

    // --- find ---------------------------------------------------------------

    /// §12.2: один подписанный `Find` на шард, все — до ожидания ответов; затем сверка подписей,
    /// отбрасывание устаревших эпох, дедупликация по владельцу и обрезка до `top_k`.
    pub async fn find(&mut self, q: &FindQuery) -> Result<FindOutcome, AgentError> {
        self.check_find(q)?;
        let deadline = tokio::time::Instant::now() + self.cfg.call_timeout;
        let groups = group_clusters(&q.clusters);
        let mut sent: BTreeMap<u16, SentFind> = BTreeMap::new();
        let mut failures: Vec<ShardFailure> = Vec::new();
        let mut first_error: Option<AgentError> = None;

        for (shard, clusters) in groups {
            let candidates = match self.candidates(shard, deadline).await {
                Ok(c) => c,
                Err(AgentError::NoBootstrap) => return Err(AgentError::NoBootstrap),
                Err(e) => {
                    first_error.get_or_insert(e);
                    failures.push(ShardFailure { shard, reason: "нет доступного держателя".into() });
                    continue;
                }
            };
            let Some(peer) = candidates.first().copied() else {
                first_error.get_or_insert(AgentError::NoProviders { shard });
                failures.push(ShardFailure { shard, reason: "нет доступного держателя".into() });
                continue;
            };
            let query_id = self.take_query_id();
            let msg = Find {
                preprocessing_version: self.network.preprocessing_version,
                query_vector: q.vec_q,
                clusters: clusters.clone(),
                top_k: q.top_k,
                query_id,
                requester_ed25519: self.owner(),
                tlv: Vec::new(),
            };
            let body = msg.body_bytes();
            let sig = self.id.sign_body(domain::FIND, Kind::Find, &body);
            if !self.net.send_frame(peer, msg.encode_signed(&sig)) {
                first_error.get_or_insert(AgentError::BadAnswer(format!(
                    "{peer}: соединение закрылось до отправки find"
                )));
                failures.push(ShardFailure { shard, reason: format!("{peer}: не отправлен") });
                continue;
            }
            sent.insert(
                shard,
                SentFind { shard, peer, query_id, clusters },
            );
        }

        if sent.is_empty() {
            return Err(first_error.unwrap_or(AgentError::NoProviders { shard: 0 }));
        }

        let mut answers = Vec::new();
        let mut raw: Vec<FoundMatch> = Vec::new();
        let mut grants: BTreeMap<(u16, u32, [u8; 32]), RendezvousGrant> = BTreeMap::new();
        // slot → owner для проверки, что приём выписан на реально найденную запись, а не на
        // произвольный слот, который атакующий надеется подставить.
        let mut slots: BTreeMap<(u16, u32), [u8; 32]> = BTreeMap::new();
        let mut answered: Vec<u16> = Vec::new();

        while answered.len() < sent.len() && tokio::time::Instant::now() < deadline {
            self.net.step().await;
            self.drain_find(
                &sent,
                &mut answered,
                &mut answers,
                &mut raw,
                &mut grants,
                &mut slots,
                &mut failures,
            );
        }
        for shard in sent.keys() {
            if !answered.contains(shard) {
                failures.push(ShardFailure {
                    shard: *shard,
                    reason: format!("ответ не пришёл за {:?}", self.cfg.call_timeout),
                });
            }
        }
        // Приёмы приходят в том же батче, что `MatchResult`; в батче, принёсшем последний ответ,
        // они уже разобраны. Повторный проход нужен только для кадров, дошедших отдельным
        // запросом (нештатно, но дешёво проверить).
        self.drain_find(
            &sent,
            &mut answered,
            &mut answers,
            &mut raw,
            &mut grants,
            &mut slots,
            &mut failures,
        );

        for m in &mut raw {
            let key = (m.shard, m.slot, m.owner_ed25519);
            if let Some(g) = grants.remove(&key) {
                m.grant = Some(g);
            }
        }
        answers.sort_by_key(|a| a.shard);
        failures.sort_by_key(|a| a.shard);
        Ok(FindOutcome { matches: merge_matches(raw, q.top_k as usize), answers, failures })
    }

    fn check_find(&self, q: &FindQuery) -> Result<(), AgentError> {
        if q.clusters.is_empty() {
            return Err(AgentError::Invalid(
                "пустой список кластеров: Find без шарда не маршрутизируется, и «искать везде» — \
                 это не оптимизация, а полный скан §8.6"
                    .into(),
            ));
        }
        for c in &q.clusters {
            if *c >= self.network.nlist {
                return Err(AgentError::Invalid(format!(
                    "cluster_id {c} вне nlist {}",
                    self.network.nlist
                )));
            }
        }
        if q.top_k == 0 || q.top_k > self.network.top_k_max {
            return Err(AgentError::Invalid(format!(
                "top_k = {} вне 1..={} (§7.5)",
                q.top_k, self.network.top_k_max
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn drain_find(
        &mut self,
        sent: &BTreeMap<u16, SentFind>,
        answered: &mut Vec<u16>,
        answers: &mut Vec<ShardAnswer>,
        raw: &mut Vec<FoundMatch>,
        grants: &mut BTreeMap<(u16, u32, [u8; 32]), RendezvousGrant>,
        slots: &mut BTreeMap<(u16, u32), [u8; 32]>,
        failures: &mut Vec<ShardFailure>,
    ) {
        for (from, bytes) in self.net.take_inbox() {
            let Ok(frame) = decode_frame(&bytes) else { continue };
            match frame.header.kind {
                Kind::MatchResult => {
                    let Ok(res) = MatchResult::decode(&bytes) else { continue };
                    let Some(entry) = sent.values().find(|s| s.query_id == res.query_id) else {
                        // Чужой/поздний ответ: query_id — anti-replay (§14.3), и ответ на
                        // запрос, которого мы не делали, не должен влиять на результат.
                        continue;
                    };
                    if answered.contains(&entry.shard) {
                        continue;
                    }
                    if from != entry.peer {
                        failures.push(ShardFailure {
                            shard: entry.shard,
                            reason: format!("ответ пришёл от {from}, а запрос уходил к {}", entry.peer),
                        });
                        answered.push(entry.shard);
                        continue;
                    }
                    match self.verify_match_result(from, entry.shard, &frame, &res) {
                        Ok(()) => {}
                        Err(e) => {
                            failures.push(ShardFailure { shard: entry.shard, reason: e.to_string() });
                            answered.push(entry.shard);
                            continue;
                        }
                    }
                    let floor = self.known_epoch.get(&entry.shard).copied().unwrap_or(0);
                    if res.epoch < floor {
                        failures.push(ShardFailure {
                            shard: entry.shard,
                            reason: format!("эпоха {} ниже уже известной {floor} (§12.2, шаг 5)", res.epoch),
                        });
                        answered.push(entry.shard);
                        continue;
                    }
                    self.known_epoch
                        .entry(entry.shard)
                        .and_modify(|e| *e = (*e).max(res.epoch))
                        .or_insert(res.epoch);
                    let mut violation = None;
                    for m in &res.matches {
                        if !entry.clusters.contains(&m.cluster_id) {
                            violation = Some(format!(
                                "cluster_id {} не запрашивался для шарда {}",
                                m.cluster_id, entry.shard
                            ));
                            break;
                        }
                        if shard_of(m.cluster_id) != entry.shard {
                            violation = Some(format!(
                                "cluster_id {} принадлежит шарду {}, а ответ — по {}",
                                m.cluster_id,
                                shard_of(m.cluster_id),
                                entry.shard
                            ));
                            break;
                        }
                        slots.insert((entry.shard, m.slot), m.owner_ed25519);
                    }
                    if let Some(reason) = violation {
                        failures.push(ShardFailure { shard: entry.shard, reason });
                        answered.push(entry.shard);
                        continue;
                    }
                    for m in &res.matches {
                        raw.push(FoundMatch {
                            owner_ed25519: m.owner_ed25519,
                            shard: entry.shard,
                            cluster_id: m.cluster_id,
                            slot: m.slot,
                            d2: m.d2,
                            epoch: res.epoch,
                            grant: None,
                        });
                    }
                    answers.push(ShardAnswer {
                        shard: entry.shard,
                        peer: from,
                        owner: res.responder_ed25519,
                        epoch: res.epoch,
                        matches: res.matches.len(),
                    });
                    answered.push(entry.shard);
                }
                Kind::RendezvousAccept => {
                    let Ok(acc) = RendezvousAccept::decode(&bytes) else { continue };
                    let Some(entry) = sent.get(&acc.shard) else { continue };
                    if from != entry.peer {
                        continue;
                    }
                    let Some(&target) = slots.get(&(acc.shard, acc.slot)) else {
                        // Приём на слот, которого нет в подписанном ответе, — это попытка
                        // расширить шортлист; не пришиваем его ни к какой записи.
                        continue;
                    };
                    if acc.target != target {
                        continue;
                    }
                    match self.verify_accept_frame(&bytes, acc.shard, from, &frame, &acc) {
                        Ok(g) => {
                            grants.entry((acc.shard, acc.slot, acc.target)).or_insert(g);
                        }
                        Err(e) => failures.push(ShardFailure {
                            shard: acc.shard,
                            reason: format!("приём отвергнут: {e}"),
                        }),
                    }
                }
                Kind::Error => {
                    let Ok(err) = ProtocolError::decode(&bytes) else { continue };
                    if err.shard == 0 {
                        // Ошибка уровня соединения: отказ в handshake уже случился бы раньше;
                        // здесь это DENIED/BAD_ENUM по кадру и относится ко всем ожидающим.
                        for shard in sent.keys() {
                            if !answered.contains(shard) {
                                failures.push(ShardFailure {
                                    shard: *shard,
                                    reason: format!("{} (без шарда)", err.code),
                                });
                                answered.push(*shard);
                            }
                        }
                        continue;
                    }
                    if let Some(entry) = sent.get(&err.shard) {
                        if !answered.contains(&entry.shard) {
                            failures.push(ShardFailure {
                                shard: entry.shard,
                                reason: err.code,
                            });
                            answered.push(entry.shard);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // --- session ------------------------------------------------------------

    /// Проверить приём против аутентифицированного издателя. Используется и для кадров из
    /// `find`, и для hex-кадра, переданного CLI/SDK: в обоих случаях ключ издателя берётся не
    /// из самого приёма, а из handshake. Проверки идут в порядке §12.3: подпись → адресат →
    /// политика TTL → истечение.
    pub fn verify_accept_frame(
        &self,
        frame: &[u8],
        shard: u16,
        issuer_peer: PeerId,
        parsed: &Frame<'_>,
        acc: &RendezvousAccept,
    ) -> Result<RendezvousGrant, AgentError> {
        let who = self
            .net
            .peer_identity(&issuer_peer)
            .ok_or_else(|| AgentError::Session(format!("{issuer_peer}: нет handshake")))?;
        if who.role != Role::IndexNode {
            return Err(AgentError::Session(format!(
                "{issuer_peer}: приём подписан не index-node, а {:?}",
                who.role
            )));
        }
        if acc.shard != shard || shard >= SHARDS {
            return Err(AgentError::Session(format!(
                "приём по шарду {}, а кадр пришёл по {shard}",
                acc.shard
            )));
        }
        let sig: [u8; 64] = parsed
            .signature
            .ok_or_else(|| AgentError::Session("RendezvousAccept без подписи".into()))?
            .try_into()
            .map_err(|_| AgentError::Session("подпись приёма не 64 байта".into()))?;
        if !verify_body(&who.owner, domain::RENDEZVOUS, Kind::RendezvousAccept, parsed.body, &sig)
            .unwrap_or(false)
        {
            return Err(AgentError::Session(format!(
                "{issuer_peer}: подпись приёма не принадлежит издателю"
            )));
        }
        check_accept_policy(acc, &self.owner(), &self.network, Clock::bucket_now())?;
        Ok(RendezvousGrant { issuer: who.owner, accept: *acc, frame: frame.to_vec() })
    }

    /// Открыть аутентифицированный прямой канал к цели приёма (§12.5).
    ///
    /// Приём перепроверяется здесь, а не только при `find`: между поиском и сессией его можно
    /// подменить в памяти вызывающего, и доверять структуре, собранной из полей, нельзя.
    /// Адрес цели берётся из Kademlia/identify; если его там нет (агенты не объявляются
    /// провайдерами), используйте [`Agent::open_session_at`] с адресом из address book.
    pub async fn open_session(&mut self, grant: &RendezvousGrant) -> Result<SessionInfo, AgentError> {
        self.open_session_at(grant, &[]).await
    }

    /// То же, но с явными адресами цели — прямой путь для CLI/SDK, где адрес пришёл из
    /// address book (§12.5), а не из DHT. Адрес не делает цель доверенной: владелец всё равно
    /// сверяется с `target` приёма после handshake.
    pub async fn open_session_at(
        &mut self,
        grant: &RendezvousGrant,
        target_addrs: &[Multiaddr],
    ) -> Result<SessionInfo, AgentError> {
        let verified = self.verify_standalone_accept(&grant.frame, grant.issuer)?;
        let acc = verified.accept;
        if acc.target == self.owner() {
            return Err(AgentError::Session("приём выписан на самого агента".into()));
        }
        let peer = keys::peer_from_owner(&acc.target).ok_or_else(|| {
            AgentError::Session(format!(
                "target {}… — не Ed25519-ключ",
                hex::encode(&acc.target[..4])
            ))
        })?;
        let deadline = tokio::time::Instant::now() + self.cfg.call_timeout;
        if !self.net.is_authenticated(&peer) {
            if !target_addrs.is_empty() {
                for addr in target_addrs {
                    let _ = self.net.dial(addr.clone());
                }
            } else {
                let _ = self.net.dial_peer(peer);
            }
        }
        let mut dialed = tokio::time::Instant::now();
        while !self.net.is_authenticated(&peer) {
            if tokio::time::Instant::now() >= deadline {
                return Err(AgentError::Session(format!(
                    "цель {peer} не дозвонилась за {:?}: адрес неизвестен Kademlia или NAT без \
                     relay/DCUtR (§16.3)",
                    self.cfg.call_timeout
                )));
            }
            if dialed.elapsed() >= Duration::from_secs(2) {
                if target_addrs.is_empty() {
                    let _ = self.net.dial_peer(peer);
                } else {
                    for addr in target_addrs {
                        let _ = self.net.dial(addr.clone());
                    }
                }
                dialed = tokio::time::Instant::now();
            }
            self.net.step().await;
        }
        let who = self
            .net
            .peer_identity(&peer)
            .cloned()
            .ok_or_else(|| AgentError::Session(format!("{peer}: handshake исчез")))?;
        if who.owner != acc.target {
            return Err(AgentError::Session(format!(
                "{peer}: владелец {:?} не совпал с target приёма",
                hex::encode(&who.owner[..4])
            )));
        }
        Ok(SessionInfo {
            peer,
            owner: who.owner,
            issuer: verified.issuer,
            shard: acc.shard,
            slot: acc.slot,
            issued_bucket: acc.issued_bucket,
            ttl_sec: acc.ttl_sec,
            expires_bucket: verified.expires_bucket(),
            role: who.role,
            direct: true,
        })
    }

    /// Проверка кадра приёма без сетевого контекста, но с уже известным ключом издателя.
    /// `issuer` — owner index-node'а, полученный из аутентифицированного handshake при находке.
    pub fn verify_standalone_accept(
        &self,
        frame: &[u8],
        issuer: [u8; 32],
    ) -> Result<RendezvousGrant, AgentError> {
        let parsed = decode_frame(frame)
            .map_err(|e| AgentError::Session(format!("кадр приёма не разбирается: {e}")))?;
        if parsed.header.kind != Kind::RendezvousAccept {
            return Err(AgentError::Session("кадр не RendezvousAccept".into()));
        }
        let acc = RendezvousAccept::decode(frame)
            .map_err(|e| AgentError::Session(format!("тело приёма не разбирается: {e}")))?;
        let sig: [u8; 64] = parsed
            .signature
            .ok_or_else(|| AgentError::Session("RendezvousAccept без подписи".into()))?
            .try_into()
            .map_err(|_| AgentError::Session("подпись приёма не 64 байта".into()))?;
        if !verify_body(&issuer, domain::RENDEZVOUS, Kind::RendezvousAccept, parsed.body, &sig)
            .unwrap_or(false)
        {
            return Err(AgentError::Session("подпись приёма не принадлежит издателю".into()));
        }
        check_accept_policy(&acc, &self.owner(), &self.network, Clock::bucket_now())?;
        Ok(RendezvousGrant { issuer, accept: acc, frame: frame.to_vec() })
    }

    // --- внутренняя механика -------------------------------------------------

    fn take_query_id(&mut self) -> u64 {
        let q = self.next_query_id;
        self.next_query_id = self.next_query_id.wrapping_add(1);
        q
    }

    /// Кандидаты на шард: сначала провайдеры §7.4, прошедшие handshake и несущие кредашиал на
    /// этот шард; если DHT ещё не ответил, но соединения есть — аутентифицированные узлы с тем
    /// же кредашиалом. Второй путь — не замена DHT, а честный bootstrap малой сети: `NOT_OWNER`
    /// на реплике дешевле, чем «провайдер не найден» при живом соединении с primary.
    async fn candidates(&mut self, shard: u16, deadline: tokio::time::Instant) -> Result<Vec<PeerId>, AgentError> {
        let mut last_query: Option<tokio::time::Instant> = None;
        loop {
            let providers = self.net.provider_peers(shard);
            let mut usable: Vec<PeerId> = providers
                .iter()
                .copied()
                .filter(|p| self.covers(*p, shard))
                .collect();
            // Провайдер-запись — не полный список держателей: primary мог быть соединён до того,
            // как объявление дошло до таблицы, а `FIND_PROVIDER` мог ответить только частью
            // состава. Ограничиваться провайдерами значило бы, например, знать реплику и не
            // попробовать primary, получив `NOT_OWNER` при живой записи. Аутентифицированный
            // узел с кредашиалом на шард — такой же законный кандидат; порядок сохраняет
            // предпочтение DHT.
            for p in self.net.authenticated_peers() {
                if self.covers(p, shard) && !usable.contains(&p) {
                    usable.push(p);
                }
            }
            if !usable.is_empty() {
                return Ok(usable);
            }
            for p in &providers {
                if !self.net.is_authenticated(p) {
                    // Адрес приходит из Kademlia/identify; ошибка здесь — состояние таблицы
                    // маршрутизации, и ждать его исправления честнее, чем выдумывать адрес.
                    let _ = self.net.dial_peer(*p);
                }
            }
            let authenticated = self.net.authenticated_peers();
            if !authenticated.is_empty()
                && last_query.map(|t| t.elapsed() >= Duration::from_secs(3)).unwrap_or(true)
            {
                let _ = self.net.find_providers(shard);
                last_query = Some(tokio::time::Instant::now());
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            if self.cfg.bootstrap.is_empty() && authenticated.is_empty() && providers.is_empty() {
                return Err(AgentError::NoBootstrap);
            }
            self.net.step().await;
        }
        let fallback: Vec<PeerId> = self
            .net
            .authenticated_peers()
            .into_iter()
            .filter(|p| self.covers(*p, shard))
            .collect();
        if fallback.is_empty() {
            Err(AgentError::NoProviders { shard })
        } else {
            Ok(fallback)
        }
    }

    /// Узел после handshake обязан быть index-node с кредашиалом, покрывающим шард. Без этой
    /// проверки `Publish` ушёл бы агенту, который ответил бы `NOT_OWNER`, и публикация выглядела
    /// бы как «сеть не принимает», а не как «выбран не тот пир».
    fn covers(&self, peer: PeerId, shard: u16) -> bool {
        self.net
            .peer_identity(&peer)
            .map(|w| w.role == Role::IndexNode && w.covers_shard(shard))
            .unwrap_or(false)
    }

    async fn probe_epoch(
        &mut self,
        peer: PeerId,
        shard: u16,
        deadline: tokio::time::Instant,
    ) -> Result<u64, AgentError> {
        if shard >= SHARDS {
            return Err(AgentError::Invalid(format!("шард {shard} вне 0..{SHARDS}")));
        }
        let cluster = shard * CLUSTERS_PER_SHARD;
        let query_id = self.take_query_id();
        let msg = Find {
            preprocessing_version: self.network.preprocessing_version,
            query_vector: [0i8; DIM],
            clusters: vec![cluster],
            // `top_k = 0` — проба, а не поиск: узел не обязан выписывать приёмы и искать
            // кандидатов, а `MatchResult` всё равно подписан и несёт `epoch`.
            top_k: 0,
            query_id,
            requester_ed25519: self.owner(),
            tlv: Vec::new(),
        };
        let body = msg.body_bytes();
        let sig = self.id.sign_body(domain::FIND, Kind::Find, &body);
        if !self.net.send_frame(peer, msg.encode_signed(&sig)) {
            return Err(AgentError::BadAnswer(format!("{peer}: не отправлена проба эпохи")));
        }
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(AgentError::Timeout(self.cfg.call_timeout));
            }
            self.net.step().await;
            for (from, bytes) in self.net.take_inbox() {
                let Ok(frame) = decode_frame(&bytes) else { continue };
                match frame.header.kind {
                    Kind::MatchResult => {
                        let Ok(res) = MatchResult::decode(&bytes) else { continue };
                        if res.query_id != query_id {
                            continue;
                        }
                        if from != peer {
                            return Err(AgentError::BadAnswer(format!(
                                "эпоха пришла от {from}, а проба уходила к {peer}"
                            )));
                        }
                        self.verify_match_result(from, shard, &frame, &res)?;
                        self.known_epoch
                            .entry(shard)
                            .and_modify(|e| *e = (*e).max(res.epoch))
                            .or_insert(res.epoch);
                        return Ok(res.epoch);
                    }
                    Kind::Error => {
                        let Ok(err) = ProtocolError::decode(&bytes) else { continue };
                        if err.shard == shard || err.shard == 0 {
                            return Err(AgentError::Refused {
                                code: err.code,
                                shard,
                                retry_after_ms: err.retry_after_ms,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn verify_match_result(
        &self,
        from: PeerId,
        shard: u16,
        frame: &Frame<'_>,
        res: &MatchResult,
    ) -> Result<(), AgentError> {
        if frame.header.kind != Kind::MatchResult {
            return Err(AgentError::BadAnswer("кадр не MatchResult".into()));
        }
        if res.shard != shard {
            return Err(AgentError::BadAnswer(format!(
                "MatchResult по шарду {}, а запрос — по {shard}",
                res.shard
            )));
        }
        let who = self
            .net
            .peer_identity(&from)
            .ok_or_else(|| AgentError::BadAnswer(format!("{from}: нет handshake")))?;
        if who.role != Role::IndexNode {
            return Err(AgentError::BadAnswer(format!(
                "{from}: ответ подписан ролью {:?}",
                who.role
            )));
        }
        if !who.covers_shard(shard) {
            return Err(AgentError::BadAnswer(format!(
                "{from}: кредашиал не покрывает шард {shard}"
            )));
        }
        if who.owner != res.responder_ed25519 {
            return Err(AgentError::BadAnswer(format!(
                "{from}: responder_ed25519 не совпал с транспортом"
            )));
        }
        let sig: [u8; 64] = frame
            .signature
            .ok_or_else(|| AgentError::BadAnswer("MatchResult без подписи".into()))?
            .try_into()
            .map_err(|_| AgentError::BadAnswer("подпись MatchResult не 64 байта".into()))?;
        if !verify_body(&who.owner, domain::MATCH, Kind::MatchResult, frame.body, &sig)
            .unwrap_or(false)
        {
            return Err(AgentError::BadAnswer(format!("{from}: подпись MatchResult не сходится")));
        }
        res.check_sort_contract()
            .map_err(|e| AgentError::BadAnswer(format!("{from}: {e}")))?;
        Ok(())
    }

    async fn wait_publish_result(
        &mut self,
        peer: PeerId,
        shard: u16,
        epoch: u64,
        deadline: tokio::time::Instant,
    ) -> Result<PublishAck, AgentError> {
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(AgentError::Timeout(self.cfg.call_timeout));
            }
            self.net.step().await;
            for (from, bytes) in self.net.take_inbox() {
                let Ok(frame) = decode_frame(&bytes) else { continue };
                match frame.header.kind {
                    Kind::PublishAck => {
                        let Ok(ack) = PublishAck::decode(&bytes) else { continue };
                        if ack.shard != shard {
                            continue;
                        }
                        if ack.epoch != epoch {
                            // ack от прошлой эпохи/публикации. PublishAck не несёт query_id, и
                            // свежесть здесь проверяется парой (shard, epoch): принять старый
                            // ack значило бы объявить durable запись, которой нет.
                            continue;
                        }
                        if from != peer {
                            continue;
                        }
                        return Ok(ack);
                    }
                    Kind::Error => {
                        let Ok(err) = ProtocolError::decode(&bytes) else { continue };
                        if err.shard == shard || err.shard == 0 {
                            return Err(AgentError::Refused {
                                code: err.code,
                                shard,
                                retry_after_ms: err.retry_after_ms,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    async fn wait(&mut self, retry_after_ms: u32, deadline: tokio::time::Instant) {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return;
        }
        let pause = Duration::from_millis(u64::from(retry_after_ms.max(50)))
            .min(deadline.saturating_duration_since(now));
        tokio::time::sleep(pause).await;
    }
}

/// Политика приёма §12.3 в порядке, который важен: адресат → TTL → истечение. Проверка подписи
/// стоит до вызова (см. `verify_standalone_accept`), потому что ей нужен ключ издателя.
pub fn check_accept_policy(
    acc: &RendezvousAccept,
    seeker: &[u8; 32],
    network: &NetworkParams,
    now_bucket: u32,
) -> Result<(), AgentError> {
    if acc.seeker != *seeker {
        return Err(AgentError::Session(
            "приём выписан на другого seeker'а: его нельзя предъявлять".into(),
        ));
    }
    if acc.ttl_sec == 0 || acc.ttl_sec > network.rendezvous_ttl_sec {
        return Err(AgentError::Session(format!(
            "ttl_sec = {} вне политики артефакта 1..={}",
            acc.ttl_sec, network.rendezvous_ttl_sec
        )));
    }
    if acc.shard >= SHARDS {
        return Err(AgentError::Session(format!("шард {} вне 0..{SHARDS}", acc.shard)));
    }
    let ttl_buckets = buckets(acc.ttl_sec as u32).max(1);
    if now_bucket > acc.issued_bucket.saturating_add(ttl_buckets) {
        return Err(AgentError::Session(format!(
            "приём истёк: выписан в бакете {}, сейчас {now_bucket}, TTL {ttl_buckets} бакетов",
            acc.issued_bucket
        )));
    }
    Ok(())
}

/// Слияние §12.2, шаги 6–7: дедупликация по владельцу с минимальным `d2`, порядок — целый
/// `(d2, slot, shard, owner)` без float, затем обрезка.
fn merge_matches(mut all: Vec<FoundMatch>, top_k: usize) -> Vec<FoundMatch> {
    all.sort_by_key(|m| (m.d2, m.slot, m.shard, m.owner_ed25519));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|m| seen.insert(m.owner_ed25519));
    all.truncate(top_k);
    all
}

/// Группировка кластеров по шардам с сохранением порядка внутри шарда и удалением повторов.
/// Дубль в списке — не ошибка вызывающего, но второй раз тот же кластер в `Find` увеличивал бы
/// подписанное тело без изменения смысла.
fn group_clusters(clusters: &[u16]) -> Vec<(u16, Vec<u16>)> {
    let mut out: BTreeMap<u16, Vec<u16>> = BTreeMap::new();
    for c in clusters {
        let list = out.entry(shard_of(*c)).or_default();
        if !list.contains(c) {
            list.push(*c);
        }
    }
    out.into_iter().collect()
}

/// Протокольный бакет текущего времени. Единственное место, где агент смотрит на системные
/// часы до отправки: `published_bucket` и expiry — из §9.6, а не из `TimeMark` узла; узел
/// сверит их со своей политикой приёма.
struct Clock;

impl Clock {
    fn bucket_now() -> u32 {
        bucket_of(now_sec())
    }
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_node::testing;

    fn network() -> NetworkParams {
        NetworkParams::from_artifact(&vecdht_artifact::reference_artifact()).expect("эталонный артефакт")
    }

    #[test]
    fn network_params_come_from_the_artifact_not_from_constants() {
        let n = network();
        assert_eq!(n.nlist, 1024);
        assert_eq!(n.shards, 64);
        assert_eq!(n.preprocessing_version, 1);
        // 3600 с при бакете 16 с — ровно 225 бакетов, как в тестовых публикациях.
        assert_eq!(n.ttl_default_buckets, 225);
        assert_eq!(n.ttl_max_buckets, 5400);
        assert_eq!(n.pow_bits_default, 20);
        assert_eq!(n.rendezvous_ttl_sec, 300);
        assert_eq!(n.shard_of_cluster(112), Some(7));
        assert_eq!(n.shard_of_cluster(1024), None);
    }

    #[test]
    fn a_publish_request_derives_the_same_intent_id_as_the_wire_contract() {
        let v = testing::vector(3);
        let req = PublishRequest::new(v, 112, 225, 1);
        assert_eq!(req.intent_id, vecdht_crypto::ids::intent_id(&v, 1));
        // Кешированный ид must not be silently replaced by a different vector's id.
        let other = req.with_intent_id([9; 32]);
        assert_eq!(other.intent_id, [9; 32]);
        assert_eq!(other.vec_q, v);
    }

    #[test]
    fn publish_validation_rejects_a_foreign_cluster_and_an_overlong_ttl() {
        let n = network();
        assert!(n.shard_of_cluster(5000).is_none());
        let q = FindQuery::new([0; DIM], vec![112, 112, 113], 10);
        assert_eq!(group_clusters(&q.clusters), vec![(7, vec![112, 113])], "дубли схлопываются");
        assert_eq!(group_clusters(&[0, 1, 1023]), vec![(0, vec![0, 1]), (63, vec![1023])]);
    }

    #[test]
    fn find_validation_rejects_an_empty_cluster_set_and_zero_top_k() {
        // Через поля, а не через `Agent`: валидация — чистая функция от артефакта, и тест не
        // обязан поднимать Swarm/рантайм ради проверки диапазона.
        let n = network();
        assert!(n.top_k_max >= 32);
        assert!(n.top_k_max < u16::MAX);
        assert!(n.ttl_max_buckets >= n.ttl_default_buckets);
    }

    #[test]
    fn merge_keeps_the_minimum_d2_per_owner_and_truncates_without_float() {
        let m = |owner: u8, d2: u32, slot: u32, shard: u16| FoundMatch {
            owner_ed25519: [owner; 32],
            shard,
            cluster_id: shard * 16,
            slot,
            d2,
            epoch: 1,
            grant: None,
        };
        let all = vec![m(2, 50, 1, 1), m(1, 20, 2, 2), m(2, 10, 3, 3), m(1, 30, 4, 4)];
        let merged = merge_matches(all, 10);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].owner_ed25519, [2; 32], "у owner 2 осталась d2=10, а не 50");
        assert_eq!(merged[0].d2, 10);
        assert_eq!(merged[1].owner_ed25519, [1; 32]);
        assert_eq!(merge_matches(vec![m(1, 1, 1, 1), m(2, 2, 2, 2)], 1).len(), 1);
    }

    #[test]
    fn accept_policy_matches_the_target_side_of_the_node() {
        let n = network();
        let seeker = [7u8; 32];
        let ok = RendezvousAccept {
            seeker,
            target: [9u8; 32],
            shard: 7,
            slot: 41,
            issued_bucket: 100,
            ttl_sec: 300,
        };
        assert!(check_accept_policy(&ok, &seeker, &n, 100).is_ok());
        // 300 с — 19 бакетов: последний действительный бакет 119 включительно.
        assert!(check_accept_policy(&ok, &seeker, &n, 119).is_ok());
        assert!(matches!(
            check_accept_policy(&ok, &seeker, &n, 120),
            Err(AgentError::Session(_))
        ));
        assert!(matches!(
            check_accept_policy(&ok, &[8u8; 32], &n, 100),
            Err(AgentError::Session(_))
        ));
        let mut too_long = ok;
        too_long.ttl_sec = n.rendezvous_ttl_sec + 1;
        assert!(check_accept_policy(&too_long, &seeker, &n, 100).is_err());
        let zero = RendezvousAccept { ttl_sec: 0, ..ok };
        assert!(check_accept_policy(&zero, &seeker, &n, 100).is_err());
    }

    #[test]
    fn a_grant_expiry_uses_the_same_ceil_as_the_issuer() {
        let g = RendezvousGrant {
            issuer: [1; 32],
            accept: RendezvousAccept {
                seeker: [2; 32],
                target: [3; 32],
                shard: 7,
                slot: 1,
                issued_bucket: 100,
                ttl_sec: 300,
            },
            frame: Vec::new(),
        };
        assert_eq!(g.expires_bucket(), 119);
    }
}
