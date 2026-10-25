//! Сетевой сервис узла: соединения, handshake, кадры и тики (§4.1, §5.3, §7.4, §9).
//!
//! Сервис владеет `ShardNode`'ами одного процесса и libp2p-`Swarm`'ом. Разделение простое:
//! транспорт отвечает на вопрос «кто это и доставил ли он байты», узел — на вопрос «что
//! означают эти байты». `on_frame` узла уже несёт всю протокольную логику, поэтому сервис
//! не перепроверяет PoW, квоты или подписи — он передаёт аутентифицированного владельца и
//! кадр, а отправителей, которых не аутентифицировал, не пускает вовсе.
//!
//! Почему `from` — владелец, а не `PeerId`: §12.3 привязывает rendezvous-приём к
//! транспортной личности, и в v8 это 32-байтовый Ed25519-владелец (§4.1). `PeerId` —
//! multihash, менять его длину в протоколе нельзя, а `owner()` восстанавливает ключ из
//! identity-multihash без собственной деривации id.
//!
//! Один процесс — один event loop (`current_thread`): `SharedAdmission` намеренно `Rc`,
//! потому что admission — локальная политика процесса, и запирать её мьютексом ради
//! многопоточности значило бы платить за то, чего у узла нет. Сервис поэтому `!Send`.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode};
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self, QueryResult, RecordKey};
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{identify, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
use thiserror::Error;
use vecdht_crypto::{verify_body, verify_revoke, AuthoritySet, Identity};
use vecdht_node::{Clock, Envelope, RevocationInsert, Revocations, ShardNode};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::constants::{shard_of, shard_provider_key, SHARDS};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{
    domain, err_code, CertRevoke, Codec, Find, Handshake, LeaseGrant, LeaveNotice,
    MembershipUpdate, ProtocolError, Publish, ReplicateAck, ReplicateOp, Role, SnapshotOffer,
    WalPullRequest, WalPullResponse,
};

use crate::behaviour::{Behaviour, BehaviourEvent};
use crate::codec::FrameCodec;
use crate::door::{DoorLedger, DoorReason};
use crate::handshake::{self, HandshakeError, PeerIdentity};
use crate::keys;
use crate::provider_cache::ProviderCache;

/// Имя gossip-темы шарда. Семантика та же, что у ключа провайдера §7.4: один шард — одна
/// тема, без band-суффиксов, которые в v7.5 умножали записи без пользы.
pub fn shard_topic(shard: u16) -> String {
    format!("vdht/s8/{shard}/gossip")
}

/// Тема отзывов `CertRevoke` (§4.2). Отзыв не привязан к шарду: один `nonce` покрывает набор
/// шардов кредашиала, и весть обязана дойти до всех, кто уже говорит с этим ключом, а не
/// только до держателей одного шарда. Отдельная тема, а не shard-тема, ещё и потому, что
/// `CertRevoke` — единственный кадр, чья авторитетность доказана структурным порогом, а не
/// подписью отправителя кадра.
pub const CONTROL_TOPIC: &str = "vdht/s8/control";

fn control_topic() -> IdentTopic {
    IdentTopic::new(CONTROL_TOPIC)
}

#[derive(Debug, Error)]
pub enum NetError {
    #[error("не удалось собрать транспорт: {0}")]
    Build(String),
    #[error("не удалось открыть listen-адрес: {0}")]
    Listen(String),
    #[error("не удалось набрать bootstrap: {0}")]
    Dial(String),
    #[error("роль {0:?} не может держать шарды")]
    AgentCannotHost(Role),
    #[error("кредашиал не покрывает шард {0}")]
    CertDoesNotCover(u16),
    #[error("своё приветствие не собирается: {0}")]
    Greeting(#[from] HandshakeError),
    #[error("состояние отзывов (§4.2) не поднимается: {0}")]
    RevokedState(String),
    /// Собственный кредашиал с закрытым окном (§4.2): `valid_until` inclusive-конец, поэтому
    /// `valid_until <= now` — уже отказ. Отдельный вариант, а не `Build`, потому что оператору
    /// важно отличить «не собрался транспорт» от «срок вышел, перевыпусти кредашиал».
    #[error("срок собственного кредашиала истёк: valid_until={valid_until}, now={now}")]
    OwnCertExpired { now: u32, valid_until: u32 },
}

/// Что делает сервис в одном шаге. Нужен тестам и CLI: событие сети и тик различаются по
/// причине, а не по факту «что-то произошло».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Swarm,
    Tick,
}

pub struct NetConfig {
    /// Адреса прослушивания. Пустой список — только исходящие соединения (агент).
    pub listen: Vec<Multiaddr>,
    /// Адреса узлов, к которым дозваниваемся при старте. Kademlia догонит остальное.
    pub bootstrap: Vec<Multiaddr>,
    pub genesis_hash: [u8; 32],
    pub model_version: String,
    pub preprocessing_version: u16,
    pub agent_version: String,
    pub request_timeout: Duration,
    pub idle_timeout: Duration,
    /// Как часто перевыпускать provider-записи §7.4. 180 с — из спеки, не из half-TTL.
    pub provider_republish: Duration,
    /// Период пробуждения event loop. Тик узла всё равно не чаще секунды.
    pub poll_interval: Duration,
    /// Каталог, где живёт `revocation.bin` (§4.2, `ADR-0050`). `None` — поведение до цикла
    /// `H-0094`: множество отзывов только в памяти, перезапуск процесса обнуляет его. Заданный
    /// каталог создаётся при первой записи; битый файл означает «сервис не стартует», а не
    /// «отзывов нет».
    pub revoked_dir: Option<PathBuf>,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            bootstrap: Vec::new(),
            genesis_hash: [0u8; 32],
            model_version: String::new(),
            preprocessing_version: 1,
            agent_version: "vecdht-net/0.1".to_string(),
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            provider_republish: Duration::from_secs(180),
            poll_interval: Duration::from_millis(25),
            revoked_dir: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Handshake,
    App,
}

pub struct NetService {
    swarm: Swarm<Behaviour>,
    local_peer: PeerId,
    role: Role,
    greeting: Handshake,
    authorities: AuthoritySet,
    genesis_hash: [u8; 32],
    model_version: String,
    preprocessing_version: u16,
    nodes: BTreeMap<u16, ShardNode>,
    peers: HashMap<PeerId, PeerIdentity>,
    /// Обратный указатель для `Envelope.to`: узел адресует ответы владельцу, а транспорт
    /// знает только `PeerId`.
    owners: HashMap<[u8; 32], PeerId>,
    /// Отзывы §4.2 по `nonce` кредашиала. Множество переживает смену эпохи: отзыв — это
    /// свойство ключа, а не эпизода членства (§11.4). С `ADR-0050` то же множество живёт ещё и
    /// в `revocation.bin`: `E-0094` измерил, что RAM-форма обнулялась перезапуском и отозванный
    /// пир снова проходил handshake (`rv_g3_accepted_after_restart=1`).
    revoked: Revocations,
    /// Свой `nonce` — чтобы узнать в потоке отзывов собственный и замолчать.
    own_cert_nonce: Option<[u8; 16]>,
    /// Конец окна собственного кредашиала (`valid_until`, exclusive). `E-0098`: до правки сервис
    /// знал только `nonce` и отзыв, а собственный срок не читал ни разу — узел продолжал
    /// подписывать и обслуживать после закрытия окна, и отказ был виден лишь на двери соседа.
    own_cert_valid_until: Option<u32>,
    /// Сколько раз действие было отклонено именно из-за закрытого окна. Отдельно от `door`:
    /// журнал двери считает причины отказа **входящим** пирам, а это — причина собственного
    /// молчания. Число, а не текст в `errors`, потому что молчание без счётчика не наблюдаемо.
    own_cert_expired_refusals: u64,
    self_revoked: bool,
    pending: HashMap<OutboundRequestId, Pending>,
    /// Кадры, которые не принадлежат ни одному локальному шарду: ответы агента (`PublishAck`,
    /// `MatchResult`, `RendezvousAccept`, `Error`) и чужой gossip. Агент забирает их отсюда.
    inbox: Vec<(PeerId, Vec<u8>)>,
    /// Конечная таблица «шард → провайдеры» (§7.4, §P5; `E-0091`). До того цикла это был
    /// `BTreeMap<u16, BTreeSet<PeerId>>` с одним пополнением и нулём удалений — монотонный кэш,
    /// измеренный `E-0085` гейтом (в) и перенесённый `E-0086` в спеку.
    providers: ProviderCache,
    /// Локальный журнал причин отказа двери (§4.2, `E-0095`; `ADR-0051`). Конечен по
    /// построению: ключ — имя из `DoorReason::ALL`, а не текст, поэтому число записей
    /// ограничено числом имён, а не числом отказов.
    door: DoorLedger,
    listen_addrs: Vec<Multiaddr>,
    errors: Vec<String>,
    /// Сколько provider-запросов §7.4 завершилось успехом. Наблюдаемость для гейтов: «узел
    /// объявил шард» и «узел попытался объявить» — разные утверждения.
    pub provider_announcements: u64,
    cfg: NetConfig,
    last_tick_sec: u64,
    last_provide_sec: u64,
    last_bootstrap_sec: u64,
}

impl NetService {
    pub fn new(
        local: Identity,
        role: Role,
        cert: Option<NodeCert>,
        nodes: Vec<ShardNode>,
        authorities: AuthoritySet,
        cfg: NetConfig,
    ) -> Result<Self, NetError> {
        if role == Role::Agent && !nodes.is_empty() {
            return Err(NetError::AgentCannotHost(role));
        }
        if let Some(c) = &cert {
            for n in &nodes {
                if !c.covers_shard(n.shard) {
                    return Err(NetError::CertDoesNotCover(n.shard));
                }
            }
        }
        let greeting = handshake::greeting(
            role,
            &cfg.model_version,
            cfg.preprocessing_version,
            cfg.genesis_hash,
            cert.as_ref(),
        )?;
        let own_cert_nonce = cert.as_ref().map(|c| c.nonce);
        let own_cert_valid_until = cert.as_ref().map(|c| c.valid_until);
        // `E-0098`: закрытое окно до старта — отказ с причиной, а не сервис-зомби. Дверь
        // встречной стороны отвергла бы нас на каждом новом handshake, а мы бы продолжали
        // подписывать кадры и считать, что «сеть не отвечает».
        let now = now_sec();
        if own_cert_expired_at(own_cert_valid_until, now) {
            return Err(NetError::OwnCertExpired {
                now: now.min(u64::from(u32::MAX)) as u32,
                valid_until: own_cert_valid_until.unwrap_or(0),
            });
        }
        // `ADR-0050`: множество отзывов поднимается из каталога до того, как открыт транспорт.
        // Отказ здесь — единственная честная ветка для битого файла: `Revocations::open` обязан
        // не вернуть пустое множество, иначе испорченный файл снял бы все отзывы разом
        // (`L-0013`, RFC 5280 различает «не отозван» и «не определён»).
        let revoked = Revocations::open(cfg.revoked_dir.clone())
            .map_err(|e| NetError::RevokedState(e.to_string()))?;
        // Молчание отозванного узла следует из файла, а не из одного эпизода: если собственный
        // `nonce` уже в списке, сервис стартует уже молча (`E-0094`, гейм (3)).
        let self_revoked = own_cert_nonce.is_some_and(|n| revoked.contains(&n));
        let keypair = keys::keypair(&local);
        let local_peer = keypair.public().to_peer_id();
        // `ADR-0060`: сервер DHT — это роль, а не наличие шарда. Индексный узел без загруженных
        // шардов (наблюдатель, узел между назначениями) всё равно обязан принимать
        // `ADD_PROVIDER`: клиент libp2p-kad отвечает `DeniedUpgrade` и запись провайдера не
        // сохраняет. Агент остаётся клиентом — он только спрашивает.
        let is_server = role != Role::Agent;
        let model_version = cfg.model_version.clone();
        let agent_version = cfg.agent_version.clone();
        let request_timeout = cfg.request_timeout;
        let idle_timeout = cfg.idle_timeout;

        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NetError::Build(e.to_string()))?
            .with_quic_config(|mut c| {
                // `libp2p-quic` по умолчанию даёт 5 с на TLS-handshake и 10 с простоя — меньше
                // прикладного `request_timeout` (10 с). На стенде P1 (`E-0105`) 60 узлов в debug
                // дали 664 таймаута прикладного рукопожатия и 0/8 резолвов: часть соединений
                // умирала «Handshake with the remote timed out» раньше, чем приложение начинало
                // свой handshake. Порог рукопожатия берём не меньше `request_timeout`, а простой —
                // из `idle_timeout`, чтобы транспорт и `Swarm` не расходились в сроках.
                c.handshake_timeout = request_timeout.max(Duration::from_secs(10));
                c.max_idle_timeout =
                    idle_timeout.as_millis().min(u128::from(u32::MAX)) as u32;
                c
            })
            .with_behaviour(move |key| {
                let peer = key.public().to_peer_id();
                let mut kad_cfg = kad::Config::new(StreamProtocol::new("/vecdht/v8/kad"));
                kad_cfg.set_query_timeout(Duration::from_secs(30));
                let mut kad = kad::Behaviour::with_config(peer, MemoryStore::new(peer), kad_cfg);
                kad.set_mode(Some(if is_server { kad::Mode::Server } else { kad::Mode::Client }));

                let ident_cfg = identify::Config::new("/vecdht/v8/id".to_string(), key.public())
                    .with_agent_version(agent_version);
                let identify = identify::Behaviour::new(ident_cfg);
                let gossip_cfg = gossipsub::ConfigBuilder::default()
                    .validation_mode(ValidationMode::Strict)
                    .build()?;
                let gossip = gossipsub::Behaviour::new(
                    MessageAuthenticity::Signed(key.clone()),
                    gossip_cfg,
                )
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                let protocols = std::iter::once((
                    StreamProtocol::new("/vecdht/v8/frame"),
                    ProtocolSupport::Full,
                ));
                let frames = request_response::Behaviour::<FrameCodec>::new(
                    protocols,
                    request_response::Config::default().with_request_timeout(request_timeout),
                );
                Ok(Behaviour { frames, kad, identify, gossip })
            })
            .map_err(|e| NetError::Build(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(idle_timeout))
            .build();

        for addr in &cfg.listen {
            swarm.listen_on(addr.clone()).map_err(|e| NetError::Listen(e.to_string()))?;
        }
        for addr in &cfg.bootstrap {
            swarm.dial(addr.clone()).map_err(|e| NetError::Dial(e.to_string()))?;
        }
        for shard in nodes.iter().map(|n| n.shard) {
            let topic = IdentTopic::new(shard_topic(shard));
            swarm
                .behaviour_mut()
                .gossip
                .subscribe(&topic)
                .map_err(|e| NetError::Build(e.to_string()))?;
        }
        // Control-тема нужна всем ролям: агенту — чтобы не жать руку отозванному узлу, узлу —
        // чтобы сбросить уже установленные соединения. Подписка без держателей шарда ничего
        // не стоит: сообщений в этой теме ровно столько, сколько отзывов.
        swarm
            .behaviour_mut()
            .gossip
            .subscribe(&control_topic())
            .map_err(|e| NetError::Build(e.to_string()))?;

        Ok(Self {
            swarm,
            local_peer,
            role,
            greeting,
            authorities,
            genesis_hash: cfg.genesis_hash,
            model_version,
            preprocessing_version: cfg.preprocessing_version,
            nodes: nodes.into_iter().map(|n| (n.shard, n)).collect(),
            peers: HashMap::new(),
            owners: HashMap::new(),
            revoked,
            own_cert_nonce,
            own_cert_valid_until,
            own_cert_expired_refusals: 0,
            self_revoked,
            pending: HashMap::new(),
            inbox: Vec::new(),
            providers: ProviderCache::product(cfg.provider_republish.as_secs()),
            door: DoorLedger::default(),
            listen_addrs: Vec::new(),
            errors: Vec::new(),
            provider_announcements: 0,
            cfg,
            last_tick_sec: 0,
            last_provide_sec: 0,
            last_bootstrap_sec: 0,
        })
    }

    // --- наблюдение ---------------------------------------------------------

    pub fn peer_id(&self) -> PeerId {
        self.local_peer
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn node(&self, shard: u16) -> Option<&ShardNode> {
        self.nodes.get(&shard)
    }

    pub fn node_mut(&mut self, shard: u16) -> Option<&mut ShardNode> {
        self.nodes.get_mut(&shard)
    }

    pub fn shards(&self) -> impl Iterator<Item = u16> + '_ {
        self.nodes.keys().copied()
    }

    pub fn listen_addrs(&self) -> &[Multiaddr] {
        &self.listen_addrs
    }

    pub fn peer_identity(&self, peer: &PeerId) -> Option<&PeerIdentity> {
        self.peers.get(peer)
    }

    pub fn is_authenticated(&self, peer: &PeerId) -> bool {
        self.peers.contains_key(peer)
    }

    pub fn provider_peers(&self, shard: u16) -> Vec<PeerId> {
        self.providers.peers(shard)
    }

    /// Сколько записей держит таблица провайдеров (§7.4, `E-0091`). Наблюдаемость для гейтов:
    /// «кэш конечен» — утверждение о длине, а не о наличии кода удаления.
    pub fn provider_cache_len(&self) -> usize {
        self.providers.len()
    }

    /// Три числа конечности кэша по трём причинам снятия (`E-0091`): смерть пира по событию
    /// транспорта или отзыва, истечение дедлайна §7.4, предел на шард. Смешивать их нельзя —
    /// у каждой свой лимит и своя цена.
    pub fn provider_cache_stats(&self) -> (u64, u64, u64) {
        (self.providers.pruned_dead, self.providers.expired, self.providers.evicted)
    }

    /// Все пиры, прошедшие handshake. Агенту это нужно, чтобы отличить «провайдер найден, но
    /// адреса его нет» от «соединение есть, а роли не сходятся»: `provider_peers` возвращает
    /// и тех, до кого мы ещё не дозвонились.
    pub fn authenticated_peers(&self) -> Vec<PeerId> {
        let mut v: Vec<PeerId> = self.peers.keys().copied().collect();
        v.sort();
        v
    }

    /// Был ли `nonce` отозван порогом авторитетов. Наблюдаемость для тестов и оператора:
    /// «сообщение прошло» и «отзыв применён» — разные утверждения.
    pub fn is_revoked_nonce(&self, nonce: &[u8; 16]) -> bool {
        self.revoked.contains(nonce)
    }

    pub fn revocation_count(&self) -> usize {
        self.revoked.len()
    }

    /// Байт файла состояния отзывов на диске; 0 — файла нет (каталог не задан или в него ещё
    /// ничего не записывалось). Гейт цены переживаемости в `E-0094` меряет именно это число,
    /// потому что «множество в памяти» и «множество, переживающее рестарт» — разные обещания.
    pub fn revocation_file_bytes(&self) -> u64 {
        self.revoked.file_bytes()
    }

    /// Сколько отзывов отвергнуто из-за предела, сколько записей не удалось и сколько пришедших
    /// отзывов уже были в множестве. Первые две ветки — потеря необратимости, а не штатный
    /// исход, поэтому они наблюдаемы (`ADR-0050`); третья нужна оракулу, чтобы отличить
    /// «дубликат доставлен» от «дубликат не пришёл».
    pub fn revocation_counters(&self) -> (u64, u64, u64) {
        (
            self.revoked.refused_at_bound,
            self.revoked.save_errors,
            self.revoked.duplicates,
        )
    }

    /// Каталог, из которого поднято множество отзывов (`None` — только память).
    pub fn revocation_dir(&self) -> Option<PathBuf> {
        self.revoked.dir()
    }

    /// Свой кредашиал отозван: сервис перестал отвечать, подписывать и объявлять шарды.
    /// Процесс при этом не завершается — оператору нужно место, где увидеть причину.
    pub fn is_self_revoked(&self) -> bool {
        self.self_revoked
    }

    /// Собственное окно закрылось. Предикат читает часы при каждом вызове, а не булев флаг,
    /// зафиксированный на старте: окно может закрыться на ходу (`E-0098`, гейт (2)).
    pub fn is_self_expired(&self) -> bool {
        own_cert_expired_at(self.own_cert_valid_until, now_sec())
    }

    /// Сколько исходящих действий отклонено из-за закрытого окна. Нуль означает «попыток не
    /// было», а не «срок не выходил»: срок наблюдаем ещё и [`is_self_expired`].
    pub fn own_cert_expired_refusals(&self) -> u64 {
        self.own_cert_expired_refusals
    }

    /// Единый предикат молчания: отзыв и истечение — разные причины, но действие одно.
    fn credential_stopped(&self) -> bool {
        self.self_revoked || self.is_self_expired()
    }

    /// Причина остановки для текста отказа. Строка `'static`, чтобы её нельзя было получить
    /// из `format!` и засчитать как метрику.
    fn credential_refusal(&self) -> Option<&'static str> {
        if self.self_revoked {
            Some("свой кредашиал отозван")
        } else if self.is_self_expired() {
            Some("срок своего кредашиала истёк")
        } else {
            None
        }
    }

    pub fn take_inbox(&mut self) -> Vec<(PeerId, Vec<u8>)> {
        std::mem::take(&mut self.inbox)
    }

    pub fn take_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut self.errors)
    }

    /// Отказы двери по именам причин (`E-0095`). Это локальное наблюдение, а не протокол: имена
    /// не уходят на провод, и `CERT_INVALID` остаётся единственным кодом для всех причин кредашиала.
    pub fn door_refusals(&self) -> Vec<(&'static str, u64)> {
        self.door.refusals()
    }

    /// Снимок наблюдения транспорта (`H-0104`, Приложение C). Отдельный метод, а не поле:
    /// снимок не хранится и не устаревает — он читает счётчики в момент вызова.
    pub fn metrics(&self) -> crate::metrics::NetMetrics {
        crate::metrics::NetMetrics::of(self)
    }

    /// Полное число отказов, записанных дверью. Нужен, чтобы проверить `сумма по именам == refusals`
    /// (гейт (3) цикла `E-0095`).
    pub fn door_refusal_total(&self) -> u64 {
        self.door.total()
    }

    /// Счётчик одной причины. Нуль означает «эта ветка не происходила», а не «ветки нет».
    pub fn door_refusal_count(&self, reason: DoorReason) -> u64 {
        self.door.count(reason)
    }

    /// Число пиров в таблице маршрутизации Kademlia. Тестам нужно отличать «запись не ушла,
    /// потому что некого было спрашивать» от «запись ушла и не дошла».
    pub fn kad_peer_count(&mut self) -> usize {
        self.swarm.behaviour_mut().kad.kbuckets().map(|b| b.num_entries()).sum()
    }

    // --- действия -----------------------------------------------------------

    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), NetError> {
        self.swarm.dial(addr).map_err(|e| NetError::Dial(e.to_string()))
    }

    /// Дозвониться по `PeerId`, адрес которого знает Kademlia/identify. Отдельно от [`dial`]:
    /// провайдер шарда известен именно как ключ (§7.4), а `Find` не несёт адресов вовсе.
    ///
    /// Ошибка «нет адресов» — не сбой транспорта, а состояние таблицы маршрутизации: агент
    /// обязан честно сказать, что провайдер найден, но недостижим, а не изобретать адрес.
    pub fn dial_peer(&mut self, peer: PeerId) -> Result<(), NetError> {
        self.swarm
            .dial(peer)
            .map_err(|e| NetError::Dial(format!("{peer}: {e}")))
    }

    /// Отправить один кадр как запрос. Разрешено только аутентифицированному пиру: иначе
    /// `from` на той стороне не будет существовать, а анонимный publish — это уже не v8.
    pub fn send_frame(&mut self, peer: PeerId, frame: Vec<u8>) -> bool {
        if let Some(why) = self.credential_refusal() {
            if !self.self_revoked {
                self.own_cert_expired_refusals += 1;
            }
            self.errors.push(format!("{why}: кадры не отправляются"));
            return false;
        }
        if !self.peers.contains_key(&peer) {
            self.errors.push(format!("{peer}: кадр до завершения handshake не отправляется"));
            return false;
        }
        let id = self.swarm.behaviour_mut().frames.send_request(&peer, frame);
        self.pending.insert(id, Pending::App);
        true
    }

    /// Спросить Kademlia, кто держит шард (§7.4). Результат придёт событием
    /// `QueryResult::GetProviders` и осядет в `provider_peers`.
    pub fn find_providers(&mut self, shard: u16) -> Result<(), NetError> {
        let key = RecordKey::new(&shard_provider_key(shard));
        self.swarm.behaviour_mut().kad.get_providers(key);
        Ok(())
    }

    /// Подписаться на тему шарда. Нужно всем, кто публикует или слушает gossip: без подписки
    /// gossipsub не строит mesh и `publish` отвечает `InsufficientPeers`. Идемпотентно;
    /// возвращает `true`, если подписка новая.
    pub fn subscribe(&mut self, shard: u16) -> Result<bool, NetError> {
        if shard >= SHARDS {
            return Err(NetError::Build(format!("шард {shard} вне 0..{SHARDS}")));
        }
        self.swarm
            .behaviour_mut()
            .gossip
            .subscribe(&IdentTopic::new(shard_topic(shard)))
            .map_err(|e| NetError::Build(e.to_string()))
    }

    pub fn unsubscribe(&mut self, shard: u16) -> Result<bool, NetError> {
        self.swarm
            .behaviour_mut()
            .gossip
            .unsubscribe(&IdentTopic::new(shard_topic(shard)))
            .map_err(|e| NetError::Build(e.to_string()))
    }

    /// Опубликовать кадр в gossip-тему шарда. Приложение обязано подписать `Publish`/`Find`
    /// (§5.3): транспорт подписывает конверт libp2p, но не прикладное тело, и его подпись не
    /// переживает пересылку третьим лицам.
    ///
    /// Тема подписывается здесь же — иначе первый `publish` от агента всегда падал бы
    /// `InsufficientPeers`. Доставка всё равно best-effort: mesh собирается на ближайшем
    /// heartbeat gossipsub, поэтому один `Publish` подряд с подпиской может не уйти никому.
    /// Гарантированный путь — прямое соединение; gossip нужен для широковещательного поиска.
    pub fn publish_gossip(&mut self, shard: u16, frame: Vec<u8>) -> Result<(), NetError> {
        if let Some(why) = self.credential_refusal() {
            if !self.self_revoked {
                self.own_cert_expired_refusals += 1;
            }
            return Err(NetError::Build(format!(
                "{why}: публикация в темы шардов прекращена"
            )));
        }
        let signed = decode_frame(&frame).map(|f| f.header.signed()).unwrap_or(false);
        if !signed {
            return Err(NetError::Build(format!(
                "gossip-кадр шарда {shard} обязан быть подписан приложением (§5.3)"
            )));
        }
        self.subscribe(shard)?;
        self.swarm
            .behaviour_mut()
            .gossip
            .publish(IdentTopic::new(shard_topic(shard)), frame)
            .map(|_| ())
            .map_err(|e| NetError::Build(e.to_string()))
    }

    /// Разослать отзыв по control-теме. Сервис не проверяет его и ничего не добавляет от
    /// себя: авторитетность `CertRevoke` — это порог подписей внутри тела, а подпись
    /// сервиса не значила бы в нём ничего. Проверяет получатель, и делает это до записи
    /// nonce в множество; иначе ослабленный отзыв (2-of-5) отзывал бы ключи у всех, кто
    /// доверяет ретранслятору, а не авторитетам.
    pub fn publish_revoke(&mut self, revoke: &CertRevoke) -> Result<(), NetError> {
        let topic = control_topic();
        self.swarm
            .behaviour_mut()
            .gossip
            .subscribe(&topic)
            .map_err(|e| NetError::Build(e.to_string()))?;
        self.swarm
            .behaviour_mut()
            .gossip
            .publish(topic, revoke.encode_unsigned())
            .map(|_| ())
            .map_err(|e| NetError::Build(e.to_string()))
    }

    /// Шаговый режим: одно событие сети либо один тик. `run` — тот же шаг в цикле.
    pub async fn step(&mut self) -> Step {
        tokio::select! {
            ev = self.swarm.select_next_some() => {
                self.on_swarm_event(ev);
                Step::Swarm
            }
            _ = tokio::time::sleep(self.cfg.poll_interval) => {
                self.maybe_tick();
                Step::Tick
            }
        }
    }

    pub async fn run(mut self) {
        loop {
            self.step().await;
        }
    }

    // --- события ------------------------------------------------------------

    fn on_swarm_event(&mut self, ev: SwarmEvent<BehaviourEvent>) {
        match ev {
            SwarmEvent::NewListenAddr { address, .. } => self.listen_addrs.push(address),
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                if peer_id == self.local_peer {
                    self.errors.push("соединение с самим собой".to_string());
                    return;
                }
                self.start_handshake(peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                // Соединений с одним пиром может быть несколько (dial-гонка); таблица
                // handshake одна на пира, и сбрасывать её при закрытии первого из них
                // значило бы отвергать кадры на всё ещё живом соединении.
                if num_established > 0 {
                    return;
                }
                let Some(who) = self.forget_peer(peer_id) else { return };
                // §9.8: смерть пира доказывается событием транспорта, а не тишиной. Без
                // этого вызова primary ждал бы истечения lease (90 с), и handoff начинался
                // бы после простоя шарда, а не в ту же секунду.
                self.notify_peer_lost(who.owner);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                self.errors.push(format!("dial {peer_id:?}: {error}"));
            }
            SwarmEvent::ListenerError { listener_id, error } => {
                self.errors.push(format!("listener {listener_id:?}: {error}"));
            }
            SwarmEvent::Behaviour(e) => self.on_behaviour(e),
            _ => {}
        }
    }

    fn start_handshake(&mut self, peer: PeerId) {
        if self.credential_stopped() {
            // Предъявлять отозванный или просроченный кредашиал нечего: соединение закрывается
            // до обмена приветствиями, чтобы встречная сторона не приняла нас за живого узла.
            let _ = self.swarm.disconnect_peer_id(peer);
            return;
        }
        let frame = self.greeting.encode_unsigned();
        let id = self.swarm.behaviour_mut().frames.send_request(&peer, frame);
        self.pending.insert(id, Pending::Handshake);
    }

    fn on_behaviour(&mut self, ev: BehaviourEvent) {
        match ev {
            BehaviourEvent::Frames(e) => self.on_frame_event(e),
            BehaviourEvent::Kad(e) => self.on_kad_event(e),
            BehaviourEvent::Identify(e) => self.on_identify_event(e),
            BehaviourEvent::Gossip(e) => self.on_gossip_event(e),
        }
    }

    fn on_frame_event(&mut self, ev: request_response::Event<Vec<u8>, Vec<Vec<u8>>>) {
        match ev {
            request_response::Event::Message { peer, message } => match message {
                request_response::Message::Request { request, channel, .. } => {
                    let batch = self.on_request(peer, request);
                    self.swarm.behaviour_mut().frames.send_response(channel, batch).ok();
                }
                request_response::Message::Response { request_id, response } => {
                    self.on_response(peer, request_id, response);
                }
            },
            request_response::Event::OutboundFailure { peer, request_id, error } => {
                self.pending.remove(&request_id);
                self.errors.push(format!("ответ {peer}: {error}"));
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                self.errors.push(format!("запрос {peer}: {error}"));
            }
            _ => {}
        }
    }

    fn on_request(&mut self, peer: PeerId, request: Vec<u8>) -> Vec<Vec<u8>> {
        if self.credential_stopped() {
            // Ни handshake, ни прикладной кадр: узел без действующего кредашиала не имеет
            // права ни отвечать, ни подписывать. Отказ явный, чтобы встречная сторона не
            // ждала таймаута и не считала молчание согласием.
            if self.self_revoked {
                self.door.record(DoorReason::SelfCertRevoked);
                return vec![error_frame(err_code::CERT_INVALID, 0, 0, "кредашиал отозван")];
            }
            // Срок — не отзыв: имя причины локальное и отдельное (`E-0098`), а провод остаётся
            // прежним — `CERT_INVALID` (§13).
            self.own_cert_expired_refusals += 1;
            return vec![error_frame(err_code::CERT_INVALID, 0, 0, "срок кредашиала истёк")];
        }
        let kind = match decode_frame(&request) {
            Ok(f) => f.header.kind,
            Err(e) => {
                self.door.record(DoorReason::FrameUndecodable);
                return vec![error_frame(err_code::BAD_ENUM, 0, 0, &e.to_string())];
            }
        };
        if kind == Kind::Handshake {
            return match self.accept_handshake(peer, &request) {
                Err(e) => {
                    // Причина считается ДО того, как кадр схлопнут в `CERT_INVALID`: имя живёт
                    // локально, провод остаётся прежним (`ADR-0051`, решение 1).
                    let reason = DoorReason::from_handshake_error(&e);
                    self.door.record(reason);
                    vec![error_frame(err_code::CERT_INVALID, 0, 0, &e.to_string())]
                }
                Ok(who) => {
                    let mut batch = vec![self.greeting.encode_unsigned()];
                    // ADR-0017: завершённый handshake — доказательство достижимости и повод
                    // догнать пропущенную цепочку. Кадры идут в том же ответе, после
                    // приветствия: инициирующая сторона обработает их уже аутентифицированной.
                    batch.extend(self.peer_alive_events(who.owner).into_iter().map(|e| e.frame));
                    batch
                }
            };
        }
        let Some(who) = self.peers.get(&peer).cloned() else {
            self.door.record(DoorReason::Unspecified);
            return vec![error_frame(
                err_code::DENIED,
                0,
                0,
                "кадр до handshake: отправитель не аутентифицирован",
            )];
        };
        self.route_app_frame(peer, who.owner, &request)
    }

    fn accept_handshake(&mut self, peer: PeerId, frame: &[u8]) -> Result<PeerIdentity, HandshakeError> {
        let hs = Handshake::decode(frame)?;
        let now = now_sec() as u32;
        let v = handshake::Verifier {
            authorities: &self.authorities,
            genesis_hash: self.genesis_hash,
            model_version: &self.model_version,
            preprocessing_version: self.preprocessing_version,
            now_sec: now,
            revoked_nonces: self.revoked.set(),
        };
        let who = handshake::verify(&hs, peer, &v)?;
        self.owners.insert(who.owner, peer);
        self.peers.insert(peer, who.clone());
        // §9.8 симметрично: событие транспорта доказало не только смерть, но и возвращение. С этим
        // доказательством окно недоверия кэша снимается, и ответ DHT об этом пире снова принимается
        // (`E-0091`, превью-прогон: без снятия окна легитимно перезапущенный провайдер терялся).
        self.providers.prove_alive(&peer);
        Ok(who)
    }

    fn on_response(&mut self, peer: PeerId, id: OutboundRequestId, response: Vec<Vec<u8>>) {
        match self.pending.remove(&id) {
            Some(Pending::Handshake) => {
                // Встречная сторона отвечает своим `Handshake`, а не пустым «ok»: иначе
                // инициатор принимал бы любую роль без кредашиала.
                let Some((first, rest)) = response.split_first() else {
                    self.errors.push(format!("handshake {peer}: пустой ответ"));
                    return;
                };
                match self.accept_handshake(peer, first) {
                    Ok(who) => {
                        // ADR-0017: приветствие принято — handshake завершён у обеих сторон.
                        // Сначала маршрутизируем дополнительные кадры ответа (ответчик мог
                        // вложить туда принятую цепочку), затем отдаём свою: переподключение
                        // обязано догонять membership, а не ждать следующей эпохи.
                        for frame in rest {
                            self.route_inbound(peer, frame.clone());
                        }
                        for env in self.peer_alive_events(who.owner) {
                            self.dispatch(env);
                        }
                    }
                    Err(e) => self.errors.push(format!("handshake {peer}: {e}")),
                }
            }
            _ => {
                for frame in response {
                    self.route_inbound(peer, frame);
                }
            }
        }
    }

    fn on_kad_event(&mut self, ev: kad::Event) {
        match ev {
            kad::Event::OutboundQueryProgressed { result, .. } => match result {
                QueryResult::StartProviding(Ok(_)) | QueryResult::RepublishProvider(Ok(_)) => {
                    // Успех означает «запись легла на ближайшие узлы»; логировать нечего.
                    self.provider_announcements += 1;
                }
                QueryResult::StartProviding(Err(e)) | QueryResult::RepublishProvider(Err(e)) => {
                    self.errors.push(format!("provider record: {e}"));
                }
                QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                    key,
                    providers,
                })) => {
                    if let Some(shard) = shard_from_provider_key(key.as_ref()) {
                        // Не `extend`, а `see`: ответ DHT — подтверждение записи, у которого есть
                        // дата. Без даты нельзя ни снять истёкшее (§7.4 `provider_record_ttl`), ни
                        // вытеснить старое при переборе предела (`E-0091`).
                        self.providers.see(shard, providers, now_sec());
                    }
                }
                QueryResult::GetProviders(Err(e)) => {
                    self.errors.push(format!("provider lookup: {e}"));
                }
                QueryResult::Bootstrap(Err(e)) => {
                    self.errors.push(format!("kad bootstrap: {e}"));
                }
                _ => {}
            },
            kad::Event::RoutingUpdated { peer, addresses, .. } => {
                // Узел узнал адрес пира из Kademlia — это тот же адрес, что принёс identify;
                // повторное добавление идемпотентно, а без него dial по `PeerId` невозможен.
                for a in addresses.iter() {
                    self.swarm.behaviour_mut().kad.add_address(&peer, a.clone());
                }
                // Провайдер-запись §7.4 обязана лежать у *ближайших* узлов. Изменение таблицы
                // маршрутизации меняет это множество, поэтому объявляем шарды заново на
                // ближайшем тике. Без этого запись, отправленная до первого identify, не дошла
                // бы до новых соседей до истечения 180-секундного цикла.
                self.last_provide_sec = 0;
            }
            _ => {}
        }
    }

    fn on_identify_event(&mut self, ev: identify::Event) {
        if let identify::Event::Received { peer_id, info, .. } = ev {
            for a in info.listen_addrs {
                self.swarm.behaviour_mut().kad.add_address(&peer_id, a);
            }
            // Идентичность из identify не заменяет handshake: ключ здесь есть, но роль и
            // кредашиал — нет. Используется только для маршрутизации Kademlia.
        }
    }

    fn on_gossip_event(&mut self, ev: gossipsub::Event) {
        if let gossipsub::Event::Message { propagation_source, message, .. } = ev {
            // Control-тема несёт только `CertRevoke`; всё остальное в ней — не «будущее
            // расширение», а кадр не по адресу. Проверка идёт до любых ранних выходов:
            // отзыв должен приниматься и тогда, когда сервис уже замолчал.
            if message.topic == control_topic().hash() {
                self.on_control_message(propagation_source, &message.data);
                return;
            }
            if self.credential_stopped() {
                return;
            }
            // Темы шардов несут только прикладные кадры; Handshake по gossip — это попытка
            // выдать себя за соединение, которого не было.
            let Ok(f) = decode_frame(&message.data) else { return };
            if f.header.kind == Kind::Handshake {
                self.errors.push(format!("gossip {propagation_source}: Handshake в теме шарда"));
                return;
            }
            if f.header.kind == Kind::CertRevoke {
                // Отзыв в shard-теме обошёл бы адресность: его увидели бы только подписчики
                // одного шарда, а отзываемый ключ может покрывать несколько.
                self.errors
                    .push(format!("gossip {propagation_source}: CertRevoke вне control-темы"));
                return;
            }
            // ADR-0043: parity между двумя путями одного кадра. Прямой путь требует
            // аутентифицированности пира (`on_request`: «кадр до handshake: отправитель не
            // аутентифицирован» ⇒ `DENIED`), а gossip-путь эту проверку не делал: пир, которому
            // дверь отказала, клал `Publish` в индекс шарда и получал на свой `Find` ответы
            // (`E-0076`, `E-0085` гейт (6d): `gate6d_stored=1` при `gate6a_refused=1`).
            // Граничим по пересылающему, а не по автору: подпись автора проверяется ниже и
            // остаётся единственным, что пересылка не подделывает (§5.3). Кадры членства и
            // отзыва под этот фильтр не попадают — они самовалидируются порогом авторитетов
            // (§15.2) и обязаны доходить даже от пира, с которым двери ещё не было.
            if matches!(f.header.kind, Kind::Publish | Kind::Find)
                && !self.peers.contains_key(&propagation_source)
            {
                self.errors.push(format!(
                    "gossip {propagation_source}: {:?} без пройденной двери — кадр отброшен",
                    f.header.kind
                ));
                return;
            }
            let Some(owner) = keys::owner(&propagation_source) else { return };
            if matches!(f.header.kind, Kind::Publish | Kind::Find) && f.signature.is_none() {
                self.errors
                    .push(format!("gossip {propagation_source}: неподписанный {:?}", f.header.kind));
                return;
            }
            if let Err(e) = self.authenticate_gossip_author(&message.data, f.header.kind) {
                self.errors.push(format!("gossip {propagation_source}: {e}"));
                return;
            }
            let replies = self.route_gossip(owner, &message.data);
            for env in replies {
                self.dispatch(env);
            }
        }
    }

    /// `CertRevoke` из control-темы: порог авторитетов — единственная проверка, которая
    /// делает отзыв отзывом. Автор конверта здесь ничего не значит: пересылать вправе кто
    /// угодно, подписать — только порог.
    fn on_control_message(&mut self, source: PeerId, data: &[u8]) {
        let revoke = match decode_frame(data) {
            Ok(f) if f.header.kind == Kind::CertRevoke => match CertRevoke::decode(data) {
                Ok(r) => r,
                Err(e) => {
                    self.errors.push(format!("control {source}: отзыв не разобран: {e}"));
                    return;
                }
            },
            Ok(f) => {
                self.errors
                    .push(format!("control {source}: {:?} в control-теме", f.header.kind));
                return;
            }
            Err(e) => {
                self.errors.push(format!("control {source}: кадр не разобран: {e}"));
                return;
            }
        };
        if let Err(e) = verify_revoke(&revoke, &self.authorities) {
            self.errors.push(format!("control {source}: отзыв отвергнут: {e}"));
            return;
        }
        self.apply_revoke(revoke);
    }

    /// Применить проверенный отзыв: запомнить `nonce`, сбросить соединения с его носителем и,
    /// если отозван собственный кредашиал, замолчать целиком.
    fn apply_revoke(&mut self, revoke: CertRevoke) {
        let nonce = revoke.nonce;
        // `ADR-0050`: отзыв применяется только вместе с его записью. Не удалось записать —
        // вставка откатана, `nonce` остаётся неприменённым, и `errors` получает причину;
        // молча запомнить в RAM и не дописать в файл значило бы обещать переживаемость,
        // которой нет.
        match self.revoked.insert(nonce) {
            // Повторная рассылка — штатный retry gossip: отзыв идемпотентен по `nonce`, ни
            // множество, ни файл не изменились, побочных эффектов быть не должно.
            Ok(RevocationInsert::Duplicate) => return,
            Ok(RevocationInsert::Applied) => {}
            Ok(RevocationInsert::RefusedAtBound) => {
                self.errors.push(format!(
                    "отзыв не применён: множество отзывов упёрлось в предел {}",
                    vecdht_node::MAX_REVOCATIONS
                ));
                return;
            }
            Err(e) => {
                self.errors
                    .push(format!("отзыв не записан и откатан, nonce не применён: {e}"));
                return;
            }
        }
        if self.own_cert_nonce == Some(nonce) && !self.self_revoked {
            self.self_revoked = true;
            self.errors.push(format!(
                "свой кредашиал отозван ({}): узел перестаёт отвечать, подписывать и объявлять шарды",
                revoke.reason
            ));
            // Провайдер-записи §7.4 — обещание «этот узел держит шард». Отозванный узел его
            // больше не выполняет; запись обязана исчезнуть, а не дожить до TTL.
            let shards: Vec<u16> = self.nodes.keys().copied().collect();
            for shard in shards {
                let key = RecordKey::new(&shard_provider_key(shard));
                self.swarm.behaviour_mut().kad.stop_providing(&key);
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossip
                    .unsubscribe(&IdentTopic::new(shard_topic(shard)));
            }
        }
        let victims: Vec<PeerId> = if self.self_revoked {
            // Мы больше не узел: любой собеседник говорит с отозванным ключом.
            self.peers.keys().copied().collect()
        } else {
            self.peers
                .iter()
                .filter(|(_, who)| who.cert.as_ref().is_some_and(|c| c.nonce == nonce))
                .map(|(p, _)| *p)
                .collect()
        };
        for peer in victims {
            if let Some(who) = self.forget_peer(peer) {
                let _ = self.swarm.disconnect_peer_id(peer);
                // Себя отозванный узел не уведомляет: `peer_lost` стартует выборы и подписывает
                // кадры членства, а отозванный ключ не подписывает ничего (§4.2). Для уже
                // мёртвого узла это не потеря состояния, а исполнение обязательства.
                if !self.self_revoked {
                    self.notify_peer_lost(who.owner);
                }
            }
        }
    }

    /// Убрать пира из таблиц, не трогая соединение. Возвращает его личность: решение о
    /// `peer_lost` принимает вызывающий, потому что у отзыва нет события транспорта, на
    /// которое можно было бы опереться.
    fn forget_peer(&mut self, peer: PeerId) -> Option<PeerIdentity> {
        // Провайдер-запись снимается до проверки handshake-таблицы: доказательство смерти
        // (§9.8 — событие транспорта, §4.2 — проверенный отзыв) не зависит от того, успели ли мы
        // аутентифицировать пира. Именно здесь `E-0091` закрывает монотонность: раньше у поля
        // `providers` не было ни одного удаляющего вызова.
        self.providers.forget_peer(&peer, now_sec());
        let who = self.peers.remove(&peer)?;
        self.owners.retain(|_, p| *p != peer);
        Some(who)
    }

    /// Сообщить узлам о потере владельца и разослать их реакции. §9.8: это доказательство
    /// смерти, а не догадка; отзыв ключа — такая же потеря для репликации.
    fn notify_peer_lost(&mut self, owner: [u8; 32]) {
        let clock = Clock::at(now_sec());
        let mut out = Vec::new();
        for node in self.nodes.values_mut() {
            match node.peer_lost(owner, clock.bucket) {
                Ok(list) => out.extend(list),
                Err(e) => self.errors.push(format!("peer_lost шарда {}: {e}", node.shard)),
            }
        }
        for env in out {
            self.dispatch(env);
        }
    }

    /// Обратное к `peer_lost` (§9.8, ADR-0017): завершённый handshake снимает метку и даёт
    /// узлам принятую цепочку для отставшего коллеги. Возвращает конверты, а не рассылает
    /// их: на входящем handshake они обязаны уйти в том же пакете ответа, а не запросом
    /// раньше, чем встречная сторона приняла наше приветствие.
    fn peer_alive_events(&mut self, owner: [u8; 32]) -> Vec<Envelope> {
        let mut out = Vec::new();
        for node in self.nodes.values_mut() {
            match node.peer_alive(owner) {
                Ok(list) => out.extend(list),
                Err(e) => self.errors.push(format!("peer_alive шарда {}: {e}", node.shard)),
            }
        }
        out
    }

    /// Прикладная подпись gossip-кадра (§5.3). Проверяется до узла, потому что узел видит
    /// только `from`; неподписанный `Find` в gossip дал бы rendezvous-приём от чужого имени.
    fn authenticate_gossip_author(&self, frame: &[u8], kind: Kind) -> Result<(), String> {
        let f = decode_frame(frame).map_err(|e| e.to_string())?;
        let Some(sig) = f.signature else {
            return if matches!(kind, Kind::Publish | Kind::Find) {
                Err("подпись обязательна в gossip".to_string())
            } else {
                Ok(())
            };
        };
        let sig: [u8; 64] = sig.try_into().map_err(|_| "длина подписи".to_string())?;
        let ok = match kind {
            Kind::Publish => {
                let m = Publish::decode(frame).map_err(|e| e.to_string())?;
                verify_body(&m.owner_ed25519, domain::PUBLISH, Kind::Publish, f.body, &sig)
            }
            Kind::Find => {
                let m = Find::decode(frame).map_err(|e| e.to_string())?;
                verify_body(&m.requester_ed25519, domain::FIND, Kind::Find, f.body, &sig)
            }
            // Остальные gossip-кадры в v1 не несут обязательной проверяемой подписи на этом
            // уровне: членство проверяет порог в узле, артефакт — свои подписи авторитета.
            _ => return Ok(()),
        }
        .unwrap_or(false);
        // Транспортный автор не обязан совпадать с автором тела: конверт gossip подписан
        // пересылающим, и подпись тела — единственное, что нельзя подделать пересылкой.
        if ok { Ok(()) } else { Err("подпись не сходится с телом".to_string()) }
    }

    fn maybe_tick(&mut self) {
        if self.credential_stopped() {
            // Тик узла подписывает кадры (членство, GC, репликация). Отозванный или просроченный
            // ключ не подписывает ничего — это и есть обязательство §4.2, а не только разрыв
            // соединений.
            return;
        }
        let now = now_sec();
        if now == self.last_tick_sec {
            return;
        }
        self.last_tick_sec = now;
        // §7.4 `provider_record_ttl = 420 с`: подстраховка для записей, чью смерть транспорт не
        // успел доказать (`E-0091`). Проход по таблице не чаще раза в секунду, её размер ограничен
        // пределом на шард × число шардов (статический ассерт в `provider_cache`).
        self.providers.expire(now);
        let clock = Clock::at(now);
        let mut out = Vec::new();
        for node in self.nodes.values_mut() {
            match node.tick(clock.bucket) {
                Ok(list) => out.extend(list),
                Err(e) => self.errors.push(format!("tick шарда {}: {e}", node.shard)),
            }
        }
        for env in out {
            self.dispatch(env);
        }
        if now.saturating_sub(self.last_bootstrap_sec) >= 60 && !self.peers.is_empty() {
            self.last_bootstrap_sec = now;
            let _ = self.swarm.behaviour_mut().kad.bootstrap();
        }
        if now.saturating_sub(self.last_provide_sec) >= self.cfg.provider_republish.as_secs() {
            self.last_provide_sec = now;
            for shard in self.nodes.keys().copied().collect::<Vec<_>>() {
                let key = RecordKey::new(&shard_provider_key(shard));
                if let Err(e) = self.swarm.behaviour_mut().kad.start_providing(key) {
                    self.errors.push(format!("start_providing шарда {shard}: {e}"));
                }
            }
        }
    }

    // --- маршрутизация -------------------------------------------------------

    /// Кадр от аутентифицированного пира — локальному шарду, а ответы — обратно.
    fn route_app_frame(&mut self, peer: PeerId, owner: [u8; 32], frame: &[u8]) -> Vec<Vec<u8>> {
        let shard = match shard_of_frame(frame) {
            Ok(Some(s)) => s,
            Ok(None) => {
                self.inbox.push((peer, frame.to_vec()));
                return Vec::new();
            }
            Err(e) => return vec![error_frame(err_code::BAD_ENUM, 0, 0, &e)],
        };
        let Some(node) = self.nodes.get_mut(&shard) else {
            return vec![error_frame(
                err_code::NOT_OWNER,
                1_000,
                shard,
                "этот узел не держит шард",
            )];
        };
        let replies = match node.on_frame(owner, frame, Clock::at(now_sec())) {
            Ok(replies) => replies,
            Err(e) => return vec![error_frame(err_code::BAD_ENUM, 0, shard, &e.to_string())],
        };
        let mut back = Vec::new();
        for env in replies {
            if env.to == owner {
                back.push(env.frame);
            } else {
                self.dispatch(env);
            }
        }
        back
    }

    /// Кадр из gossip: источник уже проверен на подпись тела. `from` для узла — owner
    /// источника, как и на прямом пути (§12.3 не различает пути).
    fn route_gossip(&mut self, owner: [u8; 32], frame: &[u8]) -> Vec<Envelope> {
        let Ok(Some(shard)) = shard_of_frame(frame) else { return Vec::new() };
        let Some(node) = self.nodes.get_mut(&shard) else { return Vec::new() };
        match node.on_frame(owner, frame, Clock::at(now_sec())) {
            Ok(list) => list,
            Err(e) => {
                self.errors.push(format!("gossip шарда {shard}: {e}"));
                Vec::new()
            }
        }
    }

    /// Входящий ответ по нашему запросу: ack'и и снапшоты — узлу, остальное — в inbox.
    fn route_inbound(&mut self, peer: PeerId, frame: Vec<u8>) {
        if self.credential_stopped() {
            return;
        }
        let shard = match shard_of_frame(&frame) {
            Ok(Some(s)) if self.nodes.contains_key(&s) => s,
            _ => {
                self.inbox.push((peer, frame));
                return;
            }
        };
        let Some(owner) = self.peers.get(&peer).map(|p| p.owner) else {
            self.inbox.push((peer, frame));
            return;
        };
        let replies = match self.nodes.get_mut(&shard) {
            Some(node) => node.on_frame(owner, &frame, Clock::at(now_sec())),
            None => return,
        };
        match replies {
            Ok(replies) => {
                for env in replies {
                    self.dispatch(env);
                }
            }
            Err(e) => self.errors.push(format!("ответ шарда {shard}: {e}")),
        }
    }

    /// `Envelope` адресован владельцу, а не `PeerId`: переводим через таблицу handshake'ов.
    fn dispatch(&mut self, env: Envelope) {
        if self.credential_stopped() {
            // Кадр уже подписан узлом до отзыва или до закрытия окна; отправлять его — значит
            // продолжать говорить от имени недействительного ключа. Молчание важнее доставки.
            return;
        }
        let Some(&peer) = self.owners.get(&env.to) else {
            self.errors.push(format!("нет соединения с владельцем {}…", hex_prefix(&env.to)));
            return;
        };
        if !self.peers.contains_key(&peer) {
            self.errors.push(format!("{peer}: ответ до завершения handshake"));
            return;
        }
        let id = self.swarm.behaviour_mut().frames.send_request(&peer, env.frame);
        self.pending.insert(id, Pending::App);
    }
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Закрыто ли собственное окно на момент `now`. Граница исключающая: `valid_until` — первый
/// момент, когда кредашиал уже недействителен (`cert.rs:132…133`, `in_validity`).
fn own_cert_expired_at(valid_until: Option<u32>, now: u64) -> bool {
    valid_until.is_some_and(|u| u64::from(u) <= now)
}

fn hex_prefix(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{x:02x}")).collect()
}

/// Кадр `Error` для пира. `_detail` — только для человека у вызывающей стороны: поля под
/// подробность в `ProtocolError` нет, а расширять канон ради лога нельзя (§5.1).
fn error_frame(code: &str, retry_after_ms: u32, shard: u16, _detail: &str) -> Vec<u8> {
    ProtocolError { code: code.to_string(), retry_after_ms, shard }.encode_unsigned()
}

/// Шард, которому адресован кадр, если он вообще адресован шарду.
fn shard_of_frame(frame: &[u8]) -> Result<Option<u16>, String> {
    let f = decode_frame(frame).map_err(|e| e.to_string())?;
    let shard = match f.header.kind {
        Kind::Publish => Some(shard_of(Publish::decode(frame).map_err(|e| e.to_string())?.cluster_id)),
        Kind::Find => Find::decode(frame)
            .map_err(|e| e.to_string())?
            .clusters
            .first()
            .map(|c| shard_of(*c)),
        Kind::ReplicateOp => Some(ReplicateOp::decode(frame).map_err(|e| e.to_string())?.shard),
        Kind::ReplicateAck => Some(ReplicateAck::decode(frame).map_err(|e| e.to_string())?.shard),
        Kind::LeaseGrant => Some(LeaseGrant::decode(frame).map_err(|e| e.to_string())?.shard),
        Kind::MembershipUpdate => {
            Some(MembershipUpdate::decode(frame).map_err(|e| e.to_string())?.shard)
        }
        Kind::LeaveNotice => Some(LeaveNotice::decode(frame).map_err(|e| e.to_string())?.shard),
        Kind::WalPullRequest => Some(WalPullRequest::decode(frame).map_err(|e| e.to_string())?.shard),
        Kind::WalPullResponse => Some(WalPullResponse::decode(frame).map_err(|e| e.to_string())?.shard),
        Kind::SnapshotOffer => Some(SnapshotOffer::decode(frame).map_err(|e| e.to_string())?.shard),
        _ => None,
    };
    Ok(shard)
}

fn shard_from_provider_key(key: &[u8]) -> Option<u16> {
    // `vdht/s8/` (8 байт) + u16 BE + 0x00 0x00 (§7.4).
    if key.len() != 12 || &key[..8] != b"vdht/s8/" || key[10] != 0 || key[11] != 0 {
        return None;
    }
    let shard = u16::from_be_bytes([key[8], key[9]]);
    (shard < SHARDS).then_some(shard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_key_roundtrips_and_rejects_foreign_keys() {
        for shard in [0u16, 1, 63] {
            assert_eq!(shard_from_provider_key(&shard_provider_key(shard)), Some(shard));
        }
        assert_eq!(shard_from_provider_key(b"vdht/s8/\x00\x40\x00\x00"), None);
        assert_eq!(shard_from_provider_key(b"vdht/s8/\x00\x01\x00"), None);
        assert_eq!(shard_from_provider_key(b"xxxxxxxx\x00\x01\x00\x00"), None);
    }

    #[test]
    fn frame_shard_matches_the_publish_body() {
        use vecdht_node::testing;
        use vecdht_wire::DIM;
        let agent = testing::identity(1);
        let v: [i8; DIM] = testing::vector(1);
        let frame = testing::PublishSpec {
            agent: &agent,
            vec_q: &v,
            cluster_id: 112,
            shard: 7,
            epoch: 1,
            published_bucket: 0,
            ttl_buckets: 225,
            bits: 8,
        }
        .frame();
        assert_eq!(shard_of_frame(&frame), Ok(Some(7)));
    }
}

/// `E-0098`: граница собственного окна. Отдельный модуль, чтобы фильтр
/// `cargo test --lib own_cert_window` исполнял ровно эти два кейса и ничего не задевал.
#[cfg(test)]
mod own_cert_window {
    use super::own_cert_expired_at;

    #[test]
    fn the_boundary_is_exclusive() {
        // `valid_until` — первый момент, когда кредашиал уже недействителен (`in_validity`).
        assert!(own_cert_expired_at(Some(100), 100), "граница обязана быть исключающей");
        assert!(!own_cert_expired_at(Some(100), 99), "до границы окно ещё открыто");
    }

    #[test]
    fn a_node_without_own_cert_never_expires() {
        // Агент без кредашиала: срока нет, истекать нечему.
        assert!(!own_cert_expired_at(None, u64::MAX));
    }
}
