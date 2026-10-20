//! VecDHT v8 — Python SDK (§17.1): обёртка, в которой **нет** протокольной логики.
//!
//! Правило, из которого растёт вся граница этого crate: Python не кодирует и не подписывает
//! ничего. Байтовый кодек кадров (§5), канонический текст и квантование (§6), assign по
//! замороженным центроидам (§7.2), PoW (§11.1) и сетевой путь §12 уже реализованы в
//! `vecdht-{wire,crypto,artifact,embed,net}` и здесь только проброшены. Дублировать любой из этих
//! шагов на Python означало бы второй источник истины — ровно тот дефект, из-за которого v7.5 с
//! двумя «каноническими» protobuf-энкодерами стал несовместим сам с собой (§0, строка 10).
//!
//! Что [`PyAgent`] делает по-настоящему:
//!
//! * `publish` — путь §12.1: encode шагов 1–8, проба эпохи, PoW, подписанный `Publish` и ожидание
//!   `PublishAck`; возвращается подтверждение durable-записи, а не «отправлено»;
//! * `find` — §12.2: один `Find` на шард, сверка подписей и эпох, дедупликация и `top_k`; рядом
//!   лежат отказы отдельных шардов, потому что частичный успех — штатное состояние;
//! * `session` — §12.5: проверка предъявленного `RendezvousAccept` по ключу издателя и прямой
//!   аутентифицированный канал к цели. Relay/DCUtR в v1 не подняты, поэтому адрес цели берётся из
//!   address book (`to=[...]`) или Kademlia.
//!
//! Честная граница этой сборки: шаг 4 (§6.2) считает `HashModel` из тестового оракула, а не
//! ModernBERT. Поэтому `publish`/`find` требуют явного `allow_surrogate=True` и помечают результат
//! `vector_source`; молча подставить хеш вместо смысла SDK не имеет права. Настоящие веса — это
//! feature `candle` и `--model-dir` в Rust-пути (P0/§18.1), который появится в SDK вместе с P6.
//! Суррогатный вектор годится для проверки механики: publish и find, посчитанные одной и той же
//! моделью, маршрутизируются согласованно, но числа не сопоставимы с сетью на ModernBERT.
//!
//! Вызовы синхронные и на время сети отпускают GIL (`Python::allow_threads`). Постоянного
//! listener'а у SDK-агента нет: он не принимает входящие сессии в покое (§12.5, `agent run` в CLI
//! ещё не реализован), поэтому `session` — исходящая.
//!
//! Сборка и проверка — в `Cargo.toml` и `test.py` рядом с этим файлом.

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use libp2p::Multiaddr;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use vecdht_crypto::Identity;
use vecdht_embed::testing::HashModel;
use vecdht_embed::Encoder;
use vecdht_net::keys;
use vecdht_net::{
    Agent, AgentConfig, AgentError, FindOutcome, FindQuery, NetworkParams, PublishReceipt,
    PublishRequest, SessionInfo,
};
use vecdht_node::buckets;

/// Один мост между «ошибкой Rust-контракта» и исключением Python. Тип не выбирается по тексту:
/// все провалы валидации в этом crate — про неверные байты, длины или биты, то есть `ValueError`.
/// Сетевые состояния идут отдельно через [`agent_err`]: их вызывающий не чинит аргументом.
fn bad<E: std::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(format!("{e}"))
}

fn unhex(s: &str) -> PyResult<Vec<u8>> {
    hex::decode(s).map_err(bad)
}

/// Сетевые состояния — не «плохие байты», а недоступная сеть или отвергнутый кадр, поэтому
/// `RuntimeError`; `ValueError` остаётся за тем, что вызывающий может исправить в аргументах.
fn agent_err(e: AgentError) -> PyErr {
    match &e {
        AgentError::Invalid(_) | AgentError::Artifact(_) => PyValueError::new_err(e.to_string()),
        _ => PyRuntimeError::new_err(e.to_string()),
    }
}

fn runtime() -> PyResult<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("tokio-рантайм: {e}")))
}

fn hex32(raw: &str, what: &str) -> PyResult<[u8; 32]> {
    let bytes = hex::decode(raw).map_err(|e| PyValueError::new_err(format!("{what}: {e}")))?;
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "{what}: ожидалось 32 байта, пришло {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn seed_from_hex(raw: &str) -> PyResult<[u8; 32]> {
    hex32(raw, "seed_hex")
}

fn parse_addrs(raw: Option<Vec<String>>, what: &str) -> PyResult<Vec<Multiaddr>> {
    raw.unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(i, s)| {
            s.parse::<Multiaddr>()
                .map_err(|e| PyValueError::new_err(format!("{what}[{i}] = {s:?}: {e}")))
        })
        .collect()
}

/// Всё, что нужно сетевому вызову, в `Send`-форме: методы [`PyAgent`] клонируют набор и уходят с
/// ним в `allow_threads`. Сам [`Agent`] и его `NetService` — `!Send` и создаются внутри закрытия,
/// поэтому Python-поток не держит GIL ни на время handshake, ни на время PoW.
#[derive(Clone)]
struct AgentSetup {
    artifact: vecdht_artifact::Artifact,
    network: NetworkParams,
    seed: [u8; 32],
    bootstrap: Vec<Multiaddr>,
    timeout: Duration,
}

impl AgentSetup {
    fn cfg(&self) -> AgentConfig {
        AgentConfig {
            bootstrap: self.bootstrap.clone(),
            // Клиент: входящих сессий в покое SDK v1 не принимает (см. шапку модуля).
            listen: Vec::new(),
            call_timeout: self.timeout,
            request_timeout: self.timeout.min(Duration::from_secs(10)),
            ..AgentConfig::default()
        }
    }

    fn encode_intent(&self, text: &str) -> PyResult<vecdht_embed::Encoded> {
        let enc = Encoder::from_artifact(&self.artifact).map_err(bad)?;
        let model = HashModel::new();
        let intent = enc.encode_intent(&model, text).map_err(bad)?;
        Ok(intent.encoded)
    }

    fn encode_query(&self, text: &str, nprobe: usize) -> PyResult<vecdht_embed::Query> {
        let enc = Encoder::from_artifact(&self.artifact).map_err(bad)?;
        let model = HashModel::new();
        enc.encode_query(&model, text, nprobe).map_err(bad)
    }

    fn publish(
        &self,
        text: &str,
        ttl_sec: Option<u32>,
    ) -> PyResult<(vecdht_embed::Encoded, PublishReceipt)> {
        if self.bootstrap.is_empty() {
            return Err(PyValueError::new_err(
                "publish: нет bootstrap-адресов: агент не знает, кого спросить о держателе шарда; \
                 передайте bootstrap=[...] в Agent(...)",
            ));
        }
        let encoded = self.encode_intent(text)?;
        let ttl_sec = ttl_sec.unwrap_or(self.artifact.manifest.time.ttl_default_sec);
        if ttl_sec == 0 {
            return Err(PyValueError::new_err(
                "ttl_sec = 0: запись истекла бы до записи в WAL",
            ));
        }
        if ttl_sec > self.artifact.manifest.time.ttl_max_sec {
            return Err(PyValueError::new_err(format!(
                "ttl_sec = {ttl_sec} выше потолка манифеста {} (§13)",
                self.artifact.manifest.time.ttl_max_sec
            )));
        }
        let ttl_buckets = u16::try_from(buckets(ttl_sec)).map_err(|_| {
            PyValueError::new_err(format!("ttl_sec = {ttl_sec}: не помещается в бакеты u16"))
        })?;
        let req = PublishRequest {
            vec_q: encoded.vec_q,
            cluster_id: encoded.cluster_id,
            ttl_buckets,
            intent_id: encoded.intent_id,
        };
        let rt = runtime()?;
        let receipt = rt.block_on(async {
            let mut agent = Agent::new(Identity::from_seed(self.seed), self.network.clone(), self.cfg())
                .map_err(agent_err)?;
            agent.publish(&req).await.map_err(agent_err)
        })?;
        Ok((encoded, receipt))
    }

    fn find(
        &self,
        text: &str,
        nprobe: Option<usize>,
        top_k: Option<u16>,
    ) -> PyResult<(vecdht_embed::Query, FindOutcome)> {
        if self.bootstrap.is_empty() {
            return Err(PyValueError::new_err(
                "find: нет bootstrap-адресов: агент не знает, кого спросить о держателе шарда; \
                 передайте bootstrap=[...] в Agent(...)",
            ));
        }
        let nprobe = nprobe.unwrap_or(usize::from(self.network.nprobe_default));
        if nprobe == 0 || nprobe > usize::from(self.network.nlist) {
            return Err(PyValueError::new_err(format!(
                "nprobe = {nprobe}: вне 1..{}; пустой список означал бы «искать нигде», а больший \
                 nlist — полный скан под видом оптимизации (§8.6)",
                self.network.nlist
            )));
        }
        let top_k = top_k.unwrap_or(self.network.top_k_default);
        if top_k == 0 || top_k > self.network.top_k_max {
            return Err(PyValueError::new_err(format!(
                "top_k = {top_k} вне 1..={} (§7.5)",
                self.network.top_k_max
            )));
        }
        let q = self.encode_query(text, nprobe)?;
        let query = FindQuery { vec_q: q.vec_q, clusters: q.clusters.clone(), top_k };
        let rt = runtime()?;
        let outcome = rt.block_on(async {
            let mut agent = Agent::new(Identity::from_seed(self.seed), self.network.clone(), self.cfg())
                .map_err(agent_err)?;
            agent.find(&query).await.map_err(agent_err)
        })?;
        Ok((q, outcome))
    }

    fn session(
        &self,
        accept: Vec<u8>,
        issuer: [u8; 32],
        to: Vec<Multiaddr>,
    ) -> PyResult<SessionInfo> {
        if self.bootstrap.is_empty() && to.is_empty() {
            return Err(PyValueError::new_err(
                "session: нужен to=[ADDR] (address book) или bootstrap: без адреса цели прямой \
                 канал v1 не открывается, а relay/DCUtR не подняты (§16.3)",
            ));
        }
        let rt = runtime()?;
        rt.block_on(async {
            let mut agent = Agent::new(Identity::from_seed(self.seed), self.network.clone(), self.cfg())
                .map_err(agent_err)?;
            let grant = agent.verify_standalone_accept(&accept, issuer).map_err(agent_err)?;
            agent.open_session_at(&grant, &to).await.map_err(agent_err)
        })
    }
}

#[pyclass(name = "Artifact")]
pub struct PyArtifact {
    inner: vecdht_artifact::Artifact,
}

#[pymethods]
impl PyArtifact {
    /// Открыть артефакт из каталога (`manifest.json` + `centroid.bin` + подписи, §15.1).
    #[new]
    fn load(dir: &str) -> PyResult<Self> {
        vecdht_artifact::Artifact::load(std::path::Path::new(dir))
            .map(|inner| Self { inner })
            .map_err(bad)
    }

    /// Эталонный артефакт репозитория — для тестов и для ответа «что такое наше координатное пространство», когда
    /// своего каталога ещё нет.
    #[staticmethod]
    fn reference() -> Self {
        Self { inner: vecdht_artifact::reference_artifact() }
    }

    fn artifact_hash(&self) -> String {
        hex::encode(self.inner.artifact_hash())
    }

    fn genesis_hash(&self) -> String {
        hex::encode(self.inner.genesis_hash())
    }

    /// Записать артефакт в каталог: `centroid.bin` раньше `manifest.json`, как в Rust-пути
    /// (§15.1). Нужно стендам, где ещё нет своего подписанного артефакта: `Agent` принимает
    /// каталог, а не объект в памяти.
    fn save(&self, dir: &str) -> PyResult<()> {
        self.inner.save(Path::new(dir)).map_err(bad)
    }

    /// Манифест как JSON: то же, что печатает `vecdht-cli artifact show`, чтобы Python-тест мог
    /// сверить `nlist`/`dim`/`pow_bits_default` без второго парсера.
    fn manifest_json(&self) -> String {
        String::from_utf8(self.inner.manifest.to_json_bytes()).unwrap_or_default()
    }

    /// Число принятых подписей авторитетов; `pinned` — hex `artifact_hash`, ради которого узел
    /// обязан отвергнуть другой артефакт (§15.1).
    #[pyo3(signature = (pinned = None))]
    fn verify(&self, pinned: Option<&str>) -> PyResult<usize> {
        let pinned = match pinned {
            Some(h) => {
                let b = unhex(h)?;
                if b.len() != 32 {
                    return Err(PyValueError::new_err(format!("pinned hash: ожидалось 32 байта, пришло {}", b.len())));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Some(a)
            }
            None => None,
        };
        self.inner.verify(pinned).map_err(bad)
    }

    /// Шаги 6–8 (§6.2) для готового pooled-вектора: L2-нормализация, квантование в i8/127,
    /// assign по центроидам артефакта, `intent_id`. Единственный честный способ вызвать контракт
    /// без модели: пул векторов приносит вызывающий.
    fn finalize<'py>(&self, py: Python<'py>, pooled: Vec<f32>) -> PyResult<Bound<'py, PyDict>> {
        if pooled.len() != vecdht_wire::DIM {
            return Err(PyValueError::new_err(format!(
                "pooled: ожидалось {} компоненты, пришло {}",
                vecdht_wire::DIM,
                pooled.len()
            )));
        }
        let p: vecdht_embed::model::Pooled = pooled.as_slice().try_into().expect("длина проверена выше");
        let e = vecdht_embed::finalize(&p, &self.inner.centroids, vecdht_embed::PREPROCESSING_VERSION)
            .map_err(bad)?;
        encoded_to_dict(py, &e)
    }

    /// Весь publish-путь (§6.2 шаги 1–3, 6–8) на суррогатной модели. Название обязано напоминать,
    /// что эмбеддинги здесь — детерминированный оракул из тестов, а не modernbert: publish,
    /// сделанный этим вызовом, в живой сети не совпадёт ни с одним другим узлом.
    fn encode_intent_surrogate<'py>(&self, py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
        let enc = vecdht_embed::Encoder::from_artifact(&self.inner).map_err(bad)?;
        let model = vecdht_embed::testing::HashModel::new();
        let intent = enc.encode_intent(&model, text).map_err(bad)?;
        let d = encoded_to_dict(py, &intent.encoded)?;
        d.set_item("canonical", intent.canonical)?;
        Ok(d)
    }

    /// Query-путь: вектор запроса, топ-`nprobe` кластеров и их группировка по шардам (§7.5).
    /// `per_shard` — это ровно то число `Find`, которое уйдёт по сети на один запрос.
    fn encode_query_surrogate<'py>(
        &self,
        py: Python<'py>,
        text: &str,
        nprobe: usize,
    ) -> PyResult<Bound<'py, PyDict>> {
        let enc = vecdht_embed::Encoder::from_artifact(&self.inner).map_err(bad)?;
        let model = vecdht_embed::testing::HashModel::new();
        let q = enc.encode_query(&model, text, nprobe).map_err(bad)?;
        let d = PyDict::new(py);
        d.set_item("canonical", q.canonical)?;
        d.set_item("vec_q", q.vec_q.to_vec())?;
        d.set_item("clusters", q.clusters.clone())?;
        d.set_item("per_shard", q.per_shard.clone())?;
        d.set_item("fanout", q.per_shard.len())?;
        Ok(d)
    }
}

fn encoded_to_dict<'py>(py: Python<'py>, e: &vecdht_embed::Encoded) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("vec_q", e.vec_q.to_vec())?;
    d.set_item("cluster_id", e.cluster_id)?;
    d.set_item("shard", e.shard)?;
    d.set_item("intent_id", hex::encode(e.intent_id))?;
    d.set_item("preprocessing_version", e.preprocessing_version)?;
    Ok(d)
}

const SURROGATE_NOTE: &str = "HashModel (суррогат, не семантический)";

fn require_surrogate(allow_surrogate: bool, method: &str) -> PyResult<()> {
    if allow_surrogate {
        return Ok(());
    }
    Err(PyValueError::new_err(format!(
        "Agent.{method}: шаг 4 этой сборки — только детерминированный суррогат HashModel; передайте \
         allow_surrogate=True, если нужна проверка механики маршрутизации. Настоящая модель \
         (feature `candle` + model_dir) появится в SDK вместе с P6; молча подставлять хеш вместо \
         смысла нельзя"
    )))
}

fn publish_dict<'py>(
    py: Python<'py>,
    owner: [u8; 32],
    cluster_id: u16,
    receipt: &PublishReceipt,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("owner", hex::encode(owner))?;
    d.set_item("cluster_id", cluster_id)?;
    d.set_item("shard", receipt.shard)?;
    d.set_item("primary", receipt.primary.to_string())?;
    d.set_item("epoch", receipt.epoch)?;
    d.set_item("seq", receipt.seq)?;
    d.set_item("slot", receipt.slot)?;
    d.set_item("pow_bits", receipt.pow_bits)?;
    d.set_item("next_pow_bits", receipt.next_pow_bits)?;
    d.set_item("nonce", receipt.nonce)?;
    d.set_item("published_bucket", receipt.published_bucket)?;
    d.set_item("expires_bucket", receipt.expires_bucket)?;
    d.set_item("ttl_buckets", receipt.ttl_buckets)?;
    d.set_item("intent_id", hex::encode(receipt.intent_id))?;
    d.set_item("vector_source", SURROGATE_NOTE)?;
    Ok(d)
}

fn find_dict<'py>(
    py: Python<'py>,
    q: &vecdht_embed::Query,
    out: &FindOutcome,
) -> PyResult<Bound<'py, PyDict>> {
    let matches = PyList::empty(py);
    for m in &out.matches {
        let d = PyDict::new(py);
        d.set_item("owner", hex::encode(m.owner_ed25519))?;
        d.set_item("shard", m.shard)?;
        d.set_item("cluster_id", m.cluster_id)?;
        d.set_item("slot", m.slot)?;
        d.set_item("d2", m.d2)?;
        d.set_item("similarity", m.similarity())?;
        d.set_item("epoch", m.epoch)?;
        // Приём — исходные байты кадра, а не пересобранные поля: его предъявляют `session`.
        let grant: Option<Bound<'py, PyDict>> = match &m.grant {
            Some(g) => {
                let gd = PyDict::new(py);
                gd.set_item("issuer", hex::encode(g.issuer))?;
                gd.set_item("expires_bucket", g.expires_bucket())?;
                gd.set_item("frame_hex", hex::encode(&g.frame))?;
                Some(gd)
            }
            None => None,
        };
        d.set_item("grant", grant)?;
        matches.append(d)?;
    }
    let answers = PyList::empty(py);
    for a in &out.answers {
        let d = PyDict::new(py);
        d.set_item("shard", a.shard)?;
        d.set_item("peer", a.peer.to_string())?;
        d.set_item("owner", hex::encode(a.owner))?;
        d.set_item("epoch", a.epoch)?;
        d.set_item("matches", a.matches)?;
        answers.append(d)?;
    }
    let failures = PyList::empty(py);
    for f in &out.failures {
        let d = PyDict::new(py);
        d.set_item("shard", f.shard)?;
        d.set_item("reason", f.reason.clone())?;
        failures.append(d)?;
    }
    let d = PyDict::new(py);
    d.set_item("canonical", q.canonical.clone())?;
    d.set_item("clusters", q.clusters.clone())?;
    d.set_item("fanout", q.per_shard.len())?;
    d.set_item("matches", matches)?;
    d.set_item("answers", answers)?;
    d.set_item("failures", failures)?;
    d.set_item("vector_source", SURROGATE_NOTE)?;
    Ok(d)
}

fn session_dict<'py>(py: Python<'py>, s: &SessionInfo) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("peer", s.peer.to_string())?;
    d.set_item("owner", hex::encode(s.owner))?;
    d.set_item("issuer", hex::encode(s.issuer))?;
    d.set_item("shard", s.shard)?;
    d.set_item("slot", s.slot)?;
    d.set_item("issued_bucket", s.issued_bucket)?;
    d.set_item("ttl_sec", s.ttl_sec)?;
    d.set_item("expires_bucket", s.expires_bucket)?;
    d.set_item("role", format!("{:?}", s.role))?;
    d.set_item("direct", s.direct)?;
    Ok(d)
}

/// Агент §12. `unsendable`, потому что `Agent`/`NetService` привязаны к рантайму и не `Send`;
/// PyO3 в этом случае запрещает трогать объект из другого Python-потока, а не прячет гонку.
///
/// `artifact_dir` — каталог артефакта, который агент обязан pinned'ить (§15.1): с другим
/// `artifact_hash` узел не участвует в matching. `seed_hex` — единственная идентичность:
/// `owner` и `PeerId` выводятся из неё, а не выбираются отдельно (§4.1).
#[pyclass(name = "Agent", unsendable)]
pub struct PyAgent {
    #[pyo3(get)]
    artifact_dir: String,
    setup: AgentSetup,
    allow_surrogate: bool,
}

impl PyAgent {
    fn owner_bytes(&self) -> [u8; 32] {
        Identity::from_seed(self.setup.seed).pubkey()
    }
}

#[pymethods]
impl PyAgent {
    #[new]
    #[pyo3(signature = (artifact_dir, seed_hex, bootstrap=None, allow_surrogate=false, timeout_sec=20.0))]
    fn new(
        artifact_dir: String,
        seed_hex: &str,
        bootstrap: Option<Vec<String>>,
        allow_surrogate: bool,
        timeout_sec: f64,
    ) -> PyResult<Self> {
        let artifact = vecdht_artifact::Artifact::load(Path::new(&artifact_dir))
            .map_err(|e| PyValueError::new_err(format!("artifact_dir {artifact_dir:?}: {e}")))?;
        let seed = seed_from_hex(seed_hex)?;
        let bootstrap = parse_addrs(bootstrap, "bootstrap")?;
        if !(timeout_sec.is_finite() && timeout_sec > 0.0) {
            return Err(PyValueError::new_err(format!(
                "timeout_sec = {timeout_sec}: вызов без дедлайна неотличим от зависания"
            )));
        }
        // Сверка с кодеком — до первого сетевого вызова: манифест с другим nlist прошёл бы
        // собственную проверку артефакта, но шарды в проводе считаются по константам v8.
        let network = NetworkParams::from_artifact(&artifact).map_err(bad)?;
        Ok(Self {
            artifact_dir,
            setup: AgentSetup {
                artifact,
                network,
                seed,
                bootstrap,
                timeout: Duration::from_secs_f64(timeout_sec),
            },
            allow_surrogate,
        })
    }

    /// `owner_ed25519` в hex: по нему `find` сверяет записи, и он же печатается в выводе CLI.
    #[getter]
    fn owner(&self) -> String {
        hex::encode(self.owner_bytes())
    }

    /// `PeerId` выводится из того же seed: адресная книга для `session(to=...)` хранит именно его.
    #[getter]
    fn peer_id(&self) -> String {
        keys::peer_id(&Identity::from_seed(self.setup.seed)).to_string()
    }

    /// §12.1: опубликовать текст. Возвращается подтверждение durable-записи (после `PublishAck`),
    /// а не «отправлено»: `epoch`/`seq`/`slot` — то, что увидел primary.
    #[pyo3(signature = (text, ttl_sec=None))]
    fn publish<'py>(
        &self,
        py: Python<'py>,
        text: &str,
        ttl_sec: Option<u32>,
    ) -> PyResult<Bound<'py, PyDict>> {
        require_surrogate(self.allow_surrogate, "publish")?;
        let setup = self.setup.clone();
        let text = text.to_string();
        let owner = self.owner_bytes();
        let (encoded, receipt) = py.allow_threads(move || setup.publish(&text, ttl_sec))?;
        publish_dict(py, owner, encoded.cluster_id, &receipt)
    }

    /// §12.2: найти записи. Частичный успех — штатное состояние, поэтому `answers`/`failures`
    /// лежат рядом с `matches`, а не превращают весь вызов в исключение.
    #[pyo3(signature = (text, top_k=None, nprobe=None))]
    fn find<'py>(
        &self,
        py: Python<'py>,
        text: &str,
        top_k: Option<u16>,
        nprobe: Option<usize>,
    ) -> PyResult<Bound<'py, PyDict>> {
        require_surrogate(self.allow_surrogate, "find")?;
        let setup = self.setup.clone();
        let text = text.to_string();
        let (q, outcome) = py.allow_threads(move || setup.find(&text, nprobe, top_k))?;
        find_dict(py, &q, &outcome)
    }

    /// §12.5: открыть прямой аутентифицированный канал по приёму из `find`. Приём передаётся
    /// исходным кадром и ключом издателя: подпись считается по байтам кадра, не по полям.
    #[pyo3(signature = (accept_hex, issuer_hex, to=None))]
    fn session<'py>(
        &self,
        py: Python<'py>,
        accept_hex: &str,
        issuer_hex: &str,
        to: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let accept = hex::decode(accept_hex)
            .map_err(|e| PyValueError::new_err(format!("accept_hex: {e}")))?;
        let issuer = hex32(issuer_hex, "issuer_hex")?;
        let to = parse_addrs(to, "to")?;
        let setup = self.setup.clone();
        let info = py.allow_threads(move || setup.session(accept, issuer, to))?;
        session_dict(py, &info)
    }
}

#[pyfunction]
fn protocol_version() -> u8 {
    vecdht_wire::PROTOCOL_VERSION
}

/// Единая точка, откуда Python узнает константы. Держать их копипастой в `vecdht/__init__.py`
/// нельзя: расхождение `dim` или `nlist` между SDK и узлом читается как `MODEL_MISMATCH` (§6.7).
#[pyfunction]
fn constants<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("protocol_version", vecdht_wire::PROTOCOL_VERSION)?;
    d.set_item("dim", vecdht_wire::DIM)?;
    d.set_item("nlist", vecdht_wire::NLIST)?;
    d.set_item("clusters_per_shard", vecdht_wire::CLUSTERS_PER_SHARD)?;
    d.set_item("shards", vecdht_wire::SHARDS)?;
    d.set_item("time_bucket_sec", vecdht_wire::TIME_BUCKET_SEC)?;
    d.set_item("preprocessing_version", vecdht_embed::PREPROCESSING_VERSION)?;
    d.set_item("pow_bits_default", vecdht_crypto::pow::POW_BITS_DEFAULT)?;
    d.set_item("pow_bits_min", vecdht_crypto::pow::POW_BITS_MIN)?;
    d.set_item("pow_bits_max", vecdht_crypto::pow::POW_BITS_MAX)?;
    d.set_item("blake3_mhz_core_fallback", vecdht_crypto::pow::BLAKE3_MHZ_CORE_FALLBACK)?;
    Ok(d)
}

/// Шаг 1 пайплайна: NFKC + trim + collapse, то же, что подписывается (§6.6).
#[pyfunction]
fn normalize(text: &str) -> PyResult<String> {
    vecdht_embed::normalize_text(text).map_err(bad)
}

#[pyfunction]
fn is_canonical(text: &str) -> bool {
    vecdht_embed::is_canonical(text)
}

/// Канонический PoW-вход (§11.1): owner ‖ shard ‖ epoch ‖ slot_key ‖ expires_bucket. `slot_key` —
/// это `intent_id`, а не `entry_key`: агент обязан уметь собрать вход до `PublishAck`.
#[pyfunction]
fn pow_input(
    owner_ed25519_hex: &str,
    shard: u16,
    epoch: u64,
    slot_key_hex: &str,
    expires_bucket: u32,
) -> PyResult<String> {
    let owner = fixed32(unhex(owner_ed25519_hex)?)?;
    let slot = fixed32(unhex(slot_key_hex)?)?;
    Ok(hex::encode(vecdht_crypto::pow::pow_input(&owner, shard, epoch, &slot, expires_bucket)))
}

fn fixed32(b: Vec<u8>) -> PyResult<[u8; 32]> {
    if b.len() != 32 {
        return Err(PyValueError::new_err(format!("ожидалось 32 байта, пришло {}", b.len())));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}

#[pyfunction]
fn pow_verify(input_hex: &str, nonce: u64, bits: u32) -> PyResult<bool> {
    Ok(vecdht_crypto::pow::pow_ok(&unhex(input_hex)?, nonce, bits))
}

/// Перебор nonce с проверкой диапазона внутри `mine_pow`: сложность вне адаптивного диапазона
/// артефакта — это не «чуть дороже», а вход, который узел не примет (§11.2).
#[pyfunction]
#[pyo3(signature = (input_hex, bits, start = 0, max_attempts = 1_000_000))]
fn pow_mine(input_hex: &str, bits: u32, start: u64, max_attempts: u64) -> PyResult<Option<u64>> {
    match vecdht_crypto::pow::mine_pow(&unhex(input_hex)?, bits, start, max_attempts) {
        Ok(n) => Ok(Some(n)),
        Err(vecdht_crypto::pow::PowError::Exhausted(_)) => Ok(None),
        Err(e) => Err(bad(e)),
    }
}

/// Разбор кадра (§5.2): kind, версия, тело и подпись как есть. Никакой структуры кадра Python не
/// собирает и не разбирает сам — иначе второй канонический энкодер гарантирован (§0, строка 10).
#[pyfunction]
fn decode_frame<'py>(py: Python<'py>, frame_hex: &str) -> PyResult<Bound<'py, PyDict>> {
    let bytes = unhex(frame_hex)?;
    let f = vecdht_wire::decode_frame(&bytes).map_err(bad)?;
    let d = PyDict::new(py);
    d.set_item("kind", f.header.kind.name())?;
    d.set_item("version", f.header.version)?;
    d.set_item("body_hex", hex::encode(f.body))?;
    d.set_item("signature_hex", f.signature.map(hex::encode))?;
    Ok(d)
}

#[pymodule]
#[pyo3(name = "vecdht_pyd")]
fn module_(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("PROTOCOL_VERSION", vecdht_wire::PROTOCOL_VERSION)?;
    m.add_class::<PyArtifact>()?;
    m.add_class::<PyAgent>()?;
    m.add_function(wrap_pyfunction!(constants, m)?)?;
    m.add_function(wrap_pyfunction!(protocol_version, m)?)?;
    m.add_function(wrap_pyfunction!(normalize, m)?)?;
    m.add_function(wrap_pyfunction!(is_canonical, m)?)?;
    m.add_function(wrap_pyfunction!(pow_input, m)?)?;
    m.add_function(wrap_pyfunction!(pow_verify, m)?)?;
    m.add_function(wrap_pyfunction!(pow_mine, m)?)?;
    m.add_function(wrap_pyfunction!(decode_frame, m)?)?;
    Ok(())
}
