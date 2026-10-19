//! VecDHT v8 — Python SDK (§17.1): каркас, в котором **нет** протокольной логики.
//!
//! Правило, из которого растёт вся граница этого crate: Python не кодирует ничего. Байтовый
//! кодек кадров (§5), канонический текст и квантование (§6), assign по замороженным центроидам
//! (§7.2) и PoW (§11.1) уже реализованы в `vecdht-{wire,crypto,artifact,embed}` и здесь только
//! проброшены. Дублировать любой из этих шагов на Python означало бы второй источник истины —
//! ровно тот дефект, из-за которого v7.5 с двумя «каноническими» protobuf-энкодерами стал
//! несовместим сам с собой (§0, строка 10).
//!
//! Что каркас сознательно **не** делает:
//!
//! * не поднимает соединение — `Agent.publish/find/session` возвращают `NotImplementedError`.
//!   Транспорт (libp2p QUIC + kad) появляется на P5 (§18.6), relay и сессии — на P6 (§18.7);
//! * не делает инференс — шаг 4 (§6.2) живёт под feature `candle` в `vecdht-embed` и требует
//!   каталога весов. `*_surrogate` функции используют детерминированный оракул `HashModel` из
//!   `vecdht_embed::testing` и называются так именно поэтому: они нужны, чтобы Python-тесты
//!   гоняли весь пайплайн до появления весов, а не чтобы их принимали за настоящую модель.
//!
//! Сборка и проверка — в `Cargo.toml` и `test.py` рядом с этим файлом.

#![forbid(unsafe_code)]

use pyo3::exceptions::{PyNotImplementedError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Один мост между «ошибкой Rust-контракта» и исключением Python. Тип не выбирается по тексту:
/// все провалы валидации в этом crate — про неверные байты, длины или биты, то есть `ValueError`.
/// Отдельный тип нужен только для `NotImplementedError`, и он ставится явно.
fn bad<E: std::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(format!("{e}"))
}

fn unhex(s: &str) -> PyResult<Vec<u8>> {
    hex::decode(s).map_err(bad)
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

/// Класс-каркас агента. Методы существуют, чтобы API можно было зафиксировать и покрыть
/// Python-тестами **до** P5, а не чтобы молча возвращать заглушку, похожую на результат.
#[pyclass(name = "Agent")]
pub struct PyAgent {
    #[pyo3(get)]
    artifact_dir: String,
}

#[pymethods]
impl PyAgent {
    /// `artifact_dir` — каталог артефакта, который агент обязан pinned'ить (§15.1): с другим
    /// `artifact_hash` узел не участвует в matching.
    #[new]
    fn new(artifact_dir: String) -> Self {
        Self { artifact_dir }
    }

    #[pyo3(signature = (text, ttl_sec = None))]
    fn publish(&self, text: &str, ttl_sec: Option<u32>) -> PyResult<String> {
        let _ = (text, ttl_sec);
        Err(PyNotImplementedError::new_err(
            "Agent.publish: транспорт (libp2p QUIC/kad) и publish-рукопожатие делаются на P5 \
             (§18.6); офлайн-половина — Artifact.encode_intent_surrogate + pow_mine — уже здесь",
        ))
    }

    #[pyo3(signature = (text, top_k = 10, nprobe = None))]
    fn find(&self, text: &str, top_k: u16, nprobe: Option<usize>) -> PyResult<Vec<Bound<'_, PyDict>>> {
        let _ = (text, top_k, nprobe);
        Err(PyNotImplementedError::new_err(
            "Agent.find: RPC-обмен с владельцами шардов — P5 (§18.6); число `Find` на запрос \
             (fan-out) можно посчитать уже сейчас через Artifact.encode_query_surrogate",
        ))
    }

    fn session(&self, peer_pubkey_hex: &str) -> PyResult<String> {
        let _ = peer_pubkey_hex;
        Err(PyNotImplementedError::new_err(
            "Agent.session: rendezvous-токен и Noise-сессия — P6 (§18.7)",
        ))
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
