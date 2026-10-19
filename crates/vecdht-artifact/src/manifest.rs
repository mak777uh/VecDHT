//! `manifest.json` — параметры сети, зафиксированные артефактом (спека §15.1, §15.3, приложение B).
//!
//! Это единственное место, где числа из приложения B существуют не в таблице, а как данные:
//! узел, скачавший артефакт, обязан размещать ровно те лимиты, что объявлены в манифесте, иначе
//! два узла «одной версии» расходятся в admission, GC и репликации. Отсюда три правила:
//!
//! 1. байтовая форма манифеста канонична ([`crate::json`]) и именно её подписывает авторитет;
//! 2. параметры сверяются с константами кодека (`DIM`, `NLIST`, `SHARDS`, `MAX_D2`,
//!    `TIME_BUCKET_SEC`, `POW_BITS_*`) — манифест не может «перевзначить» то, что зашито в
//!    `vecdht-wire`, потому что тогда разъедутся байты кадров;
//! 3. неизвестное поле или поле не в порядке схемы — ошибка разбора, а не «игнорируем»: в v7.5
//!    игнорируемое поле и стало причиной расхождения `similarity`.

use vecdht_crypto::pow::{POW_BITS_MAX, POW_BITS_MIN};
use vecdht_wire::cert::MAX_CERT_SHARDS;
use vecdht_wire::codec::DIM;
use vecdht_wire::constants::{CLUSTERS_PER_SHARD, MAX_D2, NLIST, SHARDS, TIME_BUCKET_SEC};
use vecdht_wire::frame::ED25519_SIG_LEN;
use vecdht_wire::messages::MAX_INTENT_TEXT_BYTES;

use crate::json::{field, parse, Json, JsonError};

/// Версия схемы манифеста. Меняется только вместе со способом читать сам манифест.
pub const MANIFEST_SCHEMA: u16 = 1;

pub const DOMAIN_ARTIFACT: &[u8] = b"vecdht/v8/artifact";

const KEYS_TOP: &[&str] = &[
    "schema",
    "model_version",
    "preprocessing_version",
    "model_blake3",
    "tokenizer_blake3",
    "tokenizer_revision",
    "centroid_blake3",
    "pooling",
    "max_length",
    "add_special_tokens",
    "intent_prefix",
    "query_prefix",
    "quant",
    "routing",
    "time",
    "power",
    "admission",
    "replication",
    "index",
    "query",
    "authority",
    "signatures",
];
const KEYS_QUANT: &[&str] = &["dim", "grid", "rounding", "max_d2"];
const KEYS_ROUTING: &[&str] = &["nlist", "clusters_per_shard", "shards", "nprobe_default", "nprobe_allowed"];
const KEYS_TIME: &[&str] = &["bucket_sec", "time_mark_every", "ttl_default_sec", "ttl_max_sec"];
const KEYS_POWER: &[&str] = &["pow_bits_default", "pow_bits_min", "pow_bits_max", "blake3_mhz_core"];
const KEYS_ADMISSION: &[&str] = &[
    "max_live_per_shard",
    "per_peer_publish_rps",
    "per_peer_publish_burst",
    "per_peer_find_rps",
    "node_admits_per_s",
];
const KEYS_REPLICATION: &[&str] = &[
    "r",
    "w",
    "membership_threshold",
    "lease_sec",
    "renew_sec",
    "election_timeout_sec",
    "provider_record_ttl_sec",
    "provider_republish_sec",
];
const KEYS_INDEX: &[&str] = &[
    "snapshot_ops",
    "wal_segment_bytes",
    "wal_group_commit_ms",
    "wal_group_commit_ops",
];
const KEYS_QUERY: &[&str] = &[
    "top_k_default",
    "top_k_max",
    "intent_text_max_bytes",
    "rendezvous_ttl_sec",
    "timestamp_window_sec",
];
const KEYS_AUTHORITY: &[&str] = &["keys", "threshold"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pooling {
    /// CLS-токен (granite-embedding).
    Cls,
    /// Mean-pool по non-pad позициям (fallback-модели семейства BERT).
    MeanNonPad,
}

impl Pooling {
    pub fn as_str(self) -> &'static str {
        match self {
            Pooling::Cls => "cls",
            Pooling::MeanNonPad => "mean_non_pad",
        }
    }
    fn parse(s: &str) -> Result<Self, ManifestError> {
        match s {
            "cls" => Ok(Pooling::Cls),
            "mean_non_pad" => Ok(Pooling::MeanNonPad),
            other => Err(ManifestError::Bad(format!("неизвестный pooling `{other}`"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quant {
    pub dim: u16,
    /// Имя сетки как строка контракта: `i8/127` — то, что реализует `vecdht_crypto::quant`.
    pub grid: String,
    pub rounding: String,
    pub max_d2: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing {
    pub nlist: u16,
    pub clusters_per_shard: u16,
    pub shards: u16,
    pub nprobe_default: u16,
    /// Разрешённые значения `nprobe` для клиента (§7.5: 16 по умолчанию, опции 4 и 32).
    pub nprobe_allowed: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Time {
    pub bucket_sec: u32,
    /// `TimeMark` каждые N применённых опсов (§9.6).
    pub time_mark_every: u32,
    pub ttl_default_sec: u32,
    /// Политический потолок TTL — 24 ч (§13).
    pub ttl_max_sec: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Power {
    pub pow_bits_default: u32,
    pub pow_bits_min: u32,
    pub pow_bits_max: u32,
    /// Измеренная скорость blake3 на ядре, МХеш/с. Целое намеренно: float в манифесте означал бы
    /// расхождение в подписи между платформами (§11.2, калибровка `[P0]`).
    pub blake3_mhz_core: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub max_live_per_shard: u64,
    pub per_peer_publish_rps: u32,
    pub per_peer_publish_burst: u32,
    pub per_peer_find_rps: u32,
    pub node_admits_per_s: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replication {
    pub r: u16,
    pub w: u16,
    /// Порог подписей членства от предыдущего множества (§9.2).
    pub membership_threshold: u16,
    pub lease_sec: u32,
    pub renew_sec: u32,
    pub election_timeout_sec: u32,
    pub provider_record_ttl_sec: u32,
    pub provider_republish_sec: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexParams {
    pub snapshot_ops: u64,
    pub wal_segment_bytes: u64,
    pub wal_group_commit_ms: u32,
    pub wal_group_commit_ops: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryParams {
    pub top_k_default: u16,
    pub top_k_max: u16,
    pub intent_text_max_bytes: u32,
    pub rendezvous_ttl_sec: u32,
    pub timestamp_window_sec: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    /// Публичные ключи bootstrap-авторитета, 32 байта каждый (hex в манифесте).
    pub keys: Vec<[u8; 32]>,
    pub threshold: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub schema: u16,
    pub model_version: String,
    pub preprocessing_version: u16,
    pub model_blake3: [u8; 32],
    pub tokenizer_blake3: [u8; 32],
    /// Pin пересборки tokenizer'а: revision HF вместе с хешем файла.
    pub tokenizer_revision: String,
    pub centroid_blake3: [u8; 32],
    pub pooling: Pooling,
    pub max_length: u32,
    pub add_special_tokens: bool,
    /// Префикс индексируемого интента — пустой (§6.6: интенты без префикса).
    pub intent_prefix: String,
    /// Карточный query-префикс модели, дословно.
    pub query_prefix: String,
    pub quant: Quant,
    pub routing: Routing,
    pub time: Time,
    pub power: Power,
    pub admission: Admission,
    pub replication: Replication,
    pub index: IndexParams,
    pub query: QueryParams,
    pub authority: Authority,
    pub signatures: Vec<[u8; ED25519_SIG_LEN]>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest: {0}")]
    Json(#[from] JsonError),
    #[error("manifest: секция `{section}` ждёт ключи {want:?}, найдено {got:?}")]
    Keys {
        section: &'static str,
        want: Vec<String>,
        got: Vec<String>,
    },
    #[error("manifest: поле `{field}` отсутствует или имеет не тот тип")]
    Field { field: &'static str },
    #[error("manifest: `{field}` = {value} вне допустимого [{min}; {max}]")]
    Range {
        field: &'static str,
        value: i128,
        min: i128,
        max: i128,
    },
    #[error("manifest: hex-поле `{field}` не читается ({detail})")]
    Hex { field: &'static str, detail: String },
    #[error("manifest: `{field}` = {actual}, а кодек говорит {expected}")]
    CodecMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    #[error("manifest: {0}")]
    Bad(String),
}

impl ManifestError {
    fn field(f: &'static str) -> Self {
        ManifestError::Field { field: f }
    }
    fn range(f: &'static str, v: i64, min: i64, max: i64) -> Self {
        ManifestError::Range { field: f, value: v as i128, min: min as i128, max: max as i128 }
    }
}

// ---------------------------------------------------------------- accessors --

/// Проверка, что объект содержит ровно `want` ключей и именно в этом порядке. Порядок — часть
/// канонической формы, поэтому «просто unknown field» здесь тоже ошибка порядка.
fn check_keys(obj: &Json, section: &'static str, want: &[&str]) -> Result<(), ManifestError> {
    let got: Vec<&str> = match obj {
        Json::Obj(fields) => fields.iter().map(|(k, _)| k.as_str()).collect(),
        _ => return Err(ManifestError::Bad(format!("секция `{section}` — не объект"))),
    };
    if got != want {
        return Err(ManifestError::Keys {
            section,
            want: want.iter().map(|s| s.to_string()).collect(),
            got: got.iter().map(|s| s.to_string()).collect(),
        });
    }
    Ok(())
}

fn value<'a>(obj: &'a Json, name: &'static str) -> Result<&'a Json, ManifestError> {
    field(obj, name).map_err(|_| ManifestError::field(name))
}

fn i64_of(obj: &Json, name: &'static str, min: i64, max: i64) -> Result<i64, ManifestError> {
    let v = value(obj, name)?
        .as_int()
        .ok_or(ManifestError::field(name))?;
    if v < min || v > max {
        return Err(ManifestError::range(name, v, min, max));
    }
    Ok(v)
}

fn str_of(obj: &Json, name: &'static str) -> Result<String, ManifestError> {
    value(obj, name)?
        .as_str()
        .map(|s| s.to_string())
        .ok_or(ManifestError::field(name))
}

fn bool_of(obj: &Json, name: &'static str) -> Result<bool, ManifestError> {
    match value(obj, name)? {
        Json::Bool(b) => Ok(*b),
        _ => Err(ManifestError::field(name)),
    }
}

/// Фиксированная длина hex-поля: `blake3` — 32 байта, подпись — 64. Строковой дамп хеша короче
/// или длиннее быть не может, это отдельная ошибка от «не hex».
/// Строка → `[u8; N]` в единственно канонической форме: ровно `2N` символов `[0-9a-f]`.
///
/// `hex::decode` принимает и заглавные, а `hex::encode` всегда отдаёт строчные. Если бы разбор
/// пропускал `0A…`, такой манифест пересобрался бы другими байтами: подпись под «тем же значением,
/// но иными байтами» — это две разные подписи под двумя разными документами, и расхождение
/// вспыхнуло бы там, где его никто не ждал. Фаззер `tests/fuzz_decode.rs` ловит этот класс.
fn hex_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        // Значение поля в сообщение не тащим: оно может быть не-UTF-8-подобным мусором из
        // фаззера, а ошибка уходит в лог узла.
        let found = if s.len() > 80 { "…" } else { s };
        return Err(format!(
            "ожидалось {want} строчных hex-символов, найдено `{found}`",
            want = 2 * N
        ));
    }
    let mut out = [0u8; N];
    /// Полусимвол уже валидирован предшествующей проверкой, так что разбора «как-нибудь» нет.
    fn nib(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            _ => b - b'a' + 10,
        }
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (nib(s.as_bytes()[2 * i]) << 4) | nib(s.as_bytes()[2 * i + 1]);
    }
    Ok(out)
}

fn hex_of<const N: usize>(obj: &Json, name: &'static str) -> Result<[u8; N], ManifestError> {
    let s = str_of(obj, name)?;
    hex_fixed::<N>(&s).map_err(|detail| ManifestError::Hex { field: name, detail })
}

fn u16_list_of(obj: &Json, name: &'static str) -> Result<Vec<u16>, ManifestError> {
    let items = value(obj, name)?
        .as_arr()
        .ok_or(ManifestError::field(name))?;
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        let v = it
            .as_int()
            .ok_or_else(|| ManifestError::Bad(format!("`{name}`: элемент не целое")))?;
        out.push(u16::try_from(v).map_err(|_| ManifestError::range(name, v, 0, u16::MAX as i64))?);
    }
    Ok(out)
}

// --------------------------------------------------------------- conversion --

impl Quant {
    fn to_json(&self) -> Json {
        Json::obj(vec![
            ("dim", Some(Json::int(self.dim as i64))),
            ("grid", Some(Json::string(self.grid.clone()))),
            ("rounding", Some(Json::string(self.rounding.clone()))),
            ("max_d2", Some(Json::int(self.max_d2 as i64))),
        ])
    }
    fn from_json(obj: &Json) -> Result<Self, ManifestError> {
        check_keys(obj, "quant", KEYS_QUANT)?;
        Ok(Quant {
            dim: i64_of(obj, "dim", 1, u16::MAX as i64)? as u16,
            grid: str_of(obj, "grid")?,
            rounding: str_of(obj, "rounding")?,
            max_d2: i64_of(obj, "max_d2", 1, u32::MAX as i64)? as u32,
        })
    }
}

impl Routing {
    fn to_json(&self) -> Json {
        Json::obj(vec![
            ("nlist", Some(Json::int(self.nlist as i64))),
            ("clusters_per_shard", Some(Json::int(self.clusters_per_shard as i64))),
            ("shards", Some(Json::int(self.shards as i64))),
            ("nprobe_default", Some(Json::int(self.nprobe_default as i64))),
            (
                "nprobe_allowed",
                Some(Json::Arr(
                    self.nprobe_allowed.iter().map(|v| Json::int(*v as i64)).collect(),
                )),
            ),
        ])
    }
    fn from_json(obj: &Json) -> Result<Self, ManifestError> {
        check_keys(obj, "routing", KEYS_ROUTING)?;
        Ok(Routing {
            nlist: i64_of(obj, "nlist", 1, u16::MAX as i64)? as u16,
            clusters_per_shard: i64_of(obj, "clusters_per_shard", 1, u16::MAX as i64)? as u16,
            shards: i64_of(obj, "shards", 1, u16::MAX as i64)? as u16,
            nprobe_default: i64_of(obj, "nprobe_default", 1, u16::MAX as i64)? as u16,
            nprobe_allowed: u16_list_of(obj, "nprobe_allowed")?,
        })
    }
}

impl Time {
    fn to_json(&self) -> Json {
        Json::obj(vec![
            ("bucket_sec", Some(Json::int(self.bucket_sec as i64))),
            ("time_mark_every", Some(Json::int(self.time_mark_every as i64))),
            ("ttl_default_sec", Some(Json::int(self.ttl_default_sec as i64))),
            ("ttl_max_sec", Some(Json::int(self.ttl_max_sec as i64))),
        ])
    }
    fn from_json(obj: &Json) -> Result<Self, ManifestError> {
        check_keys(obj, "time", KEYS_TIME)?;
        Ok(Time {
            bucket_sec: i64_of(obj, "bucket_sec", 1, u32::MAX as i64)? as u32,
            time_mark_every: i64_of(obj, "time_mark_every", 1, u32::MAX as i64)? as u32,
            ttl_default_sec: i64_of(obj, "ttl_default_sec", 1, u32::MAX as i64)? as u32,
            ttl_max_sec: i64_of(obj, "ttl_max_sec", 1, u32::MAX as i64)? as u32,
        })
    }
}

impl Power {
    fn to_json(&self) -> Json {
        Json::obj(vec![
            ("pow_bits_default", Some(Json::int(self.pow_bits_default as i64))),
            ("pow_bits_min", Some(Json::int(self.pow_bits_min as i64))),
            ("pow_bits_max", Some(Json::int(self.pow_bits_max as i64))),
            ("blake3_mhz_core", Some(Json::int(self.blake3_mhz_core as i64))),
        ])
    }
    fn from_json(obj: &Json) -> Result<Self, ManifestError> {
        check_keys(obj, "power", KEYS_POWER)?;
        Ok(Power {
            pow_bits_default: i64_of(obj, "pow_bits_default", 1, 64)? as u32,
            pow_bits_min: i64_of(obj, "pow_bits_min", 1, 64)? as u32,
            pow_bits_max: i64_of(obj, "pow_bits_max", 1, 64)? as u32,
            blake3_mhz_core: i64_of(obj, "blake3_mhz_core", 1, u32::MAX as i64)? as u32,
        })
    }
}

impl Admission {
    fn to_json(&self) -> Json {
        Json::obj(vec![
            ("max_live_per_shard", Some(Json::int(self.max_live_per_shard as i64))),
            ("per_peer_publish_rps", Some(Json::int(self.per_peer_publish_rps as i64))),
            ("per_peer_publish_burst", Some(Json::int(self.per_peer_publish_burst as i64))),
            ("per_peer_find_rps", Some(Json::int(self.per_peer_find_rps as i64))),
            ("node_admits_per_s", Some(Json::int(self.node_admits_per_s as i64))),
        ])
    }
    fn from_json(obj: &Json) -> Result<Self, ManifestError> {
        check_keys(obj, "admission", KEYS_ADMISSION)?;
        Ok(Admission {
            max_live_per_shard: i64_of(obj, "max_live_per_shard", 1, i64::MAX)? as u64,
            per_peer_publish_rps: i64_of(obj, "per_peer_publish_rps", 1, u32::MAX as i64)? as u32,
            per_peer_publish_burst: i64_of(obj, "per_peer_publish_burst", 1, u32::MAX as i64)?
                as u32,
            per_peer_find_rps: i64_of(obj, "per_peer_find_rps", 1, u32::MAX as i64)? as u32,
            node_admits_per_s: i64_of(obj, "node_admits_per_s", 1, u32::MAX as i64)? as u32,
        })
    }
}

impl Replication {
    fn to_json(&self) -> Json {
        Json::obj(vec![
            ("r", Some(Json::int(self.r as i64))),
            ("w", Some(Json::int(self.w as i64))),
            ("membership_threshold", Some(Json::int(self.membership_threshold as i64))),
            ("lease_sec", Some(Json::int(self.lease_sec as i64))),
            ("renew_sec", Some(Json::int(self.renew_sec as i64))),
            ("election_timeout_sec", Some(Json::int(self.election_timeout_sec as i64))),
            ("provider_record_ttl_sec", Some(Json::int(self.provider_record_ttl_sec as i64))),
            ("provider_republish_sec", Some(Json::int(self.provider_republish_sec as i64))),
        ])
    }
    fn from_json(obj: &Json) -> Result<Self, ManifestError> {
        check_keys(obj, "replication", KEYS_REPLICATION)?;
        Ok(Replication {
            r: i64_of(obj, "r", 1, 16)? as u16,
            w: i64_of(obj, "w", 1, 16)? as u16,
            membership_threshold: i64_of(obj, "membership_threshold", 1, 16)? as u16,
            lease_sec: i64_of(obj, "lease_sec", 1, u32::MAX as i64)? as u32,
            renew_sec: i64_of(obj, "renew_sec", 1, u32::MAX as i64)? as u32,
            election_timeout_sec: i64_of(obj, "election_timeout_sec", 1, u32::MAX as i64)? as u32,
            provider_record_ttl_sec: i64_of(obj, "provider_record_ttl_sec", 1, u32::MAX as i64)?
                as u32,
            provider_republish_sec: i64_of(obj, "provider_republish_sec", 1, u32::MAX as i64)?
                as u32,
        })
    }
}

impl IndexParams {
    fn to_json(&self) -> Json {
        Json::obj(vec![
            ("snapshot_ops", Some(Json::int(self.snapshot_ops as i64))),
            ("wal_segment_bytes", Some(Json::int(self.wal_segment_bytes as i64))),
            ("wal_group_commit_ms", Some(Json::int(self.wal_group_commit_ms as i64))),
            ("wal_group_commit_ops", Some(Json::int(self.wal_group_commit_ops as i64))),
        ])
    }
    fn from_json(obj: &Json) -> Result<Self, ManifestError> {
        check_keys(obj, "index", KEYS_INDEX)?;
        Ok(IndexParams {
            snapshot_ops: i64_of(obj, "snapshot_ops", 1, i64::MAX)? as u64,
            wal_segment_bytes: i64_of(obj, "wal_segment_bytes", 1024, i64::MAX)? as u64,
            wal_group_commit_ms: i64_of(obj, "wal_group_commit_ms", 0, u32::MAX as i64)? as u32,
            wal_group_commit_ops: i64_of(obj, "wal_group_commit_ops", 1, u32::MAX as i64)? as u32,
        })
    }
}

impl QueryParams {
    fn to_json(&self) -> Json {
        Json::obj(vec![
            ("top_k_default", Some(Json::int(self.top_k_default as i64))),
            ("top_k_max", Some(Json::int(self.top_k_max as i64))),
            ("intent_text_max_bytes", Some(Json::int(self.intent_text_max_bytes as i64))),
            ("rendezvous_ttl_sec", Some(Json::int(self.rendezvous_ttl_sec as i64))),
            ("timestamp_window_sec", Some(Json::int(self.timestamp_window_sec as i64))),
        ])
    }
    fn from_json(obj: &Json) -> Result<Self, ManifestError> {
        check_keys(obj, "query", KEYS_QUERY)?;
        Ok(QueryParams {
            top_k_default: i64_of(obj, "top_k_default", 1, u16::MAX as i64)? as u16,
            top_k_max: i64_of(obj, "top_k_max", 1, u16::MAX as i64)? as u16,
            intent_text_max_bytes: i64_of(obj, "intent_text_max_bytes", 1, u32::MAX as i64)? as u32,
            rendezvous_ttl_sec: i64_of(obj, "rendezvous_ttl_sec", 1, u32::MAX as i64)? as u32,
            timestamp_window_sec: i64_of(obj, "timestamp_window_sec", 1, u32::MAX as i64)? as u32,
        })
    }
}

impl Authority {
    fn to_json(&self) -> Json {
        Json::obj(vec![
            (
                "keys",
                Some(Json::Arr(
                    self.keys
                        .iter()
                        .map(|k| Json::string(hex::encode(k)))
                        .collect(),
                )),
            ),
            ("threshold", Some(Json::int(self.threshold as i64))),
        ])
    }
    fn from_json(obj: &Json) -> Result<Self, ManifestError> {
        check_keys(obj, "authority", KEYS_AUTHORITY)?;
        let items = value(obj, "keys")?
            .as_arr()
            .ok_or(ManifestError::field("keys"))?;
        let mut keys = Vec::with_capacity(items.len());
        for (i, it) in items.iter().enumerate() {
            let s = it
                .as_str()
                .ok_or_else(|| ManifestError::Bad(format!("authority.keys[{i}] — не строка")))?;
            let k: [u8; 32] = hex_fixed::<32>(s).map_err(|detail| ManifestError::Hex {
                field: "authority.keys",
                detail: format!("ключ #{i}: {detail}"),
            })?;
            keys.push(k);
        }
        Ok(Authority {
            keys,
            threshold: i64_of(obj, "threshold", 1, 16)? as u16,
        })
    }
}

impl Manifest {
    /// Канонические байты без подписей — ровно это подписывает авторитет (§14.5: 3-of-5 поверх
    /// параметров, подпись не может быть частью собственного материала).
    pub fn unsigned_json(&self) -> Vec<u8> {
        self.build(false).render()
    }

    /// Полный манифест: те же байты плюс ключ `signatures`.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        self.build(true).render()
    }

    fn build(&self, with_sigs: bool) -> Json {
        let mut fields: Vec<(&str, Option<Json>)> = vec![
            ("schema", Some(Json::int(self.schema as i64))),
            ("model_version", Some(Json::string(self.model_version.clone()))),
            ("preprocessing_version", Some(Json::int(self.preprocessing_version as i64))),
            ("model_blake3", Some(Json::string(hex::encode(self.model_blake3)))),
            ("tokenizer_blake3", Some(Json::string(hex::encode(self.tokenizer_blake3)))),
            ("tokenizer_revision", Some(Json::string(self.tokenizer_revision.clone()))),
            ("centroid_blake3", Some(Json::string(hex::encode(self.centroid_blake3)))),
            ("pooling", Some(Json::string(self.pooling.as_str()))),
            ("max_length", Some(Json::int(self.max_length as i64))),
            ("add_special_tokens", Some(Json::bool(self.add_special_tokens))),
            ("intent_prefix", Some(Json::string(self.intent_prefix.clone()))),
            ("query_prefix", Some(Json::string(self.query_prefix.clone()))),
            ("quant", Some(self.quant.to_json())),
            ("routing", Some(self.routing.to_json())),
            ("time", Some(self.time.to_json())),
            ("power", Some(self.power.to_json())),
            ("admission", Some(self.admission.to_json())),
            ("replication", Some(self.replication.to_json())),
            ("index", Some(self.index.to_json())),
            ("query", Some(self.query.to_json())),
            ("authority", Some(self.authority.to_json())),
        ];
        if with_sigs {
            fields.push((
                "signatures",
                Some(Json::Arr(
                    self.signatures
                        .iter()
                        .map(|s| Json::string(hex::encode(s)))
                        .collect(),
                )),
            ));
        }
        Json::Obj(fields.into_iter().filter_map(|(k, v)| v.map(|v| (k.to_string(), v))).collect())
    }

    /// Разбор канонических байтов. Нестрогая форма (пробелы, дубли, другой порядок) отвергается,
    /// потому что такие байты не сошлись бы ни с подписью, ни с хешем у соседа.
    pub fn decode(bytes: &[u8]) -> Result<Manifest, ManifestError> {
        let doc = parse(bytes)?;
        check_keys(&doc, "manifest", KEYS_TOP)?;
        let m = Manifest {
            schema: i64_of(&doc, "schema", 1, u16::MAX as i64)? as u16,
            model_version: str_of(&doc, "model_version")?,
            preprocessing_version: i64_of(&doc, "preprocessing_version", 0, u16::MAX as i64)?
                as u16,
            model_blake3: hex_of(&doc, "model_blake3")?,
            tokenizer_blake3: hex_of(&doc, "tokenizer_blake3")?,
            tokenizer_revision: str_of(&doc, "tokenizer_revision")?,
            centroid_blake3: hex_of(&doc, "centroid_blake3")?,
            pooling: Pooling::parse(&str_of(&doc, "pooling")?)?,
            max_length: i64_of(&doc, "max_length", 1, u32::MAX as i64)? as u32,
            add_special_tokens: bool_of(&doc, "add_special_tokens")?,
            intent_prefix: str_of(&doc, "intent_prefix")?,
            query_prefix: str_of(&doc, "query_prefix")?,
            quant: Quant::from_json(value(&doc, "quant")?)?,
            routing: Routing::from_json(value(&doc, "routing")?)?,
            time: Time::from_json(value(&doc, "time")?)?,
            power: Power::from_json(value(&doc, "power")?)?,
            admission: Admission::from_json(value(&doc, "admission")?)?,
            replication: Replication::from_json(value(&doc, "replication")?)?,
            index: IndexParams::from_json(value(&doc, "index")?)?,
            query: QueryParams::from_json(value(&doc, "query")?)?,
            authority: Authority::from_json(value(&doc, "authority")?)?,
            signatures: {
                let items = value(&doc, "signatures")?
                    .as_arr()
                    .ok_or(ManifestError::field("signatures"))?;
                let mut v = Vec::with_capacity(items.len());
                for (i, it) in items.iter().enumerate() {
                    let s = it.as_str().ok_or_else(|| {
                        ManifestError::Bad(format!("signatures[{i}] — не строка"))
                    })?;
                    let sig: [u8; 64] = hex_fixed::<64>(s).map_err(|detail| ManifestError::Hex {
                        field: "signatures",
                        detail: format!("подпись #{i}: {detail}"),
                    })?;
                    v.push(sig);
                }
                v
            },
        };
        m.check()?;
        // Финальная сверка каноничности: разбор обязан быть обратим байт в байт. Поэлементные
        // проверки (порядок ключей, строчный hex, целые числа) закрывают известные случаи, а это
        // условие закрывает весь класс «значение то же, байты другие» — в частности то, что
        // обнаружил фаззер: заглавную букву в hex-поле `hex::decode` принимал.
        let again = m.to_json_bytes();
        if again != bytes {
            return Err(ManifestError::Bad(
                "манифест пересобрался не в свои байты: вход не в канонической форме".into(),
            ));
        }
        Ok(m)
    }

    /// Сверка с константами кодека и внутренняя согласованность (§15.3).
    pub fn check(&self) -> Result<(), ManifestError> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(ManifestError::Bad(format!("неизвестная схема манифеста {}", self.schema)));
        }
        if self.model_version.is_empty() {
            return Err(ManifestError::field("model_version"));
        }
        if self.tokenizer_revision.is_empty() {
            return Err(ManifestError::field("tokenizer_revision"));
        }
        let mismatch = |field: &'static str, expected: u64, actual: u64| {
            Err(ManifestError::CodecMismatch { field, expected, actual })
        };
        if self.quant.dim as u64 != DIM as u64 {
            return mismatch("quant.dim", DIM as u64, self.quant.dim as u64);
        }
        if self.quant.max_d2 != MAX_D2 {
            return mismatch("quant.max_d2", MAX_D2 as u64, self.quant.max_d2 as u64);
        }
        if self.quant.grid != "i8/127" {
            return Err(ManifestError::Bad(format!("сетка `{}` не i8/127", self.quant.grid)));
        }
        if self.quant.rounding != "half_away" {
            return Err(ManifestError::Bad(format!(
                "округление `{}` не half_away",
                self.quant.rounding
            )));
        }
        if self.routing.nlist != NLIST {
            return mismatch("routing.nlist", NLIST as u64, self.routing.nlist as u64);
        }
        if self.routing.clusters_per_shard != CLUSTERS_PER_SHARD {
            return mismatch(
                "routing.clusters_per_shard",
                CLUSTERS_PER_SHARD as u64,
                self.routing.clusters_per_shard as u64,
            );
        }
        if self.routing.shards != SHARDS {
            return mismatch("routing.shards", SHARDS as u64, self.routing.shards as u64);
        }
        if u64::from(self.routing.nlist)
            != u64::from(self.routing.clusters_per_shard) * u64::from(self.routing.shards)
        {
            return Err(ManifestError::Bad(
                "nlist != clusters_per_shard * shards: разбиение кластеров не полное".into(),
            ));
        }
        if self.routing.nprobe_allowed.is_empty() {
            return Err(ManifestError::field("routing.nprobe_allowed"));
        }
        if !self.routing.nprobe_allowed.contains(&self.routing.nprobe_default) {
            return Err(ManifestError::Bad(format!(
                "nprobe_default {} вне разрешённого {:?}",
                self.routing.nprobe_default, self.routing.nprobe_allowed
            )));
        }
        if self.routing.nprobe_allowed.windows(2).any(|w| w[0] >= w[1]) {
            return Err(ManifestError::Bad("nprobe_allowed обязан быть строго возрастающим".into()));
        }
        if u64::from(self.routing.nprobe_default) > u64::from(self.routing.nlist) {
            return Err(ManifestError::Bad("nprobe больше nlist".into()));
        }
        if self.time.bucket_sec != TIME_BUCKET_SEC {
            return mismatch("time.bucket_sec", TIME_BUCKET_SEC as u64, self.time.bucket_sec as u64);
        }
        for (name, v) in [
            ("time.ttl_default_sec", self.time.ttl_default_sec),
            ("time.ttl_max_sec", self.time.ttl_max_sec),
        ] {
            if v % self.time.bucket_sec != 0 {
                return Err(ManifestError::Bad(format!(
                    "{name} = {v} не кратно бакету {}",
                    self.time.bucket_sec
                )));
            }
            // Поле `ttl_buckets` в кадре — u16 бакетов (§8.2); артефакт не вправе обещать больше.
            if v / self.time.bucket_sec > u16::MAX as u32 {
                return Err(ManifestError::Bad(format!(
                    "{name} = {v} не выражается в u16 бакетах"
                )));
            }
        }
        if self.time.ttl_default_sec > self.time.ttl_max_sec {
            return Err(ManifestError::Bad("TTL по умолчанию больше политического потолка".into()));
        }
        if self.time.time_mark_every == 0 {
            return Err(ManifestError::field("time.time_mark_every"));
        }
        if self.power.pow_bits_min != POW_BITS_MIN
            || self.power.pow_bits_max != POW_BITS_MAX
            || !(self.power.pow_bits_min..=self.power.pow_bits_max)
                .contains(&self.power.pow_bits_default)
        {
            return Err(ManifestError::Bad(format!(
                "диапазон PoW {}/{}/{} вне [{POW_BITS_MIN}; {POW_BITS_MAX}]",
                self.power.pow_bits_default, self.power.pow_bits_min, self.power.pow_bits_max
            )));
        }
        if self.replication.w > self.replication.r {
            return Err(ManifestError::Bad("W > R: кворум нельзя собрать".into()));
        }
        if self.replication.membership_threshold > self.replication.r {
            return Err(ManifestError::Bad("порог членства больше состава шарда".into()));
        }
        if self.replication.renew_sec >= self.replication.lease_sec
            || self.replication.election_timeout_sec <= self.replication.renew_sec
        {
            return Err(ManifestError::Bad(
                "lease/renew/election обязаны идти возрастающей цепочкой renew < lease ≤ election".into(),
            ));
        }
        if self.replication.provider_republish_sec >= self.replication.provider_record_ttl_sec {
            return Err(ManifestError::Bad("републикация позже истечения provider record".into()));
        }
        if self.admission.per_peer_publish_burst < self.admission.per_peer_publish_rps {
            return Err(ManifestError::Bad("burst меньше скорости — квота недоступна в принципе".into()));
        }
        if self.query.top_k_default > self.query.top_k_max {
            return Err(ManifestError::Bad("top_k_default больше top_k_max".into()));
        }
        if self.query.intent_text_max_bytes as usize > MAX_INTENT_TEXT_BYTES {
            return mismatch(
                "query.intent_text_max_bytes",
                MAX_INTENT_TEXT_BYTES as u64,
                self.query.intent_text_max_bytes as u64,
            );
        }
        if self.authority.keys.is_empty() || self.authority.threshold == 0 {
            return Err(ManifestError::field("authority"));
        }
        if self.authority.threshold > self.authority.keys.len() as u16 {
            return Err(ManifestError::Bad(format!(
                "порог {} больше числа ключей авторитета",
                self.authority.threshold
            )));
        }
        let mut sorted = self.authority.keys.clone();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return Err(ManifestError::Bad("дублирующийся ключ авторитета".into()));
        }
        if self.signatures.len() > crate::MAX_ARTIFACT_SIGS {
            return Err(ManifestError::Bad(format!(
                "подписей больше предела {}",
                crate::MAX_ARTIFACT_SIGS
            )));
        }
        if self.max_length == 0 {
            return Err(ManifestError::field("max_length"));
        }
        if self.query_prefix.len() > MAX_INTENT_TEXT_BYTES || self.intent_prefix.len() > MAX_INTENT_TEXT_BYTES {
            return Err(ManifestError::Bad("префикс длиннее лимита текста".into()));
        }
        // M при 424 Б на запись: 1e9 записей — это 424 ГБ на один шард. Дальше параметр
        // перестаёт означать что-либо физическое и `shard_bytes_budget` начинает переполняться.
        if self.admission.max_live_per_shard > 1_000_000_000 {
            return Err(ManifestError::Bad(
                "max_live_per_shard больше 1e9 — байтовый бюджет не выражается в u64".into(),
            ));
        }
        if self.routing.shards as usize > MAX_CERT_SHARDS {
            return mismatch(
                "routing.shards",
                MAX_CERT_SHARDS as u64,
                self.routing.shards as u64,
            );
        }
        Ok(())
    }

    /// Число записей, которое артефакт разрешает держать в одном шарде, в байтах int8-векторов —
    /// проверка «≤ 450 МБ» гейта P3 считается отсюда, а не от комментария в спеке.
    pub fn shard_bytes_budget(&self) -> u64 {
        // 384 байта вектора + 40 байт метаданных `IndexEntry` (§8.2: 424 Б на запись).
        self.admission.max_live_per_shard * (DIM as u64 + 40)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_manifest;

    #[test]
    fn reference_manifest_is_canonical_and_valid() {
        let m = reference_manifest();
        m.check().expect("эталонный манифест не проходит сверку");
        let bytes = m.to_json_bytes();
        let back = Manifest::decode(&bytes).expect("канонические байты не читаются");
        assert_eq!(back, m, "round-trip изменил манифест");
        assert_eq!(back.to_json_bytes(), bytes);
    }

    #[test]
    fn unsigned_and_signed_bytes_differ_only_by_signatures() {
        let mut m = reference_manifest();
        m.signatures.clear();
        let unsigned = m.unsigned_json();
        let signed = m.to_json_bytes();
        assert_ne!(unsigned, signed);
        assert!(String::from_utf8(signed).unwrap().contains("\"signatures\":[]"));
        // Подписываемый материал не содержит подписей: иначе подпись зависела бы от себя.
        assert!(!String::from_utf8(unsigned.clone()).unwrap().contains("signatures"));
        assert!(unsigned.starts_with(b"{\"schema\":1,"));
    }

    #[test]
    fn non_canonical_bytes_rejected() {
        let m = reference_manifest();
        let bytes = m.to_json_bytes();
        // Пробел после двоеточия — синтаксически JSON, байтово — уже не тот документ.
        let mut spaced = Vec::new();
        spaced.extend_from_slice(b"{ ");
        spaced.extend_from_slice(&bytes[1..]);
        assert!(Manifest::decode(&spaced).is_err());
        assert!(Manifest::decode(&m.unsigned_json()).is_err(), "байты без подписей читаются как полный манифест");
    }

    #[test]
    fn unknown_or_reordered_key_rejected() {
        let text = String::from_utf8(reference_manifest().to_json_bytes()).unwrap();
        assert!(Manifest::decode(text.as_bytes()).is_ok(), "эталонный текст не читается");
        // Неизвестное поле в конце.
        let extra = text.replacen("\"signatures\":[", "\"max_d2\":1,\"signatures\":[", 1);
        assert_ne!(extra, text, "ключ signatures не найден в сериализации");
        assert!(Manifest::decode(extra.as_bytes()).is_err(), "неизвестное поле принято");
        // Тот же набор ключей, но `schema` переехал с первого места перед `signatures`.
        // Порядок фиксирован таблицей, поэтому перестановка — ошибка, а не «то же самое».
        let moved = text
            .replacen("{\"schema\":1,", "{", 1)
            .replacen(",\"signatures\":[", ",\"schema\":1,\"signatures\":[", 1);
        assert_ne!(moved, text, "перестановка не изменила текст");
        assert_eq!(moved.len(), text.len(), "перестановка обязана сохранять набор байтов");
        assert!(matches!(
            Manifest::decode(moved.as_bytes()),
            Err(ManifestError::Keys { section: "manifest", .. })
        ));
    }

    #[test]
    fn duplicate_key_rejected() {
        let text = String::from_utf8(reference_manifest().to_json_bytes()).unwrap();
        let dup = text.replacen("\"schema\":1,", "\"schema\":1,\"schema\":1,", 1);
        assert!(matches!(
            Manifest::decode(dup.as_bytes()),
            Err(ManifestError::Json(JsonError::DuplicateKey(_)))
        ));
    }

    #[test]
    fn codec_mismatch_is_an_error_not_a_redefinition() {
        let mut m = reference_manifest();
        m.quant.dim = 256;
        assert!(matches!(
            m.check(),
            Err(ManifestError::CodecMismatch { field: "quant.dim", expected: 384, actual: 256 })
        ));

        let mut m = reference_manifest();
        m.time.bucket_sec = 15;
        assert!(matches!(
            m.check(),
            Err(ManifestError::CodecMismatch { field: "time.bucket_sec", .. })
        ));

        let mut m = reference_manifest();
        m.routing.shards = 32;
        assert!(matches!(m.check(), Err(ManifestError::CodecMismatch { .. })));
    }

    #[test]
    fn semantic_checks_reject_impossible_parameters() {
        let mut m = reference_manifest();
        m.time.ttl_default_sec = 3601;
        assert!(format!("{}", m.check().unwrap_err()).contains("не кратно бакету"));

        let mut m = reference_manifest();
        m.time.ttl_max_sec = 86_400;
        m.time.ttl_default_sec = 100_000;
        assert!(format!("{}", m.check().unwrap_err()).contains("политического потолка"));

        let mut m = reference_manifest();
        m.routing.nprobe_default = 8;
        assert!(format!("{}", m.check().unwrap_err()).contains("вне разрешённого"));

        let mut m = reference_manifest();
        m.replication.w = 4;
        assert!(format!("{}", m.check().unwrap_err()).contains("W > R"));

        let mut m = reference_manifest();
        m.replication.renew_sec = 120;
        assert!(format!("{}", m.check().unwrap_err()).contains("lease/renew/election"));

        let mut m = reference_manifest();
        m.authority.threshold = 6;
        assert!(format!("{}", m.check().unwrap_err()).contains("числа ключей"));

        let mut m = reference_manifest();
        m.authority.keys.push(m.authority.keys[0]);
        assert!(format!("{}", m.check().unwrap_err()).contains("дублирующи"));

        let mut m = reference_manifest();
        m.query.intent_text_max_bytes = MAX_INTENT_TEXT_BYTES as u32 + 1;
        assert!(matches!(m.check(), Err(ManifestError::CodecMismatch { .. })));

        let mut m = reference_manifest();
        m.quant.grid = "f32".into();
        assert!(format!("{}", m.check().unwrap_err()).contains("не i8/127"));

        let mut m = reference_manifest();
        m.power.pow_bits_default = 20;
        assert!(format!("{}", m.check().unwrap_err()).contains("диапазон PoW"));
    }

    #[test]
    fn hex_fields_are_fixed_length() {
        let text = String::from_utf8(reference_manifest().to_json_bytes()).unwrap();
        // Замена привязана к ключу: в референсном манифесте оба хешa — нули, и глобальная
        // замена по значениям тронула бы всегда одно и то же поле.
        let scope = |key: &str, value: &str| {
            text.replacen(
                &format!("\"{key}\":\"{}\"", hex::encode([0u8; 32])),
                &format!("\"{key}\":\"{value}\""),
                1,
            )
        };
        let short = scope("model_blake3", "deadbeef");
        assert_ne!(short, text, "ключ model_blake3 не найден в сериализации");
        assert!(matches!(
            Manifest::decode(short.as_bytes()),
            Err(ManifestError::Hex { field: "model_blake3", .. })
        ));
        let not_hex = scope("centroid_blake3", &"z".repeat(64));
        assert_ne!(not_hex, text, "ключ centroid_blake3 не найден в сериализации");
        assert!(matches!(
            Manifest::decode(not_hex.as_bytes()),
            Err(ManifestError::Hex { field: "centroid_blake3", .. })
        ));
    }

    #[test]
    fn uppercase_hex_is_not_canonical() {
        // Нашёл фаззер: `hex::decode` принимает заглавные, `hex::encode` отдаёт строчные, и
        // манифест с `0A…` в hex-поле читался, но пересобирался уже другими байтами. Для
        // подписанного документа это два разных манифеста под двумя разными подписями.
        let mut m = reference_manifest();
        // Нули регистр не меняют, поэтому поля заполнены значением с буквами.
        m.model_blake3 = [0xab; 32];
        m.tokenizer_blake3 = [0xcd; 32];
        m.centroid_blake3 = [0xef; 32];
        let base = String::from_utf8(m.to_json_bytes()).unwrap();
        for (field, lower) in [
            ("model_blake3", hex::encode(m.model_blake3)),
            ("tokenizer_blake3", hex::encode(m.tokenizer_blake3)),
            ("centroid_blake3", hex::encode(m.centroid_blake3)),
        ] {
            let upper = lower.to_uppercase();
            assert_ne!(lower, upper, "значение {field} без букв");
            let doc = base.replacen(
                &format!("\"{field}\":\"{lower}\""),
                &format!("\"{field}\":\"{upper}\""),
                1,
            );
            assert_ne!(doc, base, "{field} не найден в сериализации");
            assert!(
                matches!(Manifest::decode(doc.as_bytes()), Err(ManifestError::Hex { .. })),
                "{field} в верхнем регистре принят"
            );
        }
        // Тот же hex живёт и в массивах: ключ авторитета — такое же поле фиксированной длины.
        let key = m
            .authority
            .keys
            .iter()
            .map(hex::encode)
            .find(|k| *k != k.to_uppercase())
            .expect("хоть один ключ авторитета содержит hex-буквы");
        let doc = base.replacen(&format!("\"{key}\""), &format!("\"{}\"", key.to_uppercase()), 1);
        assert_ne!(doc, base, "ключ авторитета не найден в сериализации");
        assert!(Manifest::decode(doc.as_bytes()).is_err(), "ключ в верхнем регистре принят");
    }

    #[test]
    fn shard_budget_matches_the_spec_estimate() {
        let m = reference_manifest();
        // M = 2 000 000 записей по 424 Б = 848 МБ — то, что обещает приложение B (§11.3).
        assert_eq!(m.shard_bytes_budget(), 2_000_000 * 424);
        assert!(m.shard_bytes_budget() > 800 * 1024 * 1024);
    }

    #[test]
    fn ranges_reject_negative_and_oversized() {
        let text = String::from_utf8(reference_manifest().to_json_bytes()).unwrap();
        let neg = text.replacen("\"max_length\":256", "\"max_length\":-1", 1);
        assert!(matches!(
            Manifest::decode(neg.as_bytes()),
            Err(ManifestError::Range { field: "max_length", .. })
        ));
        let huge = text.replacen("\"max_length\":256", "\"max_length\":99999999999999", 1);
        assert!(Manifest::decode(huge.as_bytes()).is_err());
    }
}
