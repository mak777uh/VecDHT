//! Сообщения протокола v8 (спека §5.3–§5.4, §12).
//!
//! Каждое сообщение — фиксированная часть + опциональный TLV-хвост. Порядок полей — часть
//! контракта: он задаёт канонические байты, по которым считается подпись (§5.2).

use crate::codec::{DecodeError, Reader, Writer, DIM};
use crate::frame::{decode_frame, encode_frame, Kind, PROTOCOL_VERSION};

/// Доменные строки подписи (§5.2). Разные типы никогда не подписываются одной domain-строкой.
pub mod domain {
    pub const HANDSHAKE: &[u8] = b"vecdht/v8/handshake";
    pub const PUBLISH: &[u8] = b"vecdht/v8/publish";
    pub const FIND: &[u8] = b"vecdht/v8/find";
    pub const MATCH: &[u8] = b"vecdht/v8/match";
    pub const TEXT: &[u8] = b"vecdht/v8/text";
    pub const REPLICA: &[u8] = b"vecdht/v8/replica";
    pub const MEMBER: &[u8] = b"vecdht/v8/member";
    pub const LEAVE: &[u8] = b"vecdht/v8/leave";
    pub const RENDEZVOUS: &[u8] = b"vecdht/v8/rendezvous";
    pub const LEASE: &[u8] = b"vecdht/v8/lease";
    pub const ACK: &[u8] = b"vecdht/v8/ack";
    pub const ARTIFACT: &[u8] = b"vecdht/v8/artifact";
    pub const WAL: &[u8] = b"vecdht/v8/wal";
    /// Отдача снапшота шарда seed-узлом (§9.5, шаг 2): каждый кусок подписан, иначе
    /// «пояс» превращается в вектор подмены состояния.
    pub const SNAPSHOT: &[u8] = b"vecdht/v8/snapshot";
}

/// Коды ошибок прикладного уровня (`Error{code:...}` из спеки).
pub mod err_code {
    pub const MODEL_MISMATCH: &str = "MODEL_MISMATCH";
    pub const SHARD_MISMATCH: &str = "SHARD_MISMATCH";
    pub const POW_INVALID: &str = "POW_INVALID";
    pub const POW_BITS_LOW: &str = "POW_BITS_LOW";
    pub const BUSY: &str = "BUSY";
    pub const QUOTA_PUBLISH: &str = "QUOTA_PUBLISH";
    pub const QUOTA_FIND: &str = "QUOTA_FIND";
    pub const SHARD_FULL: &str = "SHARD_FULL";
    pub const EPOCH_STALE: &str = "EPOCH_STALE";
    pub const NOT_OWNER: &str = "NOT_OWNER";
    pub const NO_SUCH_SLOT: &str = "NO_SUCH_SLOT";
    pub const WAL_FAILED: &str = "WAL_FAILED";
    pub const BAD_ENUM: &str = "BAD_ENUM";
    pub const CERT_INVALID: &str = "CERT_INVALID";
    pub const DENIED: &str = "DENIED";
}

/// Вид опса внутри WAL/`ReplicateOp`. `TimeMark` и `GcTick` — не отдельные сообщения,
/// а op-виды (§5.3, §9.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpKind {
    Insert = 1,
    Delete = 2,
    TimeMark = 0x30,
    GcTick = 0x31,
}

impl OpKind {
    pub fn from_u8(v: u8) -> Result<Self, DecodeError> {
        Ok(match v {
            1 => OpKind::Insert,
            2 => OpKind::Delete,
            0x30 => OpKind::TimeMark,
            0x31 => OpKind::GcTick,
            other => {
                return Err(DecodeError::BadEnum { value: other as u64, what: "OpKind", offset: 0 })
            }
        })
    }
}

/// Роль в `Handshake` и `NodeCert`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Agent = 0,
    IndexNode = 1,
    Relay = 2,
}

impl Role {
    pub fn from_u8(v: u8) -> Result<Self, DecodeError> {
        Ok(match v {
            0 => Role::Agent,
            1 => Role::IndexNode,
            2 => Role::Relay,
            other => {
                return Err(DecodeError::BadEnum { value: other as u64, what: "Role", offset: 0 })
            }
        })
    }
}

/// Общий контракт сообщения: каноническое тело, кадр, декод.
pub trait Codec: Sized {
    const KIND: Kind;
    const DOMAIN: &'static [u8];

    fn encode_body(&self, w: &mut Writer);

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError>;

    /// Канонические байты тела — именно они входят в `sig_input`.
    fn body_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode_body(&mut w);
        w.into_vec()
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        encode_frame(Self::KIND, &self.body_bytes(), None)
    }

    fn encode_signed(&self, sig: &[u8]) -> Vec<u8> {
        encode_frame(Self::KIND, &self.body_bytes(), Some(sig))
    }

    /// Декод из кадра: сверка kind/version + декод тела.
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let frame = decode_frame(bytes)?;
        if frame.header.kind != Self::KIND {
            return Err(DecodeError::BadEnum {
                value: frame.header.kind as u8 as u64,
                what: "frame kind for message",
                offset: 0,
            });
        }
        if frame.header.version != PROTOCOL_VERSION {
            return Err(DecodeError::Version(frame.header.version));
        }
        let mut r = Reader::new(frame.body);
        Self::decode_body(&mut r)
    }
}

/// TLV-хвост, который сообщение умеет переносить через декод→энкод без изменения байтов.
pub type Tlv = Vec<(u16, Vec<u8>)>;

fn write_tlv(w: &mut Writer, tlv: &Tlv) {
    // Канонический порядок тегов — возрастающий (§5.1 п. 4). Сортируем копию индексов, а не сам
    // `Tlv`: вызывающий вправе держать пары в любом порядке, а `Writer::tlv` паникует на убывании
    // (это правильно для ручной сериализации, но не для данных, собранных из конфигурации).
    // Неизвестные теги сохраняются как есть: их порядок между собой уже задан вызывающим.
    let mut order: Vec<usize> = (0..tlv.len()).collect();
    order.sort_by_key(|&i| tlv[i].0);
    for i in order {
        let (tag, value) = &tlv[i];
        w.tlv(*tag, value);
    }
}

/// Атрибуты объявления записи (§5.5): класс, цена и направление.
///
/// Цена — `Option<u64>` без единицы; узел её декодирует, проверяет и выбрасывает, поэтому в
/// индексе живут только класс и направление (один байт `slot_attr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IntentAttrs {
    pub class: IntentClass,
    pub price: Option<u64>,
    pub dir: IntentDir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntentClass {
    #[default]
    Free = 0,
    Paid = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntentDir {
    #[default]
    Unspecified = 0,
    Buy = 1,
    Sell = 2,
}

impl IntentClass {
    fn from_byte(v: u8) -> Result<Self, DecodeError> {
        match v {
            0 => Ok(IntentClass::Free),
            1 => Ok(IntentClass::Paid),
            _ => Err(DecodeError::BadEnum { value: v as u64, what: "intent_class", offset: 0 }),
        }
    }

    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl IntentDir {
    fn from_byte(v: u8) -> Result<Self, DecodeError> {
        match v {
            0 => Ok(IntentDir::Unspecified),
            1 => Ok(IntentDir::Buy),
            2 => Ok(IntentDir::Sell),
            _ => Err(DecodeError::BadEnum { value: v as u64, what: "intent_dir", offset: 0 }),
        }
    }

    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

fn tlv_one_byte(tlv: &Tlv, tag: u16, what: &'static str) -> Result<Option<u8>, DecodeError> {
    match tlv.iter().find(|(t, _)| *t == tag) {
        None => Ok(None),
        Some((_, v)) if v.len() == 1 => Ok(Some(v[0])),
        Some(_) => Err(DecodeError::IntentAttr(what)),
    }
}

impl IntentAttrs {
    /// Разобрать TLV-хвост `Publish` по канонической форме §5.5.
    ///
    /// Явные `intent_class = 0` и `intent_dir = 0` не ошибка (они схлопываются в отсутствие тега
    /// до проверки подписи), а вот `price` без класса, цена при `free` и `price = 0` при `paid` —
    /// ошибка декода, а не «трактуем как free»: молчаливая трактовка превратила бы платное
    /// объявление в бесплатное для того, кто обязан был отказать.
    pub fn parse(tlv: &Tlv) -> Result<Self, DecodeError> {
        let class_raw = tlv_one_byte(tlv, TLV_INTENT_CLASS, "intent_class length")?;
        let dir_raw = tlv_one_byte(tlv, TLV_INTENT_DIR, "intent_dir length")?;
        let class = match class_raw {
            None => IntentClass::Free,
            Some(v) => IntentClass::from_byte(v)?,
        };
        let dir = match dir_raw {
            None => IntentDir::Unspecified,
            Some(v) => IntentDir::from_byte(v)?,
        };
        let price = match tlv.iter().find(|(t, _)| *t == TLV_PRICE) {
            None => None,
            Some((_, v)) if v.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(v);
                Some(u64::from_le_bytes(b))
            }
            Some(_) => return Err(DecodeError::IntentAttr("price length")),
        };
        match (class_raw, class, price) {
            (None, _, Some(_)) => Err(DecodeError::IntentAttr("price without intent_class")),
            (_, IntentClass::Paid, None) => Err(DecodeError::IntentAttr("price missing for paid")),
            (_, IntentClass::Paid, Some(0)) => Err(DecodeError::IntentAttr("price zero for paid")),
            (_, IntentClass::Free, Some(_)) => Err(DecodeError::IntentAttr("price for free")),
            _ => Ok(IntentAttrs { class, price, dir }),
        }
    }

    /// Записать атрибуты в TLV, сохранив неизвестные вызывающему теги. Известные теги
    /// пересобираются, поэтому вызвать дважды безопасно.
    pub fn write_into(&self, tlv: &mut Tlv) {
        tlv.retain(|(t, _)| {
            !matches!(*t, TLV_INTENT_CLASS | TLV_PRICE | TLV_INTENT_DIR)
        });
        if self.class == IntentClass::Paid {
            tlv.push((TLV_INTENT_CLASS, vec![1]));
            tlv.push((TLV_PRICE, self.price.unwrap_or(0).to_le_bytes().to_vec()));
        }
        if self.dir != IntentDir::Unspecified {
            tlv.push((TLV_INTENT_DIR, vec![self.dir.as_u8()]));
        }
        tlv.sort_by_key(|(t, _)| *t);
    }
}

/// Убрать неканоничные нулевые теги ДО проверки подписи (§5.5 п. 1, §12.7): явный `0` в
/// перечислении и отсутствие тега обязаны давать одни и те же подписанные байты.
fn collapse_zero_tags(tlv: &mut Tlv, tags: &[u16]) {
    tlv.retain(|(tag, v)| !(tags.contains(tag) && v.as_slice() == [0u8]));
}

// ---------------------------------------------------------------------------
// 0x01 Handshake
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub role: Role,
    pub preprocessing_version: u16,
    pub model_version: String,
    pub genesis_hash: [u8; 32],
    /// Сериализованный `NodeCert` (role != Agent обязана его нести).
    pub cert: Vec<u8>,
    pub tlv: Tlv,
}

impl Codec for Handshake {
    const KIND: Kind = Kind::Handshake;
    const DOMAIN: &'static [u8] = domain::HANDSHAKE;

    fn encode_body(&self, w: &mut Writer) {
        w.u8(self.role as u8);
        w.u16(self.preprocessing_version);
        w.string(&self.model_version);
        w.fixed(&self.genesis_hash);
        w.bytes(&self.cert);
        write_tlv(w, &self.tlv);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let role = Role::from_u8(r.u8()?)?;
        let preprocessing_version = r.u16()?;
        let model_version = r.string()?;
        let genesis_hash = r.fixed()?;
        let cert = r.bytes()?;
        let tlv = r.tlv_tail()?;
        r.expect_end()?;
        Ok(Handshake { role, preprocessing_version, model_version, genesis_hash, cert, tlv })
    }
}

// ---------------------------------------------------------------------------
// 0x02 Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: String,
    pub retry_after_ms: u32,
    pub shard: u16,
}

impl Codec for ProtocolError {
    const KIND: Kind = Kind::Error;
    const DOMAIN: &'static [u8] = b"vecdht/v8/error";

    fn encode_body(&self, w: &mut Writer) {
        w.string(&self.code);
        w.u32(self.retry_after_ms);
        w.u16(self.shard);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let code = r.string()?;
        let retry_after_ms = r.u32()?;
        let shard = r.u16()?;
        r.expect_end()?;
        Ok(ProtocolError { code, retry_after_ms, shard })
    }
}

// ---------------------------------------------------------------------------
// 0x10 Publish / 0x11 PublishAck
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub preprocessing_version: u16,
    pub cluster_id: u16,
    pub vec_q: [i8; DIM],
    pub owner_ed25519: [u8; 32],
    /// TTL в 16-секундных бакетах (§8.2).
    pub ttl_buckets: u16,
    /// Бакет публикации из `TimeMark`, а не из локальных часов (§9.6).
    pub published_bucket: u32,
    pub pow_bits: u8,
    pub pow_nonce: u64,
    pub intent_id: [u8; 32],
    pub tlv: Tlv,
}

/// Зарезервированный TLV-тег `role_slot` (спека §6.5: несколько интентов на агента — не активировано).
pub const TLV_ROLE_SLOT: u16 = 0x0001;

/// Атрибуты объявления в TLV-хвосте `Publish` (§5.5). `0x0001` занят `role_slot`.
pub const TLV_INTENT_CLASS: u16 = 0x0002;
pub const TLV_PRICE: u16 = 0x0003;
pub const TLV_INTENT_DIR: u16 = 0x0004;

impl Publish {
    /// Атрибуты объявления (§5.5). Декод уже проверил каноническую форму, поэтому ошибка здесь
    /// возможна только у структуры, собранной в обход `decode`/`set_intent`.
    pub fn intent(&self) -> Result<IntentAttrs, DecodeError> {
        IntentAttrs::parse(&self.tlv)
    }

    /// Записать атрибуты в TLV. `free` + `unspecified` не добавляет ни одного тега, то есть
    /// интент без объявления остаётся байт-в-байт прежним.
    pub fn set_intent(&mut self, attrs: IntentAttrs) {
        attrs.write_into(&mut self.tlv);
    }
}

impl Codec for Publish {
    const KIND: Kind = Kind::Publish;
    const DOMAIN: &'static [u8] = domain::PUBLISH;

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.preprocessing_version);
        w.u16(self.cluster_id);
        w.vec_q(&self.vec_q);
        w.fixed(&self.owner_ed25519);
        w.u16(self.ttl_buckets);
        w.u32(self.published_bucket);
        w.u8(self.pow_bits);
        w.u64(self.pow_nonce);
        w.fixed(&self.intent_id);
        write_tlv(w, &self.tlv);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let preprocessing_version = r.u16()?;
        let cluster_id = r.u16()?;
        if cluster_id >= crate::constants::NLIST {
            return Err(DecodeError::BadEnum {
                value: cluster_id as u64,
                what: "cluster_id",
                offset: 0,
            });
        }
        let vec_q = r.vec_q()?;
        let owner_ed25519 = r.fixed()?;
        let ttl_buckets = r.u16()?;
        let published_bucket = r.u32()?;
        let pow_bits = r.u8()?;
        let pow_nonce = r.u64()?;
        let intent_id = r.fixed()?;
        let mut tlv = r.tlv_tail()?;
        // Схлопывание нулевых тегов — часть декода, а не проверки подписи: подпись считается по
        // пересобранным canonical-байтам (§5.2), и обе записи обязаны дать одни и те же байты.
        collapse_zero_tags(&mut tlv, &[TLV_INTENT_CLASS, TLV_INTENT_DIR]);
        // Валидация канонической формы на входе: неканоничная запись отвергается здесь, а не
        // выясняется при первом поиске с фильтром.
        IntentAttrs::parse(&tlv)?;
        r.expect_end()?;
        Ok(Publish {
            preprocessing_version,
            cluster_id,
            vec_q,
            owner_ed25519,
            ttl_buckets,
            published_bucket,
            pow_bits,
            pow_nonce,
            intent_id,
            tlv,
        })
    }
}

/// Результат приёма: `code == "OK"` означает запись в durable WAL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishAck {
    pub shard: u16,
    pub epoch: u64,
    pub seq: u64,
    pub slot: u32,
    /// Актуальная сложность PoW для следующего publish на этом шарде (§11.2).
    pub next_pow_bits: u8,
    pub error_code: String,
    pub retry_after_ms: u32,
}

impl Codec for PublishAck {
    const KIND: Kind = Kind::PublishAck;
    const DOMAIN: &'static [u8] = b"vecdht/v8/publish_ack";

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.shard);
        w.u64(self.epoch);
        w.u64(self.seq);
        w.u32(self.slot);
        w.u8(self.next_pow_bits);
        w.string(&self.error_code);
        w.u32(self.retry_after_ms);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let shard = r.u16()?;
        let epoch = r.u64()?;
        let seq = r.u64()?;
        let slot = r.u32()?;
        let next_pow_bits = r.u8()?;
        let error_code = r.string()?;
        let retry_after_ms = r.u32()?;
        r.expect_end()?;
        Ok(PublishAck {
            shard,
            epoch,
            seq,
            slot,
            next_pow_bits,
            error_code,
            retry_after_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// 0x12 Find / 0x13 MatchResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Find {
    pub preprocessing_version: u16,
    pub query_vector: [i8; DIM],
    /// Кластеры этого узла, входящие в nprobe-множество запроса (§7.5).
    pub clusters: Vec<u16>,
    pub top_k: u16,
    /// Anti-replay: идентификатор запроса, живёт в теле (§14.3).
    pub query_id: u64,
    pub requester_ed25519: [u8; 32],
    pub tlv: Tlv,
}

pub const TLV_BATCH_HINT: u16 = 0x0001;

/// Фильтры поиска в TLV-хвосте `Find` (§12.7). `0x0001` в namespace `Find` занят `batch_hint`.
pub const TLV_CLASS_FILTER: u16 = 0x0002;
pub const TLV_DIR_FILTER: u16 = 0x0003;

/// Класс, который проситель хочет видеть. `Any` — поведение до §5.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClassFilter {
    #[default]
    Any = 0,
    OnlyFree = 1,
    OnlyPaid = 2,
}

/// Направление автора записи, которое проситель хочет видеть (§12.7: фильтр выбирает
/// направление АВТОРА, а не своё). `Any` — поведение до §5.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirFilter {
    #[default]
    Any = 0,
    Buy = 1,
    Sell = 2,
    Unspecified = 3,
}

impl ClassFilter {
    fn from_byte(v: u8) -> Result<Self, DecodeError> {
        match v {
            0 => Ok(ClassFilter::Any),
            1 => Ok(ClassFilter::OnlyFree),
            2 => Ok(ClassFilter::OnlyPaid),
            _ => Err(DecodeError::BadEnum { value: v as u64, what: "class_filter", offset: 0 }),
        }
    }

    /// Предикат над битом `paid` записи. `Any` не смотрит на бит вовсе.
    #[inline]
    pub fn rejects(self, paid: bool) -> bool {
        match self {
            ClassFilter::Any => false,
            ClassFilter::OnlyFree => paid,
            ClassFilter::OnlyPaid => !paid,
        }
    }

    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl DirFilter {
    fn from_byte(v: u8) -> Result<Self, DecodeError> {
        match v {
            0 => Ok(DirFilter::Any),
            1 => Ok(DirFilter::Buy),
            2 => Ok(DirFilter::Sell),
            3 => Ok(DirFilter::Unspecified),
            _ => Err(DecodeError::BadEnum { value: v as u64, what: "dir_filter", offset: 0 }),
        }
    }

    /// `dir` — младшие два бита `slot_attr` (§5.5). `Any` не смотрит на бит вовсе.
    #[inline]
    pub fn rejects(self, dir_bits: u8) -> bool {
        match self {
            DirFilter::Any => false,
            DirFilter::Buy => dir_bits != IntentDir::Buy.as_u8(),
            DirFilter::Sell => dir_bits != IntentDir::Sell.as_u8(),
            DirFilter::Unspecified => dir_bits != IntentDir::Unspecified.as_u8(),
        }
    }

    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl Find {
    /// Разобрать фильтры §12.7. Отсутствие тега — `Any`; явный `0` до этого уже схлопнут декодом.
    pub fn filters(&self) -> Result<(ClassFilter, DirFilter), DecodeError> {
        let class = match tlv_one_byte(&self.tlv, TLV_CLASS_FILTER, "class_filter length")? {
            None => ClassFilter::Any,
            Some(v) => ClassFilter::from_byte(v)?,
        };
        let dir = match tlv_one_byte(&self.tlv, TLV_DIR_FILTER, "dir_filter length")? {
            None => DirFilter::Any,
            Some(v) => DirFilter::from_byte(v)?,
        };
        Ok((class, dir))
    }

    /// Записать фильтры в TLV, сохранив неизвестные теги. `Any` пишется как отсутствие тега.
    pub fn set_filters(&mut self, class: ClassFilter, dir: DirFilter) {
        self.tlv.retain(|(t, _)| !matches!(*t, TLV_CLASS_FILTER | TLV_DIR_FILTER));
        if class != ClassFilter::Any {
            self.tlv.push((TLV_CLASS_FILTER, vec![class.as_u8()]));
        }
        if dir != DirFilter::Any {
            self.tlv.push((TLV_DIR_FILTER, vec![dir.as_u8()]));
        }
        self.tlv.sort_by_key(|(t, _)| *t);
    }
}

impl Codec for Find {
    const KIND: Kind = Kind::Find;
    const DOMAIN: &'static [u8] = domain::FIND;

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.preprocessing_version);
        w.vec_q(&self.query_vector);
        w.u16_list(&self.clusters);
        w.u16(self.top_k);
        w.u64(self.query_id);
        w.fixed(&self.requester_ed25519);
        write_tlv(w, &self.tlv);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let preprocessing_version = r.u16()?;
        let query_vector = r.vec_q()?;
        let clusters = r.u16_list()?;
        let top_k = r.u16()?;
        let query_id = r.u64()?;
        let requester_ed25519 = r.fixed()?;
        let mut tlv = r.tlv_tail()?;
        collapse_zero_tags(&mut tlv, &[TLV_CLASS_FILTER, TLV_DIR_FILTER]);
        let find = Find {
            preprocessing_version,
            query_vector,
            clusters,
            top_k,
            query_id,
            requester_ed25519,
            tlv,
        };
        find.filters()?;
        r.expect_end()?;
        Ok(find)
    }
}

/// Одна строка результата. Поле `similarity` отсутствует намеренно: оно производное от `d2`
/// и считается агентом (§6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub owner_ed25519: [u8; 32],
    pub cluster_id: u16,
    /// Целочисленный L2² из контракта сортировки (§8.4).
    pub d2: u32,
    pub slot: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub shard: u16,
    pub epoch: u64,
    pub query_id: u64,
    pub responder_ed25519: [u8; 32],
    /// Отсортирован по контракту: `d2 ASC`, затем `slot ASC`.
    pub matches: Vec<Match>,
}

impl MatchResult {
    /// Проверка контракта сортировки перед подписанием: подписывать неканонически
    /// отсортированный результат запрещено (§8.4).
    pub fn check_sort_contract(&self) -> Result<(), DecodeError> {
        for (i, w) in self.matches.windows(2).enumerate() {
            let a = (w[0].d2, w[0].slot);
            let b = (w[1].d2, w[1].slot);
            if a > b {
                return Err(DecodeError::OutOfOrder { index: i + 1 });
            }
        }
        Ok(())
    }
}

impl Codec for MatchResult {
    const KIND: Kind = Kind::MatchResult;
    const DOMAIN: &'static [u8] = domain::MATCH;

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.shard);
        w.u64(self.epoch);
        w.u64(self.query_id);
        w.fixed(&self.responder_ed25519);
        w.u16(self.matches.len() as u16);
        for m in &self.matches {
            w.fixed(&m.owner_ed25519);
            w.u16(m.cluster_id);
            w.u32(m.d2);
            w.u32(m.slot);
        }
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let shard = r.u16()?;
        let epoch = r.u64()?;
        let query_id = r.u64()?;
        let responder_ed25519 = r.fixed()?;
        let n = r.u16()? as usize;
        let mut matches = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let owner_ed25519 = r.fixed()?;
            let cluster_id = r.u16()?;
            let d2 = r.u32()?;
            let slot = r.u32()?;
            matches.push(Match { owner_ed25519, cluster_id, d2, slot });
        }
        r.expect_end()?;
        Ok(MatchResult { shard, epoch, query_id, responder_ed25519, matches })
    }
}

// ---------------------------------------------------------------------------
// 0x14/0x15 IntentText
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentTextRequest {
    pub query_id: u64,
    pub target_ed25519: [u8; 32],
    pub slot: u32,
    /// Предъявление (`ADR-0013`, §12.3): полный байтовый подписанный кадр
    /// `RendezvousAccept`. Пустое значение разборимо, но цель обязана отказать (`NoAccept`).
    pub present: Vec<u8>,
}

/// Лимит `present`: кадр приёма ~148 Б (76 тело + 8 заголовок + 64 подпись), запас на рост.
pub const MAX_PRESENT_BYTES: usize = 512;

impl Codec for IntentTextRequest {
    const KIND: Kind = Kind::IntentTextRequest;
    const DOMAIN: &'static [u8] = b"vecdht/v8/text_req";

    fn encode_body(&self, w: &mut Writer) {
        w.u64(self.query_id);
        w.fixed(&self.target_ed25519);
        w.u32(self.slot);
        w.bytes(&self.present);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let query_id = r.u64()?;
        let target_ed25519 = r.fixed()?;
        let slot = r.u32()?;
        let present = r.bytes()?;
        r.expect_end()?;
        if present.len() > MAX_PRESENT_BYTES {
            return Err(DecodeError::FieldTooLong(present.len()));
        }
        Ok(IntentTextRequest { query_id, target_ed25519, slot, present })
    }
}

/// Текст публикуется за подписью автора (§6.6) — иначе агент не может отличить
/// полученный текст от подменённого.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentTextResponse {
    pub owner_ed25519: [u8; 32],
    pub model_version: String,
    pub preprocessing_version: u16,
    pub text: Vec<u8>,
}

/// Жёсткий лимит canonical intent_text — 1000 байт UTF-8 (§6.6).
pub const MAX_INTENT_TEXT_BYTES: usize = 1000;

impl Codec for IntentTextResponse {
    const KIND: Kind = Kind::IntentTextResponse;
    const DOMAIN: &'static [u8] = domain::TEXT;

    fn encode_body(&self, w: &mut Writer) {
        w.fixed(&self.owner_ed25519);
        w.string(&self.model_version);
        w.u16(self.preprocessing_version);
        w.bytes(&self.text);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let owner_ed25519 = r.fixed()?;
        let model_version = r.string()?;
        let preprocessing_version = r.u16()?;
        let text = r.bytes()?;
        r.expect_end()?;
        if text.len() > MAX_INTENT_TEXT_BYTES {
            return Err(DecodeError::FieldTooLong(text.len()));
        }
        Ok(IntentTextResponse { owner_ed25519, model_version, preprocessing_version, text })
    }
}

// ---------------------------------------------------------------------------
// 0x20/0x21/0x22 Репликация
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalPullRequest {
    pub shard: u16,
    pub from_seq: u64,
    /// 0 = до текущего.
    pub to_seq: u64,
    pub max_bytes: u32,
}

impl Codec for WalPullRequest {
    const KIND: Kind = Kind::WalPullRequest;
    const DOMAIN: &'static [u8] = b"vecdht/v8/wal_pull_req";

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.shard);
        w.u64(self.from_seq);
        w.u64(self.to_seq);
        w.u32(self.max_bytes);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let shard = r.u16()?;
        let from_seq = r.u64()?;
        let to_seq = r.u64()?;
        let max_bytes = r.u32()?;
        r.expect_end()?;
        Ok(WalPullRequest { shard, from_seq, to_seq, max_bytes })
    }
}

/// Фреймы отдаются как есть: каждый из них уже подписан (`ReplicateOp`), поэтому подпись
/// на уровне сообщения не нужна — важна подпись каждой записи (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalPullResponse {
    pub shard: u16,
    pub from_seq: u64,
    pub to_seq: u64,
    pub primary_epoch: u64,
    pub frames: Vec<u8>,
}

impl Codec for WalPullResponse {
    const KIND: Kind = Kind::WalPullResponse;
    const DOMAIN: &'static [u8] = b"vecdht/v8/wal_pull_resp";

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.shard);
        w.u64(self.from_seq);
        w.u64(self.to_seq);
        w.u64(self.primary_epoch);
        w.bytes(&self.frames);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let shard = r.u16()?;
        let from_seq = r.u64()?;
        let to_seq = r.u64()?;
        let primary_epoch = r.u64()?;
        let frames = r.bytes()?;
        r.expect_end()?;
        Ok(WalPullResponse { shard, from_seq, to_seq, primary_epoch, frames })
    }
}

/// Подписанная запись репликации. `body` — кодировка опса (`InsertOp`/`DeleteOp`/TimeMark/GcTick).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicateOp {
    pub shard: u16,
    pub epoch: u64,
    pub seq: u64,
    pub op_kind: OpKind,
    pub body: Vec<u8>,
}

impl Codec for ReplicateOp {
    const KIND: Kind = Kind::ReplicateOp;
    const DOMAIN: &'static [u8] = domain::REPLICA;

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.shard);
        w.u64(self.epoch);
        w.u64(self.seq);
        w.u8(self.op_kind as u8);
        w.bytes(&self.body);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let shard = r.u16()?;
        let epoch = r.u64()?;
        let seq = r.u64()?;
        let op_kind = OpKind::from_u8(r.u8()?)?;
        let body = r.bytes()?;
        r.expect_end()?;
        Ok(ReplicateOp { shard, epoch, seq, op_kind, body })
    }
}

/// Lease primary'а на шард (§9.4): продлевается раз в 30 с, каждый WAL-фрейм несёт `epoch`.
/// Реплика, увидевшая `epoch < saved_max_epoch`, фрейм отбрасывает — old primary демотируется
/// сам, без отдельного протокола выборов. Подпись — Ed25519 кадра ключом `primary_ed25519`,
/// который обязан совпасть с аутентифицированным транспортом ключом и с `NodeCert` (§4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGrant {
    pub shard: u16,
    pub epoch: u64,
    pub primary_ed25519: [u8; 32],
    /// libp2p-байты, как их отдал транспорт; сверяется с remote PeerId.
    pub dht_peer_id: Vec<u8>,
    /// Абсолютный бакет 16-секундного времени (§9.6: `TIME_BUCKET_SEC = 16`), а не delta — иначе
    /// часы реплики влияют
    /// на то, когда lease истёк.
    pub expires_at_bucket: u32,
}

impl Codec for LeaseGrant {
    const KIND: Kind = Kind::LeaseGrant;
    const DOMAIN: &'static [u8] = domain::LEASE;

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.shard);
        w.u64(self.epoch);
        w.fixed(&self.primary_ed25519);
        w.bytes(&self.dht_peer_id);
        w.u32(self.expires_at_bucket);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let shard = r.u16()?;
        if shard >= crate::constants::SHARDS {
            return Err(DecodeError::BadEnum { value: shard as u64, what: "shard", offset: 0 });
        }
        let epoch = r.u64()?;
        let primary_ed25519 = r.fixed()?;
        let dht_peer_id = r.bytes()?;
        let expires_at_bucket = r.u32()?;
        r.expect_end()?;
        Ok(LeaseGrant { shard, epoch, primary_ed25519, dht_peer_id, expires_at_bucket })
    }
}

/// Отдача последнего снапшота шарда (§9.5): когда членство шарда обнулилось, seed-узлы
/// объявляют пустой шард и раздают снимок, чтобы новый состав мог начать с него, а не с нуля.
///
/// Файл `snap.<seq>.log` режется на куски ≤ `SNAPSHOT_CHUNK_MAX_LEN`; `content_hash` — blake3
/// **всего** файла и одинаков во всех кусках, поэтому приёмник проверяет сборку целиком, а не
/// каждый кусок в отдельности. Метаданные повторяют `MANIFEST` (§10.2), потому что приёмнику
/// нужно записать их до открытия индекса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotOffer {
    pub shard: u16,
    /// Эпоха членства на момент снимка: приёмник обязан принять только `epoch >= своего`.
    pub epoch: u64,
    pub snapshot_seq: u64,
    pub oldest_wal_needed: u64,
    pub applied_seq: u64,
    pub next_slot: u64,
    pub time_mark_bucket: u32,
    /// Размер файла целиком, байт.
    pub total_len: u32,
    /// Смещение куска внутри файла.
    pub offset: u32,
    pub content_hash: [u8; 32],
    pub chunk: Vec<u8>,
}

impl SnapshotOffer {
    /// Последний кусок: `offset + chunk.len() == total_len`.
    pub fn is_last_chunk(&self) -> bool {
        self.offset as u64 + self.chunk.len() as u64 == self.total_len as u64
    }
}

impl Codec for SnapshotOffer {
    const KIND: Kind = Kind::SnapshotOffer;
    const DOMAIN: &'static [u8] = domain::SNAPSHOT;

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.shard);
        w.u64(self.epoch);
        w.u64(self.snapshot_seq);
        w.u64(self.oldest_wal_needed);
        w.u64(self.applied_seq);
        w.u64(self.next_slot);
        w.u32(self.time_mark_bucket);
        w.u32(self.total_len);
        w.u32(self.offset);
        w.fixed(&self.content_hash);
        w.bytes(&self.chunk);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let shard = r.u16()?;
        if shard >= crate::constants::SHARDS {
            return Err(DecodeError::BadEnum { value: shard as u64, what: "shard", offset: 0 });
        }
        let epoch = r.u64()?;
        let snapshot_seq = r.u64()?;
        let oldest_wal_needed = r.u64()?;
        let applied_seq = r.u64()?;
        let next_slot = r.u64()?;
        let time_mark_bucket = r.u32()?;
        let total_len = r.u32()?;
        let offset = r.u32()?;
        let content_hash = r.fixed()?;
        let chunk = r.bytes()?;
        r.expect_end()?;
        // Пустой кусок — это не данные, а способ застопорить пересборку; геометрия обязана
        // быть внутри файла (иначе приёмник не отличит «хвост» от порчи).
        if chunk.is_empty() {
            return Err(DecodeError::BadEnum { value: 0, what: "snapshot chunk len", offset: 0 });
        }
        if offset as u64 + chunk.len() as u64 > total_len as u64 {
            return Err(DecodeError::BadEnum {
                value: offset as u64 + chunk.len() as u64,
                what: "snapshot chunk past total_len",
                offset: 0,
            });
        }
        Ok(SnapshotOffer {
            shard,
            epoch,
            snapshot_seq,
            oldest_wal_needed,
            applied_seq,
            next_slot,
            time_mark_bucket,
            total_len,
            offset,
            content_hash,
            chunk,
        })
    }
}

/// Подтверждение реплики для кворума W (§9.4): «фрейм `seq` у меня durable, `applied_seq` = …».
/// Подпись обязательна — ack, который нельзя атрибутировать, не может входить в кворум
/// durability: иначе любой наблюдатель объявляет запись зафиксированной.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicateAck {
    pub shard: u16,
    pub epoch: u64,
    /// На какой фрейм отвечает реплика.
    pub seq: u64,
    pub replica_ed25519: [u8; 32],
    /// Состояние после применения: `applied_seq >= seq` при ok = true.
    pub applied_seq: u64,
    /// false ⇒ реплика отказала фрейму (gap, чужой шард, младшая эпизода). Кворум не засчитывается.
    pub ok: bool,
}

impl Codec for ReplicateAck {
    const KIND: Kind = Kind::ReplicateAck;
    const DOMAIN: &'static [u8] = domain::ACK;

    fn encode_body(&self, w: &mut Writer) {
        w.u16(self.shard);
        w.u64(self.epoch);
        w.u64(self.seq);
        w.fixed(&self.replica_ed25519);
        w.u64(self.applied_seq);
        w.bool(self.ok);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let shard = r.u16()?;
        if shard >= crate::constants::SHARDS {
            return Err(DecodeError::BadEnum { value: shard as u64, what: "shard", offset: 0 });
        }
        let epoch = r.u64()?;
        let seq = r.u64()?;
        let replica_ed25519 = r.fixed()?;
        let applied_seq = r.u64()?;
        let ok = r.bool()?;
        r.expect_end()?;
        Ok(ReplicateAck { shard, epoch, seq, replica_ed25519, applied_seq, ok })
    }
}

/// Тело `Insert`: ровно те же поля, что `IndexEntry` (§8.2), без служебных.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsertOp {
    pub owner_ed25519: [u8; 32],
    pub vec_q: [i8; DIM],
    pub cluster_id: u16,
    pub published_bucket: u32,
    pub ttl_buckets: u16,
}

impl InsertOp {
    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.owner_ed25519);
        w.vec_q(&self.vec_q);
        w.u16(self.cluster_id);
        w.u32(self.published_bucket);
        w.u16(self.ttl_buckets);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let owner_ed25519 = r.fixed()?;
        let vec_q = r.vec_q()?;
        let cluster_id = r.u16()?;
        let published_bucket = r.u32()?;
        let ttl_buckets = r.u16()?;
        r.expect_end()?;
        Ok(InsertOp { owner_ed25519, vec_q, cluster_id, published_bucket, ttl_buckets })
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.into_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteOp {
    pub owner_ed25519: [u8; 32],
    pub shard: u16,
}

impl DeleteOp {
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.owner_ed25519);
        w.u16(self.shard);
        w.into_vec()
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let owner_ed25519 = r.fixed()?;
        let shard = r.u16()?;
        r.expect_end()?;
        Ok(DeleteOp { owner_ed25519, shard })
    }
}

/// `TimeMark` (спека §9.6): бакет выровнен, поэтому байты фрейма одинаковы на всех узлах.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeMark {
    pub seq: u64,
    pub bucket: u32,
}

/// `GcTick`: экспирация определяется только относительно этого бакета.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcTick {
    pub up_to_seq: u64,
    pub bucket: u32,
}

pub fn encode_mark(seq: u64, bucket: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(seq);
    w.u32(bucket);
    w.into_vec()
}

pub fn decode_mark(bytes: &[u8]) -> Result<(u64, u32), DecodeError> {
    let mut r = Reader::new(bytes);
    let seq = r.u64()?;
    let bucket = r.u32()?;
    r.expect_end()?;
    Ok((seq, bucket))
}

// ---------------------------------------------------------------------------
// 0x40/0x41 Членство
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub owner_ed25519: [u8; 32],
    pub dht_peer_id: Vec<u8>,
    pub capacity_entries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipUpdate {
    pub epoch: u64,
    pub shard: u16,
    pub members: Vec<Member>,
    pub primary_idx: u8,
    pub generated_at: u32,
    /// (индекс участника epoch−1, подпись) — не меньше порога t.
    pub sigs: Vec<(u8, [u8; 64])>,
}

impl Codec for MembershipUpdate {
    const KIND: Kind = Kind::MembershipUpdate;
    const DOMAIN: &'static [u8] = domain::MEMBER;

    fn encode_body(&self, w: &mut Writer) {
        w.u64(self.epoch);
        w.u16(self.shard);
        w.u16(self.members.len() as u16);
        for m in &self.members {
            w.fixed(&m.owner_ed25519);
            w.bytes(&m.dht_peer_id);
            w.u64(m.capacity_entries);
        }
        w.u8(self.primary_idx);
        w.u32(self.generated_at);
        w.u16(self.sigs.len() as u16);
        for (idx, sig) in &self.sigs {
            w.u8(*idx);
            w.fixed(sig);
        }
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let epoch = r.u64()?;
        let shard = r.u16()?;
        let n = r.u16()? as usize;
        let mut members = Vec::with_capacity(n.min(256));
        for _ in 0..n {
            let owner_ed25519 = r.fixed()?;
            let dht_peer_id = r.bytes()?;
            let capacity_entries = r.u64()?;
            members.push(Member { owner_ed25519, dht_peer_id, capacity_entries });
        }
        let primary_idx = r.u8()?;
        let generated_at = r.u32()?;
        let ns = r.u16()? as usize;
        let mut sigs = Vec::with_capacity(ns.min(256));
        for _ in 0..ns {
            let idx = r.u8()?;
            let sig = r.fixed()?;
            sigs.push((idx, sig));
        }
        r.expect_end()?;
        // Первичный обязан быть участником (§9.2). Пустое членство — легитимный случай:
        // так seed объявляют освобождённый шард (§9.5, п.2), и `primary_idx` в нём
        // обязан быть нулём — это проверяет узел, потому что здесь длина списка неизвестна
        // заранее только у пустого.
        if !members.is_empty() && primary_idx as usize >= members.len() {
            return Err(DecodeError::BadEnum {
                value: primary_idx as u64,
                what: "primary_idx",
                offset: 0,
            });
        }
        Ok(MembershipUpdate { epoch, shard, members, primary_idx, generated_at, sigs })
    }
}

impl MembershipUpdate {
    /// Байты, которые подписывает участник предыдущей эпохи: всё, кроме самого `sigs`
    /// (так же, как `NodeCert::unsigned_body`). Без этого поля подпись была бы над собой.
    pub fn unsigned_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.epoch);
        w.u16(self.shard);
        w.u16(self.members.len() as u16);
        for m in &self.members {
            w.fixed(&m.owner_ed25519);
            w.bytes(&m.dht_peer_id);
            w.u64(m.capacity_entries);
        }
        w.u8(self.primary_idx);
        w.u32(self.generated_at);
        w.into_vec()
    }

    /// Число членов: `primary_idx` обязан быть строго меньше (§9.2).
    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaveNotice {
    pub epoch: u64,
    pub shard: u16,
    pub leaving_owner: [u8; 32],
    pub drain_deadline_bucket: u32,
}

impl Codec for LeaveNotice {
    const KIND: Kind = Kind::LeaveNotice;
    const DOMAIN: &'static [u8] = domain::LEAVE;

    fn encode_body(&self, w: &mut Writer) {
        w.u64(self.epoch);
        w.u16(self.shard);
        w.fixed(&self.leaving_owner);
        w.u32(self.drain_deadline_bucket);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let epoch = r.u64()?;
        let shard = r.u16()?;
        let leaving_owner = r.fixed()?;
        let drain_deadline_bucket = r.u32()?;
        r.expect_end()?;
        Ok(LeaveNotice { epoch, shard, leaving_owner, drain_deadline_bucket })
    }
}

// ---------------------------------------------------------------------------
// 0x50 RendezvousAccept / 0x60 ArtifactAnnounce
// ---------------------------------------------------------------------------

/// Rendezvous выдаёт match-узел из собственной lease-таблицы (§12.3).
///
/// Подпись — Ed25519 на уровне кадра, а не HMAC «ключом кредашиала»: HMAC с ключом, который
/// получатель способен проверить, обязан быть ему известен, а публичный симметричный ключ
/// = свобода подделки для любого наблюдателя. Ed25519-ключ index-node уже верифицируется по
/// `NodeCert` из `Handshake`, поэтому свойство «приём подписан третьей стороной, а не самим
/// атакующим» сохраняется без противоречия.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RendezvousAccept {
    pub seeker: [u8; 32],
    pub target: [u8; 32],
    pub shard: u16,
    pub slot: u32,
    pub issued_bucket: u32,
    /// 300 с по умолчанию; хранится в секундах, бакет — время выпуска.
    pub ttl_sec: u16,
}

impl Codec for RendezvousAccept {
    const KIND: Kind = Kind::RendezvousAccept;
    const DOMAIN: &'static [u8] = domain::RENDEZVOUS;

    fn encode_body(&self, w: &mut Writer) {
        w.fixed(&self.seeker);
        w.fixed(&self.target);
        w.u16(self.shard);
        w.u32(self.slot);
        w.u32(self.issued_bucket);
        w.u16(self.ttl_sec);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let seeker = r.fixed()?;
        let target = r.fixed()?;
        let shard = r.u16()?;
        let slot = r.u32()?;
        let issued_bucket = r.u32()?;
        let ttl_sec = r.u16()?;
        r.expect_end()?;
        Ok(RendezvousAccept { seeker, target, shard, slot, issued_bucket, ttl_sec })
    }
}

/// Отзыв кредашиала по nonce (§4.2). Рассылается авторитетом по gossip; узел, увидев отзыв,
/// сбрасывает соединения и перестаёт подписывать чем-либо этим ключом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRevoke {
    pub nonce: [u8; 16],
    pub revoked_at: u32,
    pub reason: String,
    pub authority_sigs: Vec<[u8; 64]>,
}

impl CertRevoke {
    /// Байты, которые подписывает авторитет: всё, кроме списка подписей.
    ///
    /// Без этого метода подпись покрывала бы поле `authority_sigs.len()`, которое на момент
    /// подписания пусто и растёт с каждой добавленной подписью — проверка бы всегда падала.
    /// Та же причина, по которой у `NodeCert` есть `unsigned_body`.
    pub fn unsigned_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.nonce);
        w.u32(self.revoked_at);
        w.string(&self.reason);
        w.into_vec()
    }
}

impl Codec for CertRevoke {
    const KIND: Kind = Kind::CertRevoke;
    const DOMAIN: &'static [u8] = b"vecdht/v8/cert_revoke";

    fn encode_body(&self, w: &mut Writer) {
        w.fixed(&self.nonce);
        w.u32(self.revoked_at);
        w.string(&self.reason);
        w.u16(self.authority_sigs.len() as u16);
        for s in &self.authority_sigs {
            w.fixed(s);
        }
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let nonce = r.fixed()?;
        let revoked_at = r.u32()?;
        let reason = r.string()?;
        let n = r.u16()? as usize;
        if n > 16 {
            return Err(DecodeError::FieldTooLong(n));
        }
        let mut authority_sigs = Vec::with_capacity(n);
        for _ in 0..n {
            authority_sigs.push(r.fixed()?);
        }
        r.expect_end()?;
        Ok(CertRevoke { nonce, revoked_at, reason, authority_sigs })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactAnnounce {
    pub artifact_hash: [u8; 32],
    pub model_version: String,
    pub preprocessing_version: u16,
    pub nlist: u16,
    pub clusters_per_shard: u16,
    pub issued_at: u32,
}

impl Codec for ArtifactAnnounce {
    const KIND: Kind = Kind::ArtifactAnnounce;
    const DOMAIN: &'static [u8] = domain::ARTIFACT;

    fn encode_body(&self, w: &mut Writer) {
        w.fixed(&self.artifact_hash);
        w.string(&self.model_version);
        w.u16(self.preprocessing_version);
        w.u16(self.nlist);
        w.u16(self.clusters_per_shard);
        w.u32(self.issued_at);
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let artifact_hash = r.fixed()?;
        let model_version = r.string()?;
        let preprocessing_version = r.u16()?;
        let nlist = r.u16()?;
        let clusters_per_shard = r.u16()?;
        let issued_at = r.u32()?;
        r.expect_end()?;
        Ok(ArtifactAnnounce {
            artifact_hash,
            model_version,
            preprocessing_version,
            nlist,
            clusters_per_shard,
            issued_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_publish() -> Publish {
        let mut v = [0i8; DIM];
        for (i, x) in v.iter_mut().enumerate() {
            *x = (i as i32 % 251 - 125) as i8;
        }
        Publish {
            preprocessing_version: 3,
            cluster_id: 777,
            vec_q: v,
            owner_ed25519: [0xA1; 32],
            ttl_buckets: 225,
            published_bucket: 1_700_000_000 / 16,
            pow_bits: 24,
            pow_nonce: 0x0102_0304_0506_0708,
            intent_id: [0xB2; 32],
            tlv: vec![],
        }
    }

    fn roundtrip<M: Codec + PartialEq + std::fmt::Debug>(m: &M) {
        let body = m.body_bytes();
        let frame = encode_frame(M::KIND, &body, None);
        let back = M::decode(&frame).unwrap();
        assert_eq!(&back, m);
        // байты тела обязаны воспроизводиться побайтово
        assert_eq!(back.body_bytes(), body);
    }

    #[test]
    fn publish_roundtrip() {
        roundtrip(&sample_publish());
    }

    #[test]
    fn publish_with_reserved_tlv_roundtrip() {
        let mut p = sample_publish();
        p.tlv = vec![(TLV_ROLE_SLOT, vec![0u8])];
        roundtrip(&p);
    }

    #[test]
    fn unknown_tlv_tag_is_ignored_not_fatal() {
        let mut p = sample_publish();
        p.tlv = vec![(0x0FF0, vec![1, 2, 3])];
        // Декод не обязан знать тег: он переносится и не ломает подпись.
        roundtrip(&p);
    }

    #[test]
    fn all_messages_roundtrip() {
        roundtrip(&Handshake {
            role: Role::IndexNode,
            preprocessing_version: 3,
            model_version: "granite-embedding-97m-v2".into(),
            genesis_hash: [1; 32],
            cert: vec![9; 64],
            tlv: vec![],
        });
        roundtrip(&ProtocolError { code: err_code::BUSY.into(), retry_after_ms: 250, shard: 12 });
        roundtrip(&PublishAck {
            shard: 5,
            epoch: 99,
            seq: 1234,
            slot: 77,
            next_pow_bits: 26,
            error_code: "OK".into(),
            retry_after_ms: 0,
        });
        roundtrip(&Find {
            preprocessing_version: 3,
            query_vector: [3i8; DIM],
            clusters: vec![10, 41, 300],
            top_k: 32,
            query_id: 0xDEAD_BEEF_CAFE_1234,
            requester_ed25519: [0xC3; 32],
            tlv: vec![(TLV_BATCH_HINT, vec![1])],
        });
        roundtrip(&MatchResult {
            shard: 5,
            epoch: 99,
            query_id: 1,
            responder_ed25519: [7; 32],
            matches: vec![
                Match { owner_ed25519: [1; 32], cluster_id: 80, d2: 1000, slot: 3 },
                Match { owner_ed25519: [2; 32], cluster_id: 81, d2: 1000, slot: 4 },
                Match { owner_ed25519: [3; 32], cluster_id: 80, d2: 2000, slot: 1 },
            ],
        });
        roundtrip(&IntentTextRequest {
            query_id: 5,
            target_ed25519: [0xEE; 32],
            slot: 41,
            present: vec![0x50; 12],
        });
        roundtrip(&IntentTextResponse {
            owner_ed25519: [1; 32],
            model_version: "granite-embedding-97m-v2".into(),
            preprocessing_version: 3,
            text: b"ishu kontraktent po russkii".to_vec(),
        });
        roundtrip(&WalPullRequest { shard: 5, from_seq: 10, to_seq: 0, max_bytes: 1 << 20 });
        roundtrip(&WalPullResponse {
            shard: 5,
            from_seq: 10,
            to_seq: 12,
            primary_epoch: 3,
            frames: vec![1, 2, 3, 4],
        });
        roundtrip(&ReplicateOp {
            shard: 5,
            epoch: 3,
            seq: 11,
            op_kind: OpKind::Insert,
            body: InsertOp {
                owner_ed25519: [1; 32],
                vec_q: [-2i8; DIM],
                cluster_id: 12,
                published_bucket: 1000,
                ttl_buckets: 225,
            }
            .body_bytes(),
        });
        roundtrip(&LeaseGrant {
            shard: 5,
            epoch: 3,
            primary_ed25519: [0x11; 32],
            dht_peer_id: vec![0x00, 0x24, 0x00],
            expires_at_bucket: 40_000,
        });
        roundtrip(&ReplicateAck {
            shard: 5,
            epoch: 3,
            seq: 11,
            replica_ed25519: [0x22; 32],
            applied_seq: 11,
            ok: true,
        });
        roundtrip(&MembershipUpdate {
            epoch: 4,
            shard: 5,
            members: vec![
                Member { owner_ed25519: [1; 32], dht_peer_id: vec![0xAA; 34], capacity_entries: 100 },
                Member { owner_ed25519: [2; 32], dht_peer_id: vec![0xBB; 34], capacity_entries: 200 },
            ],
            primary_idx: 0,
            generated_at: 999,
            sigs: vec![(0, [7u8; 64]), (1, [8u8; 64])],
        });
        roundtrip(&LeaveNotice { epoch: 4, shard: 5, leaving_owner: [1; 32], drain_deadline_bucket: 100 });
        roundtrip(&RendezvousAccept {
            seeker: [1; 32],
            target: [2; 32],
            shard: 7,
            slot: 41,
            issued_bucket: 99,
            ttl_sec: 300,
        });
        roundtrip(&ArtifactAnnounce {
            artifact_hash: [9; 32],
            model_version: "m".into(),
            preprocessing_version: 1,
            nlist: 1024,
            clusters_per_shard: 16,
            issued_at: 10,
        });
    }

    #[test]
    fn cluster_id_out_of_range_rejected() {
        let mut p = sample_publish();
        p.cluster_id = 1024;
        let frame = p.encode_unsigned();
        assert!(matches!(Publish::decode(&frame), Err(DecodeError::BadEnum { what: "cluster_id", .. })));
    }

    #[test]
    fn intent_text_over_limit_rejected() {
        let m = IntentTextResponse {
            owner_ed25519: [1; 32],
            model_version: "m".into(),
            preprocessing_version: 1,
            text: vec![b'a'; MAX_INTENT_TEXT_BYTES + 1],
        };
        let frame = m.encode_unsigned();
        // Энкoder пишет u16 length-prefix, лимит проверяется на декоде.
        assert!(matches!(IntentTextResponse::decode(&frame), Err(DecodeError::FieldTooLong(_))));
    }

    #[test]
    fn kind_mismatch_between_messages_rejected() {
        let frame = sample_publish().encode_unsigned();
        assert!(Find::decode(&frame).is_err());
    }

    #[test]
    fn match_sort_contract_enforced() {
        let mut m = MatchResult {
            shard: 0,
            epoch: 0,
            query_id: 0,
            responder_ed25519: [0; 32],
            matches: vec![
                Match { owner_ed25519: [1; 32], cluster_id: 0, d2: 5, slot: 1 },
                Match { owner_ed25519: [2; 32], cluster_id: 0, d2: 4, slot: 1 },
            ],
        };
        assert!(m.check_sort_contract().is_err());
        m.matches.reverse();
        assert!(m.check_sort_contract().is_ok());
    }

    #[test]
    fn marks_encode_deterministically() {
        let b = encode_mark(7, 1234);
        assert_eq!(b.len(), 12);
        assert_eq!(decode_mark(&b).unwrap(), (7, 1234));
    }

    #[test]
    fn signature_required_matrix_matches_spec() {
        // §5.3: обязательная подпись
        for k in [
            Kind::MatchResult,
            Kind::IntentTextResponse,
            Kind::ReplicateOp,
            Kind::MembershipUpdate,
            Kind::LeaveNotice,
            Kind::CertRevoke,
            Kind::LeaseGrant,
            Kind::SnapshotOffer,
            Kind::ReplicateAck,
            Kind::RendezvousAccept,
            Kind::ArtifactAnnounce,
        ] {
            assert!(k.signature_required(), "{k:?}");
        }
        // транспортные/подтверждающие — без обязательной подписи
        for k in [Kind::Handshake, Kind::Error, Kind::PublishAck, Kind::IntentTextRequest] {
            assert!(!k.signature_required(), "{k:?}");
        }
        // опциональная подпись на Publish/Find обрабатывается флагом кадра, не матрицей
        assert!(!Kind::Publish.signature_required());
    }

    #[test]
    fn cert_revoke_unsigned_body_excludes_signature_list() {
        let mut r = CertRevoke {
            nonce: [0x01; 16],
            revoked_at: 42,
            reason: "compromised".into(),
            authority_sigs: Vec::new(),
        };
        let before = r.unsigned_body();
        r.authority_sigs.push([0x77; 64]);
        r.authority_sigs.push([0x88; 64]);
        assert_eq!(r.unsigned_body(), before, "подписываемое не зависит от числа подписей");
        assert_ne!(r.body_bytes(), before, "транспортное тело подписи включает");
        let back = CertRevoke::decode(&r.encode_signed(&[0x99; 64])).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn membership_unsigned_body_excludes_signature_list() {
        let mut m = MembershipUpdate {
            epoch: 4,
            shard: 5,
            members: vec![
                Member { owner_ed25519: [1; 32], dht_peer_id: vec![0xAA; 34], capacity_entries: 100 },
                Member { owner_ed25519: [2; 32], dht_peer_id: vec![0xBB; 34], capacity_entries: 200 },
            ],
            primary_idx: 0,
            generated_at: 999,
            sigs: Vec::new(),
        };
        let before = m.unsigned_body();
        m.sigs.push((0, [7u8; 64]));
        m.sigs.push((1, [8u8; 64]));
        assert_eq!(m.unsigned_body(), before, "подписываемое не зависит от числа подписей");
        assert_ne!(m.body_bytes(), before, "транспортное тело подписи включает");
        // Индекс подписанта смотрит в набор epoch−1, а не в новый состав: уходящий участник
        // должен иметь возможность подписать переход, поэтому длину списка здесь проверяет
        // не декодер, а валидатор цепочки. А вот primary обязан быть участником.
        m.sigs.push((9, [9u8; 64]));
        let frame = m.encode_signed(&[0u8; 64]);
        assert_eq!(MembershipUpdate::decode(&frame).unwrap(), m);
        let bad_primary = MembershipUpdate { primary_idx: 2, ..m.clone() };
        assert!(matches!(
            MembershipUpdate::decode(&bad_primary.encode_signed(&[0u8; 64])),
            Err(DecodeError::BadEnum { what: "primary_idx", .. })
        ));
        // Пустой состав (§9.5) переживает кодирование: иначе «объявить шард свободным»
        // было бы нечем.
        let empty = MembershipUpdate { members: Vec::new(), sigs: Vec::new(), ..m };
        roundtrip(&empty);
    }

    #[test]
    fn snapshot_offer_geometry_is_validated_on_decode() {
        let offer = SnapshotOffer {
            shard: 5,
            epoch: 7,
            snapshot_seq: 12,
            oldest_wal_needed: 900,
            applied_seq: 1_024,
            next_slot: 1_000_001,
            time_mark_bucket: 40_000_111,
            total_len: 7,
            offset: 4,
            content_hash: [0xAB; 32],
            chunk: vec![1, 2, 3],
        };
        assert!(offer.is_last_chunk());
        roundtrip(&offer);
        // Кусок за пределами файла.
        let bad = SnapshotOffer { offset: 8, ..offer.clone() };
        assert!(SnapshotOffer::decode(&bad.encode_signed(&[0x55; 64])).is_err());
        // Пустой кусок.
        let empty = SnapshotOffer { chunk: Vec::new(), ..offer.clone() };
        assert!(SnapshotOffer::decode(&empty.encode_signed(&[0x55; 64])).is_err());
        // Чужой шард.
        let other = SnapshotOffer { shard: crate::constants::SHARDS, ..offer };
        assert!(SnapshotOffer::decode(&other.encode_signed(&[0x55; 64])).is_err());
    }

    #[test]
    fn lease_grant_rejects_unknown_shard() {
        let g = LeaseGrant {
            shard: 64,
            epoch: 1,
            primary_ed25519: [0; 32],
            dht_peer_id: vec![],
            expires_at_bucket: 10,
        };
        assert!(matches!(
            LeaseGrant::decode(&g.encode_unsigned()),
            Err(DecodeError::BadEnum { what: "shard", .. })
        ));
        let ok = LeaseGrant { shard: 63, ..g };
        assert_eq!(LeaseGrant::decode(&ok.encode_unsigned()).unwrap(), ok);
    }
}
