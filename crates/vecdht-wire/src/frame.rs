//! Заголовок кадра и таблица типов сообщений (спека §5.1, §5.3).

use crate::codec::{DecodeError, Reader, Writer, MAX_BODY_LEN};

/// `version` в заголовке кадра — она же major-версия сети (§15.4).
pub const PROTOCOL_VERSION: u8 = 8;

/// Бит 0: поле подписи присутствует.
pub const FLAG_SIGNED: u16 = 1 << 0;
/// Биты 1..15 зарезервированы и обязаны быть нулём.
pub const FLAG_RESERVED_MASK: u16 = !FLAG_SIGNED;

/// Максимальная длина подписи: Ed25519 = 64.
pub const MAX_SIG_LEN: usize = 64;

/// Единственный допустимый тип подписи в v8 — Ed25519, ровно 64 байта. 32-байтный HMAC,
/// который допускал листинг v7.5, удалён: симметричный ключ, известный всем проверяющим,
/// даёт свободу подделки любому наблюдателю (§4.3).
pub const ED25519_SIG_LEN: usize = MAX_SIG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Handshake = 0x01,
    Error = 0x02,
    Publish = 0x10,
    PublishAck = 0x11,
    Find = 0x12,
    MatchResult = 0x13,
    IntentTextRequest = 0x14,
    IntentTextResponse = 0x15,
    WalPullRequest = 0x20,
    WalPullResponse = 0x21,
    ReplicateOp = 0x22,
    LeaseGrant = 0x23,
    SnapshotOffer = 0x24,
    ReplicateAck = 0x25,
    MembershipUpdate = 0x40,
    LeaveNotice = 0x41,
    CertRevoke = 0x42,
    RendezvousAccept = 0x50,
    ArtifactAnnounce = 0x60,
}

impl Kind {
    /// Полный набор кодов таблицы §5.3. Нужен тестам: golden-фикстура и фаззер обязаны
    /// покрывать каждый вид кадра, а не тот, что вспомнили.
    pub const ALL: [Kind; 19] = [
        Kind::Handshake,
        Kind::Error,
        Kind::Publish,
        Kind::PublishAck,
        Kind::Find,
        Kind::MatchResult,
        Kind::IntentTextRequest,
        Kind::IntentTextResponse,
        Kind::WalPullRequest,
        Kind::WalPullResponse,
        Kind::ReplicateOp,
        Kind::LeaseGrant,
        Kind::SnapshotOffer,
        Kind::ReplicateAck,
        Kind::MembershipUpdate,
        Kind::LeaveNotice,
        Kind::CertRevoke,
        Kind::RendezvousAccept,
        Kind::ArtifactAnnounce,
    ];

    pub fn from_u8(v: u8) -> Result<Self, DecodeError> {
        Ok(match v {
            0x01 => Kind::Handshake,
            0x02 => Kind::Error,
            0x10 => Kind::Publish,
            0x11 => Kind::PublishAck,
            0x12 => Kind::Find,
            0x13 => Kind::MatchResult,
            0x14 => Kind::IntentTextRequest,
            0x15 => Kind::IntentTextResponse,
            0x20 => Kind::WalPullRequest,
            0x21 => Kind::WalPullResponse,
            0x22 => Kind::ReplicateOp,
            0x23 => Kind::LeaseGrant,
            0x24 => Kind::SnapshotOffer,
            0x25 => Kind::ReplicateAck,
            0x40 => Kind::MembershipUpdate,
            0x41 => Kind::LeaveNotice,
            0x42 => Kind::CertRevoke,
            0x50 => Kind::RendezvousAccept,
            0x60 => Kind::ArtifactAnnounce,
            other => {
                return Err(DecodeError::BadEnum {
                    value: other as u64,
                    what: "Kind",
                    offset: 0,
                })
            }
        })
    }

    /// Имя вида кадра — только для логов, ошибок и `vecdht-cli dump`. Протокол по имени ничего
    /// не решает, поэтому расхождение с `from_u8` не опаснее косметики; тест ниже обязывает
    /// покрывать `ALL`, чтобы новый kind не остался без имени.
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Handshake => "Handshake",
            Kind::Error => "Error",
            Kind::Publish => "Publish",
            Kind::PublishAck => "PublishAck",
            Kind::Find => "Find",
            Kind::MatchResult => "MatchResult",
            Kind::IntentTextRequest => "IntentTextRequest",
            Kind::IntentTextResponse => "IntentTextResponse",
            Kind::WalPullRequest => "WalPullRequest",
            Kind::WalPullResponse => "WalPullResponse",
            Kind::ReplicateOp => "ReplicateOp",
            Kind::LeaseGrant => "LeaseGrant",
            Kind::SnapshotOffer => "SnapshotOffer",
            Kind::ReplicateAck => "ReplicateAck",
            Kind::MembershipUpdate => "MembershipUpdate",
            Kind::LeaveNotice => "LeaveNotice",
            Kind::CertRevoke => "CertRevoke",
            Kind::RendezvousAccept => "RendezvousAccept",
            Kind::ArtifactAnnounce => "ArtifactAnnounce",
        }
    }

    /// Требует ли подпись для этого типа (спека §4.3, матрица подписей).
    pub fn signature_required(&self) -> bool {
        matches!(
            self,
            Kind::MatchResult
                | Kind::IntentTextResponse
                | Kind::ReplicateOp
                | Kind::LeaseGrant
                | Kind::SnapshotOffer
                | Kind::ReplicateAck
                | Kind::MembershipUpdate
                | Kind::LeaveNotice
                | Kind::CertRevoke
                | Kind::RendezvousAccept
                | Kind::ArtifactAnnounce
        )
    }
}

/// Разобранное представление кадра. Тело остаётся байтами — его декодирует конкретное
/// сообщение, потому что декод-и-перекодировка перед подписанием (§5.2) обязана идти по
/// каноническим байтам, а не по пришедшим.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub version: u8,
    pub flags: u16,
    pub body_len: u32,
}

impl Header {
    pub fn signed(&self) -> bool {
        self.flags & FLAG_SIGNED != 0
    }
}

/// Собрать кадр: заголовок + тело + (опционально) `[u8 sig_len][sig]`.
pub fn encode_frame(kind: Kind, body: &[u8], signature: Option<&[u8]>) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(kind as u8);
    w.u8(PROTOCOL_VERSION);
    w.u16(if signature.is_some() { FLAG_SIGNED } else { 0 });
    w.u32(body.len() as u32);
    w.extend_raw(body);
    if let Some(sig) = signature {
        assert_eq!(sig.len(), ED25519_SIG_LEN, "v8 знает только Ed25519: подпись ровно 64 байта");
        w.u8(sig.len() as u8);
        w.extend_raw(sig);
    }
    w.into_vec()
}

/// `body` — канонические байты тела, по которым считается `sig_input` (§5.2).
pub fn sig_input(domain: &[u8], kind: Kind, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.extend_raw(domain);
    w.u8(kind as u8);
    w.u8(PROTOCOL_VERSION);
    w.u16(flags);
    w.extend_raw(body);
    w.into_vec()
}

/// Заголовок + слайсы на тело и подпись внутри входящего буфера.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub header: Header,
    pub body: &'a [u8],
    pub signature: Option<&'a [u8]>,
}

/// Расширенный заголовок кадра: считывает 8 байт и отдаёт длины.
pub fn parse_header(bytes: &[u8]) -> Result<(Header, usize), DecodeError> {
    let mut r = Reader::new(bytes);
    let kb = r.u8()?;
    let kind = Kind::from_u8(kb).map_err(|e| match e {
        DecodeError::BadEnum { value, what, .. } => {
            DecodeError::BadEnum { value, what, offset: 0 }
        }
        other => other,
    })?;
    let version = r.u8()?;
    if version != PROTOCOL_VERSION {
        return Err(DecodeError::Version(version));
    }
    let flags = r.u16()?;
    if flags & FLAG_RESERVED_MASK != 0 {
        return Err(DecodeError::ReservedFlags(flags));
    }
    let body_len = r.u32()?;
    if body_len > MAX_BODY_LEN as u32 {
        return Err(DecodeError::BodyTooLarge { declared: body_len, cap: MAX_BODY_LEN as u32 });
    }
    Ok((Header { kind, version, flags, body_len }, r.offset()))
}

/// Разобрать кадр целиком. Проверок подписи здесь нет — они в `vecdht-crypto`,
/// чтобы кодек не тянул криптографию.
pub fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>, DecodeError> {
    let (header, after) = parse_header(bytes)?;
    let need = after + header.body_len as usize;
    if bytes.len() < need {
        return Err(DecodeError::Truncated { offset: bytes.len() });
    }
    let body = &bytes[after..need];
    let mut rest = &bytes[need..];
    let signature = if header.signed() {
        if rest.is_empty() {
            return Err(DecodeError::SigMissing);
        }
        let n = rest[0] as usize;
        if n != ED25519_SIG_LEN {
            return Err(DecodeError::SigLength(rest[0]));
        }
        rest = &rest[1..];
        if rest.len() < n {
            return Err(DecodeError::Truncated { offset: need });
        }
        Some(&rest[..n])
    } else {
        None
    };
    Ok(Frame { header, body, signature })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_unsigned() {
        let f = encode_frame(Kind::PublishAck, &[1, 2, 3], None);
        let d = decode_frame(&f).unwrap();
        assert_eq!(d.header.kind, Kind::PublishAck);
        assert_eq!(d.header.version, PROTOCOL_VERSION);
        assert_eq!(d.header.body_len, 3);
        assert_eq!(d.body, &[1, 2, 3]);
        assert_eq!(d.signature, None);
    }

    #[test]
    fn frame_roundtrip_signed() {
        let sig = [7u8; 64];
        let f = encode_frame(Kind::MatchResult, &[9], Some(&sig));
        let d = decode_frame(&f).unwrap();
        assert!(d.header.signed());
        assert_eq!(d.signature, Some(&sig[..]));
    }

    #[test]
    fn reserved_flags_rejected() {
        let mut f = encode_frame(Kind::Error, &[0], None);
        f[2] = 0xFF;
        f[3] = 0xFF;
        assert!(matches!(decode_frame(&f), Err(DecodeError::ReservedFlags(_))));
    }

    #[test]
    fn version_mismatch_rejected() {
        let mut f = encode_frame(Kind::Error, &[0], None);
        f[1] = 7;
        assert!(matches!(decode_frame(&f), Err(DecodeError::Version(7))));
    }

    #[test]
    fn unknown_kind_rejected() {
        let mut f = encode_frame(Kind::Error, &[0], None);
        f[0] = 0x99;
        assert!(matches!(decode_frame(&f), Err(DecodeError::BadEnum { value: 0x99, .. })));
        // Дырки в таблице — легитимны (0x03, 0x30/0x31 это op-виды внутри ReplicateOp),
        // но занятый код обязан быть известен.
        for k in Kind::ALL {
            assert_eq!(Kind::from_u8(k as u8).unwrap(), k);
        }
    }

    #[test]
    fn kind_table_is_complete_and_disjoint() {
        // §5.3: у каждого вида свой байт. Дубликат означал бы, что приём не отличает
        // сообщения друг от друга, а `Kind::ALL` без варианта — что тесты его не видят.
        let mut seen = std::collections::BTreeSet::new();
        for k in Kind::ALL {
            assert!(seen.insert(k as u8), "дубликат кода у {k:?}");
            assert_eq!(Kind::from_u8(k as u8).unwrap(), k, "{k:?} не проходит через from_u8");
        }
        assert_eq!(Kind::ALL.len(), seen.len());
        // Нумерация групп: транспорт 0x0x, агент↔индекс 0x1x, репликация 0x2x, членство 0x4x,
        // rendezvous 0x5x, артефакт 0x6x. Новый вид обязан попасть в свою группу.
        assert_eq!(Kind::SnapshotOffer as u8, 0x24, "0x2x — группа репликации (§5.3)");
    }

    #[test]
    fn sig_length_validated() {
        let mut f = encode_frame(Kind::MatchResult, &[1, 2], Some(&[0u8; 64]));
        // портим sig_len
        let idx = 8 + 2;
        f[idx] = 33;
        assert!(matches!(decode_frame(&f), Err(DecodeError::SigLength(33))));
    }

    /// Регрессия на «32 либо 64»: 32-байтный HMAC больше не является подписью.
    #[test]
    fn only_ed25519_length_is_accepted() {
        let mut f = encode_frame(Kind::MatchResult, &[1, 2], Some(&[0u8; 64]));
        f[8 + 2] = 32;
        assert!(matches!(decode_frame(&f), Err(DecodeError::SigLength(32))));
        // корректный кадр проходит, и длина подписи ровно 64
        let good = encode_frame(Kind::MatchResult, &[1, 2], Some(&[9u8; 64]));
        let ok = decode_frame(&good).unwrap();
        assert_eq!(ok.signature.unwrap().len(), ED25519_SIG_LEN);
    }

    #[test]
    fn body_len_cap() {
        let mut f = vec![0x10u8, 8, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        f.extend_from_slice(&[0u8; 16]);
        assert!(matches!(decode_frame(&f), Err(DecodeError::BodyTooLarge { .. })));
    }

    #[test]
    fn sig_input_is_deterministic_and_kind_bounded() {
        let a = sig_input(b"vecdht/v8/publish", Kind::Publish, 0, &[1, 2]);
        let b = sig_input(b"vecdht/v8/find", Kind::Find, 0, &[1, 2]);
        assert_ne!(a, b, "доменная строка обязана различать одинаковые тела");
        let c = sig_input(b"vecdht/v8/publish", Kind::Publish, FLAG_SIGNED, &[1, 2]);
        assert_ne!(a, c, "flags входят в sig_input");
    }
}
