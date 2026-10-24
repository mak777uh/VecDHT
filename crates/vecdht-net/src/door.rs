//! Именуемая причина отказа двери (§4.2:181, §14.4 (ii):1250, Приложение C:1947, `ADR-0051`).
//!
//! Причина в коде уже существует: `HandshakeError` (`handshake.rs:31…52`) — десять армов с
//! человекочитаемыми `#[error(...)]`, `CertError` (`cert.rs:19…39`) — ещё десять, из них девять
//! достижимы из `verify_cert`. Теряется она в одном месте: `service.rs` вычисляет `&e.to_string()` и
//! отдаёт его в `error_frame(..., _detail)`, который параметр не использует, потому что поля
//! `detail` в `ProtocolError` нет, а расширять канон ради лога запрещено (§5.1: подпись считается по
//! каноническим байтам тела). Замерено на `E-0095`: 19 отказов двумя кадрами, ноль записей с
//! именем причины у отказавшей стороны (`dr_responder_named=0`) и ноль у дозванивающегося
//! (`dr_initiator_named=0`).
//!
//! Здесь причина получает имя — локальное и конечное. Наружу она по-прежнему не уходит: `CERT_INVALID`
//! остаётся единственным кодом для всех причин. Это решение, а не беспомощность, и оно взято по
//! образцу RFC 8446 §6.2, где `bad_record_mac` («alert is used for all deprotection failures»)
//! соседствует с тонкими `certificate_revoked(44)`/`certificate_expired(45)`: причина, уходящая
//! наружу, была бы оракулом для подбора — 22 различных ответа на вопрос «почему отказано» это карта
//! веток двери для того, кто вправе стучаться сколько хочет.
//!
//! Конечность — не обещание, а тип: счётчик индексируется `DoorReason`, а не строкой, поэтому
//! число его записей ограничено числом имён (`ALL`), а не числом отказов. Свободный текст в
//! `errors: Vec<String>` для того же не годится: тот вектор не ограничен ни длиной, ни числом, и
//! завести в нём причину означало бы открыть ровно ту неконечность, которую закрыл `E-0091`.

use std::collections::BTreeMap;

use vecdht_crypto::cert::CertError;

use crate::handshake::HandshakeError;

/// Замкнутый список имён. 22 = девять имён `HandshakeError` (`CertRejected` делегирует вложенному
/// ошибке) + десять имён `CertError` + два отказа, у которых нет своего типа ошибки (`service.rs:643`
/// и `:647`), + `unspecified`.
///
/// Порядок — порядок объявления; `ALL` обязан быть полным, и это проверяется тестом
/// `taxonomy_covers_every_handshake_error_variant` ниже.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DoorReason {
    /// `HandshakeError::GenesisMismatch` — кредашиал из другой сети (§15).
    GenesisMismatch,
    /// `HandshakeError::ModelMismatch` — другая модель предсказаний (§6.6).
    ModelMismatch,
    /// `HandshakeError::PreprocessingMismatch` — другой вектор для одного текста (§6.6).
    PreprocessingMismatch,
    /// `HandshakeError::AgentWithCert` — роль не даёт права нести кредашиал.
    AgentWithCert,
    /// `HandshakeError::MissingCert` — узлу кредашиала не досталось (§4.2).
    MissingCert,
    /// `HandshakeError::BadCert` — тело кредашиала не разобрано (`DecodeError`).
    CertUndecodable,
    /// `HandshakeError::PeerIdMismatch` — кредашиал выдан другому `PeerId`.
    CertPeerIdMismatch,
    /// `HandshakeError::OwnerMismatch` — владелец не совпал с ключом транспорта.
    CertOwnerMismatch,
    /// `HandshakeError::NoOwner` — транспортный ключ не Ed25519. Над QUIC/Noise недостижимо:
    /// граница названа гейтом (11) цикла `E-0095`, имя существует, счётчик на нуле.
    TransportNoOwner,
    /// `CertError::Version` — кредашиал другой версии протокола.
    CertVersionUnsupported,
    /// `CertError::GenesisMismatch` — генезис внутри кредашиала (отличается от заголовка handshake:
    /// это два разных вопроса, и имя у каждого своё).
    CertGenesisMismatch,
    /// `CertError::BelowThreshold` — подписей авторитетов меньше порога. Сюда же приходит
    /// «подписей больше `MAX_AUTHORITY_SIGS`» (`cert.rs:140…141` переиспользует этот арм):
    /// столкновение названо в пороге (4), а не сглажено.
    CertBelowThreshold,
    /// `CertError::NotYetValid` — окно ещё не открылось. Сюда же падает `valid_from > valid_until`.
    CertNotYetValid,
    /// `CertError::Expired` — окно закрылось. §4.2 требует для этого отказа другое действие, чем для
    /// отзыва, поэтому имя обязано быть другим.
    CertExpired,
    /// `CertError::Revoked` — nonce в множестве отзывов (§4.2:181, `E-0094`).
    CertRevoked,
    /// `CertError::ShardNotCovered` — рождается только в `verify_index_cert` (`cert.rs:150…166`),
    /// которую `vecdht-net` не вызывает: имя на нуле по границе, а не по недосмотру.
    CertShardNotCovered,
    /// `CertError::WrongRole` — роль заголовка и роль в кредашиале расходятся (`handshake.rs:152…158`).
    CertWrongRole,
    /// `CertError::ZeroCapacity` — нулевая ёмкость (§9.2).
    CertZeroCapacity,
    /// `CertError::Malformed` — байты кредашиала не каноничны.
    CertMalformed,
    /// Отказ без типа ошибки: узел собственный кредашиал отозвал, и он молчит даже на handshake
    /// (`service.rs:643`).
    SelfCertRevoked,
    /// Отказ без типа ошибки: кадр не разобран до всякого handshake (`service.rs:647`, `BAD_ENUM`).
    FrameUndecodable,
    /// Причина не указана. Отдельное именованное значение по образцу `unspecified(0)` у `ReasonCode`
    /// в RFC 5280 §5.3.1: «причины нет» — это значение, а не отсутствие поля. Ни одна ветка двери в
    /// него не попадает, и проверяется это числом (`dc_unspecified_hits=0`), а не обещанием.
    Unspecified,
}

impl DoorReason {
    /// Полный список имён. Массив, а не `&[DoorReason]`, чтобы длина была частью типа.
    pub const ALL: [DoorReason; 22] = [
        DoorReason::GenesisMismatch,
        DoorReason::ModelMismatch,
        DoorReason::PreprocessingMismatch,
        DoorReason::AgentWithCert,
        DoorReason::MissingCert,
        DoorReason::CertUndecodable,
        DoorReason::CertPeerIdMismatch,
        DoorReason::CertOwnerMismatch,
        DoorReason::TransportNoOwner,
        DoorReason::CertVersionUnsupported,
        DoorReason::CertGenesisMismatch,
        DoorReason::CertBelowThreshold,
        DoorReason::CertNotYetValid,
        DoorReason::CertExpired,
        DoorReason::CertRevoked,
        DoorReason::CertShardNotCovered,
        DoorReason::CertWrongRole,
        DoorReason::CertZeroCapacity,
        DoorReason::CertMalformed,
        DoorReason::SelfCertRevoked,
        DoorReason::FrameUndecodable,
        DoorReason::Unspecified,
    ];

    /// Имя для счётчика и для будущего `admit_drops_total{reason}` (Приложение C:1947). Строка
    /// `'static` намеренно: метка метрики не должна получать жизнь из `format!`.
    pub fn name(&self) -> &'static str {
        match self {
            DoorReason::GenesisMismatch => "genesis_mismatch",
            DoorReason::ModelMismatch => "model_mismatch",
            DoorReason::PreprocessingMismatch => "preprocessing_mismatch",
            DoorReason::AgentWithCert => "agent_with_cert",
            DoorReason::MissingCert => "missing_cert",
            DoorReason::CertUndecodable => "cert_undecodable",
            DoorReason::CertPeerIdMismatch => "cert_peer_id_mismatch",
            DoorReason::CertOwnerMismatch => "cert_owner_mismatch",
            DoorReason::TransportNoOwner => "transport_no_owner",
            DoorReason::CertVersionUnsupported => "cert_version_unsupported",
            DoorReason::CertGenesisMismatch => "cert_genesis_mismatch",
            DoorReason::CertBelowThreshold => "cert_below_threshold",
            DoorReason::CertNotYetValid => "cert_not_yet_valid",
            DoorReason::CertExpired => "cert_expired",
            DoorReason::CertRevoked => "cert_revoked",
            DoorReason::CertShardNotCovered => "cert_shard_not_covered",
            DoorReason::CertWrongRole => "cert_wrong_role",
            DoorReason::CertZeroCapacity => "cert_zero_capacity",
            DoorReason::CertMalformed => "cert_malformed",
            DoorReason::SelfCertRevoked => "self_cert_revoked",
            DoorReason::FrameUndecodable => "frame_undecodable",
            DoorReason::Unspecified => "unspecified",
        }
    }

    /// Отображение ошибки двери в имя. Исчерпывающий `match` без `_ =>`: новый арм в
    /// `HandshakeError` не сможет молча остаться без имени — сборка упадёт. Это и есть то
    /// соответствие модели и кода, которое в `E-0095` проверяется прибором, а не утверждением
    /// (пятый вопрос рубрики Lean, `lab/lean-rubric.md`).
    pub fn from_handshake_error(e: &HandshakeError) -> DoorReason {
        match e {
            HandshakeError::GenesisMismatch => DoorReason::GenesisMismatch,
            HandshakeError::ModelMismatch(_) => DoorReason::ModelMismatch,
            HandshakeError::PreprocessingMismatch(_) => DoorReason::PreprocessingMismatch,
            HandshakeError::AgentWithCert(_) => DoorReason::AgentWithCert,
            HandshakeError::MissingCert(_) => DoorReason::MissingCert,
            HandshakeError::BadCert(_) => DoorReason::CertUndecodable,
            HandshakeError::CertRejected(inner) => DoorReason::from_cert_error(inner),
            HandshakeError::PeerIdMismatch => DoorReason::CertPeerIdMismatch,
            HandshakeError::OwnerMismatch => DoorReason::CertOwnerMismatch,
            HandshakeError::NoOwner => DoorReason::TransportNoOwner,
        }
    }

    /// То же для вложенной ошибки кредашиала: все десять армов, включая недостижимый на этой двери
    /// `ShardNotCovered` — иначе карта веток была бы неполной ровно там, где её проверяют.
    pub fn from_cert_error(e: &CertError) -> DoorReason {
        match e {
            CertError::Version(_) => DoorReason::CertVersionUnsupported,
            CertError::GenesisMismatch { .. } => DoorReason::CertGenesisMismatch,
            CertError::BelowThreshold { .. } => DoorReason::CertBelowThreshold,
            CertError::NotYetValid { .. } => DoorReason::CertNotYetValid,
            CertError::Expired { .. } => DoorReason::CertExpired,
            CertError::Revoked => DoorReason::CertRevoked,
            CertError::ShardNotCovered(_) => DoorReason::CertShardNotCovered,
            CertError::WrongRole(_) => DoorReason::CertWrongRole,
            CertError::ZeroCapacity => DoorReason::CertZeroCapacity,
            CertError::Malformed => DoorReason::CertMalformed,
        }
    }
}

/// Локальный счётчик отказов по именам. Конечен по построению: ключ — `&'static str` из `ALL`,
/// поэтому записей не больше 22, сколько бы отказов ни произошло (гейт (7) цикла `E-0095`).
#[derive(Debug, Clone, Default)]
pub struct DoorLedger {
    counts: BTreeMap<&'static str, u64>,
    total: u64,
}

impl DoorLedger {
    pub fn record(&mut self, reason: DoorReason) {
        *self.counts.entry(reason.name()).or_insert(0) += 1;
        self.total += 1;
    }

    /// Пары `(<имя>, <счётчик>)` в порядке имён. Только ненулевые: пустой счётчик не должен
    /// выглядеть как «причина наблюдалась ноль раз» там, где она просто не происходила.
    pub fn refusals(&self) -> Vec<(&'static str, u64)> {
        self.counts.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub fn count(&self, reason: DoorReason) -> u64 {
        self.counts.get(reason.name()).copied().unwrap_or(0)
    }

    /// Число наблюдавшихся имён, а не число отказов: это и есть мера конечности журнала.
    pub fn entries(&self) -> usize {
        self.counts.len()
    }

    pub fn total(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::codec::DecodeError;
    use vecdht_wire::messages::Role;

    /// По одному значению на каждый прямой арм `HandshakeError` — НАСТОЯЩЕГО enum'а продукта, а не
    /// его пересказ. Если у арма появится новый вложенный тип, этот список перестанет собираться,
    /// и тест не сможет «пройти» молча. Девятый арм `CertRejected(_)` здесь не нужен: он разбирается
    /// в цикле `cert_error_at` ниже, и именно там проверяется, что имя не зависит от пути.
    fn every_handshake_error() -> Vec<HandshakeError> {
        vec![
            HandshakeError::GenesisMismatch,
            HandshakeError::ModelMismatch("1.2.3".to_string()),
            HandshakeError::PreprocessingMismatch(7),
            HandshakeError::AgentWithCert(Role::Agent),
            HandshakeError::MissingCert(Role::IndexNode),
            HandshakeError::BadCert(DecodeError::Truncated { offset: 0 }),
            HandshakeError::NoOwner,
            HandshakeError::PeerIdMismatch,
            HandshakeError::OwnerMismatch,
        ]
    }

    /// `CertError` без `Clone`, поэтому ошибочное значение нельзя взять из вектора дважды:
    /// конструктор по индексу даёт свежий экземпляр каждому из двух путей (`match` полный,
    /// новый арм сместит счётчик и соберётся с паникой в тесте, а не пройдёт молча).
    fn cert_error_at(i: usize) -> CertError {
        match i {
            0 => CertError::Version(9),
            1 => CertError::GenesisMismatch { expected: [1u8; 32], actual: [2u8; 32] },
            2 => CertError::BelowThreshold { have: 1, need: 3 },
            3 => CertError::NotYetValid { now: 1, valid_from: 2 },
            4 => CertError::Expired { now: 5, valid_until: 4 },
            5 => CertError::Revoked,
            6 => CertError::ShardNotCovered(3),
            7 => CertError::WrongRole(Role::Agent),
            8 => CertError::ZeroCapacity,
            9 => CertError::Malformed,
            _ => panic!("cert_error_at: индекс {i} вне списка армов"),
        }
    }

    fn every_cert_error_count() -> usize {
        10
    }

    /// Гейт соответствия «модель ↔ код»: каждая достижимая ошибка двери имеет своё имя, имена
    /// различны, и `ALL` покрывает всё множество.
    #[test]
    fn taxonomy_covers_every_handshake_error_variant() {
        let mut seen: BTreeMap<&'static str, DoorReason> = BTreeMap::new();
        let mut mapped = 0usize;
        for e in every_handshake_error() {
            let r = DoorReason::from_handshake_error(&e);
            assert!(!r.name().is_empty(), "пустое имя у {e:?}");
            assert_ne!(r, DoorReason::Unspecified, "безымянная ветка: {e:?}");
            if let Some(prev) = seen.insert(r.name(), r) {
                assert_eq!(prev, r, "одно имя на два разных DoorReason: {}", r.name());
            }
            mapped += 1;
        }
        for i in 0..every_cert_error_count() {
            let e = cert_error_at(i);
            let r = DoorReason::from_cert_error(&e);
            assert!(!r.name().is_empty(), "пустое имя у {e:?}");
            assert_ne!(r, DoorReason::Unspecified, "безымянная ветка: {e:?}");
            // Ошибка кредашиала, пришедшая через `CertRejected`, обязана именоваться так же, как
            // та же ошибка сама по себе: иначе счётчик зависел бы от пути, а не от причины.
            let via = DoorReason::from_handshake_error(&HandshakeError::CertRejected(cert_error_at(i)));
            assert_eq!(via, r, "имя зависит от пути: {e:?}");
            seen.insert(r.name(), r);
            mapped += 1;
        }
        assert_eq!(mapped, 19, "разобрано не 19 армов (9 + 10)");
        // Дыра, ради которой этот модуль написан: безымянной ветки на двери не осталось.
        assert_eq!(seen.len(), 19, "девятнадцати ошибок дали меньше девятнадцати имён: {seen:?}");

        // ALL полон: покрыты все имена отображений плюс два служебных отказа и unspecified.
        let all: Vec<&'static str> = DoorReason::ALL.iter().map(|r| r.name()).collect();
        assert_eq!(all.len(), 22, "размер ALL разошёлся с типом");
        let mut uniq = all.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), 22, "в ALL есть повтор имени");
        for name in seen.keys() {
            assert!(all.contains(name), "имени {name} нет в ALL");
        }
        for extra in ["self_cert_revoked", "frame_undecodable", "unspecified"] {
            assert!(all.contains(&extra), "в ALL нет служебного имени {extra}");
        }
    }

    /// Столкновения имён — факт кода, а не дефект таксономии, и они названы (порог (4)).
    #[test]
    fn named_collisions_are_the_only_shared_names() {
        // `cert.rs:140…141` переиспользует `BelowThreshold` для «подписей больше предела».
        assert_eq!(
            DoorReason::from_cert_error(&CertError::BelowThreshold { have: 17, need: 3 }),
            DoorReason::CertBelowThreshold
        );
        // `valid_from > valid_until` ловится окном `NotYetValid`, отдельной ветки в коде нет.
        assert_eq!(
            DoorReason::from_cert_error(&CertError::NotYetValid { now: 1, valid_from: 2 }),
            DoorReason::CertNotYetValid
        );
        // `genesis_hash` заголовка и `genesis_hash` кредашиала — разные вопросы: имена обязаны
        // различаться, иначе оператор, видящий «другая сеть», не отличит, где именно сеть другая.
        assert_ne!(
            DoorReason::from_handshake_error(&HandshakeError::GenesisMismatch).name(),
            DoorReason::from_cert_error(&CertError::GenesisMismatch {
                expected: [1u8; 32],
                actual: [2u8; 32]
            })
            .name()
        );
    }

    /// §4.2:181 требует разных действий для трёх случаев — значит, имена у них разные.
    #[test]
    fn revoked_expired_and_below_threshold_are_three_names() {
        let names: BTreeMap<&str, ()> = [
            DoorReason::CertRevoked.name(),
            DoorReason::CertExpired.name(),
            DoorReason::CertBelowThreshold.name(),
        ]
        .into_iter()
        .map(|n| (n, ()))
        .collect();
        assert_eq!(names.len(), 3, "три разных действия схлопнулись в меньшее чем три числа имён");
    }

    /// Конечность журнала: ключ — имя, а не строка, поэтому повторы корпуса не растят число записей.
    #[test]
    fn ledger_is_bounded_by_names_not_by_refusals() {
        let mut l = DoorLedger::default();
        for _ in 0..1_000 {
            l.record(DoorReason::CertExpired);
            l.record(DoorReason::CertRevoked);
        }
        assert_eq!(l.entries(), 2, "журнал растёт числом записей, а не числом имён");
        assert_eq!(l.total(), 2_000, "сумма счётчиков потеряла повторы");
        assert_eq!(l.count(DoorReason::CertExpired), 1_000);
        assert_eq!(l.count(DoorReason::CertMalformed), 0, "несуществующее имя прочиталось как ноль");
        assert!(l.refusals().iter().all(|(_, v)| *v > 0), "в refusals попал нулевой счётчик");
        // Сумма по списку равна общей сумме: «нет неучтённых и нет двойных» проверяется на приборе,
        // а не на живом стенде, где её заслоняет расписание шагов.
        assert_eq!(l.refusals().iter().map(|(_, v)| v).sum::<u64>(), l.total());
    }
}
