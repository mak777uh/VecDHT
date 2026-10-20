//! `Handshake` §4.2/§5.3: кредашиал роли, привязанный к транспорту.
//!
//! Проверка разделена на две части намеренно:
//!
//! * `vecdht-crypto::cert` проверяет *кредашиал* — порог авторитета, срок, genesis, отзыв;
//! * этот модуль проверяет *связку* — `cert.dht_peer_id == remote PeerId` и
//!   `cert.owner_ed25519 == ` ключ, который восстановлен из этого PeerId. Без второй части
//!   валидный кредашиал можно было бы предъявить с чужого соединения: он подписан
//!   авторитетом и потому «настоящий», но выдан не этому пиру.
//!
//! Агент кредашиала не несёт (§4.2): его владелец — транспортный ключ. Поэтому роль
//! `Agent` с непустым `cert` — ошибка, а не «дополнительные данные»: принимать кредашиал,
//! который никто не обязан проверять, значит оставить место для двух разных ответов на
//! вопрос «кто это».
//!
//! Время здесь берётся из системных часов только для срока действия кредашиала. Это
//! локальное решение о соединении, а не replicated-путь: индекс от него не зависит (§9.6).

use libp2p::PeerId;
use thiserror::Error;
use vecdht_crypto::cert::verify_cert;
use vecdht_crypto::AuthoritySet;
use vecdht_wire::cert::NodeCert;
use vecdht_wire::codec::DecodeError;
use vecdht_wire::messages::{Handshake, Role};

use crate::keys;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("другая сеть: genesis_hash не совпал с артефактом")]
    GenesisMismatch,
    #[error("другая модель: {0:?}")]
    ModelMismatch(String),
    #[error("другой preprocessing_version: {0}")]
    PreprocessingMismatch(u16),
    #[error("роль {0:?} не даёт права нести кредашиал")]
    AgentWithCert(Role),
    #[error("роль {0:?} обязана нести кредашиал")]
    MissingCert(Role),
    #[error("кредашиал не разобран: {0}")]
    BadCert(#[from] DecodeError),
    #[error("кредашиал отвергнут: {0}")]
    CertRejected(#[from] vecdht_crypto::cert::CertError),
    #[error("кредашиал выдан другому PeerId")]
    PeerIdMismatch,
    #[error("владелец кредашиала не совпал с ключом транспорта")]
    OwnerMismatch,
    #[error("транспортный ключ не Ed25519/identity: владельца записи не существует")]
    NoOwner,
}

/// Кто стоит за соединением после проверки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub peer: PeerId,
    /// 32-байтовый владелец: `owner_ed25519` из кредашиала либо транспортный ключ агента.
    pub owner: [u8; 32],
    pub role: Role,
    /// `None` только у агента.
    pub cert: Option<NodeCert>,
    /// До какого unix-секундного момента кредашиал действителен. У агента — `None`:
    /// переподключение снова пройдёт handshake.
    pub valid_until: Option<u32>,
}

impl PeerIdentity {
    pub fn covers_shard(&self, shard: u16) -> bool {
        match &self.cert {
            Some(c) => c.covers_shard(shard),
            None => false,
        }
    }
}

/// Параметры локального узла, с которыми сверяется встречный `Handshake`.
pub struct Verifier<'a> {
    pub authorities: &'a AuthoritySet,
    pub genesis_hash: [u8; 32],
    pub model_version: &'a str,
    pub preprocessing_version: u16,
    pub now_sec: u32,
}

/// Собрать своё приветствие. Кредашиал кодируется ровно в том виде, в котором подписан.
pub fn greeting(
    role: Role,
    model_version: &str,
    preprocessing_version: u16,
    genesis_hash: [u8; 32],
    cert: Option<&NodeCert>,
) -> Result<Handshake, HandshakeError> {
    match (role, cert) {
        (Role::Agent, Some(_)) => return Err(HandshakeError::AgentWithCert(role)),
        (Role::Agent, None) | (Role::IndexNode | Role::Relay, Some(_)) => {}
        (other, None) => return Err(HandshakeError::MissingCert(other)),
    }
    Ok(Handshake {
        role,
        preprocessing_version,
        model_version: model_version.to_string(),
        genesis_hash,
        cert: cert.map(NodeCert::encode).unwrap_or_default(),
        tlv: Vec::new(),
    })
}

/// Проверить встречное приветствие.
pub fn verify(
    hs: &Handshake,
    remote: PeerId,
    v: &Verifier<'_>,
) -> Result<PeerIdentity, HandshakeError> {
    if hs.genesis_hash != v.genesis_hash {
        return Err(HandshakeError::GenesisMismatch);
    }
    // §6.6: расхождение версии препроцессинга — это разные векторы для одного текста, то есть
    // разные сети. Молча принять его значило бы сравнивать несравнимое.
    if hs.model_version != v.model_version {
        return Err(HandshakeError::ModelMismatch(hs.model_version.clone()));
    }
    if hs.preprocessing_version != v.preprocessing_version {
        return Err(HandshakeError::PreprocessingMismatch(hs.preprocessing_version));
    }
    let transport_owner = keys::owner(&remote).ok_or(HandshakeError::NoOwner)?;

    match (hs.role, hs.cert.is_empty()) {
        (Role::Agent, true) => Ok(PeerIdentity {
            peer: remote,
            owner: transport_owner,
            role: Role::Agent,
            cert: None,
            valid_until: None,
        }),
        (Role::Agent, false) => Err(HandshakeError::AgentWithCert(Role::Agent)),
        (role, true) => Err(HandshakeError::MissingCert(role)),
        (role, false) => {
            let cert = NodeCert::decode(&hs.cert)?;
            verify_cert(
                &cert,
                v.authorities,
                &v.genesis_hash,
                v.now_sec,
                // Отзывы приходят gossip'ом (§4.2) и живут в узле; сюда передаётся пустое
                // множество до подключения `CertRevoke`-пути. Проверка порога и срока от
                // этого не зависит, а «отозван» без источника отзыва — не проверка.
                |_| false,
            )?;
            if cert.role != role {
                // Роль в заголовке и в кредашиале — два ответа на один вопрос. Расхождение
                // означает, что отправитель выбрал, кому верить, — значит, не верим никому.
                return Err(HandshakeError::CertRejected(
                    vecdht_crypto::cert::CertError::WrongRole(cert.role),
                ));
            }
            if cert.dht_peer_id != remote.to_bytes() {
                return Err(HandshakeError::PeerIdMismatch);
            }
            if cert.owner_ed25519 != transport_owner {
                return Err(HandshakeError::OwnerMismatch);
            }
            let valid_until = cert.valid_until;
            Ok(PeerIdentity {
                peer: remote,
                owner: cert.owner_ed25519,
                role,
                cert: Some(cert),
                valid_until: Some(valid_until),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_node::testing;

    fn cert_for(seed: u8, peer: PeerId, role: Role) -> NodeCert {
        testing::node_cert(seed, peer.to_bytes(), vec![7], role, 0, u32::MAX)
    }

    fn verifier<'a>(authorities: &'a AuthoritySet) -> Verifier<'a> {
        Verifier {
            authorities,
            genesis_hash: testing::genesis_hash(),
            model_version: "granite-test",
            preprocessing_version: testing::PREPROCESSING_VERSION,
            now_sec: 1_000,
        }
    }

    #[test]
    fn a_cert_bound_to_the_transport_passes_and_reports_its_owner() {
        let id = testing::identity(11);
        let peer = keys::peer_id(&id);
        let cert = cert_for(11, peer, Role::IndexNode);
        let hs = greeting(
            Role::IndexNode,
            "granite-test",
            testing::PREPROCESSING_VERSION,
            testing::genesis_hash(),
            Some(&cert),
        )
        .unwrap();
        let authorities = testing::authority_set();
        let v = verifier(&authorities);
        let who = verify(&hs, peer, &v).expect("владелец и транспорт совпадают");
        assert_eq!(who.owner, id.pubkey());
        assert_eq!(who.role, Role::IndexNode);
        assert!(who.covers_shard(7));
        assert!(!who.covers_shard(8));
        assert_eq!(who.valid_until, Some(u32::MAX));
    }

    #[test]
    fn an_agent_needs_no_cert_and_is_its_transport_key() {
        let id = testing::identity(12);
        let peer = keys::peer_id(&id);
        let hs = greeting(
            Role::Agent,
            "granite-test",
            testing::PREPROCESSING_VERSION,
            testing::genesis_hash(),
            None,
        )
        .unwrap();
        let authorities = testing::authority_set();
        let v = verifier(&authorities);
        let who = verify(&hs, peer, &v).unwrap();
        assert_eq!(who.owner, id.pubkey());
        assert_eq!(who.role, Role::Agent);
        assert!(who.cert.is_none());
    }

    #[test]
    fn a_cert_from_another_connection_is_rejected() {
        // Кредашиал настоящий (подписан порогом), но выдан ключу 11, а предъявлен с ключа 12.
        // Без сверки с транспортом это был бы «валидный» чужой пропуск.
        let honest = testing::identity(11);
        let thief = testing::identity(12);
        let cert = cert_for(11, keys::peer_id(&honest), Role::IndexNode);
        let hs = greeting(
            Role::IndexNode,
            "granite-test",
            testing::PREPROCESSING_VERSION,
            testing::genesis_hash(),
            Some(&cert),
        )
        .unwrap();
        let authorities = testing::authority_set();
        let v = verifier(&authorities);
        let err = verify(&hs, keys::peer_id(&thief), &v).unwrap_err();
        assert!(matches!(err, HandshakeError::PeerIdMismatch | HandshakeError::OwnerMismatch));
    }

    #[test]
    fn role_header_must_match_the_cert_and_agents_must_not_carry_one() {
        let id = testing::identity(13);
        let peer = keys::peer_id(&id);
        let cert = cert_for(13, peer, Role::IndexNode);
        assert!(matches!(
            greeting(Role::Agent, "m", 1, [0; 32], Some(&cert)),
            Err(HandshakeError::AgentWithCert(Role::Agent))
        ));
        assert!(matches!(
            greeting(Role::IndexNode, "m", 1, [0; 32], None),
            Err(HandshakeError::MissingCert(Role::IndexNode))
        ));
    }

    #[test]
    fn a_different_preprocessing_version_is_a_different_network() {
        let id = testing::identity(14);
        let peer = keys::peer_id(&id);
        let hs = greeting(
            Role::Agent,
            "granite-test",
            testing::PREPROCESSING_VERSION + 1,
            testing::genesis_hash(),
            None,
        )
        .unwrap();
        let authorities = testing::authority_set();
        let v = verifier(&authorities);
        assert!(matches!(verify(&hs, peer, &v), Err(HandshakeError::PreprocessingMismatch(_))));
    }
}
