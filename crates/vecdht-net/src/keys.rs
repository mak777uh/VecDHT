//! Связь прикладного Ed25519-ключа с libp2p-идентичностью (§4.1).
//!
//! §4.1 запрещает собственную деривацию `PeerId`: транспорт сам аутентифицирует ключ и
//! отдаёт `PeerId`. Здесь ровно обратная операция — из прикладного ключа получить тот же
//! libp2p-ключ, чтобы транспорт аутентифицировал именно владельца, а не отдельную пару.
//! Одна пара на узел/агента: иначе `NodeCert.owner_ed25519` и транспортный ключ могли бы
//! разойтись, и правило 3 §4.2 («владелец == ключ, аутентифицированный транспортом») стало
//! бы непроверяемым.
//!
//! `owner()` — не «наша деривация id», а разбор уже аутентифицированного `PeerId`. Для
//! Ed25519 libp2p кладёт protobuf-ключ в identity-multihash (ключ мал, хешировать нечего),
//! поэтому публичный ключ восстанавливается однозначно. Для остальных multihash (sha256)
//! восстановить ключ нельзя — и это не ошибка транспорта, а сигнал, что такой пир не может
//! быть владельцем записи в v8: `Publish`/`Find` несут 32-байтовый `owner_ed25519`.

use libp2p::identity::Keypair;
use libp2p::PeerId;
use vecdht_crypto::Identity;

/// Тот же секрет, что подписывает кадры v8, в форме, которую принимает libp2p.
pub fn keypair(identity: &Identity) -> Keypair {
    let mut seed = identity.seed();
    let kp = Keypair::ed25519_from_bytes(&mut seed)
        .expect("32-байтовый seed — единственная форма, которую принимает ed25519 libp2p");
    debug_assert_eq!(kp.public().to_peer_id(), PeerId::from_public_key(&kp.public()));
    kp
}

pub fn peer_id(identity: &Identity) -> PeerId {
    keypair(identity).public().to_peer_id()
}

/// Публичный ключ владельца из `PeerId`, если он там лежит целиком.
///
/// Формат: identity-multihash (код 0x00, длина 36) от protobuf
/// `PublicKey{type=Ed25519(1), data=<32 байта>}`. Проверяются все три уровня, потому что
/// «похожие 32 байта» из чужого формата — это не владелец, а подстановка.
pub fn owner(peer: &PeerId) -> Option<[u8; 32]> {
    let mh = peer.as_ref();
    if mh.code() != 0 {
        return None;
    }
    let digest = mh.digest();
    // 0x08 0x01 — поле type=1 (Ed25519), 0x12 0x20 — поле data длины 32.
    if digest.len() != 36 || digest[..4] != [0x08, 0x01, 0x12, 0x20] {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[4..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_node::testing;

    #[test]
    fn the_same_seed_yields_the_same_libp2p_identity_and_the_key_roundtrips() {
        let id = testing::identity(42);
        let peer = peer_id(&id);
        assert_eq!(peer, peer_id(&testing::identity(42)), "ключ детерминирован по сиду");
        assert_ne!(peer, peer_id(&testing::identity(43)));
        // §4.2 правило 3: владелец из PeerId — это ровно прикладной ключ, не его хеш.
        assert_eq!(owner(&peer), Some(id.pubkey()));
    }

    #[test]
    fn a_sha256_peer_id_has_no_recoverable_owner() {
        // Такой PeerId легитимен для libp2p (rsa/secp256k1), но владельцем v8-записи быть не
        // может: 32-байтового ключа в нём нет. Это отказ, а не «возьмём первые 32 байта».
        // 0x12 0x20 — multihash sha2-256 с дайджестом в 32 байта.
        let mut bytes = vec![0x12u8, 0x20];
        bytes.extend_from_slice(&[9u8; 32]);
        let peer = PeerId::from_bytes(&bytes).expect("sha256 PeerId легитимен для libp2p");
        assert_eq!(owner(&peer), None);
    }
}
