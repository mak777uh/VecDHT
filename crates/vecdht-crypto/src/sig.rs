//! Подписи и идентичность приложения (спека §4.3, §5.2).
//!
//! `PeerId` остаётся тем, что выводит libp2p (§4.1) — здесь нет собственной деривации id.
//! Здесь есть только Ed25519-ключ агента/узла и доменно-разделённое подписание канонических
//! байтов тела.

use ed25519_dalek::{Signature, Signer, VerifyingKey, SigningKey};
use thiserror::Error;
use vecdht_wire::frame::{Kind, FLAG_SIGNED};
use vecdht_wire::sig_input;

/// Максимум, что мы когда-либо подписываем: тело сообщения. Подпись — по blake3 от
/// канонических байтов, а не по самим байтам: фиксированная длина входа и защита от
/// length-extension-рассуждений.
pub fn sig_digest(domain: &[u8], kind: Kind, flags: u16, body: &[u8]) -> [u8; 32] {
    *blake3::hash(&sig_input(domain, kind, flags, body)).as_bytes()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigError {
    #[error("invalid ed25519 public key")]
    BadPublicKey,
    #[error("signature verification failed")]
    Invalid,
}

/// Локальная идентичность: одна Ed25519-пара. Роль даёт не форма ключа, а `NodeCert` (§4.2).
#[derive(Debug, Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn generate<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        Self { signing: SigningKey::generate(rng) }
    }

    pub fn pubkey(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Подписать каноническое тело сообщения (flag SIGNED в заголовке).
    pub fn sign_body(&self, domain: &[u8], kind: Kind, body: &[u8]) -> [u8; 64] {
        let digest = sig_digest(domain, kind, FLAG_SIGNED, body);
        self.signing.sign(&digest).to_bytes()
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }
}

/// Произвольное доменное подписание (например, для `ShardMembership`-цепочки, где подписывается
/// не кадр, а структура данных).
pub fn sign_domain(signing: &SigningKey, domain: &[u8], payload: &[u8]) -> [u8; 64] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(payload);
    signing.sign(&h.finalize().as_bytes()[..]).to_bytes()
}

pub fn verify_domain(pubkey: &[u8; 32], domain: &[u8], payload: &[u8], sig: &[u8; 64]) -> bool {
    match verifying(pubkey) {
        Ok(vk) => {
            let mut h = blake3::Hasher::new();
            h.update(domain);
            h.update(payload);
            let digest = *h.finalize().as_bytes();
            vk.verify_strict(&digest, &Signature::from_bytes(sig)).is_ok()
        }
        Err(_) => false,
    }
}

/// Проверка подписи сообщения. `owner` — публичный ключ, который обязан соответствовать
/// подписанту (транспорт уже аутентифицировал пира, но агент сверяет его с `Match{owner}`).
pub fn verify_body(
    owner: &[u8; 32],
    domain: &[u8],
    kind: Kind,
    body: &[u8],
    sig: &[u8; 64],
) -> Result<bool, SigError> {
    let vk = verifying(owner)?;
    let digest = sig_digest(domain, kind, FLAG_SIGNED, body);
    Ok(vk.verify_strict(&digest, &Signature::from_bytes(sig)).is_ok())
}

pub fn verifying(pubkey: &[u8; 32]) -> Result<VerifyingKey, SigError> {
    VerifyingKey::from_bytes(pubkey).map_err(|_| SigError::BadPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::messages::{Codec, Match, MatchResult};
    #[allow(unused_imports)]
    use vecdht_wire::messages::domain;

    fn key(seed: u8) -> Identity {
        Identity::from_seed([seed; 32])
    }

    #[test]
    fn sign_and_verify_message_body() {
        let id = key(1);
        let body = vec![1, 2, 3, 4];
        let sig = id.sign_body(b"vecdht/v8/match", Kind::MatchResult, &body);
        assert!(verify_body(&id.pubkey(), b"vecdht/v8/match", Kind::MatchResult, &body, &sig).unwrap());
    }

    #[test]
    fn tampered_body_or_domain_fails() {
        let id = key(2);
        let body = vec![1, 2, 3];
        let sig = id.sign_body(b"vecdht/v8/match", Kind::MatchResult, &body);
        let mut bad = body.clone();
        bad[0] ^= 1;
        assert!(!verify_body(&id.pubkey(), b"vecdht/v8/match", Kind::MatchResult, &bad, &sig).unwrap());
        assert!(!verify_body(&id.pubkey(), b"vecdht/v8/find", Kind::Find, &body, &sig).unwrap());
        assert!(!verify_body(&[9u8; 32], b"vecdht/v8/match", Kind::MatchResult, &body, &sig).unwrap());
    }

    #[test]
    fn kind_confusion_is_rejected() {
        // Одно и то же тело, подписанное как MatchResult, не проходит как Find.
        let id = key(3);
        let body = vec![7u8; 64];
        let sig = id.sign_body(b"vecdht/v8/match", Kind::MatchResult, &body);
        assert!(!verify_body(&id.pubkey(), domain::FIND, Kind::Find, &body, &sig).unwrap());
    }

    #[test]
    fn suspicious_pubkeys_are_rejected_without_panicking() {
        // ed25519-dalek 2.x проверяет точку при верификации, а не при разборе ключа, поэтому
        // допустимы оба отказа: Err(BadPublicKey) и Ok(false). Запрещён только один исход —
        // Ok(true) для подписи, сделанной настоящим ключом.
        let id = key(4);
        let body = vec![1];
        let sig = id.sign_body(b"vecdht/v8/match", Kind::MatchResult, &body);
        let mut zero = [0u8; 32];
        zero[31] = 0x80;
        let mut small_order = [0u8; 32];
        small_order[0] = 0x01; // точка порядка 1 (identity)
        for bad in [zero, [0xFFu8; 32], small_order] {
            let r = verify_body(&bad, b"vecdht/v8/match", Kind::MatchResult, &body, &sig);
            assert_ne!(r, Ok(true), "подделка не должна проходить");
        }
        // настоящий ключ проходит
        assert_eq!(verify_body(&id.pubkey(), b"vecdht/v8/match", Kind::MatchResult, &body, &sig), Ok(true));
    }

    #[test]
    fn domain_signing_for_membership_chain() {
        let id = key(5);
        let payload = b"membership-payload";
        let signing = SigningKey::from_bytes(&id.seed());
        let sig = sign_domain(&signing, b"vecdht/v8/member", payload);
        assert!(verify_domain(&id.pubkey(), b"vecdht/v8/member", payload, &sig));
        assert!(!verify_domain(&id.pubkey(), b"vecdht/v8/member", b"other", &sig));
    }

    #[test]
    fn signed_match_result_frame_roundtrip() {
        let id = key(6);
        let m = MatchResult {
            shard: 1,
            epoch: 2,
            query_id: 3,
            responder_ed25519: id.pubkey(),
            matches: vec![Match { owner_ed25519: [1; 32], cluster_id: 2, d2: 5, slot: 6 }],
        };
        let body = m.body_bytes();
        let sig = id.sign_body(MatchResult::DOMAIN, MatchResult::KIND, &body);
        let frame = m.encode_signed(&sig);
        let decoded = vecdht_wire::decode_frame(&frame).unwrap();
        assert!(decoded.header.signed());
        assert_eq!(decoded.signature.unwrap().len(), 64);
        let back = MatchResult::decode(&frame).unwrap();
        assert_eq!(back, m);
        assert!(verify_body(
            &id.pubkey(),
            MatchResult::DOMAIN,
            MatchResult::KIND,
            &back.body_bytes(),
            sig.as_slice().try_into().unwrap()
        )
        .unwrap());
    }
}
