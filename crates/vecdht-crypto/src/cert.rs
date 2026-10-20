//! Проверка `NodeCert` и отзывов (спека §4.2, §15.2).
//!
//! Роль даёт не форма ключа, а кредашиал, подписанный порогом авторитетов. Здесь же —
//! единственное место, где порог выражается в коде: в листинге §4.2 было одно поле
//! `authority_sig: [u8; 64]` при правиле «3-of-5», то есть подпись порог выразить не могла.

use crate::sig::verify_domain;
use thiserror::Error;
use vecdht_wire::cert::{NodeCert, MAX_CERT_SHARDS};
use vecdht_wire::messages::{CertRevoke, Role};

pub const DOMAIN_NODE_CERT: &[u8] = b"vecdht/v8/node_cert";
pub const DOMAIN_CERT_REVOKED: &[u8] = b"vecdht/v8/cert_revoke";

/// Максимум подписей в одном кредашиале/отзыве (совпадает с лимитом декадера `NodeCert`).
pub const MAX_AUTHORITY_SIGS: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertError {
    #[error("protocol version {0} is not supported")]
    Version(u16),
    #[error("genesis mismatch: cert says {actual:?}, we are in {expected:?}")]
    GenesisMismatch { expected: [u8; 32], actual: [u8; 32] },
    #[error("cert has {have} valid authority signatures, need {need}")]
    BelowThreshold { have: usize, need: usize },
    #[error("not valid yet: now={now}, valid_from={valid_from}")]
    NotYetValid { now: u32, valid_from: u32 },
    #[error("expired: now={now}, valid_until={valid_until}")]
    Expired { now: u32, valid_until: u32 },
    #[error("cert is revoked by nonce")]
    Revoked,
    #[error("cert does not cover shard {0}")]
    ShardNotCovered(u16),
    #[error("role {0:?} is not allowed here")]
    WrongRole(Role),
    #[error("capacity is zero")]
    ZeroCapacity,
    #[error("malformed cert bytes")]
    Malformed,
}

/// Множество авторитетов genesis-сети. `threshold` — минимум разных ключей, чьи подписи
/// проверились (3-of-5 по умолчанию, §15.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySet {
    pub keys: Vec<[u8; 32]>,
    pub threshold: usize,
}

impl AuthoritySet {
    pub fn new(keys: Vec<[u8; 32]>, threshold: usize) -> Self {
        Self { keys, threshold }
    }

    /// Число подписей из `sigs`, прошедших проверку по `payload`. Дубликаты одним ключом
    /// считаются один раз: порог — это про разные ключи, а не про переупаковку.
    pub fn count_valid(&self, payload: &[u8], domain: &[u8], sigs: &[[u8; 64]]) -> usize {
        let mut used = Vec::with_capacity(self.keys.len());
        let mut n = 0usize;
        for key in &self.keys {
            if used.contains(key) {
                continue;
            }
            if sigs.iter().any(|s| verify_domain(key, domain, payload, s)) {
                used.push(*key);
                n += 1;
            }
        }
        n
    }

    pub fn check(&self, payload: &[u8], domain: &[u8], sigs: &[[u8; 64]]) -> Result<usize, CertError> {
        if self.threshold == 0 || self.keys.len() < self.threshold {
            return Err(CertError::BelowThreshold { have: 0, need: self.threshold });
        }
        let have = self.count_valid(payload, domain, sigs);
        if have >= self.threshold {
            Ok(have)
        } else {
            Err(CertError::BelowThreshold { have, need: self.threshold })
        }
    }
}

/// Выпуск кредашиала стороной авторитета: подпись всего `unsigned_body()` доменом
/// `DOMAIN_NODE_CERT`. Возвращает копию с добавленной подписью.
pub fn sign_cert(cert: &NodeCert, signing_key: &ed25519_dalek::SigningKey) -> NodeCert {
    let mut out = cert.clone();
    let sig = crate::sig::sign_domain(signing_key, DOMAIN_NODE_CERT, &cert.unsigned_body());
    out.authority_sigs.push(sig);
    out
}

/// Та же подпись, но ключом приложения: авторитет в v8 — такой же Ed25519-владелец, и
/// отдельная форма с `SigningKey` нужна только инструментам, которые держат ключ не как
/// [`Identity`](crate::Identity). Две формы вместо одной — потому что `Identity` намеренно не
/// отдаёт наружу приватный ключ.
pub fn sign_cert_identity(cert: &NodeCert, signer: &crate::Identity) -> NodeCert {
    let mut out = cert.clone();
    let sig = signer.sign_domain(DOMAIN_NODE_CERT, &cert.unsigned_body());
    out.authority_sigs.push(sig);
    out
}

/// Полная проверка кредашиала перед тем, как принять соединение или запись.
///
/// `revoked_nonces` — множество отзывов из §4.2; проверка идёт до подписи, потому что
/// корректно подписанный, но отозванный ключ именно та цель отзыва.
pub fn verify_cert(
    cert: &NodeCert,
    authorities: &AuthoritySet,
    genesis_hash: &[u8; 32],
    now_sec: u32,
    revoked_nonces: impl Fn(&[u8; 16]) -> bool,
) -> Result<(), CertError> {
    if cert.version != vecdht_wire::cert::CERT_VERSION {
        return Err(CertError::Version(cert.version));
    }
    if cert.genesis_hash != *genesis_hash {
        return Err(CertError::GenesisMismatch {
            expected: *genesis_hash,
            actual: cert.genesis_hash,
        });
    }
    if cert.capacity_entries == 0 {
        return Err(CertError::ZeroCapacity);
    }
    if cert.shards.len() > MAX_CERT_SHARDS {
        return Err(CertError::Malformed);
    }
    if now_sec < cert.valid_from {
        return Err(CertError::NotYetValid { now: now_sec, valid_from: cert.valid_from });
    }
    if now_sec >= cert.valid_until {
        return Err(CertError::Expired { now: now_sec, valid_until: cert.valid_until });
    }
    if revoked_nonces(&cert.nonce) {
        return Err(CertError::Revoked);
    }
    if cert.authority_sigs.len() > MAX_AUTHORITY_SIGS {
        return Err(CertError::BelowThreshold { have: 0, need: authorities.threshold });
    }
    authorities.check(&cert.unsigned_body(), DOMAIN_NODE_CERT, &cert.authority_sigs)?;
    Ok(())
}

/// `Handshake`-проверка: кредашиал валиден, роль — `IndexNode`, и он покрывает шард, на
/// который идёт запрос (§4.3: сверка с транспортом живёт в `vecdht-node`, потому что там есть
/// аутентифицированный `PeerId`).
pub fn verify_index_cert(
    cert: &NodeCert,
    authorities: &AuthoritySet,
    genesis_hash: &[u8; 32],
    now_sec: u32,
    revoked_nonces: impl Fn(&[u8; 16]) -> bool,
    shard: u16,
) -> Result<(), CertError> {
    verify_cert(cert, authorities, genesis_hash, now_sec, revoked_nonces)?;
    if cert.role != Role::IndexNode {
        return Err(CertError::WrongRole(cert.role));
    }
    if !cert.covers_shard(shard) {
        return Err(CertError::ShardNotCovered(shard));
    }
    Ok(())
}

/// Проверка отзыва: подписан тем же порогом авторитетов, иначе anyone-can-revoke.
pub fn verify_revoke(revoke: &CertRevoke, authorities: &AuthoritySet) -> Result<(), CertError> {
    authorities.check(&revoke.unsigned_body(), DOMAIN_CERT_REVOKED, &revoke.authority_sigs)?;
    Ok(())
}

/// Собрать `CertRevoke` с подписями авторитетов.
pub fn build_revoke(
    nonce: [u8; 16],
    revoked_at: u32,
    reason: &str,
    signing_keys: &[ed25519_dalek::SigningKey],
) -> CertRevoke {
    let mut r = CertRevoke {
        nonce,
        revoked_at,
        reason: reason.to_string(),
        authority_sigs: Vec::new(),
    };
    let body = r.unsigned_body();
    for k in signing_keys {
        r.authority_sigs.push(crate::sig::sign_domain(k, DOMAIN_CERT_REVOKED, &body));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkeys(seeds: &[u8]) -> Vec<[u8; 32]> {
        seeds.iter().map(|&s| key(s).verifying_key().to_bytes()).collect()
    }

    fn cert_base() -> NodeCert {
        NodeCert {
            version: vecdht_wire::cert::CERT_VERSION,
            genesis_hash: [0x11; 32],
            role: Role::IndexNode,
            owner_ed25519: [0x22; 32],
            dht_peer_id: vec![0x00, 0x24, 0x00],
            shards: vec![3],
            capacity_entries: 100_000,
            valid_from: 1_000,
            valid_until: 2_000,
            nonce: [0x33; 16],
            authority_sigs: Vec::new(),
        }
    }

    const GENESIS: [u8; 32] = [0x11; 32];
    const NO_REVOKED: fn(&[u8; 16]) -> bool = |_| false;

    fn five_of_three() -> AuthoritySet {
        AuthoritySet::new(pubkeys(&[1, 2, 3, 4, 5]), 3)
    }

    #[test]
    fn threshold_exactly_met() {
        let a = five_of_three();
        let mut c = cert_base();
        for s in [1u8, 2, 3] {
            c = sign_cert(&c, &key(s));
        }
        assert_eq!(c.authority_sigs.len(), 3);
        assert_eq!(a.count_valid(&c.unsigned_body(), DOMAIN_NODE_CERT, &c.authority_sigs), 3);
        assert_eq!(verify_cert(&c, &a, &GENESIS, 1_500, NO_REVOKED), Ok(()));
    }

    #[test]
    fn one_signature_short_is_rejected() {
        // Прямое отражение расхождения §4.2: одна подпись не выражает 3-of-5.
        let a = five_of_three();
        let mut c = cert_base();
        c = sign_cert(&c, &key(1));
        assert_eq!(
            verify_cert(&c, &a, &GENESIS, 1_500, NO_REVOKED),
            Err(CertError::BelowThreshold { have: 1, need: 3 })
        );
    }

    #[test]
    fn duplicate_signature_from_same_key_does_not_reach_threshold() {
        let a = five_of_three();
        let mut c = cert_base();
        for _ in 0..5 {
            c = sign_cert(&c, &key(2));
        }
        assert_eq!(c.authority_sigs.len(), 5);
        assert_eq!(
            verify_cert(&c, &a, &GENESIS, 1_500, NO_REVOKED),
            Err(CertError::BelowThreshold { have: 1, need: 3 })
        );
    }

    #[test]
    fn unknown_signer_is_not_counted() {
        let a = five_of_three();
        let mut c = cert_base();
        for s in [9u8, 10, 11] {
            c = sign_cert(&c, &key(s));
        }
        assert_eq!(a.count_valid(&c.unsigned_body(), DOMAIN_NODE_CERT, &c.authority_sigs), 0);
        assert!(verify_cert(&c, &a, &GENESIS, 1_500, NO_REVOKED).is_err());
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let a = five_of_three();
        let mut c = cert_base();
        for s in [1u8, 2, 3] {
            c = sign_cert(&c, &key(s));
        }
        c.capacity_entries += 1;
        assert!(verify_cert(&c, &a, &GENESIS, 1_500, NO_REVOKED).is_err());
    }

    #[test]
    fn genesis_validity_and_capacity_are_checked_before_signature() {
        let a = five_of_three();
        let mut c = cert_base();
        for s in [1u8, 2, 3] {
            c = sign_cert(&c, &key(s));
        }
        assert_eq!(
            verify_cert(&c, &a, &[0xEE; 32], 1_500, NO_REVOKED),
            Err(CertError::GenesisMismatch { expected: [0xEE; 32], actual: [0x11; 32] })
        );
        assert!(matches!(
            verify_cert(&c, &a, &GENESIS, 2_000, NO_REVOKED),
            Err(CertError::Expired { .. })
        ));
        assert!(matches!(
            verify_cert(&c, &a, &GENESIS, 999, NO_REVOKED),
            Err(CertError::NotYetValid { .. })
        ));
        let mut zero = c.clone();
        zero.capacity_entries = 0;
        assert_eq!(verify_cert(&zero, &a, &GENESIS, 1_500, NO_REVOKED), Err(CertError::ZeroCapacity));
    }

    #[test]
    fn revoked_nonce_rejects_otherwise_valid_cert() {
        let a = five_of_three();
        let mut c = cert_base();
        for s in [1u8, 2, 3] {
            c = sign_cert(&c, &key(s));
        }
        let nonce = c.nonce;
        let revoked = |n: &[u8; 16]| *n == nonce;
        assert_eq!(verify_cert(&c, &a, &GENESIS, 1_500, revoked), Err(CertError::Revoked));
    }

    #[test]
    fn role_and_shard_scoping() {
        let a = five_of_three();
        let sign_all = |mut c: NodeCert| -> NodeCert {
            for s in [1u8, 2, 3] {
                c = sign_cert(&c, &key(s));
            }
            c
        };
        let revoked = |_: &[u8; 16]| false;
        let c = sign_all(cert_base());
        assert_eq!(verify_index_cert(&c, &a, &GENESIS, 1_500, revoked, 3), Ok(()));
        assert_eq!(
            verify_index_cert(&c, &a, &GENESIS, 1_500, revoked, 4),
            Err(CertError::ShardNotCovered(4))
        );

        // роль входит в подписываемое: агентский кредашиал обязан быть подписан как агентский
        let mut agent_src = cert_base();
        agent_src.role = Role::Agent;
        let agent = sign_all(agent_src);
        assert_eq!(verify_cert(&agent, &a, &GENESIS, 1_500, revoked), Ok(()));
        assert_eq!(
            verify_index_cert(&agent, &a, &GENESIS, 1_500, revoked, 3),
            Err(CertError::WrongRole(Role::Agent))
        );

        // подмена роли после подписи ломает подпись, а не проходит как роль
        let mut forged = c.clone();
        forged.role = Role::Agent;
        assert!(matches!(
            verify_index_cert(&forged, &a, &GENESIS, 1_500, revoked, 3),
            Err(CertError::BelowThreshold { .. })
        ));

        let mut wild_src = cert_base();
        wild_src.shards.clear();
        let wild = sign_all(wild_src);
        assert_eq!(verify_index_cert(&wild, &a, &GENESIS, 1_500, revoked, 63), Ok(()));
    }

    #[test]
    fn cert_survives_wire_roundtrip_after_signing() {
        let mut c = cert_base();
        for s in [1u8, 2, 3] {
            c = sign_cert(&c, &key(s));
        }
        let bytes = c.encode();
        let back = NodeCert::decode(&bytes).unwrap();
        assert_eq!(back, c);
        let a = five_of_three();
        assert_eq!(verify_cert(&back, &a, &GENESIS, 1_500, NO_REVOKED), Ok(()));
    }

    #[test]
    fn revoke_needs_threshold_and_is_verifiable() {
        let a = five_of_three();
        let keys: Vec<SigningKey> = [1u8, 2, 3].iter().map(|&s| key(s)).collect();
        let r = build_revoke([0xAA; 16], 1_234, "compromised", &keys);
        assert_eq!(verify_revoke(&r, &a), Ok(()));

        let weak = build_revoke([0xAA; 16], 1_234, "compromised", &keys[..2]);
        assert!(verify_revoke(&weak, &a).is_err());

        // отзыв, подписанный правильным порогом, но про другое nonce — не покрывает наш ключ
        let other = build_revoke([0xBB; 16], 1_234, "other", &keys);
        assert_eq!(other.nonce, [0xBB; 16]);
        assert_eq!(r.nonce, [0xAA; 16]);
        assert_ne!(r.unsigned_body(), other.unsigned_body());
        assert!(verify_revoke(&other, &a).is_ok());
    }

    #[test]
    fn malformed_authority_sig_count_is_rejected_by_decoder() {
        let mut c = cert_base();
        c.authority_sigs = vec![[0u8; 64]; 17];
        assert!(NodeCert::decode(&c.encode()).is_err());
    }

    #[test]
    fn verify_domain_rejects_wrong_length_pubkey_material() {
        // неканонический pubkey не паникует, а просто не проходит
        let mut bad = [0u8; 32];
        bad[31] = 0x80;
        assert!(!verify_domain(&bad, DOMAIN_NODE_CERT, b"x", &[0u8; 64]));
    }
}
