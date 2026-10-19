//! `NodeCert` — application-level кредашиал роли (спека §4.2).
//!
//! Это НЕ форма peer-идентичности: `PeerId` выводит libp2p (§4.1). Кредашиал отвечает только
//! на вопрос «имеет ли право этот пир держать чужие данные».
//!
//! В v7.5 роль выводилась из `peer_id == blake3(pubkey)[..20]`, что требовало бы форка libp2p.

use crate::codec::{DecodeError, Reader, Writer};
use crate::messages::Role;

pub const CERT_VERSION: u16 = 8;

/// Максимальное число шардов в явном списке: wildcard (пустой список) покрывает всю сеть.
pub const MAX_CERT_SHARDS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCert {
    pub version: u16,
    /// blake3 от manifest Model Artifact: кредашиал действует только в этой сети.
    pub genesis_hash: [u8; 32],
    pub role: Role,
    pub owner_ed25519: [u8; 32],
    /// Сериализованный libp2p `PeerId` — байты как их отдаёт libp2p, без нашей деривации.
    pub dht_peer_id: Vec<u8>,
    /// Явный список шардов; пустой список = wildcard (узел готов обслуживать любой).
    pub shards: Vec<u16>,
    pub capacity_entries: u32,
    pub valid_from: u32,
    pub valid_until: u32,
    /// Для отзыва (§4.2) — 16 байт случайных.
    pub nonce: [u8; 16],
    /// Пороговая подпись авторитета: не меньше `t` разных подписей (3-of-5, §15.2).
    ///
    /// Отличие от первоначального листинга §4.2, где было одно поле `authority_sig: [u8;64]`
    /// при правиле «3-of-5»: одна подпись не может выразить порог. Проверка порога
    /// реализована в `vecdht-crypto::cert`.
    pub authority_sigs: Vec<[u8; 64]>,
}

impl NodeCert {
    /// Байты, которые подписывает авторитет: всё, кроме `authority_sigs`.
    pub fn unsigned_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write_unsigned(&mut w);
        w.into_vec()
    }

    fn write_unsigned(&self, w: &mut Writer) {
        w.u16(self.version);
        w.fixed(&self.genesis_hash);
        w.u8(self.role as u8);
        w.fixed(&self.owner_ed25519);
        w.bytes(&self.dht_peer_id);
        w.u16(self.shards.len() as u16);
        for s in &self.shards {
            w.u16(*s);
        }
        w.u32(self.capacity_entries);
        w.u32(self.valid_from);
        w.u32(self.valid_until);
        w.fixed(&self.nonce);
    }

    /// Полный канонический байт кредашиала (для `Handshake.cert` и для хранения).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write_unsigned(&mut w);
        w.u16(self.authority_sigs.len() as u16);
        for s in &self.authority_sigs {
            w.fixed(s);
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version != CERT_VERSION {
            return Err(DecodeError::Version(version as u8));
        }
        let genesis_hash = r.fixed()?;
        let role = Role::from_u8(r.u8()?)?;
        let owner_ed25519 = r.fixed()?;
        let dht_peer_id = r.bytes()?;
        let n = r.u16()? as usize;
        if n > MAX_CERT_SHARDS {
            return Err(DecodeError::FieldTooLong(n));
        }
        let mut shards = Vec::with_capacity(n);
        for _ in 0..n {
            let s = r.u16()?;
            if s >= crate::constants::SHARDS {
                return Err(DecodeError::BadEnum { value: s as u64, what: "shard", offset: 0 });
            }
            shards.push(s);
        }
        let capacity_entries = r.u32()?;
        let valid_from = r.u32()?;
        let valid_until = r.u32()?;
        let nonce = r.fixed()?;
        let ns = r.u16()? as usize;
        if ns > 16 {
            return Err(DecodeError::FieldTooLong(ns));
        }
        let mut authority_sigs = Vec::with_capacity(ns);
        for _ in 0..ns {
            authority_sigs.push(r.fixed()?);
        }
        r.expect_end()?;
        if valid_until <= valid_from {
            return Err(DecodeError::FieldTooLong(0));
        }
        Ok(NodeCert {
            version,
            genesis_hash,
            role,
            owner_ed25519,
            dht_peer_id,
            shards,
            capacity_entries,
            valid_from,
            valid_until,
            nonce,
            authority_sigs,
        })
    }

    pub fn covers_shard(&self, shard: u16) -> bool {
        self.shards.is_empty() || self.shards.contains(&shard)
    }

    pub fn in_validity(&self, now_sec: u32) -> bool {
        now_sec >= self.valid_from && now_sec < self.valid_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NodeCert {
        NodeCert {
            version: CERT_VERSION,
            genesis_hash: [0x11; 32],
            role: Role::IndexNode,
            owner_ed25519: [0x22; 32],
            dht_peer_id: vec![0x00, 0x24, 0x00],
            shards: vec![0, 5, 63],
            capacity_entries: 500_000,
            valid_from: 1_000,
            valid_until: 2_000,
            nonce: [0x33; 16],
            authority_sigs: vec![[0x44; 64], [0x55; 64], [0x66; 64]],
        }
    }

    #[test]
    fn cert_roundtrip_and_canonical_bytes() {
        let c = sample();
        let b = c.encode();
        let back = NodeCert::decode(&b).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.encode(), b, "перекодировка обязана давать те же байты");
    }

    #[test]
    fn unsigned_body_excludes_sigs() {
        let mut c = sample();
        let body = c.unsigned_body();
        c.authority_sigs.push([0x77; 64]);
        assert_eq!(c.unsigned_body(), body, "подписи не входят в подписываемое");
    }

    #[test]
    fn wildcard_covers_every_shard() {
        let mut c = sample();
        c.shards.clear();
        for s in 0..crate::constants::SHARDS {
            assert!(c.covers_shard(s));
        }
        c.shards = vec![7];
        assert!(c.covers_shard(7));
        assert!(!c.covers_shard(8));
    }

    #[test]
    fn validity_half_open() {
        let c = sample();
        assert!(c.in_validity(1_000));
        assert!(c.in_validity(1_999));
        assert!(!c.in_validity(2_000), "valid_until exclusive");
        assert!(!c.in_validity(999));
    }

    #[test]
    fn bad_version_role_and_shard_rejected() {
        let mut b = sample().encode();
        b[0] = 7;
        b[1] = 0;
        assert!(matches!(NodeCert::decode(&b), Err(DecodeError::Version(7))));

        let mut c = sample();
        c.role = Role::Agent;
        let mut b = c.encode();
        // role-байт: 2 (u16 version) + 32 (genesis) = offset 34
        b[34] = 9;
        assert!(matches!(NodeCert::decode(&b), Err(DecodeError::BadEnum { what: "Role", .. })));

        let mut c = sample();
        c.shards = vec![64];
        assert!(c.encode().len() > 0);
        let enc = c.encode();
        assert!(matches!(NodeCert::decode(&enc), Err(DecodeError::BadEnum { what: "shard", .. })));
    }

    #[test]
    fn inverted_validity_window_rejected() {
        let mut c = sample();
        c.valid_from = 5_000;
        c.valid_until = 4_000;
        let enc = c.encode();
        assert!(NodeCert::decode(&enc).is_err());
    }
}
