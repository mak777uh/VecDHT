//! Lease и epoch как fencing (§9.8).
//!
//! `LeaseGrant` подписывается primary и продлевается раз в `renew_buckets`; `expires_at_bucket` —
//! абсолютный бакет (§9.6), а не дельта, иначе часы реплики решали бы, когда lease истёк.
//! Грант действует только на **принятую** эпоху и только от primary принятого состава
//! (ADR-0016): подпись доказывает владение ключом, а право быть primary — только цепочка
//! `ShardMembership`. Эпоху двигает принятие цепочки (`adopt`), а не lease: старый primary
//! демотируется, когда принимает цепочку с большей эпохой, а до этого его фреймы не проходят
//! fencing на репликах. Отдельного протокола выборов нет: каждый WAL-фрейм несёт `epoch`, а
//! реплика с `epoch < max_epoch_served` фрейм отбрасывает.

use thiserror::Error;
use vecdht_crypto::Identity;
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{Codec, LeaseGrant, domain};

use crate::net::Addr;

/// Имя файла, в котором primary держит действующий грант (§9.8, `ADR-0065`).
///
/// Содержимое — ровно тот массив байтов, что уходит по проводу: отдельной дисковой формы нет,
/// иначе проверка подписи при открытии не значила бы ничего, а расхождение формы диска и провода
/// стало бы второй дверью.
pub const LEASE_FILE: &str = "lease.bin";

/// Предел размера файла: один подписанный кадр `LeaseGrant` вместе с адресом libp2p. Кадр
/// по определению короче, поэтому предел — предохранитель от «файла-списка», а не часть
/// протокола.
pub const LEASE_FILE_MAX: usize = 512;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LeaseError {
    #[error("кадр не разобран: {0}")]
    BadFrame(String),
    #[error("LeaseGrant без подписи — lease некому выдать (§5.3)")]
    MissingSignature,
    #[error("подпись LeaseGrant не проходит по ключу primary")]
    BadSignature,
    #[error("lease для шарда {found}, узел держит {want}")]
    ForeignShard { want: u16, found: u16 },
    #[error("lease уже истёк: now={now} ≥ expires={expires} (§9.8)")]
    Expired { now: u32, expires: u32 },
    #[error("lease из прошлого: epoch={got} < принятой {have}")]
    Stale { got: u64, have: u64 },
    #[error("lease из будущего: epoch={got} > принятой {have} — эпоху двигает членство, а не грант (ADR-0016)")]
    Future { got: u64, have: u64 },
}

/// Действующий lease, как его видит узел: либо «я primary», либо «primary вот этот».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub epoch: u64,
    pub primary: Addr,
    pub expires_at_bucket: u32,
}

impl Lease {
    /// Выдать lease на `epoch` с продолжением на `lease_buckets` бакетов.
    pub fn grant(epoch: u64, primary: Addr, now_bucket: u32, lease_buckets: u32) -> Lease {
        Lease { epoch, primary, expires_at_bucket: now_bucket + lease_buckets }
    }

    #[inline]
    pub fn active_at(&self, now_bucket: u32) -> bool {
        now_bucket < self.expires_at_bucket
    }

    /// Сколько бакетов до истечения — по нему узел решает, пора ли продлевать (§9.8).
    #[inline]
    pub fn remaining(&self, now_bucket: u32) -> u32 {
        self.expires_at_bucket.saturating_sub(now_bucket)
    }

    /// Сообщение-грант. `dht_peer_id` — байты libp2p-адреса primary: транспорт проверяет их с
    /// аутентифицированным PeerId (§4.3), а не мы.
    pub fn to_grant(&self, shard: u16, primary: &Identity, dht_peer_id: Vec<u8>) -> LeaseGrant {
        LeaseGrant {
            shard,
            epoch: self.epoch,
            primary_ed25519: primary.pubkey(),
            dht_peer_id,
            expires_at_bucket: self.expires_at_bucket,
        }
    }

    pub fn from_grant(g: &LeaseGrant) -> Lease {
        Lease {
            epoch: g.epoch,
            primary: g.primary_ed25519,
            expires_at_bucket: g.expires_at_bucket,
        }
    }

    /// Кадрированный подписанный грант для рассылки.
    pub fn signed_frame(&self, shard: u16, primary: &Identity, dht_peer_id: Vec<u8>) -> Vec<u8> {
        let g = self.to_grant(shard, primary, dht_peer_id);
        let body = g.body_bytes();
        let sig = primary.sign_body(domain::LEASE, Kind::LeaseGrant, &body);
        g.encode_signed(&sig)
    }

    /// Принять грант: подпись обязана сходиться с ключом, который заявлен в самом теле —
    /// иначе любой наблюдатель объявляет себя primary. Эпоха — ровно принятая: прошлый грант
    /// это воскресший primary, будущий — попытка сдвинуть эпоху в обход цепочки членства
    /// (ADR-0016); ни тот, ни другой lease не меняют.
    pub fn verify(
        bytes: &[u8],
        shard: u16,
        have_epoch: Option<u64>,
        now_bucket: u32,
    ) -> Result<(Lease, LeaseGrant), LeaseError> {
        let f = decode_frame(bytes).map_err(|e| LeaseError::BadFrame(e.to_string()))?;
        if f.header.kind != Kind::LeaseGrant {
            return Err(LeaseError::BadFrame(format!("kind {:?}", f.header.kind)));
        }
        let g = LeaseGrant::decode(bytes).map_err(|e| LeaseError::BadFrame(e.to_string()))?;
        if g.shard != shard {
            return Err(LeaseError::ForeignShard { want: shard, found: g.shard });
        }
        if !f.header.signed() {
            return Err(LeaseError::MissingSignature);
        }
        let sig = f.signature.ok_or(LeaseError::MissingSignature)?;
        let sig: [u8; 64] = sig.try_into().map_err(|_| LeaseError::BadSignature)?;
        if !vecdht_crypto::verify_body(&g.primary_ed25519, domain::LEASE, Kind::LeaseGrant, f.body, &sig)
            .unwrap_or(false)
        {
            return Err(LeaseError::BadSignature);
        }
        if let Some(have) = have_epoch {
            if g.epoch < have {
                return Err(LeaseError::Stale { got: g.epoch, have });
            }
            if g.epoch > have {
                return Err(LeaseError::Future { got: g.epoch, have });
            }
        }
        if now_bucket >= g.expires_at_bucket {
            return Err(LeaseError::Expired { now: now_bucket, expires: g.expires_at_bucket });
        }
        Ok((Lease::from_grant(&g), g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_artifact::reference_manifest;
    use crate::config::Params;

    fn id(seed: u8) -> Identity {
        Identity::from_seed([seed; 32])
    }

    fn grant(primary: &Identity, epoch: u64, expires: u32) -> Vec<u8> {
        let lease = Lease { epoch, primary: primary.pubkey(), expires_at_bucket: expires };
        lease.signed_frame(0, primary, vec![0xAA; 34])
    }

    #[test]
    fn lease_arithmetic_is_in_buckets_not_seconds() {
        let p = Params::from_manifest(&reference_manifest()).unwrap();
        let l = Lease::grant(3, [1u8; 32], 1_000, p.lease_buckets);
        assert_eq!(l.expires_at_bucket, 1_006, "lease_sec=90 → 6 бакетов по 16 с");
        assert!(l.active_at(1_005));
        assert!(!l.active_at(1_006), "истечение — строгое сравнение: в бакете 1006 lease мёртв");
        assert_eq!(l.remaining(1_004), 2);
        assert_eq!(l.remaining(2_000), 0, "saturating: отрицательного остатка не бывает");
    }

    #[test]
    fn grant_must_be_signed_by_the_key_it_claims() {
        let a = id(21);
        let bytes = grant(&a, 1, 2_000);
        let (l, g) = Lease::verify(&bytes, 0, None, 1_000).unwrap();
        assert_eq!(l.primary, a.pubkey());
        assert_eq!(g.expires_at_bucket, 2_000);

        // Тот же кадр, но заявленный другим ключом: подпись обязана отвалиться.
        let mut tampered = bytes.clone();
        // primary_ed25519 лежит в теле после kind/version/flags/body_len + shard(u16)+epoch(u64).
        let off = 8 + 2 + 8;
        tampered[off..off + 32].copy_from_slice(&[0x99; 32]);
        assert_eq!(
            Lease::verify(&tampered, 0, None, 1_000).unwrap_err(),
            LeaseError::BadSignature,
            "грант, подписанный не тем ключом, которого он объявляет primary, — это не lease"
        );

        // Кадр без подписи.
        let unsigned = {
            let g = LeaseGrant {
                shard: 0,
                epoch: 1,
                primary_ed25519: a.pubkey(),
                dht_peer_id: vec![],
                expires_at_bucket: 2_000,
            };
            g.encode_unsigned()
        };
        assert_eq!(Lease::verify(&unsigned, 0, None, 1_000), Err(LeaseError::MissingSignature));
    }

    #[test]
    fn stale_and_expired_grants_are_refused() {
        let a = id(22);
        let bytes = grant(&a, 5, 2_000);
        assert_eq!(
            Lease::verify(&bytes, 0, Some(7), 1_000),
            Err(LeaseError::Stale { got: 5, have: 7 }),
            "грант из прошлой эпизоды не может отменить уже принятую"
        );
        let (l, g) = Lease::verify(&bytes, 0, Some(5), 1_000)
            .expect("epoch == уже принятая — это возобновление собственного lease, оно легитимно (§9.2)");
        assert_eq!(l, Lease { epoch: 5, primary: a.pubkey(), expires_at_bucket: 2_000 });
        assert_eq!(g.primary_ed25519, a.pubkey());
        assert_eq!(g.dht_peer_id, vec![0xAA; 34]);
        assert_eq!(
            Lease::verify(&bytes, 0, None, 2_000),
            Err(LeaseError::Expired { now: 2_000, expires: 2_000 })
        );
        assert_eq!(
            Lease::verify(&bytes, 3, None, 1_000),
            Err(LeaseError::ForeignShard { want: 3, found: 0 })
        );
    }

    #[test]
    fn a_lease_from_the_future_is_not_adopted() {
        let a = id(24);
        let bytes = grant(&a, 6, 2_000);
        assert_eq!(
            Lease::verify(&bytes, 0, Some(5), 1_000),
            Err(LeaseError::Future { got: 6, have: 5 }),
            "эпоху двигает принятая цепочка членства, а не грант (ADR-0016)"
        );
        // Равенство эпох — по-прежнему легитимное продление, а не «приблизительно та же эпоха».
        assert!(Lease::verify(&bytes, 0, Some(6), 1_000).is_ok());
    }

    #[test]
    fn renew_happens_before_expiry_and_election_is_earlier_than_lease() {
        let p = Params::from_manifest(&reference_manifest()).unwrap();
        let a = id(23);
        let mut l = Lease::grant(1, a.pubkey(), 0, p.lease_buckets);
        // Продление: за `renew_buckets` до истечения.
        while l.remaining(100) <= p.renew_buckets {
            l = Lease::grant(l.epoch, a.pubkey(), 100, p.lease_buckets);
        }
        assert!(l.remaining(100) > p.renew_buckets);
        assert!(p.election_buckets < p.lease_buckets);
    }
}
