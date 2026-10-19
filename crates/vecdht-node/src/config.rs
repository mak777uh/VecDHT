//! Параметры узла из манифеста артефакта, приведённые к бакетам (§9.2, §9.4, §9.8).
//!
//! Узел не оперирует секундами wall-clock: `lease_sec = 90` превращается в `lease_buckets = 6`,
//! и все сравнения идут по бакету из `TimeMark`/`LeaseGrant`. Иначе часы узла попадали бы в
//! replicated-путь, что §9.6 запрещает.

use thiserror::Error;
use vecdht_artifact::Manifest;
use vecdht_wire::TIME_BUCKET_SEC;

/// Секунды → бакеты вверх: 30 с при бакете 16 с — это 2 бакета, а не 1 (иначе узел продлевал
/// бы lease вдвое чаще, чем обещает манифест).
#[inline]
pub const fn buckets(sec: u32) -> u32 {
    sec.div_ceil(TIME_BUCKET_SEC)
}

#[inline]
pub const fn bucket_of(sec: u64) -> u32 {
    (sec / TIME_BUCKET_SEC as u64) as u32
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParamError {
    #[error("r={r} < w={w}: кворум записи не соберётся (§9.4)")]
    WAboveR { r: u16, w: u16 },
    #[error("w < 2: без второго держателя это не репликация, а один диск (§9.4)")]
    WTooSmall(u16),
    #[error("r < 2: реплицировать некому")]
    RTooSmall(u16),
    #[error("membership_threshold={0} = 0: цепочка §9.2 без порога — это single-writer")]
    ThresholdZero(u16),
    #[error("lease_sec={lease_sec} не переживает renew_sec={renew_sec}: lease истекает до продления")]
    LeaseTooShort { lease_sec: u32, renew_sec: u32 },
    #[error("election_timeout_sec={election_timeout_sec} ≤ renew_sec={renew_sec}: выборы раньше, чем одно продление")]
    ElectionTooShort { election_timeout_sec: u32, renew_sec: u32 },
    #[error("bucket_sec={0}: узел понимает только бакет из спеки (§9.6)")]
    BucketSec(u32),
    #[error("time_mark_every=0: TimeMark обязан писаться, иначе экспирация не определена (§9.6)")]
    TimeMarkEveryZero,
    #[error("pow bits {def} вне [{min}; {max}]: манифест требует сложность, которую узел не может ни выдать, ни проверить")]
    PowRange { def: u32, min: u32, max: u32 },
}

/// То, что узел читает из артефакта и с чем живёт. `Copy`, чтобы обработчики не держали
/// `Arc<Params>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Членов на шард (§9.3).
    pub r: usize,
    /// Подтверждений для записи (§9.4), включая самого primary.
    pub w: usize,
    /// Порог подписей членства от предыдущего множества (§9.2).
    pub membership_threshold: usize,
    /// Порог подписей авторитета для genesis (§9.2, §15.2).
    pub authority_threshold: usize,
    pub lease_buckets: u32,
    pub renew_buckets: u32,
    /// Partition-detiction: тишина дольше этого срока — повод выбирать нового primary.
    pub election_buckets: u32,
    /// Каждые N применённых опсов — `TimeMark` (§9.6).
    pub time_mark_every: u64,
    /// Сложность PoW, которую узел требует от publish и возвращает в `next_pow_bits` (§11.2).
    pub pow_bits: u8,
    pub pow_bits_min: u8,
    pub pow_bits_max: u8,
    /// Потолок живых записей на шард (§13.2 `admission.max_live_per_shard`) — по нему primary
    /// отвечает `SHARD_FULL`, а не начинает вытеснять чужие записи.
    pub max_live_per_shard: u64,
    /// Потолок `top_k` в `Find` (§7.5): без него один запрос может вытащить из индекса всё.
    pub top_k_max: u16,
}

impl Params {
    pub fn from_manifest(m: &Manifest) -> Result<Self, ParamError> {
        let rep = &m.replication;
        if rep.r < 2 {
            return Err(ParamError::RTooSmall(rep.r));
        }
        if rep.w < 2 {
            return Err(ParamError::WTooSmall(rep.w));
        }
        if rep.w > rep.r {
            return Err(ParamError::WAboveR { r: rep.r, w: rep.w });
        }
        if rep.membership_threshold == 0 {
            return Err(ParamError::ThresholdZero(rep.membership_threshold));
        }
        if rep.lease_sec <= rep.renew_sec {
            return Err(ParamError::LeaseTooShort {
                lease_sec: rep.lease_sec,
                renew_sec: rep.renew_sec,
            });
        }
        if rep.election_timeout_sec <= rep.renew_sec {
            return Err(ParamError::ElectionTooShort {
                election_timeout_sec: rep.election_timeout_sec,
                renew_sec: rep.renew_sec,
            });
        }
        if m.time.bucket_sec != TIME_BUCKET_SEC {
            return Err(ParamError::BucketSec(m.time.bucket_sec));
        }
        if m.time.time_mark_every == 0 {
            return Err(ParamError::TimeMarkEveryZero);
        }
        // Политический пол («не ниже 24») живёт в `Manifest::check` (§11.2): узел обязан
        // следовать зафиксированному артефакту, а не собственные константы, иначе тестовая сеть
        // с другой сложностью стала бы невозможной, а боевая — проверяемой на двух местах сразу.
        let pow = &m.power;
        let ok = pow.pow_bits_default >= pow.pow_bits_min
            && pow.pow_bits_default <= pow.pow_bits_max
            && pow.pow_bits_min >= 1
            && pow.pow_bits_max <= 64;
        if !ok {
            return Err(ParamError::PowRange {
                def: pow.pow_bits_default,
                min: pow.pow_bits_min,
                max: pow.pow_bits_max,
            });
        }
        Ok(Params {
            r: rep.r as usize,
            w: rep.w as usize,
            membership_threshold: rep.membership_threshold as usize,
            authority_threshold: m.authority.threshold as usize,
            lease_buckets: buckets(rep.lease_sec),
            renew_buckets: buckets(rep.renew_sec),
            election_buckets: buckets(rep.election_timeout_sec),
            time_mark_every: m.time.time_mark_every as u64,
            pow_bits: pow.pow_bits_default as u8,
            pow_bits_min: pow.pow_bits_min as u8,
            pow_bits_max: pow.pow_bits_max as u8,
            max_live_per_shard: m.admission.max_live_per_shard,
            top_k_max: m.query.top_k_max,
        })
    }

    /// Сколько ack нужно собрать реплике, чтобы primary считал запись подтверждённой.
    /// Primary засчитывает собственный fsync, поэтому остальных — `w - 1` (§9.4).
    #[inline]
    pub fn peer_acks_needed(&self) -> usize {
        self.w - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_round_up_to_buckets() {
        assert_eq!(buckets(16), 1);
        assert_eq!(buckets(30), 2);
        assert_eq!(buckets(32), 2);
        assert_eq!(buckets(90), 6);
        assert_eq!(buckets(60), 4);
        assert_eq!(buckets(0), 0);
        assert_eq!(bucket_of(1_700_000_016), 106_250_001);
    }

    #[test]
    fn reference_manifest_yields_the_spec_numbers() {
        let p = Params::from_manifest(&vecdht_artifact::reference_manifest()).unwrap();
        // §9.3/§9.4: R=3, W=2, t=2; §9.8: lease 90 с, renew 30 с, election 60 с.
        assert_eq!((p.r, p.w, p.membership_threshold, p.authority_threshold), (3, 2, 2, 3));
        assert_eq!((p.lease_buckets, p.renew_buckets, p.election_buckets), (6, 2, 4));
        assert_eq!(p.time_mark_every, 512);
        assert_eq!(p.peer_acks_needed(), 1);
        // §11.2: сложность берётся из артефакта, а не из константы кода. Сами числа при этом
        // сверяются с константами — `[P0]`-калибровка сдвигает диапазон, и литерал в тесте
        // протух бы на первом же пересняте.
        assert_eq!(
            (u32::from(p.pow_bits), u32::from(p.pow_bits_min), u32::from(p.pow_bits_max)),
            (
                vecdht_crypto::pow::POW_BITS_DEFAULT,
                vecdht_crypto::pow::POW_BITS_MIN,
                vecdht_crypto::pow::POW_BITS_MAX
            )
        );
        assert_eq!(p.max_live_per_shard, 2_000_000);
        assert_eq!(p.top_k_max, 64);
        // Продление обязано случаться до истечения, иначе handoff идёт по election, а не по lease.
        assert!(p.renew_buckets < p.lease_buckets);
        assert!(p.election_buckets < p.lease_buckets);
    }

    #[test]
    fn inconsistent_replication_is_rejected_not_silently_tolerated() {
        let base = vecdht_artifact::reference_manifest();
        let mut m = base.clone();
        m.replication.w = 4;
        assert_eq!(
            Params::from_manifest(&m),
            Err(ParamError::WAboveR { r: 3, w: 4 }),
            "W>R означает кворум, который никогда не наступит"
        );
        let mut m = base.clone();
        m.replication.w = 1;
        assert_eq!(Params::from_manifest(&m), Err(ParamError::WTooSmall(1)));
        let mut m = base.clone();
        m.replication.membership_threshold = 0;
        assert_eq!(Params::from_manifest(&m), Err(ParamError::ThresholdZero(0)));
        let mut m = base.clone();
        m.replication.lease_sec = 30;
        assert_eq!(
            Params::from_manifest(&m),
            Err(ParamError::LeaseTooShort { lease_sec: 30, renew_sec: 30 }),
            "lease равный интервалу продления истекает в том же тике, где продлевается"
        );
        let mut m = base.clone();
        m.time.bucket_sec = 15;
        assert_eq!(Params::from_manifest(&m), Err(ParamError::BucketSec(15)));
        let mut m = base;
        m.time.time_mark_every = 0;
        assert_eq!(Params::from_manifest(&m), Err(ParamError::TimeMarkEveryZero));
        let mut m = vecdht_artifact::reference_manifest();
        // Число берётся от диапазона: тест про «default ниже min этого же артефакта», а не про
        // конкретные биты, которые переснимает замер (§11.2).
        let too_easy = vecdht_crypto::pow::POW_BITS_MIN - 1;
        m.power.pow_bits_default = too_easy;
        assert_eq!(
            Params::from_manifest(&m),
            Err(ParamError::PowRange {
                def: too_easy,
                min: vecdht_crypto::pow::POW_BITS_MIN,
                max: vecdht_crypto::pow::POW_BITS_MAX
            }),
            "сложность ниже заявленного диапазона артефакта — это не «чуть дешевле», а манифест, \
             который узел не умеет обслуживать"
        );
    }

    #[test]
    fn cheap_difficulty_is_a_valid_artifact_choice_not_a_code_bug() {
        // Харнес гейтов P4 майнит PoW; при 24 битах тест превращается в бенчмарк blake3.
        // Узел обязан подчиняться артефакту, поэтому дешёвая сложность проходит `from_manifest`.
        let mut m = vecdht_artifact::reference_manifest();
        m.power.pow_bits_default = 8;
        m.power.pow_bits_min = 8;
        let p = Params::from_manifest(&m).unwrap();
        assert_eq!(p.pow_bits, 8);
    }
}
