//! Publish PoW, привязанный к контексту (спека §11.1, §11.2).
//!
//! v7.5 использовала Argon2id для NodeID-PoW (24 бита ≈ дни, а не «2–5 с») и blake3 на 20 бит
//! для publish («~60 с» вместо реальных 1–2 мс). В v8 Argon2id удалён целиком: стоимость
//! записи даёт blake3 с привязкой nonce к `(shard, epoch, slot_key, expires_bucket)`.

use thiserror::Error;
use vecdht_wire::Writer;

pub const POW_DOMAIN: &[u8] = b"vecdht/v8/pow";

/// Адаптивный диапазон сложности (§11.2).
pub const POW_BITS_DEFAULT: u32 = 24;
pub const POW_BITS_MIN: u32 = 24;
pub const POW_BITS_MAX: u32 = 28;

/// Бюджет blake3 на 64-байтных входах, если артефакт ещё не откалиброван `[P0]`.
pub const BLAKE3_MHZ_CORE_FALLBACK: f64 = 200.0;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PowError {
    #[error("pow bits {0} outside [{min}; {max}]", min = POW_BITS_MIN, max = POW_BITS_MAX)]
    BitsOutOfRange(u32),
    #[error("pow not found within {0} attempts")]
    Exhausted(u64),
}

/// Канонический вход PoW. Привязка означает, что nonce, нафармленный для одного
/// шарда/эпизода/слота, не переиспользуется ни в каком другом, и нельзя нафармить впрок
/// за пределы TTL.
pub fn pow_input(
    owner_ed25519: &[u8; 32],
    shard: u16,
    epoch: u64,
    slot_key: &[u8; 32],
    expires_bucket: u32,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.extend_raw(POW_DOMAIN);
    w.fixed(owner_ed25519);
    w.u16(shard);
    w.u64(epoch);
    w.fixed(slot_key);
    w.u32(expires_bucket);
    w.into_vec()
}

/// Проверка: один blake3, ~5 нс.
pub fn pow_ok(input: &[u8], nonce: u64, bits: u32) -> bool {
    if bits == 0 || bits > 64 {
        return false;
    }
    let mut buf = Vec::with_capacity(input.len() + 8);
    buf.extend_from_slice(input);
    buf.extend_from_slice(&nonce.to_le_bytes());
    let h = blake3::hash(&buf);
    let x = u64::from_be_bytes(h.as_bytes()[..8].try_into().unwrap());
    let target = if bits >= 64 { 0 } else { 1u64 << (64 - bits) };
    x < target
}

/// Перебор с детерминированным стартом: `start` позволяет тестам не зависеть от RNG,
/// а боевой код передаёт свежее случайное число, чтобы разные пиры не толкались в одном
/// префиксе пространства.
pub fn mine_pow(input: &[u8], bits: u32, start: u64, max_attempts: u64) -> Result<u64, PowError> {
    if !(POW_BITS_MIN..=POW_BITS_MAX).contains(&bits) {
        return Err(PowError::BitsOutOfRange(bits));
    }
    for k in 0..max_attempts {
        let nonce = start.wrapping_add(k);
        if pow_ok(input, nonce, bits) {
            return Ok(nonce);
        }
    }
    Err(PowError::Exhausted(max_attempts))
}

/// Оценка стоимости publish в мс для данного железа (используется CLI и калибровкой артефакта).
pub fn expected_millis(bits: u32, blake3_mhz_core: f64) -> f64 {
    let attempts = (1u128 << bits) as f64;
    attempts / (blake3_mhz_core * 1e6) * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Vec<u8> {
        pow_input(&[0xA1; 32], 7, 3, &[0xB2; 32], 1234)
    }

    #[test]
    fn input_is_context_bound() {
        let base = input();
        let owner2 = pow_input(&[0xA2; 32], 7, 3, &[0xB2; 32], 1234);
        assert_ne!(base, owner2);
        assert_ne!(base, pow_input(&[0xA1; 32], 8, 3, &[0xB2; 32], 1234), "шард");
        assert_ne!(base, pow_input(&[0xA1; 32], 7, 4, &[0xB2; 32], 1234), "эпоха");
        assert_ne!(base, pow_input(&[0xA1; 32], 7, 3, &[0xB3; 32], 1234), "слот");
        assert_ne!(base, pow_input(&[0xA1; 32], 7, 3, &[0xB2; 32], 1235), "истечение");
        assert_eq!(base.len(), 32 + 2 + 8 + 32 + 4 + POW_DOMAIN.len());
    }

    #[test]
    fn low_bits_found_quickly_and_verifies() {
        // 12 бит для теста скорости; боевой диапазон проверяется отдельно и специально долго.
        let nonce = {
            let mut found = None;
            for k in 0..200_000u64 {
                if pow_ok(&input(), k, 12) {
                    found = Some(k);
                    break;
                }
            }
            found.expect("12 бит обязаны найтись за 200k попыток")
        };
        assert!(pow_ok(&input(), nonce, 12));
    }

    #[test]
    fn nonce_does_not_transfer_between_contexts() {
        // Найденный для одного контекста nonce почти наверняка не годится для другого.
        let i1 = input();
        let i2 = pow_input(&[0xA1; 32], 8, 3, &[0xB2; 32], 1234);
        let mut transferred = 0;
        for k in 0..20_000u64 {
            if pow_ok(&i1, k, 12) && pow_ok(&i2, k, 12) {
                transferred += 1;
            }
        }
        assert!(transferred <= 2, "переиспользование nonce между контекстами должно быть событием редким: {transferred}");
    }

    #[test]
    fn bits_are_monotone_in_difficulty() {
        // Проверка статистическая, но на малой выборке: чем больше бит, тем меньше успехов.
        let i = input();
        let mut c12 = 0;
        let mut c16 = 0;
        for k in 0..20_000u64 {
            if pow_ok(&i, k, 12) {
                c12 += 1;
            }
            if pow_ok(&i, k, 16) {
                c16 += 1;
            }
        }
        assert!(c12 > c16 * 8, "ожидали ~16× реже: c12={c12} c16={c16}");
    }

    #[test]
    fn boundary_bits_rejected() {
        assert_eq!(mine_pow(&input(), 23, 0, 1), Err(PowError::BitsOutOfRange(23)));
        assert_eq!(mine_pow(&input(), 29, 0, 1), Err(PowError::BitsOutOfRange(29)));
        assert!(!pow_ok(&input(), 1, 0));
        assert!(!pow_ok(&input(), 1, 65));
    }

    #[test]
    fn cost_estimate_matches_spec_arithmetic() {
        // §11.1: 2^24 попыток при 200 MH/s ≈ 84 мс.
        let ms = expected_millis(24, BLAKE3_MHZ_CORE_FALLBACK);
        assert!((80.0..=90.0).contains(&ms), "{ms}");
        // 2^28 ≈ 1.34 с — «единственный реальный рычаг» адаптивности.
        assert!((1300.0..=1400.0).contains(&expected_millis(28, BLAKE3_MHZ_CORE_FALLBACK)));
    }
}
