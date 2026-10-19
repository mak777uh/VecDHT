//! Publish PoW, привязанный к контексту (спека §11.1, §11.2).
//!
//! v7.5 использовала Argon2id для NodeID-PoW (24 бита ≈ дни, а не «2–5 с») и blake3 на 20 бит
//! для publish («~60 с» вместо реальных 1–2 мс). В v8 Argon2id удалён целиком: стоимость
//! записи даёт blake3 с привязкой nonce к `(shard, epoch, slot_key, expires_bucket)`.

use thiserror::Error;
use vecdht_wire::Writer;

pub const POW_DOMAIN: &[u8] = b"vecdht/v8/pow";

/// Адаптивный диапазон сложности (§11.2).
///
/// Диапазон переснят с замера (§18.1, `cargo bench --bench wire`): на измеренной скорости
/// `2^20 ≈ 150 мс` CPU на один publish (на спокойном хосте; на загруженном — ≈350 мс, см. ниже),
/// что и есть изначальный смысл §11.1 («стоимость записи — десятая доля секунды, щит — квоты
/// §11.3»). Диапазон 24..28 из черновика соответствовал этому только при предположении 200
/// МХеш/с, которого на коротких входах не бывает: замер даёт 3,0–7,0 МХеш/с на ядро, то есть
/// 2²⁴ = 2,4–5,6 с, а 2²⁸ = 38–89 с.
pub const POW_BITS_DEFAULT: u32 = 20;
pub const POW_BITS_MIN: u32 = 18;
pub const POW_BITS_MAX: u32 = 24;

// Инвариант политики проверяется на сборке: значения констант, значит и проверка константная.
// Держать это рантайм-тестом нельзя — тест бы «проходил» до того, как кто-то успеет сломать
// диапазон, и clippy право указывает, что у утверждения постоянное значение.
const _: () = {
    assert!(POW_BITS_MIN > 0 && POW_BITS_MAX < 64, "диапазон PoW вне ёмкости 64-битной цели");
    assert!(
        POW_BITS_DEFAULT >= POW_BITS_MIN && POW_BITS_DEFAULT <= POW_BITS_MAX,
        "pow_bits_default обязан лежать в адаптивном диапазоне §11.2"
    );
};

/// Бюджет blake3 на коротких (≈100-байтных) входах, если артефакт ещё не откалиброван `[P0]`.
///
/// Число — измерение, а не оценка «из головы»: release-прогон `cargo bench --bench wire` на
/// x86_64-windows-gnu, одно ядро, `pow_ok` без аллокаций, 2026-10-19: 2 000 000 попыток за
/// 285 мс = 7.01 МХеш/с. Прежнее значение 200 МХеш/с было взято из скорости blake3 на *потоковых*
/// больших входах и применялось к хешу 100-байтного входа, где dominating — фиксированная цена
/// вызова и двух компрессий. Фолбэк обязан быть честным, потому что по нему CLI считает
/// «сколько ждать publish» до калибровки артефакта (§15.1).
///
/// Знать про этот же замер через день: 3.0–3.7 МХеш/с на том же стенде и том же бинарнике. Это
/// не «константа скорости blake3», а свойство хоста, и у неё два практических следствия. Меньшее
/// из замеров — консервативнее для сети (завышенный `blake3_mhz_core` удешевляет publish для
/// всех), поэтому оператор кладёт в манифест меньший из двух прогонов (§15.1). И цикл съёма обязан
/// быть длинным: короткий цикл без прогрева (400 000 попыток, прогрев 100 000) даёт 1.1–2.6 МХеш/с —
/// занижение в 2–3× из-за разгона частоты, а не из-за `pow_ok`.
pub const BLAKE3_MHZ_CORE_FALLBACK: f64 = 7.0;

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

/// Проверка: один blake3 над `input ‖ nonce`.
///
/// Реализация — инкрементальный `Hasher`, а не `blake3::hash(&[input, nonce].concat())`: переборщик
/// зовёт эту функцию 2^bits раз, и аллокация конкатенированного входа на каждую попытку стоила бы
/// больше, чем сам хеш (замер — `benches/src/bench/wire.rs`). Инкрементальность blake3 даёт ровно
/// тот же дайджест, что и хеш конкатенации, поэтому контракт функции не меняется.
#[inline]
pub fn pow_ok(input: &[u8], nonce: u64, bits: u32) -> bool {
    if bits == 0 || bits > 64 {
        return false;
    }
    let mut h = blake3::Hasher::new();
    h.update(input);
    h.update(&nonce.to_le_bytes());
    let x = u64::from_be_bytes(h.finalize().as_bytes()[..8].try_into().unwrap());
    // bits ∈ 1..=64, поэтому сдвиг всегда в диапазоне 63..=0 и переполнения нет. Замечание по краю:
    // bits = 64 — это «все 64 бита обнулены», то есть почти недостижимая цель, а не «принимает всё»;
    // отдельная ветка на 64 была бы ловушкой, потому что `1 << 0 == 1` и есть правильный target.
    let target = 1u64 << (64 - bits);
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
        assert_eq!(mine_pow(&input(), POW_BITS_MIN - 1, 0, 1), Err(PowError::BitsOutOfRange(POW_BITS_MIN - 1)));
        assert_eq!(mine_pow(&input(), POW_BITS_MAX + 1, 0, 1), Err(PowError::BitsOutOfRange(POW_BITS_MAX + 1)));
        assert!(!pow_ok(&input(), 1, 0));
        assert!(!pow_ok(&input(), 1, 65));
    }

    #[test]
    fn streaming_hasher_equals_one_shot_hash_of_concat() {
        // Рефакторинг `pow_ok` обязан сохранять определение: критерий — дайджест от
        // `input ‖ nonce_le`, а не от того, как именно blake3 его посчитал.
        let input = input();
        for nonce in [0u64, 1, 42, u64::MAX] {
            let mut buf = input.clone();
            buf.extend_from_slice(&nonce.to_le_bytes());
            let want = u64::from_be_bytes(blake3::hash(&buf).as_bytes()[..8].try_into().unwrap());
            for bits in [1u32, 8, 24, 63, 64] {
                let target = 1u64 << (64 - bits);
                assert_eq!(pow_ok(&input, nonce, bits), want < target, "bits {bits} nonce {nonce}");
            }
        }
    }

    #[test]
    fn cost_estimate_matches_measured_throughput() {
        // Арифметика §11.1 на измеренной скорости: 2^20 попыток при 7 МХеш/с ≈ 150 мс CPU.
        let ms = expected_millis(POW_BITS_DEFAULT, BLAKE3_MHZ_CORE_FALLBACK);
        assert!((140.0..=165.0).contains(&ms), "{ms} мс — не та арифметика у стоимости publish");
        // Верх диапазона — рычаг под атакой: 2^(24−18) = 64× дороже нижнего, то есть ≈2,4 с CPU.
        // Заметно для узла, но не запретительно: именно этот край делает адаптивность осмысленной.
        assert!(
            (2_200.0..=2_600.0).contains(&expected_millis(POW_BITS_MAX, BLAKE3_MHZ_CORE_FALLBACK)),
            "верх адаптивности обязан быть заметным, но не запретительным"
        );
        assert!(
            expected_millis(POW_BITS_MIN, BLAKE3_MHZ_CORE_FALLBACK) < 50.0,
            "низ диапазона — «шард не под ударом»: доли секунды"
        );
    }

    #[test]
    fn cost_is_geometric_across_the_adaptive_range() {
        // Сам инвариант «default ∈ [min; max] и max < 64» проверяется на сборке (`const _` выше),
        // поэтому здесь остаётся то, что сборке не видно: стоимость должна расти ровно
        // геометрически — §11.4 опирается на «верх дороже низа в 2^(max−min)×».
        // Сравниваем с допуском: `expected_millis` делит на вещественную скорость, и точное
        // равенство f64 было бы проверкой округления IEEE-754, а не политики.
        let ratio = expected_millis(POW_BITS_MAX, BLAKE3_MHZ_CORE_FALLBACK)
            / expected_millis(POW_BITS_MIN, BLAKE3_MHZ_CORE_FALLBACK);
        let want = (1u64 << (POW_BITS_MAX - POW_BITS_MIN)) as f64;
        assert!(
            (ratio - want).abs() / want < 1e-9,
            "стоимость верха = {ratio}, ожидалось {want}× от низа"
        );
    }
}
