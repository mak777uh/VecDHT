//! Квантование в фиксированную точку, целочисленные дистанции, присваивание кластера
//! (спека §6.3, §6.4, §7.2).
//!
//! Это граница детерминизма: всё после `quantize` — целые числа, поэтому consensus-path
//! не зависит от libm, ширины SIMD и числа потоков.

use thiserror::Error;
use vecdht_wire::constants::{CLUSTERS_PER_SHARD, MAX_D2, NLIST, Q_SCALE, SHARDS};
pub use vecdht_wire::DIM;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuantError {
    #[error("wrong dimension: got {0}, want {DIM}")]
    Dim(usize),
    #[error("vector norm is zero or not finite")]
    DegenerateNorm,
}

/// round half away from zero — явно, потому что banker's rounding расходится между
/// libm и компиляторами, а переключение координаты сетки меняет `intent_id`.
#[inline]
pub fn round_half_away(x: f64) -> i32 {
    if x >= 0.0 {
        (x + 0.5).floor() as i32
    } else {
        (x - 0.5).ceil() as i32
    }
}

/// L2-нормализация в f64 (шаг 6 пайплайна §6.2). Делается до квантования, и только здесь
/// живёт плавающая точка нормализации.
pub fn l2_normalize(v: &mut [f64]) -> Result<(), QuantError> {
    if v.len() != DIM {
        return Err(QuantError::Dim(v.len()));
    }
    let mut acc = 0f64;
    for x in v.iter() {
        if !x.is_finite() {
            return Err(QuantError::DegenerateNorm);
        }
        acc += x * x;
    }
    if acc <= 0.0 || !acc.is_finite() {
        return Err(QuantError::DegenerateNorm);
    }
    let inv = 1.0 / acc.sqrt();
    for x in v.iter_mut() {
        *x *= inv;
    }
    Ok(())
}

/// Сетка Δ = 1/127 на единичном шаре: `|u_i| ≤ 1`, поэтому clamping — не потеря данных.
pub fn quantize(u: &[f64; DIM]) -> [i8; DIM] {
    let mut v = [0i8; DIM];
    for i in 0..DIM {
        let q = round_half_away(u[i] * Q_SCALE).clamp(-127, 127);
        v[i] = q as i8;
    }
    v
}

/// Тот же контракт, но на срезе (для `centroid.bin`, где данные приходят из файла).
pub fn quantize_slice(u: &[f64]) -> Result<[i8; DIM], QuantError> {
    if u.len() != DIM {
        return Err(QuantError::Dim(u.len()));
    }
    let mut a = [0f64; DIM];
    a.copy_from_slice(u);
    Ok(quantize(&a))
}

/// Обратная сторона (только для отладки и обучения центроидов, никогда не в consensus).
pub fn dequantize(v: &[i8; DIM]) -> [f64; DIM] {
    let mut out = [0f64; DIM];
    for i in 0..DIM {
        out[i] = v[i] as f64 / Q_SCALE;
    }
    out
}

/// Целочисленный квадрат L2. Max на координату = `255² = 65 025`, на вектор ≤ `2.5e7` —
/// в `u32` помещается с трёхкратным запасом, поэтому `wrapping_add` здесь не теряет данные.
///
/// Форма цикла (чанки по 8 и восемь независимых аккумуляторов) выбрана ради авто-векторизации:
/// результат побитово тот же, что у покомпонентной суммы, потому что целое сложение
/// ассоциативно и переполнения нет (§6.4). Детерминизм между узлами не зависит от порядка
/// аккумуляторов — он фиксирован этим кодом, а не процессором.
#[inline]
pub fn l2_sq(a: &[i8; DIM], b: &[i8; DIM]) -> u32 {
    let mut acc = [0u32; 8];
    for (ax, bx) in a.chunks_exact(8).zip(b.chunks_exact(8)) {
        for ((av, bv), out) in ax.iter().zip(bx).zip(acc.iter_mut()) {
            let d = *av as i32 - *bv as i32;
            *out = out.wrapping_add((d * d) as u32);
        }
    }
    let mut total = 0u32;
    for x in acc {
        total = total.wrapping_add(x);
    }
    total
}

/// Единственная разрешённая формула similarity (§6.4). Плавающая точка только на стороне
/// агента для отображения; сортировка и подпись используют `d2`.
pub fn similarity_from_d2(d2: u32) -> f32 {
    let s = 1.0 - (d2 as f64 / MAX_D2 as f64) as f32;
    s.clamp(0.0, 1.0)
}

/// Присваивание кластера: `argmin l2_sq`, tie-break — наименьший индекс центроида.
///
/// В исходном листинге спеки §7.2 было `if d < best || best_c == 0` при `best = 0`:
/// ветка `best_c == 0` остаётся истинной для всех кандидатов, когда ближайший центроид —
/// нулевой, и она перекрывала `best` худшими дистанциями. Реализация ниже детерминирована
/// и корректна; тест `assign_nearest_wins_when_centroid_zero_is_closest` ловит регрессию.
pub fn assign_cluster(v: &[i8; DIM], centroids: &[&[i8; DIM]]) -> u16 {
    let mut best = u32::MAX;
    let mut best_c = 0u16;
    for (c, cent) in centroids.iter().enumerate() {
        let d = l2_sq(v, cent);
        if d < best {
            best = d;
            best_c = c as u16;
        }
    }
    best_c
}

/// Топ-`nprobe` ближайших кластеров, отсортированных по `(d2 ASC, cluster ASC)`.
/// Порядок часть контракта: он определяет, какие шарды будут зондированы (§7.5).
pub fn top_clusters(v: &[i8; DIM], centroids: &[&[i8; DIM]], nprobe: usize) -> Vec<u16> {
    let mut d: Vec<(u32, u16)> = centroids
        .iter()
        .enumerate()
        .map(|(c, cent)| (l2_sq(v, cent), c as u16))
        .collect();
    d.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    d.truncate(nprobe.min(d.len()));
    d.into_iter().map(|(_, c)| c).collect()
}

/// Группировка nprobe-множества по шардам: один `Find` на шард несёт только свои кластеры.
pub fn group_by_shard(clusters: &[u16]) -> Vec<(u16, Vec<u16>)> {
    let mut per: Vec<(u16, Vec<u16>)> = Vec::new();
    for &c in clusters {
        let s = c / CLUSTERS_PER_SHARD;
        if let Some(e) = per.iter_mut().find(|e| e.0 == s) {
            e.1.push(c);
        } else {
            per.push((s, vec![c]));
        }
    }
    per.sort_unstable_by_key(|e| e.0);
    for e in per.iter_mut() {
        e.1.sort_unstable();
    }
    per
}

/// Все кластеры шарда (для «no-IVF» режима малых сетей и для теста потолка recall, §8.6).
pub fn clusters_of_shard(shard: u16) -> Vec<u16> {
    let base = shard * CLUSTERS_PER_SHARD;
    (base..base + CLUSTERS_PER_SHARD).map(|c| c % NLIST).collect()
}

#[inline]
pub fn shard_of_cluster(cluster: u16) -> u16 {
    cluster / CLUSTERS_PER_SHARD
}

#[inline]
pub fn is_valid_shard(shard: u16) -> bool {
    shard < SHARDS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_e(i: usize) -> [f64; DIM] {
        let mut v = [0f64; DIM];
        v[i] = 1.0;
        v
    }

    #[test]
    fn quantize_maps_unit_vectors_exactly() {
        let q = quantize(&unit_e(0));
        assert_eq!(q[0], 127);
        assert!(q[1..].iter().all(|&x| x == 0));
    }

    #[test]
    fn quantize_is_deterministic_and_symmetric_in_rounding() {
        let mut u = [0f64; DIM];
        for (i, x) in u.iter_mut().enumerate() {
            *x = if i % 2 == 0 { 0.5 } else { -0.5 };
        }
        let q = quantize(&u);
        // 0.5·127 = 63.5 → half away from zero → 64, а не banker's 64 (совпадает) и не 63.
        assert_eq!(q[0], 64);
        assert_eq!(q[1], -64);
        assert_eq!(quantize(&u), q);
    }

    #[test]
    fn rounding_is_half_away_not_banker() {
        assert_eq!(round_half_away(0.5), 1);
        assert_eq!(round_half_away(-0.5), -1);
        assert_eq!(round_half_away(1.5), 2);
        assert_eq!(round_half_away(2.5), 3);
        assert_eq!(round_half_away(-2.5), -3);
        assert_eq!(round_half_away(0.0), 0);
    }

    #[test]
    fn l2_sq_bounds_match_contract() {
        let a = [-127i8; DIM];
        let b = [127i8; DIM];
        let d = l2_sq(&a, &b);
        // Реальный максимум сетки: 384 · 254² = 24 727 296, но в единичном шаре он
        // ограничен MAX_D2 (спека §6.4). Проверяем, что арифметика не переполняется.
        assert!(d > 0);
        assert_eq!(d, (DIM as u32) * (254 * 254));
        assert_eq!(l2_sq(&a, &a), 0);
        assert_eq!(l2_sq(&a, &b), l2_sq(&b, &a));
    }

    /// Эталон в лоб: один аккумулятор, покомпонентный порядок. Векторизованная форма `l2_sq`
    /// обязана давать побитово тот же `u32` — иначе `d2` в `MatchResult` разошёлся бы между
    /// узлами и подпись под canonical-байтами не совпала бы (§8.4, §19.1).
    #[inline(never)]
    fn l2_sq_reference(a: &[i8; DIM], b: &[i8; DIM]) -> u32 {
        let mut acc: u32 = 0;
        for i in 0..DIM {
            let d = a[i] as i32 - b[i] as i32;
            acc = acc.wrapping_add((d * d) as u32);
        }
        acc
    }

    #[test]
    fn l2_sq_equals_naive_reference_on_random_inputs() {
        /// xorshift64*: свои случайные векторы, чтобы тест был воспроизводим без `rand`.
        struct Gen(u64);
        impl Gen {
            fn byte(&mut self) -> u8 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 31) as u8
            }
            fn vec(&mut self) -> [i8; DIM] {
                let mut v = [0i8; DIM];
                for l in v.iter_mut() {
                    *l = self.byte() as i8;
                }
                v
            }
        }
        let mut g = Gen(0x2545_F491_4F6C_DD1D);
        for _ in 0..256 {
            let (a, b) = (g.vec(), g.vec());
            assert_eq!(l2_sq(&a, &b), l2_sq_reference(&a, &b), "векторизация сменила арифметику");
        }
        // Крайние сетки: максимум по модулю и противоположный ему минимум.
        let lo = [-128i8; DIM];
        let hi = [127i8; DIM];
        assert_eq!(l2_sq(&hi, &lo), l2_sq_reference(&hi, &lo));
        assert_eq!(l2_sq(&hi, &lo), (DIM as u32) * (255 * 255));
    }

    #[test]
    fn similarity_is_monotone_in_d2() {
        let mut prev = 1.0f32;
        for d2 in [0u32, 100, 1000, 5000, 20000, MAX_D2, MAX_D2 * 2] {
            let s = similarity_from_d2(d2);
            assert!(s <= prev, "similarity должна убывать с ростом d2");
            assert!((0.0..=1.0).contains(&s));
            prev = s;
        }
        assert_eq!(similarity_from_d2(0), 1.0);
        assert_eq!(similarity_from_d2(MAX_D2 * 3), 0.0);
    }

    #[test]
    fn quantization_error_within_budget() {
        // Суммарная squared-ошибка ≤ 384 · (1/(2·127))² (спека §6.3).
        let mut u = [0f64; DIM];
        for (i, x) in u.iter_mut().enumerate() {
            *x = ((i as f64) * 0.013).sin() / 8.0;
        }
        l2_normalize(&mut u).unwrap();
        let q = quantize(&u);
        let dq = dequantize(&q);
        let mut err = 0f64;
        for i in 0..DIM {
            err += (u[i] - dq[i]) * (u[i] - dq[i]);
        }
        let bound = DIM as f64 * (1.0 / (2.0 * Q_SCALE)).powi(2);
        assert!(err <= bound * 1.0001, "err={err} bound={bound}");
    }

    #[test]
    fn normalize_rejects_degenerate() {
        let mut z = [0f64; DIM];
        assert_eq!(l2_normalize(&mut z), Err(QuantError::DegenerateNorm));
        let mut nan = [0f64; DIM];
        nan[3] = f64::NAN;
        assert_eq!(l2_normalize(&mut nan), Err(QuantError::DegenerateNorm));
        assert_eq!(l2_normalize(&mut [0f64; DIM - 1]), Err(QuantError::Dim(DIM - 1)));
    }

    fn centroid_set() -> Vec<[i8; DIM]> {
        // Детерминированный синтетический квантизатор: 64 центроида, каждый — унитарный
        // вектор, сдвинутый по своей координате.
        (0..64u16)
            .map(|c| {
                let mut v = [0i8; DIM];
                v[c as usize % DIM] = 127;
                v[(c as usize + 1) % DIM] = 64;
                v
            })
            .collect()
    }

    #[test]
    fn assign_picks_nearest_with_lowest_index_tiebreak() {
        let cs = centroid_set();
        let refs: Vec<&[i8; DIM]> = cs.iter().collect();
        let mut q = [0i8; DIM];
        q[5] = 127;
        q[6] = 64;
        assert_eq!(assign_cluster(&q, &refs), 5);
        // Точный tie: два идентичных центроида на индексах 0 и 1 → берётся меньший индекс.
        let mut c = [0i8; DIM];
        c[0] = 127;
        c[1] = 64;
        let far = {
            let mut v = [0i8; DIM];
            v[200] = -127;
            v
        };
        let tied = [c, c, far];
        let tied_refs: Vec<&[i8; DIM]> = tied.iter().collect();
        let mut probe = [0i8; DIM];
        probe[0] = 100;
        assert_eq!(
            l2_sq(&probe, &tied[0]),
            l2_sq(&probe, &tied[1]),
            "конфигурация обязана давать ровно равные дистанции"
        );
        assert_eq!(assign_cluster(&probe, &tied_refs), 0);
        assert_eq!(top_clusters(&probe, &tied_refs, 2), vec![0, 1]);
    }

    /// Регрессия на баг исходного листинга §7.2 (`|| best_c == 0`).
    #[test]
    fn assign_nearest_wins_when_centroid_zero_is_closest() {
        let mut cs = centroid_set();
        // центроид 0 — ближайший; центроид 1 — очень далёкий.
        cs[1] = {
            let mut v = [0i8; DIM];
            v[100] = -127;
            v[101] = -127;
            v
        };
        let refs: Vec<&[i8; DIM]> = cs.iter().collect();
        let q = {
            let mut v = [0i8; DIM];
            v[0] = 127;
            v[1] = 64;
            v
        };
        assert_eq!(assign_cluster(&q, &refs), 0, "условие `|| best_c == 0` из спеки выбрало бы 1");
    }

    #[test]
    fn top_clusters_and_grouping() {
        let cs = centroid_set();
        let refs: Vec<&[i8; DIM]> = cs.iter().collect();
        let mut q = [0i8; DIM];
        q[3] = 127;
        q[4] = 64;
        let top = top_clusters(&q, &refs, 16);
        assert_eq!(top.len(), 16);
        assert_eq!(top[0], 3);
        assert!(top.iter().all(|&c| (c as usize) < 64));
        let g = group_by_shard(&top);
        let total: usize = g.iter().map(|e| e.1.len()).sum();
        assert_eq!(total, 16);
        for (s, cl) in &g {
            for &c in cl {
                assert_eq!(shard_of_cluster(c), *s);
            }
        }
    }

    #[test]
    fn clusters_of_shard_partition_nlist_exactly() {
        let mut all: Vec<u16> = Vec::new();
        for s in 0..SHARDS {
            let c = clusters_of_shard(s);
            assert_eq!(c.len(), CLUSTERS_PER_SHARD as usize);
            all.extend(c);
        }
        all.sort_unstable();
        assert_eq!(all.len(), NLIST as usize);
        for (i, c) in all.iter().enumerate() {
            assert_eq!(*c, i as u16, "разбиение обязано быть точным покрытием без дублей");
        }
    }

    #[test]
    fn shard_validity() {
        assert!(is_valid_shard(0));
        assert!(is_valid_shard(63));
        assert!(!is_valid_shard(64));
    }
}
