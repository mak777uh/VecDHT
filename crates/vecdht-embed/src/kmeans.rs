//! Balanced k-means для замороженного coarse-квантизатора (§7.1, §7.6).
//!
//! Это **не** consensus-path: обучение центроидов происходит один раз при выпуске артефакта, а
//! результат квантуется в ту же int8-сетку, что и векторы записей. Поэтому f32/f64 здесь
//! допустимы так же, как в [`crate::metrics`], и не влияют на побайтовую стабильность выдачи.
//!
//! Два свойства, которые нужны спеке и которые легко потерять при «обычном» k-means:
//!
//! * **детерминизм**: фиксированный seed, разбиение на потоки по индексам, порядок суммирования
//!   не зависит от планировщика. Два прогона на одной машине дают побитово одинаковые центроиды;
//! * **balancing cap 2×N/NLIST** (§7.6): после присваивания по ближайшему центроиду кластеры
//!   сверх cap переливают самые неоднозначные точки (минимальный зазор между первым и вторым
//!   центроидом) во второй по близости. Это эвристика, а не гарантия: если оба кандидата уже
//!   заполнены, перелив невозможен, и [`KMeansResult::clusters_over_cap`] покажет это числом, а
//!   не скроет.
//!
//! Входные строки обязаны быть L2-нормированы: расстояние тогда считается одним dot-product, а
//! геометрия совпадает с [`crate::finalize`], который нормирует pooled-вектор перед квантованием.
//! Это проверяется, а не предполагается.

use std::thread;

const CONVERGENCE_DENOM: usize = 1000;
const MAX_BALANCE_PASSES: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct KMeansConfig {
    /// Число центроидов; для v8 это `NLIST = 1024`.
    pub k: usize,
    /// Верхняя граница итераций; ранняя остановка — по числу переключений.
    pub max_iters: usize,
    pub seed: u64,
    /// Максимальный размер кластера при обучении (§7.6: 2×N/NLIST).
    pub balance_cap: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct IterationStats {
    pub changed: usize,
    pub objective: f64,
    pub max_cluster: u32,
    pub clusters_over_cap: usize,
}

#[derive(Debug, Clone)]
pub struct KMeansResult {
    /// Плоский массив `k × dim`, каждая строка нормирована.
    pub centroids: Vec<f32>,
    /// Финальное (после перелива) присваивание в `0..k`.
    pub assignment: Vec<u16>,
    pub counts: Vec<u32>,
    pub iterations: usize,
    pub history: Vec<IterationStats>,
}

#[derive(Debug, thiserror::Error)]
pub enum KMeansError {
    #[error("k-means: dim = 0")]
    ZeroDim,
    #[error("k-means: {vectors} значений не делятся на dim = {dim}")]
    BadShape { vectors: usize, dim: usize },
    #[error("k-means: k = 0 или k = {k} больше числа векторов {vectors}")]
    BadK { k: usize, vectors: usize },
    #[error("k-means: k = {k} не помещается в u16 cluster_id")]
    KTooLarge { k: usize },
    #[error("k-means: cap = {cap} меньше 1")]
    BadCap { cap: usize },
    #[error("k-means: вектор {row} не конечен")]
    NonFinite { row: usize },
    #[error("k-means: вектор {row} не единичной длины (|v| = {norm}); ожидается L2-нормировка")]
    NonUnit { row: usize, norm: f64 },
}

/// Обучить центроиды. `threads` влияет только на скорость: результат от него не зависит.
pub fn train(
    vectors: &[f32],
    dim: usize,
    config: KMeansConfig,
    threads: usize,
) -> Result<KMeansResult, KMeansError> {
    if dim == 0 {
        return Err(KMeansError::ZeroDim);
    }
    if vectors.len() % dim != 0 {
        return Err(KMeansError::BadShape { vectors: vectors.len(), dim });
    }
    let n = vectors.len() / dim;
    if config.k == 0 || config.k > n {
        return Err(KMeansError::BadK { k: config.k, vectors: n });
    }
    if config.k > u16::MAX as usize {
        return Err(KMeansError::KTooLarge { k: config.k });
    }
    if config.balance_cap == 0 {
        return Err(KMeansError::BadCap { cap: config.balance_cap });
    }
    validate_unit_rows(vectors, n, dim)?;

    let threads = threads.max(1);
    let mut centroids = kmeans_plus_plus(vectors, n, dim, config.k, config.seed);
    let mut previous = vec![u16::MAX; n];
    let mut history = Vec::with_capacity(config.max_iters);

    for iter in 0..config.max_iters {
        let (nearest, second, margin) = top2_all(vectors, n, dim, &centroids, config.k, threads);
        let (assignment, counts) =
            balanced_assign(&nearest, &second, &margin, config.k, config.balance_cap);
        let changed = assignment
            .iter()
            .zip(&previous)
            .filter(|(a, b)| a != b)
            .count();
        let objective = mean_objective(vectors, n, dim, &centroids, &assignment, threads);
        let max_cluster = counts.iter().copied().max().unwrap_or(0);
        let clusters_over_cap =
            counts.iter().filter(|&&c| c as usize > config.balance_cap).count();

        update_centroids(vectors, n, dim, &assignment, config.k, &mut centroids);
        history.push(IterationStats { changed, objective, max_cluster, clusters_over_cap });
        previous = assignment;

        // Первая итерация «меняет» всё; ранняя остановка имеет смысл только со второй.
        if iter > 0 && changed <= (n / CONVERGENCE_DENOM).max(1) {
            break;
        }
    }

    // Финальное присваивание обязано соответствовать финальным центроидам, а не предыдущей
    // итерации: иначе counts описывали бы центроиды, которых уже нет.
    let (nearest, second, margin) = top2_all(vectors, n, dim, &centroids, config.k, threads);
    let (assignment, counts) =
        balanced_assign(&nearest, &second, &margin, config.k, config.balance_cap);

    Ok(KMeansResult {
        centroids,
        assignment,
        counts,
        iterations: history.len(),
        history,
    })
}

fn validate_unit_rows(vectors: &[f32], n: usize, dim: usize) -> Result<(), KMeansError> {
    for row in 0..n {
        let v = &vectors[row * dim..(row + 1) * dim];
        let mut norm = 0f64;
        for &x in v {
            if !x.is_finite() {
                return Err(KMeansError::NonFinite { row });
            }
            norm += f64::from(x) * f64::from(x);
        }
        let norm = norm.sqrt();
        if (norm - 1.0).abs() > 1e-3 {
            return Err(KMeansError::NonUnit { row, norm });
        }
    }
    Ok(())
}

/// K-means++ на полном наборе: на каждом шаге обновляется только расстояние до последнего
/// центроида, поэтому инициализация стоит примерно одно присваивание, а не k присваиваний.
fn kmeans_plus_plus(vectors: &[f32], n: usize, dim: usize, k: usize, seed: u64) -> Vec<f32> {
    let mut rng = SplitMix64::new(seed);
    let mut centroids = vec![0f32; k * dim];
    let mut chosen = vec![false; n];
    let mut min_d2 = vec![f32::INFINITY; n];

    let first = (rng.next_u64() % n as u64) as usize;
    chosen[first] = true;
    centroids[..dim].copy_from_slice(&vectors[first * dim..(first + 1) * dim]);

    for c in 1..k {
        let last = (c - 1) * dim;
        let mut total = 0f64;
        for row in 0..n {
            let v = &vectors[row * dim..(row + 1) * dim];
            let d = sq_l2_unit(v, &centroids[last..last + dim]);
            if d < min_d2[row] {
                min_d2[row] = d;
            }
            total += f64::from(min_d2[row]);
        }

        let target = rng.next_f64() * total;
        let mut acc = 0f64;
        let mut pick = n - 1;
        if total > 0.0 {
            for (row, &d) in min_d2.iter().enumerate() {
                acc += f64::from(d);
                if acc >= target {
                    pick = row;
                    break;
                }
            }
        } else {
            pick = (rng.next_u64() % n as u64) as usize;
        }
        // Дубликат центроида сделал бы кластер пустым; сдвиг по кругу детерминирован.
        while chosen[pick] {
            pick = (pick + 1) % n;
        }
        chosen[pick] = true;
        let dst = c * dim;
        centroids[dst..dst + dim].copy_from_slice(&vectors[pick * dim..(pick + 1) * dim]);
    }
    centroids
}

/// Для каждого вектора — первый и второй по близости центроиды и зазор между ними.
///
/// Зазор нужен переливу: точка, у которой первый и второй почти равны, дешевле уезжает во
/// второй центроид, чем точка, для которой первый центр — единственный осмысленный выбор.
fn top2_all(
    vectors: &[f32],
    n: usize,
    dim: usize,
    centroids: &[f32],
    k: usize,
    threads: usize,
) -> (Vec<u16>, Vec<u16>, Vec<f32>) {
    let mut nearest = vec![0u16; n];
    let mut second = vec![0u16; n];
    let mut margin = vec![0f32; n];
    let chunk = n.div_ceil(threads);

    thread::scope(|scope| {
        let n_chunks = nearest.chunks_mut(chunk);
        let s_chunks = second.chunks_mut(chunk);
        let m_chunks = margin.chunks_mut(chunk);
        for (t, ((n_out, s_out), m_out)) in
            n_chunks.zip(s_chunks).zip(m_chunks).enumerate()
        {
            let start = t * chunk;
            scope.spawn(move || {
                for (local, ((best_out, second_out), margin_out)) in
                    n_out.iter_mut().zip(s_out.iter_mut()).zip(m_out.iter_mut()).enumerate()
                {
                    let row = start + local;
                    let v = &vectors[row * dim..(row + 1) * dim];
                    let (best_c, second_c, best_d, second_d) = top2_one(v, centroids, k);
                    *best_out = best_c;
                    *second_out = second_c;
                    *margin_out = second_d - best_d;
                }
            });
        }
    });

    (nearest, second, margin)
}

fn top2_one(v: &[f32], centroids: &[f32], k: usize) -> (u16, u16, f32, f32) {
    let mut best = f32::INFINITY;
    let mut second = f32::INFINITY;
    let mut best_c = 0u16;
    let mut second_c = 0u16;
    for c in 0..k {
        let d = sq_l2_unit(v, &centroids[c * v.len()..(c + 1) * v.len()]);
        // Строгое `<` сохраняет tie-break меньшим индексом, как assign_cluster в §7.2.
        if d < best {
            second = best;
            second_c = best_c;
            best = d;
            best_c = c as u16;
        } else if d < second {
            second = d;
            second_c = c as u16;
        }
    }
    (best_c, second_c, best, second)
}

/// Присваивание с переливом. Возвращает присваивание и размеры кластеров.
///
/// Перелив идёт по исходным членам кластера, а не по «принятым» точкам: иначе две точки могли бы
/// бесконечно перекидывать друг друга между двумя переполненными кластерами. Несколько проходов
/// нужны потому, что кластер, обработанный раньше, мог переполниться от перелива соседа.
fn balanced_assign(
    nearest: &[u16],
    second: &[u16],
    margin: &[f32],
    k: usize,
    cap: usize,
) -> (Vec<u16>, Vec<u32>) {
    let mut assignment = nearest.to_vec();
    let mut counts = vec![0u32; k];
    for &c in nearest {
        counts[c as usize] += 1;
    }
    if counts.iter().all(|&c| c as usize <= cap) {
        return (assignment, counts);
    }

    let mut members: Vec<Vec<u32>> = vec![Vec::new(); k];
    for (row, &c) in nearest.iter().enumerate() {
        members[c as usize].push(row as u32);
    }
    for list in &mut members {
        list.sort_unstable_by(|&a, &b| {
            margin[a as usize].total_cmp(&margin[b as usize]).then(a.cmp(&b))
        });
    }

    let mut next = vec![0usize; k];
    for _ in 0..MAX_BALANCE_PASSES {
        let mut moved = false;
        for c in 0..k {
            while counts[c] as usize > cap && next[c] < members[c].len() {
                let row = members[c][next[c]] as usize;
                next[c] += 1;
                if assignment[row] as usize != c {
                    continue;
                }
                let dst = second[row] as usize;
                if dst != c && (counts[dst] as usize) < cap {
                    assignment[row] = dst as u16;
                    counts[c] -= 1;
                    counts[dst] += 1;
                    moved = true;
                }
            }
        }
        if !moved {
            break;
        }
    }
    (assignment, counts)
}

fn update_centroids(
    vectors: &[f32],
    n: usize,
    dim: usize,
    assignment: &[u16],
    k: usize,
    centroids: &mut [f32],
) {
    let mut sums = vec![0f64; k * dim];
    let mut counts = vec![0u32; k];
    for row in 0..n {
        let c = assignment[row] as usize;
        counts[c] += 1;
        let v = &vectors[row * dim..(row + 1) * dim];
        let sum = &mut sums[c * dim..(c + 1) * dim];
        for (s, &x) in sum.iter_mut().zip(v) {
            *s += f64::from(x);
        }
    }

    for (c, &count) in counts.iter().enumerate() {
        let dst = c * dim;
        if count == 0 {
            // Пустой кластер не должен остаться в точке предыдущей итерации: он снова притянет
            // точки и снова опустеет. Детерминированный разброс по строкам выводит его из
            // локального минимума, не трогая остальные центроиды.
            let row = ((c as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) % n as u64) as usize;
            centroids[dst..dst + dim].copy_from_slice(&vectors[row * dim..(row + 1) * dim]);
            continue;
        }
        let mut norm = 0f64;
        for &s in &sums[dst..dst + dim] {
            norm += s * s;
        }
        let norm = norm.sqrt();
        if norm <= f64::EPSILON {
            let row = ((c as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) % n as u64) as usize;
            centroids[dst..dst + dim].copy_from_slice(&vectors[row * dim..(row + 1) * dim]);
            continue;
        }
        for d in 0..dim {
            centroids[dst + d] = (sums[dst + d] / norm) as f32;
        }
    }
}

fn mean_objective(
    vectors: &[f32],
    n: usize,
    dim: usize,
    centroids: &[f32],
    assignment: &[u16],
    threads: usize,
) -> f64 {
    let chunk = n.div_ceil(threads);
    let mut partial = vec![0f64; threads];
    thread::scope(|scope| {
        for (t, out) in partial.iter_mut().enumerate() {
            let start = t * chunk;
            let end = ((t + 1) * chunk).min(n);
            scope.spawn(move || {
                let mut acc = 0f64;
                for row in start..end {
                    let v = &vectors[row * dim..(row + 1) * dim];
                    let c = assignment[row] as usize;
                    acc += f64::from(sq_l2_unit(v, &centroids[c * dim..(c + 1) * dim]));
                }
                *out = acc;
            });
        }
    });
    partial.iter().sum::<f64>() / n as f64
}

/// `||a − b||²` для единичных векторов. Отрицательное значение возможно только из-за округления.
fn sq_l2_unit(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = [0f32; 8];
    for (ax, bx) in a.chunks_exact(8).zip(b.chunks_exact(8)) {
        for i in 0..8 {
            acc[i] += ax[i] * bx[i];
        }
    }
    let mut dot: f32 = acc.iter().sum();
    // DIM=384 делится на 8, но модуль не должен молча терять хвост на другой размерности.
    let tail = a.len() - a.len() % 8;
    for i in tail..a.len() {
        dot += a[i] * b[i];
    }
    (2.0 - 2.0 * dot).max(0.0)
}

/// SplitMix64: детерминированный поток без внешней зависимости. Нужен только для инициализации.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_f64(&mut self) -> f64 {
        // 53 старших бита — ровно мантисса f64; значение в [0, 1).
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_crypto::DIM;

    fn unit(v: &mut [f32]) {
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        for x in v.iter_mut() {
            *x /= norm;
        }
    }

    /// Четыре плотных облака вокруг ортогональных направлений; между ними заведомо есть зазор.
    fn clouds(n_per: usize) -> (Vec<f32>, Vec<usize>) {
        let mut values = Vec::new();
        let mut truth = Vec::new();
        for (cloud, axis) in [0usize, 1, 2, 3].into_iter().enumerate() {
            for i in 0..n_per {
                let mut v = vec![0.001f32; DIM];
                v[axis] = 1.0;
                v[(axis + 4) % DIM] += (i as f32) * 1e-4;
                unit(&mut v);
                values.extend_from_slice(&v);
                truth.push(cloud);
            }
        }
        (values, truth)
    }

    fn config(k: usize, cap: usize) -> KMeansConfig {
        KMeansConfig { k, max_iters: 8, seed: 0x5EED_2026, balance_cap: cap }
    }

    #[test]
    fn finds_orthogonal_clouds_and_is_deterministic() {
        let (values, truth) = clouds(30);
        let n = truth.len();
        let cfg = config(4, n.div_ceil(2));
        let a = train(&values, DIM, cfg, 4).unwrap();
        let b = train(&values, DIM, cfg, 4).unwrap();
        assert_eq!(a.centroids, b.centroids, "k-means с фиксированным seed обязан повторяться");
        assert_eq!(a.assignment, b.assignment);
        assert_eq!(a.counts, b.counts);

        // Каждое облако должно целиком попасть в один кластер, и разные облака — в разные.
        for cloud in 0..4 {
            let assigned: Vec<u16> = truth
                .iter()
                .enumerate()
                .filter(|(_, c)| **c == cloud)
                .map(|(i, _)| a.assignment[i])
                .collect();
            assert!(assigned.windows(2).all(|w| w[0] == w[1]), "облако {cloud} разрезано");
        }
        let mut used: Vec<u16> = a.assignment.clone();
        used.sort_unstable();
        used.dedup();
        assert_eq!(used.len(), 4, "четыре облака не могут делить кластер");
    }

    #[test]
    fn cap_is_respected_when_second_cluster_has_room() {
        let (mut values, _) = clouds(30);
        // Три облака и k=2: естественное деление 60/30, cap=50 требует перелить 10 точек.
        values.truncate(3 * 30 * DIM);
        let n = values.len() / DIM;
        let cfg = config(2, 50);
        let result = train(&values, DIM, cfg, 3).unwrap();
        assert!(
            result.counts.iter().all(|&c| c as usize <= cfg.balance_cap),
            "cap не выдержан: {:?}",
            result.counts
        );
        assert_eq!(result.counts.iter().sum::<u32>() as usize, n);
    }

    #[test]
    fn rejects_non_unit_and_bad_shape() {
        let mut v = vec![0.5f32; DIM];
        let err = train(&v, DIM, config(1, 1), 1).unwrap_err();
        assert!(matches!(err, KMeansError::NonUnit { .. }));
        unit(&mut v);
        let err = train(&v[..DIM - 1], DIM, config(1, 1), 1).unwrap_err();
        assert!(matches!(err, KMeansError::BadShape { .. }));
    }
}
