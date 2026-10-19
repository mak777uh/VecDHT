//! Метрики качества для harness'а гейтов P0 (§18.1 ii, iii).
//!
//! Это единственное место crate, где `f64` и `log2` встречаются в открытом виде. Причина, по
//! которой это не нарушает «никакого float в consensus-path» (§6.3): метрики считаются один раз
//! на машине, которая измеряет, и никуда не попадают, кроме отчёта. Побайтовая воспроизводимость
//! нужна `MatchResult`, а не числу recall в README — но и здесь порядок суммирования фиксирован,
//! чтобы повторный прогон на том же железе дал ровно то же число с последней цифрой.

/// Доля истинных топ-k, которую вернул приближённый поиск (§8.6).
///
/// `truth` и `got` — идентификаторы (slot'ы, владельцы) в порядке выдачи; порядок внутри списков
/// не важен, важны множества.
pub fn recall_at_k(truth: &[u32], got: &[u32], k: usize) -> f64 {
    if k == 0 || truth.is_empty() {
        return 0.0;
    }
    let want = truth.len().min(k);
    let hit = got
        .iter()
        .take(k)
        .filter(|id| truth.iter().take(want).any(|t| t == *id))
        .count();
    hit as f64 / want as f64
}

/// DCG@k для ранжированного списка релевантностей (`rel[i]` — релевантность документа на позиции
/// i). Формула стандартная: `sum rel_i / log2(i + 2)` — discount по позиции, i начинается с 0.
pub fn dcg_at_k(rel: &[f64], k: usize) -> f64 {
    let mut acc = 0.0;
    for (i, r) in rel.iter().take(k).enumerate() {
        acc += r / (i as f64 + 2.0).log2();
    }
    acc
}

/// nDCG@10: DCG данной выдачи делится на DCG идеальной сортировки тех же релевантностей.
/// Значение 1.0 означает «выдача уже идеальна», и именно разность двух nDCG (§18.1 iii) решает,
/// нужен ли reranker в ядре обещаний качества.
pub fn ndcg_at_k(rel: &[f64], k: usize) -> f64 {
    let ideal = {
        let mut v = rel.to_vec();
        v.sort_unstable_by(|a, b| b.total_cmp(a));
        dcg_at_k(&v, k)
    };
    if ideal <= 0.0 {
        // Ни одного релевантного документа во всём наборе: nDCG не определён, и возвращать 0.0
        // значило бы «модель плохая», хотя оценивать нечего.
        return f64::NAN;
    }
    dcg_at_k(rel, k) / ideal
}

/// Прирост относительно базового значения, в процентах: `(a / b - 1) · 100` (§18.1 iii).
pub fn gain_percent(candidate: f64, baseline: f64) -> f64 {
    if baseline == 0.0 {
        return f64::NAN;
    }
    (candidate / baseline - 1.0) * 100.0
}

/// Среднее по невыроненным значениям (`NAN` пропускается, а не отравляет сумму).
pub fn mean_skip_nan(values: &[f64]) -> f64 {
    let mut acc = 0.0;
    let mut n = 0usize;
    for v in values {
        if v.is_finite() {
            acc += v;
            n += 1;
        }
    }
    if n == 0 {
        0.0
    } else {
        acc / n as f64
    }
}

/// Медиана: устойчивая оценка «типичной» латентности, потому что один промах кеша процессора
/// не должен превращать замер §12.7 в провал гейта.
pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut v = values.to_vec();
    v.sort_unstable_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recall_counts_the_intersection_over_the_truth_prefix() {
        let truth: Vec<u32> = vec![1, 2, 3, 4, 5];
        assert_eq!(recall_at_k(&truth, &[5, 4, 9, 8, 7], 5), 0.4);
        assert_eq!(recall_at_k(&truth, &truth, 5), 1.0);
        assert_eq!(recall_at_k(&truth, &[9; 5], 5), 0.0);
        // k больше, чем длина truth: знаменатель — `len(truth)`, а не k, иначе recall@100 при
        // ground truth из 10 элементов никогда не мог бы быть 1.0.
        assert_eq!(recall_at_k(&truth, &truth, 100), 1.0);
        assert_eq!(recall_at_k(&[], &[1], 10), 0.0);
    }

    #[test]
    fn recall_ignores_extra_hits_beyond_k() {
        // Выдача длиной 20 при k=3: считаются только первые k, иначе метрика зависела бы от
        // того, сколько мусора агент притащил после.
        let truth = [1u32, 2, 3];
        let mut got: Vec<u32> = vec![1, 2, 3];
        got.extend(100..120);
        assert_eq!(recall_at_k(&truth, &got, 3), 1.0);
        // Попадание за пределами k не засчитывается: «3» стоит на четвёртой позиции выдачи.
        assert_eq!(recall_at_k(&truth, &[1, 2, 100, 3], 3), 2.0 / 3.0);
        // Знаменатель — min(len(truth), k), а не k: при k=2 оцениваются два верхних истинных
        // документа, и если оба найдены, это ровно 1.0, а не 2/3.
        assert_eq!(recall_at_k(&truth, &got, 2), 1.0);
    }

    #[test]
    fn dcg_discounts_by_position() {
        assert!((dcg_at_k(&[1.0], 1) - 1.0).abs() < 1e-12, "первая позиция — discount log2(2) = 1");
        let two = dcg_at_k(&[1.0, 1.0], 2);
        let expect = 1.0 + 1.0 / (3.0f64).log2();
        assert!((two - expect).abs() < 1e-12);
    }

    #[test]
    fn ndcg_is_one_for_the_ideal_order_and_less_otherwise() {
        let rel = [3.0, 2.0, 1.0, 0.0];
        assert!((ndcg_at_k(&rel, 4) - 1.0).abs() < 1e-12);
        let bad = [0.0, 1.0, 2.0, 3.0];
        assert!(ndcg_at_k(&bad, 4) < 1.0);
        assert!(ndcg_at_k(&bad, 4) > 0.0);
        // Нет ни одного релевантного документа — метрика не определена.
        assert!(ndcg_at_k(&[0.0, 0.0], 2).is_nan());
    }

    #[test]
    fn gain_percent_is_relative_to_the_baseline() {
        assert!((gain_percent(1.08, 1.0) - 8.0).abs() < 1e-9, "гейт iii — это +8% относительно ANN");
        assert!(gain_percent(1.0, 0.0).is_nan());
    }

    #[test]
    fn median_and_mean_survive_nan() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 2.0, 3.0]), 2.5);
        assert_eq!(median(&[]), 0.0);
        assert_eq!(mean_skip_nan(&[1.0, f64::NAN, 2.0]), 1.5);
        assert_eq!(mean_skip_nan(&[]), 0.0);
    }

    #[test]
    fn metrics_are_order_of_summation_sensitive_but_deterministic() {
        // Замер два раза подряд обязан дать побитово одинаковое число: суммирование идёт в одном
        // порядке, и это единственное, что мы обещаем от float-метрик.
        let rel: Vec<f64> = (0..1000).map(|i| (i % 4) as f64).collect();
        let a = ndcg_at_k(&rel, 10);
        let b = ndcg_at_k(&rel, 10);
        assert_eq!(a.to_bits(), b.to_bits());
    }
}
