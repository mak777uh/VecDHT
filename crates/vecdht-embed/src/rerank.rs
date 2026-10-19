//! Rerank-контракт на стороне агента (§12.4, §8.6, §18.1 iii).
//!
//! Модель здесь не загружается и не вызывается: реранкер — чужая реализация (кросс-энкодер
//! `ms-marco-MiniLM-L-6-v2` с дописанной головой, §12.4), а контракт — это то, что вокруг него
//! обязано быть правильным:
//!
//! * реранк **не может** вернуть то, что не найдено на ANN-этапе — отсюда запрет на любое
//!   изменение множества кандидатов (§8.6: «recall > 95% за счёт reranker» было неверно по
//!   построению именно потому, что порядок и множество путали);
//! * равные скоры разрешаются по ANN-порядку, а не по памяти процессора: иначе ΔnDCG@10 из гейта (iii)
//!   зависел бы от того, как сопутировались равные числа с плавающей точкой;
//! * не-конечный скор — ошибка, а не «документ куда-то встал»: NaN в сортировке дал бы порядок,
//!   который невозможно повторить.
//!
//! Отдельно зафиксировано ограничение бюджета: K кандидатов и cap токенов (§12.4: 14 пар/с на
//! ~17M модель ⇒ 3.6 с на 50 пар, поэтому K=32 и 256 токенов, ~0.12 с на запрос).

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RerankError {
    #[error("rerank: оценок {got}, кандидатов {want} — оценки обязаны соответствовать шортлисту")]
    LengthMismatch { got: usize, want: usize },
    #[error("rerank: оценка №{0} не конечна — кросс-энкодер вернул NaN/inf, порядок не определён")]
    NonFinite(usize),
    #[error("rerank: кандидатов {count}, а лимит реранкера {limit} (§12.4: K=32 на бюджет 0.12 с)")]
    TooManyCandidates { count: usize, limit: usize },
}

/// Результат реранка: кандидат плюс его место до и после.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RankedDoc {
    /// Slot записи в индексе (§8.3) — идентичность кандидата.
    pub slot: u32,
    /// Целочисленная дистанция из ANN-этапа (§6.4): единственный аргумент, по которому
    /// разрешено сравнивать результаты с разных узлов.
    pub d2: u32,
    /// Скор кросс-энкодера: выше = лучше. Только для отображения и сортировки агентом.
    pub score: f32,
    /// Позиция в ANN-порядке (0 = лучший по `d2`). Нужен, чтобы разрешить равенство скоров
    /// и чтобы измерить, насколько реранк вообще сдвинул выдачу.
    pub ann_rank: usize,
}

/// Что умеет оценивать пары конкретная реализация.
pub trait Reranker {
    /// Оценить `docs` против `query`. Порядок возвращаемых оценок совпадает с порядком входа —
    /// сопоставление по индексу, а не по тексту, чтобы дубликаты текстов не слились в одну оценку.
    ///
    /// Реализация обязана быть чистой по входу: одинаковая пара ⇒ одинаковая оценка, иначе
    /// измерение гейта (iii) теряет смысл.
    fn score(&self, query: &str, docs: &[String]) -> Result<Vec<f32>, RerankError>;

    /// Максимум кандидатов за один вызов (§12.4: K=32).
    fn max_docs(&self) -> usize {
        DEFAULT_RERANK_K
    }
}

/// K шортлиста для реранка по умолчанию (§12.4).
pub const DEFAULT_RERANK_K: usize = 32;

/// Применить реранкер к ANN-порядку и вернуть окончательный порядок.
///
/// `ann` — пары `(d2, slot)` из [`vecdht_index::ivf::IvfIndex::search`], уже отсортированные по
/// контракту §8.4. Множество кандидатов не меняется никогда: меняется только порядок внутри него.
pub fn rerank_order<R: Reranker + ?Sized>(
    reranker: &R,
    query: &str,
    ann: &[(u32, u32)],
    texts: &[String],
) -> Result<Vec<RankedDoc>, RerankError> {
    if ann.len() != texts.len() {
        return Err(RerankError::LengthMismatch { got: texts.len(), want: ann.len() });
    }
    if texts.len() > reranker.max_docs() {
        return Err(RerankError::TooManyCandidates { count: texts.len(), limit: reranker.max_docs() });
    }
    let scores = reranker.score(query, texts)?;
    order_by_scores(ann, &scores)
}

/// Та же сортировка, но с уже готовыми оценками — путь harness'а, где «модель» подменяется
/// детерминированным скором, чтобы ΔnDCG@10 можно было посчитать без весов.
pub fn order_by_scores(ann: &[(u32, u32)], scores: &[f32]) -> Result<Vec<RankedDoc>, RerankError> {
    if ann.len() != scores.len() {
        return Err(RerankError::LengthMismatch { got: scores.len(), want: ann.len() });
    }
    for (i, s) in scores.iter().enumerate() {
        if !s.is_finite() {
            return Err(RerankError::NonFinite(i));
        }
    }
    let mut docs: Vec<RankedDoc> = ann
        .iter()
        .enumerate()
        .map(|(rank, (d2, slot))| RankedDoc { slot: *slot, d2: *d2, score: scores[rank], ann_rank: rank })
        .collect();
    docs.sort_unstable_by(|a, b| {
        // total_cmp вместо `<`: порядок обязан быть полным, включая -0.0 и равные значения.
        b.score
            .total_cmp(&a.score)
            // Равные скоры не переворачиваются: они остаются в ANN-порядке, а он сам
            // детерминирован по `(d2, slot)` (§8.4).
            .then(a.d2.cmp(&b.d2))
            .then(a.slot.cmp(&b.slot))
    });
    Ok(docs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Детерминированный «реранкер»: скор = длина текста минус ANN-ранг. Достаточно, чтобы ловить
    /// порядок и не требовать весов.
    struct LengthReranker;
    impl Reranker for LengthReranker {
        fn score(&self, _query: &str, docs: &[String]) -> Result<Vec<f32>, RerankError> {
            Ok(docs.iter().map(|d| d.len() as f32).collect())
        }
    }

    /// Реранкер, который врёт про количество оценок.
    struct Broken;
    impl Reranker for Broken {
        fn score(&self, _query: &str, docs: &[String]) -> Result<Vec<f32>, RerankError> {
            Ok(vec![0.0; docs.len() - 1])
        }
    }

    fn ann() -> Vec<(u32, u32)> {
        // Контрактный вход: (d2 ASC, slot ASC).
        vec![(10, 1), (20, 2), (30, 3)]
    }

    fn texts() -> Vec<String> {
        vec!["коротко".into(), "средний текст".into(), "самый длинный текст из трёх".into()]
    }

    #[test]
    fn higher_score_wins_and_the_candidate_set_is_unchanged() {
        let docs = rerank_order(&LengthReranker, "запрос", &ann(), &texts()).unwrap();
        assert_eq!(
            docs.iter().map(|d| d.slot).collect::<Vec<_>>(),
            vec![3, 2, 1],
            "чем длиннее текст, тем выше скор — порядок обязан быть по убыванию"
        );
        let mut slots: Vec<u32> = docs.iter().map(|d| d.slot).collect();
        slots.sort_unstable();
        assert_eq!(slots, vec![1, 2, 3], "реранк переупорядочивает, но не добавляет и не теряет кандидатов");
        assert_eq!(docs[0].ann_rank, 2, "документ 3 был последним в ANN-порядке");
    }

    #[test]
    fn ties_fall_back_to_ann_order() {
        // Все скоры равны ⇒ порядок обязан совпасть с входным, а не с порядком памяти.
        let docs = order_by_scores(&ann(), &[0.5, 0.5, 0.5]).unwrap();
        assert_eq!(docs.iter().map(|d| d.slot).collect::<Vec<_>>(), vec![1, 2, 3]);
        // Второй уровень равенства — по d2, если скоры равны и ранги перепутаны на входе.
        let shuffled = vec![(30, 3), (10, 1), (20, 2)];
        let docs = order_by_scores(&shuffled, &[0.0, 0.0, 0.0]).unwrap();
        assert_eq!(
            docs.iter().map(|d| (d.d2, d.slot)).collect::<Vec<_>>(),
            vec![(10, 1), (20, 2), (30, 3)],
            "при равных скрах сортировка идёт по (d2, slot) — то есть по §8.4"
        );
    }

    #[test]
    fn nan_score_is_an_error_not_an_order() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let err = order_by_scores(&ann(), &[0.1, bad, 0.3]).unwrap_err();
            assert_eq!(err, RerankError::NonFinite(1));
        }
    }

    #[test]
    fn length_mismatch_is_caught_before_ordering() {
        assert_eq!(
            order_by_scores(&ann(), &[0.1, 0.2]).unwrap_err(),
            RerankError::LengthMismatch { got: 2, want: 3 }
        );
        let err = rerank_order(&Broken, "q", &ann(), &texts()).unwrap_err();
        assert!(matches!(err, RerankError::LengthMismatch { .. }));
    }

    #[test]
    fn too_many_candidates_is_refused_rather_than_silently_truncated() {
        // §12.4: K=32 — это бюджет времени, а не пожелание. Обрезать молча означало бы, что
        // агент получил другие recall/precision, чем заявлено в сценарии.
        let n = DEFAULT_RERANK_K + 1;
        let ann: Vec<(u32, u32)> = (0..n as u32).map(|i| (i, i)).collect();
        let texts: Vec<String> = (0..n).map(|i| format!("текст {i}")).collect();
        assert_eq!(
            rerank_order(&LengthReranker, "q", &ann, &texts).unwrap_err(),
            RerankError::TooManyCandidates { count: n, limit: DEFAULT_RERANK_K }
        );
    }

    #[test]
    fn empty_shortlist_is_a_valid_empty_result() {
        assert!(rerank_order(&LengthReranker, "q", &[], &[]).unwrap().is_empty());
    }

    #[test]
    fn ordering_is_idempotent_and_stable_across_runs() {
        let scores: Vec<f32> = (0..64).map(|i| ((i * 7) % 5) as f32 * 0.25).collect();
        let ann: Vec<(u32, u32)> = (0..64).map(|i| (i, 1000 - i)).collect();
        let a = order_by_scores(&ann, &scores).unwrap();
        let b = order_by_scores(&ann, &scores).unwrap();
        assert_eq!(a, b);
        // Повторный прогон по уже отсортированному списку с теми же скорами ничего не меняет.
        let ann2: Vec<(u32, u32)> = a.iter().map(|d| (d.d2, d.slot)).collect();
        let scores2: Vec<f32> = a.iter().map(|d| d.score).collect();
        let c = order_by_scores(&ann2, &scores2).unwrap();
        assert_eq!(c.iter().map(|d| d.slot).collect::<Vec<_>>(), a.iter().map(|d| d.slot).collect::<Vec<_>>());
    }
}
