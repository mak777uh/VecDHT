//! VecDHT v8 — embedding contract (спека §6, §18.1).
//!
//! Граница модулей совпадает с границей детерминизма, а не с границей «ML / не-ML»:
//!
//! * [`text`], [`prefix`], [`model::finalize`], [`cache`], [`rerank::order_by_scores`], [`metrics`]
//!   — шаги 1–3 и 6–8 пайплайна §6.2. Это байтовые правила и целочисленная арифметика: они
//!   обязаны давать один и тот же результат на AVX-512, AVX2 и NEON, и они тестируются без весов;
//! * шаг 4 (forward) — единственный недетерминированный шаг, и он живёт за feature `candle`
//!   ([`candle_backend`]) как реализация трейта [`model::EmbeddingModel`].
//!
//! Отсюда разделение гейтов P0 (§18.1): (iv) детерминизм измеряется здесь и сейчас, а (i)
//! throughput инференса, (iii) дельта nDCG и (v) совпадение с HF-референсом требуют весов и
//! tokenizer'а — [`testing`] даёт для них только механику (целочисленная половина (i) измеряется
//! в `tests/p0_harness.rs` и без весов), а числовые обещания §18.1 без `VEC_DHT_MODEL_DIR` не
//! измеряются вообще.
//!
//! Что crate сознательно **не** делает:
//!
//! * не считает `intent_text_hash` сам — текст под подписью (§6.6) это каноническая форма из
//!   [`text::normalize_text`], а хеш и подпись живут в `vecdht-crypto`;
//! * не трогает индекс и сеть — `cluster_id` здесь только присваивается по замороженным
//!   центроидам (§7.2), список зондируемых кластеров отдаётся как есть;
//! * не хранит часы — TTL кеша считается в бакетах, которые передаёт вызывающий код (§9.6).

#![forbid(unsafe_code)]

pub mod cache;
pub mod kmeans;
pub mod metrics;
pub mod model;
pub mod prefix;
pub mod publish;
pub mod rerank;
pub mod shardmap;
pub mod text;

#[cfg(feature = "candle")]
pub mod candle_backend;

/// Вендоренный ModernBERT-backbone: upstream candle жёстко использует GELU и теряет
/// `hidden_activation: silu` из config.json granite-97m-r2 (§18.1 v).
#[cfg(feature = "candle")]
pub(crate) mod modernbert_backbone;

/// Детерминированные оракулы для тестов всего репозитория (см. модуль). Публичный и без feature,
/// потому что интеграционные тесты собирают crate как зависимость и `cfg(test)` для них
/// не включается.
pub mod testing;

pub use cache::{CacheKey, CacheStats, EmbedCache};
pub use model::{
    finalize, EmbedError, EmbeddingModel, Encoded, Encoder, Intent, Pooled, Query, quantize_pooled,
};
pub use prefix::{PrefixError, PrefixPolicy};
pub use rerank::{order_by_scores, RankedDoc, RerankError, Reranker, rerank_order};
pub use text::{emb_digest, is_canonical, normalize_text, TextError};
pub use vecdht_wire::messages::MAX_INTENT_TEXT_BYTES;

/// Версия пайплайна preprocessинга, которую реализует этот crate (§6.2). Она обязана совпасть с
/// `preprocessing_version` артефакта — расхождение читается как `MODEL_MISMATCH` (§6.7), а не как
/// «поищем чуть хуже».
pub const PREPROCESSING_VERSION: u16 = 1;
