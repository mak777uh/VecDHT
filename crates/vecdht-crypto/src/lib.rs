//! VecDHT v8 — детерминизм и криптография приложения (спека §4–§6, §11).
//!
//! Четыре слоя, и все они обязаны быть воспроизводимы байт-в-байт между железом:
//!
//! * [`quant`] — фиксированная точка Δ=1/127, целочисленные дистанции, присваивание кластера;
//!   после `quantize` плавающей точки в consensus-path нет;
//! * [`ids`] — три неразделённые ранее идентификатора: `intent_id` (advisory), `entry_key`
//!   (авторитетный dedup-слот), `cluster_id` (routing, не consensus);
//! * [`pow`] — publish-стоимость как blake3, привязанный к `(owner, shard, epoch, slot,expiry)`;
//!   Argon2id из v7.5 удалён;
//! * [`sig`] + [`cert`] — Ed25519 с доменной реализацией и пороговый кредашиал роли.
//!
//! Crate не знает ни о каком сетевом транспорте: `PeerId` выводит libp2p (§4.1), здесь его нет.
//! Никакого `unsafe` и никаких глобальных инициализаторов — детерминизм должен быть локальным
//! свойством функций.

#![forbid(unsafe_code)]

pub mod cert;
pub mod ids;
pub mod pow;
pub mod quant;
pub mod sig;

pub use cert::{
    build_revoke, sign_cert, sign_cert_identity, verify_cert, verify_index_cert, verify_revoke,
    AuthoritySet, CertError, DOMAIN_CERT_REVOKED, DOMAIN_NODE_CERT, MAX_AUTHORITY_SIGS,
};
pub use ids::{
    candidate_order_key, content_hash, entry_key, intent_id, intent_text_hash, DedupKey,
    DOMAIN_CANDIDATE_ORDER, DOMAIN_ENTRY_KEY, DOMAIN_INTENT, DOMAIN_INTENT_TEXT,
};
pub use pow::{
    expected_millis, mine_pow, pow_input, pow_ok, PowError, BLAKE3_MHZ_CORE_FALLBACK,
    POW_BITS_DEFAULT, POW_BITS_MAX, POW_BITS_MIN, POW_DOMAIN,
};
pub use quant::{
    assign_cluster, clusters_of_shard, dequantize, group_by_shard, is_valid_shard, l2_normalize,
    l2_sq, quantize, quantize_slice, round_half_away, shard_of_cluster, similarity_from_d2,
    top_clusters, QuantError,
};
pub use sig::{
    sign_domain, sig_digest, verify_body, verify_domain, verifying, Identity, SigError,
};

/// Реэкспорт, чтобы потребитель `vecdht-crypto` не зависел от пути `vecdht-wire` напрямую.
pub use vecdht_wire::DIM;
