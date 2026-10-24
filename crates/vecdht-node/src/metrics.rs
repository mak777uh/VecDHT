//! Снимок наблюдения узла (Приложение C): конечный список пар `(имя, u64)`.
//!
//! Конечность — по построению, а не по дисциплине: имя берётся из константного массива
//! [`NAMES`], значение — одно из полей, которые узел уже считает для протокола или для
//! собственных решений. Свободной строки в снимке нет, метки с ценой интента тоже: цена живёт
//! в байтах `slot_attr` (§5.5) и в наблюдение не выносится — метка с числовым значением цены
//! была бы кардинальностью без предела и утечкой объявления.
//!
//! Снимок — не эндпоинт и не формат провода. `render()` печатает стабильные строки
//! `имя=значение` для оператора и для стенда P1; сетевой поверхности у него в v1 нет.
//!
//! Чего здесь нет и почему — это не забывчивость, а граница цикла `H-0104`: `shard_resolve_ms`,
//! `find_rpc_latency_ms`, `index_scan_us`, `embed_latency_ms`, `rerank_ms` — величины со
//! стороны клиента или таймеры, которых продукт пока не считает; `replica_lag_ops` требует
//! сравнения `applied_seq` двух узлов, а узел о соседе знает только `Awaiting`; `gc_freed`,
//! `snapshot_seconds` — события, чья цена измерена тестом, но не накоплена счётчиком. Таблица
//! «метрика → источник или нет источника в v1» — `lab/decisions/ADR-0059-metrics-surface.md`.

use crate::node::ShardNode;

/// Имена полей снимка в том порядке, в котором их печатает `render()`. Порядок — часть
/// контракта: два прогона стенда обязаны давать побайтово сравнимые снимки (правило 7 (е)).
pub const NAMES: [&str; 37] = [
    // Локальная политика приёма §11.3 и её решения (§14.4 iv).
    "admit_publishes_allowed",
    "admit_finds_allowed",
    "admit_denied_by_denylist",
    "admit_denylist_refused_at_bound",
    "admit_denylist_save_errors",
    "admit_rejected_publish_quota",
    "admit_rejected_find_quota",
    "admit_rejected_node_busy",
    "admit_forgotten_peers",
    "cell_cap_moves",
    "cell_cap_rejections",
    "cluster_reassigned",
    "cluster_cross_shard",
    "cluster_unverified",
    // Состояние шарда: что применено и что лежит (§8, §10).
    "applied_seq",
    "next_seq",
    "max_epoch_served",
    "epoch_served",
    "live_records",
    "tombstone_slots",
    "last_snapshot_seq",
    "replayed_ops",
    "time_mark_bucket",
    "wal_bytes",
    // Разбивка памяти §8.2.
    "mem_arena_bytes",
    "mem_lists_bytes",
    "mem_owners_bytes",
    "mem_bitmap_bytes",
    "mem_slot_attr_bytes",
    "mem_total_bytes",
    // Параметры и роль узла.
    "pow_bits_current",
    "gc_ticks",
    "centroids_loaded",
    "membership_epoch",
    "membership_members",
    "lease_epoch",
    "lease_active_at_mark",
];

/// Снимок узла. Поля — `Vec`, а не структура с 37 полями, намеренно: потребитель (стенд P1,
/// CLI) обходит его циклом, и добавить имя без значения компилятор не даст (см. `of`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeMetrics {
    pairs: Vec<(&'static str, u64)>,
}

impl NodeMetrics {
    /// Снять снимок с живого узла. Боров заимствуется на время вызова: `assign`/`publish`
    /// в это же время не исполняются (узел не многопоточный), а снимок не держит ссылку дольше.
    pub fn of(node: &ShardNode) -> Self {
        let stats = node.admission.borrow().stats;
        let s = &node.store;
        let mem = s.index.mem_bytes();
        let membership_epoch = node.membership.as_ref().map_or(0, |m| m.epoch());
        let membership_members = node.membership.as_ref().map_or(0, |m| m.len() as u64);
        let lease_epoch = node.lease.as_ref().map_or(0, |l| l.epoch);
        // «Активен на последней наблюдённой метке» — это не часы: у узла нет wall-clock (§9.6),
        // и `time_mark_bucket` — единственное «сейчас», которое он признаёт.
        let lease_active = node
            .lease
            .as_ref()
            .is_some_and(|l| l.active_at(s.time_mark_bucket));
        let pairs = vec![
            ("admit_publishes_allowed", stats.publishes_allowed),
            ("admit_finds_allowed", stats.finds_allowed),
            ("admit_denied_by_denylist", stats.denied_by_denylist),
            ("admit_denylist_refused_at_bound", stats.denylist_refused_at_bound),
            ("admit_denylist_save_errors", stats.denylist_save_errors),
            ("admit_rejected_publish_quota", stats.rejected_publish_quota),
            ("admit_rejected_find_quota", stats.rejected_find_quota),
            ("admit_rejected_node_busy", stats.rejected_node_busy),
            ("admit_forgotten_peers", stats.forgotten_peers),
            ("cell_cap_moves", stats.cell_cap_moves),
            ("cell_cap_rejections", stats.cell_cap_rejections),
            ("cluster_reassigned", stats.cluster_reassigned),
            ("cluster_cross_shard", stats.cluster_cross_shard),
            ("cluster_unverified", stats.cluster_unverified),
            ("applied_seq", s.applied_seq),
            ("next_seq", s.next_seq),
            ("max_epoch_served", s.max_epoch_served),
            ("epoch_served", s.epoch),
            ("live_records", s.index.live as u64),
            ("tombstone_slots", s.index.tombstones as u64),
            ("last_snapshot_seq", s.last_snapshot_seq),
            ("replayed_ops", s.replayed),
            ("time_mark_bucket", u64::from(s.time_mark_bucket)),
            ("wal_bytes", s.wal.bytes()),
            ("mem_arena_bytes", mem.arena as u64),
            ("mem_lists_bytes", mem.lists as u64),
            ("mem_owners_bytes", mem.owners as u64),
            ("mem_bitmap_bytes", mem.bitmap as u64),
            ("mem_slot_attr_bytes", mem.slot_attr as u64),
            ("mem_total_bytes", mem.total() as u64),
            ("pow_bits_current", u64::from(node.pow_bits)),
            ("gc_ticks", node.gc_ticks),
            ("centroids_loaded", node.centroids.is_some() as u64),
            ("membership_epoch", membership_epoch),
            ("membership_members", membership_members),
            ("lease_epoch", lease_epoch),
            ("lease_active_at_mark", lease_active as u64),
        ];
        // Контракт «имя ↔ значение» проверяется здесь, а не в тесте: снимок с 36 именами при
        // 37 объявленных — это метрика, которая молча исчезла из наблюдения.
        debug_assert_eq!(pairs.len(), NAMES.len(), "снимок разошёлся с NAMES");
        Self { pairs }
    }

    pub fn pairs(&self) -> &[(&'static str, u64)] {
        &self.pairs
    }

    pub fn get(&self, name: &str) -> Option<u64> {
        self.pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }

    /// Стабильный текст для оператора и стенда: одна пара на строку, порядок [`NAMES`].
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.pairs.len() * 32);
        for (name, value) in &self.pairs {
            out.push_str(name);
            out.push('=');
            out.push_str(&value.to_string());
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_lowercase_ascii() {
        let mut seen = std::collections::BTreeSet::new();
        for n in NAMES {
            assert!(seen.insert(n), "имя повторено: {n}");
            assert!(
                n.bytes().all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()),
                "имя вне [a-z0-9_]: {n}"
            );
        }
        assert_eq!(seen.len(), NAMES.len());
    }

    #[test]
    fn no_price_or_free_text_metric() {
        for n in NAMES {
            for bad in ["price", "cost", "amount", "unit", "text", "reason"] {
                assert!(!n.contains(bad), "метрика `{n}` содержит запрещённую основу `{bad}`");
            }
        }
    }
}
