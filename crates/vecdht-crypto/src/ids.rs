//! Идентификаторы v8 (спека §6.5): три разные сущности вместо перегруженного «fingerprint».

use blake3::Hasher;
use vecdht_wire::DIM;

pub const DOMAIN_INTENT: &[u8] = b"vecdht/v8/intent";
pub const DOMAIN_ENTRY_KEY: &[u8] = b"vecdht/v8/entry_key";
pub const DOMAIN_CANDIDATE_ORDER: &[u8] = b"vecdht/v8/candidate_order";
pub const DOMAIN_INTENT_TEXT: &[u8] = b"vecdht/v8/text";

/// `intent_id = blake3(v ‖ preprocessing_version)` — advisory: идемпотентность, кеш
/// embedding'ов, диагностика. Не consensus-critical: ложное совпадение стоит только лишний
/// publish, расхождение — только лишнюю запись.
pub fn intent_id(vec_q: &[i8; DIM], preprocessing_version: u16) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_INTENT);
    h.update(&preprocessing_version.to_le_bytes());
    h.update(&as_bytes_owned(vec_q));
    *h.finalize().as_bytes()
}

/// `entry_key` — авторитетный dedup-слот. Ровно один живой интент на агента на шард
/// на эпизоде; republish заменяет запись на месте в том же слоте (дефект 7d).
pub fn entry_key(
    owner_ed25519: &[u8; 32],
    shard: u16,
    slot: u32,
    epoch: u64,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_ENTRY_KEY);
    h.update(owner_ed25519);
    h.update(&shard.to_le_bytes());
    h.update(&slot.to_le_bytes());
    h.update(&epoch.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Ключ dedup-индекса узла: `(owner, shard) → slot`. Отдельный тип, чтобы нельзя было
/// перепутать с `entry_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DedupKey {
    pub owner_ed25519: [u8; 32],
    pub shard: u16,
}

impl DedupKey {
    pub fn new(owner_ed25519: [u8; 32], shard: u16) -> Self {
        Self { owner_ed25519, shard }
    }
}

/// Детерминированная непредвзятая перестановка кандидатов на шард (§9.3).
/// Сортировка по этому значению не зависит от того, кто её считает, и не контролируется
/// кандидатом (в v7.5 tie-break шёл по `uptime_bucket`).
pub fn candidate_order_key(epoch: u64, shard: u16, owner_ed25519: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_CANDIDATE_ORDER);
    h.update(&epoch.to_le_bytes());
    h.update(&shard.to_le_bytes());
    h.update(owner_ed25519);
    *h.finalize().as_bytes()
}

/// Отпечаток canonical intent_text: и кеш-ключ, и материал для подписи текста (§6.6).
pub fn intent_text_hash(text: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_INTENT_TEXT);
    h.update(text);
    *h.finalize().as_bytes()
}

/// Контент-хеш произвольных байтов (артефакт, снапшот, genesis).
pub fn content_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[inline]
fn as_bytes_owned(v: &[i8; DIM]) -> [u8; DIM] {
    let mut b = [0u8; DIM];
    for (o, i) in b.iter_mut().zip(v.iter()) {
        *o = *i as u8;
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_domain_separated() {
        let v = [1i8; DIM];
        let owner = [2u8; 32];
        let a = intent_id(&v, 3);
        let b = entry_key(&owner, 1, 2, 3);
        let c = candidate_order_key(3, 1, &owner);
        assert_ne!(a, b);
        assert_ne!(b, c);
    }

    #[test]
    fn intent_id_depends_on_preprocessing_version() {
        let v = [0i8; DIM];
        assert_ne!(intent_id(&v, 1), intent_id(&v, 2));
    }

    #[test]
    fn entry_key_separates_slots_and_shards() {
        let o = [7u8; 32];
        assert_ne!(entry_key(&o, 1, 1, 1), entry_key(&o, 1, 2, 1));
        assert_ne!(entry_key(&o, 1, 1, 1), entry_key(&o, 2, 1, 1));
        assert_ne!(entry_key(&o, 1, 1, 1), entry_key(&o, 1, 1, 2));
    }

    #[test]
    fn dedup_key_orders_deterministically() {
        let mut ks = vec![
            DedupKey::new([2u8; 32], 5),
            DedupKey::new([1u8; 32], 7),
            DedupKey::new([1u8; 32], 5),
        ];
        ks.sort_unstable();
        assert_eq!(ks[0], DedupKey::new([1u8; 32], 5));
        assert_eq!(ks[1], DedupKey::new([1u8; 32], 7));
    }

    #[test]
    fn intent_text_hash_matches_content_hash_domain() {
        let t = b"hello";
        assert_ne!(intent_text_hash(t), content_hash(t), "домены разные");
        assert_eq!(intent_text_hash(t), intent_text_hash(t));
    }
}
