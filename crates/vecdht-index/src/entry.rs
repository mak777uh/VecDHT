//! Запись индекса шарда — ровно 424 байта payload (спека §8.2).
//!
//! Раскладка совпадает с `InsertOp` из `vecdht-wire`: то, что уходит по сети, и то, что лежит
//! в арене и в снапшоте, — одни и те же байты. Отдельного «формата хранения» нет намеренно:
//! в v7.5 их было два, и они разошлись на поле `scale`.
//!
//! Поле `scale` отсутствует: все векторы в одной глобальной сетке Δ=1/127 (§6.3), поэтому
//! целочисленное расстояние между записью и центроидом согласовано без пересчёта.

use vecdht_wire::codec::{DecodeError, Reader, Writer, DIM};
use vecdht_wire::messages::InsertOp;

/// Размер записи в байтах: 32 + 384 + 2 + 4 + 2.
pub const INDEX_ENTRY_BYTES: usize = 32 + DIM + 2 + 4 + 2;

/// Запись IVF-арены. `Copy` — чтобы скан не держил заимствование арены и чтобы снапшот
/// стримился блоками без аллокаций на запись.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    /// Ключ агента; PeerId выводится локально (§4.1). Дедуплицирующая часть `entry_key`.
    pub owner_ed25519: [u8; 32],
    /// int8, Δ=1/127 (§6.3).
    pub vec_q: [i8; DIM],
    /// Кластер, в котором лежит запись (§7.2).
    pub cluster_id: u16,
    /// `TimeMark`-бакет публикации (16 с), **не** локальные часы (§9.6).
    pub published_bucket: u32,
    /// TTL в бакетах по 16 с; `u16` вмещает ≈291 ч, политический лимит — 24 ч (§13).
    pub ttl_buckets: u16,
}

/// Проверка раскладки на этапе компиляции: 424 байта и `align ≤ 4`. Иначе бюджет §8.2
/// («1M записей в бюджете 428 МБ», тест §19.1) расходится с кодом молча.
const _: () = {
    assert!(core::mem::size_of::<IndexEntry>() == INDEX_ENTRY_BYTES);
    assert!(core::mem::align_of::<IndexEntry>() <= 4);
};

/// Пустая запись-заглушка для дыр в арене: `entries[slot]` у мёртвого slot'а обязан что-то
/// содержать, а бит bitmap говорит «мёртв». Реализация `Default` для массивов в std покрывает
/// не все длины (384 — не гарантируется), поэтому заполнение ручное, а не `derive`.
impl Default for IndexEntry {
    fn default() -> Self {
        IndexEntry {
            owner_ed25519: [0u8; 32],
            vec_q: [0i8; DIM],
            cluster_id: 0,
            published_bucket: 0,
            ttl_buckets: 0,
        }
    }
}

impl IndexEntry {
    #[inline]
    pub fn from_insert(op: &InsertOp) -> Self {
        IndexEntry {
            owner_ed25519: op.owner_ed25519,
            vec_q: op.vec_q,
            cluster_id: op.cluster_id,
            published_bucket: op.published_bucket,
            ttl_buckets: op.ttl_buckets,
        }
    }

    #[inline]
    pub fn to_insert(&self) -> InsertOp {
        InsertOp {
            owner_ed25519: self.owner_ed25519,
            vec_q: self.vec_q,
            cluster_id: self.cluster_id,
            published_bucket: self.published_bucket,
            ttl_buckets: self.ttl_buckets,
        }
    }

    /// Байты записи в wire-порядке. Тот же порядок полей, что `InsertOp::encode`.
    pub fn write(&self, w: &mut Writer) {
        w.fixed(&self.owner_ed25519);
        w.vec_q(&self.vec_q);
        w.u16(self.cluster_id);
        w.u32(self.published_bucket);
        w.u16(self.ttl_buckets);
    }

    /// Строгий читатель: хвост после 424 байт — ошибка, а не «следующая запись».
    pub fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(IndexEntry::from_insert(&InsertOp::decode(r)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_vec()
    }

    /// Те же 424 байта в буфер вызывающего, без промежуточной аллокации — это путь стриминга
    /// снапшота (§10.4), где `to_bytes()` на запись значимо при 1M записей.
    ///
    /// Порядок байтов обязан совпадать с `Writer::vec_q`: `i8` пишется как его собственный
    /// дополнительный байт, без zigzag и length-prefix.
    pub fn write_into(&self, out: &mut Vec<u8>) {
        out.reserve(INDEX_ENTRY_BYTES);
        out.extend_from_slice(&self.owner_ed25519);
        for v in self.vec_q {
            out.push(v as u8);
        }
        out.extend_from_slice(&self.cluster_id.to_le_bytes());
        out.extend_from_slice(&self.published_bucket.to_le_bytes());
        out.extend_from_slice(&self.ttl_buckets.to_le_bytes());
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let e = Self::read(&mut r)?;
        r.expect_end()?;
        Ok(e)
    }

    /// Бакет, в котором запись становится мёртвой. `saturating_add`: `u16` TTL при
    /// `published_bucket` близком к `u32::MAX` иначе вызвал бы панику в debug и оборот в release,
    /// а «вечно живая» запись — безобидный отказ, тогда как оборот снял бы её досрочно.
    #[inline]
    pub fn deadline_bucket(&self) -> u32 {
        self.published_bucket.saturating_add(self.ttl_buckets as u32)
    }

    /// Экспирация определяется **только** относительно `TimeMark`/`GcTick` (§9.6):
    /// `expire(entry) ⇔ published_bucket + ttl_buckets ≤ bucket`.
    #[inline]
    pub fn is_expired(&self, now_bucket: u32) -> bool {
        self.deadline_bucket() <= now_bucket
    }

    /// Ключ дедупликации в пределах шарда: `(owner, shard)`, где `shard` фиксирован самим
    /// индексом, поэтому в таблице остаётся `owner` (§8.3).
    #[inline]
    pub fn owner(&self) -> &[u8; 32] {
        &self.owner_ed25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::constants::NLIST;

    fn sample() -> IndexEntry {
        IndexEntry {
            owner_ed25519: [7u8; 32],
            vec_q: [-128i8; DIM],
            cluster_id: 1023,
            published_bucket: 0xFFFF_FFF0,
            ttl_buckets: 5400,
        }
    }

    #[test]
    fn layout_is_424_bytes() {
        assert_eq!(INDEX_ENTRY_BYTES, 424);
        assert_eq!(core::mem::size_of::<IndexEntry>(), 424);
        assert_eq!(sample().to_bytes().len(), 424);
    }

    #[test]
    fn wire_bytes_equal_insert_op_bytes() {
        let e = sample();
        assert_eq!(e.to_bytes(), e.to_insert().body_bytes());
        assert_eq!(IndexEntry::from_bytes(&e.to_bytes()).unwrap(), e);
    }

    #[test]
    fn bytes_are_read_back_for_every_field_order() {
        // Проверка, что чтение не «догадывается» о порядке: поворачиваем каждое поле.
        let base = sample();
        for (i, b) in base.owner_ed25519.iter().enumerate() {
            let mut e = base;
            e.owner_ed25519[i] = b.wrapping_add(1);
            assert_eq!(IndexEntry::from_bytes(&e.to_bytes()).unwrap(), e, "owner[{i}]");
        }
        let mut e = base;
        e.vec_q[0] = 127;
        e.vec_q[DIM - 1] = -1;
        assert_eq!(IndexEntry::from_bytes(&e.to_bytes()).unwrap().vec_q[DIM - 1], -1);
    }

    #[test]
    fn truncated_and_trailing_inputs_are_rejected() {
        let bytes = sample().to_bytes();
        for cut in [0, 1, 32, 415, 416, 420, 423] {
            assert!(IndexEntry::from_bytes(&bytes[..cut]).is_err(), "принят вход {cut} Б");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(IndexEntry::from_bytes(&extra).is_err(), "принят вход с хвостом");
    }

    #[test]
    fn expiry_is_purely_bucket_relative() {
        let e = IndexEntry { published_bucket: 100, ttl_buckets: 10, ..sample() };
        assert_eq!(e.deadline_bucket(), 110);
        assert!(!e.is_expired(109), "жива ровно до дедлайна");
        assert!(e.is_expired(110), "спека: expire ⇔ published+ttl ≤ bucket");
        assert!(e.is_expired(1_000_000));
    }

    #[test]
    fn near_overflow_bucket_does_not_wrap_the_deadline() {
        // Тот случай, который оборачивается при наивном `+`: без saturating запись с
        // published_bucket = u32::MAX-8 «истекает» в бакете 0.
        let e = IndexEntry { published_bucket: u32::MAX - 8, ttl_buckets: 100, ..sample() };
        assert_eq!(e.deadline_bucket(), u32::MAX);
        assert!(!e.is_expired(0));
        assert!(!e.is_expired(u32::MAX - 1));
        assert!(e.is_expired(u32::MAX));
    }

    #[test]
    fn ttl_field_holds_the_political_limit() {
        // §13: лимит жизни 24 ч = 86400 с / 16 = 5400 бакетов; поле u16 — с запасом (§8.2).
        let buckets_24h = 24 * 60 * 60 / crate::TIME_BUCKET_SEC;
        assert_eq!(buckets_24h, 5400);
        assert!(buckets_24h <= u16::MAX as u32, "{buckets_24h}");
        // Начало жизни — обычный бакет, а не `u32::MAX`: тут проверяется поле TTL, а не переполнение.
        let e = IndexEntry { published_bucket: 1000, ttl_buckets: buckets_24h as u16, ..sample() };
        assert!(!e.is_expired(1000 + buckets_24h - 1), "снята на секунду раньше дедлайна");
        assert!(e.is_expired(1000 + buckets_24h), "24-часовой TTL не влезает в поле");
    }

    #[test]
    fn cluster_id_domain_matches_nlist() {
        let e = sample();
        assert!((e.cluster_id as u32) < NLIST as u32);
    }
}
