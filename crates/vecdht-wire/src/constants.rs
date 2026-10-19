//! Константы протокола, влияющие на байтовое представление.
//!
//! Они живут в `vecdht-wire`, потому что это факты кодирования (длины фиксированных массивов,
//! границы валидности полей). `vecdht-artifact` использует те же значения как параметры
//! артефакта и сверяет их при загрузке (§15.3).

/// Размерность квантованного вектора (совпадает с `codec::DIM`).
pub use crate::codec::DIM;

/// Проверка постоянного выражения на этапе компиляции.
#[macro_export]
macro_rules! static_assert {
    ($cond:expr) => {
        const _: [(); true as usize] = [(); $cond as usize];
    };
}

/// Число центроидов глобального coarse-квантизатора (§7.1).
pub const NLIST: u16 = 1024;

/// Кластеров на шард (§7.4).
pub const CLUSTERS_PER_SHARD: u16 = 16;

/// Шардов на сеть — и ровно столько DHT-ключей (§7.4).
pub const SHARDS: u16 = NLIST / CLUSTERS_PER_SHARD;

static_assert!(SHARDS == 64);

/// Бакет времени в секундах (§9.6). `bucket = unix_sec / 16`.
pub const TIME_BUCKET_SEC: u32 = 16;

/// Контрактная граница квадрата дистанции (§6.4): `127² · 4 + 64 = 64 580 ≤ 65 536`.
pub const MAX_D2: u32 = 65_536;

/// Масштаб сетки квантования: Δ = 1/127 (§6.3).
pub const Q_SCALE: f64 = 127.0;

/// `shard_of` — единственная функция отображения кластера в шард.
#[inline]
pub const fn shard_of(cluster_id: u16) -> u16 {
    cluster_id / CLUSTERS_PER_SHARD
}

/// Единственный DHT-ключ на шард, 12 байт, без band-суффиксов (§7.4).
pub fn shard_provider_key(shard: u16) -> Vec<u8> {
    let mut k = Vec::with_capacity(12);
    k.extend_from_slice(b"vdht/s8/");
    k.extend_from_slice(&shard.to_be_bytes());
    k.extend_from_slice(&[0u8, 0u8]);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_key_layout() {
        let k = shard_provider_key(1);
        assert_eq!(k.len(), 12);
        assert_eq!(&k[..8], b"vdht/s8/");
        assert_eq!(&k[8..10], &[0u8, 1u8], "shard — big-endian в ключе DHT");
        assert_eq!(&k[10..], &[0u8, 0u8]);
        let k63 = shard_provider_key(63);
        assert_eq!(&k63[8..10], &[0u8, 63u8]);
    }

    #[test]
    fn shard_mapping_covers_all_clusters() {
        for c in 0..NLIST {
            assert!(shard_of(c) < SHARDS);
        }
        assert_eq!(shard_of(0), 0);
        assert_eq!(shard_of(15), 0);
        assert_eq!(shard_of(16), 1);
        assert_eq!(shard_of(1023), 63);
    }

    #[test]
    fn max_d2_bound_is_sound() {
        // Худший случай сетки: две антиподальные точки единичной нормы.
        let worst = (Q_SCALE * Q_SCALE * 4.0) as u32 + 64;
        assert!(worst <= MAX_D2, "{worst}");
    }
}
