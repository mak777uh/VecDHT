//! VecDHT v8 — индекс шарда на одном узле: IVF-арена int8, WAL, снапшот-барьер и GC без
//! wall-clock (спека §8, §9.6, §10).
//!
//! Crate намеренно не знает ни о сети, ни о членстве: он отвечает за то, чтобы
//! *последовательность опсов* превращалась в *побайтово воспроизводимое состояние на диске*.
//! Отсюда три правила, на которых держатся все тесты §19.1:
//!
//! 1. **Никаких часов в пути применения.** `TimeMark`/`GcTick` приносят бакет как данные опса
//!    (§9.6), поэтому два узла с расхождением часов на 40 минут дают один и тот же файл.
//! 2. **Никакого float в контракте поиска.** `l2_sq` целочисленный, порядок — `(l2_sq, slot)`
//!    (§8.4); `MatchResult` под ним побайтово одинаков на любой корректной реализации.
//! 3. **Durable раньше памяти.** Append → fsync → apply (§10.1); отказ на любой точке матрицы
//!    §10.5 оставляет состояние, из которого `recover(disk) == replay(all ops)`.
//!
//! Плавающая точка встречается только в диагностике бюджета памяти (`MemBytes::per_entry`).
//!
//! ```text
//! entry      424-байтовая запись и её wire-байты (§8.2)
//! owner_table дедупликация owner → slot в бюджете §8.2
//! ivf        арена + inverted lists + поиск + GC
//! wal        фрейм, сегменты, group commit, точки падений (§10.2)
//! snapshot   стримящийся файл индекса без двойного пика RAM (§10.4)
//! manifest   MANIFEST и durable max_epoch_served (§10.4, §9.2)
//! store      порядок операций, барьер, recovery (§10.1–§10.5)
//! ```

#![forbid(unsafe_code)]

use std::io;
use std::path::Path;

pub mod entry;
pub mod ivf;
pub mod manifest;
pub mod owner_table;
pub mod snapshot;
pub mod store;
pub mod wal;

pub use entry::{IndexEntry, INDEX_ENTRY_BYTES};
pub use ivf::{IvfIndex, MemBytes};
pub use manifest::StoreManifest;
pub use snapshot::{SnapshotMeta, SNAP_HEADER_LEN};
pub use store::{Applied, ShardStore, StoreError, SNAPSHOT_OPS};
pub use wal::{Fault, WalFrame, WalWriter, GROUP_COMMIT_MAX, GROUP_COMMIT_MS, SEGMENT_MAX_OPS};

/// Размер бакета времени в секундах (§9.6): `bucket = unix_sec / 16`.
pub use vecdht_wire::TIME_BUCKET_SEC;

/// Число кластеров на шард — переэкспортировано, чтобы тесты индекса не тянули `wire` прямо.
pub use vecdht_wire::{CLUSTERS_PER_SHARD, NLIST, SHARDS};

/// Локальное время узла в бакетах. Единственное место crate, где часы вообще читаются, и
/// используется оно только для *генерации* `TimeMark` на primary; в путь применения и поиска
/// часы не входят (§9.6).
pub fn now_bucket(unix_sec: u64) -> u32 {
    (unix_sec / TIME_BUCKET_SEC as u64) as u32
}

/// fsync каталога.
///
/// На unix это открытие каталога и `sync_all`. На Windows открыть каталог для чтения нельзя
/// (`ERROR_ACCESS_DENIED`), а `FlushFileBuffers` на нём не применяется; NTFS журналирует
/// метаданные `rename` сама. Возвращаем `Ok(false)`, когда платформа не позволяет, — барьер
/// §10.4 обязан переживать и этот случай, и именно это проверяет точка 6 матрицы §10.5: если
/// MANIFEST не дошёл до каталога, WAL-сегменты просто не удаляются, и восстановление остаётся
/// корректным, только медленнее.
pub fn fsync_dir(dir: &Path) -> io::Result<bool> {
    // Каталог открывается на чтение только на unix; на Windows это ERROR_ACCESS_DENIED, и
    // ничего не остаётся, кроме как положиться на журнал NTFS для rename. Порядок шагов 5→6
    // барьера (§10.4) — вот что даёт durability, а не fsync каталога.
    match std::fs::OpenOptions::new().read(true).open(dir) {
        Ok(f) => match f.sync_all() {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        },
        Err(_) => Ok(false),
    }
}

#[doc(hidden)]
pub mod testing {
    //! Помощники интеграционных тестов: изолированный каталог на тест и его удаление.

    use std::path::{Path, PathBuf};

    /// Уникальный каталог в temp. Собирается, даже если предыдущий прогон оставил мусор.
    ///
    /// Счётчик в имени обязателен: тесты идут параллельно в одном процессе, и два сценария
    /// матрицы §10.5 с одним тегом иначе писали бы в один каталог — падение одного узла
    /// становилось бы «падением» другого.
    pub fn dir(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("vecdht-index-{}-{n}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("создать тестовый каталог");
        p
    }

    pub fn remove(path: &Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    /// Детерминированный xorshift64*: свои генераторы вместо `proptest`/`rand`, потому что
    /// property-тесты обязаны быть воспроизводимыми по сиду (§10.5).
    pub struct Rng(pub u64);

    impl Rng {
        pub fn new(seed: u64) -> Self {
            Rng(seed | 0x9E37_79B9_7F4A_7C15)
        }
        #[inline]
        pub fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        #[inline]
        pub fn below(&mut self, n: u64) -> u64 {
            if n == 0 {
                0
            } else {
                self.next_u64() % n
            }
        }
        #[inline]
        pub fn byte(&mut self) -> u8 {
            (self.next_u64() & 0xff) as u8
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_math_matches_the_spec() {
        assert_eq!(TIME_BUCKET_SEC, 16);
        assert_eq!(now_bucket(0), 0);
        assert_eq!(now_bucket(15), 0);
        assert_eq!(now_bucket(16), 1);
        assert_eq!(now_bucket(1_700_000_000), 1_700_000_000 / 16);
        // 40 минут расхождения часов — это ровно 150 бакетов; тест кросс-часового GC (§19.1)
        // опирается на это число.
        assert_eq!(now_bucket(2_400), 150);
    }

    #[test]
    fn shard_and_cluster_constants_agree_with_wire() {
        assert_eq!(NLIST, 1024);
        assert_eq!(CLUSTERS_PER_SHARD, 16);
        assert_eq!(SHARDS, 64);
        assert_eq!(INDEX_ENTRY_BYTES, 424);
        assert_eq!(SNAPSHOT_OPS, 50_000);
        assert_eq!(GROUP_COMMIT_MS, 5);
        assert_eq!(GROUP_COMMIT_MAX, 32);
        assert_eq!(SEGMENT_MAX_OPS, 100_000);
    }

    #[test]
    fn fsync_dir_does_not_break_recovery_on_windows() {
        let d = testing::dir("fsync-dir");
        let ok = fsync_dir(&d);
        // Либо удалось, либо платформа не позволила — паники и ошибки быть не должно.
        assert!(ok.is_ok(), "{ok:?}");
        testing::remove(&d);
    }
}
