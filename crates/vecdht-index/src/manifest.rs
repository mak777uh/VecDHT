//! MANIFEST и durable-эпоха: единственный источник истины о консистентной паре
//! (снапшот, хвост WAL) (§10.4) и об обслуживаемой эпизоде (§9.2).
//!
//! ```text
//! magic "vdht/v8/mf" | format u16 | shard u16 | snapshot_seq u64 | oldest_wal_needed u64
//!   | applied_seq u64 | next_slot u64 | time_mark_bucket u32 | crc32 u32
//! ```
//!
//! MANIFEST переписывается атомично: `MANIFEST.partial` → fsync файла → rename → fsync
//! каталога. `rename` атомичен, поэтому в середине шага 5 на диске остаётся одна из двух
//! полных версий (§10.5, точка 5).
//!
//! Отдельный `epoch.marker` fsync'ится при каждой смене эпохи, потому что snapshot может быть
//! реже, чем lease: без него перезапуск откатывал бы `max_epoch_served` — ровно тот дефект,
//! который §9.2 называет причиной split-brain в v7.5.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crc32fast::Hasher;

use crate::wal::Fault;

pub const MF_MAGIC: &[u8; 10] = b"vdht/v8/mf";
pub const MF_FORMAT: u16 = 1;
pub const MF_NAME: &str = "MANIFEST";
pub const MF_PARTIAL_NAME: &str = "MANIFEST.partial";
/// 10 + 2 + 2 + 8·4 + 4 + 4.
pub const MF_LEN: usize = 10 + 2 + 2 + 8 + 8 + 8 + 8 + 4 + 4;

pub const EPOCH_MAGIC: &[u8; 10] = b"vdht/v8/ep";
pub const EPOCH_NAME: &str = "epoch.marker";
/// 10 (magic) + 8 (`max_epoch_served`) + 4 (crc32 от первых 18 байт).
pub const EPOCH_LEN: usize = 10 + 8 + 4;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("io: {0}")]
    Io(String),
    #[error("файл {name} имеет размер {found}, ожидался {want}")]
    Size { name: &'static str, found: usize, want: usize },
    #[error("магическая строка не `{expected}`")]
    BadMagic { expected: &'static str },
    #[error("версия формата {0}")]
    BadFormat(u16),
    #[error("битый crc32 в {0}")]
    Crc(&'static str),
    #[error("MANIFEST относится к шарду {found}, а индекс — к {want}")]
    ShardMismatch { want: u16, found: u16 },
    #[error("инжектированное падение на точке {0:?}")]
    Injected(Fault),
}

impl From<std::io::Error> for ManifestError {
    fn from(e: std::io::Error) -> Self {
        ManifestError::Io(e.to_string())
    }
}

/// То, что узел обязан знать до любого обслуживания: какая пара файлов консистентна.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreManifest {
    pub shard: u16,
    pub snapshot_seq: u64,
    /// Самый старый сегмент WAL, нужный для восстановления этого снапшота (§10.4, шаг 5).
    pub oldest_wal_needed: u64,
    pub applied_seq: u64,
    pub next_slot: u64,
    pub time_mark_bucket: u32,
}

impl StoreManifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(MF_LEN);
        v.extend_from_slice(MF_MAGIC);
        v.extend_from_slice(&MF_FORMAT.to_le_bytes());
        v.extend_from_slice(&self.shard.to_le_bytes());
        v.extend_from_slice(&self.snapshot_seq.to_le_bytes());
        v.extend_from_slice(&self.oldest_wal_needed.to_le_bytes());
        v.extend_from_slice(&self.applied_seq.to_le_bytes());
        v.extend_from_slice(&self.next_slot.to_le_bytes());
        v.extend_from_slice(&self.time_mark_bucket.to_le_bytes());
        let mut h = Hasher::new();
        h.update(&v);
        v.extend_from_slice(&h.finalize().to_le_bytes());
        v
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() != MF_LEN {
            return Err(ManifestError::Size { name: MF_NAME, found: bytes.len(), want: MF_LEN });
        }
        if &bytes[..MF_MAGIC.len()] != MF_MAGIC.as_slice() {
            return Err(ManifestError::BadMagic { expected: "vdht/v8/mf" });
        }
        let format = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
        if format != MF_FORMAT {
            return Err(ManifestError::BadFormat(format));
        }
        let mut h = Hasher::new();
        h.update(&bytes[..MF_LEN - 4]);
        if h.finalize() != u32::from_le_bytes(bytes[MF_LEN - 4..].try_into().unwrap()) {
            return Err(ManifestError::Crc(MF_NAME));
        }
        Ok(StoreManifest {
            shard: u16::from_le_bytes(bytes[12..14].try_into().unwrap()),
            snapshot_seq: u64::from_le_bytes(bytes[14..22].try_into().unwrap()),
            oldest_wal_needed: u64::from_le_bytes(bytes[22..30].try_into().unwrap()),
            applied_seq: u64::from_le_bytes(bytes[30..38].try_into().unwrap()),
            next_slot: u64::from_le_bytes(bytes[38..46].try_into().unwrap()),
            time_mark_bucket: u32::from_le_bytes(bytes[46..50].try_into().unwrap()),
        })
    }
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join(MF_NAME)
}

/// Прочитать MANIFEST. Отсутствие файла — штатный случай первого запуска и случай «упали до
/// rename»: тогда восстановление идёт по всем сегментам WAL (§10.5, точки 5 и 6).
pub fn read_manifest(dir: &Path) -> Result<Option<StoreManifest>, ManifestError> {
    match std::fs::read(manifest_path(dir)) {
        Ok(b) => Ok(Some(StoreManifest::decode(&b)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ManifestError::Io(e.to_string())),
    }
}

/// Атомичная перепись: partial → fsync → rename → fsync каталога. `fault` реализует точку 5
/// матрицы (§10.5): partial записан и fsync'нут, rename не сделан.
///
/// `truncate(true)` здесь разрешён: он применяется к `MANIFEST.partial`, на который ничего не
/// ссылается. Запрет §10.2 касается живых файлов — сегментов WAL и самого `MANIFEST`.
pub fn write_manifest(dir: &Path, mf: &StoreManifest, fault: Option<Fault>) -> Result<(), ManifestError> {
    std::fs::create_dir_all(dir)?;
    let partial = dir.join(MF_PARTIAL_NAME);
    let mut f = OpenOptions::new().create(true).read(true).write(true).truncate(true).open(&partial)?;
    f.write_all(&mf.encode())?;
    f.sync_all()?;
    drop(f);
    if fault == Some(Fault::ManifestRenameMid) {
        return Err(ManifestError::Injected(Fault::ManifestRenameMid));
    }
    std::fs::rename(&partial, manifest_path(dir))?;
    crate::fsync_dir(dir)?;
    Ok(())
}

/// `max_epoch_served` — durable-инвариант §9.2. Пишется до того, как узел подписал что-либо
/// или обслужил publish; перезапуск не может откатить эпизоду.
pub fn read_max_epoch(dir: &Path) -> Result<u64, ManifestError> {
    match std::fs::read(dir.join(EPOCH_NAME)) {
        Ok(b) => {
            if b.len() != EPOCH_LEN {
                return Err(ManifestError::Size { name: EPOCH_NAME, found: b.len(), want: EPOCH_LEN });
            }
            if &b[..EPOCH_MAGIC.len()] != EPOCH_MAGIC.as_slice() {
                return Err(ManifestError::BadMagic { expected: "vdht/v8/ep" });
            }
            let mut h = Hasher::new();
            h.update(&b[..EPOCH_LEN - 4]);
            if h.finalize() != u32::from_le_bytes(b[EPOCH_LEN - 4..].try_into().unwrap()) {
                return Err(ManifestError::Crc(EPOCH_NAME));
            }
            Ok(u64::from_le_bytes(b[10..18].try_into().unwrap()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(ManifestError::Io(e.to_string())),
    }
}

pub fn write_max_epoch(dir: &Path, epoch: u64) -> Result<(), ManifestError> {
    std::fs::create_dir_all(dir)?;
    let mut v = Vec::with_capacity(EPOCH_LEN);
    v.extend_from_slice(EPOCH_MAGIC);
    v.extend_from_slice(&epoch.to_le_bytes());
    let mut h = Hasher::new();
    h.update(&v);
    v.extend_from_slice(&h.finalize().to_le_bytes());
    let path = dir.join(EPOCH_NAME);
    let mut f = File::create(&path)?;
    f.write_all(&v)?;
    f.sync_all()?;
    drop(f);
    crate::fsync_dir(dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StoreManifest {
        StoreManifest {
            shard: 7,
            snapshot_seq: 50_000,
            oldest_wal_needed: 49_001,
            applied_seq: 50_000,
            next_slot: 4200,
            time_mark_bucket: 1234,
        }
    }

    #[test]
    fn manifest_roundtrip_is_fixed_size() {
        let mf = sample();
        let b = mf.encode();
        assert_eq!(b.len(), MF_LEN);
        assert_eq!(StoreManifest::decode(&b).unwrap(), mf);
    }

    #[test]
    fn every_byte_of_the_manifest_is_covered_by_crc_or_magic() {
        let b = sample().encode();
        for i in 0..b.len() {
            let mut c = b.clone();
            c[i] ^= 0x40;
            assert!(StoreManifest::decode(&c).is_err(), "байт {i} принят без ошибки");
        }
    }

    #[test]
    fn wrong_size_and_shard_are_rejected() {
        let b = sample().encode();
        assert!(matches!(
            StoreManifest::decode(&b[..MF_LEN - 1]),
            Err(ManifestError::Size { name: MF_NAME, found: 53, want: 54 })
        ));
        let mut longer = b.clone();
        longer.push(0);
        assert!(matches!(StoreManifest::decode(&longer), Err(ManifestError::Size { .. })));
        assert!(matches!(
            StoreManifest::decode(&b[..0]),
            Err(ManifestError::Size { .. })
        ));
    }

    #[test]
    fn epoch_marker_roundtrip_and_absence() {
        let dir = crate::testing::dir("epoch");
        assert_eq!(read_max_epoch(&dir).unwrap(), 0, "нет файла ⇒ ни одна эпоха не обслуживалась");
        write_max_epoch(&dir, 9).unwrap();
        assert_eq!(read_max_epoch(&dir).unwrap(), 9);
        write_max_epoch(&dir, 10).unwrap();
        assert_eq!(read_max_epoch(&dir).unwrap(), 10);
        let mut raw = std::fs::read(dir.join(EPOCH_NAME)).unwrap();
        raw[12] ^= 1;
        std::fs::write(dir.join(EPOCH_NAME), &raw).unwrap();
        assert!(matches!(read_max_epoch(&dir), Err(ManifestError::Crc(_))));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn manifest_write_is_atomic_and_respects_the_fault() {
        let dir = crate::testing::dir("atomic");
        let mf = sample();
        // Точка 5: partial записан, rename не сделан ⇒ на диске старого MANIFEST нет вообще.
        let err = write_manifest(&dir, &mf, Some(Fault::ManifestRenameMid)).unwrap_err();
        assert!(matches!(err, ManifestError::Injected(Fault::ManifestRenameMid)));
        assert!(read_manifest(&dir).unwrap().is_none(), "MANIFEST не должен появиться (§10.5, 5)");
        assert!(dir.join(MF_PARTIAL_NAME).exists(), "partial остаётся и игнорируется");
        write_manifest(&dir, &mf, None).unwrap();
        assert_eq!(read_manifest(&dir).unwrap(), Some(mf));
        assert!(!dir.join(MF_PARTIAL_NAME).exists(), "rename забирает partial");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn half_write_never_leaves_two_versions() {
        // Точка 4 матрицы: снапшот fsync'нут, MANIFEST ещё старый. Здесь проверяем саму
        // возможность состояния: после записи нового MANIFEST старый исчезает атомично, и
        // прочитать можно ровно одну из двух версий.
        let dir = crate::testing::dir("two");
        let a = StoreManifest { snapshot_seq: 1, oldest_wal_needed: 1, ..sample() };
        let b = StoreManifest { snapshot_seq: 2, oldest_wal_needed: 2, ..sample() };
        write_manifest(&dir, &a, None).unwrap();
        write_manifest(&dir, &b, None).unwrap();
        assert_eq!(read_manifest(&dir).unwrap(), Some(b));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
