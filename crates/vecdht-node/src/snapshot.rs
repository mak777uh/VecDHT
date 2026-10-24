//! Отдача и сборка снапшота шарда по кускам (§9.5, шаг 2, сообщение `SnapshotOffer`).
//!
//! Кусок ограничен `SNAPSHOT_CHUNK_MAX_LEN` (= `MAX_VAR_LEN`), поэтому файл отдаётся частями, а
//! целостность проверяется один раз — по blake3 **всего** файла, одинаковому во всех кусках.
//! Проверка по кускам означала бы, что подменить хвост возможно: последний кусок приходит
//! последним, и «всё предыдущее сошлось» ничего не гарантирует.
//!
//! Установка тоже заимствована у барьера §10.4: `snap.<seq>.partial` → fsync → rename →
//! fsync каталога → MANIFEST. Никакого «распакуем в рабочий файл» нет: узел, упавший на середине
//! приёма, обязан остаться на старом снапшоте, а не на половине нового.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use thiserror::Error;
use vecdht_index::manifest::{write_manifest, StoreManifest};
use vecdht_index::snapshot::{
    partial_name, snapshot_name, SnapshotMeta, SNAP_FORMAT, SNAP_HEADER_LEN, SNAP_MAGIC,
};
use vecdht_wire::SNAPSHOT_CHUNK_MAX_LEN;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyncError {
    #[error("io {ctx}: {detail}")]
    Io { ctx: &'static str, detail: String },
    #[error("файл короче заголовка: не хватает {0} байт")]
    TooShort(usize),
    #[error("магическая строка не `vdht/s8/snap`")]
    BadMagic,
    #[error("версия формата снапшота {0}, ожидаем 2")]
    BadFormat(u16),
    #[error("снапшот относится к шарду {found}, узел держит {want}")]
    ShardMismatch { want: u16, found: u16 },
    #[error("кусок {offset}..{end} не влезает в файл длиной {total}")]
    BadGeometry { offset: u32, end: u64, total: u32 },
    #[error("кусок нулевой длины — по нему нельзя продвигать приём")]
    EmptyChunk,
    #[error("дубликат куска на offset {0}")]
    DuplicateChunk(u32),
    #[error("в файле {received} байт из {total}: куски не покрывают его связно")]
    Hole { received: u32, total: u32 },
    #[error("куски перекрываются: после куска на {offset} набегает {incoming} байт при файле из {total}")]
    Overlap { offset: u32, incoming: u32, total: u32 },
    #[error("blake3 собранного файла {actual}, ожидалось {expected}")]
    HashMismatch { expected: String, actual: String },
    #[error("в файле snapshot_seq={file}, MANIFEST обещает {manifest}")]
    SeqMismatch { file: u64, manifest: u64 },
}

/// Файл снапшота, который обязан существовать у seed-узла: `snap.<snapshot_seq>.log`.
pub fn path_of(dir: &Path, snapshot_seq: u64) -> std::path::PathBuf {
    dir.join(snapshot_name(snapshot_seq))
}

/// Сколько байт отдавать, начиная с `offset`, из файла длиной `total`.
#[inline]
pub fn chunk_len(total: u32, offset: u32) -> usize {
    let rest = total.saturating_sub(offset) as usize;
    rest.min(SNAPSHOT_CHUNK_MAX_LEN)
}

/// Прочитать кусок, не загружая файл целиком: снапшот шарда — это сотни мегабайт, а
/// `SnapshotOffer` отдаёт по 64 КиБ.
pub fn read_chunk(path: &Path, offset: u32, total: u32) -> Result<Vec<u8>, SyncError> {
    let len = chunk_len(total, offset);
    if len == 0 {
        return Err(SyncError::EmptyChunk);
    }
    let mut f = File::open(path).map_err(|e| SyncError::Io { ctx: "open snapshot", detail: e.to_string() })?;
    f.seek(SeekFrom::Start(offset as u64))
        .map_err(|e| SyncError::Io { ctx: "seek snapshot", detail: e.to_string() })?;
    // Кусок обязан быть ровно `len`: короткий read — это либо EOF раньше `total`, либо обрыв.
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)
        .map_err(|e| SyncError::Io { ctx: "read chunk", detail: e.to_string() })?;
    Ok(buf)
}

/// blake3 всего файла — он же `content_hash` во всех кусках одного transferred-снапшота.
pub fn file_hash(path: &Path) -> Result<[u8; 32], SyncError> {
    let mut f = File::open(path).map_err(|e| SyncError::Io { ctx: "open for hash", detail: e.to_string() })?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| SyncError::Io { ctx: "hash read", detail: e.to_string() })?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(*h.finalize().as_bytes())
}

/// Заголовок собранного файла без построения индекса: проверка «этот снапшот вообще про наш
/// шард» не должна стоить 428 МБ аллокаций (§8.2). Полную валидацию арены сделает
/// `ShardStore::open`, когда снапшот станет рабочим.
pub fn header(bytes: &[u8]) -> Result<(SnapshotMeta, u32), SyncError> {
    if bytes.len() < SNAP_HEADER_LEN {
        return Err(SyncError::TooShort(SNAP_HEADER_LEN - bytes.len()));
    }
    if &bytes[0..12] != SNAP_MAGIC {
        return Err(SyncError::BadMagic);
    }
    let mut off = 12;
    let u16 = |b: &[u8], o: &mut usize| {
        let v = u16::from_le_bytes(b[*o..*o + 2].try_into().unwrap());
        *o += 2;
        v
    };
    let u32 = |b: &[u8], o: &mut usize| {
        let v = u32::from_le_bytes(b[*o..*o + 4].try_into().unwrap());
        *o += 4;
        v
    };
    let u64 = |b: &[u8], o: &mut usize| {
        let v = u64::from_le_bytes(b[*o..*o + 8].try_into().unwrap());
        *o += 8;
        v
    };
    let format = u16(bytes, &mut off);
    if format != SNAP_FORMAT {
        return Err(SyncError::BadFormat(format));
    }
    let shard = u16(bytes, &mut off);
    let snapshot_seq = u64(bytes, &mut off);
    let next_slot = u64(bytes, &mut off);
    let max_epoch_served = u64(bytes, &mut off);
    let time_mark_bucket = u32(bytes, &mut off);
    let live = u32(bytes, &mut off);
    Ok((
        SnapshotMeta { snapshot_seq, next_slot, time_mark_bucket, max_epoch_served, shard },
        live,
    ))
}

/// Сборщик кусков: копит куски по offset, замыкает файл только когда покрытие связно и хеш
/// сошёлся.
#[derive(Debug)]
pub struct Assembler {
    total: u32,
    expected: [u8; 32],
    chunks: BTreeMap<u32, Vec<u8>>,
    received: u32,
}

impl Assembler {
    pub fn new(total: u32, expected_hash: [u8; 32]) -> Self {
        Assembler { total, expected: expected_hash, chunks: BTreeMap::new(), received: 0 }
    }

    #[inline]
    pub fn is_complete(&self) -> bool {
        self.received == self.total
    }

    /// Поставить кусок. `Ok(None)` — приём не закончен, `Ok(Some(bytes))` — файл собран,
    /// хеш совпал, можно ставить.
    pub fn push(&mut self, offset: u32, chunk: &[u8]) -> Result<Option<Vec<u8>>, SyncError> {
        if chunk.is_empty() {
            return Err(SyncError::EmptyChunk);
        }
        let end = offset as u64 + chunk.len() as u64;
        if end > self.total as u64 {
            return Err(SyncError::BadGeometry { offset, end, total: self.total });
        }
        if self.chunks.contains_key(&offset) {
            return Err(SyncError::DuplicateChunk(offset));
        }
        let incoming = self.received + chunk.len() as u32;
        if incoming > self.total {
            // Все куски лежат внутри `[0, total)`, поэтому сумма длин, превышающая размер файла, —
            // это ровно перекрытие. Без проверки приём просто никогда не замкнулся бы: приёмник
            // висел бы на «не закончен» вместо ошибки (§9.5).
            return Err(SyncError::Overlap { offset, incoming, total: self.total });
        }
        self.received += chunk.len() as u32;
        self.chunks.insert(offset, chunk.to_vec());
        if !self.is_complete() {
            return Ok(None);
        }
        let bytes = self.concatenate()?;
        let actual = *blake3::hash(&bytes).as_bytes();
        if actual != self.expected {
            return Err(SyncError::HashMismatch {
                expected: hex(&self.expected),
                actual: hex(&actual),
            });
        }
        Ok(Some(bytes))
    }

    /// Куски обязаны идти вплотную от нуля: «сумма длин совпала» при дыре посередине дала бы
    /// файл нужного размера с мусором внутри.
    fn concatenate(&self) -> Result<Vec<u8>, SyncError> {
        let mut out = Vec::with_capacity(self.total as usize);
        let mut cursor = 0u32;
        for (offset, chunk) in &self.chunks {
            if *offset != cursor {
                return Err(SyncError::Hole { received: self.received, total: self.total });
            }
            out.extend_from_slice(chunk);
            cursor += chunk.len() as u32;
        }
        if cursor != self.total {
            return Err(SyncError::Hole { received: self.received, total: self.total });
        }
        Ok(out)
    }
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Поставить принятый снапшот в каталог шарда и переписать MANIFEST. Возвращает метаданные
/// файла — по ним вызывающий строит `StoreManifest` и решает, какой хвост WAL ещё нужен.
///
/// Ничего из старого состояния узла здесь не трогается кроме MANIFEST: если у узла уже есть
/// применённые опсы, решение «перезагрузиться с этого снапшота» принимает вызывающий (§9.5
/// запрещает тихо откатывать живой индекс).
pub fn install(dir: &Path, bytes: &[u8], mf: &StoreManifest) -> Result<SnapshotMeta, SyncError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| SyncError::Io { ctx: "create_dir_all", detail: e.to_string() })?;
    let (meta, _) = header(bytes)?;
    if meta.shard != mf.shard {
        return Err(SyncError::ShardMismatch { want: mf.shard, found: meta.shard });
    }
    if meta.snapshot_seq != mf.snapshot_seq {
        // Имя файла и MANIFEST обязаны сойтись на одном seq, иначе `open` не найдёт снапшот.
        return Err(SyncError::SeqMismatch { file: meta.snapshot_seq, manifest: mf.snapshot_seq });
    }
    let partial = dir.join(partial_name(meta.snapshot_seq));
    {
        let mut f = File::create(&partial)
            .map_err(|e| SyncError::Io { ctx: "create partial", detail: e.to_string() })?;
        f.write_all(bytes).map_err(|e| SyncError::Io { ctx: "write partial", detail: e.to_string() })?;
        f.sync_all().map_err(|e| SyncError::Io { ctx: "fsync partial", detail: e.to_string() })?;
    }
    std::fs::rename(&partial, dir.join(snapshot_name(meta.snapshot_seq)))
        .map_err(|e| SyncError::Io { ctx: "rename snapshot", detail: e.to_string() })?;
    vecdht_index::fsync_dir(dir).map_err(|e| SyncError::Io { ctx: "fsync dir", detail: e.to_string() })?;
    write_manifest(dir, mf, None)
        .map_err(|e| SyncError::Io { ctx: "write manifest", detail: e.to_string() })?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_file(seq: u64, shard: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(SNAP_MAGIC);
        b.extend_from_slice(&SNAP_FORMAT.to_le_bytes());
        b.extend_from_slice(&shard.to_le_bytes());
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&1_000_001u64.to_le_bytes());
        b.extend_from_slice(&7u64.to_le_bytes());
        b.extend_from_slice(&40_000_111u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(b"payload tail");
        b
    }

    #[test]
    fn chunking_covers_a_file_exactly_once() {
        let total = (SNAPSHOT_CHUNK_MAX_LEN * 2 + 7) as u32;
        let mut offsets = Vec::new();
        let mut off = 0u32;
        let mut sum = 0usize;
        while off < total {
            let n = chunk_len(total, off);
            offsets.push((off, n));
            off += n as u32;
            sum += n;
        }
        assert_eq!(sum, total as usize);
        assert_eq!(offsets.len(), 3);
        assert_eq!(offsets[0].1, SNAPSHOT_CHUNK_MAX_LEN);
        assert_eq!(offsets[2].1, 7, "хвост короче лимита куска — это нормально");
        assert_eq!(chunk_len(total, total), 0, "за концом файла куска нет");
    }

    #[test]
    fn header_is_read_without_touching_the_arena() {
        let bytes = fake_file(12, 5);
        let (meta, live) = header(&bytes).unwrap();
        assert_eq!(
            meta,
            SnapshotMeta {
                snapshot_seq: 12,
                next_slot: 1_000_001,
                time_mark_bucket: 40_000_111,
                max_epoch_served: 7,
                shard: 5
            }
        );
        assert_eq!(live, 2);
        // Усечённый заголовок и испорченная магическая строка ловятся до записи на диск.
        assert_eq!(header(&bytes[..SNAP_HEADER_LEN - 1]).unwrap_err(), SyncError::TooShort(1));
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 0xff;
        assert_eq!(header(&bad_magic).unwrap_err(), SyncError::BadMagic);
        let mut other_shard = bytes.clone();
        // Чужая версия формата лежит сразу после магической строки; берём заведомо не текущую,
        // иначе проверка «формат 2 отвергается» проверяет саму себя.
        let bogus = SNAP_FORMAT + 1;
        other_shard[12..14].copy_from_slice(&bogus.to_le_bytes());
        assert_eq!(header(&other_shard).unwrap_err(), SyncError::BadFormat(bogus));
        let mut other = bytes.clone();
        other[14..16].copy_from_slice(&6u16.to_le_bytes());
        assert_eq!(header(&other).unwrap().0.shard, 6, "чужой шард читается из заголовка");
    }

    #[test]
    fn assembler_needs_contiguous_chunks_and_a_matching_hash() {
        let bytes = fake_file(3, 0);
        let total = bytes.len() as u32;
        let h = *blake3::hash(&bytes).as_bytes();
        let mut a = Assembler::new(total, h);
        // Не по порядку: покрытие всё равно замыкается только на последнем куске.
        assert_eq!(a.push(20, &bytes[20..]).unwrap(), None);
        // Дыра: куски в пределах файла, но между ними пропуск — assembled-файл нечем собрать.
        let mut gap = Assembler::new(30, h);
        assert_eq!(gap.push(0, &bytes[..10]).unwrap(), None);
        assert_eq!(gap.push(20, &bytes[20..30]).unwrap(), None);
        assert!(matches!(gap.concatenate(), Err(SyncError::Hole { received: 20, total: 30 })));
        // Перекрытие: сумма байт превысила размер файла — приём обязан упасть, а не зависнуть.
        let mut overlap = Assembler::new(30, h);
        overlap.push(0, &bytes[..15]).unwrap();
        assert_eq!(
            overlap.push(10, &bytes[10..30]).unwrap_err(),
            SyncError::Overlap { offset: 10, incoming: 35, total: 30 }
        );
        // Пустой кусок: по нему приём не двигается, а `total` он бы «покрывал» нулём.
        assert_eq!(gap.push(30, &[]).unwrap_err(), SyncError::EmptyChunk);
        // Дубликат offset — это попытка подменить уже принятый кусок.
        let mut dup = Assembler::new(total, h);
        dup.push(0, &bytes[..10]).unwrap();
        assert_eq!(dup.push(0, &bytes[..10]).unwrap_err(), SyncError::DuplicateChunk(0));
        // За границей файла.
        assert!(matches!(a.push(total, b"x"), Err(SyncError::BadGeometry { .. })));
        let done = a.push(0, &bytes[..20]).unwrap();
        assert_eq!(done, Some(bytes.clone()));
        // Тот же набор, но ожидаемый хеш чужой.
        let mut evil = Assembler::new(total, [0u8; 32]);
        evil.push(0, &bytes[..20]).unwrap();
        let err = evil.push(20, &bytes[20..]).unwrap_err();
        assert!(matches!(err, SyncError::HashMismatch { .. }), "{err}");
    }

    #[test]
    fn install_goes_through_partial_then_manifest() {
        let dir = vecdht_index::testing::dir("node_install");
        let bytes = fake_file(9, 4);
        let mf = StoreManifest {
            shard: 4,
            snapshot_seq: 9,
            oldest_wal_needed: 901,
            applied_seq: 900,
            next_slot: 1_000_001,
            time_mark_bucket: 40_000_111,
        };
        let meta = install(&dir, &bytes, &mf).unwrap();
        assert_eq!(meta.snapshot_seq, 9);
        assert!(dir.join(snapshot_name(9)).exists());
        assert!(!dir.join(partial_name(9)).exists(), "partial обязан быть переименован");
        assert_eq!(vecdht_index::manifest::read_manifest(&dir).unwrap().unwrap(), mf);
        // Чужой шард и расхождение seq с MANIFEST ловятся до записи. Шард проверяется раньше:
        // файл чужого шарда нельзя ни переименовать, ни описать в MANIFEST этого узла.
        let foreign = fake_file(9, 5);
        assert!(matches!(
            install(&dir, &foreign, &mf),
            Err(SyncError::ShardMismatch { want: 4, found: 5 })
        ));
        let mut later = fake_file(9, 4);
        later[16..24].copy_from_slice(&10u64.to_le_bytes());
        assert_eq!(
            install(&dir, &later, &mf),
            Err(SyncError::SeqMismatch { file: 10, manifest: 9 }),
            "MANIFEST и имя файла обязаны сойтись на одном seq, иначе `open` не найдёт снапшот"
        );
        vecdht_index::testing::remove(&dir);
    }

    #[test]
    fn read_chunk_matches_the_file_and_hashes_whole() {
        let dir = vecdht_index::testing::dir("node_chunk");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snap.bin");
        let bytes: Vec<u8> = (0..SNAPSHOT_CHUNK_MAX_LEN + 5).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        let total = bytes.len() as u32;
        let h = file_hash(&path).unwrap();
        assert_eq!(h, *blake3::hash(&bytes).as_bytes());
        assert_eq!(read_chunk(&path, 0, total).unwrap(), bytes[..SNAPSHOT_CHUNK_MAX_LEN]);
        assert_eq!(read_chunk(&path, SNAPSHOT_CHUNK_MAX_LEN as u32, total).unwrap(), bytes[SNAPSHOT_CHUNK_MAX_LEN..]);
        // За концом файла куска нет — и это ошибка, а не пустой ответ: пустой кусок в протоколе
        // означает «приём не двигается».
        assert!(matches!(read_chunk(&path, total, total), Err(SyncError::EmptyChunk)));
        // Короткий файл: read_exact обязан не выдать огрызок.
        std::fs::write(&path, &bytes[..10]).unwrap();
        assert!(matches!(read_chunk(&path, 0, total), Err(SyncError::Io { .. })));
        vecdht_index::testing::remove(&dir);
    }

    #[test]
    fn hash_hex_is_stable() {
        assert_eq!(hex(&[0xab; 32]), "ab".repeat(32));
    }
}
