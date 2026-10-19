//! Файл индекса: снапшот, стримящийся из арены (§10.4).
//!
//! В v7.5 `flush_snapshot` делал `self.index.clone()` — на 5M записей это +2.3 ГБ на время
//! снапшота. Здесь снапшот пишется блоками прямо из арены по возрастанию slot'а, whole-index не
//! клонируется вообще, поэтому пик RAM во время барьера равен пику до него.
//!
//! Байты файла детерминированы состоянием: записи идут по slot'у, списки — по cluster_id и
//! slot'у, плавающей точки нет. Отсюда требуемый тест §19.1: «два узла на одном потоке опсов
//! при часах, различающихся на 40 минут, дают побайтово идентичный файл индекса».
//!
//! Раскладка (`<` — little-endian):
//!
//! ```text
//! magic "vdht/s8/snap" | format u16 | shard u16 | snapshot_seq u64 | next_slot u64
//!   | max_epoch_served u64 | time_mark_bucket u32 | live u32
//!   | [ slot u32 | entry 424 ] × live
//!   | [ len u32 | slot u32 × len ] × NLIST
//!   | crc32 u32  (над всем предыдущим)
//! ```

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;

use crc32fast::Hasher;
use vecdht_wire::constants::NLIST;

use crate::entry::{IndexEntry, INDEX_ENTRY_BYTES};
use crate::ivf::{IvfIndex, IndexError};

pub const SNAP_MAGIC: &[u8; 12] = b"vdht/s8/snap";
pub const SNAP_FORMAT: u16 = 1;
pub const SNAP_PREFIX: &str = "snap.";
pub const SNAP_SUFFIX: &str = ".log";
pub const SNAP_PARTIAL_SUFFIX: &str = ".partial";
/// Хвостовой crc32.
pub const CRC_LEN: usize = 4;
/// 12 magic + 2 format + 2 shard + 8 snapshot_seq + 8 next_slot + 8 epoch + 4 bucket + 4 live.
pub const SNAP_HEADER_LEN: usize = 12 + 2 + 2 + 8 + 8 + 8 + 4 + 4;

/// Байт размера заголовка записей, для теста бюджета.
#[inline]
pub fn snapshot_size_for(live: usize) -> usize {
    SNAP_HEADER_LEN + live * (4 + INDEX_ENTRY_BYTES) + (NLIST as usize) * 4 + live * 4 + CRC_LEN
}

/// Служебные поля снапшота, не входящие в арену.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotMeta {
    /// `applied_seq` на момент снапшота: с него+1 начинается нужный хвост WAL.
    pub snapshot_seq: u64,
    /// Следующий slot. Персистится, потому что slot'ы не перенумеровываются (§8.3).
    pub next_slot: u64,
    pub time_mark_bucket: u32,
    pub max_epoch_served: u64,
    pub shard: u16,
}

#[derive(Debug)]
pub struct LoadedSnapshot {
    pub meta: SnapshotMeta,
    pub index: IvfIndex,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("io: {0}")]
    Io(String),
    #[error("файл короче заголовка: не хватает {0} байт")]
    TooShort(usize),
    #[error("магическая строка не `vdht/s8/snap`")]
    BadMagic,
    #[error("версия формата снапшота {0}, ожидаем 1")]
    BadFormat(u16),
    #[error("снапшот относится к шарду {found}, а индекс — к {want}")]
    ShardMismatch { want: u16, found: u16 },
    #[error("битый crc32 файла: ожидалось {want:08x}, посчитано {found:08x}")]
    Crc { want: u32, found: u32 },
    #[error("в снапшоте {found} живых записей, заголовок обещает {want}")]
    LiveCount { want: u32, found: u32 },
    #[error("inverted lists расходятся с записями: {0} против {1}")]
    ListsMismatch(usize, usize),
    #[error("slot {slot} в списке кластера {cluster}, а у записи cluster_id {found}")]
    ClusterMismatch { slot: u32, cluster: u16, found: u16 },
    #[error("список кластера {0} не отсортирован по slot")]
    UnsortedList(usize),
    #[error("slot {slot} за пределами next_slot {next_slot}")]
    SlotOutOfRange { slot: u32, next_slot: u64 },
    #[error("повторяющийся slot {0} в снапшоте")]
    DuplicateSlot(u32),
    #[error("имя файла снапшота не разобрано: {0}")]
    BadName(String),
    #[error("ошибка инварианта арены при загрузке: {0}")]
    Index(String),
}

impl From<std::io::Error> for SnapshotError {
    fn from(e: std::io::Error) -> Self {
        SnapshotError::Io(e.to_string())
    }
}

impl From<IndexError> for SnapshotError {
    fn from(e: IndexError) -> Self {
        SnapshotError::Index(e.to_string())
    }
}

pub fn snapshot_name(snapshot_seq: u64) -> String {
    format!("{SNAP_PREFIX}{snapshot_seq:020}{SNAP_SUFFIX}")
}

pub fn partial_name(snapshot_seq: u64) -> String {
    format!("{SNAP_PREFIX}{snapshot_seq:020}{SNAP_PARTIAL_SUFFIX}")
}

pub fn parse_snapshot_name(name: &str) -> Result<u64, SnapshotError> {
    let rest = name
        .strip_prefix(SNAP_PREFIX)
        .and_then(|r| r.strip_suffix(SNAP_SUFFIX))
        .ok_or_else(|| SnapshotError::BadName(name.to_string()))?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SnapshotError::BadName(name.to_string()));
    }
    rest.parse::<u64>().map_err(|_| SnapshotError::BadName(name.to_string()))
}

/// Все снапшоты каталога по возрастанию `snapshot_seq`. `*.partial` не снапшот: он не в
/// MANIFEST и обязан игнорироваться (§10.5, точка 3).
pub fn list_snapshots(dir: &Path) -> std::io::Result<Vec<(u64, std::path::PathBuf)>> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in rd {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Ok(seq) = parse_snapshot_name(&name) {
            out.push((seq, entry.path()));
        }
    }
    out.sort_by_key(|(s, _)| *s);
    Ok(out)
}

/// Записать снапшот потоково. Вызывающий решает, в какой файл писать: барьер §10.4 сначала
/// пишет в `snap.<seq>.partial`, fsync'ит его, и только потом делает rename.
pub fn write_snapshot(
    file: &mut File,
    meta: SnapshotMeta,
    index: &IvfIndex,
) -> Result<u64, SnapshotError> {
    if index.shard != meta.shard {
        return Err(SnapshotError::ShardMismatch { want: meta.shard, found: index.shard });
    }
    let live = index.live;
    let mut w = BufWriter::with_capacity(64 * 1024, &mut *file);
    let mut h = Hasher::new();
    let mut written = 0u64;

    let mut out: Vec<u8> = Vec::with_capacity(64 * 1024);
    out.extend_from_slice(SNAP_MAGIC);
    out.extend_from_slice(&SNAP_FORMAT.to_le_bytes());
    out.extend_from_slice(&meta.shard.to_le_bytes());
    out.extend_from_slice(&meta.snapshot_seq.to_le_bytes());
    out.extend_from_slice(&meta.next_slot.to_le_bytes());
    out.extend_from_slice(&meta.max_epoch_served.to_le_bytes());
    out.extend_from_slice(&meta.time_mark_bucket.to_le_bytes());
    out.extend_from_slice(&(live as u32).to_le_bytes());

    // Записи: строго по возрастанию slot'а, только живые (§8.3 — дыры в файл не пишутся).
    for (slot, e) in index.live_slots() {
        out.extend_from_slice(&slot.to_le_bytes());
        e.write_into(&mut out);
        if out.len() >= 32 * 1024 {
            written += flush_block(&mut w, &mut h, &out)?;
            out.clear();
        }
    }

    // Inverted lists: 1024 кластеров, внутри slot'ы по возрастанию. Храним их явно — это строка
    // «inverted list: slot_id u32 = 4 Б/запись» из §8.2, и заодно контроль структуры:
    // загрузчик сверяет списки с cluster_id записей.
    let mut lists_total = 0usize;
    for list in &index.lists {
        lists_total += list.len();
        out.extend_from_slice(&(list.len() as u32).to_le_bytes());
        for &slot in list {
            out.extend_from_slice(&slot.to_le_bytes());
        }
        if out.len() >= 32 * 1024 {
            written += flush_block(&mut w, &mut h, &out)?;
            out.clear();
        }
    }
    if lists_total != live {
        return Err(SnapshotError::ListsMismatch(lists_total, live));
    }
    if !out.is_empty() {
        written += flush_block(&mut w, &mut h, &out)?;
        out.clear();
    }
    w.flush()?;
    let crc = h.finalize();
    w.write_all(&crc.to_le_bytes())?;
    w.flush()?;
    written += CRC_LEN as u64;
    Ok(written)
}

fn flush_block(
    w: &mut BufWriter<&mut File>,
    h: &mut Hasher,
    block: &[u8],
) -> Result<u64, SnapshotError> {
    h.update(block);
    w.write_all(block)?;
    Ok(block.len() as u64)
}

/// Прочитать файл индекса. Проверка crc — до восстановления состояния.
pub fn read_snapshot(path: &Path) -> Result<LoadedSnapshot, SnapshotError> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    let (meta, index) = parse_snapshot(&bytes)?;
    Ok(LoadedSnapshot { meta, index })
}

pub fn parse_snapshot(bytes: &[u8]) -> Result<(SnapshotMeta, IvfIndex), SnapshotError> {
    if bytes.len() < SNAP_HEADER_LEN + CRC_LEN {
        return Err(SnapshotError::TooShort(SNAP_HEADER_LEN + CRC_LEN - bytes.len()));
    }
    if &bytes[..SNAP_MAGIC.len()] != SNAP_MAGIC.as_slice() {
        return Err(SnapshotError::BadMagic);
    }
    let body = &bytes[..bytes.len() - CRC_LEN];
    let want = u32::from_le_bytes(bytes[bytes.len() - CRC_LEN..].try_into().unwrap());
    let mut h = Hasher::new();
    h.update(body);
    let found = h.finalize();
    if want != found {
        return Err(SnapshotError::Crc { want, found });
    }
    let mut p = Cursor::new(body);
    p.skip(SNAP_MAGIC.len())?;
    let format = p.u16()?;
    if format != SNAP_FORMAT {
        return Err(SnapshotError::BadFormat(format));
    }
    let shard = p.u16()?;
    let snapshot_seq = p.u64()?;
    let next_slot = p.u64()?;
    let max_epoch_served = p.u64()?;
    let time_mark_bucket = p.u32()?;
    let live_declared = p.u32()?;
    let meta = SnapshotMeta { snapshot_seq, next_slot, max_epoch_served, time_mark_bucket, shard };

    // Число записей ограничено размером файла: `(live_declared, next_slot)` — данные из
    // заголовка, и резервировать память по ним наивыжим значением нельзя.
    let max_records = (bytes.len() - SNAP_HEADER_LEN - CRC_LEN) / (4 + INDEX_ENTRY_BYTES);
    let mut index = IvfIndex::with_capacity(shard, (live_declared as usize).min(max_records));
    // Арена восстанавливается с теми же номерами slot'ов: `resize`, а не `push` (§8.3).
    let room = usize::try_from(next_slot).map_err(|_| SnapshotError::TooShort(usize::MAX))?;
    if room > 0 {
        index.entries.reserve_exact(room);
        while (index.entries.len() as u64) < next_slot {
            index.entries.push(IndexEntry::default());
        }
    }

    let mut last_slot = None::<u32>;
    for _ in 0..live_declared {
        let slot = p.u32()?;
        if slot as usize >= room {
            return Err(SnapshotError::SlotOutOfRange { slot, next_slot });
        }
        if let Some(prev) = last_slot {
            if slot <= prev {
                return Err(SnapshotError::DuplicateSlot(slot));
            }
        }
        last_slot = Some(slot);
        let e = IndexEntry::from_bytes(p.take(INDEX_ENTRY_BYTES)?)
            .map_err(|_| SnapshotError::TooShort(0))?;
        index.load_entry(slot, e)?;
    }

    // Списки: сверяем с тем, что уже выстроено из записей. Расхождение = битый или подменённый
    // файл, и загрузить его как валидное состояние нельзя.
    let mut total = 0usize;
    for c in 0..NLIST as usize {
        let len = p.u32()? as usize;
        total += len;
        let mut prev = None::<u32>;
        for _ in 0..len {
            let slot = p.u32()?;
            if let Some(x) = prev {
                if slot <= x {
                    return Err(SnapshotError::UnsortedList(c));
                }
            }
            prev = Some(slot);
            if slot as usize >= room {
                return Err(SnapshotError::SlotOutOfRange { slot, next_slot });
            }
            if !index.is_live(slot) {
                return Err(SnapshotError::DuplicateSlot(slot));
            }
            let found = index.entries[slot as usize].cluster_id;
            if found as usize != c {
                return Err(SnapshotError::ClusterMismatch { slot, cluster: c as u16, found });
            }
        }
    }
    if total != live_declared as usize {
        return Err(SnapshotError::ListsMismatch(total, live_declared as usize));
    }
    if p.remaining() != 0 {
        return Err(SnapshotError::TooShort(p.remaining()));
    }
    index.check_invariants().map_err(SnapshotError::Index)?;
    Ok((meta, index))
}

/// Минимальный читатель байтов уже проверенного crc файла.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data, off: 0 }
    }
    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.off
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], SnapshotError> {
        if self.remaining() < n {
            return Err(SnapshotError::TooShort(n - self.remaining()));
        }
        let s = &self.data[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }
    pub fn skip(&mut self, n: usize) -> Result<(), SnapshotError> {
        self.take(n).map(|_| ())
    }
    pub fn u16(&mut self) -> Result<u16, SnapshotError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32, SnapshotError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, SnapshotError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    // 424-байтовая запись читается целиком через `IndexEntry::from_bytes` — раскладка одна и
    // та же, что в сети (§8.2), поэтому отдельного «поле за полем» читателя здесь нет.
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::codec::DIM;
    use vecdht_wire::constants::CLUSTERS_PER_SHARD;

    fn entry(owner: u8, cluster: u16, published: u32, ttl: u16) -> IndexEntry {
        IndexEntry {
            owner_ed25519: [owner; 32],
            vec_q: [(owner as i8) ^ 0x5a; DIM],
            cluster_id: cluster,
            published_bucket: published,
            ttl_buckets: ttl,
        }
    }

    fn populated(shard: u16, n: u8) -> IvfIndex {
        let mut ix = IvfIndex::new(shard);
        for o in 0..n {
            let c = shard * CLUSTERS_PER_SHARD + (o as u16) % CLUSTERS_PER_SHARD;
            ix.insert(entry(o, c, 100, 10)).unwrap();
        }
        ix
    }

    fn tmpfile(tag: &str) -> (std::path::PathBuf, File) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("vecdht-snap-{}-{n}-{tag}.bin", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let f = File::create(&p).unwrap();
        (p, f)
    }

    fn write_to_bytes(ix: &IvfIndex, seq: u64) -> Vec<u8> {
        let m = SnapshotMeta {
            snapshot_seq: seq,
            next_slot: ix.next_slot() as u64,
            time_mark_bucket: 77,
            max_epoch_served: 3,
            shard: ix.shard,
        };
        let (path, mut file) = tmpfile("write");
        let n = write_snapshot(&mut file, m, ix).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(n as usize, bytes.len(), "писатель вернул неверный размер");
        assert_eq!(bytes.len(), snapshot_size_for(ix.live));
        let _ = std::fs::remove_file(&path);
        bytes
    }

    #[test]
    fn snapshot_file_is_the_state_not_the_ram() {
        let ix = populated(0, 20);
        let bytes = write_to_bytes(&ix, 11);
        let (m2, back) = parse_snapshot(&bytes).unwrap();
        assert_eq!(m2.snapshot_seq, 11);
        assert_eq!(m2.time_mark_bucket, 77);
        assert_eq!(m2.max_epoch_served, 3);
        assert_eq!(m2.next_slot, ix.next_slot() as u64);
        assert_eq!(back.live, ix.live);
        for s in 0..ix.next_slot() {
            assert_eq!(back.entry(s), ix.entry(s), "slot {s}");
        }
        for c in 0..CLUSTERS_PER_SHARD {
            assert_eq!(back.cluster_slots(c), ix.cluster_slots(c));
        }
        back.check_invariants().unwrap();
    }

    #[test]
    fn read_then_write_is_the_identity() {
        // Снапшот — это состояние, а не история: перечитать файл и записать его же обязано дать
        // ровно те же байты. На этом свойстве держится и тест §19.1 про идентичные файлы
        // реплик, и шаг 2 барьера §10.4.
        let ix = populated(0, 30);
        let a = write_to_bytes(&ix, 5);
        let (meta, reload) = parse_snapshot(&a).unwrap();
        assert_eq!(reload.check_invariants(), Ok(()));
        let b = write_to_bytes(&reload, 5);
        assert_eq!(a, b, "read → write обязан быть тождественностью (§10.4)");
        assert_eq!(meta.next_slot, reload.next_slot() as u64);
        // Тот же контент, но другая история вставки ⇒ другие slot'ы ⇒ другие байты. Это и есть
        // причина, по которой реплики обязаны применять *один и тот же* поток опсов (§8.3).
        let mut other = IvfIndex::new(0);
        for o in (0..30u8).rev() {
            other.insert(entry(o, (o as u16) % CLUSTERS_PER_SHARD, 100, 10)).unwrap();
        }
        assert_ne!(write_to_bytes(&other, 5), a);
    }

    #[test]
    fn holes_are_not_written_but_slots_survive() {
        let mut ix = populated(0, 12);
        ix.mark_dead(3);
        ix.mark_dead(4);
        let bytes = write_to_bytes(&ix, 1);
        let (_, back) = parse_snapshot(&bytes).unwrap();
        assert_eq!(back.next_slot(), ix.next_slot(), "next_slot персистится (§8.3)");
        assert_eq!(back.live, 10);
        assert!(!back.is_live(3) && !back.is_live(4));
        assert_eq!(back.entry(5), ix.entry(5));
        assert_eq!(back.owner_slot(&[5u8; 32]), Some(5));
        assert!(bytes.len() < write_to_bytes(&populated(0, 12), 1).len());
    }

    #[test]
    fn crc_and_magic_catch_tampering() {
        let ix = populated(0, 5);
        let mut bytes = write_to_bytes(&ix, 2);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(matches!(parse_snapshot(&bytes), Err(SnapshotError::Crc { .. })));
        bytes[last] ^= 1;
        for pos in [0usize, 1, 11, 12, 13, 20, bytes.len() / 2, last - 1] {
            let mut b = bytes.clone();
            b[pos] ^= 0x80;
            assert!(parse_snapshot(&b).is_err(), "изменение байта {pos} не замечено");
        }
        assert!(parse_snapshot(&bytes).is_ok(), "исходный файл обязан читаться");
        let short = bytes[..20].to_vec();
        assert!(matches!(parse_snapshot(&short), Err(SnapshotError::TooShort(_))));
        let mut other_magic = bytes.clone();
        other_magic[..3].copy_from_slice(b"xyz");
        assert!(matches!(parse_snapshot(&other_magic), Err(SnapshotError::BadMagic)));
    }

    #[test]
    fn next_slot_that_is_too_small_is_rejected() {
        let ix = populated(0, 4);
        let mut bytes = write_to_bytes(&ix, 2);
        // Раскладка заголовка: magic 12 + format 2 + shard 2 + snapshot_seq 8 + **next_slot 8**
        // + max_epoch 8 + time_mark 4 + live 4 ⇒ next_slot лежит на 24..32.
        bytes[SNAP_HEADER_LEN - 24..SNAP_HEADER_LEN - 16].copy_from_slice(&2u64.to_le_bytes());
        recrc(&mut bytes);
        assert!(
            matches!(parse_snapshot(&bytes), Err(SnapshotError::SlotOutOfRange { .. })),
            "{:?}",
            parse_snapshot(&bytes)
        );
    }

    #[test]
    fn list_that_disagrees_with_entries_is_rejected() {
        let ix = populated(0, 4);
        let mut bytes = write_to_bytes(&ix, 2);
        // Первая запись: slot(4) + owner(32) + vec_q(384) → cluster_id там и портим.
        let at = SNAP_HEADER_LEN + 4 + 32 + DIM;
        assert_eq!(bytes[at], 0, "первая запись лежит в кластере 0");
        bytes[at] ^= 0b0000_0001;
        recrc(&mut bytes);
        assert!(
            matches!(parse_snapshot(&bytes), Err(SnapshotError::ClusterMismatch { .. })),
            "{:?}",
            parse_snapshot(&bytes)
        );
    }

    fn recrc(bytes: &mut [u8]) {
        let body = bytes.len() - CRC_LEN;
        let mut h = Hasher::new();
        h.update(&bytes[..body]);
        let crc = h.finalize();
        bytes[body..].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn names_roundtrip_and_reject_foreign_files() {
        assert_eq!(parse_snapshot_name(&snapshot_name(17)).unwrap(), 17);
        assert_eq!(snapshot_name(17), "snap.00000000000000000017.log");
        assert_eq!(partial_name(17), "snap.00000000000000000017.partial");
        assert!(parse_snapshot_name(&partial_name(17)).is_err(), "partial не снапшот (§10.4)");
        for bad in ["MANIFEST", "wal.00000000000000000001.log", "snap..log", "snap.x.log", "snap.1"]
        {
            assert!(parse_snapshot_name(bad).is_err(), "{bad} принято");
        }
    }

    #[test]
    fn empty_index_writes_and_reads() {
        let ix = IvfIndex::new(3);
        let m = SnapshotMeta {
            snapshot_seq: 0,
            next_slot: 0,
            time_mark_bucket: 0,
            max_epoch_served: 0,
            shard: 3,
        };
        let (path, mut file) = tmpfile("empty");
        let n = write_snapshot(&mut file, m, &ix).unwrap();
        drop(file);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(n as usize, bytes.len());
        assert_eq!(bytes.len(), snapshot_size_for(0));
        let (m2, back) = parse_snapshot(&bytes).unwrap();
        assert_eq!(m2, m);
        assert_eq!(back.live, 0);
        assert_eq!(back.next_slot(), 0);
        assert_eq!(back.shard, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn shard_mismatch_is_refused_before_writing() {
        let ix = IvfIndex::new(1);
        let m = SnapshotMeta {
            snapshot_seq: 0,
            next_slot: 0,
            time_mark_bucket: 0,
            max_epoch_served: 0,
            shard: 0,
        };
        let (path, mut file) = tmpfile("mismatch");
        assert!(matches!(
            write_snapshot(&mut file, m, &ix),
            Err(SnapshotError::ShardMismatch { want: 0, found: 1 })
        ));
        drop(file);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn list_snapshots_skips_partials_and_wal() {
        let dir = crate::testing::dir("snap-list");
        std::fs::write(dir.join(snapshot_name(30)), b"x").unwrap();
        std::fs::write(dir.join(snapshot_name(4)), b"x").unwrap();
        std::fs::write(dir.join(partial_name(99)), b"x").unwrap();
        std::fs::write(dir.join("MANIFEST"), b"x").unwrap();
        std::fs::write(dir.join(crate::wal::segment_name(1)), b"x").unwrap();
        let got = list_snapshots(&dir).unwrap();
        assert_eq!(got.iter().map(|(s, _)| *s).collect::<Vec<u64>>(), vec![4, 30]);
        crate::testing::remove(&dir);
    }
}
