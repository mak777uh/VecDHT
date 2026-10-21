//! WAL: фрейм, сегменты, group commit и инъекция падений (спека §10.1–§10.5).
//!
//! Порядок для любой мутации (§10.1): построить опс → append WAL → fsync → применить в память →
//! ответить. Здесь живёт первая половина этого порядка; применение — в `store`.
//!
//! Фрейм (§10.2), little-endian:
//!
//! ```text
//! [u32 crc32(seq ‖ kind ‖ body_len ‖ body)] [u64 seq] [u8 kind] [u32 body_len] [body..]
//! ```
//!
//! `body_len` — `u32`, не `u8`: тело `Insert` = 424 байта.
//!
//! `truncate` по живому файлу запрещён: сегменты открываются только на `append`. В v7.5
//! снапшот открывал тот же путь с `truncate(true)` и разрушал журнал, на который ещё ссылался
//! старый снапшот (§10.2).

use std::fs::{File, OpenOptions, ReadDir};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use vecdht_wire::codec::MAX_BODY_LEN;
use vecdht_wire::messages::OpKind;

/// Ротация по размеру (§10.2).
pub const SEGMENT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Ротация по числу опсов (§10.2).
pub const SEGMENT_MAX_OPS: u64 = 100_000;
/// Окно группового коммита в миллисекундах (§10.2).
pub const GROUP_COMMIT_MS: u64 = 5;
/// Максимум опсов в групповом коммите (§10.2).
pub const GROUP_COMMIT_MAX: usize = 32;
/// 4 (crc) + 8 (seq) + 1 (kind) + 4 (len).
pub const FRAME_HEADER_BYTES: usize = 4 + 8 + 1 + 4;
pub const WAL_PREFIX: &str = "wal.";
pub const WAL_SUFFIX: &str = ".log";

/// Точки падений из матрицы §10.5, которые реализуются как отказ записи.
///
/// Внедряемый хук, а не crate `fail`: `fail::call` работает глобальным статическим реестром, а
/// нам нужно параллельно гонять несколько сценариев в одном процессе и на двух разных «узлах»
/// (тест кросс-часового GC), где глобальный state смешал бы падения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// 1 — середина append: часть байт фрейма уже на диске.
    AppendMid,
    /// 2 — после fsync, до применения в память.
    AfterWalFsync,
    /// 3 — середина записи `snap.partial`.
    SnapshotMid,
    /// 5 — середина rename MANIFEST (partial записан, rename не сделан).
    ManifestRenameMid,
    /// 9 — ENOSPC в mid-append: publish ⇒ `WAL_FAILED`, память не тронута.
    EnospcMidAppend,
    /// 10 — restart с `epoch < max_epoch_served`: узел отказывается обслуживать шард (§9.2).
    StaleEpochRestart,
}

/// Метка точки падения для сообщений об ошибках: в `StoreError::WalFailed` попадает строка,
/// и по ней тест матрицы проверяет, *какая именно* точка сработала.
impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Fault::AppendMid => "mid-append",
            Fault::AfterWalFsync => "after-wal-fsync",
            Fault::SnapshotMid => "mid-snapshot",
            Fault::ManifestRenameMid => "mid-manifest-rename",
            Fault::EnospcMidAppend => "enospc-mid-append",
            Fault::StaleEpochRestart => "stale-epoch-restart",
        };
        f.write_str(name)
    }
}

/// Ошибка чтения/записи журнала. `Clone` — `SegmentContents` отдаёт её вместе с кадрами,
/// а тестам матрицы §10.5 нужно сохранить отказ, чтобы сравнить два прогона.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalError {
    #[error("io: {0}")]
    Io(String),
    #[error("несовпадение crc32 на смещении {at}: ожидалось {want:08x}, найдено {found:08x}")]
    Crc { at: u64, want: u32, found: u32 },
    #[error("усеченный заголовок на смещении {at}: {have} байт вместо {FRAME_HEADER_BYTES}")]
    ShortHeader { at: u64, have: usize },
    #[error("усеченное тело на смещении {at}: нужно {need} байт, найдено {have}")]
    ShortBody { at: u64, need: u64, have: usize },
    #[error("неизвестный OpKind {value} на смещении {at}")]
    BadKind { at: u64, value: u8 },
    #[error("тело {len} байт на смещении {at} превышает MAX_BODY_LEN")]
    BodyTooLong { at: u64, len: u32 },
    #[error("инжектированное падение на точке {0:?}")]
    Injected(Fault),
    #[error("имя файла WAL не разобрано: {0}")]
    BadSegmentName(String),
}

impl From<io::Error> for WalError {
    fn from(e: io::Error) -> Self {
        WalError::Io(e.to_string())
    }
}

/// Одна запись журнала. `kind` — вид опса, `body` — его канонические wire-байты.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalFrame {
    pub seq: u64,
    pub kind: OpKind,
    pub body: Vec<u8>,
}

impl WalFrame {
    pub fn new(seq: u64, kind: OpKind, body: Vec<u8>) -> Self {
        WalFrame { seq, kind, body }
    }

    /// Байты, по которым считается crc32: `seq ‖ kind ‖ body_len ‖ body`. Видимость crate'а —
    /// потому что корень (`root`) обязан хешировать ровно те же байты, что и crc32: «тот же оп»
    /// должен означать «те же байты» и на диске, и в цепи, и в дереве.
    pub(crate) fn payload(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + 1 + 4 + self.body.len());
        v.extend_from_slice(&self.seq.to_le_bytes());
        v.push(self.kind as u8);
        v.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.body);
        v
    }

    #[inline]
    pub fn crc(&self) -> u32 {
        let mut h = crc32fast::Hasher::new();
        h.update(&self.payload());
        h.finalize()
    }

    /// Полный фрейм на диске.
    pub fn encode(&self) -> Vec<u8> {
        let payload = self.payload();
        let crc = {
            let mut h = crc32fast::Hasher::new();
            h.update(&payload);
            h.finalize()
        };
        let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + self.body.len());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    pub fn total_frame_bytes(&self) -> usize {
        FRAME_HEADER_BYTES + self.body.len()
    }

    /// Разбор фрейма из начала `bytes`. Возвращает фрейм и число потребленных байт.
    pub fn decode(bytes: &[u8]) -> Result<(WalFrame, usize), WalError> {
        if bytes.len() < FRAME_HEADER_BYTES {
            return Err(WalError::ShortHeader { at: 0, have: bytes.len() });
        }
        let want = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let seq = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        let kind = bytes[12];
        let len = u32::from_le_bytes(bytes[13..17].try_into().unwrap());
        if len as usize > MAX_BODY_LEN {
            return Err(WalError::BodyTooLong { at: 0, len });
        }
        let need = FRAME_HEADER_BYTES + len as usize;
        if bytes.len() < need {
            return Err(WalError::ShortBody { at: 0, need: need as u64, have: bytes.len() });
        }
        let body = &bytes[FRAME_HEADER_BYTES..need];
        let mut h = crc32fast::Hasher::new();
        h.update(&bytes[4..need]);
        let found = h.finalize();
        if found != want {
            return Err(WalError::Crc { at: 0, want, found });
        }
        let kind = OpKind::from_u8(kind).map_err(|_| WalError::BadKind { at: 0, value: kind })?;
        Ok((WalFrame { seq, kind, body: body.to_vec() }, need))
    }
}

/// Имя сегмента: `wal.<start_seq>.log` (§10.2).
pub fn segment_name(start_seq: u64) -> String {
    format!("{WAL_PREFIX}{start_seq:020}{WAL_SUFFIX}")
}

/// Разобрать имя сегмента обратно в `start_seq`. Чужие файлы (снапшоты, MANIFEST) — ошибка.
pub fn parse_segment_name(name: &str) -> Result<u64, WalError> {
    let rest = name
        .strip_prefix(WAL_PREFIX)
        .and_then(|r| r.strip_suffix(WAL_SUFFIX))
        .ok_or_else(|| WalError::BadSegmentName(name.to_string()))?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WalError::BadSegmentName(name.to_string()));
    }
    rest.parse::<u64>().map_err(|_| WalError::BadSegmentName(name.to_string()))
}

/// Все сегменты каталога по возрастанию `start_seq`.
pub fn list_segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut out: Vec<(u64, PathBuf)> = Vec::new();
    let rd: ReadDir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in rd {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Ok(start) = parse_segment_name(&name) {
            out.push((start, entry.path()));
        }
    }
    out.sort_by_key(|(s, _)| *s);
    Ok(out)
}

/// Прочитать сегмент целиком. Останавливается на первом повреждённом фрейме: продолжить
/// нельзя, потому что после неверного `body_len` граница следующего фрейма неизвестна.
/// Усечение хвоста и битый crc — штатный результат, а не ошибка (§10.5, точка 1).
pub fn read_segment(path: &Path) -> io::Result<SegmentContents> {
    let all = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(SegmentContents::default())
        }
        Err(e) => return Err(e),
    };
    Ok(SegmentContents::parse(&all))
}

#[derive(Debug, Clone, Default)]
pub struct SegmentContents {
    pub frames: Vec<WalFrame>,
    /// Причина, по которой чтение остановилось: `None` — сегмент прочитан до конца чисто.
    pub stopped: Option<WalError>,
    pub bytes_consumed: usize,
}

impl SegmentContents {
    pub fn parse(bytes: &[u8]) -> Self {
        let mut out = SegmentContents::default();
        let mut off = 0usize;
        loop {
            if off >= bytes.len() {
                break;
            }
            match WalFrame::decode(&bytes[off..]) {
                Ok((frame, used)) => {
                    out.bytes_consumed = off + used;
                    off += used;
                    out.frames.push(frame);
                }
                Err(e) => {
                    out.stopped = Some(e);
                    break;
                }
            }
        }
        out
    }

    pub fn seqs(&self) -> Vec<u64> {
        self.frames.iter().map(|f| f.seq).collect()
    }
}

/// Писатель одного сегмента.
pub struct WalWriter {
    dir: PathBuf,
    path: PathBuf,
    file: File,
    start_seq: u64,
    bytes: u64,
    ops: u64,
    last_seq: Option<u64>,
    pub fault: Option<Fault>,
}

impl WalWriter {
    /// Открыть (или продолжить) сегмент, начинающийся с `start_seq`. Без `truncate`: живые
    /// байты сегмента неприкосновенны (§10.2).
    pub fn open(dir: &Path, start_seq: u64) -> Result<Self, WalError> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(segment_name(start_seq));
        let file = OpenOptions::new().append(true).create(true).open(&path)?;
        let bytes = file.metadata()?.len();
        let existing = read_segment(&path)?;
        Ok(WalWriter {
            dir: dir.to_path_buf(),
            path,
            file,
            start_seq,
            bytes,
            ops: existing.frames.len() as u64,
            last_seq: existing.frames.last().map(|f| f.seq),
            fault: None,
        })
    }

    #[inline]
    pub fn start_seq(&self) -> u64 {
        self.start_seq
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    #[inline]
    pub fn ops(&self) -> u64 {
        self.ops
    }

    #[inline]
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// Нужно ли ротировать до следующей записи (§10.2).
    #[inline]
    pub fn needs_rotation(&self) -> bool {
        self.bytes >= SEGMENT_MAX_BYTES || self.ops >= SEGMENT_MAX_OPS
    }

    /// Записать фрейм в файл и в буфер ОС. Не гарантирует durability — для этого `fsync`.
    ///
    /// Отказ записи не должен оставлять обрывок в живом сегменте: читатель останавливается на
    /// первом битом фрейме, и всё, что допишется после обрывка, стало бы нечитаемым. Исключение —
    /// `Fault::AppendMid`: она моделирует падение процесса посреди append (§10.5, точка 1), а
    /// умерший процесс ничего не откатывает. Настоящая ошибка io (ENOSPC, EIO) процесс переживает,
    /// поэтому хвост срезается до последней целостной границы (точка 9).
    pub fn append(&mut self, frame: &WalFrame) -> Result<(), WalError> {
        let err = match self.append_raw(frame) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        if !matches!(err, WalError::Injected(Fault::AppendMid)) {
            let _ = self.truncate_to(self.bytes);
        }
        Err(err)
    }

    /// Собственно запись байтов; откат хвоста делает `append`.
    ///
    /// `Fault::AppendMid`/`Fault::EnospcMidAppend` пишут половину фрейма и возвращают ошибку,
    /// не сдвинув `bytes`/`ops`/`last_seq`: состояние писателя остаётся таким, каким его застал
    /// бы процесс после падения, а на диске остаётся хвост, который читатель отбросит по crc или
    /// по усечению (§10.5, точки 1 и 9).
    fn append_raw(&mut self, frame: &WalFrame) -> Result<(), WalError> {
        if frame.body.len() > MAX_BODY_LEN {
            return Err(WalError::BodyTooLong { at: frame.seq, len: frame.body.len() as u32 });
        }
        if let Some(f @ (Fault::AppendMid | Fault::EnospcMidAppend)) = self.fault {
            let bytes = frame.encode();
            let half = bytes.len() / 2;
            self.file.write_all(&bytes[..half])?;
            self.file.flush()?;
            return Err(WalError::Injected(f));
        }
        let bytes = frame.encode();
        self.file.write_all(&bytes)?;
        self.file.flush()?;
        self.bytes += bytes.len() as u64;
        self.ops += 1;
        self.last_seq = Some(frame.seq);
        Ok(())
    }

    /// fsync сегмента. `Fault::AfterWalFsync` имитирует падение *после* успешного fsync и *до*
    /// применения опса в память: байты durable, память чистая, replay обязан применить опс ровно
    /// один раз (§10.5, точка 2).
    pub fn fsync(&mut self) -> Result<(), WalError> {
        self.file.sync_all()?;
        if let Some(f @ Fault::AfterWalFsync) = self.fault {
            return Err(WalError::Injected(f));
        }
        Ok(())
    }

    /// Срезать хвост сегмента до `len` — последней целостной границы фрейма (§10.5, точка 1).
    ///
    /// Без этого `open` оставил бы писателя дописывать ПОСЛЕ оборванного фрейма: читатель
    /// останавливается на первом битом фрейме, поэтому все опсы, записанные после восстановления,
    /// стали бы нечитаемыми. Append-only дескриптор `set_len` не принимает, поэтому файл
    /// открывается заново на чтение-запись, а потом снова на дозапись.
    pub fn truncate_to(&mut self, len: u64) -> Result<(), WalError> {
        // Сверяемся с длиной файла, а не с `self.bytes`: при откате неудачного append они
        // расходятся ровно на written-но-не-учтённый обрывок.
        if self.file.metadata()?.len() == len {
            self.bytes = len;
            return Ok(());
        }
        let path = self.path.clone();
        let f = OpenOptions::new().read(true).write(true).open(&path)?;
        f.set_len(len)?;
        f.sync_all()?;
        drop(f);
        self.file = OpenOptions::new().append(true).create(true).open(&path)?;
        self.bytes = len;
        Ok(())
    }

    /// Ротация: текущий сегмент fsync'ится и закрывается, новый начинается с `next_start_seq`.
    pub fn rotate(&mut self, next_start_seq: u64) -> Result<(), WalError> {
        self.fsync()?;
        let path = self.dir.join(segment_name(next_start_seq));
        let file = OpenOptions::new().append(true).create(true).open(&path)?;
        self.file = file;
        self.path = path;
        self.start_seq = next_start_seq;
        self.bytes = 0;
        self.ops = 0;
        self.last_seq = None;
        Ok(())
    }

    /// Удалить сегменты, полностью перекрытые снапшотом. Вызывается **только после** того, как
    /// MANIFEST записан (§10.4, шаг 6 после шага 5): до этого номера удалять нечем, и тест
    /// матрицы §10.5 точка 7 проверяет именно порядок.
    pub fn delete_older_than(dir: &Path, keep_from: u64) -> Result<Vec<PathBuf>, WalError> {
        let mut deleted = Vec::new();
        for (start, path) in list_segments(dir)? {
            if start < keep_from {
                std::fs::remove_file(&path)?;
                deleted.push(path);
            }
        }
        Ok(deleted)
    }

    pub fn sync_dir_best_effort(dir: &Path) -> io::Result<bool> {
        crate::fsync_dir(dir)
    }
}

impl Drop for WalWriter {
    fn drop(&mut self) {
        // Данные уже в буфере ОС после каждого append; fsync при drop — страховка от
        // «снапшот сделали, сегмент не дописали».
        let _ = self.file.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("vecdht-wal-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn frame(seq: u64, body: &[u8]) -> WalFrame {
        WalFrame::new(seq, OpKind::Insert, body.to_vec())
    }

    #[test]
    fn frame_roundtrip_and_layout() {
        let f = frame(0x0102_0304_0506_0708, &[0u8; 424]);
        let bytes = f.encode();
        assert_eq!(bytes.len(), FRAME_HEADER_BYTES + 424);
        // Порядок полей: crc, seq, kind, len, body.
        assert_eq!(&bytes[12..13], &[OpKind::Insert as u8]);
        assert_eq!(
            &bytes[13..17],
            &424u32.to_le_bytes(),
            "длина тела — u32: u8 её не описывает (§10.2)"
        );
        let (back, used) = WalFrame::decode(&bytes).unwrap();
        assert_eq!(back, f);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn crc_covers_seq_kind_len_and_body() {
        let f = frame(1, b"abc");
        let mut bytes = f.encode();
        for i in 4..bytes.len() {
            let saved = bytes[i];
            bytes[i] ^= 0xff;
            assert!(WalFrame::decode(&bytes).is_err(), "изменение байта {i} не замечено");
            bytes[i] = saved;
        }
        assert_eq!(WalFrame::decode(&bytes).unwrap().0, f);
    }

    #[test]
    fn truncated_tail_is_reported_not_fatal() {
        let mut f = Vec::new();
        f.extend(frame(1, b"a").encode());
        f.extend(frame(2, b"bb").encode());
        let full = SegmentContents::parse(&f);
        assert_eq!(full.seqs(), vec![1, 2]);
        assert!(full.stopped.is_none());
        let cut = SegmentContents::parse(&f[..f.len() - 1]);
        assert_eq!(cut.seqs(), vec![1], "предыдущие фреймы обязаны сохраниться (§10.5, 1)");
        assert!(matches!(cut.stopped, Some(WalError::ShortBody { .. })));
        let head_cut = SegmentContents::parse(&f[..FRAME_HEADER_BYTES - 1]);
        assert!(head_cut.frames.is_empty());
        assert!(matches!(head_cut.stopped, Some(WalError::ShortHeader { .. })));
    }

    #[test]
    fn unknown_op_kind_is_rejected_after_crc() {
        let mut bytes = frame(7, b"x").encode();
        bytes[12] = 0xEE;
        // crc считается по исходным байтам ⇒ после подмены kind он не сходится. Сначала crc,
        // потом kind: порядок проверок важен для теста точки 1.
        assert!(matches!(WalFrame::decode(&bytes), Err(WalError::Crc { .. })));
        // Теперь пересоберём crc поверх битого kind — ошибка должна быть про сам перечислитель.
        let payload = {
            let mut v = Vec::new();
            v.extend_from_slice(&7u64.to_le_bytes());
            v.push(0xEE);
            v.extend_from_slice(&1u32.to_le_bytes());
            v.extend_from_slice(b"x");
            v
        };
        let mut h = crc32fast::Hasher::new();
        h.update(&payload);
        let mut ok = h.finalize().to_le_bytes().to_vec();
        ok.extend_from_slice(&payload);
        assert!(matches!(WalFrame::decode(&ok), Err(WalError::BadKind { value: 0xEE, .. })));
    }

    #[test]
    fn absurd_body_len_is_rejected_without_allocating() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.push(OpKind::Delete as u8);
        bytes.extend_from_slice(&(u32::MAX - 1).to_le_bytes());
        assert!(matches!(WalFrame::decode(&bytes), Err(WalError::BodyTooLong { .. })));
    }

    #[test]
    fn segment_names_roundtrip() {
        assert_eq!(parse_segment_name(&segment_name(0)).unwrap(), 0);
        assert_eq!(parse_segment_name(&segment_name(12345)).unwrap(), 12345);
        assert_eq!(segment_name(7), "wal.00000000000000000007.log");
        for bad in ["snap.1.log", "MANIFEST", "wal..log", "wal.x.log", "wal.1"] {
            assert!(parse_segment_name(bad).is_err(), "{bad} принято");
        }
    }

    #[test]
    fn append_fsync_read_back() {
        let dir = tmp("basic");
        {
            let mut w = WalWriter::open(&dir, 1).unwrap();
            for s in 1..4u64 {
                w.append(&frame(s, format!("op{s}").as_bytes())).unwrap();
            }
            w.fsync().unwrap();
            assert_eq!(w.ops(), 3);
            assert_eq!(w.last_seq(), Some(3));
            assert_eq!(w.bytes(), (FRAME_HEADER_BYTES * 3 + 9) as u64);
        }
        let seg = dir.join(segment_name(1));
        let got = read_segment(&seg).unwrap();
        assert_eq!(got.seqs(), vec![1, 2, 3]);
        assert!(got.stopped.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reopening_a_segment_does_not_truncate_it() {
        let dir = tmp("no-truncate");
        {
            let mut w = WalWriter::open(&dir, 5).unwrap();
            w.append(&frame(5, b"first")).unwrap();
            w.fsync().unwrap();
        }
        {
            let mut w = WalWriter::open(&dir, 5).unwrap();
            assert_eq!(w.ops(), 1, "открытие не должно терять учётные данные сегмента");
            w.append(&frame(6, b"second")).unwrap();
            w.fsync().unwrap();
        }
        let got = read_segment(&dir.join(segment_name(5))).unwrap();
        assert_eq!(got.seqs(), vec![5, 6], "append, не overwrite (§10.2)");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn injected_append_leaves_a_recoverable_stub() {
        let dir = tmp("append-mid");
        {
            let mut w = WalWriter::open(&dir, 1).unwrap();
            w.append(&frame(1, b"good")).unwrap();
            w.fsync().unwrap();
            w.fault = Some(Fault::AppendMid);
            let err = w.append(&frame(2, b"body-that-is-long")).unwrap_err();
            assert!(matches!(err, WalError::Injected(Fault::AppendMid)));
            assert_eq!(w.ops(), 1, "счётчики не сдвинуты (§10.1)");
            assert_eq!(w.last_seq(), Some(1));
        }
        let got = read_segment(&dir.join(segment_name(1))).unwrap();
        assert_eq!(got.seqs(), vec![1]);
        assert!(got.stopped.is_some(), "хвост обязан быть замечен");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn injected_fsync_keeps_bytes_durable() {
        let dir = tmp("after-fsync");
        {
            let mut w = WalWriter::open(&dir, 1).unwrap();
            w.append(&frame(1, b"x")).unwrap();
            w.fault = Some(Fault::AfterWalFsync);
            let err = w.fsync().unwrap_err();
            assert!(matches!(err, WalError::Injected(Fault::AfterWalFsync)));
        }
        let got = read_segment(&dir.join(segment_name(1))).unwrap();
        assert_eq!(got.seqs(), vec![1], "опс durable: replay применит его (§10.5, 2)");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rotation_thresholds() {
        let dir = tmp("rotation");
        let mut w = WalWriter::open(&dir, 1).unwrap();
        assert!(!w.needs_rotation());
        // Размер фрейма: заголовок + тело, без length-prefix у crc.
        for body_len in [0usize, 8, 1024] {
            let f = frame(1, &vec![0u8; body_len]);
            assert_eq!(f.total_frame_bytes(), FRAME_HEADER_BYTES + body_len);
        }
        w.append(&frame(1, &[0u8; 8])).unwrap();
        assert!(!w.needs_rotation(), "один фрейм — не повод ротировать");
        w.ops = SEGMENT_MAX_OPS;
        assert!(w.needs_rotation(), "ротация по числу опсов");
        w.ops = SEGMENT_MAX_OPS - 1;
        assert!(!w.needs_rotation(), "порог — строго `>=`");
        w.ops = 1;
        w.bytes = SEGMENT_MAX_BYTES;
        assert!(w.needs_rotation(), "ротация по размеру");
        w.bytes = SEGMENT_MAX_BYTES - 1;
        assert!(!w.needs_rotation());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_older_than_keeps_the_referenced_segment() {
        let dir = tmp("delete");
        for s in [1u64, 100, 200] {
            let mut w = WalWriter::open(&dir, s).unwrap();
            w.append(&frame(s, b"a")).unwrap();
            w.fsync().unwrap();
        }
        let all = list_segments(&dir).unwrap();
        assert_eq!(all.iter().map(|(s, _)| *s).collect::<Vec<u64>>(), vec![1, 100, 200]);
        let deleted = WalWriter::delete_older_than(&dir, 100).unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            list_segments(&dir).unwrap().iter().map(|(s, _)| *s).collect::<Vec<u64>>(),
            vec![100, 200]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
