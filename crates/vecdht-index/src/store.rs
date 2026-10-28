//! `ShardStore`: WAL + индекс + снапшот-барьер + recovery (спека §10, §9.2).
//!
//! Порядок для каждой мутации (§10.1): построить опс → append WAL → fsync → применить в память
//! → ответить. `stage` выполняет первые два шага, `commit` — третий и четвёртый. Никакой
//! мутации in-memory до того, как опс durable: ошибка append ⇒ `publish` возвращает
//! `WAL_FAILED`, память не тронута, `next_slot` не сдвинут (§10.5, точка 9).
//!
//! Путь применения не читает системные часы (§9.6): бакет приходит только из `TimeMark` и
//! `GcTick` как данные опса. Именно поэтому тест «два узла, часы расходятся на 40 минут» даёт
//! побайтово равный файл, а не «обычно совпадает».

use std::path::{Path, PathBuf};

use vecdht_wire::codec::{Reader, DIM};
use vecdht_wire::messages::{
    decode_mark, encode_mark, ClassFilter, DeleteOp, DirFilter, InsertOp, OpKind, ReplicateOp,
};

use crate::entry::IndexEntry;
use crate::ivf::IvfIndex;
use crate::manifest::{
    read_manifest, read_max_epoch, write_manifest, write_max_epoch, ManifestError, StoreManifest,
};
use crate::snapshot::{
    partial_name, read_snapshot, snapshot_name, write_snapshot, SnapshotError, SnapshotMeta,
};
use crate::wal::{
    list_segments, read_segment, Fault, WalError, WalFrame, WalWriter, GROUP_COMMIT_MAX,
};

/// Триггер снапшота по дельте применённых опсов, а не по живому счётчику (§10.3).
pub const SNAPSHOT_OPS: u64 = 50_000;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Wal(#[from] WalError),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Index(#[from] crate::ivf::IndexError),
    #[error("io {ctx}: {detail}")]
    Io { ctx: &'static str, detail: String },
    #[error("publish отбит: WAL не записан, память не тронута (код протокола WAL_FAILED, §10.1)")]
    WalFailed(String),
    #[error("эпоха {given} не обслуживается: на диске зафиксировано max_epoch_served = {saved} (§9.2)")]
    StaleEpoch { given: u64, saved: u64 },
    #[error("lease не подтверждён на диске: publish и подпись невозможны до grant_epoch (§9.2)")]
    NeedLease,
    #[error("WAL-фрейм seq={seq} не декодируется как опс вида {kind}: {detail}")]
    BadOp { seq: u64, kind: &'static str, detail: String },
    #[error("фрейм seq={seq} относится к шарду {found}, а индекс — к {want}")]
    ForeignShard { seq: u64, want: u16, found: u16 },
    #[error("снапшот в MANIFEST указан snapshot_seq={wanted}, а файла нет на диске")]
    MissingSnapshot { wanted: u64 },
    #[error("MANIFEST обещает {field}={expected}, снапшот содержит {found}")]
    ManifestDisagrees { field: &'static str, expected: u64, found: u64 },
    #[error("gap в WAL: пропущено {count} опсов между {from} и {to} (долечится pull'ом, §9.7)")]
    WalGap { from: u64, to: u64, count: u64 },
    #[error("индекс после восстановления не удовлетворяет инвариантам: {0}")]
    Invariants(String),
}

/// Что store сделал с опсом при применении.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Опс durable и применён.
    Ok,
    /// `seq ≤ applied_seq`: идемпотентность по seq (§10.5, точка 2).
    Duplicate,
}

pub struct ShardStore {
    pub dir: PathBuf,
    pub shard: u16,
    pub index: IvfIndex,
    /// Последний применённый seq. От него считается дельта до снапшота (§10.3).
    pub applied_seq: u64,
    /// Следующий seq для записи (primary назначает его сам).
    pub next_seq: u64,
    /// Последний применённый `TimeMark` — единственное «сейчас» для поиска и GC (§9.6).
    pub time_mark_bucket: u32,
    pub max_epoch_served: u64,
    /// Эпизода текущего lease; фреймы со старым epoch не пишутся и не применяются (§9.8).
    pub epoch: u64,
    /// Файл `epoch.marker` подтверждён на диске для `epoch` (§9.2). `open` его не создаёт молча:
    /// «я стою на эпизоде E» — решение держателя lease, а не побочный эффект восстановления.
    marker_durable: bool,
    pub last_snapshot_seq: u64,
    pub wal: WalWriter,
    /// Причина, по которой хвост последнего прочитанного сегмента оборвался (точка 1 матрицы).
    pub tail_corruption: Option<String>,
    /// Сколько опсов хвоста WAL применено при последнем `open` — для теста матрицы.
    pub replayed: u64,
    staged: Vec<WalFrame>,
    /// Точки матрицы §10.5; в проде всегда `None`.
    pub fault: Option<Fault>,
}

impl ShardStore {
    /// Открыть шард: MANIFEST → снапшот → хвост WAL. Пустой каталог — это новый шард.
    pub fn open(dir: &Path, shard: u16) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| StoreError::Io { ctx: "create_dir_all", detail: e.to_string() })?;
        let max_epoch_served = read_max_epoch(dir)?;
        let mf = read_manifest(dir)?;

        let mut index = IvfIndex::new(shard);
        let mut applied_seq = 0u64;
        let mut time_mark_bucket = 0u32;
        let mut last_snapshot_seq = 0u64;
        if let Some(m) = mf {
            if m.shard != shard {
                return Err(StoreError::ForeignShard { seq: 0, want: shard, found: m.shard });
            }
            let path = dir.join(snapshot_name(m.snapshot_seq));
            if !path.exists() {
                return Err(StoreError::MissingSnapshot { wanted: m.snapshot_seq });
            }
            let loaded = read_snapshot(&path)?;
            if loaded.meta.snapshot_seq != m.snapshot_seq {
                return Err(StoreError::ManifestDisagrees {
                    field: "snapshot_seq",
                    expected: m.snapshot_seq,
                    found: loaded.meta.snapshot_seq,
                });
            }
            if loaded.meta.next_slot != m.next_slot {
                return Err(StoreError::ManifestDisagrees {
                    field: "next_slot",
                    expected: m.next_slot,
                    found: loaded.meta.next_slot,
                });
            }
            index = loaded.index;
            applied_seq = m.applied_seq;
            time_mark_bucket = m.time_mark_bucket;
            last_snapshot_seq = m.snapshot_seq;
        }

        // Хвост WAL. `oldest_wal_needed` говорит, откуда начинать; без MANIFEST читаем все
        // сегменты — это случай «упали до записи MANIFEST», он обязан быть безопасным (§10.5, 6).
        let from = mf.map(|m| m.oldest_wal_needed).unwrap_or(0);
        let segments = list_segments(dir)
            .map_err(|e| StoreError::Io { ctx: "list_segments", detail: e.to_string() })?;
        // Продолжаем только тот сегмент, который ещё нужен MANIFEST. Иначе (точка 6: шаг 6 барьера
        // не сделан) дописка ушла бы в файл, который MANIFEST считает перекрытым снапшотом, и
        // `oldest_wal_needed` следующего flush'а остался бы прежним — сегменты не вычищались бы
        // никогда. Новый сегмент начинается с `applied_seq + 1`.
        // Сегменты отсортированы по start, поэтому идем с конца: первый подходящий и есть самый
        // свежий, который ещё нужен MANIFEST.
        let wal_start = segments
            .iter()
            .rev()
            .find(|(start, _)| *start >= from)
            .map(|(start, _)| *start)
            .unwrap_or(applied_seq + 1);
        let mut store = ShardStore {
            dir: dir.to_path_buf(),
            shard,
            index,
            applied_seq,
            next_seq: applied_seq + 1,
            time_mark_bucket,
            max_epoch_served,
            epoch: max_epoch_served,
            // Маркер есть на диске ⇒ durable-инвариант §9.2 выполнен для этой эпизоды; отсутствие
            // файла при `max_epoch_served = 0` означает «решение ещё не записано», и publish
            // обязан быть отвергнут до `grant_epoch`.
            marker_durable: dir.join(crate::manifest::EPOCH_NAME).exists(),
            last_snapshot_seq,
            wal: WalWriter::open(dir, wal_start)?,
            tail_corruption: None,
            replayed: 0,
            staged: Vec::new(),
            fault: None,
        };

        let mut expected = applied_seq;
        let mut applied = 0u64;
        let mut torn: Option<(PathBuf, u64)> = None;
        for (_start, path) in segments.iter().filter(|(start, _)| *start >= from) {
            let seg = read_segment(path)
                .map_err(|e| StoreError::Io { ctx: "read_segment", detail: e.to_string() })?;
            for frame in seg.frames {
                if frame.seq <= expected {
                    continue; // уже в снапшоте или применённый хвост
                }
                store.apply_frame(&frame)?;
                expected = frame.seq;
                applied += 1;
            }
            if let Some(err) = seg.stopped {
                // Битый или усечённый хвост — штатный итог падения посреди append: фреймы до
                // него применены, дальше журнала нет (§10.5, точка 1).
                store.tail_corruption = Some(err.to_string());
                torn = Some((path.clone(), seg.bytes_consumed as u64));
            }
        }
        // Точка 1 матрицы на этом не заканчивается: хвост надо срезать, иначе первый же publish
        // после восстановления допишется ЗА битым фреймом, а читатель останавливается на первом
        // бите — все опсы после точки падения стали бы нечитаемыми.
        if let Some((path, good)) = torn {
            if path == store.wal.path() {
                store.wal.truncate_to(good).map_err(|e| StoreError::Io {
                    ctx: "truncate torn tail",
                    detail: e.to_string(),
                })?;
            }
        }
        store.replayed = applied;
        store.next_seq = expected + 1;
        let problems = store.index.check_invariants();
        if let Err(e) = problems {
            return Err(StoreError::Invariants(e));
        }
        Ok(store)
    }

    /// Новый шард в чистом каталоге с начальной эпизодой lease.
    pub fn create(dir: &Path, shard: u16, epoch: u64) -> Result<Self, StoreError> {
        let mut s = ShardStore::open(dir, shard)?;
        s.grant_epoch(epoch)?;
        Ok(s)
    }

    /// Сколько опсов хвоста WAL было применено при открытии — для теста матрицы.
    pub fn replayed(&self) -> u64 {
        self.replayed
    }

    /// Lease выдан/продлён (§9.8). До подписания и обслуживания `max_epoch_served` обязан быть
    /// fsync'нут (§9.2), поэтому маркер пишется до смены `epoch`.
    ///
    /// `Ok(true)` — эпизода выдана заново или подтверждена после потери маркера: вызывающий
    /// обязан переподписать `ShardMembership` и разослать его. `Ok(false)` — возобновление той же
    /// эпизоды, никакого раунда подписей не нужно.
    pub fn grant_epoch(&mut self, epoch: u64) -> Result<bool, StoreError> {
        if epoch < self.max_epoch_served {
            return Err(StoreError::StaleEpoch { given: epoch, saved: self.max_epoch_served });
        }
        if epoch > self.max_epoch_served {
            write_max_epoch(&self.dir, epoch)?;
            self.max_epoch_served = epoch;
            self.marker_durable = true;
            self.epoch = epoch;
            return Ok(true);
        }
        // epoch == saved. Если маркер потерян, запись «я обслуживаю E» ещё не durable —
        // восстанавливаем её и считаем это новой выдачей, а не тихим возобновлением.
        if !self.marker_durable {
            write_max_epoch(&self.dir, epoch)?;
            self.marker_durable = true;
            self.epoch = epoch;
            return Ok(true);
        }
        self.epoch = epoch;
        Ok(false)
    }

    /// Готов ли шард обслуживать publish и подписывать ответы (§9.2, §9.8): нужна эпизода,
    /// подтверждённая на диске и не младше уже обслуженной.
    #[inline]
    pub fn need_lease(&self) -> bool {
        self.epoch < self.max_epoch_served || !self.marker_durable
    }

    /// Эпизода, с которой узел готов обслуживать, — `None`, пока lease не подтверждён.
    #[inline]
    pub fn serving_epoch(&self) -> Option<u64> {
        (!self.need_lease()).then_some(self.epoch)
    }

    // --- запись ---------------------------------------------------------------

    /// Полный путь publish (§10.1): stage + commit, один fsync.
    pub fn publish(&mut self, e: IndexEntry) -> Result<u32, StoreError> {
        self.stage_insert(e)?;
        self.commit()?;
        self.index.owner_slot(&e.owner_ed25519).ok_or_else(|| StoreError::Invariants(
            "publish отработал, но записи нет в индексе".into(),
        ))
    }

    /// `publish` с байтом объявления (§5.5). Путь тот же — WAL → fsync → apply, — но байт едет
    /// в теле фрейма и переживает рестарт вместе с записью, а не остаётся «параметром вызова».
    pub fn publish_with_attr(&mut self, e: IndexEntry, slot_attr: u8) -> Result<u32, StoreError> {
        self.stage_insert_with_attr(e, slot_attr)?;
        self.commit()?;
        self.index.owner_slot(&e.owner_ed25519).ok_or_else(|| StoreError::Invariants(
            "publish_with_attr отработал, но записи нет в индексе".into(),
        ))
    }

    pub fn stage_insert(&mut self, e: IndexEntry) -> Result<u64, StoreError> {
        self.stage_insert_with_attr(e, 0)
    }

    /// `Insert` с байтом объявления (§5.5). Байт едет в теле фрейма, а не отдельным опсом:
    /// реплика применяет тот же фрейм и получает тот же `slot_attr` без второго сообщения.
    pub fn stage_insert_with_attr(
        &mut self,
        e: IndexEntry,
        slot_attr: u8,
    ) -> Result<u64, StoreError> {
        self.stage(WalFrame::new(
            0,
            OpKind::Insert,
            e.to_insert_with_attr(slot_attr).body_bytes(),
        ))
    }

    pub fn stage_delete(&mut self, owner: [u8; 32]) -> Result<u64, StoreError> {
        let op = DeleteOp { owner_ed25519: owner, shard: self.shard };
        self.stage(WalFrame::new(0, OpKind::Delete, op.body_bytes()))
    }

    /// `TimeMark` каждые 512 применённых опсов (§9.6). Бакет выровнен, поэтому байты фрейма
    /// одинаковы на всех узлах.
    pub fn stage_time_mark(&mut self, bucket: u32) -> Result<u64, StoreError> {
        self.stage(WalFrame::new(0, OpKind::TimeMark, encode_mark(0, bucket)))
    }

    /// `GcTick` — обычный WAL-фрейм: реплики применяют его на том же seq и с тем же `bucket`.
    pub fn stage_gc_tick(&mut self, bucket: u32) -> Result<u64, StoreError> {
        self.stage(WalFrame::new(0, OpKind::GcTick, encode_mark(0, bucket)))
    }

    /// Назначить seq, проверить ротацию, записать фрейм в WAL. Не fsync'ит и не применяет.
    pub fn stage(&mut self, frame: WalFrame) -> Result<u64, StoreError> {
        if self.need_lease() {
            if self.epoch < self.max_epoch_served {
                return Err(StoreError::StaleEpoch {
                    given: self.epoch,
                    saved: self.max_epoch_served,
                });
            }
            return Err(StoreError::NeedLease);
        }
        let seq = self.next_seq;
        let mut frame = WalFrame { seq, ..frame };
        if matches!(frame.kind, OpKind::TimeMark | OpKind::GcTick) {
            // seq внутри тела обязан совпадать с seq фрейма, иначе реплика применит mark из
            // другой позиции потока (§9.6).
            let (_body_seq, bucket) = decode_mark(&frame.body).map_err(|e| StoreError::BadOp {
                seq,
                kind: "TimeMark/GcTick",
                detail: e.to_string(),
            })?;
            frame.body = encode_mark(seq, bucket);
        }
        if self.wal.needs_rotation() {
            self.wal.rotate(seq)?;
        }
        // Хук падений живёт в writer'е: store решает, *какая* точка включена, wal — *где*
        // оборвать запись (матрица §10.5 реализована внедряемым хуком, а не crate `fail`).
        self.wal.fault = self.fault;
        self.wal.append(&frame).map_err(|e| match e {
            WalError::Injected(f) => StoreError::WalFailed(f.to_string()),
            other => StoreError::Wal(other),
        })?;
        self.next_seq += 1;
        self.staged.push(frame);
        Ok(seq)
    }

    /// fsync сегмента, затем применение staged. Ошибка fsync ⇒ память не тронута, staged
    /// остаются: повторный commit применит их ровно один раз (идемпотентность по seq, §10.5, 2).
    pub fn commit(&mut self) -> Result<usize, StoreError> {
        if self.staged.is_empty() {
            return Ok(0);
        }
        self.wal.fault = self.fault;
        self.wal.fsync().map_err(|e| match e {
            WalError::Injected(f) => StoreError::WalFailed(f.to_string()),
            other => StoreError::Wal(other),
        })?;
        let staged = std::mem::take(&mut self.staged);
        let mut n = 0usize;
        for frame in staged {
            if self.apply_frame(&frame)? == Applied::Ok {
                n += 1;
            }
        }
        self.maybe_snapshot()?;
        Ok(n)
    }

    /// Нужно ли коммитить прямо сейчас (групповой коммит по числу опсов, §10.2).
    #[inline]
    pub fn should_group_commit(&self) -> bool {
        self.staged.len() >= GROUP_COMMIT_MAX
    }

    #[inline]
    pub fn staged_len(&self) -> usize {
        self.staged.len()
    }

    /// Применить уже durable-фрейм (путь recovery и путь реплики). Идемпотентен по seq.
    pub fn apply_frame(&mut self, frame: &WalFrame) -> Result<Applied, StoreError> {
        if frame.seq <= self.applied_seq {
            return Ok(Applied::Duplicate);
        }
        match frame.kind {
            OpKind::Insert => {
                let mut r = Reader::new(&frame.body);
                let op = InsertOp::decode(&mut r).map_err(|e| StoreError::BadOp {
                    seq: frame.seq,
                    kind: "Insert",
                    detail: e.to_string(),
                })?;
                self.index
                    .insert_with_attr(IndexEntry::from_insert(&op), op.slot_attr)?;
            }
            OpKind::Delete => {
                let mut r = Reader::new(&frame.body);
                let op = DeleteOp::decode(&mut r).map_err(|e| StoreError::BadOp {
                    seq: frame.seq,
                    kind: "Delete",
                    detail: e.to_string(),
                })?;
                if op.shard != self.shard {
                    return Err(StoreError::ForeignShard {
                        seq: frame.seq,
                        want: self.shard,
                        found: op.shard,
                    });
                }
                self.index.remove_owner(&op.owner_ed25519);
            }
            OpKind::TimeMark => {
                let (body_seq, bucket) = decode_mark(&frame.body).map_err(|e| StoreError::BadOp {
                    seq: frame.seq,
                    kind: "TimeMark",
                    detail: e.to_string(),
                })?;
                if body_seq != frame.seq {
                    return Err(StoreError::BadOp {
                        seq: frame.seq,
                        kind: "TimeMark",
                        detail: format!("в теле seq={body_seq}"),
                    });
                }
                self.time_mark_bucket = self.time_mark_bucket.max(bucket);
            }
            OpKind::GcTick => {
                let (up_to_seq, bucket) = decode_mark(&frame.body).map_err(|e| StoreError::BadOp {
                    seq: frame.seq,
                    kind: "GcTick",
                    detail: e.to_string(),
                })?;
                if up_to_seq > frame.seq {
                    return Err(StoreError::BadOp {
                        seq: frame.seq,
                        kind: "GcTick",
                        detail: format!("up_to_seq={up_to_seq} больше самого фрейма"),
                    });
                }
                // Экспирация — только относительно бакета из фрейма (§9.6).
                self.time_mark_bucket = self.time_mark_bucket.max(bucket);
                self.index.expire(bucket);
            }
        }
        self.applied_seq = frame.seq;
        Ok(Applied::Ok)
    }

    /// Путь реплики-догоняющего (§9.7, §9.8): фрейм пришёл в составе подписанного `ReplicateOp`.
    /// `epoch < max_epoch_served` ⇒ отбросить и не применять: старый primary демотируется сам.
    pub fn apply_replicated(&mut self, op: &ReplicateOp) -> Result<Applied, StoreError> {
        if op.shard != self.shard {
            return Err(StoreError::ForeignShard { seq: op.seq, want: self.shard, found: op.shard });
        }
        if op.epoch < self.max_epoch_served {
            return Err(StoreError::StaleEpoch { given: op.epoch, saved: self.max_epoch_served });
        }
        if op.seq <= self.applied_seq {
            return Ok(Applied::Duplicate);
        }
        let frame = WalFrame::new(op.seq, op.op_kind, op.body.clone());
        // Реплика пишет фрейм primary'а дословно: seq не переназначается, иначе поток перестал
        // бы совпадать с потоком primary и файлы разошлись бы (§8.3).
        if op.seq > self.applied_seq + 1 {
            return Err(StoreError::WalGap {
                from: self.applied_seq,
                to: op.seq,
                count: op.seq - self.applied_seq - 1,
            });
        }
        self.wal.append(&frame)?;
        self.wal.fsync()?;
        let applied = self.apply_frame(&frame)?;
        self.next_seq = self.next_seq.max(op.seq + 1);
        Ok(applied)
    }

    // --- чтение ---------------------------------------------------------------

    /// Поиск с последним применённым `TimeMark` в роли «сейчас» (§8.4).
    pub fn search(&self, q: &[i8; DIM], clusters: &[u16], top_k: usize) -> Vec<(u32, u32)> {
        self.index.search(q, clusters, top_k, self.time_mark_bucket)
    }

    /// Поиск с фильтрами класса и направления (§12.7). `Any/Any` — ровно `search`.
    pub fn search_filtered(
        &self,
        q: &[i8; DIM],
        clusters: &[u16],
        top_k: usize,
        class: ClassFilter,
        dir: DirFilter,
    ) -> Vec<(u32, u32)> {
        self.index.search_filtered(q, clusters, top_k, self.time_mark_bucket, class, dir)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.index.live
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.index.live == 0
    }

    // --- снапшот-барьер -------------------------------------------------------

    /// Триггер по дельте применённых опсов (§10.3). При TTL-плато живой счётчик стоит, а
    /// `applied_seq` растёт всегда (перепубликации, экспирации, `TimeMark`) — поэтому «WAL
    /// растёт бесконечно, потому что снапшот никогда не сработал» невозможен по построению.
    pub fn maybe_snapshot(&mut self) -> Result<bool, StoreError> {
        if self.applied_seq.saturating_sub(self.last_snapshot_seq) >= SNAPSHOT_OPS {
            self.flush_snapshot()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Барьер §10.4, шаги 1–6 ровно в этом порядке.
    pub fn flush_snapshot(&mut self) -> Result<u64, StoreError> {
        let seq = self.applied_seq;
        // 1. fsync текущего WAL-сегмента.
        self.wal.fsync()?;
        // Хвост из мёртвых slot'ов в файл не пишется и в `next_slot` не попадает: он ничего не
        // описывает, а стоит 424 Б на дыру. Аллокатор от подрезки не меняется (§8.3, тест
        // `trimming_the_tail_does_not_change_future_slot_numbers`), поэтому равенство
        // `recover == replay` сохраняется.
        let next_slot = u64::from(self.index.trimmed_next_slot());
        // 2. потоковая запись snap.<seq>.partial → fsync файла.
        let partial = self.dir.join(partial_name(seq));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&partial)
            .map_err(|e| StoreError::Io { ctx: "open partial", detail: e.to_string() })?;
        let meta = SnapshotMeta {
            snapshot_seq: seq,
            next_slot,
            time_mark_bucket: self.time_mark_bucket,
            max_epoch_served: self.max_epoch_served,
            shard: self.shard,
        };
        let written = write_snapshot(&mut file, meta, &self.index)?;
        if self.fault == Some(Fault::SnapshotMid) {
            // Точка 3: partial остался на диске, fsync не сделан, в MANIFEST его нет ⇒
            // восстановление его игнорирует.
            drop(file);
            return Err(StoreError::Snapshot(SnapshotError::Io(Fault::SnapshotMid.to_string())));
        }
        file.sync_all().map_err(|e| StoreError::Io { ctx: "fsync partial", detail: e.to_string() })?;
        drop(file);
        // 3. rename → snap.<seq>.log (атомично).
        std::fs::rename(&partial, self.dir.join(snapshot_name(seq)))
            .map_err(|e| StoreError::Io { ctx: "rename snapshot", detail: e.to_string() })?;
        // 4. fsync каталога. Платформа без fsync каталога (Windows) — не ошибка: rename
        // заурналирован NTFS, а шаг 6 без этого всё равно не удаляет сегменты, пока MANIFEST
        // не переписан (§10.4).
        crate::fsync_dir(&self.dir).map_err(|e| StoreError::Io { ctx: "fsync dir", detail: e.to_string() })?;
        // 5. атомично переписать MANIFEST.
        let mf = StoreManifest {
            shard: self.shard,
            snapshot_seq: seq,
            oldest_wal_needed: self.wal.start_seq(),
            applied_seq: self.applied_seq,
            next_slot,
            time_mark_bucket: self.time_mark_bucket,
        };
        write_manifest(&self.dir, &mf, self.fault)?;
        // 6. и только теперь удалять сегменты старше `oldest_wal_needed`.
        WalWriter::delete_older_than(&self.dir, self.wal.start_seq())
            .map_err(|e| StoreError::Io { ctx: "delete segments", detail: e.to_string() })?;
        // 7. отдать память хвоста, который файл уже не описывает. Порядок важен: до rename и
        // переписанного MANIFEST'а арена обязана оставаться прежней, иначе падение между шагами
        // 3 и 5 оставило бы на диске снапшот, не соответствующий памяти (§10.4).
        self.index.truncate_holes();
        self.last_snapshot_seq = seq;
        Ok(written)
    }

    pub fn manifest(&self) -> StoreManifest {
        StoreManifest {
            shard: self.shard,
            snapshot_seq: self.last_snapshot_seq,
            oldest_wal_needed: self.wal.start_seq(),
            applied_seq: self.applied_seq,
            next_slot: self.index.next_slot() as u64,
            time_mark_bucket: self.time_mark_bucket,
        }
    }

    /// Слить staged и закрыть store (штатная остановка узла).
    pub fn shutdown(mut self) -> Result<(), StoreError> {
        if !self.staged.is_empty() {
            self.commit()?;
        }
        self.wal.fsync()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{dir, remove};
    use vecdht_wire::codec::MAX_BODY_LEN;

    fn entry(owner: u8, published: u32, ttl: u16) -> IndexEntry {
        IndexEntry {
            owner_ed25519: [owner; 32],
            vec_q: [(owner as i8) % 7; DIM],
            cluster_id: (owner as u16) % 16,
            published_bucket: published,
            ttl_buckets: ttl,
        }
    }

    fn open(tag: &str) -> ShardStore {
        ShardStore::create(&dir(tag), 0, 1).unwrap()
    }

    #[test]
    fn publish_writes_then_applies() {
        let mut s = open("publish");
        let slot = s.publish(entry(1, 0, 100)).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(s.applied_seq, 1);
        assert_eq!(s.len(), 1);
        let path = s.dir.clone();
        s.shutdown().unwrap();
        let back = ShardStore::open(&path, 0).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back.applied_seq, 1);
        remove(&path);
    }

    #[test]
    fn error_before_fsync_leaves_memory_untouched() {
        // §10.1: ошибка append ⇒ publish возвращает WAL_FAILED, память не тронута,
        // next_slot не сдвинут (точка 9).
        let mut s = open("no-fsync");
        s.fault = Some(Fault::AppendMid);
        let err = s.publish(entry(2, 0, 100)).unwrap_err();
        assert!(matches!(err, StoreError::WalFailed(_)), "{err}");
        assert_eq!(s.len(), 0);
        assert_eq!(s.applied_seq, 0);
        assert_eq!(s.index.next_slot(), 0);
        assert_eq!(s.staged_len(), 0, "staged пуст, потому что append не прошёл");
        s.fault = None;
        let slot = s.publish(entry(3, 0, 100)).unwrap();
        assert_eq!(slot, 0, "первый successful slot после отказа — тот же 0");
        let path = s.dir.clone();
        s.shutdown().unwrap();
        remove(&path);
    }

    #[test]
    fn durable_then_crash_applies_once_on_retry() {
        // Точка 2: fsync прошёл, применения не было. Повторный commit обязан применить staged
        // ровно один раз, recovery — тоже.
        let mut s = open("after-fsync");
        s.stage_insert(entry(4, 0, 100)).unwrap();
        s.fault = Some(Fault::AfterWalFsync);
        let err = s.commit().unwrap_err();
        assert!(matches!(err, StoreError::WalFailed(_)), "{err}");
        assert_eq!(s.len(), 0, "память не тронута");
        assert_eq!(s.staged_len(), 1, "staged сохранены");
        let path = s.dir.clone();
        drop(s);
        let back = ShardStore::open(&path, 0).unwrap();
        assert_eq!(back.len(), 1, "durable-опс применён при replay (§10.5, 2)");
        assert_eq!(back.applied_seq, 1);
        remove(&path);
    }

    #[test]
    fn group_commit_batches_then_applies_in_order() {
        let mut s = open("group");
        for o in 0..GROUP_COMMIT_MAX as u8 {
            s.stage_insert(entry(o, 0, 100)).unwrap();
        }
        assert!(s.should_group_commit());
        assert_eq!(s.len(), 0, "до commit памяти нет");
        let n = s.commit().unwrap();
        assert_eq!(n, GROUP_COMMIT_MAX);
        assert_eq!(s.applied_seq, GROUP_COMMIT_MAX as u64);
        assert_eq!(s.len(), GROUP_COMMIT_MAX);
        // Порядок применения = порядок seq: slot'ы назначались по возрастанию.
        for o in 0..GROUP_COMMIT_MAX as u8 {
            assert_eq!(s.index.owner_slot(&[o; 32]), Some(o as u32));
        }
        let path = s.dir.clone();
        s.shutdown().unwrap();
        remove(&path);
    }

    #[test]
    fn dedup_goes_through_the_wal() {
        let mut s = open("dedup");
        let a = s.publish(entry(7, 10, 100)).unwrap();
        let b = s.publish(entry(7, 20, 100)).unwrap();
        assert_eq!(a, b, "перепубликация заменяет на месте");
        assert_eq!(s.len(), 1);
        assert_eq!(s.applied_seq, 2, "но опсов в журнале два");
        let path = s.dir.clone();
        s.shutdown().unwrap();
        let back = ShardStore::open(&path, 0).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back.index.entry(a).unwrap().published_bucket, 20);
        remove(&path);
    }

    #[test]
    fn gc_tick_and_time_mark_are_replicated_state() {
        let mut s = open("gc");
        // У помощника `entry` кластер = owner % 16, поэтому записи живут в кластерах 1 и 2.
        s.publish(entry(1, 0, 5)).unwrap();
        s.publish(entry(2, 0, 1000)).unwrap();
        s.stage_time_mark(4).unwrap();
        s.commit().unwrap();
        assert_eq!(s.time_mark_bucket, 4);
        assert_eq!(s.search(&[0i8; DIM], &[1, 2], 10).len(), 2);
        s.stage_gc_tick(5).unwrap();
        s.commit().unwrap();
        assert_eq!(s.len(), 1, "entry(1) истёк по бакету, не по часам узла");
        let path = s.dir.clone();
        s.shutdown().unwrap();
        let back = ShardStore::open(&path, 0).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back.time_mark_bucket, 5);
        remove(&path);
    }

    #[test]
    fn epoch_fencing_blocks_service_and_replay() {
        let mut s = open("epoch");
        s.grant_epoch(4).unwrap();
        assert_eq!(s.max_epoch_served, 4);
        assert!(matches!(s.grant_epoch(3), Err(StoreError::StaleEpoch { given: 3, saved: 4 })));
        // Publish под fenced-эпизодой невозможен.
        s.epoch = 3;
        assert!(matches!(s.stage_insert(entry(1, 0, 1)), Err(StoreError::StaleEpoch { .. })));
        s.epoch = 4;
        // Op с чужим старым epoch отбрасывается репликой.
        let op = ReplicateOp {
            shard: 0,
            epoch: 2,
            seq: 1,
            op_kind: OpKind::Insert,
            body: entry(9, 0, 100).to_insert().body_bytes(),
        };
        assert!(matches!(s.apply_replicated(&op), Err(StoreError::StaleEpoch { given: 2, saved: 4 })));
        assert_eq!(s.len(), 0);
        let path = s.dir.clone();
        s.shutdown().unwrap();
        remove(&path);
    }

    #[test]
    fn serving_requires_an_epoch_confirmed_on_disk() {
        // §9.2: `open` не выдаёт lease молча. Пока `epoch.marker` не записан, шард читается,
        // но publish и подпись отказываются — иначе сам факт восстановления означал бы, что
        // узел «стоит» на какой-то эпизоде, которую никто не подтверждал.
        let d = dir("no-lease");
        let mut fresh = ShardStore::open(&d, 0).unwrap();
        assert!(fresh.need_lease());
        assert_eq!(fresh.serving_epoch(), None);
        assert!(matches!(fresh.publish(entry(1, 0, 10)), Err(StoreError::NeedLease)));
        assert_eq!(fresh.len(), 0);
        assert!(!d.join(crate::manifest::EPOCH_NAME).exists(), "до lease маркера нет");

        assert!(fresh.grant_epoch(3).unwrap(), "первая выдача — новый раунд подписей");
        assert_eq!(fresh.serving_epoch(), Some(3));
        fresh.publish(entry(1, 0, 10)).unwrap();
        let path = fresh.dir.clone();
        drop(fresh);

        let mut back = ShardStore::open(&path, 0).unwrap();
        assert!(!back.need_lease(), "маркер на диске ⇒ возобновление той же эпизоды легитимно");
        assert!(!back.grant_epoch(3).unwrap(), "та же эпизода — без нового раунда");
        assert!(matches!(
            back.grant_epoch(2),
            Err(StoreError::StaleEpoch { given: 2, saved: 3 })
        ));
        drop(back);

        // Потеря маркера — отказ обслуживать, а не тихая подмена: `max_epoch_served` вместе с
        // файлом обнуляется, и узел обязан взять эпизоду из своей копии цепочки (§9.5).
        std::fs::remove_file(path.join(crate::manifest::EPOCH_NAME)).unwrap();
        let mut lost = ShardStore::open(&path, 0).unwrap();
        assert!(lost.need_lease());
        assert_eq!(lost.max_epoch_served, 0);
        assert_eq!(lost.len(), 1, "состояние шарда при этом прочитано полностью");
        assert!(matches!(lost.publish(entry(2, 0, 10)), Err(StoreError::NeedLease)));
        assert!(lost.grant_epoch(4).unwrap());
        lost.publish(entry(2, 0, 10)).unwrap();
        assert_eq!(lost.len(), 2);
        remove(&path);
    }

    #[test]
    fn replicated_stream_rebuilds_the_same_index() {        // §9.4: primary и реплика на одном потоке опсов обязаны сойтись в одно состояние.
        let primary_dir = dir("repl-a");
        let mut primary = ShardStore::create(&primary_dir, 0, 1).unwrap();
        for o in 0..12u8 {
            primary.publish(entry(o, 3, 100)).unwrap();
        }
        primary.stage_time_mark(7).unwrap();
        primary.stage_gc_tick(9).unwrap();
        primary.commit().unwrap();
        primary.stage_delete([3u8; 32]).unwrap();
        primary.commit().unwrap();

        let replica_dir = dir("repl-b");
        let mut replica = ShardStore::create(&replica_dir, 0, 1).unwrap();
        let frames: Vec<WalFrame> = list_segments(&primary_dir)
            .unwrap()
            .into_iter()
            .flat_map(|(_, p)| read_segment(&p).unwrap().frames)
            .collect();
        for f in frames {
            let op = ReplicateOp {
                shard: 0,
                epoch: 1,
                seq: f.seq,
                op_kind: f.kind,
                body: f.body,
            };
            assert_eq!(replica.apply_replicated(&op).unwrap(), Applied::Ok);
        }
        assert_eq!(replica.applied_seq, primary.applied_seq);
        assert_eq!(replica.time_mark_bucket, primary.time_mark_bucket);
        assert_eq!(replica.index.next_slot(), primary.index.next_slot());
        for s in 0..primary.index.next_slot() {
            assert_eq!(replica.index.entry(s), primary.index.entry(s), "slot {s}");
        }
        // И побайтово равные файлы индекса.
        primary.flush_snapshot().unwrap();
        replica.flush_snapshot().unwrap();
        let a = std::fs::read(primary_dir.join(snapshot_name(primary.applied_seq))).unwrap();
        let b = std::fs::read(replica_dir.join(snapshot_name(replica.applied_seq))).unwrap();
        assert_eq!(a, b, "снапшоты двух узлов на одном потоке равны (§8.3)");
        primary.shutdown().unwrap();
        replica.shutdown().unwrap();
        remove(&primary_dir);
        remove(&replica_dir);
    }

    #[test]
    fn snapshot_barrier_pairs_files_and_drops_covered_segments() {
        let mut s = open("barrier");
        for o in 0..200u8 {
            s.publish(entry(o % 250, 0, 1000)).unwrap();
        }
        let seg_before = list_segments(&s.dir).unwrap().len();
        s.flush_snapshot().unwrap();
        let mf = read_manifest(&s.dir).unwrap().expect("MANIFEST обязан быть");
        assert_eq!(mf.snapshot_seq, s.applied_seq);
        assert_eq!(mf.oldest_wal_needed, s.wal.start_seq());
        assert!(s.dir.join(snapshot_name(s.applied_seq)).exists());
        assert!(!s.dir.join(partial_name(s.applied_seq)).exists(), "partial забирается rename'ом");
        let seg_after = list_segments(&s.dir).unwrap().len();
        assert!(seg_after <= seg_before, "сегменты старше oldest_wal_needed удалены");
        let path = s.dir.clone();
        s.shutdown().unwrap();
        let back = ShardStore::open(&path, 0).unwrap();
        assert_eq!(back.len(), 200);
        assert_eq!(back.applied_seq, mf.applied_seq);
        assert_eq!(back.last_snapshot_seq, mf.snapshot_seq);
        remove(&path);
    }

    #[test]
    fn snapshot_trigger_counts_applied_ops_not_live() {
        // §10.3: при TTL-плато живой счётчик стоит, а applied_seq растёт — триггер обязан
        // сработать от дельты applied.
        let mut s = open("trigger");
        assert_eq!(SNAPSHOT_OPS, 50_000);
        s.applied_seq = SNAPSHOT_OPS - 1;
        s.last_snapshot_seq = 0;
        assert!(!s.maybe_snapshot().unwrap());
        s.applied_seq += 1;
        assert!(s.maybe_snapshot().unwrap());
        assert_eq!(s.last_snapshot_seq, SNAPSHOT_OPS, "снимок привязан к applied_seq");
        let path = s.dir.clone();
        s.shutdown().unwrap();
        remove(&path);
    }

    #[test]
    fn foreign_shard_frames_are_refused() {
        let mut s = open("foreign");
        let op = DeleteOp { owner_ed25519: [1u8; 32], shard: 5 };
        let f = WalFrame::new(1, OpKind::Delete, op.body_bytes());
        assert!(matches!(
            s.apply_frame(&f),
            Err(StoreError::ForeignShard { want: 0, found: 5, .. })
        ));
        let mut ins = entry(2, 0, 10);
        // Кластер 20 относится к шарду 1 (20 / CLUSTERS_PER_SHARD), а индекс — шарду 0 (§7.4).
        ins.cluster_id = 20;
        let body = ins.to_insert().body_bytes();
        let f2 = WalFrame::new(2, OpKind::Insert, body);
        // Insert в чужой кластер отказывает через индекс (§7.4), applied_seq не сдвинут.
        assert!(s.apply_frame(&f2).is_err(), "чужой кластер принят");
        assert_eq!(s.applied_seq, 0);
        let path = s.dir.clone();
        drop(s);
        remove(&path);
    }

    #[test]
    fn oversized_frame_body_is_refused_before_write() {
        let mut s = open("oversized");
        let f = WalFrame::new(0, OpKind::Insert, vec![0u8; MAX_BODY_LEN + 1]);
        assert!(s.stage(f).is_err());
        assert_eq!(s.next_seq, 1, "seq не израсходован при отказе записи");
        let path = s.dir.clone();
        drop(s);
        remove(&path);
    }
}
