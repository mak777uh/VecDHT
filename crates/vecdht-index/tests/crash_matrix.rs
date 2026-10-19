//! Crash-матрица §10.5 — десять точек плюс property-тест `recover(disk) == replay(all ops)`
//! (§19.1).
//!
//! «Убить процесс» здесь означает буквально то, что написано в спеке: *дальнейшее выполнение
//! прекращается, состояние на диске перечитывается с нуля*. Точка падения включается через
//! внедряемый хук `Fault` (§10.5, абзац про crate `fail`), после чего `ShardStore` выбрасывается,
//! а каталог открывается вторым экземпляром — общего состояния между «до» и «после» нет.

use std::fs::File;
use std::path::{Path, PathBuf};

use vecdht_index::entry::IndexEntry;
use vecdht_index::ivf::IvfIndex;
use vecdht_index::manifest::{
    read_manifest, read_max_epoch, write_manifest, ManifestError, StoreManifest, MF_NAME,
    MF_PARTIAL_NAME,
};
use vecdht_index::snapshot::{
    partial_name, read_snapshot, snapshot_name, write_snapshot, SnapshotError, SnapshotMeta,
};
use vecdht_index::store::{Applied, ShardStore, StoreError};
use vecdht_index::wal::{list_segments, read_segment, Fault, WalFrame, WalWriter};
use vecdht_index::testing::{dir, remove, Rng};
use vecdht_wire::codec::DIM;
use vecdht_wire::messages::{OpKind, ReplicateOp};

// --- общий каркас -----------------------------------------------------------

fn owner_of(id: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[..8].copy_from_slice(&id.to_le_bytes());
    o
}

/// Запись шарда 0: `cluster = id % 16` ⇒ все кластеры принадлежат этому шарду (§7.4).
fn entry(id: u64, published: u32, ttl: u16) -> IndexEntry {
    IndexEntry {
        owner_ed25519: owner_of(id),
        vec_q: [(id.rem_euclid(7)) as i8; DIM],
        cluster_id: (id % 16) as u16,
        published_bucket: published,
        ttl_buckets: ttl,
    }
}

fn ttl_of(id: u64) -> u16 {
    if id % 3 == 0 {
        15
    } else {
        400
    }
}

fn create(tag: &str) -> (PathBuf, ShardStore) {
    let d = dir(tag);
    let s = ShardStore::create(&d, 0, 1).unwrap();
    (d, s)
}

/// Живое состояние индекса: `(slot, байты записи)` по возрастанию slot'а. Это то же самое
/// множество, из которого стримится снапшот (§10.4), поэтому равенство по нему означает
/// равенство файлов.
fn live_state(index: &IvfIndex) -> Vec<(u32, Vec<u8>)> {
    index.live_slots().map(|(s, e)| (s, e.to_bytes())).collect()
}

/// Снапшот в байты — чтобы сравнивать два индекса побайтово, а не «по полям».
fn snapshot_bytes(tag: &str, index: &IvfIndex, seq: u64, tb: u32, epoch: u64) -> Vec<u8> {
    let d = dir(tag);
    let path = d.join(snapshot_name(seq));
    let mut f = File::create(&path).unwrap();
    let meta = SnapshotMeta {
        snapshot_seq: seq,
        next_slot: index.next_slot() as u64,
        time_mark_bucket: tb,
        max_epoch_served: epoch,
        shard: index.shard,
    };
    write_snapshot(&mut f, meta, index).unwrap();
    drop(f);
    let bytes = std::fs::read(&path).unwrap();
    remove(&d);
    bytes
}

/// Инвариант точки 7: для MANIFEST, который реально лежит на диске, каждый фрейм с
/// `seq > applied_seq` обязан читаться из сегментов, которые MANIFEST считает нужными. Дыра —
/// это молча потерянные опсы; именно её запрещает порядок «шаг 5, потом шаг 6» (§10.4).
fn missing_ops(d: &Path) -> Vec<u64> {
    let mf = read_manifest(d).unwrap();
    let (applied, from) = match mf {
        Some(m) => (m.applied_seq, m.oldest_wal_needed),
        None => (0, 0),
    };
    let mut present: Vec<u64> = Vec::new();
    for (start, path) in list_segments(d).unwrap() {
        if start < from {
            continue;
        }
        let seg = read_segment(&path).unwrap();
        present.extend(seg.seqs());
    }
    present.sort_unstable();
    let max = present.last().copied().unwrap_or(applied);
    (applied + 1..=max).filter(|s| !present.contains(s)).collect()
}

// --- точка 1: середина append -----------------------------------------------

#[test]
fn point_01_torn_append_is_rejected_and_the_tail_is_cut() {
    let (d, mut s) = create("p1");
    for i in 0..5 {
        s.publish(entry(i, 100, 60)).unwrap();
    }
    assert_eq!(s.applied_seq, 5);

    s.fault = Some(Fault::AppendMid);
    let err = s.publish(entry(5, 100, 60)).unwrap_err();
    let detail = match &err {
        StoreError::WalFailed(detail) => detail.clone(),
        other => panic!("ожидался WAL_FAILED, получено {other:?}"),
    };
    assert!(detail.contains("mid-append"), "{detail}");
    // Память не тронута, seq не израсходован (§10.1).
    assert_eq!(s.index.live, 5);
    assert_eq!(s.index.next_slot(), 5);
    assert_eq!(s.next_seq, 6);
    drop(s);

    // Полфрейма остались на диске: они отбракованы, предыдущие — целы.
    let s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.replayed(), 5);
    assert!(s.tail_corruption.is_some(), "хвост обязан быть замечен");
    assert_eq!(s.index.live, 5);
    assert_eq!(s.applied_seq, 5);
    assert_eq!(missing_ops(&d), Vec::<u64>::new());
    drop(s);

    // Обрывок срезан при восстановлении: иначе следующий append лёг бы за битым фреймом,
    // а читатель останавливается на первом битом (§10.5, точка 1).
    let seg = read_segment(&d.join(vecdht_index::wal::segment_name(1))).unwrap();
    assert!(seg.stopped.is_none(), "{:?}", seg.stopped);
    assert_eq!(seg.seqs(), vec![1, 2, 3, 4, 5]);

    let mut s = ShardStore::open(&d, 0).unwrap();
    s.publish(entry(5, 100, 60)).unwrap();
    assert_eq!(s.index.live, 6);
    assert_eq!(s.applied_seq, 6);
    remove(&d);
}

// --- точка 2: после fsync, до применения в память ---------------------------

#[test]
fn point_02_crash_after_fsync_applies_the_op_exactly_once() {
    let (d, mut s) = create("p2");
    s.publish(entry(0, 10, 60)).unwrap();
    let second = entry(1, 10, 60);
    s.fault = Some(Fault::AfterWalFsync);
    let err = s.publish(second).unwrap_err();
    assert!(matches!(err, StoreError::WalFailed(_)), "{err:?}");
    // Байты durable, память чистая, staged не выброшен.
    assert_eq!(s.index.live, 1);
    assert_eq!(s.staged_len(), 1);
    drop(s);

    let mut s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.replayed(), 2, "оба фрейма durable ⇒ оба догнаны реплеем");
    assert_eq!(s.index.live, 2);
    assert_eq!(s.applied_seq, 2);

    // Дублей нет: тот же seq повторно — Duplicate, состояние не меняется.
    let again = WalFrame::new(2, OpKind::Insert, second.to_insert().body_bytes());
    assert_eq!(s.apply_frame(&again).unwrap(), Applied::Duplicate);
    assert_eq!(s.index.live, 2);
    assert_eq!(s.index.owner_slot(&second.owner_ed25519), Some(1));
    remove(&d);
}

// --- точка 3: середина записи snap.partial ----------------------------------

#[test]
fn point_03_partial_snapshot_is_ignored_by_recovery() {
    let (d, mut s) = create("p3");
    for i in 0..4 {
        s.publish(entry(i, 10, 60)).unwrap();
    }
    s.flush_snapshot().unwrap();
    let mf = read_manifest(&d).unwrap().unwrap();
    assert_eq!(mf.snapshot_seq, 4);
    for i in 4..8 {
        s.publish(entry(i, 10, 60)).unwrap();
    }

    s.fault = Some(Fault::SnapshotMid);
    let err = s.flush_snapshot().unwrap_err();
    assert!(
        matches!(err, StoreError::Snapshot(SnapshotError::Io(_))),
        "{err:?}"
    );
    assert!(d.join(partial_name(8)).exists(), "partial остался на диске");
    assert!(!d.join(snapshot_name(8)).exists(), "rename не делался");
    drop(s);

    // MANIFEST ведёт старый снапшот, partial для восстановления не существует (§10.4).
    let s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.last_snapshot_seq, 4);
    assert_eq!(s.index.live, 8);
    assert_eq!(s.replayed(), 4, "хвост 5..8 доигран поверх снапшота 4");
    assert_eq!(s.applied_seq, 8);
    assert!(s.tail_corruption.is_none());
    let loaded = read_snapshot(&d.join(snapshot_name(4))).unwrap();
    assert_eq!(loaded.index.live, 4);
    remove(&d);
}

// --- точка 4: снапшот fsync'нут, MANIFEST ещё старый -----------------------

#[test]
fn point_04_fresh_snapshot_without_manifest_update_is_still_the_old_pair() {
    let (d, mut s) = create("p4");
    for i in 0..4 {
        s.publish(entry(i, 10, 60)).unwrap();
    }
    s.flush_snapshot().unwrap(); // snap.4 + MANIFEST(snapshot_seq = 4)
    for i in 4..7 {
        s.publish(entry(i, 10, 60)).unwrap();
    }

    // Шаги 1–3 барьера сделаны и durable, шага 5 (MANIFEST) — нет.
    let mut f = File::create(d.join(snapshot_name(7))).unwrap();
    let meta = SnapshotMeta {
        snapshot_seq: 7,
        next_slot: s.index.next_slot() as u64,
        time_mark_bucket: s.time_mark_bucket,
        max_epoch_served: s.max_epoch_served,
        shard: 0,
    };
    write_snapshot(&mut f, meta, &s.index).unwrap();
    f.sync_all().unwrap();
    drop(f);
    drop(s);

    let s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.last_snapshot_seq, 4, "источник истины — MANIFEST, а не самый новый файл");
    assert_eq!(s.index.live, 7, "старый снапшот + весь хвост корректны, просто медленнее");
    assert_eq!(s.replayed(), 3);
    assert_eq!(s.applied_seq, 7);
    // Результат «догоняния» побайтово равен снапшоту, который успел записать оборванный барьер.
    let written_by_barrier = std::fs::read(d.join(snapshot_name(7))).unwrap();
    assert_eq!(
        snapshot_bytes("p4-cmp", &s.index, 7, s.time_mark_bucket, s.max_epoch_served),
        written_by_barrier
    );
    remove(&d);
}

// --- точка 5: середина rename MANIFEST --------------------------------------

#[test]
fn point_05_manifest_rename_mid_keeps_one_complete_version() {
    let (d, mut s) = create("p5");
    for i in 0..3 {
        s.publish(entry(i, 10, 60)).unwrap();
    }
    s.flush_snapshot().unwrap();
    let before = std::fs::read(d.join(MF_NAME)).unwrap();
    assert!(std::fs::read(d.join(MF_PARTIAL_NAME)).is_err());

    for i in 3..6 {
        s.publish(entry(i, 10, 60)).unwrap();
    }
    s.fault = Some(Fault::ManifestRenameMid);
    let err = s.flush_snapshot().unwrap_err();
    assert!(matches!(err, StoreError::Manifest(ManifestError::Injected(_))), "{err:?}");
    // Rename атомичен: на диске — прежняя полная версия, рядом только partial.
    assert_eq!(std::fs::read(d.join(MF_NAME)).unwrap(), before);
    assert!(d.join(MF_PARTIAL_NAME).exists());
    assert!(d.join(snapshot_name(6)).exists(), "шаг 3 был сделан до отказа на шаге 5");
    assert_eq!(missing_ops(&d), Vec::<u64>::new());
    drop(s);

    let s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.last_snapshot_seq, 3);
    assert_eq!(s.index.live, 6);
    assert_eq!(s.replayed(), 3);
    assert_eq!(s.applied_seq, 6);
    remove(&d);
}

// --- точка 6: MANIFEST записан, каталог не fsync'нут ------------------------

#[test]
fn point_06_absent_manifest_is_safe_because_the_wal_was_not_pruned() {
    // Первый барьер оборван на шаге 5 ⇒ MANIFEST вообще не появляется, а удаление сегментов
    // (шаг 6) идёт после него ⇒ журнал цел. Восстановление читает всё с нуля: корректно,
    // медленнее (§10.5, точка 6; платформа без fsync каталога — §10.4, шаг 4).
    let (d, mut s) = create("p6a");
    for i in 0..6 {
        s.publish(entry(i, 10, 60)).unwrap();
    }
    s.fault = Some(Fault::ManifestRenameMid);
    assert!(s.flush_snapshot().is_err());
    assert!(read_manifest(&d).unwrap().is_none());
    assert_eq!(list_segments(&d).unwrap().len(), 1, "сегменты не удалялись");
    drop(s);

    let mut s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.index.live, 6);
    assert_eq!(s.replayed(), 6);
    assert_eq!(s.applied_seq, 6);
    // И дальше живой: publish продолжается с того же seq.
    s.publish(entry(6, 10, 60)).unwrap();
    assert_eq!(s.applied_seq, 7);
    drop(s);

    // Второй случай той же точки: MANIFEST переписан, шаг 6 не сделан — лишние сегменты на
    // диске не должны приводить ни к дублям, ни к дописке в перекрытый снапшотом файл.
    let (d2, mut s2) = create("p6b");
    for i in 0..6 {
        s2.publish(entry(i, 10, 60)).unwrap();
    }
    let meta = SnapshotMeta {
        snapshot_seq: 6,
        next_slot: s2.index.next_slot() as u64,
        time_mark_bucket: s2.time_mark_bucket,
        max_epoch_served: s2.max_epoch_served,
        shard: 0,
    };
    let mut f = File::create(d2.join(snapshot_name(6))).unwrap();
    write_snapshot(&mut f, meta, &s2.index).unwrap();
    f.sync_all().unwrap();
    drop(f);
    let mf = StoreManifest {
        shard: 0,
        snapshot_seq: 6,
        oldest_wal_needed: 7,
        applied_seq: 6,
        next_slot: 6,
        time_mark_bucket: s2.time_mark_bucket,
    };
    write_manifest(&d2, &mf, None).unwrap();
    drop(s2);
    assert_eq!(list_segments(&d2).unwrap().len(), 1, "шаг 6 не сделан");

    let mut s3 = ShardStore::open(&d2, 0).unwrap();
    assert_eq!(s3.index.live, 6);
    assert_eq!(s3.replayed(), 0, "перекрытые снапшотом фреймы отсечены по seq");
    assert_eq!(s3.wal.start_seq(), 7, "в старый сегмент дописывать нельзя — он уже не нужен");
    s3.publish(entry(6, 10, 60)).unwrap();
    assert_eq!(s3.applied_seq, 7);
    assert_eq!(s3.index.live, 7);
    remove(&d);
    remove(&d2);
}

// --- точка 7: удаление сегмента до MANIFEST запрещено порядком --------------

#[test]
fn point_07_segments_are_pruned_only_after_the_manifest_is_written() {
    let (d, mut s) = create("p7");
    for i in 0..3 {
        s.publish(entry(i, 10, 60)).unwrap();
    }
    s.flush_snapshot().unwrap(); // MANIFEST: snapshot_seq=3, oldest_wal_needed=1
    // Ротация: опсы 4..9 уходят в новый сегмент, старый всё ещё нужен MANIFEST'у.
    s.wal.rotate(4).unwrap();
    for i in 3..6 {
        s.publish(entry(i, 10, 60)).unwrap();
    }
    s.wal.rotate(7).unwrap();
    for i in 6..9 {
        s.publish(entry(i, 10, 60)).unwrap();
    }

    // «Запрещённый» порядок — сначала шаг 6, потом шаг 5. Потерянные опсы 4..6 ничем не
    // закрыты: MANIFEST на диске ссылается на снапшот 3, а сегмент с 4..6 уже удалён.
    let deleted = WalWriter::delete_older_than(&d, 7).unwrap();
    assert!(!deleted.is_empty());
    assert_eq!(missing_ops(&d), vec![4, 5, 6], "проверка должна иметь зубы");
    drop(s);

    // Тот же сценарий честным барьером: MANIFEST переписывается до удаления, и при отказе на
    // шаге 5 удаление вообще не происходит (§10.4).
    let (d2, mut s2) = create("p7b");
    for i in 0..3 {
        s2.publish(entry(i, 10, 60)).unwrap();
    }
    s2.flush_snapshot().unwrap();
    s2.wal.rotate(4).unwrap();
    for i in 3..6 {
        s2.publish(entry(i, 10, 60)).unwrap();
    }
    s2.fault = Some(Fault::ManifestRenameMid);
    assert!(s2.flush_snapshot().is_err(), "шаг 5 не прошёл");
    assert_eq!(list_segments(&d2).unwrap().len(), 2, "шаг 6 не имел права начаться");
    assert_eq!(missing_ops(&d2), Vec::<u64>::new());
    drop(s2);
    let s2 = ShardStore::open(&d2, 0).unwrap();
    assert_eq!(s2.index.live, 6);
    assert_eq!(s2.applied_seq, 6);

    // Успешный барьер: MANIFEST и удаление согласованы, хвост цел.
    let (d3, mut s3) = create("p7c");
    for i in 0..3 {
        s3.publish(entry(i, 10, 60)).unwrap();
    }
    s3.flush_snapshot().unwrap();
    s3.wal.rotate(4).unwrap();
    for i in 3..6 {
        s3.publish(entry(i, 10, 60)).unwrap();
    }
    s3.flush_snapshot().unwrap();
    let mf = read_manifest(&d3).unwrap().unwrap();
    assert_eq!(mf.snapshot_seq, 6);
    assert_eq!(mf.oldest_wal_needed, 4);
    let segs = list_segments(&d3).unwrap();
    assert_eq!(segs.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![4]);
    assert_eq!(missing_ops(&d3), Vec::<u64>::new());
    remove(&d);
    remove(&d2);
    remove(&d3);
}

// --- точка 8: GcTick одновременно с вставкой --------------------------------

#[test]
fn point_08_gc_tick_and_inserts_apply_in_seq_order_with_stable_slots() {
    let (d, mut s) = create("p8");
    // 0..3 — короткий TTL, 3..6 — длинный; все шесть становятся живыми.
    for i in 0..6 {
        let ttl = if i < 3 { 10 } else { 500 };
        s.publish(entry(i, 100, ttl)).unwrap();
    }
    let slots_before: Vec<u32> = (0..6).map(|i| s.index.owner_slot(&owner_of(i)).unwrap()).collect();
    assert_eq!(slots_before, vec![0, 1, 2, 3, 4, 5]);

    // Вставка и GcTick в одном потоке: seq 7 — вставка, 8 — TimeMark, 9 — GcTick.
    s.stage_insert(entry(6, 100, 500)).unwrap();
    s.commit().unwrap();
    s.stage_time_mark(115).unwrap();
    s.commit().unwrap();
    s.stage_gc_tick(115).unwrap();
    s.commit().unwrap();

    assert_eq!(s.time_mark_bucket, 115);
    assert_eq!(s.index.live, 4, "сняты ровно три записи с TTL 10");
    let mut after: Vec<(u32, u64)> = Vec::new();
    for (slot, e) in s.index.live_slots() {
        after.push((slot, u64::from_le_bytes(e.owner_ed25519[..8].try_into().unwrap())));
    }
    assert_eq!(after, vec![(3, 3), (4, 4), (5, 5), (6, 6)], "slot'ы не перенумерованы (§8.3)");
    for i in 3..6 {
        assert_eq!(s.index.owner_slot(&owner_of(i)), Some(slots_before[i as usize]));
    }
    assert_eq!(s.index.cluster_slots(3).to_vec(), vec![3], "список кластера почистился");
    remove(&d);

    // Тот же поток на втором узле ⇒ побайтово равный файл индекса (§8.3).
    let (d2, mut b) = create("p8-replica");
    let (d1, mut a) = create("p8-primary");
    let mut stream: Vec<WalFrame> = Vec::new();
    for i in 0..6 {
        let ttl = if i < 3 { 10 } else { 500 };
        let e = entry(i, 100, ttl);
        a.stage_insert(e).unwrap();
        stream.push(WalFrame::new(i + 1, OpKind::Insert, e.to_insert().body_bytes()));
    }
    a.stage_time_mark(115).unwrap();
    stream.push(WalFrame::new(7, OpKind::TimeMark, vecdht_wire::messages::encode_mark(7, 115)));
    a.stage_gc_tick(115).unwrap();
    stream.push(WalFrame::new(8, OpKind::GcTick, vecdht_wire::messages::encode_mark(8, 115)));
    a.commit().unwrap();
    for f in &stream {
        b.apply_frame(f).unwrap();
    }
    assert_eq!(live_state(&a.index), live_state(&b.index));
    assert_eq!(
        snapshot_bytes("p8-a", &a.index, a.applied_seq, a.time_mark_bucket, a.epoch),
        snapshot_bytes("p8-b", &b.index, a.applied_seq, a.time_mark_bucket, a.epoch)
    );
    remove(&d1);
    remove(&d2);
}

// --- точка 9: ENOSPC в mid-append -------------------------------------------

#[test]
fn point_09_enospc_mid_append_touches_neither_wal_nor_memory() {
    let (d, mut s) = create("p9");
    for i in 0..4 {
        s.publish(entry(i, 10, 60)).unwrap();
    }
    let seq_before = s.next_seq;
    let slot_before = s.index.next_slot();

    s.fault = Some(Fault::EnospcMidAppend);
    let err = s.publish(entry(4, 10, 60)).unwrap_err();
    let detail = match &err {
        StoreError::WalFailed(detail) => detail.clone(),
        other => panic!("ожидался код WAL_FAILED, получено {other:?}"),
    };
    assert!(detail.contains("enospc"), "{detail}");
    assert_eq!(s.index.live, 4, "память не тронута (§10.1, точка 9)");
    assert_eq!(s.index.next_slot(), slot_before);
    assert_eq!(s.next_seq, seq_before);
    assert_eq!(s.staged_len(), 0);
    s.fault = None;
    // Тот же опс после освобождения места проходит по тому же seq.
    s.publish(entry(4, 10, 60)).unwrap();
    assert_eq!(s.next_seq, seq_before + 1);
    assert_eq!(s.applied_seq, seq_before);
    drop(s);

    let s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.index.live, 5);
    assert_eq!(s.applied_seq, 5);
    assert_eq!(missing_ops(&d), Vec::<u64>::new());
    remove(&d);
}

// --- точка 10: restart с откатом эпизоды -------------------------------------

#[test]
fn point_10_restart_cannot_roll_the_epoch_back() {
    let (d, mut s) = create("p10");
    s.grant_epoch(7).unwrap();
    assert_eq!(read_max_epoch(&d).unwrap(), 7, "маркер durable до обслуживания (§9.2)");
    let e = entry(0, 10, 60);
    s.publish(e).unwrap();
    drop(s);

    let mut s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.max_epoch_served, 7);
    // Откат эпизоды невозможен: старшая сохранённая — 7, младшая обслуживается отказом.
    assert!(matches!(
        s.grant_epoch(6),
        Err(StoreError::StaleEpoch { given: 6, saved: 7 })
    ));
    s.epoch = 5;
    let err = s.publish(entry(1, 10, 60)).unwrap_err();
    assert!(matches!(err, StoreError::StaleEpoch { given: 5, saved: 7 }), "{err:?}");
    assert_eq!(s.index.live, 1, "отказ не тронул состояние");
    // Реплика так же отбрасывает фреймы старой эпизоды.
    let op = ReplicateOp {
        shard: 0,
        epoch: 6,
        seq: 2,
        op_kind: OpKind::Insert,
        body: entry(1, 10, 60).to_insert().body_bytes(),
    };
    assert!(matches!(s.apply_replicated(&op), Err(StoreError::StaleEpoch { .. })));

    // epoch == saved — возобновление того же lease, а новая эпизода обязана быть больше.
    s.grant_epoch(7).unwrap();
    s.publish(entry(1, 10, 60)).unwrap();
    assert_eq!(s.index.live, 2);
    s.grant_epoch(8).unwrap();
    drop(s);
    assert_eq!(read_max_epoch(&d).unwrap(), 8);
    let s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.max_epoch_served, 8);
    assert_eq!(s.index.live, 2);
    remove(&d);
}

// --- property: recover(disk) == replay(all ops) -----------------------------

#[derive(Clone, Copy, Debug)]
enum Op {
    Insert(u64),
    Delete(u64),
    Mark(u32),
    Tick(u32),
}

/// Опсы в индекс применяются так же, как в `ShardStore`, но через прямой путь `IvfIndex` —
/// иначе сравнение «диск == поток» проверяло бы само себя.
fn apply_model(model: &mut IvfIndex, tb: &mut u32, op: &Op) {
    match op {
        Op::Insert(id) => {
            model.insert(entry(*id, *tb, ttl_of(*id))).unwrap();
        }
        Op::Delete(id) => {
            model.remove_owner(&owner_of(*id));
        }
        Op::Mark(b) => *tb = (*tb).max(*b),
        Op::Tick(b) => {
            *tb = (*tb).max(*b);
            model.expire(*b);
        }
    }
}

fn apply_store(s: &mut ShardStore, op: &Op) -> Result<(), StoreError> {
    match op {
        Op::Insert(id) => {
            s.stage_insert(entry(*id, s.time_mark_bucket, ttl_of(*id)))?;
        }
        Op::Delete(id) => {
            s.stage_delete(owner_of(*id))?;
        }
        Op::Mark(b) => {
            s.stage_time_mark(*b)?;
        }
        Op::Tick(b) => {
            s.stage_gc_tick(*b)?;
        }
    }
    s.commit()?;
    Ok(())
}

/// Для случайной последовательности опсов и случайной точки падения: состояние, поднятое с
/// диска, равно состоянию, полученному проигрыванием всех durable-опсов (§10.5, property).
#[test]
fn property_recover_disk_equals_replay_all_ops() {
    const N: usize = 90;
    const FAULTS: [Option<Fault>; 6] = [
        None,
        Some(Fault::AppendMid),
        Some(Fault::AfterWalFsync),
        Some(Fault::SnapshotMid),
        Some(Fault::ManifestRenameMid),
        Some(Fault::EnospcMidAppend),
    ];

    // Каждый сид выбирает класс падения по `seed % FAULTS.len()`, поэтому число сидов кратно
    // числу классов. Полный набор — 36 (по 6 на класс); в debug 36 × 90 опсов с fsync дают
    // ~135 с на одном ядре, что превращает `cargo test` в стендап, поэтому debug берёт 12
    // (по 2 на класс), а 36 идут в release-прогоне. Покрытие от этого не меняется по классам.
    const SEEDS: u64 = if cfg!(debug_assertions) { 12 } else { 36 };

    for seed in 0..SEEDS {
        let mut r = Rng::new(seed + 1);
        let fault = FAULTS[(seed % FAULTS.len() as u64) as usize];
        let crash_at = r.below(N as u64) as usize;
        let flush_at = r.below(N as u64) as usize;

        // Поток опсов: вставки по пулу из 40 владельцев (перепубликации дают дедупликацию),
        // удаления, метки времени и GC-тики.
        let mut ops = Vec::with_capacity(N);
        let mut bucket = 1_000u32;
        for _ in 0..N {
            let pick = r.below(10);
            let owner = r.below(40);
            ops.push(match pick {
                0..=5 => Op::Insert(owner),
                6 => Op::Delete(owner),
                7 => Op::Mark(bucket),
                8..=9 => {
                    bucket += 4 + r.below(6) as u32;
                    Op::Tick(bucket)
                }
                _ => unreachable!(),
            });
        }

        let d = dir("prop");
        let mut store = ShardStore::create(&d, 0, 1).unwrap();
        let mut model = IvfIndex::new(0);
        let mut tb = 0u32;
        let mut durable = N; //exclusive bound of ops that reached the disk

        for (i, op) in ops.iter().enumerate() {
            // Хук включается ровно на одной точке: «падение» не может случиться на каждом опсе.
            store.fault = if fault.is_some() && i == crash_at { fault } else { None };
            if store.fault.is_none() {
                apply_store(&mut store, op).unwrap();
                apply_model(&mut model, &mut tb, op);
                if i == flush_at {
                    store.flush_snapshot().unwrap();
                }
                continue;
            }
            // Точка падения: опс, на котором она включена, ведёт себя по-разному для разных
            // строк матрицы — ровно это и нужно проверить.
            match fault {
                Some(Fault::AppendMid) | Some(Fault::EnospcMidAppend) => {
                    // Фрейм не дописан ⇒ опса нет ни в памяти, ни на диске (точки 1, 9).
                    assert!(apply_store(&mut store, op).is_err(), "seed {seed}");
                    durable = i;
                }
                Some(Fault::AfterWalFsync) => {
                    // Байты durable, применение не состоялось (точка 2) — recovery доиграет.
                    assert!(apply_store(&mut store, op).is_err(), "seed {seed}");
                    apply_model(&mut model, &mut tb, op);
                    durable = i + 1;
                }
                Some(Fault::SnapshotMid) | Some(Fault::ManifestRenameMid) => {
                    // Опс применён, а барьер оборван (точки 3–5): старый MANIFEST + хвост.
                    apply_store(&mut store, op).unwrap();
                    apply_model(&mut model, &mut tb, op);
                    durable = i + 1;
                    assert!(store.flush_snapshot().is_err(), "seed {seed}: барьер прошёл целиком");
                }
                _ => unreachable!("StaleEpochRestart — не write-fault, точка 10"),
            }
            break;
        }
        store.fault = None;
        let tb_at_crash = tb;
        drop(store);

        // --- перечитываем диск с нуля
        let mut recovered = ShardStore::open(&d, 0).unwrap();
        assert_eq!(recovered.time_mark_bucket, tb_at_crash, "seed {seed}");
        assert_eq!(live_state(&recovered.index), live_state(&model), "seed {seed}");
        assert_eq!(recovered.index.next_slot(), model.next_slot(), "seed {seed}");
        assert_eq!(recovered.applied_seq, durable as u64, "seed {seed}");
        assert_eq!(missing_ops(&d), Vec::<u64>::new(), "seed {seed}");
        assert_eq!(
            snapshot_bytes("prop-recovered", &recovered.index, durable as u64, tb_at_crash, 1),
            snapshot_bytes("prop-model", &model, durable as u64, tb_at_crash, 1),
            "seed {seed}: файлы индекса обязаны совпадать побайтово"
        );

        // Recovery — не «музейный» снимок: следующий опс продолжается с тем же slot'ом и
        // дедупликацией, и модель за ним идёт так же.
        let next_owner = 41 + seed;
        recovered
            .stage_insert(entry(next_owner, recovered.time_mark_bucket, 300))
            .unwrap();
        recovered.commit().unwrap();
        model.insert(entry(next_owner, tb_at_crash, 300)).unwrap();
        assert_eq!(live_state(&recovered.index), live_state(&model), "seed {seed}");

        remove(&d);
    }
}
