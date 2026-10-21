//! `E-0019` — цена инкрементального корня шарда (`H-0018`).
//!
//! Стенд, а не гейт: тест `#[ignore]` и запускается вручную, потому что меряет время на реальном
//! диске. Пороги и справочные колонки зафиксированы в
//! `lab/experiments/E-0019-shard-root-cost.md` **до** прогона; здесь они повторены цифрами в
//! assert'ах, чтобы правка порога не могла незаметно стать правкой результата.
//!
//! Запуск: `RAYON_NUM_THREADS=1 cargo test --release -p vecdht-index root_cost -- --ignored
//! --nocapture` (одна нить — параллелизм искажает fsync). Число опов: `VEC_DHT_ROOT_N`,
//! по умолчанию 100 000 (порог (1) сформулирован для индекса ≥ 100 000 записей).
//!
//! Что именно измеряется:
//!
//! * baseline полной стоимости `publish` (stage + commit, один fsync на op) на уже тёплом индексе;
//! * baseline батч-стоимости (1000 опов на один fsync) — это «чистая CPU-часть op без fsync», и
//!   именно она решает вопрос при пакетной записи 100 admits/с (§11.3);
//! * `ChainRoot::update` (с аллокацией payload) и `ChainRoot::update_parts` (без неё) на тех же
//!   байтах, которые легли на диск (фреймы читаются из WAL, а не сочиняются);
//! * байты: 32 Б корня в снапшоте + 32 Б в MANIFEST против размера снапшота;
//! * сходимость: три корня над одним логом и корень, набранный при применении опов вторым store;
//! * податливость: подменённый body при том же `seq` меняет корень;
//! * справочно — `OpTree` (дерево Меркела над опами): op-cost, хеш-обновлений на op, байты
//!   хранения, размер доказательства, цена проверки и цена удаления (пересборка).

use std::path::{Path, PathBuf};
use std::time::Instant;

use vecdht_index::entry::IndexEntry;
use vecdht_index::root::{op_payload, ChainRoot, OpTree, ROOT_BYTES};
use vecdht_index::snapshot::{snapshot_name, write_snapshot, SnapshotMeta};
use vecdht_index::store::ShardStore;
use vecdht_index::testing::{dir, remove};
use vecdht_index::wal::{list_segments, read_segment, WalFrame};
use vecdht_wire::codec::DIM;

/// Записи того же вида, что в crash-матрице: `cluster = id % 16` ⇒ кластеры принадлежат шарду 0.
fn entry(id: u64) -> IndexEntry {
    let mut owner = [0u8; 32];
    owner[..8].copy_from_slice(&id.to_le_bytes());
    IndexEntry {
        owner_ed25519: owner,
        vec_q: [(id.rem_euclid(7)) as i8; DIM],
        cluster_id: (id % 16) as u16,
        published_bucket: 1_000,
        ttl_buckets: 54_000,
    }
}

fn n_from_env() -> usize {
    std::env::var("VEC_DHT_ROOT_N")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v >= 1_000)
        .unwrap_or(100_000)
}

/// Все фреймы шарда с диска, по возрастанию seq — ровно то, что обязан воспроизвести реплика.
fn log_from_disk(d: &Path) -> Vec<WalFrame> {
    let mut out = Vec::new();
    for (_start, path) in list_segments(d).unwrap() {
        out.extend(read_segment(&path).unwrap().frames);
    }
    out.sort_by_key(|f| f.seq);
    out
}

/// Написать снапшот индекса в файл и вернуть его размер в байтах.
fn snapshot_bytes(store: &ShardStore, tag: &str) -> (PathBuf, u64) {
    let d = dir(tag);
    let path = d.join(snapshot_name(store.applied_seq));
    let mut f = std::fs::File::create(&path).unwrap();
    let meta = SnapshotMeta {
        snapshot_seq: store.applied_seq,
        next_slot: store.index.next_slot() as u64,
        time_mark_bucket: store.time_mark_bucket,
        max_epoch_served: store.max_epoch_served,
        shard: store.shard,
    };
    write_snapshot(&mut f, meta, &store.index).unwrap();
    drop(f);
    let len = std::fs::metadata(&path).unwrap().len();
    (path, len)
}

#[test]
#[ignore = "E-0019: замер на реальном диске, RAYON_NUM_THREADS=1"]
fn root_cost_measured_on_real_store() {
    let n = n_from_env();
    let batch = 1_000usize;
    println!("E-0019: n = {n} опов, батч = {batch}, рут-проходов = 16");

    // --- 1. Батч-запись: греет индекс и даёт «CPU-часть op без fsync» -------------
    let d1 = dir("e0019_primary");
    let mut s = ShardStore::create(&d1, 0, 1).unwrap();
    let t0 = Instant::now();
    for i in 0..n as u64 {
        s.stage_insert(entry(i)).unwrap();
        if s.staged_len() >= batch {
            s.commit().unwrap();
        }
    }
    s.commit().unwrap();
    let batched_ns = t0.elapsed().as_nanos() as f64 / n as f64;
    println!(
        "батч-путь ({batch} опов на fsync): {batched_ns:.0} нс/op, индекс = {} записей",
        s.len()
    );
    assert!(s.len() >= n, "индекс обязан содержать все {n} записей");

    // --- 2. Полный publish (один fsync на op) на тёплом индексе ------------------
    let m = n / 10; // 10 % опов с fsync достаточно для оценки; индекс уже ≥ n записей
    let t1 = Instant::now();
    for i in n as u64..(n + m) as u64 {
        s.publish(entry(i)).unwrap();
        if (i as usize + 1) % (m / 10).max(1) == 0 {
            println!("  publish: {} из {m}", i as usize + 1 - n);
        }
    }
    let full_ns = t1.elapsed().as_nanos() as f64 / m as f64;
    println!(
        "publish (stage + commit с одним fsync) на индексе {} записей: {full_ns:.0} нс/op ({m} опов)",
        s.len()
    );

    // --- 3. Корень над байтами, легшими на диск ----------------------------------
    let frames = log_from_disk(&d1);
    let ops = frames.len();
    assert_eq!(ops, n + m, "WAL обязан содержать все опов");
    let body_bytes: usize = frames.iter().map(|f| f.body.len()).sum();
    println!(
        "лог: {ops} фреймов, payload в среднем {:.0} Б/op",
        body_bytes as f64 / ops as f64
    );

    let mut alloc_best = f64::MAX;
    let mut stream_best = f64::MAX;
    let mut root = ChainRoot::genesis(0);
    for pass in 0..16 {
        let a = Instant::now();
        let mut r = ChainRoot::genesis(0);
        for f in &frames {
            r.update(f);
        }
        alloc_best = alloc_best.min(a.elapsed().as_nanos() as f64 / ops as f64);

        let b = Instant::now();
        let mut r2 = ChainRoot::genesis(0);
        for f in &frames {
            r2.update_parts(f.seq, f.kind as u8, &f.body);
        }
        stream_best = stream_best.min(b.elapsed().as_nanos() as f64 / ops as f64);
        assert_eq!(r.value(), r2.value(), "pass {pass}: update_parts разошёлся с update");
        root = r;
    }
    let share_full = 100.0 * alloc_best / full_ns;
    let share_batched = 100.0 * stream_best / batched_ns;
    println!(
        "цепочка blake3: {alloc_best:.0} нс/op (с аллокацией payload), {stream_best:.0} нс/op (без) — \
         доля от publish с fsync {share_full:.3} %, доля от батч-операции {share_batched:.3} %"
    );
    assert_eq!(root.ops() as usize, ops);

    // --- 4. Байты: корень против размера снапшота --------------------------------
    let (snap_path, snap_len) = snapshot_bytes(&s, "e0019_snap");
    let root_overhead = (2 * ROOT_BYTES + 8) as f64; // 32 Б в снапшоте + 32 Б в MANIFEST + счётчик опов
    let share_snap = 100.0 * root_overhead / snap_len as f64;
    println!(
        "снапшот {} записей = {snap_len} Б; корень добавляет {root_overhead:.0} Б = {share_snap:.5} %",
        s.len()
    );

    // --- 5. Сходимость трёх реплик -------------------------------------------------
    let mut roots = Vec::new();
    for _ in 0..3 {
        let mut r = ChainRoot::genesis(0);
        for f in &frames {
            r.update(f);
        }
        roots.push(r);
    }
    assert_eq!(roots[0].value(), roots[1].value());
    assert_eq!(roots[1].value(), roots[2].value());
    // Тот же лог, применённый вторым store (путь реплики §9.7), обязан дать тот же корень.
    let d2 = dir("e0019_replica");
    let mut rep = ShardStore::create(&d2, 0, 1).unwrap();
    let ta = Instant::now();
    for f in &frames {
        rep.apply_frame(f).unwrap();
    }
    let apply_ns = ta.elapsed().as_nanos() as f64 / ops as f64;
    let mut rep_root = ChainRoot::genesis(0);
    for f in &frames {
        rep_root.update(f);
    }
    let share_apply = 100.0 * alloc_best / apply_ns;
    println!(
        "чистая CPU-часть op (apply_frame без WAL и fsync): {apply_ns:.0} нс/op; доля цепи в ней = \
         {share_apply:.2} %"
    );
    assert_eq!(rep.applied_seq, ops as u64);
    assert_eq!(rep_root.value(), roots[0].value(), "корень реплики не сошёлся с primary");
    // Другой шард — другой корень на том же логе (иначе сверка ничего не стоит).
    let mut other_shard = ChainRoot::genesis(1);
    for f in &frames {
        other_shard.update(f);
    }
    assert_ne!(other_shard.value(), roots[0].value());
    println!("сходимость: 3 корня над одним логом побитово равны, реплика через apply_frame — тоже");

    // --- 6. Подменный body при том же seq -----------------------------------------
    let mut tampered = frames.clone();
    let k = tampered.len() / 2;
    let before = tampered[k].body[0];
    tampered[k].body[0] = before ^ 0xFF;
    let mut t = ChainRoot::genesis(0);
    for f in &tampered {
        t.update(f);
    }
    assert_ne!(t.value(), roots[0].value(), "подменённый body не изменил корень");
    // Тот же трюк на Delete (другая длина тела) и перестановка двух соседних опов.
    let mut swapped = frames.clone();
    swapped.swap(k, k + 1);
    let mut sw = ChainRoot::genesis(0);
    for f in &swapped {
        sw.update(f);
    }
    assert_ne!(sw.value(), roots[0].value(), "переставленные опсы не изменили корень");
    println!("податливость: один изменённый байт и одна перестановка меняют корень");

    // --- 7. Пороги H-0018 ----------------------------------------------------------
    assert!(
        share_full <= 1.0,
        "фальсификатор `H-0018` (1): цепочка стоит {share_full:.3} % полной стоимости publish (> 1 %)"
    );
    assert!(
        share_snap <= 2.0,
        "фальсификатор `H-0018` (2): байты корня — {share_snap:.5} % снапшота (> 2 %)"
    );

    // --- 8. Справочно: цена дерева Меркела -----------------------------------------
    let mut tree = OpTree::with_capacity(0, ops);
    let tt = Instant::now();
    for f in &frames {
        tree.push(&op_payload(f.seq, f.kind, &f.body));
    }
    let tree_ns = tt.elapsed().as_nanos() as f64 / ops as f64;
    let h = tree.height();
    let proof = tree.proof(0);
    let one = proof.len() * ROOT_BYTES;
    let target = tree.root();
    let pv = Instant::now();
    for i in 0..10 {
        let pos = (i * (ops / 10).max(1)).min(ops - 1);
        let pl = op_payload(frames[pos].seq, frames[pos].kind, &frames[pos].body);
        let p = tree.proof(pos);
        assert!(OpTree::verify(&target, &pl, pos, &p), "позиция {pos} не проходит проверку");
    }
    let verify_ns = pv.elapsed().as_nanos() as f64 / 10.0;
    // Удаление в дереве над опами = пересборка: дерево фиксированной высоты, дыру нельзя
    // «сдвинуть», не переписав путь до корня для всех последующих листьев.
    let rb = Instant::now();
    let mut rebuild = OpTree::with_capacity(0, ops);
    for (i, f) in frames.iter().enumerate() {
        if i == k {
            continue;
        }
        rebuild.push(&op_payload(f.seq, f.kind, &f.body));
    }
    let rebuild_ms = rb.elapsed().as_millis() as f64;
    println!(
        "дерево Меркела (height {h}): {tree_ns:.0} нс/op, хеш-обновлений на op = {h}, \
         хранение {} Б (использовано {} Б) = {:.1}× снапшота, доказательство 1/op = {one} Б, \
         топ-10 = {} Б, проверка 10 доказательств = {verify_ns:.0} нс, \
         удаление одного опа (пересборка) = {rebuild_ms:.0} мс",
        tree.node_bytes(),
        tree.node_bytes_used(),
        tree.node_bytes_used() as f64 / snap_len as f64,
        10 * one
    );
    println!(
        "хеш-обновлений на пакет 100 admits/с: цепочка = 100, дерево = {} ({} нс против {:.0} нс)",
        100 * h,
        100 * h,
        100.0 * tree_ns
    );
    println!(
        "ИТОГ E-0019: доля цепи в publish (fsync/op) = {share_full:.3} % (порог ≤ 1 %), доля в \
         батч-op (1 fsync на {batch}) = {share_batched:.3} %, доля в чистой CPU-части op = \
         {share_apply:.2} % (справочно), байты корня = {share_snap:.5} % снапшота (порог ≤ 2 %)"
    );

    remove(&d1);
    remove(&d2);
    remove(snap_path.parent().unwrap());
}
