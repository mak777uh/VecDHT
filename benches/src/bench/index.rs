//! Замеры индекса шарда: скорость вставки и поиска IVF, бюджет RAM (§8.2) и настоящая цена
//! durability (§10.1).
//!
//! Здесь меряются три вещи, которые спека обещает числами, и ни одна из них не является
//! «тестом на скорость»:
//!
//! * **вставка** — арена растёт шагом `ARENA_BLOCK` и копирует себя на каждом блоке, поэтому
//!   замер обязан использовать `with_capacity`, иначе он измеряет quadratic-рост аллокатора, а
//!   не индекс (§8.2, комментарий к `IvfIndex::with_capacity`);
//! * **поиск** — цена строго `nprobe × средняя длина списка × DIM` целочисленных операций
//!   (§8.4), и её надо видеть в микросекундах на реальном размере списка, а не в формуле;
//! * **fsync** — publish это один fsync, group commit — один fsync на `GROUP_COMMIT_MAX` опсов
//!   (§10.1). Разница между ними и есть ответ на «сколько записей в секунду принимает шард», и
//!   она держится на диске, а не на CPU: число машинно-зависимое, поэтому оно печатается вместе
//!   с числом fsync, из которого выведено.
//!
//! Данные — синтетика `vecdht_embed::testing::Synthetic`: берутся её центроиды как центры
//! кластеров шарда, а записи — это центроид плюс детерминированный шум из `Rng`. Это не «данные
//! пользователя», а геометрия, на которой IVF обязан работать; recall-гейт §18.1 по ней не
//! считается и измеряется в `p0`/`p0_harness`.

use std::time::Instant;

use vecdht_crypto::DIM;
use vecdht_crypto::quant::l2_sq;
use vecdht_embed::testing::Synthetic;
use vecdht_index::ivf::IvfIndex;
use vecdht_index::store::ShardStore;
use vecdht_index::testing::{Rng, dir, remove};
use vecdht_index::{CLUSTERS_PER_SHARD, GROUP_COMMIT_MAX, INDEX_ENTRY_BYTES, IndexEntry};

use vecdht_benches::{Sink, header, rate, scale, value};

/// Записей на кластер при множителе 1. 16 кластеров шарда × 256 = 4096 записей: достаточно,
/// чтобы средний список был видно в статистике, и мало, чтобы прогон в debug не встал.
const PER_CLUSTER: usize = 256;

/// Бакет публикации. `ttl_buckets = 225` ⇒ дедлайн `published + 225`, а поиск идёт при
/// `now_bucket = published`, поэтому записи живые, а GC в этом замере не участвует (§9.6).
const PUBLISHED_BUCKET: u32 = 1_000;
const TTL_BUCKETS: u16 = 225;

/// Запись вокруг центроида кластера: координаты сдвинуты не больше чем на 6, знак и величина —
/// из детерминированного `Rng`. Одинаковые владельцы были бы одной записью (дедупликация по
/// `owner`, §8.2), поэтому `seq` входит в ключ.
fn entry(rng: &mut Rng, center: &[i8; DIM], cluster: u16, seq: u64) -> IndexEntry {
    let mut vec_q = *center;
    for x in vec_q.iter_mut() {
        let d = rng.below(13) as i32 - 6;
        *x = (i32::from(*x) + d).clamp(-127, 127) as i8;
    }
    let mut owner = [0u8; 32];
    owner[..8].copy_from_slice(&seq.to_le_bytes());
    owner[8..].copy_from_slice(&blake3::hash(&seq.to_le_bytes()).as_bytes()[..24]);
    IndexEntry {
        owner_ed25519: owner,
        vec_q,
        cluster_id: cluster,
        published_bucket: PUBLISHED_BUCKET,
        ttl_buckets: TTL_BUCKETS,
    }
}

/// Кластеры шарда 0 — ровно те 16, которые он обязан обслуживать (§7.4).
fn shard_clusters() -> Vec<u16> {
    (0..CLUSTERS_PER_SHARD).collect()
}

fn main() {
    let k = scale();
    header("index", "IVF-арена (§8.2–§8.4), бюджет RAM и цена fsync при publish (§10.1)");

    let synth = Synthetic::generate(1, 0);
    let per_cluster = PER_CLUSTER * k;
    let n = CLUSTERS_PER_SHARD as usize * per_cluster;

    // 1. Вставка. `with_capacity` — не микрооптимизация, а условие того, что замер про индекс:
    //    без него арена копируется с каждого блока, и число зависит от объёма, а не от вставки.
    let mut rng = Rng::new(0xC0FFEE);
    let mut index = IvfIndex::with_capacity(0, n);
    let entries: Vec<IndexEntry> = (0..n as u64)
        .map(|i| entry(&mut rng, &synth.centers[(i / per_cluster as u64) as usize], (i / per_cluster as u64) as u16, i))
        .collect();
    let t = Instant::now();
    for e in &entries {
        index.insert(*e).expect("вставка записи своего шарда");
    }
    let inserted = t.elapsed();
    rate("insert (дедуп owner + арена + inverted list)", n, inserted);
    assert_eq!(index.live, n, "все вставки обязаны стать живыми записями");

    // 2. Бюджет памяти (§8.2). Считаем по capacity, а не по len: бюджет спеки — про выделенное.
    let mem = index.mem_bytes();
    println!(
        "память: арена {} Б + списки {} Б + owners {} Б + bitmap {} Б = {} Б на {} записей",
        mem.arena,
        mem.lists,
        mem.owners,
        mem.bitmap,
        mem.total(),
        index.live
    );
    value("байт на живую запись", mem.per_entry(index.live), "Б");
    println!(
        "сравнение с §8.2: запись {} Б, прогноз ≈449 Б на запись ⇒ {}",
        INDEX_ENTRY_BYTES,
        if mem.per_entry(index.live) <= 449.0 { "в бюджете" } else { "СВЕРХ бюджета — пересчитать спеку" }
    );

    // 3. Поиск по nprobe (§8.4). Просматриваются первые `np` списков шарда: при фиксированной
    //    геометрии это то же самое по объёму, что `Centroids::top` выбрал бы для реального
    //    запроса, и стоимость считается честно — как сумма длин просмотренных списков.
    let clusters = shard_clusters();
    let mut sink = Sink::default();
    for np in [1usize, 4, CLUSTERS_PER_SHARD as usize] {
        let scan = &clusters[..np];
        let list_len: usize = scan.iter().map(|&c| index.cluster_len(c)).sum();
        let top_k = 10usize;
        let queries = 32usize * k;
        let mut qrng = Rng::new(0xBEEF);
        let qs: Vec<[i8; DIM]> = (0..queries)
            .map(|_| {
                let mut v = synth.centers[qrng.below(np as u64) as usize];
                for x in v.iter_mut() {
                    *x = (i32::from(*x) + qrng.below(13) as i32 - 6).clamp(-127, 127) as i8;
                }
                v
            })
            .collect();
        let mut hits = 0usize;
        let t = Instant::now();
        for q in &qs {
            let r = index.search(q, scan, top_k, PUBLISHED_BUCKET);
            hits += r.len();
            sink.add(r.first().map(|(d, _)| *d).unwrap_or(0) as u64);
        }
        let el = t.elapsed();
        rate(&format!("search nprobe={np} (top_k {top_k})"), queries, el);
        println!(
            "  просмотрено списков: {list_len} записей из {} , целочисленных l2_sq на запрос ≈ {} ; хитов {} из {}",
            index.live,
            list_len * DIM,
            hits,
            queries * top_k
        );
    }
    sink.commit("index-search");

    // Инвариант порядка, а не скорость: просмотр всех списков шарда обязан совпасть с полным
    // перебором по тем же int8-байтам (§8.4). Если это разъедется, все числа выше — про другой
    // алгоритм.
    let q = entries[0].vec_q;
    let mut brute: Vec<(u32, u32)> = index
        .live_slots()
        .map(|(slot, e)| (l2_sq(&q, &e.vec_q), slot))
        .collect();
    brute.sort_unstable();
    brute.truncate(10);
    let ann = index.search(&q, &clusters, 10, PUBLISHED_BUCKET);
    println!(
        "полный скан шарда == brute-force: {}",
        ann == brute
    );

    // 4. Durable-запись. Два одинаковых объёма опсов, разное число fsync — ровно то сравнение,
    //    которое §10.1 обещает превратить в пропускную способность узла.
    let ops = (200 * k).max(40);
    let one = dir("bench-publish");
    let grouped = dir("bench-group");
    let mut store_a = ShardStore::create(&one, 0, 1).expect("создать шард");
    let mut store_b = ShardStore::create(&grouped, 0, 1).expect("создать шард");
    let mut s1 = Sink::default();
    let t = Instant::now();
    for (i, e) in entries.iter().take(ops).cloned().enumerate() {
        store_a.publish(e).expect("publish одного шарда");
        s1.add(i as u64);
    }
    let solo = t.elapsed();
    rate(&format!("publish с fsync на каждый опс ({ops} опсов = {ops} fsync)"), ops, solo);
    s1.commit("solo-publish");

    let mut s2 = Sink::default();
    let t = Instant::now();
    let mut commits = 0usize;
    for (i, e) in entries.iter().skip(ops).take(ops).cloned().enumerate() {
        store_b.stage_insert(e).expect("stage insert");
        s2.add(i as u64);
        if store_b.should_group_commit() {
            store_b.commit().expect("group commit");
            commits += 1;
        }
    }
    if store_b.staged_len() > 0 {
        store_b.commit().expect("хвост группы");
        commits += 1;
    }
    let group = t.elapsed();
    rate(
        &format!("group commit ≤{GROUP_COMMIT_MAX} опсов на fsync ({ops} опсов = {commits} fsync)"),
        ops,
        group,
    );
    s2.commit("group-commit");
    let per_op_solo = solo.as_secs_f64() / ops as f64;
    let per_op_group = group.as_secs_f64() / ops as f64;
    if per_op_group > 0.0 {
        println!(
            "ускорение group commit: {:.1}×  ({:.2} мс/опс против {:.2} мс/опс) — узел на этом диске тянет ≈{:.0} опсов/с",
            per_op_solo / per_op_group,
            per_op_solo * 1e3,
            per_op_group * 1e3,
            1.0 / per_op_group
        );
    }

    // 5. Снапшот-барьер (§10.4): стриминг индекса на диск. `flush_snapshot` возвращает число
    //    записанных байт, а не seq — размер берём оттуда, а имя читаем из каталога, чтобы замер
    //    не начал «сходиться» с файлом, которого нет. Байт на запись здесь и есть проверка
    //    бюджета §8.2 на реальном сериализаторе, а не на оценке из структуры записи.
    let snap = Instant::now();
    let bytes = store_b.flush_snapshot().expect("снапшот обязан дописаться");
    let snap_el = snap.elapsed();
    let name = std::fs::read_dir(&grouped)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with("snap.") && n.ends_with(".log"))
        .unwrap_or_else(|| "<снапшот не найден в каталоге>".into());
    let live = store_b.len().max(1) as f64;
    println!(
        "flush_snapshot: {} живых записей → {} Б ({:.0} Б/запись) за {:.1} мс, файл {} = {:.1} МБ/с",
        store_b.len(),
        bytes,
        bytes as f64 / live,
        snap_el.as_secs_f64() * 1e3,
        name,
        bytes as f64 / snap_el.as_secs_f64().max(1e-9) / 1e6
    );

    store_a.shutdown().expect("корректное закрытие");
    store_b.shutdown().expect("корректное закрытие");
    remove(&one);
    remove(&grouped);

    println!(
        "примечание: fsync-числа зависят от диска и антивируса сильнее, чем от кода; для спеки \
         берётся release-прогон и явно указывается хост"
    );
}
