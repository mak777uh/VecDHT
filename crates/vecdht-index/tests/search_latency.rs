//! Гейт §19.1 по задержке: `search` на узле с ~1.1k записей обязан укладываться в 0.3 мс.
//!
//! Отдельный test-таргет и один тест в нём: замер в общем процессе глушится параллельными
//! тестами, которые пилят диск и аллоцируют арены. Порог §19.1 определён для релизной сборки,
//! поэтому гейт включается только в ней — запускать `cargo test --release -p vecdht-index
//! --test search_latency`. В debug-профиле время совсем другое (на этой машине ~200×), и
//! «масштабированный» порог ничего не доказывал бы, так что в debug остаются только
//! инварианты: равномерность кластеров, полнота `top_k` и стоимость, линейная по nprobe.

use std::hint::black_box;
use std::time::{Duration, Instant};

use vecdht_index::entry::IndexEntry;
use vecdht_index::store::ShardStore;
use vecdht_index::testing::{Rng, dir, remove};
use vecdht_index::CLUSTERS_PER_SHARD;
use vecdht_wire::codec::DIM;

/// «~1.1k записей на узел» из гейта. 1104 = 16 × 69: записи ложатся на кластеры шарда 0 ровно,
/// иначе assert равномерности ниже ловил бы остаток от деления, а не регрессию поиска.
const N: u64 = 1_104;
const CPS: u64 = CLUSTERS_PER_SHARD as u64;
const QUERIES: usize = 500;
const TOP_K: usize = 10;
/// 0.3 мс — контракт гейта в релизной сборке (§19.1).
const RELEASE_LIMIT: Duration = Duration::from_micros(300);

fn pct(sorted: &[Duration], p: usize) -> Duration {
    let i = (sorted.len() * p / 100).min(sorted.len() - 1);
    sorted[i]
}

/// Худший случай для шарда 0: nprobe = все 16 кластеров этого шарда, записи распределены по
/// ним ровно. Полное сканирование `NLIST` кластеров — это уже не узел v8, а другой алгоритм.
fn clusters_of_shard_0() -> Vec<u16> {
    (0..CLUSTERS_PER_SHARD).collect()
}

fn entry(i: u64, r: &mut Rng) -> IndexEntry {
    let mut owner = [0u8; 32];
    owner[..8].copy_from_slice(&i.to_le_bytes());
    owner[8] = 0x3e;
    let mut v = [0i8; DIM];
    for lane in v.iter_mut() {
        *lane = (r.below(7) as i8) - 3;
    }
    IndexEntry {
        owner_ed25519: owner,
        vec_q: v,
        // CLUSTERS_PER_SHARD = 16, поэтому кластеры 0..16 — шард 0 (§7.4); дальше идёт чужой шард.
        cluster_id: (i % CPS) as u16,
        published_bucket: 1_000,
        // Живая на момент запроса бакетом 1_100 — иначе поиск фильтровал бы пустоту.
        ttl_buckets: 54_000,
    }
}

#[test]
fn search_is_under_300_microseconds_at_1104_entries() {
    let d = dir("latency");
    let mut s = ShardStore::create(&d, 0, 1).unwrap();
    let mut r = Rng::new(0xC0FFEE);
    for i in 0..N {
        s.stage_insert(entry(i, &mut r)).unwrap();
    }
    s.stage_time_mark(1_100).unwrap();
    s.commit().unwrap();
    assert_eq!(s.index.live, N as usize);
    // Все 16 кластеров шарда заполнены: без этого замер был бы замером пустых списков.
    for c in clusters_of_shard_0() {
        assert_eq!(s.index.cluster_len(c), (N / CPS) as usize);
    }

    let clusters = clusters_of_shard_0();
    let mut q = [0i8; DIM];
    let mut times: Vec<Duration> = Vec::with_capacity(QUERIES);

    // Прогрев: page cache арены + ветчинание в отборе.
    for _ in 0..16 {
        for lane in q.iter_mut() {
            *lane = (r.below(7) as i8) - 3;
        }
        black_box(s.search(&q, &clusters, TOP_K));
    }
    for _ in 0..QUERIES {
        for lane in q.iter_mut() {
            *lane = (r.below(7) as i8) - 3;
        }
        let t = Instant::now();
        let hits = s.search(&q, &clusters, TOP_K);
        times.push(t.elapsed());
        black_box(hits);
    }
    times.sort_unstable();
    let p50 = pct(&times, 50);
    let p95 = pct(&times, 95);
    let p99 = pct(&times, 99);

    // Второй замер — тот же запрос по одному кластеру. Нужен не «ради красоты», а как страж
    // nprobe: если `search` начнёт обходить все 1024 кластера вместо переданных, цена
    // одно-кластерного запроса сравняется с шестнадцати-кластерным и гейт превратится в шум.
    let mut one: Vec<Duration> = Vec::with_capacity(QUERIES / 4);
    for _ in 0..QUERIES / 4 {
        for lane in q.iter_mut() {
            *lane = (r.below(7) as i8) - 3;
        }
        let t = Instant::now();
        let hits = s.search(&q, &[clusters[0]], TOP_K);
        one.push(t.elapsed());
        assert_eq!(hits.len(), TOP_K, "top_k не выбран одним кластером");
        black_box(hits);
    }
    one.sort_unstable();
    let p50_one = pct(&one, 50);
    assert!(
        p50_one * 6 <= p50,
        "стоимость не масштабируется по nprobe: 1 кластер {:.3} мс, 16 кластеров {:.3} мс",
        p50_one.as_secs_f64() * 1e3,
        p50.as_secs_f64() * 1e3
    );

    println!(
        "search nprobe={} при {} записях [{}]: p50 {:.3} мс, p95 {:.3} мс, p99 {:.3} мс, \
         один кластер p50 {:.3} мс, порог §19.1 {:.3} мс, живых на шарде 0: {}",
        clusters.len(),
        N,
        if cfg!(debug_assertions) { "debug" } else { "release" },
        p50.as_secs_f64() * 1e3,
        p95.as_secs_f64() * 1e3,
        p99.as_secs_f64() * 1e3,
        p50_one.as_secs_f64() * 1e3,
        RELEASE_LIMIT.as_secs_f64() * 1e3,
        s.index.live,
    );

    if cfg!(debug_assertions) {
        println!(
            "debug: временной гейт пропущен ({} мс — это профиль, а не алгоритм). \
             Проверка §19.1: cargo test --release -p vecdht-index --test search_latency",
            p95.as_secs_f64() * 1e3
        );
    } else {
        assert!(
            p95 <= RELEASE_LIMIT,
            "p95 {:.3} мс > порога {:.3} мс (§19.1)",
            p95.as_secs_f64() * 1e3,
            RELEASE_LIMIT.as_secs_f64() * 1e3
        );
    }

    remove(&d);
}
