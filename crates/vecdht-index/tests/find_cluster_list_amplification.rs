//! Оракул E-0037, порог (3): `IvfIndex::search` сканирует запросные кластеры поштучно,
//! дубликаты не схлопываются — число обработанных записей ровно линейно по длине списка.
//!
//! Стенд снят с гейта §19.1 (`search_latency.rs`): шард 0, 1 104 записи = 16 × 69, все 16
//! кластеров заполнены ровно. Доказательное свидетельство усиления — точное число hits,
//! оно от профиля сборки не зависит; времена p50 печатаются справочно и порогом не являются
//! (в debug абсолютные числа ничего не значат, §19.1 меряется отдельным гейтом в release).

use std::hint::black_box;
use std::time::{Duration, Instant};

use vecdht_index::entry::IndexEntry;
use vecdht_index::store::ShardStore;
use vecdht_index::testing::{Rng, dir, remove};
use vecdht_index::CLUSTERS_PER_SHARD;
use vecdht_wire::codec::DIM;

/// 1 104 = 16 × 69: ровно по 69 живых записей в каждом кластере шарда 0.
const N: u64 = 1_104;
const PER: usize = 69;
/// Значения `n` из порога (3): 1 и законные 16 — нижняя рамка; 4 096 — 256× законного списка
/// одного шарда, и при этом заметно меньше предельных 65 535 (с ним тест строил бы 4,5 млн хитов).
const SIZES: [usize; 5] = [1, 16, 256, 1024, 4096];

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
        cluster_id: (i % CLUSTERS_PER_SHARD as u64) as u16,
        published_bucket: 1_000,
        ttl_buckets: 54_000,
    }
}

fn p50(mut times: Vec<Duration>) -> Duration {
    times.sort_unstable();
    times[times.len() / 2]
}

#[test]
fn duplicate_cluster_lists_are_not_collapsed() {
    let d = dir("find-amp");
    let mut s = ShardStore::create(&d, 0, 1).unwrap();
    let mut r = Rng::new(0xC0FFEE);
    for i in 0..N {
        s.stage_insert(entry(i, &mut r)).unwrap();
    }
    s.stage_time_mark(1_100).unwrap();
    s.commit().unwrap();
    assert_eq!(s.index.live, N as usize);
    for c in 0..CLUSTERS_PER_SHARD as u64 {
        assert_eq!(s.index.cluster_len(c as u16), PER, "кластер {c} заполнен неровно");
    }

    let q = [1i8; DIM];
    let mut rows: Vec<String> = Vec::new();
    for n in SIZES {
        // Порог (3): список из `n` копий кластера 0 обязан обработать ровно `n · 69` записей —
        // top_k берётся на единицу больше, чтобы срез по top_k не замаскировал нелинейность.
        let clusters = vec![0u16; n];
        let hits = s.search(&q, &clusters, n * PER + 1);
        assert_eq!(
            hits.len(),
            n * PER,
            "n={n}: дубликаты схлопнулись ({} вместо {})",
            hits.len(),
            n * PER
        );
        rows.push(format!("{n}→{}", hits.len()));
    }
    // Контроль среза: при малом top_k результат обрезан, но поиск всё равно ходил по списку —
    // это тот же вызов, что выше, только с `top_k = 10`.
    let cut = s.search(&q, &vec![0u16; 1024], 10);
    assert_eq!(cut.len(), 10, "top_k=10 не срезан при 1024 дублях");

    // Справочно: p50 законного 16-кластерного запроса против 4 096 дублей одного. Порога нет.
    let mut t16: Vec<Duration> = Vec::new();
    let mut t4096: Vec<Duration> = Vec::new();
    let c16: Vec<u16> = (0..CLUSTERS_PER_SHARD).collect();
    for i in 0..40 {
        let t = Instant::now();
        black_box(s.search(&q, &c16, 10));
        t16.push(t.elapsed());
        let clusters = vec![0u16; 4096];
        let t = Instant::now();
        black_box(s.search(&q, &clusters, 10));
        t4096.push(t.elapsed());
        black_box(i);
    }
    let p50_16 = p50(t16);
    let p50_4096 = p50(t4096);
    eprintln!(
        "## порог (3): hits по длине списка: {} ##",
        rows.join(", ")
    );
    eprintln!(
        "## справочно (debug): p50 законного списка 16 — {:.3} мс, списка 4096 — {:.3} мс, \
         отношение ×{:.0} ##",
        p50_16.as_secs_f64() * 1e3,
        p50_4096.as_secs_f64() * 1e3,
        p50_4096.as_secs_f64() / p50_16.as_secs_f64()
    );

    remove(&d);
}
