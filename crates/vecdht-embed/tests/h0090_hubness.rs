//! `H-0090`: хабность реального корпуса и цена слепого отравления — на том же корпусе, что `E-0004`,
//! без нового индекса и без весов (читается кеш эмбеддингов `*.p0emb`).
//!
//! Что печатается числом, а не словами:
//!
//! * `H0090_HUB_SKEW` — асимметрия распределения `N_10` на детерминированной выборке корпуса:
//!   сколько раз запись попадает в top-10 чужих запросов. Это и есть хабность `L-0005`;
//! * `H0090_TRUE10_IN_PROBE` — доля истинных top-10, чьи кластеры попали в top-16 зонда. Если она
//!   совпадает с `H0090_RECALL16`, провал recall — усечение зонда, а не хабность;
//! * `H0090_ATTACK_*` — атакующий публикует копии 10 самых хабных записей, **не зная запроса**:
//!   сколько запросов получают атакующего в top-1/top-10 (точно и через зонд);
//! * `H0090_TARGETED_IVF_TOP1` — контроль прибора: копия самого запроса обязана захватить top-1 у
//!   100 % запросов, иначе меряется не то.
//!
//! ```
//! VEC_DHT_H0090_CORPUS_CACHE=<...>/corpus-50k.p0emb \
//! VEC_DHT_H0090_QUERIES_CACHE=<...>/queries-1k.p0emb \
//! VEC_DHT_H0090_CENTROIDS=<...>/artifact-50k/centroid.bin \
//! cargo test --release -p vecdht-embed --test h0090_hubness -- --ignored --nocapture
//! ```
//!
//! Кеш и артефакт — те же внешние файлы, что в `E-0004` (веса и корпус вне git). Тест ничего не
//! переобучает: центроиды читаются из `centroid.bin`, поэтому геометрия сравниваема с `0.8303`.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Instant;

use vecdht_artifact::Centroids;
use vecdht_crypto::quant::{assign_cluster, l2_sq, top_clusters};
use vecdht_crypto::DIM;
use vecdht_embed::model::quantize_pooled;
use vecdht_wire::NLIST;

const K: usize = 10;
const NPROBE: usize = 16;
/// Детерминированная выборка для `N_k`: полный корпус 50 000² пар — 1,9·10¹⁰ сравнений, выборка
/// каждого десятого — ровно 5 000². Страйд фиксирован до прогона, а не подбирается по результату.
const SAMPLE: usize = 5_000;
const HUBS: usize = 10;
const CACHE_TAG: &[u8; 8] = b"VDP0EMB1";
const CACHE_HEADER: usize = 8 + 4 + 4 + 32;

#[test]
#[ignore = "H-0090: 50k реального корпуса, минуты CPU; запускать вручную"]
fn hubness_and_blind_poisoning_on_the_real_corpus() {
    let (Some(corpus_path), Some(queries_path), Some(centroids_path)) = (
        env_path("VEC_DHT_H0090_CORPUS_CACHE"),
        env_path("VEC_DHT_H0090_QUERIES_CACHE"),
        env_path("VEC_DHT_H0090_CENTROIDS"),
    ) else {
        println!(
            "H0090_MEASURED=0: нужны VEC_DHT_H0090_CORPUS_CACHE, VEC_DHT_H0090_QUERIES_CACHE, \
             VEC_DHT_H0090_CENTROIDS"
        );
        return;
    };
    let corpus = read_cache(&corpus_path);
    let queries = read_cache(&queries_path);
    assert!(corpus.len() >= 50_000, "корпус {} < 50 000", corpus.len());
    assert!(queries.len() >= 1_000, "запросов {} < 1 000", queries.len());
    assert_eq!(
        corpus_hash(&corpus_path).len(),
        64,
        "blake3 корпуса печатается полным, чтобы провенанс не был догадкой"
    );
    println!(
        "H0090_MEASURED=1 H0090_CORPUS={} H0090_QUERIES={} H0090_SAMPLE={} H0090_K={K} \
         H0090_NPROBE={NPROBE} H0090_HUBS={HUBS}",
        corpus.len(),
        queries.len(),
        SAMPLE
    );
    println!(
        "H0090_CORPUS_HASH={} H0090_QUERIES_HASH={}",
        corpus_hash(&corpus_path),
        corpus_hash(&queries_path)
    );

    // --- (1) Хабность: N_10 на детерминированной выборке ---------------------
    let started = Instant::now();
    let stride = (corpus.len() / SAMPLE).max(1);
    let sample: Vec<[i8; DIM]> = corpus.iter().step_by(stride).take(SAMPLE).copied().collect();
    let mut occ = vec![0u32; sample.len()];
    for (qi, q) in sample.iter().enumerate() {
        for (_, idx) in top_k(&sample, q, K, Some(qi)) {
            occ[idx] += 1;
        }
    }
    let stats = skewness(&occ);
    println!(
        "H0090_HUB_MEAN={:.4} H0090_HUB_SKEW={:.4} H0090_HUB_MAX={} H0090_HUB_P99={} \
         H0090_HUB_ZERO={} H0090_HUB_SAMPLE_SEC={:.2}",
        stats.mean,
        stats.skew,
        stats.max,
        stats.p99,
        stats.zero,
        started.elapsed().as_secs_f64()
    );

    // --- (2) Геометрия зонда: recall@16 и покрытие истинного top-10 ----------
    let started = Instant::now();
    let centroids =
        Centroids::from_u8(&fs::read(&centroids_path).expect("centroid.bin читается")).expect(
            "centroid.bin — ровно NLIST×DIM байт; другой файл к протокольной геометрии не относится",
        );
    let rows = centroids.rows();
    let clusters: Vec<u16> = corpus.iter().map(|v| assign_cluster(v, &rows)).collect();
    let mut members: Vec<Vec<u32>> = vec![Vec::new(); NLIST as usize];
    for (id, &c) in clusters.iter().enumerate() {
        members[c as usize].push(id as u32);
    }

    let queries = &queries[..1_000.min(queries.len())];
    let mut recall_hits = 0usize;
    let mut truth_in_probe = 0usize;
    let mut truth_total = 0usize;
    let mut truth: Vec<Vec<(u32, usize)>> = Vec::with_capacity(queries.len());
    let mut scanned_best: Vec<Vec<(u32, usize)>> = Vec::with_capacity(queries.len());
    let mut probes: Vec<HashSet<u16>> = Vec::with_capacity(queries.len());
    for q in queries {
        let exact = top_k(&corpus, q, K, None);
        let probe = top_clusters(q, &rows, NPROBE);
        let probe_set: HashSet<u16> = probe.iter().copied().collect();
        let mut candidates: Vec<usize> = Vec::new();
        for &c in &probe {
            candidates.extend(members[c as usize].iter().map(|&i| i as usize));
        }
        let exact_ids: HashSet<usize> = exact.iter().map(|&(_, i)| i).collect();
        let ivf = top_k_subset(&corpus, q, K, &candidates);
        recall_hits += ivf.iter().filter(|&&(_, i)| exact_ids.contains(&i)).count();
        for &(_, i) in &exact {
            truth_total += 1;
            if probe_set.contains(&clusters[i]) {
                truth_in_probe += 1;
            }
        }
        truth.push(exact);
        scanned_best.push(ivf);
        probes.push(probe_set);
    }
    let recall = recall_hits as f64 / (queries.len() * K) as f64;
    let in_probe = truth_in_probe as f64 / truth_total as f64;
    println!(
        "H0090_RECALL16={recall:.4} H0090_TRUE10_IN_PROBE={in_probe:.4} \
         H0090_TRUTH_IN_PROBE={truth_in_probe} H0090_TRUTH_TOTAL={truth_total} \
         H0090_GEOMETRY_SEC={:.2}",
        started.elapsed().as_secs_f64()
    );

    // --- (3) Слепое отравление: копии самых хабных записей --------------------
    let mut hub_order: Vec<usize> = (0..occ.len()).collect();
    hub_order.sort_by(|&a, &b| occ[b].cmp(&occ[a]).then(a.cmp(&b)));
    let hubs: Vec<[i8; DIM]> = hub_order.iter().take(HUBS).map(|&i| sample[i]).collect();
    let hub_ids: Vec<usize> = hub_order.iter().take(HUBS).copied().collect();
    println!(
        "H0090_HUB_IDS={:?} H0090_HUB_OCC={:?}",
        hub_ids,
        hub_ids.iter().map(|&i| occ[i]).collect::<Vec<_>>()
    );

    let (mut exact_top1, mut exact_top10) = (0usize, 0usize);
    let (mut ivf_top1, mut ivf_top10) = (0usize, 0usize);
    let mut targeted_ivf_top1 = 0usize;
    for (qi, q) in queries.iter().enumerate() {
        let d_best = truth[qi][0].0;
        let d_tenth = truth[qi][K - 1].0;
        let a_min = hubs.iter().map(|h| l2_sq(q, h)).min().expect("HUBS > 0");
        if a_min < d_best {
            exact_top1 += 1;
        }
        if a_min < d_tenth {
            exact_top10 += 1;
        }
        // Через зонд: копия хаба лежит в его собственном кластере; если кластер не зондирован,
        // запись не видна вовсе.
        let probed_min = hub_ids
            .iter()
            .zip(hubs.iter())
            .filter(|(id, _)| probes[qi].contains(&clusters[**id]))
            .map(|(_, h)| l2_sq(q, h))
            .min();
        if let Some(a) = probed_min {
            if a < scanned_best[qi][0].0 {
                ivf_top1 += 1;
            }
            if a < scanned_best[qi][K - 1].0 {
                ivf_top10 += 1;
            }
        }
        // Контроль: копия самого запроса. Её кластер — top-1 зонда, дистанция 0.
        let targeted = l2_sq(q, q);
        if targeted < scanned_best[qi][0].0 {
            targeted_ivf_top1 += 1;
        }
    }
    let n = queries.len();
    println!(
        "H0090_ATTACK_EXACT_TOP1={:.4} H0090_ATTACK_EXACT_TOP10={:.4} \
         H0090_ATTACK_IVF_TOP1={:.4} H0090_ATTACK_IVF_TOP10={:.4} \
         H0090_ATTACK_TOP1_COUNT={} H0090_ATTACK_TOP10_COUNT={} \
         H0090_TARGETED_IVF_TOP1={:.4} H0090_TARGETED_COUNT={}",
        exact_top1 as f64 / n as f64,
        exact_top10 as f64 / n as f64,
        ivf_top1 as f64 / n as f64,
        ivf_top10 as f64 / n as f64,
        ivf_top1,
        ivf_top10,
        targeted_ivf_top1 as f64 / n as f64,
        targeted_ivf_top1
    );
    assert_eq!(targeted_ivf_top1, n, "контроль сломан: копия запроса не захватила top-1");
}

/// Топ-`k` по контракту `(d2 ASC, индекс ASC)`; `skip` исключает сам запрос из выборки.
fn top_k(items: &[[i8; DIM]], q: &[i8; DIM], k: usize, skip: Option<usize>) -> Vec<(u32, usize)> {
    let mut best: Vec<(u32, usize)> = Vec::with_capacity(k + 1);
    for (i, item) in items.iter().enumerate() {
        if skip == Some(i) {
            continue;
        }
        let d = l2_sq(q, item);
        if best.len() == k && d >= best[k - 1].0 {
            continue;
        }
        let pos = best.partition_point(|&(bd, _)| bd <= d);
        best.insert(pos, (d, i));
        if best.len() > k {
            best.pop();
        }
    }
    best
}

/// Тот же отбор, но по подмножеству индексов корпуса (скан выбранных ячеек).
fn top_k_subset(
    items: &[[i8; DIM]],
    q: &[i8; DIM],
    k: usize,
    subset: &[usize],
) -> Vec<(u32, usize)> {
    let mut best: Vec<(u32, usize)> = Vec::with_capacity(k + 1);
    for &i in subset {
        let d = l2_sq(q, &items[i]);
        if best.len() == k && d >= best[k - 1].0 {
            continue;
        }
        let pos = best.partition_point(|&(bd, _)| bd <= d);
        best.insert(pos, (d, i));
        if best.len() > k {
            best.pop();
        }
    }
    best
}

struct Skew {
    mean: f64,
    skew: f64,
    max: u32,
    p99: u32,
    zero: usize,
}

fn skewness(occ: &[u32]) -> Skew {
    let n = occ.len() as f64;
    let mean = occ.iter().map(|&x| f64::from(x)).sum::<f64>() / n;
    let m2 = occ.iter().map(|&x| (f64::from(x) - mean).powi(2)).sum::<f64>() / n;
    let m3 = occ.iter().map(|&x| (f64::from(x) - mean).powi(3)).sum::<f64>() / n;
    let skew = if m2 == 0.0 { 0.0 } else { m3 / m2.powf(1.5) };
    let mut sorted = occ.to_vec();
    sorted.sort_unstable();
    let p99 = sorted[((sorted.len() as f64 * 0.99) as usize).min(sorted.len() - 1)];
    Skew {
        mean,
        skew,
        max: *sorted.last().expect("выборка не пуста"),
        p99,
        zero: occ.iter().filter(|&&x| x == 0).count(),
    }
}

fn env_path(name: &str) -> Option<std::path::PathBuf> {
    std::env::var(name).ok().filter(|v| !v.is_empty()).map(std::path::PathBuf::from)
}

/// Кеш `*.p0emb`: шапка `VDP0EMB1`, count, dim, digest, затем `count × DIM` f32.
/// Дайджест не пересчитывается: текстов рядом нет, а провенанс фиксируется blake3 всего файла.
fn read_cache(path: &Path) -> Vec<[i8; DIM]> {
    let data = fs::read(path).unwrap_or_else(|e| panic!("{} не читается: {e}", path.display()));
    assert_eq!(&data[..8], CACHE_TAG.as_slice(), "{}: не кеш H-0090", path.display());
    let count = u32::from_le_bytes(data[8..12].try_into().expect("count")) as usize;
    let dim = u32::from_le_bytes(data[12..16].try_into().expect("dim")) as usize;
    assert_eq!(dim, DIM, "{}: размерность {dim} ≠ {DIM}", path.display());
    assert_eq!(
        data.len(),
        CACHE_HEADER + count * DIM * 4,
        "{}: длина не сходится с шапкой",
        path.display()
    );
    let mut rows = Vec::with_capacity(count);
    for chunk in data[CACHE_HEADER..].chunks_exact(DIM * 4) {
        let mut row = [0f32; DIM];
        for (i, cell) in row.iter_mut().enumerate() {
            *cell = f32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().expect("f32"));
        }
        rows.push(quantize_pooled(&row).expect("эмбеддинг квантуется"));
    }
    rows
}

fn corpus_hash(path: &Path) -> String {
    blake3::hash(&fs::read(path).unwrap_or_else(|e| panic!("{} не читается: {e}", path.display())))
        .to_hex()
        .to_string()
}
