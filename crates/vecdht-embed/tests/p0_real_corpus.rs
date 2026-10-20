//! Гейт (ii) §18.1 на **реальном** корпусе: recall@10 IVF против brute-force в том же
//! int8-представлении, nlist = 1024, nprobe = 16, ≥50 000 реальных интент-текстов.
//!
//! Синтетический harness (`p0_harness.rs`) проверяет механику; здесь измеряется число, которое
//! вносится в §19.4. Корпус и запросы — вне git (правило AGENTS.md о весах и больших артефактах),
//! их источник, sha256 и точный способ выборки фиксируются в `E-0004`.
//!
//! ```
//! VEC_DHT_MODEL_DIR=<...> \
//! VEC_DHT_P0_CORPUS=<...>/corpus-50k.txt \
//! VEC_DHT_P0_QUERIES=<...>/queries-1k.txt \
//! RAYON_NUM_THREADS=4 \
//! cargo test --release -p vecdht-embed --features candle gate_ii_real_corpus_recall -- --ignored --nocapture
//! ```
//!
//! `embed_pooled` кешируется рядом с корпусом (`*.p0emb`): прогон занимает десятки минут, и
//! потерять его из-за падения на k-means было бы недопустимо. Кеш проверяется по blake3
//! канонических текстов, `model_version` и `preprocessing_version`; устаревший кеш отвергается, а
//! не используется молча. Файл кеша — тоже вне git.
//!
//! Порог и процедура зафиксированы до прогона в `H-0004`/`E-0004`. Тест не ослабляет порог: при
//! recall@16 < 0.95 он падает и печатает лестницу §8.6, а не «почти прошёл».
//!
//! Режимы (переменные окружения, каждый — отдельная зарегистрированная гипотеза, порог один):
//! `VEC_DHT_P0_NLIST` — лестница §8.6, nlist 1024→512 (`E-0004`); `VEC_DHT_P0_SHARD_COMPLETE=1` —
//! полный скан выбранных шардов (`E-0005`); `VEC_DHT_P0_COARSE=1` — двухуровневая карта шардов
//! `H-0007`/`E-0007`: шард = грубая ячейка из 16 пространственно близких кластеров.

#![cfg(feature = "candle")]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use vecdht_artifact::{reference_manifest, Centroids};
use vecdht_crypto::quant::{
    assign_cluster, clusters_of_shard, group_by_shard, l2_normalize, l2_sq, quantize_slice,
    top_clusters,
};
use vecdht_crypto::DIM;
use vecdht_embed::candle_backend::ModernBertEmbedder;
use vecdht_embed::kmeans::{self, KMeansConfig};
use vecdht_embed::metrics::recall_at_k;
use vecdht_embed::model::{quantize_pooled, Pipeline};
use vecdht_embed::text::normalize_text;
use vecdht_embed::EmbeddingModel;
use vecdht_wire::{CLUSTERS_PER_SHARD, NLIST};

const TOP_K: usize = 10;
const NPROBE_GATE: usize = 16;
const MAX_ITERS: usize = 12;
/// Фиксирован до прогона; смена seed — новая запись E, а не «подкрутить и повторить».
const SEED: u64 = 0x5645_4344_4854_0002;
const CACHE_TAG: &[u8; 8] = b"VDP0EMB1";
const CACHE_HEADER: usize = 8 + 4 + 4 + 32;

#[derive(Clone, Copy)]
enum TextKind {
    Corpus,
    Query,
}

#[test]
#[ignore = "P0(ii): 50k реальных текстов + веса; десятки минут CPU, запускать вручную"]
fn gate_ii_real_corpus_recall() {
    let Some(corpus_path) = env_path("VEC_DHT_P0_CORPUS") else {
        println!("гейт (ii) НЕ ИЗМЕРЕН: VEC_DHT_P0_CORPUS не задан");
        return;
    };
    let Some(queries_path) = env_path("VEC_DHT_P0_QUERIES") else {
        println!("гейт (ii) НЕ ИЗМЕРЕН: VEC_DHT_P0_QUERIES не задан");
        return;
    };

    let pipeline = Pipeline::from_manifest(&reference_manifest()).expect("эталонный манифест");
    let Some(model) = ModernBertEmbedder::from_env(&pipeline, "granite-embedding-97m-v2")
        .expect("VEC_DHT_MODEL_DIR задан, но модель не загружается")
    else {
        println!(
            "гейт (ii) НЕ ИЗМЕРЕН: VEC_DHT_MODEL_DIR не задан; нужны те же веса, что в E-0002"
        );
        return;
    };

    let corpus = canonical_lines(read_lines(&corpus_path), "корпус");
    let queries = canonical_lines(read_lines(&queries_path), "запросы");
    // Малый прогон проверяет код, но не является гейтом: при 1024 кластерах на 3k текстах
    // recall измеряет стенд, а не §18.1. Порог размера ослабляется только этой явной переменной.
    let smoke = std::env::var("VEC_DHT_P0_ALLOW_SMALL").is_ok_and(|v| v == "1");
    if !smoke {
        assert!(
            corpus.len() >= 50_000,
            "гейт (ii): корпус {} текстов, §18.1 требует ≥50 000",
            corpus.len()
        );
        assert!(
            queries.len() >= 1_000,
            "гейт (ii): запросов {}, нужно ≥1 000 для устойчивого среднего",
            queries.len()
        );
    } else {
        println!("P0(ii): SMOKE-режим (VEC_DHT_P0_ALLOW_SMALL=1) — числа не являются гейтом");
    }
    let corpus_set: HashSet<&str> = corpus.iter().map(String::as_str).collect();
    assert_eq!(corpus_set.len(), corpus.len(), "в корпусе есть повторы канонических текстов");
    assert!(
        queries.iter().all(|q| !corpus_set.contains(q.as_str())),
        "held-out запросы пересекаются с корпусом: recall перестал бы быть честным"
    );

    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .clamp(1, 8);
    println!(
        "P0(ii): корпус {} текстов (blake3 {}), запросы {} (blake3 {}); потоков расчёта {threads}",
        corpus.len(),
        blake3::hash(&fs::read(&corpus_path).expect("корпус читается")).to_hex(),
        queries.len(),
        blake3::hash(&fs::read(&queries_path).expect("запросы читаются")).to_hex(),
    );

    let corpus_raw = embed_cached(&corpus, TextKind::Corpus, &model, &pipeline, &corpus_path);
    let query_raw = embed_cached(&queries, TextKind::Query, &model, &pipeline, &queries_path);
    print_token_stats(&corpus, &model, "корпус");
    print_token_stats(&queries, &model, "запросы");

    let corpus_unit = normalize_rows(&corpus_raw);
    drop(corpus_raw);
    let query_unit = normalize_rows(&query_raw);
    drop(query_raw);

    // Лестница §8.6: nlist — параметр артефакта. Гейт по умолчанию всегда NLIST=1024;
    // переменная существует только для отдельного ladder-прогона, зафиксированного в E-0004
    // до запуска. Значение 512 — шаг «nlist 1024→512» из §8.6, а не новая редакция гейта.
    let nlist = match std::env::var("VEC_DHT_P0_NLIST") {
        Ok(raw) => raw.parse::<usize>().expect("VEC_DHT_P0_NLIST — целое число"),
        Err(_) => NLIST as usize,
    };
    assert!(
        nlist > 0 && nlist <= NLIST as usize && nlist % 16 == 0,
        "nlist={nlist} должен делить шарды по 16 кластеров и не превышать NLIST={NLIST}"
    );
    let ladder = nlist != NLIST as usize;
    // §8.6, вариант «точный скан всех кластеров шарда»: топ-nprobe кластеров выбирает шарды,
    // но каждый выбранный шард сканирует все 16 своих кластеров. Fan-out при этом не растёт.
    let shard_complete = matches!(std::env::var("VEC_DHT_P0_SHARD_COMPLETE").as_deref(), Ok("1"));
    // H-0007/E-0007: двухуровневая карта шардов. Верхний уровень — `nlist / 16` грубых
    // центроидов над замороженными 1024; шард = грубая ячейка, поэтому полный скан выбранного
    // шарда перестаёт быть лотереей: он покрывает пространственно связную область, а не
    // случайные кластеры `cluster_id / 16`. Fan-out тот же, меняется только карта.
    let coarse = matches!(std::env::var("VEC_DHT_P0_COARSE").as_deref(), Ok("1"));
    if coarse && shard_complete {
        println!("COARSE и SHARD-COMPLETE заданы вместе: считается только COARSE");
    }
    let k = nlist;
    let cap = (2 * corpus.len()).div_ceil(k);
    let config = KMeansConfig { k, max_iters: MAX_ITERS, seed: SEED, balance_cap: cap };
    println!(
        "k-means: k={k}, cap={cap} (2×N/nlist), max_iters={MAX_ITERS}, seed=0x{SEED:016X}{}",
        if ladder { format!(" [ЛЕСТНИЦА §8.6: nlist={nlist}, гейт по умолчанию — {NLIST}]") } else { String::new() }
    );
    if shard_complete {
        println!(
            "режим SHARD-COMPLETE: каждый выбранный шард сканирует все {CLUSTERS_PER_SHARD} кластера; \
             fan-out считается по топ-{NPROBE_GATE} кластерам и не меняется"
        );
    }
    if coarse {
        println!(
            "режим COARSE: шард = грубая ячейка ({} ячеек над {nlist} кластерами); выбранный шард \
             сканирует все свои кластеры, fan-out считается по топ-{NPROBE_GATE} ячейкам",
            nlist / CLUSTERS_PER_SHARD as usize
        );
    }
    let started = Instant::now();
    let trained = kmeans::train(&corpus_unit, DIM, config, threads).expect("balanced k-means");
    println!("k-means: {} итераций за {:.1} с", trained.iterations, started.elapsed().as_secs_f64());
    for (i, s) in trained.history.iter().enumerate() {
        println!(
            "  итерация {:>2}: changed={:>6}, objective={:.6}, max_cluster={:>5}, over_cap={}",
            i + 1,
            s.changed,
            s.objective,
            s.max_cluster,
            s.clusters_over_cap
        );
    }

    let centroid_f64: Vec<f64> = trained.centroids.iter().map(|&x| f64::from(x)).collect();
    // Для nlist=NLIST — production-путь артефакта: он проверяет и фиксированный размер
    // centroid.bin (NLIST×DIM). Для ladder nlist=512 используется тот же quantize_slice,
    // но контракт CENTROID_BYTES к тестовой ручке не применяется.
    let centroid_store: Vec<[i8; DIM]> = if ladder {
        centroid_f64
            .chunks_exact(DIM)
            .map(|chunk| quantize_slice(chunk).expect("центроид ladder-набора квантуется"))
            .collect()
    } else {
        Centroids::from_f64(&centroid_f64)
            .expect("центроиды квантуются в int8")
            .rows()
            .into_iter()
            .copied()
            .collect()
    };
    let rows: Vec<&[i8; DIM]> = centroid_store.iter().collect();

    let corpus_i8: Vec<[i8; DIM]> = corpus_unit
        .chunks_exact(DIM)
        .map(|row| {
            let arr: &[f32; DIM] = row.try_into().expect("строка DIM");
            quantize_pooled(arr).expect("квантование корпуса")
        })
        .collect();
    drop(corpus_unit);
    let query_i8: Vec<[i8; DIM]> = query_unit
        .chunks_exact(DIM)
        .map(|row| {
            let arr: &[f32; DIM] = row.try_into().expect("строка DIM");
            quantize_pooled(arr).expect("квантование запроса")
        })
        .collect();
    drop(query_unit);

    // Реальное присваивание публикации — argmin по int8 (§7.2), без training-cap. Именно его
    // увидит узел; training-cap влияет на центроиды, а не на это правило.
    let actual: Vec<u16> = corpus_i8.iter().map(|v| assign_cluster(v, &rows)).collect();
    let mut actual_counts = vec![0u32; k];
    let mut members: Vec<Vec<u32>> = vec![Vec::new(); k];
    for (id, &c) in actual.iter().enumerate() {
        actual_counts[c as usize] += 1;
        members[c as usize].push(id as u32);
    }
    print_cluster_stats(&actual_counts, cap);

    // Верхний уровень карты шардов (только режим COARSE): грубые ячейки над теми же
    // замороженными центроидами. Обучается после int8-присваивания и не влияет на него.
    let cells = coarse.then(|| build_cells(&trained.centroids, &centroid_store, nlist, threads));
    if let Some(c) = &cells {
        let sizes = &c.counts;
        let min = sizes.iter().copied().min().unwrap_or(0);
        let max = sizes.iter().copied().max().unwrap_or(0);
        let over = sizes.iter().filter(|&&n| n as usize > CLUSTERS_PER_SHARD as usize).count();
        let empty = sizes.iter().filter(|&&n| n == 0).count();
        println!(
            "COARSE: {} ячеек над {nlist} кластерами, k-means top-level за {} итераций; \
             размер ячейки min {min} / max {max} (ровно {} ожидалось), over_cap={over}, пустых={empty}",
            c.rows.len(),
            c.iterations,
            CLUSTERS_PER_SHARD
        );
        println!(
            "COARSE: fan-out при nprobe=16 ячеек ≤16 шардов, скан {} кластеров ({}% nlist) — \
             против {CLUSTERS_PER_SHARD} кластеров у пересечения",
            16 * CLUSTERS_PER_SHARD as usize,
            16 * CLUSTERS_PER_SHARD as usize * 100 / nlist
        );
    }

    let truth_started = Instant::now();
    let truth = parallel_map(query_i8.len(), threads, |qi| {
        brute_force(&corpus_i8, &query_i8[qi])
    });
    println!(
        "ground truth: brute-force по {} int8-векторам для {} запросов за {:.1} с",
        corpus_i8.len(),
        query_i8.len(),
        truth_started.elapsed().as_secs_f64()
    );

    println!("nprobe  recall@10   fan-out avg/max   candidates avg   время");
    // Точка гейта — nprobe=16. Остальные точки (включая полный скан nprobe=nlist) —
    // данные лестницы §8.6: они показывают, где recall упирается в потолок зондирования.
    let mut probes = vec![1usize, 4, 8, NPROBE_GATE, 24, 32, 64, 128, 256];
    // В режиме COARSE единица зондирования — грубая ячейка (их nlist/16), а не кластер.
    let scan_units = cells.as_ref().map_or(nlist, |c| c.rows.len());
    probes.retain(|&p| p <= scan_units);
    if probes.last().copied() != Some(scan_units) {
        probes.push(scan_units);
    }
    let mut recall_at_16 = 0.0;
    for nprobe in probes {
        let started = Instant::now();
        let runs: Vec<AnnRun> = parallel_map(query_i8.len(), threads, |qi| {
            ann_search(&rows, &members, &corpus_i8, &query_i8[qi], nprobe, shard_complete, cells.as_ref())
        });
        let per_query: Vec<f64> = runs
            .iter()
            .zip(&truth)
            .map(|(r, t)| recall_at_k(t, &r.ids, TOP_K))
            .collect();
        let recall = per_query.iter().sum::<f64>() / per_query.len() as f64;
        let recall_min = per_query.iter().copied().fold(f64::INFINITY, f64::min);
        let fanout_sum: usize = runs.iter().map(|r| r.fanout).sum();
        let fanout_max = runs.iter().map(|r| r.fanout).max().unwrap_or(0);
        let candidates: usize = runs.iter().map(|r| r.candidates).sum();
        println!(
            "{nprobe:>6}  {recall:.4} (min {recall_min:.2})  {:>5.1}/{:<3}        {:>8.1}       {:.1} с",
            fanout_sum as f64 / runs.len() as f64,
            fanout_max,
            candidates as f64 / runs.len() as f64,
            started.elapsed().as_secs_f64(),
        );
        assert!(fanout_max <= nprobe, "fan-out {fanout_max} больше nprobe={nprobe}");
        if nprobe == NPROBE_GATE {
            recall_at_16 = recall;
        }
    }

    if smoke {
        println!("SMOKE: recall@10 = {recall_at_16:.4} при nprobe={NPROBE_GATE} — не гейт, размер корпуса ниже §18.1");
    } else if coarse {
        println!(
            "COARSE (H-0007): recall@10 = {recall_at_16:.4} при nprobe={NPROBE_GATE} ячеек, порог 0.95, \
             цель 0.98 — {}",
            if recall_at_16 >= 0.95 { "PASS" } else { "FAIL" }
        );
    } else if ladder {
        println!(
            "ЛЕСТНИЦА §8.6: nlist={nlist}, recall@10 = {recall_at_16:.4} при nprobe={NPROBE_GATE}, \
             порог 0.95 — {}",
            if recall_at_16 >= 0.95 { "PASS" } else { "FAIL" }
        );
    } else if shard_complete {
        println!(
            "SHARD-COMPLETE: recall@10 = {recall_at_16:.4} при nprobe={NPROBE_GATE}, порог 0.95, \
             цель 0.98 — {}",
            if recall_at_16 >= 0.95 { "PASS" } else { "FAIL" }
        );
    } else {
        println!(
            "ГЕЙТ (ii): recall@10 = {recall_at_16:.4} при nprobe={NPROBE_GATE}, порог 0.95, цель 0.98 — {}",
            if recall_at_16 >= 0.95 { "PASS" } else { "FAIL" }
        );
    }
    if !smoke {
        let hint = if coarse {
            "COARSE (H-0007): связная карта шардов не подняла recall до 0.95 — механизм \
             опровергнут, и следующим шагом идёт другой индекс, а не подкрутка порога"
        } else {
            "Лестница §8.6: nprobe=24/32 → nlist=512 → полный скан; при недостижимости — \
             пересмотр claim'а §8.6, а не порога"
        };
        assert!(
            recall_at_16 >= 0.95,
            "гейт (ii): nlist={nlist}, recall@10 = {recall_at_16:.4} < 0.95 при nprobe={NPROBE_GATE}. {hint}"
        );
    }
}

struct AnnRun {
    ids: Vec<u32>,
    fanout: usize,
    candidates: usize,
}

fn ann_search(
    centroids: &[&[i8; DIM]],
    members: &[Vec<u32>],
    corpus: &[[i8; DIM]],
    query: &[i8; DIM],
    nprobe: usize,
    shard_complete: bool,
    cells: Option<&Cells>,
) -> AnnRun {
    let (scan_clusters, fanout) = if let Some(c) = cells {
        // Зонд единица — грубая ячейка. Выбранные ячейки — шарды; каждый сканирует свои
        // кластеры целиком (их ровно `CLUSTERS_PER_SHARD`), дублей нет.
        let refs: Vec<&[i8; DIM]> = c.rows.iter().collect();
        let chosen = top_clusters(query, &refs, nprobe);
        let mut scan: Vec<u16> = Vec::with_capacity(chosen.len() * CLUSTERS_PER_SHARD as usize);
        for cell in &chosen {
            scan.extend_from_slice(&c.clusters_of_cell[*cell as usize]);
        }
        let fanout = chosen.len();
        (scan, fanout)
    } else {
        let clusters = top_clusters(query, centroids, nprobe);
        let shards = group_by_shard(&clusters);
        let fanout = shards.len();
        // Shard-complete: узел уже выбран, его 16 кластеров лежат локально, поэтому сканируем их
        // все. Множество кластеров — объединение по шардам; дублей нет, шарды не пересекаются.
        let scan = if shard_complete {
            shards
                .iter()
                .flat_map(|(shard, _)| clusters_of_shard(*shard))
                .collect()
        } else {
            clusters
        };
        (scan, fanout)
    };
    let mut top = TopK::new();
    let mut candidates = 0;
    for cluster in scan_clusters {
        for &id in &members[cluster as usize] {
            top.push(l2_sq(query, &corpus[id as usize]), id);
            candidates += 1;
        }
    }
    AnnRun { ids: top.ids(), fanout, candidates }
}

/// Верхний уровень карты шардов для режима COARSE: `k = nlist / CLUSTERS_PER_SHARD` грубых
/// центроидов над замороженными, cap = `CLUSTERS_PER_SHARD`, чтобы шард держал ровно 16
/// кластеров. Ячейка кластера — int8-argmin, тот же контракт, что у присваивания записи (§7.2).
struct Cells {
    rows: Vec<[i8; DIM]>,
    clusters_of_cell: Vec<Vec<u16>>,
    counts: Vec<u32>,
    iterations: usize,
}

fn build_cells(
    centroids_f32: &[f32],
    fine_i8: &[[i8; DIM]],
    nlist: usize,
    threads: usize,
) -> Cells {
    let k = nlist / CLUSTERS_PER_SHARD as usize;
    assert!(k > 0, "nlist={nlist} меньше одного шарда из {CLUSTERS_PER_SHARD} кластеров");
    let cfg =
        KMeansConfig { k, max_iters: MAX_ITERS, seed: SEED ^ 0x0007, balance_cap: CLUSTERS_PER_SHARD as usize };
    let trained = kmeans::train(centroids_f32, DIM, cfg, threads).expect("верхний уровень k-means");
    let coarse_f64: Vec<f64> = trained.centroids.iter().map(|&x| f64::from(x)).collect();
    let rows: Vec<[i8; DIM]> = coarse_f64
        .chunks_exact(DIM)
        .map(|chunk| quantize_slice(chunk).expect("центроид ячейки квантуется"))
        .collect();
    let refs: Vec<&[i8; DIM]> = rows.iter().collect();
    let mut clusters_of_cell = vec![Vec::new(); k];
    let mut counts = vec![0u32; k];
    for (cluster, fine) in fine_i8.iter().enumerate() {
        let cell = assign_cluster(fine, &refs) as usize;
        clusters_of_cell[cell].push(cluster as u16);
        counts[cell] += 1;
    }
    // Внутренняя непротиворечивость карты: каждый замороженный кластер попал ровно в одну ячейку.
    // Это инвариант построения (кластер присваивается один раз), а не метрика качества: если он
    // нарушится, recall посчитается по неполному покрытию и число будет ложно низким, а причина
    // будет выглядеть как «механизм не работает».
    let covered: usize = counts.iter().map(|&n| n as usize).sum();
    assert_eq!(
        covered,
        fine_i8.len(),
        "ячейки покрывают {covered} кластеров из {} — карта неполна",
        fine_i8.len()
    );
    Cells { rows, clusters_of_cell, counts, iterations: trained.iterations }
}

fn brute_force(corpus: &[[i8; DIM]], query: &[i8; DIM]) -> Vec<u32> {
    let mut top = TopK::new();
    for (id, point) in corpus.iter().enumerate() {
        top.push(l2_sq(query, point), id as u32);
    }
    top.ids()
}

#[derive(Clone)]
struct TopK {
    d2: [u32; TOP_K],
    ids: [u32; TOP_K],
    len: usize,
}

impl TopK {
    fn new() -> Self {
        Self { d2: [u32::MAX; TOP_K], ids: [u32::MAX; TOP_K], len: 0 }
    }

    /// Вставка с контрактом `(d2 ASC, id ASC)`. Отсечение по худшему элементу делает полный
    /// перебор 50k точек дешёвым: большинство расстояний даже не сдвигает массив.
    fn push(&mut self, d2: u32, id: u32) {
        if self.len == TOP_K {
            let worst_d = self.d2[TOP_K - 1];
            let worst_id = self.ids[TOP_K - 1];
            if d2 > worst_d || (d2 == worst_d && id > worst_id) {
                return;
            }
        }
        let mut pos = if self.len < TOP_K { self.len } else { TOP_K - 1 };
        while pos > 0 {
            let prev_d = self.d2[pos - 1];
            let prev_id = self.ids[pos - 1];
            if prev_d < d2 || (prev_d == d2 && prev_id < id) {
                break;
            }
            self.d2[pos] = prev_d;
            self.ids[pos] = prev_id;
            pos -= 1;
        }
        self.d2[pos] = d2;
        self.ids[pos] = id;
        if self.len < TOP_K {
            self.len += 1;
        }
    }

    fn ids(&self) -> Vec<u32> {
        self.ids[..self.len].to_vec()
    }
}

fn embed_cached(
    texts: &[String],
    kind: TextKind,
    model: &ModernBertEmbedder,
    pipeline: &Pipeline,
    source: &Path,
) -> Vec<f32> {
    let cache = source.with_extension("p0emb");
    let digest = text_digest(model.model_version(), model.preprocessing_version(), texts);
    if let Some(values) = read_cache(&cache, texts.len(), &digest) {
        eprintln!("эмбеддинги: кеш {} ({} строк)", cache.display(), texts.len());
        return values;
    }

    eprintln!("эмбеддинги: {} строк через forward (кеш будет записан)", texts.len());
    let started = Instant::now();
    let mut values = Vec::with_capacity(texts.len() * DIM);
    for (i, text) in texts.iter().enumerate() {
        let pooled = match kind {
            TextKind::Corpus => model.embed_pooled(pipeline.model_input_for_index(text)),
            TextKind::Query => model.embed_pooled(&pipeline.model_input_for_query(text)),
        }
        .unwrap_or_else(|e| panic!("forward на строке {i}: {e}"));
        values.extend_from_slice(&pooled);
        if i % 1000 == 0 || i + 1 == texts.len() {
            let elapsed = started.elapsed().as_secs_f64();
            eprintln!(
                "  {}/{}: {:.1} с, {:.2} строк/с",
                i + 1,
                texts.len(),
                elapsed,
                (i + 1) as f64 / elapsed
            );
        }
    }
    write_cache(&cache, &values, &digest, texts.len());
    values
}

fn text_digest(model_version: &str, preprocessing_version: u16, texts: &[String]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vecdht/p0/real-corpus/emb/v1\0");
    h.update(model_version.as_bytes());
    h.update(&[0]);
    h.update(&preprocessing_version.to_le_bytes());
    for text in texts {
        h.update(text.as_bytes());
        h.update(&[0]);
    }
    *h.finalize().as_bytes()
}

fn read_cache(path: &Path, count: usize, digest: &[u8; 32]) -> Option<Vec<f32>> {
    let data = fs::read(path).ok()?;
    if data.len() != CACHE_HEADER + count * DIM * 4 || &data[..8] != CACHE_TAG.as_slice() {
        return None;
    }
    let cached_count = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
    let cached_dim = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
    if cached_count != count || cached_dim != DIM || &data[16..48] != digest.as_slice() {
        return None;
    }
    let mut values = Vec::with_capacity(count * DIM);
    for chunk in data[CACHE_HEADER..].chunks_exact(4) {
        let value = f32::from_le_bytes(chunk.try_into().ok()?);
        if !value.is_finite() {
            return None;
        }
        values.push(value);
    }
    Some(values)
}

fn write_cache(path: &Path, values: &[f32], digest: &[u8; 32], count: usize) {
    let mut data = Vec::with_capacity(CACHE_HEADER + values.len() * 4);
    data.extend_from_slice(CACHE_TAG);
    data.extend_from_slice(&(count as u32).to_le_bytes());
    data.extend_from_slice(&(DIM as u32).to_le_bytes());
    data.extend_from_slice(digest);
    for value in values {
        data.extend_from_slice(&value.to_le_bytes());
    }
    let tmp = path.with_extension("p0emb.tmp");
    fs::write(&tmp, &data).expect("запись кеша эмбеддингов");
    if path.exists() {
        fs::remove_file(path).expect("удаление устаревшего кеша");
    }
    fs::rename(&tmp, path).expect("переименование кеша эмбеддингов");
    eprintln!("эмбеддинги: кеш записан {} ({} МБ)", path.display(), data.len() / (1024 * 1024));
}

/// Нормировка pooled-вектора в f64 — ровно то, что делает `finalize` перед квантованием. K-means
/// требует единичных строк, поэтому это отдельный проход, а не неявное допущение.
fn normalize_rows(raw: &[f32]) -> Vec<f32> {
    assert_eq!(raw.len() % DIM, 0);
    let mut out = Vec::with_capacity(raw.len());
    for (row, chunk) in raw.chunks_exact(DIM).enumerate() {
        let mut d = [0f64; DIM];
        for (dst, &src) in d.iter_mut().zip(chunk) {
            *dst = f64::from(src);
        }
        l2_normalize(&mut d).unwrap_or_else(|e| panic!("нормировка строки {row}: {e}"));
        out.extend(d.iter().map(|&x| x as f32));
    }
    out
}

fn print_token_stats(texts: &[String], model: &ModernBertEmbedder, what: &str) {
    let mut lens: Vec<usize> = texts
        .iter()
        .map(|t| model.token_len(t).expect("tokenizer на тексте корпуса"))
        .collect();
    lens.sort_unstable();
    let p95 = lens[(lens.len() * 95 / 100).min(lens.len() - 1)];
    println!(
        "{what}: токенов min {} / медиана {} / p95 {} / max {}",
        lens[0],
        lens[lens.len() / 2],
        p95,
        lens[lens.len() - 1]
    );
}

fn print_cluster_stats(counts: &[u32], cap: usize) {
    let n: u32 = counts.iter().sum();
    let mut sorted = counts.to_vec();
    sorted.sort_unstable();
    let len = sorted.len();
    let over = sorted.iter().filter(|&&c| c as usize > cap).count();
    println!(
        "кластеры (argmin int8): min {} / p50 {} / p95 {} / max {} / среднее {:.1}; over_cap={} (cap {})",
        sorted[0],
        sorted[len / 2],
        sorted[(len * 95 / 100).min(len - 1)],
        sorted[len - 1],
        n as f64 / len as f64,
        over,
        cap
    );
}

fn parallel_map<T, F>(n: usize, threads: usize, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Sync,
{
    let mut out: Vec<Option<T>> = (0..n).map(|_| None).collect();
    let chunk = n.div_ceil(threads.max(1));
    let f = &f;
    std::thread::scope(|scope| {
        for (t, slot) in out.chunks_mut(chunk).enumerate() {
            let start = t * chunk;
            scope.spawn(move || {
                for (j, item) in slot.iter_mut().enumerate() {
                    *item = Some(f(start + j));
                }
            });
        }
    });
    out.into_iter().map(|item| item.expect("parallel_map: пропущен индекс")).collect()
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(str::to_owned)
        .collect()
}

fn canonical_lines(lines: Vec<String>, what: &str) -> Vec<String> {
    lines
        .into_iter()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(i, line)| {
            normalize_text(&line).unwrap_or_else(|e| panic!("{what}: строка {}: {e}", i + 1))
        })
        .collect()
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}
