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
/// Потолок владельцев на один запрос — §7.5 (fan-out). В групповой заявке он жёсткий:
/// заявка, не уместившаяся в 16 владельцев, отбрасывается.
const MAX_OWNERS: usize = 16;
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
    // Протокольный вид карты: ровно `CLUSTERS_PER_SHARD` кластеров на шард (иначе
    // `shard_of_cluster(c) = c / 16` перестаёт быть контрактом). Переключатель меняет, ЧТО
    // меряется гейтом, но не порог и не точку гейта: отдельный опыт `E-0008`.
    let exact_shards = matches!(std::env::var("VEC_DHT_P0_EXACT_SHARDS").as_deref(), Ok("1"));
    // Внедряемый вид карты: назначение при обучении верхнего уровня (ровно 16 кластеров на
    // шард) — это и есть порядок строк таблицы центроидов блоками по 16.
    let train_map = matches!(std::env::var("VEC_DHT_P0_TRAIN_MAP").as_deref(), Ok("1"));
    // H-0011/E-0011: ровная карта шардов, построенная делением, а не починкой.
    let balanced = matches!(std::env::var("VEC_DHT_P0_BALANCED").as_deref(), Ok("1"));
    // H-0010/E-0010: политика «заявка по кластерам» — клиент запрашивает у владельца только
    // нужные ему кластеры, а не весь шард; потолок владельцев — 16 (§7.5).
    let grouped = matches!(std::env::var("VEC_DHT_P0_GROUPED").as_deref(), Ok("1"));
    assert!(
        !(exact_shards && train_map),
        "VEC_DHT_P0_EXACT_SHARDS и VEC_DHT_P0_TRAIN_MAP задают разные карты одновременно"
    );
    assert!(
        !train_map || coarse,
        "VEC_DHT_P0_TRAIN_MAP имеет смысл только вместе с VEC_DHT_P0_COARSE=1"
    );
    assert!(
        !balanced || coarse,
        "VEC_DHT_P0_BALANCED имеет смысл только вместе с VEC_DHT_P0_COARSE=1"
    );
    assert!(
        !grouped || coarse,
        "VEC_DHT_P0_GROUPED имеет смысл только вместе с VEC_DHT_P0_COARSE=1"
    );
    assert!(
        !(balanced && (exact_shards || train_map)),
        "VEC_DHT_P0_BALANCED задаёт третью карту — с EXACT_SHARDS/TRAIN_MAP одновременно бессмысленно"
    );
    if grouped {
        println!(
            "режим GROUPED: K ближайших кластеров раскладываются по шардам карты; владельцев \
             не более {MAX_OWNERS} (§7.5), у каждого запрашиваются только его кластеры"
        );
    }
    if balanced {
        println!("режим BALANCED: карта шардов построена рекурсивным делением (ровно 16 на шард)");
    }

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
    // Две карты: int8-argmin (как в `E-0007`) и назначение при обучении (ровные шарды).
    let cell_maps =
        coarse.then(|| build_cells(&trained.centroids, &centroid_store, nlist, threads));
    let cells = cell_maps.as_ref().map(|(argmin, _)| argmin);
    let train_cells = cell_maps.as_ref().map(|(_, train)| train);
    // Протокольный вид карты: жадная перебалансировка до ровно 16 кластеров на ячейку.
    let exact_cells = cells.map(rebalance_exact);
    // Ровная карта, построенная делением, а не починкой (`H-0011`/`E-0011`): рекурсивное
    // деление центроидов по оси максимальной дисперсии до групп ровно по 16.
    let balanced_cells =
        balanced.then(|| build_balanced_cells(&trained.centroids, nlist));
    if let Some(bc) = &balanced_cells {
        let sizes = &bc.counts;
        let min = sizes.iter().copied().min().unwrap_or(0);
        let max = sizes.iter().copied().max().unwrap_or(0);
        println!(
            "BALANCED (рекурсивное деление): {} ячеек над {nlist} кластерами; размер ячейки \
             min {min} / max {max} (ровно {CLUSTERS_PER_SHARD} ожидалось)",
            bc.rows.len()
        );
        assert!(
            sizes.iter().all(|&n| n as usize == CLUSTERS_PER_SHARD as usize),
            "карта ровных шардов неровная: {sizes:?}"
        );
    }

    if let Some(ex) = &exact_cells {
        let sizes = &ex.counts;
        let min = sizes.iter().copied().min().unwrap_or(0);
        let max = sizes.iter().copied().max().unwrap_or(0);
        println!(
            "COARSE (ровные шарды, жадная правка): размер ячейки min {min} / max {max} \
             (ровно {CLUSTERS_PER_SHARD} ожидалось)"
        );
        if exact_shards {
            // Протокольная карта обязана быть ровной: иначе `shard_of_cluster(c) = c / 16`
            // не описывает шард, и измеренный recall относится не к той геометрии.
            assert!(
                sizes.iter().all(|&n| n as usize == CLUSTERS_PER_SHARD as usize),
                "карта ровных шардов неровная: {sizes:?}"
            );
        }
    }
    if let Some(tc) = &train_cells {
        let sizes = &tc.counts;
        let min = sizes.iter().copied().min().unwrap_or(0);
        let max = sizes.iter().copied().max().unwrap_or(0);
        println!(
            "COARSE (карта обучения): размер ячейки min {min} / max {max} \
             (ровно {CLUSTERS_PER_SHARD} ожидалось)"
        );
    }
    // Карта, по которой считается гейт: int8-argmin (E-0007), жадная правка (E-0008),
    // назначение при обучении (E-0009) или рекурсивное деление (E-0011).
    let gate_map: Option<&Cells> = if balanced {
        balanced_cells.as_ref()
    } else if train_map {
        train_cells
    } else if exact_shards {
        exact_cells.as_ref()
    } else {
        cells
    };
    // Правило оценки ячейки для гейта: в режиме карты обучения — «ближайший кластер» (это
    // внедряемая клиентская политика: блок из 16 строк оценивается минимумом по строкам),
    // в остальных режимах — пред-регистрированное «до центроида ячейки».
    let gate_score =
        if train_map { CellScore::NearestFine } else { CellScore::Centroid };

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

    // Точка гейта — nprobe=16. Остальные точки (включая полный скан nprobe=nlist) —
    // данные лестницы §8.6: они показывают, где recall упирается в потолок зондирования.
    let mut probes = vec![1usize, 4, 8, NPROBE_GATE, 24, 32, 64, 128, 256];
    // В режиме COARSE единица зондирования — грубая ячейка (их nlist/16), а не кластер.
    let scan_units = cells.map_or(nlist, |c| c.rows.len());
    probes.retain(|&p| p <= scan_units);
    if probes.last().copied() != Some(scan_units) {
        probes.push(scan_units);
    }
    // В режиме GROUPED единица зондирования — запрошенный кластер: K — это размер заявки,
    // а не число шардов. Лестница K фиксирована пре-регистрацией `H-0010`.
    if grouped {
        probes = vec![16usize, 24, 32, 48, 64, 96, 128, 256];
    }

    let (points, recall_at_16) = run_curve(
        &rows,
        &members,
        &corpus_i8,
        &query_i8,
        &truth,
        &probes,
        threads,
        shard_complete,
        gate_map,
        gate_score,
        grouped,
    );
    print_curve("nprobe  recall@10   fan-out avg/max   candidates avg   время", &points);

    // Дополнительное измерение для решения ADR-0004 (клиентская политика выбора ячеек):
    // ячейка оценивается минимумом `l2_sq` по её 16 мелким центроидам вместо расстояния до
    // собственного центроида ячейки. Оно НЕ заменяет пред-регистрированное основное правило
    // и не влияет на гейт: если основное правило не проходит, это остаётся провалом опыта.
    if coarse && !grouped {
        // Дополнительное измерение — второе правило оценки ячейки на той же карте. Гейтом не
        // является: если основное правило не проходит, это остаётся провалом опыта.
        let (aux_map, aux_score, aux_label) = if train_map {
            (
                gate_map,
                CellScore::Centroid,
                "ДОПОЛНИТЕЛЬНОЕ ПРАВИЛО ОЦЕНКИ ЯЧЕЙКИ (не гейт): до центроида ячейки",
            )
        } else {
            (
                cells,
                CellScore::NearestFine,
                "ДОПОЛНИТЕЛЬНОЕ ПРАВИЛО ОЦЕНКИ ЯЧЕЙКИ (не гейт): минимум l2_sq по 16 центроидам ячейки",
            )
        };
        let (aux_points, aux_recall) = run_curve(
            &rows,
            &members,
            &corpus_i8,
            &query_i8,
            &truth,
            &probes,
            threads,
            shard_complete,
            aux_map,
            aux_score,
            false,
        );
        print_curve(
            &format!("{aux_label}\nnprobe  recall@10   fan-out avg/max   candidates avg   время"),
            &aux_points,
        );
        println!(
            "COARSE (дополнительное правило): recall@10 = {aux_recall:.4} при nprobe={NPROBE_GATE} — \
             справочное измерение, гейт считается по основному правилу"
        );
    }

    if grouped {
        // Гейт групповой заявки (`H-0010`): существует K, при котором recall@10 ≥ 0.95,
        // владельцев ≤ 16 (§7.5) и заявка укладывается в K ≤ 64 кластера (≤ 6,3 % корпуса).
        let passing = points.iter().filter(|p| p.nprobe <= 64 && p.fanout_max <= MAX_OWNERS);
        let best = passing.clone().filter(|p| p.recall >= 0.95).min_by_key(|p| p.nprobe);
        match best {
            Some(p) => println!(
                "GROUPED (H-0010): recall@10 = {:.4} при K={} (владельцев ≤ {}, кандидатов {:.1}) \
                 — PASS",
                p.recall, p.nprobe, p.fanout_max, p.candidates_avg
            ),
            None => println!(
                "GROUPED (H-0010): нет K ≤ 64 с recall@10 ≥ 0.95 при ≤{MAX_OWNERS} владельцах — FAIL"
            ),
        }
        if !smoke {
            assert!(
                best.is_some(),
                "гейт (ii), групповая заявка: нет K ≤ 64 с recall@10 ≥ 0.95 при ≤{MAX_OWNERS} \
                 владельцах. Кривая выше; пре-регистрация `H-0010`"
            );
        }
    } else if smoke {
        println!("SMOKE: recall@10 = {recall_at_16:.4} при nprobe={NPROBE_GATE} — не гейт, размер корпуса ниже §18.1");
    } else if coarse {
        println!(
            "COARSE{}: recall@10 = {recall_at_16:.4} при nprobe={NPROBE_GATE} ячеек, порог 0.95, \
             цель 0.98 — {}",
            if balanced {
                "-BALANCED (H-0011)"
            } else if train_map {
                "-TRAIN (H-0009)"
            } else if exact_shards {
                "-EXACT (H-0008)"
            } else {
                " (H-0007)"
            },
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
    if !smoke && !grouped {
        let hint = if coarse && train_map {
            "COARSE-TRAIN (H-0009): карта обучения (ровно 16 кластеров на шард) не подняла \
             recall до 0.95 — значит, внедряемый вид карты требует другого верхнего уровня"
        } else if coarse && exact_shards {
            "COARSE-EXACT (H-0008): протокольная карта с ровно 16 кластерами на шард не подняла \
             recall до 0.95 — перенумерация центроидов в таком виде не годится"
        } else if coarse && balanced {
            "COARSE-BALANCED (H-0011): ровная карта шардов, построенная делением, не подняла \
             recall до 0.95 — деление по одной оси рвёт связность"
        } else if coarse {
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

/// Правило оценки грубой ячейки в режиме COARSE.
/// `Centroid` — пред-регистрированное основное правило: расстояние до собственного центроида
/// ячейки (int8). `NearestFine` — дополнительное, справочное: минимум `l2_sq` по 16 мелким
/// центроидам ячейки; именно оно описано как клиентская политика в `E-0007`
/// («Реализуемость в сети») и решается в `ADR-0004`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CellScore {
    Centroid,
    NearestFine,
}

/// Точка кривой recall по числу зондов.
struct CurvePoint {
    nprobe: usize,
    recall: f64,
    recall_min: f64,
    fanout_avg: f64,
    fanout_max: usize,
    candidates_avg: f64,
    secs: f64,
}

/// Прогон кривой recall по заданным точкам зондирования. Один и тот же код обслуживает основной
/// и дополнительный прогоны: различается только правило оценки ячейки.
#[allow(clippy::too_many_arguments)]
fn run_curve(
    rows: &[&[i8; DIM]],
    members: &[Vec<u32>],
    corpus: &[[i8; DIM]],
    query_i8: &[[i8; DIM]],
    truth: &[Vec<u32>],
    probes: &[usize],
    threads: usize,
    shard_complete: bool,
    cells: Option<&Cells>,
    score: CellScore,
    grouped: bool,
) -> (Vec<CurvePoint>, f64) {
    let mut points = Vec::with_capacity(probes.len());
    let mut recall_at_gate = 0.0;
    for &nprobe in probes {
        let started = Instant::now();
        let runs: Vec<AnnRun> = parallel_map(query_i8.len(), threads, |qi| {
            ann_search(
                rows,
                members,
                corpus,
                &query_i8[qi],
                nprobe,
                shard_complete,
                cells,
                score,
                grouped,
            )
        });
        let per_query: Vec<f64> = runs
            .iter()
            .zip(truth)
            .map(|(r, t)| recall_at_k(t, &r.ids, TOP_K))
            .collect();
        let recall = per_query.iter().sum::<f64>() / per_query.len() as f64;
        let recall_min = per_query.iter().copied().fold(f64::INFINITY, f64::min);
        let fanout_sum: usize = runs.iter().map(|r| r.fanout).sum();
        let fanout_max = runs.iter().map(|r| r.fanout).max().unwrap_or(0);
        let candidates: usize = runs.iter().map(|r| r.candidates).sum();
        assert!(fanout_max <= nprobe, "fan-out {fanout_max} больше nprobe={nprobe}");
        if nprobe == NPROBE_GATE {
            recall_at_gate = recall;
        }
        points.push(CurvePoint {
            nprobe,
            recall,
            recall_min,
            fanout_avg: fanout_sum as f64 / runs.len() as f64,
            fanout_max,
            candidates_avg: candidates as f64 / runs.len() as f64,
            secs: started.elapsed().as_secs_f64(),
        });
    }
    (points, recall_at_gate)
}

fn print_curve(header: &str, points: &[CurvePoint]) {
    println!("{header}");
    for p in points {
        println!(
            "{:>6}  {:.4} (min {:.2})  {:>5.1}/{:<3}        {:>8.1}       {:.1} с",
            p.nprobe,
            p.recall,
            p.recall_min,
            p.fanout_avg,
            p.fanout_max,
            p.candidates_avg,
            p.secs
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn ann_search(
    centroids: &[&[i8; DIM]],
    members: &[Vec<u32>],
    corpus: &[[i8; DIM]],
    query: &[i8; DIM],
    nprobe: usize,
    shard_complete: bool,
    cells: Option<&Cells>,
    score: CellScore,
    grouped: bool,
) -> AnnRun {
    let (scan_clusters, fanout) = if grouped {
        // Политика «заявка по кластерам» (`H-0010`): клиент берёт K ближайших мелких
        // центроидов, раскладывает их по шардам карты и обращается не более чем к 16
        // владельцам; у каждого запрашиваются только его кластеры, а не весь шард.
        // Владельцы выбираются по числу запрошенных у них кластеров (tie-break — номер шарда).
        let c = cells.expect("групповая заявка требует карты шардов");
        let nearest = top_clusters(query, centroids, nprobe);
        let mut per: Vec<(u16, Vec<u16>)> = Vec::new();
        for &cl in &nearest {
            let cell = c.cell_of_cluster[cl as usize];
            match per.iter_mut().find(|e| e.0 == cell) {
                Some(e) => e.1.push(cl),
                None => per.push((cell, vec![cl])),
            }
        }
        per.sort_unstable_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
        per.truncate(MAX_OWNERS);
        let mut scan: Vec<u16> = Vec::with_capacity(nearest.len());
        for (_, clusters) in &per {
            scan.extend_from_slice(clusters);
        }
        scan.sort_unstable();
        scan.dedup();
        (scan, per.len())
    } else if let Some(c) = cells {
        // Зонд единица — грубая ячейка. Выбранные ячейки — шарды; каждый сканирует свои
        // кластеры целиком (их ровно `CLUSTERS_PER_SHARD`), дублей нет.
        let chosen = match score {
            CellScore::Centroid => {
                let refs: Vec<&[i8; DIM]> = c.rows.iter().collect();
                top_clusters(query, &refs, nprobe)
            }
            CellScore::NearestFine => {
                // Оценка ячейки — минимум расстояния до её 16 мелких центроидов: ячейка тем
                // ближе, чем ближе её лучший кластер. Порядок сортировки `(score, cell)` —
                // детерминированный, как и в `top_clusters`.
                let mut scored: Vec<(u32, u16)> = c
                    .clusters_of_cell
                    .iter()
                    .enumerate()
                    .map(|(cell, clusters)| {
                        let best = clusters
                            .iter()
                            .map(|&cl| l2_sq(query, centroids[cl as usize]))
                            .min()
                            .unwrap_or(u32::MAX);
                        (best, cell as u16)
                    })
                    .collect();
                scored.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
                scored.truncate(nprobe.min(scored.len()));
                scored.into_iter().map(|(_, cell)| cell).collect()
            }
        };
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
    /// Мелкие центроиды ячеек — нужны для перебалансировки карты до ровных шардов.
    fine: Vec<[i8; DIM]>,
    /// Обратная карта: кластер → ячейка. По ней заявка клиента раскладывается по владельцам.
    cell_of_cluster: Vec<u16>,
}

fn build_cells(
    centroids_f32: &[f32],
    fine_i8: &[[i8; DIM]],
    nlist: usize,
    threads: usize,
) -> (Cells, Cells) {
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

    // Карта 1 — int8-argmin по квантованным грубым центроидам: то, что измерял `E-0007`.
    // Ячейки разного размера (cap выдержан при обучении, но не при переприсвоении).
    let mut clusters_of_cell = vec![Vec::new(); k];
    let mut counts = vec![0u32; k];
    let mut cell_of_cluster_argmin = vec![0u16; fine_i8.len()];
    for (cluster, fine) in fine_i8.iter().enumerate() {
        let cell = assign_cluster(fine, &refs) as usize;
        clusters_of_cell[cell].push(cluster as u16);
        counts[cell] += 1;
        cell_of_cluster_argmin[cluster] = cell as u16;
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
    let argmin_cells = Cells {
        rows: rows.clone(),
        clusters_of_cell,
        counts,
        iterations: trained.iterations,
        fine: fine_i8.to_vec(),
        cell_of_cluster: cell_of_cluster_argmin,
    };

    // Карта 2 — назначение при обучении верхнего уровня. `balanced_assign` переливает точку
    // только во второй ближайший центроид, поэтому ёмкость 16 на верхнем уровне **не**
    // выдерживается: `E-0009` зафиксировал ячейки 4…30. Assert заменён печатью — измерение
    // должно довести прогон до recall, а не оборваться на первом же факте неровности (факт
    // зафиксирован в `E-0009`).
    let mut train_clusters = vec![Vec::new(); k];
    let mut train_counts = vec![0u32; k];
    let mut train_cell_of_cluster = vec![0u16; fine_i8.len()];
    for (cluster, &cell) in trained.assignment.iter().enumerate() {
        train_clusters[cell as usize].push(cluster as u16);
        train_counts[cell as usize] += 1;
        train_cell_of_cluster[cluster] = cell;
    }
    // `balanced_assign` переливает точку только во второй ближайший центроид, поэтому ёмкость
    // 16 на верхнем уровне **не** выдерживается: `E-0009` зафиксировал ячейки 4…30. Assert
    // заменён печатью — измерение должно довести прогон до recall, а не оборваться на первом
    // же факте неровности (факт зафиксирован в `E-0009`).
    let uneven = train_counts
        .iter()
        .filter(|&&n| n as usize != CLUSTERS_PER_SHARD as usize)
        .count();
    if uneven > 0 {
        println!(
            "ВАЖНО: назначение при обучении НЕ даёт ровных шардов — неровных ячеек {uneven} \
             из {} (см. `E-0009`); карта используется как есть",
            train_counts.len()
        );
    }
    let train_cells = Cells {
        rows,
        clusters_of_cell: train_clusters,
        counts: train_counts,
        iterations: trained.iterations,
        fine: fine_i8.to_vec(),
        cell_of_cluster: train_cell_of_cluster,
    };
    (argmin_cells, train_cells)
}

/// Карта шардов с **ровно** `CLUSTERS_PER_SHARD` кластерами в каждом: рекурсивное деление
/// центроидов пополам по оси максимальной дисперсии, делённое по медиане.
///
/// Баланс получается по построению, а не «починкой» готовой карты: `E-0008` показал, что
/// перенос вытесняемых кластеров рвёт связность (recall 0,9549 → 0,9055), а `E-0009` показал,
/// что ёмкость в обучении k-means тоже не выдерживается. Деление задаёт форму ячейки до того,
/// как связность станет важной.
///
/// Требования: `nlist` кратно 16, а частное — степень двойки (тогда каждое деление пополам
/// остаётся целым до групп по 16). Порядок листьев — обход в глубину, детерминированный.
fn build_balanced_cells(centroids_f32: &[f32], nlist: usize) -> Cells {
    let target = CLUSTERS_PER_SHARD as usize;
    assert!(
        nlist % target == 0,
        "nlist={nlist} не кратно {target} — ровная карта невозможна"
    );
    let groups = nlist / target;
    assert!(
        groups.is_power_of_two(),
        "частное nlist/{target} = {groups} не степень двойки — деление пополам не покрывает карту"
    );
    let mut leaves: Vec<Vec<u16>> = Vec::new();
    let all: Vec<usize> = (0..nlist).collect();
    split_balanced(all, centroids_f32, &mut leaves);
    assert_eq!(leaves.len(), groups, "получено {} ячеек вместо {groups}", leaves.len());

    let mut cell_of_cluster = vec![0u16; nlist];
    let mut counts = vec![0u32; groups];
    let mut rows = Vec::with_capacity(groups);
    for (cell, members) in leaves.iter().enumerate() {
        assert_eq!(
            members.len(),
            target,
            "ячейка {cell} содержит {} кластеров вместо {target}",
            members.len()
        );
        counts[cell] = members.len() as u32;
        // Центроид ячейки — среднее её кластеров: нужен для оценки «до центроида ячейки».
        let mut mean = vec![0f64; DIM];
        for &m in members {
            let row = m as usize * DIM;
            for d in 0..DIM {
                mean[d] += f64::from(centroids_f32[row + d]);
            }
        }
        for v in mean.iter_mut() {
            *v /= members.len() as f64;
        }
        let row: [i8; DIM] = quantize_slice(&mean).expect("центроид ячейки квантуется");
        rows.push(row);
        for &m in members {
            cell_of_cluster[m as usize] = cell as u16;
        }
    }
    Cells {
        rows,
        clusters_of_cell: leaves,
        counts,
        iterations: 0,
        fine: Vec::new(),
        cell_of_cluster,
    }
}

/// Рекурсивное деление группы пополам по оси максимальной дисперсии.
fn split_balanced(mut members: Vec<usize>, centroids_f32: &[f32], leaves: &mut Vec<Vec<u16>>) {
    let target = CLUSTERS_PER_SHARD as usize;
    if members.len() <= target {
        assert_eq!(members.len(), target, "остаток деления не кратен {target}");
        leaves.push(members.iter().map(|&m| m as u16).collect());
        return;
    }
    // Ось максимальной дисперсии внутри группы.
    let mut best_dim = 0usize;
    let mut best_var = -1f64;
    for d in 0..DIM {
        let n = members.len() as f64;
        let mean = members.iter().map(|&m| f64::from(centroids_f32[m * DIM + d])).sum::<f64>() / n;
        let var = members
            .iter()
            .map(|&m| {
                let x = f64::from(centroids_f32[m * DIM + d]) - mean;
                x * x
            })
            .sum::<f64>()
            / n;
        if var > best_var {
            best_var = var;
            best_dim = d;
        }
    }
    members.sort_unstable_by(|&a, &b| {
        let va = centroids_f32[a * DIM + best_dim];
        let vb = centroids_f32[b * DIM + best_dim];
        va.total_cmp(&vb).then(a.cmp(&b))
    });
    let mid = members.len() / 2;
    let right = members.split_off(mid);
    split_balanced(members, centroids_f32, leaves);
    split_balanced(right, centroids_f32, leaves);
}

/// Перебалансировка карты до **ровно** `CLUSTERS_PER_SHARD` кластеров в ячейке.
///
/// Замерённая карта (int8-argmin по грубым центроидам) даёт ячейки разного размера (4…30 на
/// 50k), а протокол требует ровно 16 кластеров на шард (`CLUSTERS_PER_SHARD`) — иначе
/// `shard_of_cluster(c) = c / 16` перестаёт быть контрактом. Внедряемый вариант — перенумерация
/// строк таблицы центроидов: каждому шарду отдаётся ровно 16 близких кластеров.
///
/// Правило жадное и детерминированное: из ячейки с избытком вытесняется самый дальний от её
/// центроида кластер, дефицитной ячейке достаётся ближайший по центроиду; порядок обработки —
/// по убыванию размера, затем по индексу ячейки.
fn rebalance_exact(cells: &Cells) -> Cells {
    let target = CLUSTERS_PER_SHARD as usize;
    let mut clusters_of_cell: Vec<Vec<u16>> = cells.clusters_of_cell.clone();
    loop {
        let over: Vec<usize> = (0..clusters_of_cell.len())
            .filter(|&c| clusters_of_cell[c].len() > target)
            .collect();
        if over.is_empty() {
            break;
        }
        let from = over
            .iter()
            .copied()
            .max_by_key(|&c| (clusters_of_cell[c].len(), std::cmp::Reverse(c)))
            .expect("есть ячейка с избытком");
        let centroid = &cells.rows[from];
        let pos = clusters_of_cell[from]
            .iter()
            .enumerate()
            .max_by_key(|&(i, &cl)| {
                (l2_sq(centroid, &cells.fine[cl as usize]), std::cmp::Reverse(i))
            })
            .map(|(i, _)| i)
            .expect("ячейка непуста");
        let moved = clusters_of_cell[from].remove(pos);
        let to = (0..clusters_of_cell.len())
            .filter(|&c| c != from && clusters_of_cell[c].len() < target)
            .min_by_key(|&c| (l2_sq(&cells.fine[moved as usize], &cells.rows[c]), c))
            .expect("суммарный избыток равен дефициту");
        clusters_of_cell[to].push(moved);
    }
    let counts = clusters_of_cell.iter().map(|c| c.len() as u32).collect();
    let mut cell_of_cluster = vec![0u16; cells.cell_of_cluster.len()];
    for (cell, members) in clusters_of_cell.iter().enumerate() {
        for &m in members {
            cell_of_cluster[m as usize] = cell as u16;
        }
    }
    Cells {
        rows: cells.rows.clone(),
        clusters_of_cell,
        counts,
        iterations: cells.iterations,
        fine: cells.fine.clone(),
        cell_of_cluster,
    }
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
