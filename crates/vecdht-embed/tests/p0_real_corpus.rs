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
//! `H-0007`/`E-0007`: шард = грубая ячейка из 16 пространственно близких кластеров;
//! `VEC_DHT_P0_INTRA=1` — резка скана внутри ячейки по `t` кластерам (`H-0017`/`E-0018`);
//! `VEC_DHT_P0_SUB=1` — третий уровень IVF, скан по `s` подспискам кластера
//! (`H-0020`/`E-0021`); `VEC_DHT_P0_FACET=1` — фильтрованный поиск по корзине facet-поля
//! (`H-0019`/`E-0020`): гейт считается по немодифицированной кривой, фильтр измеряется поверх неё.

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
use vecdht_embed::shardmap;
use vecdht_embed::text::normalize_text;
use vecdht_embed::EmbeddingModel;
use vecdht_wire::{CLUSTERS_PER_SHARD, NLIST};

const TOP_K: usize = 10;
const NPROBE_GATE: usize = 16;
/// Потолок владельцев на один запрос — §7.5 (fan-out). В групповой заявке он жёсткий:
/// заявка, не уместившаяся в 16 владельцев, отбрасывается.
const MAX_OWNERS: usize = 16;
const MAX_ITERS: usize = 12;
/// Потолок итераций целочисленного Lloyd для третьего уровня (`H-0020`). Фиксирован до прогона:
/// число подсписков `m` задаётся окружением, а вот это — нет, иначе «сходимость» можно было бы
/// покупать итерациями.
const SUB_MAX_ITERS: usize = 16;
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
    // H-0013/E-0013: размер шарда как параметр стенда. При значении по умолчанию (протокольные
    // 16) прогон обязан совпасть числами с `E-0012`; любое другое значение даёт геометрию, которую
    // текущий протокол выразить не может (`SHARDS = 64` — static_assert в `vecdht-wire`, а манифест
    // сверяет `clusters_per_shard` с константой), поэтому она именуется гипотетической.
    let cps: usize = match std::env::var("VEC_DHT_P0_CLUSTERS_PER_SHARD") {
        Ok(raw) => raw
            .parse()
            .expect("VEC_DHT_P0_CLUSTERS_PER_SHARD — целое число кластеров на шард"),
        Err(_) => CLUSTERS_PER_SHARD as usize,
    };
    assert!(
        cps > 0 && nlist % cps == 0,
        "nlist={nlist} не делится на размер шарда {cps}: ровная карта невозможна"
    );
    if cps != CLUSTERS_PER_SHARD as usize {
        println!(
            "ГЕОМЕТРИЯ ВНЕ ПРОТОКОЛА: {cps} кластеров на шард вместо {CLUSTERS_PER_SHARD} — при \
             nlist={nlist} это {} шардов, а `vecdht-wire` объявляет SHARDS=64 и \
             `shard_of_cluster(c) = c / {CLUSTERS_PER_SHARD}`. Числа относятся к гипотетической \
             геометрии и становятся протокольными только со стадии 1 плана v9 (геометрия как данные \
             манифеста).",
            nlist / cps
        );
    }
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
    // H-0012/E-0012: ровная (ровно 16 кластеров на шард) И связная карта: транспортная задача
    // вместо int8-argmin. Это «честная» ровная карта — в отличие от жадной починки `E-0008`
    // и рекурсивного деления `E-0011`.
    let coherent = matches!(std::env::var("VEC_DHT_P0_COHERENT").as_deref(), Ok("1"));
    // H-0016/E-0017: модель co-hosting'а — сколько ячеек карты держит один владелец. Бюджет §7.5
    // («не более 16 владельцев») при этом считается владельцами, а не шардами: два шарда могут
    // лежать на одном узле, и `NodeCert.shards` — список. 0 — режим выключен.
    let owner_cells: usize = std::env::var("VEC_DHT_P0_OWNER_CELLS")
        .ok()
        .map(|raw| raw.parse::<usize>().expect("VEC_DHT_P0_OWNER_CELLS — целое число"))
        .unwrap_or(0);
    assert!(
        owner_cells == 0 || (coarse && owner_cells >= 2),
        "VEC_DHT_P0_OWNER_CELLS имеет смысл только вместе с VEC_DHT_P0_COARSE=1 и значением ≥2"
    );
    // H-0017/E-0018: резка скана внутри шарда. Выбранных ячеек по-прежнему ≤16 (бюджет §7.5), но
    // в каждой сканируется только t ближайших мелких кластеров из cps. Лестница в этом режиме идёт
    // по t, а не по числу ячеек; точка t = cps обязана повторить `E-0012` — это контроль
    // инертности, а не точка порога. Режим выключен (переключатель не задан) — полный скан шарда,
    // как в протоколе.
    let intra = matches!(std::env::var("VEC_DHT_P0_INTRA").as_deref(), Ok("1"));
    assert!(
        !intra || coarse,
        "VEC_DHT_P0_INTRA имеет смысл только вместе с VEC_DHT_P0_COARSE=1"
    );
    assert!(
        !intra || (owner_cells == 0 && !grouped),
        "INTRA, OWNERS и GROUPED — три разные политики скана; вместе они не определяют скан"
    );
    // H-0020/E-0021: третий уровень IVF — подсписки внутри мелкого кластера. Ячейки выбираются
    // тем же гейтным правилом и в том же бюджете §7.5 (≤16 владельцев), карта остаётся
    // протокольной, но единицей отбора становится не кластер, а его подсписок. Лестница идёт по
    // s — числу ближайших подсписков на кластер; точка s = subm обязана повторить `E-0012`.
    let sub = matches!(std::env::var("VEC_DHT_P0_SUB").as_deref(), Ok("1"));
    let subm: usize = std::env::var("VEC_DHT_P0_SUBM")
        .ok()
        .map(|raw| raw.parse::<usize>().expect("VEC_DHT_P0_SUBM — целое число подсписков"))
        .unwrap_or(8);
    assert!(
        !sub || (coarse && coherent),
        "VEC_DHT_P0_SUB имеет смысл только на протокольной карте: VEC_DHT_P0_COARSE=1 \
         VEC_DHT_P0_COHERENT=1 (числа сверяются с `E-0012`)"
    );
    assert!(
        !sub || (owner_cells == 0 && !grouped && !intra),
        "SUB, INTRA, OWNERS и GROUPED — разные политики скана; вместе они не определяют скан"
    );
    assert!(
        subm >= 2,
        "VEC_DHT_P0_SUBM={subm} бессмыслен: при одном подсписке резки нет"
    );
    // H-0019/E-0020: facet-фильтр. Протокол поля ещё не содержит (ни TLV-тега, ни 8 Б в записи,
    // ни `Find.filter`), поэтому режим измеряет **цену введения**, а не существующую механику:
    // тот же протокольный скан ≤16 ячеек карты `E-0012`, но запись участвует в contract-сортировке
    // только если её корзина совпала с фильтром запроса. Предикат не зависит от запроса, значит
    // §8.4 (побайтовая сходимость двух реализаций) не затрагивается — это и есть аргумент стадии 3.
    let facet = matches!(std::env::var("VEC_DHT_P0_FACET").as_deref(), Ok("1"));
    let facet_buckets: usize = std::env::var("VEC_DHT_P0_FACET_BUCKETS")
        .ok()
        .map(|raw| raw.parse::<usize>().expect("VEC_DHT_P0_FACET_BUCKETS — целое число корзин"))
        .unwrap_or(10);
    let facet_arm = std::env::var("VEC_DHT_P0_FACET_ARM").unwrap_or_else(|_| "text".to_string());
    assert!(
        (2..=100).contains(&facet_buckets),
        "VEC_DHT_P0_FACET_BUCKETS={facet_buckets}: за пределами осмысленного (доля корзины должна \
         быть измеримой, а id корзины — умещаться в u8)"
    );
    assert!(
        facet_arm == "text" || facet_arm == "random",
        "VEC_DHT_P0_FACET_ARM={facet_arm}: допустимы только text (дециль длины пассажи) и \
         random (контрольная рука, геометрию не видит)"
    );
    assert!(
        !facet || (coarse && coherent),
        "VEC_DHT_P0_FACET имеет смысл только на протокольной карте: VEC_DHT_P0_COARSE=1 \
         VEC_DHT_P0_COHERENT=1 (числа сверяются с `E-0012`)"
    );
    assert!(
        !facet || (owner_cells == 0 && !grouped && !intra && !sub),
        "FACET — отдельная политика скана; с OWNERS, GROUPED, INTRA и SUB она не определяет скан"
    );
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
        !coherent || coarse,
        "VEC_DHT_P0_COHERENT имеет смысл только вместе с VEC_DHT_P0_COARSE=1"
    );
    assert!(
        !(coherent && (balanced || train_map || exact_shards)),
        "VEC_DHT_P0_COHERENT задаёт карту, отличную от BALANCED/TRAIN_MAP/EXACT_SHARDS"
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
    if facet {
        println!(
            "режим FACET: поверх протокольного скана ≤{MAX_OWNERS} ячеек карта `E-0012` — фильтр \
             по корзине (рука {facet_arm}, корзин {facet_buckets}, селективность {:.1} %); \
             корзина запроса = номер запроса mod корзин, ground truth — brute-force по корзине. \
             Немодифицированная кривая того же прогона остаётся гейтом и контролем инертности",
            100.0 / facet_buckets as f64
        );
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
            nlist / cps
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
        coarse.then(|| build_cells(&trained.centroids, &centroid_store, nlist, cps, threads));
    let cells = cell_maps.as_ref().map(|(argmin, _)| argmin);
    let train_cells = cell_maps.as_ref().map(|(_, train)| train);
    // Протокольный вид карты: жадная перебалансировка до ровно 16 кластеров на ячейку.
    let exact_cells = cells.map(rebalance_exact);
    // Ровная карта, построенная делением, а не починкой (`H-0011`/`E-0011`): рекурсивное
    // деление центроидов по оси максимальной дисперсии до групп ровно по 16.
    let balanced_cells =
        balanced.then(|| build_balanced_cells(&trained.centroids, nlist, cps));
    // Ровная И связная карта (`H-0012`/`E-0012`): транспортная задача — оптимальное
    // назначение мелких центроидов в ячейки при жёсткой ёмкости 16.
    let coherent_cells = (coarse && coherent)
        .then(|| build_coherent_cells(&trained.centroids, &centroid_store, nlist, cps, threads));
    if let Some(bc) = &balanced_cells {
        let sizes = &bc.counts;
        let min = sizes.iter().copied().min().unwrap_or(0);
        let max = sizes.iter().copied().max().unwrap_or(0);
        println!(
            "BALANCED (рекурсивное деление): {} ячеек над {nlist} кластерами; размер ячейки \
             min {min} / max {max} (ровно {cps} ожидалось)",
            bc.rows.len()
        );
        assert!(
            sizes.iter().all(|&n| n as usize == cps),
            "карта ровных шардов неровная: {sizes:?}"
        );
    }

    if let Some(ex) = &exact_cells {
        let sizes = &ex.counts;
        let min = sizes.iter().copied().min().unwrap_or(0);
        let max = sizes.iter().copied().max().unwrap_or(0);
        println!(
            "COARSE (ровные шарды, жадная правка): размер ячейки min {min} / max {max} \
             (ровно {cps} ожидалось)"
        );
        if exact_shards {
            // Протокольная карта обязана быть ровной: иначе `shard_of_cluster(c) = c / 16`
            // не описывает шард, и измеренный recall относится не к той геометрии.
            assert!(
                sizes.iter().all(|&n| n as usize == cps),
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
             (ровно {cps} ожидалось)"
        );
    }
    if let Some(cc) = &coherent_cells {
        let sizes = &cc.counts;
        let min = sizes.iter().copied().min().unwrap_or(0);
        let max = sizes.iter().copied().max().unwrap_or(0);
        println!(
            "COHERENT (транспортная задача): {} ячеек над {nlist} кластерами; размер ячейки \
             min {min} / max {max} (ровно {cps} ожидалось), разброс внутри \
             шарда {:.0} (int8 l2_sq до центроида шарда)",
            cc.rows.len(),
            cell_dispersion(cc)
        );
        if let Some(ac) = &cells {
            println!(
                "COARSE (int8-argmin) для сравнения: разброс внутри ячейки {:.0}",
                cell_dispersion(ac)
            );
        }
    }
    // Карта, по которой считается гейт: int8-argmin (E-0007), жадная правка (E-0008),
    // назначение при обучении (E-0009), рекурсивное деление (E-0011) или транспортная
    // задача (E-0012).
    let gate_map: Option<&Cells> = if coherent {
        coherent_cells.as_ref()
    } else if balanced {
        balanced_cells.as_ref()
    } else if train_map {
        train_cells
    } else if exact_shards {
        exact_cells.as_ref()
    } else {
        cells
    };
    // Правило оценки ячейки для гейта: в режиме карты обучения и в режиме транспортной
    // задачи — «ближайший кластер» (это внедряемая клиентская политика: блок из 16 строк
    // оценивается минимумом по строкам), в остальных — пред-регистрированное «до центроида
    // ячейки».
    let gate_score =
        if train_map || coherent { CellScore::NearestFine } else { CellScore::Centroid };
    // H-0016/E-0017: размещение строится по той же карте, по которой считается гейт, — иначе
    // измерялась бы политика поверх другой геометрии, чем та, что дала recall.
    let owners = (owner_cells != 0)
        .then(|| build_owners(gate_map.expect("режим владельцев требует карты ячеек"), owner_cells));
    // H-0020/E-0021: третий уровень IVF. Строится над теми же int8-векторами корпуса и тем же
    // присваиванием §7.2, что видит узел, — поэтому sub-центроиды зависят только от выпускаемой
    // таблицы центроидов и корпуса, а не от запроса. Offline-цена (её платит издатель один раз)
    // измеряется и печатается: без неё «бесплатный» третий уровень был бы неверным утверждением.
    let subs = sub.then(|| {
        let started = Instant::now();
        let built = build_sublists(&members, &corpus_i8, subm, threads);
        print_sublist_stats(&built, corpus_i8.len(), started.elapsed().as_secs_f64());
        built
    });

    if let Some(c) = &cells {
        let sizes = &c.counts;
        let min = sizes.iter().copied().min().unwrap_or(0);
        let max = sizes.iter().copied().max().unwrap_or(0);
        let over = sizes.iter().filter(|&&n| n as usize > cps).count();
        let empty = sizes.iter().filter(|&&n| n == 0).count();
        println!(
            "COARSE: {} ячеек над {nlist} кластерами, k-means top-level за {} итераций; \
             размер ячейки min {min} / max {max} (ровно {} ожидалось), over_cap={over}, пустых={empty}",
            c.rows.len(),
            c.iterations,
            cps
        );
        println!(
            "COARSE: fan-out при nprobe={NPROBE_GATE} ячейках ≤{MAX_OWNERS} шардов, скан {} \
             кластеров ({}% nlist) — против {cps} кластеров у пересечения",
            NPROBE_GATE * cps,
            NPROBE_GATE * cps * 100 / nlist
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

    // H-0019/E-0020: facet-корзины, фильтр запроса и **фильтрованный** ground truth. Правило
    // назначения фильтра зафиксировано пре-регистрацией и не подлежит подбору: корзина запроса =
    // `номер_запроса mod buckets`, так что все корзины проверяются равномерно и по одной на запрос.
    let facets: Option<Facets> = facet.then(|| {
        let arm = if facet_arm == "text" { FacetArm::TextLength } else { FacetArm::Random };
        let started = Instant::now();
        let built = build_facets(&corpus, corpus_i8.len(), arm, facet_buckets);
        print_facet_stats(&built, corpus_i8.len(), started.elapsed().as_secs_f64());
        built
    });
    let ftruth: Option<Vec<Vec<u32>>> = facets.as_ref().map(|f| {
        let started = Instant::now();
        let t = parallel_map(query_i8.len(), threads, |qi| {
            brute_force_filtered(&corpus_i8, &query_i8[qi], f, facet_of(qi, f.buckets))
        });
        println!(
            "фильтрованный ground truth: brute-force по корзине каждого запроса для {} запросов \
             за {:.1} с (расстояние считается только для записей нужной корзины — предикат не \
             зависит от запроса, поэтому пропуск не меняет правильного ответа)",
            query_i8.len(),
            started.elapsed().as_secs_f64()
        );
        t
    });

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
    if owner_cells != 0 {
        probes = vec![1usize, 2, 4, 8, 12, MAX_OWNERS];
        println!(
            "режим OWNERS: владелец держит {owner_cells} ячеек карты; nprobe — бюджет владельцев \
             (§7.5), сканируются только выбранные ячейки, работа ≤ nprobe × owner_cells × {cps} \
             кластеров; дополнительная проверка «до грубого центроида» в этом режиме не считается"
        );
    }
    if intra {
        probes = vec![1usize, 2, 4, 8, 12, cps];
        probes.retain(|&t| t <= cps);
        println!(
            "режим INTRA: ячеек выбирается всегда ≤{MAX_OWNERS} (бюджет §7.5), в каждой сканируется \
             t ближайших мелких кластеров из {cps}; лестница идёт по t, точка t={cps} — контроль \
             инертности (обязана повторить `E-0012`); дополнительная проверка «до грубого \
             центроида» в этом режиме не считается"
        );
    }

    if sub {
        probes = vec![1usize, 2, 3, 4, 6, subm];
        probes.retain(|&s| s <= subm);
        println!(
            "режим SUB: ячеек выбирается всегда ≤{MAX_OWNERS} (бюджет §7.5), в каждом из {cps} \
             кластеров ячейки сканируются s ближайших подсписков из {subm}; лестница идёт по s, \
             точка s={subm} — контроль инертности (обязана повторить `E-0012`); дополнительная \
             проверка «до грубого центроида» в этом режиме не считается"
        );
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
        owners.as_deref(),
        intra,
        subs.as_ref(),
        sub,
    );
    print_curve("s/t/nprobe  recall@10   fan-out avg/max   candidates avg   время", &points);

    // Дополнительное измерение для решения ADR-0004 (клиентская политика выбора ячеек):
    // ячейка оценивается минимумом `l2_sq` по её 16 мелким центроидам вместо расстояния до
    // собственного центроида ячейки. Оно НЕ заменяет пред-регистрированное основное правило
    // и не влияет на гейт: если основное правило не проходит, это остаётся провалом опыта.
    if coarse && !grouped && owner_cells == 0 && !intra && !sub {
        // Дополнительное измерение — второе правило оценки ячейки на той же карте. Гейтом не
        // является: если основное правило не проходит, это остаётся провалом опыта.
        let (aux_map, aux_score, aux_label) = if coherent {
            (
                gate_map,
                CellScore::Centroid,
                "ДОПОЛНИТЕЛЬНОЕ ПРАВИЛО ОЦЕНКИ ШАРДА (не гейт): до грубого центроида ячейки",
            )
        } else if train_map {
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
            None,
            false,
            None,
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

    if sub {
        // Порог `H-0020`: успех — существует s < subm с работой ≤ 0,5 × полного скана и
        // recall@10 ≥ 0,95 при ≤16 владельцах. Контроль (s = subm) печатается отдельной строкой:
        // не совпадёт с `E-0012` — прогон недействителен.
        let control = points
            .iter()
            .find(|p| p.nprobe == subm)
            .expect("лестница SUB обязана содержать точку s = subm (контроль)");
        let best = points
            .iter()
            .filter(|p| p.nprobe < subm && p.fanout_max <= MAX_OWNERS)
            .filter(|p| p.candidates_avg <= 0.5 * control.candidates_avg)
            .max_by(|a, b| a.recall.total_cmp(&b.recall));
        println!(
            "КОНТРОЛЬ SUB (s={subm}): recall@10 = {:.4} при {:.1} кандидатах, владельцев \
             {:.1}/{} — это тот же скан, что в `E-0012`",
            control.recall, control.candidates_avg, control.fanout_avg, control.fanout_max
        );
        match best {
            Some(p) => println!(
                "SUB (H-0020): лучшая точка при работе ≤ 0,5 × контроля: s={}, recall@10 = \
                 {:.4}, кандидатов {:.1} против {:.1}; порог 0,95 — {}",
                p.nprobe,
                p.recall,
                p.candidates_avg,
                control.candidates_avg,
                if p.recall >= 0.95 { "PASS" } else { "FAIL" }
            ),
            None => println!(
                "SUB (H-0020): ни одна точка лестницы не укладывается в 0,5 × работы контроля — \
                 лестница обязана содержать s < subm/2, прогон недействителен"
            ),
        }
        println!(
            "ЦЕНА ОТБОРА: {MAX_OWNERS} ячеек × {cps} кластеров × {subm} подсписков = {} \
             целочисленных l2_sq до sub-центроидов на запрос сверх кандидатов; при s ≥ subm эти \
             сравнения не делаются",
            MAX_OWNERS * cps * subm
        );
        if !smoke {
            assert!(
                best.is_some_and(|p| p.recall >= 0.95),
                "фальсификатор гейта (ii) по `H-0020`: при работе ≤ 0,5 × полного скана шарда нет \
                 recall@10 ≥ 0,95 (контроль s={subm}: {:.4}). Кривая выше; пре-регистрация `H-0020`",
                control.recall
            );
        }
    } else if intra {
        // Порог `H-0017`: успех — существует t < cps с работой ≤ 0,5 × полного скана и
        // recall@10 ≥ 0,95 при ≤16 владельцах. Контроль (t = cps) печатается отдельной строкой:
        // не совпадёт с `E-0012` — прогон недействителен.
        let control = points
            .iter()
            .find(|p| p.nprobe == cps)
            .expect("лестница INTRA обязана содержать точку t = cps (контроль)");
        let best = points
            .iter()
            .filter(|p| p.nprobe < cps && p.fanout_max <= MAX_OWNERS)
            .filter(|p| p.candidates_avg <= 0.5 * control.candidates_avg)
            .max_by(|a, b| a.recall.total_cmp(&b.recall));
        println!(
            "КОНТРОЛЬ INTRA (t={cps}): recall@10 = {:.4} при {:.1} кандидатах, владельцев \
             {:.1}/{} — это тот же скан, что в `E-0012`",
            control.recall, control.candidates_avg, control.fanout_avg, control.fanout_max
        );
        match best {
            Some(p) => println!(
                "INTRA (H-0017): лучшая точка при работе ≤ 0,5 × контроля: t={}, recall@10 = \
                 {:.4}, кандидатов {:.1} против {:.1}; порог 0,95 — {}",
                p.nprobe,
                p.recall,
                p.candidates_avg,
                control.candidates_avg,
                if p.recall >= 0.95 { "PASS" } else { "FAIL" }
            ),
            None => println!(
                "INTRA (H-0017): ни одна точка лестницы не укладывается в 0,5 × работы контроля — \
                 лестница обязана содержать t < cps/2, прогон недействителен"
            ),
        }
        println!(
            "ЦЕНА ОТБОРА: {MAX_OWNERS} ячеек × {cps} кластеров = {} целочисленных l2_sq до мелких \
             центроидов на запрос сверх кандидатов; при полном скане эти сравнения не делаются",
            MAX_OWNERS * cps
        );
        if !smoke {
            assert!(
                best.is_some_and(|p| p.recall >= 0.95),
                "фальсификатор гейта (ii) по `H-0017`: при работе ≤ 0,5 × полного скана шарда нет \
                 recall@10 ≥ 0,95 (контроль t={cps}: {:.4}). Кривая выше; пре-регистрация `H-0017`",
                control.recall
            );
        }
    } else if grouped {
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
        let unit = if owner_cells != 0 { "владельцев" } else { "ячеек" };
        println!(
            "COARSE{}: recall@10 = {recall_at_16:.4} при nprobe={NPROBE_GATE} {unit}, порог 0.95, \
             цель 0.98 — {}",
            if owner_cells != 0 {
                "-OWNERS (H-0016)"
            } else if coherent {
                "-COHERENT (H-0012)"
            } else if balanced {
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
    if !smoke && !grouped && !intra && !sub {
        let hint = if owner_cells != 0 {
            "OWNERS (H-0016): даже с co-hosting'ом 16 владельцев при карте c=8 не подняли recall \
             до 0.95 — выигрыш меньшей геометрии не переживает бюджет §7.5"
        } else if coarse && coherent {
            "COHERENT (H-0012): оптимальное ровное назначение (транспортная задача) не подняло \
             recall до 0.95 — «ровно 16 на шард» и «пространственная связность» несовместимы \
             при заданной верхней карте"
        } else if coarse && train_map {
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

    // H-0019/E-0020: фильтрованный поиск поверх той же протокольной кривой. Идётся **после**
    // гейта, а не вместо него: немодифицированная кривая выше — это контроль инертности, её числа
    // обязаны совпасть с `E-0012`, иначе фильтрованная часть прогона недействительна.
    if let (Some(facets), Some(ftruth)) = (facets.as_ref(), ftruth.as_ref()) {
        let base = points
            .iter()
            .find(|p| p.nprobe == NPROBE_GATE)
            .expect("кривая без фильтра обязана содержать точку nprobe=16 (контроль `E-0012`)");
        println!(
            "КОНТРОЛЬ FACET: скан без фильтра при nprobe={NPROBE_GATE} даёт recall@10 = {:.4} при \
             {:.1} кандидатах — это база, относительно которой считается потеря фильтра",
            base.recall, base.candidates_avg
        );
        let fp = run_facet_curve(
            &rows,
            &members,
            &corpus_i8,
            &query_i8,
            ftruth,
            facets,
            &probes,
            threads,
            gate_map,
            gate_score,
            &points,
        );
        print_facet_curve(facets, &fp);
        let at_gate = fp
            .iter()
            .find(|p| p.nprobe == NPROBE_GATE)
            .expect("фильтрованная кривая обязана содержать точку nprobe=16");
        let worst_bucket = at_gate
            .per_bucket
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min);
        let protocol_point = at_gate.nprobe <= MAX_OWNERS;
        println!(
            "FACET (H-0019): при nprobe={} ({} владельцев ≤ {MAX_OWNERS}, корректно по §7.5) \
             средняя потеря = {:.2} п.п. (recall {:.4} против {:.4}), худшая корзина {:.4}, \
             оценено {:.1} расстояний при {:.1} прочитанных записях (фильтр до MAC снимает {:.1} % \
             арифметики скана); порог 2,0 п.п. — {}",
            at_gate.nprobe,
            if protocol_point { "бюджет" } else { "вне бюджета" },
            at_gate.loss * 100.0,
            at_gate.recall,
            base.recall,
            worst_bucket,
            at_gate.candidates_avg,
            at_gate.scanned_avg,
            100.0 * (1.0 - at_gate.candidates_avg / at_gate.scanned_avg.max(1.0)),
            if at_gate.loss <= 0.02 { "PASS" } else { "FAIL" }
        );
        let first_passing = fp.iter().find(|p| p.recall >= 0.95);
        match first_passing {
            Some(p) => println!(
                "ЦЕНА ФИЛЬТРА В ЛЕСТНИЦЕ: первая точка с recall@10 ≥ 0,95 — nprobe={} (владельцев \
                 {}); {} — это {} сверх протокольного бюджета §7.5",
                p.nprobe,
                p.fanout_max,
                if p.nprobe > MAX_OWNERS { "точка" } else { "точка в бюджете" },
                p.nprobe.saturating_sub(MAX_OWNERS),
            ),
            None => println!(
                "ЦЕНА ФИЛЬТРА В ЛЕСТНИЦЕ: ни одна точка лестницы (вплоть до {} ячеек = весь \
                 корпус) не даёт recall@10 ≥ 0,95 с фильтром",
                probes.last().copied().unwrap_or(0)
            ),
        }
        if !smoke {
            assert!(
                at_gate.loss <= 0.02,
                "фальсификатор `H-0019`: при 10 % селективности и протокольном скане ≤{MAX_OWNERS} \
                 ячеек средняя потеря recall@10 из-за фильтра = {:.2} п.п. > 2,0 п.п. (recall \
                 {:.4} против {:.4} без фильтра, худшая корзина {:.4}). Пре-регистрация `H-0019`, \
                 кривая выше.",
                at_gate.loss * 100.0,
                at_gate.recall,
                base.recall,
                worst_bucket
            );
        }
    }
}

struct AnnRun {
    ids: Vec<u32>,
    fanout: usize,
    candidates: usize,
    /// Сколько записей выбранного скана **прочитано** — то есть попало в цикл до фильтра.
    /// Без фильтра (`E-0012`) совпадает с `candidates`; с фильтром (`H-0019`) показывает, какую
    /// часть работы узла снимает предикат, поставленный до вычисления расстояния.
    scanned: usize,
    /// Число владельцев **без** потолка §7.5 (16). Равняется `fanout`, когда потолок не
    /// связывает; в групповой заявке (`H-0010`) — реальное число разных шардов, которых
    /// коснулись K запрошенных кластеров.
    owners_uncapped: usize,
    /// Сколько из K запрошенных кластеров выпало из скана из-за потолка владельцев.
    dropped_clusters: usize,
    /// Результат того же запроса **без** потолка владельцев: показывает цену самого
    /// ограничения §7.5 отдельно от цены скана.
    ids_uncapped: Vec<u32>,
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
    /// Записей **прочитано** на запрос (до фильтра). Равно `candidates_avg` без фильтра;
    /// в режиме FACET (`H-0019`) показывает, какую долю арифметики скана снимает предикат.
    scanned_avg: f64,
    secs: f64,
    /// Recall того же запроса **без** потолка §7.5 (16 владельцев). Ненулевой только в
    /// групповой заявке: показывает, сколько даёт сам потолок, а сколько — геометрия скана.
    recall_uncapped: f64,
    /// Владельцев без потолка (в среднем по запросам) и выпавших из-за потолка кластеров.
    owners_uncapped_avg: f64,
    dropped_avg: f64,
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
    owners: Option<&[u16]>,
    intra: bool,
    subs: Option<&Sublists>,
    sub: bool,
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
                owners,
                intra,
                subs,
                None,
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
        let scanned: usize = runs.iter().map(|r| r.scanned).sum();
        // В режимах INTRA и SUB лестница идёт по числу кластеров/подсписков на шард, а ячейки
        // зафиксированы бюджетом §7.5, поэтому проверять надо против него.
        let budget = if intra || sub { MAX_OWNERS } else { nprobe };
        assert!(fanout_max <= budget, "fan-out {fanout_max} больше бюджета {budget}");
        if nprobe == NPROBE_GATE {
            recall_at_gate = recall;
        }
        // Цена потолка §7.5: тот же запрос без ограничения «не более 16 владельцев».
        let recall_uncapped = if runs.iter().all(|r| r.ids_uncapped.is_empty()) {
            0.0
        } else {
            let per_query_un: Vec<f64> = runs
                .iter()
                .zip(truth)
                .map(|(r, t)| recall_at_k(t, &r.ids_uncapped, TOP_K))
                .collect();
            per_query_un.iter().sum::<f64>() / per_query_un.len() as f64
        };
        let owners_uncapped_avg =
            runs.iter().map(|r| r.owners_uncapped).sum::<usize>() as f64 / runs.len() as f64;
        let dropped_avg =
            runs.iter().map(|r| r.dropped_clusters).sum::<usize>() as f64 / runs.len() as f64;
        points.push(CurvePoint {
            nprobe,
            recall,
            recall_min,
            fanout_avg: fanout_sum as f64 / runs.len() as f64,
            fanout_max,
            candidates_avg: candidates as f64 / runs.len() as f64,
            scanned_avg: scanned as f64 / runs.len() as f64,
            secs: started.elapsed().as_secs_f64(),
            recall_uncapped,
            owners_uncapped_avg,
            dropped_avg,
        });
    }
    (points, recall_at_gate)
}

/// Печать кривой. В групповой заявке добавляются колонки цены потолка §7.5: recall без
/// ограничения «16 владельцев», число владельцев без потолка и число выпавших кластеров.
fn print_curve(header: &str, points: &[CurvePoint]) {
    let grouped = points.iter().any(|p| p.recall_uncapped > 0.0);
    println!("{header}");
    for p in points {
        // Колонка «прочитано» появляется только там, где фильтр снимает часть арифметики
        // (режим FACET): без неё прочитанное равно оцененному и печатать нечего.
        let read = if p.scanned_avg > p.candidates_avg {
            format!("  прочитано {:>9.1}", p.scanned_avg)
        } else {
            String::new()
        };
        if grouped {
            println!(
                "{:>6}  {:.4} (min {:.2})  {:>5.1}/{:<3}        {:>8.1}       {:.1} с{}   без потолка {:.4}  владельцев без потолка {:>5.1}  выпало {:>4.1}",
                p.nprobe,
                p.recall,
                p.recall_min,
                p.fanout_avg,
                p.fanout_max,
                p.candidates_avg,
                p.secs,
                read,
                p.recall_uncapped,
                p.owners_uncapped_avg,
                p.dropped_avg
            );
        } else {
            println!(
                "{:>6}  {:.4} (min {:.2})  {:>5.1}/{:<3}        {:>8.1}       {:.1} с{}",
                p.nprobe,
                p.recall,
                p.recall_min,
                p.fanout_avg,
                p.fanout_max,
                p.candidates_avg,
                p.secs,
                read
            );
        }
    }
}

/// Точка фильтрованной кривой (`H-0019`): те же метрики, что у `CurvePoint`, плюс цена фильтра
/// (прочитано против оценено) и разрез по корзинам, потому что порог гипотезы — **средняя**
/// потеря, а вывод по averages прятал бы худшую корзину.
struct FacetPoint {
    nprobe: usize,
    recall: f64,
    recall_min: f64,
    /// Потеря против того же скана без фильтра (`E-0012`) при том же `nprobe`, в долях.
    loss: f64,
    /// Средняя recall@10 по запросам каждой корзины (`per_bucket[b]`).
    per_bucket: Vec<f64>,
    fanout_avg: f64,
    fanout_max: usize,
    /// Оценено расстояний на запрос.
    candidates_avg: f64,
    /// Прочитано записей на запрос (скан до фильтра).
    scanned_avg: f64,
    secs: f64,
}

/// Фильтрованная кривая: тот же протокольный скан, что в `E-0012`, но в contract-сортировку
/// попадает только корзина, совпавшая с фильтром запроса, и ground truth — brute-force по этой
/// же корзине (`ftruth`). Политика выбора ячеек не меняется: §7.5.1, бюджет `nprobe` ячеек.
#[allow(clippy::too_many_arguments)]
fn run_facet_curve(
    rows: &[&[i8; DIM]],
    members: &[Vec<u32>],
    corpus: &[[i8; DIM]],
    query_i8: &[[i8; DIM]],
    ftruth: &[Vec<u32>],
    facets: &Facets,
    probes: &[usize],
    threads: usize,
    cells: Option<&Cells>,
    score: CellScore,
    base: &[CurvePoint],
) -> Vec<FacetPoint> {
    let mut points = Vec::with_capacity(probes.len());
    for &nprobe in probes {
        let started = Instant::now();
        let runs: Vec<AnnRun> = parallel_map(query_i8.len(), threads, |qi| {
            ann_search(
                rows,
                members,
                corpus,
                &query_i8[qi],
                nprobe,
                false,
                cells,
                score,
                false,
                None,
                false,
                None,
                Some((facets, facet_of(qi, facets.buckets))),
            )
        });
        let per_query: Vec<f64> = runs
            .iter()
            .zip(ftruth)
            .map(|(r, t)| recall_at_k(t, &r.ids, TOP_K))
            .collect();
        let recall = per_query.iter().sum::<f64>() / per_query.len() as f64;
        let recall_min = per_query.iter().copied().fold(f64::INFINITY, f64::min);
        let mut per_bucket = vec![0.0f64; facets.buckets];
        let mut bucket_n = vec![0usize; facets.buckets];
        for (b, r) in per_query.iter().enumerate().map(|(i, v)| (usize::from(facet_of(i, facets.buckets)), v)) {
            per_bucket[b] += r;
            bucket_n[b] += 1;
        }
        for (avg, n) in per_bucket.iter_mut().zip(&bucket_n) {
            *avg /= (*n).max(1) as f64;
        }
        let fanout_max = runs.iter().map(|r| r.fanout).max().unwrap_or(0);
        assert!(fanout_max <= nprobe, "fan-out {fanout_max} больше бюджета {nprobe}");
        let base_recall = base
            .iter()
            .find(|p| p.nprobe == nprobe)
            .map(|p| p.recall)
            .unwrap_or(f64::NAN);
        points.push(FacetPoint {
            nprobe,
            recall,
            recall_min,
            loss: base_recall - recall,
            per_bucket,
            fanout_avg: runs.iter().map(|r| r.fanout).sum::<usize>() as f64 / runs.len() as f64,
            fanout_max,
            candidates_avg: runs.iter().map(|r| r.candidates).sum::<usize>() as f64 / runs.len() as f64,
            scanned_avg: runs.iter().map(|r| r.scanned).sum::<usize>() as f64 / runs.len() as f64,
            secs: started.elapsed().as_secs_f64(),
        });
    }
    points
}

fn print_facet_curve(facets: &Facets, points: &[FacetPoint]) {
    println!(
        "FACET ({} корзин, рука {}): nprobe  recall@10 (min)  потеря п.п.  fan-out  оценено  \
         прочитано  время",
        facets.buckets,
        match facets.arm {
            FacetArm::TextLength => "дециль длины текста",
            FacetArm::Random => "случайная — контроль корреляции",
        }
    );
    for p in points {
        print!("{:>6}  {:.4} (min {:.2})  {:>6.2}  {:>5.1}/{:<3}  {:>9.1}  {:>9.1}  {:.1} с", p.nprobe, p.recall, p.recall_min, p.loss * 100.0, p.fanout_avg, p.fanout_max, p.candidates_avg, p.scanned_avg, p.secs);
        if p.nprobe == NPROBE_GATE {
            print!("   по корзинам: {}", format_bucket_recalls(&p.per_bucket));
        }
        println!();
    }
}

fn format_bucket_recalls(per_bucket: &[f64]) -> String {
    let mut out = String::new();
    for (b, r) in per_bucket.iter().enumerate() {
        if b > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b}:{r:.4}"));
    }
    out
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
    owners: Option<&[u16]>,
    intra: bool,
    subs: Option<&Sublists>,
    // Facet-фильтр (`H-0019`): `(корзины корпуса, нужная корзина)`. `None` — скан без фильтра,
    // то есть ровно `E-0012`.
    filter: Option<(&Facets, u8)>,
) -> AnnRun {
    // `(скан, владельцы, скан без потолка, владельцы без потолка, выпавшие кластеры)`.
    // Последние три — диагностика цены потолка §7.5: они показывают, сколько recall теряется
    // именно из-за ограничения «не более 16 владельцев», а не из-за самого скана.
    let (scan_clusters, fanout, scan_uncapped, owners_uncapped, dropped) = if let Some(own) = owners {
        // Политика `H-0016`: выбор идёт между ячейками (гранулярность карты), а платёж —
        // владельцами (бюджет §7.5). Обход ячеек по гейтной сортировке §7.5.1: ячейка
        // берётся, если её владелец уже взят (вторая ячейка пары достаётся бесплатно) или
        // если использовано ещё меньше `nprobe` владельцев. Сканируются только выбранные
        // ячейки: `Find` несёт номер шарда, просто два шарда лежат на одном узле.
        let c = cells.expect("режим владельцев требует карты ячеек");
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
        let mut used: Vec<u16> = Vec::with_capacity(nprobe);
        let mut chosen: Vec<u16> = Vec::with_capacity(nprobe * 2);
        for (_, cell) in scored {
            let owner = own[cell as usize];
            if used.contains(&owner) {
                chosen.push(cell);
            } else if used.len() < nprobe {
                used.push(owner);
                chosen.push(cell);
            }
        }
        let mut scan: Vec<u16> = Vec::with_capacity(chosen.len() * c.cps);
        for cell in &chosen {
            scan.extend_from_slice(&c.clusters_of_cell[*cell as usize]);
        }
        (scan, used.len(), Vec::new(), used.len(), 0)
    } else if grouped {
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
        let owners_uncapped = per.len();
        let mut scan_all: Vec<u16> = Vec::with_capacity(nearest.len());
        for (_, clusters) in &per {
            scan_all.extend_from_slice(clusters);
        }
        scan_all.sort_unstable();
        scan_all.dedup();
        per.truncate(MAX_OWNERS);
        let mut scan: Vec<u16> = Vec::with_capacity(nearest.len());
        for (_, clusters) in &per {
            scan.extend_from_slice(clusters);
        }
        scan.sort_unstable();
        scan.dedup();
        let dropped = scan_all.len() - scan.len();
        (scan, per.len(), scan_all, owners_uncapped, dropped)
    } else if let Some(c) = cells {
        // Зонд единица — грубая ячейка. Выбранные ячейки — шарды; каждый сканирует свои
        // кластеры целиком (ёмкость карты — `cells.cps`), дублей нет.
        // Бюджет §7.5 связывает число ячеек и в INTRA, и в SUB: там лестница идёт по
        // числу кластеров/подсписков, а не по числу владельцев.
        let budget = if intra || subs.is_some() { MAX_OWNERS } else { nprobe };
        let chosen = match score {
            CellScore::Centroid => {
                let refs: Vec<&[i8; DIM]> = c.rows.iter().collect();
                top_clusters(query, &refs, budget)
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
                scored.truncate(budget.min(scored.len()));
                scored.into_iter().map(|(_, cell)| cell).collect()
            }
        };
        // Резка скана внутри ячейки (`H-0017`): остаются t ближайших мелких кластеров, порядок —
        // `(l2_sq, cluster_id)`, то есть те же целочисленные сравнения, что делает узел по
        // квантованному вектору запроса (§5). При выключенном режиме и при t ≥ размера ячейки
        // берётся весь список, и ветка совпадает с `E-0012` без единого лишнего сравнения.
        let mut scan: Vec<u16> = Vec::with_capacity(chosen.len() * c.cps);
        for cell in &chosen {
            let clusters = &c.clusters_of_cell[*cell as usize];
            if intra && nprobe < clusters.len() {
                let mut ranked: Vec<(u32, u16)> = clusters
                    .iter()
                    .map(|&cl| (l2_sq(query, centroids[cl as usize]), cl))
                    .collect();
                ranked.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
                scan.extend(ranked.iter().take(nprobe).map(|(_, cl)| *cl));
            } else {
                scan.extend_from_slice(clusters);
            }
        }
        let fanout = chosen.len();
        (scan, fanout, Vec::new(), fanout, 0)
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
        (scan, fanout, Vec::new(), fanout, 0)
    };
    let mut top = TopK::new();
    let mut candidates = 0;
    let mut scanned = 0usize;
    // Число подсписков на кластер: в режиме SUB лестница идёт по s, поэтому s — это nprobe;
    // вне режима SUB — бесконечность, то есть кластер сканируется целиком (`E-0012`).
    let s = if subs.is_some() { nprobe } else { usize::MAX };
    for cluster in scan_clusters {
        for list in scan_lists(members, subs, cluster as usize, query, s) {
            for &id in list {
                scanned += 1;
                // Фильтр стоит **до** вычисления расстояния: предикат зависит только от идентификатора
                // записи, поэтому пропуск снимает у узла работу (целочисленное MAC-сравнение — самая
                // дорогая часть скана), но не меняет множество записей, которые прошли бы фильтр и
                // попали бы в contract-сортировку. §8.4 при этом не затрагивается.
                if let Some((facets, want)) = filter {
                    if facets.slot[id as usize] != want {
                        continue;
                    }
                }
                top.push(l2_sq(query, &corpus[id as usize]), id);
                candidates += 1;
            }
        }
    }
    let ids_uncapped = if scan_uncapped.is_empty() {
        Vec::new()
    } else {
        let mut top_un = TopK::new();
        for cluster in scan_uncapped {
            for &id in &members[cluster as usize] {
                top_un.push(l2_sq(query, &corpus[id as usize]), id);
            }
        }
        top_un.ids()
    };
    AnnRun {
        ids: top.ids(),
        fanout,
        candidates,
        scanned,
        owners_uncapped,
        dropped_clusters: dropped,
        ids_uncapped,
    }
}

/// Третий уровень IVF (`H-0020`/`E-0021`): подсписки внутри мелкого кластера. Объект существует
/// только в стенде; если гипотеза подтвердится, он становится полем артефакта (§15.1) и шагом
/// построения (§7.6), а отбор подсписков — частью политики скана (§8.4).
struct Sublists {
    /// `lists[cluster][sub]` — id записей корпуса в подсписке.
    lists: Vec<Vec<Vec<u32>>>,
    /// `centroids[cluster][sub]` — целочисленный sub-центроид того же подсписка.
    centroids: Vec<Vec<[i8; DIM]>>,
    /// Заявленное `m`; кластер короче `m` получает `min(m, |cluster|)` подсписков.
    m: usize,
    /// Худшее число итераций Lloyd по всем кластерам.
    max_iters_used: usize,
    /// Суммарное число переприсваиваний «участник → подсписок» за всё обучение.
    reassignments: usize,
}

fn build_sublists(
    members: &[Vec<u32>],
    corpus: &[[i8; DIM]],
    m: usize,
    threads: usize,
) -> Sublists {
    let per_cluster = parallel_map(members.len(), threads, |cluster| {
        let built = sublist_cluster(&members[cluster], corpus, m);
        // Инвариант: подсписки — разбиение кластера, без потерь и дублей. Если он нарушится,
        // «экономия работы» считалась бы по неполному покрытию, и дефект построения выглядел
        // бы как плохой механизм отбора.
        let total: usize = built.0.iter().map(Vec::len).sum();
        assert_eq!(
            total,
            members[cluster].len(),
            "кластер {cluster}: подсписки покрыли {total} записей из {}",
            members[cluster].len()
        );
        built
    });
    let mut subs = Sublists {
        lists: Vec::with_capacity(per_cluster.len()),
        centroids: Vec::with_capacity(per_cluster.len()),
        m,
        max_iters_used: 0,
        reassignments: 0,
    };
    for (lists, centroids, iters, reassignments) in per_cluster {
        subs.max_iters_used = subs.max_iters_used.max(iters);
        subs.reassignments += reassignments;
        subs.lists.push(lists);
        subs.centroids.push(centroids);
    }
    subs
}

/// Один кластер → его подсписки и sub-центроиды. Всё целыми числами: инициализация
/// farthest-first по `l2_sq`, затем Lloyd с целочисленным средним.
fn sublist_cluster(
    ids: &[u32],
    corpus: &[[i8; DIM]],
    m: usize,
) -> (Vec<Vec<u32>>, Vec<[i8; DIM]>, usize, usize) {
    if ids.is_empty() {
        return (Vec::new(), Vec::new(), 0, 0);
    }
    let k = m.min(ids.len());
    // Первый центр — участник с наименьшим id (`ids` упорядочены по id при построении карты),
    // каждый следующий — максимально удалённый от уже взятых, при равенстве — наименьший id.
    // Генератора нет, поэтому построение воспроизводимо без seed'а вообще.
    let mut chosen: Vec<usize> = vec![0usize];
    let mut nearest: Vec<u32> =
        ids.iter().map(|&id| l2_sq(&corpus[ids[0] as usize], &corpus[id as usize])).collect();
    while chosen.len() < k {
        let mut best: Option<(u32, usize)> = None;
        for (pos, &d) in nearest.iter().enumerate() {
            if chosen.contains(&pos) {
                continue;
            }
            match best {
                None => best = Some((d, pos)),
                Some((bd, _)) if d > bd => best = Some((d, pos)),
                _ => {}
            }
        }
        let Some((_, pos)) = best else { break };
        chosen.push(pos);
        for (p, d) in nearest.iter_mut().enumerate() {
            let nd = l2_sq(&corpus[ids[pos] as usize], &corpus[ids[p] as usize]);
            if nd < *d {
                *d = nd;
            }
        }
    }
    let mut centroids: Vec<[i8; DIM]> =
        chosen.iter().map(|&pos| corpus[ids[pos] as usize]).collect();
    let mut assign = vec![0u8; ids.len()];
    let mut iters = 0usize;
    let mut reassignments = 0usize;
    loop {
        iters += 1;
        let mut changed = 0usize;
        for (pos, &id) in ids.iter().enumerate() {
            let mut best_sub = 0usize;
            let mut best_d = u32::MAX;
            for (sub, c) in centroids.iter().enumerate() {
                let d = l2_sq(&corpus[id as usize], c);
                // Строгое сравнение: при равенстве остаётся меньший номер подсписка — тот же
                // tie-break, что у `top_clusters`, и он же делает разбиение однозначным.
                if d < best_d {
                    best_d = d;
                    best_sub = sub;
                }
            }
            if assign[pos] as usize != best_sub {
                changed += 1;
                assign[pos] = best_sub as u8;
            }
        }
        reassignments += changed;
        if changed == 0 || iters >= SUB_MAX_ITERS {
            break;
        }
        let mut next = Vec::with_capacity(centroids.len());
        for sub in 0..centroids.len() {
            let of_sub: Vec<u32> = ids
                .iter()
                .enumerate()
                .filter(|(p, _)| assign[*p] as usize == sub)
                .map(|(_, &id)| id)
                .collect();
            // Подсписок мог опустеть после переприсваивания: центр остаётся прежним, иначе
            // среднее от пустого набора делило бы на ноль.
            next.push(if of_sub.is_empty() { centroids[sub] } else { int_mean(&of_sub, corpus) });
        }
        centroids = next;
    }
    let mut lists: Vec<Vec<u32>> = vec![Vec::new(); centroids.len()];
    for (pos, &sub) in assign.iter().enumerate() {
        lists[sub as usize].push(ids[pos]);
    }
    (lists, centroids, iters, reassignments)
}

/// Целочисленное среднее строк int8 с округлением вверх при остатке ≥ половины делителя — без
/// float, чтобы две корректные реализации (§8.4) не могли разъехаться на ничьей.
fn int_mean(ids: &[u32], corpus: &[[i8; DIM]]) -> [i8; DIM] {
    let cnt = i64::try_from(ids.len()).expect("размер кластера влезает в i64");
    let mut out = [0i8; DIM];
    for d in 0..DIM {
        let mut sum = 0i64;
        for &id in ids {
            sum += i64::from(corpus[id as usize][d]);
        }
        let q = sum.div_euclid(cnt);
        let r = sum.rem_euclid(cnt);
        let v = if 2 * r >= cnt { q + 1 } else { q };
        out[d] = i64::from(i8::MIN).max(v).min(i64::from(i8::MAX)) as i8;
    }
    out
}

/// Единицы скана внутри кластера: целый кластер (протокольный полный скан `E-0012` и контроль
/// `s = m`) либо `s` ближайших подсписков (`H-0020`). Отбор — int8-argmin по sub-центроидам с
/// разрывом равенства по номеру подсписка, то есть целочисленный и contract-определимый, как §7.2.
fn scan_lists<'a>(
    members: &'a [Vec<u32>],
    subs: Option<&'a Sublists>,
    cluster: usize,
    query: &[i8; DIM],
    s: usize,
) -> Vec<&'a [u32]> {
    let Some(subs) = subs else {
        return vec![members[cluster].as_slice()];
    };
    let lists = &subs.lists[cluster];
    if lists.is_empty() || s >= lists.len() {
        return vec![members[cluster].as_slice()];
    }
    let mut ranked: Vec<(u32, u16)> = subs.centroids[cluster]
        .iter()
        .enumerate()
        .map(|(sub, c)| (l2_sq(query, c), sub as u16))
        .collect();
    ranked.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    ranked.iter().take(s).map(|(_, sub)| lists[*sub as usize].as_slice()).collect()
}

/// Цена третьего уровня, которую платит издатель: offline-время и лишние байты артефакта.
fn print_sublist_stats(subs: &Sublists, corpus_len: usize, secs: f64) {
    let mut min = usize::MAX;
    let mut max = 0usize;
    let mut total = 0usize;
    let mut empty = 0usize;
    let mut centroids = 0usize;
    for lists in &subs.lists {
        centroids += lists.len();
        for list in lists {
            total += list.len();
            min = min.min(list.len());
            max = max.max(list.len());
            if list.is_empty() {
                empty += 1;
            }
        }
    }
    let min = if subs.lists.is_empty() { 0 } else { min };
    let overhead = centroids * DIM;
    println!(
        "SUB: третий уровень построен за {secs:.1} с — {} кластеров, {centroids} sub-центроидов \
         при m={}, размер подсписка min {min} / max {max}, средний {:.1}, пустых {empty}; \
         переприсваиваний {}, \
         худшее число итераций {}; overhead артефакта {overhead} Б (m × {DIM} int8 на кластер) \
         против {} Б записей корпуса (424 Б × {corpus_len}), то есть {:.2} %",
        subs.lists.len(),
        subs.m,
        total as f64 / centroids.max(1) as f64,
        subs.reassignments,
        subs.max_iters_used,
        corpus_len * 424,
        overhead as f64 * 100.0 / (corpus_len as f64 * 424.0)
    );
}

/// Верхний уровень карты шардов для режима COARSE: `k = nlist / cps` грубых центроидов над
/// замороженными, `balance_cap = cps`, чтобы шард держал ровно `cps` кластеров (в протоколе 16,
/// `H-0013` измеряет 8). Ячейка кластера — int8-argmin, тот же контракт, что у присваивания записи (§7.2).
struct Cells {
    /// Ёмкость ячейки, из которой карта построена: в протоколе `CLUSTERS_PER_SHARD` = 16, а
    /// `H-0013` измеряет 8. Это поле, а не константа: иначе карта из 8 кластеров не отличалась бы
    /// от карты из 16 ни в assert'е ровности, ни в скане, и неровность уехала бы молча в recall.
    cps: usize,
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
    cps: usize,
    threads: usize,
) -> (Cells, Cells) {
    let k = nlist / cps;
    assert!(k > 0, "nlist={nlist} меньше одного шарда из {cps} кластеров");
    let cfg = KMeansConfig { k, max_iters: MAX_ITERS, seed: SEED ^ 0x0007, balance_cap: cps };
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
        cps,
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
        .filter(|&&n| n as usize != cps)
        .count();
    if uneven > 0 {
        println!(
            "ВАЖНО: назначение при обучении НЕ даёт ровных шардов — неровных ячеек {uneven} \
             из {} (см. `E-0009`); карта используется как есть",
            train_counts.len()
        );
    }
    let train_cells = Cells {
        cps,
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
/// Требования: `nlist` кратно `cps`, а частное — степень двойки (тогда каждое деление пополам
/// остаётся целым до групп по `cps`). Порядок листьев — обход в глубину, детерминированный.
fn build_balanced_cells(centroids_f32: &[f32], nlist: usize, cps: usize) -> Cells {
    let target = cps;
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
    split_balanced(all, centroids_f32, target, &mut leaves);
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
        cps: target,
        rows,
        clusters_of_cell: leaves,
        counts,
        iterations: 0,
        fine: Vec::new(),
        cell_of_cluster,
    }
}

/// Рекурсивное деление группы пополам по оси максимальной дисперсии.
fn split_balanced(
    mut members: Vec<usize>,
    centroids_f32: &[f32],
    target: usize,
    leaves: &mut Vec<Vec<u16>>,
) {
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
    split_balanced(members, centroids_f32, target, leaves);
    split_balanced(right, centroids_f32, target, leaves);
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
    let target = cells.cps;
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
        cps: target,
        rows: cells.rows.clone(),
        clusters_of_cell,
        counts,
        iterations: cells.iterations,
        fine: cells.fine.clone(),
        cell_of_cluster,
    }
}

/// Размещение ячеек по владельцам для `H-0016`: жадная детерминированная сборка групп по
/// `per_owner` ячеек. Первая несобранная ячейка по номеру берётся как затравка, к ней
/// добавляются `per_owner-1` ближайших по грубым центроидам (tie-break — номер ячейки).
///
/// Это **модель** co-hosting'а, а не механизм сети: какие именно шарды отдавать одному узлу,
/// решает §7.6 и балансировка, и у модели есть своя цена (потеря владельца уносит сразу два
/// шарда). Здесь она нужна ровно для одного вопроса — сколько из выигрыша меньшей геометрии
/// переживает бюджет «≤16 владельцев».
fn build_owners(cells: &Cells, per_owner: usize) -> Vec<u16> {
    let n = cells.rows.len();
    let mut owner_of = vec![u16::MAX; n];
    let mut next = 0u16;
    for seed in 0..n {
        if owner_of[seed] != u16::MAX {
            continue;
        }
        owner_of[seed] = next;
        let mut cand: Vec<(u32, usize)> = (0..n)
            .filter(|&j| owner_of[j] == u16::MAX)
            .map(|j| (l2_sq(&cells.rows[seed], &cells.rows[j]), j))
            .collect();
        cand.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let mut taken = 1usize;
        for (_, j) in cand {
            if taken == per_owner {
                break;
            }
            owner_of[j] = next;
            taken += 1;
        }
        next += 1;
    }
    let owners = next as usize;
    assert!(
        owners * per_owner >= n && (owners - 1) * per_owner < n,
        "размещение {owners} владельцев по {per_owner} ячеек не покрывает {n} ячеек"
    );
    println!(
        "OWNERS: {n} ячеек собраны в {owners} владельцев по ≤{per_owner} ячеек (жадно по грубым \
         центроидам, детерминированно)"
    );
    owner_of
}

fn brute_force(corpus: &[[i8; DIM]], query: &[i8; DIM]) -> Vec<u32> {
    let mut top = TopK::new();
    for (id, point) in corpus.iter().enumerate() {
        top.push(l2_sq(query, point), id as u32);
    }
    top.ids()
}

/// Facet-поле записи (`H-0019`/`E-0020`). В предполагаемом протоколе это 8 Б: четыре слота
/// tag-hash u16 в каноническом порядке. В стенде — номер корзины на запись, потому что для
/// вопроса «сколько стоит фильтр» важны только селективность и то, что предикат не зависит от
/// запроса. Поля нет ни в `vecdht-wire`, ни в спеке: режим измеряет цену введения, а не
/// существующую механику.
struct Facets {
    /// `slot[id]` — корзина записи корпуса (0..buckets).
    slot: Vec<u8>,
    buckets: usize,
    arm: FacetArm,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FacetArm {
    /// Дециль длины канонического текста пассажи: метаданная реальная (видна в самом корпусе),
    /// назначение по рангу `(len, id)` — детерминировано и не зависит от эмбеддинга.
    TextLength,
    /// Контрольная рука: геометрию не видит, изолирует вклад корреляции facet ↔ пространство.
    Random,
}

/// Правило фильтра зафиксировано пре-регистрацией и не поддаётся подбору: корзина запроса =
/// `номер_запроса mod buckets`. Все корзины проверяются равномерно и ровно по одному фильтру
/// на запрос.
fn facet_of(qi: usize, buckets: usize) -> u8 {
    (qi % buckets) as u8
}

fn build_facets(texts: &[String], n: usize, arm: FacetArm, buckets: usize) -> Facets {
    assert_eq!(texts.len(), n, "facet строится по корпусу текстов и по int8-корпусу сразу");
    let slot = match arm {
        FacetArm::TextLength => {
            let mut order: Vec<(usize, u32)> = (0..n)
                .map(|i| (texts[i].chars().count(), i as u32))
                .collect();
            // Сортировка по `(длина, id)`: порядок строгий и не зависит от перестановки входа,
            // равные длины не образуют «скользящей» границы корзин.
            order.sort_unstable();
            let mut slot = vec![0u8; n];
            for (rank, (_, id)) in order.iter().enumerate() {
                slot[*id as usize] = (rank * buckets / n) as u8;
            }
            slot
        }
        FacetArm::Random => (0..n)
            .map(|i| (splitmix64(SEED ^ (i as u64)) % buckets as u64) as u8)
            .collect(),
    };
    let mut sizes = vec![0usize; buckets];
    for &b in &slot {
        sizes[usize::from(b)] += 1;
    }
    assert!(
        sizes.iter().all(|&s| s >= TOP_K),
        "есть корзина меньше TOP_K записей — фильтрованный ground truth был бы вырожден"
    );
    Facets { slot, buckets, arm }
}

fn print_facet_stats(facets: &Facets, n: usize, secs: f64) {
    let mut sizes = vec![0usize; facets.buckets];
    for &b in &facets.slot {
        sizes[usize::from(b)] += 1;
    }
    let min = sizes.iter().copied().min().unwrap_or(0);
    let max = sizes.iter().copied().max().unwrap_or(0);
    println!(
        "FACET: {} корзин построено за {secs:.1} с; размер корзины min {min} / max {max} при \
         среднем {:.1} ({:.2} % корпуса); overhead артефакта — 8 Б на запись (4 слота tag-hash \
         u16), то есть {} Б против {} Б записей корпуса (424 Б × {n}), {:.2} %; 1 Б корзины в \
         стенде соответствует одному слоту протокольного поля",
        facets.buckets,
        n as f64 / facets.buckets as f64,
        100.0 / facets.buckets as f64,
        8 * n,
        424 * n,
        800.0 / 42400.0,
    );
}

/// Детерминированный хеш для контрольной руки (`H-0019`): splitmix64, целые числа, без RNG-состояния.
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Фильтрованный ground truth: brute-force по корзине. Расстояние считается только для записей
/// нужной корзины — предикат не зависит от запроса, поэтому пропуск не меняет правильного ответа
/// и стоит ≈1/`buckets` полного brute-force прохода.
fn brute_force_filtered(
    corpus: &[[i8; DIM]],
    query: &[i8; DIM],
    facets: &Facets,
    want: u8,
) -> Vec<u32> {
    let mut top = TopK::new();
    for (id, point) in corpus.iter().enumerate() {
        if facets.slot[id] != want {
            continue;
        }
        top.push(l2_sq(query, point), id as u32);
    }
    top.ids()
}

/// Карта шардов с **ровно** `CLUSTERS_PER_SHARD` кластерами на шард и максимально возможной
/// пространственной связностью (`H-0012`/`E-0012`): транспортная задача.
///
/// Строится **библиотечной** функцией `vecdht_embed::shardmap::build_shard_map` — тем же кодом,
/// которым издатель строит порядок строк `centroid.bin` (§7.4.1, `ADR-0004`). Стенд не имеет
/// собственной копии решателя: иначе измеренное число относилось бы к коду, которого в
/// артефакте не будет.
///
/// Верхний уровень — k-means (k = nlist/16, cap = 16, seed `SEED ^ 0x0007`), а назначение
/// мелких центроидов в ячейки решается не int8-argmin'ом и не жадной починкой, а оптимальным
/// сбалансированным назначением: каждой из 64 ячеек ровно 16 кластеров при минимальной сумме
/// расстояний до грубых центроидов.
///
/// Отличие от предыдущих попыток: `E-0008` вытесняла из переполненной ячейки самый дальний
/// кластер (то есть выбрасывала «дальние» кластеры в чужие ячейки и рвала связность), а
/// `E-0011` резала пространство плоскостями. Здесь кластеры **меняются местами**: избыток
/// ячейки компенсируется обменом с дефицитной, и суммарная цена минимальна.
fn build_coherent_cells(
    centroids_f32: &[f32],
    fine_i8: &[[i8; DIM]],
    nlist: usize,
    cps: usize,
    threads: usize,
) -> Cells {
    let target = cps;
    assert!(nlist % target == 0, "nlist={nlist} не кратно {target}");
    let k = nlist / target;
    let cfg = KMeansConfig {
        k,
        max_iters: MAX_ITERS,
        seed: SEED ^ 0x0007,
        balance_cap: target,
    };
    let map = shardmap::build_shard_map(centroids_f32, fine_i8, target, cfg, threads)
        .expect("карта шардов строится");

    let mut clusters_of_cell: Vec<Vec<u16>> = vec![Vec::new(); k];
    for (cluster, &cell) in map.cell_of_cluster.iter().enumerate() {
        clusters_of_cell[cell as usize].push(cluster as u16);
    }
    for (cell, members) in clusters_of_cell.iter().enumerate() {
        assert_eq!(
            members.len(),
            target,
            "ячейка {cell} получила {} кластеров вместо {target} — ёмкость не выдержана",
            members.len()
        );
    }
    // Порядок публикации (то, что уедет в `centroid.bin`) обязан совпадать с картой: строка `p`
    // публикуется как кластер `p`, её шард — `p / 16`.
    for p in 0..map.order.len() {
        assert_eq!(
            map.cell_of_cluster[map.order[p] as usize] as usize,
            p / target,
            "опубликованный порядок нарушает контракт шарда в позиции {p}"
        );
    }
    let counts = clusters_of_cell.iter().map(|c| c.len() as u32).collect();
    Cells {
        cps: target,
        rows: map.coarse,
        clusters_of_cell,
        counts,
        iterations: map.iterations,
        fine: fine_i8.to_vec(),
        cell_of_cluster: map.cell_of_cluster,
    }
}

/// Связность карты одним числом: среднее по шардам расстояние от члена шарда до собственного
/// центроида шарда (int8, квадрат евклидова). Чем меньше, тем шард компактнее. Считается по
/// тем же данным, что и клиент, поэтому сравнимо между картами.
fn cell_dispersion(cells: &Cells) -> f64 {
    let mut sum = 0f64;
    let mut count = 0f64;
    for members in &cells.clusters_of_cell {
        if members.is_empty() {
            continue;
        }
        let mut mean = vec![0f64; DIM];
        for &m in members {
            let row = &cells.fine[m as usize];
            for (d, acc) in mean.iter_mut().enumerate() {
                *acc += f64::from(row[d]);
            }
        }
        for v in mean.iter_mut() {
            *v /= members.len() as f64;
        }
        let center: [i8; DIM] = quantize_slice(&mean).expect("центроид шарда квантуется");
        for &m in members {
            sum += f64::from(l2_sq(&cells.fine[m as usize], &center));
            count += 1.0;
        }
    }
    if count == 0.0 {
        0.0
    } else {
        sum / count
    }
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

/// Дайджест набора текстов для кеша эмбеддингов.
///
/// Формула живёт в crate ([`vecdht_embed::text::emb_digest`]), а не здесь: кеш должен быть общим и
/// для стенда, и для издателя (`artifact publish`). Две копии одной формулы разошлись бы при первой
/// же правке, и кеш стенда перестал бы подходить к корпусу — молча, без единой строки в выводе.
fn text_digest(model_version: &str, preprocessing_version: u16, texts: &[String]) -> [u8; 32] {
    vecdht_embed::text::emb_digest(model_version, preprocessing_version, texts)
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
