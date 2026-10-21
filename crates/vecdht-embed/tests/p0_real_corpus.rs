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
//! `VEC_DHT_P0_NLIST` — лестница §8.6: вниз до 512 (`E-0004`) и вверх до 8192 (`E-0025`, геометрия
//! вне протокола); `VEC_DHT_P0_SHARD_COMPLETE=1` —
//! полный скан выбранных шардов (`E-0005`); `VEC_DHT_P0_COARSE=1` — двухуровневая карта шардов
//! `H-0007`/`E-0007`: шард = грубая ячейка из 16 пространственно близких кластеров;
//! `VEC_DHT_P0_INTRA=1` — резка скана внутри ячейки по `t` кластерам (`H-0017`/`E-0018`);
//! `VEC_DHT_P0_SUB=1` — третий уровень IVF, скан по `s` подспискам кластера
//! (`H-0020`/`E-0021`); `VEC_DHT_P0_FACET=1` — фильтрованный поиск по корзине facet-поля
//! (`H-0019`/`E-0020`): гейт считается по немодифицированной кривой, фильтр измеряется поверх неё;
//! `VEC_DHT_P0_PQ=1` — двухстадийный скан (`H-0022`/`E-0023`): множество кандидатов остаётся
//! протокольным, но оценивается product quantization-кодом (`m` × 8 бит на подпространство), а
//! точный int8 считается только для глобальных top-R.

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
/// Число центроидов в подпространстве PQ (`H-0022`): 8 бит на подпространство, значит код записи
/// занимает ровно `m` байт. Фиксируется пре-регистрацией, а не подбирается по результату.
const PQ_K: usize = 256;
/// Потолок итераций целочисленного Lloyd для кодобука PQ — тот же, что у второго уровня IVF
/// (`MAX_ITERS`), чтобы «точность кода» нельзя было купить лишними проходами.
const PQ_MAX_ITERS: usize = MAX_ITERS;
/// Минимальное `R`, при котором требуется recall ≥ 0,95, и максимальное, при котором срабатывает
/// фальсификатор (а) `H-0022`. Оба числа — из пре-регистрации, не из данных прогона.
const PQ_R_TARGET: usize = 100;
const PQ_R_FALSIFIER: usize = 1024;
/// Размер справочной выборки ADC-ошибки: `PQ_ERR_QUERIES` запросов × `PQ_ERR_SAMPLE` записей
/// корпуса (первые id по порядку файла — это произвольный, не зависящий от запроса срез). Выборка
/// считается **отдельным проходом, вне измеряемой стадии**: иначе стенд читал бы int8-байты,
/// которые не учтены ни в байтовой модели условия (2), ни в тайминге условия (3), и PQ-рука
/// отличалась бы от int8-руки не только «числом байт на кандидата».
const PQ_ERR_SAMPLE: usize = 1024;
const PQ_ERR_QUERIES: usize = 200;
/// Доля записей протокольного скана, доказуемо исключаемых точной нижней оценкой: порог успеха и
/// фальсификатор `H-0023`. Оба числа взяты из пре-регистрации, не из данных прогона.
const BOUND_SUCCESS: f64 = 0.50;
const BOUND_FALSIFIER: f64 = 0.25;
/// Контроль инертности `E-0012` при nprobe=16: `(размер корпуса, recall@10, кандидатов)`.
/// Немодифицированная кривая этого же прогона обязана дать ровно эти числа: иначе PQ-рука
/// измерялась бы поверх другой геометрии, чем та, что даёт гейт.
const E0012_CONTROL: &[(usize, f64, f64)] =
    &[(50_000, 0.9645, 12_558.8), (807_596, 0.9790, 204_715.6)];
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
    // `H-0024`/`E-0025` разворачивает лестницу вверх: `NLIST = 1024` — контракт файла `centroid.bin`
    // (`SHARDS = 64` и `CENTROID_BYTES` в `vecdht-wire`), а не свойство измерения. Ground truth,
    // exact brute-force, контракт сортировки и бюджет ≤16 владельцев от nlist не зависят, поэтому
    // более мелкая геометрия проверяется ровно тем же оракулом — и такое nlist помечается ниже
    // строкой «ГЕОМЕТРИЯ ВНЕ ПРОТОКОЛА», как уже сделано для размера шарда.
    let nlist = match std::env::var("VEC_DHT_P0_NLIST") {
        Ok(raw) => raw.parse::<usize>().expect("VEC_DHT_P0_NLIST — целое число"),
        Err(_) => NLIST as usize,
    };
    assert!(
        nlist >= 16 && nlist % 16 == 0,
        "nlist={nlist} должен быть кратен 16 кластерам шарда и не быть меньше 16"
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
    if nlist > NLIST as usize {
        // Арифметика, ради которой существует этот прогон: бюджет §7.5 — `MAX_OWNERS` ячеек по
        // `cps` кластеров, то есть ровно `MAX_OWNERS × cps` кластеров на запрос, а доля корпуса в
        // скане — это `(MAX_OWNERS × cps) / nlist`. Она не зависит ни от правила отбора, ни от цены
        // байта, и потому падает только вместе с ростом nlist.
        println!(
            "ГЕОМЕТРИЯ ВНЕ ПРОТОКОЛА (`H-0024`): nlist={nlist} вместо протокольного {NLIST} — при \
             {cps} кластерах на шард это {} шардов, а `vecdht-wire` объявляет SHARDS=64 и \
             фиксирует `centroid.bin` ровно в {NLIST} строк; манифест такой артефакт не примет. \
             Числа относятся к гипотетической геометрии и становятся протокольными только со \
             стадии 1 плана v9. Доля корпуса в скане при бюджете {MAX_OWNERS} ячеек — {:.1} % \
             против {:.1} % при nlist={NLIST}.",
            nlist / cps,
            100.0 * (MAX_OWNERS * cps) as f64 / nlist as f64,
            100.0 * (MAX_OWNERS * cps) as f64 / NLIST as f64,
        );
    }
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
    // H-0021/E-0022: facet-осознанный отбор ячеек. Отличается от `E-0020` ровно одним — какие
    // ≤16 ячеек выбираются: не по грубому центроиду ячейки, а по целочисленному центроиду нужной
    // корзины внутри ячейки. Предикат, скан, contract-сортировка и ground truth не меняются,
    // поэтому числа двух прогонов сравнимы напрямую.
    let facet_aware = matches!(std::env::var("VEC_DHT_P0_FACET_AWARE").as_deref(), Ok("1"));
    assert!(
        !facet_aware || facet,
        "VEC_DHT_P0_FACET_AWARE без VEC_DHT_P0_FACET бессмыслен: корзины задаёт режим FACET"
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
             по корзине (рука {facet_arm}, корзин {facet_buckets}, доля корпуса {:.1} %); \
             корзина запроса = номер запроса mod корзин, ground truth — brute-force по корзине. \
             Немодифицированная кривая того же прогона остаётся гейтом и контролем инертности",
            100.0 / facet_buckets as f64
        );
    }
    if facet_aware {
        println!(
            "режим FACET-AWARE (`H-0021`): отбор ≤{MAX_OWNERS} ячеек идёт по целочисленному \
             центроиду **нужной корзины внутри ячейки**, а не по грубому центроиду ячейки; скан \
             внутри выбранной ячейки, предикат и contract-сортировка не меняются — отличается \
             только множество выбранных владельцев"
        );
    }
    // H-0022/E-0023: двухстадийный скан. Все четыре закрытых рычага цены (`E-0013`, `E-0017`,
    // `E-0018`, `E-0021`) и facet (`E-0020`, `E-0022`) меняли **сколько записей** попадает в скан;
    // этот режим меняет **сколько байт читается на одну попавшую в скан запись**: правило отбора
    // ячеек, fan-out и множество кандидатов остаются ровно картой `E-0012`.
    let pq = matches!(std::env::var("VEC_DHT_P0_PQ").as_deref(), Ok("1"));
    let pq_m: usize = std::env::var("VEC_DHT_P0_PQ_M")
        .ok()
        .map(|raw| raw.parse::<usize>().expect("VEC_DHT_P0_PQ_M — целое число подпространств"))
        .unwrap_or(24);
    let pq_r: usize = std::env::var("VEC_DHT_P0_PQ_R")
        .ok()
        .map(|raw| raw.parse::<usize>().expect("VEC_DHT_P0_PQ_R — целое число рефайнов"))
        .unwrap_or(PQ_R_TARGET);
    assert!(
        DIM % pq_m == 0 && DIM / pq_m % 8 == 0 && (8..=64).contains(&(DIM / pq_m)),
        "VEC_DHT_P0_PQ_M={pq_m}: подпространство должно делить {DIM} измерений и давать 8..64 \
         измерений, кратных 8, иначе код считается не тем целочисленным суммированием, что §7.2"
    );
    assert!(
        (1..=PQ_R_FALSIFIER).contains(&pq_r),
        "VEC_DHT_P0_PQ_R={pq_r}: за пределами зарегистрированной лестницы R (1..={PQ_R_FALSIFIER})"
    );
    assert!(
        !pq || (coarse && coherent),
        "VEC_DHT_P0_PQ имеет смысл только на протокольной карте: VEC_DHT_P0_COARSE=1 \
         VEC_DHT_P0_COHERENT=1 (числа сверяются с `E-0012`)"
    );
    assert!(
        !pq || (owner_cells == 0 && !grouped && !intra && !sub && !facet),
        "PQ — отдельная рука цены; с OWNERS, GROUPED, INTRA, SUB и FACET она не определена \
         пре-регистрацией `H-0022`"
    );
    if pq {
        println!(
            "режим PQ (`H-0022`): {DIM} измерений делятся на {pq_m} подпространств по {} с {} \
             центроидами (8 бит), код = {pq_m} Б на запись; кандидаты выбираются протокольной \
             картой (полный скан ≤{MAX_OWNERS} ячеек), оценка — ADC по целочисленной LUT, \
             рефайн — точный int8 глобальных top-R (R={pq_r}); немодифицированная кривая этого \
             же прогона остаётся контролем инертности `E-0012`",
            DIM / pq_m,
            PQ_K,
        );
    }
    // H-0023/E-0024: точная отсечка. Скан **не меняется физически**: отдельный проход считает,
    // сколько записей протокольного скана можно было бы не читать, если бы узел держал в метаданных
    // блока точную нижнюю оценку расстояний. Поэтому recall этого прогона побайтово равен гейту, а
    // предмет измерения — доля работы, снимаемая **без риска для качества** (в отличие от `E-0018`
    // и `E-0021`, где отсечка приближённая).
    let bound_prune = matches!(std::env::var("VEC_DHT_P0_BOUND_PRUNE").as_deref(), Ok("1"));
    assert!(
        !bound_prune || (coarse && coherent),
        "VEC_DHT_P0_BOUND_PRUNE имеет смысл только на протокольной карте: VEC_DHT_P0_COARSE=1 \
         VEC_DHT_P0_COHERENT=1 (числа сверяются с `E-0012`)"
    );
    assert!(
        !bound_prune || (owner_cells == 0 && !grouped && !intra && !sub && !facet && !pq),
        "BOUND_PRUNE — отдельная рука цены; с OWNERS, GROUPED, INTRA, SUB, FACET и PQ она не \
         определена пре-регистрацией `H-0023`"
    );
    if bound_prune {
        println!(
            "режим BOUND-PRUNE (`H-0023`): скан не изменён; для каждого блока (грубая ячейка и \
             мелкий кластер) считается точная нижняя оценка l2_sq — (н1) по максимуму нормы блока, \
             (н2) по померным min/max, порог отсечки — 10-е **точное** расстояние того же запроса \
             из exact brute-force (идеализация порога); печатается доля записей, которые можно \
             было не читать. Порог успеха ≥ {:.0} %, фальсификатор < {:.0} %.",
            BOUND_SUCCESS * 100.0,
            BOUND_FALSIFIER * 100.0
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
    // H-0022/E-0023: кодобук PQ и коды корпуса. Строится по **тем же** int8-векторам, что видит
    // узел, тем же целочисленным k-means, что и второй уровень (farthest-first по `l2_sq`,
    // Lloyd с целочисленным средним, порядок сложения по id), — иначе «код» был бы другой
    // геометрией, а не другим представлением той же. Offline-цена печатается: утверждение
    // «PQ дешевле» без стоимости обучения кодобука было бы неверным.
    let pq_obj = pq.then(|| {
        let started = Instant::now();
        let built = build_pq(&corpus_i8, pq_m, threads, &corpus_path);
        print_pq_stats(&built, corpus_i8.len(), started.elapsed().as_secs_f64());
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

    // H-0021/E-0022: центроид корзины внутри ячейки — то, по чему клиент выбирает ≤16 владельцев,
    // когда запрос несёт фильтр. Строится по уже квантованным int8-векторам корпуса тем же
    // целочисленным средним (`int_mean`), что и sub-центроиды `E-0021`: порядок сложения — по id
    // записи, значит значение воспроизводится издателем детерминированно и две корректные
    // реализации (§8.4) не разъедутся на ничьей. Пустая корзина в ячейке не имеет центроида и в
    // отборе участвует с оценкой `u32::MAX` — она не вытесняет содержательные ячейки.
    let cell_buckets: Option<CellBuckets> = if facet_aware {
        let f = facets.as_ref().expect("FACET_AWARE требует FACET: корзины задаёт он");
        let c = gate_map.expect("FACET_AWARE определён только на протокольной карте");
        let started = Instant::now();
        let built = build_cell_buckets(c, &members, &corpus_i8, f, threads);
        print_cell_bucket_stats(&built, corpus_i8.len(), started.elapsed().as_secs_f64());
        Some(built)
    } else {
        None
    };

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

    // В PQ-прогоне обе кривые идут до точки гейта: ни одно из трёх условий `H-0022` не проверяется
    // на nprobe > 16, а полный скан 64 ячеек корпуса 807k стоил бы прогону больше, чем измеряет.
    let ctl_probes: Vec<usize> = if pq {
        probes.iter().copied().filter(|&n| n <= NPROBE_GATE).collect()
    } else {
        probes.clone()
    };
    let (points, recall_at_16) = run_curve(
        &rows,
        &members,
        &corpus_i8,
        &query_i8,
        &truth,
        &ctl_probes,
        threads,
        shard_complete,
        gate_map,
        gate_score,
        grouped,
        owners.as_deref(),
        intra,
        subs.as_ref(),
        sub,
        // int8-кривая: она же гейт (ii), она же контроль инертности PQ-руки (`H-0022` требует
        // совпадения с `E-0012` в пределах допуска, который печатается явно).
        None,
    );
    print_curve("s/t/nprobe  recall@10   fan-out avg/max   candidates avg   время", &points);

    // H-0023/E-0024: точная отсечка. Сканы этого прогона не изменены ни на одну запись, поэтому
    // измеряется только доля работы, которую **можно было не делать**: отдельный проход по тем же
    // выбранным ячейкам сравнивает нижнюю оценку блока с 10-м точным расстоянием того же запроса.
    // Контроль инертности печатается здесь же, потому что без совпадения с `E-0012` доля считается
    // по другой геометрии, чем та, что даёт гейт.
    if bound_prune {
        print_control_inertness(&points, corpus_i8.len());
        let c = gate_map.expect("режим BOUND_PRUNE требует карты ячеек (COARSE + COHERENT)");
        let started = Instant::now();
        let bb = build_block_bounds(&corpus_i8, &members, c, threads);
        let build_secs = started.elapsed().as_secs_f64();
        let shares = bound_shares(
            &bb,
            c,
            &members,
            &rows,
            &corpus_i8,
            &query_i8,
            &truth,
            gate_score,
            threads,
            false,
        );
        // Положительный контроль: тот же проход при пороге 0. Он ничего не измеряет про гипотезу,
        // но отличает «оценка слабая» от «счётчик не работает».
        let spike = bound_shares(
            &bb,
            c,
            &members,
            &rows,
            &corpus_i8,
            &query_i8,
            &truth,
            gate_score,
            threads,
            true,
        );
        print_bound_verdict(&bb, c, &shares, &spike, query_i8.len(), corpus_i8.len(), build_secs);
    }

    if let Some(p) = pq_obj.as_ref() {
        print_control_inertness(&points, corpus_i8.len());
        // Справочная точность кода — отдельный проход вне обеих измеряемых кривых, поэтому он не
        // влияет на байтовый учёт условия (2) и на тайминг условия (3).
        let err = pq_error_sample(p, &corpus_i8, &query_i8, threads);
        // Лестница PQ-руки — те же точки, что у int8-базы: сравнение по одному числу ячеек.
        let (pq_points, _pq_recall) = run_curve(
            &rows,
            &members,
            &corpus_i8,
            &query_i8,
            &truth,
            &ctl_probes,
            threads,
            shard_complete,
            gate_map,
            gate_score,
            grouped,
            owners.as_deref(),
            intra,
            subs.as_ref(),
            sub,
            Some((p, pq_r)),
        );
        print_pq_curve(p.m, &pq_points);
        print_pq_verdict(p.m, pq_r, &points, &pq_points, err);
    }

    // Дополнительное измерение для решения ADR-0004 (клиентская политика выбора ячеек):
    // ячейка оценивается минимумом `l2_sq` по её 16 мелким центроидам вместо расстояния до
    // собственного центроида ячейки. Оно НЕ заменяет пред-регистрированное основное правило
    // и не влияет на гейт: если основное правило не проходит, это остаётся провалом опыта.
    if coarse && !grouped && owner_cells == 0 && !intra && !sub && !pq {
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
            None,
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
            cell_buckets.as_ref(),
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
            "FACET ({}): при nprobe={} ({} владельцев ≤ {MAX_OWNERS}, корректно по §7.5) \
             средняя потеря = {:.2} п.п. (recall {:.4} против {:.4}), худшая корзина {:.4}, \
             оценено {:.1} расстояний при {:.1} прочитанных записях (фильтр до MAC снимает {:.1} % \
             арифметики скана); {} — {}",
            if facet_aware { "H-0021, отбор по центроиду корзины" } else { "H-0019" },
            at_gate.nprobe,
            if protocol_point { "бюджет" } else { "вне бюджета" },
            at_gate.loss * 100.0,
            at_gate.recall,
            base.recall,
            worst_bucket,
            at_gate.candidates_avg,
            at_gate.scanned_avg,
            100.0 * (1.0 - at_gate.candidates_avg / at_gate.scanned_avg.max(1.0)),
            if facet_aware { "порог 0,95 recall@10 в бюджете" } else { "порог 2,0 п.п." },
            if facet_aware {
                if at_gate.recall >= 0.95 {
                    "PASS"
                } else {
                    "FAIL"
                }
            } else if at_gate.loss <= 0.02 {
                "PASS"
            } else {
                "FAIL"
            }
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
            if facet_aware {
                let best_in_budget = fp
                    .iter()
                    .filter(|p| p.nprobe <= MAX_OWNERS)
                    .fold(f64::NEG_INFINITY, |m, p| m.max(p.recall));
                assert!(
                    best_in_budget >= 0.95,
                    "фальсификатор `H-0021`: facet-осознанный отбор ячеек не оплачивает поле — \
                     лучший фильтрованный recall@10 при бюджете ≤{MAX_OWNERS} владельцев равен \
                     {best_in_budget:.4} < 0,95 (контроль без фильтра — {:.4}). Условие (а) из \
                     `ADR-0005` не выполнено, и facet остаётся только с отдельными списками. \
                     Пре-регистрация `H-0021`, кривая выше.",
                    base.recall
                );
            } else {
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
    /// Сколько записей точно переоценено int8 на стадии рефайна (`H-0022`). В int8-руке — то же
    /// число, что и `candidates`, потому что там рефайна нет: переоценивается всё.
    refined: usize,
    /// Секунды, проведённые в цикле скана (оценка кандидатов + рефайн), без загрузки корпуса,
    /// без отбора ячеек и без распаралливания. Измеряется одинаково в обеих руках, поэтому
    /// отношение чисел — это и есть цена «меньше байт на кандидата».
    stage_secs: f64,
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
    /// Среднее число записей, переоцененных точным int8 на запросе (`H-0022`). Вне PQ-руки равно
    /// `candidates_avg` — там рефайна нет.
    refined_avg: f64,
    /// Среднее время стадии скана на запрос, в миллисекундах (сумма по потокам делится на число
    /// запросов). Отношение int8/PQ при равном множестве кандидатов — условие (в) `H-0022`.
    stage_ms_avg: f64,
    /// Рука PQ (`H-0022`): отличает строку, где кандидатов оценивает код, от int8-строки, где их
    /// оценивает `l2_sq`. Поле, а не вывод из чисел: при `R ≥` числа кандидатов колонки
    /// «рефайнов» и «int8» совпадают, и отличить руки по ним было бы нельзя.
    pq_arm: bool,
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
    // Рука PQ (`H-0022`): `(кодобук и коды корпуса, R рефайна)`. `None` — int8-скан, то есть
    // ровно `E-0012`; множество кандидатов от этого не зависит.
    pq: Option<(&Pq, usize)>,
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
                None,
                pq,
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
        let refined_avg = runs.iter().map(|r| r.refined).sum::<usize>() as f64 / runs.len() as f64;
        let stage_ms_avg =
            runs.iter().map(|r| r.stage_secs).sum::<f64>() * 1000.0 / runs.len() as f64;
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
            refined_avg,
            stage_ms_avg,
            pq_arm: pq.is_some(),
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
                "{:>6}  {:.4} (min {:.2})  {:>5.1}/{:<3} {:>8.1} {:.1} с{} без потолка {:.4}  владельцев без потолка {:>5.1}  выпало {:>4.1}",
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
                "{:>6}  {:.4} (min {:.2})  {:>5.1}/{:<3} {:>8.1} {:.1} с{}",
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

/// Байтный расчёт условия (б) `H-0022`: на кандидата читается `m` Б кода, на рефайн — {DIM} Б
/// int8-записи; база сравнения — {DIM} Б на того же кандидата, то есть цена int8-скана этого же
/// протокольного множества. Числа арифметические и совпадают с пре-регистрацией: здесь нет ни
/// заголовков, ни сетевых пакетов, ни стоимости LUT.
fn pq_bytes(m: usize, candidates: f64, refined: f64) -> (f64, f64, f64) {
    let pq = m as f64 * candidates + DIM as f64 * refined;
    let int8 = DIM as f64 * candidates;
    (pq, int8, 100.0 * pq / int8)
}

/// Кривая PQ-руки (`H-0022`): те же метрики скана, что у `print_curve`, плюс цена стадии — число
/// рефайнов, байт на запрос и время цикла скана. Печатается отдельной функцией, потому что
/// «кандидат» в двух руках стоит разными байтами, и сводить их в одну таблицю значило бы прятать
/// условие (б) за общей колонкой.
fn print_pq_curve(m: usize, points: &[CurvePoint]) {
    println!(
        "PQ (m={m}, код {m} Б на запись): nprobe  recall@10 (min)  fan-out  кандидатов  рефайнов  Б/запрос  доля от int8  мс/стадия  время"
    );
    for p in points.iter().filter(|p| p.pq_arm) {
        let (bytes, _, share) = pq_bytes(m, p.candidates_avg, p.refined_avg);
        println!(
            "{:>6}  {:.4} (min {:.2})  {:>5.1}/{:<3}  {:>9.1}  {:>9.1}  {:>10.0}  {:>7.1} %  \
             {:>8.2}  {:.1} с",
            p.nprobe,
            p.recall,
            p.recall_min,
            p.fanout_avg,
            p.fanout_max,
            p.candidates_avg,
            p.refined_avg,
            bytes,
            share,
            p.stage_ms_avg,
            p.secs
        );
    }
}

/// Контроль инертности (`E-0023`): немодифицированная кривая этого же прогона при nprobe=16 обязана
/// повторить числа `E-0012`, иначе PQ-рука измерялась бы поверх другой геометрии, чем та, что даёт
/// гейт. Печатается явно и отдельно от таблицы: расхождение делает прогон недействительным, а не
/// «чуть хуже контроля».
fn print_control_inertness(points: &[CurvePoint], corpus_len: usize) {
    let Some(p) = points.iter().find(|x| x.nprobe == NPROBE_GATE) else {
        println!(
            "КОНТРОЛЬ ИНЕРТНОСТИ: кривая не содержит nprobe={NPROBE_GATE} — прогон недействителен"
        );
        return;
    };
    match E0012_CONTROL.iter().find(|(n, _, _)| *n == corpus_len) {
        Some((_, recall, cand)) => {
            let ok = (p.recall - recall).abs() <= 5e-5 && (p.candidates_avg - cand).abs() <= 0.1;
            println!(
                "КОНТРОЛЬ ИНЕРТНОСТИ `E-0012` (nprobe={NPROBE_GATE}): recall@10 = {:.4} при {:.1} кандидатах, ожидалось {recall:.4} при {cand:.1} — {}",
                p.recall,
                p.candidates_avg,
                if ok { "СОВПАЛО" } else { "РАСХОЖДЕНИЕ, ПРОГОН НЕДЕЙСТВИТЕЛЕН" }
            );
        }
        None => println!(
            "КОНТРОЛЬ ИНЕРТНОСТИ: корпус {corpus_len} не зарегистрирован в `E-0012` (известны {}) — сверка невозможна, числа приведены выше",
            E0012_CONTROL.iter().map(|(n, _, _)| n.to_string()).collect::<Vec<_>>().join("/")
        ),
    }
}

/// Вердикт `H-0022` по трём пре-регистрированным условиям. Ничего не assert'ится и прогон не
/// прерывается: рука обязана отпечататься при каждом R из лестницы {32, 100, 256, 1024}, а вывод
/// делается по собранной таблице, а не по первой упавшей точке.
fn print_pq_verdict(
    m: usize,
    r: usize,
    control: &[CurvePoint],
    pq: &[CurvePoint],
    err: (f64, f64, usize, usize),
) {
    let base = control.iter().find(|p| p.nprobe == NPROBE_GATE);
    let gate = pq.iter().find(|p| p.nprobe == NPROBE_GATE);
    let (Some(base), Some(gate)) = (base, gate) else {
        println!(
            "PQ (H-0022): nprobe={NPROBE_GATE} отсутствует в одной из кривых — прогон недействителен"
        );
        return;
    };
    let (bytes, int8, share) = pq_bytes(m, gate.candidates_avg, gate.refined_avg);
    let (err_med, err_p95, err_n, err_skip) = err;
    let speedup = if gate.stage_ms_avg > 0.0 { base.stage_ms_avg / gate.stage_ms_avg } else { 0.0 };
    println!("PQ (H-0022/E-0023): m={m}, код {m} Б на запись, R={r}, nprobe={NPROBE_GATE}:");
    println!(
        "  (1) recall@10 = {:.4} против exact brute-force (int8-база того же прогона {:.4}); порог 0,95 при R ≤ {PQ_R_TARGET}: recall {}, зарегистрированный бюджет R {} — {}",
        gate.recall,
        base.recall,
        if gate.recall >= 0.95 { "≥ 0,95" } else { "< 0,95" },
        if r <= PQ_R_TARGET { "выдержан" } else { "ПРЕВЫШЕН" },
        if gate.recall >= 0.95 && r <= PQ_R_TARGET { "PASS" } else { "FAIL" }
    );
    println!(
        "  (2) прочитано {:.0} Б на запрос ({} Б кода × {:.1} кандидатов + {DIM} Б × {:.1} рефайнов) против {:.0} Б int8-скана тех же кандидатов — доля {:.2} %, порог ≤ {:.2} % — {}",
        bytes,
        m,
        gate.candidates_avg,
        gate.refined_avg,
        int8,
        share,
        100.0 / 6.0,
        if share <= 100.0 / 6.0 { "PASS" } else { "FAIL" }
    );
    println!(
        "  (3) стадия скана: int8 {:.2} мс/запрос, PQ {:.2} мс/запрос → {:.2}× (порог ≥ 2× — {}); wall-time точки гейта {:.1} с против {:.1} с → {:.2}×",
        base.stage_ms_avg,
        gate.stage_ms_avg,
        speedup,
        if speedup >= 2.0 { "PASS" } else { "FAIL" },
        base.secs,
        gate.secs,
        if gate.secs > 0.0 { base.secs / gate.secs } else { 0.0 }
    );
    println!(
        "  справочно: относительная ADC-ошибка med {:.4} / p95 {:.4} по {err_n} парам «запрос × запись» (срез: {PQ_ERR_QUERIES} запросов × первые {PQ_ERR_SAMPLE} записей, {err_skip} пар с нулевым точным расстоянием отброшено); считается отдельным проходом вне измеряемой стадии и потому не входит ни в байты условия (2), ни в время условия (3). Фальсификатор (а) в намеренной формулировке звучит как «ни одна точка лестницы R ≤ {PQ_R_FALSIFIER} не даёт recall ≥ 0,95», поэтому по одной руке он не решается: эта рука при R={r} дает recall {:.4} — {}",
        err_med,
        err_p95,
        gate.recall,
        if gate.recall >= 0.95 { "эта точка ВЫШЕ 0,95, (а) опровергнут самой лестницей" } else { "эта точка ниже 0,95" }
    );
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
    buckets: Option<&CellBuckets>,
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
                buckets,
                None,
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
/// Отбор грубых ячеек при бюджете `budget` — **одна** реализация правила. Она вынесена из
/// `ann_search` не ради порядка кода: рука `E-0024` обязана считать долю пропусков по ровно тому
/// множеству ячеек, которое сканирует узел, а вторая копия правила гарантировала бы расхождение
/// (тот же дефект, что исправлен в `E-0022`, где ветка отбора стояла не над `match score`).
/// Сортировка `(score, cell_id)` детерминирована, как в `top_clusters`, и зависит только от
/// квантованного вектора запроса (§5, §8.4).
fn select_cells(
    query: &[i8; DIM],
    cells: &Cells,
    centroids: &[&[i8; DIM]],
    budget: usize,
    score: CellScore,
) -> Vec<u16> {
    match score {
        CellScore::Centroid => {
            let refs: Vec<&[i8; DIM]> = cells.rows.iter().collect();
            top_clusters(query, &refs, budget)
        }
        CellScore::NearestFine => {
            // Оценка ячейки — минимум расстояния до её мелких центроидов: ячейка тем ближе, чем
            // ближе её лучший кластер.
            let mut scored: Vec<(u32, u16)> = cells
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
    }
}

/// Нижняя оценка `l2_sq(query, x)` по блоку записей, для которого известна граница норм.
/// Обратное неравенство треугольника: `‖q − x‖ ≥ ‖q‖ − ‖x‖ ≥ ‖q‖ − max‖x‖`. Оба корня берутся в
/// целых — `floor(‖q‖)` снизу и `ceil(max‖x‖)` сверху, — поэтому разность не превосходит настоящей,
/// а её квадрат (при положительной разности) — законная нижняя граница целочисленного `l2_sq`.
/// Поправка на квантование не нужна: оценка, порог и ground truth живут в одном int8-мире, где
/// `l2_sq` точен; поправка потребовалась бы только при сравнении с расстоянием до эмбеддинга.
fn bound_by_norm(q_norm_sq: u32, block_max_norm_sq: u32) -> u32 {
    let lo = q_norm_sq.isqrt();
    let hi = {
        let r = block_max_norm_sq.isqrt();
        if r * r == block_max_norm_sq { r } else { r + 1 }
    };
    if lo > hi {
        (lo - hi) * (lo - hi)
    } else {
        0
    }
}

/// Нижняя оценка `l2_sq(query, x)` по померной рамке блока (min/max по каждому измерению): в каждом
/// измерении берётся точка интервала, ближайшая к запросу, — сумма квадратов отклонений и есть
/// минимум по всей рамке, а значит и по лежащим в ней записям. Оценка сильнее нормовой (та
/// эквивалентна шару), цена — `2 × {DIM}` int8 на блок вместо одного u32.
fn bound_by_box(query: &[i8; DIM], minmax: &[(i8, i8)]) -> u32 {
    let mut acc = 0u32;
    for d in 0..DIM {
        let (lo, hi) = minmax[d];
        let q = i32::from(query[d]);
        let gap = if q < i32::from(lo) {
            i32::from(lo) - q
        } else if q > i32::from(hi) {
            q - i32::from(hi)
        } else {
            0
        };
        acc += (gap * gap) as u32;
    }
    acc
}

/// Метаданные блоков для точной отсечки (`H-0023`): максимум нормы и померная рамка — по мелким
/// кластерам и по грубым ячейкам карты. Считаются **по записям корпуса**, а не по центроидам, и
/// метаданные ячейки получаются слиянием дочерних кластеров (максимум норм — максимум по детям,
/// рамка — объединение детских рамок), поэтому оценка остаётся честной нижней границей своего блока
/// при любом его размере.
struct BlockBounds {
    /// Максимум ‖x‖² по записям блока (u32: 384 × 127² = 6 195 456 влезает с запасом).
    cluster_max_norm: Vec<u32>,
    cell_max_norm: Vec<u32>,
    /// Плоские рамки: `[block * DIM + d] = (min, max)` по измерению `d` — 2 × DIM int8 на блок.
    cluster_minmax: Vec<(i8, i8)>,
    cell_minmax: Vec<(i8, i8)>,
    /// Распределение ‖x‖² по записям корпуса (min / медиана / max) — объясняет результат: если
    /// нормы лежат в узкой полосе, отсечка по норме вырождается по построению.
    norm_min: u32,
    norm_median: u32,
    norm_max: u32,
}

/// Строит метаданные блоков. Цена offline (её платит издатель один раз на выпуск): проход по
/// корпусу за нормами и померный min/max по каждому блоку; время и размер печатаются вызывающей
/// стороной, потому что «дешёвая отсечка» без цены метаданных было бы неверным утверждением.
fn build_block_bounds(
    corpus: &[[i8; DIM]],
    members: &[Vec<u32>],
    cells: &Cells,
    threads: usize,
) -> BlockBounds {
    let norms: Vec<u32> = parallel_map(corpus.len(), threads.max(1), |i| {
        corpus[i].iter().map(|&v| (i64::from(v) * i64::from(v)) as u32).sum()
    });
    let mut sorted = norms.clone();
    sorted.sort_unstable();
    let per_cluster = parallel_map(members.len(), threads, |cl| {
        let list = &members[cl];
        let mut mx = 0u32;
        for &id in list {
            mx = mx.max(norms[id as usize]);
        }
        let mut minmax: Vec<(i8, i8)> = Vec::with_capacity(DIM);
        for d in 0..DIM {
            let mut lo = i8::MAX;
            let mut hi = i8::MIN;
            for &id in list {
                let v = corpus[id as usize][d];
                if v < lo {
                    lo = v;
                }
                if v > hi {
                    hi = v;
                }
            }
            minmax.push((lo, hi));
        }
        (mx, minmax)
    });
    let cluster_max_norm: Vec<u32> = per_cluster.iter().map(|(mx, _)| *mx).collect();
    let cluster_minmax: Vec<(i8, i8)> =
        per_cluster.iter().flat_map(|(_, minmax)| minmax.iter().copied()).collect();
    let cell_max_norm: Vec<u32> = cells
        .clusters_of_cell
        .iter()
        .map(|list| list.iter().map(|&cl| cluster_max_norm[cl as usize]).max().unwrap_or(0))
        .collect();
    let mut cell_minmax: Vec<(i8, i8)> = Vec::with_capacity(cells.clusters_of_cell.len() * DIM);
    for list in &cells.clusters_of_cell {
        for d in 0..DIM {
            let mut lo = i8::MAX;
            let mut hi = i8::MIN;
            for &cl in list {
                let (a, b) = cluster_minmax[cl as usize * DIM + d];
                if a < lo {
                    lo = a;
                }
                if b > hi {
                    hi = b;
                }
            }
            cell_minmax.push((lo, hi));
        }
    }
    BlockBounds {
        cluster_max_norm,
        cell_max_norm,
        cluster_minmax,
        cell_minmax,
        norm_min: sorted.first().copied().unwrap_or(0),
        norm_median: sorted[sorted.len() / 2],
        norm_max: sorted.last().copied().unwrap_or(0),
    }
}

/// Четыре измеренные отсечки — два уровня блока × два вида оценки, в этом порядке.
const BOUND_NAMES: [&str; 4] = [
    "кластер, оценка по норме (н1)",
    "кластер, оценка по рамке (н2)",
    "ячейка, оценка по норме (н1)",
    "ячейка, оценка по рамке (н2)",
];

/// Одна свёрнутая по запросам доля. Решающая статистика — `mean`: пре-регистрация говорит «доля
/// считается по каждому запросу и усредняется». Распределение печатается справочно, потому что
/// вывод по среднему прячет худший запрос.
struct BoundShare {
    mean: f64,
    min: f64,
    median: f64,
    max: f64,
    excluded: u64,
    scanned: u64,
    /// Запросов, где не исключено ничего, и где исключено всё (то есть скан можно было не делать).
    zero: usize,
    all: usize,
    /// Насколько близко лучшая оценка блока подошла к порогу: `mean` — среднее по запросам от
    /// `max_block(lb / порог)`, `best` — максимум по запросам. Без этой пары чисел «0,00 %»
    /// неотличимо от «оценка не посчитана»: она показывает, во сколько раз отсечка не дотянула.
    ratio_mean: f64,
    ratio_best: f64,
}

/// Доля записей протокольного скана, исключаемая точной оценкой при **идеальном** пороге (`H-0023`).
/// Проход не трогает скан: он берёт то же множество ячеек, что даёт `select_cells` (та же функция,
/// не вторая копия правила), и сравнивает нижнюю оценку блока с 10-м точным расстоянием того же
/// запроса из exact brute-force. Блок исключается, только если оценка **строго больше** порога: при
/// равенстве запись ещё может войти в топ-10 по tie-break `(l2_sq, id)`, и отбрасывать её было бы
/// неверно.
fn bound_shares(
    bb: &BlockBounds,
    cells: &Cells,
    members: &[Vec<u32>],
    centroids: &[&[i8; DIM]],
    corpus: &[[i8; DIM]],
    queries: &[[i8; DIM]],
    truth: &[Vec<u32>],
    score: CellScore,
    threads: usize,
    // Положительный контроль механизма: при `spike = true` порог подменён нулём, то есть
    // исключается любой блок с **положительной** оценкой. Если и тогда доля остаётся нулевой,
    // дело не в силе оценки, а в самом счёте — и этот контроль отличает одно от другого.
    spike: bool,
) -> [BoundShare; 4] {
    let per_query: Vec<[(u64, u64, f64); 4]> =
        parallel_map(queries.len(), threads.max(1), |qi| {
            let q = &queries[qi];
            let q_norm: u32 = q.iter().map(|&v| (i64::from(v) * i64::from(v)) as u32).sum();
            // 10-е точное расстояние того же запроса: ground truth отсортирован контрактом
            // `(l2_sq, id)`, значит его последний элемент — ровно порог топ-10 (при корпусе не
            // короче K).
            let tenth = truth[qi][truth[qi].len() - 1] as usize;
            let threshold = if spike { 0 } else { l2_sq(q, &corpus[tenth]) };
            // Отношение «лучшая оценка / порог» считается даже там, где исключать нечего: оно и
            // есть объяснение нуля. При пороге 0 (запрос совпал с записью) отношение не определено
            // и берётся 1 — блок тогда и не исключается.
            let ratio = |lb: u32| -> f64 {
                if threshold == 0 { 1.0 } else { lb as f64 / threshold as f64 }
            };
            let chosen = select_cells(q, cells, centroids, MAX_OWNERS, score);
            let mut acc = [(0u64, 0u64, 0.0f64); 4];
            for &cell in &chosen {
                let clusters = &cells.clusters_of_cell[cell as usize];
                for &cl in clusters {
                    let n = members[cl as usize].len() as u64;
                    let box_at = &bb.cluster_minmax[cl as usize * DIM..(cl as usize + 1) * DIM];
                    let lb = bound_by_norm(q_norm, bb.cluster_max_norm[cl as usize]);
                    if lb > threshold {
                        acc[0].0 += n;
                    }
                    acc[0].1 += n;
                    acc[0].2 = acc[0].2.max(ratio(lb));
                    let lb = bound_by_box(q, box_at);
                    if lb > threshold {
                        acc[1].0 += n;
                    }
                    acc[1].1 += n;
                    acc[1].2 = acc[1].2.max(ratio(lb));
                }
                let cell_size: u64 =
                    clusters.iter().map(|&cl| members[cl as usize].len() as u64).sum();
                let box_at = &bb.cell_minmax[cell as usize * DIM..(cell as usize + 1) * DIM];
                let lb = bound_by_norm(q_norm, bb.cell_max_norm[cell as usize]);
                if lb > threshold {
                    acc[2].0 += cell_size;
                }
                acc[2].1 += cell_size;
                acc[2].2 = acc[2].2.max(ratio(lb));
                let lb = bound_by_box(q, box_at);
                if lb > threshold {
                    acc[3].0 += cell_size;
                }
                acc[3].1 += cell_size;
                acc[3].2 = acc[3].2.max(ratio(lb));
            }
            acc
        });
    let mut out: [BoundShare; 4] = std::array::from_fn(|_| BoundShare {
        mean: 0.0,
        min: 0.0,
        median: 0.0,
        max: 0.0,
        excluded: 0,
        scanned: 0,
        zero: 0,
        all: 0,
        ratio_mean: 0.0,
        ratio_best: 0.0,
    });
    for slot in 0..4 {
        let mut shares: Vec<f64> = Vec::with_capacity(per_query.len());
        let mut ratios: Vec<f64> = Vec::with_capacity(per_query.len());
        let (mut excluded, mut scanned) = (0u64, 0u64);
        for r in &per_query {
            shares.push(if r[slot].1 == 0 {
                0.0
            } else {
                r[slot].0 as f64 / r[slot].1 as f64
            });
            ratios.push(r[slot].2);
            excluded += r[slot].0;
            scanned += r[slot].1;
        }
        shares.sort_unstable_by(|a, b| a.partial_cmp(b).expect("доля конечна"));
        let ratio_sum: f64 = ratios.iter().sum();
        out[slot] = BoundShare {
            mean: excluded as f64 / scanned.max(1) as f64,
            min: *shares.first().unwrap_or(&0.0),
            median: shares[shares.len() / 2],
            max: *shares.last().unwrap_or(&0.0),
            excluded,
            scanned,
            zero: shares.iter().filter(|&&v| v == 0.0).count(),
            all: shares.iter().filter(|&&v| v >= 1.0).count(),
            ratio_mean: ratio_sum / ratios.len().max(1) as f64,
            ratio_best: ratios.iter().copied().fold(0.0f64, f64::max),
        };
    }
    out
}

/// Печать цены метаданных, распределения норм и четырёх долей с вердиктом по порогам `H-0023`.
fn print_bound_verdict(
    bb: &BlockBounds,
    cells: &Cells,
    shares: &[BoundShare; 4],
    spikes: &[BoundShare; 4],
    queries: usize,
    corpus_len: usize,
    build_secs: f64,
) {
    let blocks = bb.cluster_max_norm.len() + bb.cell_max_norm.len();
    let norm_bytes = 4 * blocks;
    let box_bytes = 2 * DIM * blocks;
    println!(
        "BOUND: метаданные построены за {build_secs:.1} с для {blocks} блоков ({} кластеров + {} \
         ячеек): оценка по норме — {norm_bytes} Б (1 u32 на блок), по рамке — ещё {box_bytes} Б \
         (2 × {DIM} int8 на блок); вместе {:.3} % int8-корпуса из {corpus_len} записей",
        bb.cluster_max_norm.len(),
        bb.cell_max_norm.len(),
        100.0 * (norm_bytes + box_bytes) as f64 / (DIM as f64 * corpus_len as f64),
    );
    println!(
        "BOUND: распределение ‖x‖² по записям корпуса — min {} / медиана {} / max {} (разброс в \
         {:.2}×): при узкой полосе оценка по норме обязана вырождаться, и это ровно то, что \
         проверяет гипотеза",
        bb.norm_min,
        bb.norm_median,
        bb.norm_max,
        bb.norm_max as f64 / bb.norm_min.max(1) as f64,
    );
    println!(
        "BOUND: цена самой отсечки — {} оценок блока на запрос ({} ячеек + {} кластеров) против \
         {:.1} оценок расстояния в скане, то есть {:.2} % работы скана",
        MAX_OWNERS + MAX_OWNERS * cells.cps,
        MAX_OWNERS,
        MAX_OWNERS * cells.cps,
        shares[0].scanned as f64 / queries.max(1) as f64,
        100.0 * (MAX_OWNERS + MAX_OWNERS * cells.cps) as f64
            / (shares[0].scanned as f64 / queries.max(1) as f64),
    );
    for (name, s) in BOUND_NAMES.iter().zip(shares) {
        println!(
            "BOUND {name}: средняя доля исключённых записей {:.2} % — порог ≥ {:.0} % {}, \
             фальсификатор < {:.0} % {}; справочно: min {:.2} %, медиана {:.2} %, макс {:.2} %, \
             исключено {}/{} записей, запросов с нулевой отсечкой {}, с полной — {}; лучшая оценка \
             блока к порогу: в среднем {:.3}×, в лучшем запросе {:.3}× (×1,0 — это ровно порог, то \
             есть отсечке не хватает этого множителя)",
            s.mean * 100.0,
            BOUND_SUCCESS * 100.0,
            if s.mean >= BOUND_SUCCESS { "PASS" } else { "FAIL" },
            BOUND_FALSIFIER * 100.0,
            if s.mean < BOUND_FALSIFIER { "СРАБОТАЛ" } else { "нет" },
            s.min * 100.0,
            s.median * 100.0,
            s.max * 100.0,
            s.excluded,
            s.scanned,
            s.zero,
            s.all,
            s.ratio_mean,
            s.ratio_best,
        );
    }
    println!(
        "BOUND: КОНТРОЛЬ МЕХАНИЗМА — тот же проход при пороге, подменённом нулём (исключается \
         любой блок с ненулевой оценкой, счётчик обязан отвечать). Доли по четырём отсечкам: \
         {}, {}, {}, {} — если они нулевые, молчит кодировка, а не отсечка; реальные доли выше \
         означают только то, что механизм считает.",
        fmt_spike(&spikes[0]),
        fmt_spike(&spikes[1]),
        fmt_spike(&spikes[2]),
        fmt_spike(&spikes[3]),
    );
}

/// Строка spike-контроля: доля плюс абсолютные числа, чтобы нулевой результат читался как
/// «счётчик молчит», а не как «отсечка ничего не даёт».
fn fmt_spike(s: &BoundShare) -> String {
    format!("{:.2} % ({}/{} записей)", s.mean * 100.0, s.excluded, s.scanned)
}


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
    // Центроиды корзин внутри ячеек (`H-0021`): меняют только **правило отбора** ячеек. `None` —
    // отбор по грубому центроиду ячейки, как в `E-0012` и `E-0020`.
    cell_buckets: Option<&CellBuckets>,
    // Рука PQ (`H-0022`): `(кодобук с кодами корпуса, R рефайна)`. Меняет ровно две вещи — **чем**
    // оценивается кандидат и **сколько** кандидатов доходит до contract-сортировки. Множество
    // сканируемых записей, правило отбора ячеек, fan-out и ground truth остаются `E-0012`.
    pq: Option<(&Pq, usize)>,
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
        // `H-0021`: если запрос несёт фильтр и издатель выложил центроиды корзин, ячейка оценивается
        // по центроиду **нужной корзины внутри ячейки** — то есть по той её части, из которой
        // вообще может быть ответ. Это замена обоим гейтным правилам отбора (`Centroid` и
        // `NearestFine`), а не одному: гейт `E-0012` проходит по `NearestFine`, и подмена одного
        // `Centroid` оставила бы фильтрованную кривую побайтово равной `E-0020` — гипотеза
        // проверяла бы сама себя. Пустая корзина даёт `u32::MAX` и не вытесняет содержательные
        // ячейки; сортировка `(score, cell_id)` — детерминированная, как в `top_clusters`.
        let aware: Option<(&CellBuckets, u8)> = match (cell_buckets, filter) {
            (Some(cbc), Some((_, want))) => Some((cbc, want)),
            (None, _) | (Some(_), None) => None,
        };
        let chosen: Vec<u16> = if let Some((cbc, want)) = aware {
            let mut scored: Vec<(u32, u16)> = (0..c.rows.len())
                .map(|cell| {
                    let idx = cell * cbc.buckets + usize::from(want);
                    let d = if cbc.counts[idx] == 0 {
                        u32::MAX
                    } else {
                        l2_sq(query, &cbc.rows[idx])
                    };
                    (d, cell as u16)
                })
                .collect();
            scored.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            scored.truncate(budget.min(scored.len()));
            scored.into_iter().map(|(_, cell)| cell).collect()
        } else {
            select_cells(query, c, centroids, budget, score)
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
    let mut refined = 0usize;
    // Границы стадии «прочитать кандидатов и оценить их» одинаковы в обеих руках, поэтому их
    // отношение — это и есть измеряемая цена условия (в) `H-0022`, а не разница whole-run времён.
    let stage_started = Instant::now();
    // Число подсписков на кластер: в режиме SUB лестница идёт по s, поэтому s — это nprobe;
    // вне режима SUB — бесконечность, то есть кластер сканируется целиком (`E-0012`).
    let s = if subs.is_some() { nprobe } else { usize::MAX };
    match pq {
        None => {
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
            // Вне PQ-руки рефайна нет: переоценивается всё, что попало в скан.
            refined += candidates;
        }
        Some((pq, r)) => {
            // Стадия 1: тот же протокольный скан, но кандидат стоит `m` байт кода и `m`
            // целочисленных сложений по LUT вместо {DIM} байт и {DIM} MAC. Отсечки нет — ADC не
            // даёт права ничего пропустить (`H-0023` про точную отсечку отдельно), поэтому
            // множество кандидатов побитово равно int8-руке.
            let lut = pq.lut(query);
            let mut sel = TopR::new(r);
            for cluster in scan_clusters {
                for list in scan_lists(members, subs, cluster as usize, query, s) {
                    for &id in list {
                        scanned += 1;
                        if let Some((facets, want)) = filter {
                            if facets.slot[id as usize] != want {
                                continue;
                            }
                        }
                        let adc = pq.score(&lut, id as usize);
                        sel.push(adc, id);
                        candidates += 1;
                    }
                }
            }
            // Стадия 2: точный int8 только для глобальных top-R. Сортировка и `TopK` не меняются
            // вовсе — контракт `(l2_sq, id)` остаётся контрактом §7.2, меняется только множество
            // записей, до него допущенных.
            for &id in sel.ids() {
                top.push(l2_sq(query, &corpus[id as usize]), id);
            }
            refined += sel.len();
        }
    }
    let stage_secs = stage_started.elapsed().as_secs_f64();
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
        refined,
        stage_secs,
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

/// Product quantization (`H-0022`/`E-0023`): код записи — `m` байт, по одному индексу центроида
/// в каждом из `m` подпространств по `DIM/m` измерений. Объект существует только в стенде: ни в
/// `vecdht-wire`, ни в спеке поля кода нет, и данный прогон решает, входить ли ему вообще.
struct Pq {
    /// Число подпространств = число байт в коде записи.
    m: usize,
    /// Измерений в подпространстве: `DIM / m`, всегда кратно 8 (проверяется при разборе режима).
    dsub: usize,
    /// Центроидов на подпространство: `min(PQ_K, n)`, то есть 8 бит, но не больше записей корпуса.
    k: usize,
    /// `books[(j * k + c) * dsub ..]` — int8-центроиды `j`-го подпространства, плоский массив.
    books: Vec<i8>,
    /// `codes[id * m + j]` — байт-индекс записи `id` в подпространстве `j`.
    codes: Vec<u8>,
    /// Худшее число проходов Lloyd по подпространствам и суммарные переприсваивания — offline-цена,
    /// которую печатает издатель (аргумент против «PQ бесплатен»).
    max_iters_used: usize,
    reassignments: usize,
    /// Среднее по записям квадратичное смещение кода относительно int8-вектора и средний квадрат
    /// нормы самого вектора — их отношение печатается как доля искажения геометрии.
    mean_sq_error: f64,
    mean_norm_sq: f64,
    /// Кодобук и коды пришли с диска, а не из этого обучения: статистика обучения (итерации,
    /// переприсваивания, смещение) в кеше не хранится, и печатать её нулями нельзя — рука,
    /// построившая кеш, напечатала её первая.
    from_cache: bool,
}

impl Pq {
    /// LUT запроса: `lut[j * k + c] = l2_sq(query_j, centroid[j][c])` — целая, `m × k` int32
    /// (6 144 числа при m = 24), строится один раз на запрос и не зависит от корпуса.
    fn lut(&self, query: &[i8; DIM]) -> Vec<u32> {
        let mut lut = vec![0u32; self.m * self.k];
        for j in 0..self.m {
            let q = &query[j * self.dsub..(j + 1) * self.dsub];
            for c in 0..self.k {
                let at = (j * self.k + c) * self.dsub;
                lut[j * self.k + c] = l2_sq_sub(q, &self.books[at..at + self.dsub]);
            }
        }
        lut
    }

    /// ADC-оценка записи: Σ_j LUT[j][code_j]. Это ровно сумма квадратов расстояний от подвекторов
    /// запроса до выбранных центроидов, то есть оценка `l2_sq(query, reconstruction(code))`, и
    /// считается она без единого умножения — только `m` сложений по `m` байтам кода.
    fn score(&self, lut: &[u32], id: usize) -> u32 {
        let mut acc = 0u32;
        let base = id * self.m;
        for j in 0..self.m {
            acc += lut[j * self.k + usize::from(self.codes[base + j])];
        }
        acc
    }
}

/// Кодобук и коды корпуса: `m` независимых целочисленных k-means по `DIM/m` измерений, тем же
/// механизмом, что второй уровень IVF (`sublist_cluster`): farthest-first инициализация по `l2_sq`
/// без генератора, Lloyd с целочисленным средним и округлением вверх при остатке ≥ половины
/// делителя, порядок накопления сумм — по возрастанию id. Значит код воспроизводится издателем
/// детерминированно (§8.4), а не «примерно тот же, что у соседа».
fn build_pq(corpus: &[[i8; DIM]], m: usize, threads: usize, source: &Path) -> Pq {
    let dsub = DIM / m;
    let digest = pq_digest(corpus, m);
    let path = source.with_extension(format!("pq{m}"));
    if let Some(mut built) = read_pq_cache(&path, corpus.len(), m, dsub, &digest) {
        println!(
            "PQ: кодобук и коды взяты из кеша {} — offline-обучение не повторено, его цена \
             напечатана в той руке, где кеш строился",
            path.display()
        );
        built.from_cache = true;
        return built;
    }
    let per_sub = parallel_map(m, threads, |j| pq_subspace(corpus, j * dsub, dsub));
    let k = per_sub[0].0.len() / dsub;
    let mut books = Vec::with_capacity(m * k * dsub);
    let mut max_iters_used = 0usize;
    let mut reassignments = 0usize;
    for (centroids, iters, re) in &per_sub {
        books.extend_from_slice(centroids);
        max_iters_used = max_iters_used.max(*iters);
        reassignments += re;
    }
    let (codes, sq_err, norm_sq) = pq_encode(corpus, &books, m, dsub, k, threads);
    let n = corpus.len().max(1) as f64;
    let built = Pq {
        m,
        dsub,
        k,
        books,
        codes,
        max_iters_used,
        reassignments,
        mean_sq_error: sq_err / n,
        mean_norm_sq: norm_sq / n,
        from_cache: false,
    };
    write_pq_cache(&path, &built, &digest);
    built
}

/// Одно подпространство: `k` центроидов по `dsub` int8-координат, плоским массивом, плюс цена
/// обучения. Центроидов ровно `min(PQ_K, n)`, поэтому `u8`-индекс кода всегда достаточен.
fn pq_subspace(corpus: &[[i8; DIM]], off: usize, dsub: usize) -> (Vec<i8>, usize, usize) {
    let n = corpus.len();
    let k = PQ_K.min(n);
    // Первый центр — запись с наименьшим id, каждый следующий — максимально удалённый от уже
    // взятых (при равенстве — наименьшая позиция): генератора нет, построение воспроизводимо.
    // `nearest` обновляется СРАЗУ после каждого выбора, включая первый: иначе вторая точка
    // выбирается из массива, где всюду `u32::MAX`, снова получает id 0 и кодобук содержит
    // дублированный центроид (то есть k−1 полезных центров вместо k).
    let mut chosen: Vec<usize> = Vec::with_capacity(k);
    let mut nearest = vec![u32::MAX; n];
    while chosen.len() < k {
        let pick = if chosen.is_empty() {
            0usize
        } else {
            let mut best: Option<(u32, usize)> = None;
            for (pos, &d) in nearest.iter().enumerate() {
                let better = match best {
                    None => true,
                    Some((bd, bp)) => d > bd || (d == bd && pos < bp),
                };
                if better {
                    best = Some((d, pos));
                }
            }
            let Some((_, pos)) = best else { break };
            pos
        };
        for (p, d) in nearest.iter_mut().enumerate() {
            let nd = l2_sq_sub(&corpus[pick][off..off + dsub], &corpus[p][off..off + dsub]);
            if nd < *d {
                *d = nd;
            }
        }
        chosen.push(pick);
    }
    let mut centroids: Vec<i8> = Vec::with_capacity(k * dsub);
    for &pos in &chosen {
        centroids.extend_from_slice(&corpus[pos][off..off + dsub]);
    }
    let mut assign = vec![0u8; n];
    let mut iters = 0usize;
    let mut reassignments = 0usize;
    loop {
        iters += 1;
        let mut changed = 0usize;
        for (id, row) in corpus.iter().enumerate() {
            let v = &row[off..off + dsub];
            let mut best_c = 0u8;
            let mut best_d = u32::MAX;
            for c in 0..k {
                let at = c * dsub;
                let d = l2_sq_sub(v, &centroids[at..at + dsub]);
                // Строгое сравнение: при равенстве остаётся меньший номер центроида — тот же
                // tie-break, что у `top_clusters` и `sublist_cluster`.
                if d < best_d {
                    best_d = d;
                    best_c = c as u8;
                }
            }
            if assign[id] != best_c {
                changed += 1;
                assign[id] = best_c;
            }
        }
        reassignments += changed;
        if changed == 0 || iters >= PQ_MAX_ITERS {
            break;
        }
        // Суммы копятся в обходе по возрастанию id — тот же порядок сложения, что у `int_mean`,
        // поэтому среднее не разъедётся с другой корректной реализацией.
        let mut sums = vec![vec![0i64; dsub]; k];
        let mut counts = vec![0i64; k];
        for (id, &c) in assign.iter().enumerate() {
            let v = &corpus[id][off..off + dsub];
            let sum = &mut sums[c as usize];
            counts[c as usize] += 1;
            for (acc, &x) in sum.iter_mut().zip(v) {
                *acc += i64::from(x);
            }
        }
        centroids = int_means_sub(&sums, &counts, dsub, &centroids);
    }
    (centroids, iters, reassignments)
}

/// Целочисленное среднее по подпространству: `int_mean`, применённый к `dsub` координатам, с тем
/// же округлением вверх при остатке ≥ половины делителя и тем же зажимом в диапазон i8. Пустой
/// кластер оставляет прежний центроид — иначе среднее от пустого набора делило бы на ноль.
fn int_means_sub(sums: &[Vec<i64>], counts: &[i64], dsub: usize, keep: &[i8]) -> Vec<i8> {
    let mut out = Vec::with_capacity(sums.len() * dsub);
    for (c, sum) in sums.iter().enumerate() {
        let cnt = counts[c];
        if cnt == 0 {
            out.extend_from_slice(&keep[c * dsub..c * dsub + dsub]);
            continue;
        }
        for &s in sum {
            let q = s.div_euclid(cnt);
            let r = s.rem_euclid(cnt);
            let v = if 2 * r >= cnt { q + 1 } else { q };
            out.push(i64::from(i8::MIN).max(v).min(i64::from(i8::MAX)) as i8);
        }
    }
    out
}

/// Коды корпуса: argmin по центроидам каждого подпространства. Заодно считается справочная цена
/// квантования — суммарное квадратичное смещение кода и суммарный квадрат нормы вектора.
fn pq_encode(
    corpus: &[[i8; DIM]],
    books: &[i8],
    m: usize,
    dsub: usize,
    k: usize,
    threads: usize,
) -> (Vec<u8>, f64, f64) {
    const BLOCK: usize = 4096;
    let blocks = corpus.len().div_ceil(BLOCK);
    let per_block = parallel_map(blocks, threads, |b| {
        let from = b * BLOCK;
        let to = (from + BLOCK).min(corpus.len());
        let mut codes = Vec::with_capacity((to - from) * m);
        let mut sq_err = 0u64;
        let mut norm_sq = 0u64;
        for row in &corpus[from..to] {
            for j in 0..m {
                let v = &row[j * dsub..(j + 1) * dsub];
                let mut best_c = 0u8;
                let mut best_d = u32::MAX;
                for c in 0..k {
                    let at = (j * k + c) * dsub;
                    let d = l2_sq_sub(v, &books[at..at + dsub]);
                    if d < best_d {
                        best_d = d;
                        best_c = c as u8;
                    }
                }
                codes.push(best_c);
                sq_err += u64::from(best_d);
                for &x in v {
                    let q = i32::from(x);
                    norm_sq += (q * q) as u64;
                }
            }
        }
        (codes, sq_err, norm_sq)
    });
    let mut codes = Vec::with_capacity(corpus.len() * m);
    let mut sq_err = 0u64;
    let mut norm_sq = 0u64;
    for (c, e, n) in per_block {
        codes.extend_from_slice(&c);
        sq_err += e;
        norm_sq += n;
    }
    (codes, sq_err as f64, norm_sq as f64)
}

/// `l2_sq` по произвольному числу измерений: те же 8 аккумуляторов и тот же порядок сложения, что
/// у протокольного `vecdht_crypto::quant::l2_sq`, поэтому значение совпадает с контрактом §7.2 и
/// для целого вектора, и для его подпространства. Длина обязана кратиться 8 — иначе аккумуляторы
/// раскладываются уже не по тем координатам.
fn l2_sq_sub(a: &[i8], b: &[i8]) -> u32 {
    debug_assert!(a.len() == b.len() && a.len() % 8 == 0);
    let mut acc = [0u32; 8];
    for (ax, bx) in a.chunks_exact(8).zip(b.chunks_exact(8)) {
        for ((av, bv), out) in ax.iter().zip(bx).zip(acc.iter_mut()) {
            let d = *av as i32 - *bv as i32;
            *out = out.wrapping_add((d * d) as u32);
        }
    }
    let mut total = 0u32;
    for x in acc {
        total = total.wrapping_add(x);
    }
    total
}

/// Глобальные top-R по ADC-оценке с контрактом `(score ASC, id ASC)` — тот же tie-break, что у
/// `TopK`, поэтому множество рефайна определено однозначно. Линейная вставка в отсортированный
/// массив делается только для кандидата, прошедшего отсечение по худшему: на полном скане ячейки
/// большинство кандидатов стоит одно сравнение.
struct TopR {
    cap: usize,
    d2: Vec<u32>,
    ids: Vec<u32>,
}

impl TopR {
    fn new(cap: usize) -> Self {
        // `push` вычисляет `len() - 1` и `pos` в предположении непустого предела; R разбирается
        // из окружения с assert'ом ниже по тесту, но стенд не должен падать по арифметике.
        debug_assert!(cap > 0, "TopR требует ненулевой предел");
        Self { cap: cap.max(1), d2: Vec::with_capacity(cap), ids: Vec::with_capacity(cap) }
    }

    fn push(&mut self, d2: u32, id: u32) {
        let full = self.d2.len() == self.cap;
        if full {
            let last = self.d2.len() - 1;
            let (wd, wi) = (self.d2[last], self.ids[last]);
            if d2 > wd || (d2 == wd && id > wi) {
                return;
            }
        }
        let pos = self.pos(d2, id);
        self.d2.insert(pos, d2);
        self.ids.insert(pos, id);
        if full {
            self.d2.pop();
            self.ids.pop();
        }
    }

    /// Позиция вставки: первый элемент, строже которого пара `(d2, id)`. Бинарный поиск по тому же
    /// сравнению, что и `push`, — иначе порядок массива перестал бы быть contract-сортировкой.
    fn pos(&self, d2: u32, id: u32) -> usize {
        let (mut lo, mut hi) = (0usize, self.d2.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.d2[mid] < d2 || (self.d2[mid] == d2 && self.ids[mid] < id) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    fn len(&self) -> usize {
        self.ids.len()
    }

    fn ids(&self) -> &[u32] {
        &self.ids
    }
}

/// Отпечаток корпуса для кеша кодобука: blake3 по int8-байтам всех записей плюс параметры. Кеш
/// обязан «схлопнуться» при другом корпусе или другом `m`, иначе рука `m = 48` измерялась бы кодом,
/// обученным при `m = 24`.
fn pq_digest(corpus: &[[i8; DIM]], m: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vecdht-pq-cache-v2");
    h.update(&(corpus.len() as u64).to_le_bytes());
    h.update(&(m as u32).to_le_bytes());
    let mut buf = [0u8; DIM];
    for row in corpus {
        for (d, &x) in row.iter().enumerate() {
            buf[d] = x as u8;
        }
        h.update(&buf);
    }
    *h.finalize().as_bytes()
}

fn read_pq_cache(path: &Path, n: usize, m: usize, dsub: usize, digest: &[u8; 32]) -> Option<Pq> {
    // v2: farthest-first инициализация обновляет `nearest` после каждого центра (до этого второй
    // центр совпадал с первым, и кодобук имел k−1 полезных центров); кеш, построенный прежним
    // построителем, обязан быть отвергнут, а не подтянут в новую руку.
    const TAG: &[u8; 8] = b"VDP0PQ02";
    const HEAD: usize = 8 + 4 + 4 + 4 + 32;
    let data = fs::read(path).ok()?;
    let k = PQ_K.min(n);
    let books_len = m * k * dsub;
    if data.len() != HEAD + books_len + n * m || &data[..8] != TAG {
        return None;
    }
    let c_m = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
    let c_k = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
    let c_n = u32::from_le_bytes(data[16..20].try_into().ok()?) as usize;
    if (c_m, c_k, c_n) != (m, k, n) || &data[20..HEAD] != digest.as_slice() {
        return None;
    }
    let books = data[HEAD..HEAD + books_len].iter().map(|&b| b as i8).collect();
    let codes = data[HEAD + books_len..].to_vec();
    Some(Pq {
        m,
        dsub,
        k,
        books,
        codes,
        // Цена обучения в кеше не хранится: её печатает рука, построившая кеш (`from_cache`).
        max_iters_used: 0,
        reassignments: 0,
        mean_sq_error: 0.0,
        mean_norm_sq: 0.0,
        from_cache: false,
    })
}

fn write_pq_cache(path: &Path, pq: &Pq, digest: &[u8; 32]) {
    const HEAD: usize = 8 + 4 + 4 + 4 + 32;
    let mut data = Vec::with_capacity(HEAD + pq.books.len() + pq.codes.len());
    data.extend_from_slice(b"VDP0PQ02");
    data.extend_from_slice(&(pq.m as u32).to_le_bytes());
    data.extend_from_slice(&(pq.k as u32).to_le_bytes());
    data.extend_from_slice(&((pq.codes.len() / pq.m) as u32).to_le_bytes());
    data.extend_from_slice(digest);
    data.extend(pq.books.iter().map(|&b| b as u8));
    data.extend_from_slice(&pq.codes);
    if let Err(e) = fs::write(path, &data) {
        println!("PQ: кеш кодобука не записан ({e}) — на числа прогона это не влияет");
    }
}

/// Справочная точность кода (`E-0023`; порогом не является): медиана и p95 относительной ошибки
/// ADC на срезе, не зависящем от запроса, — `PQ_ERR_QUERIES` запросов × первые `PQ_ERR_SAMPLE`
/// записей корпуса. Ошибка определена как `|adc − l2_sq| / l2_sq`; пары с нулевым точным
/// расстоянием (запрос совпал с записью) отброшены и печатаются отдельным числом, потому что
/// иначе отношение обращается в inf. Проход идёт **вне** измеряемой стадии скана: если считать
/// ошибку внутри неё, стенд читал бы int8-байты, которые не учтены ни в модели условия (2), ни в
/// тайминге условия (3), и PQ-рука отличалась бы от int8-руки уже не «числом байт на кандидата».
fn pq_error_sample(
    pq: &Pq,
    corpus: &[[i8; DIM]],
    queries: &[[i8; DIM]],
    threads: usize,
) -> (f64, f64, usize, usize) {
    let recs = PQ_ERR_SAMPLE.min(corpus.len());
    let qs = PQ_ERR_QUERIES.min(queries.len());
    let per_query: Vec<(Vec<f64>, usize)> = parallel_map(qs, threads.max(1), |qi| {
        let lut = pq.lut(&queries[qi]);
        let mut v: Vec<f64> = Vec::with_capacity(recs);
        let mut skipped = 0usize;
        for (id, row) in corpus[..recs].iter().enumerate() {
            let exact = f64::from(l2_sq(&queries[qi], row));
            if exact == 0.0 {
                skipped += 1;
                continue;
            }
            v.push((f64::from(pq.score(&lut, id)) - exact).abs() / exact);
        }
        (v, skipped)
    });
    let mut all: Vec<f64> = Vec::with_capacity(recs * qs);
    let mut skipped_total = 0usize;
    for (v, s) in per_query {
        all.extend(v);
        skipped_total += s;
    }
    let n = all.len();
    if n == 0 {
        return (0.0, 0.0, 0, skipped_total);
    }
    all.sort_unstable_by(|a, b| a.partial_cmp(b).expect("ошибка ADC конечна"));
    let quantile = |p: f64| all[((n - 1) as f64 * p).round() as usize];
    (quantile(0.5), quantile(0.95), n, skipped_total)
}

/// Цена и размер кода (`H-0022`): offline-время, размер кодобука, байт на запись и искажение
/// геометрии. Без этих чисел утверждение «PQ дешевле» было бы неверным: при двухстадийном скане
/// код **добавляется** к int8 (рефайн требует векторов), а не заменяет его.
fn print_pq_stats(pq: &Pq, corpus_len: usize, secs: f64) {
    let book_bytes = pq.books.len();
    let code_bytes = pq.codes.len();
    let share = if pq.mean_norm_sq > 0.0 {
        100.0 * pq.mean_sq_error / pq.mean_norm_sq
    } else {
        0.0
    };
    let (m, k, dsub) = (pq.m, pq.k, pq.dsub);
    let (iters, re) = (pq.max_iters_used, pq.reassignments);
    let (mse, norm) = (pq.mean_sq_error, pq.mean_norm_sq);
    let over = 100.0 * m as f64 / DIM as f64;
    if pq.from_cache {
        // Нулями статистику обучения печатать нельзя: ноль читался бы как «Lloyd сошёлся за ноль
        // проходов» и «код не искажает геометрию».
        println!(
            "PQ: кодобук {m} × {k} центроидов по {dsub} измерений — {book_bytes} Б кодобука и \
             {code_bytes} Б кода ({m} Б на запись, корпус {corpus_len} записей); offline-статистика \
             (время, итерации Lloyd, переприсваивания, смещение кода) относится к руке, построившей \
             кеш. RAM узла: код добавляется к int8, то есть +{m} Б/запись = +{over:.2} % к {DIM} Б \
             вектора",
        );
    } else {
        println!(
            "PQ: кодобук {m} × {k} центроидов по {dsub} измерений построен за {secs:.1} с — \
             {book_bytes} Б кодобука и {code_bytes} Б кода ({m} Б на запись, корпус {corpus_len} \
             записей), Lloyd: худшее число итераций {iters}, переприсваиваний {re}; смещение кода \
             {mse:.0} против нормы² {norm:.0} = {share:.2} %; RAM узла: код добавляется к int8, то \
             есть +{m} Б/запись = +{over:.2} % к {DIM} Б вектора",
        );
    }
    println!(
        "PQ: {m} Б кода против {DIM} Б int8-записи — {:.1}× меньше читаемых байт на кандидата до \
         стадии рефайна",
        DIM as f64 / m as f64,
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

/// Центроид корзины внутри ячейки (`H-0021`/`E-0022`) — поле артефакта, которого в протоколе нет.
/// Это то, что позволяло бы клиенту выбирать ≤16 владельцев **под конкретный фильтр**: оценка
/// ячейки для запроса с корзиной `b` берётся от записей этой ячейки с корзиной `b`, а не от всей
/// ячейки. `rows[cell * buckets + bucket]`, `counts` — число записей пары (ячейка, корзина).
struct CellBuckets {
    rows: Vec<[i8; DIM]>,
    counts: Vec<u32>,
    buckets: usize,
}

/// Целочисленное среднее по записям пары (ячейка, корзина): те же `int_mean` и тот же порядок
/// сложения (по id записи), что у sub-центроидов `E-0021`, поэтому издатель воспроизводит поле
/// детерминированно. Пустая пара получает нулевой вектор и в отборе не участвует (`counts` = 0).
fn build_cell_buckets(
    cells: &Cells,
    members: &[Vec<u32>],
    corpus: &[[i8; DIM]],
    facets: &Facets,
    threads: usize,
) -> CellBuckets {
    let b = facets.buckets;
    let per_cell = parallel_map(cells.clusters_of_cell.len(), threads, |cell| {
        let mut ids_by_bucket: Vec<Vec<u32>> = vec![Vec::new(); b];
        for &cl in &cells.clusters_of_cell[cell] {
            for &id in &members[cl as usize] {
                ids_by_bucket[usize::from(facets.slot[id as usize])].push(id);
            }
        }
        // `members` упорядочены по id, обход кластеров ячейки детерминирован, поэтому список
        // каждой корзины упорядочен по id и среднее не зависит от раскладки карты по потокам.
        for ids in &mut ids_by_bucket {
            ids.sort_unstable();
        }
        let counts: Vec<u32> = ids_by_bucket.iter().map(|v| v.len() as u32).collect();
        let rows: Vec<[i8; DIM]> = ids_by_bucket
            .iter()
            .map(|ids| if ids.is_empty() { [0i8; DIM] } else { int_mean(ids, corpus) })
            .collect();
        (counts, rows)
    });
    let mut counts = Vec::with_capacity(per_cell.len() * b);
    let mut rows = Vec::with_capacity(per_cell.len() * b);
    let mut empty = 0usize;
    for (c, r) in per_cell {
        empty += c.iter().filter(|&&n| n == 0).count();
        counts.extend(c);
        rows.extend(r);
    }
    assert!(
        empty * 100 / counts.len() < 50,
        "половина пар (ячейка, корзина) пуста: отбор по центроиду корзины вырождается в «сколько \
         ячеек вообще содержит корзину», и сравнение с `E-0020` теряет смысл"
    );
    if empty > 0 {
        println!(
            "FACET-AWARE: {empty} пустых пар (ячейка, корзина) из {} — они получают оценку \
             `u32::MAX` и не входят в ≤{MAX_OWNERS} выбранных ячеек; fan-out запроса может стать \
             меньше бюджета, и это ограничение данных, а не механики отбора",
            counts.len()
        );
    }
    CellBuckets { rows, counts, buckets: b }
}

/// Цена поля: байты доп. центроидов и счётчиков относительно объёма корпуса + распределение
/// размеров корзин по ячейкам (это и есть то, что отбор начинает видеть).
fn print_cell_bucket_stats(cb: &CellBuckets, n: usize, secs: f64) {
    let bytes = cb.rows.len() * DIM + cb.counts.len() * 4;
    let min = cb.counts.iter().copied().min().unwrap_or(0);
    let max = cb.counts.iter().copied().max().unwrap_or(0);
    let avg = cb.counts.iter().map(|&c| u64::from(c)).sum::<u64>() as f64 / cb.counts.len() as f64;
    println!(
        "FACET-AWARE: {} пар (ячейка, корзина) построено за {secs:.1} с; размер пары min {min} / \
         max {max} при среднем {avg:.1} записи; цена поля — {bytes} Б ({:.3} % от {} Б int8-корпуса) \
         сверх грубых центроидов карты: {} × {} × {DIM} int8 + счётчики",
        cb.counts.len(),
        100.0 * bytes as f64 / (n * DIM) as f64,
        n * DIM,
        cb.rows.len() / cb.buckets,
        cb.buckets,
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
