//! Harness гейтов P0 (§18.1). Один процесс, никакого сетевого кода.
//!
//! Что здесь честно измеряется, а что **не** может быть измерено без весов:
//!
//! | Гейт | Состояние в этом harness |
//! |---|---|
//! | (i) throughput | измерена целочисленная половина (квантование + assign + поиск); инференс — только с `candle` и `VEC_DHT_MODEL_DIR` |
//! | (ii) recall@10 | измерена **механика** IVF против brute-force на синтетике; само число гейта требует >=50k реальных интент-текстов и реальной модели |
//! | (iii) rerank gain | измерен контракт порядка и метрика; дельта nDCG требует кросс-энкодера |
//! | (iv) детерминизм | шаги 1–3 и 6–8: 1000/1000 идентичных выходов между потоками; чувствительность сетки к возмущению 1e-5 |
//! | (v) candle modernbert | `crates/vecdht-embed/src/candle_backend.rs`, тест `gate_v_*` — без каталога модели ничего не утверждает |
//!
//! Синтетика (`vecdht_embed::testing::Synthetic`) — не замена измерениям, а стенд для кода: она
//! позволяет проверить, что brute-force, IVF, fan-out и метрики считают одно и то же. Числа
//! recall'а на ней не являются обещанием качества и не заносятся в спецификацию.
//!
//! Долгие прогоны включаются переменной окружения, а не флагом «полный»: `VEC_DHT_P0_FULL=1`
//! поднимает корпус до гейтного размера (1024 кластера x 50 записей = 51 200) и число запросов до
//! 200. В debug-профиле это минуты, поэтому полный прогон — `cargo test --release`.

use std::hint::black_box;
use std::time::{Duration, Instant};

use vecdht_artifact::{reference_artifact, Artifact, Centroids};
use vecdht_crypto::quant::{group_by_shard, l2_normalize, l2_sq, quantize, shard_of_cluster};
use vecdht_crypto::DIM;
use vecdht_embed::metrics::{median, recall_at_k};
use vecdht_embed::model::{finalize, EmbeddingModel, Encoded, Pooled};
use vecdht_embed::rerank::order_by_scores;
use vecdht_embed::testing::{HashModel, Synthetic};
use vecdht_embed::{Encoder, PREPROCESSING_VERSION};
use vecdht_index::entry::IndexEntry;
use vecdht_index::ivf::IvfIndex;
use vecdht_wire::{NLIST, SHARDS};

/// Порог §6.1: квантование + assign после инференса обязаны стоить меньше 0.3 мс.
const ASSIGN_BUDGET: Duration = Duration::from_micros(300);

fn full_mode() -> bool {
    std::env::var("VEC_DHT_P0_FULL").is_ok_and(|v| v == "1")
}

fn corpus_size() -> usize {
    if full_mode() {
        50
    } else {
        4
    }
}

fn n_queries() -> usize {
    if full_mode() {
        200
    } else {
        40
    }
}

/// Тексты для гейта (iv): разная длина, кириллица и латиница, combining-акцент, хвостовые
/// пробелы — то есть весь шаг 1 пайплайна в работе, а не только happy path.
fn texts(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| match i % 4 {
            0 => format!("ищу контрагента для vector search, итерация {i}, стек rust и cuda"),
            1 => format!("аген\u{0301}т ищет партнёра {i} — мультиязычный вход с combining-акцентом"),
            2 => format!("{i} ").repeat(60) + "короткое послесловие",
            _ => "короткий текст".to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------- (iv) детерминизм --

/// Гейт (iv) из §18.1 для всей детерминированной половины пайплайна: один и тот же список
/// текстов обязан давать побайтово одинаковые 384-байтные выходы при любом числе потоков.
///
/// Разбиение фиксировано по индексам (не work-stealing), иначе «одинаковость» зависела бы от
/// планировщика, а не от кода.
#[test]
fn gate_iv_pipeline_outputs_are_identical_across_thread_counts() {
    let n_texts = 1000;
    let corpus = texts(n_texts);
    let artifact = reference_artifact();
    let model = HashModel::new();

    let reference = run_serial(&artifact, &model, &corpus);
    assert_eq!(reference.len(), n_texts);

    for threads in [1usize, 2, 4, 8, 16] {
        let got = run_parallel(&artifact, &model, &corpus, threads);
        let same = got.iter().zip(reference.iter()).filter(|(a, b)| a.vec_q == b.vec_q).count();
        assert_eq!(
            same, n_texts,
            "гейт (iv): {threads} потоков дали расхождение в 384-байтных выходах"
        );
        // Идентичность выходов без идентичности идентификатора и кластера была бы половинчатой
        // проверкой: `intent_id` (§6.5) и `cluster_id` (§7.2) обязан совпадать тоже.
        assert_eq!(got, reference, "расхождение по всем полям Encoded при {threads} потоках");
    }
    println!(
        "гейт (iv): {n_texts}/{n_texts} идентичных выходов на потоках 1/2/4/8/16 — шаги 1-3, 6-8"
    );
    println!("         шаг 4 (forward) здесь не проверяется: он и есть единственный недетерминированный (§6.2)");
}

/// То же, но по одному вектору на вызов: ловит состояние, которое осталось бы между вызовами
/// (кеш аллокаторов, переиспользованные буферы).
#[test]
fn gate_iv_no_hidden_state_between_calls() {
    let artifact = reference_artifact();
    let model = HashModel::new();
    let corpus = texts(64);
    let first = run_serial(&artifact, &model, &corpus);
    // Обратный порядок и повторные вызовы не должны менять ни одного байта.
    let mut rev = corpus.clone();
    rev.reverse();
    let mut second = run_serial(&artifact, &model, &rev);
    second.reverse();
    assert_eq!(first, second, "порядок вызовов embed не должен влиять на результат");
    for _ in 0..3 {
        assert_eq!(first, run_serial(&artifact, &model, &corpus));
    }
}

/// Измерение §6.3: возмущение входа на 1e-5 переключает около 1 координаты из 384, а не половину.
///
/// Это прямая проверка числа, на котором держится вся маршрутизация: если бы сетка была `1/512`
/// при i8, доля переключённых координат выросла бы вчетверо, и `cluster_id` расходился бы между
/// узлами постоянно (§7.3 допускает 1–5%, а не 50%).
#[test]
fn gate_iv_grid_perturbation_is_one_coordinate_not_fifty_percent() {
    let corpus = texts(1000);
    let mut flipped_total = 0usize;
    let mut vectors_with_flip = 0usize;
    let mut max_flip = 0usize;
    let model = HashModel::new();

    for (i, t) in corpus.iter().enumerate() {
        let pooled = model.embed_pooled(t).unwrap();
        let mut u = [0f64; DIM];
        for k in 0..DIM {
            u[k] = f64::from(pooled[k]);
        }
        l2_normalize(&mut u).unwrap();
        let clean = quantize(&u);

        // Возмущение: каждая координата сдвигается не больше чем на 1e-5, величина и знак — из
        // blake3 по индексу, чтобы прогон был повторяемым.
        let mut perturbed = u;
        let seed = blake3::hash(&(i as u64).to_le_bytes());
        for k in 0..DIM {
            let b = seed.as_bytes()[k % 32];
            let eps = ((b % 21) as f64 - 10.0) * 1e-6; // [-1e-5, +1e-5]
            perturbed[k] = u[k] + eps;
        }
        let dirty = quantize(&perturbed);

        let flips = (0..DIM).filter(|&k| clean[k] != dirty[k]).count();
        flipped_total += flips;
        max_flip = max_flip.max(flips);
        vectors_with_flip += usize::from(flips > 0);
    }

    let mean = flipped_total as f64 / corpus.len() as f64;
    let per_coord = flipped_total as f64 / (corpus.len() * DIM) as f64;
    println!(
        "возмущение 1e-5: средних переключённых координат {mean:.2} из {DIM} (покоординатная доля {per_coord:.2e}, §6.3 ждёт 2.5e-3), максимум {max_flip}"
    );
    println!(
        "               векторов хотя бы с одной переменной координатой: {vectors_with_flip}/{}",
        corpus.len()
    );
    // Верхняя граница — вчетверо против предсказания: порядок сортировки от такого не переворачивается.
    assert!(mean < 4.0, "сетка переключается слишком часто: §6.3 нарушен, средний сдвиг {mean}");
    assert!(per_coord < 1.0e-2, "доля переключённых координат {per_coord} - кластеры будут расходиться");
}

/// Проверяет, что `cluster_id` устойчив к тому же возмущению: расхождение издателя и узла стоит
/// recall, но не должно быть массовым (§7.3).
#[test]
fn gate_iv_cluster_assignment_is_stable_under_perturbation() {
    let artifact = reference_artifact();
    let centroids = &artifact.centroids;
    let corpus = texts(2000);
    let model = HashModel::new();
    let mut moved = 0usize;
    for t in &corpus {
        let pooled = model.embed_pooled(t).unwrap();
        let a = finalize(&pooled, centroids, PREPROCESSING_VERSION).unwrap();
        // Сдвиг каждого значения pooled на 1e-5 в одну сторону: худший случай для направления.
        let shifted: Pooled = std::array::from_fn(|k| pooled[k] + 1e-5);
        let b = finalize(&shifted, centroids, PREPROCESSING_VERSION).unwrap();
        moved += usize::from(a.cluster_id != b.cluster_id);
    }
    let pct = 100.0 * moved as f64 / corpus.len() as f64;
    println!("сдвиг входа на 1e-5 меняет cluster_id в {pct:.2}% записей (допуск §7.3 на расхождение издателя и узла: 1-5%)");
    assert!(pct < 25.0, "присваивание кластера неустойчиво: {pct}% записей сменили кластер");
}

// ------------------------------------------------------------ (ii) механика IVF --

/// Механика гейта (ii): ANN-результат сравнивается с brute-force в **том же** int8-представлении
/// (§8.6), через настоящие `IvfIndex`, `Centroids::top` и группировку по шардам (§7.5).
///
/// Инварианты, которые проверяются как гейт:
/// * `nprobe = NLIST` (полный скан) обязан совпасть с brute-force целиком, вплоть до порядка выдачи;
/// * recall монотонен по `nprobe` - множество кандидатов расширяется, и это следствие того, что
///   `Centroids::top` берёт префикс одного и того же полного порядка;
/// * число шардов в fan-out не превышает `nprobe` (§7.5: один `Find` на шард).
///
/// Число recall на синтетике печатается, но гейтом не считается: у синтетического распределения
/// нет отношения к реальным интент-текстам, и §8.6 обещает цифру «попавшую в спеку из замера», а
/// не из стенда.
#[test]
fn gate_ii_ann_machinery_matches_brute_force_at_full_probe() {
    let s = Synthetic::generate(corpus_size(), n_queries());
    let centroids = Centroids::from_i8(&s.centroid_bytes()).expect("синтетический centroid.bin");
    let corpus = Corpus::build(&s, &centroids);

    println!(
        "корпус: {} записей, {} кластеров, {} запросов, режим {}",
        s.len(),
        NLIST,
        s.queries.len(),
        if full_mode() { "полный" } else { "быстрый" }
    );

    let mut recalls = vec![];
    let mut truth_cache: Vec<Vec<u32>> = Vec::with_capacity(s.queries.len());
    for q in &s.queries {
        truth_cache.push(brute_force(&s.points, q, 10));
    }

    for &nprobe in [1u64, 4, 16, 24, 32].iter().chain(std::iter::once(&(NLIST as u64))) {
        let mut rec_sum = 0.0;
        let mut worst_shards = 0usize;
        let mut mismatches = 0usize;
        let t0 = Instant::now();
        for (q, truth) in s.queries.iter().zip(truth_cache.iter()) {
            let ann = corpus.ann_search(&centroids, q, nprobe as usize, 10, &mut worst_shards);
            assert!(
                worst_shards <= nprobe as usize,
                "fan-out {} шардов при nprobe {nprobe}: кластеры одного шарда обязаны группироваться (§7.5)",
                worst_shards
            );
            rec_sum += recall_at_k(truth, &slots_of(&ann), 10);
            if nprobe as usize == NLIST as usize && slots_of(&ann) != *truth {
                mismatches += 1;
            }
        }
        let per_query = t0.elapsed().div_f64(s.queries.len() as f64);
        let mean = rec_sum / s.queries.len() as f64;
        recalls.push((nprobe, mean));
        if nprobe as usize == NLIST as usize {
            assert_eq!(mean, 1.0, "полный скан обязан быть тождественен brute-force, а не «близок»");
            assert_eq!(mismatches, 0, "полный скан разошёлся с brute-force по порядку выдачи");
        }
        println!(
            "  nprobe={nprobe:>5}  recall@10 = {mean:.4}  макс. шардов в fan-out {worst_shards}  поиск {ms:.3} мс/запрос",
            ms = per_query.as_secs_f64() * 1e3
        );
    }

    // Монотонность по nprobe - свойство алгоритма, оно обязано держаться на любых данных.
    for w in recalls.windows(2) {
        let (a, ra) = w[0];
        let (b, rb) = w[1];
        assert!(
            rb + 1e-12 >= ra,
            "recall@10 упал при росте nprobe {a} -> {b}: {ra} > {rb} - значит множество кандидатов не вложено"
        );
    }
    println!(
        "механика IVF подтверждена; гейт (ii) (§18.1) ЖДЁТ реальный корпус: recall@16 = {:.4} на синтетике, порогу 0.95 это не аргумент",
        recalls.iter().find(|(n, _)| *n == 16).map(|(_, r)| *r).unwrap_or(0.0)
    );
}

/// Стоимость квантования и assign против бюджета §6.1 (< 0.3 мс). Включается только в release:
/// в debug-профиле целочисленный цикл на этой машине медленнее на два порядка, и «масштабированный
/// порог» ничего бы не доказал.
#[test]
fn gate_i_quantize_and_assign_cost() {
    let artifact = reference_artifact();
    let model = HashModel::new();
    let pooled: Vec<Pooled> = texts(200).iter().map(|t| model.embed_pooled(t).unwrap()).collect();

    let mut lat = Vec::with_capacity(pooled.len());
    for p in &pooled {
        let t0 = Instant::now();
        let e = finalize(black_box(p), &artifact.centroids, PREPROCESSING_VERSION).unwrap();
        lat.push(t0.elapsed());
        black_box(e);
    }
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    let mut sorted: Vec<Duration> = lat.clone();
    sorted.sort_unstable();
    let p50 = median(&sorted.iter().map(|d| d.as_nanos() as f64).collect::<Vec<_>>()) / 1e6;
    let p99 = sorted[(sorted.len() * 99) / 100];

    println!(
        "квантование + assign по {} центроидов: p50 {p50:.4} мс, p99 {:.4} мс, максимум {:.4} мс (бюджет §6.1: 0.3 мс)",
        NLIST,
        ms(p99),
        ms(*sorted.last().unwrap())
    );
    if cfg!(debug_assertions) {
        println!("  профиль debug: время не гейтуется, проверены только корректность и конечность");
    } else {
        assert!(
            p99 < ASSIGN_BUDGET,
            "release-прогон: assign p99 {:.4} мс против бюджета 0.3 мс (§6.1)",
            ms(p99)
        );
    }
}

// --------------------------------------------------------------- (iii) rerank --

/// Контракт реранка (§12.4, §8.6): порядок - это перестановка шортлиста, а не новое множество,
/// равные скоры разрешаются по ANN-порядку, и метрика считает то, что действительно было выдано.
///
/// Дельта nDCG@10 из гейта (iii) без кросс-энкодера не измеряется: нужен скор пары (query, text).
/// Здесь проверяется механика, на которой она и будет считаться, и одновременно показывается
/// «потолок»: реранк по истинному порядку даёт nDCG = 1 ровно тогда, когда ANN-множество уже
/// содержит истинный топ-k.
#[test]
fn gate_iii_rerank_contract_and_metric_machinery() {
    let s = Synthetic::generate(4, 8);
    let centroids = Centroids::from_i8(&s.centroid_bytes()).unwrap();
    let corpus = Corpus::build(&s, &centroids);

    let mut ann_equals_truth = 0usize;
    let mut rerank_ceiling_ok = true;
    for q in &s.queries {
        let truth = brute_force(&s.points, q, 10);
        let mut worst = 0usize;
        let ann = corpus.ann_search(&centroids, q, 16, 10, &mut worst);
        let after_slots = slots_of(&ann);
        let ann_set = sorted_ids(&after_slots);
        let truth_set = sorted_ids(&truth);

        // «Оракул» вместо кросс-энкодера: скор = минус позиция в истинном порядке. Кандидаты,
        // которых в истине нет, получают одинаковый худший скор - их взаимный порядок остаётся
        // ANN-ным, что и проверяет разрешение равенства скоров.
        let scores: Vec<f32> = ann
            .iter()
            .map(|(_, slot)| match truth.iter().position(|t| *t == *slot) {
                Some(pos) => -(pos as f32),
                None => -1000.0,
            })
            .collect();
        let ordered = order_by_scores(&ann, &scores).unwrap();
        let after: Vec<u32> = ordered.iter().map(|d| d.slot).collect();
        if ann_set == truth_set {
            ann_equals_truth += 1;
            rerank_ceiling_ok &= after == truth;
        } else {
            // Множества разные => реранк не обязан возвращать истинный порядок и не обязан
            // ничего сохранять: он не может достать то, чего нет в шортлисте (§8.6).
            assert_eq!(sorted_ids(&after), ann_set, "реранк изменил МНОЖЕСТВО кандидатов - этого делать нельзя");
        }
    }
    println!("из {} запросов ANN-шортлист совпал с brute-force по множеству: {ann_equals_truth}", s.queries.len());
    assert!(rerank_ceiling_ok, "при совпадающем множестве реранк по истинному порядку обязан вернуть истинный порядок");
    println!("гейт (iii) ЖДЁТ кросс-энкодер: измерен контракт порядка, дельта nDCG@10 без модели не считается");
}

// ------------------------------------------------------------------ инфраструктура --

/// Корпус из 64 шардов плюс отображение локального slot'а в глобальный индекс точки.
///
/// Отображение строится один раз при сборке: обратный проход по аренам на каждое попадание
/// превратил бы замер поиска в замер обхода корпуса, и `gate_ii` измерял бы не IVF.
struct Corpus {
    shards: Vec<IvfIndex>,
    /// `global[shard][slot] = id` точки в `Synthetic::points`.
    global: Vec<Vec<u32>>,
}

impl Corpus {
    /// Один индекс на шард - как в реальной сети (§7.4): запись лежит в том шарде, которому
    /// принадлежит её `cluster_id`.
    fn build(s: &Synthetic, centroids: &Centroids) -> Self {
        let mut shards: Vec<IvfIndex> = (0..SHARDS).map(IvfIndex::new).collect();
        let mut global: Vec<Vec<u32>> = vec![Vec::new(); SHARDS as usize];
        for (id, p) in s.points.iter().enumerate() {
            let cluster = centroids.assign(p);
            let sh = shard_of_cluster(cluster) as usize;
            let owner = *blake3::hash(format!("owner-{id}").as_bytes()).as_bytes();
            let out = shards[sh]
                .insert(IndexEntry {
                    owner_ed25519: owner,
                    vec_q: *p,
                    cluster_id: cluster,
                    published_bucket: 0,
                    ttl_buckets: u16::MAX,
                })
                .expect("вставка синтетической записи");
            assert!(!out.replaced, "у синтетических записей уникальные владельцы");
            if global[sh].len() <= out.slot as usize {
                global[sh].resize(out.slot as usize + 1, u32::MAX);
            }
            global[sh][out.slot as usize] = id as u32;
        }
        Self { shards, global }
    }

    fn to_global(&self, shard: u16, slot: u32) -> u32 {
        self.global[shard as usize]
            .get(slot as usize)
            .copied()
            .unwrap_or_else(|| panic!("шард {shard} вернул несуществующий slot {slot}"))
    }

    /// ANN тем же кодом, что и узел: топ-`nprobe` центроидов, группировка по шардам, `search` на
    /// каждый шард, слияние по `(d2, slot)`. Возвращает пары `(d2, глобальный id)`.
    fn ann_search(
        &self,
        centroids: &Centroids,
        q: &[i8; DIM],
        nprobe: usize,
        k: usize,
        worst_shards: &mut usize,
    ) -> Vec<(u32, u32)> {
        let clusters = centroids.top(q, nprobe);
        let per_shard = group_by_shard(&clusters);
        *worst_shards = (*worst_shards).max(per_shard.len());
        let mut hits: Vec<(u32, u32)> = Vec::new();
        for (shard, list) in per_shard {
            for (d2, slot) in self.shards[shard as usize].search(q, &list, k, 0) {
                hits.push((d2, self.to_global(shard, slot)));
            }
        }
        hits.sort_unstable();
        hits.truncate(k);
        hits
    }
}

/// Истинный топ-k полным перебором в том же int8-представлении (§8.6).
/// Возвращает **глобальные id** в порядке `(d2, id)` - то же, что выдаёт `ann_search`.
fn brute_force(points: &[[i8; DIM]], q: &[i8; DIM], k: usize) -> Vec<u32> {
    let mut all: Vec<(u32, u32)> =
        points.iter().enumerate().map(|(id, p)| (l2_sq(q, p), id as u32)).collect();
    all.sort_unstable();
    all.truncate(k);
    all.into_iter().map(|(_, id)| id).collect()
}

fn slots_of(pairs: &[(u32, u32)]) -> Vec<u32> {
    pairs.iter().map(|(_, id)| *id).collect()
}

fn sorted_ids(ids: &[u32]) -> Vec<u32> {
    let mut v = ids.to_vec();
    v.sort_unstable();
    v
}

/// Параллельный прогон пайплайна: `threads` потоков, каждому - непрерывный кусок по индексам.
fn run_parallel(artifact: &Artifact, model: &HashModel, corpus: &[String], threads: usize) -> Vec<Encoded> {
    let chunk = corpus.len().div_ceil(threads);
    let mut out: Vec<Vec<Encoded>> = vec![Vec::new(); threads];
    std::thread::scope(|scope| {
        for (i, slot) in out.iter_mut().enumerate() {
            let start = (i * chunk).min(corpus.len());
            let end = (start + chunk).min(corpus.len());
            // Именно spawn, а не последовательный вызов: гейт (iv) проверяет отсутствие
            // разделяемого состояния между потоками, и «одинаково» надо получать в параллели.
            scope.spawn(move || {
                slot.extend(run_serial(artifact, model, &corpus[start..end]));
            });
        }
    });
    out.concat()
}

fn run_serial(artifact: &Artifact, model: &HashModel, corpus: &[String]) -> Vec<Encoded> {
    let enc = Encoder::from_artifact(artifact).expect("эталонный артефакт читается контрактом");
    corpus
        .iter()
        .map(|t| enc.encode_intent(model, t).expect("текст оракула обязан проходить валидацию"))
        .map(|i| i.encoded)
        .collect()
}
