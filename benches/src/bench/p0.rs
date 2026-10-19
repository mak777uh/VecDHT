//! Замеры P0-гейтов (§18.1): throughput детерминированной половины пайплайна, fan-out по шардам,
//! детерминизм выходов и механика recall.
//!
//! Что этот прогон измеряет, а что принципиально не может:
//!
//! | Гейт §18.1 | Здесь |
//! |---|---|
//! | (i) throughput | измерена целочисленная половина (нормализация, квантование, assign, поиск). Инференс — только с `candle` и `VEC_DHT_MODEL_DIR`, его число печатает `crates/vecdht-embed/tests/p0_harness.rs` |
//! | (ii) recall@10 | измерена **механика** на синтетике; число гейта требует ≥50k реальных интент-текстов и контрактной модели, и в спеку оно из стенда не переносится |
//! | (iii) rerank gain | НЕ ИЗМЕРЕН: нужен кросс-энкодер, а не скор по int8-дистанции |
//! | (iv) детерминизм | измерен: повторный прогон обязан быть побайтовым, включая `artifact_hash` |
//! | (v) candle modernbert | НЕ ИЗМЕРЕН без каталога весов |
//!
//! Гейты на порогах живут в тестах (`cargo test --release`), здесь — только числа и условия
//! прогона. Разделение не косметическое: «красный» замер на чужом диске соврал бы о коде.

use std::time::Instant;

use vecdht_artifact::{Centroids, reference_artifact};
use vecdht_crypto::quant::{group_by_shard, l2_sq, shard_of_cluster};
use vecdht_embed::metrics::recall_at_k;
use vecdht_embed::model::EmbeddingModel;
use vecdht_embed::testing::{HashModel, Synthetic};
use vecdht_embed::{Encoder, PREPROCESSING_VERSION};
use vecdht_index::ivf::IvfIndex;
use vecdht_index::{IndexEntry, SHARDS};
use vecdht_wire::{DIM, NLIST};

use vecdht_benches::{Sink, header, not_measured, rate, scale, value};

/// Тексты той же формы, что и в harness'е: разная длина, кириллица, латиница, хвостовые пробелы —
/// чтобы шаг 1 (§6.6) тоже был в измеряемом пути, а не только «квантование».
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

fn main() {
    let k = scale();
    header("p0", "гейты §18.1: throughput целочисленной половины, fan-out (§7.5), детерминизм, механика recall");

    let artifact = reference_artifact();
    let enc = Encoder::from_artifact(&artifact).expect("эталонный артефакт читается контрактом");
    let model = HashModel::new();

    // 1. Throughput пайплайна без инференса: normalize_text → prefix → (суррогатный pooled) →
    //    квантование → assign. Это ровно то, что останется после вычитания forward'а из гейта (i).
    let corpus = texts(200 * k);
    let mut sink = Sink::default();
    let t = Instant::now();
    for txt in &corpus {
        let i = enc.encode_intent(&model, txt).expect("текст оракула обязан проходить валидацию");
        sink.add(u64::from(i.encoded.cluster_id));
    }
    rate("encode_intent (суррогатный pooled: preprocess + квантование + assign)", corpus.len(), t.elapsed());
    sink.commit("encode-intent");

    // Только шаги 6–8, без normalize и без «модели»: бюджет §6.1 (< 0.3 мс) относится к ним.
    let pooled: Vec<_> = corpus.iter().map(|txt| model.embed_pooled(txt).unwrap()).collect();
    let t = Instant::now();
    let mut s2 = Sink::default();
    for p in &pooled {
        let e = vecdht_embed::finalize(p, &artifact.centroids, PREPROCESSING_VERSION).unwrap();
        s2.add(u64::from(e.cluster_id));
    }
    let el = t.elapsed();
    rate("finalize = квантование + assign по 1024 центроидам", pooled.len(), el);
    value("доля бюджета §6.1 (0.3 мс) на один finalize", el.as_secs_f64() / pooled.len() as f64 / 3e-4, "×");
    s2.commit("finalize");

    // 2. Детерминизм (гейт iv): два прогона обязаны совпасть побайтно, включая intent_id и
    //    кластер; «почти совпало» — это уже другой preprocessing.
    let first: Vec<_> = corpus.iter().map(|t| enc.encode_intent(&model, t).unwrap().encoded).collect();
    let second: Vec<_> = corpus.iter().map(|t| enc.encode_intent(&model, t).unwrap().encoded).collect();
    let same = first
        .iter()
        .zip(second.iter())
        .filter(|(a, b)| a.vec_q == b.vec_q && a.intent_id == b.intent_id && a.cluster_id == b.cluster_id)
        .count();
    println!("повторный прогон пайплайна: {same}/{} выходов идентичны побайтно", corpus.len());
    // Хеш артефакта — то, во что упирается вся сверка узлов (§15.1): он обязан воспроизводиться
    // из байтов центроидов и манифеста на любой машине, иначе «одинаковый артефакт» означает
    // «разные пространства», и recall двух узлов не сравним.
    let short = |b: &[u8]| -> String { b.iter().take(8).map(|x| format!("{x:02x}")).collect() };
    let h1 = artifact.artifact_hash();
    let h2 = reference_artifact().artifact_hash();
    println!("artifact_hash воспроизводим: {} (первые 8 байт: {})", h1 == h2, short(&h1));

    // 3. Fan-out (§7.5): один `Find` на шард, и именно число шардов в группе — сетевая цена
    //    запроса. Меряем на реальных выходах пайплайна (`encoded.vec_q` из шага 1), а не на
    //    «случайных» векторах, и по двум квантизаторам сразу:
    //    — синтетическому (тот же, что и корпус в шаге 4, чтобы recall и fan-out говорили об
    //      одной геометрии);
    //    — замороженным центроидам эталонного артефакта, потому что вопрос спеки «сколько `Find`
    //      на запрос» — про рабочую сеть, а не про тестовый синтетический распределитель.
    //    Расхождение строк — не баг замера, а факт о распределении: у синтетики ближайшие nprobe
    //    центроиды лежат в одном супер-блоке, то есть в одном шарде, и fan-out там искусственно
    //    минимальный.
    let s = Synthetic::generate(k, 32 * k);
    let centroids = Centroids::from_i8(&s.centroid_bytes()).expect("синтетический centroid.bin");
    let qvs: Vec<[i8; DIM]> = first.iter().map(|e| e.vec_q).collect();
    let fan_out = |cent: &Centroids, np: usize| -> (usize, f64) {
        let mut shard_sum = 0usize;
        let mut cluster_sum = 0usize;
        for q in &qvs {
            let clusters = cent.top(q, np);
            shard_sum += group_by_shard(&clusters).len();
            cluster_sum += clusters.len();
        }
        let n = qvs.len().max(1);
        (cluster_sum / n, shard_sum as f64 / n as f64)
    };
    for np in [1usize, 4, 16, 32] {
        let (cs_syn, sh_syn) = fan_out(&centroids, np);
        let (cs_art, sh_art) = fan_out(&artifact.centroids, np);
        println!(
            "nprobe {np}: синтетика — кластеров {cs_syn}, шардов {sh_syn:.1} из {SHARDS}; \
             артефакт — кластеров {cs_art}, шардов {sh_art:.1} из {SHARDS} ⇒ столько `Find` на запрос"
        );
    }

    // 4. Механика recall: IVF против brute-force в том же int8-представлении (§8.6).
    let mut shards: Vec<IvfIndex> = (0..SHARDS).map(IvfIndex::new).collect();
    // slot → глобальный id точки: без этой карты сравнение с brute-force было бы сравнением
    // разных нумераций, а не разных алгоритмов.
    let mut global: Vec<Vec<u32>> = vec![Vec::new(); SHARDS as usize];
    let t = Instant::now();
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
        if global[sh].len() <= out.slot as usize {
            global[sh].resize(out.slot as usize + 1, u32::MAX);
        }
        global[sh][out.slot as usize] = id as u32;
    }
    let build = t.elapsed();
    rate(&format!("построение корпуса из {} записей по {SHARDS} шардам", s.len()), s.len(), build);

    let truth: Vec<Vec<u32>> = s
        .queries
        .iter()
        .map(|q| {
            let mut all: Vec<(u32, u32)> =
                s.points.iter().enumerate().map(|(id, p)| (l2_sq(q, p), id as u32)).collect();
            all.sort_unstable();
            all.truncate(10);
            all.into_iter().map(|(_, id)| id).collect()
        })
        .collect();

    for np in [1usize, 4, 16, 32, NLIST as usize] {
        let mut sum = 0.0;
        let t = Instant::now();
        for (q, tr) in s.queries.iter().zip(truth.iter()) {
            let clusters = centroids.top(q, np);
            let mut hits: Vec<(u32, u32)> = Vec::new();
            for (shard, list) in group_by_shard(&clusters) {
                for (d2, slot) in shards[shard as usize].search(q, &list, 10, 0) {
                    hits.push((d2, global[shard as usize][slot as usize]));
                }
            }
            hits.sort_unstable();
            hits.truncate(10);
            sum += recall_at_k(tr, &hits.iter().map(|(_, id)| *id).collect::<Vec<_>>(), 10);
        }
        let el = t.elapsed();
        let per = sum / s.queries.len().max(1) as f64;
        let note = if np == NLIST as usize {
            assert!(
                (per - 1.0).abs() < 1e-12,
                "полный скан обязан совпасть с brute-force целиком, а не «быть близок»: {per}"
            );
            " — полный скан тождественен brute-force"
        } else {
            " — механика, не гейт (ii)"
        };
        println!(
            "  nprobe={np:>5}  recall@10 = {per:.4}{note}  поиск {:.3} мс/запрос",
            el.as_secs_f64() * 1e3 / s.queries.len().max(1) as f64
        );
    }
    not_measured(
        "гейт (ii) recall@10 ≥ 0.95",
        "нужны ≥50k реальных интент-текстов и контрактная модель; синтетика проверяет механику, \
         а не качество — см. crates/vecdht-embed/tests/p0_harness.rs",
    );
    not_measured("гейт (iii) прирост nDCG@10 от реранка", "нужен кросс-энкодер-скор пары (query, текст)");
    not_measured(
        "гейт (v) modernbert через candle",
        "нужен каталог весов: VEC_DHT_MODEL_DIR + feature `candle`, иначе forward не вызывается",
    );
}
