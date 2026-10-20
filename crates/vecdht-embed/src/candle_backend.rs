//! Шаг 4 пайплайна §6.2: forward модели. Только под feature `candle` (§17.2, §18.1 v).
//!
//! Здесь живёт единственная часть контракта, которая не может быть детерминирована по построению,
//! — поэтому она и изолирована: без весов crate не собирается с этой feature'ой, а с feature'ой,
//! но без каталога модели, — падает на загрузке с внятной ошибкой, а не на первом же инференсе.
//!
//! Почему f32, а не bf16 (§6.1): веса лежат в bfloat16, и candle апкастит их один раз при
//! загрузке (`VarBuilder` на `DType::F32`). Контракт ограничивает возмущение входа одной величиной
//! (1e-5 из §6.3), а bf16-арифметика добавила бы второй, независимый источник расхождения, который
//! нельзя ни оценить, ни воспроизвести.
//!
//! Что здесь **не** делается: pooling-головы классификации и проекции. `modules.json` гранита
//! говорит «CLS + normalize», а normalize — это шаг 6 (§6.2), который делает
//! [`crate::model::finalize`]; значит после бэкбона не должно быть ни одного линейного слоя. Если
//! артефакт принесёт `pooler`/проекцию — это другой `preprocessing_version`, а не эта сборка.

use std::path::Path;

use candle_core::{D, Device, DType, IndexOp, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::modernbert::Config;
use tokenizers::{TruncationParams, Tokenizer};

use crate::modernbert_backbone::{activation_from_config_json, Backbone};

use vecdht_artifact::Pooling;
use vecdht_crypto::DIM;

use crate::model::{EmbedError, EmbeddingModel, Pipeline, Pooled};

/// Имена файлов каталога модели (§15.1: веса и tokenizer пинятся хешем в манифесте, а не
/// пересылаются по сети).
pub const CONFIG_FILE: &str = "config.json";
pub const TOKENIZER_FILE: &str = "tokenizer.json";
pub const WEIGHTS_FILE: &str = "model.safetensors";

/// Переменная окружения, из которой harness берёт каталог модели (§18.1 v). Не задана — гейты,
/// требующие весов, считаются неизмеренными, а не проваленными.
pub const MODEL_DIR_ENV: &str = "VEC_DHT_MODEL_DIR";

/// Bi-encoder ModernBERT на candle: шаги 3–5 пайплайна (§6.2).
pub struct ModernBertEmbedder {
    tokenizer: Tokenizer,
    model: Backbone,
    device: Device,
    pooling: Pooling,
    add_special_tokens: bool,
    model_version: String,
    preprocessing_version: u16,
}

impl ModernBertEmbedder {
    /// Загрузить каталог модели. `pipeline` несёт контрактные параметры (pooling, max_length,
    /// add_special_tokens) — они берутся из манифеста, а не из `config.json`, потому что манифест
    /// подписан авторитетами (§15.2), а `config.json` — файл из того же каталога, который мы
    /// проверяем по хешу весов.
    pub fn from_dir(dir: &Path, pipeline: &Pipeline, model_version: &str) -> Result<Self, EmbedError> {
        let cfg_text = std::fs::read_to_string(dir.join(CONFIG_FILE))
            .map_err(|e| backend(format!("{CONFIG_FILE} не читается в {dir:?}: {e}")))?;
        let config: Config = serde_json::from_str(&cfg_text)
            .map_err(|e| backend(format!("{CONFIG_FILE}: {e}")))?;
        // Активация — часть контракта модели, но не часть candle-структуры Config: без
        // отдельного чтения `hidden_activation: silu` превращается в GELU (см. гейт v).
        let activation = activation_from_config_json(&cfg_text)
            .map_err(|e| backend(format!("{CONFIG_FILE}: {e}")))?;
        // Размерность выхода — часть контракта: 384 (§6.1). Модель с другим hidden_size это уже
        // не `granite-embedding-97m-v2`, и её векторы не лягут в тот же артефакт.
        if config.hidden_size != DIM {
            return Err(EmbedError::WrongDim { got: config.hidden_size, want: DIM });
        }

        let device = Device::Cpu;
        let weights = std::fs::read(dir.join(WEIGHTS_FILE))
            .map_err(|e| backend(format!("{WEIGHTS_FILE} не читается: {e}")))?;
        // `candle_transformers::models::modernbert::ModernBert::load` адресует веса как
        // `model.embeddings...` (checkpoint `ModernBertForMaskedLM`), а опубликованный
        // granite-97m-r2 — это `ModernBertModel`: в его `model.safetensors` префикса `model.`
        // нет. Без переименования загрузка падает на первом же тензоре, поэтому префикс
        // добавляется здесь, один раз; формат самого файла и его хеш не меняются.
        let tensors = candle_core::safetensors::load_buffer(&weights, &device)
            .map_err(|e| backend(format!("{WEIGHTS_FILE}: {e}")))?;
        let tensors = match tensors.keys().any(|k| k.starts_with("model.")) {
            true => tensors,
            false => tensors
                .into_iter()
                .map(|(name, tensor)| (format!("model.{name}"), tensor))
                .collect(),
        };
        let vb = VarBuilder::from_tensors(tensors, DType::F32, &device);
        let model = Backbone::load(vb, &config, activation)
            .map_err(|e| backend(format!("сборка модели: {e}")))?;

        let tokenizer_path = dir.join(TOKENIZER_FILE);
        let mut tokenizer =
            Tokenizer::from_file(&tokenizer_path).map_err(|e| backend(format!("{TOKENIZER_FILE}: {e}")))?;
        // Шаг 3 пайплайна: max_length из манифеста, обрезка с хвоста (§6.2). Направление не
        // выбирается здесь: `TruncationParams::default()` — это `TruncationDirection::Right`, то
        // есть ровно «обрезка с хвоста», и если реализация tokenizers сменит дефолт, тест гейта
        // (v) это поймает по расхождению векторов.
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: pipeline.max_length as usize,
                ..Default::default()
            }))
            .map_err(|e| backend(format!("обрезка до max_length={}: {e}", pipeline.max_length)))?;

        Ok(Self {
            tokenizer,
            model,
            device,
            pooling: pipeline.pooling,
            add_special_tokens: pipeline.add_special_tokens,
            model_version: model_version.to_string(),
            preprocessing_version: pipeline.preprocessing_version,
        })
    }

    /// Каталог из `VEC_DHT_MODEL_DIR`, либо `None` — честный ответ «весов нет», который harness
    /// (§18.1 i, iii, v) трактует как «гейт не измерялся», а не «гейт провален».
    pub fn from_env(pipeline: &Pipeline, model_version: &str) -> Result<Option<Self>, EmbedError> {
        match std::env::var_os(MODEL_DIR_ENV) {
            Some(dir) if !dir.is_empty() => Ok(Some(Self::from_dir(Path::new(&dir), pipeline, model_version)?)),
            _ => Ok(None),
        }
    }

    /// Сколько токенов реально ушло в модель — диагностика для гейта (i): длина входа решает
    /// стоимость инференса, а не число символов (§6.1: «предложение 20–80 токенов»).
    pub fn token_len(&self, text: &str) -> Result<usize, EmbedError> {
        let enc = self
            .tokenizer
            .encode(text, self.add_special_tokens)
            .map_err(|e| backend(format!("tokenize: {e}")))?;
        Ok(enc.get_ids().len())
    }
}

impl EmbeddingModel for ModernBertEmbedder {
    fn embed_pooled(&self, model_input: &str) -> Result<Pooled, EmbedError> {
        let enc = self
            .tokenizer
            .encode(model_input, self.add_special_tokens)
            .map_err(|e| backend(format!("tokenize: {e}")))?;
        let ids = enc.get_ids();
        let mask = enc.get_attention_mask();
        if ids.len() != mask.len() {
            return Err(backend(format!("tokenizer: ids {} против mask {}", ids.len(), mask.len())));
        }
        if ids.is_empty() {
            return Err(backend("tokenizer вернул 0 токенов — пустой вход не инференсится".into()));
        }
        let seq = ids.len();
        let ids_t = Tensor::from_vec(ids.to_vec(), (1, seq), &self.device)
            .map_err(|e| backend(format!("ids: {e}")))?;
        let mask_t = Tensor::from_vec(mask.to_vec(), (1, seq), &self.device)
            .map_err(|e| backend(format!("mask: {e}")))?;

        // batch=1, один проход (§6.2 шаг 4).
        let hidden = self
            .model
            .forward(&ids_t, &mask_t)
            .map_err(|e| backend(format!("forward: {e}")))?;

        let pooled = match self.pooling {
            Pooling::Cls => hidden.i((.., 0, ..)).map_err(|e| backend(format!("CLS: {e}")))?,
            Pooling::MeanNonPad => {
                // Mean по non-pad: ровно та же формула, что в `ModernBertForSequenceClassification`
                // (candle 0.10), — своя реализация означала бы тихое расхождение с HF-референсом.
                let m = mask_t
                    .unsqueeze(D::Minus1)
                    .and_then(|t| t.to_dtype(DType::F32))
                    .map_err(|e| backend(format!("mean: mask: {e}")))?;
                let sum = hidden
                    .broadcast_mul(&m)
                    .and_then(|t| t.sum(1))
                    .map_err(|e| backend(format!("mean: sum: {e}")))?;
                let n = mask_t
                    .sum_keepdim(1)
                    .and_then(|t| t.to_dtype(DType::F32))
                    .map_err(|e| backend(format!("mean: count: {e}")))?;
                sum.broadcast_div(&n).map_err(|e| backend(format!("mean: div: {e}")))?
            }
        };
        // `pooled` уже имеет ранг 2 — `(1, DIM)` после среза CLS или mean; `to_vec1` требует
        // ранг 1. Первая версия делала `reshape((1, DIM))` и падала на любом реальном выходе:
        // без весов этот путь не исполнялся, поэтому ошибка дожила до гейта (v).
        let flat = pooled
            .reshape(DIM)
            .and_then(|t| t.contiguous())
            .and_then(|t| t.to_vec1::<f32>())
            .map_err(|e| backend(format!("pooling → vec: {e}")))?;
        if flat.len() != DIM {
            return Err(EmbedError::WrongDim { got: flat.len(), want: DIM });
        }
        let mut out = [0f32; DIM];
        out.copy_from_slice(&flat);
        Ok(out)
    }

    fn model_version(&self) -> &str {
        &self.model_version
    }

    fn preprocessing_version(&self) -> u16 {
        self.preprocessing_version
    }

    fn pooling(&self) -> Pooling {
        self.pooling
    }
}

/// Ошибка бэкенда: текст всегда собирается здесь, чтобы `EmbedError` не тащил candle-типы в
/// публичный API crate, собранного без feature.
fn backend(detail: String) -> EmbedError {
    EmbedError::Backend(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_artifact::reference_manifest;

    fn pipeline() -> Pipeline {
        Pipeline::from_manifest(&reference_manifest()).unwrap()
    }

    /// Тексты гейта (v) — часть протокола измерения, а не удобная выборка: смена строк делает
    /// `VEC_DHT_HF_REFERENCE` недействительным и требует перегенерации референса.
    ///
    /// Набор закрывает классы, на которых ошибка загрузки или активации может не проявиться на
    /// одном коротком предложении: кириллица, английский, очень короткий вход, смешанная
    /// мультиязычность и ровно `max_length = 256` токенов, то есть обе ветки обрезки.
    fn gate_v_texts() -> Vec<String> {
        vec![
            "Ищу контрагента для vector search".to_string(),
            "Find a contractor for vector search".to_string(),
            "короткий текст".to_string(),
            "мультиязычный запрос: 東京でベクトル検索".to_string(),
            // Python-референс писал `(sentence * 40).strip()`; `trim()` даёт те же байты UTF-8.
            "Это длинный текст для проверки обрезки по max_length. "
                .repeat(40)
                .trim()
                .to_string(),
        ]
    }

    fn cosine(a: &[f32], b: &[f32]) -> f64 {
        let dot: f64 = a.iter().zip(b).map(|(x, y)| f64::from(*x) * f64::from(*y)).sum();
        let na: f64 = a.iter().map(|x| f64::from(*x) * f64::from(*x)).sum::<f64>().sqrt();
        let nb: f64 = b.iter().map(|y| f64::from(*y) * f64::from(*y)).sum::<f64>().sqrt();
        dot / (na * nb)
    }

    /// Гейт (v) из §18.1: granite-97m-r2 против HF-референса, косинус ≥ 0.999 на каждом тексте.
    ///
    /// Без каталога модели тест **не** считается пройденным и **не** проваливается — он ничего не
    /// утверждает. Проваливать сборку без весов означало бы, что `cargo test` зелёный только там,
    /// где кто-то скачал 200 МБ, и это ровно та ложь, которую §18 принципиально не допускает.
    #[test]
    fn gate_v_against_hf_reference() {
        let Some(embedder) = ModernBertEmbedder::from_env(&pipeline(), "granite-embedding-97m-v2")
            .expect("VEC_DHT_MODEL_DIR задан, но модель не загружается")
        else {
            println!(
                "гейт (v) НЕ ИЗМЕРЕН: {MODEL_DIR_ENV} не задан. Положите в каталог config.json, \
                 tokenizer.json и model.safetensors, затем:\n  \
                 VEC_DHT_MODEL_DIR=<путь> cargo test --release -p vecdht-embed --features candle -- --nocapture"
            );
            return;
        };
        // Референсные векторы обязан принести артефакт: без запиненных HF-выходов сравнение
        // нечем провести, и выдумывать их здесь нельзя.
        let reference: Option<Vec<f32>> = std::env::var_os("VEC_DHT_HF_REFERENCE")
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.split_whitespace().filter_map(|x| x.parse().ok()).collect());
        let Some(reference) = reference else {
            println!("модель загружена, но VEC_DHT_HF_REFERENCE не задан: сравнивать не с чем");
            return;
        };
        let texts = gate_v_texts();
        assert_eq!(
            reference.len() % DIM,
            0,
            "HF-референс длиной {} не кратен DIM={DIM}: это не набор векторов",
            reference.len()
        );
        let vectors = reference.len() / DIM;
        assert_eq!(
            vectors,
            texts.len(),
            "в HF-референсе {vectors} векторов, а текстов гейта {}: референс и строки разошлись",
            texts.len()
        );

        let mut worst = f64::INFINITY;
        for (i, text) in texts.iter().enumerate() {
            let got = embedder.embed_pooled(text).unwrap();
            let want = &reference[i * DIM..(i + 1) * DIM];
            let cos = cosine(&got, want);
            println!("вектор {i}: косинус candle против HF = {cos:.6}");
            worst = worst.min(cos);
        }
        println!("минимум по {} текстам: {worst:.6}", texts.len());
        assert!(
            worst >= 0.999,
            "гейт (v): минимальный косинус {worst} ниже 0.999 — нужен fallback из §6.1"
        );
    }

    /// Гейт (i) из §18.1: фактический throughput реального инференса.
    ///
    /// Это измерение, а не порог: у гейта (i) нет pass/fail — его числа пересчитывают бюджеты
    /// §6.1/§12.6 и решают, сколько стоит корпус для гейта (ii). Тяжёлый прогон, поэтому
    /// `#[ignore]`: `cargo test` без весов и без явного вызова его не запускает.
    ///
    /// `RAYON_NUM_THREADS` задаёт intra-op параллелизм candle; без переменной rayon берёт все
    /// логические ядра. Прогон на 1/4/16 потоках — три отдельных процесса, потому что пул
    /// rayon фиксируется при старте.
    #[test]
    #[ignore = "P0(i): требует весов; запускать вручную с RAYON_NUM_THREADS"]
    fn measure_i_real_inference_throughput() {
        use std::time::{Duration, Instant};

        let Some(embedder) = ModernBertEmbedder::from_env(&pipeline(), "granite-embedding-97m-v2")
            .expect("VEC_DHT_MODEL_DIR задан, но модель не загружается")
        else {
            println!("гейт (i) НЕ ИЗМЕРЕН: {MODEL_DIR_ENV} не задан");
            return;
        };

        // 20–80 токенов по §6.1: три длины, по семь текстов. Повтор базы — не «реалистичный
        // корпус», а способ получить предсказуемую длину входа; стоимость forward зависит от
        // неё, а не от смысла текста.
        const PER_LENGTH: usize = 7;
        let base = "Ищу контрагента для векторного поиска в распределённой сети без центрального \
                    сервера и обязательной регистрации";
        let mut texts = Vec::new();
        for repeat in 1..=3 {
            let text = vec![base; repeat].join(" ");
            for _ in 0..PER_LENGTH {
                texts.push(text.clone());
            }
        }

        let token_lens: Vec<usize> = texts
            .iter()
            .map(|t| embedder.token_len(t).expect("tokenizer"))
            .collect();
        let mut sorted_lens = token_lens.clone();
        sorted_lens.sort_unstable();
        let median_tokens = sorted_lens[sorted_lens.len() / 2];

        // Прогрев: первый forward включает ленивую инициализацию ядер, его нельзя мешать с
        // установившимся режимом.
        for text in texts.iter().take(3) {
            embedder.embed_pooled(text).expect("прогрев");
        }

        let mut durations = Vec::with_capacity(texts.len());
        let total_start = Instant::now();
        for text in &texts {
            let start = Instant::now();
            let vector = embedder.embed_pooled(text).expect("forward");
            durations.push(start.elapsed());
            assert_eq!(vector.len(), DIM);
        }
        let total = total_start.elapsed();

        durations.sort_unstable();
        let p50 = durations[durations.len() / 2];
        let p95 = durations[(durations.len() * 95 / 100).min(durations.len() - 1)];
        let throughput = texts.len() as f64 / total.as_secs_f64();
        let threads = std::env::var("RAYON_NUM_THREADS")
            .unwrap_or_else(|_| format!("unset ({} доступных)", std::thread::available_parallelism().map_or(0, |n| n.get())));

        println!(
            "P0(i): потоков rayon {threads}; текстов {}; токенов {}..{} (медиана {median_tokens}); \
             прогрев 3",
            texts.len(),
            sorted_lens[0],
            sorted_lens[sorted_lens.len() - 1],
        );
        println!(
            "  p50 {:.1} мс, p95 {:.1} мс, min {:.1} мс, max {:.1} мс; \
             throughput {throughput:.3} emb/s (весь батч за {:.2} с)",
            ms(p50),
            ms(p95),
            ms(durations[0]),
            ms(durations[durations.len() - 1]),
            total.as_secs_f64(),
        );
        assert!(throughput.is_finite() && throughput > 0.0);

        fn ms(d: Duration) -> f64 {
            d.as_secs_f64() * 1000.0
        }
    }
}
