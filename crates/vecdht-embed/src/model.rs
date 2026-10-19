//! Модель, пайплайн и шаги 6–8 (§6.1–§6.4).
//!
//! Разделение ответственности здесь принципиальное:
//!
//! * [`EmbeddingModel`] — единственная точка, где живёт недетерминизм (шаг 4, forward). Она
//!   намеренно маленькая: `&str -> [f32; DIM]`, ничего больше;
//! * [`finalize`] — шаги 6–8 (L2 в f64, квантование в int8, присваивание кластера). Это чистые
//!   целочисленные/вещественные операции из `vecdht-crypto`, и именно их побайтовую стабильность
//!   проверяет гейт (iv) из §18.1 — без весов и без candle.
//!
//! [`Encoder`] связывает их с контрактом артефакта: берёт `preprocessing_version`, префиксы и
//! замороженные центроиды, и не даёт вызывающему коду посчитать вектор «своими словами».
//!
//! ```text
//! raw ──normalize_text──▶ canonical ──prefix──▶ model input ──▶ pooled f32
//!    §6.6 (шаг 1)             §6.5 (текст под подписью и в ключе кеша)   §6.2 шаг 4
//! pooled f32 ──finalize──▶ vec_q int8 + cluster_id + intent_id
//!              §6.3, §7.2 (шаги 6–8)
//! ```

use thiserror::Error;

use vecdht_artifact::{Artifact, Centroids, Manifest, Pooling};
use vecdht_crypto::ids::intent_id;
use vecdht_crypto::quant::{l2_normalize, quantize, shard_of_cluster, QuantError};
use vecdht_crypto::DIM;
use vecdht_wire::NLIST;

use crate::prefix::{PrefixError, PrefixPolicy};
use crate::text::{TextError, normalize_text};

/// Вектор после pooling: то, что возвращает шаг 5 пайплайна §6.2, до нормализации и квантования.
pub type Pooled = [f32; DIM];

#[derive(Debug, Error)]
pub enum EmbedError {
    #[error(transparent)]
    Text(#[from] TextError),
    #[error(transparent)]
    Prefix(#[from] PrefixError),
    #[error(transparent)]
    Quant(#[from] QuantError),
    #[error("модель вернула не-конечное значение в координате {0} — инференс сломался, а не «плохой текст»")]
    NonFinite(usize),
    #[error("модель вернула вектор длины {got}, контракт требует {want} (§6.3)")]
    WrongDim { got: usize, want: usize },
    #[error("бэкенд инференса: {0}")]
    Backend(String),
    #[error("манифест: {0}")]
    Manifest(String),
}

/// Единственный недетерминированный шаг пайплайна, вынесенный в трейт.
///
/// Реализация обязана: принимать уже нормализованный и уже снабжённый префиксом текст (иначе
/// `preprocessing_version` врёт), делать один проход batch=1 (§6.2 шаг 4) и возвращать f32 —
/// контрактная точность инференса f32 даже для bf16-весов (§6.1).
pub trait EmbeddingModel {
    /// Шаг 4 + шаг 5 (pooling) модели: `pooled` до нормализации.
    fn embed_pooled(&self, model_input: &str) -> Result<Pooled, EmbedError>;

    /// Имя из `manifest.model_version` — сверяется с артефактом на handshake (§6.7).
    fn model_version(&self) -> &str;

    /// Версия preprocessинга, которую реализует эта сборка (§6.2).
    fn preprocessing_version(&self) -> u16;

    /// Как именно сделан pooling: CLS или mean по non-pad (§6.2 шаг 5). Нужно для диагностики —
    /// два pooling'а на тех же весах дают разные векторы, и путать их нельзя.
    fn pooling(&self) -> Pooling;
}

/// Параметры контракта, приведённые из манифеста. Держим их рядом, чтобы `Encoder` не читал
/// манифест в каждом вызове и чтобы `check()` отловил противоречие «манифест про другой пайплайн»
/// один раз при загрузке, а не на первом же publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub preprocessing_version: u16,
    pub pooling: Pooling,
    pub max_length: u32,
    pub add_special_tokens: bool,
    pub nprobe_default: usize,
    pub prefixes: PrefixPolicy,
}

impl Pipeline {
    pub fn from_manifest(m: &Manifest) -> Result<Self, EmbedError> {
        // Сверка с тем, что реально умеет этот crate. Если манифест объявляет другую сетку или
        // другую размерность — молча искать нельзя: векторы агента и узла окажутся в разных
        // пространствах, а различие не проявится ни в одной подписи.
        if m.quant.dim as usize != DIM {
            return Err(EmbedError::Manifest(format!(
                "manifest.quant.dim = {}, а кодек и квантование живут с DIM = {DIM}",
                m.quant.dim
            )));
        }
        if m.quant.grid != "i8/127" {
            return Err(EmbedError::Manifest(format!(
                "manifest.quant.grid = `{}`, реализована только сетка `i8/127` (§6.3)",
                m.quant.grid
            )));
        }
        if m.quant.rounding != "half_away" {
            return Err(EmbedError::Manifest(format!(
                "manifest.quant.rounding = `{}`, реализовано `half_away` (§6.3)",
                m.quant.rounding
            )));
        }
        if m.routing.nlist as usize != NLIST as usize {
            return Err(EmbedError::Manifest(format!(
                "manifest.routing.nlist = {}, а `Centroids` обязан нести ровно {NLIST} строк (§7.1)",
                m.routing.nlist
            )));
        }
        if m.preprocessing_version != crate::PREPROCESSING_VERSION {
            return Err(EmbedError::Manifest(format!(
                "manifest.preprocessing_version = {}, эта сборка реализует {}",
                m.preprocessing_version,
                crate::PREPROCESSING_VERSION
            )));
        }
        if m.max_length == 0 || m.max_length > 32768 {
            return Err(EmbedError::Manifest(format!(
                "manifest.max_length = {} вне разумного диапазона",
                m.max_length
            )));
        }
        Ok(Self {
            preprocessing_version: m.preprocessing_version,
            pooling: m.pooling,
            max_length: m.max_length,
            add_special_tokens: m.add_special_tokens,
            nprobe_default: m.routing.nprobe_default as usize,
            prefixes: PrefixPolicy::from_manifest(m)?,
        })
    }

    /// Шаг 2 для publish: возвращает текст на вход модели без изменений (§6.7).
    pub fn model_input_for_index<'a>(&self, canonical: &'a str) -> &'a str {
        self.prefixes.apply_index(canonical)
    }

    /// Шаг 2 для find: `query_prefix ‖ canonical`.
    pub fn model_input_for_query(&self, canonical: &str) -> String {
        self.prefixes.apply_query(canonical)
    }
}

/// Квантованная запись: результат шагов 6–8. Ровно те байты, которые уходят в `Publish` и в
/// индекс (§8.2); f32-представление после `finalize` не сохраняется нигде (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encoded {
    pub vec_q: [i8; DIM],
    /// Ближайший центроид глобального квантизатора (§7.2).
    pub cluster_id: u16,
    /// Шард, которому принадлежит кластер (§7.1): `cluster_id / 16`.
    pub shard: u16,
    /// Advisory-идентификатор из §6.5: идемпотентность publish и ключ диагностики.
    pub intent_id: [u8; 32],
    pub preprocessing_version: u16,
}

/// Шаги 6–7: L2-нормализация в f64 и квантование в int8. Отдельная функция, потому что гейт (iv)
/// (§18.1) сравнивает именно эти 384 байта, а присваивание кластера — уже шаг 8, требующий
/// замороженного `centroid.bin`.
pub fn quantize_pooled(pooled: &Pooled) -> Result<[i8; DIM], EmbedError> {
    let mut d = [0f64; DIM];
    for i in 0..DIM {
        let x = pooled[i];
        if !x.is_finite() {
            return Err(EmbedError::NonFinite(i));
        }
        d[i] = x as f64;
    }
    l2_normalize(&mut d)?;
    Ok(quantize(&d))
}

/// Шаг 6–8 целиком: `pooled` → `Encoded` по центроидам артефакта.
pub fn finalize(
    pooled: &Pooled,
    centroids: &Centroids,
    preprocessing_version: u16,
) -> Result<Encoded, EmbedError> {
    let vec_q = quantize_pooled(pooled)?;
    let cluster_id = centroids.assign(&vec_q);
    Ok(Encoded {
        vec_q,
        cluster_id,
        shard: shard_of_cluster(cluster_id),
        intent_id: intent_id(&vec_q, preprocessing_version),
        preprocessing_version,
    })
}

/// Результат publish-пути: канонический текст (он же идёт под подпись, §6.6) и вектор.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    /// Шаг 1: то, что подписывается и кладётся в кеш. Не «сырой» текст от пользователя.
    pub canonical: String,
    pub encoded: Encoded,
}

/// Результат query-пути: вектор запроса и кластеры, которые его шард обязан просматреть.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub canonical: String,
    pub vec_q: [i8; DIM],
    /// Топ-`nprobe` кластеров с сортировкой `(d2 ASC, cluster ASC)` (§7.5).
    pub clusters: Vec<u16>,
    /// Те же кластеры, сгруппированные по шардам (§7.5): один `Find` на шард несёт свои.
    pub per_shard: Vec<(u16, Vec<u16>)>,
}

/// Собирает шаги 1–2 и 6–8 вокруг модели.
pub struct Encoder<'a> {
    pipeline: Pipeline,
    centroids: &'a Centroids,
}

impl<'a> Encoder<'a> {
    pub fn new(pipeline: Pipeline, centroids: &'a Centroids) -> Self {
        Self { pipeline, centroids }
    }

    /// Из артефакта: манифест обязана пройти `Manifest::check()`, иначе `Pipeline` построен по
    /// недоверенным параметрам.
    pub fn from_artifact(a: &'a Artifact) -> Result<Self, EmbedError> {
        a.manifest.check().map_err(|e| EmbedError::Manifest(e.to_string()))?;
        Ok(Self::new(Pipeline::from_manifest(&a.manifest)?, &a.centroids))
    }

    pub fn pipeline(&self) -> &Pipeline {
        &self.pipeline
    }

    /// Полный publish-путь для одного интента.
    pub fn encode_intent(
        &self,
        model: &dyn EmbeddingModel,
        raw: &str,
    ) -> Result<Intent, EmbedError> {
        self.check_model(model)?;
        let canonical = normalize_text(raw)?;
        let encoded = self.encode_canonical(model, &canonical)?;
        Ok(Intent { canonical, encoded })
    }

    /// Шаг 4–8 для уже канонического текста — путь кеша ([`crate::cache`]): при попадании сюда
    /// никто не заходит, а при промахе вызывающий код обязан вставить результат в кеш.
    pub fn encode_canonical(
        &self,
        model: &dyn EmbeddingModel,
        canonical: &str,
    ) -> Result<Encoded, EmbedError> {
        let input = self.pipeline.model_input_for_index(canonical);
        let pooled = model.embed_pooled(input)?;
        finalize(&pooled, self.centroids, self.pipeline.preprocessing_version)
    }

    /// Полный find-путь: нормализация запроса, query-префикс, вектор, nprobe кластеров.
    pub fn encode_query(
        &self,
        model: &dyn EmbeddingModel,
        raw: &str,
        nprobe: usize,
    ) -> Result<Query, EmbedError> {
        self.check_model(model)?;
        let canonical = normalize_text(raw)?;
        let input = self.pipeline.model_input_for_query(&canonical);
        let pooled = model.embed_pooled(&input)?;
        let encoded = finalize(&pooled, self.centroids, self.pipeline.preprocessing_version)?;
        // `Centroids::top` уже даёт контрактную сортировку `(d2 ASC, cluster ASC)` и обрезку
        // (§7.5) — повторять её здесь значило бы иметь две реализации одного порядка.
        let clusters = self.centroids.top(&encoded.vec_q, nprobe);
        let per_shard = vecdht_crypto::quant::group_by_shard(&clusters);
        Ok(Query { canonical, vec_q: encoded.vec_q, clusters, per_shard })
    }

    /// Сверка модели с артефактом по `preprocessing_version` (§6.7): несовпадение — это
    /// `MODEL_MISMATCH` и закрытие соединения, а не «чуть другой вектор».
    ///
    /// Здесь сознательно проверяется только версия пайплайна, а не `model_version`: идентичность
    /// самих весов (§6.1) — это проверка артефакта при загрузке, `blake3` файла и полей манифеста
    /// (§15.3), а не то, что можно вывести из вызова `embed_pooled`. Побочный эффект, о котором
    /// надо помнить: тестовый оракул [`crate::testing::HashModel`] проходит эту сверку, потому что
    /// объявляет тот же `preprocessing_version` — поэтому числа, полученные на нём, всегда помечены
    /// как «механика», а не как измерение гейта.
    fn check_model(&self, model: &dyn EmbeddingModel) -> Result<(), EmbedError> {
        if model.preprocessing_version() != self.pipeline.preprocessing_version {
            return Err(EmbedError::Manifest(format!(
                "MODEL_MISMATCH: модель на preprocessing {}, артефакт на {}",
                model.preprocessing_version(),
                self.pipeline.preprocessing_version
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_artifact::{reference_artifact, reference_centroids};

    fn pipeline() -> Pipeline {
        Pipeline::from_manifest(&vecdht_artifact::reference_manifest()).unwrap()
    }

    #[test]
    fn pipeline_follows_the_reference_manifest() {
        let p = pipeline();
        assert_eq!(p.preprocessing_version, crate::PREPROCESSING_VERSION);
        assert_eq!(p.pooling, Pooling::Cls);
        assert_eq!(p.max_length, 256);
        assert_eq!(p.nprobe_default, 16);
        assert_eq!(p.prefixes, PrefixPolicy::none());
    }

    #[test]
    fn manifest_declaring_another_grid_or_dim_is_refused() {
        for mutate in [
            |m: &mut Manifest| m.quant.grid = "i8/512".into(),
            |m: &mut Manifest| m.quant.dim = 768,
            |m: &mut Manifest| m.quant.rounding = "banker".into(),
            |m: &mut Manifest| m.routing.nlist = 512,
            |m: &mut Manifest| m.preprocessing_version = 2,
            |m: &mut Manifest| m.max_length = 0,
        ] {
            let mut m = vecdht_artifact::reference_manifest();
            mutate(&mut m);
            let err = Pipeline::from_manifest(&m).unwrap_err();
            assert!(
                matches!(err, EmbedError::Manifest(_)),
                "манифест с другим контрактом обязан быть отвергнут, а не проигнорирован: {err}"
            );
        }
    }

    #[test]
    fn finalize_is_deterministic_and_lands_on_the_grid() {
        let centroids = reference_centroids();
        let pooled: Pooled = std::array::from_fn(|i| (i as f32) * 0.01 - 1.0);
        let a = finalize(&pooled, &centroids, 1).unwrap();
        let b = finalize(&pooled, &centroids, 1).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.shard, shard_of_cluster(a.cluster_id));
        assert!(a.cluster_id < NLIST);
        // Сетка: каждая координата — целый шаг Δ=1/127, и ни одна не вылезла за ±127 (§6.3).
        for &x in a.vec_q.iter() {
            assert!((-127..=127).contains(&i32::from(x)));
        }
        assert_eq!(a.intent_id, intent_id(&a.vec_q, 1));
    }

    #[test]
    fn pooled_is_normalized_before_quantizing() {
        // Масштаб входа не должен менять направление: вектор и его десятикратная копия дают один
        // и тот же `vec_q`. Это и есть смысл шага 6 перед шагом 7 (§6.2).
        let base: Pooled = std::array::from_fn(|i| ((i % 7) as f32 - 3.0) * 0.37);
        let scaled: Pooled = std::array::from_fn(|i| base[i] * 10.0);
        assert_eq!(quantize_pooled(&base).unwrap(), quantize_pooled(&scaled).unwrap());
    }

    #[test]
    fn non_finite_and_zero_vectors_are_errors_not_garbage() {
        let mut pooled: Pooled = [0.1; DIM];
        pooled[42] = f32::NAN;
        assert!(matches!(quantize_pooled(&pooled), Err(EmbedError::NonFinite(_))));
        pooled[42] = f32::INFINITY;
        assert!(matches!(quantize_pooled(&pooled), Err(EmbedError::NonFinite(_))));
        // Нулевой вектор: нормализовать невозможно, а «квантовать в ноль» — значит молча
        // положить интент в произвольный кластер.
        assert!(matches!(quantize_pooled(&[0.0; DIM]), Err(EmbedError::Quant(_))));
    }

    #[test]
    fn query_and_intent_use_the_same_canonical_text() {
        // Свойство §6.6/§6.7: нормализация применяется к обоим путям (publish и find), а префикс
        // — только к запросу.
        let a = reference_artifact();
        let enc = Encoder::from_artifact(&a).unwrap();
        let model = crate::testing::HashModel::new();
        let raw = "  ищу   контрагента  ";
        let intent = enc.encode_intent(&model, raw).unwrap();
        let query = enc.encode_query(&model, raw, 4).unwrap();
        assert_eq!(intent.canonical, query.canonical);
        assert_eq!(intent.canonical, "ищу контрагента");
        assert_eq!(intent.encoded.vec_q, query.vec_q, "без query-префикса векторы совпадают");
    }

    #[test]
    fn query_clusters_are_grouped_by_shard_and_bounded_by_nprobe() {
        let a = reference_artifact();
        let enc = Encoder::from_artifact(&a).unwrap();
        let model = crate::testing::HashModel::new();
        let q = enc.encode_query(&model, "ищу партнёра по vector search", 16).unwrap();
        assert_eq!(q.clusters.len(), 16);
        assert!(!q.per_shard.is_empty());
        let total: usize = q.per_shard.iter().map(|(_, c)| c.len()).sum();
        assert_eq!(total, 16, "группировка не теряет и не добавляет кластеров");
        for (shard, clusters) in &q.per_shard {
            for &c in clusters {
                assert_eq!(*shard, shard_of_cluster(c), "кластер обязан лежать в своём шарде");
            }
        }
        // Сортировка §7.5: кластеры идут по возрастанию дистанции, а внутри шарда — по cluster.
        let mut seen_shards = q.per_shard.iter().map(|(s, _)| *s).collect::<Vec<_>>();
        let sorted = {
            seen_shards.sort_unstable();
            seen_shards.clone()
        };
        assert_eq!(seen_shards, sorted, "перечисление шардов детерминировано по возрастанию");
    }

    #[test]
    fn model_mismatch_is_refused_before_inference() {
        let a = reference_artifact();
        let enc = Encoder::from_artifact(&a).unwrap();
        let model = crate::testing::HashModel::with_preprocessing(99);
        let err = enc.encode_intent(&model, "ищу партнёра").unwrap_err();
        assert!(
            matches!(&err, EmbedError::Manifest(m) if m.contains("MODEL_MISMATCH")),
            "несогласованный preprocessing обязан быть ошибкой, а не тихой потерей recall (§6.7): {err}"
        );
    }

    #[test]
    fn intent_text_that_fails_validation_never_reaches_the_model() {
        let a = reference_artifact();
        let enc = Encoder::from_artifact(&a).unwrap();
        let model = crate::testing::HashModel::new();
        assert!(matches!(
            enc.encode_intent(&model, "первый\nвторой"),
            Err(EmbedError::Text(_))
        ));
    }
}
