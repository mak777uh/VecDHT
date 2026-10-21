//! Общий выбор модели для `encode` и `agent`: сетевой путь обязан считать вектор тем же
//! способом, что и офлайн-диагностика, иначе `encode` показывал бы один кластер, а publish уходил
//! бы в другой.
//!
//! Модель выбирается явно по тем же правилам, что и в [`crate::encode_cmd`]: `--model-dir` требует
//! собранного feature `candle`, а детерминированный суррогат — только по `--allow-surrogate` и с
//! пометкой в выводе. Молча подставить суррогат в сетевую команду было бы хуже, чем в `encode`:
//! оператор увидел бы «опубликовано», не увидев, что публиковал хеш, а не смысл.

#[cfg(feature = "candle")]
use std::path::Path;

use vecdht_embed::model::Pipeline;
use vecdht_embed::EmbeddingModel;

use crate::args::Parsed;
use crate::CliError;
#[cfg(feature = "candle")]
use crate::fail;

/// Одна из двух реализаций `EmbeddingModel`. Перечисление, а не `Box<dyn …>`, потому что источник
/// вектора обязан быть виден в выводе: числа суррогата и модели несопоставимы.
pub enum Source {
    #[cfg_attr(not(feature = "candle"), allow(dead_code))]
    Model(Box<dyn EmbeddingModel + 'static>),
    Surrogate,
}

impl Source {
    pub fn label(&self) -> &'static str {
        match self {
            Source::Model(_) => "candle/ModernBERT",
            Source::Surrogate => "суррогат HashModel",
        }
    }

    pub fn is_surrogate(&self) -> bool {
        matches!(self, Source::Surrogate)
    }
}

/// Кто считает шаг 4. `cmd` нужен, чтобы сообщение об отсутствии источника называло именно ту
/// команду, которую вызвал оператор.
///
/// `pipeline` и `model_version` передаются отдельно, а не берутся из артефакта: команда
/// `artifact publish` строит артефакт, и артефакта у неё ещё нет — а пайплайн и имя модели нужны
/// уже для первого вектора. `model_version` — это то, что уедет в `manifest.model_version` и что
/// сверяется на handshake (§6.7), поэтому для суррогата оно равно имени самой суррогатной модели,
/// а не выдуманному «granite-…».
pub fn build_model(
    p: &Parsed,
    cmd: &str,
    pipeline: &Pipeline,
    model_version: &str,
) -> Result<Source, CliError> {
    match origin(p, cmd)? {
        Origin::ModelDir(dir) => Ok(Source::Model(load_model(&dir, pipeline, model_version)?)),
        Origin::Surrogate => Ok(Source::Surrogate),
    }
}

/// Объявленный источник вектора — без самой модели.
///
/// Отдельный тип от [`Source`] потому, что модель нужна не всегда: издатель, который читает
/// готовые эмбеддинги, весов не грузит, но сказать, чьи это векторы, обязан. Имя модели при
/// этом — часть подписанного манифеста (§6.7), то есть не «подпись к картинке», а проверяемое
/// утверждение.
#[derive(Debug, Clone)]
pub enum Origin {
    /// Каталог весов (`--model-dir`).
    ModelDir(String),
    /// Детерминированный суррогат из тестового оракула (`--allow-surrogate`).
    Surrogate,
}

/// Откуда берётся вектор. Без явного объявления команда не угадывает: молчаливый суррогат дал бы
/// «правдоподобные» векторы, а оператор решил бы, что считал настоящей моделью.
pub fn origin(p: &Parsed, cmd: &str) -> Result<Origin, CliError> {
    if let Some(dir) = p.value(cmd, "model-dir")? {
        return Ok(Origin::ModelDir(dir));
    }
    if p.bool_flag(cmd, "allow-surrogate")? {
        return Ok(Origin::Surrogate);
    }
    Err(CliError::Fail(
        "нет источника вектора: нужен --model-dir DIR (feature `candle`) или сознательное \
         --allow-surrogate; суррогат помечает вывод как немаршрутизируемый по смыслу".into(),
    ))
}

/// Загрузить веса каталога. Требует сборки с feature `candle`: без него `--model-dir` — это
/// опечатка, а не «просто не грузить».
pub fn load_model(
    dir: &str,
    pipeline: &Pipeline,
    model_version: &str,
) -> Result<Box<dyn EmbeddingModel + 'static>, CliError> {
    #[cfg(feature = "candle")]
    {
        let m = vecdht_embed::candle_backend::ModernBertEmbedder::from_dir(
            Path::new(dir),
            pipeline,
            model_version,
        )
        .map_err(|e| fail("загрузка модели", e))?;
        Ok(Box::new(m))
    }
    #[cfg(not(feature = "candle"))]
    {
        let _ = (dir, pipeline, model_version);
        Err(CliError::Fail(
            "--model-dir требует сборки с feature `candle`: \
             cargo run -p vecdht-cli --features candle".into(),
        ))
    }
}

/// Пометка о суррогате — часть результата, а не декор: по ней видно, можно ли верить порядку.
pub fn warn_surrogate(source: &Source, out: &mut String) {
    if source.is_surrogate() {
        out.push_str(
            "ВНИМАНИЕ: вектор посчитан детерминированным суррогатом из тестового оракула, он НЕ \
             семантический. Годится для проверки механики маршрутизации и разбора форматов, не годится \
             для суждений о качестве поиска (§18.1: recall на таком стенде не измеряется).\n",
        );
    }
}

pub fn push_vector(hex_vec: &str, show: bool, out: &mut String) {
    if show {
        out.push_str(&format!("  vec_q                {hex_vec}\n"));
    } else {
        out.push_str(&format!(
            "  vec_q                {}… ({} hex-символов, --show-vector)\n",
            &hex_vec[..24],
            hex_vec.len()
        ));
    }
}
