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

use vecdht_artifact::Artifact;
use vecdht_embed::{EmbeddingModel, Encoder};

use crate::args::Parsed;
use crate::CliError;
#[cfg(feature = "candle")]
use crate::fail;

/// Одна из двух реализаций `EmbeddingModel`. Перечисление, а не `Box<dyn …>`, потому что источник
/// вектора обязан быть виден в выводе: числа суррогата и модели несопоставимы.
pub enum Source<'a> {
    #[cfg_attr(not(feature = "candle"), allow(dead_code))]
    Model(Box<dyn EmbeddingModel + 'a>),
    Surrogate,
}

impl Source<'_> {
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
pub fn build_model<'a>(
    p: &Parsed,
    cmd: &str,
    a: &'a Artifact,
    enc: &Encoder<'a>,
) -> Result<Source<'a>, CliError> {
    if let Some(dir) = p.value(cmd, "model-dir")? {
        #[cfg(feature = "candle")]
        {
            let m = vecdht_embed::candle_backend::ModernBertEmbedder::from_dir(
                Path::new(&dir),
                enc.pipeline(),
                &a.manifest.model_version,
            )
            .map_err(|e| fail("загрузка модели", e))?;
            return Ok(Source::Model(Box::new(m)));
        }
        #[cfg(not(feature = "candle"))]
        {
            let _ = (dir, a, enc);
            return Err(CliError::Fail(
                "--model-dir требует сборки с feature `candle`: \
                 cargo run -p vecdht-cli --features candle".into(),
            ));
        }
    }
    if !p.bool_flag(cmd, "allow-surrogate")? {
        return Err(CliError::Fail(
            "нет источника вектора: нужен --model-dir DIR (feature `candle`) или сознательное \
             --allow-surrogate; суррогат помечает вывод как немаршрутизируемый по смыслу".into(),
        ));
    }
    Ok(Source::Surrogate)
}

/// Пометка о суррогате — часть результата, а не декор: по ней видно, можно ли верить порядку.
pub fn warn_surrogate(source: &Source<'_>, out: &mut String) {
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
