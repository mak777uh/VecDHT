//! `encode` — пайплайн §6.2 для одного текста, без сети.
//!
//! Команда существует потому, что расхождение маршрутизации почти всегда выглядит как «мой интент
//! не находится», а причиной является один из шагов: каноническая форма, префикс, квантование или
//! присваивание кластера. Без инструмента оператор видел бы только пустой результат поиска; с ним
//! видно `cluster_id`, шард и fan-out, то есть ровно те байты, по которым узлы расходятся (§7.3).
//!
//! Модель выбирается явно, и это не косметика:
//!
//! * `--model-dir` требует собранного feature `candle` — тогда считается настоящий ModernBERT;
//! * без весов остаётся детерминированный суррогат (`HashModel` из тестового оракула), и он
//!   подключается только по `--allow-surrogate`, а вывод помечается строкой «вектор НЕ
//!   семантический». Молча подставить суррогат вместо модели означало бы выдать оператору
//!   правдоподобный кластер, посчитанный по хешу байтов.

use std::path::Path;

use vecdht_artifact::Artifact;
use vecdht_crypto::ids::intent_text_hash;
use vecdht_embed::testing::HashModel;
use vecdht_embed::{normalize_text, Encoder};
use vecdht_wire::{NLIST, SHARDS};

use crate::args::Parsed;
use crate::model::{build_model, push_vector, warn_surrogate, Source};
use crate::{CliError, fail, vector_hex};

pub const CMD: &str = "encode";
pub const FLAGS: &[&str] = &[
    "artifact", "text", "kind", "nprobe", "model-dir", "allow-surrogate", "show-vector",
];

pub const HELP: &str = "\
encode — шаги 1-8 пайплайна §6.2 для одного текста

  --artifact DIR        артефакт сети (обязателен: центроиды и манифест)
  --text STR            интент или запрос (обязателен)
  --kind intent|query   путь кодирования; по умолчанию intent
  --nprobe N            для query: сколько кластеров зондировать (§7.5)
  --model-dir DIR       каталог с config.json, tokenizer.json, model.safetensors
                        (нужен собранный feature `candle`)
  --allow-surrogate     разрешить детерминированный суррогат вместо модели
  --show-vector         напечатать все 768 hex-символов vec_q";

pub fn exec(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let dir = p.required(CMD, "artifact")?;
    let text = p.required(CMD, "text")?;
    let kind = p.value(CMD, "kind")?.unwrap_or_else(|| "intent".to_string());
    if kind != "intent" && kind != "query" {
        return Err(CliError::Fail(format!(
            "--kind {kind}: бывает только intent или query, потому что пути §6.6 и §6.2 различаются \
             префиксом и тем, кто подписывает текст"
        )));
    }

    let a = Artifact::load(Path::new(&dir)).map_err(|e| fail("чтение артефакта", e))?;
    let enc = Encoder::from_artifact(&a).map_err(|e| fail("построение Encoder из артефакта", e))?;

    let source = build_model(p, CMD, enc.pipeline(), &a.manifest.model_version)?;
    // Суррогат живёт до конца функции, а не создаётся в ветке match: `&HashModel::new()` внутри
    // match был бы ссылкой на временный объект.
    let surrogate = HashModel::new();
    let model: &dyn vecdht_embed::EmbeddingModel = match &source {
        Source::Model(m) => m.as_ref(),
        Source::Surrogate => &surrogate,
    };

    out.push_str(&format!("артефакт {}\n", a.manifest.model_version));
    out.push_str(&format!("источник вектора: {}\n", source.label()));
    warn_surrogate(&source, out);

    // Шаг 1 печатается отдельно и до всего остального: если канонизация отвергла текст, оператор
    // должен увидеть причину именно так (§6.6), а не как «вектор получился странным».
    let canonical = normalize_text(&text).map_err(|e| fail("канонизация текста", e))?;
    out.push_str(&format!("канонический текст {:?}\n", canonical));
    out.push_str(&format!(
        "intent_text_hash  {}\n",
        hex::encode(intent_text_hash(canonical.as_bytes()))
    ));

    match kind.as_str() {
        "intent" => {
            let intent = enc.encode_intent(model, &text).map_err(|e| fail("encode_intent", e))?;
            assert_eq!(intent.canonical, canonical, "каноническая форма посчитана дважды по-разному");
            let e = intent.encoded;
            out.push_str(&format!("  preprocessing_version {}\n", e.preprocessing_version));
            out.push_str(&format!("  cluster_id           {} (шард {})\n", e.cluster_id, e.shard));
            out.push_str(&format!("  intent_id            {}\n", hex::encode(e.intent_id)));
            push_vector(&vector_hex(&e.vec_q), p.bool_flag(CMD, "show-vector")?, out);
        }
        _ => {
            let nprobe = p.num_or::<usize>(CMD, "nprobe", usize::from(a.manifest.routing.nprobe_default))?;
            if nprobe == 0 || nprobe > NLIST as usize {
                return Err(CliError::Fail(format!(
                    "--nprobe {nprobe}: вне 1..{NLIST}; пустой список кластеров означал бы «искать \
                     нигде», а больший nlist — это полный скан под видом оптимизации (§8.6)"
                )));
            }
            let q = enc.encode_query(model, &text, nprobe).map_err(|e| fail("encode_query", e))?;
            push_vector(&vector_hex(&q.vec_q), p.bool_flag(CMD, "show-vector")?, out);
            out.push_str(&format!("  кластеры ({}) {:?}\n", q.clusters.len(), q.clusters));
            out.push_str(&format!(
                "  fan-out {} шард(ов) из {SHARDS}: {:?}\n",
                q.per_shard.len(),
                q.per_shard.iter().map(|(s, c)| (*s, c.len())).collect::<Vec<_>>()
            ));
            // Проверка, которая стоит того, чтобы печатать её в выводе: кластеры query-пути
            // обязаны покрываться тем же разбиением, что и интенты (§7.1).
            let clusters: usize = q.per_shard.iter().map(|(_, c)| c.len()).sum();
            assert_eq!(clusters, q.clusters.len(), "группировка по шардам потеряла кластеры");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_label_names_the_real_model_or_the_surrogate() {
        // Пометка об источнике — часть результата, а не декор: по ней оператор понимает, можно ли
        // верить найденному порядку.
        assert_eq!(Source::Surrogate.label(), "суррогат HashModel");
    }

    #[test]
    fn the_vector_line_is_truncated_unless_asked() {
        let mut out = String::new();
        push_vector(&"ab".repeat(384), false, &mut out);
        assert!(out.contains("768 hex-символов"), "{out}");
        assert!(out.contains("…"), "{out}");
        let mut full = String::new();
        push_vector(&"ab".repeat(384), true, &mut full);
        assert!(full.contains(&"ab".repeat(384)), "полный вектор обязан печататься целиком");
    }

    #[test]
    fn kind_rejects_anything_but_the_two_paths() {
        for bad in ["Intent", "intent ", "both", ""] {
            let p = Parsed::parse(&[CMD, "--artifact", "x", "--text", "y", "--kind", bad]).unwrap();
            assert!(exec(&p, &mut String::new()).is_err(), "`{bad}` обязан быть отвергнут");
        }
    }
}
