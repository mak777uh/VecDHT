//! `demo` — весь офлайн-путь в одном процессе: артефакт → encode → 64 шарда → поиск.
//!
//! Это не «демо-узел» и не замена тестам: однострочная команда, которая показывает оператору, что
//! маршрутизация работает *как механика*, и где именно она деградирует. Всё состояние живёт в
//! памяти, сеть не поднимается, модель по умолчанию — детерминированный суррогат.
//!
//! Что демо доказывает и чего не доказывает (§18.1):
//!
//! * доказывает: канонизация → квантование → assign → разбиение кластеров по шардам → поиск по
//!   int8-арене дают согласованный результат, а фан-запроса ровно `per_shard`;
//! * не доказывает: качество поиска. На суррогатных векторах «recall» — это проверка механики, а
//!   не семантики, поэтому число печатается с явной пометкой, а не как результат гейта.

use std::path::Path;

use vecdht_artifact::Artifact;
use vecdht_crypto::quant::l2_sq;
use vecdht_embed::{EmbeddingModel, Encoder};
use vecdht_embed::testing::HashModel;
use vecdht_index::{IndexEntry, IvfIndex};
use vecdht_wire::SHARDS;

use crate::args::Parsed;
use crate::{CliError, fail, vector_hex};

pub const CMD: &str = "demo";
pub const FLAGS: &[&str] = &["artifact", "intents", "queries", "nprobe", "top-k", "show-queries"];

pub const HELP: &str = "\
demo — артефакт → encode → 64 шарда в памяти → ANN против полного скана

  --artifact DIR   свой артефакт; без него берётся reference-артефакт crate (§15.1)
  --intents N      сколько интентов опубликовать, 1..512; по умолчанию 64
  --queries N      сколько запросов прогнать, 1..64; по умолчанию 8
  --nprobe N       кластеров на запрос; по умолчанию nprobe_default из манифеста
  --top-k N        глубина выдачи; по умолчанию 10
  --show-queries   напечатать тексты запросов и их кластеры";

/// Верхние границы: демо обязано отработать за секунды даже в debug, а «подождите 20 минут» в
/// однострочной команде — это не демо, а прогон harness'а (§18.1), у которого для этого есть
/// отдельный тест и отдельный флаг.
const MAX_INTENTS: usize = 512;
const MAX_QUERIES: usize = 64;

pub fn exec(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = match p.value(CMD, "artifact")? {
        Some(dir) => Artifact::load(Path::new(&dir)).map_err(|e| fail("чтение артефакта", e))?,
        None => vecdht_artifact::reference_artifact(),
    };
    a.manifest.check().map_err(|e| fail("манифест артефакта", e))?;
    out.push_str(&format!(
        "артефакт {} ({}): artifact_hash {}\n",
        a.manifest.model_version,
        if p.value(CMD, "artifact")?.is_some() { "из --artifact" } else { "reference" },
        hex::encode(a.artifact_hash())
    ));

    let intents = p.num_or::<usize>(CMD, "intents", 64)?;
    let queries = p.num_or::<usize>(CMD, "queries", 8)?;
    if !(1..=MAX_INTENTS).contains(&intents) || !(1..=MAX_QUERIES).contains(&queries) {
        return Err(CliError::Fail(format!(
            "--intents {intents} / --queries {queries}: пределы 1..{MAX_INTENTS} и 1..{MAX_QUERIES} — \
             демо печатает механику, а не гоняет корпус; корпусом занимается p0_harness (§18.1)"
        )));
    }
    let nprobe = p.num_or::<usize>(CMD, "nprobe", usize::from(a.manifest.routing.nprobe_default))?;
    let top_k = p.num_or::<usize>(CMD, "top-k", 10)?;
    if nprobe == 0 || top_k == 0 {
        return Err(CliError::Fail("--nprobe и --top-k обязаны быть положительными (§7.5)".into()));
    }

    let enc = Encoder::from_artifact(&a).map_err(|e| fail("построение Encoder из артефакта", e))?;
    let model = HashModel::new();
    out.push_str(&format!(
        "источник вектора: суррогат HashModel ({}, pooling {:?}); записей {intents}, запросов \
         {queries}, nprobe {nprobe}, top-k {top_k}\n",
        model.model_version(),
        model.pooling()
    ));
    out.push_str(
        "ВНИМАНИЕ: векторы НЕ семантические. Числа ниже проверяют механику маршрутизации и поиска, \
         они не являются recall по §18.1 и в спеку как результат не переносятся.\n",
    );

    // Шаг 1: опубликовать интенты по шардам. Арены — те же `IvfIndex`, что и на узле, только без
    // WAL и диска: демо не должно создавать файлов в рабочем каталоге оператора.
    let mut shards: Vec<IvfIndex> = (0..SHARDS).map(IvfIndex::new).collect();
    let mut owners: Vec<[u8; 32]> = Vec::with_capacity(intents);
    for i in 0..intents {
        let text = format!("найти устройство, которое хранит заметку номер {i}");
        let intent = enc
            .encode_intent(&model, &text)
            .map_err(|e| fail(format!("encode_intent №{i}"), e))?;
        let owner = demo_owner(i as u64);
        let e = IndexEntry {
            owner_ed25519: owner,
            vec_q: intent.encoded.vec_q,
            cluster_id: intent.encoded.cluster_id,
            published_bucket: 1,
            ttl_buckets: 5400,
        };
        shards[usize::from(intent.encoded.shard)]
            .insert(e)
            .map_err(|err| fail(format!("вставка в шард {}", intent.encoded.shard), err))?;
        owners.push(owner);
    }
    // Количество разных владельцев — отдельная строка, потому что именно она показывает, что
    // дедупликация по owner (§8.3) не схлопнула записи: N записей при M < N владельцах означало бы,
    // что демо публикует один и тот же ключ несколько раз.
    let unique_owners = {
        let mut sorted = owners.clone();
        sorted.sort_unstable();
        sorted.dedup();
        sorted.len()
    };
    let filled: Vec<usize> = (0..SHARDS as usize).filter(|s| shards[*s].live > 0).collect();
    out.push_str(&format!(
        "опубликовано {} записей, владельцев {}, непустых шардов {} из {SHARDS}, суммарно слотов \
         {}\n",
        intents,
        unique_owners,
        filled.len(),
        filled.iter().map(|s| shards[*s].live).sum::<usize>()
    ));
    if unique_owners != intents {
        return Err(CliError::Fail(format!(
            "внутренняя ошибка демо: {intents} записей дали только {unique_owners} различных \
             владельцев — демо перестало быть демонстрацией дедупликации §8.3"
        )));
    }

    // Шаг 2: запросы. Оракул — полный скан всех шардов; сравниваем владельцев, потому что slot
    // глобально не уникален (§8.4 фиксирует порядок внутри шарда).
    let show = p.bool_flag(CMD, "show-queries")?;
    let mut sum_recall = 0f64;
    let mut sum_fanout = 0usize;
    let mut exact = 0usize;
    for i in 0..queries {
        let text = format!("найти устройство, которое хранит заметку номер {}", (i * 7) % intents);
        let q = enc
            .encode_query(&model, &text, nprobe)
            .map_err(|e| fail(format!("encode_query №{i}"), e))?;
        let mut ann: Vec<(u32, [u8; 32])> = Vec::new();
        for (shard, clusters) in &q.per_shard {
            for (d2, slot) in shards[usize::from(*shard)].search(&q.vec_q, clusters, top_k, 0) {
                let e = shards[usize::from(*shard)]
                    .entry(slot)
                    .ok_or_else(|| CliError::Fail(format!("slot {slot} пуст в шарде {shard}")))?;
                ann.push((d2, e.owner_ed25519));
            }
        }
        let mut full: Vec<(u32, [u8; 32])> = Vec::new();
        for s in shards.iter() {
            for (_slot, e) in s.live_slots() {
                full.push((l2_sq(&q.vec_q, &e.vec_q), e.owner_ed25519));
            }
        }
        let order = |v: &mut Vec<(u32, [u8; 32])>| {
            v.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)))
        };
        order(&mut full);
        order(&mut ann);
        full.truncate(top_k);
        ann.truncate(top_k);
        let hits = ann.iter().filter(|h| full.contains(h)).count();
        let recall = hits as f64 / full.len().max(1) as f64;
        sum_recall += recall;
        sum_fanout += q.per_shard.len();
        if ann == full {
            exact += 1;
        }
        if show {
            out.push_str(&format!(
                "  запрос {i}: {text:?}\n    vec_q {}…\n    кластеры {:?} по шардам {:?}\n    \
                 оракул (полный скан) {}, ANN {}, совпало {hits} из {}, тот же результат: {}\n",
                &vector_hex(&q.vec_q)[..32],
                q.clusters,
                q.per_shard.iter().map(|(s, c)| (*s, c.len())).collect::<Vec<_>>(),
                full.len(),
                ann.len(),
                full.len(),
                ann == full
            ));
        }
        out.push_str(&format!(
            "запрос {i}: fan-out {} шард(ов), выдача {}, recall@{top_k} {recall:.4}\n",
            q.per_shard.len(),
            ann.len(),
        ));
    }
    out.push_str(&format!(
        "\nитоги: средний fan-out {:.2} из {SHARDS}, средний recall@{top_k} {:.4}, полностью \
         совпало с полным сканом {exact} из {queries}\n",
        sum_fanout as f64 / queries as f64,
        sum_recall / queries as f64
    ));
    out.push_str(
        "Что это значит: расхождение с полным сканом — потеря recall из-за nprobe (§18.1, часть ii), \
         а не ошибка кода; совпадение во всех запросах при nprobe = nlist обязано быть по построению, \
         и это удобная проверка «а не сломалась ли маршрутизация вовсе».\n",
    );
    out.push_str(
        "Чего здесь нет: сети, репликации, PoW, TimeMark-экспирации и настоящей модели. Ни один из \
         этих слоёв демо не заменяет.\n",
    );
    Ok(())
}

/// Ключ «автора» демо: детерминированный и уникальный по номеру, иначе дедупликация по owner
/// (§8.3) слила бы записи в одну и демо показывало бы пустой индекс.
fn demo_owner(i: u64) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(b"vecdht/v8/cli/demo/owner")
        .update(&i.to_le_bytes())
        .finalize()
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Parsed {
        let mut argv: Vec<&str> = vec!["demo"];
        argv.extend_from_slice(args);
        Parsed::parse(&argv).unwrap()
    }

    #[test]
    fn the_default_run_finishes_and_reports_an_honest_surrogate_warning() {
        let mut out = String::new();
        exec(&parse(&["--intents", "12", "--queries", "3"]), &mut out).unwrap();
        assert!(out.contains("ВНИМАНИЕ"), "{out}");
        assert!(out.contains("не являются recall"), "{out}");
        assert!(out.contains("непустых шардов"), "{out}");
        assert!(out.contains("средний recall@10"), "{out}");
    }

    #[test]
    fn a_full_probe_reproduces_the_brute_force_exactly() {
        // nprobe = nlist означает «просмотреть все кластеры»: тогда ANN обязан совпасть с оракулом
        // во всех запросах (§18.1, часть ii). Это единственный случай, где демо имеет право
        // что-то утверждать, а не что-то измерять.
        let mut out = String::new();
        exec(&parse(&["--intents", "16", "--queries", "4", "--nprobe", "1024"]), &mut out).unwrap();
        assert!(out.contains("совпало с полным сканом 4 из 4"), "{out}");
    }

    #[test]
    fn bounds_reject_a_corpus_disguised_as_a_demo() {
        for (intents, queries) in [("0", "4"), ("513", "4"), ("8", "0"), ("8", "65")] {
            let err = exec(
                &parse(&["--intents", intents, "--queries", queries]),
                &mut String::new(),
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("пределы"), "{intents}/{queries}: {err}");
        }
    }

    #[test]
    fn demo_owner_is_unique_and_stable() {
        assert_eq!(demo_owner(1), demo_owner(1));
        assert_ne!(demo_owner(1), demo_owner(2));
        for i in 0..64u64 {
            assert_ne!(demo_owner(i), [0u8; 32], "нулевой ключ означал бы «анонимный автор»");
        }
    }
}
