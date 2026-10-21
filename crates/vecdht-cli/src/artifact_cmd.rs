//! `artifact init|show|verify|publish|remap` — артефакт сети (§15).
//!
//! Здесь нужна особая аккуратность с тем, что именно обещает вывод. `init` собирает **dev**-артефакт:
//! центроиды детерминированы из seed (это не результат k-means на реальных интентах, и §7.1 требует
//! именно k-means), поля `model_blake3`/`tokenizer_blake3` унаследованы от reference-манифеста, а
//! ключи авторитета выведены из того же seed. Такой артефакт годится для локальной сети, тестов и
//! разбора «почему мой интент уехал в другой шард», и ровно об этом он и пишет в предупреждении.
//! Публичной сети нужен артефакт, подписанный 3-of-5 ключами bootstrap-авторитета (§15.2), — CLI
//! его не заменяет и не делает вид.
//!
//! `publish` — противоположный полюс: настоящий артефакт, центроиды которого обучены k-means на
//! корпусе, а порядок строк `centroid.bin` задан ровной связной картой шардов (§7.4.1, `ADR-0004`).
//! Это единственная команда, которая меняет геометрию сети, и поэтому она меняет и `artifact_hash`:
//! перенумерованные кластеры — это другая сеть, а не «тот же артефакт, но пересортированный».
//!
//! `remap` — половина той же операции, применённая к уже опубликованным записям: `cluster_id`
//! пересчитывается по опубликованным строкам (§7.2), и записи раскладываются по шардам, потому
//! что индекс шарда не примет запись чужого шарда (§7.4, §8.2).
//!
//! `verify` вызывает `Artifact::verify` с тем же `pinned_hash`, что и узел на handshake (§15.3):
//! сверка хеша обязана предшествовать инициализации индексных структур, иначе «артефакт с чужими
//! центроидами» успевает построить IVF раньше, чем будет отвергнут.

use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use vecdht_artifact::manifest::DOMAIN_ARTIFACT;
use vecdht_artifact::{Artifact, Centroids, reference_manifest, CENTROID_FILE, MANIFEST_FILE};
use vecdht_crypto::ids::content_hash;
use vecdht_crypto::quant::l2_normalize;
use vecdht_crypto::sig::Identity;
use vecdht_embed::model::Pipeline;
use vecdht_embed::publish::{self, PublishConfig};
use vecdht_embed::testing::{HashModel, HASH_MODEL_VERSION};
use vecdht_embed::{emb_digest, normalize_text, EmbeddingModel, PREPROCESSING_VERSION};
use vecdht_index::{IndexEntry, INDEX_ENTRY_BYTES};
use vecdht_wire::{CLUSTERS_PER_SHARD, DIM, NLIST, SHARDS};

use crate::args::Parsed;
use crate::{CliError, fail};

pub const CMD_INIT: &str = "artifact init";
pub const CMD_SHOW: &str = "artifact show";
pub const CMD_VERIFY: &str = "artifact verify";
pub const CMD_PUBLISH: &str = "artifact publish";
pub const CMD_REMAP: &str = "artifact remap";

pub const FLAGS_INIT: &[&str] = &[
    "out", "seed", "label", "dev-keys", "authority", "threshold", "pow-bits", "mhz", "force",
    "show-seed",
];
pub const FLAGS_SHOW: &[&str] = &["artifact"];
pub const FLAGS_VERIFY: &[&str] = &["artifact", "pinned"];
pub const FLAGS_PUBLISH: &[&str] = &[
    "out", "corpus", "embeddings", "model-dir", "allow-surrogate", "label", "seed", "dev-keys",
    "authority", "threshold", "assignments", "threads", "show-seed", "force",
];
pub const FLAGS_REMAP: &[&str] = &["artifact", "entries", "out"];

pub const HELP_INIT: &str = "\
artifact init — собрать dev-артефакт сети и положить его в каталог (§15.1)

  --out DIR            каталог назначения (обязателен)
  --seed HEX64         32 байта seed; по умолчанию blake3(домен || label), то есть
                       повторный вызов с тем же label даёт побайтово тот же артефакт
  --label STR          model_version артефакта, только [a-z0-9._/-]
  --dev-keys N         сколько ключей авторитета вывести из seed (по умолчанию 1)
  --authority HEX64    публичный ключ авторитета без приватной части, повторять можно
  --threshold N        порог подписей; по умолчанию = dev-keys, чтобы verify проходил
  --pow-bits N         сложность publish-PoW в манифесте (диапазон §11.2)
  --mhz N              измеренная скорость blake3 на ядро, МХеш/с (§11.2 калибровка)
  --force              перезаписать непустой каталог
  --show-seed          напечатать seed (приватный материал dev-ключей!)";

pub const HELP_SHOW: &str = "\
artifact show — манифест и хеши без проверки подписи (§15.1)

  --artifact DIR       каталог артефакта";

pub const HELP_VERIFY: &str = "\
artifact verify — полная проверка перед использованием (§15.3)

  --artifact DIR       каталог артефакта
  --pinned HEX64       ожидаемый artifact_hash; без него проверяются только связность
                       манифеста с центроидами и порог подписей";

pub const HELP_PUBLISH: &str = "\
artifact publish — настоящий артефакт: центроиды, обученные на корпусе, и связная карта шардов

  Это единственная команда, которая меняет геометрию сети: строки centroid.bin публикуются
  блоками по 16 (шард = cluster_id / 16, §7.4.1, ADR-0004), поэтому меняется artifact_hash,
  а это значит — новая сеть и новые кластеры у всех записей (§7.2).

  --out DIR            каталог артефакта (обязателен)
  --corpus FILE        корпус: строки файла, каждая — один интент-текст
  --embeddings FILE    готовые векторы (f32, по DIM на текст): формат VDPEMB01
  --model-dir DIR      каталог весов: пинит model_blake3/tokenizer_blake3 (§15.1)
  --allow-surrogate    сознательно считать суррогатом из тестового оракула
  --label STR          model_version артефакта, только [a-z0-9._/-]
  --seed HEX64         seed приватных dev-ключей авторитета (не seed k-means!)
  --dev-keys N         сколько ключей авторитета вывести из seed (по умолчанию 1)
  --authority HEX64    публичный ключ авторитета без приватной части, повторять можно
  --threshold N        порог подписей; по умолчанию = dev-keys
  --assignments FILE   выписать `<документ> <кластер> <шард>` по каждому документу корпуса
  --threads N          потоков обучения (по умолчанию — число ядер, не больше 8)
  --force              перезаписать непустой каталог
  --show-seed          напечатать seed (приватный материал dev-ключей!)

  Векторы берутся из кеша `<корпус>.p0emb`, если он есть и его дайджест совпадает с корпусом,
  моделью и версией preprocessинга: forward заново не считается. Формат кеша и формула
  дайджеста — те же, что у стенда §18.1, иначе измеренный гейт и издатель считали бы разное.";

pub const HELP_REMAP: &str = "\
artifact remap — переприсвоить cluster_id записям под опубликованные центроиды

  После смены карты шардов номера кластеров другие, и записи, уже лежащие в индексе, обязаны
  получить новые (§7.2). Кластер считается тем же правилом, что и у узла при publish: argmin
  l2_sq по опубликованным строкам.

  --artifact DIR       каталог артефакта, из которого берутся опубликованные строки
  --entries FILE       конкатенация 424-байтовых IndexEntry (§8.2)
  --out DIR            каталог для файлов `shard-NN.bin` (по одному на непустой шард)

  Файлы раскладываются по шардам, потому что индекс шарда не примет запись чужого шарда
  (§7.4, §8.2). После переприсвоения индекс шарда пересобирается заново.";

/// Домены вывода seed'а и ключей: разные домены означают, что из одного seed нельзя получить
/// и центроиды, и подписи, и что чужой «артефакт с тем же label» не унаследует ключи.
const DOMAIN_SEED: &[u8] = b"vecdht/v8/cli/dev-seed";
const DOMAIN_CENTROIDS: &[u8] = b"vecdht/v8/cli/dev-centroids";
const DOMAIN_DEV_KEY: &[u8] = b"vecdht/v8/cli/dev-key";

pub fn exec_init(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let dir = PathBuf::from(p.required(CMD_INIT, "out")?);
    let label = p.value(CMD_INIT, "label")?.unwrap_or_else(|| "local".to_string());
    validate_label(&label)?;
    // Порог подписей проверяется до записи, а не после: отказ обязан оставить каталог таким,
    // каким он был, — артефакт, который `verify` не принимает, но который лежит и выглядит
    // готовым, хуже отсутствующего (§14.5).
    let exists = dir.join(MANIFEST_FILE).exists() || dir.join(CENTROID_FILE).exists();
    let force = p.bool_flag(CMD_INIT, "force")?;
    if exists && !force {
        return Err(CliError::Fail(format!(
            "в `{}` уже есть артефакт; перезапись подписала бы новый документ поверх \
             подписанного старого — нужен --force (§15.1)",
            dir.display()
        )));
    }

    let seed = match p.hex_fixed::<32>(CMD_INIT, "seed")? {
        Some(s) => s,
        // Значение по умолчанию выводится из label детерминированно: два запуска с одинаковым
        // label обязаны давать одинаковый artifact_hash, иначе «per-init» нельзя воспроизвести
        // в тесте и нельзя объяснить расхождение между двумя машинами.
        None => *blake3::Hasher::new().update(DOMAIN_SEED).update(label.as_bytes()).finalize().as_bytes(),
    };

    let mut m = vecdht_artifact::reference_manifest();
    m.model_version = format!("dev/{label}");
    if let Some(bits) = p.num::<u32>(CMD_INIT, "pow-bits")? {
        m.power.pow_bits_default = bits;
    }
    if let Some(mhz) = p.num::<u32>(CMD_INIT, "mhz")? {
        m.power.blake3_mhz_core = mhz;
    }

    let centroids = dev_centroids(&seed);
    m.centroid_blake3 = content_hash(&centroids.as_bytes());

    let dev_keys = p.num_or::<u16>(CMD_INIT, "dev-keys", 1)?;
    if dev_keys == 0 || dev_keys > 16 {
        return Err(CliError::Fail(format!(
            "--dev-keys {dev_keys}: смысл имеет 1..16 (больше, чем MAX_ARTIFACT_SIGS)"
        )));
    }
    let ids: Vec<Identity> = (0..dev_keys).map(|i| Identity::from_seed(dev_key_seed(&seed, i))).collect();
    let mut keys: Vec<[u8; 32]> = ids.iter().map(|i| i.pubkey()).collect();
    keys.extend(extra_authorities(p, CMD_INIT)?);
    m.authority.keys = keys.clone();
    m.authority.threshold = p.num_or::<u16>(CMD_INIT, "threshold", dev_keys)?;
    if m.authority.threshold == 0 || u32::from(m.authority.threshold) > keys.len() as u32 {
        return Err(CliError::Fail(format!(
            "порог {} при {} ключах недостижим: подпись авторитета не соберётся никогда (§14.5)",
            m.authority.threshold,
            keys.len()
        )));
    }
    m.signatures.clear();

    let mut a = Artifact::assemble(m, centroids).map_err(|e| fail("сборка артефакта", e))?;
    // Подпись идёт поверх `signing_material` — манифеста без ключа `signatures` (§15.1): иначе
    // «манифест + другие центроиды» не отличался бы от «другого манифеста с теми же центроидами».
    let material = a.signing_material();
    for id in &ids {
        a.manifest.signatures.push(id.sign_domain(DOMAIN_ARTIFACT, &material));
    }

    a.save(&dir).map_err(|e| fail("запись артефакта", e))?;
    let hash = a.artifact_hash();
    let have = a
        .verify(None)
        .map_err(|e| fail("свежесобранный артефакт не прошёл собственную проверку", e))?;

    out.push_str(&format!("артефакт записан в {}\n", dir.display()));
    out.push_str(&format!("  model_version       {}\n", a.manifest.model_version));
    out.push_str(&format!("  artifact_hash       {}\n", hex::encode(hash)));
    out.push_str(&format!("  centroid.bin        {} байт, blake3 {}\n",
        a.centroids.as_bytes().len(), hex::encode(a.manifest.centroid_blake3)));
    out.push_str(&format!("  авторитет           {} ключ(ей), порог {}, валидных подписей {have}\n",
        a.manifest.authority.keys.len(), a.manifest.authority.threshold));
    for (i, k) in a.manifest.authority.keys.iter().enumerate() {
        out.push_str(&format!("    [{i}] {}\n", hex::encode(k)));
    }
    if p.bool_flag(CMD_INIT, "show-seed")? {
        out.push_str(&format!("  seed (--show-seed)   {}\n", hex::encode(seed)));
    }
    out.push_str(
        "\nПРЕДУПРЕЖДЕНИЕ: это dev-артефакт. Центроиды выведены из seed, а не обучены k-means \
         на реальных интентах (§7.1), model_blake3/tokenizer_blake3 унаследованы от \
         reference-манифеста, а приватные ключи авторитета выводятся из того же seed: публичная \
         сеть на таком артефакте работать не обязана.\n",
    );
    Ok(())
}

pub fn exec_show(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = load(p.required(CMD_SHOW, "artifact")?)?;
    show(&a, out);
    Ok(())
}

pub fn exec_verify(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = load(p.required(CMD_VERIFY, "artifact")?)?;
    let pinned = p.hex_fixed::<32>(CMD_VERIFY, "pinned")?;
    let have = a.verify(pinned).map_err(|e| fail("проверка артефакта", e))?;
    // Порядок здесь — копия порядка узла (§15.3): сначала хеш, потом preprocessing, и только
    // потом всё остальное. `verify` уже делает хеш и подписи; `check_preprocessing` — сверку с
    // этим кодом, из-за которой узел обязан отказать в обслуживании, а не искать хуже (§6.7).
    a.check_preprocessing(PREPROCESSING_VERSION)
        .map_err(|e| fail("несогласованный preprocessing", e))?;
    show(&a, out);
    out.push_str(&format!(
        "проверено: {have} валидных подписей при пороге {}, preprocessing_version {} совпадает \
         с этим кодом\n",
        a.manifest.authority.threshold, PREPROCESSING_VERSION
    ));
    Ok(())
}

// ---------------------------------------------------------------- publish ---

/// Имя модели эталона: `manifest.model_version` по умолчанию, когда веса берутся из каталога.
/// Совпадает с тем, чем помечает себя стенд §18.1, — иначе кеш `<корпус>.p0emb`, посчитанный
/// стендом, не подошёл бы издателю по дайджесту.
const REFERENCE_MODEL_VERSION: &str = "granite-embedding-97m-v2";

/// Формат файла эмбеддингов издателя: магия, число строк, размерность — без дайджеста.
/// Пишет его сам издатель, когда форвард считать нечем, а векторы пришли извне.
const EMB_TAG: &[u8; 8] = b"VDPEMB01";
const EMB_HEADER: usize = 8 + 4 + 4;

/// Формат кеша стенда §18.1: то же самое, но с дайджестом канонических текстов, модели и версии
/// preprocessинга. Именно этот файл лежит рядом с корпусом (`*.p0emb`), и издатель его читает и
/// пишет: две копии формата разошлись бы при первой же правке, и кеш стенда перестал бы
/// подходить к корпусу — молча.
const P0EMB_TAG: &[u8; 8] = b"VDP0EMB1";
const P0EMB_HEADER: usize = 8 + 4 + 4 + 32;

/// Сколько записей переприсваивать за один проход `remap`. Пачка ограничивает память: файл
/// записей может занимать сотни мегабайт, а весь корпус в память — это ровно то, чего на 1M
/// записей делать нельзя (§8.2: 1M записей в бюджете 428 МБ).
const REMAP_BATCH: usize = 4096;

/// Источник векторов, объявленный оператором, и имя модели, которое уедет в манифест.
#[derive(Debug)]
enum VectorSource {
    /// Веса в каталоге: `model_version` — это `--label`, а хеши весов и токенизатора пинятся
    /// из файлов каталога (§15.1).
    Weights { dir: String, model_version: String },
    /// Суррогат из тестового оракула: имя модели фиксировано, подменить его нельзя (§6.7).
    Surrogate { model_version: String },
    /// Только имя: векторы пришли готовыми, и вперёд их не пересчитывают.
    Declared { model_version: String },
}

impl VectorSource {
    fn model_version(&self) -> &str {
        match self {
            VectorSource::Weights { model_version, .. }
            | VectorSource::Surrogate { model_version }
            | VectorSource::Declared { model_version } => model_version,
        }
    }
}

/// `artifact publish` — собрать настоящий артефакт: центроиды, обученные k-means на корпусе,
/// и порядок строк, заданный ровной связной картой шардов (§7.1, §7.4.1, `ADR-0004`).
///
/// Порядок шагов совпадает с оракулом стенда до последнего байта, иначе издатель и стенд
/// измеряли бы разные вещи: квантование документов → k-means → квантование центроидов → карта
/// шардов → присваивание по **опубликованным** строкам (§7.2). Именно последний шаг связывает
/// две части: узел посчитает `cluster_id` по тем строкам, что лежат в артефакте, поэтому
/// издатель обязан считать по тем же строкам.
pub fn exec_publish(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let dir = PathBuf::from(p.required(CMD_PUBLISH, "out")?);
    let force = p.bool_flag(CMD_PUBLISH, "force")?;
    if (dir.join(MANIFEST_FILE).exists() || dir.join(CENTROID_FILE).exists()) && !force {
        return Err(CliError::Fail(format!(
            "в `{}` уже есть артефакт; смена карты шардов меняет `artifact_hash`, то есть это \
             другая сеть, а не «тот же артефакт, пересортированный». Перезапись — только с \
             --force (§15.1)",
            dir.display()
        )));
    }
    let corpus = p.value(CMD_PUBLISH, "corpus")?;
    let embeddings = p.value(CMD_PUBLISH, "embeddings")?;
    if corpus.is_none() && embeddings.is_none() {
        return Err(CliError::Fail(
            "нужен --corpus FILE или --embeddings FILE: центроиды обучаются на корпусе (§7.1), \
             а не выдумываются из seed, как в `artifact init`".into(),
        ));
    }

    let source = vector_source(p)?;
    let mut m = reference_manifest();
    m.model_version = source.model_version().to_string();
    if let VectorSource::Weights { dir, .. } = &source {
        pin_model_files(&mut m, Path::new(dir))?;
    }
    let pipeline = Pipeline::from_manifest(&m).map_err(|e| fail("пайплайн §6.2", e))?;

    let (values, vectors_note) = load_vectors(
        &source,
        &pipeline,
        corpus.as_deref(),
        embeddings.as_deref(),
        out,
    )?;

    let threads = p.num_or::<usize>(CMD_PUBLISH, "threads", default_threads())?;
    let started = std::time::Instant::now();
    let published = publish::publish(&values, &PublishConfig::default(), threads)
        .map_err(|e| fail("издательский прогон", e))?;
    let elapsed = started.elapsed().as_secs_f64();

    let centroids = published.centroids().map_err(|e| fail("centroid.bin", e))?;
    m.centroid_blake3 = content_hash(&centroids.as_bytes());

    // Seed dev-ключей выводится из модели и центроидов: тот же корпус и тот же каталог весов
    // дают тот же артефакт побайтово, а другой корпус — другой seed и другой `artifact_hash`.
    let seed = match p.hex_fixed::<32>(CMD_PUBLISH, "seed")? {
        Some(s) => s,
        None => *blake3::Hasher::new()
            .update(DOMAIN_SEED)
            .update(source.model_version().as_bytes())
            .update(&m.centroid_blake3)
            .finalize()
            .as_bytes(),
    };
    let dev_keys = p.num_or::<u16>(CMD_PUBLISH, "dev-keys", 1)?;
    if dev_keys == 0 || dev_keys > 16 {
        return Err(CliError::Fail(format!(
            "--dev-keys {dev_keys}: смысл имеет 1..16 (больше, чем MAX_ARTIFACT_SIGS)"
        )));
    }
    let ids: Vec<Identity> = (0..dev_keys).map(|i| Identity::from_seed(dev_key_seed(&seed, i))).collect();
    let mut keys: Vec<[u8; 32]> = ids.iter().map(|i| i.pubkey()).collect();
    keys.extend(extra_authorities(p, CMD_PUBLISH)?);
    m.authority.keys = keys.clone();
    m.authority.threshold = p.num_or::<u16>(CMD_PUBLISH, "threshold", dev_keys)?;
    if m.authority.threshold == 0 || u32::from(m.authority.threshold) > keys.len() as u32 {
        return Err(CliError::Fail(format!(
            "порог {} при {} ключах недостижим: подпись авторитета не соберётся никогда (§14.5)",
            m.authority.threshold,
            keys.len()
        )));
    }
    m.signatures.clear();

    let mut a = Artifact::assemble(m, centroids).map_err(|e| fail("сборка артефакта", e))?;
    let material = a.signing_material();
    for id in &ids {
        a.manifest.signatures.push(id.sign_domain(DOMAIN_ARTIFACT, &material));
    }
    a.save(&dir).map_err(|e| fail("запись артефакта", e))?;
    let hash = a.artifact_hash();
    let have = a
        .verify(None)
        .map_err(|e| fail("свежесобранный артефакт не прошёл собственную проверку", e))?;

    out.push_str(&format!("артефакт записан в {}\n", dir.display()));
    out.push_str(&format!("  векторы             {vectors_note}\n"));
    out.push_str(&format!("  model_version       {}\n", a.manifest.model_version));
    out.push_str(&format!("  artifact_hash       {}\n", hex::encode(hash)));
    out.push_str(&format!(
        "  centroid.bin        {} байт, blake3 {}\n",
        a.centroids.as_bytes().len(),
        hex::encode(a.manifest.centroid_blake3)
    ));
    out.push_str(&format!(
        "  корпус              {} документов, k-means {} итераций, карта {} итераций, {:.1} с\n",
        published.stats.docs,
        published.stats.kmeans_iterations,
        published.stats.map_iterations,
        elapsed
    ));
    out.push_str(&format!(
        "  шардов              {}, по {} кластеров на шард, цена назначения {}\n",
        published.shards(),
        published.per_shard,
        published.stats.map_cost
    ));
    out.push_str(&format!(
        "  кластеры            пустых {}, самый большой {}, разброс внутри шарда {:.0} (int8 l2_sq)\n",
        published.stats.empty_clusters,
        published.stats.max_cluster,
        published.stats.dispersion
    ));
    out.push_str(&format!(
        "  авторитет           {} ключ(ей), порог {}, валидных подписей {have}\n",
        a.manifest.authority.keys.len(),
        a.manifest.authority.threshold
    ));
    if p.bool_flag(CMD_PUBLISH, "show-seed")? {
        out.push_str(&format!("  seed (--show-seed)   {}\n", hex::encode(seed)));
    }

    if let Some(path) = p.value(CMD_PUBLISH, "assignments")? {
        let mut text = String::with_capacity(published.cluster_of_doc.len() * 12);
        for (d, &c) in published.cluster_of_doc.iter().enumerate() {
            text.push_str(&format!("{d} {c} {}\n", published.shard_of(c)));
        }
        std::fs::write(&path, text)
            .map_err(|e| fail(format!("запись файла присваиваний `{path}`"), e))?;
        out.push_str(&format!(
            "  присваивания        {} строк в `{path}` (документ, кластер, шард)\n",
            published.cluster_of_doc.len()
        ));
    }

    out.push_str(
        "\nЭто новая сеть: перенумерованные кластеры означают другой `artifact_hash`, и все ранее \
         опубликованные записи обязаны получить новые `cluster_id` (`artifact remap`), а индексы \
         шардов — быть пересобраны. Подписи ниже — dev-ключи, выведенные из seed: публичной сети \
         нужен артефакт, подписанный ключами bootstrap-авторитета (§15.2).\n",
    );
    Ok(())
}

/// `artifact remap` — переприсвоить `cluster_id` записям под опубликованные центроиды.
///
/// Кластер считается тем же правилом, что и у узла при publish (§7.2): argmin `l2_sq` по
/// опубликованным строкам. «Просто переставить номера» нельзя — при равных расстояниях
/// tie-break у argmin это наименьший индекс центроида, а после перенумерации он указывает на
/// другой кластер.
pub fn exec_remap(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = load(p.required(CMD_REMAP, "artifact")?)?;
    let entries_path = p.required(CMD_REMAP, "entries")?;
    let out_dir = PathBuf::from(p.required(CMD_REMAP, "out")?);
    let per_shard = a.manifest.routing.clusters_per_shard as usize;
    let shards = a.manifest.routing.shards as usize;
    if per_shard != CLUSTERS_PER_SHARD as usize || shards != SHARDS as usize {
        return Err(CliError::Fail(format!(
            "артефакт объявляет {per_shard} кластеров на шард и {shards} шардов, а протокол \
             требует ровно {CLUSTERS_PER_SHARD} и {SHARDS} (§7.4)"
        )));
    }
    let rows: Vec<[i8; DIM]> = a.centroids.rows().into_iter().copied().collect();
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| fail(format!("создание каталога `{}`", out_dir.display()), e))?;

    let file = std::fs::File::open(&entries_path)
        .map_err(|e| fail(format!("чтение файла записей `{entries_path}`"), e))?;
    let mut reader = BufReader::new(file);
    let mut writers: Vec<Option<BufWriter<std::fs::File>>> = (0..shards).map(|_| None).collect();
    let mut counts = vec![0usize; shards];
    let mut total = 0usize;
    let mut changed = 0usize;
    let mut batch: Vec<IndexEntry> = Vec::with_capacity(REMAP_BATCH);

    loop {
        let mut raw = vec![0u8; INDEX_ENTRY_BYTES];
        let mut n = reader
            .read(&mut raw)
            .map_err(|e| fail(format!("чтение файла записей `{entries_path}`"), e))?;
        if n == 0 {
            break;
        }
        while n < INDEX_ENTRY_BYTES {
            let more = reader
                .read(&mut raw[n..])
                .map_err(|e| fail(format!("чтение файла записей `{entries_path}`"), e))?;
            if more == 0 {
                return Err(CliError::Fail(format!(
                    "файл `{entries_path}` обрывается на {} байтах: запись №{} неполная, а IndexEntry — \
                     это ровно {INDEX_ENTRY_BYTES} байт (§8.2)",
                    total * INDEX_ENTRY_BYTES + n,
                    total + 1
                )));
            }
            n += more;
        }
        let entry = IndexEntry::from_bytes(&raw)
            .map_err(|e| fail(format!("запись №{} файла `{entries_path}`", total + 1), e))?;
        batch.push(entry);
        total += 1;
        if batch.len() == REMAP_BATCH {
            remap_batch(&mut batch, &rows, &mut writers, &out_dir, per_shard, &mut counts, &mut changed)?;
        }
    }
    remap_batch(&mut batch, &rows, &mut writers, &out_dir, per_shard, &mut counts, &mut changed)?;

    let mut written = 0usize;
    for (shard, w) in writers.iter_mut().enumerate() {
        if let Some(mut w) = w.take() {
            w.flush().map_err(|e| fail(format!("сброс файла шарда {shard}"), e))?;
            written += 1;
        }
    }
    if total == 0 {
        return Err(CliError::Fail(format!(
            "файл `{entries_path}` пуст: переприсваивать нечего, а молчаливый «успех» означал бы, \
             что оператор перепутал файл"
        )));
    }
    let empty: Vec<usize> = (0..shards).filter(|&s| counts[s] == 0).collect();
    out.push_str(&format!(
        "переприсвоено {total} записей, номер кластера изменился у {changed}; записано {written} \
         файлов в `{}`\n",
        out_dir.display()
    ));
    out.push_str(&format!(
        "раскладка по шардам: минимум {}, максимум {}, пустых шардов {}\n",
        counts.iter().copied().min().unwrap_or(0),
        counts.iter().copied().max().unwrap_or(0),
        empty.len()
    ));
    if !empty.is_empty() {
        out.push_str(&format!("  пустые шарды: {empty:?}\n"));
    }
    out.push_str(
        "\nИндексы шардов после переприсвоения пересобираются заново: запись, лежащая в шарде, \
         обязана иметь `cluster_id` своего шарда (§7.4), иначе индекс её не примет.\n",
    );
    Ok(())
}

/// Переприсвоить пачку записей и разложить их по файлам шардов.
fn remap_batch(
    batch: &mut [IndexEntry],
    rows: &[[i8; DIM]],
    writers: &mut [Option<BufWriter<std::fs::File>>],
    out_dir: &Path,
    per_shard: usize,
    counts: &mut [usize],
    changed: &mut usize,
) -> Result<(), CliError> {
    if batch.is_empty() {
        return Ok(());
    }
    let vectors: Vec<[i8; DIM]> = batch.iter().map(|e| e.vec_q).collect();
    let assigned = publish::remap_clusters(&vectors, rows);
    let mut buf: Vec<u8> = Vec::with_capacity(INDEX_ENTRY_BYTES);
    for (entry, &cluster) in batch.iter_mut().zip(assigned.iter()) {
        if entry.cluster_id != cluster {
            *changed += 1;
        }
        entry.cluster_id = cluster;
        let shard = cluster as usize / per_shard;
        counts[shard] += 1;
        if writers[shard].is_none() {
            let path = out_dir.join(format!("shard-{shard:02}.bin"));
            let f = std::fs::File::create(&path)
                .map_err(|e| fail(format!("создание файла `{}`", path.display()), e))?;
            writers[shard] = Some(BufWriter::new(f));
        }
        buf.clear();
        entry.write_into(&mut buf);
        writers[shard]
            .as_mut()
            .expect("писатель шарда только что создан")
            .write_all(&buf)
            .map_err(|e| fail(format!("запись в файл шарда {shard}"), e))?;
    }
    Ok(())
}

/// Откуда взяты векторы и как зовётся модель в манифесте.
///
/// Правило одно и строгое: имя модели в манифесте обязано называть ту модель, которая считала
/// векторы. Суррогат поэтому подписать чужим именем нельзя — сверка на handshake (§6.7) иначе
/// прошла бы, а векторы были бы не от той модели.
fn vector_source(p: &Parsed) -> Result<VectorSource, CliError> {
    let model_dir = p.value(CMD_PUBLISH, "model-dir")?;
    let allow_surrogate = p.bool_flag(CMD_PUBLISH, "allow-surrogate")?;
    let label = p.value(CMD_PUBLISH, "label")?;
    match (model_dir, allow_surrogate) {
        (Some(dir), _) => {
            let model_version = label.unwrap_or_else(|| REFERENCE_MODEL_VERSION.to_string());
            validate_label(&model_version)?;
            Ok(VectorSource::Weights { dir, model_version })
        }
        (None, true) => {
            if let Some(l) = &label {
                if l != HASH_MODEL_VERSION {
                    return Err(CliError::Fail(format!(
                        "--label `{l}` вместе с --allow-surrogate: суррогат называется \
                         `{HASH_MODEL_VERSION}`, и манифест не имеет права объявлять другую \
                         модель (§6.7 — сверка на handshake)"
                    )));
                }
            }
            Ok(VectorSource::Surrogate { model_version: HASH_MODEL_VERSION.to_string() })
        }
        (None, false) => {
            let model_version = label.unwrap_or_else(|| REFERENCE_MODEL_VERSION.to_string());
            validate_label(&model_version)?;
            Ok(VectorSource::Declared { model_version })
        }
    }
}

/// Векторы для издателя: из готового файла, из кеша стенда или форвардом.
///
/// Порядок источников выбран так, чтобы «посчитать заново» было последним шагом, а не первым:
/// форвард на 50k текстов занимает десятки минут, и терять его из-за упавшего k-means
/// недопустимо. Кеш стенда (§18.1) принимается только если совпал дайджест корпуса, модели и
/// версии preprocessинга: иначе измеренный гейт и издатель считали бы разное.
fn load_vectors(
    source: &VectorSource,
    pipeline: &Pipeline,
    corpus: Option<&str>,
    embeddings: Option<&str>,
    out: &mut String,
) -> Result<(Vec<f32>, String), CliError> {
    match (corpus, embeddings) {
        (None, Some(path)) => {
            let file = read_embeddings(Path::new(path))?;
            out.push_str(&format!(
                "векторы: `{path}` ({} строк{})\n",
                file.count,
                match file.digest {
                    Some(d) => format!(", дайджест {}", hex::encode(d)),
                    None => ", без дайджеста".to_string(),
                }
            ));
            if file.digest.is_none() {
                out.push_str(
                    "ВНИМАНИЕ: в файле нет дайджеста, сверить его с корпусом нечем — соответствие \
                     векторов корпусу остаётся на слове оператора.\n",
                );
            }
            Ok((file.values, format!("`{path}` ({} строк)", file.count)))
        }
        (Some(corpus_path), emb_path) => {
            let texts = read_corpus(Path::new(corpus_path))?;
            let digest = emb_digest(source.model_version(), pipeline.preprocessing_version, &texts);
            if let Some(path) = emb_path {
                let file = read_embeddings(Path::new(path))?;
                match file.digest {
                    Some(d) if d == digest => out.push_str(&format!(
                        "векторы: `{path}` ({} строк, дайджест совпал с корпусом)\n",
                        file.count
                    )),
                    Some(d) => {
                        return Err(CliError::Fail(format!(
                            "`{path}` посчитан по другому корпусу или другой модели: дайджест {}, \
                             а корпус `{corpus_path}` с моделью `{}` даёт {}. Пересчитайте \
                             эмбеддинги или укажите правильный корпус",
                            hex::encode(d),
                            source.model_version(),
                            hex::encode(digest)
                        )))
                    }
                    None => out.push_str(
                        "ВНИМАНИЕ: в файле эмбеддингов нет дайджеста, сверить его с корпусом \
                         нечем — соответствие векторов корпусу остаётся на слове оператора.\n",
                    ),
                }
                return Ok((file.values, format!("`{path}` ({} строк)", file.count)));
            }
            let cache = Path::new(corpus_path).with_extension("p0emb");
            if let Some(values) = read_p0emb(&cache, texts.len(), &digest)? {
                out.push_str(&format!(
                    "векторы: кеш `{}` ({} строк) — форвард не запускался\n",
                    cache.display(),
                    texts.len()
                ));
                return Ok((values, format!("кеш `{}` ({} строк)", cache.display(), texts.len())));
            }
            let model = forward_model(source, pipeline)?;
            let values = embed_corpus(model.as_ref(), pipeline, &texts)?;
            write_p0emb(&cache, &values, &digest, texts.len())?;
            out.push_str(&format!(
                "векторы: {} строк форвардом, кеш записан `{}`\n",
                texts.len(),
                cache.display()
            ));
            Ok((values, format!("корпус `{corpus_path}` ({} строк)", texts.len())))
        }
        (None, None) => unreachable!("пути без корпуса и без файла отсечены выше"),
    }
}

/// Модель, которая считает векторы. Без каталога весов и без суррогата форвард невозможен — и
/// сказать об этом надо прямо, а не «считать нечего, но всё в порядке».
fn forward_model(
    source: &VectorSource,
    pipeline: &Pipeline,
) -> Result<Box<dyn EmbeddingModel + 'static>, CliError> {
    match source {
        VectorSource::Weights { dir, model_version } => {
            crate::model::load_model(dir, pipeline, model_version)
        }
        VectorSource::Surrogate { .. } => Ok(Box::new(HashModel::new())),
        VectorSource::Declared { .. } => Err(CliError::Fail(
            "посчитать векторы нечем: нужен --model-dir DIR (feature `candle`) или \
             --allow-surrogate; готовые эмбеддинги берутся через --embeddings".into(),
        )),
    }
}

/// Форвард по корпусу: шаг 4 пайплайна §6.2, теми же словами, что и стенд.
fn embed_corpus(
    model: &dyn EmbeddingModel,
    pipeline: &Pipeline,
    texts: &[String],
) -> Result<Vec<f32>, CliError> {
    let mut values = Vec::with_capacity(texts.len() * DIM);
    for (i, text) in texts.iter().enumerate() {
        let pooled = model
            .embed_pooled(pipeline.model_input_for_index(text))
            .map_err(|e| fail(format!("форвард на строке {}", i + 1), e))?;
        values.extend_from_slice(&pooled);
    }
    Ok(values)
}

/// Корпус: строки файла → канонические тексты.
///
/// Порядок — как в стенде: пустые строки выбрасываются, остальные нормализуются (§6.2 шаг 1), и
/// уже по ним считается дайджест. Нормализация обязана быть до дайджеста: иначе корпус, отличающийся
/// от кеша только пробелами, выглядел бы как другой корпус.
fn read_corpus(path: &Path) -> Result<Vec<String>, CliError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| fail(format!("чтение корпуса `{}`", path.display()), e))?;
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let canonical = normalize_text(line)
            .map_err(|e| fail(format!("корпус `{}`, строка {}", path.display(), i + 1), e))?;
        out.push(canonical);
    }
    if out.is_empty() {
        return Err(CliError::Fail(format!(
            "корпус `{}` пуст: обучать центроиды не на чем",
            path.display()
        )));
    }
    Ok(out)
}

/// Файл эмбеддингов: магия, число строк, размерность и (необязательно) дайджест.
#[derive(Debug)]
struct Embeddings {
    values: Vec<f32>,
    count: usize,
    digest: Option<[u8; 32]>,
}

fn read_embeddings(path: &Path) -> Result<Embeddings, CliError> {
    let data = std::fs::read(path)
        .map_err(|e| fail(format!("чтение файла эмбеддингов `{}`", path.display()), e))?;
    if data.len() < EMB_HEADER {
        return Err(CliError::Fail(format!(
            "файл `{}` короче заголовка: {} байт, а нужно хотя бы {EMB_HEADER}",
            path.display(),
            data.len()
        )));
    }
    let count = u32::from_le_bytes(data[8..12].try_into().expect("срез 4 байта")) as usize;
    let dim = u32::from_le_bytes(data[12..16].try_into().expect("срез 4 байта")) as usize;
    if dim != DIM {
        return Err(CliError::Fail(format!(
            "файл `{}`: размерность {dim}, а протокол — {DIM} (§6.1)",
            path.display()
        )));
    }
    let (digest, offset) = if &data[..8] == P0EMB_TAG.as_slice() {
        if data.len() < P0EMB_HEADER {
            return Err(CliError::Fail(format!(
                "файл `{}` обрезан: заголовок кеша не дописан",
                path.display()
            )));
        }
        let d: [u8; 32] = data[16..48].try_into().expect("срез 32 байта");
        (Some(d), P0EMB_HEADER)
    } else if &data[..8] == EMB_TAG.as_slice() {
        (None, EMB_HEADER)
    } else {
        return Err(CliError::Fail(format!(
            "файл `{}`: магия `{}`, а ожидались `VDPEMB01` (файл издателя) или `VDP0EMB1` \
             (кеш стенда §18.1)",
            path.display(),
            String::from_utf8_lossy(&data[..8])
        )));
    };
    let payload = &data[offset..];
    if payload.len() != count * DIM * 4 {
        return Err(CliError::Fail(format!(
            "файл `{}`: {} байт векторов при {count} строках по {DIM} координат — хвост или обрыв",
            path.display(),
            payload.len()
        )));
    }
    let values: Vec<f32> = payload
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes(c.try_into().expect("срез 4 байта")))
        .collect();
    if values.iter().any(|v| !v.is_finite()) {
        return Err(CliError::Fail(format!(
            "файл `{}` содержит не-число: вектор с NaN или бесконечностью не квантуется (§6.3)",
            path.display()
        )));
    }
    Ok(Embeddings { values, count, digest })
}

/// Чтение кеша стенда: вернуть `None`, если кеша нет или он от другого корпуса/модели.
fn read_p0emb(path: &Path, count: usize, digest: &[u8; 32]) -> Result<Option<Vec<f32>>, CliError> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    if data.len() != P0EMB_HEADER + count * DIM * 4 || &data[..8] != P0EMB_TAG.as_slice() {
        return Ok(None);
    }
    let cached_count = u32::from_le_bytes(data[8..12].try_into().expect("срез 4 байта")) as usize;
    let cached_dim = u32::from_le_bytes(data[12..16].try_into().expect("срез 4 байта")) as usize;
    if cached_count != count || cached_dim != DIM || &data[16..48] != digest.as_slice() {
        return Ok(None);
    }
    let values: Vec<f32> = data[P0EMB_HEADER..]
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes(c.try_into().expect("срез 4 байта")))
        .collect();
    if values.iter().any(|v| !v.is_finite()) {
        return Ok(None);
    }
    Ok(Some(values))
}

/// Запись кеша стенда: сначала во временный файл, потом переименование. Обрыв на середине
/// оставил бы после сбоя файл, который читается как «кеш», а на деле обрезан.
fn write_p0emb(path: &Path, values: &[f32], digest: &[u8; 32], count: usize) -> Result<(), CliError> {
    let tmp = path.with_extension("p0emb.tmp");
    let mut w = BufWriter::new(
        std::fs::File::create(&tmp).map_err(|e| fail(format!("создание `{}`", tmp.display()), e))?,
    );
    w.write_all(P0EMB_TAG).map_err(|e| fail("запись кеша", e))?;
    w.write_all(&(count as u32).to_le_bytes()).map_err(|e| fail("запись кеша", e))?;
    w.write_all(&(DIM as u32).to_le_bytes()).map_err(|e| fail("запись кеша", e))?;
    w.write_all(digest).map_err(|e| fail("запись кеша", e))?;
    for v in values {
        w.write_all(&v.to_le_bytes()).map_err(|e| fail("запись кеша", e))?;
    }
    w.flush().map_err(|e| fail("сброс кеша", e))?;
    drop(w);
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| fail(format!("удаление `{}`", path.display()), e))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| fail(format!("переименование `{}`", path.display()), e))?;
    Ok(())
}

/// Пины весов и токенизатора: `model_blake3` и `tokenizer_blake3` — это хеши файлов каталога
/// модели, а не «наследованные нули» из эталонного манифеста. Артефакт с нулевым хешем весов
/// проверял бы на handshake только имя модели, а не сами веса (§15.1).
fn pin_model_files(m: &mut vecdht_artifact::Manifest, dir: &Path) -> Result<(), CliError> {
    let weights = dir.join("model.safetensors");
    let tokenizer = dir.join("tokenizer.json");
    for path in [&weights, &tokenizer] {
        if !path.exists() {
            return Err(CliError::Fail(format!(
                "в `{}` нет `{}`",
                dir.display(),
                path.file_name().and_then(|n| n.to_str()).unwrap_or("?")
            )));
        }
    }
    let hash_of = |path: &Path| -> Result<[u8; 32], CliError> {
        let bytes = std::fs::read(path)
            .map_err(|e| fail(format!("чтение `{}`", path.display()), e))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    };
    m.model_blake3 = hash_of(&weights)?;
    m.tokenizer_blake3 = hash_of(&tokenizer)?;
    m.tokenizer_revision = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".to_string());
    Ok(())
}

/// Потоки по умолчанию: число ядер, но не больше восьми. Больше — уже не ускорение, а толчка в
/// когти: измерение на 8 потоках и так занимает десятки минут.
fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(1, 8)
}

fn load(dir: String) -> Result<Artifact, CliError> {
    Artifact::load(Path::new(&dir)).map_err(|e| fail(format!("чтение артефакта из `{dir}`"), e))
}

fn show(a: &Artifact, out: &mut String) {
    let m = &a.manifest;
    out.push_str(&format!("{} {}\n", CMD_PREFIX, m.model_version));
    out.push_str(&format!("  artifact_hash        {}\n", hex::encode(a.artifact_hash())));
    out.push_str(&format!("  genesis_hash         {}\n", hex::encode(a.genesis_hash())));
    out.push_str(&format!("  preprocessing_version  {}\n", m.preprocessing_version));
    out.push_str(&format!("  pooling              {:?}\n", m.pooling));
    out.push_str(&format!(
        "  routing              nlist {} × {} кластеров на шард, {} шардов, nprobe {} из {:?}\n",
        m.routing.nlist, m.routing.clusters_per_shard, m.routing.shards,
        m.routing.nprobe_default, m.routing.nprobe_allowed
    ));
    out.push_str(&format!(
        "  quant                {} / {}, max_d2 {}\n",
        m.quant.grid, m.quant.rounding, m.quant.max_d2
    ));
    out.push_str(&format!(
        "  time                 бакет {} с, ttl {}–{} с, TimeMark каждые {} опсов\n",
        m.time.bucket_sec, m.time.ttl_default_sec, m.time.ttl_max_sec, m.time.time_mark_every
    ));
    out.push_str(&format!(
        "  power                {} бит по умолчанию, диапазон {}–{}, blake3 {} МХеш/с\n",
        m.power.pow_bits_default, m.power.pow_bits_min, m.power.pow_bits_max, m.power.blake3_mhz_core
    ));
    out.push_str(&format!(
        "  admission            ≤ {} живых на шард, {} publish/с и burst {} на пира, {} find/с, {} приёма/с узлом\n",
        m.admission.max_live_per_shard, m.admission.per_peer_publish_rps,
        m.admission.per_peer_publish_burst, m.admission.per_peer_find_rps, m.admission.node_admits_per_s
    ));
    out.push_str(&format!(
        "  replication          R {} W {}, порог членства {}, lease {} с, renew {} с, выборы {} с\n",
        m.replication.r, m.replication.w, m.replication.membership_threshold,
        m.replication.lease_sec, m.replication.renew_sec, m.replication.election_timeout_sec
    ));
    out.push_str(&format!(
        "  index                снапшот каждые {} опсов, сегмент WAL {} Б, group commit {} мс\n",
        m.index.snapshot_ops, m.index.wal_segment_bytes, m.index.wal_group_commit_ms
    ));
    out.push_str(&format!(
        "  авторитет            {} ключ(ей), порог {}, подписей в файле {}\n",
        m.authority.keys.len(), m.authority.threshold, m.signatures.len()
    ));
    out.push_str(&format!("  model_blake3         {}\n", hex::encode(m.model_blake3)));
    out.push_str(&format!("  tokenizer_blake3     {} (revision {})\n",
        hex::encode(m.tokenizer_blake3), m.tokenizer_revision));
    out.push_str(&format!("  centroid_blake3      {}\n", hex::encode(m.centroid_blake3)));
}

/// Префикс строки `show`: команда подставляется вызывающим, чтобы вывод `artifact show` и
/// `artifact verify` отличался заголовком, а не только содержимым.
const CMD_PREFIX: &str = "артефакт:";

/// Центроиды из seed: 1024 строки по 384 координат, каждая — нормализованный вектор с
/// детерминированными знаками. Нормализация обязательна: центроид обязан быть сравним с
/// квантованным вектором записи без пересчёта масштаба (§6.3), а `Centroids::from_f64` квантует
/// той же сеткой, что и записи.
fn dev_centroids(seed: &[u8; 32]) -> Centroids {
    let mut flat: Vec<f64> = Vec::with_capacity(NLIST as usize * DIM);
    for c in 0..NLIST as u32 {
        let mut row = [0f64; DIM];
        for block in 0..(DIM / 32) {
            let d = blake3::Hasher::new()
                .update(DOMAIN_CENTROIDS)
                .update(seed)
                .update(&c.to_le_bytes())
                .update(&(block as u16).to_le_bytes())
                .finalize();
            for (j, b) in d.as_bytes().iter().enumerate() {
                // Центр отображения — 127.5, а не 128: без него все координаты были бы
                // неотрицательными, строки жались бы к одному октанту сферы, и соседние кластеры
                // оказались бы неразличимы по расстоянию — ровно та поломка, от которой §7.1 и
                // требует настоящего k-means.
                row[block * 32 + j] = (f64::from(*b) - 127.5) / 127.5;
            }
        }
        // Нормализация обязана получиться: 384 ненулевых координат дают ненулевую норму всегда,
        // а `.expect` здесь — потому что тихий пропуск оставил бы в файле строку вне сетки.
        l2_normalize(&mut row).expect("случайная строка из 384 ненулевых координат нормализуется");
        flat.extend_from_slice(&row);
    }
    Centroids::from_f64(&flat).expect("1024 строк по 384 значения")
}

fn dev_key_seed(seed: &[u8; 32], index: u16) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(DOMAIN_DEV_KEY)
        .update(seed)
        .update(&index.to_le_bytes())
        .finalize()
        .as_bytes()
}

fn extra_authorities(p: &Parsed, cmd: &str) -> Result<Vec<[u8; 32]>, CliError> {
    let mut out = Vec::new();
    for raw in p.values(cmd, "authority")? {
        let bytes = crate::args::parse_hex::<32>(cmd, "authority", &raw)
            .map_err(CliError::Arg)?;
        out.push(bytes);
    }
    Ok(out)
}

/// `model_version` входит в канонический JSON и под подпись, поэтому алфавит узкий и проверяется
/// здесь, а не «как-нибудь потом в манифесте»: неизвестный символ в подписанном материале — это
/// документ, который другой декодер отвергнет.
fn validate_label(label: &str) -> Result<(), CliError> {
    if label.is_empty() || label.len() > 64 {
        return Err(CliError::Fail("label обязан быть 1..64 символа".into()));
    }
    if !label.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'/' | b'-')
    }) {
        return Err(CliError::Fail(format!(
            "label `{label}` содержит недопустимые символы: только [a-z0-9._/-]"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(cmd: &str, args: &[&str]) -> Parsed {
        let mut argv: Vec<&str> = vec!["artifact", cmd];
        argv.extend_from_slice(args);
        Parsed::parse(&argv[1..]).unwrap()
    }

    #[test]
    fn dev_centroids_are_on_the_grid_and_all_distinct() {
        let c = dev_centroids(&[7u8; 32]);
        assert_eq!(c.len(), (NLIST as usize) * DIM);
        // Разные seed'ы дают разные разбиения; одинаковые координатные строки внутри одного
        // набора означали бы, что два кластера неразличимы, и assign был бы жеребьёвкой.
        let first = c.row(0);
        for i in 1..NLIST {
            assert_ne!(c.row(i), first, "кластер {i} совпал с 0");
        }
        // Каждый ряд — единичный вектор, квантованный сеткой i8/127, поэтому его максимальная
        // координата не может быть мелкой по самой конструкции: при норме 1 хотя бы одна
        // координата ≥ 1/√384, то есть ≥ 6 после умножения на 127 (округрование снимает единицу).
        // Меньшее число означало бы, что `l2_normalize` отработала иначе, чем заявлено, и
        // расстояния до центроидов перестали бы быть сравнимыми (§6.3).
        let mx: i32 = (0..NLIST)
            .map(|i| c.row(i).iter().map(|v| i32::from(*v).abs()).max().unwrap_or(0))
            .min()
            .unwrap();
        assert!(mx >= 5, "строки центроидов не лежат на сетке единичных векторов: max |x| = {mx}");
    }

    #[test]
    fn label_alphabet_is_narrow_on_purpose() {
        validate_label("local").unwrap();
        validate_label("site-2/rack_a").unwrap();
        assert!(validate_label("").is_err());
        assert!(validate_label("Local").is_err());
        assert!(validate_label(&"x".repeat(65)).is_err());
    }

    #[test]
    fn dev_key_seeds_are_domain_and_index_bound() {
        let s = [3u8; 32];
        assert_ne!(dev_key_seed(&s, 0), dev_key_seed(&s, 1));
        assert_ne!(dev_key_seed(&s, 0), *blake3::hash(&[0u8; 2]).as_bytes());
    }

    #[test]
    fn corpus_drops_blank_lines_and_canonicalizes_the_rest() {
        let d = vecdht_index::testing::dir("cli-artifact-corpus");
        let file = d.join("corpus.txt");
        std::fs::write(&file, "  Привет  \n\n\tМир\t\n").unwrap();
        let texts = read_corpus(&file).unwrap();
        assert_eq!(texts.len(), 2, "пустая строка — не документ");
        assert_eq!(texts[0], "Привет", "текст обязан быть канонизирован (§6.2 шаг 1)");
        assert_eq!(texts[1], "Мир");
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn embeddings_file_with_foreign_magic_or_dimension_is_refused() {
        let d = vecdht_index::testing::dir("cli-artifact-emb");
        let file = d.join("vectors.bin");
        // Чужая магия: файл не эмбеддинги, а, скажем, архив.
        let mut bytes = b"NOTEMB01".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(DIM as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; DIM * 4]);
        std::fs::write(&file, &bytes).unwrap();
        let err = read_embeddings(&file).unwrap_err().to_string();
        assert!(err.contains("VDPEMB01"), "{err}");

        // Правильная магия, чужая размерность: 8 координат вместо 384.
        let mut bytes = EMB_TAG.to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8 * 4]);
        std::fs::write(&file, &bytes).unwrap();
        let err = read_embeddings(&file).unwrap_err().to_string();
        assert!(err.contains("размерность 8"), "{err}");
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn surrogate_cannot_be_published_under_another_model_name() {
        // Суррогат — это `test-hash-model-v1`; подписать артефакт именем настоящей модели
        // значило бы соврать в том самом поле, которое сверяется на handshake (§6.7).
        let err = vector_source(&parse("publish", &["--allow-surrogate", "--label", "granite-embedding-97m-v2"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("test-hash-model-v1"), "{err}");
        // Без --label имя суррогата и есть имя модели.
        let s = vector_source(&parse("publish", &["--allow-surrogate"])).unwrap();
        assert_eq!(s.model_version(), HASH_MODEL_VERSION);
    }

    #[test]
    fn remap_puts_every_record_into_the_shard_of_its_new_cluster() {
        let d = vecdht_index::testing::dir("cli-artifact-remap");
        let artifact = d.join("artifact");
        let mut out = String::new();
        exec_init(
            &parse("init", &["--out", &artifact.display().to_string(), "--dev-keys", "1"]),
            &mut out,
        )
        .unwrap();
        let a = Artifact::load(&artifact).unwrap();
        let rows = a.centroids.rows();

        // Две записи: вектор первой строки центроидов (кластер 0, шард 0) и вектор строки 20
        // (кластер 20, шард 1). Старый `cluster_id` у обеих — 999, то есть он обязан измениться.
        let mut bytes = Vec::new();
        for (n, row) in [rows[0], rows[20]].iter().enumerate() {
            let e = IndexEntry {
                owner_ed25519: [n as u8 + 1; 32],
                vec_q: **row,
                cluster_id: 999,
                published_bucket: 7,
                ttl_buckets: 100,
            };
            bytes.extend_from_slice(&e.to_bytes());
        }
        let file = d.join("entries.bin");
        std::fs::write(&file, &bytes).unwrap();

        let out_dir = d.join("shards");
        let mut out = String::new();
        exec_remap(
            &parse(
                "remap",
                &[
                    "--artifact",
                    &artifact.display().to_string(),
                    "--entries",
                    &file.display().to_string(),
                    "--out",
                    &out_dir.display().to_string(),
                ],
            ),
            &mut out,
        )
        .unwrap();
        assert!(out.contains("номер кластера изменился у 2"), "{out}");

        // Файлы шардов: запись с кластером 0 — в шард 0, с кластером 20 — в шард 1 (§7.4).
        for (shard, cluster) in [(0usize, 0u16), (1, 20)] {
            let path = out_dir.join(format!("shard-{shard:02}.bin"));
            let data = std::fs::read(&path).unwrap();
            assert_eq!(data.len(), INDEX_ENTRY_BYTES, "шард {shard}: записей не одна");
            let e = IndexEntry::from_bytes(&data).unwrap();
            assert_eq!(e.cluster_id, cluster, "кластер записи переприсвоен неверно");
            assert_eq!(e.cluster_id as usize / CLUSTERS_PER_SHARD as usize, shard);
            // Остальные поля записи не тронуты: переприсваивается только кластер.
            assert_eq!(e.published_bucket, 7);
            assert_eq!(e.ttl_buckets, 100);
        }
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn remap_refuses_a_truncated_records_file() {
        let d = vecdht_index::testing::dir("cli-artifact-remap-trunc");
        let artifact = d.join("artifact");
        let mut out = String::new();
        exec_init(
            &parse("init", &["--out", &artifact.display().to_string(), "--dev-keys", "1"]),
            &mut out,
        )
        .unwrap();
        let file = d.join("entries.bin");
        std::fs::write(&file, vec![0u8; INDEX_ENTRY_BYTES - 1]).unwrap();
        let err = exec_remap(
            &parse(
                "remap",
                &[
                    "--artifact",
                    &artifact.display().to_string(),
                    "--entries",
                    &file.display().to_string(),
                    "--out",
                    &d.join("shards").display().to_string(),
                ],
            ),
            &mut String::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("неполная"), "{err}");
        vecdht_index::testing::remove(&d);
    }
}
