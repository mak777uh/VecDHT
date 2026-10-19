//! `artifact init|show|verify` — артефакт сети (§15).
//!
//! Здесь нужна особая аккуратность с тем, что именно обещает вывод. `init` собирает **dev**-артефакт:
//! центроиды детерминированы из seed (это не результат k-means на реальных интентах, и §7.1 требует
//! именно k-means), поля `model_blake3`/`tokenizer_blake3` унаследованы от reference-манифеста, а
//! ключи авторитета выведены из того же seed. Такой артефакт годится для локальной сети, тестов и
//! разбора «почему мой интент уехал в другой шард», и ровно об этом он и пишет в предупреждении.
//! Публичной сети нужен артефакт, подписанный 3-of-5 ключами bootstrap-авторитета (§15.2), — CLI
//! его не заменяет и не делает вид.
//!
//! `verify` вызывает `Artifact::verify` с тем же `pinned_hash`, что и узел на handshake (§15.3):
//! сверка хеша обязана предшествовать инициализации индексных структур, иначе «артефакт с чужими
//! центроидами» успевает построить IVF раньше, чем будет отвергнут.

use std::path::{Path, PathBuf};

use vecdht_artifact::manifest::DOMAIN_ARTIFACT;
use vecdht_artifact::{Artifact, Centroids, CENTROID_FILE, MANIFEST_FILE};
use vecdht_crypto::ids::content_hash;
use vecdht_crypto::quant::l2_normalize;
use vecdht_crypto::sig::Identity;
use vecdht_embed::PREPROCESSING_VERSION;
use vecdht_wire::{DIM, NLIST};

use crate::args::Parsed;
use crate::{CliError, fail};

pub const CMD_INIT: &str = "artifact init";
pub const CMD_SHOW: &str = "artifact show";
pub const CMD_VERIFY: &str = "artifact verify";

pub const FLAGS_INIT: &[&str] = &[
    "out", "seed", "label", "dev-keys", "authority", "threshold", "pow-bits", "mhz", "force",
    "show-seed",
];
pub const FLAGS_SHOW: &[&str] = &["artifact"];
pub const FLAGS_VERIFY: &[&str] = &["artifact", "pinned"];

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
    keys.extend(extra_authorities(p)?);
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

fn extra_authorities(p: &Parsed) -> Result<Vec<[u8; 32]>, CliError> {
    let mut out = Vec::new();
    for raw in p.values(CMD_INIT, "authority")? {
        let bytes = crate::args::parse_hex::<32>(CMD_INIT, "authority", &raw)
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
}
