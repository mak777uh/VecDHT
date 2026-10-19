//! Golden-векторы артефакта (гейт P2 из §20: «golden-векторы побайтово совпадают на двух
//! разных машинах»).
//!
//! Фикстура `tests/golden/artifact.txt` — зафиксированные байты, а не «характеристики»: здесь
//! подписываемый материал манифеста, его хеши, часть файла центроидов и вывод маршрутизации по
//! ним. Смысл ровно тот же, что у golden-векторов `vecdht-wire`: если на другой машине
//! канонический JSON собрался другими байтами, фикстура не совпадёт, и расхождение будет видно
//! как diff hex-строк, а не как mysteriously не проходящая подпись в продакшене.
//!
//! Всё, что попадает в фикстуру, обязано быть свободно от libm и от порядка итерирования хеш-таблиц:
//! целочисленная арифметика, фиксированный порядок ключей, фиксированный порядок строк файла.
//!
//! Перезапись: `VEC_DHT_GOLDEN=1 cargo test -p vecdht-artifact --test golden_artifact`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_artifact::{reference_artifact, reference_manifest, CENTROID_BYTES};
use vecdht_wire::codec::DIM;
use vecdht_wire::messages::Codec as _;

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/artifact.txt")
}

fn vectors() -> BTreeMap<String, Vec<u8>> {
    let mut v = BTreeMap::new();
    let mut add = |key: &str, bytes: Vec<u8>| {
        v.insert(key.to_string(), bytes);
    };

    let a = reference_artifact();

    // 1. Канонические байты манифеста: то, что идёт в подпись и в `artifact_hash`.
    add("manifest.unsigned_json", a.signing_material());
    add("manifest.json", a.manifest.to_json_bytes());
    // Тот же манифест, собранный из структуры: расхождение здесь означает, что порядок ключей
    // или формат числа поехал, и все подписи авторитетов станут невалидными.
    add("manifest.unsigned_json.twice", reference_manifest().unsigned_json());

    // 2. Хеши: `genesis_hash` совпадает с `artifact_hash` по построению (§15.3), пиним оба.
    add("artifact.artifact_hash", a.artifact_hash().to_vec());
    add("artifact.genesis_hash", a.genesis_hash().to_vec());
    add("manifest.centroid_blake3", a.manifest.centroid_blake3.to_vec());

    // 3. Файл центроидов целиком в фикстуру не просится (384 КиБ), но его границы и размер пинованы.
    let bytes = a.centroids.as_bytes();
    add("centroids.len", (bytes.len() as u32).to_le_bytes().to_vec());
    add("centroids.head32", bytes[..32].to_vec());
    add("centroids.tail32", bytes[bytes.len() - 32..].to_vec());
    add("centroids.const_centroid_bytes", (CENTROID_BYTES as u32).to_le_bytes().to_vec());
    assert_eq!(bytes.len(), CENTROID_BYTES);

    // 4. Маршрутизация по замороженному квантизатору: присваивание и топ-4 для трёх строк.
    //    Это тот контракт `(d2 ASC, cluster ASC)`, без которого два узела разводят интенты по
    //    разным шардам, не имея ни ошибки, ни расхождения в хешах.
    for (name, cluster) in [("q17", 17u16), ("q500", 500), ("q1023", 1023)] {
        let row = a.centroids.row(cluster);
        add(&format!("routing.assign.{name}"), a.centroids.assign(row).to_le_bytes().to_vec());
        add(
            &format!("routing.top4.{name}"),
            a.centroids
                .top(row, 4)
                .into_iter()
                .flat_map(|c| c.to_le_bytes())
                .collect(),
        );
    }
    // Смещённый запрос: та же строка с инвертированным знаком — ближайший кластер обязан
    // перестать быть собой, и это тоже фиксированный байт.
    let flipped: Vec<i8> = a.centroids.row(17).iter().map(|x| -x).collect();
    let mut flipped_arr = [0i8; DIM];
    flipped_arr.copy_from_slice(&flipped);
    add(
        "routing.assign.flipped17",
        a.centroids.assign(&flipped_arr).to_le_bytes().to_vec(),
    );

    // 5. `ArtifactAnnounce` — числа манифеста в байтах протокола (§5, §7.7).
    add("announce.encode", a.announce(0).encode_unsigned());
    add("announce.encode_bucket", a.announce(0x1234_5678).encode_unsigned());

    // 6. Производные лимиты: байтовый бюджет шарда (§11.3) как u64 LE.
    add(
        "manifest.shard_bytes_budget",
        a.manifest.shard_bytes_budget().to_le_bytes().to_vec(),
    );

    v
}

fn render(v: &BTreeMap<String, Vec<u8>>) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("# vecdht-artifact golden vectors (spec v8 §7.1, §15). key=hex\n");
    s.push_str("# regenerate: VEC_DHT_GOLDEN=1 cargo test -p vecdht-artifact --test golden_artifact\n");
    for (k, b) in v {
        let _ = writeln!(s, "{k}={}", hex::encode(b));
    }
    s
}

fn parse(text: &str) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, hx) = line.split_once('=').unwrap_or_else(|| panic!("строка без '=': {line}"));
        out.insert(
            k.trim().to_string(),
            hex::decode(hx.trim()).unwrap_or_else(|e| panic!("{k}: {e}")),
        );
    }
    out
}

#[test]
fn golden_artifact_matches_checked_in_fixture() {
    let produced = vectors();
    let path = golden_path();
    if std::env::var("VEC_DHT_GOLDEN").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, render(&produced)).unwrap();
        println!("фикстура перезаписана: {}", path.display());
        return;
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "нет фикстуры {} ({e}). Запусти: VEC_DHT_GOLDEN=1 cargo test -p vecdht-artifact --test golden_artifact",
            path.display()
        )
    });
    let expected = parse(&text);
    let mut diffs = Vec::new();
    for (k, b) in &produced {
        match expected.get(k.as_str()) {
            None => diffs.push(format!("{k}: отсутствует в фикстуре")),
            Some(want) if want != b => diffs.push(format!(
                "{k}: расхождение\n   было: {}\n   стало: {}",
                hex::encode(want),
                hex::encode(b)
            )),
            _ => {}
        }
    }
    for k in expected.keys() {
        if !produced.contains_key(k.as_str()) {
            diffs.push(format!("{k}: есть в фикстуре, но больше не производится"));
        }
    }
    assert!(
        diffs.is_empty(),
        "golden-векторы артефакта разошлись ({}):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

/// Контент-фикстура обязана быть именно тем, что подписывают: подпись над байтами, которых нет
/// в файле, — это обещание, которое нельзя проверить офлайн.
#[test]
fn fixture_pins_the_signed_bytes_not_their_hash() {
    if std::env::var("VEC_DHT_GOLDEN").is_ok() {
        return; // фикстура ещё не написана: её создаёт соседний тест этого же запуска
    }
    let path = golden_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("нет фикстуры {} ({e})", path.display()));
    let a = reference_artifact();
    let signed = hex::encode(a.signing_material());
    assert!(
        text.contains(&format!("manifest.unsigned_json={signed}")),
        "в фикстуре записан не тот манифест, что подписывается"
    );
    // Пиним байты, а не только хеш: подмена «другой манифест при том же артефакте» обязана быть
    // видна в фикстуре, а не только в том, что её не примет подпись.
    assert!(signed.len() > 1_000, "подписываемый материал подозрительно короткий");
}
