//! Golden-векторы `vecdht-crypto` (гейт P2: «побайтовое совпадение на двух разных машинах»).
//!
//! Здесь фиксируется ровно то, что спецификация §6 называет consensus-critical: квантованная
//! форма вектора, целочисленные дистанции, идентификаторы, вход PoW, вход подписи и сама
//! Ed25519-подпись. Всё, что использует плавающую точку, построено на точных целочисленных
//! делениях: `transcendental` (sin/exp/log) в векторах нет намеренно — libm между libc
//! различается, а `sqrt` и деление обязаны быть корректно округлёнными по IEEE-754.
//!
//! Перезапись: `VEC_DHT_GOLDEN=1 cargo test -p vecdht-crypto --test golden_vectors`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use vecdht_crypto::cert::{sign_cert, AuthoritySet, DOMAIN_NODE_CERT};
use vecdht_crypto::ids::{candidate_order_key, content_hash, entry_key, intent_id, intent_text_hash};
use vecdht_crypto::pow::{mine_pow, pow_input};
use vecdht_crypto::quant::{
    assign_cluster, clusters_of_shard, dequantize, group_by_shard, l2_normalize, l2_sq, quantize_slice,
    round_half_away, shard_of_cluster, similarity_from_d2, top_clusters, DIM,
};
use vecdht_crypto::sig::{sig_digest, sign_domain, Identity};
use vecdht_wire::frame::{Kind, FLAG_SIGNED};
use vecdht_wire::messages::{Codec, Match, MatchResult, domain};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::messages::Role;

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/vectors.txt")
}

/// Nonce, найденный перебором для входа ниже при старте `POW_NONCE_START` (24 бита ≈ 16,7 млн
/// blake3). Ищется только при перегенерации фикстуры (`VEC_DHT_GOLDEN=1`); в обычной проверке
/// это константа, и ей остаётся только пройти проверку порога.
const POW_NONCE: u64 = 0x0ADE_0000_0016_7751;
const POW_NONCE_START: u64 = 0x0ADE_0000_0000_0000;

/// Сложность, на которой зафиксирован nonce. Это **не** `POW_BITS_MIN`: фикстура закрепляет
/// алгоритм (вход → порог), а политику сложности `[P0]`-замер может менять, и смена диапазона не
/// должна делать golden-файл невалидным — иначе вся фикстура и все её байты перегенерировались бы
/// из-за одного числа.
const POW_BITS_FIXTURE: u32 = 24;

/// Детерминированная «f32-подобная» последовательность без трансцендентных функций:
/// целое, поделённое на 105.5 (= 211/2), — корректно округлённое деление IEEE одинаково везде.
fn raw_embedding(offset: usize) -> Vec<f64> {
    (0..DIM).map(|i| ((i * 37 + offset) % 211) as f64 / 105.5 - 1.0).collect()
}

fn normalized(offset: usize) -> Vec<f64> {
    let mut v = raw_embedding(offset);
    l2_normalize(&mut v).expect("вектор ненулевой");
    v
}

/// Пайплайн §6.2 целиком: f64 → нормализация → сетка Δ=1/127.
fn qv(offset: usize) -> [i8; DIM] {
    quantize_slice(&normalized(offset)).expect("вектор корректной размерности")
}

fn centroid(idx: usize) -> [i8; DIM] {
    let mut v = [0i8; DIM];
    for (i, x) in v.iter_mut().enumerate() {
        *x = (((i + idx * 11) % 7) as i32 - 3) as i8;
    }
    v
}

fn match_result_body() -> Vec<u8> {
    MatchResult {
        shard: 5,
        epoch: 99,
        query_id: 1,
        responder_ed25519: [0x07; 32],
        matches: vec![
            Match { owner_ed25519: [1; 32], cluster_id: 80, d2: 1000, slot: 3 },
            Match { owner_ed25519: [2; 32], cluster_id: 81, d2: 1000, slot: 4 },
        ],
    }
    .body_bytes()
}

fn vectors() -> BTreeMap<String, Vec<u8>> {
    let mut v: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut add = |k: &str, b: Vec<u8>| {
        v.insert(k.to_string(), b);
    };

    // --- §6.3: пайплайн квантования --------------------------------------
    let vec_q = qv(0);
    add("quant.vec_q", vec_q.iter().map(|x| *x as u8).collect());
    add("quant.vec_q.second", qv(1).iter().map(|x| *x as u8).collect());

    // Сетка и округление: половина в сторону от нуля, а не banker's.
    let mut rounding = Vec::new();
    for k in -6..=6i32 {
        let x = k as f64 / 2.0;
        let q = round_half_away(x);
        // знак старшего байта + величина: значение в [-3, 3], хватает одного байта со знаком
        rounding.push(q as u8);
    }
    add("quant.round_half_away", rounding);

    // --- §6.4: целочисленные дистанции -----------------------------------
    let other = qv(7);
    let d2 = l2_sq(&vec_q, &other);
    add("quant.l2_sq", d2.to_le_bytes().to_vec());
    add("quant.l2_sq.self", l2_sq(&vec_q, &vec_q).to_le_bytes().to_vec());
    let sim = similarity_from_d2(d2);
    add("quant.similarity_from_d2", sim.to_le_bytes().to_vec());

    // --- §7.2: присваивание кластера и nprobe -----------------------------
    let centroids: Vec<[i8; DIM]> = (0..64).map(centroid).collect();
    let refs: Vec<&[i8; DIM]> = centroids.iter().collect();
    add("quant.assign_cluster", (assign_cluster(&vec_q, &refs) as u16).to_le_bytes().to_vec());
    let probe: Vec<u8> = top_clusters(&vec_q, &refs, 16)
        .into_iter()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    add("quant.top_clusters_16", probe);
    let grouped: Vec<u8> = group_by_shard(&top_clusters(&vec_q, &refs, 16))
        .into_iter()
        .flat_map(|(s, cs)| {
            let mut b = s.to_le_bytes().to_vec();
            b.push(cs.len() as u8);
            b.extend(cs.iter().flat_map(|c| c.to_le_bytes()));
            b
        })
        .collect();
    add("quant.group_by_shard", grouped);
    add(
        "quant.clusters_of_shard_63",
        clusters_of_shard(63).into_iter().flat_map(|c| c.to_le_bytes()).collect(),
    );
    add("quant.shard_of_cluster_1023", (shard_of_cluster(1023) as u16).to_le_bytes().to_vec());

    // --- §6.5: идентификаторы --------------------------------------------
    add("ids.intent_id", intent_id(&vec_q, 3).to_vec());
    add("ids.entry_key", entry_key(&[0xA1; 32], 5, 77, 99).to_vec());
    add("ids.candidate_order_key", candidate_order_key(99, 5, &[0xA1; 32]).to_vec());
    add("ids.intent_text_hash", intent_text_hash("найди мне контрагент".as_bytes()).to_vec());
    add("ids.content_hash", content_hash(b"vecdht-genesis").to_vec());

    // --- §11.1: PoW -------------------------------------------------------
    let slot = entry_key(&[0xA1; 32], 5, 77, 99);
    let input = pow_input(&[0xA1; 32], 5, 99, &slot, 106_250_010);
    add("pow.input", input.clone());
    // При перегенерации фикстуры nonce ищется перебором (секунды), при обычной проверке
    // берётся из const и только проверяется на порог (один blake3).
    let nonce = if std::env::var("VEC_DHT_GOLDEN").is_ok() {
        mine_pow(&input, POW_BITS_FIXTURE, POW_NONCE_START, 1 << 28)
            .expect("24 бита находятся за 2^28 попыток с вероятностью ~1")
    } else {
        POW_NONCE
    };
    add("pow.nonce", nonce.to_le_bytes().to_vec());
    assert!(
        vecdht_crypto::pow::pow_ok(&input, nonce, POW_BITS_FIXTURE),
        "nonce не проходит порог: вход PoW изменился — перегенерируй фикстуру и обнови POW_NONCE"
    );

    // --- §5.2/§4.3: вход подписи и детерминизм Ed25519 -------------------
    let body = match_result_body();
    add(
        "sig.sig_digest.match_result",
        sig_digest(domain::MATCH, Kind::MatchResult, FLAG_SIGNED, &body).to_vec(),
    );
    let id = Identity::from_seed([0x11; 32]);
    add("identity.pubkey", id.pubkey().to_vec());
    add(
        "sig.ed25519.match_result",
        id.sign_body(domain::MATCH, Kind::MatchResult, &body).to_vec(),
    );
    add(
        "sig.ed25519.domain_membership",
        sign_domain(&SigningKey::from_bytes(&[0x22; 32]), domain::MEMBER, b"payload-1").to_vec(),
    );

    // --- §4.2: подписанный NodeCert --------------------------------------
    let cert = NodeCert {
        version: 8,
        genesis_hash: content_hash(b"vecdht-genesis"),
        role: Role::IndexNode,
        owner_ed25519: id.pubkey(),
        dht_peer_id: vec![0x00, 0x24, 0x00, 0xDE, 0xAD],
        shards: vec![0, 5, 63],
        capacity_entries: 200_000,
        valid_from: 1_700_000_000,
        valid_until: 1_700_086_400,
        nonce: [0x5A; 16],
        authority_sigs: vec![],
    };
    add("cert.unsigned_body", cert.unsigned_body());
    // Подпись ключом, которого нет в наборе авторитетов: порог не достигнут, и golden-вектор
    // это фиксирует (15.2: доверенные ключи pinned, чужой ключ не засчитывается).
    let foreign = SigningKey::from_bytes(&[0x33; 32]);
    let signed_foreign = sign_cert(&cert, &foreign);
    add("cert.signed_by_foreign", signed_foreign.encode());
    let set = AuthoritySet::new(vec![id.pubkey()], 1);
    add(
        "cert.count_foreign",
        vec![set.count_valid(&cert.unsigned_body(), DOMAIN_NODE_CERT, &signed_foreign.authority_sigs) as u8],
    );
    // Тот же сертификат, подписанный доверенным ключом: порог выполнен, подпись в байтах.
    let signed_ok = sign_cert(&cert, &SigningKey::from_bytes(&id.seed()));
    add("cert.signed_by_authority", signed_ok.encode());
    add(
        "cert.count_authority",
        vec![set.count_valid(&cert.unsigned_body(), DOMAIN_NODE_CERT, &signed_ok.authority_sigs) as u8],
    );

    // Обратная сторона сетки — только для отладки, но байты тоже фиксированы (f64 LE).
    add(
        "quant.dequantize.first8",
        dequantize(&vec_q)[..8].iter().flat_map(|x| x.to_le_bytes()).collect(),
    );

    v
}

fn render(v: &BTreeMap<String, Vec<u8>>) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("# vecdht-crypto golden vectors (spec v8 §4–§6, §11). key=hex\n");
    s.push_str("# regenerate: VEC_DHT_GOLDEN=1 cargo test -p vecdht-crypto --test golden_vectors\n");
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
        out.insert(k.trim().to_string(), hex::decode(hx.trim()).unwrap_or_else(|e| panic!("{k}: {e}")));
    }
    out
}

#[test]
fn golden_vectors_match_checked_in_fixture() {
    let produced = vectors();
    let path = golden_path();
    if std::env::var("VEC_DHT_GOLDEN").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, render(&produced)).unwrap();
        println!("golden-файл перезаписан: {}", path.display());
        return;
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "нет фикстуры {} ({e}). Запусти: VEC_DHT_GOLDEN=1 cargo test -p vecdht-crypto --test golden_vectors",
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
            Some(_) => {}
        }
    }
    for k in expected.keys() {
        if !produced.contains_key(k.as_str()) {
            diffs.push(format!("{k}: есть в фикстуре, но больше не генерируется"));
        }
    }
    assert!(diffs.is_empty(), "{} golden-расхождений:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
fn pow_nonce_in_fixture_satisfies_the_threshold() {
    let v = vectors();
    // Генерация находит nonce перебором; проверка — это то, что делает узел, и она обязана
    // оставаться дешёвой (один blake3) для любого входа из фикстуры.
    let input = &v["pow.input"];
    let nonce = u64::from_le_bytes(v["pow.nonce"].as_slice().try_into().unwrap());
    assert!(vecdht_crypto::pow::pow_ok(input, nonce, POW_BITS_FIXTURE));
    // Монотонность порога: nonce, выполненный на 24 битах, годится и на любой более лёгкой
    // политике, то есть на всём адаптивном диапазоне §11.2 — иначе смена `POW_BITS_MIN`
    // отвергала бы уже принятые сетью записи.
    for bits in vecdht_crypto::pow::POW_BITS_MIN..=vecdht_crypto::pow::POW_BITS_MAX {
        assert!(vecdht_crypto::pow::pow_ok(input, nonce, bits), "bits {bits}");
    }
    // 13 (доменная строка) + 32 (owner) + 2 (shard) + 8 (epoch) + 32 (slot) + 4 (expires_bucket)
    assert_eq!(input.len(), 13 + 32 + 2 + 8 + 32 + 4);
}

#[test]
fn quantized_form_is_always_in_grid() {
    // Сетка без clamping-потерь: |u_i| ≤ 1 ⇒ квант в [-127, 127] (спека §6.3).
    for off in [0usize, 1, 3, 17, 99] {
        let q = qv(off);
        for &x in q.iter() {
            assert!((-127..=127).contains(&(x as i32)), "вне сетки: {x}");
        }
        assert_eq!(l2_sq(&q, &q), 0);
        // детерминизм: тот же вход — те же байты
        assert_eq!(intent_id(&q, 3), intent_id(&qv(off), 3));
    }
}
