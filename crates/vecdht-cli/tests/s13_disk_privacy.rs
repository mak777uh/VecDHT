//! Оракул `H-0108`/`E-0108`: аудит «что реально пишется на диск» (§13.1, условие 5 v1).
//!
//! Спека §13.1 обещает: индекс-узел хранит квантованное представление (384 байта int8 плюс
//! метаданные, 424 Б на запись) «без исходного текста, без отображения вектор→текст, без
//! идентификатора автора помимо его публичного ключа». `ADR-0044` (Batch C, приватностный слой)
//! требует, чтобы это было «оформлено тестом», а не абзацем. До этого цикла теста не было:
//! `grep` по `crates/*/tests` на `f32`/«ни текста»/`on_disk` не даёт ничего.
//!
//! ## Что прибор доказывает, а что нет
//!
//! Доказываемое — по корпусу байт, которые узел сам положил в свой каталог:
//!
//! * (1) **текста нет.** Зонд — исходный текст объявления, `model_version` и ASCII-токен из
//!   текста. Текст не просто «не поле типа»: один `Publish` несёт его в `tlv` (§5.3 — поле
//!   зарезервировано, узел его не читает), второй приходит кадром `IntentTextResponse`, который
//!   узел обязан проигнорировать (§12.4). Оба зонда обязаны не оставить следов на диске.
//! * (2) **f32/f64 нет.** Зонд — блоки байтов тех самых float-векторов, из которых получены
//!   int8-коды: raw `f32` (по 4 координаты), raw `f64` и нормализованный `f64` (тот, что
//!   квантовщик получает перед сеткой Δ=1/127). Если бы индекс хранил float-рефайн (§13.1
//!   называет это соблазном, из-за которого v7.5 и солгала), эти последовательности стояли бы
//!   в WAL или снапшоте.
//! * (3) ** positives: корпус настоящий.** int8-коды записей и публичные ключи владельцев на
//!   диске найдены, записей ровно столько, сколько опубликовано, после reopen коды совпадают
//!   побайтно. Пустой каталог дал бы «чисто» по всем зондам — эти четыре факта не дают так
//!   считать.
//! * (4) **широкий аудит.** Регистратор «пробега» из ≥`TEXTLIKE_MIN` подряд идущих ASCII-букв —
//!   то, что человек мог бы написать. Он не подменняет зонды (короткое слово он не увидит), но
//!   показывает, что в каталоге узла нет ничего письмо-подобного. У него есть названная ложная
//!   тревога, найденная этим же прогоном: монотонная лесенка int8 проходит через диапазоны
//!   ASCII-букв и даёт ~3·10³ «пробегов» в `centroid.bin` эталонного артефакта, где текста нет.
//!   Поэтому регистратор гейтит только каталог узла, а артефакт проверяется известными зондами и
//!   структурой (шаг 5).
//! * (5) **прибор не слеп.** Посадка: в копию корпуса кладутся файл с текстом и файлы с тремя
//!   float-зондами; детекторы обязаны сработать по каждому. Это и есть PRE_FIX-класс проверки
//!   для аудита байтов: мы не мутируем продукт (cargo-mutants вне CI по `L-0026`), мы сажаем
//!   дефект в сам носитель и требуем, чтобы сканер его нашёл.
//!
//! Границы, которые прибор НЕ закрывает, названы в карточке и здесь: «нет f32» — это отсутствие
//! известных float-последовательностей и int8-layout'а по построению (`INDEX_ENTRY_BYTES`), а не
//! доказательство, что никакие 4 байта корпуса не являются f32 (произвольные байты недоказуемы);
//! каталог артефакта сканируется отдельно, потому что `manifest.json` — JSON по замыслу (§15.1),
//! и это единственный файл с текстом, который объявлен; denylist/revocation проверяются здесь
//! только по байтам, их семантика — `E-0092`/`E-0094`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use vecdht_artifact::{reference_artifact, reference_centroids};
use vecdht_crypto::quant::{DIM, l2_normalize};
use vecdht_crypto::{intent_id, pow_input, Identity};
use vecdht_embed::model::{Pooled, quantize_pooled};
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::Addr;
use vecdht_node::{candidates, denylist, revocation, session, testing, Clock, Params, ShardNode};
use vecdht_wire::TIME_BUCKET_SEC;
use vecdht_wire::messages::{Codec, ProtocolError, Publish};
use vecdht_wire::{domain, Kind};

const SHARD: u16 = 7;
const BASE: u16 = SHARD * 16;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const TTL: u16 = 225;
const SEC0: u64 = 16_000;

/// Записей до снапшота и после него: и снапшот, и свежие WAL-сегменты обязаны попасть в корпус.
const BEFORE_SNAPSHOT: u64 = 3;
const AFTER_SNAPSHOT: u64 = 2;
const RECORDS: u64 = BEFORE_SNAPSHOT + AFTER_SNAPSHOT;

/// Тег зарезервированного TLV, под которым издатель пытается протащить текст (§5.3).
const TLV_SECRET_TAG: u16 = 0x0F00;

/// Нижний порог «письмо-подобного» пробега: только ASCII-буквы, длина ≥ 10. Десять выбрано не
/// «чтобы прошло», а по цене ложной тревоги: случайные i8-байты дают пробег такой длины с
/// вероятностью ~1,2·10⁻⁷ на позицию, а в корпусе их ~10⁴ — ложный ноль вероятнее, чем восемь.
const TEXTLIKE_MIN: usize = 10;

/// Исходный текст объявления. Специально содержит и кириллицу, и длинный ASCII-токен: первый
/// зонд ловит UTF-8-байты целиком, второй — то, что увидел бы регистратор пробега.
const SECRET_TEXT: &str =
    "ищу подрядчика на монтаж вышки, оплата 45000, связь podryadchikagent почтой";
/// ASCII-токен из текста — отдельный зонд: он же проходит как «пробег букв».
const SECRET_TOKEN: &str = "podryadchikagent";
/// Версия модели из `IntentTextResponse` (§6.6): текст в явном виде, обязан не долететь до диска.
const MODEL_VERSION: &str = "granite-audit-v8";

// ---------------------------------------------------------------- каркас

/// Каталог, удаляемый при выходе из области видимости (`E-0085`-ДИАГНОЗ-2: без гарда падающий
/// тест оставляет мусор, а мусор в `target` — это расход носителя, за который отвечает прибор).
struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

fn params() -> Params {
    let mut p = testing::params(POW);
    p.lease_buckets = 1_000_000;
    p
}

fn primary_on(name: &str, p: Params) -> (ShardNode, Tmp) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = Tmp(dir(name));
    let mut n = testing::node(&d.0, SHARD, seed, p, &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "писать умеет только primary эпизоды");
    (n, d)
}

/// Семя владельца №`i` с первым байтом `200` (авторитеты — из сидов, denylist/revocation — с
/// первым байтом `210`); ключ выводится из семени, поэтому находка ключа в корпусе однозначна.
fn owner(i: u64) -> Addr {
    owner_identity(i).pubkey()
}

fn owner_identity(i: u64) -> Identity {
    let mut seed = [0u8; 32];
    seed[0] = 200;
    seed[24..].copy_from_slice(&i.to_le_bytes());
    Identity::from_seed(seed)
}

fn bucket_of(sec: u64) -> u32 {
    (sec / u64::from(TIME_BUCKET_SEC)) as u32
}

// ---------------------------------------------------------------- зонды

/// Детерминированный float-вектор: целочисленный LCG, никаких `sin`/`exp` (§6.3 требует
/// платформенной независимости, а зонды обязаны воспроизводиться в обоих прогонах).
fn probe(seed: u64) -> Pooled {
    let mut s = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x1234_5678_9ABC_DEF0);
    let mut v = [0f32; DIM];
    for x in v.iter_mut() {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let hi = (s >> 11) as u32;
        *x = (hi as f32) / 2_097_152.0 - 1.0;
    }
    v
}

/// Блоки по 4 координаты `f32` (16 байт) без перекрытия: если вектор лежит на диске как float,
/// каждый блок лежит целиком.
fn f32_blocks(v: &Pooled) -> Vec<Vec<u8>> {
    v.chunks_exact(4)
        .map(|c| c.iter().flat_map(|x| x.to_le_bytes()).collect())
        .collect()
}

fn f64_blocks(v: &[f64; DIM]) -> Vec<Vec<u8>> {
    v.chunks_exact(4)
        .map(|c| c.iter().flat_map(|x| x.to_le_bytes()).collect())
        .collect()
}

/// Тот же вектор в f64 и нормализованный — тем же публичным `l2_normalize`, что стоит в шаге 6
/// контракта (§6.2): «если хранили float, то вот эти байты».
fn normalized(v: &Pooled) -> [f64; DIM] {
    let mut d = [0f64; DIM];
    for i in 0..DIM {
        d[i] = f64::from(v[i]);
    }
    l2_normalize(&mut d).expect("ненулевой вектор");
    d
}

struct Patterns {
    text: Vec<Vec<u8>>,
    f32raw: Vec<Vec<u8>>,
    f64raw: Vec<Vec<u8>>,
    f64norm: Vec<Vec<u8>>,
    codes: Vec<Vec<u8>>,
    owners: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------- сканер

fn occurrences(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

fn count_any(hay: &[u8], patterns: &[Vec<u8>]) -> usize {
    patterns.iter().map(|p| occurrences(hay, p)).sum()
}

fn any_fired(hay: &[u8], patterns: &[Vec<u8>]) -> bool {
    patterns.iter().any(|p| occurrences(hay, p) > 0)
}

/// Число пробегов из ≥`TEXTLIKE_MIN` подряд идущих ASCII-букв.
fn letter_runs(hay: &[u8]) -> usize {
    let mut runs = 0;
    let mut cur = 0usize;
    for &b in hay {
        if b.is_ascii_alphabetic() {
            cur += 1;
            if cur == TEXTLIKE_MIN {
                runs += 1;
            }
        } else {
            cur = 0;
        }
    }
    runs
}

/// Рекурсивно прочесть весь каталог: аудит ведётся по байтам носителя, а не по списку того, что
/// «мы умеем писать». Новый файл отсюда не спрячется.
fn read_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).expect("read_dir корпуса") {
            let p = e.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push((p.clone(), std::fs::read(&p).expect("read файла")));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

// ---------------------------------------------------------------- кадры

/// Подписанный `Publish` с явным `vec_q` и — для одного кадра — текстом в зарезервированном
/// TLV (§5.3: подпись `Publish` обязательна, `H-0164`).
fn frame_vec(
    owner_id: &Identity,
    vec_q: &[i8; DIM],
    bucket: u32,
    bits: u32,
    tlv: Vec<(u16, Vec<u8>)>,
) -> Vec<u8> {
    let owner_key = owner_id.pubkey();
    let intent = intent_id(vec_q, testing::PREPROCESSING_VERSION);
    let expires = bucket + u32::from(TTL);
    let input = pow_input(&owner_key, SHARD, 1, &intent, expires);
    let msg = Publish {
        preprocessing_version: testing::PREPROCESSING_VERSION,
        cluster_id: BASE,
        vec_q: *vec_q,
        owner_ed25519: owner_key,
        ttl_buckets: TTL,
        published_bucket: bucket,
        pow_bits: bits as u8,
        pow_nonce: testing::mine(&input, bits),
        intent_id: intent,
        tlv,
    };
    let sig = owner_id.sign_body(domain::PUBLISH, Kind::Publish, &msg.body_bytes());
    msg.encode_signed(&sig)
}

fn stored_codes(n: &ShardNode, key: &Addr) -> Option<[i8; DIM]> {
    n.store
        .index
        .owner_slot(key)
        .and_then(|s| n.store.index.entry(s))
        .map(|e| e.vec_q)
}

fn fact(key: &str, value: impl std::fmt::Display) {
    println!("{key}={value}");
}

// ---------------------------------------------------------------- тест

#[test]
fn disk_privacy_audit_scans_what_the_node_actually_writes() {
    // ---- 1. узел пишет всё, что умеет: записи, снапшот, свежие WAL, членство, denylist, отзыв.
    let (mut n, d) = primary_on("s13-node", params());
    let node_dir = d.0.clone();

    let probes: Vec<Pooled> = (1..=RECORDS).map(probe).collect();
    // int8-коды всех зондов считаются сразу: перестановка записей фактов не меняет, а вот
    // одинаковые векторы схлопнули бы корпус (dedup по владельцу) — проверяем это до публикаций.
    let codes: Vec<[i8; DIM]> = probes
        .iter()
        .map(|p| quantize_pooled(p).expect("квантование зонда"))
        .collect();
    for (i, c) in codes.iter().enumerate() {
        assert!(
            codes[..i].iter().all(|o| o != c),
            "зонды не различаются: корпус из {RECORDS} записей схлопнулся бы"
        );
    }
    for (i, c) in codes[..BEFORE_SNAPSHOT as usize].iter().enumerate() {
        let c = *c;
        let sec = SEC0 + (i as u64) * 7;
        // Текст протаскиваем в TLV первой записи: узел обязан его выбросить, а не сохранить кадр.
        let tlv: Vec<(u16, Vec<u8>)> = if i == 0 {
            vec![(TLV_SECRET_TAG, SECRET_TEXT.as_bytes().to_vec())]
        } else {
            Vec::new()
        };
        let id = owner_identity((i as u64) + 1);
        let key = id.pubkey();
        let replies = n
            .on_frame(
                key,
                &frame_vec(&id, &c, bucket_of(sec), POW, tlv),
                Clock::at(sec),
            )
            .expect("publish");
        let rejected = replies
            .iter()
            .find(|e| e.to == key)
            .and_then(|e| ProtocolError::decode(&e.frame).ok());
        assert!(
            rejected.is_none(),
            "публикация #{i} отвергнута: корпус пуст, и «чисто» ничего не значит"
        );
    }
    assert_eq!(n.store.len() as u64, BEFORE_SNAPSHOT, "до снапшота лежит {BEFORE_SNAPSHOT}");

    // Кадр с текстом, который узел обязан проигнорировать (§12.4): сначала убеждаемся, что сам
    // кадр текст несёт — иначе зонд пустой.
    let owner_id = testing::identity(11);
    let text_frame = session::sign_response(&owner_id, MODEL_VERSION, testing::PREPROCESSING_VERSION, SECRET_TEXT)
        .expect("подписанный ответ");
    let readback = session::verify_response(&text_frame, &owner_id.pubkey()).expect("проверка ответа");
    assert_eq!(readback.text, SECRET_TEXT, "кадр не несёт текст — зонд битый");
    let seen = n
        .on_frame(owner_id.pubkey(), &text_frame, Clock::at(SEC0 + 90))
        .expect("узел обязан принять кадр, который ему не по пути, и промолчать");
    fact("S13_TEXTFRAME_SEEN", u8::from(seen.is_empty()));

    n.store.flush_snapshot().expect("снапшот");

    for i in BEFORE_SNAPSHOT..RECORDS {
        let sec = SEC0 + i * 7;
        let id = owner_identity(i + 1);
        n.on_frame(
            id.pubkey(),
            &frame_vec(&id, &codes[i as usize], bucket_of(sec), POW, Vec::new()),
            Clock::at(sec),
        )
        .expect("publish после снапшота");
    }
    assert_eq!(n.store.len() as u64, RECORDS);

    // Denylist и отзыв живут в том же каталоге (§11.4, `E-0092`/`E-0094`): их байты тоже входят
    // в аудит. Первый байт `210` отличает их от ключей владельцев.
    let mut dl = BTreeSet::new();
    let mut rv = BTreeSet::new();
    for i in 0..4u64 {
        let mut k = [0u8; 32];
        k[0] = 210;
        k[31] = i as u8;
        dl.insert(k);
        let mut nonce = [0u8; 16];
        nonce[0] = 210;
        nonce[15] = i as u8;
        rv.insert(nonce);
    }
    denylist::save(&node_dir, &dl).expect("denylist");
    revocation::save(&node_dir, &rv).expect("revocation");
    let records_alive = n.store.len() as u64;
    let codes_last = stored_codes(&n, &owner(RECORDS)).expect("последняя запись видна узлу");
    drop(n);

    // ---- 2. reopen: то же состояние читается с диска побайтно (значит, representation ровно
    // int8-layout'а, а не float-приближение, из которого «точность не вернётся»).
    let reopened = testing::node(&node_dir, SHARD, 1, params(), &SEEDS);
    let reopen_codes = stored_codes(&reopened, &owner(RECORDS));
    let reopen_match = reopen_codes == Some(codes_last);
    fact("S13_REOPEN_RECORDS", reopened.store.len() as u64);
    fact("S13_REOPEN_MATCH", u8::from(reopen_match));
    drop(reopened);

    // ---- 3. паттерны зондов: текст, три вида float-блоков, int8-коды, ключи владельцев.
    let text_pats: Vec<Vec<u8>> = [
        SECRET_TEXT.as_bytes().to_vec(),
        SECRET_TOKEN.as_bytes().to_vec(),
        MODEL_VERSION.as_bytes().to_vec(),
    ]
    .to_vec();
    let mut f32_pats = Vec::new();
    let mut f64_pats = Vec::new();
    let mut f64n_pats = Vec::new();
    for pooled in probes.iter() {
        f32_pats.extend(f32_blocks(pooled));
        let raw: [f64; DIM] = {
            let mut a = [0f64; DIM];
            for i in 0..DIM {
                a[i] = f64::from(pooled[i]);
            }
            a
        };
        f64_pats.extend(f64_blocks(&raw));
        f64n_pats.extend(f64_blocks(&normalized(pooled)));
    }
    let pats = Patterns {
        text: text_pats.clone(),
        f32raw: f32_pats.clone(),
        f64raw: f64_pats.clone(),
        f64norm: f64n_pats.clone(),
        codes: codes.iter().map(|c| c.iter().map(|&x| x as u8).collect()).collect(),
        owners: (1..=RECORDS).map(|i| owner(i).to_vec()).collect(),
    };

    let files = read_tree(&node_dir);
    let bytes: usize = files.iter().map(|(_, b)| b.len()).sum();
    fact("S13_FILES_SCANNED", files.len());
    fact("S13_BYTES_SCANNED", bytes);
    fact("S13_CORPUS_GE_6", u8::from(files.len() >= 6));
    assert!(files.len() >= 6, "в каталоге узла меньше 6 файлов: снапшот, WAL, манифест, членство, denylist, отзыв");
    for (p, b) in &files {
        println!(
            "  файл {} ({} Б, письмо-пробегов={})",
            p.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
            b.len(),
            letter_runs(b)
        );
    }

    let secret_hits: usize = files.iter().map(|(_, b)| count_any(b, &pats.text)).sum();
    let f32_hits: usize = files.iter().map(|(_, b)| count_any(b, &pats.f32raw)).sum();
    let f64_hits: usize = files.iter().map(|(_, b)| count_any(b, &pats.f64raw)).sum();
    let f64n_hits: usize = files.iter().map(|(_, b)| count_any(b, &pats.f64norm)).sum();
    let runs: usize = files.iter().map(|(_, b)| letter_runs(b)).sum();
    let code_hits: usize = files.iter().map(|(_, b)| count_any(b, &pats.codes)).sum();
    let owner_hits: usize = files.iter().map(|(_, b)| count_any(b, &pats.owners)).sum();
    fact("S13_NODE_SECRET_HITS", secret_hits);
    fact("S13_NODE_F32_HITS", f32_hits);
    fact("S13_NODE_F64_HITS", f64_hits);
    fact("S13_NODE_F64N_HITS", f64n_hits);
    fact("S13_NODE_TEXTLIKE", runs);
    fact("S13_NODE_QCODE_HITS", code_hits);
    fact("S13_NODE_OWNER_HITS", owner_hits);
    fact("S13_NODE_RECORDS", records_alive);
    // Отдельно по классам: суммарный ноль не различил бы «текста нет» и «прибор не искал».
    let node_clean = u8::from(
        secret_hits == 0
            && f32_hits == 0
            && f64_hits == 0
            && f64n_hits == 0
            && runs == 0
            && code_hits >= RECORDS as usize
            && owner_hits >= RECORDS as usize
            && records_alive == RECORDS
            && reopen_match,
    );
    fact("S13_NODE_CLEAN", node_clean);

    // ---- 4. посадка: копия корпуса с подмешанным текстом и тремя float-файлами. Сканер обязан
    // поймать каждый класс, иначе «ноль находок» в пункте 3 — это молчание прибора.
    let decoy_dir = dir("s13-decoy");
    let dd = Tmp(decoy_dir.clone());
    std::fs::create_dir_all(dd.0.join("copy")).expect("create copy");
    for (p, b) in &files {
        std::fs::write(dd.0.join("copy").join(p.file_name().unwrap()), b).expect("копия файла");
    }
    std::fs::write(dd.0.join("copy").join("decoy_text.bin"), SECRET_TEXT.as_bytes()).expect("decoy text");
    std::fs::write(dd.0.join("copy").join("decoy_model.bin"), MODEL_VERSION.as_bytes()).expect("decoy model");
    let flat32: Vec<u8> = f32_pats.concat();
    let flat64: Vec<u8> = f64_pats.concat();
    let flat64n: Vec<u8> = f64n_pats.concat();
    std::fs::write(dd.0.join("copy").join("decoy_f32.bin"), &flat32).expect("decoy f32");
    std::fs::write(dd.0.join("copy").join("decoy_f64.bin"), &flat64).expect("decoy f64");
    std::fs::write(dd.0.join("copy").join("decoy_f64n.bin"), &flat64n).expect("decoy f64n");
    let dfiles = read_tree(&dd.0);
    let d_text = any_fired(&dfiles.iter().map(|(_, b)| b.as_slice()).collect::<Vec<_>>().concat(), &pats.text);
    let d_f32 = any_fired(&dfiles.iter().map(|(_, b)| b.as_slice()).collect::<Vec<_>>().concat(), &pats.f32raw);
    let d_f64 = any_fired(&dfiles.iter().map(|(_, b)| b.as_slice()).collect::<Vec<_>>().concat(), &pats.f64raw);
    let d_f64n = any_fired(&dfiles.iter().map(|(_, b)| b.as_slice()).collect::<Vec<_>>().concat(), &pats.f64norm);
    let d_runs = dfiles.iter().map(|(_, b)| letter_runs(b)).sum::<usize>();
    fact("S13_DECOY_TEXT_FIRED", u8::from(d_text));
    fact("S13_DECOY_F32_FIRED", u8::from(d_f32));
    fact("S13_DECOY_F64_FIRED", u8::from(d_f64));
    fact("S13_DECOY_F64N_FIRED", u8::from(d_f64n));
    fact("S13_DECOY_TEXTLIKE_FIRED", u8::from(d_runs > 0));
    let decoy_all = u8::from(d_text && d_f32 && d_f64 && d_f64n && d_runs > 0);
    fact("S13_DECOY_ALL_FIRED", decoy_all);
    drop(dd);

    // ---- 5. каталог артефакта: `centroid.bin` (int8-строки) и `manifest.json` (JSON по замыслу).
    // Сюда НЕ применяется регистратор пробегов как гейт: эталонные центроиды — монотонная лесенка
    // `((i % 255) − 127)`, и она проходит через диапазоны ASCII-букв, давая ~3·10³ «письмо-пробегов»
    // в файле, где текста нет. Это названная ложная тревога детектора (ДИАГНОЗ-1 цикла), а не находка
    // о приватности: здесь проверяются известные зонды и структура файла.
    let art_dir = dir("s13-artifact");
    let ad = Tmp(art_dir.clone());
    reference_artifact().save(&ad.0).expect("записать артефакт");
    let afiles = read_tree(&ad.0);
    let mut art_json_files = 0usize;
    let mut json_runs = 0usize;
    let mut centroid_runs = 0usize;
    let mut art_secret = 0usize;
    let mut art_float = 0usize;
    let mut centroid_is_fixture = false;
    for (p, b) in &afiles {
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("?").to_string();
        let r = letter_runs(b);
        println!("  артефакт {name}: {} Б, письмо-пробегов={r}", b.len());
        if name.ends_with(".json") {
            art_json_files += 1;
            json_runs += r;
        }
        if name.ends_with("centroid.bin") {
            centroid_runs += r;
            centroid_is_fixture = b.as_slice() == reference_centroids().as_bytes();
        }
        art_secret += count_any(b, &pats.text);
        art_float += count_any(b, &pats.f32raw)
            + count_any(b, &pats.f64raw)
            + count_any(b, &pats.f64norm);
    }
    fact("S13_ART_SECRET_HITS", art_secret);
    fact("S13_ART_FLOAT_HITS", art_float);
    fact("S13_ART_JSON_FILES", art_json_files);
    // Живой контроль регистратора: JSON артефакта — настоящий текст, и детектор обязан увидеть
    // его без всякой посадки (иначе «ноль пробегов» в каталоге узла ничего не значит).
    fact("S13_ART_JSON_RUNS", json_runs);
    fact("S13_CONTROL_TEXTLIKE_LIVE", u8::from(json_runs > 0));
    fact("S13_ART_CENTROID_IS_FIXTURE", u8::from(centroid_is_fixture));
    fact("S13_ART_CENTROID_RUNS", centroid_runs);
    fact(
        "S13_ART_CLEAN",
        u8::from(
            art_secret == 0
                && art_float == 0
                && art_json_files == 1
                && centroid_is_fixture
                && records_alive == RECORDS,
        ),
    );
    drop(ad);

    // Зонды float-векторов не должны были «случайно» оказаться int8-кодами: иначе ноль находок
    // означал бы, что искать нечего. Проверка на живом корпусе уже есть (QCODE/OWNER ≥ записей),
    // здесь — что паттернов много и они разные.
    assert!(f32_pats.len() as u64 >= RECORDS * (DIM as u64 / 4));
}
