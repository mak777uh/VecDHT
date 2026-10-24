//! Оракул `H-0102`/`E-0102` — хвост `H-0088b`: вытеснение внутри полной ячейки не должно
//! зависеть от шардового резервуара.
//!
//! `E-0088` измерил дыру исполнением: при `live = 34 286` кап уходит в **отказ** (`g5_branch=refuse`,
//! `evicted 0→0`, `scanned=0`), хотя в горячей ячейке лежат записи дешевле новичка. Причина —
//! `Evictor::cell_victim` смотрит только в глобальный резервуар 64 самых дешёвых **увиденных**
//! записей шарда; когда он заполнен дешёвыми записями чужих ячеек, у горячей ячейки жертвы нет
//! (`admission.rs`, абзац «Чего этот выбор не гарантирует»).
//!
//! Этот файл собран так, чтобы краснеть на базовом продукте, не трогая новых имён API: он
//! проверяет только поведение (отказ/приём, размер ячейки, число вытеснений). Сценарий маленький
//! по построению — кап задаётся параметром `cell_cap_min`, и 400 живых записей дают ту же форму,
//! что 34 286: резервуар наполнен дешёвыми записями **чужой** ячейки, а в целевой первые 256
//! записей дороже новичка, дешёвые лежат сразу за окном скана.
//!
//! Что здесь **не** проверяется и названо в карточке: записи, принятые другим узлом или до
//! рестарта, цены не имеют (`bits = 0`), и жертвой не становятся — отказ для них остаётся
//! осознанной ошибкой в безопасную сторону (§11.3.3), а не регрессией этого цикла.

use vecdht_crypto::{intent_id, pow_input};
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Clock, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, ProtocolError, Publish};
use vecdht_wire::TIME_BUCKET_SEC;

const SHARD: u16 = 7;
/// Ячейки шарда идут подряд: `shard_of_cluster` делит номер на 16.
const BASE: u16 = SHARD * 16;
const NEIGHBOUR: u16 = BASE + 1;
const EMPTY: u16 = BASE + 2;
const SEEDS: [u8; 3] = [1, 2, 3];
/// Минимум капа — параметр (`Params::cell_cap_min`), а не константа: сценарию хватает 300
/// записей, и это то же отношение «ячейка полна, резервуар занят чужой», что у 4096.
const CAP: u64 = 300;
const SEC0: u64 = 16_000;
/// Вдвое ниже узлового бюджета §11.3.4 (100/с), чтобы отказ приёма не подменял измеряемый кап.
const FRAMES_PER_SEC: u64 = 50;
/// Окно ограниченного скана — предсказание, а не импорт: если продукт изменит бюджет,
/// `s77b` упадёт фактом, а не подстроится.
const BUDGET: usize = 256;

fn params() -> Params {
    let mut p = testing::params(8);
    p.lease_buckets = 1_000_000;
    p.cell_cap_min = CAP;
    p.max_live_per_shard = 2_000_000;
    p
}

struct Tmp(std::path::PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

fn primary_on(dir_name: &str, p: Params) -> (ShardNode, Tmp) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = Tmp(dir(dir_name));
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

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

fn owner(i: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 200;
    k[24..].copy_from_slice(&i.to_le_bytes());
    k
}

fn bucket_of(sec: u64) -> u32 {
    (sec / u64::from(TIME_BUCKET_SEC)) as u32
}

fn frame(owner_key: &[u8; 32], vec_seed: u8, cluster: u16, bucket: u32, bits: u32) -> Vec<u8> {
    let vec_q = testing::vector(vec_seed);
    let intent = intent_id(&vec_q, testing::PREPROCESSING_VERSION);
    let expires = bucket + u32::from(225u16);
    let input = pow_input(owner_key, SHARD, 1, &intent, expires);
    Publish {
        preprocessing_version: testing::PREPROCESSING_VERSION,
        cluster_id: cluster,
        vec_q,
        owner_ed25519: *owner_key,
        ttl_buckets: 225,
        published_bucket: bucket,
        pow_bits: bits as u8,
        pow_nonce: testing::mine(&input, bits),
        intent_id: intent,
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

fn fill(n: &mut ShardNode, cell: u16, count: u64, bits: u32, sec: u64) -> u64 {
    let start = n.store.len() as u64;
    for i in 0..count {
        let at = sec + i / FRAMES_PER_SEC;
        let bucket = bucket_of(at);
        let k = owner(start + i);
        let replies = n
            .on_frame(k, &frame(&k, 1, cell, bucket, bits), Clock::at(at))
            .expect("publish живым путём");
        let err = error_to(&replies, k);
        assert!(
            err.is_none(),
            "кадр наполнения #{i} (ячейка {cell}, бакет {bucket}, bits {bits}) отвергнут: {:?}",
            err.map(|e| e.code)
        );
    }
    sec + count / FRAMES_PER_SEC + 1
}

/// Сценарий: чужая ячейка даёт 100 записей по 8 бит (они занимают весь глобальный резервуар),
/// целевая ячейка — 300 записей: первые 280 по 12 бит, последние 20 по 9. Новичок с 11 битами
/// дороже всех в окне `[0, 256)` и дешевле тех, что лежат за окном, — то есть первый заход обязан
/// отказать по §11.3.3, а второй (курсор сдвинулся) — вытеснить дешёвого обитателя.
fn scenario(tag: &str) -> (ShardNode, Tmp, u64) {
    let (mut n, d) = primary_on(tag, params());
    let mut sec = fill(&mut n, NEIGHBOUR, 100, 8, SEC0);
    sec = fill(&mut n, BASE, 280, 12, sec);
    sec = fill(&mut n, BASE, 20, 9, sec);
    assert_eq!(n.store.index.cluster_len(BASE) as u64, CAP, "ячейка не долилась до капа");
    assert_eq!(n.store.len() as u64, 400, "наполнение сцены не сошлось");
    (n, d, sec)
}

/// (1) Главный гейт: два захода в полную ячейку. На базовом продукте оба отказаны — тест красный
/// на второй проверке; после правки второй заход вытесняет дешёвого обитателя.
#[test]
fn a_full_cell_finds_a_cheaper_resident_outside_the_global_reservoir() {
    let (mut n, _d, sec) = scenario("cap-scan");
    let bucket = bucket_of(sec);
    let evicted0 = n.evictor.evicted;
    let scanned0 = n.evictor.scanned;

    let k = owner(900_000);
    let r = n
        .on_frame(k, &frame(&k, 1, BASE, bucket, 11), Clock::at(sec))
        .expect("publish");
    let first = error_to(&r, k).map(|e| e.code);
    assert_eq!(
        first.as_deref(),
        Some(err_code::SHARD_FULL),
        "окно [0, 256) содержит только 12-битные записи: новичок 11 бит дешевле всех — обязан быть отказ"
    );
    // Печать до второго захода: PRE_FIX падает на следующей проверке, и первый отказ обязан
    // остаться в замороженном логе фактом, а не выводом из номера строки паники.
    eprintln!(
        "S77_FIRST_REFUSED={} S77_FIRST_CODE={} S77_AFTER_FIRST_CELL={} \
         S77_AFTER_FIRST_TOTAL={} S77_AFTER_FIRST_EVICTED={}",
        u8::from(first.is_some()),
        first.clone().unwrap_or_else(|| "NONE".to_string()),
        n.store.index.cluster_len(BASE),
        n.store.len(),
        n.evictor.evicted
    );

    let k2 = owner(900_001);
    let r2 = n
        .on_frame(k2, &frame(&k2, 1, BASE, bucket, 11), Clock::at(sec))
        .expect("publish");
    let second = error_to(&r2, k2).map(|e| e.code);
    assert!(
        second.is_none(),
        "за окном скана лежат 9-битные записи дешевле новичка — кап обязан вытеснить одну, ответ: {second:?}"
    );
    eprintln!(
        "S77_SECOND_REFUSED={} S77_SECOND_CODE={}",
        u8::from(second.is_some()),
        second.clone().unwrap_or_else(|| "NONE".to_string())
    );
    assert_eq!(n.store.index.cluster_len(BASE) as u64, CAP, "вытеснение не сохранило кап");
    assert_eq!(n.store.len() as u64, 400, "вытеснение изменило размер шарда");
    assert_eq!(n.evictor.evicted, evicted0 + 1, "ровно одно вытеснение на один cap-кадр");
    assert_eq!(
        n.evictor.scanned, scanned0,
        "локальное окно не обходит глобальную арену: счётчик `scanned` не двигается"
    );
    let nines_left = (380..400u64)
        .filter(|i| n.store.index.owner_slot(&owner(*i)).is_some())
        .count();
    assert_eq!(nines_left, 19, "жертвой обязан стать дешёвый обитатель (9 бит), а не дорогой 12");
    // Печать состояния кап-ветки — до контрольного приёма в пустую ячейку: иначе `SHARD_TOTAL`
    // включал бы кадр, к капу не относящийся, и ключ перестал бы означать то, что назван.
    eprintln!(
        "S77_CELL={} S77_SHARD_TOTAL={} S77_EVICTED={} S77_GLOBAL_SCANNED={} S77_NINES_LEFT={nines_left}",
        n.store.index.cluster_len(BASE),
        n.store.len(),
        n.evictor.evicted,
        n.evictor.scanned
    );

    // (2) Новичок дешевле всех в ячейке: §11.3.3 запрещает вытеснять дороже принятой записи.
    let k3 = owner(900_002);
    let r3 = n
        .on_frame(k3, &frame(&k3, 1, BASE, bucket, 8), Clock::at(sec))
        .expect("publish");
    let cheap = error_to(&r3, k3).map(|e| e.code);
    assert_eq!(
        cheap.as_deref(),
        Some(err_code::SHARD_FULL),
        "8 бит дешевле любой записи ячейки — отказ, а не вытеснение дорогой"
    );
    assert_eq!(n.evictor.evicted, evicted0 + 1, "дешёвый отказ не вытесняет");
    assert_eq!(n.store.index.cluster_len(BASE) as u64, CAP, "дешёвый отказ не меняет ячейку");

    // (3) Контроль: кап не связан — локальный скан не запускается вовсе.
    let before = n.evictor.scanned;
    let k4 = owner(900_003);
    let r4 = n
        .on_frame(k4, &frame(&k4, 1, EMPTY, bucket, 10), Clock::at(sec))
        .expect("publish");
    assert!(error_to(&r4, k4).is_none(), "приём в пустую ячейку отвергнут: сцена не собралась");
    assert_eq!(n.evictor.scanned, before, "при свободном капе арена не обходится");
    assert_eq!(n.evictor.evicted, evicted0 + 1, "приём без капа не вытесняет");

    eprintln!(
        "S77_CHEAP_REFUSED={} S77_CHEAP_CODE={} S77_CHEAP_EVICTED={} \
         S77_CONTROL_SCANNED_DELTA={} S77_CONTROL_EVICTED_DELTA={}",
        u8::from(cheap.is_some()),
        cheap.clone().unwrap_or_else(|| "NONE".to_string()),
        n.evictor.evicted,
        n.evictor.scanned - before,
        n.evictor.evicted - (evicted0 + 1)
    );
    eprintln!("S77_BUDGET={BUDGET} S77_CAP={CAP}");
    // Каталог снимается Drop'ом `Tmp`.
}

/// (3) Продление и переезд прежним путём не затронуты: кап проверяется только на смене ячейки,
/// а продление в своей полной ячейке не вытесняет никого (§11.3.2). Контроль нужен затем, чтобы
/// «вытеснение появилось» не оказалось вытеснением на каждом кадре.
#[test]
fn renewal_stays_free_while_the_window_scan_is_opt_in() {
    let (mut n, _d, sec) = scenario("cap-renew-scan");
    let bucket = bucket_of(sec);
    let evicted0 = n.evictor.evicted;
    let first = owner(100);
    for i in 0..25u64 {
        let r = n
            .on_frame(first, &frame(&first, 1, BASE, bucket, 12), Clock::at(sec + i))
            .expect("перепубликация");
        assert!(error_to(&r, first).is_none(), "продление в своей ячейке отвергнуто (i={i})");
    }
    assert_eq!(n.evictor.evicted, evicted0, "продление не вытесняет");
    assert_eq!(n.store.index.cluster_len(BASE) as u64, CAP, "продление не меняет кап");
    eprintln!(
        "S77_RENEW_EVICTED={} S77_RENEW_CELL={} S77_RENEW_TOTAL={}",
        n.evictor.evicted,
        n.store.index.cluster_len(BASE),
        n.store.len()
    );
}
