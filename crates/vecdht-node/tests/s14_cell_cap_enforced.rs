//! Оракул `H-0088`/`E-0088` — релиз-блокер (2) из `ADR-0044`: per-cluster cap работает.
//!
//! Спека v8 §14.4 (iv): «per-cluster admission cap реализован как локальная политика приёма
//! (`E-0088`, гейты (1), (3), (5), (7); `ADR-0044` решение 5)»; до `E-0088` здесь стояло
//! признание отсутствия. `E-0079` измерил цену этого
//! отсутствия (подмена чужой записи в горячий центроид = один PoW, 256,8× усиления скана), а
//! перебор 256 булевых форм оставил одну допустимую — 143 = `partM`: **проверять кап только при
//! смене ячейки**. Владелец (`ADR-0044`, решение 5) выбрал реализацию как *вытеснение по дешёвому
//! PoW*, а не отказ приёму, и потребовал, чтобы число капа было параметром, а не константой.
//!
//! Границы этого оракула важнее его зелёного цвета:
//!
//! * здесь **нет** нового wire-поля и нет изменения `pow_input`: узел по-прежнему принимает
//!   `cluster_id` издателя как факт (`node.rs:806` до фикса и после), а перевыбор горячей ячейки
//!   по-прежнему не стоит новой работы. Это предмет отдельного цикла, не этого;
//! * кап — локальная политика приёма (§11.3): его решения не попадают в WAL и не реплицируются,
//!   поэтому две копии шарда могут иметь разное *решение* и обязаны иметь одинаковый *индекс* —
//!   отсюда проверка `total` и числа вытеснений, а не состава;
//! * это **не** Sybil-защита: у атакующего с бесплатными ключами и уплаченным PoW всегда есть
//!   право занять место самой дешёвой записи ячейки. Цена для него — PoW, цена для сети —
//!   вытесненные легитимные дешёвые записи (`ADR-0044` называет это прямо).
//!
//! Форма предела относительная — `max(пол, ⌈c·m/n⌉)`, где `c = 2` взят из §8.6 («cap 2× среднего»),
//! `n = CLUSTERS_PER_SHARD` (`L-0001`, [arXiv:1608.01350](https://arxiv.org/abs/1608.01350)).
//! Пол = самая длинная ячейка, чью цену измеряли мы: `E-0079`/`E-0081` дают 0,05542…0,059815 мкс
//! на запись скана и живой `Find` 1534…1547 мкс при 4096 записях против бюджета §12.6 (≤ 50 мс).
//! Тест (5) проверяет, что выше пола связан именно средний, а не константа.
//!
//! Единица цены — **переезд** (вытеснение по капу), а не отказ: этого требует `L-0001`. Время
//! здесь не единица: тест (6) гейтится счётчиком обходов арены, а медианы только печатаются
//! (правило 7 (д) — отношение запаса к межпрогонному разбросу на publish меньше 10).

use std::time::Instant;

use vecdht_crypto::{intent_id, pow_input, Identity};
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Clock, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, ProtocolError, Publish};
use vecdht_wire::TIME_BUCKET_SEC;
use vecdht_wire::{domain, Kind};

const SHARD: u16 = 7;
/// Первый кластер шарда: `shard_of_cluster` делит на 16, «удобный» ноль скрыл бы ошибку маршрута.
const BASE: u16 = SHARD * 16;
const NEIGHBOUR: u16 = BASE + 1;
const SEEDS: [u8; 3] = [1, 2, 3];
/// Дешёвый PoW (тот же, что у `E-0079`): кап не про стоимость майнинга, а про порядок ячеек.
const POW: u32 = 8;
const TTL: u16 = 225;
/// Пол капа из продукта (`admission::CELL_CAP_MIN`). Здесь он зафиксирован как **предсказание**:
/// если продукт изменит пол, тест (1) упадёт, и падение будет фактом, а не правкой порога.
const FLOOR: u64 = 4_096;
/// Стартовая секунда наполнения: бакет 1000 нужен затем, чтобы у теста был «более старый» бакет
/// (отказ по цене §11.3.3 меряется кадром с `published_bucket` ниже всех в ячейке).
const SEC0: u64 = 16_000;
/// Сколько кадров на одну секунду часов: вдвое меньше узлового бюджета (§11.3.4 = 100/с), чтобы
/// отказ приёма никогда не подменял измеряемый кап.
const FRAMES_PER_SEC: u64 = 50;

fn params() -> Params {
    let mut p = testing::params(POW);
    // Lease выдаётся при genesis на бакете 0 и живёт `lease_buckets` (= 90 с / 16 = 5 бакетов),
    // а наполнение ячейки до 4096 идёт бакетами ~1000 — без этого узел отвечал бы `EPOCH_STALE`
    // и кап не проверялся бы вовсе. Срок lease здесь — не предмет теста: мы меряем *приём*,
    // а не выбор primary, поэтому lease удлиняется, а не воспроизводится по-боевому.
    p.lease_buckets = 1_000_000;
    p
}

/// Каталог, который удаляется при выходе из области видимости, а не последней строкой тела
/// теста. Это не косметика: прогон PRE_FIX (дерево без правки) паникует в трёх таргетах из пяти,
/// и ручной `remove(&d)` в конце тела оставил 14 каталогов на 61 МБ — тот же дефект метода, что
/// `E-0085` ДИАГНОЗ-2 (13 осевших каталогов), воспроизведённый здесь намеренно, чтобы проверить
/// порог (8) helper'а.
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

/// Семя владельца №`i`, которого нет среди авторитетов и холдеров: ключ выводится из него
/// `Identity::from_seed`, первый байт семени `200`, остальные — индекс.
fn owner(i: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = 200;
    seed[24..].copy_from_slice(&i.to_le_bytes());
    seed
}

/// Публичный ключ владельца с семенем `seed` — то, что `on_frame` видит как адрес.
fn key(seed: &[u8; 32]) -> [u8; 32] {
    Identity::from_seed(*seed).pubkey()
}

fn bucket_of(sec: u64) -> u32 {
    (sec / u64::from(TIME_BUCKET_SEC)) as u32
}

/// Подписанный `Publish` от владельца с семенем `owner_seed` в `cluster` с ценой `bits`.
///
/// Подпись в `Publish` обязательна (`H-0164`), поэтому владелец — пара `Identity`, а не
/// произвольные байты: ключ выводится из семени, и кадр подписывается им же. Семена берутся из
/// счётчика, а не из 256 сидов `testing::identity`, то есть ячейка наполняется до 4096 и выше
/// живым путём узла, а не прямым вызовом индекса.
fn frame(owner_seed: &[u8; 32], vec_seed: u8, cluster: u16, bucket: u32, bits: u32) -> Vec<u8> {
    let id = Identity::from_seed(*owner_seed);
    let owner_key = id.pubkey();
    let vec_q = testing::vector(vec_seed);
    let intent = intent_id(&vec_q, testing::PREPROCESSING_VERSION);
    let expires = bucket + u32::from(TTL);
    let input = pow_input(&owner_key, SHARD, 1, &intent, expires);
    let msg = Publish {
        preprocessing_version: testing::PREPROCESSING_VERSION,
        cluster_id: cluster,
        vec_q,
        owner_ed25519: owner_key,
        ttl_buckets: TTL,
        published_bucket: bucket,
        pow_bits: bits as u8,
        pow_nonce: testing::mine(&input, bits),
        intent_id: intent,
        tlv: Vec::new(),
    };
    let sig = id.sign_body(domain::PUBLISH, Kind::Publish, &msg.body_bytes());
    msg.encode_signed(&sig)
}

/// Наполнение ячейки живым путём: каждый кадр — новый ключ, секунда растёт каждые
/// `FRAMES_PER_SEC` кадров (узловой бюджет 100 admits/с, §11.3.4, не должен подменять
/// измеряемый лимит).
///
/// Нумерация владельцев продолжается от фактической длины шарда, поэтому один и тот же узел может
/// наполнять несколько ячеек без коллизий ключей.
///
/// Каждый кадр обязан быть принят, и это проверяется: прогон, где `fill()` тихо ловил
/// `EPOCH_STALE` на всех 4096 кадрах, дал бы ноль вытеснений и «зелёный» кап вместо теста
/// (ДИАГНОЗ пре-регистрации — `assert` приёма стоит до порога, а не после).
fn fill(n: &mut ShardNode, cell: u16, count: u64, bits: u32, sec: u64) -> u64 {
    let start = n.store.len() as u64;
    for i in 0..count {
        let at = sec + i / FRAMES_PER_SEC;
        let bucket = bucket_of(at);
        let k = owner(start + i);
        let replies = n
            .on_frame(key(&k), &frame(&k, 1, cell, bucket, bits), Clock::at(at))
            .expect("publish живым путём");
        let err = error_to(&replies, key(&k));
        assert!(
            err.is_none(),
            "кадр наполнения #{i} (ячейка {cell}, сек {at}, бакет {bucket}) отвергнут: {:?} — кап не измеряется, пока наполнение не принято",
            err.map(|e| e.code)
        );
    }
    sec + count / FRAMES_PER_SEC + 1
}

/// (1) + (4) + (6) — основной гейт: кап связывает там, где вместимость шарда нет; дешёвому
/// новичку в полной ячейке отказывают; решение стоит O(резервуар).
#[test]
fn the_cell_cap_binds_far_below_the_shard_capacity() {
    let mut p = params();
    p.max_live_per_shard = 2_000_000;
    let (mut n, _d) = primary_on("cap-floor", p);

    let sec = fill(&mut n, BASE, FLOOR, POW, SEC0);
    assert_eq!(n.store.index.cluster_len(BASE) as u64, FLOOR, "ячейка не долилась до пола");
    assert_eq!(
        n.store.len() as u64,
        FLOOR,
        "пол ячейки обязан наступить раньше вместимости шарда"
    );
    assert_eq!(n.evictor.evicted, 0, "до капа вытеснений быть не может");
    assert_eq!(n.evictor.scanned, 0, "пока кап не связан, арена не обходится вовсе");
    assert_eq!(n.store.index.cluster_len(NEIGHBOUR), 0, "флуд шёл ровно в одну ячейку");

    // Кадр №4097 дороже всех в ячейке ⇒ вытеснение самого дешёвого её обитателя, а не рост.
    let bucket = bucket_of(sec);
    let k = owner(900_000);
    let started = Instant::now();
    let replies = n
        .on_frame(key(&k), &frame(&k, 1, BASE, bucket, POW + 1), Clock::at(sec))
        .expect("publish");
    let over_cap_us = started.elapsed().as_micros() as u64;
    assert!(error_to(&replies, key(&k)).is_none(), "новичок дороже обитателей — его обязаны принять");
    assert_eq!(n.store.index.cluster_len(BASE) as u64, FLOOR, "кап пропущен: ячейка выросла");
    assert_eq!(n.store.len() as u64, FLOOR, "total не обязан меняться при вытеснении по капу");
    assert_eq!(n.evictor.evicted, 1, "ровно одно вытеснение на один cap-связанный кадр");
    assert_eq!(n.evictor.scanned, 0, "решение о капе стоит O(резервуар), а не O(M)");
    assert_eq!(n.store.index.cluster_len(NEIGHBOUR), 0, "чужая ячейка не тронута");
    let victim_cell = n.store.index.cluster_len(BASE) as u64;
    assert_eq!(victim_cell, FLOOR, "вытеснение обязано освободить место в той же ячейке");

    // Кадр, который дешевле всех в ячейке (те же биты, более старый бакет ⇒ §11.3.3 запрещает
    // вытеснять дороже принятой) ⇒ отказ существующим coarse-кодом, ничего не меняется.
    let k2 = owner(900_001);
    let replies2 = n
        .on_frame(key(&k2), &frame(&k2, 1, BASE, bucket_of(SEC0) - 100, POW), Clock::at(sec))
        .expect("publish");
    let err = error_to(&replies2, k2).expect("дешевле всех в ячейке — отказ");
    assert_eq!(err.code, err_code::SHARD_FULL, "наружу только существующий код (`ADR-0044` (3))");
    assert_eq!(n.store.index.cluster_len(BASE) as u64, FLOOR, "отказ не должен ничего менять");
    assert_eq!(n.evictor.evicted, 1, "отказ не вытесняет");
    assert_eq!(n.store.len() as u64, FLOOR, "отказ не занимает slot");
    // Снимок до тайминг-цикла: `g1_total` обязан быть числом состояния на cap-ветке, а не суммой
    // с 20 последующими publish'ами в соседнюю ячейку.
    let (total_at_cap, evicted_at_cap, cell_at_cap) = (
        n.store.len() as u64,
        n.evictor.evicted,
        n.store.index.cluster_len(BASE) as u64,
    );

    // Медиана обычного приёма в том же прогоне — только печатью (правило 7 (д)).
    let mut plain = Vec::new();
    for i in 0..20u64 {
        let kk = owner(1_000_000 + i);
        let t = Instant::now();
        n.on_frame(key(&kk), &frame(&kk, 1, NEIGHBOUR, bucket, POW), Clock::at(sec))
            .expect("publish в пустую ячейку");
        plain.push(t.elapsed().as_micros() as u64);
    }
    plain.sort();
    eprintln!(
        "## (1) пол капа: g1_cell={cell_at_cap} g1_total={total_at_cap} g1_evicted={evicted_at_cap} \
         g1_scanned={} g1_refused_code={} g1_neighbour={} \
         g1_cap_us={over_cap_us} g1_plain_med_us={} ##",
        n.evictor.scanned,
        err.code,
        n.store.index.cluster_len(NEIGHBOUR),
        plain[plain.len() / 2]
    );
    // Каталог снимается Drop'ом `Tmp` при выходе из функции — см. его документацию.
}

/// (2) Продление в своей полной ячейке проходит и не вытесняет никого — строгая форма (15)
/// ломала ровно это, и `E-0079` отверг её за нарушение §11.3.2.
#[test]
fn renewal_in_a_full_cell_never_costs_a_record() {
    let (mut n, _d) = primary_on("cap-renew", params());
    let sec = fill(&mut n, BASE, FLOOR, POW, SEC0);
    let bucket = bucket_of(sec);

    let first = owner(0);
    for i in 0..25u64 {
        let replies = n
            .on_frame(key(&first), &frame(&first, 1, BASE, bucket, POW), Clock::at(sec + i))
            .expect("перепубликация");
        assert!(
            error_to(&replies, key(&first)).is_none(),
            "продление в своей полной ячейке отвергнуто (i={i}) — это форма 15, а не 143"
        );
    }
    assert_eq!(n.store.index.cluster_len(BASE) as u64, FLOOR, "продление не меняет размер ячейки");
    assert_eq!(n.evictor.evicted, 0, "продление не вытесняет");
    assert_eq!(n.store.len() as u64, FLOOR, "продление не занимает новый slot (§11.3.2)");
    eprintln!("## (2) продление в полной ячейке: 25 кадров, evicted=0, cell={FLOOR} ##");
    eprintln!(
        "MERE g2_frames=25 g2_evicted={} g2_cell={} g2_total={}",
        n.evictor.evicted,
        n.store.index.cluster_len(BASE),
        n.store.len()
    );
    // Каталог снимается Drop'ом `Tmp` при выходе из функции — см. его документацию.
}

/// (3) Переезд в полную ячейку не бесплатен: льгота (207) пропускала его, и кап пробивался
/// чужими записями без единой новой оплаты.
#[test]
fn migrating_into_a_full_cell_is_capped() {
    let (mut n, _d) = primary_on("cap-mig", params());
    let sec = fill(&mut n, BASE, FLOOR, POW, SEC0);
    let bucket = bucket_of(sec);
    let k = owner(FLOOR);
    let replies = n
        .on_frame(key(&k), &frame(&k, 2, NEIGHBOUR, bucket, POW), Clock::at(sec))
        .expect("publish в соседнюю ячейку");
    assert!(
        error_to(&replies, key(&k)).is_none(),
        "первичный publish в соседнюю ячейку отвергнут: {:?} — сценарий не собрался",
        error_to(&replies, key(&k)).map(|e| e.code)
    );
    assert_eq!(n.store.index.cluster_len(NEIGHBOUR), 1);
    let total = n.store.len() as u64;

    // Тот же ключ и тот же вектор, другая ячейка: до фикса это был рост горячей ячейки сверх
    // предела и ноль новой работы сверх уплаченной.
    let replies = n
        .on_frame(key(&k), &frame(&k, 2, BASE, bucket + 1, POW + 1), Clock::at(sec + 1))
        .expect("переезд");
    let refused = error_to(&replies, key(&k)).map(|e| e.code);
    let cell = n.store.index.cluster_len(BASE) as u64;
    let moved = n.store.index.cluster_len(NEIGHBOUR) == 0;
    let evicted = n.evictor.evicted;
    let after = n.store.len() as u64;
    assert!(cell <= FLOOR, "переезд пробил кап: cell={cell} > {FLOOR}");
    assert!(refused.is_some() || moved, "переезд не связан капом и не вытеснил никого");
    // Единственный законный способ вырасти/сжаться здесь — вытеснение: переезд переносит запись
    // (её слот переиспользуется), а кап забирает ровно одного обитателя полной ячейки.
    assert_eq!(
        after + evicted,
        total,
        "переезд изменил шард не на число вытеснений: total {total}→{after}, evicted={evicted}"
    );
    eprintln!(
        "## (3) переезд в полную ячейку: cell={cell}, соседняя={}, отказ={refused:?}, evicted={evicted}, total {total}→{} ##",
        n.store.index.cluster_len(NEIGHBOUR),
        n.store.len()
    );
    eprintln!(
        "MERE g3_cell={cell} g3_neighbour={} g3_refused={} g3_evicted={evicted} \
         g3_total_before={total} g3_total_after={after}",
        n.store.index.cluster_len(NEIGHBOUR),
        refused.clone().unwrap_or_else(|| "NONE".to_string())
    );
    // Каталог снимается Drop'ом `Tmp` при выходе из функции — см. его документацию.
}

/// (5) Выше пола связан средний, а не константа.
///
/// Фиксированная точка относительного предела: при `A = 2000` в остальных пятнадцати ячейках
/// live = `15A + cell`, а предел = `⌈live/8⌉`, откуда `cell = ⌈(30000+cell)/8⌉` даёт 4286 —
/// и это **больше** пола 4096. Значит если бы продукт держал константу (пол), ячейка встала бы
/// на 4096 и `fill()` упал бы на первом же непринятом кадре наполнения, а не прошёл бы тихонько:
/// именно так гейт отличает относительный кап от ручной настройки под размер корпуса (`L-0001`).
///
/// Что здесь наблюдается, а не гейтится: *ветка* исхода (вытеснение или отказ) при большом
/// live. Резервуар цен держит 64 самых дешёвых записей **шарда**, а не ячейки, поэтому в
/// разросшемся шарде обитатели горячей ячейки могут в него не попадать — тогда кап достигается
/// отказом. Инвариант «ячейка не выше предела» обязан держаться в обеих ветках, и именно он
/// здесь порог; ветка печатается числом.
#[test]
fn above_the_floor_the_cap_is_the_mean_and_not_a_constant() {
    const OTHERS: u64 = 2_000;
    /// Предсказание: `cell` такое, что `8·cell ≥ 15·OTHERS + cell` и `8·(cell−1) < 15·OTHERS + cell−1`.
    const AT_LIMIT: u64 = 4_286;
    let (mut n, _d) = primary_on("cap-relative", params());
    let mut sec = SEC0;
    for c in 1..16u16 {
        sec = fill(&mut n, BASE + c, OTHERS, POW, sec);
    }
    let live_before = n.store.len() as u64;
    assert_eq!(live_before, 15 * OTHERS, "наполнение остальных ячеек не долилось");
    let limit_at_full = (2 * (live_before + AT_LIMIT)).div_ceil(16);
    assert!(
        limit_at_full == AT_LIMIT && AT_LIMIT > FLOOR,
        "фиксированная точка не совпала с предсказанием: limit={limit_at_full}, cell={AT_LIMIT}"
    );

    // Догоняем первую ячейку до предела: ниже предела рост обязан быть свободным.
    sec = fill(&mut n, BASE, AT_LIMIT, POW, sec);
    let live = n.store.len() as u64;
    let limit = (2 * live).div_ceil(16);
    assert!(live > 32_768, "шард не вышел за порог относительной ветки: live={live}");
    assert_eq!(
        n.store.index.cluster_len(BASE) as u64,
        AT_LIMIT,
        "ячейка встала раньше относительного предела: live={live}, limit={limit}"
    );

    // Один кадр сверх предела: кап обязан не пустить рост — вытеснением или отказом.
    let before = n.evictor.evicted;
    let k = owner(5_000_000);
    let replies = n
        .on_frame(key(&k), &frame(&k, 1, BASE, bucket_of(sec), POW + 1), Clock::at(sec))
        .expect("publish");
    let refused = error_to(&replies, key(&k)).map(|e| e.code);
    let cell = n.store.index.cluster_len(BASE) as u64;
    assert_eq!(
        cell, limit,
        "кап выше пола не связан: live={live}, limit={limit}, cell={cell}"
    );
    assert_eq!(
        refused.is_some() as u64 + (n.evictor.evicted - before),
        1,
        "cap-связанный кадр обязан либо вытеснить ровно одного, либо быть отвергнутым"
    );
    eprintln!(
        "## (5) относительный кап: live {live_before}→{live}, предел={limit} (пол {FLOOR}), \
         cell={AT_LIMIT}, ветка = {} (evicted {}→{}), scanned={} ##",
        if refused.is_some() { "отказ" } else { "вытеснение" },
        before,
        n.evictor.evicted,
        n.evictor.scanned
    );
    eprintln!(
        "MERE g5_live_before={live_before} g5_live={live} g5_limit={limit} g5_cell={cell} \
         g5_branch={} g5_refused={} g5_evicted={} g5_scanned={}",
        if refused.is_some() { "refuse" } else { "move" },
        refused.clone().unwrap_or_else(|| "NONE".to_string()),
        n.evictor.evicted,
        n.evictor.scanned
    );
    // Каталог снимается Drop'ом `Tmp` при выходе из функции — см. его документацию.
}

/// (7) Оба лимита сразу: вместимость шарда и кап ячейки дают ровно одно вытеснение на кадр,
/// а не два, и `total` не растёт — кап не должен удваивать цену приёма.
#[test]
fn shard_cap_and_cell_cap_together_evict_exactly_once() {
    let mut p = params();
    p.max_live_per_shard = FLOOR;
    let (mut n, _d) = primary_on("cap-both", p);
    let sec = fill(&mut n, BASE, FLOOR, POW, SEC0);
    assert_eq!(n.evictor.evicted, 0, "ровно до лимита вытеснений нет");
    let k = owner(777_777);
    n.on_frame(key(&k), &frame(&k, 1, BASE, bucket_of(sec), POW + 1), Clock::at(sec))
        .expect("publish");
    assert_eq!(n.store.len() as u64, FLOOR, "total не растёт при двух связанных лимитах");
    assert_eq!(n.evictor.evicted, 1, "двойное вытеснение: кап и вместимость посчитали одного");
    eprintln!("## (7) max_live=пол: total={}, evicted={} ##", n.store.len(), n.evictor.evicted);
    eprintln!(
        "MERE g7_total={} g7_cell={} g7_evicted={} g7_scanned={}",
        n.store.len(),
        n.store.index.cluster_len(BASE),
        n.evictor.evicted,
        n.evictor.scanned
    );
    // Каталог снимается Drop'ом `Tmp` при выходе из функции — см. его документацию.
}
