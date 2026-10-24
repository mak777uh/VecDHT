//! Оракул `H-0103`/`E-0103`: узел пересчитывает `cluster_id` по своим центроидам (§7.3).
//!
//! Спека §7.3 говорит: «узел пересчитывает присваивание по `vec_q` и использует своё», а §7.2 —
//! что `cluster_id` — аргминимум целочисленного L2² по 1024 центроидам. Код до фикса принимал
//! `cluster_id` издателя как факт (`node.rs:806` до правки) и выбирал по нему ячейку индекса.
//! Это не «доверие подсказке» в вакууме: ячейка определяет, увидит ли запись зондирование её
//! шарда, и `E-0079` уже измерил, что переезд в горячую ячейку стоил один PoW.
//!
//! Что доказывает этот прибор и что нет:
//!
//! * (1) подделанный `cluster_id` больше не выбирает ячейку: запись с `vec_q`, присвоенным
//!   кластеру `BASE+5`, но заявленная в `BASE+7`, лежит в `BASE+5`;
//! * (2) пересчитанный кластер другого шарда отвергается `SHARD_MISMATCH`, а не принимается в
//!   чужой шард: принять значило бы спрятать запись от зондирования её собственного шарда;
//! * (3) честное присваивание не считается «пересборкой» и не платит счётчиком;
//! * (4) без центроидов поведение прежнее (fail-open), но каждый такой кадр считается
//!   `cluster_unverified` — развёртывание без артефакта наблюдаемо, а не молчаливо;
//! * (5) цена `assign` на publish-пути против бюджета §6.1 (< 0.3 мс) — p50, не p95: `E-0003`
//!   дал p50 0.108 / p99 0.215 мс для той же операции, и повторять p95 здесь значило бы мерить
//!   хост, а не код (правило 7 (д)).
//!
//! Границы: сетка центроидов синтетическая (две координаты кодируют номер кластера, остальные
//! нули) — она проверяет маршрутизацию и цену, а не качество настоящего `centroid.bin` (это
//! `E-0004`/`E-0090`). Wire не менялся: `cluster_id` остаётся в кадре как подсказка маршрута, и
//! его шардовая проверка идёт до пересчёта. `pow_input` не накрывает кластер — и не должен:
//! издатель платит за шард (§11.1), а ячейку выбирает геометрия вектора, а не заявление.

use std::sync::Arc;

use vecdht_artifact::Centroids;
use vecdht_crypto::quant::DIM;
use vecdht_crypto::{intent_id, pow_input};
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Clock, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, ProtocolError, Publish};
use vecdht_wire::TIME_BUCKET_SEC;

const SHARD: u16 = 7;
/// Первый кластер шарда: `shard_of_cluster` делит на 16, «удобный» ноль скрыл бы ошибку маршрута.
const BASE: u16 = SHARD * 16;
/// Куда вектор действительно присваивается.
const OWN: u16 = BASE + 5;
/// Что заявляет издатель: соседняя ячейка того же шарда.
const CLAIMED: u16 = BASE + 7;
/// Вектор, который присваивается уже другому шарду (`BASE + 20` при 16 кластерах на шард).
const CROSS: u16 = BASE + 20;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const TTL: u16 = 225;
/// Стартовая секунда: lease в `params()` удлинён, но бюджет приёма §11.3.4 — нет, поэтому каждый
/// кадр получает свою секунду.
const SEC0: u64 = 16_000;
/// Число кадров в ценовом цикле: 60 секунд укладываются в узловой бюджет 100 admits/с.
const PRICE_FRAMES: u64 = 60;
/// Бюджет `квантование + assign` из §6.1 — 0.3 мс; `assign` здесь только часть пары.
const ASSIGN_BUDGET_US: u64 = 300;

fn params() -> Params {
    let mut p = testing::params(POW);
    // Lease выдаётся при genesis на бакете 0 и живёт `lease_buckets`; кадры идут на секундах
    // ~16 000, поэтому срок удлиняется. Это не предмет теста: мы меряем приём, а не выбор primary.
    p.lease_buckets = 1_000_000;
    p
}

/// Каталог, который удаляется при выходе из области видимости: PRE_FIX-прогон падает в трёх
/// тестах из пяти, и ручной `remove` в конце тела оставил бы каталоги (ДИАГНОЗ `E-0085`-2).
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

/// Ключ владельца №`i`, которого нет среди авторитетов и холдеров: первый байт `200`.
fn owner(i: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 200;
    k[24..].copy_from_slice(&i.to_le_bytes());
    k
}

fn bucket_of(sec: u64) -> u32 {
    (sec / u64::from(TIME_BUCKET_SEC)) as u32
}

/// Строка центроида `c`: номер кластера в первых двух координатах, остальное — нули.
///
/// `c % 100` укладывается в −50…49, `c / 100` — в −5…10, поэтому все 1024 строки различны, а
/// `assign` строки `c` равен ровно `c` (дистанция 0) без tie-break. Никаких `sin`/`exp`: сетка
/// обязана быть платформенно-независимой (§6.3).
fn grid_row(c: u16) -> [i8; DIM] {
    let mut row = [0i8; DIM];
    row[0] = (c % 100) as i8 - 50;
    row[1] = (c / 100) as i8 - 5;
    row
}

fn all_centroids() -> Arc<Centroids> {
    let bytes: Vec<i8> = (0..1024u16).flat_map(grid_row).collect();
    let c = Centroids::from_i8(&bytes).expect("1024 строки по DIM");
    // Санитарная проверка сетки здесь, а не в пороге: если `assign` строки не равен её номеру,
    // все пять фактов ниже измеряют не то.
    for probe in [OWN, CLAIMED, CROSS] {
        assert_eq!(c.assign(&grid_row(probe)), probe, "сетка не различает кластеры");
    }
    Arc::new(c)
}

/// Неподписанный `Publish` с явным `vec_q`: подпись в `Publish` опциональна (§5.3), поэтому
/// владельцев можно брать из счётчика, а вектор — из строки синтетической сетки.
fn frame_vec(
    owner_key: &[u8; 32],
    vec_q: &[i8; DIM],
    cluster: u16,
    bucket: u32,
    bits: u32,
) -> Vec<u8> {
    let intent = intent_id(vec_q, testing::PREPROCESSING_VERSION);
    let expires = bucket + u32::from(TTL);
    let input = pow_input(owner_key, SHARD, 1, &intent, expires);
    Publish {
        preprocessing_version: testing::PREPROCESSING_VERSION,
        cluster_id: cluster,
        vec_q: *vec_q,
        owner_ed25519: *owner_key,
        ttl_buckets: TTL,
        published_bucket: bucket,
        pow_bits: bits as u8,
        pow_nonce: testing::mine(&input, bits),
        intent_id: intent,
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

fn cell_of(n: &ShardNode, key: &[u8; 32]) -> Option<u16> {
    n.store
        .index
        .owner_slot(key)
        .and_then(|s| n.store.index.entry(s))
        .map(|e| e.cluster_id)
}

fn publish(
    n: &mut ShardNode,
    key: [u8; 32],
    vec_q: &[i8; DIM],
    claimed: u16,
    sec: u64,
) -> Option<ProtocolError> {
    let bucket = bucket_of(sec);
    let replies = n
        .on_frame(key, &frame_vec(&key, vec_q, claimed, bucket, POW), Clock::at(sec))
        .expect("publish живым путём");
    error_to(&replies, key)
}

/// (1) Подделанный `cluster_id` не выбирает ячейку: запись лежит там, куда её присвоил `vec_q`.
#[test]
fn forged_cluster_id_does_not_choose_the_cell() {
    let (n, _d) = primary_on("c103-forged", params());
    let mut n = n.with_centroids(all_centroids());
    let k = owner(1);
    let err = publish(&mut n, k, &grid_row(OWN), CLAIMED, SEC0);
    assert!(err.is_none(), "честный PoW и шард — повода отказывать нет: {err:?}");
    assert_eq!(n.store.len(), 1, "запись обязана быть принята");
    assert_eq!(cell_of(&n, &k), Some(OWN), "ячейку выбрал заявленный cluster_id");
    assert_eq!(n.store.index.cluster_len(OWN), 1);
    assert_eq!(n.store.index.cluster_len(CLAIMED), 0, "заявленная ячейка не тронута");
    assert_eq!(
        n.admission.borrow().stats.cluster_reassigned, 1,
        "расхождение подсказки и пересчёта обязано быть видно"
    );
    eprintln!(
        "## C103_FORGED_ENTRY_CELL={OWN} C103_FORGED_CLAIMED_COUNT={} \
         C103_REASSIGNED={} ##",
        n.store.index.cluster_len(CLAIMED),
        n.admission.borrow().stats.cluster_reassigned
    );
}

/// (2) Пересчитанный кластер другого шарда отвергается: принять его значило бы спрятать запись
/// от зондирования собственного шарда (§8.4/§8.6), а не «быть терпимым к подсказке».
#[test]
fn cross_shard_recompute_is_refused() {
    let (n, _d) = primary_on("c103-cross", params());
    let mut n = n.with_centroids(all_centroids());
    let k = owner(2);
    let err = publish(&mut n, k, &grid_row(CROSS), OWN, SEC0);
    let err = err.expect("пересчёт в чужой шард обязан быть отказом");
    assert_eq!(err.code, err_code::SHARD_MISMATCH, "наружу существующий код, wire не менялся");
    assert_eq!(n.store.len(), 0, "отказ не занимает slot");
    assert_eq!(n.store.index.cluster_len(OWN), 0);
    assert_eq!(n.admission.borrow().stats.cluster_cross_shard, 1);
    eprintln!(
        "## C103_CROSS_SHARD_CODE={} C103_CROSS_SHARD={} C103_CROSS_SHARD_STORE={} ##",
        err.code,
        n.admission.borrow().stats.cluster_cross_shard,
        n.store.len()
    );
}

/// (3) Контроль прибора: честное присваивание принимается и не считается пересборкой.
#[test]
fn honest_assignment_is_not_a_reassignment() {
    let (n, _d) = primary_on("c103-honest", params());
    let mut n = n.with_centroids(all_centroids());
    let k = owner(3);
    let err = publish(&mut n, k, &grid_row(OWN), OWN, SEC0);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(cell_of(&n, &k), Some(OWN));
    assert_eq!(
        n.admission.borrow().stats.cluster_reassigned, 0,
        "счётчик обязан считать расхождение, а не каждый приём"
    );
    eprintln!("## C103_HONEST_ENTRY_CELL={OWN} C103_HONEST_REASSIGNED=0 ##");
}

/// (4) Без центроидов поведение прежнее (fail-open), но кадр посчитан: развёртывание без
/// артефакта наблюдаемо. Это граница цикла, а не обещание защиты.
#[test]
fn without_centroids_reuse_of_claim_is_observable() {
    let (mut n, _d) = primary_on("c103-nocentroids", params());
    let k = owner(4);
    let err = publish(&mut n, k, &grid_row(OWN), CLAIMED, SEC0);
    assert!(err.is_none(), "без артефакта узел ведёт себя как раньше: {err:?}");
    assert_eq!(cell_of(&n, &k), Some(CLAIMED), "fail-open: ячейка из подсказки");
    assert_eq!(
        n.admission.borrow().stats.cluster_unverified, 1,
        "молчание здесь было бы дырой развёртывания"
    );
    eprintln!(
        "## C103_NO_CENTROIDS_ENTRY_CELL={CLAIMED} C103_NO_CENTROIDS_UNVERIFIED={} ##",
        n.admission.borrow().stats.cluster_unverified
    );
}

/// (5) Цена пересчёта: `assign` на publish-пути против бюджета §6.1 (0.3 мс). Время здесь
/// вердикт только по абсолютному бюджету; разница «с центроидами / без» печатается, но
/// вердиктом не является (правило 7 (д): шум publish-пути на 60 кадрах).
#[test]
fn assign_price_stays_inside_the_budget() {
    let c = all_centroids();
    let probes: Vec<[i8; DIM]> = (0..PRICE_FRAMES as u16)
        .map(|i| grid_row(BASE + (i % 16)))
        .collect();
    let mut direct = Vec::new();
    for v in &probes {
        let t = std::time::Instant::now();
        std::hint::black_box(c.assign(std::hint::black_box(v)));
        direct.push(t.elapsed().as_micros() as u64);
    }
    direct.sort_unstable();
    let p50 = direct[direct.len() / 2];

    let mut with = Vec::new();
    let (n, _d) = primary_on("c103-price-on", params());
    let mut n = n.with_centroids(Arc::clone(&c));
    for i in 0..PRICE_FRAMES {
        let k = owner(100 + i);
        let cell = BASE + (i as u16 % 16);
        let sec = SEC0 + i;
        let t = std::time::Instant::now();
        let err = publish(&mut n, k, &grid_row(cell), cell, sec);
        with.push(t.elapsed().as_micros() as u64);
        assert!(err.is_none(), "ценовой кадр #{i} отвергнут: {err:?}");
    }
    with.sort_unstable();
    let p50_with = with[with.len() / 2];

    let mut without = Vec::new();
    let (n2, _d2) = primary_on("c103-price-off", params());
    let mut n2 = n2;
    for i in 0..PRICE_FRAMES {
        let k = owner(200 + i);
        let cell = BASE + (i as u16 % 16);
        let sec = SEC0 + i;
        let t = std::time::Instant::now();
        let err = publish(&mut n2, k, &grid_row(cell), cell, sec);
        without.push(t.elapsed().as_micros() as u64);
        assert!(err.is_none(), "ценовой кадр без центроидов #{i} отвергнут: {err:?}");
    }
    without.sort_unstable();
    let p50_without = without[without.len() / 2];

    let ok = u64::from(p50 <= ASSIGN_BUDGET_US);
    // Debug-сборка не оптимизирована: тот же `assign` стоит там десятки миллисекунд, и гонять
    // этот тест в регрессии с релизным порогом значило бы приписать код хосту. В релизе порог
    // один и тот же; факт `..._LE_300US` всегда считается против 300 и в debug честно равен 0
    // (в `workspace-verify` он не сверяется, в замер идут только релизные прогоны).
    let budget = if cfg!(debug_assertions) { 20_000 } else { ASSIGN_BUDGET_US };
    eprintln!(
        "## C103_ASSIGN_P50_US={p50} C103_ASSIGN_BUDGET_US={budget} \
         C103_ASSIGN_P50_LE_300US={ok} C103_PUBLISH_P50_WITH_US={p50_with} \
         C103_PUBLISH_P50_WITHOUT_US={p50_without} ##"
    );
    assert!(p50 <= budget, "assign p50 {p50} мкс вышел за бюджет {budget} мкс (debug — запасной)");
    assert_eq!(
        n2.admission.borrow().stats.cluster_unverified, PRICE_FRAMES,
        "ценовой цикл без артефакта обязан быть посчитан целиком"
    );
}
