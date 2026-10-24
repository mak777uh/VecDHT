//! Наблюдаемость и граница окна `H-0102`/`E-0102` — файл появляется вместе с правкой, как `s76b`
//! у `E-0098`: он читает счётчик, которого до правки нет, и поэтому не может быть частью PRE_FIX.
//!
//! Что проверяется числом, а не поведением:
//!
//! * проход по окну стоит ровно бюджет (`EVICT_SCAN_BUDGET = 256`), а не размер ячейки;
//! * курсор сдвигается: второй заход видит хвост ячейки (44 слота), третий — снова начало
//!   (обёртка), то есть отказ на первом окне не запирает дешёвую запись навсегда;
//! * глобальный `scanned` (обход арены) не двигается: цена капа — локальное окно, а не O(M).

use vecdht_crypto::{intent_id, pow_input};
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Clock, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, ProtocolError, Publish};
use vecdht_wire::TIME_BUCKET_SEC;

const SHARD: u16 = 7;
const BASE: u16 = SHARD * 16;
const NEIGHBOUR: u16 = BASE + 1;
const SEEDS: [u8; 3] = [1, 2, 3];
const CAP: u64 = 300;
const SEC0: u64 = 16_000;
const FRAMES_PER_SEC: u64 = 50;
/// Предсказание продукта, а не импорт: изменение бюджета обязано уронить тест фактом.
const BUDGET: u64 = 256;
/// Хвост ячейки: 300 − 256 = 44 слота. В них лежат 20 записей по 9 бит и 24 по 12.
const TAIL: u64 = 44;

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
        assert!(
            error_to(&replies, k).is_none(),
            "кадр наполнения #{i} отвергнут — сцена не собралась"
        );
    }
    sec + count / FRAMES_PER_SEC + 1
}

#[test]
fn the_window_scan_is_bounded_advances_and_wraps() {
    let (mut n, _d) = primary_on("cap-scan-b", params());
    let mut sec = fill(&mut n, NEIGHBOUR, 100, 8, SEC0);
    sec = fill(&mut n, BASE, 280, 12, sec);
    sec = fill(&mut n, BASE, 20, 9, sec);
    assert_eq!(n.store.index.cluster_len(BASE) as u64, CAP);
    let bucket = bucket_of(sec);

    let s0 = n.evictor.cell_scanned;
    let k = owner(900_000);
    let r = n.on_frame(k, &frame(&k, 1, BASE, bucket, 11), Clock::at(sec)).expect("publish");
    assert_eq!(
        error_to(&r, k).map(|e| e.code),
        Some(err_code::SHARD_FULL.to_string()),
        "первое окно дешевле новичка не содержит — обязан отказ"
    );
    let d1 = n.evictor.cell_scanned - s0;
    assert_eq!(d1, BUDGET, "первый проход обязан стоить ровно бюджет, а не размер ячейки");

    let k2 = owner(900_001);
    let r2 = n.on_frame(k2, &frame(&k2, 1, BASE, bucket, 11), Clock::at(sec)).expect("publish");
    assert!(error_to(&r2, k2).is_none(), "хвост ячейки содержит 9-битную запись — обязан переезд");
    let d2 = n.evictor.cell_scanned - s0 - d1;
    assert_eq!(d2, TAIL, "второй проход обязан начаться с курсора и кончиться на конце списка");

    let k3 = owner(900_002);
    let r3 = n.on_frame(k3, &frame(&k3, 1, BASE, bucket, 8), Clock::at(sec)).expect("publish");
    assert!(error_to(&r3, k3).is_some(), "8 бит дешевле любой записи ячейки — обязан отказ");
    let d3 = n.evictor.cell_scanned - s0 - d1 - d2;
    assert_eq!(d3, BUDGET, "после конца списка курсор обязан обернуться и снова стоить бюджет");

    assert_eq!(n.store.index.cluster_len(BASE) as u64, CAP);
    assert_eq!(n.evictor.evicted, 1, "ровно одно вытеснение за сцену");
    assert_eq!(n.evictor.scanned, 0, "глобальная арена по-прежнему не обходится");

    eprintln!(
        "S77B_FIRST_SCAN={d1} S77B_SECOND_SCAN={d2} S77B_WRAP_SCAN={d3} \
         S77B_TOTAL_SCAN={} S77B_BUDGET={BUDGET} S77B_CELL={} S77B_EVICTED={}",
        n.evictor.cell_scanned - s0,
        n.store.index.cluster_len(BASE),
        n.evictor.evicted
    );
}
