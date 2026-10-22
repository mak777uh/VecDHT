//! Оракул E-0037, порог (4): цена `Find` в admission не зависит от длины списка кластеров.
//!
//! Harness — `tests/admission.rs` (шард 7, кластер 112, primary после genesis). Два свежих
//! ключа при `testing::clock(0)` шлют по шесть `Find`: первый — законный список из одного
//! кластера, второй — 4 096 копий того же кластера (256× законного nprobe шарда; guard
//! `shard_of_cluster` такие дубликаты пропускает). Требуемый исход: ровно 5 пропущены, шестой
//! — `QUOTA_FIND` с `retry_after_ms = 200`, и шестые ответы обоих ключей идентичны по коду
//! и ожиданию. Любое различие исходов длинного и короткого списка фальсифицирует (г).
//!
//! Пустой индекс здесь — часть метода: отказ квоты обязан наступать ДО разбора тела и до
//! поиска, поэтому на исход шестого ответа содержимое шарда влиять не может.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, ProtocolError};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

/// Узел шарда, принявший genesis эпохи 1 (тот же порядок, что в `tests/admission.rs`).
fn primary_on(dir_name: &str, p: Params) -> (ShardNode, std::path::PathBuf) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = testing::node(&d, SHARD, seed, p, &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "отвечает на Find только primary эпизоды");
    (n, d)
}

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

/// Прогон шести `Find` от свежего ключа; возвращает коды отказов по порядку (None = пропущен).
fn six_finds(n: &mut ShardNode, list_len: usize) -> (Vec<Option<String>>, Vec<Option<u32>>) {
    let agent = if list_len == 1 {
        testing::identity(201)
    } else {
        testing::identity(202)
    };
    let me = agent.pubkey();
    let clusters = vec![CLUSTER; list_len];
    let frame = testing::find_frame(&agent, &testing::vector(1), &clusters, 8, 1);
    let mut codes = Vec::new();
    let mut waits = Vec::new();
    for i in 0..6 {
        let replies = n
            .on_frame(me, &frame, testing::clock(0))
            .expect("find обязан обработаться");
        let err = error_to(&replies, me);
        assert!(
            err.is_none() == (i < 5),
            "ключ со списком {list_len}: отказ №{i} не на шестом запросе"
        );
        codes.push(err.as_ref().map(|e| e.code.clone()));
        waits.push(err.map(|e| e.retry_after_ms));
    }
    (codes, waits)
}

#[test]
fn find_quota_price_ignores_cluster_list_length() {
    let (mut n, d) = primary_on("find-price", testing::params(POW));
    let (short_codes, short_waits) = six_finds(&mut n, 1);
    let (long_codes, long_waits) = six_finds(&mut n, 4096);

    // Порог (4): пять пропусков, шестой — QUOTA_FIND/200, у обоих длин списков одинаково.
    for (label, codes, waits) in [("список 1", &short_codes, &short_waits), ("список 4096", &long_codes, &long_waits)] {
        assert!(
            codes[..5].iter().all(Option::is_none),
            "{label}: первые пять find не пропущены"
        );
        assert_eq!(
            codes[5].as_deref(),
            Some(err_code::QUOTA_FIND),
            "{label}: шестой find не получил QUOTA_FIND"
        );
        assert_eq!(waits[5], Some(200), "{label}: 5/с обязана отвечать 200 мс");
    }
    assert_eq!(short_codes, long_codes, "код шестого отказа зависит от длины списка — фальсификатор (г)");
    assert_eq!(short_waits, long_waits, "retry_after_ms зависит от длины списка — фальсификатор (г)");

    eprintln!(
        "## порог (4): список 1 → {:?} / {} мс; список 4096 → {:?} / {} мс ##",
        short_codes[5].as_deref().unwrap_or("?"),
        short_waits[5].unwrap_or(0),
        long_codes[5].as_deref().unwrap_or("?"),
        long_waits[5].unwrap_or(0),
    );
    remove(&d);
}
