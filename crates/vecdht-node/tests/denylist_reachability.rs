//! Оракул H-0042/E-0042: подотчётность через denylist (§11.4 (ii)) на живом узле.
//!
//! «До» перезагрузки внесённый ключ отвечает на проводе `DENIED` и виден в списке; «после»
//! повторного открытия того же каталога цепочка членства восстановлена (`epoch()==Some(1)`),
//! но список пуст и счётчик отказа обнулён — denylist живёт только в RAM. Порог (3) сознательно
//! слабее ожидания: код после перезагрузки обязан быть не `DENIED` (фактический печатается;
//! по порядку проверок `handle_publish` это `NOT_OWNER`).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, ProtocolError};

const SHARD: u16 = 7;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn params() -> Params {
    testing::params(POW)
}

/// Узел шарда, принявший genesis эпохи 1: primary с активным lease (harness `tests/admission.rs`).
fn primary_on(dir_name: &str) -> (ShardNode, std::path::PathBuf) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = testing::node(&d, SHARD, seed, params(), &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "отказ DENIED меряется на пути записи primary");
    (n, d)
}

/// Кадр publish от агента с_seed=1 (тот же `intent_id`, что и в «до»-наблюдении).
fn publish_frame(agent_seed: u8) -> Vec<u8> {
    let agent = testing::identity(agent_seed);
    testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(1),
        cluster_id: SHARD << 4,
        shard: SHARD,
        epoch: 1,
        published_bucket: 0,
        ttl_buckets: 225,
        bits: POW,
    }
    .frame()
}

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

#[test]
fn denylist_is_unreachable_in_and_vanishes_on_restart() {
    let (mut n, d) = primary_on("deny-restart");
    let bad = testing::identity(85);
    let me = bad.pubkey();

    // Порог (1): «до» — внесение первым вызовом, отказ ровно DENIED, счётчики видят список.
    assert!(n.admission.borrow_mut().deny(me), "первый deny того же ключа");
    let before = {
        let a = n.admission.borrow();
        (a.denylist_len(), a.is_denied(&me), a.stats.denied_by_denylist)
    };
    assert_eq!(before, (1, true, 0), "состояние admission сразу после deny");
    let replies = n
        .on_frame(me, &publish_frame(85), testing::clock(0))
        .expect("publish от внесённого ключа");
    let err = error_to(&replies, me).expect("внесённый ключ обязан получить Error");
    assert_eq!(err.code, err_code::DENIED, "код «до» перезагрузки");
    let after_hit = {
        let a = n.admission.borrow();
        (a.denylist_len(), a.is_denied(&me), a.stats.denied_by_denylist)
    };
    assert_eq!(after_hit, (1, true, 1), "отказ учтён в denied_by_denylist");

    // Порог (2): «после» открытия того же каталога — цепочка с диска, denylist из воздуха.
    drop(n);
    let seed = {
        let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
        *SEEDS
            .iter()
            .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
            .expect("тот же primary-сид, что и в первом открытии")
    };
    let mut n2 = testing::node(&d, SHARD, seed, params(), &SEEDS);
    assert_eq!(n2.epoch(), Some(1), "фальсификатор (д): состояние узла восстановлено с диска");
    let a2 = n2.admission.borrow();
    assert_eq!(a2.denylist_len(), 0, "фальсификатор (б): запрет пережил перезагрузку");
    assert!(!a2.is_denied(&me), "внесённый «до» ключ снова свободен");
    assert_eq!(a2.stats.denied_by_denylist, 0);
    drop(a2);

    // Порог (3): тот же кадр после перезагрузки — код обязан быть не DENIED; печатаем факт.
    let replies = n2
        .on_frame(me, &publish_frame(85), testing::clock(1))
        .expect("publish после перезагрузки");
    let code = error_to(&replies, me).map(|e| e.code).unwrap_or_else(|| {
        // Ответа Error нет — значит кадр ушёл дальше по пути приёма; фиксируем это числом конвертов.
        assert_eq!(replies.len(), 0, "без Error и без конвертов быть не может");
        "(нет Error)".to_string()
    });
    eprintln!("## порог (3): код после перезагрузки = {code} (ожидание по порядку проверок: NOT_OWNER) ##");
    assert_ne!(code, err_code::DENIED, "фальсификатор (в): запрет всё ещё на проводе");

    remove(&d);
}
