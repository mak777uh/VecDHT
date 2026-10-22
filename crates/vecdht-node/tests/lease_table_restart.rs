//! Оракул H-0046/E-0046: рестарт узла-издателя обнуляет lease-таблицу, новый `Find`
//! выпускает побайтово тот же приём, а цель расходует довоенный кадр.
//!
//! Граница §12.3 «таблица — RAM; после рестарта она пуста, и новый `Find` выпускает новые
//! приёмы, а ранее выданные доживают TTL у целей, потому что проверяются по подписи
//! издателя, а не по его текущей таблице» — на живом узле не измерена нигде (reopen
//! проверялся только для denylist, `E-0042`).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode, Spend};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, ProtocolError, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn first_seed() -> u8 {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов")
}

fn boot(d: &std::path::Path, seed: u8) -> ShardNode {
    let mut n = testing::node(d, SHARD, seed, testing::params(POW), &SEEDS);
    if n.epoch().is_none() {
        n.on_frame(
            testing::identity(9).pubkey(),
            &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
            testing::clock(0),
        )
        .expect("genesis");
    }
    assert!(n.is_primary(), "приём выпускает primary; состояние после reopen — эпизод 1");
    n
}

fn publish_frame(agent_seed: u8) -> Vec<u8> {
    let agent = testing::identity(agent_seed);
    testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(1),
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch: 1,
        published_bucket: 0,
        ttl_buckets: 225,
        bits: POW,
    }
    .frame()
}

fn find_frame(agent: &vecdht_crypto::Identity) -> Vec<u8> {
    testing::find_frame(agent, &testing::vector(1), &[CLUSTER], 8, 91)
}

fn accepts(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("accept")))
        .collect()
}

fn match_result(replies: &[vecdht_node::Envelope]) -> Option<MatchResult> {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
}

#[test]
fn restart_empties_the_table_and_the_old_accept_still_spends() {
    let seed = first_seed();
    let d = dir("lease-restart");
    let owner = testing::identity(77);
    let a = testing::identity(88);

    let mut n = boot(&d, seed);
    n.on_frame(owner.pubkey(), &publish_frame(77), testing::clock(0))
        .expect("publish");
    let r1 = n.on_frame(a.pubkey(), &find_frame(&a), testing::clock(0)).expect("find 1");
    assert_eq!(match_result(&r1).map(|m| m.matches.len()), Some(1), "запись находится");
    let f1 = accepts(&r1);
    assert_eq!(f1.len(), 1, "один match — один приём (шаг E-0044 для отсечки)");
    assert_eq!(n.rendezvous.live(), 1, "до рестарта таблица живая");
    let bytes_before = f1[0].0.clone();
    drop(n);

    // Порог (1): таблица не переживает reopen (фальсификатор (а)).
    let mut n2 = boot(&d, seed);
    assert_eq!(n2.epoch(), Some(1), "цепочка восстановлена с диска (якорь E-0042)");
    assert_eq!(n2.rendezvous.live(), 0, "фальсификатор (а): lease-таблица пережила рестарт");

    // Порог (2): новый Find выпускает приём, побайтово равный прежнему (фиксификаторы (в)/(г)).
    let r2 = n2.on_frame(a.pubkey(), &find_frame(&a), testing::clock(0)).expect("find 2");
    let f2 = accepts(&r2);
    if f2.is_empty() {
        for e in &r2 {
            if let Ok(p) = ProtocolError::decode(&e.frame) {
                eprintln!("факт: вместо приёма — ProtocolError code={} retry={}", p.code, p.retry_after_ms);
            }
        }
    }
    assert_eq!(f2.len(), 1, "фальсификатор (г): Find после reopen не выпустил приём");
    assert_eq!(f2[0].0, bytes_before, "фальсификатор (в): выпуск нечист от состояния — байты разошлись");
    assert_eq!(n2.rendezvous.live(), 1, "новая таблица заполнена одной строкой");

    // Порог (3): цель расходует довоенный кадр после рестарта издателя (фальсификатор (б)).
    let mut spend = Spend::new(300);
    let grant = spend
        .consume(&bytes_before, &n2.me(), &owner.pubkey(), 0)
        .expect("фальсификатор (б): довоенный приём не расходован после рестарта издателя");
    assert_eq!((grant.seeker, grant.shard), (a.pubkey(), SHARD));
    assert_eq!(
        spend.consume(&bytes_before, &n2.me(), &owner.pubkey(), 0),
        Err(rendezvous::AcceptError::AlreadySpent),
        "повторный расход по-прежнему одноразов"
    );

    eprintln!(
        "## пороги (1)…(3): live==0 после reopen; приём после рестарта побайтово равен \
         прежнему; довоенный кадр расходован целью (Ok), повтор — AlreadySpent ##"
    );
    remove(&d);
}
