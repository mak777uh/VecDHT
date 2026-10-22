//! Оракул H-0048/E-0048: потолок таблицы при ≥2 совпадений — «без части приёмов» §12.3.
//!
//! MatchResult полон и подписан до цикла приёмов; приёмы выпускаются порядком контракта
//! сортировки, значит отказ бьёт по детерминированному хвосту: при 3 match и 2 свободных
//! слотах — первые две пары (target, slot), третий match без приёма, refused_full +1.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, ProtocolError, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER_SEEDS: [u8; 3] = [77, 78, 79];

fn primary_on(dir_name: &str) -> (ShardNode, std::path::PathBuf) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = testing::node(&d, SHARD, seed, testing::params(POW), &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "приёмы выпускает primary эпизоды");
    (n, d)
}

fn publish_frame(agent_seed: u8, vec_seed: u8) -> Vec<u8> {
    let agent = testing::identity(agent_seed);
    testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(vec_seed),
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

fn match_result(replies: &[vecdht_node::Envelope]) -> Option<MatchResult> {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
}

fn accepts(replies: &[vecdht_node::Envelope]) -> Vec<RendezvousAccept> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| RendezvousAccept::decode(&e.frame).expect("accept"))
        .collect()
}

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

#[test]
fn ceiling_drops_the_sorted_tail_of_accepts_and_keeps_the_full_match_result() {
    let (mut n, d) = primary_on("ceiling-partial");
    for (i, s) in OWNER_SEEDS.iter().enumerate() {
        n.on_frame(
            testing::identity(*s).pubkey(),
            &publish_frame(*s, 1 + i as u8),
            testing::clock(0),
        )
        .expect("publish");
    }
    assert_eq!(n.store.len(), 3, "три живые записи — три будущих match");

    // Дыров в таблице ровно 2: третий приём обязан упереться в потолок.
    let fill = rendezvous::MAX_ACCEPTS - 2;
    let junk = [9u8; 32];
    for i in 0..fill {
        assert!(
            n.rendezvous
                .issue(junk, testing::identity(90).pubkey(), SHARD, 5_000 + i as u32, 0)
                .is_some(),
            "строка №{i} обязана влезть до дыры"
        );
    }
    assert_eq!(n.rendezvous.live(), fill);

    let a = testing::identity(88);
    let me_a = a.pubkey();
    let r = n.on_frame(me_a, &find_frame(&a), testing::clock(0)).expect("find");
    let m = match_result(&r).expect("фальсификатор (а): MatchResult цел при частичной выдаче");
    assert_eq!(m.matches.len(), 3, "порог (1): отказ в приёме не тронул находки");
    let acc = accepts(&r);
    assert_eq!(acc.len(), 2, "порог (1): свободных слотов ровно 2");
    for (i, x) in acc.iter().enumerate() {
        assert_eq!(
            (x.target, x.slot),
            (m.matches[i].owner_ed25519, m.matches[i].slot),
            "фальсификатор (б): выпущен приём №{i} не первой пары сортированного списка"
        );
    }
    assert!(error_to(&r, me_a).is_none(), "фальсификатор (д): частичная выдача — не ошибка");
    let refused_after_first = n.rendezvous.refused_full;
    assert_eq!(refused_after_first, 1, "фальсификатор (в): ровно третий match не получил приём");
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (г)");

    // Повтор: строки третьего match в таблице нет — это новый отказ, не идемпотентный Some.
    let r2 = n.on_frame(me_a, &find_frame(&a), testing::clock(0)).expect("find 2");
    assert_eq!(match_result(&r2).expect("MatchResult цел").matches.len(), 3);
    assert!(accepts(&r2).is_empty(), "таблица полна — приёмов ноль");
    assert_eq!(n.rendezvous.refused_full, 2, "фальсификатор (в): повтор не засчитан как отказ");
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (г)");

    eprintln!(
        "## пороги (1)…(4): 3 matches целы, приёмы — первые две пары (target,slot) хвоста \
         не тронули, refused_full 1 затем 2, live ровно 100 000, ProtocolError нет ##"
    );
    remove(&d);
}
