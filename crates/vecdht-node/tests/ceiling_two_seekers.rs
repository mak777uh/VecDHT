//! Оракул H-0055/E-0055: потолок lease-таблицы при двух seeker'ах на одной дыре.
//!
//! Ключ расхода включает `seeker` (`rendezvous.rs:36`), поэтому находки двух агентов
//! занимают РАЗНЫЕ строки одной таблицы. `E-0048` мерил хвост для одного seeker'а,
//! `E-0053` — композицию с clamp'ом тоже для одного. Здесь: дыра в 2 строки, два агента
//! по 3 находки — первый съедает дыру, второй не получает ничего, и оба получают целый
//! `MatchResult` без ошибки (§12.3, `ADR-0012`).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, ProtocolError, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER_SEEDS: [u8; 3] = [77, 78, 79];
const FREE: usize = 2;

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
    assert!(n.is_primary(), "приёмы выпускает primary эпизода");
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

fn find(agent: &vecdht_crypto::Identity, top_k: u16, query_id: u64) -> Vec<u8> {
    testing::find_frame(agent, &testing::vector(1), &[CLUSTER], top_k, query_id)
}

fn match_result(replies: &[vecdht_node::Envelope]) -> MatchResult {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
        .expect("фальсификатор (а): MatchResult отсутствует")
}

fn accepts(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("accept")))
        .collect()
}

fn has_error(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> bool {
    replies.iter().any(|e| {
        e.to == agent
            && decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::Error)
            && ProtocolError::decode(&e.frame).is_ok()
    })
}

#[test]
fn one_hole_is_consumed_by_the_first_seeker_and_the_second_gets_no_accept_at_all() {
    let (mut n, d) = primary_on("ceiling-two-seekers");
    for (i, s) in OWNER_SEEDS.iter().enumerate() {
        n.on_frame(
            testing::identity(*s).pubkey(),
            &publish_frame(*s, 1 + i as u8),
            testing::clock(0),
        )
        .expect("publish");
    }
    // Скоуп H-0055 (записан до прогона, гейт не трогает): в этом оракуле таблица
    // наполнена ВРУЧНУЮ чужими ключами (`issue(junk, …)`), поэтому до шага (1) в ней нет
    // ни одной строки seeker'ов A и B. Идемпотентность (`seen` проверяется до `cap`)
    // возвращает A его же префикс на шаге (4) — 2 побайтовых приёма при полной таблице,
    // а B таких строк не имеет вовсе, поэтому и удостаивается отказа за каждую находку.
    // Постановка дыры трафиком самих seeker'ами покрывалась в E-0048/E-0053 и здесь не
    // измеряется, чтобы не менять пороги задним числом.
    assert_eq!(n.store.len(), 3, "три живые записи — три будущих match");

    let fill = rendezvous::MAX_ACCEPTS - FREE;
    let junk = [9u8; 32];
    for i in 0..fill {
        assert!(
            n.rendezvous
                .issue(junk, testing::identity(90).pubkey(), SHARD, 20_000 + i as u32, 0)
                .is_some(),
            "строка №{i} обязана влезть до дыры"
        );
    }
    assert_eq!(n.rendezvous.live(), fill, "фальсификатор (в): дыра ровно {FREE} строки");

    let a = testing::identity(88);
    let b = testing::identity(87);

    // Порог (1): первый seeker съедает дыру — 2 приёма по голове списка, 1 отказ.
    let ra = n.on_frame(a.pubkey(), &find(&a, 8, 401), testing::clock(0)).expect("find A");
    let ma = match_result(&ra);
    assert_eq!(ma.matches.len(), 3, "порог (1): находок столько же, сколько записей");
    let acc_a = accepts(&ra);
    assert_eq!(acc_a.len(), FREE, "порог (1): первый seeker получил ровно дыру");
    for (i, (_, x)) in acc_a.iter().enumerate() {
        assert_eq!(
            (x.target, x.slot),
            (ma.matches[i].owner_ed25519, ma.matches[i].slot),
            "фальсификатор (б)-состав: приём №{i} не первой пары списка"
        );
    }
    assert_eq!(n.rendezvous.refused_full, 1, "порог (1): хвостовая находка без приёма");
    assert!(!has_error(&ra, a.pubkey()), "фальсификатор (а): частичная выдача стала ошибкой");
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (в)");

    // Порог (2): второй seeker — те же 3 находки, НИ ОДНОГО приёма, +3 отказа.
    let rb = n.on_frame(b.pubkey(), &find(&b, 8, 402), testing::clock(0)).expect("find B");
    let mb = match_result(&rb);
    assert_eq!(mb.matches.len(), 3, "фальсификатор (а): MatchResult B урезан относительно A");
    for i in 0..3 {
        assert_eq!(
            (mb.matches[i].owner_ed25519, mb.matches[i].slot, mb.matches[i].d2),
            (ma.matches[i].owner_ed25519, ma.matches[i].slot, ma.matches[i].d2),
            "фальсификатор (а): состав находок разошёлся между seeker'ами"
        );
    }
    assert_eq!(accepts(&rb).len(), 0, "фальсификатор (б): второй seeker получил приём при пустой дыре");
    assert_eq!(n.rendezvous.refused_full, 1 + 3, "порог (2): B удостаивается отказа за каждую находку");
    assert!(!has_error(&rb, b.pubkey()), "фальсификатор (а): отказ B стал ошибкой поиска");
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (в)");

    // Порог (3): малый запрос B (одна находка, её строки в таблице нет) — ровно 1 отказ.
    let rb1 = n.on_frame(b.pubkey(), &find(&b, 1, 403), testing::clock(0)).expect("find B top_k=1");
    assert_eq!(match_result(&rb1).matches.len(), 1, "порог (3): одна находка запрошена и получена");
    assert_eq!(accepts(&rb1).len(), 0, "фальсификатор (б): малый запрос B прошёл при пустой дыре");
    assert_eq!(n.rendezvous.refused_full, 5, "порог (3): refusals = 1+3+1");

    // Порог (4): повтор A — те же 2 побайтовых кадра, ещё 1 отказ, дыра не выросла.
    let ra2 = n.on_frame(a.pubkey(), &find(&a, 8, 404), testing::clock(0)).expect("find A повтор");
    let acc_a2 = accepts(&ra2);
    assert_eq!(acc_a2.len(), FREE, "порог (4): строки таблицы отдают A его же префикс");
    for i in 0..FREE {
        assert_eq!(acc_a2[i].0, acc_a[i].0, "фальсификатор (д): приём №{i} повтора не побайтовый");
    }
    assert_eq!(n.rendezvous.refused_full, 6, "порог (4): хвост A удостаивается отказа заново");
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (в)");

    eprintln!(
        "## пороги (1)…(4): дыра {} строки съедена первым seeker'ом (2 приёма по голове \
         списка), второй seeker при тех же 3 находках получил 0 приёмов, малый запрос второго \
         — 1 отказ, повтор первого — те же 2 побайтовых кадра; refused_full 1→4→5→6, live \
         ровно 100 000, ProtocolError нет у обоих ##",
        FREE
    );
    remove(&d);
}
