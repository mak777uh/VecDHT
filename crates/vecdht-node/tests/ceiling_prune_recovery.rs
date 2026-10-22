//! Оракул H-0056/E-0056: дыра lease-таблицы возвращается после `prune` по TTL (§12.3).
//!
//! `E-0044`/`E-0048`/`E-0053`/`E-0055` мерили поведение НА потолке. Что происходит с
//! потолком, когда строки таблицы истекают, не мерилось ни разу: `Issuer::prune`
//! (`rendezvous.rs`) выбрасывает целые бакеты при `bucket < now - ttl_buckets`, то есть
//! для бакета 0 при `ttl_sec = 300` (`buckets(300) = 19`) — только начиная с `now = 20`.
//! Значит на `now = 19` таблица всё ещё полная (и выдача пустая), а на `now = 20`
//! освобождается разом, и тот же `Find` снова получает приёмы — уже нового бакета.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER_SEEDS: [u8; 3] = [77, 78, 79];
const TTL_SEC: u16 = 300;
const TTL_BUCKETS: u32 = 19;

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

fn match_result(replies: &[vecdht_node::Envelope]) -> MatchResult {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
        .expect("фальсификатор (д): MatchResult отсутствует")
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
        e.to == agent && decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::Error)
    })
}

#[test]
fn the_ceiling_hole_returns_when_leased_rows_expire_out_of_prune() {
    let (mut n, d) = primary_on("ceiling-prune-recovery");
    assert_eq!(
        vecdht_node::buckets(TTL_SEC as u32),
        TTL_BUCKETS,
        "фальсификатор (е): границы бакетов взяты не из той же арифметики, что `Issuer`"
    );
    assert_eq!(
        testing::params(POW).rendezvous_ttl,
        TTL_SEC,
        "фальсификатор (е): TTL тестового узла разошёлся с TTL оракула"
    );
    for (i, s) in OWNER_SEEDS.iter().enumerate() {
        n.on_frame(
            testing::identity(*s).pubkey(),
            &publish_frame(*s, 1 + i as u8),
            testing::clock(0),
        )
        .expect("publish");
    }
    assert_eq!(n.store.len(), 3, "три живые записи");

    // Таблица забита СТРОКАМИ БАКЕТА 0 под завязку: дыры нет вовсе.
    let junk = [9u8; 32];
    for i in 0..rendezvous::MAX_ACCEPTS {
        assert!(
            n.rendezvous
                .issue(junk, testing::identity(90).pubkey(), SHARD, 30_000 + i as u32, 0)
                .is_some(),
            "строка №{i} обязана влезть (дыры не оставляем)"
        );
    }
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (а)");

    let a = testing::identity(88);
    let find = testing::find_frame(&a, &testing::vector(1), &[CLUSTER], 8, 501);

    // Порог (1): now = 0 — полная таблица, ни одного приёма, 3 отказа.
    let r0 = n.on_frame(a.pubkey(), &find, testing::clock(0)).expect("find@0");
    assert_eq!(match_result(&r0).matches.len(), 3, "фальсификатор (д): находки целы");
    assert_eq!(accepts(&r0).len(), 0, "порог (1): дыры нет — приёмов нет");
    assert_eq!(n.rendezvous.refused_full, 3, "порог (1): три отказа");
    assert!(!has_error(&r0, a.pubkey()), "фальсификатор (б): пустая выдача стала ошибкой");

    // Порог (2): now = 19 (граница действительности) — бакет 0 ЕЩЁ не выброшен.
    let r19 = n.on_frame(a.pubkey(), &find, testing::clock(TTL_BUCKETS)).expect("find@19");
    assert_eq!(accepts(&r19).len(), 0, "фальсификатор (в): бакет 0 выброшен раньше границы");
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (в)");
    assert_eq!(n.rendezvous.refused_full, 6, "порог (2): ещё +3 отказа");

    // Порог (3): now = 20 — prune выбрасывает бакет 0 целиком, дыра возвращается разом.
    let r20 = n.on_frame(a.pubkey(), &find, testing::clock(TTL_BUCKETS + 1)).expect("find@20");
    let acc20 = accepts(&r20);
    assert_eq!(acc20.len(), 3, "фальсификатор (г): после prune приёмов не стало больше");
    assert_eq!(match_result(&r20).matches.len(), 3, "фальсификатор (д)");
    assert_eq!(n.rendezvous.live(), 3, "порог (3): 100 000 строк бакета 0 выброшены, live == 3");
    assert_eq!(n.rendezvous.refused_full, 6, "порог (3): новых отказов нет");
    for (i, (_, x)) in acc20.iter().enumerate() {
        assert_eq!(x.issued_bucket, TTL_BUCKETS + 1, "порог (3): приём выпущен бакетом 20");
        assert_eq!(
            (x.target, x.slot),
            (
                match_result(&r20).matches[i].owner_ed25519,
                match_result(&r20).matches[i].slot
            ),
            "фальсификатор (ж): приём №{i} не первой пары списка"
        );
    }

    // Порог (4): повтор в бакете 20 — те же 3 кадра побайтово, live остаётся 3.
    let find2 = testing::find_frame(&a, &testing::vector(1), &[CLUSTER], 8, 502);
    let rb = n.on_frame(a.pubkey(), &find2, testing::clock(TTL_BUCKETS + 1)).expect("find@20 повтор");
    let acc_b = accepts(&rb);
    assert_eq!(acc_b.len(), 3, "порог (4): повтор отдаёт те же строки таблицы");
    for i in 0..3 {
        assert_eq!(acc_b[i].0, acc20[i].0, "фальсификатор (з): кадр повтора не побайтовый");
    }
    assert_eq!(n.rendezvous.live(), 3, "порог (4): повтор не удваивает таблицу");
    assert_eq!(n.rendezvous.refused_full, 6, "порог (4): отказов больше нет");

    eprintln!(
        "## пороги (1)…(4): live 100 000 → выдача 0/3 отказа на now=0 и на now=19 (бакет 0 ещё \
         не выброшен), на now=20 prune снимает 100 000 строк разом → выдача 3/3 с \
         issued_bucket=20 и live=3, повтор в том же бакете — те же 3 побайтовых кадра; \
         refused_full 3→6→6→6, ProtocolError нет ##"
    );
    remove(&d);
}
