//! Оракул H-0058/E-0058: окно расхода post-prune приёма синхронизировано с prune (§12.3).
//!
//! `E-0057` показал: приём, переживший prune своей таблицы, при новом `Find` возвращается
//! НОВОЙ строкой нового бакета (`Key` включает `issued_bucket`). `E-0047` мерил окно
//! `Spend::consume` для приёма бакета 0 (граница `issued+buckets(ttl)` включительно Ok,
//! +1 — `Expired`). Не мерилось: что происходит с окном расхода приёма, ВЫДАННОГО ПОСЛЕ
//! prune (бакет 20). Из кода обе границы выведены из одной величины `buckets(ttl_sec)`:
//! `Issuer::prune` выбрасывает строку при `now > issued + ttl_buckets` (cutoff =
//! now − ttl_buckets, уходит `bucket < cutoff`), `Spend::consume` даёт `Expired` при том
//! же строгом `>` — значит дыра в таблице издателя и отказ цели истекают ОДНИМ бакетом.
//!
//! Пороги (ttl=300, buckets=19; приём A20 выписан бакетом 20):
//! (1) consume при now=39 → Ok (грань 39=20+19 включительно);
//! (2) повтор того же кадра при now=39 → AlreadySpent;
//! (3) тот же кадр при now=40 → Expired (ровно когда prune издателя выбросил бы строку 20);
//! (4) второй кадр (seeker B, бакет 20, тот же слот) расходуется при now=39 → Ok —
//!     расход A не блокирует побратима: разные seeker'ы = разные ключи (`E-0055`),
//!     на границе 40 он тоже Expired;
//! (5) таблица издателя на now=40 уже без строки 20 (prune синхронен границе отказа).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode, Spend};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER_SEEDS: [u8; 3] = [77, 78, 79];
const POST_PRUNE_BUCKET: u32 = 20;
const OK_EDGE: u32 = 39;
const DEAD_EDGE: u32 = 40;

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

fn accepts(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("accept")))
        .collect()
}

fn find(n: &mut ShardNode, a: &vecdht_crypto::Identity, bucket: u32, qid: u64) -> Vec<vecdht_node::Envelope> {
    n.on_frame(
        a.pubkey(),
        &testing::find_frame(a, &testing::vector(1), &[CLUSTER], 8, qid),
        testing::clock(bucket),
    )
    .expect("find")
}

#[test]
fn post_prune_accept_expires_at_the_same_bucket_the_issuer_prunes_it() {
    let (mut n, d) = primary_on("post-prune-spend-window");
    for (i, s) in OWNER_SEEDS.iter().enumerate() {
        n.on_frame(
            testing::identity(*s).pubkey(),
            &publish_frame(*s, 1 + i as u8),
            testing::clock(0),
        )
        .expect("publish");
    }
    assert_eq!(n.store.len(), 3, "три живые записи");

    let a = testing::identity(88);
    let b = testing::identity(89);
    // Голова бакета 0 + достройка до потолка чужими строками бакета 0 (E-0056/E-0057).
    let r0 = find(&mut n, &a, 0, 701);
    assert_eq!(accepts(&r0).len(), 3, "фальсификатор (д): голова не выдана");
    let junk = [9u8; 32];
    for i in 0..rendezvous::MAX_ACCEPTS - 3 {
        assert!(
            n.rendezvous
                .issue(junk, testing::identity(90).pubkey(), SHARD, 30_000 + i as u32, 0)
                .is_some(),
            "строка №{i} бакета 0 обязана влезть"
        );
    }

    // now = 20: prune снимает бакет 0, A и B получают приёмы НОВОГО бакета 20.
    let ra = find(&mut n, &a, POST_PRUNE_BUCKET, 702);
    let acc_a = accepts(&ra);
    assert_eq!(acc_a.len(), 3, "фальсификатор (д): A не получил post-prune дыру");
    let rb = find(&mut n, &b, POST_PRUNE_BUCKET, 703);
    let acc_b = accepts(&rb);
    assert_eq!(acc_b.len(), 3, "фальсификатор (д): B не получил дыру");
    for (i, (_, x)) in acc_a.iter().enumerate() {
        assert_eq!(x.issued_bucket, POST_PRUNE_BUCKET, "фальсификатор (д): приём №{i} не бакета 20");
        assert_eq!(x.ttl_sec, 300, "фальсификатор (е): ttl кадра разошёлся с Params");
        assert_eq!(
            (acc_b[i].1.slot, acc_b[i].1.target),
            (x.slot, x.target),
            "фальсификатор (ж): побратим B не на тот же слот"
        );
    }

    // Порог (1): грань 39 = 20 + buckets(300) включительно Ok.
    let owner = testing::identity(77);
    let mut spend = Spend::new(300);
    let grant = spend
        .consume(&acc_a[0].0, &n.me(), &owner.pubkey(), OK_EDGE)
        .expect("порог (1): приём бакета 20 истёк раньше синхронной грани");
    assert_eq!((grant.seeker, grant.issued_bucket), (a.pubkey(), POST_PRUNE_BUCKET), "фальсификатор (з): grant не связан с A20");

    // Порог (2): повтор при now=39 — AlreadySpent (память расхода переживает граничный бакет).
    assert_eq!(
        spend.consume(&acc_a[0].0, &n.me(), &owner.pubkey(), OK_EDGE),
        Err(rendezvous::AcceptError::AlreadySpent),
        "фальсификатор (а): повтор предъявления обслужен"
    );

    // Порог (3): now=40 — Expired: тот же бакет, в котором prune издателя выбрасывает строку.
    assert_eq!(
        spend.consume(&acc_a[0].0, &n.me(), &owner.pubkey(), DEAD_EDGE),
        Err(rendezvous::AcceptError::Expired),
        "фальсификатор (б): цель приняла приём, который издатель уже не хранит"
    );

    // Порог (4): побратим B (тот же слот/цель, другой seeker) расходуется независимо.
    let grant_b = spend
        .consume(&acc_b[0].0, &n.me(), &owner.pubkey(), OK_EDGE)
        .expect("фальсификатор (в): расход A заблокировал побратима B");
    assert_eq!(grant_b.seeker, b.pubkey(), "фальсификатор (в): grant B выдан на чужого seeker'а");
    assert_eq!(
        spend.consume(&acc_b[0].0, &n.me(), &owner.pubkey(), DEAD_EDGE),
        Err(rendezvous::AcceptError::Expired),
        "фальсификатор (б): побратим пережил синхронную грань"
    );

    // Порог (5): синхронность на живом пути — на now=40 строки бакета 20 выбрасывает и
    // `Issuer::prune` (первый же issue их чистит): повторный Find бакета 40 даёт НОВЫЕ
    // строки бакета 40, а не идемпотентный кадр 20 (байты разошлись).
    let r40 = find(&mut n, &a, DEAD_EDGE, 704);
    let acc40 = accepts(&r40);
    assert_eq!(acc40.len(), 3, "фальсификатор (г): пустой prune не вернул дыру");
    for i in 0..3 {
        assert_eq!(acc40[i].1.issued_bucket, DEAD_EDGE, "фальсификатор (г): строка не бакета 40");
        assert_ne!(acc40[i].0, acc_a[i].0, "фальсификатор (г): кадр 20 пережил собственный prune");
    }
    assert_eq!(n.rendezvous.live(), 3, "порог (5): live = 3 строки A бакета 40; и A, и B бакета 20 выброшены cutoff 21");

    eprintln!(
        "## пороги (1)…(5): приём post-prune бакета 20 расходуется на грани 39=20+19 \
         включительно (Ok), повтор — AlreadySpent, now=40 — Expired; побратим B того же \
         слота расходуется независимо и тоже истекает на 40; на now=40 Issue-путь \
         выбрасывает строки 20 (повтор даёт новые байты бакета 40, live 3) — отказ цели \
         и дыра издателя истекают одним бакетом ##"
    );
    remove(&d);
}
