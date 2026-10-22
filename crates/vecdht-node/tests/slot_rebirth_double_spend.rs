//! Оракул H-0059/E-0059: перерождение слота — второй lease того же слота после prune
//! расходуется вторично, оставаясь одноразовым внутри себя (§12.3).
//!
//! `E-0055`: разные seeker'ы одного слота — разные ключи расхода. `E-0058`: приём бакета 20
//! умирает для цели на 40 — тем же бакетом, что его выбрасывает `Issuer::prune`. Оставался
//! неизмеренным стык: если издатель после prune выдаёт ТОМУ ЖЕ seeker'у ТОТ ЖЕ слот заново
//! (бакет 40), расходится ли этот второй lease в прежнем `Spend` — или цель считает слот
//! «сожжённым навсегда»? Из кода: `Key` включает `issued_bucket`, значит `(A, t, shard,
//! slot, 40)` — новый ключ, и ответ обязан быть «расходится». Отличие от adversarial/
//! determinism (переиспользование слота хранилищем при republication): здесь слот НЕ
//! перевыставляется хранилищем, а ПЕРЕиздаётся издательским lease после истечения первого.
//!
//! Раскладка: ОДНА запись (owner identity(77)); таблица: 1 строка A бакета 0 + 99 999
//! чужих бакета 0 (потолок ровно). Шаги: find@0 → f0; достройка; consume f0@0 → Ok,
//! повтор → AlreadySpent; find@20 → prune бакета 0, f20 (issued_bucket=20, байты ≠ f0);
//! find@40 → prune бакета 20, f40; consume f40@40 → Ok (слот возродился); повтор f40@40
//! → AlreadySpent; старый f0@40 → Expired (строгий `>`, ПЕРЕД проверкой spent — не
//! AlreadySpent).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode, Spend};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER_SEED: u8 = 77;

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

fn match_result(replies: &[vecdht_node::Envelope]) -> MatchResult {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
        .expect("фальсификатор (д): MatchResult отсутствует")
}

fn only_accept(replies: &[vecdht_node::Envelope]) -> (Vec<u8>, RendezvousAccept) {
    let mut v = accepts(replies);
    assert_eq!(v.len(), 1, "фальсификатор (д): одна находка — ровно один приём");
    v.remove(0)
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
fn a_pruned_slot_reissues_and_the_same_spend_consumes_the_second_lease_once() {
    let (mut n, d) = primary_on("slot-rebirth-double-spend");
    let owner = testing::identity(OWNER_SEED);
    n.on_frame(
        owner.pubkey(),
        &testing::PublishSpec {
            agent: &owner,
            vec_q: &testing::vector(1),
            cluster_id: CLUSTER,
            shard: SHARD,
            epoch: 1,
            published_bucket: 0,
            ttl_buckets: 225,
            bits: POW,
        }
        .frame(),
        testing::clock(0),
    )
    .expect("publish");

    let a = testing::identity(88);
    let r = find(&mut n, &a, 0, 801);
    assert_eq!(match_result(&r).matches.len(), 1, "фальсификатор (д): одна запись — одна находка");
    let (f0, x0) = only_accept(&r);
    assert_eq!(x0.issued_bucket, 0, "фальсификатор (д): первый lease не бакета 0");
    assert_eq!(x0.ttl_sec, 300, "фальсификатор (е): ttl кадра разошёлся с Params");

    // Достройка до потолка чужими строками бакета 0: дыры нет.
    let junk = [9u8; 32];
    for i in 0..rendezvous::MAX_ACCEPTS - 1 {
        assert!(
            n.rendezvous
                .issue(junk, testing::identity(90).pubkey(), SHARD, 30_000 + i as u32, 0)
                .is_some(),
            "строка №{i} бакета 0 обязана влезть"
        );
    }
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (а): дыра осталась");

    // Порог (1): первый lease расходуется однажды на бакете 0.
    let mut spend = Spend::new(300);
    let g1 = spend
        .consume(&f0, &n.me(), &owner.pubkey(), 0)
        .expect("фальсификатор (в): первый lease не расходится");
    assert_eq!((g1.seeker, g1.slot, g1.issued_bucket), (a.pubkey(), x0.slot, 0), "фальсификатор (ж): grant первого lease");
    assert_eq!(
        spend.consume(&f0, &n.me(), &owner.pubkey(), 0),
        Err(rendezvous::AcceptError::AlreadySpent),
        "фальсификатор (б): повтор первого lease обслужен"
    );

    // now = 20: prune бакета 0, тот же слот тому же seeker — новый lease бакета 20.
    let (f20, x20) = only_accept(&find(&mut n, &a, 20, 802));
    assert_eq!(x20.issued_bucket, 20, "фальсификатор (д): второй lease не бакета 20");
    assert_eq!((x20.slot, x20.target), (x0.slot, x0.target), "фальсификатор (ж): слот/цель съехали");
    assert_ne!(f20, f0, "фальсификатор (д): строка бакета 0 пережила собственный prune");
    assert_eq!(n.rendezvous.live(), 1, "фальсификатор (а): после prune осталась лишняя строка");
    assert_eq!(n.rendezvous.refused_full, 0, "фальсификатор (з): возврат дыры сопровождался отказом");

    // Порог (2): now = 40 — третий lease того же слота (prune бакета 20 ровно на 40,
    // E-0058), и он расходуется в той же памяти цели: слот возродился, а не «сожжён».
    let (f40, x40) = only_accept(&find(&mut n, &a, 40, 803));
    assert_eq!(x40.issued_bucket, 40, "фальсификатор (д): третий lease не бакета 40");
    let g2 = spend
        .consume(&f40, &n.me(), &owner.pubkey(), 40)
        .expect("фальсификатор (в): цель отвергла перерождённый слот — расход слота пожизненный");
    assert_eq!((g2.seeker, g2.slot, g2.issued_bucket), (a.pubkey(), x0.slot, 40), "фальсификатор (ж): grant второго lease");
    assert_eq!(spend.spent(), 2, "порог (2): в памяти цели ДВА одноразовых расхода одного слота");

    // Порог (3): одноразовость живёт внутри lease: повтор f40 — AlreadySpent, а мёртвый
    // f0 на now=40 — Expired (строгая проверка ПЕРЕД spent: неAlreadySpent).
    assert_eq!(
        spend.consume(&f40, &n.me(), &owner.pubkey(), 40),
        Err(rendezvous::AcceptError::AlreadySpent),
        "фальсификатор (б): повтор перерождённого lease обслужен"
    );
    assert_eq!(
        spend.consume(&f0, &n.me(), &owner.pubkey(), 40),
        Err(rendezvous::AcceptError::Expired),
        "фальсификатор (г): мёртвый lease дымит AlreadySpent вместо Expired"
    );

    eprintln!(
        "## пороги (1)…(3): lease бакета 0 расходется однажды; после prune тот же слот \
         тому же seeker выдаёт lease 20 (live 1, новых отказов 0), а на 40 — lease 40, \
         который расходуется в той же памяти цели (spent == 2, разные issued_bucket = \
         разные ключи); повтор lease 40 — AlreadySpent, предъявление мёртвого lease 0 \
         на 40 — Expired, не AlreadySpent ##"
    );
    remove(&d);
}
