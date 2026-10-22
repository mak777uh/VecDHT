//! Оракул H-0047/E-0047: «сколько живёт» §12.3 на живом стыке Find → Spend.
//!
//! Спека обещает: «на границе `now = issued + ceil(ttl/16)` повтор отклоняется как „уже
//! израсходован“, а в следующем бакете — как „истёк“», и держит lease-таблицу ровно столько
//! же. Единицы helper'ов сверены по сигнатурам до прогона (урок `E-0044`): `testing::clock`
//! принимает бакеты, не секунды; `buckets(300) = 19`; узел выписывает ttl из манифеста (300).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{buckets, candidates, rendezvous, testing, ShardNode, Spend};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const ACCEPT_TTL_SEC: u32 = 300;

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

fn accept_frames(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("accept")))
        .collect()
}

fn slot_of_match(replies: &[vecdht_node::Envelope]) -> u32 {
    let m = replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
        .expect("MatchResult");
    assert_eq!(m.matches.len(), 1);
    m.matches[0].slot
}

#[test]
fn accept_lives_inclusive_to_the_boundary_bucket_and_the_table_prunes_with_it() {
    let (mut n, d) = primary_on("ttl-boundary");
    let owner = testing::identity(77);
    let seeker = testing::identity(88);
    let me_s = seeker.pubkey();

    // Арифметика границы — из живого узла, а не из тестовых констант.
    assert_eq!(u32::from(n.rendezvous.ttl_sec()), ACCEPT_TTL_SEC, "узел берёт ttl из манифеста");
    assert_eq!(vecdht_wire::TIME_BUCKET_SEC, 16, "бакет 16 с — иначе граница 19 не выводится");
    assert_eq!(buckets(ACCEPT_TTL_SEC), 19, "пре-регистрационный факт: ceil(300/16) = 19");
    let boundary = buckets(u32::from(n.rendezvous.ttl_sec()));

    n.on_frame(owner.pubkey(), &publish_frame(77), testing::clock(0))
        .expect("publish");
    let f1 = n
        .on_frame(me_s, &testing::find_frame(&seeker, &testing::vector(1), &[CLUSTER], 8, 71), testing::clock(0))
        .expect("find@0");
    let slot = slot_of_match(&f1);
    let a0 = accept_frames(&f1);
    assert_eq!(a0.len(), 1);
    assert_eq!((a0[0].1.issued_bucket, a0[0].1.ttl_sec), (0, ACCEPT_TTL_SEC as u16));
    assert_eq!(n.rendezvous.live(), 1, "строка бакета 0 живёт с момента выпуска");

    // Порог (1): граница включительно. Расход в бакете 19 живого кадра — Ok;
    // повтор там же — AlreadySpent; бакет 20 — Expired (фальсификаторы (а)/(б)/(в)).
    let mut spend = Spend::new(ACCEPT_TTL_SEC as u16);
    spend
        .consume(&a0[0].0, &n.me(), &owner.pubkey(), boundary)
        .expect("фальсификатор (а): на границе now=issued+ceil(ttl/16) приём ещё действителен");
    assert_eq!(
        spend.consume(&a0[0].0, &n.me(), &owner.pubkey(), boundary),
        Err(rendezvous::AcceptError::AlreadySpent),
        "фальсификатор (б): на границе повтор обязан быть «уже израсходован», не «истёк»"
    );
    assert_eq!(
        spend.consume(&a0[0].0, &n.me(), &owner.pubkey(), boundary + 1),
        Err(rendezvous::AcceptError::Expired),
        "фальсификатор (в): в следующем бакете — «истёк»"
    );

    // Порог (2): таблица издателя живёт ровно столько же, включительно до границы.
    n.on_frame(me_s, &testing::find_frame(&seeker, &testing::vector(1), &[CLUSTER], 8, 72), testing::clock(boundary))
        .expect("find@19");
    assert_eq!(n.rendezvous.live(), 2, "фальсификатор (г): бакет 0 выброшен раньше срока");

    // Порог (3): на бакет позже границы строка 0 выбрасывается (2 = минус ноль, плюс 20).
    n.on_frame(me_s, &testing::find_frame(&seeker, &testing::vector(1), &[CLUSTER], 8, 73), testing::clock(boundary + 1))
        .expect("find@20");
    assert_eq!(n.rendezvous.live(), 2, "фальсификатор (д): таблица пережила ttl или потолок съеден");
    // Прямое доказательство: строка бакета 0 в таблице именно отсутствует (повторный выпуск
    // с now_bucket=0 возвращает Some и добавляет строку, а не идемпотентно даёт live 2).
    let again = n
        .rendezvous
        .issue(me_s, owner.pubkey(), SHARD, slot, 0)
        .expect("фальсификатор (е): выпуск бакета 0 обязан был стать новым (строку выбросило)");
    assert_eq!(again.issued_bucket, 0);
    assert_eq!(n.rendezvous.live(), 3, "фальсификатор (д)/(е): идемпотентный Some — строка 0 выжила");

    eprintln!(
        "## пороги (1)…(3): расход живого кадра на границе 19 — Ok, повтор — AlreadySpent, \
         20 — Expired; live 1→2 при find@19; find@20 оставил 2, прямое переиздание бакета 0 \
         подняло live до 3 (строка 0 выброшена prune включительно до 19) ##"
    );
    remove(&d);
}
