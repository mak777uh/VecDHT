//! Оракул H-0049/E-0049: живой путь `handle_find` срезает `q.top_k` до `top_k_max = 64`,
//! а §12.3 обещает «по одному кадру RendezvousAccept на каждый Match (до top_k)».
//! Байтовая арифметика `E-0026` и чтение `E-0037` фиксировали существование clamp'а
//! (`node.rs:985`), но ни разу не мерили его поведение на живом запросе при >64 записях:
//! сколько находок, сколько приёмов, как ведёт себя таблица при повторе с меньшим top_k.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const N_RECORDS: usize = 70;

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

fn match_result(replies: &[vecdht_node::Envelope]) -> Option<MatchResult> {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
}

fn accepts(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("accept")))
        .collect()
}

#[test]
fn live_find_clamps_top_k_to_64_and_issues_one_accept_per_match() {
    let (mut n, d) = primary_on("top-k-clamp-live");
    for i in 0..N_RECORDS {
        n.on_frame(
            testing::identity(100 + i as u8).pubkey(),
            &publish_frame(100 + i as u8, 1 + i as u8),
            testing::clock(0),
        )
        .expect("publish");
    }
    assert_eq!(n.store.len(), N_RECORDS, "70 живых записей в кластере 112");

    let a = testing::identity(88);
    let me_a = a.pubkey();

    // Порог (1)+(2): завышенный q.top_k срезан до 64; приём — ровно по кадру на находку.
    let r = n
        .on_frame(me_a, &find(&a, 1000, 101), testing::clock(0))
        .expect("find 1000");
    let m = match_result(&r).expect("фальсификатор (а): MatchResult при clamp'е существует");
    assert_eq!(m.matches.len(), 64, "порог (1):matches == min(q.top_k, top_k_max) == 64");
    let acc = accepts(&r);
    assert_eq!(acc.len(), 64, "порог (1): по кадру приёма на каждый Match (до top_k)");
    for (i, (_, x)) in acc.iter().enumerate() {
        assert_eq!(
            (x.target, x.slot),
            (m.matches[i].owner_ed25519, m.matches[i].slot),
            "фальсификатор (б): приём №{i} не по паре (owner, slot) находки №{i}"
        );
    }
    for w in m.matches.windows(2) {
        assert!(
            (w[0].d2, w[0].slot) <= (w[1].d2, w[1].slot),
            "фальсификатор (д): срезанный список неканонически отсортирован"
        );
    }
    assert_eq!(n.rendezvous.live(), 64, "фальсификатор (в): таблица = число выпущенных приёма");
    assert_eq!(n.rendezvous.refused_full, 0, "фальсификатор (в): до потолка далеко, отказов нет");

    // Порог (3): top_k ниже потолка — узел не добавляет сверх запрошенного.
    let r2 = n.on_frame(me_a, &find(&a, 32, 102), testing::clock(0)).expect("find 32");
    let m2 = match_result(&r2).expect("MatchResult при top_k=32");
    assert_eq!(m2.matches.len(), 32, "порог (3): min(32, 64) == 32");
    let a2 = accepts(&r2);
    assert_eq!(a2.len(), 32, "порог (3): приёмы ровно по списку");
    assert_eq!(n.rendezvous.live(), 64, "порог (3): префиксные ключи уже в таблице — идемпотентность");

    // Порог (4): top_k == потолку — побайтовые повторы первого Find (сортировка детерминирована).
    let r3 = n.on_frame(me_a, &find(&a, 64, 103), testing::clock(0)).expect("find 64");
    let m3 = match_result(&r3).expect("MatchResult при top_k=64");
    assert_eq!(m3.matches.len(), 64);
    let a3 = accepts(&r3);
    assert_eq!(a3.len(), 64, "фальсификатор (в): повтор не удвоил таблицу");
    assert_eq!(n.rendezvous.live(), 64, "фальсификатор (в): live заперт на 64");
    for i in 0..64 {
        assert_eq!(a3[i].0, acc[i].0, "приём №{i} при top_k=64 обязан быть побайтово тем же");
        assert_eq!(
            (m3.matches[i].owner_ed25519, m3.matches[i].slot, m3.matches[i].d2),
            (m.matches[i].owner_ed25519, m.matches[i].slot, m.matches[i].d2),
            "фальсификатор (г): усечённый список не является префиксом полного"
        );
    }
    eprintln!("## пороги (1)…(4): clamp 64/32/64, приёмы 1:1, префикс побайтово, live заперт ##");
    remove(&d);
}
