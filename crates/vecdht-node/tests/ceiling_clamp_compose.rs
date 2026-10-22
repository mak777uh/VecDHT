//! Оракул H-0053/E-0053: порядок композиции clamp'а и потолка lease-таблицы (§12.3).
//!
//! `E-0049` померил clamp отдельно, `E-0048` — потолок отдельно. Здесь оба живём в одном
//! прогоне: 70 записей, `top_k_max = 64` (`node.rs:985`), в таблице ровно 40 свободных
//! слотов. Утверждение: clamp применяется ДО выпуска приёмов (поиск → `store.search` →
//! цикл по `res.matches`), поэтому отказ удостаивает хвост СРЕЗАННОГО списка — за один
//! `Find` отказов не больше 64, а не 1000, как мог бы дать запрошенный `top_k`.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, ProtocolError, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const N_RECORDS: usize = 70;
const TOP_K_MAX: usize = 64;
const FREE: usize = 40;

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

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

#[test]
fn clamp_runs_before_issue_so_the_ceiling_refuses_the_tail_of_the_clamped_list() {
    let (mut n, d) = primary_on("ceiling-clamp-compose");
    for i in 0..N_RECORDS {
        n.on_frame(
            testing::identity(100 + i as u8).pubkey(),
            &publish_frame(100 + i as u8, 1 + i as u8),
            testing::clock(0),
        )
        .expect("publish");
    }
    assert_eq!(n.store.len(), N_RECORDS, "70 живых записей в кластере 112");

    // Дыр в таблице ровно FREE: дальше каждый новый ключ удостаивается отказа.
    let fill = rendezvous::MAX_ACCEPTS - FREE;
    let junk = [9u8; 32];
    for i in 0..fill {
        assert!(
            n.rendezvous
                .issue(junk, testing::identity(90).pubkey(), SHARD, 10_000 + i as u32, 0)
                .is_some(),
            "строка №{i} обязана влезть до дыры"
        );
    }
    assert_eq!(n.rendezvous.live(), fill, "фальсификатор (д): таблица заполнена ровно на дыру");

    let a = testing::identity(88);
    let me_a = a.pubkey();

    // Порог (1): find@1000 при 40 свободных слотах → 64 находки, 40 приёмов, 24 отказа.
    let r = n.on_frame(me_a, &find(&a, 1000, 91), testing::clock(0)).expect("find@1000");
    let m = match_result(&r).expect("фальсификатор (г): MatchResult обязан выжить при потолке");
    assert_eq!(
        m.matches.len(),
        TOP_K_MAX,
        "порог (1): clamp до top_k_max применяется до поиска — 64 находки, не 70 и не 1000"
    );
    let acc = accepts(&r);
    assert_eq!(acc.len(), FREE, "порог (1): свободных слотов ровно {FREE}");
    for (i, (_, x)) in acc.iter().enumerate() {
        assert_eq!(
            (x.target, x.slot),
            (m.matches[i].owner_ed25519, m.matches[i].slot),
            "фальсификатор (б): выпущен приём №{i} не первой пары сортированного списка"
        );
    }
    assert_eq!(
        n.rendezvous.refused_full,
        (TOP_K_MAX - FREE) as u64,
        "фальсификатор (а): за один Find отказов 24 = хвост срезанного списка, а не 960 от запрошенного top_k"
    );
    assert!(error_to(&r, me_a).is_none(), "фальсификатор (г): отказ в приёме — не ошибка поиска");
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (д)");

    // Порог (2): повтор в том же бакете — те же 40 побайтово, refusal-счётчик +24.
    let r2 = n.on_frame(me_a, &find(&a, 1000, 92), testing::clock(0)).expect("find@1000 повтор");
    let m2 = match_result(&r2).expect("MatchResult цел и в повторе");
    assert_eq!(m2.matches.len(), TOP_K_MAX, "порог (2): находок столько же");
    let a2 = accepts(&r2);
    assert_eq!(a2.len(), FREE, "порог (2): строки таблицы отдают тот же префикс");
    for i in 0..FREE {
        assert_eq!(a2[i].0, acc[i].0, "приём №{i} повтора обязан быть побайтово тем же");
    }
    assert_eq!(
        n.rendezvous.refused_full,
        2 * (TOP_K_MAX - FREE) as u64,
        "фальсификатор (а)-повтор: хвост удостаивается отказа заново, а не молча"
    );
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (д)");

    // Порог (3): тот же агент find@8 при ПОЛНОЙ таблице — 8/8 побайтовый префикс, отказов ноль.
    let refused_before_small = n.rendezvous.refused_full;
    let r3 = n.on_frame(me_a, &find(&a, 8, 93), testing::clock(0)).expect("find@8");
    let m3 = match_result(&r3).expect("фальсификатор (г): и при clamp@8 MatchResult цел");
    assert_eq!(m3.matches.len(), 8, "порог (3): top_k=8 ниже потолка — 8 находок");
    for i in 0..8 {
        assert_eq!(
            (m3.matches[i].owner_ed25519, m3.matches[i].slot, m3.matches[i].d2),
            (m.matches[i].owner_ed25519, m.matches[i].slot, m.matches[i].d2),
            "фальсификатор (в): префикс find@8 не совпал с головой find@1000 — сортировка зависит от размера запроса"
        );
    }
    let a3 = accepts(&r3);
    assert_eq!(a3.len(), 8, "фальсификатор (в): clamp@8 попал целиком в уже выписанные строки таблицы");
    for i in 0..8 {
        assert_eq!(a3[i].0, acc[i].0, "приём №{i} мелкого запроса обязан быть побайтово тем же");
    }
    assert_eq!(
        n.rendezvous.refused_full, refused_before_small,
        "фальсификатор (в): ни одного нового отказа при запросе, чей префикс уже в таблице"
    );
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (д)");

    eprintln!(
        "## пороги (1)…(3): find@1000 → 64 находки/40 приёма/24 отказа, повтор → те же 40 \
         побайтово/ещё +24, find@8 при полной таблице → 8/8 побайтовый префикс и 0 новых \
         отказов; live ровно 100 000, ProtocolError нет ##"
    );
    remove(&d);
}
