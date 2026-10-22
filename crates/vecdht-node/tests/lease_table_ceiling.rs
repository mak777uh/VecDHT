//! Оракул H-0044/E-0044: потолок lease-таблицы §12.3 на живом узле и идемпотентность повтора.
//!
//! «Что при потолке» и «повтор в том же бакете» в `tests/rendezvous.rs` объявлены предметом
//! unit-тестов; здесь меряется стык с живым `handle_find`: второй `Find` в том же бакете —
//! побайтово тот же приём и ноль новых строк, а запрос при полной таблице сохраняет
//! подписанный `MatchResult` с совпадением, теряя только приёмы (никакого `ProtocolError`).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, Find, MatchResult, ProtocolError, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

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
    assert!(n.is_primary(), "отвечает на Find и выпускает приёмы primary эпизоды");
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

fn find_frame(agent: &vecdht_crypto::Identity) -> Vec<u8> {
    Find {
        preprocessing_version: testing::PREPROCESSING_VERSION,
        query_vector: testing::vector(1),
        clusters: vec![CLUSTER],
        top_k: 8,
        query_id: 91,
        requester_ed25519: agent.pubkey(),
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

fn match_result(replies: &[vecdht_node::Envelope]) -> Option<MatchResult> {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
}

fn accept_frames(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
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
fn repeat_find_in_same_bucket_is_idempotent_and_ceiling_keeps_the_match_result() {
    let (mut n, d) = primary_on("lease-ceiling");
    let pub_agent = testing::identity(77);
    n.on_frame(pub_agent.pubkey(), &publish_frame(77), testing::clock(0))
        .expect("publish");
    assert_eq!(n.store.len(), 1, "одна живая запись — один будущий match");

    // Шаг 1…3: seeker A, бакет 0, повтор в том же бакете, затем бакет 1.
    let a = testing::identity(88);
    let me_a = a.pubkey();
    let r1 = n.on_frame(me_a, &find_frame(&a), testing::clock(0)).expect("find 1");
    let m1 = match_result(&r1).expect("первый MatchResult");
    assert_eq!(m1.matches.len(), 1);
    let f1 = accept_frames(&r1);
    assert_eq!(f1.len(), 1, "одно совпадение — один приём");
    assert_eq!(n.rendezvous.live(), 1, "строка таблицы ровно одна");

    let r2 = n.on_frame(me_a, &find_frame(&a), testing::clock(0)).expect("find 2");
    let f2 = accept_frames(&r2);
    // Порог (1): повтор — побайтово тот же кадр и НОВАЯ строка отсутствует (фальсификатор (а)).
    assert_eq!(f2.len(), 1);
    assert_eq!(f2[0].0, f1[0].0, "приём в том же бакете обязан быть побайтово тем же");
    assert_eq!(n.rendezvous.live(), 1, "фальсификатор (а): повтор съел вторую строку таблицы");

    let r3 = n.on_frame(me_a, &find_frame(&a), testing::clock(16)).expect("find 3");
    let f3 = accept_frames(&r3);
    assert_eq!(f3.len(), 1);
    assert_eq!(f3[0].1.issued_bucket, 1, "фальсификатор (г): бакет не повлиял на выпуск");
    assert_ne!(f3[0].0, f1[0].0, "новый бакет — новый приём");
    assert_eq!(n.rendezvous.live(), 2, "порог (1): live 1 → 1 → 2");

    // Шаг 4: дозаполнение до потолка на бакете 1 (prune при now_bucket=1 ничего не выбрасывает).
    let need = rendezvous::MAX_ACCEPTS - n.rendezvous.live();
    for i in 0..need {
        let mut seeker = [0u8; 32];
        seeker[..4].copy_from_slice(&(i as u32).to_le_bytes());
        let slot = 1000 + i as u32;
        assert!(
            n.rendezvous.issue(seeker, me_a, SHARD, slot, 1).is_some(),
            "строка №{i} обязала быть выпущена до потолка"
        );
    }
    // Порог (2): live ровно MAX_ACCEPTS (фальсификатор (в): мягкого потолка нет).
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS);

    // Шаг 5: свежий ключ B при бакете 1 — graceful degradation из §12.3.
    let b = testing::identity(89);
    let me_b = b.pubkey();
    let refused_before = n.rendezvous.refused_full;
    let r5 = n.on_frame(me_b, &find_frame(&b), testing::clock(16)).expect("find B");
    let m5 = match_result(&r5).expect("фальсификатор (б): при потолке MatchResult обязан остаться");
    assert_eq!(m5.matches.len(), 1, "совпадение не теряется");
    assert!(accept_frames(&r5).is_empty(), "приёмов при потолке — ноль");
    assert!(
        error_to(&r5, me_b).is_none(),
        "фальсификатор (б): отказ в приёме не обязан быть ошибкой поиска"
    );
    // Порог (3): ровно +1 к refusals, потолок не расширился.
    assert_eq!(n.rendezvous.refused_full - refused_before, 1, "фальсификатор (в): refusal не учтён");
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (в): live превысил потолок");

    eprintln!(
        "## пороги (1)…(3): live 1→1→2 при повторе/новом бакете; таблица 100 000 ровно; \
         Find при потолке: MatchResult c 1 match, 0 приёмов, 0 ошибок, refused_full +1 ##"
    );
    remove(&d);
}
