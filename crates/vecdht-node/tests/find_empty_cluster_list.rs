//! Оракул E-0038, пороги (1)…(2): пустой список кластеров в `Find` обслуживается без отказа —
//! узел тратит токен квоты, расписывает пустой `MatchResult` и не подаёт никакого признака
//! «здесь был запрос в никуда».
//!
//! Harness — `tests/admission.rs` / `find_admission_price.rs`: шард 7, primary после genesis,
//! свежий ключ. Пустой индекс — часть метода: `SHARD_MISMATCH` на пустом итераторе (`any()` равно
//! `false`) не срабатывает ни при каких данных, а `search` по пустому множеству зондов не делает
//! ни одной оценки, поэтому содержимое шарда на исход влиять не может.
//!
//! Третий блок — не-primary узел: его исход только протоколируется (порог (3) из `H-0038`
//! фиксирует это заранее: утверждений там нет).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Params, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{err_code, Codec, MatchResult, ProtocolError};

const SHARD: u16 = 7;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn primary_on(dir_name: &str, p: Params) -> (ShardNode, std::path::PathBuf) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = testing::node(&d, SHARD, seed, p, &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "отвечает на Find только primary эпизоды");
    (n, d)
}

/// Узел того же шарда на сиде, который в порядке эпохи 1 НЕ первый: ровно тот же код, ровно
/// тот же кадр, другой статус эпизоды.
fn second_on(dir_name: &str, p: Params) -> (ShardNode, std::path::PathBuf, u8) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[1].owner_ed25519)
        .expect("второй в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let n = testing::node(&d, SHARD, seed, p, &SEEDS);
    assert!(!n.is_primary(), "второй в порядке по построению не primary");
    (n, d, seed)
}

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

fn match_result(replies: &[vecdht_node::Envelope]) -> Option<MatchResult> {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
}

#[test]
fn empty_cluster_list_is_served_as_signed_empty_result() {
    let (mut n, d) = primary_on("find-empty", testing::params(POW));
    let agent = testing::identity(203);
    let me = agent.pubkey();
    let frame = testing::find_frame(&agent, &testing::vector(1), &[], 8, 1);

    // Порог (1): пустой Find -> расписанный MatchResult с нулём matches, отказ отсутствует.
    let replies = n
        .on_frame(me, &frame, testing::clock(0))
        .expect("пустой find обязан обработаться");
    assert!(
        error_to(&replies, me).is_none(),
        "фальсификатор (а): узел отказал на пустом списке: {:?}",
        error_to(&replies, me).map(|e| e.code)
    );
    let res = match_result(&replies).expect("фальсификатор (а): вместо MatchResult — ничего");
    assert!(
        res.matches.is_empty(),
        "фальсификатор (б): пустой список зондов вернул {} matches",
        res.matches.len()
    );
    assert_eq!(res.query_id, 1, "query_id не протерялся");

    // Порог (2): пять пропущено, шестой — QUOTA_FIND/200: пустой кадр стоит ровно один токен.
    let mut codes: Vec<Option<String>> = Vec::new();
    for _ in 0..6 {
        let replies = n
            .on_frame(me, &frame, testing::clock(0))
            .expect("пустой find");
        codes.push(error_to(&replies, me).map(|e| e.code));
    }
    // Первый пропуск уже снят выше (запрос №1), здесь №2..=7 того же ключа: из семи пропущено
    // ровно пять (№1..№5 выше и здесь первые четыре), шестой и седьмой — QUOTA_FIND.
    let allowed = codes.iter().filter(|c| c.is_none()).count();
    assert_eq!(allowed, 4, "из №2..№7 пропустить следовало ровно четыре (бакет 5 с №1)");
    assert!(
        codes[4..].iter().all(|c| c.as_deref() == Some(err_code::QUOTA_FIND)),
        "шестой и седьмой пустой find обязаны быть QUOTA_FIND: {codes:?}"
    );
    eprintln!("## порог (1)(2): пустой список — пустой подписанный MatchResult; квота тратится как за обычный find ##");

    // Порог (3): не-primary — только факт, без утверждений.
    let (mut n2, d2, seed2) = second_on("find-empty-2", testing::params(POW));
    let agent2 = testing::identity(204);
    let me2 = agent2.pubkey();
    let frame2 = testing::find_frame(&agent2, &testing::vector(1), &[], 8, 1);
    match n2.on_frame(me2, &frame2, testing::clock(0)) {
        Ok(replies) => eprintln!(
            "## факт (не-primary, сид {seed2}): {} ответов; error={:?}; match_result={} ##",
            replies.len(),
            error_to(&replies, me2).map(|e| e.code),
            match_result(&replies).map(|r| r.matches.len()).is_some(),
        ),
        Err(e) => eprintln!("## факт (не-primary, сид {seed2}): NodeError: {e:?} ##"),
    }

    remove(&d);
    remove(&d2);
}
