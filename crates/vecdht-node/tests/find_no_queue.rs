//! Оракул E-0041, пороги (1)…(3): очереди `Find` с ограничением по времени (§11.3.6, п. 6
//! спеки) в коде нет — каждый легальный кадр получает финальный ответ в том же вызове
//! `on_frame`, повтор идентичного кадра даёт побайтово тот же ответ, а sybil-пачка из
//! `E-0039`-подобного сценария не оставляет ни одного кадра без ответа.
//!
//! Пустой индекс: при нуле матчей узел обязан ровно одним конвертом (`out` в `handle_find`
//! ёмкостью `1 + matches.len()`), значит «кадр задержан/отложен» наблюдаемо как пустой
//! список ответов — фальсификатор (а).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, MatchResult, ProtocolError};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const LIST_LEN: usize = 4096;
const KEYS: u8 = 21;

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
    assert!(n.is_primary(), "отвечает на Find primary эпизоды");
    (n, d)
}

#[test]
fn an_expensive_find_is_fixed_in_one_answer_and_repeats_byte_identically() {
    let (mut n, d) = primary_on("find-no-queue", testing::params(POW));
    let agent = testing::identity(201);
    let me = agent.pubkey();
    // Кадр из `E-0037`: полный список 4096 кластеров своего шарда — самый дорогой легальный.
    let list: Vec<u16> = vec![CLUSTER; LIST_LEN];
    let frame = testing::find_frame(&agent, &testing::vector(1), &list, 8, 1);

    // Порог (1): ответ — в том же вызове, ровно один кадр, декодируется как MatchResult.
    let r1 = n.on_frame(me, &frame, testing::clock(0)).expect("find #1");
    assert_eq!(r1.len(), 1, "легальный find обязан фиксироваться одним ответом сразу");
    assert_eq!(r1[0].to, me, "ответ адресован запросившему");
    let m1 = MatchResult::decode(&r1[0].frame).expect("первый ответ — MatchResult, не отсрочка");
    assert_eq!(m1.matches.len(), 0, "пустой индекс");
    assert_eq!(m1.query_id, 1, "echo запроса — часть того же мгновенного ответа");

    // Порог (2): повтор идентичного кадра при той же секунде — побайтово тот же ответ:
    // состояния «в очереди», меняющего судьбу кадра, нет (ed25519 детерминирован на теле).
    let r2 = n.on_frame(me, &frame, testing::clock(0)).expect("find #2");
    assert_eq!(r2.len(), 1);
    assert_eq!(r1[0].frame, r2[0].frame, "разные байты на идентичный кадр — где-то есть состояние");
    remove(&d);
}

#[test]
fn the_sybil_surge_leaves_no_frame_without_an_answer() {
    let (mut n, d) = primary_on("find-no-queue-surge", testing::params(POW));
    // Сценарий E-0039 (21 ключ × 6 кадров), список — законные 16 кластеров своего шарда.
    let list: Vec<u16> = (0..16u16).map(|i| CLUSTER + i).collect();
    let mut match_frames = 0usize;
    let mut err_frames = 0usize;
    for k in 0..KEYS {
        let agent = testing::identity(220 + k);
        let me = agent.pubkey();
        let frame = testing::find_frame(&agent, &testing::vector(1), &list, 8, 1);
        for _ in 0..6 {
            let replies = n.on_frame(me, &frame, testing::clock(0)).expect("find");
            assert_eq!(replies.len(), 1, "кадр ключа {k} без единственного адресованного ответа");
            assert_eq!(replies[0].to, me);
            if MatchResult::decode(&replies[0].frame).is_ok() {
                match_frames += 1;
            } else {
                let e = ProtocolError::decode(&replies[0].frame).expect("иначе это Error");
                assert_eq!(e.code, err_code::QUOTA_FIND, "отказ не из квоты find: {}", e.code);
                err_frames += 1;
            }
        }
    }
    // Порог (3): ровно 105 мгновенных MatchResult + 21 мгновенный Error/QUOTA_FIND.
    assert_eq!(match_frames, 126 - usize::from(KEYS), "пропущенных-без-ответа кадров быть не может");
    assert_eq!(err_frames, usize::from(KEYS), "отказ должен быть ровно квотный, кадром на кадр");
    eprintln!(
        "## порог (3): {match_frames} MatchResult + {err_frames} QUOTA_FIND, все в теле on_frame ##"
    );
    remove(&d);
}
