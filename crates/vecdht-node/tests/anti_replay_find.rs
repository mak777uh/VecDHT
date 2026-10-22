//! Оракул H-0043/E-0043: anti-replay §14.3 на пути `Find`.
//!
//! Спека обещает «`query_id` дедуплицируется на узле 60 с» и «|now − timestamp| < 30 с».
//! Здесь меряется поведенческая половина: три кадра с одним `query_id` (t=0, t=0, t=61)
//! получают три адресованных ответа, побайтово одинаковых — состояния дедупа на узле нет,
//! и подавлять повтор нечему. Инвентари (поле времени, позиции `query_id`, множества) —
//! в `lab/e0043-run.sh`.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, ShardNode};
use vecdht_wire::messages::{Codec, MatchResult};

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
    assert!(n.is_primary(), "отвечает на Find primary эпизоды");
    (n, d)
}

fn answer_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<MatchResult> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| MatchResult::decode(&e.frame).ok())
}

#[test]
fn the_same_query_id_is_answered_again_and_again_including_after_61_seconds() {
    let (mut n, d) = primary_on("anti-replay");
    let agent = testing::identity(31);
    let me = agent.pubkey();
    // Один и тот же кадр: query_id=7, вектор, список кластеров, top_k — идентичны во всех трёх.
    let frame = testing::find_frame(&agent, &testing::vector(1), &[CLUSTER], 8, 7);

    // t=0: первый и второй ответы (окно «60 с» из спеки, если бы состояние было, задавило бы второе).
    let r1 = n.on_frame(me, &frame, testing::clock(0)).expect("find 1");
    let r2 = n.on_frame(me, &frame, testing::clock(0)).expect("find 2");
    // Порог (1): по одному адресованному MatchResult в каждом пучке, пустой индекс — пустой список.
    let m1 = answer_to(&r1, me).expect("первый ответ");
    let m2 = answer_to(&r2, me).expect("фальсификатор (в): второй ответ с тем же query_id");
    assert_eq!(m2.query_id, 7, "второй ответ несёт тот же id — это повтор, а не новый запрос");
    assert_eq!(m1.matches.len(), 0);
    assert_eq!(m1.query_id, 7, "id эхом возвращается, но ничем не расходуется");
    // Порог (1, продолжение): побайтовое равенство — повтор не просто отвечен, а отвечен идентично.
    let f1 = r1.iter().find(|e| e.to == me).expect("конверт 1");
    let f2 = r2.iter().find(|e| e.to == me).expect("конверт 2");
    assert_eq!(f1.frame, f2.frame, "повтор кадра обязан дать побайтово тот же ответ");

    // Порог (2): t=61 — «окно 60 с» истекло бы даже гипотетически; проверяется отсутствие и окна.
    let r3 = n.on_frame(me, &frame, testing::clock(61)).expect("find 3");
    let m3 = answer_to(&r3, me).expect("фальсификатор (в): ответ через 61 с");
    assert_eq!(m3.query_id, 7);
    let f3 = r3.iter().find(|e| e.to == me).expect("конверт 3");
    assert_eq!(f1.frame, f3.frame, "ответ через 61 с побайтово равен ответу при t=0");

    eprintln!(
        "## пороги (1)…(2): три адресованных MatchResult (t=0, 0, 61), все побайтово равны; \
         повтор с одним query_id принят трижды ##"
    );
    remove(&d);
}
