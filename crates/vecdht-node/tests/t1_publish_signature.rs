//! T1 / H-0164: подпись `Publish` обязательна — кадр без неё не доходит до двери.
//!
//! Три исхода, и каждый назван отдельно: неподписанный кадр дверь `on_frame` отбрасывает молча
//! (матрица §5.3); кадр, подписанный не заявленным владельцем, получает `DENIED`; честно
//! подписанный владельцем принимается и попадает в индекс. Матрица проверяется
//! отдельным случаем: без неё `handle_publish` защищает только тот путь, где кадр дошёл.
//!
//! Шард 7 — как в гейтах P4: ноль в качестве «удобного» значения скрыл бы ошибку маршрута (§7.4).

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, ProtocolError, Publish};
use vecdht_wire::{domain, Kind};

const SHARD: u16 = 7;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const TTL: u16 = 225;

fn params() -> Params {
    testing::params(POW)
}

/// Узел шарда, принявший genesis эпохи 1 (тот же порядок, что в `tests/admission.rs`).
fn primary_on(dir_name: &str) -> (ShardNode, std::path::PathBuf) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = testing::node(&d, SHARD, seed, params(), &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "писать умеет только primary эпизоды");
    (n, d)
}

fn error_to(replies: &[vecdht_node::Envelope], peer: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == peer)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

/// Кадр по `PublishSpec`: `vec_q` живёт в функции, потому что `PublishSpec` держит срез, а
/// `Publish` владеет массивом. Возврат `PublishSpec` из помощника оставлял бы срез на временном.
fn spec_msg(id: &Identity, vec_seed: u8, tlv: Vec<(u16, Vec<u8>)>) -> Publish {
    let vec_q = testing::vector(vec_seed);
    testing::PublishSpec {
        agent: id,
        vec_q: &vec_q,
        cluster_id: SHARD * 16,
        shard: SHARD,
        epoch: 1,
        published_bucket: 0,
        ttl_buckets: TTL,
        bits: POW,
    }
    .msg(tlv)
}

fn signed_frame(id: &Identity, msg: &Publish) -> Vec<u8> {
    let body = msg.body_bytes();
    let sig = id.sign_body(domain::PUBLISH, Kind::Publish, &body);
    msg.encode_signed(&sig)
}

#[test]
fn unsigned_publish_never_reaches_the_door() {
    let (mut n, d) = primary_on("t1-unsigned");
    let agent = testing::identity(60);
    let msg = spec_msg(&agent, 1, Vec::new());
    let out = n
        .on_frame(agent.pubkey(), &msg.encode_unsigned(), testing::clock(0))
        .expect("on_frame");
    assert!(out.is_empty(), "неподписанный Publish дверь отбрасывает молча: {out:?}");
    assert!(n.store.is_empty(), "и в индекс не попадает");
    remove(&d);
}

#[test]
fn publish_signed_by_someone_else_is_denied() {
    let (mut n, d) = primary_on("t1-wrong-key");
    let agent = testing::identity(61);
    let attacker = testing::identity(62);
    let msg = spec_msg(&agent, 2, Vec::new());
    let frame = signed_frame(&attacker, &msg);
    let out = n
        .on_frame(attacker.pubkey(), &frame, testing::clock(0))
        .expect("on_frame");
    let err = error_to(&out, attacker.pubkey()).expect("подпись чужим ключом — отказ, а не тишина");
    assert_eq!(err.code, err_code::DENIED, "отказ обязан быть DENIED: {err:?}");
    assert!(n.store.is_empty(), "запись под чужим владельцем не создаётся");
    remove(&d);
}

#[test]
fn publish_signed_by_the_owner_is_accepted() {
    let (mut n, d) = primary_on("t1-signed");
    let agent = testing::identity(63);
    let msg = spec_msg(&agent, 3, Vec::new());
    let frame = signed_frame(&agent, &msg);
    let out = n
        .on_frame(agent.pubkey(), &frame, testing::clock(0))
        .expect("on_frame");
    // `PublishAck` выдаётся после `w ≥ 2` подтверждений (см. `awaiting` в `handle_publish`),
    // а у этого узла реплик нет: принятие наблюдается записью и отсутствием `Error`, а не ack.
    assert!(error_to(&out, agent.pubkey()).is_none(), "честный кадр не должен получить Error");
    assert_eq!(n.store.len(), 1, "запись в индексе");
    assert!(n.store.index.owner_slot(&agent.pubkey()).is_some(), "слот владельца");
    remove(&d);
}

#[test]
fn the_matrix_requires_the_publish_signature() {
    assert!(Kind::Publish.signature_required(), "Publish обязан быть в матрице §5.3");
}
