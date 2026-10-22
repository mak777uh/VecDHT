//! Оракул H-0051/E-0051 (цикл разработки `ADR-0013`): v1-минимум предъявления.
//!
//! Порядок дисциплины: критерии приёмки заморожены в `ADR-0013` (коммит спеки до кода),
//! пороги ниже повторяют их дословно; это не наблюдательный оракул, а приёмка фичи —
//! поэтому реализация и тест в одном коммите, а зелёный `main` не прерывался.
//!
//! Проверяется живым узлом: `Find` у primary даёт подписанный `RendezvousAccept` (кадр F0,
//! как в `E-0044`…`E-0046`), сторона цели из `session.rs` обслуживает запрос только с
//! предъявлением; повтор — `AlreadySpent` через `TextError::Spend`; чужой список издателей
//! — `NotSignedByShardHolder`; пустое предъявление — `NoAccept`. Плюс байтовый оверхед
//! против бюджета §5.4 (`E-0026`: ≤ 1 МБ/запрос) и лимит `MAX_PRESENT_BYTES` на разборе.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, session, testing, Spend};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, IntentTextRequest, MatchResult, MAX_PRESENT_BYTES};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn primary_on(dir_name: &str) -> (vecdht_node::ShardNode, std::path::PathBuf) {
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

#[test]
fn serving_gate_requires_presentation_and_spend_once() {
    let (mut n, d) = primary_on("present-serving-gate");
    let owner = testing::identity(90);
    let seeker = testing::identity(91);

    n.on_frame(owner.pubkey(), &publish_frame(90), testing::clock(0))
        .expect("publish");
    let find = testing::find_frame(&seeker, &testing::vector(1), &[CLUSTER], 8, 7);
    let replies = n.on_frame(seeker.pubkey(), &find, testing::clock(0)).expect("find");

    let mr = replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
        .expect("MatchResult");
    let slot = mr.matches[0].slot;
    let f0: Vec<u8> = replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| e.frame.clone())
        .expect("один match — один приём");

    // Порог (1): живой приём предъявлен через present, serve_request пропускает расход.
    let req = session::encode_request_present(7, owner.pubkey(), slot, &f0);
    let issuers = [n.me()];
    let mut spend = Spend::new(300);
    let grant = session::serve_request(&req, &owner.pubkey(), &issuers, 0, &mut spend)
        .expect("порог (1): корректное предъявление обслуживается");
    assert_eq!(
        (grant.seeker, grant.shard, grant.slot, grant.issuer),
        (seeker.pubkey(), SHARD, slot, n.me()),
        "порог (1): grant связан с живым кадром"
    );

    // Порог (2): повтор того же кадра — отказ обслуживания (одноразовость на живом входе).
    assert_eq!(
        session::serve_request(&req, &owner.pubkey(), &issuers, 0, &mut spend),
        Err(session::TextError::Spend(rendezvous::AcceptError::AlreadySpent)),
        "фальсификатор (б): повтор предъявления обслужен"
    );

    // Порог (3): запрос без предъявления (путь до ADR-0013) — разборим, но не обслуживается.
    let bare = session::encode_request(7, owner.pubkey(), slot);
    assert!(session::parse_request(&bare, &owner.pubkey()).is_ok(), "разбор прежнего формата жив");
    assert_eq!(
        session::serve_request(&bare, &owner.pubkey(), &issuers, 0, &mut spend),
        Err(session::TextError::NoAccept),
        "фальсификатор (в): пустое предъявление обслужено"
    );

    // Порог (4): список издателей — перебор только по BadSignature.
    let wrong = [[3u8; 32]];
    let mut spend2 = Spend::new(300);
    assert_eq!(
        session::serve_request(&req, &owner.pubkey(), &wrong, 0, &mut spend2),
        Err(session::TextError::NotSignedByShardHolder),
        "фальсификатор (г): подпись чужого ключа пропущена"
    );
    let mixed = [[9u8; 32], n.me()];
    assert!(
        session::serve_request(&req, &owner.pubkey(), &mixed, 0, &mut spend2).is_ok(),
        "порог (4): верный издатель второй в списке — перебор сработал"
    );

    // Порог (5): байтовый оверхед против бюджета §5.4 — present = кадр + префикс длины.
    // Пустой present тоже стоит 2 Б (u16-префикс): bare=54 против 52 до ADR-0013;
    // предъявленный запрос дороже пустого ровно на байты кадра.
    let delta = req.len() - bare.len();
    assert_eq!(bare.len(), 54, "пустой present стоит +2 Б к прежнему запросу (52 Б)");
    assert_eq!(delta, f0.len(), "оверхед предъявления = байты кадра приёма (u16-префикс уже в bare)");
    assert!(f0.len() <= MAX_PRESENT_BYTES, "живой кадр приёма влезает в лимит 512");
    eprintln!(
        "## оверхед: bare {} Б → present {} Б (+{} Б на кадр {} Б ≤ лимит {}; против 52 Б до ADR-0013 —          +{} Б на предъявление) ##",
        bare.len(),
        req.len(),
        delta,
        f0.len(),
        MAX_PRESENT_BYTES,
        req.len() - 52
    );

    // Порог (6): разбор с present поверх лимита — DecodeError, а не тихий обрез.
    let fat = IntentTextRequest {
        query_id: 7,
        target_ed25519: owner.pubkey(),
        slot,
        present: vec![0x50; MAX_PRESENT_BYTES + 1],
    }
    .encode_unsigned();
    assert!(IntentTextRequest::decode(&fat).is_err(), "фальсификатор (д): лимит present не соблюдён");

    eprintln!("## пороги (1)…(6): предъявление обязательно, расход одноразов на живом входе, перебор кандидатов, оверхед и лимит в норме ##");
    remove(&d);
}
