//! Оракул H-0045/E-0045: одноразовость расхода §12.3 — API встраивателя.
//!
//! Живой путь узла (`node.rs`) кадр `RendezvousAccept` не принимает и `Spend` не зовёт;
//! `IntentTextRequest` несёт ровно `query_id/target_ed25519/slot` — предъявить приём
//! нечем. Здесь меряется два факта: (1) сторона цели из `session.rs` обслуживает запрос
//! без всякого приёма (отсечь его не может), (2) библиотека `Spend` исправна — второй
//! расход того же кадра есть `AlreadySpent`.
//! АДДЕНДУМ 2026-10-22 (`ADR-0013`, `E-0051`): фикция закрыта — появился кадр
//! предъявления. `IntentTextRequest` несёт поле `present` (лимит `MAX_PRESENT_BYTES = 512`),
//! единственный путь обслуживания запроса — `session::serve_request`: пустое `present`
//! даёт `TextError::NoAccept`, подпись вне списка держателей шарда — `NotSignedByShardHolder`.
//! Живой гейт приёмки — `tests/present_serving_gate.rs` (`E-0051`).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, session, testing, Spend};

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
    assert!(n.is_primary(), "primary обязан выпускать приёмы");
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
fn target_side_serves_text_without_accept_and_spend_is_library_only() {
    let (mut n, d) = primary_on("accept-api-only");
    let owner = testing::identity(90);
    let seeker = testing::identity(91);

    n.on_frame(owner.pubkey(), &publish_frame(90), testing::clock(0))
        .expect("publish");

    // Живой приём: один подписанный кадр на одну находку (для порога (4)).
    let find = testing::find_frame(&seeker, &testing::vector(1), &[CLUSTER], 8, 7);
    let replies = n
        .on_frame(seeker.pubkey(), &find, testing::clock(0))
        .expect("find");
    let frames: Vec<Vec<u8>> = replies
        .iter()
        .filter(|e| {
            vecdht_wire::frame::decode_frame(&e.frame).map(|f| f.header.kind)
                == Ok(vecdht_wire::frame::Kind::RendezvousAccept)
        })
        .map(|e| e.frame.clone())
        .collect();
    assert_eq!(frames.len(), 1, "один match — один приём");

    // Порог (4): библиотека исправна — первый расход Ok, повтор AlreadySpent.
    let mut spend = Spend::new(300);
    let grant = spend
        .consume(&frames[0], &n.me(), &owner.pubkey(), 0)
        .expect("первый расход");
    assert_eq!((grant.seeker, grant.shard), (seeker.pubkey(), SHARD));
    assert_eq!(
        spend.consume(&frames[0], &n.me(), &owner.pubkey(), 0),
        Err(rendezvous::AcceptError::AlreadySpent),
        "фальсификатор (г)-часть: одноразовость типа не сломана"
    );

    // Порог (3): сторона цели из session.rs обслуживает запрос БЕЗ приёма.
    // Кадр запроса несёт ровно query_id/target/slot — поля для приёма нет (порог (2) —
    // инвентарь в скрипте), поэтому отсечь «непредъявившего» разбор не может.
    let req_frame = session::encode_request(7, owner.pubkey(), 3);
    let req = session::parse_request(&req_frame, &owner.pubkey())
        .expect("фальсификатор (в): разбор корректного запроса без приёма обязан пройти");
    assert_eq!((req.query_id, req.slot), (7, 3));
    let resp = session::sign_response(&owner, "granite", 1, "текст без предъявления")
        .expect("подпись ответа");
    let text = session::verify_response(&resp, &owner.pubkey()).expect("проверка ответа");
    assert!(!text.text.is_empty(), "ответ существует без всякого расхода приёма");
    // Единственная проверка адреса в parse_request — адресат, не приём.
    assert_eq!(
        session::parse_request(&req_frame, &seeker.pubkey()),
        Err(session::TextError::WrongTarget),
        "уровень фильтрации стороны цели — адресат"
    );

    eprintln!(
        "## пороги (3)…(4): запрос без приёма разборим и отвечен; чужому адресату — \
         WrongTarget; Spend::consume дважды — Ok затем AlreadySpent ##"
    );
    remove(&d);
}
