//! Rendezvous-приём §12.3 на живом узле: выпуск, подпись, привязка к паре и одноразовость.
//!
//! Проверяется стык §5.3 и §12.3, а не арифметика TTL (она — в `rendezvous::tests`): приём
//! обязан прийти в том же ответе на `Find`, быть подписанным издателем, связывать именно
//! транспортный `from` с найденным `owner` и расходоваться целью ровно один раз. Всё остальное
//! («сколько живёт», «что при потолке») — unit-тесты модуля.
//!
//! Шард 7 и кластер 112 — как в гейтах P4: ноль скрыл бы ошибку маршрута (§7.4).

use vecdht_crypto::{verify_body, Identity};
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, Clock, Params, ShardNode, Spend};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{
    domain, Codec, Find, MatchResult, ProtocolError, RendezvousAccept,
};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn params() -> Params {
    testing::params(POW)
}

/// Узел шарда с genesis эпохи 1: только primary выпускает ответы на `Find` в этих тестах.
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
    assert!(n.is_primary(), "отвечать на Find должен primary эпизоды");
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

/// Один `Find`: `requester_ed25519` в теле можно подменить — кадр не подписан, и именно поэтому
/// приём обязан привязываться к транспортному `from`.
fn find_frame(requester: &Identity, cluster: u16) -> Vec<u8> {
    Find {
        preprocessing_version: testing::PREPROCESSING_VERSION,
        query_vector: testing::vector(1),
        clusters: vec![cluster],
        top_k: 8,
        query_id: 77,
        requester_ed25519: requester.pubkey(),
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

fn match_result(replies: &[vecdht_node::Envelope]) -> MatchResult {
    let frame = replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .map(|e| e.frame.as_slice())
        .expect("MatchResult обязан быть в ответе");
    MatchResult::decode(frame).expect("MatchResult")
}

fn accepts(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| {
            let acc = RendezvousAccept::decode(&e.frame).expect("RendezvousAccept");
            (e.frame.clone(), acc)
        })
        .collect()
}

#[test]
fn find_returns_one_signed_accept_per_match_bound_to_the_transport_identity() {
    let (mut n, d) = primary_on("rdv-issue");
    let owner = testing::identity(90);
    let seeker = testing::identity(91);
    let victim = testing::identity(92);

    let replies = n.on_frame(owner.pubkey(), &publish_frame(90), testing::clock(0)).expect("publish");
    assert!(error_to(&replies, owner.pubkey()).is_none(), "publish обязан пройти");

    // `requester_ed25519` в теле — жертва, а кадр пришёл от seeker: приём обязан назвать
    // seeker, иначе подделка тела привязывала бы чужой ключ к сессии.
    let replies = n.on_frame(seeker.pubkey(), &find_frame(&victim, CLUSTER), testing::clock(0)).expect("find");
    let res = match_result(&replies);
    assert_eq!(res.matches.len(), 1, "опубликованная запись обязана найтись");
    let m = res.matches[0];

    let got = accepts(&replies);
    assert_eq!(got.len(), 1, "ровно один приём на одну найденную запись");
    let (frame, acc) = &got[0];
    assert_eq!(
        (acc.seeker, acc.target, acc.shard, acc.slot, acc.issued_bucket, acc.ttl_sec),
        (seeker.pubkey(), owner.pubkey(), SHARD, m.slot, 0, 300),
        "seeker — from, target — owner из MatchResult, TTL — из манифеста"
    );

    // Подпись — Ed25519 кадра, издатель — сам узел (§12.3).
    let f = decode_frame(frame).expect("кадр");
    let sig: [u8; 64] = f.signature.expect("приём обязан быть подписан").try_into().expect("64");
    assert!(
        verify_body(&n.me(), domain::RENDEZVOUS, Kind::RendezvousAccept, f.body, &sig).unwrap(),
        "цель обязана уметь проверить издателя"
    );

    // Цель проверяет и расходует. Повтор — не вторая сессия.
    let mut spend = Spend::new(300);
    let grant = spend.consume(frame, &n.me(), &owner.pubkey(), 0).expect("приём действителен");
    assert_eq!((grant.seeker, grant.shard, grant.slot), (seeker.pubkey(), SHARD, m.slot));
    assert_eq!(
        spend.consume(frame, &n.me(), &owner.pubkey(), 0),
        Err(rendezvous::AcceptError::AlreadySpent),
        "одноразовость обеспечивает цель, а не издатель"
    );

    // Повторный Find в том же бакете не плодит записи: тот же приём, тот же бюджет таблицы.
    let replies = n.on_frame(seeker.pubkey(), &find_frame(&victim, CLUSTER), testing::clock(0)).expect("find");
    assert_eq!(accepts(&replies), vec![(frame.clone(), *acc)], "идемпотентность в бакете");
    assert_eq!((n.rendezvous.live(), n.rendezvous.issued), (1, 1));
    remove(&d);
}

#[test]
fn a_find_without_matches_issues_no_accept() {
    let (mut n, d) = primary_on("rdv-empty");
    let owner = testing::identity(93);
    let seeker = testing::identity(94);
    n.on_frame(owner.pubkey(), &publish_frame(93), testing::clock(0)).expect("publish");

    // Кластер 113 принадлежит тому же шарду, но в нём нет ни одной записи (§7.4): поиск
    // возвращает пустой MatchResult, и приём не на что выписывать.
    let replies = n.on_frame(seeker.pubkey(), &find_frame(&seeker, CLUSTER + 1), testing::clock(0)).expect("find");
    assert!(match_result(&replies).matches.is_empty());
    assert!(accepts(&replies).is_empty());
    assert_eq!((n.rendezvous.live(), n.rendezvous.issued), (0, 0));
    remove(&d);
}

#[test]
fn an_accept_stops_working_after_its_ttl() {
    let (mut n, d) = primary_on("rdv-ttl");
    let owner = testing::identity(95);
    let seeker = testing::identity(96);
    n.on_frame(owner.pubkey(), &publish_frame(95), testing::clock(0)).expect("publish");
    let replies = n.on_frame(seeker.pubkey(), &find_frame(&seeker, CLUSTER), Clock::at(0)).expect("find");
    let (frame, _) = accepts(&replies).pop().expect("приём");

    // 300 с — 19 бакетов: в бакете 19 приём ещё жив, в 20 — уже нет.
    let mut spend = Spend::new(300);
    assert!(spend.consume(&frame, &n.me(), &owner.pubkey(), 19).is_ok());
    assert_eq!(
        spend.consume(&frame, &n.me(), &owner.pubkey(), 19),
        Err(rendezvous::AcceptError::AlreadySpent),
        "повтор в пределах TTL — не вторая сессия"
    );
    // В 20-м бакете проверка истечения стоит раньше проверки расхода, поэтому тот же байт
    // отвечает «Expired», а не «AlreadySpent»: цель не обязана помнить истёкшее.
    let mut fresh = Spend::new(300);
    assert_eq!(
        fresh.consume(&frame, &n.me(), &owner.pubkey(), 20),
        Err(rendezvous::AcceptError::Expired)
    );
    remove(&d);
}
