//! Admission-контроль §11.3 на живом узле: квоты, узловой бюджет, вытеснение.
//!
//! Здесь проверяется именно стык политики и протокола, а не арифметика бакетов (она — в
//! `admission::tests`). Каждый тест смотрит на байты, которые узел вернул агенту, и на индекс,
//! который остался после: «узел отказал» и «узел отказал кодом из §5.5» — разные утверждения, и
//! гейт обязан фиксировать второе.
//!
//! Шард 7 и кластер 112 — те же, что в гейтах P4: кластер принадлежит шарду по `>> 4`, и ноль в
//! качестве «удобного» значения скрыл бы ошибку маршрута (§7.4).

use std::rc::Rc;

use vecdht_index::testing::{dir, remove};
use vecdht_node::{admission, candidates, testing, Clock, Params, SharedAdmission, ShardNode};
use vecdht_wire::messages::{err_code, Codec, DeleteOp, OpKind, ProtocolError, ReplicateOp};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn params() -> Params {
    testing::params(POW)
}

/// Узел шарда, который уже принял genesis эпохи 1 и потому является primary с активным lease.
///
/// Genesis приносится напрямую в `on_frame`, как и в гейтах P4: источник истины — порог подписей
/// в теле перехода, а не тот, кто его принёс (§9.2).
fn primary_on(dir_name: &str, shard: u16, p: Params, shared: Option<SharedAdmission>) -> (ShardNode, std::path::PathBuf) {
    // Primary — первый в детерминированном порядке эпохи (§9.3), а не первый сид массива:
    // порядок зависит от шарда, и тест, открывший «не того», не является primary вовсе.
    let order = candidates::ordered(1, shard, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = match shared {
        Some(a) => ShardNode::open_with_admission(
            &d,
            shard,
            testing::identity(seed),
            testing::DHT_PEER_ID.to_vec(),
            p,
            testing::authority_set(),
            testing::holders(&SEEDS),
            a,
        )
        .expect("открыть узел"),
        None => testing::node(&d, shard, seed, p, &SEEDS),
    };
    let carrier = testing::identity(9).pubkey();
    n.on_frame(
        carrier,
        &testing::signed_frame(&testing::genesis_update(shard, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "тест дальше проверяет путь записи, а писать умеет только primary");
    assert!(n.serving_epoch(0).is_some(), "lease + durable-маркер = обслуживаем (§9.2)");
    (n, d)
}

fn cluster_of(shard: u16) -> u16 {
    shard << 4
}

/// Кадр publish от агента с заданной сложностью и вектором.
///
/// `vec_seed` меняет только вектор: `intent_id` от него зависит, поэтому PoW-вход другой, и
/// переиспользовать nonce между публикациями нельзя (§11.1).
fn publish_frame(agent_seed: u8, vec_seed: u8, shard: u16, bucket: u32, bits: u32, ttl: u16) -> Vec<u8> {
    let agent = testing::identity(agent_seed);
    testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(vec_seed),
        cluster_id: cluster_of(shard),
        shard,
        epoch: 1,
        published_bucket: bucket,
        ttl_buckets: ttl,
        bits,
    }
    .frame()
}

/// Код `Error`, адресованного агенту, если узел ответил отказом.
fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

#[test]
fn publish_quota_is_a_burst_of_twenty_then_one_per_second() {
    let (mut n, d) = primary_on("adm-quota", SHARD, params(), None);
    let agent = testing::identity(77);
    let me = agent.pubkey();
    for i in 0..20 {
        let frame = publish_frame(77, (i % 4) as u8, SHARD, 0, POW, 225);
        let replies = n.on_frame(me, &frame, testing::clock(0)).expect("секунда 0");
        assert!(error_to(&replies, me).is_none(), "publish №{i} обязан пройти в пределах burst");
    }
    let replies = n.on_frame(me, &publish_frame(77, 5, SHARD, 0, POW, 225), testing::clock(0)).expect("секунда 0");
    let err = error_to(&replies, me).expect("21-й publish в ту же секунду обязан получить Error");
    assert_eq!(err.code, err_code::QUOTA_PUBLISH);
    assert_eq!(err.retry_after_ms, 1_000, "1 publish/с ⇒ ждать ровно секунду");
    // Refill — целыми токенами в секунду: через секунду ровно один publish.
    let replies = n.on_frame(me, &publish_frame(77, 6, SHARD, 1, POW, 225), Clock::at(1)).expect("секунда 1");
    assert!(error_to(&replies, me).is_none());
    let replies = n.on_frame(me, &publish_frame(77, 7, SHARD, 1, POW, 225), Clock::at(1)).expect("секунда 1");
    assert_eq!(error_to(&replies, me).map(|e| e.code), Some(err_code::QUOTA_PUBLISH.to_string()));
    assert_eq!(n.admission.borrow().stats.rejected_publish_quota, 2);
    remove(&d);
}

#[test]
fn find_quota_is_five_per_second_keyed_by_the_transport_identity() {
    let (mut n, d) = primary_on("adm-find", SHARD, params(), None);
    let agent = testing::identity(78);
    let me = agent.pubkey();
    let frame = testing::find_frame(&agent, &testing::vector(1), &[CLUSTER], 8, 1);
    for i in 0..5 {
        let replies = n.on_frame(me, &frame, testing::clock(0)).expect("find");
        assert!(error_to(&replies, me).is_none(), "find №{i} в пределах 5/с");
    }
    let replies = n.on_frame(me, &frame, testing::clock(0)).expect("find");
    let err = error_to(&replies, me).expect("6-й find обязан получить Error");
    assert_eq!(err.code, err_code::QUOTA_FIND);
    assert_eq!(err.retry_after_ms, 200, "5/с ⇒ 200 мс");
    let replies = n.on_frame(me, &frame, Clock::at(1)).expect("find");
    assert!(error_to(&replies, me).is_none());
    remove(&d);
}

#[test]
fn shards_of_one_process_share_the_node_budget() {
    let p = params();
    let shared: SharedAdmission = admission::shared(&p);
    let (a, da) = primary_on("adm-share-a", SHARD, p, Some(shared.clone()));
    let (mut b, db) = primary_on("adm-share-b", SHARD + 1, p, Some(shared.clone()));
    assert!(Rc::ptr_eq(&a.admission, &b.admission), "один процесс — один admission (§11.3.4)");

    // Сжигаем весь узловой бюджет у шарда A. Шард B обязан увидеть тот же ноль: лимит — «на
    // узел», а не «на шард», и второй шард не должен получать собственные 100/с.
    for _ in 0..100 {
        assert!(a.admission.borrow_mut().reserve_admit(0).is_allow());
    }
    let agent = testing::identity(79);
    let frame = publish_frame(79, 1, SHARD + 1, 0, POW, 225);
    let replies = b.on_frame(agent.pubkey(), &frame, testing::clock(0)).expect("publish B");
    let err = error_to(&replies, agent.pubkey()).expect("бюджет узла исчерпан");
    assert_eq!(err.code, err_code::BUSY);
    assert_eq!(err.retry_after_ms, 10, "100 admits/с ⇒ 10 мс до следующего токена");

    let replies = b.on_frame(agent.pubkey(), &frame, Clock::at(1)).expect("publish B");
    assert!(error_to(&replies, agent.pubkey()).is_none(), "прошла секунда — бюджет восполнился");
    remove(&da);
    remove(&db);
}

#[test]
fn a_full_shard_still_accepts_a_republish_in_place() {
    let mut p = params();
    p.max_live_per_shard = 1;
    let (mut n, d) = primary_on("adm-replace", SHARD, p, None);
    let agent = testing::identity(80);
    let me = agent.pubkey();

    let replies = n.on_frame(me, &publish_frame(80, 1, SHARD, 0, POW, 225), testing::clock(0)).expect("первая");
    assert!(error_to(&replies, me).is_none());
    assert_eq!(n.store.len(), 1);

    // Тот же (owner, shard) с другим вектором: §6.5 разрешает замену на месте, и §11.3.2 не
    // должен превращать полный шард в замороженный — иначе M записей не смогли бы обновиться.
    let replies = n.on_frame(me, &publish_frame(80, 2, SHARD, 1, POW, 225), testing::clock(1)).expect("замена");
    assert!(error_to(&replies, me).is_none(), "полный шард не мешает перепубликации");
    assert_eq!(n.store.len(), 1, "замена не занимает второй slot");
    assert_eq!(n.evictor.evicted, 0, "никого не вытеснили");
    remove(&d);
}

#[test]
fn a_full_shard_evicts_the_cheaper_record_and_replicates_the_delete() {
    let mut p = params();
    p.max_live_per_shard = 1;
    let (mut n, d) = primary_on("adm-evict", SHARD, p, None);
    let cheap = testing::identity(81);
    let newcomer = testing::identity(82);

    let replies = n.on_frame(cheap.pubkey(), &publish_frame(81, 1, SHARD, 0, POW, 225), testing::clock(0)).expect("дешёвая");
    assert!(error_to(&replies, cheap.pubkey()).is_none());
    assert_eq!(n.store.index.owner_slot(&cheap.pubkey()), Some(0));

    // Новичок дороже на бит: §11.4(i) — «дешёвые записи вытесняются первыми».
    let replies = n.on_frame(newcomer.pubkey(), &publish_frame(82, 2, SHARD, 1, POW + 1, 225), testing::clock(1)).expect("новичок");
    assert!(error_to(&replies, newcomer.pubkey()).is_none(), "вытеснение обязано пропустить запись");
    assert_eq!(n.store.len(), 1, "вытеснение сохраняет потолок M");
    assert_eq!(n.store.index.owner_slot(&cheap.pubkey()), None, "дешёвая запись вытеснена");
    assert!(n.store.index.owner_slot(&newcomer.pubkey()).is_some());
    assert_eq!(n.evictor.evicted, 1);

    // Удаление — это WAL-фрейм и реплика, а не локальная правка RAM: иначе после handoff'а
    // реплика вернула бы вытесненную запись, и узлы разошлись бы (§8.3).
    let deletes: Vec<ReplicateOp> = replies
        .iter()
        .filter(|e| e.to != newcomer.pubkey())
        .filter_map(|e| ReplicateOp::decode(&e.frame).ok())
        .filter(|op| op.op_kind == OpKind::Delete)
        .collect();
    assert_eq!(deletes.len(), peers(&n), "delete уходит каждому пиру шарда");
    let expected = DeleteOp { owner_ed25519: cheap.pubkey(), shard: SHARD };
    assert_eq!(deletes[0].body, expected.body_bytes(), "реплика обязана применить ровно того же владельца");
    remove(&d);
}

#[test]
fn a_full_shard_refuses_a_newcomer_cheaper_than_everything_it_holds() {
    let mut p = params();
    p.max_live_per_shard = 1;
    let (mut n, d) = primary_on("adm-full", SHARD, p, None);
    let defender = testing::identity(83);
    let cheap = testing::identity(84);

    let replies = n.on_frame(defender.pubkey(), &publish_frame(83, 1, SHARD, 0, POW + 1, 225), testing::clock(0)).expect("дорогая");
    assert!(error_to(&replies, defender.pubkey()).is_none());

    // §11.3.3: вытеснять запись дороже принятой запрещено — значит отказ, а не «найдём хоть кого-то».
    let replies = n.on_frame(cheap.pubkey(), &publish_frame(84, 2, SHARD, 1, POW, 225), testing::clock(1)).expect("дешёвый");
    let err = error_to(&replies, cheap.pubkey()).expect("полный шард обязан отказать");
    assert_eq!(err.code, err_code::SHARD_FULL);
    assert_eq!(n.store.len(), 1);
    assert!(n.store.index.owner_slot(&defender.pubkey()).is_some(), "защитник не тронут");
    assert_eq!(n.store.index.owner_slot(&cheap.pubkey()), None);
    assert_eq!(n.evictor.evicted, 0);
    remove(&d);
}

#[test]
fn a_denied_key_pays_nothing_and_gets_no_second_chance() {
    let (mut n, d) = primary_on("adm-deny", SHARD, params(), None);
    let bad = testing::identity(85);
    assert!(n.admission.borrow_mut().deny(bad.pubkey()));
    let replies = n.on_frame(bad.pubkey(), &publish_frame(85, 1, SHARD, 0, POW, 225), testing::clock(0)).expect("deny");
    let err = error_to(&replies, bad.pubkey()).expect("denylist обязан ответить");
    assert_eq!(err.code, err_code::DENIED);
    // Отказ не тратит ни per-key токен, ни узловой бюджет: ключ всё равно не будет обслужен,
    // а бюджет должен достаться тем, кто может.
    let a = n.admission.borrow();
    assert_eq!(a.stats.rejected_publish_quota, 0);
    assert_eq!(a.stats.rejected_node_busy, 0);
    assert_eq!(a.stats.denied_by_denylist, 1);
    drop(a);
    remove(&d);
}

/// Сколько пиров у узла — столько и адресатов у реплики. Вынесено в функцию, чтобы тест не
/// дублировал `peers().len()`, который сам по себе часть контракта `replicate`.
fn peers(n: &ShardNode) -> usize {
    n.peers().len()
}
