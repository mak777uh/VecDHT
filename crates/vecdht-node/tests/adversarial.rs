//! Adversarial-набор §19.3 и гейт P5 (§18.6).
//!
//! Здесь проверяются атаки, у которых есть проверяемое следствие в коде v1, а не «плохие
//! намерения» вообще:
//!
//! * pre-farmed PoW: nonce, намайненный для другого шарда/эпизоды/срока/intent'а, отвергается;
//! * чужой `preprocessing_version` не попадает ни в индекс, ни в matching (`MODEL_MISMATCH`);
//! * `ReplicateOp` со старой эпизодой или чужим подписантом не применяется и не получает ack;
//! * тысяча DHT-подобных кадров не двигает членство — оно приходит только из подписанной цепочки
//!   (§9.2), а не из provider records;
//! * лгущий index-node не может подменить текст владельца: `IntentTextResponse` проверяется по
//!   ключу владельца до того, как текст станет доступен (§6.6, §14.2);
//! * rendezvous-приём бесполезен чужой цели и расходуется ровно один раз;
//! * масштабированный sybil: 16 независимых ключей, узловой бюджет 100 admits/с, потолок M
//!   записей, плоская память индекса и `pow_bits`-evict.
//!
//! Чего в v1 нет и что поэтому нельзя честно объявить пройденным: penalty/reputation table
//! (§14.2 — клиентская политика показа, §20.5 исключает репутационный слой из v1), сигнал
//! расхождения владельцев одного кластера (агент опрашивает по одному узлу на шард) и
//! verifiable re-computation `l2_sq` агентом (в v1 агент не скачивает байты записи). Набор
//! фиксирует криптографический барьер, который делает ложь бесполезной уже сейчас; перечисленные
//! три механизма — работа P6/P7, и притворяться, что они проверены, нельзя.
//!
//! Полный гейт P5 (16 ядер, 10 минут, 20 бит) вынесен в `#[ignore]`-тест: в CI он стоил бы
//! десяти минут чужого CPU. Рядом стоит масштабированный эквивалент на 8 битах: он проверяет
//! те же правила (потолок, бюджет, плоская память, evict), а не «примерно столько записей».

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vecdht_crypto::{intent_id, Identity};
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, session, testing, Clock, Params, ShardNode, Spend};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{
    domain, err_code, Codec, Find, InsertOp, IntentTextResponse, MatchResult, OpKind,
    ProtocolError, Publish, ReplicateAck, ReplicateOp, RendezvousAccept,
};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn params() -> Params {
    testing::params(POW)
}

/// Узел шарда с genesis эпохи 1: только он в этих тестах является primary.
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
    assert!(n.is_primary(), "писать и отвечать на Find должен primary эпизоды");
    (n, d)
}

/// Кадр `Error`, адресованный агенту, если узел отказал.
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

fn accepts(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("приём")))
        .collect()
}

/// Ключ с полным 32-байтовым сидом: `testing::identity(u8)` умеет только 256 разных ключей,
/// а сибилу нужно больше.
fn key(n: u64) -> Identity {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&n.to_le_bytes());
    seed[8] = 0xA7;
    seed[31] = 0x5C;
    Identity::from_seed(seed)
}

/// Легитимная публикация от `agent` с точным контролем всех полей PoW-входа.
#[allow(clippy::too_many_arguments)]
fn mined_frame(
    agent: &Identity,
    vec_seed: u8,
    shard: u16,
    cluster: u16,
    epoch: u64,
    bucket: u32,
    ttl: u16,
    bits: u32,
) -> Vec<u8> {
    testing::PublishSpec {
        agent,
        vec_q: &testing::vector(vec_seed),
        cluster_id: cluster,
        shard,
        epoch,
        published_bucket: bucket,
        ttl_buckets: ttl,
        bits,
    }
    .frame()
}

fn find_frame(requester: &Identity, cluster: u16, version: u16, query_id: u64) -> Vec<u8> {
    Find {
        preprocessing_version: version,
        query_vector: testing::vector(1),
        clusters: vec![cluster],
        top_k: 8,
        query_id,
        requester_ed25519: requester.pubkey(),
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

#[test]
fn a_prefarmed_pow_dies_when_shard_epoch_slot_or_expiry_changes() {
    let (mut n, d) = primary_on("adv-pow", params());
    let honest = testing::identity(40);
    let frame = mined_frame(&honest, 1, SHARD, CLUSTER, 1, 0, 225, POW);
    let replies = n.on_frame(honest.pubkey(), &frame, testing::clock(0)).expect("честная");
    assert!(error_to(&replies, honest.pubkey()).is_none(), "контрольный publish обязан пройти");
    assert_eq!(n.store.len(), 1);

    // Тот же nonce, но PoW считался для другого шарда: кластер остаётся «своим», иначе узел
    // отказал бы ещё на маршруте и тест не дошёл бы до проверки привязки.
    let a = testing::identity(41);
    let wrong_shard = mined_frame(&a, 2, SHARD - 1, CLUSTER, 1, 0, 225, POW);
    let err = error_to(&n.on_frame(a.pubkey(), &wrong_shard, testing::clock(0)).unwrap(), a.pubkey())
        .expect("чужой шард в PoW");
    assert_eq!(err.code, err_code::POW_INVALID);

    // Чужая эпизода: `Publish` её не несёт, поэтому узел подставляет serving_epoch и nonce
    // перестаёт сходиться — это и есть весь смысл привязки к эпохе (§11.1).
    let b = testing::identity(42);
    let wrong_epoch = mined_frame(&b, 3, SHARD, CLUSTER, 0, 0, 225, POW);
    let err = error_to(&n.on_frame(b.pubkey(), &wrong_epoch, testing::clock(0)).unwrap(), b.pubkey())
        .expect("чужая эпизода в PoW");
    assert_eq!(err.code, err_code::POW_INVALID);

    // Срок: меняем `published_bucket` после майнинга. `expires = bucket + ttl` входит в
    // PoW-вход, поэтому заготовка «на потом» за пределы TTL не переиспользуется.
    let c = testing::identity(43);
    let mut moved = Publish::decode(&mined_frame(&c, 4, SHARD, CLUSTER, 1, 0, 225, POW)).unwrap();
    moved.published_bucket = 1;
    let err = error_to(
        &n.on_frame(c.pubkey(), &moved.encode_unsigned(), testing::clock(1)).unwrap(),
        c.pubkey(),
    )
    .expect("сдвинутый срок");
    assert_eq!(err.code, err_code::POW_INVALID);

    // Слот: `intent_id` — это slot_key §11.1. Подмена вектора при старом `intent_id` — попытка
    // выдать чужую (уже оплаченную) работу за новую запись.
    let e = testing::identity(44);
    let mut substituted = Publish::decode(&mined_frame(&e, 5, SHARD, CLUSTER, 1, 0, 225, POW)).unwrap();
    substituted.vec_q = testing::vector(6);
    assert_ne!(
        intent_id(&substituted.vec_q, substituted.preprocessing_version),
        substituted.intent_id,
        "подмена обязана изменить slot_key, иначе тест ничего не проверяет"
    );
    let err = error_to(
        &n.on_frame(e.pubkey(), &substituted.encode_unsigned(), testing::clock(0)).unwrap(),
        e.pubkey(),
    )
    .expect("подменённый вектор при чужом intent_id");
    assert_eq!(err.code, err_code::POW_INVALID);

    // Ни одна подделка не изменила индекс, и честная запись на месте.
    assert_eq!(n.store.len(), 1);
    remove(&d);
}

#[test]
fn a_mismatched_artifact_does_not_enter_the_index_or_matching() {
    let (mut n, d) = primary_on("adv-artifact", params());
    let owner = testing::identity(45);
    let seeker = testing::identity(46);

    let good = mined_frame(&owner, 1, SHARD, CLUSTER, 1, 0, 225, POW);
    assert!(error_to(&n.on_frame(owner.pubkey(), &good, testing::clock(0)).unwrap(), owner.pubkey()).is_none());

    // Публикация из сети с другой `preprocessing_version`: подпись не обязательна, поэтому
    // именно эта проверка не даёт вектору чужой сетки попасть в индекс (§6.7, §15.3).
    let alien = testing::identity(47);
    let mut frame = Publish::decode(&mined_frame(&alien, 2, SHARD, CLUSTER, 1, 0, 225, POW)).unwrap();
    frame.preprocessing_version = testing::PREPROCESSING_VERSION + 1;
    let err = error_to(
        &n.on_frame(alien.pubkey(), &frame.encode_unsigned(), testing::clock(0)).unwrap(),
        alien.pubkey(),
    )
    .expect("чужой preprocessing_version");
    assert_eq!(err.code, err_code::MODEL_MISMATCH);
    assert_eq!(n.store.len(), 1, "чужая запись не должна появиться в индексе");

    // Find из чужой сетки — отказ, а не пустой MatchResult: пустой ответ агент не отличил бы
    // от «ничего не найдено» и продолжил бы с тихо испорченным recall.
    let bad_find = find_frame(&seeker, CLUSTER, testing::PREPROCESSING_VERSION + 1, 1);
    let replies = n.on_frame(seeker.pubkey(), &bad_find, testing::clock(0)).expect("find");
    let err = error_to(&replies, seeker.pubkey()).expect("MODEL_MISMATCH на Find");
    assert_eq!(err.code, err_code::MODEL_MISMATCH);
    assert!(match_result(&replies).is_none(), "до matching дело доходить не должно");

    // Свой Find по-прежнему находит ровно одну запись.
    let good_find = find_frame(&seeker, CLUSTER, testing::PREPROCESSING_VERSION, 2);
    let replies = n.on_frame(seeker.pubkey(), &good_find, testing::clock(0)).expect("find");
    assert_eq!(match_result(&replies).expect("MatchResult").matches.len(), 1);
    remove(&d);
}

#[test]
fn a_forged_replicate_op_with_an_old_epoch_is_never_applied_or_acked() {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed_of = |owner: [u8; 32]| {
        *SEEDS
            .iter()
            .find(|s| testing::identity(**s).pubkey() == owner)
            .expect("член эпохи — один из тестовых сидов")
    };
    let primary = testing::identity(seed_of(order[0].owner_ed25519));
    let replica_seed = seed_of(order[1].owner_ed25519);
    let d = dir("adv-replica");
    let mut replica = testing::node(&d, SHARD, replica_seed, params(), &SEEDS);
    replica
        .on_frame(
            testing::identity(9).pubkey(),
            &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
            testing::clock(0),
        )
        .expect("genesis");
    assert!(!replica.is_primary(), "тесту нужна именно реплика");

    let insert = InsertOp {
        owner_ed25519: testing::identity(48).pubkey(),
        vec_q: testing::vector(1),
        cluster_id: CLUSTER,
        published_bucket: 0,
        ttl_buckets: 225,
        slot_attr: 0,
    };
    let op = |epoch: u64, seq: u64| ReplicateOp {
        shard: SHARD,
        epoch,
        seq,
        op_kind: OpKind::Insert,
        body: insert.body_bytes(),
    };
    let signed = |op: &ReplicateOp, signer: &Identity| {
        let body = op.body_bytes();
        let sig = signer.sign_body(domain::REPLICA, Kind::ReplicateOp, &body);
        op.encode_signed(&sig)
    };

    // Контроль: корректный опс текущей эпизоды применяется и получает ok-ack.
    let good = op(1, 1);
    let replies = replica
        .on_frame(primary.pubkey(), &signed(&good, &primary), testing::clock(0))
        .expect("replicate");
    assert_eq!(replies.len(), 1, "реплика обязана ответить ack'ом primary");
    let ack = ReplicateAck::decode(&replies[0].frame).expect("ReplicateAck");
    assert!(ack.ok);
    assert_eq!((replica.store.len(), replica.applied_seq()), (1, 1));

    // Старая эпизода: кадр подписан настоящим primary, но membership его эпохи не знает.
    // Ответа нет вовсе — иначе отправитель получил бы oracle «эпоха принята/нет».
    let old = op(0, 2);
    let replies = replica
        .on_frame(primary.pubkey(), &signed(&old, &primary), testing::clock(0))
        .expect("replicate");
    assert!(replies.is_empty(), "старый epoch не получает ack");
    assert_eq!((replica.store.len(), replica.applied_seq()), (1, 1), "и не меняет store");

    // Текущая эпизода, но чужой ключ: primary эпизоды — единственный, кому разрешено писать.
    let impostor = testing::identity(49);
    let replies = replica
        .on_frame(impostor.pubkey(), &signed(&op(1, 2), &impostor), testing::clock(0))
        .expect("replicate");
    assert!(replies.is_empty(), "чужой подписант не получает ack");
    assert_eq!((replica.store.len(), replica.applied_seq()), (1, 1));
    remove(&d);
}

#[test]
fn a_thousand_dht_shaped_frames_do_not_touch_membership() {
    let (mut n, d) = primary_on("adv-dht", params());
    let before = (n.epoch(), n.peers(), n.is_primary());
    let carrier = testing::identity(50);
    for i in 0..1000u64 {
        // Кадры, которые узел реально видит от DHT-клиентов: поиск с разными query_id и
        // отправителями. Provider records в v8 вообще не имеют кадра — Kademlia хранит их
        // вне протокола узла (§9.2), поэтому единственный вход членства — подписанный
        // MembershipUpdate, и тысяча запросов не могут его подменить.
        let from = key(1_000_000 + i).pubkey();
        let frame = find_frame(&carrier, CLUSTER + (i as u16 % 16), testing::PREPROCESSING_VERSION, i + 1);
        let replies = n.on_frame(from, &frame, Clock::at(i % 8)).expect("find");
        assert!(error_to(&replies, from).is_none(), "find №{i} не должен упираться в квоту");
    }
    assert_eq!(
        (n.epoch(), n.peers(), n.is_primary()),
        before,
        "членство приходит из цепочки, а не из DHT-запросов (§9.2)"
    );
    assert_eq!(n.epoch(), Some(1));
    assert_eq!(n.store.len(), 0, "поиск не пишет в индекс");
    remove(&d);
}

#[test]
fn a_lying_index_node_cannot_substitute_the_owners_text() {
    let owner = testing::identity(51);
    let liar = testing::identity(52);
    let honest_frame = session::sign_response(&owner, "granite", 1, "настоящий текст").expect("подпись");
    let honest = session::verify_response(&honest_frame, &owner.pubkey()).expect("проверка");
    assert_eq!(honest.text, "настоящий текст");

    // Лгущий index-node подставляет свой текст, но оставляет в теле ключ владельца: подпись
    // посчитана его ключом и не сходится с `owner_ed25519`. Именно это не даёт тексту попасть
    // в контекст агента (§12.4: текст — данные, но только после проверки источника).
    let forged = IntentTextResponse {
        owner_ed25519: owner.pubkey(),
        model_version: "granite".into(),
        preprocessing_version: 1,
        text: b"\xd0\xbf\xd0\xbe\xd0\xb4\xd0\xbc\xd0\xb5\xd0\xbd\xd0\xb0".to_vec(),
    };
    let sig = liar.sign_body(domain::TEXT, Kind::IntentTextResponse, &forged.body_bytes());
    assert_eq!(
        session::verify_response(&forged.encode_signed(&sig), &owner.pubkey()),
        Err(session::TextError::BadSignature),
        "чужой текст под именем владельца обязан быть отвергнут"
    );

    // Ответ настоящего владельца, но выданный за другого — тоже не текст этого другого.
    let wrong_expected = testing::identity(53);
    assert!(matches!(
        session::verify_response(&honest_frame, &wrong_expected.pubkey()),
        Err(session::TextError::WrongOwner { .. })
    ));
}

#[test]
fn a_rendezvous_accept_is_bound_to_its_target_and_spends_once() {
    let (mut n, d) = primary_on("adv-rdv", params());
    let owner = testing::identity(54);
    let seeker = testing::identity(55);
    let publish = mined_frame(&owner, 1, SHARD, CLUSTER, 1, 0, 225, POW);
    assert!(error_to(&n.on_frame(owner.pubkey(), &publish, testing::clock(0)).unwrap(), owner.pubkey()).is_none());

    let replies = n
        .on_frame(seeker.pubkey(), &find_frame(&seeker, CLUSTER, testing::PREPROCESSING_VERSION, 7), testing::clock(0))
        .expect("find");
    let (frame, acc) = accepts(&replies).pop().expect("ровно один приём на match");
    assert_eq!((acc.seeker, acc.target), (seeker.pubkey(), owner.pubkey()));

    // Приём у другого владельца — не сессия: цель сверяет `target` с собой.
    let other = testing::identity(56);
    let mut wrong = Spend::new(300);
    assert_eq!(
        wrong.consume(&frame, &n.me(), &other.pubkey(), 0),
        Err(rendezvous::AcceptError::WrongTarget)
    );
    // Правильная цель расходует ровно один раз; повтор — AlreadySpent, даже если приём ещё
    // не истёк. Это проверяет цель, а не издатель (§12.3).
    let mut spend = Spend::new(300);
    assert!(spend.consume(&frame, &n.me(), &owner.pubkey(), 0).is_ok());
    assert_eq!(
        spend.consume(&frame, &n.me(), &owner.pubkey(), 0),
        Err(rendezvous::AcceptError::AlreadySpent)
    );
    remove(&d);
}

#[test]
fn a_scaled_sixteen_key_sybil_is_capped_exactly_at_m_and_keeps_index_memory_flat() {
    let mut p = params();
    p.max_live_per_shard = 256;
    let (mut n, d) = primary_on("adv-sybil", p);
    assert_eq!(
        (p.per_peer_publish_burst, p.node_admits_per_s),
        (20, 100),
        "тест строится на квотах артефакта: 20 burst и 100 admits/с"
    );

    let mut accepted = 0u64;
    let mut busy = 0u64;
    let mut lens = Vec::new();
    let mut mem_at_cap = 0usize;

    // 16 независимых ключей на «ядро» не нужны: у сибила ключи бесплатны, и узловой бюджет
    // 100/с — единственный общий лимит. Каждая попытка идёт с новым ключом, как и у атакующего,
    // который не хочет упираться в 1 publish/с на ключ.
    for sec in 0..4u64 {
        let attempts = if sec == 0 { 101 } else { 100 };
        for i in 0..attempts {
            let id = sec * 1000 + i;
            let agent = key(2_000_000 + id);
            let frame = mined_frame(&agent, id as u8, SHARD, CLUSTER, 1, sec as u32, 225, POW);
            let replies = n.on_frame(agent.pubkey(), &frame, Clock::at(sec)).expect("publish");
            match error_to(&replies, agent.pubkey()) {
                Some(err) => {
                    assert_eq!(err.code, err_code::BUSY, "секунда {sec}, попытка {i}: {err:?}");
                    busy += 1;
                }
                None => {
                    accepted += 1;
                    assert!(
                        n.store.len() as u64 <= p.max_live_per_shard,
                        "потолок M нарушен после {accepted} принятых записей"
                    );
                }
            }
        }
        lens.push(n.store.len());
        if sec == 2 {
            mem_at_cap = n.store.index.mem_bytes().total();
        }
    }

    assert_eq!(busy, 1, "101-я попытка в первую секунду обязана получить BUSY (§11.3.4)");
    assert_eq!(accepted, 400);
    assert_eq!(lens, vec![100, 200, 256, 256], "шард обязан упереться ровно в M");
    assert_eq!(n.evictor.evicted, 144, "все принятые сверх M вытеснили по одной записи");
    assert_eq!(
        n.store.index.mem_bytes().total(),
        mem_at_cap,
        "после достижения M память индекса не растёт: слоты переиспользуются (§8.3)"
    );

    // Легитимный поиск под заполненным шардом: результат есть, серверная часть укладывается
    // в бюджет §12.6 (≤ 50 мс), то есть спам не вытеснил саму возможность отвечать.
    let mut samples = Vec::new();
    for i in 0..20u64 {
        let requester = key(3_000_000 + i);
        let frame = find_frame(&requester, CLUSTER, testing::PREPROCESSING_VERSION, 100 + i);
        let started = Instant::now();
        let replies = n.on_frame(requester.pubkey(), &frame, Clock::at(4)).expect("find");
        samples.push(started.elapsed());
        let res = match_result(&replies).expect("MatchResult под нагрузкой");
        assert!(!res.matches.is_empty(), "запись обязана находиться");
    }
    samples.sort();
    let p50 = samples[samples.len() / 2];
    assert!(p50 < Duration::from_millis(50), "p50 легитимного Find {p50:?} выше бюджета §12.6");

    // `pow_bits`-evict: дорогая запись обязана вытеснить дешёвую, а не быть отвергнутой,
    // потому что полный шард из одинаковых по цене записей — это не повод замораживать приём.
    let expensive = key(4_000_000);
    let frame = mined_frame(&expensive, 99, SHARD, CLUSTER, 1, 4, 225, POW + 1);
    let replies = n.on_frame(expensive.pubkey(), &frame, Clock::at(4)).expect("publish");
    assert!(error_to(&replies, expensive.pubkey()).is_none(), "дорогая запись проходит");
    assert_eq!(n.store.len(), 256);
    assert_eq!(n.evictor.evicted, 145);
    remove(&d);
}

/// Полный гейт P5: 16 ядер, 10 минут, default 20 бит.
///
/// Почему `#[ignore]`: это не юнит-тест, а измерение стоимости атаки на реальном CPU. Запуск —
/// `cargo test --release -p vecdht-node --test adversarial -- --ignored --nocapture`. Параметры
/// (`VECDHT_P5_SECONDS`, `VECDHT_P5_CORES`, `VECDHT_P5_BITS`) существуют для smoke-прогона, а не
/// для «подкрутить гейт»: при значениях по умолчанию проверяется формулировка §18.6.
#[test]
#[ignore = "гейт P5: 16 ядер × 10 минут × 2^20; запускать в release с --ignored"]
fn p5_gate_sixteen_core_sybil_for_ten_minutes() {
    let seconds: u64 = std::env::var("VECDHT_P5_SECONDS").ok().and_then(|s| s.parse().ok()).unwrap_or(600);
    let cores: usize = std::env::var("VECDHT_P5_CORES").ok().and_then(|s| s.parse().ok()).unwrap_or(16);
    let bits: u32 = std::env::var("VECDHT_P5_BITS").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    assert!(cores > 0, "нужно хотя бы одно ядро");

    let p = testing::params(bits);
    assert_eq!(u32::from(p.pow_bits), bits, "сложность гейта берётся из манифеста");
    let (mut n, d) = primary_on("adv-p5", p);

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let start = Instant::now();
    let mut accepted = 0u64;
    let mut busy = 0u64;
    let mut attempted = 0u64;
    let mut last_bucket = 0u32;
    let mut find_samples = Vec::new();
    let mut next_find = 5u64;

    /// Погасить воркеров при panic'е внутри гейта: иначе `scope` ждал бы вечно потоки,
    /// которые продолжают майнить «в никуда».
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    std::thread::scope(|scope| {
        let _stop_on_drop = StopOnDrop(Arc::clone(&stop));
        for worker in 0..cores {
            let tx = tx.clone();
            let stop = Arc::clone(&stop);
            scope.spawn(move || {
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    // Ключ и вектор зависят от ядра и счётчика: все 16 потоков майнят разные
                    // записи, как и настоящий сибил, у которого identity бесплатна.
                    let agent = key(((worker as u64) << 40) | i);
                    let vec_seed = (i as u8) ^ (worker as u8).wrapping_mul(37);
                    let frame = testing::PublishSpec {
                        agent: &agent,
                        vec_q: &testing::vector(vec_seed),
                        cluster_id: CLUSTER,
                        shard: SHARD,
                        epoch: 1,
                        published_bucket: 0,
                        ttl_buckets: 225,
                        bits,
                    }
                    .frame();
                    if tx.send(frame).is_err() {
                        break;
                    }
                    i += 1;
                }
            });
        }
        drop(tx);

        while start.elapsed().as_secs() < seconds {
            let now = Clock::at(start.elapsed().as_secs());
            // Тик — и при таймауте канала: на 20 битах кадр может не прийти целую секунду, а
            // lease обязан продлеваться по часам, а не по прибытию чужой работы. Иначе гейт
            // измерил бы EPOCH_STALE вместо admission.
            if now.bucket != last_bucket {
                n.tick(now.bucket).expect("tick primary");
                last_bucket = now.bucket;
            }
            match rx.recv_timeout(Duration::from_millis(20)) {
                Ok(frame) => {
                    let msg = match Publish::decode(&frame) {
                        Ok(m) => m,
                        Err(e) => panic!("воркер собрал неразбираемый Publish: {e}"),
                    };
                    let replies = n.on_frame(msg.owner_ed25519, &frame, now).expect("publish");
                    attempted += 1;
                    match error_to(&replies, msg.owner_ed25519) {
                        Some(err) => {
                            if err.code == err_code::BUSY {
                                busy += 1;
                            }
                        }
                        None => {
                            accepted += 1;
                            assert!(
                                n.store.len() as u64 <= p.max_live_per_shard,
                                "потолок M нарушен при {accepted} принятых"
                            );
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }

            let elapsed = start.elapsed().as_secs();
            if elapsed >= next_find {
                next_find = elapsed + 5;
                // Легитимный Find раз в 5 секунд: p50 под атакой не должен деградировать до
                // неприличия. Отдельный ключ на каждый замер — иначе упёрлись бы в 5/с.
                let requester = key(9_000_000 + elapsed);
                let frame = find_frame(&requester, CLUSTER, testing::PREPROCESSING_VERSION, 1_000 + elapsed);
                let t0 = Instant::now();
                let _ = n.on_frame(requester.pubkey(), &frame, Clock::at(elapsed)).expect("find");
                find_samples.push(t0.elapsed());
            }
        }
        stop.store(true, Ordering::Relaxed);
        // Воркеры могут стоять в `send`; канал неограничен, поэтому достаточно дочитать и
        // дать scope дождаться их выхода из текущего майнинга.
        while rx.recv_timeout(Duration::from_millis(50)).is_ok() {}
    });

    find_samples.sort();
    let p50 = find_samples.get(find_samples.len() / 2).copied().unwrap_or_default();
    eprintln!(
        "P5-гейт: ядер={cores} bits={bits} секунд={seconds}; попыток={attempted}, принято={accepted}, \
         BUSY={busy}, store={}, evicted={}, p50 Find={p50:?}",
        n.store.len(),
        n.evictor.evicted
    );

    assert_eq!(n.store.len() as u64, accepted, "каждая принятая запись должна лежать в индексе");
    let admission_cap = u64::from(p.node_admits_per_s) * seconds
        + u64::from(p.per_peer_publish_burst) * cores as u64;
    assert!(
        accepted <= admission_cap,
        "принято {accepted} при бюджете admissions {admission_cap}"
    );
    if seconds >= 600 && cores >= 16 && bits >= 20 {
        assert!(accepted <= 64_000, "гейт §18.6: {accepted} записей за 10 минут при 20 битах");
    }
    if p.max_live_per_shard > accepted {
        assert_eq!(n.evictor.evicted, 0, "до потолка M вытеснять нечего");
    }
    remove(&d);
}
