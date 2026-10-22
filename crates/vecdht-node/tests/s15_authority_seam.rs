//! H-0075 / E-0075: §15/§9.2 — пороговая подпись на трёх дверях и genesis.
//!
//! Юнит-тесты каждой двери уже есть; здесь меряется **шов**:
//! * `MembershipUpdate.sigs` — единственные подписи с индексом, и §9.2 говорит, что
//!   индекс — позиция подписанта (для genesis — в наборе `authorities`). `check_members`
//!   это связывает, `check_authorities` — нет: диапазон и уникальность без привязки к ключу.
//! * порог genesis берётся из `Params.authority_threshold`, порог `NodeCert` — из
//!   `AuthoritySet.threshold`; `ShardNode::open` принимает обе структуры без сверки.
//! * домены `member`/`node_cert`/`artifact` обязаны разделять двери, а не только называться
//!   по-разному.
//!
//! Один процесс, ручная доставка, шард 7, сиды 1..=3, PoW 8.

use std::path::{Path, PathBuf};

use vecdht_artifact::DOMAIN_ARTIFACT;
use vecdht_crypto::cert::{verify_cert, CertError, DOMAIN_NODE_CERT};
use vecdht_crypto::verify_domain;
use vecdht_index::testing::{dir, remove};
use vecdht_node::config::Params;
use vecdht_node::{
    candidates, membership, testing, Chain, MembershipError, Membership, ShardNode,
};
use vecdht_wire::messages::{domain, Codec, MembershipUpdate, Role};

const SHARD: u16 = 7;
const POW: u32 = 8;
const SEEDS: [u8; 3] = [1, 2, 3];
const CARRIER: u8 = 200;
const NOW_SEC: u32 = 100;

fn full_genesis() -> MembershipUpdate {
    testing::genesis_update(SHARD, &SEEDS, 0)
}

fn open_node(tag: &str, seed: u8, params: Params) -> (ShardNode, PathBuf) {
    let d = dir(tag);
    let n = ShardNode::open(
        &d,
        SHARD,
        testing::identity(seed),
        testing::DHT_PEER_ID.to_vec(),
        params,
        testing::authority_set(),
        testing::holders(&SEEDS),
    )
    .expect("открыть узел");
    (n, d)
}

fn membership_file(d: &Path, epoch: u64) -> PathBuf {
    d.join(format!("membership.{epoch:020}.log"))
}

fn seed_of(key: [u8; 32]) -> u8 {
    *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == key)
        .expect("ключ принадлежит тройке")
}

fn carrier() -> vecdht_node::Addr {
    testing::identity(CARRIER).pubkey()
}

/// Ожидаемый переход на эпоху 2 из того же состава, подписанный членами `prev`
/// по индексам `labels` (длина labels ≤ числа подписантов).
fn epoch2_update(prev: &Membership, labels: &[u8], generated_at: u32) -> MembershipUpdate {
    let holders = testing::holders(&SEEDS);
    let p = testing::params(POW);
    let list = candidates::expected_update(2, SHARD, &holders, p.r, 0, generated_at);
    let mut upd = membership::build_update(&list, Vec::new());
    let payload = upd.unsigned_body();
    upd.sigs = prev
        .members()
        .iter()
        .zip(labels.iter())
        .map(|(m, &label)| {
            let id = testing::identity(seed_of(m.owner_ed25519));
            (label, id.sign_domain(domain::MEMBER, &payload))
        })
        .collect();
    upd
}

#[test]
fn genesis_threshold_is_exactly_three_of_five() {
    let c = testing::chain(SHARD, POW);
    let full = full_genesis();
    let payload = full.unsigned_body();
    assert_eq!(full.sigs.len(), 3, "(0) genesis подписан тремя ключами");

    let mut one = full.clone();
    one.sigs.truncate(1);
    assert_eq!(
        c.validate(None, &one),
        Err(MembershipError::BelowThreshold { have: 1, need: 3 }),
        "(1) одной подписи мало"
    );

    let mut two = full.clone();
    two.sigs.truncate(2);
    assert_eq!(
        c.validate(None, &two),
        Err(MembershipError::BelowThreshold { have: 2, need: 3 }),
        "(1) двух подписей мало"
    );

    // Чужая доля: валидная подпись ключа вне набора не добирает порог.
    let mut alien = two.clone();
    alien
        .sigs
        .push((3, testing::identity(200).sign_domain(domain::MEMBER, &payload)));
    assert_eq!(
        c.validate(None, &alien),
        Err(MembershipError::BelowThreshold { have: 2, need: 3 }),
        "(1) подпись не-авторитета не считается"
    );

    // Переупаковка: три копии подписи одного ключа — это один ключ.
    let dup_sig = full.sigs[0].1;
    let mut dup = full.clone();
    dup.sigs = (0..3u8).map(|i| (i, dup_sig)).collect();
    assert_eq!(
        c.validate(None, &dup),
        Err(MembershipError::BelowThreshold { have: 1, need: 3 }),
        "(1) дубликат одного ключа не набивает квоту"
    );

    let m = c.validate(None, &full).expect("(0) genesis принимается");
    assert_eq!(m.epoch(), 1);
    assert_eq!(m.len(), 3);
    assert_eq!(m.primary(), Some(full.members[0].owner_ed25519));

    // Две другие двери открыты теми же ключами.
    let cert = testing::node_cert(
        SEEDS[0],
        testing::DHT_PEER_ID.to_vec(),
        vec![SHARD],
        Role::IndexNode,
        0,
        10_000,
    );
    assert_eq!(
        verify_cert(&cert, &testing::authority_set(), &testing::genesis_hash(), NOW_SEC, |_| false),
        Ok(()),
        "(0) NodeCert 3-of-5 открывается"
    );
    let manifest = vecdht_artifact::reference_manifest();
    assert_eq!(
        (manifest.authority.keys.len(), manifest.authority.threshold),
        (5, 3),
        "(0) эталонный набор — 5 ключей с порогом 3"
    );

    // Живой узел: сначала две подписи (черновик), затем третья того же тела.
    let (mut n, d) = open_node("s15-base", SEEDS[0], testing::params(POW));
    let out = n
        .on_frame(carrier(), &testing::signed_frame(&two), testing::clock(0))
        .expect("(1) короткий genesis — не ошибка разбора");
    assert!(out.is_empty(), "(1) без принятой эпохи рассылать некому");
    assert_eq!(n.epoch(), None, "(1) двух подписей недостаточно");
    assert!(!membership_file(&d, 1).exists(), "(1) файл членства не создан");

    n.on_frame(carrier(), &testing::signed_frame(&full), testing::clock(0))
        .expect("(1) полный genesis принимается");
    assert_eq!(n.epoch(), Some(1), "(1) третья подпись добирает порог");
    assert!(membership_file(&d, 1).exists(), "(0) членство персистится");

    let reopened = ShardNode::open(
        &d,
        SHARD,
        testing::identity(SEEDS[0]),
        testing::DHT_PEER_ID.to_vec(),
        testing::params(POW),
        testing::authority_set(),
        testing::holders(&SEEDS),
    )
    .expect("(0) reopen");
    assert_eq!(reopened.epoch(), Some(1), "(0) эпоха переживает reopen");
    remove(&d);
}

#[test]
fn genesis_accepts_a_signature_under_a_foreign_index() {
    let c = testing::chain(SHARD, POW);
    let full = full_genesis();
    let payload = full.unsigned_body();
    let keys = testing::authority_set().keys;

    // Подписи настоящие, но заявленные позиции сдвинуты: 0→2, 1→3, 2→4.
    let mut relabeled = full.clone();
    for (i, sig) in relabeled.sigs.iter_mut().enumerate() {
        sig.0 = [2u8, 3, 4][i];
    }

    for (i, key) in keys.iter().enumerate().take(3) {
        assert!(
            verify_domain(key, domain::MEMBER, &payload, &relabeled.sigs[i].1),
            "(2) подпись {i} принадлежит ключу {i}"
        );
    }
    for (declared, sig) in &relabeled.sigs {
        assert!(
            !verify_domain(&keys[*declared as usize], domain::MEMBER, &payload, sig),
            "(2) ключ {declared} не подписывал подпись, заявленную под его индексом"
        );
    }

    let m = c
        .validate(None, &relabeled)
        .expect("(2) сегодня genesis принимает чужой индекс — находка");
    assert_eq!(m.epoch(), 1);
    assert_eq!(m.len(), 3);

    let (mut n, d) = open_node("s15-relabel", SEEDS[0], testing::params(POW));
    n.on_frame(carrier(), &testing::signed_frame(&relabeled), testing::clock(0))
        .expect("(2) кадр genesis");
    assert_eq!(n.epoch(), Some(1), "(2) живой узел принял чужой индекс");

    let bytes = std::fs::read(membership_file(&d, 1)).expect("(2) файл членства");
    let saved = MembershipUpdate::decode(&bytes).expect("(2) decode");
    let idx: Vec<u8> = saved.sigs.iter().map(|(i, _)| *i).collect();
    assert_eq!(idx, vec![2, 3, 4], "(2) персистентное членство хранит чужие индексы");
    assert_eq!(saved.sigs.len(), 3);
    remove(&d);
}

#[test]
fn transition_binds_the_index_that_genesis_ignores() {
    let c = testing::chain(SHARD, POW);
    let full = full_genesis();
    let m1 = c.validate(None, &full).expect("genesis эпохи 1");
    assert_eq!(testing::params(POW).membership_threshold, 2, "(3) порог перехода");

    // Тот же приём: подписи членов 0,1,2 под индексами 1,2,0.
    let permuted = epoch2_update(&m1, &[1, 2, 0], 7);
    let payload = permuted.unsigned_body();
    for (k, (_, sig)) in permuted.sigs.iter().enumerate() {
        assert!(
            verify_domain(&m1.members()[k].owner_ed25519, domain::MEMBER, &payload, sig),
            "(3) подпись {k} верна своему ключу"
        );
    }
    assert_eq!(
        c.validate(Some(&m1), &permuted),
        Err(MembershipError::BelowThreshold { have: 0, need: 2 }),
        "(3) переход связывает индекс с ключом"
    );

    let (mut n, d) = open_node("s15-transition", SEEDS[0], testing::params(POW));
    n.on_frame(carrier(), &testing::signed_frame(&full), testing::clock(0))
        .expect("genesis");
    assert_eq!(n.epoch(), Some(1));

    let out = n
        .on_frame(carrier(), &testing::signed_frame(&permuted), testing::clock(0))
        .expect("(3) кадр перехода");
    assert_eq!(n.epoch(), Some(1), "(3) живой узел остался на эпохе 1");
    assert!(!membership_file(&d, 2).exists(), "(3) файла эпохи 2 нет");
    assert_eq!(out.len(), 2, "(3) черновик разослан двум пирам");

    // Исправленный переход того же состава: настоящие индексы 0,1 и другое
    // `generated_at`, чтобы тело не слилось с отвергнутым черновиком.
    let corrected = epoch2_update(&m1, &[0, 1], 8);
    let m2 = c
        .validate(Some(&m1), &corrected)
        .expect("(3) правильные индексы принимаются");
    assert_eq!(m2.epoch(), 2);
    assert_eq!(m2.primary(), Some(corrected.members[0].owner_ed25519));

    n.on_frame(carrier(), &testing::signed_frame(&corrected), testing::clock(0))
        .expect("(3) исправленный переход");
    assert_eq!(n.epoch(), Some(2), "(3) исправленный переход принят");
    assert!(membership_file(&d, 2).exists(), "(3) эпоха 2 персистится");
    remove(&d);
}

#[test]
fn doors_do_not_lend_signatures() {
    let c = testing::chain(SHARD, POW);
    let full = full_genesis();
    let payload = full.unsigned_body();
    let auth = testing::authorities();

    let mut wrong_cert_domain = full.clone();
    wrong_cert_domain.sigs = auth
        .iter()
        .take(3)
        .enumerate()
        .map(|(i, a)| (i as u8, a.sign_domain(DOMAIN_NODE_CERT, &payload)))
        .collect();
    assert_eq!(
        c.validate(None, &wrong_cert_domain),
        Err(MembershipError::BelowThreshold { have: 0, need: 3 }),
        "(4) домен node_cert не засчитывается в genesis"
    );

    let mut wrong_artifact_domain = full.clone();
    wrong_artifact_domain.sigs = auth
        .iter()
        .take(3)
        .enumerate()
        .map(|(i, a)| (i as u8, a.sign_domain(DOMAIN_ARTIFACT, &payload)))
        .collect();
    assert_eq!(
        c.validate(None, &wrong_artifact_domain),
        Err(MembershipError::BelowThreshold { have: 0, need: 3 }),
        "(4) домен artifact не засчитывается в genesis"
    );

    let cert = testing::node_cert(
        SEEDS[0],
        testing::DHT_PEER_ID.to_vec(),
        vec![SHARD],
        Role::IndexNode,
        0,
        10_000,
    );
    assert_eq!(cert.authority_sigs.len(), 3);
    assert_eq!(
        verify_cert(&cert, &testing::authority_set(), &testing::genesis_hash(), NOW_SEC, |_| false),
        Ok(()),
        "(4) своя дверь открыта"
    );

    let mut crossed_in = full.clone();
    crossed_in.sigs =
        cert.authority_sigs.iter().enumerate().map(|(i, s)| (i as u8, *s)).collect();
    assert_eq!(
        c.validate(None, &crossed_in),
        Err(MembershipError::BelowThreshold { have: 0, need: 3 }),
        "(4) подписи NodeCert не годятся для genesis"
    );

    let mut crossed_out = cert.clone();
    crossed_out.authority_sigs = full.sigs.iter().map(|(_, s)| *s).collect();
    assert_eq!(
        verify_cert(
            &crossed_out,
            &testing::authority_set(),
            &testing::genesis_hash(),
            NOW_SEC,
            |_| false
        ),
        Err(CertError::BelowThreshold { have: 0, need: 3 }),
        "(4) подписи genesis не годятся для NodeCert"
    );
}

#[test]
fn authority_threshold_lives_in_two_hands() {
    let full = full_genesis();
    let mut two = full.clone();
    two.sigs.truncate(2);
    let payload = two.unsigned_body();

    let mut weak = testing::params(POW);
    assert_eq!(weak.authority_threshold, 3, "(5) штатный порог из манифеста");
    weak.authority_threshold = 2;
    assert_eq!(testing::authority_set().threshold, 3, "(5) набор остаётся 3-of-5");

    let c2 = Chain { shard: SHARD, params: weak, authorities: testing::authority_set() };
    let m = c2
        .validate(None, &two)
        .expect("(5) chain смотрит в params — двух подписей хватает");
    assert_eq!(m.epoch(), 1);

    let list: Vec<[u8; 64]> = two.sigs.iter().map(|(_, s)| *s).collect();
    assert_eq!(
        testing::authority_set().check(&payload, domain::MEMBER, &list),
        Err(CertError::BelowThreshold { have: 2, need: 3 }),
        "(5) та же пара подписей на двери NodeCert отвергается"
    );

    let (mut weak_node, d1) = open_node("s15-two-hands-weak", SEEDS[0], weak);
    weak_node
        .on_frame(carrier(), &testing::signed_frame(&two), testing::clock(0))
        .expect("(5) кадр");
    assert_eq!(weak_node.epoch(), Some(1), "(5) узел с params=2 принял genesis");
    assert!(membership_file(&d1, 1).exists());

    let (mut normal, d2) = open_node("s15-two-hands-normal", SEEDS[1], testing::params(POW));
    normal
        .on_frame(carrier(), &testing::signed_frame(&two), testing::clock(0))
        .expect("(5) кадр");
    assert_eq!(normal.epoch(), None, "(5) штатный порог 3 тот же кадр не принял");
    assert!(!membership_file(&d2, 1).exists());

    remove(&d1);
    remove(&d2);
}
