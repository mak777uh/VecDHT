//! H-0069 / E-0069: heal-окно §9.8 — когда старый primary принимает подписанную эпоху.
//!
//! Спека обещает: «Старые primary после resurrect демотируются сами, когда принимают
//! подписанную цепочку `ShardMembership` с большим epoch». Здесь измеряется, при каких
//! условиях это действительно происходит: `validate_with_candidates` сверяет состав с
//! локальным `live_roster(now)`, а `unreachable` чистится только в `adopt`.
//!
//! Три независимых трио, ручная доставка, без таймеров:
//! * A — P не видел обрыва: цепочка принимается ровно после истечения его lease;
//! * B — P сам получил `peer_lost(Q)`/`peer_lost(R)`: принятия нет ни на 6, ни на 100;
//! * C — цепочку P никто не переслал: тики Q/R не адресуют ему ни одного кадра.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::{Addr, Envelope};
use vecdht_node::{Clock, ShardNode, candidates, membership, testing};
use vecdht_wire::codec::DIM;
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{
    Codec, MembershipUpdate, ProtocolError, PublishAck, domain, err_code,
};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const TTL: u16 = 225;

// --- каркас: три узла и ручная доставка ---------------------------------------

struct Trio {
    nodes: BTreeMap<Addr, ShardNode>,
    seeds: BTreeMap<Addr, u8>,
    dirs: Vec<PathBuf>,
}

impl Trio {
    fn open(tag: &str) -> Trio {
        let params = testing::params(POW);
        let mut nodes = BTreeMap::new();
        let mut seeds = BTreeMap::new();
        let mut dirs = Vec::new();
        for seed in SEEDS {
            let d = dir(&format!("{tag}-{seed}"));
            dirs.push(d.clone());
            let n = testing::node(&d, SHARD, seed, params, &SEEDS);
            seeds.insert(n.me(), seed);
            nodes.insert(n.me(), n);
        }
        let genesis = testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0));
        let carrier = testing::identity(9).pubkey();
        let addrs: Vec<Addr> = nodes.keys().copied().collect();
        for a in addrs {
            nodes
                .get_mut(&a)
                .expect("узел из карты")
                .on_frame(carrier, &genesis, testing::clock(0))
                .expect("genesis эпохи 1 принимается каждым узлом");
        }
        Trio { nodes, seeds, dirs }
    }

    fn addr(&self, seed: u8) -> Addr {
        *self
            .seeds
            .iter()
            .find(|(_, s)| **s == seed)
            .expect("сид принадлежит тройке")
            .0
    }

    fn node(&self, addr: Addr) -> &ShardNode {
        self.nodes.get(&addr).expect("узел из карты")
    }

    fn node_mut(&mut self, addr: Addr) -> &mut ShardNode {
        self.nodes.get_mut(&addr).expect("узел из карты")
    }

    fn route(&mut self, from: Addr, envs: &[Envelope], now: Clock) -> Vec<Envelope> {
        let mut out = Vec::new();
        for e in envs {
            let kind = kind_of(e);
            let node = self
                .nodes
                .get_mut(&e.to)
                .unwrap_or_else(|| panic!("кадр {kind:?} адресован узлу, которого нет в тройке"));
            match node.on_frame(from, &e.frame, now) {
                Ok(replies) => out.extend(replies),
                Err(err) => panic!("{kind:?} сломал узел: {err}"),
            }
        }
        out
    }

    fn clean(mut self) {
        self.nodes.clear();
        for d in &self.dirs {
            remove(d);
        }
    }
}

fn kind_of(e: &Envelope) -> Kind {
    decode_frame(&e.frame).expect("узел обязан отдавать разбираемые кадры").header.kind
}

fn acks(envs: &[Envelope]) -> Vec<PublishAck> {
    envs.iter()
        .filter(|e| kind_of(e) == Kind::PublishAck)
        .map(|e| PublishAck::decode(&e.frame).expect("PublishAck обязан разбираться"))
        .collect()
}

fn errors(envs: &[Envelope]) -> Vec<ProtocolError> {
    envs.iter()
        .filter(|e| kind_of(e) == Kind::Error)
        .map(|e| ProtocolError::decode(&e.frame).expect("Error обязан разбираться"))
        .collect()
}

fn publish_frame(agent: &Identity, v: &[i8; DIM], epoch: u64, published_bucket: u32) -> Vec<u8> {
    testing::PublishSpec {
        agent,
        vec_q: v,
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch,
        published_bucket,
        ttl_buckets: TTL,
        bits: POW,
    }
    .frame()
}

fn split_for(envs: Vec<Envelope>, q: Addr, r: Addr) -> (Vec<Envelope>, Vec<Envelope>) {
    let mut to_q = Vec::new();
    let mut to_r = Vec::new();
    for e in envs {
        if e.to == q {
            to_q.push(e);
        } else if e.to == r {
            to_r.push(e);
        } else {
            panic!("кадр {:?} адресован не Q и не R", kind_of(&e));
        }
    }
    (to_q, to_r)
}

/// База: Publish A на бакете 1 собирает W=2 (primary + первый ack), applied_seq=1 у всех.
fn base_publish(t: &mut Trio, p: Addr, q: Addr, r: Addr) {
    let agent = testing::identity(60);
    let frame = publish_frame(&agent, &testing::vector(20), 1, 1);
    let out = t
        .node_mut(p)
        .on_frame(agent.pubkey(), &frame, testing::clock(1))
        .expect("Publish A");
    assert_eq!(out.len(), 2, "база: по одному ReplicateOp каждой реплике: {out:?}");
    assert!(out.iter().all(|e| kind_of(e) == Kind::ReplicateOp));
    let (op_q, op_r) = split_for(out, q, r);
    let ack_q = t.route(p, &op_q, testing::clock(1));
    let ack_r = t.route(p, &op_r, testing::clock(1));
    let delivered = t.route(q, &ack_q, testing::clock(1));
    let a = acks(&delivered);
    assert_eq!(a.len(), 1, "база: W=2 собрался: {delivered:?}");
    assert_eq!(a[0].error_code, "OK");
    assert_eq!((a[0].epoch, a[0].seq), (1, 1));
    assert!(t.route(r, &ack_r, testing::clock(1)).is_empty(), "база: второй ack не нужен");
}

/// Раскол: Q и R объявляют P недоступным и принимают эпоху 2 из двух членов.
fn split_adopt_epoch2(
    t: &mut Trio,
    p: Addr,
    q: Addr,
    r: Addr,
    frame2: &[u8],
) {
    for seed in [q, r] {
        t.node_mut(seed)
            .peer_lost(p, 4)
            .expect("событие транспорта об обрыве с P");
    }
    for seed in [q, r] {
        let replies = t
            .node_mut(seed)
            .on_frame(q, frame2, testing::clock(4))
            .expect("переход эпохи 2 из легитимных подписей");
        assert!(errors(&replies).is_empty(), "раскол: переход без Error: {replies:?}");
    }
}

fn epoch2_frame(q_seed: u8, r_seed: u8) -> (Vec<u8>, [u8; 32]) {
    let params = testing::params(POW);
    let ordered1 = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let list2 = candidates::expected_update(
        2,
        SHARD,
        &testing::holders(&[q_seed, r_seed]),
        params.r,
        0,
        4,
    );
    let draft = membership::build_update(&list2, Vec::new());
    let mut sigs = Vec::new();
    for seed in [q_seed, r_seed] {
        let id = testing::identity(seed);
        let idx = ordered1
            .iter()
            .position(|h| h.owner_ed25519 == id.pubkey())
            .expect("подписант обязан быть участником эпохи 1");
        sigs.push((idx as u8, id.sign_domain(domain::MEMBER, &draft.unsigned_body())));
    }
    let upd2 = membership::build_update(&list2, sigs);
    let new_primary = list2.members[0].owner_ed25519;
    (testing::signed_frame(&upd2), new_primary)
}

// --- замер --------------------------------------------------------------------

#[test]
fn heal_demotion_window() {
    let ordered1 = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let p_seed = SEEDS
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == ordered1[0].owner_ed25519)
        .expect("primary эпохи 1 — один из тестовых сидов");
    let mut rest = SEEDS.iter().copied().filter(|s| *s != p_seed);
    let q_seed = rest.next().expect("второй сид");
    let r_seed = rest.next().expect("третий сид");
    let (frame2, new_primary) = epoch2_frame(q_seed, r_seed);
    let new_seed = SEEDS
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == new_primary)
        .expect("новый primary — один из сидов");

    // ---------- A: P не видел обрыва ----------
    let mut t = Trio::open("heal-a");
    let p = t.addr(p_seed);
    let q = t.addr(q_seed);
    let r = t.addr(r_seed);
    base_publish(&mut t, p, q, r);
    split_adopt_epoch2(&mut t, p, q, r, &frame2);

    // (0) База A.
    for seed in SEEDS {
        let n = t.node(t.addr(seed));
        assert_eq!(n.serving_epoch(4), Some(1), "(0) до раскола lease эпохи 1 жив");
        assert_eq!(n.applied_seq(), 1, "(0) запись A применена");
    }
    {
        let n = t.node(p);
        assert_eq!(n.epoch(), Some(1), "(0) P остался на эпохе 1");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, p, 6)),
            "(0) lease P: эпоха 1, expires 6"
        );
        assert_eq!(n.membership.as_ref().map(|m| m.members().len()), Some(3), "(0) состав [P,Q,R]");
    }

    // (1) Доставка до истечения lease: ожидание по [P,Q,R] — три члена против двух.
    for bucket in [4u32, 5] {
        let out = t
            .node_mut(p)
            .on_frame(q, &frame2, testing::clock(bucket))
            .expect("frame2 до истечения lease разбирается");
        assert!(out.is_empty(), "(1) приём молчалив на {bucket}: {out:?}");
        let n = t.node(p);
        assert_eq!(n.epoch(), Some(1), "(1) цепочка не принята на {bucket}");
        assert_eq!(n.serving_epoch(bucket), Some(1), "(1) P ещё обслуживает эпоху 1");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, p, 6)),
            "(1) lease не подменён грантом"
        );
    }

    // (2) Бакет 6: свой lease истёк, P исключает себя из live-roster — ожидание совпадает.
    let out = t
        .node_mut(p)
        .on_frame(q, &frame2, testing::clock(6))
        .expect("frame2 на бакете 6");
    assert_eq!(out.len(), 3, "(2) рассылка принятой эпохи + догон: {out:?}");
    let membership_updates: Vec<&Envelope> =
        out.iter().filter(|e| kind_of(e) == Kind::MembershipUpdate).collect();
    let pulls: Vec<&Envelope> =
        out.iter().filter(|e| kind_of(e) == Kind::WalPullRequest).collect();
    assert_eq!(membership_updates.len(), 2, "(2) эпоха уходит обеим репликам: {out:?}");
    assert_eq!(pulls.len(), 1, "(2) догон — новому primary: {out:?}");
    assert_eq!(pulls[0].to, t.addr(new_seed), "(2) WalPullRequest адресован primary эпохи 2");
    for e in &membership_updates {
        assert!(e.to == q || e.to == r, "(2) MembershipUpdate только репликам");
    }
    {
        let n = t.node(p);
        assert_eq!(n.epoch(), Some(2), "(2) цепочка принята");
        assert_eq!(n.store.serving_epoch(), Some(2), "(2) durable-маркер эпохи 2");
        assert_eq!(n.serving_epoch(6), Some(2), "(2) lease и маркер совпали");
        assert!(!n.is_member(), "(2) P исключён из состава");
        assert!(!n.is_primary(), "(2) P больше не primary");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary)),
            Some((2, new_primary)),
            "(2) adopt выдал lease эпохи 2"
        );
        let members: Vec<[u8; 32]> =
            n.membership.as_ref().expect("состав есть").members().iter().map(|m| m.owner_ed25519).collect();
        assert_eq!(
            members,
            vec![testing::identity(q_seed).pubkey(), testing::identity(r_seed).pubkey()],
            "(2) принятый состав — [Q,R] в детерминированном порядке"
        );
        assert_eq!(n.applied_seq(), 1, "(2) adopt не пишет WAL");
    }
    let agent_b = testing::identity(61);
    let frame_b = publish_frame(&agent_b, &testing::vector(30), 2, 6);
    let out = t
        .node_mut(p)
        .on_frame(agent_b.pubkey(), &frame_b, testing::clock(6))
        .expect("Publish на исключённом узле");
    let errs = errors(&out);
    assert_eq!(errs.len(), 1, "(2) ровно один отказ: {out:?}");
    assert_eq!(errs[0].code, err_code::NOT_OWNER, "(2) {errs:?}");
    assert!(acks(&out).is_empty(), "(2) OK не выдан");
    assert_eq!(t.node(p).applied_seq(), 1, "(2) WAL не тронут");
    t.clean();

    // ---------- B: P сам получил события обрыва ----------
    let mut t = Trio::open("heal-b");
    let p = t.addr(p_seed);
    let q = t.addr(q_seed);
    let r = t.addr(r_seed);
    base_publish(&mut t, p, q, r);
    split_adopt_epoch2(&mut t, p, q, r, &frame2);
    for addr in [q, r] {
        let out = t.node_mut(p).peer_lost(addr, 4).expect("P узнал обрыв с репликой");
        for e in &out {
            assert!(e.to == q || e.to == r, "(3) черновик P уходит только репликам");
        }
    }
    assert!(t.node(p).is_unreachable(&q), "(3) Q помечен недоступным");
    assert!(t.node(p).is_unreachable(&r), "(3) R помечен недоступным");

    for bucket in [6u32, 100] {
        let out = t
            .node_mut(p)
            .on_frame(q, &frame2, testing::clock(bucket))
            .expect("frame2 на {bucket}");
        assert!(out.is_empty(), "(3) приём молчалив и на {bucket}: {out:?}");
        assert_eq!(t.node(p).epoch(), Some(1), "(3) цепочка не принята на {bucket}");
        assert_eq!(t.node(p).serving_epoch(bucket), None, "(3) запись запрещена на {bucket}");
    }
    // Свой состав P видит пустым: Q,R недоступны, свой lease истёк.
    let out = t.node_mut(p).tick(6).expect("tick на бакете 6");
    assert_eq!(out.len(), 2, "(3) предложение уходит двум репликам: {out:?}");
    for e in &out {
        assert_eq!(kind_of(e), Kind::MembershipUpdate, "(3) только MembershipUpdate: {out:?}");
        assert!(e.to == q || e.to == r, "(3) адресат — Q или R");
        let upd = MembershipUpdate::decode(&e.frame).expect("MembershipUpdate разбирается");
        assert_eq!(upd.epoch, 2, "(3) предложение несёт эпоху 2");
        assert!(upd.members.is_empty(), "(3) P объявляет пустой шард: {upd:?}");
        assert_eq!(upd.sigs.len(), 1, "(3) подпись только своя — порога нет");
    }
    assert!(t.node_mut(p).tick(100).expect("tick на бакете 100").is_empty(), "(3) черновик уже разослан");
    assert_eq!(t.node(p).epoch(), Some(1), "(3) P так и остался на эпохе 1");
    assert!(t.node(p).is_unreachable(&q), "(3) peer_alive не случился — Q всё ещё мёртв");
    assert!(t.node(p).is_unreachable(&r), "(3) peer_alive не случился — R всё ещё мёртв");
    let agent_c = testing::identity(88);
    let frame_c = publish_frame(&agent_c, &testing::vector(40), 1, 100);
    let out = t
        .node_mut(p)
        .on_frame(agent_c.pubkey(), &frame_c, testing::clock(100))
        .expect("Publish на застрявшем P");
    let errs = errors(&out);
    assert_eq!(errs.len(), 1, "(3) ровно один отказ: {out:?}");
    assert_eq!(errs[0].code, err_code::EPOCH_STALE, "(3) {errs:?}");
    assert_eq!(t.node(p).applied_seq(), 1, "(3) WAL не тронут");
    t.clean();

    // ---------- C: цепочку P никто не переслал ----------
    let mut t = Trio::open("heal-c");
    let p = t.addr(p_seed);
    let q = t.addr(q_seed);
    let r = t.addr(r_seed);
    base_publish(&mut t, p, q, r);
    split_adopt_epoch2(&mut t, p, q, r, &frame2);
    for bucket in [6u32, 8, 10, 11] {
        for seed in [q, r] {
            let out = t.node_mut(seed).tick(bucket).expect("тик живого члена эпохи 2");
            for e in &out {
                assert_ne!(e.to, p, "(4) кадр к P на бакете {bucket}: {out:?}");
            }
        }
    }
    {
        let n = t.node(p);
        assert_eq!(n.epoch(), Some(1), "(4) P не узнал об эпохе 2");
        assert_eq!(n.serving_epoch(11), None, "(4) после истечения lease записи нет");
        assert_eq!(n.applied_seq(), 1, "(4) WAL не тронут");
    }
    let agent_d = testing::identity(89);
    let frame_d = publish_frame(&agent_d, &testing::vector(50), 1, 11);
    let out = t
        .node_mut(p)
        .on_frame(agent_d.pubkey(), &frame_d, testing::clock(11))
        .expect("Publish на P без цепочки");
    let errs = errors(&out);
    assert_eq!(errs.len(), 1, "(4) ровно один отказ: {out:?}");
    assert_eq!(errs[0].code, err_code::EPOCH_STALE, "(4) {errs:?}");
    assert_eq!(t.node(p).applied_seq(), 1, "(4) WAL не тронут");
    t.clean();
}
