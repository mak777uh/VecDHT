//! H-0068 / E-0068: `LeaseGrant` привязан к принятой эпохе и primary членства (ADR-0016).
//!
//! Обратный оракул к историческому `future_epoch_lease_freeze.rs`: там грант будущей эпохи
//! от произвольного ключа **замораживал** шард (`E-0067`, rev `20921de`). Здесь заморозки быть
//! не должно: `Lease::verify` отвергает `g.epoch != have` (`Future`/`Stale`), а
//! `handle_lease_grant` принимает только грант от primary **принятого** состава. Ротация при
//! этом не ломается: `adopt` эпохи 2 сам выдаёт lease эпохи 2 каждому принявшему, поэтому
//! легитимный грант нового primary после членства принимается, а до членства — отвергается.
//!
//! Ручная доставка, без таймеров; три независимых `ShardNode` в одном процессе.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::{Addr, Envelope};
use vecdht_node::{Clock, Lease, ShardNode, candidates, membership, testing};
use vecdht_wire::codec::DIM;
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{Codec, ProtocolError, PublishAck, domain, err_code};

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
    /// Три держателя шарда с genesis эпохи 1. Ответы genesis не разносятся: `adopt` уже
    /// выдал lease каждому (expires = 0 + lease_buckets), а пустой store нечего догонять.
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
        // Сначала закрываем store, потом каталоги: на Windows удаление файла с открытым handle
        // молча не срабатывает и temp забивается после прогона.
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

fn owner_slot(n: &ShardNode, owner: &[u8; 32]) -> Option<u32> {
    n.store.index.owner_slot(owner)
}

fn signed_grant(by: &Identity, epoch: u64, primary: Addr, expires_at_bucket: u32) -> Vec<u8> {
    Lease { epoch, primary, expires_at_bucket }.signed_frame(SHARD, by, vec![0xAA; 34])
}

// --- замер --------------------------------------------------------------------

#[test]
fn a_grant_is_bound_to_the_accepted_epoch_and_primary() {
    let params = testing::params(POW);
    let attacker = testing::identity(77);
    assert!(
        !SEEDS.iter().any(|s| testing::identity(*s).pubkey() == attacker.pubkey()),
        "attacker обязан быть вне состава"
    );

    // P — primary эпохи 1 по детерминированному порядку (§9.3), Q и R — остальные.
    let ordered1 = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let p_seed = SEEDS
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == ordered1[0].owner_ed25519)
        .expect("primary эпохи 1 — один из тестовых сидов");
    let mut rest = SEEDS.iter().copied().filter(|s| *s != p_seed);
    let q_seed = rest.next().expect("второй сид");
    let r_seed = rest.next().expect("третий сид");

    let mut t = Trio::open("lease-binding");
    let p = t.addr(p_seed);
    let q = t.addr(q_seed);
    let r = t.addr(r_seed);

    // (0) База: путь W=2 работает до всяких грантов.
    for seed in SEEDS {
        let addr = t.addr(seed);
        assert_eq!(
            t.node(addr).serving_epoch(1),
            Some(1),
            "(0) genesis выдал lease эпохи 1 каждому"
        );
    }
    let agent_a = testing::identity(60);
    let frame_a = publish_frame(&agent_a, &testing::vector(20), 1, 1);
    let out = t
        .node_mut(p)
        .on_frame(agent_a.pubkey(), &frame_a, testing::clock(1))
        .expect("Publish A до грантов");
    assert!(acks(&out).is_empty(), "(0) сам fsync — не кворум");
    assert!(errors(&out).is_empty(), "(0) P принял запись: {out:?}");
    assert_eq!(out.len(), 2, "(0) по одному ReplicateOp каждой реплике");
    assert!(out.iter().all(|e| kind_of(e) == Kind::ReplicateOp));
    let (op_q, op_r) = split_for(out, q, r);
    let ack_q = t.route(p, &op_q, testing::clock(1));
    let ack_r = t.route(p, &op_r, testing::clock(1));
    let delivered = t.route(q, &ack_q, testing::clock(1));
    let a = acks(&delivered);
    assert_eq!(a.len(), 1, "(0) W=2 собрался: {delivered:?}");
    assert_eq!(a[0].error_code, "OK", "(0) {a:?}");
    assert_eq!(a[0].epoch, 1);
    assert_eq!(a[0].seq, 1);
    assert!(t.route(r, &ack_r, testing::clock(1)).is_empty(), "(0) второй ack не нужен");
    for seed in SEEDS {
        assert_eq!(t.node(t.addr(seed)).applied_seq(), 1, "(0) запись A применена");
    }

    // (1) Future-грант от не-члена отвергнут: EPOCH_STALE, lease и serving не меняются.
    let grant_future = signed_grant(&attacker, 1000, attacker.pubkey(), u32::MAX);
    for seed in SEEDS {
        let addr = t.addr(seed);
        let out = t
            .node_mut(addr)
            .on_frame(attacker.pubkey(), &grant_future, testing::clock(2))
            .expect("грант разбирается");
        let errs = errors(&out);
        assert_eq!(errs.len(), 1, "(1) ровно один отказ: {out:?}");
        assert_eq!(errs[0].code, err_code::EPOCH_STALE, "(1) {errs:?}");
        assert_eq!(out.len(), 1, "(1) кроме Error ничего: {out:?}");
    }
    for seed in SEEDS {
        let n = t.node(t.addr(seed));
        assert_eq!(n.epoch(), Some(1), "(1) цепочка не двигалась");
        assert!(n.lease_active(2), "(1) lease эпохи 1 остался активен");
        assert_eq!(n.serving_epoch(2), Some(1), "(1) запись не заморожена");
        assert_eq!(
            n.lease.as_ref().map(|l| l.primary),
            Some(p),
            "(1) lease.primary не подменён"
        );
        assert_eq!(n.applied_seq(), 1, "(1) грант не пишет WAL");
    }

    // (2) Запись после отвергнутого гранта: W=2 собирается, заморозки нет.
    let agent_b = testing::identity(61);
    let vb = testing::vector(30);
    let frame_b = publish_frame(&agent_b, &vb, 1, 3);
    let out = t
        .node_mut(p)
        .on_frame(agent_b.pubkey(), &frame_b, testing::clock(3))
        .expect("Publish B после future-гранта");
    assert!(acks(&out).is_empty(), "(2) OK сразу не выдаётся");
    assert!(errors(&out).is_empty(), "(2) P принял запись: {out:?}");
    assert_eq!(out.len(), 2, "(2) два ReplicateOp");
    let (op_q, op_r) = split_for(out, q, r);
    let ack_q = t.route(p, &op_q, testing::clock(3));
    let ack_r = t.route(p, &op_r, testing::clock(3));
    let delivered = t.route(q, &ack_q, testing::clock(3));
    let a = acks(&delivered);
    assert_eq!(a.len(), 1, "(2) W=2 собрался: {delivered:?}");
    assert_eq!(a[0].error_code, "OK", "(2) {a:?}");
    assert_eq!(a[0].epoch, 1);
    assert_eq!(a[0].seq, 2);
    assert!(t.route(r, &ack_r, testing::clock(3)).is_empty());
    for seed in SEEDS {
        let addr = t.addr(seed);
        assert_eq!(t.node(addr).applied_seq(), 2, "(2) B применена");
        assert!(
            owner_slot(t.node(addr), &agent_b.pubkey()).is_some(),
            "(2) владелец B виден"
        );
    }

    // (3) Грант той же эпохи от члена-не-primary: подпись верна, права нет — молчание.
    let q_id = testing::identity(q_seed);
    let forged_same_epoch = signed_grant(&q_id, 1, q_id.pubkey(), u32::MAX);
    for addr in [p, r] {
        let out = t
            .node_mut(addr)
            .on_frame(q, &forged_same_epoch, testing::clock(3))
            .expect("same-epoch грант разбирается");
        assert!(out.is_empty(), "(3) приём молчалив: {out:?}");
        let n = t.node(addr);
        assert_eq!(
            n.lease.as_ref().map(|l| l.primary),
            Some(p),
            "(3) lease.primary не подменён членом"
        );
        assert_eq!(
            n.lease.as_ref().map(|l| l.expires_at_bucket),
            Some(6),
            "(3) expires не подменён на u32::MAX"
        );
        assert!(n.lease_active(3), "(3) lease эпохи 1 ещё жив");
    }
    // Настоящий lease истекает на 6: бакет 4 — последний, где remaining ≤ renew и продление
    // обязано случиться. Подмена expires на u32::MAX погасила бы `due` и оставила реплики без
    // lease на бакете 6.
    let out = t.node_mut(p).tick(4).expect("tick на бакете 4");
    assert_eq!(out.len(), 2, "(3) продление пошло двум репликам: {out:?}");
    assert!(
        out.iter().all(|e| kind_of(e) == Kind::LeaseGrant),
        "(3) только LeaseGrant: {out:?}"
    );
    for e in &out {
        let g = vecdht_wire::messages::LeaseGrant::decode(&e.frame).expect("LeaseGrant разбирается");
        assert_eq!(g.epoch, 1, "(3) продлевается принятая эпоха");
        assert_eq!(g.primary_ed25519, p, "(3) продлевает настоящий primary");
    }
    let renew = t.route(p, &out, testing::clock(4));
    assert!(renew.is_empty(), "(3) реплики приняли продление молча: {renew:?}");
    for seed in SEEDS {
        let n = t.node(t.addr(seed));
        assert!(n.lease_active(4), "(3) lease активен на 4");
        assert_eq!(n.serving_epoch(4), Some(1), "(3) запись не заморожена");
    }

    // (4) Легитимная ротация без P: Q и R принимают эпоху 2, adopt сам выдаёт lease эпохи 2.
    for seed in [q_seed, r_seed] {
        t.node_mut(t.addr(seed))
            .peer_lost(p, 4)
            .expect("событие транспорта об обрыве с P");
    }
    let list2 =
        candidates::expected_update(2, SHARD, &testing::holders(&[q_seed, r_seed]), params.r, 0, 4);
    let draft = membership::build_update(&list2, Vec::new());
    let mut sigs = Vec::new();
    for seed in [q_seed, r_seed] {
        let id = testing::identity(seed);
        let idx = ordered1
            .iter()
            .position(|h| h.owner_ed25519 == id.pubkey())
            .expect("подписант эпохи 2 обязан быть участником эпохи 1");
        sigs.push((idx as u8, id.sign_domain(domain::MEMBER, &draft.unsigned_body())));
    }
    let upd2 = membership::build_update(&list2, sigs);
    let frame2 = testing::signed_frame(&upd2);
    for seed in [q_seed, r_seed] {
        let addr = t.addr(seed);
        let replies = t
            .node_mut(addr)
            .on_frame(q, &frame2, testing::clock(4))
            .expect("переход эпохи 2 собран из легитимных подписей");
        assert!(errors(&replies).is_empty(), "(4) переход без Error: {replies:?}");
    }
    let new_primary = list2.members[0].owner_ed25519;
    let follower = list2.members[1].owner_ed25519;
    assert!(t.node(new_primary).is_primary(), "(4) primary эпохи 2 — members[0]");
    assert!(!t.node(follower).is_primary(), "(4) вторая реплика не primary");
    for seed in [q_seed, r_seed] {
        let n = t.node(t.addr(seed));
        assert_eq!(n.epoch(), Some(2), "(4) эпоха 2 принята");
        assert_eq!(n.store.serving_epoch(), Some(2), "(4) durable-маркер эпохи 2");
        assert_eq!(n.serving_epoch(4), Some(2), "(4) lease и цепочка совпали");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary)),
            Some((2, new_primary)),
            "(4) adopt выдал lease новой эпохи"
        );
    }
    assert_eq!(t.node(p).epoch(), Some(1), "(4) P о разделении не узнал");
    assert_eq!(t.node(p).serving_epoch(4), Some(1), "(4) P обслуживает эпоху 1");

    // Легитимный грант нового primary: принявшая эпоху реплика принимает, P — future.
    let new_seed = SEEDS
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == new_primary)
        .expect("новый primary — один из сидов");
    let legit = signed_grant(&testing::identity(new_seed), 2, new_primary, 10);
    let out = t
        .node_mut(follower)
        .on_frame(new_primary, &legit, testing::clock(4))
        .expect("легитимный грант эпохи 2");
    assert!(out.is_empty(), "(4) реплика приняла молча: {out:?}");
    assert_eq!(t.node(follower).serving_epoch(4), Some(2), "(4) lease эпохи 2 действует");
    let out = t
        .node_mut(p)
        .on_frame(new_primary, &legit, testing::clock(4))
        .expect("грант новой эпохи на старом primary");
    let errs = errors(&out);
    assert_eq!(errs.len(), 1, "(4) P обязан отказать: {out:?}");
    assert_eq!(errs[0].code, err_code::EPOCH_STALE, "(4) {errs:?}");
    assert_eq!(t.node(p).epoch(), Some(1), "(4) грант не двигает эпоху P");
    assert_eq!(t.node(p).serving_epoch(4), Some(1), "(4) lease P не подменён");

    // (5) Новая эпоха пишет W=2 (два узла): ровно один ReplicateOp и OK.
    let agent_c = testing::identity(88);
    let vc = testing::vector(40);
    let frame_c = publish_frame(&agent_c, &vc, 2, 4);
    let out = t
        .node_mut(new_primary)
        .on_frame(agent_c.pubkey(), &frame_c, testing::clock(4))
        .expect("Publish C на primary эпохи 2");
    assert!(errors(&out).is_empty(), "(5) ошибок нет: {out:?}");
    assert_eq!(out.len(), 1, "(5) в составе эпохи 2 одна реплика: {out:?}");
    assert_eq!(kind_of(&out[0]), Kind::ReplicateOp);
    let ack_frames = t.route(new_primary, &out, testing::clock(4));
    assert_eq!(ack_frames.len(), 1, "(5) реплика подтвердила применение");
    let delivered = t.route(follower, &ack_frames, testing::clock(4));
    let a = acks(&delivered);
    assert_eq!(a.len(), 1, "(5) W=2 собрался: {delivered:?}");
    assert_eq!(a[0].error_code, "OK", "(5) {a:?}");
    assert_eq!(a[0].epoch, 2);
    assert_eq!(a[0].seq, 3);
    assert_eq!(t.node(new_primary).applied_seq(), 3, "(5) primary применил C");
    assert_eq!(t.node(follower).applied_seq(), 3, "(5) реплика применила C");
    assert_eq!(t.node(p).applied_seq(), 2, "(5) P остался на своей эпохе");
    for addr in [new_primary, follower] {
        assert!(
            owner_slot(t.node(addr), &agent_c.pubkey()).is_some(),
            "(5) владелец C виден в эпохе 2"
        );
    }
    assert_eq!(
        owner_slot(t.node(p), &agent_c.pubkey()),
        None,
        "(5) в индексе P владельца C нет"
    );

    t.clean();
}
