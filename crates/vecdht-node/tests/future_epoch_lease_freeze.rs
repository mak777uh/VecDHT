//! H-0067 / E-0067: грант lease будущей эпохи как заморозка шарда.
//!
//! `E-0066` закрыл грант **прошлой** эпохи. Здесь меряется обратное направление:
//! `Lease::verify` отвергает только `g.epoch < have`, а `handle_lease_grant` сверяет лишь
//! подпись с ключом, который сам себя объявил primary. Грант `epoch=1000` от ключа вне
//! состава принимается, `lease_active` падает (эпохи не совпадают), `serving_epoch` — в
//! `None`, publish получает `EPOCH_STALE` до WAL, а `tick` не продлевает lease и не
//! предлагает следующую эпоху до чужого `expires_at_bucket`.
//!
//! Два независимых трио: A — срок `u32::MAX` и проверка, что и на бакете 6 (настоящая
//! lease истекла), и на 1000 нет ни продления, ни выбора; B — срок 10 и проверка, что
//! заморозка кончается ровно на чужой границе, а не на 6. Доставка ручная, без таймеров.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::{Addr, Envelope};
use vecdht_node::{Clock, Lease, ShardNode, candidates, testing};
use vecdht_wire::codec::DIM;
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{Codec, MembershipUpdate, ProtocolError, PublishAck, err_code};

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
    /// выдал lease каждому, а пустой store нечего догонять.
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

/// Грант, подписанный ключом, который сам себя объявил primary. Именно такую форму
/// `Lease::verify` принимает: подпись сходится с `primary_ed25519`, а членство не спрашивается.
fn fake_grant(attacker: &Identity, epoch: u64, expires_at_bucket: u32) -> Vec<u8> {
    Lease { epoch, primary: attacker.pubkey(), expires_at_bucket }
        .signed_frame(SHARD, attacker, vec![0xAA; 34])
}

// --- замер --------------------------------------------------------------------

#[test]
fn a_future_epoch_grant_from_an_arbitrary_key_freezes_the_shard() {
    let attacker = testing::identity(77);
    assert!(
        !SEEDS.iter().any(|s| testing::identity(*s).pubkey() == attacker.pubkey()),
        "Attacker обязан быть вне состава"
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

    let mut t = Trio::open("future-freeze-a");
    let p = t.addr(p_seed);
    let q = t.addr(q_seed);
    let r = t.addr(r_seed);

    // (0) База: путь W=2 работает до гранта.
    for seed in SEEDS {
        let addr = t.addr(seed);
        assert_eq!(
            t.node(addr).serving_epoch(1),
            Some(1),
            "(0) genesis выдал lease эпохи 1 каждому"
        );
    }
    let agent_a = testing::identity(60);
    let va = testing::vector(20);
    let frame_a = publish_frame(&agent_a, &va, 1, 1);
    let out = t
        .node_mut(p)
        .on_frame(agent_a.pubkey(), &frame_a, testing::clock(1))
        .expect("Publish A до гранта");
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
        let addr = t.addr(seed);
        assert_eq!(t.node(addr).applied_seq(), 1, "(0) запись A применена");
    }

    // (1) Грант будущей эпохи от не-члена принимается каждым молча.
    let grant_forever = fake_grant(&attacker, 1000, u32::MAX);
    for seed in SEEDS {
        let addr = t.addr(seed);
        let out = t
            .node_mut(addr)
            .on_frame(attacker.pubkey(), &grant_forever, testing::clock(2))
            .expect("грант разбирается");
        assert!(out.is_empty(), "(1) приём гранта молчалив: {out:?}");
    }
    for seed in SEEDS {
        let addr = t.addr(seed);
        let n = t.node(addr);
        assert_eq!(n.epoch(), Some(1), "(1) цепочка не двигалась");
        assert!(!n.lease_active(2), "(1) lease чужой эпохи не активен");
        assert_eq!(n.serving_epoch(2), None, "(1) запись запрещена");
        assert_eq!(n.applied_seq(), 1, "(1) грант не пишет WAL");
    }
    assert!(t.node(p).is_primary(), "(1) P остаётся primary по членству");
    assert!(!t.node(q).is_primary(), "(1) Q не primary");
    assert!(!t.node(r).is_primary(), "(1) R не primary");

    // (2) Publish после гранта: отказ стоит до admission/WAL, реплик нет вовсе.
    let agent_b = testing::identity(61);
    let vb = testing::vector(30);
    let frame_b = publish_frame(&agent_b, &vb, 1, 3);
    let out = t
        .node_mut(p)
        .on_frame(agent_b.pubkey(), &frame_b, testing::clock(3))
        .expect("Publish B после гранта");
    let errs = errors(&out);
    assert_eq!(errs.len(), 1, "(2) ровно один отказ: {out:?}");
    assert_eq!(errs[0].code, err_code::EPOCH_STALE, "(2) {errs:?}");
    assert_eq!(out.len(), 1, "(2) ни ReplicateOp, ни PublishAck: {out:?}");
    assert!(acks(&out).is_empty(), "(2) OK не выдан");
    for seed in SEEDS {
        let addr = t.addr(seed);
        assert_eq!(t.node(addr).applied_seq(), 1, "(2) WAL не тронут");
        assert_eq!(
            owner_slot(t.node(addr), &agent_b.pubkey()),
            None,
            "(2) записи B нет ни у кого"
        );
    }
    assert_eq!(t.node(p).serving_epoch(3), None, "(2) serving_epoch по-прежнему пуст");

    // (3) Настоящая lease истекла на 6, но чужой expires держит узел: тик пуст.
    for seed in SEEDS {
        let addr = t.addr(seed);
        let out = t.node_mut(addr).tick(6).expect("tick на бакете 6");
        assert!(out.is_empty(), "(3) продление/выбор живы: {out:?}");
    }
    for seed in SEEDS {
        let addr = t.addr(seed);
        let n = t.node(addr);
        assert_eq!(n.epoch(), Some(1), "(3) эпоха не сменилась");
        assert_eq!(n.serving_epoch(6), None, "(3) запись всё ещё запрещена");
    }

    // (4) Далеко за настоящим сроком: чужой expires всё ещё держит; запись отклоняется.
    for seed in SEEDS {
        let addr = t.addr(seed);
        let out = t.node_mut(addr).tick(1000).expect("tick на бакете 1000");
        assert!(out.is_empty(), "(4) выбор эпохи ожил: {out:?}");
    }
    let agent_c = testing::identity(88);
    let vc = testing::vector(40);
    let frame_c = publish_frame(&agent_c, &vc, 1, 1000);
    let out = t
        .node_mut(p)
        .on_frame(agent_c.pubkey(), &frame_c, testing::clock(1000))
        .expect("Publish C после долгой заморозки");
    let errs = errors(&out);
    assert_eq!(errs.len(), 1, "(4) ровно один отказ: {out:?}");
    assert_eq!(errs[0].code, err_code::EPOCH_STALE, "(4) {errs:?}");
    for seed in SEEDS {
        let addr = t.addr(seed);
        assert_eq!(t.node(addr).applied_seq(), 1, "(4) WAL не тронут и поздно");
    }

    // (5) Срок — чужой: при expires=10 тик 9 пуст, тик 10 возвращает выбор.
    let grant_short = fake_grant(&attacker, 1000, 10);
    let mut s = Trio::open("future-freeze-b");
    for seed in SEEDS {
        let addr = s.addr(seed);
        assert_eq!(
            s.node(addr).serving_epoch(1),
            Some(1),
            "(5) до гранта lease эпохи 1 действует"
        );
    }
    for seed in SEEDS {
        let addr = s.addr(seed);
        let out = s
            .node_mut(addr)
            .on_frame(attacker.pubkey(), &grant_short, testing::clock(2))
            .expect("короткий грант разбирается");
        assert!(out.is_empty(), "(5) приём молчалив: {out:?}");
    }
    for seed in SEEDS {
        let addr = s.addr(seed);
        let n = s.node(addr);
        assert!(!n.lease_active(2), "(5) lease чужой эпохи не активен");
        assert_eq!(n.serving_epoch(2), None, "(5) запись запрещена");
    }
    for seed in SEEDS {
        let addr = s.addr(seed);
        let out = s.node_mut(addr).tick(9).expect("tick на бакете 9");
        assert!(out.is_empty(), "(5) заморозка кончилась раньше срока: {out:?}");
    }
    let owners: Vec<[u8; 32]> = SEEDS.iter().map(|s| testing::identity(*s).pubkey()).collect();
    let first_owner = candidates::speaker_order(2, SHARD, &owners)[0];
    let first_seed = SEEDS
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == first_owner)
        .expect("говорящий ранга 0 — один из сидов");
    let first = s.addr(first_seed);
    let out = s.node_mut(first).tick(10).expect("tick на чужой границе");
    assert_eq!(out.len(), 2, "(5) предложение эпохи 2 двум коллегам: {out:?}");
    assert!(
        out.iter().all(|e| kind_of(e) == Kind::MembershipUpdate),
        "(5) только MembershipUpdate: {out:?}"
    );
    for e in &out {
        let upd = MembershipUpdate::decode(&e.frame).expect("MembershipUpdate разбирается");
        assert_eq!(upd.epoch, 2, "(5) предложение несёт эпоху 2");
    }
    for seed in SEEDS {
        let addr = s.addr(seed);
        let n = s.node(addr);
        assert_eq!(n.epoch(), Some(1), "(5) предложение ещё не принято");
        assert_eq!(n.serving_epoch(10), None, "(5) запись вернётся только с новым lease");
    }

    t.clean();
    s.clean();
}
