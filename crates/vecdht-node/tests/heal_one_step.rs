//! H-0070 / E-0070: heal в один шаг после ADR-0017.
//!
//! Проверяются три правила ADR-0017 на одном шарде с ручной доставкой:
//! * R1 — `peer_alive` на завершении handshake снимает `unreachable` и отдаёт цепочку;
//! * R2 — устаревший `MembershipUpdate` получает ответ текущей цепочкой;
//! * R3 — цепочка, исключающая узел, демотирует его без сверки с локальным `live_roster`,
//!   а содержащая его — по-прежнему обязана совпасть с кандидатами.
//!
//! Сценарий heal: P (primary эпохи 1) и Q,R пережили разрыв; Q,R приняли эпоху 2 `[Q,R]`,
//! все трое считают друг друга недоступными. Переподключение P↔Q на бакете 4 (lease P ещё
//! жив, expires=6) обязано демотировать P парой кадров, без `tick` и без внешней доставки.

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
fn split_adopt_epoch2(t: &mut Trio, p: Addr, q: Addr, r: Addr, frame2: &[u8]) {
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

fn ordered1() -> Vec<vecdht_node::candidates::Holder> {
    candidates::ordered(1, SHARD, &testing::holders(&SEEDS))
}

fn sig_index(ordered: &[vecdht_node::candidates::Holder], seed: u8) -> u8 {
    let key = testing::identity(seed).pubkey();
    ordered
        .iter()
        .position(|h| h.owner_ed25519 == key)
        .expect("подписант обязан быть участником эпохи 1") as u8
}

/// Кадр эпохи 2: состав из `members_seeds`, подписи `signers` (индексы эпохи 1).
fn epoch_frame(members_seeds: &[u8], signers: &[u8]) -> Vec<u8> {
    let params = testing::params(POW);
    let list = candidates::expected_update(
        2,
        SHARD,
        &testing::holders(members_seeds),
        params.r,
        0,
        4,
    );
    let draft = membership::build_update(&list, Vec::new());
    let ordered = ordered1();
    let sigs: Vec<(u8, [u8; 64])> = signers
        .iter()
        .map(|seed| {
            let id = testing::identity(*seed);
            (
                sig_index(&ordered, *seed),
                id.sign_domain(domain::MEMBER, &draft.unsigned_body()),
            )
        })
        .collect();
    testing::signed_frame(&membership::build_update(&list, sigs))
}

fn epoch2_frame(q_seed: u8, r_seed: u8) -> (Vec<u8>, [u8; 32]) {
    let params = testing::params(POW);
    let list = candidates::expected_update(
        2,
        SHARD,
        &testing::holders(&[q_seed, r_seed]),
        params.r,
        0,
        4,
    );
    let new_primary = list.members[0].owner_ed25519;
    (epoch_frame(&[q_seed, r_seed], &[q_seed, r_seed]), new_primary)
}

// --- замер --------------------------------------------------------------------

#[test]
fn heal_one_step() {
    let ordered = ordered1();
    let p_seed = SEEDS
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == ordered[0].owner_ed25519)
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

    // ---------- heal: R1 → R2 → R3 ----------
    let mut t = Trio::open("heal-one");
    let p = t.addr(p_seed);
    let q = t.addr(q_seed);
    let r = t.addr(r_seed);
    base_publish(&mut t, p, q, r);
    split_adopt_epoch2(&mut t, p, q, r, &frame2);
    for addr in [q, r] {
        t.node_mut(p).peer_lost(addr, 4).expect("P узнал обрыв с репликой");
    }

    // (0) База: P на эпохе 1 с живым lease, оба репликанта помечены мёртвыми.
    {
        let n = t.node(p);
        assert_eq!(n.epoch(), Some(1), "(0) P остался на эпохе 1");
        assert_eq!(n.serving_epoch(4), Some(1), "(0) P обслуживает эпоху 1");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, p, 6)),
            "(0) lease P: эпоха 1, expires 6"
        );
        assert_eq!(n.applied_seq(), 1, "(0) запись A применена у P");
        assert!(n.is_unreachable(&q), "(0) Q помечен недоступным у P");
        assert!(n.is_unreachable(&r), "(0) R помечен недоступным у P");
        assert_eq!(n.membership.as_ref().map(|m| m.members().len()), Some(3), "(0) [P,Q,R]");
    }
    for addr in [q, r] {
        let n = t.node(addr);
        assert_eq!(n.epoch(), Some(2), "(0) Q/R приняли эпоху 2");
        assert_eq!(n.serving_epoch(4), Some(2), "(0) Q/R обслуживают эпоху 2");
        assert_eq!(n.applied_seq(), 1, "(0) запись A применена у Q/R");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary)),
            Some((2, new_primary)),
            "(0) adopt выдал lease эпохи 2"
        );
    }

    // (1) R1: peer_alive снимает метку и отдаёт цепочку; R2: Q отвечает своей.
    let alive = t.node_mut(p).peer_alive(q).expect("handshake с Q завершён");
    assert_eq!(alive.len(), 1, "(1) peer_alive отдаёт ровно одну цепочку: {alive:?}");
    assert_eq!(kind_of(&alive[0]), Kind::MembershipUpdate, "(1) kind");
    assert_eq!(alive[0].to, q, "(1) адресат — Q");
    let sent = MembershipUpdate::decode(&alive[0].frame).expect("цепочка разбирается");
    assert_eq!(sent.epoch, 1, "(1) P отдаёт свою принятую эпоху");
    {
        let n = t.node(p);
        assert!(!n.is_unreachable(&q), "(1) Q снова достижим");
        assert!(n.is_unreachable(&r), "(1) R ещё не переподключился");
        assert_eq!(n.epoch(), Some(1), "(1) одна метка — не демоция");
        assert_eq!(n.serving_epoch(4), Some(1), "(1) P ещё пишет эпоху 1");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, p, 6)),
            "(1) lease не тронут"
        );
    }
    let reply = t.route(p, &alive, testing::clock(4));
    assert_eq!(reply.len(), 1, "(1) Q отвечает одной цепочкой: {reply:?}");
    assert_eq!(kind_of(&reply[0]), Kind::MembershipUpdate, "(1) R2: kind");
    assert_eq!(reply[0].to, p, "(1) R2: ответ P");
    let got = MembershipUpdate::decode(&reply[0].frame).expect("ответ разбирается");
    assert_eq!(got.epoch, 2, "(1) R2: Q отдаёт принятую эпоху 2");
    {
        let n = t.node(q);
        assert_eq!(n.epoch(), Some(2), "(1) Q не изменился");
        assert_eq!(n.serving_epoch(4), Some(2), "(1) Q по-прежнему пишет эпоху 2");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary)),
            Some((2, new_primary)),
            "(1) lease Q не тронут"
        );
    }

    // (2) R3: исключающая цепочка демотирует P до истечения lease, без tick.
    let healed = t.route(q, &reply, testing::clock(4));
    assert_eq!(healed.len(), 3, "(2) рассылка принятой эпохи + догон: {healed:?}");
    let updates: Vec<&Envelope> =
        healed.iter().filter(|e| kind_of(e) == Kind::MembershipUpdate).collect();
    let pulls: Vec<&Envelope> =
        healed.iter().filter(|e| kind_of(e) == Kind::WalPullRequest).collect();
    assert_eq!(updates.len(), 2, "(2) эпоха уходит обеим репликам: {healed:?}");
    assert_eq!(pulls.len(), 1, "(2) догон — новому primary: {healed:?}");
    assert_eq!(pulls[0].to, t.addr(new_seed), "(2) WalPullRequest адресован primary эпохи 2");
    for e in &updates {
        assert!(e.to == q || e.to == r, "(2) MembershipUpdate только репликам");
    }
    {
        let n = t.node(p);
        assert_eq!(n.epoch(), Some(2), "(2) цепочка принята на бакете 4");
        assert_eq!(n.store.serving_epoch(), Some(2), "(2) durable-маркер эпохи 2");
        assert_eq!(
            n.serving_epoch(4),
            Some(2),
            "(2) принятие подтверждено lease и маркером; право писать — отдельный гейт"
        );
        assert!(!n.is_member(), "(2) P исключён из состава");
        assert!(!n.is_primary(), "(2) P больше не primary");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary)),
            Some((2, new_primary)),
            "(2) adopt выдал lease эпохи 2"
        );
        let members: Vec<[u8; 32]> = n
            .membership
            .as_ref()
            .expect("состав есть")
            .members()
            .iter()
            .map(|m| m.owner_ed25519)
            .collect();
        assert_eq!(
            members,
            vec![testing::identity(q_seed).pubkey(), testing::identity(r_seed).pubkey()],
            "(2) принятый состав — [Q,R]"
        );
        assert_eq!(n.applied_seq(), 1, "(2) adopt не пишет WAL");
        assert!(!n.is_unreachable(&q) && !n.is_unreachable(&r), "(2) adopt снял метки членов");
    }
    let agent_b = testing::identity(61);
    let frame_b = publish_frame(&agent_b, &testing::vector(30), 2, 4);
    let out = t
        .node_mut(p)
        .on_frame(agent_b.pubkey(), &frame_b, testing::clock(4))
        .expect("Publish на исключённом узле");
    let errs = errors(&out);
    assert_eq!(errs.len(), 1, "(2) ровно один отказ: {out:?}");
    assert_eq!(errs[0].code, err_code::NOT_OWNER, "(2) {errs:?}");
    assert!(acks(&out).is_empty(), "(2) OK не выдан");
    assert_eq!(t.node(p).applied_seq(), 1, "(2) WAL не тронут");

    // (3) Замыкание: равная эпоха молчит, тики не адресуют P ни кадра.
    let m_updates: Vec<Envelope> = healed
        .iter()
        .filter(|e| kind_of(e) == Kind::MembershipUpdate)
        .cloned()
        .collect();
    let echoes = t.route(p, &m_updates, testing::clock(4));
    assert!(echoes.is_empty(), "(3) равная эпоха молчит: {echoes:?}");
    for seed in [q_seed, r_seed] {
        let a = t.addr(seed);
        for bucket in [4u32, 5] {
            let out = t.node_mut(a).tick(bucket).expect("тик живого члена эпохи 2");
            assert!(out.is_empty(), "(3) тик {bucket} {seed} пуст: {out:?}");
        }
    }
    assert!(t.node_mut(p).tick(4).expect("тик исключённого P").is_empty(), "(3) P не член");
    t.clean();

    // ---------- гейт: включающая чужая цепочка не принимается ----------
    let mut t = Trio::open("heal-gate");
    let p = t.addr(p_seed);
    let q = t.addr(q_seed);
    let r = t.addr(r_seed);
    base_publish(&mut t, p, q, r);
    let foreign = epoch_frame(&[p_seed, q_seed], &[q_seed, r_seed]);
    for bucket in [4u32, 6] {
        let out = t
            .node_mut(p)
            .on_frame(q, &foreign, testing::clock(bucket))
            .expect("включающая чужая цепочка разбирается");
        assert!(out.is_empty(), "(4) включающая цепочка отвергнута на {bucket}: {out:?}");
        let n = t.node(p);
        assert_eq!(n.epoch(), Some(1), "(4) цепочка не принята на {bucket}");
        if bucket == 4 {
            assert_eq!(n.serving_epoch(4), Some(1), "(4) на 4 P ещё обслуживает эпоху 1");
        } else {
            assert_eq!(
                n.serving_epoch(6),
                None,
                "(4) на 6 lease истёк, но включающая цепочка всё равно не принята"
            );
        }
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, p, 6)),
            "(4) lease не тронут на {bucket}"
        );
    }
    let _ = (q, r);
    t.clean();

    // ---------- порог: одна подпись не демотирует ----------
    let mut t = Trio::open("heal-threshold");
    let p = t.addr(p_seed);
    let q = t.addr(q_seed);
    let r = t.addr(r_seed);
    base_publish(&mut t, p, q, r);
    let weak = epoch_frame(&[q_seed, r_seed], &[q_seed]);
    let out = t
        .node_mut(p)
        .on_frame(q, &weak, testing::clock(4))
        .expect("ниже-пороговая цепочка разбирается");
    assert_eq!(out.len(), 2, "(5) черновик уходит обеим репликам: {out:?}");
    for e in &out {
        assert_eq!(kind_of(e), Kind::MembershipUpdate, "(5) только MembershipUpdate: {out:?}");
        assert!(e.to == q || e.to == r, "(5) адресат — Q или R");
        let upd = MembershipUpdate::decode(&e.frame).expect("черновик разбирается");
        assert_eq!(upd.epoch, 2, "(5) черновик несёт эпоху 2");
        assert_eq!(upd.sigs.len(), 1, "(5) P не подписал исключающую цепочку: {upd:?}");
    }
    {
        let n = t.node(p);
        assert_eq!(n.epoch(), Some(1), "(5) эпическая демоция не случилась");
        assert_eq!(n.serving_epoch(4), Some(1), "(5) P ещё пишет эпоху 1");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, p, 6)),
            "(5) lease не тронут"
        );
    }
    let _ = (q, r);
    t.clean();
}
