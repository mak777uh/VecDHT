//! H-0066 / E-0066: живое разделение §9.8.
//!
//! `gates_p4.rs` закрывает смерть primary, рестарт со старым epoch, `W=2` и снапшот seed.
//! Здесь меряется непокрытое: старый primary **жив** (его никто не убивал и не рестартовал),
//! но две реплики потеряли с ним связь и собрали эпоху 2 без него. Старый primary продолжает
//! считать себя primary, принимает `Publish` и пишет WAL; вопрос — может ли он подтвердить
//! запись агенту или навязать её репликам, и остаётся ли новая эпоха пишущей.
//!
//! `LocalNet` не умеет «не доставлять» кадры живущему узлу, поэтому три `ShardNode` стоят
//! отдельно, а конверты разносит `route(from, envs, now)` — тот же детерминированный автомат,
//! что и в `LocalNet`, без таймеров и `sleep`. Разделение — событие транспорта `peer_lost`,
//! полученное только Q и R: P о нём не узнаёт.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::{Addr, Envelope};
use vecdht_node::{Clock, ShardNode, candidates, membership, testing};
use vecdht_wire::codec::DIM;
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{
    Codec, ProtocolError, PublishAck, ReplicateAck, domain, err_code,
};

/// Шард 7, а не 0: кластер 112 обязан попадать в шард через `shard_of_cluster`, и захардкоженный
/// ноль маскировал бы расхождение.
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
    /// Три держателя шарда с genesis эпохи 1. Ответы genesis (`LeaseGrant` primary, `WalPullRequest`
    /// реплик) не разносятся: `adopt` уже выдал lease каждому из состава, а пустой store нечего
    /// догонять; молчание здесь не меняет ни одного измеряемого инварианта.
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

    /// Доставить конверты, выпущенные одним отправителем. `from` — аутентифицированный транспорт,
    /// а не поле кадра: именно его сверяет протокол (§4.3). Ошибка `on_frame` — это не «узел
    /// ответил отказом», а сломанный сценарий, поэтому паника с именем кадра.
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

/// Разделить конверты одного отправителя по двум адресатам: `(для Q, для R)`.
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

// --- замер --------------------------------------------------------------------

#[test]
fn a_live_deposed_primary_cannot_ack_or_impose_its_write() {
    let params = testing::params(POW);
    let mut t = Trio::open("live-split");

    // P — primary эпохи 1 по детерминированному порядку, а не «сид 1 по договорённости» (§9.3).
    let ordered1 = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let p_seed = SEEDS
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == ordered1[0].owner_ed25519)
        .expect("primary эпохи 1 — один из тестовых сидов");
    let p = t.addr(p_seed);
    let mut rest = SEEDS.iter().copied().filter(|s| *s != p_seed);
    let q_seed = rest.next().expect("второй сид");
    let r_seed = rest.next().expect("третий сид");
    let q = t.addr(q_seed);
    let r = t.addr(r_seed);
    assert_eq!(t.node(p).serving_epoch(1), Some(1), "база: P обслуживает эпоху 1");

    // (0) Базовая запись до разделения: путь старый primary → реплики → ack → агент работает.
    let agent_a = testing::identity(60);
    let va = testing::vector(20);
    let frame_a = publish_frame(&agent_a, &va, 1, 1);
    let out = t
        .node_mut(p)
        .on_frame(agent_a.pubkey(), &frame_a, testing::clock(1))
        .expect("Publish A до разделения");
    assert!(acks(&out).is_empty(), "(0) сам fsync — не кворум: OK не выдаётся сразу");
    assert!(errors(&out).is_empty(), "(0) P принял запись: {out:?}");
    assert_eq!(out.len(), 2, "(0) по одному ReplicateOp каждой реплике");
    assert!(out.iter().all(|e| kind_of(e) == Kind::ReplicateOp), "(0) только опсы");

    let (op_q, op_r) = split_for(out, q, r);
    let ack_q = t.route(p, &op_q, testing::clock(1));
    let ack_r = t.route(p, &op_r, testing::clock(1));
    assert_eq!(ack_q.len(), 1, "(0) Q подтвердила применение");
    assert_eq!(ack_r.len(), 1, "(0) R подтвердил применение");
    let delivered = t.route(q, &ack_q, testing::clock(1));
    let a = acks(&delivered);
    assert_eq!(a.len(), 1, "(0) W=2 собрался на втором подтверждении: {delivered:?}");
    assert_eq!(a[0].error_code, "OK", "(0) {a:?}");
    assert_eq!(a[0].epoch, 1);
    assert_eq!(a[0].seq, 1);
    assert!(t.route(r, &ack_r, testing::clock(1)).is_empty(), "(0) второй ack уже не нужен");
    for (seed, name) in [(p_seed, "P"), (q_seed, "Q"), (r_seed, "R")] {
        assert_eq!(t.node(t.addr(seed)).applied_seq(), 1, "(0) {name} применил запись A");
    }

    // (1) Разделение: только Q и R узнают, что P недоступен, и собирают эпоху 2 без него.
    for seed in [q_seed, r_seed] {
        let addr = t.addr(seed);
        t.node_mut(addr)
            .peer_lost(p, 2)
            .expect("событие транспорта о обрыве с P");
    }
    let list2 =
        candidates::expected_update(2, SHARD, &testing::holders(&[q_seed, r_seed]), params.r, 0, 2);
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
            .on_frame(q, &frame2, testing::clock(2))
            .expect("переход эпохи 2 собран из легитимных подписей");
        assert!(errors(&replies).is_empty(), "(1) переход не должен давать Error: {replies:?}");
    }
    let new_primary = list2.members[0].owner_ed25519;
    let follower = list2.members[1].owner_ed25519;
    assert!(t.node(new_primary).is_primary(), "(1) primary эпохи 2 — members[0]");
    assert!(!t.node(follower).is_primary(), "(1) вторая реплика не primary");
    for seed in [q_seed, r_seed] {
        let n = t.node(t.addr(seed));
        assert_eq!(n.epoch(), Some(2), "(1) Q и R приняли эпоху 2");
        assert_eq!(n.store.serving_epoch(), Some(2), "(1) durable-маркер эпохи 2");
        assert_eq!(n.serving_epoch(2), Some(2), "(1) lease и цепочка совпали");
    }
    assert_eq!(t.node(p).epoch(), Some(1), "(1) P о разделении не узнал");
    assert_eq!(t.node(p).serving_epoch(2), Some(1), "(1) и продолжает обслуживать эпоху 1");

    // (2) Смещённый P принимает Publish B локально: WAL-first, но кворума собрать не может.
    let agent_b = testing::identity(61);
    let vb = testing::vector(30);
    let before = t.node(p).applied_seq();
    let frame_b = publish_frame(&agent_b, &vb, 1, 2);
    let out = t
        .node_mut(p)
        .on_frame(agent_b.pubkey(), &frame_b, testing::clock(2))
        .expect("Publish B на смещённом primary");
    assert!(acks(&out).is_empty(), "(2) OK без второй копии — фальсификатор (б): {out:?}");
    assert!(errors(&out).is_empty(), "(2) P принял запись локально, отказ только в ack: {out:?}");
    assert_eq!(out.len(), 2, "(2) два ReplicateOp эпохи 1");
    assert!(out.iter().all(|e| kind_of(e) == Kind::ReplicateOp));
    assert_eq!(t.node(p).applied_seq(), before + 1, "(2) WAL primary записан, это не откат");

    // (3) Опс старой эпохи отбрасывается репликами молча: ни ack, ни Error.
    let (op_q, op_r) = split_for(out, q, r);
    let replies_q = t.route(p, &op_q, testing::clock(2));
    let replies_r = t.route(p, &op_r, testing::clock(2));
    assert!(replies_q.is_empty(), "(3) Q отбросила ReplicateOp эпохи 1: {replies_q:?}");
    assert!(replies_r.is_empty(), "(3) R отбросил ReplicateOp эпохи 1: {replies_r:?}");
    assert_eq!(t.node(q).applied_seq(), 1, "(3) applied_seq Q не изменился");
    assert_eq!(t.node(r).applied_seq(), 1, "(3) applied_seq R не изменился");

    // (4) Запись B существует только на диске смещённого primary.
    assert_eq!(owner_slot(t.node(q), &agent_b.pubkey()), None, "(4) Q не знает владельца B");
    assert_eq!(owner_slot(t.node(r), &agent_b.pubkey()), None, "(4) R не знает владельца B");
    assert!(owner_slot(t.node(p), &agent_b.pubkey()).is_some(), "(4) локальная копия P осталась");
    let hits = t.node(q).store.search(&vb, &[CLUSTER], 5);
    let owners: Vec<[u8; 32]> = hits
        .iter()
        .filter_map(|(slot, _)| t.node(q).store.index.entry(*slot).map(|e| e.owner_ed25519))
        .collect();
    assert!(!owners.contains(&agent_b.pubkey()), "(4) выдача Q не содержит B: {owners:?}");

    // (5) Новая эпоха пишет: fencing не убил шард вместе со старым primary.
    let agent_c = testing::identity(88);
    let vc = testing::vector(40);
    let frame_c = publish_frame(&agent_c, &vc, 2, 3);
    let out = t
        .node_mut(new_primary)
        .on_frame(agent_c.pubkey(), &frame_c, testing::clock(3))
        .expect("Publish C в эпохе 2");
    assert!(acks(&out).is_empty(), "(5) W=2: подтверждение только после реплики");
    assert_eq!(errors(&out).len(), 0, "(5) primary эпохи 2 обязан принять: {out:?}");
    let op = out;
    assert_eq!(op.len(), 1, "(5) в составе [Q,R] ровно одна реплика");
    let ack_back = t.route(new_primary, &op, testing::clock(3));
    assert_eq!(ack_back.len(), 1, "(5) реплика подтвердила эпоху 2");
    let delivered = t.route(follower, &ack_back, testing::clock(3));
    let a = acks(&delivered);
    assert_eq!(a.len(), 1, "(5) агент C получил OK: {delivered:?}");
    assert_eq!(a[0].error_code, "OK");
    assert_eq!(a[0].epoch, 2, "(5) подтверждение несёт новую эпоху");
    assert_eq!(a[0].seq, 2);
    for seed in [q_seed, r_seed] {
        let n = t.node(t.addr(seed));
        assert_eq!(n.applied_seq(), 2, "(5) обе реплики применили запись C");
        assert!(owner_slot(n, &agent_c.pubkey()).is_some(), "(5) C виден в индексе");
    }

    // (6) Грант прошлой эпохи: старый primary продлевается, реплики отвечают EPOCH_STALE.
    let out = t.node_mut(p).tick(5).expect("tick старого primary");
    let leases: Vec<Envelope> = out
        .into_iter()
        .filter(|e| kind_of(e) == Kind::LeaseGrant)
        .collect();
    assert_eq!(leases.len(), 2, "(6) P продлевает lease своей эпохи двум репликам");
    let replies = t.route(p, &leases, testing::clock(5));
    let errs = errors(&replies);
    assert_eq!(errs.len(), 2, "(6) каждая реплика отвечает отказом: {replies:?}");
    assert!(
        errs.iter().all(|e| e.code == err_code::EPOCH_STALE),
        "(6) ровно EPOCH_STALE обещан §9.8: {errs:?}"
    );
    assert_eq!(t.node(p).epoch(), Some(1), "(6) отказ не двигает эпоху P");
    assert_eq!(t.node(p).serving_epoch(5), Some(1), "(6) P по-прежнему считает себя primary");

    // (7) Настоящий ack чужой эпохи не закрывает Awaiting старой: seq подписан Q, но epoch=2.
    let forged = ReplicateAck {
        shard: SHARD,
        epoch: 2,
        seq: 2,
        replica_ed25519: q,
        applied_seq: 2,
        ok: true,
    };
    let body = forged.body_bytes();
    let sig = testing::identity(q_seed).sign_body(domain::ACK, Kind::ReplicateAck, &body);
    let frame = forged.encode_signed(&sig);
    let replies = t
        .node_mut(p)
        .on_frame(q, &frame, testing::clock(5))
        .expect("ack разбирается");
    assert!(replies.is_empty(), "(7) ack эпохи 2 закрыл Awaiting эпохи 1: {replies:?}");
    assert!(acks(&replies).is_empty(), "(7) OK по чужой эпохе — фальсификатор (ж)");

    t.clean();
}
