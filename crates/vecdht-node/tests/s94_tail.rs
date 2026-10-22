//! H-0074 / E-0074: хвост §9.4/§9.7 — дыра WAL, аутентичность pull, снапшот-путь и уход.
//!
//! Четыре вопроса, не покрытые `E-0072` (W=2/R=3) и `E-0073` (§10 reopen):
//! * потеря нескольких `ReplicateOp` подряд даёт `WalGap`-ack, а не тихую дырку; лечит ли
//!   её **один** pull после смены эпизоды;
//! * `WalPullResponse`/`WalFrame` не подписаны — принимает ли догоняющий запись от не-члена;
//! * холодный `from_seq = 0` идёт кусками снапшота; что несёт `SnapshotOffer`, если держатель
//!   писал после `flush_snapshot`; и может ли тёплый отстающий узел поставить снапшот;
//! * уход primary: `LeaveNotice`, handoff, демоция и W=2 уже на новом primary.
//!
//! Ручная доставка, один процесс. Тройка сидов выбирается так, чтобы P был primary эпохи 1
//! и первым в `speaker_order(2)` (иначе уход не предложит состав сразу), а H — первым
//! кандидатом эпохи 2 среди `[H,S]`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use vecdht_index::manifest::read_manifest;
use vecdht_index::snapshot::{snapshot_name, snapshot_size_for};
use vecdht_index::store::ShardStore;
use vecdht_index::testing::{dir, remove};
use vecdht_index::wal::{list_segments, WalFrame, WalWriter};
use vecdht_node::net::{Addr, Envelope};
use vecdht_node::{ShardNode, candidates, membership, testing};
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{
    Codec, InsertOp, LeaseGrant, LeaveNotice, MatchResult, MembershipUpdate, OpKind, ProtocolError,
    PublishAck, ReplicateAck, ReplicateOp, SnapshotOffer, WalPullRequest, WalPullResponse, domain,
    err_code,
};

const SHARD: u16 = 7;
const POW: u32 = 8;
const TTL: u16 = 225;
const MAX_BODY_LEN: u32 = 4 * 1024 * 1024;

/// Кластер записи: свой на каждый вектор внутри шарда 7 (112..=119).
fn cluster_of(vec_seed: u8) -> u16 {
    112 + (vec_seed as u16 % 8)
}

// --- выбор ролей и каркас -----------------------------------------------------

fn seed_of(seeds: &[u8], key: [u8; 32]) -> u8 {
    *seeds
        .iter()
        .find(|s| testing::identity(**s).pubkey() == key)
        .expect("ключ принадлежит тройке")
}

/// P — primary эпохи 1 и первый в `speaker_order(2, [P,H,S])`; H — первый кандидат эпохи 2
/// среди оставшихся; S — вторая реплика.
fn choose_roles() -> (Vec<u8>, u8, u8, u8) {
    for a in 1u8..=16 {
        for b in a + 1..=16 {
            for c in b + 1..=16 {
                let seeds = vec![a, b, c];
                let holders = testing::holders(&seeds);
                let p_key = candidates::ordered(1, SHARD, &holders)[0].owner_ed25519;
                let owners: Vec<[u8; 32]> = holders.iter().map(|h| h.owner_ed25519).collect();
                if candidates::speaker_order(2, SHARD, &owners)[0] != p_key {
                    continue;
                }
                let p_seed = seed_of(&seeds, p_key);
                let rest: Vec<u8> = seeds.iter().copied().filter(|s| *s != p_seed).collect();
                let list = candidates::expected_update(
                    2,
                    SHARD,
                    &testing::holders(&rest),
                    testing::params(POW).r,
                    0,
                    4,
                );
                let h_seed = seed_of(&rest, list.members[0].owner_ed25519);
                let s_seed = *rest.iter().find(|s| **s != h_seed).expect("вторая реплика");
                return (seeds, p_seed, h_seed, s_seed);
            }
        }
    }
    panic!("тройка с нужными ролями не нашлась");
}

struct Fleet {
    seeds: Vec<u8>,
    p: u8,
    h: u8,
    s: u8,
    nodes: BTreeMap<u8, ShardNode>,
    dirs: BTreeMap<u8, PathBuf>,
    inbox: Vec<(u8, Envelope)>,
}

impl Fleet {
    fn open(tag: &str) -> Fleet {
        let (seeds, p, h, s) = choose_roles();
        let genesis = testing::signed_frame(&testing::genesis_update(SHARD, &seeds, 0));
        let carrier = testing::identity(200).pubkey();
        let mut nodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();
        for seed in &seeds {
            let d = dir(&format!("{tag}-{seed}"));
            dirs.insert(*seed, d.clone());
            let n = testing::node(&d, SHARD, *seed, testing::params(POW), &seeds);
            nodes.insert(*seed, n);
        }
        for seed in &seeds {
            nodes
                .get_mut(seed)
                .expect("узел из карты")
                .on_frame(carrier, &genesis, testing::clock(0))
                .expect("genesis эпохи 1 принимается каждым узлом");
        }
        Fleet { seeds, p, h, s, nodes, dirs, inbox: Vec::new() }
    }

    fn addr(&self, seed: u8) -> Addr {
        self.nodes.get(&seed).expect("узел из карты").me()
    }

    fn seed_at(&self, addr: Addr) -> u8 {
        *self
            .nodes
            .iter()
            .find(|(_, n)| n.me() == addr)
            .map(|(s, _)| s)
            .expect("адрес принадлежит флоту")
    }

    fn node(&self, seed: u8) -> &ShardNode {
        self.nodes.get(&seed).expect("узел из карты")
    }

    fn node_mut(&mut self, seed: u8) -> &mut ShardNode {
        self.nodes.get_mut(&seed).expect("узел из карты")
    }

    fn dir_of(&self, seed: u8) -> &Path {
        self.dirs.get(&seed).expect("каталог из карты")
    }

    fn close(&mut self, seed: u8) {
        assert!(self.inbox.is_empty(), "закрывать узел с недоставленными кадрами нельзя");
        self.nodes.remove(&seed);
    }

    fn reopen(&mut self, seed: u8) {
        self.nodes.remove(&seed);
        let d = self.dir_of(seed).to_path_buf();
        let n = testing::node(&d, SHARD, seed, testing::params(POW), &self.seeds);
        assert!(n.epoch().is_some(), "членство обязано подняться с диска");
        self.nodes.insert(seed, n);
    }

    fn send(&mut self, from: u8, envs: Vec<Envelope>) {
        for e in envs {
            self.inbox.push((from, e));
        }
    }

    /// Доставить inbox до неподвижной точки.
    fn pump(&mut self, bucket: u32, max_rounds: usize) {
        let now = testing::clock(bucket);
        let mut rounds = 0usize;
        while !self.inbox.is_empty() {
            rounds += 1;
            assert!(
                rounds <= max_rounds,
                "прокачка не сошлась за {max_rounds} раундов: {:?}",
                self.inbox
                    .iter()
                    .map(|(_, e)| (kind_of(e), e.to))
                    .collect::<Vec<_>>()
            );
            let batch = std::mem::take(&mut self.inbox);
            for (from, e) in batch {
                let kind = kind_of(&e);
                let from_addr = self.addr(from);
                let target = self
                    .nodes
                    .iter()
                    .find(|(_, n)| n.me() == e.to)
                    .map(|(s, _)| *s)
                    .unwrap_or_else(|| panic!("кадр {kind:?} адресован узлу, которого нет"));
                let replies = self
                    .node_mut(target)
                    .on_frame(from_addr, &e.frame, now)
                    .unwrap_or_else(|err| panic!("{kind:?} сломал узел {target}: {err}"));
                for r in replies {
                    self.inbox.push((target, r));
                }
            }
        }
    }

    fn clean(mut self) {
        self.nodes.clear();
        for d in self.dirs.values() {
            remove(d);
        }
    }
}

fn kind_of(e: &Envelope) -> Kind {
    decode_frame(&e.frame).expect("узел обязан отдавать разбираемые кадры").header.kind
}

fn deliver(t: &mut Fleet, to: u8, from: u8, e: &Envelope, bucket: u32) -> Vec<Envelope> {
    let from_addr = t.addr(from);
    t.node_mut(to)
        .on_frame(from_addr, &e.frame, testing::clock(bucket))
        .unwrap_or_else(|err| panic!("кадр {:?} сломал узел {to}: {err}", kind_of(e)))
}

fn deliver_raw(t: &mut Fleet, to: u8, from: Addr, bytes: &[u8], bucket: u32) -> Vec<Envelope> {
    t.node_mut(to)
        .on_frame(from, bytes, testing::clock(bucket))
        .unwrap_or_else(|err| panic!("кадр сломал узел {to}: {err}"))
}

fn acks_of(envs: &[Envelope]) -> Vec<PublishAck> {
    envs.iter()
        .filter(|e| kind_of(e) == Kind::PublishAck)
        .map(|e| PublishAck::decode(&e.frame).expect("PublishAck разбирается"))
        .collect()
}

fn errors_of(envs: &[Envelope]) -> Vec<ProtocolError> {
    envs.iter()
        .filter(|e| kind_of(e) == Kind::Error)
        .map(|e| ProtocolError::decode(&e.frame).expect("Error разбирается"))
        .collect()
}

// --- публикации ---------------------------------------------------------------

/// `Publish` в P (или в любого primary) — возвращает ровно те `ReplicateOp`, что он разослал.
fn publish(
    t: &mut Fleet,
    at: u8,
    agent_seed: u8,
    vec_seed: u8,
    epoch: u64,
    bucket: u32,
) -> Vec<Envelope> {
    let agent = testing::identity(agent_seed);
    let frame = testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(vec_seed),
        cluster_id: cluster_of(vec_seed),
        shard: SHARD,
        epoch,
        published_bucket: bucket,
        ttl_buckets: TTL,
        bits: POW,
    }
    .frame();
    t.node_mut(at)
        .on_frame(agent.pubkey(), &frame, testing::clock(bucket))
        .unwrap_or_else(|err| panic!("Publish сломал узел {at}: {err}"))
}

/// Опубликовать, доставить опс ровно одной реплике и вернуть ответ primary агенту.
fn publish_via(
    t: &mut Fleet,
    at: u8,
    agent_seed: u8,
    vec_seed: u8,
    epoch: u64,
    bucket: u32,
    to: u8,
) -> Vec<Envelope> {
    let ops = publish(t, at, agent_seed, vec_seed, epoch, bucket);
    let target = t.addr(to);
    let op = ops
        .iter()
        .find(|e| e.to == target)
        .unwrap_or_else(|| panic!("опс не адресован реплике {to}"));
    let acks = deliver(t, to, at, op, bucket);
    assert_eq!(acks.len(), 1, "ровно один ReplicateAck от {to}: {acks:?}");
    deliver(t, at, to, &acks[0], bucket)
}

/// Опубликовать обеим репликам; вернуть число `PublishAck` (W=2 закрывает ровно один).
fn publish_all(
    t: &mut Fleet,
    agent_seed: u8,
    vec_seed: u8,
    epoch: u64,
    bucket: u32,
) -> usize {
    let ops = publish(t, t.p, agent_seed, vec_seed, epoch, bucket);
    assert_eq!(ops.len(), 2, "по одному опсу каждой реплике: {ops:?}");
    let mut n = 0usize;
    for op in &ops {
        let dest = t.seed_at(op.to);
        let acks = deliver(t, dest, t.p, op, bucket);
        assert_eq!(acks.len(), 1, "ack от {dest}");
        n += acks_of(&deliver(t, t.p, dest, &acks[0], bucket)).len();
    }
    n
}

fn slot(t: &Fleet, seed: u8, key: [u8; 32]) -> u32 {
    t.node(seed)
        .store
        .index
        .owner_slot(&key)
        .unwrap_or_else(|| panic!("слот {key:?} у узла {seed}"))
}

// --- эпоха 2 ------------------------------------------------------------------

fn ordered1(seeds: &[u8]) -> Vec<candidates::Holder> {
    candidates::ordered(1, SHARD, &testing::holders(seeds))
}

fn sig_index(ordered: &[candidates::Holder], seed: u8) -> u8 {
    let key = testing::identity(seed).pubkey();
    ordered
        .iter()
        .position(|h| h.owner_ed25519 == key)
        .expect("подписант обязан быть участником эпохи 1") as u8
}

/// Синтетическая цепочка эпохи 2 `[H,S]`, подписанная H и S как участниками эпохи 1.
fn epoch2_frame(seeds: &[u8], h: u8, s: u8) -> (Vec<u8>, [u8; 32]) {
    let params = testing::params(POW);
    let list = candidates::expected_update(
        2,
        SHARD,
        &testing::holders(&[h, s]),
        params.r,
        0,
        4,
    );
    let draft = membership::build_update(&list, Vec::new());
    let ordered = ordered1(seeds);
    let sigs: Vec<(u8, [u8; 64])> = [h, s]
        .iter()
        .map(|seed| {
            let id = testing::identity(*seed);
            (sig_index(&ordered, *seed), id.sign_domain(domain::MEMBER, &draft.unsigned_body()))
        })
        .collect();
    let primary = list.members[0].owner_ed25519;
    (testing::signed_frame(&membership::build_update(&list, sigs)), primary)
}

fn want_members(h: u8, s: u8) -> Vec<[u8; 32]> {
    candidates::expected_update(2, SHARD, &testing::holders(&[h, s]), testing::params(POW).r, 0, 4)
        .members
        .iter()
        .map(|m| m.owner_ed25519)
        .collect()
}

// --- (0)–(2): дыра WAL, один pull, аутентичность -------------------------------

#[test]
fn one_pull_heals_a_gap_but_the_response_is_unauthenticated() {
    let mut t = Fleet::open("s94-gap");
    let (p, h, s) = (t.p, t.h, t.s);

    // (0) A обеим репликам: база W=2.
    assert_eq!(publish_all(&mut t, 10, 20, 1, 1), 1, "(0) один PublishAck на A");
    for seed in [p, h, s] {
        let n = t.node(seed);
        assert_eq!(n.applied_seq(), 1, "(0) A применён у {seed}");
        assert_eq!(n.store.len(), 1, "(0) одна запись у {seed}");
        assert_eq!(n.epoch(), Some(1), "(0) эпоха 1 у {seed}");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, t.addr(p), 6)),
            "(0) lease эпохи 1 у {seed}"
        );
    }
    let a_key = testing::identity(10).pubkey();
    let a_slot = slot(&t, p, a_key);
    assert_eq!(slot(&t, h, a_key), a_slot);
    assert_eq!(slot(&t, s, a_key), a_slot);

    // B и C теряются у S; D доезжает до S как дыра.
    for (agent, vec_seed) in [(11u8, 21u8), (12, 22)] {
        let out = publish_via(&mut t, p, agent, vec_seed, 1, 1, h);
        assert_eq!(acks_of(&out).len(), 1, "(0) B/C закрываются одним ack H");
    }
    assert_eq!(t.node(p).applied_seq(), 3, "(0) P применил A–C");
    assert_eq!(t.node(h).applied_seq(), 3, "(0) H применил A–C");
    assert_eq!(t.node(s).applied_seq(), 1, "(0) S застрял на A");

    let ops = publish(&mut t, p, 13, 23, 1, 1);
    let h_op = ops.iter().find(|e| e.to == t.addr(h)).expect("опс D для H");
    let h_acks = deliver(&mut t, h, p, h_op, 1);
    assert_eq!(acks_of(&deliver(&mut t, p, h, &h_acks[0], 1)).len(), 1, "(0) W=2 на D");
    let s_op = ops.iter().find(|e| e.to == t.addr(s)).expect("опс D для S");
    let s_out = deliver(&mut t, s, p, s_op, 1);
    assert_eq!(s_out.len(), 1, "(0) S отвечает только ack: {s_out:?}");
    let gap = ReplicateAck::decode(&s_out[0].frame).expect("ReplicateAck");
    assert_eq!((gap.epoch, gap.seq, gap.applied_seq, gap.ok), (1, 4, 1, false), "(0) WalGap-ack");
    assert_eq!(t.node(s).applied_seq(), 1, "(0) дыра не сдвинула applied_seq");
    assert_eq!(t.node(s).store.len(), 1);

    // (1) Смена эпизоды: S и H теряют P.
    let p_addr = t.addr(p);
    t.node_mut(h).peer_lost(p_addr, 2).expect("peer_lost P у H");
    t.node_mut(s).peer_lost(p_addr, 2).expect("peer_lost P у S");
    let (frame2, primary2) = epoch2_frame(&t.seeds, h, s);
    assert_eq!(primary2, testing::identity(h).pubkey(), "(1) H — primary эпохи 2");

    let h_addr = t.addr(h);
    let s_out = deliver_raw(&mut t, s, h_addr, &frame2, 2);
    assert_eq!(s_out.len(), 2, "(1) S: цепочка и догон: {s_out:?}");
    assert_eq!(
        s_out.iter().filter(|e| kind_of(e) == Kind::MembershipUpdate).count(),
        1,
        "(1) S рассылает цепочку"
    );
    let pull = s_out
        .iter()
        .find(|e| kind_of(e) == Kind::WalPullRequest)
        .cloned()
        .expect("(1) S шлёт ровно один догон");
    let req = WalPullRequest::decode(&pull.frame).expect("WalPullRequest");
    assert_eq!((req.shard, req.from_seq, req.to_seq), (SHARD, 2, 0), "(1) догон с 2");
    assert!(decode_frame(&pull.frame).unwrap().signature.is_none(), "(1) pull не подписан");

    let s_addr = t.addr(s);
    let h_out = deliver_raw(&mut t, h, s_addr, &frame2, 2);
    assert_eq!(h_out.len(), 2, "(1) H: цепочка и грант: {h_out:?}");
    let grant = h_out
        .iter()
        .find(|e| kind_of(e) == Kind::LeaseGrant)
        .cloned()
        .expect("(1) H выдаёт lease");
    let g = LeaseGrant::decode(&grant.frame).expect("LeaseGrant");
    assert_eq!(
        (g.epoch, g.primary_ed25519, g.expires_at_bucket),
        (2, h_addr, 8),
        "(1) грант эпохи 2 до бакета 8"
    );

    // Обмен цепочками и грантом: обе эпохи равны — тишина.
    for e in &h_out {
        assert!(deliver(&mut t, s, h, e, 2).is_empty(), "(1) S молчит на равную эпоху");
    }
    for e in s_out.iter().filter(|e| kind_of(e) == Kind::MembershipUpdate) {
        assert!(deliver(&mut t, h, s, e, 2).is_empty(), "(1) H молчит на равную эпоху");
    }
    assert_eq!(t.node(s).epoch(), Some(2));
    assert_eq!(
        t.node(s).lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
        Some((2, h_addr, 8)),
        "(1) lease S от нового primary"
    );
    assert_eq!(t.node(s).serving_epoch(2), Some(2));

    // Один pull несёт все три пропущенных опса.
    let resp = deliver(&mut t, h, s, &pull, 2);
    assert_eq!(resp.len(), 1, "(1) ровно один ответ на pull: {resp:?}");
    assert_eq!(kind_of(&resp[0]), Kind::WalPullResponse);
    let wr = WalPullResponse::decode(&resp[0].frame).expect("WalPullResponse");
    assert_eq!((wr.shard, wr.from_seq, wr.to_seq, wr.primary_epoch), (7, 2, 4, 2));
    assert!(decode_frame(&resp[0].frame).unwrap().signature.is_none(), "(1) ответ не подписан");
    let mut seqs = Vec::new();
    let mut rest = &wr.frames[..];
    while !rest.is_empty() {
        let (f, used) = WalFrame::decode(rest).expect("фрейм WAL");
        assert_eq!(f.kind, OpKind::Insert);
        seqs.push(f.seq);
        rest = &rest[used..];
    }
    assert_eq!(seqs, vec![2, 3, 4], "(1) все три пропущенных опса в одном ответе");

    let after = deliver(&mut t, s, h, &resp[0], 2);
    assert!(after.is_empty(), "(1) догнали: продолжения нет: {after:?}");
    assert_eq!(t.node(s).applied_seq(), 4, "(1) S догнал одним pull'ом");
    assert_eq!(t.node(s).store.len(), 4);
    for agent in [11u8, 12, 13] {
        let key = testing::identity(agent).pubkey();
        assert_eq!(slot(&t, s, key), slot(&t, h, key), "(1) слот агента {agent} совпал");
    }
    assert_eq!(t.node(h).applied_seq(), 4, "(1) H не двигался");

    // (2) Подписанный опс от не-члена отвергнут...
    let attacker = testing::identity(250);
    let forged = InsertOp {
        owner_ed25519: attacker.pubkey(),
        vec_q: testing::vector(77),
        cluster_id: cluster_of(77),
        published_bucket: 2,
        ttl_buckets: TTL,
    };
    let op = ReplicateOp {
        shard: SHARD,
        epoch: 2,
        seq: 5,
        op_kind: OpKind::Insert,
        body: forged.body_bytes(),
    };
    let sig = attacker.sign_body(domain::REPLICA, Kind::ReplicateOp, &op.body_bytes());
    let signed = op.encode_signed(&sig);
    let out = deliver_raw(&mut t, s, attacker.pubkey(), &signed, 2);
    assert!(out.is_empty(), "(2) чужой ReplicateOp не заслуживает ответа");
    assert_eq!(t.node(s).applied_seq(), 4, "(2) подписанный опс отвергнут");

    // ...а неподписанный WalPullResponse — принят.
    let body = WalFrame::new(5, OpKind::Insert, forged.body_bytes()).encode();
    let wr = WalPullResponse {
        shard: SHARD,
        from_seq: 5,
        to_seq: 5,
        primary_epoch: 2,
        frames: body,
    };
    let bytes = wr.encode_unsigned();
    assert!(decode_frame(&bytes).unwrap().signature.is_none(), "(2) ответ без подписи");
    let out = deliver_raw(&mut t, s, attacker.pubkey(), &bytes, 2);
    assert!(out.is_empty());
    assert_eq!(t.node(s).applied_seq(), 5, "(2) подделка применена");
    assert_eq!(t.node(s).store.len(), 5);
    assert!(t.node(s).store.index.owner_slot(&attacker.pubkey()).is_some());
    assert_eq!(t.node(h).applied_seq(), 4, "(2) H не видел подделку");
    assert_eq!(t.node(h).store.len(), 4);
    assert!(t.node(h).store.index.owner_slot(&attacker.pubkey()).is_none());

    assert!(!Kind::WalPullRequest.signature_required());
    assert!(!Kind::WalPullResponse.signature_required());
    assert!(Kind::ReplicateOp.signature_required());
    assert!(Kind::SnapshotOffer.signature_required());
    t.clean();
}

// --- (3): холодный снапшот по кускам и хвост -----------------------------------

#[test]
fn cold_node_installs_snapshot_in_two_chunks_then_pulls_the_tail() {
    let mut t = Fleet::open("s94-cold");
    let (p, h, s) = (t.p, t.h, t.s);

    for i in 0..160u32 {
        let agent = 10 + i as u8;
        let bucket = 1 + i / 40;
        let out = publish_via(&mut t, p, agent, agent, 1, bucket, h);
        let a = acks_of(&out);
        assert_eq!(a.len(), 1, "(3) W=2 закрывается ack H на {agent}: {out:?}");
        assert_eq!(a[0].error_code, "OK");
    }
    assert_eq!(t.node(p).applied_seq(), 160);
    assert_eq!(t.node(h).applied_seq(), 160);
    assert_eq!(t.node(h).store.len(), 160);
    assert_eq!(t.node(s).applied_seq(), 0, "(3) S холоден");

    let written = t.node_mut(h).store.flush_snapshot().expect("flush_snapshot");
    assert_eq!(written, 73_268, "(3) flush пишет снапшот на applied_seq 160");
    let path = t.dir_of(h).join(snapshot_name(160));
    assert_eq!(
        std::fs::metadata(&path).expect("файл снапшота").len(),
        snapshot_size_for(160) as u64,
        "(3) размер снапшота"
    );
    assert_eq!(snapshot_size_for(160), 73_268, "(3) 48 + 160*428 + 4096 + 640 + 4");
    let mf = read_manifest(t.dir_of(h)).unwrap().expect("MANIFEST");
    assert_eq!(
        (mf.snapshot_seq, mf.applied_seq, mf.oldest_wal_needed, mf.next_slot),
        (160, 160, 1, 160),
        "(3) MANIFEST держателя"
    );

    // Первый кусок.
    let req = WalPullRequest {
        shard: SHARD,
        from_seq: 0,
        to_seq: 0,
        max_bytes: MAX_BODY_LEN / 2,
    }
    .encode_unsigned();
    let s_addr = t.addr(s);
    let out = deliver_raw(&mut t, h, s_addr, &req, 4);
    assert_eq!(out.len(), 1, "(3) оффер на холодный запрос: {out:?}");
    assert_eq!(kind_of(&out[0]), Kind::SnapshotOffer);
    assert!(decode_frame(&out[0].frame).unwrap().signature.is_some(), "(3) оффер подписан");
    let o1 = SnapshotOffer::decode(&out[0].frame).expect("SnapshotOffer");
    assert_eq!(
        (
            o1.shard,
            o1.epoch,
            o1.snapshot_seq,
            o1.oldest_wal_needed,
            o1.applied_seq,
            o1.next_slot,
            o1.total_len,
            o1.offset
        ),
        (SHARD, 1, 160, 1, 160, 160, 73_268, 0),
        "(3) метаданные первого куска"
    );
    assert_eq!(o1.chunk.len(), 65_535, "(3) первый кусок во весь лимит");
    assert_eq!(o1.total_len as usize, snapshot_size_for(160));

    // S принимает кусок и просит следующий.
    let out = deliver(&mut t, s, h, &out[0], 4);
    assert_eq!(out.len(), 1, "(3) неполный набор = «дай ещё»: {out:?}");
    let again = WalPullRequest::decode(&out[0].frame).expect("WalPullRequest");
    assert_eq!((again.from_seq, again.to_seq), (0, 0), "(3) холодный запрос сохраняется");

    // Второй кусок.
    let out2 = deliver(&mut t, h, s, &out[0], 4);
    assert_eq!(out2.len(), 1);
    let o2 = SnapshotOffer::decode(&out2[0].frame).expect("SnapshotOffer");
    assert_eq!((o2.offset, o2.chunk.len()), (65_535, 7_733), "(3) второй кусок — хвост файла");
    assert_eq!(o2.snapshot_seq, o1.snapshot_seq);
    assert_eq!(o2.content_hash, o1.content_hash, "(3) один хеш на все куски");
    assert_eq!(o2.applied_seq, 160);

    // Установка и запрос хвоста.
    let out = deliver(&mut t, s, h, &out2[0], 4);
    assert_eq!(out.len(), 1, "(3) после установки — догон хвоста: {out:?}");
    assert_eq!(kind_of(&out[0]), Kind::WalPullRequest);
    let tail_pull = out[0].clone();
    let tr = WalPullRequest::decode(&tail_pull.frame).expect("WalPullRequest");
    assert_eq!((tr.from_seq, tr.to_seq), (161, 0), "(3) хвост с 161");
    assert_eq!(t.node(s).applied_seq(), 160, "(3) снапшот поставлен");
    assert_eq!(t.node(s).store.len(), 160);
    assert_eq!(t.node(s).store.last_snapshot_seq, 160);
    assert_eq!(t.node(s).store.replayed, 0, "(3) WAL не переигран");

    // Хвост публикуется после установки: E, F.
    for agent in [170u8, 171] {
        let out = publish_via(&mut t, p, agent, agent, 1, 5, h);
        assert_eq!(acks_of(&out).len(), 1, "(3) хвост {agent} закрыт H");
    }
    assert_eq!(t.node(p).applied_seq(), 162);
    assert_eq!(t.node(h).applied_seq(), 162);
    assert_eq!(t.node(h).store.len(), 162);

    let out = deliver(&mut t, h, s, &tail_pull, 5);
    assert_eq!(out.len(), 1, "(3) ответ на хвост: {out:?}");
    assert_eq!(kind_of(&out[0]), Kind::WalPullResponse);
    let wr = WalPullResponse::decode(&out[0].frame).expect("WalPullResponse");
    assert_eq!((wr.from_seq, wr.to_seq, wr.primary_epoch), (161, 162, 1));
    let mut seqs = Vec::new();
    let mut rest = &wr.frames[..];
    while !rest.is_empty() {
        let (f, used) = WalFrame::decode(rest).expect("фрейм WAL");
        seqs.push(f.seq);
        rest = &rest[used..];
    }
    assert_eq!(seqs, vec![161, 162]);
    let after = deliver(&mut t, s, h, &out[0], 5);
    assert!(after.is_empty(), "(3) продолжения нет: {after:?}");
    assert_eq!(t.node(s).applied_seq(), 162);
    assert_eq!(t.node(s).store.len(), 162);
    let q = testing::vector(170);
    assert_eq!(
        t.node(s).store.search(&q, &[cluster_of(170)], 10),
        t.node(h).store.search(&q, &[cluster_of(170)], 10),
        "(3) выдача после снапшота и хвоста совпадает с держателем"
    );
    for agent in [170u8, 171] {
        let key = testing::identity(agent).pubkey();
        assert_eq!(slot(&t, s, key), slot(&t, h, key), "(3) слот {agent} после хвоста");
    }
    t.clean();
}

// --- (4): оффер несёт живой applied_seq ---------------------------------------

#[test]
fn snapshot_offer_skews_seq_when_the_holder_has_moved_on() {
    let mut t = Fleet::open("s94-skew");
    let (p, h, s) = (t.p, t.h, t.s);

    // A — снапшот на 1.
    let out = publish_via(&mut t, p, 20, 30, 1, 1, h);
    assert_eq!(acks_of(&out).len(), 1);
    assert_eq!(t.node_mut(h).store.flush_snapshot().expect("flush 1"), 4_580,
        "(4) flush пишет снапшот на 1");
    assert_eq!(
        std::fs::metadata(t.dir_of(h).join(snapshot_name(1))).unwrap().len(),
        snapshot_size_for(1) as u64
    );
    assert_eq!(snapshot_size_for(1), 4_580);

    // B — уже после снапшота.
    let out = publish_via(&mut t, p, 21, 31, 1, 1, h);
    assert_eq!(acks_of(&out).len(), 1);
    assert_eq!(t.node(h).applied_seq(), 2);
    assert_eq!(t.node(h).store.len(), 2);

    // Холодный S просит с нуля: оффер смешивает файл (1 запись) и живой manifest (2).
    let req = WalPullRequest {
        shard: SHARD,
        from_seq: 0,
        to_seq: 0,
        max_bytes: MAX_BODY_LEN / 2,
    }
    .encode_unsigned();
    let s_addr = t.addr(s);
    let h_addr = t.addr(h);
    let out = deliver_raw(&mut t, h, s_addr, &req, 1);
    assert_eq!(out.len(), 1, "(4) один оффер: {out:?}");
    let offer = SnapshotOffer::decode(&out[0].frame).expect("SnapshotOffer");
    assert_eq!(
        (
            offer.snapshot_seq,
            offer.oldest_wal_needed,
            offer.applied_seq,
            offer.next_slot,
            offer.total_len
        ),
        (1, 1, 2, 2, 4_580),
        "(4) файл описывает 1 запись, оффер обещает 2"
    );
    assert_eq!(offer.total_len as usize, snapshot_size_for(1), "(4) геометрия файла — одна запись");
    assert_eq!(offer.chunk.len(), 4_580);

    let err = t
        .node_mut(s)
        .on_frame(h_addr, &out[0].frame, testing::clock(1))
        .expect_err("(4) установка обязана провалиться громко");
    let msg = format!("{err}");
    assert!(msg.contains("next_slot"), "(4) причина — next_slot: {msg}");
    assert_eq!(t.node(s).applied_seq(), 0, "(4) S остался холодным");
    assert!(t.node(s).store.is_empty());

    let bad = match ShardStore::open(t.dir_of(s), SHARD) {
        Err(e) => e,
        Ok(_) => panic!("(4) каталог после провалившейся установки не должен открываться"),
    };
    assert!(format!("{bad}").contains("next_slot"), "(4) каталог неоткрываем до нового снапшота: {bad}");

    // Новый снапшот на 2 записи согласован с живым manifest — установка проходит.
    assert_eq!(t.node_mut(h).store.flush_snapshot().expect("flush 2"), 5_012,
        "(4) flush пишет снапшот на 2");
    assert_eq!(
        std::fs::metadata(t.dir_of(h).join(snapshot_name(2))).unwrap().len(),
        snapshot_size_for(2) as u64
    );
    assert_eq!(snapshot_size_for(2), 5_012);

    let out = deliver_raw(&mut t, h, s_addr, &req, 1);
    assert_eq!(out.len(), 1);
    let offer = SnapshotOffer::decode(&out[0].frame).expect("SnapshotOffer");
    assert_eq!(
        (offer.snapshot_seq, offer.applied_seq, offer.next_slot, offer.total_len),
        (2, 2, 2, 5_012),
        "(4) согласованный оффер"
    );
    let out = deliver(&mut t, s, h, &out[0], 1);
    assert_eq!(out.len(), 1, "(4) после установки — догон с 3: {out:?}");
    assert_eq!(t.node(s).applied_seq(), 2);
    assert_eq!(t.node(s).store.len(), 2);
    assert!(t.node(s).store.index.owner_slot(&testing::identity(21).pubkey()).is_some());

    let empty = deliver(&mut t, h, s, &out[0], 1);
    assert_eq!(empty.len(), 1);
    let wr = WalPullResponse::decode(&empty[0].frame).expect("WalPullResponse");
    assert_eq!((wr.from_seq, wr.to_seq), (3, 2), "(4) хвоста нет");
    assert!(deliver(&mut t, s, h, &empty[0], 1).is_empty());

    // Каталог теперь открывается обычным путём.
    t.close(s);
    t.reopen(s);
    assert_eq!(t.node(s).applied_seq(), 2);
    assert_eq!(t.node(s).store.len(), 2);
    assert_eq!(t.node(s).store.last_snapshot_seq, 2);
    t.clean();
}

// --- (5): тёплый отстающий не ставит снапшот -----------------------------------

#[test]
fn warm_lagging_replica_cannot_take_the_snapshot_and_stops() {
    let mut t = Fleet::open("s94-warm");
    let (p, h, s) = (t.p, t.h, t.s);

    assert_eq!(publish_all(&mut t, 30, 40, 1, 1), 1, "(5) A всем");
    let out = publish_via(&mut t, p, 31, 41, 1, 1, h);
    assert_eq!(acks_of(&out).len(), 1);
    assert_eq!(t.node(h).applied_seq(), 2);
    assert_eq!(t.node(s).applied_seq(), 1, "(5) S отстал на B");

    // Внешняя ротация: wal.1 (1,2) остаётся, новый сегмент начинается с 3.
    t.close(h);
    {
        let mut w = WalWriter::open(t.dir_of(h), 1).expect("открыть wal.1");
        w.rotate(3).expect("ротация на 3");
    }
    t.reopen(h);
    assert_eq!(t.node(h).applied_seq(), 2, "(5) WAL поднят после ротации");
    assert_eq!(t.node(h).store.replayed, 2);
    assert_eq!(t.node(h).store.len(), 2);

    let out = publish_via(&mut t, p, 32, 42, 1, 2, h);
    assert_eq!(acks_of(&out).len(), 1);
    assert_eq!(t.node(h).applied_seq(), 3);
    assert_eq!(t.node_mut(h).store.flush_snapshot().expect("flush 3"), 5_444,
        "(5) flush пишет снапшот на 3");
    assert_eq!(
        std::fs::metadata(t.dir_of(h).join(snapshot_name(3))).unwrap().len(),
        snapshot_size_for(3) as u64
    );
    assert_eq!(snapshot_size_for(3), 5_444);
    let starts: Vec<u64> = list_segments(t.dir_of(h))
        .expect("сегменты")
        .into_iter()
        .map(|(start, _)| start)
        .collect();
    assert_eq!(starts, vec![3], "(5) сегмент 1 удалён барьером");
    let mf = read_manifest(t.dir_of(h)).unwrap().expect("MANIFEST");
    assert_eq!((mf.snapshot_seq, mf.applied_seq, mf.oldest_wal_needed), (3, 3, 3));

    let out = publish_via(&mut t, p, 33, 43, 1, 2, h);
    assert_eq!(acks_of(&out).len(), 1);
    assert_eq!(t.node(h).applied_seq(), 4, "(5) D после снапшота");
    assert_eq!(t.node(h).store.len(), 4);

    // Эпоха 2: S тянет с 2, но живой WAL держателя начинается с 3.
    let p_addr = t.addr(p);
    t.node_mut(h).peer_lost(p_addr, 2).expect("peer_lost у H");
    t.node_mut(s).peer_lost(p_addr, 2).expect("peer_lost у S");
    let (frame2, primary2) = epoch2_frame(&t.seeds, h, s);
    assert_eq!(primary2, testing::identity(h).pubkey());
    let h_addr = t.addr(h);
    let s_addr = t.addr(s);
    let s_out = deliver_raw(&mut t, s, h_addr, &frame2, 2);
    let pull = s_out
        .iter()
        .find(|e| kind_of(e) == Kind::WalPullRequest)
        .cloned()
        .expect("(5) S просит догон");
    assert_eq!(WalPullRequest::decode(&pull.frame).unwrap().from_seq, 2);
    let _ = deliver_raw(&mut t, h, s_addr, &frame2, 2);

    let out = deliver(&mut t, h, s, &pull, 2);
    assert_eq!(out.len(), 1, "(5) вместо хвоста — снапшот: {out:?}");
    assert_eq!(kind_of(&out[0]), Kind::SnapshotOffer);
    let offer = SnapshotOffer::decode(&out[0].frame).expect("SnapshotOffer");
    assert_eq!(
        (
            offer.epoch,
            offer.snapshot_seq,
            offer.oldest_wal_needed,
            offer.applied_seq,
            offer.next_slot,
            offer.total_len
        ),
        (2, 3, 3, 4, 4, 5_444),
        "(5) оффер снова смешивает файл (3 записи) и живой manifest (4)"
    );

    let out = deliver(&mut t, s, h, &out[0], 2);
    assert!(out.is_empty(), "(5) установка отвергнута молча, догона нет: {out:?}");
    assert_eq!(t.node(s).applied_seq(), 1, "(5) S не сдвинулся");
    assert_eq!(t.node(s).store.len(), 1);
    for agent in [31u8, 32, 33] {
        assert!(
            t.node(s).store.index.owner_slot(&testing::identity(agent).pubkey()).is_none(),
            "(5) запись {agent} отсутствует у тёплого S"
        );
    }
    assert_eq!(t.node(s).store.last_snapshot_seq, 0);
    assert_eq!(t.node(h).applied_seq(), 4);
    assert_eq!(t.node(h).store.len(), 4);
    t.clean();
}

// --- (6): уход primary --------------------------------------------------------

#[test]
fn leaving_primary_hands_off_and_is_demoted() {
    let mut t = Fleet::open("s94-leave");
    let (p, h, s) = (t.p, t.h, t.s);

    assert_eq!(publish_all(&mut t, 40, 40, 1, 1), 1, "(6) A всем");
    let a_slot = slot(&t, p, testing::identity(40).pubkey());

    // Подделка: H подписывает уход P. Узел обязан молчать.
    let p_addr = t.addr(p);
    let h_addr = t.addr(h);
    let forged = LeaveNotice {
        epoch: 1,
        shard: SHARD,
        leaving_owner: p_addr,
        drain_deadline_bucket: 11,
    };
    let body = forged.body_bytes();
    let sig = testing::identity(h).sign_body(domain::LEAVE, Kind::LeaveNotice, &body);
    let frame = forged.encode_signed(&sig);
    let out = deliver_raw(&mut t, p, h_addr, &frame, 1);
    assert!(out.is_empty(), "(6) чужой LeaveNotice не принимается: {out:?}");
    assert_eq!(t.node(p).epoch(), Some(1));
    assert_eq!(t.node(p).applied_seq(), 1);

    // Легитимный уход primary.
    let leave = t.node_mut(p).leave(1, 10).expect("leave");
    let notices: Vec<&Envelope> =
        leave.iter().filter(|e| kind_of(e) == Kind::LeaveNotice).collect();
    let updates: Vec<&Envelope> =
        leave.iter().filter(|e| kind_of(e) == Kind::MembershipUpdate).collect();
    assert_eq!(notices.len(), 2, "(6) уведомление каждой реплике");
    assert_eq!(updates.len(), 2, "(6) предложение состава каждой реплике");
    for n in &notices {
        let n = LeaveNotice::decode(&n.frame).expect("LeaveNotice");
        assert_eq!((n.epoch, n.leaving_owner), (1, p_addr), "(6) уходит именно P");
    }
    let want = want_members(h, s);
    for u in &updates {
        let u = MembershipUpdate::decode(&u.frame).expect("MembershipUpdate");
        let got: Vec<[u8; 32]> = u.members.iter().map(|m| m.owner_ed25519).collect();
        assert_eq!((u.epoch, got), (2, want.clone()), "(6) предложен состав [H,S]");
        assert_eq!(u.sigs.len(), 1, "(6) подпись только уходящего");
    }
    assert!(t.node(p).lease.is_none(), "(6) уходящий primary сдаёт lease сразу");
    assert!(t.node(p).is_primary(), "(6) до принятия эпохи P всё ещё primary старой");

    // Ушедший primary не пишет.
    let out = publish(&mut t, p, 41, 41, 1, 1);
    let errs = errors_of(&out);
    assert_eq!(errs.len(), 1, "(6) publish отвергнут: {out:?}");
    assert_eq!(errs[0].code, err_code::EPOCH_STALE);
    assert!(out.iter().all(|e| kind_of(e) == Kind::Error));
    assert_eq!(t.node(p).applied_seq(), 1);

    // Прокачка ухода: два уведомления + два предложения.
    t.send(p, leave);
    t.pump(1, 60);
    for seed in [p, h, s] {
        let m = t.node(seed).membership.as_ref().expect("членство");
        let got: Vec<[u8; 32]> = m.members().iter().map(|x| x.owner_ed25519).collect();
        assert_eq!(t.node(seed).epoch(), Some(2), "(6) эпоха 2 у {seed}");
        assert_eq!(got, want, "(6) состав [H,S] у {seed}");
        assert_eq!(m.primary(), Some(h_addr), "(6) primary эпохи 2 — H");
        assert!(!m.is_member(&p_addr), "(6) P выведен из состава у {seed}");
        assert_eq!(
            t.node(seed).lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((2, h_addr, 7)),
            "(6) lease эпохи 2 у {seed}"
        );
    }
    assert_eq!(t.node(h).serving_epoch(2), Some(2));

    // Новый primary собирает W=2 уже в новом составе.
    let out = publish(&mut t, h, 42, 42, 2, 2);
    assert_eq!(out.len(), 1, "(6) в составе [H,S] один ReplicateOp: {out:?}");
    assert_eq!(out[0].to, t.addr(s));
    let acks = deliver(&mut t, s, h, &out[0], 2);
    assert_eq!(acks.len(), 1);
    let ack = acks_of(&deliver(&mut t, h, s, &acks[0], 2));
    assert_eq!(ack.len(), 1, "(6) W=2 на новом primary: {ack:?}");
    assert_eq!((ack[0].error_code.as_str(), ack[0].epoch, ack[0].seq), ("OK", 2, 2));
    assert_eq!(t.node(h).applied_seq(), 2);
    assert_eq!(t.node(s).applied_seq(), 2);

    // Ушедший primary больше не пишет — теперь уже NOT_OWNER.
    let out = publish(&mut t, p, 43, 43, 2, 2);
    let errs = errors_of(&out);
    assert_eq!(errs.len(), 1, "(6) F отвергнут: {out:?}");
    assert_eq!(errs[0].code, err_code::NOT_OWNER);
    assert!(out.iter().all(|e| kind_of(e) == Kind::Error));
    assert_eq!(t.node(p).applied_seq(), 1);

    // Чтение у демотированного переживает уход.
    let who = testing::identity(60);
    let find = testing::find_frame(&who, &testing::vector(40), &[cluster_of(40)], 10, 9001);
    let out = t
        .node_mut(p)
        .on_frame(who.pubkey(), &find, testing::clock(3))
        .expect("Find");
    let results: Vec<MatchResult> = out
        .iter()
        .filter(|e| kind_of(e) == Kind::MatchResult)
        .map(|e| MatchResult::decode(&e.frame).expect("MatchResult"))
        .collect();
    assert_eq!(results.len(), 1, "(6) ровно один MatchResult: {out:?}");
    assert_eq!(results[0].epoch, 2);
    assert_eq!(results[0].responder_ed25519, p_addr);
    assert_eq!(results[0].matches.len(), 1);
    assert_eq!(results[0].matches[0].slot, a_slot, "(6) слот A тот же");
    assert!(!t.node(p).is_primary());
    assert_eq!(t.node(p).serving_epoch(2), Some(2));
    t.clean();
}
