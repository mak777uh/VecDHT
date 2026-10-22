//! H-0073 / E-0073: рестарт узла — WAL, снапшот, GC и потеря lease.
//!
//! Проверяется композиция восстановления `ShardStore` с членством, lease и W=2:
//! * реплика после reopen поднимает WAL и членство, но не имеет lease — чтение идёт, запись нет;
//! * primary после reopen теряет право писать (`EPOCH_STALE`), пока не примет новую эпоху;
//! * барьер снапшота переживает reopen: WAL не переигрывается, `TimeMark` восстанавливается;
//! * partial-снапшот игнорируется, как точка 3 §10.5;
//! * TTL после рестарта решает применённый `TimeMark`/`GcTick`, а не часы.
//!
//! Crash-матрица §10.5 на уровне `ShardStore` живёт в `crates/vecdht-index/tests/crash_matrix.rs`
//! и здесь не перемеряется: вопрос лаборатории — композиция с §9.8 и §9.4.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_index::manifest::read_manifest;
use vecdht_index::snapshot::{partial_name, snapshot_name};
use vecdht_index::testing::{dir, remove};
use vecdht_index::wal::Fault;
use vecdht_node::net::{Addr, Envelope};
use vecdht_node::{Clock, ShardNode, candidates, testing};
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{
    Codec, LeaseGrant, MatchResult, MembershipUpdate, OpKind, ProtocolError, PublishAck,
    ReplicateOp, err_code,
};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const POW: u32 = 8;
const TTL: u16 = 225;

// --- каркас: тройка и ручная доставка ----------------------------------------

/// Тройка сидов, у которой primary эпохи 1 первым стоит в `speaker_order(2)`.
///
/// Это не удобство, а условие сценария: после рестарта primary обязан успеть предложить
/// эпоху 2 до истечения lease реплик (бакет 6). Если он не первый в очереди, он пошлёт
/// черновик на `rank * election` позже, реплики успеют счесть его мёртвым, и штатный
/// путь «рестарт → эпоха 2» сменился бы путём «рестарт → исключение».
fn choose_roles() -> (Vec<u8>, u8) {
    for a in 1u8..=16 {
        for b in a + 1..=16 {
            for c in b + 1..=16 {
                let seeds = vec![a, b, c];
                let holders = testing::holders(&seeds);
                let p_key = candidates::ordered(1, SHARD, &holders)[0].owner_ed25519;
                let owners: Vec<[u8; 32]> =
                    holders.iter().map(|h| h.owner_ed25519).collect();
                if candidates::speaker_order(2, SHARD, &owners)[0] == p_key {
                    let p_seed = seed_of(&seeds, p_key);
                    return (seeds, p_seed);
                }
            }
        }
    }
    panic!("не нашлось тройки сидов: primary эпохи 1 не первый в speaker_order(2)");
}

fn seed_of(seeds: &[u8], key: [u8; 32]) -> u8 {
    *seeds
        .iter()
        .find(|s| testing::identity(**s).pubkey() == key)
        .expect("ключ принадлежит тройке")
}

struct Trio {
    nodes: BTreeMap<Addr, ShardNode>,
    seeds: BTreeMap<Addr, u8>,
    seed_list: Vec<u8>,
    dirs: BTreeMap<Addr, PathBuf>,
    p_seed: u8,
    inbox: Vec<(Addr, Envelope)>,
}

impl Trio {
    fn new(tag: &str) -> Trio {
        let (seed_list, p_seed) = choose_roles();
        let genesis = testing::signed_frame(&testing::genesis_update(SHARD, &seed_list, 0));
        let carrier = testing::identity(200).pubkey();
        let mut nodes = BTreeMap::new();
        let mut seeds = BTreeMap::new();
        let mut dirs = BTreeMap::new();
        for seed in &seed_list {
            let d = dir(&format!("{tag}-{seed}"));
            let n = testing::node(&d, SHARD, *seed, testing::params(POW), &seed_list);
            let a = n.me();
            seeds.insert(a, *seed);
            dirs.insert(a, d);
            nodes.insert(a, n);
        }
        for n in nodes.values_mut() {
            n.on_frame(carrier, &genesis, testing::clock(0))
                .expect("genesis эпохи 1 принимается каждым узлом");
        }
        Trio { nodes, seeds, seed_list, dirs, p_seed, inbox: Vec::new() }
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

    fn dir_of(&self, addr: Addr) -> &PathBuf {
        self.dirs.get(&addr).expect("каталог из карты")
    }

    /// Закрыть узел, не трогая каталог: следующий `reopen` читает диск с нуля.
    fn close(&mut self, seed: u8) {
        assert!(self.inbox.is_empty(), "закрывать узел с недоставленными кадрами нельзя");
        let a = self.addr(seed);
        self.nodes.remove(&a);
    }

    fn reopen(&mut self, seed: u8) {
        let a = self.addr(seed);
        self.nodes.remove(&a);
        let d = self.dirs.get(&a).expect("каталог узла").clone();
        let n = testing::node(&d, SHARD, seed, testing::params(POW), &self.seed_list);
        assert!(
            n.epoch().is_some(),
            "членство обязано подняться с диска; genesis повторно не доставляется"
        );
        self.nodes.insert(a, n);
    }

    fn send(&mut self, from: Addr, envs: &[Envelope]) {
        for e in envs {
            self.inbox.push((from, e.clone()));
        }
    }

    /// Прокачать inbox до неподвижной точки. Возвращает число доставленных кадров.
    fn pump(&mut self, now: u32, max_rounds: usize) -> usize {
        let mut delivered = 0usize;
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
                let node = self.nodes.get_mut(&e.to).unwrap_or_else(|| {
                    panic!("кадр {kind:?} адресован узлу, которого нет в тройке")
                });
                let replies = node
                    .on_frame(from, &e.frame, testing::clock(now))
                    .unwrap_or_else(|err| panic!("{kind:?} сломал узел: {err}"));
                delivered += 1;
                for r in replies {
                    self.inbox.push((e.to, r));
                }
            }
        }
        delivered
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

fn publish_frame(agent_seed: u8, vec_seed: u8, epoch: u64, bucket: u32, ttl: u16) -> Vec<u8> {
    let agent = testing::identity(agent_seed);
    testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(vec_seed),
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch,
        published_bucket: bucket,
        ttl_buckets: ttl,
        bits: POW,
    }
    .frame()
}

/// Опубликовать запись и собрать ровно тот путь §9.4: 2 `ReplicateOp`, acks реплик,
/// `PublishAck` после `w`. Возвращает число опсов и все выданные `PublishAck`.
fn publish(
    t: &mut Trio,
    to: Addr,
    agent_seed: u8,
    vec_seed: u8,
    epoch: u64,
    bucket: u32,
    ttl: u16,
) -> (usize, Vec<PublishAck>) {
    let agent = testing::identity(agent_seed);
    let frame = publish_frame(agent_seed, vec_seed, epoch, bucket, ttl);
    let ops = t
        .node_mut(to)
        .on_frame(agent.pubkey(), &frame, testing::clock(bucket))
        .expect("Publish");
    assert!(!ops.is_empty(), "publish обязан дать ReplicateOp: {ops:?}");
    assert!(
        ops.iter().all(|e| kind_of(e) == Kind::ReplicateOp),
        "publish обязан дать только ReplicateOp: {ops:?}"
    );
    let mut replica_acks = Vec::new();
    for e in &ops {
        let replies = t
            .node_mut(e.to)
            .on_frame(to, &e.frame, testing::clock(bucket))
            .expect("реплика разбирает op");
        assert_eq!(replies.len(), 1, "реплика обязана ответить одним ack: {replies:?}");
        assert_eq!(kind_of(&replies[0]), Kind::ReplicateAck, "ack реплики");
        replica_acks.push((e.to, replies[0].clone()));
    }
    let mut out = Vec::new();
    for (from, ack) in replica_acks {
        let replies = t
            .node_mut(to)
            .on_frame(from, &ack.frame, testing::clock(bucket))
            .expect("primary принимает ack");
        assert!(errors(&replies).is_empty(), "primary не должен отказывать ack: {replies:?}");
        out.extend(acks(&replies));
    }
    (ops.len(), out)
}

fn find(
    t: &mut Trio,
    at: Addr,
    agent_seed: u8,
    vec_seed: u8,
    bucket: u32,
    query_id: u64,
) -> MatchResult {
    let agent = testing::identity(agent_seed);
    let frame = testing::find_frame(&agent, &testing::vector(vec_seed), &[CLUSTER], 10, query_id);
    let out = t
        .node_mut(at)
        .on_frame(agent.pubkey(), &frame, testing::clock(bucket))
        .expect("Find");
    // §12.3: на каждое попадание `handle_find` добавляет отдельную квитанцию
    // `RendezvousAccept`; лабораторный контракт Find — ровно один `MatchResult`
    // и ни одного кадра догона/репликации.
    let results: Vec<&Envelope> = out.iter().filter(|e| kind_of(e) == Kind::MatchResult).collect();
    assert_eq!(results.len(), 1, "Find обязан ответить ровно одним MatchResult: {out:?}");
    for e in &out {
        let kind = kind_of(e);
        assert!(
            matches!(kind, Kind::MatchResult | Kind::RendezvousAccept),
            "Find не порождает {kind:?}: {out:?}"
        );
    }
    MatchResult::decode(&results[0].frame).expect("MatchResult обязан разбираться")
}

fn slot_of(t: &Trio, at: Addr, owner_seed: u8) -> u32 {
    t.node(at)
        .store
        .index
        .owner_slot(&testing::identity(owner_seed).pubkey())
        .expect("владелец обязан быть в индексе")
}

fn members_of(n: &ShardNode) -> Vec<[u8; 32]> {
    n.membership
        .as_ref()
        .expect("членство есть")
        .members()
        .iter()
        .map(|m| m.owner_ed25519)
        .collect()
}

fn lease_of(n: &ShardNode) -> Option<(u64, Addr, u32)> {
    n.lease
        .as_ref()
        .map(|l| (l.epoch, l.primary, l.expires_at_bucket))
}

// --- замер --------------------------------------------------------------------

#[test]
fn restart_recovers_wal_snapshot_and_gc() {
    let mut t = Trio::new("restart-recovery");
    let p_seed = t.p_seed;
    let p = t.addr(p_seed);
    let rest: Vec<u8> = t.seed_list.iter().copied().filter(|s| *s != p_seed).collect();
    let h_seed = rest[0];
    let s_seed = rest[1];
    let h = t.addr(h_seed);
    let s = t.addr(s_seed);

    // (0) База: A и B через W=2, оба ReplicateOp доставлены H и S.
    let (ops_a, ack_a) = publish(&mut t, p, 60, 20, 1, 1, TTL);
    assert_eq!(ops_a, 2, "(0) A: по опсу каждой реплике");
    assert_eq!(ack_a.len(), 1, "(0) A: ровно один PublishAck: {ack_a:?}");
    assert_eq!((ack_a[0].error_code.as_str(), ack_a[0].epoch, ack_a[0].seq), ("OK", 1, 1));
    let (ops_b, ack_b) = publish(&mut t, p, 61, 30, 1, 1, TTL);
    assert_eq!(ops_b, 2, "(0) B: по опсу каждой реплике");
    assert_eq!(ack_b.len(), 1, "(0) B: ровно один PublishAck: {ack_b:?}");
    assert_eq!((ack_b[0].error_code.as_str(), ack_b[0].epoch, ack_b[0].seq), ("OK", 1, 2));
    for addr in [p, h, s] {
        let n = t.node(addr);
        assert_eq!(n.applied_seq(), 2, "(0) две записи применены");
        assert_eq!(n.store.len(), 2, "(0) две живые записи");
        assert_eq!(n.epoch(), Some(1), "(0) эпоха 1");
        assert_eq!(n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)), Some((1, p, 6)), "(0) lease эпохи 1");
        assert_eq!(n.serving_epoch(2), Some(1), "(0) обслуживание эпохи 1");
        assert_eq!(n.membership.as_ref().map(|m| m.len()), Some(3), "(0) состав [P,H,S]");
        assert_eq!(n.store.last_snapshot_seq, 0, "(0) снапшота ещё нет");
        assert_eq!(n.store.replayed(), 0, "(0) это живой узел, не восстановленный");
        assert!(!n.is_unreachable(&p) || addr == p, "(0) никто не помечен мёртвым");
    }
    let slot_a = slot_of(&t, p, 60);
    let slot_b = slot_of(&t, p, 61);
    for addr in [h, s] {
        assert_eq!(slot_of(&t, addr, 60), slot_a, "(0) слот A совпадает");
        assert_eq!(slot_of(&t, addr, 61), slot_b, "(0) слот B совпадает");
    }
    assert_eq!(find(&mut t, h, 70, 20, 2, 1).matches.len(), 1, "(0) H видит A до рестарта");

    // (1) Рестарт реплики: WAL и членство с диска, lease потерян, чтение живо.
    t.close(h_seed);
    t.reopen(h_seed);
    {
        let n = t.node(h);
        assert_eq!(n.applied_seq(), 3 - 1, "(1) WAL H восстановлен");
        assert_eq!(n.store.replayed(), 2, "(1) переиграны ровно два фрейма");
        assert_eq!(n.store.len(), 2, "(1) записи на месте");
        assert_eq!(n.epoch(), Some(1), "(1) членство поднято с диска");
        assert!(n.lease.is_none(), "(1) lease в RAM не переживает рестарт");
        assert!(!n.lease_active(4), "(1) lease не активен");
        assert_eq!(n.serving_epoch(4), None, "(1) писать нельзя без lease");
        assert_eq!(slot_of(&t, h, 60), slot_a, "(1) слот A тот же");
    }
    let seen = find(&mut t, h, 70, 20, 4, 2);
    assert_eq!(seen.epoch, 1, "(1) чтение отвечает принятой эпохой");
    assert_eq!(seen.matches.len(), 1, "(1) чтение переживает потерю lease");
    let _ = s;

    // (2) Грант lease и W=2 с восстановленной репликой.
    let grants = t.node_mut(p).tick(4).expect("tick primary");
    assert_eq!(grants.len(), 2, "(2) продление уходит двум репликам: {grants:?}");
    for e in &grants {
        assert_eq!(kind_of(e), Kind::LeaseGrant, "(2) только LeaseGrant: {grants:?}");
        let g = LeaseGrant::decode(&e.frame).expect("LeaseGrant разбирается");
        assert_eq!((g.epoch, g.primary_ed25519, g.expires_at_bucket), (1, p, 10), "(2) грант эпохи 1");
        assert!(e.to == h || e.to == s, "(2) адресат — H или S");
    }
    for e in &grants {
        let replies = t
            .node_mut(e.to)
            .on_frame(p, &e.frame, testing::clock(4))
            .expect("реплика принимает грант");
        assert!(replies.is_empty(), "(2) грант не рождает ответа: {replies:?}");
    }
    {
        let n = t.node(h);
        assert_eq!(n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)), Some((1, p, 10)), "(2) H получил lease");
        assert_eq!(n.serving_epoch(4), Some(1), "(2) H снова обслуживает эпоху 1");
    }
    let (ops_c, ack_c) = publish(&mut t, p, 62, 31, 1, 4, TTL);
    assert_eq!(ops_c, 2, "(2) C: два ReplicateOp");
    assert_eq!(ack_c.len(), 1, "(2) C: ровно один PublishAck: {ack_c:?}");
    assert_eq!((ack_c[0].error_code.as_str(), ack_c[0].epoch, ack_c[0].seq), ("OK", 1, 3));
    for addr in [p, h, s] {
        let n = t.node(addr);
        assert_eq!(n.applied_seq(), 3, "(2) C применён у всех");
        assert_eq!(n.store.len(), 3, "(2) три живые записи");
        assert_eq!(slot_of(&t, addr, 62), slot_of(&t, p, 62), "(2) слот C совпадает");
    }
    assert_eq!(find(&mut t, h, 70, 31, 4, 3).matches.len(), 1, "(2) H видит C после восстановления");

    // (3) Рестарт primary: данные и членство живы, право писать — нет.
    t.close(p_seed);
    t.reopen(p_seed);
    {
        let n = t.node(p);
        assert_eq!(n.applied_seq(), 3, "(3) WAL P восстановлен");
        assert_eq!(n.store.replayed(), 3, "(3) переиграны три фрейма");
        assert_eq!(n.store.len(), 3, "(3) три записи");
        assert_eq!(n.epoch(), Some(1), "(3) членство эпохи 1 с диска");
        assert!(n.lease.is_none(), "(3) lease потерян");
        assert!(!n.lease_active(4), "(3) lease не активен");
        assert_eq!(n.serving_epoch(4), None, "(3) писать нельзя");
    }
    let agent_d = testing::identity(63);
    let frame_d1 = publish_frame(63, 40, 1, 4, TTL);
    let out = t
        .node_mut(p)
        .on_frame(agent_d.pubkey(), &frame_d1, testing::clock(4))
        .expect("Publish D до эпохи 2");
    let errs = errors(&out);
    assert_eq!(errs.len(), 1, "(3) ровно один отказ: {out:?}");
    assert_eq!(errs[0].code, err_code::EPOCH_STALE, "(3) {errs:?}");
    assert!(acks(&out).is_empty(), "(3) OK не выдан");
    assert!(out.iter().all(|e| kind_of(e) != Kind::ReplicateOp), "(3) репликации нет");
    assert_eq!(t.node(p).applied_seq(), 3, "(3) WAL не тронут");
    assert_eq!(find(&mut t, p, 70, 20, 4, 4).matches.len(), 1, "(3) чтение A живо");
    assert_eq!(find(&mut t, p, 70, 40, 4, 5).matches.len(), 0, "(3) D не виден");

    // (4) Эпоха 2 после рестарта: черновик, прокачка, primary и W=2.
    let drafts = t.node_mut(p).tick(4).expect("tick после рестарта primary");
    assert_eq!(drafts.len(), 2, "(4) черновик уходит двум репликам: {drafts:?}");
    for e in &drafts {
        assert_eq!(kind_of(e), Kind::MembershipUpdate, "(4) только MembershipUpdate: {drafts:?}");
        let upd = MembershipUpdate::decode(&e.frame).expect("черновик разбирается");
        assert_eq!(upd.epoch, 2, "(4) эпоха 2");
        assert_eq!(upd.sigs.len(), 1, "(4) подпись только P: {upd:?}");
        assert!(e.to == h || e.to == s, "(4) адресат — H или S");
    }
    t.send(p, &drafts);
    let delivered = t.pump(4, 20);
    assert!(delivered >= 2, "(4) прокачка доставила кадры: {delivered}");
    let expected = candidates::members(2, SHARD, &testing::holders(&t.seed_list), testing::params(POW).r, 3);
    let expected_members: Vec<[u8; 32]> = expected.iter().map(|m| m.owner_ed25519).collect();
    let new_primary_key = expected[0].owner_ed25519;
    let new_seed = seed_of(&t.seed_list, new_primary_key);
    let new_primary = t.addr(new_seed);
    for addr in [p, h, s] {
        let n = t.node(addr);
        assert_eq!(n.epoch(), Some(2), "(4) все на эпохе 2");
        assert_eq!(members_of(n), expected_members, "(4) состав детерминирован");
        assert_eq!(n.membership.as_ref().and_then(|m| m.primary()), Some(new_primary_key), "(4) primary из кандидатов");
        assert_eq!(lease_of(n), Some((2, new_primary, 10)), "(4) lease эпохи 2");
        assert_eq!(n.store.serving_epoch(), Some(2), "(4) durable-маркер эпохи 2");
        assert_eq!(n.serving_epoch(4), Some(2), "(4) обслуживание возобновлено");
        assert_eq!(n.applied_seq(), 3, "(4) adopt не пишет WAL");
    }
    let (ops_d, ack_d) = publish(&mut t, new_primary, 63, 40, 2, 5, TTL);
    assert_eq!(ops_d, 2, "(4) D: два ReplicateOp");
    assert_eq!(ack_d.len(), 1, "(4) D: ровно один PublishAck: {ack_d:?}");
    assert_eq!((ack_d[0].error_code.as_str(), ack_d[0].epoch, ack_d[0].seq), ("OK", 2, 4));
    let slot_d = slot_of(&t, new_primary, 63);
    for addr in [p, h, s] {
        let n = t.node(addr);
        assert_eq!(n.applied_seq(), 4, "(4) D применён у всех");
        assert_eq!(n.store.len(), 4, "(4) четыре записи");
        assert_eq!(slot_of(&t, addr, 63), slot_d, "(4) слот D совпадает");
        let seen = find(&mut t, addr, 70, 40, 5, 10 + addr[0] as u64);
        assert_eq!((seen.epoch, seen.matches.len()), (2, 1), "(4) D находится после heal");
    }

    // (5) GC без wall-clock: TTL решает применённый бакет, не часы.
    let (ops_e, ack_e) = publish(&mut t, new_primary, 64, 50, 2, 5, 1);
    assert_eq!(ops_e, 2, "(5) E: два ReplicateOp");
    assert_eq!(ack_e.len(), 1, "(5) E: ровно один PublishAck: {ack_e:?}");
    assert_eq!((ack_e[0].error_code.as_str(), ack_e[0].epoch, ack_e[0].seq), ("OK", 2, 5));
    assert_eq!(t.node(new_primary).store.len(), 5, "(5) E жива до GC");
    for addr in [p, h, s] {
        assert_eq!(t.node(addr).applied_seq(), 5, "(5) E применён у всех");
        assert_eq!(t.node(addr).store.time_mark_bucket, 0, "(5) TimeMark ещё 0");
        let seen = find(&mut t, addr, 70, 50, 5, 20 + addr[0] as u64);
        assert_eq!(seen.matches.len(), 1, "(5) E видна при mark 0");
    }
    let gc = t.node_mut(new_primary).tick(6).expect("GC-тик");
    assert_eq!(gc.len(), 2, "(5) GcTick уходит двум репликам: {gc:?}");
    for e in &gc {
        assert_eq!(kind_of(e), Kind::ReplicateOp, "(5) только ReplicateOp: {gc:?}");
        let op = ReplicateOp::decode(&e.frame).expect("ReplicateOp разбирается");
        assert_eq!((op.epoch, op.seq, op.op_kind), (2, 6, OpKind::GcTick), "(5) кадр GC");
    }
    for e in &gc {
        let replies = t
            .node_mut(e.to)
            .on_frame(new_primary, &e.frame, testing::clock(6))
            .expect("реплика применяет GC");
        assert_eq!(replies.len(), 1, "(5) ack на GC: {replies:?}");
        assert_eq!(kind_of(&replies[0]), Kind::ReplicateAck, "(5) ack на GC");
    }
    for addr in [p, h, s] {
        let n = t.node(addr);
        assert_eq!(n.applied_seq(), 6, "(5) GC применён у всех");
        assert_eq!(n.store.time_mark_bucket, 6, "(5) mark 6 восстановим из WAL");
        assert_eq!(n.store.len(), 4, "(5) E истекла");
        assert_eq!(find(&mut t, addr, 70, 50, 6, 30 + addr[0] as u64).matches.len(), 0, "(5) E не находится");
        assert_eq!(find(&mut t, addr, 70, 20, 6, 40 + addr[0] as u64).matches.len(), 1, "(5) A жива");
    }

    // (6) Снапшот и reopen: WAL не переигрывается, mark восстанавливается.
    let snap_dir = t.dir_of(new_primary).clone();
    let written = t
        .node_mut(new_primary)
        .store
        .flush_snapshot()
        .expect("снапшот пишется");
    assert!(written > 0, "(6) снапшот непустой");
    let mf = read_manifest(&snap_dir).expect("MANIFEST читается").expect("MANIFEST есть");
    assert_eq!(mf.snapshot_seq, 6, "(6) snapshot_seq");
    assert_eq!(mf.applied_seq, 6, "(6) applied_seq");
    assert_eq!(mf.oldest_wal_needed, 1, "(6) сегмент 1 ещё нужен как tail");
    assert_eq!(mf.time_mark_bucket, 6, "(6) mark в MANIFEST");
    assert!(snap_dir.join(snapshot_name(6)).exists(), "(6) snap.6.log на диске");
    for epoch in 1..=2u64 {
        let name = format!("membership.{epoch:020}.log");
        assert!(snap_dir.join(&name).exists(), "(6) {name} на диске");
    }
    t.close(new_seed);
    t.reopen(new_seed);
    {
        let n = t.node(new_primary);
        assert_eq!(n.store.replayed(), 0, "(6) WAL полностью покрыт снапшотом");
        assert_eq!(n.store.applied_seq, 6, "(6) applied_seq из MANIFEST");
        assert_eq!(n.store.len(), 4, "(6) живой индекс из снапшота");
        assert_eq!(n.store.time_mark_bucket, 6, "(6) mark из снапшота");
        assert_eq!(n.store.last_snapshot_seq, 6, "(6) last_snapshot_seq");
        assert_eq!(n.epoch(), Some(2), "(6) членство эпохи 2");
        assert!(n.lease.is_none(), "(6) lease не персистится");
        assert_eq!(n.serving_epoch(6), None, "(6) писать нельзя без lease");
        assert_eq!(slot_of(&t, new_primary, 60), slot_a, "(6) слот A пережил снапшот");
    }
    assert_eq!(find(&mut t, new_primary, 70, 20, 6, 51).matches.len(), 1, "(6) A из снапшота");
    assert_eq!(find(&mut t, new_primary, 70, 50, 6, 52).matches.len(), 0, "(6) E из снапшота");
    assert_eq!(
        find(&mut t, new_primary, 70, 20, 1000, 53).matches.len(),
        1,
        "(6) TTL не считает часы: mark 6 при Clock 1000"
    );
    assert_eq!(
        find(&mut t, new_primary, 70, 50, 1000, 54).matches.len(),
        0,
        "(6) E остаётся истёкшей при Clock 1000"
    );

    // (7) Partial-снапшот: точка 3 §10.5 на уровне узла.
    {
        let n = t.node_mut(new_primary);
        n.store.fault = Some(Fault::SnapshotMid);
        let err = n.store.flush_snapshot();
        assert!(err.is_err(), "(7) инъекция обязана вернуть ошибку: {err:?}");
    }
    assert!(snap_dir.join(partial_name(6)).exists(), "(7) snap.6.partial оставлен");
    assert!(snap_dir.join(snapshot_name(6)).exists(), "(7) полный snap.6.log цел");
    let mf2 = read_manifest(&snap_dir).expect("MANIFEST читается").expect("MANIFEST есть");
    assert_eq!(mf2.snapshot_seq, 6, "(7) MANIFEST не сдвинулся");
    t.close(new_seed);
    t.reopen(new_seed);
    {
        let n = t.node(new_primary);
        assert_eq!(n.store.replayed(), 0, "(7) partial не заставляет переигрывать WAL");
        assert_eq!(n.store.applied_seq, 6, "(7) applied_seq не изменился");
        assert_eq!(n.store.len(), 4, "(7) индекс не изменился");
    }
    assert_eq!(find(&mut t, new_primary, 70, 20, 6, 60).matches.len(), 1, "(7) A на месте");
    assert_eq!(find(&mut t, new_primary, 70, 50, 6, 61).matches.len(), 0, "(7) E истекла");

    let _ = (Clock::at(0), slot_b);
    t.clean();
}
