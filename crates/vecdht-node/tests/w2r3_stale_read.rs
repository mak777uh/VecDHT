//! H-0072 / E-0072: читатель у любой реплики W=2/R=3.
//!
//! Сценарий: Publish A доставлен primary P и только одной реплике H (второй ack закрывает
//! W=2); вторая реплика S не получила ничего. Проверяется, что:
//! * расхождение видно читателю — Find у S возвращает пустой `MatchResult` эпохи 1;
//! * чтение не ремонтирует: `handle_find` не шлёт ни pull, ни `ReplicateOp`;
//! * тики не ремонтируют: продление lease не догоняет данные;
//! * смена эпизоды латает: `adopt` шлёт `WalPullRequest` новому primary, и S применяет op;
//! * Publish без второго держателя не даёт `PublishAck` и не ретраится тиками.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::{Addr, Envelope};
use vecdht_node::{Clock, ShardNode, candidates, membership, testing};
use vecdht_wire::codec::DIM;
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{
    Codec, LeaseGrant, MatchResult, PublishAck, WalPullRequest, WalPullResponse, domain,
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

fn count_kind(envs: &[Envelope], kind: Kind) -> usize {
    envs.iter().filter(|e| kind_of(e) == kind).count()
}

fn acks(envs: &[Envelope]) -> Vec<PublishAck> {
    envs.iter()
        .filter(|e| kind_of(e) == Kind::PublishAck)
        .map(|e| PublishAck::decode(&e.frame).expect("PublishAck обязан разбираться"))
        .collect()
}

fn results(envs: &[Envelope]) -> Vec<MatchResult> {
    envs.iter()
        .filter(|e| kind_of(e) == Kind::MatchResult)
        .map(|e| MatchResult::decode(&e.frame).expect("MatchResult обязан разбираться"))
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

fn find(
    t: &mut Trio,
    addr: Addr,
    who: &Identity,
    vector_seed: u8,
    bucket: u32,
    query_id: u64,
) -> Vec<Envelope> {
    let frame = testing::find_frame(
        who,
        &testing::vector(vector_seed),
        &[CLUSTER],
        10,
        query_id,
    );
    t.node_mut(addr)
        .on_frame(who.pubkey(), &frame, testing::clock(bucket))
        .expect("Find обязан разбираться")
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

/// Роли эпохи 2: H — новый primary (первый в порядке `[H,S]`), S — отставшая реплика.
fn epoch2_roles(rest: &[u8]) -> (u8, u8) {
    assert_eq!(rest.len(), 2, "после primary эпохи 1 остаются две реплики");
    let params = testing::params(POW);
    let list = candidates::expected_update(
        2,
        SHARD,
        &testing::holders(rest),
        params.r,
        0,
        4,
    );
    assert_eq!(list.members.len(), 2, "эпоха 2 — обе оставшиеся реплики");
    let key = list.members[0].owner_ed25519;
    let h = rest
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == key)
        .expect("новый primary — один из сидов");
    let s = rest
        .iter()
        .copied()
        .find(|x| *x != h)
        .expect("вторая реплика");
    (h, s)
}

/// Кадр эпохи 2: состав `members_seeds`, подписи `signers` (индексы эпохи 1).
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

fn epoch2_frame(h_seed: u8, s_seed: u8) -> (Vec<u8>, [u8; 32]) {
    let params = testing::params(POW);
    let list = candidates::expected_update(
        2,
        SHARD,
        &testing::holders(&[h_seed, s_seed]),
        params.r,
        0,
        4,
    );
    let new_primary = list.members[0].owner_ed25519;
    (epoch_frame(&[h_seed, s_seed], &[h_seed, s_seed]), new_primary)
}

// --- замер --------------------------------------------------------------------

#[test]
fn w2r3_stale_read() {
    let ordered = ordered1();
    let p_seed = SEEDS
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == ordered[0].owner_ed25519)
        .expect("primary эпохи 1 — один из тестовых сидов");
    let rest: Vec<u8> = SEEDS.iter().copied().filter(|s| *s != p_seed).collect();
    let (h_seed, s_seed) = epoch2_roles(&rest);
    let (frame2, new_primary) = epoch2_frame(h_seed, s_seed);
    assert_eq!(
        new_primary,
        testing::identity(h_seed).pubkey(),
        "H выбран как новый primary эпохи 2"
    );

    // ---------- W=2, а не R=3 ----------
    let mut t = Trio::open("w2r3-main");
    let p = t.addr(p_seed);
    let h = t.addr(h_seed);
    let s = t.addr(s_seed);

    let agent = testing::identity(60);
    let a_frame = publish_frame(&agent, &testing::vector(20), 1, 1);
    let out = t
        .node_mut(p)
        .on_frame(agent.pubkey(), &a_frame, testing::clock(1))
        .expect("Publish A");
    assert_eq!(out.len(), 2, "по одному ReplicateOp каждой реплике: {out:?}");
    assert!(out.iter().all(|e| kind_of(e) == Kind::ReplicateOp));
    let mut to_h = Vec::new();
    let mut to_s = Vec::new();
    for e in out {
        if e.to == h {
            to_h.push(e);
        } else if e.to == s {
            to_s.push(e);
        } else {
            panic!("ReplicateOp адресован не реплике");
        }
    }
    assert_eq!((to_h.len(), to_s.len()), (1, 1), "по одному опсу каждой реплике");
    // Второй ack не нужен: W=2 закрывает сам primary + H. Опс для S теряется.
    let ack_envs = t.route(p, &to_h, testing::clock(1));
    let acked = t.route(h, &ack_envs, testing::clock(1));
    let a = acks(&acked);
    assert_eq!(a.len(), 1, "ровно один PublishAck: {acked:?}");
    assert_eq!(a[0].error_code, "OK");
    assert_eq!((a[0].epoch, a[0].seq), (1, 1));
    assert_eq!(acked.len(), 1, "агенту уходит только PublishAck: {acked:?}");
    drop(to_s);

    let slot_h = t
        .node(h)
        .store
        .index
        .owner_slot(&agent.pubkey())
        .expect("слот A у H");

    // (0) W=2: primary и один репликант держат запись, второй — нет.
    {
        let n = t.node(p);
        assert_eq!(n.epoch(), Some(1), "(0) P на эпохе 1");
        assert_eq!(n.applied_seq(), 1, "(0) P применил A");
        assert_eq!(n.store.len(), 1, "(0) у P одна запись");
        assert_eq!(n.store.index.owner_slot(&agent.pubkey()), Some(slot_h), "(0) слот A у P");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, p, 6)),
            "(0) lease P: эпоха 1, expires 6"
        );
    }
    {
        let n = t.node(h);
        assert_eq!(n.epoch(), Some(1), "(0) H на эпохе 1");
        assert_eq!(n.applied_seq(), 1, "(0) H применил A");
        assert_eq!(n.store.len(), 1, "(0) у H одна запись");
        assert_eq!(n.store.index.owner_slot(&agent.pubkey()), Some(slot_h), "(0) слот A у H");
        assert_eq!(n.serving_epoch(2), Some(1), "(0) H может писать эпоху 1");
    }
    {
        let n = t.node(s);
        assert_eq!(n.epoch(), Some(1), "(0) S на эпохе 1");
        assert_eq!(n.applied_seq(), 0, "(0) S не применил A");
        assert_eq!(n.store.len(), 0, "(0) у S пусто");
        assert_eq!(n.store.index.owner_slot(&agent.pubkey()), None, "(0) слота A у S нет");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, p, 6)),
            "(0) lease S получен при adopt, а не с опсом"
        );
        assert_eq!(n.serving_epoch(2), Some(1), "(0) S готов читать, но данных нет");
    }

    // (1) Расхождение видно читателю; Find не ремонтирует.
    let out_h = find(&mut t, h, &agent, 20, 2, 7001);
    let res_h = results(&out_h);
    assert_eq!(res_h.len(), 1, "(1) H: ровно один MatchResult: {out_h:?}");
    assert_eq!(res_h[0].epoch, 1, "(1) H отвечает эпохой 1");
    assert_eq!(res_h[0].responder_ed25519, h, "(1) responder — H");
    assert_eq!(res_h[0].matches.len(), 1, "(1) H видит A");
    assert_eq!(res_h[0].matches[0].owner_ed25519, agent.pubkey(), "(1) владелец A");
    assert_eq!(res_h[0].matches[0].slot, slot_h, "(1) слот A");
    assert!(
        out_h
            .iter()
            .all(|e| matches!(kind_of(e), Kind::MatchResult | Kind::RendezvousAccept)),
        "(1) ответ H — результат и приёмы, не ремонт: {out_h:?}"
    );

    let out_s = find(&mut t, s, &agent, 20, 2, 7001);
    assert_eq!(out_s.len(), 1, "(1) S: только MatchResult, без приёмов: {out_s:?}");
    let res_s = results(&out_s);
    assert_eq!(res_s.len(), 1, "(1) S: ровно один MatchResult: {out_s:?}");
    assert_eq!(res_s[0].epoch, 1, "(1) S отвечает своей эпохой 1");
    assert_eq!(res_s[0].responder_ed25519, s, "(1) responder — S");
    assert!(res_s[0].matches.is_empty(), "(1) S не видит A");
    assert_eq!(
        count_kind(&out_s, Kind::WalPullRequest)
            + count_kind(&out_s, Kind::ReplicateOp)
            + count_kind(&out_s, Kind::SnapshotOffer),
        0,
        "(1) Find не порождает ремонт: {out_s:?}"
    );
    assert_eq!(t.node(s).applied_seq(), 0, "(1) read-repair не применил опс");
    assert_eq!(t.node(s).store.len(), 0, "(1) индекс S не изменился");

    // (2) Тишина не лечит: тики реплик пусты, продление lease не догоняет данные.
    for bucket in [2u32, 3] {
        for addr in [h, s, p] {
            let out = t.node_mut(addr).tick(bucket).expect("тик живого члена эпохи 1");
            assert!(out.is_empty(), "(2) тик {bucket} узла {addr:?} пуст: {out:?}");
        }
    }
    let grants = t.node_mut(p).tick(4).expect("тик 4: продление lease");
    assert_eq!(grants.len(), 2, "(2) ровно два LeaseGrant: {grants:?}");
    assert!(grants.iter().all(|e| kind_of(e) == Kind::LeaseGrant), "(2) только гранты");
    assert!(
        grants.iter().any(|e| e.to == h) && grants.iter().any(|e| e.to == s),
        "(2) грант каждой реплике"
    );
    for e in &grants {
        let g = LeaseGrant::decode(&e.frame).expect("LeaseGrant разбирается");
        assert_eq!((g.epoch, g.primary_ed25519), (1, p), "(2) грант эпохи 1 от P");
    }
    assert_eq!(t.node(s).applied_seq(), 0, "(2) продление lease не догнало A");
    assert_eq!(t.node(s).store.len(), 0, "(2) индекс S по-прежнему пуст");

    // (3) Смена эпизоды латает: adopt S шлёт pull новому primary.
    for addr in [h, s] {
        t.node_mut(addr)
            .peer_lost(p, 4)
            .expect("событие транспорта об обрыве с P");
    }
    let s_out = t
        .node_mut(s)
        .on_frame(h, &frame2, testing::clock(4))
        .expect("цепочка эпохи 2 на S");
    assert_eq!(s_out.len(), 2, "(3) S принял эпоху и догоняется: {s_out:?}");
    let update_env = s_out
        .iter()
        .find(|e| kind_of(e) == Kind::MembershipUpdate)
        .cloned()
        .expect("(3) S рассылает принятую эпоху");
    let pull_env = s_out
        .iter()
        .find(|e| kind_of(e) == Kind::WalPullRequest)
        .cloned()
        .expect("(3) S шлёт ровно один догон");
    assert_eq!(s_out.len(), 2, "(3) кроме цепочки и догона — ничего: {s_out:?}");
    assert_eq!(pull_env.to, h, "(3) догон адресован primary эпохи 2");
    let req = WalPullRequest::decode(&pull_env.frame).expect("WalPullRequest разбирается");
    assert_eq!((req.shard, req.from_seq, req.to_seq), (SHARD, 0, 0), "(3) холодный старт");
    {
        let n = t.node(s);
        assert_eq!(n.epoch(), Some(2), "(3) S принял эпоху 2");
        assert_eq!(n.serving_epoch(4), Some(2), "(3) lease эпохи 2 + durable-маркер");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary)),
            Some((2, h)),
            "(3) lease от нового primary"
        );
        assert_eq!(n.applied_seq(), 0, "(3) adopt не пишет WAL");
    }

    // H принимает ту же цепочку от S и, как primary, отвечает цепочкой и грантом.
    let h_out = t.route(s, &[update_env], testing::clock(4));
    assert_eq!(h_out.len(), 2, "(3) H принял эпоху и рассылает: {h_out:?}");
    assert_eq!(count_kind(&h_out, Kind::MembershipUpdate), 1, "(3) цепочка от H");
    assert_eq!(count_kind(&h_out, Kind::LeaseGrant), 1, "(3) грант от H");
    assert!(
        h_out.iter().all(|e| e.to == s),
        "(3) оба кадра — отставшей реплике: {h_out:?}"
    );
    assert_eq!(
        count_kind(&h_out, Kind::WalPullRequest),
        0,
        "(3) primary не догоняется pull'ом"
    );
    assert_eq!(t.node(h).applied_seq(), 1, "(3) догонять H нечего");

    let s_echo = t.route(h, &h_out, testing::clock(4));
    assert!(s_echo.is_empty(), "(3) равная эпоха молчит, lease принят: {s_echo:?}");
    assert_eq!(
        t.node(s).lease.as_ref().map(|l| (l.epoch, l.primary)),
        Some((2, h)),
        "(3) lease эпохи 2 подтверждён"
    );

    let resp = t.route(s, &[pull_env], testing::clock(4));
    assert_eq!(resp.len(), 1, "(3) ровно один ответ на pull: {resp:?}");
    assert_eq!(kind_of(&resp[0]), Kind::WalPullResponse, "(3) kind ответа");
    assert_eq!(resp[0].to, s, "(3) ответ отставшей реплике");
    let wr = WalPullResponse::decode(&resp[0].frame).expect("WalPullResponse разбирается");
    assert_eq!(wr.shard, SHARD, "(3) шард ответа");
    assert_eq!(wr.primary_epoch, 2, "(3) ответ несёт эпоху нового primary");
    assert_eq!((wr.from_seq, wr.to_seq), (0, 1), "(3) хвост WAL: seq 1");
    assert!(!wr.frames.is_empty(), "(3) кадр записи не пуст");

    let applied = t.route(h, &resp, testing::clock(4));
    assert!(applied.is_empty(), "(3) догнали: продолжения нет: {applied:?}");
    {
        let n = t.node(s);
        assert_eq!(n.applied_seq(), 1, "(3) S применил A");
        assert_eq!(n.store.len(), 1, "(3) у S одна запись");
        assert_eq!(n.store.index.owner_slot(&agent.pubkey()), Some(slot_h), "(3) слот A у S");
    }

    // (4) После heal чтения сходятся.
    for addr in [s, h] {
        let out = find(&mut t, addr, &agent, 20, 5, 7002);
        let res = results(&out);
        assert_eq!(res.len(), 1, "(4) ровно один MatchResult от {addr:?}: {out:?}");
        assert_eq!(res[0].epoch, 2, "(4) чтение в эпохе 2");
        assert_eq!(res[0].matches.len(), 1, "(4) A виден");
        assert_eq!(res[0].matches[0].owner_ed25519, agent.pubkey(), "(4) владелец A");
        assert_eq!(res[0].matches[0].slot, slot_h, "(4) слот A тот же");
    }
    t.clean();

    // ---------- W=2 не собран: обещания durable нет ----------
    let mut t = Trio::open("w2r3-drop");
    let p = t.addr(p_seed);
    let h = t.addr(h_seed);
    let s = t.addr(s_seed);
    let agent_b = testing::identity(61);
    let b_frame = publish_frame(&agent_b, &testing::vector(30), 1, 1);
    let out = t
        .node_mut(p)
        .on_frame(agent_b.pubkey(), &b_frame, testing::clock(1))
        .expect("Publish B");
    assert_eq!(out.len(), 2, "(5) по ReplicateOp каждой реплике: {out:?}");
    assert!(out.iter().all(|e| kind_of(e) == Kind::ReplicateOp), "(5) только опсы");
    assert!(acks(&out).is_empty(), "(5) немедленного OK нет: {out:?}");
    assert_eq!(t.node(p).applied_seq(), 1, "(5) P записал B в WAL");
    assert_eq!(t.node(p).store.len(), 1, "(5) B виден у P");
    assert_eq!(t.node(h).applied_seq(), 0, "(5) H не получал B");
    assert_eq!(t.node(s).applied_seq(), 0, "(5) S не получал B");
    drop(out);

    let out_p = find(&mut t, p, &agent_b, 30, 2, 8001);
    let res_p = results(&out_p);
    assert_eq!(res_p.len(), 1, "(5) P отвечает своим MatchResult: {out_p:?}");
    assert_eq!(res_p[0].matches.len(), 1, "(5) локальный WAL виден читателю");
    let out_h = find(&mut t, h, &agent_b, 30, 2, 8001);
    let res_h = results(&out_h);
    assert_eq!(res_h.len(), 1, "(5) H отвечает своим MatchResult: {out_h:?}");
    assert!(res_h[0].matches.is_empty(), "(5) второго держателя нет");

    for bucket in [2u32, 3] {
        let out = t.node_mut(p).tick(bucket).expect("тик P без кворума");
        assert!(out.is_empty(), "(5) тик {bucket} не ретраит запись: {out:?}");
    }
    let grants = t.node_mut(p).tick(4).expect("тик 4: продление lease");
    assert_eq!(grants.len(), 2, "(5) только продление lease: {grants:?}");
    assert!(grants.iter().all(|e| kind_of(e) == Kind::LeaseGrant), "(5) только гранты");
    assert_eq!(t.node(p).applied_seq(), 1, "(5) повторной записи нет");
    t.clean();
}
