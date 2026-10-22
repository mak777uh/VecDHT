//! H-0071 / E-0071: §9 — разрыв эпох: узел, пропустивший эпоху, не догоняет шард.
//!
//! Сценарий: четыре кандидата шарда, `R = 3`, `t = 2`. Трое живых, один (`P`) заморожен —
//! он перестаёт обрабатывать кадры, но транспорт о его пропаже **не** сообщает, поэтому в
//! `live_roster` он остаётся и его слот в составе жив. Пока `P` заморожен, шард проходит две
//! ротации (эпохи 2 и 3), и `P` пропускает обе. Когда `P` оживает, цепочка эпохи 3 не имеет
//! для него промежуточной эпохи 2, а валидатор §9.2 принимает только `epoch = prev + 1`.
//!
//! Проверяется десять порогов (0)…(9) из `lab/hypotheses/H-0071-epoch-gap.md`:
//! * (0) база: эпоха 1, публикация принята, lease P = `{1, P, expires 6}`;
//! * (1) P пропускает эпоху 2, и пропуск — заморозка, а не отказ транспорта;
//! * (2) P пропускает эпоху 3 и **входит в состав эпохи 3** — слот зомби;
//! * (3) разрыв отвергнут **молча**: ни кадра ответа, ни ошибки узла; причина — `EpochNotNext`;
//! * (4) ловушка замыкается: круг «черновик P → ответ живым → P» ничего не меняет;
//! * (5) `Publish` к P отвергается `EPOCH_STALE`, хотя `is_primary()` истина;
//! * (6) `peer_alive` (heal по `ADR-0017`) разрыв не лечит;
//! * (7) уйти нельзя: `LeaveNotice` с собственной эпохой отвергнут, с чужой — принят;
//! * (8) рестарт не лечит: с диска поднимается эпоха 1;
//! * (9) холодный старт в середине цепочки невозможен: `NotGenesis`.
//!
//! Время — бакетами (§9.6), ручная доставка, один процесс, без транспорта.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::{Addr, Envelope};
use vecdht_node::{ShardNode, candidates, membership, testing};
use vecdht_wire::codec::DIM;
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{
    Codec, LeaveNotice, Member, MembershipUpdate, ProtocolError, PublishAck, domain, err_code,
};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const POW: u32 = 8;
const TTL: u16 = 225;
/// `R` — размер состава (§9.3).
const R: usize = 3;
/// Ёмкость записей шарда: фильтр `fits` при таком значении не отсекает ни одного кандидата.
const ENTRIES: u64 = 1;

// --- выбор сидов ---------------------------------------------------------------

/// Состав эпохи: детерминированный выбор из кандидатов (§9.3).
fn composition(epoch: u64, seeds: &[u8]) -> Vec<Member> {
    candidates::members(epoch, SHARD, &testing::holders(seeds), R, ENTRIES)
}

fn seed_of(seeds: &[u8], key: [u8; 32]) -> u8 {
    *seeds
        .iter()
        .find(|s| testing::identity(**s).pubkey() == key)
        .expect("ключ принадлежит набору сидов")
}

fn contains(members: &[Member], key: [u8; 32]) -> bool {
    members.iter().any(|m| m.owner_ed25519 == key)
}

/// Четыре кандидата, при которых сценарий разрыва возможен.
///
/// Условия отбора — не украшение, а условие существования сценария:
/// * `P` — primary эпохи 1: тогда его `Publish` доходит до гейта эпохи, а не до `NOT_OWNER`;
/// * оба живых участника эпохи 1 входят в составы эпох 2 и 3: только тогда цепочка очередной
///   эпохи может быть подписана двумя подписантами и доставлена тем, кто её принимает;
/// * `P` входит в состав эпох 3 и 4: слот зомби занят, и это видно.
fn choose_quad() -> (Vec<u8>, u8) {
    for a in 1u8..=16 {
        for b in a + 1..=16 {
            for c in b + 1..=16 {
                for d in c + 1..=16 {
                    let seeds = vec![a, b, c, d];
                    let x1 = composition(1, &seeds);
                    let p_seed = seed_of(&seeds, x1[0].owner_ed25519);
                    let p = testing::identity(p_seed).pubkey();
                    let live1: Vec<[u8; 32]> = x1
                        .iter()
                        .filter(|m| m.owner_ed25519 != p)
                        .map(|m| m.owner_ed25519)
                        .collect();
                    if live1.len() != 2 {
                        continue;
                    }
                    let x2 = composition(2, &seeds);
                    let x3 = composition(3, &seeds);
                    let x4 = composition(4, &seeds);
                    if !live1.iter().all(|k| contains(&x2, *k)) {
                        continue;
                    }
                    if !live1.iter().all(|k| contains(&x3, *k)) {
                        continue;
                    }
                    if !contains(&x3, p) || !contains(&x4, p) {
                        continue;
                    }
                    return (seeds, p_seed);
                }
            }
        }
    }
    panic!("не нашлось четырёх кандидатов, при которых разрыв эпох возможен");
}

// --- каркас: четыре узла и ручная доставка ------------------------------------

struct Quad {
    nodes: BTreeMap<Addr, ShardNode>,
    seeds: BTreeMap<Addr, u8>,
    dirs: BTreeMap<Addr, PathBuf>,
}

impl Quad {
    fn open(tag: &str, seed_list: &[u8]) -> Quad {
        let params = testing::params(POW);
        let mut nodes = BTreeMap::new();
        let mut seeds = BTreeMap::new();
        let mut dirs = BTreeMap::new();
        for seed in seed_list {
            let d = dir(&format!("{tag}-{seed}"));
            let n = testing::node(&d, SHARD, *seed, params, seed_list);
            let a = n.me();
            seeds.insert(a, *seed);
            dirs.insert(a, d);
            nodes.insert(a, n);
        }
        // Genesis собирается здесь, а не через `testing::genesis_update`: тот берёт ВСЕХ
        // кандидатов (`ordered`), а валидатор §9.2 отвергает состав длиннее `R`. У четырёх
        // кандидатов genesis — это тройка, выбранная детерминированно.
        let (frame, _upd, _members) = genesis_frame(seed_list);
        let carrier = testing::identity(200).pubkey();
        for n in nodes.values_mut() {
            n.on_frame(carrier, &frame, testing::clock(0))
                .expect("genesis эпохи 1 принимается каждым узлом");
        }
        Quad { nodes, seeds, dirs }
    }

    fn addr(&self, seed: u8) -> Addr {
        *self
            .seeds
            .iter()
            .find(|(_, s)| **s == seed)
            .expect("сид принадлежит четвёрке")
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

    /// Доставить кадры и собрать ответы.
    fn route(&mut self, from: Addr, envs: &[Envelope], now: u32) -> Vec<Envelope> {
        let mut out = Vec::new();
        for e in envs {
            let kind = kind_of(e);
            let node = self
                .nodes
                .get_mut(&e.to)
                .unwrap_or_else(|| panic!("кадр {kind:?} адресован узлу, которого нет в четвёрке"));
            match node.on_frame(from, &e.frame, testing::clock(now)) {
                Ok(replies) => out.extend(replies),
                Err(err) => panic!("{kind:?} сломал узел: {err}"),
            }
        }
        out
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

fn errors(envs: &[Envelope]) -> Vec<ProtocolError> {
    envs.iter()
        .filter(|e| kind_of(e) == Kind::Error)
        .map(|e| ProtocolError::decode(&e.frame).expect("Error обязан разбираться"))
        .collect()
}

fn acks(envs: &[Envelope]) -> Vec<PublishAck> {
    envs.iter()
        .filter(|e| kind_of(e) == Kind::PublishAck)
        .map(|e| PublishAck::decode(&e.frame).expect("PublishAck обязан разбираться"))
        .collect()
}

/// Genesis эпохи 1: состав `R` из кандидатов, подписи bootstrap-авторитета (3 из 5, §15.2).
fn genesis_frame(seeds: &[u8]) -> (Vec<u8>, MembershipUpdate, Vec<Member>) {
    let params = testing::params(POW);
    let list = candidates::expected_update(1, SHARD, &testing::holders(seeds), params.r, 0, 0);
    let draft = membership::build_update(&list, Vec::new());
    let payload = draft.unsigned_body();
    let sigs: Vec<(u8, [u8; 64])> = testing::authorities()
        .iter()
        .take(3)
        .enumerate()
        .map(|(i, a)| (i as u8, a.sign_domain(domain::MEMBER, &payload)))
        .collect();
    let upd = membership::build_update(&list, sigs);
    (testing::signed_frame(&upd), upd, list.members)
}

/// Цепочка эпохи: детерминированный состав из живого ростера, подписи — по индексам
/// **предыдущей** эпизоды (§9.2).
fn chain_frame(
    epoch: u64,
    live: &[u8],
    prev: &[Member],
    signers: &[u8],
    generated_at: u32,
) -> (Vec<u8>, MembershipUpdate, Vec<Member>) {
    let params = testing::params(POW);
    let list = candidates::expected_update(
        epoch,
        SHARD,
        &testing::holders(live),
        params.r,
        ENTRIES,
        generated_at,
    );
    let draft = membership::build_update(&list, Vec::new());
    let sigs: Vec<(u8, [u8; 64])> = signers
        .iter()
        .map(|seed| {
            let id = testing::identity(*seed);
            let idx = prev
                .iter()
                .position(|m| m.owner_ed25519 == id.pubkey())
                .expect("подписант — участник предыдущей эпохи") as u8;
            (idx, id.sign_domain(domain::MEMBER, &draft.unsigned_body()))
        })
        .collect();
    let upd = membership::build_update(&list, sigs);
    (testing::signed_frame(&upd), upd, list.members)
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

/// `LeaveNotice` от `P`: подписан своим ключом, названная эпоха — та, что узел знает.
fn leave_frame(seed: u8, epoch: u64, owner: [u8; 32]) -> Vec<u8> {
    let notice = LeaveNotice {
        epoch,
        shard: SHARD,
        leaving_owner: owner,
        drain_deadline_bucket: 40,
    };
    let body = notice.body_bytes();
    let sig = testing::identity(seed).sign_body(domain::LEAVE, Kind::LeaveNotice, &body);
    notice.encode_signed(&sig)
}

// --- замер ---------------------------------------------------------------------

#[test]
fn epoch_gap_never_heals() {
    let (seed_list, p_seed) = choose_quad();
    let p = testing::identity(p_seed).pubkey();
    let x1 = composition(1, &seed_list);
    let x2 = composition(2, &seed_list);
    let x3 = composition(3, &seed_list);

    // Живые участники эпохи 1 (все, кроме замороженного `P`).
    let live1: Vec<u8> = seed_list
        .iter()
        .copied()
        .filter(|s| {
            *s != p_seed && contains(&x1, testing::identity(*s).pubkey())
        })
        .collect();
    assert_eq!(live1.len(), 2, "в составе эпохи 1 двое живых участников");
    // Подписанты эпохи 2: живые участники `X1 ∩ X2`.
    let signers2: Vec<u8> = live1
        .iter()
        .copied()
        .filter(|s| contains(&x2, testing::identity(*s).pubkey()))
        .collect();
    assert_eq!(signers2.len(), 2, "подписантов эпохи 2 должно быть двое");
    // Подписанты эпохи 3: те же живые участники — они уже держат эпоху 2.
    let signers3: Vec<u8> = signers2
        .iter()
        .copied()
        .filter(|s| contains(&x3, testing::identity(*s).pubkey()))
        .collect();
    assert_eq!(signers3.len(), 2, "подписантов эпохи 3 должно быть двое");

    let mut t = Quad::open("epoch-gap", &seed_list);
    let p_addr = t.addr(p_seed);
    let a_addr = t.addr(live1[0]);
    let b_addr = t.addr(live1[1]);

    // ---------- (0) база ----------
    {
        let agent = testing::identity(60);
        let frame = publish_frame(&agent, &testing::vector(20), 1, 1);
        let out = t
            .node_mut(p_addr)
            .on_frame(agent.pubkey(), &frame, testing::clock(1))
            .expect("Publish A");
        assert_eq!(out.len(), 2, "(0) primary рассылает операцию двум репликам: {out:?}");
        let ops: Vec<Envelope> = out
            .iter()
            .filter(|e| kind_of(e) == Kind::ReplicateOp)
            .cloned()
            .collect();
        assert_eq!(ops.len(), 2, "(0) оба кадра — ReplicateOp: {out:?}");
        // Кворум §9.4 считается по **разным** отправителям (`aw.acks.push(from)`), поэтому
        // ack-и реплик доставляются раздельно и с их настоящим отправителем: общий `from`
        // на пачке дал бы кворум из одного пира и не собрал бы W=2 (ДИАГНОЗ-2).
        let op_a = ops.iter().find(|e| e.to == a_addr).expect("операция к A").clone();
        let op_b = ops.iter().find(|e| e.to == b_addr).expect("операция к B").clone();
        let ack_a = t.route(p_addr, &[op_a], 1);
        let ack_b = t.route(p_addr, &[op_b], 1);
        let mut delivered = t.route(a_addr, &ack_a, 1);
        delivered.extend(t.route(b_addr, &ack_b, 1));
        let a = acks(&delivered);
        assert_eq!(a.len(), 1, "(0) кворум W=2 собран: {delivered:?}");
        assert_eq!(a[0].error_code, "OK", "(0) {a:?}");
        assert_eq!((a[0].epoch, a[0].seq), (1, 1), "(0) запись A в эпохе 1");
    }
    {
        let n = t.node(p_addr);
        assert_eq!(n.epoch(), Some(1), "(0) P на эпохе 1");
        assert!(n.is_primary(), "(0) P — primary эпохи 1");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary, l.expires_at_bucket)),
            Some((1, p_addr, 6)),
            "(0) lease P: эпоха 1, primary P, истекает на бакете 6"
        );
        assert_eq!(n.applied_seq(), 1, "(0) запись A применена у P");
        for addr in [a_addr, b_addr] {
            assert_eq!(t.node(addr).applied_seq(), 1, "(0) запись A применена у живых");
            assert_eq!(t.node(addr).epoch(), Some(1), "(0) живые на эпохе 1");
        }
    }

    // ---------- (1) P пропускает эпоху 2 ----------
    let (frame2, _upd2, members2) = chain_frame(2, &seed_list, &x1, &signers2, 2);
    for addr in [a_addr, b_addr] {
        let replies = t
            .node_mut(addr)
            .on_frame(a_addr, &frame2, testing::clock(2))
            .expect("цепочка эпохи 2 разбирается");
        assert!(errors(&replies).is_empty(), "(1) переход без Error: {replies:?}");
        assert_eq!(t.node(addr).epoch(), Some(2), "(1) живой принял эпоху 2");
    }
    {
        let n = t.node(p_addr);
        assert_eq!(n.epoch(), Some(1), "(1) P пропустил эпоху 2");
        assert_eq!(n.applied_seq(), 1, "(1) P не тронут");
    }
    for addr in [a_addr, b_addr] {
        assert!(
            !t.node(addr).is_unreachable(&p_addr),
            "(1) пропуск — заморозка, а не отказ транспорта: P не помечен недоступным"
        );
    }

    // ---------- (2) P пропускает эпоху 3, а слот зомби уже занят ----------
    let (frame3, upd3, members3) = chain_frame(3, &seed_list, &members2, &signers3, 3);
    for addr in [a_addr, b_addr] {
        let replies = t
            .node_mut(addr)
            .on_frame(a_addr, &frame3, testing::clock(3))
            .expect("цепочка эпохи 3 разбирается");
        assert!(errors(&replies).is_empty(), "(2) переход без Error: {replies:?}");
        assert_eq!(t.node(addr).epoch(), Some(3), "(2) живой принял эпоху 3");
    }
    assert_eq!(t.node(p_addr).epoch(), Some(1), "(2) P пропустил и эпоху 3");
    assert!(
        contains(&members3, p),
        "(2) P входит в состав эпохи 3: слот занят зомби, который его не обслужит"
    );

    // ---------- (3) разрыв отвергнут молча ----------
    {
        let chain = testing::chain(SHARD, POW);
        let (_frame, upd1, _members) = genesis_frame(&seed_list);
        let m1 = chain
            .validate(None, &upd1)
            .expect("genesis собирается");
        assert_eq!(
            chain.validate(Some(&m1), &upd3),
            Err(membership::MembershipError::EpochNotNext { got: 3, need: 2 }),
            "(3) причина отказа называется точно: цепочка не пропускает эпохи"
        );
    }
    let replies = t
        .node_mut(p_addr)
        .on_frame(a_addr, &frame3, testing::clock(20))
        .expect("цепочка эпохи 3 разбирается");
    assert!(replies.is_empty(), "(3) ни одного ответного кадра: {replies:?}");
    assert!(errors(&replies).is_empty(), "(3) ни одного Error: {replies:?}");
    {
        let n = t.node(p_addr);
        assert_eq!(n.epoch(), Some(1), "(3) эпоха P не изменилась");
        assert_eq!(n.applied_seq(), 1, "(3) WAL P не тронут");
        assert_eq!(
            n.lease.as_ref().map(|l| (l.epoch, l.primary)),
            Some((1, p_addr)),
            "(3) lease P прежний: эпоха 1"
        );
    }

    // ---------- (4) ловушка замыкается ----------
    let before: Vec<(Option<u64>, u64)> = t
        .nodes
        .values()
        .map(|n| (n.epoch(), n.applied_seq()))
        .collect();
    let draft = t
        .node_mut(p_addr)
        .propose_next(20)
        .expect("P предлагает свою следующую эпоху");
    assert_eq!(draft.len(), 2, "(4) черновик уходит двум участникам эпохи 1: {draft:?}");
    for e in &draft {
        let upd = MembershipUpdate::decode(&e.frame).expect("черновик разбирается");
        assert_eq!(upd.epoch, 2, "(4) P по своему счёту предлагает эпоху 2");
        assert!(e.to == a_addr || e.to == b_addr, "(4) адресат — живой участник");
    }
    // Отвечают два разных пира, поэтому и доставляются раздельно: общий `from` на пачке
    // означал бы, что ответили оба, и адресатом был бы не тот, кто отвечал (ДИАГНОЗ-2).
    let draft_a = draft.iter().find(|e| e.to == a_addr).expect("черновик к A").clone();
    let draft_b = draft.iter().find(|e| e.to == b_addr).expect("черновик к B").clone();
    let answer_a = t.route(p_addr, &[draft_a], 20);
    let answer_b = t.route(p_addr, &[draft_b], 20);
    assert_eq!(answer_a.len(), 1, "(4) живой A отвечает текущей цепочкой: {answer_a:?}");
    assert_eq!(answer_b.len(), 1, "(4) живой B отвечает текущей цепочкой: {answer_b:?}");
    for e in [&answer_a[0], &answer_b[0]] {
        assert_eq!(kind_of(e), Kind::MembershipUpdate, "(4) ответ — MembershipUpdate");
        assert_eq!(e.to, p_addr, "(4) ответ адресован P");
        let sent = MembershipUpdate::decode(&e.frame).expect("ответ разбирается");
        assert_eq!(sent.epoch, 3, "(4) живой отдал текущую цепочку (ADR-0017)");
    }
    let mut back = t.route(a_addr, &answer_a, 20);
    back.extend(t.route(b_addr, &answer_b, 20));
    assert!(back.is_empty(), "(4) P отбросил цепочку молча: {back:?}");
    assert!(errors(&back).is_empty(), "(4) ни одного Error: {back:?}");
    let after: Vec<(Option<u64>, u64)> = t
        .nodes
        .values()
        .map(|n| (n.epoch(), n.applied_seq()))
        .collect();
    assert_eq!(before, after, "(4) круг ничего не изменил: ни эпох, ни WAL");

    // ---------- (5) дверь в данные закрыта ----------
    {
        let n = t.node(p_addr);
        assert!(n.is_primary(), "(5) P по-прежнему primary своей эпохи 1");
        assert!(!n.lease_active(20), "(5) lease истёк");
        assert_eq!(n.serving_epoch(20), None, "(5) писать нечем");
    }
    let agent_b = testing::identity(61);
    let frame_b = publish_frame(&agent_b, &testing::vector(30), 1, 20);
    let out = t
        .node_mut(p_addr)
        .on_frame(agent_b.pubkey(), &frame_b, testing::clock(20))
        .expect("Publish разбирается");
    let errs = errors(&out);
    assert_eq!(errs.len(), 1, "(5) ровно один отказ: {out:?}");
    assert_eq!(errs[0].code, err_code::EPOCH_STALE, "(5) {errs:?}");
    assert!(acks(&out).is_empty(), "(5) OK не выдан");
    assert_eq!(t.node(p_addr).applied_seq(), 1, "(5) WAL не тронут");

    // ---------- (6) heal не лечит разрыв ----------
    let healed = t
        .node_mut(a_addr)
        .peer_alive(p_addr)
        .expect("handshake с P завершён");
    assert_eq!(healed.len(), 1, "(6) peer_alive отдаёт текущую цепочку: {healed:?}");
    assert_eq!(kind_of(&healed[0]), Kind::MembershipUpdate, "(6) kind");
    let sent = MembershipUpdate::decode(&healed[0].frame).expect("цепочка разбирается");
    assert_eq!(sent.epoch, 3, "(6) это эпоха 3, а не недостающая эпоха 2");
    let back = t.route(a_addr, &healed, 20);
    assert!(back.is_empty(), "(6) P отбросил её молча: {back:?}");
    assert_eq!(t.node(p_addr).epoch(), Some(1), "(6) эпоха P не изменилась");

    // ---------- (7) уйти нельзя ----------
    {
        // Уход с собственной эпохой узла — единственная, которую он знает.
        let leave = leave_frame(p_seed, 1, p);
        let replies = t
            .node_mut(a_addr)
            .on_frame(p_addr, &leave, testing::clock(4))
            .expect("LeaveNotice разбирается");
        assert!(replies.is_empty(), "(7) уход с эпохой 1 отвергнут молча: {replies:?}");
        // Наблюдение: P остаётся в составе следующей эпохи.
        let draft4 = t
            .node_mut(a_addr)
            .propose_next(4)
            .expect("живой предлагает следующую эпоху");
        assert_eq!(draft4.len(), 2, "(7) черновик эпохи 4 уходит двум участникам: {draft4:?}");
        let upd4 = MembershipUpdate::decode(&draft4[0].frame).expect("черновик разбирается");
        assert_eq!(upd4.epoch, 4, "(7) это эпоха 4");
        assert_eq!(upd4.members.len(), R, "(7) состав эпохи 4 — тройка: {upd4:?}");
        assert!(
            contains(&upd4.members, p),
            "(7) P остался в составе эпохи 4: уход с эпохой 1 не принят"
        );
    }
    {
        // Тот же уход, названный эпохой 3: принимается. Значит причина — поле `epoch`.
        let leave = leave_frame(p_seed, 3, p);
        let replies = t
            .node_mut(a_addr)
            .on_frame(p_addr, &leave, testing::clock(4))
            .expect("LeaveNotice разбирается");
        assert!(errors(&replies).is_empty(), "(7) принятый уход не отвечает ошибкой: {replies:?}");
        let draft4 = t
            .node_mut(a_addr)
            .propose_next(4)
            .expect("живой предлагает следующую эпоху");
        let upd4 = MembershipUpdate::decode(&draft4[0].frame).expect("черновик разбирается");
        assert_eq!(upd4.epoch, 4, "(7) это эпоха 4");
        assert!(
            !contains(&upd4.members, p),
            "(7) с эпохой 3 уход принят и P исключён из состава эпохи 4: {upd4:?}"
        );
    }

    // ---------- (8) рестарт не лечит ----------
    {
        let files: Vec<String> = std::fs::read_dir(t.dir_of(p_addr).clone())
            .expect("каталог P читается")
            .map(|e| e.expect("запись каталога").file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("membership."))
            .collect();
        assert_eq!(
            files,
            vec!["membership.00000000000000000001.log".to_string()],
            "(8) на диске P только принятая эпизода: {files:?}"
        );
        t.nodes.remove(&p_addr);
        let params = testing::params(POW);
        let n = testing::node(&t.dir_of(p_addr).clone(), SHARD, p_seed, params, &seed_list);
        assert_eq!(n.epoch(), Some(1), "(8) после рестарта цепочка — эпоха 1");
        assert!(n.is_member(), "(8) P — участник своей эпохи 1 и после рестарта");
        t.nodes.insert(p_addr, n);
    }

    // ---------- (9) холодный старт в середине цепочки невозможен ----------
    {
        let chain = testing::chain(SHARD, POW);
        assert_eq!(
            chain.validate(None, &upd3),
            Err(membership::MembershipError::NotGenesis { got: 3, need: 1 }),
            "(9) без предыдущей эпизоды принимается только genesis"
        );
    }

    t.clean();
}
