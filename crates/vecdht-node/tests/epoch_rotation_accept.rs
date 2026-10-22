//! Оракул H-0050/E-0050: ротация эпохи и живучесть приёма прежнего издателя (§12.3 хвост
//! «доживают TTL у целей», проверенный на рестарте того же узла в `E-0046`, но не на смене
//! эпизоды). Килл primary → живые выборы (как в гейте P4) → эпоха 2, новый издатель.
//! Порог (4) измерительный и без assert'а: поведение find-пути реплики печатается в лог.

use std::path::PathBuf;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::LocalNet;
use vecdht_node::{Addr, Envelope, ShardNode, Spend, rendezvous, testing};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const LATENCY: u64 = 1;

struct Swarm {
    net: LocalNet,
    dirs: Vec<PathBuf>,
}

fn swarm(tag: &str) -> Swarm {
    let p = testing::params(POW);
    let mut net = LocalNet::new(LATENCY);
    let mut dirs = Vec::new();
    for seed in SEEDS {
        let d = dir(&format!("{tag}-{seed}"));
        dirs.push(d.clone());
        net.add(testing::node(&d, SHARD, seed, p, &SEEDS));
    }
    let frame = testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0));
    let carrier = testing::identity(9).pubkey();
    for addr in net.addrs() {
        let replies = net
            .node_mut(&addr)
            .unwrap()
            .on_frame(carrier, &frame, testing::clock(0))
            .expect("genesis");
        for env in replies {
            net.send(addr, env.to, env.frame);
        }
    }
    assert!(net.settle(30), "после genesis сеть обязана замолчать: {:?}", net.errors);
    Swarm { net, dirs }
}

impl Swarm {
    fn primary(&self) -> Addr {
        let v: Vec<Addr> = self
            .net
            .addrs()
            .into_iter()
            .filter(|a| self.net.node(a).map(|n| n.is_primary()).unwrap_or(false))
            .collect();
        assert_eq!(v.len(), 1, "primary обязан быть ровно один");
        v[0]
    }
    fn epoch(&self, addr: &Addr) -> Option<u64> {
        self.net.node(addr).and_then(|n| n.epoch())
    }
    fn clean(self) {
        for d in &self.dirs {
            remove(d);
        }
    }
}

fn publish_attempt(net: &mut LocalNet, agent: &vecdht_crypto::Identity, v: &[i8; 384]) {
    let bucket = net.now_bucket();
    for addr in net.addrs() {
        let epoch = match net.node(&addr).and_then(|n| n.epoch()) {
            Some(e) if e > 0 => e,
            _ => continue,
        };
        let frame = testing::PublishSpec {
            agent,
            vec_q: v,
            cluster_id: CLUSTER,
            shard: SHARD,
            epoch,
            published_bucket: bucket,
            ttl_buckets: 225,
            bits: POW,
        }
        .frame();
        net.send(agent.pubkey(), addr, frame);
    }
}

fn take_publish_ack(net: &mut LocalNet, agent: &vecdht_crypto::Identity) -> bool {
    let mut got = false;
    for (_, frame) in net.take(&agent.pubkey()) {
        if decode_frame(&frame).map(|f| f.header.kind) == Ok(Kind::PublishAck) {
            got = true;
        }
    }
    got
}

fn find_replies(node: &mut ShardNode, agent: &vecdht_crypto::Identity, bucket: u32, qid: u64) -> Vec<Envelope> {
    node.on_frame(
        agent.pubkey(),
        &testing::find_frame(agent, &testing::vector(5), &[CLUSTER], 8, qid),
        testing::clock(bucket),
    )
    .expect("find")
}

fn match_result_opt(replies: &[Envelope]) -> Option<MatchResult> {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
}

fn match_result(replies: &[Envelope]) -> MatchResult {
    match_result_opt(replies).expect("фальсификатор (б): MatchResult отсутствует")
}

fn accepts(replies: &[Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("accept")))
        .collect()
}

#[test]
fn pre_epoch_accept_spends_after_rotation_and_new_primary_issues_fresh() {
    let mut s = swarm("epoch-rotation-accept");
    let owner = testing::identity(90);
    let seeker = testing::identity(88);
    let v = testing::vector(5);

    // Честная запись через кворум (как гейт P4), чтобы выжившие держали находку.
    s.net.take(&owner.pubkey());
    let mut acked = false;
    for _ in 0..20 {
        publish_attempt(&mut s.net, &owner, &v);
        s.net.step(1);
        if take_publish_ack(&mut s.net, &owner) {
            acked = true;
            break;
        }
    }
    assert!(acked, "запись в эпоху 1 обязана подтвердиться до килла");

    let old = s.primary();
    let old_me = s.net.node(&old).unwrap().me();
    let old_epoch = s.epoch(&old).expect("эпоха 1");

    // Приём от прежнего primary в его таблице.
    let b0 = s.net.now_bucket();
    let r0 = find_replies(s.net.node_mut(&old).unwrap(), &seeker, b0, 201);
    let f0 = accepts(&r0);
    assert_eq!(match_result(&r0).matches.len(), 1, "фальсификатор (б): находка видна");
    assert_eq!(f0.len(), 1, "одна находка — один приём прежнего издателя");
    assert_eq!(f0[0].1.issued_bucket, b0, "приём помечен текущим бакетом");

    // Ротация: kill → выборы.
    s.net.kill(&old);
    for _ in 0..30 {
        s.net.step(1);
        if s.net.addrs().iter().any(|a| *a != old && s.net.node(a).map(|n| n.is_primary()).unwrap_or(false)) {
            break;
        }
    }
    let candidates_left: Vec<Addr> = s.net.addrs().into_iter().filter(|a| *a != old).collect();
    let new = *candidates_left
        .iter()
        .find(|a| s.net.node(a).map(|n| n.is_primary()).unwrap_or(false))
        .expect("фальсификатор (д): за 30 с выборов нового primary не было");
    assert_eq!(s.epoch(&new), Some(old_epoch + 1), "переход ровно на +1 эпизоду");

    // Порог (1): довоенный приём расходуется после ротации — подпись издателя, не его роль.
    let b1 = s.net.now_bucket();
    let mut spend = Spend::new(300);
    let grant = spend
        .consume(&f0[0].0, &old_me, &owner.pubkey(), b1)
        .expect("фальсификатор (а): расход приёма прежнего издателя упал после ротации");
    assert_eq!((grant.seeker, grant.shard), (seeker.pubkey(), SHARD));
    assert_eq!(
        spend.consume(&f0[0].0, &old_me, &owner.pubkey(), b1),
        Err(rendezvous::AcceptError::AlreadySpent),
        "одноразовость переживает ротацию"
    );

    // Порог (2)+(3): новый primary находит запись и выдаёт СВОЙ приём; его таблица была пуста.
    assert_eq!(s.net.node(&new).unwrap().rendezvous.live(), 0, "фальсификатор (в): новая таблица не унаследована");
    let r1 = find_replies(s.net.node_mut(&new).unwrap(), &seeker, b1, 202);
    assert_eq!(match_result(&r1).matches.len(), 1, "реплицированная находка видна новому primary");
    let f1 = accepts(&r1);
    assert_eq!(f1.len(), 1, "порог (2): новый издатель выпустил приём");
    assert_ne!(f1[0].0, f0[0].0, "порог (2): кадр подписан новым издателем — байты разошлись");
    assert_eq!(s.net.node(&new).unwrap().rendezvous.live(), 1, "фальсификатор (в): live новой таблицы == 1");
    let grant1 = spend
        .consume(&f1[0].0, &s.net.node(&new).unwrap().me(), &owner.pubkey(), b1)
        .expect("порог (3): приём нового издателя расходован");
    assert_eq!(grant1.seeker, seeker.pubkey());

    // Порог (4), измерительный без assert'а: find-путь реплики (не-primary) после ротации.
    let rep = *candidates_left.iter().find(|a| **a != new).expect("выжившая реплика");
    let rr = find_replies(s.net.node_mut(&rep).unwrap(), &seeker, b1, 203);
    eprintln!(
        "## порог (4): реплика после ротации: находок {}, приёмов {}, ошибок {} — поведение \
         печатается, порогом не является ##",
        match_result_opt(&rr).map_or(0, |m| m.matches.len()),
        accepts(&rr).len(),
        rr.iter()
            .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::Error))
            .count()
    );
    eprintln!("## пороги (1)…(3): довоенный приём расходован и одноразов, новый издатель выпустил свой, таблица не унаследована ##");
    s.clean();
}
