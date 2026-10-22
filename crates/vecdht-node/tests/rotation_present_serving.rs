//! Оракул H-0054/E-0054: путь обслуживания `ADR-0013` поверх ротации эпохи (`E-0050`).
//!
//! `E-0050` мерил живучесть приёма «голым» `Spend::consume`, `E-0051` мерил
//! `session::serve_request` в одной эпохе. Строка §12.3 «проверяются по подписи издателя,
//! а не по его текущей таблице» ни разу не мерилась через живой вход цели (`serve_request`)
//! на смене эпизоды, и не мерилась с списком издателей, в котором прежний издатель уже не
//! числится. Здесь: довоенный приём предъявляется через `present`, расход живёт в RAM цели,
//! новый издатель выдаёт свой кадр, а маска ошибки (`NotSignedByShardHolder` вместо
//! `AlreadySpent`) фиксируется как измеренное поведение.

use std::path::PathBuf;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::LocalNet;
use vecdht_node::{Addr, Envelope, ShardNode, Spend, rendezvous, session, testing};
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

fn match_result(replies: &[Envelope]) -> MatchResult {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
        .expect("фальсификатор (д): MatchResult отсутствует")
}

fn accepts(replies: &[Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("accept")))
        .collect()
}

fn holder_list(seeds: &[u8]) -> Vec<Addr> {
    seeds.iter().map(|s| testing::identity(*s).pubkey()).collect()
}

#[test]
fn serving_path_survives_rotation_and_error_masking_is_deterministic() {
    let mut s = swarm("rotation-present-serving");
    let owner = testing::identity(90);
    let seeker = testing::identity(88);
    let me_owner = owner.pubkey();
    let v = testing::vector(5);

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
    let issuers_all = holder_list(&SEEDS);

    let b0 = s.net.now_bucket();
    let r0 = find_replies(s.net.node_mut(&old).unwrap(), &seeker, b0, 301);
    let f0 = accepts(&r0);
    assert_eq!(match_result(&r0).matches.len(), 1, "фальсификатор (д): находка не видна прежнему primary");
    assert_eq!(f0.len(), 1, "одна находка — один приём прежнего издателя");
    let slot0 = f0[0].1.slot;

    // Порог (1): довоенное предъявление обслуживается через serve_request.
    let req0 = session::encode_request_present(301, me_owner, slot0, &f0[0].0);
    let mut spend = Spend::new(300);
    let grant = session::serve_request(&req0, &me_owner, &issuers_all, b0, &mut spend)
        .expect("фальсификатор (а): корректное предъявление не обслужено до ротации");
    assert_eq!(
        (grant.seeker, grant.shard, grant.slot, grant.issuer),
        (seeker.pubkey(), SHARD, slot0, old_me),
        "порог (1): grant связан с живым кадром прежнего издателя"
    );
    assert_eq!(
        session::serve_request(&req0, &me_owner, &issuers_all, b0, &mut spend),
        Err(session::TextError::Spend(rendezvous::AcceptError::AlreadySpent)),
        "фальсификатор (б): повтор предъявления обслужен"
    );

    // Ротация: kill → живые выборы.
    s.net.kill(&old);
    for _ in 0..30 {
        s.net.step(1);
        if s.net.addrs().iter().any(|a| *a != old && s.net.node(a).map(|n| n.is_primary()).unwrap_or(false)) {
            break;
        }
    }
    let left: Vec<Addr> = s.net.addrs().into_iter().filter(|a| *a != old).collect();
    let new = *left
        .iter()
        .find(|a| s.net.node(a).map(|n| n.is_primary()).unwrap_or(false))
        .expect("фальсификатор (е): за 30 с выборов нового primary не было");
    assert_eq!(s.epoch(&new), Some(old_epoch + 1), "переход ровно на +1 эпизоду");
    let issuers_new = holder_list(&[
        SEEDS[0],
        SEEDS[1],
        SEEDS[2],
    ])
    .into_iter()
    .filter(|a| *a != old_me)
    .collect::<Vec<_>>();
    assert!(!issuers_new.is_empty(), "выжившие держатели после килла");

    let b1 = s.net.now_bucket();

    // Порог (2): тот же довоенный кадр после ротации — тот же отказ, а не «истёк» и не Ok.
    let req0b = session::encode_request_present(302, me_owner, slot0, &f0[0].0);
    assert_eq!(
        session::serve_request(&req0b, &me_owner, &issuers_all, b1, &mut spend),
        Err(session::TextError::Spend(rendezvous::AcceptError::AlreadySpent)),
        "порог (2): одноразовость пути обслуживания переживает ротацию (новый query_id не помогает)"
    );

    // Порог (3): свежая запись расхода (рестарт цели) после ротации — довоенный приём снова Ok.
    let mut spend_fresh = Spend::new(300);
    let grant3 = session::serve_request(&req0b, &me_owner, &issuers_all, b1, &mut spend_fresh)
        .expect("фальсификатор (в): приём умер вместе с издателем, а должен жить по подписи");
    assert_eq!(grant3.issuer, old_me, "порог (3): издатель в grant — прежний, мёртвый узел");
    assert_eq!(grant3.seeker, seeker.pubkey());

    // Порог (4): маска ошибки — прежний издатель вне списка держателей.
    assert_eq!(
        session::serve_request(&req0b, &me_owner, &issuers_new, b1, &mut Spend::new(300)),
        Err(session::TextError::NotSignedByShardHolder),
        "фальсификатор (г): кадр мёртвого издателя обслуживается без него в списке"
    );

    // Порог (5): новый издатель — свой кадр, обслуженный по списку выживших.
    let r1 = find_replies(s.net.node_mut(&new).unwrap(), &seeker, b1, 303);
    let f1 = accepts(&r1);
    assert_eq!(match_result(&r1).matches.len(), 1, "фальсификатор (д): реплицированная находка не видна новому primary");
    assert_eq!(f1.len(), 1, "порог (5): новый primary выпустил приём");
    assert_ne!(f1[0].0, f0[0].0, "порог (5): байты разошлись — другой издатель");
    let new_me = s.net.node(&new).unwrap().me();
    let req1 = session::encode_request_present(303, me_owner, f1[0].1.slot, &f1[0].0);
    let grant5 = session::serve_request(&req1, &me_owner, &issuers_new, b1, &mut Spend::new(300))
        .expect("фальсификатор (д): предъявление нового издателя не обслужено");
    assert_eq!(
        (grant5.issuer, grant5.seeker, grant5.shard),
        (new_me, seeker.pubkey(), SHARD),
        "порог (5): grant подписан связкой нового издателя"
    );

    eprintln!(
        "## пороги (1)…(5): предъявление обслуживается до ротации и остаётся одноразовым после \
         неё (новый query_id не помогает), свежая запись расхода после ротации снова обслуживает \
         довоенный кадр (issuer в grant — мёртвый узел), прежний издатель вне списка даёт \
         NotSignedByShardHolder (маска AlreadySpent), кадр нового primary обслужен по списку \
         выживших; live новой таблицы {} ##",
        s.net.node(&new).unwrap().rendezvous.live()
    );
    s.clean();
}
