//! `GcTick` §9.6 на живом шарде: TTL освобождает вместимость, а не только меняет выдачу.
//!
//! §11.3 обещает, что `SHARD_FULL` — состояние до истечения TTL, а не навсегда. Это обещание
//! держится ровно на одном: primary обязан выпустить `GcTick`-фрейм, реплики — применить его на
//! том же `seq` и с тем же `bucket`, и `store.len()` обязан уменьшиться у всех. Тест смотрит
//! именно на это, а не на `search`: запись, которую никто не ищет, всё равно занимает слот.
//!
//! Второе утверждение — «GC по нужде, а не каждый бакет»: пустой `GcTick` на TTL-плато растил бы
//! WAL от одного времени и сбивал бы барьер снапшота (§10.3). Поэтому `gc_ticks` обязан вырасти
//! ровно на один при реальной экспирации и не вырасти на следующем бакете.
//!
//! Шард 7 и кластер 112 — как в гейтах P4: ноль скрыл бы ошибку маршрута (§7.4).

use std::path::PathBuf;

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::LocalNet;
use vecdht_node::{testing, Addr, Envelope, Params};
use vecdht_wire::codec::DIM;
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{err_code, Codec, OpKind, ProtocolError, PublishAck, ReplicateOp};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const LATENCY: u64 = 1;
const TIME_BUCKET_SEC: u64 = vecdht_wire::TIME_BUCKET_SEC as u64;

struct Swarm {
    net: LocalNet,
    dirs: Vec<PathBuf>,
}

/// Три держателя шарда и genesis эпохи 1. `max_live_per_shard = 1` — чтобы «освободить
/// вместимость» означало «после GC в шард снова можно писать», а не «счётчик уменьшился».
fn swarm(tag: &str) -> Swarm {
    let mut p: Params = testing::params(POW);
    p.max_live_per_shard = 1;
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
    assert!(net.errors.is_empty(), "ошибки диспетчера: {:?}", net.errors);
    Swarm { net, dirs }
}

impl Swarm {
    fn clean(self) {
        for d in &self.dirs {
            remove(d);
        }
    }

    fn primary(&self) -> Addr {
        let v: Vec<Addr> = self
            .net
            .addrs()
            .into_iter()
            .filter(|a| self.net.node(a).map(|n| n.is_primary()).unwrap_or(false))
            .collect();
        assert_eq!(v.len(), 1, "primary обязан быть ровно один, а их {}", v.len());
        v[0]
    }

    /// Пройти до границы бакета и дать сети улечься. `tick` сам вызывается `LocalNet` на каждой
    /// границе, поэтому `step` — это и есть «прошло 16 секунд протокольного времени».
    fn step_to(&mut self, bucket: u32) {
        let target = bucket as u64 * TIME_BUCKET_SEC;
        assert!(target >= self.net.now_sec(), "время в тесте не идёт назад");
        self.net.step(target - self.net.now_sec());
        assert_eq!(self.net.now_bucket(), bucket);
        assert!(self.net.settle(30), "сеть обязана улечься в бакете {bucket}: {:?}", self.net.errors);
        assert!(self.net.errors.is_empty(), "ошибки диспетчера: {:?}", self.net.errors);
    }
}

fn kind_of(frame: &[u8]) -> Kind {
    decode_frame(frame).expect("агент обязан получать разбираемые кадры").header.kind
}

/// Одна публикация всем держателям и ожидание ответа primary: `PublishAck` при успехе либо
/// `Error{SHARD_FULL}` при полном шарде. Реплики ответят `NOT_OWNER` — это фон, не исход.
fn probe(
    net: &mut LocalNet,
    agent: &Identity,
    v: &[i8; DIM],
    ttl_buckets: u16,
    bits: u32,
) -> (Option<PublishAck>, Vec<ProtocolError>) {
    net.take(&agent.pubkey());
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
            ttl_buckets,
            bits,
        }
        .frame();
        net.send(agent.pubkey(), addr, frame);
    }
    let mut ack = None;
    let mut errors = Vec::new();
    for _ in 0..8 {
        net.step(1);
        for (_, frame) in net.take(&agent.pubkey()) {
            match kind_of(&frame) {
                Kind::PublishAck => ack = PublishAck::decode(&frame).ok(),
                Kind::Error => {
                    if let Ok(e) = ProtocolError::decode(&frame) {
                        errors.push(e);
                    }
                }
                _ => {}
            }
        }
        if ack.is_some() || errors.iter().any(|e| e.code == err_code::SHARD_FULL) {
            break;
        }
    }
    (ack, errors)
}

/// Сколько `ReplicateOp` с конкретным op-видом узел вернул: `TimeMark` и `GcTick` ходят одним
/// видом кадра, и «просто ReplicateOp» не отличил бы GC от очередного отметчика времени.
fn replicated(replies: &[Envelope], kind: OpKind) -> usize {
    replies
        .iter()
        .filter_map(|e| ReplicateOp::decode(&e.frame).ok())
        .filter(|op| op.op_kind == kind)
        .count()
}

#[test]
fn ttl_expiry_frees_a_full_shard_for_everyone_and_gc_is_demand_driven() {
    let mut s = swarm("gc-free");
    let short = testing::identity(77);
    let newcomer = testing::identity(78);

    // A дороже новичка на бит и живёт два бакета: в полном шарде он защищён от вытеснения
    // (§11.3.3), поэтому B обязан получить `SHARD_FULL` — пока TTL не истёк.
    let (a_ack, _) = probe(&mut s.net, &short, &testing::vector(1), 2, POW + 1);
    assert_eq!(a_ack.expect("A обязан быть подтверждён").error_code, "OK");
    for a in s.net.addrs() {
        assert_eq!(s.net.node(&a).unwrap().store.len(), 1, "A доехал до реплики");
    }

    let (b_ack, b_errs) = probe(&mut s.net, &newcomer, &testing::vector(2), 225, POW);
    assert!(b_ack.is_none(), "полный шард не может подтвердить дешёвого новичка");
    assert!(
        b_errs.iter().any(|e| e.code == err_code::SHARD_FULL),
        "отказ обязан быть SHARD_FULL, а не тихим drop: {b_errs:?}"
    );

    // Бакет 1: TTL ещё жив (deadline = 0 + 2), GC нечего делать. Пустой фрейм не пишется.
    s.step_to(1);
    for a in s.net.addrs() {
        let n = s.net.node(&a).unwrap();
        assert_eq!(n.store.len(), 1);
        assert_eq!(n.gc_ticks, 0, "GcTick без истёкших записей — это рост WAL от времени");
    }

    // Бакет 2: deadline ≤ now. Primary выпускает ровно один GcTick и реплицирует его; все
    // применяют тот же bucket, поэтому «у кого часы врут» не существует как класс.
    s.step_to(2);
    let addrs = s.net.addrs();
    let primary = s.primary();
    for a in &addrs {
        let n = s.net.node(a).unwrap();
        assert_eq!(n.store.len(), 0, "истёкшая запись освободила слот у каждого держателя");
        assert!(n.store.index.owner_slot(&short.pubkey()).is_none());
        assert!(n.store.time_mark_bucket >= 2, "GcTick обязан сдвинуть «сейчас» вперёд");
        // `gc_ticks` — счётчик *выпущенных* фреймов: реплика применяет чужой GcTick и обязана
        // остаться нулевой, иначе «GC пишет только primary» перестало бы быть проверяемым.
        let expected = if *a == primary { 1 } else { 0 };
        assert_eq!(n.gc_ticks, expected, "GcTick выпускает только primary, узел {a:?}");
    }
    let seq_after_gc = s.net.node(&primary).unwrap().applied_seq();
    assert!(
        addrs.iter().all(|a| s.net.node(a).unwrap().applied_seq() == seq_after_gc),
        "реплики обязаны сойтись на GcTick, а не применить его выборочно"
    );

    // Вместимость реальна: тот же B, который получил SHARD_FULL, теперь проходит без вытеснения.
    let (b_ack, b_errs) = probe(&mut s.net, &newcomer, &testing::vector(2), 225, POW);
    assert_eq!(b_ack.expect("после GC шард не полон").error_code, "OK", "{b_errs:?}");
    s.net.step(2);
    assert!(s.net.settle(30));
    for a in &addrs {
        let n = s.net.node(a).unwrap();
        assert_eq!(n.store.len(), 1, "B обязан доехать до всех реплик");
        assert!(n.store.index.owner_slot(&newcomer.pubkey()).is_some());
    }

    // Бакет 3: жив только B (deadline 227) — новых GcTick быть не должно.
    s.step_to(3);
    for a in &addrs {
        let n = s.net.node(a).unwrap();
        if *a == primary {
            assert_eq!(n.gc_ticks, 1, "GC пишется по нужде, а не по расписанию бакета");
        }
        assert_eq!(n.store.len(), 1);
    }
    s.clean();
}

/// `GcTick` — не только локальная экспирация: фрейм обязан уехать репликам, иначе после handoff
/// новый primary вернул бы истёкшие записи из своего индекса. Проверяем, что `tick` primary
/// возвращает ровно `R-1` реплик для GcTick-фрейма.
#[test]
fn primary_replicates_the_gc_tick_to_every_peer() {
    let mut s = swarm("gc-repl");
    let agent = testing::identity(79);
    let (ack, _) = probe(&mut s.net, &agent, &testing::vector(3), 1, POW);
    assert_eq!(ack.expect("публикация").error_code, "OK");

    let primary = s.primary();
    let peers = s.net.node(&primary).unwrap().peers();
    // Бакет 1 — deadline первой записи (0 + 1).
    let replies = s.net.node_mut(&primary).unwrap().tick(1).expect("tick primary");
    assert_eq!(replicated(&replies, OpKind::GcTick), peers.len(), "GcTick уходит каждому пиру шарда");
    let gc: Vec<&Envelope> = replies
        .iter()
        .filter(|e| ReplicateOp::decode(&e.frame).map(|op| op.op_kind == OpKind::GcTick).unwrap_or(false))
        .collect();
    assert_eq!(gc.len(), peers.len());
    for env in &gc {
        assert!(peers.contains(&env.to), "GcTick адресован только членам шарда");
    }
    // Ручной `tick` не проходит через `LocalNet::tick`, поэтому кадры отправляем сами — так тест
    // проверяет именно содержимое ответа узла, а не диспетчер сети.
    for env in replies {
        s.net.send(primary, env.to, env.frame);
    }
    // Реплики не пишут GC сами: у них нет lease, и их tick обязан молчать.
    for p in peers {
        let replies = s.net.node_mut(&p).unwrap().tick(1).expect("tick реплики");
        assert_eq!(replicated(&replies, OpKind::GcTick), 0, "GC — прерогатива primary, а не каждого узла");
    }
    s.net.step(1);
    assert!(s.net.settle(30));
    assert!(s.net.errors.is_empty(), "{:?}", s.net.errors);
    for a in s.net.addrs() {
        assert_eq!(s.net.node(&a).unwrap().store.len(), 0, "истёкшая запись снята у всех");
    }
    s.clean();
}
