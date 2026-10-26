//! H-0124 / E-0124 (ADR-0065): подписанный грант lease переживает рестарт primary.
//!
//! Три ветки, одна из которых — контроль:
//! * primary с целым `lease.bin` после reopen обслуживает **ту же** эпоху и принимает `Publish`
//!   без смены эпизоды (`LR_PRIMARY_SERVING`, `LR_PRIMARY_PUBLISH_OK`, `LR_EPOCH_UNCHANGED`);
//! * primary без гранта (файл удалён) отказывает ровно `EPOCH_STALE` — прежний контракт жив и
//!   правка не превратила «права нет» в «право есть» (`LR_PRE_REFUSAL`);
//! * посадки — грант с чужой эпохой, с битой подписью и с истёкшим сроком — не поднимаются, и
//!   «не поднялась» проверяется в той же директории честным кадром: иначе нулевой результат
//!   означал бы «прибор ничего не умеет», а не «отказ случился» (`LR_PLANT_REJECTED`);
//! * реплика после reopen гранта не имеет и не имеет файла: ей lease нужен только на агентском
//!   пути записи, который отсекается `NOT_OWNER` (`LR_REPLICA_NO_LEASE`, `LR_REPLICA_PUBLISH_NOT_OWNER`).
//!
//! Факты печатаются до `assert`, потому что PRE_FIX этого цикла измеряется тем же прибором на
//! дереве до правки: красное прогон обязан пережить и назвать число, а не упасть на первом
//! предположении.
//!
//! Контракт «рестарт без гранта» целиком (эпоха 2, heal, GC) остаётся в `restart_recovery.rs`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_index::testing::{dir, remove};
use vecdht_node::lease::Lease;
use vecdht_node::net::{Addr, Envelope};
use vecdht_node::{ShardNode, candidates, testing};
use vecdht_wire::frame::{Kind, decode_frame};
use vecdht_wire::messages::{Codec, ProtocolError, PublishAck, err_code};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const POW: u32 = 8;
const TTL: u16 = 225;
const LEASE_FILE: &str = "lease.bin";

fn choose_roles() -> (Vec<u8>, u8) {
    for a in 1u8..=16 {
        for b in a + 1..=16 {
            for c in b + 1..=16 {
                let seeds = vec![a, b, c];
                let holders = testing::holders(&seeds);
                let p_key = candidates::ordered(1, SHARD, &holders)[0].owner_ed25519;
                let owners: Vec<[u8; 32]> = holders.iter().map(|h| h.owner_ed25519).collect();
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
        Trio { nodes, seeds, seed_list, dirs, p_seed }
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

    fn lease_path(&self, addr: Addr) -> PathBuf {
        self.dirs.get(&addr).expect("каталог узла").join(LEASE_FILE)
    }

    /// Сбросить узел и поднять его заново из того же каталога — ровно то, что делает
    /// перезапуск процесса с тем же `--dir`.
    fn restart(&mut self, seed: u8) {
        let a = self.addr(seed);
        self.nodes.remove(&a);
        let d = self.dirs.get(&a).expect("каталог узла").clone();
        let n = testing::node(&d, SHARD, seed, testing::params(POW), &self.seed_list);
        assert!(n.epoch().is_some(), "членство обязано подняться с диска");
        self.nodes.insert(a, n);
    }

    fn close_all(self) {
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

fn cluster_of(vec_seed: u8) -> u16 {
    CLUSTER + (vec_seed as u16 % 8)
}

fn publish_frame(agent_seed: u8, vec_seed: u8, epoch: u64, bucket: u32, ttl: u16) -> Vec<u8> {
    let agent = testing::identity(agent_seed);
    testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(vec_seed),
        cluster_id: cluster_of(vec_seed),
        shard: SHARD,
        epoch,
        published_bucket: bucket,
        ttl_buckets: ttl,
        bits: POW,
    }
    .frame()
}

/// Один кадр `Publish` без ожиданий: возвращает всё, что ответил узел.
fn publish_raw(t: &mut Trio, to: Addr, agent_seed: u8, vec_seed: u8, epoch: u64, bucket: u32) -> Vec<Envelope> {
    let agent = testing::identity(agent_seed);
    let frame = publish_frame(agent_seed, vec_seed, epoch, bucket, TTL);
    t.node_mut(to)
        .on_frame(agent.pubkey(), &frame, testing::clock(bucket))
        .expect("узел не обязан ломаться на Publish")
}

/// Полный путь §9.4: опсы, acks реплик, `PublishAck` после `w`.
///
/// Паниковать здесь нельзя: на дереве до правки этот же прибор исполняет PRE_FIX, и отказ
/// без права писать обязан превратиться в `0` в факте, а не в обрыв прогона.
fn publish(t: &mut Trio, to: Addr, agent_seed: u8, vec_seed: u8, epoch: u64, bucket: u32) -> Vec<PublishAck> {
    let ops = publish_raw(t, to, agent_seed, vec_seed, epoch, bucket);
    if !ops.iter().all(|e| kind_of(e) == Kind::ReplicateOp) {
        return Vec::new();
    }
    let mut replica_acks = Vec::new();
    for e in &ops {
        let replies = match t.node_mut(e.to).on_frame(to, &e.frame, testing::clock(bucket)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let Some(first) = replies.first() else { return Vec::new() };
        replica_acks.push((e.to, first.clone()));
    }
    let mut out = Vec::new();
    for (from, ack) in replica_acks {
        let replies = match t.node_mut(to).on_frame(from, &ack.frame, testing::clock(bucket)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        out.extend(acks(&replies));
    }
    out
}

/// Кадр гранта, подписанный настоящим primary, но с другим полем — одна из трёх посадок.
fn signed_grant(t: &Trio, seed: u8, epoch: u64, expires: u32) -> Vec<u8> {
    let n = t.node(t.addr(seed));
    let id = testing::identity(seed);
    Lease { epoch, primary: id.pubkey(), expires_at_bucket: expires }
        .signed_frame(n.shard, &id, n.dht_peer_id.clone())
}

fn first_grant_frame(envs: &[Envelope]) -> Vec<u8> {
    envs
        .iter()
        .find(|e| kind_of(e) == Kind::LeaseGrant)
        .expect("tick primary обязан дать LeaseGrant")
        .frame
        .clone()
}

// --- замер --------------------------------------------------------------------

#[test]
fn primary_grant_survives_restart() {
    let mut t = Trio::new("lease-restart-ok");
    let p_seed = t.p_seed;
    let p = t.addr(p_seed);

    // Продление эпохи 1: тик primary на бакете 4 выдаёт грант с `expires` 10 и пишет его.
    let grants = t.node_mut(p).tick(4).expect("tick primary");
    let frame = first_grant_frame(&grants);
    for e in &grants {
        t.node_mut(e.to)
            .on_frame(p, &e.frame, testing::clock(4))
            .expect("реплика принимает грант");
    }

    let path = t.lease_path(p);
    let file_present = path.exists();
    let file_eq_frame = file_present
        && std::fs::read(&path).map(|b| b == frame).unwrap_or(false);
    eprintln!("LR_LEASE_FILE={}", file_present as i32);
    eprintln!("LR_FILE_EQ_FRAME={}", file_eq_frame as i32);

    // (A) Рестарт БЕЗ гранта: прежний контракт обязан остаться живым — отказ и ровно `EPOCH_STALE`.
    let _ = std::fs::remove_file(&path);
    t.restart(p_seed);
    let refused = publish_raw(&mut t, p, 63, 40, 1, 5);
    let refusal = errors(&refused).first().map(|e| e.code.clone());
    eprintln!(
        "LR_PRE_REFUSAL={}",
        match &refusal {
            Some(c) if c == err_code::EPOCH_STALE => "EPOCH_STALE".to_string(),
            Some(c) => c.clone(),
            None => "NONE".to_string(),
        }
    );
    eprintln!("LR_NO_GRANT_SERVING={}", t.node(p).serving_epoch(5).is_some() as i32);

    // (B) Рестарт С грантом: та же директория, тот же кадр — то же право писать на той же эпохе.
    std::fs::write(&path, &frame).expect("грант записан");
    t.restart(p_seed);
    let epoch_after = t.node(p).epoch() == Some(1);
    let serving = t.node(p).serving_epoch(5) == Some(1);
    eprintln!("LR_EPOCH_UNCHANGED={}", epoch_after as i32);
    eprintln!("LR_PRIMARY_SERVING={}", serving as i32);
    let ack = publish(&mut t, p, 63, 40, 1, 5);
    let ok = ack.len() == 1
        && ack[0].error_code.as_str() == "OK"
        && ack[0].epoch == 1;
    eprintln!("LR_PRIMARY_PUBLISH_OK={}", ok as i32);

    assert!(file_present, "primary обязан положить подписанный грант в каталог шарда");
    assert!(file_eq_frame, "`lease.bin` обязан совпадать с кадром, ушедшим по проводу");
    assert_eq!(
        refusal.as_deref(),
        Some(err_code::EPOCH_STALE),
        "без гранта — прежний отказ, а не молчаливое право"
    );
    assert!(epoch_after, "эпоха после рестарта обязана остаться принятой");
    assert!(serving, "действующий грант обязан вернуть право обслуживать ту же эпоху");
    assert!(ok, "публикация после рестарта обязана пройти без смены эпизоды: {ack:?}");
    t.close_all();
}

#[test]
fn planted_grants_are_not_restored() {
    let mut t = Trio::new("lease-plants");
    let p_seed = t.p_seed;
    let p = t.addr(p_seed);
    let grants = t.node_mut(p).tick(4).expect("tick primary");
    let honest = first_grant_frame(&grants);
    let path = t.lease_path(p);

    // «будущая» эпизода, которой нет в принятой цепочке; битая подпись; истёкший срок.
    let plants: Vec<(&str, Vec<u8>)> = vec![
        ("EPOCH_FUTURE", signed_grant(&t, p_seed, 2, 10)),
        (
            "BAD_SIGNATURE",
            {
                let mut tampered = honest.clone();
                let off = 8 + 2 + 8; // заголовок + shard(u16) + epoch(u64) -> primary_ed25519
                tampered[off..off + 32].copy_from_slice(&[0x99; 32]);
                tampered
            },
        ),
        ("EXPIRED", signed_grant(&t, p_seed, 1, 0)),
    ];

    let mut rejected = 0usize;
    for (name, bytes) in &plants {
        std::fs::write(&path, bytes).expect("посадка записана");
        t.restart(p_seed);
        let refused = t.node(p).serving_epoch(5).is_none();
        // «Не поднялась» обязана означать «грант отвергнут», а не «прибор молчит»: в той же
        // директории честный кадр обязан поднять обслуживание.
        std::fs::write(&path, &honest).expect("честный кадр записан");
        t.restart(p_seed);
        let honest_works = t.node(p).serving_epoch(5) == Some(1);
        eprintln!("LR_PLANT_{name}={}", i32::from(refused && honest_works));
        if refused && honest_works {
            rejected += 1;
        }
    }
    eprintln!("LR_PLANT_REJECTED={rejected}");
    // Истёкший грант — отдельный факт: он обязан не обслуживать по часам проводника, а не
    // только потому, что не прошёл проверку при открытии.
    std::fs::write(&path, signed_grant(&t, p_seed, 1, 0)).expect("посадка записана");
    t.restart(p_seed);
    eprintln!(
        "LR_EXPIRED_GRANT_NOT_SERVING={}",
        i32::from(t.node(p).serving_epoch(5).is_none())
    );
    assert_eq!(rejected, plants.len(), "ни одна из посадок не обязана возвращать право писать");
    t.close_all();
}

#[test]
fn replica_without_grant_refuses_write() {
    let mut t = Trio::new("lease-replica");
    let p_seed = t.p_seed;
    let p = t.addr(p_seed);
    let r_seed = *t.seed_list.iter().find(|s| **s != p_seed).expect("репликант есть");
    let r = t.addr(r_seed);
    let grants = t.node_mut(p).tick(4).expect("tick primary");
    for e in &grants {
        t.node_mut(e.to)
            .on_frame(p, &e.frame, testing::clock(4))
            .expect("реплика принимает грант");
    }

    t.restart(r_seed);
    let no_lease = t.node(r).lease.is_none();
    let no_file = !t.lease_path(r).exists();
    eprintln!("LR_REPLICA_NO_LEASE={}", i32::from(no_lease && no_file));
    let refused = publish_raw(&mut t, r, 64, 41, 1, 5);
    let not_owner = errors(&refused).first().map(|e| e.code.clone()) == Some(err_code::NOT_OWNER.to_string());
    eprintln!("LR_REPLICA_PUBLISH_NOT_OWNER={}", i32::from(not_owner));

    assert!(no_lease, "реплике грант не нужен, и после reopen его быть не должно");
    assert!(no_file, "реплика не обязана писать `lease.bin`: грант персистит только primary");
    assert!(not_owner, "запись у реплики отсекается до проверки эпохи: {:?}", errors(&refused));
    t.close_all();
}
