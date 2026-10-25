//! Роль kad: индексный узел без шарда обязан быть сервером DHT.
//!
//! `ADR-0060`: до правки `is_server` вычислялся как «у меня есть шард». Наблюдатель и узел
//! между назначениями шардов не имеют, поэтому libp2p-kad переводил их в `Mode::Client`, а
//! клиент отвечает `DeniedUpgrade` на входящий `ADD_PROVIDER` и перестаёт быть хранилищем
//! провайдер-записей. Здесь это проверяется на трёх узлах и одном ребре-мосте:
//!
//! ```text
//!   B (провайдер шарда 0) ──► A (индексный, без шарда) ◄── C (наблюдатель)
//! ```
//!
//! A — единственный мост. Если A сервер, он принимает `ADD_PROVIDER` от B и отдаёт запись C.
//! Если A клиент, C не находит провайдера: маршрута к B у него нет, а A запись не хранит.
//!
//! Факт провала: `KADROLE_FOUND=0`. Факт успеха: `KADROLE_FOUND=1` и `KADROLE_MS` в бюджете.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use tokio::sync::{mpsc, oneshot};

use vecdht_artifact::reference_manifest;
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::{testing, Clock, ShardNode};
use vecdht_wire::messages::Role;

const A_SEED: u8 = 30;
const B_SEED: u8 = 31;
const C_SEED: u8 = 32;
const POW_BITS: u32 = 8;

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn cfg() -> NetConfig {
    NetConfig {
        listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "kadrole".into(),
        request_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
        revoked_dir: None,
    }
}

struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("vecdht-kadrole-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Spec {
    seed: u8,
    shard: Option<u16>,
    seeds: Vec<u8>,
    dir: PathBuf,
}

fn build(spec: &Spec) -> NetService {
    let id = testing::identity(spec.seed);
    let peer = keys::peer_id(&id);
    let nodes = match spec.shard {
        Some(sh) => {
            let mut node = ShardNode::open(
                &spec.dir,
                sh,
                id.clone(),
                peer.to_bytes(),
                testing::params(POW_BITS),
                testing::authority_set(),
                testing::holders(&spec.seeds),
            )
            .unwrap();
            let b = Clock::at(now_sec()).bucket;
            node.on_frame(
                testing::identity(9).pubkey(),
                &testing::signed_frame(&testing::genesis_update(sh, &spec.seeds, 0)),
                testing::clock(b),
            )
            .unwrap();
            vec![node]
        }
        None => Vec::new(),
    };
    let cert = testing::node_cert(
        spec.seed,
        peer.to_bytes(),
        spec.shard.map(|s| vec![s]).unwrap_or_default(),
        Role::IndexNode,
        0,
        u32::MAX,
    );
    NetService::new(id, Role::IndexNode, Some(cert), nodes, testing::authority_set(), cfg()).unwrap()
}

struct Report {
    auth: usize,
    kad: usize,
    ann: u64,
}

enum Cmd {
    Dial(Multiaddr),
    Report(oneshot::Sender<Report>),
    Resolve(u16, Duration, oneshot::Sender<Option<u128>>),
}

struct Node {
    tx: mpsc::UnboundedSender<Cmd>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Node {
    fn drop(&mut self) {
        let (dead, _) = mpsc::unbounded_channel();
        let _ = std::mem::replace(&mut self.tx, dead);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn spawn_node(spec: Spec, addr_tx: oneshot::Sender<Multiaddr>) -> Node {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let join = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let mut svc = build(&spec);
            loop {
                if let Some(a) = svc.listen_addrs().first() {
                    let _ = addr_tx.send(a.clone());
                    break;
                }
                svc.step().await;
            }
            loop {
                match rx.try_recv() {
                    Ok(Cmd::Dial(a)) => {
                        let _ = svc.dial(a);
                    }
                    Ok(Cmd::Report(t)) => {
                        let _ = t.send(Report {
                            auth: svc.authenticated_peers().len(),
                            kad: svc.kad_peer_count(),
                            ann: svc.provider_announcements,
                        });
                    }
                    Ok(Cmd::Resolve(sh, budget, t)) => {
                        let t0 = Instant::now();
                        let _ = svc.find_providers(sh);
                        let deadline = t0 + budget;
                        let mut ms = None;
                        while Instant::now() < deadline {
                            svc.step().await;
                            if !svc.provider_peers(sh).is_empty() {
                                ms = Some(t0.elapsed().as_millis());
                                break;
                            }
                        }
                        let _ = t.send(ms);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {}
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
                svc.step().await;
            }
        });
    });
    Node { tx, join: Some(join) }
}

async fn report(n: &Node) -> Report {
    let (tx, rx) = oneshot::channel();
    n.tx.send(Cmd::Report(tx)).unwrap();
    rx.await.unwrap()
}

async fn resolve(n: &Node, shard: u16, budget: Duration) -> Option<u128> {
    let (tx, rx) = oneshot::channel();
    n.tx.send(Cmd::Resolve(shard, budget, tx)).unwrap();
    rx.await.unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn index_node_without_shard_serves_the_dht() {
    let root = Tmp::new();
    let specs = [
        Spec { seed: A_SEED, shard: None, seeds: Vec::new(), dir: root.0.join("a") },
        Spec { seed: B_SEED, shard: Some(0), seeds: vec![B_SEED], dir: root.0.join("b") },
        Spec { seed: C_SEED, shard: None, seeds: Vec::new(), dir: root.0.join("c") },
    ];
    let mut nodes = Vec::new();
    let mut addrs = Vec::new();
    for s in specs {
        std::fs::create_dir_all(&s.dir).unwrap();
        let (tx, rx) = oneshot::channel();
        nodes.push(spawn_node(s, tx));
        addrs.push(rx.await.unwrap());
    }
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);

    // B и C знают только A: мост единственный, обходного ребра нет.
    let _ = b.tx.send(Cmd::Dial(addrs[0].clone()));
    let _ = c.tx.send(Cmd::Dial(addrs[0].clone()));

    // Ждём обе двери (не дольше 15 с) и один тик реанонса после RoutingUpdated.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut settled = false;
    while Instant::now() < deadline {
        let (ra, rb, rc) = (report(a).await, report(b).await, report(c).await);
        if rb.auth >= 1 && rc.auth >= 1 && ra.auth >= 2 && rb.ann >= 1 {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let ra = report(a).await;
    let rb = report(b).await;
    let rc = report(c).await;
    assert!(settled, "двери не сошлись за 15 с: A={:?} B={:?} C={:?}", (ra.auth, ra.kad), (rb.auth, rb.ann), rc.auth);

    let found = resolve(c, 0, Duration::from_secs(3)).await;

    println!(
        "## KADROLE_A_AUTH={} KADROLE_A_KAD={} KADROLE_B_AUTH={} KADROLE_B_ANN={} \
KADROLE_C_AUTH={} KADROLE_FOUND={} KADROLE_MS={} ##",
        ra.auth,
        ra.kad,
        rb.auth,
        rb.ann,
        rc.auth,
        u8::from(found.is_some()),
        found.unwrap_or(u128::MAX),
    );

    assert!(found.is_some(), "C не нашёл провайдера шарда 0 через A: индексный узел без шарда не хранит записи");
    assert!(found.unwrap() < 3_000, "резолв через A занял {} мс", found.unwrap());
}
