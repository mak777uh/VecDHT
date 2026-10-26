//! A2: продуктовый `node run` грузит центроиды и пересчитывает присваивание (§7.3).
//!
//! Оракул держит обе стороны настоящими: узлы — процессы `vecdht-cli node run`, клиент —
//! `vecdht_net::Agent` из того же крейта, что и `agent publish|find`. Артефакт, кредашиалы и
//! genesis выпускает CLI-церемония (`artifact init`, `cert issue`, `genesis build`), как в A1.
//!
//! Два утверждения:
//! 1. **отказ вместо fail-open**: артефакт без `centroid.bin` останавливает старт кодом 2, и
//!    текст называет файл. Молчаливый старт без центроидов означал бы, что узел принимает
//!    `cluster_id` издателя, а выглядит работающим;
//! 2. **пересчёт на живом узле**: честная публикация не считается пересборкой
//!    (`cluster_reassigned=0`), а публикация с подделанным `cluster_id` того же шарда
//!    принимается, но запись находится `Find`'ом по **пересчитанному** кластеру,
//!    `cluster_reassigned` растёт, `cluster_unverified` остаётся нулём. Оба счётчика видны в
//!    `NODE_STATUS` — иначе снаружи не отличить пересчёт от доверия подсказке.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use libp2p::Multiaddr;
use vecdht_artifact::Artifact;
use vecdht_cli::Outcome;
use vecdht_crypto::sig::Identity;
use vecdht_net::{keys, Agent, AgentConfig, FindQuery, FoundMatch, NetworkParams, PublishReceipt, PublishRequest};
use vecdht_wire::codec::DIM;
use vecdht_wire::constants::CLUSTERS_PER_SHARD;
use vecdht_wire::messages::{Codec, MembershipUpdate};

/// Временный каталог с гардом: прогон не должен оставлять мусор в `%TEMP%`.
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "vecdht-cli-centroids-{tag}-{}",
            std::process::id()
        ));
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

fn cli(args: &[&str]) -> Outcome {
    vecdht_cli::run(args)
}

fn ok(args: &[&str]) -> Outcome {
    let out = cli(args);
    assert_eq!(
        out.code, 0,
        "команда {args:?} вернула код {}: {}",
        out.code, out.stderr
    );
    out
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

const DEV_SEED: [u8; 32] = [7u8; 32];
const MEMBER_SEEDS: [[u8; 32]; 2] = [[31u8; 32], [32u8; 32]];
const HONEST_SEED: [u8; 32] = [41u8; 32];
const FORGER_SEED: [u8; 32] = [43u8; 32];
const SEEKER_SEED: [u8; 32] = [42u8; 32];

struct Fixture {
    artifact: PathBuf,
    certs: [PathBuf; 2],
    genesis: PathBuf,
    update: MembershipUpdate,
}

/// Церемония целиком через CLI: артефакт dev-режима, два кредашиала, genesis шарда 0.
fn fixture(root: &Path) -> Fixture {
    let artifact = root.join("artifact");
    let dev_seed = hex::encode(DEV_SEED);
    ok(&[
        "artifact", "init",
        "--out", &s(&artifact),
        "--seed", &dev_seed,
        "--dev-keys", "1",
    ]);

    let mut certs: Vec<PathBuf> = Vec::new();
    let mut member_lines = String::new();
    for (i, seed) in MEMBER_SEEDS.iter().enumerate() {
        let id = Identity::from_seed(*seed);
        let owner = hex::encode(id.pubkey());
        let peer = hex::encode(keys::peer_id(&id).to_bytes());
        let cert = root.join(format!("cert-{i}.bin"));
        let nonce = hex::encode([0x10u8 + i as u8; 16]);
        ok(&[
            "cert", "issue",
            "--artifact", &s(&artifact),
            "--out", &s(&cert),
            "--owner", &owner,
            "--peer-id", &peer,
            "--shard", "0",
            "--capacity", "100000",
            "--valid-from", "0",
            "--valid-until", "4102444800",
            "--nonce", &nonce,
            "--dev-keys", "1",
            "--seed", &dev_seed,
        ]);
        member_lines.push_str(&format!("{owner} {peer} 100000\n"));
        certs.push(cert);
    }
    let certs: [PathBuf; 2] = certs.try_into().expect("два члена — два кредашиала");
    let members = root.join("members.txt");
    std::fs::write(&members, member_lines).unwrap();
    let genesis = root.join("genesis.bin");
    ok(&[
        "genesis", "build",
        "--artifact", &s(&artifact),
        "--out", &s(&genesis),
        "--members", &s(&members),
        "--shard", "0",
        "--generated-at", "0",
        "--dev-keys", "1",
        "--seed", &dev_seed,
    ]);
    let update = MembershipUpdate::decode(&std::fs::read(&genesis).unwrap())
        .expect("genesis build пишет кадр MembershipUpdate с подписью кадра");
    Fixture { artifact, certs, genesis, update }
}

fn seed_of(owner: [u8; 32]) -> [u8; 32] {
    MEMBER_SEEDS
        .iter()
        .copied()
        .find(|seed| Identity::from_seed(*seed).pubkey() == owner)
        .expect("член genesis собран из известного seed")
}

fn cert_of(f: &Fixture, seed: [u8; 32]) -> &Path {
    let i = MEMBER_SEEDS
        .iter()
        .position(|s| *s == seed)
        .expect("seed члена известен");
    &f.certs[i]
}

fn copy_artifact(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
}

#[derive(Debug, Default, Clone)]
struct Status {
    fields: BTreeMap<String, String>,
}

impl Status {
    fn parse(line: &str) -> Self {
        let mut fields = BTreeMap::new();
        for pair in line.split_whitespace().skip(2) {
            if let Some((k, v)) = pair.split_once('=') {
                fields.insert(k.to_string(), v.to_string());
            }
        }
        Self { fields }
    }

    fn num(&self, key: &str) -> u64 {
        self.fields
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("в NODE_STATUS нет {key}: {:?}", self.fields))
    }
}

struct NodeProc {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl NodeProc {
    fn start(args: &[String]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vecdht-cli"))
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("node run запускается");
        let stdout = child.stdout.take().expect("stdout читается");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }

    /// Ждём `NODE_READY` и берём адрес из него: до этой строки узел не объявил себя работающим.
    fn wait_ready(&mut self) -> Multiaddr {
        loop {
            match self.lines.recv_timeout(Duration::from_secs(60)) {
                Ok(line) if line.starts_with("NODE_READY ") => {
                    let pair = line
                        .split_whitespace()
                        .find(|p| p.starts_with("listen="))
                        .expect("NODE_READY печатает listen=");
                    let first = pair
                        .trim_start_matches("listen=")
                        .split(',')
                        .next()
                        .expect("минимум один адрес");
                    return first.parse().expect("адрес из NODE_READY — Multiaddr");
                }
                Ok(line) => println!("node: {line}"),
                Err(e) => panic!("узел не объявил NODE_READY: {e}"),
            }
        }
    }

    /// Ближайший `NODE_STATUS`, удовлетворяющий предикату. Строки статуса идут раз в секунду,
    /// поэтому ожидание ограничено, а не «первая попавшаяся».
    fn status_until(&mut self, pred: impl Fn(&Status) -> bool, timeout: Duration) -> Status {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.starts_with("NODE_STATUS ") => {
                    let st = Status::parse(&line);
                    println!("status: {line}");
                    if pred(&st) {
                        return st;
                    }
                }
                Ok(line) => println!("node: {line}"),
                Err(e) => panic!("статус не дождались за {timeout:?}: {e}"),
            }
        }
    }
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn node_args(
    artifact: &Path,
    dir: &Path,
    seed: [u8; 32],
    cert: &Path,
    genesis: &Path,
    bootstrap: &[Multiaddr],
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "node".into(),
        "run".into(),
        "--artifact".into(),
        s(artifact),
        "--dir".into(),
        s(dir),
        "--shard".into(),
        "0".into(),
        "--seed".into(),
        hex::encode(seed),
        "--cert".into(),
        s(cert),
        "--genesis".into(),
        s(genesis),
        "--listen".into(),
        "/ip4/127.0.0.1/udp/0/quic-v1".into(),
        "--status-sec".into(),
        "1".into(),
        "--run-seconds".into(),
        "90".into(),
    ];
    for addr in bootstrap {
        args.push("--bootstrap".into());
        args.push(addr.to_string());
    }
    args
}

fn try_publish(
    seed: [u8; 32],
    network: &NetworkParams,
    addr: Multiaddr,
    vec_q: [i8; DIM],
    cluster_id: u16,
    ttl: u16,
    preprocessing: u16,
) -> Result<PublishReceipt, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut agent = Agent::new(
            Identity::from_seed(seed),
            network.clone(),
            AgentConfig {
                bootstrap: vec![addr],
                call_timeout: Duration::from_secs(15),
                ..AgentConfig::default()
            },
        )
        .map_err(|e| format!("агент-издатель: {e}"))?;
        agent
            .publish(&PublishRequest::new(vec_q, cluster_id, ttl, preprocessing))
            .await
            .map_err(|e| format!("публикация не дошла до кворума: {e}"))
    })
}

/// Публикация с ограниченными повторами **подготовки**: предмет теста — пересчёт присваивания,
/// а не устойчивость рукопожатия после `NODE_READY`. Повторяется только неудачная отправка;
/// успешная квитанция не повторяется, поэтому счётчики пересборки от повторов не растут.
fn publish_as(
    seed: [u8; 32],
    network: &NetworkParams,
    addr: Multiaddr,
    vec_q: [i8; DIM],
    cluster_id: u16,
    ttl: u16,
    preprocessing: u16,
) -> PublishReceipt {
    let mut last = String::new();
    for attempt in 1..=3u8 {
        match try_publish(seed, network, addr.clone(), vec_q, cluster_id, ttl, preprocessing) {
            Ok(r) => return r,
            Err(e) => {
                eprintln!("publish attempt {attempt}: {e}");
                last = e;
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    panic!("публикация через живой узел CLI не удалась за три попытки: {last}");
}

fn try_find(
    network: &NetworkParams,
    addr: Multiaddr,
    vec_q: [i8; DIM],
    cluster: u16,
) -> Result<Vec<FoundMatch>, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut agent = Agent::new(
            Identity::from_seed(SEEKER_SEED),
            network.clone(),
            AgentConfig {
                bootstrap: vec![addr],
                call_timeout: Duration::from_secs(15),
                ..AgentConfig::default()
            },
        )
        .map_err(|e| format!("агент-искатель: {e}"))?;
        let outcome = agent
            .find(&FindQuery::new(vec_q, vec![cluster], 5))
            .await
            .map_err(|e| format!("поиск не дошёл: {e}"))?;
        if !outcome.failures.is_empty() {
            return Err(format!("отказы шардов: {:?}", outcome.failures));
        }
        Ok(outcome.matches)
    })
}

/// Поиск с теми же ограниченными повторами подготовки: отказ шарда на первом шаге после
/// `NODE_READY` — свойство расписания рукопожатия, а не клетки, в которой лежит запись.
fn find(
    network: &NetworkParams,
    addr: Multiaddr,
    vec_q: [i8; DIM],
    cluster: u16,
) -> Vec<FoundMatch> {
    let mut last = String::new();
    for attempt in 1..=3u8 {
        match try_find(network, addr.clone(), vec_q, cluster) {
            Ok(m) => return m,
            Err(e) => {
                eprintln!("find attempt {attempt}: {e}");
                last = e;
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    panic!("поиск через живой узел CLI не удался за три попытки: {last}");
}

/// Вектор и его честный кластер **в шарде 0**: нужен, чтобы подделка оставалась в том же шарде
/// (иначе отказ был бы `SHARD_MISMATCH`, а не пересборкой).
fn honest_vector(a: &Artifact) -> ([i8; DIM], u16) {
    for k in 0..CLUSTERS_PER_SHARD {
        let v = *a.centroids.row(k);
        let honest = a.centroids.assign(&v);
        if honest < CLUSTERS_PER_SHARD {
            return (v, honest);
        }
    }
    panic!("ни один центроид первых {CLUSTERS_PER_SHARD} строк не присваивается в шард 0");
}

/// (1) Артефакт без `centroid.bin` — отказ старта, а не fail-open.
#[test]
fn node_run_refuses_artifact_without_centroids() {
    let tmp = Tmp::new("no-centroid");
    let f = fixture(&tmp.0);
    let broken = tmp.0.join("artifact-no-centroid");
    copy_artifact(&f.artifact, &broken);
    std::fs::remove_file(broken.join("centroid.bin")).expect("centroid.bin скопирован");
    assert!(
        !broken.join("centroid.bin").exists(),
        "фикстура без файла: иначе тест мерил бы не отказ"
    );
    let dir = tmp.0.join("node-no-centroid");
    let args = node_args(&broken, &dir, MEMBER_SEEDS[0], &f.certs[0], &f.genesis, &[]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = cli(&refs);
    assert_ne!(
        out.code, 0,
        "узел без centroid.bin обязан отказать, а не принять подсказку издателя: {}",
        out.stderr
    );
    assert!(
        out.stderr.contains("centroid.bin"),
        "ошибка обязана назвать файл, а не «что-то не так»: {}",
        out.stderr
    );
    assert!(
        !dir.exists(),
        "отказ до старта не создаёт каталог узла: {}",
        dir.display()
    );
    eprintln!("CT_MISSING_CODE={}", out.code);
    eprintln!("CT_MISSING_NAMED=1");
}

/// (2) Живой узел CLI пересчитывает присваивание: честная публикация — не пересборка,
/// подделанный `cluster_id` — пересборка с клеткой по `vec_q`, а не по подсказке.
#[test]
fn forged_cluster_id_is_reassigned_by_live_cli_node() {
    let tmp = Tmp::new("forged");
    let f = fixture(&tmp.0);
    let a = Artifact::load(&f.artifact).unwrap();
    let network = NetworkParams::from_artifact(&a).expect("параметры сети из артефакта");
    let (vec_q, honest) = honest_vector(&a);
    let claimed = honest ^ 1;
    assert_ne!(claimed, honest, "подделка обязана отличаться от пересчёта");
    assert_eq!(claimed / CLUSTERS_PER_SHARD, honest / CLUSTERS_PER_SHARD, "подделка в том же шарде 0");

    let primary_idx = usize::from(f.update.primary_idx);
    let primary_owner = f.update.members[primary_idx].owner_ed25519;
    let replica_owner = f.update.members[1 - primary_idx].owner_ed25519;
    let primary_seed = seed_of(primary_owner);
    let replica_seed = seed_of(replica_owner);
    let primary_cert = cert_of(&f, primary_seed);
    let replica_cert = cert_of(&f, replica_seed);

    let primary_dir = tmp.0.join("node-primary");
    let replica_dir = tmp.0.join("node-replica");
    let mut primary = NodeProc::start(&node_args(
        &f.artifact,
        &primary_dir,
        primary_seed,
        primary_cert,
        &f.genesis,
        &[],
    ));
    let primary_addr = primary.wait_ready();
    let mut replica = NodeProc::start(&node_args(
        &f.artifact,
        &replica_dir,
        replica_seed,
        replica_cert,
        &f.genesis,
        std::slice::from_ref(&primary_addr),
    ));
    let _replica_addr = replica.wait_ready();
    // W=2: публикация сразу после NODE_READY могла бы не застать второго держателя.
    std::thread::sleep(Duration::from_secs(3));

    let receipt = publish_as(
        HONEST_SEED,
        &network,
        primary_addr.clone(),
        vec_q,
        honest,
        network.ttl_default_buckets,
        network.preprocessing_version,
    );
    assert_eq!(receipt.shard, 0, "честная публикация — шард 0");
    let st = primary.status_until(
        |s| s.fields.contains_key("cluster_reassigned"),
        Duration::from_secs(30),
    );
    assert!(
        st.fields.contains_key("cluster_unverified"),
        "NODE_STATUS обязан печатать оба счётчика: {:?}",
        st.fields
    );
    assert_eq!(
        st.num("cluster_reassigned"),
        0,
        "пересчёт совпал с подсказкой — это не пересборка"
    );

    let forged = publish_as(
        FORGER_SEED,
        &network,
        primary_addr.clone(),
        vec_q,
        claimed,
        network.ttl_default_buckets,
        network.preprocessing_version,
    );
    assert_eq!(forged.shard, 0, "подделка принята в шарде 0");
    let st = primary.status_until(
        |s| s.num("cluster_reassigned") >= 1,
        Duration::from_secs(30),
    );
    assert_eq!(
        st.num("cluster_unverified"),
        0,
        "с центроидами нет ни одного непроверенного кадра"
    );

    let found = find(&network, primary_addr, vec_q, honest);
    let forger = Identity::from_seed(FORGER_SEED).pubkey();
    assert!(
        found
            .iter()
            .any(|m| m.owner_ed25519 == forger && m.slot == forged.slot && m.cluster_id == honest),
        "подделанная запись обязана лежать в пересчитанном кластере {honest}, а не в {claimed}: \
         {found:?}"
    );

    eprintln!("CT_HONEST_REASSIGNED=0");
    eprintln!("CT_FORGED_REASSIGNED_GE1=1");
    eprintln!("CT_FORGED_UNVERIFIED_ZERO=1");
    eprintln!("CT_FORGED_CELL_HONEST=1");
    eprintln!("CT_STATUS_CLUSTER_FIELDS=1");
}
