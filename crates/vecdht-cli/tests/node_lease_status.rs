//! A1c / E-0124 (ADR-0065): грант lease, пережитый рестартом, — не только в модели узлов, но и
//! в процессе, собранном из файлов церемонии.
//!
//! Оракул держит обе стороны настоящими: узел — процесс `vecdht-cli node run`, агент —
//! `vecdht_net::Agent` (§12). Тест продолжает `node_run.rs`: там после рестарта проверялось
//! чтение (индекс с диска), здесь — право писать той же эпохи без смены эпизоды.
//!
//! Три утверждения и одно ограничение:
//! 1. `NODE_STATUS` restarting-узла печатает `lease=` и `serving_epoch=` — «стою без гранта»
//!    отличимо от «обслуживаю эпоху E» снаружи, а не только в тестах крейта;
//! 2. после `drop` + старт с тем же `--dir` узел обслуживает **ту же** эпоху 1 и принимает
//!    `Publish` с `OK` — без перехода к эпохе 2;
//! 3. реплика поднимается без гранта (ей он не персистится) и не мешает кворуму `w=2`.
//!
//! Ограничение, которое здесь не измеряется: окно — `lease_buckets` (90 с), а не бессрочное
//! право; если за время простоя кластер принял новую эпоху, восстановленный грант не даст
//! писать (fencing по эпохе, ADR-0016). Эта ветка — `lease_after_restart.rs` в крейте узлов.
//!
//! Факты печатаются до проверок: PRE_FIX исполняется этим же файлом на дереве до правки и обязан
//! назвать нули, а не оборвать прогон паникой.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use libp2p::Multiaddr;
use vecdht_artifact::Artifact;
use vecdht_cli::Outcome;
use vecdht_crypto::sig::Identity;
use vecdht_net::{keys, Agent, AgentConfig, NetworkParams, PublishRequest};
use vecdht_wire::codec::DIM;
use vecdht_wire::messages::{MembershipUpdate, Codec};

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "vecdht-cli-node-lease-{tag}-{}",
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

fn ok(args: &[&str]) -> Outcome {
    let out = vecdht_cli::run(args);
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
const PUBLISHER_SEED: [u8; 32] = [41u8; 32];

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
    ok(&["artifact", "init", "--out", &s(&artifact), "--seed", &dev_seed, "--dev-keys", "1"]);

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

    /// Ближайший `NODE_STATUS`, в котором поле `key` вообще печатается, — или `None` по таймауту.
    /// Строки идут раз в 2 с, поэтому нераспознанные печатаются дозированно: лог прогона обязан
    /// оставаться читаемым.
    fn wait_status_field(&mut self, key: &str, secs: u64) -> Option<String> {
        self.collect(|l| status_field(l, key).is_some(), secs)
    }

    /// Ближайший `NODE_STATUS`, где поле `key` равно `want`.
    fn wait_status_eq(&mut self, key: &str, want: &str, secs: u64) -> Option<String> {
        self.collect(|l| status_field(l, key).as_deref() == Some(want), secs)
    }

    fn collect(&mut self, pred: impl Fn(&str) -> bool, secs: u64) -> Option<String> {
        let until = std::time::Instant::now() + Duration::from_secs(secs);
        let mut echoed = 0usize;
        while std::time::Instant::now() < until {
            match self.lines.recv_timeout(Duration::from_secs(5)) {
                Ok(line) if line.starts_with("NODE_STATUS ") => {
                    if pred(&line) {
                        return Some(line);
                    }
                    if echoed < 2 {
                        echoed += 1;
                        println!("status: {line}");
                    }
                }
                Ok(line) if line.starts_with("NODE_ERROR") => println!("node: {line}"),
                Ok(_) => {}
                Err(_) => {}
            }
        }
        None
    }
}

/// Значение поля `key=value` из строки статуса. Токен ищется по точному разделителю и обязан
/// стоять на границе слова: иначе ожидание `serving_epoch=1` удовлетворялось бы строкой
/// `serving_epoch=11`, то есть слепотой прибора.
fn status_field(line: &str, key: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut from = 0usize;
    while let Some(off) = line[from..].find(key) {
        let pos = from + off;
        let after = &line[pos + key.len()..];
        let at_boundary = pos == 0 || bytes[pos - 1] == b' ';
        if at_boundary && after.starts_with('=') {
            let value = after[1..].split_whitespace().next().unwrap_or("");
            return Some(value.to_string());
        }
        from = pos + key.len();
    }
    None
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn node_args(
    f: &Fixture,
    dir: &Path,
    seed: [u8; 32],
    cert: &Path,
    bootstrap: &[Multiaddr],
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "node".into(),
        "run".into(),
        "--artifact".into(),
        s(&f.artifact),
        "--dir".into(),
        s(dir),
        "--shard".into(),
        "0".into(),
        "--seed".into(),
        hex::encode(seed),
        "--cert".into(),
        s(cert),
        "--genesis".into(),
        s(&f.genesis),
        "--listen".into(),
        "/ip4/127.0.0.1/udp/0/quic-v1".into(),
        "--status-sec".into(),
        "2".into(),
        "--run-seconds".into(),
        "120".into(),
    ];
    for addr in bootstrap {
        args.push("--bootstrap".into());
        args.push(addr.to_string());
    }
    args
}

/// Публикация настоящим агентом. `None` вместо паники: на дереве до правки отказа дождаться
/// нельзя — прибор обязан вернуть факт `0`.
fn publish(network: &NetworkParams, addr: Multiaddr, vec_q: [i8; DIM]) -> Option<u32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut agent = Agent::new(
            Identity::from_seed(PUBLISHER_SEED),
            network.clone(),
            AgentConfig {
                bootstrap: vec![addr],
                call_timeout: Duration::from_secs(20),
                ..AgentConfig::default()
            },
        )
        .ok()?;
        agent
            .publish(&PublishRequest::new(vec_q, 0, network.ttl_default_buckets, network.preprocessing_version))
            .await
            .ok()
            .map(|r| r.slot)
    })
}

#[test]
fn node_grant_survives_process_restart() {
    let tmp = Tmp::new("status");
    let f = fixture(&tmp.0);
    let a = Artifact::load(&f.artifact).unwrap();
    let network = NetworkParams::from_artifact(&a).expect("параметры сети из артефакта");
    let vec_q = *a.centroids.rows()[0];
    let primary_idx = usize::from(f.update.primary_idx);
    let primary_owner = f.update.members[primary_idx].owner_ed25519;
    let primary_seed = seed_of(primary_owner);
    let replica_owner = f.update.members[1 - primary_idx].owner_ed25519;
    let replica_seed = seed_of(replica_owner);
    let primary_cert = cert_of(&f, primary_seed).to_path_buf();
    let replica_cert = cert_of(&f, replica_seed).to_path_buf();

    let primary_dir = tmp.0.join("node-primary");
    let replica_dir = tmp.0.join("node-replica");

    // (1) Пара поднимается и публикует: базовое право писать до рестарта.
    let mut primary = NodeProc::start(&node_args(
        &f,
        &primary_dir,
        primary_seed,
        &primary_cert,
        &[],
    ));
    let primary_addr = primary.wait_ready();
    let mut replica = NodeProc::start(&node_args(
        &f,
        &replica_dir,
        replica_seed,
        &replica_cert,
        std::slice::from_ref(&primary_addr),
    ));
    let _replica_addr = replica.wait_ready();
    std::thread::sleep(Duration::from_secs(3));

    let lease_line = primary.wait_status_field("lease", 20);
    let serving_line = primary.wait_status_field("serving_epoch", 20);
    let lease_field = lease_line
        .as_deref()
        .map(|l| status_field(l, "lease").is_some())
        .unwrap_or(false);
    let serving_field = serving_line
        .as_deref()
        .map(|l| status_field(l, "serving_epoch").is_some())
        .unwrap_or(false);
    println!("LR_STATUS_LEASE_FIELD={}", lease_field as i32);
    println!("LR_STATUS_SERVING_FIELD={}", serving_field as i32);
    if let Some(l) = &lease_line {
        println!("status(до рестарта): {l}");
    }

    let slot_before = publish(&network, primary_addr.clone(), vec_q);
    assert!(slot_before.is_some(), "(1) публикация через primary до рестарта");

    // (2) Рестарт: оба процесса гасятся, реплика поднимается заново (ей грант не нужен),
    // затем primary — с тем же `--dir` и дозвоном до живой реплики, чтобы `w=2` собрался.
    drop(primary);
    drop(replica);
    std::thread::sleep(Duration::from_millis(800));
    let mut replica2 = NodeProc::start(&node_args(&f, &replica_dir, replica_seed, &replica_cert, &[]));
    let replica2_addr = replica2.wait_ready();
    let mut primary2 = NodeProc::start(&node_args(
        &f,
        &primary_dir,
        primary_seed,
        &primary_cert,
        std::slice::from_ref(&replica2_addr),
    ));
    let primary2_addr = primary2.wait_ready();

    // Ожидание статуса с нужным значением: строка идёт раз в 2 с, а право писать обязано
    // подняться из `lease.bin` сразу при открытии — до первой смены эпизоды.
    let after = primary2.wait_status_eq("serving_epoch", "1", 40);
    let epoch_one = after.is_some();
    println!("LR_CLI_EPOCH_ONE={}", epoch_one as i32);
    if let Some(l) = &after {
        println!("status(после рестарта): {l}");
    }
    let slot_after = publish(&network, primary2_addr, vec_q);
    let restart_ok = slot_after.is_some();
    println!("LR_RESTART_PUBLISH_OK={}", restart_ok as i32);
    println!(
        "slots: до={:?} после={:?}",
        slot_before, slot_after
    );

    assert!(lease_field, "NODE_STATUS обязан печатать поле lease=");
    assert!(serving_field, "NODE_STATUS обязан печатать поле serving_epoch=");
    assert!(epoch_one, "после рестарта узел обязан обслуживать ту же эпоху 1: {after:?}");
    assert!(restart_ok, "публикация после рестарта обязана пройти без смены эпизоды");
}
