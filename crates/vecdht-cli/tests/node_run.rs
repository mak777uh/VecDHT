//! A1: шард-узел из CLI (`node run`) действительно обслуживает сеть, а не только открывает порт.
//!
//! Оракул держит обе стороны протокола настоящими: узел — процесс `vecdht-cli node run`, агент —
//! `vecdht_net::Agent` из того же крейта, которым пользуется `agent publish|find` (§12). Ни одна
//! сторона не собрана тестовым кодом узла: кредашиал и genesis выпускают `cert issue` и
//! `genesis build` (A0), а ключи и состав пишутся файлами.
//!
//! Почему агент здесь не через `vecdht-cli agent publish`: CLI-агент требует артефакт с именем
//! настоящей модели (`--model-dir` / `--allow-surrogate`), а предмет A1 — узел, а не
//! кодировщик. Публикация и поиск идут тем же `vecdht_net::Agent`, что и за командой CLI, и
//! с той же сетевой дверью.
//!
//! Три утверждения:
//! 1. узел, собранный из файлов церемонии, принимает `Publish` и отвечает на `Find` по QUIC;
//! 2. после остановки и повторного старта с тем же `--dir` запись находится — индекс пережил
//!    рестарт, а не остался в памяти процесса;
//! 3. неполная или чужая церемония отвергается кодом 2 с названным флагом: узел не открывает
//!    порт, если кредашиал или genesis не прошли проверку.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use libp2p::Multiaddr;
use vecdht_artifact::Artifact;
use vecdht_cli::Outcome;
use vecdht_crypto::sig::Identity;
use vecdht_net::{keys, Agent, AgentConfig, FindQuery, NetworkParams, PublishRequest};
use vecdht_wire::codec::DIM;
use vecdht_wire::messages::{Codec, MembershipUpdate};

/// Временный каталог с гардом: прогон не должен оставлять мусор в `%TEMP%`.
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "vecdht-cli-node-run-{tag}-{}",
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
const PUBLISHER_SEED: [u8; 32] = [41u8; 32];
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
        "artifact",
        "init",
        "--out",
        &s(&artifact),
        "--seed",
        &dev_seed,
        "--dev-keys",
        "1",
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
            "cert",
            "issue",
            "--artifact",
            &s(&artifact),
            "--out",
            &s(&cert),
            "--owner",
            &owner,
            "--peer-id",
            &peer,
            "--shard",
            "0",
            "--capacity",
            "100000",
            "--valid-from",
            "0",
            "--valid-until",
            "4102444800",
            "--nonce",
            &nonce,
            "--dev-keys",
            "1",
            "--seed",
            &dev_seed,
        ]);
        member_lines.push_str(&format!("{owner} {peer} 100000\n"));
        certs.push(cert);
    }
    let certs: [PathBuf; 2] = certs.try_into().expect("два члена — два кредашиала");
    let members = root.join("members.txt");
    std::fs::write(&members, member_lines).unwrap();
    let genesis = root.join("genesis.bin");
    ok(&[
        "genesis",
        "build",
        "--artifact",
        &s(&artifact),
        "--out",
        &s(&genesis),
        "--members",
        &s(&members),
        "--shard",
        "0",
        "--generated-at",
        "0",
        "--dev-keys",
        "1",
        "--seed",
        &dev_seed,
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
                Ok(line) => {
                    // Остальные строки — статус и ошибки транспорта; их печатаем, чтобы провал
                    // был читаемым, а не «узел молчал 60 с».
                    println!("node: {line}");
                }
                Err(e) => panic!("узел не объявил NODE_READY: {e}"),
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
        "60".into(),
    ];
    for addr in bootstrap {
        args.push("--bootstrap".into());
        args.push(addr.to_string());
    }
    args
}

fn publish(
    network: &NetworkParams,
    addr: Multiaddr,
    vec_q: [i8; DIM],
    ttl: u16,
    preprocessing: u16,
) -> vecdht_net::PublishReceipt {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut agent = Agent::new(
            Identity::from_seed(PUBLISHER_SEED),
            network.clone(),
            AgentConfig { bootstrap: vec![addr], call_timeout: Duration::from_secs(15), ..AgentConfig::default() },
        )
        .expect("агент-издатель");
        agent
            .publish(&PublishRequest::new(vec_q, 0, ttl, preprocessing))
            .await
            .expect("публикация через узел CLI")
    })
}

fn find(network: &NetworkParams, addr: Multiaddr, vec_q: [i8; DIM]) -> Vec<vecdht_net::FoundMatch> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut agent = Agent::new(
            Identity::from_seed(SEEKER_SEED),
            network.clone(),
            AgentConfig { bootstrap: vec![addr], call_timeout: Duration::from_secs(15), ..AgentConfig::default() },
        )
        .expect("агент-искатель");
        let outcome = agent
            .find(&FindQuery::new(vec_q, vec![0], 5))
            .await
            .expect("поиск через узел CLI");
        assert!(
            outcome.failures.is_empty(),
            "отказы шардов: {:?}",
            outcome.failures
        );
        outcome.matches
    })
}

#[test]
fn node_run_publishes_finds_and_survives_restart() {
    let tmp = Tmp::new("e2e");
    let f = fixture(&tmp.0);
    let a = Artifact::load(&f.artifact).unwrap();
    let network = NetworkParams::from_artifact(&a).expect("параметры сети из артефакта");
    let vec_q = *a.centroids.rows()[0];
    let primary_idx = usize::from(f.update.primary_idx);
    let primary_owner = f.update.members[primary_idx].owner_ed25519;
    let primary_seed = seed_of(primary_owner);
    let replica_owner = f.update.members[1 - primary_idx].owner_ed25519;
    let replica_seed = seed_of(replica_owner);
    let primary_cert = cert_of(&f, primary_seed);
    let replica_cert = cert_of(&f, replica_seed);

    // Primary поднимается первым: его адрес нужен и реплике, и агенту. Реплика дозванивается
    // до него сама — так primary узнаёт её без отдельного bootstrap с обеих сторон (§9.4, W=2).
    let primary_dir = tmp.0.join("node-primary");
    let replica_dir = tmp.0.join("node-replica");
    let mut primary = NodeProc::start(&node_args(&f, &primary_dir, primary_seed, primary_cert, &[]));
    let primary_addr = primary.wait_ready();
    let mut replica = NodeProc::start(&node_args(
        &f,
        &replica_dir,
        replica_seed,
        replica_cert,
        std::slice::from_ref(&primary_addr),
    ));
    let _replica_addr = replica.wait_ready();
    // Рукопожатие и объявление провайдера идут шагами узла; публикация сразу после NODE_READY
    // могла бы не застать второго держателя, и W=2 сорвался бы не по вине предмета.
    std::thread::sleep(Duration::from_secs(3));

    let t = std::time::Instant::now();
    let receipt = publish(
        &network,
        primary_addr.clone(),
        vec_q,
        network.ttl_default_buckets,
        network.preprocessing_version,
    );
    eprintln!("publish: {:?}", t.elapsed());
    assert_eq!(receipt.shard, 0, "запись шарда 0");
    let t = std::time::Instant::now();
    let found = find(&network, primary_addr.clone(), vec_q);
    eprintln!("find до рестарта: {:?}", t.elapsed());
    assert!(
        found.iter().any(|m| m.owner_ed25519 == Identity::from_seed(PUBLISHER_SEED).pubkey()
            && m.slot == receipt.slot),
        "опубликованная запись обязана найтись через тот же узел: {found:?}"
    );

    // Рестарт с тем же `--dir`: индекс и цепочка членства лежат на диске, а не в процессе.
    // Реплика гасится вместе с primary — иначе `Find` мог бы ответить из неё, и «пережило
    // рестарт» означало бы «пережил сосед». Порт намеренно новый (`udp/0`).
    drop(primary);
    drop(replica);
    std::thread::sleep(Duration::from_millis(800));
    let mut restarted = NodeProc::start(&node_args(&f, &primary_dir, primary_seed, primary_cert, &[]));
    let restarted_addr = restarted.wait_ready();
    let t = std::time::Instant::now();
    let found_after = find(&network, restarted_addr, vec_q);
    eprintln!("find после рестарта: {:?}", t.elapsed());
    assert!(
        found_after.iter().any(|m| m.owner_ed25519 == Identity::from_seed(PUBLISHER_SEED).pubkey()
            && m.slot == receipt.slot),
        "после рестарта запись обязана находиться из того же каталога: {found_after:?}"
    );
    assert!(
        std::fs::read_dir(&primary_dir).unwrap().next().is_some(),
        "каталог узла не пуст: индекс, цепочка и списки запрета живут там"
    );
}

#[test]
fn node_run_refuses_incomplete_or_foreign_ceremony() {
    let tmp = Tmp::new("refusals");
    let f = fixture(&tmp.0);
    let dir = tmp.0.join("node");
    let base: Vec<String> = node_args(&f, &dir, MEMBER_SEEDS[0], &f.certs[0], &[]);

    let run = |args: &[String]| {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        cli(&refs)
    };
    let without = |flag: &str| {
        let mut a = base.clone();
        let pos = a.iter().position(|x| x == flag).expect("флаг в аргументах");
        a.drain(pos..pos + 2);
        a
    };

    // (1) Нет genesis — отказ до открытия порта, и в тексте назван флаг, а не «что-то не так».
    // Отсутствие обязательного флага — ошибка разбора (код 1), а не отказ протокола (код 2).
    let out = run(&without("--genesis"));
    assert_eq!(out.code, 1, "без genesis: {}", out.stderr);
    assert!(out.stderr.contains("--genesis"), "{}", out.stderr);

    // (2) Нет кредашиала — то же.
    let out = run(&without("--cert"));
    assert_eq!(out.code, 1, "без cert: {}", out.stderr);
    assert!(out.stderr.contains("--cert"), "{}", out.stderr);

    // (3) Кредашиал выписан другому владельцу: подпись кадров чужим именем — не членство.
    let other = node_args(&f, &dir, MEMBER_SEEDS[1], &f.certs[0], &[]);
    let out = run(&other);
    assert_eq!(out.code, 2, "чужой кредашиал: {}", out.stderr);
    assert!(out.stderr.contains("владельцу"), "{}", out.stderr);

    // (4) Тело genesis подменено (ёмкость члена): кадр разбирается, но подпись порога над телом
    // уже не сходится — `Chain::validate` обязан отвергнуть, и порт не открывается.
    let tampered = tmp.0.join("genesis-tampered.bin");
    let mut bytes = std::fs::read(&f.genesis).unwrap();
    let needle = 100_000u64.to_le_bytes();
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("ёмкость члена лежит в теле genesis");
    bytes[pos + needle.len() - 1] ^= 0x01;
    std::fs::write(&tampered, &bytes).unwrap();
    let mut args = base.clone();
    let pos = args.iter().position(|x| x == "--genesis").unwrap();
    args[pos + 1] = s(&tampered);
    let out = run(&args);
    assert_eq!(out.code, 2, "подменённый genesis: {}", out.stderr);
    assert!(out.stderr.contains("genesis"), "{}", out.stderr);
}
