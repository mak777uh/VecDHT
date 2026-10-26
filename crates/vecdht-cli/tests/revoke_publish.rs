//! A3: отзыв, собранный CLI, применяется живым узлом **без рестарта** и переживает его рестарт.
//!
//! Оракул держит обе стороны настоящими: узлы — процессы `vecdht-cli node run`, отзыв собирает и
//! рассылает `vecdht-cli revoke`, порог подписей — dev-ключи авторитетов (5 ключей, порог 3).
//! Ни один шаг не собран тестовым кодом узла: `CertRevoke` приходит в узел по control-теме
//! gossipsub, `apply_revoke` пишет `revocation.bin`, а дверь соседа решает по множеству отзывов.
//!
//! Три утверждения:
//! 1. **без рестарта**: пока узел A работает, его счётчик отзывов становится ненулевым, и в его
//!    каталоге появляется `revocation.bin`;
//! 2. **дверь отказывает**: тот же кредашиал, который до отзыва проходил дверь (baseline
//!    `door_refusals = 0` при `peers > 0`), после отзыва отвергается — счётчик отказов растёт;
//! 3. **после рестарта**: A поднимается из того же `--dir` без bootstrap, видит отзыв с диска и
//!    снова отказывает тому же кредашиалу.
//!
//! Отзываемый член на время рассылки **погашен намеренно**. Control-тему слушают все роли
//! (`NetService::new`), поэтому живой B узнал бы о своём отзыве, сам замолчал бы (`self_revoked`)
//! и оборвал соединение — счётчик двери A при этом не вырос бы, и оракул мерил бы
//! самоумолкание вместо отказа двери. Отзыв применяет A, B узнаёт о нём только тем, что его
//! кредашиал больше не пускают.
//!
//! Второй тест — отказы производителя до записи: порог не собран (2 подписи при пороге 3) и ключ
//! вне набора авторитетов. Оба — код 2, и файл отзыва не создан.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use libp2p::Multiaddr;
use vecdht_artifact::Artifact;
use vecdht_cli::Outcome;
use vecdht_crypto::cert::verify_revoke;
use vecdht_crypto::sig::Identity;
use vecdht_net::keys;
use vecdht_wire::messages::{CertRevoke, Codec};

/// Временный каталог с гардом: прогон не должен оставлять мусор в `%TEMP%`.
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "vecdht-cli-revoke-{tag}-{}",
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
const PUBLISH_SEED: [u8; 32] = [51u8; 32];

struct Fixture {
    artifact: PathBuf,
    certs: [PathBuf; 2],
    genesis: PathBuf,
}

/// Церемония через CLI: 5 ключей авторитета при пороге 3, два члена шарда 0.
fn fixture(root: &Path) -> Fixture {
    let artifact = root.join("artifact");
    let dev_seed = hex::encode(DEV_SEED);
    ok(&[
        "artifact", "init",
        "--out", &s(&artifact),
        "--seed", &dev_seed,
        "--dev-keys", "5",
        "--threshold", "3",
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
            "--dev-keys", "3",
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
        "--dev-keys", "3",
        "--seed", &dev_seed,
    ]);
    Fixture { artifact, certs, genesis }
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

    /// Ближайший `NODE_STATUS`, удовлетворяющий предикату. Строки статуса идут раз в 2 с, поэтому
    /// ожидание ограничено, а не «первая попавшаяся».
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
    f: &Fixture,
    dir: &Path,
    seed: [u8; 32],
    cert: &Path,
    bootstrap: &[Multiaddr],
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "node".into(), "run".into(),
        "--artifact".into(), s(&f.artifact),
        "--dir".into(), s(dir),
        "--shard".into(), "0".into(),
        "--seed".into(), hex::encode(seed),
        "--cert".into(), s(cert),
        "--genesis".into(), s(&f.genesis),
        "--listen".into(), "/ip4/127.0.0.1/udp/0/quic-v1".into(),
        "--status-sec".into(), "2".into(),
        // Процесс живёт дольше теста: тест гасит его сам, а запас нужен, чтобы медленный статус
        // не превратился в «узел умер раньше проверки».
        "--run-seconds".into(), "240".into(),
    ];
    for addr in bootstrap {
        args.push("--bootstrap".into());
        args.push(addr.to_string());
    }
    args
}

fn revoke_args(f: &Fixture, cert: &Path) -> Vec<String> {
    vec![
        "revoke".into(),
        "--artifact".into(), s(&f.artifact),
        "--cert".into(), s(cert),
        "--reason".into(), "e0120".into(),
        "--revoked-at".into(), "1".into(),
        "--dev-keys".into(), "3".into(),
        "--seed".into(), hex::encode(DEV_SEED),
    ]
}

#[test]
fn revoke_applies_live_and_survives_restart() {
    let tmp = Tmp::new("live");
    let f = fixture(&tmp.0);
    let a_dir = tmp.0.join("node-a");
    let b_dir = tmp.0.join("node-b");
    let b_cert = f.certs[1].clone();

    // A поднимается один; B дозванивается до него. A — владелец шарда, B — второй член: до
    // отзыва его кредашиал проходит ту же дверь.
    let mut a = NodeProc::start(&node_args(&f, &a_dir, MEMBER_SEEDS[0], &f.certs[0], &[]));
    let a_addr = a.wait_ready();
    let mut b = NodeProc::start(&node_args(
        &f,
        &b_dir,
        MEMBER_SEEDS[1],
        &b_cert,
        std::slice::from_ref(&a_addr),
    ));
    let _b_addr = b.wait_ready();
    let baseline = a.status_until(|st| st.num("peers") > 0, Duration::from_secs(30));
    assert_eq!(baseline.num("revocations"), 0, "до отзыва отзывов нет");
    println!(
        "RV_BASELINE_DOOR_ZERO={}",
        u8::from(baseline.num("door_refusals") == 0)
    );
    assert_eq!(
        baseline.num("door_refusals"),
        0,
        "до отзыва тот же кредашиал проходит дверь: отказов быть не должно"
    );

    // Отзываемый B гасится ДО рассылки: живой он узнал бы о своём отзыве по control-теме,
    // замолчал бы сам и оборвал соединение, и рост `door_refusals` у A ничего бы не значил.
    drop(b);
    std::thread::sleep(Duration::from_millis(500));

    // Отзыв собирается офлайн: файл — тот же кадр, что уйдёт в сеть. Проверяем порог тем же
    // `verify_revoke`, что и получатель.
    let revoke_file = tmp.0.join("revoke.bin");
    let revoke_out = s(&revoke_file);
    let mut args = revoke_args(&f, &b_cert);
    args.extend(["--out".to_string(), revoke_out]);
    let built = ok(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(
        built.stdout.contains("REVOKE_SIGS      3"),
        "три подписи при пороге три: {}",
        built.stdout
    );
    let bytes = std::fs::read(&revoke_file).expect("revoke --out пишет файл");
    let parsed = CertRevoke::decode(&bytes).expect("файл — кадр CertRevoke");
    assert_eq!(parsed.nonce, [0x11u8; 16], "отозван nonce второго члена");
    let artifact = Artifact::load(&f.artifact).unwrap();
    let authorities = artifact.authorities();
    verify_revoke(&parsed, &authorities).expect("порог авторитетов сходится");
    println!("RV_SIGS={}", parsed.authority_sigs.len());
    println!("RV_THRESHOLD={}", authorities.threshold);

    // Рассылка эфемерным агентом по control-теме.
    let a_addr_s = a_addr.to_string();
    let id_seed = hex::encode(PUBLISH_SEED);
    let mut args = revoke_args(&f, &b_cert);
    args.extend([
        "--to".to_string(),
        a_addr_s,
        "--id-seed".to_string(),
        id_seed,
        "--wait-sec".to_string(),
        "8".to_string(),
    ]);
    let sent = ok(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(
        sent.stdout.contains("REVOKE_PUBLISHED 1"),
        "рассылка обязана быть принята gossipsub: {}",
        sent.stdout
    );

    // (1) Живой узел применил отзыв без рестарта и записал его на диск.
    let live = a.status_until(|st| st.num("revocations") > 0, Duration::from_secs(30));
    println!("RV_LIVE_REVOCATIONS={}", live.num("revocations"));
    let rv_bytes = std::fs::metadata(a_dir.join("revocation.bin"))
        .expect("получатель пишет revocation.bin")
        .len();
    println!("RV_LIVE_FILE_NONEMPTY={}", u8::from(rv_bytes > 0));
    assert!(rv_bytes > 0, "файл отзывов не пуст");

    // (2) Дверь того же узла отказывает тому же кредашиалу: B поднимается снова с тем же
    // кредашиалом и тем же `--dir`, но без отзыва в своём каталоге — о своём отзыве он не знает,
    // и отказ обязан прийти от двери A, а не от его собственного самоумолкания.
    let door_before = live.num("door_refusals");
    let mut b2 = NodeProc::start(&node_args(
        &f,
        &b_dir,
        MEMBER_SEEDS[1],
        &b_cert,
        std::slice::from_ref(&a_addr),
    ));
    let _ = b2.wait_ready();
    let refused = a.status_until(
        |st| st.num("door_refusals") > door_before,
        Duration::from_secs(30),
    );
    println!(
        "RV_LIVE_DOOR_GT_BASELINE={}",
        u8::from(refused.num("door_refusals") > door_before)
    );
    drop(b2);

    // (3) Рестарт A из того же каталога и без bootstrap: множество отзывов и файл переживают
    // процесс, и отказ повторяется.
    drop(a);
    std::thread::sleep(Duration::from_millis(500));
    let mut a2 = NodeProc::start(&node_args(&f, &a_dir, MEMBER_SEEDS[0], &f.certs[0], &[]));
    let a2_addr = a2.wait_ready();
    let restarted = a2.status_until(|st| st.num("revocations") > 0, Duration::from_secs(30));
    println!("RV_RESTART_REVOCATIONS={}", restarted.num("revocations"));
    let mut b3 = NodeProc::start(&node_args(
        &f,
        &b_dir,
        MEMBER_SEEDS[1],
        &b_cert,
        std::slice::from_ref(&a2_addr),
    ));
    let _ = b3.wait_ready();
    let door_restart = restarted.num("door_refusals");
    let again = a2.status_until(
        |st| st.num("door_refusals") > door_restart,
        Duration::from_secs(30),
    );
    println!(
        "RV_RESTART_DOOR_GT={}",
        u8::from(again.num("door_refusals") > door_restart)
    );
}

#[test]
fn revoke_refuses_below_threshold_and_foreign_keys() {
    let tmp = Tmp::new("refusals");
    let f = fixture(&tmp.0);
    let cert = &f.certs[1];
    let run = |args: &[String]| {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        cli(&refs)
    };

    // (1) Две подписи при пороге три: документ выглядел бы подписанным, но `verify_revoke` его
    // отвергнет — значит и записывать его нельзя. Код 2, а не 1: аргументы разобраны.
    let under = tmp.0.join("under.bin");
    let mut args = revoke_args(&f, cert);
    let p = args
        .iter()
        .position(|x| x == "--dev-keys")
        .expect("--dev-keys в аргументах")
        + 1;
    args[p] = "2".to_string();
    args.extend(["--out".to_string(), s(&under)]);
    let out = run(&args);
    assert_eq!(out.code, 2, "недонабранный порог: {}", out.stderr);
    assert!(out.stderr.contains("порог"), "{}", out.stderr);
    assert!(!under.exists(), "недонабранный отзыв не пишется на диск");

    // (2) Ключ вне набора авторитетов: его подпись не войдёт в порог. Даже в компании трёх
    // правильных ключей такая подача — ошибка, а не «четвёртая подпись».
    let foreign = tmp.0.join("foreign.key");
    std::fs::write(&foreign, hex::encode([99u8; 32])).unwrap();
    let foreign_out = tmp.0.join("foreign.bin");
    let foreign_args: Vec<String> = vec![
        "revoke".into(),
        "--artifact".into(),
        s(&f.artifact),
        "--cert".into(),
        s(cert),
        "--reason".into(),
        "e0120".into(),
        "--revoked-at".into(),
        "1".into(),
        "--key-file".into(),
        s(&foreign),
        "--out".into(),
        s(&foreign_out),
    ];
    let out = run(&foreign_args);
    assert_eq!(out.code, 2, "чужой ключ: {}", out.stderr);
    assert!(out.stderr.contains("набор авторитетов"), "{}", out.stderr);
    assert!(!foreign_out.exists(), "файл с чужой подписью не пишется");

    // (3) Ни `--out`, ни `--to`: отзыв некуда девать, и молчаливый успех был бы ложью.
    let out = run(&revoke_args(&f, cert));
    assert_eq!(out.code, 2, "без адресата: {}", out.stderr);
    assert!(out.stderr.contains("--out"), "{}", out.stderr);

    // (4) Контроль: те же три ключа с `--out` дают файл — отказы выше не «всё красное».
    let good = tmp.0.join("good.bin");
    let mut args = revoke_args(&f, cert);
    args.extend(["--out".to_string(), s(&good)]);
    let out = run(&args);
    assert_eq!(out.code, 0, "три подписи при пороге три: {}", out.stderr);
    assert!(out.stdout.contains("REVOKE_THRESHOLD 3"), "{}", out.stdout);
    assert!(good.exists(), "собранный отзыв записан");
}
