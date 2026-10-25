//! Оракул карточки A0: церемония сети собирается только из CLI и файлов вне репозитория, а
//! собранные документы принимает **тот же проверяющий код, что у узла**.
//!
//! Тест держит три вещи, которые легко объявить и трудно выполнить:
//!
//! 1. `cert issue` с ключами из файлов выпускает кредашиал, проходящий `verify_cert` с набором
//!    авторитетов артефакта; урезание подписи до порога-1 обязано краснеть, а не «почти проходить»;
//! 2. `genesis build` собирает переход, проходящий `Chain::validate(None, …)`, и его состав —
//!    ровно `candidates::ordered`, а не порядок строк файла;
//! 3. два прогона с одними аргументами дают побайтово одинаковые документы: церемония без
//!    случайности, иначе «тот же» genesis нельзя было бы сверить между операторами.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use vecdht_artifact::manifest::DOMAIN_ARTIFACT;
use vecdht_artifact::Artifact;
use vecdht_cli::run;
use vecdht_crypto::cert::verify_cert;
use vecdht_crypto::sig::Identity;
use vecdht_node::candidates::{self, Holder};
use vecdht_node::config::Params;
use vecdht_node::membership::{Chain, GENESIS_EPOCH};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::messages::{Codec, MembershipUpdate};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// Каталог прогона с `Drop`-гардом: тест, упавший по панике, обязан убрать за собой, иначе
/// временные каталоги копятся между прогонами (тот же урок, что в `E-0085`, ДИАГНОЗ-2).
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "vecdht-cli-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("временный каталог создаётся");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn seed_file(dir: &Path, name: &str, seed: [u8; 32]) -> String {
    let p = dir.join(name);
    std::fs::write(&p, hex(&seed)).expect("seed пишется");
    p.to_string_lossy().to_string()
}

fn run_ok(argv: &[&str]) -> String {
    let o = run(argv);
    assert_eq!(o.code, 0, "{argv:?} → {o:?}");
    o.stdout
}

fn run_fail(argv: &[&str]) -> String {
    let o = run(argv);
    assert_eq!(o.code, 2, "ждали отказ команды, а не разбора: {argv:?} → {o:?}");
    o.stderr
}

const PEER: &str = "0024000000000000000000000000000000000000000000000000000000000000000000";
const SEED: [u8; 32] = [0x11; 32];

/// Артефакт с порогом 2, у которого известны seed'ы обоих авторитетов: они и подаются файлами.
///
/// `artifact init` так не умеет и не должен: он подписывает артефакт только своими dev-ключами
/// (приватной части чужих ключей у него нет). Поэтому фикстура собирается через публичный
/// `Artifact::assemble`, а проверяется всё дальнейшее — продуктными командами церемонии.
fn artifact_with_files(t: &Tmp) -> (String, String, String, [[u8; 32]; 2]) {
    let seeds = [[0x5a; 32], [0x5b; 32]];
    let base = vecdht_artifact::reference_artifact();
    let mut m = base.manifest;
    m.authority.keys = seeds.iter().map(|s| Identity::from_seed(*s).pubkey()).collect();
    m.authority.threshold = 2;
    m.signatures.clear();
    let mut a = Artifact::assemble(m, base.centroids).expect("фикстура артефакта собирается");
    let material = a.signing_material();
    for s in seeds {
        a.manifest
            .signatures
            .push(Identity::from_seed(s).sign_domain(DOMAIN_ARTIFACT, &material));
    }
    let dir = t.path().join("artifact-files");
    a.save(&dir).expect("фикстура артефакта записывается");
    let a_key = seed_file(t.path(), "a.key", seeds[0]);
    let b_key = seed_file(t.path(), "b.key", seeds[1]);
    (dir.to_string_lossy().to_string(), a_key, b_key, seeds)
}

/// Артефакт из `artifact init`: оба авторитета — dev-ключи, приватная часть выводится из seed.
fn artifact_dev(t: &Tmp) -> String {
    let dir = t.path().join("artifact-dev");
    let dirs = dir.to_string_lossy().to_string();
    run_ok(&[
        "artifact",
        "init",
        "--out",
        &dirs,
        "--seed",
        &hex(&SEED),
        "--dev-keys",
        "2",
        "--threshold",
        "2",
    ]);
    dirs
}

#[test]
fn cert_from_key_files_passes_the_nodes_own_verifier_and_fails_when_a_signature_is_removed() {
    let t = Tmp::new("cert");
    let (artifact, key_a, key_b, _) = artifact_with_files(&t);
    let out = t.path().join("node.cert");
    let outs = out.to_string_lossy().to_string();
    run_ok(&[
        "cert",
        "issue",
        "--artifact",
        &artifact,
        "--out",
        &outs,
        "--owner",
        &hex(&Identity::from_seed([0x22; 32]).pubkey()),
        "--peer-id",
        PEER,
        "--shard",
        "3",
        "--capacity",
        "1000",
        "--valid-from",
        "100",
        "--valid-until",
        "200",
        "--nonce",
        &"33".repeat(16),
        "--key-file",
        &key_a,
        "--key-file",
        &key_b,
    ]);
    let a = Artifact::load(Path::new(&artifact)).expect("артефакт читается");
    let bytes = std::fs::read(&out).expect("кредашиал записан");
    let cert = NodeCert::decode(&bytes).expect("кредашиал декодируется");
    assert_eq!(cert.authority_sigs.len(), 2);
    assert_eq!(cert.shards, vec![3]);
    verify_cert(&cert, &a.authorities(), &a.genesis_hash(), 150, |_| false)
        .expect("две подписи при пороге 2 проходят проверку узла");

    // Порог — это про число подписей, а не про наличие файла: одна подпись обязана краснеть.
    let mut weak = cert.clone();
    weak.authority_sigs.truncate(1);
    assert!(
        verify_cert(&weak, &a.authorities(), &a.genesis_hash(), 150, |_| false).is_err(),
        "кредашиал с одной подписью при пороге 2 не должен проходить"
    );

    // Подмена поля ломает подпись: файл связан с содержимым, а не только с ключами.
    let mut moved = cert;
    moved.capacity_entries += 1;
    assert!(verify_cert(&moved, &a.authorities(), &a.genesis_hash(), 150, |_| false).is_err());
}

#[test]
fn cert_refuses_a_signer_outside_the_authority_set_and_writes_nothing() {
    let t = Tmp::new("cert-outsider");
    let (artifact, _, _, _) = artifact_with_files(&t);
    let outsider = seed_file(t.path(), "outsider.key", [0x77; 32]);
    let out = t.path().join("node.cert");
    let outs = out.to_string_lossy().to_string();
    let err = run_fail(&[
        "cert",
        "issue",
        "--artifact",
        &artifact,
        "--out",
        &outs,
        "--owner",
        &hex(&Identity::from_seed([0x22; 32]).pubkey()),
        "--peer-id",
        PEER,
        "--capacity",
        "1000",
        "--valid-from",
        "100",
        "--valid-until",
        "200",
        "--nonce",
        &"33".repeat(16),
        "--key-file",
        &outsider,
    ]);
    assert!(err.contains("набор авторитетов"), "{err}");
    assert!(!out.exists(), "отказ обязан оставить диск как был");
}

#[test]
fn cert_is_byte_identical_on_two_runs_with_the_same_inputs() {
    let t = Tmp::new("cert-stable");
    let artifact = artifact_dev(&t);
    let owner = hex(&Identity::from_seed([0x22; 32]).pubkey());
    let mut made = Vec::new();
    for name in ["one.cert", "two.cert"] {
        let p = t.path().join(name);
        let ps = p.to_string_lossy().to_string();
        run_ok(&[
            "cert",
            "issue",
            "--artifact",
            &artifact,
            "--out",
            &ps,
            "--owner",
            &owner,
            "--peer-id",
            PEER,
            "--capacity",
            "1000",
            "--valid-from",
            "100",
            "--valid-until",
            "200",
            "--nonce",
            &"33".repeat(16),
            "--dev-keys",
            "2",
            "--seed",
            &hex(&SEED),
        ]);
        made.push(std::fs::read(&p).expect("файл на месте"));
    }
    assert_eq!(made[0], made[1], "два прогона с теми же входами обязаны совпасть побайтово");
    let cert = NodeCert::decode(&made[0]).expect("dev-кредашиал декодируется");
    let a = Artifact::load(Path::new(&artifact)).expect("артефакт читается");
    verify_cert(&cert, &a.authorities(), &a.genesis_hash(), 150, |_| false)
        .expect("dev-ключи выведены той же формулой, что у artifact init");
}

fn members_file(dir: &Path, order: &[usize]) -> (String, Vec<Holder>) {
    let holders: Vec<Holder> = (0..3)
        .map(|i| Holder {
            owner_ed25519: [0x40 + i as u8; 32],
            dht_peer_id: vec![0x00, 0x24, i as u8],
            capacity_entries: 10_000 + i as u64,
        })
        .collect();
    let mut text = String::from("# состав шарда\n");
    for &i in order {
        let h = &holders[i];
        text.push_str(&format!(
            "{} {} {}\n",
            hex(&h.owner_ed25519),
            hex(&h.dht_peer_id),
            h.capacity_entries
        ));
    }
    let p = dir.join("members.txt");
    std::fs::write(&p, text).expect("состав пишется");
    (p.to_string_lossy().to_string(), holders)
}

#[test]
fn genesis_with_shuffled_lines_is_the_same_frame_and_passes_chain_validate() {
    let t = Tmp::new("genesis");
    let (artifact, key_a, key_b, _) = artifact_with_files(&t);
    let (m1, holders) = members_file(t.path(), &[0, 1, 2]);
    let shuffled = t.path().join("shuffled");
    std::fs::create_dir_all(&shuffled).expect("подкаталог создаётся");
    let (m2, _) = members_file(&shuffled, &[2, 0, 1]);
    let mut frames = Vec::new();
    for (i, members) in [m1, m2].iter().enumerate() {
        let out = t.path().join(format!("genesis-{i}.bin"));
        let outs = out.to_string_lossy().to_string();
        run_ok(&[
            "genesis",
            "build",
            "--artifact",
            &artifact,
            "--out",
            &outs,
            "--members",
            members,
            "--shard",
            "5",
            "--generated-at",
            "1000",
            "--key-file",
            &key_a,
            "--key-file",
            &key_b,
        ]);
        frames.push(std::fs::read(&out).expect("genesis записан"));
    }
    assert_eq!(frames[0], frames[1], "порядок строк файла не входит в байты перехода");

    let a = Artifact::load(Path::new(&artifact)).expect("артефакт читается");
    let params = Params::from_manifest(&a.manifest).expect("пороги артефакта годятся");
    let upd = MembershipUpdate::decode(&frames[0]).expect("кадр декодируется");
    assert_eq!(upd.epoch, GENESIS_EPOCH);
    assert_eq!(upd.shard, 5);
    assert_eq!(upd.sigs.len(), 2);
    let chain = Chain { shard: 5, params, authorities: a.authorities() };
    let m = chain.validate(None, &upd).expect("genesis проходит проверку узла");
    let expected = candidates::ordered(GENESIS_EPOCH, 5, &holders);
    let expected: Vec<_> = expected.iter().map(|h| h.as_member()).collect();
    assert_eq!(m.members(), &expected[..], "состав — детерминированный порядок §9.3");

    // Порог-1 обязан краснеть: иначе «подписано» значило бы «подписал кто-то один».
    let weak = {
        let mut u = upd.clone();
        u.sigs.truncate(1);
        u
    };
    assert!(chain.validate(None, &weak).is_err(), "одна подпись при пороге 2 — не genesis");
}

#[test]
fn genesis_refuses_a_duplicate_owner_and_a_shard_of_one() {
    let t = Tmp::new("genesis-refusals");
    let (artifact, key_a, key_b, _) = artifact_with_files(&t);
    let owner = hex(&[0x41; 32]);
    let dup = t.path().join("dup.txt");
    std::fs::write(
        &dup,
        format!("{owner} 002401 10\n{owner} 002402 10\n"),
    )
    .expect("файл пишется");
    let out = t.path().join("g.bin");
    let outs = out.to_string_lossy().to_string();
    let dups = dup.to_string_lossy().to_string();
    let err = run_fail(&[
        "genesis", "build", "--artifact", &artifact, "--out", &outs, "--members", &dups,
        "--shard", "0", "--generated-at", "1", "--key-file", &key_a, "--key-file", &key_b,
    ]);
    assert!(err.contains("дубликат") || err.contains("дубликат владельца"), "{err}");
    assert!(!out.exists());

    let one = t.path().join("one.txt");
    std::fs::write(&one, format!("{owner} 002401 10\n")).expect("файл пишется");
    let ones = one.to_string_lossy().to_string();
    let err = run_fail(&[
        "genesis", "build", "--artifact", &artifact, "--out", &outs, "--members", &ones,
        "--shard", "0", "--generated-at", "1", "--key-file", &key_a, "--key-file", &key_b,
    ]);
    assert!(err.contains("R ≥ 2") || err.contains("одним держателем"), "{err}");
    assert!(!out.exists());
}

// Состав для второго прогона кладётся в подкаталог, чтобы порядок строк файла был другим.

