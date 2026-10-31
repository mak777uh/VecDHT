//! Интеграционные тесты бинарника оператора (§17.1: «vecdht-cli/ бинарник node/agent/demo»).
//!
//! Два уровня проверки, и оба нужны. Первый: `vecdht_cli::run(argv)` вызывается как функция — так
//! видно коды возврата и весь вывод без издержек `spawn`, и именно так проверяются отказы
//! (`--force`, недостижимый порог, чужие кластеры). Второй: один тест запускает настоящий
//! `main`-процесс, потому что `run` может быть идеальным, а обёртка над потоками и кодами выхода —
//! нет; без этого теста расхождение `main`/`run` осталось бы незамеченным до first run оператора.
//!
//! Всё пишется в изолированные каталоги в temp и удаляется: тест, оставивший шард или артефакт,
//! через полгода выглядит как «у разработчика работает, у оператора нет».

use std::path::{Path, PathBuf};
use std::process::Command;

use vecdht_artifact::{CENTROID_FILE, MANIFEST_FILE};
use vecdht_cli::{CODE_FAILED, CODE_OK, CODE_USAGE, run};
use vecdht_crypto::sig::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_index::IndexEntry;
use vecdht_net::keys;
use vecdht_wire::messages::Publish;
use vecdht_wire::{domain, Codec, Kind, DIM, SHARDS};

/// Каталог под тест; путь нужен и как `&str` для argv, и как `PathBuf` для удаления.
fn tmp(tag: &str) -> PathBuf {
    dir(tag)
}

fn s(p: &Path) -> String {
    p.to_str().expect("тестовый путь обязан быть utf-8").to_string()
}

/// Dev-артефакт, собранный самим CLI: тест проверяет тот же путь, что и оператор, а не
/// `reference_artifact()` из библиотеки.
fn make_artifact(tag: &str) -> PathBuf {
    let d = tmp(tag);
    let o = run(&["artifact", "init", "--out", &s(&d), "--label", "cli-test"]);
    assert_eq!(o.code, CODE_OK, "{:?}", o.stderr);
    d
}

fn hash_line(out: &str) -> String {
    out.lines()
        .find(|l| l.trim_start().starts_with("artifact_hash"))
        .expect("вывод обязан печатать artifact_hash")
        .split_whitespace()
        .last()
        .unwrap()
        .to_string()
}

fn entry(owner: u8, cluster: u16, published: u32, ttl: u16) -> IndexEntry {
    IndexEntry {
        owner_ed25519: [owner; 32],
        vec_q: [(owner as i8) - 40; DIM],
        cluster_id: cluster,
        published_bucket: published,
        ttl_buckets: ttl,
    }
}

fn vec_hex(e: &IndexEntry) -> String {
    hex::encode(e.vec_q.iter().map(|v| *v as u8).collect::<Vec<u8>>())
}

#[test]
fn artifact_init_then_show_then_verify_agree_on_the_hash() {
    let d = make_artifact("artifact-roundtrip");
    let show = run(&["artifact", "show", "--artifact", &s(&d)]);
    assert_eq!(show.code, CODE_OK, "{:?}", show.stderr);
    let hash = hash_line(&show.stdout);
    assert_eq!(hash.len(), 64, "artifact_hash обязан быть 32 байта hex");
    assert!(show.stdout.contains("1 ключ(ей), порог 1"), "{}", show.stdout);

    let verify = run(&["artifact", "verify", "--artifact", &s(&d), "--pinned", &hash]);
    assert_eq!(verify.code, CODE_OK, "{:?}", verify.stderr);
    assert!(verify.stdout.contains("проверено: 1 валидных подписей"), "{}", verify.stdout);

    // Чужой pinned — отказ с кодом 2, а не «предупреждение и продолжение»: узел на handshake
    // обязан остановиться до построения индекса (§15.3).
    let mut wrong = hash.clone();
    let last = wrong.as_bytes()[63];
    wrong.replace_range(63..64, if last == b'0' { "1" } else { "0" });
    let bad = run(&["artifact", "verify", "--artifact", &s(&d), "--pinned", &wrong]);
    assert_eq!(bad.code, CODE_FAILED, "{bad:?}");
    assert!(!bad.stdout.contains("проверено:"), "{}", bad.stdout);
    remove(&d);
}

#[test]
fn the_same_label_rebuilds_a_byte_identical_artifact() {
    // Детерминизм сборки — часть контракта §15.1: два оператора с одним label обязаны получить
    // один artifact_hash, иначе «согласованная сеть» проверяется только у того, кто собирал.
    let a = make_artifact("determinism-a");
    let b = make_artifact("determinism-b");
    assert_eq!(
        hash_line(&run(&["artifact", "show", "--artifact", &s(&a)]).stdout),
        hash_line(&run(&["artifact", "show", "--artifact", &s(&b)]).stdout)
    );
    let ca = std::fs::read(a.join(CENTROID_FILE)).unwrap();
    let cb = std::fs::read(b.join(CENTROID_FILE)).unwrap();
    assert_eq!(ca, cb, "центроиды одного label обязаны совпадать побайтово");
    let ma = std::fs::read(a.join(MANIFEST_FILE)).unwrap();
    let mb = std::fs::read(b.join(MANIFEST_FILE)).unwrap();
    assert_eq!(ma, mb);
    remove(&a);
    remove(&b);
}

#[test]
fn overwriting_an_artifact_needs_an_explicit_force() {
    let d = make_artifact("force");
    let again = run(&["artifact", "init", "--out", &s(&d), "--label", "cli-test"]);
    assert_eq!(again.code, CODE_FAILED, "{again:?}");
    assert!(again.stderr.contains("--force"), "{}", again.stderr);
    let forced = run(&["artifact", "init", "--out", &s(&d), "--label", "cli-test", "--force"]);
    assert_eq!(forced.code, CODE_OK, "{:?}", forced.stderr);
    remove(&d);
}

#[test]
fn an_unreachable_signature_threshold_is_refused_before_writing() {
    let d = tmp("threshold");
    let o = run(&[
        "artifact", "init", "--out", &s(&d), "--label", "cli-test", "--dev-keys", "1",
        "--threshold", "3",
    ]);
    assert_eq!(o.code, CODE_FAILED, "{o:?}");
    assert!(o.stderr.contains("недостижим"), "{}", o.stderr);
    // Каталог обязан остаться без манифеста: отказ после записи дал бы артефакт, который
    // `verify` не принимает, но который лежит и выглядит готовым.
    assert!(!d.join(MANIFEST_FILE).exists(), "отказ обязан произойти до записи");
    remove(&d);
}

#[test]
fn encode_refuses_a_silent_surrogate_and_labels_it_when_allowed() {
    let d = make_artifact("encode");
    let no_source = run(&["encode", "--artifact", &s(&d), "--text", "найти_note_один"]);
    assert_eq!(no_source.code, CODE_FAILED, "{no_source:?}");
    assert!(no_source.stderr.contains("--allow-surrogate"), "{}", no_source.stderr);

    let intent = run(&[
        "encode", "--artifact", &s(&d), "--text", "найти устройство 1", "--allow-surrogate",
    ]);
    assert_eq!(intent.code, CODE_OK, "{:?}", intent.stderr);
    assert!(intent.stdout.contains("суррогат HashModel"), "{}", intent.stdout);
    assert!(intent.stdout.contains("НЕ семантический"), "{}", intent.stdout);
    assert!(intent.stdout.contains("cluster_id"), "{}", intent.stdout);
    assert!(intent.stdout.contains("preprocessing_version 1"), "{}", intent.stdout);

    let query = run(&[
        "encode", "--artifact", &s(&d), "--text", "найти устройство 1", "--allow-surrogate",
        "--kind", "query", "--nprobe", "8",
    ]);
    assert_eq!(query.code, CODE_OK, "{:?}", query.stderr);
    assert!(query.stdout.contains("fan-out"), "{}", query.stdout);

    // Путь один, а не «оба сразу»: `--kind` различает, кто подписывает текст (§6.6).
    let bad = run(&[
        "encode", "--artifact", &s(&d), "--text", "x", "--allow-surrogate", "--kind", "both",
    ]);
    assert_eq!(bad.code, CODE_FAILED, "{bad:?}");
    remove(&d);
}

#[test]
fn wire_kinds_prints_the_frame_table() {
    let o = run(&["wire", "kinds"]);
    assert_eq!(o.code, CODE_OK, "{:?}", o.stderr);
    assert!(o.stdout.contains("19 видов"), "{}", o.stdout);
    assert!(o.stdout.contains("подписанных 13"), "{}", o.stdout);
    for kind in ["Publish", "Find", "LeaseGrant", "SnapshotOffer", "CertRevoke"] {
        assert!(o.stdout.contains(kind), "вид {kind} обязан быть в таблице §5.3");
    }
}

#[test]
fn wire_decode_rebuilds_a_publish_frame_it_was_given() {
    // Подпись `Publish` обязательна (`H-0164`): кадр без неё — не «корректный кадр», а
    // нарушение матрицы, и предупреждение на нём было бы правдой.
    let id = Identity::from_seed([0xA1; 32]);
    let publish = Publish {
        preprocessing_version: 1,
        cluster_id: 777,
        vec_q: [3i8; DIM],
        owner_ed25519: id.pubkey(),
        ttl_buckets: 225,
        published_bucket: 1_000_000,
        pow_bits: 24,
        pow_nonce: 42,
        intent_id: [0xB2; 32],
        tlv: vec![],
    };
    let frame = publish.encode_signed(
        &id.sign_body(domain::PUBLISH, Kind::Publish, &publish.body_bytes()),
    );
    let o = run(&["wire", "decode", "--hex", &hex::encode(&frame)]);
    assert_eq!(o.code, CODE_OK, "{:?}", o.stderr);
    assert!(o.stdout.contains("как Publish"), "{}", o.stdout);
    assert!(o.stdout.contains("cluster_id: 777"), "{}", o.stdout);
    assert!(o.stdout.contains("совпадает: true"), "{}", o.stdout);
    assert!(!o.stdout.contains("ВНИМАНИЕ"), "{}", o.stdout);

    // Обрезанный кадр — это ошибка, а не «разобрали насколько смогли»; с `--lenient` дамп
    // печатается до места обрыва, потому что смотреть оборванный хвост — легитимная задача.
    let cut = hex::encode(&frame[..frame.len() - 5]);
    let strict = run(&["wire", "decode", "--hex", &cut]);
    assert_eq!(strict.code, CODE_FAILED, "{strict:?}");
    let lenient = run(&["wire", "decode", "--hex", &cut, "--lenient"]);
    assert_eq!(lenient.code, CODE_OK, "{:?}", lenient.stderr);
    assert!(lenient.stdout.contains("не дочитан"), "{}", lenient.stdout);
}

#[test]
fn index_commands_drive_one_shard_on_disk() {
    let d = tmp("index-shard");
    // Шард 2 владеет кластерами 32..47 (§7.1) — записи обязаны лежать именно там.
    let create = run(&["index", "create", "--dir", &s(&d), "--shard", "2", "--epoch", "5"]);
    assert_eq!(create.code, CODE_OK, "{:?}", create.stderr);
    assert!(create.stdout.contains("lease подтверждён = true"), "{}", create.stdout);

    let entries = vec![entry(1, 33, 10, 100), entry(2, 34, 10, 100), entry(3, 33, 10, 100)];
    let mut bytes = Vec::new();
    for e in &entries {
        bytes.extend_from_slice(&e.to_bytes());
    }
    let file = d.join("entries.bin");
    std::fs::write(&file, &bytes).unwrap();

    let add = run(&[
        "index", "add", "--dir", &s(&d), "--shard", "2", "--entries", &s(&file), "--time-mark", "20",
    ]);
    assert_eq!(add.code, CODE_OK, "{:?}", add.stderr);
    assert!(add.stdout.contains("опубликовано 3 из 3 записей"), "{}", add.stdout);

    let search = run(&[
        "index", "search", "--dir", &s(&d), "--shard", "2", "--vec", &vec_hex(&entries[0]),
        "--clusters", "33", "--show-entries",
    ]);
    assert_eq!(search.code, CODE_OK, "{:?}", search.stderr);
    assert!(search.stdout.contains("хитов 2"), "{}", search.stdout);
    assert!(search.stdout.contains("дедлайн 110"), "{}", search.stdout);
    assert!(search.stdout.contains("тот же результат"), "{}", search.stdout);

    // Чужой кластер — отказ, а не пустой ответ: пустой ответ выглядит как «записей нет» (§7.4).
    let foreign = run(&[
        "index", "search", "--dir", &s(&d), "--shard", "2", "--vec", &vec_hex(&entries[0]),
        "--clusters", "99",
    ]);
    assert_eq!(foreign.code, CODE_FAILED, "{foreign:?}");
    assert!(foreign.stderr.contains("принадлежат не шарду"), "{}", foreign.stderr);

    let stats = run(&["index", "stats", "--dir", &s(&d), "--shard", "2"]);
    assert_eq!(stats.code, CODE_OK, "{:?}", stats.stderr);
    assert!(stats.stdout.contains("инварианты IVF (§8.3): выполнены"), "{}", stats.stdout);
    assert!(stats.stdout.contains("кластеры шарда: 3 слотов в 16"), "{}", stats.stdout);

    let snap = run(&["index", "snapshot", "--dir", &s(&d), "--shard", "2"]);
    assert_eq!(snap.code, CODE_OK, "{:?}", snap.stderr);
    remove(&d);
}

#[test]
fn a_gc_tick_in_the_same_command_removes_every_record() {
    // Экспирация берётся из данных, а не из часов машины: GcTick в бакет после дедлайна обязан
    // снять всё, что было опубликовано в этой же пачке (§9.6).
    let d = tmp("index-gc");
    run(&["index", "create", "--dir", &s(&d), "--shard", "2", "--epoch", "5"]);
    let file = d.join("entries.bin");
    let mut bytes = Vec::new();
    for e in [entry(1, 33, 10, 100), entry(2, 34, 10, 100)] {
        bytes.extend_from_slice(&e.to_bytes());
    }
    std::fs::write(&file, &bytes).unwrap();
    let gc = run(&[
        "index", "add", "--dir", &s(&d), "--shard", "2", "--entries", &s(&file), "--gc", "200",
    ]);
    assert_eq!(gc.code, CODE_OK, "{:?}", gc.stderr);
    assert!(gc.stdout.contains("живых было 2, стало 0"), "{}", gc.stdout);
    remove(&d);
}

#[test]
fn index_create_without_epoch_refuses_to_publish() {
    let d = tmp("index-no-lease");
    let create = run(&["index", "create", "--dir", &s(&d), "--shard", "1"]);
    assert_eq!(create.code, CODE_OK, "{:?}", create.stderr);
    assert!(create.stdout.contains("ВНИМАНИЕ"), "{}", create.stdout);
    let file = d.join("one.bin");
    std::fs::write(&file, entry(9, 17, 1, 5).to_bytes()).unwrap();
    let add = run(&["index", "add", "--dir", &s(&d), "--shard", "1", "--entries", &s(&file)]);
    assert_eq!(add.code, CODE_FAILED, "{add:?}");
    assert!(add.stderr.contains("запись №1"), "{}", add.stderr);
    remove(&d);
}

#[test]
fn index_add_rejects_a_partial_record() {
    let d = tmp("index-partial");
    run(&["index", "create", "--dir", &s(&d), "--shard", "3", "--epoch", "1"]);
    let file = d.join("bad.bin");
    std::fs::write(&file, [0u8; 500]).unwrap();
    let add = run(&["index", "add", "--dir", &s(&d), "--shard", "3", "--entries", &s(&file)]);
    assert_eq!(add.code, CODE_FAILED, "{add:?}");
    assert!(add.stderr.contains("не кратен"), "{}", add.stderr);
    remove(&d);
}

#[test]
fn a_shard_number_outside_the_protocol_is_refused() {
    let d = tmp("index-shard-range");
    let o = run(&["index", "create", "--dir", &s(&d), "--shard", &SHARDS.to_string()]);
    assert_eq!(o.code, CODE_FAILED, "{o:?}");
    assert!(o.stderr.contains("ровно 64 шардов"), "{}", o.stderr);
    remove(&d);
}

#[test]
fn demo_runs_offline_and_calls_itself_a_surrogate() {
    let o = run(&["demo", "--intents", "16", "--queries", "3"]);
    assert_eq!(o.code, CODE_OK, "{:?}", o.stderr);
    assert!(o.stdout.contains("ВНИМАНИЕ: векторы НЕ семантические"), "{}", o.stdout);
    assert!(o.stdout.contains("средний recall@10"), "{}", o.stdout);
    assert!(o.stdout.contains("Чего здесь нет"), "{}", o.stdout);
    let too_big = run(&["demo", "--intents", "513"]);
    assert_eq!(too_big.code, CODE_FAILED, "{too_big:?}");
}

#[test]
fn a_real_process_returns_the_same_codes_as_run() {
    // Единственный тест, который поднимает бинарник: проверяет, что `main` не потерял коды и
    // порядок потоков (stdout до stderr), то есть ровно то, что `run` увидеть не может.
    let bin = env!("CARGO_BIN_EXE_vecdht-cli");
    let ok = Command::new(bin).args(["version"]).output().unwrap();
    assert!(ok.status.success(), "stderr: {}", String::from_utf8_lossy(&ok.stderr));
    assert!(String::from_utf8_lossy(&ok.stdout).contains("nlist 1024"));

    let usage = Command::new(bin).args(["artifact", "verify"]).output().unwrap();
    assert_eq!(usage.status.code(), Some(CODE_USAGE), "обязан быть код 1 (разбор аргументов)");

    let failed = Command::new(bin)
        .args(["artifact", "show", "--artifact", "Z:\\vecdht-нет-такого-каталога"])
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(CODE_FAILED), "обязан быть код 2 (выполнить нельзя)");
    assert!(failed.stdout.is_empty(), "отказ обязан писать в stderr, а не в stdout");
}

#[test]
fn help_and_unknown_flags_stay_code_usage() {
    assert_eq!(run(&["help", "index", "search"]).code, CODE_OK);
    assert!(run(&["help", "index", "search"]).stdout.contains("--clusters"));
    let o = run(&["index", "stats", "--dir", "x", "--shard", "1", "--verbose"]);
    assert_eq!(o.code, CODE_USAGE, "{o:?}");
    assert!(o.stderr.contains("не знает флага"), "{}", o.stderr);
    // Пустой argv — справка, а не ошибка: `vecdht-cli` без аргументов обязан объяснять, что умеет.
    assert_eq!(run(&[]).code, CODE_OK);
}

#[test]
fn agent_run_raises_a_listener_and_stops_on_the_registered_budget() {
    // Проверяется ровно то, чего не может увидеть клиентский путь: listener поднимается (адрес
    // печатается), цикл шагает вне вызовов, а отчёт о остановке называет счётчики. Ожидание
    // адреса без шага оставило бы процесс «слушающим» и молчащим — это и есть регрессия, ради
    // которой тест существует.
    let d = make_artifact("agent-run");
    let o = run(&[
        "agent", "run",
        "--artifact", &s(&d),
        "--seed", &"42".repeat(32),
        "--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
        "--status-sec", "0",
        "--run-seconds", "1",
    ]);
    assert_eq!(o.code, CODE_OK, "{:?}", o.stderr);
    assert!(o.stdout.contains("слушаю: /ip4/127.0.0.1/udp/"), "{}", o.stdout);
    assert!(o.stdout.contains("остановлен через"), "{}", o.stdout);
    assert!(o.stdout.contains("кадров 0"), "{}", o.stdout);
    // Строка на каждую транспортную ошибку — «ошибка транспорта: …» (единственное число), а сводка
    // всегда называет их число в родительном падеже («ошибок транспорта 0»). Проверяем отсутствие
    // именно построчных сообщений: их не должно быть на пустой сети.
    assert!(!o.stdout.contains("ошибка транспорта: "), "{}", o.stdout);

    // Без слушателя процесс бесполезен, и это отказ с кодом 2, а не «тихий клиент».
    let no_listen = run(&[
        "agent", "run", "--artifact", &s(&d), "--seed", &"42".repeat(32),
    ]);
    assert_eq!(no_listen.code, CODE_FAILED, "{no_listen:?}");
    assert!(no_listen.stderr.contains("--listen"), "{}", no_listen.stderr);
    remove(&d);
}

// §4.1/церемония двух машин: `cert issue` и файл `--members` адресуют узел owner_ed25519 и
// PeerId, а `node run` принимает seed. `key show` — единственный мост между ними. Тест сверяет
// печать с тем же кодом, что и узел (`Identity::from_seed`, `keys::peer_id`), а не с записанной
// константой: константа пережила бы смену формата PeerId и молчала бы.
#[test]
fn key_show_derives_the_same_names_the_node_uses() {
    let seed = [0x2au8; 32];
    let hex_seed = hex::encode(seed);
    let o = run(&["key", "show", "--seed", &hex_seed]);
    assert_eq!(o.code, CODE_OK, "{:?}", o.stderr);
    let id = Identity::from_seed(seed);
    let owner = hex::encode(id.pubkey());
    let peer = hex::encode(keys::peer_id(&id).to_bytes());
    assert!(o.stdout.contains(&format!("owner {owner}")), "{}", o.stdout);
    assert!(o.stdout.contains(&format!("peer_id {peer}")), "{}", o.stdout);
    assert_eq!(owner.len(), 64, "owner обязан быть 32 байта hex");
    assert!(!peer.is_empty(), "PeerId не бывает пустым");

    // Церемония идёт в два захода на двух машинах; расхождение между ними означало бы два
    // разных имени у одного seed.
    let again = run(&["key", "show", "--seed", &hex_seed]);
    assert_eq!(o.stdout, again.stdout);

    // Без seed пара не выводится ни из чего — отказ с кодом 2, как у остальных команд.
    let none = run(&["key", "show"]);
    assert_eq!(none.code, CODE_FAILED, "{none:?}");
    assert!(none.stderr.contains("--seed"), "{}", none.stderr);
}
