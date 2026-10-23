//! H-0085 / E-0085 · оракул 2/2: три неизмеренные ветки живой двери §4.2/§5.3.
//!
//! `E-0076` снял на этом же харнесе `Expired`, чужую сеть, кеш аутентификации и «вторую дверь».
//! Здесь добираются ветки чек-листа, которые не мерялись ни разу, и один вопрос, который делает
//! их полезными для оператора: **доходит ли имя отказа до встречной стороны**.
//!
//! * `:154` «время в `[valid_from, valid_until)`» — левая граница окна, `NotYetValid`;
//! * `:155` «`capacity_entries > 0` и `nonce` отсутствует в множестве отзывов» — нулевая ёмкость
//!   и живой отзыв;
//! * `:159` «узел, увидев отзыв, сбрасывает соединения и перестаёт подписывать» — что из этого
//!   происходит на самом деле и что при этом остаётся в локальных кешах.
//!
//! Стенд: один процесс, настоящий QUIC на loopback, `current_thread`, реальные настенные часы
//! (`service.rs:614` берёт `now_sec()`). Единица измерения — имя отказа и факт
//! (`is_authenticated`, код `Error`, `store.len()`, `provider_peers`), а не время: временных
//! гейтов в этом файле нет, поэтому правило 7 к циклу не применяется, а воспроизводимость
//! сверяется по blake3-свертке таблиц имён между профилями и прогонами (пороги (10)/(11)).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::{Multiaddr, PeerId};
use vecdht_artifact::reference_manifest;
use vecdht_crypto::cert::{sign_cert_identity, sign_revoke_identity};
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::{candidates, testing, Clock, ShardNode};
use vecdht_wire::cert::{NodeCert, CERT_VERSION, MAX_CERT_SHARDS};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{domain, CertRevoke, Codec, Handshake, ProtocolError, Role};

const SHARD: u16 = 7;
/// Второй шард стенда отзыва: наблюдатель держит другой шард, чтобы его членство и
/// провайдер-запись носителя не пересекались.
const SHARD_B: u16 = 9;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
/// Носитель кредашиала вне тройки сидов.
const PEER_SEED: u8 = 77;
/// Носитель отзыва: входит в ростер, поэтому его узел легитимно держит шард и объявляет его.
const VICTIM_SEED: u8 = 2;
/// Наблюдатель стенда отзыва. Он обязан быть **другой личностью**, чем носитель: первый прогон
/// взял его как `primary_seed(SHARD_B)`, а §9.3 привёл к тому же сид 2, и узел позвонил сам себе
/// (`dial local peer id`) — стенд рассыпался не на предсказании, а на идентификаторах. Подбирается
/// из троек сидов так, чтобы не совпасть с носителем (см. `watcher_seed()`).
const WATCHER_SEED_CANDIDATES: [u8; 3] = [1, 2, 3];

fn dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("vecdht-s53-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("временный каталог теста");
    p
}

fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

fn cfg(listen: Multiaddr) -> NetConfig {
    NetConfig {
        listen: vec![listen],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-e0085/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
    }
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

/// (О9), пороги (10)/(11): свёртка таблицы имён. Это blake3 из `vecdht-crypto`
/// (`ids::content_hash`), а не sha2: `sha2` в проекте прямой зависимостью не является, а порог (0)
/// запрещает добавлять зависимости ради оракула.
fn digest(rows: &[String]) -> String {
    hex::encode(vecdht_crypto::ids::content_hash(rows.join("\n").as_bytes()))
}

/// Личность наблюдателя: сид ростера, не совпадающий с носителем. Первичность по §9.3 здесь не
/// нужна — наблюдатель только смотрит, а два узла с одним `PeerId` стендом быть не могут.
fn watcher_seed() -> u8 {
    *WATCHER_SEED_CANDIDATES
        .iter()
        .find(|s| **s != VICTIM_SEED)
        .expect("наблюдатель обязан отличаться от носителя")
}

/// Primary шарда по порядку §9.3: узел выводит его из ростера, и тест не вправе назначить
/// primary первым сидом — иначе публикация получила бы `NOT_OWNER`.
fn primary_seed(shard: u16) -> u8 {
    let order = candidates::ordered(1, shard, &testing::holders(&SEEDS));
    *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("primary — один из тестовых сидов")
}

/// Узел одного шарда с genesis-эпохой и кредашиалом `0..u32::MAX`.
fn index_service_shard(seed: u8, shard: u16, dir: &Path, listen: Multiaddr) -> NetService {
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let mut node = ShardNode::open(
        dir,
        shard,
        id.clone(),
        peer.to_bytes(),
        testing::params(POW),
        testing::authority_set(),
        testing::holders(&SEEDS),
    )
    .expect("открыть узел шарда");
    let now_bucket = Clock::at(now_sec()).bucket;
    node.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(shard, &SEEDS, 0)),
        testing::clock(now_bucket),
    )
    .expect("genesis");
    let cert = testing::node_cert(seed, peer.to_bytes(), vec![shard], Role::IndexNode, 0, u32::MAX);
    NetService::new(
        id,
        Role::IndexNode,
        Some(cert),
        vec![node],
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис узла")
}

fn agent_service(seed: u8, listen: Multiaddr) -> NetService {
    NetService::new(
        testing::identity(seed),
        Role::Agent,
        None,
        Vec::new(),
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис агента")
}

/// Пир с кредашиалом произвольной формы: роль узла, шардов не держит.
fn raw_cert_service(seed: u8, listen: Multiaddr, cert: NodeCert) -> NetService {
    NetService::new(
        testing::identity(seed),
        Role::IndexNode,
        Some(cert),
        Vec::new(),
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис с кредашиалом")
}

/// Пир с кредашиалом заданного окна действия.
fn cert_service(seed: u8, listen: Multiaddr, valid_from: u32, valid_until: u32) -> NetService {
    let peer = keys::peer_id(&testing::identity(seed));
    raw_cert_service(
        seed,
        listen,
        testing::node_cert(
            seed,
            peer.to_bytes(),
            vec![SHARD],
            Role::IndexNode,
            valid_from,
            valid_until,
        ),
    )
}

/// Переподписать тело порогом: любое изменённое поле тела делает прежние подписи мусором, а тест
/// обязан отличать «отказ по этому полю» от «отказа по подписи».
fn resign(mut c: NodeCert) -> NodeCert {
    c.authority_sigs.clear();
    for a in testing::authorities().iter().take(testing::authority_set().threshold) {
        c = sign_cert_identity(&c, a);
    }
    c
}

/// Приветствие узла с произвольным кредашиалом: версия модели и genesis — корректные, чтобы
/// отказ был именно по кредашиалу.
fn door_greeting(role: Role, cert: Option<&NodeCert>) -> Vec<u8> {
    Handshake {
        role,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        model_version: reference_manifest().model_version,
        genesis_hash: testing::genesis_hash(),
        cert: cert.map(NodeCert::encode).unwrap_or_default(),
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

async fn wait_listen(s: &mut NetService) -> Multiaddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(a) = s.listen_addrs().first() {
            return a.clone();
        }
        assert!(tokio::time::Instant::now() < deadline, "listener не поднялся за 10 с");
        s.step().await;
    }
}

async fn pump_until<F>(a: &mut NetService, b: &mut NetService, mut done: F)
where
    F: FnMut(&NetService, &NetService) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if done(a, b) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "состояние не наступило за 30 с; ошибки A={:?} B={:?}",
            a.take_errors(),
            b.take_errors()
        );
        a.step().await;
        b.step().await;
    }
}

fn error_of(frames: &[(PeerId, Vec<u8>)]) -> Option<ProtocolError> {
    frames.iter().find_map(|(_, f)| {
        let k = decode_frame(f).ok()?;
        (k.header.kind == Kind::Error).then(|| ProtocolError::decode(f).ok())?
    })
}

/// Отправить кадр и дождаться первого `Error`. Ответ на отказ приходит тем же путём, что и
/// прикладной ответ, поэтому код виден у инициатора (урок `E-0076` (2)).
async fn ask_code(
    node: &mut NetService,
    peer: &mut NetService,
    target: PeerId,
    frame: Vec<u8>,
    label: &str,
) -> Option<String> {
    let _ = peer.take_inbox();
    assert!(peer.send_frame(target, frame), "{label}: пир не может отправить кадр");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut frames = Vec::new();
    while tokio::time::Instant::now() < deadline {
        node.step().await;
        peer.step().await;
        frames.extend(peer.take_inbox());
        if let Some(e) = error_of(&frames) {
            return Some(e.code);
        }
    }
    None
}

/// Прокачать оба сервиса `secs`, ничего не наблюдая. Кадрам, ушедшим до отзыва, надо дать
/// разойтись: без этой паузы первым «ответом» на новый запрос оказывался `NOT_OWNER` из
/// membership-обмена (§9.8/ADR-0017), а не реакция узла на наш кадр.
async fn settle(a: &mut NetService, b: &mut NetService, secs: u64) {
    let until = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < until {
        a.step().await;
        b.step().await;
    }
}

/// Отправить кадр и разобрать, чем он кончился: (код `Error`, `retry_after_ms`, `шард`), число
/// `MatchResult` — то есть настоящих данных — и ошибки транспорта у отправителя. `ProtocolError`
/// не несёт идентификатора запроса (в сообщении его нет), поэтому ответ отделяется от прочего
/// трафика только вычищенной почтой и паузой `settle`.
async fn probe_answer(
    node: &mut NetService,
    peer: &mut NetService,
    target: PeerId,
    frame: Vec<u8>,
    secs: u64,
) -> (bool, Option<(String, u32, u16)>, usize, Vec<String>) {
    let sent = peer.send_frame(target, frame);
    let mut answers = Vec::new();
    let mut errs = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        node.step().await;
        peer.step().await;
        answers.extend(peer.take_inbox());
        errs.extend(peer.take_errors());
    }
    let matched = answers
        .iter()
        .filter(|(_, f)| decode_frame(f).is_ok_and(|k| k.header.kind == Kind::MatchResult))
        .count();
    let code = error_of(&answers).map(|e| (e.code, e.retry_after_ms, e.shard));
    (sent, code, matched, errs)
}

/// Ответ двери одним токеном без пробелов: `КОД:retry_after_ms:shard`, либо `нет` — отказа не
/// было. Формат выбран под экстрактор helper'а: `{:?}` кортежа печатает пробелы, и значение в
/// логе терялось бы на середине (тот же класс ошибки, что ДИАГНОЗ-4 в `E-0082`).
fn answer_token(a: &Option<(String, u32, u16)>) -> String {
    match a {
        Some((c, r, s)) => format!("{c}:{r}:{s}"),
        None => "нет".to_string(),
    }
}

fn signed_publish(agent: &vecdht_crypto::Identity, bucket: u32) -> Vec<u8> {    let spec = testing::PublishSpec {
        agent,
        vec_q: &testing::vector(3),
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch: 1,
        published_bucket: bucket,
        ttl_buckets: 225,
        bits: POW,
    };
    let msg = spec.msg(Vec::new());
    let sig = agent.sign_body(domain::PUBLISH, Kind::Publish, &msg.body_bytes());
    msg.encode_signed(&sig)
}

fn find_frame(seed: u8, salt: u64) -> Vec<u8> {
    testing::find_frame(&testing::identity(seed), &testing::vector(3), &[CLUSTER], 5, salt)
}

/// Кредашиал носителя `PEER_SEED`, выданный ровно этому транспорту.
fn base_cert(peer: PeerId) -> NodeCert {
    testing::node_cert(PEER_SEED, peer.to_bytes(), vec![SHARD], Role::IndexNode, 0, u32::MAX)
}

// --- (О4), порог (5): одиннадцать причин — один код -------------------------------------------

#[test]
fn eleven_refusal_causes_all_speak_cert_invalid() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("codes");
        let mut node = index_service_shard(primary_seed(SHARD), SHARD, &d, quic_addr());
        let mut agent = agent_service(PEER_SEED, quic_addr());
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;

        let now = now_sec() as u32;
        let c_version = {
            let mut c = base_cert(ap);
            c.version = CERT_VERSION + 1;
            resign(c)
        };
        let c_genesis = {
            let mut c = base_cert(ap);
            c.genesis_hash = [9u8; 32];
            resign(c)
        };
        let c_capacity = {
            let mut c = base_cert(ap);
            c.capacity_entries = 0;
            resign(c)
        };
        let c_shards = {
            let mut c = base_cert(ap);
            c.shards = (0..=(MAX_CERT_SHARDS as u16)).collect();
            resign(c)
        };
        let c_notyet = testing::node_cert(
            PEER_SEED,
            ap.to_bytes(),
            vec![SHARD],
            Role::IndexNode,
            now + 3_600,
            now + 7_200,
        );
        let c_expired = testing::node_cert(
            PEER_SEED,
            ap.to_bytes(),
            vec![SHARD],
            Role::IndexNode,
            0,
            now - 1,
        );
        let c_few_sigs = {
            let mut c = base_cert(ap);
            c.authority_sigs.truncate(testing::authority_set().threshold - 1);
            c
        };
        let c_many_sigs = {
            let mut c = base_cert(ap);
            while c.authority_sigs.len() < 17 {
                c.authority_sigs.push([0xeeu8; 64]);
            }
            c
        };
        let c_time_order = {
            let mut c = base_cert(ap);
            c.valid_from = now + 3_600;
            c.valid_until = now;
            resign(c)
        };
        let c_other_peer = testing::node_cert(
            PEER_SEED,
            vec![0x00, 0x24, 0x00],
            vec![SHARD],
            Role::IndexNode,
            0,
            u32::MAX,
        );
        let hello = |c: &NodeCert| door_greeting(Role::IndexNode, Some(c));

        let causes: Vec<(&str, Vec<u8>)> = vec![
            ("version", hello(&c_version)),
            ("genesis", hello(&c_genesis)),
            ("capacity_zero", hello(&c_capacity)),
            ("shards_65", hello(&c_shards)),
            ("not_yet_valid", hello(&c_notyet)),
            ("expired", hello(&c_expired)),
            ("below_threshold", hello(&c_few_sigs)),
            ("sigs_17", hello(&c_many_sigs)),
            ("from_after_until", hello(&c_time_order)),
            ("other_peer_id", hello(&c_other_peer)),
            ("agent_with_cert", door_greeting(Role::Agent, Some(&base_cert(ap)))),
        ];

        let mut codes = BTreeSet::new();
        let mut refused = 0usize;
        let mut rows = Vec::new();
        for (label, frame) in &causes {
            let code = ask_code(&mut node, &mut agent, np, frame.clone(), label).await;
            match code {
                Some(c) => {
                    refused += 1;
                    codes.insert(c.clone());
                    rows.push(format!("{label}={c}"));
                    println!("МЕРЕНО probe_{label}_code={c}");
                }
                None => {
                    rows.push(format!("{label}=timeout"));
                    println!("МЕРЕНО probe_{label}_code=timeout");
                }
            }
        }
        let responder_errors = node.take_errors();
        let responder_logged = responder_errors
            .iter()
            .filter(|e| {
                e.contains("кредашиал отвергнут")
                    || e.contains("CertRejected")
                    || e.contains("not valid yet")
                    || e.contains("capacity is zero")
            })
            .count();
        println!("МЕРЕНО door_probes={}", causes.len());
        println!("МЕРЕНО door_refused={refused}");
        println!("МЕРЕНО door_distinct_codes={}", codes.len());
        println!("МЕРЕНО door_responder_logged={responder_logged}");
        println!("МЕРЕНО door_digest={}", digest(&rows));

        assert_eq!(refused, causes.len(), "(О4) не все пробы получили отказ");
        assert_eq!(codes.len(), 1, "(О4) различных кодов отказа больше одного: {codes:?}");
        assert!(codes.contains("CERT_INVALID"), "(О4) код отказа — не CERT_INVALID: {codes:?}");
        assert_eq!(
            responder_logged, 0,
            "(О4) отказавшая сторона записала причину себе в ошибки: {responder_errors:?}"
        );
        assert!(agent.is_authenticated(&np), "(О4) пробы вытеснили прежнюю личность агента");
        println!("МЕРЕНО gate5=1");
        let _ = std::fs::remove_dir_all(&d);
    });
}

// --- (О5), порог (6): ветка `valid_from` на живой двери ---------------------------------------

#[test]
fn a_cert_that_is_not_valid_yet_is_refused_and_its_publish_still_lands() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("notyet");
        let mut node = index_service_shard(primary_seed(SHARD), SHARD, &d, quic_addr());
        let now = now_sec() as u32;
        let mut peer = cert_service(PEER_SEED, quic_addr(), now + 3_600, now + 7_200);
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut peer).await;
        peer.dial(addr).expect("dial узла");
        let (np, pp) = (node.peer_id(), peer.peer_id());

        // Положительное условие: пир принял узла. Появление ошибки — не «состояствие
        // наступило» (ДИАГНОЗ-2 из `E-0076`).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut perrs = Vec::new();
        let mut nerrs = Vec::new();
        while !peer.is_authenticated(&np) && tokio::time::Instant::now() < deadline {
            node.step().await;
            peer.step().await;
            nerrs.extend(node.take_errors());
            perrs.extend(peer.take_errors());
        }
        assert!(
            peer.is_authenticated(&np),
            "(О5) пир не принял узла: ошибки пира={perrs:?}, узла={nerrs:?}"
        );
        // Второе положительное условие: ждём именно строку отказа у инициатора, а не «ошибки
        // появились». Снимать её сразу после первого условия было гонкой — кадр `Error`
        // возвращается по тому же соединению полшагом позже, чем пир успевает принять узла (тот
        // же урок, что ДИАГНОЗ-2). Списки сторон разделены: «причина не доехала» меряется по
        // логам инициатора, а «отказавший молчит» — по логам узла.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut hidden = false;
        while !hidden && tokio::time::Instant::now() < deadline {
            node.step().await;
            peer.step().await;
            nerrs.extend(node.take_errors());
            perrs.extend(peer.take_errors());
            hidden = perrs.iter().any(|e| e.contains("кредашиал не разобран"));
        }
        let refused = !node.is_authenticated(&pp);
        let reason_leaked =
            perrs.iter().any(|e| e.contains("not valid yet") || e.contains("ещё не действителен"));
        println!("МЕРЕНО gate6a_refused={}", if refused { 1 } else { 0 });
        println!("МЕРЕНО gate6b_hidden={}", if hidden && !reason_leaked { 1 } else { 0 });
        println!(
            "МЕРЕНО gate6b_responder_logged={}",
            nerrs.iter().filter(|e| e.contains("кредашиал отвергнут")).count()
        );
        println!("МЕРЕНО gate6b_responder_text={nerrs:?}");
        assert!(refused, "(О5) узел аутентифицировал недействующий кредашиал");
        assert!(hidden, "(О5) отказа на стороне инициатора не видно: {perrs:?}");
        assert!(!reason_leaked, "(О5) причина отказа доехала до пира: {perrs:?}");

        // Соединение живёт: прикладной кадр получает ответ, а не таймаут.
        let code = ask_code(&mut node, &mut peer, np, find_frame(PEER_SEED, 4244), "notyet-find")
            .await
            .expect("(О5) ответа на кадр нет — соединения как будто нет");
        println!("МЕРЕНО gate6c_answered=1 gate6c_code={code}");
        assert_eq!(code, "DENIED", "(О5) кадр от неаутентифицированного пира ответил другим кодом");

        // Третья фикция `E-0076` на второй ветке чек-листа: gossip кладёт запись в индекс.
        let bucket = Clock::at(now_sec()).bucket;
        let publish = signed_publish(&testing::identity(PEER_SEED), bucket);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let _ = peer.publish_gossip(SHARD, publish.clone());
            for _ in 0..10 {
                peer.step().await;
                node.step().await;
            }
            if node.node(SHARD).is_some_and(|n| n.store.len() == 1) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "(О5) gossip-публикация не дошла за 30 с; ошибки узла={:?}",
                node.take_errors()
            );
        }
        println!("МЕРЕНО gate6d_stored=1");
        // Свёртка содержит только те пять фактов, что не зависят от расписания шагов: счётчик
        // локальных логов (`gate6b_responder_logged`) в неё не входит — он меряется как факт и
        // печатается, но между прогонами обязан совпадать именно как число, а не как часть
        // свёртки таблицы (иначе порог (11) проверял бы тайминги вместо таблицы имён).
        println!(
            "МЕРЕНО notyet_digest={}",
            digest(&[
                format!("refused={}", refused as u8),
                format!("reason_leaked={}", reason_leaked as u8),
                format!("form_hidden={}", hidden as u8),
                format!("app_code={code}"),
                "gossip_stored=1".to_string(),
            ])
        );
        assert!(
            !node.is_authenticated(&pp),
            "(О5) запись пришла мимо handshake, а пир тем временем аутентифицирован"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}

// --- (О6), порог (7): `capacity_entries > 0` на живой двери ----------------------------------

#[test]
fn a_cert_with_zero_capacity_is_refused_on_the_door_too() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = dir("zerocap");
        let mut node = index_service_shard(primary_seed(SHARD), SHARD, &d, quic_addr());
        let mut agent = agent_service(PEER_SEED, quic_addr());
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;

        // Тот же трюк, что и в `E-0076` (2): отказ предъявляется как прикладной кадр, чтобы код
        // вернулся инициатору, а не растворился в разборе ответа.
        let signed_cert = {
            let mut c = base_cert(ap);
            c.capacity_entries = 0;
            resign(c)
        };
        let mut unsigned_cert = signed_cert.clone();
        unsigned_cert.authority_sigs.clear();

        let signed = ask_code(&mut node, &mut agent, np, hello_cert(&signed_cert), "zerocap-signed")
            .await
            .unwrap_or_default();
        let unsigned =
            ask_code(&mut node, &mut agent, np, hello_cert(&unsigned_cert), "zerocap-unsigned")
                .await
                .unwrap_or_default();
        println!("МЕРЕНО gate7_signed_code={signed} gate7_unsigned_code={unsigned}");
        assert_eq!(signed, "CERT_INVALID", "(О6) подписанный нулевой кредашиал принят");
        assert_eq!(unsigned, "CERT_INVALID", "(О6) неподписанный нулевой кредашиал принят");

        // Прямой вызов двери на том же теле: имя — ступень 3, то есть до порога.
        let (set, _) = (testing::authority_set(), ());
        let direct = vecdht_crypto::cert::verify_cert(
            &unsigned_cert,
            &set,
            &testing::genesis_hash(),
            now_sec() as u32,
            |_| false,
        )
        .expect_err("(О6) нулевая ёмкость прошла проверку");
        println!("МЕРЕНО gate7_direct_name={direct:?}");
        println!(
            "МЕРЕНО zerocap_digest={}",
            digest(&[
                format!("signed={signed}"),
                format!("unsigned={unsigned}"),
                format!("direct={direct:?}"),
            ])
        );
        assert!(
            matches!(direct, vecdht_crypto::cert::CertError::ZeroCapacity),
            "(О6) имя отказа — не ZeroCapacity: {direct:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Приветствие от имени узла с указанным кредашиалом (роль `IndexNode`).
fn hello_cert(c: &NodeCert) -> Vec<u8> {
    door_greeting(Role::IndexNode, Some(c))
}

// --- (О7), порог (8): правило суммы §9.2 -------------------------------------------------------

#[test]
fn the_sum_capacity_rule_of_9_2_has_no_mechanism() {
    let capacity = 1_000u64;
    let load = capacity * 9 / 10;
    let holders = vec![candidates::Holder {
        owner_ed25519: testing::identity(4).pubkey(),
        dht_peer_id: vec![0x00, 0x24, 0x00],
        capacity_entries: capacity,
    }];
    let in_shard = |shard: u16| {
        candidates::select(1, shard, &holders, 3, load)
            .iter()
            .any(|h| h.owner_ed25519 == holders[0].owner_ed25519)
    };
    let a = in_shard(SHARD);
    let b = in_shard(SHARD_B);
    // Фальсификатор: на одном шарде фильтр работает — при нагрузке выше ёмкости держателя нет.
    let over = candidates::select(1, SHARD, &holders, 3, capacity * 2).is_empty();
    println!("МЕРЕНО sum_rule_capacity={capacity} sum_rule_load_per_shard={load}");
    println!("МЕРЕНО sum_rule_shard7={}", if a { 1 } else { 0 });
    println!("МЕРЕНО sum_rule_shard9={}", if b { 1 } else { 0 });
    println!("МЕРЕНО sum_rule_over_single_shard_excluded={}", if over { 1 } else { 0 });
    println!("МЕРЕНО gate8={}", if a && b { 1 } else { 0 });
    assert!(a && b, "(О7) держатель с суммарной нагрузкой 1,8×capacity исключён: {a} {b}");
    assert!(over, "(О7) фильтр ёмкости не работает даже на одном шарде");
}

// --- (О8), порог (9): отзыв на живой двери ----------------------------------------------------

fn revoke_for(nonce: [u8; 16]) -> CertRevoke {
    let mut r = CertRevoke {
        nonce,
        revoked_at: now_sec() as u32,
        reason: "E-0085: отзыв в стенде".to_string(),
        authority_sigs: Vec::new(),
    };
    for a in testing::authorities().iter().take(testing::authority_set().threshold) {
        r = sign_revoke_identity(&r, a);
    }
    r
}

#[test]
fn a_live_revoke_forgets_the_peer_but_not_the_provider_cache() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let dv = dir("revoke-v");
        let db = dir("revoke-b");
        let mut victim = index_service_shard(VICTIM_SEED, SHARD, &dv, quic_addr());
        let mut watcher = index_service_shard(watcher_seed(), SHARD_B, &db, quic_addr());
        let va = wait_listen(&mut victim).await;
        let wb = wait_listen(&mut watcher).await;
        victim.dial(wb.clone()).expect("dial наблюдателя");
        let (vp, wp) = (victim.peer_id(), watcher.peer_id());
        assert_ne!(vp, wp, "(О8) узел и наблюдатель — одна личность; стенд невозможно собрать");
        assert_ne!(VICTIM_SEED, watcher_seed(), "(О8) сиды носителя и наблюдателя совпадают");
        pump_until(&mut victim, &mut watcher, |x, y| {
            x.is_authenticated(&wp) && y.is_authenticated(&vp)
        })
        .await;
        println!("МЕРЕНО revoke_handshake_done=1");

        // Наблюдатель должен сначала увидеть носителя провайдером шарда — иначе measuring
        // нечего (тот же кадр ожидания, что `transport.rs:546…568`).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut found = Vec::new();
        let mut last_query = 0u64;
        while tokio::time::Instant::now() < deadline {
            victim.step().await;
            watcher.step().await;
            let now = now_sec();
            if now != last_query {
                last_query = now;
                watcher.find_providers(SHARD).expect("kad-запрос провайдеров");
            }
            found = watcher.provider_peers(SHARD);
            if found.contains(&vp) {
                break;
            }
        }
        let seen_before = found.contains(&vp);
        println!(
            "МЕРЕНО provider_seen_before={} provider_count_before={}",
            if seen_before { 1 } else { 0 },
            found.len()
        );
        assert!(
            seen_before,
            "(О8) носитель не стал провайдером шарда: kad-пиров={}, объявления={}, ошибки={:?}",
            watcher.kad_peer_count(),
            victim.provider_announcements,
            watcher.take_errors()
        );

        // Носитель рассылает отзыв о собственном ключе: по спеке это кадр авторитетов, и
        // отправитель не обязан получать свою же рассылку обратно.
        let nonce = [VICTIM_SEED; 16];
        let revoke = revoke_for(nonce);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        while !(watcher.revocation_count() == 1 && watcher.is_revoked_nonce(&nonce)) {
            assert!(tokio::time::Instant::now() < deadline, "(О8) отзыв не дошёл за 40 с");
            let _ = victim.publish_revoke(&revoke);
            victim.step().await;
            watcher.step().await;
        }
        let forgotten = !watcher.is_authenticated(&vp);
        let self_revoked_yet = victim.is_self_revoked();
        println!(
            "МЕРЕНО gate9a_forgotten={} victim_self_revoked_before_b={}",
            if forgotten { 1 } else { 0 },
            if self_revoked_yet { 1 } else { 0 }
        );
        assert!(forgotten, "(О8) наблюдатель не забыл носителя отзыва");
        assert!(!self_revoked_yet, "(О8) отправитель получил собственный отзыв — стенд иной, чем заявлено");

        // (б) прикладной кадр носителя после отзыва. Разведка до коммита пре-регистрации показала,
        // что `apply_revoke` зовёт не только `forget_peer`, но и `disconnect_peer_id`
        // (`service.rs:825…833`): прежнее соединение сброшено, и «второй двери» из `E-0076` здесь
        // уже нет — вместо `DENIED` кадр уходит в транспорт, которого нет. Меряются три числа:
        // получил ли носитель **данные** (`MatchResult`), чем кончился запрос и знала ли его
        // собственная таблица об отзыве.
        settle(&mut watcher, &mut victim, 3).await;
        let _ = victim.take_inbox();
        let _ = watcher.take_inbox();
        let victim_still_auth = victim.is_authenticated(&wp);
        let (sent_reset, answer_reset, data_reset, errs_reset) =
            probe_answer(&mut watcher, &mut victim, wp, find_frame(VICTIM_SEED, 4245), 15).await;
        println!(
            "МЕРЕНО gate9b_reset_send={} gate9b_reset_answer={} \
             gate9b_reset_data={data_reset} gate9b_reset_victim_auth={}",
            if sent_reset { 1 } else { 0 },
            answer_token(&answer_reset),
            if victim_still_auth { 1 } else { 0 }
        );
        println!("МЕРЕНО gate9b_reset_victim_errors={errs_reset:?}");
        let gate9b = data_reset == 0 && victim_still_auth;
        println!("МЕРЕНО gate9b={}", if gate9b { 1 } else { 0 });
        assert_eq!(data_reset, 0, "(О8)(б) отозванный пир получил данные с шарда");
        assert!(victim_still_auth, "(О8)(б) таблица носителя всё-таки знает об отзыве");

        // (д) новое соединение после отзыва: чем для носителя выглядит отказ двери.
        victim.dial(wb).expect("повторный dial наблюдателя");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut verrs = Vec::new();
        while tokio::time::Instant::now() < deadline {
            victim.step().await;
            watcher.step().await;
            verrs.extend(victim.take_errors());
            if verrs.iter().any(|e| e.contains("handshake")) {
                break;
            }
        }
        let werrs = watcher.take_errors();
        let reason_local = werrs.iter().any(|e| e.contains("revoked") || e.contains("отзыв"));
        let distorted = verrs.iter().any(|e| e.contains("не разобран") && e.contains("bad enum value 2"));
        println!("МЕРЕНО gate9e_victim_sees={verrs:?}");
        println!("МЕРЕНО gate9e_watcher_sees={werrs:?}");
        println!(
            "МЕРЕНО gate9e_reason_local={} gate9e_form_distorted={}",
            if reason_local { 1 } else { 0 },
            if distorted { 1 } else { 0 }
        );
        assert!(distorted, "(О8)(д) отказ двери не стал для инициатора ошибкой разбора: {verrs:?}");
        assert!(reason_local, "(О8)(д) проверяющая сторона не знает причину: {werrs:?}");
        let (sent_new, answer_new, data_new, _) =
            probe_answer(&mut watcher, &mut victim, wp, find_frame(VICTIM_SEED, 4246), 15).await;
        println!("МЕРЕНО gate9e_new_send={}", if sent_new { 1 } else { 0 });
        println!(
            "МЕРЕНО gate9e_new_answer={} gate9e_new_data={data_new}",
            answer_token(&answer_new)
        );
        assert_eq!(data_new, 0, "(О8)(д) на новом соединении отозванный пир получил данные");

        // (в) локальный кеш провайдеров не сократился: `forget_peer` его не трогает.
        let after = watcher.provider_peers(SHARD);
        println!("МЕРЕНО provider_count_after={} gate9c={}", after.len(), if after.contains(&vp) { 1 } else { 0 });
        assert!(after.contains(&vp), "(О8) provider_peers всё-таки почистили");

        // (г) носитель узнаёт отзыв о себе и замолкает: не отправляет, не публикует, не
        // аутентифицирует.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        while !victim.is_self_revoked() {
            assert!(tokio::time::Instant::now() < deadline, "(О8) отзыв о себе не дошёл");
            let _ = watcher.publish_revoke(&revoke);
            victim.step().await;
            watcher.step().await;
        }
        let silent_send = !victim.send_frame(wp, find_frame(VICTIM_SEED, 4247));
        let bucket = Clock::at(now_sec()).bucket;
        let silent_gossip = victim
            .publish_gossip(SHARD, signed_publish(&testing::identity(VICTIM_SEED), bucket))
            .is_err();
        let errors = victim.take_errors();
        let logged = errors.iter().any(|e| e.contains("отозван"));
        println!(
            "МЕРЕНО gate9d_send={} gate9d_gossip={} gate9d_logged={}",
            if silent_send { 1 } else { 0 },
            if silent_gossip { 1 } else { 0 },
            if logged { 1 } else { 0 }
        );
        assert!(silent_send, "(О8) отозванный узел отправляет кадры");
        assert!(silent_gossip, "(О8) отозванный узел публикует в темы шардов");
        assert!(logged, "(О8) отозванный узел не записал себе причину молчания: {errors:?}");

        // Живой узел звонит отозванному: рукопожатия не будет ни в одну сторону.
        watcher.dial(va).expect("dial носителя после отзыва");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut werrs = Vec::new();
        while tokio::time::Instant::now() < deadline {
            victim.step().await;
            watcher.step().await;
            werrs.extend(watcher.take_errors());
            if werrs.iter().any(|e| e.contains("handshake")) {
                break;
            }
        }
        let still_refused = !victim.is_authenticated(&wp) && !watcher.is_authenticated(&vp);
        println!("МЕРЕНО gate9d_refuses_handshake={}", if still_refused { 1 } else { 0 });
        assert!(still_refused, "(О8) отозванный узел кого-то аутентифицировал: {werrs:?}");

        // (а) форма отказа зависит от того, кто говорит. Отказавшая сторона ничего не пишет: у
        // неё нет события отказа, есть только выданный код. Проверяющая сторона знает причину —
        // но только когда проверяет чужой кредашиал сама; отказ на *своём* приветствии приходит
        // как кадр `Error`, который разбор приветствия не понимает (см. (д)).
        let verrs_final = victim.take_errors();
        let refuser_silent = !verrs_final.iter().any(|e| e.contains("кредашиал отвергнут"));
        println!("МЕРЕНО gate9a_refuser_silent={}", if refuser_silent { 1 } else { 0 });
        println!("МЕРЕНО gate9a_victim_text={verrs_final:?}");
        println!("МЕРЕНО gate9a_watcher_text={werrs:?}");
        assert!(refuser_silent, "(О8)(а) отказавшая сторона записала отказ себе: {verrs_final:?}");

        println!(
            "МЕРЕНО revoke_digest={}",
            digest(&[
                format!("provider_seen_before={}", seen_before as u8),
                format!("forgotten={}", forgotten as u8),
                format!("self_revoked_before={}", self_revoked_yet as u8),
                format!("reset_send={}", sent_reset as u8),
                format!("reset_answer={answer_reset:?}"),
                format!("reset_data={data_reset}"),
                format!("victim_still_auth={}", victim_still_auth as u8),
                format!("new_answer={answer_new:?}"),
                format!("new_send={}", sent_new as u8),
                format!("new_data={data_new}"),
                format!("reason_local={}", reason_local as u8),
                format!("form_distorted={}", distorted as u8),
                format!("provider_kept_after={}", after.contains(&vp) as u8),
                format!("silent_send={}", silent_send as u8),
                format!("silent_gossip={}", silent_gossip as u8),
                format!("victim_self_logged={}", logged as u8),
                format!("still_refused={}", still_refused as u8),
                format!("refuser_silent={}", refuser_silent as u8),
            ])
        );
        let _ = std::fs::remove_dir_all(&dv);
        let _ = std::fs::remove_dir_all(&db);
    });
}
