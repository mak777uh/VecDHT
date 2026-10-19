//! Golden-векторы `vecdht-wire` (спека §5.1: «правила кодирования проверяются golden-векторами»,
//! гейт P2 в §20: побайтовое совпадение на двух разных машинах).
//!
//! Фикстура — текстовый файл `tests/golden/vectors.txt` вида `ключ=hex`. Он проверяется в CI
//! на любой платформе без генерации: если байты канонического кодирования изменились, тест
//! падает с именем ключа. Перезапись — только явно:
//!
//! ```text
//! VEC_DHT_GOLDEN=1 cargo test -p vecdht-wire --test golden_vectors
//! ```
//!
//! Что зафиксировано и почему этого достаточно:
//!
//! * полный кадр (заголовок + тело) для каждого сообщения — фиксирует layout головы, порядок
//!   полей и little-endian;
//! * каноническое тело каждого сообщения отдельно — чтобы расхождение показывало, где именно
//!   сломалось: в заголовке или в схеме;
//! * `sig_input` для каждого подписываемого типа — фиксирует доменную строку и вход подписи
//!   (§5.2), то есть переносимость подписи между сборками;
//! * TLV-хвост с неизвестным тегом и кадр с зарезервированным флагом — фиксирует, что схема
//!   эволюционирует хвостом, а не перекодировкой;
//! * `NodeCert` (подписываемая часть и полный байт) и DHT-ключ шарда.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vecdht_wire::cert::NodeCert;
use vecdht_wire::frame::{
    encode_frame, sig_input, Kind, FLAG_RESERVED_MASK, FLAG_SIGNED, PROTOCOL_VERSION,
};
use vecdht_wire::messages::{
    domain, encode_mark, err_code, ArtifactAnnounce, CertRevoke, Codec, DeleteOp, Find, Handshake,
    InsertOp, IntentTextRequest, IntentTextResponse, LeaseGrant, LeaveNotice, Match, MatchResult,
    Member, MembershipUpdate, OpKind, ProtocolError, Publish, PublishAck, RendezvousAccept,
    ReplicateOp, Role, WalPullRequest, WalPullResponse, TLV_BATCH_HINT, TLV_ROLE_SLOT,
};
use vecdht_wire::{decode_frame, shard_provider_key, DecodeError, DIM, MAX_BODY_LEN};

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/vectors.txt")
}

fn vec_q(pattern: i32) -> [i8; DIM] {
    let mut v = [0i8; DIM];
    for (i, x) in v.iter_mut().enumerate() {
        *x = (i as i32 % pattern - (pattern / 2)) as i8;
    }
    v
}

// ---------------------------------------------------------------------------
// Образцы: значения фиксированы буквально, без rng и без времени.
// ---------------------------------------------------------------------------

fn m_handshake() -> Handshake {
    Handshake {
        role: Role::IndexNode,
        preprocessing_version: 3,
        model_version: "granite-embedding-97m-v2".into(),
        genesis_hash: [0x11; 32],
        cert: vec![0x9C; 64],
        tlv: vec![],
    }
}

fn m_error() -> ProtocolError {
    ProtocolError { code: err_code::BUSY.into(), retry_after_ms: 250, shard: 12 }
}

fn m_publish() -> Publish {
    Publish {
        preprocessing_version: 3,
        cluster_id: 777,
        vec_q: vec_q(251),
        owner_ed25519: [0xA1; 32],
        ttl_buckets: 225,
        published_bucket: 1_700_000_000 / 16,
        pow_bits: 24,
        pow_nonce: 0x0102_0304_0506_0708,
        intent_id: [0xB2; 32],
        tlv: vec![],
    }
}

fn m_publish_tlv() -> Publish {
    Publish {
        tlv: vec![(TLV_ROLE_SLOT, vec![0x00]), (0x0FF0, vec![1, 2, 3])],
        ..m_publish()
    }
}

fn m_publish_ack() -> PublishAck {
    PublishAck {
        shard: 5,
        epoch: 99,
        seq: 1234,
        slot: 77,
        next_pow_bits: 26,
        error_code: "OK".into(),
        retry_after_ms: 0,
    }
}

fn m_find() -> Find {
    Find {
        preprocessing_version: 3,
        query_vector: [3i8; DIM],
        clusters: vec![10, 41, 300],
        top_k: 32,
        query_id: 0xDEAD_BEEF_CAFE_1234,
        requester_ed25519: [0xC3; 32],
        tlv: vec![(TLV_BATCH_HINT, vec![1])],
    }
}

fn m_match_result() -> MatchResult {
    MatchResult {
        shard: 5,
        epoch: 99,
        query_id: 1,
        responder_ed25519: [0x07; 32],
        matches: vec![
            Match { owner_ed25519: [1; 32], cluster_id: 80, d2: 1000, slot: 3 },
            Match { owner_ed25519: [2; 32], cluster_id: 81, d2: 1000, slot: 4 },
            Match { owner_ed25519: [3; 32], cluster_id: 80, d2: 2000, slot: 1 },
        ],
    }
}

fn m_text_request() -> IntentTextRequest {
    IntentTextRequest { query_id: 5, target_ed25519: [0xEE; 32], slot: 41 }
}

fn m_text_response() -> IntentTextResponse {
    IntentTextResponse {
        owner_ed25519: [1; 32],
        model_version: "granite-embedding-97m-v2".into(),
        preprocessing_version: 3,
        text: "найди мне контрагент по русской строчке".as_bytes().to_vec(),
    }
}

fn m_wal_pull_request() -> WalPullRequest {
    WalPullRequest { shard: 5, from_seq: 10, to_seq: 0, max_bytes: 1 << 20 }
}

fn m_wal_pull_response() -> WalPullResponse {
    WalPullResponse { shard: 5, from_seq: 10, to_seq: 12, primary_epoch: 3, frames: vec![1, 2, 3, 4] }
}

fn m_replicate(op_kind: OpKind, body: Vec<u8>) -> ReplicateOp {
    ReplicateOp { shard: 5, epoch: 3, seq: 11, op_kind, body }
}

fn m_lease_grant() -> LeaseGrant {
    LeaseGrant {
        shard: 5,
        epoch: 3,
        primary_ed25519: [0x11; 32],
        dht_peer_id: vec![0x00, 0x24, 0x00],
        expires_at_bucket: 40_000,
    }
}

fn m_membership() -> MembershipUpdate {
    MembershipUpdate {
        epoch: 4,
        shard: 5,
        members: vec![
            Member {
                owner_ed25519: [1; 32],
                dht_peer_id: vec![0xAA; 34],
                capacity_entries: 100,
            },
            Member {
                owner_ed25519: [2; 32],
                dht_peer_id: vec![0xBB; 34],
                capacity_entries: 200,
            },
        ],
        primary_idx: 0,
        generated_at: 999,
        sigs: vec![(0, [7u8; 64]), (1, [8u8; 64])],
    }
}

fn m_leave() -> LeaveNotice {
    LeaveNotice {
        epoch: 4,
        shard: 5,
        leaving_owner: [1; 32],
        drain_deadline_bucket: 100,
    }
}

fn m_rendezvous() -> RendezvousAccept {
    RendezvousAccept {
        seeker: [1; 32],
        target: [2; 32],
        shard: 7,
        slot: 41,
        issued_bucket: 99,
        ttl_sec: 300,
    }
}

fn m_cert_revoke() -> CertRevoke {
    CertRevoke {
        nonce: [0x01; 16],
        revoked_at: 42,
        reason: "compromised".into(),
        authority_sigs: vec![[0x77; 64], [0x88; 64]],
    }
}

fn m_artifact_announce() -> ArtifactAnnounce {
    ArtifactAnnounce {
        artifact_hash: [9; 32],
        model_version: "granite-embedding-97m-v2".into(),
        preprocessing_version: 1,
        nlist: 1024,
        clusters_per_shard: 16,
        issued_at: 10,
    }
}

fn sample_cert() -> NodeCert {
    NodeCert {
        version: 8,
        genesis_hash: [0x2A; 32],
        role: Role::IndexNode,
        owner_ed25519: [0xA1; 32],
        dht_peer_id: vec![0x00, 0x24, 0x00, 0xDE, 0xAD, 0xBE, 0xEF],
        shards: vec![0, 7, 63],
        capacity_entries: 200_000,
        valid_from: 1_700_000_000,
        valid_until: 1_700_086_400,
        nonce: [0x5A; 16],
        authority_sigs: vec![[0x31; 64], [0x32; 64], [0x33; 64]],
    }
}

/// Все golden-векторы. `BTreeMap` — сортировка по ключу, файл фикстуры стабилен в диффе.
fn vectors() -> BTreeMap<String, Vec<u8>> {
    let mut v: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    // Кадры: заголовок (kind, version=8, flags, body_len) + тело.
    let cases: Vec<(&'static str, Vec<u8>)> = vec![
        ("handshake", m_handshake().body_bytes()),
        ("error", m_error().body_bytes()),
        ("publish", m_publish().body_bytes()),
        ("publish_tlv", m_publish_tlv().body_bytes()),
        ("publish_ack", m_publish_ack().body_bytes()),
        ("find", m_find().body_bytes()),
        ("match_result", m_match_result().body_bytes()),
        ("intent_text_request", m_text_request().body_bytes()),
        ("intent_text_response", m_text_response().body_bytes()),
        ("wal_pull_request", m_wal_pull_request().body_bytes()),
        ("wal_pull_response", m_wal_pull_response().body_bytes()),
        (
            "replicate_insert",
            m_replicate(OpKind::Insert, InsertOp {
                owner_ed25519: [1; 32],
                vec_q: [-2i8; DIM],
                cluster_id: 12,
                published_bucket: 1000,
                ttl_buckets: 225,
            }
            .body_bytes())
            .body_bytes(),
        ),
        (
            "replicate_delete",
            m_replicate(OpKind::Delete, DeleteOp { owner_ed25519: [1; 32], shard: 5 }.body_bytes())
                .body_bytes(),
        ),
        (
            "replicate_time_mark",
            m_replicate(OpKind::TimeMark, encode_mark(512, 106_250_000)).body_bytes(),
        ),
        (
            "replicate_gc_tick",
            m_replicate(OpKind::GcTick, encode_mark(5_000, 106_250_010)).body_bytes(),
        ),
        ("lease_grant", m_lease_grant().body_bytes()),
        ("membership_update", m_membership().body_bytes()),
        ("leave_notice", m_leave().body_bytes()),
        ("rendezvous_accept", m_rendezvous().body_bytes()),
        ("cert_revoke", m_cert_revoke().body_bytes()),
        ("artifact_announce", m_artifact_announce().body_bytes()),
    ];
    for (name, body) in cases {
        v.insert(format!("body.{name}"), body.clone());
        v.insert(
            format!("frame.{name}"),
            encode_frame(frame_kind_of(name), &body, None),
        );
    }

    // Вход подписи (§5.2): domain ‖ kind ‖ version ‖ flags ‖ body.
    let signed: Vec<(&'static str, Kind, &'static [u8], Vec<u8>)> = vec![
        ("match_result", Kind::MatchResult, domain::MATCH, m_match_result().body_bytes()),
        ("intent_text_response", Kind::IntentTextResponse, domain::TEXT, m_text_response().body_bytes()),
        ("replicate_op", Kind::ReplicateOp, domain::REPLICA, m_replicate(OpKind::Insert, vec![1; 4]).body_bytes()),
        ("lease_grant", Kind::LeaseGrant, domain::LEASE, m_lease_grant().body_bytes()),
        ("membership_update", Kind::MembershipUpdate, domain::MEMBER, m_membership().body_bytes()),
        ("leave_notice", Kind::LeaveNotice, domain::LEAVE, m_leave().body_bytes()),
        ("cert_revoke", Kind::CertRevoke, b"vecdht/v8/cert_revoke", m_cert_revoke().body_bytes()),
        ("rendezvous_accept", Kind::RendezvousAccept, domain::RENDEZVOUS, m_rendezvous().body_bytes()),
        ("artifact_announce", Kind::ArtifactAnnounce, domain::ARTIFACT, m_artifact_announce().body_bytes()),
    ];
    for (name, kind, dom, body) in signed {
        v.insert(
            format!("sig_input.{name}"),
            sig_input(dom, kind, FLAG_SIGNED, &body),
        );
    }
    // Publish/Find подписываются только в gossip-потоке; их sig_input при flags=0.
    v.insert(
        "sig_input.publish_gossip".to_string(),
        sig_input(domain::PUBLISH, Kind::Publish, 0, &m_publish().body_bytes()),
    );
    v.insert(
        "sig_input.find_gossip".to_string(),
        sig_input(domain::FIND, Kind::Find, 0, &m_find().body_bytes()),
    );

    // Кадр с реальной структурой подписи: 64 байта детерминированного паттерна.
    let mr_body = m_match_result().body_bytes();
    v.insert(
        "frame.match_result_signed".to_string(),
        m_match_result().encode_signed(&[0x5C; 64]),
    );
    assert_eq!(mr_body, m_match_result().body_bytes());

    // NodeCert: подписываемая часть и полный байт с 3 подписями авторитета.
    let cert = sample_cert();
    v.insert("cert.unsigned_body".to_string(), cert.unsigned_body());
    v.insert("cert.encoded".to_string(), cert.encode());

    // DHT-ключ шарда — 12 байт, big-endian внутри (единственные два ключа, которые есть в сети).
    v.insert("dht_key.shard_0".to_string(), shard_provider_key(0));
    v.insert("dht_key.shard_63".to_string(), shard_provider_key(63));

    v
}

/// Имя сообщения → `Kind`. Соответствие берётся из самих типов, а не из строки:
/// компилятор не даст разойтись, если `KIND` изменится.
fn frame_kind_of(name: &str) -> Kind {
    match name {
        "handshake" => Kind::Handshake,
        "error" => Kind::Error,
        "publish" | "publish_tlv" => Kind::Publish,
        "publish_ack" => Kind::PublishAck,
        "find" => Kind::Find,
        "match_result" => Kind::MatchResult,
        "intent_text_request" => Kind::IntentTextRequest,
        "intent_text_response" => Kind::IntentTextResponse,
        "wal_pull_request" => Kind::WalPullRequest,
        "wal_pull_response" => Kind::WalPullResponse,
        "replicate_insert" | "replicate_delete" | "replicate_time_mark" | "replicate_gc_tick" => {
            Kind::ReplicateOp
        }
        "lease_grant" => Kind::LeaseGrant,
        "membership_update" => Kind::MembershipUpdate,
        "leave_notice" => Kind::LeaveNotice,
        "rendezvous_accept" => Kind::RendezvousAccept,
        "cert_revoke" => Kind::CertRevoke,
        "artifact_announce" => Kind::ArtifactAnnounce,
        other => panic!("golden-вектор {other} не сопоставлен с Kind"),
    }
}

fn render(v: &BTreeMap<String, Vec<u8>>) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("# vecdht-wire golden vectors (spec v8 §5.1). key=hex\n");
    s.push_str("# regenerate: VEC_DHT_GOLDEN=1 cargo test -p vecdht-wire --test golden_vectors\n");
    for (k, b) in v {
        let _ = writeln!(s, "{k}={}", hex::encode(b));
    }
    s
}

fn parse(text: &str) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, hx) = line.split_once('=').unwrap_or_else(|| panic!("строка без '=': {line}"));
        out.insert(k.trim().to_string(), hex::decode(hx.trim()).unwrap_or_else(|e| panic!("{k}: {e}")));
    }
    out
}

#[test]
fn golden_vectors_match_checked_in_fixture() {
    let produced = vectors();
    let path = golden_path();
    if std::env::var("VEC_DHT_GOLDEN").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, render(&produced)).unwrap();
        println!("golden-файл перезаписан: {}", path.display());
        return;
    }
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("нет фикстуры {} ({e}). Запусти: VEC_DHT_GOLDEN=1 cargo test -p vecdht-wire --test golden_vectors", path.display()));
    let expected = parse(&text);
    assert!(!expected.is_empty(), "фикстура пуста");

    let mut diffs: Vec<String> = Vec::new();
    for (k, b) in &produced {
        match expected.get(k.as_str()) {
            None => diffs.push(format!("{k}: отсутствует в фикстуре")),
            Some(want) if want != b => diffs.push(format!(
                "{k}: расхождение\n   было: {}\n   стало: {}",
                hex::encode(want),
                hex::encode(b)
            )),
            Some(_) => {}
        }
    }
    for k in expected.keys() {
        if !produced.contains_key(k.as_str()) {
            diffs.push(format!("{k}: есть в фикстуре, но больше не генерируется"));
        }
    }
    assert!(diffs.is_empty(), "{} golden-расхождений:\n{}", diffs.len(), diffs.join("\n"));
    assert!(
        produced.len() >= 40,
        "слишком мало векторов: {}: каждый вид кадра должен быть зафиксирован",
        produced.len()
    );
}

#[test]
fn golden_frames_are_self_consistent() {
    // Фикстура должна читаться тем же кодеком, чьи байты она фиксирует: иначе «золото»
    // можно было бы проверить только сравнивая строки.
    let v = vectors();
    let names: Vec<String> = v.keys().cloned().collect();
    for name in names {
        let Some(key) = name.strip_prefix("frame.") else { continue };
        let Some(body) = v.get(&format!("body.{key}")) else { continue };
        let frame = &v[&name];
        let f = decode_frame(frame).unwrap_or_else(|e| panic!("кадр {name} не декодируется: {e}"));
        assert_eq!(f.header.version, PROTOCOL_VERSION);
        assert_eq!(f.header.kind, frame_kind_of(key), "kind в заголовке не тот");
        assert_eq!(f.body, &body[..], "тело в кадре не совпадает с golden-телом");
        // 8 байт головы: kind, version, flags(2), body_len(4) — ровно как в §5.1.
        assert_eq!(&frame[..4], &[f.header.kind as u8, PROTOCOL_VERSION, 0, 0]);
        assert_eq!(&frame[4..8], &(body.len() as u32).to_le_bytes());
    }
    // Подписанный кадр: flags=1, подпись 64 байта, тело то же.
    let signed = &v["frame.match_result_signed"];
    let f = decode_frame(signed).unwrap();
    assert!(f.header.signed());
    assert_eq!(f.signature.unwrap().len(), 64);
    assert_eq!(f.body, &v["body.match_result"][..]);
    // И тело, и кадр с TLV различны с plain publish — неизвестный тег меняет байты, но не схему.
    assert_ne!(v["frame.publish"], v["frame.publish_tlv"]);
}

#[test]
fn wire_rules_that_golden_pins_down_are_still_enforced() {
    // Правила §5.1, которые golden-вектор фиксирует косвенно, проверяем и напрямую:
    // регрессия в валидации должна быть видна даже если фикстуру кто-то перепишет.
    let good = m_publish().encode_unsigned();
    assert_eq!(decode_frame(&good).unwrap().header.body_len as usize, m_publish().body_bytes().len());

    // version != 8.
    let mut bad = good.clone();
    bad[1] = 9;
    assert!(matches!(decode_frame(&bad), Err(DecodeError::Version(9))));

    // зарезервированные флаги обязаны отклоняться (иначе их нельзя занять в будущей версии).
    let mut bad = good.clone();
    bad[2] = (FLAG_RESERVED_MASK & 0xFF) as u8;
    assert!(matches!(decode_frame(&bad), Err(DecodeError::ReservedFlags(_))));

    // body_len за пределами MAX_BODY_LEN — до чтения тела.
    let mut hdr = vec![0x10u8, 8, 0, 0];
    hdr.extend_from_slice(&(MAX_BODY_LEN as u32 + 1).to_le_bytes());
    assert!(matches!(decode_frame(&hdr), Err(DecodeError::BodyTooLarge { .. })));

    // тело меньше заявленного — усечённый кадр, а не «тихий» частичный разбор.
    let mut truncated = good.clone();
    truncated.truncate(good.len() - 1);
    assert!(matches!(decode_frame(&truncated), Err(DecodeError::Truncated { .. })));

    // TLV: дубликат тега и нисходящий порядок — ошибка, а не «последний выигрывает».
    // Байты собираем вручную: Writer такой хвост не запишет (он обязан держать порядок),
    // а нам нужен именно некорректный вход с сети.
    let tail = |tags: &[(u16, &[u8])]| -> Vec<u8> {
        let mut b = m_publish().body_bytes();
        for (tag, val) in tags {
            b.extend_from_slice(&tag.to_le_bytes());
            b.extend_from_slice(&(val.len() as u16).to_le_bytes());
            b.extend_from_slice(val);
        }
        b
    };
    let dup = encode_frame(Kind::Publish, &tail(&[(0x0FF0, &[1]), (0x0FF0, &[2])]), None);
    assert!(matches!(Publish::decode(&dup), Err(DecodeError::DuplicateTag { tag: 0x0FF0 })));
    let desc = encode_frame(Kind::Publish, &tail(&[(0x0FF1, &[1]), (0x0FF0, &[2])]), None);
    assert!(matches!(Publish::decode(&desc), Err(DecodeError::TagOrder { prev: 0x0FF1, next: 0x0FF0 })));

    // Неизвестный тег — игнорируется, поле схемы при этом на месте.
    let unk = Publish { tlv: vec![(0x0FF0, vec![9, 9])], ..m_publish() };
    assert_eq!(Publish::decode(&unk.encode_unsigned()).unwrap(), unk);

    // enum-поля вне домена (правило 5): role — первый байт тела Handshake.
    let mut hs_body = m_handshake().body_bytes();
    hs_body[0] = 5;
    let bad_role = encode_frame(Kind::Handshake, &hs_body, None);
    assert!(matches!(
        Handshake::decode(&bad_role),
        Err(DecodeError::BadEnum { value: 5, what: "Role", .. })
    ));
    let cluster = Publish { cluster_id: 1024, ..m_publish() };
    assert!(matches!(
        Publish::decode(&cluster.encode_unsigned()),
        Err(DecodeError::BadEnum { what: "cluster_id", .. })
    ));
}
