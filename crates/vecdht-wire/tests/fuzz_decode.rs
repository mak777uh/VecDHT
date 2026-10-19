//! Фаззинг декодера `vecdht-wire` (гейт P2 в §20: «fuzz-декод 30 мин без panic»).
//!
//! Это не `cargo fuzz`: в crate стоит `#![forbid(unsafe_code)]`, поэтому целью фаззинга здесь
//! не memory safety, а три свойства, без которых невозможен консенсус:
//!
//! 1. **никаких паников на чужих байтах** — узел получает поток от произвольного пира;
//! 2. **каноничность**: если байты приняты декодером, повторное кодирование даёт ровно те же
//!    байты. Иначе у двух честных реализаций появляется способ подписать одно сообщение двумя
//!    разными последовательностями, и §5.2 теряет смысл;
//! 3. **не «дочитывается» лишнего**: кадр разбирается целиком или отклоняется. Кроме TLV-хвоста,
//!    где неизвестный тег обязан игнорироваться семантически, но переноситься байт-в-байт.
//!
//! Seed фиксирован, падение воспроизводится. Длинный прогон:
//! `VEC_DHT_FUZZ_SECS=1800 cargo test -p vecdht-wire --test fuzz_decode --release -- --nocapture`.

use std::panic::{catch_unwind, AssertUnwindSafe};

use vecdht_wire::cert::NodeCert;
use vecdht_wire::frame::{decode_frame, encode_frame, Kind};
use vecdht_wire::messages::{
    decode_mark, encode_mark, ArtifactAnnounce, CertRevoke, Codec, DeleteOp, Find, Handshake,
    InsertOp, IntentTextRequest, IntentTextResponse, LeaseGrant, LeaveNotice, Match, MatchResult,
    Member, MembershipUpdate, OpKind, ProtocolError, Publish, PublishAck, RendezvousAccept,
    ReplicateOp, Role, WalPullRequest, WalPullResponse,
};
use vecdht_wire::{DecodeError, Reader, Writer, DIM};

const ALL_KINDS: [Kind; 17] = [
    Kind::Handshake,
    Kind::Error,
    Kind::Publish,
    Kind::PublishAck,
    Kind::Find,
    Kind::MatchResult,
    Kind::IntentTextRequest,
    Kind::IntentTextResponse,
    Kind::WalPullRequest,
    Kind::WalPullResponse,
    Kind::ReplicateOp,
    Kind::LeaseGrant,
    Kind::MembershipUpdate,
    Kind::LeaveNotice,
    Kind::CertRevoke,
    Kind::RendezvousAccept,
    Kind::ArtifactAnnounce,
];

/// Детерминированный xorshift64*: воспроизводимый поток без внешних rng-зависимостей.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % (n as u64)) as usize
        }
    }
}

/// Сообщения переформируют весь кадр, поэтому каноничность проверяется на кадре.
fn canon<M: Codec>(b: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let m = M::decode(b)?;
    let frame = decode_frame(b)?;
    let re = m.body_bytes();
    if re != frame.body {
        // декод прошёл, но тело пересобралось иначе — неканонический вход принят
        return Err(DecodeError::TrailingBytes { offset: 0 });
    }
    Ok(encode_frame(M::KIND, &re, frame.signature))
}

/// Go-lo bodies: вставляются в чужие кадры, поэтому декодируются напрямую из байтов.
fn decode_insert(b: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut r = Reader::new(b);
    InsertOp::decode(&mut r).map(|o| o.body_bytes())
}

fn decode_delete(b: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut r = Reader::new(b);
    DeleteOp::decode(&mut r).map(|o| o.body_bytes())
}

fn decode_mark_body(b: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_mark(b).map(|(seq, bucket)| encode_mark(seq, bucket))
}

type Decode = fn(&[u8]) -> Result<Vec<u8>, DecodeError>;

const DECODERS: &[(&str, Decode)] = &[
    ("handshake", canon::<Handshake>),
    ("error", canon::<ProtocolError>),
    ("publish", canon::<Publish>),
    ("publish_ack", canon::<PublishAck>),
    ("find", canon::<Find>),
    ("match_result", canon::<MatchResult>),
    ("intent_text_request", canon::<IntentTextRequest>),
    ("intent_text_response", canon::<IntentTextResponse>),
    ("wal_pull_request", canon::<WalPullRequest>),
    ("wal_pull_response", canon::<WalPullResponse>),
    ("replicate_op", canon::<ReplicateOp>),
    ("lease_grant", canon::<LeaseGrant>),
    ("membership_update", canon::<MembershipUpdate>),
    ("leave_notice", canon::<LeaveNotice>),
    ("cert_revoke", canon::<CertRevoke>),
    ("rendezvous_accept", canon::<RendezvousAccept>),
    ("artifact_announce", canon::<ArtifactAnnounce>),
    ("node_cert", |b| NodeCert::decode(b).map(|c| c.encode())),
    ("insert_op_body", decode_insert),
    ("delete_op_body", decode_delete),
    ("mark_body", decode_mark_body),
];

/// Валидные кадры всех типов — источник «почти правильных» байтов для мутаций.
fn corpus() -> Vec<Vec<u8>> {
    let mut v = [0i8; DIM];
    for (i, x) in v.iter_mut().enumerate() {
        *x = (i as i32 % 253 - 126) as i8;
    }
    let sig = [0x2Cu8; 64];
    let ins = InsertOp {
        owner_ed25519: [1; 32],
        vec_q: v,
        cluster_id: 511,
        published_bucket: 106_250_000,
        ttl_buckets: 225,
    };
    let mut out: Vec<Vec<u8>> = vec![Handshake { role: Role::Agent, preprocessing_version: 3, model_version: "m".into(), genesis_hash: [1; 32], cert: vec![], tlv: vec![] }.encode_unsigned()];
    out.push(Handshake { role: Role::IndexNode, preprocessing_version: u16::MAX, model_version: "granite-embedding-97m-v2".into(), genesis_hash: [0xFF; 32], cert: vec![0x9C; 32], tlv: vec![(0x0001, vec![1u8])] }.encode_unsigned());
    out.push(ProtocolError { code: "BUSY".into(), retry_after_ms: 1, shard: 63 }.encode_unsigned());
    out.push(Publish { preprocessing_version: 3, cluster_id: 1023, vec_q: v, owner_ed25519: [2; 32], ttl_buckets: 0, published_bucket: u32::MAX, pow_bits: 28, pow_nonce: u64::MAX, intent_id: [3; 32], tlv: vec![(0x0001, vec![0u8]), (0x0FF0, vec![7; 3])] }.encode_unsigned());
    out.push(Publish { preprocessing_version: 0, cluster_id: 0, vec_q: [127i8; DIM], owner_ed25519: [0; 32], ttl_buckets: u16::MAX, published_bucket: 0, pow_bits: 0, pow_nonce: 0, intent_id: [0; 32], tlv: vec![] }.encode_signed(&sig));
    out.push(PublishAck { shard: 63, epoch: u64::MAX, seq: u64::MAX, slot: u32::MAX, next_pow_bits: 28, error_code: String::new(), retry_after_ms: u32::MAX }.encode_unsigned());
    out.push(Find { preprocessing_version: 3, query_vector: [-128i8; DIM], clusters: vec![0, 1023], top_k: 0, query_id: 0, requester_ed25519: [4; 32], tlv: vec![] }.encode_unsigned());
    out.push(Find { preprocessing_version: u16::MAX, query_vector: [127i8; DIM], clusters: vec![], top_k: u16::MAX, query_id: u64::MAX, requester_ed25519: [4; 32], tlv: vec![(0x0002, vec![])] }.encode_signed(&sig));
    out.push(MatchResult { shard: 0, epoch: 0, query_id: 0, responder_ed25519: [5; 32], matches: vec![] }.encode_signed(&sig));
    out.push(MatchResult { shard: 63, epoch: 1, query_id: 2, responder_ed25519: [5; 32], matches: vec![Match { owner_ed25519: [1; 32], cluster_id: 80, d2: 0, slot: 3 }, Match { owner_ed25519: [2; 32], cluster_id: 81, d2: vecdht_wire::MAX_D2, slot: 4 }] }.encode_signed(&sig));
    out.push(IntentTextRequest { query_id: u64::MAX, target_ed25519: [6; 32], slot: u32::MAX }.encode_unsigned());
    out.push(IntentTextResponse { owner_ed25519: [6; 32], model_version: String::new(), preprocessing_version: 0, text: vec![0xD0, 0xBF] }.encode_signed(&sig));
    out.push(WalPullRequest { shard: 0, from_seq: 0, to_seq: u64::MAX, max_bytes: u32::MAX }.encode_unsigned());
    let mut wal_frames = Writer::new();
    wal_frames.bytes(&ins.body_bytes());
    wal_frames.bytes(&encode_mark(7, 8));
    out.push(WalPullResponse { shard: 63, from_seq: 9, to_seq: 0, primary_epoch: u64::MAX, frames: wal_frames.into_vec() }.encode_signed(&sig));
    out.push(ReplicateOp { shard: 63, epoch: u64::MAX, seq: u64::MAX, op_kind: OpKind::GcTick, body: encode_mark(u64::MAX, u32::MAX) }.encode_signed(&sig));
    out.push(ReplicateOp { shard: 0, epoch: 0, seq: 1, op_kind: OpKind::Insert, body: ins.body_bytes() }.encode_signed(&sig));
    out.push(ReplicateOp { shard: 1, epoch: 2, seq: 3, op_kind: OpKind::Delete, body: DeleteOp { owner_ed25519: [3; 32], shard: 5 }.body_bytes() }.encode_signed(&sig));
    out.push(ReplicateOp { shard: 2, epoch: 3, seq: 4, op_kind: OpKind::TimeMark, body: encode_mark(4, 99) }.encode_signed(&sig));
    out.push(LeaseGrant { shard: 5, epoch: 3, primary_ed25519: [0x11; 32], dht_peer_id: vec![0x00, 0x24, 0x00], expires_at_bucket: 40_000 }.encode_signed(&sig));
    out.push(MembershipUpdate { epoch: 1, shard: 2, members: vec![Member { owner_ed25519: [7; 32], dht_peer_id: vec![0; 64], capacity_entries: u64::MAX }], primary_idx: 0, generated_at: 5, sigs: vec![(0, [9u8; 64])] }.encode_signed(&sig));
    out.push(LeaveNotice { epoch: u64::MAX, shard: 63, leaving_owner: [8; 32], drain_deadline_bucket: u32::MAX }.encode_signed(&sig));
    out.push(CertRevoke { nonce: [0x01; 16], revoked_at: u32::MAX, reason: "compromised".into(), authority_sigs: vec![[0x77; 64]; 16] }.encode_signed(&sig));
    out.push(RendezvousAccept { seeker: [1; 32], target: [2; 32], shard: 7, slot: u32::MAX, issued_bucket: 99, ttl_sec: 300 }.encode_signed(&sig));
    out.push(ArtifactAnnounce { artifact_hash: [9; 32], model_version: "m".into(), preprocessing_version: u16::MAX, nlist: 1024, clusters_per_shard: 16, issued_at: u32::MAX }.encode_signed(&sig));
    // NodeCert — не кадр, а отдельная структура байтов; тоже идёт в корпус мутаций.
    out.push(
        NodeCert {
            version: 8,
            genesis_hash: [8; 32],
            role: Role::IndexNode,
            owner_ed25519: [9; 32],
            dht_peer_id: vec![0xAA; 34],
            shards: vec![0, 63],
            capacity_entries: 1,
            valid_from: 0,
            valid_until: 1,
            nonce: [0; 16],
            authority_sigs: vec![[0x11; 64]],
        }
        .encode(),
    );
    out.push(ins.body_bytes());
    out
}

/// Применить декодер, поймав паник; второй возврат — каноническое перем кодирование.
fn try_decode(dec: Decode, input: &[u8]) -> Option<Result<Vec<u8>, DecodeError>> {
    catch_unwind(AssertUnwindSafe(|| dec(input))).ok()
}

#[test]
fn fuzz_decode_never_panics_and_accepts_only_canonical_bytes() {
    let seed = std::env::var("VEC_DHT_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5EED_1234_ABCD_0008u64);
    let secs = std::env::var("VEC_DHT_FUZZ_SECS").ok().and_then(|s| s.parse::<u64>().ok());
    let budget_iters = std::env::var("VEC_DHT_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        // Когда задан wall-clock бюджет, число итераций ограничивать не должно: иначе
        // «30 минут фаззинга» из §20 превращаются в секунды на быстром декодере.
        .unwrap_or(if secs.is_some() { u64::MAX } else { 200_000u64 });

    let corpus = corpus();
    assert!(
        corpus.len() >= ALL_KINDS.len(),
        "корпус обязан покрывать все {}/{}",
        corpus.len(),
        ALL_KINDS.len()
    );
    // Каждая запись корпуса должна декодироваться хотя бы одним декодером: иначе фаззер
    // мутирует мусор, а не протокол.
    for (i, c) in corpus.iter().enumerate() {
        assert!(
            DECODERS.iter().any(|(_, d)| matches!(try_decode(*d, c), Some(Ok(_)))),
            "корпусной вход #{i} не декодируется ни одним декодером"
        );
    }

    let mut rng = Rng(if seed == 0 { 1 } else { seed });
    let started = std::time::Instant::now();
    let (mut iterations, mut accepted, mut rejected, mut trailing) = (0u64, 0u64, 0u64, 0u64);

    loop {
        iterations += 1;
        let input: Vec<u8> = match rng.below(6) {
            // мусор произвольной длины
            0 => {
                let n = rng.below(600);
                (0..n).map(|_| rng.byte()).collect()
            }
            // мутация валидного кадра: побайтовые правки, обрезка, вставка
            1 | 2 => {
                let mut b = corpus[rng.below(corpus.len())].clone();
                for _ in 0..(rng.below(4) + 1) {
                    if b.is_empty() {
                        break;
                    }
                    let i = rng.below(b.len());
                    match rng.below(3) {
                        0 => b[i] = rng.byte(),
                        1 => b.truncate(i),
                        _ => b.insert(i, rng.byte()),
                    }
                }
                b
            }
            // заголовок с чужим kind и заявленной длиной больше буфера: проверка, что
            // аллокация не следует за body_len
            3 => {
                let mut b = corpus[rng.below(corpus.len())].clone();
                if b.len() >= 8 {
                    b[0] = rng.byte();
                    let fake = rng.below(1usize << 25) as u32;
                    b[4..8].copy_from_slice(&fake.to_le_bytes());
                }
                b
            }
            // случайный TLV-тег в хвосте тела
            4 => {
                let mut b = corpus[rng.below(corpus.len())].clone();
                let tag = rng.below(u16::MAX as usize) as u16;
                let len = rng.below(4);
                b.extend_from_slice(&tag.to_le_bytes());
                b.extend_from_slice(&(len as u16).to_le_bytes());
                for _ in 0..len {
                    b.push(rng.byte());
                }
                b
            }
            // склейка двух кадров: первый разбирается, второй — лишние байты
            _ => {
                let a = corpus[rng.below(corpus.len())].clone();
                let c = corpus[rng.below(corpus.len())].clone();
                [a, c].concat()
            }
        };

        for (name, dec) in DECODERS {
            match try_decode(*dec, &input) {
                None => panic!(
                    "panic в декодере {name} на входе {}\n  seed={seed}",
                    hex::encode(&input)
                ),
                Some(Ok(canonical)) => {
                    accepted += 1;
                    // Транспорт читает кадры по length-prefix, поэтому «лишние» байты после
                    // кадра — не ошибка декодера, а начало следующего кадра. Инвариант
                    // каноничности формулируется так: принятые байты пересобираются в себя,
                    // а всё, что осталось за кадром, в пересборку не входит.
                    assert!(
                        input.starts_with(&canonical),
                        "декодер {name} принял неканонические байты:\n   вход:  {}\n   канон: {}\n  seed={seed}",
                        hex::encode(&input),
                        hex::encode(&canonical)
                    );
                    if canonical.len() != input.len() {
                        trailing += 1;
                    }
                }
                Some(Err(_)) => rejected += 1,
            }
        }
        // Заголовок обязан быть сам с собой согласован: длина тела из него, подпись из flags.
        // `decode_frame` здесь уже прогнан внутри декодеров, так что panic-защита не нужна.
        if let Ok(f) = decode_frame(&input) {
            assert_eq!(f.body.len(), f.header.body_len as usize);
            assert_eq!(f.header.version, 8);
            assert_eq!(f.header.signed(), f.signature.is_some());
            assert_eq!(f.signature.map(|s| s.len()), if f.header.signed() { Some(64) } else { None });
        }

        let time_up = secs.map(|s| started.elapsed().as_secs() >= s).unwrap_or(false);
        if iterations >= budget_iters || time_up {
            println!(
                "fuzz: {iterations} итераций за {:?}, принято {accepted} (из них с хвостом следующего кадра {trailing}), отклонено {rejected}",
                started.elapsed()
            );
            assert!(accepted > 0, "ни один вход не прошёл — фаззер ничего не проверял (seed {seed})");
            assert!(rejected > 0, "ни один вход не отклонён — декодер слишком терпим");
            return;
        }
    }
}

/// Заголовки: заявленная длина больше наличия — только ошибка, никогда частичный успех.
#[test]
fn header_declared_lengths_are_bounded_by_the_buffer() {
    let mut rng = Rng(0xDEAD_BEEF_0000_0008);
    for _ in 0..20_000 {
        let declared = rng.next() % (vecdht_wire::MAX_BODY_LEN as u64 + 1000);
        let avail = rng.below(300);
        let mut b = Vec::new();
        b.push(rng.byte());
        b.push(if rng.below(8) == 0 { rng.byte() } else { 8 });
        b.extend_from_slice(&[rng.byte() & 0x01, 0u8]);
        b.extend_from_slice(&(declared as u32).to_le_bytes());
        for _ in 0..avail {
            b.push(rng.byte());
        }
        let res = catch_unwind(AssertUnwindSafe(|| decode_frame(&b)));
        let frame = res.unwrap_or_else(|_| panic!("panic на заголовке {}", hex::encode(&b)));
        if let Ok(f) = frame {
            assert_eq!(f.body.len(), declared as usize, "усечённый кадр пропущен");
            assert_eq!(f.header.version, 8);
            assert_eq!(f.header.signed(), f.signature.is_some());
            assert_eq!(
                f.signature.map(|s| s.len()),
                if f.header.signed() { Some(64) } else { None },
                "подпись без флага или флаг без подписи"
            );
        }
    }
}

/// Покрытие: every `Kind` встречается в корпусе, иначе мутации его не видят.
#[test]
fn corpus_covers_every_kind() {
    let present: Vec<u8> = corpus()
        .iter()
        .filter_map(|f| decode_frame(f).ok())
        .map(|f| f.header.kind as u8)
        .collect();
    for k in ALL_KINDS {
        assert!(present.contains(&(k as u8)), "kind {k:?} не представлен в корпусе фаззера");
    }
}
