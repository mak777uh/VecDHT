//! `wire kinds|decode` — таблица кадров (§5.3) и разбор конкретного кадра (§5.1, §5.2).
//!
//! Команды нужны, потому что сеть говорит байтами, а отладка идёт по ним же: `MatchResult` от
//! чужого узла, `ReplicateOp` из WAL, кадр из дампа. Разбор делает ровно то, что делает приёмник,
//! и ничего не «чинит»: если байты тела не пересобираются в себя после декод→энкод, это печатается
//! как расхождение каноничности, а не как успех с оговоркой (§5.2).
//!
//! Проверки подписи здесь нет намеренно: она в `vecdht-crypto` и требует доверенного набора
//! ключей, а `wire decode` — инструмент над произвольным дампом. Печатается материал подписи
//! (`sig_input` и его blake3), чтобы оператор мог сверить, *что именно* должен был подписать
//! отправитель.

use vecdht_wire::codec::Reader;
use vecdht_wire::frame::{Kind, decode_frame, parse_header, sig_input, FLAG_SIGNED};
use vecdht_wire::messages::{
    ArtifactAnnounce, CertRevoke, Codec, Find, Handshake, IntentTextRequest, IntentTextResponse,
    LeaseGrant, LeaveNotice, MatchResult, MembershipUpdate, ProtocolError, Publish, PublishAck,
    RendezvousAccept, ReplicateAck, ReplicateOp, SnapshotOffer, WalPullRequest, WalPullResponse,
};

use crate::args::Parsed;
use crate::{CliError, fail};

pub const CMD_KINDS: &str = "wire kinds";
pub const CMD_DECODE: &str = "wire decode";

/// У `kinds` флагов нет: таблица одна на все версии протокола, а «красивый режим» означал бы, что
/// вывод можно получить двумя способами.
pub const FLAGS_KINDS: &[&str] = &[];
pub const FLAGS_DECODE: &[&str] = &["hex", "file", "lenient"];

pub const HELP_KINDS: &str = "\
wire kinds — таблица видов кадра §5.3: код, имя, требует ли подпись

  флагов нет";

pub const HELP_DECODE: &str = "\
wire decode — разобрать один кадр

  --hex HEX      кадр строчными hex-символами (чётная длина, без разделителей)
  --file PATH    те же байты из файла; --hex и --file вместе — ошибка
  --lenient      не считать ошибкой то, что не декодируется: напечатать заголовок и причину";

pub fn exec_kinds(_p: &Parsed, out: &mut String) -> Result<(), CliError> {
    out.push_str("код   вид                 подпись\n");
    let mut signed = 0usize;
    for k in Kind::ALL {
        let need = k.signature_required();
        signed += usize::from(need);
        out.push_str(&format!(
            "0x{:02X}  {:<18} {}\n",
            k as u8,
            k.name(),
            if need { "обязана" } else { "нет" }
        ));
    }
    out.push_str(&format!(
        "\n{} видов, из них подписанных {signed}: список ведёт `Kind::ALL` (§5.3), а не память \
         автора таблицы.\n",
        Kind::ALL.len()
    ));
    out.push_str(
        "Отсутствие подписи там, где она обязательна, — это не «кадр без подписи», а кадр, который \
         приёмник обязан отвергнуть (§4.3).\n",
    );
    Ok(())
}

pub fn exec_decode(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let hex_form = p.value(CMD_DECODE, "hex")?;
    let file_form = p.value(CMD_DECODE, "file")?;
    let bytes = match (hex_form, file_form) {
        (Some(h), None) => {
            crate::args::parse_hex_bytes(CMD_DECODE, "hex", &h).map_err(CliError::Arg)?
        }
        (None, Some(f)) => std::fs::read(&f).map_err(|e| fail("чтение файла кадра", e))?,
        (Some(_), Some(_)) => {
            return Err(CliError::Fail(
                "--hex и --file — два источника одних и тех же байтов; выбрать надо один, иначе \
                 непонятно, какой из них проверялся".into(),
            ));
        }
        (None, None) => {
            return Err(CliError::Fail(
                "нужен --hex HEX или --file PATH: кадр без байтов не разбирается".into(),
            ));
        }
    };
    if bytes.is_empty() {
        return Err(CliError::Fail("пустой вход: ни заголовка, ни тела".into()));
    }
    let lenient = p.bool_flag(CMD_DECODE, "lenient")?;
    let (header, after) = match parse_header(&bytes) {
        Ok(v) => v,
        Err(e) => {
            if lenient {
                out.push_str(&format!("заголовок не читается: {e}\n"));
                return Ok(());
            }
            return Err(fail("разбор заголовка", e));
        }
    };
    out.push_str(&format!(
        "вид 0x{:02X} {} ({} байт тела заявлено), version {}, flags 0x{:04X}{}\n",
        header.kind as u8,
        header.kind.name(),
        header.body_len,
        header.version,
        header.flags,
        if header.signed() { ", подпись есть" } else { ", подписи нет" }
    ));
    if header.kind.signature_required() && !header.signed() {
        out.push_str(&format!(
            "ВНИМАНИЕ: {} требует подписи (§4.3), а флага FLAG_SIGNED в кадре нет — приёмник обязан \
             отвергнуть такой кадр.\n",
            header.kind.name()
        ));
    }
    if !header.kind.signature_required() && header.signed() {
        out.push_str(
            "ВНИМАНИЕ: подпись стоит в кадре, который её не требует: байты лишние, и вывод по такому \
             дампу не совпадёт с тем, что проверяет приёмник.\n",
        );
    }
    let frame = match decode_frame(&bytes) {
        Ok(f) => f,
        Err(e) => {
            if lenient {
                out.push_str(&format!("кадр не дочитан: {e}\n"));
                return Ok(());
            }
            return Err(fail("разбор кадра", e));
        }
    };
    let tail = bytes
        .len()
        .saturating_sub(after + frame.body.len() + frame.signature.map_or(0, |s| 1 + s.len()));
    out.push_str(&format!(
        "заголовок {} байт, тело {} байт{}{}\n",
        after,
        frame.body.len(),
        frame
            .signature
            .map(|s| format!(", подпись {} байт", s.len()))
            .unwrap_or_default(),
        if tail == 0 { String::new() } else { format!(", хвост после кадра {tail} байт") }
    ));
    if let Some(sig) = frame.signature {
        // Целиком подпись в лог не пишется: сверить её с чужим логом можно по префиксу, а
        // переписывать её в баг-репорт — значит плодить материал для перебора.
        out.push_str(&format!("подпись {}…\n", &hex::encode(sig)[..32]));
    }
    match decode_typed(header.kind, frame.body, header.signed(), out) {
        Ok(()) => Ok(()),
        Err(e) => {
            if lenient {
                out.push_str(&format!("тело не декодируется как {}: {e}\n", header.kind.name()));
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

/// Разбор тела по виду кадра. Отдельная функция, а не match внутри `exec_decode`, потому что arms
/// ровно девятнадцать, и каждый требует одного и того же: декод, пересборка, сравнение байтов.
fn decode_typed(
    kind: Kind,
    body: &[u8],
    signed: bool,
    out: &mut String,
) -> Result<(), CliError> {
    macro_rules! one {
        ($($K:ident => $T:ty),* $(,)?) => {
            match kind {
                $(Kind::$K => typed::<$T>(body, signed, out),)*
            }
        };
    }
    one! {
        Handshake => Handshake,
        Error => ProtocolError,
        Publish => Publish,
        PublishAck => PublishAck,
        Find => Find,
        MatchResult => MatchResult,
        IntentTextRequest => IntentTextRequest,
        IntentTextResponse => IntentTextResponse,
        WalPullRequest => WalPullRequest,
        WalPullResponse => WalPullResponse,
        ReplicateOp => ReplicateOp,
        LeaseGrant => LeaseGrant,
        SnapshotOffer => SnapshotOffer,
        ReplicateAck => ReplicateAck,
        MembershipUpdate => MembershipUpdate,
        LeaveNotice => LeaveNotice,
        CertRevoke => CertRevoke,
        RendezvousAccept => RendezvousAccept,
        ArtifactAnnounce => ArtifactAnnounce,
    }
}

fn typed<M: Codec + std::fmt::Debug>(
    body: &[u8],
    signed: bool,
    out: &mut String,
) -> Result<(), CliError> {
    let mut r = Reader::new(body);
    let m = M::decode_body(&mut r).map_err(|e| fail("декод тела", e))?;
    // Хвост после «полного» тела — это либо лишний байт, либо следы следующего кадра: декод обязан
    // сказать об этом, а не промолчать и объявить кадр разобранным.
    r.expect_end().map_err(|e| fail("лишние байты после тела", e))?;
    out.push_str(&format!("как {}:\n{m:?}\n", M::KIND.name()));
    let canonical = m.body_bytes();
    let same = canonical == body;
    out.push_str(&format!(
        "каноничность: принято {} байт, пересобрано {} байт, совпадает: {}\n",
        body.len(),
        canonical.len(),
        same
    ));
    if !same {
        out.push_str(
            "ВНИМАНИЕ: декод→энкод дал другие байты. Подпись считается по каноническому телу (§5.2), \
             значит этот кадр не примут повторно, даже если подпись корректна для пришедших байтов.\n",
        );
    }
    let flags = if signed { FLAG_SIGNED } else { 0 };
    let material = sig_input(M::DOMAIN, M::KIND, flags, &canonical);
    // Префикс хеша, а не полный дайджест: вывод сверяют глазами «тот ли это кадр», а настоящая
    // проверка подписи делается узлом и `artifact verify`, не этим дампом (§5.2).
    let digest = blake3::hash(&material);
    out.push_str(&format!(
        "домен подписи `{}`, sig_input {} байт, blake3 {}\n",
        String::from_utf8_lossy(M::DOMAIN),
        material.len(),
        hex::encode(&digest.as_bytes()[..16])
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::codec::DIM;
    use vecdht_wire::frame::encode_frame;
    use vecdht_wire::messages::Match;

    fn publish() -> Publish {
        Publish {
            preprocessing_version: 1,
            cluster_id: 777,
            vec_q: [-3i8; DIM],
            owner_ed25519: [0xA1; 32],
            ttl_buckets: 225,
            published_bucket: 1000,
            pow_bits: 24,
            pow_nonce: 7,
            intent_id: [0xB2; 32],
            tlv: vec![],
        }
    }

    fn decode_frame_bytes(frame: &[u8], out: &mut String) -> Result<(), CliError> {
        let hexed = hex::encode(frame);
        let argv = ["wire", "decode", "--hex", &hexed];
        let p = Parsed::parse(&argv[1..]).unwrap();
        exec_decode(&p, out)
    }

    #[test]
    fn the_kinds_table_is_the_whole_protocol_and_no_more() {
        let mut out = String::new();
        exec_kinds(&Parsed::default(), &mut out).unwrap();
        assert_eq!(Kind::ALL.len(), 19, "таблица §5.3");
        for k in Kind::ALL {
            assert!(out.contains(k.name()), "{} не в таблице", k.name());
            assert!(out.contains(&format!("0x{:02X}", k as u8)), "{k:?} без кода");
        }
        assert!(out.contains("19 видов"), "{out}");
        assert!(out.contains("подписанных 12"), "{out}");
    }

    #[test]
    fn a_real_frame_decodes_and_is_byte_canonical() {
        let frame = publish().encode_unsigned();
        let declared = publish().body_bytes().len();
        let mut out = String::new();
        decode_frame_bytes(&frame, &mut out).unwrap();
        assert!(out.contains("вид 0x10 Publish"), "{out}");
        assert!(out.contains(&format!("{declared} байт тела заявлено")), "{out}");
        assert!(out.contains(&format!("принято {declared} байт, пересобрано {declared} байт")), "{out}");
        assert!(out.contains("совпадает: true"), "{out}");
        assert!(out.contains("cluster_id: 777"), "{out}");
        assert!(out.contains("vecdht/v8/publish"), "{out}");
        assert!(!out.contains("ВНИМАНИЕ"), "корректный кадр не обязан ни о чём предупреждать: {out}");
    }

    #[test]
    fn every_kind_has_a_decoder_and_round_trips_its_own_body() {
        // Единственная проверка, что таблица из `Kind::ALL` и arms макроса не разъехались: для
        // каждого вида собираем его тело заново и требуем побайтового совпадения.
        for k in Kind::ALL {
            let body = sample_body(k);
            let frame = encode_frame(k, &body, k.signature_required().then_some(&[0u8; 64]));
            let mut out = String::new();
            decode_frame_bytes(&frame, &mut out)
                .unwrap_or_else(|e| panic!("{k:?}: {e}"));
            assert!(out.contains("совпадает: true"), "{k:?}: неканоничное тело");
        }
    }

    #[test]
    fn a_signed_frame_shows_its_signature_and_the_right_material() {
        let sig = [9u8; 64];
        let frame = MatchResult {
            shard: 5,
            epoch: 99,
            query_id: 1,
            responder_ed25519: [7; 32],
            matches: vec![Match { owner_ed25519: [1; 32], cluster_id: 80, d2: 1000, slot: 3 }],
        }
        .encode_signed(&sig);
        let mut out = String::new();
        decode_frame_bytes(&frame, &mut out).unwrap();
        assert!(out.contains("подпись есть"), "{out}");
        assert!(out.contains("подпись 64 байт"), "{out}");
        assert!(out.contains("vecdht/v8/match"), "{out}");
        assert!(out.contains("09090909"), "{out}");
    }

    #[test]
    fn an_unsigned_frame_of_a_signed_kind_is_warned_about() {
        // Кадр без подписи, но вида, который её требует: приёмник его отвергнет, и вывод обязан
        // говорить то же самое, а не ограничиваться «успешно разобрано».
        let frame = encode_frame(Kind::ArtifactAnnounce, &sample_body(Kind::ArtifactAnnounce), None);
        let mut out = String::new();
        decode_frame_bytes(&frame, &mut out).unwrap();
        assert!(out.contains("требует подписи"), "{out}");
        assert!(out.contains("FLAG_SIGNED"), "{out}");
    }

    #[test]
    fn lenient_prints_the_header_and_the_reason_instead_of_failing() {
        let frame = encode_frame(Kind::ArtifactAnnounce, &[0u8; 8], None);
        let hexed = hex::encode(&frame);
        let argv = ["wire", "decode", "--hex", &hexed, "--lenient"];
        let p = Parsed::parse(&argv[1..]).unwrap();
        let mut out = String::new();
        exec_decode(&p, &mut out).unwrap();
        assert!(out.contains("заголовок"), "{out}");
        assert!(out.contains("не декодируется"), "{out}");
        // Строгий режим тем же кадром обязан вернуться ошибкой, а не кодом 0.
        assert!(decode_frame_bytes(&frame, &mut String::new()).is_err());
    }

    #[test]
    fn two_sources_of_the_same_bytes_is_an_error_not_a_precedence() {
        let argv = ["wire", "decode", "--hex", "0108", "--file", "x"];
        let p = Parsed::parse(&argv[1..]).unwrap();
        let err = exec_decode(&p, &mut String::new()).unwrap_err().to_string();
        assert!(err.contains("два источника"), "{err}");
        let p = Parsed::parse(&["wire", "decode"]).unwrap();
        assert!(exec_decode(&p, &mut String::new()).unwrap_err().to_string().contains("нужен --hex"));
    }

    #[test]
    fn a_truncated_frame_is_reported_not_invented() {
        let mut frame = publish().encode_unsigned();
        frame.truncate(frame.len() - 5);
        let err = decode_frame_bytes(&frame, &mut String::new()).unwrap_err().to_string();
        assert!(err.contains("разбор кадра"), "{err}");
        let hexed = hex::encode(&frame);
        let argv = ["wire", "decode", "--hex", &hexed, "--lenient"];
        let p = Parsed::parse(&argv[1..]).unwrap();
        let mut o = String::new();
        exec_decode(&p, &mut o).unwrap();
        assert!(o.contains("не дочитан"), "{o}");
    }

    #[test]
    fn uppercase_odd_and_empty_hex_are_refused() {
        for bad in ["0A08", "010", ""] {
            let argv = ["wire", "decode", "--hex", bad];
            let p = Parsed::parse(&argv[1..]).unwrap();
            assert!(exec_decode(&p, &mut String::new()).is_err(), "`{bad}` принят");
        }
    }

    /// Каноническое тело каждого вида — чтобы тест выше не зависел от рукописных литералов.
    fn sample_body(k: Kind) -> Vec<u8> {
        match k {
            Kind::Handshake => Handshake {
                role: vecdht_wire::Role::Agent,
                preprocessing_version: 1,
                model_version: "dev/test".into(),
                genesis_hash: [1; 32],
                cert: vec![],
                tlv: vec![],
            }
            .body_bytes(),
            Kind::Error => ProtocolError {
                code: vecdht_wire::err_code::BUSY.into(),
                retry_after_ms: 250,
                shard: 12,
            }
            .body_bytes(),
            Kind::Publish => publish().body_bytes(),
            Kind::PublishAck => PublishAck {
                shard: 5,
                epoch: 99,
                seq: 1234,
                slot: 77,
                next_pow_bits: 26,
                error_code: "OK".into(),
                retry_after_ms: 0,
            }
            .body_bytes(),
            Kind::Find => Find {
                preprocessing_version: 1,
                query_vector: [3i8; DIM],
                clusters: vec![10, 41, 300],
                top_k: 32,
                query_id: 0xDEAD_BEEF,
                requester_ed25519: [0xC3; 32],
                tlv: vec![],
            }
            .body_bytes(),
            Kind::MatchResult => MatchResult {
                shard: 5,
                epoch: 99,
                query_id: 1,
                responder_ed25519: [7; 32],
                matches: vec![
                    Match { owner_ed25519: [1; 32], cluster_id: 80, d2: 1000, slot: 3 },
                    Match { owner_ed25519: [2; 32], cluster_id: 81, d2: 1001, slot: 4 },
                ],
            }
            .body_bytes(),
            Kind::IntentTextRequest => IntentTextRequest {
                query_id: 5,
                target_ed25519: [0xEE; 32],
                slot: 41,
                present: vec![0x50; 9],
            }
            .body_bytes(),
            Kind::IntentTextResponse => IntentTextResponse {
                owner_ed25519: [1; 32],
                model_version: "dev/test".into(),
                preprocessing_version: 1,
                text: b"tekst".to_vec(),
            }
            .body_bytes(),
            Kind::WalPullRequest => {
                WalPullRequest { shard: 5, from_seq: 10, to_seq: 0, max_bytes: 1 << 20 }.body_bytes()
            }
            Kind::WalPullResponse => WalPullResponse {
                shard: 5,
                from_seq: 10,
                to_seq: 12,
                primary_epoch: 3,
                frames: vec![1, 2, 3, 4],
            }
            .body_bytes(),
            Kind::ReplicateOp => ReplicateOp {
                shard: 5,
                epoch: 3,
                seq: 11,
                op_kind: vecdht_wire::OpKind::TimeMark,
                body: vecdht_wire::messages::encode_mark(11, 100),
            }
            .body_bytes(),
            Kind::LeaseGrant => LeaseGrant {
                shard: 5,
                epoch: 3,
                primary_ed25519: [4; 32],
                dht_peer_id: vec![0xAA, 0xBB],
                expires_at_bucket: 1000,
            }
            .body_bytes(),
            Kind::SnapshotOffer => SnapshotOffer {
                shard: 5,
                epoch: 3,
                snapshot_seq: 9,
                oldest_wal_needed: 1,
                applied_seq: 20,
                next_slot: 4,
                time_mark_bucket: 100,
                total_len: 4,
                offset: 0,
                content_hash: [8; 32],
                chunk: vec![1, 2, 3, 4],
            }
            .body_bytes(),
            Kind::ReplicateAck => ReplicateAck {
                shard: 5,
                epoch: 3,
                seq: 11,
                replica_ed25519: [6; 32],
                applied_seq: 11,
                ok: true,
            }
            .body_bytes(),
            Kind::MembershipUpdate => MembershipUpdate {
                epoch: 3,
                shard: 5,
                members: vec![vecdht_wire::Member {
                    owner_ed25519: [7; 32],
                    dht_peer_id: vec![0xCC],
                    capacity_entries: 1000,
                }],
                primary_idx: 0,
                generated_at: 100,
                sigs: vec![(0, [0x11; 64])],
            }
            .body_bytes(),
            Kind::LeaveNotice => LeaveNotice {
                epoch: 3,
                shard: 5,
                leaving_owner: [8; 32],
                drain_deadline_bucket: 100,
            }
            .body_bytes(),
            Kind::CertRevoke => CertRevoke {
                nonce: [9; 16],
                revoked_at: 100,
                reason: "rotated".into(),
                authority_sigs: vec![[0x22; 64]],
            }
            .body_bytes(),
            Kind::RendezvousAccept => RendezvousAccept {
                seeker: [10; 32],
                target: [11; 32],
                shard: 5,
                slot: 3,
                issued_bucket: 100,
                ttl_sec: 300,
            }
            .body_bytes(),
            Kind::ArtifactAnnounce => vecdht_wire::ArtifactAnnounce {
                artifact_hash: [12; 32],
                model_version: "dev/test".into(),
                preprocessing_version: 1,
                nlist: 1024,
                clusters_per_shard: 16,
                issued_at: 100,
            }
            .body_bytes(),
        }
    }
}
