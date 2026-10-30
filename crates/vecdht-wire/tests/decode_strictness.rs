//! H-0162/m1: у кадра v8 одно каноническое представление (§5.1).
//!
//! До этой правки `decode_frame` не смотрел на остаток после тела или после подписи, поэтому
//! `frame + мусор` разбирался в тот же `Frame` — вторая форма записи одного сообщения. Здесь
//! оба случая закреплены как отказ `TrailingBytes`, а канонические кадры проходят.

use vecdht_wire::codec::DecodeError;
use vecdht_wire::frame::{decode_frame, encode_frame, Kind, FLAG_SIGNED};

#[test]
fn unsigned_frame_with_a_trailing_byte_is_rejected() {
    let f = encode_frame(Kind::Find, &[1, 2, 3], None);
    let d = decode_frame(&f).expect("канонический неподписанный кадр обязан разбираться");
    assert_eq!(d.header.kind, Kind::Find);
    assert_eq!(d.body, &[1, 2, 3]);
    assert!(d.signature.is_none());

    let mut padded = f.clone();
    padded.push(0xAA);
    match decode_frame(&padded) {
        Err(DecodeError::TrailingBytes { offset }) => {
            assert_eq!(offset, f.len(), "offset хвоста — индекс первого лишнего байта")
        }
        other => panic!("хвост после тела обязан быть TrailingBytes, получено {other:?}"),
    }
}

#[test]
fn signed_frame_with_trailing_bytes_is_rejected() {
    let sig = [9u8; 64];
    let f = encode_frame(Kind::MatchResult, &[7, 7], Some(&sig));
    let d = decode_frame(&f).expect("канонический подписанный кадр обязан разбираться");
    assert_eq!(d.signature, Some(&sig[..]));
    assert!(d.header.flags & FLAG_SIGNED != 0);

    let mut padded = f.clone();
    padded.extend_from_slice(&[0xAA, 0xBB]);
    match decode_frame(&padded) {
        Err(DecodeError::TrailingBytes { offset }) => {
            assert_eq!(offset, f.len(), "offset хвоста — индекс первого лишнего байта")
        }
        other => panic!("хвост после подписи обязан быть TrailingBytes, получено {other:?}"),
    }

    // Усечение остаётся усечением: строгость хвоста не должна подменять диагноз.
    let cut = &f[..f.len() - 1];
    assert!(
        matches!(decode_frame(cut), Err(DecodeError::Truncated { .. })),
        "недостающая подпись обязана остаться Truncated"
    );
}
