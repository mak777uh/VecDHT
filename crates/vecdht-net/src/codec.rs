//! Кадры v8 как запрос/ответ поверх libp2p-стрима (§5.3).
//!
//! Транспорт не знает, что внутри кадра: он пересылает ровно те байты, которые собрал
//! `vecdht-wire`, и не перекодирует их. Это важно по той же причине, по которой §5.1 требует
//! один кодек: подпись считается по каноническим байтам тела, и любой промежуточный parse →
//! re-encode менял бы вход проверки.
//!
//! Формат провода — не сам кадр, а его длина:
//!
//! ```text
//! запрос:  u32 len | frame[len]
//! ответ:   u32 count | count × (u32 len | frame[len])
//! ```
//!
//! Длина перед кадром нужна потому, что `request-response` не говорит кодеку, сколько байт
//! придёт: без префикса `read_request` читал бы заголовок кадра, потом тело, но для батча
//! ответов (`Find` → `MatchResult` + до 32 `RendezvousAccept`) пришлось бы либо считать
//! кадры до EOF (полузакрытие стрима — не часть контракта), либо завести свой счётчик.
//! Счётчик и есть этот префикс.
//!
//! Лимиты зеркалят `vecdht-wire::codec`: тело ≤ 4 МиБ, подпись ≤ 64 байта, батч ≤ 256
//! кадров. Всё, что больше, — ошибка кодека, а не повод прочитать гигабайт в память
//! (anti-DoS на уровне транспорта, §11.3).

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec as RequestResponseCodec;
use libp2p::StreamProtocol;
use thiserror::Error;
use vecdht_wire::codec::MAX_BODY_LEN;
use vecdht_wire::frame::{ED25519_SIG_LEN, FLAG_SIGNED};

/// Единственный протокол кадров v8. Версия в пути дублирует `PROTOCOL_VERSION` намеренно:
/// несовместимый major обязан отваливаться на мультистриме, а не после разбора тела.
pub const FRAME_PROTOCOL: StreamProtocol = StreamProtocol::new("/vecdht/v8/frame");

/// 8 байт заголовка + тело + (1 + 64) байта подписи. Больше физически не бывает.
pub const MAX_FRAME_LEN: usize = 8 + MAX_BODY_LEN + 1 + ED25519_SIG_LEN;

/// `Find` возвращает `MatchResult` и по приёму на каждый match; 256 — с запасом к top-32.
/// Потолок нужен, чтобы счётчик в ответе не превращался в обещание аллокации.
pub const MAX_BATCH: usize = 256;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("кадр длиннее предела: {0} байт")]
    TooLong(usize),
    #[error("батч длиннее предела: {0} кадров")]
    BatchTooLong(usize),
    #[error("обрыв потока: {0}")]
    Io(#[from] std::io::Error),
}

/// Чистое кодирование запроса: префикс длины + кадр.
pub fn encode_request(frame: &[u8]) -> Result<Vec<u8>, CodecError> {
    if frame.len() > MAX_FRAME_LEN {
        return Err(CodecError::TooLong(frame.len()));
    }
    let mut out = Vec::with_capacity(4 + frame.len());
    out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    out.extend_from_slice(frame);
    Ok(out)
}

/// Разбор запроса из буфера целиком. Возвращает кадр и позицию после него.
pub fn parse_request(buf: &[u8]) -> Result<&[u8], CodecError> {
    if buf.len() < 4 {
        return Err(CodecError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "нет префикса длины",
        )));
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if n > MAX_FRAME_LEN {
        return Err(CodecError::TooLong(n));
    }
    let end = 4 + n;
    if buf.len() < end {
        return Err(CodecError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "кадр короче объявленной длины",
        )));
    }
    let frame = &buf[4..end];
    // Внешняя длина обязана совпадать с внутренней, иначе один и тот же байтовый поток
    // допускал бы два разных прочтения границы кадра.
    let declared = declared_frame_len(frame)?;
    if declared != n {
        return Err(CodecError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "длина префикса не совпала с длиной заголовка кадра",
        )));
    }
    Ok(frame)
}

/// Собрать батч ответа: счётчик + (длина + кадр) на каждый.
pub fn encode_response(frames: &[Vec<u8>]) -> Result<Vec<u8>, CodecError> {
    if frames.len() > MAX_BATCH {
        return Err(CodecError::BatchTooLong(frames.len()));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(frames.len() as u32).to_le_bytes());
    for f in frames {
        if f.len() > MAX_FRAME_LEN {
            return Err(CodecError::TooLong(f.len()));
        }
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    Ok(out)
}

/// Разобрать батч ответа.
pub fn parse_response(buf: &[u8]) -> Result<Vec<&[u8]>, CodecError> {
    if buf.len() < 4 {
        return Err(CodecError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "нет счётчика батча",
        )));
    }
    let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if count > MAX_BATCH {
        return Err(CodecError::BatchTooLong(count));
    }
    let mut out = Vec::with_capacity(count);
    let mut at = 4;
    for _ in 0..count {
        if buf.len() < at + 4 {
            return Err(CodecError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "батч оборван на длине кадра",
            )));
        }
        let n = u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize;
        at += 4;
        if n > MAX_FRAME_LEN {
            return Err(CodecError::TooLong(n));
        }
        if buf.len() < at + n {
            return Err(CodecError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "батч оборван на кадре",
            )));
        }
        let frame = &buf[at..at + n];
        let declared = declared_frame_len(frame)?;
        if declared != n {
            return Err(CodecError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "длина префикса не совпала с длиной заголовка кадра",
            )));
        }
        out.push(frame);
        at += n;
    }
    if at != buf.len() {
        return Err(CodecError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "лишние байты после батча",
        )));
    }
    Ok(out)
}

/// Сколько байт занимает кадр по его собственному заголовку (§5.1).
///
/// Проверяется только геометрия, не семантика: тип кадра и версия — дело `decode_frame`,
/// а здесь важно не дать префиксу и заголовку разойтись.
fn declared_frame_len(frame: &[u8]) -> Result<usize, CodecError> {
    if frame.len() < 8 {
        return Err(CodecError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "кадр короче заголовка",
        )));
    }
    let flags = u16::from_le_bytes([frame[2], frame[3]]);
    let body_len = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    let mut total = 8 + body_len;
    if flags & FLAG_SIGNED != 0 {
        total += 1 + ED25519_SIG_LEN;
    }
    Ok(total)
}

/// Кодек `request-response`: запрос — один кадр, ответ — батч кадров.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameCodec;

/// `request-response` требует `io::Error` от кодека: своего типа ошибки у трейта нет.
/// Обрыв потока остаётся собой, а нарушение формата — `InvalidData`, чтобы вызывающая
/// сторона могла отличить «пир закрыл стрим» от «пир прислал не то».
fn to_io(e: CodecError) -> std::io::Error {
    match e {
        CodecError::Io(e) => e,
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
    }
}

#[async_trait]
impl RequestResponseCodec for FrameCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<Vec<u8>>;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len = [0u8; 4];
        io.read_exact(&mut len).await?;
        let n = u32::from_le_bytes(len) as usize;
        if n > MAX_FRAME_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                CodecError::TooLong(n),
            ));
        }
        let mut frame = vec![0u8; n];
        io.read_exact(&mut frame).await?;
        let declared = declared_frame_len(&frame).map_err(to_io)?;
        if declared != n {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "длина префикса не совпала с длиной заголовка кадра",
            ));
        }
        Ok(frame)
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_request(&req).map_err(to_io)?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut count = [0u8; 4];
        io.read_exact(&mut count).await?;
        let count = u32::from_le_bytes(count) as usize;
        if count > MAX_BATCH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                CodecError::BatchTooLong(count),
            ));
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut len = [0u8; 4];
            io.read_exact(&mut len).await?;
            let n = u32::from_le_bytes(len) as usize;
            if n > MAX_FRAME_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    CodecError::TooLong(n),
                ));
            }
            let mut frame = vec![0u8; n];
            io.read_exact(&mut frame).await?;
            let declared = declared_frame_len(&frame).map_err(to_io)?;
            if declared != n {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "длина префикса не совпала с длиной заголовка кадра",
                ));
            }
            out.push(frame);
        }
        Ok(out)
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_response(&res).map_err(to_io)?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::frame::{encode_frame, Kind};

    fn frame(body: &[u8], signed: bool) -> Vec<u8> {
        if signed {
            encode_frame(Kind::PublishAck, body, Some(&[7u8; 64]))
        } else {
            encode_frame(Kind::PublishAck, body, None)
        }
    }

    #[test]
    fn request_roundtrip_keeps_the_frame_verbatim() {
        let f = frame(&[1, 2, 3], true);
        let wire = encode_request(&f).unwrap();
        assert_eq!(parse_request(&wire).unwrap(), &f[..]);
        // Внешний префикс обязан совпасть с внутренней геометрией: подпись входит в длину.
        assert_eq!(wire.len(), 4 + 8 + 3 + 1 + 64);
    }

    #[test]
    fn response_roundtrip_preserves_order_and_count() {
        let a = frame(&[0xAA; 10], false);
        let b = frame(&[0xBB; 20], true);
        let wire = encode_response(&[a.clone(), b.clone()]).unwrap();
        let got = parse_response(&wire).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], &a[..]);
        assert_eq!(got[1], &b[..]);
        // Пустой батч — легитимный ответ (реплика не нашла, что сказать), но он всё равно
        // несёт счётчик, и «пусто» неотличимо от обрыва только по длине.
        let empty = encode_response(&[]).unwrap();
        assert!(parse_response(&empty).unwrap().is_empty());
    }

    #[test]
    fn prefix_disagreeing_with_the_header_is_rejected() {
        let mut f = frame(&[1, 2, 3], false);
        f[4] = 99; // body_len заявляет больше, чем лежит в кадре
        let wire = encode_request(&f).unwrap();
        assert!(matches!(parse_request(&wire), Err(CodecError::Io(_))));
    }

    #[test]
    fn oversized_declarations_are_refused_before_allocation() {
        let mut wire = vec![0u8; 4];
        wire.copy_from_slice(&(MAX_FRAME_LEN as u32 + 1).to_le_bytes());
        wire.extend_from_slice(&[0u8; 8]);
        assert!(matches!(parse_request(&wire), Err(CodecError::TooLong(_))));

        let mut batch = vec![0u8; 4];
        batch.copy_from_slice(&(MAX_BATCH as u32 + 1).to_le_bytes());
        assert!(matches!(parse_response(&batch), Err(CodecError::BatchTooLong(_))));
    }

    #[test]
    fn trailing_bytes_after_a_batch_are_an_error() {
        let f = frame(&[1], false);
        let mut wire = encode_response(&[f]).unwrap();
        wire.push(0);
        assert!(parse_response(&wire).is_err(), "лишний байт — это другой протокол, а не мусор");
    }
}
