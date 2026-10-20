//! Тексты интентов (§6.6, §12.4): запрос текста и подписанный ответ владельца.
//!
//! Текст идёт напрямую между агентами и не проходит через index-node: rerank обязан жить на
//! агенте (§12.4.1), а сам текст не должен попадать в путь маршрутизации §12.1. Поэтому здесь
//! только два конца обмена, а не сервер: [`encode_request`]/[`parse_request`] для запроса и
//! [`sign_response`]/[`verify_response`] для ответа.
//!
//! Подпись ставит владелец интента, и проверяется она **до** того, как текст станет доступен
//! вызывающему: ответ — чужой байтовый поток, а текст в нём — данные для контекста агента, а не
//! инструкции (§12.4). Проверка «подпись валидна» и «владелец — ожидаемый» неделима: подпись
//! верна ровно для того ключа, который её поставил, и принимать текст «от кого угодно, кто
//! подписал» значило бы разрешить подмену источника.
//!
//! Запрос не подписывается: он идёт по уже аутентифицированному соединению (§12.5), а его
//! `target_ed25519` — маршрутизация внутри этого соединения, не идентичность. Подпись запроса
//! добавила бы только возможность отличить одного анонимного агента от другого, чего протокол
//! не обещает и не требует.

use thiserror::Error;
use vecdht_crypto::{verify_body, Identity};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{
    domain, Codec, IntentTextRequest, IntentTextResponse, MAX_INTENT_TEXT_BYTES,
};

use crate::net::Addr;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TextError {
    #[error("кадр не разобран как сообщение IntentText")]
    Malformed,
    #[error("кадр не того вида для этого шага обмена")]
    WrongKind,
    #[error("IntentTextResponse обязан быть подписан владельцем (§6.6)")]
    Unsigned,
    #[error("запрос адресован не этому владельцу")]
    WrongTarget,
    #[error("ответ подписан не ожидаемым владельцем")]
    WrongOwner { expected: Addr, found: Addr },
    #[error("подпись текста не соответствует владельцу")]
    BadSignature,
    #[error("текст {0} байт превышает лимит 1000 байт UTF-8 (§6.6)")]
    TextTooLong(usize),
    #[error("текст не является UTF-8")]
    NotUtf8,
}

/// Проверенный ответ: текст уже прошёл владельца, подпись, лимит и UTF-8. Отдельный тип, а не
/// [`IntentTextResponse`], чтобы непроверенные байты нельзя было случайно передать в rerank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentText {
    pub owner_ed25519: Addr,
    pub model_version: String,
    pub preprocessing_version: u16,
    pub text: String,
}

/// Запрос текста у владельца записи (§12.4). `slot` — из `MatchResult`, на который отвечает
/// агент: старый слот после смены эпизоды даёт `NO_SUCH_SLOT` на стороне владельца, а не чужой
/// текст.
pub fn encode_request(query_id: u64, target: Addr, slot: u32) -> Vec<u8> {
    IntentTextRequest { query_id, target_ed25519: target, slot }.encode_unsigned()
}

/// Разобрать запрос на стороне владельца и убедиться, что он адресован именно ему.
pub fn parse_request(frame: &[u8], me: &Addr) -> Result<IntentTextRequest, TextError> {
    let f = decode_frame(frame).map_err(|_| TextError::Malformed)?;
    if f.header.kind != Kind::IntentTextRequest {
        return Err(TextError::WrongKind);
    }
    let req = IntentTextRequest::decode(frame).map_err(|_| TextError::Malformed)?;
    if req.target_ed25519 != *me {
        return Err(TextError::WrongTarget);
    }
    Ok(req)
}

/// Подписать ответ владельца. `text` принимается строкой: канонический intent_text — это UTF-8
/// по построению (§6.6), и API не должен давать возможность подписать байты, которые затем не
/// пройдут собственную проверку получателя.
pub fn sign_response(
    owner: &Identity,
    model_version: &str,
    preprocessing_version: u16,
    text: &str,
) -> Result<Vec<u8>, TextError> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_INTENT_TEXT_BYTES {
        return Err(TextError::TextTooLong(bytes.len()));
    }
    let resp = IntentTextResponse {
        owner_ed25519: owner.pubkey(),
        model_version: model_version.to_string(),
        preprocessing_version,
        text: bytes.to_vec(),
    };
    let body = resp.body_bytes();
    let sig = owner.sign_body(domain::TEXT, Kind::IntentTextResponse, &body);
    Ok(resp.encode_signed(&sig))
}

/// Проверить ответ и вернуть текст только после проверки всех условий §6.6/§12.4.
///
/// Порядок: вид кадра → наличие подписи → разбор тела → ожидаемый владелец → подпись → UTF-8.
/// Владелец сверяется до криптографии намеренно: подпись чужого ключа не должна даже считаться,
/// и ошибка обязана называть источник, а не «подпись не сошлась».
pub fn verify_response(frame: &[u8], expected_owner: &Addr) -> Result<IntentText, TextError> {
    let f = decode_frame(frame).map_err(|_| TextError::Malformed)?;
    if f.header.kind != Kind::IntentTextResponse {
        return Err(TextError::WrongKind);
    }
    let sig: [u8; 64] = match f.signature {
        Some(s) => s.try_into().map_err(|_| TextError::Unsigned)?,
        None => return Err(TextError::Unsigned),
    };
    let resp = IntentTextResponse::decode(frame).map_err(|_| TextError::Malformed)?;
    if resp.owner_ed25519 != *expected_owner {
        return Err(TextError::WrongOwner {
            expected: *expected_owner,
            found: resp.owner_ed25519,
        });
    }
    if !verify_body(expected_owner, domain::TEXT, Kind::IntentTextResponse, f.body, &sig)
        .unwrap_or(false)
    {
        return Err(TextError::BadSignature);
    }
    // Лимит уже проверен декодером; повтор здесь — для симметрии с `sign_response`, чтобы
    // контракт не зависел от того, кто и когда поменяет wire-декодер.
    if resp.text.len() > MAX_INTENT_TEXT_BYTES {
        return Err(TextError::TextTooLong(resp.text.len()));
    }
    let text = String::from_utf8(resp.text).map_err(|_| TextError::NotUtf8)?;
    Ok(IntentText {
        owner_ed25519: resp.owner_ed25519,
        model_version: resp.model_version,
        preprocessing_version: resp.preprocessing_version,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::messages::domain;

    fn addr(i: u8) -> Addr {
        [i; 32]
    }

    #[test]
    fn a_signed_response_roundtrips_and_carries_owner_and_versions() {
        let owner = Identity::from_seed([21; 32]);
        let frame = sign_response(&owner, "granite", 7, "ищу контракт на Rust").expect("ответ");
        let text = verify_response(&frame, &owner.pubkey()).expect("проверка");
        assert_eq!(text.owner_ed25519, owner.pubkey());
        assert_eq!((text.model_version.as_str(), text.preprocessing_version), ("granite", 7));
        assert_eq!(text.text, "ищу контракт на Rust");
    }

    #[test]
    fn an_unsigned_response_is_refused_even_with_valid_body() {
        let owner = Identity::from_seed([22; 32]);
        let resp = IntentTextResponse {
            owner_ed25519: owner.pubkey(),
            model_version: "m".into(),
            preprocessing_version: 1,
            text: b"text".to_vec(),
        };
        assert_eq!(
            verify_response(&resp.encode_unsigned(), &owner.pubkey()),
            Err(TextError::Unsigned)
        );
    }

    #[test]
    fn a_tampered_byte_breaks_the_signature() {
        let owner = Identity::from_seed([23; 32]);
        let mut frame = sign_response(&owner, "m", 1, "abcdef").expect("ответ");
        // Тело заканчивается перед `[u8 sig_len][64]`; последний байт тела — текст.
        let last_body = frame.len() - 1 - 64 - 1;
        frame[last_body] ^= 1;
        assert_eq!(
            verify_response(&frame, &owner.pubkey()),
            Err(TextError::BadSignature),
            "подмена текста не должна проходить как тот же ответ"
        );
    }

    #[test]
    fn a_response_from_another_owner_is_named_not_just_rejected() {
        let owner = Identity::from_seed([24; 32]);
        let other = Identity::from_seed([25; 32]);
        let frame = sign_response(&owner, "m", 1, "text").expect("ответ");
        assert_eq!(
            verify_response(&frame, &other.pubkey()),
            Err(TextError::WrongOwner { expected: other.pubkey(), found: owner.pubkey() })
        );
    }

    #[test]
    fn text_over_the_limit_is_refused_at_signing_time() {
        let owner = Identity::from_seed([26; 32]);
        let long = "a".repeat(MAX_INTENT_TEXT_BYTES + 1);
        assert_eq!(
            sign_response(&owner, "m", 1, &long),
            Err(TextError::TextTooLong(MAX_INTENT_TEXT_BYTES + 1))
        );
    }

    #[test]
    fn a_non_utf8_text_is_refused_even_when_correctly_signed() {
        // `sign_response` строку не пропустит, но байты приходят из чужого процесса: проверка
        // обязана стоять и на приёме, а не только на нашей стороне.
        let owner = Identity::from_seed([27; 32]);
        let resp = IntentTextResponse {
            owner_ed25519: owner.pubkey(),
            model_version: "m".into(),
            preprocessing_version: 1,
            text: vec![0xFF, 0xFE],
        };
        let body = resp.body_bytes();
        let sig = owner.sign_body(domain::TEXT, Kind::IntentTextResponse, &body);
        assert_eq!(
            verify_response(&resp.encode_signed(&sig), &owner.pubkey()),
            Err(TextError::NotUtf8)
        );
    }

    #[test]
    fn a_request_is_bound_to_its_target() {
        let me = addr(2);
        let frame = encode_request(11, me, 41);
        let req = parse_request(&frame, &me).expect("адресован мне");
        assert_eq!((req.query_id, req.target_ed25519, req.slot), (11, me, 41));
        assert_eq!(parse_request(&frame, &addr(3)), Err(TextError::WrongTarget));
    }
}
