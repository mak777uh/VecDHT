//! Оракул H-0063/E-0063: UTF-8-ветка `session::verify_response` — последняя немеренная как
//! ПОРЯДОК ветка §12.4; два разных имени для битого UTF-8 в двух полях ответа.
//!
//! Спека §12.4: «Ответ принимается только после проверки вида кадра, наличия подписи,
//! `owner_ed25519 == ожидаемого владельца`, подписи по ключу владельца и UTF-8». UTF-8 —
//! последний гейт цепочки, и в тестах-оракулах (`crates/vecdht-node/tests/`) grep по
//! `TextError::NotUtf8` даёт НОЛЬ: базовый факт (битый текст с честной подписью → `NotUtf8`)
//! стоит только юнит-тестом модуля (`session.rs:271`), а порядковые комбинации — битый текст
//! при ЧУЖОЙ подписи (должна умирать раньше контента) и битый `model_version` (строка внутри
//! тела: её проверяет декодер, и отказ зовётся иначе) — не измерялись никогда.
//!
//! Два поля одного кадра несут UTF-8-контракт по-разному: `text` декодируется как `bytes`
//! (`codec.rs:272` — никаких проверок содержимого, только длина) и ловится гейтом
//! `session.rs:192` → `NotUtf8`; `model_version` декодируется как `string`
//! (`codec.rs:280` → `String::from_utf8` → `DecodeError`) и ловится на разборе тела →
//! `Malformed` (`session.rs:175`). Гипотеза: имена отказов различают поле и момент —
//! битый текст с честной подписью НЕ даёт `Malformed`, битая строка версии с честной
//! подписью НЕ даёт `NotUtf8`.
//!
//! Пороги (O — издатель, E — чужой ожидаемый ключ, F — третий ключ-подписант):
//! (0) раскладка честного кадра («гранит», «abcdef»): длина 8 + тело + 1 + 64, байт тела по
//!     смещению `8+32+2` равен 0xD0 (первый байт «г»); декодер ПРОПУСКАЕТ non-UTF-8 текст
//!     (`bytes`-поле), `verify_response(_, &O)` на non-UTF-8 тексте [0xFF,0xFE] с честной
//!     подписью O → `NotUtf8` (базовый факт, повторён на входе оракула);
//! (1) тот же non-UTF-8 текст, подпись ключом F, ожидаемый O → `BadSignature`, а не `NotUtf8`
//!     (подпись раньше содержимого);
//! (2) тот же кадр при ожидаемом E → `WrongOwner{expected: E, found: O}`, а не `NotUtf8`
//!     (владелец раньше содержимого);
//! (3) non-UTF-8 текст, чужой табличный вид `IntentTextRequest` с честной подписью →
//!     `WrongKind` (вид раньше содержимого);
//! (4) non-UTF-8 текст без подписи → `Unsigned` (наличие подписи раньше содержимого);
//! (5) граница лимита включительно: ровно 1000 байт валидного UTF-8 («я»×500) с честной
//!     подписью O → `Ok` и побайтовый раунд-трип текста;
//! (6) 999 байт с обрезанной последовательностью («я»×499 + 0xD1) с честной подписью →
//!     `NotUtf8` — гейт не сводится к длине: по длине кадр проходит, по содержимому нет;
//! (7) честный кадр, байт `model_version` 0xD0 → 0xFF (in-place, длина та же, подпись не
//!     тронута, но уже не нужна): при ожидаемом O → `Malformed`, а НЕ `BadSignature` и НЕ
//!     `NotUtf8` — строку проверяет декодер тела;
//! (8) тот же кадр при ожидаемом E → `Malformed` (разбор раньше владельца — зеркало (7));
//! (9) подписывающий конец: `sign_response` типизирован строкой и не может выдать битый
//!     UTF-8 — `verify_response(sign_response(...))` с многобайтовым юникодом в модели и
//!     тексте → `Ok` с побайтовым раунд-трипом обоих полей (канон §6.6 «UTF-8 по
//!     построению» на обоих концах).
//!
//! Фальсификаторы: (а) (1)/(2) дали `NotUtf8` — контент проверяется раньше подписи/владельца
//! (цепочка §12.4 перевёрнута); (б) (3)/(4) дали не `WrongKind`/`Unsigned` — содержимое
//! лезет в начало цепочки; (в) (5) отвергнут — лимит 1000 не включительный, спека врёт про
//! границу; (г) (6) дал `Ok` — UTF-8-гейта нет, длина была единственной проверкой;
//! (д) (7) дал `BadSignature` — декодер не проверяет строки, контракт `string`-поля иллюзорен;
//! (е) (7) дал `NotUtf8` — имя отказа не различает поле и момент;
//! (ж) (8) дал `WrongOwner` — владелец раньше разбора тела на битой строке;
//! (з) (0) декодер отверг non-UTF-8 `text` — `bytes`-поле на деле не bytes;
//! (и) (5)/(9) раунд-трип не побайтовый.

use vecdht_crypto::Identity;
use vecdht_node::{session, testing};
use vecdht_wire::frame::{encode_frame, Kind};
use vecdht_wire::messages::{domain, Codec, IntentTextResponse, MAX_INTENT_TEXT_BYTES};

fn response(owner: [u8; 32], model: &str, text: Vec<u8>) -> IntentTextResponse {
    IntentTextResponse {
        owner_ed25519: owner,
        model_version: model.to_string(),
        preprocessing_version: 7,
        text,
    }
}

/// Кадр ответа с подписью заданного ключа по собственному каноническому телу.
fn signed_by(resp: &IntentTextResponse, signer: &Identity) -> Vec<u8> {
    let sig = signer.sign_body(domain::TEXT, Kind::IntentTextResponse, &resp.body_bytes());
    resp.encode_signed(&sig)
}

fn with_byte(frame: &[u8], at: usize, b: u8) -> Vec<u8> {
    let mut v = frame.to_vec();
    v[at] = b;
    v
}

#[test]
fn utf8_is_the_last_gate_and_two_fields_pay_different_names() {
    let owner = testing::identity(60);
    let other = testing::identity(61);
    let foreign = testing::identity(62);
    let o = owner.pubkey();
    let e = other.pubkey();

    // (0) Базовый факт на входе оракула: декодер пропускает битый текст, гейт — последний.
    let bad_text = vec![0xFFu8, 0xFE];
    let bad = response(o, "гранит", bad_text.clone());
    let bad_frame = signed_by(&bad, &owner);
    let dec = IntentTextResponse::decode(&bad_frame).expect("фальсификатор (з): bytes-поле не пропустило битые байты");
    assert_eq!(dec.text, bad_text, "фальсификатор (з): декодер изменил текст");
    assert_eq!(
        session::verify_response(&bad_frame, &o),
        Err(session::TextError::NotUtf8),
        "порог (0): базовый NotUtf8 не на месте"
    );

    // (1) Чужая подпись на битом тексте умирает раньше контентного гейта.
    assert_eq!(
        session::verify_response(&signed_by(&bad, &foreign), &o),
        Err(session::TextError::BadSignature),
        "фальсификатор (а): контент проверен раньше подписи"
    );
    // (2) Чужой ожидаемый владелец — раньше контента.
    assert_eq!(
        session::verify_response(&bad_frame, &e),
        Err(session::TextError::WrongOwner { expected: e, found: o }),
        "фальсификатор (а): контент проверен раньше владельца"
    );
    // (3) Чужой табличный вид — раньше контента.
    assert_eq!(
        session::verify_response(
            &encode_frame(Kind::IntentTextRequest, &bad.body_bytes(), Some(&owner.sign_body(domain::TEXT, Kind::IntentTextResponse, &bad.body_bytes()))),
            &o,
        ),
        Err(session::TextError::WrongKind),
        "фальсификатор (б): содержимое добралось до конца цепочки"
    );
    // (4) Отсутствие подписи — раньше контента.
    assert_eq!(
        session::verify_response(&bad.encode_unsigned(), &o),
        Err(session::TextError::Unsigned),
        "фальсификатор (б): содержимое проверено раньше наличия подписи"
    );

    // (5) Граница лимита включительно: ровно 1000 байт валидного UTF-8 проходит целиком.
    let edge = "я".repeat(MAX_INTENT_TEXT_BYTES / 2); // «я» = 2 байта → ровно 1000
    assert_eq!(edge.len(), MAX_INTENT_TEXT_BYTES, "фикстура (5): не 1000 байт");
    let er = response(o, "гранит", edge.as_bytes().to_vec());
    let got = session::verify_response(&signed_by(&er, &owner), &o)
        .expect("фальсификатор (в): лимит 1000 не включительный");
    assert_eq!(got.text, edge, "фальсификатор (и): раунд-трип текста не побайтовый");

    // (6) По длине проходит, по содержимому — нет: гейт не сводится к лимиту.
    let mut trunc = "я".repeat(499).into_bytes();
    trunc.push(0xD1);
    assert_eq!(trunc.len(), 999, "фикстура (6): не 999 байт");
    let tr = response(o, "гранит", trunc);
    assert_eq!(
        session::verify_response(&signed_by(&tr, &owner), &o),
        Err(session::TextError::NotUtf8),
        "фальсификатор (г): UTF-8-гейта нет, длина была единственной проверкой"
    );

    // (7)…(8) Битая СТРОКА версии: то же поле-контракт, другое имя отказа и другой момент.
    let honest = response(o, "гранит", b"abcdef".to_vec());
    let hb = honest.body_bytes();
    let honest_frame = signed_by(&honest, &owner);
    assert_eq!(honest_frame.len(), 8 + hb.len() + 1 + 64, "фикстура (7): раскладка кадра не сходится");
    assert_eq!(honest_frame[8 + 32 + 2], 0xD0, "фикстура (7): первый байт «г» не 0xD0");
    let broken_str = with_byte(&honest_frame, 8 + 32 + 2, 0xFF);
    assert_eq!(broken_str.len(), honest_frame.len(), "фикстура (7): мутация не in-place");
    for (label, expected_owner, want) in [
        (
            "фальсификатор (д)/(е): битая строка версии названа не Malformed",
            o,
            session::TextError::Malformed,
        ),
        (
            "фальсификатор (ж): битая строка дошла до сверки владельца",
            e,
            session::TextError::Malformed,
        ),
    ] {
        assert_eq!(session::verify_response(&broken_str, &expected_owner), Err(want), "{label}");
    }

    // (9) Подписывающий конец не может выдать битый UTF-8: типы делают канон по построению.
    let signed_out = session::sign_response(&owner, "гранит — тире, ё", 7, "текст: 100 % юникод ✓")
        .expect("порог (9): sign_response отверг валидную строку");
    let back = session::verify_response(&signed_out, &o)
        .expect("фальсификатор (и): собственный ответ не прошёл собственную проверку");
    assert_eq!(
        (back.model_version.as_str(), back.preprocessing_version, back.text.as_str()),
        ("гранит — тире, ё", 7, "текст: 100 % юникод ✓"),
        "фальсификатор (и): раунд-трип подписи/проверки не побайтовый"
    );

    eprintln!(
        "## пороги (0)…(9): UTF-8 — последний гейт цепочки §12.4 (битый текст при чужой \
         подписи = BadSignature, при чужом ожидаемом = WrongOwner, при чужом виде = WrongKind, \
         без подписи = Unsigned); граница 1000 Б включительна (Ok с раунд-трипом), 999 Б с \
         обрезом = NotUtf8 (гейт не про длину); битая строка model_version того же кадра = \
         Malformed при любом ожидаемом (декодер строки, разбор раньше владельца) — два поля, \
         два имени, два момента; sign_response→verify_response = побайтовый раунд-трип ##"
    );
}
