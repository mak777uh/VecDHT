//! Оракул H-0062/E-0062: порядок проверок `session::verify_response` (§12.4) и немедленные
//! отказы `session::serve_request` (§12.3); непокрытые ветки `TextError::WrongKind`/`Malformed`.
//!
//! Спека §12.4: «Ответ принимается только после проверки вида кадра, наличия подписи,
//! `owner_ed25519 == ожидаемого владельца`, подписи по ключу владельца и UTF-8; лимит 1000
//! байт проверяется и при подписании, и при разборе». Порядок назван ЯВНО и в коде
//! (`session.rs:163`): «вид кадра → наличие подписи → разбор тела → ожидаемый владелец →
//! подпись → UTF-8. Владелец сверяется до криптографии намеренно: подпись чужого ключа не
//! должна даже считаться».
//!
//! Грех предшественников: grep по `crates/*/tests/` даёт НОЛЬ `TextError::WrongKind` и НОЛЬ
//! `TextError::Malformed` — две первые ветки пути ответа не измерялись; `Unsigned`,
//! `BadSignature`, `WrongOwner`, `NotUtf8`, `TextTooLong` (на подписании) покрыты юнит-тестами
//! `session.rs` и `adversarial.rs`, но НЕ как порядок. Лимит в 1000 байт на декоде покрыт
//! юнит-тестом кодека (`intent_text_over_limit_rejected` → `DecodeError::FieldTooLong`), а то,
//! КАК он именуется на выходе `verify_response`, не мерилось: по коду это `Malformed`, а
//! собственная ветка `TextTooLong` в `verify_response` (`session.rs:189`) — недостижимый
//! симметричный повтор.
//!
//! Пороги (O — издатель ответа, E — чужой ключ, F — третий ключ; ttl живого приёма 300):
//! (0) честный кадр: разберётся, `verify_response(_, &O)` → `Ok` с полями (O, «гранит», 7,
//!     «abcdef»); длина кадра = 8 + тело + 1 + 64, байт `sig_len` = 64, `flags` = 0x0001;
//! (1) вид кадра := `IntentTextRequest` при честном теле и честной подписи → `WrongKind`;
//!     тот же чужой вид БЕЗ подписи → `WrongKind` (вид раньше наличия подписи);
//! (2) вид кадра := 0xFE (нет в таблице §5.3) → `Malformed`, а не `WrongKind`;
//! (3) кадр усечён на 1 байт → `Malformed`;
//! (4) байт `sig_len` := 63 → `Malformed`, а не `Unsigned`;
//! (5) `encode_unsigned` → `Unsigned`; ложный `owner_ed25519` + отсутствие подписи → `Unsigned`
//!     (наличие подписи раньше владельца);
//! (6) честный кадр O при ожидаемом E → `WrongOwner{expected: E, found: O}`; ТОТ ЖЕ кадр с
//!     инвертированным байтом текста при ожидаемом E → `WrongOwner`, а не `BadSignature`
//!     («подпись чужого ключа не должна даже считаться»);
//! (7) честное тело O, подпись ключом F, ожидаемый O → `BadSignature`;
//! (8) текст 1001 байт с ЧЕСТНОЙ подписью O, ожидаемый O → `Malformed`, а НЕ `TextTooLong`;
//! (9) те же 1001 байт при ожидаемом E → `Malformed` (разбор тела раньше владельца);
//! (10) `sign_response` с 1001 байтом → `TextTooLong(1001)` — лимит «и при подписании»: то же
//!      число, два разных имени на двух концах;
//! (11) запрос с пустым `present`, адресованный НЕ этой цели → `WrongTarget`, а не `NoAccept`
//!      (разбор и адресат раньше требования предъявления);
//! (12) `present` = 8 нулей (не кадр) → `Spend(Malformed)`, а не `NotSignedByShardHolder`
//!      (немедленный отказ, перебор держателей не запускается);
//! (13) `present` = тот же живой кадр с байтом вида := `Publish` (табличный чужой вид,
//!      длина в пределах лимита 512 Б) → `Spend(WrongKind)`, тоже без маскировки;
//! (14) пустой `present` при верном адресате → `NoAccept` (база порядка для (11));
//! (15) живой приём предъявлен → `Ok` (харнес жив), spent == 1, повтор → `Spend(AlreadySpent)`;
//!     во всех (11)…(14) `spent == 0` — немедленные отказы не трогают память расхода.
//!
//! Фальсификаторы: (а) (1) дал `Unsigned`/`BadSignature` — вид кадра проверяется после
//! подписи, порядок §12.4 нарушен; (б) (2)/(3)/(4) дали не `Malformed` — заголовочные гейты
//! пропущены; (в) (5) с ложным владельцем дал `WrongOwner` — владелец раньше наличия подписи;
//! (г) (6) с испорченным текстом дал `BadSignature` — подпись чужого ключа всё-таки считается;
//! (д) (8) вернул `Ok` или `TextTooLong` — лимит на разборе отсутствует либо именуется не так;
//! (е) (9) дал `WrongOwner` — владелец проверяется до разбора тела;
//! (ж) (12)/(13) дали `NotSignedByShardHolder` — немедленный отказ замаскирован перебором;
//! (з) (11) дал `NoAccept` — требование предъявления раньше адресата;
//! (и) (0)/(15) grant или `IntentText` не связаны с полями честного кадра;
//! (й) `spent > 0` после (11)…(14) — отказ с побочным эффектом.

use std::path::PathBuf;
use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, session, testing, ShardNode, Spend};
use vecdht_wire::frame::{decode_frame, encode_frame, Kind, FLAG_SIGNED};
use vecdht_wire::messages::{domain, Codec, IntentTextResponse, MatchResult, MAX_INTENT_TEXT_BYTES};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER: u8 = 90;
const SEEKER: u8 = 91;

fn primary_on(dir_name: &str) -> (ShardNode, PathBuf) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = testing::node(&d, SHARD, seed, testing::params(POW), &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "приёмы выпускает primary эпизода");
    (n, d)
}

fn publish_frame(agent_seed: u8) -> Vec<u8> {
    let agent = testing::identity(agent_seed);
    testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(1),
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch: 1,
        published_bucket: 0,
        ttl_buckets: 225,
        bits: POW,
    }
    .frame()
}

fn with_byte(frame: &[u8], at: usize, b: u8) -> Vec<u8> {
    let mut v = frame.to_vec();
    v[at] = b;
    v
}

fn response(owner_key: [u8; 32], text: Vec<u8>) -> IntentTextResponse {
    IntentTextResponse {
        owner_ed25519: owner_key,
        model_version: "гранит".to_string(),
        preprocessing_version: 7,
        text,
    }
}

#[test]
fn response_checks_follow_the_named_sequence_and_refusals_stay_unmasked() {
    let owner = testing::identity(60);
    let other = testing::identity(61);
    let foreign = testing::identity(62);
    let o = owner.pubkey();
    let e = other.pubkey();

    let resp = response(o, b"abcdef".to_vec());
    let body = resp.body_bytes();
    let sig = owner.sign_body(domain::TEXT, Kind::IntentTextResponse, &body);
    let honest = resp.encode_signed(&sig);

    // Порог (0): честный кадр и его раскладка.
    let hf = decode_frame(&honest).expect("порог (0): честный ответ не разбирается");
    assert_eq!(hf.header.flags, FLAG_SIGNED, "фальсификатор (и): flags честного ответа не 0x0001");
    assert_eq!(honest.len(), 8 + body.len() + 1 + 64, "фальсификатор (и): длина кадра ответа не сходится");
    assert_eq!(honest[8 + body.len()], 64, "фальсификатор (и): байт длины подписи не 64");
    let text = session::verify_response(&honest, &o).expect("порог (0): честный ответ отвергнут");
    assert_eq!(
        (text.owner_ed25519.as_slice(), text.model_version.as_str(), text.preprocessing_version, text.text.as_str()),
        (o.as_slice(), "гранит", 7, "abcdef"),
        "фальсификатор (и): проверенный ответ не связан с полями честного кадра"
    );

    // Пороги (1)…(9): порядок названной последовательности на двойно-ложных кадрах.
    let fat = response(o, vec![b'a'; MAX_INTENT_TEXT_BYTES + 1]);
    let fat_body = fat.body_bytes();
    let fat_sig = owner.sign_body(domain::TEXT, Kind::IntentTextResponse, &fat_body);
    let fat_frame = fat.encode_signed(&fat_sig);
    let mut tampered = honest.clone();
    let last_text = tampered.len() - 1 - 64 - 1;
    tampered[last_text] ^= 1;
    let cases: [(&str, Vec<u8>, [u8; 32], session::TextError); 10] = [
        (
            "фальсификатор (а): чужой табличный вид дошёл до подписи",
            encode_frame(Kind::IntentTextRequest, &body, Some(&sig)),
            o,
            session::TextError::WrongKind,
        ),
        (
            "фальсификатор (а): чужой вид без подписи дал не WrongKind",
            encode_frame(Kind::IntentTextRequest, &body, None),
            o,
            session::TextError::WrongKind,
        ),
        (
            "фальсификатор (б): вид вне таблицы §5.3 дал не Malformed",
            with_byte(&honest, 0, 0xFE),
            o,
            session::TextError::Malformed,
        ),
        (
            "фальсификатор (б): усечение кадра ответа прошло",
            honest[..honest.len() - 1].to_vec(),
            o,
            session::TextError::Malformed,
        ),
        (
            "фальсификатор (б): sig_len=63 дал Unsigned вместо Malformed",
            with_byte(&honest, 8 + body.len(), 63),
            o,
            session::TextError::Malformed,
        ),
        (
            "фальсификатор (в): ложный владелец без подписи дал WrongOwner",
            response(e, b"abcdef".to_vec()).encode_unsigned(),
            o,
            session::TextError::Unsigned,
        ),
        (
            "фальсификатор (г): подпись чужого ключа всё-таки посчитана",
            tampered,
            e,
            session::TextError::WrongOwner { expected: e, found: o },
        ),
        (
            "фальсификатор (д): 1001 байт с честной подписью прошли или именуются TextTooLong",
            fat_frame.clone(),
            o,
            session::TextError::Malformed,
        ),
        (
            "фальсификатор (е): сверхлимитный текст дошёл до сверки владельца",
            fat_frame,
            e,
            session::TextError::Malformed,
        ),
        (
            "фальсификатор (г): честное тело O с подписью F дало не BadSignature",
            resigned_by_foreign(&resp, &body, &foreign),
            o,
            session::TextError::BadSignature,
        ),
    ];
    for (label, frame, expected_owner, want) in cases {
        assert_eq!(session::verify_response(&frame, &expected_owner), Err(want), "{label}");
    }

    // Порог (10): тот же лимит при подписании зовётся иначе.
    let long = "a".repeat(MAX_INTENT_TEXT_BYTES + 1);
    assert_eq!(
        session::sign_response(&owner, "гранит", 7, &long),
        Err(session::TextError::TextTooLong(MAX_INTENT_TEXT_BYTES + 1)),
        "порог (10): лимит не проверяется при подписании"
    );

    // Пороги (11)…(15): живой вход цели — немедленные отказы без маскировки.
    let (mut n, d) = primary_on("response-verification-order");
    let target = testing::identity(OWNER);
    let seeker = testing::identity(SEEKER);
    n.on_frame(target.pubkey(), &publish_frame(OWNER), testing::clock(0))
        .expect("publish");
    let replies = n
        .on_frame(seeker.pubkey(), &testing::find_frame(&seeker, &testing::vector(1), &[CLUSTER], 8, 7), testing::clock(0))
        .expect("find");
    let slot = replies
        .iter()
        .find(|en| decode_frame(&en.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|en| MatchResult::decode(&en.frame).ok())
        .map(|mr| mr.matches[0].slot)
        .expect("MatchResult");
    let f0: Vec<u8> = replies
        .iter()
        .find(|en| decode_frame(&en.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|en| en.frame.clone())
        .expect("приём выпущен");

    let issuers = [n.me()];
    let mut spend = Spend::new(300);
    let t = target.pubkey();

    // (11) чужой адресат + пустой present: адресат раньше требования предъявления.
    let bare_foreign = session::encode_request(7, seeker.pubkey(), slot);
    assert_eq!(
        session::serve_request(&bare_foreign, &t, &issuers, 0, &mut spend),
        Err(session::TextError::WrongTarget),
        "фальсификатор (з): чужому адресату отказали по отсутствию предъявления"
    );
    // (14) верный адресат + пустой present → NoAccept.
    let bare_mine = session::encode_request(7, t, slot);
    assert_eq!(
        session::serve_request(&bare_mine, &t, &issuers, 0, &mut spend),
        Err(session::TextError::NoAccept),
        "фальсификатор (з): пустое предъявление обслужено"
    );
    // (12) present вне кадра → немедленный Malformed, перебор держателей не запускается.
    let junk = session::encode_request_present(7, t, slot, &[0u8; 8]);
    assert_eq!(
        session::serve_request(&junk, &t, &issuers, 0, &mut spend),
        Err(session::TextError::Spend(rendezvous::AcceptError::Malformed)),
        "фальсификатор (ж): немедленный отказ замаскирован перебором"
    );
    // (13) present = табличный чужой вид (байт kind живого приёма := Publish, длина та же)
    // → WrongKind тоже без маскировки.
    let wrong_kind = session::encode_request_present(7, t, slot, &with_byte(&f0, 0, Kind::Publish as u8));
    assert_eq!(
        session::serve_request(&wrong_kind, &t, &issuers, 0, &mut spend),
        Err(session::TextError::Spend(rendezvous::AcceptError::WrongKind)),
        "фальсификатор (ж): WrongKind замаскирован NotSignedByShardHolder"
    );
    assert_eq!(spend.spent(), 0, "фальсификатор (й): немедленные отказы тронули память расхода");

    // (15) живой приём обслуживается и остаётся одноразовым.
    let live = session::encode_request_present(7, t, slot, &f0);
    let grant = session::serve_request(&live, &t, &issuers, 0, &mut spend)
        .expect("порог (15): живой приём не обслужен");
    assert_eq!(
        (grant.seeker, grant.shard, grant.slot, grant.issuer),
        (seeker.pubkey(), SHARD, slot, n.me()),
        "фальсификатор (и): grant живого предъявления не связан с кадром"
    );
    assert_eq!(spend.spent(), 1, "порог (15): spent != 1 после живого расхода");
    assert_eq!(
        session::serve_request(&live, &t, &issuers, 0, &mut spend),
        Err(session::TextError::Spend(rendezvous::AcceptError::AlreadySpent)),
        "фальсификатор (б): повтор живого предъявления обслужен"
    );

    eprintln!(
        "## пороги (0)…(15): порядок ответа = вид кадра (WrongKind раньше подписи) → разбор \
         заголовка (Malformed на 0xFE/усечении/sig_len 63) → наличие подписи (Unsigned раньше \
         владельца) → разбор тела (1001 байт = Malformed, ветка TextTooLong недостижима) → \
         ожидаемый владелец (WrongOwner даже при испорченном тексте) → подпись (BadSignature); \
         при подписании тот же лимит зовётся TextTooLong(1001); на входе цели: чужой адресат при \
         пустом present = WrongTarget (не NoAccept), present-мусор = Spend(Malformed), чужой вид \
         = Spend(WrongKind) — оба без маскировки и без следа в spent (spent 0 → 1 → AlreadySpent) ##"
    );
    remove(&d);
}

/// Честное тело ответа, пере-подписанное чужим ключом (ветка `BadSignature`).
fn resigned_by_foreign(resp: &IntentTextResponse, body: &[u8], foreign: &Identity) -> Vec<u8> {
    let sig = foreign.sign_body(domain::TEXT, Kind::IntentTextResponse, body);
    resp.encode_signed(&sig)
}
