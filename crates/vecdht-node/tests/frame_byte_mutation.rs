//! Оракул H-0061/E-0061: байтовая неканоничность кадра приёмки и непокрытые ветки
//! `AcceptError::WrongKind`/`Malformed` в `Spend::consume` (§5.1, §5.2, §12.3).
//!
//! Грех предшественников: grep по `crates/` даёт ноль упоминаний `AcceptError::WrongKind`
//! и ноль `AcceptError::Malformed` — две первые ветки `consume` (разбор кадра и сверка
//! `kind`) не измерялись никогда, тогда как `AlreadySpent` (15), `Expired` (8),
//! `WrongTarget` (3), `TtlOutOfPolicy` (2), `Unsigned` (1), `BadSignature` (1) мерились
//! (`E-0047`/`E-0058`/`E-0059`/`E-0060`).
//!
//! Спека обещает ровно следующее: §5.1 — «`[u8 sig_len][sig]` только Ed25519: sig_len
//! обязан быть 64, другие значения — ошибка декода» и «биты 1..15 зарезервированы, MUST
//! быть 0»; §5.2 — «подпись всегда по canonical-байтам, а не по пришедшим». С H-0162/m1
//! `decode_frame` отвергает любой байт после тела или подписи (`TrailingBytes`): у кадра
//! одно каноническое представление, и кадр с хвостом — отказ декода, а не второй способ
//! передать то же тело. `Spend` собирает ключ из тела, поэтому отказ обязан случиться до
//! записи в spent. До правки хвост молча принимался, и это закрепляли пороги (2)/(3).
//!
//! Пороги (живой приём A бакета 0, ttl=300, `now = 5` — часы НЕ двигаются, урок `E-0060`:
//! движение часов внутри прогона вычищает spent-таблицу `prune`-ом и делает поздне
//! проверки памяти ложными):
//! (0) раскладка: тело 76 Б (32+32+2+4+4+2), кадр 8+76+1+64 = 149 Б, байт длины подписи
//!     = 64, flags = 0x01, последний байт тела = 0x01 (старший байт ttl=300 little-endian);
//! (1) consume f0@5 → Ok, spent==1, grant = (seeker=A, shard, slot, issued_bucket=0);
//! (2) f0 + 8 байт хвоста → `TrailingBytes` с offset = длина кадра; `RendezvousAccept::decode`
//!     и `Spend::consume` → Malformed; spent остаётся 1;
//! (3) на чистой цели padded → Malformed и spent==0, затем чистый f0 → Ok, spent==1,
//!     а grant побайтово равен grant из (1);
//! (4) байт подписи инвертирован → BadSignature;
//! (5) байт ТЕЛА (первый байт `target`) инвертирован → BadSignature, НЕ WrongTarget;
//! (6) кадр усечён на 1 байт → Malformed;
//! (7) sig_len := 63 → Malformed (§5.1: обязан быть 64);
//! (8) sig_len := 65 → Malformed;
//! (9) flags := 0x03 (зарезервированный бит) → Malformed, хотя flags входят в `sig_input`;
//! (10) version := 7 → Malformed;
//! (11) kind := 0xFE (нет в таблице §5.3) → Malformed, а НЕ WrongKind;
//! (12) kind := Publish при честной подписи и честном теле → WrongKind; тот же kind без
//!      подписи → WrongKind (заголовок kind ДО проверки подписи);
//! (13) body_len занижен на 1 → Malformed (декодер читает длину подписи из последнего
//!      байта тела = 0x01);
//! (14) spent == 1 после всех веток: ни один отказ не оставил записи в памяти расхода.
//!
//! Фальсификаторы: (а) (2) хвост разобран, принят `RendezvousAccept` или потратил приём —
//! строгий декод не работает; (б) (3) отказ по хвосту потратил приём, канонический кадр
//! после него не прошёл или grant расходится с (1); (в) любой отказ (4)…(13) изменил spent;
//! (г) (4)/(5) вернули Ok — подпись не покрывает байты; (д) (5) дал WrongTarget — адресат
//! проверён до подписи (порядок §12.3 нарушен); (е) (7)/(8) дали Ok или BadSignature — гейт
//! длины подписи отсутствует; (ё) (9)/(10) дали BadSignature — заголовочные гейты идут
//! после криптографии; (ж) (11) дал WrongKind или (12) дал Malformed — судьбы «kind вне
//! таблицы» и «не тот kind» перепутаны; (з) (0) не сошлось — вся арифметика порогов
//! держится на неверной раскладке; (и) grant (1)/(3) не связан с A; (к) spent>1 в (14).

use std::path::PathBuf;
use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode, Spend};
use vecdht_wire::codec::DecodeError;
use vecdht_wire::frame::{decode_frame, encode_frame, Kind, FLAG_SIGNED};
use vecdht_wire::messages::{Codec, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER_SEEDS: [u8; 3] = [77, 78, 79];
/// Живой бакет внутри окна `0..=buckets(300)=19`: часы в прогоне не двигаются.
const LIVE_NOW: u32 = 5;
const HEAD: usize = 8;
const OFF_KIND: usize = 0;
const OFF_VERSION: usize = 1;
const OFF_FLAGS: usize = 2;
const OFF_BODY_LEN: usize = 4;
const BODY_LEN: usize = 76;
const SIG_LEN_BYTE: usize = HEAD + BODY_LEN;
const SIG: usize = SIG_LEN_BYTE + 1;
const FRAME_LEN: usize = SIG + 64;

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

fn publish_frame(agent_seed: u8, vec_seed: u8) -> Vec<u8> {
    let agent = testing::identity(agent_seed);
    testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(vec_seed),
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch: 1,
        published_bucket: 0,
        ttl_buckets: 225,
        bits: POW,
    }
    .frame()
}

fn accepts(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("accept")))
        .collect()
}

fn find(n: &mut ShardNode, a: &Identity, bucket: u32, qid: u64) -> Vec<vecdht_node::Envelope> {
    n.on_frame(
        a.pubkey(),
        &testing::find_frame(a, &testing::vector(1), &[CLUSTER], 8, qid),
        testing::clock(bucket),
    )
    .expect("find")
}

/// Кадр с заменённым байтом.
fn with_byte(frame: &[u8], at: usize, b: u8) -> Vec<u8> {
    let mut v = frame.to_vec();
    v[at] = b;
    v
}

/// Тот же кадр плюс `n` мусорных байт после подписи.
fn pad(frame: &[u8], n: usize) -> Vec<u8> {
    let mut v = frame.to_vec();
    v.resize(v.len() + n, 0xAA);
    v
}

#[test]
fn noncanonical_accept_bytes_do_not_create_a_second_spend() {
    let (mut n, d) = primary_on("frame-byte-mutation");
    for (i, s) in OWNER_SEEDS.iter().enumerate() {
        n.on_frame(
            testing::identity(*s).pubkey(),
            &publish_frame(*s, 1 + i as u8),
            testing::clock(0),
        )
        .expect("publish");
    }
    let a = testing::identity(88);
    let got = accepts(&find(&mut n, &a, 0, 801));
    assert_eq!(got.len(), 3, "харнес: живой приём не выдан");
    let (f0, a0) = got[0].clone();
    let iss = n.me();
    let tgt = a0.target;
    assert!(
        OWNER_SEEDS.iter().any(|s| testing::identity(*s).pubkey() == tgt),
        "харнес: адресат карты — не владелец записи"
    );

    // Порог (0): раскладка кадра — на ней держится арифметика всех мутаций.
    let fr = decode_frame(&f0).expect("порог (0): живой кадр не разбирается");
    assert_eq!(fr.header.body_len as usize, BODY_LEN, "фальсификатор (з): тело accept'а не 76 Б");
    assert_eq!(f0.len(), FRAME_LEN, "фальсификатор (з): кадр не 8+76+1+64 = 149 Б");
    assert_eq!(f0[SIG_LEN_BYTE], 64, "фальсификатор (з): байт длины подписи не 64");
    assert_eq!(fr.header.flags, FLAG_SIGNED, "фальсификатор (з): flags живого кадра не 0x0001");
    assert!(fr.header.signed(), "фальсификатор (з): живой кадр не помечен подписанным");
    assert_eq!(f0[HEAD + BODY_LEN - 1], 0x01, "харнес: последний байт тела — старший байт ttl=300");

    // Порог (1): базовый расход живого кадра.
    let mut spend = Spend::new(300);
    let g1 = spend
        .consume(&f0, &iss, &tgt, LIVE_NOW)
        .expect("порог (1): чистый кадр не принят");
    assert_eq!(
        (g1.seeker, g1.shard, g1.slot, g1.issued_bucket),
        (a.pubkey(), SHARD, a0.slot, 0),
        "фальсификатор (и): grant базового расхода не связан с A"
    );
    assert_eq!(spend.spent(), 1, "порог (1): spent != 1 после первого приёма");

    // Порог (2): хвост после подписи — неканонические байты, отказ декода.
    let padded = pad(&f0, 8);
    match decode_frame(&padded) {
        Err(DecodeError::TrailingBytes { offset }) => {
            assert_eq!(offset, FRAME_LEN, "фальсификатор (а): offset хвоста не равен длине кадра")
        }
        other => panic!("фальсификатор (а): кадр с хвостом не отвергнут: {other:?}"),
    }
    assert!(
        RendezvousAccept::decode(&padded).is_err(),
        "фальсификатор (а): сообщение разобрало кадр с хвостом"
    );
    assert_eq!(
        spend.consume(&padded, &iss, &tgt, LIVE_NOW),
        Err(rendezvous::AcceptError::Malformed),
        "фальсификатор (а): кадр с хвостом дошёл до проверки подписи"
    );
    assert_eq!(spend.spent(), 1, "фальсификатор (а): отказ по хвосту добавил запись в spent");

    // Порог (3): на чистой цели padded отвергнут и не тратит приём; канонический кадр после
    // него проходит, и grant совпадает с (1).
    let mut spend2 = Spend::new(300);
    assert_eq!(
        spend2.consume(&padded, &iss, &tgt, LIVE_NOW),
        Err(rendezvous::AcceptError::Malformed),
        "фальсификатор (б): кадр с хвостом прошёл как приём"
    );
    assert_eq!(spend2.spent(), 0, "фальсификатор (б): отказ по хвосту потратил приём");
    let g3 = spend2
        .consume(&f0, &iss, &tgt, LIVE_NOW)
        .expect("фальсификатор (б): канонический кадр после padded не принят");
    assert_eq!(g3, g1, "фальсификатор (б): grant после padded отличается от канонического");
    assert_eq!(spend2.spent(), 1, "порог (3): spent после канонического кадра не 1");

    // Пороги (4)…(13): неканонические кадры — отказ, и отказ разный по природе дефекта.
    let body = &f0[HEAD..SIG_LEN_BYTE];
    let sig = &f0[SIG..][..64];
    let refusals: [(&str, Vec<u8>, rendezvous::AcceptError); 11] = [
        (
            "фальсификатор (г): инверсия байта подписи прошла как приём",
            with_byte(&f0, SIG + 63, f0[SIG + 63] ^ 0xFF),
            rendezvous::AcceptError::BadSignature,
        ),
        (
            "фальсификатор (г)/(д): инверсия байта тела прошла; WrongTarget вместо BadSignature = адресат до подписи",
            with_byte(&f0, HEAD + 32, f0[HEAD + 32] ^ 0xFF),
            rendezvous::AcceptError::BadSignature,
        ),
        (
            "фальсификатор (в): усечение кадра на 1 байт не дало Malformed",
            f0[..FRAME_LEN - 1].to_vec(),
            rendezvous::AcceptError::Malformed,
        ),
        (
            "фальсификатор (е): sig_len=63 принят (§5.1 обязан быть 64)",
            with_byte(&f0, SIG_LEN_BYTE, 63),
            rendezvous::AcceptError::Malformed,
        ),
        (
            "фальсификатор (е): sig_len=65 принят (§5.1 обязан быть 64)",
            with_byte(&f0, SIG_LEN_BYTE, 65),
            rendezvous::AcceptError::Malformed,
        ),
        (
            "фальсификатор (ё): зарезервированный бит flags дошёл до подписи",
            with_byte(&f0, OFF_FLAGS, 0x03),
            rendezvous::AcceptError::Malformed,
        ),
        (
            "фальсификатор (ё): version=7 дошёл до подписи",
            with_byte(&f0, OFF_VERSION, 7),
            rendezvous::AcceptError::Malformed,
        ),
        (
            "фальсификатор (ж): kind вне таблицы §5.3 дал WrongKind вместо Malformed",
            with_byte(&f0, OFF_KIND, 0xFE),
            rendezvous::AcceptError::Malformed,
        ),
        (
            "фальсификатор (ж): чужой честный kind дал Malformed вместо WrongKind",
            encode_frame(Kind::Publish, body, Some(sig)),
            rendezvous::AcceptError::WrongKind,
        ),
        (
            "фальсификатор (ж): kind проверяется после подписи",
            encode_frame(Kind::Publish, body, None),
            rendezvous::AcceptError::WrongKind,
        ),
        (
            "фальсификатор (в): заниженный body_len принят",
            with_byte(&f0, OFF_BODY_LEN, (BODY_LEN - 1) as u8),
            rendezvous::AcceptError::Malformed,
        ),
    ];
    for (label, bad, want) in refusals {
        assert_eq!(spend.consume(&bad, &iss, &tgt, LIVE_NOW), Err(want), "{label}");
        assert_eq!(spend.spent(), 1, "{label}: фальсификатор (в) — отказ оставил след в spent");
    }

    // Порог (14): память расхода за всё время — ровно один живой приём.
    assert_eq!(spend.spent(), 1, "фальсификатор (к): spent разросся за прогон");
    assert_eq!(spend2.spent(), 1, "фальсификатор (к): spent2 разросся за прогон");

    eprintln!(
        "## пороги (0)…(14): кадр приёмки = 8+76+1+64 = 149 Б; хвост после подписи — отказ \
         декода (TrailingBytes, offset = 149) и Malformed у Spend, spent не растёт; \
         канонический кадр после отказа проходит, grant совпадает; мутация подписи и тела → \
         BadSignature (не WrongTarget); усечение, sig_len 63/65, зарезервированный флаг, \
         version 7, kind вне таблицы, заниженный body_len → Malformed; чужой табличный kind \
         (подписанный и без подписи) → WrongKind; spent == 1 во всех ветках ##"
    );
    remove(&d);
}
