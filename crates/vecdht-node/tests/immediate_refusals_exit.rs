//! Оракул H-0064/E-0064: немаскировка трёх оставшихся немедленных отказов на входе цели
//! (§12.3) — `Expired`, `WrongTarget`, `TtlOutOfPolicy` выходят из `serve_request` как
//! `TextError::Spend(...)`, а не как `NotSignedByShardHolder`.
//!
//! Спека §12.3: «`Spend::consume` по списку держателей шарда-кандидатов (перебор кандидатов
//! только по `BadSignature`; `AlreadySpent`/`Expired`/`WrongTarget`/`TtlOutOfPolicy`
//! отсекаются немедленно)». На входе цели измерялись `AlreadySpent` (`E-0051`, `E-0062`),
//! `Malformed`/`WrongKind` (`E-0062`) и маскировка `AlreadySpent` при неполном списке
//! (`E-0054`); `Expired`/`WrongTarget`/`TtlOutOfPolicy` мерились только на входе `consume`
//! (`E-0060`) и (`E-0047`: `accept_ttl_boundary.rs`), `WrongTarget` — `ttl_policy_order.rs`/
//! `adversarial.rs`; комбинаций `TextError::Spend(AcceptError::Expired | WrongTarget |
//! TtlOutOfPolicy)` на выходе `serve_request` в `crates/vecdht-node/tests/` — ноль (grep на
//! момент пре-регистрации): что немедленность этих отказов доживает до ВЫХОДА цели (не
//! превращается в `NotSignedByShardHolder` перебором) — не проверялось никогда.
//!
//! Технический ключ (урок `E-0060`: приёмку подписывает КЛЮЧ УЗЛА, `node.rs:1019`): в
//! харнесе seed узла известен, поэтому пере-подпись изменённого `RendezvousAccept` тем же
//! ключом даёт кадр, который проходит гейт подписи и падает ровно на проверяемом поле.
//! Порог (0) закрепляет это побайтовым равенством пере-выпущенного и живого кадра.
//!
//! Пороги (O — владелец записи/адресат цели, N — ключ узла-primary, seed известен харнесу;
//! живой приём F0: issued_bucket=0, ttl_sec=300, buckets(300)=19):
//! (0) `RendezvousAccept::decode(F0)`: seeker=A, target=O, shard=7, issued_bucket=0,
//!     ttl_sec=300; пере-подпись UNCHANGED тела ключом N побайтово равна F0 (ключ верный —
//!     иначе (2)…(6) теряют смысл);
//! (1) честное предъявление при now=0 → `Ok` (харнес жив; база для (8));
//! (2) тот же F0 при now=20 (= issued + buckets(300) + 1 — грань исчезновения из `E-0060`)
//!     → `Spend(Expired)`, а не `NotSignedByShardHolder` и не `Ok`;
//! (3) приём с `target` := чужой ключ, пере-подписанный N, при now=0 → `Spend(WrongTarget)`,
//!     а не `Ok` и не `NotSignedByShardHolder` (гейт адресата живой, перебор не запускается);
//! (4) приём с `ttl_sec` := 0, пере-подписанный N, при now=0 → `Spend(TtlOutOfPolicy(0))`;
//! (5) приём с `ttl_sec` := 301 при `Spend::new(300)`, пере-подписанный N → 
//!     `Spend(TtlOutOfPolicy(301))` — верхняя граница политики называет фактическое число;
//! (6) приём с `ttl_sec` := 0 при now=20 (политика И истечение одновременно) →
//!     `Spend(TtlOutOfPolicy(0))` — порядок «политика раньше истечения» доживает до выхода
//!     цели (зеркало `E-0060` на входе `consume`, сильная форма);
//! (7) кадр (4), подписанный ЧУЖИМ ключом → `NotSignedByShardHolder` — единственная ветка
//!     перебора остаётся единственной: BadSignature маскирует, немедленные — нет;
//! (8) `spent == 0` во всём spend2 после (2)…(7); повтор честного (1) → `Spend(AlreadySpent)`
//!     при spent==1 (одноразовость базы не сломана соседними отказами).
//!
//! Фальсификаторы: (а) (2)/(3)/(4)/(5)/(6) дали `NotSignedByShardHolder` — немедленный отказ
//! замаскирован перебором, §12.3 нарушен; (б) `spent > 0` в spend2 после отказов — отказ с
//! побочным эффектом; (в) (2) или (3) дали `Ok` — гейт истечения/адресата пропущен;
//! (г) (4)/(5) дали `Ok` — политики ttl на входе нет; (д) (6) дал `Spend(Expired)` —
//! порядок «политика → истечение» перевёрнут на выходе цели; (е) (7) дал `Spend(Ttl...)` —
//! чужая подпись прошла, харнес подписывает не тем ключом; (ж) (0) пере-подпись не равна F0
//! — база различения не стоит; (з) (8) повтор честного дан `Ok`.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, session, testing, ShardNode, Spend};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{domain, Codec, MatchResult, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER: u8 = 90;
const SEEKER: u8 = 91;

fn primary_on(dir_name: &str) -> (ShardNode, std::path::PathBuf, u8) {
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
    (n, d, seed)
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

/// Выпустить кадр приёма из тела пере-подписью ключом узла (seed из харнеса).
fn reissue(acc: &RendezvousAccept, node_seed: u8) -> Vec<u8> {
    let sig = testing::identity(node_seed).sign_body(domain::RENDEZVOUS, Kind::RendezvousAccept, &acc.body_bytes());
    acc.encode_signed(&sig)
}

#[test]
fn immediate_refusals_leave_serve_request_unmasked() {
    let (n, d, seed) = primary_on("immediate-refusals-exit");
    let owner = testing::identity(OWNER);
    let seeker = testing::identity(SEEKER);
    let mut n = n;

    n.on_frame(owner.pubkey(), &publish_frame(OWNER), testing::clock(0)).expect("publish");
    let replies = n
        .on_frame(seeker.pubkey(), &testing::find_frame(&seeker, &testing::vector(1), &[CLUSTER], 8, 7), testing::clock(0))
        .expect("find");
    let slot = replies
        .iter()
        .find(|en| decode_frame(&en.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|en| MatchResult::decode(&en.frame).ok())
        .map(|en| en.matches[0].slot)
        .expect("MatchResult");
    let f0: Vec<u8> = replies
        .iter()
        .find(|en| decode_frame(&en.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|en| en.frame.clone())
        .expect("приём выпущен");

    // (0) база различения: тело живого приёма и побайтовая эквивалентность пере-подписи.
    let a0 = RendezvousAccept::decode(&f0).expect("порог (0): живой приём не декодируется");
    assert_eq!(
        (a0.seeker, a0.target, a0.shard, a0.issued_bucket, a0.ttl_sec),
        (seeker.pubkey(), owner.pubkey(), SHARD, 0, 300),
        "порог (0): поля живого приёма не совпали"
    );
    assert_eq!(reissue(&a0, seed), f0, "фальсификатор (ж): пере-подпись unchanged не равна F0 — ключ не тот");

    let issuers = [n.me()];
    let t = owner.pubkey();
    let present = |acc: &RendezvousAccept, node_seed: u8| session::encode_request_present(7, t, slot, &reissue(acc, node_seed));

    // (1) база: честное предъявление обслуживается.
    let mut spend1 = Spend::new(300);
    let live = session::encode_request_present(7, t, slot, &f0);
    assert!(session::serve_request(&live, &t, &issuers, 0, &mut spend1).is_ok(), "порог (1): честный приём не обслужен");

    // (2)…(6) немедленные отказы выходят наружу без маскировки.
    let mut spend2 = Spend::new(300);
    let foreign = testing::identity(77);
    let expired = present(&a0, seed);
    let mut wrong_target = a0;
    wrong_target.target = foreign.pubkey();
    let mut ttl_zero = a0;
    ttl_zero.ttl_sec = 0;
    let mut ttl_301 = a0;
    ttl_301.ttl_sec = 301;

    let cases: [(&str, Vec<u8>, u32, session::TextError); 5] = [
        (
            "фальсификатор (а)/(в): Expired замаскирован или обслужен",
            expired.clone(),
            20,
            session::TextError::Spend(rendezvous::AcceptError::Expired),
        ),
        (
            "фальсификатор (а)/(в): WrongTarget замаскирован или обслужен",
            present(&wrong_target, seed),
            0,
            session::TextError::Spend(rendezvous::AcceptError::WrongTarget),
        ),
        (
            "фальсификатор (а)/(г): TtlOutOfPolicy(0) замаскирован или обслужен",
            present(&ttl_zero, seed),
            0,
            session::TextError::Spend(rendezvous::AcceptError::TtlOutOfPolicy(0)),
        ),
        (
            "фальсификатор (а)/(г): TtlOutOfPolicy(301) назван иначе",
            present(&ttl_301, seed),
            0,
            session::TextError::Spend(rendezvous::AcceptError::TtlOutOfPolicy(301)),
        ),
        (
            "фальсификатор (д): на выходе цели истечение опережает политику",
            present(&ttl_zero, seed),
            20,
            session::TextError::Spend(rendezvous::AcceptError::TtlOutOfPolicy(0)),
        ),
    ];
    for (label, req, now, want) in cases {
        assert_eq!(session::serve_request(&req, &t, &issuers, now, &mut spend2), Err(want), "{label}");
    }

    // (7) чужой подписант — единственная маскированная ветка: перебор гасит в NotSigned…
    let masquerade = session::encode_request_present(7, t, slot, &ttl_zero.encode_signed(&foreign.sign_body(domain::RENDEZVOUS, Kind::RendezvousAccept, &ttl_zero.body_bytes())));
    assert_eq!(
        session::serve_request(&masquerade, &t, &issuers, 0, &mut spend2),
        Err(session::TextError::NotSignedByShardHolder),
        "фальсификатор (е): чужая подпись прошла — перебор не отличим от немедленных отказов"
    );

    // (8) ни одного побочного следа в памяти расхода и одноразовость базы цела.
    assert_eq!(spend2.spent(), 0, "фальсификатор (б): немедленный отказ тронул spent");
    assert_eq!(spend1.spent(), 1, "порог (8): spent базы != 1");
    assert_eq!(
        session::serve_request(&live, &t, &issuers, 0, &mut spend1),
        Err(session::TextError::Spend(rendezvous::AcceptError::AlreadySpent)),
        "фальсификатор (з): повтор честного предъявления обслужен"
    );

    eprintln!(
        "## пороги (0)…(8): Expired (now=20 = грань исчезновения из E-0060), WrongTarget и \
         TtlOutOfPolicy(0)/(301) выходят из serve_request как Spend(...) без маскировки \
         перебором; политика раньше истечения и на выходе цели (ttl=0 при now=20 → \
         TtlOutOfPolicy(0)); чужой подписант — единственная ветка, гасящаяся в \
         NotSignedByShardHolder; spent чист (0) после всех отказов, база: Ok → spent 1 → \
         AlreadySpent ##"
    );
    remove(&d);
}
