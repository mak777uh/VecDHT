//! Оракул H-0065/E-0065: привязка `slot` запроса к `Grant` — обещание §12.4
//! «старый слот после смены эпохи просто даёт `Error{code:"NO_SUCH_SLOT"}`, а не чужой
//! текст» против кода, где константа `err_code::NO_SUCH_SLOT` объявлена (`messages.rs:41`)
//! и не конструируется НИГДЕ (grep `err_code::NO_SUCH_SLOT` по `crates/` — пуст на момент
//! пре-регистрации), а `slot` запроса (`IntentTextRequest.slot`, `messages.rs:473`) не
//! читается ни в `serve_request`, ни в `consume`: единственная подписанная привязка —
//! `slot` ВНУТРИ приёма, и `Grant` возвращает именно его.
//!
//! Отличия от покрытого: `E-0054`/`E-0064` мерили ОТКАЗЫ consume (чужие подписи, истечение,
//! адресат, политика) на входе цели; предъявление СВОЕГО валидного приёма под расходящимся
//! `req.slot` не мерилось никогда. `present_serving_gate.rs` (`ADR-0013`) мерил пустой
//! `present` и перебор держателей. Здесь — ровно то, на что ссылается §12.4: расход
//! проходит, а расхождение `req.slot` против `grant.slot` остаётся на усмотрение
//! приложения цели, и `NO_SUCH_SLOT` на этом пути не порождается.
//!
//! Пороги (после двух поправок заморозки; S0/S1 — слоты двух живых записей ДВУХ владельцев
//! из `MatchResult` по порядку списка; F0 — живой приём бакета 0 на S0; N — ключ
//! узла-primary, seed известен харнесу — метод пере-подписи `E-0064`; каждый порог Ok
//! используется на ЧИСТОМ инстансе `Spend`, чтобы double-spend не сливаться с отказом):
//! (0) decode(F0) = (seeker A, O, 7, issued_bucket 0, ttl 300, slot S0); пере-подпись
//!     unchanged тела ключом N побайтово равна F0; MatchResult: 2 находки, владельцы различны;
//! (1) честный `req.slot = S0` на spend1 → `Ok`, `grant.slot == S0`, spent == 1;
//! (2) `req.slot = S1` (чужая запись) с тем же приёмом на spend2 → `Ok`, `grant.slot == S0`;
//! (3) `req.slot = 0xFFFF_FFFF` (заранее мёртвый) на spend3 → `Ok`, `grant.slot == S0`;
//! (4a) повтор честного на spent1 → `Spend(AlreadySpent)`;
//! (4b) сильная форма: повтор с ЧУЖИМ (`S1`) и с мёртвым (`0xFFFF_FFFF`) `req.slot` на spent1
//!     даёт РОВНО ТОТ ЖЕ `AlreadySpent` — имя отказа не различает слот запроса вовсе;
//! (5) spent1 == 1 после отказных повторов — отказа нет без побочного эффекта;
//! (6) сильная форма первой поправки: тот же приём (target = O) на входе ВТОРОГО владельца
//!     (seed 92) → `Spend(WrongTarget)`, spent на инстансе B == 0 — адресат привязан
//!     подписанным телом приёма, фикция ровно в `slot`, не в мишени.
//!
//! Фальсификаторы: (а) (2)/(3) дали `Err` — механизм привязки в коде есть, фикции нет;
//! (б) `grant.slot == req.slot` в (2)/(3) — привязка всё же происходит из `req`;
//! (в) spent1 != 1 в (5) — отказный повтор тронул память расхода; (г) (4a) дал `Ok` —
//!     одноразовость базы сломана; (д) (0) пере-подпись unchanged != F0 — не тот ключ;
//! (е) фикстура некорректна: находка < 2, владельцы находок одинаковы (индекс сливает
//!     `(owner, shard)` в один слот — `ivf.rs:313`, урок первого замера), `DEAD_SLOT` занят;
//! (ж) (6) дал `Ok` или иной отказ — привязки адресата нет вовсе, дыра шире заявленной;
//! (и) (4b) дал имя отказа, отличное от `AlreadySpent` — цель всё же сверяет `req.slot`
//!     (урок второго замера: на разделённом инстансе это неотличимо от double-spend'а).

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
const DEAD_SLOT: u32 = 0xFFFF_FFFF;

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

fn publish_frame(agent: &vecdht_crypto::Identity, vec_seed: u8) -> Vec<u8> {
    testing::PublishSpec {
        agent,
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

/// Пере-выпустить приём телом кадра, подписав ключом узла (метод `E-0064`).
fn reissue(acc: &RendezvousAccept, node_seed: u8) -> Vec<u8> {
    let sig = testing::identity(node_seed)
        .sign_body(domain::RENDEZVOUS, Kind::RendezvousAccept, &acc.body_bytes());
    acc.encode_signed(&sig)
}

#[test]
fn request_slot_is_never_reconciled_with_the_spent_accept() {
    let (n0, d, seed) = primary_on("slot-request-accept-binding");
    let mut n = n0;
    let owner = testing::identity(OWNER);
    let seeker = testing::identity(SEEKER);
    let t = owner.pubkey();

    // Две живые записи ДВУХ владельцев — два разных слота в одном MatchResult (индекс
    // хранит одну запись на (owner, shard): перепубликация заменяет на месте, ivf.rs:313
    // — поправка заморозки после первого замера, где фикстура «2 записи одного владельца»
    // дала одну находку).
    let other = testing::identity(92);
    n.on_frame(owner.pubkey(), &publish_frame(&owner, 1), testing::clock(0))
        .expect("publish O");
    n.on_frame(other.pubkey(), &publish_frame(&other, 2), testing::clock(0))
        .expect("publish B");

    let replies = n
        .on_frame(
            seeker.pubkey(),
            &testing::find_frame(&seeker, &testing::vector(1), &[CLUSTER], 8, 7),
            testing::clock(0),
        )
        .expect("find");
    let mr = replies
        .iter()
        .find(|en| decode_frame(&en.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|en| MatchResult::decode(&en.frame).ok())
        .expect("фальсификатор (е): MatchResult отсутствует");
    assert_eq!(mr.matches.len(), 2, "фальсификатор (е): двух записей разных владельцев в находке не видно");
    let s0 = mr.matches[0].slot;
    let s1 = mr.matches[1].slot;
    assert_ne!(mr.matches[0].owner_ed25519, mr.matches[1].owner_ed25519, "фальсификатор (е): две записи одного владельца — индекс их бы слил");
    assert!(s0 != s1 && s0 != DEAD_SLOT && s1 != DEAD_SLOT, "фальсификатор (е): слоты неразличимы или задели мёртвый");

    let f0 = replies
        .iter()
        .find(|en| decode_frame(&en.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|en| en.frame.clone())
        .expect("порог (0): приём на первую находку не выпущен");

    // (0) база различения: живой приём привязан к S0; пере-подпись unchanged побайтово == F0.
    let a0 = RendezvousAccept::decode(&f0).expect("порог (0): живой приём не декодируется");
    assert_eq!(
        (a0.seeker, a0.target, a0.shard, a0.slot, a0.issued_bucket, a0.ttl_sec),
        (seeker.pubkey(), owner.pubkey(), SHARD, s0, 0, 300),
        "порог (0): поля живого приёма не совпали"
    );
    assert_eq!(reissue(&a0, seed), f0, "фальсификатор (д): пере-подпись unchanged != F0 — ключ не тот");

    let issuers = [n.me()];
    let req_at = |slot: u32, present: &[u8], target: [u8; 32]| session::encode_request_present(7, target, slot, present);
    let reissued = reissue(&a0, seed);

    // (1) честная привязка на spend1: Ok, grant.slot == S0, spent == 1.
    let mut spend1 = Spend::new(300);
    let g1 = session::serve_request(&req_at(s0, &f0, t), &t, &issuers, 0, &mut spend1)
        .expect("порог (1): честное предъявление не обслужено");
    assert_eq!(g1.slot, s0, "фальсификатор (б): grant(1).slot != S0");
    assert_eq!(spend1.spent(), 1, "порог (1): spent после честного != 1");

    // (2) чужой req.slot на ЧИСТОМ инстансе (spend2) — обслуживается, grant несёт слот приёма.
    let mut spend2 = Spend::new(300);
    let g2 = session::serve_request(&req_at(s1, &reissued, t), &t, &issuers, 0, &mut spend2)
        .unwrap_or_else(|e| panic!("фальсификатор (а): расходящийся req.slot S1 отклонён ({e:?}) — механизма фикции нет"));
    assert_eq!(g2.slot, s0, "фальсификатор (б): grant(2).slot ушёл за req.slot");
    assert_ne!(g2.slot, s1, "фальсификатор (б): grant(2) не различает запрос и приём");
    assert_eq!(spend2.spent(), 1, "порог (2): spent чистого инстанса после Ok != 1");

    // (3) мёртвый req.slot на ЧИСТОМ инстансе (spend3) — Ok; NO_SUCH_SLOT не порождается.
    let mut spend3 = Spend::new(300);
    let g3 = session::serve_request(&req_at(DEAD_SLOT, &reissued, t), &t, &issuers, 0, &mut spend3)
        .unwrap_or_else(|e| panic!("фальсификатор (а): мёртвый req.slot отклонён ({e:?})"));
    assert_eq!(g3.slot, s0, "фальсификатор (б): grant(3).slot != S0");
    assert_eq!(spend3.spent(), 1, "порог (3): spent чистого инстанса после Ok != 1");

    // (4a) ключ расхода выводится из ПРИЁМА: на уже потратившем его spend1 отказ рождается
    // одинаковым именем при честном и при расходящемся req.slot — сверки слота нет.
    assert_eq!(
        session::serve_request(&req_at(s0, &reissued, t), &t, &issuers, 0, &mut spend1),
        Err(session::TextError::Spend(rendezvous::AcceptError::AlreadySpent)),
        "фальсификатор (г): повтор честного предъявления обслужен — база одноразовости сломана"
    );
    // (4b) сильная форма второй поправки: тот же повтор, но с ЧУЖИМ req.slot — тоже
    // AlreadySpent, а не иной отказ. Именно эта неразличимость была причиной падения второго
    // замера (проверка на разделённом инстансе confl'атила double-spend с «отказом по слоту»).
    assert_eq!(
        session::serve_request(&req_at(s1, &reissued, t), &t, &issuers, 0, &mut spend1),
        Err(session::TextError::Spend(rendezvous::AcceptError::AlreadySpent)),
        "фальсификатор (и): расходящийся req.slot дал иной отказ, чем честный — механизм сверки слота всё же есть"
    );
    assert_eq!(
        session::serve_request(&req_at(DEAD_SLOT, &reissued, t), &t, &issuers, 0, &mut spend1),
        Err(session::TextError::Spend(rendezvous::AcceptError::AlreadySpent)),
        "фальсификатор (и): мёртвый req.slot дал не AlreadySpent — имя отказа различает слот запроса"
    );

    // (5) отказные повторения (4a)/(4b)/мёртвый не плодят строк расхода: spent всё так же 1.
    assert_eq!(spend1.spent(), 1, "фальсификатор (в): отказные повторы тронули spent");

    // (6) сильная форма поправки: адресат при этом ПРИВЯЗАН — тот же приём F0 (target=O) на
    // входе второго владельца даёт Spend(WrongTarget); фикция ровно в slot, не в адресате.
    let mut spend_b = Spend::new(300);
    assert_eq!(
        session::serve_request(&req_at(s1, &reissued, other.pubkey()), &other.pubkey(), &issuers, 0, &mut spend_b),
        Err(session::TextError::Spend(rendezvous::AcceptError::WrongTarget)),
        "фальсификатор (ж): приём обслуживается вне своего адресата — привязки target нет вовсе"
    );
    assert_eq!(spend_b.spent(), 0, "фальсификатор (ж): WrongTarget оставил след в памяти расхода B");

    eprintln!(
        "## пороги (0)…(6): serve_request обслуживает ЛЮБОЙ req.slot с валидным приёмом \
         (S1 чужого владельца и {DEAD_SLOT} — Ok на чистых инстансах), Grant несёт slot \
         приёма S0 и расхождение видно только через него; NO_SUCH_SLOT не порождается \
         (константа не конструируется нигде); повтор на потраченном инстансе даёт ОДНАКОВЫЙ \
         AlreadySpent для честного, чужого и мёртвого req.slot (4b) — цель не сверяет слот \
         вовсе, spent остаётся 1; адресат же привязан: F0(target=O) на входе B → WrongTarget ##"
    );
    remove(&d);
}
