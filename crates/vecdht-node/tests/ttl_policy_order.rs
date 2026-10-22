//! Оракул H-0060/E-0060: полный набор проверок `Spend::consume` и его порядок (§12.3).
//!
//! Спека: «Полный набор проверок — подпись издателя → адресат → политика TTL →
//! истечение → одноразовый расход — реализован в экспортируемом типе `Spend::consume`».
//! Порядок назван явно; ветка `TtlOutOfPolicy` нигде в тестах не появлялась (grep по
//! `crates/`). `adversarial.rs` мерил `WrongTarget` одним кадром, `E-0047`/`E-0058`/
//! `E-0059` — окно и память расхода. Не мерилось: (i) гейт политики при `ttl_sec == 0`
//! и `ttl_sec > max` ДО spent-таблицы, (ii) precedence адресата над политикой и
//! истечением при двойно-ложных полях, (iii) что окно считается ИЗ КАРТКИ `acc.ttl_sec`,
//! а политика `Spend::new` — только отказ.
//!
//! Пороги (ttl живой карты = 300, buckets(300)=19, buckets(1)=1, buckets(315)=20;
//! приём A бакета 0, издатель — сам primary (подпись n.id, iss = n.me())):
//! (0) consume f0@19 → Ok, spent==1;
//! (1) ttl=0 подделка @19 → TtlOutOfPolicy(0), spent не изменился;
//! (2) ttl=301 @19 в Spend::new(300) → TtlOutOfPolicy(301);
//! (3) ttl=301 @19 в Spend::new(315) → Ok (грань 20 не достигнута) — окно из карты;
//! (4) wrong-target + ttl=0 → WrongTarget (адресат до политики);
//! (5) wrong-target + now=301 → WrongTarget (адресат до истечения);
//! (6) ttl=1: @1 Ok, @1 повтор AlreadySpent, @2 Expired, spent==0 (память = окно);
//! (7) Unsigned-кадр → Unsigned; подпись чужая при верном target → BadSignature;
//! (8) f0@20 → Expired, spent базовой цели == 1 (подделки не просорили память).

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode, Spend};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{domain, Codec, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER_SEEDS: [u8; 3] = [77, 78, 79];
const EDGE_300: u32 = 19; // 0 + buckets(300)
const DEAD_300: u32 = 20;

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

/// Переиздание тела с другим `ttl_sec` (подпись — ключом `key`, кадр SIGNED).
fn reforge(acc: RendezvousAccept, ttl: u16, key: &Identity) -> Vec<u8> {
    let mut f = acc;
    f.ttl_sec = ttl;
    let body = f.body_bytes();
    let sig = key.sign_body(domain::RENDEZVOUS, Kind::RendezvousAccept, &body);
    f.encode_signed(&sig)
}


#[test]
fn ttl_policy_gate_and_check_order_match_the_spec_sequence() {
    let (mut n, d, pseed) = primary_on("ttl-policy-order");
    let pid = testing::identity(pseed);
    for (i, s) in OWNER_SEEDS.iter().enumerate() {
        n.on_frame(
            testing::identity(*s).pubkey(),
            &publish_frame(*s, 1 + i as u8),
            testing::clock(0),
        )
        .expect("publish");
    }
    let a = testing::identity(88);
    let replies = n
        .on_frame(
            a.pubkey(),
            &testing::find_frame(&a, &testing::vector(1), &[CLUSTER], 8, 901),
            testing::clock(0),
        )
        .expect("find");
    let accs = accepts(&replies);
    assert_eq!(accs.len(), 3, "фальсификатор (д): голова бакета 0 не выдана");
    let (f0, a0) = &accs[0];
    assert_eq!((a0.issued_bucket, a0.ttl_sec), (0, 300), "фальсификатор (д): карта не бакета 0/ttl=300");
    let iss = n.me();
    // ДИАГНОЗ-3: подпись приёмки — ключом узла (iss=n.me()), а `target` карты — владелец
    // записи, и именно он обязан приходить третьим аргументом (`me` цели): ровно так
    // сделано в adversarial.rs/E-0058 (`consume(&frame, &n.me(), &owner.pubkey(), ..)`).
    let tgt = a0.target;
    assert!(
        OWNER_SEEDS.iter().any(|s| testing::identity(*s).pubkey() == tgt),
        "харнес: адресат карты — не владелец записи"
    );

    // Порог (0): базовая грань окна 300.
    let mut spend = Spend::new(300);
    let g = spend.consume(f0, &iss, &tgt, EDGE_300).expect("порог (0): грань 19 отказала");
    assert_eq!((g.seeker, g.issued_bucket), (a.pubkey(), 0), "фальсификатор (ж): grant не связан");
    assert_eq!(spend.spent(), 1, "фальсификатор (ж): spent после Ok");

    // Порог (1): ttl=0 — политика; память расхода НЕ тронута (гейт до вставки).
    let f0z = reforge(*a0, 0, &pid);
    assert_eq!(
        spend.consume(&f0z, &iss, &tgt, EDGE_300),
        Err(rendezvous::AcceptError::TtlOutOfPolicy(0)),
        "фальсификатор (а): ttl=0 принят"
    );
    assert_eq!(spend.spent(), 1, "фальсификатор (б): отказ по политике тронул spent");

    // Порог (2): ttl=301 при политике 300 — отказ.
    let f301 = reforge(*a0, 301, &pid);
    assert_eq!(
        spend.consume(&f301, &iss, &tgt, EDGE_300),
        Err(rendezvous::AcceptError::TtlOutOfPolicy(301)),
        "фальсификатор (а): ttl=301 принят политикой 300"
    );
    assert_eq!(spend.spent(), 1, "фальсификатор (б): spent после TtlOutOfPolicy(301)");

    // Порог (3): та же карта у цели с политикой 315 — Ok (окно из карты: грань 20).
    let mut spend315 = Spend::new(315);
    let g3 = spend315
        .consume(&f301, &iss, &tgt, EDGE_300)
        .expect("фальсификатор (г): ttl=301 отвергнут политикой 315");
    assert_eq!((g3.seeker, g3.issued_bucket), (a.pubkey(), 0), "фальсификатор (ж): grant (3)");
    assert_eq!(spend315.spent(), 1, "порог (3): память второй цели");

    // Порог (4): wrong-target + ttl=0 → адресат ДО политики.
    let other = testing::identity(56);
    assert_ne!(other.pubkey(), tgt, "харнес: «чужой» совпал с адресатом карты");
    assert_eq!(
        spend.consume(&f0z, &iss, &other.pubkey(), EDGE_300),
        Err(rendezvous::AcceptError::WrongTarget),
        "фальсификатор (в): политика опередила адресата"
    );

    // Порог (5): wrong-target + now=301 (истекает) → адресат ДО истечения.
    assert_eq!(
        spend.consume(f0, &iss, &other.pubkey(), 301),
        Err(rendezvous::AcceptError::WrongTarget),
        "фальсификатор (в): истечение опередило адресата"
    );

    // Порог (6): ttl=1 — окно = buckets(1)=1 из карты; память = окно.
    let f1 = reforge(*a0, 1, &pid);
    let mut spend6 = Spend::new(300);
    spend6
        .consume(&f1, &iss, &tgt, 1)
        .expect("фальсификатор (д): грань buckets(1)=1 отказала");
    assert_eq!(
        spend6.consume(&f1, &iss, &tgt, 1),
        Err(rendezvous::AcceptError::AlreadySpent),
        "фальсификатор (б): повтор ttl=1 обслужен"
    );
    assert_eq!(
        spend6.consume(&f1, &iss, &tgt, 2),
        Err(rendezvous::AcceptError::Expired),
        "фальсификатор (д): ttl=1 пережил грань buckets(1)"
    );
    assert_eq!(spend6.spent(), 0, "фальсификатор (д): память расхода ttl=1 не равна окну");

    // Порог (7): Unsigned → подпись раньше всех; чужая подпись при верном target → BadSignature.
    let unsigned = {
        let mut u = *a0;
        u.ttl_sec = 0;
        u.encode_unsigned()
    };
    assert_eq!(
        spend.consume(&unsigned, &iss, &tgt, EDGE_300),
        Err(rendezvous::AcceptError::Unsigned),
        "фальсификатор (е): без-подписной кадр дошёл до тела"
    );
    let foreign_sig = reforge(*a0, 0, &testing::identity(88));
    assert_eq!(
        spend.consume(&foreign_sig, &iss, &tgt, EDGE_300),
        Err(rendezvous::AcceptError::BadSignature),
        "фальсификатор (е): чужая подпись дошла до политики"
    );
    assert_eq!(spend.spent(), 1, "фальсификатор (б): ветки (7) тронули spent");

    // Порог (8): базовый кадр на 20 — Expired; память базовой цели не просорилась.
    assert_eq!(
        spend.consume(f0, &iss, &tgt, DEAD_300),
        Err(rendezvous::AcceptError::Expired),
        "фальсификатор (з): f0 пережил собственное окно"
    );
    assert_eq!(spend.spent(), 1, "фальсификатор (з): spent базовой цели после всех веток");

    eprintln!(
        "## пороги (0)…(8): порядок consume = подпись → адресат → политика → истечение → \
         расход: ttl=0 и ttl=301 → TtlOutOfPolicy без следа в spent; ttl=301 у цели с \
         политикой 315 → Ok (окно из карты: 0+buckets(315)=20); wrong-target при \
         заведомо ложных ttl/истечении → WrongTarget; ttl=1: Ok@1, AlreadySpent@1, \
         Expired@2, spent==0 (память=окно); Unsigned/BadSignature раньше политики; f0@20 \
         Expired, spent==1 ##"
    );
    remove(&d);
}
