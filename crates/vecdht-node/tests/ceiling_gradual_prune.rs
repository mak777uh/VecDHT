//! Оракул H-0057/E-0057: постепенное снятие потолка строками РАЗНЫХ бакетов (§12.3).
//!
//! `E-0056` забил всю таблицу строками бакета 0 и увидел возврат дыры «разом» на `now=20`.
//! В бою строки приходят разными бакетами, и `Issuer::prune` (`bucket < now - ttl_buckets`,
//! вызывается в начале каждого `issue`, ДО проверки `seen`) обязан возвращать дыру по одному
//! бакету за шаг, а не одним рывком. Второе отличие от `E-0056`: здесь бакет 0 занят
//! НАСТОЯЩИМИ приёмами seeker'а A (не заполнителем), поэтому после их ухода A при новом
//! `Find` получает СТРОКИ НОВОГО БАКЕТА — строка бакета 0 больше не в `seen` (урок `E-0047`:
//! `issued_bucket` входит в ключ), и побайтовости с довоенным кадром быть не должно.
//!
//! Раскладка (`MAX_ACCEPTS = 100 000`, `ttl_buckets = buckets(300) = 19`): 3 строки A в
//! бакете 0 + 99 997 чужих строк бакета 0 (потолок достигнут ровно), затем шаги `Find`
//! при now = 0 (побайтовый повтор внутри бакета), 19 (бакет 0 жив — НОВЫЙ ключ бакета 19
//! отказан: refused_full 3), 20 (cutoff 1 — уходит весь бакет 0, A получает новые строки
//! бакета 20), 21 (cutoff 2 — повтор бакета 20 побайтовый; второй seeker B получает 3
//! строки из вернувшейся дыры); refused_full замирает на 3.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, rendezvous, testing, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, MatchResult, RendezvousAccept};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const OWNER_SEEDS: [u8; 3] = [77, 78, 79];
const TTL_SEC: u16 = 300;
const TTL_BUCKETS: u32 = 19;

fn primary_on(dir_name: &str) -> (ShardNode, std::path::PathBuf) {
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

fn match_result(replies: &[vecdht_node::Envelope]) -> MatchResult {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
        .expect("фальсификатор (д): MatchResult отсутствует")
}

fn accepts(replies: &[vecdht_node::Envelope]) -> Vec<(Vec<u8>, RendezvousAccept)> {
    replies
        .iter()
        .filter(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::RendezvousAccept))
        .map(|e| (e.frame.clone(), RendezvousAccept::decode(&e.frame).expect("accept")))
        .collect()
}

fn has_error(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> bool {
    replies.iter().any(|e| {
        e.to == agent && decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::Error)
    })
}

fn find(n: &mut ShardNode, a: &vecdht_crypto::Identity, bucket: u32, qid: u64) -> Vec<vecdht_node::Envelope> {
    n.on_frame(
        a.pubkey(),
        &testing::find_frame(a, &testing::vector(1), &[CLUSTER], 8, qid),
        testing::clock(bucket),
    )
    .expect("find")
}

#[test]
fn the_ceiling_returns_bucket_by_bucket_when_rows_live_in_different_buckets() {
    let (mut n, d) = primary_on("ceiling-gradual-prune");
    assert_eq!(
        vecdht_node::buckets(TTL_SEC as u32),
        TTL_BUCKETS,
        "фальсификатор (е): границы бакетов взяты не из той же арифметики, что `Issuer`"
    );
    assert_eq!(
        testing::params(POW).rendezvous_ttl,
        TTL_SEC,
        "фальсификатор (е): TTL тестового узла разошёлся с TTL оракула"
    );
    for (i, s) in OWNER_SEEDS.iter().enumerate() {
        n.on_frame(
            testing::identity(*s).pubkey(),
            &publish_frame(*s, 1 + i as u8),
            testing::clock(0),
        )
        .expect("publish");
    }
    assert_eq!(n.store.len(), 3, "три живые записи");

    let a = testing::identity(88);

    // now = 0: A получает 3 настоящих приёма бакета 0 — они и войдут в таблицу.
    let r0 = find(&mut n, &a, 0, 601);
    let head = accepts(&r0);
    assert_eq!(head.len(), 3, "фальсификатор (д): голова бакета 0 не выдана");
    assert_eq!(n.rendezvous.live(), 3, "фальсификатор (а): выдача A не в таблице");
    assert_eq!(n.rendezvous.refused_full, 0, "фальсификатор (а): отказ при неполной таблице");

    // Достройка до потолка чужими строками ТОГО ЖЕ бакета 0: дыры нет вовсе.
    let junk = [9u8; 32];
    for i in 0..rendezvous::MAX_ACCEPTS - 3 {
        assert!(
            n.rendezvous
                .issue(junk, testing::identity(90).pubkey(), SHARD, 30_000 + i as u32, 0)
                .is_some(),
            "строка №{i} бакета 0 обязана влезть"
        );
    }
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (а): дыра осталась");

    // Порог (1a): now = 0, таблица полная — повтор в ТОМ ЖЕ бакете идемпотентен побайтово
    // (поправка H-0057 после первого падения: `Key` включает issued_bucket, поэтому
    // «довоенный повтор» имеет смысл только внутри бакета).
    let ra0 = find(&mut n, &a, 0, 602);
    let acc_a0 = accepts(&ra0);
    assert_eq!(acc_a0.len(), 3, "фальсификатор (б): повтор того же бакета не отдаёт голову");
    for i in 0..3 {
        assert_eq!(acc_a0[i].0, head[i].0, "фальсификатор (б): повтор бакета 0 не побайтовый");
    }
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (а)");
    assert_eq!(n.rendezvous.refused_full, 0, "порог (1a): идемпотентный повтор не отказывает");

    // Порог (1b): now = 19 — бакет 0 ещё жив (19−19=0, `bucket < 0` ложно); ключ (A, …, 19)
    // НОВЫЙ (бакет входит в Key), таблица полна → ровно 3 отказа. Различающий: ранний prune
    // оставил бы дыру → выдача вместо отказа (фальсификатор (в)).
    let r19 = find(&mut n, &a, TTL_BUCKETS, 603);
    assert_eq!(accepts(&r19).len(), 0, "порог (1b): полная таблица отказывает, дыры быть не должно");
    assert_eq!(match_result(&r19).matches.len(), 3, "фальсификатор (д)");
    assert_eq!(n.rendezvous.live(), rendezvous::MAX_ACCEPTS, "фальсификатор (в): бакет 0 выброшен раньше cutoff");
    assert_eq!(n.rendezvous.refused_full, 3, "порог (1b): ровно 3 отказа");
    assert!(!has_error(&r19, a.pubkey()), "фальсификатор (ж): отказ на потолке стал ошибкой");

    // Порог (2): now = 20 — cutoff 1, уходит ВЕСЬ бакет 0 (строки A + 99 997 чужих).
    // A при этом получает 3 НОВЫХ строки бакета 20: ключ с issued_bucket=0 больше не в
    // seen (это и есть «постепенность» — дыра вернулась, но выданная строка уже новая).
    let r20 = find(&mut n, &a, TTL_BUCKETS + 1, 603);
    let acc20 = accepts(&r20);
    assert_eq!(acc20.len(), 3, "фальсификатор (в): дыра после ухода бакета 0 не вернулась");
    for (i, (_, x)) in acc20.iter().enumerate() {
        assert_eq!(x.issued_bucket, TTL_BUCKETS + 1, "порог (2): приём №{i} не бакета 20");
        assert_ne!(
            acc20[i].0, head[i].0,
            "фальсификатор (в): строка бакета 0 пережила собственный prune"
        );
    }
    assert_eq!(n.rendezvous.live(), 3, "фальсификатор (в): после prune остались лишние строки");
    assert_eq!(n.rendezvous.refused_full, 3, "порог (2): новых отказов нет (замер 1b застыл на 3)");

    // Порог (3): now = 20 ещё раз (повтор A ВНУТРИ бакета 20, cutoff 2 бакет 20 не трогает) —
    // побайтово строкам acc20; идемпотентность по поправке живёт строго внутри бакета.
    let r20b = find(&mut n, &a, TTL_BUCKETS + 1, 604);
    let acc20b = accepts(&r20b);
    assert_eq!(acc20b.len(), 3, "фальсификатор (г): повтор бакета 20 не отдаёт свои строки");
    for i in 0..3 {
        assert_eq!(acc20b[i].0, acc20[i].0, "фальсификатор (г): повтор бакета 20 не побайтовый");
    }
    assert_eq!(n.rendezvous.live(), 3, "фальсификатор (г): повтор удваивает таблицу");
    assert_eq!(n.rendezvous.refused_full, 3, "порог (3): новых отказов нет");

    // Порог (4): now = 21 — второй seeker B получает 3 строки бакета 21 из дыры,
    // returned prune'ом на шаге (2); A при этом не вытесняется.
    let b = testing::identity(89);
    let rb = find(&mut n, &b, TTL_BUCKETS + 2, 605);
    assert_eq!(accepts(&rb).len(), 3, "фальсификатор (д): B не получил дыру, которую вернул prune");
    assert_eq!(match_result(&rb).matches.len(), 3, "фальсификатор (д)");
    for (_, x) in accepts(&rb) {
        assert_eq!(x.issued_bucket, TTL_BUCKETS + 2, "фальсификатор (д): строки B не бакета 21");
    }
    assert_eq!(n.rendezvous.live(), 6, "порог (4): 3 строки A бакета 20 + 3 строки B бакета 21");
    assert_eq!(n.rendezvous.refused_full, 3, "фальсификатор (б): отказ там, где дыра есть");
    assert!(!has_error(&rb, b.pubkey()), "фальсификатор (ж): пустая выдача стала ошибкой");

    eprintln!(
        "## пороги (1a)…(4) по поправке H-0057: повтор в бакете 0 при полной таблице — \
         3 побайтовых, refused 0; now=19 — 0 приёмов, refused 3, live 100 000 (бакет 0 жив, \
         новый ключ бакета 19 отказан); now=20 — prune снимает бакет 0, A получает 3 НОВЫХ \
         строки бакета 20 (байты ≠ довоенные), live 3; повтор now=20 — те же 3 побайтовых; \
         B при now=21 — 3 новых строки бакета 21, live 6; refused_full замирает на 3, \
         кадров Error нет ##"
    );
    remove(&d);
}
