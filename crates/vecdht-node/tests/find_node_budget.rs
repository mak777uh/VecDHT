//! Оракул E-0039, пороги (1)…(3): узловой бюджет §11.3.4 на `Find` не расходуется — sybil из
//! 21 ключа легально даёт узлу 105 разрешённых поиска в секунду (больше `node_budget = 100`),
//! а все сто токенов узлового бюджета остаются целыми.
//!
//! Harness — `find_admission_price.rs`. Пустой индекс: исход политики приёма от содержимого
//! шарда не зависит (цена кадра измерена в `E-0037`, стоимость списка — тоже; здесь меряется
//! только отсутствие узлового потолка для чтения).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{admission::Verdict, candidates, testing, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, ProtocolError};

const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const KEYS: u8 = 21;

fn primary_on(dir_name: &str, p: Params) -> (ShardNode, std::path::PathBuf) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = testing::node(&d, SHARD, seed, p, &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "отвечает на Find primary эпизоды");
    (n, d)
}

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

#[test]
fn sybil_find_surge_passes_node_budget_untouched() {
    let (mut n, d) = primary_on("find-budget", testing::params(POW));

    // Пачка: 21 свежих ключа × 6 кадров при секунде 0. Ожидание: 105 разрешённых, 21 QUOTA_FIND.
    let mut allowed = 0usize;
    let mut quota = 0usize;
    let mut other: Vec<String> = Vec::new();
    for k in 0..KEYS {
        let agent = testing::identity(100 + k);
        let me = agent.pubkey();
        let frame = testing::find_frame(&agent, &testing::vector(1), &[CLUSTER], 8, 1);
        for _ in 0..6 {
            let replies = n.on_frame(me, &frame, testing::clock(0)).expect("find");
            match error_to(&replies, me) {
                None => allowed += 1,
                Some(e) if e.code == err_code::QUOTA_FIND => quota += 1,
                Some(e) => other.push(format!("{}: {}", 100 + k, e.code)),
            }
        }
    }
    // Порог (1): 105 = 5·21 пропущено, 21 отказ ровно от квоты, ноль иных исходов.
    assert_eq!(allowed, 126 - usize::from(KEYS), "пропущено не 5·K: {allowed}");
    assert_eq!(quota, usize::from(KEYS), "QUOTA_FIND не по ключу: {quota}");
    assert!(other.is_empty(), "фальсификатор (а): исход, отличный от пропуска/QUOTA_FIND: {other:?}");

    // Порог (2): статистика ровно та же (бакет find не делился с узлом).
    let stats = &n.admission.borrow().stats;
    assert_eq!(stats.finds_allowed, 126 - usize::from(KEYS) as u64, "finds_allowed");
    assert_eq!(stats.rejected_find_quota, usize::from(KEYS) as u64, "rejected_find_quota");
    assert_eq!(stats.rejected_node_busy, 0, "фальсификатор (б): find всё-таки трогает узловой бюджет");

    // Порог (3): контраст — узловой бюджет цел: 100 подряд Allow, 101-й NodeBusy/10 мс.
    for i in 0..100u32 {
        assert!(
            n.admission.borrow_mut().reserve_admit(0).is_allow(),
            "фальсификатор (б): бюджет §11.3.4 не после пачки, а уже на #{i}"
        );
    }
    assert_eq!(
        n.admission.borrow_mut().reserve_admit(0),
        Verdict::NodeBusy { retry_after_ms: 10 },
        "101-й reserve_admit обязан быть NodeBusy 10 мс (арифметика unit-теста бюджета)"
    );

    eprintln!(
        "## порог (1)…(3): {allowed} find пропущено, {quota} QUOTA_FIND, иных 0; \
         budget цел: 100 Allow после пачки, 101-й NodeBusy ##"
    );
    remove(&d);
}
