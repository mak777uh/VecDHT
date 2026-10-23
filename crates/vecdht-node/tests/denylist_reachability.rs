//! Оракул H-0042/E-0042: подотчётность через denylist (§11.4 (ii)) на живом узле.
//!
//! «До» перезагрузки внесённый ключ отвечает на проводе `DENIED` и виден в списке. Ветку «после»
//! этот оракул замерл дырой: цепочка членства восстанавливалась с диска (`epoch()==Some(1)`), а
//! список был пуст. Дыру закрыл `E-0092` (файл `denylist.bin`, `ADR-0047`), и блок ниже
//! переписан на закрытое состояние — по тому же правилу, что `E-0087` применил к оракулу
//! авторизации gossip: оракул дыры не имеет права врать после фикса, иначе зелёный воркспейс
//! означает «механизм сломан», а тест падает ровно тогда, когда переживаемость исчезает.
//!
//! Имя таргета до `E-0092` было `denylist_is_unreachable_in_and_vanishes_on_restart` — старые
//! логи (`lab/logs/e0042-*.log`, снимок PRE_FIX `E-0092`) cite именно его; оно сохранено здесь
//! как ссылка, чтобы история замеров осталась читаемой.
//!
//! Код на проводе после рестарта по-прежнему не `DENIED`, и это не дыра denylist'а:
//! `open_with_admission` поднимает цепочку членства, но не `lease`, поэтому кадр отбивается как
//! `EPOCH_STALE` раньше admission'а — для любого ключа. Отдельный неизмеренный ранее факт,
//! названный в карточке `H-0092` и перенесённый в `OPEN-QUESTIONS`.

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, ProtocolError};

const SHARD: u16 = 7;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn params() -> Params {
    testing::params(POW)
}

/// Узел шарда, принявший genesis эпохи 1: primary с активным lease (harness `tests/admission.rs`).
fn primary_on(dir_name: &str) -> (ShardNode, std::path::PathBuf) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = testing::node(&d, SHARD, seed, params(), &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "отказ DENIED меряется на пути записи primary");
    (n, d)
}

/// Кадр publish от агента с_seed=1 (тот же `intent_id`, что и в «до»-наблюдении).
fn publish_frame(agent_seed: u8) -> Vec<u8> {
    let agent = testing::identity(agent_seed);
    testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(1),
        cluster_id: SHARD << 4,
        shard: SHARD,
        epoch: 1,
        published_bucket: 0,
        ttl_buckets: 225,
        bits: POW,
    }
    .frame()
}

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

#[test]
fn denylist_is_reachable_and_survives_restart() {
    let (mut n, d) = primary_on("deny-restart");
    let bad = testing::identity(85);
    let me = bad.pubkey();

    // Порог (1): «до» — внесение первым вызовом, отказ ровно DENIED, счётчики видят список.
    assert!(n.admission.borrow_mut().deny(me), "первый deny того же ключа");
    let before = {
        let a = n.admission.borrow();
        (a.denylist_len(), a.is_denied(&me), a.stats.denied_by_denylist)
    };
    assert_eq!(before, (1, true, 0), "состояние admission сразу после deny");
    let replies = n
        .on_frame(me, &publish_frame(85), testing::clock(0))
        .expect("publish от внесённого ключа");
    let err = error_to(&replies, me).expect("внесённый ключ обязан получить Error");
    assert_eq!(err.code, err_code::DENIED, "код «до» перезагрузки");
    let after_hit = {
        let a = n.admission.borrow();
        (a.denylist_len(), a.is_denied(&me), a.stats.denied_by_denylist)
    };
    assert_eq!(after_hit, (1, true, 1), "отказ учтён в denied_by_denylist");

    // Порог (2) после `E-0092`: «после» открытия того же каталога — и цепочка с диска, и список
    // с диска. Именно этот блок был замером дыры; теперь он регрессия переживаемости.
    drop(n);
    let seed = {
        let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
        *SEEDS
            .iter()
            .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
            .expect("тот же primary-сид, что и в первом открытии")
    };
    let mut n2 = testing::node(&d, SHARD, seed, params(), &SEEDS);
    assert_eq!(n2.epoch(), Some(1), "фальсификатор (д): состояние узла восстановлено с диска");
    let a2 = n2.admission.borrow();
    assert_eq!(a2.denylist_len(), 1, "порог (2) `E-0092`: внесённый «до» запрет пережил рестарт");
    assert!(a2.is_denied(&me), "внесённый «до» ключ по-прежнему запрещён");
    assert_eq!(
        a2.stats.denied_by_denylist, 0,
        "счётчик отказов процесса начинается с нуля: это счётчик пути, а не состояние списка"
    );
    drop(a2);

    // Порог (3): код на проводе после рестарта — факт, а не предсказание denylist'а. Узел без
    // `lease` отвечает `EPOCH_STALE` любому ключу (см. документацию модуля), поэтому проверка
    // здесь одна: запрет не должен «протечь» обратно в ноль, а решение списка мерится гейтом (4)
    // оракула `denylist_durable_after_restart.rs`.
    let replies = n2
        .on_frame(me, &publish_frame(85), testing::clock(1))
        .expect("publish после перезагрузки");
    let code = error_to(&replies, me).map(|e| e.code).unwrap_or_else(|| {
        // Ответа Error нет — значит кадр ушёл дальше по пути приёма; фиксируем это числом конвертов.
        assert_eq!(replies.len(), 0, "без Error и без конвертов быть не может");
        "(нет Error)".to_string()
    });
    eprintln!("## порог (3): код после перезагрузки = {code} (узел без lease: EPOCH_STALE) ##");
    assert_ne!(code, err_code::DENIED, "на проводе отказа пока нет — дыра lease'а, не списка");

    remove(&d);
}
