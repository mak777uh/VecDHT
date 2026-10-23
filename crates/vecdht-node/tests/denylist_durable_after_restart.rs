//! Оракул `H-0092`/`E-0092` — релиз-блокер (3), часть B из `ADR-0044`: запрет переживает
//! перезапуск узла и имеет предел.
//!
//! Дыру измерил `E-0042` (её же констатировал `ADR-0009`): при повторном открытии того же
//! каталога цепочка членства поднимается с диска, а `denylist_len()` — ноль, и внесённый «до»
//! ключ больше не встречает `DENIED`. Цена — один рестарт: оператор вносит атакующего, тот
//! перезапускается и получает прежнюю квоту бесплатно. Вторая половина та же: предела у
//! `BTreeSet<Addr>` нет, поэтому встраиватель, банящий по своему наблюдению, получает
//! неограниченный рост памяти.
//!
//! Политика предела выбрана не мнением, а перебором в `lab/lean/VecDHT/Denylist.lean`: из
//! четырёх кандидатов (отказ / вытеснить старого / вытеснить новичка / счистить истёкшее)
//! «ни один не отозванный запрет не исчезает сам» выполняется ровно у одного — отказа, что
//! совпадает с выбором `E-0088` (`SHARD_FULL` вместо вытеснения) и с `HAProxy stick_table`
//! (`L-0008`). Следствие, названное в модели и обязанное быть в ADR вслух: при полном списке
//! множество **замораживается** — новый ключ войти не может, пока кто-то не отозван.
//!
//! Границы оракула. Он проверяет переживаемость и конечность как **свойство библиотеки**,
//! которой пользуется встраиватель: продуктовых вызовов `deny()` по-прежнему нет (`ADR-0009`,
//! инвентарь 4а), и это не Sybil-защита. Срока действия у запрета нет — `L-0007` его имеет, мы
//! его не вводим, потому что срок есть новая политика, а не закрытие измеряемой дыры; следствие
//! (заморозка) перенесено в `OPEN-QUESTIONS`.
//!
//! Гейт (4) измеряет решение, а не код на проводе, и это не смягчение порога, а форма замера:
//! на дереве до правки обнаружилось, что перезагруженный primary в этом харнесе не восстанавливает
//! `lease` и отвечает `EPOCH_STALE` любому ключу ещё до admission'а. Пока это не закрыто, «DENIED
//! на проводе после рестарта» нельзя отличить от «узел вообще не пишет» — отдельный неизмеренный
//! ранее факт, вынесенный в `OPEN-QUESTIONS`.
//!
//! Форма фактов — только длины, размер файла и коды отказов: ни один гейт не зависит от
//! расписания шагов или от часов (правило 7, пункт (е)), поэтому вектор обязан совпасть в двух
//! прогонах на неизменном дереве. Печать идёт по одному факту-ключу на гейт (`DENY_G1…DENY_G6`),
//! а проверки собраны в список проблем и проверяются одной строкой в конце: PRE_FIX (дерево без
//! правки) обязан дойти до всех шести гейтов и напечатать вектор, а не оборваться на втором.

use std::path::{Path, PathBuf};

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Admission, Params, ShardNode, Verdict};
use vecdht_wire::messages::{err_code, Codec, ProtocolError};

const SHARD: u16 = 7;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
/// Имя файла запрета в каталоге узла. Здесь оно — предсказание оракула, а не константа продукта:
/// если правка выберет другое имя, гейт (2) упадёт и это будет фактом, а не поводом править тест.
const FILE: &str = "denylist.bin";
/// Цена переживаемости: заголовок 8 magic + 2 версия + 4 количество + 4 контрольная сумма и
/// ровно 32 байта на ключ, ничего сверх. Число зафиксировано карточкой до пре-регистрации.
const HEADER: u64 = 18;
/// Предел списка из карточки. Модель Lean конечна (3 ключа, предел 2) и про 4096 ничего не
/// утверждает: число — решение ADR, а проверкой числа является этот гейт.
const MAX_DENYLIST: usize = 4_096;

/// Каталог удаляется при выходе из области видимости: PRE_FIX паникует в конце тела, и ручной
/// `remove` в последней строке оставил бы мусор — дефект метода из `E-0085` ДИАГНОЗ-2.
struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

fn params() -> Params {
    testing::params(POW)
}

/// Узел шарда, принявший genesis эпохи 1 (тот же харнес, что у оракула дыры).
fn primary_on(dir_name: &str) -> (ShardNode, Tmp) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = Tmp(dir(dir_name));
    let mut n = testing::node(&d.0, SHARD, seed, params(), &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "отказ DENIED меряется на пути записи primary");
    (n, d)
}

/// Второе открытие того же каталога тем же сидом — ровно то, что делает узел при рестарте.
fn reopen(d: &Path) -> ShardNode {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("тот же primary-сид, что и в первом открытии");
    testing::node(d, SHARD, seed, params(), &SEEDS)
}

/// Кадр publish от агента с сидом `agent_seed` (тот же путь приёма, что в оракуле дыры).
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

/// Три вносимых ключа — реальные идентификаторы тестовых сидов: `is_denied` обязан сработать по
/// pubkey, а не по первому попавшемуся массиву.
fn keys() -> [[u8; 32]; 3] {
    [
        testing::identity(85).pubkey(),
        testing::identity(86).pubkey(),
        testing::identity(87).pubkey(),
    ]
}

/// Отличающийся от нулевого ключ для гейта (6): первый байт 199, дальше — индекс.
fn deny_key(i: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 199;
    k[24..].copy_from_slice(&(i as u64).to_le_bytes());
    k
}

/// Код отказа на проводе, или метка «ответа Error нет» — как в оракуле дыры, где это было
/// `NOT_OWNER`, а не пустой список.
fn code_after_publish(n: &mut ShardNode, key: [u8; 32], seed: u8, bucket: u32) -> String {
    let replies = n
        .on_frame(key, &publish_frame(seed), testing::clock(bucket))
        .expect("publish от внесённого ключа");
    match error_to(&replies, key) {
        Some(e) => e.code.clone(),
        None => "(нет Error)".to_string(),
    }
}

#[test]
fn denylist_survives_restart_and_undeny() {
    let mut bad: Vec<String> = Vec::new();
    let mut note = |m: String| bad.push(m);
    let k = keys();

    // (1) «до» рестарта: три внесённых, список длины 3, отказ ровно DENIED, счётчик видит список.
    let (mut n, d) = primary_on("deny-durable");
    for key in k {
        assert!(n.admission.borrow_mut().deny(key), "первый deny того же ключа");
    }
    let g1_code = code_after_publish(&mut n, k[0], 85, 0);
    let (g1_len, g1_denied, g1_hits) = {
        let a = n.admission.borrow();
        (
            a.denylist_len(),
            [k[0], k[1], k[2]].iter().filter(|x| a.is_denied(x)).count(),
            a.stats.denied_by_denylist,
        )
    };
    eprintln!(
        "DENY_G1: g1_len={g1_len} g1_denied={g1_denied} g1_hits={g1_hits} g1_code={g1_code}"
    );
    if (g1_len, g1_denied, g1_hits) != (3, 3, 1) || g1_code != err_code::DENIED {
        note("(1) не выполнен".to_string());
    }

    // (2) цена переживаемости: файл существует и весит ровно 18 + 32·3 = 114 байт.
    let path = d.0.join(FILE);
    let (g2_file, g2_bytes) = match std::fs::metadata(&path) {
        Ok(m) => (1u8, m.len()),
        Err(_) => (0u8, 0u64),
    };
    eprintln!("DENY_G2: g2_file={g2_file} g2_bytes={g2_bytes} g2_want={}", HEADER + 32 * 3);
    if g2_file != 1 || g2_bytes != HEADER + 32 * 3 {
        note("(2) не выполнен".to_string());
    }

    // (3) повторное открытие того же каталога: состояние узла и все три запрета восстановлены.
    drop(n);
    let mut n2 = reopen(&d.0);
    let g3_epoch = n2.epoch().unwrap_or(0);
    let a2 = n2.admission.borrow();
    let (g3_len, g3_denied) = (
        a2.denylist_len(),
        [k[0], k[1], k[2]].iter().filter(|x| a2.is_denied(x)).count(),
    );
    drop(a2);
    eprintln!("DENY_G3: g3_epoch={g3_epoch} g3_len={g3_len} g3_denied={g3_denied}");
    if (g3_epoch, g3_len, g3_denied) != (1, 3, 3) {
        note("(3) не выполнен: дыра E-0042 открыта".to_string());
    }

    // (4) решение запрета после рестарта проверяется на той двери, где оно живёт: `check_publish`
    // отвечает `Denied` внесённому «до» ключу и `Allow` чистому. Код на проводе здесь только
    // печатается, и вот почему (замерено на этом же дереве до правки): перезагруженный primary не
    // восстанавливает lease, поэтому кадр отбивается как `EPOCH_STALE` **до** admission'а — любой
    // ключ, внесённый или нет. Требовать `DENIED` на проводе после рестарта значило бы гейтить не
    // переживаемость запрета, а дыру членства (ДИАГНОЗ-1 из `E-0087`: невыполнимый по построению
    // гейт). Последняя — неизмеренный ранее факт, он перенесён в `OPEN-QUESTIONS`.
    let clean = testing::identity(88).pubkey();
    let (g4_denied, g4_allow) = {
        let mut a = n2.admission.borrow_mut();
        (
            matches!(a.check_publish(&k[0], &k[0], 0), Verdict::Denied),
            matches!(a.check_publish(&clean, &clean, 1), Verdict::Allow),
        )
    };
    let g4_wire = code_after_publish(&mut n2, k[0], 85, 0);
    eprintln!("DENY_G4: g4_denied={g4_denied} g4_allow={g4_allow} g4_wire={g4_wire}");
    if !g4_denied || !g4_allow {
        note("(4) не выполнен: решение запрета не пережило рестарт".to_string());
    }

    // (5) снятие тоже переживает: отзыв одного ключа и второй рестарт ⇒ длина 2, отозванный
    // свободен, остальные двое по-прежнему внесены. Сам отзыв — факт, а не assert: на дереве без
    // правки списка после рестарта нет, и `undeny` закономерно вернёт `false`.
    let g5_undenied = if n2.admission.borrow_mut().undeny(&k[1]) { 1 } else { 0 };
    drop(n2);
    let n3 = reopen(&d.0);
    let a3 = n3.admission.borrow();
    let g5_len = a3.denylist_len();
    let g5_revoked = if a3.is_denied(&k[1]) { 1 } else { 0 };
    let g5_kept = [k[0], k[2]].iter().filter(|x| a3.is_denied(x)).count();
    drop(a3);
    eprintln!(
        "DENY_G5: g5_undenied={g5_undenied} g5_len={g5_len} g5_revoked={g5_revoked} \
         g5_kept={g5_kept}"
    );
    if (g5_undenied, g5_len, g5_revoked, g5_kept) != (1, 2, 0, 2) {
        note("(5) не выполнен".to_string());
    }

    assert!(bad.is_empty(), "гейты не выполнены: {bad:?}");
}

#[test]
fn denylist_refuses_at_the_bound_and_keeps_every_entry() {
    let mut bad: Vec<String> = Vec::new();

    // (6) предел в памяти без файла: 4096 внесений приняты, 4097-е отвергнуто, список не вырос
    // и ни один из первых ключей не вытеснен — отказ вместо вытеснения (`L-0008`, модель Lean).
    let mut a = Admission::new(&params());
    let mut g6_accepted = 0usize;
    for i in 0..MAX_DENYLIST {
        if a.deny(deny_key(i)) {
            g6_accepted += 1;
        }
    }
    let g6_first_before = a.is_denied(&deny_key(0));
    // Печатный ключ `g6_refused` заморожен в таблице ожиданий helper'а и означает «4097-е внесение
    // ПРОШЛО» (1 = предела нет, 0 = отказ). Чтение наоборот даёт ровно противоположный вердикт,
    // поэтому локальная переменная названа честно, а ключ не переименован: после пре-регистрации
    // ожидания не двигают (AGENTS.md), а записывают как есть.
    let g6_extra_accepted = a.deny(deny_key(MAX_DENYLIST));
    let g6_len = a.denylist_len();
    let mut g6_first_kept = 0usize;
    for i in 0..MAX_DENYLIST {
        if a.is_denied(&deny_key(i)) {
            g6_first_kept += 1;
        }
    }
    eprintln!(
        "DENY_G6: g6_accepted={g6_accepted} g6_refused={} g6_len={g6_len} \
         g6_first_before={g6_first_before} g6_first_kept={g6_first_kept}",
        if g6_extra_accepted { 1 } else { 0 }
    );
    if g6_accepted != MAX_DENYLIST || g6_extra_accepted || g6_len != MAX_DENYLIST || g6_first_kept != MAX_DENYLIST {
        bad.push("(6) не выполнен: предел не отказывает или список потерял внесённое".to_string());
    }
    // Отзыв при полном списке освобождает место — заморозка снимается только действием
    // встраивателя, а не механизмом предела (теорема `undeny_makes_room` в модели Lean).
    let after = {
        a.undeny(&deny_key(0));
        let ok = a.deny(deny_key(MAX_DENYLIST));
        (a.denylist_len(), ok)
    };
    eprintln!("DENY_G6b: g6b_len={} g6b_room={}", after.0, if after.1 { 1 } else { 0 });
    if after != (MAX_DENYLIST, true) {
        bad.push("(6b) не выполнен: отзыв не вернул место".to_string());
    }

    assert!(bad.is_empty(), "гейты не выполнены: {bad:?}");
}

