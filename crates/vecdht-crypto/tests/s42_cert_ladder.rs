//! H-0085 / E-0085 · оракул 1/2: лесенка отказов §4.2 как полный предикат.
//!
//! Снимается то, чего не снимал ни один предыдущий цикл по этой двери: **имена** отказов, а не
//! их непропуск неверного. `fuzz_verify.rs:299…332` доказывает, что неверный кредашиал не
//! проходит; здесь меряется, *что именно* возвращает дверь и в каком порядке.
//!
//! Три факта, ради которых написан этот файл (разведка `lab/hypotheses/H-0085-*.md`):
//!
//! * ступеней у `verify_cert` девять (`crates/vecdht-crypto/src/cert.rs:116…144`), а различных
//!   имён — восемь: ступени «слишком много подписей» и «ниже порога» дают один и тот же вариант
//!   `BelowThreshold` и различаются только полем `have`;
//! * видимость ступени равна `2^(9−k)`, поэтому `Revoked` остаётся видимым ровно в 4 строках из
//!   256 строк с нарушенным отзывом: шесть предыдущих ступеней его маскируют, хотя комментарий
//!   `cert.rs:107…108` обещает «проверка идёт до подписи»;
//! * три ступени недостижимы через провод — `NodeCert::decode` отказывает раньше, а у самого
//!   декадера есть четвёртое условие (`valid_until <= valid_from`), которого в лесенке нет.
//!
//! Юнит-гейтов по времени тут нет: предикат чистый, имена детерминированы, поэтому таблицы
//! сверяются по blake3-свертке между профилями и между прогонами (пороги (10)/(11)).

use std::collections::BTreeSet;

use vecdht_crypto::cert::{
    sign_cert_identity, verify_cert, AuthoritySet, CertError, MAX_AUTHORITY_SIGS,
};
use vecdht_crypto::Identity;
use vecdht_wire::cert::{NodeCert, CERT_VERSION, MAX_CERT_SHARDS};
use vecdht_wire::codec::DecodeError;
use vecdht_wire::messages::Role;

const NOW: u32 = 1_500;
const GENESIS: [u8; 32] = [1u8; 32];
/// Порог эталонной сети: 3 из 5 (§15.2). Тот же набор ключей, что `testing::AUTHORITY_SEEDS`,
/// но собранный локально: этот крейт не зависит от `vecdht-node`, и тащить помощники другого
/// крейта ради пяти идентификаторов не зачем.
const AUTHORITY_SEEDS: [u8; 5] = [1, 2, 3, 4, 5];
const THRESHOLD: usize = 3;

fn net() -> (AuthoritySet, Vec<Identity>) {
    let ids: Vec<Identity> =
        AUTHORITY_SEEDS.iter().map(|&s| Identity::from_seed([s; 32])).collect();
    let keys = ids.iter().map(|i| i.pubkey()).collect();
    (AuthoritySet::new(keys, THRESHOLD), ids)
}

/// Нарушено ли условие `k` (нумерация ступеней лесенки с нуля).
fn bad(bits: usize, k: usize) -> bool {
    bits & (1 << k) != 0
}

/// Кредашиал под произвольный вектор из девяти нарушений. Порядок сборки важен: подписи
/// считаются поверх уже выставленных полей, иначе «нарушение» ступени 1 меняло бы тело и
/// роняло порог — две причины вместо одной.
fn cert_for(bits: usize, ids: &[Identity]) -> (NodeCert, bool) {
    let mut c = NodeCert {
        version: if bad(bits, 0) { CERT_VERSION + 1 } else { CERT_VERSION },
        genesis_hash: if bad(bits, 1) { [9u8; 32] } else { GENESIS },
        role: Role::IndexNode,
        owner_ed25519: [3u8; 32],
        dht_peer_id: vec![0x00, 0x24, 0x00],
        // Нарушение ступени 4 = «список длиннее договора»; значения шардов остаются
        // корректными, чтобы не добавить в строку второе нарушение (BadEnum на проводе).
        shards: if bad(bits, 3) {
            (0..=(MAX_CERT_SHARDS as u16)).collect()
        } else {
            vec![0, 1]
        },
        capacity_entries: if bad(bits, 2) { 0 } else { 1_000 },
        valid_from: if bad(bits, 4) { NOW + 1_000 } else { 1_000 },
        valid_until: if bad(bits, 5) { NOW } else { NOW + 2_000 },
        nonce: [7u8; 16],
        authority_sigs: Vec::new(),
    };
    let valid = if bad(bits, 8) { THRESHOLD - 1 } else { THRESHOLD };
    for id in ids.iter().take(valid) {
        c = sign_cert_identity(&c, id);
    }
    if bad(bits, 7) {
        while c.authority_sigs.len() <= MAX_AUTHORITY_SIGS {
            c.authority_sigs.push([0xeeu8; 64]);
        }
    }
    (c, bad(bits, 6))
}

/// Имя отказа — ровно то, что увидит оператор в логе (`{:?}` того же варианта).
fn name(e: &CertError) -> &'static str {
    match e {
        CertError::Version(_) => "Version",
        CertError::GenesisMismatch { .. } => "GenesisMismatch",
        CertError::BelowThreshold { .. } => "BelowThreshold",
        CertError::NotYetValid { .. } => "NotYetValid",
        CertError::Expired { .. } => "Expired",
        CertError::Revoked => "Revoked",
        CertError::ShardNotCovered(_) => "ShardNotCovered",
        CertError::WrongRole(_) => "WrongRole",
        CertError::ZeroCapacity => "ZeroCapacity",
        CertError::Malformed => "Malformed",
    }
}

/// Поле `have` у `BelowThreshold`: единственное, чем различаются ступени 8 и 9.
fn have(e: &CertError) -> Option<usize> {
    match e {
        CertError::BelowThreshold { have, .. } => Some(*have),
        _ => None,
    }
}

fn decode_name(e: &DecodeError) -> &'static str {
    match e {
        DecodeError::Version(_) => "decode:Version",
        DecodeError::FieldTooLong(_) => "decode:FieldTooLong",
        DecodeError::BadEnum { .. } => "decode:BadEnum",
        DecodeError::Truncated { .. } => "decode:Truncated",
        DecodeError::TrailingBytes { .. } => "decode:TrailingBytes",
        DecodeError::DuplicateTag { .. } => "decode:DuplicateTag",
        DecodeError::TagOrder { .. } => "decode:TagOrder",
        DecodeError::ReservedFlags(_) => "decode:ReservedFlags",
        DecodeError::SigMissing => "decode:SigMissing",
        DecodeError::SigLength(_) => "decode:SigLength",
        DecodeError::BodyTooLarge { .. } => "decode:BodyTooLarge",
        DecodeError::OutOfOrder { .. } => "decode:OutOfOrder",
    }
}

/// Ожидаемое имя по первой нарушенной ступени: `Ok` только когда вектор нулевой.
fn expected_rung(bits: usize) -> usize {
    if bits == 0 {
        9
    } else {
        (bits.trailing_zeros() as usize).min(8)
    }
}

fn direct(c: &NodeCert, set: &AuthoritySet, revoked: bool) -> String {
    match verify_cert(c, set, &GENESIS, NOW, |_| revoked) {
        Ok(()) => "Ok".to_string(),
        Err(e) => match have(&e) {
            Some(h) => format!("{}(have={h})", name(&e)),
            None => name(&e).to_string(),
        },
    }
}

/// Тот же кредашиал, но после провода: `encode → decode → verify_cert`.
fn through_wire(c: &NodeCert, set: &AuthoritySet, revoked: bool) -> String {
    match NodeCert::decode(&c.encode()) {
        Err(e) => decode_name(&e).to_string(),
        Ok(d) => direct(&d, set, revoked),
    }
}

/// (О1)…(О3), пороги (2)…(4). Полная таблица 512 строк печатается и сворачивается в blake3.
#[test]
fn ladder_is_a_total_function_with_eight_names_and_a_power_of_two_histogram() {
    let (set, ids) = net();
    let mut table = String::new();
    let mut names = BTreeSet::new();
    let mut vis = [0usize; 10];
    let mut revoked_rows = 0usize;
    let mut revoked_visible = 0usize;
    for bits in 0..512usize {
        let (c, revoked) = cert_for(bits, &ids);
        let got = direct(&c, &set, revoked);
        // (О1) считает **имена отказа**: строка `Ok` — не отказ, её в таблице ровно одна, и она
        // учтена отдельно (`ladder_ok`). До пре-регистрации набор собирал и `Ok`, из-за чего
        // давал 9 вместо 8 — это была ошибка счётчика, а не девятое имя лесенки.
        if got != "Ok" {
            names.insert(got.split('(').next().unwrap_or(&got).to_string());
        }
        let rung = expected_rung(bits);
        vis[rung] += 1;
        if revoked {
            revoked_rows += 1;
            if got == "Revoked" {
                revoked_visible += 1;
            }
        }
        table.push_str(&format!("{bits:09b} {got}\n"));
        println!("МЕРЕНО ladder_row {bits:09b} {got}");
        assert_eq!(
            got,
            expected_name(rung),
            "(О1) ступень {rung} вернула другое имя на векторе {bits:09b}: {got}"
        );
    }
    let digest = blake3::hash(table.as_bytes()).to_hex().to_string();
    println!("МЕРЕНО ladder_rows=512");
    println!("МЕРЕНО ladder_names={}", names.len());
    let refusal_set: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    println!("МЕРЕНО ladder_refusal_set={}", refusal_set.join("+"));
    for (k, v) in vis.iter().take(9).enumerate() {
        println!("МЕРЕНО ladder_vis_{k}={v}");
    }
    println!("МЕРЕНО ladder_ok={}", vis[9]);
    println!("МЕРЕНО ladder_revoked_rows={revoked_rows}");
    println!("МЕРЕНО ladder_revoked_visible={revoked_visible}");
    println!("МЕРЕНО ladder_digest={digest}");

    assert_eq!(names.len(), 8, "(О1) различных имён должно быть восемь, а не девять");
    for (k, v) in vis.iter().take(9).enumerate() {
        assert_eq!(*v, 1usize << (8 - k), "(О1) видимость ступени {k} (нумерация с нуля) не 2^(8−k)");
    }
    assert_eq!(vis[9], 1, "(О1) комбинация без нарушений ровно одна");
    assert_eq!(revoked_rows, 256, "(О2) строк с нарушенным отзывом");
    assert_eq!(revoked_visible, 4, "(О2) `Revoked` видим должен быть в 4 строках из 256");
    println!("МЕРЕНО gate2=1");
    println!("МЕРЕНО gate3=1");
}

/// Имя, обязанное вернуться при первой нарушенной ступени. Ступени 8 и 9 различаются полем
/// `have`, но не именем — это и есть «девять ступеней, восемь имён».
fn expected_name(rung: usize) -> String {
    match rung {
        0 => "Version".to_string(),
        1 => "GenesisMismatch".to_string(),
        2 => "ZeroCapacity".to_string(),
        3 => "Malformed".to_string(),
        4 => "NotYetValid".to_string(),
        5 => "Expired".to_string(),
        6 => "Revoked".to_string(),
        7 => "BelowThreshold(have=0)".to_string(),
        8 => "BelowThreshold(have=2)".to_string(),
        _ => "Ok".to_string(),
    }
}

/// (О3), порог (4): три ступени лесенки не доживают до неё по проводам, а у декадера есть
/// четвёртое условие, которого в лесенке нет.
#[test]
fn three_ladder_rungs_are_unreachable_through_the_wire_and_the_wire_adds_a_fourth() {
    let (set, ids) = net();
    let mut diverged = 0usize;
    for rung in [0usize, 3, 7] {
        let (c, _) = cert_for(1 << rung, &ids);
        let d = direct(&c, &set, false);
        let w = through_wire(&c, &set, false);
        println!("МЕРЕНО probe_rung_{rung}_direct={d} probe_rung_{rung}_wire={w}");
        if d != w {
            diverged += 1;
        }
    }
    // Четвёртая: `valid_from > valid_until` — нарушение, которого у лесенки нет как ступени,
    // но которое декадер считает своим условием (vecdht-wire/src/cert.rs:110…112).
    let (mut c, _) = cert_for(0, &ids);
    c.valid_from = NOW + 1_000;
    c.valid_until = NOW;
    let d = direct(&c, &set, false);
    let w = through_wire(&c, &set, false);
    println!("МЕРЕНО probe_rung_9_direct={d} probe_rung_9_wire={w}");
    if d != w {
        diverged += 1;
    }

    // Контроль: корректный кредашиал проходит оба входа одинаково.
    let (ok, _) = cert_for(0, &ids);
    let control_direct = direct(&ok, &set, false);
    let control_wire = through_wire(&ok, &set, false);
    println!("МЕРЕНО probe_control_direct={control_direct} probe_control_wire={control_wire}");
    assert_eq!(control_direct, "Ok", "(О3) контроль прямого вызова");
    assert_eq!(control_wire, "Ok", "(О3) контроль провода");

    println!("МЕРЕНО gate4_probes={diverged} gate4_control=1");
    assert_eq!(diverged, 4, "(О3) расходиться обязаны ровно четыре пробы");
    assert_eq!(expected_name(9), "Ok", "(О3) внутренняя непротиворечивость таблицы имён");
}

/// (О6), порог (7): нулевая ёмкость — ступень 3, то есть отказ до проверки порога и до срока.
#[test]
fn zero_capacity_is_refused_before_the_threshold_signed_and_unsigned() {
    let (set, ids) = net();
    let (unsigned, _) = cert_for(1 << 2, &ids);
    assert!(unsigned.authority_sigs.is_empty() || unsigned.authority_sigs.len() >= THRESHOLD);
    let mut bare = unsigned.clone();
    bare.authority_sigs.clear();
    let a = direct(&bare, &set, false);
    let b = direct(&unsigned, &set, false);
    println!("МЕРЕНО zero_capacity_unsigned={a} zero_capacity_signed={b}");
    assert_eq!(a, "ZeroCapacity", "(О6) неподписанный пустой по ёмкости отвергнут по ёмкости");
    assert_eq!(b, "ZeroCapacity", "(О6) подписанный пустой по ёмкости отвергнут по ёмкости");

    // Порядок: та же нулевая ёмкость за маской чужого genesis — ступень 2 раньше ступени 3.
    let (masked, _) = cert_for((1 << 1) | (1 << 2), &ids);
    assert_eq!(direct(&masked, &set, false), "GenesisMismatch", "(О6) ступень 2 раньше ступени 3");
    // И наоборот: просроченный с нулевой ёмкостью всё ещё показывает ёмкость, а не срок.
    let (revoked_but_hidden, _) = cert_for((1 << 2) | (1 << 6), &ids);
    assert_eq!(direct(&revoked_but_hidden, &set, true), "ZeroCapacity");
    println!("МЕРЕНО gate7=1");
}

/// (О1)-в: две ступени — одно имя. Без этого пунктаLean-теорема (г) выглядит выдуманной.
#[test]
fn two_rungs_share_one_name_and_differ_only_in_have() {
    let (set, ids) = net();
    let (many, _) = cert_for(1 << 7, &ids);
    let (few, _) = cert_for(1 << 8, &ids);
    let e_many = verify_cert(&many, &set, &GENESIS, NOW, |_| false)
        .expect_err("(О1)-в ступень 8 обязана отказать");
    let e_few = verify_cert(&few, &set, &GENESIS, NOW, |_| false)
        .expect_err("(О1)-в ступень 9 обязана отказать");
    println!(
        "МЕРЕНО collapse_names_same={} collapse_have={:?} vs {:?}",
        name(&e_many) == name(&e_few),
        have(&e_many),
        have(&e_few)
    );
    assert_eq!(name(&e_many), name(&e_few), "(О1)-в имени ступени 8 и 9 совпадают");
    assert_ne!(have(&e_many), have(&e_few), "(О1)-в поле have обязаны различаться");
}
