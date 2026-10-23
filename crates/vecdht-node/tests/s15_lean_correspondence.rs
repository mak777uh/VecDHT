//! H-0078 / E-0078: соответствие Lean-модели дверей §15/§9.2 настоящему коду.
//!
//! Модель — `lab/lean/VecDHT/Auth.lean` (Lean 4, только core+Std, без Mathlib). Она
//! транскрибирует `AuthoritySet::count_valid`, `Chain::check_indices`,
//! `Chain::check_authorities` и `Chain::check_members` и формулирует инвариант спеки
//! §9.2 (строка 969 зеркала): «индекс в `sigs` — позиция подписанта в наборе epoch−1
//! (для genesis — порядок ключей в `authorities` артефакта)».
//!
//! Здесь — две половины пробы:
//!
//! * **соответствие**: числа, измеренные моделью, должны совпасть с числами
//!   настоящего кода на том же ограниченном пространстве;
//! * **базовая линия**: то же пространство перебирается в Rust с настоящими
//!   Ed25519-подписями, то есть перебор (сильнее выборки) делает и обычный
//!   тест — сравнение честное.
//!
//! Пространство (как в пре-регистрации `H-0078`):
//! * набор ключей — все упорядоченные списки различных ключей из {0..4} длиной 1..5
//!   (325 штук);
//! * список подписей — все списки длиной 0, 1 или 2 из алфавита 25 элементов
//!   (индекс 0..4 × подписавший 0..4) — 651 штука;
//! * второй срез — списки длиной ровно три (15 625 штук) при эталонном наборе ключей.
//!
//! Подписи настоящие: `Identity::sign_domain` и `verify_domain` из `vecdht-crypto`.
//! Таблица «ключ × подписавший» вычисляется один раз (25 настоящих проверок) и
//! переиспользуется: подпись авторитета проверяется под своим ключом, и это
//! утверждение тест проверяет отдельно — если бы подпись проходила под чужим
//! ключом, абстракция модели была бы неверна и тест упал бы.
//!
//! Цена настоящей проверки подписи в debug-сборке — около 7,8 мс на проверку
//! (замерено: 300 проверок за 2,34 с), поэтому полный перебор с настоящей криптографией
//! стоит минуты. Отсюда и устройство теста: перебор идёт по таблице, а настоящие
//! функции сверяются с таблицей на выборке.

use vecdht_crypto::cert::CertError;
use vecdht_crypto::verify_domain;
use vecdht_node::{testing, Chain};
use vecdht_wire::messages::{domain, MembershipUpdate};

const SHARD: u16 = 7;
const POW: u32 = 8;
const SEEDS: [u8; 3] = [1, 2, 3];
/// Авторитетов в эталонном наборе — 5 (3-of-5, §15.2).
const AUTHORITIES: usize = 5;
/// Порог genesis — 3.
const THRESHOLD: usize = 3;

/// Число контрпримеров, измеренное Lean-моделью на том же пространстве.
const LEAN_UP_TO_2: usize = 0;
const LEAN_EXACTLY_3: usize = 3540;

/// Шаг выборки для сверки с настоящими функциями: 15 625 / 781 ≈ 20 случаев.
const SAMPLE_STRIDE: usize = 781;

/// Подписи авторитетов над телом genesis: настоящие Ed25519.
fn authority_signatures(payload: &[u8]) -> Vec<[u8; 64]> {
    testing::authorities()
        .iter()
        .map(|a| a.sign_domain(domain::MEMBER, payload))
        .collect()
}

/// Таблица «ключ × подписавший»: настоящая проверка подписи.
fn verification_table(payload: &[u8]) -> Vec<Vec<bool>> {
    let auth = testing::authority_set();
    let sigs = authority_signatures(payload);
    (0..AUTHORITIES)
        .map(|k| {
            (0..AUTHORITIES)
                .map(|s| verify_domain(&auth.keys[k], domain::MEMBER, payload, &sigs[s]))
                .collect()
        })
        .collect()
}

/// Тело genesis: настоящий `MembershipUpdate`, дальше меняется только список подписей.
fn genesis_body() -> MembershipUpdate {
    testing::genesis_update(SHARD, &SEEDS, 0)
}

/// `Chain::check_indices` по исходнику: индекс в диапазоне и индексы попарно различны.
fn check_indices(sigs: &[(usize, usize)], len: usize) -> bool {
    let mut idx: Vec<usize> = sigs.iter().map(|(i, _)| *i).collect();
    idx.sort_unstable();
    idx.dedup();
    sigs.iter().all(|(i, _)| *i < len) && idx.len() == sigs.len()
}

/// `AuthoritySet::count_valid`: число разных ключей набора, под которыми есть хоть
/// одна подпись. Таблица здесь не нужна — нужно лишь то, что подпись проверяется
/// под своим ключом (проверено тестом выше).
fn count_valid(keys: &[usize], sigs: &[(usize, usize)]) -> usize {
    let mut signers: Vec<usize> = sigs.iter().map(|(_, s)| *s).collect();
    signers.sort_unstable();
    signers.dedup();
    signers.into_iter().filter(|s| keys.contains(s)).count()
}

/// Число подписей, привязанных к своему индексу.
fn bound_count(table: &[Vec<bool>], keys: &[usize], sigs: &[(usize, usize)]) -> usize {
    sigs.iter()
        .filter(|(idx, signer)| {
            keys.get(*idx)
                .map(|k| table[*k][*signer])
                .unwrap_or(false)
        })
        .count()
}

/// Контрпример: текущая дверь приняла, дверь по индексу — нет.
fn is_counterexample(table: &[Vec<bool>], keys: &[usize], sigs: &[(usize, usize)]) -> bool {
    check_indices(sigs, keys.len())
        && count_valid(keys, sigs) >= THRESHOLD
        && bound_count(table, keys, sigs) < THRESHOLD
}

/// Все списки длины ровно `n` над алфавитом.
fn combos<T: Clone>(alphabet: &[T], n: usize) -> Vec<Vec<T>> {
    if n == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for a in alphabet {
        for mut rest in combos(alphabet, n - 1) {
            rest.insert(0, a.clone());
            out.push(rest);
        }
    }
    out
}

/// Все упорядоченные списки различных ключей из {0..4} длиной 1..5.
fn key_lists() -> Vec<Vec<usize>> {
    let keys: Vec<usize> = (0..AUTHORITIES).collect();
    let mut out = Vec::new();
    for n in 1..=AUTHORITIES {
        for l in combos(&keys, n) {
            let mut sorted = l.clone();
            sorted.sort_unstable();
            sorted.dedup();
            if sorted.len() == l.len() {
                out.push(l);
            }
        }
    }
    out
}

/// Алфавит подписей: (заявленный индекс, подписавший).
fn alphabet() -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..AUTHORITIES {
        for s in 0..AUTHORITIES {
            out.push((i, s));
        }
    }
    out
}

/// Настоящие подписи для списка пар (индекс, подписавший).
fn real_sigs(sigs: &[(usize, usize)], all: &[[u8; 64]]) -> Vec<(u8, [u8; 64])> {
    sigs.iter()
        .map(|(i, s)| (*i as u8, all[*s]))
        .collect()
}

/// (0) Абстракция модели держится: подпись авторитета проходит под своим ключом и
/// только под ним. Если это перестало быть так, модель `verify k s ↔ s.signer = k`
/// больше не описывает код, и все числа ниже meaningless.
#[test]
fn a_signature_verifies_only_under_its_own_key() {
    let payload = genesis_body().unsigned_body();
    let table = verification_table(&payload);
    for (k, row) in table.iter().enumerate() {
        for (s, ok) in row.iter().enumerate() {
            assert_eq!(
                *ok,
                k == s,
                "подпись авторитета {s} прошла под ключом {k}"
            );
        }
    }
}

/// (1) Свидетель из Lean: подписи авторов 0,1,2 под заявленными индексами 2,3,4.
/// Настоящий код ведёт себя ровно как модель: порог взят (3 разных ключа), но ни
/// одна подпись не привязана к своему индексу, и настоящая genesis-дверь принимает.
#[test]
fn the_lean_witness_is_reproduced_by_the_real_code() {
    let body = genesis_body();
    let payload = body.unsigned_body();
    let table = verification_table(&payload);

    let witness: Vec<(usize, usize)> = vec![(2, 0), (3, 1), (4, 2)];
    assert_eq!(count_valid(&[0, 1, 2, 3, 4], &witness), 3);
    assert_eq!(bound_count(&table, &[0, 1, 2, 3, 4], &witness), 0);

    // Настоящая функция `AuthoritySet::count_valid` даёт тот же счёт.
    let auth = testing::authority_set();
    let all = authority_signatures(&payload);
    let real = real_sigs(&witness, &all);
    let list: Vec<[u8; 64]> = real.iter().map(|(_, s)| *s).collect();
    assert_eq!(
        auth.count_valid(&payload, domain::MEMBER, &list),
        3,
        "настоящий count_valid на свидетеле"
    );

    // Настоящая genesis-дверь принимает такой genesis.
    let mut upd = body.clone();
    upd.sigs = real;
    let chain = testing::chain(SHARD, POW);
    let m = chain
        .validate(None, &upd)
        .expect("настоящая дверь принимает genesis с чужими индексами");
    assert_eq!(m.epoch(), 1);
    assert_eq!(m.len(), 3);
}

/// (2) Счётчики контрпримеров совпадают с Lean-моделью на том же пространстве.
#[test]
fn the_counterexample_counters_match_the_lean_model() {
    let payload = genesis_body().unsigned_body();
    let table = verification_table(&payload);

    // Срез «подписей не более двух»: порог не набирается, контрпримеров нет.
    let kl = key_lists();
    let alpha = alphabet();
    let mut up_to_2: Vec<Vec<(usize, usize)>> = vec![Vec::new()];
    up_to_2.extend(combos(&alpha, 1));
    up_to_2.extend(combos(&alpha, 2));
    assert_eq!(kl.len(), 325, "наборов ключей");
    assert_eq!(up_to_2.len(), 651, "списков подписей длиной до двух");

    let mut count_a = 0usize;
    for keys in &kl {
        for sigs in &up_to_2 {
            if is_counterexample(&table, keys, sigs) {
                count_a += 1;
            }
        }
    }
    assert_eq!(count_a, LEAN_UP_TO_2, "счётчик «подписей не более двух»");

    // Срез «подписей ровно три» при эталонном наборе ключей.
    let exactly_3 = combos(&alpha, 3);
    assert_eq!(exactly_3.len(), 15_625, "списков подписей длиной три");
    let full: Vec<usize> = (0..AUTHORITIES).collect();
    let count_b = exactly_3
        .iter()
        .filter(|sigs| is_counterexample(&table, &full, sigs))
        .count();
    assert_eq!(count_b, LEAN_EXACTLY_3, "счётчик «подписей ровно три»");
}

/// (3) Настоящие функции совпадают с таблицей, а настоящая дверь — с моделью.
/// Без этого счётчики выше были бы числами реимплементации, а не кода.
#[test]
fn the_real_functions_agree_with_the_enumeration() {
    let body = genesis_body();
    let payload = body.unsigned_body();
    let auth = testing::authority_set();
    let chain = testing::chain(SHARD, POW);
    let all = authority_signatures(&payload);
    let alpha = alphabet();
    let exactly_3 = combos(&alpha, 3);

    let mut checked_functions = 0usize;
    let mut checked_doors = 0usize;
    for (i, sigs) in exactly_3.iter().enumerate() {
        if i % SAMPLE_STRIDE != 0 {
            continue;
        }
        let real = real_sigs(sigs, &all);
        let list: Vec<[u8; 64]> = real.iter().map(|(_, s)| *s).collect();
        assert_eq!(
            auth.count_valid(&payload, domain::MEMBER, &list),
            count_valid(&[0, 1, 2, 3, 4], sigs),
            "настоящий count_valid разошёлся с таблицей на {sigs:?}"
        );
        checked_functions += 1;

        let mut upd = body.clone();
        upd.sigs = real;
        let model_accepts = check_indices(sigs, AUTHORITIES)
            && count_valid(&[0, 1, 2, 3, 4], sigs) >= THRESHOLD;
        let door_accepts = chain.validate(None, &upd).is_ok();
        assert_eq!(
            door_accepts, model_accepts,
            "настоящая дверь разошлась с моделью на {sigs:?}"
        );
        checked_doors += 1;
    }
    assert!(checked_functions >= 20, "проверок функций: {checked_functions}");
    assert_eq!(checked_functions, checked_doors, "проверок дверей: {checked_doors}");
}

/// (4) Буквальная ∀-форма пре-регистрации («приняла ⇒ привязаны все подписи») на настоящем
/// коде **ложна** — и модель это подтверждает отдельно, для счётной политики: считается число
/// привязанных подписей, а лишняя непривязанная дверь не блокирует.
#[test]
fn an_unbound_extra_signature_does_not_block_the_door() {
    let body = genesis_body();
    let payload = body.unsigned_body();
    let table = verification_table(&payload);
    let all = authority_signatures(&payload);
    let full: Vec<usize> = (0..AUTHORITIES).collect();

    // Подписи 0,1,2 — под своими индексами; четвёртая — копия подписи 0, заявленная
    // под индексом 3.
    let sigs: Vec<(usize, usize)> = vec![(0, 0), (1, 1), (2, 2), (3, 0)];
    assert_eq!(count_valid(&full, &sigs), 3, "разных подписавших — трое");
    assert_eq!(bound_count(&table, &full, &sigs), 3, "привязанных к своему индексу — трое");
    let unbound = sigs
        .iter()
        .filter(|(i, s)| !table[full[*i]][*s])
        .count();
    assert_eq!(unbound, 1, "непривязанных подписей — ровно одна");

    // Настоящая дверь принимает такой набор: `have = 3 ≥ threshold = 3`.
    let mut upd = body.clone();
    upd.sigs = real_sigs(&sigs, &all);
    let chain = testing::chain(SHARD, POW);
    let m = chain
        .validate(None, &upd)
        .expect("дверь приняла genesis с лишней непривязанной подписью");
    assert_eq!(m.epoch(), 1);
    assert_eq!(m.len(), 3);

    // …а настоящая `count_valid` видит три ключа, не четыре: переупаковка квоту не набивает.
    let auth = testing::authority_set();
    let list: Vec<[u8; 64]> = upd.sigs.iter().map(|(_, s)| *s).collect();
    assert_eq!(auth.count_valid(&payload, domain::MEMBER, &list), 3);
}

/// (5) Два источника порога: расхождение представимо в настоящем коде. Тот же набор из двух
/// подписей genesis проходит (дверь смотрит в `Params.authority_threshold`) и не проходит
/// дверь NodeCert (та смотрит в `AuthoritySet.threshold`).
#[test]
fn two_threshold_sources_diverge_on_real_keys() {
    let body = genesis_body();
    let payload = body.unsigned_body();
    let all = authority_signatures(&payload);

    let sigs: Vec<(usize, usize)> = vec![(0, 0), (1, 1)];
    let real = real_sigs(&sigs, &all);
    let list: Vec<[u8; 64]> = real.iter().map(|(_, s)| *s).collect();

    let auth = testing::authority_set();
    assert_eq!(auth.threshold, 3, "порог набора — 3-of-5");
    assert_eq!(
        auth.check(&payload, domain::MEMBER, &list),
        Err(CertError::BelowThreshold { have: 2, need: 3 }),
        "дверь NodeCert по `AuthoritySet.threshold` двух подписей не принимает"
    );

    let mut weak = testing::params(POW);
    assert_eq!(weak.authority_threshold, 3, "штатный порог из манифеста — 3");
    weak.authority_threshold = 2;
    let mut upd = body.clone();
    upd.sigs = real;
    let chain2 = Chain {
        shard: SHARD,
        params: weak,
        authorities: auth.clone(),
    };
    let m = chain2
        .validate(None, &upd)
        .expect("genesis по `Params.authority_threshold = 2` принят — та же пара подписей");
    assert_eq!(m.epoch(), 1);
    assert_eq!(m.len(), 3);
}
