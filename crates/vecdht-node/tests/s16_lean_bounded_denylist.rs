//! H-0107 / E-0107: соответствие Lean-модели ограниченного множества настоящему коду.
//!
//! Модель — `lab/lean/VecDHT/Bounded.lean`. Она перебирает 7 законных стартовых множеств ×
//! 259 расписаний событий (внести/снять по каждому из трёх ключей, длина 0…3) для четырёх
//! политик и печатает агрегаты перебора строкой `SWEEP_PAIRS=… REFUSE_BITS_SUM=…`.
//!
//! Здесь та же пространство проходится **настоящим кодом**: `Admission::deny` /
//! `Admission::undeny` с `with_denylist_limit(2)` — политикой «отказ при упоре», которую модель
//! выбирает единственной выжившей. Числа в константах ниже — не ожидание автора теста, а снимок
//! вывода модели; карточка цикла сверяет их с `lake env lean` отдельно, чтобы устаревшая
//! константа была красной строкой, а не тихим расхождением.
//!
//! Что это доказывает и чего не доказывает (`lab/lean-rubric.md`, вопрос 5):
//!
//! * совпадение агрегатов = соответствие модели и кода **на этом пространстве** для класса
//!   «отказ» — названным исполняемым прибором, а не рассуждением;
//! * персистентность здесь выключена (`denylist_dir = None`): отказ записи на диск — предмет
//!   `E-0094` и `E-0136`, а не этого теста;
//! * предел 2 вместо продуктовых 4096 — форма перебора: теоремы модели не зависят от размера
//!   пространства, и тест проверяет ровно то же утверждение на том же пространстве.
//!
//! Факты печатаются по одному ключу на число, и ни один из них не зависит от часов или от
//! расписания шагов (правило 7, пункт (е)): вектор обязан совпасть в двух прогонах подряд.

use vecdht_node::{testing, Admission};

const POW: u32 = 8;
const KEYS: usize = 3;
const CAP: usize = 2;
const MAX_TRACE_LEN: usize = 3;

/// Агрегаты, напечатанные моделью `lab/lean/VecDHT/Bounded.lean` (`metricLines`).
const LEAN_SWEEP_PAIRS: usize = 1813;
const LEAN_REFUSE_BITS_SUM: usize = 5439;
const LEAN_REFUSE_CARD_SUM: usize = 2331;
const LEAN_REFUSE_AT_CAP: usize = 777;
const LEAN_REFUSE_REFUSAL_SUM: usize = 363;
const LEAN_REFUSE_AMNESTY: usize = 0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ev {
    In(usize),
    Out(usize),
}

fn key(i: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 199;
    k[24..].copy_from_slice(&(i as u64 + 1).to_le_bytes());
    k
}

fn events() -> Vec<Ev> {
    let mut v: Vec<Ev> = (0..KEYS).map(Ev::In).collect();
    v.extend((0..KEYS).map(Ev::Out));
    v
}

/// Расписания длиной 0…`MAX_TRACE_LEN`: 1 + 6 + 36 + 216 = 259, то же множество, что у модели
/// (`exactly`/`tracesUpTo`). Порядок слагаемых для сумм и счётчиков не важен.
fn traces() -> Vec<Vec<Ev>> {
    let mut exact: Vec<Vec<Ev>> = vec![vec![]];
    let mut all: Vec<Vec<Ev>> = vec![vec![]];
    for _ in 1..=MAX_TRACE_LEN {
        let mut next: Vec<Vec<Ev>> = Vec::new();
        for t in &exact {
            for e in events() {
                let mut v = vec![e];
                v.extend(t.iter().copied());
                next.push(v);
            }
        }
        all.extend(next.iter().cloned());
        exact = next;
    }
    all
}

fn card(bits: usize) -> usize {
    (0..KEYS).filter(|k| (bits >> k) & 1 == 1).count()
}

/// Состояние настоящего admission'а как битовая маска тех же трёх ключей.
fn bits_of(a: &Admission) -> usize {
    (0..KEYS)
        .filter(|k| a.is_denied(&key(*k)))
        .fold(0usize, |acc, k| acc | (1 << k))
}

#[derive(Default, Debug)]
struct Aggregates {
    pairs: usize,
    bits_sum: usize,
    card_sum: usize,
    at_cap: usize,
    refusal_sum: u64,
    amnesty: usize,
    bound_violations: usize,
}

/// Перебор «все законные старты × все расписания» на настоящем коде.
fn sweep() -> Aggregates {
    let params = testing::params(POW);
    let tr = traces();
    let mut agg = Aggregates::default();
    for start in 0..(1usize << KEYS) {
        if card(start) > CAP {
            continue; // незаконный старт: переполнение — следствие, а не вход политики
        }
        for t in &tr {
            let mut a = Admission::new(&params).with_denylist_limit(CAP);
            for k in 0..KEYS {
                if (start >> k) & 1 == 1 {
                    a.deny(key(k));
                }
            }
            assert_eq!(a.stats.denylist_refused_at_bound, 0, "легальный старт не обязан отказывать");
            for e in t {
                match *e {
                    Ev::In(k) => {
                        a.deny(key(k));
                    }
                    Ev::Out(k) => {
                        a.undeny(&key(k));
                    }
                }
            }
            let fin = bits_of(&a);
            agg.pairs += 1;
            agg.bits_sum += fin;
            agg.card_sum += card(fin);
            if card(fin) == CAP {
                agg.at_cap += 1;
            }
            if card(fin) > CAP {
                agg.bound_violations += 1;
            }
            agg.refusal_sum += a.stats.denylist_refused_at_bound;
            let lost = (0..KEYS).any(|k| {
                (start >> k) & 1 == 1
                    && !t.iter().any(|e| matches!(e, Ev::Out(j) if *j == k))
                    && (fin >> k) & 1 != 1
            });
            if lost {
                agg.amnesty += 1;
            }
        }
    }
    agg
}

#[test]
fn denylist_class_matches_the_lean_model() {
    let tr = traces();
    let legal_starts = (0..(1usize << KEYS)).filter(|s| card(*s) <= CAP).count();
    let agg = sweep();

    println!("BOUNDED_DENY_TRACES={}", tr.len());
    println!("BOUNDED_DENY_LEGAL_STARTS={legal_starts}");
    println!("BOUNDED_DENY_MODEL_PAIRS={LEAN_SWEEP_PAIRS}");
    println!("BOUNDED_DENY_REAL_PAIRS={}", agg.pairs);
    println!("BOUNDED_DENY_MODEL_BITS={LEAN_REFUSE_BITS_SUM}");
    println!("BOUNDED_DENY_REAL_BITS={}", agg.bits_sum);
    println!("BOUNDED_DENY_MODEL_CARDS={LEAN_REFUSE_CARD_SUM}");
    println!("BOUNDED_DENY_REAL_CARDS={}", agg.card_sum);
    println!("BOUNDED_DENY_MODEL_ATCAP={LEAN_REFUSE_AT_CAP}");
    println!("BOUNDED_DENY_REAL_ATCAP={}", agg.at_cap);
    println!("BOUNDED_DENY_MODEL_REFUSALS={LEAN_REFUSE_REFUSAL_SUM}");
    println!("BOUNDED_DENY_REAL_REFUSALS={}", agg.refusal_sum);
    println!("BOUNDED_DENY_MODEL_AMNESTY={LEAN_REFUSE_AMNESTY}");
    println!("BOUNDED_DENY_REAL_AMNESTY={}", agg.amnesty);
    println!("BOUNDED_DENY_BOUND_VIOLATIONS={}", agg.bound_violations);

    let agree = agg.pairs == LEAN_SWEEP_PAIRS
        && agg.bits_sum == LEAN_REFUSE_BITS_SUM
        && agg.card_sum == LEAN_REFUSE_CARD_SUM
        && agg.at_cap == LEAN_REFUSE_AT_CAP
        && agg.refusal_sum as usize == LEAN_REFUSE_REFUSAL_SUM
        && agg.amnesty == LEAN_REFUSE_AMNESTY;
    println!("BOUNDED_DENY_AGREE={}", if agree { 1 } else { 0 });

    let mut problems: Vec<String> = Vec::new();
    if tr.len() != 259 {
        problems.push(format!("расписаний {}, а модель перебирает 259", tr.len()));
    }
    if legal_starts != 7 {
        problems.push(format!("законных стартов {}, а не 7", legal_starts));
    }
    if agg.bound_violations != 0 {
        problems.push(format!(
            "предел нарушен в {} парах: настоящий deny() впускает сверх лимита",
            agg.bound_violations
        ));
    }
    if !agree {
        problems.push(format!(
            "агрегаты кода ({}, {}, {}, {}, {}, {}) не совпали с агрегатами модели ({}, {}, {}, {}, {}, {})",
            agg.pairs, agg.bits_sum, agg.card_sum, agg.at_cap, agg.refusal_sum, agg.amnesty,
            LEAN_SWEEP_PAIRS, LEAN_REFUSE_BITS_SUM, LEAN_REFUSE_CARD_SUM, LEAN_REFUSE_AT_CAP,
            LEAN_REFUSE_REFUSAL_SUM, LEAN_REFUSE_AMNESTY
        ));
    }
    if !problems.is_empty() {
        panic!("PROBLEMS={:?}", problems);
    }
}
