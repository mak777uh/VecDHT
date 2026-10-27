//! H-0107 / E-0107: соответствие той же Lean-модели настоящему кэшу провайдеров.
//!
//! Пара к тесту `crates/vecdht-node/tests/s16_lean_bounded_denylist.rs`: модель
//! `lab/lean/VecDHT/Bounded.lean` различает два класса упора в предел — отказ и вытеснение
//! — и утверждает, что «амнистия» (внесённый элемент исчез без объявленного снятия) свойственна
//! ровно классу вытеснения. `ProviderCache` — именно он: при переборе `per_shard_max` снимается
//! старая запись, и это норма, а не дыра.
//!
//! Пространство то же: 7 законных стартов × 259 расписаний, предел 2, три пира. Сверяются только
//! агрегаты, **не зависящие от того, кого именно вытеснили** (`card_sum`, `at_cap`, отсутствие
//! отказов): настоящий кэш снимает запись с древнейшей датой подтверждения, модель — минимальный
//! индекс, и это разные жертвы. Агрегаты, которые от жертвы зависят (`bits_sum`, число пар с
//! амнистией), печатаются расхождением по обе стороны — молчать о них тест не вправе.
//!
//! Второе расхождение тоже измерено, а не замолчано: у настоящего `forget_peer` снятие открывает
//! окно недоверия (`skipped_dead`), то есть событие «снять» — не чистое удаление. Модель знает
//! чистое удаление, поэтому прогон идёт двумя вариантами часов: `+1` секунды на шаг (окно живо) и
//! `+ttl` (окно всегда истекло — ровно то, что абстрагирует модель).

use std::collections::BTreeSet;

use libp2p::PeerId;
use vecdht_crypto::Identity;
use vecdht_net::keys::peer_id;
use vecdht_net::provider_cache::ProviderCache;

const KEYS: usize = 3;
const CAP: usize = 2;
const MAX_TRACE_LEN: usize = 3;
const SHARD: u16 = 7;
const TTL: u64 = 420;

/// Агрегаты политики `evict`, напечатанные моделью (`metricLines`).
const LEAN_EVICT_BITS_SUM: usize = 5687;
const LEAN_EVICT_CARD_SUM: usize = 2331;
const LEAN_EVICT_AT_CAP: usize = 777;
const LEAN_EVICT_AMNESTY: usize = 189;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ev {
    In(usize),
    Out(usize),
}

fn peer(i: usize) -> PeerId {
    let mut seed = [0u8; 32];
    seed[0] = 210;
    seed[31] = i as u8 + 1;
    peer_id(&Identity::from_seed(seed))
}

fn events() -> Vec<Ev> {
    let mut v: Vec<Ev> = (0..KEYS).map(Ev::In).collect();
    v.extend((0..KEYS).map(Ev::Out));
    v
}

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

#[derive(Default, Debug)]
struct Agg {
    pairs: usize,
    bits_sum: usize,
    card_sum: usize,
    at_cap: usize,
    over_cap: usize,
    amnesty: usize,
    skipped_sum: u64,
    evicted_sum: u64,
}

/// Один прогон перебора: `step_secs` — сколько часов проходит между событиями.
fn sweep(step_secs: u64) -> Agg {
    let tr = traces();
    let mut agg = Agg::default();
    for start in 0..(1usize << KEYS) {
        if (0..KEYS).filter(|k| (start >> k) & 1 == 1).count() > CAP {
            continue;
        }
        for t in &tr {
            let mut c = ProviderCache::new(CAP, TTL);
            let mut now = 1_000u64;
            for k in 0..KEYS {
                if (start >> k) & 1 == 1 {
                    c.see(SHARD, [peer(k)], now);
                    now += step_secs;
                }
            }
            for e in t {
                match *e {
                    Ev::In(k) => {
                        let r = c.see(SHARD, [peer(k)], now);
                        agg.skipped_sum += r.skipped_dead as u64;
                        agg.evicted_sum += r.evicted as u64;
                    }
                    Ev::Out(k) => {
                        c.forget_peer(&peer(k), now);
                    }
                }
                now += step_secs;
            }
            let live: BTreeSet<usize> = (0..KEYS).filter(|k| c.peers(SHARD).contains(&peer(*k))).collect();
            let bits = live.iter().fold(0usize, |a, k| a | (1 << k));
            let n = live.len();
            agg.pairs += 1;
            agg.bits_sum += bits;
            agg.card_sum += n;
            if n == CAP {
                agg.at_cap += 1;
            }
            if n > CAP {
                agg.over_cap += 1;
            }
            let lost = (0..KEYS).any(|k| {
                (start >> k) & 1 == 1
                    && !t.iter().any(|e| matches!(e, Ev::Out(j) if *j == k))
                    && !live.contains(&k)
            });
            if lost {
                agg.amnesty += 1;
            }
        }
    }
    agg
}

#[test]
fn evict_class_matches_the_size_aggregates_and_amnesties() {
    let clean = sweep(TTL); // модель: снятие = чистое удаление
    let live = sweep(1); // продукт: снятие открывает окно недоверия

    println!("BOUNDED_CACHE_TRACES={}", traces().len());
    println!("BOUNDED_CACHE_MODEL_PAIRS=1813");
    println!("BOUNDED_CACHE_REAL_PAIRS={}", clean.pairs);
    println!("BOUNDED_CACHE_MODEL_CARDS={LEAN_EVICT_CARD_SUM}");
    println!("BOUNDED_CACHE_REAL_CARDS={}", clean.card_sum);
    println!("BOUNDED_CACHE_MODEL_ATCAP={LEAN_EVICT_AT_CAP}");
    println!("BOUNDED_CACHE_REAL_ATCAP={}", clean.at_cap);
    println!("BOUNDED_CACHE_MODEL_BITS={LEAN_EVICT_BITS_SUM}");
    println!("BOUNDED_CACHE_REAL_BITS={}", clean.bits_sum);
    println!("BOUNDED_CACHE_MODEL_AMNESTY={LEAN_EVICT_AMNESTY}");
    println!("BOUNDED_CACHE_REAL_AMNESTY={}", clean.amnesty);
    println!("BOUNDED_CACHE_OVER_CAP={}", clean.over_cap);
    println!("BOUNDED_CACHE_DISTRUST_WINDOW_PAIRS={}", live.pairs);
    println!("BOUNDED_CACHE_DISTRUST_CARDS={}", live.card_sum);
    println!("BOUNDED_CACHE_DISTRUST_SKIPPED_SUM={}", live.skipped_sum);
    println!("BOUNDED_CACHE_EVICTED_SUM={}", clean.evicted_sum);

    let size_agrees = clean.pairs == 1813
        && clean.card_sum == LEAN_EVICT_CARD_SUM
        && clean.at_cap == LEAN_EVICT_AT_CAP
        && clean.over_cap == 0;
    println!("BOUNDED_CACHE_SIZE_AGREE={}", if size_agrees { 1 } else { 0 });
    println!(
        "BOUNDED_CACHE_VICTIM_DELTA={}",
        clean.bits_sum as i64 - LEAN_EVICT_BITS_SUM as i64
    );
    println!(
        "BOUNDED_CACHE_AMNESTY_DELTA={}",
        clean.amnesty as i64 - LEAN_EVICT_AMNESTY as i64
    );

    let mut problems: Vec<String> = Vec::new();
    if !size_agrees {
        problems.push(format!(
            "размерные агрегаты кода ({} пар, сумма кардов {}, пар с полным {} , сверх предела {}) не совпали с моделью (1813, {LEAN_EVICT_CARD_SUM}, {LEAN_EVICT_AT_CAP}, 0)",
            clean.pairs, clean.card_sum, clean.at_cap, clean.over_cap
        ));
    }
    if clean.amnesty == 0 {
        problems.push("амнистии не найдено ни в одной паре: настоящий кэш ведёт себя не как класс вытеснения".to_string());
    }
    if live.card_sum >= clean.card_sum {
        problems.push(format!(
            "окно недоверия не подорожало: кардов {} против {} — признак того, что `skipped_dead` не срабатывает",
            live.card_sum, clean.card_sum
        ));
    }
    if !problems.is_empty() {
        panic!("PROBLEMS={:?}", problems);
    }
}
