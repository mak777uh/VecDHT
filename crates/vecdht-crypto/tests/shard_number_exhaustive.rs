//! Оракул `E-0035` (`H-0035`): полный перебор `u16` для `clusters_of_shard`. `E-0034` снял десять
//! номеров и вывел из них «внедиапазонный номер молча отображается в законный список», но
//! подтверждение было выборочным (пять masked-точек и две паники). Здесь то же утверждение
//! проверяется перебором по всему входу: 65 536 значений, каждый либо даёт список, либо панику.
//!
//! Пороги зафиксированы в `lab/hypotheses/H-0035-shard-number-exhaustive.md` ДО прогона.

use std::panic::{self, AssertUnwindSafe};
use std::time::Instant;

use vecdht_crypto::quant::clusters_of_shard;
use vecdht_wire::constants::{CLUSTERS_PER_SHARD, SHARDS};

/// Без паники и с тем же списком, что у шарда `shard % SHARDS`.
fn list_of(shard: u16) -> Option<Vec<u16>> {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let r = panic::catch_unwind(AssertUnwindSafe(|| clusters_of_shard(shard)));
    panic::set_hook(hook);
    r.ok()
}

#[test]
fn every_u16_shard_number_is_either_a_masked_legal_list_or_a_panic() {
    let t0 = Instant::now();

    // (1) нижнее множество: 0..=4094 — паники нет, и список равен законному списку s % SHARDS.
    let mut mismatches: Vec<String> = Vec::new();
    let mut unexpected_panic: Vec<u16> = Vec::new();
    let mut outputs: Vec<Vec<u16>> = Vec::new();
    let mut first_panic: Option<u16> = None;
    let mut last_ok: Option<u16> = None;

    for s in 0u32..=4094 {
        let s = s as u16;
        match list_of(s) {
            None => unexpected_panic.push(s),
            Some(list) => {
                last_ok = Some(s);
                if list != clusters_of_shard(s % SHARDS) {
                    mismatches.push(format!("{s}≠{}", s % SHARDS));
                }
                if list.len() != usize::from(CLUSTERS_PER_SHARD) {
                    mismatches.push(format!("{s}: длина {} ≠ 16", list.len()));
                }
                if !outputs.iter().any(|o| o == &list) {
                    outputs.push(list);
                }
            }
        }
    }

    // (2) верхнее множество: 4095..=65535 — обязано паниковать (переполнение u16 в debug).
    let mut no_panic: Vec<u16> = Vec::new();
    for s in 4095u32..=u32::from(u16::MAX) {
        let s = s as u16;
        match list_of(s) {
            Some(_) => no_panic.push(s),
            None => {
                if first_panic.is_none() {
                    first_panic = Some(s);
                }
            }
        }
    }

    eprintln!(
        "## перебор 0..=4094: без паники {}, несоответствий маски {}, неожиданных паник {}, \
         различных выходов {} ##",
        4095_usize.saturating_sub(unexpected_panic.len()),
        mismatches.len(),
        unexpected_panic.len(),
        outputs.len()
    );
    eprintln!(
        "## перебор 4095..=65535: паник нет у {} значений (первые {:?}); первая паника зафиксирована \
         на {:?}; последний законный список — на {:?} ##",
        no_panic.len(),
        no_panic.iter().copied().take(4).collect::<Vec<_>>(),
        first_panic,
        last_ok
    );
    if !mismatches.is_empty() {
        eprintln!("## первые несоответствия: {:?} ##", &mismatches[..mismatches.len().min(6)]);
    }
    eprintln!("## время перебора {:.1} с ##", t0.elapsed().as_secs_f64());

    // Порог (1).
    assert!(unexpected_panic.is_empty(), "паника внутри 0..=4094: {unexpected_panic:?}");
    assert!(mismatches.is_empty(), "маска s % SHARDS не совпала: {mismatches:?}");
    // Порог (2).
    assert!(
        no_panic.is_empty(),
        "номера ≥ 4095 вернули список вместо паники: {:?} (всего {})",
        no_panic.iter().copied().take(8).collect::<Vec<_>>(),
        no_panic.len()
    );
    assert_eq!(first_panic, Some(4095), "первая паника не на 4095");
    assert_eq!(last_ok, Some(4094), "последний живой номер не 4094");
    // Порог (3): множество выходов ровно 64 — ничего, кроме законных списков, не производится.
    assert_eq!(
        outputs.len(),
        usize::from(SHARDS),
        "перебор 0..=4094 породил не 64 различных списка"
    );
}
