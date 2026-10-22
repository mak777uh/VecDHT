//! Оракул `E-0036` (`H-0036`): тот же полный перебор `u16`, что и в `E-0035`, но в `release`-профиле
//! — в том, который реально собирается оператору.
//!
//! `E-0035` снял поведение debug-сборки (overflow-checks по умолчанию включены): `0…4094` дают
//! замаскированный законный список, `4095…65535` паникуют. В `release` арифметика `u16` кольцевая,
//! и предсказание другое: паник нет вообще, а на `base = 65 520` (то есть при `s ≡ 4095 (mod 4096)`)
//! правая граница диапазона `base..base + 16` переполняется в `0`, диапазон пустой, и функция
//! возвращает **пустой список** — третий исход, которого в debug нет и который не является ошибкой.
//!
//! Тест в debug-профиле намеренно ничего не утверждает (перебор debug уже снят в `E-0035`) и печатает
//! строку о пропуске: содержательны только замеры `cargo test --release`. Пороги зафиксированы в
//! `lab/hypotheses/H-0036-shard-number-release.md` ДО прогона.

use std::panic::{self, AssertUnwindSafe};
use std::time::Instant;

use vecdht_crypto::quant::clusters_of_shard;
use vecdht_wire::constants::{CLUSTERS_PER_SHARD, SHARDS};

/// Список, если вызов не запаниковал. Panic-хук заглушается, чтобы перебор не печатал 65 тысяч
/// трейсов.
fn list_of(shard: u16) -> Option<Vec<u16>> {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let r = panic::catch_unwind(AssertUnwindSafe(|| clusters_of_shard(shard)));
    panic::set_hook(hook);
    r.ok()
}

#[test]
fn release_arithmetic_replaces_the_panic_with_an_empty_list() {
    if cfg!(debug_assertions) {
        eprintln!(
            "## пропуск: этот оракул измеряет только release-профиль, в debug поведение снято E-0035 ##"
        );
        return;
    }

    let t0 = Instant::now();
    let mut panics: Vec<u16> = Vec::new();
    let mut empties: Vec<u16> = Vec::new();
    let mut mismatches: Vec<String> = Vec::new();
    let mut outputs: Vec<Vec<u16>> = Vec::new();

    for s in 0..=u32::from(u16::MAX) {
        let s = s as u16;
        match list_of(s) {
            None => panics.push(s),
            Some(list) => {
                if list.is_empty() {
                    empties.push(s);
                } else {
                    if list.len() != usize::from(CLUSTERS_PER_SHARD) {
                        mismatches.push(format!("{s}: длина {} ≠ 16", list.len()));
                    }
                    if list != clusters_of_shard(s % SHARDS) {
                        mismatches.push(format!("{s}≠{}", s % SHARDS));
                    }
                }
                if !outputs.iter().any(|o| o == &list) {
                    outputs.push(list);
                }
            }
        }
    }

    // Ожидаемое множество пустых входов: s = 4095 + 4096·k, k = 0…15.
    let expected_empty: Vec<u16> = (0..16u32).map(|k| (4095 + 4096 * k) as u16).collect();

    eprintln!(
        "## release: паник {}, пустых списков {} (первые {:?}), несоответствий маски {} ##",
        panics.len(),
        empties.len(),
        empties.iter().copied().take(4).collect::<Vec<_>>(),
        mismatches.len()
    );
    eprintln!(
        "## release: различных выходов {}, ожидалось {} ({} законных списка + пустой) ##",
        outputs.len(),
        usize::from(SHARDS) + 1,
        SHARDS
    );
    if !mismatches.is_empty() {
        eprintln!("## первые несоответствия: {:?} ##", mismatches[..mismatches.len().min(6)]);
    }
    eprintln!("## время перебора {:.1} с ##", t0.elapsed().as_secs_f64());

    // Порог (1).
    assert!(panics.is_empty(), "в release нашлась паника: {:?} (первые)", &panics[..panics.len().min(8)]);
    // Порог (2).
    assert_eq!(
        empties, expected_empty,
        "пустые списки не на множестве s ≡ 4095 (mod 4096)"
    );
    // Порог (3).
    assert!(mismatches.is_empty(), "непустые выходы не равны замаскированному законному: {mismatches:?}");
    assert_eq!(
        outputs.len(),
        usize::from(SHARDS) + 1,
        "различных выходов не 65 (64 законных списка + пустой)"
    );
}
