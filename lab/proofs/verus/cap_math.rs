#![allow(dead_code)]
//! Прототип прибора `E-0099`: контракт арифметики капа ячейки.
//! Транскрипция `crates/vecdht-node/src/admission.rs::cell_cap_limit` один в один, чтобы Verus
//! говорил про ту же формулу, что исполняет продукт.

use vstd::prelude::*;
use vstd::arithmetic::div_mod::*;

verus! {

pub const CELL_CAP_NUM: u64 = 2;
pub const CLUSTERS_PER_SHARD: u64 = 16;
pub const CELL_CAP_MIN: u64 = 4_096;

/// Граница, при которой `CELL_CAP_NUM * live` и `+ (per − 1)` не переполняют `u64`. Продукт её не
/// объявляет (только комментает «при m ≤ 1e9»), и ровно это контракт делает явным.
pub const MAX_LIVE_NO_OVERFLOW: u64 = (0xFFFF_FFFF_FFFF_FFFEu64 - 15) / CELL_CAP_NUM;

/// Математическая форма предела ячейки `⌈c·m/n⌉`, взятая максимумом с полом.
pub open spec fn cap_spec(live: int, min: int) -> int {
    let rel = (live * 2 + 15) / 16;
    if rel > min { rel } else { min }
}

pub open spec fn rel_spec(live: int) -> int {
    (live * 2 + 15) / 16
}

/// Пол связан всегда: пустой шард обязывает ячейку хранить `min` записей.
pub proof fn cap_spec_floor(live: int, min: int)
    requires 0 <= live
    ensures cap_spec(live, min) >= min
{
}

/// Монотонность по загрузке: кап не уменьшается при росте живых записей.
pub proof fn cap_spec_monotone(l1: int, l2: int, min: int)
    requires 0 <= l1 <= l2
    ensures cap_spec(l1, min) <= cap_spec(l2, min)
{
    reveal(rel_spec);
    reveal(cap_spec);
}

/// Форма `⌈c·m/n⌉` никогда не ниже точного деления: кап не требует меньше, чем средняя загрузка.
pub proof fn cap_spec_ge_exact(live: int, min: int)
    requires 0 <= live
    ensures cap_spec(live, min) >= (live * 2) / 16
{
    reveal(rel_spec);
}

/// Мост «модель ↔ код»: тело продукта равно математической форме при объявленной границе, и оно
/// не переполняет `u64` ровно в той области, которую требует контракт.
pub fn cell_cap_limit(live_in_shard: u64, min: u64) -> (cap: u64)
    requires
        live_in_shard <= MAX_LIVE_NO_OVERFLOW,
    ensures
        cap >= min,
        cap as int == cap_spec(live_in_shard as int, min as int),
{
    let per = CLUSTERS_PER_SHARD;
    ((CELL_CAP_NUM * live_in_shard).saturating_add(per - 1) / per).max(min)
}

} // verus!

fn main() {}
