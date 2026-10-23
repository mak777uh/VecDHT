/-
# Модель лесенки отказов §4.2: девять ступеней, восемь имён

`H-0085` / `E-0085`. Объект моделирован по разведке, а не выбран постфактум: `verify_cert`
(`crates/vecdht-crypto/src/cert.rs:116…144`) — это девять булевых условий с фиксированным
порядком, то есть функция `2^9 → ИмяОтказа ∪ {Ok}`, исчерпываемо проверяемая `native_decide`.
Rust-оракул `crates/vecdht-crypto/tests/s42_cert_ladder.rs` перебирает те же 512 векторов в том
же порядке, так что соответствие проверяется построением: здесь теорема, там те же числа.

Что доказывается:

* (а) тотальность и однозначность: нарушенный вектор всегда получает имя, `Ok` — ровно один
  вектор (нулевой), а имя это `nameOf` первой нарушенной ступени, где «первая» означает «все
  младшие биты чисты»;
* (б) гистограмма видимости `2^(8−k)` (`256, 128, 64, 32, 16, 8, 4, 2, 1`) — О1 как теорема, а
  не как подсчёт в Rust, плюс покрытие: суммы видимостей плюс `Ok` дают всё пространство;
* (в) маскирование отзыва: из 256 векторов с нарушенным условием `Revoked` это имя остаётся
  видимым ровно в 4 (О2), и это ровно `64, 192, 320, 448`, остальные 252 показывают чужое имя —
  то есть порядок ступеней сам по себе прячет факт отзыва;
* (г) сбой отображения «ступень → имя»: девять ступеней дают восемь имён, `rungName 7 = rungName 8`
  при `7 ≠ 8`, поэтому никакой таблицы «одно имя на ступень» не существует, и коллизия ровно одна.

Что НЕ моделируется (и в вывод не идёт): криптография подписей и порог (это `Auth.lean` из
`E-0078`), декадер провода и его четвёртое условие `valid_until ≤ valid_from` (это directed-пробы
оракула, порог (4)), время, сеть, `ProtocolError` и его коды. Временных утверждений в цикле нет,
поэтому правило 8 здесь не «уступка», а точное попадание: объект дискретный.
-/
import Std

namespace VecDHT.CertLadder

/-- Ступеней девять: `Version`, `GenesisMismatch`, `ZeroCapacity`, `Malformed`, `NotYetValid`,
`Expired`, `Revoked`, `sigs > MAX`, порог.-/
def rungs : Nat := 9

/-- Вектор нарушений — число `b < 2^9`; бит `k` означает «ступень `k` нарушена». -/
def vectors : List Nat := List.range 512

/-- Нарушено ли условие `k` в векторе `b`. -/
def broken (b k : Nat) : Bool := Nat.testBit b k

/-- Младшие ступени `0…k−1` чисты: битовая формулировка «`k` — первая нарушенная». -/
def prefixClean (b k : Nat) : Bool := (b &&& ((1 <<< k) - 1)) == 0

/-- Первая нарушенная ступень; `none` — нарушений нет, то есть `Ok`. -/
def firstBroken (b : Nat) : Option Nat := (List.range rungs).find? (broken b)

/-- Имя ступени. Ступени 7 («подписей больше, чем разрешено») и 8 («ниже порога») названы
одинаково — `BelowThreshold`, — и различаются только полем `have` (`cert.rs:140` и `:143`). -/
def nameOf (k : Nat) : Nat := if k ≤ 6 then k else 7

/-- Дверь как чистая функция: вектор нарушений → имя отказа, `none` = принята. -/
def door (b : Nat) : Option Nat := (firstBroken b).map nameOf

/-- Видимость ступени `k`: число векторов, где первой нарушена именно она. -/
def vis (k : Nat) : Nat := (vectors.filter (fun b => firstBroken b == some k)).length

/-! ## (а) Тотальность: нарушенный вектор всегда назван, и назван по первой ступени -/

/-- Ровно один вектор проходит дверь, и это нулевой. -/
theorem only_the_clean_vector_passes : vectors.filter (fun b => door b == none) == [0] := by
  native_decide

/-- Ни один ненулевой вектор не остаётся без имени: отказ либо есть, либо вектор чист. -/
theorem every_dirty_vector_is_refused : vectors.filter (fun b => b != 0 && door b == none) == [] := by
  native_decide

/-- Мост между битовой маской и лесенкой: если ступень `k` нарушена и все младшие чисты, то
`find?` находит именно её. То есть «первая нарушенная» — не название, а свойство порядка. -/
theorem first_broken_is_exactly_the_lowest_violation :
    vectors.filter (fun b =>
      ((List.range rungs).filter (fun k => broken b k && prefixClean b k && firstBroken b != some k))
        != []) == [] := by
  native_decide

/-- И наоборот: если `find?` нашёл `k`, то `k` нарушена и младшие чисты — лишнего имя не
приписывает. -/
theorem first_broken_is_a_real_violation :
    vectors.filter (fun b =>
      ((List.range rungs).filter (fun k =>
          firstBroken b == some k && !(broken b k && prefixClean b k))) != []) == [] := by
  native_decide

/-- Дверь не выдаёт имён вне таблицы: каждое имя, которое она вообще печатает, — это `nameOf`
ступени, а различных таких имён ровно восемь (О1). -/
theorem door_prints_exactly_eight_names :
    ((vectors.filter (fun b => door b != none)).map (fun b => (door b).getD 99)).eraseDups.length = 8 := by
  native_decide

/-! ## (б) Гистограмма видимости -/

/-- Видимость ступени `k` равна `2^(8−k)` векторов: ровно те, где младшие биты `0…k−1` чисты, а
бит `k` выставлен. Отсюда гистограмма О1. -/
theorem visibility_is_two_to_the_eight_minus_k :
    (List.range rungs).all (fun k => vis k == 2 ^ (8 - k)) := by
  native_decide

/-- Та же проверка списком — числа, которые обязан продублировать Rust-оракул. -/
theorem visibility_is_power_of_two : (List.range rungs).map vis ==
    [256, 128, 64, 32, 16, 8, 4, 2, 1] := by
  native_decide

/-- Сумма видимостей плюс `Ok` — всё пространство векторов, то есть лесенка ничего не теряет. -/
theorem visibility_covers_everything : ((List.range rungs).map vis).sum + 1 = vectors.length := by
  native_decide

/-! ## (в) Маскирование отзыва -/

/-- Из 256 векторов с нарушенным отзывом имя `Revoked` доживает до оператора ровно в 4: шесть
предыдущих ступеней стоят раньше. Комментарий `cert.rs:107…108` («проверка идёт до подписи»)
правдив лишь против двух последних ступеней — это и есть то, что теорема делает числом. -/
theorem revoked_is_visible_in_four :
    (vectors.filter (fun b => broken b 6 && door b == some 6)).length == 4 := by
  native_decide

/-- И те четыре — это векторы, где нарушен только отзыв (64) и произвольные две последние
ступени: `64, 192, 320, 448`. -/
theorem revoked_vectors_are_these :
    vectors.filter (fun b => broken b 6 && door b == some 6) == [64, 192, 320, 448] := by
  native_decide

/-- Остальные 252 показывают чужое имя: маска — не редкость, а правило. -/
theorem revoked_is_masked_in_the_rest :
    (vectors.filter (fun b => broken b 6 && door b != some 6)).length == 252 := by
  native_decide

/-- Число векторов с нарушенным отзывом — 256, то есть доля маскирования `252/256`. -/
theorem revoked_rows_are_half_the_space : (vectors.filter (fun b => broken b 6)).length == 256 := by
  native_decide

/-! ## (г) Отображение «ступень → имя» необратимо -/

/-- Различных имён у девяти ступеней — восемь. -/
theorem there_are_eight_names : ((List.range rungs).map nameOf).eraseDups.length = 8 := by
  native_decide

/-- Имя ступени всегда `< 8`: столкновение двух последних ступеней — единственное, и других
значений лесенка не выдаёт. -/
theorem nameOf_lt_8 (k : Fin 9) : nameOf k.val < 8 := by
  unfold nameOf
  split <;> omega

/-- Отображение ступеней в имена как функция между конечными множествами. -/
def rungName : Fin 9 → Fin 8 := fun k => ⟨nameOf k.val, nameOf_lt_8 k⟩

/-- Две разные ступени называются одинаково… -/
theorem rungs_seven_and_eight_share_a_name : rungName (7 : Fin 9) = rungName (8 : Fin 9) := by
  native_decide

/-- …и поэтому никакой таблицы «одно имя на ступень» не существует: функция ступеней в имена не
инъективна. Это утверждение о структуре двери, а не о её скорости. -/
theorem no_rung_from_name_table : ¬ Function.Injective rungName := by
  intro h
  have h78 : (7 : Fin 9) = (8 : Fin 9) := h rungs_seven_and_eight_share_a_name
  exact absurd h78 (by decide)

/-- Всего упорядоченных пар «разные ступени, одно имя» — две: `(7,8)` и `(8,7)`. -/
theorem there_are_exactly_two_same_name_pairs :
    (((List.range rungs).map (fun i =>
        (List.range rungs).filter (fun j => nameOf i == nameOf j && i != j))).flatten).length == 2 := by
  native_decide

/-- Прямая формулировка того же: у ступени 7 единственный одноимённый партнёр — 8, у 8 — 7, у
остальных семи ступеней одноимённых нет. -/
theorem collision_pairs_are_exactly_seven_and_eight :
    (List.range rungs).map (fun i => (List.range rungs).filter (fun j => nameOf i == nameOf j && i != j)) ==
      [[], [], [], [], [], [], [], [8], [7]] := by
  native_decide

/- Печать чисел, которые обязан продублировать Rust-оракул: гистограмма видимости, четыре
вектора видимого отзыва, таблица имён, размер пространства. -/
#eval (List.range rungs).map vis
#eval (vectors.filter (fun b => broken b 6 && door b == some 6))
#eval ((List.range rungs).map nameOf).eraseDups
#eval vectors.length

end VecDHT.CertLadder
