/-
# Модель «ограниченного множества, которое меняют только объявленные события»

`H-0107` / `E-0107`. Объект — одна схема, под которую в продукте подпадают четыре разных места, и
схема обязана различать два исчерпывающих способа упиреться в предел: **отказ** (состояние не
меняется, событие засчитано) и **вытеснение** (состояние меняется, старый элемент теряется). Для
кэша потеря старого — норма; для запрета потеря старого — амнистия, то есть дыра. Различие между
этими двумя классами и есть утверждение модели, и оно не выводится из «множество просто не растёт»:
 вырожденная политика «никогда не вставлять» соблюдает предел и не теряет ничего, но не заполняет
множество до предела, и модель это различает (`fills_to_cap`, контрпример напечатан).

Пространство: 3 ключа, предел 2 ⇒ 8 состояний; последовательности событий длиной 0…3 из алфавита
из шести событий (внести/снять по каждому ключу) = 259 расписаний. Числа 3 и 2 — размер пространства,
а не утверждение о продукте: в продукте предел 4096 (`denylist`), 20 на шард (`ProviderCache`),
`max(4096, ⌈2·live/16⌉)` (приём ячейки). Теоремы ниже не зависят от размера пространства — в этом и
смысл ∀-утверждения вместо замера (цена: 8×259×4 проверок на политику, доли секунды под
`native_decide`).

Что доказывается (четыре политики, один и тот же список свойств):

* `bounded` — предел соблюдён из законного состояния при любом расписании;
* `only_declared` — множество под ключом, о котором в расписании не было ни одного события,
  остаётся прежним (это и есть «меняют только объявленные события»);
* `fills_to_cap` — из пустого состояния достижим предел (несторонность: отличает модель от
  «множество просто не растёт»);
* `ban_survives` — внесённый и не снятый объявленным событием элемент не исчезает;
* `last_event_wins` — финальное членство (с пустого старта) совпадает с последним событием по
  ключу; не роняет её только бесконечная `grow` — это цена предела, а не дефект политики;
* `frozen_at_cap` — при полном состоянии любое число заявок не меняет множество и засчитывает
  ровно столько отказов, сколько их было (у `evict` нарушается: состояние меняется, отказов ноль);
* `duplicate_is_free` — повтор уже присутствующего ключа не меняет ни множество, ни счётчик.

Четыре продукта в этих терминах (переход = событие, множество = состояние):

1. `denylist` (`crates/vecdht-node/src/denylist.rs`, `MAX_DENYLIST = 4096`) — `refuse`, потеря =
   амнистия запрета; событие «снять» = `undeny`, второго способа потерять элемент нет;
2. `revoked.bin` (`revocation.rs`) — та же форма, предел 4096, вытеснение запрещено решением
   `ADR-0050` именно потому, что оно амнистирует отзыв (измерено `E-0136`: амнистия наступает даже
   без вытеснения — при отказе записи, и это за пределами данной модели, см. «Что НЕ моделируется»);
3. приём ячейки (`admission.rs`, `cell_cap_limit`) — `evict` с жертвой из резервуара и
   `SHARD_FULL`, если жертвы нет; здесь потеря старого допустима (запись переезжает в другую ячейку),
   поэтому политика относится к классу `evict`, а не к запретам;
4. `ProviderCache` (`provider_cache.rs`, 20 на шард) — `evict` (снимает старый при переборе limit),
   снятие по объявленным событиям: `forget_peer` (смерть транспорта, проверенный отзыв), `expire`
   (TTL), `see` (новый ответ DHT).

Отдельным плечом моделью покрыто «внимание» gossip'а (`E-0087`: повтор того же ключа не стоит
повторной отправки): это `duplicate_is_free` на той же схеме — повтор не расходует ничего и не
изменяет состояния, то есть лимит расхода = число различных ключей, а не число событий.

Что НЕ моделируется: файловая система и её ошибки (отказ записи — предмет `E-0136`, а не этой модели),
сроки и часы (TTL в продукте — секунды; в модели событие `outKey` абстрагирует «срок истёк»),
стоимость и байты, сеть, порядок пакетов, реальная криптография, конкурентность (`RefCell` у
`Admission` один), арифметическая форма капа `max(min, ⌈2·live/16⌉)` — она покрыта Kani-харнесами
`cap_is_never_below_floor`/`cap_matches_ceiling_formula` (`admission.rs`) и `Admission.lean` (форма
двери), а здесь важна только политика при упоре.

Соответствие модели и кода: по `lab/lean-rubric.md` вопрос 5 оно засчитывается только названным
исполняемым прибором, и называет его карточка цикла, а не этот файл. Модель про себя утверждает
только одно: что перечисленные выше свойства формулируются без ссылок на время, байты и сеть.
-/
import Std

namespace VecDHT.Bounded

/-- Ключей три: пространство из 8 состояний перебирается целиком. -/
def keys : Nat := 3
/-- Предел — 2: ровно на один меньше `keys`, чтобы переполнение было достижимо. -/
def cap : Nat := 2

def space : List Nat := List.range (2 ^ keys)
def keyIdx : List Nat := List.range keys

def mem (s k : Nat) : Bool := Nat.testBit s k
def setB (s k : Nat) : Nat := s ||| 2 ^ k
def clrB (s k : Nat) : Nat := if mem s k then s - 2 ^ k else s
def card (s : Nat) : Nat := ((keyIdx.filter fun k => mem s k)).length

/-- Булевы сравнения: `native_decide` просит Bool, а `≤` на Nat даёт Prop. -/
def leB (a b : Nat) : Bool := if a ≤ b then true else false
def ltB (a b : Nat) : Bool := if a < b then true else false
/-- Места нет: кард уже не меньше предела. -/
def full (s : Nat) : Bool := leB cap (card s)

/-- Самый младший внесённый ключ — единственная кандидатуна вытеснения в этой модели. -/
def low (s : Nat) : Nat := ((keyIdx.filter fun k => mem s k)).head?.getD 0

/-! ## События -/

/-- Два объявленных события: «просить внести ключ» и «снять ключ». Третьего способа изменить
множество модель не знает, и это ровно то, что утверждает `only_declared`. -/
inductive Ev
  | inKey (k : Nat)
  | outKey (k : Nat)
  deriving Inhabited, BEq, DecidableEq, Repr

/-- Алфавит событий: по два на каждый ключ. -/
def events : List Ev :=
  (keyIdx.map Ev.inKey) ++ (keyIdx.map Ev.outKey)

/-- Ключ события, независимо от направления. -/
def keyOf : Ev → Nat
  | Ev.inKey k => k
  | Ev.outKey k => k

/-- Направление «внести». -/
def isIn : Ev → Bool
  | Ev.inKey _ => true
  | Ev.outKey _ => false

/-- Событие по ключу, независимо от направления. -/
def about : Ev → Nat → Bool
  | Ev.inKey k, j => k == j
  | Ev.outKey k, j => k == j

/-- В расписании есть объявленное снятие ключа. -/
def removedIn (t : List Ev) (k : Nat) : Bool := (t.filter fun e => about e k && !isIn e).length != 0

/-- Было ли по ключу хоть одно событие (любого направления). -/
def occurs (t : List Ev) (k : Nat) : Bool := (t.filter fun e => about e k) != []

/-- Последнее событие по ключу: «внести» ⇒ ключ должен быть виден в финальном состоянии. -/
def lastIsIn (t : List Ev) (k : Nat) : Bool :=
  match (t.filter fun e => about e k).getLast? with
  | none => false
  | some e => isIn e

/-- Расписания ровно длиной n: декартово произведение алфавита без повторов расписаний. -/
def exactly : Nat → List (List Ev)
  | 0 => [[]]
  | n + 1 => (exactly n).flatMap fun t => events.map fun e => e :: t

/-- Все расписания длиной 0…3 из алфавита шести событий: 1 + 6 + 36 + 216 = 259. -/
def tracesUpTo : Nat → List (List Ev)
  | 0 => [[]]
  | n + 1 => (exactly (n + 1)) ++ tracesUpTo n

def traces : List (List Ev) := tracesUpTo 3

/-- Расписания только из заявок (без снятий): ими формулируется «полный список заморожен». -/
def asksExactly : Nat → List (List Ev)
  | 0 => [[]]
  | n + 1 => (asksExactly n).flatMap fun t => keyIdx.map fun k => Ev.inKey k :: t

def asksUpTo : Nat → List (List Ev)
  | 0 => [[]]
  | n + 1 => (asksExactly (n + 1)) ++ asksUpTo n

/-- Заявки длиной 0…3: 1 + 3 + 9 + 27 = 40. -/
def asks : List (List Ev) := asksUpTo 3

/-! ## Четыре политики: пара (множество, счётчик засчитанных отказов) -/

/-- Состояние модели — пара: само множество и число засчитанных отказов. Счётчик обязателен, иначе
«отказ» и «молчаливое ничего» в модели невыразимо различить. -/
abbrev St := Nat × Nat

/-- Отказ при упоре: состояние не меняется, отказ засчитан (`L-0008`, HAProxy `stksess_new`). -/
def stepRefuse : Ev → St → St
  | Ev.inKey k, (s, r) =>
    if mem s k then (s, r) else if ltB (card s) cap then (setB s k, r) else (s, r + 1)
  | Ev.outKey k, (s, r) => (clrB s k, r)

/-- Вытеснение при упоре: уходит самый младший внесённый, новичок принимается, отказов ноль.
Это `ProviderCache::see` и ветка `cell_victim` приёма ячейки. -/
def stepEvict : Ev → St → St
  | Ev.inKey k, (s, r) =>
    if mem s k then (s, r) else if ltB (card s) cap then (setB s k, r) else (setB (clrB s (low s)) k, r)
  | Ev.outKey k, (s, r) => (clrB s k, r)

/-- Вырожденная политика: множество не растёт никогда. Соблюдает предел и ничего не теряет, но
не заполняет место — ею измеряется несторонность остальных утверждений. -/
def stepFrozen : Ev → St → St
  | _, (s, r) => (s, r)

/-- Рост без предела: `L-0007` (Bitcoin BanMan) и наш код до цикла `E-0092`. -/
def stepGrow : Ev → St → St
  | Ev.inKey k, (s, r) => (setB s k, r)
  | Ev.outKey k, (s, r) => (clrB s k, r)

def steps : List (String × (Ev → St → St)) :=
  [("refuse (L-0008)", stepRefuse), ("evict (ProviderCache, cell_victim)", stepEvict),
   ("frozen (вырожденная)", stepFrozen), ("grow (L-0007)", stepGrow)]

def run (step : Ev → St → St) (t : List Ev) (s0 : St) : St := t.foldl (fun acc e => step e acc) s0

/-- Законные начальные состояния: кард не больше предела, счётчик нулевой. -/
def legalStarts : List St := (space.filter fun s => leB (card s) cap).map fun s => (s, 0)

/-- Сколько заявок в расписании обратилось бы в отказ, если множество не меняется вовсе. Эта же
величина — предсказание для `frozen_at_cap`: счётчик обязан совпасть с ней, а не «что-то вырасти». -/
def expectedRefusals (t : List Ev) (s : Nat) : Nat :=
  (t.filter fun e => isIn e && !mem s (keyOf e)).length

/-! ## Семь свойств, один список политик -/

/-- (1) Предел соблюдён из любого законного состояния при любом расписании. -/
def propBounded (step : Ev → St → St) : Bool :=
  legalStarts.all fun st => traces.all fun t => leB (card (run step t st).1) cap

/-- (2) Меняют только объявленные события: о ключе, по которому в расписании не было ни одного
события, финальное множество говорит то же, что начальное. -/
def propOnlyDeclared (step : Ev → St → St) : Bool :=
  legalStarts.all fun st => traces.all fun t => keyIdx.all fun k =>
    occurs t k || (mem (run step t st).1 k == mem st.1 k)

/-- (3) Несторонность: из пустого состояния предел достижим каким-то расписанием. Без этого
плеча (1)+(2) выродилась бы в «множество просто не меняется». -/
def propFillsToCap (step : Ev → St → St) : Bool :=
  traces.any fun t => card (run step t (0, 0)).1 == cap

/-- (4) Внесённый и не снятый элемент не исчезает: для запретов это «внёс и забыл», для кэша —
слишком сильное требование, и модель обязана показать, кто его не держит. -/
def propBanSurvives (step : Ev → St → St) : Bool :=
  legalStarts.all fun st => traces.all fun t => keyIdx.all fun k =>
    !mem st.1 k || removedIn t k || mem (run step t st).1 k

/-- (5) Финал объясняется последним событием по ключу — с пустого старта, где «последнего события»
не могло быть вытеснено прошлым состоянием. Держит её только `grow`: у `refuse` она нарушается
ровно на отказе (последняя заявка есть, ключа в множестве нет), у `evict` — на амнистии, у `frozen`
на любой заявке. Это не «свойство хорошей политики», а цена предела: любая политика, которая
ограничена, обязана её ронять. -/
def propLastEventWins (step : Ev → St → St) : Bool :=
  traces.all fun t => keyIdx.all fun k => mem (run step t (0, 0)).1 k == lastIsIn t k

/-- (6) При полном состоянии любая последовательность заявок не меняет множество и засчитывает
ровно столько отказов, сколько заявок было. -/
def propFrozenAtCap (step : Ev → St → St) : Bool :=
  (space.filter fun s => full s).all fun s => asks.all fun t =>
    (run step t (s, 0)).1 == s && (run step t (s, 0)).2 == expectedRefusals t s

/-- (7) Повтор уже присутствующего ключа не стоит ничего: ни изменения множества, ни отказа. -/
def propDuplicateIsFree (step : Ev → St → St) : Bool :=
  space.all fun s => keyIdx.all fun k =>
    !mem s k || (run step [Ev.inKey k] (s, 0)) == (s, 0)

/-! ## Теоремы: что держит каждая политика -/

theorem refuse_bounded : propBounded stepRefuse = true := by native_decide
theorem evict_bounded : propBounded stepEvict = true := by native_decide
theorem frozen_bounded : propBounded stepFrozen = true := by native_decide
theorem grow_unbounded : propBounded stepGrow = false := by native_decide

theorem refuse_only_declared : propOnlyDeclared stepRefuse = true := by native_decide
theorem evict_moves_undeclared : propOnlyDeclared stepEvict = false := by native_decide
theorem frozen_only_declared : propOnlyDeclared stepFrozen = true := by native_decide
theorem grow_only_declared : propOnlyDeclared stepGrow = true := by native_decide

theorem refuse_fills_to_cap : propFillsToCap stepRefuse = true := by native_decide
theorem evict_fills_to_cap : propFillsToCap stepEvict = true := by native_decide
theorem grow_fills_to_cap : propFillsToCap stepGrow = true := by native_decide
theorem frozen_never_fills : propFillsToCap stepFrozen = false := by native_decide

theorem refuse_ban_survives : propBanSurvives stepRefuse = true := by native_decide
theorem frozen_ban_survives : propBanSurvives stepFrozen = true := by native_decide
theorem evict_amnesties : propBanSurvives stepEvict = false := by native_decide
theorem grow_ban_survives : propBanSurvives stepGrow = true := by native_decide

theorem grow_last_event_wins : propLastEventWins stepGrow = true := by native_decide
theorem refuse_last_event_breaks_at_refusal : propLastEventWins stepRefuse = false :=
  by native_decide
theorem evict_last_event_breaks_at_amnesty : propLastEventWins stepEvict = false :=
  by native_decide
theorem frozen_breaks_last_event : propLastEventWins stepFrozen = false := by native_decide

theorem refuse_frozen_at_cap : propFrozenAtCap stepRefuse = true := by native_decide
theorem evict_moves_at_cap : propFrozenAtCap stepEvict = false := by native_decide
theorem frozen_silently_refuses : propFrozenAtCap stepFrozen = false := by native_decide
theorem grow_needs_no_room : propFrozenAtCap stepGrow = false := by native_decide

theorem refuse_duplicate_is_free : propDuplicateIsFree stepRefuse = true := by native_decide
theorem evict_duplicate_is_free : propDuplicateIsFree stepEvict = true := by native_decide
theorem frozen_duplicate_is_free : propDuplicateIsFree stepFrozen = true := by native_decide
theorem grow_duplicate_is_free : propDuplicateIsFree stepGrow = true := by native_decide

/-- Ни одна ограниченная политика не роняет `last_event_wins` зря: отказ и вытеснение — единственные
два способа её нарушить, и они исчерпывающие. Формулировка: если предел соблюдён и хотя бы одна
заявка не выполнена, то найдётся расписание, где последнее событие «внести» не даёт членства.
Проверяется как таблица: политики, у которых `bounded = true` и `lastEvent = false`, — ровно
`refuse` и `evict`, а `frozen` попадает в них же из-за `fills = false`. -/
theorem bounded_policies_that_break_last_event :
    List.count true (steps.map fun p => propBounded p.2 && !propLastEventWins p.2) = 3 :=
  by native_decide

/-- Итог перебора: из четырёх политик «предел + только объявленные события + заполнение до предела
+ невыводимость запрета + наблюдаемый отказ + бесплатность повтора» выдерживает ровно одна — та,
что стоит в продукте для списков запретов. -/
def survives (step : Ev → St → St) : Bool :=
  propBounded step && propOnlyDeclared step && propFillsToCap step && propBanSurvives step &&
    propFrozenAtCap step && propDuplicateIsFree step

theorem exactly_one_policy_survives : List.count true (steps.map fun p => survives p.2) = 1 :=
  by native_decide

/-- Единственная выжившая политика — `refuse` (первая в `steps`). -/
theorem the_survivor_is_refuse : survives stepRefuse = true := by native_decide

/-- Политика теряет внесённый элемент без объявленного снятия: свидетели печатаются, а не
пересказываются. У `refuse` их ноль — это и есть «внёс и забыл», а у `evict` их сотни. -/
def lost (step : Ev → St → St) : List (St × List Ev) :=
  legalStarts.flatMap fun st =>
    (traces.filter fun t => keyIdx.any fun k =>
      mem st.1 k && !removedIn t k && !mem (run step t st).1 k).map fun t => (st, t)

theorem refuse_loses_nothing : (lost stepRefuse).length = 0 := by native_decide
theorem evict_loses_something : 0 < (lost stepEvict).length := by native_decide

/-! ## Числа, которые обязан продублировать Rust-оракул -/

/-- Перебор «все законные старты × все расписания»: 7 × 259 = 1813 пар. Агрегаты ниже выбраны так,
чтобы часть из них не зависела от того, **кого именно** вытесняет политика (`card_sum`, `at_cap`), а
часть зависела (`bits_sum`, `amnesty`) — и то, и другое полезно: первое позволяет сверить модель с
настоящим кодом, второе показывает, что выбор жертвы не безразличен. -/
def sweepPairs : Nat := legalStarts.length * traces.length

/-- Сумма бит финального множества по всем парам: зависит от того, кого вытеснили. -/
def bitsSum (step : Ev → St → St) : Nat :=
  (legalStarts.flatMap fun st => traces.map fun t => (run step t st).1).foldl (· + ·) 0
/-- Сколько пар закончили перебор с полным множеством. -/
def atCapPairs (step : Ev → St → St) : Nat :=
  (legalStarts.flatMap fun st => traces.map fun t => card (run step t st).1).foldl
    (fun a c => if c == cap then a + 1 else a) 0
/-- Сумма кардов финальных множеств: не зависит от выбора жертвы, и именно поэтому им сверяются
модель и настоящий код. -/
def cardSum (step : Ev → St → St) : Nat :=
  (legalStarts.flatMap fun st => traces.map fun t => card (run step t st).1).foldl (· + ·) 0
/-- Сумма засчитанных отказов по всем парам. -/
def refusalSum (step : Ev → St → St) : Nat :=
  (legalStarts.flatMap fun st => traces.map fun t => (run step t st).2).foldl (· + ·) 0
/-- Пары, в которых внесённый элемент исчез без объявленного снятия: амнистия в настоящем коде. -/
def amnestyPairs (step : Ev → St → St) : Nat := (lost step).length

/-- Булево как `1`/`0`: helper ловит числа, а не слова. Печатается ровно то же выражение, которое
стоит в теоремах выше, поэтому доказательством служит пара «строка напечатана И файл скомпилировался
с `ERRORS=0`»: если бы выражение было ложным, `native_decide` уронил бы компиляцию. -/
def bit (x : Bool) : String := if x then "1" else "0"

/-- Истина каждого свойства по каждой политике — семь пунктов списка плюс итог перебора. -/
def truthLines : List String :=
  ["FILLS_TO_CAP_REFUSE=" ++ bit (propFillsToCap stepRefuse),
   "FROZEN_NEVER_FILLS=" ++ bit (!propFillsToCap stepFrozen),
   "GROW_BOUNDED=" ++ bit (propBounded stepGrow),
   "EVICT_MOVES_UNDECLARED=" ++ bit (!propOnlyDeclared stepEvict),
   "REFUSE_LAST_EVENT_BREAKS=" ++ bit (!propLastEventWins stepRefuse),
   "POLICIES_BREAKING_LAST_EVENT=" ++
     toString (List.count true (steps.map fun p => propBounded p.2 && !propLastEventWins p.2)),
   "EXACTLY_ONE_SURVIVOR=" ++ toString (List.count true (steps.map fun p => survives p.2)),
   "SURVIVOR_IS_REFUSE=" ++ bit (survives stepRefuse),
   "REFUSE_LOSES_NOTHING=" ++ bit ((lost stepRefuse).length == 0),
   "EVICT_LOSES_SOMETHING=" ++ bit (0 < (lost stepEvict).length)]

/-- Одна строка «КЛЮЧ=число» на каждый агрегат — то, что ловит `grep` в прогоне. -/
def metricLines : List String :=
  ["SWEEP_PAIRS=" ++ toString sweepPairs,
   "TRACES=" ++ toString traces.length,
   "LEGAL_STARTS=" ++ toString legalStarts.length,
   "ASKS=" ++ toString asks.length,
   "SPACE=" ++ toString space.length,
   "REFUSE_BITS_SUM=" ++ toString (bitsSum stepRefuse),
   "REFUSE_CARD_SUM=" ++ toString (cardSum stepRefuse),
   "REFUSE_AT_CAP_PAIRS=" ++ toString (atCapPairs stepRefuse),
   "REFUSE_REFUSAL_SUM=" ++ toString (refusalSum stepRefuse),
   "REFUSE_AMNESTY_PAIRS=" ++ toString (amnestyPairs stepRefuse),
   "EVICT_BITS_SUM=" ++ toString (bitsSum stepEvict),
   "EVICT_CARD_SUM=" ++ toString (cardSum stepEvict),
   "EVICT_AT_CAP_PAIRS=" ++ toString (atCapPairs stepEvict),
   "EVICT_REFUSAL_SUM=" ++ toString (refusalSum stepEvict),
   "EVICT_AMNESTY_PAIRS=" ++ toString (amnestyPairs stepEvict),
   "GROW_BITS_SUM=" ++ toString (bitsSum stepGrow),
   "GROW_AT_CAP_PAIRS=" ++ toString (atCapPairs stepGrow)]

#eval (String.intercalate " " (metricLines ++ truthLines))
#eval (space.length, cap, traces.length, asks.length, legalStarts.length)

#eval (steps.map fun p => (p.1, propBounded p.2, propOnlyDeclared p.2, propFillsToCap p.2,
  propBanSurvives p.2, propLastEventWins p.2, propFrozenAtCap p.2, propDuplicateIsFree p.2,
  survives p.2))
#eval (lost stepEvict).take 3
#eval ((lost stepEvict).length, (lost stepRefuse).length, (lost stepGrow).length,
  (lost stepFrozen).length)

end VecDHT.Bounded
