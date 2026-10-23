/-
# Модель denylist'а §11.4 (ii): переживаемость, предел и заморозка

`H-0092` / `E-0092`. Объект — политика локального списка запретов, и она целиком дискретна:
состояние = подмножество ключей, переход = «внести» или «снять», файл = последовательность битов.
Время, байты, пакеты, сеть и реальная криптография в модели отсутствуют, поэтому все утверждения
ниже — ∀-инварианты, а не числа: ровно то, для чего по `lab/lean-rubric.md` Lean применим.

Пространство: 3 ключа ⇒ 8 состояний, предел 2 (в продукте 4096 — число решения ADR, а не теорема;
смысл теорем в том, что они не зависят от размера пространства).

Что доказывается:

* (а) **разведка политики предела.** Четыре кандидата, все из чужого кода: `pRefuse` (`L-0008`,
  HAProxy `stksess_new`: чистить нечего ⇒ отказ вставки), `pGrow` (текущее состояние нашего кода:
  `BTreeSet` без предела; `L-0007` — Bitcoin BanMan — тоже так), `pEvictLowest` и `pEvictHighest`
  (вытеснить что-нибудь уже внесённое). Четыре свойства: предел соблюдён, внесённый запрет не
  исчезает из-за чужого внесения, ничего кроме новичка не появляется, при упоре в предел состояние
  не меняется. Все четыре выдерживает ровно один кандидат, для остальных печатаются контрпримеры;
* (б) **формат файла:** кодирование инъективно, декодирование корректного файла даёт то же
  множество, и — главное — **испорченный или обрезанный файл не превращается в пустой список**:
  `some ∅` достижим ровно из одного файла. Это ровно тот антипаттерн, который `L-0007` выбрал
  осознанно (`m_banned = {}` при нечитаемой базе), а мы отказываемся от него;
* (в) **следствие выбранной политики:** при полном списке множество запретов заморожено по внесению
  — любая последовательность `deny` длиной до 3 состояние не меняет; разморозить его может только
  `undeny`. Оракул этого проверить не может: он конечное число случаев, а не ∀ по последовательностям.

Соответствие продукту: `18 + 32N` байт (гейт (2) оракула) — тот же «заголовок + payload»: два бита
заголовка (магический признан, версия поддержана) и N битов членства. Модель утверждает, что без
заголовка декодер не отличит пустой список от битого файла, — то есть зачем эти 18 байт есть.

Что НЕ моделируется: файловая система и её ошибки, `fsync`, стоимость записи, срок действия записи
(в v1 его нет — `OPEN-QUESTIONS`), реальные 32-байтные ключи (в модели индекс `0…2`), конкурентность
(у `Admission` один `RefCell`), wire и криптография (`Auth.lean`), репликация решений (§11.3 её не
предусматривает).
-/
import Std

namespace VecDHT.Denylist

/-- Ключей три: пространство из 8 состояний перебирается целиком.-/
def keys : Nat := 3
/-- Предел — 2: ровно на один меньше `keys`, чтобы переполнение было достижимо.-/
def cap : Nat := 2

def space : List Nat := List.range (2 ^ keys)
def keyIdx : List Nat := List.range keys

def mem (s k : Nat) : Bool := Nat.testBit s k
def setB (s k : Nat) : Nat := s ||| 2 ^ k
def clrB (s k : Nat) : Nat := if mem s k then s - 2 ^ k else s
def card (s : Nat) : Nat := ((keyIdx.filter fun k => mem s k)).length

/-- Булевы сравнения: `native_decide` просит Bool, а `≤` на Nat даёт Prop.-/
def leB (a b : Nat) : Bool := if a ≤ b then true else false
def ltB (a b : Nat) : Bool := if a < b then true else false
/-- Места нет: кард уже не меньше предела. Работает и для случая «файл переписан сборкой с
бо́льшим пределом» (кард 3 при пределе 2) — оттуда тоже не вставляем.-/
def full (s : Nat) : Bool := leB cap (card s)

/-- Самый младший и самый старший внесённый ключ — кандидаты на вытеснение.-/
def low (s : Nat) : Nat := ((keyIdx.filter fun k => mem s k)).head?.getD 0
def high (s : Nat) : Nat := ((keyIdx.filter fun k => mem s k)).getLast?.getD 0

/-! ## (а) Кандидаты политики при упоре в предел -/

/-- Отказ (`L-0008`): ключ уже запрещён — ничего, места нет — тоже ничего.-/
def pRefuse (s k : Nat) : Nat := if mem s k then s else if ltB (card s) cap then setB s k else s
/-- Рост без предела: теперешний код продукта и `L-0007`.-/
def pGrow (s k : Nat) : Nat := setB s k
/-- Вытеснить самый младший внесённый запрет и вставить новичка.-/
def pEvictLowest (s k : Nat) : Nat :=
  if mem s k then s else if ltB (card s) cap then setB s k else setB (clrB s (low s)) k
/-- То же, но жертва — самый старший внесённый.-/
def pEvictHighest (s k : Nat) : Nat :=
  if mem s k then s else if ltB (card s) cap then setB s k else setB (clrB s (high s)) k

def policies : List (Nat → Nat → Nat) := [pRefuse, pGrow, pEvictLowest, pEvictHighest]
def policyNames : List String :=
  ["refuse (L-0008)", "grow (наш код до цикла, L-0007)", "evictLowest", "evictHighest"]

/-- Предел соблюдён: из законного состояния (кард не больше предела) политика не может попасть в
незаконное. Кванторы по `space` без условия «законно» тут не годятся: надпредельное состояние —
следствие понижения константы, и политика обязана его пережить, а не «улучшить» вытеснением.-/
def legal : List Nat := space.filter fun s => leB (card s) cap
def propBounded (p : Nat → Nat → Nat) : Bool :=
  legal.all fun s => keyIdx.all fun k => leB (card (p s k)) cap

/-- Ни один уже внесённый запрет не исчезает из-за внесения другого ключа.-/
def propKeeps (p : Nat → Nat → Nat) : Bool :=
  space.all fun s => keyIdx.all fun k => keyIdx.all fun j => !mem s j || mem (p s k) j

/-- Кроме новичка в результате ничего нового.-/
def propNoInvention (p : Nat → Nat → Nat) : Bool :=
  space.all fun s => keyIdx.all fun k => keyIdx.all fun j =>
    !mem (p s k) j || j == k || mem s j

/-- При полном списке и неизвестном ключе состояние обязано остаться тем же: отказ, а не замена.-/
def propRefusesAtCap (p : Nat → Nat → Nat) : Bool :=
  space.all fun s => !full s || keyIdx.all fun k => mem s k || p s k == s

def propAll (p : Nat → Nat → Nat) : Bool :=
  propBounded p && propKeeps p && propNoInvention p && propRefusesAtCap p

theorem refuse_is_bounded : propBounded pRefuse = true := by native_decide
theorem refuse_keeps_bans : propKeeps pRefuse = true := by native_decide
theorem refuse_invents_nothing : propNoInvention pRefuse = true := by native_decide
theorem refuse_refuses_at_cap : propRefusesAtCap pRefuse = true := by native_decide

theorem grow_breaks_the_bound : propBounded pGrow = false := by native_decide
theorem evict_lowest_lifts_a_ban : propKeeps pEvictLowest = false := by native_decide
theorem evict_highest_lifts_a_ban : propKeeps pEvictHighest = false := by native_decide
theorem evict_lowest_is_bounded : propBounded pEvictLowest = true := by native_decide
theorem evict_highest_is_bounded : propBounded pEvictHighest = true := by native_decide

/-- Из четырёх кандидатов сочетание «конечность + запрет не снимается самим механизмом предела»
выдерживает ровно один. Выбор политики сделан перебором, а не мнением.-/
theorem exactly_one_survives : List.count true (policies.map propAll) = 1 := by native_decide


-- Печать таблицы кандидатов и первых контрпримеров к отброшенным.
#eval (policyNames.zip (policies.map fun p =>
  (propBounded p, propKeeps p, propNoInvention p, propRefusesAtCap p)))
#eval (legal.flatMap fun s => (keyIdx.filter fun k => ltB cap (card (pGrow s k))).map fun k =>
  (s, k, card s, card (pGrow s k)))
#eval ((space.flatMap fun s => keyIdx.map fun k => (s, k))).filter fun p =>
  keyIdx.any fun j => mem p.1 j && !mem (pEvictLowest p.1 p.2) j

/-! ## (б) Файл: заголовок + payload, и «битый файл ≠ пустой список» -/

/-- Файл = 2 бита заголовка (магический признан, версия поддержана) + N битов членства.-/
def encode (s : Nat) : List Bool := true :: false :: (keyIdx.map fun k => mem s k)

def decode : List Bool → Option Nat
  | [true, false, a, b, c] =>
    some ((if a then 1 else 0) + (if b then 2 else 0) + (if c then 4 else 0))
  | _ => none

/-- Все файлы длиной до 6 бит: сюда попадают обрезанный, с лишними битами, с битым заголовком.-/
def allLists : Nat → List (List Bool)
  | 0 => [[]]
  | n + 1 => ((allLists n).map fun l => false :: l) ++ ((allLists n).map fun l => true :: l)

def files : List (List Bool) :=
  ((List.range 7).flatMap fun n => allLists n).filter fun f => leB f.length 6

theorem decode_inverts_encode : (space.all fun s => (decode (encode s) == some s)) = true :=
  by native_decide

theorem encode_is_injective :
    (space.all fun s => space.all fun t => (encode s == encode t) == (s == t)) = true :=
  by native_decide

/-- Обрезанный файл — ошибка, а не «пустой список».-/
theorem short_file_is_error :
    (files.all fun f => !ltB f.length 5 || (decode f == none)) = true := by native_decide

/-- Центральная теорема цикла: декодер выдаёт пустое множество ровно для одного файла — корректно
записанного пустого списка. Антипаттерн `L-0007` (нечитаемая база ⇒ `m_banned = {}`) в этой модели
невыразим: испорченный файл не даёт «разрешить всех», он даёт отказ открыть узел.-/
theorem corrupt_file_is_never_empty :
    (files.all fun f => (decode f == some 0) == (f == encode 0)) = true := by native_decide

/-- Загрузка сохраняет множество целиком, а если оно уже при пределе или за пределом — ни одно
внесение его не меняет. Это и есть «снижение константы предела не снимает ни одного запрета».-/
theorem load_never_evicts :
    (space.all fun s => keyIdx.all fun k => !full s ||
      (pRefuse ((decode (encode s)).getD 0) k == (decode (encode s)).getD 0)) = true :=
  by native_decide

/-! ## (в) Заморозка при пределе и единственный выход из неё -/

/-- Последовательность внесений длиной 3: 27 расписаний.-/
def schedules : List (List Nat) := (List.range 27).map fun t => [t / 9 % 3, t / 3 % 3, t % 3]

def runDenies (ops : List Nat) (s : Nat) : Nat := ops.foldl pRefuse s

/-- Полон — значит любая последовательность внесений оставляет список тем же. Полнота перебора по
`space` и `schedules` делает это ∀-утверждением, а не наблюдением.-/
theorem frozen_at_cap :
    (schedules.all fun ops => space.all fun s => !full s || runDenies ops s == s) = true :=
  by native_decide

/-- Отзыв — единственный рычаг: сняв запрет, вносим новичка.-/
theorem undeny_makes_room :
    (space.all fun s => keyIdx.all fun j => keyIdx.all fun k =>
      (!full s || !mem s j || mem s k) || mem (pRefuse (clrB s j) k) k) = true :=
  by native_decide

/-- Сохранение и загрузка после отказа: множество в файле прежнее, запрет не потерян.-/
theorem refusal_survives_save_load :
    (space.all fun s => keyIdx.all fun k =>
      (!full s || mem s k) || (decode (encode (pRefuse s k)) == some s)) = true :=
  by native_decide


-- Числа, которые обязан продублировать Rust-оракул: 8 состояний, предел 2, 5 бит в файле,
-- единственный файл пустого списка, и сколько файлов вообще перебрано.
#eval (space.length, cap, (encode 0).length, files.length)
#eval (policyNames.zip (policies.map propAll))
#eval (schedules.filter fun ops => space.any fun s => full s && runDenies ops s != s)

end VecDHT.Denylist
