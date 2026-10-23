/-
# Модель дверей §15/§9.2: пороговая подпись авторитета

Проба формальных методов (`H-0078`): модель транскрибирует три чистые функции Rust
и формулирует инвариант спеки §9.2 как proposition, чтобы ядро могло инвариант
либо опровергнуть, либо доказать.

Что моделируется:

* `countValid` — `AuthoritySet::count_valid` (`crates/vecdht-crypto/src/cert.rs:57`):
  число **разных** ключей набора, под которыми есть хоть одна подпись;
* `checkIndices` — `Chain::check_indices` (`crates/vecdht-node/src/membership.rs:254`):
  диапазон и уникальность индекса;
* `genesisDoorCurrent` — `Chain::check_authorities` (`membership.rs:206`): текущая
  genesis-дверь, где подпись засчитывается против **любого** ключа набора;
* `transitionDoor` — `Chain::check_members` (`membership.rs:231`): дверь перехода,
  где подпись засчитывается по **своему** индексу.

Что НЕ моделируется (и в вывод не идёт): Ed25519 (подпись проверяется ровно под своим
ключом — абстракция допущения «не более чем под одним ключом набора»), сеть, время,
fsync, квоты, int8-квантование.

Соответствие модели коду проверяется отдельно, в Rust: тот же счётчик контрпримеров
по ограниченному пространству должен совпасть
(`crates/vecdht-node/tests/s15_lean_correspondence.rs`).
-/
import Std

namespace VecDHT.Auth

/-! ## Абстракция

Ключ авторитета — это его позиция в порядке артефакта (`authorities`). Подпись в
модели несёт своего подписавшего: `verify k s` истинно ровно тогда, когда `s` сделана
ключом `k`. Настоящая подпись — 64 байта Ed25519, но для этой двери важно только,
каким ключом она проверяется. -/

abbrev Key := Nat

structure Sig where
  signer : Key
  tag : Nat
deriving DecidableEq, Repr

/-- Проверка подписи под ключом. -/
def verify (k : Key) (s : Sig) : Bool := s.signer == k

/-! ## Транскрипция Rust -/

/-- `AuthoritySet::count_valid`: число разных ключей набора, под которыми есть подпись. -/
def countValid (keys : List Key) (sigs : List Sig) : Nat :=
  (keys.eraseDups.filter fun k => sigs.any (verify k)).length

/-- `Chain::check_indices`: индекс в диапазоне и индексы попарно различны. -/
def checkIndices (sigs : List (Key × Sig)) (len : Nat) : Bool :=
  (sigs.map Prod.fst).all fun i => i < len
    && (sigs.map Prod.fst).eraseDups.length == sigs.length

/-- Ключ на позиции `i` (как `keys[i]` в Rust). -/
def keyAt (keys : List Key) (i : Nat) : Option Key := (keys.drop i).head?

/-- Проверка подписи **по своему индексу**: `keys[idx]` должен ею и подписан. -/
def boundVerify (keys : List Key) (p : Key × Sig) : Bool :=
  match keyAt keys p.1 with
  | some k => verify k p.2
  | none => false

/-- Число подписей, привязанных к своему индексу (без дедупликации по ключу). -/
def boundCount (keys : List Key) (sigs : List (Key × Sig)) : Nat :=
  (sigs.filter fun p => boundVerify keys p).length

/-- Ключ, засчитываемый привязанной дверью для пары `p`: `keys[idx]`, если подпись
привязана к своему индексу. -/
def boundKey (keys : List Key) (p : Key × Sig) : Option Key :=
  match keyAt keys p.1 with
  | some k => if verify k p.2 then some k else none
  | none => none

/-- Число **разных** ключей, чья подпись привязана к своему индексу. -/
def boundDistinct (keys : List Key) (sigs : List (Key × Sig)) : Nat :=
  (sigs.filterMap (boundKey keys)).eraseDups.length

/-- Текущая genesis-дверь (`check_authorities`): индекс проверяется на диапазон и
уникальность, а сама подпись засчитывается против любого ключа набора. -/
def genesisDoorCurrent (keys : List Key) (threshold : Nat) (sigs : List (Key × Sig)) : Option Nat :=
  if checkIndices sigs keys.length then
    let cnt := countValid keys (sigs.map Prod.snd)
    if threshold ≤ cnt then some cnt else none
  else none

/-- Дверь перехода (`check_members`): подпись засчитывается по своему индексу. -/
def transitionDoor (prev : List Key) (threshold : Nat) (sigs : List (Key × Sig)) : Option Nat :=
  if checkIndices sigs prev.length then
    let cnt := boundCount prev sigs
    if threshold ≤ cnt then some cnt else none
  else none

/-- Предложенный фикс атрибуции: genesis считает подпись по своему индексу —
ровно как переход. -/
def genesisDoorBound (keys : List Key) (threshold : Nat) (sigs : List (Key × Sig)) : Option Nat :=
  if checkIndices sigs keys.length then
    let cnt := boundCount keys sigs
    if threshold ≤ cnt then some cnt else none
  else none

/-- Тот же фикс, но с дедупликацией по ключу: без неё порог слабеет, если набор
авторитетов содержит один ключ дважды (манифест это запрещает, а
`AuthoritySet::new` — нет). -/
def genesisDoorBoundDedup (keys : List Key) (threshold : Nat) (sigs : List (Key × Sig)) : Option Nat :=
  if checkIndices sigs keys.length then
    let cnt := boundDistinct keys sigs
    if threshold ≤ cnt then some cnt else none
  else none

/-! ## Инвариант спеки §9.2 (строка 969 зеркала)

«индекс в `sigs` — позиция подписанта в наборе **epoch−1** (для genesis — порядок
ключей в `authorities` артефакта)». -/

/-- Инвариант: каждая подпись списка привязана к своему индексу. -/
def attribution (keys : List Key) (sigs : List (Key × Sig)) : Prop :=
  ∀ p ∈ sigs, boundVerify keys p = true

/-- Тот же инвариант в вычислимой форме. -/
def attributedAll (keys : List Key) (sigs : List (Key × Sig)) : Bool :=
  sigs.all fun p => boundVerify keys p

/-- Мост между вычислимой формой и proposition. -/
theorem attributedAll_iff (keys : List Key) (sigs : List (Key × Sig)) :
    attributedAll keys sigs = true ↔ attribution keys sigs := by
  simp [attributedAll, attribution, List.all_eq_true]

/-! ## Контрпример: подписи авторов 0,1,2 под заявленными индексами 2,3,4 -/

def witnessKeys : List Key := [0, 1, 2, 3, 4]

def witnessSigs : List (Key × Sig) := [(2, ⟨0, 0⟩), (3, ⟨1, 1⟩), (4, ⟨2, 2⟩)]

/-- Счёт текущей двери: три разных ключа набора подписали — порог взят. -/
theorem witness_countValid : countValid witnessKeys (witnessSigs.map Prod.snd) = 3 := by native_decide

/-- Счёт привязки по индексу: ни одна подпись не привязана к своему индексу. -/
theorem witness_boundCount : boundCount witnessKeys witnessSigs = 0 := by native_decide

theorem witness_boundDistinct : boundDistinct witnessKeys witnessSigs = 0 := by native_decide

/-- Текущая дверь принимает этот genesis. -/
theorem witness_current_accepts : genesisDoorCurrent witnessKeys 3 witnessSigs = some 3 := by native_decide

/-- Инвариант спеки на этом примере нарушен. -/
theorem witness_violates_attribution : ¬ attribution witnessKeys witnessSigs := by
  intro h
  have h1 := h (2, ⟨0, 0⟩) (by native_decide)
  simp [boundVerify, keyAt, verify, witnessKeys] at h1

/-- Дверь, привязывающая индекс, тот же пример отвергает. -/
theorem witness_bound_rejects : genesisDoorBound witnessKeys 3 witnessSigs = none := by native_decide

theorem witness_boundDedup_rejects : genesisDoorBoundDedup witnessKeys 3 witnessSigs = none := by native_decide

/-- Существование контрпримера: текущая дверь принимает то, что дверь по индексу
отвергает. -/
theorem current_admits_what_bound_rejects :
    ∃ keys sigs, genesisDoorCurrent keys 3 sigs ≠ none ∧ genesisDoorBound keys 3 sigs = none := by
  refine ⟨witnessKeys, witnessSigs, ?_, ?_⟩
  · native_decide
  · native_decide

/-! ## Характеризация дверей (утверждения по всем входам) -/

/-- Текущая дверь принимает ровно тогда, когда индексы в порядке и порог взят
по **любым** ключам. -/
theorem genesisDoorCurrent_iff (keys : List Key) (t : Nat) (sigs : List (Key × Sig)) :
    genesisDoorCurrent keys t sigs ≠ none ↔
      (checkIndices sigs keys.length = true) ∧ countValid keys (sigs.map Prod.snd) ≥ t := by
  unfold genesisDoorCurrent
  by_cases h : checkIndices sigs keys.length = true
  · by_cases h2 : t ≤ countValid keys (sigs.map Prod.snd)
    · simp [h, h2]
    · simp [h, h2]
  · simp [h]

/-- Дверь по индексу принимает ровно тогда, когда порог набирают подписи,
привязанные к своим индексам. -/
theorem genesisDoorBound_iff (keys : List Key) (t : Nat) (sigs : List (Key × Sig)) :
    genesisDoorBound keys t sigs ≠ none ↔
      (checkIndices sigs keys.length = true) ∧ boundCount keys sigs ≥ t := by
  unfold genesisDoorBound
  by_cases h : checkIndices sigs keys.length = true
  · by_cases h2 : t ≤ boundCount keys sigs
    · simp [h, h2]
    · simp [h, h2]
  · simp [h]

/-- Фикс — это буквально правило перехода: две двери совпадают как функции. -/
theorem genesisBound_eq_transition (keys : List Key) (t : Nat) (sigs : List (Key × Sig)) :
    genesisDoorBound keys t sigs = transitionDoor keys t sigs := by
  unfold genesisDoorBound transitionDoor
  by_cases h : checkIndices sigs keys.length = true
  · by_cases h2 : t ≤ boundCount keys sigs
    · simp [h, h2]
    · simp [h, h2]
  · simp [h]

/-! ## Повторяющийся ключ в наборе авторитетов

`manifest.rs:836` запрещает дублирующийся ключ авторитета, а `AuthoritySet::new`
(`cert.rs:51`) — нет, и `ShardNode::open` принимает набор от вызывающего. -/

/-- Наивный фикс без дедупликации слабеет: три подписи от двух подписавших. -/
theorem naive_fix_weakens_threshold :
    ∃ keys sigs, genesisDoorBound keys 3 sigs = some 3 ∧
      countValid keys (sigs.map Prod.snd) < 3 := by
  refine ⟨[0, 0, 1], [(0, ⟨0, 0⟩), (1, ⟨0, 1⟩), (2, ⟨1, 2⟩)], ?_, ?_⟩
  · native_decide
  · native_decide

/-- С дедупликацией этот случай отвергается. -/
theorem dedup_door_rejects_duplicate_keys :
    genesisDoorBoundDedup [0, 0, 1] 3 [(0, ⟨0, 0⟩), (1, ⟨0, 1⟩), (2, ⟨1, 2⟩)] = none := by
  native_decide

/-! ## Перебор класса контрпримеров

Пространство: набор ключей — все упорядоченные списки различных ключей из {0..4}
длиной 1..5; список подписей — все списки длиной 0, 1 или 2 из алфавита
25 элементов (индекс 0..4 × подписавший 0..4). -/

def alphabet : List (Key × Sig) :=
  (List.range 5).flatMap fun i => (List.range 5).map fun s => (i, ⟨s, i⟩)

/-- Все списки длины ровно `n` над алфавитом. -/
def combos {α : Type} : List α → Nat → List (List α)
  | _, 0 => [[]]
  | alphabet, n + 1 => alphabet.flatMap fun a => (combos alphabet n).map (a :: ·)

/-- Все упорядоченные списки различных ключей из {0..4} длиной 1..5. -/
def keyLists : List (List Key) :=
  ((combos (List.range 5) 1) ++ (combos (List.range 5) 2) ++ (combos (List.range 5) 3)
    ++ (combos (List.range 5) 4) ++ (combos (List.range 5) 5)).filter fun l => l.Nodup

/-- Списки подписей длиной не более двух. -/
def sigListsUpTo2 : List (List (Key × Sig)) :=
  combos alphabet 0 ++ combos alphabet 1 ++ combos alphabet 2

/-- Списки подписей длиной ровно три. -/
def sigLists3 : List (List (Key × Sig)) := combos alphabet 3

/-- Контрпример: текущая дверь приняла, дверь по индексу — нет. -/
def isCounterexample (keys : List Key) (sigs : List (Key × Sig)) : Bool :=
  genesisDoorCurrent keys 3 sigs != none && boundCount keys sigs < 3

/-- Счётчик контрпримеров в пространстве «подписей не более двух». -/
def counterexamplesUpTo2 : Nat :=
  (keyLists.flatMap fun keys => sigListsUpTo2.filter (isCounterexample keys)).length

/-- Счётчик контрпримеров в пространстве «подписей ровно три» при эталонном наборе
ключей (5 ключей, порядок артефакта). -/
def counterexamples3 : Nat :=
  (sigLists3.filter (isCounterexample witnessKeys)).length

/-- Меньше трёх подписей порог не набирает: контрпримеров нет. -/
theorem counterexamplesUpTo2_eq_zero : counterexamplesUpTo2 = 0 := by native_decide

/-- При трёх подписях контрпримеры есть. -/
theorem counterexamples3_pos : 1 ≤ counterexamples3 := by native_decide

/-! ## Строгая и счётная политики: что именно даёт фикс (пункт (4) пре-регистрации)

Пре-регистрация требовала ∀-теоремы в сильной форме: «если связанная дверь приняла,
то для **каждой** подписи `verify keys[idx] sig = true`». Разбираем формулировку на части
и проверяем каждую ядром — обе политики описаны здесь, чтобы решение владельца
(`ADR-0022`/`ADR-0023`) было между конкретными, а не между «правильным» и «неправильным». -/

/-- Счётная политика — та, что уже есть в коде у двери перехода: считаются подписи,
привязанные к своим индексам; лишние непривязанные подписи счёт не поднимают,
но и не блокируют приём. -/
def genesisDoorCount (keys : List Key) (threshold : Nat) (sigs : List (Key × Sig)) : Option Nat :=
  genesisDoorBound keys threshold sigs

/-- Строгая политика: любая непривязанная подпись отвергает весь набор. -/
def genesisDoorStrict (keys : List Key) (threshold : Nat) (sigs : List (Key × Sig)) : Option Nat :=
  if checkIndices sigs keys.length then
    if sigs.all (boundVerify keys) then
      let cnt := boundCount keys sigs
      if threshold ≤ cnt then some cnt else none
    else none
  else none

/-- Счёт, который сообщает привязанная дверь, — это ровно число привязанных подписей. -/
theorem bound_door_count_is_bound_count (keys : List Key) (t : Nat) (sigs : List (Key × Sig))
    (c : Nat) (h : genesisDoorBound keys t sigs = some c) : c = boundCount keys sigs := by
  unfold genesisDoorBound at h
  by_cases h1 : checkIndices sigs keys.length = true
  · by_cases h2 : t ≤ boundCount keys sigs
    · simp [h1, h2] at h
      exact h.symm
    · simp [h1, h2] at h
  · simp [h1] at h

/-- Строгая дверь даёт буквально то, что записано в пре-регистрации (4): принял ⇒
привязаны **все** подписи набора. Это утверждение по всем входам. -/
theorem strict_door_all_bound (keys : List Key) (t : Nat) (sigs : List (Key × Sig))
    (h : genesisDoorStrict keys t sigs ≠ none) :
    ∀ p ∈ sigs, boundVerify keys p = true := by
  unfold genesisDoorStrict at h
  by_cases h1 : checkIndices sigs keys.length = true
  · by_cases h2 : sigs.all (boundVerify keys) = true
    · exact (List.all_eq_true.mp h2)
    · simp [h1, h2] at h
  · simp [h1] at h

/-- Счётная политика буквальной формы (4) **не** даёт: дверь принимает набор, где одна
подпись привязана не к своему индексу. -/
theorem count_policy_admits_unbound :
    genesisDoorBound witnessKeys 3
      [(0, ⟨0, 0⟩), (1, ⟨1, 1⟩), (2, ⟨2, 2⟩), (3, ⟨0, 0⟩)] = some 3 := by native_decide

/-- …и это машинно-проверное опровержение буквальной формы (4) для счётной политики. -/
theorem literal_form_false_for_count_policy :
    ∃ keys sigs, genesisDoorBound keys 3 sigs ≠ none ∧
      ¬ (∀ p ∈ sigs, boundVerify keys p = true) := by
  refine ⟨witnessKeys, [(0, ⟨0, 0⟩), (1, ⟨1, 1⟩), (2, ⟨2, 2⟩), (3, ⟨0, 0⟩)], ?_, ?_⟩
  · native_decide
  · intro hall
    have h1 := hall (3, ⟨0, 0⟩) (by native_decide)
    simp [boundVerify, keyAt, verify, witnessKeys] at h1

/-- Строгая дверь свидетеля (находка 12) отвергает. -/
theorem strict_rejects_witness : genesisDoorStrict witnessKeys 3 witnessSigs = none := by
  native_decide

/-! ## Два источника порога (пункт (5) пре-регистрации)

`Chain::check_authorities` спрашивает `params.authority_threshold`, `AuthoritySet::check` —
`authorities.threshold`, и `ShardNode::open` кладёт обе структуры рядом, не сверяя. -/

/-- Два источника порога: конфигурация узла (`params`) и набор авторитетов (`authorities`). -/
structure Thresholds where
  params : Nat
  authorities : Nat
deriving DecidableEq, Repr

/-- Genesis-дверь с текущим правилом («подпись засчитывается против любого ключа набора»)
и порогом из `params`. -/
def genesisDoorAny (keys : List Key) (th : Thresholds) (sigs : List (Key × Sig)) : Option Nat :=
  if checkIndices sigs keys.length then
    let cnt := countValid keys (sigs.map Prod.snd)
    if th.params ≤ cnt then some cnt else none
  else none

/-- Дверь NodeCert: правило то же, порог — из набора. -/
def certDoor (keys : List Key) (th : Thresholds) (sigs : List Sig) : Option Nat :=
  let cnt := countValid keys sigs
  if th.authorities ≤ cnt then some cnt else none

/-- Две настоящие подписи авторитетов. -/
def twoSigs : List (Key × Sig) := [(0, ⟨0, 0⟩), (1, ⟨1, 1⟩)]

/-- Расхождение источников **представимо**: `params = 2` проходит, `authorities = 3` — нет. -/
theorem two_sources_diverge :
    genesisDoorAny [0, 1, 2, 3, 4] ⟨2, 3⟩ twoSigs = some 2 ∧
      certDoor [0, 1, 2, 3, 4] ⟨2, 3⟩ (twoSigs.map Prod.snd) = none := by
  native_decide

/-- С одним источником две двери совпадают тождественно. -/
theorem one_source_identity (keys : List Key) (t : Nat) (sigs : List (Key × Sig))
    (h : checkIndices sigs keys.length = true) :
    genesisDoorAny keys ⟨t, t⟩ sigs = certDoor keys ⟨t, t⟩ (sigs.map Prod.snd) := by
  unfold genesisDoorAny certDoor
  by_cases hc : checkIndices sigs keys.length = true
  · by_cases ht : t ≤ countValid keys (sigs.map Prod.snd)
    · simp [hc, ht]
    · simp [hc, ht]
  · exact absurd h hc

/-- …и потому расхождение непредставимо: с одним источником обе двери принимают одно
и то же. -/
theorem one_source_no_divergence (keys : List Key) (t : Nat) (sigs : List (Key × Sig))
    (h : checkIndices sigs keys.length = true) :
    (genesisDoorAny keys ⟨t, t⟩ sigs ≠ none) ↔
      (certDoor keys ⟨t, t⟩ (sigs.map Prod.snd) ≠ none) := by
  rw [one_source_identity keys t sigs h]

/-! ## Печать измеренных чисел -/

#eval counterexamplesUpTo2
#eval counterexamples3
#eval keyLists.length
#eval sigListsUpTo2.length
#eval sigLists3.length

end VecDHT.Auth
