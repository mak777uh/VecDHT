/-
  Формальная модель §16.3 («шард без живого владельца») и того §9.3, на который §16.3 ссылается.

  Спека (зеркало, строка 1470) обещает путь деградации без отдельного протокола: «агент видит
  пустой DHT-ответ по ключу шарда, повторяет lookup с backoff и, если шард пуст, пишет интент
  первому узлу, готовому взять эпизоду (§9.3). Никакого отдельного протокола для деградации нет».

  Модель транскрибирует гейты из исходника и спрашивает ядро о трёх вещах, которые нельзя
  спросить у живого кода без сотни прогонов:

    (1) существует ли ЛОКАЛЬНО проверяемое условие «готов взять эпизоду», которое одновременно
        истинно у узла без принятой эпохи и влечёт, что этот узел примет запись;
    (2) зависит ли ИСХОД публикации от порядка кандидатов (то есть надо ли мерить перестановки)
        и зависит ли от порядка ЦЕНА;
    (3) какой график повторов lookup при дедлайне агента даёт какое покрытие — то есть что
        следовало бы написать вместо слова «backoff».

  Транскрипция гейтов (номера строк — на момент пре-регистрации):
    * `node.rs:225` `epoch()`      = `membership.map(epoch)`;
    * `node.rs:230` `is_member()`  = ключ в принятом составе;
    * `node.rs:235` `is_primary()` = `membership.and_then(primary) == Some(me)`, причём
      `membership.rs:156…161` (`PrimaryNotFirst`) обязывает primary быть ПЕРВЫМ в списке;
    * `node.rs:723` и `node.rs:726` — порядок в `handle_publish`: сначала роль (иначе `NOT_OWNER`),
      затем `serving_epoch` (`node.rs:285…286`);
    * `node.rs:333…339` `should_propose` — требует `membership = Some`, непустого состава и
      собственного членства;
    * `node.rs:1027` `handle_find` — `self.epoch().unwrap_or(0)`: ЧТЕНИЕ обслуживается и без
      эпизоды, и ответ несёт `epoch = 0`;
    * `membership.rs:164…181` — `prev = None` принимает только `epoch = 1` и только по порогу
      авторитетов (`check_authorities`, `membership.rs:206…226`).
  Граница правила: это утверждения о ТРАНСКРИПЦИИ, а не о Rust-коде; соответствие реализации
  проверяется таблицей в файле эксперимента и живыми замерами `E-0080`.
-/

import Std

namespace VecDHT.Shard

abbrev Key := Nat

/-- Принятая эпизода с точки зрения одного узла. `none` — «узлу ещё нечего обслуживать»;
`some l` — список участников, где `l.head` и есть primary (§9.3 + `PrimaryNotFirst`). -/
inductive Mem
  | none
  | some (l : List Key)
  deriving Repr, BEq

/-- Всё, что узел знает о шарде ЛОКАЛЬНО. -/
structure Local where
  cert : Bool          -- кредашиал покрывает шард (`handshake.rs:70`, фильтр агента `covers`)
  mem : Mem            -- принятая эпизода
  lease : Bool         -- lease активен на этом бакете (`lease.rs:52`)
  authKeys : Nat       -- сколько ключей bootstrap-авторитета у узла (§15.2 — у узла 0)
  deriving Repr, BEq

/-- Есть ли у узла принятая эпизода (полюбой). -/
def hasMem (n : Local) : Bool :=
  match n.mem with
  | Mem.none => false
  | Mem.some _ => true

def isMember (n : Local) (me : Key) : Bool :=
  match n.mem with
  | Mem.none => false
  | Mem.some l => l.contains me

def isPrimary (n : Local) (me : Key) : Bool :=
  match n.mem with
  | Mem.none => false
  | Mem.some l => l.head? == some me

/-- Гейт записи: роль (`node.rs:723`) И serving-эпоха (`node.rs:726`). -/
def takesPublish (n : Local) (me : Key) : Bool := isPrimary n me && n.lease

/-- Гейт предложения следующей эпизоды (`node.rs:333…339`). -/
def canPropose (n : Local) (me : Key) : Bool :=
  match n.mem with
  | Mem.none => false
  | Mem.some l => !l.isEmpty && l.contains me

/-- Гейт чтения: `node.rs:1027` — только кредашиал, эпоха не нужна. -/
def takesFind (n : Local) : Bool := n.cert

/-- Момент, который узел называет в `MatchResult.epoch`: `unwrap_or(0)` из `node.rs:1027`. -/
def answerEpoch (n : Local) (e : Nat) : Nat :=
  match n.mem with
  | Mem.none => 0
  | Mem.some _ => e

inductive PubOutcome
  | notOwner    -- `NOT_OWNER` (`node.rs:724`), `retry_after_ms = 1000`
  | epochStale  -- `EPOCH_STALE` (`node.rs:728`)
  | accepted
  deriving Repr, BEq

/-- Порядок гейтов `handle_publish` целиком. -/
def publishOutcome (n : Local) (me : Key) : PubOutcome :=
  if !isPrimary n me then PubOutcome.notOwner
  else if !n.lease then PubOutcome.epochStale
  else PubOutcome.accepted

/-! ## Пространство состояний: 2 × 3 × 2 × 2 = 24 -/

def certVals : List Bool := [false, true]
def memVals : List Mem := [Mem.none, Mem.some [8, 9], Mem.some [8, 7], Mem.some [7, 9]]
def leaseVals : List Bool := [false, true]
def authVals : List Nat := [0, 3]

/-- Все комбинации: не-владелец / реплика без права writes (член, не primary) / член-неучастник
/ primary; lease; авторитеты. -/
def states : List Local :=
  certVals.flatMap fun c =>
    memVals.flatMap fun m =>
      leaseVals.flatMap fun l => authVals.map fun a =>
        { cert := c, mem := m, lease := l, authKeys := a }

theorem states_are_32 : states.length = 32 := by native_decide

/-- Локальные признаки — 6 букв алфавита, то есть 64 возможные «формы готовности». -/
def featAt (n : Local) (me : Key) : Nat → Bool
  | 0 => n.cert
  | 1 => hasMem n
  | 2 => isMember n me
  | 3 => isPrimary n me
  | 4 => n.lease
  | 5 => n.authKeys ≥ 3
  | _ => false

def shapeBit (s i : Nat) : Bool := (s / 2 ^ i) % 2 == 1

/-- Форма = конъюнкция допущенных букв; пустая форма истинна везде. -/
def shapeHolds (s : Nat) (n : Local) (me : Key) : Bool :=
  (List.range 6).all fun i => !shapeBit s i || featAt n me i

/-- Узел «готов взять эпизоду» в смысле §16.3: кредашиал есть, эпохи нет. -/
def unowned : Local := { cert := true, mem := Mem.none, lease := false, authKeys := 0 }

/-- Годная форма обязана (а) держаться на этом узле и (б) влечь приём записи. -/
def readyForm (s : Nat) : Bool :=
  shapeHolds s unowned 7 && (states.all fun n => shapeHolds s n 7 → takesPublish n 7)

/-! ## (1) Локального условия «готов» не существует: 64 формы, 0 подходящих -/

theorem no_local_readiness : (List.range 64).filter readyForm = [] := by native_decide

/-- Форм, истинных на невладеющем узле, ровно две: пустая («согласен с любым») и «есть
кредашиал на шард». Всё остальное уже требует эпоху, то есть отрицает само условие задачи. -/
theorem only_two_forms_hold_on_unowned :
    (List.range 64).filter (fun s => shapeHolds s unowned 7) = [0, 1] := by native_decide

theorem zero_and_one_do_not_imply_accept : readyForm 0 = false ∧ readyForm 1 = false := by
  native_decide

/-- Причина: `primary` определён только через принятую эпизоду. -/
theorem primary_needs_membership :
    states.all fun n => n.mem == Mem.none → isPrimary n 7 = false := by native_decide

/-- Влекущих приём форм ровно 16: это все надмножества bits «primary» И «lease» и только они.
Буква «участник состава» сюда не входит — реплика тоже член, и тоже отказывает (§9.4: пишет
только primary). -/
def implyingForms : List Nat :=
  (List.range 64).filter fun s => states.all fun n => shapeHolds s n 7 → takesPublish n 7

theorem implyingForms_are_exactly_the_supersets :
    implyingForms = (List.range 64).filter fun s => shapeBit s 3 && shapeBit s 4 := by
  native_decide

theorem implyingForms_are_sixteen : implyingForms.length = 16 := by native_decide

/-- Быть участником — не значит принять: во всех состояниях, где узел член, но не primary,
приём отвергнут, и это `NOT_OWNER`, а не `EPOCH_STALE`. -/
theorem member_is_not_enough :
    states.all fun n => isMember n 7 && !isPrimary n 7 →
      publishOutcome n 7 == PubOutcome.notOwner := by native_decide

/-- И ни одна из них не истинна на невладеющем узле: два множества не пересекаются. -/
theorem no_intersection :
    (implyingForms.filter fun s => shapeHolds s unowned 7) = [] := by native_decide

/-! ## (2) Порядок кандидатов: исход не зависит, цена — зависит -/

/-- Четыре типа кандидата: 0 — невладеющий (`NOT_OWNER`), 1 — реплика (`NOT_OWNER`),
2 — primary без lease (`EPOCH_STALE`), 3 — честный primary (приём). -/
def acceptType : Nat → Bool
  | 3 => true
  | _ => false

def allTriples : List (List Nat) :=
  (List.range 4).flatMap fun a => (List.range 4).flatMap fun b => (List.range 4).map fun c => [a, b, c]

def anyAccept (l : List Nat) : Bool := l.any acceptType

def perms3 : List (List Nat) :=
  [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]

def nth (l : List Nat) (i : Nat) : Nat := match (l.drop i) with | x :: _ => x | [] => 0

def permute (p l : List Nat) : List Nat := p.map fun i => nth l i

/-- **Успех публикации не зависит от очерёдности кандидатов.** Класс прогонов «попробовать другой
порядок» закрывается одной проверкой. -/
theorem outcome_is_order_free :
    allTriples.all fun l => perms3.all fun p => anyAccept l == anyAccept (permute p l) := by
  native_decide

/-- Цена = сколько отказов (и, как меряет `E-0080`, сколько оплаченных PoW) уходит до первого
приёма. -/
def cost (l : List Nat) : Nat := (l.takeWhile fun i => !acceptType i).length

/-- Цена зависит от порядка ровно тогда, когда набор смешанный. -/
theorem cost_is_order_sensitive :
    allTriples.all fun l =>
      (perms3.any fun p => cost l != cost (permute p l)) == (l.any acceptType && !l.all acceptType) := by
  native_decide

/-- Если пригодных нет вовсе, порядок не меняет и цену: агент перебирает список до конца, и
число оплаченных попыток равно длине списка кандидатов. -/
theorem hopeless_cost_is_length :
    [[0, 0, 0], [0, 1, 2], [2, 0, 1], [1, 2, 2]].all fun l =>
      perms3.all fun p => cost l == 3 ∧ cost (permute p l) == 3 := by native_decide

/-! ## (3) График повторов lookup: что покрывает, чего стоит -/

/-- Шаг `i` графика `(first, factor)` — `first · factor^i`. -/
def gap (first factor i : Nat) : Nat := first * factor ^ i

/-- Моменты запросов: накапливаем шаги, пока следующий не вылез за дедлайн. Топливо `D+1`
даёт завершимость без well-founded. -/
def timesAux (first factor D acc i fuel : Nat) : List Nat :=
  match fuel with
  | 0 => []
  | fuel + 1 =>
      let g := gap first factor i
      if acc + g ≥ D then [] else (acc + g) :: timesAux first factor D (acc + g) (i + 1) fuel

def times (first factor D : Nat) : List Nat := timesAux first factor D 0 0 (D + 1)

def maxOf (l : List Nat) : Nat := l.foldl (fun a b => max a b) 0

def minOf (l : List Nat) (empty : Nat) : Nat := l.foldl (fun a b => min a b) empty

/-- Покрытие: сколько моментов прихода провайдера `t ∈ 1..D` замечены хотя бы одним запросом
(запрос в `c` видит всё, что появилось в `t ≤ c`). -/
def disc (first factor D : Nat) : Nat :=
  ((List.range D).filter fun t => (times first factor D).any fun c => c ≥ t + 1).length

/-- Суммарная задержка обнаружения по замеченным моментам. -/
def sDelay (first factor D : Nat) : Nat :=
  let qs := times first factor D
  (List.range D).foldl (fun acc t =>
    let late := qs.filter fun c => c ≥ t + 1
    if late.isEmpty then acc else acc + (minOf late (D + 1) - (t + 1))) 0

/-- Верхняя точка графика: момент последнего запроса. -/
def lastQuery (first factor D : Nat) : Nat := maxOf (times first factor D)

def load (first factor D : Nat) : Nat := (times first factor D).length

structure Point where
  first : Nat
  factor : Nat
  d : Nat
  cov : Nat
  load : Nat
  delay : Nat
  deriving Repr, BEq, DecidableEq

def mkPoint (first factor D : Nat) : Point :=
  { first := first, factor := factor, d := D, cov := disc first factor D,
    load := load first factor D, delay := sDelay first factor D }

def grid : List Point :=
  [10, 20, 40].flatMap fun D =>
    ((List.range 8).map (· + 1)).flatMap fun f => [1, 2, 3].map fun k => mkPoint f k D

/-- Точка `q` доминирует `p`, если не хуже по всем трём осям и строго лучше хоть по одной. -/
def better (q p : Point) : Bool :=
  q.cov ≥ p.cov && q.load ≤ p.load && q.delay ≤ p.delay &&
    (q.cov > p.cov || q.load < p.load || q.delay < p.delay)

def pareto : List Point := grid.filter fun p => !grid.any fun q => better q p

/-- Покрытие = момент последнего запроса: «сколько секунд до дедлайна ещё видно». -/
theorem coverage_is_the_last_query :
    grid.all fun p => p.cov == lastQuery p.first p.factor p.d := by native_decide

/-- Максимальное покрытие при дедлайне 20 с (столько у агента по умолчанию) даёт фиксированный
шаг в 1 с — 19 моментов из 20; это верхняя граница ЛЮБОГО графика. -/
theorem coverage_top_is_one_second_step :
    ((grid.filter fun p => p.d == 20 && p.cov == 19) == [mkPoint 1 1 20]) = true := by native_decide

/-- Нынешний код — фиксированный шаг 3 с (`agent.rs:1111`…1114). Он покрывает те же 18 моментов,
что и двухзапросный график `6, 12`, но шестью запросами: «число повторов» и «покрытие» в этом
коде не связаны, и связывает их только задержка. -/
theorem same_coverage_three_times_the_traffic :
    (disc 3 1 20, disc 6 2 20) = (18, 18) ∧ (load 3 1 20, load 6 2 20) = (6, 2) ∧
      (sDelay 3 1 20 < sDelay 6 2 20) = true := by native_decide

def covAtLeast (D c : Nat) : List Point := grid.filter fun p => p.d == D && p.cov ≥ c

def minDelay (l : List Point) : Nat := minOf (l.map fun p => p.delay) 1000000

/-- Среди графиков с покрытием ≥ 18 наименьшая задержка — у фиксированного шага, то есть
«backoff» в спеке нужно определять через приемлемую задержку, а не через число попыток. -/
theorem min_delay_among_covering_is_fixed_step :
    (covAtLeast 20 18).any fun p => p.delay == minDelay (covAtLeast 20 18) && p.factor == 1 := by
  native_decide

/-- Хвост недоступен любому графику: последний запрос всегда строго раньше дедлайна. -/
theorem tail_is_never_covered : grid.all fun p => p.cov < p.d := by native_decide

/-! ## (4) Дверь в эпоху 1: перебор источников подписи -/

inductive Principal
  | self          -- ключ участника самого узла
  | prevMembers   -- подписи предыдущей эпизоды (для `prev = None` их нет)
  | anyHolder     -- любой держатель кредашиала на шард
  | agent         -- ключ агента
  | authorities   -- bootstrap-авторитеты из артефакта (§15.2)
  deriving Repr, BEq, Inhabited, DecidableEq

/-- Что засчитает валидатор при `prev = None`: `check_authorities` смотрит ТОЛЬКО в набор
авторитетов (`membership.rs:206…226`), поэтому неавторитетный источник даёт ноль принятых
подписей, сколько бы ключей ни имел. -/
def validSigsOf : Principal → Nat → Nat
  | Principal.authorities, k => k
  | _, _ => 0

def tAuth : Nat := 3

def opensGenesis (p : Principal) (keys : Nat) : Bool := validSigsOf p keys ≥ tAuth

def fivePrincipals : List Principal :=
  [Principal.self, Principal.prevMembers, Principal.anyHolder, Principal.agent,
   Principal.authorities]

/-- Из пяти источников дверь открывает ровно один. -/
theorem only_authorities_open_genesis :
    fivePrincipals.filter (fun p => opensGenesis p 8) = [Principal.authorities] := by native_decide

/-- Понижением порога дверь не открыть: узел с восемью своими ключами проходит только порог 0,
то есть отмену требования подписи, а не её ослабление. -/
theorem lowering_the_threshold_only_removes_it :
    (List.range 6).filter (fun t => validSigsOf Principal.self 8 ≥ t) = [0] := by native_decide

/-- Узел без авторитетных ключей не открывает дверь НИКАКИМ числом своих ключей. -/
theorem node_keys_cannot_open :
    (List.range 9).all fun k => opensGenesis Principal.self k = false ∧
      opensGenesis Principal.agent k = false := by native_decide

/-! ## (5) Асимметрия чтения и записи, и молчание тиков -/

theorem unowned_is_silent_and_refuses :
    states.all fun n =>
      n.mem == Mem.none → canPropose n 7 = false ∧ publishOutcome n 7 == PubOutcome.notOwner := by
  native_decide

/-- Единственный принимающий узел — primary уже принятой эпизоды. -/
theorem acceptance_requires_epoch :
    states.all fun n => takesPublish n 7 == true → hasMem n == true := by native_decide

/-- И наоборот: accept = «primary ∧ lease» без запасных путей. -/
theorem accept_is_primary_and_lease :
    states.all fun n => takesPublish n 7 == (isPrimary n 7 && n.lease) := by native_decide

/-- «Чтение живое, записи нет»: узел с кредашиалом и без эпизоды отвечает на `Find` (и называет
`epoch = 0`), но на `Publish` отвечает `NOT_OWNER`. -/
theorem read_yes_write_no :
    states.all fun n =>
      n.cert && n.mem == Mem.none →
        (takesFind n && !takesPublish n 7) && answerEpoch n 5 == 0 := by native_decide

/-- Принимающих состояний — ровно 4 из 24, и во всех эпизода уже есть. -/
def acceptingStates : List Local := states.filter fun n => takesPublish n 7

theorem accepting_states_are_four : acceptingStates.length = 4 := by native_decide

/-! ## Печати: что модель даёт до замера -/

#eval states.length
#eval (List.range 64).filter readyForm
#eval (List.range 64).filter (fun s => shapeHolds s unowned 7)
#eval implyingForms
#eval allTriples.length
#eval fivePrincipals.filter (fun p => opensGenesis p 8)
#eval (List.range 64).filter (fun s => shapeHolds s unowned 7)
#eval readyForm 0
#eval (List.range 64).filter fun s => states.all fun n => shapeHolds s n 7 → takesPublish n 7
#eval (times 3 1 20, disc 3 1 20, load 3 1 20, sDelay 3 1 20)
#eval (times 6 2 20, disc 6 2 20, load 6 2 20, sDelay 6 2 20)
#eval (times 2 1 20, disc 2 1 20, load 2 1 20, sDelay 2 1 20)
#eval (covAtLeast 20 18).map fun p => (p.first, p.factor, p.cov, p.load, p.delay)
#eval (minDelay (covAtLeast 20 18))
#eval (pareto.filter fun p => p.d == 20).map fun p => (p.first, p.factor, p.cov, p.load, p.delay)
#eval (pareto.filter fun p => p.d == 20).length
#eval (pareto.filter fun p => p.d == 40).length
#eval acceptingStates

end VecDHT.Shard
