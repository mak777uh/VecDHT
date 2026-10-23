/-
Модель двери приёма §11.3/§14.4 (iv) — «надувание кластеров», и per-cluster cap как выбор между
тремя конкретными формами.

Вторая проба формальных методов по правилу, принятому владельцем после `E-0078`, и она сделана
**до** замера: функция решения формализуется, у неё спрашивается ∀-утверждение, ответ ядра
подсказывает, что измерять в живом коде (`H-0079`).

Порядок гейтов транскрибирован из `crates/vecdht-node/src/node.rs:676…800` (путь `Publish`):

* `frame.header.signed()` → `verify_body(owner, PUBLISH, …)` (685…699): подпись проверяется
  **под условием флага**; сброшенный флаг — заявленный `owner_ed25519` никто не подтверждает;
* `intent_id == intent_id(vec_q, version)` (712): вектор привязан к цене записи, подменить
  `vec_q` при чужом `intent_id` нельзя;
* `shard_of_cluster(cluster_id) == self.shard` (717): **единственная проверка кластера**;
* бакет ключа и узловой бюджет (735, 758): токен резервируется раньше, чем узел узнаёт, что
  это перепубликация;
* `pow_bits`/`pow_ok` (743…751): вход `pow_input(owner, shard, epoch, intent_id, expires)`
  (`crypto/src/pow.rs:63`) не содержит ни `cluster_id`, ни расстояния до центроида;
* вместимость (766…790): блокируется только **новая** запись — `replacing` выведен из гейта явно
  («живая запись у owner'а ровно одна… поэтому вместимость шарда её не касается»).

Профиль шарда — список пар `(ключ, кластер)`, а не вектор счётчиков: перепубликация с другим
`cluster_id` **переезжает** между posting list'ами на своём slot'е (`ivf.rs:322…328`), и именно
переезд оказывается дырой в наивном cap'е (теорема `cap_exemption_leaks`).

Пространство перебора расписаний: 4 ключа × 4 кластера × длина ≤ 4 = 83 521 расписание.
`CLUSTERS` и `CAP` уменьшены ради перебора; в коде это 16 кластеров и `max_live_per_shard`.
Модель ничего не утверждает про Ed25519, blake3, WAL, сеть и время: цена записи здесь — символ
(и токен), её число измеряется в Rust.
-/

namespace VecDHT.Admission

abbrev Key := Nat
abbrev Cluster := Nat

/-- Запись пути `Publish`: автор, заявленный кластер, вектор, истинное расстояние до центроида
этого кластера и флаг «фрейм подписан». Последние три поля на решение не влияют — ниже это
теоремы. -/
structure Pub where
  key : Key
  cluster : Cluster
  vec : Nat
  dist : Nat
  signed : Bool
deriving DecidableEq, Repr

/-- Профиль шарда: живые записи `(автор, кластер)`. Posting list'ы — `IvfIndex::lists`, таблица
авторов — `owner_slot`. -/
abbrev Profile := List (Key × Cluster)

/-- Число кластеров шарда (в коде `CLUSTERS_PER_SHARD = 16`; здесь 4 ради перебора). -/
def CLUSTERS : Nat := 4

/-- Вместимость шарда (в коде `Params.max_live_per_shard`; здесь 8). -/
def CAP : Nat := 8

/-- Цель proposed-cap'а: максимальный размер одной ячейки. -/
def maxCell : Nat := 2

/-- Размер ячейки `c` — длина posting list'а (`IvfIndex::cluster_len`, `ivf.rs:447`). -/
def cellAt (p : Profile) (c : Cluster) : Nat := (p.filter (·.2 == c)).length

/-- Общее число живых записей (`store.len()`). -/
def total (p : Profile) : Nat := p.length

/-- Есть ли в профиле ячейка выше cap. -/
def overCap (p : Profile) : Bool := p.any fun (_, c) => maxCell < cellAt p c

/-- Живая запись ключа, если она есть (`index.entry(owner_slot(key))`). Один источник истины для
`has` и `cellOf`, чтобы переход «запись в ячейке `c` ⇒ ключ жив» был теоремой, а не догадкой. -/
def ownerEntry (p : Profile) (k : Key) : Option (Key × Cluster) := p.find? fun x => x.1 == k

/-- Есть ли у ключа живая запись (`owner_slot(key).is_some()`). -/
def has (p : Profile) (k : Key) : Bool := (ownerEntry p k).isSome

/-- Где сейчас живёт запись ключа (`entry(owner_slot(key)).cluster_id`). -/
def cellOf (p : Profile) (k : Key) : Option Cluster :=
  match ownerEntry p k with
  | some (_, c) => some c
  | none => none

/-- Мост, который в Rust очевиден из типов, а в модели требует явной проверки: если запись
числится в ячейке, значит ключ жив. -/
theorem has_of_cellOf (p : Profile) (k c : Nat) (h : cellOf p k = some c) : has p k = true := by
  unfold cellOf at h
  unfold has
  cases e : ownerEntry p k with
  | none => simp [e] at h
  | some _ => simp

/-- Приём: нового ключа дописываем, существующий **переезжает** в заявленный кластер на своём
месте (§11.3.2: slot тот же, меняется только состав списков). -/
def put (p : Profile) (r : Pub) : Profile :=
  if has p r.key then p.map (fun x => if x.1 == r.key then (r.key, r.cluster) else x)
  else p ++ [(r.key, r.cluster)]

/-- Решение **текущей** политики: заявленный кластер обязан быть кластером шарда; при полной
вместимости блокируется только новая запись. Поля `signed`, `vec`, `dist` не читаются. -/
def admit (p : Profile) (r : Pub) : Bool :=
  r.cluster < CLUSTERS ∧ ¬ (CAP ≤ total p ∧ ! (has p r.key))

/-- Решение политики **cap с льготой перепубликации** — та же логика, что у гейта вместимости:
размер ячейки проверяется только для нового места. -/
def admitX (p : Profile) (r : Pub) : Bool :=
  admit p r ∧ ¬ (maxCell ≤ cellAt p r.cluster ∧ ! (has p r.key))

/-- Решение политики **cap без льготы**: размер заявленной ячейки проверяется всегда. -/
def admitA (p : Profile) (r : Pub) : Bool :=
  admit p r ∧ ¬ (maxCell ≤ cellAt p r.cluster)

/-- Решение политики **cap с учётом переезда**: обновить свою ячейку можно всегда, приехать в
полную — нельзя. -/
def admitM (p : Profile) (r : Pub) : Bool :=
  admit p r ∧ ¬ (cellOf p r.key != some r.cluster ∧ maxCell ≤ cellAt p r.cluster)

/-- Один шаг: принято — профиль меняется, отказ — профиль тот же (каждый `Publish` есть
отдельный запрос, как в живом пути). -/
def step (d : Profile → Pub → Bool) (p : Profile) (r : Pub) : Profile :=
  if d p r then put p r else p

/-- Расписание целиком с пустого шарда и с произвольного старта. -/
def runFrom (d : Profile → Pub → Bool) (start : Profile) (sched : List Pub) : Profile :=
  sched.foldl (step d) start

def run (d : Profile → Pub → Bool) (sched : List Pub) : Profile := runFrom d [] sched

/-- Алфавит одной записи для перебора: 4 ключа × 4 кластера. -/
def alphabet : List Pub :=
  [0, 1, 2, 3].flatMap fun k =>
    (List.range CLUSTERS).map fun c =>
      { key := k, cluster := c, vec := 0, dist := 0, signed := false }

/-- Все расписания длины ≤ n. -/
def schedules (n : Nat) : List (List Pub) :=
  match n with
  | 0 => [[]]
  | m + 1 =>
      let prev := schedules m
      prev ++ prev.flatMap fun s => alphabet.map fun r => s ++ [r]

/-! ## (1) Три ∀-теоремы о том, чего решение не видит

Они `rfl` — и в этом их смысл, а не слабость: транскрипция порядка гейтов не читает эти поля,
значит «проверки близко/далеко», «аутентичности автора» и «согласованности вектора с кластером»
в решении **нет**. Тест так широко не говорит никогда: он видит только свои случаи. -/

theorem admit_ignores_distance (p : Profile) (k c v : Nat) (sg : Bool) (d₁ d₂ : Nat) :
    admit p { key := k, cluster := c, vec := v, dist := d₁, signed := sg } =
      admit p { key := k, cluster := c, vec := v, dist := d₂, signed := sg } := rfl

theorem admit_ignores_vector (p : Profile) (k c d : Nat) (sg : Bool) (v₁ v₂ : Nat) :
    admit p { key := k, cluster := c, vec := v₁, dist := d, signed := sg } =
      admit p { key := k, cluster := c, vec := v₂, dist := d, signed := sg } := rfl

/-- Подпись не меняет решения: в `node.rs:685` проверка стоит **под условием** самого флага,
поэтому неподписанный кадр с заявленным автором для решения неотличим от подписанного. -/
theorem admit_ignores_signature (p : Profile) (k c v d : Nat) :
    admit p { key := k, cluster := c, vec := v, dist := d, signed := true } =
      admit p { key := k, cluster := c, vec := v, dist := d, signed := false } := rfl

/-! ## (2) Отказ зависит от суммы и от наличия ключа — и больше ни от чего

∀-форма «защиты нет»: текущая дверь не умеет отказать *потому, что ячейка полна*. -/

theorem admit_refuses_only_by_total_and_key (p q : Profile) (r : Pub)
    (ht : total p = total q) (hh : has p r.key = has q r.key) :
    admit p r = admit q r := by
  unfold admit
  rw [← ht, hh]

/-- Размер ячейки растёт только у нового ключа; переезд размера не добавляет. -/
theorem cellAt_grows_only_for_newcomer (p : Profile) (r : Pub) (h : has p r.key = false) :
    cellAt (put p r) r.cluster = cellAt p r.cluster + 1 := by
  unfold put cellAt
  simp [h, List.filter_append]

theorem displacement_keeps_total (p : Profile) (r : Pub) (hk : has p r.key = true) :
    total (put p r) = total p := by
  unfold put total
  simp [hk]

/-! ## (3) Горячую ячейку можно собрать **из чужих записей** — это нашла модель, а не план

`put` переезжает: приём записи с уже живущим ключом меняет её кластер, не меняя `total`. Значит
надувать ячейку можно не только своими записями — достаточно перетащить существующие, и гейт
вместимости на это не реагирует по построению. -/

/-- Переезд принимается **при любой заполненности шарда** — гипотезы о вместимости не нужно. -/
theorem displacement_is_always_admitted (p : Profile) (k c₁ : Nat) (hk : has p k = true)
    (hcl : c₁ < CLUSTERS) :
    admit p { key := k, cluster := c₁, vec := 0, dist := 0, signed := true } = true := by
  unfold admit
  simp [hcl, hk]

/-- Стартовый профиль: три честные записи в разных ячейках. -/
def base : Profile := [(0, 1), (1, 2), (2, 3)]

/-- Два переезда, ни одного нового автора. Вектор и «расстояние» здесь — метки, модель их не
читает (`admit_ignores_vector`, `admit_ignores_distance`); `signed := false` — кадр без подписи,
для решения это то же самое, что подписанный (`admit_ignores_signature`). -/
def mig1 : Pub := { key := 1, cluster := 1, vec := 77, dist := 4242, signed := false }
def mig2 : Pub := { key := 2, cluster := 1, vec := 78, dist := 4242, signed := false }
def migrate : List Pub := [mig1, mig2]

/-- Свидетель: три записи в разных ячейках становятся одной горячей **без единой новой записи**. -/
theorem hot_cell_from_foreign_records :
    total (runFrom admit base migrate) = 3 ∧ cellAt (runFrom admit base migrate) 1 = 3 := by
  native_decide

/-! ## (4) Cap — это три разные политики, и две из них сломаны

`E-0078` показал, что «привязать индекс» — выбор политики. Здесь то же самое с «ограничить размер
ячейки»: три естественные формы, у каждой — своё ∀-свойство.

* `admitX` (льгота как у гейта вместимости: проверяется только новое место) — **дыра в ∀-форме**:
  переезд в полную ячейку разрешён всегда;
* `admitA` (проверяется всегда) — bound держится, но решение вообще не смотрит, где запись живёт,
  поэтому **честное продление в своей полной ячейке отвергается**: owner не может обновить
  запись, то есть cap ломает §11.3.2;
* `admitM` (проверяется только смена ячейки) — bound держится, продление проходит всегда, переезд
  в полную ячейку отвергается. -/

theorem cap_exemption_leaks (p : Profile) (k c₁ : Nat) (hk : has p k = true)
    (hfull : maxCell ≤ cellAt p c₁) (hcl : c₁ < CLUSTERS) :
    admitX p { key := k, cluster := c₁, vec := 0, dist := 0, signed := true } = true := by
  unfold admitX admit
  simp [hcl, hk, hfull]

/-- Конкретный leak на реальном профиле: после двух переездов ячейка 1 выше cap'а. -/
theorem capX_leak_on_base : overCap (runFrom admitX base migrate) = true := by
  native_decide

/-- При **cap без льготы** решение не смотрит на `cellOf` вовсе, поэтому продление записи,
которая уже лежит в полной ячейке, отвергается — независимо от того, что новых мест не занимает. -/
theorem cap_strict_ignores_where_record_lives (p : Profile) (k c : Nat)
    (hfull : maxCell ≤ cellAt p c) :
    admitA p { key := k, cluster := c, vec := 0, dist := 0, signed := true } = false := by
  unfold admitA
  simp [hfull]

theorem cap_migration_aware_allows_renewal (p : Profile) (k c : Nat)
    (here : cellOf p k = some c) (hcl : c < CLUSTERS) :
    admitM p { key := k, cluster := c, vec := 0, dist := 0, signed := true } = true := by
  have hk : has p k = true := has_of_cellOf p k c here
  unfold admitM admit
  simp [here, hcl, hk]

theorem cap_migration_aware_blocks_full_migration (p : Profile) (k c₀ c₁ : Nat)
    (here : cellOf p k = some c₀) (ne : c₀ ≠ c₁) (hfull : maxCell ≤ cellAt p c₁) :
    admitM p { key := k, cluster := c₁, vec := 0, dist := 0, signed := true } = false := by
  unfold admitM
  simp [here, ne, hfull]

/-! ## (5) Перебор всех расписаний длины ≤ 4

Это **не** индукция по всем расписаниям, а замкнутое пространство 83 521 случая: обобщают
∀-теоремы выше, здесь они проверяются числами. -/

theorem doorA_never_exceeds :
    (schedules 4).all (fun s => overCap (run admitA s) = false) = true := by native_decide

theorem doorM_never_exceeds :
    (schedules 4).all (fun s => overCap (run admitM s) = false) = true := by native_decide

/-- У политики с льготой переезда находится расписание с ячейкой больше cap … -/
theorem doorX_does_exceed :
    (schedules 4).any (fun s => overCap (run admitX s)) = true := by native_decide

/-- … а текущая политика доводит одну ячейку до общей вместимости шарда. -/
theorem door_current_reaches_total_cap :
    cellAt (run admit ((List.range CAP).map fun k =>
      { key := k, cluster := 0, vec := k, dist := 0, signed := false })) 0 = CAP := by
  native_decide

/-! ## (6) Что модель сказала измерять в Rust

* (1) три `rfl`-теоремы ⇒ у живого узла мерить **приём неподписанного `Publish` с чужим
  `owner_ed25519`** и приём записи с вектором, далеко от центроида заявленного кластера: если
  оба проходят, «защиты нет» перестаёт быть строкой спеки и становится измеренным фактом;
* (3) `displacement_is_always_admitted` ⇒ мерить **сборку горячей ячейки из уже принятых
  записей** (`total` не растёт — вместимость на это не смотрит), а не только рост своими;
* (2) ⇒ потолок надувания = `max_live_per_shard`, а не размер ячейки: мерить `cluster_len`
  при лимите 100 admits/с;
* (4) ⇒ proposed cap — это **три** политики, и на замере надо различать: leakage у формы с
  льготой, смерть продления у строгой формы, и survivable у формы с учётом переезда. Формулировка
  «per-cluster admission cap не реализован» в §14.4 (iv) недостаточна: надо указать какую из трёх
  внедрять, иначе внедрится первая и дыра станет невидимой;
* узловой бюджет тратится и на переезд, и на запись без прироста ⇒ «спам дешевле записи» **не**
  следует: цена токена равна цене настоящей записи (тот же PoW), это проверяется числом;
* ключевое отношение для замера: «цена записи для атакующего» к «цена скана горячего списка для
  каждого последующего `Find`». -/

#eval (schedules 4).length
#eval cellAt (run admit ((List.range CAP).map fun k =>
  { key := k, cluster := 0, vec := k, dist := 0, signed := false })) 0
#eval cellAt (runFrom admitX base migrate) 1
#eval cellAt (runFrom admitM base migrate) 1
#eval cellAt (runFrom admitA base migrate) 1

end VecDHT.Admission
