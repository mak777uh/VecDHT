-- E-0112 — свидетель имени аксиомы.
--
-- Файл вне `lab/lean/VecDHT/` намеренно: его не разбирает `lab/lean-check.py` (тот читает только
-- модели круга и замораживает их дайджесты), и он ничего не доказывает о продукте. Задача одна —
-- заставить kernel Lean назвать третью стандартную аксиому вслух, чтобы `AXIOM_ALLOWLIST` сверялся
-- с выводом чужой системы, а не с цитатой из чужого исходника.
--
-- Исполнение (тот же `lean`, что и в верификации круга):
--     lean lab/lean/KernelName.lean
-- Ожидаемая строка info: `'q' depends on axioms: [Quot.sound]`, и выход обязан быть нулевым.
--
-- `Quot.sound` — аксиома ядра (объявлена в `Init/Prelude.lean`), поэтому файл компилируется без
-- единого импорта: всё, что напечатает kernel, — про ядро же.
theorem q {α : Sort u} {r : α → α → Prop} {a b : α} (h : r a b) : Quot.mk r a = Quot.mk r b :=
  Quot.sound h

#print axioms q

-- Посадка, проверенная исполнением: файл, где вместо `Quot.sound` написано похожее `Quoted.sound`
-- `Quoted.sound`, kernel не принимает вовсе (`Unknown identifier`), то есть имени из прежнего
-- allowlist не существует ни в какой версии ядра. Ниже — тот же текст закомментированным: его
-- исполняет helper, собирая из него временный файл (`V912_DECOY_QUOTED_UNPARSABLE=1`).
-- theorem bad {α : Sort u} {r : α → α → Prop} {a b : α} (h : r a b) :
--   Quot.mk r a = Quot.mk r b := Quoted.sound h
