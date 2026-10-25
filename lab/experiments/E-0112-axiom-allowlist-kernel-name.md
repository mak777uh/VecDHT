---
id: E-0112
hypothesis: H-0112
status: pre-registered
base_commit: "c8e5d6e — дерево без прибора: файла `crates/vecdht-orders/tests/v912_axiom_names.rs`
нет, `lab/lean/KernelName.lean` нет, `AXIOM_ALLOWLIST` в `crates/vecdht-orders/src/lib.rs:85` содержит
`Quoted.sound`. PRE_FIX снят исполнением до коммита пре-регистрации и заморожен в
`lab/logs/e0112-prefix.log` (выход 101): `V912_ALLOWLIST=propext|Classical.choice|Quoted.sound`,
`V912_HONEST_QUOT_ACCEPTED=0`, `V912_FAKE_QUOTED_REJECTED=0`, `V912_EMPTY_AXIOM_CONTROL=1`,
`V912_NONLEAN_NAMES_AXIOMS=1`, `V912_ALLOWLIST_HAS_QUOT_SOUND=0`,
`V912_ALLOWLIST_HAS_QUOTED_SOUND=1`, `V912_ALL_OK=0`. Свидетель и посадка на том же дереве:
`lean lab/lean/KernelName.lean` даёт `'q' depends on axioms: [Quot.sound]` при нулевом выходе, а
`lean` на файле с `Quoted.sound h` — `error(lean.unknownIdentifier)` с текстом
Unknown identifier Quoted.sound, при выходе 1. Правка одна: третья позиция списка"
started: "2026-10-25"
finished: ""
environment: "Windows, x8_64-pc-windows-gnu; rustc 1.99.1; PATH включает /c/Users/Admin/mingw64/bin;
`lean` 4.36.0-rc1 (commit c9afcddf514a6772bd4d649f7cfc04eff0b9f15e, Release) через elan.
Debug-профиль: утверждение — о принадлежности строки множеству, а не о скорости; release дал бы тот
же вывод. Одна crate, два тест-таргета, один `.lean`-файл; никаких стендов и сетей"
command: "bash lab/e0112-run.sh: gate H-0112 ДО замера и носитель (диск/RAM/pagefile), два прогона
`cargo test -q -p vecdht-orders --test v912_axiom_names -- --nocapture` на неизменном дереве,
пересъёмка `docs/PAID_ORDER-VECTORS.md` тем же деревом
(`V9_VECTORS_OUT=$DOC cargo test -q -p vecdht-orders --test paid_order_vectors`), свидетель имени из
`lean lab/lean/KernelName.lean` + посадка на `Quoted.sound`, сверка строки документа с правилом
вывода и sha против замороженного прежнего, `python lab/xcheck-paid-orders.py`, `audit -n 5`,
`bash lab/workspace-verify.sh E-0112`, стража текста по файлам цикла, сверка
`lab/expectations/e0112.tsv`, носитель после, баланс цикла (`lab/ledger.py`)"
threshold: "Заморожено вместе с `lab/expectations/e0112.tsv` (44 ключа), оракулом и helper'ом ДО
замерного прогона. Выведены из §V9.5 (вердикт — функция от имени, которое назвал kernel), §V9.8
(`E_AXIOM_NOT_ALLOWED`), строки `OPEN-V9-10` и PRE_FIX-снимка, а не из прогона.
Двусторонний дефект: `V912_HONEST_QUOT_ACCEPTED=1`, `V912_FAKE_QUOTED_REJECTED=1`,
`V912_ALLOWLIST_HAS_QUOT_SOUND=1`, `V912_ALLOWLIST_HAS_QUOTED_SOUND=0`, `V912_ALL_OK=1`,
`E0112_RUST_EXIT=0`. Имя называет ядро: `V912_LEAN_RC=0`, `V912_KERNEL_NAME=Quot.sound`,
`V912_KERNEL_NAME_IN_ALLOWLIST=1`. Посадка и тулчейн: `V912_DECOY_LEAN_RC=1`,
`V912_DECOY_QUOTED_UNPARSABLE=1`, `V912_LEAN_TOOLCHAIN=4.36.0-rc1` — версия входит в ожидание
намеренно: имя аксиомы есть свойство конкретного ядра, и без этой привязки «сверено с ядром» было бы
обещанием, а не фактом. Контроли, которые правка обязана оставить в покое:
`V912_EMPTY_AXIOM_CONTROL=1`, `V912_NONLEAN_NAMES_AXIOMS=1`, `V912_ALLOWLIST_SIZE=3`,
`V912_ALLOWLIST=propext|Classical.choice|Quot.sound`. Носитель векторов:
`V912_DOC_ALLOWLIST=propext|Classical.choice|Quot.sound` (побайтно то же множество, что печатает
правило вывода), `V912_DOC_HAS_QUOTED=0`, `V912_DOC_HAS_QUOT=1`,
`V912_PREV_DOC_SHA=c5de2ae0671a637c51ff71b9dd34dbf80da08a10616f029ffb99926718712935`,
`V912_DOC_SHA_CHANGED=1`. Инварианты (правка не имеет права их сдвинуть):
`V9_W1_SHA=6d37fa9f…56bc98`, `V9_W2_SHA=6e3cdf66…a52dff`, `V9_W3_SHA=1471cef6…c64564`,
`V9_W_PY_MATCHES=3`, `V9_WORKED_PARSED=3`, `V9_WORKED=3`, `V9_VECTORS=30`,
`V9_CODES_COVERED=18`, `V9_CODES_TOTAL=18`, `V9_W_DECOY_FIRED=1`, `V9_W_TAG0_COLLISION=1`,
`V9_MATRIX_ROWS=10`, `V9_DOC_EMPTY_CELLS=0`, `V9_DOC_DECOY_FIRED=1`, `V9_SPEC_ROWS=10`,
`V9_SPEC_DOC_MISMATCH=0`, `V9_SPEC_DECOY_FIRED=1`. Служебные: `GATE_H0112_OK=1`, `E0112_RUNS=2`,
`VECTOR_STABLE=1`, `AUDIT_VIOLATIONS=0`, `VERIFY_EXIT=0`, `DISK_GE_15000=1`.
Печатаются, но в замороженные ожидания не входят: `V9_VECTORS_SHA` и `V912_DOC_SHA` (это следствие
правки, его предсказать до прогона нельзя — предсказано только «изменится»), `LEDGER_*` (цена цикла, а не свойство правила вывода). Правило 7 (е): в вердикт входит только то,
что совпало в обоих прогонах на неизменном дереве (`VECTOR_STABLE=1`)"
result: ""
verdict: ""
---

# E-0112 — `AXIOM_ALLOWLIST`: имя, которое печатает ядро, а не то, которое мы набрали

## Pre-registration (до прогона)

Вопрос: называется ли третья стандартная аксиома Lean 4 в нашем правиле вывода вердикта (§V9.5) тем
именем, которое под этот термин печатает kernel, и что происходит с обеими сторонами расхождения —
честным `Quot.sound` и выдуманным `Quoted.sound`?

Права на ошибку, из-за которой цикл затеян. §V9.5 определяет вердикт как функцию от байтов:
сторонний верификатор обязан уметь вывести его, не доверяя узлу. Узел читает из квитанции список
аксиом, которые назвал kernel, и сверяет с закрытым множеством из трёх строк. Если наша строка не
из того алфавита, правило перестаёт быть правилом: оно либо отвергает доказательства, которые ядро
считает стандартными, либо принимает имя, которое ядро никогда не назовёт. Второе хуже — проверка
становится проверкой на опечатку, а замкнутость множества теряется.

`OPEN-V9-10` описывал это как «дыру в приемлемости честных доказательств». Разбор (`L-0035`, ДИАГНОЗ-3
`E-0111`) показал, что дефект двусторонний, и потому он проверяется двумя гейтами в одном тесте, а не
одним: `V912_HONEST_QUOT_ACCEPTED` и `V912_FAKE_QUOTED_REJECTED`.

Что уже исполнено до пре-регистрации (чтобы красный прогон не был пересказом):
`lab/logs/e0112-prefix.log` — выход 101, `V912_HONEST_QUOT_ACCEPTED=0`,
`V912_FAKE_QUOTED_REJECTED=0`, `V912_ALLOWLIST_HAS_QUOTED_SOUND=1`, `V912_ALL_OK=0` при работающих
контролях. Свидетель имени: `'q' depends on axioms: [Quot.sound]`, посадка с `Quoted.sound` —
`Unknown identifier`, выход 1.

Свидетель выбран не случайно. Прежний способ («в исходниках Lean написано `Quot.sound`») — цитата
чужого текста; наш прибор обязан спрашивать имя у установленного ядра, потому что риск как раз в
том, что правило вывода сверяется со строкой, а не с тем, что печатает ядро при `#print axioms`.
`KernelName.lean` лежит вне `lab/lean/VecDHT/`, чтобы страж моделей (`lab/lean-check.py`) не считал
его моделью: это свидетель-исполнение, а не теорема о продукте.

Границы замера: правка меняет одну константу продукта и две строки порождённого D2; спека D1 (§V9.5,
§V9.8, §V9.9, таблица границ) правится отдельным коммитом после закрытия, потому что внутри
замерного цикла `docs/` обязан оставаться нетронутым. Привязка allowlist к digest образа верификатора
(§V9.10, горизонт H2) этим циклом не закрывается.

## Прогон

Ещё не исполнен: карточка заморожена до прогона (шаг 2 жизненного цикла, `lab/README.md`).

## Результат

Заполняется после `bash lab/e0112-run.sh` и `python lab/expect.py lab/expectations/e0112.tsv …`.

## ДИАГНОЗы

Заполняются после прогона.
