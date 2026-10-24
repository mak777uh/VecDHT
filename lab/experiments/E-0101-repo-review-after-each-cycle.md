---
id: E-0101
hypothesis: H-0101
status: pre-registered
base_commit: "2925bf2 (дерево до прибора и до правок карточек: PRE_FIX-находки снимаются с его архива, а не с памяти)"
started: "2026-10-24"
finished: null
environment: "Windows, x86_64-pc-windows-gnu; rustc 1.99.1; Python 3 (PyYAML). Сети нет. Приборы: `python lab/repo-review.py selftest` и `check`, архив базового дерева `git archive 2925bf2`, гейт круга, `bash lab/workspace-verify.sh E-0101` (cargo test --workspace, clippy, Lean, Verus, Kani-компиляция, самопроверки приборов). `RAYON_NUM_THREADS=2`, PATH включает `/c/Users/Admin/mingw64/bin`"
command: "bash lab/e0101-run.sh (заморожен этим коммитом; исполняется неизменяемой mktemp-копией).
Порядок: (0) PRE_FIX — `git show 2925bf2:lab/repo-review.py` (0 строк), grep `repo-review` по
`lab/workspace-verify.sh` того же дерева (0), прогон прибора по архиву `2925bf2` (ожидаемо 5
находок); (1) `python lab/repo-review.py selftest` ×2 — 8 кейсов; (2) `check` ×2 — 0 находок;
(3) `python lab/cycle-gate.py gate H-0101 --skip-lean` ×2 и `audit -n 5` ×2; (4) сверка вектора
`python lab/facts.py repro --strip-run`; (5) `bash lab/workspace-verify.sh E-0101`; затем
`bash lab/check-text-clean.sh <файлы цикла>` и `python lab/expect.py lab/expectations/e0101.tsv`.
Лог — `lab/logs/e0101-all.log` (append-only, контроль от отметки начала блока)"
threshold: "Заморожено этим коммитом вместе с `lab/expectations/e0101.tsv` и helper'ом. Ожидания
выведены из арифметики прибора и посадок, а не из прогона: PRE_FIX — `PREFIX_REVIEW_SCRIPT=0`,
`PREFIX_VERIFY_REFS=0`, `PREFIX_FINDINGS=5`, `PREFIX_TOP=closed-empty-result:4` (пять находок
перечислены `H-0101`); самопроверка — `REVIEW_SELFTEST_TOTAL=8`, `REVIEW_SELFTEST_PASSED=8`; на дереве
после правки — `REVIEW_FINDINGS=0`, `REVIEW_TOP=none:0`, все классы по нулю, `REVIEW_CLOSED_EMPTY=0`,
`REVIEW_TESTING_CLOSED=0`, `REVIEW_IGNORED_NO_REASON=0`, `REVIEW_EXPECT_ORPHANS=0`,
`REVIEW_HELPER_ORPHANS=0`, `REVIEW_MISSING_EXPERIMENTS=0`, `REVIEW_REFS_STALE=0`; инвентарь без
вердикта `REVIEW_IGNORED=9`, `REVIEW_BIG_RS=4`, `REVIEW_TODOS=0`, `REVIEW_MD_FILES=243`,
`REVIEW_REFS_OK=627`. `GATE_H0101_OK=1`, `AUDIT_VIOLATIONS=0`, `AUDIT_CARDS=5`. `REPRO_VECTOR=1` —
два прогона каждого прибора на неизменном дереве дают одинаковый вектор (правило 7 (е)).
`REVIEW_IN_VERIFY=1` — блок `E-0101` в логе верификации содержит самопроверку прибора и
`REVIEW_FINDINGS=0`; без этого прибор написан, но не встроен. Ресурсный порог (11) читается тройкой
чисел; `DISK_GE_15000=1` фиксирует факт на этом хосте в момент шага 0 и не подгоняется.
Фальсификаторы — пять пунктов из `H-0101`. Продуктовый код и спека продукта не трогаются"
result: null
verdict: pending
---

# E-0101 — самопроверка репозитория после цикла: прибор, посадки и встраивание

## Что замеряется

Что после цикла всё дерево обходится прибором, который (а) находит уже накопленные слабости,
(б) краснеет на посаженных дефектах каждого класса, (в) молчит на чистом дереве и (г) исполняется
закрытием цикла, а не существует отдельным файлом.

## Почему карточка открыта до правки карточек

Пять находок — не мнение, а результат прибора, применённого к **архиву** базового дерева `2925bf2`.
Порог `PREFIX_FINDINGS=5` снимается с архива, а не с живого дерева после правок; поэтому «ноль после
правки» означает, что правка закрыла именно эти пять классов, а не что прибор разучился искать.
Чистое дерево в самопроверке ловит обратное: прибор, который «находит» всё подряд, тоже неверен.

Честно о порядке: прибор и правки карточек написаны до заморозки, поэтому ожидания `check` — это
арифметика механики (0 находок), а не предсказание шумного измерения. Единственное число, снятое с
дерева до правок, — `PREFIX_FINDINGS=5`: оно берётся с архива `2925bf2` и потому не может быть
подогнано под результат. Замороженный helper на дереве после правок ещё не исполнялся.

## Границы

Прибор не судит качество текста и не проверяет, что `путь:строка` ведёт на нужную строку — только что
она не за концом файла. `REVIEW_BIG_RS`/`REVIEW_TODOS` — инвентарь, а не вердикт. `testing` при
закрытом эксперименте не находка, если карточка объясняет, почему окно не набрано.
