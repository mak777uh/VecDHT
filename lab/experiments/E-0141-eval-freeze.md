---
id: E-0141
hypothesis: H-0141
status: pre-registered
verdict: pending
base_commit: "e98674d"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; только bash, python и компилятор Lean — цикл не
исполняет cargo и не поднимает сеть, потому что измеряет связность собственного стража с собственными
моделями; посадка работает временными копиями дерева (`git show пин:файл` с перенаправлением во
временный каталог), живой индекс и рабочее дерево во время прогона не трогаются — форма
`git checkout <пин> -- файл` отвергнута, потому что пишет в индекс (круг `E-0139`, ДИАГНОЗ-3); модели
`lab/lean/VecDHT/*.lean` починка не правит (`MODELS_TOUCHED=0`), правится только прибор и его
замороженные снимки; каждая посадка проверена на компилируемость до заморозки порога, иначе пин
краснел бы по чужой причине; дата карточки судится по UTC (`ADR-0070`)"
command: "bash lab/e0141-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0141.tsv run1.txt run2.txt`); PRE_FIX — тот же helper, три посадки на дереве пина и
три на живом дереве; `python lab/lean-check.py selftest`"
threshold: "(1) `python lab/cycle-gate.py gate H-0141` выход 0 (`GATE_H0141_OK=1`), диск ≥ 15 000 МБ
до прогона (`DISK_GE_15000=1`); (2) классы форм посчитаны по дереву: `THEOREM_TOTAL=148`,
`LEMMA_TOTAL=0`, `DEF_TOTAL=217`, `EVAL_TOTAL=47`, `STRUCT_TOTAL=5`, `INDUCTIVE_TOTAL=4`,
`PIN_FROZEN_ROWS=365`, `FROZEN_ROWS=421`, `PIN_MODELS_DIFF=0`, `MODELS_TOUCHED=0`,
`RUST_TOUCHED=0`; (3) PRE_FIX называет дыру: `PIN_FOUND=1`, `PRE_FIX_INSTRUMENT=1`, три посадки
исполнены (`PIN_EVAL_PLANTED=1`, `PIN_STRUCT_PLANTED=1`, `PIN_INDUCTIVE_PLANTED=1`), пин зелёный без
единой причины (`PIN_EVAL_EXIT=0`, `PIN_STRUCT_EXIT=0`, `PIN_INDUCTIVE_EXIT=0`, все
`PIN_*_ALL_OK=1`, все `PIN_*_REASONS=0`), `PRE_FIX_HOLE=1`; (4) живой прибор отбивает все три класса
по своей причине: `LIVE_EVAL_EXIT=1`, `LIVE_STRUCT_EXIT=1`, `LIVE_INDUCTIVE_EXIT=1`,
`LIVE_*_CAUGHT=1`, `LIVE_EVAL_KEY=1`, `LIVE_STRUCT_KEY=1`, `LIVE_INDUCTIVE_KEY=1`, все
`LIVE_*_COMPILE=0`, `PRE_FIX_DIFFERS=1`; (5) годное живое дерево зелёное и покрыто:
`BASE_CHECK_EXIT=0`, `BASE_ALL_OK=1`, `BASE_FROZEN_ROWS=421`, `BASE_DECLS_TOTAL=148`,
`BASE_EXTRAS_TOTAL=56`, `BASE_BROKEN=0`, `BASE_DIGEST_BAD=0`, `EXTRA_PARSER_OK=1`,
`FREEZE_MATCHES_CHECK=1`; (6) самопроверка стража исполняется и отбивает новые классы:
`SELFTEST_EXIT=0`, `LS_TOTAL=14`, `LS_PASSED=12`, `LS_FROM=12`, `LS_GOOD_TREE=1`; (7) прибор стоит в
контуре и в CI: `VERIFY_WIRES_LEANCHECK=1`, `CI_WIRES_LEANCHECK=1`; (8) соседние стражи не
рассоединились: `SECRETS_EXIT=0`, `REFS_EXIT=0`, `CLAIMMAP_EXIT=0`, `CLAIMS_EXIT=0`, `CONTOURS_EXIT=0`,
`TEXTGUARD_ALL_EXIT=0`, `TEXTGUARD_ALL_DIRTY=0`, `TEXTGUARD_CYCLE_EXIT=0`, `MIRROR_EXIT=0`,
`LINT_EXIT=0`, `LINT_ORPHANS=0`, `GATE_AUDIT_EXIT=0`, `REVIEW_EXIT=0`; (9) `WORST_RC=0` и два
исполнения на неизменном дереве печатают один вектор — `STABLE=1`. Порог заморожен до первого
официального прогона `lab/e0141-run.sh`; изменение любого числа — новая карточка. Вектор снимается на
дереве починки до прогона полного контура: блок `E-0141 · workspace-verify` появляется только в контуре
закрытия и сдвинул бы соседа `check-contours.py` (`CLOSED_TOTAL`), поэтому постконтурное число
печатается в носителе отдельно и в порог не входит."
---

# E-0141 — заморозка печатаемых форм моделей Lean

Карточка заведена вместе с прибором (`lab/e0141-run.sh`), расширением стража (`lab/lean-check.py`,
парсер печатаемых форм и третий класс дайджеста) и таблицей ожиданий `lab/expectations/e0141.tsv`.
Утверждение, фальсификатор и оракул — в `lab/hypotheses/H-0141-eval-freeze.md`; здесь лежит только
замороженный порог.

## Что уже измерено до официальных прогонов (разведка прибором)

Число форм посчитано по дереву независимым `grep`ом: `theorem` 148, `lemma` 0, `def`/`abbrev` 217,
`#eval` 47, `structure` 5, `inductive` 4; замороженных строк в `lab/lean/frozen/` — 365 (= 148 + 217).
Печатаемых форм вне заморозки, следовательно, 56.

Три посадки прогнаны нынешним прибором на временных копиях живых моделей (компилятор Lean, каждая
посадка компилируется без ошибок): ослабление `#eval`-числа в `Bounded.lean`, перестановка полей в
`structure Point`, перестановка конструкторов в `inductive Mem`. Все три — `rc=0`, `LEAN_ALL_OK=1`,
`FROZEN_ROWS=365`, строк «изменена после заморозки» ноль. То есть дыра измерена, а не описана:
страж зелёный на дереве, где напечатанное моделью число уже другое.

## Что починка обязана изменить и чего не обязана

Изменяет: `lab/lean-check.py` (парсер печатаемых форм, вход `frozen_pairs()`, счётчик-страж
`EXTRAS_TOTAL`) и шесть файлов `lab/lean/frozen/*.statements.tsv` (перезаморозка `--cycle E-0141`,
365 → 421 строки). Не изменяет: модели, продукт, спеку, носители статусов, счёт аксиом, пороги других
приборов, `#[ignore]`-сценарии. Утверждение C-015 в реестре («соответствие модели и кода не проверено
исполняемым прибором») починка не отменяет и не переформулирует.
