---
id: E-0143
hypothesis: H-0143
status: closed
verdict: supports
base_commit: "d835f5b"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; bash, python и cargo — прибор читает документ и
четыре владельца в дереве (карточки `E-0121`/`E-0119`, `crates/vecdht-cli/src/node_cmd.rs`,
`crates/vecdht-cli/src/args.rs`, два файла тестов), но продукт не правит (`RUST_TOUCHED=0`), сеть не
поднимает; документ пина извлекается `git show <пин>:docs/STATUS-v1.md` во временный файл и судится
`--doc` на тех же фактах дерева, рабочее дерево и индекс не трогаются; дата карточки судится по UTC
(`ADR-0070`)"
command: "bash lab/e0143-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0143.tsv run1.txt run2.txt`); PRE_FIX — тот же helper, `git show` пина во временный
каталог; `python lab/check-status-claims.py selftest`"
threshold: "(1) `python lab/cycle-gate.py gate H-0143` выход 0 (`GATE_H0143_OK=1`), диск ≥ 15 000 МБ
(`DISK_GE_15000=1`); (2) дыра названа отсутствием: `PIN_FOUND=1`, `PRE_FIX_INSTRUMENT=0`,
`PRE_FIX_STALE=none`, `PRE_FIX_KEYS=0`; (3) самопроверка прибора: `SELFTEST_EXIT=0`,
`SELFTEST_TOTAL=13`, `SELFTEST_PASSED=13`; (4) документ пина: `CHK_PREFIX_EXIT=1`,
`CHK_PREFIX_STALE=3`, `CHK_PREFIX_CONSISTENT=1`, `CHK_PREFIX_IDS=S-01,S-02,S-04`,
`CHK_PREFIX_REASONS=S-01:doc-contradicts,S-02:doc-contradicts,S-04:doc-contradicts`, `PRE_S01=stale`,
`PRE_S02=stale`, `PRE_S03=consistent`, `PRE_S04=stale`, документ пина не пуст
(`CHK_PREFIX_DOC_PRESENT=1`); (5) исправленный документ: `CHK_EXIT=0`, `CHK_OK=1`,
`CHK_STALE=0`, `CHK_IDS=none`, `CHK_CLAIMS=4`, `CHK_CONSISTENT=4`, `CHK_FACTS=9`, `CHK_FACTS_OK=9`,
`CHK_FACTS_MISSING=none`, `POST_S01..S04=consistent`; (6) носители утверждений:
`cargo test -q -p vecdht-cli --test node_centroids` — 2 passed, `--test node_run` — 3 passed, выходы 0
и `ORACLE_TESTS_OK=1`; (7) страж исполняется из CI: `CI_STATUS_STEP=1`; (8) соседние стражи и гейты
зелёные (`SECRETS_EXIT`, `REFS_EXIT`, `CLAIMMAP_EXIT`, `CLAIMS_EXIT`, `CONTOURS_EXIT`,
`TEXTGUARD_ALL_EXIT`, `TEXTGUARD_ALL_DIRTY=0`, `TEXTGUARD_CYCLE_EXIT`, `MIRROR_EXIT`,
`LINT_LATEST_EXIT`, `LINT_ORPHANS=0`, `GATE_AUDIT_EXIT`, `REVIEW_EXIT`), `RUST_TOUCHED=0`,
`WORST_RC=0`; (9) `python lab/expect.py lab/expectations/e0143.tsv` по двум прогонам:
`ОЖИДАНИЙ=55 РАСХОЖДЕНИЙ=0`, `STABLE=1`. Порог заморожен до первого прогона `lab/e0143-run.sh`;
изменение любого числа — новая карточка."
---

# E-0143 — статус-документ против дерева: четыре утверждения и их владельцы

## Что проверяется

`docs/STATUS-v1.md` утверждает наличие и отсутствие возможностей, и часть строк уже разошлась с
деревом: «The shipping binary does not load centroids yet» при закрытом `E-0121`, «there is no
\"start a node\" command … is P6» при работающем `node run` (`E-0119`) и число «1333 backtick
citations» при счётчике стража 1580. Круг заводит прибор `lab/check-status-claims.py`, который
связывает четыре строки с владельцами (карточка закрыта `supports`, символ в продукте, файл теста,
имя стража) и судит обе стороны: документ слабее дерева и документ сильнее дерева — оба находка.

## Почему это не косметика

Строка «команды запуска узла нет» читается как «P6 не сделан» и обесценивает четыре закрытых
круга (`E-0119`, `E-0121`, `E-0122`, `E-0124`); строка «бинарник не грузит центроиды» противоречит
соседней строке того же документа. Число в прозе не пересчитывает никто: 1333 против 1580 — это не
опечатка, а отсутствие владельца у факта (`E-0141`, правило «у имени факта один владелец»).

## Границы

Прибор ловит названные формы, а не смысл: новая формулировка обходит его так же, как обходила
прежняя, поэтому у каждого утверждения перечислены и положительная, и отрицательная форма. Он не
доказывает поведение — что `with_centroids` грузит центроиды, доказывает `node_centroids.rs`, и
носитель круга прогоняет его отдельно. Условие 3 (`ADR-0044`) не закрывается: прогон на второй
машине остаётся за владельцем (`E-0142`, `OPEN-QUESTIONS` п. 82).

## Результат (официальные прогоны)

Порог исполнен: `GATE_H0143_OK=1`, `DISK_GE_15000=1`; прибора в пине нет (`PRE_FIX_INSTRUMENT=0`,
`PRE_FIX_STALE=none`, `PRE_FIX_KEYS=0`); самопроверка `SELFTEST_TOTAL=13`, `SELFTEST_PASSED=13`;
документ пина — `CHK_PREFIX_EXIT=1`, `CHK_PREFIX_STALE=3`, `CHK_PREFIX_CONSISTENT=1`,
`CHK_PREFIX_IDS=S-01,S-02,S-04`, все три с причиной `doc-contradicts`, `PRE_S03=consistent`;
исправленный документ — `CHK_EXIT=0`, `CHK_OK=1`, `CHK_STALE=0`, `CHK_IDS=none`, `CHK_CLAIMS=4`,
`CHK_CONSISTENT=4`, `CHK_FACTS=9`, `CHK_FACTS_OK=9`, `CHK_FACTS_MISSING=none`, `POST_S01..S04=consistent`;
носители — `ORACLE_NODE_CENTROIDS_PASSED=2`, `ORACLE_NODE_RUN_PASSED=3`, `ORACLE_TESTS_OK=1`;
`CI_STATUS_STEP=1`; все соседние стражи 0, `LINT_ORPHANS=0`, `RUST_TOUCHED=0`, `WORST_RC=0`.

Два исполнения на неизменном дереве `6b7fc74` сверились с таблицей целиком:
`ОЖИДАНИЙ=55 РАСХОЖДЕНИЙ=0`, `STABLE=1`. Полный контур `workspace-verify.sh E-0143`:
`VERIFY_FAIL=0`, 134 среза, 786 тестов, 0 падений, 9 `#[ignore]`, `SECONDS_total=2162`,
диск 23 052 → 22 961 МБ.

## Итог исполнения

Пре-регистрация `5d56e99`, починка `b94526a` и `6b7fc74` (после ДИАГНОЗА-1), носитель
`lab/logs/e0143-all.log`. Продукт не тронут (`RUST_TOUCHED=0`): цикл документный, а поведение
владельцев строк доказывают их собственные тесты, которые носитель прогоняет отдельно. Страж
`lab/check-status-claims.py` стоит в `.github/workflows/verify.yml`. Условие 3 релиза не засчитано.
Остатки — `OPEN-QUESTIONS` п. 83; голова очереди в зелёной зоне — флаги `--class`/`--dir`
(Batch C, п. 53.2, `E-0100`).
