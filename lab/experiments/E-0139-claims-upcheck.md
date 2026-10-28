---
id: E-0139
hypothesis: H-0139
status: pre-registered
verdict: pending
base_commit: "46641f6"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; только bash и python — цикл не исполняет cargo и
не поднимает сеть, потому что измеряет связность собственного реестра с собственными носителями;
посадка работает копией `lab/claims.tsv` с `trap`-возвратом, носители (`docs/STATUS-v1.md`,
`README.md`, `README.ru.md`) во время прогона не трогаются; PRE_FIX исполняется посадкой пина
(`git checkout $PIN -- lab/claims.tsv`) и доказательством числа строк пина через `git show`; дата
карточки судится по UTC (`ADR-0070`)"
command: "bash lab/e0139-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0139.tsv`); PRE_FIX — тот же helper, посадка пина с `trap`-возвратом"
threshold: "(1) `python lab/cycle-gate.py gate H-0139` выход 0 (`GATE_H0139_OK=1`), диск ≥ 15 000 МБ
до прогона; (2) самопроверка исполняется: `PLANTED_TOTAL=8`, `PLANTED_CAUGHT=8`, `PLANTED_FALSE=0`,
`LEGAL_TOTAL=6`, `UP_PLANTED=3`, `UP_CAUGHT=3`, `UP_FALSE=0`, `SELFTEST_EXIT=0`; (3) PRE_FIX называет
дыру числом: `PRE_FIX_PIN_FOUND=1`, `PRE_FIX_PIN_ROWS=17`, `PRE_FIX_PIN_ROWS_LIVE=37`,
`PRE_FIX_PLANTED=1`, `PRE_FIX_EXIT=1`, `PRE_FIX_CLAIMS=17`, `PRE_FIX_TRIGGER_SENTENCES=26`,
`PRE_FIX_UNREGISTERED=20`, `PRE_FIX_UP_CARRIERS=3`, `PRE_FIX_VIOLATIONS=20`, все нисходящие ключи
(`DANGLING`, `CEILING`, `QUALIFIER`, `TYPE_BAD`, `LINK_BAD`, `GATE_RATIO`, `COND_LINK_BAD`) нули,
`PRE_FIX_CONDITIONS_TABLE=5`, `PRE_FIX_CONDITIONS_COVERED=5`, `PRE_FIX_READY_CARRIERS=3`,
`PRE_FIX_READY_VALUES=1`, `PRE_FIX_DIFFERS=1`, `PRE_FIX_TRIGGER_EQUALS_LIVE=1`; (4) живое дерево после
починки зелёное: `GUARD_EXIT=0`, `LIVE_CLAIMS=37`, `LIVE_TRIGGER_SENTENCES=26`, `LIVE_UNREGISTERED=0`,
`LIVE_UP_CARRIERS=3`, `LIVE_VIOLATIONS=0`, `LIVE_DANGLING=0`, `LIVE_CEILING=0`, `LIVE_QUALIFIER=0`,
`LIVE_TYPE_BAD=0`, `LIVE_LINK_BAD=0`, `LIVE_GATE_RATIO=0`, `LIVE_COND_LINK_BAD=0`,
`LIVE_CONDITIONS_TABLE=5`, `LIVE_CONDITIONS_COVERED=5`, `LIVE_READY_CARRIERS=3`, `LIVE_READY_VALUES=1`,
`LIVE_UNREGISTERED_LIST=none`, `CLAIMS_INSTRUMENT_EXISTS=1`, `CLAIMS_REGISTRY_ROWS=37`; (5) прибор
стоит в контуре и в CI: `VERIFY_WIRES_CLAIMS=1`, `CI_WIRES_CLAIMS=1`; (6) соседние стражи не
рассоединились: `SECRETS_EXIT=0`, `REFS_EXIT=0`, `CLAIMMAP_EXIT=0`, `CONTOURS_EXIT=0`,
`TEXTGUARD_ALL_EXIT=0`, `TEXTGUARD_ALL_DIRTY=0`, `TEXTGUARD_CYCLE_EXIT=0`, `MIRROR_EXIT=0`,
`LINT_EXIT=0`, `LINT_ORPHANS=0`, `GATE_AUDIT_EXIT=0`, `REVIEW_EXIT=0`; (7) продукт не тронут:
`RUST_TOUCHED=0`; (8) `WORST_RC=0` и два исполнения на неизменном дереве печатают один вектор —
`STABLE=1`. Порог заморожен до первого официального прогона `lab/e0139-run.sh`; изменение любого
числа — новая карточка. Вектор снимается на дереве починки до прогона полного контура: блок
`E-0139 · workspace-verify` появляется в контуре закрытия и сдвинул бы соседа `check-contours.py`
(`CLOSED_TOTAL`), поэтому постконтурное число печатается в носителе отдельно и в порог не входит."
---

# E-0139 — восходящая сверка реестра утверждений с носителями

Карточка заведена вместе с прибором (`lab/check-claims.py`, ключи `TRIGGER_SENTENCES`,
`UNREGISTERED`, `UP_CARRIERS`, `UNREGISTERED_LIST`) и таблицей ожиданий `lab/expectations/e0139.tsv`.
Утверждение, фальсификатор и оракул — в `lab/hypotheses/H-0139-claims-upcheck.md`; здесь лежит только
замороженный порог.

## Что уже измерено до официальных прогонов (разведка прибором)

Прибор прогнан на живом дереве при сборке. Три носителя печатают `TRIGGER_SENTENCES=26`, из них
`UNREGISTERED=20`, `UP_CARRIERS=3`, `CLAIMS=17`, `VIOLATIONS=20`, `DANGLING=0`, `CEILING=0`,
`CONDITIONS_TABLE=5`, `CONDITIONS_COVERED=5`, `READY_VALUES=1`, выход 1. Самопроверка: 8/8 нисходящих
посадок отбиты, `PLANTED_FALSE=0`, `LEGAL_TOTAL=6`, восходящих посажено 3 и поймано 3, `UP_FALSE=0`.

## Дыра, найденная уже этим кругом при сборке прибора

Первая версия восходящей сверки считывала заголовок `# Status of v1: gates, what closed them, and what
is not there` как утверждение: нормализация склеивала строку с следующим предложением, и ложная находка
уводила число дыры. Починка — заголовки markdown исключены из носителя до разрезки на предложения
(`body_for_up`), что изменило вектор разведки с `TRIGGER=28, UNREGISTERED=22` на `26` и `20`. Второй
находкой стал собственный лексикон прибора: тип `estimate` требовал слова `оценка` и не принимал
`оценкой`, а `NEGATION` для `not-done` знал только английские отрицания, поэтому русская строка «не
сделано, как есть» не проходила потолок и регистрировать её было нечем. Оба случая — тот же класс, что
у `E-0138`: проверка формы там, где надо проверять множество, и список слов там, где надо проверять
корень.
