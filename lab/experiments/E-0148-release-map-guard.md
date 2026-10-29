---
id: E-0148
hypothesis: H-0148
status: closed
verdict: "supports"
base_commit: "e1ac26e"
started: "2026-10-29"
environment: "x86_64-pc-windows-gnu, хост владельца; Python 3 и bash; сеть наружу не используется;
PRE_FIX снимается из пина через `git show`; продукт не собирается — круг документный"
command: "bash lab/e0148-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0148.tsv run1.txt run2.txt`); носители —
`python lab/check-release-map.py selftest` и `python lab/check-release-map.py`"
threshold: "(1) пин: `PIN_FOUND=1`, `PIN_MAP_FOUND=1`, `PRE_FIX_GUARD_ABSENT=1`,
`PRE_FIX_FALSE_ROW=1`, `PRE_FIX_LIE_PASSES=1`; (2) стражи: `POST_FIX_LIE_CAUGHT=1`,
`POST_FIX_LIE_IDS=M-14`, `POST_FIX_NUMBER_CAUGHT=1`, `POST_FIX_OWNER_CAUGHT=1`, `SELFTEST_EXIT=0`,
`SELFTEST_TOTAL=15`, `SELFTEST_PASSED=15`, `SELFTEST_FAILED=0`; (3) карта: `MAP_EXIT=0`,
`MAP_ROWS=16`, `ROWS_REGISTERED=16`, `ROWS_UNREGISTERED=0`, `ROWS_MISSING=0`, `MAP_DUP=0`,
`EIDS=25`, `EIDS_MISSING=0`, `EIDS_OPEN=0`, `ADRS=3`, `ADRS_MISSING=0`, `PATHS=24`,
`PATHS_MISSING=0`, `OWNERS=16`, `OWNERS_MISSING=0`, `OWNERS_MISSING_IDS=none`, `FACTS=23`,
`FACTS_OK=23`, `STALE=0`, `STALE_ROWS=none`; (4) числа P3: `NUMBERS=7`, `NUMBERS_OK=7`,
`NUMBERS_UNDECLARED=0`, `NUMBERS_UNDECLARED_IDS=none`, `PROV_BAD=0`; (5) границы:
`WIRE_TOUCHED=0`, `RUST_TOUCHED=0`; (6) соседние стражи зелёные (`SECRETS_EXIT`, `REFS_EXIT`,
`CLAIMMAP_EXIT`, `CLAIMS_EXIT`, `CONTOURS_EXIT`, `MIRROR_EXIT`, `GATE_AUDIT_EXIT`, `REVIEW_EXIT`,
`LINT_LATEST_EXIT`, `TEXTGUARD_ALL_EXIT`, `TEXTGUARD_CYCLE_EXIT`), `LINT_ORPHANS=0`,
`TEXTGUARD_ALL_DIRTY=0`; (7) `DISK_GE_15000=1`; (8) `WORST_RC=0`, `STABLE=1`. Порог заморожен до
первого официального прогона `lab/e0148-run.sh`; изменение любого числа — новая карточка."
---

# E-0148 — карта релиза под прибор: шестнадцать строк, P3 против `E-0100`

## Что проверяется

Гипотеза `H-0148`: релиз-карта связывается с деревом тем же классом доказательств, что и статус-
страница (`H-0147`), а её строка P3 перестаёт противоречить своему носителю. Круг добавляет
`lab/check-release-map.py`, реестр `lab/release-map-rows.tsv` (16 строк `M-01…M-16`), исправляет
строку P3 по фактам `E-0100` (417,5 МиБ, 437,7 Б/запись при бюджете 428 МиБ ±5 %) и доказывает, что
на пине стража не было, а три посаженные лжи новый страж ловит.

## Почему это не косметика

Карта отвечает на вопрос «почему ещё нельзя ставить тег». Её строка P3 отвечала «мерили на
фикстуре, а не на 1M» и «снято на 4 000 записей», хотя обычный `#[test]`
`memory_budget.rs::one_million_entries_fit_the_budget` меряет `N = 1_000_000`, а `E-0100` закрыта
`supports` с числами 417,5 МиБ / 437,7 Б. Это не украшение текста: ложная строка откладывает релиз
по несуществующей причине, и у неё нет владельца, который бы покраснел.

## Границы

Прибор читает названные формы: реестр подписан нами, новая строка без записи — находка, но полнота
реестра не доказывается. Числа сверяются только у P3 (7 чисел); у остальных строк они остаются
прозой и это названо. Поведение доказывает тест, а не прибор. Карта не переписывается под прибор:
исправление P3 — перенос измеренного, а не ослабление гейта.

## Что считается вердиктом

Только факты, названные в пороге. Содержание круга — `PRE_FIX_GUARD_ABSENT=1` /
`PRE_FIX_FALSE_ROW=1` против `POST_FIX_LIE_CAUGHT=1`, `POST_FIX_NUMBER_CAUGHT=1`,
`POST_FIX_OWNER_CAUGHT=1`; покрытие — `MAP_ROWS=16`, `ROWS_REGISTERED=16`, `OWNERS=16`,
`FACTS_OK=23`, `EIDS=25`, `PATHS=24`, `NUMBERS_OK=7` и нули находок.

## Результат

`supports`. Носитель — `lab/logs/e0148-all.log`. На пине (`9ba4c9d`) стража нет
(`PRE_FIX_GUARD_ABSENT=1`), ложная строка P3 стоит (`PRE_FIX_FALSE_ROW=1`,
`PRE_FIX_LIE_PASSES=1`); новый страж называет её `M-14` (`POST_FIX_LIE_CAUGHT=1`), ловит подмену
числа (`POST_FIX_NUMBER_IDS=M-14:477.5`) и стёртого владельца (`M-14 owner-not-named`).

На исправленной карте: `MAP_ROWS=16`, `ROWS_REGISTERED=16`, `ROWS_UNREGISTERED=0`,
`ROWS_MISSING=0`, `MAP_DUP=0`; `EIDS=25`, `EIDS_MISSING=0`, `EIDS_OPEN=0`; `ADRS=3`,
`ADRS_MISSING=0`; `PATHS=24`, `PATHS_MISSING=0`; `OWNERS=16`, `OWNERS_MISSING=0`;
`FACTS=23`, `FACTS_OK=23`, `STALE=0`; `NUMBERS=7`, `NUMBERS_OK=7`, `NUMBERS_UNDECLARED=0`,
`PROV_BAD=0`; самопроверка `15/15`.

Два официальных прогона на неизменном дереве: `ОЖИДАНИЙ=57 РАСХОЖДЕНИЙ=0`, `WORST_RC=0`,
`STABLE=1` во втором. Полная верификация: `VERIFY_FAIL=0`, 136 срезов, 791 passed, 0 failed,
9 `#[ignore]`, `SECONDS_total=1975`, диск 16 527 МБ. Продукт и провод не тронуты
(`RUST_TOUCHED=0`, `WIRE_TOUCHED=0`).

Остатки: прибор читает формы, а не смысл; числа сверены только у P3; полнота реестра не
доказывается (`OPEN-QUESTIONS` п. 88).
