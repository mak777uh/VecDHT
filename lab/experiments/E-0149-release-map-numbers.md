---
id: E-0149
hypothesis: H-0149
status: open
verdict: null
base_commit: "fee5f70"
started: "2026-10-29"
environment: "x86_64-pc-windows-gnu, хост владельца; Python 3, bash и cargo; сеть наружу не
используется; PRE_FIX снимается из пина через `git show`; продукт не правится, но тест `gates_p4`
исполняется как носитель строки P4"
command: "bash lab/e0149-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0149.tsv run1.txt run2.txt`); носители — `python lab/check-release-map.py
selftest`, `python lab/check-release-map.py` и `cargo test -p vecdht-node --test gates_p4 --
--nocapture --test-threads=1`"
threshold: "(1) пин: `PIN_FOUND=1`, `PRE_FIX_GUARD_OLD=1`, `PRE_FIX_NONE_PASSES=1`,
`PRE_FIX_PREFIX_PASSES=1`, `PRE_FIX_LOG_UNSUPPORTED=1`; (2) стражи: `POST_FIX_NONE_CAUGHT=1`,
`POST_FIX_PREFIX_CAUGHT=1`, `POST_FIX_LOG_OK=1`, `SELFTEST_EXIT=0`, `SELFTEST_TOTAL=20`,
`SELFTEST_PASSED=20`, `SELFTEST_FAILED=0`; (3) строка P4: `P4_LOG_FOUND=1`, `P4_LOG_VALUE=5`,
`P4_TEST_EXIT=0`, `P4_NOW=5`, `P4_MATCH=1`; (4) карта: `MAP_EXIT=0`, `MAP_ROWS=16`, `ROWS_REGISTERED=16`,
`ROWS_UNREGISTERED=0`, `ROWS_MISSING=0`, `MAP_DUP=0`, `EIDS=25`, `EIDS_MISSING=0`, `EIDS_OPEN=0`,
`ADRS=3`, `ADRS_MISSING=0`, `PATHS=25`, `PATHS_MISSING=0`, `OWNERS=16`, `OWNERS_MISSING=0`,
`OWNERS_MISSING_IDS=none`, `FACTS=23`, `FACTS_OK=23`, `STALE=0`, `STALE_ROWS=none`; (5) числа:
`NUMBERS=43`, `NUMBERS_OK=43`, `NONE_ROWS=7`, `NUMBERS_UNDECLARED=0`, `NUMBERS_UNDECLARED_IDS=none`,
`NUMBERS_PHANTOM=0`, `NUMBERS_PHANTOM_IDS=none`, `PROV_BAD=0`; (6) границы: `WIRE_TOUCHED=0`,
`RUST_TOUCHED=0`; (7) соседние стражи зелёные (`SECRETS_EXIT`, `REFS_EXIT`, `CLAIMMAP_EXIT`,
`CLAIMS_EXIT`, `CONTOURS_EXIT`, `MIRROR_EXIT`, `GATE_AUDIT_EXIT`, `REVIEW_EXIT`, `LINT_LATEST_EXIT`,
`TEXTGUARD_ALL_EXIT`, `TEXTGUARD_CYCLE_EXIT`), `LINT_ORPHANS=0`, `TEXTGUARD_ALL_DIRTY=0`;
(8) `DISK_GE_15000=1`; (9) `WORST_RC=0`, `STABLE=1`. Порог заморожен до первого официального
прогона `lab/e0149-run.sh`; изменение любого числа — новая карточка."
---

# E-0149 — числа релиз-карты против своих носителей

## Что проверяется

Гипотеза `H-0149`: все числа девяти строк `docs/RELEASE-MAP-v1.md` связаны с носителями, семь строк
без чисел утверждают их отсутствие, а строка P4 получает сохранённый вывод теста вместо
необеспеченного разложения «4 с». Круг расширяет `lab/check-release-map.py` (целое число вместо
подстроки, `none` как утверждение, типы «не число», провенанс `log:`), заполняет
`lab/release-map-rows.tsv` 43 числами и доказывает тремя посаженными лжами, что старый страж их
пропускал.

## Почему это не косметика

Прошлый круг проверял числа только у одной строки. Остальные числа карты — тезисы о готовности,
которые читают как факты; без сверки подмена или округление в свою пользу не краснеют. Новый порог
называет цену: 43 числа, 7 строк `none`, 20 посадочных случаев и сохранённый носитель P4.

## Границы

Прибор проверяет наличие числа в носителе, а не смысл; реестр подписан нами, полнота не
доказывается; `@prev` наследует карточки для провенанса, но не имя владельца; классы «не число»
объявлены списком; поведение теста прибор не доказывает.

## Что считается вердиктом

Только факты, названные в пороге. Содержание круга — `PRE_FIX_NONE_PASSES=1`,
`PRE_FIX_PREFIX_PASSES=1`, `PRE_FIX_LOG_UNSUPPORTED=1` против `POST_FIX_NONE_CAUGHT=1`,
`POST_FIX_PREFIX_CAUGHT=1`, `POST_FIX_LOG_OK=1` и носитель `P4_LOG_VALUE=5`; покрытие —
`NUMBERS=43`, `NONE_ROWS=7`, `SELFTEST_PASSED=20` и нули находок.

## Поправка до официальных прогонов

Пин `cced85f` заморозил `PATHS=24` — это был мой ручной счёт. Предварительный прогон helper'а
напечатал `PATHS=25`. Независимый пересчёт карты тем же правилом отбора (обратные кавычки, есть
`/`, нет пробелов, не `/p2p`, не `<`) даёт те же 25 имён, каждое разрешается на диске; новых путей
этот круг в карту не добавлял (лог P4 живёт в реестре как `log:`, а не в тексте карты). По правилу
«свип покрывает ровно столько единиц, сколько насчитал прибор» замороженное число исправлено на 25
до первого официального прогона; пороги исхода (посадочные лжи, `P4_*`, `NUMBERS`, `NONE_ROWS`,
селфтест) не менялись. История: пин хранит 24, и это видно в `git show cced85f:…`.
