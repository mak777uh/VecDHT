---
id: E-0116
hypothesis: H-0116
status: completed
base_commit: "4201327"
started: "2026-10-25"
finished: "2026-10-25"
environment: "x86_64-pc-windows-gnu, Python 3 из PATH, хост владельца; Rust-сборка не участвует (правка только lab/ledger.py и helper'ов), PYTHONIOENCODING=utf-8"
command: "python lab/ledger.py selftest; awk 'NR==FNR{if (/^########## /) last=FNR; next} FNR>last' lab/logs/workspace-verify-2026-10-22.log lab/logs/workspace-verify-2026-10-22.log > /tmp/vlast.txt; python lab/ledger.py report lab/logs/e0114-all.log /tmp/vlast.txt"
threshold: "(1) selftest: exit 0, в нём есть случаи «первый блок красный, последний зелёный → OK=1», «V9CTL_*_EXIT=1 не провал», «LEDGER_EXIT=1 не провал», «TEST_EXIT=1 в последнем блоке → OK=0»; (2) report на паре файлов E-0114: LEDGER_STAGES=6, LEDGER_FAILED_STAGES=0, LEDGER_MISSING_STAGES=0, LEDGER_OK=1, LEDGER_EXIT=0; (3) копия последнего блока с TEST_EXIT=1: LEDGER_OK=0, LEDGER_EXIT=1; (4) до правки тот же вызов даёт LEDGER_OK=0 — PRE_FIX зафиксирован в lab/logs/e0116-all.log"
result: "Стража текста и ожидания: `lab/expectations/e0116.tsv` 16/0, `TEXTGUARD_EXIT=0`, `PYCOMPILE_EXIT=0`. PRE_FIX на неотремонтированном приборе (дерево eeef07c) дал `PRE_FIX_LEDGER_OK=0`, `PRE_FIX_LEDGER_EXIT=1`. После правки: selftest `LEDGER_SELFTEST_TOTAL=14 PASSED=14 EXIT=0`; report на паре файлов E-0114 — `LEDGER_STAGES=6`, `LEDGER_FAILED_STAGES=0`, `LEDGER_MISSING_STAGES=0`, `LEDGER_WALL_TOTAL=2984`, `LEDGER_OK=1`, `LEDGER_EXIT=0`; посадка `TEST_EXIT=1` в копию последнего блока — `LEDGER_FAILED_STAGES=1`, `LEDGER_SPENT_ON_FAILED=1285`, `LEDGER_OK=0`, `LEDGER_EXIT=1`. Два прогона на неизменном дереве дали 58 одинаковых строк фактов каждый. Диск после прогона 31 079 МБ. Пороги (1)–(4) выполнены."
verdict: supports
---

## Pre-registration (до прогона)

Порог заморожен до правки `lab/ledger.py`. Проверяется не «стало ли красивее», а три свойства:
блочность (старый красный блок не протекает в новый), отделение контроля (посаженный
`V9CTL_BRIDGE_EXIT=1` — не провал цикла) и сохранение чувствительности (настоящий `TEST_EXIT=1` в
последнем блоке обязан краснить).

PRE_FIX исполняется первым: тот же вызов на неотремонтированном приборе обязан дать `LEDGER_OK=0`,
иначе порог (4) не выполнен и карточка не закрывается.

## Прогон

Helper — `lab/e0116-run.sh`, ожидания — `lab/expectations/e0116.tsv` (16 ключей). Один прогон после
правки, плюс PRE_FIX до неё, в append-only `lab/logs/e0116-all.log`. Копия последнего блока с посадкой
`TEST_EXIT=1` делается в `/tmp`, дерево репозитория не правится. Повторный прогон на неизменном
дереве обязателен: наборы фактов двух блоков совпали (58 строк каждый).

## Результат

Порог (1): `LEDGER_SELFTEST_EXIT=0`, `TOTAL=14`, `PASSED=14` — четыре посаженных случая на месте
(первый блок красный, последний зелёный; `V9CTL_BRIDGE_EXIT=1`; `LEDGER_EXIT=1`; `TEST_EXIT=1` в
последнем блоке).

Порог (2): `python lab/ledger.py report lab/logs/e0114-all.log <копия последнего блока
workspace-verify>` — `LEDGER_STAGES=6`, `LEDGER_FAILED_STAGES=0`, `LEDGER_MISSING_STAGES=0`,
`LEDGER_WALL_TOTAL=2984`, `LEDGER_OK=1`, `LEDGER_EXIT=0`. Ложный красный снят.

Порог (3): та же копия с `sed '0,/^TEST_EXIT=0$/s//TEST_EXIT=1/'` — `LEDGER_FAILED_STAGES=1`,
`LEDGER_SPENT_ON_FAILED=1285`, `LEDGER_OK=0`, `LEDGER_EXIT=1`, `PLANT_OK=0`, `PLANT_FAILED=1`.
Чувствительность сохранена: посаженный провал краснит и называется числом секунд.

Порог (4): PRE_FIX на `git show eeef07c:lab/ledger.py` с тем же вызовом — `PRE_FIX_LEDGER_OK=0`,
`PRE_FIX_LEDGER_EXIT=1`. Красный до правки зафиксирован в том же append-only логе.

Ожидания 16/0 (`EXPECT_EXIT=0`), стража текста `TEXTGUARD_EXIT=0`, компиляция
`PYCOMPILE_EXIT=0`, носитель до/после 31 082 / 31 079 МБ.

### ДИАГНОЗ-1: порог на одном файле был невыполним по построению

Первая редакция порога Т1 требовала `LEDGER_STAGES=6` от одного `lab/logs/e0114-all.log`. Сырых
`SECONDS_<этап>` в нём нет — они печатаются только `workspace-verify.sh` в собственный лог, — поэтому
порог давал `STAGES=0`, `MISSING=4` на любом приборе. Исправлено до заморозки: вход — пара файлов.
Урок: порог обязан называть все входы, без которых его числа неоткуда взять.

### ДИАГНОЗ-2: контрольный выход исключён из провалов, и посаженный случай переехал

После исключения `VERIFY` из списка провалов selftest-случай «промах без метки времени» перестал
печатать `СТОИМОСТЬ_ПРОВАЛА_НЕИЗВЕСТНА` (он был построен на `VERIFY_EXIT=1`). Случай переписан на
настоящий этап: `TEST_EXIT=1` без `SECONDS_test`. Семантика сохранена — ноль стоимости значит «не
мерялось», а не «дёшево»; это тот же класс, что `E-0105`/`E-0114`.

### ДИАГНОЗ-3: пункт плана «library.py use не очищает action» был ложным

Проверка `lab/library.py:199` запрещает статусу «в работе» содержать `action`; очистка при `use`
обязательна, это не дефект. Пункт в PLAN переписан в «не чинить», карточка `library.py` не трогала.
Урок: дефект прибора подтверждается его собственным стражем до правки, а не чтением одной функции.

### Цена верификации

Полный `bash lab/workspace-verify.sh E-0116` на этом дереве вернул 1, и причина названа: `REVIEW_EXIT=1`
(три находки о незакрытой этой самой карточке: `closed-empty-result`, `helper-orphans`,
`testing-closed`) и `LINT_LATEST_EXIT=2` (в свежей карточке не было таблицы ожиданий). Продуктовые
этапы зелёные: `TEST_EXIT=0`, `CLIPPY_EXIT=0`, `LEAN_EXIT=0`, `VERUS_EXIT=0`, `KCC_EXIT=0`,
`TEXTGUARD_EXIT=0`, `SECONDS_total=1481`. Отдельно review нашёл два висячих адреса `H-0109`/`H-0110`
в `docs/PLAN-v1.md` — номера будущих карточек, карточек нет; внесены в `lab/ref-allow-list.txt` с
причиной.

## Вердикт

`supports`. Гипотеза подтверждена на паре закрытых файлов и на четырёх посаженных случаях; ложный
красный снят, настоящий провал остаётся красным. Контракт продукта не менялся, ADR не требуется.

## Что это не доказывает

Не доказывает корректность `workspace-verify.sh` целиком и не проверяет Rust-гейты; проверен только
разбор логов прибором `ledger` на двух закрытых файлах `E-0114` и посаженных случаях.
