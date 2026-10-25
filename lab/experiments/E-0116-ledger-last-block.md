---
id: E-0116
hypothesis: H-0116
status: planned
base_commit: "4201327"
started: ""
finished: ""
environment: "x86_64-pc-windows-gnu, Python 3 из PATH, хост владельца; Rust-сборка не участвует (правка только lab/ledger.py и helper'ов), PYTHONIOENCODING=utf-8"
command: "python lab/ledger.py selftest; awk 'NR==FNR{if (/^########## /) last=FNR; next} FNR>last' lab/logs/workspace-verify-2026-10-22.log lab/logs/workspace-verify-2026-10-22.log > /tmp/vlast.txt; python lab/ledger.py report lab/logs/e0114-all.log /tmp/vlast.txt"
threshold: "(1) selftest: exit 0, в нём есть случаи «первый блок красный, последний зелёный → OK=1», «V9CTL_*_EXIT=1 не провал», «LEDGER_EXIT=1 не провал», «TEST_EXIT=1 в последнем блоке → OK=0»; (2) report на паре файлов E-0114: LEDGER_STAGES=6, LEDGER_FAILED_STAGES=0, LEDGER_MISSING_STAGES=0, LEDGER_OK=1, LEDGER_EXIT=0; (3) копия последнего блока с TEST_EXIT=1: LEDGER_OK=0, LEDGER_EXIT=1; (4) до правки тот же вызов даёт LEDGER_OK=0 — PRE_FIX зафиксирован в lab/logs/e0116-all.log"
result: ""
verdict: inconclusive
---

## Pre-registration (до прогона)

Порог заморожен до правки `lab/ledger.py`. Проверяется не «стало ли красивее», а три свойства:
блочность (старый красный блок не протекает в новый), отделение контроля (посаженный
`V9CTL_BRIDGE_EXIT=1` — не провал цикла) и сохранение чувствительности (настоящий `TEST_EXIT=1` в
последнем блоке обязан краснить).

PRE_FIX исполняется первым: тот же вызов на неотремонтированном приборе обязан дать `LEDGER_OK=0`,
иначе порог (4) не выполнен и карточка не закрывается.

## Прогон

Один прогон после правки, плюс PRE_FIX до неё, в append-only `lab/logs/e0116-all.log`. Копия
последнего блока с посадкой `TEST_EXIT=1` делается в `/tmp`, дерево репозитория не правится.

## Результат

Заполняется после прогона.

## Вердикт

`supports` / `refutes` / `inconclusive` — после прогона.

## Что это не доказывает

Не доказывает корректность `workspace-verify.sh` целиком и не проверяет Rust-гейты; проверен только
разбор логов прибором `ledger` на двух закрытых файлах `E-0114` и посаженных случаях.
