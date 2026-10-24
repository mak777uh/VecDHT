---
id: E-0102
hypothesis: H-0102
status: pre-registered
base_commit: "ae35a1d (продукт до правки: PRE_FIX-оракул прогнан здесь и заморожен в lab/logs/e0102-prefix.log)"
started: "2026-10-24"
finished: null
environment: "Windows, x86_64-pc-windows-gnu; rustc 1.99.1; Python 3 (PyYAML). Приборы: `cargo test -p
vecdht-node --test s77_cell_cap_scan` (2 гейта), `cargo test -p vecdht-node --test
s77b_cell_cap_scan_observe` (бюджет и курсор), `cargo test -p vecdht-node --test s14_cell_cap_enforced
above_the_floor_the_cap_is_the_mean_and_not_a_constant -- --exact` (полноразмерный случай E-0088),
`python lab/cycle-gate.py`, `bash lab/workspace-verify.sh E-0102`. `RAYON_NUM_THREADS=2`, PATH
включает `/c/Users/Admin/mingw64/bin`"
command: "bash lab/e0102-run.sh (заморожен этим коммитом; исполняется неизменяемой mktemp-копией).
Порядок: (0) PRE_FIX — статические счётчики `git show ae35a1d:...admission.rs` (`cell_victim_scan`,
`cell_scanned`, `cell_victim`) и замороженные красный прогон `s77` из `lab/logs/e0102-prefix.log`
плюс полноразмерный `g5` из `lab/logs/e0088-all.log`; (1) `cargo test --test s77_cell_cap_scan` ×2;
(2) `cargo test --test s77b_cell_cap_scan_observe` ×2; (3) полноразмерный тест `s14` (live = 34 286)
×2; (4) `gate H-0102 --skip-lean` и `audit -n 5` ×2; (5) сверка вектора `python lab/facts.py repro
--strip-run`; (6) `bash lab/workspace-verify.sh E-0102`; затем `bash lab/check-text-clean.sh <файлы
цикла>` и `python lab/expect.py lab/expectations/e0102.tsv`. Лог — `lab/logs/e0102-all.log`
(append-only, контроль от отметки начала блока)"
threshold: "Заморожено этим коммитом вместе с `lab/expectations/e0102.tsv`, оракулом `s77` и helper'ом.
Ожидания выведены из поведения до правки (замороженный лог) и из устройства правки, а не из будущего
прогона. PRE_FIX: `PREFIX_CELL_VICTIM_SCAN_HITS=0`, `PREFIX_CELL_SCANNED_HITS=0` (источник жертвы
один — резервуар), `PREFIX_CELL_VICTIM_HITS=7`, `PREFIX_ORACLE_PASSED=1`, `PREFIX_ORACLE_FAILED=1`,
`PREFIX_S77_FIRST_REFUSED=1`, `PREFIX_S77_FIRST_CODE=SHARD_FULL`, `PREFIX_S77_AFTER_FIRST_CELL=300`,
`PREFIX_S77_AFTER_FIRST_TOTAL=400`, `PREFIX_S77_AFTER_FIRST_EVICTED=0`,
`PREFIX_S77_SECOND_CODE=SHARD_FULL`, `PREFIX_G5_BRANCH=refuse`, `PREFIX_G5_EVICTED=0`,
`PREFIX_G5_SCANNED=0`. После правки: `S77_TESTS=2`, `S77_PASSED=2` дважды, при
`S77_FIRST_REFUSED=1`, `S77_FIRST_CODE=SHARD_FULL` (первый заход законно отказывает — §11.3.3),
`S77_SECOND_REFUSED=0`, `S77_SECOND_CODE=NONE`, `S77_CELL=300`, `S77_SHARD_TOTAL=400`,
`S77_EVICTED=1`, `S77_GLOBAL_SCANNED=0`, `S77_NINES_LEFT=19`; дешёвый новичок по-прежнему получает
`S77_CHEAP_REFUSED=1`, `S77_CHEAP_CODE=SHARD_FULL`, `S77_CHEAP_EVICTED=1` (число до отказа);
свободный кап не сканирует: `S77_CONTROL_SCANNED_DELTA=0`, `S77_CONTROL_EVICTED_DELTA=0`; продление
не вытесняет: `S77_RENEW_EVICTED=0`, `S77_RENEW_CELL=300`, `S77_RENEW_TOTAL=400`.
`S77B_TESTS=1`, `S77B_PASSED=1`, `S77B_FIRST_SCAN=256`, `S77B_SECOND_SCAN=44`, `S77B_WRAP_SCAN=256`,
`S77B_TOTAL_SCAN=556`, `S77B_BUDGET=256`, `S77B_CELL=300`, `S77B_EVICTED=1`. Полноразмерный случай:
`S14_G5_TESTS=1`, `S14_G5_PASSED=1`, `S14_G5_BRANCH=move`, `S14_G5_REFUSED=NONE`, `S14_G5_EVICTED=1`,
`S14_G5_SCANNED=0`, `S14_G5_CELL=4286`, `S14_G5_LIVE=34286`, `S14_G5_LIMIT=4286`. `GATE_H0102_OK=1`,
`AUDIT_VIOLATIONS=0`, `AUDIT_CARDS=5`. `REPRO_VECTOR=1` — два прогона каждого прибора на неизменном
дереве дают одинаковый вектор (правило 7 (е)). `S77_IN_VERIFY=1`, `S77B_IN_VERIFY=1` — оба оракула
исполняются полной верификацией, а не живут отдельными файлами. `VERIFY_EXIT=0`,
`TEXT_DIRTY_FILES=0`, `DISK_GE_15000=1` фиксирует ресурсный порог (11) тройкой чисел и не
подгоняется. Фальсификаторы — семь пунктов из `H-0102`"
result: null
verdict: pending
---

# E-0102 — вытеснение внутри полной ячейки не должно зависеть от шардового резервуара

## Что замеряется

Что кап ячейки, уже реализованный `E-0088`, находит жертву **среди обитателей самой ячейки**, а не
только среди 64 дешёвых записей шарда, которые успел увидеть `Evictor`; что поиск жертвы ограничен
бюджетом и не превращается в обход арены; что курсор двигается и обёртывается, то есть дешёвая
запись не запирается за окном навсегда; что §11.3.3 сохраняется (новичок дешевле всех — отказ);
что ветка «кап не связан» и продление в своей ячейке скана не запускают вовсе.

## Почему PRE_FIX — замороженный прогон, а не пересказ

Оракул `s77` компилируется на базовом продукте: он не трогает новых имён API и проверяет только
поведение (два захода в полную ячейку и ответ узла). Его красный прогон на `ae35a1d` — измерение
дыры, а не мнение о ней: первый заход отказал законно (`S77_FIRST_REFUSED=1`, `SHARD_FULL`), второй
тоже отказал (`ответ: Some("SHARD_FULL")`), хотя за первым окном в 256 слотов лежат 9-битные записи
дешевле 11-битного новичка. Прогон заморожен в `lab/logs/e0102-prefix.log`; после правки продукт
нельзя «раз-исправить», поэтому helper печатает эти факты из замороженного файла.

Полноразмерный факт берётся из уже замороженного `lab/logs/e0088-all.log`: `g5_branch=refuse`,
`g5_evicted 0→0`, `g5_scanned=0` при `live = 34 286` и пределе 4 286. Это тот же дефект в боевой
шкале, и он тоже не пересчитывается на исправленном дереве.

## Что изменено вместе с фиксом (до прогона)

`Evictor::cell_victim` остаётся как есть (он обслуживает резервуар и дешёвый случай), а рядом
появляется `cell_victim_scan`: обход живых слотов **целевой ячейки** от курсора `cell_scan[cluster]`
на `EVICT_SCAN_BUDGET = 256` записей с выбором самого дешёвого кандидата, который строго дешевле
новичка. Курсор хранит следующий непросмотренный индекс и обёртывается в 0 по концу списка. Новый
счётчик `cell_scanned` считает только эти проходы; глобальный `Evictor::scanned` не двигается.
`node.rs` вызывает скан только когда `cell_victim` вернул `None` и только на ветке смены ячейки,
то есть при свободном капе и при продлении скан не запускается.

## Границы

Записи, принятые другим узлом или до рестарта, цены не имеют (`bits = 0`): узел не знает их PoW
(§11.3.3), и жертвой они не становятся — отказ для них остаётся осознанной ошибкой в безопасную
сторону. Ветка «шард полон» (`max_live_per_shard`) и её обход арены не трогаются: `s77` не выходит
за предел ячейки, а полноразмерный `s14` проверяет, что глобальный `scanned` остался нулём. Провод,
WAL, формат индекса и `pow_input` не меняются.
