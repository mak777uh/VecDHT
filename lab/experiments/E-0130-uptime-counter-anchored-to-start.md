---
id: E-0130
hypothesis: H-0130
status: pre-registered
base_commit: "80b81c0"
started: "2026-10-27"
finished: ""
environment: "x86_64-pc-windows-gnu, хост владельца; Rust из PATH (cargo/rustc), Python 3 из PATH,
PYTHONIOENCODING=utf-8; PATH дополнен /c/Users/Admin/mingw64/bin (иначе MinGW из miniconda рвёт
линковку GetHostNameW); debug-сборка инкрементально поверх дерева 80b81c0; сеть прибора — 127.0.0.1,
QUIC, настоящие процессы `node run` с одним `--dir` на два старта, `node uptime` как отдельный
вызов бинаря; дата карточки и записей индекса судится по UTC (`ADR-0070`)"
command: "bash lab/e0130-run.sh"
threshold: "(1) `python lab/cycle-gate.py gate H-0130` выход 0; диск >= 15 000 МБ до измерений и
после них, напечатаны три числа (диск/RAM/pagefile). (2) PRE_FIX на дереве пина `80b81c0` текущим
прибором (product-файлы временно из пина, тест остаётся нынешний, trap возвращает по sha256):
`PRE_FIX_FILE_BYTES=0`, `PRE_FIX_OPEN1_STATUS=none`, `PRE_FIX_MISSING_PRINTED=0`,
`PRE_FIX_STATUS_HAS_ALL_FIELDS=0`, `PRE_FIX_STATUS_SESSIONS=none`, `PRE_FIX_RESTART_SESSIONS=none`,
`PRE_FIX_LIVE_REPORT_CODE=1`, `PRE_FIX_CORRUPT_RUN_CODE=0`, `PRE_FIX_CORRUPT_RUN_READY_PRINTED=1`,
`PRE_FIX_CORRUPT_REPORT_CODE=1`, `PRE_FIX_RESET_CODE=1`, `PRE_FIX_TEST_FAILED=1`. Краснота обязана
быть по предмету: на пине код `node uptime` не существует, поэтому отчётные коды там 1 (неизвестная
команда), а не 2, и узел подставленный `uptime.bin` игнорирует (`PRE_FIX_CORRUPT_RUN_CODE=0` при
напечатанном `NODE_READY`). (3) Формат и арифметика: `cargo test -q -p vecdht-cli --lib uptime::`
выход 0 при `LIB_UP_PASSED=7`, полный `cargo test -q -p vecdht-cli --lib` выход 0 при
`LIB_PASSED=68`. (4) Прибор `cargo test -q -p vecdht-cli --test node_run -- --test-threads=1
--nocapture` зелёный дважды на неизменном дереве: `CLI_EXIT=0`, `CLI_FAILED=0`, `CLI_PASSED=3`,
наборы фактов совпали (`STABLE=1`), и все 31 факт `UP_*` равен замороженному числу:
`UP_OPEN1_STATUS=never_started`, `UP_OPEN1_SESSIONS=1`, `UP_MISSING_PRINTED=1`,
`UP_STATUS_UPTIME_SESSIONS=1`, `UP_STATUS_UPTIME_REGRESSIONS=0`, `UP_STATUS_UPTIME_IO_ERRORS=0`,
`UP_STATUS_HAS_ALL_FIELDS=1`, `UP_LIVE_REPORT_CODE=0`, `UP_LIVE_REPORT_SESSIONS=1`,
`UP_FILE_BYTES=46`, `UP_PARTIAL_LEFT=0`, `UP_RESTART_STATUS=resumed`, `UP_RESTART_SESSIONS=2`,
`UP_RESTART_ACCUM_EQ_CLOSED=1`, `UP_RESTART_REPORT_CODE=0`, `UP_RESTART_REPORT_SESSIONS=2`,
`UP_RESTART_TOTAL_GE_ACCUM=1`, `UP_CORRUPT_RUN_CODE=2`, `UP_CORRUPT_RUN_NAMES_FILE=1`,
`UP_CORRUPT_RUN_READY_PRINTED=0`, `UP_CORRUPT_REPORT_CODE=2`, `UP_CORRUPT_REPORT_NAMES_FILE=1`,
`UP_CORRUPT_REPORT_ZERO=0`, `UP_ABSENT_REPORT_CODE=2`, `UP_ABSENT_REPORT_NAMES_FILE=1`,
`UP_ABSENT_REPORT_ZERO=0`, `UP_RESET_CODE=0`, `UP_RESET_FILE_BYTES=46`, `UP_RESET_REPORT_CODE=0`,
`UP_RESET_SESSIONS=1`, `UP_RESET_ACCUM=0`. (5) `python lab/expect.py lab/expectations/e0130.tsv
facts1 facts2` выход 0 при полном наборе. (6) Посадка: строка `UP_RESTART_SESSIONS` со значением 1 в
копию таблицы даёт `expect.py` выход 1 (`PLANT_EXIT=1`). (7) Сырые секунды (`uptime_total_sec`,
`uptime_open_sec`) в таблицу не входят: они зависят от расписания битов и от часов хоста, и
живут только в носителе — строки узла эхом напечатаны в выводе теста (правило 7 (е), `ADR-0070`).
(8) Ветка `uptime_io_errors > 0` в этом цикле не исполняется и в порог не входит: посадить её без
отказа файловой системы нечем, а ноль подставной ошибки был бы молчанием; поле наблюдаемо как факт
`UP_STATUS_UPTIME_IO_ERRORS=0`, и это значит «ошибок не было», а не «счётчика нет». (9) Страж текста
на файлах цикла (`bash lab/check-text-clean.sh`) и `python lab/repo-review.py` выход 0; полная
верификация `bash lab/workspace-verify.sh E-0130` заканчивается `VERIFY_FAIL=0`. Порог заморожен до
первого прогона `lab/e0130-run.sh`; изменение любого числа — новая карточка."
result: ""
verdict: pending
---

## Pre-registration (до прогона)

### Что проверяется и почему именно так

Предмет — не «есть ли файл на диске», а три наблюдаемых свойства одного числа: оно переживает
перезапуск процесса, оно отказывается быть напечатанным, когда истории нет или она испорчена, и оно
не умеет уменьшаться при откате настенных часов. Каждое из трёх снимается своим путём: размер файла
и отсутствие `.partial` — прямым чтением каталога узла, переживаемость — вторым процессом с тем же
`--dir`, отказ — кодом возврата и stderr настоящего вызова бинаря.

Прибор называет число, а не направление. «Аптайм вырос» было бы верно при любом нуле на экране,
поэтому заморожены ровно `UP_FILE_BYTES=46` (формат назван в `ADR-0071`, и `uptime.rs` держит
константную проверку этой длины), `UP_RESTART_SESSIONS=2` и `UP_RESTART_ACCUM_EQ_CLOSED=1`
(накопленное равно закрытому окну, а не «что-то около»), коды 2 у обоих отказов и код 0 у живого
отчёта.

### Развилки, решённые до кода

Храним абсолютные отметки и накопленное, а не обратный отсчёт. Это форма эталона: `proc_uptime(5)`
(`L-0042`) определяет аптайм как накопленное время от якоря и явно включает suspend, `etcd`
(`L-0037`) хранит остаток lease абсолютным бакетом. Обратный отсчёт на диске означал бы, что
перезапуск узла «отматывает» ему время жизни, и это была бы вторая дыра того же класса, что и
`lease` до `ADR-0065`.

Отказ — возврат ошибки, а не паника и не ноль. `L-0043` показывает, к чему обязывает выбор «поднять
любой ценой»: в `newStore` etcd нечитаемое восстановление заканчивается `panic("failed to recover
store from backend")` и висящим над ним `TODO: return the error instead of panic here?`. Наш случай
дешевле: у CLI есть коды (1 — разбор, 2 — дело), и отказ до `NODE_READY` наблюдаем как «узла нет»,
что честнее, чем работающий узел с нулём в поле.

Сон хоста засчитывается. Прибор живёт на `now_sec()`, поэтому пауза ноутбука между двумя стартами
уходит в `accumulated_sec` так же, как в эталоне Linux; развилка названа в `ADR-0071` и не
унаследована молча, потому что критерий H1 («30 дней») читается как календарное время службы, а не
как время, проведённое CPU в работе.

### Что происходит с прежним контрактом

`node run` получает новый флаг `--uptime-reset`, новый отчёт `node uptime` и пять новых полей в
`NODE_STATUS`; прежние поля и прежний смысл `t=` (монотонный таймер процесса) не меняются, поэтому
карточки `A1` (`node_run.rs`) и `A1c` (`node_lease_status.rs`) обязаны остаться зелёными — прибор
гоняется вместе с ними, а `CLI_PASSED=3` означает ровно эти три теста файла.

## План замера

Helper: PRE_FIX на пине (текущий прибор, product из `80b81c0`), затем два прогона на неизменном
дереве, сверка `STABLE`, посадка, стражи. Верификация отдельно: `bash lab/workspace-verify.sh
E-0130`.
