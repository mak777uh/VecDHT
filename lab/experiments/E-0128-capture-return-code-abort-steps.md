---
id: E-0128
hypothesis: H-0128
status: completed
base_commit: "f62b681"
started: "2026-10-27"
finished: "2026-10-27"
environment: "x86_64-pc-windows-gnu, хост владельца; bash + sed + awk + grep + python 3 из PATH,
PyYAML 6.0.3 (нужен `lab/cycle-gate.py`); PATH дополнен /c/Users/Admin/mingw64/bin. Код Rust цикл
не трогает (`CODE_CHANGED_RS=0`), `cargo` в этом helper'е не вызывается: предмет — текст трёх
workflow-файлов и семантика оболочки, а она проверяется настоящим `bash -e` на синтетических логах и
на ИЗВЛЕЧЁННОМ теле живого шага. Отдельная ловушка хоста перенесена из `E-0127` дословно:
`subprocess` из windows-python зовёт `bash`, который резолвится в сломанный WSL-лаунчер, и его вывод
выглядит как синтаксические ошибки; поэтому свип `bash -n` и механика исполняются из shell (Git Bash),
а не из python — недоступный интерпретатор не имеет права притворяться находкой"
command: "bash lab/e0128-run.sh"
threshold: "(1) `python lab/cycle-gate.py H-0128` выход 0; диск >= 15 000 МБ до измерений и после
них, печатаются три числа (диск/RAM/pagefile), в таблице оба флага: `DISK_GE_15000=1`,
`DISK_AFTER_MEASURE_GE_15000=1`; helper объявляет слепоту до замера, если запущен вне корня дерева
(`HELPER_BLIND_DIR=0`). (2) PRE_FIX на дереве пина `f62b681` из `git archive` с нынешним прибором
(прибора на пине нет — он часть этого цикла): `PRE_PIN_ARCHIVE_OK=1`, `PRE_FIX_RCC_FILES=3`,
`PRE_FIX_RCC_RUN_BLOCKS=40`, `PRE_FIX_RCC_BLOCKS_SET_PLUS_E=0`, `PRE_FIX_RCC_CAPTURES=24`,
`PRE_FIX_RCC_GUARDED=0`, `PRE_FIX_RCC_UNGUARDED=24`, `PRE_FIX_RCC_LINES_UNGUARDED=24`,
`PRE_FIX_RCC_RECOUNT_EQ=1`, `PRE_FIX_RCC_BLIND=0`, `PRE_FIX_RCC_FAIL=1`, `PRE_FIX_RCC_EXIT=1`,
`PRE_FIX_RCC_FILES_WITH_FINDINGS=3`, `PRE_FIX_RCC_FINDINGS_PRINTED=24`, `PRE_FIX_RCC_MORE_FLAG=1`,
`PRE_FIX_RCC_RED_NOT_BLIND=1`. Требование «краснота найдена, а не произведена слепотой» (находок > 0,
слепоты = 0, два кода сошлись, выход != 0) внесено специально: иначе нуль прибора неотличим от того,
что он перестал смотреть файлы (прецедент ДИАГНОЗ-1/2 из `E-0126`). (3) Тело живого шага «зеркало
спеки» с пина, извлечённое `extractstep` и запущенное под настоящим `bash -e` с пустым `HOME`
(состояние свежего runner'а): `PRE_FIX_RCS_MATCHES=1`, `PRE_FIX_RCS_EXIT=0`,
`PRE_FIX_RCS_BLOCK_LINES=13`, `PRE_FIX_MIRROR_STEP_DENIES_EXECUTION=1` (имя шага утверждало, что он
не исполняется, — при том что он исполнялся и краснел), `PRE_FIX_MIRROR_ABSENT_EXIT=1`,
`PRE_FIX_MIRROR_ABSENT_NOTICE=0`, `PRE_FIX_MIRROR_REPORT_LINES=0`, `PRE_FIX_MIRROR_SILENT_ABORT=1` —
это воспроизведение чужого прогона на хосте, а не ссылка на него. Тот же класс ВНУТРИ guard'а:
`PRE_FIX_MIRROR_SCRIPT_DIVERGE_RC=1`, `PRE_FIX_MIRROR_SCRIPT_REPORT_KEPT=0`,
`PRE_FIX_MIRROR_SCRIPT_REPORT_LOST=1` — на пине `diff | head` под `set -euo pipefail` обрывает
`lab/check-spec-mirror.sh` раньше его последней отчётной строки. (4) Живой прогон
`python lab/check-ci-rc-capture.py check --limit 30` на починном дереве: `RCC_FILES=3`,
`RCC_RUN_BLOCKS=42`, `RCC_BLOCKS_SET_PLUS_E=0`, `RCC_CAPTURES=26`, `RCC_GUARDED=26`,
`RCC_UNGUARDED=0`, `RCC_LINES_UNGUARDED=0`, `RCC_RECOUNT_EQ=1`, `RCC_BLIND=0`, `RCC_FAIL=0`,
`RCC_EXIT=0`, `RCC_NONE_PRINTED=1`, `RCC_MORE_NONE_PRINTED=1` (пустое множество напечатано словом
`none`). (5) Механика — пять форм под настоящим `bash -e`, числа обязательны ровно эти:
`MECH_A_UNGUARDED_RC=3`/`REACHED=0`/`NOTICES=0` (обрыв ДО присваивания и ДО отчёта),
`MECH_B_GUARDED_RC=3`/`REACHED=1`/`NOTICES=1` (guard сохраняет вердикт и рассылку),
`MECH_C_GREEN_RC=0`/`REACHED=1`/`NOTICES=1` (на зелёном дереве дефект невиден ни по коду, ни по
выводу), `MECH_D_SET_PLUS_E_RC=3`/`REACHED=1`/`NOTICES=1` (exemption освобождает законно),
`MECH_E_GREP_ABORT_RC=1`/`REACHED=0`/`NOTICES=0` (класс `E-0127` даёт ДРУГОЙ код: 1 против 3). Шесть
сводных утверждений `MECHOK_UNGUARDED_ABORTS_BEFORE_REPORT`, `MECHOK_GUARDED_KEEPS_VERDICT`,
`MECHOK_GREEN_LOOKS_FINE`, `MECHOK_SET_PLUS_E_EXEMPTS`, `MECHOK_CLASS_IS_E0127_NOT_RC`,
`MECHOK_ABORT_INDISTINGUISHABLE_BY_RC` равны 1; последнее и есть причина, по которой класс пролежал
незамеченным: код обрыва равен коду задуманного вердикта, и по одному коду возврата починка неотличима
от поломки. (6) Живой шаг после починки, три ветки носителя: `RCS_MATCHES=1`, `RCS_EXIT=0`,
`RCS_VERIFY_YML=1`, `MIRROR_STEP_DENIES_EXECUTION=0` (имя больше не отрицает исполнение),
`MIRROR_ABSENT_EXIT=0`/`MIRROR_ABSENT_NOTICE=1`/`MIRROR_ABSENT_LOG_NAMED=2` (нет зеркала — зелёный
шаг с названной причиной), `MIRROR_OK_EXIT=0`/`MIRROR_OK_NOTICE=1`,
`MIRROR_DIVERGE_EXIT=1`/`MIRROR_DIVERGE_ERROR=1` (расхождение осталось красным: guard не имел права
трогать вердикт), `MIRROR_SCRIPT_DIVERGE_RC=1`/`MIRROR_SCRIPT_REPORT_KEPT=1` (тот же скрипт печатает
`починить:` и остаётся красным). (7) Синтаксис: все блоки `run:` извлекаются тем же парсером и
прогоняются через `bash -n` из shell — `RCC_SYNTAX_BLOCKS=42`, `RCC_SYNTAX_DUMP_EXIT=0`,
`RCC_SYNTAX_BAD=0`, `RCC_SYNTAX_BLOCKS_EQ_RUN_BLOCKS=1`. (8) Самопроверка прибора на живом дереве:
`RCC_SELFTEST_TOTAL=12`, `RCC_SELFTEST_PASSED=12`, `RCC_SELFTEST_FIRED=0`,
`RCC_SELFTEST_FAILED_NAMES=0`, `RCC_SELFTEST_RC=0`, `RCC_SELFTEST_OK=1` — двенадцать проверок, из них
три (j/k/l) на посадках в копию ЖИВОГО дерева и потому годны и до починки, и после неё. (9) Четыре
посадки на КОПИЯХ (`--dir`, живое дерево не трогается): `plant --kind flip` снимает guard
(`PLANT_FLIP_LANDED=1`, `PLANT_FLIP_DIRECTION=to_unguarded`, `PLANT_FLIP_UNGUARDED=1`,
`PLANT_FLIP_GUARDED=25`, `PLANT_FLIP_CAPTURES=26`, `PLANT_FLIP_RECOUNT_EQ=1`, `PLANT_FLIP_NAMED=1`,
`PLANT_FLIP_NONE=0`, `PLANT_FLIP_EXIT=1`); `plant --kind bare` разводит захват на две строки
(`PLANT_BARE_DIRECTION=to_bare_assign`, те же числа, выход 1); `plant --kind sete` ставит `set +e`
(`PLANT_SETE_BLOCKS_SET_PLUS_E=1`, `PLANT_SETE_UNGUARDED=0`, `PLANT_SETE_EXIT=0` — exemption это учёт,
а не дефект, и требовать от него красноты значило бы заставить прибор врать о смысле числа); пустой
workflow-каталог (`PLANT_BLIND_BLIND=1`, `PLANT_BLIND_EXIT=1`). Итог: `PLANT_LANDED=4`,
`PLANT_RED_COUNT=3`, `PLANT_ALL_RED=1`; `PLANT_BLIND_RECOUNT_EQ=1` на пустом каталоге записан как
граница: красноту там обеспечивает `RCC_BLIND`, а не пересчёт. (10) Всё измерение исполняется дважды
на неизменном дереве, файлы фактов совпадают построчно (`diff -q`) -> `STABLE=1`. (11) Wiring и
границы: `RCC_CI_STEP_ADDED=1` (страж и его самопроверка стоят двумя шагами в `verify.yml`),
`RCC_VERIFY_BLOCK_ADDED=1` (страж стоит в `lab/workspace-verify.sh`),
`RCC_E0127_INSTRUMENT_UNTOUCHED=1` (прибор `E-0127` не переписан: у классов разные правила, и зелёный
один не говорит ничего про другой), `CODE_CHANGED_RS=0`, `SPEC_DOCS_UNTOUCHED=1`,
`MIRROR_SCRIPT_PIPE_GUARDED=1` (`diff | head -40 || true` — guard в конце трубы), и независимый от
прибора grep по трём workflow-файлам: `SEMICOLON_CAPTURE_LINES=0` (форма `; r=$?` исчезла из дерева
полностью). (12) Полный контур стражей, а не только названное в пороге: `TEXTGUARD_EXIT=0`,
`LINT_EXIT=0`, `CLAIMMAP_EXIT=0`, `REPO_REVIEW_EXIT=0`, `MIRROR_EXIT=0`. Посадка неверного ожидания
(`RCC_UNGUARDED` в копию таблицы со значением 7) обязана покраснеть: `PLANT_EXPECT_RED=1`. Сверка
`lab/expectations/e0128.tsv` (139 непустых строк, `EXPECT_ROWS=139`) против двух файлов фактов:
`ОЖИДАНИЙ=139 РАСХОЖДЕНИЙ=0`, напечатанный в носителе `EXPECT_EXIT=0` (в таблицу этот ключ НЕ входит:
сверка исполняется до его печати, и требовать собственный код — порог, невыполнимый по построению;
красноту держит `note`). (13) Полная верификация финального дерева
`bash lab/workspace-verify.sh E-0128` заканчивается `VERIFY_FAIL=0`, и в ней новый страж исполняется
в составе закрытия цикла. Порог заморожен до первого прогона `lab/e0128-run.sh`; изменение любого
числа — новая карточка. Вне порога остаётся и записано честно: зелёность или краснота `verify` на
GitHub после этого пуша — факт ЧУЖОГО прогона (раннера), на хосте контура не наблюдаемый; прибор знает
форму захвата `$?` в workflow-файлах и не знает, есть ли в шаге чем вынести вердикт (хвост `E-0127`,
п. 3); файлы `lab/*.sh` вне области прибора, кроме одного исключения, найденного чтением и закрытого
этим же циклом; тег и GitHub Release — красная зона владельца."
result: "Починка зелёна на дереве `472f6e9` при красном PRE_FIX на пине `f62b681`, и это один и тот же
прибор. Два прогона на неизменном дереве совпали построчно (`STABLE=1`), свёрстано 139 фактов без
расхождений (`ОЖИДАНИЙ=139 РАСХОЖДЕНИЙ=0`, `EXPECT_ROWS=139`, напечатанный `EXPECT_EXIT=0`), итог
носителя — `WORST_RC=0`, цена helper'а 68 с по меткам носителя (01:15:32 -> 01:16:40).

PRE_FIX (дерево пина из `git archive`, нынешний прибор внутри): `PRE_FIX_RCC_FILES=3`,
`PRE_FIX_RCC_RUN_BLOCKS=40`, `PRE_FIX_RCC_CAPTURES=24`, `PRE_FIX_RCC_GUARDED=0`,
`PRE_FIX_RCC_UNGUARDED=24`, `PRE_FIX_RCC_LINES_UNGUARDED=24`, `PRE_FIX_RCC_FINDINGS_PRINTED=24`,
`PRE_FIX_RCC_RECOUNT_EQ=1`, `PRE_FIX_RCC_BLOCKS_SET_PLUS_E=0`, `PRE_FIX_RCC_BLIND=0`,
`PRE_FIX_RCC_RED_NOT_BLIND=1`, `PRE_FIX_RCC_FAIL=1`, `PRE_FIX_RCC_EXIT=1` — краснота найдена (24
адресованных строки в трёх файлах), а не произведена слепотой. Живой прогон после починки:
`RCC_FILES=3`, `RCC_RUN_BLOCKS=42`, `RCC_CAPTURES=26`, `RCC_GUARDED=26`, `RCC_UNGUARDED=0`,
`RCC_LINES_UNGUARDED=0`, `RCC_RECOUNT_EQ=1`, `RCC_BLOCKS_SET_PLUS_E=0`, `RCC_BLIND=0`, `RCC_FAIL=0`,
`RCC_EXIT=0`, пустое множество напечатано словом (`RCC_UNGUARDED_FILE=none`,
`RCC_UNGUARDED_MORE=none`, `RCC_NONE_PRINTED=1`, `RCC_MORE_NONE_PRINTED=1`).

Симуляция живого шага «зеркало спеки» (`extractstep`: тело шага с пина под настоящим `bash -e` с
пустым `HOME`): до починки `PRE_FIX_RCS_MATCHES=1`, `PRE_FIX_RCS_BLOCK_LINES=13`,
`PRE_FIX_MIRROR_ABSENT_EXIT=1`, `PRE_FIX_MIRROR_ABSENT_NOTICE=0`, `PRE_FIX_MIRROR_REPORT_LINES=0`,
`PRE_FIX_MIRROR_SILENT_ABORT=1`, `PRE_FIX_MIRROR_STEP_DENIES_EXECUTION=1` — ровно то, что насчитал
чужой прогон; после починки `MIRROR_ABSENT_EXIT=0` при `MIRROR_ABSENT_NOTICE=1`,
`MIRROR_OK_EXIT=0`/`MIRROR_OK_NOTICE=1`, `MIRROR_DIVERGE_EXIT=1`/`MIRROR_DIVERGE_ERROR=1` (вердикт по
прежнему красен), `MIRROR_ABSENT_LOG_NAMED=2`, `MIRROR_STEP_DENIES_EXECUTION=0`. Скрипт сверки
зеркала: `PRE_FIX_MIRROR_SCRIPT_DIVERGE_RC=1` при `PRE_FIX_MIRROR_SCRIPT_REPORT_LOST=1` ->
`MIRROR_SCRIPT_DIVERGE_RC=1` при `MIRROR_SCRIPT_REPORT_KEPT=1` (код тот же, отчёт вернулся).

Механика пятью формами под `bash -e`: `MECH_A_UNGUARDED_RC=3`/`REACHED=0`/`NOTICES=0`,
`MECH_B_GUARDED_RC=3`/`REACHED=1`/`NOTICES=1` (guard сохраняет и вердикт, и отчёт),
`MECH_C_GREEN_RC=0`/`REACHED=1`/`NOTICES=1`, `MECH_D_SET_PLUS_E_RC=3`/`REACHED=1`/`NOTICES=1`,
`MECH_E_GREP_ABORT_RC=1`/`REACHED=0`/`NOTICES=0` (класс `E-0127` отличается по коду обрыва: 1 против
3); шесть сводных утверждений `MECHOK_*` равны 1, в том числе
`MECHOK_ABORT_INDISTINGUISHABLE_BY_RC=1` — по одному коду возврата обрыв неотличим от задуманного
вердикта. Синтаксис: `RCC_SYNTAX_BLOCKS=42`, `RCC_SYNTAX_DUMP_EXIT=0`, `RCC_SYNTAX_BAD=0`,
`RCC_SYNTAX_BLOCKS_EQ_RUN_BLOCKS=1`. Самопроверка: `RCC_SELFTEST_TOTAL=12`,
`RCC_SELFTEST_PASSED=12`, `RCC_SELFTEST_FIRED=0`, `RCC_SELFTEST_FAILED_NAMES=0`,
`RCC_SELFTEST_RC=0`, `RCC_SELFTEST_OK=1`.

Посадки в копии (живое дерево не тронуто): `PLANT_FLIP_*` -> `to_unguarded`, `UNGUARDED=1`,
`GUARDED=25`, `CAPTURES=26`, `RECOUNT_EQ=1`, `EXIT=1`, `NAMED=1`, `NONE=0`; `PLANT_BARE_*` ->
`to_bare_assign`, те же числа; `PLANT_SETE_*` -> `to_set_plus_e`, `UNGUARDED=0`, `GUARDED=26`,
`BLOCKS_SET_PLUS_E=1`, `EXIT=0`, `NAMED=0`, `NONE=1` (освобождение — учёт, а не
дефект); слепой каталог `PLANT_BLIND_LANDED=1`, `PLANT_BLIND_BLIND=1`, `PLANT_BLIND_EXIT=1`. Свод:
`PLANT_LANDED=4`, `PLANT_RED_COUNT=3`, `PLANT_ALL_RED=1`; посадка неверного ожидания красна
(`PLANT_EXPECT_RED=1`).

Границы и wiring: `CODE_CHANGED_RS=0`, `SPEC_DOCS_UNTOUCHED=1`, `RCC_CI_STEP_ADDED=1`,
`RCC_VERIFY_BLOCK_ADDED=1`, `RCC_E0127_INSTRUMENT_UNTOUCHED=1`, `MIRROR_SCRIPT_PIPE_GUARDED=1`,
`SEMICOLON_CAPTURE_LINES=0`. Носитель: `HELPER_BLIND_DIR=0`, `GATE_H0128_OK=1`,
`PRE_PIN_ARCHIVE_OK=1`. Диск и RAM до и после измерений: 21 892 -> 21 839 МБ, RAM 7 426 -> 6 149 МБ,
pagefile peak 7 660 МБ (`DISK_GE_15000=1`, `DISK_AFTER_MEASURE_GE_15000=1`).

Полный контур `bash lab/workspace-verify.sh E-0128`: `VERIFY_FAIL=0`, 132 среза со статусом,
775 passed / 0 failed / 9 ignored, `SECONDS_total=1649`, `TEST_EXIT=0`, `CLIPPY_EXIT=0`, новый блок
стража в контуре даёт `RCC_SELFTEST_EXIT=0`, `RCC_FAIL=0`, `RCC_EXIT=0`; рядом с ним прежний страж
`E-0127` — `CRG_SELFTEST_EXIT=0`, `CRG_UNGUARDED_AT=none`, `CRG_FAIL=0`, `CRG_EXIT=0`."
verdict: supports
---

# E-0128 — зелёный продукт прятал второй класс: `cmd; r=$?` обрывает шаг до присваивания

## Что измеряется

Три вещи, которые обычно путают в одну:

1. **Форма захвата кода возврата в файлах.** `lab/check-ci-rc-capture.py` читает
   `.github/workflows/*.yml`, извлекает блоки `run:` и находит присваивания `$?`, отделённые от команды
   точкой с запятой (`; r=$?`), и присваивания `$?` отдельной строкой после команды, которая может
   упасть. Число находок — `RCC_UNGUARDED`, освобождений `set +e` — `RCC_BLOCKS_SET_PLUS_E`.
2. **Семантика оболочки.** Пять форм прогоняются настоящим `bash -e`, и из них видно, что обрыв
   происходит ДО `r=$?` и ДО отчёта, что `|| r=$?` попадает в исключение errexit (норма — `L-0039`,
   GNU Bash manual, The Set Builtin), что `set +e` освобождает законно и что код обрыва равен коду
   упавшей команды, то есть неотличим от задуманного вердикта. Последнее и есть ответ на вопрос, почему
   класс не нашли раньше.
3. **Живой шаг, а не только статика.** `extractstep` вытаскивает тело шага «зеркало спеки» и исполняет
   его под `bash -e` с пустым `HOME` — состоянием свежего runner'а. До починки получается ровно то, что
   наблюдалось в чужом прогоне (код != 0, ни одной рассылки, ноль строк отчёта), после — три ветки
   носителя ведут себя как задумано, включая красную ветку расхождения.

## Ход цикла (E-0128)

Коммиты: пре-регистрация `c5a4c45` (прибор `lab/check-ci-rc-capture.py`, helper `lab/e0128-run.sh`, таблица 139
фактов, карточки, `ADR-0069` `proposed`, запись `L-0039`, носитель `lab/logs/ci-runner-read-2026-10-27.log`)
→ фикс `472f6e9` (24 захвата в трёх workflow-файлах получают форму `r=0` + `cmd || r=$?`; `diff | head -40` в
`lab/check-spec-mirror.sh` получает guard в конце трубы; шаг «зеркало спеки» переименован честно; два
новых шага в `verify.yml`; блок в `lab/workspace-verify.sh`) → закрытие.

**Почему отдельный номер, а не доделка `E-0127`.** Сообщение владельца говорило про отчётные grep-и, и
`E-0127` это закрыл: после его починки шаги 5…9 работы `verify` стали зелёными. Работа осталась красной
по другой причине, и у неё другой признак: код возврата 3 (или 1, или 101 — код упавшей команды) вместо
1, и ни одной рассылки от шага, который обязан был их разослать. Правила двух приборов не пересекаются
(один смотрит концы труб, другой — присваивания `$?`), зелёный один не говорит ничего про другой, и
это зафиксировано флагом `RCC_E0127_INSTRUMENT_UNTOUCHED=1`: переписывать закрытый прибор ради нового
класса значило бы потерять его вердикты.

**Что поймала подготовка до заморозки (не ДИАГНОЗы прогона, а пять браков, снятых до коммита).**
(1) Самопроверка (j) была построена на буквальной строке «снятие guard'а» и сломалась бы в тот момент,
когда починка landed: деревья после починки такой строки не содержат, и проверка превратилась бы в
посадку-пустышку. Лечится режимом `plant`, который выбирает форму по состоянию строки и печатает
`RCP_DIRECTION`, — поэтому же CI-самопроверка остаётся осмысленной после закрытия цикла. (2) Порог
механики был записан «на рассуждении» (ожидали `RC=1` у обрыва и `RC=0` у `set +e`); ad-hoc исполнение
пяти форм до заморозки дало `RC=3` в обоих случаях, и порог переписан по числам, а утверждение
`MECHOK_ABORT_INDISTINGUISHABLE_BY_RC` добавлено — именно оно объясняет невидимость класса. (3) Посадка
`bare` на красном дереве не увеличивает число находок (одна форма заменяется другой: было 24, стало 24),
и требование «+1» проверяло бы форму дерева, а не прибор; ожидание переписано на «находка названа
формулировкой, `FAIL=1`, число захватов не изменилось, пересчёт сходится». (4) Имена фактов механики
и посадок собирались шаблоном (`MECH_${k^^}_RC`, `PLANT_${kind^^}_RC`) — `lab/threshold-lint.py`
законно назвал 42 порога сиротами, потому что у имени факта обязан быть один литеральный владелец,
а сводные утверждения читают длинное имя `flag`ом и получили бы `MISSING`. Оба цикла развёрнуты в
литеральные блоки (механика общая, имена — буквами); после разворота `СИРОТ=0`. (5) Первый полный
прогон helper'а дал ровно два расхождения — `EXPECT_EXIT` и `EXPECT_ROWS`: таблица требовала код
собственной сверки, которая исполняется позже печати этих ключей, то есть порог был невыполним по
построению. `EXPECT_ROWS` напечатан до сверки (и остался в таблице числом 139), `EXPECT_EXIT` из
таблицы удалён, но печатается в носитель и красит `WORST_RC` через `note` — краснота не потеряна,
потеряна только само-ссылка. Остальные 123 проверяемых числа совпали с замороженными.

**Границы, названные до замера.** Область — workflow-файлы: `lab/*.sh` helper'ы вызывают без `-e` и
берут код через `PIPESTATUS`, поэтому та же идиома в них безопасна. Единственное исключение найдено
чтением, а не прибором, и закрывается этим же циклом: `lab/check-spec-mirror.sh` стоит под собственным
`set -euo pipefail`; проверяется исполнением (`PRE_FIX_MIRROR_SCRIPT_REPORT_LOST=1` →
`MIRROR_SCRIPT_REPORT_KEPT=1`), а не новой регуляркой. Прибор не знает, есть ли в шаге чем вынести
вердикт, — хвост `E-0127`, п. 3, остаётся.

**Что показал полный контур.** `bash lab/workspace-verify.sh E-0128` на закрытом дереве заканчивается
`VERIFY_FAIL=0` при 132 срезе со статусом, 775 passed / 0 failed / 9 ignored и `SECONDS_total=1649`;
`TEST_EXIT=0` и `CLIPPY_EXIT=0` — то есть продуктовый код не шевельнулся (`CODE_CHANGED_RS=0`), а
новый блок стража отработал внутри контура (`RCC_SELFTEST_EXIT=0`, `RCC_FAIL=0`, `RCC_EXIT=0`) рядом с
прежним (`CRG_UNGUARDED_AT=none`, `CRG_EXIT=0`). Числа контура — вердикт хоста, а не раннера: шаги
`verify.yml` на GitHub этим прогоном не засчитаны, они читаются отдельно (`L-0025`).

## Ожидаемое наблюдение чужого прогона

Первое чтение runner'а после починки `E-0127` (`lab/logs/ci-runner-read-2026-10-27.log`): шаг 10
красен, шагов 11…14 нет вовсе — то есть проверка текста, сверка векторов v9 и оба шага стража
`E-0127` на runner'е не запускались. После этого цикла ожидаем зелёную работу `verify` целиком; это
факт чужого прогона, он не засчитывается этому циклу и будет перечитан отдельно (правило: инструментом
считается только прогон с напечатанным числом — `L-0025`).
