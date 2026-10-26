---
id: E-0127
hypothesis: H-0127
status: completed
base_commit: "d18ad2b"
started: "2026-10-26"
finished: "2026-10-26"
environment: "x86_64-pc-windows-gnu, хост владельца; bash + sed + awk + grep + python 3 из PATH,
PyYAML 6.0.3 (нужен `lab/cycle-gate.py`); PATH дополнен /c/Users/Admin/mingw64/bin. Код Rust цикл
не трогает (`CODE_CHANGED_RS=0`), `cargo` в этом helper'е не вызывается вовсе: предмет — текст трёх
workflow-файлов и семантика оболочки, а она проверяется настоящим `bash -e` на синтетических логах.
Отдельная ловушка хоста, записанная сюда до замера: `subprocess` из-windows-python зовёт `bash`,
который резолвится в сломанный WSL-лаунчер, и его вывод выглядит как синтаксические ошибки; поэтому
проверка синтаксиса всех блоков `run:` исполняется из shell (Git Bash), а не из python — недоступный интерпретатор не имеет
права притворяться находкой (ДИАГНОЗ пре-регистрации)"
command: "bash lab/e0127-run.sh"
threshold: "(1) `python lab/cycle-gate.py H-0127` выход 0; диск >= 15 000 МБ до измерений и после них,
печатается три числа (диск/RAM/pagefile), и оба факта в таблице: `DISK_GE_15000=1`,
`DISK_AFTER_MEASURE_GE_15000=1`. (2) PRE_FIX на дереве пина `d18ad2b` из `git archive` с
копией нынешнего прибора внутри (прибора на пине нет — он часть этого цикла):
`PRE_FIX_CRG_FILES=2`, `PRE_FIX_CRG_RUN_BLOCKS=21`, `PRE_FIX_CRG_GREP_STATEMENTS=23`,
`PRE_FIX_CRG_UNGUARDED=21`, `PRE_FIX_CRG_MISPLACED=0`, `PRE_FIX_CRG_VERDICT_GREP=0`,
`PRE_FIX_CRG_LINES_NOGUARD=21`, `PRE_FIX_CRG_RECOUNT_EQ=1`, `PRE_FIX_CRG_BLIND=0`,
`PRE_FIX_CRG_FAIL=1`, `PRE_FIX_CRG_EXIT=1`, `PRE_FIX_RED_NOT_BLIND=1`. Требование «краснота найдена,
а не произведена слепотой» (находок > 0, слепоты = 0, два кода сошлись, выход != 0) внесено сюда
специально: иначе нуль прибора неотличим от того, что он перестал смотреть файлы (прецедент
ДИАГНОЗ-1/2 из `E-0126`). (3) Живой прогон `python lab/check-ci-report-greps.py check` на рабочем
дереве после починки: `CRG_DIR_ABSENT=0`, `CRG_FILES=3`, `CRG_RUN_BLOCKS=32`,
`CRG_GREP_STATEMENTS=30`, `CRG_UNGUARDED=0`, `CRG_MISPLACED=0`, `CRG_VERDICT_GREP=1`,
`CRG_SUBST_GREP=1`, `CRG_LINES_NOGUARD=1`, `CRG_RECOUNT_EQ=1`, `CRG_UNREADABLE=0`, `CRG_BLIND=0`,
`CRG_FAIL=0`, `CRG_EXIT=0`, `CRG_NONE_PRINTED=1` (пустое множество напечатано словом `none`).
(4) Механика исполнения — шесть форм под настоящим `bash -e`, числа обязательны ровно эти:
`MECH_A_UNGUARDED_RC=1` и `MECH_A_UNGUARDED_REACHED=0` (обрыв ДО вердикта),
`MECH_A_GUARDED_RC=0` и `MECH_A_GUARDED_REACHED=1` (guard в конце трубы возвращает вердикту силу),
`MECH_B_UNGUARDED_RC=1`/`REACHED=0` (та же поломка в форме `{ echo; grep; } | while`),
`MECH_B_GUARDED_RC=0`/`REACHED=1`/`NOTICES=1` (правильный guard сохраняет рассылку),
`MECH_C_MISPLACED_HIT_RC=0`/`REACHED=1`/`NOTICES=0` (guard не в конце трубы: зелёный шаг и потерянная
рассылка даже на находке), `MECH_D_MISPLACED_EMPTY_RC=0`/`REACHED=1`/`NOTICES=0` (и на пустоте та же
зелёность, то есть misplaced-форма неотличима от починки по коду возврата). Шесть сводных
утверждений `MECHOK_ABORT_BEFORE_VERDICT`, `MECHOK_GUARD_REACHES_VERDICT`,
`MECHOK_BRACES_ALSO_ABORT`, `MECHOK_GUARD_KEEPS_NOTICES`, `MECHOK_MISPLACED_LOSES_NOTICES`,
`MECHOK_MISPLACED_LOOKS_GREEN` равны 1 — без них цифры остались бы декорацией. (5) Синтаксис: все
блоки `run:` дерева извлекаются и прогоняются через `bash -n` из shell: `SYNTAX_BLOCKS=32`,
`SYNTAX_BAD=0`, `SYNTAX_BLOCKS_EQ_RUN_BLOCKS=1` (под проверку попало ровно столько блоков, сколько
видел прибор, иначе «все синтаксичны» означало бы «половину не извлекли»). (6) Самопроверка прибора:
`python lab/check-ci-report-greps.py selftest` даёт `CRG_SELFTEST_RC=0`, `CRG_SELFTEST_OK=1`,
`CRG_SELFTEST_FIRED=5` — пять форм: две формы guard'а (правильная молчит, misplaced красна), новая
отчётная труба в середине блока, тот же grep в комментарии (не считается), пустой каталог workflow'ов
(слепота красна), четвёртый файл workflow с трубой (перебор обязан его увидеть). (7) Две посадки на
КОПИЯХ починного дерева (`--dir`, живое дерево не трогается): снять guard ->
`PLANT_A_LANDED=1`, `PLANT_A_UNGUARDED=1`, `PLANT_A_EXIT=1`; вписать guard не в конце трубы ->
`PLANT_B_LANDED=1`, `PLANT_B_MISPLACED=1`, `PLANT_B_EXIT=1`, `PLANT_B_NAMED=1` (находка названа
адресом и фрагментом строки); вместе `PLANT_LANDED=2`, `PLANT_ALL_RED=1`. (8) Всё измерение
исполняется дважды на неизменном дереве, файлы фактов совпадают построчно (`diff -q`) -> `STABLE=1`.
(9) Wiring и границы: `CI_STEP_ADDED=1` (страж и его самопроверка стоят шагами в `verify.yml`),
`VERIFY_BLOCK_ADDED=1` (страж стоит в `lab/workspace-verify.sh`), `VERDICT_GREP_KEPT=1` (вердикт-греп
релизного рецепта в `release.yml` НЕ спрятан под guard), `CODE_CHANGED_RS=0` (ни одного `.rs` вне
`lab/`). (10) Полный контур стражей, а не только названное в пороге: `TEXTGUARD_EXIT=0`, `LINT_EXIT=0`,
`CLAIMMAP_EXIT=0`, `REPO_REVIEW_EXIT=0`, `MIRROR_EXIT=0`. (10) Посадка неверного ожидания
(`CRG_UNGUARDED` в копию таблицы со значением 7) обязана покраснеть: `PLANT_EXPECT_RED=1`. Сверка
`lab/expectations/e0127.tsv` против двух файлов фактов: расхождений ноль. (11) Полная верификация
финального дерева `bash lab/workspace-verify.sh E-0127` заканчивается `VERIFY_FAIL=0`, и в ней новый
страж исполняется в составе закрытия цикла. Порог заморожен до первого прогона `lab/e0127-run.sh`;
изменение любого числа — новая карточка. Вне порога остаётся и записано честно: зелёность
`cargo test --workspace` и clippy на runner'е после этой починки — факт ЧУЖОГО прогона (GitHub
Actions), он не может быть засчитан этим циклом на хосте контура и будет перечитан отдельно; тег и
GitHub Release — красная зона владельца."
result: "Починка зелёна на дереве `cd7c2ed` при красном PRE_FIX на пине `d18ad2b`, и это один и тот
же прибор. PRE_FIX (`git archive` пина + копия нынешнего прибора внутри): `PRE_FIX_CRG_FILES=2`,
`PRE_FIX_CRG_RUN_BLOCKS=21`, `PRE_FIX_CRG_GREP_STATEMENTS=23`, `PRE_FIX_CRG_UNGUARDED=21`,
`PRE_FIX_CRG_MISPLACED=0`, `PRE_FIX_CRG_VERDICT_GREP=0`, `PRE_FIX_CRG_LINES_NOGUARD=21`,
`PRE_FIX_CRG_RECOUNT_EQ=1`, `PRE_FIX_CRG_BLIND=0`, `PRE_FIX_CRG_FAIL=1`, `PRE_FIX_CRG_EXIT=1`,
`PRE_FIX_RED_NOT_BLIND=1` — краснота найдена (21 адресованная строка), а не произведена слепотой.
Живой прогон после починки: `CRG_DIR_ABSENT=0`, `CRG_FILES=3`, `CRG_RUN_BLOCKS=32`,
`CRG_GREP_STATEMENTS=30`, `CRG_UNGUARDED=0`, `CRG_MISPLACED=0`, `CRG_VERDICT_GREP=1`,
`CRG_SUBST_GREP=1`, `CRG_LINES_NOGUARD=1`, `CRG_RECOUNT_EQ=1`, `CRG_UNREADABLE=0`, `CRG_BLIND=0`,
`CRG_FAIL=0`, `CRG_EXIT=0`, пустое множество напечатано словом (`CRG_UNGUARDED_AT=none`,
`CRG_MISPLACED_AT=none`, `CRG_NONE_PRINTED=1`). Механика шестью формами под настоящим `bash -e`:
`MECH_A_UNGUARDED_RC=1` при `MECH_A_UNGUARDED_REACHED=0` (обрыв ДО вердикта),
`MECH_A_GUARDED_RC=0`/`REACHED=1` (guard в конце трубы возвращает вердикту силу),
`MECH_B_UNGUARDED_RC=1`/`REACHED=0` (та же поломка в форме `{ echo; grep; } | while`),
`MECH_B_GUARDED_RC=0`/`REACHED=1`/`NOTICES=1` (правильный guard сохраняет рассылку),
`MECH_C_MISPLACED_HIT_RC=0`/`REACHED=1`/`NOTICES=0` и `MECH_D_MISPLACED_EMPTY_RC=0`/`REACHED=1`/
`NOTICES=0` (misplaced-guard зелёный и на находке, и на пустоте, то есть неотличим от починки по
коду возврата); шесть сводных утверждений `MECHOK_ABORT_BEFORE_VERDICT`,
`MECHOK_GUARD_REACHES_VERDICT`, `MECHOK_BRACES_ALSO_ABORT`, `MECHOK_GUARD_KEEPS_NOTICES`,
`MECHOK_MISPLACED_LOSES_NOTICES`, `MECHOK_MISPLACED_LOOKS_GREEN` равны 1. Синтаксис: извлечено и
прогнано через `bash -n` все блоки `run:` — `SYNTAX_BLOCKS=32`, `SYNTAX_BAD=0`,
`SYNTAX_BLOCKS_EQ_RUN_BLOCKS=1`. Самопроверка прибора: `CRG_SELFTEST_RC=0`, `CRG_SELFTEST_OK=1`,
`CRG_SELFTEST_FIRED=5` (пять форм, включая слепой каталог и четвёртый файл). Посадки на копиях
починного дерева: `PLANT_A_LANDED=1`, `PLANT_A_UNGUARDED=1`, `PLANT_A_EXIT=1`, `PLANT_B_LANDED=1`,
`PLANT_B_MISPLACED=1`, `PLANT_B_EXIT=1`, `PLANT_B_NAMED=1`, `PLANT_LANDED=2`, `PLANT_ALL_RED=1`.
Границы и wiring: `CODE_CHANGED_RS=0`, `VERDICT_GREP_KEPT=1`, `CI_STEP_ADDED=1`,
`VERIFY_BLOCK_ADDED=1`. Всё измерение дважды на неизменном дереве — `STABLE=1`; цена прогона helper'а
44 с. Контур стражей: `TEXTGUARD_EXIT=0`, `LINT_EXIT=0`, `CLAIMMAP_EXIT=0`, `REPO_REVIEW_EXIT=0`,
`MIRROR_EXIT=0`; посадка неверного ожидания красна (`PLANT_EXPECT_RED=1`), сверка
`ОЖИДАНИЙ=80 РАСХОЖДЕНИЙ=0`, `EXPECT_EXIT=0`, `HELPER_EXIT=0`. Полный контур
`bash lab/workspace-verify.sh E-0127`: Полный контур `bash lab/workspace-verify.sh E-0127` на финальном дереве: VERIFY_FAIL=0, 132 среза / 775 passed / 0 failed / 9 ignored, SECONDS_total=1460, CLIPPY_EXIT=0, CRG_SELFTEST_EXIT=0 и CRG_EXIT=0 (страж исполняется в составе закрытия круга), TEXTGUARD_EXIT=0, CLAIMMAP_EXIT=0, REPO_REVIEW_EXIT=0, MIRROR_EXIT=0; диск 22 013 → 22 045 МБ, RAM 9 208 → 9 915 МБ, pagefile peak 7 660 МБ. Носитель до и после измерений: диск
22 020 → 21 970 МБ, RAM 9 753 МБ, pagefile peak 7 660 МБ (допуск >= 15 000 МБ,
`DISK_GE_15000=1`, `DISK_AFTER_MEASURE_GE_15000=1`)."
verdict: supports
---

# E-0127 — красный `verify` при зелёном продукте: отчётный grep обрывает шаг до вердикта

## Что измеряется

Три вещи, которые обычно путают в одну:

1. **Форма труб в файлах.** `lab/check-ci-report-greps.py` читает `.github/workflows/*.yml`, находит
   блоки `run:`, склеивает переносы backslash в statement'ы и смотрит, есть ли ` || true` (или
   `|| :`) в конце каждой отчётной трубы. Число находок — `CRG_UNGUARDED`, число неправильно
   поставленных guard'ов — `CRG_MISPLACED`.
2. **Семантика оболочки.** Шесть форм прогоняются настоящим `bash -e`, и из них видно, что обрыв
   происходит ДО `exit $r`, что спасает только guard в конце трубы, и что misplaced-guard зелёный и
   молча теряет рассылку `::notice::`. Это и есть основание считать вторую форму дефектом, а не
   косметикой.
3. **Наличие прибора в контуре.** Шаг в CI и блок в `lab/workspace-verify.sh` печатаются фактами,
   потому что страж, которого не гоняют, через пять циклов — это зелёный текст.

## Ход цикла (E-0127)

Коммиты: пре-регистрация `d3cb780` (прибор, helper, таблица 80 фактов, карточки, `ADR-0068`
`proposed`, запись `L-0038`, блок в `lab/workspace-verify.sh`) → фикс `cd7c2ed` (23 отчётные трубы в
трёх workflow'ах получают ` || true` в конце трубы; два новых шага в `verify.yml`; вердикт-греп
рецепта в `release.yml` не тронут) → ДИАГНОЗ-1 `27e4595` → закрытие (этот коммит).

**ДИАГНОЗ-1 — носитель не печатал производные факты.** Первая версия helper'а складывала строки
`PRE_FIX_*`, `MECH_*`, `SYNTAX_*`, `PLANT_*` только в файл фактов temp-каталога, а в
`lab/logs/e0127-all.log` попадали печати самих приборов. Формально сверка работала
(`ОЖИДАНИЙ=80 РАСХОЖДЕНИЙ=0`), но читатель лога не мог перепроверить ни одного производного числа:
`PRE_FIX_CRG_UNGUARDED=21` в логе не печаталось, а значит отчёт описывал внутренность helper'а, а не
дерево. Это ровно та форма молчания, против которой в контуре стоит правило «пустое множество
печатается словом». Правка — одна строка (`femit` печатает в лог рядом с записью в файл); пороги,
набор фактов и их значения не менялись, и перепись лога после правки даёт те же 80 совпадений при
`STABLE=1`. Урок в то же правило: производный факт годен в вердикт только если он напечатан.

**Что поймала пре-регистрация до замера (не ДИАГНОЗ прогона, а три брака, снятых до коммита).**
(1) Извлечение блоков `run:` для `bash -n` и разбор блоков у прибора — два разных кода, и исходно
их регулярки различались (прибор видел и `- run:`, и складывающий стиль `run: >`, экстрактор — нет),
из-за чего «все блоки синтаксичны» означало бы «все, которые мы случайно не потеряли». Лечится не
угадыванием, а флагом `SYNTAX_BLOCKS_EQ_RUN_BLOCKS=1`: под `bash -n` обязано попасть ровно столько
блоков, сколько насчитывает прибор (32 и 32), а две регулярки сведены в одну форму. (2)
Сводные утверждения механики собирались именем-шаблоном (`MECHOK_$1`), из-за чего `threshold-lint`
законно не находил их источника: у имени факта обязан быть один владелец, и литерал должен стоять в
тексте helper'а — оба варианта (`=1` и `=0`) теперь печатаются буквами. (3) Ключ диска после
измерений читался `lab/expect.py` до того, как был напечатан: порядок шагов переставлен (сверка —
последняя), и ключ переименован в `DISK_AFTER_MEASURE_GE_15000`.

**Механика, а не догадка.** Выбор формы правки (` || true` в конце трубы, а не после `grep`) стоит
на шести исполнениях `bash -e`, а не на чтении документации: `MECH_C_MISPLACED_HIT_RC=0` при
`NOTICES=0` показывает, что неправильная форма не краснеет никогда, — то есть починка ею была бы
неотличима от поломки. Отсюда отдельный флаг `CRG_MISPLACED` и отдельная посадка (`PLANT_B_*`).

**Что осталось за границей.** Зелёность `verify` на GitHub после пуша не наблюдалась и наблюдаться
этим циклом не может (раннер — чужой прогон); после починки `cargo test --workspace` и clippy
становятся видны в CI впервые, и их возможный красный вердикт по содержанию — отдельный цикл;
гранулярность прибора — statement'ы, две трубы в одной строке (одна под guard'ом, вторая без) от
него ускользают, в дереве такой формы нет, и это записано в docstring прибора, а не промолчано.
