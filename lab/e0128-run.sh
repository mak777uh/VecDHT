#!/usr/bin/env bash
# Helper цикла E-0128 — «захват кода возврата через `cmd; r=$?` под `bash -e`».
#
# Предмет: текст шагов трёх workflow-файлов и семантика оболочки, которая их исполняет. Cargo
# не вызывается вовсе: проверка — настоящим `bash -e` на синтетических формах и на ИЗВЛЕЧЁННОМ
# теле живого шага «зеркало спеки», потому что именно этот шаг покраснел на runner'е
# 2026-10-26 после починки E-0127 (в логе работы: после `##[endgroup]` ни одной строки вывода,
# код 1 — шаг оборвался на захвате, не дойдя до своей ветки `MIRROR_ABSENT_ON_RUNNER`).
#
# Исполняется ДВАЖДЫ на неизменном дереве; файлы фактов сверяются `diff -q` (правило 7 (е):
# факт годен в вердикт только если инвариантен к расписанию шагов). Поэтому ни один ключ не
# содержит метки времени или счётчика строк журнала: время печатается только в заголовок (`say`).
#
# Две ловушки хоста перенесены из E-0127 дословно: `subprocess` из windows-python зовёт `bash`,
# который резолвится в сломанный WSL-лаунчер (вывод — UTF-16 мусор), и потому вся механика
# исполняется отсюда, из shell; PowerShell-метки на кириллице бьёт кодовая страница, и потому
# сводные утверждения печатаются ключами, а не подписями.

set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0128-all.log"
PIN=f62b681
EXPECT="lab/expectations/e0128.tsv"
CRCC="lab/check-ci-rc-capture.py"
WF=".github/workflows"
LIMIT=30
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0128.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
G="$OUT/facts_global.txt"
F1="$OUT/facts1.txt"
F2="$OUT/facts2.txt"
: > "$G"; : > "$F1"; : > "$F2"

note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }
femit() { printf '%s\n' "$2" >> "$1"; printf '%s\n' "$2" | tee -a "$LOG" >/dev/null; }
# Факт из вывода прибора: строка `KEY=значение` с якорем по началу строки. Пустое значение
# печатается как MISSING и красит сверку: молчание прогона не считается успехом.
flag() { # flag <файл> <ключ>
  local v
  v=$(sed -n "s|^${2}=||p" "$1" 2>/dev/null | head -1)
  [ -n "$v" ] || v=MISSING
  printf '%s' "$v"
}
count_of() { # count_of <файл с выводом> <фиксированная подстрока>
  grep -aF -- "$2" "$1" 2>/dev/null | wc -l | tr -d ' '
}
all1() { # all1 <0|1 ...> -> 1 если все единицы (сводное утверждение, а не декорация цифр)
  local a
  for a in "$@"; do [ "$a" = 1 ] || { echo 0; return 0; }; done
  echo 1
}

say "########## E-0128 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

# Носитель краснеет до первого замера, если запущен не из корня дерева: иначе его «ноль находок»
# неотличим от «прибор не увидел файлов» (то же правило, что `RCC_BLIND` у самого прибора).
if [ ! -d "$WF" ] || [ ! -f "$CRCC" ] || [ ! -f "$EXPECT" ]; then
  emit0 "HELPER_BLIND_DIR=1"
  emit0 "HELPER_MISSING=$( [ -d "$WF" ] || echo -n "$WF " )$( [ -f "$CRCC" ] || echo -n "$CRCC " )$( [ -f "$EXPECT" ] || echo "$EXPECT" )"
  say "СТОП: helper запущен вне корня дерева ($VEC_DHT_ROOT); замер не исполнен"
  exit 1
fi
emit0 "HELPER_BLIND_DIR=0"

say "### ШАГ 0 гейт, носитель и ресурсы до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py H-0128 2>&1 | tail -n 12 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "GATE_H0128_OK=$( [ "$rc" -eq 0 ] && echo 1 || echo 0 )"
[ "$rc" -eq 0 ] || note 1
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf '%s' "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
ram=$(printf '%s' "$res" | sed -n 's/.*RAM_FREE_MB=\([0-9]*\).*/\1/p')
pf=$(printf '%s' "$res" | sed -n 's/.*PAGEFILE_PEAK_MB=\([0-9]*\).*/\1/p')
emit0 "DISK_BEFORE_MB=${disk:-MISSING}"
emit0 "RAM_BEFORE_MB=${ram:-MISSING}"
emit0 "PAGEFILE_BEFORE_MB=${pf:-MISSING}"
emit0 "DISK_GE_15000=$( [ "${disk:-0}" -ge 15000 ] && echo 1 || echo 0 )"
[ "${disk:-0}" -ge 15000 ] || note 1

# ----------------------------------------------------------------------------- измерения
measure() { # measure <файл-фактов> <метка исполнения>
  local F="$1" tag="$2" P="$OUT/m$2" S="$OUT/step$2" TMP o rc v u bl fl bad k n land red R f
  rm -rf "$P"; mkdir -p "$P" "$S"

  say "=== измерение $tag ==="
  mkdir -p "$P/pin"
  git archive "$PIN" | tar -x -C "$P/pin"
  rc=${PIPESTATUS[1]}
  femit "$F" "PRE_PIN_ARCHIVE_OK=$( [ "$rc" -eq 0 ] && echo 1 || echo 0 )"
  [ "$rc" -eq 0 ] || note 1

  # --- 1. PRE_FIX: нынешний прибор на дереве пина (прибора на пине нет — он часть цикла)
  o="$P/pre_scan.txt"
  python "$CRCC" check --dir "$P/pin" --limit "$LIMIT" > "$o" 2>&1; rc=$?
  femit "$F" "PRE_FIX_RCC_FILES=$(flag "$o" RCC_FILES)"
  femit "$F" "PRE_FIX_RCC_RUN_BLOCKS=$(flag "$o" RCC_RUN_BLOCKS)"
  femit "$F" "PRE_FIX_RCC_BLOCKS_SET_PLUS_E=$(flag "$o" RCC_BLOCKS_SET_PLUS_E)"
  femit "$F" "PRE_FIX_RCC_CAPTURES=$(flag "$o" RCC_CAPTURES)"
  femit "$F" "PRE_FIX_RCC_GUARDED=$(flag "$o" RCC_GUARDED)"
  femit "$F" "PRE_FIX_RCC_UNGUARDED=$(flag "$o" RCC_UNGUARDED)"
  femit "$F" "PRE_FIX_RCC_LINES_UNGUARDED=$(flag "$o" RCC_LINES_UNGUARDED)"
  femit "$F" "PRE_FIX_RCC_RECOUNT_EQ=$(flag "$o" RCC_RECOUNT_EQ)"
  femit "$F" "PRE_FIX_RCC_BLIND=$(flag "$o" RCC_BLIND)"
  femit "$F" "PRE_FIX_RCC_FAIL=$(flag "$o" RCC_FAIL)"
  femit "$F" "PRE_FIX_RCC_EXIT=$rc"
  femit "$F" "PRE_FIX_RCC_FILES_WITH_FINDINGS=$(count_of "$o" 'RCC_UNGUARDED_FILE=')"
  femit "$F" "PRE_FIX_RCC_FINDINGS_PRINTED=$(count_of "$o" 'RCC_UNGUARDED_AT=')"
  femit "$F" "PRE_FIX_RCC_MORE_FLAG=$(count_of "$o" 'RCC_UNGUARDED_MORE=')"
  # Краснота обязана быть НАЙДЕННОЙ, а не произведённой слепотой (прецедент ДИАГНОЗА из E-0126).
  u=$(flag "$o" RCC_UNGUARDED); bl=$(flag "$o" RCC_BLIND); fl=$(flag "$o" RCC_FAIL)
  femit "$F" "PRE_FIX_RCC_RED_NOT_BLIND=$( [ "$u" != 0 ] && [ "$u" != MISSING ] \
    && [ "$bl" = 0 ] && [ "$fl" = 1 ] && [ "$rc" != 0 ] && echo 1 || echo 0 )"
  [ "$u" != 0 ] || note 1
  [ "$bl" = 0 ] || note 1
  [ "$fl" = 1 ] || note 1
  [ "$rc" != 0 ] || note 1

  # --- 2. PRE_FIX механика на пине: тело живого шага под настоящим `bash -e`.
  #      Это воспроизведение runner'а: шаг по замыслу обязан сойти нулём с названной веткой.
  TMP="$P/home-empty"; mkdir -p "$TMP"
  o="$P/pre_extract.txt"
  python "$CRCC" extractstep --dir "$P/pin" --name "зеркало спеки" \
    --out "$S/pre_mirror.sh" > "$o" 2>&1; rc=$?
  femit "$F" "PRE_FIX_RCS_MATCHES=$(flag "$o" RCS_MATCHES)"
  femit "$F" "PRE_FIX_RCS_EXIT=$rc"
  femit "$F" "PRE_FIX_RCS_BLOCK_LINES=$(flag "$o" RCS_BLOCK_LINES)"
  femit "$F" "PRE_FIX_MIRROR_STEP_DENIES_EXECUTION=$(count_of "$o" 'RCS_STEP=НЕ ИСПОЛНЯЕТСЯ')"
  [ "$rc" -eq 0 ] || note 1
  o="$P/pre_mirror.out"
  ( cd "$P/pin" && GITHUB_STEP_SUMMARY="$P/pre.sum" HOME="$TMP" bash -e "$S/pre_mirror.sh" ) \
    > "$o" 2>&1; rc=$?
  femit "$F" "PRE_FIX_MIRROR_ABSENT_EXIT=$rc"
  femit "$F" "PRE_FIX_MIRROR_ABSENT_NOTICE=$(count_of "$o" 'MIRROR_ABSENT_ON_RUNNER')"
  femit "$F" "PRE_FIX_MIRROR_REPORT_LINES=$(count_of "$o" 'MIRROR_RC=')"
  femit "$F" "PRE_FIX_MIRROR_SILENT_ABORT=$(all1 "$( [ "$rc" != 0 ] && echo 1 )" \
    "$( [ "$(count_of "$o" 'MIRROR_ABSENT_ON_RUNNER')" = 0 ] && echo 1 )" \
    "$( [ "$(count_of "$o" 'MIRROR_RC=')" = 0 ] && echo 1 )" )"
  [ "$rc" != 0 ] || note 1
  [ "$(flag "$F" PRE_FIX_MIRROR_SILENT_ABORT)" = 1 ] || note 1
  # Тот же класс ВНУТРИ самого guard'а: `diff | head -40` под `set -euo pipefail` обрывает
  # скрипт раньше его последней отчётной строки. Проверяется исполнением, а не статикой:
  # прибор смотрит только workflow-файлы (граница названа в его docstring).
  R="$P/home-div-pin"; mkdir -p "$R/OneDrive/Desktop"
  cp "$P/pin"/docs/VecDHT-SPEC-v8.md "$P/pin"/docs/VecDHT-SPEC-v9.md "$R/OneDrive/Desktop/"
  printf '%s\n' '' 'посаженное расхождение' >> "$R/OneDrive/Desktop/VecDHT-SPEC-v9.md"
  o="$P/pre_script.out"
  HOME="$R" bash "$P/pin/lab/check-spec-mirror.sh" > "$o" 2>&1; rc=$?
  femit "$F" "PRE_FIX_MIRROR_SCRIPT_DIVERGE_RC=$rc"
  femit "$F" "PRE_FIX_MIRROR_SCRIPT_REPORT_KEPT=$(count_of "$o" 'починить:')"
  femit "$F" "PRE_FIX_MIRROR_SCRIPT_REPORT_LOST=$( [ "$rc" != 0 ] \
    && [ "$(count_of "$o" 'починить:')" = 0 ] && echo 1 || echo 0 )"
  [ "$rc" != 0 ] || note 1
  [ "$(flag "$F" PRE_FIX_MIRROR_SCRIPT_REPORT_LOST)" = 1 ] || note 1
  rm -rf "$R"

  # --- 3. Живой скан нынешнего дерева (после починки обязан быть нулевым)
  o="$P/live_scan.txt"
  python "$CRCC" check --limit "$LIMIT" > "$o" 2>&1; rc=$?
  femit "$F" "RCC_FILES=$(flag "$o" RCC_FILES)"
  femit "$F" "RCC_RUN_BLOCKS=$(flag "$o" RCC_RUN_BLOCKS)"
  femit "$F" "RCC_BLOCKS_SET_PLUS_E=$(flag "$o" RCC_BLOCKS_SET_PLUS_E)"
  femit "$F" "RCC_CAPTURES=$(flag "$o" RCC_CAPTURES)"
  femit "$F" "RCC_GUARDED=$(flag "$o" RCC_GUARDED)"
  femit "$F" "RCC_UNGUARDED=$(flag "$o" RCC_UNGUARDED)"
  femit "$F" "RCC_LINES_UNGUARDED=$(flag "$o" RCC_LINES_UNGUARDED)"
  femit "$F" "RCC_RECOUNT_EQ=$(flag "$o" RCC_RECOUNT_EQ)"
  femit "$F" "RCC_BLIND=$(flag "$o" RCC_BLIND)"
  femit "$F" "RCC_FAIL=$(flag "$o" RCC_FAIL)"
  femit "$F" "RCC_EXIT=$rc"
  femit "$F" "RCC_NONE_PRINTED=$(count_of "$o" 'RCC_UNGUARDED_FILE=none')"
  femit "$F" "RCC_MORE_NONE_PRINTED=$(count_of "$o" 'RCC_UNGUARDED_MORE=none')"
  [ "$rc" -eq 0 ] || note 1

  # --- 4. Механика: пять форм под настоящим `bash -e` (форма правки выбирается по их числам)
  M="$OUT/mech$tag"; mkdir -p "$M"
  cat > "$M/a_unguarded.sh" <<'EOS'
set -uo pipefail
L=/tmp/e0128-a.log
bash -c 'exit 3' > "$L" 2>&1; r=$?
echo "::notice::REPORT r=$r"
echo "REACHED"
exit $r
EOS
  cat > "$M/b_guarded.sh" <<'EOS'
set -uo pipefail
L=/tmp/e0128-b.log
r=0
bash -c 'exit 3' > "$L" 2>&1 || r=$?
echo "::notice::REPORT r=$r"
echo "REACHED"
exit $r
EOS
  cat > "$M/c_green.sh" <<'EOS'
set -uo pipefail
L=/tmp/e0128-c.log
bash -c 'exit 0' > "$L" 2>&1; r=$?
echo "::notice::REPORT r=$r"
echo "REACHED"
exit $r
EOS
  cat > "$M/d_set_plus_e.sh" <<'EOS'
set +e
L=/tmp/e0128-d.log
bash -c 'exit 3' > "$L" 2>&1; r=$?
echo "::notice::REPORT r=$r"
echo "REACHED"
exit $r
EOS
  cat > "$M/e_grep_abort.sh" <<'EOS'
set -uo pipefail
L=/tmp/e0128-e.log
bash -c 'exit 0' > "$L" 2>&1; r=$?
grep -aE 'НИЧЕГО_НЕ_СОВАЕТСЯ' "$L" | tail -2
echo "REACHED"
exit $r
EOS
  # Имена фактов печатаются БУКВАМИ по форме, а не шаблоном `MECH_${k^^}_`: у имени факта обязан
  # быть один литеральный владелец, иначе `lab/threshold-lint.py` законно называет порог сиротой,
  # а сводное утверждение ниже читает flag'ом длинное имя и получило бы MISSING.
  runmech() { bash -e "$M/$1.sh" > "$M/$1.out" 2>&1; MECH_RC=$?; }
  runmech a_unguarded
  femit "$F" "MECH_A_UNGUARDED_RC=$MECH_RC"
  femit "$F" "MECH_A_UNGUARDED_REACHED=$(count_of "$M/a_unguarded.out" 'REACHED')"
  femit "$F" "MECH_A_UNGUARDED_NOTICES=$(count_of "$M/a_unguarded.out" '::notice::REPORT')"
  runmech b_guarded
  femit "$F" "MECH_B_GUARDED_RC=$MECH_RC"
  femit "$F" "MECH_B_GUARDED_REACHED=$(count_of "$M/b_guarded.out" 'REACHED')"
  femit "$F" "MECH_B_GUARDED_NOTICES=$(count_of "$M/b_guarded.out" '::notice::REPORT')"
  runmech c_green
  femit "$F" "MECH_C_GREEN_RC=$MECH_RC"
  femit "$F" "MECH_C_GREEN_REACHED=$(count_of "$M/c_green.out" 'REACHED')"
  femit "$F" "MECH_C_GREEN_NOTICES=$(count_of "$M/c_green.out" '::notice::REPORT')"
  runmech d_set_plus_e
  femit "$F" "MECH_D_SET_PLUS_E_RC=$MECH_RC"
  femit "$F" "MECH_D_SET_PLUS_E_REACHED=$(count_of "$M/d_set_plus_e.out" 'REACHED')"
  femit "$F" "MECH_D_SET_PLUS_E_NOTICES=$(count_of "$M/d_set_plus_e.out" '::notice::REPORT')"
  runmech e_grep_abort
  femit "$F" "MECH_E_GREP_ABORT_RC=$MECH_RC"
  femit "$F" "MECH_E_GREP_ABORT_REACHED=$(count_of "$M/e_grep_abort.out" 'REACHED')"
  femit "$F" "MECH_E_GREP_ABORT_NOTICES=$(count_of "$M/e_grep_abort.out" '::notice::REPORT')"
  # Пять сводных утверждений: без них цифры остались бы декорацией. Порог каждой формы назван
  # ЧИСЛОМ, измеренным до заморозки (ad-hoc исполнение этих же пяти файлов), а не рассуждением:
  # у формы с `bash -c 'exit 3'` обрванный шаг даёт RC=3, а не RC=1, потому что errexit уходит из
  # оболочки со статусом последней команды. Это и есть шестое утверждение — код возврата обрыва
  # неотличим от кода возврата задуманного вердикта, поэтому класс и был невидим.
  femit "$F" "MECHOK_UNGUARDED_ABORTS_BEFORE_REPORT=$(all1 \
    "$( [ "$(flag "$F" MECH_A_UNGUARDED_RC)" = 3 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_A_UNGUARDED_REACHED)" = 0 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_A_UNGUARDED_NOTICES)" = 0 ] && echo 1 )" )"
  femit "$F" "MECHOK_GUARDED_KEEPS_VERDICT=$(all1 \
    "$( [ "$(flag "$F" MECH_B_GUARDED_RC)" = 3 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_B_GUARDED_REACHED)" = 1 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_B_GUARDED_NOTICES)" = 1 ] && echo 1 )" )"
  femit "$F" "MECHOK_GREEN_LOOKS_FINE=$(all1 \
    "$( [ "$(flag "$F" MECH_C_GREEN_RC)" = 0 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_C_GREEN_REACHED)" = 1 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_C_GREEN_NOTICES)" = 1 ] && echo 1 )" )"
  femit "$F" "MECHOK_SET_PLUS_E_EXEMPTS=$(all1 \
    "$( [ "$(flag "$F" MECH_D_SET_PLUS_E_RC)" = 3 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_D_SET_PLUS_E_REACHED)" = 1 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_D_SET_PLUS_E_NOTICES)" = 1 ] && echo 1 )" )"
  femit "$F" "MECHOK_CLASS_IS_E0127_NOT_RC=$(all1 \
    "$( [ "$(flag "$F" MECH_E_GREP_ABORT_RC)" = 1 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_E_GREP_ABORT_REACHED)" = 0 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_C_GREEN_RC)" = 0 ] && echo 1 )" )"
  # Главное утверждение класса: по одному только коду возврата починка неотличима от обрыва
  # (оба 3), а по дожитию отчёта — различима. Именно поэтому зелёный продукт прятал дефект.
  femit "$F" "MECHOK_ABORT_INDISTINGUISHABLE_BY_RC=$(all1 \
    "$( [ "$(flag "$F" MECH_A_UNGUARDED_RC)" = "$(flag "$F" MECH_B_GUARDED_RC)" ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_A_UNGUARDED_RC)" = 3 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_A_UNGUARDED_REACHED)" = 0 ] && echo 1 )" \
    "$( [ "$(flag "$F" MECH_B_GUARDED_REACHED)" = 1 ] && echo 1 )" )"
  for k in MECHOK_UNGUARDED_ABORTS_BEFORE_REPORT MECHOK_GUARDED_KEEPS_VERDICT \
           MECHOK_GREEN_LOOKS_FINE MECHOK_SET_PLUS_E_EXEMPTS MECHOK_CLASS_IS_E0127_NOT_RC \
           MECHOK_ABORT_INDISTINGUISHABLE_BY_RC; do
    [ "$(flag "$F" "$k")" = 1 ] || note 1
  done

  # --- 5. Живой шаг «зеркало спеки»: три ветки носителя, все под `bash -e`
  o="$P/r_extract.txt"
  python "$CRCC" extractstep --name "зеркало спеки" --out "$S/live_mirror.sh" > "$o" 2>&1
  rc=$?
  femit "$F" "RCS_MATCHES=$(flag "$o" RCS_MATCHES)"
  femit "$F" "RCS_EXIT=$rc"
  femit "$F" "RCS_VERIFY_YML=$(count_of "$o" 'RCS_FILE=.github/workflows/verify.yml')"
  femit "$F" "MIRROR_STEP_DENIES_EXECUTION=$(count_of "$o" 'RCS_STEP=НЕ ИСПОЛНЯЕТСЯ')"
  [ "$rc" -eq 0 ] || note 1
  TMP="$OUT/home-empty-$tag"; mkdir -p "$TMP"
  o="$P/absent.out"
  ( GITHUB_STEP_SUMMARY="$P/absent.sum" HOME="$TMP" bash -e "$S/live_mirror.sh" ) > "$o" 2>&1
  rc=$?
  femit "$F" "MIRROR_ABSENT_EXIT=$rc"
  femit "$F" "MIRROR_ABSENT_NOTICE=$(count_of "$o" 'MIRROR_ABSENT_ON_RUNNER')"
  femit "$F" "MIRROR_ABSENT_LOG_NAMED=$(count_of "$o" 'нет на месте')"
  [ "$rc" -eq 0 ] || note 1
  [ "$(count_of "$o" 'MIRROR_ABSENT_ON_RUNNER')" = 1 ] || note 1
  R="$OUT/home-ok-$tag"; mkdir -p "$R/OneDrive/Desktop"
  cp docs/VecDHT-SPEC-v8.md docs/VecDHT-SPEC-v9.md "$R/OneDrive/Desktop/"
  o="$P/ok.out"
  ( GITHUB_STEP_SUMMARY="$P/ok.sum" HOME="$R" bash -e "$S/live_mirror.sh" ) > "$o" 2>&1
  rc=$?
  femit "$F" "MIRROR_OK_EXIT=$rc"
  femit "$F" "MIRROR_OK_NOTICE=$(count_of "$o" 'MIRROR_OK=1')"
  [ "$rc" -eq 0 ] || note 1
  printf '%s\n' '' 'посаженное расхождение' >> "$R/OneDrive/Desktop/VecDHT-SPEC-v9.md"
  o="$P/bad.out"
  ( GITHUB_STEP_SUMMARY="$P/bad.sum" HOME="$R" bash -e "$S/live_mirror.sh" ) > "$o" 2>&1
  rc=$?
  femit "$F" "MIRROR_DIVERGE_EXIT=$rc"
  femit "$F" "MIRROR_DIVERGE_ERROR=$(count_of "$o" '::error::MIRROR_RC=')"
  [ "$rc" != 0 ] || note 1
  [ "$(count_of "$o" '::error::MIRROR_RC=')" = 1 ] || note 1
  # И тот же класс внутри guard'а, на ЖИВОМ скрипте: отчёт обязан дожить до своей строки.
  o="$P/script.out"
  HOME="$R" bash lab/check-spec-mirror.sh > "$o" 2>&1; rc=$?
  femit "$F" "MIRROR_SCRIPT_DIVERGE_RC=$rc"
  femit "$F" "MIRROR_SCRIPT_REPORT_KEPT=$(count_of "$o" 'починить:')"
  [ "$rc" != 0 ] || note 1
  [ "$(count_of "$o" 'починить:')" = 1 ] || note 1
  rm -rf "$R" "$TMP"

  # --- 6. Синтаксис всех блоков: один парсер с прибором, число обязано сойтись
  o="$P/dump.txt"
  python "$CRCC" dumpblocks --out "$P/blocks" > "$o" 2>&1; rc=$?
  femit "$F" "RCC_SYNTAX_BLOCKS=$(flag "$o" RCD_BLOCKS)"
  femit "$F" "RCC_SYNTAX_DUMP_EXIT=$rc"
  bad=0
  for f in "$P"/blocks/*; do
    bash -n "$f" > "$f.n" 2>&1 || bad=$((bad + 1))
  done
  femit "$F" "RCC_SYNTAX_BAD=$bad"
  [ "$bad" -eq 0 ] || note 1
  femit "$F" "RCC_SYNTAX_BLOCKS_EQ_RUN_BLOCKS=$(all1 \
    "$( [ "$(flag "$F" RCC_SYNTAX_BLOCKS)" = "$(flag "$F" RCC_RUN_BLOCKS)" ] && echo 1 )" \
    "$( [ "$(flag "$F" RCC_SYNTAX_BLOCKS)" != MISSING ] && echo 1 )" )"
  [ "$(flag "$F" RCC_SYNTAX_BLOCKS_EQ_RUN_BLOCKS)" = 1 ] || note 1

  # --- 7. Посадки на КОПИЯХ живого дерева. `plant` сам выбирает форму по состоянию строки,
  #        поэтому эти же проверки годны и на дереве до починки (и CI гоняет их после неё).
  #        Имена фактов печатаются БУКВАМИ (по блоку на посадку), а не шаблоном `PLANT_${kind^^}_`:
  #        `lab/threshold-lint.py` считает ключ напечатанным только если он стоит в источнике как
  #        есть, и этот же класс брака был разобран в `E-0127` (сводные утверждения собирались
  #        именем-шаблоном, и линт законно не нашёл их владельца). Механика общая, имена — literal.
  land=0; red=0
  for kind in flip bare sete; do
    R="$P/plant_$kind"; mkdir -p "$R/$WF"
    cp "$WF"/*.yml "$R/$WF/"
    o="$P/plant_${kind}_rc.txt"
    python "$CRCC" plant --dir "$R" --file verify.yml --kind "$kind" > "$o" 2>&1; rc=$?
    v=$(flag "$o" RCP_LANDED)
    # Арифметика только по цифре: посадка, которая не напечатала `RCP_LANDED`, обязана попасть в
    # сверку как 0 и покраснеть на `PLANT_LANDED`, а не молча сломать `$(( ))` на слове MISSING.
    case "$v" in ''|*[0-9]*) ;; *) v=0 ;; esac
    landed="$v"; land=$((land + v))
    direction=$(flag "$o" RCP_DIRECTION); pline=$(flag "$o" RCP_LINE)
    o="$P/plant_${kind}_scan.txt"
    python "$CRCC" check --dir "$R" --limit "$LIMIT" > "$o" 2>&1; scanrc=$?
    ung=$(flag "$o" RCC_UNGUARDED); gua=$(flag "$o" RCC_GUARDED); cap=$(flag "$o" RCC_CAPTURES)
    eq=$(flag "$o" RCC_RECOUNT_EQ); spe=$(flag "$o" RCC_BLOCKS_SET_PLUS_E)
    named=$(count_of "$o" 'RCC_UNGUARDED_AT='); non=$(count_of "$o" 'RCC_UNGUARDED_FILE=none')
    case "$kind" in
      flip)
        femit "$F" "PLANT_FLIP_RC=$rc"
        femit "$F" "PLANT_FLIP_LANDED=$landed"
        femit "$F" "PLANT_FLIP_DIRECTION=$direction"
        femit "$F" "PLANT_FLIP_LINE=$pline"
        femit "$F" "PLANT_FLIP_UNGUARDED=$ung"
        femit "$F" "PLANT_FLIP_GUARDED=$gua"
        femit "$F" "PLANT_FLIP_CAPTURES=$cap"
        femit "$F" "PLANT_FLIP_RECOUNT_EQ=$eq"
        femit "$F" "PLANT_FLIP_BLOCKS_SET_PLUS_E=$spe"
        femit "$F" "PLANT_FLIP_EXIT=$scanrc"
        femit "$F" "PLANT_FLIP_NAMED=$named"
        femit "$F" "PLANT_FLIP_NONE=$non"
        ;;
      bare)
        femit "$F" "PLANT_BARE_RC=$rc"
        femit "$F" "PLANT_BARE_LANDED=$landed"
        femit "$F" "PLANT_BARE_DIRECTION=$direction"
        femit "$F" "PLANT_BARE_LINE=$pline"
        femit "$F" "PLANT_BARE_UNGUARDED=$ung"
        femit "$F" "PLANT_BARE_GUARDED=$gua"
        femit "$F" "PLANT_BARE_CAPTURES=$cap"
        femit "$F" "PLANT_BARE_RECOUNT_EQ=$eq"
        femit "$F" "PLANT_BARE_BLOCKS_SET_PLUS_E=$spe"
        femit "$F" "PLANT_BARE_EXIT=$scanrc"
        femit "$F" "PLANT_BARE_NAMED=$named"
        femit "$F" "PLANT_BARE_NONE=$non"
        ;;
      sete)
        femit "$F" "PLANT_SETE_RC=$rc"
        femit "$F" "PLANT_SETE_LANDED=$landed"
        femit "$F" "PLANT_SETE_DIRECTION=$direction"
        femit "$F" "PLANT_SETE_LINE=$pline"
        femit "$F" "PLANT_SETE_UNGUARDED=$ung"
        femit "$F" "PLANT_SETE_GUARDED=$gua"
        femit "$F" "PLANT_SETE_CAPTURES=$cap"
        femit "$F" "PLANT_SETE_RECOUNT_EQ=$eq"
        femit "$F" "PLANT_SETE_BLOCKS_SET_PLUS_E=$spe"
        femit "$F" "PLANT_SETE_EXIT=$scanrc"
        femit "$F" "PLANT_SETE_NAMED=$named"
        femit "$F" "PLANT_SETE_NONE=$non"
        ;;
    esac
  done
  # flip и bare обязаны покраснеть и назвать адрес; sete НЕ обязан: exemption — это учёт,
  # а не дефект, и требовать от него красноты значило бы заставить прибор врать о смысле числа.
  [ "$(flag "$F" PLANT_FLIP_EXIT)" != 0 ] && [ "$(flag "$F" PLANT_FLIP_EXIT)" != MISSING ] \
    && red=$((red + 1))
  [ "$(flag "$F" PLANT_BARE_EXIT)" != 0 ] && [ "$(flag "$F" PLANT_BARE_EXIT)" != MISSING ] \
    && red=$((red + 1))
  R4="$P/plant_blind"; mkdir -p "$R4/$WF"
  o="$P/plant_blind.txt"
  python "$CRCC" check --dir "$R4" --limit "$LIMIT" > "$o" 2>&1; rc=$?
  n=$(ls -A "$R4/$WF" 2>/dev/null | wc -l | tr -d ' ')
  femit "$F" "PLANT_BLIND_LANDED=$( [ -d "$R4/$WF" ] && [ "$n" = 0 ] && echo 1 || echo 0 )"
  femit "$F" "PLANT_BLIND_BLIND=$(flag "$o" RCC_BLIND)"
  femit "$F" "PLANT_BLIND_UNGUARDED=$(flag "$o" RCC_UNGUARDED)"
  femit "$F" "PLANT_BLIND_RECOUNT_EQ=$(flag "$o" RCC_RECOUNT_EQ)"
  femit "$F" "PLANT_BLIND_EXIT=$rc"
  land=$((land + $(flag "$F" PLANT_BLIND_LANDED)))
  [ "$rc" != 0 ] && red=$((red + 1))
  femit "$F" "PLANT_LANDED=$land"
  femit "$F" "PLANT_RED_COUNT=$red"
  femit "$F" "PLANT_ALL_RED=$(all1 "$( [ "$red" = 3 ] && echo 1 )" "$( [ "$land" = 4 ] && echo 1 )" )"
  [ "$land" = 4 ] || note 1
  [ "$red" = 3 ] || note 1

  # --- 8. Прибор самопроверкой на живом дереве (CI гоняет ровно этот режим)
  o="$P/selftest.txt"
  python "$CRCC" selftest > "$o" 2>&1; rc=$?
  v=$(sed -n 's/^RCC_SELFTEST total=\([0-9]*\) passed=\([0-9]*\)$/\1/p' "$o" | head -1)
  femit "$F" "RCC_SELFTEST_TOTAL=${v:-MISSING}"
  v=$(sed -n 's/^RCC_SELFTEST total=\([0-9]*\) passed=\([0-9]*\)$/\2/p' "$o" | head -1)
  femit "$F" "RCC_SELFTEST_PASSED=${v:-MISSING}"
  femit "$F" "RCC_SELFTEST_FIRED=$(flag "$o" RCC_SELFTEST_FIRED)"
  femit "$F" "RCC_SELFTEST_FAILED_NAMES=$(count_of "$o" '=FAIL')"
  femit "$F" "RCC_SELFTEST_RC=$rc"
  femit "$F" "RCC_SELFTEST_OK=$( [ "$rc" -eq 0 ] && echo 1 || echo 0 )"
  [ "$rc" -eq 0 ] || note 1
}

measure "$F1" "R1"
measure "$F2" "R2"

say "### ШАГ 9 носитель после измерений ### $(date +%FT%T%:z)"
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf '%s' "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
ram=$(printf '%s' "$res" | sed -n 's/.*RAM_FREE_MB=\([0-9]*\).*/\1/p')
pf=$(printf '%s' "$res" | sed -n 's/.*PAGEFILE_PEAK_MB=\([0-9]*\).*/\1/p')
emit0 "DISK_AFTER_MB=${disk:-MISSING}"
emit0 "RAM_AFTER_MB=${ram:-MISSING}"
emit0 "PAGEFILE_AFTER_MB=${pf:-MISSING}"
emit0 "DISK_AFTER_MEASURE_GE_15000=$( [ "${disk:-0}" -ge 15000 ] && echo 1 || echo 0 )"
[ "${disk:-0}" -ge 15000 ] || note 1

say "### ШАГ 10 wiring и границы ### $(date +%FT%T%:z)"
v=$(count_of "$WF/verify.yml" 'lab/check-ci-rc-capture.py')
emit0 "RCC_CI_STEP_ADDED=$( [ "$v" -ge 2 ] && echo 1 || echo 0 )"
v=$(count_of lab/workspace-verify.sh 'lab/check-ci-rc-capture.py')
emit0 "RCC_VERIFY_BLOCK_ADDED=$( [ "$v" -ge 1 ] && echo 1 || echo 0 )"
v=$(git diff --name-only "$PIN" HEAD 2>/dev/null | grep -c 'lab/check-ci-report-greps.py')
emit0 "RCC_E0127_INSTRUMENT_UNTOUCHED=$( [ "$v" -eq 0 ] && echo 1 || echo 0 )"
v=$(git diff --name-only "$PIN" HEAD 2>/dev/null | grep -cE '\.rs$')
emit0 "CODE_CHANGED_RS=$v"
v=$(git diff --name-only "$PIN" HEAD 2>/dev/null | grep -cE 'docs/VecDHT-SPEC-v[89]\.md')
emit0 "SPEC_DOCS_UNTOUCHED=$( [ "$v" -eq 0 ] && echo 1 || echo 0 )"
v=$(count_of lab/check-spec-mirror.sh '| head -40 || true')
emit0 "MIRROR_SCRIPT_PIPE_GUARDED=$( [ "$v" -ge 1 ] && echo 1 || echo 0 )"
# Независимый от прибора подсчёт в shell: форма «точка с запятой и $?» обязана исчезнуть из
# всех трёх workflow-файлов. Это второй код, который смотрит тем же grep'ом, а не верой
# regex'ам прибора (прецедент `CRG_RECOUNT_EQ` из E-0127).
v=$(cat "$WF"/*.yml | grep -acE -- '; *(r|rc)=\$\?[[:space:]]*$')
emit0 "SEMICOLON_CAPTURE_LINES=$v"
for k in RCC_CI_STEP_ADDED RCC_VERIFY_BLOCK_ADDED RCC_E0127_INSTRUMENT_UNTOUCHED \
         SPEC_DOCS_UNTOUCHED MIRROR_SCRIPT_PIPE_GUARDED; do
  [ "$(flag "$G" "$k")" = 1 ] || note 1
done
[ "$(flag "$G" CODE_CHANGED_RS)" = 0 ] || note 1
[ "$(flag "$G" SEMICOLON_CAPTURE_LINES)" = 0 ] || note 1

say "### ШАГ 11 устойчивость ### $(date +%FT%T%:z)"
if diff -q "$F1" "$F2" >/dev/null; then s=1; else s=0; diff "$F1" "$F2" | head -20 | tee -a "$LOG"; fi
emit0 "STABLE=$s"
[ "$s" = 1 ] || note 1

say "### ШАГ 12 посадка неверного ожидания и сверка ### $(date +%FT%T%:z)"
# Число строк таблицы печатается ДО сверки: иначе порог «таблица не пуста» ссылается на самого
# себя и становится невыполнимым по построению (первый прогон дал `РАСХОЖДЕНИЕ: нет такого ключа`).
v=$(awk -F'\t' 'NF>=2 && $1 !~ /^#/ {n++} END{print n+0}' "$EXPECT")
emit0 "EXPECT_ROWS=$v"
[ "$v" -ge 100 ] || note 1
awk -F'\t' 'BEGIN{OFS="\t"} $1=="RCC_UNGUARDED"{$2="7"} {print}' "$EXPECT" > "$OUT/plant.tsv"
if ! grep -q $'^RCC_UNGUARDED\t7\t' "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка RCC_UNGUARDED в таблице не найдена"
  plant=0
else
  cat "$G" >> "$F1"
  python lab/expect.py "$OUT/plant.tsv" "$F1" > "$OUT/plant.out" 2>&1
  rc=$?
  plant=$( [ "$rc" -ne 0 ] && echo 1 || echo 0 )
fi
emit0 "PLANT_EXPECT_RED=$plant"
[ "$plant" = 1 ] || note 1
cat "$G" >> "$F2"
python lab/expect.py "$EXPECT" "$F1" "$F2" 2>&1 | tail -n 25 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
# Код сверки печатается в носитель, но в замороженную таблицу не входит: сравнение исполняется
# до его печати. Красноту держит `note` — зелёный итог без нуля сверки невозможен.
emit0 "EXPECT_EXIT=$rc"
note "$rc"

say "########## E-0128 итог: WORST_RC=$WORST ##########"
exit "$WORST"
