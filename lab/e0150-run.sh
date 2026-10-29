#!/usr/bin/env bash
# Носитель круга H-0150: страж Lean обязан назвать класс окружения до того, как судить модели.
#
# Порядок: (0) PRE_FIX пином — старый страж на неполном окружении печатает BROKEN=6 и не знает
# `LEAN_ENV`; (1) новый страж на том же окружении отказывается печатать BROKEN и выходит кодом 3;
# (2) контроль семантики — здоровая среда плюс заведомо сломанная модель дают BROKEN=1 и COMPILE;
# (3) настоящее дерево, самопроверка, соседние стражи; (4) вердикт по замороженной таблице.
#
# Неполное окружение изображается `ELAN_TOOLCHAIN=__nope__`: elan отвергает имя локально, без
# скачивания (имя с версией заставило бы elan идти в сеть — проверено и отвергнуто).
#
# Употребление: bash lab/e0150-run.sh [каталог-вывода]
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

SCR=$(mktemp -d)/
OUT=${1:-$SCR}
mkdir -p "$OUT"
FACTS="${OUT}facts.txt"
: > "$FACTS"

emit() { printf '%s=%s\n' "$1" "$2" | tee -a "$FACTS"; }
grab() { v=$(grep -oE "(^|[[:space:]])$2=[0-9A-Za-z/.,:%;_-]*" "$1" 2>/dev/null | tail -1 | sed 's/.*=//'); [ -n "$v" ] && printf '%s' "$v" || printf 'none'; }
# Путь, который поймёт Windows-Python: MSYS-аргументы конвертируются не всегда (прецедент —
# `zipfile` не нашёл `/tmp/lean436.zip`, пока путь не перевели через cygpath).
win() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

PIN=$(git log --format=%H --grep="H-0150 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"

# --- ШАГ 0: PRE_FIX пином на неполном окружении ------------------------------------------------
PINCHECK="${SCR}pin-lean-check.py"
if [ -n "$PIN" ] && git cat-file -e "$PIN:lab/lean-check.py" 2>/dev/null; then
  git show "$PIN:lab/lean-check.py" > "$PINCHECK"
  emit PRE_FIX_PIN_FILE 1
else
  : > "$PINCHECK"
  emit PRE_FIX_PIN_FILE 0
fi
r=0; ELAN_TOOLCHAIN=__nope__ python "$PINCHECK" check --quiet > "${SCR}pin-broken.log" 2>&1 || r=$?
emit PRE_FIX_PIN_RC "$r"
emit PRE_FIX_PIN_BROKEN "$(grab "${SCR}pin-broken.log" BROKEN)"
emit PRE_FIX_PIN_ENV_LINES "$(grep -cE '^LEAN_ENV=' "${SCR}pin-broken.log" || true)"

# --- ШАГ 1: новый страж на том же неполном окружении -------------------------------------------
r=0; ELAN_TOOLCHAIN=__nope__ python lab/lean-check.py check --quiet > "${SCR}new-partial.log" 2>&1 || r=$?
emit POST_FIX_PARTIAL_RC "$r"
emit POST_FIX_PARTIAL_ENV "$(grab "${SCR}new-partial.log" LEAN_ENV)"
emit POST_FIX_PARTIAL_BROKEN_LINES "$(grep -cE '^BROKEN=' "${SCR}new-partial.log" || true)"
emit POST_FIX_PARTIAL_ALL_OK "$(grab "${SCR}new-partial.log" LEAN_ALL_OK)"
emit POST_FIX_PARTIAL_REFUSED "$(grep -qE '^LEAN_ENV_REFUSED=1' "${SCR}new-partial.log" && echo 1 || echo 0)"

# --- ШАГ 2: контроль семантики — здоровая среда, сломанная модель -------------------------------
TMPROOT="${SCR}broken-root"
mkdir -p "$TMPROOT/lab/lean/VecDHT"
printf 'import Std\n\ntheorem bad : 1 = 2 := rfl\n' > "$TMPROOT/lab/lean/VecDHT/Bad.lean"
r=0; python lab/lean-check.py check --root "$(win "$TMPROOT")" --quiet > "${SCR}model-broken.log" 2>&1 || r=$?
emit POST_FIX_MODEL_RC "$r"
emit POST_FIX_MODEL_ENV "$(grab "${SCR}model-broken.log" LEAN_ENV)"
emit POST_FIX_MODEL_BROKEN "$(grab "${SCR}model-broken.log" BROKEN)"
emit POST_FIX_MODEL_COMPILE "$(grep -q 'COMPILE:' "${SCR}model-broken.log" && echo 1 || echo 0)"
emit POST_FIX_MODEL_ALL_OK "$(grab "${SCR}model-broken.log" LEAN_ALL_OK)"

# --- ШАГ 3: настоящее дерево, самопроверка, соседние стражи ------------------------------------
r=0; python lab/lean-check.py check --quiet > "${SCR}check.log" 2>&1 || r=$?
emit LEAN_CHECK_EXIT "$r"
for k in LEAN_ENV LEAN_ENV_PROBE_EXIT LEAN_TOTAL BROKEN DIGEST_BAD NATIVE_AXIOMS STD_AXIOMS AXIOM_FREE LEAN_ALL_OK; do
  emit "$k" "$(grab "${SCR}check.log" "$k")"
done
r=0; python lab/lean-check.py selftest > "${SCR}selftest.log" 2>&1 || r=$?
emit SELFTEST_EXIT "$r"
emit SELFTEST_TOTAL "$(grep -o 'LEANGUARD_SELFTEST total=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
emit SELFTEST_PASSED "$(grep -o 'LEANGUARD_SELFTEST total=[0-9]* passed=[0-9]*' "${SCR}selftest.log" | tail -1 | grep -o 'passed=[0-9]*' | cut -d= -f2 | grep . || echo none)"
emit SELFTEST_FAILED "$(grep -o 'failed=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"

run_guard() { local key=$1; shift; local rr=0; "$@" > "${SCR}${key}.log" 2>&1 || rr=$?; emit "$key" "$rr"; }
run_guard REVIEW_EXIT python lab/repo-review.py check
run_guard LINT_LATEST_EXIT python lab/threshold-lint.py --latest
run_guard TEXTGUARD_ALL_EXIT bash lab/check-text-clean.sh --all
run_guard CLAIMS_EXIT python lab/check-claims.py
run_guard CONTOURS_EXIT python lab/check-contours.py
run_guard MIRROR_EXIT bash lab/check-spec-mirror.sh
run_guard OQ_EXIT python lab/check-oq-numbering.py
run_guard DATE_EXIT python lab/check-date-domain.py check
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' "${SCR}LINT_LATEST_EXIT.log" 2>/dev/null | tail -1 | cut -d= -f2 | grep . || echo none)"
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' "${SCR}TEXTGUARD_ALL_EXIT.log" 2>/dev/null | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; bash lab/check-text-clean.sh lab/lean-check.py lab/e0150-run.sh lab/expectations/e0150.tsv \
  lab/hypotheses/H-0150-lean-env-class.md lab/experiments/E-0150-lean-env-class.md \
  > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"

# --- ШАГ 4: диск и вердикт по названным условиям -----------------------------------------------
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
# Ожидания читаются из замороженной таблицы: у имени факта один владелец.
# `STABLE` проверяет оракул на втором прогоне, `WORST_RC` — итог этого блока.
while IFS=$'\t' read -r k v _note; do
  case "$k" in ''|'#'*|STABLE|WORST_RC) continue;; esac
  want "$k" "$v"
done < lab/expectations/e0150.tsv
emit WORST_RC "$BAD"

# Повторяемость: снимок ключуется HEAD'ом и грязью дерева; диск и сам `STABLE` не сравниваются.
TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0150-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
