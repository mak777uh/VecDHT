#!/usr/bin/env bash
# Носитель круга H-0148: релиз-карта под прибор, строка P3 против своего носителя.
#
# Порядок: (0) PRE_FIX пином — на пине стража нет, а карта содержит ложную строку P3 («на фикстуре»,
# «4 000 записей»); новый страж эту карту ловит по имени M-14, а подменённое число и стёртого
# владельца — на исправленной карте; (1) гейт цикла и диск; (2) посадки и настоящая карта;
# (3) соседние стражи; (4) вердикт по названным условиям.
#
# Употребление: bash lab/e0148-run.sh [каталог-вывода]
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

PIN=$(git log --format=%H --grep="H-0148 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"

# --- ШАГ 0: PRE_FIX пином ---------------------------------------------------------------------
PMAP="${SCR}pin-release-map.md"
if [ -n "$PIN" ] && git cat-file -e "$PIN:docs/RELEASE-MAP-v1.md" 2>/dev/null; then
  git show "$PIN:docs/RELEASE-MAP-v1.md" > "$PMAP"
  emit PIN_MAP_FOUND 1
else
  : > "$PMAP"
  emit PIN_MAP_FOUND 0
fi
if [ -n "$PIN" ] && git cat-file -e "$PIN:lab/check-release-map.py" 2>/dev/null; then
  GABS=0
else
  GABS=1
fi
emit PRE_FIX_GUARD_ABSENT "$GABS"
FALSE_ROW=$(grep -c 'на фикстуре' "$PMAP" 2>/dev/null || true)
[ -n "$FALSE_ROW" ] || FALSE_ROW=0
emit PRE_FIX_FALSE_ROW "$FALSE_ROW"
if [ "$GABS" -eq 1 ] && [ "$FALSE_ROW" -ge 1 ]; then
  emit PRE_FIX_LIE_PASSES 1
else
  emit PRE_FIX_LIE_PASSES 0
fi

# Новый страж на карте пина: ложь обязана быть названа.
r=0; python lab/check-release-map.py --root "$ROOT" --doc "$PMAP" \
  > "${SCR}postfix-lie.log" 2>&1 || r=$?
emit POST_FIX_LIE_EXIT "$r"
emit POST_FIX_LIE_IDS "$(grab "${SCR}postfix-lie.log" STALE_ROWS)"
emit POST_FIX_LIE_CAUGHT "$([ "$r" -eq 1 ] && grep -q 'M-14' "${SCR}postfix-lie.log" && echo 1 || echo 0)"

# Посаженное число: 417,5 → 477,5 на исправленной карте.
NUMDOC="${SCR}release-map-number.md"
sed 's/417,5/477,5/' docs/RELEASE-MAP-v1.md > "$NUMDOC"
r=0; python lab/check-release-map.py --root "$ROOT" --doc "$NUMDOC" \
  > "${SCR}number-lie.log" 2>&1 || r=$?
emit POST_FIX_NUMBER_EXIT "$r"
emit POST_FIX_NUMBER_IDS "$(grab "${SCR}number-lie.log" NUMBERS_UNDECLARED_IDS)"
emit POST_FIX_NUMBER_CAUGHT "$([ "$r" -eq 1 ] && grep -q 'number-undeclared 477.5' "${SCR}number-lie.log" && echo 1 || echo 0)"

# Посаженный стёртый владелец: `E-0100` исчезает из строки P3.
OWNDOC="${SCR}release-map-owner.md"
sed 's/`, `E-0100`//' docs/RELEASE-MAP-v1.md > "$OWNDOC"
r=0; python lab/check-release-map.py --root "$ROOT" --doc "$OWNDOC" \
  > "${SCR}owner-lie.log" 2>&1 || r=$?
emit POST_FIX_OWNER_EXIT "$r"
emit POST_FIX_OWNER_CAUGHT "$([ "$r" -eq 1 ] && grep -q 'M-14 owner-not-named' "${SCR}owner-lie.log" && echo 1 || echo 0)"

# --- ШАГ 1: гейт и диск -----------------------------------------------------------------------
r=0; python lab/cycle-gate.py gate H-0148 > "${SCR}gate.log" 2>&1 || r=$?
emit GATE_H0148_OK "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

# --- ШАГ 2: прибор ------------------------------------------------------------------------------
r=0; python lab/check-release-map.py selftest > "${SCR}selftest.log" 2>&1 || r=$?
emit SELFTEST_EXIT "$r"
emit SELFTEST_TOTAL "$(grep -o 'total=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
emit SELFTEST_PASSED "$(grep -o 'passed=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
emit SELFTEST_FAILED "$(grep -o 'failed=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; python lab/check-release-map.py > "${SCR}map.log" 2>&1 || r=$?
emit MAP_EXIT "$r"
for k in MAP_ROWS ROWS_REGISTERED ROWS_UNREGISTERED ROWS_MISSING MAP_DUP EIDS EIDS_MISSING EIDS_OPEN ADRS ADRS_MISSING PATHS PATHS_MISSING OWNERS OWNERS_MISSING OWNERS_MISSING_IDS FACTS FACTS_OK STALE STALE_ROWS NUMBERS NUMBERS_OK NUMBERS_UNDECLARED NUMBERS_UNDECLARED_IDS PROV_BAD; do
  emit "$k" "$(grab "${SCR}map.log" "$k")"
done

# --- ШАГ 3: соседние стражи --------------------------------------------------------------------
run_guard() { local key=$1; shift; local rr=0; "$@" > "${SCR}${key}.log" 2>&1 || rr=$?; emit "$key" "$rr"; }
run_guard SECRETS_EXIT bash lab/check-secrets.sh --no-history
run_guard REFS_EXIT python lab/check-artifact-refs.py
run_guard CLAIMMAP_EXIT python lab/check-claim-map.py
run_guard CLAIMS_EXIT python lab/check-claims.py
run_guard CONTOURS_EXIT python lab/check-contours.py
run_guard MIRROR_EXIT bash lab/check-spec-mirror.sh
run_guard GATE_AUDIT_EXIT python lab/cycle-gate.py audit
run_guard REVIEW_EXIT python lab/repo-review.py check
run_guard LINT_LATEST_EXIT python lab/threshold-lint.py --latest
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' "${SCR}LINT_LATEST_EXIT.log" 2>/dev/null | tail -1 | cut -d= -f2 | grep . || echo none)"
run_guard TEXTGUARD_ALL_EXIT bash lab/check-text-clean.sh --all
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' "${SCR}TEXTGUARD_ALL_EXIT.log" 2>/dev/null | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; bash lab/check-text-clean.sh docs/RELEASE-MAP-v1.md docs/PLAN-v1.md lab/check-release-map.py \
  lab/release-map-rows.tsv lab/e0148-run.sh lab/expectations/e0148.tsv \
  lab/hypotheses/H-0148-release-map-guard.md lab/experiments/E-0148-release-map-guard.md \
  lab/workspace-verify.sh > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"

# --- ШАГ 4: вердикт по названным условиям ------------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
want PIN_FOUND 1
want PIN_MAP_FOUND 1
want PRE_FIX_GUARD_ABSENT 1
want PRE_FIX_FALSE_ROW 1
want PRE_FIX_LIE_PASSES 1
want POST_FIX_LIE_CAUGHT 1
want POST_FIX_LIE_IDS M-14
want POST_FIX_NUMBER_CAUGHT 1
want POST_FIX_OWNER_CAUGHT 1
want GATE_H0148_OK 1
want DISK_GE_15000 1
want SELFTEST_EXIT 0
want SELFTEST_TOTAL 15
want SELFTEST_PASSED 15
want SELFTEST_FAILED 0
want MAP_EXIT 0
want MAP_ROWS 16
want ROWS_REGISTERED 16
want ROWS_UNREGISTERED 0
want ROWS_MISSING 0
want MAP_DUP 0
want EIDS 25
want EIDS_MISSING 0
want EIDS_OPEN 0
want ADRS 3
want ADRS_MISSING 0
want PATHS 24
want PATHS_MISSING 0
want OWNERS 16
want OWNERS_MISSING 0
want OWNERS_MISSING_IDS none
want FACTS 23
want FACTS_OK 23
want STALE 0
want STALE_ROWS none
want NUMBERS 7
want NUMBERS_OK 7
want NUMBERS_UNDECLARED 0
want NUMBERS_UNDECLARED_IDS none
want PROV_BAD 0
want SECRETS_EXIT 0
want REFS_EXIT 0
want CLAIMMAP_EXIT 0
want CLAIMS_EXIT 0
want CONTOURS_EXIT 0
want MIRROR_EXIT 0
want GATE_AUDIT_EXIT 0
want REVIEW_EXIT 0
want LINT_LATEST_EXIT 0
want LINT_ORPHANS 0
want TEXTGUARD_ALL_EXIT 0
want TEXTGUARD_ALL_DIRTY 0
want TEXTGUARD_CYCLE_EXIT 0
want WIRE_TOUCHED 0
want RUST_TOUCHED 0
emit WORST_RC "$BAD"

# Повторяемость: снимок ключуется HEAD'ом и грязью дерева; диск и сам `STABLE` не сравниваются.
TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0148-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
