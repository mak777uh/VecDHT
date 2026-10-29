#!/usr/bin/env bash
# Носитель круга H-0149: второе чтение чисел релиз-карты — все строки против владельцев.
#
# Порядок: (0) PRE_FIX пином — старый страж пропускает число в строке `none` и число-префикс
# `2.25` (в карточке `2.2536`), а тип `log:` не знает вовсе; (1) гейт цикла и диск; (2) посадки
# нового стража и сохранённый носитель P4; (3) соседние стражи; (4) вердикт по названным условиям.
#
# Употребление: bash lab/e0149-run.sh [каталог-вывода]
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

PIN=$(git log --format=%H --grep="H-0149 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"

# --- ШАГ 0: PRE_FIX пином ---------------------------------------------------------------------
PINMAP="${SCR}pin-release-map.md"
PINREG="${SCR}pin-rows.tsv"
OLDG="${SCR}pin-guard.py"
if [ -n "$PIN" ] && git cat-file -e "$PIN:docs/RELEASE-MAP-v1.md" 2>/dev/null; then
  git show "$PIN:docs/RELEASE-MAP-v1.md" > "$PINMAP"
else
  : > "$PINMAP"
fi
if [ -n "$PIN" ] && git cat-file -e "$PIN:lab/release-map-rows.tsv" 2>/dev/null; then
  git show "$PIN:lab/release-map-rows.tsv" > "$PINREG"
else
  : > "$PINREG"
fi
if [ -n "$PIN" ] && git cat-file -e "$PIN:lab/check-release-map.py" 2>/dev/null; then
  git show "$PIN:lab/check-release-map.py" > "$OLDG"
  emit PRE_FIX_GUARD_OLD 1
else
  : > "$OLDG"
  emit PRE_FIX_GUARD_OLD 0
fi

# (а) число, дописанное в строку, которая в реестре объявлена `none`.
NONEMAP="${SCR}none-lie.md"
sed 's/выполнено: 64 × 20 = 1 280/выполнено: 64 × 20 = 1 280, всего 1 777 записей/' "$PINMAP" > "$NONEMAP"
r=0; python "$OLDG" --root "$ROOT" --doc "$NONEMAP" --reg "$PINREG" > "${SCR}old-none.log" 2>&1 || r=$?
emit PRE_FIX_NONE_PASSES "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
r=0; python lab/check-release-map.py --root "$ROOT" --doc "$NONEMAP" --reg "$PINREG" > "${SCR}new-none.log" 2>&1 || r=$?
emit POST_FIX_NONE_CAUGHT "$([ "$r" -eq 1 ] && grep -q 'M-07 number-undeclared 1777' "${SCR}new-none.log" && echo 1 || echo 0)"

# (б) число-префикс: реестр пина объявляет 2.25 у строки P5, а `E-0001` печатает 2.2536.
PREFREG="${SCR}prefix-rows.tsv"
python - "$PINREG" "$PREFREG" <<'PY'
import sys
a, b = sys.argv[1], sys.argv[2]
s = open(a, encoding="utf-8").read()
old = "M-16\tP5 sybil-гейт\tE-0001\tcrates/vecdht-node/tests/adversarial.rs\t31 680;31 891\tне выполнен\tnone"
new = old.rsplit("\t", 1)[0] + ("\t2026=>card:E-0001;31680=>card:E-0001;31891=>card:E-0001;"
                                "64000=>card:E-0001;0=>card:E-0001;2.25=>card:E-0001")
assert old in s, "строка M-16 не найдена в реестре пина"
open(b, "w", encoding="utf-8", newline="\n").write(s.replace(old, new, 1))
PY
r=0; python "$OLDG" --root "$ROOT" --doc "$PINMAP" --reg "$PREFREG" > "${SCR}old-prefix.log" 2>&1 || r=$?
emit PRE_FIX_PREFIX_PASSES "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
r=0; python lab/check-release-map.py --root "$ROOT" --doc "$PINMAP" --reg "$PREFREG" > "${SCR}new-prefix.log" 2>&1 || r=$?
emit POST_FIX_PREFIX_CAUGHT "$([ "$r" -eq 1 ] && grep -q 'provenance-bad 2.25' "${SCR}new-prefix.log" && echo 1 || echo 0)"

# (в) тип `log:`: старый страж его не знает, новый принимает сохранённый вывод P4.
r=0; python "$OLDG" --root "$ROOT" > "${SCR}old-log.log" 2>&1 || r=$?
emit PRE_FIX_LOG_UNSUPPORTED "$(grep -q 'unknown-prov:log' "${SCR}old-log.log" && echo 1 || echo 0)"
r=0; python lab/check-release-map.py > "${SCR}new-log.log" 2>&1 || r=$?
emit POST_FIX_LOG_OK "$([ "$r" -eq 0 ] && echo 1 || echo 0)"

# --- ШАГ 1: гейт и диск -----------------------------------------------------------------------
r=0; python lab/cycle-gate.py gate H-0149 > "${SCR}gate.log" 2>&1 || r=$?
emit GATE_H0149_OK "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

# --- ШАГ 2: прибор и носитель P4 ---------------------------------------------------------------
r=0; python lab/check-release-map.py selftest > "${SCR}selftest.log" 2>&1 || r=$?
emit SELFTEST_EXIT "$r"
emit SELFTEST_TOTAL "$(grep -o 'total=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
emit SELFTEST_PASSED "$(grep -o 'passed=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
emit SELFTEST_FAILED "$(grep -o 'failed=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; python lab/check-release-map.py > "${SCR}map.log" 2>&1 || r=$?
emit MAP_EXIT "$r"
for k in MAP_ROWS ROWS_REGISTERED ROWS_UNREGISTERED ROWS_MISSING MAP_DUP EIDS EIDS_MISSING EIDS_OPEN ADRS ADRS_MISSING PATHS PATHS_MISSING OWNERS OWNERS_MISSING OWNERS_MISSING_IDS FACTS FACTS_OK STALE STALE_ROWS NUMBERS NUMBERS_OK NUMBERS_UNDECLARED NUMBERS_UNDECLARED_IDS NUMBERS_PHANTOM NUMBERS_PHANTOM_IDS NONE_ROWS PROV_BAD; do
  emit "$k" "$(grab "${SCR}map.log" "$k")"
done

P4LOG=lab/logs/e0149-p4-handoff.log
emit P4_LOG_FOUND "$([ -f "$P4LOG" ] && echo 1 || echo 0)"
emit P4_LOG_VALUE "$(grep -o 'handoff = [0-9]*' "$P4LOG" 2>/dev/null | tail -1 | grep -o '[0-9]*$' || echo none)"
r=0; cargo test -p vecdht-node --test gates_p4 -- --nocapture --test-threads=1 > "${SCR}p4-now.log" 2>&1 || r=$?
emit P4_TEST_EXIT "$r"
emit P4_NOW "$(grep -o 'handoff = [0-9]*' "${SCR}p4-now.log" | tail -1 | grep -o '[0-9]*$' || echo none)"
emit P4_MATCH "$([ "$(grep -h '^P4_LOG_VALUE=' "$FACTS" | tail -1 | cut -d= -f2)" = "$(grep -h '^P4_NOW=' "$FACTS" | tail -1 | cut -d= -f2)" ] && echo 1 || echo 0)"

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
  lab/release-map-rows.tsv lab/e0149-run.sh lab/expectations/e0149.tsv \
  lab/hypotheses/H-0149-release-map-numbers.md lab/experiments/E-0149-release-map-numbers.md \
  lab/logs/e0149-p4-handoff.log lab/workspace-verify.sh > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"

# --- ШАГ 4: вердикт по названным условиям ------------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
want PIN_FOUND 1
want PRE_FIX_GUARD_OLD 1
want PRE_FIX_NONE_PASSES 1
want PRE_FIX_PREFIX_PASSES 1
want PRE_FIX_LOG_UNSUPPORTED 1
want POST_FIX_NONE_CAUGHT 1
want POST_FIX_PREFIX_CAUGHT 1
want POST_FIX_LOG_OK 1
want GATE_H0149_OK 1
want DISK_GE_15000 1
want SELFTEST_EXIT 0
want SELFTEST_TOTAL 20
want SELFTEST_PASSED 20
want SELFTEST_FAILED 0
want P4_LOG_FOUND 1
want P4_LOG_VALUE 5
want P4_TEST_EXIT 0
want P4_NOW 5
want P4_MATCH 1
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
want NUMBERS 43
want NUMBERS_OK 43
want NONE_ROWS 7
want NUMBERS_UNDECLARED 0
want NUMBERS_UNDECLARED_IDS none
want NUMBERS_PHANTOM 0
want NUMBERS_PHANTOM_IDS none
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
SNAP="${TMPDIR:-/tmp}/e0149-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
