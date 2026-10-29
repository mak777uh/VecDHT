#!/usr/bin/env bash
# Носитель круга H-0147: второй проход `docs/STATUS-v1.md` прибором.
#
# Порядок: (0) PRE_FIX пином — прежний страж из четырёх строк исполняется на документе с посаженным
# противоречием в области новой строки и пропускает его (это и есть дыра); (1) гейт цикла и диск;
# (2) прибор `lab/check-status-claims.py` — посадки и настоящий документ; (3) соседние стражи;
# (4) вердикт по названным условиям.
#
# Употребление: bash lab/e0147-run.sh [каталог-вывода]
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

PIN=$(git log --format=%H --grep="H-0147 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"

# --- ШАГ 0: PRE_FIX пином ---------------------------------------------------------------------
# Дыра круга — не отсутствие прибора, а его покрытие: в пине страж знает четыре строки и
# посаженную ложь в области релея не видит. Поэтому PRE_FIX — исполнение стража пина на том же
# документе, что получает новый страж.
DOCTORED="${SCR}status-contradicted.md"
sed 's/circuit relay v2 from §16.3 is up since/circuit relay v2 from §16.3 is not up since/' \
  docs/STATUS-v1.md > "$DOCTORED"
emit PRE_FIX_LIE_PLANTED "$(grep -c 'is not up since' "$DOCTORED")"
if [ -n "$PIN" ] && git cat-file -e "$PIN:lab/check-status-claims.py" 2>/dev/null; then
  emit PRE_FIX_GUARD_FOUND 1
  git show "$PIN:lab/check-status-claims.py" > "${SCR}pin-guard.py"
  r=0; python "${SCR}pin-guard.py" --root "$ROOT" --doc "$DOCTORED" \
    > "${SCR}prefix-pin.log" 2>&1 || r=$?
  emit PRE_FIX_PIN_EXIT "$r"
  emit PRE_FIX_PIN_CLAIMS "$(grab "${SCR}prefix-pin.log" STATUS_CLAIMS)"
  emit PRE_FIX_LIE_PASSES "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
  emit PRE_FIX_LIE_IDS "$(grab "${SCR}prefix-pin.log" STATUS_STALE_IDS)"
else
  emit PRE_FIX_GUARD_FOUND 0
  emit PRE_FIX_PIN_EXIT none
  emit PRE_FIX_PIN_CLAIMS none
  emit PRE_FIX_LIE_PASSES 0
  emit PRE_FIX_LIE_IDS none
fi
# Тот же документ новым стражем: он обязан назвать строку по имени.
r=0; python lab/check-status-claims.py --root "$ROOT" --doc "$DOCTORED" \
  > "${SCR}postfix-lie.log" 2>&1 || r=$?
emit POST_FIX_LIE_EXIT "$r"
emit POST_FIX_LIE_CAUGHT "$([ "$r" -eq 1 ] && echo 1 || echo 0)"
emit POST_FIX_LIE_IDS "$(grab "${SCR}postfix-lie.log" STATUS_STALE_IDS)"

# --- ШАГ 1: гейт и диск -----------------------------------------------------------------------
r=0; python lab/cycle-gate.py gate H-0147 > "${SCR}gate.log" 2>&1 || r=$?
emit GATE_H0147_OK "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

# --- ШАГ 2: прибор ------------------------------------------------------------------------------
r=0; python lab/check-status-claims.py selftest > "${SCR}selftest.log" 2>&1 || r=$?
emit SELFTEST_EXIT "$r"
emit SELFTEST_TOTAL "$(grep -o 'total=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
emit SELFTEST_PASSED "$(grep -o 'passed=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
emit SELFTEST_FAILED "$(grep -o 'failed=[0-9]*' "${SCR}selftest.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; python lab/check-status-claims.py --doc docs/STATUS-v1.md > "${SCR}status.log" 2>&1 || r=$?
emit STATUS_EXIT "$r"
for k in STATUS_CLAIMS STATUS_CONSISTENT STATUS_STALE STATUS_STALE_IDS STATUS_FACTS STATUS_FACTS_OK STATUS_FACTS_MISSING STATUS_OK; do
  emit "$k" "$(grab "${SCR}status.log" "$k")"
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
r=0; bash lab/check-text-clean.sh lab/e0147-run.sh lab/expectations/e0147.tsv \
  lab/hypotheses/H-0147-status-second-pass.md lab/experiments/E-0147-status-second-pass.md \
  lab/check-status-claims.py docs/STATUS-v1.md > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"

# --- ШАГ 4: вердикт по названным условиям ------------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
want PIN_FOUND 1
want PRE_FIX_GUARD_FOUND 1
want PRE_FIX_PIN_CLAIMS 4
want PRE_FIX_LIE_PASSES 1
want POST_FIX_LIE_CAUGHT 1
want POST_FIX_LIE_IDS S-05
want GATE_H0147_OK 1
want DISK_GE_15000 1
want SELFTEST_EXIT 0
want SELFTEST_TOTAL 37
want SELFTEST_PASSED 37
want SELFTEST_FAILED 0
want STATUS_EXIT 0
want STATUS_CLAIMS 12
want STATUS_CONSISTENT 12
want STATUS_STALE 0
want STATUS_FACTS 34
want STATUS_FACTS_OK 34
want STATUS_FACTS_MISSING none
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
SNAP="${TMPDIR:-/tmp}/e0147-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
