#!/usr/bin/env bash
# Носитель круга H-0146: цена фильтра §12.7 — recall@10 под `OnlyPaid` на разреженном корпусе.
#
# Порядок: (0) PRE_FIX пином — файла прибора в пине нет, а `search_filtered`/`insert_with_attr`
# есть (фильтр в дереве уже стоял, не хватало замера); (1) гейт цикла и диск; (2) сам прибор
# `crates/vecdht-index/tests/s19_recall_filter.rs` — оракул считает предикат и расстояние сам,
# зондирование берёт у продукта; (3) соседние стражи; (4) вердикт по названным условиям.
#
# Употребление: bash lab/e0146-run.sh [каталог-вывода]
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

PIN=$(git log --format=%H --grep="H-0146 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"

# --- ШАГ 0: PRE_FIX пином ---------------------------------------------------------------------
# Прибор до этого круга не существовал: именно его отсутствие и есть дыра. Механизм фильтра в
# пине уже есть, поэтому отдельно печатаем, что он есть, — иначе «до» и «после» не отличить.
TEST=crates/vecdht-index/tests/s19_recall_filter.rs
if [ -n "$PIN" ] && git cat-file -e "$PIN:$TEST" 2>/dev/null; then
  emit PRE_FIX_TEST 0
else
  emit PRE_FIX_TEST 1
fi
count_in_pin() { local n; n=$(git show "$PIN:$1" 2>/dev/null | grep -c -- "$2") || true; printf '%s' "${n:-none}"; }
emit PRE_FIX_FILTER "$(count_in_pin crates/vecdht-index/src/ivf.rs 'fn search_filtered')"
emit PRE_FIX_ATTR "$(count_in_pin crates/vecdht-index/src/ivf.rs 'insert_with_attr')"

# --- ШАГ 1: гейт и диск -----------------------------------------------------------------------
r=0; python lab/cycle-gate.py gate H-0146 > "${SCR}gate.log" 2>&1 || r=$?
emit GATE_H0146_OK "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

# --- ШАГ 2: прибор -----------------------------------------------------------------------------
r=0; cargo test -q -p vecdht-index --test s19_recall_filter -- --nocapture --test-threads=1 \
  > "${SCR}recall.log" 2>&1 || r=$?
emit ORACLE_EXIT "$r"
emit ORACLE_PASSED "$(grep -o 'test result: ok\. [0-9]* passed' "${SCR}recall.log" | tail -1 | grep -o '[0-9]*' | head -1 || echo none)"
emit ORACLE_FAILED "$(grep -o '[0-9]* failed' "${SCR}recall.log" | tail -1 | grep -o '[0-9]*' | head -1 || echo none)"

# Входы прибора: без них числа ниже не к чему отнести.
for k in CORPUS_CLUSTERS CORPUS_ENTRIES QUERIES TOP_K; do
  emit "$k" "$(grab "${SCR}recall.log" "МЕРЕНО $k")"
done
for label in 100 10 2 1; do
  emit "PAID_TOTAL_$label" "$(grab "${SCR}recall.log" "МЕРЕНО PAID_TOTAL_$label")"
done
for label in 100 10 2 1; do
  for np in 16 4 1; do
    emit "RECALL_PAID_${label}_NP${np}_PM" "$(grab "${SCR}recall.log" "МЕРЕНО RECALL_PAID_${label}_NP${np}_PM")"
    emit "COVERAGE_PAID_${label}_NP${np}_PM" "$(grab "${SCR}recall.log" "МЕРЕНО COVERAGE_PAID_${label}_NP${np}_PM")"
  done
done
emit CTRL_POST_TRUNC_2_NP4_PM "$(grab "${SCR}recall.log" "МЕРЕНО CTRL_POST_TRUNC_2_NP4_PM")"
emit IDENTITY_MISMATCHES "$(grab "${SCR}recall.log" "МЕРЕНО IDENTITY_MISMATCHES")"
emit FILTER_ADDS_MISSES "$(grab "${SCR}recall.log" "МЕРЕНО FILTER_ADDS_MISSES")"
emit EMPTY_WITH_ORACLE_2_NP4 "$(grab "${SCR}recall.log" "МЕРЕНО EMPTY_WITH_ORACLE_2_NP4")"
emit PROBES_EMPTY_2_NP4 "$(grab "${SCR}recall.log" "МЕРЕНО PROBES_EMPTY_2_NP4")"
# Производные булевы: равенство «полнота == покрытие» — утверждение гипотезы, а не оформление.
EQ=1
for label in 100 10 2 1; do
  for np in 16 4 1; do
    rv=$(grab "${SCR}recall.log" "МЕРЕНО RECALL_PAID_${label}_NP${np}_PM")
    cv=$(grab "${SCR}recall.log" "МЕРЕНО COVERAGE_PAID_${label}_NP${np}_PM")
    [ -n "$rv" ] && [ "$rv" = "$cv" ] || EQ=0
  done
done
emit RECALL_EQ_COVERAGE "$EQ"
CTRL=$(grab "${SCR}recall.log" "МЕРЕНО CTRL_POST_TRUNC_2_NP4_PM")
emit CTRL_LT_300 "$([ "$CTRL" != none ] && [ "$CTRL" -lt 300 ] 2>/dev/null && echo 1 || echo 0)"

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
r=0; bash lab/check-text-clean.sh lab/e0146-run.sh lab/expectations/e0146.tsv \
  lab/hypotheses/H-0146-recall-filter.md lab/experiments/E-0146-recall-filter.md \
  crates/vecdht-index/tests/s19_recall_filter.rs > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"

# --- ШАГ 4: вердикт по названным условиям ------------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
want PIN_FOUND 1
want PRE_FIX_TEST 1
want PRE_FIX_FILTER 1
want PRE_FIX_ATTR 1
want GATE_H0146_OK 1
want DISK_GE_15000 1
want ORACLE_EXIT 0
want ORACLE_PASSED 1
want ORACLE_FAILED 0
want CORPUS_ENTRIES 2048
want CORPUS_CLUSTERS 16
want QUERIES 48
want TOP_K 10
want IDENTITY_MISMATCHES 0
want FILTER_ADDS_MISSES 0
want EMPTY_WITH_ORACLE_2_NP4 0
want PROBES_EMPTY_2_NP4 0
want RECALL_EQ_COVERAGE 1
want CTRL_LT_300 1
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
want RUST_TOUCHED 1
emit WORST_RC "$BAD"

# Повторяемость: снимок ключуется HEAD'ом и грязью дерева; диск и сам `STABLE` не сравниваются.
TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0146-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
