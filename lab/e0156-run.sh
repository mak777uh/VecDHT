#!/usr/bin/env bash
# Носитель круга H-0156: `grab` печатает непустое `none`, когда факта нет, поэтому
# `[ "$a" = "$b" ]` при двух молчаниях истинно. Порядок:
#  (0) PRE_FIX пина — стража в пине нет, берём его с HEAD в worktree пина: реестра там нет,
#      единственная пара названа находкой (1, код 1);
#  (1) POST_FIX — рабочее дерево: 140 носителей, 28 сравнений, 1 пара, реестр называет e0146:80,
#      находок 0, код 0;
#  (2) посадки в синтетических корнях — незащищённая пара, пустая причина, мёртвая строка;
#  (3) отказ вне корня lab/ (код 2), самопроверка прибора (5 фикстур), соседние стражи,
#      границы продукта, диск, повторяемость.
#
# Употребление: bash lab/e0156-run.sh [каталог-вывода]
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

SCR=$(mktemp -d)/
OUT=${1:-$SCR}
mkdir -p "$OUT"
OUT="${OUT%/}/"
FACTS="${OUT}facts.txt"
: > "$FACTS"

emit() { printf '%s=%s\n' "$1" "$2" | tee -a "$FACTS"; }
grab() { v=$(grep -oE "(^|[[:space:]])$2=[0-9A-Za-z/.,:%;_-]*" "$1" 2>/dev/null | tail -1 | sed 's/.*=//'); [ -n "$v" ] && printf '%s' "$v" || printf 'none'; }
win() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
cleanup() { git worktree remove --force "${SCR}pin-tree" >/dev/null 2>&1 || true; }
trap cleanup EXIT
GUARD="lab/check-none-compare.py"

PIN=$(git log --format=%H --grep="H-0156: пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"
[ -n "$PIN" ] || PIN=$(git rev-parse HEAD)

# --- ШАГ 0: PRE_FIX пина — стража в пине нет, реестра нет, пара молчит --------------------------
WT="${SCR}pin-tree"
if git worktree add -q --detach "$WT" "$PIN" >"${SCR}wt.log" 2>&1; then
  emit PRE_FIX_WORKTREE 1
else
  emit PRE_FIX_WORKTREE 0
fi
git show "HEAD:$GUARD" > "$WT/$GUARD"
r=0; python lab/check-none-compare.py --root "$(win "$WT")" > "${SCR}pre.log" 2>&1 || r=$?
emit PRE_FIX_RC "$r"
emit PRE_FIX_CARRIERS "$(grab "${SCR}pre.log" NC_CARRIERS)"
emit PRE_FIX_COMPARISONS "$(grab "${SCR}pre.log" NC_COMPARISONS)"
emit PRE_FIX_SENTINEL_PAIRS "$(grab "${SCR}pre.log" NC_SENTINEL_PAIRS)"
emit PRE_FIX_GUARDED "$(grab "${SCR}pre.log" NC_GUARDED)"
emit PRE_FIX_BASELINE_ROWS "$(grab "${SCR}pre.log" NC_BASELINE_ROWS)"
emit PRE_FIX_BASELINE_DEFECTS "$(grab "${SCR}pre.log" NC_BASELINE_DEFECTS)"
emit PRE_FIX_FINDINGS "$(grab "${SCR}pre.log" NC_FINDINGS)"
emit PRE_FIX_FINDING "$(grab "${SCR}pre.log" NC_FINDING)"
git worktree remove --force "$WT" >/dev/null 2>&1 || true

# --- ШАГ 1: POST_FIX — рабочее дерево ----------------------------------------------------------
r=0; python "$GUARD" > "${SCR}post.log" 2>&1 || r=$?
emit POST_RC "$r"
emit POST_CARRIERS "$(grab "${SCR}post.log" NC_CARRIERS)"
emit POST_COMPARISONS "$(grab "${SCR}post.log" NC_COMPARISONS)"
emit POST_SENTINEL_PAIRS "$(grab "${SCR}post.log" NC_SENTINEL_PAIRS)"
emit POST_GUARDED "$(grab "${SCR}post.log" NC_GUARDED)"
emit POST_BASELINE_ROWS "$(grab "${SCR}post.log" NC_BASELINE_ROWS)"
emit POST_BASELINE_DEFECTS "$(grab "${SCR}post.log" NC_BASELINE_DEFECTS)"
emit POST_FINDINGS "$(grab "${SCR}post.log" NC_FINDINGS)"
LS_COUNT=$(ls lab/e*-run.sh | wc -l | tr -d ' ')
emit NC_CARRIER_MATCH_LS "$([ "$(grab "${SCR}post.log" NC_CARRIERS)" = "$LS_COUNT" ] && echo 1 || echo 0)"

# --- ШАГ 2: посадки в синтетических корнях ------------------------------------------------------
# Фикстуры строятся printf'ом: строка сравнения в этом файле не написана буквально, иначе страж
# прочитал бы собственный носитель как сайт (он читает текст, а не исполняет).
mk_pair() {
  mkdir -p "$1/lab"
  { printf 'grab() { :; }\n'
    printf '%s=$(grab log K1)\n' fa
    printf '%s=$(grab log K2)\n' fb
    printf '[ "$%s" = "$%s" ]\n' fa fb
  } > "$1/lab/e9999-run.sh"
}
mk_clean() {
  mkdir -p "$1/lab"
  printf 'x=1\n' > "$1/lab/e9999-run.sh"
}

R="${SCR}plant-none"; mk_pair "$R"
r=0; python "$GUARD" --root "$(win "$R")" > "${SCR}plant-none.log" 2>&1 || r=$?
n=0; grep -q 'NC_FINDING=lab/e9999-run.sh:4' "${SCR}plant-none.log" && n=1
emit PLANT_NONE_RC "$r"; emit PLANT_NONE_NAMED "$n"
ok1=0; [ "$r" = 1 ] && [ "$n" = 1 ] && ok1=1

R="${SCR}plant-empty"; mk_pair "$R"
printf 'lab/e9999-run.sh:4\t\n' > "$R/lab/none-compare-baseline.tsv"
r=0; python "$GUARD" --root "$(win "$R")" > "${SCR}plant-empty.log" 2>&1 || r=$?
n=0; grep -q 'NC_BASELINE_DEFECT=lab/e9999-run.sh:4:EMPTY_REASON' "${SCR}plant-empty.log" && n=1
emit PLANT_EMPTY_RC "$r"; emit PLANT_EMPTY_NAMED "$n"
ok2=0; [ "$r" = 1 ] && [ "$n" = 1 ] && ok2=1

R="${SCR}plant-stale"; mk_clean "$R"
printf 'lab/e9999-run.sh:99\tпосаженная строка\n' > "$R/lab/none-compare-baseline.tsv"
r=0; python "$GUARD" --root "$(win "$R")" > "${SCR}plant-stale.log" 2>&1 || r=$?
n=0; grep -q 'NC_BASELINE_DEFECT=lab/e9999-run.sh:99:STALE' "${SCR}plant-stale.log" && n=1
emit PLANT_STALE_RC "$r"; emit PLANT_STALE_NAMED "$n"
ok3=0; [ "$r" = 1 ] && [ "$n" = 1 ] && ok3=1

emit PLANT_CASES 3
emit PLANT_PASSED "$((ok1 + ok2 + ok3))"

# --- ШАГ 3: отказ вне корня lab/ ----------------------------------------------------------------
NG="${SCR}noroot"
mkdir -p "$NG"
r=0; python "$GUARD" --root "$(win "$NG")" > "${SCR}noroot.log" 2>&1 || r=$?
emit ROOT_RC "$r"
emit ROOT_KIND "$(grab "${SCR}noroot.log" NC_ROOT_KIND)"

# --- ШАГ 4: самопроверка прибора и соседние стражи ----------------------------------------------
r=0; python "$GUARD" --selftest > "${SCR}st.log" 2>&1 || r=$?
emit SELFTEST_RC "$r"
emit SELFTEST_CASES "$(grab "${SCR}st.log" NC_SELFTEST_CASES)"
emit SELFTEST_PASSED "$(grab "${SCR}st.log" NC_SELFTEST_PASSED)"
emit SELFTEST_FAILED "$(grab "${SCR}st.log" NC_SELFTEST_FAILED)"

r=0; python lab/check-guard-selftests.py > "${SCR}gse.log" 2>&1 || r=$?
emit GSE_EXIT "$r"
emit GSE_FINDINGS "$(grab "${SCR}gse.log" GSE_FINDINGS)"
r=0; python lab/check-contour-parity.py > "${SCR}parity.log" 2>&1 || r=$?
emit PARITY_EXIT "$r"
r=0; python lab/check-artifact-refs.py > "${SCR}refs.log" 2>&1 || r=$?
emit REFS_EXIT "$r"
r=0; python lab/check-claims.py > "${SCR}claims.log" 2>&1 || r=$?
emit CLAIMS_EXIT "$r"
r=0; python lab/check-contours.py > "${SCR}contours.log" 2>&1 || r=$?
emit CONTOURS_EXIT "$r"
r=0; python lab/check-status-claims.py > "${SCR}status.log" 2>&1 || r=$?
emit STATUS_EXIT "$r"
r=0; python lab/check-expect-freeze.py > "${SCR}expect.log" 2>&1 || r=$?
emit EXPECT_FREEZE_EXIT "$r"

# --- ШАГ 5: границы продукта и диск -------------------------------------------------------------
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_READABLE "$([ "$D" != none ] && echo 1 || echo 0)"

# --- ШАГ 6: вердикт по замороженной таблице -----------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
while IFS=$'\t' read -r k v _note; do
  case "$k" in ''|'#'*|STABLE|WORST_RC) continue;; esac
  want "$k" "$v"
done < lab/expectations/e0156.tsv
emit WORST_RC "$BAD"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0156-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
