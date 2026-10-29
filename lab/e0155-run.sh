#!/usr/bin/env bash
# Носитель круга H-0155: таблица ожиданий, переписанная после коммита пре-регистрации, не краснит
# ни один прибор — `expect.py` сверяет факты с таблицей, а таблицу с историей не сверяет никто.
# Порядок:
#  (0) PRE_FIX пина — `git worktree` на коммите пре-регистрации, новый страж против него: базовой
#      линии в пине нет, поэтому все исторические нарушения названы находками (19, код 1);
#  (1) POST_FIX — рабочее дерево: 59 таблиц, 19 названы базой, 0 находок; `--strict-all` краснеет
#      на всех 19 (строгий режим действительно видит, а не наследует ноль);
#  (2) посадки — подменённый байт e0155, удалённая таблица, мёртвая строка базы, отказ вне git;
#  (3) самопроверка прибора (6 фикстур), соседние стражи, границы продукта, диск, повторяемость.
#
# Употребление: bash lab/e0155-run.sh [каталог-вывода]
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
cleanup() { git worktree remove --force "${SCR}pin-tree" >/dev/null 2>&1 || true; git worktree remove --force "${SCR}plant-tree" >/dev/null 2>&1 || true; }
trap cleanup EXIT

PIN=$(git log --format=%H --grep="H-0155: пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"
[ -n "$PIN" ] || PIN=$(git rev-parse HEAD)
emit PIN_SHORT "$(git rev-parse --short "$PIN")"

# --- ШАГ 0: PRE_FIX пина — стража в пине нет, базы нет, нарушения молчат ------------------------
WT="${SCR}pin-tree"
if git worktree add -q --detach "$WT" "$PIN" >"${SCR}wt.log" 2>&1; then
  emit PRE_FIX_WORKTREE 1
else
  emit PRE_FIX_WORKTREE 0
fi
r=0; python lab/check-expect-freeze.py --root "$(win "$WT")" > "${SCR}pre.log" 2>&1 || r=$?
emit PRE_FIX_RC "$r"
emit PRE_FIX_TABLES "$(grab "${SCR}pre.log" EF_TABLES)"
emit PRE_FIX_SAME "$(grab "${SCR}pre.log" EF_SAME)"
emit PRE_FIX_CHANGED "$(grab "${SCR}pre.log" EF_CHANGED)"
emit PRE_FIX_ABSENT "$(grab "${SCR}pre.log" EF_ABSENT)"
emit PRE_FIX_BASELINE "$(grab "${SCR}pre.log" EF_BASELINE)"
emit PRE_FIX_FINDINGS "$(grab "${SCR}pre.log" EF_FINDINGS)"
git worktree remove --force "$WT" >/dev/null 2>&1 || true

# --- ШАГ 1: POST_FIX — рабочее дерево ----------------------------------------------------------
r=0; python lab/check-expect-freeze.py > "${SCR}post.log" 2>&1 || r=$?
emit POST_RC "$r"
emit POST_TABLES "$(grab "${SCR}post.log" EF_TABLES)"
emit POST_SAME "$(grab "${SCR}post.log" EF_SAME)"
emit POST_CHANGED "$(grab "${SCR}post.log" EF_CHANGED)"
emit POST_ABSENT "$(grab "${SCR}post.log" EF_ABSENT)"
emit POST_BASELINE_ROWS "$(grab "${SCR}post.log" EF_BASELINE_ROWS)"
emit POST_BASELINE_DEFECTS "$(grab "${SCR}post.log" EF_BASELINE_DEFECTS)"
emit POST_FINDINGS "$(grab "${SCR}post.log" EF_FINDINGS)"
LS_COUNT=$(ls lab/expectations/e*.tsv | wc -l | tr -d ' ')
emit EF_TABLE_MATCH_LS "$([ "$(grab "${SCR}post.log" EF_TABLES)" = "$LS_COUNT" ] && echo 1 || echo 0)"

r=0; python lab/check-expect-freeze.py --strict-all > "${SCR}strict.log" 2>&1 || r=$?
emit STRICT_RC "$r"
emit STRICT_FINDINGS "$(grab "${SCR}strict.log" EF_FINDINGS)"

# --- ШАГ 2: посадки ----------------------------------------------------------------------------
PT="${SCR}plant-tree"
if git worktree add -q --detach "$PT" HEAD >"${SCR}wt2.log" 2>&1; then
  emit PLANT_WORKTREE 1
else
  emit PLANT_WORKTREE 0
fi

# (а) подменённый байт таблицы: ожидание изменено после заморозки
printf '\n# подменённое ожидание\n' >> "$PT/lab/expectations/e0155.tsv"
r=0; python lab/check-expect-freeze.py --root "$(win "$PT")" > "${SCR}plant-changed.log" 2>&1 || r=$?
emit PLANT_CHANGED_RC "$r"
emit PLANT_CHANGED_NAMED "$(grep -q 'e0155.tsv:CHANGED' "${SCR}plant-changed.log" && echo 1 || echo 0)"
git -C "$PT" checkout -- lab/expectations/e0155.tsv

# (б) удалённая таблица: не исчезает из счёта, а краснит
rm -f "$PT/lab/expectations/e0155.tsv"
r=0; python lab/check-expect-freeze.py --root "$(win "$PT")" > "${SCR}plant-deleted.log" 2>&1 || r=$?
emit PLANT_DELETED_RC "$r"
emit PLANT_DELETED_NAMED "$(grep -q 'e0155.tsv:MISSING_FILE' "${SCR}plant-deleted.log" && echo 1 || echo 0)"
git -C "$PT" checkout -- lab/expectations/e0155.tsv

# (в) мёртвая строка базы: чистая таблица названа нарушителем
printf 'lab/expectations/e0090.tsv\tCHANGED\t0000000\tпосаженная строка\n' >> "$PT/lab/expect-freeze-baseline.tsv"
r=0; python lab/check-expect-freeze.py --root "$(win "$PT")" > "${SCR}plant-stale.log" 2>&1 || r=$?
emit PLANT_STALE_RC "$r"
emit PLANT_STALE_NAMED "$(grep -q 'e0090.tsv:STALE' "${SCR}plant-stale.log" && echo 1 || echo 0)"
git -C "$PT" checkout -- lab/expect-freeze-baseline.tsv
git worktree remove --force "$PT" >/dev/null 2>&1 || true

# (г) вне git: прибор отказывается мерить, а не зеленеет
NG="${SCR}nogit"
mkdir -p "$NG/lab/expectations"
cp lab/expectations/e0155.tsv "$NG/lab/expectations/e0155.tsv"
r=0; python lab/check-expect-freeze.py --root "$(win "$NG")" > "${SCR}nogit.log" 2>&1 || r=$?
emit NOGIT_RC "$r"
emit NOGIT_KIND "$(grab "${SCR}nogit.log" EF_ROOT_KIND)"

# --- ШАГ 3: самопроверка прибора и соседние стражи ----------------------------------------------
r=0; python lab/check-expect-freeze.py --selftest > "${SCR}st.log" 2>&1 || r=$?
emit SELFTEST_RC "$r"
emit SELFTEST_CASES "$(grab "${SCR}st.log" EF_SELFTEST_CASES)"
emit SELFTEST_PASSED "$(grab "${SCR}st.log" EF_SELFTEST_PASSED)"
emit SELFTEST_FAILED "$(grab "${SCR}st.log" EF_SELFTEST_FAILED)"

r=0; python lab/check-guard-selftests.py > "${SCR}gse.log" 2>&1 || r=$?
emit GSE_EXIT "$r"
emit GSE_FINDINGS "$(grab "${SCR}gse.log" GSE_FINDINGS)"
r=0; python lab/check-artifact-refs.py > "${SCR}refs.log" 2>&1 || r=$?
emit REFS_EXIT "$r"
r=0; python lab/repo-review.py check > "${SCR}review.log" 2>&1 || r=$?
emit REVIEW_EXIT "$r"
r=0; python lab/check-claims.py > "${SCR}claims.log" 2>&1 || r=$?
emit CLAIMS_EXIT "$r"
r=0; python lab/check-contours.py > "${SCR}contours.log" 2>&1 || r=$?
emit CONTOURS_EXIT "$r"
r=0; python lab/check-status-claims.py > "${SCR}status.log" 2>&1 || r=$?
emit STATUS_EXIT "$r"
r=0; bash lab/check-text-clean.sh lab/check-expect-freeze.py lab/expect-freeze-baseline.tsv \
  lab/expectations/e0155.tsv lab/hypotheses/H-0155-expect-freeze.md \
  lab/experiments/E-0155-expect-freeze.md lab/e0155-run.sh \
  .github/workflows/verify.yml lab/workspace-verify.sh > "${SCR}text.log" 2>&1 || r=$?
emit TEXT_EXIT "$r"

# --- ШАГ 4: границы продукта и диск -------------------------------------------------------------
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_READABLE "$([ "$D" != none ] && echo 1 || echo 0)"

# --- ШАГ 5: вердикт по замороженной таблице -----------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
while IFS=$'\t' read -r k v _note; do
  case "$k" in ''|'#'*|STABLE|WORST_RC) continue;; esac
  want "$k" "$v"
done < lab/expectations/e0155.tsv
emit WORST_RC "$BAD"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0155-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
