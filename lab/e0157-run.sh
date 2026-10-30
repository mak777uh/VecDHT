#!/usr/bin/env bash
# Носитель круга H-0157: сильная строка реестра утверждений (`gate-closed`/`measured`) обязана
# ссылаться на карточку с замороженной таблицей ожиданий. Порядок:
#  (0) PRE_FIX пина — стража в пине нет, берём его с HEAD в worktree пина; реестра там нет:
#      семь сильных строк названы находками (код 1);
#  (1) POST_FIX — рабочее дерево: реестр называет семь исторических строк, находок 0, код 0;
#  (2) три посадки в worktree пина — удалённая строка реестра, пустая причина, чужой набор E;
#  (3) отказ вне git-корня (код 2), самопроверка прибора (9 фикстур), соседние стражи,
#      границы продукта, диск, повторяемость.
#
# Употребление: bash lab/e0157-run.sh [каталог-вывода]
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
grab() { v=$(grep -oE "(^|[[:space:]])$2=[0-9A-Za-z/.,:%;_+-]*" "$1" 2>/dev/null | tail -1 | sed 's/.*=//'); [ -n "$v" ] && printf '%s' "$v" || printf 'none'; }
win() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
cleanup() {
  for w in pin-tree plant-missing plant-empty plant-stale; do
    git worktree remove --force "${SCR}$w" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
GUARD="lab/check-claims-frozen.py"
BASE="lab/claims-frozen-baseline.tsv"

PIN=$(git log --format=%H --grep="H-0157: пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"
[ -n "$PIN" ] || PIN=$(git rev-parse HEAD)

# --- ШАГ 0: PRE_FIX пина — стража нет в пине, реестра нет, семь находок -------------------------
WT="${SCR}pin-tree"
if git worktree add -q --detach "$WT" "$PIN" >"${SCR}wt.log" 2>&1; then
  emit PRE_FIX_WORKTREE 1
else
  emit PRE_FIX_WORKTREE 0
fi
git show "HEAD:$GUARD" > "$WT/$GUARD"
r=0; python lab/check-claims-frozen.py --root "$(win "$WT")" > "${SCR}pre.log" 2>&1 || r=$?
emit PRE_FIX_RC "$r"
emit PRE_FIX_CLAIMS "$(grab "${SCR}pre.log" CF_CLAIMS)"
emit PRE_FIX_LINK_PAIRS "$(grab "${SCR}pre.log" CF_LINK_PAIRS)"
emit PRE_FIX_NO_CARD "$(grab "${SCR}pre.log" CF_NO_CARD)"
emit PRE_FIX_NO_TABLE "$(grab "${SCR}pre.log" CF_NO_TABLE)"
emit PRE_FIX_TABLE "$(grab "${SCR}pre.log" CF_TABLE)"
emit PRE_FIX_HISTORY_SAME "$(grab "${SCR}pre.log" CF_HISTORY_SAME)"
emit PRE_FIX_HISTORY_CHANGED "$(grab "${SCR}pre.log" CF_HISTORY_CHANGED)"
emit PRE_FIX_HISTORY_ABSENT "$(grab "${SCR}pre.log" CF_HISTORY_ABSENT)"
emit PRE_FIX_CHANGED_CLAIMS "$(grab "${SCR}pre.log" CF_CHANGED_CLAIMS)"
emit PRE_FIX_STRONG_NO_E "$(grab "${SCR}pre.log" CF_STRONG_NO_E)"
emit PRE_FIX_BASELINE_ROWS "$(grab "${SCR}pre.log" CF_BASELINE_ROWS)"
emit PRE_FIX_BASELINE_DEFECTS "$(grab "${SCR}pre.log" CF_BASELINE_DEFECTS)"
emit PRE_FIX_FINDINGS "$(grab "${SCR}pre.log" CF_FINDINGS)"
emit PRE_FIX_FINDING_1 "$(grab "${SCR}pre.log" CF_FINDING_1)"
emit PRE_FIX_FINDING_2 "$(grab "${SCR}pre.log" CF_FINDING_2)"
emit PRE_FIX_FINDING_3 "$(grab "${SCR}pre.log" CF_FINDING_3)"
emit PRE_FIX_FINDING_4 "$(grab "${SCR}pre.log" CF_FINDING_4)"
emit PRE_FIX_FINDING_5 "$(grab "${SCR}pre.log" CF_FINDING_5)"
emit PRE_FIX_FINDING_6 "$(grab "${SCR}pre.log" CF_FINDING_6)"
emit PRE_FIX_FINDING_7 "$(grab "${SCR}pre.log" CF_FINDING_7)"
git worktree remove --force "$WT" >/dev/null 2>&1 || true

# --- ШАГ 1: POST_FIX — рабочее дерево -----------------------------------------------------------
r=0; python "$GUARD" > "${SCR}post.log" 2>&1 || r=$?
emit POST_RC "$r"
emit POST_CLAIMS "$(grab "${SCR}post.log" CF_CLAIMS)"
emit POST_LINK_PAIRS "$(grab "${SCR}post.log" CF_LINK_PAIRS)"
emit POST_NO_CARD "$(grab "${SCR}post.log" CF_NO_CARD)"
emit POST_NO_TABLE "$(grab "${SCR}post.log" CF_NO_TABLE)"
emit POST_TABLE "$(grab "${SCR}post.log" CF_TABLE)"
emit POST_HISTORY_SAME "$(grab "${SCR}post.log" CF_HISTORY_SAME)"
emit POST_HISTORY_CHANGED "$(grab "${SCR}post.log" CF_HISTORY_CHANGED)"
emit POST_HISTORY_ABSENT "$(grab "${SCR}post.log" CF_HISTORY_ABSENT)"
emit POST_CHANGED_CLAIMS "$(grab "${SCR}post.log" CF_CHANGED_CLAIMS)"
emit POST_STRONG_NO_E "$(grab "${SCR}post.log" CF_STRONG_NO_E)"
emit POST_BASELINE "$(grab "${SCR}post.log" CF_BASELINE)"
emit POST_BASELINE_ROWS "$(grab "${SCR}post.log" CF_BASELINE_ROWS)"
emit POST_BASELINE_DEFECTS "$(grab "${SCR}post.log" CF_BASELINE_DEFECTS)"
emit POST_FINDINGS "$(grab "${SCR}post.log" CF_FINDINGS)"
AWK_CLAIMS=$(awk -F'\t' '$1!~/^#/ && ($2=="gate-closed"||$2=="measured")' lab/claims.tsv | wc -l | tr -d ' ')
emit CF_CLAIMS_MATCH_AWK "$([ "$AWK_CLAIMS" = "$(grab "${SCR}post.log" CF_CLAIMS)" ] && echo 1 || echo 0)"

# --- ШАГ 2: посадки в worktree пина --------------------------------------------------------------
mk_plant() {
  w="${SCR}plant-$1"
  git worktree add -q --detach "$w" "$PIN" >/dev/null 2>&1 || true
  git show "HEAD:$GUARD" > "$w/$GUARD"
  git show "HEAD:$BASE" > "$w/$BASE"
  printf '%s' "$w"
}

W=$(mk_plant missing)
python - "$W" <<'PY'
import io, os, sys
p = os.path.join(sys.argv[1], "lab", "claims-frozen-baseline.tsv")
lines = [l for l in io.open(p, encoding="utf-8").read().splitlines() if not l.startswith("C-001\t")]
io.open(p, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
PY
r=0; python "$GUARD" --root "$(win "$W")" > "${SCR}plant-missing.log" 2>&1 || r=$?
n=0; grep -q 'CF_FINDING_1=C-001:NO_TABLE:E-0087,E-0088,E-0091,E-0092' "${SCR}plant-missing.log" && n=1
emit PLANT_MISSING_ROW_RC "$r"; emit PLANT_MISSING_ROW_NAMED "$n"
ok1=0; [ "$r" = 1 ] && [ "$n" = 1 ] && ok1=1
git worktree remove --force "$W" >/dev/null 2>&1 || true

W=$(mk_plant empty)
python - "$W" <<'PY'
import io, os, sys
p = os.path.join(sys.argv[1], "lab", "claims-frozen-baseline.tsv")
out = []
for l in io.open(p, encoding="utf-8").read().splitlines():
    if l.startswith("C-009\t"):
        parts = l.split("\t"); parts[3] = ""; l = "\t".join(parts)
    out.append(l)
io.open(p, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
PY
r=0; python "$GUARD" --root "$(win "$W")" > "${SCR}plant-empty.log" 2>&1 || r=$?
n=0; grep -q 'CF_BASELINE_DEFECTS=C-009:EMPTY_REASON' "${SCR}plant-empty.log" && n=1
emit PLANT_EMPTY_RC "$r"; emit PLANT_EMPTY_NAMED "$n"
ok2=0; [ "$r" = 1 ] && [ "$n" = 1 ] && ok2=1
git worktree remove --force "$W" >/dev/null 2>&1 || true

W=$(mk_plant stale)
python - "$W" <<'PY'
import io, os, sys
p = os.path.join(sys.argv[1], "lab", "claims-frozen-baseline.tsv")
out = []
for l in io.open(p, encoding="utf-8").read().splitlines():
    if l.startswith("C-018\t"):
        parts = l.split("\t"); parts[2] = "E-9999"; l = "\t".join(parts)
    out.append(l)
io.open(p, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
PY
r=0; python "$GUARD" --root "$(win "$W")" > "${SCR}plant-stale.log" 2>&1 || r=$?
n=0; grep -q 'CF_BASELINE_DEFECTS=C-018:STALE' "${SCR}plant-stale.log" && n=1
emit PLANT_STALE_RC "$r"; emit PLANT_STALE_NAMED "$n"
ok3=0; [ "$r" = 1 ] && [ "$n" = 1 ] && ok3=1
git worktree remove --force "$W" >/dev/null 2>&1 || true

emit PLANT_CASES 3
emit PLANT_PASSED "$((ok1 + ok2 + ok3))"

# --- ШАГ 3: отказ вне git-корня -----------------------------------------------------------------
NG="${SCR}noroot"
mkdir -p "$NG"
r=0; python "$GUARD" --root "$(win "$NG")" > "${SCR}noroot.log" 2>&1 || r=$?
emit ROOT_RC "$r"
emit ROOT_KIND "$(grab "${SCR}noroot.log" CF_ROOT_KIND)"

# --- ШАГ 4: самопроверка прибора и соседние стражи ----------------------------------------------
r=0; python "$GUARD" --selftest > "${SCR}st.log" 2>&1 || r=$?
emit SELFTEST_RC "$r"
emit SELFTEST_CASES "$(grab "${SCR}st.log" CF_SELFTEST_CASES)"
emit SELFTEST_PASSED "$(grab "${SCR}st.log" CF_SELFTEST_PASSED)"
emit SELFTEST_FAILED "$(grab "${SCR}st.log" CF_SELFTEST_FAILED)"

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
r=0; python lab/check-none-compare.py > "${SCR}nonecmp.log" 2>&1 || r=$?
emit NONECMP_EXIT "$r"

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
done < lab/expectations/e0157.tsv
emit WORST_RC "$BAD"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0157-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
