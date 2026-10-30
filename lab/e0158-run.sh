#!/usr/bin/env bash
# Носитель круга H-0158: у слова `none` в таблицах ожиданий остаётся один владелец — печатное
# пустое множество. Порядок:
#  (0) PRE_FIX пина — стража в пине нет, берём его с HEAD в worktree пина; реестра там нет:
#      14 исторических таблиц со старой формой названы находками, пятнадцатая — таблица этого
#      круга без носителя (код 1);
#  (1) POST_FIX — рабочее дерево: реестр называет 14 исторических таблиц, находок 0, код 0;
#  (2) пять посадок в worktree HEAD — старая форма, новая форма, пустая причина, мёртвая строка,
#      таблица без носителя;
#  (3) подмена ожидания POST_TABLES в копии замороженной таблицы — expect.py краснеет и называет
#      ровно этот ключ; EXPECT_RC входит в want, поэтому подмена рабочей таблицы краснит вердикт;
#  (4) отказ вне git-корня (код 2), самопроверка прибора (10 фикстур), соседние стражи,
#      границы продукта, диск, повторяемость.
#
# Употребление: bash lab/e0158-run.sh [каталог-вывода]
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
# Отсутствие факта называется своим словом: литерал `none` прибору не принадлежит.
grab() { v=$(grep -oE "(^|[[:space:]])$2=[0-9A-Za-z/.,:%;_+-]*" "$1" 2>/dev/null | tail -1 | sed 's/.*=//'); [ -n "$v" ] && printf '%s' "$v" || printf 'НЕ_НАПЕЧАТАН'; }
win() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
cleanup() {
  for w in pin-tree plant-sentinel plant-split plant-empty plant-stale plant-nocarrier; do
    git worktree remove --force "${SCR}$w" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
GUARD="lab/check-none-owners.py"
BASE="lab/none-owners-baseline.tsv"

PIN=$(git log --format=%H --grep="H-0158: пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"
[ -n "$PIN" ] || PIN=$(git rev-parse HEAD)

# --- ШАГ 0: PRE_FIX пина — реестра нет, 15 находок ----------------------------------------------
WT="${SCR}pin-tree"
git worktree add -q --detach "$WT" "$PIN" >"${SCR}wt.log" 2>&1 || true
git show "HEAD:$GUARD" > "$WT/$GUARD"
r=0; python "$GUARD" --root "$(win "$WT")" > "${SCR}pre.log" 2>&1 || r=$?
emit PRE_FIX_RC "$r"
emit PRE_FIX_TABLES "$(grab "${SCR}pre.log" NO_TABLES)"
emit PRE_FIX_NONE_ROWS "$(grab "${SCR}pre.log" NO_NONE_ROWS)"
emit PRE_FIX_TABLES_WITH_NONE "$(grab "${SCR}pre.log" NO_TABLES_WITH_NONE)"
emit PRE_FIX_SENTINEL_TABLES "$(grab "${SCR}pre.log" NO_SENTINEL_TABLES)"
emit PRE_FIX_BASELINE_ROWS "$(grab "${SCR}pre.log" NO_BASELINE_ROWS)"
emit PRE_FIX_FINDINGS "$(grab "${SCR}pre.log" NO_FINDINGS)"
emit PRE_FIX_FINDING_TABLES "$(grab "${SCR}pre.log" NO_FINDING_TABLES)"
git worktree remove --force "$WT" >/dev/null 2>&1 || true

# --- ШАГ 1: POST_FIX — рабочее дерево -----------------------------------------------------------
r=0; python "$GUARD" > "${SCR}post.log" 2>&1 || r=$?
emit POST_RC "$r"
emit POST_TABLES "$(grab "${SCR}post.log" NO_TABLES)"
emit POST_NONE_ROWS "$(grab "${SCR}post.log" NO_NONE_ROWS)"
emit POST_TABLES_WITH_NONE "$(grab "${SCR}post.log" NO_TABLES_WITH_NONE)"
emit POST_SENTINEL_TABLES "$(grab "${SCR}post.log" NO_SENTINEL_TABLES)"
emit POST_BASELINE "$(grab "${SCR}post.log" NO_BASELINE)"
emit POST_BASELINE_ROWS "$(grab "${SCR}post.log" NO_BASELINE_ROWS)"
emit POST_BASELINE_DEFECTS "$(grab "${SCR}post.log" NO_BASELINE_DEFECTS)"
emit POST_FINDINGS "$(grab "${SCR}post.log" NO_FINDINGS)"
emit POST_FINDING_TABLES "$(grab "${SCR}post.log" NO_FINDING_TABLES)"
AWK_TABLES=$(ls lab/expectations/e*.tsv | wc -l | tr -d ' ')
emit TABLES_MATCH_LS "$([ "$AWK_TABLES" = "$(grab "${SCR}post.log" NO_TABLES)" ] && echo 1 || echo 0)"

# --- ШАГ 2: пять посадок в worktree HEAD --------------------------------------------------------
mk_plant() {
  w="${SCR}plant-$1"
  git worktree add -q --detach "$w" HEAD >/dev/null 2>&1 || true
  printf '%s' "$w"
}

W=$(mk_plant sentinel)
printf 'КЛЮЧ\tnone\tпустое множество\n' > "$W/lab/expectations/e9001.tsv"
OLD=$(printf '|| echo %s' "n""one")
printf 'grab() { [ -n "x" ] && echo x %s; }\n' "$OLD" > "$W/lab/e9001-run.sh"
r=0; python "$GUARD" --root "$(win "$W")" > "${SCR}plant-sentinel.log" 2>&1 || r=$?
S_FIND=$(grab "${SCR}plant-sentinel.log" NO_FINDINGS)
emit PLANT_SENTINEL_RC "$r"; emit PLANT_SENTINEL_FINDINGS "$S_FIND"
n=0; grep -q 'e9001\.tsv:SENTINEL_FORM' "${SCR}plant-sentinel.log" && n=1
emit PLANT_SENTINEL_NAMED "$n"
ok1=0; [ "$r" = 1 ] && [ "$S_FIND" = 1 ] && [ "$n" = 1 ] && ok1=1
git worktree remove --force "$W" >/dev/null 2>&1 || true

W=$(mk_plant split)
printf 'КЛЮЧ\tnone\tпустое множество\n' > "$W/lab/expectations/e9001.tsv"
cat > "$W/lab/e9001-run.sh" <<'SH'
grab() { v=$(grep KEY "$1"); [ -n "$v" ] && echo "$v" || printf 'НЕ_НАПЕЧАТАН'; }
SH
r=0; python "$GUARD" --root "$(win "$W")" > "${SCR}plant-split.log" 2>&1 || r=$?
P_FIND=$(grab "${SCR}plant-split.log" NO_FINDINGS)
emit PLANT_SPLIT_RC "$r"; emit PLANT_SPLIT_FINDINGS "$P_FIND"
ok2=0; [ "$r" = 0 ] && [ "$P_FIND" = 0 ] && ok2=1
git worktree remove --force "$W" >/dev/null 2>&1 || true

W=$(mk_plant empty)
python - "$W" <<'PY'
import io, os, sys
p = os.path.join(sys.argv[1], "lab", "none-owners-baseline.tsv")
out = []
for l in io.open(p, encoding="utf-8").read().splitlines():
    if l.startswith("lab/expectations/e0139.tsv\t"):
        parts = l.split("\t"); parts[1] = ""; l = "\t".join(parts)
    out.append(l)
io.open(p, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
PY
r=0; python "$GUARD" --root "$(win "$W")" > "${SCR}plant-empty.log" 2>&1 || r=$?
n=0; grep -q 'e0139\.tsv:EMPTY_REASON' "${SCR}plant-empty.log" && n=1
emit PLANT_EMPTY_RC "$r"; emit PLANT_EMPTY_NAMED "$n"
ok3=0; [ "$r" = 1 ] && [ "$n" = 1 ] && ok3=1
git worktree remove --force "$W" >/dev/null 2>&1 || true

W=$(mk_plant stale)
printf 'lab/expectations/e9999.tsv\tнет такой таблицы\n' >> "$W/lab/none-owners-baseline.tsv"
r=0; python "$GUARD" --root "$(win "$W")" > "${SCR}plant-stale.log" 2>&1 || r=$?
n=0; grep -q 'e9999\.tsv:STALE' "${SCR}plant-stale.log" && n=1
emit PLANT_STALE_RC "$r"; emit PLANT_STALE_NAMED "$n"
ok4=0; [ "$r" = 1 ] && [ "$n" = 1 ] && ok4=1
git worktree remove --force "$W" >/dev/null 2>&1 || true

W=$(mk_plant nocarrier)
printf 'КЛЮЧ\tnone\tпустое множество\n' > "$W/lab/expectations/e9002.tsv"
r=0; python "$GUARD" --root "$(win "$W")" > "${SCR}plant-nocarrier.log" 2>&1 || r=$?
N_FIND=$(grab "${SCR}plant-nocarrier.log" NO_FINDINGS)
emit PLANT_NOCARRIER_RC "$r"; emit PLANT_NOCARRIER_FINDINGS "$N_FIND"
n=0; grep -q 'e9002\.tsv:NO_CARRIER' "${SCR}plant-nocarrier.log" && n=1
emit PLANT_NOCARRIER_NAMED "$n"
ok5=0; [ "$r" = 1 ] && [ "$N_FIND" = 1 ] && [ "$n" = 1 ] && ok5=1
git worktree remove --force "$W" >/dev/null 2>&1 || true

emit PLANT_CASES 5
emit PLANT_PASSED "$((ok1 + ok2 + ok3 + ok4 + ok5))"

# --- ШАГ 3: отказ вне git-корня -----------------------------------------------------------------
NG="${SCR}noroot"
mkdir -p "$NG/lab/expectations"
printf 'КЛЮЧ\tnone\tпустое множество\n' > "$NG/lab/expectations/e0158.tsv"
r=0; python "$GUARD" --root "$(win "$NG")" > "${SCR}noroot.log" 2>&1 || r=$?
emit ROOT_RC "$r"
emit ROOT_KIND "$(grab "${SCR}noroot.log" NO_ROOT_KIND)"

# --- ШАГ 4: самопроверка прибора и соседние стражи ----------------------------------------------
r=0; python "$GUARD" --selftest > "${SCR}st.log" 2>&1 || r=$?
emit SELFTEST_RC "$r"
emit SELFTEST_CASES "$(grab "${SCR}st.log" NO_SELFTEST_CASES)"
emit SELFTEST_PASSED "$(grab "${SCR}st.log" NO_SELFTEST_PASSED)"
emit SELFTEST_FAILED "$(grab "${SCR}st.log" NO_SELFTEST_FAILED)"

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
r=0; python lab/check-expect-freeze.py > "${SCR}expect-freeze.log" 2>&1 || r=$?
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

# --- ШАГ 6: подмена ожидания в копии замороженной таблицы ---------------------------------------
# Пять строк PLANT_SUB_* печатает сама посадка, поэтому сверка идёт до их появления; счёт
# расхождений ведётся по ключу POST_TABLES, а имя берётся из строки расхождения.
SUB="${SCR}sub.tsv"
awk -F'\t' 'BEGIN{OFS="\t"} $1=="POST_TABLES"{$2="63"} {print}' lab/expectations/e0158.tsv > "$SUB"
cmp -s lab/expectations/e0158.tsv "$SUB"; C=$?
emit PLANT_SUB_COPY "$([ "$C" -ne 0 ] && echo 1 || echo 0)"
r=0; python lab/expect.py "$SUB" "$FACTS" > "${SCR}sub.log" 2>&1 || r=$?
emit PLANT_SUB_RC "$r"
M=$(grep -c '^РАСХОЖДЕНИЕ: POST_TABLES ' "${SCR}sub.log")
emit PLANT_SUB_MISMATCH "$M"
NAME=$(awk '/^РАСХОЖДЕНИЕ: POST_TABLES /{print $2; exit}' "${SCR}sub.log")
[ -n "$NAME" ] || NAME="НЕ_НАПЕЧАТАН"
emit PLANT_SUB_NAME "$NAME"
SUB_OK=1
[ "$r" -ne 0 ] || SUB_OK=0
[ "$M" -eq 1 ] || SUB_OK=0
[ "$NAME" = POST_TABLES ] || SUB_OK=0
emit PLANT_SUB_PASS "$([ "$SUB_OK" -eq 1 ] && echo 0 || echo 1)"

# --- ШАГ 7: вердикт по замороженной таблице -----------------------------------------------------
r=0; python lab/expect.py lab/expectations/e0158.tsv "$FACTS" > "${SCR}expect.log" 2>&1 || r=$?
emit EXPECT_RC "$r"

get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
while IFS=$'\t' read -r k v _note; do
  case "$k" in ''|'#'*|STABLE|WORST_RC) continue;; esac
  want "$k" "$v"
done < lab/expectations/e0158.tsv
want EXPECT_RC 0

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0158-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
emit WORST_RC "$BAD"
if [ "$BAD" -ne 0 ]; then exit 1; fi
