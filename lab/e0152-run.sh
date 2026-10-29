#!/usr/bin/env bash
# Носитель круга H-0152: прибор, стоящий боевым шагом только в одном из двух контуров, защищает
# половину пути и при этом зеленеет. Порядок:
#  (0) PRE_FIX пина — контур и стражи пина, материализованные через `git show`; самого стража
#      паритета в пине нет, поэтому дыра названа отсутствием, а счёт даёт новый страж на
#      материализованном дереве (15 приборов, 6 молчаливых расхождений);
#  (1) POST_FIX — рабочее дерево (16 приборов, 0 расхождений без причины); числа сверяются с
#      каталогом `lab/check-*` и с числом строк реестра, а не с литералом в helper'е;
#  (2) посадки стража паритета — три посаженные ошибки обязаны краснеть;
#  (3) соседние стражи, границы продукта, диск, повторяемость на неизменном дереве.
#
# Употребление: bash lab/e0152-run.sh [каталог-вывода]
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

PIN=$(git log --format=%H --grep="H-0152: пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"
[ -n "$PIN" ] || PIN=$(git rev-parse HEAD)
emit PIN_SHORT "$(git rev-parse --short "$PIN")"

# --- ШАГ 0: PRE_FIX пина — стражи и два основных контура без стража паритета -------------------
PIN_TREE="${SCR}pin-tree"
mkdir -p "$PIN_TREE/lab" "$PIN_TREE/.github/workflows"
for f in $(git ls-tree --name-only "$PIN" lab/ | grep -E '^lab/check-'); do
  git show "$PIN:$f" > "$PIN_TREE/$f"
done
git show "$PIN:.github/workflows/verify.yml" > "$PIN_TREE/.github/workflows/verify.yml"
# Дополнительные места тоже материализуются: без `release.yml` прибор, чей единственный боевой
# вызов живёт на теге, выглядел бы «без вызова вовсе» — это дефект копии, а не дерева (ДИАГНОЗ-1).
for f in release.yml formal.yml; do
  if git cat-file -e "$PIN:.github/workflows/$f" 2>/dev/null; then
    git show "$PIN:.github/workflows/$f" > "$PIN_TREE/.github/workflows/$f"
  fi
done
git show "$PIN:lab/workspace-verify.sh" > "$PIN_TREE/lab/workspace-verify.sh"
if git cat-file -e "$PIN:lab/contour-parity.tsv" 2>/dev/null; then
  git show "$PIN:lab/contour-parity.tsv" > "$PIN_TREE/lab/contour-parity.tsv"
fi
if git cat-file -e "$PIN:lab/check-contour-parity.py" 2>/dev/null; then
  emit PRE_FIX_PIN_FILE_ABSENT 0
else
  emit PRE_FIX_PIN_FILE_ABSENT 1
fi
r=0; python lab/check-contour-parity.py --root "$(win "$PIN_TREE")" > "${SCR}pre.log" 2>&1 || r=$?
emit PRE_FIX_RC "$r"
emit PRE_FIX_GUARDS "$(grab "${SCR}pre.log" ПАРИТЕТ_ПРИБОРОВ)"
emit PRE_FIX_DIFFERENCES "$(grab "${SCR}pre.log" ПАРИТЕТ_РАСХОЖДЕНИЙ)"
emit PRE_FIX_UNNAMED "$(grab "${SCR}pre.log" ПАРИТЕТ_БЕЗ_ПРИЧИНЫ)"
emit PRE_FIX_UNWIRED "$(grab "${SCR}pre.log" ПАРИТЕТ_БЕЗ_ВЫЗОВА)"
emit PRE_FIX_FINDINGS "$(grab "${SCR}pre.log" ПАРИТЕТ_НАХОДОК)"

# --- ШАГ 1: POST_FIX — рабочее дерево ----------------------------------------------------------
r=0; python lab/check-contour-parity.py > "${SCR}post.log" 2>&1 || r=$?
emit POST_FIX_RC "$r"
emit ПАРИТЕТ_ПРИБОРОВ "$(grab "${SCR}post.log" ПАРИТЕТ_ПРИБОРОВ)"
emit ПАРИТЕТ_РАСХОЖДЕНИЙ "$(grab "${SCR}post.log" ПАРИТЕТ_РАСХОЖДЕНИЙ)"
emit ПАРИТЕТ_БЕЗ_ПРИЧИНЫ "$(grab "${SCR}post.log" ПАРИТЕТ_БЕЗ_ПРИЧИНЫ)"
emit ПАРИТЕТ_БЕЗ_ВЫЗОВА "$(grab "${SCR}post.log" ПАРИТЕТ_БЕЗ_ВЫЗОВА)"
emit ПАРИТЕТ_ПРИЧИН "$(grab "${SCR}post.log" ПАРИТЕТ_ПРИЧИН)"
emit ПАРИТЕТ_ПУСТЫХ_ПРИЧИН "$(grab "${SCR}post.log" ПАРИТЕТ_ПУСТЫХ_ПРИЧИН)"
emit ПАРИТЕТ_МЁРТВЫХ_СТРОК "$(grab "${SCR}post.log" ПАРИТЕТ_МЁРТВЫХ_СТРОК)"
emit ПАРИТЕТ_НАХОДОК "$(grab "${SCR}post.log" ПАРИТЕТ_НАХОДОК)"
# Число приборов и строк реестра считаются здесь заново, по каталогу и по файлу: литерал в
# helper'е сгнил бы на первом же новом страже.
LS_COUNT=$(ls lab/check-* | wc -l | tr -d ' ')
emit LS_CHECK_COUNT "$LS_COUNT"
emit PARITY_GUARDS_MATCH_LS "$([ "$(grab "${SCR}post.log" ПАРИТЕТ_ПРИБОРОВ)" = "$LS_COUNT" ] && echo 1 || echo 0)"
ROWS=$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*$/ {next} {n++} END {print n+0}' lab/contour-parity.tsv)
emit PARITY_REGISTRY_ROWS "$ROWS"
emit PARITY_REASONS_MATCH_ROWS "$([ "$(grab "${SCR}post.log" ПАРИТЕТ_ПРИЧИН)" = "$ROWS" ] && echo 1 || echo 0)"

# --- ШАГ 2: посадки стража паритета -------------------------------------------------------------
r=0; python lab/check-contour-parity.py --selftest > "${SCR}st-parity.log" 2>&1 || r=$?
emit PARITY_SELFTEST_RC "$r"
emit PARITY_SELFTEST_CASES "$(grab "${SCR}st-parity.log" PARITY_SELFTEST_CASES)"
emit PARITY_SELFTEST_PASSED "$(grab "${SCR}st-parity.log" PARITY_SELFTEST_PASSED)"
emit PARITY_SELFTEST_FAILED "$(grab "${SCR}st-parity.log" PARITY_SELFTEST_FAILED)"
emit PARITY_SELFTEST_DIRTY "$(grep -q 'ПОСАДКА removed_call: OK' "${SCR}st-parity.log" && echo 1 || echo 0)"
# Мета-страж H-0151 обязан быть зелёным: новый прибор получил и посадку, и вызов контура.
r=0; python lab/check-guard-selftests.py > "${SCR}gse.log" 2>&1 || r=$?
emit GSE_EXIT "$r"
emit GSE_FINDINGS "$(grab "${SCR}gse.log" GSE_FINDINGS)"

# --- ШАГ 3: боевые стражи, границы, диск --------------------------------------------------------
r=0; python lab/check-artifact-refs.py > "${SCR}refs.log" 2>&1 || r=$?
emit REFS_EXIT "$r"
r=0; python lab/check-status-claims.py > "${SCR}status.log" 2>&1 || r=$?
emit STATUS_EXIT "$r"
r=0; bash lab/check-secrets.sh > "${SCR}secrets.log" 2>&1 || r=$?
emit SECRETS_EXIT "$r"
r=0; bash lab/check-release-kit.sh > "${SCR}kit.log" 2>&1 || r=$?
emit KIT_EXIT "$r"
r=0; bash lab/check-spec-mirror.sh > "${SCR}mirror.log" 2>&1 || r=$?
emit MIRROR_EXIT "$r"
r=0; bash lab/check-text-clean.sh --all > "${SCR}text.log" 2>&1 || r=$?
emit TEXTGUARD_ALL_EXIT "$r"
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' "${SCR}text.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; python lab/repo-review.py check > "${SCR}review.log" 2>&1 || r=$?
emit REVIEW_EXIT "$r"
r=0; python lab/threshold-lint.py --latest > "${SCR}lint.log" 2>&1 || r=$?
emit LINT_LATEST_EXIT "$r"
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' "${SCR}lint.log" 2>/dev/null | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; python lab/check-claims.py > "${SCR}claims.log" 2>&1 || r=$?
emit CLAIMS_EXIT "$r"
r=0; python lab/check-contours.py > "${SCR}contours.log" 2>&1 || r=$?
emit CONTOURS_EXIT "$r"
r=0; bash lab/check-text-clean.sh lab/check-contour-parity.py lab/contour-parity.tsv \
  lab/e0152-run.sh lab/expectations/e0152.tsv lab/hypotheses/H-0152-contour-parity.md \
  lab/experiments/E-0152-contour-parity.md .github/workflows/verify.yml \
  lab/workspace-verify.sh > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"

bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

# --- ШАГ 4: вердикт по замороженной таблице ----------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
while IFS=$'\t' read -r k v _note; do
  case "$k" in ''|'#'*|STABLE|WORST_RC) continue;; esac
  want "$k" "$v"
done < lab/expectations/e0152.tsv
emit WORST_RC "$BAD"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0152-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
