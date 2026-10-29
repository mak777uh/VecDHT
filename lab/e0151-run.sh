#!/usr/bin/env bash
# Носитель круга H-0151: у каждого стража `lab/check-*` обязана быть посаженная ошибка, и контур
# обязан её исполнять — иначе зелёный страж неотличим от выключенного.
#
# Имя носителя — канон `eXXXX-run.sh`, который проверяет `repo-review` («у таблицы ожиданий есть
# свой helper»). Оракул карточки назвал файл `h-selftests-run.sh`; переименование сделано до
# первого официального прогона и записано в «Поправку» карточки.
#
# Порядок: (0) PRE_FIX пина — контура и стражей пина, материализованных через `git show`; самого
# мета-стража в пине нет, поэтому дыра названа отсутствием, а счёт пина даёт новый мета-страж на
# материализованном дереве (14 приборов, 5 находок: три без посадки, две без вызова);
# (1) POST_FIX — рабочее дерево (15 приборов, 0 находок); (2) каждая посадка исполняется и
# печатает свои случаи; (3) соседние стражи, диск, замороженная таблица, повторяемость.
#
# Употребление: bash lab/e0151-run.sh [каталог-вывода]
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

PIN=$(git log --format=%H --grep="H-0151: пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"
[ -n "$PIN" ] || PIN=$(git rev-parse HEAD)

# --- ШАГ 0: PRE_FIX пина — стражи и контур без мета-стража -------------------------------------
PIN_TREE="${SCR}pin-tree"
mkdir -p "$PIN_TREE/lab" "$PIN_TREE/.github/workflows"
for f in $(git ls-tree --name-only "$PIN" lab/ | grep -E '^lab/check-'); do
  git show "$PIN:$f" > "$PIN_TREE/$f"
done
git show "$PIN:.github/workflows/verify.yml" > "$PIN_TREE/.github/workflows/verify.yml"
git show "$PIN:lab/workspace-verify.sh" > "$PIN_TREE/lab/workspace-verify.sh"
if git cat-file -e "$PIN:lab/check-guard-selftests.py" 2>/dev/null; then
  emit PRE_FIX_PIN_FILE_ABSENT 0
else
  emit PRE_FIX_PIN_FILE_ABSENT 1
fi
# Карточка мерила счёт на `3f47d0b`; её стражи обязаны быть теми же байтами, что у пина, иначе
# «14 приборов» — число из другого дерева.
if [ -z "$(git diff --name-only 3f47d0b "$PIN" -- 'lab/check-*' .github/workflows/verify.yml lab/workspace-verify.sh)" ]; then
  emit PRE_FIX_PIN_GUARDS_SAME 1
else
  emit PRE_FIX_PIN_GUARDS_SAME 0
fi
r=0; python lab/check-guard-selftests.py --root "$(win "$PIN_TREE")" > "${SCR}pre.log" 2>&1 || r=$?
emit PRE_FIX_RC "$r"
emit PRE_FIX_GUARDS "$(grab "${SCR}pre.log" GSE_GUARDS)"
emit PRE_FIX_WITHOUT "$(grab "${SCR}pre.log" GSE_WITHOUT_SELFTEST)"
emit PRE_FIX_UNWIRED "$(grab "${SCR}pre.log" GSE_SELFTEST_UNWIRED)"
emit PRE_FIX_FINDINGS "$(grab "${SCR}pre.log" GSE_FINDINGS)"

# --- ШАГ 1: POST_FIX — рабочее дерево ----------------------------------------------------------
r=0; python lab/check-guard-selftests.py > "${SCR}post.log" 2>&1 || r=$?
emit POST_FIX_RC "$r"
emit POST_FIX_GUARDS "$(grab "${SCR}post.log" GSE_GUARDS)"
emit POST_FIX_WITHOUT "$(grab "${SCR}post.log" GSE_WITHOUT_SELFTEST)"
emit POST_FIX_UNWIRED "$(grab "${SCR}post.log" GSE_SELFTEST_UNWIRED)"
emit POST_FIX_FINDINGS "$(grab "${SCR}post.log" GSE_FINDINGS)"

# --- ШАГ 2: каждая посадка исполняется ---------------------------------------------------------
r=0; bash lab/check-release-kit.sh --selftest > "${SCR}st-kit.log" 2>&1 || r=$?
emit KIT_SELFTEST_RC "$r"
emit KIT_SELFTEST_CASES "$(grab "${SCR}st-kit.log" RKS_SELFTEST_CASES)"
emit KIT_SELFTEST_PASSED "$(grab "${SCR}st-kit.log" RKS_SELFTEST_PASSED)"
emit KIT_SELFTEST_FAILED "$(grab "${SCR}st-kit.log" RKS_SELFTEST_FAILED)"

r=0; bash lab/check-spec-mirror.sh --selftest > "${SCR}st-mirror.log" 2>&1 || r=$?
emit MIRROR_SELFTEST_RC "$r"
emit MIRROR_SELFTEST_CASES "$(grab "${SCR}st-mirror.log" SMK_SELFTEST_CASES)"
emit MIRROR_SELFTEST_PASSED "$(grab "${SCR}st-mirror.log" SMK_SELFTEST_PASSED)"
emit MIRROR_SELFTEST_FAILED "$(grab "${SCR}st-mirror.log" SMK_SELFTEST_FAILED)"

r=0; bash lab/check-text-clean.sh --selftest > "${SCR}st-text.log" 2>&1 || r=$?
emit TEXT_SELFTEST_RC "$r"
emit TEXT_SELFTEST_CASES "$(grab "${SCR}st-text.log" TCS_SELFTEST_CASES)"
emit TEXT_SELFTEST_PASSED "$(grab "${SCR}st-text.log" TCS_SELFTEST_PASSED)"
emit TEXT_SELFTEST_FAILED "$(grab "${SCR}st-text.log" TCS_SELFTEST_FAILED)"

r=0; python lab/check-artifact-refs.py --selftest > "${SCR}st-refs.log" 2>&1 || r=$?
emit REFS_SELFTEST_RC "$r"
emit REFS_SELFTEST "$(grab "${SCR}st-refs.log" REFS_SELFTEST)"

r=0; bash lab/check-secrets.sh --selftest > "${SCR}st-secrets.log" 2>&1 || r=$?
emit SECRETS_SELFTEST_RC "$r"
emit SECRETS_SELFTEST "$(grab "${SCR}st-secrets.log" SECRETS_SELFTEST)"

r=0; python lab/check-guard-selftests.py --selftest > "${SCR}st-gse.log" 2>&1 || r=$?
emit GSE_SELFTEST_RC "$r"
emit GSE_SELFTEST_CASES "$(grab "${SCR}st-gse.log" GSE_SELFTEST_CASES)"
emit GSE_SELFTEST_PASSED "$(grab "${SCR}st-gse.log" GSE_SELFTEST_PASSED)"
emit GSE_SELFTEST_FAILED "$(grab "${SCR}st-gse.log" GSE_SELFTEST_FAILED)"
# Посадка мета-стража обязана ловить непривязанную посадку, а не только отсутствие режима.
emit GSE_SELFTEST_DIRTY "$(grep -q 'ПОСАДКА dirty: OK' "${SCR}st-gse.log" && echo 1 || echo 0)"

# --- ШАГ 3: соседние стражи, диск --------------------------------------------------------------
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
r=0; bash lab/check-text-clean.sh lab/check-guard-selftests.py lab/e0151-run.sh \
  lab/expectations/e0151.tsv lab/hypotheses/H-0151-guard-selftests.md \
  lab/experiments/E-0151-guard-selftests.md > "${SCR}textcycle.log" 2>&1 || r=$?
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
done < lab/expectations/e0151.tsv
emit WORST_RC "$BAD"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0151-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
