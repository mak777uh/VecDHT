#!/usr/bin/env bash
# H-0160 / E-0160 — носитель: ссылки на строки спеки запрещены, объявленная цитата проверяется.
#
# PRE_FIX — шесть шапок с пина пре-регистрации через `git show`/`git grep`: ссылок должно быть 11,
# прибора на пине быть не должно (посадка «отсутствием», как у стража закрытых карточек).
# POST — прибор рабочего дерева: `SPEC_CITES_CITES` и `SPEC_CITES_FINDINGS`; самопроверка —
# шесть посаженных случаев. Границы (спека, продукт), CI и соседние стражи печатаются фактами.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
[ -f lab/expectations/e0160.tsv ] || { echo "НЕ КОРЕНЬ ДЕРЕВА: нет lab/expectations/e0160.tsv" >&2; exit 2; }

PIN=b5ad7f0
GUARD=lab/check-spec-cites.py
TMP=$(mktemp -d "${TMPDIR:-/tmp}/e0160.XXXXXX") || exit 2
trap 'rm -rf "$TMP"' EXIT
FACTS="$TMP/facts.txt"
: > "$FACTS"

emit() { printf '%s=%s\n' "$1" "${2:-none}" | tee -a "$FACTS"; }
grab() { sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1; }
win() { printf '%s' "$1" | sed 's|\\|/|g'; }
REF_RE='строк[а-я]+ +[0-9]{3,4}'

# --- ШАГ 0: PRE_FIX — дерево пина --------------------------------------------------------------
p=0; git cat-file -e "$PIN^{commit}" 2>/dev/null && p=1
emit PIN_FOUND "$p"
p=0; git cat-file -e "$PIN:$GUARD" 2>/dev/null && p=1
emit PRE_FIX_GUARD_FILE "$p"
git grep -oE "$REF_RE" "$PIN" -- crates > "$TMP/pre-refs.log" 2>/dev/null
emit PRE_FIX_REFS "$(wc -l < "$TMP/pre-refs.log" | tr -d ' ')"

# --- ШАГ 1: POST_FIX — прибор рабочего дерева ---------------------------------------------------
r=0; python "$GUARD" > "$TMP/guard.log" 2>&1 || r=$?
emit GUARD_EXIT "$r"
emit GUARD_FINDINGS "$(grab "$TMP/guard.log" SPEC_CITES_FINDINGS)"
emit GUARD_CITES "$(grab "$TMP/guard.log" SPEC_CITES_CITES)"
git grep -oE "$REF_RE" -- crates > "$TMP/post-refs.log" 2>/dev/null
emit POST_FIX_REFS "$(wc -l < "$TMP/post-refs.log" | tr -d ' ')"

r=0; python "$GUARD" --selftest > "$TMP/selftest.log" 2>&1 || r=$?
emit SELFTEST_CASES "$(grab "$TMP/selftest.log" SELFTEST_CASES)"
emit SELFTEST_PASS "$(grab "$TMP/selftest.log" SELFTEST_PASS)"

r=0; python -m py_compile "$GUARD" > "$TMP/pyc.log" 2>&1 || r=$?
emit PY_COMPILE "$r"

# Две формы вызова в CI: боевая и самопроверочная. Считаются формы, а не упоминания имени:
# первый пробный прогон `grep -c check-spec-cites` дал 3 (имя шага + два вызова) при смысле
# «вызван боевым и самопроверочным шагами»; определение исправлено до официальных прогонов.
w=0
grep -qE 'python lab/check-spec-cites\.py( >|$)' .github/workflows/verify.yml && w=$((w + 1))
grep -q 'check-spec-cites.py --selftest' .github/workflows/verify.yml && w=$((w + 1))
emit CI_WIRED "$w"

# --- ШАГ 2: границы — спека и продукт -----------------------------------------------------------
emit SPEC_TOUCHED "$(git diff --name-only "$PIN" -- docs/VecDHT-SPEC-v8.md docs/VecDHT-SPEC-v9.md | wc -l | tr -d ' ')"
emit PRODUCT_TOUCHED "$(git diff --name-only "$PIN" -- crates | grep '/src/' | wc -l | tr -d ' ')"

# --- ШАГ 3: соседние стражи ---------------------------------------------------------------------
r=0; python lab/check-guard-selftests.py > "$TMP/gse.log" 2>&1 || r=$?
emit GSE_EXIT "$r"
r=0; python lab/check-contour-parity.py > "$TMP/parity.log" 2>&1 || r=$?
emit PARITY_EXIT "$r"
r=0; python lab/check-contours.py > "$TMP/contours.log" 2>&1 || r=$?
emit CONTOURS_EXIT "$r"
r=0; python lab/check-expect-freeze.py > "$TMP/expect.log" 2>&1 || r=$?
emit EXPECT_FREEZE_EXIT "$r"
r=0; bash lab/check-text-clean.sh --all > "$TMP/text.log" 2>&1 || r=$?
emit TEXT_EXIT "$r"
r=0; python lab/check-claims.py > "$TMP/claims.log" 2>&1 || r=$?
emit CLAIMS_EXIT "$r"

# --- ШАГ 4: диск --------------------------------------------------------------------------------
bash lab/disk-report.sh > "$TMP/disk.log" 2>&1
D=$(grab "$TMP/disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_READABLE "$([ "$D" != none ] && echo 1 || echo 0)"

# --- ШАГ 5: вердикт по замороженной таблице -----------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2-; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
while IFS=$'\t' read -r k v _note; do
  case "$k" in ''|'#'*|STABLE|WORST_RC) continue;; esac
  want "$k" "$v"
done < lab/expectations/e0160.tsv
emit WORST_RC "$BAD"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0160-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
[ "$BAD" -eq 0 ] || exit 1
