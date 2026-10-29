#!/usr/bin/env bash
# Носитель круга H-0153: форма записи не равна механизму. Три прибора зеленели на форме,
# которая не обозначает работу:
#  (а) мета-страж `check-guard-selftests.py` считал посадкой слово `selftest` в комментарии и
#      вызовом — закомментированную строку контура;
#  (б) самотест `check-artifact-refs.py` проверял исключение каталога на файле, которого нет, —
#      то есть доказывал отсутствие, а не исключение;
#  (в) `check-text-clean.sh --all` не читал `lab/*.txt` и `lab/*.tsv`, где и жил гибрид.
# Порядок:
#  (0) PRE_FIX — приборы пина через `git show`, три посаженные ошибки обязаны дать зелёный;
#  (1) POST_FIX — те же посадки на рабочем дереве обязаны дать красный и назвать имена;
#  (2) боевые факты настоящего дерева, соседние стражи, границы продукта, диск;
#  (3) вердикт по замороженной таблице `lab/expectations/e0153.tsv`.
#
# Употребление: bash lab/e0153-run.sh [каталог-вывода]
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

PIN=$(git log --format=%H --grep="H-0153: пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"
[ -n "$PIN" ] || PIN=$(git rev-parse HEAD)
emit PIN_SHORT "$(git rev-parse --short "$PIN")"
emit PIN_BASE_SAME_BYTES "$(git diff --quiet "$PIN" 2f07908 -- lab/check-guard-selftests.py lab/check-artifact-refs.py lab/check-text-clean.sh && echo 1 || echo 0)"

# Общие фикстуры GSE: (а) режим только в комментарии; (б) вызов только в комментарии.
GSE_ROOT="${SCR}gse-root"
mkdir -p "$GSE_ROOT/lab" "$GSE_ROOT/.github/workflows"
printf '#!/usr/bin/env bash\n# умеет --selftest\nexit 0\n' > "$GSE_ROOT/lab/check-commentonly.sh"
printf '#!/usr/bin/env bash\n[ "${1:-}" = "--selftest" ] && exit 0\nexit 0\n' > "$GSE_ROOT/lab/check-beta.sh"
printf '#!/usr/bin/env bash\n' > "$GSE_ROOT/lab/workspace-verify.sh"
printf '# python lab/check-beta.sh --selftest\npython lab/check-commentonly.sh --selftest\n' \
  > "$GSE_ROOT/.github/workflows/verify.yml"

# Фикстуры текста: (а) гибрид только в `.txt`; (б) только в `.tsv`; (в) чистое дерево.
# Гибрид собирается из двух кусков, иначе этот же файл покраснел бы сам на себе.
HY="тест"; HY="${HY}x"
TXT_REPO="${SCR}txt-root"; TSV_REPO="${SCR}tsv-root"; CLEAN_REPO="${SCR}clean-root"
for R in "$TXT_REPO" "$TSV_REPO" "$CLEAN_REPO"; do
  mkdir -p "$R/lab"
  printf 'обычный текст без дефекта\n' > "$R/lab/clean.md"
done
printf 'разрешение: %s в списке\n' "$HY" > "$TXT_REPO/lab/allow.txt"
printf 'ключ\tзначение\nстолбец\tчисло\n' > "$TXT_REPO/lab/rows.tsv"
printf 'разрешение: обычный текст в списке\n' > "$TSV_REPO/lab/allow.txt"
printf 'ключ\tзначение\nстолбец\t%s\n' "$HY" > "$TSV_REPO/lab/rows.tsv"
printf 'разрешение: обычный текст в списке\n' > "$CLEAN_REPO/lab/allow.txt"
printf 'ключ\tзначение\nстолбец\tчисло\n' > "$CLEAN_REPO/lab/rows.tsv"
for R in "$TXT_REPO" "$TSV_REPO" "$CLEAN_REPO"; do
  git -C "$R" init -q
  git -C "$R" add -A
  git -C "$R" -c user.email=selftest@example.invalid -c user.name=selftest commit -qm plant 2>/dev/null
done

# --- ШАГ 0: PRE_FIX пина — три формы, которые приборы пина принимали за механизм ---------------
git show "$PIN:lab/check-guard-selftests.py" > "${SCR}pin-gse.py"
git show "$PIN:lab/check-artifact-refs.py" > "${SCR}pin-refs.py"
git show "$PIN:lab/check-text-clean.sh" > "${SCR}pin-text.sh"

r=0; python "${SCR}pin-gse.py" --root "$(win "$GSE_ROOT")" > "${SCR}pre-gse.log" 2>&1 || r=$?
emit PRE_FIX_GSE_RC "$r"
emit PRE_FIX_GSE_FINDINGS "$(grab "${SCR}pre-gse.log" GSE_FINDINGS)"
emit PRE_FIX_GSE_FALSE_GREEN "$([ "$r" = 0 ] && [ "$(grab "${SCR}pre-gse.log" GSE_FINDINGS)" = 0 ] && echo 1 || echo 0)"

# Копия прежнего самотеста со снятым исключением: настоящее имя в interop/ — и всё равно ok.
python - "${SCR}pin-refs.py" "${SCR}pin-refs-nodir.py" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()
s2 = re.sub(r'EXTERNAL_DIRS = \([^)]*\)', 'EXTERNAL_DIRS = ()', s, count=1)
assert s2 != s, "EXTERNAL_DIRS not found"
open(dst, "w", encoding="utf-8", newline="\n").write(s2)
PY
r=0; python "${SCR}pin-refs-nodir.py" --selftest > "${SCR}pre-refs.log" 2>&1 || r=$?
emit PRE_FIX_REFS_RC "$r"
emit PRE_FIX_REFS_SELFTEST "$(grab "${SCR}pre-refs.log" REFS_SELFTEST)"
emit PRE_FIX_REFS_FALSE_GREEN "$([ "$r" = 0 ] && [ "$(grab "${SCR}pre-refs.log" REFS_SELFTEST)" = ok ] && echo 1 || echo 0)"

r=0; out=$(VEC_DHT_ROOT="$TXT_REPO" bash "${SCR}pin-text.sh" --all 2>/dev/null) || r=$?
emit PRE_FIX_TEXT_TXT_RC "$r"
d=$(printf '%s\n' "$out" | grep -o 'файлов_с_грязью=[0-9]*' | tail -1 | cut -d= -f2); emit PRE_FIX_TEXT_TXT_DIRTY "${d:-none}"
emit PRE_FIX_TEXT_FALSE_GREEN "$([ "$r" = 0 ] && [ "${d:-none}" = 0 ] && echo 1 || echo 0)"

# --- ШАГ 1: POST_FIX — те же три посадки на рабочем дереве --------------------------------------
r=0; python lab/check-guard-selftests.py --root "$(win "$GSE_ROOT")" > "${SCR}post-gse.log" 2>&1 || r=$?
emit POST_FIX_GSE_RC "$r"
emit POST_FIX_GSE_FINDINGS "$(grab "${SCR}post-gse.log" GSE_FINDINGS)"
emit POST_FIX_GSE_NAMES "$(grep -o 'lab/check-[A-Za-z0-9_.-]*' "${SCR}post-gse.log" | sort -u | paste -sd, -)"
emit POST_FIX_GSE_NAMES_BOTH "$(grep -q 'check-beta.sh' "${SCR}post-gse.log" && grep -q 'check-commentonly.sh' "${SCR}post-gse.log" && echo 1 || echo 0)"

r=0; python lab/check-artifact-refs.py --selftest > "${SCR}post-refs-ok.log" 2>&1 || r=$?
emit POST_FIX_REFS_SELFTEST_OK_RC "$r"
emit POST_FIX_REFS_SELFTEST_OK "$(grab "${SCR}post-refs-ok.log" REFS_SELFTEST)"
emit POST_FIX_REFS_EXTERNAL_DIR "$(grab "${SCR}post-refs-ok.log" EXTERNAL_DIR)"
emit POST_FIX_REFS_REMOVAL "$(grab "${SCR}post-refs-ok.log" EXTERNAL_DIR_REMOVAL)"
# Та же мутация, что в PRE_FIX, но на новом приборе: снятое исключение обязано покраснеть.
python - lab/check-artifact-refs.py "${SCR}new-refs-nodir.py" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()
s2 = re.sub(r'EXTERNAL_DIRS = \([^)]*\)', 'EXTERNAL_DIRS = ()', s, count=1)
assert s2 != s, "EXTERNAL_DIRS not found"
open(dst, "w", encoding="utf-8", newline="\n").write(s2)
PY
r=0; python "${SCR}new-refs-nodir.py" --selftest > "${SCR}post-refs-bad.log" 2>&1 || r=$?
emit POST_FIX_REFS_SELFTEST_RC "$r"
emit POST_FIX_REFS_BAD_STATE "$(grab "${SCR}post-refs-bad.log" REFS_SELFTEST)"

for name in TXT TSV; do
  R="$TXT_REPO"; [ "$name" = TSV ] && R="$TSV_REPO"
  r=0; out=$(VEC_DHT_ROOT="$R" bash lab/check-text-clean.sh --all 2>/dev/null) || r=$?
  emit "POST_FIX_TEXT_${name}_RC" "$r"
  d=$(printf '%s\n' "$out" | grep -o 'файлов_с_грязью=[0-9]*' | tail -1 | cut -d= -f2)
  emit "POST_FIX_TEXT_${name}_DIRTY" "${d:-none}"
done
r=0; out=$(VEC_DHT_ROOT="$CLEAN_REPO" bash lab/check-text-clean.sh --all 2>/dev/null) || r=$?
emit POST_FIX_TEXT_CLEAN_RC "$r"
d=$(printf '%s\n' "$out" | grep -o 'файлов_с_грязью=[0-9]*' | tail -1 | cut -d= -f2)
emit POST_FIX_TEXT_CLEAN_DIRTY "${d:-none}"

# --- ШАГ 2: боевые факты настоящего дерева ------------------------------------------------------
python lab/check-guard-selftests.py --selftest > "${SCR}gse-st.log" 2>&1
emit GSE_SELFTEST_CASES "$(grab "${SCR}gse-st.log" GSE_SELFTEST_CASES)"
emit GSE_SELFTEST_PASSED "$(grab "${SCR}gse-st.log" GSE_SELFTEST_PASSED)"
bash lab/check-text-clean.sh --selftest > "${SCR}text-st.log" 2>&1
emit TCS_SELFTEST_CASES "$(grab "${SCR}text-st.log" TCS_SELFTEST_CASES)"
emit TCS_SELFTEST_PASSED "$(grab "${SCR}text-st.log" TCS_SELFTEST_PASSED)"

r=0; python lab/check-guard-selftests.py > "${SCR}gse.log" 2>&1 || r=$?
emit GSE_EXIT "$r"
emit GSE_GUARDS "$(grab "${SCR}gse.log" GSE_GUARDS)"
emit GSE_FINDINGS "$(grab "${SCR}gse.log" GSE_FINDINGS)"
LS_COUNT=$(ls lab/check-* | wc -l | tr -d ' ')
emit LS_CHECK_COUNT "$LS_COUNT"
emit GSE_GUARDS_MATCH_LS "$([ "$(grab "${SCR}gse.log" GSE_GUARDS)" = "$LS_COUNT" ] && echo 1 || echo 0)"

r=0; python lab/check-artifact-refs.py > "${SCR}refs.log" 2>&1 || r=$?
emit REFS_EXIT "$r"
emit REFS_CITED "$(grab "${SCR}refs.log" REFS_CITED)"
emit REFS_MISSING "$(grab "${SCR}refs.log" REFS_MISSING)"

r=0; bash lab/check-text-clean.sh --all > "${SCR}text.log" 2>&1 || r=$?
emit TEXTGUARD_ALL_EXIT "$r"
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' "${SCR}text.log" | tail -1 | cut -d= -f2 | grep . || echo none)"

r=0; python lab/check-contour-parity.py > "${SCR}parity.log" 2>&1 || r=$?
emit PARITY_EXIT "$r"
r=0; python lab/check-status-claims.py > "${SCR}status.log" 2>&1 || r=$?
emit STATUS_EXIT "$r"
r=0; bash lab/check-secrets.sh > "${SCR}secrets.log" 2>&1 || r=$?
emit SECRETS_EXIT "$r"
r=0; bash lab/check-release-kit.sh > "${SCR}kit.log" 2>&1 || r=$?
emit KIT_EXIT "$r"
r=0; bash lab/check-spec-mirror.sh > "${SCR}mirror.log" 2>&1 || r=$?
emit MIRROR_EXIT "$r"
r=0; python lab/repo-review.py check > "${SCR}review.log" 2>&1 || r=$?
emit REVIEW_EXIT "$r"
r=0; python lab/threshold-lint.py --latest > "${SCR}lint.log" 2>&1 || r=$?
emit LINT_LATEST_EXIT "$r"
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' "${SCR}lint.log" 2>/dev/null | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; python lab/check-claims.py > "${SCR}claims.log" 2>&1 || r=$?
emit CLAIMS_EXIT "$r"
r=0; python lab/check-contours.py > "${SCR}contours.log" 2>&1 || r=$?
emit CONTOURS_EXIT "$r"
r=0; bash lab/check-text-clean.sh lab/check-guard-selftests.py lab/check-artifact-refs.py \
  lab/check-text-clean.sh lab/e0153-run.sh lab/expectations/e0153.tsv \
  lab/hypotheses/H-0153-guard-form-vs-mechanism.md \
  lab/experiments/E-0153-guard-form-vs-mechanism.md > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"

emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ 2>/dev/null | wc -l | tr -d ' ')"

bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

# --- ШАГ 3: вердикт по замороженной таблице ----------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
while IFS=$'\t' read -r k v _note; do
  case "$k" in ''|'#'*|STABLE|WORST_RC) continue;; esac
  want "$k" "$v"
done < lab/expectations/e0153.tsv
emit WORST_RC "$BAD"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0153-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
