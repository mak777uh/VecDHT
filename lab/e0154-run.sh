#!/usr/bin/env bash
# Носитель круга H-0154: число в комментарии CI обязано иметь исполнителя.
#
# Предмет. Шапка `.github/workflows/verify.yml` печатает числа вместе с командами пересчёта и
# расходилась с деревом на 40 тестов (762 против 802, `cli 79` против 102, «203 из 764», «~764
# теста») — молча, потому что ни один страж арифметику комментария не читал.
#
# Порядок:
#  (0) PRE_FIX — дерево пина разворачивается временным `git worktree`; команды, напечатанные в
#      самой шапке, исполняются bash'ем и называют drift; те же десять приборов пина над тем же
#      деревом зелёные, то есть drift для них невидим; новый прибор на дереве пина красен и
#      называет каждое утверждение по классам.
#  (1) POST_FIX — на рабочем дереве тот же прибор зелёный и печатает все утверждения; самотест
#      обязан поймать семь посаженных форм.
#  (2) боевые факты настоящего дерева, соседи, границы продукта и круга, диск.
#  (3) вердикт по замороженной таблице `lab/expectations/e0154.tsv`.
#
# Употребление: bash lab/e0154-run.sh [каталог-вывода]
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
grab() { v=$(grep -oE "(^|[[:space:]])$2=[0-9A-Za-z/.,:%_-]*" "$1" 2>/dev/null | tail -1 | sed 's/.*=//'); [ -n "$v" ] && printf '%s' "$v" || printf 'none'; }
# Факты на кириллице (у стража паритета ключи русские) — их берёт отдельный читатель, а имя
# факта круга остаётся ASCII: у имени факта обязан быть один владелец.
grabc() { v=$(grep -oE "^$2=[^[:space:]]*" "$1" 2>/dev/null | tail -1 | sed 's/^[^=]*=//'); [ -n "$v" ] && printf '%s' "$v" || printf 'none'; }
win() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

PIN=$(git log --format=%H --grep="H-0154: пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"
[ -n "$PIN" ] || PIN=$(git rev-parse HEAD)
emit PIN_SHORT "$(git rev-parse --short "$PIN")"
# На пине прибора нет: это и есть находка (число в комментарии existed, исполнитель — нет).
emit PIN_INSTRUMENT_ABSENT "$(git cat-file -e "$PIN:lab/check-ci-numbers.py" 2>/dev/null && echo 0 || echo 1)"

# --- ШАГ 0: PRE_FIX на дереве пина ---------------------------------------------------------------
WT="${SCR}pin-tree"
git worktree add --detach "$WT" "$PIN" >/dev/null 2>&1
emit WT_MADE "$([ -f "$WT/.github/workflows/verify.yml" ] && echo 1 || echo 0)"
trap 'cd "$ROOT"; git worktree remove --force "$WT" >/dev/null 2>&1 || true; git worktree prune >/dev/null 2>&1 || true' EXIT
# Побайтовое равенство развёрнутого файла blob'у пина — хешем, а не длиной: файл, из которого
# носитель вынимает обещанные числа, обязан быть тем же файлом, что лежит на пине.
BLOB=$(git rev-parse "$PIN:.github/workflows/verify.yml")
ONDISK=$(git hash-object "$WT/.github/workflows/verify.yml")
emit WT_PIN_BLOB "$BLOB"
emit WT_PIN_ONDISK "$ONDISK"
emit WT_PIN_BYTES "$([ "$BLOB" = "$ONDISK" ] && echo 1 || echo 0)"

WF="$WT/.github/workflows/verify.yml"
# Числа, которые обещает шапка пина, вынимаются из той же строки, что и команда, а команды
# исполняются буквально — иначе носитель сверял бы свою память, а не файл.
claim_of() { grep -F "$1" "$WF" | grep -oE '#[[:space:]]+[0-9]+' | tail -1 | grep -oE '[0-9]+'; }
CL_TEST=$(claim_of "test\\]' crates");  CL_TEST=${CL_TEST:-none}
CL_TOKIO=$(claim_of "tokio::test");     CL_TOKIO=${CL_TOKIO:-none}
CL_CASE=$(claim_of "test_case");        CL_CASE=${CL_CASE:-none}
CL_IGN=$(claim_of "ignore' crates");    CL_IGN=${CL_IGN:-none}
CL_ALL=$(grep -oE 'всего [0-9]+' "$WF" | head -1 | grep -oE '[0-9]+'); CL_ALL=${CL_ALL:-none}
emit PRE_FIX_CLAIMED_TEST "$CL_TEST"
emit PRE_FIX_CLAIMED_TOKIO "$CL_TOKIO"
emit PRE_FIX_CLAIMED_CASE "$CL_CASE"
emit PRE_FIX_CLAIMED_IGNORED "$CL_IGN"
emit PRE_FIX_CLAIMED_ALL "$CL_ALL"

TR_TEST=$( (cd "$WT" && grep -rhoE '#\[test\]' crates --include=*.rs | wc -l) | tr -d ' ')
TR_TOKIO=$( (cd "$WT" && grep -rhoE '#\[tokio::test(\([^)]*\))?\]' crates --include=*.rs | wc -l) | tr -d ' ')
TR_CASE=$( (cd "$WT" && grep -rhoE '#\[test_case' crates --include=*.rs | wc -l) | tr -d ' ')
TR_IGN=$( (cd "$WT" && grep -rhoE '^[[:space:]]*#\[ignore' crates --include=*.rs | wc -l) | tr -d ' ')
TR_ALL=$((TR_TEST + TR_TOKIO + TR_CASE))
emit PRE_FIX_TREE_TEST "$TR_TEST"
emit PRE_FIX_TREE_TOKIO "$TR_TOKIO"
emit PRE_FIX_TREE_CASE "$TR_CASE"
emit PRE_FIX_TREE_IGNORED "$TR_IGN"
emit PRE_FIX_TREE_ALL "$TR_ALL"
emit PRE_FIX_TOTAL_DRIFT "$([ "$CL_TEST" != "$TR_TEST" ] && echo 1 || echo 0)"
emit PRE_FIX_ALL_DRIFT "$([ "$CL_ALL" != "$TR_ALL" ] && echo 1 || echo 0)"

PAIR_DIFF=0; PAIR_NAMES=""
for c in wire orders crypto artifact index node net embed cli; do
  cl=$(grep -oE "\b$c [0-9]+" "$WF" | head -1 | awk '{print $2}'); cl=${cl:-none}
  ac=$( (cd "$WT" && grep -rhoE '#\[test\]' "crates/vecdht-$c" --include=*.rs | wc -l) | tr -d ' ')
  if [ "$cl" != "$ac" ]; then PAIR_DIFF=$((PAIR_DIFF + 1)); PAIR_NAMES="${PAIR_NAMES:+$PAIR_NAMES,}$c"; fi
done
emit PRE_FIX_PAIR_DIFF_COUNT "$PAIR_DIFF"
emit PRE_FIX_PAIR_DIFF_NAMES "${PAIR_NAMES:-none}"

# Приборы пина над деревом пина: drift обязан быть им невидим (иначе находка не про класс).
# Десять названных команд — те, чей предмет сам контур: подключение приборов, трубы отчётов,
# захват кода возврата, цитаты путей, карточки, реестры. По ним считается `PRE_FIX_PIN_INVISIBLE`.
# Ещё шесть прогнаны отдельным списком: без них «ни один из шестнадцати» было бы утверждением
# про десять. `check-secrets.sh` над деревом пина не прогоняется, и это названо: он читает всю
# историю (`git log -p --all`, 312 с на прогон) и не свёрстывает ни одного числа комментария,
# а его цена удваивается каждым из двух официальных прогонов.
# `check-date-domain.py` над деревом пина вызывается без флага `--require-git`: в откреплённом
# worktree история файла недоступна прибору (проверено: `DDF_GIT_EVIDENCE=0`, находка `blind`), и
# требовать доказательство там, где его не даёт носитель, значит краснить на контексте прогона, а не
# на дереве. На рабочем дереве тот же прибор вызывается с `--require-git`, как его зовёт контур.
runpin() { r=0; (cd "$WT" && eval "$1" >/dev/null 2>&1) || r=$?; printf '%s' "$r"; }
BATT=("python lab/check-guard-selftests.py" "python lab/check-contour-parity.py"
      "python lab/check-ci-report-greps.py check"
      "python lab/check-ci-rc-capture.py check --limit 30" "python lab/check-artifact-refs.py"
      "python lab/repo-review.py check" "python lab/check-status-claims.py"
      "python lab/check-claims.py" "python lab/check-contours.py" "python lab/check-oq-numbering.py")
RED=0; REDS=""
for c in "${BATT[@]}"; do
  f=$(printf '%s\n' "$c" | awk '{print $2}')
  [ "$(runpin "$c")" = 0 ] || { RED=$((RED + 1)); REDS="${REDS:+$REDS,}$f"; }
done
emit PRE_FIX_PIN_BATTERY_RED "$RED"
emit PRE_FIX_PIN_BATTERY_REDS "${REDS:-none}"
emit PRE_FIX_PIN_INVISIBLE "$([ "$RED" = 0 ] && echo 1 || echo 0)"

OTHER=("python lab/check-claim-map.py" "python lab/check-release-map.py"
       "python lab/check-date-domain.py check" "bash lab/check-release-kit.sh"
       "bash lab/check-spec-mirror.sh" "bash lab/check-text-clean.sh --all")
RED2=0; REDS2=""
for c in "${OTHER[@]}"; do
  f=$(printf '%s\n' "$c" | awk '{print $2}')
  [ "$(runpin "$c")" = 0 ] || { RED2=$((RED2 + 1)); REDS2="${REDS2:+$REDS2,}$f"; }
done
emit PRE_FIX_PIN_OTHER_RED "$RED2"
emit PRE_FIX_PIN_OTHER_REDS "${REDS2:-none}"
emit PRE_FIX_PIN_OTHER_INVISIBLE "$([ "$RED2" = 0 ] && echo 1 || echo 0)"
# Пятнадцать прогнанных из шестнадцати: счёт берётся из самих списков, а не из длины списка
# в памяти автора носителя.
emit PRE_FIX_PIN_RUN "$((${#BATT[@]} + ${#OTHER[@]}))"
emit PRE_FIX_PIN_SECRETS_SKIPPED 1

# Тот же drift новым прибором на дереве пина: красное, и каждое утверждение названо.
r=0; python lab/check-ci-numbers.py --root "$(win "$WT")" > "${SCR}pin-cin.log" 2>&1 || r=$?
emit PRE_FIX_NEW_ON_PIN_RC "$r"
emit PRE_FIX_NEW_ON_PIN_CLAIMS "$(grab "${SCR}pin-cin.log" CIN_CLAIMS)"
emit PRE_FIX_NEW_ON_PIN_MATCH "$(grab "${SCR}pin-cin.log" CIN_MATCH)"
emit PRE_FIX_NEW_ON_PIN_FINDINGS "$(grab "${SCR}pin-cin.log" CIN_FINDINGS)"
emit PRE_FIX_NEW_ON_PIN_DRIFT_COUNT "$(grab "${SCR}pin-cin.log" CIN_DRIFT_COUNT)"
emit PRE_FIX_NEW_ON_PIN_DEFINITION "$(grab "${SCR}pin-cin.log" CIN_DEFINITION)"
emit PRE_FIX_NEW_ON_PIN_TOTAL_TEST "$(grab "${SCR}pin-cin.log" CIN_TOTAL_TEST)"
# Одно определение, два исполнителя: bashliteral'ом по команде из шапки и прибор по своему обходу
# того же дерева пина. Расхождение = прибор сверяет не то, что обещает комментарий (фальсификатор (в)).
emit TREE_EQ_PIN_BASH "$([ "$TR_TEST" = "$(grab "${SCR}pin-cin.log" CIN_TOTAL_TEST)" ] && echo 1 || echo 0)"
DRIFT=$(grep -oE '^CIN_DRIFT=.*' "${SCR}pin-cin.log" | tail -1 | cut -d= -f2-)
D_CMD=$(printf '%s\n' "$DRIFT" | tr ';' '\n' | grep -c '^cmd:')
D_PAIR=$(printf '%s\n' "$DRIFT" | tr ';' '\n' | grep -c '^pair:')
D_DER=$(printf '%s\n' "$DRIFT" | tr ';' '\n' | grep -cEv '^(cmd|pair):')
emit PRE_FIX_NEW_ON_PIN_CMD "$D_CMD"
emit PRE_FIX_NEW_ON_PIN_PAIRS "$D_PAIR"
emit PRE_FIX_NEW_ON_PIN_DERIVED "$D_DER"
emit PRE_FIX_NEW_ON_PIN_TOKENS "$([ "$((D_CMD + D_PAIR + D_DER))" = "$(grab "${SCR}pin-cin.log" CIN_DRIFT_COUNT)" ] && echo 1 || echo 0)"
# Временное дерево пина больше не нужно, и оно обязано быть снято до шага 1: боевые факты круга
# снимаются с рабочего дерева, а `git status` с висячим worktree остался бы другим деревом.
git worktree remove --force "$WT" >/dev/null 2>&1 || true
git worktree prune >/dev/null 2>&1 || true
emit WT_REMOVED "$(git worktree list | grep -qF "$WT" && echo 0 || echo 1)"

# --- ШАГ 1: POST_FIX — рабочий корень и посадки прибора ------------------------------------------
r=0; python lab/check-ci-numbers.py > "${SCR}tree-cin.log" 2>&1 || r=$?
emit POST_FIX_TREE_RC "$r"
emit POST_FIX_TREE_FINDINGS "$(grab "${SCR}tree-cin.log" CIN_FINDINGS)"
emit POST_FIX_TREE_MATCH "$(grab "${SCR}tree-cin.log" CIN_MATCH)"
emit POST_FIX_TREE_CLAIMS "$(grab "${SCR}tree-cin.log" CIN_CLAIMS)"
emit POST_FIX_TREE_DRIFT_COUNT "$(grab "${SCR}tree-cin.log" CIN_DRIFT_COUNT)"
emit POST_FIX_TREE_DRIFT "$(grab "${SCR}tree-cin.log" CIN_DRIFT)"
emit POST_FIX_TREE_DEFINITION "$(grab "${SCR}tree-cin.log" CIN_DEFINITION)"
emit POST_FIX_TREE_UNKNOWN "$(grab "${SCR}tree-cin.log" CIN_UNKNOWN_COMMAND)"
emit POST_FIX_TREE_MISSING "$(grab "${SCR}tree-cin.log" CIN_BREAKDOWN_MISSING)"
emit POST_FIX_TREE_MULTIPLE "$(grab "${SCR}tree-cin.log" CIN_PAIR_MULTIPLE)"

r=0; python lab/check-ci-numbers.py --selftest > "${SCR}cin-st.log" 2>&1 || r=$?
emit CIN_SELFTEST_RC "$r"
emit PLANT_GREEN "$(grab "${SCR}cin-st.log" PLANTED_green_when_matching)"
emit PLANT_STALE "$(grab "${SCR}cin-st.log" PLANTED_stale_numbers_red)"
emit PLANT_MISSING "$(grab "${SCR}cin-st.log" PLANTED_missing_crate_red)"
emit PLANT_UNKNOWN "$(grab "${SCR}cin-st.log" PLANTED_unknown_command_red)"
emit PLANT_NODEF "$(grab "${SCR}cin-st.log" PLANTED_no_definition_red)"
emit PLANT_DUP "$(grab "${SCR}cin-st.log" PLANTED_duplicate_crate_red)"
emit PLANT_TARGET "$(grab "${SCR}cin-st.log" PLANTED_target_dir_skipped)"
emit CIN_SELFCASES "$(grab "${SCR}cin-st.log" CIN_SELFCASES)"
emit CIN_SELFPASSED "$(grab "${SCR}cin-st.log" CIN_SELFPASSED)"
emit CIN_SELFTEST "$(grab "${SCR}cin-st.log" CIN_SELFTEST)"

# Боевой вызов прибора в обоих контурах — иначе «прибор есть» не равно «прибор исполняется».
H=$(grep -E '^[[:space:]]*python lab/check-ci-numbers\.py' lab/workspace-verify.sh | grep -vc selftest)
C=$(grep -E '^[[:space:]]*python lab/check-ci-numbers\.py' .github/workflows/verify.yml | grep -vc selftest)
emit CIN_BATTLE_HOST "$H"
emit CIN_BATTLE_CI "$C"
emit CIN_WIRED_BOTH "$([ "$H" = 1 ] && [ "$C" = 1 ] && echo 1 || echo 0)"

# Истина дерева, которую печатает прибор (замораживается в пороге как боевой факт).
for k in TOTAL_TEST TOTAL_TOKIO TOTAL_CASE TOTAL_ALL IGNORED RS_FILES; do
  emit "TREE_$k" "$(grab "${SCR}tree-cin.log" "CIN_$k")"
done
for c in WIRE ORDERS CRYPTO ARTIFACT INDEX NODE NET EMBED CLI; do
  emit "TREE_CRATE_$c" "$(grab "${SCR}tree-cin.log" "CIN_CRATE_$c")"
done

# --- ШАГ 2: соседи и границы ---------------------------------------------------------------------
r=0; python lab/check-guard-selftests.py --selftest > "${SCR}gse-st.log" 2>&1 || r=$?
emit GSE_SELFTEST_CASES "$(grab "${SCR}gse-st.log" GSE_SELFTEST_CASES)"
emit GSE_SELFTEST_PASSED "$(grab "${SCR}gse-st.log" GSE_SELFTEST_PASSED)"
r=0; python lab/check-guard-selftests.py > "${SCR}gse.log" 2>&1 || r=$?
emit GSE_EXIT "$r"
emit GSE_GUARDS "$(grab "${SCR}gse.log" GSE_GUARDS)"
emit GSE_FINDINGS "$(grab "${SCR}gse.log" GSE_FINDINGS)"
LS_COUNT=$(ls lab/check-* | wc -l | tr -d ' ')
emit LS_CHECK_COUNT "$LS_COUNT"
emit GSE_GUARDS_MATCH_LS "$([ "$(grab "${SCR}gse.log" GSE_GUARDS)" = "$LS_COUNT" ] && echo 1 || echo 0)"

r=0; python lab/check-contour-parity.py > "${SCR}parity.log" 2>&1 || r=$?
emit PARITY_EXIT "$r"
emit PARITY_INSTRUMENTS "$(grabc "${SCR}parity.log" ПАРИТЕТ_ПРИБОРОВ)"
emit PARITY_FINDINGS "$(grabc "${SCR}parity.log" ПАРИТЕТ_НАХОДОК)"

r=0; python lab/check-artifact-refs.py > "${SCR}refs.log" 2>&1 || r=$?
emit REFS_EXIT "$r"
emit REFS_CITED "$(grab "${SCR}refs.log" REFS_CITED)"
emit REFS_MISSING "$(grab "${SCR}refs.log" REFS_MISSING)"
r=0; python lab/check-artifact-refs.py --selftest > "${SCR}refs-st.log" 2>&1 || r=$?
emit REFS_SELFTEST "$(grab "${SCR}refs-st.log" REFS_SELFTEST)"
emit REFS_EXTERNAL_DIR "$(grab "${SCR}refs-st.log" EXTERNAL_DIR)"
emit REFS_EXTERNAL_DIR_2 "$(grab "${SCR}refs-st.log" EXTERNAL_DIR_2)"

r=0; python lab/check-ci-report-greps.py check > "${SCR}crg.log" 2>&1 || r=$?
emit CRG_EXIT "$r"
r=0; python lab/check-ci-rc-capture.py check --limit 30 > "${SCR}rcc.log" 2>&1 || r=$?
emit RCC_EXIT "$r"
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
emit LINT_ORPHANS "$(grep -oE 'СИРОТ=[0-9]*' "${SCR}lint.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; python lab/check-claims.py > "${SCR}claims.log" 2>&1 || r=$?
emit CLAIMS_EXIT "$r"
r=0; python lab/check-contours.py > "${SCR}contours.log" 2>&1 || r=$?
emit CONTOURS_EXIT "$r"
r=0; python lab/check-oq-numbering.py > "${SCR}oq.log" 2>&1 || r=$?
emit OQ_EXIT "$r"
r=0; python lab/check-date-domain.py check --require-git > "${SCR}ddf.log" 2>&1 || r=$?
emit DDF_EXIT "$r"
r=0; bash lab/check-text-clean.sh --all > "${SCR}text.log" 2>&1 || r=$?
emit TEXTGUARD_ALL_EXIT "$r"
emit TEXTGUARD_ALL_DIRTY "$(grep -oE 'файлов_с_грязью=[0-9]*' "${SCR}text.log" | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; bash lab/check-text-clean.sh lab/check-ci-numbers.py lab/e0154-run.sh \
  lab/expectations/e0154.tsv .github/workflows/verify.yml lab/workspace-verify.sh \
  lab/hypotheses/H-0154-ci-comment-numbers.md lab/experiments/E-0154-ci-comment-numbers.md \
  > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"

emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ | wc -l | tr -d ' ')"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire/ | wc -l | tr -d ' ')"
emit SPEC_TOUCHED "$(git diff --name-only "$PIN" -- docs/VecDHT-SPEC-v8.md docs/VecDHT-SPEC-v9.md | wc -l | tr -d ' ')"
# Число без имён непроверяемо: в первом же прогоне `TOUCHED_OUTSIDE=1` не назвало файл, и
# остаётся только гадать. Носитель печатает то, что посчитал (правило «носитель печатает входы пересчёта»).
OUTSIDE_LIST=$(git diff --name-only "$PIN" | grep -Ev '^(lab/|\.github/|docs/PLAN-v1\.md$)' || true)
emit TOUCHED_OUTSIDE "$(printf '%s' "$OUTSIDE_LIST" | grep -c . )"
emit TOUCHED_OUTSIDE_NAMES "$(printf '%s' "$OUTSIDE_LIST" | paste -sd, - | grep . || echo none)"

bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_READABLE "$([ "$D" != none ] && echo 1 || echo 0)"

# --- ШАГ 3: вердикт по замороженной таблице ------------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
while IFS=$'\t' read -r k v _note; do
  case "$k" in ''|'#'*|STABLE|WORST_RC) continue;; esac
  want "$k" "$v"
done < lab/expectations/e0154.tsv
emit WORST_RC "$BAD"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0154-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
