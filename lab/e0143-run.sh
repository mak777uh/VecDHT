#!/usr/bin/env bash
# Носитель круга H-0143: статус-документ против дерева.
#
# Порядок: (0) PRE_FIX «отсутствием» — прибора в пине нет, `git show` во временный каталог;
# (1) гейт цикла и диск; (2) самопроверка прибора на посаженных случаях; (3) прибор по документу
# пина (`--doc`, файл из `git show`, рабочее дерево не трогается) — обязан назвать ровно три
# расхождения; (4) прибор по рабочему документу — ноль; (5) носители утверждений — два файла
# исполняемых тестов; (6) соседние стражи; (7) вердикт по названным условиям.
#
# Ключи `CHK_*` печатает сам прибор; здесь они перепечатываются через `grab`, чтобы у носителя
# была одна форма и её читал `lab/expect.py`. `PRE_FIX_STALE=none` — не «ноль расхождений», а
# «прибора нет»: пустое множество печатается словом `none`.
#
# Вердикт считает не «все ключи равны нулю»: `CHK_PREFIX_EXIT` обязан быть 1, `PRE_FIX_INSTRUMENT` —
# 0, а `CHK_PREFIX_IDS` — ровно `S-01,S-02,S-04`. Условия названы по одному, как в карточке.
#
# Употребление: bash lab/e0143-run.sh [каталог-вывода]
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

SCR=$(mktemp -d)/
OUT=${1:-$SCR}
mkdir -p "$OUT"
FACTS="${OUT}facts.txt"
: > "$FACTS"

emit() { printf '%s=%s\n' "$1" "$2" | tee -a "$FACTS"; }
grab() { v=$(grep -o "^$2=[0-9A-Za-z/.,:%;_-]*" "$1" 2>/dev/null | tail -1 | cut -d= -f2); [ -n "$v" ] && printf '%s' "$v" || printf 'none'; }

PIN=$(git log --format=%H --grep="H-0143 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"

# --- ШАГ 0: PRE_FIX отсутствием ------------------------------------------------------------
PRE_INSTRUMENT=0
PRE_STALE=none
PRE_KEYS=0
if [ -n "$PIN" ] && git cat-file -e "$PIN:lab/check-status-claims.py" 2>/dev/null; then
  git show "$PIN:lab/check-status-claims.py" > "${SCR}chk-pin.py"
  PRE_INSTRUMENT=1
  git show "$PIN:docs/STATUS-v1.md" > "${SCR}status-pin-pre.md"
  python "${SCR}chk-pin.py" --root "$ROOT" --doc "${SCR}status-pin-pre.md" > "${SCR}pre-pin.log" 2>&1
  PRE_STALE=$(grab "${SCR}pre-pin.log" STATUS_STALE)
  PRE_KEYS=$(grep -c '^STATUS_[A-Za-z0-9_]*=' "${SCR}pre-pin.log" || true)
fi
emit PRE_FIX_INSTRUMENT "$PRE_INSTRUMENT"
emit PRE_FIX_STALE "$PRE_STALE"
emit PRE_FIX_KEYS "$PRE_KEYS"

# --- ШАГ 1: гейт и диск ----------------------------------------------------------------------
r=0; python lab/cycle-gate.py gate H-0143 > "${SCR}gate.log" 2>&1 || r=$?
emit GATE_H0143_OK "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

# --- ШАГ 2: самопроверка прибора ------------------------------------------------------------
r=0; python lab/check-status-claims.py selftest > "${SCR}selftest.log" 2>&1 || r=$?
emit SELFTEST_EXIT "$r"
ST=$(grep -o 'СЕЛФТЕСТ_ИТОГ total=[0-9]* passed=[0-9]* failed=[0-9]*' "${SCR}selftest.log" | tail -1)
emit SELFTEST_TOTAL "$(printf '%s' "$ST" | sed -n 's/.*total=\([0-9]*\).*/\1/p' | grep . || echo none)"
emit SELFTEST_PASSED "$(printf '%s' "$ST" | sed -n 's/.*passed=\([0-9]*\).*/\1/p' | grep . || echo none)"

# --- ШАГ 3: документ пина ---------------------------------------------------------------------
git show "$PIN:docs/STATUS-v1.md" > "${SCR}status-pin.md"
r=0; python lab/check-status-claims.py --doc "${SCR}status-pin.md" > "${SCR}prefix.log" 2>&1 || r=$?
emit CHK_PREFIX_EXIT "$r"
emit CHK_PREFIX_DOC_PRESENT "$([ -s "${SCR}status-pin.md" ] && echo 1 || echo 0)"
emit CHK_PREFIX_STALE "$(grab "${SCR}prefix.log" STATUS_STALE)"
emit CHK_PREFIX_CONSISTENT "$(grab "${SCR}prefix.log" STATUS_CONSISTENT)"
emit CHK_PREFIX_IDS "$(grab "${SCR}prefix.log" STATUS_STALE_IDS)"
emit CHK_PREFIX_REASONS "$(grab "${SCR}prefix.log" STATUS_STALE_REASONS)"
for c in S01 S02 S03 S04; do emit "PRE_${c}" "$(grab "${SCR}prefix.log" "STATUS_${c}")"; done

# --- ШАГ 4: рабочий документ ------------------------------------------------------------------
r=0; python lab/check-status-claims.py > "${SCR}post.log" 2>&1 || r=$?
emit CHK_EXIT "$r"
emit CHK_OK "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
emit CHK_DOC "$(grab "${SCR}post.log" STATUS_DOC)"
emit CHK_CLAIMS "$(grab "${SCR}post.log" STATUS_CLAIMS)"
emit CHK_CONSISTENT "$(grab "${SCR}post.log" STATUS_CONSISTENT)"
emit CHK_STALE "$(grab "${SCR}post.log" STATUS_STALE)"
emit CHK_IDS "$(grab "${SCR}post.log" STATUS_STALE_IDS)"
emit CHK_FACTS "$(grab "${SCR}post.log" STATUS_FACTS)"
emit CHK_FACTS_OK "$(grab "${SCR}post.log" STATUS_FACTS_OK)"
emit CHK_FACTS_MISSING "$(grab "${SCR}post.log" STATUS_FACTS_MISSING)"
for c in S01 S02 S03 S04; do emit "POST_${c}" "$(grab "${SCR}post.log" "STATUS_${c}")"; done

# --- ШАГ 5: носители утверждений ---------------------------------------------------------------
r=0; cargo test -q -p vecdht-cli --test node_centroids > "${SCR}oracle-centroids.log" 2>&1 || r=$?
emit ORACLE_NODE_CENTROIDS_EXIT "$r"
emit ORACLE_NODE_CENTROIDS_PASSED "$(grep -o 'test result: ok\. [0-9]* passed' "${SCR}oracle-centroids.log" | tail -1 | grep -o '[0-9]*' | head -1 || echo none)"
r=0; cargo test -q -p vecdht-cli --test node_run > "${SCR}oracle-noderun.log" 2>&1 || r=$?
emit ORACLE_NODE_RUN_EXIT "$r"
emit ORACLE_NODE_RUN_PASSED "$(grep -o 'test result: ok\. [0-9]* passed' "${SCR}oracle-noderun.log" | tail -1 | grep -o '[0-9]*' | head -1 || echo none)"
if [ "$r" -eq 0 ] && grep -q 'test result: ok\. 2 passed' "${SCR}oracle-centroids.log" 2>/dev/null \
   && grep -q 'test result: ok\. 3 passed' "${SCR}oracle-noderun.log" 2>/dev/null; then
  emit ORACLE_TESTS_OK 1
else
  emit ORACLE_TESTS_OK 0
fi
emit CI_STATUS_STEP "$([ "$(grep -c 'check-status-claims\.py' .github/workflows/verify.yml || true)" -ge 1 ] && echo 1 || echo 0)"

# --- ШАГ 6: соседние стражи --------------------------------------------------------------------
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
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'ГРЯЗНЫХ=[0-9]*' "${SCR}TEXTGUARD_ALL_EXIT.log" 2>/dev/null | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; bash lab/check-text-clean.sh lab/check-status-claims.py lab/e0143-run.sh \
  lab/expectations/e0143.tsv lab/hypotheses/H-0143-status-claims.md \
  lab/experiments/E-0143-status-claims.md > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"

# --- ШАГ 7: вердикт по названным условиям -------------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
want PRE_FIX_INSTRUMENT 0
want PIN_FOUND 1
want GATE_H0143_OK 1
want DISK_GE_15000 1
want SELFTEST_EXIT 0
want SELFTEST_TOTAL 13
want SELFTEST_PASSED 13
want CHK_PREFIX_EXIT 1
want CHK_PREFIX_DOC_PRESENT 1
want CHK_PREFIX_STALE 3
want CHK_PREFIX_CONSISTENT 1
want CHK_PREFIX_IDS "S-01,S-02,S-04"
want CHK_PREFIX_REASONS "S-01:doc-contradicts,S-02:doc-contradicts,S-04:doc-contradicts"
want PRE_S01 stale
want PRE_S02 stale
want PRE_S03 consistent
want PRE_S04 stale
want CHK_EXIT 0
want CHK_OK 1
want CHK_DOC docs/STATUS-v1.md
want CHK_CLAIMS 4
want CHK_CONSISTENT 4
want CHK_STALE 0
want CHK_IDS none
want CHK_FACTS_MISSING none
want POST_S01 consistent
want POST_S02 consistent
want POST_S03 consistent
want POST_S04 consistent
want ORACLE_NODE_CENTROIDS_EXIT 0
want ORACLE_NODE_CENTROIDS_PASSED 2
want ORACLE_NODE_RUN_EXIT 0
want ORACLE_NODE_RUN_PASSED 3
want ORACLE_TESTS_OK 1
want CI_STATUS_STEP 1
want SECRETS_EXIT 0
want REFS_EXIT 0
want CLAIMMAP_EXIT 0
want CLAIMS_EXIT 0
want CONTOURS_EXIT 0
want TEXTGUARD_ALL_EXIT 0
want TEXTGUARD_CYCLE_EXIT 0
want MIRROR_EXIT 0
want LINT_LATEST_EXIT 0
want GATE_AUDIT_EXIT 0
want REVIEW_EXIT 0
want RUST_TOUCHED 0
[ "$(get CHK_FACTS)" = "$(get CHK_FACTS_OK)" ] || bad CHK_FACTS_OK "равно CHK_FACTS"
emit WORST_RC "$BAD"

# Повторяемость: снимок фактов ключуется HEAD'ом и грязью дерева; диск и сам `STABLE` не входят
# в то, что вердикт сверяет (довод `E-0141`). Первое исполнение печатает `STABLE=none`.
TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0143-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
