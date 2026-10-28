#!/usr/bin/env bash
# Носитель круга H-0144: флаги фильтра у CLI — --class и --intent-dir.
#
# Порядок: (0) PRE_FIX пином — исходники через `git show` (флагов, `search_filtered`,
# `publish_with_attr` ноль) и замороженный снимок поведения `lab/logs/e0144-prefix.txt`;
# (1) гейт цикла и диск; (2) самопроверка стража статуса; (3) документ пина новым владельцем S-03 —
# обязан назвать ровно S-03 причиной `oracle-missing` (владельца строки в пине ещё нет);
# (4) рабочий документ — ноль; (5) носители: два теста `index_cmd` и два lib-прогона; (6) help-ручки
# собранного бинарника; (7) соседние стражи; (8) вердикт по названным условиям.
#
# Употребление: bash lab/e0144-run.sh [каталог-вывода]
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

PIN=$(git log --format=%H --grep="H-0144 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"

# --- ШАГ 0: PRE_FIX пином ---------------------------------------------------------------------
# `grep -c` печатает 0 и выходит с кодом 1; без этой ловушки ноль превращался в две строки
# «0» и «none» (ДИАГНОЗ-1). Значение у `emit` обязано быть ровно одним.
count_in_pin() { local n; n=$(git show "$PIN:$1" 2>/dev/null | grep -c -- "$2") || true; printf '%s' "${n:-none}"; }
emit PRE_FIX_FLAGS "$(count_in_pin crates/vecdht-cli/src/index_cmd.rs '"class"')"
emit PRE_FIX_INTENT "$(count_in_pin crates/vecdht-cli/src/index_cmd.rs '"intent-dir"')"
emit PRE_FIX_FILTER "$(count_in_pin crates/vecdht-cli/src/index_cmd.rs 'search_filtered')"
emit PRE_FIX_ATTR "$(count_in_pin crates/vecdht-index/src/store.rs 'publish_with_attr')"
PREFIX_LOG=lab/logs/e0144-prefix.txt
# Имя ключа — `index add`, а в снимке две строки про `--class` (add и search); поэтому строка
# ищется вместе с командой, иначе счётчик мерил бы не то, что назван ключом (ДИАГНОЗ-2).
emit PREFIX_LOG_ADD_CLASS "$(grep -c '`index add` не знает флага `--class`' "$PREFIX_LOG" 2>/dev/null || true)"
emit PREFIX_LOG_DIR_COLLISION "$(grep -c 'указан 2 раз' "$PREFIX_LOG" 2>/dev/null || echo none)"

# --- ШАГ 1: гейт и диск -----------------------------------------------------------------------
r=0; python lab/cycle-gate.py gate H-0144 > "${SCR}gate.log" 2>&1 || r=$?
emit GATE_H0144_OK "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

# --- ШАГ 2: самопроверка стража статуса --------------------------------------------------------
r=0; python lab/check-status-claims.py selftest > "${SCR}selftest.log" 2>&1 || r=$?
emit SELFTEST_EXIT "$r"
ST=$(grep -o 'СЕЛФТЕСТ_ИТОГ total=[0-9]* passed=[0-9]* failed=[0-9]*' "${SCR}selftest.log" | tail -1)
emit SELFTEST_TOTAL "$(printf '%s' "$ST" | sed -n 's/.*total=\([0-9]*\).*/\1/p' | grep . || echo none)"
emit SELFTEST_PASSED "$(printf '%s' "$ST" | sed -n 's/.*passed=\([0-9]*\).*/\1/p' | grep . || echo none)"

# --- ШАГ 3: документ пина на дереве пина -------------------------------------------------------
# Факты берутся из пина, а не из рабочего дерева: иначе закрытая карточка делает `S-03`
# согласованной и «до» перестаёт отличаться от «после» (ДИАГНОЗ-3). Дерево пина — отдельный
# worktree, снятый сразу после суда; рабочее дерево не трогается.
PIN_TREE="${SCR}pin-tree"
git worktree add --detach "$PIN_TREE" "$PIN" > "${SCR}worktree.log" 2>&1
r=0; python lab/check-status-claims.py --root "$PIN_TREE" --doc "$PIN_TREE/docs/STATUS-v1.md" \
  > "${SCR}prefix.log" 2>&1 || r=$?
git worktree remove --force "$PIN_TREE" >> "${SCR}worktree.log" 2>&1
emit CHK_PREFIX_EXIT "$r"
emit CHK_PREFIX_STALE "$(grab "${SCR}prefix.log" STATUS_STALE)"
emit CHK_PREFIX_IDS "$(grab "${SCR}prefix.log" STATUS_STALE_IDS)"
emit CHK_PREFIX_REASONS "$(grab "${SCR}prefix.log" STATUS_STALE_REASONS)"
for c in S01 S02 S03 S04; do emit "PRE_${c}" "$(grab "${SCR}prefix.log" "STATUS_${c}")"; done

# --- ШАГ 4: рабочий документ -------------------------------------------------------------------
r=0; python lab/check-status-claims.py > "${SCR}post.log" 2>&1 || r=$?
emit CHK_EXIT "$r"
emit CHK_STALE "$(grab "${SCR}post.log" STATUS_STALE)"
emit CHK_IDS "$(grab "${SCR}post.log" STATUS_STALE_IDS)"
emit CHK_CLAIMS "$(grab "${SCR}post.log" STATUS_CLAIMS)"
emit CHK_FACTS "$(grab "${SCR}post.log" STATUS_FACTS)"
emit CHK_FACTS_OK "$(grab "${SCR}post.log" STATUS_FACTS_OK)"
for c in S01 S02 S03 S04; do emit "POST_${c}" "$(grab "${SCR}post.log" "STATUS_${c}")"; done

# --- ШАГ 5: носители ---------------------------------------------------------------------------
r=0; cargo test -q -p vecdht-cli --lib index_cmd::tests::filters_are_stored_in_slot_attr_and_survive_reopen > "${SCR}filter.log" 2>&1 || r=$?
emit ORACLE_FILTER_EXIT "$r"
emit ORACLE_FILTER_PASSED "$(grep -o 'test result: ok\. [0-9]* passed' "${SCR}filter.log" | tail -1 | grep -o '[0-9]*' | head -1 || echo none)"
r=0; cargo test -q -p vecdht-cli --lib index_cmd::tests::any_filter_reproduces_the_unfiltered_answer > "${SCR}any.log" 2>&1 || r=$?
emit ORACLE_ANY_EXIT "$r"
emit ORACLE_ANY_PASSED "$(grep -o 'test result: ok\. [0-9]* passed' "${SCR}any.log" | tail -1 | grep -o '[0-9]*' | head -1 || echo none)"
r=0; cargo test -q -p vecdht-cli --lib > "${SCR}clilib.log" 2>&1 || r=$?
emit ORACLE_CLI_LIB_EXIT "$r"
r=0; cargo test -q -p vecdht-index --lib > "${SCR}indexlib.log" 2>&1 || r=$?
emit ORACLE_INDEX_LIB_EXIT "$r"

# --- ШАГ 6: help-ручки собранного бинарника ----------------------------------------------------
r=0; cargo build -q -p vecdht-cli > "${SCR}build.log" 2>&1 || r=$?
BIN=target/debug/vecdht-cli.exe
[ -x "$BIN" ] || BIN=target/debug/vecdht-cli
# Ключ означает «ручка видна оператору», а не «сколько раз строка встретилась»: help печатает имя
# флага и в тексте справки, и в сводке флагов, поэтому `grep -c` давал 2–3 при исправном коде.
has() { if "$BIN" help "$1" 2>/dev/null | grep -q -- "$2"; then echo 1; else echo 0; fi; }
emit HELP_ADD_CLASS "$([ "$r" -eq 0 ] && has "index add" '--class' || echo none)"
emit HELP_SEARCH_CLASS "$([ "$r" -eq 0 ] && has "index search" '--class' || echo none)"
emit HELP_ADD_INTENT "$([ "$r" -eq 0 ] && has "index add" '--intent-dir' || echo none)"
emit HELP_SEARCH_INTENT "$([ "$r" -eq 0 ] && has "index search" '--intent-dir' || echo none)"
emit DIR_IS_DIRECTORY "$([ "$r" -eq 0 ] && has "index create" '--dir DIR' || echo none)"

# --- ШАГ 7: соседние стражи --------------------------------------------------------------------
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
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' "${SCR}TEXTGUARD_ALL_EXIT.log" 2>/dev/null | tail -1 | cut -d= -f2 | grep . || echo none)"
r=0; bash lab/check-text-clean.sh lab/e0144-run.sh lab/expectations/e0144.tsv \
  lab/hypotheses/H-0144-cli-filters.md lab/experiments/E-0144-cli-filters.md \
  crates/vecdht-cli/src/index_cmd.rs crates/vecdht-index/src/store.rs \
  lab/check-status-claims.py docs/STATUS-v1.md > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"

# --- ШАГ 8: вердикт по названным условиям ------------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
want PIN_FOUND 1
want PRE_FIX_FLAGS 0
want PRE_FIX_INTENT 0
want PRE_FIX_FILTER 0
want PRE_FIX_ATTR 0
want PREFIX_LOG_ADD_CLASS 1
want PREFIX_LOG_DIR_COLLISION 1
want GATE_H0144_OK 1
want DISK_GE_15000 1
want SELFTEST_EXIT 0
want SELFTEST_TOTAL 13
want SELFTEST_PASSED 13
want CHK_PREFIX_EXIT 1
want CHK_PREFIX_STALE 1
want CHK_PREFIX_IDS S-03
want CHK_PREFIX_REASONS "S-03:oracle-missing"
want PRE_S01 consistent
want PRE_S02 consistent
want PRE_S03 stale
want PRE_S04 consistent
want CHK_EXIT 0
want CHK_STALE 0
want CHK_IDS none
want CHK_CLAIMS 4
want CHK_FACTS 9
want CHK_FACTS_OK 9
want POST_S03 consistent
want ORACLE_FILTER_EXIT 0
want ORACLE_FILTER_PASSED 1
want ORACLE_ANY_EXIT 0
want ORACLE_ANY_PASSED 1
want ORACLE_CLI_LIB_EXIT 0
want ORACLE_INDEX_LIB_EXIT 0
want HELP_ADD_CLASS 1
want HELP_SEARCH_CLASS 1
want HELP_ADD_INTENT 1
want HELP_SEARCH_INTENT 1
want DIR_IS_DIRECTORY 1
want SECRETS_EXIT 0
want REFS_EXIT 0
want CLAIMMAP_EXIT 0
want CLAIMS_EXIT 0
want CONTOURS_EXIT 0
want MIRROR_EXIT 0
want GATE_AUDIT_EXIT 0
want REVIEW_EXIT 0
want LINT_LATEST_EXIT 0
want LINT_ORPHANS 0
want TEXTGUARD_ALL_EXIT 0
want TEXTGUARD_ALL_DIRTY 0
want TEXTGUARD_CYCLE_EXIT 0
want RUST_TOUCHED 2
emit WORST_RC "$BAD"

# Повторяемость: снимок ключуется HEAD'ом и грязью дерева; диск и сам `STABLE` не сравниваются.
# Первое исполнение печатает `STABLE=none`.
# Ключ обязан меняться от правки содержимого, а не только от списка грязных путей: иначе
# «неизменное дерево» склеивается с прежней попыткой на тех же путях (ДИАГНОЗ-4).
TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0144-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
