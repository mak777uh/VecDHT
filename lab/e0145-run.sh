#!/usr/bin/env bash
# Носитель круга H-0145: circuit relay v2 — контур проводит прикладной handshake.
#
# Порядок: (0) PRE_FIX пином — исходники через `git show` (фичи `relay`, полей `relay_client`/
# `relay_server`, метода `reserve_circuit`, счётчиков и теста ноль); (1) гейт цикла и диск;
# (2) продукт получил механизм (grep по рабочим файлам); (3) носитель — два теста контура на
# настоящем QUIC; (4) соседние стражи; (5) вердикт по названным условиям.
#
# Употребление: bash lab/e0145-run.sh [каталог-вывода]
set -uo pipefail
cd "$(dirname "$0")/.."

SCR=$(mktemp -d)/
OUT=${1:-$SCR}
mkdir -p "$OUT"
FACTS="${OUT}facts.txt"
: > "$FACTS"

emit() { printf '%s=%s\n' "$1" "$2" | tee -a "$FACTS"; }
# Факт напечатан тестом как `МЕРЕНО <ключ>=<значение>`; якорь обязан допускать префикс,
# иначе все значения выходят `none` при зелёном тесте (ДИАГНОЗ-1 этого цикла).
grab() { v=$(grep -oE "(^|[[:space:]])$2=[0-9A-Za-z/.,:%;_-]*" "$1" 2>/dev/null | tail -1 | sed 's/.*=//'); [ -n "$v" ] && printf '%s' "$v" || printf 'none'; }

PIN=$(git log --format=%H --grep="H-0145 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "$PIN" ] && echo 1 || echo 0)"

# --- ШАГ 0: PRE_FIX пином ---------------------------------------------------------------------
# `grep -c` печатает 0 и выходит с кодом 1; без ловушки ноль превращался бы в две строки.
count_in_pin() { local n; n=$(git show "$PIN:$1" 2>/dev/null | grep -c -- "$2") || true; printf '%s' "${n:-none}"; }
emit PRE_FIX_RELAY_FEATURE "$(count_in_pin Cargo.toml '"relay"')"
emit PRE_FIX_RELAY_FIELD "$(count_in_pin crates/vecdht-net/src/behaviour.rs 'relay_client')"
emit PRE_FIX_RESERVE "$(count_in_pin crates/vecdht-net/src/service.rs 'reserve_circuit')"
emit PRE_FIX_RELAY_STATS "$(count_in_pin crates/vecdht-net/src/service.rs 'relay_stats')"
if git cat-file -e "$PIN:crates/vecdht-net/tests/s163_relay_circuit.rs" 2>/dev/null; then
  emit PRE_FIX_TEST 1
else
  emit PRE_FIX_TEST 0
fi

# --- ШАГ 1: гейт и диск -----------------------------------------------------------------------
r=0; python lab/cycle-gate.py gate H-0145 > "${SCR}gate.log" 2>&1 || r=$?
emit GATE_H0145_OK "$([ "$r" -eq 0 ] && echo 1 || echo 0)"
bash lab/disk-report.sh > "${SCR}disk.log" 2>&1
D=$(grab "${SCR}disk.log" DISK_FREE_MB)
emit DISK_FREE_MB "$D"
emit DISK_GE_15000 "$([ "$D" != none ] && [ "$D" -ge 15000 ] 2>/dev/null && echo 1 || echo 0)"

# --- ШАГ 2: продукт получил механизм ----------------------------------------------------------
has_in() { local n; n=$(grep -c -- "$2" "$1" 2>/dev/null) || true; printf '%s' "${n:-none}"; }
emit RELAY_FEATURE "$(has_in Cargo.toml '"relay"')"
emit RELAY_CLIENT_FIELD "$(has_in crates/vecdht-net/src/behaviour.rs 'pub relay_client')"
emit RELAY_SERVER_FIELD "$(has_in crates/vecdht-net/src/behaviour.rs 'pub relay_server')"
emit RESERVE_CIRCUIT "$(has_in crates/vecdht-net/src/service.rs 'pub fn reserve_circuit')"
emit RELAY_STATS "$(has_in crates/vecdht-net/src/service.rs 'pub fn relay_stats')"

# --- ШАГ 3: носитель --------------------------------------------------------------------------
LOG="${SCR}oracle.log"
r=0; cargo test -q -p vecdht-net --test s163_relay_circuit -- --nocapture --test-threads=1 \
  > "$LOG" 2>&1 || r=$?
emit ORACLE_EXIT "$r"
emit ORACLE_PASSED "$(grep -o 'test result: ok\. [0-9]* passed' "$LOG" | tail -1 | sed -n 's/.*ok\. \([0-9]*\) passed/\1/p' | grep . || echo none)"
emit ORACLE_FAILED "$(grep -o '[0-9]* failed' "$LOG" | tail -1 | grep -o '^[0-9]*' || echo none)"
for k in target_direct_listeners \
  positive_server_reservations positive_server_circuits positive_target_reservations \
  positive_client_reservations positive_client_circuits \
  positive_auth_client_to_target positive_auth_target_to_client \
  positive_relay_auth_target positive_relay_auth_client positive_target_door_refusals \
  negative_server_reservations negative_server_circuits negative_target_reservations \
  negative_auth_client_to_target; do
  emit "$k" "$(grab "$LOG" "$k")"
done

# --- ШАГ 4: соседние стражи -------------------------------------------------------------------
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
r=0; bash lab/check-text-clean.sh lab/e0145-run.sh lab/expectations/e0145.tsv \
  lab/hypotheses/H-0145-relay-circuit.md lab/experiments/E-0145-relay-circuit.md \
  crates/vecdht-net/src/behaviour.rs crates/vecdht-net/src/service.rs \
  crates/vecdht-net/tests/s163_relay_circuit.rs > "${SCR}textcycle.log" 2>&1 || r=$?
emit TEXTGUARD_CYCLE_EXIT "$r"
emit WIRE_TOUCHED "$(git diff --name-only "$PIN" -- crates/vecdht-wire 2>/dev/null | wc -l | tr -d ' ')"
emit RUST_TOUCHED "$(git diff --name-only "$PIN" -- crates/ 2>/dev/null | wc -l | tr -d ' ')"
emit LOCK_TOUCHED "$(git diff --name-only "$PIN" -- Cargo.lock 2>/dev/null | wc -l | tr -d ' ')"

# --- ШАГ 5: вердикт по названным условиям -----------------------------------------------------
get() { grep -h "^$1=" "$FACTS" | tail -1 | cut -d= -f2; }
BAD=0
bad() { BAD=$((BAD + 1)); printf 'УСЛОВИЕ_НАРУШЕНО %s: ожидалось %s, получено %s\n' "$1" "$2" "$(get "$1")" >&2; }
want() { [ "$(get "$1")" = "$2" ] || bad "$1" "$2"; }
want PIN_FOUND 1
want PRE_FIX_RELAY_FEATURE 0
want PRE_FIX_RELAY_FIELD 0
want PRE_FIX_RESERVE 0
want PRE_FIX_RELAY_STATS 0
want PRE_FIX_TEST 0
want GATE_H0145_OK 1
want DISK_GE_15000 1
want RELAY_FEATURE 1
want RELAY_CLIENT_FIELD 1
want RELAY_SERVER_FIELD 1
want RESERVE_CIRCUIT 1
want RELAY_STATS 1
want ORACLE_EXIT 0
want ORACLE_PASSED 2
want ORACLE_FAILED 0
want target_direct_listeners 0
want positive_server_reservations 1
want positive_server_circuits 1
want positive_target_reservations 1
want positive_client_reservations 0
want positive_client_circuits 1
want positive_auth_client_to_target 1
want positive_auth_target_to_client 1
want positive_relay_auth_target 1
want positive_relay_auth_client 1
want positive_target_door_refusals 0
want negative_server_reservations 0
want negative_server_circuits 0
want negative_target_reservations 0
want negative_auth_client_to_target 0
want WIRE_TOUCHED 0
want RUST_TOUCHED 3
want LOCK_TOUCHED 1
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
emit WORST_RC "$BAD"

# Повторяемость: снимок ключуется HEAD'ом и содержимым грязного дерева; диск и сам `STABLE`
# не сравниваются. Первое исполнение печатает `STABLE=none`, второе — `1`.
TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$({ git status --porcelain 2>/dev/null; git diff HEAD 2>/dev/null; } | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0145-${TREE_KEY}.facts"
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$FACTS") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$FACTS" > "$SNAP"
if [ "$BAD" -ne 0 ]; then exit 1; fi
