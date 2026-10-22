#!/usr/bin/env bash
# E-0069: heal-окно §9.8 — когда старый primary принимает подписанную эпоху, а когда нет.
# Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0069-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0069 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test heal_demotion_window --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test heal_demotion_window -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- peer_alive/peer_reachable в коде (ожидается пусто, порог 5):"
  grep -rn "peer_alive\|peer_reachable" crates/vecdht-node/src crates/vecdht-net/src || echo "НЕТ НИ ОДНОГО"
  echo "-- unreachable пишется только в peer_lost и чистится только в adopt:"
  grep -n "unreachable.push\|unreachable.retain\|unreachable:" crates/vecdht-node/src/node.rs
  echo "-- handle_membership: MembersOutOfOrder и прочие Err гасятся молча:"
  grep -n "validate_with_candidates" -A 14 crates/vecdht-node/src/node.rs
  echo "-- ожидание состава считается по ЛОКАЛЬНОМУ live_roster:"
  grep -n "fn live_roster" -A 12 crates/vecdht-node/src/node.rs
  grep -n "fn excluded" -A 10 crates/vecdht-node/src/node.rs
  echo "-- откуда рассылается MembershipUpdate (только propose/adopt/ниже-порог):"
  grep -n "broadcast_membership" crates/vecdht-node/src/node.rs
  echo "-- обещание §9.8 в рабочем дереве:"
  grep -n "Старые primary после resurrect" docs/VecDHT-SPEC-v8.md
  echo "-- уже покрытые соседние тесты (не перемеряются):"
  grep -n "#\[test\]\|#\[ignore" -A 1 crates/vecdht-node/tests/lease_membership_binding.rs crates/vecdht-node/tests/future_epoch_lease_freeze.rs | head -20
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
