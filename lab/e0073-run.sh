#!/usr/bin/env bash
# E-0073: §10 — рестарт узла: WAL, снапшот, GC, lease и групповой коммит.
# Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0073-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0073 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test restart_recovery --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test restart_recovery -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- групповой коммит: константы и все употребления:"
  grep -rn "GROUP_COMMIT" crates
  echo "-- should_group_commit: определение и вызовы:"
  grep -rn "should_group_commit" crates
  echo "-- publish-путь узла: stage→commit на опс:"
  awk '/fn handle_publish/,/fn handle_replicate/' crates/vecdht-node/src/node.rs \
    | grep -nE "stage_insert|\.commit\(|should_group_commit|GROUP_COMMIT" || echo "   нет ни одного упоминания"
  echo "-- wall-clock в index/node:"
  grep -rnE "SystemTime|Instant::now" crates/vecdht-index/src crates/vecdht-node/src \
    || echo "   SystemTime/Instant отсутствуют"
  echo "-- wire не тронут (нет диффа):"
  git diff HEAD --stat -- crates/vecdht-wire
  echo "-- §10.2: обещание группового коммита:"
  grep -n "GROUP_COMMIT" docs/VecDHT-SPEC-v8.md
  echo "-- §10.5: crash-матрица остаётся юнит-тестом:"
  grep -n "#\[test\]" crates/vecdht-index/tests/crash_matrix.rs
  echo "-- исторические ignored в node-тестах:"
  grep -rn "#\[ignore" crates/vecdht-node/tests
  echo "-- оракул E-0073:"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/tests/restart_recovery.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
