#!/usr/bin/env bash
# E-0072: §9.4 — read у любой реплики W=2/R=3: расхождение, read-repair, смена эпизоды.
# Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0072-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0072 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test w2r3_stale_read --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test w2r3_stale_read -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- R4: Find не ремонтирует (окно handle_find):"
  awk '/fn handle_find/,/fn handle_pull_request/' crates/vecdht-node/src/node.rs \
    | grep -nE "pull_request|replicate\(|SnapshotOffer" || echo "   нет вызовов ремонта"
  echo "-- pull_request: определение и все вызовы:"
  grep -n "pull_request" crates/vecdht-node/src/node.rs
  echo "-- gossip-триггер догона:"
  grep -rn "heard_wal_seq" crates || echo "   heard_wal_seq отсутствует"
  echo "-- anti-entropy в adopt:"
  grep -n "Догоняемся с нового primary" -B 3 -A 3 crates/vecdht-node/src/node.rs
  echo "-- wire не тронут (нет диффа):"
  git diff HEAD --stat -- crates/vecdht-wire
  echo "-- §9.4: обещание read-repair в рабочем дереве:"
  grep -n "read-repair" docs/VecDHT-SPEC-v8.md
  echo "-- оракул E-0072:"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/tests/w2r3_stale_read.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
