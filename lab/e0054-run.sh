#!/usr/bin/env bash
# E-0054: путь обслуживания ADR-0013 поверх ротации эпохи. Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0054-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0054 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test rotation_present_serving --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test rotation_present_serving -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"; echo "-- цикл serve_request:"; sed -n '/for issuer in issuers/,/^    }/p' crates/vecdht-node/src/session.rs; echo "-- consume: подпись до расхода:"; grep -n "fn consume" -A 22 crates/vecdht-node/src/rendezvous.rs | head -30; } | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
