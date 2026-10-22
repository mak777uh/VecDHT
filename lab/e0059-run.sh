#!/usr/bin/env bash
# E-0059: перерождение слота — второй lease после prune. Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0059-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0059 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test slot_rebirth_double_spend --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test slot_rebirth_double_spend -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"; echo "-- Key расхода включает issued_bucket:"; grep -n "struct Key" -A 8 crates/vecdht-node/src/rendezvous.rs; echo "-- consume: Expired ДО spent-проверки:"; grep -n "saturating_add(ttl_buckets)" -B 2 -A 12 crates/vecdht-node/src/rendezvous.rs | head -22; echo "-- spent-ключ (issuer, Key):"; grep -n "self.spent.insert" -B 2 -A 2 crates/vecdht-node/src/rendezvous.rs; } | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
