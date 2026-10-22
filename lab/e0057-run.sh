#!/usr/bin/env bash
# E-0057: постепенное снятие потолка строками разных бакетов. Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0057-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0057 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test ceiling_gradual_prune --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test ceiling_gradual_prune -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"; echo "-- Key включает issued_bucket, prune чистит seen:"; grep -n "struct Key" -A 8 crates/vecdht-node/src/rendezvous.rs; grep -n "seen.remove" crates/vecdht-node/src/rendezvous.rs; echo "-- порядок issue(): prune -> seen -> cap:"; grep -n "self.prune(now_bucket)" -A 10 crates/vecdht-node/src/rendezvous.rs | head -14; echo "-- арифметика бакетов:"; grep -n "pub const fn buckets" -A 3 crates/vecdht-node/src/config.rs; } | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
