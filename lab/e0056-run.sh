#!/usr/bin/env bash
# E-0056: дыра lease-таблицы после prune по TTL. Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0056-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0056 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test ceiling_prune_recovery --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test ceiling_prune_recovery -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"; echo "-- Issuer::prune (cutoff по бакетам, checked_sub):"; grep -n "fn prune" -A 10 crates/vecdht-node/src/rendezvous.rs | head -32; echo "-- арифметика бакетов:"; grep -n "pub const fn buckets" -A 3 crates/vecdht-node/src/config.rs; echo "-- TTL из Params:"; grep -n "rendezvous_ttl" crates/vecdht-node/src/config.rs | head -6; echo "-- ttl_buckets узла:"; grep -rn "ttl_buckets" crates/vecdht-node/src/node.rs | head -6; } | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
