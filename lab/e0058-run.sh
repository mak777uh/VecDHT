#!/usr/bin/env bash
# E-0058: окно расхода post-prune приёма. Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0058-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0058 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test post_prune_spend_window --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test post_prune_spend_window -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"; echo "-- Issuer::prune (cutoff = now - ttl_buckets):"; grep -n "fn prune" -A 6 crates/vecdht-node/src/rendezvous.rs | head -10; echo "-- Spend::consume (Expired при now > issued + buckets(ttl)):"; grep -n "saturating_add(ttl_buckets)" -B 3 -A 2 crates/vecdht-node/src/rendezvous.rs; echo "-- expires памяти расхода (+1 к грани):"; grep -n "let expires" -A 2 crates/vecdht-node/src/rendezvous.rs; } | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
