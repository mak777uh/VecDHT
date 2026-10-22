#!/usr/bin/env bash
# E-0067: грант lease будущей эпохи — заморозка шарда чужим expires.
# Helper исполняет команду целиком (урок e0049), логи append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0067-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0067 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test future_epoch_lease_freeze --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test future_epoch_lease_freeze -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- Lease::verify отвергает только epoch < have:"
  grep -n "if let Some(have) = have_epoch" -A 5 crates/vecdht-node/src/lease.rs
  echo "-- handle_lease_grant: самосогласованность ключа, затем self.lease = Some(lease):"
  grep -n "fn handle_lease_grant" -A 24 crates/vecdht-node/src/node.rs
  echo "-- lease_active требует равенства эпох:"
  grep -n "pub fn lease_active" -A 8 crates/vecdht-node/src/node.rs
  echo "-- should_propose берёт base из lease.expires_at_bucket:"
  grep -n "fn should_propose" -A 34 crates/vecdht-node/src/node.rs
  echo "-- tick входит в продление только при lease_active:"
  grep -n "pub fn tick" -A 22 crates/vecdht-node/src/node.rs
  echo "-- уже покрытые юнит-тесты Lease (не перемеряются):"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/src/lease.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
