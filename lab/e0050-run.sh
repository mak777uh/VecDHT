#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS=2
LOG=lab/logs/e0050-all.log
run_cargo() { # $1=label; rest=полная команда (cargo ...); коды rc — настоящие
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0050 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -p vecdht-node --test epoch_rotation_accept --no-run -j 2
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test epoch_rotation_accept -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"; echo "-- epoch в rendezvous.rs:"; grep -c "epoch" crates/vecdht-node/src/rendezvous.rs || true; echo "-- гейт роли на find-пути:"; grep -n "is_primary" crates/vecdht-node/src/node.rs | head -6; echo "-- кадры приёма (полей эпохи нет):"; grep -n "pub struct RendezvousAccept" -A 8 crates/vecdht-wire/src/messages.rs; } | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -p vecdht-node -j 2
