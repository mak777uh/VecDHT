#!/usr/bin/env bash
# E-0066: живое разделение §9.8 — смещённый primary не подтверждает и не навязывает запись.
# Helper исполняет команду целиком (урок e0049), логи append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0066-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0066 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test live_split_brain_fencing --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test live_split_brain_fencing -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- реплика принимает ReplicateOp только от primary СВОЕЙ эпохи:"
  grep -n "m.epoch() == op.epoch" -B 5 -A 5 crates/vecdht-node/src/node.rs
  echo "-- ack доверяется только своей эпохе и члену состава:"
  grep -n "m.epoch() == ack.epoch && m.is_member" -B 3 -A 4 crates/vecdht-node/src/node.rs
  echo "-- грант прошлой эпохи → EPOCH_STALE:"
  grep -n "EPOCH_STALE" -B 4 -A 2 crates/vecdht-node/src/node.rs
  echo "-- serving_epoch = lease + durable-маркер:"
  grep -n "fn serving_epoch\|fn durable_epoch" -A 10 crates/vecdht-node/src/node.rs
  echo "-- уже покрытые гейты P4 (не перемеряются):"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/tests/gates_p4.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
