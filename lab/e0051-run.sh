#!/usr/bin/env bash
# E-0051 (ADR-0013): приёмка v1-минимума предъявления. Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0051-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "########## E-0051 ·present· $(date -Is) ##########"; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test present_serving_gate -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"; grep -n "present" crates/vecdht-wire/src/messages.rs | head -6; grep -n "fn serve_request" crates/vecdht-node/src/session.rs; } | tee -a "$LOG"
run_cargo "КОНТРОЛЬ wire+node+net" cargo test -j 2 -p vecdht-wire -p vecdht-node -p vecdht-net
