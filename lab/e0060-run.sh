#!/usr/bin/env bash
# E-0060: полный набор проверок consume и порядок (§12.3). Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0060-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0060 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test ttl_policy_order --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test ttl_policy_order -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"; echo "-- порядок проверок consume:"; grep -n "verify_body\|acc.target != \*me\|ttl_sec == 0\|AcceptError::Expired\|spent.insert" crates/vecdht-node/src/rendezvous.rs | head; echo "-- цитата спеки о порядке:"; grep -n "Полный набор проверок" docs/VecDHT-SPEC-v8.md; } | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
