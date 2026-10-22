#!/usr/bin/env bash
# E-0053: композиция clamp'а и потолка lease-таблицы. Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0053-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0053 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test ceiling_clamp_compose --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test ceiling_clamp_compose -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"; echo "-- clamp до поиска:"; grep -n "top_k as usize" crates/vecdht-node/src/node.rs; echo "-- идемпотность до потолка:"; grep -n "seen.contains\|live >= self.cap\|refused_full += 1" crates/vecdht-node/src/rendezvous.rs; echo "-- цикл выпуска по matches:"; grep -n "for m in &res.matches" crates/vecdht-node/src/node.rs; } | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
