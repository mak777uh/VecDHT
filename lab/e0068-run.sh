#!/usr/bin/env bash
# E-0068: ADR-0016 — LeaseGrant привязан к принятой эпохе и primary членства.
# Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0068-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0068 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test lease_membership_binding --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test lease_membership_binding -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- грант будущей эпохи отвергается в Lease::verify (ADR-0016):"
  grep -n "LeaseError::Future" -B 4 -A 2 crates/vecdht-node/src/lease.rs
  echo "-- handle_lease_grant сверяет primary принятого состава:"
  grep -n "mine != Some(lease.primary)" -B 12 -A 4 crates/vecdht-node/src/node.rs
  echo "-- старый оракул E-0067 остаётся историческим и игнорируется:"
  grep -n "#\[ignore" -A 2 crates/vecdht-node/tests/future_epoch_lease_freeze.rs
  echo "-- юнит-тест Future:"
  grep -n "a_lease_from_the_future_is_not_adopted" -A 12 crates/vecdht-node/src/lease.rs
  echo "-- спека §9.8 (ADR-0016) в рабочем дереве:"
  grep -n "LeaseGrant.*действует только на уже принятую эпоху" docs/VecDHT-SPEC-v8.md
  echo "-- уже покрытые lease-тесты (не перемеряются):"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/src/lease.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
