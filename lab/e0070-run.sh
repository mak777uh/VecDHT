#!/usr/bin/env bash
# E-0070: ADR-0017 — heal в один шаг (peer_alive, анти-энтропия цепочки, демоция
# исключающей цепочкой). Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0070-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0070 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test heal_one_step --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test heal_one_step -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- R1: peer_alive в узле:"
  grep -n "pub fn peer_alive" -A 8 crates/vecdht-node/src/node.rs
  echo "-- R1: вызов на handshake с обеих сторон (сервис):"
  grep -n "peer_alive_events" -B 3 -A 4 crates/vecdht-net/src/service.rs
  echo "-- R2: устаревшая эпоха получает ответ текущей цепочкой:"
  grep -n "incoming.epoch < cur.epoch()" -B 6 -A 14 crates/vecdht-node/src/node.rs
  echo "-- R3: демоция исключающей цепочкой ровно при !contains(me):"
  grep -n "MembershipError::MembersOutOfOrder" -B 8 -A 14 crates/vecdht-node/src/node.rs
  echo "-- само-подпись только для цепочки, содержащей узел:"
  grep -n "upd.members.iter().any(|m| m.owner_ed25519 == self.me())" -B 4 -A 8 crates/vecdht-node/src/node.rs
  echo "-- handle_membership знает отправителя:"
  grep -n "fn handle_membership" -A 6 crates/vecdht-node/src/node.rs
  echo "-- wire не тронут (нет диффа):"
  git diff HEAD --stat -- crates/vecdht-wire
  echo "-- исторический оракул E-0069:"
  grep -n "#\[ignore" -A 1 crates/vecdht-node/tests/heal_demotion_window.rs
  echo "-- спека §9.8 (ADR-0017) в рабочем дереве:"
  grep -n "Доставка цепочки — не обещание, а механизм" docs/VecDHT-SPEC-v8.md
  echo "-- новые lease/handshake тесты не перемеряются:"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/tests/heal_one_step.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
