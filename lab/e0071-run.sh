#!/usr/bin/env bash
# E-0071: §9 хвост — узел, пропустивший эпоху, не догоняет шард никогда.
# Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0071-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0071 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test s9_epoch_gap --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test s9_epoch_gap -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- цепочка принимает только epoch+1, разрыв — EpochNotNext:"
  grep -n "EpochNotNext" -B 6 crates/vecdht-node/src/membership.rs
  echo "-- разрыв гасится молча: Ok(Vec::new()) без Error и без лога:"
  grep -n "Err(_) => Ok(Vec::new())" -B 4 crates/vecdht-node/src/node.rs
  echo "-- next_list всегда предлагает текущая+1:"
  grep -n "fn next_list" -A 12 crates/vecdht-node/src/node.rs
  echo "-- узел с меньшей эпохой отвечает текущей цепочкой (§9.8/ADR-0017):"
  grep -n "fn handle_membership" -A 24 crates/vecdht-node/src/node.rs
  echo "-- peer_alive лечит только текущей цепочкой:"
  grep -n "fn peer_alive" -A 12 crates/vecdht-node/src/node.rs
  echo "-- leave принимается только по эпохе текущего члена:"
  grep -n "fn handle_leave" -A 16 crates/vecdht-node/src/node.rs
  echo "-- публикация отвергается по serving_epoch (EPOCH_STALE):"
  grep -n "EPOCH_STALE" crates/vecdht-node/src/node.rs crates/vecdht-wire/src/messages.rs
  echo "-- на проводе нет вида кадра для истории членства:"
  grep -n "pub enum Kind" -A 40 crates/vecdht-wire/src/messages.rs
  echo "-- §9.2 обещает доставку принятой эпизоды всем участникам:"
  grep -n "разослать всем её участникам\|доставить её тому, кто ещё не знает" docs/VecDHT-SPEC-v8.md
  echo "-- wire и спека не тронуты этим циклом:"
  git diff HEAD --stat -- crates/vecdht-wire docs/VecDHT-SPEC-v8.md
  echo "-- оракул E-0071:"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/tests/s9_epoch_gap.rs
  echo "-- пороги заморожены в пре-регистрации:"
  grep -n "Замороженные пороги" -A 3 lab/hypotheses/H-0071-epoch-gap.md
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
