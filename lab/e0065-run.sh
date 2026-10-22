#!/usr/bin/env bash
# E-0065: привязка req.slot к Grant на входе цели — фикция NO_SUCH_SLOT (§12.4, §5.3). Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0065-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0065 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test slot_request_accept_binding --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test slot_request_accept_binding -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- константа NO_SUCH_SLOT: объявление и ЕДИНСТВЕННЫЕ упоминания (комментарии) — construction нет:"
  grep -rn "NO_SUCH_SLOT" crates/ docs/VecDHT-SPEC-v8.md
  echo "-- consume/serve_request не читают slot запроса (слот приходит только из приёма):"
  grep -n "fn consume\|req.slot\|Key { seeker\|\.slot" crates/vecdht-node/src/rendezvous.rs | head -12
  grep -n "req\.slot\|let req = parse_request\|spend.consume" crates/vecdht-node/src/session.rs
  echo "-- цитата спеки §12.4 про старый слот:"
  grep -n "NO_SUCH_SLOT" docs/VecDHT-SPEC-v8.md
  echo "-- покрытие TextError::Spend в тестах-оракулах (состоящее на момент замера):"
  grep -rhoP "Spend\(rendezvous::AcceptError::\w+" crates/vecdht-node/tests/ | sort | uniq -c | sort -rn
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
