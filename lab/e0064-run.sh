#!/usr/bin/env bash
# E-0064: немаскировка Expired/WrongTarget/TtlOutOfPolicy на выходе serve_request (§12.3). Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0064-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0064 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test immediate_refusals_exit --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test immediate_refusals_exit -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- serve_request: цикл по issuers, перебор только по BadSignature, прочее наружу:"
  grep -n "for issuer in issuers\|Err(AcceptError::BadSignature) => saw_bad_signature\|Err(e) => return Err(TextError::Spend(e))\|NotSignedByShardHolder" crates/vecdht-node/src/session.rs
  echo "-- consume: порядок подпись → адресат → политика → истечение → расход:"
  grep -n "acc.target != \*me\|ttl_sec == 0 || acc.ttl_sec > self.max_ttl_sec\|now_bucket > \|spent.insert" crates/vecdht-node/src/rendezvous.rs
  echo "-- приёмку подписывает ключ узла (урок E-0060):"
  grep -n "sign_body(domain::RENDEZVOUS\|domain::RENDEZVOUS" crates/vecdht-node/src/node.rs crates/vecdht-wire/src/messages.rs | head -4
  echo "-- цитата спеки §12.3 про немедленные отказы:"
  grep -n "отсекаются немедленно" docs/VecDHT-SPEC-v8.md
  echo "-- покрытие комбинаций Spend(...) в тестах-оракулах (состоящее на момент замера):"
  grep -rhoP "Spend\(rendezvous::AcceptError::\w+" crates/vecdht-node/tests/ | sort | uniq -c | sort -rn
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
