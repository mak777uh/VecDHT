#!/usr/bin/env bash
# E-0062: порядок проверок verify_response (§12.4) и немедленные отказы serve_request (§12.3). Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0062-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0062 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test response_verification_order --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test response_verification_order -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- порядок проверок verify_response (вид → подпись → тело → владелец → подпись → UTF-8):"
  grep -n "header.kind != Kind::IntentTextResponse\|f.signature\|IntentTextResponse::decode\|resp.owner_ed25519 != \*expected_owner\|verify_body(expected_owner\|MAX_INTENT_TEXT_BYTES\|from_utf8" crates/vecdht-node/src/session.rs
  echo "-- serve_request: NoAccept и цикл по issuers (перебор только по BadSignature):"
  grep -n "present.is_empty\|TextError::NoAccept\|saw_bad_signature\|for issuer in issuers\|Err(AcceptError::BadSignature)\|TextError::Spend" crates/vecdht-node/src/session.rs
  echo "-- parse_request: разбор раньше адресата, адресат раньше предъявления:"
  grep -n "fn parse_request\|decode_frame(frame).map_err\|WrongKind\|WrongTarget" crates/vecdht-node/src/session.rs
  echo "-- цитата спеки §12.4:"
  grep -n "Ответ принимается только после проверки" docs/VecDHT-SPEC-v8.md
  echo "-- цитата спеки §12.3 (порядок входа цели):"
  grep -n "перебор кандидатов только по" docs/VecDHT-SPEC-v8.md
  echo "-- покрытие веток TextError в тестах (до этого оракула):"
  grep -rhoP "TextError::\w+" crates/vecdht-node/tests/ | sort | uniq -c | sort -rn
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
