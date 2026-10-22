#!/usr/bin/env bash
# E-0063: UTF-8-ветка verify_response как порядок (§12.4) и два имени для битого UTF-8 в двух полях. Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0063-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0063 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test utf8_last_gate --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test utf8_last_gate -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- UTF-8-гейт verify_response (последняя ступень) и разбор тела раньше него:"
  grep -n "IntentTextResponse::decode\|from_utf8(resp.text)\|TextError::NotUtf8\|MAX_INTENT_TEXT_BYTES" crates/vecdht-node/src/session.rs
  echo "-- декодер: bytes не смотрит в содержимое, string требует UTF-8:"
  grep -n "pub fn bytes\|pub fn string\|String::from_utf8(b)\|FieldTooLong" crates/vecdht-wire/src/codec.rs
  echo "-- декодер тела: лимит строго больше (включительность границы 1000):"
  grep -n "text.len() > MAX_INTENT_TEXT_BYTES\|FieldTooLong(text.len())" crates/vecdht-wire/src/messages.rs
  echo "-- цитата спеки §12.4 (короткий якорь: в спеке переносит строку):"
  grep -n "Ответ принимается только после" docs/VecDHT-SPEC-v8.md
  echo "-- покрытие веток TextError в тестах-оракулах (состоящее на момент замера):"
  grep -rhoP "TextError::\w+" crates/vecdht-node/tests/ | sort | uniq -c | sort -rn
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
