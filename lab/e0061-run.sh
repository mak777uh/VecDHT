#!/usr/bin/env bash
# E-0061: байтовая неканоничность кадра приёмки + WrongKind/Malformed (§5.1, §5.2, §12.3). Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0061-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0061 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-node --test frame_byte_mutation --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-node --test frame_byte_mutation -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- decode_frame: тело по body_len, подпись по sig_len, хвост не смотрим:"
  grep -n "let need = after\|bytes.len() < need\|let body =\|let mut rest\|n != ED25519_SIG_LEN\|Some(&rest\[..n\])" crates/vecdht-wire/src/frame.rs
  echo "-- первые проверки consume (разбор, kind, подпись):"
  grep -n "self.prune(now_bucket)\|decode_frame(frame).map_err\|header.kind != Kind::RendezvousAccept\|try_into().map_err\|acc.target != \*me" crates/vecdht-node/src/rendezvous.rs
  echo "-- гейты заголовка в parse_header:"
  grep -n "Version(version)\|ReservedFlags\|BodyTooLarge\|Kind::from_u8" crates/vecdht-wire/src/frame.rs
  echo "-- цитата спеки про sig_len и reserved-биты:"
  grep -n "sig_len обязан быть 64\|зарезервированы, MUST" docs/VecDHT-SPEC-v8.md
  echo "-- цитата спеки про canonical-байты подписи:"
  grep -n "подпись всегда по canonical-байтам" docs/VecDHT-SPEC-v8.md
  echo "-- покрытие веток AcceptError в тестах (до этого оракула):"
  grep -rhoP "AcceptError::\w+" crates/vecdht-node/tests/ | sort | uniq -c | sort -rn
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
