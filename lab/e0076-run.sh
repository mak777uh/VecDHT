#!/usr/bin/env bash
# E-0076: §5.3/§4.2 — handshake: код отказа, жизнь кеша и вторая дверь в индекс.
# Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0076-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0076 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-net --test s5_handshake_seam --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-net --test s5_handshake_seam -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- дверь различает семь причин, но отдаёт одну:"
  grep -n "pub enum HandshakeError" -A 30 crates/vecdht-net/src/handshake.rs | grep -n "Mismatch\|Expired\|Revoked\|Owner\|PeerId\|BadCert\|MissingCert\|AgentWithCert"
  echo "-- ветка отказа handshake сводит всё к CERT_INVALID, а причину выбрасывает:"
  grep -n "accept_handshake(peer, &request)" -A 12 crates/vecdht-net/src/service.rs
  grep -n "fn error_frame" -A 4 crates/vecdht-net/src/service.rs
  echo "-- MODEL_MISMATCH в коде handshake не строится (в шард-двери — да):"
  grep -rn "MODEL_MISMATCH" crates/vecdht-net/src/ crates/vecdht-node/src/node.rs crates/vecdht-wire/src/messages.rs
  echo "-- соединение закрывается только при самоотзыве и отзыве пира:"
  grep -n "disconnect_peer_id" crates/vecdht-net/src/service.rs
  echo "-- valid_until записывается и больше нигде не читается:"
  grep -rn "valid_until" crates/vecdht-net/src/
  echo "-- кеш handshake удаляется только при закрытии соединения и при отзыве:"
  grep -n "forget_peer" crates/vecdht-net/src/service.rs
  echo "-- gossip-путь не спрашивает таблицу handshake, прямой — спрашивает:"
  grep -n "fn route_gossip" -A 10 crates/vecdht-net/src/service.rs
  grep -n "fn route_app_frame" -A 10 crates/vecdht-net/src/service.rs
  grep -n "fn authenticate_gossip_author" -A 6 crates/vecdht-net/src/service.rs
  echo "-- §4.2 обещает кеш до valid_until, §6.7/§15.3 — MODEL_MISMATCH и закрытие:"
  grep -n "кеш по \`remote PeerId\` до \`valid_until\`" docs/VecDHT-SPEC-v8.md
  grep -n "MODEL_MISMATCH" docs/VecDHT-SPEC-v8.md
  grep -n "0x01   Handshake" docs/VecDHT-SPEC-v8.md
  echo "-- wire и спека не тронуты этим циклом:"
  git diff HEAD --stat -- crates/vecdht-wire docs/VecDHT-SPEC-v8.md
  echo "-- оракул E-0076:"
  grep -n "#\[test\]" -A 1 crates/vecdht-net/tests/s5_handshake_seam.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-net" cargo test -j 2 -p vecdht-net
