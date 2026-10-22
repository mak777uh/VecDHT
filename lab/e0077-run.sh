#!/usr/bin/env bash
# E-0077: §13/§14 — приватность (pad, джиттер) и проверяемость ответа.
# Helper исполняет команду целиком (урок e0049), лог append-only.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0077-all.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0077 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-net --test s13_privacy_pad --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-net --test s13_privacy_pad -- --nocapture
{ echo "### ИНВЕНТАРЬ ###"
  echo "-- в агенте нет ни функции расстояния, ни репутации, ни штрафа:"
  grep -rn "l2_sq\|reputation\|penalty" crates/vecdht-net/src/ || echo "(совпадений нет)"
  echo "-- то же по всему дереву пакетов:"
  grep -rn "reputation\|penalty" crates/*/src/ || echo "(совпадений нет)"
  echo "-- int8-вектор несут только три сообщения wire:"
  grep -n "vec_q" crates/vecdht-wire/src/messages.rs
  echo "-- агент строит Find с пустым TLV — носителя pad нет:"
  grep -n "tlv: Vec::new()" crates/vecdht-net/src/agent.rs
  echo "-- поля pad-цели в конфигах нет:"
  grep -rn "pad" crates/vecdht-net/src/agent.rs crates/vecdht-net/src/service.rs || echo "(слова pad нет)"
  echo "-- один Find на шард, разрешение кандидатов ждёт предыдущий кадр:"
  grep -n "for (shard, clusters) in groups" -A 6 crates/vecdht-net/src/agent.rs
  grep -n "fn group_clusters" -A 16 crates/vecdht-net/src/agent.rs
  echo "-- длина тела Find и подпись кадра:"
  grep -n "pub struct Find" -A 16 crates/vecdht-wire/src/messages.rs
  grep -n "fn encode_frame" -A 20 crates/vecdht-wire/src/frame.rs
  echo "-- проверка ответа: d2 не сверяется, пересчёта нет:"
  grep -n "fn verify_match_result" -A 45 crates/vecdht-net/src/agent.rs
  echo "-- §13.3 обещает джиттер 0–150 мс, pad до 512 и 1024:"
  grep -n "джиттером 0–150 мс" docs/VecDHT-SPEC-v8.md
  grep -n "pad-цель в коде должна быть параметром политики" docs/VecDHT-SPEC-v8.md
  grep -n "512 байт" docs/VecDHT-SPEC-v8.md
  echo "-- §14.2 обещает re-computation, reputation и штраф:"
  grep -n "verifiable re-computation" docs/VecDHT-SPEC-v8.md
  grep -n "reputation table" docs/VecDHT-SPEC-v8.md
  grep -n "штрафуется" docs/VecDHT-SPEC-v8.md
  echo "-- §19.3 перечисляет, чего в v1 нет:"
  grep -n "penalty/reputation table" -A 4 docs/VecDHT-SPEC-v8.md
  grep -n "verifiable re-computation \`l2_sq\`" -B 3 docs/VecDHT-SPEC-v8.md
  echo "-- wire и спека не тронуты этим циклом:"
  git diff HEAD --stat -- crates/vecdht-wire docs/VecDHT-SPEC-v8.md
  echo "-- оракул E-0077:"
  grep -n "#\[test\]" -A 1 crates/vecdht-net/tests/s13_privacy_pad.rs
} | tee -a "$LOG"
run_cargo "КОНТРОЛЬ vecdht-net" cargo test -j 2 -p vecdht-net
