#!/usr/bin/env bash
# E-0043 (H-0043): anti-replay §14.3 на пути Find — повторы query_id отвечаются всегда,
# поля timestamp в протоколе нет. ЗАПУСКАТЬ ТОЛЬКО с mingw64 в PATH (урок контроля E-0042).
# Коды выхода cargo — настоящего, без пайпа.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0043-all.log"
run_cargo() { # $@ = аргументы cargo; печатает настоящий EXIT
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0043 · anti-replay Find: ни поля, ни состояния · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test anti_replay_find --no-run
  echo "########## ИНВЕНТАРЬ (3): timestamp в vecdht-wire (кроме cert) ##########"
  grep -rn "timestamp" crates/vecdht-wire/src/ || echo "(в wire слова timestamp нет нигде)"
  grep -rn "timestamp" crates/vecdht-wire/src/ --include=*.rs | grep -v cert.rs || echo "(вне cert.rs — ноль)"
  echo "########## ИНВЕНТАРЬ (3): позиции query_id в node.rs ##########"
  grep -n "query_id" crates/vecdht-node/src/node.rs
  echo "########## ИНВЕНТАРЬ (3): состояния виденных id в vecdht-node ##########"
  grep -rnE "BTreeSet<u64>|HashSet<u64>|seen|dedup|replay" crates/vecdht-node/src/ || echo "(состояния дедупа нет нигде, включая rendezvous)"
  echo "--- отдельной строкой: одноразовость RendezvousAccept (истинная половина §14.3) ---"
  grep -n "spent\|by_expiry\|Spend" crates/vecdht-node/src/rendezvous.rs | head -8
  echo "########## RUN (1)…(2): anti_replay_find ##########"
  run_cargo test -j 2 -p vecdht-node --test anti_replay_find -- --nocapture
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
