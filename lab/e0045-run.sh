#!/usr/bin/env bash
# E-0045 (H-0045): одноразовость расхода §12.3 — только API; живого пути цели нет.
# ЗАПУСКАТЬ с mingw64 в PATH. Коды выхода cargo — настоящего, без пайпа.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0045-all.log"
run_cargo() {
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0045 · расход приёма: предъявить нечем, звать некому · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test accept_presentation_api_only --no-run
  echo "########## ИНВЕНТАРЬ 1: Spend/consume в node.rs / session.rs / agent.rs ##########"
  grep -nE "Spend|\.consume\(" crates/vecdht-node/src/node.rs crates/vecdht-node/src/session.rs crates/vecdht-net/src/agent.rs || echo "(вхождений нет)"
  echo "########## ИНВЕНТАРЬ 2: поля IntentTextRequest (messages.rs) ##########"
  grep -n "pub struct IntentTextRequest" -A 6 crates/vecdht-wire/src/messages.rs
  echo "########## ИНВЕНТАРЬ 3: все файлы с Spend в crates (классификация в E-0045) ##########"
  grep -rl "Spend" crates --include=*.rs
  echo "########## ИНВЕНТАРЬ 4: relay-путь узла — что он не принимает ##########"
  sed -n '1395,1400p' crates/vecdht-node/src/node.rs
  echo "########## RUN (3)…(4): accept_presentation_api_only ##########"
  run_cargo test -j 2 -p vecdht-node --test accept_presentation_api_only -- --nocapture
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
