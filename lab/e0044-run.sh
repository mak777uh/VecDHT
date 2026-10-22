#!/usr/bin/env bash
# E-0044 (H-0044): потолок lease-таблицы на живом узле + идемпотентность повтора Find.
# ЗАПУСКАТЬ с mingw64 в PATH. Коды выхода cargo — настоящего, без пайпа.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0044-all.log"
run_cargo() {
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0044 · lease-таблица: повтор и потолок на живом Find · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test lease_table_ceiling --no-run
  echo "########## ИНВЕНТАРЬ: позиция continue при issue()==None в handle_find ##########"
  sed -n '966,1040p' crates/vecdht-node/src/node.rs | grep -nE "issue|continue|err\(" || echo "(нет вхождений — проверить границы окна)"
  echo "########## RUN (1)…(3): lease_table_ceiling ##########"
  run_cargo test -j 2 -p vecdht-node --test lease_table_ceiling -- --nocapture
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
