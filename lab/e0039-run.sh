#!/usr/bin/env bash
# E-0039 (H-0039): узловой бюджет и Find — sybil-пачка 21×6 проходит, бакет 100/с цел.
# Коды выхода cargo — настоящего, без пайпа (уроки E-0035/E-0036).
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0039-all.log"
run_cargo() { # $@ = аргументы cargo; печатает настоящий EXIT
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0039 · Find против узлового бюджета · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test find_node_budget --no-run
  echo "########## RUN (1)…(3): find_node_budget ##########"
  run_cargo test -j 2 -p vecdht-node --test find_node_budget -- --nocapture
  echo "########## ИНВЕНТАРЬ (4): позиции reserve_admit и handle_find ##########"
  echo "--- все вызовы reserve_admit в node.rs ---"
  grep -n "reserve_admit" crates/vecdht-node/src/node.rs
  echo "--- тело handle_find: вхождения reserve_admit / узлового счётчика ---"
  sed -n '966,1010p' crates/vecdht-node/src/node.rs | grep -nE "reserve_admit|node_budget|self\.node" || echo "(вхождений нет)"
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
