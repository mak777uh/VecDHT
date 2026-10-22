#!/usr/bin/env bash
# E-0038 (H-0038): пустой список Find — обслуживается ли он как обычный запрос.
# Коды выхода cargo — настоящего, без пайпа (уроки E-0035/E-0036).
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0038-all.log"
: > "$LOG"
run_cargo() { # $@ = аргументы cargo; печатает настоящий EXIT
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0038 · пустой список Find · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test find_empty_cluster_list --no-run
  echo "########## RUN (1)(2)(факт 3): find_empty_cluster_list ##########"
  run_cargo test -j 2 -p vecdht-node --test find_empty_cluster_list -- --nocapture
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
