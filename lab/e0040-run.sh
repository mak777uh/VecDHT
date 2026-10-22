#!/usr/bin/env bash
# E-0040 (H-0040): выбор жертвы в prune_idle и мягкость потолка таблицы §11.3.1.
# Коды выхода cargo — настоящего, без пайпа (уроки E-0035/E-0036).
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0040-all.log"
run_cargo() { # $@ = аргументы cargo; печатает настоящий EXIT
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0040 · prune: порядок жертв и мягкий потолок · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test admission_table_over_limit --no-run
  echo "########## RUN (2)(3)(4): admission_table_over_limit ##########"
  run_cargo test -j 2 -p vecdht-node --test admission_table_over_limit -- --nocapture
  echo "########## RUN (1): internal prune_among_idle_rows... в vecdht-node unit ##########"
  run_cargo test -j 2 -p vecdht-node --lib prune_among_idle_rows -- --nocapture
  echo "########## ИНВЕНТАРЬ (5): все упоминания seen_sec и тело prune_idle ##########"
  echo "--- grep seen_sec по всем crates ---"
  grep -rn "seen_sec" crates/ --include=*.rs
  echo "--- тело prune_idle ---"
  sed -n '368,387p' crates/vecdht-node/src/admission.rs
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
