#!/usr/bin/env bash
# E-0048 (H-0048): потолок таблицы при ≥2 совпадений — «без части приёмов» §12.3:
# теряется детерминированный хвост сортированного списка. Скрипт сам фиксирует mingw64.
# Коды cargo — настоящего, без пайпа.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0048-all.log"
run_cargo() {
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0048 · частичная выдача приёмов на потолке · $(date -Is) ##########"
  git rev-parse --short HEAD
  x86_64-w64-mingw32-gcc --version | head -1
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test ceiling_partial_accepts --no-run
  echo "########## ИНВЕНТАРЬ: порядок выпуска приёмов в handle_find ##########"
  sed -n '/for m in &res.matches/,+10p' crates/vecdht-node/src/node.rs
  echo "########## ИНВЕНТАРЬ: цитата §12.3 про частичную выдачу ##########"
  grep -n "без части приёмов" docs/VecDHT-SPEC-v8.md
  echo "########## RUN (1)…(4): ceiling_partial_accepts ##########"
  run_cargo test -j 2 -p vecdht-node --test ceiling_partial_accepts -- --nocapture
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
