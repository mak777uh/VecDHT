#!/usr/bin/env bash
# E-0047 (H-0047): граница «сколько живёт» §12.3 на живом стыке Find → Spend.
# Инструмент: скрипт САМ фиксирует mingw64 (MinGW-Builds 16.2) — урок 2026-10-22:
# miniconda-gcc 5.3 не линкует std rustc 1.99.1 (нет GetHostNameW), путь из памяти ненадёжен.
# Коды cargo — настоящего, без пайпа.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0047-all.log"
run_cargo() {
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0047 · приём живёт включительно до бакета issued+ceil(ttl/16) · $(date -Is) ##########"
  git rev-parse --short HEAD
  x86_64-w64-mingw32-gcc --version | head -1
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test accept_ttl_boundary --no-run
  echo "########## ИНВЕНТАРЬ: граница Expired в Spend::consume и предикат prune ##########"
  grep -n "now_bucket > acc.issued_bucket\|issued + ttl\|checked_sub\|bucket >= cutoff" crates/vecdht-node/src/rendezvous.rs
  echo "########## ИНВЕНТАРЬ: цитата спеки §12.3 про границу ###"
  grep -n "на границе \`now = issued" docs/VecDHT-SPEC-v8.md | head -2
  echo "########## RUN (1)…(3): accept_ttl_boundary ##########"
  run_cargo test -j 2 -p vecdht-node --test accept_ttl_boundary -- --nocapture
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
