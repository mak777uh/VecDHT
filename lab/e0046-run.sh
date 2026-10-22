#!/usr/bin/env bash
# E-0046 (H-0046): рестарт обнуляет lease-таблицу; приём после reopen тот же; цель
# расходует довоенный кадр. ЗАПУСКАТЬ с mingw64 в PATH. Коды cargo — настоящего, без пайпа.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0046-all.log"
run_cargo() {
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0046 · lease-таблица и рестарт: RAM-граница §12.3 · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test lease_table_restart --no-run
  echo "########## ИНВЕНТАРЬ: сериализация таблицы приёма (rendezvous.rs / snapshot.rs) ##########"
  grep -niE "serialize|persist|snapshot|flush|wal" crates/vecdht-node/src/rendezvous.rs crates/vecdht-node/src/snapshot.rs | grep -iE "issuer|lease|accept|rendezvous" || echo "(вхождений нет — таблица не сериализуется)"
  echo "########## RUN (1)…(3): lease_table_restart ##########"
  run_cargo test -j 2 -p vecdht-node --test lease_table_restart -- --nocapture
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
