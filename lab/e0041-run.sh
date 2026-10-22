#!/usr/bin/env bash
# E-0041 (H-0041): очереди Find с ограничением по времени (§11.3.6 п. 6) в коде нет.
# Коды выхода cargo — настоящего, без пайпа (уроки E-0035/E-0036).
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0041-all.log"
run_cargo() { # $@ = аргументы cargo; печатает настоящий EXIT
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0041 · нет очереди Find · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test find_no_queue --no-run
  echo "########## RUN (1)…(3): find_no_queue ##########"
  run_cargo test -j 2 -p vecdht-node --test find_no_queue -- --nocapture
  echo "########## ИНВЕНТАРЬ (4): очередь/таймер на пути find ##########"
  echo "--- окно handle_find (966…1040): queue|deadline|timeout|defer|timer|sleep ---"
  sed -n '966,1040p' crates/vecdht-node/src/node.rs | grep -nE "queue|deadline|timeout|defer|timer|sleep" || echo "(вхождений нет)"
  echo "--- поля ShardNode: то же ---"
  awk '/pub struct ShardNode/,/^}/' crates/vecdht-node/src/node.rs | grep -nE "queue|deadline|timeout|defer|timer|VecDeque|Duration" || echo "(полей-очередей нет)"
  echo "--- весь vecdht-node/src: латинские слова очереди (полный список в лог) ---"
  grep -rnE "queue|Queue|deadline|timeout" crates/vecdht-node/src/ || echo "(нет вовсе)"
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
