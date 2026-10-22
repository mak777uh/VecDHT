#!/usr/bin/env bash
# E-0037 (H-0037): раздутый список Find — кодек, линеарность поиска, цена квоты.
# Коды выхода cargo пишутся без пайпа (уроки E-0035/E-0036: `$?` после `| grep` — код grep'а).
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0037-all.log"
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
  echo "########## E-0037 · список Find: кодек/поиск/квота · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run, все три оракула) ##########"
  run_cargo test -j 2 -p vecdht-wire --test find_cluster_list --no-run
  run_cargo test -j 2 -p vecdht-index --test find_cluster_list_amplification --no-run
  run_cargo test -j 2 -p vecdht-node --test find_admission_price --no-run
  echo "########## RUN (1)(2): find_cluster_list ##########"
  run_cargo test -j 2 -p vecdht-wire --test find_cluster_list -- --nocapture
  echo "########## RUN (3): find_cluster_list_amplification ##########"
  run_cargo test -j 2 -p vecdht-index --test find_cluster_list_amplification -- --nocapture
  echo "########## RUN (4): find_admission_price ##########"
  run_cargo test -j 2 -p vecdht-node --test find_admission_price -- --nocapture
  echo "########## ИНВЕНТАРЬ (5): проверки длины clusters в приёмном пути ##########"
  echo "--- messages.rs: Find::decode_body ---"
  sed -n '371,390p' crates/vecdht-wire/src/messages.rs
  echo "--- node.rs: handle_find (guard'ы после decode) ---"
  sed -n '966,996p' crates/vecdht-node/src/node.rs
  echo "--- grep len/limits по трём файлам приёмного пути ---"
  grep -nE "clusters\.(len|is_empty)|MAX.*CLUSTER|CLUSTER.*LIMIT|len\(\) *[<>]" \
    crates/vecdht-wire/src/messages.rs crates/vecdht-node/src/node.rs crates/vecdht-node/src/admission.rs || echo "(вхождений нет)"
  echo "########## КОНТРОЛЬ: тесты трёх затронутых крейтов зелёные ##########"
  run_cargo test -j 2 -p vecdht-wire
  run_cargo test -j 2 -p vecdht-index
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
