#!/usr/bin/env bash
# E-0042 (H-0042): denylist §11.4 (ii) — нет продуктовых вызовов deny, нет сериализации,
# запрет испаряется при перезагрузке. Коды выхода cargo — настоящего, без пайпа.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0042-all.log"
run_cargo() { # $@ = аргументы cargo; печатает настоящий EXIT
  local out; out=$(mktemp)
  cargo "$@" > "$out" 2>&1
  local rc=$?
  cat "$out"; rm -f "$out"
  echo "########## EXIT=$rc ##########"
  return $rc
}
{
  echo "########## E-0042 · denylist: путь «внести» и перезагрузка · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD (--no-run) ##########"
  run_cargo test -j 2 -p vecdht-node --test denylist_reachability --no-run
  echo "########## ИНВЕНТАРЬ (4а): все вызовы deny/undeny в crates (классификация руками) ##########"
  grep -rn "\.deny(\|\.undeny(\|denylist" crates/ --include=*.rs
  echo "--- продуктовые вызовы: строки вне src/admission.rs и вне tests/ ---"
  grep -rn "\.deny(\|\.undeny(" crates/ --include=*.rs | grep -v "src/admission.rs" | grep -v "/tests/" || echo "(продуктовых вызовов нет)"
  echo "########## ИНВЕНТАРЬ (4б): «deny» вне admission.rs в узле/снапшоте/индексе и в wire ##########"
  grep -n "deny" crates/vecdht-node/src/node.rs crates/vecdht-node/src/snapshot.rs || echo "(в node.rs/snapshot.rs вхождений нет)"
  grep -rn "deny" crates/vecdht-index/src/ || echo "(в vecdht-index вхождений нет)"
  grep -rni "denylist" crates/vecdht-wire/src/ || echo "(в wire-протоколе denylist'а нет)"
  echo "########## ИНВЕНТАРЬ (4в): операции над полем denylist в admission.rs ##########"
  grep -n "denylist" crates/vecdht-node/src/admission.rs
  echo "--- clear/retain/время над списком ---"
  grep -nE "denylist\.(clear|retain)|denylist.*sec|DENY_.*(TTL|EXPIRE)" crates/vecdht-node/src/admission.rs || echo "(чистки и времени у denylist нет)"
  echo "########## RUN (1)…(3): denylist_reachability ##########"
  run_cargo test -j 2 -p vecdht-node --test denylist_reachability -- --nocapture
  echo "########## КОНТРОЛЬ: тесты vecdht-node зелёные ##########"
  run_cargo test -j 2 -p vecdht-node
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
