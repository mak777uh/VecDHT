#!/usr/bin/env bash
# E-0032 (H-0032): два правила выбора — собранное (по кластерам) и спековское (§7.5.1, по шардам).
# Сборка ограничена -j 2: в это время из другого дерева идёт тяжёлая рука E-0027.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0032-all.log"
: > "$LOG"
{
  echo "########## E-0032 · fan-out: правило кода против правила спеки · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD ##########"
  cargo test -j 2 -p vecdht-artifact --test fanout_rule --no-run 2>&1 | tail -8
  echo "########## RUN fanout_rule ##########"
  cargo test -j 2 -p vecdht-artifact --test fanout_rule -- --nocapture 2>&1
  echo "########## EXIT=$? ##########"
  echo "########## КОНТРОЛЬ: тесты artifact не сломаны ##########"
  cargo test -j 2 -p vecdht-artifact 2>&1 | grep -E "test result|^error" | tail -8
  echo "########## ПОРОГ (1): правила §7.5.1 вне vecdht-embed (нетестовый код) ##########"
  grep -rn --include='*.rs' "7.5.1\|минимум по" crates/*/src 2>/dev/null | grep -v "/tests/"
  echo "-- всех упоминаний §7.5.1 по нетестовому коду: $(grep -rn --include='*.rs' '7\.5\.1' crates/*/src 2>/dev/null | grep -vc '/tests/')"
  echo "-- из них вне embed: $(grep -rn --include='*.rs' '7\.5\.1' crates/*/src 2>/dev/null | grep -v '/tests/' | grep -vc 'crates/vecdht-embed/src')"
  echo "########## ПОРОГ (2): кто зовёт Centroids::top (нетестовый код) ##########"
  grep -rn --include='*.rs' "centroids.top(\|\.top(&\|top_clusters(" crates/*/src sdk 2>/dev/null | grep -v "/tests/"
  echo "########## клиентский список кластеров против скана владельца ##########"
  grep -rn --include='*.rs' "store.search(\|fn search(" crates/vecdht-node/src crates/vecdht-index/src 2>/dev/null | grep -v "/tests/"
  echo "########## где стенд гейта считает правило сам ##########"
  grep -n "7.5.1\|ячеек по гейтной сортировке\|бюджет \`nprobe\` ячеек" crates/vecdht-embed/tests/p0_real_corpus.rs | head -8
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
