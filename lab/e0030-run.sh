#!/usr/bin/env bash
# E-0030 (H-0030): две реализации отображения кластер → шард.
# Сборка ограничена -j 2: в это время из другого дерева идёт тяжёлая рука E-0027.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0030-all.log"
: > "$LOG"
{
  echo "########## E-0030 · две карты шардов · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD ##########"
  cargo test -j 2 -p vecdht-net --test shard_map_divergence --no-run 2>&1 | tail -6
  echo "########## RUN shard_map_divergence ##########"
  cargo test -j 2 -p vecdht-net --test shard_map_divergence -- --nocapture 2>&1
  echo "########## EXIT=$? ##########"
  echo "########## КОНТРОЛЬ: тесты net не сломаны ##########"
  cargo test -j 2 -p vecdht-net 2>&1 | grep -E "test result|^error" | tail -8
  echo "########## ИНВЕНТАРЬ (справочно): сайты константной механики, нетестовый код ##########"
  for pat in "shard_of(" "clusters_of_shard" "CLUSTERS_PER_SHARD" "NLIST"; do
    printf '%s: ' "$pat"
    grep -rn --include='*.rs' -F "$pat" crates/*/src 2>/dev/null | grep -v "/tests/" | grep -vc "//"
  done
  echo "########## где именно в agent.rs живёт константная механика ##########"
  grep -n "shard_of(\*\|shard_of(c)\|shard_of(cluster\|CLUSTERS_PER_SHARD\|NLIST" crates/vecdht-net/src/agent.rs | grep -v "//" | head -20
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
