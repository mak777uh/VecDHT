#!/usr/bin/env bash
# E-0031 (H-0031): стена стадии 1 — валидатор манифеста, потолок шардов, граница значения в кредашиале.
# Сборка ограничена -j 2: в это время из другого дерева идёт тяжёлая рука E-0027.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0031-all.log"
: > "$LOG"
{
  echo "########## E-0031 · стена геометрии в манифесте · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD ##########"
  cargo test -j 2 -p vecdht-artifact --test geometry_wall --no-run 2>&1 | tail -8
  echo "########## RUN geometry_wall ##########"
  cargo test -j 2 -p vecdht-artifact --test geometry_wall -- --nocapture 2>&1
  echo "########## EXIT=$? ##########"
  echo "########## КОНТРОЛЬ: тесты artifact не сломаны ##########"
  cargo test -j 2 -p vecdht-artifact 2>&1 | grep -E "test result|^error" | tail -8
  echo "########## ИНВЕНТАРЬ (справочно): геометрические константы в нетестовом коде ##########"
  for pat in "CLUSTERS_PER_SHARD" "SHARDS" "MAX_CERT_SHARDS" "NLIST"; do
    printf '%s: ' "$pat"
    grep -rn --include='*.rs' -F "$pat" crates/*/src 2>/dev/null | grep -v "/tests/" | grep -vc "//"
  done
  echo "########## сайты проверок геометрии в manifest.rs ##########"
  grep -n "routing.nlist\|routing.clusters_per_shard\|routing.shards\|MAX_CERT_SHARDS\|NLIST\|SHARDS\|CLUSTERS_PER_SHARD" crates/vecdht-artifact/src/manifest.rs | head -25
  echo "########## где граница номера шарда в кредашиале ##########"
  grep -n "SHARDS\|MAX_CERT_SHARDS\|covers_shard" crates/vecdht-wire/src/cert.rs
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
