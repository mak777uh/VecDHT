#!/usr/bin/env bash
# E-0033 (H-0033): один запросный поток на двух стендах центроидов — сетка эталона и случайные
# строки. Сборка ограничена -j 2: в это время из другого дерева идёт тяжёлая рука E-0027.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0033-all.log"
: > "$LOG"
{
  echo "########## E-0033 · пригодность стенда: сетка эталона против случайных центроидов · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD ##########"
  cargo test -j 2 -p vecdht-artifact --test stand_grid_degeneracy --no-run 2>&1 | tail -8
  echo "########## RUN stand_grid_degeneracy ##########"
  cargo test -j 2 -p vecdht-artifact --test stand_grid_degeneracy -- --nocapture 2>&1
  echo "########## EXIT=$? ##########"
  echo "########## КОНТРОЛЬ: тесты artifact не сломаны ##########"
  cargo test -j 2 -p vecdht-artifact 2>&1 | grep -E "test result|^error" | tail -10
  echo "########## ОРИЕНТИР (расчёт по равномерной модели, не замер) ##########"
  echo "доля запросов с хотя бы одним столкновением при выборке k кластеров из 1024 по 16 в шарде,"
  echo "если бы кластеры выбирались наугад (без учёта близости к запросу):"
  python -c "
from math import perm
for k in (4, 16, 32):
    tot, good = perm(1024, k), perm(64, k) * 16 ** k
    print('  k=%-2d  %.2f %%  (из 256 запросов ~ %.1f)' % (k, 100 * (1 - good / tot), 256 * (1 - good / tot)))
"
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
