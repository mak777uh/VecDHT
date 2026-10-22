#!/usr/bin/env bash
# E-0035 (H-0035): полный перебор u16 для clusters_of_shard. Сборка на -j 2: идёт тяжёлая рука E-0027.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0035-all.log"
: > "$LOG"
{
  echo "########## E-0035 · clusters_of_shard: перебор всего u16 · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD ##########"
  cargo test -j 2 -p vecdht-crypto --test shard_number_exhaustive --no-run 2>&1 | tail -6
  echo "########## RUN shard_number_exhaustive ##########"
  cargo test -j 2 -p vecdht-crypto --test shard_number_exhaustive -- --nocapture 2>&1
  echo "########## EXIT=$? ##########"
  echo "########## КОНТРОЛЬ: тесты crypto не сломаны ##########"
  cargo test -j 2 -p vecdht-crypto 2>&1 | grep -E "test result|^error" | tail -8
  echo "########## СПРАВОЧНО: арифметика границы (расчёт, не замер) ##########"
  python -c "
cps, u16max = 16, 65535
print('  base + 16 умещается при s <=', (u16max - cps) // cps)
print('  base умещается при s <=', u16max // cps)
print('  всего значений без паники:', (u16max - cps) // cps + 1, 'из', u16max + 1)
"
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
