#!/usr/bin/env bash
# E-0036 (H-0036): clusters_of_shard в release-профиле — перебор всего u16.
# Рука E-0027 завершена, но сборки держим на -j 2 и RAYON_NUM_THREADS=2: в это же время идёт
# полная верификация main (lab/logs/workspace-verify-2026-10-22.log).
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0036-all.log"
: > "$LOG"
{
  echo "########## E-0036 · clusters_of_shard в release · $(date -Is) ##########"
  git rev-parse --short HEAD
  grep -n -A 4 "\[profile.release\]" Cargo.toml
  echo "########## BUILD (release, --no-run) ##########"
  cargo test -j 2 --release -p vecdht-crypto --test shard_number_release --no-run 2>&1 | tail -6
  echo "########## RUN shard_number_release (release) ##########"
  cargo test -j 2 --release -p vecdht-crypto --test shard_number_release -- --nocapture 2>&1
  echo "########## EXIT=$? ##########"
  echo "########## КОНТРОЛЬ 1: тесты crypto в release не сломаны ##########"
  cargo test -j 2 --release -p vecdht-crypto 2>&1 | grep -E "test result|^error" | tail -8
  echo "########## КОНТРОЛЬ 2: debug-ветка теста честно пропускает ##########"
  cargo test -j 2 -p vecdht-crypto --test shard_number_release -- --nocapture 2>&1 | grep -E "пропуск|^test |test result"
  echo "########## СПРАВОЧНО: кольцевая арифметика (расчёт, не замер) ##########"
  python -c "
cps, mod = 16, 1 << 16
empty = [s for s in range(mod) if (cps * s) % mod + cps >= mod]
print('  позиций с замыканием base+16:', len(empty), 'первые:', empty[:4], 'последняя:', empty[-1] if empty else None)
print('  ожидалось: 4095 + 4096k, k=0..15 ->', [4095 + 4096 * k for k in range(16)][:4], '…', 4095 + 4096 * 15)
print('  различных выходов (расчёт):', 64 + (1 if empty else 0))
"
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
