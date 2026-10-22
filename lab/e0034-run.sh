#!/usr/bin/env bash
# E-0034 (H-0034): номер шарда вне диапазона — маска в clusters_of_shard и распределение
# диапазонных проверок по wire-сообщениям. Сборка на -j 2: идёт тяжёлая рука E-0027.
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0034-all.log"
: > "$LOG"
{
  echo "########## E-0034 · admission номера шарда · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD ##########"
  cargo test -j 2 -p vecdht-crypto --test shard_number_admission --no-run 2>&1 | tail -8
  echo "########## RUN shard_number_admission ##########"
  cargo test -j 2 -p vecdht-crypto --test shard_number_admission -- --nocapture 2>&1
  echo "########## EXIT=$? ##########"
  echo "########## КОНТРОЛЬ: тесты crypto не сломаны ##########"
  cargo test -j 2 -p vecdht-crypto 2>&1 | grep -E "test result|^error" | tail -8
  echo "########## ПОРОГ (1): вызовы clusters_of_shard в нетестовом коде ##########"
  grep -rn --include='*.rs' "clusters_of_shard(" crates sdk 2>/dev/null | grep -v "/tests/" | grep -v "mod tests"
  echo "-- сайтов вызова в нетестовом коде: $(grep -rn --include='*.rs' 'clusters_of_shard(' crates sdk 2>/dev/null | grep -v '/tests/' | grep -vc 'fn clusters_of_shard')"
  echo "########## ПОРОГ (2): кто зовёт is_valid_shard ##########"
  grep -rn --include='*.rs' "is_valid_shard(" crates sdk 2>/dev/null
  echo "-- сайтов вне vecdht-crypto (нетестовый код): $(grep -rn --include='*.rs' 'is_valid_shard(' crates sdk 2>/dev/null | grep -v '/tests/' | grep -v 'crates/vecdht-crypto/src' | wc -l)"
  echo "########## ПОРОГ (3): поля shard в wire-сообщениях против проверок ##########"
  echo "-- struct'ов с 'pub shard: u16': $(grep -c 'pub shard: u16' crates/vecdht-wire/src/messages.rs)"
  echo "-- диапазонных проверок при декоде: $(grep -c 'if shard >= crate::constants::SHARDS' crates/vecdht-wire/src/messages.rs)"
  echo "-- какие сообщения имеют поле и где стоит проверка:"
  python - <<'PY'
import io, re
lines = io.open('crates/vecdht-wire/src/messages.rs', encoding='utf-8').read().split('\n')
cur, out = None, []
for i, l in enumerate(lines, 1):
    m = re.match(r'pub struct (\w+)', l)
    if m:
        cur = m.group(1)
    if 'pub shard: u16' in l:
        out.append((cur, 'поле'))
    if 'if shard >= crate::constants::SHARDS' in l:
        out.append((cur, 'ПРОВЕРКА'))
for name, kind in out:
    print('   %-20s %s' % (name, kind))
PY
  echo "########## СПРАВОЧНО: где приёмка сверяет номер со своим ##########"
  grep -n "shard != self.shard\|!= self.shard" crates/vecdht-node/src/node.rs | head -12
  echo "-- сайтов сверки '.shard != self.shard' в node.rs: $(grep -c '!= self.shard' crates/vecdht-node/src/node.rs)"
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
