#!/usr/bin/env bash
# E-0028 (H-0027): стадия 1 — что именно мешает открыть nlist как данные.
# Лёгкий прогон: debug, без candle/весов/корпуса. Запускать ТОЛЬКО когда измерительная
# цепочка e0025/e0027 окончена (не отбирать ядра у гейта).
set -uo pipefail
cd "$(dirname "$0")/.."
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-4}"
LOG="lab/logs/e0028-all.log"
: > "$LOG"
{
  echo "########## E-0028 · геометрия как данные · $(date -Is) ##########"
  git rev-parse --short HEAD
  echo "########## BUILD ##########"
  cargo test --debug -p vecdht-index --test geometry_rotation --no-run 2>&1
  echo "########## RUN geometry_rotation ##########"
  cargo test --debug -p vecdht-index --test geometry_rotation -- --nocapture 2>&1
  echo "########## EXIT=$? ##########"
  echo "########## КОНТРОЛЬ: существующие тесты индекса не сломаны ##########"
  cargo test --debug -p vecdht-index 2>&1 | tail -25
  echo "########## EXIT=$? ##########"
  echo "########## ПУНКТ (5): читатели Kind::ArtifactAnnounce в нетестовом коде node/net ##########"
  # Ожидание H-0027: ноль (кадр доходит до `_ => Ok(Vec::new())` в node.rs:1397).
  # Считаем совпадения вне tests/ и вне комментариев; cli не входит (это отчёт, не читатель пути).
  grep -rn "ArtifactAnnounce" crates/vecdht-node/src crates/vecdht-net/src 2>/dev/null \
    | grep -v "//" | tee -a /dev/null
  echo "########## ЧИТАТЕЛЕЙ (строк с упоминанием вне комментариев): $(grep -rn "ArtifactAnnounce" crates/vecdht-node/src crates/vecdht-net/src 2>/dev/null | grep -vc "//") ##########"
} 2>&1 | tee -a "$LOG"
echo "лог: $LOG"
