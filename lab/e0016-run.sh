#!/usr/bin/env bash
# E-0016 — издательский конвейер на реальном корпусе 50k (H-0015).
#
# Сырые прогоны пишутся в лог; артефакт — ВНЕ репозитория (§15.1: в git не едут ни веса,
# ни большие артефакты, ни dev-ключи). Форвард не запускается: векторы берутся из кеша
# `E-0004` (`corpus-50k.p0emb`), сверкой по дайджесту корпуса+модели+preprocessing_version.
set -euo pipefail
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS=4

STAND=/c/Users/Admin/models/p0-msmarco
OUT=$STAND/artifact-50k
LOG=${E0016_LOG:-/tmp/e0016.log}
: >"$LOG"

cd "$(dirname "$0")/.."
cargo build --release -p vecdht-cli

# 1. Издание артефакта из корпуса (шаг гейта: карта, метрики, подпись).
{
  echo "### 1. artifact publish"
  ./target/release/vecdht-cli.exe artifact publish \
    --out "$OUT" --force \
    --corpus "$STAND/corpus-50k.txt" \
    --model-dir /c/Users/Admin/models/granite-embedding-97m-r2 \
    --label granite-embedding-97m-v2 \
    --assignments "$STAND/artifact-50k-assignments.txt" \
    --dev-keys 3
} >>"$LOG" 2>&1

# 2. Проверка выпущенного артефакта (§15.1: подпись, состав, centroid.bin, genesis_hash).
{
  echo "### 2. artifact verify"
  ./target/release/vecdht-cli.exe artifact verify --artifact "$OUT"
} >>"$LOG" 2>&1

# 3. Сводка по артефакту: artifact_hash == genesis_hash, число строк, геометрия.
{
  echo "### 3. artifact show"
  ./target/release/vecdht-cli.exe artifact show --artifact "$OUT"
} >>"$LOG" 2>&1

echo "лог: $LOG"
echo "артефакт: $OUT (вне git)"
grep -E "разброс внутри шарда|цена назначения|кластеры|шардов|артефакт записан|artifact_hash|проверено|присваивания|корпус" "$LOG" || true
