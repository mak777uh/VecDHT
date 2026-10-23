#!/usr/bin/env bash
# Страж формальных моделей: все `lab/lean/VecDHT/*.lean` обязаны компилироваться, ноль `error`
# и ноль `sorry`.
#
# Причина появления скрипта (2026-10-23): модели `Auth.lean`, `Admission.lean`, `Shard.lean`,
# `CertLadder.lean` исполнялись только внутри helper'а того цикла, который их написал
# (`lab/e0078-run.sh`, `lab/e0079-run.sh`). Стоящей проверки у них не было ни у одной, то есть
# правка продукта, ломающая транскрипцию, не была бы замечена никогда. Это ровно тот класс
# молчания, который `E-0085…E-0091` ловили в коде: обещание без механизма.
#
# Стоимость измерена на этом хосте (2026-10-23): холодный прогон — Admission 32,5 с, Auth 26,4 с,
# Shard 2,7 с, CertLadder 1,8 с (итого ~63 с); повторный — 4,4 / 4,1 / 1,9 / 2,6 с (итого 12,9 с).
# Разница — прогрев, поэтому в гейт идёт отношение к границе, а не абсолютное число: даже
# холодный прогон дешевле одной сборки `cargo test --workspace`. Гейт стоит
# в `workspace-verify.sh` (один раз на закрытие цикла), а не перед каждой командой.
#
# Употребление: bash lab/lean-check.sh [--quiet]
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1

if ! command -v lean >/dev/null 2>&1; then
  echo "LEAN_TOOLCHAIN=0 — компилятор Lean не найден в PATH (/c/Users/Admin/.elan/bin); модели СЕГОДНЯ не проверялись"
  echo "LEAN_ALL_OK=0"
  exit 2
fi

TOTAL=0; BROKEN=0; TOTAL_SORRY=0; TOTAL_MS=0
for f in lab/lean/VecDHT/*.lean; do
  [ -e "$f" ] || continue
  TOTAL=$((TOTAL + 1))
  t0=$(date +%s%N)
  out=$(lean "$f" 2>&1); rc=$?
  t1=$(date +%s%N)
  ms=$(( (t1 - t0) / 1000000 ))
  TOTAL_MS=$((TOTAL_MS + ms))
  errs=$(printf '%s\n' "$out" | grep -c 'error:' || true)
  sorry=$(grep -c '\bsorry\b' "$f" || true)
  TOTAL_SORRY=$((TOTAL_SORRY + sorry))
  # `sorry` — это не доказательство: модель с ним обязана падать, а не печататься.
  ok=1
  [ "$rc" -ne 0 ] && ok=0
  [ "$errs" -gt 0 ] && ok=0
  [ "$sorry" -gt 0 ] && ok=0
  [ "$ok" -eq 0 ] && BROKEN=$((BROKEN + 1))
  echo "LEAN_FILE=$(basename "$f") EXIT=$rc ERRORS=$errs SORRY=$sorry MS=$ms OK=$ok"
  [ "$ok" -eq 0 ] && [ "$QUIET" -eq 0 ] && printf '%s\n' "$out" | head -20
done

if [ "$TOTAL" -eq 0 ]; then
  echo "LEAN_ALL_OK=0 — каталог lab/lean/VecDHT пуст"
  exit 1
fi

echo "LEAN_TOTAL=$TOTAL BROKEN=$BROKEN SORRY_TOTAL=$TOTAL_SORRY LEAN_MS_TOTAL=$TOTAL_MS"
if [ "$BROKEN" -eq 0 ]; then
  echo "LEAN_ALL_OK=1"
  exit 0
fi
echo "LEAN_ALL_OK=0"
exit 1
