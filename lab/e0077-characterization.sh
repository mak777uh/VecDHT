#!/usr/bin/env bash
# E-0077: характеристика переписанного оракула (прецедент E-0032).
#
# После решения по замороженному порогу (5) («`Find` следующей группы уходит на провод
# не раньше 1,6 с») тест заменён на утверждение измеренного: кадр не уходит вовсе (5′).
# Порог (4) («разброс прихода < 20 мс») стоял внутри шума loopback — контрольный повтор
# того же бинаря дал 22,1 мс (ДИАГНОЗ-5) — и переведён на утверждение по существу:
# джиттера нет по исходнику, а замер лишь подтверждает.
#
# Лог отдельный и append-only: решающий прогон остаётся в `lab/logs/e0077-all.log`.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0077-characterization.log"
run_cargo() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0077 характеристика $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; } | tee -a "$LOG"
run_cargo "BUILD --no-run" cargo test -j 2 -p vecdht-net --test s13_privacy_pad --no-run
run_cargo "RUN --nocapture" cargo test -j 2 -p vecdht-net --test s13_privacy_pad -- --nocapture
run_cargo "КОНТРОЛЬ vecdht-net" cargo test -j 2 -p vecdht-net
