#!/usr/bin/env bash
# Отчёт о носителе: свободный диск, RAM, pagefile — всегда; размеры каталогов — по требованию.
#
# Почему размеры не по умолчанию: `du -sm target` на этом хосте стоит 34 с (измерено 2026-10-24,
# 11 481 МБ), а `workspace-verify.sh` зовёт отчёт дважды за цикл. Верификация, которая тратит
# минуту на косметику, вытесняет собой замер — поэтому быстрый путь меряет три числа, которые
# владелец просил держать под наблюдением, и ничего не обходит.
#
# Правило владельца: `cargo clean` — только с объявлением. Здесь его нет вовсе. `--apply` удаляет
# единственное, что возвращает запас, не ломая warm-перекомпиляцию: кэш инкрементальной сборки
# `target/*/incremental` (прецедент — 2026-10-24, 3 077 МБ, свободный диск 12 193 -> 15 270 МБ).
# Перед удалением печатается объявление с числами до и после, поэтому действие видно в логе.
#
# Употребление:
#   bash lab/disk-report.sh            — быстрый отчёт: диск, RAM, pagefile
#   bash lab/disk-report.sh --full     — плюс TARGET_MB, INCREMENTAL_MB, CARGO_HOME_MB, LAB_LOGS_MB
#   bash lab/disk-report.sh --apply    — объявление + удаление кэша инкрементальной сборки
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

ram_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null | tr -d '\r' | tail -1; }
disk_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1; }
pagefile_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_PageFileUsage).PeakUsage / 1)" 2>/dev/null | tr -d '\r' | tail -1; }
size_mb() { [ -e "$1" ] && du -sm "$1" 2>/dev/null | cut -f1 || echo 0; }
incremental_mb() {
  local total=0 d s
  for d in "${ROOT}"/target/*/incremental; do
    [ -d "$d" ] || continue
    s=$(size_mb "$d"); total=$((total + s))
  done
  echo "$total"
}

quick() {
  printf 'DISK_FREE_MB=%s RAM_FREE_MB=%s PAGEFILE_PEAK_MB=%s\n' \
    "$(disk_mb)" "$(ram_mb)" "$(pagefile_mb)"
}

full() {
  printf 'DISK_FREE_MB=%s TARGET_MB=%s INCREMENTAL_MB=%s CARGO_HOME_MB=%s LAB_LOGS_MB=%s RAM_FREE_MB=%s PAGEFILE_PEAK_MB=%s\n' \
    "$(disk_mb)" "$(size_mb "$ROOT/target")" "$(incremental_mb)" \
    "$(size_mb "${CARGO_HOME:-$HOME/.cargo}")" "$(size_mb "$ROOT/lab/logs")" \
    "$(ram_mb)" "$(pagefile_mb)"
}

case "${1:-}" in
  ""|--report)
    quick
    ;;
  --full)
    full
    ;;
  --apply)
    before=$(disk_mb); cache=$(incremental_mb)
    if [ "$cache" -eq 0 ]; then
      echo "ОБЪЯВЛЕНИЕ: кэша инкрементальной сборки нет, удалять нечего; cargo clean не вызывался"
      quick
      exit 0
    fi
    echo "ОБЪЯВЛЕНИЕ: удаляется кэш инкрементальной сборки target/*/incremental (${cache} МБ) —"
    echo "это не cargo clean: зависимости и собранные бинарники остаются; свободный диск до ${before} МБ"
    for d in "${ROOT}"/target/*/incremental; do
      [ -d "$d" ] && rm -rf "$d"
    done
    after=$(disk_mb)
    echo "ВОЗВРАЩЕНО_MB=$((after - before)) DISK_FREE_MB_AFTER=$after"
    quick
    ;;
  *)
    echo "употребление: bash lab/disk-report.sh [--full|--apply]"
    exit 2
    ;;
esac
