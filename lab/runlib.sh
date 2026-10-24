#!/usr/bin/env bash
# Общая библиотека замерных helper'ов: разбор фактов, ресурсы, шаги, лог.
#
# Зачем: за 98 helper'ов один и тот же код (`val`, `grab`, `strip_run`, `run_to`, счёт RAM/диска)
# переписывался в каждом, и вместе с ним переезжали одни и те же дефекты — метка прогона в имени
# ключа (`E-0088`, `E-0100`), потерянный знак (`E-0084`), `tail` не от начала блока (`E-0087`).
# Здесь эти функции живут один раз и проверяются посаженными случаями:
#
#     bash lab/runlib.sh --selftest
#
# Helper нового цикла подключает библиотеку и не переписывает разбор:
#
#     . "$VEC_DHT_ROOT/lab/runlib.sh"
#
# Замороженные helper'ы прошлых циклов не переписываются: их текст — часть замерной истории.
# Совместимость: bash (process substitution, PIPESTATUS), как и сами helper'ы.

VEC_DHT_ROOT="${VEC_DHT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export VEC_DHT_ROOT

# --- ресурсы: три числа вместе; диск — производная давления на RAM (ДИАГНОЗ-2 `E-0088`) ---
ram_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null | tr -d '\r' | tail -1
}
disk_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1
}
pagefile_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_PageFileUsage).PeakUsage / 1)" 2>/dev/null | tr -d '\r' | tail -1
}
resources() {
  printf 'RAM_FREE_MB=%s DISK_FREE_MB=%s PAGEFILE_PEAK_MB=%s\n' "$(ram_mb)" "$(disk_mb)" "$(pagefile_mb)"
}

# --- разбор печатных фактов: ключ — токен, значение — до пробела, побеждает последний ---
val() { grep -oE "(^|[[:space:]])$2=[^[:space:]]*" "$1" | tail -1 | cut -d= -f2-; }
grab() { local f="$1" s="$2" k; for k in $3; do printf '%s_%s=%s\n' "$k" "$s" "$(val "$f" "$k")"; done; }
# Метка прогона вшивается в ИМЯ ключа, а не в значение: без снятия `cmp` разойдётся на неизменном
# дереве (`E-0100`, ДИАГНОЗ-1).
strip_run() { sed -E 's/_(r[0-9]+)=/=/g' "$1"; }
# Сверка двух векторов по карте ключ->значение, а не по байтам: печатает REPRO_VECTOR=1|0.
facts_repro() { python "$VEC_DHT_ROOT/lab/facts.py" repro "$1" "$2" --strip-run; }

# --- шаги и лог: блок считается от отметки начала, иначе ожидание удовлетворит старый прогон ---
log_begin() { BLOCK_START=$(wc -l < "$LOG"); }
block() { tail -n +"$((BLOCK_START + 1))" "$LOG"; }
run_to() { # $1=файл шага («-» = временный) $2=label; rest=команда
  local f="$1" label="$2" tmp="" rc
  shift 2
  if [ "$f" = "-" ]; then f=$(mktemp); tmp="$f"; fi
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$f" 2>&1; rc=$?
  cat "$f" | tee -a "$LOG"
  [ -n "$tmp" ] && rm -f "$tmp"
  echo "EXIT=$rc" | tee -a "$LOG"
  if [ "$rc" -gt "${WORST_RC:-0}" ]; then WORST_RC=$rc; fi
  return $rc
}

selftest() {
  local total=0 bad=0 d f1 f2 rc got
  d=$(mktemp -d)
  f1="$d/n1.txt"; f2="$d/n2.txt"
  check() { # $1=имя $2=ждали $3=получили
    total=$((total + 1))
    if [ "$2" = "$3" ]; then echo "СЕЛФТЕСТ ok: $1"
    else bad=$((bad + 1)); echo "СЕЛФТЕСТ ПРОВАЛ: $1: ждали «$2», получили «$3»"; fi
  }
  printf 'A=1\nPRE_FIX_A=2\nA=3\n' > "$f1"
  check "val: последний факт побеждает" "3" "$(val "$f1" A)"
  check "val: чужой префикс не подменяет" "3" "$(val "$f1" A)"
  printf 'B=7\n' > "$f1"
  check "grab: метка в имени ключа" "B_r1=7" "$(grab "$f1" r1 "B")"
  printf 'B_r1=7\n' > "$f1"
  check "strip_run: метка снята" "B=7" "$(strip_run "$f1" | head -1)"
  printf 'A_r1=1\nC_r1=x\n' > "$f1"; printf 'A_r2=1\nC_r2=x\n' > "$f2"
  got=$(facts_repro "$f1" "$f2" | grep -E '^REPRO_VECTOR=' )
  check "facts_repro: метки не мешают совпадению" "REPRO_VECTOR=1" "$got"
  printf 'A_r2=2\nC_r2=x\n' > "$f2"
  got=$(facts_repro "$f1" "$f2" | grep -E '^REPRO_VECTOR=' )
  check "facts_repro: расхождение видно" "REPRO_VECTOR=0" "$got"
  got=$(resources)
  if [[ "$got" =~ ^RAM_FREE_MB=[0-9]+\ DISK_FREE_MB=[0-9]+\ PAGEFILE_PEAK_MB=[0-9]+$ ]]; then
    check "resources: три числа вместе" "ok" "ok"
  else
    check "resources: три числа вместе" "ok" "$got"
  fi
  rm -rf "$d"
  echo "RUNLIB_SELFTEST total=$total passed=$((total - bad))"
  [ "$bad" -eq 0 ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --selftest) selftest ;;
    *) echo "употребление: bash lab/runlib.sh --selftest (подключается через . из helper'а)"; exit 2 ;;
  esac
fi
