#!/usr/bin/env bash
# E-0091: релиз-блокер (3), часть A — таблица провайдеров шарда конечна (§7.4, §P5, §9.8;
# ADR-0044 «конечность кэшей»). Единица цикла — факт и счётчик (есть ли мёртвый пир в таблице,
# длина таблицы, число снятых/вытесненных/истёкших записей), не время: временных предсказаний в
# вердикте нет, поэтому правило 7 (д) к этому циклу применяется только как запрет на временные
# гейты, а не как проверка запаса.
#
# Пороги заморожены в `lab/hypotheses/H-0091-provider-cache-finite.md` и в assert'ах оракула
# `crates/vecdht-net/tests/s74_provider_cache_finite.rs`. Helper ничего из них не пересчитывает:
# он снимает напечатанные оракулом ключи `g*`, сверяет вектор фактов между двумя прогонами и
# считает нуль/ненуль по bound'ам.
#
# Встроенные уроки метода: (а) helper исполняет свою неизменяемую mktemp-копию, корень репо —
# через VEC_DHT_ROOT; (б) ресурсы меряются до сборки, после каждого прогона и в ИТОГЕ, метки —
# ASCII; (в) регрессия идёт с `--no-fail-fast` (ДИАГНОЗ-2 из `E-0087`); (г) контроль append-only
# лога берётся `tail -1` (ДИАГНОЗ-3 из `E-0087`); (д) векторы фактов двух прогонов сверяются ПОСЛЕ
# снятия метки прогона с имени ключа (ДИАГНОЗ-1 из `E-0088`: иначе порог воспроизводимости
# невыполним по построению); (е) осевшие каталоги считаются после прогона (ДИАГНОЗ-2 из `E-0085`);
# (ж) `cargo clean` не исполняется, свободный диск меряется до замера (порог (13)).
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0091-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0091-all.log"
PREFIX="lab/logs/e0091-oracle-before-fix.txt"
ORACLE=crates/vecdht-net/tests/s74_provider_cache_finite.rs
LIVE=1        # живых провайдеров шарда в стенде после смерти A
DISK_MIN=15000

# Ключи оракула: только факты и счётчики. Временем здесь ничего не печатается.
FACT_KEYS="g1_cache_len g1_kad_peers g1_announce_a g1_announce_b
g3_has_dead_at_death g3_has_dead_after g4_live_present g5_len_at_death g5_len_after
g5_kad_peers g5_errors_total g5_dial_errors g6_after_prune g6_after_requery g6_dead_back"

WORST_RC=0

run_to() { # $1=файл шага («-» = временный) $2=label; rest=команда
  local f="$1" label="$2" tmp=""; shift 2
  local rc
  if [ "$f" = "-" ]; then f=$(mktemp); tmp="$f"; fi
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$f" 2>&1; rc=$?
  cat "$f" | tee -a "$LOG"
  [ -n "$tmp" ] && rm -f "$tmp"
  echo "EXIT=$rc" | tee -a "$LOG"
  if [ "$rc" -gt "$WORST_RC" ]; then WORST_RC=$rc; fi
  return $rc
}

free_ram_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null \
    | tr -d '\r' | tail -1
}

free_disk_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1
}

# Экстрактор по подписям печати: ключ ascii, за ним `=`, одно слово значения; граница перед ключом
# обязательна (ДИАГНОЗ-4 из `E-0082`), контроль append-only берётся последним вхождением.
val() { grep -oE "(^|[[:space:]])$2=[^[:space:]]*" "$1" | tail -1 | cut -d= -f2-; }
grab() { local f="$1" s="$2" k; for k in $3; do printf '%s_%s=%s\n' "$k" "$s" "$(val "$f" "$k")"; done; }
get() { grep "^$1=" "$2" | tail -1 | cut -d= -f2-; }
eq() { if [ -n "$1" ] && [ "$1" = "$2" ]; then echo 1; else echo 0; fi; }

R1=$(mktemp); R2=$(mktemp); REG=$(mktemp); F1=$(mktemp); F2=$(mktemp)
{ echo
  echo "########## E-0091 · таблица провайдеров шарда конечна · прогон $(date +%FT%T%:z) ##########"
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "oracle: $ORACLE"
  echo "RAM_FREE_MB_BEFORE=$(free_ram_mb) DISK_FREE_MB_BEFORE=$(free_disk_mb)"
} >> "$LOG"

# Шаг 0 — предсказание на дереве ДО правки. Снимок лежит в репозитории (append-only), helper
# только контролирует: последний `test result` обязан быть `1 passed; 1 failed`, числа дыры
# (`g3_has_dead_after=1`, `g5_len_after=2`) обязаны быть в снимке, а `EXIT` — 101.
{ echo "### ШАГ 0 PRE_FIX (дерево до правки, $PREFIX) ###"
  if [ -s "$PREFIX" ]; then
    echo "prefix_test_result=$(grep -E 'test result' "$PREFIX" | tail -1)"
    echo "prefix_dead_after=$(val "$PREFIX" g3_has_dead_after)"
    echo "prefix_len_after=$(val "$PREFIX" g5_len_after)"
    echo "prefix_live=$(val "$PREFIX" g4_live_present)"
    echo "prefix_exit=$(grep -E '^EXIT=' "$PREFIX" | tail -1)"
    echo "prefix_g6=$(val "$PREFIX" g6_dead_back)"
  else
    echo "ВНИМАНИЕ: снимок PRE_FIX отсутствует — порог (3) не может быть проверен"
  fi
} >> "$LOG"

# Диск меряется ДО замера (порог (13)): цикл с прогонами не вправе начинать сборку, если допуск не
# выполнен, — цена `E-0086`/`E-0088` описана в PLAN п. 8в.
DISK_BEFORE=$(free_disk_mb)
{ echo "### ШАГ 0а диск и RAM до замера ###"
  echo "DISK_FREE_MB=$DISK_BEFORE TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

run_to "$R1" "ШАГ 1 оракул, прогон n=1" cargo test -p vecdht-net --test s74_provider_cache_finite --no-fail-fast -- --nocapture --test-threads=1
{ echo "### ВЕКТОР ПОРОГОВ n=1 ###"; grab "$R1" r1 "$FACT_KEYS"; } >> "$LOG"

run_to "$R2" "ШАГ 2 оракул, прогон n=2 (порог (11): вектор фактов обязан совпасть)" cargo test -p vecdht-net --test s74_provider_cache_finite --no-fail-fast -- --nocapture --test-threads=1
{ echo "### ВЕКТОР ПОРОГОВ n=2 ###"; grab "$R2" r2 "$FACT_KEYS"; } >> "$LOG"

grab "$R1" r1 "$FACT_KEYS" > "$F1"
grab "$R2" r2 "$FACT_KEYS" > "$F2"

# Шаг 3 — регрессия по соседям (порог (10)): весь `vecdht-net`, включая `transport.rs`, который
# ждёт живого провайдера в `provider_peers`, и `s53_door_branches.rs` с перевёрнутым блоком `(в)`.
run_to "$REG" "ШАГ 3 регрессия: весь vecdht-net (--no-fail-fast)" cargo test -p vecdht-net --no-fail-fast
{ echo "### РЕГРЕССИЯ ###"
  grep -E "^test result|^error" "$REG" | tail -40
  echo "reg_failed=$(grep -oE '[0-9]+ failed' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "reg_ignored=$(grep -oE '[0-9]+ ignored' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "reg_passed=$(grep -oE '[0-9]+ passed' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "reg_s53=$(grep -E 's53_door_branches' "$REG" | tail -2)"
} >> "$LOG"

{ echo "### КОНТРОЛЬ ПОРОГОВ ###"
  echo "порог (4) оракул зелёный: n1=$(grep -E 'test result' "$R1" | tail -1) | n2=$(grep -E 'test result' "$R2" | tail -1)"
  echo "порог (5) bound: g5_len_after=$(get g5_len_after_r1 "$F1") ожидание=$LIVE ok=$(eq "$(get g5_len_after_r1 "$F1")" "$LIVE")"
  echo "порог (3) дыра до правки: prefix_exit=$(grep -E '^EXIT=' "$PREFIX" | tail -1) prefix_dead_after=$(val "$PREFIX" g3_has_dead_after)"
  echo "порог (3) дыра закрыта после правки: g3_has_dead_after=$(get g3_has_dead_after_r1 "$F1") g4_live_present=$(get g4_live_present_r1 "$F1")"
  echo "порог (6) граница переспроса (только факт): g6_after_prune=$(get g6_after_prune_r1 "$F1") g6_after_requery=$(get g6_after_requery_r1 "$F1") g6_dead_back=$(get g6_dead_back_r1 "$F1")"
  echo "порог (10) регрессия: failed=$(grep -oE '[0-9]+ failed' "$REG" | awk '{s+=$1} END {print s+0}') ignored=$(grep -oE '[0-9]+ ignored' "$REG" | awk '{s+=$1} END {print s+0}')"
  # Метка прогона снимается с имени ключа ПЕРЕД сравнением (ДИАГНОЗ-1 из `E-0088`: `grab` вшивает
  # `_r1`/`_r2` в имя, и сырое `cmp` различалось всегда).
  echo "порог (11) repro_fact_keys=$( [ -s "$F1" ] && cmp -s <(sed 's/_r1=/=/' "$F1") <(sed 's/_r2=/=/' "$F2") && echo 1 || echo 0)"
  echo "порог (13) осевшие_каталоги=$(ls "${TMPDIR:-/tmp}" 2>/dev/null | grep -c 'vecdht-s74-') disk_ok=$( [ "${DISK_BEFORE:-0}" -ge "$DISK_MIN" ] && echo 1 || echo 0)"
  echo "порог (14) contour=$(python lab/library.py value --cycles 5 2>/dev/null | grep LIBVALUE | tail -1)"
  echo "RAM_FREE_MB_AFTER=$(free_ram_mb) DISK_FREE_MB_AFTER=$(free_disk_mb)"
  echo "TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

rm -f "$R1" "$R2" "$REG" "$F1" "$F2"
echo "=== E-0091 готов; WORST_RC=$WORST_RC ==="
exit "$WORST_RC"
