#!/usr/bin/env bash
# E-0094: релиз-блокер (4), часть A — переживаемость множества отозванных nonce перезапуском
# (§4.2:155 и §4.2:181, ADR-0050, ADR-0044 «двусторонний отзыв»). Единица цикла — факт и число
# (длина множества у второго сервиса, размер файла состояния, булевы решения двери и факт
# аутентификации), не время: временных предсказаний в пороге нет.
#
# Пороги заморожены в `lab/hypotheses/H-0094-revocation-durable-after-restart.md` и в assert'ах
# оракула `crates/vecdht-net/tests/revocation_durable_after_restart.rs`. Helper ничего из них не
# пересчитывает: снимает напечатанные оракулом ключи `rv_*`, сверяет вектор фактов между двумя
# прогонами и проверяет ожидания таблицей `lab/expectations/e0094.tsv` (`python lab/expect.py`).
#
# Встроенные уроки метода:
#  (а) helper исполняет свою неизменяемую mktemp-копию, корень репо — через VEC_DHT_ROOT;
#  (б) ресурсы меряются до сборки, после каждого прогона и в ИТОГЕ, метки — ASCII (pagefile обязано
#      быть в тройке чисел: свободный диск — производная от давления на RAM, ДИАГНОЗ-2 из `E-0088`);
#  (в) регрессия идёт с `--no-fail-fast` (ДИАГНОЗ-2 из `E-0087`);
#  (г) контроль append-only лога берётся `tail -1` (ДИАГНОЗ-3 из `E-0087`);
#  (д) векторы двух прогонов сравниваются БЕЗ колонок времени: время объявлено ценой прогона, а
#      равенствный гейт по цене — дефект гейта (ДИАГНОЗ-6 из `E-0093`);
#  (е) осевшие каталоги считаются после прогона (ДИАГНОЗ-2 из `E-0085`, здесь каталог снимается
#      Drop'ом `Tmp`);
#  (ж) `cargo clean` не исполняется, свободный диск меряется до замера;
#  (з) каждый ключ порога воспроизводимости обязан быть инвариантен к расписанию шагов
#      (ДИАГНОЗ из `E-0091`);
#  (и) expectations живут файлом и сверяются исполнением, а не памятью (правило (к) п. 8в).
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0094-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0094-all.log"
PREFIX="lab/logs/e0094-oracle-before-fix.txt"
ORACLE=crates/vecdht-net/tests/revocation_durable_after_restart.rs
EXPECT="lab/expectations/e0094.tsv"
DISK_MIN=15000
DIR_TAG=vecdht-e0094
mkdir -p lab/logs

# Ключи оракула: только длины, размер файла и булевы решения. Временем здесь ничего не печатается.
FACT_KEYS="rv_g0_primary_shard7 rv_g0_primary_shard9 rv_g0_carrier rv_g0_watcher
rv_g1_count_before rv_g1_file_before rv_g1_carrier_knows rv_g1b_denied_before_restart
rv_g2_count_after rv_g2_knows_after rv_g2_file_after rv_g2_addr_changed
rv_g3_accepted_after_restart rv_g3_carrier_self_revoked rv_g3_watcher2_count
rv_g4_fresh_dir_knows rv_g4_fresh_dir_count rv_g4_fresh_file
rv_g5_self_revoked rv_g5_silent_send rv_g5_count rv_g5_file_before
rv_g6_self_revoked_after rv_g6_serves_after_restart rv_g6_peer_agrees rv_g6_count_after
rv_g6_file_after rv_g6_load_errors rv_g7_fresh_control_serves rv_g7_control_self_revoked
rv_g7_control_file"

ram_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null | tr -d '\r' | tail -1; }
disk_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1; }
pagefile_mb() { powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_PageFileUsage).PeakUsage / 1)" 2>/dev/null | tr -d '\r' | tail -1; }

# Экстрактор по подписям печати: ключ ascii, за ним `=`, одно слово значения; граница перед ключом
# обязательна, контроль append-only берётся последним вхождением.
val() { grep -oE "(^|[[:space:]])$2=[^[:space:]]*" "$1" | tail -1 | cut -d= -f2-; }
grab() { local f="$1" s="$2" k; for k in $3; do printf '%s_%s=%s\n' "$k" "$s" "$(val "$f" "$k")"; done; }
strip_run() { sed -E 's/_(r1|r2)=/=/g' "$1"; }

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

R1=$(mktemp); R2=$(mktemp); REGN=$(mktemp); REGD=$(mktemp); F1=$(mktemp); F2=$(mktemp)
{ echo
  echo "########## E-0094 · переживаемость отзыва перезапуском · прогон $(date +%FT%T%:z) ##########"
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "oracle: $ORACLE"
  echo "RAM_FREE_MB_BEFORE=$(ram_mb) DISK_FREE_MB_BEFORE=$(disk_mb) PAGEFILE_PEAK_MB=$(pagefile_mb)"
} >> "$LOG"
# Нумерация строк на старте блока: контроль и сверка читают ТОЛЬКО текущий блок, иначе ожидание
# мог бы удовлетворить факт из прошлого прогона (append-only, ДИАГНОЗ-3 из `E-0087`).
BLOCK_START=$(wc -l < "$LOG")
block() { tail -n +"$((BLOCK_START + 1))" "$LOG"; }

# Шаг 0 — предсказание на дереве ДО правки: снимок лежит в репозитории (append-only), helper только
# контролирует, что дыра в нём напечатана числом, а не молчанием.
{ echo "### ШАГ 0 PRE_FIX (дерево до правки, $PREFIX) ###"
  if [ -s "$PREFIX" ]; then
    echo "prefix_test_result=$(grep -E 'test result' "$PREFIX" | tail -1)"
    echo "prefix_exit=$(val "$PREFIX" EXIT)"
    echo "prefix_g1_file=$(val "$PREFIX" rv_g1_file_before)"
    echo "prefix_g2_count=$(val "$PREFIX" rv_g2_count_after)"
    echo "prefix_g3_accepted=$(val "$PREFIX" rv_g3_accepted_after_restart)"
    echo "prefix_g6_self_revoked=$(val "$PREFIX" rv_g6_self_revoked_after)"
    echo "prefix_g6_serves=$(val "$PREFIX" rv_g6_serves_after_restart)"
    echo "prefix_g7_control=$(val "$PREFIX" rv_g7_fresh_control_serves)"
    echo "prefix_g4_fresh=$(val "$PREFIX" rv_g4_fresh_dir_knows)"
  else
    echo "ВНИМАНИЕ: снимок PRE_FIX отсутствует — порог (1) не может быть проверен"
  fi
} >> "$LOG"

# Диск меряется ДО замера: цикл не вправе начинать сборку, если допуск не выполнен.
DISK_BEFORE=$(disk_mb)
{ echo "### ШАГ 0а диск и RAM до замера ###"
  echo "DISK_FREE_MB=$DISK_BEFORE TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

run_to "$R1" "ШАГ 1 оракул, прогон n=1" cargo test -p vecdht-net --test revocation_durable_after_restart --no-fail-fast -- --nocapture --test-threads=1
echo "run1_exit=$?" >> "$LOG"
{ echo "### ВЕКТОР ПОРОГОВ n=1 ###"; grab "$R1" r1 "$FACT_KEYS"; } >> "$LOG"

run_to "$R2" "ШАГ 2 оракул, прогон n=2 (порог (8): вектор фактов обязан совпасть)" cargo test -p vecdht-net --test revocation_durable_after_restart --no-fail-fast -- --nocapture --test-threads=1
echo "run2_exit=$?" >> "$LOG"
{ echo "### ВЕКТОР ПОРОГОВ n=2 ###"; grab "$R2" r2 "$FACT_KEYS"; } >> "$LOG"

grab "$R1" r1 "$FACT_KEYS" > "$F1"
grab "$R2" r2 "$FACT_KEYS" > "$F2"

# Шаг 3 — регрессия по соседям (порог (9)): сначала юнит-тесты модуля состояния и оракул дыры в
# `vecdht-node`, потом весь `vecdht-net`, включая прежние стенды двери (`s53_door_branches.rs`,
# `gossip_door_parity.rs`, `transport.rs`): фикс касается их `NetConfig` механически.
run_to "$REGD" "ШАГ 3а регрессия: vecdht-node (--no-fail-fast)" cargo test -p vecdht-node --no-fail-fast
run_to "$REGN" "ШАГ 3б регрессия: vecdht-net (--no-fail-fast)" cargo test -p vecdht-net --no-fail-fast

{ echo "### РЕГРЕССИЯ ###"
  grep -E "^test result|^error" "$REGN" | tail -40
  echo "reg_net_failed=$(grep -oE '[0-9]+ failed' "$REGN" | awk '{s+=$1} END {print s+0}')"
  echo "reg_net_passed=$(grep -oE '[0-9]+ passed' "$REGN" | awk '{s+=$1} END {print s+0}')"
  echo "reg_net_ignored=$(grep -oE '[0-9]+ ignored' "$REGN" | awk '{s+=$1} END {print s+0}')"
} >> "$LOG"
echo "reg_node_failed=$(grep -oE '[0-9]+ failed' "$REGD" | awk '{s+=$1} END {print s+0}')" >> "$LOG"

{ echo "### КОНТРОЛЬ ПОРОГОВ ###"
  echo "порог (2)…(7) оракул зелёный: n1=$(grep -E 'test result' "$R1" | tail -1) | n2=$(grep -E 'test result' "$R2" | tail -1)"
  echo "порог (1) дыра до правки: prefix_exit=$(val "$PREFIX" EXIT) rv_g1_file_before=$(val "$PREFIX" rv_g1_file_before) rv_g2_count_after=$(val "$PREFIX" rv_g2_count_after) rv_g3_accepted_after_restart=$(val "$PREFIX" rv_g3_accepted_after_restart) rv_g6_serves_after_restart=$(val "$PREFIX" rv_g6_serves_after_restart)"
  echo "порог (8) repro_вектор=$(cmp -s <(strip_run "$F1") <(strip_run "$F2") && echo совпал || echo РАЗОШЁЛСЯ)"
  echo "порог (9) регрессия: reg_node_failed=$(grep -oE '[0-9]+ failed' "$REGD" | awk '{s+=$1} END {print s+0}') reg_net_failed=$(grep -oE '[0-9]+ failed' "$REGN" | awk '{s+=$1} END {print s+0}') ignored=$(grep -oE '[0-9]+ ignored' "$REGN" | awk '{s+=$1} END {print s+0}')"
  echo "порог (13) осевшие_каталоги=$(ls "${TMPDIR:-/tmp}" 2>/dev/null | grep -c "$DIR_TAG") disk_ok=$( [ "${DISK_BEFORE:-0}" -ge "$DISK_MIN" ] && echo 1 || echo 0)"
  echo "порог (14) contour=$(python lab/library.py value --cycles 5 2>/dev/null | grep LIBVALUE | tail -1)"
} >> "$LOG"

# Шаг 4 — сверка печатных фактов с замороженной таблицей. В корпус идут оба вывода оракула и
# строки контроля helper'а: ключ ищется токеном, поэтому чужая строка ожидание не удовлетворит.
CORP=$(mktemp)
grep -hE '^(RV_|run1_exit|run2_exit|repro_вектор|reg_net_failed|reg_node_failed)' "$R1" "$R2" > "$CORP" 2>/dev/null || true
block >> "$CORP"
{ echo "### ШАГ 4 СВЕРКА: $EXPECT против напечатанных фактов ###"
  python lab/expect.py "$EXPECT" "$CORP"
  echo "СВЕРКА_EXIT=$?"
} >> "$LOG"

{ echo "МЕРЕНО после: RAM_FREE_MB=$(ram_mb) DISK_FREE_MB=$(disk_mb) PAGEFILE_PEAK_MB=$(pagefile_mb) TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
  echo "########## E-0094 · конец блока ##########"
} >> "$LOG"

rm -f "$R1" "$R2" "$REGN" "$REGD" "$F1" "$F2" "$CORP"
echo "=== E-0094 готов; WORST_RC=$WORST_RC ==="
exit "$WORST_RC"
