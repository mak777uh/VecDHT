#!/usr/bin/env bash
# E-0092: релиз-блокер (3), часть B — denylist переживает перезапуск и имеет предел (§11.4 (ii),
# ADR-0009, ADR-0044 «конечность кэшей»). Единица цикла — факт и число (длина списка после
# повторного открытия каталога, размер файла запрета, код отказа на проводе, исход 4097-го
# внесения), не время: временных предсказаний в пороге нет, поэтому правило 7 (д) здесь работает
# как запрет на временные гейты, а не как проверка запаса.
#
# Пороги заморожены в `lab/hypotheses/H-0092-denylist-durable-and-bounded.md` и в assert'ах
# оракула `crates/vecdht-node/tests/denylist_durable_after_restart.rs`. Helper ничего из них не
# пересчитывает: снимает напечатанные оракулом ключи `g*`, сверяет вектор фактов между двумя
# прогонами и проверяет expectation'ы гейтов таблицей `EXPECT`.
#
# Встроенные уроки метода: (а) helper исполняет свою неизменяемую mktemp-копию, корень репо —
# через VEC_DHT_ROOT; (б) ресурсы меряются до сборки, после каждого прогона и в ИТОГЕ, метки —
# ASCII; (в) регрессия идёт с `--no-fail-fast` (ДИАГНОЗ-2 из `E-0087`); (г) контроль append-only
# лога берётся `tail -1` (ДИАГНОЗ-3 из `E-0087`); (д) векторы двух прогонов сверяются ПОСЛЕ
# снятия метки прогона с имени ключа (ДИАГНОЗ-1 из `E-0088`); (е) осевшие каталоги считаются
# после прогона (ДИАГНОЗ-2 из `E-0085`, здесь каталог снимается Drop'ом `Tmp`); (ж) `cargo clean`
# не исполняется, свободный диск меряется до замера (порог (13)); (з) каждый ключ порога
# воспроизводимости обязан быть инвариантен к расписанию шагов (ДИАГНОЗ из `E-0091`: вектор с
# счётчиками, зависящими от расписания, порог не проходит).
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0092-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0092-all.log"
PREFIX="lab/logs/e0092-oracle-before-fix.txt"
ORACLE=crates/vecdht-node/tests/denylist_durable_after_restart.rs
DISK_MIN=15000
DIR_TAG=deny-durable

# Ключи оракула: только длины, размер файла и коды. Временем здесь ничего не печатается.
FACT_KEYS="g1_len g1_denied g1_hits g1_code g2_file g2_bytes g2_want
g3_epoch g3_len g3_denied g4_denied g4_allow g4_wire g5_undenied g5_len g5_revoked g5_kept
g6_accepted g6_refused g6_len g6_first_before g6_first_kept g6b_len g6b_room"

# Предсказания гейтов (1)…(6) карточки: знак «=» в значении не используется. `g4_wire` —
# факт, а не предсказание правки: узел после рестарта без lease отвечает `EPOCH_STALE` и до,
# и после неё (форма гейта (4) в карточке), поэтому ожиданием правки он не становится.
EXPECT="g1_len=3 g1_denied=3 g1_hits=1 g1_code=DENIED g2_file=1 g2_bytes=114 g2_want=114
g3_epoch=1 g3_len=3 g3_denied=3 g4_denied=true g4_allow=true g5_undenied=1 g5_len=2
g5_revoked=0 g5_kept=2 g6_accepted=4096 g6_refused=0 g6_len=4096 g6_first_before=true
g6_first_kept=4096 g6b_len=4096 g6b_room=1"

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
  echo "########## E-0092 · denylist переживает перезапуск и имеет предел · прогон $(date +%FT%T%:z) ##########"
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "oracle: $ORACLE"
  echo "RAM_FREE_MB_BEFORE=$(free_ram_mb) DISK_FREE_MB_BEFORE=$(free_disk_mb)"
} >> "$LOG"

# Шаг 0 — предсказание на дереве ДО правки. Снимок лежит в репозитории (append-only); helper
# только контролирует: `EXIT` обязан быть 101, `g2_file` и `g3_len` — нулями (дыра `E-0042`).
{ echo "### ШАГ 0 PRE_FIX (дерево до правки, $PREFIX) ###"
  if [ -s "$PREFIX" ]; then
    echo "prefix_test_result=$(grep -E 'test result' "$PREFIX" | tail -1)"
    echo "prefix_exit=$(grep -E '^EXIT=' "$PREFIX" | tail -1)"
    echo "prefix_g1_len=$(val "$PREFIX" g1_len)"
    echo "prefix_g2_file=$(val "$PREFIX" g2_file)"
    echo "prefix_g3_len=$(val "$PREFIX" g3_len)"
    echo "prefix_g4_denied=$(val "$PREFIX" g4_denied)"
    echo "prefix_g4_wire=$(val "$PREFIX" g4_wire)"
    echo "prefix_g6_refused=$(val "$PREFIX" g6_refused)"
  else
    echo "ВНИМАНИЕ: снимок PRE_FIX отсутствует — порог (3) не может быть проверен"
  fi
} >> "$LOG"

# Диск меряется ДО замера (порог (13)): цикл не вправе начинать сборку, если допуск не выполнен.
DISK_BEFORE=$(free_disk_mb)
{ echo "### ШАГ 0а диск и RAM до замера ###"
  echo "DISK_FREE_MB=$DISK_BEFORE TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

run_to "$R1" "ШАГ 1 оракул, прогон n=1" cargo test -p vecdht-node --test denylist_durable_after_restart --no-fail-fast -- --nocapture --test-threads=1
{ echo "### ВЕКТОР ПОРОГОВ n=1 ###"; grab "$R1" r1 "$FACT_KEYS"; } >> "$LOG"

run_to "$R2" "ШАГ 2 оракул, прогон n=2 (порог (11): вектор фактов обязан совпасть)" cargo test -p vecdht-node --test denylist_durable_after_restart --no-fail-fast -- --nocapture --test-threads=1
{ echo "### ВЕКТОР ПОРОГОВ n=2 ###"; grab "$R2" r2 "$FACT_KEYS"; } >> "$LOG"

grab "$R1" r1 "$FACT_KEYS" > "$F1"
grab "$R2" r2 "$FACT_KEYS" > "$F2"

# Шаг 3 — регрессия по соседям (порог (10)): весь `vecdht-node`, включая оракул дыры
# `denylist_reachability.rs` (его пост-рестартные assert'ы перевёрнуты в фиксе) и юнит-тесты
# `admission.rs`.
run_to "$REG" "ШАГ 3 регрессия: весь vecdht-node (--no-fail-fast)" cargo test -p vecdht-node --no-fail-fast
{ echo "### РЕГРЕССИЯ ###"
  grep -E "^test result|^error" "$REG" | tail -40
  echo "reg_failed=$(grep -oE '[0-9]+ failed' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "reg_ignored=$(grep -oE '[0-9]+ ignored' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "reg_passed=$(grep -oE '[0-9]+ passed' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "reg_reachability=$(grep -E 'denylist' "$REG" | tail -4)"
} >> "$LOG"

{ echo "### КОНТРОЛЬ ПОРОГОВ ###"
  echo "порог (4) оракул зелёный: n1=$(grep -E 'test result' "$R1" | tail -1) | n2=$(grep -E 'test result' "$R2" | tail -1)"
  miss=0
  for e in $EXPECT; do
    k=${e%%=*}; want=${e#*=}; got=$(get "${k}_r1" "$F1")
    if [ "$got" != "$want" ]; then echo "гейт НЕ выполнен: $k ожидалось=$want получено=$got"; miss=$((miss+1)); fi
  done
  echo "порог (5) гейты (1)…(6): расхождений=$miss из $(echo "$EXPECT" | wc -w)"
  echo "порог (3) дыра до правки: prefix_exit=$(grep -E '^EXIT=' "$PREFIX" | tail -1) prefix_g2_file=$(val "$PREFIX" g2_file) prefix_g3_len=$(val "$PREFIX" g3_len)"
  echo "порог (6) переживаемость закрыта: g3_len=$(get g3_len_r1 "$F1") g3_denied=$(get g3_denied_r1 "$F1") g4_denied=$(get g4_denied_r1 "$F1") g4_wire=$(get g4_wire_r1 "$F1")"
  echo "порог (7) цена = файл 18+32N: g2_file=$(get g2_file_r1 "$F1") g2_bytes=$(get g2_bytes_r1 "$F1")"
  echo "порог (8) снятие переживает: g5_len=$(get g5_len_r1 "$F1") g5_revoked=$(get g5_revoked_r1 "$F1") g5_kept=$(get g5_kept_r1 "$F1")"
  echo "порог (9) предел отказывает: g6_accepted=$(get g6_accepted_r1 "$F1") g6_refused=$(get g6_refused_r1 "$F1") g6_len=$(get g6_len_r1 "$F1") g6_first_kept=$(get g6_first_kept_r1 "$F1") g6b_room=$(get g6b_room_r1 "$F1")"
  echo "порог (10) регрессия: failed=$(grep -oE '[0-9]+ failed' "$REG" | awk '{s+=$1} END {print s+0}') ignored=$(grep -oE '[0-9]+ ignored' "$REG" | awk '{s+=$1} END {print s+0}')"
  # Метка прогона снимается с имени ключа ПЕРЕД сравнением (ДИАГНОЗ-1 из `E-0088`).
  echo "порог (11) repro_fact_keys=$( [ -s "$F1" ] && cmp -s <(sed 's/_r1=/=/' "$F1") <(sed 's/_r2=/=/' "$F2") && echo 1 || echo 0)"
  echo "порог (13) осевшие_каталоги=$(ls "${TMPDIR:-/tmp}" 2>/dev/null | grep -c "$DIR_TAG") disk_ok=$( [ "${DISK_BEFORE:-0}" -ge "$DISK_MIN" ] && echo 1 || echo 0)"
  echo "порог (14) contour=$(python lab/library.py value --cycles 5 2>/dev/null | grep LIBVALUE | tail -1)"
  echo "RAM_FREE_MB_AFTER=$(free_ram_mb) DISK_FREE_MB_AFTER=$(free_disk_mb)"
  echo "TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

rm -f "$R1" "$R2" "$REG" "$F1" "$F2"
echo "=== E-0092 готов; WORST_RC=$WORST_RC ==="
exit "$WORST_RC"

