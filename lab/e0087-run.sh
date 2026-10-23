#!/usr/bin/env bash
# E-0087: фикс ADR-0043 — у gossip-пути те же права, что у прямого. Цикл релизной очереди
# Batch A (релиз-блокер 1), первый цикл, где единица — «замеренная дыра → фикс → тот же замер
# как регрессия», а не «гипотеза → замер».
#
# Пороги заморожены в `lab/hypotheses/H-0087-gossip-door-parity.md` и в assert'ах оракула
# `crates/vecdht-net/tests/gossip_door_parity.rs`. Helper ничего из них не пересчитывает: он
# снимает напечатанные оракулом ключи `o*` и сверяет blake3-свёртку `o12_digest` между прогонами.
#
# Единица цикла — факт, не время: временных гейтов нет, поэтому правило 7 (запас против разброса)
# здесь не применяется, а его роль исполняет воспроизводимость свёртки (порог (6)).
#
# Уроки, встроенные в метод: (а) helper исполняет свою неизменяемую mktemp-копию (ДИАГНОЗ-6 из
# `e0079`), корень репо — через VEC_DHT_ROOT; (б) ресурсы — часть метода (указание владельца):
# RAM и диск меряются до сборки, после каждого прогона и в ИТОГЕ, метки — ASCII (кириллица в
# выводе PowerShell бьёт кодовую страницу: цифры верны, подписи нет); (в) временные каталоги теста
# закрываются Drop-гардом, а helper проверяет это счётчиком осевших каталогов (ДИАГНОЗ-2 из
# `E-0085`: 13 каталогов осталось, потому что очистка была в конце тела теста); (г) `cargo clean`
# без объявления не исполняется.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0087-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0087-all.log"
ORACLE=crates/vecdht-net/tests/gossip_door_parity.rs

# Ключи оракула: (О1) отказ + сохранение прямого DENIED, (О2) gossip не лёг, (О3) два
# положительных контроля, (О4) кадр членства не отфильтрован, свёртка фактов.
KEYS="o1_refused o1_direct_code o2_gossip_landed o2_stored o2_gate_publish o2_gate_find
o2_find_gated o12_digest o3_stored o3_gate_hits o3_agent_stored o3_agent_gate_hits o4_gated"
# ПОПРАВКА (ДИАГНОЗ-1): печатается и отдельный ключ стражи §5.3 — он факт продукта, а не
# предсказание фикса, поэтому в KEYS (и в свёртку) не входит, но в лог обязан попасть.
EXTRA_KEYS="o2_unsigned_guard"

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

# Экстрактор по подписям печати: ключ ascii, за ним `=` и одно слово значения; граница перед
# ключом обязательна (ДИАГНОЗ-4 из `E-0082`), `-f2-` сохраняет значение целиком.
val() { grep -oE "(^|[[:space:]])$2=[^[:space:]]*" "$1" | tail -1 | cut -d= -f2-; }
grab() { local f="$1" s="$2" k; for k in $3; do printf '%s_%s=%s\n' "$k" "$s" "$(val "$f" "$k")"; done; }
get() { grep "^$1=" "$2" | head -1 | cut -d= -f2-; }
eq() { if [ -n "$1" ] && [ "$1" = "$2" ]; then echo 1; else echo 0; fi; }

R1=$(mktemp); R2=$(mktemp); REG=$(mktemp); V1=$(mktemp)
{ echo
  echo "########## E-0087 · ADR-0043 gossip-путь обязан пройти дверь · прогон $(date +%FT%T%:z) ##########"
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "oracle: $ORACLE"
  echo "PRE_FIX_ЗАМЕР: снят отдельным вызовом до коммита правки (git stash сервиса), блок ниже"
  echo "RAM_FREE_MB_BEFORE=$(free_ram_mb) DISK_FREE_MB_BEFORE=$(free_disk_mb)"
} >> "$LOG"

# Шаг 0 — предсказание на дереве ДО правки. Файл блока (`/tmp/e0087_prefix.txt`) создан вручную до
# пре-регистрационного коммита; если его нет, цикл обязан остановиться на пороге (3), а не «домерить».
{ echo "### ШАГ 0 PRE_FIX (дерево до правки) ###"
  if [ -s /tmp/e0087_prefix.txt ]; then
    grep -E "МЕРЕНО|test result|panicked at" /tmp/e0087_prefix.txt
  else
    echo "ВНИМАНИЕ: снимок PRE_FIX отсутствует — порог (3) не может быть проверен"
  fi
} >> "$LOG"

run_to "$R1" "ШАГ 1 оракул, прогон n=1 (после ПОПРАВКИ ДИАГНОЗ-1)" cargo test -p vecdht-net --test gossip_door_parity -- --nocapture --test-threads=1
{ echo "### ВЕКТОР ПОРОГОВ n=1 ###"; grab "$R1" r1 "$KEYS"; grab "$R1" r1 "$EXTRA_KEYS"; } >> "$LOG"

run_to "$R2" "ШАГ 2 оракул, прогон n=2 (порог (6): свёртка обязана совпасть)" cargo test -p vecdht-net --test gossip_door_parity -- --nocapture --test-threads=1
{ echo "### ВЕКТОР ПОРОГОВ n=2 ###"; grab "$R2" r2 "$KEYS"; grab "$R2" r2 "$EXTRA_KEYS"; } >> "$LOG"

# Шаг 3 — регрессия по соседям (порог (5)): все тесты `vecdht-net`, кроме двух помеченных
# `#[ignore]` как описание поведения до ADR-0043. `--no-fail-fast` обязателен: в первом прогоне
# cargo остановился на упавшем бинаре и остальные 8 таргетов не были исполнены вовсе, то есть
# порог (5) был не «провален», а не измерен (ДИАГНОЗ-2 в логе).
run_to "$REG" "ШАГ 3 регрессия: весь vecdht-net (--no-fail-fast)" cargo test -p vecdht-net --no-fail-fast
{ echo "### РЕГРЕССИЯ ###"
  grep -E "^test result|running \d+ tests|EXIT=" "$REG" | tail -30
  echo "ignored_всего=$(grep -c 'ignore = ' crates/vecdht-net/tests/s53_door_branches.rs crates/vecdht-net/tests/s5_handshake_seam.rs | tr '\n' ' ')"
} >> "$LOG"

D1=$(get o12_digest_r1 "$LOG"); D2=$(get o12_digest_r2 "$LOG")
{ echo "### КОНТРОЛЬ ПОРОГОВ ###"
  echo "порог (4) оракул зелёный оба прогона: EXIT n1/n2 см. блоки ШАГ 1/2"
  echo "порог (6) digest_совпал=$(eq "$D1" "$D2")  r1=$D1  r2=$D2"
  echo "порог (8) осевшие_каталоги=$(ls "${TMPDIR:-/tmp}" 2>/dev/null | grep -c 'vecdht-gdp')"
  echo "порог (5) регрессия: failed=$(grep -oE '[0-9]+ failed' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "RAM_FREE_MB_AFTER=$(free_ram_mb) DISK_FREE_MB_AFTER=$(free_disk_mb)"
  echo "TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

rm -f "$R1" "$R2" "$REG" "$V1"
echo "=== E-0087 готов; WORST_RC=$WORST_RC ==="
exit "$WORST_RC"
