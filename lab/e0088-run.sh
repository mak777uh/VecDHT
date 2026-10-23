#!/usr/bin/env bash
# E-0088: релиз-блокер (2) — per-cluster admission cap становится политикой приёма (§14.4 (iv),
# ADR-0044 решение 5). Единица цикла — факт (длина ячейки против предела, число вытеснений, число
# обходов резервуара), не время: временные числа оракул печатает, но в вердикт они не входят
# (правило 7 (д): отношение запаса publish-медианы к межпрогонному разбросу меньше ~10).
#
# Пороги заморожены в `lab/hypotheses/H-0088-cell-cap-enforced.md` и в assert'ах оракула
# `crates/vecdht-node/tests/s14_cell_cap_enforced.rs`. Helper ничего из них не пересчитывает: он
# снимает напечатанные оракулом ключи `g*`, сверяет вектор фактов между двумя прогонами и считает
# нуль/ненуль по bound'ам.
#
# Встроенные уроки метода: (а) helper исполняет свою неизменяемую mktemp-копию, корень репо —
# через VEC_DHT_ROOT; (б) ресурсы меряются до сборки, после каждого прогона и в ИТОГЕ, метки —
# ASCII; (в) регрессия идёт с `--no-fail-fast` (ДИАГНОЗ-2 из `E-0087`: без него cargo обрывается на
# первом упавшем бинаре, и порог не измерается, а не проваливается); (г) контроль append-only лога
# берётся `tail -1`, а не первым вхождением (ДИАГНОЗ-3 из `E-0087`); (д) осевшие каталоги считаются
# после прогона —Drop-гард в оракуле добавлен ровно потому, что PRE_FIX-прогон оставил 14 каталогов
# на 61 МБ; (е) `cargo clean` не исполняется.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0088-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0088-all.log"
PREFIX="lab/logs/e0088-oracle-before-fix.txt"
ORACLE=crates/vecdht-node/tests/s14_cell_cap_enforced.rs
FLOOR=4096

# Ключи оракула. Временные (`*_us`) в вектор фактов не входят — они не предсказание.
FACT_KEYS="g1_cell g1_total g1_evicted g1_scanned g1_refused_code g1_neighbour
g2_frames g2_evicted g2_cell g2_total
g3_cell g3_neighbour g3_refused g3_evicted g3_total_before g3_total_after
g5_live_before g5_live g5_limit g5_cell g5_branch g5_refused g5_evicted g5_scanned
g7_total g7_cell g7_evicted g7_scanned"
TIME_KEYS="g1_cap_us g1_plain_med_us"

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
le() { if [ -n "$1" ] && [ "$1" -le "$2" ]; then echo 1; else echo 0; fi; }

R1=$(mktemp); R2=$(mktemp); REG=$(mktemp); F1=$(mktemp); F2=$(mktemp)
{ echo
  echo "########## E-0088 · per-cluster cap как политика приёма · прогон $(date +%FT%T%:z) ##########"
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "oracle: $ORACLE"
  echo "RAM_FREE_MB_BEFORE=$(free_ram_mb) DISK_FREE_MB_BEFORE=$(free_disk_mb)"
} >> "$LOG"

# Шаг 0 — предсказание на дереве ДО правки. Снимок лежит в репозитории (append-only), helper его
# только контролирует: последний `test result` обязан быть `2 passed; 3 failed`, а оба bound-нарушения
# (`left: 4097` — пол, `left: 4287` — относительная ветка) обязаны быть в нём хоть по одному разу.
# Снимков в файле три (первый прогон и два среза после правок оракула), потому счёт — по
# вхождениям, а последний `test result` — по `tail -1` (ДИАГНОЗ-3 из `E-0087`).
{ echo "### ШАГ 0 PRE_FIX (дерево до правки, $PREFIX) ###"
  if [ -s "$PREFIX" ]; then
    echo "prefix_test_result=$(grep -E 'test result' "$PREFIX" | tail -1)"
    echo "prefix_cell_floor_violation=$(grep -c 'left: 4097' "$PREFIX")"
    echo "prefix_cell_relative_violation=$(grep -c 'left: 4287' "$PREFIX")"
    echo "prefix_exit=$(grep -E '^EXIT=' "$PREFIX" | tail -1)"
  else
    echo "ВНИМАНИЕ: снимок PRE_FIX отсутствует — порог (3) не может быть проверен"
  fi
} >> "$LOG"

run_to "$R1" "ШАГ 1 оракул, прогон n=1" cargo test -p vecdht-node --test s14_cell_cap_enforced --no-fail-fast -- --nocapture --test-threads=1
{ echo "### ВЕКТОР ПОРОГОВ n=1 ###"; grab "$R1" r1 "$FACT_KEYS"; grab "$R1" r1 "$TIME_KEYS"; } >> "$LOG"

run_to "$R2" "ШАГ 2 оракул, прогон n=2 (порог (9): вектор фактов обязан совпасть)" cargo test -p vecdht-node --test s14_cell_cap_enforced --no-fail-fast -- --nocapture --test-threads=1
{ echo "### ВЕКТОР ПОРОГОВ n=2 ###"; grab "$R2" r2 "$FACT_KEYS"; grab "$R2" r2 "$TIME_KEYS"; } >> "$LOG"

grab "$R1" r1 "$FACT_KEYS" > "$F1"
grab "$R2" r2 "$FACT_KEYS" > "$F2"

# Шаг 3 — регрессия по соседям (порог (8)): весь `vecdht-node`, включая исторический оракул
# `E-0079` (`s14_cluster_bloat_price`), который кап не должен ни ломать, ни переписывать.
run_to "$REG" "ШАГ 3 регрессия: весь vecdht-node (--no-fail-fast)" cargo test -p vecdht-node --no-fail-fast
{ echo "### РЕГРЕССИЯ ###"
  grep -E "^test result|^error" "$REG" | tail -30
  echo "reg_failed=$(grep -oE '[0-9]+ failed' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "reg_ignored=$(grep -oE '[0-9]+ ignored' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "reg_passed=$(grep -oE '[0-9]+ passed' "$REG" | awk '{s+=$1} END {print s+0}')"
  echo "bloat_oracle=$(grep -A2 'ClusterBloatPrice' /dev/null; grep -E 's14_cluster_bloat_price' "$REG" | tail -2)"
} >> "$LOG"

{ echo "### КОНТРОЛЬ ПОРОГОВ ###"
  echo "порог (4) оракул зелёный: n1=$(get 'test' "$R1" >/dev/null; grep -E 'test result' "$R1" | tail -1) | n2=$(grep -E 'test result' "$R2" | tail -1)"
  echo "порог (5) bound пол: g1_cell_le_floor=$(le "$(get g1_cell_r1 "$F1")" "$FLOOR") g1_total_le_floor=$(le "$(get g1_total_r1 "$F1")" "$FLOOR")"
  echo "порог (5) bound относительный: g5_cell_eq_limit=$(eq "$(get g5_cell_r1 "$F1")" "$(get g5_limit_r1 "$F1")") g5_limit_gt_floor=$( [ "$(get g5_limit_r1 "$F1")" -gt "$FLOOR" ] 2>/dev/null && echo 1 || echo 0)"
  echo "порог (6) ровно-один g3: evicted=$(get g3_evicted_r1 "$F1") refused=$(get g3_refused_r1 "$F1")"
  echo "порог (7) цена: g1_scanned=$(get g1_scanned_r1 "$F1") g5_scanned=$(get g5_scanned_r1 "$F1") g7_scanned=$(get g7_scanned_r1 "$F1")"
  echo "порог (9) repro_fact_keys=$( [ -s "$F1" ] && cmp -s <(sed 's/_r1=/=/' "$F1") <(sed 's/_r2=/=/' "$F2") && echo 1 || echo 0)"
  # ^ ПОПРАВКА (ДИАГНОЗ-1), внесена после прогона: `grab` вшивает метку прогона в имя ключа
  # (`g1_cell_r1=` против `g1_cell_r2=`), поэтому сырое `cmp` F1/F2 различалось ВСЕГДА и пород (9)
  # был невыполним по построению — тот же класс дефекта, что ДИАГНОЗ-1 из `E-0087` (проверка,
  # которая не может быть пройдена). Сверяется значение, метка снимается перед сравнением;
  # пересчёт порога по уже закоммиченному логу — в блоке «ПОПРАВКА после прогона» ниже.
  echo "порог (8) осевшие_каталоги=$(ls "${TMPDIR:-/tmp}" 2>/dev/null | grep -c 'vecdht-index-.*cap-')"
  echo "порог (12) contour=$(python lab/library.py value --cycles 5 2>/dev/null | grep LIBVALUE | tail -1)"
  echo "RAM_FREE_MB_AFTER=$(free_ram_mb) DISK_FREE_MB_AFTER=$(free_disk_mb)"
  echo "TARGET_SIZE_MB=$(du -sm target 2>/dev/null | cut -f1)"
} >> "$LOG"

rm -f "$R1" "$R2" "$REG" "$F1" "$F2"
echo "=== E-0088 готов; WORST_RC=$WORST_RC ==="
exit "$WORST_RC"
