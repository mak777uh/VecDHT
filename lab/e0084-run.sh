#!/usr/bin/env bash
# E-0084: §19.4 — последняя незамеренная строка таблицы целей, «find end-to-end, p50 / p95 |
# ≤ 1,5 с / ≤ 4 с», снятая на настоящем QUIC-харнесе (libp2p loopback, `current_thread` +
# `LocalSet`), а не на однопоточном харнесе `vecdht-index` из `E-0083`.
#
# Цикл не правит продуктовый код, wire, крипто, спеку и чужие пороги: в репозитории только новый
# тестовый таргет `crates/vecdht-net/tests/s19_find_e2e_price.rs` и этот helper.
#
# Пороги заморожены в пре-регистрации (`lab/experiments/E-0084-*.md`) и в константах оракула;
# helper ничего из них не пересчитывает и не двигает — он снимает вектор `gate_*`, уже напечатанный
# оракулом, и проверяет правило 7 по МЕЖПРОГОННОМУ пределу воспроизводимости (урок ДИАГНОЗ-1 из
# `E-0083`: внутренний разброс одно-прогонной выборки может насыщаться снизу).
#
# Уроки, встроенные в метод: (а) экстрактор `m()` берёт число сразу после `=` по ascii-подписи
# печати, границы гейтов в helper'е — строки, а не проза (ДИАГНОЗ-4 из `E-0082`); (б)helper
# исполняет свою неизменяемую mktemp-копию (ДИАГНОЗ-6 из `e0079`), корень репо — через
# VEC_DHT_ROOT; (в) ресурсы — часть метода (указание владельца): свободные RAM и диск меряются до
# прогона, после каждого прогона и в ИТОГЕ, допуск ≥ 15 000 МБ диска и ≥ 4 000 МБ RAM, числа
# уходят в репозиторий вместе с логом, локальные черновики удаляются после коммита,
# `cargo clean` без объявления не делается.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0084-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0084-all.log"
CRATE=vecdht-net
ORACLE=s19_find_e2e_price
SRC="crates/$CRATE/tests/$ORACLE.rs"
BASE=5d99f88

# Вектор гейтов, ровно в том порядке, в котором они напечатаны в оракуле. Имена — подписи `gate_*`
# из печати, поэтому расхождение helper'а с оракулом видно как пустое значение, а не как подмена.
GATES="2a_provider_seen_zero 3_cold1_p50_le_row 4_cold1_p95_le_row 5a_cold1_margin_p50
5b_cold1_margin_p95 13a_drift_cold1 13b_drift_warm1 2b_all_shards_answered
7_cold13_p50_le_row 8_cold13_p95_le_row 6a_cold13_margin_p50 6b_cold13_margin_p95
9_cold13_to_warm13_window 10_marginal_per_shard_window 11_fanout_ratio_window
12_setup_share_window 13a_drift_cold13 13b_drift_warm13 13c_drift_one_ref
14_scan_ratio_window 15_search_share_le"

# Числа, снимаемые с каждого прогона: структура стенда, fan-out 1, доля арифметики, fan-out 13.
KEYS="nlist shards clusters_per_shard top_k_max nprobe_default pow_bits_default
agent_poll_ms agent_call_timeout_ms agent_request_timeout_ms node_poll_ms
node_request_timeout_ms stand_pow k_cold k_fanout k_phase k_warm k_scan heavy fanout
query_clusters query_shards_distinct per_peer_find_rps per_peer_publish_rps
per_peer_publish_burst node_admits_per_s top_k_max_param lease_buckets e2e_struct_ok
stand_nodes stand_seeds_distinct
cold1_p50_ms cold1_p95_ms cold1_min_ms cold1_max_ms cold1_spread_promil cold1_argmax
find1_p50_ms new1_p50_ms setup1_p50_ms phasewarm1_p50_ms warm1_p50_ms warm1_p95_ms
cold1_first_half_p50_ms cold1_second_half_p50_ms cold1_drift_promil warm1_drift_promil
setup1_drift_promil provider_seen_min provider_seen_max cold1_to_warm1_x setup1_to_cold1_x
warm1_to_cold1_x phasewarm1_to_cold1_x new1_share_promil rel_spread_cold1 rel_spread_warm1
rel_spread_setup1 cold1_margin_p50_x cold1_margin_p95_x
scanlight_p50_ms scanlight_p95_ms scanheavy_p50_ms scanheavy_p95_ms scan_ratio_x
scan_delta_ms rel_spread_scanlight rel_spread_scanheavy direct_search_light_p50_us
direct_search_heavy_p50_us direct_search_ratio_x direct_per_record_us
direct_light_below_clock_us net_heavy_p50_ms search_share
cold13_p50_ms cold13_p95_ms cold13_min_ms cold13_max_ms cold13_spread_promil cold13_argmax
find13_p50_ms warm13_p50_ms one13ref_p50_ms setup13_p50_ms
cold13_first_half_p50_ms cold13_second_half_p50_ms cold13_drift_promil warm13_drift_promil
one13_drift_promil covered_shards_min covered_shards_max answers_min answers_max
fanout13_to_one_x per_shard_marginal_ms cold13_to_warm13_x setup13_to_cold13_x
rel_spread_cold13 rel_spread_warm13 rel_spread_cold1_ref cold13_margin_p50_x
cold13_margin_p95_x"

WORST_RC=0

run_step() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out
  out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
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

# Экстрактор по подписям печати: ключ ascii, за ним `=число`. Граница перед ключом обязательна:
# без неё «cold1_p50_ms» матчился бы внутри чужого имени и `tail -1` взял бы не то число
# (тот же класс ошибки, что ДИАГНОЗ-4 в `E-0082`).
m() { grep -oE "(^|[[:space:]])$1=[0-9.]*" "$LOG" | tail -1 | cut -d= -f2; }

pct_diff() { # $1=a $2=b → |a-b|/max ×100
  awk -v a="$1" -v b="$2" 'BEGIN { if (a=="" || b=="") { print "нет чисел"; exit } m = (a>b)?a:b; if (m==0) { print "0,00"; exit } printf "%.2f", (a>b?a-b:b-a)*100/m }'
}

rel_diff() { # $1=a $2=b → |a-b|/max в долях (сравнивается с запасом строки)
  awk -v a="$1" -v b="$2" 'BEGIN { if (a=="" || b=="") { print "нет чисел"; exit } m = (a>b)?a:b; if (m==0) { print "0"; exit } printf "%.4f", (a>b?a-b:b-a)/m }'
}

rule7() { # $1=запас_долями $2=разброс_долями → вердикт правила 7
  awk -v g="$1" -v s="$2" 'BEGIN { if (g=="" || s=="" || g ~ /[^0-9.-]/ || s ~ /[^0-9.-]/) { print "нет чисел"; exit } printf "запас=%s 2x_разброс=%s вердикт=%s", g, 2*s, (g+0 >= 2*s+0 ? "выполнен" : "НЕ ВЫПОЛНЕН") }'
}

margin_of() { # $1=число $2=граница → (граница/число − 1) для гейтов «меньше границы»
  awk -v p="$1" -v lim="$2" 'BEGIN { if (p=="" || p ~ /[^0-9.]/) { print ""; exit } printf "%.3f", lim/p-1 }'
}

check_nums() { # самопроверка экстракторов (ДИАГНОЗ-2): каждый аргумент вида ключ=число
  local pair v
  for pair in "$@"; do
    v=${pair#*=}
    case "$v" in
      ''|*[!0-9.]*) echo "ВНИМАНИЕ: экстрактор «${pair%%=*}» вернул не число («$v») — единицы helper'а сверять до пре-регистрации";;
    esac
  done
}

{ echo "=== E-0084 прогон $(date +%FT%T%:z) — §19.4: find end-to-end на QUIC-стенде ==="
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "gcc: $(gcc --version | head -1)"
  echo "cargo: $(cargo --version)"
  echo "RAYON_NUM_THREADS=$RAYON_NUM_THREADS"
  echo "ЯДЕР: $(nproc)"
  echo "RAM СВОБОДНО до прогона, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО до прогона, МБ: $(free_disk_mb)"
} | tee -a "$LOG"

# --- Допуск к прогону (техника безопасности, не порог замера) ---
DISK0=$(free_disk_mb)
RAM0=$(free_ram_mb)
{ echo "### ДОПУСК ### $(date +%FT%T%:z)"
  echo "диск $DISK0 МБ, RAM $RAM0 МБ"
} | tee -a "$LOG"
if [ "${DISK0:-0}" -lt 15000 ]; then
  { echo "### ДОПУСК: ОТКАЗ ### $(date +%FT%T%:z)"
    echo "свободного диска $DISK0 МБ < 15 000 МБ — release-прогон остановлен, объявить владельцу"
  } | tee -a "$LOG"
  exit 86
fi
if [ "${RAM0:-0}" -lt 4000 ]; then
  { echo "### ДОПУСК: ОТКАЗ ### $(date +%FT%T%:z)"
    echo "свободной RAM $RAM0 МБ < 4 000 МБ — release-прогон остановлен, объявить владельцу"
  } | tee -a "$LOG"
  exit 87
fi

# --- Порог (0): стоимость метода ---
{ echo "### СТОИМОСТЬ ### $(date +%FT%T%:z)"
  echo "-- таргет $ORACLE: строк $(wc -l < "$SRC"), тестов $(grep -c '#\[test\]' "$SRC")"
  echo "-- продуктовый код (crates/*/src) и спека этим циклом не тронуты (пусто = ок):"
  git diff --stat "$BASE"..HEAD -- crates/*/src docs/VecDHT-SPEC-v8.md
  echo "-- тронутые тесты:"
  git diff --stat "$BASE"..HEAD -- crates/*/tests
  echo "-- зависимостей добавлено не было (пусто = ок):"
  git diff --stat "$BASE"..HEAD -- Cargo.toml Cargo.lock crates/*/Cargo.toml
  echo "-- пороги, замороженные в исходнике (константы, не строки отчёта):"
  grep -E '^const (ROW_|MARGIN_|COLD_TO_|MARGINAL_|FANOUT_RATIO_|SETUP_SHARE_|SEARCH_SHARE_|SCAN_RATIO_|DRIFT_)' "$SRC" | sed 's/^/   /'
} | tee -a "$LOG"

# --- Сборка release: один таргет, цена метода ---
build_t0=$(date +%s%N)
run_step "RELEASE BUILD --no-run" cargo test -j 2 --release -p "$CRATE" --test "$ORACLE" --no-run
build_t1=$(date +%s%N)
echo "BUILD_MS=$(( (build_t1 - build_t0) / 1000000 ))" | tee -a "$LOG"

EXE=$(ls -t "target/release/deps/${ORACLE}-"*.exe 2>/dev/null | head -1)
{ echo "### БИНАРЬ $ORACLE ### $(date +%FT%T%:z)"
  echo "путь: $EXE"
  echo "sha256: $(sha256sum "$EXE" 2>/dev/null | cut -d' ' -f1)"
  echo "размер, МБ: $(du -m "$EXE" 2>/dev/null | cut -f1)"
} | tee -a "$LOG"

grab() { # $1 = суффикс прогона → строки ключ_суффикс=значение
  local s="$1" k
  for k in $KEYS; do
    printf '%s_%s=%s\n' "$k" "$s" "$(m "$k")"
  done
  for k in $GATES; do
    printf 'gate_%s_%s=%s\n' "$k" "$s" "$(m "gate_$k")"
  done
}

get() { grep "^$1=" "$2" | head -1 | cut -d= -f2-; }

N1_FILE=$(mktemp)
N2_FILE=$(mktemp)
N3_FILE=$(mktemp)

run1_t0=$(date +%s%N)
run_step "ORACLE $ORACLE RUN 1 (release, --nocapture, --test-threads=1)" \
  cargo test --release -p "$CRATE" --test "$ORACLE" -- --nocapture --test-threads=1
run1_t1=$(date +%s%N)
grab 1 > "$N1_FILE"
{ echo "### ЧИСЛА ПРОГОНА 1 ### $(date +%FT%T%:z)"
  cat "$N1_FILE"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "осевших каталогов e0084 в %TEMP%: $(ls -d "$TEMP"/vecdht-net-e0084-* 2>/dev/null | wc -l)"
} | tee -a "$LOG"

run2_t0=$(date +%s%N)
run_step "ORACLE $ORACLE RUN 2 (release, --nocapture, --test-threads=1 — тот же бинарь, воспроизводимость)" \
  cargo test --release -p "$CRATE" --test "$ORACLE" -- --nocapture --test-threads=1
run2_t1=$(date +%s%N)
grab 2 > "$N2_FILE"

# Правило 7 по МЕЖПРОГОННОму пределу воспроизводимости: запас до границы строки против разброса
# той же статистики между двумя прогонами одного бинаря. Пороги от этого не двигались — это
# более строгий контроль (урок ДИАГНОЗ-1 из `E-0083`).
C1_50_1=$(get cold1_p50_ms_1 "$N1_FILE");  C1_50_2=$(get cold1_p50_ms_2 "$N2_FILE")
C1_95_1=$(get cold1_p95_ms_1 "$N1_FILE");  C1_95_2=$(get cold1_p95_ms_2 "$N2_FILE")
C13_50_1=$(get cold13_p50_ms_1 "$N1_FILE"); C13_50_2=$(get cold13_p50_ms_2 "$N2_FILE")
C13_95_1=$(get cold13_p95_ms_1 "$N1_FILE"); C13_95_2=$(get cold13_p95_ms_2 "$N2_FILE")
{ echo "### ЧИСЛА ПРОГОНА 2 (воспроизводимость) ### $(date +%FT%T%:z)"
  cat "$N2_FILE"
  echo "-- расхождение двух release-прогонов одного бинаря, %:"
  for k in cold1_p50_ms cold1_p95_ms cold13_p50_ms cold13_p95_ms one13ref_p50_ms setup13_p50_ms \
           warm13_p50_ms fanout13_to_one_x per_shard_marginal_ms cold13_to_warm13_x \
           setup13_to_cold13_x cold1_to_warm1_x setup1_to_cold1_x scanlight_p50_ms \
           scanheavy_p50_ms scan_ratio_x direct_search_heavy_p50_us search_share; do
    echo "   $k: $(pct_diff "$(get "${k}_1" "$N1_FILE")" "$(get "${k}_2" "$N2_FILE")")"
  done
  check_nums "cold1_p50_ms=$C1_50_2" "cold13_p50_ms=$C13_50_2" "cold13_p95_ms=$C13_95_2" \
             "fanout13_to_one_x=$(get fanout13_to_one_x_2 "$N2_FILE")" \
             "per_shard_marginal_ms=$(get per_shard_marginal_ms_2 "$N2_FILE")" \
             "search_share=$(get search_share_2 "$N2_FILE")" \
             "scan_ratio_x=$(get scan_ratio_x_2 "$N2_FILE")"
  echo "-- ПРАВИЛО 7 по межпрогонному пределу воспроизводимости (границы строки §19.4):"
  echo "   cold1 p50  (граница 1500 мс):  $(rule7 "$(margin_of "$C1_50_2" 1500)" "$(rel_diff "$C1_50_1" "$C1_50_2")")  [внутрипрогонный разброс оракула: $(get rel_spread_cold1_2 "$N2_FILE")]"
  echo "   cold1 p95  (граница 4000 мс):  $(rule7 "$(margin_of "$C1_95_2" 4000)" "$(rel_diff "$C1_95_1" "$C1_95_2")")"
  echo "   cold13 p50 (граница 1500 мс):  $(rule7 "$(margin_of "$C13_50_2" 1500)" "$(rel_diff "$C13_50_1" "$C13_50_2")")  [внутрипрогонный: $(get rel_spread_cold13_2 "$N2_FILE")]"
  echo "   cold13 p95 (граница 4000 мс):  $(rule7 "$(margin_of "$C13_95_2" 4000)" "$(rel_diff "$C13_95_1" "$C13_95_2")")"
  echo "-- ВЕКТОР ГЕЙТОВ (1 = выполнен), n=1 / n=2:"
  for k in $GATES; do
    echo "   gate_$k: $(get "gate_${k}_1" "$N1_FILE") / $(get "gate_${k}_2" "$N2_FILE")"
  done
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "осевших каталогов e0084 в %TEMP%: $(ls -d "$TEMP"/vecdht-net-e0084-* 2>/dev/null | wc -l)"
  echo "sha256 $ORACLE после прогонов (обязан совпасть с блоком БИНАРЬ): $(sha256sum "$EXE" 2>/dev/null | cut -d' ' -f1)"
} | tee -a "$LOG"
echo "RUST_MS_1=$(( (run1_t1 - run1_t0) / 1000000 )) RUST_MS_2=$(( (run2_t1 - run2_t0) / 1000000 ))" | tee -a "$LOG"

# --- КОНТРОЛЬ: юнит-тесты того же крейта в том же профиле ---
run_step "КОНТРОЛЬ --release -p vecdht-net --lib" cargo test -j 2 --release -p "$CRATE" --lib

# --- Debug-половина: структура + кросс-профильные отношения (правило 6: временные гейты только в
# release; здесь они только печатаются) ---
run_step "DEBUG SMOKE $ORACLE" cargo test -p "$CRATE" --test "$ORACLE" -- --nocapture --test-threads=1
grab 3 > "$N3_FILE"
{ echo "### DEBUG ЧИСЛА (профиль-зависимая половина) ### $(date +%FT%T%:z)"
  echo "cold1_p50_ms debug:  $(get cold1_p50_ms_3 "$N3_FILE")"
  echo "cold13_p50_ms debug: $(get cold13_p50_ms_3 "$N3_FILE")"
  echo "gate-вектор debug (печать, не assert — правило 6):"
  for k in $GATES; do
    echo "   gate_$k=$(get "gate_${k}_3" "$N3_FILE")"
  done
  echo "-- КРОСС-ПРОФИЛЬ cold1 debug/release (репорт: окно не замораживалось):"
  awk -v d="$(get cold1_p50_ms_3 "$N3_FILE")" -v r="$C1_50_2" 'BEGIN {
    if (d==""||r=="") { print "   нет чисел"; exit }
    printf "   debug=%s release=%s отношение=%.1f\n", d, r, d/r }'
  echo "-- КРОСС-ПРОФИЛЬ cold13 debug/release (репорт):"
  awk -v d="$(get cold13_p50_ms_3 "$N3_FILE")" -v r="$C13_50_2" 'BEGIN {
    if (d==""||r=="") { print "   нет чисел"; exit }
    printf "   debug=%s release=%s отношение=%.1f\n", d, r, d/r }'
  echo "-- структурные гейты в debug обязаны быть 1 (профиль не влияет):"
  for k in 2a_provider_seen_zero 2b_all_shards_answered; do
    echo "   gate_$k debug=$(get "gate_${k}_3" "$N3_FILE")"
  done
} | tee -a "$LOG"

{ echo "### ИТОГ ### $(date +%FT%T%:z)"
  echo "HEAD после прогонов: $(git rev-parse --short HEAD)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "target/, МБ: $(du -sm target 2>/dev/null | cut -f1)"
  echo "осевших каталогов e0084 в %TEMP% (порог (16) про чистоту требует 0): $(ls -d "$TEMP"/vecdht-net-e0084-* 2>/dev/null | wc -l)"
  echo "лог: $LOG ($(wc -l < "$LOG") строк)"
  echo "HELPER_EXIT=$WORST_RC (худший из кодов шагов; 0 = все шаги отработали)"
} | tee -a "$LOG"
rm -f "$N1_FILE" "$N2_FILE" "$N3_FILE"
exit "$WORST_RC"
