#!/usr/bin/env bash
# E-0083: §19.4 — три оставшиеся строки целей v8, снятые прямо, в двух профилях:
# «cluster assign (1024 int8 центроидов) < 0,15 мс», «WAL append, group commit ≤32 опсов на fsync
# | ≥ 6 400 ops/s» и «search, 1.1k записей/узел < 0,3 мс». Строка «find end-to-end» в этот цикл
# не входит: ей нужен настоящий QUIC-харнес, она уходит в H-0084.
#
# Цикл не правит продуктовый код, wire, крипто и спеку и не двигает чужие пороги. Единственная
# правка существующего теста — машинно извлекаемая копия уже печатаемых чисел `search`
# (`МЕРЕНО …`, ascii), чтобы helper'у не пришлось разбирать прозу (урок ДИАГНОЗ-4 из `E-0082`);
# assert p95 ≤ 300 мкс и страж nprobe в нём остались дословно те же.
#
# Helper исполняет команду целиком и ведёт append-only лог (урок e0049). Единицы подписаны в
# именах ключей печати (us, ops_per_s, promil, x), экстрактор `m()` берёт число сразу после `=`,
# поэтому сдвиг awk-поля больше не может подменить единицу. Скрипт исполняет свою неизменяемую
# mktemp-копию (ДИАГНОЗ-6 в e0079), корень репозитория передаётся через VEC_DHT_ROOT.
#
# Ресурсы — часть метода (указание владельца): свободные RAM и диск меряются до прогона, после
# каждого прогона, после КОНТРОЛЯ и в ИТОГЕ; допуск по диску ≥ 15 000 МБ, по RAM ≥ 4 000 МБ;
# числа уходят в репозиторий вместе с логом, локальные черновики удаляются после коммита,
# `cargo clean` без объявления не делается.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0083-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0083-all.log"
CRATE=vecdht-index
ORACLES=(s19_assign_row_price s19_wal_group_commit_price search_latency)
BASE=d292625

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

# Экстрактор по подписям печати: ключ ascii, за ним `=число`.
# Граница перед ключом обязательна: без неё «group_ops_per_s» матчится и внутри
# «productgroup_ops_per_s», и `tail -1` взял бы чужое число (тот же класс ошибки, что ДИАГНОЗ-4).
m() { grep -oE "(^|[[:space:]])$1=[0-9.]*" "$LOG" | tail -1 | cut -d= -f2; }

# Для линейности assign: строка печати содержит три числа, нужное — третье.
m_at() { # $1=полный ключ с префиксом → третье число строки
  grep -oE "(^|[[:space:]])$1=[0-9.]*" "$LOG" | tail -1 | cut -d= -f3
}

pct_diff() { # $1=a $2=b → |a-b|/max ×100
  awk -v a="$1" -v b="$2" 'BEGIN { if (a=="" || b=="") { print "нет чисел"; exit } m = (a>b)?a:b; if (m==0) { print "0,00"; exit } printf "%.2f", (a>b?a-b:b-a)*100/m }'
}

rel_diff() { # $1=a $2=b → |a-b|/max в долях (сравнивается с запасом строки)
  awk -v a="$1" -v b="$2" 'BEGIN { if (a=="" || b=="") { print "нет чисел"; exit } m = (a>b)?a:b; if (m==0) { print "0"; exit } printf "%.4f", (a>b?a-b:b-a)/m }'
}

rule7() { # $1=запас_долями $2=разброс_долями → вердикт правила 7
  awk -v g="$1" -v s="$2" 'BEGIN { if (g=="" || s=="" || g ~ /[^0-9.-]/ || s ~ /[^0-9.-]/) { print "нет чисел"; exit } printf "запас=%s 2x_разброс=%s вердикт=%s", g, 2*s, (g+0 >= 2*s+0 ? "выполнен" : "НЕ ВЫПОЛНЕН") }'
}

margin_of() { # $1=число $2=граница → (граница/число − 1), для гейтов «меньше границы»
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

{ echo "=== E-0083 прогон $(date +%FT%T%:z) — §19.4: assign, WAL group commit, search margin ==="
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

# --- Стоимость метода (порог (0)) ---
{ echo "### СТОИМОСТЬ ### $(date +%FT%T%:z)"
  for o in "${ORACLES[@]}"; do
    echo "-- таргет $o: строк $(wc -l < "crates/$CRATE/tests/$o.rs"), тестов $(grep -c '#\[test\]' "crates/$CRATE/tests/$o.rs")"
  done
  echo "-- продуктовый код (crates/*/src) и спека этим циклом не тронуты (пусто = ок):"
  git diff --stat "$BASE"..HEAD -- crates/*/src docs/VecDHT-SPEC-v8.md
  echo "-- тронутые тесты:"
  git diff --stat "$BASE"..HEAD -- crates/*/tests
  echo "-- зависимостей добавлено не было (пусто = ок):"
  git diff --stat "$BASE"..HEAD -- Cargo.toml Cargo.lock crates/*/Cargo.toml
} | tee -a "$LOG"

# --- Сборка release: три таргета, цена метода ---
build_t0=$(date +%s%N)
run_step "RELEASE BUILD --no-run (три таргета)" cargo test -j 2 --release -p "$CRATE" \
  --test "${ORACLES[0]}" --test "${ORACLES[1]}" --test "${ORACLES[2]}" --no-run
build_t1=$(date +%s%N)
echo "BUILD_MS=$(( (build_t1 - build_t0) / 1000000 ))" | tee -a "$LOG"

EXES=()
for o in "${ORACLES[@]}"; do
  EXE=$(ls -t "target/release/deps/${o}-"*.exe 2>/dev/null | head -1)
  EXES+=("$EXE")
  { echo "### БИНАРЬ $o ### $(date +%FT%T%:z)"
    echo "путь: $EXE"
    echo "sha256: $(sha256sum "$EXE" 2>/dev/null | cut -d' ' -f1)"
    echo "размер, МБ: $(du -m "$EXE" 2>/dev/null | cut -f1)"
  } | tee -a "$LOG"
done

run_oracles() { # $1 = метка прогона
  local o
  for o in "${ORACLES[@]}"; do
    run_step "ORACLE $o RUN $1 (release, --nocapture, --test-threads=1)" \
      cargo test --release -p "$CRATE" --test "$o" -- --nocapture --test-threads=1
  done
}

# Ключи, которые снимаются с каждого прогона (имена = подписи оракулов).
KEYS="assign_full_p50_us assign_full_per_row_us ratio_to_scan_lo ratio_to_scan_hi
full_spread_promil reference_to_full_x ref_spread_promil assign_api_p50_us rows_overhead_x
top16_to_assign_x assign_margin_x assign_rel_spread_x assign_gate7_ok distinct_rows_reference
distinct_rows_full pred_from_scan_lo_us pred_from_scan_hi_us
wal_solo_per_op_us solo_ops_per_s solo_spread_promil solo_ratio_to_195_x
wal_group_per_op_us group_ops_per_s group_spread_promil speedup_vs_solo_x group_ratio_to_195_x
wal_append_per_op_us wal_append_bytes wal_publish_per_op_us publish_to_solo_x
publish_spread_promil wal_productgroup_per_op_us publish_to_productgroup_x row_margin_x
wal_rel_spread_x wal_gate7_ok
search_p50_us search_p95_us search_p99_us search_one_cluster_p50_us"

grab() { # $1 = суффикс прогона → строки ключ_суффикс=значение
  local s="$1" k
  for k in $KEYS; do
    printf '%s_%s=%s\n' "$k" "$s" "$(m "$k")"
  done
  printf 'line256_%s=%s\n'   "$s" "$(m_at 'assign_line_rows=256 assign_line_p50_us' 3)"
  printf 'line512_%s=%s\n'   "$s" "$(m_at 'assign_line_rows=512 assign_line_p50_us' 3)"
  printf 'line1024_%s=%s\n'  "$s" "$(m_at 'assign_line_rows=1024 assign_line_p50_us' 3)"
}

get() { grep "^$1=" "$2" | head -1 | cut -d= -f2-; }

N1_FILE=$(mktemp)
N2_FILE=$(mktemp)
N3_FILE=$(mktemp)

run1_t0=$(date +%s%N)
run_oracles 1
run1_t1=$(date +%s%N)
grab 1 > "$N1_FILE"
{ echo "### ЧИСЛА ПРОГОНА 1 ### $(date +%FT%T%:z)"
  cat "$N1_FILE"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "осевших каталогов s19-wal в %TEMP%: $(ls -d "$TEMP"/vecdht-index-*s19-wal-* 2>/dev/null | wc -l)"
} | tee -a "$LOG"

run2_t0=$(date +%s%N)
run_oracles 2
run2_t1=$(date +%s%N)
grab 2 > "$N2_FILE"
S95_1=$(get search_p95_us_1 "$N1_FILE")
S95_2=$(get search_p95_us_2 "$N2_FILE")
A50_1=$(get assign_full_p50_us_1 "$N1_FILE")
A50_2=$(get assign_full_p50_us_2 "$N2_FILE")
WS1=$(get wal_solo_per_op_us_1 "$N1_FILE")
WS2=$(get wal_solo_per_op_us_2 "$N2_FILE")
WG1=$(get wal_group_per_op_us_1 "$N1_FILE")
WG2=$(get wal_group_per_op_us_2 "$N2_FILE")
SMARGIN=$(margin_of "$S95_2" 300)
SREL=$(rel_diff "$S95_1" "$S95_2")
# ДИАГНОЗ-1 (2): внутренний разброс одно-прогонной выборки насыщается снизу (медианы половин
# совпадают при разрешении таймера ~0,1 мкс), поэтому правило 7 надо проверять и по межпрогонному
# пределу воспроизводимости. Пороги от этого не двигались: добавлен более строгий контроль.
AMARGIN=$(margin_of "$A50_2" 150)
AREL=$(rel_diff "$A50_1" "$A50_2")
GO2=$(get group_ops_per_s_2 "$N2_FILE")
GREL=$(rel_diff "$(get wal_group_per_op_us_1 "$N1_FILE")" "$WG2")
GMARGIN=$(awk -v g="$GO2" 'BEGIN { if (g=="" || g+0==0) { print ""; exit } printf "%.3f", g/6400-1 }')
{ echo "### ЧИСЛА ПРОГОНА 2 (воспроизводимость) ### $(date +%FT%T%:z)"
  cat "$N2_FILE"
  echo "-- расхождение двух release-прогонов одного бинаря, %:"
  for k in assign_full_p50_us reference_to_full_x assign_api_p50_us top16_to_assign_x \
           wal_solo_per_op_us wal_group_per_op_us wal_publish_per_op_us publish_to_solo_x \
           wal_productgroup_per_op_us publish_to_productgroup_x search_p50_us search_p95_us \
           search_one_cluster_p50_us; do
    echo "   $k: $(pct_diff "$(get "${k}_1" "$N1_FILE")" "$(get "${k}_2" "$N2_FILE")")"
  done
  check_nums "assign_full_p50_us=$A50_2" "group_ops_per_s=$(get group_ops_per_s_2 "$N2_FILE")" \
             "search_p95_us=$S95_2" "wal_solo_per_op_us=$WS2" \
             "reference_to_full_x=$(get reference_to_full_x_2 "$N2_FILE")" \
             "publish_to_solo_x=$(get publish_to_solo_x_2 "$N2_FILE")" \
             "line1024=$(get line1024_2 "$N2_FILE")"
  echo "-- ПРАВИЛО 7 для строки search (запас p95 до 300 мкс против межпрогонного разброса):"
  echo "   $(rule7 "$SMARGIN" "$SREL")"
  echo "   межпрогонный разброс search p95, долях: $SREL"
  echo "-- ПРАВИЛО 7 по МЕЖПРОГОННОМУ пределу воспроизводимости (ДИАГНОЗ-1; пороги не двигались):"
  echo "   assign  (граница 150 мкс):  $(rule7 "$AMARGIN" "$AREL")  [внутрипрогонный разброс оракула: $(get assign_rel_spread_x_2 "$N2_FILE")]"
  echo "   WAL     (граница 6 400 опсов/с): $(rule7 "$GMARGIN" "$GREL")  [внутрипрогонный: $(get wal_rel_spread_x_2 "$N2_FILE")]"
  echo "   assign linearity межпрогонно, 256/1024 = $(awk -v a="$(get line256_1 "$N1_FILE")" -v b="$(get line1024_1 "$N1_FILE")" -v c="$(get line256_2 "$N2_FILE")" -v d="$(get line1024_2 "$N2_FILE")" 'BEGIN{ if(a==""||b==""||c==""||d==""){print "нет чисел";exit} printf "%.3f/%.3f", a/b, c/d }')"
  echo "   межпрогонный разброс assign, %: $(pct_diff "$A50_1" "$A50_2")"
  echo "   межпрогонный разброс WAL solo, %: $(pct_diff "$WS1" "$WS2")"
  echo "   межпрогонный разброс WAL group, %: $(pct_diff "$WG1" "$WG2")"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "осевших каталогов s19-wal в %TEMP%: $(ls -d "$TEMP"/vecdht-index-*s19-wal-* 2>/dev/null | wc -l)"
  for i in "${!ORACLES[@]}"; do
    echo "sha256 ${ORACLES[$i]} после прогонов (обязан совпасть): $(sha256sum "${EXES[$i]}" 2>/dev/null | cut -d' ' -f1)"
  done
} | tee -a "$LOG"
echo "RUST_MS_1=$(( (run1_t1 - run1_t0) / 1000000 )) RUST_MS_2=$(( (run2_t1 - run2_t0) / 1000000 ))" | tee -a "$LOG"

# --- КОНТРОЛЬ: юнит-тесты того же крейта в том же профиле ---
run_step "КОНТРОЛЬ --release -p vecdht-index --lib" cargo test -j 2 --release -p "$CRATE" --lib

# --- Debug-половина: структурные и арифметические гейты + кросс-профильные отношения ---
for o in "${ORACLES[@]}"; do
  run_step "DEBUG SMOKE $o" cargo test -p "$CRATE" --test "$o" -- --nocapture --test-threads=1
done
grab 3 > "$N3_FILE"
{ echo "### DEBUG ЧИСЛА (профиль-зависимая половина) ### $(date +%FT%T%:z)"
  echo "assign_full_p50_us debug: $(get assign_full_p50_us_3 "$N3_FILE")"
  echo "wal_solo_per_op_us debug: $(get wal_solo_per_op_us_3 "$N3_FILE")"
  echo "search_p95_us debug: $(get search_p95_us_3 "$N3_FILE")"
  echo "-- КРОСС-ПРОФИЛЬ assign debug/release (окно заморожено из фактора скана E-0081: [150; 280]):"
  awk -v d="$(get assign_full_p50_us_3 "$N3_FILE")" -v r="$A50_2" 'BEGIN {
    if (d==""||r=="") { print "   нет чисел"; exit }
    x=d/r; printf "   debug=%s release=%s отношение=%.1f вердикт=%s\n", d, r, x, (x>=150 && x<=280 ? "ок" : "ВНЕ ОКНА") }'
  echo "-- КРОСС-ПРОФИЛЬ search p95 debug/release (репорт, окно не замораживалось):"
  awk -v d="$(get search_p95_us_3 "$N3_FILE")" -v r="$S95_2" 'BEGIN {
    if (d==""||r=="") { print "   нет чисел"; exit }
    printf "   debug=%s release=%s отношение=%.1f\n", d, r, d/r }'
  echo "-- КРОСС-ПРОФИЛЬ WAL solo (fsync-доминированный путь; отношение обязано быть близко к 1):"
  awk -v d="$(get wal_solo_per_op_us_3 "$N3_FILE")" -v r="$WS2" 'BEGIN {
    if (d==""||r=="") { print "   нет чисел"; exit }
    printf "   debug=%s release=%s отношение=%.3f\n", d, r, d/r }'
} | tee -a "$LOG"

{ echo "### ИТОГ ### $(date +%FT%T%:z)"
  echo "HEAD после прогонов: $(git rev-parse --short HEAD)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "target/, МБ: $(du -sm target 2>/dev/null | cut -f1)"
  echo "осевших каталогов s19-wal в %TEMP% (порог (13) требует 0): $(ls -d "$TEMP"/vecdht-index-*s19-wal-* 2>/dev/null | wc -l)"
  echo "лог: $LOG ($(wc -l < "$LOG") строк)"
  echo "HELPER_EXIT=$WORST_RC (худший из кодов шагов; 0 = все шаги отработали)"
} | tee -a "$LOG"
rm -f "$N1_FILE" "$N2_FILE" "$N3_FILE"
exit "$WORST_RC"
