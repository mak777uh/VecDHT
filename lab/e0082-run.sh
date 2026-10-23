#!/usr/bin/env bash
# E-0082: §19.4 — две строки целей v8, у которых не было прямого замера, против того, что код
# показывает в боевом профиле: «PoW: генерация / verify ≈150–350 мс / ≈0,14–0,33 мкс» и
# «снапшот 1M записей (стриминг) < 2 с, пик RAM < 1,2×». Цикл не правит продукт и не двигает
# чужие пороги: он добавляет два test-таргета и снимает в них release-числа.
#
# Lean здесь не применяется: единица обоих замеров — время и байты, а не форма предиката или
# маска поля (правило владельца о трёх применениях, пункт 3). Единственное место, где цикл
# становится перебором, — сетка «7 бит × 5 скоростей» внутри оракула PoW: там множество
# формулировок строки §19.4 исчерпывающее, и оно перебирается целой арифметикой в обоих
# профилях, до всякого замера.
#
# Helper исполняет команду целиком и ведёт append-only лог (урок e0049). Единицы подписаны:
# нс/попытка, нс/вызов, мс, МБ/с, ‰ (урок ДИАГНОЗ-1 в e0077 и e0078). Худший код шагов
# возвращается из скрипта (ДИАГНОЗ-3 в e0079). Скрипт исполняет свою неизменяемую mktemp-копию
# (ДИАГНОЗ-6 в e0079), корень репозитория передаётся через VEC_DHT_ROOT.
#
# Ресурсы — часть метода (указание владельца): свободные RAM и диск меряются до прогона, после
# каждого из двух прогонов и в ИТОГЕ, числа уходят в репозиторий вместе с логом; локальные
# черновики удаляются после коммита, `cargo clean` без объявления не делается. Здесь ресурс ещё
# и предмет замера: снапшот 1M записей — это ~432 МБ на диск и ~1 ГБ живых аллокаций в процессе.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0082-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0082-all.log"
CRATE=vecdht-index
ORACLES=(s19_pow_row_price s19_snapshot_1m_price)
BASE=8a9554a

WORST_RC=0
run_step() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
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
# Числа оракулов вытаскиваются из логов по подписям печати — единицы те же, что в порогах.
pow_ns()      { grep -o 'verify: медиана [0-9]* нс' "$LOG" | tail -1 | grep -o '[0-9]*'; }
est_default() { grep -o 'gen bits=20:.*' "$LOG" | tail -1 | sed -n 's/.*ожидаемая цена \([0-9.]*\) мс.*/\1/p'; }
stream_ms()   { grep -o 'стриминг: [0-9]* Б за [0-9]* мс' "$LOG" | tail -1 | awk '{print $4}'; }
barrier_ms()  { grep -o 'барьер: [0-9]* Б за [0-9]* мс' "$LOG" | tail -1 | awk '{print $4}'; }
permille()    { grep -o '→ [0-9]*‰ цели' "$LOG" | tail -1 | grep -o '[0-9]*'; }
pct_diff() { # $1=a $2=b → |a-b|/max ×100, два знака
  awk -v a="$1" -v b="$2" 'BEGIN { if (a=="" || b=="") { print "нет чисел"; exit } m = (a>b)?a:b; if (m==0) { print "0,00"; exit } printf "%.2f", (a>b?a-b:b-a)*100/m }'
}

{ echo "=== E-0082 прогон $(date +%FT%T%:z) — §19.4, строки PoW и снапшота 1M, профиль release ==="
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "gcc: $(gcc --version | head -1)"
  echo "cargo: $(cargo --version)"
  echo "RAYON_NUM_THREADS=$RAYON_NUM_THREADS"
  echo "ЯДЕР: $(nproc)"
  echo "RAM СВОБОДНО до прогона, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО до прогона, МБ: $(free_disk_mb)"
} | tee -a "$LOG"

# --- Допуск к прогону (не порог замера, а техника безопасности по диску) ---
# Здесь он ещё и содержательный: прогон пишет ~1,3 ГБ в %TEMP% (WAL + два снапшота по 432 МБ).
DISK0=$(free_disk_mb)
if [ "${DISK0:-0}" -lt 15000 ]; then
  { echo "### ДОПУСК: ОТКАЗ ### $(date +%FT%T%:z)"
    echo "свободного диска $DISK0 МБ < 15 000 МБ — release-прогон остановлен, объявить владельцу"
  } | tee -a "$LOG"
  exit 86
fi
echo "ДОПУСК: диск $DISK0 МБ — ок $(date +%FT%T%:z)" | tee -a "$LOG"

# --- Стоимость метода (порог (0)) ---
{ echo "### СТОИМОСТЬ ### $(date +%FT%T%:z)"
  for o in "${ORACLES[@]}"; do
    echo "-- оракул $o: строк $(wc -l < "crates/$CRATE/tests/$o.rs"), тестов $(grep -c '#\[test\]' "crates/$CRATE/tests/$o.rs")"
  done
  echo "-- продуктовый код, wire, крипто, спека этим циклом не тронуты (пусто = ок):"
  git diff --stat "$BASE"..HEAD -- crates/*/src docs/VecDHT-SPEC-v8.md
  echo "-- зависимостей добавлено не было (пусто = ок):"
  git diff --stat "$BASE"..HEAD -- Cargo.toml Cargo.lock crates/*/Cargo.toml
} | tee -a "$LOG"

# --- Сборка release: оба оракула, цена метода ---
build_t0=$(date +%s%N)
run_step "RELEASE BUILD --no-run (оба таргета)" cargo test -j 2 --release -p "$CRATE" \
  --test "${ORACLES[0]}" --test "${ORACLES[1]}" --no-run
build_t1=$(date +%s%N)
echo "BUILD_MS=$(( (build_t1 - build_t0) / 1000000 ))" | tee -a "$LOG"

declare -a EXES
for o in "${ORACLES[@]}"; do
  EXE=$(ls -t target/release/deps/${o}-*.exe 2>/dev/null | head -1)
  EXES+=("$EXE")
  { echo "### БИНАРЬ $o ### $(date +%FT%T%:z)"
    echo "путь: $EXE"
    echo "sha256: $(sha256sum "$EXE" 2>/dev/null | cut -d' ' -f1)"
    echo "размер, МБ: $(du -m "$EXE" 2>/dev/null | cut -f1)"
  } | tee -a "$LOG"
done

run_oracles() { # $1 = метка прогона
  local i o
  for i in "${!ORACLES[@]}"; do
    o="${ORACLES[$i]}"
    run_step "ORACLE $o RUN $1 (release, --nocapture, --test-threads=1)" \
      cargo test --release -p "$CRATE" --test "$o" -- --nocapture --test-threads=1
  done
}

run1_t0=$(date +%s%N)
run_oracles 1
run1_t1=$(date +%s%N)
echo "RUST_MS_1=$(( (run1_t1 - run1_t0) / 1000000 ))" | tee -a "$LOG"
V1=$(pow_ns); E1=$(est_default); S1=$(stream_ms); B1=$(barrier_ms); P1=$(permille)
{ echo "### ЧИСЛА ПРОГОНА 1 ### $(date +%FT%T%:z)"
  echo "verify нс/вызов: $V1"; echo "ожидаемая цена default, мс: $E1"
  echo "стриминг, мс: $S1"; echo "барьер, мс: $B1"; echo "пик аллокаций, ‰: $P1"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"; echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "осевших тестовых каталогов snap1m в %TEMP%: $(ls -d "$TEMP"/vecdht-index-*snap1m* 2>/dev/null | wc -l)"
} | tee -a "$LOG"

run2_t0=$(date +%s%N)
run_oracles 2
run2_t1=$(date +%s%N)
echo "RUST_MS_2=$(( (run2_t1 - run2_t0) / 1000000 ))" | tee -a "$LOG"
V2=$(pow_ns); E2=$(est_default); S2=$(stream_ms); B2=$(barrier_ms); P2=$(permille)
{ echo "### ЧИСЛА ПРОГОНА 2 (порог (11) — воспроизводимость) ### $(date +%FT%T%:z)"
  echo "verify нс/вызов: $V2"; echo "ожидаемая цена default, мс: $E2"
  echo "стриминг, мс: $S2"; echo "барьер, мс: $B2"; echo "пик аллокаций, ‰: $P2"
  echo "-- расхождение двух прогонов одного бинаря, %: verify $(pct_diff "$V1" "$V2"), цена default $(pct_diff "$E1" "$E2"), стриминг $(pct_diff "$S1" "$S2"), барьер $(pct_diff "$B1" "$B2"), пик ‰ $(pct_diff "$P1" "$P2")"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"; echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "осевших тестовых каталогов snap1m в %TEMP%: $(ls -d "$TEMP"/vecdht-index-*snap1m* 2>/dev/null | wc -l)"
  for i in "${!ORACLES[@]}"; do
    echo "sha256 ${ORACLES[$i]} после прогонов (обязан совпасть): $(sha256sum "${EXES[$i]}" 2>/dev/null | cut -d' ' -f1)"
  done
} | tee -a "$LOG"

# --- КОНТРОЛЬ: юнит-тесты того же крейта в том же профиле ---
run_step "КОНТРОЛЬ --release -p vecdht-index --lib" cargo test -j 2 --release -p "$CRATE" --lib

# --- Debug-половина порогов (2), (3), (8): арифметика и структура, от профиля не зависят ---
run_step "DEBUG SMOKE s19_pow_row_price" cargo test -p "$CRATE" --test "${ORACLES[0]}" -- --nocapture --test-threads=1
run_step "DEBUG SMOKE s19_snapshot_1m_price" cargo test -p "$CRATE" --test "${ORACLES[1]}" -- --nocapture --test-threads=1

{ echo "### ИТОГ ### $(date +%FT%T%:z)"
  echo "HEAD после прогонов: $(git rev-parse --short HEAD)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "target/, МБ: $(du -sm target 2>/dev/null | cut -f1)"
  echo "лог: $LOG ($(wc -l < "$LOG") строк)"
  echo "HELPER_EXIT=$WORST_RC (худший из кодов шагов; 0 = все шаги отработали)"
} | tee -a "$LOG"
exit "$WORST_RC"
