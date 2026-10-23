#!/usr/bin/env bash
# E-0081: §14.4 (iv) / §20.2 строка 4 — **абсолютная шкала в боёвом профиле**. Цикл не правит
# оракул `E-0079` и не пересматривает его замороженные пороги: он переснимает тот же файл в
# профиле `release` и смотрит, что из вывода было свойством протокола, а что — артефактом
# `unoptimized + debuginfo`.
#
# Lean здесь не применяется осознанно (правило владельца о трёх применениях, пункт 3): единица
# этого замера — время, а не форма предиката или маска поля. Единственное детерминированное
# утверждение, которое пришло из модели `E-0079`, — «профиль меняет скорость, но не выборку»:
# перебор nonce детерминирован, поэтому печати зонда (5в) обязаны совпасть с debug побайтово
# (порог (2)).
#
# Helper исполняет команду целиком и ведёт append-only лог (урок e0049). Единицы подписаны:
# нс/попытка, мкс/запись, мс/с CPU, МБ (урок ДИАГНОЗ-1 в e0077 и e0078). Худший код шагов
# возвращается из скрипта (ДИАГНОЗ-3 в e0079). Скрипт исполняет свою неизменяемую mktemp-копию
# (ДИАГНОЗ-6 в e0079), корень репозитория передаётся через VEC_DHT_ROOT.
#
# Ресурсы — часть метода (указание владельца): свободные RAM и диск меряются до прогона, после
# каждого из двух прогонов и в ИТОГЕ, числа уходят в репозиторий вместе с логом; локальные
# черновики удаляются после коммита, `cargo clean` без объявления не делается.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0081-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0081-all.log"
ORACLE=s14_cluster_bloat_price
CRATE=vecdht-node
DBASE=lab/logs/e0079-all.log

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

{ echo "=== E-0081 прогон $(date +%FT%T%:z) — профиль release, оракул E-0079 без правок ==="
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
DISK0=$(free_disk_mb)
if [ "${DISK0:-0}" -lt 15000 ]; then
  { echo "### ДОПУСК: ОТКАЗ ### $(date +%FT%T%:z)"
    echo "свободного диска $DISK0 МБ < 15 000 МБ — release-сборка остановлена, объявить владельцу"
  } | tee -a "$LOG"
  exit 86
fi
echo "ДОПУСК: диск $DISK0 МБ — ок $(date +%FT%T%:z)" | tee -a "$LOG"

# --- Стоимость метода: оракул не правился, продукт не тронут, зависимостей не добавлено ---
{ echo "### СТОИМОСТЬ ### $(date +%FT%T%:z)"
  echo "-- оракул Rust (тот же файл, что в E-0079): строк / тестов:"
  echo "   строк: $(wc -l < "crates/$CRATE/tests/$ORACLE.rs")"
  echo "   тестов: $(grep -c '#\[test\]' "crates/$CRATE/tests/$ORACLE.rs")"
  echo "-- правок оракула с момента закрытия E-0079 (пусто = ок):"
  git diff --stat 759b29b..HEAD -- "crates/$CRATE/tests/$ORACLE.rs"
  echo "-- продуктовый код, wire, спека и узел этим циклом не тронуты (пусто = ок):"
  git diff --stat 759b29b..HEAD -- crates/vecdht-node/src crates/vecdht-index/src crates/vecdht-crypto/src crates/vecdht-wire/src docs/VecDHT-SPEC-v8.md
  echo "-- зависимостей добавлено не было (пусто = ок):"
  git diff --stat 759b29b..HEAD -- Cargo.toml Cargo.lock crates/*/Cargo.toml
} | tee -a "$LOG"

# --- Debug-база: что именно переснимается (замороженные числа E-0079, не правятся) ---
{ echo "### DEBUG-БАЗА (E-0079, замерный прогон; переснято в логе $DBASE) ### $(date +%FT%T%:z)"
  grep -o "## (4) скан.*##" "$DBASE" | tail -1
  grep -o "## (5в) зонд.*##" "$DBASE" | tail -1
  grep -o "## (5а) один вход.*##" "$DBASE" | tail -1
  grep -o "## (5) цена записи.*" "$DBASE" | tail -1
  echo "-- константы фикстуры, которые цикл обязан сохранить: DIM, POW, ladder, top_k, max_live_per_shard"
  grep -n "const DIM\|const POW\|const BASE\|const TTL\|let ladder = \|max_live_per_shard" "crates/$CRATE/tests/$ORACLE.rs" | head -12
} | tee -a "$LOG"

# --- Сборка release: гейт (0) и цена метода ---
build_t0=$(date +%s%N)
run_step "RELEASE BUILD --no-run" cargo test -j 2 --release -p "$CRATE" --test "$ORACLE" --no-run
build_t1=$(date +%s%N)
echo "BUILD_MS=$(( (build_t1 - build_t0) / 1000000 )) BUILD_S=$(( (build_t1 - build_t0) / 1000000000 ))" | tee -a "$LOG"

EXE=$(ls -t target/release/deps/${ORACLE}-*.exe 2>/dev/null | head -1)
{ echo "### БИНАРЬ ### $(date +%FT%T%:z)"
  echo "путь: $EXE"
  echo "sha256: $(sha256sum "$EXE" 2>/dev/null | cut -d' ' -f1)"
  echo "размер, МБ: $(du -m "$EXE" 2>/dev/null | cut -f1)"
} | tee -a "$LOG"

# --- Оракул: два независимых прогона одного бинаря (порог (10) — воспроизводимость) ---
run1_t0=$(date +%s%N)
run_step "ORACLE RUN 1 (release, --nocapture, --test-threads=1)" cargo test --release -p "$CRATE" --test "$ORACLE" -- --nocapture --test-threads=1
run1_t1=$(date +%s%N)
echo "RUST_MS_1=$(( (run1_t1 - run1_t0) / 1000000 )) RUST_S_1=$(( (run1_t1 - run1_t0) / 1000000000 ))" | tee -a "$LOG"

{ echo "### РЕСУРСЫ ПОСЛЕ ПРОГОНА 1 ### $(date +%FT%T%:z)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "target/, МБ: $(du -sm target 2>/dev/null | cut -f1)"
  echo "осевших тестовых каталогов bloat в %TEMP%: $(ls -d "$TEMP"/vecdht-index-*bloat* 2>/dev/null | wc -l)"
} | tee -a "$LOG"

run2_t0=$(date +%s%N)
run_step "ORACLE RUN 2 (release, --nocapture, --test-threads=1)" cargo test --release -p "$CRATE" --test "$ORACLE" -- --nocapture --test-threads=1
run2_t1=$(date +%s%N)
echo "RUST_MS_2=$(( (run2_t1 - run2_t0) / 1000000 )) RUST_S_2=$(( (run2_t1 - run2_t0) / 1000000000 ))" | tee -a "$LOG"

{ echo "### РЕСУРСЫ ПОСЛЕ ПРОГОНА 2 ### $(date +%FT%T%:z)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "sha256 бинаря после второго прогона (обязан совпасть): $(sha256sum "$EXE" 2>/dev/null | cut -d' ' -f1)"
} | tee -a "$LOG"

# --- КОНТРОЛЬ: unit-тесты узла в том же профиле. Пороги этих тестов калиброваны по debug ---
run_step "КОНТРОЛЬ --release -p vecdht-node --lib" cargo test -j 2 --release -p "$CRATE" --lib

{ echo "### ИТОГ ### $(date +%FT%T%:z)"
  echo "HEAD после прогонов: $(git rev-parse --short HEAD)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "target/, МБ: $(du -sm target 2>/dev/null | cut -f1)"
  echo "лог: $LOG ($(wc -l < "$LOG") строк)"
  echo "HELPER_EXIT=$WORST_RC (худший из кодов шагов; 0 = все шаги отработали)"
} | tee -a "$LOG"
exit "$WORST_RC"
