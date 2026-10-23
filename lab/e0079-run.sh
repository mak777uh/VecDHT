#!/usr/bin/env bash
# E-0079: §14.4 (iv) — цена надувания кластера. Первый цикл по правилу, принятому владельцем
# после E-0078: формальная модель (`lab/lean/VecDHT/Admission.lean`) написана ДО замера и
# подсказала, что мерить; оракул `s14_cluster_bloat_price.rs` меряет.
#
# Helper исполняет команду целиком и ведёт append-only лог (урок e0049). Единицы подписаны:
# таймеры печатают `_MS`/`_S`, скан — мкс, PoW — нс/хеш (урок ДИАГНОЗ-1 в e0077 и e0078).
#
# ДИАГНОЗ-0 (инструментальный, зафиксирован до прогона): в этой среде PATH по умолчанию даёт
# `x86_64-w64-mingw32-gcc` 5.3.0 из miniconda, и линковка тестового бинаря падает на
# `undefined reference to GetHostNameW` (импортная библиотека ws2_32 того года её не содержит).
# Helper, как и e0078, первым ставит /c/Users/Admin/mingw64/bin — gcc 16.2.0, линковка проходит.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0079-all.log"
ORACLE=s14_cluster_bloat_price
MODEL=lab/lean/VecDHT/Admission.lean

WORST_RC=0
run_step() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  # ДИАГНОЗ-3 (первый прогон): helper печатал HELPER_EXIT=0 при EXIT=101 внутри — код шага
  # терялся, и «прогон зелёный» не означал «оракул зелёный». Худший код собирается здесь и
  # возвращается из скрипта. Пороги оракула при этом не двигались.
  if [ "$rc" -gt "$WORST_RC" ]; then WORST_RC=$rc; fi
  return $rc
}
free_ram_mb() {
  # Округляем на стороне PowerShell: локаль печатает дробь с запятой, а значение с запятой в
  # логе нельзя сравнивать глазами — единица подписана как МБ, значит число обязано быть целым.
  powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null \
    | tr -d '\r' | tail -1
}
free_disk_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1
}

{ echo "=== E-0079 прогон $(date +%FT%T%:z) ==="
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "gcc: $(gcc --version | head -1)"
  echo "lean: $(lean --version)"
  echo "cargo: $(cargo --version)"
  echo "RAYON_NUM_THREADS=$RAYON_NUM_THREADS"
  echo "ОС: $(powershell -NoProfile -Command '(Get-CimInstance Win32_OperatingSystem).Caption + " " + (Get-CimInstance Win32_OperatingSystem).Version' 2>/dev/null | tr -d '\r')"
  echo "ЯДЕР: $(nproc)"
  echo "RAM СВОБОДНО до прогона, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО до прогона, МБ: $(free_disk_mb)"
} | tee -a "$LOG"

# --- Стоимость метода: модель, оракул, отсутствие правок продукта ---
{ echo "### СТОИМОСТЬ ### $(date +%FT%T%:z)"
  echo "-- модель Lean: строк всего / без комментариев / теорем / определений / native_decide:"
  echo "   всего: $(wc -l < "$MODEL")"
  echo "   без комментариев и пустых: $(grep -vc '^[[:space:]]*--\|^[[:space:]]*$\|^[[:space:]]*/-' "$MODEL")"
  echo "   теорем: $(grep -c '^theorem' "$MODEL")"
  echo "   определений: $(grep -c '^def \|^structure \|^abbrev ' "$MODEL")"
  echo "   native_decide: $(grep -c 'native_decide' "$MODEL")"
  echo "   sorry (обязан быть 0): $(grep -c 'sorry' "$MODEL")"
  echo "   import Mathlib (обязан быть 0): $(grep -c 'import Mathlib' "$MODEL")"
  echo "-- оракул Rust: строк / тестов:"
  echo "   строк: $(wc -l < "crates/vecdht-node/tests/$ORACLE.rs")"
  echo "   тестов: $(grep -c '#\[test\]' "crates/vecdht-node/tests/$ORACLE.rs")"
  echo "-- зависимостей добавлено не было:"
  git diff HEAD --stat -- Cargo.toml Cargo.lock crates/*/Cargo.toml
  echo "-- продуктовый код, wire и спека этим циклом не тронуты (пусто = ок):"
  git diff HEAD --stat -- crates/vecdht-node/src crates/vecdht-index/src crates/vecdht-crypto/src crates/vecdht-wire/src docs/VecDHT-SPEC-v8.md
} | tee -a "$LOG"

# --- Lean: проверка модели тем же ядром, что и перед пре-регистрацией ---
lean_t0=$(date +%s%N)
run_step "LEAN CHECK $MODEL" lean "$MODEL"
lean_t1=$(date +%s%N)
echo "LEAN_MS=$(( (lean_t1 - lean_t0) / 1000000 )) LEAN_S=$(( (lean_t1 - lean_t0) / 1000000000 ))" | tee -a "$LOG"

# --- Инвентарь: что именно транскрибировано и где в коде стоит измеряемое ---
{ echo "### ИНВЕНТАРЬ ### $(date +%FT%T%:z)"
  echo "-- порядок гейтов Publish (модель повторяет его по строкам):"
  sed -n '683,700p;712,720p;735,760p;766,790p' crates/vecdht-node/src/node.rs
  echo "-- pow_input: owner, shard, epoch, slot_key, expires — cluster_id нет:"
  sed -n '63,80p' crates/vecdht-crypto/src/pow.rs
  echo "-- константы сложности §11.2:"
  sed -n '18,24p' crates/vecdht-crypto/src/pow.rs
  echo "-- переезд между posting list'ами:"
  sed -n '313,330p' crates/vecdht-index/src/ivf.rs
  echo "-- размер ячейки есть в индексе и не вызывается при приёме:"
  grep -rn "cluster_len" crates/*/src | head
  echo "-- скан без дедупликации списка кластеров:"
  sed -n '471,500p' crates/vecdht-index/src/ivf.rs
  echo "-- документированная уверенность, которую проверяет тест (1):"
  sed -n '267,274p' crates/vecdht-node/src/testing.rs
  echo "-- обещание спеки (строка 1392):"
  grep -n "надувание кластеров" docs/VecDHT-SPEC-v8.md | head -2
  echo "-- тесты оракула:"
  grep -n "#\[test\]" -A 1 "crates/vecdht-node/tests/$ORACLE.rs"
} | tee -a "$LOG"

# --- Оракул: замер цены. Последовательно, чтобы замеры не мешали друг другу ---
rust_t0=$(date +%s%N)
run_step "ORACLE BUILD --no-run" cargo test -j 2 -p vecdht-node --test "$ORACLE" --no-run
run_step "ORACLE RUN --nocapture" cargo test -j 2 -p vecdht-node --test "$ORACLE" -- --nocapture --test-threads=1
rust_t1=$(date +%s%N)
echo "RUST_MS=$(( (rust_t1 - rust_t0) / 1000000 )) RUST_S=$(( (rust_t1 - rust_t0) / 1000000000 ))" | tee -a "$LOG"

{ echo "### РЕСУРСЫ ПОСЛЕ ОРАКУЛА ### $(date +%FT%T%:z)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "target/, МБ: $(du -sm target 2>/dev/null | cut -f1)"
  echo "лог, МБ: $(du -sm "$LOG" 2>/dev/null | cut -f1)"
} | tee -a "$LOG"

run_step "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node

{ echo "### ИТОГ ### $(date +%FT%T%:z)"
  echo "HEAD после прогонов: $(git rev-parse --short HEAD)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "лог: $LOG ($(wc -l < "$LOG") строк)"
  echo "HELPER_EXIT=$WORST_RC (худший из кодов шагов; 0 = все шаги отработали; exit в блоке | tee не сработал бы — он вышел бы из подшелла)"
} | tee -a "$LOG"
exit "$WORST_RC"
