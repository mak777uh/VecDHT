#!/usr/bin/env bash
# E-0080: §16.3 — «шард без живого владельца». Второй цикл по правилу, принятому владельцем
# после E-0078: формальная модель (`lab/lean/VecDHT/Shard.lean`) написана ДО замера и подсказала,
# что мерить; оракул `s163_shard_without_owner.rs` меряет.
#
# Helper исполняет команду целиком и ведёт append-only лог (урок e0049). Единицы подписаны:
# таймеры печатают `_MS`/`_S`, RAM и диск — целые МБ (урок ДИАГНОЗ-1 в e0077 и e0078).
#
# Ресурсы — часть метода, а не сноски (указание владельца): свободная RAM меряется до прогона,
# после оракула и в ИТОГЕ, числа уходят в репозиторий вместе с логом, а локальные черновики
# прогона (осевшие тестовые каталоги в %TEMP%, stdout-файлы) после коммита удаляются отсюда.
# Каталог `target/` объявляется вслух: `cargo clean` без него не делается.
#
# Защита от ДИАГНОЗ-6 (e0079): скрипт копирует себя в неизменяемый снимок и исполняет его, пока
# оригинал можно править. Корень репозитория передаётся через переменную, потому что у снимка
# свой `dirname`.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0080-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0080-all.log"
ORACLE=s163_shard_without_owner
MODEL=lab/lean/VecDHT/Shard.lean

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

{ echo "=== E-0080 прогон $(date +%FT%T%:z) ==="
  echo "HEAD: $(git rev-parse --short HEAD)"
  echo "rustc: $(rustc --version)"
  echo "gcc: $(gcc --version | head -1)"
  echo "lean: $(lean --version)"
  echo "cargo: $(cargo --version)"
  echo "RAYON_NUM_THREADS=$RAYON_NUM_THREADS"
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
  echo "   строк: $(wc -l < "crates/vecdht-net/tests/$ORACLE.rs")"
  echo "   тестов: $(grep -c '#\[test\]' "crates/vecdht-net/tests/$ORACLE.rs")"
  echo "-- зависимостей добавлено не было:"
  git diff HEAD --stat -- Cargo.toml Cargo.lock crates/*/Cargo.toml
  echo "-- продуктовый код, wire, спека и узел этим циклом не тронуты (пусто = ок):"
  git diff HEAD --stat -- crates/vecdht-net/src crates/vecdht-node/src crates/vecdht-crypto/src crates/vecdht-wire/src docs/VecDHT-SPEC-v8.md
} | tee -a "$LOG"

# --- Lean: проверка модели тем же ядром, что и перед пре-регистрацией ---
lean_t0=$(date +%s%N)
run_step "LEAN CHECK $MODEL" lean "$MODEL"
lean_t1=$(date +%s%N)
echo "LEAN_MS=$(( (lean_t1 - lean_t0) / 1000000 )) LEAN_S=$(( (lean_t1 - lean_t0) / 1000000000 ))" | tee -a "$LOG"

# --- Инвентарь: что именно транскрибировано и где в коде стоит измеряемое ---
{ echo "### ИНВЕНТАРЬ ### $(date +%FT%T%:z)"
  echo "-- обещание спеки (§16.3, строка 1470):"
  sed -n '1468,1471p' docs/VecDHT-SPEC-v8.md
  echo "-- гейт записи: primary раньше эпохи, эпоха раньше nonce (node.rs:721…741):"
  sed -n '717,745p' crates/vecdht-node/src/node.rs
  echo "-- чтение обслуживается без эпизоды и называет нулевую эпоху (node.rs:1027):"
  sed -n '1025,1035p' crates/vecdht-node/src/node.rs
  echo "-- молчание тика: требуется принятый непустой состав с собой (node.rs:299…317, 333…339):"
  sed -n '299,318p;333,340p' crates/vecdht-node/src/node.rs
  echo "-- четвёртый случай «шов молчит»: Err(_) => Ok(Vec::new()) (node.rs:530…538):"
  sed -n '516,539p' crates/vecdht-node/src/node.rs
  echo "-- агент: кандидатов дают провайдеры И аутентифицированные пиры по кредашиалу (agent.rs:1079…1110):"
  sed -n '1079,1112p' crates/vecdht-net/src/agent.rs
  echo "-- шаг повтора lookup фиксирован, ≥ 3 с (agent.rs:1111):"
  sed -n '1111,1115p' crates/vecdht-net/src/agent.rs
  echo "-- NOT_OWNER обрывает без паузы (agent.rs:545…552), временный код зовёт wait() (agent.rs:560…573):"
  sed -n '543,574p' crates/vecdht-net/src/agent.rs
  echo "-- пауза, названная узлом (agent.rs:1313…1321):"
  sed -n '1313,1322p' crates/vecdht-net/src/agent.rs
  echo "-- PoW майнится до отправки, вход — owner, shard, epoch, intent, expires (agent.rs:477…492):"
  sed -n '477,493p' crates/vecdht-net/src/agent.rs
  echo "-- провайдинг объявляется без гейта членства (service.rs:933…942):"
  sed -n '933,943p' crates/vecdht-net/src/service.rs
  echo "-- covers — по кредашиалу, не по членству (handshake.rs:70…75):"
  sed -n '68,76p' crates/vecdht-net/src/handshake.rs
  echo "-- тесты оракула:"
  grep -n "#\[test\]" -A 1 "crates/vecdht-net/tests/$ORACLE.rs"
} | tee -a "$LOG"

# --- Оракул: замер. Последовательно, чтобы сценарии не мешали друг другу ---
rust_t0=$(date +%s%N)
run_step "ORACLE BUILD --no-run" cargo test -j 2 -p vecdht-net --test "$ORACLE" --no-run
run_step "ORACLE RUN --nocapture" cargo test -j 2 -p vecdht-net --test "$ORACLE" -- --nocapture --test-threads=1
rust_t1=$(date +%s%N)
echo "RUST_MS=$(( (rust_t1 - rust_t0) / 1000000 )) RUST_S=$(( (rust_t1 - rust_t0) / 1000000000 ))" | tee -a "$LOG"

{ echo "### РЕСУРСЫ ПОСЛЕ ОРАКУЛА ### $(date +%FT%T%:z)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "target/, МБ: $(du -sm target 2>/dev/null | cut -f1)"
  echo "лог, МБ: $(du -sm "$LOG" 2>/dev/null | cut -f1)"
  echo "осевших тестовых каталогов s163 в %TEMP%: $(ls -d "$TEMP"/vecdht-net-s163-* 2>/dev/null | wc -l)"
} | tee -a "$LOG"

run_step "КОНТРОЛЬ vecdht-net" cargo test -j 2 -p vecdht-net

{ echo "### ИТОГ ### $(date +%FT%T%:z)"
  echo "HEAD после прогонов: $(git rev-parse --short HEAD)"
  echo "RAM СВОБОДНО, МБ: $(free_ram_mb)"
  echo "ДИСК СВОБОДНО, МБ: $(free_disk_mb)"
  echo "лог: $LOG ($(wc -l < "$LOG") строк)"
  echo "HELPER_EXIT=$WORST_RC (худший из кодов шагов; 0 = все шаги отработали)"
} | tee -a "$LOG"
exit "$WORST_RC"
