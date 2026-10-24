#!/usr/bin/env bash
# Прибор формального контура №2 (после Lean): Verus исполняет контракты над арифметикой продукта.
#
# Зачем он отдельный, а не ещё один `lab/lean-check.sh`: Lean в этом репозитории доказывает
# утверждения о *политиках на перечислимых множествах* (двери, лесенки, cap как выбор политики) и
# делает это через `native_decide` — то есть через перебор. Verus доказывает утверждения о *том же
# теле, что компилируется в продукт*: контракт висит на функции, транскрибированной один в один из
# `crates/vecdht-node/src/admission.rs`, и арифметика идёт через SMT, а не через перебор. Разница
# видна на дефекте: снятое `requires` о переполнении Verus ловит ошибкой в `2 * live`, а Lean-модель
# такого состояния не содержит вовсе (у неё `Nat`, переполнения нет по построению) — `ADR-0053`.
#
# Метки вывода (стабильные, чтобы парсер прогона и `lab/workspace-verify.sh` не зависели от прозы):
#   VERUS_FILE=…, VERUS_VERIFIED=<n>, VERUS_ERRORS=<n>, VERUS_STATUS=OK|BAD|SKIP, VERUS_MS=…, VERUS_RC=…
#   VERUS_TOTAL verified=… errors=… files=… status=OK|BAD|SKIP
#   CONST_MATCH=OK|BAD (сверка констант модели с константами продукта — см. «Мост» ниже)
#
# Разрешённое молчание и его граница: если бинаря Verus на хосте нет, прибор печатает SKIP, а падает
# (код 1) только при `VEC_DHT_VERUS_REQUIRED=1`. Отсутствие тулчейна и недоказанный контракт — разные
# события, и смешать их значит однажды прочитать зелёный круг там, где никто ничего не проверял.
# Поэтому `lab/workspace-verify.sh` зовёт прибор с REQUIRED=1: пропустить проверку при закрытии цикла
# — это дыра, а не экономия.
#
# Мост «модель ↔ код»: `--check-constants` сверяет три числа (`CELL_CAP_NUM`, `CLUSTERS_PER_SHARD`,
# `CELL_CAP_MIN`) и формулу тела в `lab/proofs/verus/cap_math.rs` с `crates/vecdht-node/src/admission.rs`.
# Это НЕ доказательство соответствия модели и кода: оно ловит только расхождение констант и текста
# формулы. Полная эквивалентность не проверена, и карточка закрытия обязана писать именно так.
#
# Употребление:
#   bash lab/verus-check.sh [--quiet] [файл …]     # проверка (без аргументов — все lab/proofs/verus/*.rs)
#   bash lab/verus-check.sh selftest               # три посаженных дефекта + контроль
#   bash lab/verus-check.sh --check-constants      # только мост модель/код
# Переменные: VEC_DHT_VERUS — путь к бинарю, VEC_DHT_VERUS_TOOLCHAIN — тулчейн, VEC_DHT_VERUS_REQUIRED=1.
set -uo pipefail
cd "${VEC_DHT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

VERUS_BIN="${VEC_DHT_VERUS:-/c/Users/Admin/verus/verus-x86-win/verus.exe}"
MODEL="lab/proofs/verus/cap_math.rs"
PRODUCT="crates/vecdht-node/src/admission.rs"
WIRE_CONST="crates/vecdht-wire/src/constants.rs"
QUIET=0
MODE=check
FILES=()
for a in "$@"; do
  case "$a" in
    --quiet) QUIET=1 ;;
    selftest) MODE=selftest ;;
    --check-constants) MODE=constants ;;
    *) FILES+=("$a") ;;
  esac
done
say() { [ "$QUIET" -eq 1 ] || echo "$@"; }

have_verus() { [ -f "$VERUS_BIN" ] || [ -x "$VERUS_BIN" ]; }

require_verus_or_skip() {
  if have_verus; then return 0; fi
  say "VERUS_STATUS=SKIP причина=нет_бинаря:$VERUS_BIN"
  if [ "${VEC_DHT_VERUS_REQUIRED:-0}" = "1" ]; then
    echo "VERUS_REQUIRED_BUT_MISSING"
    exit 1
  fi
  echo "VERUS_TOTAL verified=0 errors=0 files=0 status=SKIP"
  exit 0
}

RUN_VERIFIED=0
RUN_ERRORS=0
RUN_STATUS=BAD

run_one() {
  local f="$1"
  # Без `--compile`: на этом хосте сборка до бинаря падает на линковке (`link.exe`), а вердикт
  # контрактов от неё не зависит — его даёт строка `verification results::`. Замерено: с --compile
  # rc=1 при verified=8 errors=0, то есть прибор врал бы о провале там, где всё доказано.
  local out line rc start end ms
  start=$(date +%s%3N 2>/dev/null || echo 0)
  out="$("$VERUS_BIN" "$f" 2>&1)"; rc=$?
  end=$(date +%s%3N 2>/dev/null || echo 0)
  ms=$((end - start))
  line=$(printf '%s\n' "$out" | grep -E "verification results::" | tail -1)
  RUN_VERIFIED=$(printf '%s' "$line" | sed -n 's/.*verification results:: \([0-9]\+\) verified.*/\1/p')
  RUN_ERRORS=$(printf '%s' "$line" | sed -n 's/.*verification results:: [0-9]\+ verified, \([0-9]\+\) errors.*/\1/p')
  RUN_VERIFIED="${RUN_VERIFIED:-0}"; RUN_ERRORS="${RUN_ERRORS:-0}"
  RUN_STATUS=OK
  if [ "$rc" -ne 0 ] || [ "$RUN_ERRORS" -gt 0 ]; then RUN_STATUS=BAD; fi
  say "VERUS_FILE=$f VERUS_VERIFIED=$RUN_VERIFIED VERUS_ERRORS=$RUN_ERRORS VERUS_STATUS=$RUN_STATUS VERUS_MS=$ms VERUS_RC=$rc"
  if [ "$RUN_STATUS" = "BAD" ]; then
    printf '%s\n' "$out" | grep -E "^error" | head -4 | sed 's/^/    /'
  fi
  [ "$RUN_STATUS" = "OK" ]
}

# Модель обязана называть те же числа и ту же формулу, что продукт: расхождение превращает все её
# теоремы в утверждения про другую функцию.
check_constants() {
  local bad=0 pair m p
  for pair in CELL_CAP_NUM CLUSTERS_PER_SHARD CELL_CAP_MIN; do
    m=$(grep -oE "pub const ${pair}: u64 = [0-9_]+" "$MODEL" | grep -oE "[0-9_]+$" | tail -1)
    p=$(grep -hoE "const ${pair}(: [A-Za-z0-9_ ]+)? = [0-9_]+" "$PRODUCT" "$WIRE_CONST" 2>/dev/null | grep -oE "[0-9_]+$" | tail -1)
    m="${m:-нет}"; p="${p:-нет}"
    if [ "${m//_/}" != "${p//_/}" ]; then
      echo "CONST_MATCH=BAD ${pair}: модель=${m} продукт=${p}"
      bad=1
    else
      say "CONST_OK ${pair}=${m}"
    fi
  done
  local pat mbody pbody
  pat='\(\(CELL_CAP_NUM \* live_in_shard\)\.saturating_add\(per - 1\) \/ per\)\.max\(min\)'
  mbody=$(grep -oE "$pat" "$MODEL" | tail -1)
  pbody=$(grep -oE "$pat" "$PRODUCT" | tail -1)
  if [ -z "$mbody" ] || [ "$mbody" != "$pbody" ]; then
    echo "CONST_MATCH=BAD формула_тела: модель='${mbody}' продукт='${pbody}'"
    bad=1
  else
    say "CONST_OK формула_тела совпадает дословно"
  fi
  if [ "$bad" -eq 0 ]; then echo "CONST_MATCH=OK"; return 0; else return 1; fi
}

if [ "$MODE" = "constants" ]; then
  check_constants; exit $?
fi

if [ "$MODE" = "selftest" ]; then
  require_verus_or_skip
  export RUSTUP_TOOLCHAIN="${VEC_DHT_VERUS_TOOLCHAIN:-1.99.1-x86_64-pc-windows-msvc}"
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  cp "$MODEL" "$TMP/good.rs"
  # (1) снятая предпосылка переполнения: контракт обязан падать, а не «доказывать меньше».
  sed '/^        live_in_shard <= MAX_LIVE_NO_OVERFLOW,$/d' "$MODEL" > "$TMP/overflow.rs"
  # (2) модель расходится с продуктом: знаменатель относительной ветки 16 → 15.
  sed 's|let rel = (live \* 2 + 15) / 16;|let rel = (live * 2 + 15) / 15;|' "$MODEL" > "$TMP/constdrift.rs"
  # (3) перевёрнутая ветка максимума: пол перестаёт быть полом, `cap_spec_floor` падает.
  sed 's|    if rel > min { rel } else { min }|    if rel > min { min } else { rel }|' "$MODEL" > "$TMP/inverted.rs"
  PASS=0; TOTAL=0
  for case in good:OK overflow:BAD constdrift:BAD inverted:BAD; do
    name="${case%%:*}"; want="${case##*:}"
    TOTAL=$((TOTAL + 1))
    run_one "$TMP/$name.rs" || true
    if [ "$RUN_STATUS" = "$want" ]; then
      PASS=$((PASS + 1))
      echo "  ${name}: ожидалось=${want} получено=${RUN_STATUS} ОТБИТО"
    else
      echo "  ${name}: ожидалось=${want} получено=${RUN_STATUS} ПРОПУЩЕНО"
    fi
  done
  if check_constants; then
    PASS=$((PASS + 1)); echo "  мост_констант: КОНТРОЛЬ OK"
  else
    echo "  мост_констант: ПРОПУЩЕНО (модель и продукт расходятся)"
  fi
  TOTAL=$((TOTAL + 1))
  echo "VERUS_SELFTEST total=$TOTAL passed=$PASS"
  [ "$PASS" -ge "$TOTAL" ] || exit 1
  exit 0
fi

require_verus_or_skip
export RUSTUP_TOOLCHAIN="${VEC_DHT_VERUS_TOOLCHAIN:-1.99.1-x86_64-pc-windows-msvc}"
if [ "${#FILES[@]}" -eq 0 ]; then
  mapfile -t FILES < <(ls lab/proofs/verus/*.rs 2>/dev/null)
fi
TOTAL_VERIFIED=0; TOTAL_ERRORS=0; BAD_FILES=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || { say "VERUS_FILE=$f VERUS_STATUS=SKIP причина=нет_файла"; continue; }
  if ! run_one "$f"; then BAD_FILES=$((BAD_FILES + 1)); fi
  TOTAL_VERIFIED=$((TOTAL_VERIFIED + RUN_VERIFIED))
  TOTAL_ERRORS=$((TOTAL_ERRORS + RUN_ERRORS))
done
overall=OK
[ "$BAD_FILES" -gt 0 ] && overall=BAD
if ! check_constants; then overall=BAD; fi
echo "VERUS_TOTAL verified=$TOTAL_VERIFIED errors=$TOTAL_ERRORS files=${#FILES[@]} status=$overall"
[ "$overall" = "OK" ] || exit 1
exit 0
