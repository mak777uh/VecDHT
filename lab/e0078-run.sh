#!/usr/bin/env bash
# E-0078: проба формальных методов — Lean 4 против property-based тестов на шве §15/§9.2.
# Helper исполняет команду целиком (урок e0049), лог append-only.
# ДИАГНОЗ-1: в первой версии таймеры печатали сотые доли секунды под именем «SECONDS»
# (деление на 1e8 при nanosecond-разности). Здесь таймер в мс, и рядом — секунды.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LOG="lab/logs/e0078-all.log"
run_step() { # $1=label; rest=полная команда
  local label="$1"; shift
  local rc out; out=$(mktemp)
  echo "### $label ### $(date +%FT%T%:z)" | tee -a "$LOG"
  "$@" >"$out" 2>&1; rc=$?
  cat "$out" | tee -a "$LOG"; rm -f "$out"
  echo "EXIT=$rc" | tee -a "$LOG"
  return $rc
}
{ echo "=== E-0078 прогон $(date +%FT%T%:z) ==="; git rev-parse --short HEAD; rustc --version; gcc --version | head -1; lean --version; } | tee -a "$LOG"

# --- Стоимость: строки и число проверенных утверждений ---
{ echo "### СТОИМОСТЬ ###"
  echo "-- модель Lean: строк всего / нетеоремных / теорем / native_decide / Mathlib:"
  echo "   всего: $(wc -l < lab/lean/VecDHT/Auth.lean)"
  echo "   без комментариев и пустых: $(grep -vc '^\s*--\|^\s*$\|^\s*/-' lab/lean/VecDHT/Auth.lean)"
  echo "   теорем: $(grep -c '^theorem' lab/lean/VecDHT/Auth.lean)"
  echo "   определений: $(grep -c '^def \|^structure \|^abbrev ' lab/lean/VecDHT/Auth.lean)"
  echo "   native_decide: $(grep -c 'native_decide' lab/lean/VecDHT/Auth.lean)"
  echo "   import Mathlib (обязан быть 0): $(grep -c 'import Mathlib' lab/lean/VecDHT/Auth.lean)"
  echo "-- базовая линия Rust: строк / тестов:"
  echo "   строк: $(wc -l < crates/vecdht-node/tests/s15_lean_correspondence.rs)"
  echo "   тестов: $(grep -c '#\[test\]' crates/vecdht-node/tests/s15_lean_correspondence.rs)"
  echo "-- зависимостей добавлено не было:"
  git diff HEAD --stat -- Cargo.toml Cargo.lock crates/*/Cargo.toml
} | tee -a "$LOG"

# --- Lean: проверка модели (счёт ошибок и время) ---
{ echo "### LEAN CHECK lab/lean/VecDHT/Auth.lean ### $(date +%FT%T%:z)"
  lean_out=$(mktemp)
  lean_t0=$(date +%s%N)
  lean lab/lean/VecDHT/Auth.lean >"$lean_out" 2>&1
  lean_rc=$?
  lean_t1=$(date +%s%N)
  lean_err=$(grep -c 'error' "$lean_out" || true)
  cat "$lean_out"; rm -f "$lean_out"
  echo "EXIT=$lean_rc"
  echo "LEAN_MS=$(( (lean_t1 - lean_t0) / 1000000 )) LEAN_S=$(( (lean_t1 - lean_t0) / 1000000000 )) ОШИБОК=$lean_err"
} | tee -a "$LOG"

# --- Rust: оракул соответствия и базовая линия ---
rust_t0=$(date +%s%N)
run_step "BUILD --no-run" cargo test -j 2 -p vecdht-node --test s15_lean_correspondence --no-run
run_step "RUN --nocapture" cargo test -j 2 -p vecdht-node --test s15_lean_correspondence -- --nocapture
rust_t1=$(date +%s%N)
echo "RUST_MS=$(( (rust_t1 - rust_t0) / 1000000 )) RUST_S=$(( (rust_t1 - rust_t0) / 1000000000 ))" | tee -a "$LOG"

{ echo "### ИНВЕНТАРЬ ###"
  echo "-- модель транскрибирует функции Rust:"
  grep -n "^def \|^structure " lab/lean/VecDHT/Auth.lean
  echo "-- в Rust то же самое по именам исходника:"
  grep -n "fn count_valid" -A 10 crates/vecdht-crypto/src/cert.rs
  grep -n "fn check_indices" -A 10 crates/vecdht-node/src/membership.rs
  grep -n "fn check_authorities" -A 20 crates/vecdht-node/src/membership.rs
  grep -n "fn check_members" -A 20 crates/vecdht-node/src/membership.rs
  echo "-- инвариант спеки §9.2 (строка 969 зеркала):"
  grep -n "позиция подписанта" docs/VecDHT-SPEC-v8.md
  echo "-- пороги двух дверей (находка 13):"
  grep -n "authority_threshold" crates/vecdht-node/src/membership.rs crates/vecdht-node/src/config.rs | head -20
  grep -n "self.threshold\|authorities.threshold" crates/vecdht-crypto/src/cert.rs | head -20
  echo "-- манифест запрещает повтор ключа авторитета, AuthoritySet::new — нет:"
  grep -n "дублирующийся ключ авторитета" crates/vecdht-artifact/src/manifest.rs
  grep -n "pub fn new" -A 3 crates/vecdht-crypto/src/cert.rs | head -12
  echo "-- оракул E-0078:"
  grep -n "#\[test\]" -A 1 crates/vecdht-node/tests/s15_lean_correspondence.rs
  echo "-- продуктовый код, спека и wire этим циклом не тронуты:"
  git diff HEAD --stat -- crates/vecdht-crypto/src crates/vecdht-node/src crates/vecdht-wire docs/VecDHT-SPEC-v8.md
} | tee -a "$LOG"

run_step "КОНТРОЛЬ vecdht-node" cargo test -j 2 -p vecdht-node
