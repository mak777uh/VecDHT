#!/usr/bin/env bash
# Верификация воркспейса для цикла: $1 = метка блока (например E-0061).
# Append-блок в lab/logs/workspace-verify-2026-10-22.log: cargo test --workspace + clippy -D warnings
# с настоящими exit-кодами. Helper исполняет команду целиком (урок e0049).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LABEL="${1:?метка блока, например E-0061}"
LOG="lab/logs/workspace-verify-2026-10-22.log"
{ echo "########## $LABEL · workspace-verify · $(date +%FT%T%:z) ##########"
  echo "### cargo test --workspace ### $(date +%FT%T%:z)"
  cargo test -j 2 --workspace 2>&1
  echo "TEST_EXIT=$?"
  echo "### clippy ### $(date +%FT%T%:z)"
  cargo clippy -j 2 --workspace --all-targets -- -D warnings 2>&1
  echo "CLIPPY_EXIT=$?"
  # Формальные модели проверяются тем же закрытием цикла: без этой строки `lab/lean/` мог
  # сгнить незаметно — у helper'ов `e0078`/`e0079` они исполнялись один раз, в своём цикле.
  echo "### lean-check ### $(date +%FT%T%:z)"
  bash lab/lean-check.sh --quiet 2>&1
  echo "LEAN_EXIT=$?"
  # Гейт круга (боль -> источники -> рубрика Lean -> оракул) и индекс источников проверяются
  # вместе с кодом: механизм, который никто не гоняет, через пять циклов превращается в текст.
  echo "### cycle-gate selftest ### $(date +%FT%T%:z)"
  python lab/cycle-gate.py selftest 2>&1
  echo "CYCLEGATE_EXIT=$?"
  echo "### library check+digest ### $(date +%FT%T%:z)"
  python lab/library.py check 2>&1
  echo "LIBCHECK_EXIT=$?"
  python lab/library.py digest 2>&1 | grep -E "^(LIBDIGEST|LIBCLASSES|КЛАССЫ|ДАЙДЖЕСТ)|ВНИМАНИЕ"
  echo "LIBDIGEST_EXIT=$?"
} >> "$LOG"
