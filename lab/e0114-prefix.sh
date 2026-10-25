#!/usr/bin/env bash
# Снимок PRE_FIX для `E-0114`, исполненный ДО коммита пре-регистрации. Жанр как в
# `lab/logs/e0113-prefix.log`: заголовок с хешами входов, три блока фактов, метки ASCII.
# Отличие: базовое дерево здесь уже несёт носитель и прибор (они ещё не закоммичены), поэтому
# «до правки» исполняется посадкой — `lab/v9-payout-plant-decoy.py` возвращает в копию носителя
# прежнюю формулу `term_hash`, и красный прогон есть результат работы прибора, а не память о
# прежнем тексте.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0114pre.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
LOG=lab/logs/e0114-prefix.log
DOC=docs/PAID_PAYOUT-VECTORS.md
ODOC=docs/PAID_ORDER-VECTORS.md
SPEC=docs/VecDHT-SPEC-v9.md
NOTE=lab/notes/DESIGN-2026-10-25-chain-binding.md
BRIDGE=lab/v9-payout-bridge.py
PLANT=lab/v9-payout-plant-decoy.py
GEN=crates/vecdht-orders/tests/payout_claim_vectors.rs
say() { printf '%s\n' "$*" >> "$LOG"; }
{ echo "########## E-0114 PRE_FIX · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) (носитель, прибор и генератор — рабочие, не закоммичены) ##########"; } >> "$LOG"
bash lab/disk-report.sh 2>&1 | tail -n 3 >> "$LOG"
for pair in "DOC_SHA=$DOC" "SPEC_SHA=$SPEC" "ODOC_SHA=$ODOC" "NOTE_SHA=$NOTE" "BRIDGE_SHA=$BRIDGE" "PLANT_SHA=$PLANT" "GEN_SHA=$GEN" "RUST_SRC_SHA=crates/vecdht-orders/src/lib.rs"; do
  k=${pair%%=*}; f=${pair#*=}
  say "$k=$(sha256sum "$f" | cut -d' ' -f1)"
done
say "PYTHON=$(python -c 'import sys; print(sys.version.split()[0])')"

say "### RUN 1 · контроль посадки: прежняя формула term_hash в копии носителя ###"
python "$PLANT" "$DOC" > "$OUT/decoy.md" 2> "$OUT/plant.log"
say "V9CTL_PLANT_EXIT=$?"
cat "$OUT/plant.log" >> "$LOG"
V9C_VERBOSE=1 python "$BRIDGE" "$OUT/decoy.md" "$SPEC" "$ODOC" "$NOTE" > "$OUT/run1.txt" 2>&1
# Имена фактов в этом снимке не повторяются между блоками: `E0114_BRIDGE_EXIT` в двух смыслах
# (красный контроль и зелёный прогон) читался бы как два владельца одного имени.
say "V9CTL_BRIDGE_EXIT=$?"
grep -E '^V9C_|^  # ' "$OUT/run1.txt" | sed 's/^V9C_/V9CTL_/' >> "$LOG"

say "### RUN 2 · прибор на носителе как есть (ожидание зелёного прогона) ###"
V9C_VERBOSE=1 python "$BRIDGE" "$DOC" "$SPEC" "$ODOC" "$NOTE" > "$OUT/run2.txt" 2>&1
say "E0114_BRIDGE_EXIT=$?"
grep -E '^V9C_|^  # ' "$OUT/run2.txt" >> "$LOG"

say "### RUN 3 · генератор носителя в temp: побайтное воспроизведение и V9P_* ###"
REGEN="$OUT/carrier_regen.md"
V9P_VECTORS_OUT="$REGEN" cargo test -q -p vecdht-orders --test payout_claim_vectors -- --nocapture > "$OUT/gen.txt" 2>&1
say "V9P_GEN_EXIT=$?"
grep -E '^V9P_' "$OUT/gen.txt" >> "$LOG"
say "V9P_REGEN_SHA=$(sha256sum "$REGEN" | cut -d' ' -f1)"
say "V9P_COMMITTED_SHA=$(sha256sum "$DOC" | cut -d' ' -f1)"
if diff -q "$REGEN" "$DOC" >/dev/null 2>&1; then say "V9C_CARRIER_REPRODUCED=1"; else say "V9C_CARRIER_REPRODUCED=0"; fi
say "### КОНЕЦ PRE_FIX ###"
