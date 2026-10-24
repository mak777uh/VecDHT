#!/usr/bin/env bash
# E-0103: узел пересчитывает cluster_id (§7.3) — H-0103.
#
# Один прибор на оба прогона: `crates/vecdht-node/tests/c103_cluster_reassign.rs`, синтетическая
# сетка 1024×384 (номер кластера в двух координатах), пять тестов: подделка того же шарда, подделка
# в чужой шард, честный контроль, fail-open без артефакта, цена assign.
#
# Шаги:
#   (0) gate ДО замерного helper'а (правило AGENTS.md п. 11: E-0090 заплатил 30 мин верификации за
#       `GATE_H0090_OK=0`); носитель: диск/RAM/pagefile;
#   (1) два релизных прогона на неизменном дереве, литеральные `C103_*`;
#   (2) производные факты и совпадение векторов двух прогонов;
#   (3) `audit -n 5`;
#   (4) `workspace-verify.sh E-0103`;
#   (5) стража текста и сверка `lab/expectations/e0103.tsv`;
#   (6) носитель после прогона.
#
# PRE_FIX снимается не здесь: он требует дерева, где блок пересчёта заменён на `msg.cluster_id`, и
# записан отдельным логом `lab/logs/e0103-prefix.log` (см. E-0103 «Ход»). Здесь дерево неизменно.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0103-all.log"
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0103.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
FACTS=""
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
# Литеральная печать: линт порогов видит `KEY=` в источнике, а не шаблон с переменной.
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
pick() { grep -o "$1=[A-Za-z0-9_.:-]*" "$2" | tail -1 | cut -d= -f2; }

say "########## E-0103 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 gate и носитель ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0103 --skip-lean 2>&1 | tail -n 8 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
printf "GATE_H0103_OK=%s\n" "$gok" | tee -a "$LOG"
printf "GATE_H0103_OK=%s\n" "$gok" >> "$OUT/gate.txt"
note "$rc"
if [ "$gok" != 1 ]; then
  say "ГЕЙТ НЕ ПРОЙДЕН — замер не начинается (порог (0) helper'а)"
  say "WORST_RC=1"
  exit 1
fi
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf "%s" "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then dok=1; else dok=0; fi
printf "DISK_GE_15000=%s\n" "$dok" | tee -a "$LOG"

say "### ШАГ 1 два релизных прогона ### $(date +%FT%T%:z)"
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  : > "$FACTS"
  cargo test --release -p vecdht-node --test c103_cluster_reassign -- --nocapture \
    > "$OUT/run$f.txt" 2>&1
  rc=$?
  note "$rc"
  tail -n 30 "$OUT/run$f.txt" | tee -a "$LOG"
  ok5=$(grep -c '^test .* \.\.\. ok$' "$OUT/run$f.txt")
  if [ "$rc" -eq 0 ] && [ "${ok5:-0}" = 5 ]; then measured=1; else measured=0; fi
  forged=$(pick C103_FORGED_ENTRY_CELL "$OUT/run$f.txt")
  claimed=$(pick C103_FORGED_CLAIMED_COUNT "$OUT/run$f.txt")
  reassigned=$(pick C103_REASSIGNED "$OUT/run$f.txt")
  honest=$(pick C103_HONEST_ENTRY_CELL "$OUT/run$f.txt")
  honest_r=$(pick C103_HONEST_REASSIGNED "$OUT/run$f.txt")
  xcode=$(pick C103_CROSS_SHARD_CODE "$OUT/run$f.txt")
  xcount=$(pick C103_CROSS_SHARD "$OUT/run$f.txt")
  xstore=$(pick C103_CROSS_SHARD_STORE "$OUT/run$f.txt")
  nocell=$(pick C103_NO_CENTROIDS_ENTRY_CELL "$OUT/run$f.txt")
  nounv=$(pick C103_NO_CENTROIDS_UNVERIFIED "$OUT/run$f.txt")
  budget=$(pick C103_ASSIGN_BUDGET_US "$OUT/run$f.txt")
  le300=$(pick C103_ASSIGN_P50_LE_300US "$OUT/run$f.txt")
  p50=$(pick C103_ASSIGN_P50_US "$OUT/run$f.txt")
  emit "C103_MEASURED=${measured}"
  emit "C103_FORGED_ENTRY_CELL=${forged:-NONE}"
  emit "C103_FORGED_CLAIMED_COUNT=${claimed:-NONE}"
  emit "C103_REASSIGNED=${reassigned:-NONE}"
  emit "C103_HONEST_ENTRY_CELL=${honest:-NONE}"
  emit "C103_HONEST_REASSIGNED=${honest_r:-NONE}"
  emit "C103_CROSS_SHARD_CODE=${xcode:-NONE}"
  emit "C103_CROSS_SHARD=${xcount:-NONE}"
  emit "C103_CROSS_SHARD_STORE=${xstore:-NONE}"
  emit "C103_NO_CENTROIDS_ENTRY_CELL=${nocell:-NONE}"
  emit "C103_NO_CENTROIDS_UNVERIFIED=${nounv:-NONE}"
  emit "C103_ASSIGN_BUDGET_US=${budget:-NONE}"
  emit "C103_ASSIGN_P50_LE_300US=${le300:-0}"
  emit "C103_EXIT=$rc"
  emit "C103_RUNS=2"
  emit "DISK_GE_15000=$dok"
  # Медиана assign печатается рядом, но в ожидания не входит (правило 7 (д)).
  printf "C103_ASSIGN_P50_US_PRINTED=%s\n" "${p50:-NONE}" | tee -a "$LOG"
done

if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable=1; else stable=0; fi
printf "C103_VECTOR_STABLE=%s\n" "$stable" | tee -a "$LOG"
for f in 1 2; do printf "C103_VECTOR_STABLE=%s\n" "$stable" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 2 audit ### $(date +%FT%T%:z)"
python lab/cycle-gate.py audit -n 5 > "$OUT/audit.txt" 2>&1
rc=$?; note "$rc"
tail -n 3 "$OUT/audit.txt" | tee -a "$LOG"
aud=$(sed -n 's/.*нарушениий=\([0-9]*\).*/\1/p' "$OUT/audit.txt" | tail -1)
printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" | tee -a "$LOG"

say "### ШАГ 3 полная верификация ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0103 2>&1 | tail -n 12 | tee -a "$LOG"
vrc=${PIPESTATUS[0]}
printf "VERIFY_EXIT=%s\n" "$vrc" | tee -a "$LOG"
note "$vrc"

for f in 1 2; do
  printf "GATE_H0103_OK=%s\n" "$gok" >> "$OUT/facts_r$f.txt"
  printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "VERIFY_EXIT=%s\n" "$vrc" >> "$OUT/facts_r$f.txt"
done

say "### ШАГ 4 стража текста и сверка ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh \
  crates/vecdht-node/tests/c103_cluster_reassign.rs \
  lab/hypotheses/H-0103-node-recomputes-cluster-id.md \
  lab/experiments/E-0103-cluster-reassign.md \
  lab/expectations/e0103.tsv lab/e0103-run.sh 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note $rc

python lab/expect.py lab/expectations/e0103.tsv "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" 2>&1 | tail -n 8 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "### ШАГ 5 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
