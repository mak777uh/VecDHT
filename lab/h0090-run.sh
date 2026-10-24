#!/usr/bin/env bash
# E-0090: хабность реального корпуса и цена слепого отравления (H-0090).
#
# Прибор один и тот же на оба прогона: `crates/vecdht-embed/tests/h0090_hubness.rs` читает внешний
# кеш эмбеддингов `*.p0emb` и `centroid.bin` из `artifact-50k` — те же файлы, что в `E-0004`, и
# ничего не переобучает. Код продукта в цикле не меняется: PRE_FIX здесь — контрольная точка
# `E-0004` (recall@10 = 0.8303 при nprobe=16), а не снимок другого продукта.
#
# Шаги:
#   (0) носитель: диск/RAM/pagefile (порог (11) пишет три числа);
#   (1) два прогона теста на неизменном дереве, литеральные `H0090_*`;
#   (2) производные пороги (skew, recall-диапазон, пробел зонда, слепой захват, контроль);
#   (3) `cycle-gate.py gate H-0090 --skip-lean` и `audit -n 5`;
#   (4) `workspace-verify.sh E-0090` (игнорируемый тест в регрессию не входит — он меряет корпус);
#   (5) стража текста и сверка `lab/expectations/e0090.tsv`.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
export VEC_DHT_H0090_CORPUS_CACHE="${VEC_DHT_H0090_CORPUS_CACHE:-/c/Users/Admin/models/p0-msmarco/corpus-50k.p0emb}"
export VEC_DHT_H0090_QUERIES_CACHE="${VEC_DHT_H0090_QUERIES_CACHE:-/c/Users/Admin/models/p0-msmarco/queries-1k.p0emb}"
export VEC_DHT_H0090_CENTROIDS="${VEC_DHT_H0090_CENTROIDS:-/c/Users/Admin/models/p0-msmarco/artifact-50k/centroid.bin}"
LOG="lab/logs/e0090-all.log"
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0090.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
FACTS=""
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
# Литеральная печать: линт порогов видит `KEY=` в источнике, а не шаблон с переменной.
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
pick() { grep -o "$1=[A-Za-z0-9_.:-]*" "$2" | tail -1 | cut -d= -f2; }

say "########## E-0090 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"
say "### ШАГ 0 носитель ### $(date +%FT%T%:z)"
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf "%s" "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then dok=1; else dok=0; fi
printf "DISK_GE_15000=%s\n" "$dok" | tee -a "$LOG"

say "### ШАГ 1 два прогона прибора ### $(date +%FT%T%:z)"
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  : > "$FACTS"
  cargo test --release -p vecdht-embed --test h0090_hubness -- --ignored --nocapture \
    > "$OUT/run$f.txt" 2>&1
  rc=$?
  note "$rc"
  tail -n 45 "$OUT/run$f.txt" | tee -a "$LOG"
  measured=$(pick H0090_MEASURED "$OUT/run$f.txt")
  corpus=$(pick H0090_CORPUS "$OUT/run$f.txt")
  queries=$(pick H0090_QUERIES "$OUT/run$f.txt")
  sample=$(pick H0090_SAMPLE "$OUT/run$f.txt")
  k=$(pick H0090_K "$OUT/run$f.txt")
  nprobe=$(pick H0090_NPROBE "$OUT/run$f.txt")
  hubs=$(pick H0090_HUBS "$OUT/run$f.txt")
  skew=$(pick H0090_HUB_SKEW "$OUT/run$f.txt")
  hmax=$(pick H0090_HUB_MAX "$OUT/run$f.txt")
  hzero=$(pick H0090_HUB_ZERO "$OUT/run$f.txt")
  recall=$(pick H0090_RECALL16 "$OUT/run$f.txt")
  inprobe=$(pick H0090_TRUE10_IN_PROBE "$OUT/run$f.txt")
  attack=$(pick H0090_ATTACK_IVF_TOP1 "$OUT/run$f.txt")
  tcount=$(pick H0090_TARGETED_COUNT "$OUT/run$f.txt")
  emit "H0090_MEASURED=${measured:-0}"
  emit "H0090_CORPUS=${corpus:-NONE}"
  emit "H0090_QUERIES=${queries:-NONE}"
  emit "H0090_SAMPLE=${sample:-NONE}"
  emit "H0090_K=${k:-NONE}"
  emit "H0090_NPROBE=${nprobe:-NONE}"
  emit "H0090_HUBS=${hubs:-NONE}"
  emit "H0090_HUB_SKEW_GE_1=$(awk -v a="${skew:-0}" -v b=1 'BEGIN { print (a + 0 >= b + 0) ? 1 : 0 }')"
  emit "H0090_HUB_MAX_GE_50=$(awk -v a="${hmax:-0}" -v b=50 'BEGIN { print (a + 0 >= b + 0) ? 1 : 0 }')"
  emit "H0090_HUB_ZERO_GT_0=$([ "${hzero:-0}" -gt 0 ] && echo 1 || echo 0)"
  emit "H0090_RECALL16_IN_0829_0832=$(awk -v r="${recall:-0}" 'BEGIN { print (r >= 0.829 && r <= 0.832) ? 1 : 0 }')"
  emit "H0090_PROBE_GAP_LE_002=$(awk -v a="${inprobe:-0}" -v b="${recall:-0}" 'BEGIN { d = a - b; if (d < 0) d = -d; print (d <= 0.02) ? 1 : 0 }')"
  emit "H0090_ATTACK_IVF_TOP1_LE_1PCT=$(awk -v x="${attack:-1}" 'BEGIN { print (x <= 0.01) ? 1 : 0 }')"
  emit "H0090_TARGETED_IVF_TOP1_EQ_1000=$([ -n "${tcount:-}" ] && [ "${tcount:-0}" = "${queries:-x}" ] && echo 1 || echo 0)"
  emit "H0090_EXIT=$rc"
  emit "H0090_RUNS=2"
  emit "DISK_GE_15000=$dok"
done

if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable=1; else stable=0; fi
printf "H0090_VECTOR_STABLE=%s\n" "$stable" | tee -a "$LOG"
for f in 1 2; do printf "H0090_VECTOR_STABLE=%s\n" "$stable" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 2 gate/audit ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0090 --skip-lean 2>&1 | tail -n 8 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
printf "GATE_H0090_OK=%s\n" "$gok" | tee -a "$LOG"
note "$rc"
python lab/cycle-gate.py audit -n 5 > "$OUT/audit.txt" 2>&1
rc=$?; note "$rc"
tail -n 3 "$OUT/audit.txt" | tee -a "$LOG"
aud=$(sed -n 's/.*нарушениий=\([0-9]*\).*/\1/p' "$OUT/audit.txt" | tail -1)
printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" | tee -a "$LOG"

say "### ШАГ 3 полная верификация ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0090 2>&1 | tail -n 12 | tee -a "$LOG"
vrc=${PIPESTATUS[0]}
printf "VERIFY_EXIT=%s\n" "$vrc" | tee -a "$LOG"
note "$vrc"

for f in 1 2; do
  printf "GATE_H0090_OK=%s\n" "$gok" >> "$OUT/facts_r$f.txt"
  printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "VERIFY_EXIT=%s\n" "$vrc" >> "$OUT/facts_r$f.txt"
done

say "### ШАГ 4 стража текста и сверка ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh \
  crates/vecdht-embed/tests/h0090_hubness.rs \
  lab/hypotheses/H-0090-hubness-and-blind-poisoning.md \
  lab/experiments/E-0090-hubness-and-blind-poisoning.md \
  lab/expectations/e0090.tsv lab/h0090-run.sh 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note $rc

python lab/expect.py lab/expectations/e0090.tsv "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" 2>&1 | tail -n 8 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
