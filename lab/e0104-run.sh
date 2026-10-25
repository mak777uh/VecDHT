#!/usr/bin/env bash
# E-0104: снимок наблюдения Приложения C — H-0104.
#
# Два прибора на одних и тех же двух прогонах:
#   `crates/vecdht-node/tests/c104_metrics_closed.rs`  — 37 имён, маппинг полей, память, роль;
#   `crates/vecdht-net/tests/c104_metrics_closed.rs`   — 7 фиксированных имён, 22 метки двери.
# Оба — debug: `debug_assert!` в модулях в release выключен, и release-прогон проверял бы пустоту.
#
# Шаги:
#   (0) gate ДО замерного helper'а (правило AGENTS.md п. 11) и носитель: диск/RAM/pagefile;
#   (1) два прогона на неизменном дереве, литеральные `C104_*`;
#   (2) производные факты и совпадение векторов двух прогонов;
#   (3) `audit -n 5`;
#   (4) `workspace-verify.sh E-0104`;
#   (5) стража текста и сверка `lab/expectations/e0104.tsv`;
#   (6) носитель после прогона.
#
# PRE_FIX структурный: на `e0856d5` поверхности нет (`git grep` = 0, файлов приборов нет);
# лог `lab/logs/e0104-prefix.log` снят до правки. Здесь дерево неизменно.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0104-all.log"
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0104.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
FACTS=""
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
# Литеральная печать: линт порогов видит `KEY=` в источнике, а не шаблон с переменной.
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
pick() { grep -o "$1=[A-Za-z0-9_.:/=,%|-]*" "$2" | tail -1 | cut -d= -f2-; }

say "########## E-0104 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 gate и носитель ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0104 --skip-lean 2>&1 | tail -n 8 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
printf "GATE_H0104_OK=%s\n" "$gok" | tee -a "$LOG"
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

say "### ШАГ 1 два прогона, оба бинаря ### $(date +%FT%T%:z)"
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  : > "$FACTS"
  cargo test -p vecdht-node --test c104_metrics_closed -- --nocapture \
    > "$OUT/node$f.txt" 2>&1
  rc1=$?
  cargo test -p vecdht-net --test c104_metrics_closed -- --nocapture \
    > "$OUT/net$f.txt" 2>&1
  rc2=$?
  note "$rc1"; note "$rc2"
  tail -n 12 "$OUT/node$f.txt" | tee -a "$LOG"
  tail -n 12 "$OUT/net$f.txt" | tee -a "$LOG"
  ok1=$(grep -c '^test .* \.\.\. ok$' "$OUT/node$f.txt")
  ok2=$(grep -c '^test .* \.\.\. ok$' "$OUT/net$f.txt")
  okall=$((ok1 + ok2))
  # Один прогон — оба бинаря: exit 0 у обоих и ровно шесть исполненных тестов.
  if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ "$okall" -eq 6 ]; then
    measured=1; rc=0
  else
    measured=0; rc=1
  fi
  cname=$(pick C104_NODE_NAMES "$OUT/node$f.txt")
  cexact=$(pick C104_NODE_EXACT "$OUT/node$f.txt")
  crender=$(pick C104_NODE_RENDER_OK "$OUT/node$f.txt")
  cmapped=$(pick C104_NODE_MAPPED "$OUT/node$f.txt")
  cmem=$(pick C104_NODE_MEMORY_ROWS "$OUT/node$f.txt")
  ccent=$(pick C104_NODE_CENTROIDS_OBSERVABLE "$OUT/node$f.txt")
  nprice=$(pick C104_NODE_NO_PRICE "$OUT/node$f.txt")
  ndoor=$(pick C104_NODE_DOOR_SEPARATE "$OUT/node$f.txt")
  wiring=$(pick C104_NET_WIRING "$OUT/net$f.txt")
  fixed=$(pick C104_NET_FIXED "$OUT/net$f.txt")
  labels=$(pick C104_NET_DOOR_LABELS "$OUT/net$f.txt")
  closed=$(pick C104_NET_LABELS_CLOSED "$OUT/net$f.txt")
  nsum=$(pick C104_NET_SUM "$OUT/net$f.txt")
  sumok=$(pick C104_NET_SUM_OK "$OUT/net$f.txt")
  nrender=$(pick C104_NET_RENDER_OK "$OUT/net$f.txt")
  stable=$(pick C104_NET_SIZE_STABLE "$OUT/net$f.txt")
  tprice=$(pick C104_NET_NO_PRICE "$OUT/net$f.txt")
  emit "C104_MEASURED=${measured}"
  emit "C104_NODE_NAMES=${cname:-NONE}"
  emit "C104_NODE_EXACT=${cexact:-NONE}"
  emit "C104_NODE_RENDER_OK=${crender:-NONE}"
  emit "C104_NODE_MAPPED=${cmapped:-NONE}"
  emit "C104_NODE_MEMORY_ROWS=${cmem:-NONE}"
  emit "C104_NODE_CENTROIDS_OBSERVABLE=${ccent:-NONE}"
  emit "C104_NODE_NO_PRICE=${nprice:-NONE}"
  emit "C104_NODE_DOOR_SEPARATE=${ndoor:-NONE}"
  emit "C104_NET_WIRING=${wiring:-NONE}"
  emit "C104_NET_FIXED=${fixed:-NONE}"
  emit "C104_NET_DOOR_LABELS=${labels:-NONE}"
  emit "C104_NET_LABELS_CLOSED=${closed:-NONE}"
  emit "C104_NET_SUM=${nsum:-NONE}"
  emit "C104_NET_SUM_OK=${sumok:-NONE}"
  emit "C104_NET_RENDER_OK=${nrender:-NONE}"
  emit "C104_NET_SIZE_STABLE=${stable:-NONE}"
  emit "C104_NET_NO_PRICE=${tprice:-NONE}"
  emit "C104_EXIT=$rc"
  emit "C104_RUNS=2"
  emit "DISK_GE_15000=$dok"
done

if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable2=1; else stable2=0; fi
printf "C104_VECTOR_STABLE=%s\n" "$stable2" | tee -a "$LOG"
for f in 1 2; do printf "C104_VECTOR_STABLE=%s\n" "$stable2" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 2 audit ### $(date +%FT%T%:z)"
python lab/cycle-gate.py audit -n 5 > "$OUT/audit.txt" 2>&1
rc=$?; note "$rc"
tail -n 3 "$OUT/audit.txt" | tee -a "$LOG"
aud=$(sed -n 's/.*нарушени[^=]*=\([0-9]*\).*/\1/p' "$OUT/audit.txt" | tail -1)
printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" | tee -a "$LOG"

say "### ШАГ 3 полная верификация ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0104 2>&1 | tail -n 12 | tee -a "$LOG"
vrc=${PIPESTATUS[0]}
printf "VERIFY_EXIT=%s\n" "$vrc" | tee -a "$LOG"
note "$vrc"

for f in 1 2; do
  printf "GATE_H0104_OK=%s\n" "$gok" >> "$OUT/facts_r$f.txt"
  printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "VERIFY_EXIT=%s\n" "$vrc" >> "$OUT/facts_r$f.txt"
done

say "### ШАГ 4 стража текста и сверка ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh \
  crates/vecdht-node/src/metrics.rs \
  crates/vecdht-net/src/metrics.rs \
  crates/vecdht-node/tests/c104_metrics_closed.rs \
  crates/vecdht-net/tests/c104_metrics_closed.rs \
  lab/hypotheses/H-0104-metrics-surface.md \
  lab/experiments/E-0104-metrics-surface.md \
  lab/decisions/ADR-0059-metrics-surface.md \
  lab/expectations/e0104.tsv lab/e0104-run.sh 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note $rc

python lab/expect.py lab/expectations/e0104.tsv "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" 2>&1 | tail -n 8 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "### ШАГ 5 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
