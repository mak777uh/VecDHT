#!/usr/bin/env bash
# E-0108: аудит приватности диска — «на диске нет ни текста, ни f32» (H-0108, условие 5 v1).
#
# Один прибор: `crates/vecdht-cli/tests/s13_disk_privacy.rs` — debug, один узел в процессе,
# реальные кадры, снапшот, reopen, посадка дефекта и живой контроль внутри того же прогона.
#
# PRE_FIX-мутации продукта здесь нет по построению (правое поведение уже в сериализаторе);
# отказом прибора считается непосадка дефекта в носитель — шаг «посадка» обязан покраснеть, если
# сканер слеп, и это пять фактов `S13_DECOY_*` плюс `S13_CONTROL_TEXTLIKE_LIVE`.
#
# Шаги:
#   (0) gate ДО замерного helper'а (правило AGENTS.md п. 11) и носитель: диск/RAM/pagefile;
#   (1) два прогона прибора на неизменном дереве, литеральные `S13_*`;
#   (2) сверка вектора двух прогонов (правило 7 (е));
#   (3) `audit -n 5`;
#   (4) `workspace-verify.sh E-0108`;
#   (5) стража текста и сверка `lab/expectations/e0108.tsv`;
#   (6) носитель после прогона;
#   (6b) баланс цикла (`lab/ledger.py`).
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0108-all.log"
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0108.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
FACTS=""
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
# Литеральная печать: линт порогов видит `KEY=` в источнике, а не шаблон с переменной.
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
pick() { grep -o "$1=[A-Za-z0-9_.:-]*" "$2" | tail -1 | cut -d= -f2; }

say "########## E-0108 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 gate и носитель ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0108 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
printf "GATE_H0108_OK=%s\n" "$gok" | tee -a "$LOG"
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

say "### ШАГ 1 два прогона прибора ### $(date +%FT%T%:z)"
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  : > "$FACTS"
  cargo test -q -p vecdht-cli --test s13_disk_privacy -- --nocapture \
    > "$OUT/run$f.txt" 2>&1
  rc1=$?
  note "$rc1"
  if [ "$rc1" -eq 0 ]; then measured=1; else measured=0; fi
  grep -E '^S13_|test result' "$OUT/run$f.txt" | tail -n 40 | tee -a "$LOG"
  # Печать литеральная и только замороженных ключей (lab/expectations/e0108.tsv): абсолютные числа
  # находок по кодам/ключам и объёмы остаются в логе, но не в файлах фактов — иначе `VECTOR_STABLE`
  # сравнил бы то, что карточка принципиально не замороживала (урок `E0105_MEASURED`/`P1_P95_MS`).
  emit "E0108_MEASURED=${measured}"
  emit "S13_TEXTFRAME_SEEN=$(pick S13_TEXTFRAME_SEEN "$OUT/run$f.txt")"
  emit "S13_REOPEN_RECORDS=$(pick S13_REOPEN_RECORDS "$OUT/run$f.txt")"
  emit "S13_REOPEN_MATCH=$(pick S13_REOPEN_MATCH "$OUT/run$f.txt")"
  emit "S13_CORPUS_GE_6=$(pick S13_CORPUS_GE_6 "$OUT/run$f.txt")"
  emit "S13_NODE_SECRET_HITS=$(pick S13_NODE_SECRET_HITS "$OUT/run$f.txt")"
  emit "S13_NODE_F32_HITS=$(pick S13_NODE_F32_HITS "$OUT/run$f.txt")"
  emit "S13_NODE_F64_HITS=$(pick S13_NODE_F64_HITS "$OUT/run$f.txt")"
  emit "S13_NODE_F64N_HITS=$(pick S13_NODE_F64N_HITS "$OUT/run$f.txt")"
  emit "S13_NODE_TEXTLIKE=$(pick S13_NODE_TEXTLIKE "$OUT/run$f.txt")"
  emit "S13_NODE_QCODE_HITS=$(pick S13_NODE_QCODE_HITS "$OUT/run$f.txt")"
  emit "S13_NODE_OWNER_HITS=$(pick S13_NODE_OWNER_HITS "$OUT/run$f.txt")"
  emit "S13_NODE_RECORDS=$(pick S13_NODE_RECORDS "$OUT/run$f.txt")"
  emit "S13_NODE_CLEAN=$(pick S13_NODE_CLEAN "$OUT/run$f.txt")"
  emit "S13_DECOY_TEXT_FIRED=$(pick S13_DECOY_TEXT_FIRED "$OUT/run$f.txt")"
  emit "S13_DECOY_F32_FIRED=$(pick S13_DECOY_F32_FIRED "$OUT/run$f.txt")"
  emit "S13_DECOY_F64_FIRED=$(pick S13_DECOY_F64_FIRED "$OUT/run$f.txt")"
  emit "S13_DECOY_F64N_FIRED=$(pick S13_DECOY_F64N_FIRED "$OUT/run$f.txt")"
  emit "S13_DECOY_TEXTLIKE_FIRED=$(pick S13_DECOY_TEXTLIKE_FIRED "$OUT/run$f.txt")"
  emit "S13_DECOY_ALL_FIRED=$(pick S13_DECOY_ALL_FIRED "$OUT/run$f.txt")"
  emit "S13_ART_SECRET_HITS=$(pick S13_ART_SECRET_HITS "$OUT/run$f.txt")"
  emit "S13_ART_FLOAT_HITS=$(pick S13_ART_FLOAT_HITS "$OUT/run$f.txt")"
  emit "S13_ART_JSON_FILES=$(pick S13_ART_JSON_FILES "$OUT/run$f.txt")"
  emit "S13_ART_JSON_RUNS=$(pick S13_ART_JSON_RUNS "$OUT/run$f.txt")"
  emit "S13_CONTROL_TEXTLIKE_LIVE=$(pick S13_CONTROL_TEXTLIKE_LIVE "$OUT/run$f.txt")"
  emit "S13_ART_CENTROID_IS_FIXTURE=$(pick S13_ART_CENTROID_IS_FIXTURE "$OUT/run$f.txt")"
  emit "S13_ART_CLEAN=$(pick S13_ART_CLEAN "$OUT/run$f.txt")"
  say "прогон $f: EXIT=$rc1 node_clean=$(pick S13_NODE_CLEAN "$OUT/run$f.txt") decoy=$(pick S13_DECOY_ALL_FIRED "$OUT/run$f.txt") art=$(pick S13_ART_CLEAN "$OUT/run$f.txt")"
done

# Ключ, сводящий два прогона, обязан быть и в логе, и в обоих файлах фактов (Поправка 5 из E-0105).
for f in 1 2; do
  printf "GATE_H0108_OK=%s\n" "$gok" >> "$OUT/facts_r$f.txt"
  printf "E0108_RUNS=2\n" >> "$OUT/facts_r$f.txt"
  printf "DISK_GE_15000=%s\n" "$dok" >> "$OUT/facts_r$f.txt"
done
say "E0108_RUNS=2"

say "### ШАГ 2 сверка векторов двух прогонов ### $(date +%FT%T%:z)"
if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable2=1; else stable2=0; fi
printf "VECTOR_STABLE=%s\n" "$stable2" | tee -a "$LOG"
for f in 1 2; do printf "VECTOR_STABLE=%s\n" "$stable2" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 3 audit ### $(date +%FT%T%:z)"
python lab/cycle-gate.py audit -n 5 > "$OUT/audit.txt" 2>&1
rc=$?; note "$rc"
tail -n 3 "$OUT/audit.txt" | tee -a "$LOG"
aud=$(sed -n 's/.*нарушениий=\([0-9]*\).*/\1/p' "$OUT/audit.txt" | tail -1)
printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" | tee -a "$LOG"

say "### ШАГ 4 полная верификация ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0108 2>&1 | tail -n 12 | tee -a "$LOG"
vrc=${PIPESTATUS[0]}
printf "VERIFY_EXIT=%s\n" "$vrc" | tee -a "$LOG"
note "$vrc"

for f in 1 2; do
  printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "VERIFY_EXIT=%s\n" "$vrc" >> "$OUT/facts_r$f.txt"
done

say "### ШАГ 5 стража текста и сверка ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh \
  crates/vecdht-cli/tests/s13_disk_privacy.rs \
  lab/hypotheses/H-0108-disk-privacy-audit.md \
  lab/experiments/E-0108-disk-privacy-audit.md \
  lab/expectations/e0108.tsv lab/e0108-run.sh 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note "$rc"

python lab/expect.py lab/expectations/e0108.tsv "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "### ШАГ 6 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "### ШАГ 6b баланс цикла (lab/ledger.py) ### $(date +%FT%T%:z)"
# Последний блок верификации целиком: баланс считается по факту прогона, а не по sums за весь
# append-only лог (иначе сорванные блоки задним числом удорожают закрытый цикл).
VLOG=lab/logs/workspace-verify-2026-10-22.log
awk 'NR==FNR{if (/^########## /) last=FNR; next} FNR>last' "$VLOG" "$VLOG" > "$OUT/verify-last-block.txt"
python lab/ledger.py report "$LOG" "$OUT/verify-last-block.txt" 2>&1 | tail -n 22 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; printf "LEDGER_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
