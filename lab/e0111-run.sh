#!/usr/bin/env bash
# E-0111: канонизация платных заказов v9 воспроизводима вне нашего кода (H-0111; deliverables D1/D2
# задачи `docs/TASK-spec-v9-paid-orders.md`, проверка §4 «процедура хеширования воспроизводима на
# трёх примерах»).
#
# Прибор: `cargo test -p vecdht-orders` — 14 юнит-тестов + генератор векторов
# `tests/paid_order_vectors.rs`, который печатает `V9_*` и порождает `docs/PAID_ORDER-VECTORS.md`.
# Независимая сверка: `lab/xcheck-paid-orders.py` пересобирает хеши из напечатанных в документе
# нормализованных байтов чистой реализацией (`hashlib`) — проверяется текст, который читает сторонний
# верификатор, а не шов, написанный рядом с кодом.
#
# PRE_FIX-мутации продукта здесь нет по построению: в этом цикле нечего ломать и чинить в продукте —
# проверяется воспроизводимость байтовых правил. Отказом прибора считается непосадка дефекта:
# посаженные варианты сборки байтов обязаны дать другие хеши (`V9_W_DECOY_FIRED=1`), а посаженная
# пустая клетка матрицы — быть пойманной (`V9_DOC_DECOY_FIRED=1`).
#
# Шаги:
#   (0) gate ДО helper'а (правило AGENTS.md п. 11) и носитель: диск/RAM/pagefile;
#   (1) два прогона прибора на неизменном дереве, литеральные `V9_*`;
#   (2) сверка вектора двух прогонов (правило 7 (е));
#   (3) независимая пересборка хешей и страж матрицы (`lab/xcheck-paid-orders.py`);
#   (4) `audit -n 5`;
#   (5) `workspace-verify.sh E-0111`;
#   (6) стража текста и сверка `lab/expectations/e0111.tsv`;
#   (7) носитель после прогона;
#   (7b) баланс цикла (`lab/ledger.py`).
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0111-all.log"
DOC=docs/PAID_ORDER-VECTORS.md
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0111.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
FACTS=""
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
# Литеральная печать: линт порогов видит `KEY=` в источнике, а не шаблон с переменной.
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
pick() { grep -o "$1=[A-Za-z0-9_.:/=,%|-]*" "$2" | tail -1 | cut -d= -f2-; }

say "########## E-0111 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 gate и носитель ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0111 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
printf "GATE_H0111_OK=%s\n" "$gok" | tee -a "$LOG"
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
  V9_VECTORS_OUT="$DOC" cargo test -q -p vecdht-orders -- --nocapture \
    > "$OUT/run$f.txt" 2>&1
  rc1=$?
  note "$rc1"
  if [ "$rc1" -eq 0 ]; then measured=1; else measured=0; fi
  grep -E '^V9_|test result' "$OUT/run$f.txt" | tail -n 30 | tee -a "$LOG"
  emit "E0111_MEASURED=${measured}"
  emit "V9_VECTORS=$(pick V9_VECTORS "$OUT/run$f.txt")"
  cov=$(grep -o 'V9_CODES_COVERED=[0-9]*/[0-9]*' "$OUT/run$f.txt" | tail -1 | cut -d= -f2)
  emit "V9_CODES_COVERED=${cov%%/*}"
  emit "V9_CODES_TOTAL=${cov##*/}"
  emit "V9_WORKED=$(pick V9_WORKED "$OUT/run$f.txt")"
  emit "V9_W1_SHA=$(pick V9_W1_SHA "$OUT/run$f.txt")"
  emit "V9_W2_SHA=$(pick V9_W2_SHA "$OUT/run$f.txt")"
  emit "V9_W3_SHA=$(pick V9_W3_SHA "$OUT/run$f.txt")"
  emit "V9_W_NORM_IDEMPOTENT=$(pick V9_W_NORM_IDEMPOTENT "$OUT/run$f.txt")"
  emit "V9_W_HASH_STABLE=$(pick V9_W_HASH_STABLE "$OUT/run$f.txt")"
  emit "V9_ORDER_REF=$(pick V9_ORDER_REF "$OUT/run$f.txt")"
  emit "V9_SUBMISSION_REF=$(pick V9_SUBMISSION_REF "$OUT/run$f.txt")"
  emit "V9_ARTIFACT_ROOT=$(pick V9_ARTIFACT_ROOT "$OUT/run$f.txt")"
  emit "V9_RECEIPT_JSON_SHA=$(pick V9_RECEIPT_JSON_SHA "$OUT/run$f.txt")"
  # Числа берутся из ПЕРВОГО блока `test result` — это юнит-набор crate; второй блок относится к
  # тесту-генератору (всегда 1) и в ожидания не входит.
  read -r passed failed <<EOF2
$(sed -n 's/^test result: ok\. \([0-9]*\) passed; \([0-9]*\) failed.*/\1 \2/p' "$OUT/run$f.txt" | head -1)
EOF2
  emit "V9_LIB_PASSED=${passed:-0}"
  emit "V9_LIB_FAILED=${failed:-1}"
  emit "V9_VECTORS_SHA=$(pick V9_VECTORS_SHA "$OUT/run$f.txt")"
  say "прогон $f: EXIT=$rc1 векторов=$(pick V9_VECTORS "$OUT/run$f.txt") sha=$(pick V9_VECTORS_SHA "$OUT/run$f.txt")"
done

# Ключ, сводящий два прогона, обязан быть и в логе, и в обоих файлах фактов (Поправка 5 из E-0105).
for f in 1 2; do
  printf "GATE_H0111_OK=%s\n" "$gok" >> "$OUT/facts_r$f.txt"
  printf "E0111_RUNS=2\n" >> "$OUT/facts_r$f.txt"
  printf "DISK_GE_15000=%s\n" "$dok" >> "$OUT/facts_r$f.txt"
done
say "E0111_RUNS=2"

say "### ШАГ 2 сверка векторов двух прогонов ### $(date +%FT%T%:z)"
if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable2=1; else stable2=0; fi
printf "VECTOR_STABLE=%s\n" "$stable2" | tee -a "$LOG"
for f in 1 2; do printf "VECTOR_STABLE=%s\n" "$stable2" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 3 независимая пересборка хешей и страж матрицы ### $(date +%FT%T%:z)"
python lab/xcheck-paid-orders.py "$DOC" > "$OUT/xcheck.txt" 2>&1
rc3=$?
note "$rc3"
cat "$OUT/xcheck.txt" | tee -a "$LOG"
# Факты сверки относятся к документу, а не к прогону, но в оба файла фактов попадают намеренно:
# иначе `VECTOR_STABLE` не покрывал бы независимую часть проверки (уроки `E-0105`, `E-0108`).
for f in 1 2; do cat "$OUT/xcheck.txt" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 4 audit ### $(date +%FT%T%:z)"
python lab/cycle-gate.py audit -n 5 > "$OUT/audit.txt" 2>&1
rc=$?; note "$rc"
tail -n 3 "$OUT/audit.txt" | tee -a "$LOG"
aud=$(sed -n 's/.*нарушени[^=]*=\([0-9]*\).*/\1/p' "$OUT/audit.txt" | tail -1)
printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" | tee -a "$LOG"

say "### ШАГ 5 полная верификация ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0111 2>&1 | tail -n 12 | tee -a "$LOG"
vrc=${PIPESTATUS[0]}
printf "VERIFY_EXIT=%s\n" "$vrc" | tee -a "$LOG"
note "$vrc"

for f in 1 2; do
  printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "VERIFY_EXIT=%s\n" "$vrc" >> "$OUT/facts_r$f.txt"
done
# Пересводка после шагов 4–5: файлы фактов меняются синхронно, и `VECTOR_STABLE` остаётся
# осмысленным (сравниваются уже полные векторы).
if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable3=1; else stable3=0; fi
printf "VECTOR_STABLE=%s\n" "$stable3" | tee -a "$LOG"
for f in 1 2; do
  sed -i "s/^VECTOR_STABLE=.*$/VECTOR_STABLE=${stable3}/" "$OUT/facts_r$f.txt"
done

say "### ШАГ 6 стража текста и сверка ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh \
  crates/vecdht-orders/src/lib.rs \
  crates/vecdht-orders/tests/paid_order_vectors.rs \
  lab/xcheck-paid-orders.py \
  lab/hypotheses/H-0111-paid-order-canonicalization.md \
  lab/experiments/E-0111-paid-order-canonicalization.md \
  lab/expectations/e0111.tsv lab/e0111-run.sh "$DOC" 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note "$rc"

python lab/expect.py lab/expectations/e0111.tsv "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" 2>&1 | tail -n 12 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "### ШАГ 7 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "### ШАГ 7b баланс цикла (lab/ledger.py) ### $(date +%FT%T%:z)"
# Последний блок верификации целиком: баланс считается по факту прогона, а не по sums за весь
# append-only лог (иначе сорванные блоки задним числом удорожают закрытый цикл).
VLOG=lab/logs/workspace-verify-2026-10-22.log
awk 'NR==FNR{if (/^########## /) last=FNR; next} FNR>last' "$VLOG" "$VLOG" > "$OUT/verify-last-block.txt"
python lab/ledger.py report "$LOG" "$OUT/verify-last-block.txt" 2>&1 | tail -n 22 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; printf "LEDGER_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
