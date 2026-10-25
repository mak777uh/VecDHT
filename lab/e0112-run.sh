#!/usr/bin/env bash
# E-0112 (`OPEN-V9-10`): `AXIOM_ALLOWLIST` обязан называть третью стандартную аксиому Lean тем
# именем, которое печатает её же kernel (H-0112; ДИАГНОЗ-3 цикла `E-0111`).
#
# Прибор: `cargo test -p vecdht-orders --test v912_axiom_names` — две стороны дефекта (ложный отказ
# на честном `Quot.sound`, ложное принятие на выдуманном `Quoted.sound`) плюс два контроля: пустой
# список обязан проходить, а не-Lean класс, назвавший аксиомы, обязан оставаться отвергнутым.
# Свидетель имени — не цитата и не строка Rust-кода: `lean lab/lean/KernelName.lean` спрашивает имя
# у kernel и печатает `'q' depends on axioms: [Quot.sound]`; helper сверяет это имя с напечатанным
# `V912_ALLOWLIST=`. Посадка — тот же kernel на файле с `Quoted.sound`: он его не разбирает.
#
# PRE_FIX-замер исполнен до коммита пре-регистрации (числа в карточке `E-0112`): на дереве до правки
# тест компилируется и даёт `V912_HONEST_QUOT_ACCEPTED=0`, `V912_FAKE_QUOTED_REJECTED=0`,
# `V912_ALLOWLIST_HAS_QUOTED_SOUND=1`, `V912_ALL_OK=0`.
#
# Инерварианты, которые цикл обязан не тронуть: три хеша канонизации (`V9_W_PY_MATCHES=3`), число
# векторов и покрытие кодов (`V9_VECTORS=30`, `V9_CODES_COVERED=18/18`), матрица §V9.6 (`V9_SPEC_…`).
# Меняется ровно одно: имя в allowlist и, как следствие, sha порождённого документа — предсказание
# `V912_DOC_SHA_CHANGED=1` с записанным до правки прежним sha.
#
# Шаги:
#   (0) gate ДО прогона и носитель: диск/RAM/pagefile;
#   (1) два прогона прибора на неизменном дереве, литеральные `V912_*` и `V9_*`;
#   (2) свидетель Lean: имя из вывода kernel + посадка на выдуманном имени;
#   (3) порождённый документ: строка allowlist, отсутствие старого имени, sha против записанного;
#   (4) независимая сверка векторов и матрицы (`lab/xcheck-paid-orders.py`);
#   (5) `audit -n 5`;
#   (6) `workspace-verify.sh E-0112`;
#   (7) стража текста по файлам цикла и сверка `lab/expectations/e0112.tsv`;
#   (8) носитель после прогона и баланс цикла (`lab/ledger.py`).
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0112-all.log"
DOC=docs/PAID_ORDER-VECTORS.md
# Прежний sha документа переписан СЮДА до правки (он же — в карточке и в логе `E-0111`): ожидание
# «документ обязан измениться» проверяется сравнением с этой константой, а не с памятью.
PREV_DOC_SHA=c5de2ae0671a637c51ff71b9dd34dbf80da08a10616f029ffb99926718712935
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0112.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
# Класс символов включает `|`: список аксиом печатается именно так (`propext|Classical.choice|…`),
# и без `|` в классе `pick` вернул бы первое имя — молчание прибора, а не факт.
pick() { grep -o "$1=[A-Za-z0-9_.:|-]*" "$2" | tail -1 | cut -d= -f2-; }

say "########## E-0112 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 gate и носитель ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0112 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
printf "GATE_H0112_OK=%s\n" "$gok" | tee -a "$LOG"
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
  cargo test -q -p vecdht-orders --test v912_axiom_names -- --nocapture > "$OUT/rust$f.txt" 2>&1
  rc1=$?
  note "$rc1"
  grep -E '^V912_|test result' "$OUT/rust$f.txt" | tee -a "$LOG"
  emit "E0112_RUST_EXIT=${rc1}"
  # Литеральная печать: линт порогов видит `KEY=` в источнике, а не шаблон с переменной.
  emit "V912_ALLOWLIST=$(pick V912_ALLOWLIST "$OUT/rust$f.txt")"
  emit "V912_ALLOWLIST_SIZE=$(pick V912_ALLOWLIST_SIZE "$OUT/rust$f.txt")"
  emit "V912_HONEST_QUOT_ACCEPTED=$(pick V912_HONEST_QUOT_ACCEPTED "$OUT/rust$f.txt")"
  emit "V912_FAKE_QUOTED_REJECTED=$(pick V912_FAKE_QUOTED_REJECTED "$OUT/rust$f.txt")"
  emit "V912_EMPTY_AXIOM_CONTROL=$(pick V912_EMPTY_AXIOM_CONTROL "$OUT/rust$f.txt")"
  emit "V912_NONLEAN_NAMES_AXIOMS=$(pick V912_NONLEAN_NAMES_AXIOMS "$OUT/rust$f.txt")"
  emit "V912_ALLOWLIST_HAS_QUOT_SOUND=$(pick V912_ALLOWLIST_HAS_QUOT_SOUND "$OUT/rust$f.txt")"
  emit "V912_ALLOWLIST_HAS_QUOTED_SOUND=$(pick V912_ALLOWLIST_HAS_QUOTED_SOUND "$OUT/rust$f.txt")"
  emit "V912_ALL_OK=$(pick V912_ALL_OK "$OUT/rust$f.txt")"

  # Генератор векторов перезапускается на том же дереве: документ — функция дерева, и правка обязана
  # быть видна в его строке allowlist. Заодно переснимаются инварианты (хеши, векторы, коды).
  V9_VECTORS_OUT="$DOC" cargo test -q -p vecdht-orders --test paid_order_vectors -- --nocapture \
    > "$OUT/gen$f.txt" 2>&1
  rc2=$?
  note "$rc2"
  grep -E '^V9_(VECTORS|CODES|WORKED|W1|W2|W3|VECTORS_SHA)' "$OUT/gen$f.txt" | tail -n 12 | tee -a "$LOG"
  emit "V9_VECTORS=$(pick V9_VECTORS "$OUT/gen$f.txt")"
  cov=$(grep -o 'V9_CODES_COVERED=[0-9]*/[0-9]*' "$OUT/gen$f.txt" | tail -1 | cut -d= -f2)
  emit "V9_CODES_COVERED=${cov%%/*}"
  emit "V9_CODES_TOTAL=${cov##*/}"
  emit "V9_WORKED=$(pick V9_WORKED "$OUT/gen$f.txt")"
  emit "V9_W1_SHA=$(pick V9_W1_SHA "$OUT/gen$f.txt")"
  emit "V9_W2_SHA=$(pick V9_W2_SHA "$OUT/gen$f.txt")"
  emit "V9_W3_SHA=$(pick V9_W3_SHA "$OUT/gen$f.txt")"
  emit "V9_VECTORS_SHA=$(pick V9_VECTORS_SHA "$OUT/gen$f.txt")"
done

say "### ШАГ 2 свидетель Lean: имя называет kernel ### $(date +%FT%T%:z)"
# Факты шагов 2–3 относятся к дереву, а не к прогону: они пишутся в отдельный файл и потом
# добавляются к обоим векторам, иначе `VECTOR_STABLE` сравнивал бы unequal наборы.
FACTS="$OUT/shared.txt"
: > "$FACTS"
lean lab/lean/KernelName.lean > "$OUT/lean.txt" 2>&1
lrc=$?
note "$lrc"
cat "$OUT/lean.txt" | tee -a "$LOG"
emit "V912_LEAN_RC=${lrc}"
kname=$(grep -o "depends on axioms: \[[^]]*\]" "$OUT/lean.txt" | tail -1 | sed 's/.*\[//; s/\]//')
emit "V912_KERNEL_NAME=${kname}"
# Версия тулчейна входит в факт: имя аксиомы — свойство конкретного ядра, и сверять его надо,
# называя, каким именно `lean` оно названо.
emit "V912_LEAN_TOOLCHAIN=$(lean --version 2>&1 | sed -n 's/.*version \([^,]*\),.*/\1/p' | head -1)"
al=$(pick V912_ALLOWLIST "$OUT/facts_r1.txt")
if [ -n "$kname" ] && printf '%s' "$al" | tr '|' '\n' | grep -qx "$kname"; then kin=1; else kin=0; fi
emit "V912_KERNEL_NAME_IN_ALLOWLIST=${kin}"

# Посадка: то же ядро на файле с прежним именем из allowlist. Нулевой вывод здесь означал бы, что
# имя всё-таки существует, и тогда «правка оформительская» была бы правдой. Текст — тот же, что
# закомментирован в свидетеле; собирается литеральным here-document, а не вырезкой из файла, чтобы
# отказ собирались ловить, а не молча пропускать.
mkdir -p "$OUT/decoy"
cat > "$OUT/decoy/Decoy.lean" <<'LEAN'
theorem bad {α : Sort u} {r : α → α → Prop} {a b : α} (h : r a b) :
  Quot.mk r a = Quot.mk r b := Quoted.sound h
LEAN
if ! grep -q "Quoted.sound" "$OUT/decoy/Decoy.lean"; then
  say "ПОСАДКА НЕ СОБРАНА: в Decoy.lean нет ожидаемого имени — прибор слеп"
  say "WORST_RC=1"; exit 1
fi
lean "$OUT/decoy/Decoy.lean" > "$OUT/decoy.txt" 2>&1
drc=$?
grep -qi "unknown identifier.*Quoted\.sound" "$OUT/decoy.txt" && dq=1 || dq=0
emit "V912_DECOY_LEAN_RC=${drc}"
emit "V912_DECOY_QUOTED_UNPARSABLE=${dq}"
sed -n 's/.*error.*/  &/p' "$OUT/decoy.txt" | head -2 | tee -a "$LOG"

say "### ШАГ 3 порождённый документ ### $(date +%FT%T%:z)"
line=$(grep -o '^- AXIOM_ALLOWLIST: .*' "$DOC" | head -1)
say "строка документа: ${line}"
# Имена из документа нормализуются к тому же виду, что печатает Rust-тест (`|` без пробелов):
# сравнение двух представлений и есть проверка, что документ и правило вывода называют одно
# множество, а не два похожих текста.
doc_al=$(printf '%s' "${line#*: }" | tr -d '[] ' | tr ',' '|')
emit "V912_DOC_ALLOWLIST=${doc_al}"
if printf '%s' "$line" | grep -q "Quoted.sound"; then had=1; else had=0; fi
if printf '%s' "$line" | grep -q "Quot.sound"; then has=1; else has=0; fi
emit "V912_DOC_HAS_QUOTED=${had}"
emit "V912_DOC_HAS_QUOT=${has}"
now=$(sha256sum "$DOC" | cut -d' ' -f1)
if [ -n "$now" ] && [ "$now" != "$PREV_DOC_SHA" ]; then ch=1; else ch=0; fi
emit "V912_PREV_DOC_SHA=${PREV_DOC_SHA}"
emit "V912_DOC_SHA=${now}"
emit "V912_DOC_SHA_CHANGED=${ch}"

# Ключи, сводящие два прогона, обязаны быть в обоих файлах фактов (Поправка 5 из `E-0105`).
for f in 1 2; do
  printf "GATE_H0112_OK=%s\n" "$gok" >> "$OUT/facts_r$f.txt"
  printf "DISK_GE_15000=%s\n" "$dok" >> "$OUT/facts_r$f.txt"
  printf "E0112_RUNS=2\n" >> "$OUT/facts_r$f.txt"
  cat "$OUT/shared.txt" >> "$OUT/facts_r$f.txt"
done
say "E0112_RUNS=2"

say "### ШАГ 4 независимая сверка векторов и матрицы ### $(date +%FT%T%:z)"
python lab/xcheck-paid-orders.py "$DOC" > "$OUT/xcheck.txt" 2>&1
rc4=$?
note "$rc4"
cat "$OUT/xcheck.txt" | tee -a "$LOG"
for f in 1 2; do cat "$OUT/xcheck.txt" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 5 сверка вектора двух прогонов ### $(date +%FT%T%:z)"
if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable2=1; else stable2=0; fi
printf "VECTOR_STABLE=%s\n" "$stable2" | tee -a "$LOG"
for f in 1 2; do printf "VECTOR_STABLE=%s\n" "$stable2" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 6 audit ### $(date +%FT%T%:z)"
python lab/cycle-gate.py audit -n 5 > "$OUT/audit.txt" 2>&1
rc=$?; note "$rc"
tail -n 3 "$OUT/audit.txt" | tee -a "$LOG"
aud=$(sed -n 's/.*нарушени[^=]*=\([0-9]*\).*/\1/p' "$OUT/audit.txt" | tail -1)
printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" | tee -a "$LOG"

say "### ШАГ 7 полная верификация ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0112 2>&1 | tail -n 12 | tee -a "$LOG"
vrc=${PIPESTATUS[0]}
printf "VERIFY_EXIT=%s\n" "$vrc" | tee -a "$LOG"
note "$vrc"

for f in 1 2; do
  printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "VERIFY_EXIT=%s\n" "$vrc" >> "$OUT/facts_r$f.txt"
done
if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable3=1; else stable3=0; fi
printf "VECTOR_STABLE=%s\n" "$stable3" | tee -a "$LOG"
for f in 1 2; do
  sed -i "s/^VECTOR_STABLE=.*$/VECTOR_STABLE=${stable3}/" "$OUT/facts_r$f.txt"
done

say "### ШАГ 8 стража текста и сверка ожиданий ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh \
  crates/vecdht-orders/src/lib.rs \
  crates/vecdht-orders/tests/v912_axiom_names.rs \
  lab/lean/KernelName.lean \
  lab/hypotheses/H-0112-axiom-allowlist-kernel-name.md \
  lab/experiments/E-0112-axiom-allowlist-kernel-name.md \
  lab/decisions/ADR-0062-axiom-allowlist-kernel-name.md \
  lab/expectations/e0112.tsv lab/e0112-run.sh "$DOC" 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note "$rc"

python lab/expect.py lab/expectations/e0112.tsv "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" 2>&1 | tail -n 14 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "### ШАГ 9 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "### ШАГ 9b баланс цикла (lab/ledger.py) ### $(date +%FT%T%:z)"
VLOG=lab/logs/workspace-verify-2026-10-22.log
awk 'NR==FNR{if (/^########## /) last=FNR; next} FNR>last' "$VLOG" "$VLOG" > "$OUT/verify-last-block.txt"
python lab/ledger.py report "$LOG" "$OUT/verify-last-block.txt" 2>&1 | tail -n 22 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; printf "LEDGER_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
