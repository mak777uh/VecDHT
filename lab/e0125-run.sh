#!/usr/bin/env bash
# A4 / E-0125 (ADR-0066): промах холодного резолва на стенде P1 обязан называть себя числом,
# а операционный контракт — перестать требовать «ноль промахов внутри одного прогона».
#
# Что мерится. Прибор `crates/vecdht-net/tests/s182_p1_scale.rs` (200 узлов, release, `--ignored`):
# (1) пять прогонов по 192 пробы = 960 проб — p95 обязан быть ниже 500 мс в каждом, суммарно
# допускается не больше одного промаха, и каждый промах обязан быть именован (число деталей равно
# числу промахов); (2) посадка `VEC_P1_BUDGET_MS=1` — рукав, который делает промах гарантированным,
# иначе «каждый промах назван» проверялось бы на пустом множестве; (3) PRE_FIX — тот же прибор с той
# же посадкой на дереве `8b7c1e4` (= `184954c` + только рукав бюджета), где именования промаха нет, а гейт требует `miss == 0`.
#
# Дорогой цикл: один прогон стенда стоит 90…160 с, поэтому helper печатает диск/RAM перед каждой
# серией и не запускает серии параллельно.
#
# Порог: lab/expectations/e0125.tsv.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG=lab/logs/e0125-all.log
BASE_PIN=184954c
PRE_FIX_PIN=8b7c1e4
EXPECT=lab/expectations/e0125.tsv
TEST_FILE=crates/vecdht-net/tests/s182_p1_scale.rs
RUNS=5
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0125.XXXXXX")
KEEP="$OUT/keep"
mkdir -p "$KEEP" "$OUT/run"
restore_test() { [ -f "$KEEP/$TEST_FILE" ] && cp "$KEEP/$TEST_FILE" "$TEST_FILE"; }
trap 'restore_test; rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
G="$OUT/facts_global.txt"
: > "$G"
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }
# Факт одного исполнения helper'а пишется в `$F` литералом в двойных кавычках: страж
# `lab/threshold-lint.py` считает факт напечатанным, только если слева от имени стоит начало
# строки, двойная кавычка или пробел, а не одиночная кавычка шаблона printf.
F=""
femit() { printf '%s\n' "$1" >> "$F"; }

# Факт из вывода прибора — строка `KEY=значение`, снятая по границе слова (libtest в quiet-режиме
# дописывает в первую строку вывода символ прогресса, якорь `^` теряет первые ключи). Если строки
# нет — печатается MISSING, и сверка краснеет: молчание прогона не считается успехом.
fact() { # fact <файл-вывода> <ключ>
  grep -m1 -oE "\b${2}=[^ ]*" "$1" 2>/dev/null | head -1 | sed "s/^${2}=//" || true
}

say "########## E-0125 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 гейт и носитель до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py H-0125 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
emit0 "GATE_H0125_OK=${gok}"
note "$rc"
if [ "$gok" != 1 ]; then
  say "ГЕЙТ НЕ ПРОЙДЕН — замер не начинается"
  say "WORST_RC=1"
  exit 1
fi
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf "%s" "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then dok=1; else dok=0; fi
emit0 "DISK_GE_15000=${dok}"
[ "$dok" = 1 ] || note 1

mkdir -p "$KEEP/$(dirname "$TEST_FILE")"
cp "$TEST_FILE" "$KEEP/$TEST_FILE"

say "### ШАГ 1 PRE_FIX: прибор дерева ${PRE_FIX_PIN}, та же посадка ### $(date +%FT%T%:z)"
git cat-file -e "${PRE_FIX_PIN}:${TEST_FILE}" 2>/dev/null || say "ПИН НЕ НАЙДЕН"
git checkout "$PRE_FIX_PIN" -- "$TEST_FILE" 2>&1 | tee -a "$LOG"
note $?
say "checkout: P1_MISS_DETAIL в пине: $(grep -c 'P1_MISS_DETAIL' "$TEST_FILE" || true) совпадений"
VEC_P1_BUDGET_MS=1 cargo test --release -q -p vecdht-net --test s182_p1_scale -- \
  --ignored --nocapture > "$OUT/prefix-plant.txt" 2>&1
rcp=$?
say "PRE_FIX plant: exit=${rcp}"
tail -n 12 "$OUT/prefix-plant.txt" | tee -a "$LOG"
cp "$OUT/prefix-plant.txt" lab/logs/e0125-prefix-plant.log
v=$(fact "$OUT/prefix-plant.txt" P1_MISS_DETAIL_LINES)
if [ -n "$v" ]; then pdf=1; else pdf=0; fi
emit0 "PRE_FIX_MISS_DETAIL_FIELD=${pdf}"
[ "$pdf" = 0 ] || note 1
if [ "$rcp" -ne 0 ]; then prr=1; else prr=0; fi
emit0 "PRE_FIX_RUN_RED=${prr}"
[ "$prr" = 1 ] || note 1
restore_test
want=$(sha256sum < "$KEEP/$TEST_FILE" | cut -d' ' -f1)
got=$(sha256sum < "$TEST_FILE" | cut -d' ' -f1)
if [ "$want" != "$got" ]; then
  say "ВОССТАНОВЛЕНИЕ НЕ СРАБОТАЛО: $TEST_FILE"
  note 1
fi
git reset -q -- "$TEST_FILE"
say "прибор возвращён: P1_MISS_DETAIL в дереве: $(grep -c 'P1_MISS_DETAIL' "$TEST_FILE" || true) совпадений"

say "### ШАГ 2 два исполнения по пять прогонов release на неизменном дереве ### $(date +%FT%T%:z)"
for i in 1 2; do
  say "ИСПОЛНЕНИЕ ${i}: $(bash lab/disk-report.sh 2>&1)"
  F="$OUT/facts${i}.txt"
  : > "$F"
  samples=0; misses=0; p95ok=0; named=0; red=0; done_runs=0
  for j in $(seq 1 $RUNS); do
    f="$OUT/run/r${i}j${j}.txt"
    t0=$(date +%s)
    cargo test --release -q -p vecdht-net --test s182_p1_scale -- --ignored --nocapture > "$f" 2>&1
    rc=$?
    t1=$(date +%s)
    s=$(fact "$f" P1_SAMPLES); m=$(fact "$f" P1_MISS)
    p=$(fact "$f" P1_P95_OK); n=$(fact "$f" P1_MISS_ALL_NAMED)
    p50=$(fact "$f" P1_P50_MS); p95=$(fact "$f" P1_P95_MS)
    say "RUN${i}.${j}: exit=${rc} секунд=$((t1 - t0)) samples=${s:-MISSING} miss=${m:-MISSING} p50=${p50:-?} p95=${p95:-?} p95_ok=${p:-MISSING} named=${n:-MISSING}"
    [ "$rc" -eq 0 ] || { red=$((red + 1)); cp "$f" "lab/logs/e0125-run${i}-${j}-fail.txt"; }
    # ДИАГНОЗ-2 (первый прогон helper'а): промахи до правки красили прогон, и красная ветка
    # архивировала лог; теперь названный промах прогоном красным не считается, и единственный
    # штатный промах измерения (прогон 1.3, `P1_MISS=1`) остался без сохранённой детальной строки.
    # Молчание после снятия числа — то же самое, что потеря факта: каждый лог стенда архивируется,
    # а детали промахов печатаются в общий лог цикла.
    cp "$f" "lab/logs/e0125-stand-r${i}-${j}.log"
    grep -h 'P1_MISS_DETAIL obs=' "$f" | tee -a "$LOG" >/dev/null || true
    [ -n "$s" ] && { done_runs=$((done_runs + 1)); samples=$((samples + s)); }
    [ -n "$m" ] && misses=$((misses + m))
    [ "$p" = "1" ] && p95ok=$((p95ok + 1))
    [ "$n" = "1" ] && named=$((named + 1))
  done
  # ДИАГНОЗ-1: в первом прогоне совокупный бюджет считался по логам второго исполнения, поэтому
  # `MISS_TOTAL=0` относился к 960 проб из 1 920 и не включил промах первого исполнения.
  # Теперь число — сумма по всем прогонам обоих исполнений, а флаг бюджета берётся от наихудшего
  # исполнения (контракт сформулирован как «≤ 1 промах на 960 проб», и каждое исполнение — 960).
  if [ "$i" = 1 ]; then MTOT1=$misses; else MTOT2=$misses; fi
  plant_f="$OUT/plant${i}.txt"
  VEC_P1_BUDGET_MS=1 cargo test --release -q -p vecdht-net --test s182_p1_scale -- \
    --ignored --nocapture > "$plant_f" 2>&1
  say "PLANT${i}: exit=$?"
  cp "$plant_f" "lab/logs/e0125-plant${i}.log"
  pm=$(fact "$plant_f" P1_MISS); pd=$(fact "$plant_f" P1_MISS_DETAIL_LINES)
  pn=$(fact "$plant_f" P1_MISS_ALL_NAMED)
  names=$(grep -c 'P1_MISS_DETAIL obs=' "$plant_f" 2>/dev/null || true)
  three=$(grep -c 'shard=[0-9]* probe_ms=[0-9]* node_errors=[0-9]*' "$plant_f" 2>/dev/null || true)
  say "PLANT${i}: miss=${pm:-MISSING} деталей=${pd:-MISSING} строк=$names с-тремя-именами=$three named=${pn:-MISSING}"
  pmg=$([ -n "${pm:-}" ] && [ "$pm" -ge 1 ] && echo 1 || echo 0)
  pmn=$([ "${pn:-0}" = "1" ] && [ "${pd:-x}" = "${pm:-y}" ] && echo 1 || echo 0)
  pds=$([ "${three:-0}" -ge 1 ] && [ "${three:-0}" = "${names:-0}" ] && echo 1 || echo 0)
  femit "RUNS_COMPLETED=$done_runs"
  femit "RUNS_SAMPLES=$samples"
  femit "RUNS_RED=$red"
  femit "P95_OK_RUNS=$p95ok"
  femit "MISS_NAMED_RUNS=$named"
  femit "PLANT_MISSES_GE_1=$pmg"
  femit "PLANT_MISS_NAMED=$pmn"
  femit "PLANT_DETAIL_SHARD_SEEN=$pds"
done

# Инвариантные факты двух исполнений. Числа p50/p95 и величина MISS_TOTAL в сравнение сознательно
# не входят: они зависят от расписания хоста (правило 7 (е)), и вердикт по ним был бы не фактом,
# а шумом.
if diff -q "$OUT/facts1.txt" "$OUT/facts2.txt" >/dev/null 2>&1; then st=1; else st=0; fi
emit0 "STABLE=${st}"
say "STABLE=${st}"
[ "$st" = 1 ] || note 1
cat "$OUT/facts2.txt" | tee -a "$LOG"
# Совокупный бюджет: ≤ 1 промах на 960 проб. Число промахов складывается из замеров каждого
# исполнения (переменные считаются в цикле), печатается и как замер по всем 1 920 проб, и как флаг
# по наихудшему исполнению. ДИАГНОЗ-1: в первом прогоне helper'а сюда повторялся обход логов
# второго исполнения, и `MISS_TOTAL` описывал 960 проб из 1 920.
MISS_TOTAL=$(( ${MTOT1:-0} + ${MTOT2:-0} ))
mx=${MTOT2:-0}
[ "${MTOT1:-0}" -gt "$mx" ] && mx=${MTOT1:-0}
emit0 "MISS_TOTAL=${MISS_TOTAL}"
emit0 "MISS_WORST_EXEC=${mx}"
if [ "$mx" -le 1 ]; then mob=1; else mob=0; fi
emit0 "MISS_BUDGET_OK=${mob}"
[ "$mob" = 1 ] || note 1

say "### ШАГ 3 границы правки, clippy и стража текста ### $(date +%FT%T%:z)"
touched=$(git diff --name-only "$BASE_PIN" -- crates/ 2>/dev/null | grep -vc '^crates/vecdht-net/tests/' || true)
emit0 "PRODUCT_TOUCHED=${touched:-0}"
[ "${touched:-1}" = "0" ] || note 1
say "продукт не тронут: файлов вне crates/vecdht-net/tests = ${touched:-0}"
cargo clippy -q -p vecdht-net --all-targets -- -D warnings > "$OUT/clippy.txt" 2>&1
rccl=$?
note "$rccl"
emit0 "CLIPPY_EXIT=${rccl}"
tail -n 5 "$OUT/clippy.txt" | tee -a "$LOG"
CYCLE_FILES="lab/e0125-run.sh $EXPECT $TEST_FILE \
lab/hypotheses/H-0125-cold-resolve-miss-named.md \
lab/experiments/E-0125-cold-resolve-miss-named.md \
lab/decisions/ADR-0066-cold-resolve-miss-budget.md"
# shellcheck disable=SC2086
bash lab/check-text-clean.sh $CYCLE_FILES 2>&1 | tail -3 | tee -a "$LOG"
rct=${PIPESTATUS[0]}
note "$rct"
emit0 "TEXTGUARD_CYCLE_EXIT=${rct}"
python lab/repo-review.py 2>&1 | tail -3 | tee -a "$LOG"
rcrr=${PIPESTATUS[0]}
emit0 "REPO_REVIEW_EXIT=${rcrr}"

say "### ШАГ 4 посадка: неверное ожидание обязано краснеть ### $(date +%FT%T%:z)"
awk -F'\t' 'BEGIN{OFS="\t"} $1=="MISS_BUDGET_OK"{$2="0"} {print}' "$EXPECT" > "$OUT/plant.tsv"
if ! grep -q $'^MISS_BUDGET_OK\t0\t' "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка MISS_BUDGET_OK в таблице не найдена"
  plant=0
else
  python lab/expect.py "$OUT/plant.tsv" "$OUT/facts2.txt" "$G" > "$OUT/plant.out" 2>&1
  plant=$([ $? -ne 0 ] && echo 1 || echo 0)
fi
emit0 "PLANT_EXIT=${plant}"
say "PLANT_EXIT=${plant}"
[ "$plant" = 1 ] || note 1

say "### ШАГ 5 ожидания ### $(date +%FT%T%:z)"
for f in "$OUT/facts1.txt" "$OUT/facts2.txt"; do cat "$G" >> "$f"; done
python lab/expect.py "$EXPECT" "$OUT/facts1.txt" "$OUT/facts2.txt" 2>&1 | tail -n 25 | tee -a "$LOG"
rce=${PIPESTATUS[0]}
note "$rce"
emit0 "EXPECT_EXIT=${rce}"

say "### ШАГ 6 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
