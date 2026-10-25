#!/usr/bin/env bash
# A0 / E-0118: церемония сети собирается из CLI — `cert issue` и `genesis build`.
#
# Что мерится. Не «команды отвечают нулём», а то, что документы принимает **проверяющий код
# узла**: кредашиал проходит `verify_cert`, genesis — `Chain::validate(None, …)`, а урезанная до
# порога-1 подпись, подписант вне набора авторитетов, дубликат владельца и состав из одного члена
# отвергаются **до записи**. Это проверяет оракул `crates/vecdht-cli/tests/node_bootstrap.rs`
# (пять тестов); helper гоняет его дважды на неизменном дереве, чтобы факты не зависели от
# расписания.
#
# PRE_FIX — пин `8355c72` (дерево до карточки): на нём пути `cert issue` в диспетчере нет, поэтому
# «до» — это ноль команд, а не красный тест. Мерить «было красным» в том же дереве нельзя: до
# правки команда не могла вернуть ничего, кроме `UnknownCommand`.
#
# Порог: RESULT_EXIT=0, PASSED=5, FAILED=0 в обоих прогонах, STABLE=1, EXPECT_EXIT=0,
# PLANT_EXIT=1 (таблица ожиданий чувствительна), PRE_FIX_NO_COMMAND=1, CLIPPY_EXIT=0,
# TEXTGUARD_CYCLE_EXIT=0, диск ≥ 15 000 МБ.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG=lab/logs/e0118-all.log
PRE_FIX_PIN=8355c72
EXPECT=lab/expectations/e0118.tsv
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0118.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
G="$OUT/facts_global.txt"
: > "$G"
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }

say "########## E-0118 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 гейт и носитель до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0118 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
emit0 "GATE_H0118_OK=${gok}"
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

say "### ШАГ 1 PRE_FIX: на дереве ${PRE_FIX_PIN} команд нет ### $(date +%FT%T%:z)"
if git merge-base --is-ancestor "$PRE_FIX_PIN" HEAD 2>/dev/null; then anc=1; else anc=0; fi
raw=$(git grep -c -F 'cert issue' "$PRE_FIX_PIN" -- crates/vecdht-cli/src/lib.rs 2>/dev/null | tail -1 || true)
n=$(printf '%s' "$raw" | awk -F: '{print $NF}')
n=${n:-0}
if [ "$anc" = 1 ] && [ "$n" -eq 0 ]; then pf=1; else pf=0; fi
say "BASE_IS_ANCESTOR=${anc} PRE_FIX_LINES=${n} PRE_FIX_NO_COMMAND=${pf}"
emit0 "BASE_IS_ANCESTOR=${anc}"
emit0 "PRE_FIX_NO_COMMAND=${pf}"
[ "$pf" -eq 1 ] || note 1

say "### ШАГ 2 оракул дважды на неизменном дереве ### $(date +%FT%T%:z)"
for i in 1 2; do
  FACTS="$OUT/facts${i}.txt"
  : > "$FACTS"
  cargo test -q -p vecdht-cli --test node_bootstrap -- --nocapture > "$OUT/test${i}.txt" 2>&1
  rc=$?
  note "$rc"
  summary=$(grep 'test result:' "$OUT/test${i}.txt" | tail -1)
  say "RUN${i}: ${summary:-<нет строки test result>}"
  if printf '%s' "$summary" | grep -q 'test result: ok'; then ok=1; else ok=0; fi
  passed=$(printf '%s' "$summary" | sed -n 's/.*ok\. \([0-9]\+\) passed.*/\1/p')
  failed=$(printf '%s' "$summary" | sed -n 's/.* \([0-9]\+\) failed.*/\1/p')
  emit "RESULT_EXIT=${rc}"
  emit "TEST_RESULT_OK=${ok}"
  emit "PASSED=${passed:-0}"
  emit "FAILED=${failed:-0}"
  [ "$ok" -eq 1 ] || note 1
done

if diff -q "$OUT/facts1.txt" "$OUT/facts2.txt" >/dev/null 2>&1; then st=1; else st=0; fi
emit0 "STABLE=${st}"
say "STABLE=${st}"
[ "$st" -eq 1 ] || note 1

say "### ШАГ 3 ожидания ### $(date +%FT%T%:z)"
for f in "$OUT/facts1.txt" "$OUT/facts2.txt"; do cat "$G" >> "$f"; done
python lab/expect.py "$EXPECT" "$OUT/facts1.txt" "$OUT/facts2.txt" 2>&1 | tail -n 20 | tee -a "$LOG"
rce=${PIPESTATUS[0]}
note "$rce"

say "### ШАГ 4 посадка: неверное ожидание обязано краснеть ### $(date +%FT%T%:z)"
sed 's/^PASSED=5$/PASSED=4/' "$EXPECT" > "$OUT/plant.tsv"
if cmp -s "$EXPECT" "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка PASSED=5 не найдена в таблице"
  plant=0
else
  python lab/expect.py "$OUT/plant.tsv" "$OUT/facts1.txt" "$OUT/facts2.txt" > "$OUT/plant.out" 2>&1
  plant=$([ $? -ne 0 ] && echo 1 || echo 0)
fi
emit0 "PLANT_EXIT=${plant}"
say "PLANT_EXIT=${plant}"
[ "$plant" -eq 1 ] || note 1

say "### ШАГ 5 clippy по пакету со всеми целями ### $(date +%FT%T%:z)"
cargo clippy -q -p vecdht-cli --all-targets -- -D warnings > "$OUT/clippy.txt" 2>&1
rcc=$?
note "$rcc"
tail -n 5 "$OUT/clippy.txt" | tee -a "$LOG"
emit0 "CLIPPY_EXIT=${rcc}"

say "### ШАГ 6 стража текста ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh lab/e0118-run.sh "$EXPECT" \
  lab/hypotheses/H-0118-a0-ceremony-cli.md \
  lab/experiments/E-0118-a0-ceremony-cli.md 2>&1 | tail -3 | tee -a "$LOG"
rct=${PIPESTATUS[0]}
note "$rct"
emit0 "TEXTGUARD_CYCLE_EXIT=${rct}"

say "### ШАГ 7 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
