#!/usr/bin/env bash
# E-0116 (T1): ledger обязан читать последний блок прогона, а не весь append-only лог, и не считать
# провалом посаженный контроль (`V9CTL_*`), сводку `VERIFY` и собственный прошлый `LEDGER_EXIT`
# (H-0116). Порог заморожен коммитом `eeef07c` до правки прибора.
#
# Шаги:
#   (0) носитель до прогона;
#   (1) PRE_FIX: прежняя версия прибора из `eeef07c` на тех же входах обязана дать LEDGER_OK=0;
#   (2) selftest после правки: exit 0 и total=passed;
#   (3) report на паре «E-0114 all.log + workspace-verify log»: STAGES=6, FAILED=0, MISSING=0, OK=1;
#   (4) посадка TEST_EXIT=1 в последний блок: OK=0, EXIT=1;
#   (5) стража текста и сверка ожиданий `lab/expectations/e0116.tsv`;
#   (6) носитель после прогона.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0116-all.log"
VLOG="lab/logs/workspace-verify-2026-10-22.log"
ALOG="lab/logs/e0114-all.log"
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0116.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
FACTS="$OUT/facts.txt"
: > "$FACTS"
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
pick() { grep -o "$1=[A-Za-z0-9_.:/=,%|-]*" "$2" | tail -1 | cut -d= -f2-; }

say "########## E-0116 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 носитель до прогона ### $(date +%FT%T%:z)"
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf "%s" "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then dok=1; else dok=0; fi
emit "DISK_GE_15000=$dok"

say "### ШАГ 1 PRE_FIX: прежний прибор на тех же входах ### $(date +%FT%T%:z)"
git show eeef07c:lab/ledger.py > "$OUT/ledger-prefix.py"
python "$OUT/ledger-prefix.py" report "$ALOG" "$VLOG" > "$OUT/prefix.txt" 2>&1
rc=$?
tail -n 16 "$OUT/prefix.txt" | tee -a "$LOG"
pref_ok=$(pick LEDGER_OK "$OUT/prefix.txt")
emit "PRE_FIX_LEDGER_OK=$pref_ok"
emit "PRE_FIX_LEDGER_EXIT=$rc"
if [ "$pref_ok" = "0" ] && [ "$rc" -ne 0 ]; then echo "PRE_FIX ok: ложный красный воспроизведён"; else
  say "PRE_FIX ПРОВАЛ: прежний прибор не краснеет — порог (1) не выполнен"; note 1; fi

say "### ШАГ 2 selftest после правки ### $(date +%FT%T%:z)"
python lab/ledger.py selftest > "$OUT/self.txt" 2>&1
rc=$?
tail -n 4 "$OUT/self.txt" | tee -a "$LOG"
emit "LEDGER_SELFTEST_EXIT=$rc"
emit "LEDGER_SELFTEST_TOTAL=$(sed -n 's/.*LEDGER_SELFTEST total=\([0-9]*\).*/\1/p' "$OUT/self.txt" | tail -1)"
emit "LEDGER_SELFTEST_PASSED=$(sed -n 's/.*passed=\([0-9]*\).*/\1/p' "$OUT/self.txt" | tail -1)"
note "$rc"

say "### ШАГ 3 report на паре файлов E-0114 ### $(date +%FT%T%:z)"
python lab/ledger.py report "$ALOG" "$VLOG" > "$OUT/report.txt" 2>&1
rc=$?
tail -n 16 "$OUT/report.txt" | tee -a "$LOG"
for k in LEDGER_STAGES LEDGER_FAILED_STAGES LEDGER_MISSING_STAGES LEDGER_OK LEDGER_WALL_TOTAL; do
  emit "$k=$(pick "$k" "$OUT/report.txt")"
done
emit "LEDGER_EXIT=$rc"
note "$rc"

say "### ШАГ 4 посадка TEST_EXIT=1 в последний блок ### $(date +%FT%T%:z)"
awk 'NR==FNR{if (/^########## /) last=FNR; next} FNR>last' "$VLOG" "$VLOG" > "$OUT/vlast.txt"
sed '0,/^TEST_EXIT=0$/s//TEST_EXIT=1/' "$OUT/vlast.txt" > "$OUT/vlast-red.txt"
python lab/ledger.py report "$ALOG" "$OUT/vlast-red.txt" > "$OUT/plant.txt" 2>&1
rc=$?
tail -n 14 "$OUT/plant.txt" | tee -a "$LOG"
emit "PLANT_OK=$(pick LEDGER_OK "$OUT/plant.txt")"
emit "PLANT_FAILED=$(pick LEDGER_FAILED_STAGES "$OUT/plant.txt")"
emit "PLANT_EXIT=$rc"
if [ "$(pick LEDGER_OK "$OUT/plant.txt")" = "0" ] && [ "$rc" -ne 0 ]; then
  echo "PLANT ok: TEST_EXIT=1 краснит"; else say "PLANT ПРОВАЛ: посадка не видна"; note 1; fi

say "### ШАГ 5 стража текста, сверка ожиданий ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh lab/ledger.py lab/e0116-run.sh lab/expectations/e0116.tsv \
  lab/hypotheses/H-0116-ledger-last-block.md lab/experiments/E-0116-ledger-last-block.md \
  lab/e0090-run.sh lab/e0102-run.sh lab/e0103-run.sh lab/e0104-run.sh lab/e0105-run.sh \
  lab/e0108-run.sh lab/e0111-run.sh lab/e0112-run.sh lab/e0113-run.sh > "$OUT/text.txt" 2>&1
rc=$?
tail -n 2 "$OUT/text.txt" | tee -a "$LOG"
emit "TEXTGUARD_EXIT=$rc"; note "$rc"
python -c "compile(open('lab/ledger.py', encoding='utf-8').read(), 'lab/ledger.py', 'exec')" > "$OUT/py.txt" 2>&1
rc=$?
emit "PYCOMPILE_EXIT=$rc"; note "$rc"
python lab/expect.py lab/expectations/e0116.tsv "$FACTS" "$FACTS" > "$OUT/exp.txt" 2>&1
rc=$?
tail -n 8 "$OUT/exp.txt" | tee -a "$LOG"
emit "EXPECT_EXIT=$rc"; note "$rc"

say "### ШАГ 6 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
