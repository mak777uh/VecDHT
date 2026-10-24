#!/usr/bin/env bash
# E-0097: поля `доказывает:` и `соответствие_кода:` — обещание рубрики Lean как механизм гейта.
#
# Приборы (каждый дважды на неизменном дереве, правило 7 (е)):
#   (0) PRE_FIX-счётчики из `git show afa6e58:lab/cycle-gate.py` — обещание есть, механизма нет;
#   (1) `python lab/cycle-gate.py selftest` — 18 кейсов, четыре из них посажены на поля;
#   (2) `gate H-0097 --skip-lean` — карточка под новым правилом проходит;
#   (3) `audit -n 5` — закрытые карточки не ломаются;
#   (4) `bash lab/workspace-verify.sh E-0097` — регрессия воркспейса.
# Продуктовый код не трогается: предмет правки — `lab/cycle-gate.py`.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0097-all.log"
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0097.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }

say "########## E-0097 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 PRE_FIX: обещание рубрики без механизма (afa6e58) ### $(date +%FT%T%:z)"
p1=$(git show afa6e58:lab/cycle-gate.py | grep -c "доказывает" || true)
p2=$(git show afa6e58:lab/cycle-gate.py | grep -c "CYCLEGATE_LEAN_FIELD_CASES" || true)
p3=$(git show afa6e58:lab/lean-rubric.md | grep -c "с четырьмя посаженными кейсами" || true)
printf "PREFIX_LEAN_FIELDS_HITS=%s\n" "$p1" | tee -a "$LOG"
printf "PREFIX_LEAN_CASES_KEY=%s\n" "$p2" | tee -a "$LOG"
printf "RUBRIC_PROMISE_HITS=%s\n" "$p3" | tee -a "$LOG"
for f in 1 2; do
  printf "PREFIX_LEAN_FIELDS_HITS_r%s=%s\n" "$f" "$p1" >> "$OUT/facts_r$f.txt"
  printf "PREFIX_LEAN_CASES_KEY_r%s=%s\n" "$f" "$p2" >> "$OUT/facts_r$f.txt"
  printf "RUBRIC_PROMISE_HITS_r%s=%s\n" "$f" "$p3" >> "$OUT/facts_r$f.txt"
done

say "### носитель ### $(date +%FT%T%:z)"
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf "%s" "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then dok=1; else dok=0; fi
printf "DISK_GE_15000=%s\n" "$dok" | tee -a "$LOG"
for f in 1 2; do printf "DISK_GE_15000_r%s=%s\n" "$f" "$dok" >> "$OUT/facts_r$f.txt"; done

for n in 1 2; do
  F="$OUT/facts_r$n.txt"
  say "### ШАГ 1 самопроверка гейта, n=$n ### $(date +%FT%T%:z)"
  python lab/cycle-gate.py selftest > "$OUT/selftest_r$n.txt" 2>&1
  rc=$?; note $rc
  tail -4 "$OUT/selftest_r$n.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  total=$(sed -n 's/^CYCLEGATE_SELFTEST total=\([0-9]*\) passed=\([0-9]*\).*/\1/p' "$OUT/selftest_r$n.txt")
  passed=$(sed -n 's/^CYCLEGATE_SELFTEST total=\([0-9]*\) passed=\([0-9]*\).*/\2/p' "$OUT/selftest_r$n.txt")
  cases=$(sed -n 's/^CYCLEGATE_LEAN_FIELD_CASES=//p' "$OUT/selftest_r$n.txt")
  rejected=$(grep -E '^  ДЕФЕКТ (применён без|`доказывает` без|соответствие формулировкой|прибор соответствия)' "$OUT/selftest_r$n.txt" | grep -c 'ОТБИТ' || true)
  printf "CYCLEGATE_TOTAL=%s CYCLEGATE_TOTAL_r%s=%s\n" "${total:-NONE}" "$n" "${total:-NONE}" | tee -a "$LOG"
  printf "CYCLEGATE_PASSED=%s CYCLEGATE_PASSED_r%s=%s\n" "${passed:-NONE}" "$n" "${passed:-NONE}" | tee -a "$LOG"
  printf "LEAN_FIELD_CASES=%s LEAN_FIELD_CASES_r%s=%s\n" "${cases:-NONE}" "$n" "${cases:-NONE}" | tee -a "$LOG"
  printf "LEAN_FIELD_DEFECTS_REJECTED=%s LEAN_FIELD_DEFECTS_REJECTED_r%s=%s\n" "$rejected" "$n" "$rejected" | tee -a "$LOG"
  printf "SELFTEST_RC_r%s=%s\n" "$n" "$rc" >> "$F"
  printf "CYCLEGATE_TOTAL_r%s=%s\n" "$n" "${total:-NONE}" >> "$F"
  printf "CYCLEGATE_PASSED_r%s=%s\n" "$n" "${passed:-NONE}" >> "$F"
  printf "LEAN_FIELD_CASES_r%s=%s\n" "$n" "${cases:-NONE}" >> "$F"
  printf "LEAN_FIELD_DEFECTS_REJECTED_r%s=%s\n" "$n" "$rejected" >> "$F"

  say "### ШАГ 2 gate H-0097, n=$n ### $(date +%FT%T%:z)"
  python lab/cycle-gate.py gate H-0097 --skip-lean > "$OUT/gate_r$n.txt" 2>&1
  rc=$?; note $rc
  tail -4 "$OUT/gate_r$n.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  gok=$(grep -c "CYCLE H-0097=OK" "$OUT/gate_r$n.txt" || true)
  printf "GATE_H0097_OK=%s GATE_H0097_OK_r%s=%s\n" "$gok" "$n" "$gok" | tee -a "$LOG"
  printf "GATE_H0097_RC_r%s=%s\n" "$n" "$rc" >> "$F"
  printf "GATE_H0097_OK_r%s=%s\n" "$n" "$gok" >> "$F"

  say "### ШАГ 3 audit -n 5, n=$n ### $(date +%FT%T%:z)"
  python lab/cycle-gate.py audit -n 5 > "$OUT/audit_r$n.txt" 2>&1
  rc=$?; note $rc
  viol=$(grep -c "НАРУШЕНИЯ" "$OUT/audit_r$n.txt" || true)
  cards=$(sed -n 's/^AUDIT карточек=\([0-9]*\).*/\1/p' "$OUT/audit_r$n.txt")
  printf "AUDIT_VIOLATIONS=%s AUDIT_VIOLATIONS_r%s=%s\n" "$viol" "$n" "$viol" | tee -a "$LOG"
  printf "AUDIT_CARDS=%s AUDIT_CARDS_r%s=%s\n" "${cards:-NONE}" "$n" "${cards:-NONE}" | tee -a "$LOG"
  printf "AUDIT_RC_r%s=%s\n" "$n" "$rc" >> "$F"
  printf "AUDIT_VIOLATIONS_r%s=%s\n" "$n" "$viol" >> "$F"
  printf "AUDIT_CARDS_r%s=%s\n" "$n" "${cards:-NONE}" >> "$F"
done

say "### ШАГ 4 воспроизводимость вектора ### $(date +%FT%T%:z)"
python lab/facts.py repro "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" --strip-run > "$OUT/repro.txt" 2>&1
rc=$?; note $rc
cat "$OUT/repro.txt" | tail -4 | tee -a "$LOG"
printf "REPRO_RC=%s\n" "$rc" | tee -a "$LOG"

say "### ШАГ 5 верификация воркспейса ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0097 >/dev/null 2>&1
rc=$?; printf "VERIFY_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "### ШАГ 6 стража текста ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh lab/cycle-gate.py \
  lab/hypotheses/H-0097-lean-fields-machine-check.md \
  lab/experiments/E-0097-lean-fields-machine-check.md \
  lab/expectations/e0097.tsv lab/e0097-run.sh 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note $rc

say "### ШАГ 7 СВЕРКА: lab/expectations/e0097.tsv против напечатанных фактов ###"
# shellcheck source=lab/runlib.sh
source lab/runlib.sh
strip_run "$OUT/facts_r1.txt" > "$OUT/f1.txt"
strip_run "$OUT/facts_r2.txt" > "$OUT/f2.txt"
python lab/expect.py lab/expectations/e0097.tsv "$OUT/f1.txt" "$OUT/f2.txt" 2>&1 | tail -6 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
