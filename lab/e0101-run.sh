#!/usr/bin/env bash
# E-0101: самопроверка репозитория после цикла — прибор, посадки и встраивание.
#
# Приборы (каждый дважды на неизменном дереве, правило 7 (е)):
#   (0) PRE_FIX на архиве `2925bf2`: прибора нет (0 строк), verify его не зовёт (0 вхождений),
#       а применённый к архиву прибор находит 5 слабостей — это и есть предмет цикла;
#   (1) `python lab/repo-review.py selftest` — 8 кейсов (семь классов + чистое дерево);
#   (2) `python lab/repo-review.py check` — 0 находок на дереве после правки;
#   (3) `gate H-0101 --skip-lean` и `audit -n 5` — карточка и соседние карточки не ломаются;
#   (4) `bash lab/workspace-verify.sh E-0101` — прибор исполняется закрытием цикла.
# Продуктовый код не трогается: предмет — `lab/repo-review.py` и пять карточек.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0101-all.log"
BASE="${E0101_BASE:-2925bf2}"
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0101.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }

say "########## E-0101 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 PRE_FIX: прибора нет, слабости есть (архив $BASE) ### $(date +%FT%T%:z)"
p1=$(git show "$BASE":lab/repo-review.py 2>/dev/null | wc -l | tr -d ' ')
p2=$(git show "$BASE":lab/workspace-verify.sh 2>/dev/null | grep -c 'repo-review' || true)
mkdir -p "$OUT/prefix"
git archive "$BASE" | tar -x -C "$OUT/prefix"
python lab/repo-review.py check --root "$OUT/prefix" > "$OUT/prefix.txt" 2>&1
prc=$?; note $prc
pf=$(sed -n 's/^REVIEW_FINDINGS=//p' "$OUT/prefix.txt" | tail -1)
pt=$(sed -n 's/^REVIEW_TOP=//p' "$OUT/prefix.txt" | tail -1)
printf "PREFIX_REVIEW_SCRIPT=%s\n" "${p1:-NONE}" | tee -a "$LOG"
printf "PREFIX_VERIFY_REFS=%s\n" "${p2:-NONE}" | tee -a "$LOG"
printf "PREFIX_FINDINGS=%s\n" "${pf:-NONE}" | tee -a "$LOG"
printf "PREFIX_TOP=%s\n" "${pt:-NONE}" | tee -a "$LOG"
grep '^НАХОДКА' "$OUT/prefix.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
for f in 1 2; do
  printf "PREFIX_REVIEW_SCRIPT_r%s=%s\n" "$f" "${p1:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "PREFIX_VERIFY_REFS_r%s=%s\n" "$f" "${p2:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "PREFIX_FINDINGS_r%s=%s\n" "$f" "${pf:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "PREFIX_TOP_r%s=%s\n" "$f" "${pt:-NONE}" >> "$OUT/facts_r$f.txt"
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
  say "### ШАГ 1 самопроверка прибора, n=$n ### $(date +%FT%T%:z)"
  python lab/repo-review.py selftest > "$OUT/selftest_r$n.txt" 2>&1
  rc=$?; note $rc
  tail -9 "$OUT/selftest_r$n.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  st=$(sed -n 's/^REVIEW_SELFTEST total=\([0-9]*\) passed=\([0-9]*\).*/\1/p' "$OUT/selftest_r$n.txt")
  sp=$(sed -n 's/^REVIEW_SELFTEST total=\([0-9]*\) passed=\([0-9]*\).*/\2/p' "$OUT/selftest_r$n.txt")
  printf "REVIEW_SELFTEST_TOTAL=%s REVIEW_SELFTEST_TOTAL_r%s=%s\n" "${st:-NONE}" "$n" "${st:-NONE}" | tee -a "$LOG"
  printf "REVIEW_SELFTEST_PASSED=%s REVIEW_SELFTEST_PASSED_r%s=%s\n" "${sp:-NONE}" "$n" "${sp:-NONE}" | tee -a "$LOG"
  printf "SELFTEST_RC_r%s=%s\n" "$n" "$rc" >> "$F"
  printf "REVIEW_SELFTEST_TOTAL_r%s=%s\n" "$n" "${st:-NONE}" >> "$F"
  printf "REVIEW_SELFTEST_PASSED_r%s=%s\n" "$n" "${sp:-NONE}" >> "$F"

  say "### ШАГ 2 check: находки и инвентарь, n=$n ### $(date +%FT%T%:z)"
  python lab/repo-review.py check > "$OUT/check_r$n.txt" 2>&1
  rc=$?; note $rc
  grep -E '^(REVIEW_(FINDINGS|TOP|CLOSED_EMPTY|TESTING_CLOSED|IGNORED_NO_REASON|EXPECT_ORPHANS|HELPER_ORPHANS|MISSING_EXPERIMENTS|REFS_STALE|MD_FILES|REFS_OK|IGNORED|BIG_RS|TODOS)=|НАХОДКА)' "$OUT/check_r$n.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  # Каждый ключ печатается литералом: линт порогов обязан видеть, что факт кто-то
  # печатает, а не что helper умеет печатать что угодно. Цикл по переменной этого не даёт.
  v=$(sed -n 's/^REVIEW_FINDINGS=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_FINDINGS=%s REVIEW_FINDINGS_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_FINDINGS_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_TOP=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_TOP=%s REVIEW_TOP_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_TOP_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_CLOSED_EMPTY=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_CLOSED_EMPTY=%s REVIEW_CLOSED_EMPTY_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_CLOSED_EMPTY_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_TESTING_CLOSED=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_TESTING_CLOSED=%s REVIEW_TESTING_CLOSED_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_TESTING_CLOSED_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_IGNORED_NO_REASON=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_IGNORED_NO_REASON=%s REVIEW_IGNORED_NO_REASON_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_IGNORED_NO_REASON_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_EXPECT_ORPHANS=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_EXPECT_ORPHANS=%s REVIEW_EXPECT_ORPHANS_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_EXPECT_ORPHANS_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_HELPER_ORPHANS=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_HELPER_ORPHANS=%s REVIEW_HELPER_ORPHANS_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_HELPER_ORPHANS_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_MISSING_EXPERIMENTS=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_MISSING_EXPERIMENTS=%s REVIEW_MISSING_EXPERIMENTS_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_MISSING_EXPERIMENTS_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_REFS_STALE=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_REFS_STALE=%s REVIEW_REFS_STALE_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_REFS_STALE_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_MD_FILES=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_MD_FILES=%s REVIEW_MD_FILES_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_MD_FILES_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_REFS_OK=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_REFS_OK=%s REVIEW_REFS_OK_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_REFS_OK_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_IGNORED=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_IGNORED=%s REVIEW_IGNORED_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_IGNORED_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_BIG_RS=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_BIG_RS=%s REVIEW_BIG_RS_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_BIG_RS_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  v=$(sed -n 's/^REVIEW_TODOS=//p' "$OUT/check_r$n.txt" | tail -1)
  printf "REVIEW_TODOS=%s REVIEW_TODOS_r%s=%s
" "${v:-NONE}" "$n" "${v:-NONE}" | tee -a "$LOG" >/dev/null
  printf "REVIEW_TODOS_r%s=%s
" "$n" "${v:-NONE}" >> "$F"
  printf "CHECK_RC_r%s=%s\n" "$n" "$rc" >> "$F"

  say "### ШАГ 3 gate H-0101 и audit -n 5, n=$n ### $(date +%FT%T%:z)"
  python lab/cycle-gate.py gate H-0101 --skip-lean > "$OUT/gate_r$n.txt" 2>&1
  rc=$?; note $rc
  tail -4 "$OUT/gate_r$n.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  gok=$(grep -c "CYCLE H-0101=OK" "$OUT/gate_r$n.txt" || true)
  printf "GATE_H0101_OK=%s GATE_H0101_OK_r%s=%s\n" "$gok" "$n" "$gok" | tee -a "$LOG"
  printf "GATE_RC_r%s=%s\n" "$n" "$rc" >> "$F"
  printf "GATE_H0101_OK_r%s=%s\n" "$n" "$gok" >> "$F"

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
rv=$(sed -n 's/^REPRO_VECTOR=//p' "$OUT/repro.txt" | tail -1)
for f in 1 2; do printf "REPRO_VECTOR_r%s=%s\n" "$f" "${rv:-NONE}" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 5 верификация воркспейса ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0101 >/dev/null 2>&1
rc=$?; printf "VERIFY_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc
awk '/^########## E-0101 · workspace-verify/{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}' \
  lab/logs/workspace-verify-2026-10-22.log > "$OUT/verify_block.txt"
if grep -q 'REVIEW_SELFTEST total=8 passed=8' "$OUT/verify_block.txt" &&
   grep -q 'REVIEW_FINDINGS=0' "$OUT/verify_block.txt"; then
  iv=1
else
  iv=0
fi
printf "REVIEW_IN_VERIFY=%s (selftest_строк=%s, findings_строк=%s)\n" "$iv" \
  "$(grep -c 'REVIEW_SELFTEST total=' "$OUT/verify_block.txt" || true)" \
  "$(grep -c 'REVIEW_FINDINGS=0' "$OUT/verify_block.txt" || true)" | tee -a "$LOG"
for f in 1 2; do printf "REVIEW_IN_VERIFY_r%s=%s\n" "$f" "$iv" >> "$OUT/facts_r$f.txt"; done
grep -E 'REVIEW_(SELFTEST|FINDINGS)=' "$OUT/verify_block.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null

say "### ШАГ 6 стража текста ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh lab/repo-review.py lab/workspace-verify.sh lab/PLAN.md \
  lab/README.md lab/library/index.jsonl \
  lab/hypotheses/H-0101-repo-review-after-each-cycle.md \
  lab/experiments/E-0101-repo-review-after-each-cycle.md \
  lab/hypotheses/H-0092-denylist-durable-and-bounded.md \
  lab/hypotheses/H-0093-lean-model-guards.md \
  lab/hypotheses/H-0094-revocation-durable-after-restart.md \
  lab/hypotheses/H-0095-door-refusal-reason-observable.md \
  lab/experiments/E-0015-owner-cap-cost.md \
  lab/expectations/e0101.tsv lab/e0101-run.sh 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note $rc

say "### ШАГ 7 СВЕРКА: lab/expectations/e0101.tsv против напечатанных фактов ###"
# shellcheck source=lab/runlib.sh
source lab/runlib.sh
strip_run "$OUT/facts_r1.txt" > "$OUT/f1.txt"
strip_run "$OUT/facts_r2.txt" > "$OUT/f2.txt"
python lab/expect.py lab/expectations/e0101.tsv "$OUT/f1.txt" "$OUT/f2.txt" 2>&1 | tail -6 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
