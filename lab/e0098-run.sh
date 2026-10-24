#!/usr/bin/env bash
# E-0098: политика просроченного собственного кредашиала — fail-stop и наблюдаемая причина.
#
# Приборы (каждый дважды на неизменном дереве, правило 7 (е)):
#   (0) PRE_FIX: своего срока в `service.rs` нет (0 вхождений `valid_until`, 0 `own_cert_expired`
#       при 17 `self_revoked`), а замороженный прогон оракула на базовом продукте показывает
#       `G1_CONSTRUCTED=1` и `G2_AFTER_EXPIRY_SERVED=1` — дыра измерена исполнением;
#   (1) `cargo test -p vecdht-net --test s76_own_cert_expiry` — 3 гейта;
#   (2) `cargo test -p vecdht-net --test s76b_own_cert_expiry_observe` — счётчик и флаг;
#   (3) `cargo test -p vecdht-net --lib own_cert_window` — граница окна;
#   (4) `gate H-0098 --skip-lean` и `audit -n 5`;
#   (5) `bash lab/workspace-verify.sh E-0098` — оракул исполняется полной регрессией.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0098-all.log"
BASE="${E0098_BASE:-f9923c9}"
PREFIX_LOG="lab/logs/e0098-prefix.log"
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0098.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }

say "########## E-0098 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 PRE_FIX: своего срока нет, дыра измерена оракулом ### $(date +%FT%T%:z)"
p1=$(git show "$BASE:crates/vecdht-net/src/service.rs" | grep -c "valid_until" || true)
p2=$(git show "$BASE:crates/vecdht-net/src/service.rs" | grep -c "own_cert_expired" || true)
p3=$(git show "$BASE:crates/vecdht-net/src/service.rs" | grep -c "self_revoked" || true)
pp=$(sed -n 's/.*test result: FAILED\. \([0-9]*\) passed; \([0-9]*\) failed.*/\1/p' "$PREFIX_LOG" | tail -1)
pf=$(sed -n 's/.*test result: FAILED\. \([0-9]*\) passed; \([0-9]*\) failed.*/\2/p' "$PREFIX_LOG" | tail -1)
pg1=$(grep -o 'G1_CONSTRUCTED=[0-9]*' "$PREFIX_LOG" | tail -1 | cut -d= -f2)
pg2=$(grep -o 'G2_AFTER_EXPIRY_SERVED=[0-9]*' "$PREFIX_LOG" | tail -1 | cut -d= -f2)
pg3=$(grep -o 'G3_FRESH_SERVED=[0-9]*' "$PREFIX_LOG" | tail -1 | cut -d= -f2)
printf "PREFIX_VALID_UNTIL_HITS=%s\n" "$p1" | tee -a "$LOG"
printf "PREFIX_OWN_CERT_EXPIRED_HITS=%s\n" "$p2" | tee -a "$LOG"
printf "PREFIX_SELF_REVOKED_HITS=%s\n" "$p3" | tee -a "$LOG"
printf "PREFIX_ORACLE_PASSED=%s\n" "${pp:-NONE}" | tee -a "$LOG"
printf "PREFIX_ORACLE_FAILED=%s\n" "${pf:-NONE}" | tee -a "$LOG"
printf "PREFIX_G1_CONSTRUCTED=%s\n" "${pg1:-NONE}" | tee -a "$LOG"
printf "PREFIX_G2_AFTER_EXPIRY_SERVED=%s\n" "${pg2:-NONE}" | tee -a "$LOG"
printf "PREFIX_G3_FRESH_SERVED=%s\n" "${pg3:-NONE}" | tee -a "$LOG"

say "### носитель ### $(date +%FT%T%:z)"
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf "%s" "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then dok=1; else dok=0; fi
printf "DISK_GE_15000=%s\n" "$dok" | tee -a "$LOG"

for n in 1 2; do
  F="$OUT/facts_r$n.txt"
  {
    printf "PREFIX_VALID_UNTIL_HITS_r%s=%s\n" "$n" "$p1"
    printf "PREFIX_OWN_CERT_EXPIRED_HITS_r%s=%s\n" "$n" "$p2"
    printf "PREFIX_SELF_REVOKED_HITS_r%s=%s\n" "$n" "$p3"
    printf "PREFIX_ORACLE_PASSED_r%s=%s\n" "$n" "${pp:-NONE}"
    printf "PREFIX_ORACLE_FAILED_r%s=%s\n" "$n" "${pf:-NONE}"
    printf "PREFIX_G1_CONSTRUCTED_r%s=%s\n" "$n" "${pg1:-NONE}"
    printf "PREFIX_G2_AFTER_EXPIRY_SERVED_r%s=%s\n" "$n" "${pg2:-NONE}"
    printf "PREFIX_G3_FRESH_SERVED_r%s=%s\n" "$n" "${pg3:-NONE}"
    printf "DISK_GE_15000_r%s=%s\n" "$n" "$dok"
  } >> "$F"

  say "### ШАГ 1 оракул s76: три гейта, n=$n ### $(date +%FT%T%:z)"
  cargo test -p vecdht-net --test s76_own_cert_expiry -- --nocapture --test-threads=1 \
    > "$OUT/s76_r$n.txt" 2>&1
  rc=$?; note $rc
  grep -E '^test |^G[123]_|test result' "$OUT/s76_r$n.txt" | tail -8 | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  total=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\1/p' "$OUT/s76_r$n.txt" | tail -1)
  passed=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\1/p' "$OUT/s76_r$n.txt" | tail -1)
  failed=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\2/p' "$OUT/s76_r$n.txt" | tail -1)
  g1=$(grep -o 'G1_CONSTRUCTED=[0-9]*' "$OUT/s76_r$n.txt" | tail -1 | cut -d= -f2)
  g2b=$(grep -o 'G2_BEFORE_EXPIRY_SERVED=[0-9]*' "$OUT/s76_r$n.txt" | tail -1 | cut -d= -f2)
  g2=$(grep -o 'G2_AFTER_EXPIRY_SERVED=[0-9]*' "$OUT/s76_r$n.txt" | tail -1 | cut -d= -f2)
  g3=$(grep -o 'G3_FRESH_SERVED=[0-9]*' "$OUT/s76_r$n.txt" | tail -1 | cut -d= -f2)
  printf "S76_TOTAL=%s S76_TOTAL_r%s=%s\n" "$(( ${total:-0} + ${failed:-0} ))" "$n" "$(( ${total:-0} + ${failed:-0} ))" | tee -a "$LOG"
  printf "S76_PASSED=%s S76_PASSED_r%s=%s\n" "${passed:-NONE}" "$n" "${passed:-NONE}" | tee -a "$LOG"
  printf "S76_G1_CONSTRUCTED=%s S76_G1_CONSTRUCTED_r%s=%s\n" "${g1:-NONE}" "$n" "${g1:-NONE}" | tee -a "$LOG"
  printf "S76_G2_BEFORE_EXPIRY_SERVED=%s S76_G2_BEFORE_EXPIRY_SERVED_r%s=%s\n" "${g2b:-NONE}" "$n" "${g2b:-NONE}" | tee -a "$LOG"
  printf "S76_G2_AFTER_EXPIRY_SERVED=%s S76_G2_AFTER_EXPIRY_SERVED_r%s=%s\n" "${g2:-NONE}" "$n" "${g2:-NONE}" | tee -a "$LOG"
  printf "S76_G3_FRESH_SERVED=%s S76_G3_FRESH_SERVED_r%s=%s\n" "${g3:-NONE}" "$n" "${g3:-NONE}" | tee -a "$LOG"
  {
    printf "S76_TOTAL_r%s=%s\n" "$n" "$(( ${total:-0} + ${failed:-0} ))"
    printf "S76_PASSED_r%s=%s\n" "$n" "${passed:-NONE}"
    printf "S76_G1_CONSTRUCTED_r%s=%s\n" "$n" "${g1:-NONE}"
    printf "S76_G2_BEFORE_EXPIRY_SERVED_r%s=%s\n" "$n" "${g2b:-NONE}"
    printf "S76_G2_AFTER_EXPIRY_SERVED_r%s=%s\n" "$n" "${g2:-NONE}"
    printf "S76_G3_FRESH_SERVED_r%s=%s\n" "$n" "${g3:-NONE}"
  } >> "$F"

  say "### ШАГ 2 счётчик и флаг, n=$n ### $(date +%FT%T%:z)"
  cargo test -p vecdht-net --test s76b_own_cert_expiry_observe -- --nocapture --test-threads=1 \
    > "$OUT/s76b_r$n.txt" 2>&1
  rc=$?; note $rc
  tail -4 "$OUT/s76b_r$n.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  btotal=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\1/p' "$OUT/s76b_r$n.txt" | tail -1)
  bfailed=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\2/p' "$OUT/s76b_r$n.txt" | tail -1)
  bself=$(grep -o 'S76B_SELF_EXPIRED=[0-9]*' "$OUT/s76b_r$n.txt" | tail -1 | cut -d= -f2)
  bref=$(grep -o 'S76B_REFUSALS_GE_1=[0-9]*' "$OUT/s76b_r$n.txt" | tail -1 | cut -d= -f2)
  printf "S76B_TOTAL=%s S76B_TOTAL_r%s=%s\n" "$(( ${btotal:-0} + ${bfailed:-0} ))" "$n" "$(( ${btotal:-0} + ${bfailed:-0} ))" | tee -a "$LOG"
  printf "S76B_PASSED=%s S76B_PASSED_r%s=%s\n" "${btotal:-NONE}" "$n" "${btotal:-NONE}" | tee -a "$LOG"
  printf "S76B_SELF_EXPIRED=%s S76B_SELF_EXPIRED_r%s=%s\n" "${bself:-NONE}" "$n" "${bself:-NONE}" | tee -a "$LOG"
  printf "S76B_REFUSALS_GE_1=%s S76B_REFUSALS_GE_1_r%s=%s\n" "${bref:-NONE}" "$n" "${bref:-NONE}" | tee -a "$LOG"
  {
    printf "S76B_TOTAL_r%s=%s\n" "$n" "$(( ${btotal:-0} + ${bfailed:-0} ))"
    printf "S76B_PASSED_r%s=%s\n" "$n" "${btotal:-NONE}"
    printf "S76B_SELF_EXPIRED_r%s=%s\n" "$n" "${bself:-NONE}"
    printf "S76B_REFUSALS_GE_1_r%s=%s\n" "$n" "${bref:-NONE}"
  } >> "$F"

  say "### ШАГ 3 граница окна, n=$n ### $(date +%FT%T%:z)"
  cargo test -p vecdht-net --lib own_cert_window -- --nocapture --test-threads=1 \
    > "$OUT/unit_r$n.txt" 2>&1
  rc=$?; note $rc
  utotal=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\1/p' "$OUT/unit_r$n.txt" | tail -1)
  ufailed=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\2/p' "$OUT/unit_r$n.txt" | tail -1)
  printf "UNIT_TOTAL=%s UNIT_TOTAL_r%s=%s\n" "$(( ${utotal:-0} + ${ufailed:-0} ))" "$n" "$(( ${utotal:-0} + ${ufailed:-0} ))" | tee -a "$LOG"
  printf "UNIT_PASSED=%s UNIT_PASSED_r%s=%s\n" "${utotal:-NONE}" "$n" "${utotal:-NONE}" | tee -a "$LOG"
  {
    printf "UNIT_TOTAL_r%s=%s\n" "$n" "$(( ${utotal:-0} + ${ufailed:-0} ))"
    printf "UNIT_PASSED_r%s=%s\n" "$n" "${utotal:-NONE}"
  } >> "$F"

  say "### ШАГ 4 gate H-0098 и audit -n 5, n=$n ### $(date +%FT%T%:z)"
  python lab/cycle-gate.py gate H-0098 --skip-lean > "$OUT/gate_r$n.txt" 2>&1
  rc=$?; note $rc
  tail -4 "$OUT/gate_r$n.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  gok=$(grep -c "CYCLE H-0098=OK" "$OUT/gate_r$n.txt" || true)
  printf "GATE_H0098_OK=%s GATE_H0098_OK_r%s=%s\n" "$gok" "$n" "$gok" | tee -a "$LOG"
  python lab/cycle-gate.py audit -n 5 > "$OUT/audit_r$n.txt" 2>&1
  rc=$?; note $rc
  viol=$(grep -c "НАРУШЕНИЯ" "$OUT/audit_r$n.txt" || true)
  cards=$(sed -n 's/^AUDIT карточек=\([0-9]*\).*/\1/p' "$OUT/audit_r$n.txt")
  printf "AUDIT_VIOLATIONS=%s AUDIT_VIOLATIONS_r%s=%s\n" "$viol" "$n" "$viol" | tee -a "$LOG"
  printf "AUDIT_CARDS=%s AUDIT_CARDS_r%s=%s\n" "${cards:-NONE}" "$n" "${cards:-NONE}" | tee -a "$LOG"
  {
    printf "GATE_H0098_OK_r%s=%s\n" "$n" "$gok"
    printf "AUDIT_VIOLATIONS_r%s=%s\n" "$n" "$viol"
    printf "AUDIT_CARDS_r%s=%s\n" "$n" "${cards:-NONE}"
  } >> "$F"
done

say "### ШАГ 5 воспроизводимость вектора ### $(date +%FT%T%:z)"
python lab/facts.py repro "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" --strip-run > "$OUT/repro.txt" 2>&1
rc=$?; note $rc
tail -4 "$OUT/repro.txt" | tee -a "$LOG"
printf "REPRO_VECTOR=%s\n" "$(sed -n 's/^REPRO_VECTOR=//p' "$OUT/repro.txt" | tail -1)" | tee -a "$LOG"
rv=$(sed -n 's/^REPRO_VECTOR=//p' "$OUT/repro.txt" | tail -1)
for f in 1 2; do printf "REPRO_VECTOR_r%s=%s\n" "$f" "${rv:-NONE}" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 6 верификация воркспейса ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0098 >/dev/null 2>&1
rc=$?; printf "VERIFY_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc
VLOG="lab/logs/workspace-verify-2026-10-22.log"
start=$(grep -n "########## E-0098 · workspace-verify" "$VLOG" | tail -1 | cut -d: -f1)
if [ -n "$start" ]; then
  tail -n +"$start" "$VLOG" > "$OUT/verify_block.txt"
  if grep -q "s76_own_cert_expiry" "$OUT/verify_block.txt" \
     && grep -q "test result: ok. 3 passed" "$OUT/verify_block.txt"; then
    vin=1
  else
    vin=0
  fi
else
  vin=0
fi
printf "S76_IN_VERIFY=%s\n" "$vin" | tee -a "$LOG"
for f in 1 2; do printf "S76_IN_VERIFY_r%s=%s\n" "$f" "$vin" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 7 стража текста ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh \
  crates/vecdht-net/src/service.rs \
  crates/vecdht-net/tests/s76_own_cert_expiry.rs \
  crates/vecdht-net/tests/s76b_own_cert_expiry_observe.rs \
  lab/hypotheses/H-0098-own-cert-expiry-policy.md \
  lab/experiments/E-0098-own-cert-expiry-policy.md \
  lab/expectations/e0098.tsv lab/e0098-run.sh 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note $rc
dirty=$(sed -n 's/.*файлов_с_грязью=\([0-9]*\).*/\1/p' "$LOG" | tail -1)
printf "TEXT_DIRTY_FILES=%s\n" "${dirty:-NONE}" | tee -a "$LOG"
for f in 1 2; do printf "TEXT_DIRTY_FILES_r%s=%s\n" "$f" "${dirty:-NONE}" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 8 СВЕРКА: lab/expectations/e0098.tsv против напечатанных фактов ###"
# shellcheck source=lab/runlib.sh
source lab/runlib.sh
strip_run "$OUT/facts_r1.txt" > "$OUT/f1.txt"
strip_run "$OUT/facts_r2.txt" > "$OUT/f2.txt"
python lab/expect.py lab/expectations/e0098.tsv "$OUT/f1.txt" "$OUT/f2.txt" 2>&1 | tail -6 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
