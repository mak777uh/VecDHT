#!/usr/bin/env bash
# E-0102: вытеснение внутри полной ячейки не должно зависеть от шардового резервуара.
#
# Приборы (каждый дважды на неизменном дереве, правило 7 (е)):
#   (0) PRE_FIX: в базовом `admission.rs` нет ни `cell_victim_scan`, ни `cell_scanned`
#       (резервуар — единственный источник жертвы), а замороженный прогон `s77` на базовом
#       продукте даёт отказ на обоих заходах в полную ячейку. Плюс уже замороженный `E-0088`
#       даёт полноразмерный факт `g5_branch=refuse` при `live=34 286`;
#   (1) `cargo test -p vecdht-node --test s77_cell_cap_scan` — 2 гейта (оба на базовом продукте
#       компилируются: файл появился в пре-регистрации, не с правкой);
#   (2) `cargo test -p vecdht-node --test s77b_cell_cap_scan_observe` — бюджет, курсор, обёртка;
#   (3) `cargo test -p vecdht-node --test s14_cell_cap_enforced above_the_floor ... --exact` —
#       полноразмерный случай `E-0088` (live=34 286, предел 4286) обязан перейти в вытеснение;
#   (4) `gate H-0102 --skip-lean` и `audit -n 5`;
#   (5) сверка вектора `python lab/facts.py repro --strip-run`;
#   (6) `bash lab/workspace-verify.sh E-0102` — оба оракула исполняются полной регрессией;
#   (7) стража текста и `python lab/expect.py lab/expectations/e0102.tsv`.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0102-all.log"
BASE="${E0102_BASE:-ae35a1d}"
PREFIX_LOG="lab/logs/e0102-prefix.log"
FREEZE_LOG="lab/logs/e0088-all.log"
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0102.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
pick() { grep -o "$1=[A-Za-z0-9_]*" "$2" | tail -1 | cut -d= -f2; }

say "########## E-0102 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 PRE_FIX: резервуар — единственный источник жертвы, дыра измерена ### $(date +%FT%T%:z)"
p1=$(git show "$BASE:crates/vecdht-node/src/admission.rs" | grep -c "cell_victim_scan" || true)
p2=$(git show "$BASE:crates/vecdht-node/src/admission.rs" | grep -c "cell_scanned" || true)
p3=$(git show "$BASE:crates/vecdht-node/src/admission.rs" | grep -c "cell_victim" || true)
pp=$(sed -n 's/.*test result: FAILED\. \([0-9]*\) passed; \([0-9]*\) failed.*/\1/p' "$PREFIX_LOG" | tail -1)
pf=$(sed -n 's/.*test result: FAILED\. \([0-9]*\) passed; \([0-9]*\) failed.*/\2/p' "$PREFIX_LOG" | tail -1)
pfr=$(pick "S77_FIRST_REFUSED" "$PREFIX_LOG")
pfc=$(pick "S77_FIRST_CODE" "$PREFIX_LOG")
pfc2=$(pick "S77_AFTER_FIRST_CELL" "$PREFIX_LOG")
pft=$(pick "S77_AFTER_FIRST_TOTAL" "$PREFIX_LOG")
pfe=$(pick "S77_AFTER_FIRST_EVICTED" "$PREFIX_LOG")
psec=$(sed -n 's/.*ответ: Some("\([A-Z_]*\)").*/\1/p' "$PREFIX_LOG" | tail -1)
# Строка E-0088 начинается с `MERE g5_live_before=…`, поэтому `g5_branch` стоит не сразу за
# `MERE`, а в середине строки; якорь — сам токен, а не первое слово (ДИАГНОЗ-5 E-0102).
pgb=$(grep -o 'g5_branch=[a-z]*' "$FREEZE_LOG" | tail -1 | cut -d= -f2)
pge=$(grep -o 'g5_evicted=[0-9]*' "$FREEZE_LOG" | tail -1 | cut -d= -f2)
pgs=$(grep -o 'g5_scanned=[0-9]*' "$FREEZE_LOG" | tail -1 | cut -d= -f2)
printf "PREFIX_CELL_VICTIM_SCAN_HITS=%s\n" "$p1" | tee -a "$LOG"
printf "PREFIX_CELL_SCANNED_HITS=%s\n" "$p2" | tee -a "$LOG"
printf "PREFIX_CELL_VICTIM_HITS=%s\n" "$p3" | tee -a "$LOG"
printf "PREFIX_ORACLE_PASSED=%s\n" "${pp:-NONE}" | tee -a "$LOG"
printf "PREFIX_ORACLE_FAILED=%s\n" "${pf:-NONE}" | tee -a "$LOG"
printf "PREFIX_S77_FIRST_REFUSED=%s\n" "${pfr:-NONE}" | tee -a "$LOG"
printf "PREFIX_S77_FIRST_CODE=%s\n" "${pfc:-NONE}" | tee -a "$LOG"
printf "PREFIX_S77_AFTER_FIRST_CELL=%s\n" "${pfc2:-NONE}" | tee -a "$LOG"
printf "PREFIX_S77_AFTER_FIRST_TOTAL=%s\n" "${pft:-NONE}" | tee -a "$LOG"
printf "PREFIX_S77_AFTER_FIRST_EVICTED=%s\n" "${pfe:-NONE}" | tee -a "$LOG"
printf "PREFIX_S77_SECOND_CODE=%s\n" "${psec:-NONE}" | tee -a "$LOG"
printf "PREFIX_G5_BRANCH=%s\n" "${pgb:-NONE}" | tee -a "$LOG"
printf "PREFIX_G5_EVICTED=%s\n" "${pge:-NONE}" | tee -a "$LOG"
printf "PREFIX_G5_SCANNED=%s\n" "${pgs:-NONE}" | tee -a "$LOG"

say "### носитель ### $(date +%FT%T%:z)"
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf "%s" "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then dok=1; else dok=0; fi
printf "DISK_GE_15000=%s\n" "$dok" | tee -a "$LOG"

for n in 1 2; do
  F="$OUT/facts_r$n.txt"
  {
    printf "PREFIX_CELL_VICTIM_SCAN_HITS_r%s=%s\n" "$n" "$p1"
    printf "PREFIX_CELL_SCANNED_HITS_r%s=%s\n" "$n" "$p2"
    printf "PREFIX_CELL_VICTIM_HITS_r%s=%s\n" "$n" "$p3"
    printf "PREFIX_ORACLE_PASSED_r%s=%s\n" "$n" "${pp:-NONE}"
    printf "PREFIX_ORACLE_FAILED_r%s=%s\n" "$n" "${pf:-NONE}"
    printf "PREFIX_S77_FIRST_REFUSED_r%s=%s\n" "$n" "${pfr:-NONE}"
    printf "PREFIX_S77_FIRST_CODE_r%s=%s\n" "$n" "${pfc:-NONE}"
    printf "PREFIX_S77_AFTER_FIRST_CELL_r%s=%s\n" "$n" "${pfc2:-NONE}"
    printf "PREFIX_S77_AFTER_FIRST_TOTAL_r%s=%s\n" "$n" "${pft:-NONE}"
    printf "PREFIX_S77_AFTER_FIRST_EVICTED_r%s=%s\n" "$n" "${pfe:-NONE}"
    printf "PREFIX_S77_SECOND_CODE_r%s=%s\n" "$n" "${psec:-NONE}"
    printf "PREFIX_G5_BRANCH_r%s=%s\n" "$n" "${pgb:-NONE}"
    printf "PREFIX_G5_EVICTED_r%s=%s\n" "$n" "${pge:-NONE}"
    printf "PREFIX_G5_SCANNED_r%s=%s\n" "$n" "${pgs:-NONE}"
    printf "DISK_GE_15000_r%s=%s\n" "$n" "$dok"
  } >> "$F"

  say "### ШАГ 1 оракул s77: два захода в полную ячейку, n=$n ### $(date +%FT%T%:z)"
  cargo test -p vecdht-node --test s77_cell_cap_scan -- --nocapture --test-threads=1 \
    > "$OUT/s77_r$n.txt" 2>&1
  rc=$?; note $rc
  grep -E '^test |^S77_|test result' "$OUT/s77_r$n.txt" | tail -8 | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  sp=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\1/p' "$OUT/s77_r$n.txt" | tail -1)
  sf=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\2/p' "$OUT/s77_r$n.txt" | tail -1)
  printf "S77_TESTS=%s S77_TESTS_r%s=%s\n" "$(( ${sp:-0} + ${sf:-0} ))" "$n" "$(( ${sp:-0} + ${sf:-0} ))" | tee -a "$LOG"
  printf "S77_PASSED=%s S77_PASSED_r%s=%s\n" "${sp:-NONE}" "$n" "${sp:-NONE}" | tee -a "$LOG"
  for k in FIRST_REFUSED FIRST_CODE SECOND_REFUSED SECOND_CODE CELL SHARD_TOTAL EVICTED GLOBAL_SCANNED NINES_LEFT CHEAP_REFUSED CHEAP_CODE CHEAP_EVICTED CONTROL_SCANNED_DELTA CONTROL_EVICTED_DELTA RENEW_EVICTED RENEW_CELL RENEW_TOTAL; do
    v=$(pick "S77_$k" "$OUT/s77_r$n.txt")
    printf "S77_%s=%s S77_%s_r%s=%s\n" "$k" "${v:-NONE}" "$k" "$n" "${v:-NONE}" | tee -a "$LOG"
    printf "S77_%s_r%s=%s\n" "$k" "$n" "${v:-NONE}" >> "$F"
  done
  printf "S77_TESTS_r%s=%s\n" "$n" "$(( ${sp:-0} + ${sf:-0} ))" >> "$F"
  printf "S77_PASSED_r%s=%s\n" "$n" "${sp:-NONE}" >> "$F"

  say "### ШАГ 2 счётчик окна: бюджет, курсор, обёртка, n=$n ### $(date +%FT%T%:z)"
  cargo test -p vecdht-node --test s77b_cell_cap_scan_observe -- --nocapture --test-threads=1 \
    > "$OUT/s77b_r$n.txt" 2>&1
  rc=$?; note $rc
  tail -4 "$OUT/s77b_r$n.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  bp=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\1/p' "$OUT/s77b_r$n.txt" | tail -1)
  bf=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\2/p' "$OUT/s77b_r$n.txt" | tail -1)
  printf "S77B_TESTS=%s S77B_TESTS_r%s=%s\n" "$(( ${bp:-0} + ${bf:-0} ))" "$n" "$(( ${bp:-0} + ${bf:-0} ))" | tee -a "$LOG"
  printf "S77B_PASSED=%s S77B_PASSED_r%s=%s\n" "${bp:-NONE}" "$n" "${bp:-NONE}" | tee -a "$LOG"
  for k in FIRST_SCAN SECOND_SCAN WRAP_SCAN TOTAL_SCAN BUDGET CELL EVICTED; do
    v=$(pick "S77B_$k" "$OUT/s77b_r$n.txt")
    printf "S77B_%s=%s S77B_%s_r%s=%s\n" "$k" "${v:-NONE}" "$k" "$n" "${v:-NONE}" | tee -a "$LOG"
    printf "S77B_%s_r%s=%s\n" "$k" "$n" "${v:-NONE}" >> "$F"
  done
  printf "S77B_TESTS_r%s=%s\n" "$n" "$(( ${bp:-0} + ${bf:-0} ))" >> "$F"
  printf "S77B_PASSED_r%s=%s\n" "$n" "${bp:-NONE}" >> "$F"

  say "### ШАГ 3 полноразмерный случай E-0088: live=34 286, предел 4286, n=$n ### $(date +%FT%T%:z)"
  # Полное имя теста, а не префикс: `--exact` с усечённым именем отобрал бы ноль тестов, и
  # шаг зеленел бы на пустоте (тот же класс, что «молчание = провал»).
  cargo test -p vecdht-node --test s14_cell_cap_enforced \
    above_the_floor_the_cap_is_the_mean_and_not_a_constant -- --exact --nocapture \
    > "$OUT/s14_r$n.txt" 2>&1
  rc=$?; note $rc
  grep -E '^test |MERE g5_|test result' "$OUT/s14_r$n.txt" | tail -5 | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  gp=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\1/p' "$OUT/s14_r$n.txt" | tail -1)
  gf=$(sed -n 's/^test result: .* \([0-9]*\) passed; \([0-9]*\) failed;.*/\2/p' "$OUT/s14_r$n.txt" | tail -1)
  printf "S14_G5_TESTS=%s S14_G5_TESTS_r%s=%s\n" "$(( ${gp:-0} + ${gf:-0} ))" "$n" "$(( ${gp:-0} + ${gf:-0} ))" | tee -a "$LOG"
  printf "S14_G5_PASSED=%s S14_G5_PASSED_r%s=%s\n" "${gp:-NONE}" "$n" "${gp:-NONE}" | tee -a "$LOG"
  # Ключи печатаются литерально, а не шаблоном `S14_G5_%s`: иначе threshold-lint не видит
  # прибора («порог без прибора»), а `pick` по верхнему регистру молча берёт NONE — гейт s14
  # печатает `g5_branch=` строчными. Оба дефекта первого прогона E-0102, найдены машиной.
  vb=$(pick "g5_branch" "$OUT/s14_r$n.txt")
  vr=$(pick "g5_refused" "$OUT/s14_r$n.txt")
  ve=$(pick "g5_evicted" "$OUT/s14_r$n.txt")
  vs=$(pick "g5_scanned" "$OUT/s14_r$n.txt")
  vc=$(pick "g5_cell" "$OUT/s14_r$n.txt")
  vl=$(pick "g5_live" "$OUT/s14_r$n.txt")
  vm=$(pick "g5_limit" "$OUT/s14_r$n.txt")
  printf "S14_G5_BRANCH=%s S14_G5_BRANCH_r%s=%s\n" "${vb:-NONE}" "$n" "${vb:-NONE}" | tee -a "$LOG"
  printf "S14_G5_REFUSED=%s S14_G5_REFUSED_r%s=%s\n" "${vr:-NONE}" "$n" "${vr:-NONE}" | tee -a "$LOG"
  printf "S14_G5_EVICTED=%s S14_G5_EVICTED_r%s=%s\n" "${ve:-NONE}" "$n" "${ve:-NONE}" | tee -a "$LOG"
  printf "S14_G5_SCANNED=%s S14_G5_SCANNED_r%s=%s\n" "${vs:-NONE}" "$n" "${vs:-NONE}" | tee -a "$LOG"
  printf "S14_G5_CELL=%s S14_G5_CELL_r%s=%s\n" "${vc:-NONE}" "$n" "${vc:-NONE}" | tee -a "$LOG"
  printf "S14_G5_LIVE=%s S14_G5_LIVE_r%s=%s\n" "${vl:-NONE}" "$n" "${vl:-NONE}" | tee -a "$LOG"
  printf "S14_G5_LIMIT=%s S14_G5_LIMIT_r%s=%s\n" "${vm:-NONE}" "$n" "${vm:-NONE}" | tee -a "$LOG"
  {
    printf "S14_G5_BRANCH_r%s=%s\n" "$n" "${vb:-NONE}"
    printf "S14_G5_REFUSED_r%s=%s\n" "$n" "${vr:-NONE}"
    printf "S14_G5_EVICTED_r%s=%s\n" "$n" "${ve:-NONE}"
    printf "S14_G5_SCANNED_r%s=%s\n" "$n" "${vs:-NONE}"
    printf "S14_G5_CELL_r%s=%s\n" "$n" "${vc:-NONE}"
    printf "S14_G5_LIVE_r%s=%s\n" "$n" "${vl:-NONE}"
    printf "S14_G5_LIMIT_r%s=%s\n" "$n" "${vm:-NONE}"
  } >> "$F"
  printf "S14_G5_TESTS_r%s=%s\n" "$n" "$(( ${gp:-0} + ${gf:-0} ))" >> "$F"
  printf "S14_G5_PASSED_r%s=%s\n" "$n" "${gp:-NONE}" >> "$F"

  say "### ШАГ 4 gate H-0102 и audit -n 5, n=$n ### $(date +%FT%T%:z)"
  python lab/cycle-gate.py gate H-0102 --skip-lean > "$OUT/gate_r$n.txt" 2>&1
  rc=$?; note $rc
  tail -4 "$OUT/gate_r$n.txt" | sed 's/^/    /' | tee -a "$LOG" >/dev/null
  gok=$(grep -c "CYCLE H-0102=OK" "$OUT/gate_r$n.txt" || true)
  printf "GATE_H0102_OK=%s GATE_H0102_OK_r%s=%s\n" "$gok" "$n" "$gok" | tee -a "$LOG"
  python lab/cycle-gate.py audit -n 5 > "$OUT/audit_r$n.txt" 2>&1
  rc=$?; note $rc
  viol=$(grep -c "НАРУШЕНИЯ" "$OUT/audit_r$n.txt" || true)
  cards=$(sed -n 's/^AUDIT карточек=\([0-9]*\).*/\1/p' "$OUT/audit_r$n.txt")
  printf "AUDIT_VIOLATIONS=%s AUDIT_VIOLATIONS_r%s=%s\n" "$viol" "$n" "$viol" | tee -a "$LOG"
  printf "AUDIT_CARDS=%s AUDIT_CARDS_r%s=%s\n" "${cards:-NONE}" "$n" "${cards:-NONE}" | tee -a "$LOG"
  {
    printf "GATE_H0102_OK_r%s=%s\n" "$n" "$gok"
    printf "AUDIT_VIOLATIONS_r%s=%s\n" "$n" "$viol"
    printf "AUDIT_CARDS_r%s=%s\n" "$n" "${cards:-NONE}"
  } >> "$F"
done

say "### ШАГ 5 воспроизводимость вектора ### $(date +%FT%T%:z)"
python lab/facts.py repro "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" --strip-run > "$OUT/repro.txt" 2>&1
rc=$?; note $rc
tail -4 "$OUT/repro.txt" | tee -a "$LOG"
rv=$(sed -n 's/^REPRO_VECTOR=//p' "$OUT/repro.txt" | tail -1)
printf "REPRO_VECTOR=%s\n" "${rv:-NONE}" | tee -a "$LOG"
for f in 1 2; do printf "REPRO_VECTOR_r%s=%s\n" "$f" "${rv:-NONE}" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 6 верификация воркспейса ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0102 >/dev/null 2>&1
rc=$?; printf "VERIFY_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc
for f in 1 2; do printf "VERIFY_EXIT_r%s=%s\n" "$f" "$rc" >> "$OUT/facts_r$f.txt"; done
VLOG="lab/logs/workspace-verify-2026-10-22.log"
start=$(grep -n "########## E-0102 · workspace-verify" "$VLOG" | tail -1 | cut -d: -f1)
if [ -n "$start" ]; then
  tail -n +"$start" "$VLOG" > "$OUT/verify_block.txt"
  if grep -q "s77_cell_cap_scan" "$OUT/verify_block.txt" \
     && grep -q "test result: ok. 2 passed" "$OUT/verify_block.txt"; then vin=1; else vin=0; fi
  if grep -q "s77b_cell_cap_scan_observe" "$OUT/verify_block.txt" \
     && grep -q "test result: ok. 1 passed" "$OUT/verify_block.txt"; then bin=1; else bin=0; fi
else
  vin=0; bin=0
fi
printf "S77_IN_VERIFY=%s\n" "$vin" | tee -a "$LOG"
printf "S77B_IN_VERIFY=%s\n" "$bin" | tee -a "$LOG"
for f in 1 2; do
  printf "S77_IN_VERIFY_r%s=%s\n" "$f" "$vin" >> "$OUT/facts_r$f.txt"
  printf "S77B_IN_VERIFY_r%s=%s\n" "$f" "$bin" >> "$OUT/facts_r$f.txt"
done

say "### ШАГ 7 стража текста ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh \
  crates/vecdht-node/src/admission.rs \
  crates/vecdht-node/src/node.rs \
  crates/vecdht-node/tests/s77_cell_cap_scan.rs \
  crates/vecdht-node/tests/s77b_cell_cap_scan_observe.rs \
  lab/hypotheses/H-0102-cell-cap-scan-victim.md \
  lab/experiments/E-0102-cell-cap-scan-victim.md \
  lab/expectations/e0102.tsv lab/e0102-run.sh 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note $rc
dirty=$(sed -n 's/.*файлов_с_грязью=\([0-9]*\).*/\1/p' "$LOG" | tail -1)
printf "TEXT_DIRTY_FILES=%s\n" "${dirty:-NONE}" | tee -a "$LOG"
for f in 1 2; do printf "TEXT_DIRTY_FILES_r%s=%s\n" "$f" "${dirty:-NONE}" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 8 СВЕРКА: lab/expectations/e0102.tsv против напечатанных фактов ###"
# shellcheck source=lab/runlib.sh
source lab/runlib.sh
strip_run "$OUT/facts_r1.txt" > "$OUT/f1.txt"
strip_run "$OUT/facts_r2.txt" > "$OUT/f2.txt"
python lab/expect.py lab/expectations/e0102.tsv "$OUT/f1.txt" "$OUT/f2.txt" 2>&1 | tail -6 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
