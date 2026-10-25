#!/usr/bin/env bash
# E-0105: стенд P1 — 200 узлов, 64 ключа — H-0105.
#
# Два прибора:
#   `crates/vecdht-net/tests/kad_server_role.rs` — debug, 3 узла, один мост: роль kad-сервера;
#   `crates/vecdht-net/tests/s182_p1_scale.rs`  — release, 200 узлов, 192 холодных резолва.
#
# Профили разные намеренно: роль не зависит от криптоскорости и проверяется в debug; гейт p95
# написан про боевой бинарь, и в debug он мерил бы не тот профиль (60 узлов в debug дают 0/8).
#
# Шаги:
#   (0) gate ДО замерного helper'а (правило AGENTS.md п. 11) и носитель: диск/RAM/pagefile;
#   (1) два прогона обоих приборов на неизменном дереве, литеральные `KADROLE_*`/`P1_*`;
#   (2) PRE_FIX из исполненного лога `lab/logs/e0105-prefix.log`;
#   (3) `audit -n 5`;
#   (4) `workspace-verify.sh E-0105`;
#   (5) стража текста и сверка `lab/expectations/e0105.tsv`;
#   (6) носитель после прогона.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0105-all.log"
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0105.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
FACTS=""
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
# Литеральная печать: линт порогов видит `KEY=` в источнике, а не шаблон с переменной.
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
pick() { grep -o "$1=[A-Za-z0-9_.:/=,%|-]*" "$2" | tail -1 | cut -d= -f2-; }

say "########## E-0105 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 gate и носитель ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0105 --skip-lean 2>&1 | tail -n 8 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
printf "GATE_H0105_OK=%s\n" "$gok" | tee -a "$LOG"
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

say "### ШАГ 1 два прогона, оба прибора ### $(date +%FT%T%:z)"
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  : > "$FACTS"
  cargo test -q -p vecdht-net --test kad_server_role -- --nocapture \
    > "$OUT/role$f.txt" 2>&1
  rc1=$?
  cargo test --release -q -p vecdht-net --test s182_p1_scale -- --ignored --nocapture \
    > "$OUT/p1$f.txt" 2>&1
  rc2=$?
  note "$rc1"; note "$rc2"
  grep -E "KADROLE_|test result" "$OUT/role$f.txt" | tail -n 3 | tee -a "$LOG"
  grep -E "P1_|test result" "$OUT/p1$f.txt" | tail -n 8 | tee -a "$LOG"
  if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ]; then measured=1; else measured=0; fi
  kfound=$(pick KADROLE_FOUND "$OUT/role$f.txt")
  kaa=$(pick KADROLE_A_AUTH "$OUT/role$f.txt")
  kba=$(pick KADROLE_B_AUTH "$OUT/role$f.txt")
  kca=$(pick KADROLE_C_AUTH "$OUT/role$f.txt")
  psamples=$(pick P1_SAMPLES "$OUT/p1$f.txt")
  pres=$(pick P1_RESOLVED "$OUT/p1$f.txt")
  pmiss=$(pick P1_MISS "$OUT/p1$f.txt")
  paz=$(pick P1_AUTH_ZERO "$OUT/p1$f.txt")
  pkz=$(pick P1_KAD_ZERO "$OUT/p1$f.txt")
  p95=$(pick P1_P95_MS "$OUT/p1$f.txt")
  p50=$(pick P1_P50_MS "$OUT/p1$f.txt")
  pmax=$(pick P1_MAX_MS "$OUT/p1$f.txt")
  perrs=$(pick P1_ERRORS "$OUT/p1$f.txt")
  say "прогон $f: KADROLE=$kfound p50=$p50 p95=$p95 max=$pmax errors=$perrs"
  if [ "${p95:-999999}" -lt 500 ]; then punder=1; else punder=0; fi
  emit "E0105_MEASURED=${measured}"
  emit "KADROLE_FOUND=${kfound:-NONE}"
  emit "KADROLE_A_AUTH=${kaa:-NONE}"
  emit "KADROLE_B_AUTH=${kba:-NONE}"
  emit "KADROLE_C_AUTH=${kca:-NONE}"
  emit "P1_SAMPLES=${psamples:-NONE}"
  emit "P1_RESOLVED=${pres:-NONE}"
  emit "P1_MISS=${pmiss:-NONE}"
  emit "P1_AUTH_ZERO=${paz:-NONE}"
  emit "P1_KAD_ZERO=${pkz:-NONE}"
  emit "P1_P95_UNDER_500=${punder}"
done

say "### ШАГ 2 PRE_FIX (исполненный) ### $(date +%FT%T%:z)"
pre=$(grep -o "KADROLE_FOUND=[0-9]*" lab/logs/e0105-prefix.log | tail -1 | cut -d= -f2)
say "PRE_FIX на строке is_server = !nodes.is_empty(): KADROLE_FOUND=${pre:-NONE}"
for f in 1 2; do printf "KADROLE_PRE_FIX_FOUND=%s\n" "${pre:-NONE}" >> "$OUT/facts_r$f.txt"; done
FACTS=/dev/null

if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable2=1; else stable2=0; fi
printf "VECTOR_STABLE=%s\n" "$stable2" | tee -a "$LOG"
for f in 1 2; do printf "VECTOR_STABLE=%s\n" "$stable2" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 3 audit ### $(date +%FT%T%:z)"
python lab/cycle-gate.py audit -n 5 > "$OUT/audit.txt" 2>&1
rc=$?; note "$rc"
tail -n 3 "$OUT/audit.txt" | tee -a "$LOG"
aud=$(sed -n 's/.*нарушени[^=]*=\([0-9]*\).*/\1/p' "$OUT/audit.txt" | tail -1)
printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" | tee -a "$LOG"

say "### ШАГ 4 полная верификация ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0105 2>&1 | tail -n 12 | tee -a "$LOG"
vrc=${PIPESTATUS[0]}
printf "VERIFY_EXIT=%s\n" "$vrc" | tee -a "$LOG"
note "$vrc"

# Ключ, который сводит два прогона, обязан быть в логе: пересборка фактов из append-only лога
# иначе теряет ожидание, которое на прогоне выполнено (Поправка 5). Печатается один раз на блок.
say "E0105_RUNS=2"
for f in 1 2; do
  printf "GATE_H0105_OK=%s\n" "$gok" >> "$OUT/facts_r$f.txt"
  printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "VERIFY_EXIT=%s\n" "$vrc" >> "$OUT/facts_r$f.txt"
  printf "E0105_RUNS=2\n" >> "$OUT/facts_r$f.txt"
  printf "DISK_GE_15000=%s\n" "$dok" >> "$OUT/facts_r$f.txt"
done

say "### ШАГ 5 стража текста и сверка ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh \
  crates/vecdht-net/src/service.rs \
  crates/vecdht-net/tests/kad_server_role.rs \
  crates/vecdht-net/tests/s182_p1_scale.rs \
  lab/hypotheses/H-0105-p1-scale.md \
  lab/experiments/E-0105-p1-scale.md \
  lab/decisions/ADR-0060-kad-server-role.md \
  lab/expectations/e0105.tsv lab/e0105-run.sh 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; note $rc

python lab/expect.py lab/expectations/e0105.tsv "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" 2>&1 | tail -n 8 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "### ШАГ 6 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "### ШАГ 6b баланс цикла (lab/ledger.py) ### $(date +%FT%T%:z)"
# Берём последний блок верификации целиком: баланс считается по факту прогона, а не по sums
# за весь append-only лог (иначе два сорванных блока задним числом удорожают закрытый цикл).
VLOG=lab/logs/workspace-verify-2026-10-22.log
awk 'NR==FNR{if (/^########## /) last=FNR; next} FNR>last' "$VLOG" "$VLOG" > "$OUT/verify-last-block.txt"
python lab/ledger.py report "$LOG" "$OUT/verify-last-block.txt" 2>&1 | tail -n 22 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; printf "LEDGER_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
