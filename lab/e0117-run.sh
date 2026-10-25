#!/usr/bin/env bash
# К0 / E-0117 (docs-цикл): закрытие `E-0114` переносится в спеку v9 словами носителя.
#
# Что мерится. Три вставки в спеку (§V9.7 — порядок шагов и таблица доверия; §V9.9 — таблица
# ролей; §V9.10 — строки OPEN-V9-11…21) обязаны быть **невидимы прибору**: мост
# `lab/v9-payout-bridge.py` на старой и новой спеке обязан напечатать один и тот же набор фактов
# байт в байт. Это сильнее, чем «прибор остался зелёным»: зелёный `V9C_ALL_OK=1` мог бы стоять и
# там, где вставка молча увела разбор в другую ветку.
#
# Почему не повтор `lab/e0114-run.sh`: у него заморожены `PREV_SPEC_SHA=102fc694…` и ожидание
# `V9C_SPEC_SHA_UNCHANGED=1` («спека не изменилась за время прогона»). Правка спеки делает второй
# факт нулём по построению, а его таблица ожиданий (164 ключа) заморожена и не правится
# (`docs/PLAN-v1.md`, ловушка 4). Поэтому baseline берётся не из лога, а из того же дерева:
# `git show HEAD:<спека>` — текст эпохи `E-0114` (до этой правки), на нём прибор гоняется тем же
# вызовом.
#
# Порог: `K0_TRANSFER_DIFF=0` — ни одна строка фактов `V9C_|V9P_` не отличается между старой и
# новой спекой; `K0_OLD_SPEC_IS_E0114=1` — старый текст действительно тот, на котором закрыт
# `E-0114`; `K0_SPEC_CHANGED=1` — новый текст отличается; `V9C_ALL_OK=1` на обоих текстах,
# `VECTOR_STABLE=1` внутри каждой пары прогонов, `XCHECK_EXIT=0`, стража текста 0.
#
# Шаги: (0) гейт и носитель до; (1) четыре прогона моста (старая ×2, новая ×2); (2) сверка
# наборов, пины sha, стабильность; (3) `xcheck-paid-orders.py`; (4) стража текста; (5) ожидания;
# (6) носитель после.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG=lab/logs/e0117-all.log
DOC=docs/PAID_PAYOUT-VECTORS.md
SPEC=docs/VecDHT-SPEC-v9.md
ODOC=docs/PAID_ORDER-VECTORS.md
NOTE=lab/notes/DESIGN-2026-10-25-chain-binding.md
BRIDGE=lab/v9-payout-bridge.py
PREV_SPEC_SHA=102fc69418f783a46bf397faea373b64c371a3382eab6c35f2910c31d3b532b7
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0117.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
G="$OUT/facts_global.txt"
: > "$G"
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
pick() { grep -o "$1=[A-Za-z0-9_.:/=,%|-]*" "$2" | tail -1 | cut -d= -f2-; }
facts() { grep -oE '^(V9C|V9P)_[A-Z0-9_]+=.*' "$1" | sort -u; }

say "########## E-0117 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 гейт и носитель до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0117 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
emit0 "GATE_H0117_OK=${gok}"
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

# Текст эпохи E-0114: тот же файл из HEAD (правка спеки в этой эпохе не закоммичена).
git show "HEAD:${SPEC}" > "$OUT/spec_prev.md"
old_sha=$(sha256sum "$OUT/spec_prev.md" | cut -d' ' -f1)
new_sha=$(sha256sum "$SPEC" | cut -d' ' -f1)
say "K0_OLD_SPEC_SHA=${old_sha}"
say "K0_SPEC_SHA=${new_sha}"

say "### ШАГ 1 четыре прогона моста: старая спека ×2, новая ×2 ### $(date +%FT%T%:z)"
for v in prev new; do
  if [ "$v" = prev ]; then SPECARG="$OUT/spec_prev.md"; else SPECARG="$SPEC"; fi
  for f in 1 2; do
    FACTS="$OUT/facts_${v}${f}.txt"
    : > "$FACTS"
    V9C_VERBOSE=1 python "$BRIDGE" "$DOC" "$SPECARG" "$ODOC" "$NOTE" > "$OUT/cli_${v}${f}.txt" 2>&1
    rcc=$?
    note "$rcc"
    say "BRIDGE_${v}${f}_EXIT=${rcc}"
    emit "E0117_BRIDGE_EXIT=${rcc}"
    emit "V9C_ALL_OK=$(pick V9C_ALL_OK "$OUT/cli_${v}${f}.txt")"
    emit "V9C_WORST=$(pick V9C_WORST "$OUT/cli_${v}${f}.txt")"
    emit "V9C_TERM_EQ_GOT=$(pick V9C_TERM_EQ_GOT "$OUT/cli_${v}${f}.txt")"
    emit "V9C_MIRROR_MATCH=$(pick V9C_MIRROR_MATCH "$OUT/cli_${v}${f}.txt")"
    emit "V9C_CLAIM_EQ_GOT=$(pick V9C_CLAIM_EQ_GOT "$OUT/cli_${v}${f}.txt")"
    emit "V9C_SIGNATURES_CHECKED=$(pick V9C_SIGNATURES_CHECKED "$OUT/cli_${v}${f}.txt")"
    emit "V9C_DOMAIN_ROWS_GOT=$(pick V9C_DOMAIN_ROWS_GOT "$OUT/cli_${v}${f}.txt")"
    emit "V9C_STEP_ROWS_GOT=$(pick V9C_STEP_ROWS_GOT "$OUT/cli_${v}${f}.txt")"
    emit "V9C_CODES_EQ_SPEC=$(pick V9C_CODES_EQ_SPEC "$OUT/cli_${v}${f}.txt")"
    emit "V9C_CODES_USED_MINE=$(pick V9C_CODES_USED_MINE "$OUT/cli_${v}${f}.txt")"
    emit "V9C_REGISTRY_ROWS_GOT=$(pick V9C_REGISTRY_ROWS_GOT "$OUT/cli_${v}${f}.txt")"
    emit "V9C_REGISTRY_ROOT=$(pick V9C_REGISTRY_ROOT "$OUT/cli_${v}${f}.txt")"
    emit "V9C_V01_ORDER_REF=$(pick V9C_V01_ORDER_REF "$OUT/cli_${v}${f}.txt")"
    emit "V9C_KEYPAIR_MATCH=$(pick V9C_KEYPAIR_MATCH "$OUT/cli_${v}${f}.txt")"
    emit "V9C_DOUBLE_REPLAY_COUNT=$(pick V9C_DOUBLE_REPLAY_COUNT "$OUT/cli_${v}${f}.txt")"
    emit "V9C_INDEP_MATCH=$(pick V9C_INDEP_MATCH "$OUT/cli_${v}${f}.txt")"
  done
done

say "### ШАГ 2 набор фактов: старая против новой ### $(date +%FT%T%:z)"
facts "$OUT/cli_prev1.txt" > "$OUT/prev.norm"
facts "$OUT/cli_new1.txt" > "$OUT/new.norm"
diff -u "$OUT/prev.norm" "$OUT/new.norm" > "$OUT/transfer.diff" 2>&1
if [ -s "$OUT/transfer.diff" ]; then tdiff=$(grep -c '^[+-][^+-]' "$OUT/transfer.diff"); else tdiff=0; fi
say "K0_BASELINE_KEYS=$(wc -l < "$OUT/prev.norm") K0_NEW_KEYS=$(wc -l < "$OUT/new.norm") K0_TRANSFER_DIFF=${tdiff}"
if [ "$tdiff" -ne 0 ]; then
  say "ВСТАВКА ИЗМЕНИЛА ФАКТЫ ПРИБОРА:"
  sed -n '1,40p' "$OUT/transfer.diff" | tee -a "$LOG"
fi
if [ "$old_sha" = "$PREV_SPEC_SHA" ]; then oldpin=1; else oldpin=0; fi
if [ "$new_sha" != "$PREV_SPEC_SHA" ]; then specch=1; else specch=0; fi
say "K0_OLD_SPEC_IS_E0114=${oldpin} K0_SPEC_CHANGED=${specch}"
emit0 "K0_BASELINE_KEYS=$(wc -l < "$OUT/prev.norm")"
emit0 "K0_NEW_KEYS=$(wc -l < "$OUT/new.norm")"
emit0 "K0_TRANSFER_DIFF=${tdiff}"
emit0 "K0_OLD_SPEC_IS_E0114=${oldpin}"
emit0 "K0_SPEC_SHA=${new_sha}"
emit0 "K0_SPEC_CHANGED=${specch}"
[ "$tdiff" -eq 0 ] || note 1
[ "$oldpin" -eq 1 ] || note 1
[ "$specch" -eq 1 ] || note 1

if diff -q "$OUT/facts_prev1.txt" "$OUT/facts_prev2.txt" >/dev/null 2>&1; then sp=1; else sp=0; fi
if diff -q "$OUT/facts_new1.txt" "$OUT/facts_new2.txt" >/dev/null 2>&1; then sn=1; else sn=0; fi
if [ "$sp" -eq 1 ] && [ "$sn" -eq 1 ]; then stable=1; else stable=0; fi
emit0 "VECTOR_STABLE=${stable}"
say "VECTOR_STABLE=${stable} (старая пара ${sp}, новая пара ${sn})"
[ "$stable" -eq 1 ] || note 1

say "### ШАГ 3 сверка матрицы §V9.6 против порождённого носителя ### $(date +%FT%T%:z)"
python lab/xcheck-paid-orders.py > "$OUT/xcheck.txt" 2>&1
rcx=$?
note "$rcx"
tail -n 6 "$OUT/xcheck.txt" | tee -a "$LOG"
emit0 "XCHECK_EXIT=${rcx}"

say "### ШАГ 4 стража текста ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh "$SPEC" lab/e0117-run.sh lab/expectations/e0117.tsv \
  lab/hypotheses/H-0117-k0-spec-transfer.md \
  lab/experiments/E-0117-k0-spec-transfer.md 2>&1 | tail -3 | tee -a "$LOG"
rct=${PIPESTATUS[0]}
note "$rct"
emit0 "TEXTGUARD_CYCLE_EXIT=${rct}"

say "### ШАГ 5 ожидания ### $(date +%FT%T%:z)"
for f in "$OUT/facts_prev1.txt" "$OUT/facts_prev2.txt" "$OUT/facts_new1.txt" "$OUT/facts_new2.txt"; do
  cat "$G" >> "$f"
done
python lab/expect.py lab/expectations/e0117.tsv \
  "$OUT/facts_prev1.txt" "$OUT/facts_prev2.txt" \
  "$OUT/facts_new1.txt" "$OUT/facts_new2.txt" 2>&1 | tail -n 20 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
note $rc

say "### ШАГ 6 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
