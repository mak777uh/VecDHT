#!/usr/bin/env bash
# E-0113 (приёмочный тест пакета v9): сторонний реализатор обязан собрать байтовые правила только
# из текста спеки и порождённого документа векторов, не читая `crates/` (H-0113, `ADR-0063`).
#
# Прибор: `lab/v9-independent-client.py` — чужая реализация (`hashlib`, свой Ed25519 из текста
# `RFC 8032`), у которой два входа: `docs/VecDHT-SPEC-v9.md` и `docs/PAID_ORDER-VECTORS.md`.
# Раскладка берётся из текста: длина домена — из напечатанной строки таблицы, порядок и ширины
# полей — из §V9.2 в её печатном виде, терминатор `0x00` ставится только там, где о нём в колонке
# кодировки буквально написано. Если спека соврёт или не напечатает вход, пересборка разойдётся с
# носителем, и прибор покраснеет; подправить текст под красивые числа он не позволит.
#
# PRE_FIX-замер исполнен до коммита пре-регистрации (дерево `e22511d`, выход 1):
# `V913_DOMAIN_DECLARED_BYTES=19` против `V913_DOMAIN_ROW_BYTES=20`, `V913_DOMAIN_LEN_OK=0`,
# `V913_RECORD_LEN_EQ=0` и `V913_RECORD_EQ_DOC=0` при 215 собранных байтах против 217 напечатанных,
# `V913_ORDER_REF_EQ=0`, `V913_ORDER_SIGNATURE_VALID=0`, `V913_FILESET_INPUTS_PRINTED=0`,
# `V913_WORST=1`, `V913_ALL_OK=0`; при этом `V913_ORDER_SIG_OVER_PRINTED=1` и
# `V913_ORDER_REF_OVER_PRINTED=1` — то есть носитель самосогасован, а расходится именно текст.
# Полный снимок — `lab/logs/e0113-prefix.log` (79 фактов на прогон, `VECTOR_STABLE=1`), хеши входов
# того же дерева: спека `0498855d1a1e8a2e…ca1be057`, документ `5d60cfc57c6a34f9…d2c56667`,
# прибор `5eb2d56d478966ee…59553966`.
#
# Правка ожидает две: (1) §V9.2 — длина домена и два терминатора (`kind`, `reward.asset`), верстка
# строки 12; (2) генератор векторов — печатает пары «путь + sha256 содержимого», без которых листья
# множества файлов не вычисляются. Байты продукта не меняются: `V9_ORDER_REF`, `V9_ARTIFACT_ROOT`,
# `V9_SUBMISSION_REF`, три хеша канонизации и `V913_RECEIPT_SIGNED_LEN=697` обязаны остаться теми же.
#
# Шаги:
#   (0) gate ДО прогона и носитель: диск/RAM/pagefile;
#   (1) два прогона прибора на неизменном дереве, литеральные `V913_*`;
#   (2) генератор векторов на том же дереве: `V9_*`-инварианты и sha против замороженного прежнего;
#   (3) независимая сверка векторов и матрицы (`lab/xcheck-paid-orders.py`);
#   (4) `audit -n 5`;
#   (5) `workspace-verify.sh E-0113`;
#   (6) стража текста по файлам цикла и сверка `lab/expectations/e0113.tsv`;
#   (7) носитель после прогона и баланс цикла (`lab/ledger.py`).
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0113-all.log"
DOC=docs/PAID_ORDER-VECTORS.md
SPEC=docs/VecDHT-SPEC-v9.md
CLIENT=lab/v9-independent-client.py
# Прежние sha носителя и спеки переписаны СЮДА до правки (они же — в пре-регистрации и в
# `lab/logs/e0113-prefix.log`): ожидание «носитель изменился, спека изменилась» проверяется
# сравнением с этими константами, а не с памятью о том, что было раньше.
PREV_DOC_SHA=5d60cfc57c6a34f9e9fc5dea0dfaace87f3a3f8bd7ffe5b3e9deed7dd2c56667
PREV_SPEC_SHA=0498855d1a1e8a2e5a2814cbe872a13f53b1552becb1d056c2375525ca1be057
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0113.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
pick() { grep -o "$1=[A-Za-z0-9_.:/=,%|-]*" "$2" | tail -1 | cut -d= -f2-; }

say "########## E-0113 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 gate и носитель ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0113 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
printf "GATE_H0113_OK=%s\n" "$gok" | tee -a "$LOG"
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

say "### ШАГ 1 два прогона стороннего реализатора ### $(date +%FT%T%:z)"
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  : > "$FACTS"
  V913_VERBOSE=1 python "$CLIENT" "$DOC" "$SPEC" > "$OUT/cli$f.txt" 2>&1
  rcc=$?
  note "$rcc"
  grep -E '^V913_|^  # ' "$OUT/cli$f.txt" | tee -a "$LOG"
  emit "E0113_CLIENT_EXIT=${rcc}"
  # Литеральная печать каждого ключа: линт порогов требует, чтобы `V913_KEY=` стоял в
  # источнике буквой, а не собирался шаблоном с переменной (иначе ожидание может быть
  # выписано против факта, которого прибор не печатает).
  emit "V913_TOOLCHAIN=$(pick "V913_TOOLCHAIN" "$OUT/cli$f.txt")"
  emit "V913_UNICODE_DATA=$(pick "V913_UNICODE_DATA" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_ORDER_READ=$(pick "V913_DOMAIN_ORDER_READ" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_FILESET_READ=$(pick "V913_DOMAIN_FILESET_READ" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_RECEIPT_READ=$(pick "V913_DOMAIN_RECEIPT_READ" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_ORDER_BYTES=$(pick "V913_DOMAIN_ORDER_BYTES" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_FILESET_BYTES=$(pick "V913_DOMAIN_FILESET_BYTES" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_RECEIPT_BYTES=$(pick "V913_DOMAIN_RECEIPT_BYTES" "$OUT/cli$f.txt")"
  emit "V913_KIND_TAGS_READ=$(pick "V913_KIND_TAGS_READ" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_DECLARED_BYTES=$(pick "V913_DOMAIN_DECLARED_BYTES" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_ROW_BYTES=$(pick "V913_DOMAIN_ROW_BYTES" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_LEN_OK=$(pick "V913_DOMAIN_LEN_OK" "$OUT/cli$f.txt")"
  emit "V913_DOMAIN_ROW_VS_FORMULA_EQ=$(pick "V913_DOMAIN_ROW_VS_FORMULA_EQ" "$OUT/cli$f.txt")"
  emit "V913_STATEMENT_FORMULA_TOKENS=$(pick "V913_STATEMENT_FORMULA_TOKENS" "$OUT/cli$f.txt")"
  emit "V913_W1_NORM_EQ=$(pick "V913_W1_NORM_EQ" "$OUT/cli$f.txt")"
  emit "V913_W1_HASH_EQ=$(pick "V913_W1_HASH_EQ" "$OUT/cli$f.txt")"
  emit "V913_W2_NORM_EQ=$(pick "V913_W2_NORM_EQ" "$OUT/cli$f.txt")"
  emit "V913_W2_HASH_EQ=$(pick "V913_W2_HASH_EQ" "$OUT/cli$f.txt")"
  emit "V913_W3_NORM_EQ=$(pick "V913_W3_NORM_EQ" "$OUT/cli$f.txt")"
  emit "V913_W3_HASH_EQ=$(pick "V913_W3_HASH_EQ" "$OUT/cli$f.txt")"
  emit "V913_EXAMPLES=$(pick "V913_EXAMPLES" "$OUT/cli$f.txt")"
  emit "V913_EXAMPLE_HASHES=$(pick "V913_EXAMPLE_HASHES" "$OUT/cli$f.txt")"
  emit "V913_NFC_UNICODE_VERSION=$(pick "V913_NFC_UNICODE_VERSION" "$OUT/cli$f.txt")"
  emit "V913_FIELDS_PARSED=$(pick "V913_FIELDS_PARSED" "$OUT/cli$f.txt")"
  emit "V913_INPUTS_MISSING=$(pick "V913_INPUTS_MISSING" "$OUT/cli$f.txt")"
  emit "V913_RECORD_REBUILT_LEN=$(pick "V913_RECORD_REBUILT_LEN" "$OUT/cli$f.txt")"
  emit "V913_RECORD_PRINTED_LEN=$(pick "V913_RECORD_PRINTED_LEN" "$OUT/cli$f.txt")"
  emit "V913_RECORD_LEN_EQ=$(pick "V913_RECORD_LEN_EQ" "$OUT/cli$f.txt")"
  emit "V913_RECORD_EQ_DOC=$(pick "V913_RECORD_EQ_DOC" "$OUT/cli$f.txt")"
  emit "V913_ORDER_REF_EQ=$(pick "V913_ORDER_REF_EQ" "$OUT/cli$f.txt")"
  emit "V913_ORDER_REF_OVER_PRINTED=$(pick "V913_ORDER_REF_OVER_PRINTED" "$OUT/cli$f.txt")"
  emit "V913_KEYPAIR_LAYOUT_WORDS=$(pick "V913_KEYPAIR_LAYOUT_WORDS" "$OUT/cli$f.txt")"
  emit "V913_KEYPAIR_CONVENTION_PRINTED=$(pick "V913_KEYPAIR_CONVENTION_PRINTED" "$OUT/cli$f.txt")"
  emit "V913_PUBKEY_PUBLISHER_EQ=$(pick "V913_PUBKEY_PUBLISHER_EQ" "$OUT/cli$f.txt")"
  emit "V913_ORDER_SIGNATURE_VALID=$(pick "V913_ORDER_SIGNATURE_VALID" "$OUT/cli$f.txt")"
  emit "V913_ORDER_SIGNATURE_DECOY=$(pick "V913_ORDER_SIGNATURE_DECOY" "$OUT/cli$f.txt")"
  emit "V913_ORDER_SIG_OVER_PRINTED=$(pick "V913_ORDER_SIG_OVER_PRINTED" "$OUT/cli$f.txt")"
  emit "V913_SUBMISSION_FORMULA_TOKENS=$(pick "V913_SUBMISSION_FORMULA_TOKENS" "$OUT/cli$f.txt")"
  emit "V913_SUBMISSION_WIDTHS_READ=$(pick "V913_SUBMISSION_WIDTHS_READ" "$OUT/cli$f.txt")"
  emit "V913_SUBMISSION_BYTES_PRINTED=$(pick "V913_SUBMISSION_BYTES_PRINTED" "$OUT/cli$f.txt")"
  emit "V913_SUBMISSION_TAIL_OK=$(pick "V913_SUBMISSION_TAIL_OK" "$OUT/cli$f.txt")"
  emit "V913_SUBMISSION_ROUNDTRIP_EQ=$(pick "V913_SUBMISSION_ROUNDTRIP_EQ" "$OUT/cli$f.txt")"
  emit "V913_SUBMISSION_REF_EQ=$(pick "V913_SUBMISSION_REF_EQ" "$OUT/cli$f.txt")"
  emit "V913_SUBMISSION_FIELDS_READ=$(pick "V913_SUBMISSION_FIELDS_READ" "$OUT/cli$f.txt")"
  emit "V913_FILESET_LEAF_TOKENS=$(pick "V913_FILESET_LEAF_TOKENS" "$OUT/cli$f.txt")"
  emit "V913_FILESET_ROOT_TOKENS=$(pick "V913_FILESET_ROOT_TOKENS" "$OUT/cli$f.txt")"
  emit "V913_FILESET_INPUTS_PRINTED=$(pick "V913_FILESET_INPUTS_PRINTED" "$OUT/cli$f.txt")"
  emit "V913_FILESET_LEAVES_PRINTED=$(pick "V913_FILESET_LEAVES_PRINTED" "$OUT/cli$f.txt")"
  emit "V913_FILESET_LEAVES_EQ=$(pick "V913_FILESET_LEAVES_EQ" "$OUT/cli$f.txt")"
  emit "V913_FILESET_ROOT_EQ=$(pick "V913_FILESET_ROOT_EQ" "$OUT/cli$f.txt")"
  emit "V913_JSON_CANON_EQ=$(pick "V913_JSON_CANON_EQ" "$OUT/cli$f.txt")"
  emit "V913_RECEIPT_FIELDS=$(pick "V913_RECEIPT_FIELDS" "$OUT/cli$f.txt")"
  emit "V913_JSON_KEYS_MATCH_RULE=$(pick "V913_JSON_KEYS_MATCH_RULE" "$OUT/cli$f.txt")"
  emit "V913_JSON_FLOAT_FIELDS=$(pick "V913_JSON_FLOAT_FIELDS" "$OUT/cli$f.txt")"
  emit "V913_RECEIPT_SIGNED_LEN=$(pick "V913_RECEIPT_SIGNED_LEN" "$OUT/cli$f.txt")"
  emit "V913_RECEIPT_PUBKEY_EQ=$(pick "V913_RECEIPT_PUBKEY_EQ" "$OUT/cli$f.txt")"
  emit "V913_RECEIPT_SIGNATURE_VALID=$(pick "V913_RECEIPT_SIGNATURE_VALID" "$OUT/cli$f.txt")"
  emit "V913_RECEIPT_SIGNATURE_DECOY=$(pick "V913_RECEIPT_SIGNATURE_DECOY" "$OUT/cli$f.txt")"
  emit "V913_ALLOWLIST_DOC=$(pick "V913_ALLOWLIST_DOC" "$OUT/cli$f.txt")"
  emit "V913_ALLOWLIST_SPEC=$(pick "V913_ALLOWLIST_SPEC" "$OUT/cli$f.txt")"
  emit "V913_ALLOWLIST_SPEC_READ=$(pick "V913_ALLOWLIST_SPEC_READ" "$OUT/cli$f.txt")"
  emit "V913_ALLOWLIST_SPEC_VS_DOC_EQ=$(pick "V913_ALLOWLIST_SPEC_VS_DOC_EQ" "$OUT/cli$f.txt")"
  emit "V913_DERIVE_RULES_PRINTED=$(pick "V913_DERIVE_RULES_PRINTED" "$OUT/cli$f.txt")"
  emit "V913_VERDICT_DERIVABLE=$(pick "V913_VERDICT_DERIVABLE" "$OUT/cli$f.txt")"
  emit "V913_PAYOUT_ALLOWED_EQ=$(pick "V913_PAYOUT_ALLOWED_EQ" "$OUT/cli$f.txt")"
  emit "V913_RFC8032_PUBKEY_EQ=$(pick "V913_RFC8032_PUBKEY_EQ" "$OUT/cli$f.txt")"
  emit "V913_RFC8032_VERIFY=$(pick "V913_RFC8032_VERIFY" "$OUT/cli$f.txt")"
  emit "V913_RFC8032_SIGN_EQ=$(pick "V913_RFC8032_SIGN_EQ" "$OUT/cli$f.txt")"
  emit "V913_RFC8032_DECOY_REJECTED=$(pick "V913_RFC8032_DECOY_REJECTED" "$OUT/cli$f.txt")"
  emit "V913_RFC8032_SWEEP_SIGS=$(pick "V913_RFC8032_SWEEP_SIGS" "$OUT/cli$f.txt")"
  emit "V913_RFC8032_SWEEP_ODD_X=$(pick "V913_RFC8032_SWEEP_ODD_X" "$OUT/cli$f.txt")"
  emit "V913_RFC8032_SWEEP_EVEN_X=$(pick "V913_RFC8032_SWEEP_EVEN_X" "$OUT/cli$f.txt")"
  emit "V913_RFC8032_SWEEP_ALL_VERIFY=$(pick "V913_RFC8032_SWEEP_ALL_VERIFY" "$OUT/cli$f.txt")"
  emit "V913_RFC8032_SWEEP_BOTH_PARITIES=$(pick "V913_RFC8032_SWEEP_BOTH_PARITIES" "$OUT/cli$f.txt")"
  emit "V913_WORST=$(pick "V913_WORST" "$OUT/cli$f.txt")"
  emit "V913_ALL_OK=$(pick "V913_ALL_OK" "$OUT/cli$f.txt")"
done

say "### ШАГ 2 генератор векторов на том же дереве ### $(date +%FT%T%:z)"
FACTS="$OUT/facts_r1.txt"
V9_VECTORS_OUT="$DOC" cargo test -q -p vecdht-orders --test paid_order_vectors -- --nocapture \
  > "$OUT/gen.txt" 2>&1
rcg=$?
note "$rcg"
grep -E '^V9_(VECTORS|CODES|WORKED|W1|W2|W3|ORDER_REF|ARTIFACT_ROOT|SUBMISSION_REF|VECTORS_SHA)' \
  "$OUT/gen.txt" | tee -a "$LOG"
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  emit "V9_RUST_VECTORS_EXIT=${rcg}"
  emit "V9_VECTORS=$(pick V9_VECTORS "$OUT/gen.txt")"
  cov=$(grep -o 'V9_CODES_COVERED=[0-9]*/[0-9]*' "$OUT/gen.txt" | tail -1 | cut -d= -f2)
  emit "V9_CODES_COVERED=${cov%%/*}"
  emit "V9_ORDER_REF=$(pick V9_ORDER_REF "$OUT/gen.txt")"
  emit "V9_ARTIFACT_ROOT=$(pick V9_ARTIFACT_ROOT "$OUT/gen.txt")"
  emit "V9_SUBMISSION_REF=$(pick V9_SUBMISSION_REF "$OUT/gen.txt")"
  emit "V9_W1_SHA=$(pick V9_W1_SHA "$OUT/gen.txt")"
  emit "V9_W2_SHA=$(pick V9_W2_SHA "$OUT/gen.txt")"
  emit "V9_W3_SHA=$(pick V9_W3_SHA "$OUT/gen.txt")"
done

say "### ШАГ 3 порождённый носитель: изменился и только ли он ### $(date +%FT%T%:z)"
now_doc=$(sha256sum "$DOC" | cut -d' ' -f1)
now_spec=$(sha256sum "$SPEC" | cut -d' ' -f1)
if [ -n "$now_doc" ] && [ "$now_doc" != "$PREV_DOC_SHA" ]; then ch=1; else ch=0; fi
if [ -n "$now_spec" ] && [ "$now_spec" != "$PREV_SPEC_SHA" ]; then chs=1; else chs=0; fi
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  emit "V9_PREV_DOC_SHA=${PREV_DOC_SHA}"
  emit "V9_DOC_SHA=${now_doc}"
  emit "V9_DOC_SHA_CHANGED=${ch}"
  emit "V9_SPEC_SHA_CHANGED=${chs}"
done
say "V9_DOC_SHA=${now_doc} V9_DOC_SHA_CHANGED=${ch} V9_SPEC_SHA_CHANGED=${chs}"
# Строки, появившиеся в носителе после правки генератора: их печатает код, а не человек.
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  n=$(grep -c '^- файл ' "$DOC" || true)
  emit "V9_FILE_PAIR_LINES=${n}"
done
say "V9_FILE_PAIR_LINES=$(grep -c '^- файл ' "$DOC" || true)"

say "### ШАГ 4 независимая сверка векторов и матрицы ### $(date +%FT%T%:z)"
python lab/xcheck-paid-orders.py "$DOC" > "$OUT/xcheck.txt" 2>&1
rc4=$?
note "$rc4"
cat "$OUT/xcheck.txt" | tee -a "$LOG"
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  cat "$OUT/xcheck.txt" >> "$FACTS"
done

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
bash lab/workspace-verify.sh E-0113 2>&1 | tail -n 12 | tee -a "$LOG"
vrc=${PIPESTATUS[0]}
printf "VERIFY_EXIT=%s\n" "$vrc" | tee -a "$LOG"
note "$vrc"

for f in 1 2; do
  printf "GATE_H0113_OK=%s\n" "$gok" >> "$OUT/facts_r$f.txt"
  printf "DISK_GE_15000=%s\n" "$dok" >> "$OUT/facts_r$f.txt"
  printf "E0113_RUNS=2\n" >> "$OUT/facts_r$f.txt"
  printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "VERIFY_EXIT=%s\n" "$vrc" >> "$OUT/facts_r$f.txt"
done
if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable3=1; else stable3=0; fi
printf "VECTOR_STABLE=%s\n" "$stable3" | tee -a "$LOG"
for f in 1 2; do
  sed -i "s/^VECTOR_STABLE=.*$/VECTOR_STABLE=${stable3}/" "$OUT/facts_r$f.txt"
done

say "### ШАГ 8 стража текста и сверка ожиданий ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh "$CLIENT" "$SPEC" "$DOC" \
  lab/expectations/e0113.tsv lab/e0113-run.sh \
  lab/hypotheses/H-0113-independent-client-bytes.md \
  lab/experiments/E-0113-independent-client-bytes.md \
  lab/decisions/ADR-0063-spec-describes-bytes.md 2>&1 | tail -3 | tee -a "$LOG"
rct=${PIPESTATUS[0]}
printf "TEXTGUARD_CYCLE_EXIT=%s\n" "$rct" | tee -a "$LOG"; note "$rct"
for f in 1 2; do printf "TEXTGUARD_CYCLE_EXIT=%s\n" "$rct" >> "$OUT/facts_r$f.txt"; done

python lab/expect.py lab/expectations/e0113.tsv "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" 2>&1 \
  | tail -n 16 | tee -a "$LOG"
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
