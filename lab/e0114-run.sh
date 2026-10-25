#!/usr/bin/env bash
# E-0114 (слой стыковки цепочек: байты автовыплаты обязаны собираться вне Rust): сторонний
# реализатор моста обязан пересобрать term_hash, корень реестра, байты связки, свидетельства и
# требования, проверить пять подписей и вывести решение по каждому вектору, читая только
# напечатанные тексты, — не узел и не `crates/` (H-0114, `ADR-0064`).
#
# Прибор: `lab/v9-payout-bridge.py` — мост-эмулятор на Python (свой разбор таблиц, `hashlib`,
# Ed25519, интерпретатор напечатанных раскладок). У него четыре входа: носитель слоя
# `docs/PAID_PAYOUT-VECTORS.md`, спека `docs/VecDHT-SPEC-v9.md`, носитель заказов
# `docs/PAID_ORDER-VECTORS.md` (ради якоря аддитивности) и записка
# `lab/notes/DESIGN-2026-10-25-chain-binding.md` (ради того, чтобы раскладка записки и носителя
# не разъезжались). Первичные алгоритмы он берёт из прибора `E-0113` — осознанное ослабление
# независимости, записанное в карточку: предметом этого цикла была раскладка и машина решения
# слоя, не SHA-256.
#
# PRE_FIX-замер исполнен до коммита пре-регистрации и снят не «памятью о прежнем тексте», а
# посадкой: `lab/v9-payout-plant-decoy.py` возвращает в копию носителя ровно ту формулу
# `term_hash`, которую §1 печатал до правки (терминатор `0x00` после каждого поля), и прибор на
# этой копии краснеет там же, где покраснел в первый раз (дерево `25556ae`, выход 1):
# `V9C_TERM_EQ_GOT=0` из 31, `V9C_TERM_EQ=0`, `V9C_MIRROR_MATCH=4/31`, `V9C_MIRROR_EQ=0`,
# `V9C_DECOY_WITNESS_SIG=0` (посадка залога спотыкается раньше — на шаге (1)), `V9C_WORST=1`,
# `V9C_ALL_OK=0`. При этом на той же копии зелёные `V9C_RECORD_EQ=1`, `V9C_BINDING_EQ=1`,
# `V9C_WITNESS_EQ=1`, `V9C_SIGNATURES_VALID=1`, `V9C_ANCHOR_CARRIER_EQ=1` — то есть расходится
# именно напечатанная формула, а не носитель целиком. Шаги (3) этого helper'а повторяют посадку
# на каждом прогоне: контроль не может протухнуть, потому что он исполняется, а не записан.
#
# Правка ожидает три вещи. (1) §V9.7 спеки обязана описывать ту раскладку, которую исполняет
# `vecdht-orders` (пять доменов, четыре объекта, порядок шагов, коды шага (5)); (2) носитель
# обязан воспроизводиться из кода побайтно: `V9P_DOC_SHA` равен sha закоммиченного файла;
# (3) ни один байт заказа не двигается — инвариант аддитивности: `V9C_V01_ORDER_REF` остаётся
# `4167d021…ac70`, а `V9P_V01_ORDER_REF=4167d021…ac70` печатает сам генератор.
#
# Шаги:
#   (0) gate ДО прогона и носитель: диск/RAM/pagefile;
#   (1) два прогона прибора на неизменном дереве, литеральные `V9C_*`;
#   (2) генератор носителя на том же дереве в temp: `V9P_*` и побайтное воспроизведение носителя;
#   (3) контроль посадки: прежняя формула в копии носителя обязана краснить прибор;
#   (4) два прогона против себя (`VECTOR_STABLE`);
#   (5) `audit -n 5`;
#   (6) `workspace-verify.sh E-0114`;
#   (7) стража текста по файлам цикла и сверка `lab/expectations/e0114.tsv`;
#   (8) носитель после прогона и баланс цикла (`lab/ledger.py`).
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0114-all.log"
DOC=docs/PAID_PAYOUT-VECTORS.md
ODOC=docs/PAID_ORDER-VECTORS.md
SPEC=docs/VecDHT-SPEC-v9.md
NOTE=lab/notes/DESIGN-2026-10-25-chain-binding.md
BRIDGE=lab/v9-payout-bridge.py
PLANT=lab/v9-payout-plant-decoy.py
GEN=crates/vecdht-orders/tests/payout_claim_vectors.rs
# Хеши входов записаны СЮДА до пре-регистрации (они же — в карточке `E-0114` и в
# `lab/logs/e0114-prefix.log`) и замораживают дерево замера: helper обязан подтвердить, что ни
# носитель, ни спека, ни прибор, ни генератор не сдвинулись за время прогона. Правило хоста —
# «дерево не править во время прогона», и здесь оно числом, а не обещанием: «изменилось/не
# изменилось» сверяется с этими константами, а не с памятью о том, что было раньше.
PREV_DOC_SHA=11468b493dcae7512d99b6e0bb7a462b828efc9dcf3eaaafde4e24e0520eb88c
PREV_SPEC_SHA=102fc69418f783a46bf397faea373b64c371a3382eab6c35f2910c31d3b532b7
PREV_BRIDGE_SHA=28bf8bb0eba81180da5cc310890f19cab78124bd2a547c0661e46c0cf89507a7
PREV_PLANT_SHA=dfe69906b075de826ae35f26797b567a4960ae7208a0fd09590e6243efee775d
PREV_GEN_SHA=4a8be70a2dc0229c1b7f65f77e38d1f10e22d0d87a5e6f96c41b3134a950eded
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0114.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }
# Граница токена: значение может содержать `=`, `%`, `,`, `/`, `|`, `-` и двоеточие (KEYPAIR_MATCH,
# DECOY_*_PAIR, NOTE_FIELDS, пути), но не пробел и не кириллицу — прибор печатает значения ASCII.
pick() { grep -o "$1=[A-Za-z0-9_.:/=,%-]*" "$2" | tail -1 | cut -d= -f2-; }

say "########## E-0114 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 gate и носитель ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0114 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
printf "GATE_H0114_OK=%s\n" "$gok" | tee -a "$LOG"
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

say "### ШАГ 1 два прогона мост-эмулятора ### $(date +%FT%T%:z)"
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  : > "$FACTS"
  V9C_VERBOSE=1 python "$BRIDGE" "$DOC" "$SPEC" "$ODOC" "$NOTE" > "$OUT/cli$f.txt" 2>&1
  rcc=$?
  note "$rcc"
  grep -E '^V9C_|^  # ' "$OUT/cli$f.txt" | tee -a "$LOG"
  emit "E0114_BRIDGE_EXIT=${rcc}"
  # Литеральная печать каждого ключа: линт порогов требует, чтобы `V9C_KEY=` стояло в источнике
  # буквой, а не собиралось шаблоном — иначе ожидание можно выписать против факта, которого прибор
  # не печатает.
  emit "V9C_TOOLCHAIN=$(pick "V9C_TOOLCHAIN" "$OUT/cli$f.txt")"
  emit "V9C_UNICODE_DATA=$(pick "V9C_UNICODE_DATA" "$OUT/cli$f.txt")"
  emit "V9C_CARRIER_BYTES=$(pick "V9C_CARRIER_BYTES" "$OUT/cli$f.txt")"
  emit "V9C_CARRIER_SHA=$(pick "V9C_CARRIER_SHA" "$OUT/cli$f.txt")"
  emit "V9C_PRIMITIVES_FROM_E0113=$(pick "V9C_PRIMITIVES_FROM_E0113" "$OUT/cli$f.txt")"
  emit "V9C_VECTORS_PARSED=$(pick "V9C_VECTORS_PARSED" "$OUT/cli$f.txt")"
  emit "V9C_VECTOR_KEYS_UNIFORM=$(pick "V9C_VECTOR_KEYS_UNIFORM" "$OUT/cli$f.txt")"
  emit "V9C_VECTOR_KEY_COUNT=$(pick "V9C_VECTOR_KEY_COUNT" "$OUT/cli$f.txt")"
  emit "V9C_DOMAIN_ROWS_GOT=$(pick "V9C_DOMAIN_ROWS_GOT" "$OUT/cli$f.txt")"
  emit "V9C_DOMAIN_ROWS=$(pick "V9C_DOMAIN_ROWS" "$OUT/cli$f.txt")"
  emit "V9C_LAYOUT_OBJECTS_GOT=$(pick "V9C_LAYOUT_OBJECTS_GOT" "$OUT/cli$f.txt")"
  emit "V9C_LAYOUT_OBJECTS=$(pick "V9C_LAYOUT_OBJECTS" "$OUT/cli$f.txt")"
  emit "V9C_LAYOUT_ROWS=$(pick "V9C_LAYOUT_ROWS" "$OUT/cli$f.txt")"
  emit "V9C_STEP_ROWS_GOT=$(pick "V9C_STEP_ROWS_GOT" "$OUT/cli$f.txt")"
  emit "V9C_STEP_ROWS=$(pick "V9C_STEP_ROWS" "$OUT/cli$f.txt")"
  emit "V9C_CODE_NAMES_GOT=$(pick "V9C_CODE_NAMES_GOT" "$OUT/cli$f.txt")"
  emit "V9C_CODE_NAMES=$(pick "V9C_CODE_NAMES" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_ROWS_GOT=$(pick "V9C_REGISTRY_ROWS_GOT" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_ROWS=$(pick "V9C_REGISTRY_ROWS" "$OUT/cli$f.txt")"
  emit "V9C_DOMAIN_LEN_DIFF=$(pick "V9C_DOMAIN_LEN_DIFF" "$OUT/cli$f.txt")"
  emit "V9C_DOMAIN_LEN_EQ=$(pick "V9C_DOMAIN_LEN_EQ" "$OUT/cli$f.txt")"
  emit "V9C_DOMAIN_RECEIPT_LEN_EQ=$(pick "V9C_DOMAIN_RECEIPT_LEN_EQ" "$OUT/cli$f.txt")"
  emit "V9C_DOMAIN_RECEIPT_LEN=$(pick "V9C_DOMAIN_RECEIPT_LEN" "$OUT/cli$f.txt")"
  emit "V9C_DOMAIN_LEN_DECOY=$(pick "V9C_DOMAIN_LEN_DECOY" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_BYTES_EQ_GOT=$(pick "V9C_REGISTRY_BYTES_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_BYTES_EQ=$(pick "V9C_REGISTRY_BYTES_EQ" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_LEAF_EQ_GOT=$(pick "V9C_REGISTRY_LEAF_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_LEAF_EQ=$(pick "V9C_REGISTRY_LEAF_EQ" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_ROOT=$(pick "V9C_REGISTRY_ROOT" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_ROOT_EQ=$(pick "V9C_REGISTRY_ROOT_EQ" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_PERMUTE_EQ=$(pick "V9C_REGISTRY_PERMUTE_EQ" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_ROOT_SENSITIVE=$(pick "V9C_REGISTRY_ROOT_SENSITIVE" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_EMPTY_ROOT=$(pick "V9C_REGISTRY_EMPTY_ROOT" "$OUT/cli$f.txt")"
  emit "V9C_REGISTRY_BRIDGE_CODES=$(pick "V9C_REGISTRY_BRIDGE_CODES" "$OUT/cli$f.txt")"
  emit "V9C_KEYPAIR_MATCH=$(pick "V9C_KEYPAIR_MATCH" "$OUT/cli$f.txt")"
  emit "V9C_KEYPAIR_MASK=$(pick "V9C_KEYPAIR_MASK" "$OUT/cli$f.txt")"
  emit "V9C_KEYPAIR_PUBLISHER_EQ=$(pick "V9C_KEYPAIR_PUBLISHER_EQ" "$OUT/cli$f.txt")"
  emit "V9C_KEYPAIR_BENEFICIARY_EQ=$(pick "V9C_KEYPAIR_BENEFICIARY_EQ" "$OUT/cli$f.txt")"
  emit "V9C_KEYPAIR_VERIFIER_EQ=$(pick "V9C_KEYPAIR_VERIFIER_EQ" "$OUT/cli$f.txt")"
  emit "V9C_KEYPAIR_OBSERVER_EQ=$(pick "V9C_KEYPAIR_OBSERVER_EQ" "$OUT/cli$f.txt")"
  emit "V9C_KEYPAIR_STRANGE_VECTORS=$(pick "V9C_KEYPAIR_STRANGE_VECTORS" "$OUT/cli$f.txt")"
  emit "V9C_KEYPAIR_DECOY_NAMED=$(pick "V9C_KEYPAIR_DECOY_NAMED" "$OUT/cli$f.txt")"
  emit "V9C_RECORD_EQ_GOT=$(pick "V9C_RECORD_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_RECORD_EQ=$(pick "V9C_RECORD_EQ" "$OUT/cli$f.txt")"
  emit "V9C_TERM_EQ_GOT=$(pick "V9C_TERM_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_TERM_EQ=$(pick "V9C_TERM_EQ" "$OUT/cli$f.txt")"
  emit "V9C_BINDING_EQ_GOT=$(pick "V9C_BINDING_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_BINDING_EQ=$(pick "V9C_BINDING_EQ" "$OUT/cli$f.txt")"
  emit "V9C_WITNESS_EQ_GOT=$(pick "V9C_WITNESS_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_WITNESS_EQ=$(pick "V9C_WITNESS_EQ" "$OUT/cli$f.txt")"
  emit "V9C_RECEIPT_JSON_EQ_GOT=$(pick "V9C_RECEIPT_JSON_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_RECEIPT_JSON_EQ=$(pick "V9C_RECEIPT_JSON_EQ" "$OUT/cli$f.txt")"
  emit "V9C_CLAIM_EQ_GOT=$(pick "V9C_CLAIM_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_CLAIM_EQ=$(pick "V9C_CLAIM_EQ" "$OUT/cli$f.txt")"
  emit "V9C_CLAIM_MISS=$(pick "V9C_CLAIM_MISS" "$OUT/cli$f.txt")"
  emit "V9C_SIGNATURES_CHECKED=$(pick "V9C_SIGNATURES_CHECKED" "$OUT/cli$f.txt")"
  emit "V9C_SIGNATURES_VALID_GOT=$(pick "V9C_SIGNATURES_VALID_GOT" "$OUT/cli$f.txt")"
  emit "V9C_SIGNATURES_VALID=$(pick "V9C_SIGNATURES_VALID" "$OUT/cli$f.txt")"
  emit "V9C_MIRROR_MATCH=$(pick "V9C_MIRROR_MATCH" "$OUT/cli$f.txt")"
  emit "V9C_MIRROR_MISS=$(pick "V9C_MIRROR_MISS" "$OUT/cli$f.txt")"
  emit "V9C_MIRROR_EQ=$(pick "V9C_MIRROR_EQ" "$OUT/cli$f.txt")"
  emit "V9C_INDEP_MATCH=$(pick "V9C_INDEP_MATCH" "$OUT/cli$f.txt")"
  emit "V9C_V01_ORDER_REF=$(pick "V9C_V01_ORDER_REF" "$OUT/cli$f.txt")"
  emit "V9C_ANCHOR_IN_LAYER_DOC=$(pick "V9C_ANCHOR_IN_LAYER_DOC" "$OUT/cli$f.txt")"
  emit "V9C_ANCHOR_CARRIER_EQ=$(pick "V9C_ANCHOR_CARRIER_EQ" "$OUT/cli$f.txt")"
  emit "V9C_ORDER_REF_REBUILT_EQ=$(pick "V9C_ORDER_REF_REBUILT_EQ" "$OUT/cli$f.txt")"
  emit "V9C_ORDER_REF_SENSITIVE=$(pick "V9C_ORDER_REF_SENSITIVE" "$OUT/cli$f.txt")"
  emit "V9C_CODES_SEEN=$(pick "V9C_CODES_SEEN" "$OUT/cli$f.txt")"
  emit "V9C_CODES_USED_MINE=$(pick "V9C_CODES_USED_MINE" "$OUT/cli$f.txt")"
  emit "V9C_CODES_SUBSET=$(pick "V9C_CODES_SUBSET" "$OUT/cli$f.txt")"
  emit "V9C_CODES_USED_EQ_COVERAGE=$(pick "V9C_CODES_USED_EQ_COVERAGE" "$OUT/cli$f.txt")"
  emit "V9C_CODES_NAMED_EQ_COVERAGE=$(pick "V9C_CODES_NAMED_EQ_COVERAGE" "$OUT/cli$f.txt")"
  emit "V9C_CODES_EQ_SPEC=$(pick "V9C_CODES_EQ_SPEC" "$OUT/cli$f.txt")"
  emit "V9C_CODE_GUARD_DECOY=$(pick "V9C_CODE_GUARD_DECOY" "$OUT/cli$f.txt")"
  emit "V9C_CODES_NAMED_IN_STEPS=$(pick "V9C_CODES_NAMED_IN_STEPS" "$OUT/cli$f.txt")"
  emit "V9C_STEP_CODES_COUNT=$(pick "V9C_STEP_CODES_COUNT" "$OUT/cli$f.txt")"
  emit "V9C_STEP_CODES_KNOWN=$(pick "V9C_STEP_CODES_KNOWN" "$OUT/cli$f.txt")"
  emit "V9C_STEP_CODES_PARSED=$(pick "V9C_STEP_CODES_PARSED" "$OUT/cli$f.txt")"
  emit "V9C_USED_CODES_IN_STEPS=$(pick "V9C_USED_CODES_IN_STEPS" "$OUT/cli$f.txt")"
  emit "V9C_FAIL_CLOSED_LEAK=$(pick "V9C_FAIL_CLOSED_LEAK" "$OUT/cli$f.txt")"
  emit "V9C_FAIL_CLOSED=$(pick "V9C_FAIL_CLOSED" "$OUT/cli$f.txt")"
  emit "V9C_EMPTY_TRUST_CODES=$(pick "V9C_EMPTY_TRUST_CODES" "$OUT/cli$f.txt")"
  emit "V9C_VECTORS_COV_EQ_GOT=$(pick "V9C_VECTORS_COV_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_VECTORS_COV_EQ=$(pick "V9C_VECTORS_COV_EQ" "$OUT/cli$f.txt")"
  emit "V9C_PAYOUT_COV_EQ_GOT=$(pick "V9C_PAYOUT_COV_EQ_GOT" "$OUT/cli$f.txt")"
  emit "V9C_PAYOUT_COV_EQ=$(pick "V9C_PAYOUT_COV_EQ" "$OUT/cli$f.txt")"
  emit "V9C_DOUBLE_REPLAY_COUNT=$(pick "V9C_DOUBLE_REPLAY_COUNT" "$OUT/cli$f.txt")"
  emit "V9C_DOUBLE_REPLAY_EQ_COVERAGE=$(pick "V9C_DOUBLE_REPLAY_EQ_COVERAGE" "$OUT/cli$f.txt")"
  emit "V9C_SIG_DECOY=$(pick "V9C_SIG_DECOY" "$OUT/cli$f.txt")"
  emit "V9C_DECOY_STATUS_PAIR=$(pick "V9C_DECOY_STATUS_PAIR" "$OUT/cli$f.txt")"
  emit "V9C_DECOY_STATUS=$(pick "V9C_DECOY_STATUS" "$OUT/cli$f.txt")"
  emit "V9C_DECOY_AMOUNT_PAIR=$(pick "V9C_DECOY_AMOUNT_PAIR" "$OUT/cli$f.txt")"
  emit "V9C_DECOY_AMOUNT=$(pick "V9C_DECOY_AMOUNT" "$OUT/cli$f.txt")"
  emit "V9C_DECOY_WITNESS_SIG_PAIR=$(pick "V9C_DECOY_WITNESS_SIG_PAIR" "$OUT/cli$f.txt")"
  emit "V9C_DECOY_WITNESS_SIG=$(pick "V9C_DECOY_WITNESS_SIG" "$OUT/cli$f.txt")"
  emit "V9C_DECOY_STATUS_SIGNED_PAIR=$(pick "V9C_DECOY_STATUS_SIGNED_PAIR" "$OUT/cli$f.txt")"
  emit "V9C_DECOY_STATUS_SIGNED=$(pick "V9C_DECOY_STATUS_SIGNED" "$OUT/cli$f.txt")"
  emit "V9C_LAYOUT_DECOY=$(pick "V9C_LAYOUT_DECOY" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_DOMAINS=$(pick "V9C_NOTE_DOMAINS" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_DOMAINS_EQ=$(pick "V9C_NOTE_DOMAINS_EQ" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_TERM_SEQ=$(pick "V9C_NOTE_TERM_SEQ" "$OUT/cli$f.txt")"
  emit "V9C_CARRIER_TERM_SEQ=$(pick "V9C_CARRIER_TERM_SEQ" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_TERM_ORDER_EQ=$(pick "V9C_NOTE_TERM_ORDER_EQ" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_FIELDS=$(pick "V9C_NOTE_FIELDS" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_FIELDS_PARSED=$(pick "V9C_NOTE_FIELDS_PARSED" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_FIELD_ORDER_EQ=$(pick "V9C_NOTE_FIELD_ORDER_EQ" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_STEPS=$(pick "V9C_NOTE_STEPS" "$OUT/cli$f.txt")"
  emit "V9C_STEP_COVERAGE=$(pick "V9C_STEP_COVERAGE" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_OPENS=$(pick "V9C_NOTE_OPENS" "$OUT/cli$f.txt")"
  emit "V9C_NOTE_OPENS_NUMBERED=$(pick "V9C_NOTE_OPENS_NUMBERED" "$OUT/cli$f.txt")"
  emit "V9C_WORST=$(pick "V9C_WORST" "$OUT/cli$f.txt")"
  emit "V9C_ALL_OK=$(pick "V9C_ALL_OK" "$OUT/cli$f.txt")"
done

say "### ШАГ 2 генератор носителя: побайтное воспроизведение ### $(date +%FT%T%:z)"
REGEN="$OUT/carrier_regen.md"
V9P_VECTORS_OUT="$REGEN" cargo test -q -p vecdht-orders --test payout_claim_vectors -- --nocapture \
  > "$OUT/gen.txt" 2>&1
rcg=$?
note "$rcg"
grep -E '^V9P_' "$OUT/gen.txt" | tee -a "$LOG"
gen_sha=$(pick "V9P_DOC_SHA" "$OUT/gen.txt")
regen_sha=$(sha256sum "$REGEN" | cut -d' ' -f1)
doc_sha=$(sha256sum "$DOC" | cut -d' ' -f1)
spec_sha=$(sha256sum "$SPEC" | cut -d' ' -f1)
bridge_sha=$(sha256sum "$BRIDGE" | cut -d' ' -f1)
plant_sha=$(sha256sum "$PLANT" | cut -d' ' -f1)
gen_src_sha=$(sha256sum "$GEN" | cut -d' ' -f1)
if [ -n "$regen_sha" ] && [ "$regen_sha" = "$doc_sha" ]; then repro=1; else repro=0; fi
if [ "$doc_sha" = "$PREV_DOC_SHA" ]; then docsame=1; else docsame=0; fi
if [ "$spec_sha" = "$PREV_SPEC_SHA" ]; then specsame=1; else specsame=0; fi
if [ "$bridge_sha" = "$PREV_BRIDGE_SHA" ]; then bridgesame=1; else bridgesame=0; fi
if [ "$plant_sha" = "$PREV_PLANT_SHA" ]; then plantsame=1; else plantsame=0; fi
if [ "$gen_src_sha" = "$PREV_GEN_SHA" ]; then gensame=1; else gensame=0; fi
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  emit "V9P_GEN_EXIT=${rcg}"
  emit "V9P_V01_ORDER_REF=$(pick V9P_V01_ORDER_REF "$OUT/gen.txt")"
  emit "V9P_ORDER_REF_UNCHANGED=$(pick V9P_ORDER_REF_UNCHANGED "$OUT/gen.txt")"
  emit "V9P_VECTORS=$(pick V9P_VECTORS "$OUT/gen.txt")"
  emit "V9P_VECTOR_KEYS=$(pick V9P_VECTOR_KEYS "$OUT/gen.txt")"
  emit "V9P_CODE_TOTAL=$(pick V9P_CODE_TOTAL "$OUT/gen.txt")"
  emit "V9P_CODES_USED=$(pick V9P_CODES_USED "$OUT/gen.txt")"
  emit "V9P_CODES_SUBSET=$(pick V9P_CODES_SUBSET "$OUT/gen.txt")"
  emit "V9P_PAYOUTS=$(pick V9P_PAYOUTS "$OUT/gen.txt")"
  emit "V9P_DOUBLE_REPLAY=$(pick V9P_DOUBLE_REPLAY "$OUT/gen.txt")"
  emit "V9P_REGISTRY_ROOT=$(pick V9P_REGISTRY_ROOT "$OUT/gen.txt")"
  emit "V9P_DOMAINS=$(pick V9P_DOMAINS "$OUT/gen.txt")"
  emit "V9P_RECEIPT_KEYS=$(pick V9P_RECEIPT_KEYS "$OUT/gen.txt")"
  emit "V9P_ORDER_REF=$(pick V9P_ORDER_REF "$OUT/gen.txt")"
  emit "V9P_TERM_HASH=$(pick V9P_TERM_HASH "$OUT/gen.txt")"
  emit "V9P_CLAIM_LEN=$(pick V9P_CLAIM_LEN "$OUT/gen.txt")"
  emit "V9P_CLAIM_SHA=$(pick V9P_CLAIM_SHA "$OUT/gen.txt")"
  emit "V9P_FORMULA_EQ=$(pick V9P_FORMULA_EQ "$OUT/gen.txt")"
  emit "V9P_TERM_TOKENS=$(pick V9P_TERM_TOKENS "$OUT/gen.txt")"
  emit "V9P_DOC_BYTES=$(pick V9P_DOC_BYTES "$OUT/gen.txt")"
  emit "V9P_DOC_SHA=${gen_sha}"
  emit "V9C_CARRIER_REGEN_SHA=${regen_sha}"
  emit "V9C_CARRIER_REPRODUCED=${repro}"
  emit "V9C_DOC_SHA=${doc_sha}"
  emit "V9C_SPEC_SHA=${spec_sha}"
  emit "V9C_DOC_SHA_UNCHANGED=${docsame}"
  emit "V9C_SPEC_SHA_UNCHANGED=${specsame}"
  emit "V9C_INSTRUMENT_SHA=${bridge_sha}"
  emit "V9C_INSTRUMENT_SHA_UNCHANGED=${bridgesame}"
  emit "V9C_PLANT_SHA=${plant_sha}"
  emit "V9C_PLANT_SHA_UNCHANGED=${plantsame}"
  emit "V9C_GENERATOR_SHA=${gen_src_sha}"
  emit "V9C_GENERATOR_SHA_UNCHANGED=${gensame}"
done
say "V9P_DOC_SHA=${gen_sha} V9C_CARRIER_REGEN_SHA=${regen_sha} V9C_CARRIER_REPRODUCED=${repro}"
say "V9C_DOC_SHA_UNCHANGED=${docsame} V9C_SPEC_SHA_UNCHANGED=${specsame} прибор=${bridge_sha}"

say "### ШАГ 3 контроль посадки: прежняя формула обязана краснить ### $(date +%FT%T%:z)"
python "$PLANT" "$DOC" > "$OUT/carrier_decoy.md" 2> "$OUT/plant.log"
rcp=$?
note "$rcp"
cat "$OUT/plant.log" | tee -a "$LOG"
python "$BRIDGE" "$OUT/carrier_decoy.md" "$SPEC" "$ODOC" "$NOTE" > "$OUT/decoy.txt" 2>&1
rcd=$?
# Посадка обязана быть красной: выход 1 и `V9C_TERM_EQ=0`. Зелёный контроль = прибор слеп.
if [ "$rcd" -eq 1 ]; then redok=1; else redok=0; note 1; fi
ctl_term=$(pick "V9C_TERM_EQ" "$OUT/decoy.txt")
ctl_got=$(pick "V9C_TERM_EQ_GOT" "$OUT/decoy.txt")
ctl_all=$(pick "V9C_ALL_OK" "$OUT/decoy.txt")
ctl_mirror=$(pick "V9C_MIRROR_MATCH" "$OUT/decoy.txt")
ctl_record=$(pick "V9C_RECORD_EQ" "$OUT/decoy.txt")
ctl_sig=$(pick "V9C_SIGNATURES_VALID" "$OUT/decoy.txt")
ctl_decoy=$(pick "V9C_DECOY_WITNESS_SIG" "$OUT/decoy.txt")
ctl_sha=$(pick "V9C_CARRIER_SHA" "$OUT/decoy.txt")
for f in 1 2; do
  FACTS="$OUT/facts_r$f.txt"
  emit "V9CTL_PLANT_EXIT=${rcp}"
  emit "V9CTL_BRIDGE_EXIT=${rcd}"
  emit "V9CTL_IS_RED=${redok}"
  emit "V9CTL_TERM_EQ_GOT=${ctl_got}"
  emit "V9CTL_TERM_EQ=${ctl_term}"
  emit "V9CTL_ALL_OK=${ctl_all}"
  emit "V9CTL_MIRROR_MATCH=${ctl_mirror}"
  emit "V9CTL_RECORD_EQ=${ctl_record}"
  emit "V9CTL_SIGNATURES_VALID=${ctl_sig}"
  emit "V9CTL_DECOY_WITNESS_SIG=${ctl_decoy}"
  emit "V9CTL_DECOY_SHA=${ctl_sha}"
done
say "V9CTL_BRIDGE_EXIT=${rcd} V9CTL_IS_RED=${redok} V9CTL_TERM_EQ_GOT=${ctl_got} V9CTL_MIRROR_MATCH=${ctl_mirror}"

say "### ШАГ 4 два прогона против себя ### $(date +%FT%T%:z)"
if diff -q "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" >/dev/null 2>&1; then stable=1; else stable=0; fi
printf "VECTOR_STABLE=%s\n" "$stable" | tee -a "$LOG"
for f in 1 2; do printf "VECTOR_STABLE=%s\n" "$stable" >> "$OUT/facts_r$f.txt"; done

say "### ШАГ 5 audit ### $(date +%FT%T%:z)"
python lab/cycle-gate.py audit -n 5 > "$OUT/audit.txt" 2>&1
rc=$?; note "$rc"
tail -n 3 "$OUT/audit.txt" | tee -a "$LOG"
aud=$(sed -n 's/.*нарушени[^=]*=\([0-9]*\).*/\1/p' "$OUT/audit.txt" | tail -1)
printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" | tee -a "$LOG"

say "### ШАГ 6 полная верификация ### $(date +%FT%T%:z)"
bash lab/workspace-verify.sh E-0114 2>&1 | tail -n 12 | tee -a "$LOG"
vrc=${PIPESTATUS[0]}
printf "VERIFY_EXIT=%s\n" "$vrc" | tee -a "$LOG"
note "$vrc"

for f in 1 2; do
  printf "GATE_H0114_OK=%s\n" "$gok" >> "$OUT/facts_r$f.txt"
  printf "DISK_GE_15000=%s\n" "$dok" >> "$OUT/facts_r$f.txt"
  printf "E0114_RUNS=2\n" >> "$OUT/facts_r$f.txt"
  printf "AUDIT_VIOLATIONS=%s\n" "${aud:-NONE}" >> "$OUT/facts_r$f.txt"
  printf "VERIFY_EXIT=%s\n" "$vrc" >> "$OUT/facts_r$f.txt"
done

say "### ШАГ 7 стража текста и сверка ожиданий ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh "$BRIDGE" "$PLANT" "$DOC" "$GEN" \
  lab/expectations/e0114.tsv lab/e0114-run.sh \
  lab/hypotheses/H-0114-payout-bridge-bytes.md \
  lab/experiments/E-0114-payout-bridge-bytes.md \
  lab/decisions/ADR-0064-chain-binding-is-data.md 2>&1 | tail -3 | tee -a "$LOG"
rct=${PIPESTATUS[0]}
printf "TEXTGUARD_CYCLE_EXIT=%s\n" "$rct" | tee -a "$LOG"; note "$rct"
for f in 1 2; do printf "TEXTGUARD_CYCLE_EXIT=%s\n" "$rct" >> "$OUT/facts_r$f.txt"; done

python lab/expect.py lab/expectations/e0114.tsv "$OUT/facts_r1.txt" "$OUT/facts_r2.txt" 2>&1 \
  | tail -n 16 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "СВЕРКА_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "### ШАГ 8 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "### ШАГ 8b баланс цикла (lab/ledger.py) ### $(date +%FT%T%:z)"
VLOG=lab/logs/workspace-verify-2026-10-22.log
awk 'NR==FNR{if (/^########## /) last=FNR; next} FNR>last' "$VLOG" "$VLOG" > "$OUT/verify-last-block.txt"
python lab/ledger.py report "$LOG" "$OUT/verify-last-block.txt" 2>&1 | tail -n 22 | tee -a "$LOG"
rc=${PIPESTATUS[0]}; printf "LEDGER_EXIT=%s\n" "$rc" | tee -a "$LOG"; note $rc

say "WORST_RC=$WORST"
exit "$WORST"
