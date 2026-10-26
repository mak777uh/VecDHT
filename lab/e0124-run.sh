#!/usr/bin/env bash
# A1c / E-0124 (ADR-0065): подписанный грант lease переживает рестарт узла.
#
# Что мерится. Право писать той же эпохи после reopen — не в модели узлов, а в двух местах сразу:
# (1) `crates/vecdht-node/tests/lease_after_restart.rs` — три ветки (целый `lease.bin` возвращает
# serving_epoch и `PublishAck OK`; удалённый файл оставляет прежний отказ `EPOCH_STALE`; три
# посадки — чужая эпоха, битая подпись, истёкший бакет — не поднимаются, и контрольный кадр
# поднимается в той же директории, поэтому ноль означает «отказ случился», а не «прибор молчит»);
# (2) `crates/vecdht-cli/tests/node_lease_status.rs` — тот же контракт для процесса
# `vecdht-cli node run`: `NODE_STATUS` печатает `lease=` и `serving_epoch=`, а после `drop` и
# старта с тем же `--dir` публикация настоящим агентом проходит на эпохе 1.
#
# PRE_FIX: тот же прибор на дереве `d8d3087`, где правки нет (product-файлы временно берутся из
# пина, тесты остаются текущими; по завершении файлы возвращаются — см. trap).
#
# Порог: lab/expectations/e0124.tsv.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG=lab/logs/e0124-all.log
PRE_FIX_PIN=d8d3087
EXPECT=lab/expectations/e0124.tsv
PRODUCT=(crates/vecdht-node/src/node.rs crates/vecdht-node/src/lease.rs crates/vecdht-cli/src/node_cmd.rs)
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0124.XXXXXX")
KEEP="$OUT/keep"
mkdir -p "$KEEP"
restore_product() {
  for f in "${PRODUCT[@]}"; do
    b="$KEEP/$(echo "$f" | tr '/' '@')"
    [ -f "$b" ] && cp "$b" "$f"
  done
}
trap 'restore_product; rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
G="$OUT/facts_global.txt"
: > "$G"
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }

# Факт из вывода прибора: строка `KEY=значение`. Если строки нет — печатается MISSING, и сверка
# краснеет: молчание прогона не считается успехом.
fact() { # fact <файл-вывода> <ключ>
  grep -m1 -oE "^${2}=[^ ]*" "$1" 2>/dev/null | head -1 | sed "s/^${2}=//" || true
}
pick() { # pick <исходный ключ> <печатаемый ключ> <файл>
  v=$(fact "$3" "$1")
  emit0 "$2=${v:-MISSING}"
}

say "########## E-0124 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 гейт и носитель до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0124 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
emit0 "GATE_H0124_OK=${gok}"
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
[ "$dok" = 1 ] || note 1

for f in "${PRODUCT[@]}"; do cp "$f" "$KEEP/$(echo "$f" | tr '/' '@')"; done

say "### ШАГ 1 PRE_FIX: product-файлы дерева ${PRE_FIX_PIN}, прибор текущий ### $(date +%FT%T%:z)"
git cat-file -e "${PRE_FIX_PIN}:crates/vecdht-node/src/node.rs" 2>/dev/null || say "ПИН НЕ НАЙДЕН"
git checkout "$PRE_FIX_PIN" -- "${PRODUCT[@]}" 2>&1 | tee -a "$LOG"
rc=$?
note "$rc"
say "checkout: exit=${rc}; lease.bin в node.rs: $(grep -c 'LEASE_FILE' crates/vecdht-node/src/node.rs || true)"
cargo test -q -p vecdht-node --test lease_after_restart -- --nocapture --test-threads=1 > "$OUT/prefix-node.txt" 2>&1
say "PRE_FIX node: exit=$?"
grep -E '^LR_' "$OUT/prefix-node.txt" | sort | tee -a "$LOG" >/dev/null
pick LR_LEASE_FILE PRE_FIX_LEASE_FILE "$OUT/prefix-node.txt"
pick LR_PRIMARY_SERVING PRE_FIX_PRIMARY_SERVING "$OUT/prefix-node.txt"
pick LR_PRIMARY_PUBLISH_OK PRE_FIX_PRIMARY_PUBLISH_OK "$OUT/prefix-node.txt"
pick LR_PLANT_REJECTED PRE_FIX_PLANT_REJECTED "$OUT/prefix-node.txt"
pick LR_PRE_REFUSAL PRE_FIX_REFUSAL "$OUT/prefix-node.txt"
cargo test -q -p vecdht-cli --test node_lease_status -- --nocapture > "$OUT/prefix-cli.txt" 2>&1
say "PRE_FIX cli: exit=$?"
grep -E '^LR_' "$OUT/prefix-cli.txt" | sort | tee -a "$LOG" >/dev/null
pick LR_STATUS_LEASE_FIELD PRE_FIX_STATUS_LEASE_FIELD "$OUT/prefix-cli.txt"
pick LR_RESTART_PUBLISH_OK PRE_FIX_RESTART_PUBLISH_OK "$OUT/prefix-cli.txt"
cp "$OUT/prefix-node.txt" lab/logs/e0124-prefix-node.log
cp "$OUT/prefix-cli.txt" lab/logs/e0124-prefix-cli.log
restore_product
for f in "${PRODUCT[@]}"; do
  if ! cmp -s "$KEEP/$(echo "$f" | tr '/' '@')" "$f"; then
    say "ВОССТАНОВЛЕНИЕ НЕ СРАБОТАЛО: $f"
    note 1
  fi
done
say "product-файлы возвращены: $(grep -c 'LEASE_FILE' crates/vecdht-node/src/node.rs || true) совпадений LEASE_FILE в node.rs"

say "### ШАГ 2 два прогона приборов на неизменном дереве ### $(date +%FT%T%:z)"
for i in 1 2; do
  FACTS="$OUT/facts${i}.txt"
  : > "$FACTS"
  t0=$(date +%s)
  cargo test -q -p vecdht-node --test lease_after_restart -- --nocapture --test-threads=1 > "$OUT/node${i}.txt" 2>&1
  rcn=$?
  cargo test -q -p vecdht-node --test restart_recovery > "$OUT/rr${i}.txt" 2>&1
  rcr=$?
  cargo test -q -p vecdht-cli --test node_lease_status -- --nocapture > "$OUT/cli${i}.txt" 2>&1
  rcc=$?
  t1=$(date +%s)
  say "ПРОГОН${i}: node=${rcn} restart_recovery=${rcr} cli=${rcc} секунд=$((t1 - t0))"
  note "$rcn"; note "$rcr"; note "$rcc"
  sn=$(grep 'test result:' "$OUT/node${i}.txt" | tail -1)
  sc=$(grep 'test result:' "$OUT/cli${i}.txt" | tail -1)
  fn=$(printf '%s' "$sn" | sed -n 's/.* \([0-9]\+\) failed.*/\1/p')
  fc=$(printf '%s' "$sc" | sed -n 's/.* \([0-9]\+\) failed.*/\1/p')
  emit0 "NODE_EXIT=${rcn}"
  emit0 "NODE_FAILED=${fn:-0}"
  emit0 "RESTART_RECOVERY_EXIT=${rcr}"
  emit0 "CLI_EXIT=${rcc}"
  emit0 "CLI_FAILED=${fc:-0}"
  if [ "$rcn" -ne 0 ] || [ "$rcc" -ne 0 ]; then
    cp "$OUT/node${i}.txt" "lab/logs/e0124-node${i}-fail.txt"
    cp "$OUT/cli${i}.txt" "lab/logs/e0124-cli${i}-fail.txt"
    say "RED RUN${i}: выводы сохранены в lab/logs"
  fi
  { grep -E '^LR_' "$OUT/node${i}.txt"; grep -E '^LR_' "$OUT/cli${i}.txt"; } | sort -u > "$FACTS"
  cat "$FACTS" | tee -a "$LOG"
done

if diff -q "$OUT/facts1.txt" "$OUT/facts2.txt" >/dev/null 2>&1; then st=1; else st=0; fi
emit0 "STABLE=${st}"
say "STABLE=${st}"
[ "$st" = 1 ] || note 1

say "### ШАГ 3 стража текста и repo-review на файлах цикла ### $(date +%FT%T%:z)"
CYCLE_FILES="lab/e0124-run.sh $EXPECT crates/vecdht-node/tests/lease_after_restart.rs \
crates/vecdht-cli/tests/node_lease_status.rs crates/vecdht-node/src/node.rs \
crates/vecdht-node/src/lease.rs crates/vecdht-cli/src/node_cmd.rs \
crates/vecdht-node/tests/restart_recovery.rs lab/hypotheses/H-0124-lease-after-restart.md \
lab/experiments/E-0124-lease-after-restart.md lab/decisions/ADR-0065-lease-grant-is-durable.md"
# shellcheck disable=SC2086
bash lab/check-text-clean.sh $CYCLE_FILES 2>&1 | tail -3 | tee -a "$LOG"
rct=${PIPESTATUS[0]}
note "$rct"
emit0 "TEXTGUARD_CYCLE_EXIT=${rct}"
python lab/repo-review.py 2>&1 | tail -5 | tee -a "$LOG"
rcrr=${PIPESTATUS[0]}
emit0 "REPO_REVIEW_EXIT=${rcrr}"

say "### ШАГ 4 посадка: неверное ожидание обязано краснеть ### $(date +%FT%T%:z)"
awk -F'\t' 'BEGIN{OFS="\t"} $1=="LR_PLANT_REJECTED"{$2="1"} {print}' "$EXPECT" > "$OUT/plant.tsv"
if ! grep -q $'^LR_PLANT_REJECTED\t1\t' "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка LR_PLANT_REJECTED в таблице не найдена"
  plant=0
else
  python lab/expect.py "$OUT/plant.tsv" "$OUT/facts1.txt" "$G" > "$OUT/plant.out" 2>&1
  plant=$([ $? -ne 0 ] && echo 1 || echo 0)
fi
emit0 "PLANT_EXIT=${plant}"
say "PLANT_EXIT=${plant}"
[ "$plant" = 1 ] || note 1

say "### ШАГ 5 ожидания ### $(date +%FT%T%:z)"
for f in "$OUT/facts1.txt" "$OUT/facts2.txt"; do cat "$G" >> "$f"; done
python lab/expect.py "$EXPECT" "$OUT/facts1.txt" "$OUT/facts2.txt" 2>&1 | tail -n 25 | tee -a "$LOG"
rce=${PIPESTATUS[0]}
note "$rce"
emit0 "EXPECT_EXIT=${rce}"

say "### ШАГ 6 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
