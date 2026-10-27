#!/usr/bin/env bash
# A7b / E-0130 (ADR-0071): счётчик аптайма переживает рестарт, а отказ печатается словами.
#
# Что мерится. Три наблюдаемых свойства одного числа, а не «наличие файла»:
# (1) `cargo test -q -p vecdht-cli --lib uptime::` — арифметика ledger'а и формат (7 тестов, включая
#     ветку отката настенных часов, которую интеграционный прибор не воспроизводит);
# (2) `cargo test -q -p vecdht-cli --test node_run` — тест
#     `node_uptime_counter_survives_restart_and_refuses_corruption`: два настоящих процесса
#     `node run` с одним `--dir`, отчёт `node uptime` по живому и по закрытому узлу, подставленный
#     битый `uptime.bin`, каталог без истории и сброс явным флагом; 31 инвариантный факт `UP_*`.
# Сырые секунды (`uptime_total_sec`, `uptime_open_sec`) фактами не печатаются: они зависят от
# расписания битов и от часов хоста, и по `ADR-0070` clock-зависимое наблюдение живёт только в
# носителе — строки узла эхом уходят в вывод теста.
#
# PRE_FIX: тот же прибор на дереве `80b81c0`, где правки нет (product-файлы временно берутся из
# пина, тесты остаются текущими; по завершении файлы возвращаются по sha256 — см. trap). Файл
# `uptime.rs` на пине не объявлен ни в одном `mod`, поэтому его можно не трогать: он не компилируется.
#
# Порог: lab/expectations/e0130.tsv.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG=lab/logs/e0130-all.log
PRE_FIX_PIN=80b81c0
EXPECT=lab/expectations/e0130.tsv
PRODUCT=(crates/vecdht-cli/src/lib.rs crates/vecdht-cli/src/node_cmd.rs)
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0130.XXXXXX")
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

# Факт из вывода прибора: строка `KEY=значение`, найденная по границе слова (не по `^KEY`): libtest
# в quiet-режиме дописывает в первую строку вывода теста символ прогресса `.`, и якорь по началу
# строки терял бы ровно те факты, что печатаются первыми (ДИАГНОЗ `E-0124`).
fact() { # fact <файл-вывода> <ключ>
  grep -m1 -oE "\b${2}=[^ ]*" "$1" 2>/dev/null | head -1 | sed "s/^${2}=//" || true
}
# Факты PRE_FIX печатаются литералом имени, а не циклом по ключам: страж `lab/threshold-lint.py`
# требует, чтобы каждое имя ожидания стояло в источнике текстом.
facts_from() {
  grep -oE '\bUP_[A-Z0-9_]+=[^ ]*' "$1" 2>/dev/null
}
# Число passed/failed из последней строки `test result:` (append-only вывод: середина не показатель).
res_num() { # res_num <файл> <passed|failed>
  grep 'test result:' "$1" 2>/dev/null | tail -1 | grep -oE "[0-9]+ ${2}" | head -1 | awk '{print $1}'
}

say "########## E-0130 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 гейт, носитель до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0130 2>&1 | tail -n 12 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
emit0 "GATE_H0130_OK=${gok}"
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
git cat-file -e "${PRE_FIX_PIN}:crates/vecdht-cli/src/node_cmd.rs" 2>/dev/null || say "ПИН НЕ НАЙДЕН"
git checkout "$PRE_FIX_PIN" -- "${PRODUCT[@]}" 2>&1 | tee -a "$LOG"
note "$?"
say "checkout сделан; упоминаний uptime в node_cmd.rs: $(grep -c 'uptime' crates/vecdht-cli/src/node_cmd.rs || true)"
t0=$(date +%s)
cargo test -q -p vecdht-cli --test node_run -- --nocapture --test-threads=1 > "$OUT/prefix-cli.txt" 2>&1
rcp=$?
t1=$(date +%s)
say "PRE_FIX node_run: exit=${rcp} секунд=$((t1 - t0))"
cp "$OUT/prefix-cli.txt" lab/logs/e0130-prefix-cli.log
facts_from "$OUT/prefix-cli.txt" | sort | tee -a "$LOG" >/dev/null
v=$(fact "$OUT/prefix-cli.txt" UP_FILE_BYTES);                 emit0 "PRE_FIX_FILE_BYTES=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_OPEN1_STATUS);               emit0 "PRE_FIX_OPEN1_STATUS=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_MISSING_PRINTED);            emit0 "PRE_FIX_MISSING_PRINTED=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_STATUS_HAS_ALL_FIELDS);      emit0 "PRE_FIX_STATUS_HAS_ALL_FIELDS=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_STATUS_UPTIME_SESSIONS);     emit0 "PRE_FIX_STATUS_SESSIONS=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_RESTART_SESSIONS);           emit0 "PRE_FIX_RESTART_SESSIONS=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_LIVE_REPORT_CODE);           emit0 "PRE_FIX_LIVE_REPORT_CODE=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_CORRUPT_RUN_CODE);           emit0 "PRE_FIX_CORRUPT_RUN_CODE=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_CORRUPT_RUN_FAST_REFUSAL);   emit0 "PRE_FIX_CORRUPT_RUN_FAST_REFUSAL=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_CORRUPT_REPORT_CODE);        emit0 "PRE_FIX_CORRUPT_REPORT_CODE=${v:-MISSING}"
v=$(fact "$OUT/prefix-cli.txt" UP_RESET_CODE);                 emit0 "PRE_FIX_RESET_CODE=${v:-MISSING}"
emit0 "PRE_FIX_TEST_FAILED=$(res_num "$OUT/prefix-cli.txt" failed)"
restore_product
for f in "${PRODUCT[@]}"; do
  want=$(sha256sum < "$KEEP/$(echo "$f" | tr '/' '@')" | cut -d' ' -f1)
  got=$(sha256sum < "$f" | cut -d' ' -f1)
  if [ "$want" != "$got" ]; then
    say "ВОССТАНОВЛЕНИЕ НЕ СРАБОТАЛО: $f"
    note 1
  fi
done
say "product-файлы возвращены; упоминаний uptime в node_cmd.rs: $(grep -c 'uptime' crates/vecdht-cli/src/node_cmd.rs || true)"

say "### ШАГ 2 модульные тесты формата и арифметики ### $(date +%FT%T%:z)"
cargo test -q -p vecdht-cli --lib uptime:: > "$OUT/lib-up.txt" 2>&1
rcl=$?
note "$rcl"
emit0 "LIB_EXIT=${rcl}"
emit0 "LIB_UP_PASSED=$(res_num "$OUT/lib-up.txt" passed)"
cargo test -q -p vecdht-cli --lib > "$OUT/lib-all.txt" 2>&1
rcall=$?
note "$rcall"
emit0 "LIB_PASSED=$(res_num "$OUT/lib-all.txt" passed)"
say "LIB: uptime_exit=${rcl} uptime_passed=$(res_num "$OUT/lib-up.txt" passed) all_exit=${rcall} all_passed=$(res_num "$OUT/lib-all.txt" passed)"

say "### ШАГ 3 два прогона прибора на неизменном дереве ### $(date +%FT%T%:z)"
for i in 1 2; do
  FACTS="$OUT/facts${i}.txt"
  : > "$FACTS"
  t0=$(date +%s)
  cargo test -q -p vecdht-cli --test node_run -- --nocapture --test-threads=1 > "$OUT/cli${i}.txt" 2>&1
  rcc=$?
  t1=$(date +%s)
  say "ПРОГОН${i}: cli=${rcc} секунд=$((t1 - t0))"
  note "$rcc"
  emit0 "CLI_EXIT=${rcc}"
  emit0 "CLI_FAILED=$(res_num "$OUT/cli${i}.txt" failed)"
  emit0 "CLI_PASSED=$(res_num "$OUT/cli${i}.txt" passed)"
  if [ "$rcc" -ne 0 ]; then
    cp "$OUT/cli${i}.txt" "lab/logs/e0130-cli${i}-fail.txt"
    say "RED RUN${i}: вывод сохранён в lab/logs"
  fi
  facts_from "$OUT/cli${i}.txt" | sort -u > "$FACTS"
  cat "$FACTS" | tee -a "$LOG"
done

if diff -q "$OUT/facts1.txt" "$OUT/facts2.txt" >/dev/null 2>&1; then st=1; else st=0; fi
emit0 "STABLE=${st}"
say "STABLE=${st}"
[ "$st" = 1 ] || note 1

say "### ШАГ 4 стража текста и repo-review на файлах цикла ### $(date +%FT%T%:z)"
CYCLE_FILES="lab/e0130-run.sh lab/check-text-clean.sh $EXPECT crates/vecdht-cli/tests/node_run.rs \
crates/vecdht-cli/src/uptime.rs crates/vecdht-cli/src/node_cmd.rs crates/vecdht-cli/src/lib.rs \
lab/hypotheses/H-0130-uptime-counter-anchored-to-start.md \
lab/experiments/E-0130-uptime-counter-anchored-to-start.md \
lab/decisions/ADR-0071-uptime-counter-survives-restart.md"
# shellcheck disable=SC2086
bash lab/check-text-clean.sh $CYCLE_FILES 2>&1 | tail -3 | tee -a "$LOG"
rct=${PIPESTATUS[0]}
note "$rct"
emit0 "TEXTGUARD_CYCLE_EXIT=${rct}"
python lab/repo-review.py 2>&1 | tail -6 | tee -a "$LOG"
rcrr=${PIPESTATUS[0]}
emit0 "REPO_REVIEW_EXIT=${rcrr}"

say "### ШАГ 4b самопроверка стража текста: escape-исключение не должны быть индульгенцией ### $(date +%FT%T%:z)"
# Правка стража (исключение «обратный слэш + латиница» для `"\nВсе"`) проверяется посадкой, а не
# словом: файл содержит три законных строки с escape и две посаженных опечатки. Законные не должны
# давать грязи, посаженные — обязаны, причём названными номерами строк. Без этого исключения страж
# краснел на чужих строках `crates/vecdht-cli/src/lib.rs:316,324` — то есть на тексте, которого в
# цикле нет (ДИАГНОЗ).
GST="$OUT/guard-selftest.rs"
# Посадка собирается из маркера `%%`, а не записана в помощнике прямо: строка с дефектом-гибридом,
# напечатанная в самом помощнике, красила бы проверку текста на файлах цикла (страж не различает
# «цитату» вне код-спа). Маркер и его замена видны в логе, так что посадка не прячется.
cat > "$GST" <<'GST_EOF'
fn a() {
    out.push_str("\nВсе hex-поля — ровно 2N строчных символов");
    Some(c) => format!("{}\n\nФЛАГИ:\n{}", c.help, flag_list(c.flags)),
    s.push("hello\nбайт%% мир");
    t.push_str("\tтабличка");
    u.push_str("простой гибрид байт%% без слэша");
}
GST_EOF
sed -i 's/%%/e/g' "$GST"
bash lab/check-text-clean.sh "$GST" > "$OUT/guard-selftest.txt" 2>&1
rcg=$?
emit0 "GUARD_SELFTEST_EXIT=${rcg}"
emit0 "GUARD_SELFTEST_HITS=$(grep -c '^ГРЯЗНО' "$OUT/guard-selftest.txt")"
LINES=$(grep -oE ':[0-9]+: гибрид' "$OUT/guard-selftest.txt" | grep -oE '[0-9]+' | paste -sd, -)
emit0 "GUARD_SELFTEST_LINES=${LINES}"
# Красный выход здесь и есть зелёный результат: страж обязан отбрить посадку и не закраснеть
# от законных escape. Поэтому вердикт считается не от кода возврата, а от совращения трёх чисел.
hits=$(grep -c '^ГРЯЗНО' "$OUT/guard-selftest.txt")
if [ "$rcg" != 1 ] || [ "$hits" != 2 ] || [ "$LINES" != "4,6" ]; then
  say "САМОПРОВЕРКА СТРАЖА НЕ ПРОЙДЕНА: exit=${rcg} грязью=${hits} строки=${LINES} (ждали exit 1, две строки, 4 и 6)"
  note 1
fi
say "guard-selftest: exit=${rcg} грязью=${hits} строки=${LINES}"

say "### ШАГ 5 посадка: неверное ожидание обязано краснеть ### $(date +%FT%T%:z)"
awk -F'\t' 'BEGIN{OFS="\t"} $1=="UP_RESTART_SESSIONS"{$2="1"} {print}' "$EXPECT" > "$OUT/plant.tsv"
if ! grep -q $'^UP_RESTART_SESSIONS\t1\t' "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка UP_RESTART_SESSIONS в таблице не найдена"
  plant=0
else
  python lab/expect.py "$OUT/plant.tsv" "$OUT/facts1.txt" "$G" > "$OUT/plant.out" 2>&1
  plant=$([ $? -ne 0 ] && echo 1 || echo 0)
fi
emit0 "PLANT_EXIT=${plant}"
say "PLANT_EXIT=${plant}"
[ "$plant" = 1 ] || note 1

say "### ШАГ 6 ожидания ### $(date +%FT%T%:z)"
for f in "$OUT/facts1.txt" "$OUT/facts2.txt"; do cat "$G" >> "$f"; done
python lab/expect.py "$EXPECT" "$OUT/facts1.txt" "$OUT/facts2.txt" 2>&1 | tail -n 30 | tee -a "$LOG"
rce=${PIPESTATUS[0]}
note "$rce"
emit0 "EXPECT_EXIT=${rce}"
say "EXPECT_ROWS=$(grep -cvE '^(#|$)' "$EXPECT")"

say "### ШАГ 7 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
