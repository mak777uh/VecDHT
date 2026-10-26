#!/usr/bin/env bash
# A5 / E-0122: сценарий двух машин исполним командами из README.
#
# Что мерится. Не «скрипт существует», а: (1) `key show` выводит те же owner/PeerId, что
# использует `node run` (одни и те же функции вывода из seed; тест `cli.rs`); (2) три настоящих
# узла шарда 0, поднятых CLI, принимают публикацию через primary, а поиск с другого узла находит
# ту же запись: владелец и слот равны опубликованным, `d2 = 0`, совпадение одно; (3) текст
# сценария лежит в шарде 0 (cluster 9); (4) каталог церемонии читают и `serve`, и клиенты.
# Сеть — 127.0.0.1: это dry-run одной машины, а не двухмашинный прогон (его делает владелец).
#
# PRE_FIX — пин `faac87e` (вершина до фикса): на нём нет ни команды `key show`, ни `lab/two-hosts.sh`.
# «До» — это отсутствие сценария, а не красный тест: оракул появляется вместе со сценарием.
#
# Порог: KEYSHOW_EXIT=0/PASSED=1, HOSTS_OK=1, HOSTS_PUBLISH_OK=1, HOSTS_FIND_OK=1, HOSTS_MATCH=1,
# D2=0, MATCHES=1, HOSTS_TEXT_SHARD=0, OWNER_EQ=1, SLOT_EQ=1, STABLE=1, EXPECT_EXIT=0,
# PLANT_EXIT=1, PRE_FIX_*=1, README_*_OK=1, TEXTGUARD_CYCLE_EXIT=0, диск ≥ 15 000 МБ.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG=lab/logs/e0122-all.log
PRE_FIX_PIN=faac87e
EXPECT=lab/expectations/e0122.tsv
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0122.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
G="$OUT/facts_global.txt"
: > "$G"
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }

say "########## E-0122 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 гейт и носитель до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0122 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
emit0 "GATE_H0122_OK=${gok}"
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

say "### ШАГ 1 PRE_FIX: на дереве ${PRE_FIX_PIN} сценария нет ### $(date +%FT%T%:z)"
if git merge-base --is-ancestor "$PRE_FIX_PIN" HEAD 2>/dev/null; then anc=1; else anc=0; fi
if git cat-file -e "${PRE_FIX_PIN}:crates/vecdht-cli/src/key_cmd.rs" 2>/dev/null; then kc=1; else kc=0; fi
if git cat-file -e "${PRE_FIX_PIN}:lab/two-hosts.sh" 2>/dev/null; then th=1; else th=0; fi
if [ "$anc" = 1 ] && [ "$kc" = 0 ]; then pk=1; else pk=0; fi
if [ "$anc" = 1 ] && [ "$th" = 0 ]; then ps=1; else ps=0; fi
say "BASE_IS_ANCESTOR=${anc} PRE_FIX_KEY_CMD=${kc} PRE_FIX_SCRIPT=${th} PRE_FIX_NO_KEY_SHOW=${pk} PRE_FIX_NO_SCRIPT=${ps}"
emit0 "BASE_IS_ANCESTOR=${anc}"
emit0 "PRE_FIX_NO_KEY_SHOW=${pk}"
emit0 "PRE_FIX_NO_SCRIPT=${ps}"
[ "$pk" -eq 1 ] || note 1
[ "$ps" -eq 1 ] || note 1

say "### ШАГ 2 key show совпадает с выводом из seed ### $(date +%FT%T%:z)"
cargo test -q -p vecdht-cli --test cli key_show > "$OUT/keyshow.txt" 2>&1
rck=$?
note "$rck"
summary=$(grep 'test result:' "$OUT/keyshow.txt" | tail -1)
say "KEYSHOW: ${summary:-<нет строки test result>}"
passed=$(printf '%s' "$summary" | sed -n 's/.*ok\. \([0-9]\+\) passed.*/\1/p')
failed=$(printf '%s' "$summary" | sed -n 's/.* \([0-9]\+\) failed.*/\1/p')
emit0 "KEYSHOW_EXIT=${rck}"
emit0 "KEYSHOW_PASSED=${passed:-0}"
emit0 "KEYSHOW_FAILED=${failed:-0}"
[ "$rck" -eq 0 ] || note 1

say "### ШАГ 3 README называет сценарий и честно говорит, что двух хостов ещё не было ### $(date +%FT%T%:z)"
ren=0
if grep -qF 'lab/two-hosts.sh' README.md && grep -qF 'not been run on two hosts' README.md; then ren=1; fi
rru=0
if grep -qF 'lab/two-hosts.sh' README.ru.md && grep -qF 'на двух хостах он ещё не исполнялся' README.ru.md; then rru=1; fi
say "README_EN_OK=${ren} README_RU_OK=${rru}"
emit0 "README_EN_OK=${ren}"
emit0 "README_RU_OK=${rru}"
[ "$ren" -eq 1 ] || note 1
[ "$rru" -eq 1 ] || note 1

say "### ШАГ 4 сборка CLI и два прогона selfcheck на неизменном дереве ### $(date +%FT%T%:z)"
cargo build -q -p vecdht-cli > "$OUT/build.txt" 2>&1
rcb=$?
note "$rcb"
say "BUILD_EXIT=${rcb}"
emit0 "BUILD_EXIT=${rcb}"
if [ -x target/debug/vecdht-cli.exe ]; then CLI_PATH=target/debug/vecdht-cli.exe; else CLI_PATH=target/debug/vecdht-cli; fi
export VECDHT_CLI="$CLI_PATH"

extract() {
  # ДИАГНОЗ (первый прогон helper'а): признак строки (`seen_find`) ставился в конце обработки
  # строки, поэтому поля OWNER/SLOT/D2/MATCHES той же строки разбирались ещё как «публикация».
  # Теперь вид строки определяется по `$1` до разбора полей; факты те же, порог не менялся.
  awk '
    { is_pub = ($1 ~ /^HOSTS_PUBLISH_OK=/); is_find = ($1 ~ /^HOSTS_FIND_OK=/);
      for (i=1;i<=NF;i++) { k=$i; sub(/=.*/,"",k); v=$i; sub(/^[^=]*=/,"",v);
        if (k=="HOSTS_CEREMONY") cer=v;
        else if (k=="HOSTS_TEXT_CLUSTER") tcl=v;
        else if (k=="HOSTS_TEXT_SHARD") tsh=v;
        else if (k=="HOSTS_PUBLISH_OK") pok=v;
        else if (k=="HOSTS_FIND_OK") fok=v;
        else if (k=="HOSTS_MATCH") mat=v;
        else if (k=="HOSTS_OK") ok=v;
        else if (k=="OWNER" && is_pub) pown=v;
        else if (k=="SLOT" && is_pub) pslot=v;
        else if (k=="OWNER" && is_find) fown=v;
        else if (k=="SLOT" && is_find) fslot=v;
        else if (k=="D2" && is_find) d2=v;
        else if (k=="MATCHES" && is_find) mcnt=v;
      }
    }
    END {
      print "HOSTS_CEREMONY=" (cer==""?"0":cer);
      print "HOSTS_TEXT_CLUSTER=" (tcl==""?"-1":tcl);
      print "HOSTS_TEXT_SHARD=" (tsh==""?"-1":tsh);
      print "HOSTS_PUBLISH_OK=" (pok==""?"0":pok);
      print "HOSTS_FIND_OK=" (fok==""?"0":fok);
      print "HOSTS_MATCH=" (mat==""?"0":mat);
      print "HOSTS_OK=" (ok==""?"0":ok);
      print "PUB_SLOT=" (pslot==""?"-1":pslot);
      print "FIND_SLOT=" (fslot==""?"-1":fslot);
      print "FIND_D2=" (d2==""?"-1":d2);
      print "FIND_MATCHES=" (mcnt==""?"-1":mcnt);
      print "OWNER_EQ=" ((pown!="" && pown==fown)?1:0);
      print "OWNER_LEN64=" ((length(pown)==64 && pown==fown)?1:0);
      print "SLOT_EQ=" ((pslot!="" && pslot==fslot)?1:0);
    }'
}

for i in 1 2; do
  FACTS="$OUT/facts${i}.txt"
  : > "$FACTS"
  t0=$(date +%s)
  bash lab/two-hosts.sh selfcheck > "$OUT/selfcheck${i}.txt" 2>&1
  rc=$?
  t1=$(date +%s)
  say "SELFCHECK${i}: exit=${rc} seconds=$((t1 - t0))"
  note "$rc"
  grep -E '^HOSTS_' "$OUT/selfcheck${i}.txt" | tail -n 6 | tee -a "$LOG"
  extract < "$OUT/selfcheck${i}.txt" | sort | tee -a "$LOG" >> "$FACTS"
  if [ "$rc" -ne 0 ]; then
    cp "$OUT/selfcheck${i}.txt" "lab/logs/e0122-run${i}-fail.txt"
    say "RED RUN${i}: вывод сохранён в lab/logs/e0122-run${i}-fail.txt"
  fi
done

if diff -q "$OUT/facts1.txt" "$OUT/facts2.txt" >/dev/null 2>&1; then st=1; else st=0; fi
emit0 "STABLE=${st}"
say "STABLE=${st}"
[ "$st" -eq 1 ] || note 1

say "### ШАГ 5 стража текста на файлах цикла ### $(date +%FT%T%:z)"
bash lab/check-text-clean.sh lab/e0122-run.sh "$EXPECT" \
  lab/hypotheses/H-0122-two-hosts-walkthrough.md lab/experiments/E-0122-two-hosts-walkthrough.md \
  lab/two-hosts.sh crates/vecdht-cli/src/key_cmd.rs crates/vecdht-cli/tests/cli.rs \
  README.md README.ru.md 2>&1 | tail -3 | tee -a "$LOG"
rct=${PIPESTATUS[0]}
note "$rct"
emit0 "TEXTGUARD_CYCLE_EXIT=${rct}"

say "### ШАГ 6 посадка: неверное ожидание обязано краснеть ### $(date +%FT%T%:z)"
awk -F'	' 'BEGIN{OFS="	"} $1=="HOSTS_MATCH"{$2="0"} {print}' "$EXPECT" > "$OUT/plant.tsv"
if ! grep -q $'^HOSTS_MATCH\t0\t' "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка HOSTS_MATCH в таблице не найдена"
  plant=0
else
  python lab/expect.py "$OUT/plant.tsv" "$OUT/facts1.txt" "$OUT/facts2.txt" > "$OUT/plant.out" 2>&1
  plant=$([ $? -ne 0 ] && echo 1 || echo 0)
fi
emit0 "PLANT_EXIT=${plant}"
say "PLANT_EXIT=${plant}"
[ "$plant" -eq 1 ] || note 1

say "### ШАГ 7 ожидания ### $(date +%FT%T%:z)"
for f in "$OUT/facts1.txt" "$OUT/facts2.txt"; do cat "$G" >> "$f"; done
python lab/expect.py "$EXPECT" "$OUT/facts1.txt" "$OUT/facts2.txt" 2>&1 | tail -n 20 | tee -a "$LOG"
rce=${PIPESTATUS[0]}
note "$rce"

say "### ШАГ 8 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
