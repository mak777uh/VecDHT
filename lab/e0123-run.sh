#!/usr/bin/env bash
# A6 / E-0123: §18.9 спеки v8 обязан быть картой «слово → id замера», а не списком обещаний.
#
# Что мерится. (1) Прибор `lab/check-claim-map.py` краснеть умеет: `--selftest` ловит и клаузу без
# метки (3 посадки из 8 случаев), и выдуманные ссылки (id без карточки, `.rs` без файла). (2) PRE_FIX:
# на пине `a069eba` (до правки раздела) тот же прибор находит 6 немаркированных клауз из 8 и выходит 1.
# (3) После правки: немаркированных 0, отсылок без карточки/файла 0, выход 0, число клауз не меньше 8,
# и два прогона на неизменном дереве дают одинаковый набор фактов. (4) Посадки красные: клауза без
# метки, добавленная в копию раздела, обязана быть найдена (PLANT_GUARD=1), а подделанное ожидание —
# отклонено expect.py (PLANT_EXIT=1). (5) Зеркало спеки и страж текста зелёные.
#
# Cargo-ярус здесь не запускается: цикл правит markdown и собственный grep-прибор, прецедент S-0004
# и E-0086 (docs-цикл = mirror + YAML + diff + стражи вместо полной верификации).
#
# Порог: SELFTEST_*=8/8/3/3 и вердикт 1, PRE_SENTENCES=8, PRE_UNMAPPED=6, PRE_EXIT=1,
# CLAIMMAP_UNMAPPED=0, CLAIMMAP_MISSING_IDS=0, CLAIMMAP_MISSING_INSTRUMENTS=0, CLAIMMAP_EXIT=0,
# CLAIMMAP_SENTENCES_GE8=1, STABLE=1, PLANT_GUARD=1, PLANT_EXIT=1, MIRROR_EXIT=0,
# TEXTGUARD_CYCLE_EXIT=0, REPOREVIEW_EXIT=0, DISK_GE_15000=1, WORST_RC=0.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG=lab/logs/e0123-all.log
PRE_FIX_PIN=a069eba
SPEC=docs/VecDHT-SPEC-v8.md
EXPECT=lab/expectations/e0123.tsv
mkdir -p lab/logs
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0123.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
G="$OUT/facts_global.txt"
: > "$G"
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }
emit() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$FACTS"; }

# Разбирает сводную строку стража в отдельные факты. Приставка нужна, чтобы PRE_* и пост-замер
# не совпадали именами: expect.py ищет ключ в начале строки или после пробела.
parse_map() {
  # $1 = строка CLAIMMAP_…, $2 = префикс фактов
  local line="$1" pre="$2"
  for key in SENTENCES UNMAPPED IDS MISSING_IDS INSTRUMENTS MISSING_INSTRUMENTS; do
    val=$(printf '%s' "$line" | sed -n "s/.*CLAIMMAP_${key}=\([0-9-]*\).*/\1/p")
    emit "${pre}${key}=${val:--1}"
  done
}

say "########## E-0123 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 гейт и носитель до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py gate H-0123 2>&1 | tail -n 10 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
emit0 "GATE_H0123_OK=${gok}"
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

say "### ШАГ 1 селфтест прибора: посадки обязаны отстреливаться ### $(date +%FT%T%:z)"
python lab/check-claim-map.py --selftest > "$OUT/selftest.txt" 2>&1
rcs=$?
note "$rcs"
say "SELFTEST: $(cat "$OUT/selftest.txt" | tr '\n' ' ')"
st_line=$(grep -m1 '^СЕЛФТЕСТ всего=' "$OUT/selftest.txt")
st_refs=$(grep -m1 '^СЕЛФТЕСТ_ССЫЛКИ' "$OUT/selftest.txt")
st_total=$(printf '%s' "$st_line" | sed -n 's/.*всего=\([0-9]*\).*/\1/p')
st_pass=$(printf '%s' "$st_line" | sed -n 's/.*прошло=\([0-9]*\).*/\1/p')
st_plant=$(printf '%s' "$st_line" | sed -n 's/.*посажено=\([0-9]*\).*/\1/p')
st_caught=$(printf '%s' "$st_line" | sed -n 's/.*поймано=\([0-9]*\).*/\1/p')
st_refs_ok=$(printf '%s' "$st_refs" | sed -n 's/.*вердикт=\([0-9]*\).*/\1/p')
emit0 "SELFTEST_EXIT=${rcs}"
emit0 "SELFTEST_TOTAL=${st_total:--1}"
emit0 "SELFTEST_PASSED=${st_pass:--1}"
emit0 "SELFTEST_PLANTED=${st_plant:--1}"
emit0 "SELFTEST_CAUGHT=${st_caught:--1}"
emit0 "SELFTEST_REFS_VERDICT=${st_refs_ok:--1}"
[ "$rcs" -eq 0 ] || note 1

say "### ШАГ 2 PRE_FIX: страж на §18.9 пина ${PRE_FIX_PIN} (до правки) ### $(date +%FT%T%:z)"
if git merge-base --is-ancestor "$PRE_FIX_PIN" HEAD 2>/dev/null; then anc=1; else anc=0; fi
emit0 "BASE_IS_ANCESTOR=${anc}"
[ "$anc" -eq 1 ] || note 1
git show "${PRE_FIX_PIN}:${SPEC}" > "$OUT/spec_base.md" 2>/dev/null
FACTS="$OUT/facts_pre.txt"; : > "$FACTS"
python lab/check-claim-map.py --path "$OUT/spec_base.md" > "$OUT/pre.out" 2>"$OUT/pre.err"
pre_rc=$?
pre_line=$(tail -1 "$OUT/pre.out")
say "PRE: ${pre_line}"
say "PRE БЕЗ_ID строк: $(grep -c '^БЕЗ_ID:' "$OUT/pre.err")"
parse_map "$pre_line" "PRE_CLAIMMAP_"
emit "PRE_CLAIMMAP_EXIT=${pre_rc}"
cat "$OUT/facts_pre.txt" >> "$G"
# Порог утверждает: до правки 8 клауз, 6 без метки, выход 1.
[ "$pre_rc" -eq 1 ] || note 1

say "### ШАГ 3 страж на отредактированном разделе, два прогона на неизменном дереве ### $(date +%FT%T%:z)"
for i in 1 2; do
  FACTS="$OUT/facts${i}.txt"
  : > "$FACTS"
  python lab/check-claim-map.py > "$OUT/map${i}.out" 2>"$OUT/map${i}.err"
  rc=$?
  map_line=$(tail -1 "$OUT/map${i}.out")
  say "RUN${i}: ${map_line}"
  if [ -s "$OUT/map${i}.err" ]; then sed -n '1,12p' "$OUT/map${i}.err" | tee -a "$LOG"; fi
  parse_map "$map_line" "CLAIMMAP_"
  emit "CLAIMMAP_EXIT=${rc}"
  s_count=$(printf '%s' "$map_line" | sed -n 's/.*CLAIMMAP_SENTENCES=\([0-9-]*\).*/\1/p')
  if [ "${s_count:-0}" -ge 8 ]; then ge8=1; else ge8=0; fi
  emit "CLAIMMAP_SENTENCES_GE8=${ge8}"
  note "$rc"
  sort -o "$FACTS" "$FACTS"
done
if diff -q "$OUT/facts1.txt" "$OUT/facts2.txt" >/dev/null 2>&1; then st=1; else st=0; fi
emit0 "STABLE=${st}"
say "STABLE=${st}"
[ "$st" -eq 1 ] || note 1

say "### ШАГ 4 посадка в текст: клауза без метки обязана быть найдена ### $(date +%FT%T%:z)"
awk 'BEGIN{done=0} /^- P0/ && !done {print; print "- рестарт primary описан словами и ничем не подтверждён"; done=1; next} {print}' \
  "$SPEC" > "$OUT/spec_planted.md"
if ! grep -q 'ничем не подтверждён' "$OUT/spec_planted.md"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: клауза в копию не добавлена"
  pg=0; pu=0
else
  python lab/check-claim-map.py --path "$OUT/spec_planted.md" > "$OUT/plant_guard.out" 2>/dev/null
  prc=$?
  plant_line=$(tail -1 "$OUT/plant_guard.out")
  say "PLANT_GUARD: ${plant_line} (exit=${prc})"
  pu=$(printf '%s' "$plant_line" | sed -n 's/.*CLAIMMAP_UNMAPPED=\([0-9-]*\).*/\1/p')
  pg=$([ "$prc" -ne 0 ] && echo 1 || echo 0)
fi
emit0 "PLANT_GUARD=${pg}"
emit0 "PLANT_UNMAPPED=${pu:--1}"
[ "$pg" -eq 1 ] || note 1

say "### ШАГ 5 зеркало спеки и страж текста ### $(date +%FT%T%:z)"
bash lab/check-spec-mirror.sh > "$OUT/mirror.txt" 2>&1
rcm=$?
note "$rcm"
emit0 "MIRROR_EXIT=${rcm}"
say "MIRROR: $(tail -2 "$OUT/mirror.txt" | tr '\n' ' ')"
bash lab/check-text-clean.sh lab/e0123-run.sh "$EXPECT" \
  lab/hypotheses/H-0123-claim-map-18-9.md lab/experiments/E-0123-claim-map-18-9.md \
  lab/check-claim-map.py "$SPEC" 2>&1 | tail -3 | tee -a "$LOG"
rct=${PIPESTATUS[0]}
note "$rct"
emit0 "TEXTGUARD_CYCLE_EXIT=${rct}"

say "### ШАГ 6 страж репозитория ### $(date +%FT%T%:z)"
python lab/repo-review.py > "$OUT/review.txt" 2>&1
rcv=$?
note "$rcv"
emit0 "REPOREVIEW_EXIT=${rcv}"
say "REVIEW: $(tail -2 "$OUT/review.txt" | tr '\n' ' ')"

say "### ШАГ 7 посадка в таблицу: неверное ожидание обязано краснеть ### $(date +%FT%T%:z)"
for f in "$OUT/facts1.txt" "$OUT/facts2.txt"; do cat "$G" >> "$f"; done
awk -F'	' 'BEGIN{OFS="	"} $1=="CLAIMMAP_UNMAPPED"{$2="1"} {print}' "$EXPECT" > "$OUT/plant.tsv"
if ! grep -q $'^CLAIMMAP_UNMAPPED\t1\t' "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка CLAIMMAP_UNMAPPED в таблице не найдена"
  plant=0
else
  python lab/expect.py "$OUT/plant.tsv" "$OUT/facts1.txt" "$OUT/facts2.txt" > "$OUT/plant.out" 2>&1
  plant=$([ $? -ne 0 ] && echo 1 || echo 0)
fi
emit0 "PLANT_EXIT=${plant}"
say "PLANT_EXIT=${plant}"
[ "$plant" -eq 1 ] || note 1

say "### ШАГ 8 ожидания ### $(date +%FT%T%:z)"
for f in "$OUT/facts1.txt" "$OUT/facts2.txt"; do cat "$G" >> "$f"; done
python lab/expect.py "$EXPECT" "$OUT/facts1.txt" "$OUT/facts2.txt" 2>&1 | tail -n 25 | tee -a "$LOG"
rce=${PIPESTATUS[0]}
note "$rce"

say "### ШАГ 9 носитель после прогона ### $(date +%FT%T%:z)"
bash lab/disk-report.sh 2>&1 | tail -n 3 | tee -a "$LOG"

say "WORST_RC=$WORST"
exit "$WORST"
