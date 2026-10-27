#!/usr/bin/env bash
# Helper цикла E-0129 — «домен дат контура источников: хост живёт в UTC+3, runner — в UTC».
#
# Предмет: три файла лабораторного кода (`lab/library.py`, `lab/sources.py`,
# `lab/cycle-gate.py`), индекс `lab/library/index.jsonl` и два шага CI, которые по ним судят.
# Cargo не вызывается: правка не трогает продукт (`crates/**`), а красноту `verify` даёт именно
# лабораторный контур. Cargo-контур на этом дереве зелёный — это отдельное наблюдение runner'а,
# в вердикт цикла оно не входит (прецедент `L-0025`: чужой прогон локальному циклу не засчитывается).
#
# Измерение (`measure`) исполняется ДВАЖДЫ внутри одного вызова helper'а на неизменном дереве —
# файлы фактов сверяются `diff -q` (прецедент `E-0128`, строки 453–454: два исполнения в одном
# процессе, а не два вызова, потому что между вызовами дерево может измениться). Поэтому ни один
# замороженный ключ не содержит метки времени, числа строк журнала и текущей даты: `DDF_UTC_TODAY`,
# `DDF_LOCAL_TODAY`, `DDF_DOMAIN_SPLIT` и точное значение даты закрытия печатаются только в
# носитель — они меняются от часа снятия (правило 7, пункт (е)). В таблице вместо значения даты
# лежат его ФОРМА (`CLOSED_SHAPE_*`) и равенство дат в двух часовых поясах (`WRITE_TZ_MATCH`).
#
# Пятая ловушка этого цикла найдена им самим, на полпути через полночь. Краснота PRE_FIX на пине
# бывает двух сортов: из байт дерева (семь вызовов местной даты, стёртое `opened`, аудит без гейта —
# они не меняются никогда) и из часов съёма (`library.py` пина судит по настенным часам, и его
# красный выход держался только пока UTC-день не догнал местный). Второе в таблицу не входит:
# `PRE_FIX_LIBCHECK_*` и `PRE_FIX_DOMAIN_RED_GREEN` из неё убраны и печатаются только в носитель.
# Вместо них там инвариантные свидетели того же расхождения: `PRE_FIX_PIN_FUTURE_DATES=4` (в индексе
# пина лежат даты позже его UTC-дня — это след местного домена в байтах, он не зависит от того,
# когда прогнали helper) и `PRE_FIX_DDF_DATES_AFTER_UTC=4`, снятый с замороженными часами прибора
# (`VEC_DHT_DDF_TODAY`, шов есть только у измерителя, механизм дату из окружения не берёт). Проверка
# сработала в тот же вечер: первый прогон после 00:00 UTC дал бы на пине `DATES_AFTER_UTC=0`, то
# есть зелёный PRE_FIX на красном дереве.
#
# Четыре ловушки перенесены из закрытых циклов: вывод `subprocess` без явной кодировки декодируется
# локальной страницей (cp1251) и падает на кириллице; сводные утверждения печатаются ключами, а не
# подписями; форма захвата кода — `r=0` + `cmd || r=$?` (класс `E-0128`: точка с запятой убила бы
# этот helper сама); контроль «аудит красен по находкам» нельзя снимать живыми карточками пина,
# потому что на пине у последних пяти карточек ноль нарушений — посадка делается в копии дерева
# (класс `E-0087`, ДИАГНОЗ-1: невыполнимый по построению контроль — это не контроль).

set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0129-all.log"
PIN=336e7d5
EXPECT="lab/expectations/e0129.tsv"
DD="lab/check-date-domain.py"
# Дата пина по UTC. PRE_FIX обязан судиться по НЕЙ, а не по часам съёма: иначе число находок на
# дереве пина зависит от того, до или после полуночи запустили helper, а замороженное ожидание,
# которое краснеет от расписания, — не факт (правило 7, пункт (е)). Шов `VEC_DHT_DDF_TODAY` есть
# только у прибора; механизм дату из окружения не берёт, поэтому подделать запись шов не может.
# Ловушка снята на живом примере: helper писали 26.10 около 23:45 UTC, и первый же прогон после
# полуночи дал бы на пине `DDF_DATES_AFTER_UTC=0` вместо 4 — то есть зелёный PRE_FIX на красном
# дереве.
CLK=2026-10-26
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0129.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
G="$OUT/facts_global.txt"
F1="$OUT/facts1.txt"
F2="$OUT/facts2.txt"
: > "$G"; : > "$F1"; : > "$F2"
F="$F1"

note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }
femit() { printf '%s\n' "$2" >> "$1"; printf '%s\n' "$2" | tee -a "$LOG" >/dev/null; }
# Факт из вывода прибора: строка `КЛЮЧ=значение` с якорем по началу строки. Пустое значение
# печатается как MISSING и красит сверку: молчание прогона не считается успехом.
flag() { # flag <файл> <ключ>
  local v
  v=$(sed -n "s|^${2}=||p" "$1" 2>/dev/null | head -1)
  [ -n "$v" ] || v=MISSING
  printf '%s' "$v"
}
val() { # val <файл-вывода> <ключ> — значение строки `КЛЮЧ=...`
  grep -aE "^$2=" "$1" 2>/dev/null | head -1 | sed "s|^$2=||"
}
field() { # field <файл> <начало строки> <поле> — `поле=NN` внутри сводной строки
  # Сводные строки приборов печатаются `КЛЮЧ а=1 б=2` (без `=` после КЛЮЧА), поэтому обычный `val`
  # их не видит и вернул бы пустоту, то есть ложную находку.
  grep -a "^$2" "$1" 2>/dev/null | head -1 | tr ' ' '\n' | grep -a "^$3=" | head -1 | sed "s|^$3=||"
}
count_of() { grep -aF -- "$2" "$1" 2>/dev/null | wc -l | tr -d ' '; }
all1() {
  local a
  for a in "$@"; do [ "$a" = 1 ] || { echo 0; return 0; }; done
  echo 1
}
# Сводное условие собирается в переменные и вызывается ОДНОЙ строкой. Причина не косметика:
# перенос строки обратной косой чертой ВНУТРИ `"$( … )"` байш не разбирает — файл с такими
# переносами не читается вовсе (`bash -n` падает на `}`). Однострочные вложения он переваривает,
# но длинное вложение в три уровня читается хуже двух коротких переменных.
is() { # is <значение> <эталон> -> 1 если равны
  if [ "$1" = "$2" ]; then echo 1; else echo 0; fi
}
nz() { # nz <значение> -> 1 если не ноль
  if [ "$1" != 0 ]; then echo 1; else echo 0; fi
}
# Годная по форме, но заведомо нарушающая гейт карточка: пустой `prior_art` («не сделан») и нет
# карточки эксперимента («не найдена — пре-регистрация»). Обе причины определяются содержимым
# карточки, а не часами и не сетью — иначе посадка зависела бы от расписания (правило 7 (е)).
plant_card() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<'MD'
---
id: H-9999
claim: посаженная карточка — пустой prior_art и нет карточки эксперимента
falsifier: прогон helper'а, если аудит возвращает ноль при нарушениях
oracle: лабораторный тест
date: 2026-10-26
prior_art: []
lean:
  решение: не применён
  причина: посадка гейта, модель не нужна
  пространство: нет
  без_времени: нет
  для_всех: нет
  дешевле_стенда: нет
---
MD
}

measure() {
  F="$1"
  local P ARCH o r v z t f before C1 C2 RT BAD a b c

  # ---------------------------------------------- ШАГ 1 · PRE_FIX на пине
  say "### ${2} ШАГ 1 PRE_FIX: нынешний прибор на дереве пина $PIN ### $(date +%FT%T%:z)"
  P="$OUT/${2}/prefix"; mkdir -p "$P/pin"
  r=0
  git archive "$PIN" | tar -x -C "$P/pin" || r=$?
  note "$r"
  ARCH="$P/pin"
  o="$P/check_pin.txt"
  r=0
  VEC_DHT_DDF_TODAY="$CLK" python "$DD" check --root "$ARCH" > "$o" 2>&1 || r=$?
  # Имена фактов печатаются литералом, а не собираются из переменной: замороженное ожидание должно
  # быть находимым в helper'е простым grep'ом (`threshold-lint.py` зовёт ключ без владельца сиротой).
  for k in DDF_LOCAL_TODAY_CALLS DDF_FUNNEL_FILES DDF_USE_WRITES_OPENED DDF_CLOSE_NO_CLOSED \
           DDF_AUDIT_NO_GATE DDF_DATES_AFTER_UTC DDF_LEGACY_LOCAL_STAMP DDF_RECORDS \
           DDF_FINDINGS DDF_BLIND DDF_CLOCK_FROZEN DDF_CLOCK_DATE; do
    [ "$(val "$o" "$k")" != MISSING ] || note 1
  done
  femit "$F" "PRE_FIX_DDF_LOCAL_TODAY_CALLS=$(val "$o" DDF_LOCAL_TODAY_CALLS)"
  femit "$F" "PRE_FIX_DDF_FUNNEL_FILES=$(val "$o" DDF_FUNNEL_FILES)"
  femit "$F" "PRE_FIX_DDF_USE_WRITES_OPENED=$(val "$o" DDF_USE_WRITES_OPENED)"
  femit "$F" "PRE_FIX_DDF_CLOSE_NO_CLOSED=$(val "$o" DDF_CLOSE_NO_CLOSED)"
  femit "$F" "PRE_FIX_DDF_AUDIT_NO_GATE=$(val "$o" DDF_AUDIT_NO_GATE)"
  femit "$F" "PRE_FIX_DDF_DATES_AFTER_UTC=$(val "$o" DDF_DATES_AFTER_UTC)"
  femit "$F" "PRE_FIX_DDF_LEGACY_LOCAL_STAMP=$(val "$o" DDF_LEGACY_LOCAL_STAMP)"
  femit "$F" "PRE_FIX_DDF_RECORDS=$(val "$o" DDF_RECORDS)"
  femit "$F" "PRE_FIX_DDF_FINDINGS=$(val "$o" DDF_FINDINGS)"
  femit "$F" "PRE_FIX_DDF_BLIND=$(val "$o" DDF_BLIND)"
  femit "$F" "PRE_FIX_DDF_CLOCK_FROZEN=$(val "$o" DDF_CLOCK_FROZEN)"
  femit "$F" "PRE_FIX_DDF_CLOCK_DATE=$(val "$o" DDF_CLOCK_DATE)"
  femit "$F" "PRE_FIX_DDF_EXIT=$r"
  [ "$r" -ne 0 ] || note 1
  # Часы PRE_FIX проверяются флагом, а не молчаливым допущением: замороженное значение должно быть
  # ровно датой пина, иначе весь блок ниже сравнивал бы пино с сегодняшним днём.
  a=$(is "$(flag "$F" PRE_FIX_DDF_CLOCK_FROZEN)" 1)
  b=$(is "$(flag "$F" PRE_FIX_DDF_CLOCK_DATE)" "$CLK")
  femit "$F" "PRE_FIX_CLOCK_FROZEN_OK=$(all1 "$a" "$b")"
  [ "$(flag "$F" PRE_FIX_CLOCK_FROZEN_OK)" = 1 ] || note 1

  # Независимый пересчёт находок пина без прибора: сколько дат в ИНДЕКСЕ пина лежат позже даты
  # пина. Это и есть след локального домена в байтах, и он инвариантен к часам съёма: число
  # считывается из дерева пина, а не из текущего дня.
  q="$P/pin_recount.txt"
  r=0
  python - "$ARCH/lab/library/index.jsonl" "$CLK" > "$q" 2>&1 <<'PY' || r=$?
import json, re, sys
path, cut = sys.argv[1], sys.argv[2]
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
n = 0
for line in open(path, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    row = json.loads(line)
    for k in ("verified", "opened", "closed"):
        s_ = str(row.get(k, ""))
        if DATE.match(s_) and s_ > cut:
            n += 1
print(f"PIN_FUTURE_DATES={n}")
PY
  note "$r"
  [ "$r" = 0 ] || note 1
  v=$(val "$q" PIN_FUTURE_DATES)
  femit "$F" "PRE_FIX_PIN_FUTURE_DATES=$v"
  a=$(is "$v" "$(flag "$F" PRE_FIX_DDF_DATES_AFTER_UTC)")
  b=$(nz "$v")
  femit "$F" "PRE_FIX_PIN_RECOUNT_EQ=$(all1 "$a" "$b")"
  [ "$(flag "$F" PRE_FIX_PIN_RECOUNT_EQ)" = 1 ] || note 1

  # Краснота runner'а в его окружении (TZ=UTC) против зелёного местного часа — наблюдение, привязанное
  # к МОМЕНТУ съёма: код `library.py` на пине читает настенные часы и шва у него нет, а замораживать
  # часы нельзя, подделывать предмет измерения — тоже. Поэтому эти три числа печатаются только в
  # носитель и в таблицу не входят (правило 7 (е); чужой прогон runner'а засвидетельствован отдельно
  # в носителе runner'а и локальному циклу не засчитывается — `L-0025`). Инвариантный свидетель
  # того же расхождения лежит выше: `PRE_FIX_PIN_FUTURE_DATES` — даты, записанные в местном домене.
  o="$P/libcheck_utc.txt"
  r=0
  TZ=UTC VEC_DHT_ROOT="$ARCH" python "$ARCH/lab/library.py" check > "$o" 2>&1 || r=$?
  say "${2} наблюдение (не факт таблицы): пин под TZ=UTC дал exit=$r errors=$(field "$o" LIBCHECK errors)"
  o="$P/libcheck_host.txt"
  r=0
  TZ=Australia/Sydney VEC_DHT_ROOT="$ARCH" python "$ARCH/lab/library.py" check > "$o" 2>&1 || r=$?
  say "${2} наблюдение (не факт таблицы): пин под TZ=Australia/Sydney дал exit=$r errors=$(field "$o" LIBCHECK errors)"
  a=$(nz "$(flag "$F" PRE_FIX_PIN_FUTURE_DATES)")
  b=$(is "$(flag "$F" PRE_FIX_DDF_USE_WRITES_OPENED)" 1)
  c=$(is "$(flag "$F" PRE_FIX_DDF_LOCAL_TODAY_CALLS)" 7)
  femit "$F" "PRE_FIX_DOMAIN_DEFECT_WITNESSED=$(all1 "$a" "$b" "$c")"
  [ "$(flag "$F" PRE_FIX_DOMAIN_DEFECT_WITNESSED)" = 1 ] || note 1

  # Третья ветка пина: аудит печатает `CYCLE …=FAIL нарушений=N` и выходит нулём — вердикт без
  # гейта. Снимается на посаженной карточке ВНУТРИ копии пина: живые карточки пина чисты, поэтому
  # на них ветка «FAIL при нулевом коде» была бы недостижима.
  plant_card "$ARCH/lab/hypotheses/H-9999-e0129-plant.md"
  o="$P/audit_pin.txt"
  r=0
  VEC_DHT_ROOT="$ARCH" python "$ARCH/lab/cycle-gate.py" audit -n 1 > "$o" 2>&1 || r=$?
  femit "$F" "PRE_FIX_AUDIT_PLANT_EXIT=$r"
  femit "$F" "PRE_FIX_AUDIT_PLANT_FAIL_LINES=$(count_of "$o" '=FAIL нарушений=')"
  a=$(is "$r" 0)
  b=$(nz "$(flag "$F" PRE_FIX_AUDIT_PLANT_FAIL_LINES)")
  femit "$F" "PRE_FIX_AUDIT_PIN_SILENT=$(all1 "$a" "$b")"
  [ "$(flag "$F" PRE_FIX_AUDIT_PIN_SILENT)" = 1 ] || note 1

  # ---------------------------------------------- ШАГ 2 · прибор на живом дереве
  say "### ${2} ШАГ 2 прибор на живом дереве ### $(date +%FT%T%:z)"
  o="$P/check_live.txt"
  r=0
  python "$DD" check --require-git > "$o" 2>&1 || r=$?
  for k in DDF_FILES DDF_DATE_FILES DDF_LOCAL_TODAY_CALLS DDF_CUTOVER DDF_FUNNEL_FILES \
           DDF_USE_WRITES_OPENED DDF_CLOSE_NO_CLOSED DDF_AUDIT_NO_GATE DDF_RECORDS DDF_DATE_FIELDS \
           DDF_DATES_AFTER_UTC DDF_GIT_CHECKED DDF_OPENED_AFTER_ADDED DDF_LEGACY_LOCAL_STAMP \
           DDF_CLOSED_BEFORE_OPENED DDF_GIT_EVIDENCE DDF_RECOUNT_EQ DDF_FINDINGS \
           DDF_FINDINGS_PRINTED DDF_CLOSED_FIELD DDF_BLIND DDF_FAIL DDF_EXIT DDF_CLOCK_FROZEN; do
    femit "$F" "$k=$(val "$o" "$k")"
    [ "$(val "$o" "$k")" != MISSING ] || note 1
  done
  [ "$r" = 0 ] || note 1
  say "${2} часовые часы (в таблицу не входят): UTC=$(val "$o" DDF_UTC_TODAY) \
местное=$(val "$o" DDF_LOCAL_TODAY) расхождение_доменов=$(val "$o" DDF_DOMAIN_SPLIT)"

  # ---------------------------------------------- ШАГ 3 · независимый пересчёт
  say "### ${2} ШАГ 3 пересчёт без прибора ### $(date +%FT%T%:z)"
  v=$(cat lab/library.py lab/sources.py | grep -aF -- 'date.today()' | wc -l | tr -d ' ')
  femit "$F" "SHELL_LOCAL_TODAY_LINES=$v"
  v=$(cat lab/library.py lab/sources.py | grep -aF -- 'utc_today' | wc -l | tr -d ' ')
  femit "$F" "SHELL_FUNNEL_LINES=$v"
  a=$(nz "$v")
  b=$(is "$(flag "$F" DDF_LOCAL_TODAY_CALLS)" 0)
  c=$(is "$(flag "$F" DDF_FUNNEL_FILES)" 2)
  femit "$F" "SHELL_RECOUNT_EQ=$(all1 "$a" "$b" "$c")"
  [ "$(flag "$F" SHELL_RECOUNT_EQ)" = 1 ] || note 1
  v=$(git diff --name-only "$PIN" -- crates '*.rs' Cargo.toml Cargo.lock | wc -l | tr -d ' ')
  femit "$F" "CODE_CHANGED_RS=$v"
  [ "$v" = 0 ] || note 1

  # ---------------------------------------------- ШАГ 4 · живой прогон в двух доменах
  say "### ${2} ШАГ 4 library check: UTC и час runner'а против местного часа ### $(date +%FT%T%:z)"
  o="$P/lib_utc.txt"
  r=0
  TZ=UTC python lab/library.py check > "$o" 2>&1 || r=$?
  femit "$F" "LIBCHECK_UTC_EXIT=$r"
  femit "$F" "LIBCHECK_UTC_ERRORS=$(field "$o" LIBCHECK errors)"
  [ "$r" = 0 ] || note 1
  o="$P/lib_host.txt"
  r=0
  TZ=Australia/Sydney python lab/library.py check > "$o" 2>&1 || r=$?
  femit "$F" "LIBCHECK_HOST_EXIT=$r"
  femit "$F" "LIBCHECK_HOST_ERRORS=$(field "$o" LIBCHECK errors)"
  [ "$r" = 0 ] || note 1
  a=$(is "$(flag "$F" LIBCHECK_UTC_EXIT)" "$(flag "$F" LIBCHECK_HOST_EXIT)")
  b=$(is "$(flag "$F" LIBCHECK_HOST_EXIT)" 0)
  femit "$F" "DOMAIN_MATCH=$(all1 "$a" "$b")"
  [ "$(flag "$F" DOMAIN_MATCH)" = 1 ] || note 1

  # ---------------------------------------------- ШАГ 5 · запись дат по-новому
  say "### ${2} ШАГ 5 use/close: opened не стирается, closed ставится, дата одна на всех ### $(date +%FT%T%:z)"
  for z in UTC AustraliaSydney; do
    case "$z" in UTC) zone=UTC;; *) zone=Australia/Sydney;; esac
    t="$OUT/${2}/idx_$z.jsonl"; mkdir -p "$OUT/${2}"
    f="$OUT/${2}/state_$z.txt"; : > "$f"
    cp lab/library/index.jsonl "$t"
    before=$(python -c "import json,sys
for l in open(sys.argv[1],encoding='utf-8'):
    if l.strip() and json.loads(l)['id']=='L-0001':
        print(json.loads(l)['opened']); break" "$t")
    # Цель — существующая карточка: `library.py check` проверяет, что цель записи найдена в
    # репозитории, и посадка на собственную карточку цикла краснела бы по причине «карточки ещё
    # нет», а не по проверяемому свойству (дата `opened`).
    r=0
    VEC_DHT_LIBRARY="$t" TZ="$zone" python lab/library.py use L-0001 --target H-0128 \
      > "$OUT/${2}/use_$z.txt" 2>&1 || r=$?
    echo "USE_RC=$r" >> "$f"
    [ "$r" = 0 ] || note 1
    python - "$t" "$before" >> "$f" 2>&1 <<'PY'
import json, sys
path, before = sys.argv[1], sys.argv[2]
row = next(json.loads(l) for l in open(path, encoding="utf-8")
           if l.strip() and json.loads(l)["id"] == "L-0001")
print("OPENED_KEPT=" + ("1" if str(row.get("opened")) == before else "0"))
print("USED_PRESENT=" + ("1" if row.get("used") else "0"))
PY
    r=0
    VEC_DHT_LIBRARY="$t" TZ="$zone" python lab/library.py close L-0001 --action "не повлияло" \
      --what "E-0129: посадка записи на живой механизм helper'а, проверка поля closed" \
      >> "$OUT/${2}/use_$z.txt" 2>&1 || r=$?
    echo "CLOSE_RC=$r" >> "$f"
    python - "$t" >> "$f" 2>&1 <<'PY'
import json, re, sys
row = next(json.loads(l) for l in open(sys.argv[1], encoding="utf-8")
           if l.strip() and json.loads(l)["id"] == "L-0001")
c = str(row.get("closed", ""))
print("CLOSED_SHAPE=" + ("1" if re.match(r"^\d{4}-\d{2}-\d{2}$", c) else "0"))
print("CLOSED_VALUE=" + c)
PY
    say "${2} зона $zone: дата закрытия=$(sed -n 's/^CLOSED_VALUE=//p' "$f") код записи=$(sed -n 's/^CLOSE_RC=//p' "$f")"
  done
  # Имена фактов по зонам — литералы (см. шаг 1): ключ таблицы обязан находиться в helper'е grep'ом.
  SU="$OUT/${2}/state_UTC.txt"; SA="$OUT/${2}/state_AustraliaSydney.txt"
  femit "$F" "USE_OK_UTC=$(sed -n 's/^USE_RC=//p' "$SU")"
  femit "$F" "CLOSE_OK_UTC=$(sed -n 's/^CLOSE_RC=//p' "$SU")"
  femit "$F" "USE_KEEPS_OPENED_UTC=$(sed -n 's/^OPENED_KEPT=//p' "$SU")"
  femit "$F" "USED_FIELD_UTC=$(sed -n 's/^USED_PRESENT=//p' "$SU")"
  femit "$F" "CLOSED_SHAPE_UTC=$(sed -n 's/^CLOSED_SHAPE=//p' "$SU")"
  femit "$F" "USE_OK_AustraliaSydney=$(sed -n 's/^USE_RC=//p' "$SA")"
  femit "$F" "CLOSE_OK_AustraliaSydney=$(sed -n 's/^CLOSE_RC=//p' "$SA")"
  femit "$F" "USE_KEEPS_OPENED_AustraliaSydney=$(sed -n 's/^OPENED_KEPT=//p' "$SA")"
  femit "$F" "USED_FIELD_AustraliaSydney=$(sed -n 's/^USED_PRESENT=//p' "$SA")"
  femit "$F" "CLOSED_SHAPE_AustraliaSydney=$(sed -n 's/^CLOSED_SHAPE=//p' "$SA")"
  C1=$(sed -n 's/^CLOSED_VALUE=//p' "$OUT/${2}/state_UTC.txt")
  C2=$(sed -n 's/^CLOSED_VALUE=//p' "$OUT/${2}/state_AustraliaSydney.txt")
  femit "$F" "WRITE_TZ_MATCH=$( [ -n "$C1" ] && [ "$C1" = "$C2" ] && echo 1 || echo 0 )"
  femit "$F" "WRITE_KEEPS_OPENED=$(all1 "$(flag "$F" USE_KEEPS_OPENED_UTC)" "$(flag "$F" USE_KEEPS_OPENED_AustraliaSydney)")"
  femit "$F" "CLOSED_SHAPES_OK=$(all1 "$(flag "$F" CLOSED_SHAPE_UTC)" "$(flag "$F" CLOSED_SHAPE_AustraliaSydney)")"
  [ "$(flag "$F" WRITE_TZ_MATCH)" = 1 ] || note 1
  [ "$(flag "$F" WRITE_KEEPS_OPENED)" = 1 ] || note 1
  [ "$(flag "$F" USED_FIELD_UTC)" = 1 ] || note 1
  [ "$(flag "$F" CLOSED_SHAPES_OK)" = 1 ] || note 1

  # ---------------------------------------------- ШАГ 6 · гейт аудита
  say "### ${2} ШАГ 6 аудит обязан краснеть по находкам ### $(date +%FT%T%:z)"
  RT="$OUT/${2}/root"
  mkdir -p "$RT/lab/hypotheses" "$RT/lab/experiments" "$RT/lab/library"
  r=0
  cp lab/hypotheses/H-*.md "$RT/lab/hypotheses/" 2>"$OUT/${2}/cp.log" || r=$?
  cp lab/experiments/*.md "$RT/lab/experiments/" 2>>"$OUT/${2}/cp.log" || r=$?
  cp lab/library/index.jsonl "$RT/lab/library/" 2>>"$OUT/${2}/cp.log" || r=$?
  note "$r"
  BAD="$RT/lab/hypotheses/H-9999-e0129-plant.md"
  plant_card "$BAD"
  o="$OUT/${2}/audit_bad.txt"
  r=0
  VEC_DHT_ROOT="$RT" python lab/cycle-gate.py audit -n 1 > "$o" 2>&1 || r=$?
  femit "$F" "AUDIT_PLANT_EXIT=$r"
  femit "$F" "AUDIT_PLANT_FAIL_LINES=$(count_of "$o" '=FAIL нарушений=')"
  femit "$F" "AUDIT_PLANT_BAD_COUNT=$(field "$o" AUDIT_BAD карточек_с_нарушениями)"
  a=$(nz "$r")
  b=$(nz "$(flag "$F" AUDIT_PLANT_FAIL_LINES)")
  c=$(is "$(flag "$F" AUDIT_PLANT_BAD_COUNT)" 1)
  femit "$F" "AUDIT_GATE_FIRES=$(all1 "$a" "$b" "$c")"
  [ "$(flag "$F" AUDIT_GATE_FIRES)" = 1 ] || note 1
  rm -f "$BAD"
  o="$OUT/${2}/audit_clean.txt"
  r=0
  VEC_DHT_ROOT="$RT" python lab/cycle-gate.py audit -n 5 > "$o" 2>&1 || r=$?
  femit "$F" "AUDIT_CLEAN_COPY_EXIT=$r"
  [ "$r" = 0 ] || note 1
  o="$OUT/${2}/audit_live.txt"
  r=0
  python lab/cycle-gate.py audit -n 5 > "$o" 2>&1 || r=$?
  femit "$F" "AUDIT_LIVE_EXIT=$r"
  femit "$F" "AUDIT_LIVE_BAD_COUNT=$(field "$o" AUDIT_BAD карточек_с_нарушениями)"
  [ "$r" = 0 ] || note 1

  # ---------------------------------------------- ШАГ 7 · самопроверка прибора
  say "### ${2} ШАГ 7 самопроверка: посадки обязаны отбиваться ### $(date +%FT%T%:z)"
  o="$OUT/${2}/selftest.txt"
  r=0
  python "$DD" selftest > "$o" 2>&1 || r=$?
  femit "$F" "DDF_SELFTEST_EXIT=$r"
  femit "$F" "DDF_SELFTEST_TOTAL=$(field "$o" DDF_SELFTEST total)"
  femit "$F" "DDF_SELFTEST_PASSED=$(field "$o" DDF_SELFTEST passed)"
  femit "$F" "DDF_SELFTEST_PLANTS=$(val "$o" DDF_SELFTEST_PLANTS)"
  femit "$F" "PLANT_LOCAL_TODAY_FIRED=$(val "$o" PLANT_LOCAL_TODAY_FIRED)"
  femit "$F" "PLANT_NO_FUNNEL_FIRED=$(val "$o" PLANT_NO_FUNNEL_FIRED)"
  femit "$F" "PLANT_USE_WRITES_OPENED_FIRED=$(val "$o" PLANT_USE_WRITES_OPENED_FIRED)"
  femit "$F" "PLANT_CLOSE_NO_CLOSED_FIRED=$(val "$o" PLANT_CLOSE_NO_CLOSED_FIRED)"
  femit "$F" "PLANT_AUDIT_NO_GATE_FIRED=$(val "$o" PLANT_AUDIT_NO_GATE_FIRED)"
  femit "$F" "PLANT_DATE_AFTER_UTC_FIRED=$(val "$o" PLANT_DATE_AFTER_UTC_FIRED)"
  femit "$F" "PLANT_CLOSED_BEFORE_OPENED_FIRED=$(val "$o" PLANT_CLOSED_BEFORE_OPENED_FIRED)"
  femit "$F" "PLANT_BLIND_INDEX_FIRED=$(val "$o" PLANT_BLIND_INDEX_FIRED)"
  femit "$F" "PLANT_MISSING_FILE_FIRED=$(val "$o" PLANT_MISSING_FILE_FIRED)"
  [ "$r" = 0 ] || note 1

  # ---------------------------------------------- ШАГ 8 · замкнутость прибора
  say "### ${2} ШАГ 8 прибор стоит в CI и в контуре, закрытые приборы не тронуты ### $(date +%FT%T%:z)"
  femit "$F" "DDF_CI_STEPS=$(count_of .github/workflows/verify.yml 'check-date-domain')"
  femit "$F" "DDF_CONTOUR_BLOCK=$(count_of lab/workspace-verify.sh 'check-date-domain')"
  femit "$F" "E0127_INSTRUMENT_UNTOUCHED=$(git diff --name-only "$PIN" -- lab/check-ci-report-greps.py | wc -l | tr -d ' ')"
  femit "$F" "E0128_INSTRUMENT_UNTOUCHED=$(git diff --name-only "$PIN" -- lab/check-ci-rc-capture.py | wc -l | tr -d ' ')"
  femit "$F" "SPEC_V8_UNTOUCHED=$(git diff --name-only "$PIN" -- docs/VecDHT-SPEC-v8.md docs/VecDHT-SPEC-v9.md docs/PAID_ORDER-VECTORS.md | wc -l | tr -d ' ')"
  [ "$(flag "$F" DDF_CI_STEPS)" != 0 ] || note 1
  [ "$(flag "$F" DDF_CONTOUR_BLOCK)" != 0 ] || note 1
  for k in E0127_INSTRUMENT_UNTOUCHED E0128_INSTRUMENT_UNTOUCHED SPEC_V8_UNTOUCHED; do
    [ "$(flag "$F" "$k")" = 0 ] || note 1
  done
}

say "########## E-0129 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) · пин $PIN ##########"
# Свободный диск и RAM печатаются в носитель, но фактами цикла не являются: они уезжают от
# посторонних прогонов и не входят в замороженную таблицу (правило «носитель печатает входы
# пересчёта», порог (9) проверяется человеком по этим строкам).
r=0
bash lab/disk-report.sh | tee -a "$LOG" || r=$?
note "$r"

measure "$F1" "R1"
measure "$F2" "R2"

say "### ШАГ 9 устойчивость: два исполнения на неизменном дереве ### $(date +%FT%T%:z)"
if diff -q "$F1" "$F2" >/dev/null; then s=1; else s=0; diff "$F1" "$F2" | head -20 | tee -a "$LOG"; fi
emit0 "STABLE=$s"
[ "$s" = 1 ] || note 1

say "### ШАГ 10 посадка неверного ожидания и сверка ### $(date +%FT%T%:z)"
# Число строк таблицы печатается ДО сверки: иначе порог «таблица не пуста» ссылается на самого себя
# и становится невыполнимым по построению (урок `E-0128`, шаг 12).
v=$(awk -F'\t' 'NF>=2 && $1 !~ /^#/ {n++} END{print n+0}' "$EXPECT")
emit0 "EXPECT_ROWS=$v"
[ "$v" -ge 80 ] || note 1
awk -F'\t' 'BEGIN{OFS="\t"} $1=="DDF_RECORDS"{$2="99"} {print}' "$EXPECT" > "$OUT/plant.tsv"
if ! grep -q $'^DDF_RECORDS\t99\t' "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка DDF_RECORDS в таблице не найдена"
  plant=0
else
  cat "$G" >> "$F1"
  r=0
  python lab/expect.py "$OUT/plant.tsv" "$F1" > "$OUT/plant.out" 2>&1 || r=$?
  plant=$( [ "$r" -ne 0 ] && echo 1 || echo 0 )
fi
emit0 "PLANT_EXPECT_RED=$plant"
[ "$plant" = 1 ] || note 1
cat "$G" >> "$F2"
python lab/expect.py "$EXPECT" "$F1" "$F2" 2>&1 | tail -n 25 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
# Код самой сверки печатается в носитель, но в замороженную таблицу не входит: сверка исполняется
# до его печати. Красноту держит `note` — зелёный итог без нуля сверки невозможен.
emit0 "EXPECT_EXIT=$rc"
note "$rc"

say "### ШАГ 11 ресурсы после измерений ### $(date +%FT%T%:z)"
r=0
bash lab/disk-report.sh | tee -a "$LOG" || r=$?
note "$r"

say "########## E-0129 итог: WORST_RC=$WORST ##########"
exit "$WORST"
