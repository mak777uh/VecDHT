#!/usr/bin/env bash
# E-0127: отчётный `grep` в workflow'ах не имеет права обрывать шаг раньше вердикта (H-0127).
#
# Механизм измерен здесь же, ШАГ 3: GitHub исполняет содержимое `run:` как `bash -e`, наши шаги
# дополнительно ставят `set -uo pipefail`. Отчётный grep без находки возвращает 1, труба под
# pipefail отдаёт её наружу, `-e` обрывает шаг в этой строке — ДО `exit $r`, которое и является
# вердиктом. Прибор — `lab/check-ci-report-greps.py`, таблица порогов —
# `lab/expectations/e0127.tsv`, PRE_FIX — дерево пина `d18ad2b` из `git archive` с копией нынешнего
# прибора внутри (прибора на пине нет, и это записано в пороге).
#
# Имена фактов печатаются ЛИТЕРАЛОМ, а не шаблоном `PRE_FIX_${k}=`: `lab/threshold-lint.py` считает
# ключ напечатанным, только если видит его имя в тексте helper'а или источника, иначе ключ остался
# бы сиротой (прецедент `E-0095`, повторенный в `E-0126`).
#
# Шаги:
#   (0) гейт карточки и носитель до прогона;
#   (1) PRE_FIX: пин + нынешний прибор, красен по находкам, а не по слепоте;
#   (2) живой прогон прибора на рабочем дереве;
#   (3) механика: шесть форм под `bash -e` на синтетических логах — что именно обрывается и что
#       теряет рассылку `::notice::`; это доказательство ВЫБОРА формы правки, а не иллюстрация;
#   (4) синтаксис: каждый блок `run:` дерева через `bash -n`;
#   (5) самопроверка прибора: пять посаженных форм на копиях;
#   (6) две посадки на копиях починного дерева: снять guard и поставить guard не в конце трубы;
#   (7) wiring: страж стоит и в CI, и в закрытии цикла; вердикт-греп рецепта остался без guard;
#   (8) полный контур стражей по файлам цикла;
#   (9) носитель после измерений (три числа: диск/RAM/pagefile);
#  (10) посадка неверного ожидания и сверка `lab/expect.py` двумя файлами фактов.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0127-all.log"
PIN=d18ad2b
EXPECT="lab/expectations/e0127.tsv"
CRG="lab/check-ci-report-greps.py"
WF=".github/workflows"
OUT=$(mktemp -d "${TMPDIR:-/tmp}/e0127.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
WORST=0
G="$OUT/facts_global.txt"
F1="$OUT/facts1.txt"
F2="$OUT/facts2.txt"
: > "$G"; : > "$F1"; : > "$F2"
note() { [ "${1:-1}" -ne 0 ] && WORST=1; return 0; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
emit0() { printf '%s\n' "$1" | tee -a "$LOG"; printf '%s\n' "$1" >> "$G"; }
# Носитель печатает КАЖДЫЙ производный факт, а не только выводы приборов: иначе строка таблицы
# `PRE_FIX_CRG_UNGUARDED=21` нельзя перепроверить по логу, а сверка по молчаливо собранному
# файлу фактов — это отчёт о внутренности helper'а, а не о дереве (ДИАГНОЗ цикла).
femit() { printf '%s\n' "$2" >> "$1"; printf '%s\n' "$2" | tee -a "$LOG" >/dev/null; }
# Факт из вывода прибора: строка `KEY=значение` с якорем по началу строки. Пустое значение
# печатается как MISSING и красит сверку: молчание прогона не считается успехом.
flag() { # flag <файл> <ключ>
  local v
  v=$(sed -n "s|^${2}=||p" "$1" 2>/dev/null | head -1)
  [ -n "$v" ] || v=MISSING
  printf '%s' "$v"
}

say "########## E-0127 · $(date +%FT%T%:z) · дерево $(git rev-parse --short HEAD) ##########"

say "### ШАГ 0 гейт и носитель до ### $(date +%FT%T%:z)"
python lab/cycle-gate.py H-0127 2>&1 | tail -n 12 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
gok=$([ "$rc" -eq 0 ] && echo 1 || echo 0)
emit0 "GATE_H0127_OK=${gok}"
[ "$gok" = 1 ] || note 1
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf '%s' "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then dok=1; else dok=0; fi
emit0 "DISK_GE_15000=${dok}"
[ "$dok" = 1 ] || note 1

measure() { # measure <файл-фактов> <метка исполнения>
  local F="$1" tag="$2" pfx root rc v landed red tot bad p ok rc1 mk1 nn1
  local a1 a2 b1 b2 c1 c2 d1 d2 d3 e1 e2 e3 f1 f2 f3

  say "### ШАГ 1.${tag} PRE_FIX: пин ${PIN} + нынешний прибор ### $(date +%FT%T%:z)"
  pfx="$OUT/prefix-$tag"; root="$OUT/plants-$tag"
  rm -rf "$pfx" "$root"; mkdir -p "$pfx" "$root"
  git archive --format=tar "$PIN" | tar -x -C "$pfx"
  # Прибора на пине нет (`d18ad2b` старше него), поэтому PRE_FIX исполняется нынешним прибором,
  # копия которого кладётся внутрь извлечённого дерева: краснота обязана быть про дерево, а не
  # про отсутствие исполнителя.
  cp "$CRG" "$pfx/$CRG"
  [ -f "$pfx/$CRG" ]
  python "$pfx/$CRG" check --dir "$pfx" > "$OUT/prefix-$tag.txt" 2>&1
  rc=$?
  cat "$OUT/prefix-$tag.txt" | tee -a "$LOG"
  femit "$F" "PRE_FIX_CRG_FILES=$(flag "$OUT/prefix-$tag.txt" CRG_FILES)"
  femit "$F" "PRE_FIX_CRG_RUN_BLOCKS=$(flag "$OUT/prefix-$tag.txt" CRG_RUN_BLOCKS)"
  femit "$F" "PRE_FIX_CRG_GREP_STATEMENTS=$(flag "$OUT/prefix-$tag.txt" CRG_GREP_STATEMENTS)"
  femit "$F" "PRE_FIX_CRG_UNGUARDED=$(flag "$OUT/prefix-$tag.txt" CRG_UNGUARDED)"
  femit "$F" "PRE_FIX_CRG_MISPLACED=$(flag "$OUT/prefix-$tag.txt" CRG_MISPLACED)"
  femit "$F" "PRE_FIX_CRG_VERDICT_GREP=$(flag "$OUT/prefix-$tag.txt" CRG_VERDICT_GREP)"
  femit "$F" "PRE_FIX_CRG_LINES_NOGUARD=$(flag "$OUT/prefix-$tag.txt" CRG_LINES_NOGUARD)"
  femit "$F" "PRE_FIX_CRG_RECOUNT_EQ=$(flag "$OUT/prefix-$tag.txt" CRG_RECOUNT_EQ)"
  femit "$F" "PRE_FIX_CRG_BLIND=$(flag "$OUT/prefix-$tag.txt" CRG_BLIND)"
  femit "$F" "PRE_FIX_CRG_FAIL=$(flag "$OUT/prefix-$tag.txt" CRG_FAIL)"
  femit "$F" "PRE_FIX_CRG_EXIT=${rc}"
  # Краснота PRE_FIX обязана быть находками, а не слепотой: «ноль находок» у ослепшего прибора
  # неотличим от «ноль находок» у здорового (прецедент ДИАГНОЗ-1/2 из `E-0126`).
  if [ "$(flag "$OUT/prefix-$tag.txt" CRG_UNGUARDED)" -gt 0 ] \
     && [ "$(flag "$OUT/prefix-$tag.txt" CRG_BLIND)" = 0 ] \
     && [ "$(flag "$OUT/prefix-$tag.txt" CRG_RECOUNT_EQ)" = 1 ] && [ "$rc" -ne 0 ]; then
    femit "$F" "PRE_FIX_RED_NOT_BLIND=1"
  else
    femit "$F" "PRE_FIX_RED_NOT_BLIND=0"; note 1
  fi

  say "### ШАГ 2.${tag} живой прогон прибора ### $(date +%FT%T%:z)"
  python "$CRG" check > "$OUT/live-$tag.txt" 2>&1
  rc=$?
  cat "$OUT/live-$tag.txt" | tee -a "$LOG"
  femit "$F" "CRG_DIR_ABSENT=$(flag "$OUT/live-$tag.txt" CRG_DIR_ABSENT)"
  femit "$F" "CRG_FILES=$(flag "$OUT/live-$tag.txt" CRG_FILES)"
  femit "$F" "CRG_RUN_BLOCKS=$(flag "$OUT/live-$tag.txt" CRG_RUN_BLOCKS)"
  femit "$F" "CRG_GREP_STATEMENTS=$(flag "$OUT/live-$tag.txt" CRG_GREP_STATEMENTS)"
  femit "$F" "CRG_UNGUARDED=$(flag "$OUT/live-$tag.txt" CRG_UNGUARDED)"
  femit "$F" "CRG_MISPLACED=$(flag "$OUT/live-$tag.txt" CRG_MISPLACED)"
  femit "$F" "CRG_VERDICT_GREP=$(flag "$OUT/live-$tag.txt" CRG_VERDICT_GREP)"
  femit "$F" "CRG_SUBST_GREP=$(flag "$OUT/live-$tag.txt" CRG_SUBST_GREP)"
  femit "$F" "CRG_LINES_NOGUARD=$(flag "$OUT/live-$tag.txt" CRG_LINES_NOGUARD)"
  femit "$F" "CRG_RECOUNT_EQ=$(flag "$OUT/live-$tag.txt" CRG_RECOUNT_EQ)"
  femit "$F" "CRG_UNREADABLE=$(flag "$OUT/live-$tag.txt" CRG_UNREADABLE)"
  femit "$F" "CRG_BLIND=$(flag "$OUT/live-$tag.txt" CRG_BLIND)"
  femit "$F" "CRG_FAIL=$(flag "$OUT/live-$tag.txt" CRG_FAIL)"
  femit "$F" "CRG_EXIT=${rc}"
  [ "$rc" -eq 0 ] || note 1
  # Пустое множество печатается словом, а не молчанием; непустое — адресом и фрагментом строки.
  if [ "$(flag "$OUT/live-$tag.txt" CRG_UNGUARDED)" = 0 ]; then
    v=$(grep -c '^CRG_UNGUARDED_AT=none' "$OUT/live-$tag.txt" || true)
    if [ "$v" = 1 ]; then femit "$F" "CRG_NONE_PRINTED=1"; else femit "$F" "CRG_NONE_PRINTED=0"; note 1; fi
  else
    femit "$F" "CRG_NONE_PRINTED=0"; note 1
  fi

  say "### ШАГ 3.${tag} механика: шесть форм под bash -e ### $(date +%FT%T%:z)"
  printf 'test result: ok\nREVIEW_EXIT=0\n' > "$OUT/hit.log"
  printf 'test result: ok\n' > "$OUT/empty.log"
  E="$OUT/empty.log"; H="$OUT/hit.log"
  shape() { # shape <команда> -> глобальные rc1/mk1/nn1 (метрики одной формы)
    out=$(bash -e -c "$1" 2>&1); rc1=$?
    nn1=$(printf '%s' "$out" | grep -ac '::notice::' || true)
    mk1=$(printf '%s' "$out" | grep -c 'СЮДА_ДОШЛИ' || true)
    printf '  MECH %s RC=%s REACHED=%s NOTICES=%s\n' "${2:-}" "$rc1" "$mk1" "$nn1" | tee -a "$LOG"
  }
  shape "set -uo pipefail; grep -aE '^РАЗРЫВ ' $E | head -20; echo СЮДА_ДОШЛИ" A_UNGUARDED
  femit "$F" "MECH_A_UNGUARDED_RC=${rc1}"
  femit "$F" "MECH_A_UNGUARDED_REACHED=${mk1}"
  femit "$F" "MECH_A_UNGUARDED_NOTICES=${nn1}"
  shape "set -uo pipefail; grep -aE '^РАЗРЫВ ' $E | head -20 || true; echo СЮДА_ДОШЛИ" A_GUARDED
  femit "$F" "MECH_A_GUARDED_RC=${rc1}"
  femit "$F" "MECH_A_GUARDED_REACHED=${mk1}"
  femit "$F" "MECH_A_GUARDED_NOTICES=${nn1}"
  shape "set -uo pipefail; { echo \"R=0\"; grep -aE '^РАЗРЫВ ' $E; } | while IFS= read -r n; do echo \"::notice::\$n\"; done; echo СЮДА_ДОШЛИ" B_UNGUARDED
  femit "$F" "MECH_B_UNGUARDED_RC=${rc1}"
  femit "$F" "MECH_B_UNGUARDED_REACHED=${mk1}"
  femit "$F" "MECH_B_UNGUARDED_NOTICES=${nn1}"
  shape "set -uo pipefail; { echo \"R=0\"; grep -aE '^РАЗРЫВ ' $E; } | while IFS= read -r n; do echo \"::notice::\$n\"; done || true; echo СЮДА_ДОШЛИ" B_GUARDED
  femit "$F" "MECH_B_GUARDED_RC=${rc1}"
  femit "$F" "MECH_B_GUARDED_REACHED=${mk1}"
  femit "$F" "MECH_B_GUARDED_NOTICES=${nn1}"
  shape "set -uo pipefail; grep -aE '^REVIEW_EXIT' $H || true | while IFS= read -r n; do echo \"::notice::\$n\"; done; echo СЮДА_ДОШЛИ" C_MISPLACED_HIT
  femit "$F" "MECH_C_MISPLACED_HIT_RC=${rc1}"
  femit "$F" "MECH_C_MISPLACED_HIT_REACHED=${mk1}"
  femit "$F" "MECH_C_MISPLACED_HIT_NOTICES=${nn1}"
  shape "set -uo pipefail; grep -aE '^РАЗРЫВ ' $E || true | while IFS= read -r n; do echo \"::notice::\$n\"; done; echo СЮДА_ДОШЛИ" D_MISPLACED_EMPTY
  femit "$F" "MECH_D_MISPLACED_EMPTY_RC=${rc1}"
  femit "$F" "MECH_D_MISPLACED_EMPTY_REACHED=${mk1}"
  femit "$F" "MECH_D_MISPLACED_EMPTY_NOTICES=${nn1}"
  # Утверждения порога проверяются прямо на этих числах, иначе цифры остались бы декорацией.
  # Имя факта передаётся литералом аргументом — см. шапку файла про `lab/threshold-lint.py`.
  # Оба литерала печатаются в источнике: `lab/threshold-lint.py` считает ключ напечатанным только
  # если видит `КЛЮЧ=` в тексте helper'а или прибора, поэтому имя передаётся вместе со значением.
  chk() { # chk <факт-при-истине> <факт-при-лжи> <0-или-1>
    if [ "$3" = 1 ]; then femit "$F" "$1"; else femit "$F" "$2"; note 1; fi
  }
  a1=$(flag "$F" "MECH_A_UNGUARDED_RC");     a2=$(flag "$F" "MECH_A_UNGUARDED_REACHED")
  b1=$(flag "$F" "MECH_A_GUARDED_RC");       b2=$(flag "$F" "MECH_A_GUARDED_REACHED")
  c1=$(flag "$F" "MECH_B_UNGUARDED_RC");     c2=$(flag "$F" "MECH_B_UNGUARDED_REACHED")
  d1=$(flag "$F" "MECH_B_GUARDED_RC");       d2=$(flag "$F" "MECH_B_GUARDED_REACHED")
  d3=$(flag "$F" "MECH_B_GUARDED_NOTICES")
  e1=$(flag "$F" "MECH_C_MISPLACED_HIT_RC"); e2=$(flag "$F" "MECH_C_MISPLACED_HIT_REACHED")
  e3=$(flag "$F" "MECH_C_MISPLACED_HIT_NOTICES")
  f1=$(flag "$F" "MECH_D_MISPLACED_EMPTY_RC"); f2=$(flag "$F" "MECH_D_MISPLACED_EMPTY_REACHED")
  f3=$(flag "$F" "MECH_D_MISPLACED_EMPTY_NOTICES")
  ok=1; [ "$a1" = 1 ] && [ "$a2" = 0 ] || ok=0
  chk "MECHOK_ABORT_BEFORE_VERDICT=1" "MECHOK_ABORT_BEFORE_VERDICT=0" "$ok"
  ok=1; [ "$b1" = 0 ] && [ "$b2" = 1 ] || ok=0
  chk "MECHOK_GUARD_REACHES_VERDICT=1" "MECHOK_GUARD_REACHES_VERDICT=0" "$ok"
  ok=1; [ "$c1" = 1 ] && [ "$c2" = 0 ] || ok=0
  chk "MECHOK_BRACES_ALSO_ABORT=1" "MECHOK_BRACES_ALSO_ABORT=0" "$ok"
  ok=1; [ "$d1" = 0 ] && [ "$d2" = 1 ] && [ "$d3" = 1 ] || ok=0
  chk "MECHOK_GUARD_KEEPS_NOTICES=1" "MECHOK_GUARD_KEEPS_NOTICES=0" "$ok"
  ok=1; [ "$e1" = 0 ] && [ "$e2" = 1 ] && [ "$e3" = 0 ] || ok=0
  chk "MECHOK_MISPLACED_LOSES_NOTICES=1" "MECHOK_MISPLACED_LOSES_NOTICES=0" "$ok"
  ok=1; [ "$f1" = 0 ] && [ "$f2" = 1 ] && [ "$f3" = 0 ] || ok=0
  chk "MECHOK_MISPLACED_LOOKS_GREEN=1" "MECHOK_MISPLACED_LOOKS_GREEN=0" "$ok"

  say "### ШАГ 4.${tag} синтаксис всех блоков run: через bash -n ### $(date +%FT%T%:z)"
  mkdir -p "$OUT/blk-$tag"
  python - "$WF" "$OUT/blk-$tag" <<'PY' > "$OUT/blk-$tag.txt" 2>&1
import os, re, sys
RUN = re.compile(r"^\s*(?:-\s+)?run:\s*[|>]")
d, out = sys.argv[1], sys.argv[2]
n = 0
for f in sorted(os.listdir(d)):
    if not f.endswith((".yml", ".yaml")):
        continue
    lines = open(os.path.join(d, f), encoding="utf-8").read().replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        if RUN.match(lines[i]):
            ki = len(lines[i]) - len(lines[i].lstrip()); j = i + 1; body = []
            while j < len(lines):
                l = lines[j]
                if l.strip() == "":
                    body.append("")
                elif (len(l) - len(l.lstrip())) > ki:
                    body.append(l)
                else:
                    break
                j += 1
            if any(x.strip() for x in body):
                ind = min(len(x) - len(x.lstrip()) for x in body if x.strip())
                n += 1
                with open(os.path.join(out, "%s__%d.sh" % (f[:-4], n)),
                          "w", encoding="utf-8", newline="\n") as fh:
                    fh.write("set -uo pipefail\n")
                    fh.write("\n".join((x[ind:] if x.strip() else "") for x in body) + "\n")
            i = j
        else:
            i += 1
print("EXTRACTED=%d" % n)
PY
  [ -s "$OUT/blk-$tag.txt" ] || { say "extractor молчит — шаг невозможен"; note 1; }
  tot=0; bad=0
  for s in "$OUT"/blk-"$tag"/*.sh; do
    tot=$((tot + 1))
    if ! bash -n "$s" 2>"$s.err"; then bad=$((bad + 1)); sed -n '1,2p' "$s.err" | tee -a "$LOG"; fi
  done
  femit "$F" "SYNTAX_BLOCKS=${tot}"
  femit "$F" "SYNTAX_BAD=${bad}"
  [ "$bad" = 0 ] || note 1
  # Число блоков, попавших под `bash -n`, обязано равняться числу блоков, которые видел прибор:
  # иначе «все блоки синтаксичны» могло бы означать «половину блоков не извлекли».
  if [ "$tot" = "$(flag "$OUT/live-$tag.txt" CRG_RUN_BLOCKS)" ]; then
    femit "$F" "SYNTAX_BLOCKS_EQ_RUN_BLOCKS=1"
  else
    femit "$F" "SYNTAX_BLOCKS_EQ_RUN_BLOCKS=0"; note 1
  fi

  say "### ШАГ 5.${tag} самопроверка прибора: пять форм ### $(date +%FT%T%:z)"
  python "$CRG" selftest > "$OUT/st-$tag.txt" 2>&1
  rc=$?
  cat "$OUT/st-$tag.txt" | tee -a "$LOG"
  femit "$F" "CRG_SELFTEST_RC=${rc}"
  femit "$F" "CRG_SELFTEST_OK=$(flag "$OUT/st-$tag.txt" CRG_SELFTEST_OK)"
  v=$(sed -n 's|^CRG_SELFTEST total=\([0-9]*\) fired=\([0-9]*\).*|\2|p' "$OUT/st-$tag.txt" | head -1)
  [ -n "$v" ] || v=MISSING
  femit "$F" "CRG_SELFTEST_FIRED=${v}"
  [ "$rc" -eq 0 ] || note 1

  say "### ШАГ 6.${tag} две посадки на копиях починного дерева ### $(date +%FT%T%:z)"
  landed=0; red=0
  # (а) снять `|| true` с первой отчётной трубы -> прибор обязан увидеть находку и покраснеть.
  p="$root/a"; mkdir -p "$p/$WF"; cp "$WF"/*.yml "$p/$WF/"
  python - "$p/$WF/verify.yml" <<'PY'
import re, sys
p = sys.argv[1]
t = open(p, encoding="utf-8").read()
m = re.search(r"(?m)^(?P<body>[ ]*grep [^\n]*\|\| true)[ ]*$", t)
if not m:
    sys.exit(3)
open(p, "w", encoding="utf-8", newline="\n").write(
    t[:m.start("body")] + m.group("body").replace(" || true", "") + t[m.end("body"):])
sys.exit(0)
PY
  rc=$?
  if [ "$rc" = 0 ] && ! diff -q "$WF/verify.yml" "$p/$WF/verify.yml" >/dev/null 2>&1; then
    landed=$((landed + 1)); femit "$F" "PLANT_A_LANDED=1"
  else
    femit "$F" "PLANT_A_LANDED=0"; note 1
  fi
  python "$CRG" check --dir "$p" > "$OUT/plant-a-$tag.txt" 2>&1; rc=$?
  femit "$F" "PLANT_A_UNGUARDED=$(flag "$OUT/plant-a-$tag.txt" CRG_UNGUARDED)"
  femit "$F" "PLANT_A_EXIT=${rc}"
  [ "$rc" -ne 0 ] && red=$((red + 1))
  # (б) guard НЕ в конце трубы: шаг зеленеет, notices теряются. Посадка вписывает синтетическую
  # строку, чтобы не зависеть от того, какая именно форма случится в дереве.
  p="$root/b"; mkdir -p "$p/$WF"; cp "$WF"/*.yml "$p/$WF/"
  python - "$p/$WF/verify.yml" <<'PY'
import sys
p = sys.argv[1]
lines = open(p, encoding="utf-8").read().split("\n")
anchor = None
for i, l in enumerate(lines):
    if l.strip().startswith("exit $r"):
        anchor = i
        break
if anchor is None:
    sys.exit(3)
lines.insert(anchor, '          grep -aE \'^CRG_PROBE_MISPLACED=\' "$L" || true | tail -3')
open(p, "w", encoding="utf-8", newline="\n").write("\n".join(lines))
sys.exit(0)
PY
  rc=$?
  if [ "$rc" = 0 ] && ! diff -q "$WF/verify.yml" "$p/$WF/verify.yml" >/dev/null 2>&1; then
    landed=$((landed + 1)); femit "$F" "PLANT_B_LANDED=1"
  else
    femit "$F" "PLANT_B_LANDED=0"; note 1
  fi
  python "$CRG" check --dir "$p" > "$OUT/plant-b-$tag.txt" 2>&1; rc=$?
  femit "$F" "PLANT_B_MISPLACED=$(flag "$OUT/plant-b-$tag.txt" CRG_MISPLACED)"
  femit "$F" "PLANT_B_EXIT=${rc}"
  [ "$rc" -ne 0 ] && red=$((red + 1))
  # Находка обязана быть названа адресом, а не только числом: число без адреса неотличимо от того,
  # что прибор смотрит в другое место.
  v=$(grep -c '^CRG_MISPLACED_AT=.*CRG_PROBE_MISPLACED' "$OUT/plant-b-$tag.txt" || true)
  if [ "$v" = 1 ]; then femit "$F" "PLANT_B_NAMED=1"; else femit "$F" "PLANT_B_NAMED=0"; note 1; fi
  femit "$F" "PLANT_LANDED=${landed}"
  if [ "$landed" = 2 ] && [ "$red" = 2 ]; then
    femit "$F" "PLANT_ALL_RED=1"
  else
    femit "$F" "PLANT_ALL_RED=0"; note 1
  fi
}

say "########## ИЗМЕРЕНИЕ 1 ##########"
measure "$F1" 1
say "########## ИЗМЕРЕНИЕ 2 ##########"
measure "$F2" 2

if diff -q "$F1" "$F2" >/dev/null 2>&1; then st=1; else st=0; fi
emit0 "STABLE=${st}"
[ "$st" = 1 ] || note 1
say "два исполнения сравнены построчно (diff -q): STABLE=${st}"

say "### ШАГ 7 прибор вписан в контур, вердикт-греп рецепта не спрятан ### $(date +%FT%T%:z)"
# Страж, которого не гоняет ни CI, ни закрытие цикла, через пять циклов становится зелёным текстом.
if grep -qF 'name: check-ci-report-greps' "$WF/verify.yml" \
   && grep -qF 'python lab/check-ci-report-greps.py selftest' "$WF/verify.yml"; then
  ci=1
else
  ci=0
fi
emit0 "CI_STEP_ADDED=${ci}"; [ "$ci" = 1 ] || note 1
if grep -qF 'python lab/check-ci-report-greps.py selftest' lab/workspace-verify.sh \
   && grep -qF 'python lab/check-ci-report-greps.py check' lab/workspace-verify.sh; then
  vb=1
else
  vb=0
fi
emit0 "VERIFY_BLOCK_ADDED=${vb}"; [ "$vb" = 1 ] || note 1
# Последний statement шага — вердикт: `grep -F` по рецепту обязан КРАСНИТЬ работу, если строки
# рецепта нет в README. Спрятать его под `|| true` — значит сделать провал релизного рецепта
# зелёным, поэтому он проверяется отдельным фактом, а не молчаливым исключением в приборе.
verdict=$(sed -n "/grep -F 'cargo build --release -p vecdht-cli'/p" "$WF/release.yml" | head -1)
if [ -n "$verdict" ] && ! printf '%s' "$verdict" | grep -q '|| true'; then vk=1; else vk=0; fi
emit0 "VERDICT_GREP_KEPT=${vk}"; [ "$vk" = 1 ] || note 1
rs=$(git diff --name-only "$PIN" -- '*.rs' 2>/dev/null | grep -cve '^lab/' || true)
emit0 "CODE_CHANGED_RS=${rs:-0}"
[ "${rs:-0}" = 0 ] || note 1

say "### ШАГ 8 полный контур стражей ### $(date +%FT%T%:z)"
CYCLE_FILES="$CRG $EXPECT lab/e0127-run.sh $WF/verify.yml $WF/formal.yml $WF/release.yml \
lab/hypotheses/H-0127-ci-report-greps-abort-steps.md \
lab/experiments/E-0127-ci-report-greps-abort-steps.md \
lab/decisions/ADR-0068-report-pipes-cannot-replace-verdicts.md"
# shellcheck disable=SC2086
bash lab/check-text-clean.sh $CYCLE_FILES 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "TEXTGUARD_EXIT=${rc}"; note "$rc"
python lab/threshold-lint.py "$EXPECT" --helper lab/e0127-run.sh \
  --sources "$CRG" lab/e0127-run.sh 2>&1 | tail -4 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "LINT_EXIT=${rc}"; note "$rc"
python lab/check-claim-map.py 2>&1 | tail -2 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "CLAIMMAP_EXIT=${rc}"; note "$rc"
python lab/repo-review.py check 2>&1 | tail -3 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "REPO_REVIEW_EXIT=${rc}"; note "$rc"
bash lab/check-spec-mirror.sh 2>&1 | tail -2 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
emit0 "MIRROR_EXIT=${rc}"; note "$rc"

say "### ШАГ 9 носитель после измерений ### $(date +%FT%T%:z)"
# Меряется до сверки, а не после: `lab/expect.py` сравнивает файлы фактов, и ключ, напечатанный
# после сверки, физически не может в них попасть (это и есть ДИАГНОЗ пре-регистрации: первый
#dry-run покраснел ровно на этом). Измерения цикла к этому моменту закончены.
res=$(bash lab/disk-report.sh 2>&1)
say "$res"
disk=$(printf '%s' "$res" | sed -n 's/.*DISK_FREE_MB=\([0-9]*\).*/\1/p')
if [ "${disk:-0}" -ge 15000 ]; then da=1; else da=0; fi
emit0 "DISK_AFTER_MEASURE_GE_15000=${da}"
[ "$da" = 1 ] || note 1

say "### ШАГ 10 посадка неверного ожидания и сверка ### $(date +%FT%T%:z)"
awk -F'	' 'BEGIN{OFS="	"} $1=="CRG_UNGUARDED"{$2="7"} {print}' "$EXPECT" > "$OUT/plant.tsv"
if ! grep -q $'^CRG_UNGUARDED	7	' "$OUT/plant.tsv"; then
  say "ПОСАДКА НЕ СРАБОТАЛА: строка CRG_UNGUARDED в таблице не найдена"
  plant=0
else
  cat "$G" >> "$F1"
  python lab/expect.py "$OUT/plant.tsv" "$F1" > "$OUT/plant.out" 2>&1
  plant=$([ $? -ne 0 ] && echo 1 || echo 0)
fi
emit0 "PLANT_EXPECT_RED=${plant}"
[ "$plant" = 1 ] || note 1
cat "$G" >> "$F2"
python lab/expect.py "$EXPECT" "$F1" "$F2" 2>&1 | tail -n 25 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
printf "EXPECT_EXIT=%s
" "$rc" | tee -a "$LOG"
note "$rc"

say "WORST_RC=$WORST"
exit "$WORST"
