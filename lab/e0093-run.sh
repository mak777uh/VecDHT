#!/usr/bin/env bash
# Helper цикла `E-0093` — страж формальных моделей Lean.
#
# Четыре шага исполняются по порядку, и ни один не «проверяется по памяти»:
#
#   PRE_FIX   — прежний прибор (`lab/lean-check.sh` версии коммита 9ecb326, bash + grep) обязан
#               ПРОПУСТИТЬ два настоящих нарушения: теорему, выведенную из объявленной аксиомы, и
#               ослабленную формулировку (`= 8` -> `<= 8`). Это замер дыры, а не нового прибора;
#               старый скрипт берётся из git-блоба, поэтому шаг воспроизводится и после того, как
#               обёртка указала на python.
#   SELFTEST  — новый прибор обязан отбить восемь посаженных дефектов, каждый по СВОЕЙ причине,
#               и пройти два позитивных контроля.
#   INVENTORY — инвентарь настоящего дерева, снятый дважды на неизменном дереве (n=2).
#   WRAPPER   — прежний вызов `bash lab/lean-check.sh --quiet` обязан работать и печатать
#               `LEAN_FILE=` по каждой модели (гейт (7): интерфейс не сломан).
#   СВЕРКА    — ключи из `lab/expectations/e0093.tsv` ищутся в напечатанных фактах
#               (`python lab/expect.py`); печатается `ОЖИДАНИЙ=N РАСХОЖДЕНИЙ=x` и `СВЕРКА_EXIT=`.
#               Пороги после пре-регистрации не двигаются (AGENTS.md).
#
# Употребление: bash lab/e0093-run.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/.elan/bin:/c/Users/Admin/mingw64/bin:$PATH"
export PYTHONIOENCODING=utf-8
LOG="lab/logs/e0093-all.log"
OLD_GUARD_REF="${OLD_GUARD_REF:-9ecb326}"
EXPECT="lab/expectations/e0093.tsv"
mkdir -p lab/logs

{
echo "########## E-0093 · lean-model-guards · $(date +%Y-%m-%dT%H:%M:%S%:z) ##########"
ram() { powershell.exe -NoProfile -Command "[math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024)" 2>/dev/null | tr -d '\r'; }
disk() { powershell.exe -NoProfile -Command "[math]::Round((Get-CimInstance Win32_LogicalDisk -Filter 'DeviceID=\"C:\"').FreeSpace/1GB)" 2>/dev/null | tr -d '\r'; }
echo "МЕРЕНО до: RAM_свободно_МБ=$(ram) ДИСК_свободно_ГБ=$(disk)"

TMP=$(mktemp -d)
FACTS="$TMP/facts.txt"; : > "$FACTS"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- PRE_FIX
echo "### шаг PRE_FIX: прежний прибор (git show $OLD_GUARD_REF:lab/lean-check.sh) ###"
git show "$OLD_GUARD_REF:lab/lean-check.sh" > "$TMP/old-guard.sh" || {
  echo "PRE_FIX=НЕТ СТАРОГО ПРИБОРА в $OLD_GUARD_REF"; exit 1; }
for kind in axiom weaken; do
  d="$TMP/tree-$kind"
  mkdir -p "$d/lab/lean/VecDHT"
  cp "$TMP/old-guard.sh" "$d/lab/lean-check.sh"
  cp lab/lean/VecDHT/*.lean "$d/lab/lean/VecDHT/"
  if [ "$kind" = "axiom" ]; then
    cat > "$d/lab/lean/VecDHT/BadAxiom.lean" <<'LEAN'
namespace VecDHT.BadAxiom

/-- Настоящее нарушение: теорема, выведенная из объявленной в файле аксиомы. -/
axiom localBad : 1 = 2

theorem direct : 1 = 2 := localBad

end VecDHT.BadAxiom
LEAN
  else
    python - "$d/lab/lean/VecDHT/CertLadder.lean" <<'PY'
import sys
p = sys.argv[1]
t = open(p, encoding="utf-8").read()
a = "theorem there_are_eight_names : ((List.range rungs).map nameOf).eraseDups.length = 8 := by"
b = "theorem there_are_eight_names : ((List.range rungs).map nameOf).eraseDups.length <= 8 := by"
assert a in t, "посадка не сработала: строка не найдена"
open(p, "w", encoding="utf-8").write(t.replace(a, b))
PY
    [ $? -eq 0 ] || { echo "PRE_FIX_${kind}=ПОСАДКА НЕ СРАБОТАЛА"; exit 1; }
  fi
  out=$(bash "$d/lab/lean-check.sh" --quiet); rc=$?
  printf '%s\n' "$out" > "$TMP/prefix-$kind.txt"
  allok=$(printf '%s\n' "$out" | grep -o 'LEAN_ALL_OK=[01]' | tail -1 | cut -d= -f2)
  echo "PRE_FIX_${kind}_EXIT=${rc} PRE_FIX_${kind}_LEAN_ALL_OK=${allok}" | tee -a "$FACTS"
done

# ---------------------------------------------------------------- SELFTEST
echo "### шаг SELFTEST: новый прибор, восемь посадок + два контроля ###"
# Осевшие каталоги прибора считаются ДО и ПОСЛЕ именно этой шага: `selftest` строит дерево-копию в
# временном хранилище, и с первой версии сносил его только на удачной ветке.
lg_count() { python -c 'import glob,os,tempfile;print(len(glob.glob(os.path.join(tempfile.gettempdir(),"leanguard-*"))))'; }
LG_BEFORE=$(lg_count)
t0=$(date +%s%N)
python lab/lean-check.py selftest > "$TMP/selftest.txt" 2>&1
SERC=$?
t1=$(date +%s%N)
LG_AFTER=$(lg_count)
cat "$TMP/selftest.txt"
echo "SELFTEST_EXIT=${SERC} SELFTEST_MS=$(( (t1 - t0 ) / 1000000 ))" | tee -a "$FACTS"
echo "SELFTEST_осевших_каталогов_до=${LG_BEFORE} после=${LG_AFTER}" | tee -a "$FACTS"

# ---------------------------------------------------------------- INVENTORY
echo "### шаг INVENTORY: настоящий прибор на настоящем дереве, n=2 ###"
# Вектор повторяемости сравнивается БЕЗ колонок времени (`MS=`, `LEAN_MS_TOTAL=`): окружение цикла
# объявляет их ценой, а не гейтом (правило 7 пункт (е): время на этом хосте — снимок хоста, а не
# свойство кода). Разброс времени при этом меряется и печатается числом, а не выбрасывается.
strip_ms() { sed -E 's/[ ]MS=[0-9]+//g; s/[ ]LEAN_MS_TOTAL=[0-9]+//g' "$1"; }
ms_total() { grep -o 'LEAN_MS_TOTAL=[0-9]*' "$1" | tail -1 | cut -d= -f2; }
for i in 1 2; do
  python lab/lean-check.py check --quiet > "$TMP/inv-$i.txt"; rc=$?
  echo "VECTOR_${i}_EXIT=${rc}" | tee -a "$FACTS"
  grep -E "^(LEAN_FILE|LEAN_TOTAL|LEAN_ALL_OK)" "$TMP/inv-$i.txt"
done
m1=$(ms_total "$TMP/inv-1.txt"); m2=$(ms_total "$TMP/inv-2.txt")
if diff -q <(strip_ms "$TMP/inv-1.txt") <(strip_ms "$TMP/inv-2.txt") >/dev/null; then
  echo "repro_вектор=совпал" | tee -a "$FACTS"
else
  echo "repro_вектор=РАЗОШЁЛСЯ" | tee -a "$FACTS"
  diff <(strip_ms "$TMP/inv-1.txt") <(strip_ms "$TMP/inv-2.txt") | head -12
fi
if [ -n "$m1" ] && [ -n "$m2" ] && [ "$m1" -gt 0 ]; then
  d=$(( m2 - m1 )); [ "$d" -lt 0 ] && d=$(( -d ))
  echo "repro_время_мс_1=${m1} repro_время_мс_2=${m2} repro_время_разброс_проц=$(( 100 * d / m1 ))" | tee -a "$FACTS"
fi

# ---------------------------------------------------------------- WRAPPER
echo "### шаг WRAPPER: сохранённый интерфейс bash lab/lean-check.sh ###"
bash lab/lean-check.sh --quiet > "$TMP/wrapper.txt" 2>&1
WRC=$?
wfiles=$(grep -c '^LEAN_FILE=' "$TMP/wrapper.txt")
echo "WRAPPER_EXIT=${WRC} WRAPPER_LEAN_FILE_COUNT=${wfiles}" | tee -a "$FACTS"

# ---------------------------------------------------------------- СВЕРКА
echo "### шаг СВЕРКА: ожидания из $EXPECT против напечатанных фактов ###"
# В сверку идут ТОЛЬКО печатные факты: строки шагов и сводные строки приборов. Дампы per-file
# (`NATIVE_AXIOMS=30` по одной модели) в корпус не попадают, иначе ожидание суммы могло бы случайно
# совпасть с одной строкой файла. Строка `LEAN_ALL_OK=` берётся отдельно: прибор печатает её следующей
# строкой после сводной, и первая версия фильтра её теряла — сверка честным образом сообщила «нет
# такого ключа» вместо того, чтобы пройти молча (ДИАГНОЗ-7).
grep -hE '^(LEAN_TOTAL=|LEAN_ALL_OK=|LEANGUARD_SELFTEST )' "$TMP/selftest.txt" "$TMP/inv-1.txt" \
  "$TMP/inv-2.txt" "$TMP/wrapper.txt" > "$TMP/summaries.txt" || true
cat "$FACTS" "$TMP/summaries.txt" > "$TMP/corpus.txt"
python lab/expect.py "$EXPECT" "$TMP/corpus.txt"
echo "СВЕРКА_EXIT=$?"

echo "порог (13) осевшие_каталоги_прибора — см. строку SELFTEST_осевших_каталогов_до/после выше"
echo "МЕРЕНО после: RAM_свободно_МБ=$(ram) ДИСК_свободно_ГБ=$(disk)"
echo "########## E-0093 · конец блока ##########"
} | tee -a "$LOG"
