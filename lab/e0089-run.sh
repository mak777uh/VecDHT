#!/usr/bin/env bash
# E-0089: контур источников (`H-0089`, `ADR-0045`). Цикл без Rust-оракула: проверяемая вещь —
# сам механизм, поэтому оракул это negative/positive-контроли над `lab/library.py`.
#
# Пороги заморожены в `lab/hypotheses/H-0089-prior-art-contour.md` (0)…(9) и повторяются assert'ами
# здесь. Пороги после прогона не двигаются: непройденный гейт пишется в лог вердиктом и делает
# `HELPER_EXIT` ненулевым.
#
# Встроенные уроки метода: (а) helper исполняет свою mktemp-копию (ДИАГНОЗ-6 из `E-0079`);
# (б) ресурсы — часть метода, метки ASCII (кириллица в выводе PowerShell бьёт кодовую страницу);
# (в) append-only лог ⇒ контроль берёт ПОСЛЕДНЕЕ вхождение (`tail -1`, ДИАГНОЗ-3 из `E-0087`);
# (г) проверка обязана быть выполнимой по построению (ДИАГНОЗ-1 из `E-0087`): порог (7) сверяется
#     и на «не готов», и на «годен» при разумном окне;
# (д) порог (2) требует, чтобы каждый посаженный дефект УПАЛ: молчание checker'а — отказ механизма,
#     а не зелёный прогон.
if [ -z "${VEC_DHT_ROOT:-}" ]; then
  VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  export VEC_DHT_ROOT
  RUN_COPY="$(mktemp "${TMPDIR:-/tmp}/e0089-run-XXXXXX.sh")"
  cp "$0" "$RUN_COPY"
  bash "$RUN_COPY" "$@"; rc=$?
  rm -f "$RUN_COPY"
  exit $rc
fi
cd "$VEC_DHT_ROOT"
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
LOG="lab/logs/e0089-all.log"
LIB_PY="python lab/library.py"
WORST_RC=0

free_ram_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)" 2>/dev/null \
    | tr -d '\r' | tail -1
}
free_disk_mb() {
  powershell -NoProfile -Command "[int][Math]::Round((Get-PSDrive C).Free / 1MB)" 2>/dev/null | tr -d '\r' | tail -1
}
val() { grep -oE "(^|[[:space:]])$2=[^[:space:]]*" "$1" | tail -1 | cut -d= -f2-; }
note() { echo "$@" | tee -a "$LOG"; }
gate() { local name="$1" want="$2" got="$3";
  if [ "$want" = "$got" ]; then note "ГЕЙТ $name=OK (rc=$got)";
  else note "ГЕЙТ $name=FAIL (хотел rc=$want, получил $got)"; WORST_RC=1; fi; }
bool() { local name="$1" want="$2" got="$3";
  if [ "$want" = "$got" ]; then note "ГЕЙТ $name=OK";
  else note "ГЕЙТ $name=FAIL (ожидалось $want, получено $got)"; WORST_RC=1; fi; }

T1="$(mktemp)"; T2="$(mktemp)"; T3="$(mktemp)"; T4="$(mktemp)"; T5="$(mktemp)"; T6="$(mktemp)"

note ""
note "########## E-0089 · контур источников · прогон $(date +%FT%T%:z) ##########"
note "HEAD: $(git rev-parse --short HEAD)"
note "python: $(python --version 2>&1)"
note "RAM_FREE_MB_BEFORE=$(free_ram_mb) DISK_FREE_MB_BEFORE=$(free_disk_mb)"

# --- порог (0): инструмент собран; продуктовый код и спека не тронуты ------------------------
$LIB_PY --help >/dev/null 2>&1; gate "(0) help" 0 $?
python -m py_compile lab/library.py 2>"$T1"; gate "(0) py_compile" 0 $?
NOTEACH=0
for c in check digest scan verify value add use close; do
  $LIB_PY "$c" --help >/dev/null 2>&1 || { note "  НЕ_ЖИВАЯ подкоманда: $c"; NOTEACH=$((NOTEACH + 1)); }
done
note "МЕРЕНО subcommands_mrtvye=$NOTEACH"
[ "$NOTEACH" = 0 ] || { note "ГЕЙТ (0)=FAIL: подкоманды без --help"; WORST_RC=1; }
DIFF_CODE="$(git diff --stat -- crates docs | wc -l | tr -d ' ')"
note "МЕРЕНО diff_crates_docs_strok=$DIFF_CODE"
[ "$DIFF_CODE" = 0 ] || { note "ГЕЙТ (0)=FAIL: затронут продуктовый код или спека"; WORST_RC=1; }

# --- порог (1): положительные контроли на рабочем индексе ------------------------------------
$LIB_PY check >"$T1" 2>&1; RC=$?; cat "$T1" | tee -a "$LOG"; note "EXIT=$RC"
gate "(1) check" 0 $RC
CR=$(grep -oE "LIBCHECK records=[0-9]+.*errors=[0-9]+[^ ]*" "$T1" | tail -1)
note "МЕРЕНО $CR"
$LIB_PY verify >"$T2" 2>&1; RC=$?; cat "$T2" | tee -a "$LOG"; note "EXIT=$RC"
gate "(1) verify" 0 $RC
grep -oE "LIBVERIFY checked=[0-9]+ matched=[0-9]+ wrong=[0-9]+.*" "$T2" | tail -1 | sed 's/^/МЕРЕНО /' | tee -a "$LOG"
grep -oE "LIBVERIFY_IMPL checked=[0-9]+.*" "$T2" | tail -1 | sed 's/^/МЕРЕНО /' | tee -a "$LOG"
# Починка гнилья прибора (ДИАГНОЗ-1 прогона 2026-10-23, записан в лог): expectation было
# литералом `matched=2`, потому что на момент заморозки в индексе жило 2 arXiv-записи.
# Индекс растёт — литерал гниёт. Смысл порога (1) был «каждое машинно-проверяемое
# подтверждение проверилось и совпало, и их не меньше двух»; теперь так и считаем.
N_PAPER=$(python -c 'import json,io,sys
rows=[json.loads(l) for l in io.open("lab/library/index.jsonl",encoding="utf-8") if l.strip()]
print(sum(1 for r in rows if str(r.get("cite","")).startswith("arXiv:")))')
N_IMPL=$(python -c 'import json,io
rows=[json.loads(l) for l in io.open("lab/library/index.jsonl",encoding="utf-8") if l.strip()]
print(sum(1 for r in rows if r.get("kind")=="реализация" or str(r.get("url","")).startswith("https://github.com/")))')
N_CHECKABLE=$((N_PAPER + N_IMPL))
LV=$(grep -E "^LIBVERIFY " "$T2" | tail -1)
V_MATCH=$(printf '%s\n' "$LV" | grep -oE "matched=[0-9]+" | cut -d= -f2)
V_CHECKED=$(printf '%s\n' "$LV" | grep -oE "checked=[0-9]+" | cut -d= -f2)
V_WRONG=$(printf '%s\n' "$LV" | grep -oE "wrong=[0-9]+" | cut -d= -f2)
LI=$(grep -E "^LIBVERIFY_IMPL " "$T2" | tail -1)
I_MATCH=$(printf '%s\n' "$LI" | grep -oE "matched=[0-9]+" | cut -d= -f2)
I_WRONG=$(printf '%s\n' "$LI" | grep -oE "wrong=[0-9]+" | cut -d= -f2)
note "МЕРЕНО порог1 arxiv_записей=$N_PAPER ссылок_на_код=$N_IMPL проверено_всего=$N_CHECKABLE"
bool "(1) каждое arXiv-подтверждение совпало" "$N_PAPER" "${V_CHECKED:-x}"
bool "(1) каждое совпадение подтверждено" "$N_PAPER" "${V_MATCH:-x}"
bool "(1) ни одного подлога (статьи)" 0 "${V_WRONG:-x}"
bool "(1) каждая ссылка на код проверена машинно" "$N_IMPL" "${I_MATCH:-x}"
bool "(1) ни одного битого пина" 0 "${I_WRONG:-x}"
if [ "$N_CHECKABLE" -ge 2 ]; then note "ГЕЙТ (1) не менее двух машинных сверок=OK ($N_CHECKABLE)";
else note "ГЕЙТ (1) не менее двух машинных сверок=FAIL (получено $N_CHECKABLE)"; WORST_RC=1; fi

# --- порог (2): девять посаженных дефектов обязаны отбиться ------------------------------------
note "### ШАГ 2 девять посаженных дефектов (рабочий индекс не трогается: VEC_DHT_LIBRARY) ###"
python - "$T3" <<'PY'
import json, sys, io, os, subprocess, datetime as dt
out = sys.argv[1]
rows = [json.loads(l) for l in io.open("lab/library/index.jsonl", encoding="utf-8") if l.strip()]
base = rows[0]
def b(**kw):
    r = dict(base); r.update(kw); return r
defects = [
    ("нет_поля", b(gives="")),
    ("id_вне_формата", b(id="L1")),
    ("дубль_id", b(id=rows[1]["id"])),
    ("статус_вне_списка", b(id="L-0010", status="прочитано")),
    ("несуществующая_цель", b(id="L-0011", targets=["H-9999"])),
    ("изменено_без_ссылки", b(id="L-0012", status="изменено", action="просто так", targets=["PLAN"])),
    ("не_повлияло_без_причины", b(id="L-0013", status="не повлияло", action="ок", targets=["PLAN"])),
    ("cost_вне_бюджета", b(id="L-0014", status="в работе", cost_min=31, targets=["PLAN"], action="")),
    ("в_работе_слишком_долго", b(id="L-0015", status="в работе", targets=["PLAN"], action="",
                                  opened=(dt.date.today() - dt.timedelta(days=30)).isoformat())),
]
env = dict(os.environ)
tmp = os.environ.get("TMPDIR", "/tmp") + "/e0089_defect.jsonl"
lines, ok = [], 0
for name, r in defects:
    # Дубликат id сажается ДВУМЯ строками: в файле из одной строки дубликата не существует,
    # и «СЕЛ» в первом прогоне был дефектом посадки, а не checker'а (ДИАГНОЗ-1 прогона).
    pair = [rows[1], r] if name == "дубль_id" else [r]
    io.open(tmp, "w", encoding="utf-8").write(
        "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in pair))
    env["VEC_DHT_LIBRARY"] = tmp
    rc = subprocess.call(["python", "lab/library.py", "check"], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    verdict = "ОТБИТ" if rc == 1 else "СЕЛ"
    lines.append(f"  ДЕФЕКТ {name}: rc={rc} {verdict}")
    ok += 1 if rc == 1 else 0
lines.append(f"МЕРЕНО defects_total={len(defects)} defects_отбито={ok}")
io.open(out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
cat "$T3" | tee -a "$LOG"
DO=$(grep -oE "defects_отбито=[0-9]+" "$T3" | tail -1 | cut -d= -f2)
grep -E "defects_total" "$T3" | sed 's/^/МЕРЕНО /' | tee -a "$LOG"
bool "(2) все девять отбиты" 9 "$DO"

# --- порог (3): неверная цитата обязана быть поймана -------------------------------------------
note "### ШАГ 3 запись с чужим arXiv-id (схема верна, ссылки нет) ###"
python - - <<'PY' > /tmp/e0089_fake_row.jsonl
import json, io, sys
row = {"id": "L-9001", "title": "Eclipse Attacks on Peer-to-Peer Networks",
       "url": "https://arxiv.org/abs/1501.06539", "cite": "arXiv:1501.06539",
       "verified": "2026-10-23", "depth": "аннотация", "kind": "бумага",
       "gives": "посаженная неверная ссылка для контроля (3)", "targets": ["PLAN"],
       "status": "в работе", "action": "", "cost_min": 1, "opened": "2026-10-23"}
print(json.dumps(row, ensure_ascii=False))
PY
VEC_DHT_LIBRARY=/tmp/e0089_fake_row.jsonl $LIB_PY check >"$T4" 2>&1; gate "(3) схема у ловушки верна" 0 $?
VEC_DHT_LIBRARY=/tmp/e0089_fake_row.jsonl $LIB_PY verify >"$T4" 2>&1; RC=$?
cat "$T4" | tee -a "$LOG"; note "EXIT=$RC"
gate "(3) verify поймал не ту статью" 1 $RC
if grep -q "НЕ ТА СТАТЬЯ" "$T4"; then note "ГЕЙТ (3) метка=OK"; else note "ГЕЙТ (3) метка=FAIL: нет строки «НЕ ТА СТАТЬЯ»"; WORST_RC=1; fi

# --- порог (4): недоступная сеть не есть успех --------------------------------------------------
note "### ШАГ 4 сеть недоступна (timeout 0.001 с) ###"
$LIB_PY verify --timeout 0.001 >"$T5" 2>&1; RC=$?
cat "$T5" | tee -a "$LOG"; note "EXIT=$RC"
grep -oE "LIBVERIFY checked=[0-9]+ matched=[0-9]+ wrong=[0-9]+ skipped=[0-9]+ net_unavailable=[0-9]+" "$T5" | tail -1 | sed 's/^/МЕРЕНО offline /' | tee -a "$LOG"
grep -oE "LIBVERIFY_IMPL checked=[0-9]+ matched=[0-9]+ wrong=[0-9]+ skipped=[0-9]+ net_unavailable=[0-9]+" "$T5" | tail -1 | sed 's/^/МЕРЕНО offline /' | tee -a "$LOG"
OLV=$(grep -E "^LIBVERIFY " "$T5" | tail -1)
OLI=$(grep -E "^LIBVERIFY_IMPL " "$T5" | tail -1)
N_CHECKED=$(printf '%s\n' "$OLV" | grep -oE "checked=[0-9]+" | cut -d= -f2)
N_NET=$(printf '%s\n' "$OLV" | grep -oE "net_unavailable=[0-9]+" | cut -d= -f2)
N_NET_IMPL=$(printf '%s\n' "$OLI" | grep -oE "net_unavailable=[0-9]+" | cut -d= -f2)
N_NET_TOTAL=$(( ${N_NET:-0} + ${N_NET_IMPL:-0} ))
note "МЕРЕНО offline недоступно_всего=$N_NET_TOTAL (статей $N_NET + кода $N_NET_IMPL), проверимо было $N_CHECKABLE"
bool "(4) пустое множество не притворяется проверкой" 0 "$N_CHECKED"
bool "(4) недоступность помечена по всем строкам класса бумага" "$N_PAPER" "$N_NET"
bool "(4) недоступность помечена по всем ссылкам на код" "$N_IMPL" "$N_NET_IMPL"
if [ "$N_NET_TOTAL" -ge 2 ]; then note "ГЕЙТ (4) недоступность не молчит=OK ($N_NET_TOTAL)";
else note "ГЕЙТ (4) недоступность не молчит=FAIL (получено $N_NET_TOTAL)"; WORST_RC=1; fi
if grep -qE "СОВПАЛО|ЕСТЬ КОД" "$T5"; then note "ГЕЙТ (4)=FAIL: при недоступной сети напечатано «совпало/есть код»"; WORST_RC=1; else note "ГЕЙТ (4) тишины=OK"; fi

# --- порог (5): дайджест задаёт вопросы по разделам спеки --------------------------------------
note "### ШАГ 5 дайджест: неиспользованное и § без сверки ###"
$LIB_PY digest >"$T6" 2>&1; gate "(5) digest" 0 $?
cat "$T6" | tee -a "$LOG"
grep -oE "LIBTRIGGERS lines=[0-9]+ sections=[0-9]+ uncovered=[0-9]+ covered=[0-9]+" "$T6" | tail -1 | sed 's/^/МЕРЕНО /' | tee -a "$LOG"
D_SECS=$(grep -oE "LIBTRIGGERS lines=[0-9]+ sections=[0-9]+" "$T6" | tail -1 | awk '{print $3}' | cut -d= -f2)
D_OPEN=$(grep -oE "uncovered=[0-9]+" "$T6" | tail -1 | cut -d= -f2)
if [ "${D_SECS:-0}" -ge 5 ] && [ "${D_OPEN:-0}" -ge 1 ]; then note "ГЕЙТ (5а)=OK"; else note "ГЕЙТ (5а)=FAIL: дайджест молчит"; WORST_RC=1; fi
if $LIB_PY scan | grep -E "§14\.4.*Векторы атак" >/dev/null; then
  note "ГЕЙТ (5б)=OK: строка «Векторы атак» отнесена к §14.4"
else
  note "ГЕЙТ (5б)=FAIL: раздел строки определён неверно (ДИАГНОЗ-1 механизма — раздел берётся из заголовка)"; WORST_RC=1
fi
if $LIB_PY scan | grep -E "§9\.2.*Векторы атак" >/dev/null; then
  note "ГЕЙТ (5в)=FAIL: §9.2 из текста строки победил заголовок"; WORST_RC=1
else
  note "ГЕЙТ (5в)=OK: §9.2 не приписан строке §14.4"
fi

# --- порог (6): действие обязано жить в репозитории --------------------------------------------
PLAN_HITS=$(grep -c 'm/n' lab/PLAN.md)
OQ_HITS=$(grep -c 'Black-Hole' lab/decisions/OPEN-QUESTIONS.md)
note "МЕРЕНО plan_ссылок=$PLAN_HITS openquestions_ссылок=$OQ_HITS"
bool "(6) PLAN получил форму капа" 1 "$([ "$PLAN_HITS" -ge 1 ] && echo 1 || echo 0)"
bool "(6) OPEN-QUESTIONS получил вектор" 1 "$([ "$OQ_HITS" -ge 1 ] && echo 1 || echo 0)"

# --- порог (7): критерий полезности не выносится досрочно --------------------------------------
# Починка гнилья прибора (ДИАГНОЗ-2 прогона 2026-10-23): контрольные состояния строились
# НА ЖИВОМ индексе — «до закрытия» означало «в индексе пока 0 закрытых строк», а записей
# в индексе с тех пор стало 6 и все закрыты, поэтому гейт мог быть зелёным только в одном
# прогоне из жизни (этом). Теперь состояние строится на временной копии, а живой индекс
# только читается: контроль не должен портить измеряемый объект (тот же урок, что и
# девять посаженных дефектов шага 2, они пишутся в VEC_DHT_LIBRARY-копию).
# ДИАГНОЗ-3 прогона 2026-10-23: файл, записанный внутри python по имени «/tmp/…», лежит в
# C:\tmp, а та же строка, переданная через окружение из bash, MSYS конвертирует в
# AppData\Local\Temp — checker читал несуществующий индекс и печатал «записей 0», что
# выглядит как зелёный контроль (verdict не готов) там, где состояние вообще не построено.
# Пути создаёт bash через mktemp, python получает их argv'ом: одна вселенная имён.
V2="$(mktemp)"; V5="$(mktemp)"; VD="$(mktemp)"
note "### ШАГ 7 критерий: три состояния индекса на временных копиях ###"
python - "$V2" "$V5" "$VD" <<'PY'
import json, io, sys
rows = [json.loads(l) for l in io.open("lab/library/index.jsonl", encoding="utf-8") if l.strip()]
def dump(path, closed_ids, status):
    out = []
    for r in rows:
        r.pop("_line", None)
        if r["id"] in closed_ids:
            r["status"] = status
            r["cost_min"] = 12
            r["action"] = ("PLAN п. 8б: форма капа ⌈c·m/n⌉ — правка гипотезы H-0088 "
                           "до её пре-регистрации" if status == "изменено"
                           else "прочитано, на пороги и гипотезу этого цикла не повлияло: "
                                "механизм в нашей сети другой")
        else:
            r["status"] = "не использован"; r["targets"] = []; r["action"] = ""; r["cost_min"] = 0
        out.append(r)
    io.open(path, "w", encoding="utf-8").write("".join(
        json.dumps(x, ensure_ascii=False) + "\n" for x in out))
ids = [r["id"] for r in rows]
dump(sys.argv[1], set(ids[:2]), "изменено")
dump(sys.argv[2], set(ids[:5]), "изменено")
dump(sys.argv[3], set(ids[:5]), "не повлияло")
print("посажжено состояний=3 записей_в_индексе=%d" % len(rows))
PY
$LIB_PY value --cycles 5 >"$T1" 2>&1; cat "$T1" | tee -a "$LOG"
note "МЕРЕНО живой_индекс_как_есть=$(grep -E '^LIBVALUE' "$T1" | tail -1)"
VEC_DHT_LIBRARY="$V2" $LIB_PY value --cycles 5 >"$T1" 2>&1
cat "$T1" | tee -a "$LOG"
if grep -q "ВЕРДИКТ не готов" "$T1" && grep -q "LIBVALUE closed=2" "$T1";
then note "ГЕЙТ (7а) при 2 из 5 закрытых вердикт молчит=OK";
else note "ГЕЙТ (7а)=FAIL: состояние не построено или вердикт вынесен при 2 < 5"; WORST_RC=1; fi
VEC_DHT_LIBRARY="$V5" $LIB_PY value --cycles 5 >"$T1" 2>&1
cat "$T1" | tee -a "$LOG"
if grep -q "КОНТУР ГОДЕН" "$T1" && grep -q "LIBVALUE closed=5" "$T1";
then note "ГЕЙТ (7б) при 5 закрытых с изменением=OK";
else note "ГЕЙТ (7б)=FAIL: выполнимый критерий не срабатывает (ДИАГНОЗ-1 из E-0087)"; WORST_RC=1; fi
VEC_DHT_LIBRARY="$VD" $LIB_PY value --cycles 5 >"$T1" 2>&1
cat "$T1" | tee -a "$LOG"
if grep -q "КОНТУР ДЕКОРАТИВЕН" "$T1" && grep -q "verdict=decorative" "$T1";
then note "ГЕЙТ (7в) пять прочитанных без действия=OK";
else note "ГЕЙТ (7в)=FAIL: декоративный контур получает зелёный вердикт"; WORST_RC=1; fi
rm -f "$V2" "$V5" "$VD"

# --- порог (8): след, зеркало спеки, YAML, ресурсы ----------------------------------------------
$LIB_PY check >"$T1" 2>&1; RC=$?; cat "$T1" | tee -a "$LOG"; gate "(8) финальный check" 0 $RC
bash lab/check-spec-mirror.sh >"$T4" 2>&1; RC=$?; tail -3 "$T4" | tee -a "$LOG"; gate "(8) зеркало спеки" 0 $RC
python - - <<'PY' 2>&1 | tee -a "$LOG"
import yaml, io, sys
want = {"lab/hypotheses/H-0089-prior-art-contour.md": ("id", "claim", "falsifier", "oracle",
                                                       "threshold", "prior_art"),
        "lab/decisions/ADR-0045-prior-art-contour.md": ("id", "status", "cycle", "spec", "depends")}
rc = 0
for path, keys in want.items():
    text = io.open(path, encoding="utf-8").read()
    body = text.split("---")[1]
    fm = yaml.safe_load(body)
    missing = [k for k in keys if k not in fm]
    print(f"YAML {path}: ключей={len(fm)} пропущено={missing}")
    if missing:
        rc = 1
sys.exit(rc)
PY
gate "(8) YAML карточек" 0 ${PIPESTATUS[0]:-0}
note "### ШАГ 8б текстура текста (гейт (9)) ###"
# После пре-регистрационного коммита `git diff HEAD` пуст, поэтому список файлов берётся из
# самого коммита-pre-registration (только `lab/`): проверка обязана ловить этот цикл, а не
# случайное рабочее дерево.
CYCLE_FILES="$(git show --name-only --pretty=format: HEAD | tr -d '\r' | grep -E '^lab/' | grep -v '^lab/logs/' | tr '\n' ' ')"
note "МЕРЕНО текстовых_файлов_цикла=$(echo $CYCLE_FILES | wc -w)"
bash lab/check-text-clean.sh $CYCLE_FILES >"$T6" 2>&1; RC=$?
cat "$T6" | tee -a "$LOG"; note "EXIT=$RC"
gate "(9) check-text-clean" 0 $RC
note "RAM_FREE_MB_AFTER=$(free_ram_mb) DISK_FREE_MB_AFTER=$(free_disk_mb)"
note "TARGET_MB=$(du -sm target 2>/dev/null | cut -f1 | tail -1) LOG_MB=$(du -m lab/logs/e0089-all.log 2>/dev/null | cut -f1)"
note "ВНМАНИЕ: cargo clean не исполнялся; продуктовый код, wire и docs этого цикла не тронуты (см. МЕРЕНО diff_crates_docs_strok)"

note "ИТОГ $(date +%FT%T%:z): HELPER_EXIT=$WORST_RC"
echo "HELPER_EXIT=$WORST_RC" | tee -a "$LOG"
rm -f "$T1" "$T2" "$T3" "$T4" "$T5" "$T6" /tmp/e0089_defect.jsonl /tmp/e0089_fake_row.jsonl
exit $WORST_RC
