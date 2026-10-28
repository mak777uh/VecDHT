#!/usr/bin/env bash
# H-0140 / E-0140: сведение линта порогов по всем таблицам ожиданий закрытых циклов.
# Прежний линт знал три формы печати (литерал, воронку, Rust-воронку) и объявлял сиротами 26 ключей в
# пяти закрытых таблицах: цикл `for kind in axiom weaken` и числовой `for i in 1 2` (`e0093`), список
# имён и метка прогона в `grab … "$DR_KEYS"` со `strip_run` (`e0095`), `printf 'n%s_%s'` со списком-
# аргументом (`e0099`), приставка аргументом `${pre}${key}` (`e0123`), `grep -E` + перепечатка
# `printf "%s=%s" "$k"` + переименование + тег `--tag` (`e0131`). Цикл приборный: продукт не трогается
# (`RUST_TOUCHED=0`), правится только `lab/threshold-lint.py`.
#
# PRE_FIX исполняется ПИН-прибором, извлечённым `git show "$PIN:lab/threshold-lint.py"` во временный
# каталог: рабочее дерево и индекс не трогаются ни на одном шаге. Пин не знает режима свода, поэтому
# PRE_FIX идёт по таблицам по одной (`--sources crates benches lab`) — тем же прибором, каким линт
# работал в закрытых циклах. Своя таблица (`e0140.tsv`) исключена и это названо фактом: пин-прибор не
# печатает `СВЕД_*`, и её ключи — прибор над прибором, а не предмет пробы. Множество таблиц сверяется с
# тем, что видит живой свод (`TABLES_AGREE`).
#
# Ключи печатаются литералами (`emit LIVE_...`), без склейки: линт порогов обязан узнавать сам себя.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }
# Пустой ключ обязан стать `none`, а не пустой строкой: пустое значение сверка читает как «не найдено»
# (ДИАГНОЗ круга `E-0139`).
grab() { v=$(grep -o "^$2=[0-9A-Za-z/.,:%_-]*" "$1" | tail -1 | cut -d= -f2); [ -n "$v" ] && echo "$v" || echo none; }
# Сводку пин-прибора (`ПОРОГОВ=… СИРОТ=n`) `grab` не читает: якорь `^` находит только первый ключ
# строки. Чужой stdout сначала раскладывается по строкам (тот же довод, что в `E-0141`).
grabi() { v=$(tr ' \t' '\n\n' < "$1" | grep -o "^$2=[0-9A-Za-z/.,:%_-]*" | tail -1 | cut -d= -f2); [ -n "$v" ] && echo "$v" || echo none; }
# Строка сироты обязана назвать ключ: «красный» без имени не отличает класс от соседнего дефекта.
orph() { grep -F 'ПОРОГ БЕЗ ПРИБОРА' "$1" | grep -qF "$2" && echo 1 || echo 0; }

PIN=$(git log --format=%H --grep="H-0140 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "${PIN:-}" ] && echo 1 || echo 0)"
if [ -n "${PIN:-}" ]; then
  git show "$PIN:lab/threshold-lint.py" > "${SCR}tl-pin.py" 2>/dev/null
else
  : > "${SCR}tl-pin.py"
fi
emit PRE_FIX_INSTRUMENT "$([ -s "${SCR}tl-pin.py" ] && echo 1 || echo 0)"
emit PRE_FIX_PIN_LINES "$(wc -l < "${SCR}tl-pin.py" | tr -d ' ')"
# Пин обязан быть ДО починки: наличие режима свода означало бы, что измеряется не та дыра.
emit PRE_FIX_HAS_SWEEP "$([ -s "${SCR}tl-pin.py" ] && { grep -c -- '--sweep' "${SCR}tl-pin.py" || true; } || echo none)"

# --- PRE_FIX: пин-прибор по таблицам закрытых циклов, по одной --------------------------------
: > "${SCR}pin-sweep.txt"
PRE_TABS=0; PRE_TOTAL=0; PRE_WITH=0; PRE_SELF=0; PRE_NOSUM=0
if [ -s "${SCR}tl-pin.py" ]; then
  for t in lab/expectations/*.tsv; do
    base=$(basename "$t" .tsv)
    if [ "$base" = "e0140" ]; then PRE_SELF=1; continue; fi
    PRE_TABS=$((PRE_TABS + 1))
    python "${SCR}tl-pin.py" "$t" --sources crates benches lab > "${SCR}pin-one.txt" 2>&1
    n=$(grabi "${SCR}pin-one.txt" СИРОТ)
    # Прибор, не напечатавший сводку, обязан быть назван, а не прочитан как ноль сирот.
    [ "$n" = none ] && { PRE_NOSUM=$((PRE_NOSUM + 1)); n=0; }
    PRE_TOTAL=$((PRE_TOTAL + n))
    [ "$n" -gt 0 ] && PRE_WITH=$((PRE_WITH + 1))
    printf '### %s СИРОТ=%s\n' "$base" "$n" >> "${SCR}pin-sweep.txt"
    grep -F 'ПОРОГ БЕЗ ПРИБОРА' "${SCR}pin-one.txt" >> "${SCR}pin-sweep.txt"
  done
fi
emit PRE_FIX_SELF_EXCLUDED "$PRE_SELF"
emit PRE_FIX_TABLES "$PRE_TABS"
emit PRE_FIX_SIROT "$PRE_TOTAL"
emit PRE_FIX_TABLES_WITH_SIROT "$PRE_WITH"
emit PRE_FIX_NO_SUMMARY "$PRE_NOSUM"
pre_tab() { v=$(grep -o "^### $1.tsv СИРОТ=[0-9]*" "${SCR}pin-sweep.txt" | tail -1 | cut -d= -f2); [ -n "$v" ] && echo "$v" || echo none; }
emit PRE_FIX_E0093 "$(pre_tab e0093)"
emit PRE_FIX_E0095 "$(pre_tab e0095)"
emit PRE_FIX_E0099 "$(pre_tab e0099)"
emit PRE_FIX_E0123 "$(pre_tab e0123)"
emit PRE_FIX_E0131 "$(pre_tab e0131)"
# По одному представителю каждой формы: имя класса, а не только счёт.
emit PRE_FIX_KEY_AXIOM "$(orph "${SCR}pin-sweep.txt" PRE_FIX_axiom_EXIT)"
emit PRE_FIX_KEY_DR "$(orph "${SCR}pin-sweep.txt" dr_g3_door_authenticated)"
emit PRE_FIX_KEY_VERUS "$(orph "${SCR}pin-sweep.txt" n1_VERUS_VERIFIED)"
emit PRE_FIX_KEY_CLAIMMAP "$(orph "${SCR}pin-sweep.txt" PRE_CLAIMMAP_SENTENCES)"
emit PRE_FIX_KEY_ALLOWLIST "$(orph "${SCR}pin-sweep.txt" ALLOWLIST_EMPTY_REASON)"

# --- LIVE: свод по всем закрытым таблицам одним проходом --------------------------------------
python lab/threshold-lint.py --sweep --verbose > "${SCR}sweep.txt" 2>&1; emit LIVE_SWEEP_EXIT $?
sv() { v=$(grab "${SCR}sweep.txt" "$1"); [ -n "$v" ] && echo "$v" || echo none; }
emit LIVE_TABLES "$(sv СВЕД_ТАБЛИЦ)"
emit LIVE_CLOSED "$(sv СВЕД_ЗАКРЫТЫХ)"
emit LIVE_KEYS "$(sv СВЕД_ПОРОГОВ)"
emit LIVE_SOURCES "$(sv СВЕД_ИСТОЧНИКОВ)"
emit LIVE_CARRIER "$(sv СВЕД_НОСИТЕЛЕЙ)"
emit LIVE_FORM_LITERAL "$(sv СВЕД_ФОРМА_ЛИТЕРАЛОМ)"
emit LIVE_FORM_FUNNEL "$(sv СВЕД_ФОРМА_ВОРОНКОЙ)"
emit LIVE_FORM_RUSTFUNNEL "$(sv СВЕД_ФОРМА_RUST-ВОРОНКОЙ)"
emit LIVE_FORM_TEMPLATE "$(sv СВЕД_ФОРМА_ШАБЛОНОМ)"
emit LIVE_FORM_LOOP "$(sv СВЕД_ФОРМА_ЦИКЛОМ)"
emit LIVE_FORM_SPLICE "$(sv СВЕД_ФОРМА_СКЛЕЙКОЙ)"
emit LIVE_FORM_REPRINT "$(sv СВЕД_ФОРМА_ПЕРЕПЕЧАТКОЙ)"
emit LIVE_FORM_TAG "$(sv СВЕД_ФОРМА_ТЕГОМ)"
emit LIVE_FORM_CARRIER "$(sv СВЕД_ФОРМА_НОСИТЕЛЕМ)"
emit LIVE_SIROT "$(sv СВЕД_СИРОТ)"
emit LIVE_TABLES_WITH_SIROT "$(sv СВЕД_ТАБЛИЦ_С_СИРОТАМИ)"
emit LIVE_CROSSCHECKED "$(sv СВЕД_ПРОВЕРЕНО_ЭТАЛОНОМ)"
emit LIVE_DIVERGE "$(sv СВЕД_РАСХОЖДЕНИЙ_ИНДЕКСА)"
nz() { v=$(sv "$1"); [ "$v" = none ] && echo 0 || echo "$v"; }
emit LIVE_FORM_SUM "$(( $(nz СВЕД_ФОРМА_ЛИТЕРАЛОМ) + $(nz СВЕД_ФОРМА_ВОРОНКОЙ) \
  + $(nz СВЕД_ФОРМА_RUST-ВОРОНКОЙ) + $(nz СВЕД_ФОРМА_ШАБЛОНОМ) + $(nz СВЕД_ФОРМА_ЦИКЛОМ) \
  + $(nz СВЕД_ФОРМА_СКЛЕЙКОЙ) + $(nz СВЕД_ФОРМА_ПЕРЕПЕЧАТКОЙ) + $(nz СВЕД_ФОРМА_ТЕГОМ) \
  + $(nz СВЕД_ФОРМА_НОСИТЕЛЕМ) ))"
emit TABLES_AGREE "$([ "$(grab "$buf" PRE_FIX_TABLES)" = "$(grab "$buf" LIVE_TABLES)" ] && echo 1 || echo 0)"
# Те же пять ключей, что пин объявил сиротами, живой свод обязан не называть сиротами вовсе.
emit LIVE_ORPHAN_AXIOM "$(orph "${SCR}sweep.txt" PRE_FIX_axiom_EXIT)"
emit LIVE_ORPHAN_DR "$(orph "${SCR}sweep.txt" dr_g3_door_authenticated)"
emit LIVE_ORPHAN_VERUS "$(orph "${SCR}sweep.txt" n1_VERUS_VERIFIED)"
emit LIVE_ORPHAN_CLAIMMAP "$(orph "${SCR}sweep.txt" PRE_CLAIMMAP_SENTENCES)"
emit LIVE_ORPHAN_ALLOWLIST "$(orph "${SCR}sweep.txt" ALLOWLIST_EMPTY_REASON)"

# --- самопроверка прибора: посаженные дефекты всех девяти классов -------------------------------
python lab/threshold-lint.py --selftest > "${SCR}st.txt" 2>&1; emit SELFTEST_EXIT $?
emit SELFTEST_TOTAL "$(grep -o 'THRESHOLD_LINT_SELFTEST total=[0-9]*' "${SCR}st.txt" | tail -1 | cut -d= -f2)"
emit SELFTEST_PASSED "$(grep -o 'SELFTEST total=[0-9]* passed=[0-9]*' "${SCR}st.txt" | tail -1 | cut -d= -f3)"
# Измеренный дефект алфавита (`repro_вектор` в `E-0093`…`E-0095`) обязан быть заперт посадкой.
emit SELFTEST_CYRILLIC "$(grep -qF 'СЕЛФТЕСТ ok: кириллица в имени печатаемого ключа' "${SCR}st.txt" && echo 1 || echo 0)"
emit SELFTEST_CYRILLIC_NEG "$(grep -qF 'СЕЛФТЕСТ ok: кириллица в имени ненапечатанного ключа' "${SCR}st.txt" && echo 1 || echo 0)"

# --- соседние стражи и гейты --------------------------------------------------------------------
python lab/cycle-gate.py gate H-0140 > "${SCR}gate.txt" 2>&1; gr=$?
emit GATE_H0140_OK "$([ "$gr" = 0 ] && echo 1 || echo 0)"
bash lab/disk-report.sh > "${SCR}disk.txt" 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' "${SCR}disk.txt" | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0
bash lab/check-secrets.sh --no-history > "${SCR}sec.txt" 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py > "${SCR}refs.txt" 2>&1; emit REFS_EXIT $?
python lab/check-claim-map.py > "${SCR}cmap.txt" 2>&1; emit CLAIMMAP_EXIT $?
python lab/check-claims.py > "${SCR}claims.txt" 2>&1; emit CLAIMS_EXIT $?
python lab/check-contours.py > "${SCR}contours.txt" 2>&1; emit CONTOURS_EXIT $?
bash lab/check-text-clean.sh --all > "${SCR}all.txt" 2>&1; emit TEXTGUARD_ALL_EXIT $?
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' "${SCR}all.txt" | tail -1 | cut -d= -f2)"
bash lab/check-text-clean.sh lab/threshold-lint.py lab/e0140-run.sh lab/expectations/e0140.tsv \
  lab/hypotheses/H-0140-threshold-sweep.md > "${SCR}text.txt" 2>&1
emit TEXTGUARD_CYCLE_EXIT $?
bash lab/check-spec-mirror.sh > "${SCR}mirror.txt" 2>&1; emit MIRROR_EXIT $?
python lab/threshold-lint.py --latest > "${SCR}lint.txt" 2>&1; emit LINT_LATEST_EXIT $?
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' "${SCR}lint.txt" | tail -1 | cut -d= -f2)"
python lab/cycle-gate.py audit > "${SCR}audit.txt" 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check > "${SCR}review.txt" 2>&1; emit REVIEW_EXIT $?
emit RUST_TOUCHED "$(git diff --name-only "${PIN:-HEAD}" -- crates/ | wc -l | tr -d ' ')"

WORST=0
for k in SELFTEST_EXIT LIVE_SWEEP_EXIT SECRETS_EXIT REFS_EXIT CLAIMMAP_EXIT CLAIMS_EXIT \
         CONTOURS_EXIT TEXTGUARD_ALL_EXIT TEXTGUARD_CYCLE_EXIT MIRROR_EXIT LINT_LATEST_EXIT \
         GATE_AUDIT_EXIT REVIEW_EXIT; do
  v=$(grep -o "^$k=[0-9]*" "$buf" | tail -1 | cut -d= -f2); [ "${v:-1}" = 0 ] || WORST=1
done
# Годность починки: дыра названа (пин видит 26 сирот в 5 таблицах), живой свод закрывает все ключи,
# быстрый индекс не расходится с медленным эталоном, формы разбивают множество без остатка.
[ "$(grab "$buf" PRE_FIX_SIROT)" = 26 ] || WORST=1
[ "$(grab "$buf" PRE_FIX_TABLES_WITH_SIROT)" = 5 ] || WORST=1
[ "$(grab "$buf" LIVE_SIROT)" = 0 ] || WORST=1
[ "$(grab "$buf" LIVE_DIVERGE)" = 0 ] || WORST=1
[ "$(grab "$buf" LIVE_FORM_SUM)" = "$(grab "$buf" LIVE_KEYS)" ] || WORST=1
[ "$(grab "$buf" TABLES_AGREE)" = 1 ] || WORST=1
[ "$(grab "$buf" GATE_H0140_OK)" = 1 ] || WORST=1
[ "$(grab "$buf" PRE_FIX_NO_SUMMARY)" = 0 ] || WORST=1
emit WORST_RC "$WORST"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0140-${TREE_KEY}.facts"
# Из сравнения исключены диск и собственный вердикт повторяемости: они дышат между прогонами
# (тот же довод, что в `E-0141`: вердикт о повторяемости не входит в то, что он сверяет).
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$buf" > "$SNAP"
cat "$buf"; rm -f "$buf"; rm -rf "$SCR"
