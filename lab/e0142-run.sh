#!/usr/bin/env bash
# H-0142 / E-0142: прибор второй машины — снимок золотых векторов и сверка чужого лога.
# Условие 3 релиза (`ADR-0044`) требует сценарий на разных машинах, а вторая половина P2 — побайтовое
# совпадение golden-векторов на второй машине. Сегодня это обещание без прибора: `lab/two-hosts.sh`
# готовит сценарий, но ни один файл дерева не умеет ни снять снимок векторов, ни отличить чужой лог
# от своего. Круг заводит `lab/two-machine.py`; сам прогон на машине B остаётся за владельцем, здесь
# проверяется «чем сверять и по какому праву».
#
# Измеренная ловушка круга: байты вектора — blob в git, а не рабочая форма. Тест перезаписывает
# фикстуры через `writeln!`, и на Windows рабочая форма получает CRLF (30/66/22 строк), тогда как blob
# хранит LF (4509/23137/11787 байт). Сверка рабочих байтов между машинами краснела бы на исправном
# дереве, поэтому прибор сверяет blob и `CLEAN`, а рабочую форму печатает для диагноза.
#
# PRE_FIX исполняется «отсутствием» (довод `E-0138`): в пине прибора нет, `git show <пин>:lab/
# two-machine.py` пуст, ключей снимка — ноль. Рабочее дерево и индекс не трогаются: пин читается
# `git show` во временный каталог, а не `git checkout` (тот пишет в индекс, `E-0139`, ДИАГНОЗ-3).
#
# Ключи печатаются литералами (`emit SNAP_FIXTURE_...`), без склейки: линт порогов обязан узнавать
# сам себя, а таблица этого круга — быть слепой к собственной форме печати не больше, чем к чужой.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }
# Пустой ключ обязан стать `none`, а не пустой строкой: `expect.py` читает пустое как «не найдено».
grab() { v=$(grep -o "^$2=[0-9A-Za-z/.,:%_-]*" "$1" | tail -1 | cut -d= -f2); [ -n "$v" ] && echo "$v" || echo none; }

# --- PRE_FIX: в пине прибора нет, и это измерено, а не заявлено ---------------------------------
PIN=$(git log --format=%H --grep="H-0142 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "${PIN:-}" ] && echo 1 || echo 0)"
if [ -n "${PIN:-}" ]; then
  git show "$PIN:lab/two-machine.py" > "${SCR}tm-pin.py" 2>/dev/null
else
  : > "${SCR}tm-pin.py"
fi
emit PRE_FIX_INSTRUMENT "$([ -s "${SCR}tm-pin.py" ] && echo 1 || echo 0)"
PRE_KEYS=0; PRE_SNAP=none
if [ -s "${SCR}tm-pin.py" ]; then
  python "${SCR}tm-pin.py" snapshot --label pre-fix > "${SCR}pin-snap.txt" 2>&1
  PRE_KEYS=$(grep -c '^TM_[A-Za-z0-9_]*=' "${SCR}pin-snap.txt" || true)
  [ "${PRE_KEYS:-0}" -gt 0 ] && PRE_SNAP=built
fi
emit PRE_FIX_KEYS "$PRE_KEYS"
emit PRE_FIX_SNAPSHOT "$PRE_SNAP"

# --- гейт и диск -------------------------------------------------------------------------------
python lab/cycle-gate.py gate H-0142 > "${SCR}gate.txt" 2>&1; gr=$?
emit GATE_H0142_OK "$([ "$gr" = 0 ] && echo 1 || echo 0)"
bash lab/disk-report.sh > "${SCR}disk.txt" 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' "${SCR}disk.txt" | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# --- самопроверка сверщика: 24 посаженных случая ----------------------------------------------
python lab/two-machine.py selftest > "${SCR}st.txt" 2>&1; emit SELFTEST_EXIT $?
ST() { grep -o "СЕЛФТЕСТ_ИТОГ total=[0-9]* passed=[0-9]* failed=[0-9]*" "${SCR}st.txt" | tail -1; }
emit SELFTEST_TOTAL "$(ST | grep -o 'total=[0-9]*' | cut -d= -f2)"
emit SELFTEST_PASSED "$(ST | grep -o 'passed=[0-9]*' | cut -d= -f2)"

# --- снимок машины A: 35 ключей, три золотых теста --------------------------------------------
python lab/two-machine.py snapshot --label machine-A > "${SCR}snap.txt" 2>&1; emit SNAP_EXIT $?
emit SNAP_KEYS "$(grep -c '^TM_[A-Za-z0-9_]*=' "${SCR}snap.txt" || true)"
snap() { grab "${SCR}snap.txt" "$1"; }
emit SNAP_MACHINE "$(snap TM_MACHINE)"
emit SNAP_OK "$(snap TM_SNAPSHOT_OK)"
emit SNAP_ESCAPE "$(snap TM_FIXTURE_ESCAPE)"
emit SNAP_DIRTY "$(snap TM_DIRTY)"
emit SNAP_ROOT_NAME "$(snap TM_ROOT_NAME)"
emit SNAP_TESTS_RAN "$(snap TM_TESTS_RAN)"
emit SNAP_TESTS_OK "$(snap TM_TESTS_OK)"
emit SNAP_FIXTURE_crypto_BLOB_SHA256 "$(snap TM_FIXTURE_crypto_BLOB_SHA256)"
emit SNAP_FIXTURE_crypto_BLOB_BYTES "$(snap TM_FIXTURE_crypto_BLOB_BYTES)"
emit SNAP_FIXTURE_crypto_WORK_BYTES "$(snap TM_FIXTURE_crypto_WORK_BYTES)"
emit SNAP_FIXTURE_crypto_WORK_CRLF "$(snap TM_FIXTURE_crypto_WORK_CRLF)"
emit SNAP_FIXTURE_crypto_CLEAN "$(snap TM_FIXTURE_crypto_CLEAN)"
emit SNAP_FIXTURE_wire_BLOB_SHA256 "$(snap TM_FIXTURE_wire_BLOB_SHA256)"
emit SNAP_FIXTURE_wire_BLOB_BYTES "$(snap TM_FIXTURE_wire_BLOB_BYTES)"
emit SNAP_FIXTURE_wire_WORK_BYTES "$(snap TM_FIXTURE_wire_WORK_BYTES)"
emit SNAP_FIXTURE_wire_WORK_CRLF "$(snap TM_FIXTURE_wire_WORK_CRLF)"
emit SNAP_FIXTURE_wire_CLEAN "$(snap TM_FIXTURE_wire_CLEAN)"
emit SNAP_FIXTURE_artifact_BLOB_SHA256 "$(snap TM_FIXTURE_artifact_BLOB_SHA256)"
emit SNAP_FIXTURE_artifact_BLOB_BYTES "$(snap TM_FIXTURE_artifact_BLOB_BYTES)"
emit SNAP_FIXTURE_artifact_WORK_BYTES "$(snap TM_FIXTURE_artifact_WORK_BYTES)"
emit SNAP_FIXTURE_artifact_WORK_CRLF "$(snap TM_FIXTURE_artifact_WORK_CRLF)"
emit SNAP_FIXTURE_artifact_CLEAN "$(snap TM_FIXTURE_artifact_CLEAN)"

# --- сверка собственного снимка ----------------------------------------------------------------
python lab/two-machine.py verify "${SCR}snap.txt" > "${SCR}v.txt" 2>&1; emit VERIFY_EXIT $?
vw() { grab "${SCR}v.txt" "$1"; }
emit V_HEAD_MATCH "$(vw TMV_HEAD_MATCH)"
emit V_MATCH "$(vw TMV_MATCH)"
emit V_MISMATCH "$(vw TMV_MISMATCH)"
emit V_MISSING "$(vw TMV_MISSING)"
emit V_FOREIGN "$(vw TMV_FOREIGN)"
emit V_DUPLICATE "$(vw TMV_DUPLICATE)"
emit V_TESTS "$(vw TMV_TESTS)"
emit V_TESTS_OK "$(vw TMV_TESTS_OK)"
emit V_VERDICT "$(vw TMV_VERDICT)"
emit V_REASONS "$(vw TMV_REASONS)"

# --- подмена blob-хеша: отказ обязан назвать ключ ----------------------------------------------
Z=$(printf '0%.0s' $(seq 1 64))
sed "s/^TM_FIXTURE_wire_BLOB_SHA256=.*/TM_FIXTURE_wire_BLOB_SHA256=${Z}/" "${SCR}snap.txt" > "${SCR}tamper.txt"
python lab/two-machine.py verify "${SCR}tamper.txt" > "${SCR}tv.txt" 2>&1; emit TAMPER_EXIT $?
emit TAMPER_VERDICT "$(grab "${SCR}tv.txt" TMV_VERDICT)"
emit TAMPER_MATCH "$(grab "${SCR}tv.txt" TMV_MATCH)"
emit TAMPER_MISMATCH "$(grab "${SCR}tv.txt" TMV_MISMATCH)"

# --- законное различие: машина B со свежим клоном (рабочая форма LF) ---------------------------
# Крипто-фикстура в свежем клоне лежит LF: рабочая форма равна blob. Это НЕ дефект, и вердикт
# обязан остаться `pass`; сверка рабочих байтов здесь покраснела бы на исправном дереве.
CB=$(snap TM_FIXTURE_crypto_BLOB_SHA256)
sed -e 's/^TM_MACHINE=.*/TM_MACHINE=linux-x86_64/' -e 's/^TM_LABEL=.*/TM_LABEL=machine-B/' \
  -e "s/^TM_FIXTURE_crypto_WORK_SHA256=.*/TM_FIXTURE_crypto_WORK_SHA256=${CB}/" \
  -e 's/^TM_FIXTURE_crypto_WORK_BYTES=.*/TM_FIXTURE_crypto_WORK_BYTES=4509/' \
  -e 's/^TM_FIXTURE_crypto_WORK_CRLF=.*/TM_FIXTURE_crypto_WORK_CRLF=0/' \
  -e 's/^TM_FIXTURE_crypto_WORK_LINES=.*/TM_FIXTURE_crypto_WORK_LINES=30/' \
  "${SCR}snap.txt" > "${SCR}other.txt"
python lab/two-machine.py verify "${SCR}other.txt" > "${SCR}ov.txt" 2>&1; emit OTHER_EXIT $?
emit OTHER_VERDICT "$(grab "${SCR}ov.txt" TMV_VERDICT)"

# --- соседние стражи --------------------------------------------------------------------------
bash lab/check-secrets.sh --no-history > "${SCR}sec.txt" 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py > "${SCR}refs.txt" 2>&1; emit REFS_EXIT $?
python lab/check-claim-map.py > "${SCR}cmap.txt" 2>&1; emit CLAIMMAP_EXIT $?
python lab/check-claims.py > "${SCR}claims.txt" 2>&1; emit CLAIMS_EXIT $?
python lab/check-contours.py > "${SCR}contours.txt" 2>&1; emit CONTOURS_EXIT $?
bash lab/check-text-clean.sh --all > "${SCR}all.txt" 2>&1; emit TEXTGUARD_ALL_EXIT $?
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' "${SCR}all.txt" | tail -1 | cut -d= -f2)"
bash lab/check-text-clean.sh lab/two-machine.py lab/e0142-run.sh lab/expectations/e0142.tsv \
  lab/hypotheses/H-0142-two-machine.md lab/experiments/E-0142-two-machine.md > "${SCR}text.txt" 2>&1
emit TEXTGUARD_CYCLE_EXIT $?
bash lab/check-spec-mirror.sh > "${SCR}mirror.txt" 2>&1; emit MIRROR_EXIT $?
python lab/threshold-lint.py --latest > "${SCR}lint.txt" 2>&1; emit LINT_LATEST_EXIT $?
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' "${SCR}lint.txt" | tail -1 | cut -d= -f2)"
python lab/cycle-gate.py audit > "${SCR}audit.txt" 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check > "${SCR}review.txt" 2>&1; emit REVIEW_EXIT $?
emit RUST_TOUCHED "$(git diff --name-only "${PIN:-HEAD}" -- crates/ | wc -l | tr -d ' ')"

WORST=0
for k in SELFTEST_EXIT SNAP_EXIT VERIFY_EXIT SECRETS_EXIT REFS_EXIT CLAIMMAP_EXIT CLAIMS_EXIT \
         CONTOURS_EXIT TEXTGUARD_ALL_EXIT TEXTGUARD_CYCLE_EXIT MIRROR_EXIT LINT_LATEST_EXIT \
         GATE_AUDIT_EXIT REVIEW_EXIT; do
  v=$(grep -o "^$k=[0-9]*" "$buf" | tail -1 | cut -d= -f2); [ "${v:-1}" = 0 ] || WORST=1
done
# Подмена обязана быть отвергнута и названа поимённо; собственный снимок и чужая рабочая форма —
# засчитаны. Дыра названа отсутствием, снимок полон, формы не расходятся с таблицей.
[ "$(grab "$buf" TAMPER_EXIT)" = 1 ] || WORST=1
[ "$(grab "$buf" TAMPER_VERDICT)" = fail ] || WORST=1
[ "$(grab "$buf" OTHER_EXIT)" = 0 ] || WORST=1
[ "$(grab "$buf" OTHER_VERDICT)" = pass ] || WORST=1
[ "$(grab "$buf" V_VERDICT)" = pass ] || WORST=1
[ "$(grab "$buf" SNAP_KEYS)" = 35 ] || WORST=1
[ "$(grab "$buf" SNAP_TESTS_OK)" = 3 ] || WORST=1
[ "$(grab "$buf" PRE_FIX_INSTRUMENT)" = 0 ] || WORST=1
[ "$(grab "$buf" PRE_FIX_KEYS)" = 0 ] || WORST=1
[ "$(grab "$buf" GATE_H0142_OK)" = 1 ] || WORST=1
emit WORST_RC "$WORST"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0142-${TREE_KEY}.facts"
# Диск и собственный вердикт повторяемости не входят в то, что вердикт сверяет (довод `E-0141`).
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$buf" > "$SNAP"
cat "$buf"; rm -f "$buf"; rm -rf "$SCR"
