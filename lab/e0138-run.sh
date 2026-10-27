#!/usr/bin/env bash
# H-0138 / E-0138: сведение закрытых карточек очереди с блоками прогона контура
# (`lab/check-contours.py` + `lab/contour-exceptions.tsv`). Цикл приборный: продукта не касается
# (`RUST_TOUCHED=0`). PRE_FIX исполняется посадкой отсутствием: файл исключений убирается во
# временный каталог, на этом дереве гоняется тот же прибор, затем `trap` возвращает его на место —
# на пине пре-регистрации файла нет, и посадка воспроизводит ровно то дерево, а не цитату о нём.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }
grab() { grep -o "^$2=[0-9A-Za-z/._-]*" "$1" | tail -1 | cut -d= -f2; }

# --- посадка: дерево без файла исключений, возврат по trap --------------------------------------
EXC=lab/contour-exceptions.tsv
HELD="${SCR}contour-exceptions.held"
PIN=$(git log --format=%H --grep="E-0138 пре-регистрация" -1)
restore() { [ -f "$HELD" ] && mv "$HELD" "$EXC"; }
trap restore EXIT
if [ -f "$EXC" ]; then
  mv "$EXC" "$HELD"
  if [ -n "${PIN:-}" ]; then
    # проверка, что на пине файла действительно нет: иначе посадка — не воспроизведение пина
    emit PRE_FIX_PIN_FILE_ABSENT "$([ -z "$(git ls-tree "$PIN" -- "$EXC")" ] && echo 1 || echo 0)"
    emit PRE_FIX_PIN_FOUND 1
  else
    emit PRE_FIX_PIN_FOUND 0; emit PRE_FIX_PIN_FILE_ABSENT none
  fi
  python lab/check-contours.py >${SCR}prefix.txt 2>&1; emit PRE_FIX_EXIT $?
  for k in CLOSED_TOTAL BLOCK_LABELS COVERED MISSING_TOTAL EXPLAINED UNEXPLAINED ERA_TOTAL \
           MODERN_TOTAL EXCEPTIONS_ABSENT REASON_EMPTY CLASS_BAD GHOST DUP VIOLATIONS; do
    emit "PRE_FIX_$k" "$(grab ${SCR}prefix.txt "$k")"
  done
  restore
else
  emit PRE_FIX_PLANTED 0
  for k in EXIT CLOSED_TOTAL BLOCK_LABELS COVERED MISSING_TOTAL EXPLAINED UNEXPLAINED ERA_TOTAL \
           MODERN_TOTAL EXCEPTIONS_ABSENT REASON_EMPTY CLASS_BAD GHOST DUP VIOLATIONS; do
    emit "PRE_FIX_$k" none
  done
fi

python lab/cycle-gate.py gate H-0138 >>"$buf" 2>&1 && emit GATE_H0138_OK 1 || emit GATE_H0138_OK 0
bash lab/disk-report.sh >${SCR}disk.txt 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' ${SCR}disk.txt | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# --- сам прибор --------------------------------------------------------------------------------
emit CONTOUR_GUARD_EXISTS "$([ -f lab/check-contours.py ] && echo 1 || echo 0)"
emit CONTOUR_EXCEPTIONS_EXISTS "$([ -f "$EXC" ] && echo 1 || echo 0)"
emit CONTOUR_EXCEPTIONS_ROWS "$(grep -c '^E-' "$EXC" 2>/dev/null | tr -d ' ')"
python lab/check-contours.py --selftest >${SCR}self.txt 2>&1; emit SELFTEST_EXIT $?
for k in PLANTED_TOTAL PLANTED_CAUGHT PLANTED_FALSE LEGAL_TOTAL ABSENT_UNEXPLAINED ABSENT_OK; do
  emit "$k" "$(grab ${SCR}self.txt "SELFTEST_$k")"
done

python lab/check-contours.py >${SCR}live.txt 2>&1; emit GUARD_EXIT $?
emit LIVE_FORM_FIRST "$(grab ${SCR}live.txt FORM_FIRST)"
for k in CLOSED_TOTAL BLOCK_LABELS COVERED MISSING_TOTAL EXPLAINED UNEXPLAINED ERA_TOTAL \
         MODERN_TOTAL EXCEPTIONS_ABSENT REASON_EMPTY CLASS_BAD GHOST DUP VIOLATIONS; do
  emit "LIVE_$k" "$(grab ${SCR}live.txt "$k")"
done
# Ключ различия пина и починки: без него зелёная строка прибора ничего не стоит — на пине
# `UNEXPLAINED` печатает число, на живом дереве нуль.
PV=$(grab ${SCR}prefix.txt UNEXPLAINED 2>/dev/null || true)
LV=$(grab ${SCR}live.txt UNEXPLAINED)
if [ -n "${PV:-}" ] && [ "$PV" != none ] && [ "${PV:-0}" -gt 0 ] && [ "${LV:-x}" = 0 ]; then
  emit PRE_FIX_DIFFERS 1
else
  emit PRE_FIX_DIFFERS 0
fi

# --- постановка прибора в контур и в CI ---------------------------------------------------------
# Булево, а не число строк: утверждение карточки — «прибор стоит в контуре», то есть 0 или 1.
w1=$(grep -c 'check-contours.py' lab/workspace-verify.sh | head -1 | tr -d ' ')
w2=$(grep -c 'check-contours.py' .github/workflows/verify.yml | head -1 | tr -d ' ')
emit VERIFY_WIRES_CONTOURS "$([ "${w1:-0}" -gt 0 ] && echo 1 || echo 0)"
emit CI_WIRES_CONTOURS "$([ "${w2:-0}" -gt 0 ] && echo 1 || echo 0)"

# --- стражи репозитория -------------------------------------------------------------------------
bash lab/check-secrets.sh --no-history >${SCR}sec.txt 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py >${SCR}refs.txt 2>&1; emit REFS_EXIT $?
python lab/check-claim-map.py >${SCR}cmap.txt 2>&1; emit CLAIMMAP_EXIT $?
python lab/check-claims.py >${SCR}claims.txt 2>&1; emit CLAIMS_EXIT $?
bash lab/check-text-clean.sh --all >${SCR}all.txt 2>&1; emit TEXTGUARD_ALL_EXIT $?
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' ${SCR}all.txt | tail -1 | cut -d= -f2)"
bash lab/check-text-clean.sh lab/check-contours.py "$EXC" lab/e0138-run.sh \
  lab/expectations/e0138.tsv lab/hypotheses/H-0138-contour-closure.md \
  lab/experiments/E-0138-contour-closure.md >${SCR}text.txt 2>&1; emit TEXTGUARD_CYCLE_EXIT $?
bash lab/check-spec-mirror.sh >${SCR}mirror.txt 2>&1; emit MIRROR_EXIT $?
python lab/threshold-lint.py --latest >${SCR}lint.txt 2>&1; emit LINT_EXIT $?
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' ${SCR}lint.txt | tail -1 | cut -d= -f2)"
python lab/cycle-gate.py audit >${SCR}audit.txt 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check >${SCR}review.txt 2>&1; emit REVIEW_EXIT $?
emit RUST_TOUCHED "$(git diff --name-only "${PIN:-HEAD}" -- crates/ | wc -l | tr -d ' ')"

WORST=0
for k in SELFTEST_EXIT GUARD_EXIT SECRETS_EXIT REFS_EXIT CLAIMMAP_EXIT CLAIMS_EXIT \
         TEXTGUARD_ALL_EXIT TEXTGUARD_CYCLE_EXIT MIRROR_EXIT LINT_EXIT GATE_AUDIT_EXIT REVIEW_EXIT \
         PRE_FIX_EXIT; do
  v=$(grep -o "^$k=[0-9]*" "$buf" | tail -1 | cut -d= -f2)
  [ "$k" = PRE_FIX_EXIT ] && { [ "${v:-1}" = 1 ] || WORST=1; continue; }
  [ "${v:-1}" = 0 ] || WORST=1
done
[ "$(grab "$buf" GATE_H0138_OK)" = 1 ] || WORST=1
emit WORST_RC $WORST

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0138-${TREE_KEY}.facts"
Filt() { grep -v -E '^DISK_FREE_MB=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
fi
Filt "$buf" > "$SNAP"
cat "$buf"; rm -f "$buf"
