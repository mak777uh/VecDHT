#!/usr/bin/env bash
# H-0139 / E-0139: реестр утверждений обязана сверять текст вверх — каждое сильное утверждение
# трёх носителей (`docs/STATUS-v1.md`, `README.md`, `README.ru.md`) обязано быть покрыто строкой
# `lab/claims.tsv` (`lab/check-claims.py`, ключ `UNREGISTERED`). Цикл приборный: продукта не
# касается (`RUST_TOUCHED=0`). PRE_FIX исполняется посадкой пина: файл реестра меняется на версию
# пре-регистрации (`git checkout "$PIN" -- lab/claims.tsv`), на этом дереве гоняется тот же прибор,
# затем `trap` возвращает живую копию; носители при этом не трогаются, поэтому число сильных
# утверждений на пине и на живом дереве обязано совпасть.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }
grab() { grep -o "^$2=[0-9A-Za-z/.,:%_-]*" "$1" | tail -1 | cut -d= -f2; }

REG=lab/claims.tsv
HELD="${SCR}claims.tsv.live"
PIN=$(git log --format=%H --grep="E-0139 пре-регистрация" -1)
restore() { [ -f "$HELD" ] && mv "$HELD" "$REG"; }
trap restore EXIT

# --- посадка: реестр пина пре-регистрации под живыми носителями ---------------------------------
if [ -n "${PIN:-}" ] && [ -f "$REG" ]; then
  cp "$REG" "$HELD"
  emit PRE_FIX_PIN_FOUND 1
  emit PRE_FIX_PIN_ROWS "$(git show "$PIN:$REG" | grep -vc '^#\|^$')"
  emit PRE_FIX_PIN_ROWS_LIVE "$(grep -vc '^#\|^$' "$REG")"
  git checkout "$PIN" -- "$REG" || true
  python lab/check-claims.py >${SCR}prefix.txt 2>&1; emit PRE_FIX_EXIT $?
  for k in CLAIMS TRIGGER_SENTENCES UNREGISTERED UP_CARRIERS VIOLATIONS DANGLING CEILING QUALIFIER \
           TYPE_BAD LINK_BAD GATE_RATIO COND_LINK_BAD CONDITIONS_TABLE CONDITIONS_COVERED \
           READY_CARRIERS READY_VALUES; do
    emit "PRE_FIX_$k" "$(grab ${SCR}prefix.txt "$k")"
  done
  restore
  emit PRE_FIX_PLANTED 1
else
  emit PRE_FIX_PIN_FOUND 0
  emit PRE_FIX_PLANTED 0
  for k in PIN_ROWS PIN_ROWS_LIVE EXIT CLAIMS TRIGGER_SENTENCES UNREGISTERED UP_CARRIERS VIOLATIONS \
           DANGLING CEILING QUALIFIER TYPE_BAD LINK_BAD GATE_RATIO COND_LINK_BAD CONDITIONS_TABLE \
           CONDITIONS_COVERED READY_CARRIERS READY_VALUES; do
    emit "PRE_FIX_$k" none
  done
fi

python lab/cycle-gate.py gate H-0139 >>"$buf" 2>&1 && emit GATE_H0139_OK 1 || emit GATE_H0139_OK 0
bash lab/disk-report.sh >${SCR}disk.txt 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' ${SCR}disk.txt | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# --- сам прибор ----------------------------------------------------------------------------------
emit CLAIMS_INSTRUMENT_EXISTS "$([ -f lab/check-claims.py ] && echo 1 || echo 0)"
emit CLAIMS_REGISTRY_ROWS "$(grep -vc '^#\|^$' "$REG")"
python lab/check-claims.py --selftest >${SCR}self.txt 2>&1; emit SELFTEST_EXIT $?
for k in PLANTED_TOTAL PLANTED_CAUGHT PLANTED_FALSE LEGAL_TOTAL UP_PLANTED UP_CAUGHT UP_FALSE; do
  emit "$k" "$(grab ${SCR}self.txt "$k")"
done

python lab/check-claims.py >${SCR}live.txt 2>&1; emit GUARD_EXIT $?
for k in CLAIMS TRIGGER_SENTENCES UNREGISTERED UP_CARRIERS VIOLATIONS DANGLING CEILING QUALIFIER \
         TYPE_BAD LINK_BAD GATE_RATIO COND_LINK_BAD CONDITIONS_TABLE CONDITIONS_COVERED \
         READY_CARRIERS READY_VALUES; do
  emit "LIVE_$k" "$(grab ${SCR}live.txt "$k")"
done
emit LIVE_UNREGISTERED_LIST "$(grab ${SCR}live.txt UNREGISTERED_LIST)"

# Ключ различия пина и починки: без него зелёная строка прибора ничего не стоит.
PT=$(grab ${SCR}prefix.txt TRIGGER_SENTENCES); LT=$(grab ${SCR}live.txt TRIGGER_SENTENCES)
PU=$(grab ${SCR}prefix.txt UNREGISTERED);      LU=$(grab ${SCR}live.txt UNREGISTERED)
emit PRE_FIX_TRIGGER_EQUALS_LIVE "$([ -n "${PT:-}" ] && [ "$PT" = "${LT:-x}" ] && echo 1 || echo 0)"
if [ -n "${PU:-}" ] && [ "$PU" != none ] && [ "${PU:-0}" -gt 0 ] && [ "${LU:-x}" = 0 ]; then
  emit PRE_FIX_DIFFERS 1
else
  emit PRE_FIX_DIFFERS 0
fi

# --- постановка прибора в контур и в CI ----------------------------------------------------------
w1=$(grep -c 'check-claims.py' lab/workspace-verify.sh | head -1 | tr -d ' ')
w2=$(grep -c 'check-claims.py' .github/workflows/verify.yml | head -1 | tr -d ' ')
emit VERIFY_WIRES_CLAIMS "$([ "${w1:-0}" -gt 0 ] && echo 1 || echo 0)"
emit CI_WIRES_CLAIMS "$([ "${w2:-0}" -gt 0 ] && echo 1 || echo 0)"

# --- стражи репозитория ---------------------------------------------------------------------------
bash lab/check-secrets.sh --no-history >${SCR}sec.txt 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py >${SCR}refs.txt 2>&1; emit REFS_EXIT $?
python lab/check-claim-map.py >${SCR}cmap.txt 2>&1; emit CLAIMMAP_EXIT $?
python lab/check-contours.py >${SCR}contours.txt 2>&1; emit CONTOURS_EXIT $?
bash lab/check-text-clean.sh --all >${SCR}all.txt 2>&1; emit TEXTGUARD_ALL_EXIT $?
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' ${SCR}all.txt | tail -1 | cut -d= -f2)"
bash lab/check-text-clean.sh lab/check-claims.py "$REG" lab/e0139-run.sh \
  lab/expectations/e0139.tsv lab/hypotheses/H-0139-claims-upcheck.md \
  lab/experiments/E-0139-claims-upcheck.md >${SCR}text.txt 2>&1; emit TEXTGUARD_CYCLE_EXIT $?
bash lab/check-spec-mirror.sh >${SCR}mirror.txt 2>&1; emit MIRROR_EXIT $?
python lab/threshold-lint.py --latest >${SCR}lint.txt 2>&1; emit LINT_EXIT $?
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' ${SCR}lint.txt | tail -1 | cut -d= -f2)"
python lab/cycle-gate.py audit >${SCR}audit.txt 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check >${SCR}review.txt 2>&1; emit REVIEW_EXIT $?
emit RUST_TOUCHED "$(git diff --name-only "${PIN:-HEAD}" -- crates/ | wc -l | tr -d ' ')"

WORST=0
for k in SELFTEST_EXIT GUARD_EXIT SECRETS_EXIT REFS_EXIT CLAIMMAP_EXIT CONTOURS_EXIT \
         TEXTGUARD_ALL_EXIT TEXTGUARD_CYCLE_EXIT MIRROR_EXIT LINT_EXIT GATE_AUDIT_EXIT REVIEW_EXIT; do
  v=$(grep -o "^$k=[0-9]*" "$buf" | tail -1 | cut -d= -f2)
  [ "${v:-1}" = 0 ] || WORST=1
done
[ "$(grab "$buf" PRE_FIX_EXIT)" = 1 ] || WORST=1
[ "$(grab "$buf" GATE_H0139_OK)" = 1 ] || WORST=1
emit WORST_RC $WORST

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0139-${TREE_KEY}.facts"
Filt() { grep -v -E '^DISK_FREE_MB=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
fi
Filt "$buf" > "$SNAP"
cat "$buf"; rm -f "$buf"
