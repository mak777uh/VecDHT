#!/usr/bin/env bash
# H-0132 / E-0132: соединённый реестр утверждений релизной готовности (`lab/claims.tsv` +
# `lab/check-claims.py`). Цикл приборный: продукта не касается (`RUST_TOUCHED=0`), чинит речь о
# замеренном. PRE_FIX исполняется посадчиком: дерево пина (пре-регистрация) возвращается на
# lab/claims.tsv, lab/check-claims.py, docs/STATUS-v1.md, README.md и README.ru.md, на нём гоняется
# тот же прибор, затем trap возвращает HEAD — иначе «дыра» была бы цитатой, а не исполнением.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }
grab() { grep -o "^$2=[0-9A-Za-z/._-]*" "$1" | tail -1 | cut -d= -f2; }

# --- восстановление дерева пина и возврат после прогона -----------------------------------------
TOUCH=(lab/claims.tsv lab/check-claims.py docs/STATUS-v1.md README.md README.ru.md)
PIN=$(git log --format=%H --grep="E-0132 пре-регистрация" -1)
restore() { [ -n "${PIN:-}" ] && git checkout HEAD -- "${TOUCH[@]}" 2>/dev/null; }
trap restore EXIT
if [ -n "${PIN:-}" ]; then
  emit PRE_FIX_PIN_FOUND 1
  git checkout "$PIN" -- "${TOUCH[@]}" 2>/dev/null
  python lab/check-claims.py >${SCR}prefix.txt 2>&1; emit PRE_FIX_EXIT $?
  emit PRE_FIX_CLAIMS "$(grab ${SCR}prefix.txt CLAIMS)"
  emit PRE_FIX_VIOLATIONS "$(grab ${SCR}prefix.txt VIOLATIONS)"
  emit PRE_FIX_GATE_RATIO "$(grab ${SCR}prefix.txt GATE_RATIO)"
  emit PRE_FIX_CEILING "$(grab ${SCR}prefix.txt CEILING)"
  emit PRE_FIX_QUALIFIER "$(grab ${SCR}prefix.txt QUALIFIER)"
  emit PRE_FIX_READY_VALUES "$(grab ${SCR}prefix.txt READY_VALUES)"
  emit PRE_FIX_COND_COVERED "$(grab ${SCR}prefix.txt CONDITIONS_COVERED)"
  restore
else
  emit PRE_FIX_PIN_FOUND 0
  for k in CLAIMS VIOLATIONS GATE_RATIO CEILING QUALIFIER READY_VALUES COND_COVERED EXIT; do
    emit "PRE_FIX_$k" none
  done
fi

python lab/cycle-gate.py gate H-0132 >>"$buf" 2>&1 && emit GATE_H0132_OK 1 || emit GATE_H0132_OK 0
bash lab/disk-report.sh >${SCR}disk.txt 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' ${SCR}disk.txt | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# --- сам прибор --------------------------------------------------------------------------------
emit CLAIM_GUARD_EXISTS "$([ -f lab/check-claims.py ] && echo 1 || echo 0)"
emit CLAIMS_REGISTRY_EXISTS "$([ -f lab/claims.tsv ] && echo 1 || echo 0)"
python lab/check-claims.py --selftest >${SCR}self.txt 2>&1; emit SELFTEST_EXIT $?
PC=$(grep -o '^PLANTED_CAUGHT=[0-9]*' ${SCR}self.txt | tail -1 | cut -d= -f2)
PT=$(grep -o '^PLANTED_TOTAL=[0-9]*' ${SCR}self.txt | tail -1 | cut -d= -f2)
emit PLANTED_CAUGHT "${PC:-none}"; emit PLANTED_TOTAL "${PT:-none}"
emit PLANTED_FALSE "$(grep -o '^PLANTED_FALSE=[0-9]*' ${SCR}self.txt | tail -1 | cut -d= -f2)"
emit LEGAL_TOTAL "$(grep -o '^LEGAL_TOTAL=[0-9]*' ${SCR}self.txt | tail -1 | cut -d= -f2)"

python lab/check-claims.py >${SCR}live.txt 2>&1; emit GUARD_EXIT $?
for k in CLAIMS VIOLATIONS DANGLING CEILING QUALIFIER TYPE_BAD LINK_BAD GATE_RATIO COND_LINK_BAD \
         READY_VALUES READY_CARRIERS; do
  emit "LIVE_$k" "$(grab ${SCR}live.txt "$k")"
done
emit LIVE_COND_TABLE "$(grab ${SCR}live.txt CONDITIONS_TABLE)"
emit LIVE_COND_COVERED "$(grab ${SCR}live.txt CONDITIONS_COVERED)"
# Ключ различия пина и фикса: без него зелёная строка прибора ничего не стоит (`OPEN-QUESTIONS`
# п. 75, пункт (б): у прибора обязан быть хотя бы один ключ, который на пине печатает другое число).
PV=$(grab ${SCR}prefix.txt VIOLATIONS 2>/dev/null || true)
LV=$(grab ${SCR}live.txt VIOLATIONS)
if [ -n "${PV:-}" ] && [ "$PV" != none ] && [ "${LV:-x}" = 0 ]; then emit PRE_FIX_DIFFERS 1
else emit PRE_FIX_DIFFERS 0; fi

# --- постановка прибора в контур и в CI ---------------------------------------------------------
# Булево, а не число строк: точное число упоминаний зависит от того, сколько шагов заведёт следующий
# цикл, а утверждение карточки — «прибор стоит в контуре», то есть 0 или 1.
w1=$(grep -c 'check-claims.py' lab/workspace-verify.sh | head -1 | tr -d ' ')
w2=$(grep -c 'check-claims.py' .github/workflows/verify.yml | head -1 | tr -d ' ')
emit VERIFY_WIRES_CLAIMS "$([ "${w1:-0}" -gt 0 ] && echo 1 || echo 0)"
emit CI_WIRES_CLAIMS "$([ "${w2:-0}" -gt 0 ] && echo 1 || echo 0)"

# --- стражи репозитория -------------------------------------------------------------------------
bash lab/check-secrets.sh --no-history >${SCR}sec.txt 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py >${SCR}refs.txt 2>&1; emit REFS_EXIT $?
python lab/check-claim-map.py >${SCR}cmap.txt 2>&1; emit CLAIMMAP_EXIT $?
bash lab/check-text-clean.sh --all >${SCR}all.txt 2>&1; emit TEXTGUARD_ALL_EXIT $?
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' ${SCR}all.txt | tail -1 | cut -d= -f2)"
bash lab/check-text-clean.sh lab/claims.tsv lab/check-claims.py lab/hypotheses/H-0132-claims-registry.md \
  lab/e0132-run.sh lab/expectations/e0132.tsv >${SCR}text.txt 2>&1; emit TEXTGUARD_CYCLE_EXIT $?
bash lab/check-spec-mirror.sh >${SCR}mirror.txt 2>&1; emit MIRROR_EXIT $?
python lab/threshold-lint.py --latest >${SCR}lint.txt 2>&1; emit LINT_EXIT $?
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' ${SCR}lint.txt | tail -1 | cut -d= -f2)"
python lab/cycle-gate.py audit >${SCR}audit.txt 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check >${SCR}review.txt 2>&1; emit REVIEW_EXIT $?
emit RUST_TOUCHED "$(git diff --name-only "${PIN:-HEAD}" -- crates/ | wc -l | tr -d ' ')"

WORST=0
for k in SELFTEST_EXIT GUARD_EXIT SECRETS_EXIT REFS_EXIT CLAIMMAP_EXIT TEXTGUARD_ALL_EXIT \
         TEXTGUARD_CYCLE_EXIT MIRROR_EXIT LINT_EXIT GATE_AUDIT_EXIT REVIEW_EXIT PRE_FIX_EXIT; do
  v=$(grep -o "^$k=[0-9]*" "$buf" | tail -1 | cut -d= -f2)
  [ "$k" = PRE_FIX_EXIT ] && { [ "${v:-1}" = 1 ] || WORST=1; continue; }
  [ "${v:-1}" = 0 ] || WORST=1
done
[ "$(grab "$buf" GATE_H0132_OK)" = 1 ] || WORST=1
emit WORST_RC $WORST

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0132-${TREE_KEY}.facts"
Filt() { grep -v -E '^DISK_FREE_MB=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
fi
Filt "$buf" > "$SNAP"
cat "$buf"; rm -f "$buf"
