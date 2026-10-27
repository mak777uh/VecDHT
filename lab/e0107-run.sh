#!/usr/bin/env bash
# H-0107 / E-0107:Lean-модель ограниченного множества и её соответствие настоящему коду.
# Три halves одного замера: (1) модель обязана компилироваться и быть замороженной, (2) числа
# модели обязан продублировать настоящий код двумя исполняемыми тестами, (3) страж обязан ловить
# посаженное ослабление формулировки именно на этой модели.
# Цикл зелёной зоны: правит `lab/lean`, очередь и два тестовых файла; `src` и спеку не трогает.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }
# PIN — дерево пре-регистрации (модель и заморозка есть, Rust-приборов нет). Для прогонов на
# дереве починки передаётся явно: E0107_PIN=<хеш пре-регистрации>.
PIN="${E0107_PIN:-$(git rev-parse --short HEAD 2>/dev/null || echo nohead)}"
val()  { local v; v=$(grep -oE "(^|[[:space:]])$1=[0-9]+" "$2" | tail -1 | grep -oE "[0-9]+$"); printf '%s' "${v:-none}"; }
vals() { local v; v=$(grep -oE "$1=-?[0-9]+" "$2" | tail -1 | grep -oE "=-?[0-9]+$" | tr -d '='); printf '%s' "${v:-none}"; }
# Пустое значение — это молчание прибора, а не измеренное отсутствие: сворачивается в `none`
# (правило «пустое множество печатать none»), иначе отсутствие ключа неотличимо от его нуля.
ornone() { local v; v=$(cat); [ -n "$v" ] || v=none; printf '%s' "$v"; }
# Число с той же строки, где и другое число (`LEANGUARD_SELFTEST total=N passed=M`): `val` требует
# ключ после начала строки или пробела и не может найти `LEANGUARD_SELFTEST passed=`, поэтому
# прошлая строка объявляла измеренное число отсутствующим.
fromline() { local g; g=$(grep -E "$2" "$3" | tail -1); printf '%s' "$g" | sed -nE "s/.*$1=([0-9-]+).*/\1/p" | ornone; }

python lab/cycle-gate.py gate H-0107 >>"$buf" 2>&1 && emit GATE_H0107_OK 1 || emit GATE_H0107_OK 0
bash lab/disk-report.sh >${SCR}disk.txt 2>&1
D=$(val DISK_FREE_MB ${SCR}disk.txt)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# --- (1) модель на диске, заморожена, компилируется --------------------------------------------
MODEL=lab/lean/VecDHT/Bounded.lean
FRZ=lab/lean/frozen/Bounded.lean.statements.tsv
emit LEAN_MODEL_EXISTS "$([ -f $MODEL ] && echo 1 || echo 0)"
emit LEAN_FROZEN_EXISTS "$([ -f $FRZ ] && echo 1 || echo 0)"
if [ -f "$MODEL" ]; then
  bash lab/lean-check.sh >${SCR}lean.txt 2>&1; emit LEAN_CHECK_EXIT $?
  emit LEAN_ALL_OK "$(val LEAN_ALL_OK ${SCR}lean.txt)"
  emit LEAN_SORRY_TOTAL "$(val SORRY_TOTAL ${SCR}lean.txt)"
  emit LEAN_CUSTOM_AXIOMS_TOT "$(val CUSTOM_AXIOMS ${SCR}lean.txt | tail -1)"
  emit BOUND_ERRORS "$(fromline 'ERRORS' 'LEAN_FILE=Bounded.lean' ${SCR}lean.txt)"
  emit BOUND_DECLS "$(fromline 'DECLS' 'LEAN_FILE=Bounded.lean' ${SCR}lean.txt)"
  emit BOUND_DEFS "$(fromline 'DEFS' 'LEAN_FILE=Bounded.lean' ${SCR}lean.txt)"
  emit LEAN_CHECK_DIGEST_BAD "$(val DIGEST_BAD ${SCR}lean.txt)"
  emit LEAN_CHECK_FROZEN_ROWS "$(val FROZEN_ROWS ${SCR}lean.txt)"
  python lab/lean-check.py selftest >${SCR}guard.txt 2>&1; emit GUARD_SELFTEST_EXIT $?
  emit GUARD_SELFTEST_TOTAL "$(fromline 'total' 'LEANGUARD_SELFTEST' ${SCR}guard.txt)"
  emit GUARD_SELFTEST_PASSED "$(fromline 'passed' 'LEANGUARD_SELFTEST' ${SCR}guard.txt)"
  # Числа модели: тот же вывод `#eval`, что зафиксирован в Rust-константах.
  (cd lab/lean && lake env lean VecDHT/Bounded.lean) >${SCR}metrics.txt 2>&1; emit METRICS_EXIT $?
  # Имена фактов печатаются литералом, а не циклом по `$k`: порог без прибора — это ключ,
  # который никто не вызывается напечатать (`lab/threshold-lint.py`). Модель печатает их в
  # одну строку `#eval`, здесь они становятся отдельными фактами замера.
  emit SWEEP_PAIRS "$(vals SWEEP_PAIRS ${SCR}metrics.txt)"
  emit TRACES "$(vals TRACES ${SCR}metrics.txt)"
  emit LEGAL_STARTS "$(vals LEGAL_STARTS ${SCR}metrics.txt)"
  emit ASKS "$(vals ASKS ${SCR}metrics.txt)"
  emit SPACE "$(vals SPACE ${SCR}metrics.txt)"
  emit REFUSE_BITS_SUM "$(vals REFUSE_BITS_SUM ${SCR}metrics.txt)"
  emit REFUSE_CARD_SUM "$(vals REFUSE_CARD_SUM ${SCR}metrics.txt)"
  emit REFUSE_AT_CAP_PAIRS "$(vals REFUSE_AT_CAP_PAIRS ${SCR}metrics.txt)"
  emit REFUSE_REFUSAL_SUM "$(vals REFUSE_REFUSAL_SUM ${SCR}metrics.txt)"
  emit REFUSE_AMNESTY_PAIRS "$(vals REFUSE_AMNESTY_PAIRS ${SCR}metrics.txt)"
  emit EVICT_BITS_SUM "$(vals EVICT_BITS_SUM ${SCR}metrics.txt)"
  emit EVICT_CARD_SUM "$(vals EVICT_CARD_SUM ${SCR}metrics.txt)"
  emit EVICT_AT_CAP_PAIRS "$(vals EVICT_AT_CAP_PAIRS ${SCR}metrics.txt)"
  emit EVICT_REFUSAL_SUM "$(vals EVICT_REFUSAL_SUM ${SCR}metrics.txt)"
  emit EVICT_AMNESTY_PAIRS "$(vals EVICT_AMNESTY_PAIRS ${SCR}metrics.txt)"
  emit GROW_BITS_SUM "$(vals GROW_BITS_SUM ${SCR}metrics.txt)"
  emit GROW_AT_CAP_PAIRS "$(vals GROW_AT_CAP_PAIRS ${SCR}metrics.txt)"
  emit FILLS_TO_CAP_REFUSE "$(vals FILLS_TO_CAP_REFUSE ${SCR}metrics.txt)"
  emit FROZEN_NEVER_FILLS "$(vals FROZEN_NEVER_FILLS ${SCR}metrics.txt)"
  emit GROW_BOUNDED "$(vals GROW_BOUNDED ${SCR}metrics.txt)"
  emit EVICT_MOVES_UNDECLARED "$(vals EVICT_MOVES_UNDECLARED ${SCR}metrics.txt)"
  emit REFUSE_LAST_EVENT_BREAKS "$(vals REFUSE_LAST_EVENT_BREAKS ${SCR}metrics.txt)"
  emit POLICIES_BREAKING_LAST_EVENT "$(vals POLICIES_BREAKING_LAST_EVENT ${SCR}metrics.txt)"
  emit EXACTLY_ONE_SURVIVOR "$(vals EXACTLY_ONE_SURVIVOR ${SCR}metrics.txt)"
  emit SURVIVOR_IS_REFUSE "$(vals SURVIVOR_IS_REFUSE ${SCR}metrics.txt)"
  emit REFUSE_LOSES_NOTHING "$(vals REFUSE_LOSES_NOTHING ${SCR}metrics.txt)"
  emit EVICT_LOSES_SOMETHING "$(vals EVICT_LOSES_SOMETHING ${SCR}metrics.txt)"
else
  for k in LEAN_CHECK_EXIT LEAN_ALL_OK LEAN_SORRY_TOTAL LEAN_CUSTOM_AXIOMS_TOT BOUND_ERRORS BOUND_DECLS \
           BOUND_DEFS LEAN_CHECK_DIGEST_BAD LEAN_CHECK_FROZEN_ROWS GUARD_SELFTEST_EXIT \
           GUARD_SELFTEST_TOTAL GUARD_SELFTEST_PASSED METRICS_EXIT; do
    emit $k none
  done
  for k in SWEEP_PAIRS TRACES LEGAL_STARTS ASKS REFUSE_BITS_SUM REFUSE_CARD_SUM REFUSE_AT_CAP_PAIRS \
           REFUSE_REFUSAL_SUM REFUSE_AMNESTY_PAIRS EVICT_CARD_SUM EVICT_AT_CAP_PAIRS EVICT_BITS_SUM \
           EVICT_AMNESTY_PAIRS GROW_BITS_SUM GROW_AT_CAP_PAIRS FILLS_TO_CAP_REFUSE FROZEN_NEVER_FILLS \
           GROW_BOUNDED EVICT_MOVES_UNDECLARED REFUSE_LAST_EVENT_BREAKS POLICIES_BREAKING_LAST_EVENT \
           EXACTLY_ONE_SURVIVOR SURVIVOR_IS_REFUSE REFUSE_LOSES_NOTHING EVICT_LOSES_SOMETHING; do
    emit "$k" none; done
fi

# --- (2) соответствие настоящему коду: два исполняемых прибора --------------------------------
TD=crates/vecdht-node/tests/s16_lean_bounded_denylist.rs
TC=crates/vecdht-net/tests/s16_lean_bounded_cache.rs
emit TEST_DENY_EXISTS "$([ -f $TD ] && echo 1 || echo 0)"
emit TEST_CACHE_EXISTS "$([ -f $TC ] && echo 1 || echo 0)"
if [ -f "$TD" ]; then
  cargo test -q -p vecdht-node --test s16_lean_bounded_denylist -- --nocapture >${SCR}td.txt 2>&1 || true
  r=$(grep -c 'test result: ok' ${SCR}td.txt); emit DENY_TEST_OK "$([ "$r" = 1 ] && echo 1 || echo 0)"
  for k in BOUNDED_DENY_AGREE BOUNDED_DENY_REAL_BITS BOUNDED_DENY_REAL_CARDS BOUNDED_DENY_REAL_ATCAP \
           BOUNDED_DENY_REAL_REFUSALS BOUNDED_DENY_REAL_AMNESTY BOUNDED_DENY_BOUND_VIOLATIONS \
           BOUNDED_DENY_REAL_PAIRS BOUNDED_DENY_TRACES; do
    emit "$k" "$(val $k ${SCR}td.txt)"
  done
  # Константы теста обязаны равняться числам модели: иначе «соответствие» меряется устаревшим снимком.
  fresh=1
  for pair in "SWEEP_PAIRS:BOUNDED_DENY_MODEL_PAIRS" "REFUSE_BITS_SUM:BOUNDED_DENY_MODEL_BITS" \
              "REFUSE_CARD_SUM:BOUNDED_DENY_MODEL_CARDS" "REFUSE_AT_CAP_PAIRS:BOUNDED_DENY_MODEL_ATCAP" \
              "REFUSE_REFUSAL_SUM:BOUNDED_DENY_MODEL_REFUSALS" \
              "REFUSE_AMNESTY_PAIRS:BOUNDED_DENY_MODEL_AMNESTY"; do
    m=${pair%%:*}; t=${pair##*:}
    a=$(vals "$m" ${SCR}metrics.txt); b=$(val "$t" ${SCR}td.txt)
    [ -n "$a" ] && [ "$a" != none ] && [ "$a" = "$b" ] || fresh=0
  done
  emit BOUNDED_DENY_CONSTS_FRESH "$fresh"
else
  for k in DENY_TEST_OK BOUNDED_DENY_AGREE BOUNDED_DENY_REAL_BITS BOUNDED_DENY_REAL_CARDS \
           BOUNDED_DENY_REAL_ATCAP BOUNDED_DENY_REAL_REFUSALS BOUNDED_DENY_REAL_AMNESTY \
           BOUNDED_DENY_BOUND_VIOLATIONS BOUNDED_DENY_REAL_PAIRS BOUNDED_DENY_TRACES; do emit $k none; done
  emit BOUNDED_DENY_CONSTS_FRESH 0
fi
if [ -f "$TC" ]; then
  cargo test -q -p vecdht-net --test s16_lean_bounded_cache -- --nocapture >${SCR}tc.txt 2>&1 || true
  r=$(grep -c 'test result: ok' ${SCR}tc.txt); emit CACHE_TEST_OK "$([ "$r" = 1 ] && echo 1 || echo 0)"
  for k in BOUNDED_CACHE_SIZE_AGREE BOUNDED_CACHE_REAL_CARDS BOUNDED_CACHE_REAL_ATCAP \
           BOUNDED_CACHE_REAL_BITS BOUNDED_CACHE_REAL_AMNESTY BOUNDED_CACHE_OVER_CAP \
           BOUNDED_CACHE_DISTRUST_WINDOW_PAIRS BOUNDED_CACHE_DISTRUST_CARDS \
           BOUNDED_CACHE_DISTRUST_SKIPPED_SUM BOUNDED_CACHE_EVICTED_SUM \
           BOUNDED_CACHE_REAL_PAIRS; do
    emit "$k" "$(val $k ${SCR}tc.txt)"
  done
  emit BOUNDED_CACHE_VICTIM_DELTA "$(vals BOUNDED_CACHE_VICTIM_DELTA ${SCR}tc.txt)"
  emit BOUNDED_CACHE_AMNESTY_DELTA "$(vals BOUNDED_CACHE_AMNESTY_DELTA ${SCR}tc.txt)"
  cf=1
  for pair in "EVICT_CARD_SUM:BOUNDED_CACHE_MODEL_CARDS" "EVICT_AT_CAP_PAIRS:BOUNDED_CACHE_MODEL_ATCAP" \
              "EVICT_BITS_SUM:BOUNDED_CACHE_MODEL_BITS" "EVICT_AMNESTY_PAIRS:BOUNDED_CACHE_MODEL_AMNESTY"; do
    m=${pair%%:*}; t=${pair##*:}
    a=$(vals "$m" ${SCR}metrics.txt); b=$(val "$t" ${SCR}tc.txt)
    [ -n "$a" ] && [ "$a" != none ] && [ "$a" = "$b" ] || cf=0
  done
  emit BOUNDED_CACHE_CONSTS_FRESH "$cf"
  # Совпадение двух независимых приборов: число вытеснений кэша равно числу отказов списка запретов —
  # это одно и то же событие («заявка при полном множестве»), посчитанное двумя настоящими кодами.
  dref=$(val BOUNDED_DENY_REAL_REFUSALS ${SCR}td.txt); dcev=$(val BOUNDED_CACHE_EVICTED_SUM ${SCR}tc.txt)
  [ -n "$dref" ] && [ "$dref" = "$dcev" ] && emit DENY_REFUSAL_EQ_CACHE_EVICTED 1 || emit DENY_REFUSAL_EQ_CACHE_EVICTED 0
else
  for k in CACHE_TEST_OK BOUNDED_CACHE_SIZE_AGREE BOUNDED_CACHE_REAL_CARDS BOUNDED_CACHE_REAL_ATCAP \
           BOUNDED_CACHE_REAL_BITS BOUNDED_CACHE_REAL_AMNESTY BOUNDED_CACHE_OVER_CAP \
           BOUNDED_CACHE_DISTRUST_WINDOW_PAIRS BOUNDED_CACHE_DISTRUST_CARDS \
           BOUNDED_CACHE_DISTRUST_SKIPPED_SUM BOUNDED_CACHE_EVICTED_SUM \
           BOUNDED_CACHE_REAL_PAIRS BOUNDED_CACHE_VICTIM_DELTA BOUNDED_CACHE_AMNESTY_DELTA; do emit $k none; done
  emit BOUNDED_CACHE_CONSTS_FRESH 0; emit DENY_REFUSAL_EQ_CACHE_EVICTED none
fi

# --- (3) страж обязан ловить посаженное ослабление на этой модели ------------------------------
if [ -f "$MODEL" ] && [ -f "$FRZ" ]; then
  python lab/plant-lean-weakening.py >${SCR}plant.txt 2>&1; emit PLANT_EXIT $?
  emit PLANT_CONTROL_OK "$(val PLANT_CONTROL_OK ${SCR}plant.txt)"
  emit PLANT_APPLIED "$(val PLANT_APPLIED ${SCR}plant.txt)"
  emit PLANT_CAUGHT "$(val PLANT_CAUGHT ${SCR}plant.txt)"
  emit PLANT_REASON_DIGEST_BAD "$(val PLANT_REASON_DIGEST_BAD ${SCR}plant.txt)"
  emit PLANT_REASON_NAMES_THE_DEF "$(val PLANT_REASON_NAMES_THE_DEF ${SCR}plant.txt)"
else
  for k in PLANT_EXIT PLANT_CONTROL_OK PLANT_APPLIED PLANT_CAUGHT PLANT_REASON_DIGEST_BAD \
           PLANT_REASON_NAMES_THE_DEF; do emit $k none; done
fi

# --- границы правки и контур -------------------------------------------------------------------
emit SRC_TOUCHED "$(git diff --name-only "$PIN" -- 'crates/*/src' 2>/dev/null | grep -c . )"
emit SPEC_TOUCHED "$(git diff --name-only "$PIN" -- docs/VecDHT-SPEC-v8.md docs/VecDHT-SPEC-v9.md 2>/dev/null | grep -c . )"
emit TESTS_ADDED "$(git diff --name-only "$PIN" -- 'crates/*/tests' 2>/dev/null | grep -c . )"

# Источники — только `.rs/.py/.sh`: `lab/lean/VecDHT/Bounded.lean` линт молча пропускает по
# расширению, поэтому имена фактов модели печатает сам helper, а не ссылается на модель.
python lab/threshold-lint.py lab/expectations/e0107.tsv --helper lab/e0107-run.sh \
  lab/plant-lean-weakening.py lab/lean-check.py \
  crates/vecdht-node/tests/s16_lean_bounded_denylist.rs \
  crates/vecdht-net/tests/s16_lean_bounded_cache.rs >${SCR}lint.txt 2>&1; emit LINT_EXIT $?
emit LINT_ORPHANS "$(val СИРОТ ${SCR}lint.txt)"
bash lab/check-secrets.sh --no-history >${SCR}sec.txt 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py >${SCR}refs.txt 2>&1; emit REFS_EXIT $?
bash lab/check-text-clean.sh >${SCR}text.txt 2>&1; emit TEXTGUARD_EXIT $?
bash lab/check-spec-mirror.sh >${SCR}mirror.txt 2>&1; emit MIRROR_EXIT $?
python lab/cycle-gate.py audit >${SCR}audit.txt 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check >${SCR}review.txt 2>&1; emit REVIEW_EXIT $?

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0107-${TREE_KEY}.facts"
Filt() { grep -v -E '^DISK_FREE_MB=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
fi
Filt "$buf" > "$SNAP"
cat "$buf"; rm -f "$buf"
