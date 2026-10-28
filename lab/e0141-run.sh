#!/usr/bin/env bash
# H-0141 / E-0141: страж моделей обязан замораживать печатаемые формы. `lab/lean-check.py` сводит
# дайджест по подписям `theorem`/`lemma` (`E-0093`) и телам `def`/`abbrev` (`E-0107`), а строки
# `#eval` — те, что печатают числа модели (`space.length`, `cap`, `traces.length`) — и объявления
# `structure`/`inductive` остаются вне заморозки: их правка не даёт ни дайджеста, ни отказа
# (остаток (а) `OPEN-QUESTIONS` п. 75). Цикл приборный: продукта не касается (`RUST_TOUCHED=0`),
# модели тоже не правятся — правится только прибор и его замороженные снимки.
#
# PRE_FIX исполняется посадкой на ВРЕМЕННОМ дереве: модели живые, а прибор и замороженные дайджесты
# — с пина пре-регистрации (`git show "$PIN:…"` с перенаправлением во временный каталог). Живой
# индекс и рабочее дерево не трогаются ни на одном шаге (правило круга `E-0139`, ДИАГНОЗ-3). Классов
# дыры три, поэтому посадок три: `#eval` (ослабление печатаемого числа), `structure` (перестановка
# полей), `inductive` (перестановка конструкторов). Каждая посадка обязана компилироваться — иначе
# пин краснел бы по чужой причине (COMPILE), и «зелёный пин» перестал бы быть доказательством дыры.
#
# Ключи печатаются развёрнуто, без склейки префикса с переменной (`PIN_${K}_EXIT`): линт порогов
# распознаёт только литеральные имена ключей, а склейка — известная слепая зона, названная в
# `OPEN-QUESTIONS` п. 78/79 и не разбираемая этим кругом.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }
# Ключ, которого прибор не напечатал, обязан стать `none`, а не пустой строкой (ДИАГНОЗ круга
# `E-0139`: пустое значение сверка читает как «не найдено», и расхождение тонет в форме печати).
grab() { v=$(grep -o "^$2=[0-9A-Za-z/.,:%_-]*" "$1" | tail -1 | cut -d= -f2); [ -n "$v" ] && echo "$v" || echo none; }
# Выход стража читать тем же `grab` нельзя: `check` печатает итог одной строкой
# (`LEAN_TOTAL=… FROZEN_ROWS=… EXTRAS_TOTAL=…`), а якорь `^` находит только первый ключ, и
# остальные молча становятся `none` — расхождение, которого сверка не видит, потому что читает
# напечатанный вектор. Поэтому чужой stdout сначала раскладывается по строкам, и только потом
# ищется ключ с начала строки (тот же довод, что у молчания экстракторов в ДИАГНОЗ-1 `E-0107`).
grabi() { v=$(tr ' \t' '\n\n' < "$1" | grep -o "^$2=[0-9A-Za-z/.,:%_-]*" | tail -1 | cut -d= -f2); [ -n "$v" ] && echo "$v" || echo none; }
# Строки дайджеста — сумма по всем `.statements.tsv`; пустой набор даёт ноль, а не панику.
rows() { n=$(find "$1" -name '*.statements.tsv' -print0 2>/dev/null | xargs -0 -r grep -h '^[^#]' 2>/dev/null | grep -c ''); echo "${n:-0}"; }
# Сколько деклараций данного класса в моделях — считается по дереву, а не берётся из веры в прибор.
cls() { c=$(grep -hcE "^$1" lab/lean/VecDHT/*.lean 2>/dev/null | awk '{s+=$1} END {print s+0}'); echo "${c:-0}"; }

PIN=$(git log --format=%H --grep="H-0141 пре-регистрация" -1)
emit PIN_FOUND "$([ -n "${PIN:-}" ] && echo 1 || echo 0)"

# --- три посадки: правка «до» обязана встречаться в модели ровно один раз ------------------------
EVAL_FROM='#eval (space.length, cap, traces.length, asks.length, legalStarts.length)'
EVAL_TO='#eval (space.length, cap, (traces.take 3).length, asks.length, legalStarts.length)'
STRUCT_FROM='structure Point where
  first : Nat
  factor : Nat'
STRUCT_TO='structure Point where
  factor : Nat
  first : Nat'
IND_FROM='inductive Mem
  | none
  | some (l : List Key)'
IND_TO='inductive Mem
  | some (l : List Key)
  | none'

# --- классы форм, посчитанные по дереву (не прибором) ---------------------------------------------
emit THEOREM_TOTAL "$(cls 'theorem\b')"
emit LEMMA_TOTAL "$(cls 'lemma\b')"
emit DEF_TOTAL "$(cls '(def|abbrev)\b')"
emit EVAL_TOTAL "$(cls '#eval\b')"
emit STRUCT_TOTAL "$(cls 'structure\b')"
emit INDUCTIVE_TOTAL "$(cls 'inductive\b')"
emit FROZEN_ROWS "$(rows lab/lean/frozen)"
if [ -n "${PIN:-}" ]; then
  emit PIN_FROZEN_ROWS "$(for f in Admission Auth Bounded CertLadder Denylist Shard; do
    git show "$PIN:lab/lean/frozen/$f.lean.statements.tsv" 2>/dev/null; done | grep -c '^[^#]')"
  # Модели починка не трогает: без этого ключа «пин зелёный, живой красный» мог бы означать, что на
  # пине просто другие модели (тот же довод, что в `E-0139` дал `PRE_FIX_TRIGGER_EQUALS_LIVE`).
  emit PIN_MODELS_DIFF "$(git diff --name-only "$PIN" -- lab/lean/VecDHT/ | grep -c '')"
  emit MODELS_TOUCHED "$(git diff --name-only "$PIN" -- lab/lean/VecDHT/ | wc -l | tr -d ' ')"
else
  emit PIN_FROZEN_ROWS none; emit PIN_MODELS_DIFF none; emit MODELS_TOUCHED none
fi

# --- сборка двух деревьев: пин-прибор + живые модели, и живой прибор + живые модели --------------
mk_tree() { # $1=root $2=pin|live
  mkdir -p "$1/lab/lean/VecDHT" "$1/lab/lean/frozen"
  cp lab/lean/VecDHT/*.lean "$1/lab/lean/VecDHT/"
  if [ "$2" = pin ]; then
    git show "$PIN:lab/lean-check.py" > "${SCR}lean-check-pin.py" 2>/dev/null
    for f in Admission Auth Bounded CertLadder Denylist Shard; do
      git show "$PIN:lab/lean/frozen/$f.lean.statements.tsv" > "$1/lab/lean/frozen/$f.lean.statements.tsv" 2>/dev/null
    done
  else
    cp lab/lean/frozen/*.tsv "$1/lab/lean/frozen/"
  fi
}
plant() { # $1=root $2=файл $3=from $4=to — выход 3, если «до» встречается не один раз
  python - "$1/lab/lean/VecDHT/$2" "$3" "$4" <<'PY'
import sys
p, frm, to = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(p, encoding="utf-8").read()
if t.count(frm) != 1:
    sys.exit(3)
open(p, "w", encoding="utf-8").write(t.replace(frm, to))
PY
}
run_check() { # $1=прибор $2=root $3=файл вывода; печатает код возврата
  python "$1" check --quiet --root "$2" >"$3" 2>&1; echo $?
}
PINROOT="${SCR}pin-tree"; LIVROOT="${SCR}live-tree"
if [ -n "${PIN:-}" ]; then mk_tree "$PINROOT" pin; fi
mk_tree "$LIVROOT" live
emit PRE_FIX_INSTRUMENT "$([ -s "${SCR}lean-check-pin.py" ] && echo 1 || echo 0)"

# --- посадка `#eval`: ослабление печатаемого числа -------------------------------------------------
if [ -n "${PIN:-}" ]; then
  cp lab/lean/VecDHT/*.lean "$PINROOT/lab/lean/VecDHT/"
  plant "$PINROOT" Bounded.lean "$EVAL_FROM" "$EVAL_TO"; r=$?
  emit PIN_EVAL_PLANTED "$([ "$r" = 0 ] && echo 1 || echo 0)"
  emit PIN_EVAL_EXIT "$(run_check "${SCR}lean-check-pin.py" "$PINROOT" "${SCR}pin-eval.txt")"
  emit PIN_EVAL_ALL_OK "$(grabi ${SCR}pin-eval.txt LEAN_ALL_OK)"
  emit PIN_EVAL_REASONS "$(grep -c 'ПРОТИВ' "${SCR}pin-eval.txt")"
else
  emit PIN_EVAL_PLANTED none; emit PIN_EVAL_EXIT none; emit PIN_EVAL_ALL_OK none; emit PIN_EVAL_REASONS none
fi
cp lab/lean/VecDHT/*.lean "$LIVROOT/lab/lean/VecDHT/"
plant "$LIVROOT" Bounded.lean "$EVAL_FROM" "$EVAL_TO"; r=$?
emit LIVE_EVAL_PLANTED "$([ "$r" = 0 ] && echo 1 || echo 0)"
emit LIVE_EVAL_EXIT "$(run_check lab/lean-check.py "$LIVROOT" "${SCR}live-eval.txt")"
emit LIVE_EVAL_CAUGHT "$(grep -qF 'изменена после заморозки' "${SCR}live-eval.txt" && echo 1 || echo 0)"
# Причина обязана назвать сам класс: «красный» без имени формы не доказывает, что охраняется она, а
# не соседняя декларация (тот же довод, что у дефекта `__weakdef__` в самопроверке стража).
emit LIVE_EVAL_KEY "$(grep -qF '#eval' "${SCR}live-eval.txt" && echo 1 || echo 0)"
emit LIVE_EVAL_COMPILE "$(grep -qF 'COMPILE' "${SCR}live-eval.txt" && echo 1 || echo 0)"

# --- посадка `structure`: перестановка полей записи ----------------------------------------------
if [ -n "${PIN:-}" ]; then
  cp lab/lean/VecDHT/*.lean "$PINROOT/lab/lean/VecDHT/"
  plant "$PINROOT" Shard.lean "$STRUCT_FROM" "$STRUCT_TO"; r=$?
  emit PIN_STRUCT_PLANTED "$([ "$r" = 0 ] && echo 1 || echo 0)"
  emit PIN_STRUCT_EXIT "$(run_check "${SCR}lean-check-pin.py" "$PINROOT" "${SCR}pin-struct.txt")"
  emit PIN_STRUCT_ALL_OK "$(grabi ${SCR}pin-struct.txt LEAN_ALL_OK)"
  emit PIN_STRUCT_REASONS "$(grep -c 'ПРОТИВ' "${SCR}pin-struct.txt")"
else
  emit PIN_STRUCT_PLANTED none; emit PIN_STRUCT_EXIT none; emit PIN_STRUCT_ALL_OK none
  emit PIN_STRUCT_REASONS none
fi
cp lab/lean/VecDHT/*.lean "$LIVROOT/lab/lean/VecDHT/"
plant "$LIVROOT" Shard.lean "$STRUCT_FROM" "$STRUCT_TO"; r=$?
emit LIVE_STRUCT_PLANTED "$([ "$r" = 0 ] && echo 1 || echo 0)"
emit LIVE_STRUCT_EXIT "$(run_check lab/lean-check.py "$LIVROOT" "${SCR}live-struct.txt")"
emit LIVE_STRUCT_CAUGHT "$(grep -qF 'изменена после заморозки' "${SCR}live-struct.txt" && echo 1 || echo 0)"
emit LIVE_STRUCT_KEY "$(grep -qF 'structure Point' "${SCR}live-struct.txt" && echo 1 || echo 0)"
emit LIVE_STRUCT_COMPILE "$(grep -qF 'COMPILE' "${SCR}live-struct.txt" && echo 1 || echo 0)"

# --- посадка `inductive`: перестановка конструкторов ----------------------------------------------
if [ -n "${PIN:-}" ]; then
  cp lab/lean/VecDHT/*.lean "$PINROOT/lab/lean/VecDHT/"
  plant "$PINROOT" Shard.lean "$IND_FROM" "$IND_TO"; r=$?
  emit PIN_INDUCTIVE_PLANTED "$([ "$r" = 0 ] && echo 1 || echo 0)"
  emit PIN_INDUCTIVE_EXIT "$(run_check "${SCR}lean-check-pin.py" "$PINROOT" "${SCR}pin-ind.txt")"
  emit PIN_INDUCTIVE_ALL_OK "$(grabi ${SCR}pin-ind.txt LEAN_ALL_OK)"
  emit PIN_INDUCTIVE_REASONS "$(grep -c 'ПРОТИВ' "${SCR}pin-ind.txt")"
else
  emit PIN_INDUCTIVE_PLANTED none; emit PIN_INDUCTIVE_EXIT none; emit PIN_INDUCTIVE_ALL_OK none
  emit PIN_INDUCTIVE_REASONS none
fi
cp lab/lean/VecDHT/*.lean "$LIVROOT/lab/lean/VecDHT/"
plant "$LIVROOT" Shard.lean "$IND_FROM" "$IND_TO"; r=$?
emit LIVE_INDUCTIVE_PLANTED "$([ "$r" = 0 ] && echo 1 || echo 0)"
emit LIVE_INDUCTIVE_EXIT "$(run_check lab/lean-check.py "$LIVROOT" "${SCR}live-ind.txt")"
emit LIVE_INDUCTIVE_CAUGHT "$(grep -qF 'изменена после заморозки' "${SCR}live-ind.txt" && echo 1 || echo 0)"
emit LIVE_INDUCTIVE_KEY "$(grep -qF 'inductive Mem' "${SCR}live-ind.txt" && echo 1 || echo 0)"
emit LIVE_INDUCTIVE_COMPILE "$(grep -qF 'COMPILE' "${SCR}live-ind.txt" && echo 1 || echo 0)"

# Дыра названа числом: пин проходит все три посаженных дерева зелёным и без единой причины отказа.
emit PRE_FIX_HOLE "$([ "$(grab "$buf" PIN_EVAL_EXIT)" = 0 ] && [ "$(grab "$buf" PIN_STRUCT_EXIT)" = 0 ] \
  && [ "$(grab "$buf" PIN_INDUCTIVE_EXIT)" = 0 ] && echo 1 || echo 0)"
# …а живой прибор отбивает все три по своей причине — без этого ключа зелёная строка починки ничего
# не стоит (`OPEN-QUESTIONS` п. 75, пункт (б)).
emit PRE_FIX_DIFFERS "$([ "$(grab "$buf" PRE_FIX_HOLE)" = 1 ] && \
  [ "$(grab "$buf" LIVE_EVAL_CAUGHT)" = 1 ] && [ "$(grab "$buf" LIVE_STRUCT_CAUGHT)" = 1 ] && \
  [ "$(grab "$buf" LIVE_INDUCTIVE_CAUGHT)" = 1 ] && echo 1 || echo 0)"

# --- годное живое дерево обязано оставаться зелёным ----------------------------------------------
python lab/lean-check.py check --quiet >${SCR}base.txt 2>&1; emit BASE_CHECK_EXIT $?
emit BASE_ALL_OK "$(grabi ${SCR}base.txt LEAN_ALL_OK)"
emit BASE_FROZEN_ROWS "$(grabi ${SCR}base.txt FROZEN_ROWS)"
emit BASE_DECLS_TOTAL "$(grabi ${SCR}base.txt DECLS_TOTAL)"
emit BASE_EXTRAS_TOTAL "$(grabi ${SCR}base.txt EXTRAS_TOTAL)"
emit BASE_BROKEN "$(grabi ${SCR}base.txt BROKEN)"
emit BASE_DIGEST_BAD "$(grabi ${SCR}base.txt DIGEST_BAD)"
# Счётчик-страж: насчитанное парсером прибора обязано совпасть с насчитанным `grep`'ом по дереву.
# Расхождение означает, что форма не разобрана, — а неразобранная форма снова вне заморозки.
emit EXTRA_PARSER_OK "$([ "$(grab "$buf" BASE_EXTRAS_TOTAL)" = \
  "$(($(grab "$buf" EVAL_TOTAL) + $(grab "$buf" STRUCT_TOTAL) + $(grab "$buf" INDUCTIVE_TOTAL)))" ] \
  && echo 1 || echo 0)"
# Замороженных стрек должно быть ровно столько, сколько насчитывает прибор: дайджест и сверка
# работают по одному множеству (довод `E-0132`: расхождение freeze/check делало гейт красным на
# годном дереве).
emit FREEZE_MATCHES_CHECK "$([ "$(grab "$buf" BASE_FROZEN_ROWS)" = \
  "$(rows lab/lean/frozen)" ] && echo 1 || echo 0)"

# --- самопроверка стража -------------------------------------------------------------------------
python lab/lean-check.py selftest >${SCR}st.txt 2>&1; emit SELFTEST_EXIT $?
emit LS_TOTAL "$(grep -o 'LEANGUARD_SELFTEST total=[0-9]*' ${SCR}st.txt | tail -1 | cut -d= -f2)"
emit LS_PASSED "$(grep -o 'отбито=[0-9]*' ${SCR}st.txt | tail -1 | cut -d= -f2)"
emit LS_FROM "$(grep -o 'из [0-9]*' ${SCR}st.txt | tail -1 | cut -d' ' -f2)"
emit LS_GOOD_TREE "$(grep -qF 'КОНТРОЛЬ годное дерево: rc=0 ПРОЙДЕН' ${SCR}st.txt && echo 1 || echo 0)"

python lab/cycle-gate.py gate H-0141 >>"$buf" 2>&1 && emit GATE_H0141_OK 1 || emit GATE_H0141_OK 0
bash lab/disk-report.sh >${SCR}disk.txt 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' ${SCR}disk.txt | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# --- постановка под контур и в CI: тот же `lab/lean-check.sh`, новых файлов не заводим ------------
emit VERIFY_WIRES_LEANCHECK "$([ "$(grep -c 'lean-check' lab/workspace-verify.sh)" -gt 0 ] && echo 1 || echo 0)"
emit CI_WIRES_LEANCHECK "$([ "$(grep -c 'lean-check' .github/workflows/formal.yml)" -gt 0 ] && echo 1 || echo 0)"

# --- соседние стражи ------------------------------------------------------------------------------
bash lab/check-secrets.sh --no-history >${SCR}sec.txt 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py >${SCR}refs.txt 2>&1; emit REFS_EXIT $?
python lab/check-claim-map.py >${SCR}cmap.txt 2>&1; emit CLAIMMAP_EXIT $?
python lab/check-claims.py >${SCR}claims.txt 2>&1; emit CLAIMS_EXIT $?
python lab/check-contours.py >${SCR}contours.txt 2>&1; emit CONTOURS_EXIT $?
bash lab/check-text-clean.sh --all >${SCR}all.txt 2>&1; emit TEXTGUARD_ALL_EXIT $?
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' ${SCR}all.txt | tail -1 | cut -d= -f2)"
bash lab/check-text-clean.sh lab/lean-check.py lab/e0141-run.sh lab/expectations/e0141.tsv \
  lab/hypotheses/H-0141-eval-freeze.md lab/experiments/E-0141-eval-freeze.md >${SCR}text.txt 2>&1
emit TEXTGUARD_CYCLE_EXIT $?
bash lab/check-spec-mirror.sh >${SCR}mirror.txt 2>&1; emit MIRROR_EXIT $?
python lab/threshold-lint.py --latest >${SCR}lint.txt 2>&1; emit LINT_EXIT $?
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' ${SCR}lint.txt | tail -1 | cut -d= -f2)"
python lab/cycle-gate.py audit >${SCR}audit.txt 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check >${SCR}review.txt 2>&1; emit REVIEW_EXIT $?
emit RUST_TOUCHED "$(git diff --name-only "${PIN:-HEAD}" -- crates/ | wc -l | tr -d ' ')"

WORST=0
for k in SELFTEST_EXIT BASE_CHECK_EXIT SECRETS_EXIT REFS_EXIT CLAIMMAP_EXIT CLAIMS_EXIT \
         CONTOURS_EXIT TEXTGUARD_ALL_EXIT TEXTGUARD_CYCLE_EXIT MIRROR_EXIT LINT_EXIT GATE_AUDIT_EXIT \
         REVIEW_EXIT; do
  v=$(grep -o "^$k=[0-9]*" "$buf" | tail -1 | cut -d= -f2); [ "${v:-1}" = 0 ] || WORST=1
done
# Годность починки: пин обязан пройти все три посаженных дерева зелёным и без причин (дыра названа),
# живой прибор — отбить все три по своей причине и без чужого COMPILE.
emit PIN_EVAL_OK "$([ "$(grab "$buf" PIN_EVAL_EXIT)" = 0 ] && [ "$(grab "$buf" PIN_EVAL_REASONS)" = 0 ] && echo 1 || echo 0)"
emit PIN_STRUCT_OK "$([ "$(grab "$buf" PIN_STRUCT_EXIT)" = 0 ] && [ "$(grab "$buf" PIN_STRUCT_REASONS)" = 0 ] && echo 1 || echo 0)"
emit PIN_INDUCTIVE_OK "$([ "$(grab "$buf" PIN_INDUCTIVE_EXIT)" = 0 ] && [ "$(grab "$buf" PIN_INDUCTIVE_REASONS)" = 0 ] && echo 1 || echo 0)"
emit LIVE_EVAL_OK "$([ "$(grab "$buf" LIVE_EVAL_PLANTED)" = 1 ] && [ "$(grab "$buf" LIVE_EVAL_CAUGHT)" = 1 ] && [ "$(grab "$buf" LIVE_EVAL_KEY)" = 1 ] && [ "$(grab "$buf" LIVE_EVAL_COMPILE)" = 0 ] && echo 1 || echo 0)"
emit LIVE_STRUCT_OK "$([ "$(grab "$buf" LIVE_STRUCT_PLANTED)" = 1 ] && [ "$(grab "$buf" LIVE_STRUCT_CAUGHT)" = 1 ] && [ "$(grab "$buf" LIVE_STRUCT_KEY)" = 1 ] && [ "$(grab "$buf" LIVE_STRUCT_COMPILE)" = 0 ] && echo 1 || echo 0)"
emit LIVE_INDUCTIVE_OK "$([ "$(grab "$buf" LIVE_INDUCTIVE_PLANTED)" = 1 ] && [ "$(grab "$buf" LIVE_INDUCTIVE_CAUGHT)" = 1 ] && [ "$(grab "$buf" LIVE_INDUCTIVE_KEY)" = 1 ] && [ "$(grab "$buf" LIVE_INDUCTIVE_COMPILE)" = 0 ] && echo 1 || echo 0)"
[ "$(grab "$buf" PRE_FIX_HOLE)" = 1 ] || WORST=1
[ "$(grab "$buf" PRE_FIX_DIFFERS)" = 1 ] || WORST=1
[ "$(grab "$buf" PIN_MODELS_DIFF)" = 0 ] || WORST=1
[ "$(grab "$buf" EXTRA_PARSER_OK)" = 1 ] || WORST=1
[ "$(grab "$buf" FREEZE_MATCHES_CHECK)" = 1 ] || WORST=1
[ "$(grab "$buf" GATE_H0141_OK)" = 1 ] || WORST=1
emit WORST_RC "$WORST"

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0141-${TREE_KEY}.facts"
# Из сравнения исключены две строки: измерение диска (оно дышит между прогонами) и собственный
# вердикт этого же блока. Без второй ловушки первый прогон пишет в снимок `STABLE=none`, а второй
# сравнивает свой `STABLE=1` с чужим `none` и краснеет на годном дереве (ДИАГНОЗ круга: вердикт о
# повторяемости не имеет права входить в то, что он сверяет).
Filt() { grep -v -E '^(DISK_FREE_MB|STABLE)=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
else
  emit STABLE none
fi
Filt "$buf" > "$SNAP"
rm -rf "${SCR}pin-tree" "${SCR}live-tree" "${SCR}lean-check-pin.py"
cat "$buf"; rm -f "$buf"
