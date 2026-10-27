#!/usr/bin/env bash
# H-0133 / E-0133: у нумерации очереди есть вторая форма, и страж её не видел (`E-0137` остаток).
# Цикл приборный: правит только `lab/` и очередь, продукта и спеки не касается (`RUST_TOUCHED=0`,
# `SPEC_TOUCHED=0`). Каждый посаженный случай обязан быть отбит, каждый законный — не отбит.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }
PIN=89895f2                      # дерево до починки: снимок очереди и указатели берутся из него
# Значение ключа из вывода прибора: ключ отделён пробелом, иначе `inline=` матчится внутри
# `только_inline=` (прецедент E-0137: у имени факта один владелец, а у экстрактора — одна граница).
val() { local v; v=$(grep -oE "(^|[[:space:]])$1=[0-9]+" "$2" | tail -1 | grep -oE "[0-9]+$"); printf '%s' "${v:-none}"; }

python lab/cycle-gate.py gate H-0133 >>"$buf" 2>&1 && emit GATE_H0133_OK 1 || emit GATE_H0133_OK 0
bash lab/disk-report.sh >${SCR}disk.txt 2>&1
D=$(val DISK_FREE_MB ${SCR}disk.txt)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# --- прибор: страж нумерации обязан видеть вторую форму -----------------------------------------
emit OQ_GUARD_EXISTS "$([ -f lab/check-oq-numbering.py ] && echo 1 || echo 0)"
git show "$PIN:lab/decisions/OPEN-QUESTIONS.md" > ${SCR}pin-oq.md 2>/dev/null || echo "нет снимка очереди на пине" >&2
if [ -f lab/check-oq-numbering.py ]; then
  python lab/check-oq-numbering.py >${SCR}oq_live.txt 2>&1; emit OQ_NUMBERING_EXIT $?
  emit OQ_INLINE_LIVE "$(val inline ${SCR}oq_live.txt)"
  emit OQ_FORMS_LIVE "$(val форм ${SCR}oq_live.txt)"
  emit OQ_DUP_LIVE "$(val дублей ${SCR}oq_live.txt)"
  emit OQ_ITEMS_LIVE "$(val пунктов ${SCR}oq_live.txt)"

  python lab/check-oq-numbering.py --file ${SCR}pin-oq.md >${SCR}oq_pin.txt 2>&1; emit OQ_PIN_EXIT $?
  emit OQ_PIN_INLINE "$(val inline ${SCR}oq_pin.txt)"
  emit OQ_PIN_FORMS "$(val форм ${SCR}oq_pin.txt)"
  emit OQ_PIN_DUP "$(val дублей ${SCR}oq_pin.txt)"
  [ "$(val inline ${SCR}oq_pin.txt)" -ge 6 ] 2>/dev/null && emit OQ_PIN_INLINE_GE_6 1 || emit OQ_PIN_INLINE_GE_6 0
  [ "$(val дублей ${SCR}oq_pin.txt)" -ge 1 ] 2>/dev/null && emit OQ_PIN_DUP_GE_1 1 || emit OQ_PIN_DUP_GE_1 0

  python lab/check-oq-numbering.py --selftest >${SCR}oq_self.txt 2>&1; emit OQ_SELFTEST_EXIT $?
  emit OQ_PLANTED_CAUGHT "$(val PLANTED_CAUGHT ${SCR}oq_self.txt)"
  emit OQ_PLANTED_TOTAL "$(val PLANTED_TOTAL ${SCR}oq_self.txt)"
  emit OQ_PLANTED_FALSE "$(val PLANTED_FALSE ${SCR}oq_self.txt)"

  python lab/check-oq-numbering.py --pointers >${SCR}ptr_live.txt 2>&1; emit PTR_EXIT $?
  emit PTR_TOTAL "$(val указателей ${SCR}ptr_live.txt)"
  [ "$(val указателей ${SCR}ptr_live.txt)" -ge 60 ] 2>/dev/null && emit PTR_TOTAL_GE_60 1 || emit PTR_TOTAL_GE_60 0
  emit PTR_DANGLING "$(val висях ${SCR}ptr_live.txt)"
  emit PTR_VIA_INLINE_LIVE "$(val только_inline ${SCR}ptr_live.txt)"

  python lab/check-oq-numbering.py --pointers --file ${SCR}pin-oq.md >${SCR}ptr_pin.txt 2>&1; emit PIN_PTR_EXIT $?
  emit PIN_PTR_VIA_INLINE "$(val только_inline ${SCR}ptr_pin.txt)"
  [ "$(val только_inline ${SCR}ptr_pin.txt)" -ge 5 ] 2>/dev/null && emit PIN_PTR_VIA_INLINE_GE_5 1 || emit PIN_PTR_VIA_INLINE_GE_5 0
else
  for k in OQ_NUMBERING_EXIT OQ_SELFTEST_EXIT PTR_EXIT PIN_PTR_EXIT; do emit $k 2; done
  for k in OQ_INLINE_LIVE OQ_FORMS_LIVE OQ_DUP_LIVE OQ_ITEMS_LIVE OQ_PIN_EXIT OQ_PIN_INLINE \
           OQ_PIN_FORMS OQ_PIN_DUP OQ_PLANTED_CAUGHT OQ_PLANTED_TOTAL OQ_PLANTED_FALSE \
           PTR_TOTAL PTR_TOTAL_GE_60 PTR_DANGLING PTR_VIA_INLINE_LIVE PIN_PTR_VIA_INLINE; do emit $k none; done
  emit OQ_PIN_INLINE_GE_6 0; emit OQ_PIN_DUP_GE_1 0; emit PIN_PTR_VIA_INLINE_GE_5 0
fi

# Широкая формулировка («заявка номера в жирной строке — дефект везде») измеряется числом: у
# каждого файла своё пространство номеров, и вне очереди таких строк большинство.
python - >${SCR}naive.txt 2>&1 <<'PY'
import io, re, subprocess
files = subprocess.run(["git", "ls-files", "--", "*.md"], capture_output=True, text=True).stdout.split()
NUM = re.compile(r"^\*\*[0-9]{1,3}\. ")
hits = 0; hitfiles = 0
for f in files:
    try: t = io.open(f, encoding="utf-8", errors="replace").read()
    except OSError: continue
    c = sum(1 for line in t.split("\n") if NUM.match(line))
    if c: hitfiles += 1; hits += c
print("NAIVE_INLINE_HITS=%d" % hits)
print("NAIVE_INLINE_FILES=%d" % hitfiles)
print("NAIVE_INLINE_GE_40=%d" % (1 if hits >= 40 else 0))
print("NAIVE_INLINE_FILES_GE_10=%d" % (1 if hitfiles >= 10 else 0))
PY
grep -q '^NAIVE_INLINE_HITS=' ${SCR}naive.txt || { echo "счетчик наивного правила не напечатал ничего" >&2; exit 2; }
for k in NAIVE_INLINE_HITS NAIVE_INLINE_FILES NAIVE_INLINE_GE_40 NAIVE_INLINE_FILES_GE_10; do
  emit $k "$(val $k ${SCR}naive.txt)"
done

# Область починки: ни одного файла продукта, ни одной строки спеки, заголовков стало ровно 47.
emit HEADINGS_LIVE "$(grep -c '^## п\. ' lab/decisions/OPEN-QUESTIONS.md)"
emit RUST_TOUCHED "$(git diff --name-only $PIN -- crates/ | wc -l | tr -d ' ')"
emit SPEC_TOUCHED "$(git diff --name-only $PIN -- docs/VecDHT-SPEC-v8.md docs/VecDHT-SPEC-v9.md | wc -l | tr -d ' ')"
# Починка считается исполненной в контуре, а не объявленной: прибор обязан стоять в verify и в CI.
# Ключ = флаг присутствия (0/1), а не число строк: замороженное ожидание `=1` означает «стоит», и
# счётчик строк делал бы порог невыполнимым по построению (прецедент ДИАГНОЗа-1 в `E-0088`: у имени
# факта один владелец — здесь владельцем названо присутствие, строки печатаются отдельным ключом).
wired() { n=$(grep -c 'check-oq-numbering' "$1" 2>/dev/null); [ "${n:-0}" -ge 1 ] && echo 1 || echo 0; }
emit VERIFY_WIRES_OQ "$(wired lab/workspace-verify.sh)"
emit CI_WIRES_OQ "$(wired .github/workflows/verify.yml)"
emit VERIFY_WIRES_LINES "$(grep -c 'check-oq-numbering' lab/workspace-verify.sh 2>/dev/null || true)"
emit CI_WIRES_LINES "$(grep -c 'check-oq-numbering' .github/workflows/verify.yml 2>/dev/null || true)"

# `--latest` выбирает цикл по наибольшему номеру, а он у нас меньше (E-0137), поэтому линт вызывается
# явным списком файлов — иначе ключи E-0133 судились бы по чужому порогу.
python lab/threshold-lint.py lab/expectations/e0133.tsv --helper lab/e0133-run.sh \
  lab/experiments/E-0133-queue-numbering-second-form.md \
  lab/hypotheses/H-0133-queue-numbering-second-form.md >${SCR}lint.txt 2>&1; emit LINT_EXIT $?
emit LINT_ORPHANS "$(val СИРОТ ${SCR}lint.txt)"

bash lab/check-secrets.sh --no-history >${SCR}sec.txt 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py >${SCR}refs.txt 2>&1; emit REFS_EXIT $?
bash lab/check-text-clean.sh >${SCR}text.txt 2>&1; emit TEXTGUARD_EXIT $?
bash lab/check-spec-mirror.sh >${SCR}mirror.txt 2>&1; emit MIRROR_EXIT $?
python lab/cycle-gate.py audit >${SCR}audit.txt 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check >${SCR}review.txt 2>&1; emit REVIEW_EXIT $?

TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0133-${TREE_KEY}.facts"
Filt() { grep -v -E '^DISK_FREE_MB=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
fi
Filt "$buf" > "$SNAP"
cat "$buf"; rm -f "$buf"
