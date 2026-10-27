#!/usr/bin/env bash
# H-0137 / E-0137: стражи обязаны видеть форму, на которой они молчат (`E-0136` ДИАГНОЗ-4 и -5).
# Цикл приборный: правит только `lab/`, продукта не касается (`RUST_TOUCHED=0`). Каждый посаженный
# дефект обязан быть отбит, каждый законный случай — не отбит, иначе зелёный контур снова станет
# утверждением про множество форм, которого никто не назвал.
set -uo pipefail
if [ -z "${VEC_DHT_ROOT:-}" ]; then VEC_DHT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; export VEC_DHT_ROOT; fi
cd "$VEC_DHT_ROOT"; export PYTHONIOENCODING=utf-8
SCR=$(mktemp -d)/; buf=$(mktemp) || exit 2
emit() { printf '%s=%s\n' "$1" "$2" >>"$buf"; }

python lab/cycle-gate.py gate H-0137 >>"$buf" 2>&1 && emit GATE_H0137_OK 1 || emit GATE_H0137_OK 0
bash lab/disk-report.sh >${SCR}disk.txt 2>&1
D=$(grep -o 'DISK_FREE_MB=[0-9]*' ${SCR}disk.txt | tail -1 | cut -d= -f2)
emit DISK_FREE_MB "${D:-none}"; [ "${D:-0}" -ge 15000 ] && emit DISK_GE_15000 1 || emit DISK_GE_15000 0

# --- прибор 1: форма, уникальность и порядок номеров пунктов OPEN-QUESTIONS ---------------------
emit OQ_GUARD_EXISTS "$([ -f lab/check-oq-numbering.py ] && echo 1 || echo 0)"
if [ -f lab/check-oq-numbering.py ]; then
  python lab/check-oq-numbering.py >${SCR}oq_live.txt 2>&1; emit OQ_NUMBERING_EXIT $?
  python lab/check-oq-numbering.py --selftest >${SCR}oq_self.txt 2>&1; emit OQ_SELFTEST_EXIT $?
  emit OQ_PLANTED_CAUGHT "$(grep -o '^PLANTED_CAUGHT=[0-9]*' ${SCR}oq_self.txt | tail -1 | cut -d= -f2)"
  emit OQ_PLANTED_TOTAL "$(grep -o '^PLANTED_TOTAL=[0-9]*' ${SCR}oq_self.txt | tail -1 | cut -d= -f2)"
  emit OQ_PLANTED_FALSE "$(grep -o '^PLANTED_FALSE=[0-9]*' ${SCR}oq_self.txt | tail -1 | cut -d= -f2)"
else
  emit OQ_NUMBERING_EXIT 2; emit OQ_SELFTEST_EXIT 2
  emit OQ_PLANTED_CAUGHT none; emit OQ_PLANTED_TOTAL none; emit OQ_PLANTED_FALSE none
fi

# --- прибор 2: отдельное латинское служебное слово в русском предложении ------------------------
# marker=строка определения блока связок: её ищем, чтобы счетчик не зависел от того, сколько раз
# имя множества упомянуто в теле проверки.
emit NARROW_RULE_PRESENT "$(grep -c '^CONNECTIVES = ' lab/check-text-clean.sh)"

# Посаженные дефекты: связка написана латиницей в русской прозе вне кода.
# Сами связки собираются склейкой (`"there" "fore"`): этот файл попадает в репозиторный список
# стража (`lab/*.sh`), и написанное целиком слово сделало бы прибор грязным по правилу, которое он
# же проверяет — ровно тот же приём, что MARKER в `check-text-clean.sh`. Измерено до склейки:
# `--all` дал 7 файлов с грязью, из них 4 строки этого файла.
W1="there""fore"; W2="howe""ver"; W3="thu""s"; W4="unle""ss"
printf 'Отказ носителя %s амнистирует отозванный сертификат.\n' "$W1" > ${SCR}d1.md
printf 'Проба должна %s отличать дыру от слепоты прибора.\n' "$W2" > ${SCR}d2.md
printf 'Таблица иначе %s теряет смысл заморозки чисел.\n' "$W3" > ${SCR}d3.md
printf 'Страж молчит %s форма заголовка проверена прибором.\n' "$W4" > ${SCR}d4.md
# Законные случаи: инлайн-код, fenced-блок, англоязычный файл, часть длинного идентификатора.
printf 'Слово `%s` в инлайн-коде — цитата, а не проза этого файла.\n' "$W1" > ${SCR}c1.md
printf 'Вот образец:\n\n```text\n%s замороженный вектор\n```\n\nи после блока.\n' "$W1" > ${SCR}c2.md
printf 'This guard is %s blind to the shape of a heading.\n' "$W1" > ${SCR}c3.md
printf 'Функция %s_checked ловит только вызовы воронки, а не текст.\n' "$W1" > ${SCR}c4.md

caught=0; for f in ${SCR}d1.md ${SCR}d2.md ${SCR}d3.md ${SCR}d4.md; do
  if bash lab/check-text-clean.sh "$f" >/dev/null 2>&1; then :; else caught=$((caught + 1)); fi
done
emit TXT_PLANTED_CAUGHT $caught
emit TXT_PLANTED_TOTAL 4
false_hits=0; for f in ${SCR}c1.md ${SCR}c2.md ${SCR}c3.md ${SCR}c4.md; do
  if bash lab/check-text-clean.sh "$f" >/dev/null 2>&1; then :; else false_hits=$((false_hits + 1)); fi
done
emit TXT_PLANTED_FALSE $false_hits

# Наивное правило соседства измеряется числом, чтобы его непригодность была фактом, а не мнением.
python - >${SCR}naive.txt 2>&1 <<'PY'
import io, re, subprocess
files = subprocess.run(["git", "ls-files", "--", "*.md"], capture_output=True, text=True).stdout.split()
CYR = re.compile(r"[\u0400-\u04FF]"); WORD = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}")
hits = 0
for f in files:
    try: s = io.open(f, encoding="utf-8", errors="ignore").read()
    except OSError: continue
    if not CYR.search(s): continue
    for line in s.split("\n"):
        bare = re.sub(r"`[^`]*`", "", line)
        if not CYR.search(bare): continue
        for m in WORD.finditer(bare):
            w = m.group(0)
            if w.isupper(): continue
            a, b = bare[:m.start()], bare[m.end():]
            if re.search(r"[\u0400-\u04FF]", a[-6:]) and re.search(r"[\u0400-\u04FF]", b[:6]):
                hits += 1
print("NAIVE_HITS=%d" % hits)
print("NAIVE_GE_1000=%d" % (1 if hits >= 1000 else 0))
PY
grep -q '^NAIVE_GE_1000=' ${SCR}naive.txt || { echo "прибор наивного правила не напечатал ничего" >&2; exit 2; }
emit NAIVE_HITS "$(grep -o '^NAIVE_HITS=[0-9]*' ${SCR}naive.txt | cut -d= -f2)"
emit NAIVE_GE_1000 "$(grep -o '^NAIVE_GE_1000=[0-9]*' ${SCR}naive.txt | cut -d= -f2)"

# Репозиторий обязан соответствовать новому правилу, иначе зелёный контур снова станет ложью.
bash lab/check-text-clean.sh --all >${SCR}all.txt 2>&1; emit TEXTGUARD_ALL_EXIT $?
emit TEXTGUARD_ALL_DIRTY "$(grep -o 'файлов_с_грязью=[0-9]*' ${SCR}all.txt | tail -1 | cut -d= -f2)"

python lab/threshold-lint.py --latest >${SCR}lint.txt 2>&1; emit LINT_EXIT $?
emit LINT_ORPHANS "$(grep -o 'СИРОТ=[0-9]*' ${SCR}lint.txt | tail -1 | cut -d= -f2)"
emit RUST_TOUCHED "$(git diff --name-only 0522144 -- crates/ | wc -l | tr -d ' ')"

bash lab/check-secrets.sh --no-history >${SCR}sec.txt 2>&1; emit SECRETS_EXIT $?
python lab/check-artifact-refs.py >${SCR}refs.txt 2>&1; emit REFS_EXIT $?
bash lab/check-text-clean.sh >${SCR}text.txt 2>&1; emit TEXTGUARD_EXIT $?
bash lab/check-spec-mirror.sh >${SCR}mirror.txt 2>&1; emit MIRROR_EXIT $?
python lab/cycle-gate.py audit >${SCR}audit.txt 2>&1; emit GATE_AUDIT_EXIT $?
python lab/repo-review.py check >${SCR}review.txt 2>&1; emit REVIEW_EXIT $?

# Снимок привязан к дереву: имя ключа «HEAD + отпечаток несохранённых правок». Без привязки
# строка «вектор уже сверялся» читается как факт про два исполнения одного дерева, а на деле
# оказывалось сравнение прогона на пине с чужим снапшотом прошлого прогона (ДИАГНОЗ цикла:
# на пине `0522144` первый запуск дал `STABLE=1` именно так).
TREE_KEY="$(git rev-parse --short HEAD 2>/dev/null || echo nohead)-$(git status --porcelain 2>/dev/null | sha1sum | cut -c1-8)"
SNAP="${TMPDIR:-/tmp}/e0137-${TREE_KEY}.facts"
Filt() { grep -v -E '^DISK_FREE_MB=' "$1"; }
if [ -f "$SNAP" ]; then
  if diff -q <(Filt "$buf") <(Filt "$SNAP") >/dev/null; then emit STABLE 1; else emit STABLE 0; fi
fi
Filt "$buf" > "$SNAP"
cat "$buf"; rm -f "$buf"
