#!/usr/bin/env bash
# Проверка текстуры текста: в lab-документах и коде не должно быть символов чужих алфавитов —
# иероглифов, каны, хангыля, а также латинской буквы, прилипшей к кириллической внутри одного
# слова. Класс дефекта пойман нами руками несколько раз подряд (иероглиф посреди русского
# предложения, латинское слово вместо «их», латинское числительное вместо русского) и молча
# уезжал в main, потому что diff человек просматривает по смыслу.
#
# Что проверяется машинно: (а) символ-буква не латиницы, не кириллицы и не греческого (математика:
# ε, Θ, Δ в документах намеренные); (б) идеографическая пунктуация; (в) латинская буква
# непосредственно рядом с кириллической (слово-гибрид); (г) латинская буква с диакритикой, кроме
# намеренных русских знаков ударения (ó и U+0301).
#
# Чего здесь сознательно НЕТ: отдельное латинское слово в русском предложении («eight стадиями»)
# не отличить от рабочей терминологии («helper'а», «PoW», `clippy`), поэтому такие случаи — на
# человеческом просмотре, и гипотеза об их машинной ловле здесь не заявляется.
#
# Разрешено намеренное: ASCII, кириллица, все математические и типовые символы (↔, ⊇, ⊂, ⌈⌉, § …)
# — они не алфавит и ловить их смысла нет.
#
# Употребление: bash lab/check-text-clean.sh [путь …]   (без аргументов — git diff HEAD~1..HEAD
# плюс untracked; поэтому в прогоне после пре-регистрационного коммита пути передают явно)
# Выход: 0 — чисто, 1 — найдено.
set -u
cd "${VEC_DHT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
if [ "$#" -gt 0 ]; then
  FILES="$*"
else
  FILES="$(git diff --name-only HEAD~1 HEAD 2>/dev/null; git ls-files --others --exclude-standard)"
fi
python - $FILES <<'PY'
import io, re, sys, unicodedata

CYR = re.compile(r"[\u0400-\u04FF]")
LAT = re.compile(r"[A-Za-z]")
STRESS = {"ó", "\u0301"}           # русское ударение ставится намеренно
CJK_PUNCT = ("IDEOGRAPHIC", "CJK", "FULLWIDTH", "HALFWIDTH")

def bad_char(ch):
    if ord(ch) < 128 or ch.isspace() or 0x400 <= ord(ch) <= 0x4FF or ch in STRESS:
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        name = "??"
    cat = unicodedata.category(ch)
    if cat.startswith("L"):
        if any(k in name for k in ("LATIN", "CYRILLIC", "GREEK")):
            if "WITH" in name and ch not in STRESS:
                return f"{ch}({name})"
            return None
        return f"{ch}({name})"
    if cat[0] in "PZS" and any(k in name for k in CJK_PUNCT):
        return f"{ch}({name})"
    return None                     # прочие символы (математика, пунктуация) — разрешены

bad = 0
for path in sys.argv[1:]:
    path = path.strip()
    if not path:
        continue
    try:
        text = io.open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    for n, line in enumerate(text.splitlines(), 1):
        hits = [c for c in (bad_char(ch) for ch in line) if c]
        # слово-гибрид: латинская буква вплотную к кириллической
        for m in re.finditer(r"[A-Za-z][\u0400-\u04FF]|[\u0400-\u04FF][A-Za-z]", line):
            hits.append(f"гибрид:{m.group(0)!r}")
        if hits:
            bad += 1
            print(f"ГРЯЗНО {path}:{n}: {' '.join(hits[:4])} :: {line.strip()[:90]}")
print(f"ПРОВЕРКА_ТЕКСТА файлов_с_грязью={bad}")
sys.exit(1 if bad else 0)
PY
