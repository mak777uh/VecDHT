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
# Чего здесь сознательно НЕТ (в узкой части): полный класс отдельных латинских слов в русском
# предложении («eight стадиями») не отличить от рабочей терминологии («helper'а», «PoW», `clippy`),
# поэтому он остаётся на человеческом просмотре и гипотеза о его машинной ловле здесь не заявляется.
# Подзадача решена двумя списками разного статуса. Стоп-лист служебных слов (в него входят `the`,
# `of`, `and`) не содержит ни одного технического имени, но слово из него может оказаться внутри
# цитаты, поэтому такие попадания печатаются строкой ПОДОЗРЕНИЕ и выход скрипта НЕ меняют. Список
# дискурсивных связок (`therefore`, `however`, `thus`, `unless` …) — наоборот: связка не бывает именем
# фреймворка или путём, поэтому её попадание в русскую прозу считается грязью и меняет выход. Причина
# разделения статуса измерена: карточка `E-0136` написала «therefore» в русском тексте и контур
# прошёл нулём, то есть предупреждающий канал для этого класса не работает. Ограничение узкой части
# тоже измерено и записано в `ADR-0045`: пропущенная связка — свойство списка, а не текста, поэтому
# новый случай класса лечится строкой в CONNECTIVES, а не надеждой на человека.
# Код-спаны (`…`), кавычки-ёлочки и лапки из проверки вырезаются: дословная цитата чужого документа
# — не наша опечатка (прецедент: цитата OCI в `ADR-0061`).
#
# Посадка этой проверки проверяется так (четыре слова пойманы, идентификатор и лицензия — нет):
#     printf 'В русском тексте служебное the проскочило, и ещё of или and, но not здесь лишний раз.\n' > /tmp/decoy.md
#     printf 'Функция `is_server = role != Role::Agent` не подозрение, и (MIT OR Apache) тоже.\n' >> /tmp/decoy.md
#     bash lab/check-text-clean.sh /tmp/decoy.md
#
# Канал ПОДОЗРЕНИЕ работает только по разметке (`.md`): в исходниках Python служебные слова — операторы
# языка (`k in row for k in need`), и на код-строке с русским комментарием они дают шум, а не дефект.
# Файл, которому разрешено носить чужой алфавит (тестовая фикстура с настоящей японской строкой), ставит
# в тексте маркер `страж-текста` с последующим словом «разрешено» (полная строка собирается в коде
# склейкой, чтобы этот файл не выводил сам себя из проверки); исключение печатается в вывод и не может
# случиться молча.
#
# Разрешено намеренное: ASCII, кириллица, все математические и типовые символы (↔, ⊇, ⊂, ⌈⌉, § …)
# — они не алфавит и ловить их смысла нет.
#
# Употребление: bash lab/check-text-clean.sh [путь …]   (без аргументов — git diff HEAD~1..HEAD
# плюс untracked; поэтому в прогоне после пре-регистрационного коммита пути передают явно)
#
# Второй режим — `bash lab/check-text-clean.sh --all`: список строится по всему репозиторию из
# `git ls-files` (вся разметка плюс `lab/*.py` и `lab/*.sh`), а не из того, что вспомнил вызывающий.
# Режим нужен потому, что дефекты алфавита живут ровно в тех файлах, которые в текущий прогон не
# передавали: перебор 2026-10-25 нашёл 23 слово-гибрида в 14 карточках и заметках `lab/` — в файлах,
# которые ни в один прогон того дня явно не передавались (списки прогонов строятся вручную, поэтому
# покрытие зависит от памяти вызывающего, а не от репозитория).
# Выход: 0 — чисто, 1 — найдено.
#
# `--selftest` (карточка `H-0151`) сажает дефект каждого канала в temp-файл: связку, гибрид,
# чужой алфавит, разрешающий маркер и чистый текст. Каждый канал проверяется отдельно, а не
# одной строкой со всем сразу, иначе нельзя отличить «страж видит» от «страж печатает».
set -u
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" = "--selftest" ]; then
  SELF="$SELF_DIR/$(basename "$0")"
  T="$(mktemp -d)" || exit 2
  trap 'rm -rf "$T"' EXIT
  cases=0; passed=0
  run_case() { # $1 имя, $2 файл, $3 ожидаемый rc, $4 подстрока вывода
    cases=$((cases + 1))
    rc=0
    out=$(bash "$SELF" "$2" 2>&1) || rc=$?
    if [ "$rc" = "$3" ] && printf '%s\n' "$out" | grep -qF "$4"; then
      passed=$((passed + 1)); echo "ПОСАДКА $1: OK (rc=$rc)"
    else
      echo "ПОСАДКА $1: FAIL — rc=$rc, ожидались rc=$3 и «$4»" >&2
    fi
  }
  printf 'Обычный русский текст с `кодом` и цифрой 5 в строке, ничего лишнего.\n' > "$T/clean.md"
  # Посадочные слова собираются в переменных: литерал в этом файле красил бы сам страж (он
  # гоняется по `lab/*.sh`). Правило то же, что у MARK ниже: называющий класс пишет его в защиту.
  WC="therefore"
  printf 'В русском тексте %s стоит связка, и строка обязана покраснеть.\n' "$WC" > "$T/connective.md"
  printf 'В русском предложении затесался иероглиф \346\274\242 посреди слов.\n' > "$T/cjk.md"
  HY="тест"; HY="${HY}x"
  printf 'Слово с латиницей внутри: %s и ещё слова вокруг, строка русская.\n' "$HY" > "$T/hybrid.md"
  MARK="страж-текста"; MARK="$MARK: разрешено"
  { printf 'Маркер %s и иероглиф ' "$MARK"; printf '\346\274\242'; printf ' в строке.\n'; } > "$T/marker.md"
  run_case clean "$T/clean.md" 0 'файлов_с_грязью=0'
  run_case connective "$T/connective.md" 1 'связка:therefore'
  run_case cjk "$T/cjk.md" 1 'ГРЯЗНО'
  run_case hybrid "$T/hybrid.md" 1 'гибрид'
  run_case marker "$T/marker.md" 0 'ИСКЛЮЧЕНИЕ'
  echo "TCS_SELFTEST_CASES=$cases"
  echo "TCS_SELFTEST_PASSED=$passed"
  echo "TCS_SELFTEST_FAILED=$((cases - passed))"
  [ "$cases" = "$passed" ] && exit 0
  exit 1
fi

cd "${VEC_DHT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
if [ "${1:-}" = "--all" ]; then
  shift
  FILES="$(git ls-files -- '*.md' 'lab/*.py' 'lab/*.sh')"
elif [ "$#" -gt 0 ]; then
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
sus = 0
excluded = 0

# Разрешение на чужой алфавит внутри файла: тестовые фикстуры с настоящей мультиязычной строкой
# (японский запрос в `E-0002-hf-reference.py`) проверяют не нашу текстуру, а поведение кода. Такой
# файл выводится из проверки
# маркером в тексте — молчаливое «исключим по пути» здесь хуже, потому что исключение должно быть
# видно в выводе стража и читаться как явное разрешение.
MARKER = "страж-текста" + ": " + "разрешено"   # собрано склейкой: иначе файл сам себя выводит из проверки

# Подзадача из шапки: английское служебное слово в русской строке. Список закрыт словами, которые
# не могут быть именем кода, фреймворка или идентификатором в этом репозитории.
STOP = set("the a an and or of to in is are was were not for with that this these those from by as "
           "it its at on be can could would should must have has had which who whom whose when where "
           "then than there they them their you your we our i".split())

# Дискурсивные связки. В отличие от STOP они не предупреждение, а грязь: слово из этого списка в
# русской строке не бывает цитой кода, именем инструмента или пути, и пропущенное здесь стоило
# циклу `E-0136` целого ДИАГНОЗа (текст карточки написал «therefore» и контур прошёл нулём).
# Формулировка «список закрыт» обязана перечитываться: пропущенная связка — свойство списка.
CONNECTIVES = set("therefore however thus hence moreover furthermore nevertheless nonetheless "
                  "otherwise unless although whereas thereby whereby thereafter hereafter likewise "
                  "meanwhile consequently accordingly".split())

def hard_flags(text):
    """Защита для РЕШАЮЩЕЙ проверки связок. Совпадает с protected_flags кроме одного: одинарные
    кавычки сюда не входят намеренно. Их аргумент уже написан в protected_flags и он здесь решающий:
    русская строка с двумя апострофами защищает кусок между ними, то есть прячет дефект — для
    предупреждающего канала это приемлемо, для меняющего выход — нет. Многострочные цитаты при этом
    не теряются: `«…»` и код-спан здесь ищутся по всему тексту, а не построчно."""
    flags = [False] * len(text)
    for rx in (r"`[^`]*`", r"«[^»]*»", r'"[^"]*"'):
        for m in re.finditer(rx, text):
            for k in range(m.start(), m.end()):
                flags[k] = True
    return flags

def connective_lines(text):
    """Номера строк, где английская связка стоит в русской прозе вне цитаты. Три исключения проверены
    посаженными случаями: код-спан и fenced-блок (там чужое слово — материал, а не опечатка), кавычки
    (там дословная цитата) и соседство с `_`, цифрой или слэшем (там это часть идентификатора
    или пути). Файл, который называет класс, обязан писать связку в защиту, иначе страж ловит
    собственное описание — это не ложное срабатывание по алфавиту, а рабочее правило: проверено на
    шапке этого файла."""
    out = {}
    flags = hard_flags(text)
    off = 0
    fence = False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fence = not fence
            off += len(line) + 1
            continue
        if not fence and sum(1 for c in line if CYR.match(c)) >= 8:
            for m in re.finditer(r"[A-Za-z]+", line):
                w = m.group(0)
                if w != w.lower() or w not in CONNECTIVES:
                    continue
                k = off + m.start()
                if flags[k]:
                    continue
                prev = line[m.start() - 1] if m.start() else ""
                nxt = line[m.end()] if m.end() < len(line) else ""
                if prev in NEIGH or nxt in NEIGH:
                    continue
                out.setdefault(n, []).append(w)
        off += len(line) + 1
    return out

def protected_flags(text):
    """Код-спаны, кавычки-ёлочки, лапки и одинарные кавычки — чужое слово, а не наша опечатка. Ищем по
    всему тексту, потому что цитата и многострочный код-спан переносятся на следующую строку.
    Одинарные кавычки стоят того, чтобы принять их неуклюжесть: русская строка с двумя апострофами
    («helper'а», «PoW'а») защищает кусок между ними, то есть теоретически прячет дефект — для
    предупреждающей проверки это приемлемо, для решающей (грязь по алфавитам) нет."""
    flags = [False] * len(text)
    for rx in (r"`[^`]*`", r"«[^»]*»", r'"[^"]*"', r"'[^'\n]*'"):
        for m in re.finditer(rx, text):
            for k in range(m.start(), m.end()):
                flags[k] = True
    return flags

# Соседние символы, которые превращают слово в часть идентификатора или пути: их не считаем.
NEIGH = set("_=/0123456789")

def suspicions(path, text):
    flags = protected_flags(text)
    lines = text.splitlines()
    for m in re.finditer(r"[A-Za-z][A-Za-z'-]*", text):
        w = m.group(0)
        # только строчными: лицензионное «MIT OR Apache-2.0» и заглавные аббревиатуры — не проза
        if len(w) < 2 or w != w.lower() or w not in STOP or flags[m.start()]:
            continue
        prev = text[m.start() - 1] if m.start() else ""
        nxt = text[m.end()] if m.end() < len(text) else ""
        if prev in NEIGH or nxt in NEIGH:
            continue
        n = text.count("\n", 0, m.start()) + 1
        if sum(1 for c in lines[n - 1] if CYR.match(c)) < 8:
            continue                     # строка не русская проза — сверять нечего
        yield n, w, lines[n - 1].strip()[:90]

for path in sys.argv[1:]:
    path = path.strip()
    if not path:
        continue
    try:
        text = io.open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    if MARKER in text:
        excluded += 1
        print(f"ИСКЛЮЧЕНИЕ {path}: файл разрешён маркером «{MARKER}», проверка не выполняется")
        continue
    if path.endswith(".md"):
        for n, w, snip in suspicions(path, text):
            sus += 1
            print(f"ПОДОЗРЕНИЕ {path}:{n}: служебное латинское слово {w!r} в русской строке :: {snip}")
    spans = [(m.start(), m.end()) for m in re.finditer(r"`[^`]*`", text)]
    off = 0
    for n, line in enumerate(text.splitlines(), 1):
        hits = [c for c in (bad_char(ch) for ch in line) if c]
        # слово-гибрид: латинская буква вплотную к кириллической. То же самое слово в код-спане —
        # цитата дефекта (её мы и обязаны печатать в ДИАГНОЗах), а не новая опечатка.
        for m in re.finditer(r"[A-Za-z][\u0400-\u04FF]|[\u0400-\u04FF][A-Za-z]", line):
            if any(s <= off + m.start() < e for s, e in spans):
                continue
            # Исключение по escape-последовательности: в исходнике `"\nВсе"` соседство `n` и `В` —
            # это управляющий символ перевода строки, записанный двумя байтами, а не буква внутри
            # слова. Пара «обратный слэш + латиница» не может быть началом нашего слова, поэтому
            # она не грязь. Проверено на посаженном дефекте (шаг 4b в `lab/e0130-run.sh`): строка
            # с переводом строки и дефектом внутри слова остаётся грязной — слэш к нему не ведёт.
            latin = m.start() if LAT.match(line[m.start()]) else m.end() - 1
            if latin > 0 and line[latin - 1] == "\\":
                continue
            hits.append(f"гибрид:{m.group(0)!r}")
        off += len(line) + 1
        if hits:
            bad += 1
            print(f"ГРЯЗНО {path}:{n}: {' '.join(hits[:4])} :: {line.strip()[:90]}")
    # Связки сверяем отдельным проходом: им не нужен offset-каркас код-спанов, потому что
    # многострочный span здесь ловится флагом fenced-блока, а не парой обратных кавычек.
    for n, ws in sorted(connective_lines(text).items()):
        bad += 1
        print(f"ГРЯЗНО {path}:{n}: связка:{' '.join(sorted(set(ws)))} :: {text.splitlines()[n - 1].strip()[:90]}")
print(f"ПРОВЕРКА_ТЕКСТА файлов_с_грязью={bad} подозрений={sus} исключено={excluded}")
sys.exit(1 if bad else 0)
PY
