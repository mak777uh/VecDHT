#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Порог, который некому напечатать, — не порог, а обещание. Линт до 20-минутного прогона.

История, ради которой прибор существует: четыре раза подряд замерный цикл выяснял на прогоне,
что порог невыполним по построению, а не по факту — `E-0088` (имя ключа с меткой прогона внутри),
`E-0091` (в вектор попали счётчики шагов), `E-0095` (ожидание сверяло строку, которой helper не
печатал), `E-0100` (cmp сравнивал файлы с `_r1`/`_r2`). Каждый раз это стоило полного прогона и
разбора, и каждый раз ловилось глазами. Здесь те же три проверки делает машина:

1. каждый ключ таблицы ожиданий обязан встречаться в ИСТОЧНИКЕ как печатный факт (`KEY=`,
   воронка `emit KEY`, `emit_fact("KEY"`, шаблон семейства `PRE_"KEY_{}"` или список имён цикла
   с воронкой `emit "PREFIX_$k"`);
2. helper не вправе сравнивать файлы, в именах ключей которых вшита метка прогона, иначе
   `cmp` разойдётся на неизменном дереве;
3. таблица не вправе быть пустой или состоять из комментариев.

Употребление:
    python lab/threshold-lint.py lab/expectations/e0100.tsv \
        --helper lab/e0100-run.sh --sources crates benches lab/*.py lab/*.sh
    python lab/threshold-lint.py --selftest

Выход 0 — все ключи кому-то принадлежат; 1 — есть сирота; 2 — линт не смог прочитать вход.
"""

import glob
import itertools
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LEFT = r"(?:(?<=^)|(?<=\s))"
# Перенос строки обратным слэшем. Записан через коды, а не литералом: разбор экранирования в
# редакторе уже один раз съел обратный слэш и вырезал из шаблонов `\n`, после чего циклы `printf`
# перестали разрешаться (ДИАГНОЗ-1 `E-0140`).
CONT = chr(92) + chr(10)


def load_keys(path):
    keys = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                raise ValueError(f"строка без табуляции: {line!r}")
            keys.append(parts[0].strip())
    return keys


def key_pattern(key):
    """Ключ обязан стоять началом токена, но в ИСХОДНИКЕ он стоит внутри строкового литерала.

    Поэтому слева допускается кавычка или `\\n`/`\\t`-escape: `println!("\\nKEY={}", …)` — это
    печать (так счётчики отделяются от префикса libtest, блок 3 `E-0100`), а `PRE_FIX_KEY=1`
    по-прежнему не является печатью `KEY=1`.
    """
    parts = key.split(" ")
    left = r'(?:^|["\s]|\\[nt])'
    if len(parts) == 1:
        head = left + re.escape(parts[0])
    else:
        head = r"(?:^|[\"\s]|\\[nt])" + re.escape(parts[0]) + r"[^\n]*?" + re.escape(parts[-1])
    return re.compile(head + r"\s*=\s*\S")


def emit_pattern(key):
    """Shell-воронка `emit KEY значение` — печать факта без литерала `KEY=`.

    До этого цикла линт знал только литеральные печати и объявлял сиротами ключи helper'ов
    `E-0134`/`E-0135`, которые печатают факты воронкой `emit`. Требуется буквально `emit`
    плюс имя ключа отдельным словом: `emit PRE_FIX_A` ключом `A` не считается.
    """
    return re.compile(r'\bemit\s+' + re.escape(key) + r'\b')


def gather_sources(paths):
    files = []
    for p in paths:
        hits = glob.glob(p)
        if not hits and os.path.exists(p):
            hits = [p]
        for h in hits:
            if os.path.isdir(h):
                for root, _, names in os.walk(h):
                    files.extend(os.path.join(root, n) for n in names
                                 if n.endswith((".rs", ".py", ".sh")))
            elif os.path.isfile(h) and h.endswith((".rs", ".py", ".sh")):
                files.append(h)
    # Сама таблица и логи не считаются источником факта: иначе ключ «напечатан» ожиданием.
    return sorted({f for f in files
                   if "/expectations/" not in f.replace("\\", "/")
                   and "/logs/" not in f.replace("\\", "/")})


# Имя факта, включая кириллицу: таблицы закрытых циклов содержат `repro_вектор` (`E-0093`…`E-0095`).
# Латинский алфавит объявлял такие ключи сиротами, хотя дерево печатает их литералом. Диапазон задан
# кодами, а не литералом: страж текста справедливо видит в литеральном классе гибрид алфавитов.
_CYR = "".join(chr(c) for c in range(0x0410, 0x0450)) + chr(0x0401) + chr(0x0451)
_TOKEN = "[A-Za-z" + _CYR + "0-9_]+"
_ID = "[A-Za-z" + _CYR + "][A-Za-z" + _CYR + "0-9_]*"


def _tokens(chunk):
    """Слова литерального списка: `A B C`, в том числе через `\\`-перенос.

    Цифры допущены: `for i in 1 2` печатает `VECTOR_1_EXIT`, а запрет на числовой токен объявлял
    такой ключ сиротой (первый прогон свода `E-0140`). Годность решает итоговая проверка целого
    имени, а не отдельное слово списка.
    """
    return {t for t in chunk.replace(CONT, " ").split() if re.fullmatch(_TOKEN, t)}


def _literals(text):
    """Литеральные списки имён: `VAR="A B C"` (в том числе через перевод строки) и `for x in A B C`.

    Только то, что написано в файле буквально: переменная окружения, вывод другой программы или
    аргумент командной строки сюда не попадают, и ключ, собранный из них, остаётся без статического
    владельца (пункт (в) п. 78: сведение обязано печатать, чем закрыт каждый ключ).
    """
    out = {}
    for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"', text):
        toks = _tokens(m.group(2))
        if toks:
            out.setdefault(m.group(1), set()).update(toks)
    for m in re.finditer(r"\bfor\s+(\w+)\s+in\s+([^;{]*?)(?:;|\bdo\b)", text):
        toks = _tokens(m.group(2))
        if toks:
            out.setdefault(m.group(1), set()).update(toks)
    return out


def _ref_values(name, lits, body, text):
    """Что может подставить `$name`: литеральный список, литералы позиционного аргумента.

    Позиционный аргумент связывается с вызовом той же функции в том же файле: `grab "$V1" 1 "$K"`
    обязано оставить в множестве только те токены, что стоят на этой позиции буквально. Это узкая
    мера: она закрывает формы «приставка или список имён приходят аргументом в общий прибор»
    (пункт (б) п. 79) и не выдумывает значений, которых в файле нет. Имя из одних цифр — это
    позиция в теле функции (`for k in $3`), а не переменная.
    """
    if name in lits:
        return set(lits[name])
    if name.isdigit():
        pos = int(name) - 1
    else:
        m = re.search(r'(?:local\s+)?' + re.escape(name) + r'="\$\{?(\d+)(?::-[^}]*)?\}?"', body)
        if not m:
            m = re.search(r'(?:local\s+)?' + re.escape(name) + r'="\$\{?(\d+)(?::-[^}]*)?\}?"',
                          text)
        if not m:
            return set()
        pos = int(m.group(1)) - 1
    fn = _enclosing_func(body, text)
    if fn is None:
        return set()
    # Аргументы вызова не переходят границу строки без `\`: прежний `\s+` заглатывал слова
    # следующего комментария (`# --- ШАГ 1: POST_FIX ...`) и второй вызов `probe` переставал
    # существовать — POST_FIX оставался сиротой при верном носителе (красный блок `E-0159`).
    vals = set()
    for call in re.finditer(
            r'\b' + re.escape(fn) +
            r'((?:(?:[ \t]+|\\\r?\n[ \t]*)(?:"[^"]*"|[^\s;|&]+))+)', text):
        args = re.findall(r'"([^"]*)"|([^\s]+)', call.group(1))
        args = [a or b for a, b in args]
        if len(args) <= pos:
            continue
        tok = args[pos]
        # На позиции может стоять не список, а имя переменной со списком (`grab … 1 "$DR_KEYS"`):
        # тогда список берётся из литеральных присваиваний файла, а не из текста самого имени.
        ref = re.fullmatch(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?(?:[:\-][^}]*)?', tok)
        if ref:
            vals |= set(lits.get(ref.group(1), set()))
        else:
            vals |= _tokens(tok)
    return vals


def _enclosing_func(body, text):
    """Функция, в теле которой стоит печатающая строка: определение, чьи скобки её накрывают.

    Прежняя версия требовала, чтобы имя функции стояло в самой печатающей строке. У `grab()` и
    `parse_map()` этого нет, и приставка, пришедшая аргументом (пункт (б) п. 79), не разрешалась.
    Скобки считаются по тексту целиком, поэтому `{` внутри строки может сдвинуть границу; если
    граница не замкнулась, функция не называется и ключ остаётся сиротой — прибор не угадывает.
    """
    first = body.strip().split("\n", 1)[0].strip()
    if not first:
        return None
    at = text.find(first)
    if at < 0:
        return None
    best = None
    for m in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", text, re.M):
        if m.end() > at:
            continue
        depth = 0
        i = m.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i > at:
            best = m.group(1)
    return best


FUNNEL = r'(?:\bemit\b|\becho\b|\bsay\b|\bprintf\b)'


def _templates(chunk):
    """Литералы печатающей воронки: `emit "X"`, `echo "X"`, `printf 'X' аргументы`.

    Возвращает список шаблонных строк вместе с аргументами, стоящими после них (нужно для `printf`,
    где имя собирается из `%s` и последующих `$k`).
    """
    out = []
    for m in re.finditer(FUNNEL + r'\s+("([^"]*)"|\'([^\']*)\')(.*)', chunk):
        tmpl = m.group(2) if m.group(2) is not None else m.group(3)
        out.append((tmpl, m.group(4) or ""))
    return out


def _name_tokens(tmpl):
    """Куски шаблона, где может стоять имя факта: в каждом слове — до первого `=`.

    Одна печать часто несёт несколько фактов (`echo "A=${x} B=${y}"`), а значение справа от `=`
    именем не является: `echo "TAG=$k"` не печатает факт `axiom`. Слово без `=` — факт только
    тогда, когда имя в нём собирается (`emit "LIVE_$k"`): чистая проза шапок
    (`echo "########## STEP ${name} ##########"`) давала ложные склейки (`Verus`, `selftest`,
    `ШАГ`) в множестве напечатанных имён.
    """
    return [t.split("=")[0] for t in tmpl.split()
            if "=" in t or "$" in t or "%s" in t]


def _splice_template(tmpl, args, lits, text, body, bind=None):
    """Имена, которые воронка печатает склейкой шаблона и литеральных подстановок.

    Две формы: `$var`/`${var}` внутри имени (`"PRE_FIX_${kind}_EXIT"`) и `printf '%s_%s='` с
    аргументами (`"$k" "$s"`). Все ссылки имени разрешаются обязательно — если хоть одна не
    раскрывается литералом, имя не выдаётся вовсе: прибор не угадывает.
    """
    out = set()
    for tok in _name_tokens(tmpl):
        if "%s" in tok:
            parts = tok.split("%s")
            words = re.findall(r'"[^"]*"|\S+', args)
            refs = []
            for w in words:
                m = re.fullmatch(r'"\$\{?([A-Za-z0-9_]+)\}?"|\$\{?([A-Za-z0-9_]+)\}?', w)
                refs.append((m.group(1) or m.group(2)) if m else None)
            pools = []
            for i in range(len(parts) - 1):
                vals = _ref_values(refs[i], lits, body, text) \
                    if i < len(refs) and refs[i] else set()
                if i < len(refs) and refs[i] in (bind or {}):
                    vals = set(bind[refs[i]])
                if not vals:
                    pools = None
                    break
                pools.append(sorted(vals))
            if pools:
                for combo in itertools.product(*pools):
                    out.add("".join(p + c for p, c in zip(parts, combo)) + parts[-1])
            continue
        refs = [(m.start(), m.end(), m.group(1)) for m in re.finditer(r"\$\{?(\w+)\}?", tok)]
        pools = []
        for _, _, name in refs:
            vals = set((bind or {}).get(name, set())) or _ref_values(name, lits, body, text)
            if not vals:
                pools = None
                break
            pools.append(sorted(vals))
        if not pools:
            continue
        for combo in itertools.product(*pools):
            s = tok
            for (a, b, _), c in reversed(list(zip(refs, combo))):
                s = s[:a] + c + s[b:]
            out.add(s)
    return [c for c in out if re.fullmatch(_ID, c)]


def emitted_names(text):
    """Имена, которые дерево печатает воронкой: (склейкой вне цикла, циклом по списку).

    Привязка списка к телу цикла обязательна (пункт (а) п. 78): два `for` с одной переменной не
    сливаются, потому что значения берутся из списка этого же `for` и передаются в подстановку
    явно. Список вправе прийти позиционным аргументом (`for k in $3` у `grab`) — это форма (б) п. 79.
    """
    flat = text.replace(CONT, "")
    lits = _literals(text)
    spliced, looped = set(), set()
    spans = []
    for m in re.finditer(r"\bfor\s+(\w+)\s+in\s+([^;]*?)(?:\s*;\s*)?\bdo\b\s*(.*?)\bdone\b",
                         flat, re.S):
        var, lst, body = m.group(1), m.group(2), m.group(3)
        spans.append((m.start(), m.end()))
        vals = _tokens(lst)
        for ref in re.findall(r"\$\{?([A-Za-z0-9_]+)\}?", lst):
            vals |= _ref_values(ref, lits, body, text)
        if not vals:
            continue
        bind = {var: vals}
        for chunk in re.findall(FUNNEL + r'[^\n]*', body):
            for tmpl, args in _templates(chunk):
                looped |= set(_splice_template(tmpl, args, lits, text, body, bind))
    for m in re.finditer(FUNNEL + r'[^\n]*', flat):
        if any(a <= m.start() < b for a, b in spans):
            continue
        for tmpl, args in _templates(m.group(0)):
            spliced |= set(_splice_template(tmpl, args, lits, text, m.group(0)))
    return spliced, looped


def reprinted_names(text):
    """Имена, перепечатанные из переменной: `k=ИМЯ` рядом с печатью `"$k"`, и отбор `grep -E`.

    Прибор `E-0131` читает файл чужого прибора, печатает его ключи своим `printf '%s=%s' "$k"` и
    по дороге переименовывает часть (`k=ALLOWLIST_EMPTY_REASON`). Ни `k=`, ни `grep -E` сами по
    себе печатью не являются: имя закрывается только когда в том же теле цикла стоит печать
    переменной, а набор имён отбирает регулярка `^PREFIX_(A|B)=` непосредственно перед циклом.
    """
    out = set()
    for m in re.finditer(r"\bwhile\b[^;\n]*\bread\b[^;]*;\s*do\b(.*?)\bdone\b", text, re.S):
        body = m.group(1)
        if not re.search(r"printf\s+[\"']%s=%s[^\"']*[\"']\s+\"\$k\"", body):
            continue
        for mm in re.finditer(r"\bk=([A-Za-z_][A-Za-z0-9_]*)\b", body):
            out.add(mm.group(1))
        head = text[:m.start()].rstrip().split("\n")[-1]
        g = re.search(r"grep\s+-E\s+[\"']?\^?([A-Za-z0-9_]*)_\(([A-Za-z0-9_|]+)\)=", head)
        if g:
            out |= {g.group(1) + "_" + a for a in g.group(2).split("|") if a}
    return out


def tag_tokens(text):
    """Приставка, которую прибор приписывает фактам при сбросе: `sed "s/^/${TAG}/"` + `--tag TOK`."""
    if not re.search(r"sed\s+[\"']s/\^/\$\{?TAG\}?/", text):
        return set()
    return set(re.findall(r"--tag\s+([A-Za-z0-9_]+)", text))


def strip_tokens(text):
    """Метки прогона, которые прибор снимает перед сверкой: `sed -E 's/_(r1|r2)=/=/g'`."""
    out = set()
    for m in re.finditer(r"s/_\(([A-Za-z0-9_|]+)\)=/", text):
        out |= {t for t in m.group(1).split("|") if t}
    return out


def tree_names(texts):
    """Всё, что дерево печатает, по классам: индекс одиночных имён и склейки/перепечатки/тег."""
    idx = corpus_index(list(texts))
    looped, spliced, reprinted, tagged = set(), set(), set(), set()
    strip = set()
    for text in texts:
        sp, lp = emitted_names(text)
        spliced |= sp
        looped |= lp
        reprinted |= reprinted_names(text)
        strip |= strip_tokens(text)
        tags = tag_tokens(text)
        if tags:
            base = sp | lp | reprinted | set(
                re.findall(r"\bemit\s+([A-Za-z_][A-Za-z0-9_]*)\b", text))
            for t in tags:
                tagged |= {t + n for n in base}
    if strip:
        for group in (looped, spliced):
            for n in list(group):
                for t in strip:
                    if n.endswith("_" + t):
                        group.add(n[: -len(t) - 1])
    return {"idx": idx, "loop": looped, "spliced": spliced,
            "reprint": reprinted, "tag": tagged}


def carrier_names(paths):
    """Имена, напечатанные в носителях закрытых циклов: доказательство исполнения, а не чтения.

    Таблица закрытого цикла описывает дерево того прогона; прибор мог быть переименован позже, и
    тогда статический поиск по живому дереву объявляет порог сиротой, которого не было. Носитель
    содержит фактическую строку факта, поэтому он и является владельцем такого имени. Класс печатается
    отдельным числом и в живом прогоне (`--latest`) не участвует: там обязано быть живое дерево.
    """
    out = set()
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for line in text.splitlines():
            s = line.strip()
            for m in re.finditer(r'(?:^|МЕРЕНО\s+|\s)([A-Za-z][A-Za-z0-9_]*)=', s):
                out.add(m.group(1))
    return out



def dynamic_pattern(key):
    """Ключ, который прибор печатает шаблоном: `NODE_SLOT_ATTR_{}` для owner 101.

    Прибор вправе печатать семейство фактов циклом, но тогда имя обязано быть
    «префикс + _{» буквально в источнике — иначе это не шаблон, а догадка линта.
    """
    m = re.match(r"^(.*)_\d+$", key)
    if not m:
        return None
    return re.compile(r'"' + re.escape(m.group(1)) + r"_\{")


FORM_KEYS = ("ЛИТЕРАЛОМ", "ВОРОНКОЙ", "RUST-ВОРОНКОЙ", "ШАБЛОНОМ", "ЦИКЛОМ",
             "СКЛЕЙКОЙ", "ПЕРЕПЕЧАТКОЙ", "ТЕГОМ", "НОСИТЕЛЕМ")


def read_blobs(paths):
    out = []
    for f in paths:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                out.append(fh.read())
        except OSError:
            continue
    return out


def lint(expect_path, helper, source_paths, carrier_paths=(), per_form=False):
    keys = load_keys(expect_path)
    files = gather_sources(source_paths)
    if helper:
        files.append(helper)
    texts = read_blobs(files)
    names = tree_names(texts)
    carrier = carrier_names(carrier_paths) if carrier_paths else set()
    bad = 0
    cyc = 0
    forms = {k: 0 for k in FORM_KEYS}
    if not keys:
        print("ПОРОГ БЕЗ ПРИБОРА: таблица ожиданий пуста")
        return 1
    for key in keys:
        form = classify(key, names, carrier)
        if form == "СИРОТОЙ":
            bad += 1
            print(f"ПОРОГ БЕЗ ПРИБОРА: {key} — ни один источник не печатает этот факт")
        else:
            forms[form] += 1
            if form == "ЦИКЛОМ":
                cyc += 1

    # Сравнение файлов фактов без снятия метки прогона: `cmp -s "$F1" "$F2"` — невыполнимый порог.
    if helper and os.path.isfile(helper):
        for n, line in enumerate(open(helper, encoding="utf-8", errors="replace"), 1):
            if re.search(r"\bcmp\s+-s?\b", line) and "strip_run" not in line \
                    and "facts.py" not in line and "factlib" not in line:
                bad += 1
                print(f"ПОРОГ НЕВЫПОЛНИМ: {helper}:{n} сравнивает файлы без снятия метки "
                      f"прогона: {line.strip()}")
    print(f"ПОРОГОВ={len(keys)} ИСТОЧНИКОВ={len(texts)} ЦИКЛОМ={cyc} СИРОТ={bad}")
    if per_form:
        # По одному ключу на строку: сводка в одной строке читается якорем плохо (правило E-0131).
        for form in FORM_KEYS:
            print(f"ФОРМА_{form}={forms[form] or 'none'}")
    return 0 if bad == 0 else 1



CASES = [
    # (имя, ключ таблицы, текст источника, строка cmp в helper или None, ожидаемый rc)
    ("rust-воронка emit_fact узнаётся", "A", 'fn t() { emit_fact("A", 1); }', None, 0),
    ("ключ напечатан — пропуск", "A", "A=1\n", None, 0),
    ("ключа нет — сирота", "A", "B=1\n", None, 1),
    ("ключ только префиксом чужого — сирота", "A", "PRE_FIX_A=1\n", None, 1),
    ("cmp с метками прогона — невыполним", "A", "A=1\n", 'cmp -s "$F1" "$F2"', 1),
    ("cmp через strip_run — выполним", "A", "A=1\n", 'cmp -s <(strip_run "$F1") <(strip_run "$F2")', 0),
    ("шаблон семейства — динамический порог", "S_101", 'println!("S_{}={}", 101, 1);\n', None, 0),
    ("шаблон чужого префикса — сирота", "S_101", 'println!("Q_{}={}", 101, 1);\n', None, 1),
    # `E-0140`: в таблицах закрытых циклов есть кириллица в имени (`repro_вектор`, `E-0093`…`E-0095`).
    # Латинский алфавит индекса объявлял живой литерал сиротой; медленный путь находил его, и
    # расхождение печаталось отдельным счётчиком.
    ("кириллица в имени печатаемого ключа", "repro_вектор",
     'echo "repro_вектор=совпал"\n', None, 0),
    ("кириллица в имени ненапечатанного ключа", "repro_время",
     'echo "repro_вектор=совпал"\n', None, 1),
    # Блок 3 `E-0100`: счётчик печатается с ведущим `\n`, и прежняя граница «кавычка или пробел»
    # объявила четыре живых ключа сиротами. Escape в литерале — тоже печать.
    ("ключ после \\n-escape в литерале", "A", 'println!("\\nA={}", 1);\n', None, 0),
    # `E-0135`: helper'ы печатают факты воронкой emit, а не литералом.
    ("ключ напечатан воронкой emit - пропуск", "A", 'emit A "1"\n', None, 0),
    ("воронка печатает чужой ключ - сирота", "A", 'emit B "1"\n', None, 1),
    ("префикс PRE_FIX_ в воронке не печатает ключ", "A", 'emit PRE_FIX_A 1\n', None, 1),
    # `E-0138`: семейства печатаются списком имён и одной воронкой с переменной.
    ("ключ напечатан циклом с префиксом - пропуск", "LIVE_A",
     'for k in A B; do\n  emit "LIVE_$k"\ndone\n', None, 0),
    ("ключ напечатан циклом без префикса - пропуск", "A",
     'for k in A B; do\n  emit "$k"\ndone\n', None, 0),
    ("список цикла продолжен обратным слэшем - пропуск", "LIVE_B",
     'for k in A \\\n  B; do\n  emit "LIVE_$k"\ndone\n', None, 0),
    ("имени нет в списке цикла - сирота", "LIVE_C",
     'for k in A B; do\n  emit "LIVE_$k"\ndone\n', None, 1),
    ("префикс цикла не совпадает - сирота", "FIX_A",
     'for k in A; do\n  emit "LIVE_$k"\ndone\n', None, 1),
    ("воронка с переменной без списка имён - сирота", "A", 'emit "$k"\n', None, 1),
    # `E-0140`, форма (1): переменная внутри имени, суффикс после неё, две печати в одной строке
    # и числовой список (`for i in 1 2`) — так напечатаны шесть ключей `E-0093`.
    ("переменная в середине имени - пропуск", "PRE_FIX_axiom_EXIT",
     'for kind in axiom weaken; do\n'
     '  echo "PRE_FIX_${kind}_EXIT=${rc} PRE_FIX_${kind}_LEAN_ALL_OK=${allok}"\n'
     'done\n', None, 0),
    ("вторая печать той же строки - пропуск", "PRE_FIX_weaken_LEAN_ALL_OK",
     'for kind in axiom weaken; do\n'
     '  echo "PRE_FIX_${kind}_EXIT=${rc} PRE_FIX_${kind}_LEAN_ALL_OK=${allok}"\n'
     'done\n', None, 0),
    ("числовой список цикла - пропуск", "VECTOR_2_EXIT",
     'for i in 1 2; do\n  echo "VECTOR_${i}_EXIT=${rc}"\ndone\n', None, 0),
    # `E-0140`, форма (2): приставка приходит аргументом в общий прибор (`parse_map … "PRE_M_"`).
    # Заголовок `# do` стоит здесь нарочно: граница функции ищется по первой строке тела, и
    # прежний разбор тела цикла («; do» оставалось в теле) цеплялся за первое `do` файла.
    ("приставка приходит аргументом - пропуск", "PRE_M_SENTENCES",
     '# do not touch\nparse_map() {\n  local pre="$2"\n  for key in SENTENCES IDS; do\n'
     '    emit "${pre}${key}=$v"\n  done\n}\nparse_map x "PRE_M_"\n', None, 0),
    ("чужая приставка не печатает ключ", "OTHER_SENTENCES",
     '# do not touch\nparse_map() {\n  local pre="$2"\n  for key in SENTENCES IDS; do\n'
     '    emit "${pre}${key}=$v"\n  done\n}\nparse_map x "PRE_M_"\n', None, 1),
    # `E-0159`: аргументы вызова не переходят строку без `\`; слова следующего комментария
    # не должны съедать второй вызов той же функции.
    ("приставка второго вызова после комментария - пропуск", "POST_M_SENTENCES",
     '# do not touch\nparse_map() {\n  local pre="$2"\n  for key in SENTENCES IDS; do\n'
     '    emit "${pre}${key}=$v"\n  done\n}\nparse_map x "PRE_M_"\n'
     '# второй вызов: "POST_M_" и слова\nparse_map x "POST_M_"\n', None, 0),
    # `E-0140`, форма (3): список имён и метка прогона идут в общий `printf` позиционными
    # аргументами, а `strip_run` снимает метку перед сверкой.
    ("список имён в аргументе printf - пропуск", "n1_V",
     '# do not touch\ngrab() {\n  local s="$2" k v\n  for k in $3; do\n'
     '    printf \'n%s_%s=%s\\n\' "$s" "$k" "$v"\n  done\n}\ngrab f 1 "V W"\n', None, 0),
    ("имени нет в списке аргумента - сирота", "n1_X",
     '# do not touch\ngrab() {\n  local s="$2" k v\n  for k in $3; do\n'
     '    printf \'n%s_%s=%s\\n\' "$s" "$k" "$v"\n  done\n}\ngrab f 1 "V W"\n', None, 1),
    ("метка прогона снимается strip_run - пропуск", "dr_x",
     '# do not touch\ngrab() {\n  local s="$2" k v\n  for k in $3; do\n'
     '    printf \'%s_%s=%s\\n\' "$k" "$s" "$v"\n  done\n}\n'
     'strip_run() { sed -E \'s/_(r1|r2)=/=/g\' "$1"; }\ngrab f r1 "dr_x"\n', None, 0),
    ("без strip_run метка остаётся в имени - сирота", "dr_x",
     '# do not touch\ngrab() {\n  local s="$2" k v\n  for k in $3; do\n'
     '    printf \'%s_%s=%s\\n\' "$k" "$s" "$v"\n  done\n}\ngrab f r1 "dr_x"\n', None, 1),
    # `E-0140`, форма (4): имя собирается из чужого файла перепечаткой (`printf "$k"`), набор
    # отбирает `grep -E '^PREFIX_(A|B)='`, часть имён переименована присваиванием.
    ("имя отобрано регуляркой grep и перепечатано - пропуск", "OLD_B",
     'grep -E \'^OLD_(A|B)=\' f |\n  while IFS== read -r k v; do\n'
     '    printf \'%s=%s\\n\' "$k" "$v" >>"$buf"\n  done\n', None, 0),
    ("имя назначено перед перепечаткой - пропуск", "NEW_NAME",
     'grep -E \'^OLD_(A|B)=\' f |\n  while IFS== read -r k v; do\n'
     '    [ "$k" = "OLD_A" ] && k=NEW_NAME\n'
     '    printf \'%s=%s\\n\' "$k" "$v" >>"$buf"\n  done\n', None, 0),
    ("ни grep, ни присваивание не дают это имя - сирота", "OLD_C",
     'grep -E \'^OLD_(A|B)=\' f |\n  while IFS== read -r k v; do\n'
     '    printf \'%s=%s\\n\' "$k" "$v" >>"$buf"\n  done\n', None, 1),
    # `E-0140`, форма (5): прибор приписывает приставку всем своим фактам при сбросе буфера.
    ("тег приставки при сбросе буфера - пропуск", "PRE_FIX_OTHER",
     'emit() { printf \'%s\\n\' "$1" >>"$buf"; }\n# --tag PRE_FIX_\nemit OTHER 1\n'
     'if [ -n "$TAG" ]; then sed "s/^/${TAG}/" "$buf"; fi\n', None, 0),
    ("тег не выдумывает ненапечатанное имя - сирота", "PRE_FIX_NOPE",
     'emit() { printf \'%s\\n\' "$1" >>"$buf"; }\n# --tag PRE_FIX_\nemit OTHER 1\n'
     'if [ -n "$TAG" ]; then sed "s/^/${TAG}/" "$buf"; fi\n', None, 1),
]

def closed_cycles(root):
    """Номера закрытых E-карточек — только их носители имеют право закрывать имя ключа.

    Словарь статуса не один: карточки разных эр пишут `closed`, `completed` и `done` (тот же урок,
    что и сводка `E-0138`, где 127 закрытых карточек имели 73 метки). Живой цикл обязан печатать
    факт деревом: ссылка на собственный лог означала бы «факт напечатан, потому что мы его уже
    видели», и проверка переставала бы быть проверкой (правило круга `E-0139`).
    """
    statuses = ("closed", "completed", "done")
    out = set()
    for p in glob.glob(os.path.join(root, "lab", "experiments", "E-*.md")):
        try:
            head = open(p, encoding="utf-8", errors="replace").read(4000)
        except OSError:
            continue
        m = re.search(r"^status:\s*([A-Za-z_]+)", head, re.M)
        if m and m.group(1).lower() in statuses:
            n = re.search(r"E-(\d+)", os.path.basename(p))
            if n:
                out.add("e" + n.group(1))
    return out


def corpus_index(texts):
    """Индекс того, что дерево печатает, за один проход вместо тысячи регулярных поисков.

    Слева у имени — начало строки, пробел или кавычка (в том числе `\\n`-escape в литерале Rust),
    справа — обязательный непробел после `=`. Это ровно то же условие, что у `key_pattern`, и
    самопроверка круга сверяет индекс с медленным путём на всех таблицах: ускорение не имеет права
    менять вердикт ни на одном ключе.
    """
    corpus = "\n".join(texts)
    flat = "".join(corpus.split())
    lit = set(re.findall(r'(?:^|[\s"\']|\\[nrt])(' + _ID + r')\s*=\s*\S', corpus, re.M))
    emitted = set(re.findall(r'\bemit\s+["\']?(' + _ID + r')\b', corpus))
    facts = set(re.findall(r'emit_fact\("(' + _ID + r')"', flat))
    templates = set(re.findall(r'"(' + _ID + r')_\{', corpus))
    return {"corpus": corpus, "lit": lit, "emit": emitted, "fact": facts, "tpl": templates}



def classify(key, names, carrier):
    """Чем закрыт ключ: печать дерева одним из классов — или ничем.

    Индекс (`corpus_index`) отвечает за одиночные имена; ключ из двух токенов — это сводная строка,
    для него остаётся медленный регэксп. Склейка, перепечатка и тег приходят из `tree_names`, а
    носитель закрывает имя только у закрытого цикла.
    """
    idx = names["idx"]
    if " " in key:
        if key_pattern(key).search(idx["corpus"]):
            return "ЛИТЕРАЛОМ"
        if emit_pattern(key).search(idx["corpus"]):
            return "ВОРОНКОЙ"
    else:
        if key in idx["lit"]:
            return "ЛИТЕРАЛОМ"
        if key in idx["emit"]:
            return "ВОРОНКОЙ"
        if key in idx["fact"]:
            return "RUST-ВОРОНКОЙ"
        m = re.match(r"^(.*)_\d+$", key)
        if m and m.group(1) in idx["tpl"]:
            return "ШАБЛОНОМ"
    if key in names["loop"]:
        return "ЦИКЛОМ"
    if key in names["spliced"]:
        return "СКЛЕЙКОЙ"
    if key in names["reprint"]:
        return "ПЕРЕПЕЧАТКОЙ"
    if key in names["tag"]:
        return "ТЕГОМ"
    if key in carrier:
        return "НОСИТЕЛЕМ"
    return "СИРОТОЙ"


def classify_slow(key, corpus, names, carrier):
    """Прежний путь: регэксп по всему корпусу на каждый ключ — эталон, с которым сверяется индекс."""
    if key_pattern(key).search(corpus):
        return "ЛИТЕРАЛОМ"
    if emit_pattern(key).search(corpus):
        return "ВОРОНКОЙ"
    if ("emit_fact(" + chr(34) + key + chr(34)) in "".join(corpus.split()):
        return "RUST-ВОРОНКОЙ"
    dyn = dynamic_pattern(key)
    if dyn is not None and dyn.search(corpus):
        return "ШАБЛОНОМ"
    if key in names["loop"]:
        return "ЦИКЛОМ"
    if key in names["spliced"]:
        return "СКЛЕЙКОЙ"
    if key in names["reprint"]:
        return "ПЕРЕПЕЧАТКОЙ"
    if key in names["tag"]:
        return "ТЕГОМ"
    if key in carrier:
        return "НОСИТЕЛЕМ"
    return "СИРОТОЙ"




def sweep(root, source_paths, verbose=False):
    """Сведение по всем таблицам ожиданий закрытых циклов — один прочитанный корпус на всех.

    Корпус читается один раз, и класс одиночного имени определяется множествами индекса. Чтобы
    ускорение не могло молча поменять вердикт, каждый ключ, закрытый не литералом (редкие кланы —
    именно там индекс вправе разойтись с регэкспом), плюс каждый 97-й сверяются с медленным путём;
    число расхождений печатается и обязано быть нулём.
    """
    tables = sorted(glob.glob(os.path.join(root, "lab", "expectations", "*.tsv")))
    texts = read_blobs(gather_sources(source_paths))
    names = tree_names(texts)
    corpus = names["idx"]["corpus"]
    closed = closed_cycles(root)
    # Таблица открытого цикла в свод не входит: её пороги ещё не заморожены, и судить о них рано
    # (своя таблица этого круга — первый такой случай). Закрытость — единственное условие отбора,
    # поэтому `СВЕД_ТАБЛИЦ` и `СВЕД_ЗАКРЫТЫХ` обязаны совпасть.
    tables = [t for t in tables if os.path.basename(t)[:-4] in closed]
    forms = {k: 0 for k in FORM_KEYS}
    total_keys = 0
    bad = 0
    bad_tables = 0
    carrier_files = 0
    checked = 0
    diverged = 0
    for tsv in tables:
        cycle = os.path.basename(tsv)[:-4]
        cpaths = []
        if cycle in closed:
            cpaths = sorted(glob.glob(os.path.join(root, "lab", "logs", cycle + "-*.log")))
        carrier_files += len(cpaths)
        carrier = carrier_names(cpaths)
        counts = {k: 0 for k in FORM_KEYS}
        local_bad = 0
        keys = load_keys(tsv)
        for n, key in enumerate(keys):
            form = classify(key, names, carrier)
            if form != "ЛИТЕРАЛОМ" or n % 97 == 0:
                checked += 1
                slow = classify_slow(key, corpus, names, carrier)
                if slow != form:
                    diverged += 1
                    print(f"ИНДЕКС НЕ ВЕРЕН: {cycle} {key} — индекс `{form}`, эталон `{slow}`")
            if form == "СИРОТОЙ":
                local_bad += 1
                bad += 1
                print(f"ПОРОГ БЕЗ ПРИБОРА: {cycle} {key} — ни дерево, ни носитель цикла")
            else:
                counts[form] += 1
                forms[form] += 1
        total_keys += len(keys)
        if local_bad:
            bad_tables += 1
        if verbose:
            print("ТАБЛИЦА=%s ЗАКРЫТА=%s ПОРОГОВ=%d СИРОТ=%d %s" % (
                cycle, "да" if cycle in closed else "нет", len(keys),
                local_bad, " ".join("%s=%s" % (k, counts[k] or "none") for k in FORM_KEYS)))
    print("СВЕД_ТАБЛИЦ=%d" % len(tables))
    print("СВЕД_ЗАКРЫТЫХ=%d" % len([t for t in tables
                                    if os.path.basename(t)[:-4] in closed]))
    print("СВЕД_ПОРОГОВ=%d" % total_keys)
    print("СВЕД_ИСТОЧНИКОВ=%d" % len(texts))
    print("СВЕД_НОСИТЕЛЕЙ=%d" % carrier_files)
    for form in FORM_KEYS:
        print("СВЕД_ФОРМА_%s=%s" % (form, forms[form] or "none"))
    print("СВЕД_СИРОТ=%d" % bad)
    print("СВЕД_ТАБЛИЦ_С_СИРОТАМИ=%d" % bad_tables)
    print("СВЕД_ПРОВЕРЕНО_ЭТАЛОНОМ=%d" % checked)
    print("СВЕД_РАСХОЖДЕНИЙ_ИНДЕКСА=%d" % diverged)
    return 0 if bad == 0 and diverged == 0 else 1


def cmd_selftest():
    import tempfile

    bad = 0
    for name, key, src, cmp_line, want in CASES:
        d = tempfile.mkdtemp(prefix="threshold-lint-")
        exp = os.path.join(d, "e.tsv")
        with open(exp, "w", encoding="utf-8") as fh:
            fh.write(key + "\t1\t" + "ключ " + key + "\n")
        srcf = os.path.join(d, "instr.rs")
        with open(srcf, "w", encoding="utf-8") as fh:
            fh.write(src)
        helper = os.path.join(d, "run.sh")
        with open(helper, "w", encoding="utf-8") as fh:
            fh.write((cmp_line + " && echo same\n") if cmp_line else "true\n")
        rc = lint(exp, helper, [srcf])
        if rc != want:
            bad += 1
            print(f"СЕЛФТЕСТ ПРОВАЛ: {name}: ждали rc={want}, получили {rc}")
        else:
            print(f"СЕЛФТЕСТ ok: {name}")
    print(f"THRESHOLD_LINT_SELFTEST total={len(CASES)} passed={len(CASES) - bad}")
    return 0 if bad == 0 else 1


def latest_cycle(root):
    """Самый свежий номер E-карточки: его пороги и линтуются на закрытии цикла.

    Пути берутся из текста карточки, а не угадываются: карточка — единственное место, где
    заморожены и таблица ожиданий, и helper.
    """
    cards = glob.glob(os.path.join(root, "lab", "experiments", "E-*.md"))

    def num(p):
        m = re.search(r"E-(\d+)", os.path.basename(p))
        return int(m.group(1)) if m else -1

    if not cards:
        return None, None, None
    card = max(cards, key=num)
    text = open(card, encoding="utf-8", errors="replace").read()
    exp = re.search(r"lab/expectations/[A-Za-z0-9_.\-]+\.tsv", text)
    helper = re.search(r"lab/[A-Za-z0-9_.\-]+-run\.sh", text)
    return (os.path.basename(card)[:6],
            os.path.join(root, exp.group(0)) if exp else None,
            os.path.join(root, helper.group(0)) if helper else None)


def cmd_latest():
    root = os.path.dirname(HERE)
    eid, exp, helper = latest_cycle(root)
    if exp is None or not os.path.isfile(exp):
        print("ЛИНТ_ПРОПУЩЕН: в самой свежей карточке нет таблицы ожиданий")
        return 2
    print(f"ЦИКЛ={eid} ТАБЛИЦА={os.path.relpath(exp, root)} "
          f"HELPER={os.path.relpath(helper, root) if helper else 'не назван'}")
    return lint(exp, helper, [os.path.join(root, "crates"), os.path.join(root, "benches"),
                              os.path.join(root, "lab")])


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    if "--selftest" in argv[1:]:
        return cmd_selftest()
    if "--sweep" in argv[1:]:
        root = os.path.dirname(HERE)
        t0 = time.time()
        rc = sweep(root, [os.path.join(root, "crates"), os.path.join(root, "benches"),
                          os.path.join(root, "lab")],
                   verbose="--verbose" in argv[1:])
        print("СВЕД_ЦЕНА_C=%d" % round(time.time() - t0))
        return rc
    if "--latest" in argv[1:]:
        return cmd_latest()
    if not argv[1:]:
        print(__doc__.strip().splitlines()[5])
        return 2
    expect_path, helper, sources = argv[1], None, []
    rest = argv[2:]
    i = 0
    while i < len(rest):
        if rest[i] == "--helper":
            helper = rest[i + 1]
            i += 2
        elif rest[i] == "--sources":
            i += 1
            sources.extend(rest[i:])
            break
        else:
            sources.append(rest[i])
            i += 1
    if not os.path.isfile(expect_path):
        print(f"нет таблицы ожиданий {expect_path}")
        return 2
    return lint(expect_path, helper, sources)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
