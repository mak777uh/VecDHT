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
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEFT = r"(?:(?<=^)|(?<=\s))"


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


def loop_emitted(text):
    """Имена, которые helper печатает циклом: `for k in A B C; do emit "LIVE_$k"`.

    Починка `E-0135` научила линт литеральной воронке `emit KEY`, но helper'ы печатают
    семейства списком имён и одним `emit` с переменной. До этого цикла такие ключи объявлялись
    сиротами, хотя печатались: на живой таблице `E-0138` линт дал 29 ложных сирот, а на уже
    опубликованной `E-0132` даёт 11. Правило остаётся литеральным с обеих сторон: имя обязано
    стоять в списке `for … in …`, а префикс — буквально предшествовать `$` в воронке `emit`;
    «префикс + что угодно» и `emit "$k"` без списка имён по-прежнему сироты.
    """
    flat = text.replace("\\\n", "")
    lists: dict[str, set] = {}
    for m in re.finditer(r"\bfor\s+(\w+)\s+in\s+([^;{]*?)(?:;|\bdo\b)", flat):
        lists.setdefault(m.group(1), set()).update(m.group(2).split())
    names: set[str] = set()
    for m in re.finditer(r'\bemit\s*"([A-Za-z0-9_]*)\$\{?(\w+)\}?[^"]*"', flat):
        for n in lists.get(m.group(2), ()):
            names.add(m.group(1) + n)
    return names


def dynamic_pattern(key):
    """Ключ, который прибор печатает шаблоном: `NODE_SLOT_ATTR_{}` для owner 101.

    Прибор вправе печатать семейство фактов циклом, но тогда имя обязано быть
    «префикс + _{» буквально в источнике — иначе это не шаблон, а догадка линта.
    """
    m = re.match(r"^(.*)_\d+$", key)
    if not m:
        return None
    return re.compile(r'"' + re.escape(m.group(1)) + r"_\{")
def lint(expect_path, helper, source_paths):
    keys = load_keys(expect_path)
    files = gather_sources(source_paths)
    if helper:
        files.append(helper)
    blobs = []
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                blobs.append((f, fh.read()))
        except OSError:
            continue
    corpus = "\n".join(t for _, t in blobs)
    families: set[str] = set()
    for _, text in blobs:
        families |= loop_emitted(text)
    bad = 0
    cyc = 0
    if not keys:
        print("ПОРОГ БЕЗ ПРИБОРА: таблица ожиданий пуста")
        return 1
    for key in keys:
        if key_pattern(key).search(corpus):
            continue
        if emit_pattern(key).search(corpus):
            continue
        # Rust-воронка `emit_fact("KEY", value)` — печать факта из теста-пробы: литерал ключа
        # ищется как `emit_fact("` + ключ + `"`), поэтому чужой ключ не засчитывается.
        # Пробел свёрнут: rustfmt переносит литерал на новую строку, и проверка по исходному
        # тексту объявляла бы такие факты сиротами.
        flat = "".join(corpus.split())
        if ("emit_fact(" + chr(34) + key + chr(34)) in flat:
            continue
        dyn = dynamic_pattern(key)
        if dyn is not None and dyn.search(corpus):
            print(f"ПОРОГ ДИНАМИЧЕСКИЙ: {key} — печатается шаблоном семейства")
            continue
        if key in families:
            cyc += 1
            continue
        bad += 1
        print(f"ПОРОГ БЕЗ ПРИБОРА: {key} — ни один источник не печатает этот факт")
    # Сравнение файлов фактов без снятия метки прогона: `cmp -s "$F1" "$F2"` — невыполнимый порог.
    if helper and os.path.isfile(helper):
        for n, line in enumerate(open(helper, encoding="utf-8", errors="replace"), 1):
            if re.search(r"\bcmp\s+-s?\b", line) and "strip_run" not in line \
                    and "facts.py" not in line and "factlib" not in line:
                bad += 1
                print(f"ПОРОГ НЕВЫПОЛНИМ: {helper}:{n} сравнивает файлы без снятия метки "
                      f"прогона: {line.strip()}")
    print(f"ПОРОГОВ={len(keys)} ИСТОЧНИКОВ={len(blobs)} ЦИКЛОМ={cyc} СИРОТ={bad}")
    return 0 if bad == 0 else 1


CASES = [
    ("rust-воронка emit_fact узнаётся", 'fn t() { emit_fact("A", 1); }', "A", "1", True),
    # (имя, ключ таблицы, текст источника, строка cmp в helper или None, ожидаемый rc)
    ("ключ напечатан — пропуск", "A", "A=1\n", None, 0),
    ("ключа нет — сирота", "A", "B=1\n", None, 1),
    ("ключ только префиксом чужого — сирота", "A", "PRE_FIX_A=1\n", None, 1),
    ("cmp с метками прогона — невыполним", "A", "A=1\n", 'cmp -s "$F1" "$F2"', 1),
    ("cmp через strip_run — выполним", "A", "A=1\n", 'cmp -s <(strip_run "$F1") <(strip_run "$F2")', 0),
    ("шаблон семейства — динамический порог", "S_101", 'println!("S_{}={}", 101, 1);\n', None, 0),
    ("шаблон чужого префикса — сирота", "S_101", 'println!("Q_{}={}", 101, 1);\n', None, 1),
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
]


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
