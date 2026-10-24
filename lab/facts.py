#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Вектор фактов прогона: извлечение и сверка без меток прогона.

Зачем отдельный прибор, а не `grep` в каждом helper'е: трижды за историю лаборатории
сравнение векторов ломалось не на факте, а на форме записи — метка прогона в имени ключа
(`E-0088`, `E-0100`), знак числа (`E-0084`), префикс libtest перед первым `println!`.
Поэтому разбор `key=value` живёт в одном месте и проверяется посаженными случаями.

Употребление:
    python lab/facts.py extract ФАЙЛ... [--strip-run]     — KEY=VALUE по возрастанию ключа
    python lab/facts.py repro ФАЙЛ1 ФАЙЛ2 [--strip-run]   — REPRO_VECTOR=1|0 и расхождения
    python lab/facts.py selftest                          — посаженные случаи обязаны отбиваться

Правила разбора (те же, что у `lab/expect.py`, чтобы приборы не расходились):
* ключ стоит в начале строки или после пробела — `PRE_FIX_KEY=1` не является фактом `KEY=1`;
* после значения нет буквы/цифры/подчёркивания — `N=93` не удовлетворяет `N=9`;
* из повторов ключа побеждает ПОСЛЕДНИЙ: append-only лог и `tail -1` — одна конвенция;
* значение — один токен без пробелов (`-5`, `1`, `совпал`, `0x1f`).
"""

import re
import sys

LEFT = r"(?:(?<=^)|(?<=\s))"
FACT = re.compile(LEFT + r"([A-Za-z_][A-Za-z0-9_.\-]*)=(\S+)", re.MULTILINE)
RUN_LABEL = re.compile(r"_(r\d+)$")


def extract(text, strip_run=False):
    """Словарь key -> value; последний печатный факт побеждает."""
    out = {}
    for m in FACT.finditer(text):
        key, val = m.group(1), m.group(2)
        if strip_run:
            key = RUN_LABEL.sub("", key)
        out[key] = val
    return out


def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def cmd_extract(args):
    strip = "--strip-run" in args
    paths = [a for a in args if a != "--strip-run"]
    if not paths:
        print("нужен хотя бы один файл фактов", file=sys.stderr)
        return 2
    facts = {}
    for p in paths:
        facts.update(extract(read(p), strip))
    for k in sorted(facts):
        print(f"{k}={facts[k]}")
    return 0


def cmd_repro(args):
    strip = "--strip-run" in args
    paths = [a for a in args if a != "--strip-run"]
    if len(paths) != 2:
        print("repro ждёт ровно два файла фактов", file=sys.stderr)
        return 2
    a, b = extract(read(paths[0]), strip), extract(read(paths[1]), strip)
    if not a or not b:
        print("РЕПРО: один из файлов не содержит ни одного факта — молчание не вектор")
        print("REPRO_VECTOR=0")
        return 1
    diffs = [(k, a.get(k), b.get(k)) for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    for k, x, y in diffs:
        print(f"РАСХОЖДЕНИЕ: {k} n1={x if x is not None else 'нет ключа'} "
              f"n2={y if y is not None else 'нет ключа'}")
    print(f"КЛЮЧЕЙ={len(set(a) | set(b))} РАСХОЖДЕНИЙ={len(diffs)}")
    print(f"REPRO_VECTOR={1 if not diffs else 0}")
    return 0 if not diffs else 1


CASES = [
    # (имя, текст n1, текст n2, strip, ожидаемый REPRO_VECTOR)
    ("метки прогона без strip — расхождение", "A_r1=1\n", "A_r2=1\n", False, 0),
    ("метки прогона со strip — совпадение", "A_r1=1\n", "A_r2=1\n", True, 1),
    ("префикс libtest перед первым println", "test foo ... ok\nA=1 B=2\n", "A=1 B=2\n", False, 1),
    ("знак числа не теряется", "D=-5\n", "D=5\n", False, 0),
    ("дробное значение", "P=4377\n", "P=4377\n", False, 1),
    ("чужой ключ не подменяет", "PRE_FIX_A=9\n", "A=1\n", False, 0),
    ("граница цифры", "N=93\n", "N=9\n", False, 0),
    ("повтор ключа — побеждает последний", "A=1\nA=2\n", "A=2\n", False, 1),
    ("ключ есть только в n2", "A=1\n", "A=1\nB=2\n", False, 0),
    ("пустой файл — не вектор", "", "A=1\n", False, 0),
]


def cmd_selftest(_args):
    import os
    import tempfile

    bad = 0
    for name, t1, t2, strip, want in CASES:
        p1 = os.path.join(tempfile.gettempdir(), "facts-selftest-1.txt")
        p2 = os.path.join(tempfile.gettempdir(), "facts-selftest-2.txt")
        with open(p1, "w", encoding="utf-8") as fh:
            fh.write(t1)
        with open(p2, "w", encoding="utf-8") as fh:
            fh.write(t2)
        got = extract(t1, strip) == extract(t2, strip)
        if bool(got) != bool(want):
            bad += 1
            print(f"СЕЛФТЕСТ ПРОВАЛ: {name}: ждали {want}, посчитали {int(got)}")
        else:
            print(f"СЕЛФТЕСТ ok: {name}")
    print(f"FACTS_SELFTEST total={len(CASES)} passed={len(CASES) - bad}")
    return 0 if bad == 0 else 1


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[4])
        return 2
    cmd, rest = argv[1], argv[2:]
    if cmd == "extract":
        return cmd_extract(rest)
    if cmd == "repro":
        return cmd_repro(rest)
    if cmd == "selftest":
        return cmd_selftest(rest)
    print(f"неизвестная команда {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
