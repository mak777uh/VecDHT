#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Сверка печатных фактов прогона с таблицей ожиданий, замороженной до пре-регистрации.

Употребление:
    python lab/expect.py lab/expectations/e0093.tsv факты.txt [ещё_факты.txt ...]

Формат таблицы — TSV: `ключ <TAB> ожидание [<TAB> человекочитаемый комментарий]`. Пустые строки и
строки, начинающиеся с `#`, пропускаются. Ключ — это имя печатного факта без `=` (внутри допускаются
пробелы, чтобы задать второй ключ сводной строки: `LEANGUARD_SELFTEST passed`).

Правила поиска сделаны специально под то, чтобы сверка не могла пройти случайно:

* совпадение ищется только там, где ключ стоит в начале строки или после пробела — иначе ожидание
  `LEAN_ALL_OK=1` было бы выполнено строкой `PRE_FIX_axiom_LEAN_ALL_OK=1`, то есть доказательством
  слепоты прежнего прибора;
* значение обязано граничить с не-словом справа — иначе `NATIVE_AXIOMS=9` считалось бы выполненным
  строкой `NATIVE_AXIOMS=93`;
* ключа нет в фактах = расхождение (молчание прогона не считается успехом);
* выход 0 только когда расхождений ноль; 2 — если нечем сверять (нет таблицы или нет фактов).
"""

import os
import re
import sys


def load_expectations(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                raise SystemExit(f"ОЖИДАНИЙ_ПОВРЕЖДЁН: строка без табуляции: {line!r}")
            rows.append((parts[0].strip(), parts[1].strip()))
    return rows


LEFT = r"(?:(?<=^)|(?<=\s))"


def pattern(key, want):
    """Регэксп поиска факта.

    Ключ из одного токена ищется как отдельный токен (`(?<=^|\\s)` слева) — этого достаточно для
    `LEAN_ALL_OK`, `BROKEN`, `repro_вектор`.

    Ключ с пробелом означает «второй ключ сводной строки»: первый токен обязан начать строку, а
    второй искать в ней. Так `LEANGUARD_SELFTEST passed` не может быть удовлетворено чужой строкой,
    где просто написано `passed=`, и в то же время работает для печатного вида
    `LEANGUARD_SELFTEST total=10 passed=10`.
    """
    parts = key.split(" ")
    if len(parts) == 1:
        head = LEFT + re.escape(parts[0])
    else:
        head = r"^" + re.escape(parts[0]) + r"\b[^\n]*?" + LEFT + re.escape(parts[-1])
    tail = r"\s*=\s*" + (re.escape(want) + r"(?!\w)" if want is not None else r"(\S+)")
    return re.compile(head + tail, re.MULTILINE)


def find(key, want, corpus):
    return pattern(key, want).search(corpus) is not None


def printed_value(key, corpus):
    m = pattern(key, None).search(corpus)
    return m.group(1) if m else None


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    if len(argv) < 3:
        print(__doc__.strip().splitlines()[2])
        return 2
    exp_path, fact_paths = argv[1], argv[2:]
    if not os.path.isfile(exp_path):
        print(f"РАСХОЖДЕНИЙ=1 — нет таблицы ожиданий {exp_path}: сверкать не с чем")
        return 2
    corpus_parts = []
    for p in fact_paths:
        if not os.path.isfile(p):
            print(f"РАСХОЖДЕНИЙ=1 — нет файла фактов {p}: прогон их не напечатал")
            return 2
        with open(p, encoding="utf-8", errors="replace") as fh:
            corpus_parts.append(fh.read())
    corpus = "\n".join(corpus_parts)
    if not corpus.strip():
        print("РАСХОЖДЕНИЙ=1 — факты пусты: молчание прогона не считается успехом")
        return 2
    rows = load_expectations(exp_path)
    bad = 0
    for key, want in rows:
        if find(key, want, corpus):
            continue
        bad += 1
        got = printed_value(key, corpus)
        print(f"РАСХОЖДЕНИЕ: {key} ждали «{want}», напечатано «{got if got is not None else 'нет такого ключа'}»")
    print(f"ОЖИДАНИЙ={len(rows)} РАСХОЖДЕНИЙ={bad}")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
