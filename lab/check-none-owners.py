#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Страж двух владельцев слова `none` в таблицах ожиданий (`H-0158`).

Замороженная строка `КЛЮЧ <TAB> none` сегодня может быть удовлетворена двумя разными событиями:
прибор осознанно напечатал пустое множество (`CHK_IDS=none`) — или носитель не нашёл строку
прибора и сам напечатал литерал `none` через `grab()`/`sv()`/`${X:-none}`. Во втором случае
молчание прибора становится зелёным фактом, и таблица этого не различает.

Правило для новых таблиц: если таблица содержит значение `none`, её носитель не имеет права
превращать отсутствие в `none`. Отсутствие называется другим словом (`НЕ_НАПЕЧАТАН`), и тогда
`none` остаётся единственным владельцем — печатным пустым множеством. Исторические таблицы
заморожены и не переписываются; их носители названы реестром `lab/none-owners-baseline.tsv`
с причиной. Реестр обязан называть ровно те таблицы, которые нарушают правило: лишняя строка —
`STALE`, пустая причина — `EMPTY_REASON`, повтор — `DUP`.

Употребление:
    python lab/check-none-owners.py [--root КАТАЛОГ]
    python lab/check-none-owners.py --selftest

Коды: 0 — расхождений нет; 1 — есть находки или дефекты реестра; 2 — мерить нечего (нет таблиц
или корень вне git — контекст прогона не принимается за предмет проверки).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

DEFAULT_BASELINE = "lab/none-owners-baseline.tsv"
TABLE_RE = re.compile(r"^e\d{4}\.tsv$")
# Формы, в которых отсутствие превращается в литерал `none`.
ABSENCE_NONE = re.compile(r"\|\|\s*(?:echo|printf)\s+['\"]?none(?![0-9A-Za-z_])|:-\s*none(?![0-9A-Za-z_])")


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def expectations_dir(root):
    return os.path.join(root, "lab", "expectations")


def list_tables(root):
    d = expectations_dir(root)
    try:
        names = sorted(n for n in os.listdir(d) if TABLE_RE.match(n))
    except OSError:
        return []
    return names


def none_rows(path):
    """Строки таблицы, у которых значение ровно `none` (не `none:0` и не упоминание в комментарии)."""
    text = read_text(path)
    if text is None:
        return 0
    n = 0
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1].strip() == "none":
            n += 1
    return n


def carrier_path(root, table):
    return os.path.join(root, "lab", table[:-4] + "-run.sh")


def sentinel_lines(root, table):
    """Строки носителя, где отсутствие печатается словом `none`; комментарии не считаются."""
    path = carrier_path(root, table)
    text = read_text(path)
    if text is None:
        return None
    hits = []
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if line.lstrip().startswith("#"):
            continue
        if ABSENCE_NONE.search(line):
            hits.append((no, line.strip()))
    return hits


def short(table):
    return os.path.basename(table.strip())


def read_baseline(root):
    """Строки реестра и дефекты формы. Реестр — `путь_таблицы <TAB> причина`."""
    path = os.path.join(root, DEFAULT_BASELINE)
    text = read_text(path)
    rows = []
    defects = []
    if text is None:
        return rows, defects
    seen = set()
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        table = parts[0].strip()
        reason = parts[1].strip() if len(parts) > 1 else ""
        if table in seen:
            defects.append(f"{short(table)}:DUP")
        seen.add(table)
        if not reason:
            defects.append(f"{short(table)}:EMPTY_REASON")
        rows.append((table, reason))
    return rows, defects


def judge(root):
    """Вердикт без git: код и строки фактов. Годится и для самопроверки на синтетических корнях."""
    tables = list_tables(root)
    if not tables:
        return 2, ["NO_TABLES=0", "NO_NONE_ROWS=0", "NO_TABLES_WITH_NONE=0",
                   "NO_SENTINEL_TABLES=0", "NO_BASELINE_ROWS=0", "NO_BASELINE_DEFECTS=none",
                   "NO_FINDINGS=0", "NO_FINDING_TABLES=none", "NO_ROOT_KIND=no-tables"]

    rows_by = {}
    for t in tables:
        rows_by[t] = none_rows(os.path.join(expectations_dir(root), t))

    baseline, defects = read_baseline(root)
    baselined = {os.path.basename(parts[0].strip()) for parts in baseline}

    findings = []       # (имя, класс, пояснение)
    sentinel_tables = []
    with_none = [t for t in tables if rows_by[t] > 0]
    for t in with_none:
        hits = sentinel_lines(root, t)
        if hits is None:
            findings.append((t, "NO_CARRIER", "таблица ожидает none, а носителя нет"))
            continue
        if not hits:
            continue
        sentinel_tables.append(t)
        if t in baselined:
            continue
        no, line = hits[0]
        findings.append((t, "SENTINEL_FORM", f"строка {no}: {line[:120]}"))

    # Реестр обязан быть ровно списком нарушителей: лишняя строка — мёртвая.
    for table, _reason in baseline:
        name = os.path.basename(table.strip())
        if name not in tables:
            defects.append(f"{name}:STALE")
            continue
        if rows_by.get(name, 0) == 0:
            defects.append(f"{name}:STALE")
            continue
        hits = sentinel_lines(root, name)
        if hits is None:
            defects.append(f"{name}:STALE")
        elif not hits:
            defects.append(f"{name}:STALE")

    for d in defects:
        findings.append((d.split(":")[0], d.split(":")[1], "реестр исключений"))

    out = [
        f"NO_BASELINE={DEFAULT_BASELINE}",
        f"NO_TABLES={len(tables)}",
        f"NO_NONE_ROWS={sum(rows_by.values())}",
        f"NO_TABLES_WITH_NONE={len(with_none)}",
        f"NO_SENTINEL_TABLES={len(sentinel_tables)}",
        f"NO_BASELINE_ROWS={len(baseline)}",
        f"NO_BASELINE_DEFECTS={','.join(defects) if defects else 'none'}",
        f"NO_FINDINGS={len(findings)}",
    ]
    names = [f"{f[0]}:{f[1]}" for f in findings]
    out.append(f"NO_FINDING_TABLES={','.join(names) if names else 'none'}")
    for i, (name, klass, detail) in enumerate(findings, 1):
        out.append(f"NO_FINDING_{i}={name}:{klass}")
        print(f"НАХОДКА {name}:{klass} — {detail}")
    return (0 if not findings else 1), out


def root_refusal(root):
    if not os.path.isdir(root):
        return "no-root"
    if not list_tables(root):
        return "no-tables"
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=root,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return "no-git"
    if r.returncode != 0:
        return "no-git"
    return ""


def parse_root(argv):
    root = "."
    i = 1
    while i < len(argv):
        if argv[i] == "--root" and i + 1 < len(argv):
            root = argv[i + 1]
            i += 2
        else:
            i += 1
    return root


def fixture(d, table, carrier, baseline=None, value="none"):
    os.makedirs(os.path.join(d, "lab", "expectations"), exist_ok=True)
    with open(os.path.join(d, "lab", "expectations", table), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"КЛЮЧ\t{value}\tпустое множество\n")
    if carrier is not None:
        with open(os.path.join(d, "lab", table[:-4] + "-run.sh"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(carrier)
    if baseline is not None:
        with open(os.path.join(d, DEFAULT_BASELINE), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(baseline)


def selftest():
    cases = []

    def case(name, table, carrier, baseline, want_rc, want_findings, want_defects=None, value="none"):
        cases.append((name, table, carrier, baseline, want_rc, want_findings, want_defects, value))

    old_grab = "grab() { v=$(grep KEY \"$1\"); [ -n \"$v\" ] && echo \"$v\" || echo none; }\nemit X \"$(grab log X)\"\n"
    new_grab = "grab() { v=$(grep KEY \"$1\"); [ -n \"$v\" ] && echo \"$v\" || echo НЕ_НАПЕЧАТАН; }\nemit X \"$(grab log X)\"\n"
    case("старый grab краснит", "e9001.tsv", old_grab, None, 1, 1)
    case("новое слово отсутствия зелёное", "e9001.tsv", new_grab, None, 0, 0)
    case("носителя нет — находка", "e9001.tsv", None, None, 1, 1)
    case("таблица без none не смотрится", "e9002.tsv", old_grab, None, 0, 0, value="0")
    case("историческая строка названа реестром", "e9001.tsv", old_grab,
         "lab/expectations/e9001.tsv\tисторическая таблица\n", 0, 0)
    case("пустая причина — дефект", "e9001.tsv", old_grab,
         "lab/expectations/e9001.tsv\t\n", 1, 1, "e9001.tsv:EMPTY_REASON")
    case("мёртвая строка реестра — дефект", "e9001.tsv", old_grab,
         "lab/expectations/e9001.tsv\tисторическая таблица\nlab/expectations/e9999.tsv\tнет такой таблицы\n", 1, 1, "e9999.tsv:STALE")
    case("форма ${X:-none}", "e9001.tsv", "v=${X:-none}\nemit X \"$v\"\n", None, 1, 1)
    case("реестр для чистой таблицы — STALE", "e9001.tsv", new_grab,
         "lab/expectations/e9001.tsv\tлишняя строка\n", 1, 1, "e9001.tsv:STALE")

    bad = 0
    for name, table, carrier, baseline, want_rc, want_findings, want_defects, value in cases:
        d = tempfile.mkdtemp(prefix="none-owners-")
        try:
            fixture(d, table, carrier, baseline, value)
            rc, lines = judge(d)
            facts = {}
            for line in lines:
                if "=" in line:
                    k, v = line.split("=", 1)
                    facts[k] = v
            ok = rc == want_rc and facts.get("NO_FINDINGS") == str(want_findings)
            if want_defects is not None:
                ok = ok and want_defects in facts.get("NO_BASELINE_DEFECTS", "")
            if ok:
                print(f"СЕЛФТЕСТ ok: {name}")
            else:
                bad += 1
                print(f"СЕЛФТЕСТ ПРОВАЛ: {name}: rc={rc} findings={facts.get('NO_FINDINGS')} "
                      f"defects={facts.get('NO_BASELINE_DEFECTS')}")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # Отказ вне дерева: пустой корень не принимается за таблицу без нарушений.
    d = tempfile.mkdtemp(prefix="none-owners-empty-")
    try:
        kind = root_refusal(d)
        if kind == "no-tables":
            print("СЕЛФТЕСТ ok: пустой корень — отказ")
        else:
            bad += 1
            print(f"СЕЛФТЕСТ ПРОВАЛ: пустой корень: kind={kind!r}")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    total = len(cases) + 1
    passed = total - bad
    print(f"NO_SELFTEST_CASES={total}")
    print(f"NO_SELFTEST_PASSED={passed}")
    print(f"NO_SELFTEST_FAILED={bad}")
    print(f"NO_SELFTEST total={total} passed={passed} failed={bad}")
    return 0 if bad == 0 else 1


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    if len(argv) > 1 and argv[1] == "--selftest":
        return selftest()
    root = parse_root(argv)
    refusal = root_refusal(root)
    if refusal:
        print(f"NO_ROOT_KIND={refusal}")
        print("NO_FINDINGS=0")
        return 2
    rc, lines = judge(root)
    for line in lines:
        print(line)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
