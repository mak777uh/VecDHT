#!/usr/bin/env python3
"""Страж none-compare (H-0156): два литерала `none` не считаются равенством фактов.

Соглашение носителей `lab/e*-run.sh`: `grab` печатает непустое `none`, когда факта нет.
Тогда `[ -n "$v" ]` не отличает факт от молчания, а `[ "$a" = "$b" ]` при двух
молчаниях истинно: гейт зеленеет из двух отсутствий. Страж читает текст носителей,
восстанавливает множество переменных, способных нести литерал `none` (присваивание,
в правой части которого `grab`, `none`, `:-none` или другая такая переменная — до
неподвижной точки), и находит сравнения `[ "$A" = "$B" ]` / `!=`, где оба операнда
способны быть `none`. Защитой считается отказ `"$X" != none` хотя бы у одного
операнда в той же строке: тогда пара не может быть `none`-против-`none`. Сайт без
защиты — находка, пока не назван строкой реестра `lab/none-compare-baseline.tsv`
вида `lab/e0146-run.sh:80<TAB>причина` с непустой причиной; строка реестра без
сайта — дефект STALE (реестр не гниёт).

Факты: NC_ROOT_KIND, NC_CARRIERS, NC_COMPARISONS, NC_SENTINEL_PAIRS, NC_GUARDED,
NC_BASELINE, NC_BASELINE_ROWS, NC_BASELINE_DEFECTS, NC_BASELINE_DEFECT, NC_FINDING,
NC_FINDINGS; при самопроверке — NC_SELFTEST_CASE/CASES/PASSED/FAILED.
Код: 0 — чисто, 1 — находки или дефекты реестра, 2 — отказ вне корня с `lab/`.

Граница: прибор читает текст, а не исполняет носитель; защита в другой строке или
в другой ветке не видна, sentinel-способность — консервативная оценка присваиваний.
"""
import argparse
import glob
import os
import re
import shutil
import sys
import tempfile

CMP = re.compile(
    r'\[\s*"(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)"\s*(==?|!=)\s*"(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)"\s*\]'
)
ASSIGN = re.compile(r'^\s*(?:local\s+|export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$')
GUARD = re.compile(r'"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"\s*!=\s*["\']?none["\']?')
SENTINEL = re.compile(r'\bgrab\b|\bnone\b')
ROW_KEY = re.compile(r'^(lab/[^:\s]+):(\d+)$')
BASELINE_REL = os.path.join("lab", "none-compare-baseline.tsv")


def var_of(tok):
    return tok.strip('"').strip('${}')


def sentinel_vars(lines):
    """Переменные, способные нести литерал `none`, — неподвижная точка по присваиваниям."""
    known = set()
    changed = True
    while changed:
        changed = False
        for line in lines:
            m = ASSIGN.match(line)
            if not m:
                continue
            var, rhs = m.group(1), m.group(2)
            if var in known:
                continue
            if SENTINEL.search(rhs):
                known.add(var)
                changed = True
                continue
            for other in known:
                if re.search(r'\$\{?' + re.escape(other) + r'\b', rhs):
                    known.add(var)
                    changed = True
                    break
    return known


def scan_carrier(path, rel):
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    known = sentinel_vars(lines)
    comparisons, pairs, guarded, sites = 0, 0, 0, []
    for no, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        for m in CMP.finditer(line):
            a, b = var_of(m.group(1)), var_of(m.group(3))
            comparisons += 1
            if a not in known or b not in known:
                continue
            pairs += 1
            guards = set(GUARD.findall(line))
            key = "%s:%d" % (rel, no)
            if a in guards or b in guards:
                guarded += 1
                sites.append((key, True))
            else:
                sites.append((key, False))
    return comparisons, pairs, guarded, sites


def read_baseline(root):
    """Строки реестра и дефекты: EMPTY_REASON, BAD_FORMAT, DUP."""
    path = os.path.join(root, BASELINE_REL)
    if not os.path.isfile(path):
        return [], [], "absent"
    rows, defects, seen = [], [], set()
    for raw in open(path, encoding="utf-8", errors="replace").read().splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        parts = raw.split("\t")
        key = parts[0].strip()
        if not ROW_KEY.match(key):
            defects.append((key or raw.strip(), "BAD_FORMAT"))
            continue
        if key in seen:
            defects.append((key, "DUP"))
        seen.add(key)
        reason = "\t".join(parts[1:]).strip() if len(parts) > 1 else ""
        if not reason:
            defects.append((key, "EMPTY_REASON"))
            continue
        rows.append((key, reason))
    return rows, defects, ("ok" if not defects else "defects")


def judge(root):
    lab = os.path.join(root, "lab")
    if not os.path.isdir(lab):
        return 2, {"NC_ROOT_KIND": "not-lab", "NC_ROOT": root}
    files = sorted(glob.glob(os.path.join(lab, "e*-run.sh")))
    comparisons = pairs = guarded = 0
    all_sites = []
    for path in files:
        rel = "lab/" + os.path.basename(path)
        c, p, g, sites = scan_carrier(path, rel)
        comparisons += c
        pairs += p
        guarded += g
        all_sites.extend(sites)
    rows, defects, bstate = read_baseline(root)
    named = set(key for key, _ in rows)
    unguarded = [key for key, ok in all_sites if not ok]
    findings = [key for key in unguarded if key not in named]
    stale = [key for key, _ in rows if key not in set(unguarded)]
    for key in stale:
        defects.append((key, "STALE"))
    facts = {
        "NC_ROOT_KIND": "lab",
        "NC_CARRIERS": len(files),
        "NC_COMPARISONS": comparisons,
        "NC_SENTINEL_PAIRS": pairs,
        "NC_GUARDED": guarded,
        "NC_BASELINE": bstate if rows or defects or bstate != "absent" else "absent",
        "NC_BASELINE_ROWS": len(rows),
        "NC_BASELINE_DEFECTS": len(defects) if defects else "none",
    }
    for key, kind in defects:
        facts.setdefault("NC_BASELINE_DEFECT_LINES", []).append("%s:%s" % (key, kind))
    facts["NC_FINDINGS"] = len(findings)
    facts["_findings"] = findings
    return (1 if findings or defects else 0), facts


def print_facts(code, facts):
    print("NC_ROOT_KIND=%s" % facts.get("NC_ROOT_KIND", "lab"))
    if code == 2:
        print("NC_ROOT=%s" % facts.get("NC_ROOT", "?"))
        return
    for key in ("NC_CARRIERS", "NC_COMPARISONS", "NC_SENTINEL_PAIRS", "NC_GUARDED",
                "NC_BASELINE", "NC_BASELINE_ROWS", "NC_BASELINE_DEFECTS"):
        print("%s=%s" % (key, facts[key]))
    for line in facts.get("NC_BASELINE_DEFECT_LINES", []):
        print("NC_BASELINE_DEFECT=%s" % line)
    for key in facts["_findings"]:
        print("NC_FINDING=%s" % key)
    print("NC_FINDINGS=%d" % facts["NC_FINDINGS"])


# --- самопроверка: пять синтетических корней -----------------------------------------------------
UNGUARDED = ('grab() { :; }\n'
             'fa=$(grab log K1)\n'
             'fb=$(grab log K2)\n'
             '[ "$fa" = "$fb" ]\n')
GUARDED = ('grab() { :; }\n'
           'fa=$(grab log K1)\n'
           'fb=$(grab log K2)\n'
           '[ "$fa" != none ] && [ "$fa" = "$fb" ]\n')
ONE_SIDE = ('grab() { :; }\n'
            'fa=$(grab log K1)\n'
            'n=3\n'
            '[ "$fa" = "$n" ]\n')
CLEAN = 'x=1\n'


def write_fixture(root, carrier, baseline=None):
    os.makedirs(os.path.join(root, "lab"))
    with open(os.path.join(root, "lab", "e9001-run.sh"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(carrier)
    if baseline is not None:
        with open(os.path.join(root, BASELINE_REL), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(baseline)


def run_selftest():
    cases = [
        ("unguarded", UNGUARDED, None, 1, ("NC_FINDING=lab/e9001-run.sh:4",)),
        ("guarded", GUARDED, None, 0, ()),
        ("one_side", ONE_SIDE, None, 0, ()),
        ("empty_reason", UNGUARDED, "lab/e9001-run.sh:4\t\n", 1,
         ("NC_BASELINE_DEFECT=lab/e9001-run.sh:4:EMPTY_REASON", "NC_FINDING=lab/e9001-run.sh:4")),
        ("stale_row", CLEAN, "lab/e9001-run.sh:99\tпосаженная строка\n", 1,
         ("NC_BASELINE_DEFECT=lab/e9001-run.sh:99:STALE",)),
    ]
    passed = 0
    base = tempfile.mkdtemp(prefix="none-compare-selftest-")
    try:
        for name, carrier, baseline, want_rc, want_lines in cases:
            root = os.path.join(base, name)
            write_fixture(root, carrier, baseline)
            code, facts = judge(root)
            buf = []
            old = sys.stdout
            try:
                import io
                sys.stdout = io.StringIO()
                print_facts(code, facts)
                out = sys.stdout.getvalue()
            finally:
                sys.stdout = old
            ok = code == want_rc and all(line in out for line in want_lines)
            if name == "unguarded" or name == "empty_reason":
                ok = ok and "NC_FINDINGS=1" in out
            if name == "guarded":
                ok = ok and "NC_GUARDED=1" in out and "NC_SENTINEL_PAIRS=1" in out
            if name == "one_side":
                ok = ok and "NC_COMPARISONS=1" in out and "NC_SENTINEL_PAIRS=0" in out
            print("NC_SELFTEST_CASE=%s:%s" % (name, "ok" if ok else "fail"))
            if ok:
                passed += 1
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print("NC_SELFTEST_CASES=%d" % len(cases))
    print("NC_SELFTEST_PASSED=%d" % passed)
    print("NC_SELFTEST_FAILED=%d" % (len(cases) - passed))
    return 0 if passed == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return run_selftest()
    code, facts = judge(os.path.abspath(args.root))
    print_facts(code, facts)
    return code


if __name__ == "__main__":
    sys.exit(main())
