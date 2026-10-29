#!/usr/bin/env python3
"""Паритет боевого режима: прибор должен краснеть в обоих контурах или разница названа (H-0152).

Зачем. `H-0151` доказал, что посадка у каждого стража есть и что посадку зовёт контур. Он не
спросил другого: зовёт ли контур сам прибор. Ответ оказался разным: на дереве `18a3a70` шесть
приборов стояли боевым шагом только в одном месте — или только в CI, или только на хосте, а
`check-release-kit.sh` — только на теге. 2026-10-29 это стоило находки: несуществующую цитату в
носителе `E-0151` поймал ручной запуск стража цитат, потому что на хосте он стоял только посадкой.

Что считается боевым вызовом. Строка вида `python lab/check-*.py …` или `bash lab/check-*.sh …`
без слова `selftest` в аргументах. Комментарии и строки внутри кавычек не разбираются: страж читает
текст контура, а не исполняет его (граница названа в карточке).

Два основных контура — `.github/workflows/verify.yml` и `lab/workspace-verify.sh`. Если боевой
вызов есть в обоих, прибор в паритете. Если нет — разница обязана стоять строкой реестра
`lab/contour-parity.tsv` с непустой причиной. `release.yml` и `formal.yml` — дополнительные места:
вызов там засчитывается как «прибор где-то исполняется», но не снимает разницу основных двух.

Находки: разница без причины, строка реестра для прибора, которого нет в каталоге, пустая причина,
прибор без боевого вызова нигде.

Употребление:
    python lab/check-contour-parity.py             # боевой прогон, факты в stdout
    python lab/check-contour-parity.py --selftest  # три посаженные ошибки на временных фикстурах
    python lab/check-contour-parity.py --root DIR  # корень дерева (для фикстур)

Выход: 0 — находок нет, 1 — есть.
"""
import argparse
import io
import os
import re
import shutil
import sys
import tempfile

MAIN = [".github/workflows/verify.yml", "lab/workspace-verify.sh"]
EXTRA = [".github/workflows/release.yml", ".github/workflows/formal.yml"]
REGISTRY = "lab/contour-parity.tsv"
CALL = re.compile(r"^\s*(?:python3?|bash)\s+lab/(check-[A-Za-z0-9_.-]+)(.*)$")


def read(path):
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def battle_calls(root, rel):
    """Имена приборов, вызванных в файле боевым режимом (без аргумента посадки)."""
    found = set()
    for line in read(os.path.join(root, rel)).splitlines():
        m = CALL.match(line)
        if not m:
            continue
        if "selftest" in m.group(2):
            continue
        found.add(m.group(1))
    return found


def load_registry(root):
    """Реестр причин: имя прибора -> причина. Пустая причина сохраняется как пустая строка."""
    rows = {}
    path = os.path.join(root, REGISTRY)
    for raw in read(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t", 1)
        name = parts[0].strip()
        reason = parts[1].strip() if len(parts) > 1 else ""
        if name:
            rows[name] = reason
    return rows


def fmt(items):
    return ",".join(items) if items else "none"


def scan(root):
    lab = os.path.join(root, "lab")
    try:
        names = sorted(n for n in os.listdir(lab) if n.startswith("check-"))
    except OSError:
        names = []
    names = [n for n in names if os.path.isfile(os.path.join(lab, n))]
    in_main = [battle_calls(root, rel) for rel in MAIN]
    in_extra = set()
    for rel in EXTRA:
        in_extra |= battle_calls(root, rel)
    both = in_main[0] & in_main[1]
    everywhere = in_main[0] | in_main[1] | in_extra
    differences = [n for n in names if n not in both]
    unwired = [n for n in names if n not in everywhere]
    rows = load_registry(root)
    named = [n for n in differences if rows.get(n)]
    unnamed = [n for n in differences if not rows.get(n)]
    empty = sorted(g for g, why in rows.items() if not why)
    stale = sorted(g for g in rows if g not in names)
    findings = len(unnamed) + len(unwired) + len(empty) + len(stale)
    return {
        "names": names, "differences": differences, "unnamed": unnamed, "unwired": unwired,
        "named": named, "rows": rows, "empty": empty, "stale": stale, "findings": findings,
    }


def emit(key, value):
    sys.stdout.write("%s=%s\n" % (key, value))


def run(root):
    r = scan(root)
    emit("ПАРИТЕТ_ПРИБОРОВ", len(r["names"]))
    emit("ПАРИТЕТ_РАСХОЖДЕНИЙ", len(r["differences"]))
    emit("ПАРИТЕТ_БЕЗ_ПРИЧИНЫ", fmt(r["unnamed"]))
    emit("ПАРИТЕТ_БЕЗ_ВЫЗОВА", fmt(r["unwired"]))
    emit("ПАРИТЕТ_ПРИЧИН", len(r["named"]))
    emit("ПАРИТЕТ_ПУСТЫХ_ПРИЧИН", len(r["empty"]))
    emit("ПАРИТЕТ_МЁРТВЫХ_СТРОК", fmt(r["stale"]))
    emit("ПАРИТЕТ_НАХОДОК", r["findings"])
    for n in r["unnamed"]:
        sys.stderr.write("НАХОДКА[разница без причины] lab/%s\n" % n)
    for n in r["unwired"]:
        sys.stderr.write("НАХОДКА[нет боевого вызова] lab/%s\n" % n)
    for n in r["empty"]:
        sys.stderr.write("НАХОДКА[пустая причина] %s\n" % n)
    for n in r["stale"]:
        sys.stderr.write("НАХОДКА[строка реестра без прибора] %s\n" % n)
    return 0 if r["findings"] == 0 else 1


FIXTURES = ("check-alpha.sh", "check-beta.sh")


def make_fixture(base, verify, workspace, registry=None):
    """root с двумя фикстурами-приборами и двумя контурами; `registry` — строки реестра или None."""
    root = os.path.join(base, "root")
    os.makedirs(os.path.join(root, "lab"))
    os.makedirs(os.path.join(root, ".github", "workflows"))
    for name in FIXTURES:
        with io.open(os.path.join(root, "lab", name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("#!/usr/bin/env bash\nexit 0\n")
    with io.open(os.path.join(root, ".github", "workflows", "verify.yml"), "w",
                 encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(verify) + "\n")
    with io.open(os.path.join(root, "lab", "workspace-verify.sh"), "w",
                 encoding="utf-8", newline="\n") as fh:
        fh.write("#!/usr/bin/env bash\n" + "\n".join(workspace) + "\n")
    if registry is not None:
        with io.open(os.path.join(root, REGISTRY), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(registry) + "\n")
    return root


def selftest():
    cases = []
    alpha_v, alpha_w = "bash lab/check-alpha.sh", "bash lab/check-alpha.sh"
    beta_v = "bash lab/check-beta.sh"
    base = tempfile.mkdtemp(prefix="parity-")
    try:
        # (а) боевой вызов есть в verify и нет в workspace: разница без причины — находка.
        a = make_fixture(os.path.join(base, "a"), [alpha_v, beta_v], [alpha_w])
        r = scan(a)
        cases.append(("removed_call",
                      r["findings"] == 1 and r["unnamed"] == ["check-beta.sh"]
                      and r["differences"] == ["check-beta.sh"],
                      "findings=%d unnamed=%s" % (r["findings"], fmt(r["unnamed"]))))
        # (б) строка реестра с пустой причиной не снимает находку.
        b = make_fixture(os.path.join(base, "b"), [alpha_v, beta_v], [alpha_w],
                         ["check-beta.sh\t"])
        r = scan(b)
        cases.append(("empty_reason",
                      r["findings"] == 2 and r["empty"] == ["check-beta.sh"]
                      and r["unnamed"] == ["check-beta.sh"],
                      "findings=%d empty=%s" % (r["findings"], fmt(r["empty"]))))
        # (в) строка реестра для прибора, которого нет в каталоге, — находка.
        c = make_fixture(os.path.join(base, "c"), [alpha_v, beta_v], [alpha_w, "bash lab/check-beta.sh"],
                         ["check-ghost.sh\tпричина названа"])
        r = scan(c)
        cases.append(("foreign_row",
                      r["findings"] == 1 and r["stale"] == ["check-ghost.sh"]
                      and r["differences"] == [],
                      "findings=%d stale=%s" % (r["findings"], fmt(r["stale"]))))
    finally:
        shutil.rmtree(base, ignore_errors=True)
    failed = [c for c in cases if not c[1]]
    for name, ok, detail in cases:
        sys.stdout.write("ПОСАДКА %s: %s (%s)\n" % (name, "OK" if ok else "FAIL", detail))
    emit("PARITY_SELFTEST_CASES", len(cases))
    emit("PARITY_SELFTEST_PASSED", len(cases) - len(failed))
    emit("PARITY_SELFTEST_FAILED", len(failed))
    return 0 if not failed else 1


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    return run(args.root)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
