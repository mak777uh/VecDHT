#!/usr/bin/env python3
"""Мета-страж: каждый прибор `lab/check-*` обязан уметь краснеть (карточка H-0151).

Зачем: стражи — единственный исполняемый довод, что документы и CI не разошлись с деревом.
Страж, у которого нет посадки дефекта, защищает так же, как выключенный: его ноль неотличим от
«не смотрел». Прибор называет две формы дыры по отдельности, потому что лечатся они по-разному:

  * `БЕЗ_ПОСАДКИ`  — в файле прибора нет режима самопроверки вовсе;
  * `БЕЗ_ВЫЗОВА`   — режим есть, но его не зовёт ни `verify.yml`, ни `workspace-verify.sh`.

Контуром считаются ровно два файла: `.github/workflows/verify.yml` и `lab/workspace-verify.sh`.
Одноразовые helper'ы циклов (`lab/eXXXX-run.sh`) контуром не считаются: их вызов действует один раз
и не защищает следующие коммиты (прецедент — `check-artifact-refs.py`, чья самопроверка жила только
в `lab/e0131-run.sh`).

Список приборов берётся из каталога по префиксу `check-`, а не из списка в этом файле: прибор,
заведённый завтра, попадает в счёт без правки стража.

Употребление:
    python lab/check-guard-selftests.py            # боевой прогон, факты в stdout
    python lab/check-guard-selftests.py --selftest # посадка дефектов на временных фикстурах
    python lab/check-guard-selftests.py --root DIR # корень дерева (для фикстур)

Выход: 0 — находок нет, 1 — есть.
"""
import argparse
import io
import os
import re
import shutil
import sys
import tempfile

CONTOUR = [".github/workflows/verify.yml", "lab/workspace-verify.sh"]
SELFTEST_TOKEN = re.compile(r"\bselftest\b")


def read(path):
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def scan(root):
    lab = os.path.join(root, "lab")
    try:
        names = sorted(n for n in os.listdir(lab) if n.startswith("check-"))
    except OSError:
        names = []
    names = [n for n in names if os.path.isfile(os.path.join(lab, n))]
    contour = "\n".join(read(os.path.join(root, p)) for p in CONTOUR)
    without, unwired = [], []
    for name in names:
        text = read(os.path.join(lab, name))
        if not SELFTEST_TOKEN.search(text):
            without.append(name)
            continue
        # Вызов самопроверки: имя прибора и следом аргумент самопроверки в одной строке контура.
        pat = re.compile(re.escape(name) + r"[^\n]*?(--selftest|selftest)\b")
        if not pat.search(contour):
            unwired.append(name)
    findings = len(without) + len(unwired)
    return names, without, unwired, findings


def emit(key, value):
    sys.stdout.write("%s=%s\n" % (key, value))


def fmt(items):
    return ",".join(items) if items else "none"


def run(root):
    names, without, unwired, findings = scan(root)
    emit("GSE_GUARDS", len(names))
    emit("GSE_WITH_SELFTEST", len(names) - len(without))
    emit("GSE_WITHOUT_SELFTEST", fmt(without))
    emit("GSE_SELFTEST_UNWIRED", fmt(unwired))
    emit("GSE_FINDINGS", findings)
    for name in without:
        sys.stderr.write("НАХОДКА[без посадки] lab/%s\n" % name)
    for name in unwired:
        sys.stderr.write("НАХОДКА[посадка не вызвана] lab/%s\n" % name)
    return 0 if findings == 0 else 1


FIXTURES = {
    # имя файла прибора -> текст прибора; чем его зовёт контур, решает `wiring`, а не эта таблица
    "check-wired.sh": "#!/usr/bin/env bash\n[ \"${1:-}\" = selftest ] && exit 0\n",
    "check-noselftest.sh": "#!/usr/bin/env bash\nexit 0\n",
    "check-unwired.py": "# режим: --selftest\nprint('ok')\n",
    "check-runonly.sh": "#!/usr/bin/env bash\n# умеет selftest, но контур зовёт только боевой режим\n",
}


def make_fixture(base, wiring):
    root = os.path.join(base, "root")
    lab = os.path.join(root, "lab")
    os.makedirs(lab)
    for name, text in FIXTURES.items():
        with io.open(os.path.join(lab, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    os.makedirs(os.path.join(root, ".github", "workflows"))
    lines = []
    for name in FIXTURES:
        if wiring.get(name, False):
            lines.append("python lab/%s --selftest" % name)
        else:
            lines.append("python lab/%s" % name)
    with io.open(os.path.join(root, ".github", "workflows", "verify.yml"), "w",
                 encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    with io.open(os.path.join(root, "lab", "workspace-verify.sh"), "w",
                 encoding="utf-8", newline="\n") as fh:
        fh.write("#!/usr/bin/env bash\n")
    return root


def selftest():
    # Посадка: (а) дефектная фикстура обязана назвать ровно два имени; (б) чистая — ноль находок.
    cases = []
    base = tempfile.mkdtemp(prefix="gse-")
    try:
        dirty = make_fixture(os.path.join(base, "dirty"), {
            "check-wired.sh": True, "check-noselftest.sh": True,
            "check-unwired.py": False, "check-runonly.sh": False,
        })
        names, without, unwired, findings = scan(dirty)
        cases.append(("dirty",
                      findings == 3
                      and without == ["check-noselftest.sh"]
                      and unwired == ["check-runonly.sh", "check-unwired.py"],
                      "findings=%d without=%s unwired=%s" % (findings, fmt(without), fmt(unwired))))
        clean = make_fixture(os.path.join(base, "clean"), {
            "check-wired.sh": True, "check-noselftest.sh": False,
            "check-unwired.py": True, "check-runonly.sh": False,
        })
        # «чистая» фикстура обязана содержать ноль приборов без посадки: убираем лишние файлы.
        for name in ("check-noselftest.sh", "check-runonly.sh"):
            os.remove(os.path.join(clean, "lab", name))
        _, without2, unwired2, findings = scan(clean)
        cases.append(("clean", findings == 0,
                      "findings=%d without=%s unwired=%s"
                      % (findings, fmt(without2), fmt(unwired2))))
        # Каталог без lab/ — прибор деградирует в нули, а не падает.
        empty = os.path.join(base, "empty")
        os.makedirs(empty)
        _, _, _, findings = scan(empty)
        cases.append(("empty", findings == 0, "findings=%d" % findings))
    finally:
        shutil.rmtree(base, ignore_errors=True)
    failed = [c for c in cases if not c[1]]
    for name, ok, detail in cases:
        sys.stdout.write("ПОСАДКА %s: %s (%s)\n" % (name, "OK" if ok else "FAIL", detail))
    emit("GSE_SELFTEST_CASES", len(cases))
    emit("GSE_SELFTEST_PASSED", len(cases) - len(failed))
    emit("GSE_SELFTEST_FAILED", len(failed))
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
