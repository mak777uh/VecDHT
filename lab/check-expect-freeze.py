#!/usr/bin/env python3
"""Страж заморозки таблиц ожиданий (карточка H-0155, разведка — OQ п. 93).

Зачем: таблица ожиданий — порог цикла. Если её можно переписать после коммита пре-регистрации,
подменённое ожидание делает красный носитель зелёным, и это не покраснит ни один прибор: `expect.py`
сравнивает факты с таблицей, а не таблицу с её историей. `H-0154` показал класс: две строки были
переписаны между пробным прогоном и первым официальным, и сверить их было нечем.

Правило прибора: у каждой таблицы `lab/expectations/e<NNNN>.tsv` есть ровно одна точка заморозки —
коммит, добавивший карточку `lab/hypotheses/H-<NNNN>-*.md`. Таблица обязана:

  * существовать в этом коммите (иначе `ABSENT` — класс E-0154: таблица появилась позже);
  * совпадать с блобом этого коммита по байтам (иначе `CHANGED` — правка после пре-регистрации);
  * существовать в рабочем дереве (иначе `MISSING_FILE`);
  * иметь H-карточку (иначе `MISSING_H`).

Нарушения не запрещены задним числом: исторические 19 названы в `lab/expect-freeze-baseline.tsv`
строкой с коммитом и причиной. Строка базовой линии обязана совпадать с фактическим нарушением;
строка без причины, с чужим коммитом или для уже чистого дерева — находка (база не гниёт).

Границы: прибор сверяет файл таблицы, а не её содержание; `expect.py` и закрытые helper'ы не
трогает; строка `STABLE`/`WORST_RC` в таблицах не имеет к нему отношения. Без `.git` прибор
отказывается мерить (код 2): вне истории у таблицы нет точки заморозки, и «ноль находок» там был бы
нулём слепого.

Употребление:
    python lab/check-expect-freeze.py                 # боевой прогон по рабочему дереву
    python lab/check-expect-freeze.py --strict-all    # база игнорируется: краснеет всё, что не SAME
    python lab/check-expect-freeze.py --root DIR      # корень дерева (пин, фикстуры)
    python lab/check-expect-freeze.py --selftest      # шесть посаженных дефектов на фикстурах

Выход: 0 — находок нет, 1 — есть, 2 — корень не является корнем git-дерева.
"""
import argparse
import io
import os
import re
import subprocess
import sys
import tempfile

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_NO_GIT = 2

FINDING = "EF_FINDING"


def emit(key, value):
    sys.stdout.write("%s=%s\n" % (key, value))


def fmt(items):
    return ",".join(items) if items else "none"


def git(root, *args):
    """git в корне; текст и код возврата, без исключений."""
    cmd = ["git", "-C", root] + list(args)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return "", 127
    return p.stdout.decode("utf-8", "replace").strip(), p.returncode


def read_text(path):
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def toplevel(root):
    out, rc = git(root, "rev-parse", "--show-toplevel")
    if rc != 0 or not out:
        return None
    return out


def same_path(a, b):
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def tables(root):
    """Все таблицы, когда-либо добавленные в историю, плюс лежащие в рабочем дереве.

    Каталог рабочего дерева не видит удалённую таблицу: без истории она исчезает из счёта, и
    «ноль находок» становится нулём слепого (первый прогон самопроверки это и поймал).
    """
    names = set()
    out, rc = git(root, "log", "--all", "--diff-filter=A", "--format=", "--name-only", "--",
                  "lab/expectations/e*.tsv")
    if rc == 0 and out:
        for line in out.splitlines():
            m = re.match(r"^(lab/expectations/e\d{4}\.tsv)$", line.strip())
            if m:
                names.add(m.group(1))
    try:
        for n in os.listdir(os.path.join(root, "lab", "expectations")):
            if re.match(r"^e\d{4}\.tsv$", n):
                names.add("lab/expectations/" + n)
    except OSError:
        pass
    return sorted(names)


def freeze_commit(root, table):
    ident = re.match(r"^lab/expectations/e(\d{4})\.tsv$", table).group(1)
    out, rc = git(root, "log", "--diff-filter=A", "--format=%H", "-1", "--",
                  "lab/hypotheses/H-%s-*.md" % ident)
    return out.splitlines()[0] if rc == 0 and out else ""


def blob_at(root, commit, table, short=False):
    out, rc = git(root, "rev-parse" + (" --short" if short else ""), "%s:%s" % (commit, table))
    return out if rc == 0 else ""


def worktree_blob(root, table):
    out, rc = git(root, "hash-object", "--path=%s" % table, "--", table)
    return out if rc == 0 else ""


def classify(root):
    """Список (table, kind, pin) и счётчики по видам."""
    rows = []
    stats = {"SAME": 0, "CHANGED": 0, "ABSENT": 0, "MISSING_H": 0, "MISSING_FILE": 0}
    for table in tables(root):
        pin = freeze_commit(root, table)
        if not pin:
            rows.append((table, "MISSING_H", "-"))
            stats["MISSING_H"] += 1
            continue
        if read_text(os.path.join(root, table)) is None:
            rows.append((table, "MISSING_FILE", pin[:7]))
            stats["MISSING_FILE"] += 1
            continue
        at_pin = blob_at(root, pin, table)
        if not at_pin:
            rows.append((table, "ABSENT", pin[:7]))
            stats["ABSENT"] += 1
            continue
        now = worktree_blob(root, table)
        if now and now == at_pin:
            rows.append((table, "SAME", pin[:7]))
            stats["SAME"] += 1
        else:
            rows.append((table, "CHANGED", pin[:7]))
            stats["CHANGED"] += 1
    return rows, stats


def parse_baseline(path):
    """Строки (table, status, pin, reason) и дефекты самой базы."""
    rows, defects = [], []
    text = read_text(path)
    if text is None:
        return None, defects
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            defects.append("baseline:%d:COLUMNS" % lineno)
            continue
        table, status, pin, reason = parts[0], parts[1], parts[2], "\t".join(parts[3:])
        if status not in ("CHANGED", "ABSENT"):
            defects.append("%s:STATUS" % table)
            continue
        if not reason.strip():
            defects.append("%s:EMPTY_REASON" % table)
            continue
        rows.append((table, status, pin.strip(), reason.strip()))
    return rows, defects


def judge(root, strict_all):
    rows, stats = classify(root)
    findings = []
    baseline_path = os.path.join(root, "lab", "expect-freeze-baseline.tsv")
    base_rows, defects = parse_baseline(baseline_path)
    if strict_all:
        base_kind = "ignored"
        base_rows = []
    elif base_rows is None:
        base_kind = "none"
        base_rows = []
    else:
        base_kind = "lab/expect-freeze-baseline.tsv"

    by_table = {t: (kind, pin) for t, kind, pin in rows}
    expected = {}
    for table, status, pin, _reason in base_rows:
        expected[table] = (status, pin)

    for table, kind, pin in rows:
        if kind == "SAME":
            continue
        if not strict_all:
            want = expected.get(table)
            if want and want[0] == kind and pin.startswith(want[1]):
                continue
            if want and want[0] == kind and not pin.startswith(want[1]):
                findings.append("%s:PIN_MISMATCH" % table)
                continue
        findings.append("%s:%s" % (table, kind))

    for table, (status, pin) in expected.items():
        now = by_table.get(table)
        if now is None:
            findings.append("%s:STALE" % table)
        elif now[0] == "SAME":
            findings.append("%s:STALE" % table)
        elif now[0] != status or not now[1].startswith(pin):
            findings.append("%s:STALE" % table)

    findings.extend(defects)

    for key, val in (("EF_TABLES", len(rows)),
                     ("EF_SAME", stats["SAME"]),
                     ("EF_CHANGED", stats["CHANGED"]),
                     ("EF_ABSENT", stats["ABSENT"]),
                     ("EF_MISSING_H", stats["MISSING_H"]),
                     ("EF_MISSING_FILE", stats["MISSING_FILE"]),
                     ("EF_STRICT_ALL", 1 if strict_all else 0),
                     ("EF_BASELINE", base_kind),
                     ("EF_BASELINE_ROWS", len(base_rows)),
                     ("EF_BASELINE_DEFECTS", fmt(defects))):
        emit(key, val)
    for finding in findings:
        emit(FINDING, finding)
    emit("EF_FINDINGS", len(findings))
    return EXIT_FINDINGS if findings else EXIT_OK


# --- самопроверка: шесть посаженных дефектов на одноразовых git-деревьях ------------------------

def sh(root, *args):
    p = subprocess.run(["git", "-C", root] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def new_repo(base, name):
    """Дерево: H-0001 и e0001 в первом коммите; H-0002 — тоже, e0002 — позже (класс ABSENT)."""
    root = os.path.join(base, name)
    os.makedirs(root)
    assert sh(root, "init", "-q") == 0
    sh(root, "config", "user.name", "selftest")
    sh(root, "config", "user.email", "selftest@example.invalid")
    sh(root, "config", "commit.gpgsign", "false")
    write(os.path.join(root, "lab", "hypotheses", "H-0001-a.md"), "card 1\n")
    write(os.path.join(root, "lab", "hypotheses", "H-0002-b.md"), "card 2\n")
    write(os.path.join(root, "lab", "expectations", "e0001.tsv"), "# t\nK\t1\tone\n")
    assert sh(root, "add", "-A") == 0
    assert sh(root, "commit", "-q", "-m", "H-0001, H-0002: registration") == 0
    write(os.path.join(root, "lab", "expectations", "e0002.tsv"), "# t\nK\t2\ttwo\n")
    assert sh(root, "add", "-A") == 0
    assert sh(root, "commit", "-q", "-m", "e0002: table after H card") == 0
    pin1 = subprocess.run(["git", "-C", root, "rev-parse", "--short", "HEAD~1"],
                          stdout=subprocess.PIPE).stdout.decode().strip()
    return root, pin1


def baseline(root, rows):
    lines = ["# fixture baseline"]
    lines.extend(rows)
    write(os.path.join(root, "lab", "expect-freeze-baseline.tsv"), "\n".join(lines) + "\n")


def run_guard(root):
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "--root", root],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def selftest():
    base = tempfile.mkdtemp(prefix="ef-selftest-")
    cases = []

    def case(name, fn):
        try:
            ok = fn()
        except Exception as exc:  # noqa: BLE001 - фикстура обязана назвать, а не упасть молча
            ok = False
            sys.stderr.write("EF_SELFTEST_ERROR %s: %s\n" % (name, exc))
        cases.append((name, ok))
        emit("EF_SELFTEST_CASE", "%s:%s" % (name, "OK" if ok else "FAIL"))

    def clean():
        root, pin1 = new_repo(base, "clean")
        baseline(root, ["lab/expectations/e0002.tsv\tABSENT\t%s\tисторическое" % pin1])
        rc, out = run_guard(root)
        return rc == 0 and "EF_FINDINGS=0" in out

    def changed():
        root, pin1 = new_repo(base, "changed")
        baseline(root, ["lab/expectations/e0002.tsv\tABSENT\t%s\tисторическое" % pin1])
        write(os.path.join(root, "lab", "expectations", "e0001.tsv"), "# t\nK\t9\tsubstituted\n")
        rc, out = run_guard(root)
        return rc == 1 and "EF_FINDING=lab/expectations/e0001.tsv:CHANGED" in out

    def empty_reason():
        root, pin1 = new_repo(base, "empty")
        baseline(root, ["lab/expectations/e0002.tsv\tABSENT\t%s\t" % pin1])
        rc, out = run_guard(root)
        return rc == 1 and "e0002.tsv:EMPTY_REASON" in out

    def stale():
        root, pin1 = new_repo(base, "stale")
        baseline(root, ["lab/expectations/e0001.tsv\tCHANGED\t%s\tстрока для чистой таблицы" % pin1])
        rc, out = run_guard(root)
        return rc == 1 and "e0001.tsv:STALE" in out

    def no_git():
        root = os.path.join(base, "nogit")
        write(os.path.join(root, "lab", "expectations", "e0001.tsv"), "K\t1\n")
        rc, out = run_guard(root)
        return rc == 2 and "EF_ROOT_KIND=no-git" in out

    def deleted():
        root, pin1 = new_repo(base, "deleted")
        baseline(root, [])
        os.remove(os.path.join(root, "lab", "expectations", "e0001.tsv"))
        rc, out = run_guard(root)
        return rc == 1 and "EF_FINDING=lab/expectations/e0001.tsv:MISSING_FILE" in out

    case("clean_with_baseline", clean)
    case("changed_after_freeze", changed)
    case("baseline_empty_reason", empty_reason)
    case("baseline_stale_row", stale)
    case("refuses_without_git", no_git)
    case("deleted_table", deleted)

    passed = sum(1 for _n, ok in cases if ok)
    emit("EF_SELFTEST_CASES", len(cases))
    emit("EF_SELFTEST_PASSED", passed)
    emit("EF_SELFTEST_FAILED", len(cases) - passed)
    return EXIT_OK if passed == len(cases) else EXIT_FINDINGS


def main(argv=None):
    ap = argparse.ArgumentParser(description="Страж заморозки таблиц ожиданий (H-0155)")
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--strict-all", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    root = os.path.abspath(args.root)
    top = toplevel(root)
    if not top:
        emit("EF_ROOT_KIND", "no-git")
        emit("EF_FINDINGS", "none")
        return EXIT_NO_GIT
    if not same_path(top, root):
        emit("EF_ROOT_KIND", "wrong-root")
        emit("EF_TOPLEVEL", top)
        emit("EF_FINDINGS", "none")
        return EXIT_NO_GIT
    emit("EF_ROOT_KIND", "git")
    return judge(root, args.strict_all)


if __name__ == "__main__":
    sys.exit(main())
