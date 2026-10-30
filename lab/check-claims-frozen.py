#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Страж колонки ожидания у сильных строк реестра утверждений (карточка H-0157, разведка — OQ п. 96).

Зачем: ссылка `E-XXXX` в `lab/claims.tsv` проверяется на резолв в карточку с вердиктом, но не на
то, что у карточки есть порог-таблица. `check-expect-freeze.py` обходит только существующие файлы
`lab/expectations/e*.tsv`; карточка без таблицы для него не событие. В итоге сильнее всего
сказанное («гейт закрыт», «измерено») может опираться на карточку, чей порог жил только в тексте,
и ни один прибор этого не назовёт.

Правило прибора: для каждой строки типа `gate-closed`/`measured` каждая ссылка `E-XXXX` обязана
иметь карточку `lab/hypotheses/H-XXXX-*.md` и файл `lab/expectations/eXXXX.tsv`. Отсутствие — находка,
пока строка не названа в `lab/claims-frozen-baseline.tsv` строкой
`claim <TAB> класс <TAB> E-номера <TAB> причина` с точным совпадением первых трёх колонок.

Существующая таблица классифицируется по коммиту добавления H-карточки: `SAME`, `CHANGED`,
`ABSENT`, и печатается фактом `CF_HISTORY_*`; находкой этого прибора `CHANGED`/`ABSENT` не являются:
их владелец — `check-expect-freeze.py` (`H-0155`). У класса один владелец, двойного счёта нет.
Слабые типы (`estimate`, `not-done`, `instrument`, `partial`, `model-proof`) вне правила: оценка и
инструмент не обещают измерения. Сильная строка без единой E-ссылки — находка `NO_E_LINK`.

Границы: прибор не судит формулировки и не пересчитывает факты (это `check-claims.py`), не читает
содержание таблиц (это носитель цикла) и не правит закрытые карточки. Без `.git` отказывается
мерить (код 2). Строка реестра с пустой причиной, чужим классом, дублем или без факта — дефект
реестра, а не пропуск.

Употребление:
    python lab/check-claims-frozen.py                 # боевой прогон по рабочему дереву
    python lab/check-claims-frozen.py --root DIR      # корень дерева (пин, фикстуры)
    python lab/check-claims-frozen.py --selftest      # девять посаженных случаев на git-фикстурах

Выход: 0 — находок и дефектов нет, 1 — есть, 2 — корень не годится для измерения.
"""
from __future__ import annotations

import glob
import io
import os
import re
import subprocess
import sys
import tempfile

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_NO_ROOT = 2

DEFAULT_REGISTRY = "lab/claims.tsv"
BASELINE_REL = os.path.join("lab", "claims-frozen-baseline.tsv")
STRONG = ("gate-closed", "measured")
BASELINE_CLASSES = ("NO_TABLE",)
E_RE = re.compile(r"^E-(\d{4})$")
CLAIM_RE = re.compile(r"^C-\d{3}$")


def emit(key, value):
    sys.stdout.write("%s=%s\n" % (key, value))


def fmt(items):
    return ",".join(items) if items else "none"


def read_text(path):
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def git(root, *args):
    """git в корне; текст и код возврата, без исключений."""
    cmd = ["git", "-C", root] + list(args)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return "", 127
    return p.stdout.decode("utf-8", "replace").strip(), p.returncode


def root_refusal(root):
    """Пустая строка — корень годится; иначе напечатанная причина отказа."""
    out, rc = git(root, "rev-parse", "--show-toplevel")
    if rc != 0 or not out:
        return "no-git"
    text = read_text(os.path.join(root, DEFAULT_REGISTRY))
    if text is None:
        return "no-claims"
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(line.split("\t")) < 6:
            return "bad-claims"
    return ""


def parse_claims(text):
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        links = [t.strip() for t in parts[5].split(",") if t.strip()]
        rows.append((parts[0].strip(), parts[1].strip(), links))
    return rows


def card_for(root, ident):
    hits = sorted(glob.glob(os.path.join(root, "lab", "hypotheses", "H-%s-*.md" % ident)))
    if not hits:
        return ""
    return os.path.relpath(hits[0], root).replace(os.sep, "/")


def table_state(root, ident):
    """Состояние пары (карточка, таблица); историю существующей таблицы судит H-0155."""
    card = card_for(root, ident)
    if not card:
        return "NO_CARD", ""
    table = "lab/expectations/e%s.tsv" % ident
    if read_text(os.path.join(root, table)) is None:
        return "NO_TABLE", card
    pin, rc = git(root, "log", "--diff-filter=A", "--format=%H", "-1", "--", card)
    pin = pin.splitlines()[0] if rc == 0 and pin else ""
    if not pin:
        return "NO_PIN", card
    at, rc = git(root, "rev-parse", "%s:%s" % (pin, table))
    if rc != 0 or not at:
        return "ABSENT", card
    now, rc2 = git(root, "hash-object", "--path=%s" % table, "--", table)
    if rc2 != 0 or not now:
        return "CHANGED", card
    return ("SAME" if now == at else "CHANGED"), card


def read_baseline(root):
    """(имя файла или none, {claim: (класс, E-номера, причина)}, дефекты реестра)."""
    text = read_text(os.path.join(root, BASELINE_REL))
    if text is None:
        return "none", {}, []
    rows, defects = {}, []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            defects.append("baseline:%d:COLUMNS" % lineno)
            continue
        cid = parts[0].strip()
        cls = parts[1].strip()
        raw_ids = parts[2].strip()
        reason = "\t".join(parts[3:]).strip()
        if not CLAIM_RE.match(cid):
            defects.append("baseline:%d:CLAIM" % lineno)
            continue
        if cls not in BASELINE_CLASSES:
            defects.append("%s:CLASS" % cid)
            continue
        ids = [x.strip() for x in raw_ids.split(",") if x.strip()]
        if not ids or not all(E_RE.match(x) for x in ids):
            defects.append("%s:EIDS" % cid)
            continue
        if not reason:
            defects.append("%s:EMPTY_REASON" % cid)
            continue
        if cid in rows:
            defects.append("%s:DUP" % cid)
            continue
        rows[cid] = (cls, tuple(sorted(ids)), reason)
    return "lab/claims-frozen-baseline.tsv", rows, defects


def judge(root):
    refusal = root_refusal(root)
    if refusal:
        emit("CF_ROOT_KIND", refusal)
        return EXIT_NO_ROOT

    text = read_text(os.path.join(root, DEFAULT_REGISTRY))
    claims = parse_claims(text or "")
    stats = {"NO_CARD": 0, "NO_TABLE": 0, "NO_PIN": 0,
             "SAME": 0, "CHANGED": 0, "ABSENT": 0}
    strong = 0
    pairs = 0
    strong_no_e = 0
    changed_claims = set()
    findings = {}

    def add(cid, cls, eid):
        slot = findings.setdefault(cid, {"classes": set(), "eids": set()})
        slot["classes"].add(cls)
        if eid:
            slot["eids"].add(eid)

    for cid, ctype, links in claims:
        if ctype not in STRONG:
            continue
        strong += 1
        elinks = [E_RE.match(t).group(1) for t in links if E_RE.match(t)]
        if not elinks:
            strong_no_e += 1
            add(cid, "NO_E_LINK", "")
            continue
        for ident in elinks:
            pairs += 1
            state, _card = table_state(root, ident)
            stats[state] += 1
            if state in ("NO_CARD", "NO_TABLE", "NO_PIN"):
                add(cid, state, "E-" + ident)
            if state == "CHANGED":
                changed_claims.add(cid)

    base_name, base_rows, defects = read_baseline(root)
    waived = set()
    for cid, slot in findings.items():
        cls = "+".join(sorted(slot["classes"]))
        eids = tuple(sorted(slot["eids"]))
        row = base_rows.get(cid)
        if row and row[0] == cls and row[1] == eids:
            waived.add(cid)
    for cid in base_rows:
        if cid not in waived:
            defects.append("%s:STALE" % cid)

    active = sorted(cid for cid in findings if cid not in waived)
    total = len(active) + len(defects)

    for key, val in (("CF_CLAIMS", strong),
                     ("CF_LINK_PAIRS", pairs),
                     ("CF_NO_CARD", stats["NO_CARD"]),
                     ("CF_NO_TABLE", stats["NO_TABLE"]),
                     ("CF_TABLE", stats["SAME"] + stats["CHANGED"] + stats["ABSENT"]),
                     ("CF_HISTORY_SAME", stats["SAME"]),
                     ("CF_HISTORY_CHANGED", stats["CHANGED"]),
                     ("CF_HISTORY_ABSENT", stats["ABSENT"]),
                     ("CF_CHANGED_CLAIMS", fmt(sorted(changed_claims))),
                     ("CF_STRONG_NO_E", strong_no_e),
                     ("CF_BASELINE", base_name),
                     ("CF_BASELINE_ROWS", len(base_rows)),
                     ("CF_BASELINE_DEFECTS", fmt(defects))):
        emit(key, val)
    for i, cid in enumerate(active, 1):
        slot = findings[cid]
        cls = "+".join(sorted(slot["classes"]))
        eids = ",".join(sorted(slot["eids"])) or "-"
        emit("CF_FINDING_%d" % i, "%s:%s:%s" % (cid, cls, eids))
    emit("CF_FINDINGS", total)
    return EXIT_FINDINGS if total else EXIT_OK


# --- самопроверка: девять посаженных случаев на одноразовых git-деревьях -------------------------

def sh(root, *args):
    p = subprocess.run(["git", "-C", root] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def new_repo(base, name, claims, edit_table=False):
    """Дерево: H-0001/H-0002 и e0001 — первый коммит; реестр строк — тоже.

    При `edit_table` второй коммит правит таблицу: пара становится `CHANGED` (владелец H-0155).
    """
    root = os.path.join(base, name)
    os.makedirs(root)
    assert sh(root, "init", "-q") == 0
    sh(root, "config", "user.name", "selftest")
    sh(root, "config", "user.email", "selftest@example.invalid")
    sh(root, "config", "commit.gpgsign", "false")
    write(os.path.join(root, "lab", "hypotheses", "H-0001-a.md"), "card 1\n")
    write(os.path.join(root, "lab", "hypotheses", "H-0002-b.md"), "card 2\n")
    write(os.path.join(root, "lab", "expectations", "e0001.tsv"), "# t\nK\t1\tone\n")
    write(os.path.join(root, "lab", "claims.tsv"), claims)
    assert sh(root, "add", "-A") == 0
    assert sh(root, "commit", "-q", "-m", "H-0001, H-0002: registration") == 0
    if edit_table:
        write(os.path.join(root, "lab", "expectations", "e0001.tsv"), "# t\nK\t2\ttwo\n")
        assert sh(root, "add", "-A") == 0
        assert sh(root, "commit", "-q", "-m", "e0001: edited after freeze") == 0
    return root


def run_guard(root):
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "--root", root],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout.decode("utf-8", "replace")


CLEAN = ("C-001\tgate-closed\t1\tdocs/STATUS-v1.md\tquote\tE-0001\n"
         "C-002\testimate\t-\tdocs/STATUS-v1.md\tquote\tE-0002\n")
NO_TABLE = "C-001\tgate-closed\t1\tdocs/STATUS-v1.md\tquote\tE-0002\n"
NO_CARD = "C-001\tmeasured\t1\tdocs/STATUS-v1.md\tquote\tE-0003\n"
NO_E = "C-001\tmeasured\t1\tdocs/STATUS-v1.md\tquote\tdocs/STATUS-v1.md\n"


def selftest():
    base = tempfile.mkdtemp(prefix="cf-selftest-")
    cases = []

    def case(name, fn):
        try:
            ok = fn()
        except Exception as exc:  # noqa: BLE001 - фикстура обязана назвать, а не упасть молча
            ok = False
            sys.stderr.write("CF_SELFTEST_ERROR %s: %s\n" % (name, exc))
        cases.append((name, ok))
        emit("CF_SELFTEST_CASE", "%s:%s" % (name, "OK" if ok else "FAIL"))

    def baseline(root, row):
        write(os.path.join(root, BASELINE_REL), "# fixture baseline\n" + row)

    def clean_same():
        root = new_repo(base, "clean", CLEAN)
        rc, out = run_guard(root)
        return rc == 0 and "CF_CLAIMS=1" in out and "CF_LINK_PAIRS=1" in out and "CF_FINDINGS=0" in out

    def no_table():
        root = new_repo(base, "no-table", NO_TABLE)
        rc, out = run_guard(root)
        return rc == 1 and "CF_FINDING_1=C-001:NO_TABLE:E-0002" in out

    def changed_not_counted():
        root = new_repo(base, "changed", CLEAN, edit_table=True)
        rc, out = run_guard(root)
        return rc == 0 and "CF_HISTORY_CHANGED=1" in out and "CF_FINDINGS=0" in out

    def baseline_names():
        root = new_repo(base, "named", NO_TABLE)
        baseline(root, "C-001\tNO_TABLE\tE-0002\tкарточка старше конвенции\n")
        rc, out = run_guard(root)
        return rc == 0 and "CF_BASELINE_ROWS=1" in out and "CF_FINDINGS=0" in out

    def empty_reason():
        root = new_repo(base, "empty", NO_TABLE)
        baseline(root, "C-001\tNO_TABLE\tE-0002\t\n")
        rc, out = run_guard(root)
        return rc == 1 and "CF_BASELINE_DEFECTS=C-001:EMPTY_REASON" in out

    def stale_row():
        root = new_repo(base, "stale", CLEAN)
        baseline(root, "C-001\tNO_TABLE\tE-0002\tстроке нечего снимать\n")
        rc, out = run_guard(root)
        return rc == 1 and "CF_BASELINE_DEFECTS=C-001:STALE" in out

    def no_card():
        root = new_repo(base, "no-card", NO_CARD)
        rc, out = run_guard(root)
        return rc == 1 and "CF_FINDING_1=C-001:NO_CARD:E-0003" in out

    def no_e_link():
        root = new_repo(base, "no-e", NO_E)
        rc, out = run_guard(root)
        return rc == 1 and "CF_FINDING_1=C-001:NO_E_LINK:-" in out

    def no_git():
        root = os.path.join(base, "nogit")
        write(os.path.join(root, "lab", "claims.tsv"), CLEAN)
        rc, out = run_guard(root)
        return rc == 2 and "CF_ROOT_KIND=no-git" in out

    case("clean_same", clean_same)
    case("no_table", no_table)
    case("changed_not_counted", changed_not_counted)
    case("baseline_names", baseline_names)
    case("baseline_empty_reason", empty_reason)
    case("baseline_stale_row", stale_row)
    case("no_card", no_card)
    case("strong_no_e_link", no_e_link)
    case("refuses_without_git", no_git)

    passed = sum(1 for _, ok in cases if ok)
    emit("CF_SELFTEST_CASES", len(cases))
    emit("CF_SELFTEST_PASSED", passed)
    emit("CF_SELFTEST_FAILED", len(cases) - passed)
    return EXIT_OK if passed == len(cases) else EXIT_FINDINGS


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    root = "."
    selftest_mode = False
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--selftest":
            selftest_mode = True
        elif arg == "--root" and i + 1 < len(argv):
            root = argv[i + 1]
            i += 1
        elif arg.startswith("--root="):
            root = arg.split("=", 1)[1]
        else:
            sys.stderr.write("неизвестный аргумент: %s\n" % arg)
            return EXIT_NO_ROOT
        i += 1
    if selftest_mode:
        return selftest()
    return judge(root)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
