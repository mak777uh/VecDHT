#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Статус-документ как проверяемое утверждение (`H-0143`).

`docs/STATUS-v1.md` читает посторонний, чтобы судить о готовности, — значит каждая его строка про
наличие или отсутствие возможности обязана иметь владельца в дереве. Прибор связывает четыре такие
строки с четырьмя видами доказательства: закрытая карточка с вердиктом `supports`, символ в
продукте, файл исполняемого теста и (для правила «у числа в прозе один владелец») имя стража,
который это число печатает.

Строка, утверждающая наличие, требует всех доказательств своего класса; строка, утверждающая
отсутствие, — ни одного. Прибор проверяет и в одну, и в другую сторону: документ, который слабее
дерева и документ, который сильнее дерева, — оба находка, и у каждой своё имя причины
(`doc-missing`, `doc-contradicts`, `doc-stale`, `oracle-missing`).

Границы, названные до замера
----------------------------

* Прибор читает **названные формы**, а не смысл: свободный текст («Batch C», «P6») он не понимает,
  поэтому у каждого утверждения перечислены и положительная, и отрицательная форма. Новая
  формулировка обходит прибор так же, как обходила прежняя; это цена дешёвого стража, а не его
  обещание.
* Прибор не доказывает поведение: что `with_centroids` действительно загружает центроиды,
  доказывает `crates/vecdht-cli/tests/node_centroids.rs`, и прибор лишь требует, чтобы файл теста
  существовал и был назван. Красный тест при зелёном приборе возможен — носитель круга прогоняет
  оба теста отдельно и печатает их счёт.
* `--doc` существует затем, чтобы один и тот же прибор судил документ пина (файл из `git show`,
  вне рабочего дерева) и документ после починки на одних и тех же фактах дерева; без него «до» и
  «после» сравнивались бы на одном файле. Корень важен фактам, а не документу: пути владельцев
  относительны корня, и их отсутствие — находка, а не молчание.

Выход: 0 — все четыре строки согласованы с деревом; 1 — хотя бы одна расходится (печатает имена);
2 — документ или корень не читается.

`selftest` строит временное дерево и тринадцать посаженных случаев: положительный контроль,
каждую из четырёх поломок документа, ослабленную карточку-владельца, пропавший символ, удалённый
тест, ослабленную карточку `S-03`, число в прозе, удалённое имя стража, отсутствующий документ и
пропавшую карточку второго утверждения.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import sys
import tempfile

DOC_DEFAULT = "docs/STATUS-v1.md"


class Claim:
    """Одно утверждение документа и его владельцы в дереве."""

    def __init__(self, cid, title, doc_yes, doc_no, facts):
        self.cid = cid
        self.title = title
        self.doc_yes = doc_yes      # все формы обязаны найтись: так звучит согласованная строка
        self.doc_no = doc_no        # ни одна не имеет права найтись: так звучит расхождение
        self.facts = facts          # [(kind, путь, образец)]


CLAIMS = [
    Claim(
        "S-01",
        "поставляемый бинарник грузит centroid.bin",
        [r"`centroid\.bin` is loaded", r"`E-0121`"],
        [r"does not load centroids"],
        [
            ("card", "lab/experiments/E-0121-*.md", None),
            ("contains", "crates/vecdht-cli/src/node_cmd.rs", r"\.with_centroids\("),
            ("file", "crates/vecdht-cli/tests/node_centroids.rs", None),
            ("contains", "crates/vecdht-cli/tests/node_centroids.rs", r"cluster_reassigned"),
        ],
    ),
    Claim(
        "S-02",
        "есть команда запуска узла: node run",
        [r"`node run` starts a node", r"`E-0119`"],
        [r'there is no "start a node" command', r"`node`[^.]{0,120}is P6"],
        [
            ("card", "lab/experiments/E-0119-*.md", None),
            ("contains", "crates/vecdht-cli/src/node_cmd.rs", r"NODE_READY"),
            ("file", "crates/vecdht-cli/tests/node_run.rs", None),
        ],
    ),
    Claim(
        "S-03",
        "CLI объявляет и фильтрует класс/направление: --class и --intent-dir",
        [r"accepts `--class` and `--intent-dir`", r"`crates/vecdht-cli/src/index_cmd\.rs`",
         r"`E-0144`"],
        [r"there are no CLI flags `--class`"],
        [
            # Владелец строки — карточка круга: флаг без закрытого измерения не доказательство.
            ("card", "lab/experiments/E-0144-*.md", None),
        ],
    ),
    Claim(
        "S-04",
        "счётчики стража цитат не переписаны в прозу",
        [r"check-artifact-refs\.py"],
        [r"\b\d{3,}\b backtick\s+citations?"],
        [
            ("contains", "lab/check-artifact-refs.py", r"REFS_CITED"),
        ],
    ),
]


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def card_facts(path):
    """status: closed и verdict: supports из frontmatter карточки."""
    text = read_text(path)
    head = text.split("---", 2)
    body = head[1] if len(head) >= 3 else text[:2000]
    status = re.search(r"^status:\s*(\S+)", body, re.M)
    verdict = re.search(r"^verdict:\s*(\S+)", body, re.M)
    st = status.group(1).strip("\"'") if status else "none"
    vd = verdict.group(1).strip("\"'") if verdict else "none"
    return st, vd


def check_fact(root, kind, rel, pattern):
    """Проверка одного владельца. Возвращает (ok, имя_провала)."""
    if kind == "card":
        hits = sorted(glob.glob(os.path.join(root, rel)))
        if not hits:
            return False, rel + ":нет карточки"
        status, verdict = card_facts(hits[0])
        if status not in ("closed", "completed") or verdict != "supports":
            return False, "%s:%s/%s" % (os.path.basename(hits[0]), status, verdict)
        return True, ""
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return False, rel + ":нет файла"
    text = read_text(path)
    if kind == "contains":
        if re.search(pattern, text):
            return True, ""
        return False, rel + ":нет символа"
    if kind == "absent":
        if re.search(pattern, text):
            return False, rel + ":символ есть"
        return True, ""
    if kind == "file":
        return True, ""
    raise ValueError("неизвестный вид факта: " + kind)


def evaluate(root, doc_path):
    """Возвращает (код, строки вывода, факты)."""
    if not os.path.isdir(root):
        return 2, ["STATUS_EXIT=2", "STATUS_DOC=%s" % doc_path, "STATUS_ERROR=корень не каталог"], {}
    if not os.path.isfile(doc_path):
        return 2, ["STATUS_EXIT=2", "STATUS_DOC=%s" % doc_path, "STATUS_ERROR=документ не читается"], {}
    doc = read_text(doc_path)
    lines = []
    facts_total = 0
    facts_ok = 0
    missing = []
    stale = []
    reasons = []
    consistent = 0
    for claim in CLAIMS:
        failures = []
        for kind, rel, pattern in claim.facts:
            facts_total += 1
            ok, why = check_fact(root, kind, rel, pattern)
            if ok:
                facts_ok += 1
            else:
                failures.append(why)
                missing.append(why)
        if failures:
            verdict = "stale"
            reason = "oracle-missing"
        else:
            lack = [p for p in claim.doc_yes if not re.search(p, doc, re.S)]
            contra = [p for p in claim.doc_no if re.search(p, doc, re.S)]
            if lack:
                verdict, reason = "stale", "doc-missing"
            elif contra:
                verdict, reason = "stale", "doc-contradicts"
            else:
                verdict, reason = "consistent", ""
        if verdict == "stale":
            stale.append(claim.cid)
            reasons.append("%s:%s" % (claim.cid, reason))
        else:
            consistent += 1
        lines.append("ПРОВЕРКА %s %s %s %s" % (claim.cid, verdict, reason or "-", claim.title))
        if verdict == "stale" and failures:
            for f in failures:
                lines.append("ПРОВЕРКА %s провал %s" % (claim.cid, f))
        lines.append("STATUS_%s=%s" % (claim.cid.replace("-", ""), verdict))
    code = 1 if stale else 0
    try:
        shown = os.path.relpath(doc_path, root).replace(os.sep, "/")
    except ValueError:
        shown = doc_path.replace(os.sep, "/")
    if shown.startswith(".."):
        shown = doc_path.replace(os.sep, "/")
    out = [
        "STATUS_DOC=%s" % shown,
        "STATUS_CLAIMS=%d" % len(CLAIMS),
        "STATUS_CONSISTENT=%d" % consistent,
        "STATUS_STALE=%d" % len(stale),
        "STATUS_STALE_IDS=%s" % (",".join(stale) if stale else "none"),
        "STATUS_STALE_REASONS=%s" % (",".join(reasons) if reasons else "none"),
        "STATUS_FACTS=%d" % facts_total,
        "STATUS_FACTS_OK=%d" % facts_ok,
        "STATUS_FACTS_MISSING=%s" % (",".join(missing) if missing else "none"),
        "STATUS_OK=%d" % (1 if code == 0 else 0),
        "STATUS_EXIT=%d" % code,
    ]
    return code, lines + out, {"stale": stale, "facts": facts_total, "ok": facts_ok}


# --- самопроверка -------------------------------------------------------------------------

CLEAN_DOC = """# Status

The signing ceremony is a command (`E-0118`), `node run` starts a node from those files and
`centroid.bin` is loaded and `cluster_id` recomputed by the shipped binary (`E-0121`,
`E-0119`).

* paid intents: the CLI accepts `--class` and `--intent-dir` (`crates/vecdht-cli/src/index_cmd.rs`,
  `E-0144`), and there is no settlement.
* M6 guards — `lab/check-secrets.sh` and `lab/check-artifact-refs.py`; the guard prints its own
  counts, a stale allowance is a finding.
"""


def build_tree(root):
    def put(rel, text):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    put("docs/STATUS-v1.md", CLEAN_DOC)
    put("lab/experiments/E-0121-a2.md", "---\nid: E-0121\nstatus: closed\nverdict: supports\n---\n# E\n")
    put("lab/experiments/E-0119-a1.md", "---\nid: E-0119\nstatus: closed\nverdict: supports\n---\n# E\n")
    put("crates/vecdht-cli/src/node_cmd.rs",
        "fn run() { let node = node.with_centroids(arc); }\nprintln!(\"NODE_READY listen=…\");\n")
    put("crates/vecdht-cli/tests/node_centroids.rs", "#[test] fn reassign() { cluster_reassigned(); }\n")
    put("crates/vecdht-cli/tests/node_run.rs", "#[test] fn ready() { NODE_READY(); }\n")
    put("lab/experiments/E-0144-a3.md", "---\nid: E-0144\nstatus: closed\nverdict: supports\n---\n# E\n")
    put("lab/check-artifact-refs.py", "REFS_CITED=1580\n")


def selftest():
    base = tempfile.mkdtemp(prefix="status-claims-")
    cases = []

    def case(name, mutate, expect_stale, expect_exit):
        root = os.path.join(base, name)
        shutil.copytree(base + "/seed", root)
        mutate(root)
        code, out, _ = evaluate(root, os.path.join(root, DOC_DEFAULT))
        text = "\n".join(out)
        got = re.search(r"^STATUS_STALE_IDS=(.*)$", text, re.M)
        got = got.group(1) if got else "none"
        want = ",".join(expect_stale) if expect_stale else "none"
        ok = code == expect_exit and (expect_exit == 2 or got == want)
        cases.append((name, ok))
        if not ok:
            print("СЕЛФТЕСТ_СЛУЧАЙ %s FAIL код=%d ids=%s ожидалось код=%d ids=%s"
                  % (name, code, got, expect_exit, want))

    def doc(root):
        return os.path.join(root, DOC_DEFAULT)

    def append(text):
        def _m(root):
            with open(doc(root), "a", encoding="utf-8") as fh:
                fh.write(text)
        return _m

    def drop(pattern):
        def _m(root):
            t = read_text(doc(root))
            t2 = re.sub(pattern, "", t)
            assert t2 != t, "посадка не изменила документ: " + pattern
            with open(doc(root), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(t2)
        return _m

    def edit(rel, old, new):
        def _m(root):
            p = os.path.join(root, rel)
            t = read_text(p)
            assert old in t, "посадка не нашла строку " + old
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(t.replace(old, new, 1))
        return _m

    def remove(rel):
        def _m(root):
            os.remove(os.path.join(root, rel))
        return _m

    def missing_doc(root):
        os.remove(doc(root))

    clean = os.path.join(base, "seed")
    build_tree(clean)

    case("clean", lambda r: None, [], 0)
    case("doc-contradicts-centroids",
         append("\nThe shipping binary does not load centroids yet.\n"), ["S-01"], 1)
    case("doc-missing-centroids", drop(r"`centroid\.bin` is loaded"), ["S-01"], 1)
    case("doc-contradicts-node",
         append('\nThere is no "start a node" command; `node` is P6.\n'), ["S-02"], 1)
    case("doc-missing-node", drop(r"`node run` starts a node"), ["S-02"], 1)
    case("card-weakened",
         edit("lab/experiments/E-0121-a2.md", "verdict: supports", "verdict: refutes"), ["S-01"], 1)
    case("symbol-gone",
         edit("crates/vecdht-cli/src/node_cmd.rs", ".with_centroids(", ".without_centroids("), ["S-01"], 1)
    case("test-gone", remove("crates/vecdht-cli/tests/node_centroids.rs"), ["S-01"], 1)
    case("filter-card-pending",
         edit("lab/experiments/E-0144-a3.md", "verdict: supports", "verdict: pending"), ["S-03"], 1)
    case("prose-number",
         append("\nThe guard checks 1333 backtick citations.\n"), ["S-04"], 1)
    case("guard-unnamed", drop(r"check-artifact-refs\.py"), ["S-04"], 1)
    case("card-node-gone", remove("lab/experiments/E-0119-a1.md"), ["S-02"], 1)
    case("doc-absent", missing_doc, [], 2)

    total = len(cases)
    passed = sum(1 for _, ok in cases if ok)
    for name, ok in cases:
        print("СЕЛФТЕСТ_СЛУЧАЙ %s %s" % (name, "OK" if ok else "FAIL"))
    print("СЕЛФТЕСТ_ИТОГ total=%d passed=%d failed=%d" % (total, passed, total - passed))
    shutil.rmtree(base, ignore_errors=True)
    return 0 if passed == total else 1


def main(argv):
    ap = argparse.ArgumentParser(description="статус-документ против дерева (H-0143)")
    ap.add_argument("mode", nargs="?", default="check", choices=("check", "selftest"))
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--doc", default=None)
    ns = ap.parse_args(argv)
    if ns.mode == "selftest":
        return selftest()
    root = os.path.abspath(ns.root)
    doc = os.path.abspath(ns.doc) if ns.doc else os.path.join(root, DOC_DEFAULT)
    code, out, _ = evaluate(root, doc)
    print("\n".join(out))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
