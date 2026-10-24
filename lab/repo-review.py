#!/usr/bin/env python3
"""repo-review.py — самопроверка репозитория после цикла (слово владельца 2026-10-24).

Что делает: проходит по всему дереву и ищет слабые подходы, которые уже случались в этом
репозитории, а не «вообще плохие практики»:

  stale-refs            ссылка `путь:строка` в документе указывает за конец файла;
  closed-empty-result   карточка закрыта, а результата в ней нет (или остался заголовок-пустышка);
  testing-closed        гипотеза `testing`, а её эксперимент уже вынес вердикт;
  ignored-no-reason     `#[ignore]` без причины: отключённый тест без объяснения — это тишина;
  expect-orphans        таблица ожиданий без helper'а или карточки эксперимента;
  helper-orphans        helper цикла не назван в своей карточке (воспроизвести прогон нечем);
  missing-experiments   карточка гипотезы ссылается на несуществующий эксперимент.

Плюс инвентарь без вердикта: размеры больших `.rs`, число `TODO/FIXME`, число `#[ignore]`.
Вывод детерминирован: `REVIEW_*`-факты и строки `НАХОДКА <класс>: <путь> — <причина>`.
`selftest` строит временное дерево с посаженными дефектами каждого класса и чистый контроль.

Запуск: python lab/repo-review.py [check|selftest] [--root ПУТЬ]
"""
import glob
import io
import os
import re
import shutil
import sys
import tempfile

SKIP_DIRS = {"target", ".git", "node_modules", "__pycache__"}
CLOSED_STATUS = {"supported", "refuted", "satisfies", "closed"}
BIG_RS_LINES = 1500
RESULT_MIN = 80
RESULT_HEADINGS = re.compile(r"^##\s+(Результат|Итог)\b", re.M | re.I)
HEADING_ANY = re.compile(r"^##\s+", re.M)
REF = re.compile(r"(?<![\w/.:-])([A-Za-z0-9_][A-Za-z0-9_./\\-]*\.(?:rs|py|sh|md|toml|jsonl|tsv|lean)):(\d+)")


def read(path):
    try:
        return io.open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def walk(root, suffix):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(suffix):
                out.append(os.path.join(dirpath, name))
    return sorted(out)


def rel(root, path):
    return os.path.relpath(path, root).replace("\\", "/")


def front_matter(path):
    text = read(path)
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    head = text[3:end]
    body = text[end + 4:]
    data = {}
    for line in head.splitlines():
        m = re.match(r"^([a-z_]+):\s*(.*)$", line)
        if m:
            data[m.group(1)] = m.group(2).strip()
    return data, body


def section_text(body, pattern):
    m = pattern.search(body)
    if not m:
        return None
    rest = body[m.end():]
    nxt = HEADING_ANY.search(rest)
    return rest[:nxt.start()] if nxt else rest


def line_count(path):
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return -1


def check_refs(root):
    stale, ok, unresolved = [], 0, 0
    for path in walk(root, ".md"):
        text = read(path)
        for m in REF.finditer(text):
            ref, line_no = m.group(1), int(m.group(2))
            target = ref if os.path.isfile(os.path.join(root, ref)) else None
            if target is None:
                base = os.path.basename(ref)
                hits = [p for p in glob.glob(os.path.join(root, "**", base), recursive=True)
                        if os.path.isfile(p) and not any(s in p.split(os.sep) for s in SKIP_DIRS)]
                if len(hits) == 1:
                    target = hits[0]
                else:
                    unresolved += 1
                    continue
            total = line_count(target)
            if total >= 0 and line_no > total:
                stale.append((rel(root, path), ref, line_no, total))
            else:
                ok += 1
    return ok, stale, unresolved


def check_cards(root):
    findings = []
    experiments = {}
    for path in sorted(glob.glob(os.path.join(root, "lab", "experiments", "E-*.md"))):
        fm, _ = front_matter(path)
        eid = fm.get("id") or ""
        if eid:
            experiments[eid] = (path, fm)
    hyps = []
    for path in sorted(glob.glob(os.path.join(root, "lab", "hypotheses", "H-*.md"))):
        fm, body = front_matter(path)
        hyps.append((path, fm, body))
    for path, fm, body in hyps:
        status = fm.get("status", "").strip()
        if "lean" in fm and status in CLOSED_STATUS:
            text = section_text(body, RESULT_HEADINGS)
            if text is None:
                findings.append(("closed-empty-result", path,
                                 "нет раздела «Результат»/«Итог» при status=%s" % status))
            elif len(text.strip()) < RESULT_MIN or text.strip().lower().startswith("заполняется"):
                findings.append(("closed-empty-result", path,
                                 "раздел результата пуст или остался заготовкой при status=%s" % status))
    for path, fm, body in hyps:
        if fm.get("status", "").strip() != "testing":
            continue
        # `testing` при закрытом эксперименте — не всегда дефект: `H-0089` сознательно остаётся
        # testing, пока окно полезности не набрано, и объясняет это в разделе результата. Поэтому
        # находка ставится только там, где объяснения нет.
        explained = section_text(body, RESULT_HEADINGS)
        if explained is not None and len(explained.strip()) >= RESULT_MIN:
            continue
        for eid in sorted(set(re.findall(r"E-\d{4}", fm.get("experiments", "")))):
            if eid in experiments and experiments[eid][1].get("verdict", "").strip() not in ("", "pending"):
                verdict = experiments[eid][1].get("verdict")
                findings.append(("testing-closed", path,
                                 "status=testing, а %s уже вынес вердикт %s" % (eid, verdict)))
                break
    for path, fm, _ in hyps:
        for eid in sorted(set(re.findall(r"E-\d{4}", fm.get("experiments", "")))):
            if eid not in experiments:
                findings.append(("missing-experiments", path, "нет карточки эксперимента %s" % eid))
    for eid, (path, fm) in sorted(experiments.items()):
        verdict = fm.get("verdict", "").strip()
        if "result" in fm and verdict not in ("", "pending"):
            if fm.get("result", "").strip().lower() in ("", "null", '""'):
                findings.append(("closed-empty-result", path,
                                 "verdict=%s, а поле result пусто" % verdict))
    return findings, experiments


def check_ignored(root):
    annotations, findings = [], []
    for path in walk(root, ".rs"):
        lines = read(path).splitlines()
        for i, line in enumerate(lines):
            if not line.strip().startswith("#[ignore"):
                continue
            annotations.append((rel(root, path), i + 1))
            if not re.search(r'ignore[^\]]*"[^"]{10,}"', line):
                findings.append(("ignored-no-reason", path,
                                 "строка %d: #[ignore] без причины в кавычках" % (i + 1)))
    return annotations, findings


def check_orphans(root):
    findings = []
    for table in sorted(glob.glob(os.path.join(root, "lab", "expectations", "e*.tsv"))):
        tag = os.path.basename(table)[1:5]
        helper = os.path.join(root, "lab", "e%s-run.sh" % tag)
        cards = glob.glob(os.path.join(root, "lab", "experiments", "E-%s-*.md" % tag))
        if not os.path.isfile(helper):
            findings.append(("expect-orphans", table, "нет helper'а lab/e%s-run.sh" % tag))
        if not cards:
            findings.append(("expect-orphans", table, "нет карточки E-%s" % tag))
    for helper in sorted(glob.glob(os.path.join(root, "lab", "e*-run.sh"))):
        tag = os.path.basename(helper)[1:5]
        cards = glob.glob(os.path.join(root, "lab", "experiments", "E-%s-*.md" % tag))
        if not cards:
            findings.append(("helper-orphans", helper, "helper без карточки E-%s" % tag))
            continue
        fm, body = front_matter(cards[0])
        if "result" not in fm:
            continue  # историческая карточка: конвенция другая, не переписываем
        if os.path.basename(helper) not in read(cards[0]):
            findings.append(("helper-orphans", helper,
                             "не назван в карточке %s: прогон не воспроизводится" %
                             os.path.basename(cards[0])))
    return findings


def check_inventory(root):
    todos = 0
    big = []
    for path in walk(root, ".rs"):
        text = read(path)
        todos += len(re.findall(r"\b(?:TODO|FIXME|XXX)\b", text))
        n = text.count("\n") + 1
        if n > BIG_RS_LINES:
            big.append((rel(root, path), n))
    return todos, big


def review(root):
    findings = []
    ok, stale, unresolved = check_refs(root)
    for doc, ref, line_no, total in stale:
        findings.append(("stale-refs", os.path.join(root, doc),
                         "%s:%d, а в файле %d строк" % (ref, line_no, total)))
    card_findings, experiments = check_cards(root)
    findings += card_findings
    annotations, ign = check_ignored(root)
    findings += ign
    findings += check_orphans(root)
    todos, big = check_inventory(root)
    md = len(walk(root, ".md"))
    facts = {
        "REVIEW_MD_FILES": md,
        "REVIEW_REFS_OK": ok,
        "REVIEW_REFS_STALE": len(stale),
        "REVIEW_REFS_UNRESOLVED": unresolved,
        "REVIEW_CLOSED_EMPTY": sum(1 for f in findings if f[0] == "closed-empty-result"),
        "REVIEW_TESTING_CLOSED": sum(1 for f in findings if f[0] == "testing-closed"),
        "REVIEW_IGNORED": len(annotations),
        "REVIEW_IGNORED_NO_REASON": sum(1 for f in findings if f[0] == "ignored-no-reason"),
        "REVIEW_EXPECT_ORPHANS": sum(1 for f in findings if f[0] == "expect-orphans"),
        "REVIEW_HELPER_ORPHANS": sum(1 for f in findings if f[0] == "helper-orphans"),
        "REVIEW_MISSING_EXPERIMENTS": sum(1 for f in findings if f[0] == "missing-experiments"),
        "REVIEW_TODOS": todos,
        "REVIEW_BIG_RS": len(big),
    }
    ranked = sorted(findings, key=lambda f: (f[0], rel(root, f[1]) if os.path.isabs(f[1]) else f[1]))
    facts["REVIEW_FINDINGS"] = len(ranked)
    if ranked:
        counts = {}
        for cls, _, _ in ranked:
            counts[cls] = counts.get(cls, 0) + 1
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        facts["REVIEW_TOP"] = "%s:%d" % top
    else:
        facts["REVIEW_TOP"] = "none:0"
    return facts, ranked, big


def print_report(root, facts, ranked, big):
    for key in sorted(facts):
        print("%s=%s" % (key, facts[key]))
    for path, n in sorted(big, key=lambda x: (-x[1], x[0])):
        print("ИНВЕНТАРЬ большой| %s строк=%d (порог %d)" % (path, n, BIG_RS_LINES))
    for cls, path, why in ranked:
        shown = rel(root, path) if os.path.isabs(path) else path.replace("\\", "/")
        print("НАХОДКА %s: %s — %s" % (cls, shown, why))


def make_tree(base):
    def put(relpath, text):
        full = os.path.join(base, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        io.open(full, "w", encoding="utf-8", newline="\n").write(text)
    put("docs/a.md", "Ссылка `lib.rs:999` уходит за конец.\n")
    put("crates/x/src/lib.rs", "fn a() {}\nfn b() {}\n")
    put("lab/hypotheses/H-0001-closed-empty.md",
        "---\nid: H-0001\nstatus: supported\nexperiments: [E-0001]\nlean:\n  решение: \"не применён\"\n---\n\n## Результат\n\n## Зачем\n")
    put("lab/experiments/E-0001-x.md",
        "---\nid: E-0001\nhypothesis: H-0001\nstatus: completed\nverdict: supports\nresult: null\n---\n")
    put("lab/hypotheses/H-0002-stuck.md",
        "---\nid: H-0002\nstatus: testing\nexperiments: [E-0002, E-0404]\nlean:\n  решение: \"не применён\"\n---\n")
    put("lab/experiments/E-0002-x.md",
        "---\nid: E-0002\nhypothesis: H-0002\nstatus: completed\nverdict: supports\nresult: \"итог есть\"\n---\n")
    put("lab/expectations/e0002.tsv", "X=1\n")
    put("lab/e0003-run.sh", "#!/usr/bin/env bash\n")
    put("crates/x/src/ign.rs", "fn t() {}\n#[ignore]\nfn slow() {}\n")
    return base


def selftest():
    tmp = tempfile.mkdtemp(prefix="repo-review-")
    planted = ["stale-refs", "closed-empty-result", "testing-closed",
               "ignored-no-reason", "expect-orphans", "helper-orphans",
               "missing-experiments"]
    try:
        facts, ranked, _ = review(make_tree(tmp))
        classes = {f[0] for f in ranked}
        missed = [c for c in planted if c not in classes]
        clean_root = tempfile.mkdtemp(prefix="repo-review-clean-")
        try:
            clean_facts, clean_ranked, _ = review(clean_root)
        finally:
            shutil.rmtree(clean_root, ignore_errors=True)
        clean_ok = clean_facts["REVIEW_FINDINGS"] == 0
        total = len(planted) + 1
        passed = total - len(missed) - (0 if clean_ok else 1)
        print("REVIEW_SELFTEST total=%d passed=%d" % (total, passed))
        for c in planted:
            mark = "ОТБИТ" if c in classes else "ПРОПУЩЕН"
            print("  КЕЙС %s: %s" % (c, mark))
        print("  КЕЙС чистое_дерево: %s (находок=%d)" %
              ("OK" if clean_ok else "ЛОЖНАЯ ТРЕВОГА", clean_facts["REVIEW_FINDINGS"]))
        return 0 if passed == total else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    mode = "check"
    root = os.environ.get("VEC_DHT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    args = list(argv[1:])
    if args and not args[0].startswith("--"):
        mode = args.pop(0)
    if "--root" in args:
        root = args[args.index("--root") + 1]
    if mode == "selftest":
        return selftest()
    if mode != "check":
        print("режим %r неизвестен: check|selftest" % mode)
        return 2
    facts, ranked, big = review(root)
    print_report(root, facts, ranked, big)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
