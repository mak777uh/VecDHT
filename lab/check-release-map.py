#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Релиз-карта как проверяемое утверждение (`H-0148`).

`docs/RELEASE-MAP-v1.md` читает посторонний, чтобы решить, можно ли ставить тег. Документ сам
обещает: «каждая строка обязана назвать исполняемый прибор или id замера, иначе строка помечена
словом „не проверено“». Прибор исполняет это обещание механически:

* каждая табличная строка зарегистрирована в `lab/release-map-rows.tsv` под своим id (`M-01…`);
* названный владелец — карточка (`E-…`), ADR (`ADR-…`) или файл прибора — существует в дереве,
  а карточка закрыта (`status: completed|closed`); вердикт карточки не требуется `supports`:
  карта ссылается и на `refutes`-карточки как на названный замер;
* обязательные слова строки (положительная форма) стоят на месте, запрещённые (старая ложь)
  отсутствуют;
* у строки, где объявлены числа, каждое число сверено с носителем: `spec` — спека, `card:E-…` —
  карточка и её цитатный лог `lab/logs/eXXXX-all.log`, `test:<путь>` — файл прибора. Числа строк,
  где в реестре стоит `none`, прибор не сверяет — это названная граница, а не молчание.

Строка-отсутствие (`cards` и `paths` пусты) обязана содержать слово отсутствия; это тот же класс,
что строки-отсутствия в `check-status-claims.py`.

Выход: 0 — карта согласована с деревом; 1 — есть находка (печатает id и причину); 2 — документ,
реестр или корень не читается.

`selftest` строит временное дерево и пятнадцать посаженных случаев: положительный контроль,
незарегистрированная строка, пропавшая строка, стёртый владелец, открытая карточка, пропавшая
карточка, пропавший файл прибора, запрещённая фраза, подменённое число, сломанная провенанс-ссылка,
пропавшее обязательное слово, пропавший ADR, дубль строки, отсутствующий документ и отсутствующий
реестр.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import sys
import tempfile

DOC_DEFAULT = "docs/RELEASE-MAP-v1.md"
REG_DEFAULT = "lab/release-map-rows.tsv"
ABSENCE = re.compile(r"не измерен|не проверено|не выполнено|не подтверждено")


class Row:
    """Одна табличная строка карты и её владельцы из реестра."""

    def __init__(self, rid, key, cards, paths, must, forbid, numbers):
        self.rid = rid
        self.key = key
        self.cards = cards
        self.paths = paths
        self.must = must
        self.forbid = forbid
        self.numbers = numbers


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def norm(text):
    """Число в одну форму: запятая → точка, пробелы убраны, чтобы «4 000» = «4000»."""
    return re.sub(r"[ \u00a0]+", "", text.replace(",", "."))


def num_tokens(text):
    """Числовые ядра строки; номера §, id, даты и дроби имён файлов не считаются."""
    out = []
    for m in re.finditer(r"(?<![\w§./-])(\d[\d \u00a0]*(?:[.,]\d+)?)", text):
        tok = norm(m.group(1))
        if tok and tok not in out:
            out.append(tok)
    return out


def parse_rows(doc):
    rows = {}
    order = []
    dup = []
    for line in doc.splitlines():
        if not line.startswith("|"):
            continue
        if re.fullmatch(r"\|[\s:|-]+\|", line.strip()):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or cells[0] == "Гейт":
            continue
        key = cells[0]
        if key in rows:
            dup.append(key)
            continue
        rows[key] = {"evidence": cells[1], "state": cells[2], "rest": cells[3]}
        order.append(key)
    return rows, order, dup


def load_registry(path):
    reg = []
    errors = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line or line.lstrip().startswith("#"):
                continue
            cells = line.split("\t")
            if len(cells) != 7:
                errors.append("строка %d: колонок %d, ожидалось 7" % (n, len(cells)))
                continue
            rid, key, cards, paths, must, forbid, numbers = [c.strip() for c in cells]

            def split(s):
                return [] if s in ("", "-") else [x.strip() for x in s.split(";") if x.strip()]

            reg.append(Row(
                rid, key,
                [] if cards in ("", "-") else [x.strip() for x in cards.split(",") if x.strip()],
                [] if paths in ("", "-") else [x.strip() for x in paths.split(",") if x.strip()],
                split(must), split(forbid),
                [] if numbers in ("", "none") else [x.strip() for x in numbers.split(";") if x.strip()],
            ))
    return reg, errors


def card_files(root, eid):
    return glob.glob(os.path.join(root, "lab", "experiments", eid + "-*.md"))


def card_status(path):
    text = read_text(path)
    m = re.search(r"^status:\s*[\"']?([A-Za-z_-]+)", text, re.M)
    return m.group(1) if m else "none"


def adr_files(root, aid):
    return glob.glob(os.path.join(root, "lab", "decisions", "*" + aid + "*.md"))


def carrier_files(root, eid):
    num = eid.split("-")[-1].lower()
    return glob.glob(os.path.join(root, "lab", "logs", "e%s-*.log" % num))


def prov_ok(root, prov, token, cards, spec_text):
    """Провенанс одного числа. Возвращает (ok, причина)."""
    if prov == "spec":
        return (norm(token) in norm(spec_text), "spec")
    if prov.startswith("card:"):
        eid = prov.split(":", 1)[1]
        if eid not in cards:
            return (False, "card-not-in-row:" + eid)
        src = ""
        for p in card_files(root, eid):
            src += read_text(p)
        for p in carrier_files(root, eid):
            src += read_text(p)
        return (norm(token) in norm(src), "card:" + eid)
    if prov.startswith("test:"):
        rel = prov.split(":", 1)[1]
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            return (False, "test-missing:" + rel)
        return (norm(token) in norm(read_text(p)), "test:" + rel)
    return (False, "unknown-prov:" + prov)


def evaluate(root, doc_path, reg_path):
    if not os.path.isdir(root):
        return 2, ["MAP_EXIT=2", "MAP_ERROR=корень не каталог"], {}
    if not os.path.isfile(doc_path):
        return 2, ["MAP_EXIT=2", "MAP_ERROR=документ не читается"], {}
    if not os.path.isfile(reg_path):
        return 2, ["MAP_EXIT=2", "MAP_ERROR=реестр не читается"], {}
    doc = read_text(doc_path)
    reg, reg_errors = load_registry(reg_path)
    rows, order, dup = parse_rows(doc)

    findings = []
    facts_total = 0
    facts_ok = 0
    owners = 0
    owners_missing = []
    stale_rows = []
    numbers = 0
    numbers_ok = 0
    numbers_undeclared = []
    prov_bad = []

    ids = {}
    for row in reg:
        if row.rid in ids:
            findings.append("%s duplicate-id" % row.rid)
        ids[row.rid] = row
    by_key = {}
    for row in reg:
        by_key[row.key] = row

    # Глобальные владельцы документа: каждая карточка, ADR и путь.
    eids = sorted(set(re.findall(r"\bE-\d{4}\b", doc)))
    eids_missing = []
    eids_open = []
    for eid in eids:
        files = card_files(root, eid)
        if not files:
            eids_missing.append(eid)
            continue
        if card_status(files[0]) not in ("completed", "closed"):
            eids_open.append(eid)

    adrs = sorted(set(re.findall(r"\bADR-\d{4}\b", doc)))
    adrs_missing = [a for a in adrs if not adr_files(root, a)]

    paths = []
    for span in re.findall(r"`([^`]+)`", doc):
        if "/" not in span or any(ch.isspace() for ch in span):
            continue
        if span.startswith("/p2p") or "<" in span:
            continue
        paths.append(span)
    paths = sorted(set(paths))
    paths_missing = [p for p in paths if not os.path.exists(os.path.join(root, p))]

    spec_path = os.path.join(root, "docs", "VecDHT-SPEC-v8.md")
    spec_text = read_text(spec_path) if os.path.isfile(spec_path) else ""

    # Строки документа против реестра.
    unregistered = [k for k in order if k not in by_key]
    for key in unregistered:
        findings.append("row-unregistered " + key)
    missing_rows = [r.rid + ":" + r.key for r in reg if r.key not in rows]
    for item in missing_rows:
        findings.append("row-missing " + item)

    prev_evidence = ""
    for row in reg:
        if row.key not in rows:
            continue
        cells = rows[row.key]
        whole = " | ".join(cells.values())
        cards = list(row.cards)
        rpaths = list(row.paths)
        inherited = False
        if cards == ["@prev"] or rpaths == ["@prev"]:
            inherited = True
            cards = [] if cards == ["@prev"] else cards
            rpaths = [] if rpaths == ["@prev"] else rpaths
            if not prev_evidence:
                owners_missing.append(row.rid + ":no-prev")
                findings.append(row.rid + " inherit-without-prev")
            else:
                owners += 1
        else:
            if not cards and not rpaths:
                if ABSENCE.search(cells["state"]):
                    owners += 1
                else:
                    owners_missing.append(row.rid + ":no-owner")
                    findings.append(row.rid + " absence-row-without-absence-word")
            else:
                named_cards = [c for c in cards if c in cells["evidence"]]
                named_paths = [p for p in rpaths if p in cells["evidence"]]
                if len(named_cards) == len(cards) and len(named_paths) == len(rpaths):
                    owners += 1
                else:
                    owners_missing.append(row.rid + ":owner-not-named")
                    findings.append(row.rid + " owner-not-named")

        for token in row.must:
            facts_total += 1
            if token in cells["state"]:
                facts_ok += 1
            else:
                findings.append(row.rid + " fact-missing " + token)

        for token in row.forbid:
            if token in whole:
                stale_rows.append(row.rid)
                findings.append(row.rid + " stale " + token)

        if row.numbers:
            toks = num_tokens(cells["evidence"] + " " + cells["state"] + " " + cells["rest"])
            declared = []
            for item in row.numbers:
                if "=>" not in item:
                    findings.append(row.rid + " number-without-provenance " + item)
                    continue
                tok, prov = [x.strip() for x in item.split("=>", 1)]
                declared.append(norm(tok))
                numbers += 1
                ok, why = prov_ok(root, prov, tok, cards, spec_text)
                if ok:
                    numbers_ok += 1
                else:
                    prov_bad.append(row.rid + ":" + tok + ":" + why)
                    findings.append(row.rid + " provenance-bad " + tok + " " + why)
            for tok in toks:
                if tok not in declared:
                    numbers_undeclared.append(row.rid + ":" + tok)
                    findings.append(row.rid + " number-undeclared " + tok)
        prev_evidence = cells["evidence"]

    for msg in reg_errors:
        findings.append("registry " + msg)
    for key in dup:
        findings.append("row-duplicate " + key)
    for eid in eids_missing:
        findings.append("card-missing " + eid)
    for eid in eids_open:
        findings.append("card-open " + eid)
    for aid in adrs_missing:
        findings.append("adr-missing " + aid)
    for p in paths_missing:
        findings.append("path-missing " + p)

    code = 1 if findings else 0
    out = [
        "MAP_DOC=%s" % os.path.relpath(doc_path, root).replace(os.sep, "/") if doc_path.startswith(root)
        else "MAP_DOC=" + doc_path.replace(os.sep, "/"),
        "MAP_ROWS=%d" % len(order),
        "ROWS_REGISTERED=%d" % sum(1 for r in reg if r.key in rows),
        "ROWS_UNREGISTERED=%d" % len(unregistered),
        "ROWS_MISSING=%d" % len(missing_rows),
        "MAP_DUP=%d" % len(dup),
        "EIDS=%d" % len(eids),
        "EIDS_MISSING=%d" % len(eids_missing),
        "EIDS_OPEN=%d" % len(eids_open),
        "ADRS=%d" % len(adrs),
        "ADRS_MISSING=%d" % len(adrs_missing),
        "PATHS=%d" % len(paths),
        "PATHS_MISSING=%d" % len(paths_missing),
        "OWNERS=%d" % owners,
        "OWNERS_MISSING=%d" % len(owners_missing),
        "OWNERS_MISSING_IDS=%s" % (",".join(owners_missing) if owners_missing else "none"),
        "FACTS=%d" % facts_total,
        "FACTS_OK=%d" % facts_ok,
        "STALE=%d" % len(stale_rows),
        "STALE_ROWS=%s" % (",".join(sorted(set(stale_rows))) if stale_rows else "none"),
        "NUMBERS=%d" % numbers,
        "NUMBERS_OK=%d" % numbers_ok,
        "NUMBERS_UNDECLARED=%d" % len(numbers_undeclared),
        "NUMBERS_UNDECLARED_IDS=%s" % (",".join(numbers_undeclared) if numbers_undeclared else "none"),
        "PROV_BAD=%d" % len(prov_bad),
        "MAP_OK=%d" % (1 if code == 0 else 0),
        "MAP_EXIT=%d" % code,
    ]
    body = ["НАХОДКА " + f for f in findings]
    return code, body + out, {"findings": findings, "rows": len(order)}


# --- самопроверка -------------------------------------------------------------------------

CLEAN_MAP = """# Release map

| Гейт | Чем закрыт | Состояние | Что нужно |
|---|---|---|---|
| (a) alpha | `crates/x/t.rs`, `E-9001`, `ADR-9001` | выполнено: 10 мс | нечего |
| P3 beta 1M записей ≤ 428 МБ | `crates/x/m.rs`, `E-9001` | выполнено: 417,5 МиБ, 437,7 Б/запись | нечего |
| P4 gamma | `crates/x/g.rs` | выполнено: 5 с | нечего |
"""

CLEAN_REG = """# id\tkey\tcards\tpaths\tmust\tforbid\tnumbers
M-01\t(a) alpha\tE-9001\tcrates/x/t.rs\t10 мс\t-\tnone
M-02\tP3 beta 1M записей ≤ 428 МБ\tE-9001\tcrates/x/m.rs\t417,5;437,7\tна фикстуре\t1=>card:E-9001;428=>spec;417.5=>card:E-9001;437.7=>card:E-9001
M-03\tP4 gamma\t-\tcrates/x/g.rs\t5 с\t-\tnone
"""


def build_tree(root):
    def put(rel, text):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    put("docs/RELEASE-MAP-v1.md", CLEAN_MAP)
    put("lab/release-map-rows.tsv", CLEAN_REG)
    put("docs/VecDHT-SPEC-v8.md", "бюджет 428 МБ; всё в MiB\n")
    put("lab/experiments/E-9001-a.md",
        "---\nid: E-9001\nstatus: completed\nverdict: supports\n---\n# E\n"
        "1M записей: 417,5 МиБ, 437,7 Б/запись\n")
    put("lab/logs/e9001-all.log", "MEM_TOTAL_MIB=417\nMEM_PER_ENTRY_TENTHS=4377\n")
    put("lab/decisions/ADR-9001-test.md", "# ADR-9001\n")
    put("crates/x/t.rs", "// 10 мс\n")
    put("crates/x/m.rs", "const BUDGET: usize = 428 * MIB;\n")
    put("crates/x/g.rs", "// 5 с\n")


def selftest():
    base = tempfile.mkdtemp(prefix="release-map-")
    seed = os.path.join(base, "seed")
    build_tree(seed)
    cases = []

    def case(name, mutate, expect_exit, expect_fact=None):
        root = os.path.join(base, name)
        shutil.copytree(seed, root)
        mutate(root)
        code, out, _ = evaluate(
            root,
            os.path.join(root, DOC_DEFAULT),
            os.path.join(root, REG_DEFAULT),
        )
        text = "\n".join(out)
        ok = code == expect_exit
        if ok and expect_fact:
            key, want = expect_fact
            m = re.search(r"^%s=(.*)$" % key, text, re.M)
            got = m.group(1) if m else "none"
            ok = got == want
            if not ok:
                print("СЕЛФТЕСТ_СЛУЧАЙ %s FAIL %s=%s ожидалось %s" % (name, key, got, want))
        elif not ok:
            print("СЕЛФТЕСТ_СЛУЧАЙ %s FAIL код=%d ожидалось %d" % (name, code, expect_exit))
        cases.append((name, ok))

    def doc(root):
        return os.path.join(root, DOC_DEFAULT)

    def reg(root):
        return os.path.join(root, REG_DEFAULT)

    def append_doc(text):
        def _m(root):
            with open(doc(root), "a", encoding="utf-8") as fh:
                fh.write(text)
        return _m

    def edit(rel, old, new):
        def _m(root):
            p = os.path.join(root, rel)
            t = read_text(p)
            assert old in t, "посадка не нашла " + old
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(t.replace(old, new, 1))
        return _m

    def drop(rel, pattern):
        def _m(root):
            p = os.path.join(root, rel)
            t = read_text(p)
            t2 = re.sub(pattern, "", t)
            assert t2 != t, "посадка не изменила " + rel
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(t2)
        return _m

    def remove(rel):
        def _m(root):
            os.remove(os.path.join(root, rel))
        return _m

    def open_card(root):
        edit("lab/experiments/E-9001-a.md", "status: completed", "status: open")(root)

    def broken_prov(root):
        edit("lab/experiments/E-9001-a.md", "417,5", "ноль")(root)
        edit("lab/logs/e9001-all.log", "417", "ноль")(root)

    def duplicate_row(root):
        with open(doc(root), "a", encoding="utf-8") as fh:
            fh.write("| (a) alpha | `crates/x/t.rs`, `E-9001` | выполнено: 10 мс | нечего |\n")

    case("clean", lambda r: None, 0, ("MAP_ROWS", "3"))
    case("unregistered", append_doc("| (z) omega | `crates/x/t.rs` | выполнено | нечего |\n"),
         1, ("ROWS_UNREGISTERED", "1"))
    case("missing-row", drop(DOC_DEFAULT, r"\| P4 gamma .*\n"), 1, ("ROWS_MISSING", "1"))
    case("owner-removed", edit(DOC_DEFAULT, "`crates/x/t.rs`, `E-9001`, `ADR-9001`", "текст"),
         1, ("OWNERS_MISSING", "1"))
    case("card-open", open_card, 1, ("EIDS_OPEN", "1"))
    case("card-missing", remove("lab/experiments/E-9001-a.md"), 1, ("EIDS_MISSING", "1"))
    case("path-missing", remove("crates/x/t.rs"), 1, ("PATHS_MISSING", "1"))
    case("stale-phrase", edit(DOC_DEFAULT, "выполнено: 417,5", "на фикстуре: 417,5"),
         1, ("STALE", "1"))
    case("number-changed", edit(DOC_DEFAULT, "417,5", "477,5"), 1, ("NUMBERS_UNDECLARED", "1"))
    case("provenance-broken", broken_prov, 1, ("PROV_BAD", "1"))
    case("fact-missing", edit(DOC_DEFAULT, "выполнено: 10 мс", "выполнено"), 1)
    case("adr-missing", remove("lab/decisions/ADR-9001-test.md"), 1, ("ADRS_MISSING", "1"))
    case("duplicate-row", duplicate_row, 1, ("MAP_DUP", "1"))
    case("doc-missing", remove(DOC_DEFAULT), 2)
    case("registry-missing", remove(REG_DEFAULT), 2)

    bad = [n for n, ok in cases if not ok]
    print("СЕЛФТЕСТ total=%d passed=%d failed=%d" %
          (len(cases), len(cases) - len(bad), len(bad)))
    return 0 if not bad else 1


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    if argv[1:] and argv[1] == "selftest":
        return selftest()
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--doc", default=None)
    ap.add_argument("--reg", default=None)
    ns = ap.parse_args(argv[1:])
    root = os.path.abspath(ns.root)
    doc = ns.doc or os.path.join(root, DOC_DEFAULT)
    reg = ns.reg or os.path.join(root, REG_DEFAULT)
    code, out, _ = evaluate(root, doc, reg)
    print("\n".join(out))
    return 0 if code == 0 else code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
