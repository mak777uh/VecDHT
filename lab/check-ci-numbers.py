#!/usr/bin/env python3
"""Страж чисел в шапке CI (`E-0154`).

Почему он появился. Шапка `.github/workflows/verify.yml` — самый дисциплинированный комментарий в
репозитории: она печатает числа вместе с командами пересчёта. Команды в комментарии исполняются
только тогда, когда кто-то их набирает. Никто не набирал: на пине круга (и раньше, с `f7294f9`)
шапка обещает 762 декларации `#[test]` и 764 всего, а теми же командами по дереву считается 802 и
804; разбивка по крейтам устарела в пяти именах из девяти; производные «203 из 764», «27 %»,
«остальные 561» и «~764 теста» не следуют ни из каких актуальных чисел. Ни один из семнадцати
существовавших приборов над этим не краснел: они сверяют подключение приборов, цитаты путей,
исполнение боевых режимов и адреса карточек, но не арифметику комментария. Носитель круга гоняет
шестнадцать из семнадцати над деревом пина; семнадцатый, `check-secrets.sh`, читает всю историю и
чисел шапки не свёрстывает — это названо в карточке.

Что проверяется (четыре формы утверждения, всё остальное — проза):

* (а) командно-привязанное: строка вида `# <grep …> | wc -l   # 762`. Команда обязана быть в
  Frozen-таблице `KNOWN_COMMANDS` — иначе `CIN_UNKNOWN_COMMAND`: новое определение нельзя вписать
  в шапку так, чтобы его никто не пересчитывал;
* (б) разбивка по крейтам: `wire 57`, `orders 16`, … для всех девяти имён. Пропавшее имя —
  `CIN_BREAKDOWN_MISSING`, одно имя с двумя разными числами — `CIN_PAIR_MULTIPLE`;
* (в) производные фразы: `N из M`, `всего N`, `остальные N`, `(N %)`, `~N теста` — сверяются
  арифметически с (а) и (б);
* (г) определение счёта: в шапке обязана стоять строка `Определение счёта:`, и в ней — `crates/`,
  `*.rs`, `tests/` и `target`. Без неё расхождение «cli 79 или 102» невозможно ни подтвердить, ни
  опровергнуть (это полу-находка внешней рецензии: «определение нигде не записано»).

Истина дерева считается одним кодом: все `*.rs` под `crates/`, каталоги `SKIP_DIRS` не читаются,
метка — вхождение литерала. Прибор сверяет написанное с написанным по одному правилу, а не считает
исполняемые кейсы: что именно исполнит `cargo test --workspace`, — другой факт, его печатает
верификация цикла.

Код возврата: 0 — все утверждения равны дереву; 1 — есть расхождение, отсутствующее утверждение
или незнакомая команда; 2 — дерево или файл контура не читаются (прибор не делает вид, что
сверил). `--selftest` исполняет семь посаженных форм на временном дереве и ничего не трогает
в репозитории.
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKIP_DIRS = {"target", ".git", "node_modules", "__pycache__", ".venv"}
CRATE_NAMES = ("wire", "orders", "crypto", "artifact", "index", "node", "net", "embed", "cli")
DEFINITION_MARK = "Определение счёта:"
DEFINITION_TOKENS = ("crates/", "*.rs", "tests/", "target")

# Команда (пробелы свёрнуты) -> ключ пересчёта. Ключи пересчёта печатает count_tree().
KNOWN_COMMANDS = {
    "grep -rhoE '#\\[test\\]' crates --include=*.rs | wc -l": "total_test",
    "grep -rhoE '#\\[tokio::test(\\([^)]*\\))?\\]' crates --include=*.rs | wc -l": "total_tokio",
    "grep -rhoE '#\\[test_case' crates --include=*.rs | wc -l": "total_case",
    "grep -rhoE '^[[:space:]]*#\\[ignore' crates --include=*.rs | wc -l": "ignored",
}

RE_CMD = re.compile(r"^\s*(grep\s.+?)\s+#\s+(\d+)\b.*$")
RE_PAIR = r"\b(%s)\s+(\d+)"
RE_FROM = r"(\d+)(?:(?!\d).){0,60}?из\s+(\d+)"
RE_TOTAL = r"всего\s+(\d+)"
RE_REST = r"остальные\s+(\d+)"
RE_PCT = r"(\d+)\s*%"
RE_TILDE = r"~(\d+)\s+теста"


def die(msg):
    print("CIN_READ=%s" % msg)
    print("CIN_MATCH=0")
    print("CIN_DRIFT_COUNT=none")
    print("CIN_DRIFT=none")
    print("CIN_EXIT=2")
    return 2


def count_tree(root):
    """Истина дерева: вхождения литералов по всем `*.rs` под `crates/`."""
    crates = os.path.join(root, "crates")
    if not os.path.isdir(crates):
        return None
    per = {}
    files = 0
    tot = {"total_test": 0, "total_tokio": 0, "total_case": 0, "ignored": 0}
    for dirpath, dirnames, filenames in os.walk(crates):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".rs"):
                continue
            files += 1
            path = os.path.join(dirpath, fn)
            text = open(path, encoding="utf-8", errors="replace").read()
            short = os.path.relpath(path, crates).split(os.sep)[0]
            short = short[len("vecdht-"):] if short.startswith("vecdht-") else short
            c = per.setdefault(short, {"total_test": 0, "total_tokio": 0,
                                       "total_case": 0, "ignored": 0})
            c["total_test"] += text.count("#[test]")
            c["total_tokio"] += len(re.findall(r"#\[tokio::test(\([^)]*\))?\]", text))
            c["total_case"] += text.count("#[test_case")
            for line in text.splitlines():
                if re.match(r"^[ \t]*#\[ignore", line):
                    c["ignored"] += 1
    for k in tot:
        tot[k] = sum(c[k] for c in per.values())
    tot["total_all"] = tot["total_test"] + tot["total_tokio"] + tot["total_case"]
    for name, c in per.items():
        c["total_all"] = c["total_test"] + c["total_tokio"] + c["total_case"]
    return {"per": per, "tot": tot, "files": files}


def read_header(path):
    """Строки шапки: лидирующий блок комментариев до первой исполняемой строки."""
    if not os.path.isfile(path):
        return None
    raw = []
    for line in open(path, encoding="utf-8", errors="replace").read().splitlines():
        if line.lstrip().startswith("#") or not line.strip():
            raw.append(line)
        else:
            break
    return raw


def claims_of(header):
    """(командные, пары, производные, плоский текст, тело строки без `#`)."""
    bodies = [l.lstrip()[1:] if l.lstrip().startswith("#") else l for l in header]
    cmds = []
    for line in bodies:
        m = RE_CMD.match(line)
        if m:
            cmds.append((re.sub(r"\s+", " ", m.group(1).strip()), int(m.group(2))))
    flat = " ".join(s.strip() for s in bodies)
    pairs = []
    for name in CRATE_NAMES:
        hits = re.findall(RE_PAIR % "|".join(CRATE_NAMES), flat)
        vals = sorted({int(n) for _, n in hits if _ == name})
        cnt = sum(1 for k, _ in hits if k == name)
        pairs.append((name, vals, cnt))
    derived = {
        "from": [(int(a), int(b)) for a, b in re.findall(RE_FROM, flat)],
        "total": [int(x) for x in re.findall(RE_TOTAL, flat)],
        "rest": [int(x) for x in re.findall(RE_REST, flat)],
        "pct": [int(x) for x in re.findall(RE_PCT, flat)],
        "tilde": [int(x) for x in re.findall(RE_TILDE, flat)],
    }
    return cmds, pairs, derived, flat


def check(root, workflow):
    facts = []

    def emit(key, value):
        facts.append((key, value))

    header = read_header(workflow)
    if header is None:
        return die("missing-workflow")
    tree = count_tree(root)
    if tree is None:
        return die("missing-crates-dir")

    tot, per = tree["tot"], tree["per"]
    emit("CIN_HEADER_LINES", len(header))
    emit("CIN_RS_FILES", tree["files"])
    emit("CIN_TOTAL_TEST", tot["total_test"])
    emit("CIN_TOTAL_TOKIO", tot["total_tokio"])
    emit("CIN_TOTAL_CASE", tot["total_case"])
    emit("CIN_TOTAL_ALL", tot["total_all"])
    emit("CIN_IGNORED", tot["ignored"])
    for name in CRATE_NAMES:
        emit("CIN_CRATE_%s" % name.upper(), per.get(name, {}).get("total_test", "absent"))

    drift, unknown, missing, multiple = [], [], [], []
    claims = 0

    # (а) командно-привязанные
    for cmd, claimed in claims_of(header)[0]:
        claims += 1
        key = KNOWN_COMMANDS.get(cmd)
        if key is None:
            unknown.append(cmd)
            continue
        actual = tot.get(key, tot.get("total_%s" % key, None))
        if actual is not None and actual != claimed:
            drift.append("cmd:%s=%s!=%s" % (key, claimed, actual))

    # (б) разбивка по крейтам
    for name, vals, cnt in claims_of(header)[1]:
        if not vals:
            missing.append(name)
            continue
        claims += 1
        if len(vals) > 1:
            multiple.append("%s:%s" % (name, "/".join(str(v) for v in vals)))
            continue
        actual = per.get(name, {}).get("total_test")
        if actual is None:
            missing.append("%s(absent)" % name)
        elif actual != vals[0]:
            drift.append("pair:%s=%s!=%s" % (name, vals[0], actual))

    # (в) производные фразы
    derived = claims_of(header)[2]
    node_test = per.get("node", {}).get("total_test", 0)
    for a, b in derived["from"]:
        claims += 1
        if a != node_test or b != tot["total_all"]:
            drift.append("from:%s/%s!=%s/%s" % (a, b, node_test, tot["total_all"]))
    for x in derived["total"]:
        claims += 1
        if x != tot["total_all"]:
            drift.append("total:%s!=%s" % (x, tot["total_all"]))
    for x in derived["rest"]:
        claims += 1
        if x != tot["total_all"] - node_test:
            drift.append("rest:%s!=%s" % (x, tot["total_all"] - node_test))
    shares = set()
    if tot["total_all"]:
        shares = {int(round(100.0 * node_test / tot["total_all"])),
                  int(round(100.0 * (tot["total_all"] - node_test) / tot["total_all"]))}
    for x in derived["pct"]:
        claims += 1
        if x not in shares:
            drift.append("pct:%s!=%s" % (x, "/".join(str(s) for s in sorted(shares))))
    for x in derived["tilde"]:
        claims += 1
        if x != tot["total_all"]:
            drift.append("tilde:%s!=%s" % (x, tot["total_all"]))

    # (г) определение счёта записано
    flat = claims_of(header)[3]
    pos = flat.find(DEFINITION_MARK)
    if pos < 0:
        definition = "missing"
    else:
        sentence = flat[pos:pos + 400].split(". ")[0]
        definition = "full" if all(tok in sentence for tok in DEFINITION_TOKENS) else "partial"

    red = len(drift) + len(unknown) + len(multiple)
    structural = len(missing) + (0 if definition == "full" else 1)
    emit("CIN_DEFINITION", definition)
    emit("CIN_CLAIMS", claims)
    emit("CIN_UNKNOWN_COMMAND", "|".join(unknown) if unknown else "none")
    emit("CIN_BREAKDOWN_MISSING", "|".join(missing) if missing else "none")
    emit("CIN_PAIR_MULTIPLE", "|".join(multiple) if multiple else "none")
    emit("CIN_DRIFT_COUNT", len(drift))
    emit("CIN_DRIFT", ";".join(drift) if drift else "none")
    emit("CIN_MATCH", claims - red)
    emit("CIN_FINDINGS", red + structural)
    emit("CIN_EXIT", 0 if red + structural == 0 else 1)

    for key, value in facts:
        print("%s=%s" % (key, value))
    return 0 if red + structural == 0 else 1


def cmd_selftest():
    """Семь посаженных форм на временном дереве: прибор обязан краснеть на каждой."""
    import shutil
    import tempfile

    root = tempfile.mkdtemp(prefix="cin-selftest-")
    crates = os.path.join(root, "crates")
    for name in CRATE_NAMES:
        d = os.path.join(crates, "vecdht-%s" % name, "tests")
        os.makedirs(d)
        n = {
            "wire": 3, "orders": 5, "crypto": 2, "artifact": 4, "index": 6,
            "node": 8, "net": 7, "embed": 1, "cli": 9,
        }[name]
        with open(os.path.join(d, "t.rs"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join("#[test]\nfn t%d() {}" % i for i in range(n)) + "\n")
        with open(os.path.join(crates, "vecdht-%s" % name, "src_lib.rs"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write("#[test]\nfn one() {}\n#[ignore]\n")
    # один tokio-тест и один test_case — чтобы «всего» не было суммой только #[test]
    with open(os.path.join(crates, "vecdht-net", "tests", "tokio.rs"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("#[tokio::test(flavor = \"current_thread\")]\nasync fn a() {}\n")
    with open(os.path.join(crates, "vecdht-cli", "tests", "case.rs"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("#[test_case]\nfn b() {}\n")

    wfdir = os.path.join(root, ".github", "workflows")
    os.makedirs(wfdir)
    wf = os.path.join(wfdir, "verify.yml")

    tree = count_tree(root)
    tot, per = tree["tot"], tree["per"]
    node = per["node"]["total_test"]

    def header(good_numbers=True, with_definition=True, with_cli=True):
        lines = [
            "# Разделение по событиям:",
            "#   * `push` в `main` -> полный воркспейс: ~%d теста;" % (
                tot["total_all"] if good_numbers else 4242),
            "#",
            "#     grep -rhoE '#\\[test\\]' crates --include=*.rs | wc -l                     # %d"
            % (tot["total_test"] if good_numbers else tot["total_test"] - 1),
            "#     grep -rhoE '#\\[tokio::test(\\([^)]*\\))?\\]' crates --include=*.rs | wc -l   #   %d"
            % tot["total_tokio"],
            "#     grep -rhoE '#\\[test_case' crates --include=*.rs | wc -l                   #   %d"
            % tot["total_case"],
            "#     ------------------------------------------------------------------------------  всего %d"
            % (tot["total_all"] if good_numbers else tot["total_all"] + 7),
            "#     grep -rhoE '^[[:space:]]*#\\[ignore' crates --include=*.rs | wc -l         #  %d"
            " в --ignored" % tot["ignored"],
            "#",
            "# Разбивка по крейтам (`#[test]`):",
        ]
        pairs = ["%s %d" % (n, per[n]["total_test"]) for n in CRATE_NAMES if with_cli or n != "cli"]
        lines.append("#   " + ", ".join(pairs) + ".")
        lines.append("#   работа `admission` покрывает %d из %d (%d %%), работа `workspace`"
                     " добавляет остальные %d." % (
                         node if good_numbers else node - 3, tot["total_all"],
                         99 if not good_numbers else int(round(100.0 * node / tot["total_all"])),
                         tot["total_all"] - node if good_numbers else 1))
        if with_definition:
            lines.append("#   Определение счёта: все `*.rs` под crates/, включая tests/, "
                         "исключая target/.")
        lines.append("name: verify")
        lines.append("jobs:")
        return "\n".join(lines) + "\n"

    cases = []

    def write(text):
        with open(wf, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    def run():
        out = subprocess.run([sys.executable, os.path.abspath(__file__), "--root", root],
                             capture_output=True, text=True, encoding="utf-8", errors="replace")
        return out.returncode, out.stdout

    write(header())
    rc, out = run()
    cases.append(("green_when_matching", rc == 0 and "CIN_EXIT=0" in out))

    write(header(good_numbers=False))
    rc, out = run()
    hit = all(k in out for k in ("cmd:total_test", "total:", "rest:", "tilde:", "pct:99"))
    cases.append(("stale_numbers_red", rc == 1 and hit))

    write(header(with_cli=False))
    rc, out = run()
    cases.append(("missing_crate_red", rc == 1 and "CIN_BREAKDOWN_MISSING=cli" in out))

    bad = header().replace("#   работа `admission` покрывает",
                           "#     grep -rhoE '#\\[nope\\]' crates | wc -l   # 5\n"
                           "#   работа `admission` покрывает")
    write(bad)
    rc, out = run()
    cases.append(("unknown_command_red",
                  rc == 1 and "CIN_UNKNOWN_COMMAND=grep -rhoE '#\\[nope" in out))

    write(header(with_definition=False))
    rc, out = run()
    cases.append(("no_definition_red",
                  rc == 1 and "CIN_DEFINITION=missing" in out and "CIN_FINDINGS=1" in out))

    # одно имя с двумя разными числами: «cli 9» и добавленное «cli 4» в прозе
    write(header().replace("включая tests/", "включая tests/ и cli 4"))
    rc, out = run()
    cases.append(("duplicate_crate_red",
                  rc == 1 and "CIN_PAIR_MULTIPLE=cli" in out))

    # Сборка leave-behind: девять поддельных меток в `crates/*/target/` не должны менять число
    # (находка V-2 внешней рецензии: обход обязан исключать `target/`, а не полагаться на то, что
    # его нет). Проверка исполняема в обе стороны: те же девять меток вне `target/` красят зелёное.
    leak = "#[test]\n" * 9
    tgt = os.path.join(crates, "vecdht-wire", "target")
    os.makedirs(tgt)
    with open(os.path.join(tgt, "leak.rs"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(leak)
    write(header())
    rc_in, _ = run()
    with open(os.path.join(crates, "vecdht-wire", "leak-outside.rs"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write(leak)
    rc_out, _ = run()
    os.remove(os.path.join(crates, "vecdht-wire", "leak-outside.rs"))
    cases.append(("target_dir_skipped", rc_in == 0 and rc_out != 0))

    shutil.rmtree(root, ignore_errors=True)
    passed = sum(1 for _, ok in cases if ok)
    for name, ok in cases:
        print("PLANTED_%s=%s" % (name, "caught" if ok else "MISSED"))
    print("CIN_SELFCASES=%d" % len(cases))
    print("CIN_SELFPASSED=%d" % passed)
    print("CIN_SELFTEST=%s" % ("ok" if passed == len(cases) else "fail"))
    return 0 if passed == len(cases) else 1


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return cmd_selftest()
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--root", default=os.path.dirname(HERE))
    ap.add_argument("--workflow", default=None)
    ns, _ = ap.parse_known_args(argv)
    workflow = ns.workflow or os.path.join(ns.root, ".github", "workflows", "verify.yml")
    return check(os.path.abspath(ns.root), workflow)


if __name__ == "__main__":
    sys.exit(main())
