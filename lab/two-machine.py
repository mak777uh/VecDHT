#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Прибор второй машины: снимок золотых векторов и сверка чужого лога.

Зачем. Условие 3 релиза (`ADR-0044`) требует сценарий на разных машинах, а половина P2 —
побайтовое совпадение golden-векторов на второй машине. Сам прогон на чужой машине делает
владелец; здесь живёт то, что можно проверить на одной: машина A печатает снимок, машина B
печатает такой же, A сверяет лог B и отказывается засчитывать его, если расходятся байты
векторов, HEAD, чистота дерева или прогон тестов.

Что именно сверяется. Байты вектора — это blob в git (`git cat-file blob HEAD:<путь>`), а не
байты рабочего файла: тест перезаписывает фикстуру через `writeln!`, и на Windows рабочая
форма получает CRLF, тогда как blob хранит LF (правило `.gitattributes`). Сверка рабочих
байтов между машинами краснела бы на исправном дереве — поэтому прибор печатает рабочую форму
(`WORK_*`) для диагноза, но сверяет blob (`BLOB_*`) и `CLEAN` (рабочая форма нормализуется в
blob). Это и есть измеренная ловушка круга: «побайтово» без названного носителя байтов лжёт.

Правила круга, вшитые в прибор:
* корень дерева — единственное место, откуда берутся фикстуры; путь, вышедший за корень,
  не меряется (`TM_FIXTURE_ESCAPE`, а не панику);
* пустое множество печатается `none`;
* прибор деградирует в нули: нечитаемое даёт `none`/`0`, а не исключение;
* в лог не печатается домашний абсолютный путь: только имя корневого каталога;
* чужие ключи, повторы и пропуски называются поимённо, а не молчанием;
* отсутствие тестов не засчитывается: `no-tests` — отказ, а не пропуск.

Команды:
    python lab/two-machine.py snapshot --label <имя> [--no-tests]
    python lab/two-machine.py verify <лог> [--allow-no-tests]
    python lab/two-machine.py selftest
"""
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = {
    "crypto": "crates/vecdht-crypto/tests/golden/vectors.txt",
    "wire": "crates/vecdht-wire/tests/golden/vectors.txt",
    "artifact": "crates/vecdht-artifact/tests/golden/artifact.txt",
}
TESTS = {
    "crypto": "golden_vectors",
    "wire": "golden_vectors",
    "artifact": "golden_artifact",
}
WORK_KEYS = ("BLOB_SHA256", "BLOB_BYTES", "WORK_SHA256", "WORK_BYTES",
             "WORK_LINES", "WORK_CRLF", "CLEAN")
COMPARED = ("BLOB_SHA256", "BLOB_BYTES", "CLEAN")
SNAP_KEYS = (
    ["TM_MACHINE", "TM_LABEL", "TM_HEAD", "TM_DIRTY", "TM_ROOT_NAME", "TM_FIXTURES",
     "TM_FIXTURE_ESCAPE", "TM_TEST_CRYPTO", "TM_TEST_WIRE", "TM_TEST_ARTIFACT",
     "TM_TESTS_RAN", "TM_TESTS_OK", "TM_SNAPSHOT_OK", "TM_EXIT"]
    + [f"TM_FIXTURE_{n}_{k}" for n in FIXTURES for k in WORK_KEYS]
)
LINE = re.compile(r"^([A-Z][A-Za-z0-9_]*)=(.*)$")


def root_ok():
    """Меряем только внутри корня дерева: иначе снимок описывает чужой каталог."""
    return os.path.isfile(os.path.join(ROOT, "Cargo.toml")) and os.path.isdir(
        os.path.join(ROOT, ".git"))


def under_root(rel):
    full = os.path.realpath(os.path.join(ROOT, rel))
    base = os.path.realpath(ROOT)
    return os.path.normcase(full).startswith(os.path.normcase(base) + os.sep)


def run(cmd):
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=900)
        return p.returncode, p.stdout.decode("utf-8", "replace") + p.stderr.decode(
            "utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def git(*args):
    rc, out = run(["git"] + list(args))
    return rc, out.strip()


def blob_facts(rel):
    """Байты вектора — blob из git, а не рабочая форма: см. шапку."""
    try:
        p = subprocess.run(["git", "cat-file", "blob", f"HEAD:{rel}"], cwd=ROOT,
                           capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None, 0
    if p.returncode != 0:
        return None, 0
    return hashlib.sha256(p.stdout).hexdigest(), len(p.stdout)


def file_facts(rel):
    """Рабочая форма. Путь вне корня не читается вовсе."""
    if not under_root(rel):
        return None, 0, 0, 0
    try:
        blob = open(os.path.join(ROOT, rel), "rb").read()
    except OSError:
        return None, 0, 0, 0
    return hashlib.sha256(blob).hexdigest(), len(blob), blob.count(b"\n"), blob.count(b"\r\n")


def is_clean(rel):
    rc, out = run(["git", "status", "--porcelain", "--", rel])
    return 1 if rc == 0 and not out else 0


def one_test(crate, name):
    rc, out = run(["cargo", "test", "-q", "-p", f"vecdht-{crate}", "--test", name])
    ok = rc == 0 and "test result: ok." in out
    return "ok" if ok else "FAIL"


def snapshot(label, with_tests, out):
    facts = {k: "none" for k in SNAP_KEYS}
    facts["TM_MACHINE"] = f"{platform.system().lower()}-{platform.machine().lower()}"
    facts["TM_LABEL"] = label or "none"
    facts["TM_HEAD"] = git("rev-parse", "HEAD")[1] or "none"
    facts["TM_DIRTY"] = "1" if git("status", "--porcelain")[1] else "0"
    facts["TM_ROOT_NAME"] = os.path.basename(os.path.realpath(ROOT)) or "none"
    facts["TM_FIXTURES"] = str(len(FIXTURES))
    escape = 0
    readable = 0
    for name, rel in FIXTURES.items():
        bsha, bsize = blob_facts(rel)
        wsha, wsize, wlines, wcrlf = file_facts(rel)
        if not under_root(rel):
            escape = 1
        if bsha is None:
            bsha, bsize = "none", 0
        else:
            readable += 1
        facts[f"TM_FIXTURE_{name}_BLOB_SHA256"] = bsha
        facts[f"TM_FIXTURE_{name}_BLOB_BYTES"] = str(bsize)
        facts[f"TM_FIXTURE_{name}_WORK_SHA256"] = wsha or "none"
        facts[f"TM_FIXTURE_{name}_WORK_BYTES"] = str(wsize)
        facts[f"TM_FIXTURE_{name}_WORK_LINES"] = str(wlines)
        facts[f"TM_FIXTURE_{name}_WORK_CRLF"] = str(wcrlf)
        facts[f"TM_FIXTURE_{name}_CLEAN"] = str(is_clean(rel)) if wsha else "0"
    facts["TM_FIXTURE_ESCAPE"] = str(escape)
    ran = 0
    tests_ok = 0
    if with_tests:
        for crate, test in TESTS.items():
            verdict = one_test(crate, test)
            facts[f"TM_TEST_{crate.upper()}"] = verdict
            ran += 1
            tests_ok += 1 if verdict == "ok" else 0
    facts["TM_TESTS_RAN"] = str(ran)
    facts["TM_TESTS_OK"] = str(tests_ok)
    facts["TM_SNAPSHOT_OK"] = "1" if readable == len(FIXTURES) and escape == 0 else "0"
    facts["TM_EXIT"] = "0" if facts["TM_SNAPSHOT_OK"] == "1" and root_ok() else "1"
    if not root_ok():
        for k in SNAP_KEYS:
            if k not in ("TM_MACHINE", "TM_LABEL", "TM_SNAPSHOT_OK", "TM_EXIT"):
                facts[k] = "none"
    for k in SNAP_KEYS:
        out.append(f"{k}={facts[k]}")


def parse(blob):
    got, dup, foreign = {}, [], []
    for raw in blob.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not raw.strip():
            continue
        m = LINE.match(raw.strip())
        if not m:
            foreign.append(raw.strip()[:40])
            continue
        key, value = m.group(1), m.group(2).strip()
        if key not in SNAP_KEYS:
            foreign.append(key)
            continue
        if key in got:
            dup.append(key)
            continue
        got[key] = value
    return got, dup, foreign


def verify(log_path, allow_no_tests, out):
    try:
        blob = open(log_path, encoding="utf-8", errors="replace").read()
    except OSError:
        blob = ""
    got, dup, foreign = parse(blob)
    missing = [k for k in SNAP_KEYS if k not in got]
    head_local = git("rev-parse", "HEAD")[1] or "none"
    mismatch, reasons = [], []
    for name, rel in FIXTURES.items():
        bsha, bsize = blob_facts(rel)
        want = {"BLOB_SHA256": bsha or "none", "BLOB_BYTES": str(bsize), "CLEAN": "1"}
        for k in COMPARED:
            key = f"TM_FIXTURE_{name}_{k}"
            if key in got and got[key] != want[k]:
                mismatch.append(key)
    if mismatch:
        reasons.append("hash")
    if got.get("TM_HEAD", "") != head_local:
        reasons.append("head")
    if got.get("TM_DIRTY", "none") != "0":
        reasons.append("dirty")
    if got.get("TM_LABEL", "none") in ("", "none"):
        reasons.append("label")
    tests = [got.get(f"TM_TEST_{c.upper()}", "none") for c in TESTS]
    if all(t == "none" for t in tests):
        if not allow_no_tests:
            reasons.append("no-tests")
    elif any(t != "ok" for t in tests):
        reasons.append("test")
    for key, want, reason in (("TM_EXIT", "0", "exit"), ("TM_FIXTURE_ESCAPE", "0", "escape"),
                              ("TM_SNAPSHOT_OK", "1", "snapshot")):
        if got.get(key, "none") != want:
            reasons.append(reason)
    if missing:
        reasons.append("missing")
    if foreign:
        reasons.append("foreign")
    if dup:
        reasons.append("duplicate")
    verdict = "pass" if not reasons else "fail"
    present = sum(1 for n in FIXTURES for k in COMPARED
                  if f"TM_FIXTURE_{n}_{k}" in got)
    out.append(f"TMV_HEAD={got.get('TM_HEAD', 'none')}")
    out.append(f"TMV_HEAD_MATCH={'1' if got.get('TM_HEAD', '') == head_local else '0'}")
    out.append(f"TMV_FIXTURES={len(FIXTURES)}")
    out.append(f"TMV_MATCH={max(0, present - len(mismatch))}")
    out.append(f"TMV_MISMATCH={','.join(mismatch) if mismatch else 'none'}")
    out.append(f"TMV_MISSING={','.join(missing) if missing else 'none'}")
    out.append(f"TMV_FOREIGN={','.join(foreign) if foreign else 'none'}")
    out.append(f"TMV_DUPLICATE={','.join(dup) if dup else 'none'}")
    out.append(f"TMV_TESTS={sum(1 for t in tests if t != 'none')}")
    out.append(f"TMV_TESTS_OK={sum(1 for t in tests if t == 'ok')}")
    out.append(f"TMV_VERDICT={verdict}")
    out.append(f"TMV_REASONS={','.join(reasons) if reasons else 'none'}")
    out.append(f"TMV_EXIT={0 if verdict == 'pass' else 1}")
    return 0 if verdict == "pass" else 1


def capture(label, with_tests=False):
    out = []
    snapshot(label, with_tests, out)
    return "\n".join(out) + "\n"


def plant(base, changes):
    lines = base.split("\n")
    for key, value in changes.items():
        lines = [f"{key}={value}" if l.startswith(key + "=") else l for l in lines]
    return "\n".join(lines)


def selftest(out):
    tmp = tempfile.mkdtemp(prefix="tm-selftest-")
    total = 0
    bad = 0

    def check(name, want, got):
        nonlocal total, bad
        total += 1
        ok = want == got
        if not ok:
            bad += 1
        out.append(f"СЕЛФТЕСТ {'ok' if ok else 'ПРОВАЛ'}: {name}"
                   + ("" if ok else f": ждали «{want}», получили «{got}»"))

    def case(name, blob, allow, reason):
        path = os.path.join(tmp, "case.log")
        open(path, "w", encoding="utf-8").write(blob)
        res = []
        rc = verify(path, allow, res)
        text = "\n".join(res)
        m = re.search(r"^TMV_REASONS=(.*)$", text, re.M)
        have = (m.group(1).split(",") if m else [])
        check(f"{name}: отказ с причиной {reason}", "1", "1" if rc == 1 and reason in have else "0")
        return text

    # Контроль меряет сверщик, а не чистоту дерева: в дереве разработки лежит сам прибор.
    base = plant(capture("machine-A"), {"TM_DIRTY": "0"})
    good = os.path.join(tmp, "good.log")
    open(good, "w", encoding="utf-8").write(base)
    check("положительный контроль: снимок без тестов с --allow-no-tests",
          "0", str(verify(good, True, [])))
    check("без тестов по умолчанию — отказ", "1", str(verify(good, False, [])))
    head = re.search(r"^TM_HEAD=(.*)$", base, re.M).group(1)
    blob_sha = re.search(r"^TM_FIXTURE_wire_BLOB_SHA256=(.*)$", base, re.M).group(1)
    case("подменённый blob-хеш", plant(base, {"TM_FIXTURE_wire_BLOB_SHA256": "0" * 64}),
         True, "hash")
    text = case("подменённые blob-байты", plant(base, {"TM_FIXTURE_crypto_BLOB_BYTES": "1"}),
                True, "hash")
    m = re.search(r"^TMV_MISMATCH=(.*)$", text, re.M)
    check("подменённые blob-байты: mismatch называет ключ",
          "TM_FIXTURE_crypto_BLOB_BYTES", m.group(1) if m else "none")
    case("грязная рабочая форма", plant(base, {"TM_FIXTURE_wire_CLEAN": "0"}), True, "hash")
    case("чужой HEAD", plant(base, {"TM_HEAD": "0" * 40}), True, "head")
    case("грязное дерево", plant(base, {"TM_DIRTY": "1"}), True, "dirty")
    case("пустая метка", plant(base, {"TM_LABEL": "none"}), True, "label")
    case("упавший тест", plant(base, {"TM_TEST_CRYPTO": "FAIL"}), True, "test")
    case("путь за корень", plant(base, {"TM_FIXTURE_ESCAPE": "1"}), True, "escape")
    case("снимок не собран", plant(base, {"TM_SNAPSHOT_OK": "0"}), True, "snapshot")
    case("нерулонный выход", plant(base, {"TM_EXIT": "1"}), True, "exit")
    case("чужой ключ семейства", base + "TM_EXTRA=1\n", True, "foreign")
    case("ключ другого семейства", base + "OTHER=1\n", True, "foreign")
    case("повтор ключа", base + "TM_HEAD=" + head + "\n", True, "duplicate")
    case("пропущен ключ", "\n".join(l for l in base.split("\n")
                                  if not l.startswith("TM_FIXTURE_wire_WORK_LINES=")), True,
         "missing")
    case("пустой лог", "", True, "missing")
    # Рабочая форма машины B законно отличается: сверять её нельзя.
    other_machine = plant(base, {"TM_FIXTURE_crypto_WORK_SHA256": "f" * 64,
                                 "TM_FIXTURE_crypto_WORK_CRLF": "30",
                                 "TM_FIXTURE_crypto_WORK_LINES": "30"})
    path = os.path.join(tmp, "other.log")
    open(path, "w", encoding="utf-8").write(other_machine)
    check("рабочая форма другой машины не меняет вердикт", "0",
          str(verify(path, True, [])))
    check("blob-хеш фикстуры не пуст", "1", "1" if len(blob_sha) == 64 else "0")
    # Положительный контроль с тестами: три золотых теста на этом дереве обязаны быть ok.
    with_tests = plant(capture("machine-A", with_tests=True), {"TM_DIRTY": "0"})
    path = os.path.join(tmp, "tests.log")
    open(path, "w", encoding="utf-8").write(with_tests)
    res = []
    rc = verify(path, False, res)
    text = "\n".join(res)
    have = re.search(r"^TMV_TESTS_OK=(.*)$", text, re.M).group(1)
    check("три золотых теста на этом дереве: 3 из 3", "3", have)
    check("снимок с тестами проходит сверку", "0", str(rc))
    check("снимок без тестов не притворяется прогоном", "0",
          re.search(r"^TM_TESTS_RAN=(.*)$", base, re.M).group(1))
    # Копия прибора вне корня дерева обязана отказать, а не мерить чужой каталог.
    outside = os.path.join(tmp, "two-machine.py")
    shutil.copyfile(os.path.abspath(__file__), outside)
    rc, _ = run([sys.executable, outside, "snapshot", "--label", "outside", "--no-tests"])
    check("копия вне корня дерева: снимок отказывает", "1", str(rc))
    shutil.rmtree(tmp, ignore_errors=True)
    out.append(f"СЕЛФТЕСТ_ИТОГ total={total} passed={total - bad} failed={bad}")
    return 0 if bad == 0 else 1


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 2
    cmd = argv[1]
    out = []
    if cmd == "snapshot":
        label = ""
        if "--label" in argv and argv.index("--label") + 1 < len(argv):
            label = argv[argv.index("--label") + 1]
        if not root_ok():
            out = [f"{k}=none" for k in SNAP_KEYS]
            out[0] = f"TM_MACHINE={platform.system().lower()}-{platform.machine().lower()}"
            out[SNAP_KEYS.index("TM_SNAPSHOT_OK")] = "TM_SNAPSHOT_OK=0"
            out[SNAP_KEYS.index("TM_EXIT")] = "TM_EXIT=1"
            print("\n".join(out))
            return 1
        snapshot(label, "--no-tests" not in argv, out)
        print("\n".join(out))
        return 0 if "TM_EXIT=0" in out else 1
    if cmd == "verify":
        if len(argv) < 3:
            print("verify: нужен путь к логу")
            return 2
        rc = verify(argv[2], "--allow-no-tests" in argv, out)
        print("\n".join(out))
        return rc
    if cmd == "selftest":
        rc = selftest(out)
        print("\n".join(out))
        return rc
    print(f"неизвестная команда: {cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
