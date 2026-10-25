#!/usr/bin/env python3
"""Счётчики лаборатории — единственный носитель инвентарных чисел.

Правило, ради которого этот файл существует: число, которое порождается из дерева, не имеет
права печататься руками. `README.md`, `README.ru.md`, `PITCH.en.md` и `ROADMAP.md` обязаны
ссылаться на `lab/INVENTORY.md`, а не переписывать счётчики друг у друга (аудит
`lab/notes/AUDIT-2026-10-25-repo-spec-readme.md`, находка M1).

Что считается и как:

* `hypotheses`, `experiments`, `adrs`, `syntheses` — перебор каталогов `lab/`;
* `verdict_*` — поле `verdict:` карточек экспериментов, приведённое к словарю (`lab/README.md`,
  шаг 4); стилизованные многострочные вердикты читаются по первому слову, поэтому четыре
  стиля записи (`N5` аудита) не ломают разбор;
* `library_entries` — непустые строки `lab/library/index.jsonl` (каждая обязана быть JSON,
  иначе счётчик не вычислен и выход ненулевой);
* `logs`, `verify_blocks` — перебор `lab/logs/` и заголовков прогонов `########## <метка> ·`;
* `carrier_sha256_*` — контрольные суммы носителей, а не пересказ;
* `dangling_id_mentions` — сколько раз документы для чтения называют `H-`/`E-`/`ADR-`/`L-`
  номер, под которым нет файла (аудит, B6). Нуль означает, что правило «документ не имеет
  права называть номер без файла» выполняется машинно, а не на честном слове.

Выход: 0 — все напечатанные числа вычислены из дерева; 1 — хотя бы одно число вычислить не
удалось (нет каталога, пустой каталог, битый JSON, нечитаемый файл, нет ни одного документа).
Ненулевой `dangling_id_mentions` нулевым выходом НЕ является: это напечатанный факт, а не
поломка прибора.

Употребление:

    python lab/inventory.py --date 2026-10-25
    python lab/inventory.py --date 2026-10-25 --write lab/INVENTORY.md
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def path(*parts):
    return os.path.join(ROOT, *parts)


def read_lines(p):
    with io.open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


class Counter:
    """Накопитель чисел. Любая неудача вычислить помечается в `errors` и валит выход."""

    def __init__(self):
        self.values = []
        self.errors = []

    def add(self, key, value, how):
        self.values.append((key, value, how))
        return value

    def fail(self, key, why):
        self.errors.append(f"{key}: {why}")
        return None


def glob_count(c, key, pattern, how):
    d = os.path.dirname(pattern)
    if not os.path.isdir(path(d)):
        c.fail(key, f"нет каталога {d}/")
        return 0
    n = len(glob.glob(path(pattern)))
    if n == 0:
        c.fail(key, f"каталог {d}/ пуст по шаблону {os.path.basename(pattern)}")
    return c.add(key, n, how)


def cards(pattern):
    return sorted(glob.glob(path(pattern)))


VERDICT_WORDS = ("supports", "refutes", "satisfies", "accepted", "pending", "inconclusive")


def first_verdict_word(raw):
    """`verdict: "supports — гейт выполнен…"` и `verdict: refutes` приводят к одному слову."""
    text = raw.strip().lstrip("\"'").strip()
    m = re.match(r"([a-z_]+)", text)
    if not m:
        return None
    return m.group(1)


def verdict_histogram(c):
    hist = {}
    missing = 0
    files = cards("lab/experiments/*.md")
    if not files:
        c.fail("verdict_total", "нет карточек экспериментов")
        return hist
    for f in files:
        verdict = None
        for line in read_lines(f):
            if line.startswith("verdict:"):
                verdict = line[len("verdict:"):]
                break
        if verdict is None:
            missing += 1
            continue
        word = first_verdict_word(verdict)
        if word is None:
            missing += 1
            continue
        hist[word] = hist.get(word, 0) + 1
    c.add("verdict_missing", missing, "карточки без разбираемого поля `verdict:`")
    known = sum(v for k, v in hist.items() if k in VERDICT_WORDS)
    other = sum(v for k, v in hist.items() if k not in VERDICT_WORDS)
    c.add("verdict_total", known + other, "сумма разобранного поля `verdict:` по карточкам")
    for w in VERDICT_WORDS:
        c.add("verdict_" + w, hist.get(w, 0), f"первое слово поля `verdict:` == {w}")
    c.add("verdict_other", other, "вердикты вне объявленного словаря (аудит, N5)")
    return hist


def simple_histogram(c, key_prefix, files, field, how):
    hist = {}
    for f in files:
        value = None
        for line in read_lines(f):
            if line.startswith(field + ":"):
                value = line.split(":", 1)[1].strip().strip("\"'")
                break
        if value:
            hist[value] = hist.get(value, 0) + 1
    untagged = len(files) - sum(hist.values())
    c.add(key_prefix + "_total", len(files), how)
    c.add(key_prefix + "_untagged", untagged, f"файлы без поля `{field}:`")
    for k in sorted(hist):
        c.add(f"{key_prefix}_{k}", hist[k], f"поле `{field}:` == {k}")
    return hist


def library_entries(c):
    p = path("lab/library/index.jsonl")
    if not os.path.isfile(p):
        c.fail("library_entries", "нет файла lab/library/index.jsonl")
        return 0
    lines = [x for x in read_lines(p) if x.strip()]
    bad = 0
    ids = set()
    for x in lines:
        try:
            row = json.loads(x)
        except ValueError:
            bad += 1
            continue
        if isinstance(row, dict) and row.get("id"):
            ids.add(str(row["id"]))
    if bad:
        c.fail("library_entries", f"{bad} строк индекса не разбираются как JSON")
    c.add("library_entries", len(lines), "непустые строки lab/library/index.jsonl")
    c.add("library_ids", len(ids), "непустые различающиеся поля id в индексе источников")
    return len(lines)


def logs_and_runs(c):
    logs = [p for p in glob.glob(path("lab/logs", "*")) if os.path.isfile(p)]
    if not logs:
        c.fail("logs", "каталог lab/logs/ пуст или отсутствует")
    c.add("logs", len(logs), "файлы в lab/logs/ (append-only)")
    c.add("log_dirs", len([p for p in glob.glob(path("lab/logs", "*")) if os.path.isdir(p)]),
          "подкаталоги lab/logs/")
    sha = {}
    for p in logs:
        try:
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
        except OSError as exc:
            c.fail("logs_sha256_unique", f"не читается {os.path.basename(p)}: {exc}")
            continue
        digest = h.hexdigest()
        sha[digest] = sha.get(digest, 0) + 1
    c.add("logs_sha256_unique", len(sha), "различающиеся sha256 среди файлов lab/logs/")
    c.add("logs_sha256_duplicated", sum(1 for v in sha.values() if v > 1),
          "sha256, встречающиеся в log-файлах более одного раза")

    vlogs = sorted(glob.glob(path("lab/logs", "workspace-verify-*.log")))
    if not vlogs:
        c.fail("verify_blocks", "нет ни одного журнала lab/logs/workspace-verify-*.log")
    blocks = 0
    labels = set()
    for p in vlogs:
        for line in read_lines(p):
            if line.startswith("########## "):
                blocks += 1
                m = re.match(r"#+\s+(\S+)\s+·", line)
                if m:
                    labels.add(m.group(1))
    c.add("verify_log_files", len(vlogs), "файлы lab/logs/workspace-verify-*.log")
    c.add("verify_blocks", blocks, "заголовки прогонов `########## <метка> ·` в них")
    c.add("verify_labels", len(labels), "различающиеся метки прогонов, переданные "
                                        "lab/workspace-verify.sh")
    return vlogs


def carrier_digests(c):
    for key, rel in (
        ("carrier_sha256_paid_order_vectors", "docs/PAID_ORDER-VECTORS.md"),
        ("carrier_sha256_spec_v8", "docs/VecDHT-SPEC-v8.md"),
        ("carrier_sha256_spec_v9", "docs/VecDHT-SPEC-v9.md"),
    ):
        p = path(rel)
        if not os.path.isfile(p):
            c.fail(key, f"нет файла {rel}")
            continue
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        c.add(key, h.hexdigest(), f"sha256sum {rel}")
    for key, rel in (
        ("carrier_lines_paid_order_vectors", "docs/PAID_ORDER-VECTORS.md"),
        ("carrier_lines_spec_v8", "docs/VecDHT-SPEC-v8.md"),
        ("carrier_lines_spec_v9", "docs/VecDHT-SPEC-v9.md"),
    ):
        p = path(rel)
        if not os.path.isfile(p):
            c.fail(key, f"нет файла {rel}")
            continue
        c.add(key, len(read_lines(p)), f"`wc -l` по {rel}")


DOC_SET = [
    "README.md", "README.ru.md", "PITCH.en.md", "ROADMAP.md",
    "docs/ARCHITECTURE.md", "docs/STATUS-v1.md", "docs/METRICS.md", "docs/FORMAL.md",
    "docs/PAID_ORDERS.md", "docs/VecDHT-v9-REVIEW.md", "docs/VecDHT-SPEC-v8.md",
    "docs/VecDHT-SPEC-v9.md", "lab/README.md", "lab/PLAN.md",
]

ID_RX = re.compile(r"\b(ADR|H|E|L)-(\d{4})([a-z])?\b")
KIND = {"ADR": "ADR", "H": "H", "E": "E", "L": "L"}


def existing_ids():
    have = set()
    for f in glob.glob(path("lab/hypotheses/*.md")):
        m = re.search(r"H-\d{4}", os.path.basename(f))
        if m:
            have.add(m.group(0))
    for f in glob.glob(path("lab/experiments/*.md")):
        m = re.search(r"E-\d{4}", os.path.basename(f))
        if m:
            have.add(m.group(0))
    for f in glob.glob(path("lab/decisions/ADR-*.md")):
        m = re.search(r"ADR-\d{4}", os.path.basename(f))
        if m:
            have.add(m.group(0))
    p = path("lab/library/index.jsonl")
    if os.path.isfile(p):
        for line in read_lines(p):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("id"):
                have.add(str(row["id"]))
    return have


def dangling_refs(c):
    """Сколько раз документы для чтения называют номер, под которым нет файла (аудит, B6)."""
    have = existing_ids()
    if not have:
        c.fail("dangling_id_mentions", "не удалось собрать множество существующих номеров")
        return
    scanned = [d for d in DOC_SET if os.path.isfile(path(d))]
    if not scanned:
        c.fail("dangling_id_mentions", "ни одного документа из DOC_SET нет на диске")
        return
    c.add("docs_scanned", len(scanned), "файлы DOC_SET, перебранные проверкой разрешимости")
    dangling = {}
    total_mentions = 0
    for d in scanned:
        text = "\n".join(read_lines(path(d)))
        for m in ID_RX.finditer(text):
            kind, num, suffix = m.group(1), m.group(2), m.group(3)
            total_mentions += 1
            ident = f"{KIND[kind]}-{num}" + (suffix if (suffix and kind == "H") else "")
            if ident not in have:
                loc = f"{d}:{text[:m.start()].count(chr(10)) + 1}"
                dangling.setdefault(ident, []).append(loc)
    c.add("id_mentions", total_mentions, "упоминания `H-`/`E-`/`ADR-`/`L-` в этих документах")
    c.add("dangling_id_mentions", len(dangling),
          "названные номера, под которыми нет файла (правило разрешимости, аудит B6)")
    c.add("dangling_ids", ", ".join(sorted(dangling)) or "-", "список неразрешённых номеров")
    for k in sorted(dangling):
        c.add("dangling_where_" + k, "; ".join(sorted(set(dangling[k]))[:6]),
              "адреса упоминаний")


def formal_files(c):
    vecdht = glob.glob(path("lab/lean/VecDHT/*.lean"))
    outside = [p for p in glob.glob(path("lab/lean/*.lean")) if os.path.basename(p) != "VecDHT"]
    c.add("lean_models_guarded", len(vecdht),
          "`lab/lean/VecDHT/*.lean` — то, что покрывает `bash lab/lean-check.sh`")
    c.add("lean_models_outside_guard", len(outside),
          ".lean вне `lab/lean/VecDHT/`, их страж моделей не компилирует")
    frozen = glob.glob(path("lab/lean/frozen/*.tsv")) + glob.glob(path("lab/lean/frozen/*.txt"))
    c.add("lean_frozen", len(frozen), "файлы заморозки формулировок в lab/lean/frozen/")
    verus = glob.glob(path("lab/proofs/verus/*.rs"))
    c.add("verus_files", len(verus), ".rs в lab/proofs/verus/")
    helpers = glob.glob(path("lab/e0*-run.sh"))
    c.add("cycle_helpers", len(helpers), "lab/e0XXXX-run.sh helper'ов циклов")
    expects = glob.glob(path("lab/expectations/*.tsv"))
    c.add("expectation_files", len(expects), "таблицы ожиданий lab/expectations/*.tsv")


def build():
    c = Counter()
    glob_count(c, "hypotheses", "lab/hypotheses/*.md", "`ls lab/hypotheses/*.md | wc -l`")
    glob_count(c, "experiments", "lab/experiments/*.md", "`ls lab/experiments/*.md | wc -l`")
    glob_count(c, "adrs", "lab/decisions/ADR-*.md", "`ls lab/decisions/ADR-*.md | wc -l`")
    glob_count(c, "syntheses", "lab/notes/S-*.md", "`ls lab/notes/S-*.md | wc -l`")
    simple_histogram(c, "hypothesis_status", cards("lab/hypotheses/*.md"), "status",
                     "поле `status:` карточек гипотез")
    simple_histogram(c, "experiment_status", cards("lab/experiments/*.md"), "status",
                     "поле `status:` карточек экспериментов")
    verdict_histogram(c)
    library_entries(c)
    logs_and_runs(c)
    carrier_digests(c)
    formal_files(c)
    dangling_refs(c)
    return c


def render(c, date):
    lines = [
        "# Инвентарь `lab/` — порождённый, не набранный",
        "",
        "> Единственный носитель инвентарных счётчиков репозитория. README, PITCH и ROADMAP",
        "> ссылаются на этот файл и не печатают числа. Измеренные величины живут в",
        "> `docs/METRICS.md` и всегда стоят рядом с id цикла, который их снял.",
        "",
        "Переснять: `python lab/inventory.py --date <ГГГГ-ММ-ДД> --write lab/INVENTORY.md`",
        f"Дата этого среза: {date} (передаётся аргументом, чтобы повтор был воспроизводим).",
        "Прибор выходит ненулём, если хотя бы одно напечатанное число нельзя вычислить из дерева.",
        "",
        "| счётчик | значение | как снято |",
        "|---|---|---|",
    ]
    def esc(s):
        # вертикальная черта в команде ломает строку markdown-таблицы: её печатаем экранированной
        return str(s).replace("|", "\\|")

    for k, v, how in c.values:
        lines.append(f"| `{esc(k)}` | {v} | {esc(how)} |")
    lines += ["", "## Что не является числом", "",
              "Разрешимость имён (`dangling_id_mentions`) считает документы для чтения из",
              "`DOC_SET` в начале `lab/inventory.py`. Нулевое значение — это выполненное правило",
              "«документ не называет `H-`/`E-`/`ADR-`/`L-` без файла»; ненулевое — список адресов,",
              "по которому видно, какой документ править. Строки прогона и измеренные числа здесь",
              "не появляются намеренно: они принадлежат `docs/METRICS.md`.", ""]
    if c.errors:
        lines += ["## Ошибки прибора", ""] + [f"* {e}" for e in c.errors] + [""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="порождение инвентарных счётчиков lab/")
    ap.add_argument("--date", help="дата среза ГГГГ-ММ-ДД; обязательна для --write")
    ap.add_argument("--write", help="файл markdown, например lab/INVENTORY.md")
    ap.add_argument("--json", action="store_true", help="напечатать пары ключ-значение как JSON")
    args = ap.parse_args()

    c = build()
    if args.json:
        print(json.dumps({k: v for k, v, _ in c.values}, ensure_ascii=False, indent=2))
    else:
        width = max(len(k) for k, _, _ in c.values) if c.values else 0
        for k, v, _ in c.values:
            print(f"{k}={v}")
    if args.write:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date or ""):
            c.fail("date", "--date ГГГГ-ММ-ДД обязателен при --write, иначе срез не воспроизводится")
        else:
            out = path(args.write) if not os.path.isabs(args.write) else args.write
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with io.open(out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(render(c, args.date))
            print(f"записан {args.write}")
    if c.errors:
        for e in c.errors:
            print(f"ОШИБКА {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
