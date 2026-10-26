#!/usr/bin/env python3
"""Страж карты «слово → id замера» для §18.9 спеки v8 (условие 4 v1, карточка A6).

Каждое предложение §18.9 обязано либо называть номер замера/решения (`E-XXXX`, `ADR-XXXX`,
`S-XXXX`, `H-XXXX`, `L-XXXX`), либо ссылаться на исполняемый прибор (`что-то.rs::имя_теста`),
либо стоять с явной пометкой «не реализовано в v1» / «не проверено в v1». Ссылка на раздел спеки
(`§8.6`) таковым не считается: она говорит, где лежит обещание, а не чем оно подтверждено.

Выход 0 — немаркированных предложений нет и все названные ссылки реальны; выход 1 — есть (печатает
список); выход 2 — раздел не найден или файл не читается. `--selftest` гоняет посадку: предложение
без id обязано быть поймано, а выдуманный id и несуществующий прибор — быть названы отсутствующими.

Вторая проверка, без которой первая — формальность: каждый названный `E-`/`H-`/`ADR-`/`S-`-id обязан
иметь карточку в `lab/` (для `L-` — запись в `lab/library/index.jsonl`), каждый названный `.rs` —
существовать в `crates/` или `lab/`. Страж, который проверяет только наличие буквы «E», краснеет на
выдуманном номере ровно так же, как на отсутствующем тесте.
"""

from __future__ import annotations

import json
import os
import re
import sys

DEFAULT_SPEC = "docs/VecDHT-SPEC-v8.md"
DEFAULT_SECTION = "### 18.9"
NOT_DONE = ("не реализовано в v1", "не проверено в v1", "не закрыто в v1")

# Где живёт карточка каждого класса id: префикс → каталог репозитория.
ID_DIRS = {"E": "lab/experiments", "H": "lab/hypotheses", "ADR": "lab/decisions", "S": "lab/notes"}
L_INDEX = "lab/library/index.jsonl"
RS_DIRS = ("crates", "lab", "docs", "src")

ID_RE = re.compile(r"\b(?:E|ADR|S|H|L)-\d{4}\b")
INSTRUMENT_RE = re.compile(r"\b[\w./-]+\.rs\b|::[a-z_][a-z0-9_]*")
FILE_RE = re.compile(r"\b[\w./-]+\.rs\b")
SENT_SPLIT = re.compile(r"(?<=[.;!])\s+")


def section_lines(text: str, section: str) -> list[str]:
    lines: list[str] = []
    inside = False
    for line in text.splitlines():
        if line.startswith(section):
            inside = True
            continue
        if inside:
            if line.startswith("##") or line.strip() == "---":
                break
            lines.append(line)
    return lines


def sentences(lines: list[str]) -> list[str]:
    """Строки одного bullet'a склеиваются: перенос внутри пункта — не граница утверждения.
    Границы утверждений — точка и точка с запятой, потому что §18.9 пишет по одному требованию
    на клаузу."""
    blocks: list[str] = []
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("- "):
            blocks.append(stripped[2:].strip())
        elif stripped.startswith("* "):
            blocks.append(stripped[2:].strip())
        elif blocks:
            blocks[-1] += " " + stripped
        else:
            blocks.append(stripped)
    out: list[str] = []
    for block in blocks:
        for sent in SENT_SPLIT.split(block):
            sent = sent.strip(" -*")
            if len(sent) >= 20:
                out.append(sent)
    return out


def is_mapped(sentence: str) -> bool:
    if ID_RE.search(sentence) or INSTRUMENT_RE.search(sentence):
        return True
    return any(mark in sentence for mark in NOT_DONE)


def check(text: str, section: str) -> tuple[int, list[str]]:
    sents = sentences(section_lines(text, section))
    bad = [s for s in sents if not is_mapped(s)]
    return len(sents), bad


def known_ids() -> set[str]:
    """Номер id годен только если под ним лежит карточка (файл, начинающийся с `E-0105…`)."""
    out: set[str] = set()
    for prefix, folder in ID_DIRS.items():
        if not os.path.isdir(folder):
            continue
        for name in os.listdir(folder):
            m = re.match(rf"{prefix}-(\d{{4}})", name)
            if m:
                out.add(f"{prefix}-{m.group(1)}")
    if os.path.isfile(L_INDEX):
        with open(L_INDEX, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                lid = str(rec.get("id", ""))
                if re.fullmatch(r"L-\d{4}", lid):
                    out.add(lid)
    return out


def known_rs() -> tuple[set[str], set[str]]:
    """(полные пути от корня, базовые имена) для всех `.rs` репозитория."""
    paths: set[str] = set()
    stems: set[str] = set()
    for root in RS_DIRS:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            if any(p in dirpath for p in (os.sep + "target", "target" + os.sep)):
                continue
            for fn in filenames:
                if fn.endswith(".rs"):
                    full = os.path.join(dirpath, fn).replace(os.sep, "/")
                    paths.add(full)
                    stems.add(fn)
    return paths, stems


def missing_refs(section_text: str) -> tuple[int, int, list[str], list[str]]:
    """Возвращает (число id, число приборов, списки отсутствующих)."""
    ids = sorted(set(ID_RE.findall(section_text)))
    have = known_ids()
    bad_ids = [i for i in ids if i not in have]
    paths, stems = known_rs()
    mentioned: list[str] = []
    for m in FILE_RE.finditer(section_text):
        token = m.group(0)
        if token not in mentioned:
            mentioned.append(token)
    bad_files: list[str] = []
    for token in mentioned:
        bare = token.split("/")[-1]
        if token in paths or any(p.endswith("/" + token) or p == token for p in paths) or bare in stems:
            continue
        bad_files.append(token)
    return len(ids), len(mentioned), bad_ids, bad_files


def selftest() -> int:
    """Прибор обязан краснеть на посадке: проверяем и приём, и отклонение."""
    cases = [
        ("DHT-фундамент подтверждён на 200 узлах (`E-0105`).", True),
        ("crash-матрица живёт в `crash_matrix.rs` точками 1–10 плюс property.", True),
        ("Единого реестра дефектов нет — не реализовано в v1.", True),
        ("Ни один дефект Приложения A не воспроизводится тестом.", False),
        ("Приватностный раздел соответствует §13 как обещано.", False),
        ("Heal в один шаг подтверждён (`ADR-0017`).", True),
        ("Рестарт узла описан в документе.", False),
        ("Порог собран (`E-0094`, `ADR-0046`).", True),
    ]
    ok = 0
    for text, expected in cases:
        got = is_mapped(text)
        if got == expected:
            ok += 1
        else:
            print(f"СЕЛФТЕСТ ждали={expected} получили={got} :: {text}", file=sys.stderr)
    planted = sum(1 for _, e in cases if not e)
    caught = sum(1 for t, e in cases if not is_mapped(t) and not e)
    print(
        f"СЕЛФТЕСТ всего={len(cases)} прошло={ok} посажено={planted} поймано={caught}"
    )
    if ok != len(cases):
        return 1
    # Вторая половина селфтеста: отсылки. Реальный id и реальный прибор обязаны пройти,
    # выдуманные — быть пойманы.
    probe = (
        "реальный E-0105 и crash_matrix.rs; выдуманный E-9999 и no_such_instrument.rs "
        "для верного ADR-0044"
    )
    n_ids, n_files, bad_ids, bad_files = missing_refs(probe)
    want_bad_ids = ["E-9999"]
    want_bad_files = ["no_such_instrument.rs"]
    refs_ok = bad_ids == want_bad_ids and bad_files == want_bad_files
    print(
        f"СЕЛФТЕСТ_ССЫЛКИ id={n_ids} файлов={n_files} "
        f"отсутств_id={','.join(bad_ids) or 'none'} отсутств_файл={','.join(bad_files) or 'none'} "
        f"вердикт={1 if refs_ok else 0}"
    )
    if not refs_ok:
        print(
            f"СЕЛФТЕСТ ждали id={want_bad_ids} файлы={want_bad_files}, "
            f"получили id={bad_ids} файлы={bad_files}",
            file=sys.stderr,
        )
        return 1
    return 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    if "--selftest" in args:
        return selftest()
    spec = DEFAULT_SPEC
    section = DEFAULT_SECTION
    skip_refs = "--no-refs" in args
    for i, a in enumerate(args):
        if a == "--path" and i + 1 < len(args):
            spec = args[i + 1]
        if a == "--section" and i + 1 < len(args):
            section = args[i + 1]
    try:
        with open(spec, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"CLAIMMAP_FAIL нет файла {spec}: {exc}", file=sys.stderr)
        return 2
    lines = section_lines(text, section)
    total, bad = check(text, section)
    if total == 0:
        print(f"CLAIMMAP_FAIL раздел {section} не найден в {spec}", file=sys.stderr)
        return 2
    for s in bad:
        print(f"БЕЗ_ID: {s}", file=sys.stderr)
    body = "\n".join(lines)
    n_ids = n_files = 0
    bad_ids: list[str] = []
    bad_files: list[str] = []
    if not skip_refs:
        n_ids, n_files, bad_ids, bad_files = missing_refs(body)
        for x in bad_ids:
            print(f"НЕТ_КАРТОЧКИ: {x}", file=sys.stderr)
        for x in bad_files:
            print(f"НЕТ_ПРИБОРА: {x}", file=sys.stderr)
    print(
        f"CLAIMMAP_SECTION={section} CLAIMMAP_SENTENCES={total} CLAIMMAP_UNMAPPED={len(bad)} "
        f"CLAIMMAP_IDS={n_ids} CLAIMMAP_MISSING_IDS={len(bad_ids)} "
        f"CLAIMMAP_INSTRUMENTS={n_files} CLAIMMAP_MISSING_INSTRUMENTS={len(bad_files)}"
    )
    if bad or bad_ids or bad_files:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
