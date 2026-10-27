#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Соединённый реестр утверждений релизной готовности (`H-0132`).

Каждая строка `lab/claims.tsv` — опубликованное утверждение, а не желание: её формулировка обязана
дословно встречаться в названном носителе, её ссылки — резолвиться в карточку с вердиктом или в файл
из дерева, а тип свидетельства задаёт потолок формулировки. Тип решает, насколько сильно вообще
можно сказать: «измерено одним прогоном» не имеет права сказать «всегда», «доказано для модели» —
«доказано для кода», «оценка» — назваться измерением, «гейт закрыт» — назвать три гейта, не назвав
трёх носителей.

Проверка двусторонняя, иначе реестр становится параллельной правдой:

* вниз — каждая строка обязана найтись в носителе (`DANGLING`), иначе это выдуманное утверждение;
* вверх — каждый пункт таблицы пяти условий `docs/STATUS-v1.md` обязан иметь хотя бы одну строку
  (`CONDITIONS_COVERED` против `CONDITIONS_TABLE`), иначе реестр не покрывает то множество,
  которое читает посторонний.

Отдельным правилом живёт «у имени факта один владелец»: цифра готовности ищется по списку носителей
и обязана иметь одно значение (`READY_VALUES`), а не два — расхождение 78 % в README против 85 % в
статус-документе прибор обязан назвать числом, а не абзацем.

Слова потолка читаются по строке без инлайн-кода и без цитат в кавычках: сосланное и отрицаемое слово
не является утверждением прибора — точно так же не является им слово, стоящее за «not a» или «no»
(`not a measurement` не утверждает, что было измерение). Двоеточие границей строки не считается,
потому что «The audit is an executable test: `E-0108` …» — одно утверждение, и носителя оно требует
вместе со своей ссылкой.

Выход: 0 — нарушений нет и покрытие полное; 1 — есть хотя бы одно; 2 — реестр не читается.

`--selftest` собирает временное дерево (поддельные носители и карточки) и прогоняет восемь посаженных
дефектов и четыре законных случая: первые обязаны быть отбиты, вторые — не тронуты. Посадка
исполняется, а не описывается в комментарии.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile

DEFAULT_REGISTRY = "lab/claims.tsv"
STATUS_DOC = "docs/STATUS-v1.md"
READY_SCAN = ("README.md", "README.ru.md", "docs/STATUS-v1.md")
VERDICTS = ("supports", "refutes", "satisfies")
ID_RE = re.compile(r"\b(?:E|ADR|S|H|L)-\d{4}\b")
PATH_RE = re.compile(r"\b[\w./-]+\.(?:rs|sh|py|md|tsv|jsonl|lean)\b")
GATE_RE = re.compile(r"\bP\d\b")
SENT_SPLIT = re.compile(r"(?<=[.!?;])\s")  # граница — знак и пробел: «§19.3» не два предложения
CODE_STRIP = (re.compile(r"`[^`]*`"), re.compile(r"“[^”]*”"), re.compile(r"\"[^\"]*\""),
              re.compile(r"«[^»]*»"))
NEGATION = r"\b(?:not|no|never|without|absent|partial)\b"
MEASURED_MARK = r"\bmeasure(?:d|ment|s)?\b"
# Отрицание до слова делает его чужим утверждением: «not a measurement» не утверждает, что
# измерение было. Окно в 18 знаков — потому что отрицание стоит в одной фразе со словом, а не
# в начале параграфа.
NEG_BEFORE = re.compile(r"\b(?:not|no|never|without)\b[^.;]{0,18}$", re.I)


def negated(text: str, at: int) -> bool:
    return bool(NEG_BEFORE.search(text[max(0, at - 24):at]))

# Тип свидетельства → потолок формулировки. Закрытый список: новый тип заводится строкой здесь, а не
# надеждой на то, что автор реестра знал английский порядок слов.
TYPES = {
    "measured": {"forbid": [r"\balways\b", r"\bany machine\b", r"\bany host\b",
                            r"\bguarantee\w*", r"\bnever fails\b"],
                 "require": None, "need_id": True, "min_links": 1},
    "estimate": {"forbid": [MEASURED_MARK], "require": r"\bestimate\b|оценка",
                 "need_id": False, "min_links": 1},
    "not-done": {"forbid": [r"\bare closed\b", r"\bis closed\b", r"\bready for v1\b"],
                 "require": NEGATION, "need_id": False, "min_links": 1},
    "partial": {"forbid": [r"\bcomplete\b", r"\bevery word\b", r"\bfully\b", r"\bis closed\b"],
                "require": r"\bpartial\b|not closed|не закрыто", "need_id": True, "min_links": 1},
    "gate-closed": {"forbid": [r"\balways\b", r"\bguarantee\w*"], "require": None,
                    "need_id": True, "min_links": 1, "gate_ratio": True},
    "model-proof": {"forbid": [r"\bcode is proved\b", r"\bproved the code\b",
                               r"\bproduct is proved\b", r"\bguarantees the code\b"],
                    "require": r"\bmodel", "need_id": False, "min_links": 1},
    "instrument": {"forbid": [r"\balways\b", r"\bguarantee\w*", r"\bproved\b"],
                   "require": None, "need_id": False, "min_links": 1},
}

# Где живёт карточка id — тот же словарь, что у `lab/check-claim-map.py`, чтобы один класс номеров
# не жил в двух приборах с разными правилами.
ID_DIRS = {"E": "lab/experiments", "H": "lab/hypotheses", "ADR": "lab/decisions", "S": "lab/notes"}
L_INDEX = "lab/library/index.jsonl"
COLUMNS = ("id", "type", "cond", "carrier", "wording", "links")
FACT_KEYS = ("CLAIMS", "VIOLATIONS", "DANGLING", "CEILING", "QUALIFIER", "TYPE_BAD", "LINK_BAD",
             "GATE_RATIO", "COND_LINK_BAD")


def norm(text: str) -> str:
    """Пробелы и переносы не входят в утверждение: носитель переносит строку, реестр — нет."""
    return re.sub(r"\s+", " ", text).strip()


def load_rows(path: str) -> tuple[list[dict], list[str]]:
    rows, bad = [], []
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < len(COLUMNS):
                bad.append(f"строка {n} имеет {len(parts)} колонок вместо {len(COLUMNS)}")
                continue
            row = dict(zip(COLUMNS, (p.strip() for p in parts[:len(COLUMNS)])))
            row["note"] = parts[len(COLUMNS)].strip() if len(parts) > len(COLUMNS) else ""
            rows.append(row)
    return rows, bad


def read_file(root: str, rel: str) -> str | None:
    path = os.path.join(root, rel.replace("/", os.sep))
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def strip_quoted(sentence: str) -> str:
    for rx in CODE_STRIP:
        sentence = rx.sub(" ", sentence)
    return sentence


def cell_of(sentence: str, fragment: str) -> str:
    """Ячейка таблицы — это и есть утверждение: левая колонка называет условие, а не заявляет факт.

    Без разрезки по « | » строка состояния получала бы формулировку самого условия, и прибор
    считал бы запрещенным словом чужой заголовок (измерено на `docs/STATUS-v1.md`: «every word
    carries a measurement id» — текст условия 4, а не заявление о состоянии).
    """
    at = sentence.find(fragment)
    if at < 0 or " | " not in sentence:
        return sentence
    pos = 0
    for piece in sentence.split(" | "):
        if pos <= at and at + len(fragment) <= pos + len(piece):
            return piece.strip()
        pos += len(piece) + 3
    return sentence


def sentence_of(text: str, fragment: str) -> str:
    at = text.find(fragment)
    if at < 0:
        return ""
    lo = 0
    for m in SENT_SPLIT.finditer(text, 0, at):
        lo = m.end()
    hi = len(text)
    m = SENT_SPLIT.search(text, at + len(fragment))
    if m:
        hi = m.start()
    return cell_of(text[lo:hi].strip(), fragment)


def known_ids(root: str) -> set[str]:
    out: set[str] = set()
    for prefix, folder in ID_DIRS.items():
        d = os.path.join(root, folder.replace("/", os.sep))
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            m = re.match(rf"{prefix}-(\d{{4}})", name)
            if m:
                out.add(f"{prefix}-{m.group(1)}")
    index = read_file(root, L_INDEX)
    if index is not None:
        for line in index.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                lid = str(json.loads(line).get("id", ""))
            except ValueError:
                continue
            if re.fullmatch(r"L-\d{4}", lid):
                out.add(lid)
    return out


def verdict_of(root: str, eid: str) -> str | None:
    """Первое слово вердикта карточки; нет карточки или нет вердикта — `None`."""
    folder = os.path.join(root, ID_DIRS["E"].replace("/", os.sep))
    if not os.path.isdir(folder):
        return None
    for name in sorted(os.listdir(folder)):
        if name.startswith(eid):
            body = read_file(root, f"{ID_DIRS['E']}/{name}")
            if body is None:
                return None
            for raw in body.splitlines():
                m = re.match(r"^verdict:\s*['\"`]?([A-Za-z-]+)", raw)
                if m:
                    return m.group(1)
            return None
    return None


def link_reason(root: str, link: str, ids: set[str]) -> str | None:
    """`None` — ссылка годна; иначе — причина, почему она не называет носителя."""
    if link in ("", "-"):
        return "пустая ссылка"
    if ID_RE.fullmatch(link):
        if link not in ids:
            return f"под {link} нет карточки"
        if link.startswith("E-"):
            verdict = verdict_of(root, link)
            if verdict is None:
                return f"{link}: карточка без вердикта"
            if verdict not in VERDICTS:
                return f"{link}: вердикт {verdict!r} вне закрытого списка"
        return None
    if os.path.exists(os.path.join(root, link.replace("/", os.sep))):
        return None
    if "::" in link and os.path.exists(os.path.join(root, link.split("::")[0].replace("/", os.sep))):
        return f"{link}: файл есть, а такого пути в реестре быть не должно"
    return f"нет файла {link}"


def table_rows_of_status(root: str) -> int | None:
    """Сколько строк в таблице пяти условий — считывается из носителя, а не берётся из веры."""
    body = read_file(root, STATUS_DOC)
    if body is None:
        return None
    inside = 0
    for line in body.splitlines():
        if line.startswith("## The five v1 conditions"):
            inside = 1
            continue
        if inside and line.startswith("##"):
            break
        if inside and line.startswith("|") and not re.match(r"^\|[ :-]+\|", line):
            first = line.split("|")[1].strip()
            if first and first != "v1 condition":
                inside += 1
    return max(inside - 1, 0)


def check_rows(root: str, registry: str) -> tuple[dict, list[str]]:
    counts = {k: 0 for k in FACT_KEYS}
    counts.update({"CONDITIONS_TABLE": 0, "CONDITIONS_COVERED": 0, "READY_CARRIERS": 0,
                   "READY_VALUES": 0, "READY_DISTINCT": 0})
    problems: list[str] = []

    def fire(kind: str, msg: str) -> None:
        if kind in counts:
            counts[kind] += 1
        counts["VIOLATIONS"] += 1
        problems.append(f"НАРУШЕНИЕ {kind}: {msg}")

    rows, malformed = load_rows(registry)
    for bad in malformed:
        fire("TYPE_BAD", f"реестр повреждён: {bad}")
    ids = known_ids(root)
    counts["CLAIMS"] = len(rows)
    covered: set[str] = set()

    for row in rows:
        cid, typ = row["id"], row["type"]
        rule = TYPES.get(typ)
        if rule is None:
            fire("TYPE_BAD", f"{cid}: тип {typ!r} вне закрытого списка {sorted(TYPES)}")
            continue
        body = read_file(root, row["carrier"])
        if body is None:
            fire("DANGLING", f"{cid}: нет носителя {row['carrier']}")
            continue
        text = norm(body)
        frag = norm(row["wording"])
        if frag not in text:
            fire("DANGLING", f"{cid}: формулировка не найдена дословно в {row['carrier']}: "
                             f"{frag[:60]!r}")
            continue
        sentence = sentence_of(text, frag)
        bare = strip_quoted(sentence)
        for pat in rule["forbid"]:
            for m in re.finditer(pat, bare, re.I):
                if negated(bare, m.start()):
                    continue
                fire("CEILING", f"{cid}: тип {typ} не имеет права на {m.group(0)!r}")
                break
        if rule["require"] and not re.search(rule["require"], bare, re.I):
            fire("QUALIFIER", f"{cid}: типу {typ} обязана принадлежать строка {rule['require']!r}")
        if rule["need_id"] and not ID_RE.search(sentence):
            fire("QUALIFIER", f"{cid}: типу {typ} обязан принадлежать id замера этой строки")
        if rule.get("gate_ratio"):
            gates = sorted(set(GATE_RE.findall(sentence)))
            cites = sorted(set(ID_RE.findall(sentence)) | set(PATH_RE.findall(sentence)))
            if len(gates) > len(cites):
                fire("GATE_RATIO", f"{cid}: гейтов {gates} = {len(gates)}, носителей "
                                   f"{cites} = {len(cites)}")
        links = [l.strip() for l in row["links"].split(",") if l.strip()]
        if len(links) < rule["min_links"]:
            fire("LINK_BAD", f"{cid}: ссылок {len(links)}, типу {typ} нужно {rule['min_links']}")
        for link in links:
            reason = link_reason(root, link, ids)
            if reason:
                fire("LINK_BAD", f"{cid}: {reason}")
        if row["cond"] not in ("", "-"):
            if re.fullmatch(r"[1-9]\d*", row["cond"]):
                covered.add(row["cond"])
            else:
                fire("COND_LINK_BAD", f"{cid}: колонка cond = {row['cond']!r} вне 1..N")

    table = table_rows_of_status(root)
    if table is None:
        fire("DANGLING", f"нет {STATUS_DOC}: покрытие таблицы пяти условий нечем сверять")
        table = 0
    counts["CONDITIONS_TABLE"] = table
    counts["CONDITIONS_COVERED"] = table - len([i for i in range(1, table + 1)
                                                if str(i) not in covered])
    missing = [str(i) for i in range(1, table + 1) if str(i) not in covered]
    if missing:
        fire("COND_LINK_BAD", f"условия {','.join(missing)} не покрыты ни одной строкой реестра")

    values: set[str] = set()
    seen = 0
    for rel in READY_SCAN:
        body = read_file(root, rel)
        if body is None:
            continue
        seen += 1
        for m in re.finditer(r"(?:≈|около|about)\s*(\d{1,3})\s*%\s*(?:ready|readiness|готовность)"
                             r"|(?:readiness|готовность)\s*(?:v1\s*)?[^%.]{0,40}?(\d{1,3})\s*%",
                             norm(body), re.I):
            values.add(m.group(1) or m.group(2))
    counts["READY_CARRIERS"] = seen
    counts["READY_VALUES"] = len(values)
    counts["READY_DISTINCT"] = len(values)
    if len(values) > 1:
        fire("CEILING", f"цифра готовности печатает {len(values)} значений в {seen} носителях: "
                        f"{sorted(values, key=int)} — у имени факта один владелец")
    elif seen and not values:
        fire("QUALIFIER", "ни один носитель не печатает цифру готовности: правило сверяет пустоту")
    return counts, problems


CASES = [
    # (id, тип, cond, носитель, формулировка, ссылки, должен ли нарушить, имя случая)
    ("C-101", "measured", "-", "docs/STATUS-v1.md", "The audit was run once by `E-0001`",
     "E-0001", False, "законное измеренное"),
    ("C-102", "estimate", "-", "docs/STATUS-v1.md", "The estimate is about 40 %",
     "docs/STATUS-v1.md", False, "законная оценка"),
    ("C-103", "model-proof", "-", "docs/STATUS-v1.md",
     "It proves statements about the model, not about code", "ADR-0001", False,
     "законная модель с оговоркой"),
    ("C-104", "not-done", "-", "docs/STATUS-v1.md", "The run has not happened",
     "docs/STATUS-v1.md", False, "законное не-сделано"),
    ("C-105", "gate-closed", "-", "docs/STATUS-v1.md",
     "Gates P3 and P5 are closed by `E-0001` and `lab/claims.tsv`", "E-0001", False,
     "законный гейт с носителем на каждый"),
    ("C-106", "guessed", "-", "docs/STATUS-v1.md", "The audit was run once by `E-0001`",
     "E-0001", True, "выдуманный тип"),
    ("C-107", "measured", "-", "docs/STATUS-v1.md", "The audit was run twice", "E-0001", True,
     "формулировки нет в носителе"),
    ("C-108", "measured", "-", "docs/STATUS-v1.md", "The stand always finishes", "E-0001", True,
     "«всегда» под типом measured"),
    ("C-109", "estimate", "-", "docs/STATUS-v1.md", "It is measured once, the estimate",
     "docs/STATUS-v1.md", True, "оценка названа измерением"),
    ("C-110", "model-proof", "-", "docs/STATUS-v1.md", "Everything is complete", "E-0001", True,
     "модель без слова model"),
    ("C-111", "measured", "-", "docs/STATUS-v1.md", "The audit was run once by `E-0001`",
     "E-9999", True, "несуществующий id"),
    ("C-112", "gate-closed", "-", "docs/STATUS-v1.md",
     "Gates P2 and P4 are closed by `E-0001`", "E-0001", True, "два гейта, один носитель"),
    ("C-113", "not-done", "-", "docs/STATUS-v1.md", "Everything is complete",
     "docs/STATUS-v1.md", True, "not-done без отрицания"),
]

SELFTEST_DOC = (
    "The audit was run once by `E-0001`. The stand always finishes. "
    "The estimate is about 40 %. It is measured once, the estimate. "
    "It proves statements about the model, not about code. "
    "The run has not happened. Everything is complete. "
    "Gates P2 and P4 are closed by `E-0001`. Gates P3 and P5 are closed by `E-0001` and "
    "`lab/claims.tsv`. Readiness is about 40 %.\n"
)


def selftest_tree(root: str) -> None:
    for folder in ("docs", "lab/experiments", "lab/decisions"):
        os.makedirs(os.path.join(root, folder.replace("/", os.sep)), exist_ok=True)
    with open(os.path.join(root, "lab", "experiments", "E-0001-planted.md"), "w",
              encoding="utf-8") as fh:
        fh.write('---\nid: E-0001\nverdict: "supports"\n---\n\n# карточка посадки\n')
    with open(os.path.join(root, "lab", "decisions", "ADR-0001-planted.md"), "w",
              encoding="utf-8") as fh:
        fh.write("# ADR-0001 — карточка посадки\n")
    for name in ("docs/STATUS-v1.md", "README.md", "README.ru.md"):
        with open(os.path.join(root, name.replace("/", os.sep)), "w", encoding="utf-8") as fh:
            fh.write(SELFTEST_DOC)


def selftest(root: str) -> dict:
    selftest_tree(root)
    registry = os.path.join(root, "lab", "claims.tsv")
    with open(registry, "w", encoding="utf-8") as fh:
        fh.write("# id\ttype\tcond\tcarrier\twording\tlinks\tnote\n")
        for cid, typ, cond, carrier, wording, links, should, name in CASES:
            fh.write(f"{cid}\t{typ}\t{cond}\t{carrier}\t{wording}\t{links}\t{name}\n")
    counts, problems = check_rows(root, registry)
    fired = {m.group(1) for line in problems for m in [re.search(r"\b(C-1\d\d)\b", line)] if m}
    planted = [c for c in CASES if c[6]]
    legal = [c for c in CASES if not c[6]]
    caught = sum(1 for c in planted if c[0] in fired)
    false = sum(1 for c in legal if c[0] in fired)
    for cid, _t, _c, _ca, _w, _l, should, name in CASES:
        hit = cid in fired
        ok = hit == should
        print(f"СЕЛФТЕСТ {'ok' if ok else 'ПРОВАЛ'}: {name} ({cid}) "
              f"нарушение={int(hit)} ожидалось={int(should)}")
    for line in problems:
        print("  " + line)
    return {"PLANTED_TOTAL": len(planted), "PLANTED_CAUGHT": caught,
            "PLANTED_FALSE": false, "LEGAL_TOTAL": len(legal), "ROWS": len(CASES)}


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true", help="посаженные дефекты на временном дереве")
    ap.add_argument("--root", default=".", help="корень репозитория")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY, help="файл реестра")
    args = ap.parse_args(argv)
    if args.selftest:
        with tempfile.TemporaryDirectory(prefix="claims-selftest-") as tmp:
            res = selftest(tmp)
        print(f"PLANTED_TOTAL={res['PLANTED_TOTAL']}")
        print(f"PLANTED_CAUGHT={res['PLANTED_CAUGHT']}/{res['PLANTED_TOTAL']}")
        print(f"PLANTED_FALSE={res['PLANTED_FALSE']}")
        print(f"LEGAL_TOTAL={res['LEGAL_TOTAL']}")
        ok = (res["PLANTED_CAUGHT"] == res["PLANTED_TOTAL"] and res["PLANTED_FALSE"] == 0)
        print(f"CLAIMS_SELFTEST_EXIT={0 if ok else 1}")
        return 0 if ok else 1
    registry = (args.registry if os.path.isabs(args.registry)
                else os.path.join(args.root, args.registry))
    if not os.path.isfile(registry):
        print(f"РЕЕСТР_НЕТ {registry}")
        return 2
    counts, problems = check_rows(args.root, registry)
    for line in problems:
        print(line)
    for key in FACT_KEYS:
        print(f"{key}={counts[key]}")
    for key in ("CONDITIONS_TABLE", "CONDITIONS_COVERED", "READY_CARRIERS", "READY_VALUES"):
        print(f"{key}={counts[key]}")
    print(f"VIOLATIONS={counts['VIOLATIONS']}")
    print(f"CLAIMS_GUARD_EXIT={0 if counts['VIOLATIONS'] == 0 else 1}")
    return 0 if counts["VIOLATIONS"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
