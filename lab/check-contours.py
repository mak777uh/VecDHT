#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сведение закрытых карточек очереди с блоками прогона контура (`H-0138`).

Определение «зелёно» в `docs/AUTONOMY.md` требует `cargo test --workspace` без падений и `clippy`
без предупреждений. Слово «вердикт» в шапке карточки этого не стоит: его стоит блок контура —
строка `########## E-XXXX · workspace-verify · <метка времени> ##########` в носителе `lab/logs/`.
Прибор сводит два множества и печатает расхождение числом.

Правила:

* закрытая карточка (`verdict` из списка `supports`, `refutes`, `satisfies`) обязана либо иметь блок
  контура, либо стоять в `lab/contour-exceptions.tsv` с причиной;
* причина обязана быть напечатана: пустая строка делает исключение способом молчания;
* файла исключений может не быть — это не поломка чтения и не «пустая причина»: прибор печатает
  `EXCEPTIONS_ABSENT=1` и название непокрытых числом, потому что отсутствие файла и есть то
  состояние дерева, которое находят закрытые карточки без блока;
* класс исключения сверяется с деревом: `до-формы` разрешено только карточке с id раньше первой
  метки контура, `после-формы` — позже;
* исключение не должно прикрывать карточку, у которой блок уже есть, и не должно ссылаться на
  незакрытую или несуществующую карточку (такое исключение — фантом).

Метка с суффиксом (`E-0107b` — второе исполнение того же цикла) покрывает свою карточку: суффикс
печатает номер исполнения, а не новый адрес.

Выход: 0 — непокрытых без причины нет и фантомов нет; 1 — есть хотя бы одно нарушение; 2 — дерево
не читается (нет `lab/experiments`, нет логов).
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys
import tempfile

DEFAULT_EXCEPTIONS = "lab/contour-exceptions.tsv"
VERDICTS = ("supports", "refutes", "satisfies")
CARD_RE = re.compile(r"^E-\d{4}")
BLOCK_RE = re.compile(r"^#+\s+(E-\d{4})[a-z]?\s*·\s*workspace-verify\s*·", re.M)
LABEL_RE = re.compile(r"E-\d{4}")
CLASSES = ("до-формы", "после-формы")
FACT_KEYS = ("CLOSED_TOTAL", "BLOCK_LABELS", "COVERED", "MISSING_TOTAL", "EXPLAINED",
             "UNEXPLAINED", "ERA_TOTAL", "MODERN_TOTAL", "EXCEPTIONS_ABSENT", "REASON_EMPTY",
             "CLASS_BAD", "GHOST", "DUP", "VIOLATIONS")


def read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def verdict_of(text: str) -> str | None:
    """Вердикт берётся из YAML-шапки, а не из тела: тело цитирует чужие вердикты."""
    head = text.split("---", 2)
    if len(head) < 3:
        return None
    m = re.search(r"^verdict:\s*['\"`]?([A-Za-z-]+)", head[1], re.M)
    return m.group(1) if m else None


def closed_cards(root: str) -> dict[str, str]:
    out = {}
    for path in sorted(glob.glob(os.path.join(root, "lab", "experiments", "E-*.md"))):
        text = read(path)
        if text is None:
            continue
        cid = CARD_RE.match(os.path.basename(path))
        if not cid:
            continue
        verdict = verdict_of(text)
        if verdict in VERDICTS:
            out[cid.group(0)] = verdict
    return out


def block_labels(root: str) -> set[str]:
    out: set[str] = set()
    for path in sorted(glob.glob(os.path.join(root, "lab", "logs", "*.log"))):
        text = read(path)
        if text:
            out |= set(BLOCK_RE.findall(text))
    return out


def load_exceptions(path: str) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    bad: list[str] = []
    text = read(path)
    if text is None:
        # отсутствие файла — не поломка чтения и не «пустая причина»: это то же самое, что файл
        # без строк, и прибор обязан назвать число непокрытых, а не выдумывать нарушение
        return rows, []
    for num, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            bad.append(f"строка {num}: колонок {len(parts)}, нужно 3 (id · класс · причина)")
            continue
        if not LABEL_RE.fullmatch(parts[0].strip()):
            bad.append(f"строка {num}: id {parts[0]!r} вне формы E-NNNN")
            continue
        rows.append({"id": parts[0].strip(), "cls": parts[1].strip(),
                     "reason": parts[2].strip(), "line": num})
    return rows, bad


def check(root: str, exceptions_rel: str) -> tuple[dict, list[str], set[str]]:
    counts = {k: 0 for k in FACT_KEYS}
    problems: list[str] = []
    fired: set[str] = set()

    def fire(kind: str, msg: str, cid: str | None = None) -> None:
        counts[kind] += 1
        counts["VIOLATIONS"] += 1
        problems.append(f"НАРУШЕНИЕ {kind}: {msg}")
        if cid:
            fired.add(cid)

    closed = closed_cards(root)
    blocks = block_labels(root)
    if not closed:
        print(f"СВЕДЕНИЕ_НЕТ закрытых карточек в {root}: сверять нечем")
        return counts, problems, fired
    counts["CLOSED_TOTAL"] = len(closed)
    counts["BLOCK_LABELS"] = len(blocks)
    covered = {c for c in closed if c in blocks}
    counts["COVERED"] = len(covered)
    missing = sorted(set(closed) - covered)
    counts["MISSING_TOTAL"] = len(missing)

    form_first = min(blocks) if blocks else "E-0000"
    print(f"FORM_FIRST={form_first}")

    # путь решается относительно названного корня: `--root` временного каталога обязан получать
    # временное дерево, а не то, что лежит под текущим каталогом оболочки (иначе самопроверка
    # читает живые исключения и считает фантомами свои же законные строки). Абсолютный аргумент
    # os.path.join пропускает как есть
    exc_path = os.path.join(root, exceptions_rel)
    if not os.path.exists(exc_path) and os.path.exists(exceptions_rel):
        exc_path = exceptions_rel
    counts["EXCEPTIONS_ABSENT"] = 0 if os.path.exists(exc_path) else 1
    rows, malformed = load_exceptions(exc_path)
    for bad in malformed:
        fire("REASON_EMPTY", f"файл исключений повреждён: {bad}")
    by_id: dict[str, dict] = {}
    valid: set[str] = set()
    for row in rows:
        cid = row["id"]
        if cid in by_id:
            fire("DUP", f"{cid}: исключение записано дважды (строки {by_id[cid]['line']} "
                        f"и {row['line']})", cid)
            continue
        by_id[cid] = row
        ok = True
        if row["reason"] in ("", "-") or len(row["reason"]) < 12:
            fire("REASON_EMPTY", f"{cid}: причина не напечатана ({row['reason']!r})", cid)
            ok = False
        if row["cls"] not in CLASSES:
            fire("CLASS_BAD", f"{cid}: класс {row['cls']!r} вне закрытого списка {list(CLASSES)}",
                 cid)
            ok = False
        elif row["cls"] == "до-формы" and cid >= form_first:
            fire("CLASS_BAD", f"{cid}: помечено «до-формы», а форма блока началась с {form_first}",
                 cid)
            ok = False
        elif row["cls"] == "после-формы" and cid < form_first:
            fire("CLASS_BAD", f"{cid}: помечено «после-формы», а его id раньше {form_first}", cid)
            ok = False
        if cid in covered:
            fire("GHOST", f"{cid}: блок контура есть, исключение прикрывает молчание", cid)
            ok = False
        elif cid not in closed:
            fire("GHOST", f"{cid}: карточка не закрыта (или её нет), исключение не о чём", cid)
            ok = False
        if ok:
            valid.add(cid)

    unexplained = [m for m in missing if m not in valid]
    counts["EXPLAINED"] = len(missing) - len(unexplained)
    counts["ERA_TOTAL"] = len([r for r in rows if r["cls"] == "до-формы"])
    counts["MODERN_TOTAL"] = len([r for r in rows if r["cls"] == "после-формы"])
    for m in unexplained:
        fire("UNEXPLAINED", f"{m}: закрыта вердиктом {closed[m]!r}, блока контура нет, "
                            f"исключения нет", m)
    print(f"MISSING_UNEXPLAINED_LIST={','.join(unexplained) if unexplained else 'none'}")
    return counts, problems, fired


# (карточка, вердикт, блок контура, строки исключений, ожидание, имя случая)
LEGAL = [
    ("E-0001", "supports", False, [("до-формы", "закрыта до того, как блок контура стал формой")],
     "законное исключение эры до формы"),
    ("E-0049", "supports", True, [], "закрыта и покрыта блоком"),
    ("E-0050", "supports", "suffix", [], "блок второго исполнения (метка с суффиксом) покрывает"),
    ("E-0051", "refutes", False, [("после-формы", "контур не исполнялся, снят только helper")],
     "законное исключение с причиной"),
]
PLANTED = [
    ("E-0101", "supports", False, [], "закрыта без блока и без причины"),
    ("E-0102", "supports", False, [("после-формы", "")], "исключение без причины"),
    ("E-0103", "supports", False, [("вечно", "причина есть, класс выдуман")], "класс вне списка"),
    ("E-0104", "supports", False, [("до-формы", "id позже первой метки формы")],
     "класс не сверяется с деревом"),
    ("E-0105", "supports", True, [("после-формы", "блок контура у карточки есть")],
     "исключение прикрывает покрытую карточку"),
    ("E-0106", "pending", False, [("после-формы", "карточка не закрыта вердиктом из списка")],
     "исключение о незакрытой карточке"),
    ("E-0107", "satisfies", False, [("после-формы", "записано дважды"),
                                    ("после-формы", "записано дважды")], "дубликат исключения"),
    ("E-0110", None, False, [("после-формы", "строка без карточки: фантом")],
     "исключение несуществующей карточки"),
    ("E-0052", "supports", "other", [], "блок есть, но не формы контура"),
]


def selftest_tree(root: str) -> None:
    exp = os.path.join(root, "lab", "experiments")
    logs = os.path.join(root, "lab", "logs")
    os.makedirs(exp, exist_ok=True)
    os.makedirs(logs, exist_ok=True)
    blocks = ["########## E-0049 · workspace-verify · 2026-01-01T00:00:00+03:00 ##########",
              "########## E-0050b · workspace-verify · 2026-01-01T02:00:00+03:00 ##########",
              "########## E-0105 · workspace-verify · 2026-01-02T00:00:00+03:00 ##########",
              "########## E-0052 · разбор · 2026-01-03T00:00:00+03:00 ##########"]
    with open(os.path.join(logs, "selftest.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(blocks) + "\n")
    with open(os.path.join(exp, "E-0049-first.md"), "w", encoding="utf-8") as fh:
        fh.write('---\nid: E-0049\nverdict: "supports"\n---\n\nпервая метка формы\n')
    with open(os.path.join(exp, "E-0110-open.md"), "w", encoding="utf-8") as fh:
        fh.write('---\nid: E-0110\nverdict: "pending"\n---\n\nне закрыта, но в исключениях лежит\n')
    for cid, verdict, block, _exc, _name in LEGAL + PLANTED:
        if cid in ("E-0049", "E-0110"):
            continue
        with open(os.path.join(exp, f"{cid}-planted.md"), "w", encoding="utf-8") as fh:
            fh.write(f'---\nid: {cid}\nverdict: "{verdict}"\n---\n\nпосадка\n')


def selftest_exceptions(path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# id · класс · причина\n")
        for cases in (LEGAL, PLANTED):
            for cid, _v, _b, excs, _name in cases:
                for cls, reason in excs:
                    fh.write(f"{cid}\t{cls}\t{reason}\n")


def selftest(root: str) -> dict:
    selftest_tree(root)
    exc = os.path.join(root, "lab", "contour-exceptions.tsv")
    selftest_exceptions(exc)
    counts, problems, fired = check(root, "lab/contour-exceptions.tsv")
    want_bad = {c[0] for c in PLANTED}
    want_good = {c[0] for c in LEGAL}
    caught = len(want_bad & fired)
    false = len(want_good & fired)
    for cid, _v, _b, _e, name in PLANTED:
        print(f"СЕЛФТЕСТ {'ok' if cid in fired else 'ПРОВАЛ'}: посадка {name} ({cid})")
    for cid, _v, _b, _e, name in LEGAL:
        print(f"СЕЛФТЕСТ {'ok' if cid not in fired else 'ПРОВАЛ'}: законный случай {name} ({cid})")
    for line in problems:
        print("  " + line)
    # отдельная проба: файла исключений нет — прибор обязан назвать число непокрытых и флаг
    # отсутствия, а не превратить отсутствие файла в «пустую причину»
    absent_counts, absent_problems, _af = check(root, "lab/нет-такого-файла.tsv")
    absent_ok = (absent_counts["EXCEPTIONS_ABSENT"] == 1 and absent_counts["UNEXPLAINED"] == 8
                 and absent_counts["REASON_EMPTY"] == 0)
    print(f"СЕЛФТЕСТ {'ok' if absent_ok else 'ПРОВАЛ'}: файла исключений нет — печатается число "
          f"(`UNEXPLAINED={absent_counts['UNEXPLAINED']}`, "
          f"`REASON_EMPTY={absent_counts['REASON_EMPTY']}`)")
    return {"PLANTED_TOTAL": len(PLANTED), "PLANTED_CAUGHT": caught, "PLANTED_FALSE": false,
            "LEGAL_TOTAL": len(LEGAL), "UNEXPLAINED": counts["UNEXPLAINED"],
            "GHOST": counts["GHOST"], "REASON_EMPTY": counts["REASON_EMPTY"],
            "CLASS_BAD": counts["CLASS_BAD"], "DUP": counts["DUP"],
            "VIOLATIONS": counts["VIOLATIONS"],
            "ABSENT_UNEXPLAINED": absent_counts["UNEXPLAINED"],
            "ABSENT_OK": 1 if absent_ok else 0}


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true", help="посаженные дефекты на временном дереве")
    ap.add_argument("--root", default=".", help="корень репозитория")
    ap.add_argument("--exceptions", default=DEFAULT_EXCEPTIONS, help="файл исключений")
    args = ap.parse_args(argv)
    if args.selftest:
        with tempfile.TemporaryDirectory(prefix="contours-selftest-") as tmp:
            res = selftest(tmp)
        for key in ("PLANTED_TOTAL", "PLANTED_CAUGHT", "PLANTED_FALSE", "LEGAL_TOTAL",
                    "UNEXPLAINED", "GHOST", "REASON_EMPTY", "CLASS_BAD", "DUP", "VIOLATIONS",
                    "ABSENT_UNEXPLAINED", "ABSENT_OK"):
            print(f"SELFTEST_{key}={res[key]}")
        # числа ниже — не вера в правило, а то, сколько нарушений объявлено самой таблицей
        # посадки: 5 карточек без годного исключения, 3 фантома, 1 пустая причина,
        # 2 неверных класса, 1 дубликат; проба без файла — 8 непокрытых
        ok = (res["PLANTED_CAUGHT"] == res["PLANTED_TOTAL"] and res["PLANTED_FALSE"] == 0
              and res["UNEXPLAINED"] == 5 and res["GHOST"] == 3 and res["DUP"] == 1
              and res["REASON_EMPTY"] == 1 and res["CLASS_BAD"] == 2 and res["ABSENT_OK"] == 1)
        print(f"CONTOURS_SELFTEST_EXIT={0 if ok else 1}")
        return 0 if ok else 1
    if not os.path.isdir(os.path.join(args.root, "lab", "experiments")):
        print(f"ДЕРЕВО_НЕЧИТАЕМО нет {os.path.join(args.root, 'lab', 'experiments')}")
        return 2
    counts, problems, _fired = check(args.root, args.exceptions)
    for line in problems:
        print(line)
    for key in FACT_KEYS:
        print(f"{key}={counts[key]}")
    print(f"CONTOURS_EXIT={0 if counts['VIOLATIONS'] == 0 else 1}")
    return 0 if counts["VIOLATIONS"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
