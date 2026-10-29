#!/usr/bin/env python3
"""H-0131 / E-0131 (ADR-0072): страж существования цитируемых артефактов.

Перенесено из flowguard-spec, но без их предупреждающего режима: там `lab/check-claims.py` отмечает
«cited artifact отсутствует» как warning, а `lab/check-links.py` проверяет только markdown-ссылки.
У нас предупреждение не переносится (молчание = провал), а проверка ссылок почти бесполезна:
измерено на этом дереве 2026-10-27 — относительных markdown-ссылок 73, битых 0. Настоящий носитель
обещаний в VecDHT — backtick-цитаты путей, по ним и ходит страж.

Правила, каждое с причиной:
(1) рассматриваются только tracked `.md` и только цитаты в бэктиках, содержащие разделитель путей,
    заканчивающиеся известным расширением и не являющиеся URL;
(2) цитата живая, если полное относительное имя существует ИЛИ имя файла существует в репозитории
    где-то: карточки ссылаются по базовому имени намеренно (`service.rs`, `e0131-run.sh`);
(3) плейсхолдеры (`*`, `<`, `>`, `…`, `{`, `}`, `%`, классы `[0-9]`, `[a-z]`, `XXXX`, `00XX`) — форма
    записи, а не обещание файла;
(4) отсутствующий путь проходит только если он назван в ALLOWLIST с причиной. ALLOWLIST — единственное
    место, где «ещё не существует» перестаёт быть молчанием, и он сам под проверкой: если разрешённое
    имя появилось в дереве, разрешение устарело и это находка (иначе список деградирует в то, чем его
    всегда подозревают, — в индульгенцию).

Выход 0 — находок нет; 1 — находки напечатаны; 2 — сломан прибор. `--selftest` сажает вымышленный
путь (обязан быть пойман), проверяет, что плейсхолдер и URL не ловятся, что разрешённый план не
ловится, и что устаревшее разрешение ловится (ДИАГНОЗ-2 цикла E-0130: у разрешения обязан быть
исполняемый тест на посадку).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile

EXTS = (".rs", ".py", ".sh", ".md", ".toml", ".yaml", ".yml", ".json",
        ".jsonl", ".tsv", ".cwl", ".lean")
PLACE = ("*", "<", ">", "\u2026", "{", "}", "%", "XXXX", "00XX", "[0-9]", "[a-z]")
CITE = re.compile(r"`([^`\n]{3,160})`")

# Каталог переписки: ссылки в заметках другого репозитория описывают его дерево, а не наше.
# Исключение названо и проверяется самотестом (вымышленный путь в docs/ ловится, в interop/ — нет).
# `cross-audit/` добавлен кругом `E-0154`: рецензия LexSpec (коммит `61a9767`) кончается строкой
# «след этой рецензии — одна строка в моём docs/30-REPO-WALK.md»; такого файла в нашем дереве нет
# и не планируется, то есть страж краснел на пути чужого дерева. Править заметку рецензента
# означало бы подделать чужой след, поэтому назван каталог переписки, а не отдельный путь.
EXTERNAL_DIRS = ("interop/", "lab/logs/", "cross-audit/")
SEP = ("/", chr(92))

# Разрешения. У каждого — причина, и пустая причина есть находка.
ALLOWLIST = {
    # (а) План размещения, описанный спекой v8 до того, как дерево стало `crates/*`.
    "manifest.json": "спека v8 описывает план каталога моделей, не факт дерева",
    "fetch-model.sh": "спека v8: запланированный загрузчик модели",
    "verify-model.sh": "спека v8: запланированный верификатор модели",
    "genesis.rs": "спека v8: план `core/src/genesis.rs`, продукт живёт в `crates/*`",
    # (б) Артефакты смежного проекта, названные вслух как чужие.
    "escrow.lean": "модель эскроу proof-market: docs/PAID_ORDERS.md §6 прямо говорит, что в этом "
                   "дереве её нет; тот же путь назван в docs/TASK-spec-v9-paid-orders.md как "
                   "mak777uh/audits",
    "valuepath.lean": "модель идемпотентности смежного проекта, docs/PAID_ORDERS.md §6",
    "flows.lean": "модель Project Morphogenesis (репо `-`); lab/PLAN.md запрещает внешние числа",
    "flows_info.lean": "то же: уровень событий смежного проекта, вне этого дерева",
    "Prelude.lean": "файл тулчейна Lean 4.36.0-rc1 (`Init/Prelude.lean`), вне репозитория",
    "verifier-image.yml": "план CI из docs/PLAN-v1.md:363, workflow не создан",
    "REGISTRY.md": "реестр панельного ревью: каталог review-panel/ в дерево не закоммичен, "
                   "ссылка E-0114 ведёт на несуществующий артефакт (названо здесь, а не молча)",
    # (в) Исторические имена и свидетельства отсутствия.
    "h0090-run.sh": "прежнее имя helper'а: карточка E-0090 сама описывает переименование в "
                    "lab/e0090-run.sh",
    "h-selftests-run.sh": "имя, названное оракулом H-0151 и переименованное до первого прогона в "
                          "lab/e0151-run.sh; файла с таким именем не было",
    "config.toml": "карточка E-0086 цитирует `.cargo/config.toml` как ОТСУТСТВУЮЩИЙ («его нет » — "
                   "свидетельство, а не обещание файла)",
    "check-interop.py": "артефакт смежного репозитория flowguard-spec, назван в ADR-0072",
    "check-links.py": "то же: их страж ссылок, в нашем дереве его нет и не планируется",
    "99-SOURCES.md": "их реестр источников, где VecDHT назван методом-эталоном",
    "2026-10-27.md": "их интероп-отчёт (docs/interop/) — артефакт чужого дерева",
}


def tracked(root):
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, cwd=root)
    if out.returncode != 0:
        print("ПРИБОР: git ls-files не исполнен", file=sys.stderr)
        sys.exit(2)
    files = out.stdout.split()
    return files, {os.path.basename(f) for f in files}


def is_promise(s: str) -> bool:
    if any(p in s for p in PLACE):
        return False
    if "://" in s or " " in s or s.startswith(SEP):
        return False
    if not s.endswith(EXTS):
        return False
    return any(sep in s for sep in SEP)


def scan(md_files, bases, root):
    findings = []
    cited = 0
    for f in md_files:
        if f.startswith(EXTERNAL_DIRS):
            continue
        path = os.path.join(root, f)
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for m in CITE.finditer(text):
            s = m.group(1)
            if not is_promise(s):
                continue
            cited += 1
            norm = s.replace(SEP[1], SEP[0])
            b = os.path.basename(norm)
            full = os.path.normpath(norm)
            if os.path.exists(os.path.join(root, full)) or b in bases:
                if b in ALLOWLIST:
                    findings.append((f, s, "устаревшее_разрешение"))
                continue
            if b in ALLOWLIST:
                continue
            findings.append((f, s, "цитата"))
    for b, why in sorted(ALLOWLIST.items()):
        if not str(why).strip():
            findings.append(("lab/check-artifact-refs.py", b, "пустая_причина"))
    return cited, findings


def selftest(root):
    """Посадки прибора на собственном временном корне, без записи в рабочее дерево.

    Исключение каталога проверяется на НАСТОЯЩЕМ файле в `interop/`: до круга `H-0153` самотест
    скармливал `scan` имя файла, которого нет, поэтому «исключение работает» и «файла нет» давали
    один и тот же зелёный, а снятие исключения не краснило тест. Теперь тот же файл обязан дать
    находку при снятом исключении — иначе самотест красный.
    """
    global EXTERNAL_DIRS
    tmp = tempfile.mkdtemp(prefix="refs-")
    ok = True
    try:
        with open(os.path.join(tmp, "planted.md"), "w", encoding="utf-8") as fh:
            fh.write(
                "хорошая: `lab/check-secrets.sh`\n"
                "вымышленный: `lab/nonexistent-guard-9000.py`\n"
                "плейсхолдер: `lab/expectations/eXXXX.tsv` и `benches/src/bench/{a,b}.rs`\n"
                "url: `https://example.com/a/queries.train.tsv`\n"
                "разрешённый план: `core/src/genesis.rs`\n"
            )
        rel = "planted.md"
        cited, found = scan([rel], {"check-secrets.sh"}, tmp)
        kinds = [(s, k) for _, s, k in found]
        if ("lab/nonexistent-guard-9000.py", "цитата") in kinds:
            print("PLANT_REF=caught")
        else:
            print("САМОТЕСТ: вымышленный путь не пойман", file=sys.stderr)
            ok = False
        if len(found) != 1:
            print("САМОТЕСТ: ожидалась одна находка, названо %d" % len(found), file=sys.stderr)
            ok = False
        if any("XXXX" in s or "{" in s or "://" in s for s, _ in kinds):
            print("САМОТЕСТ: плейсхолдер или url пойман как дефект", file=sys.stderr)
            ok = False
        # Исключение каталога переписки: заметка о чужом дереве не обязана краснеть за чужие пути.
        # Файл существует — иначе отличие исключения от отсутствия не проверяется.
        os.makedirs(os.path.join(tmp, "interop"))
        with open(os.path.join(tmp, "interop", "planted2.md"), "w", encoding="utf-8") as fh:
            fh.write("чужое дерево: `lab/nonexistent-guard-9000.py`\n")
        cited_ext, found_ext = scan(["interop/planted2.md"], set(), tmp)
        if cited_ext == 0 and not found_ext:
            print("EXTERNAL_DIR=excluded")
        else:
            print("САМОТЕСТ: каталог переписки не исключён", file=sys.stderr); ok = False
        saved = EXTERNAL_DIRS
        EXTERNAL_DIRS = ()
        try:
            cited_neg, found_neg = scan(["interop/planted2.md"], set(), tmp)
        finally:
            EXTERNAL_DIRS = saved
        # Ключ называется иначе, чем исключение: два факта одной строкой `EXTERNAL_DIR=` слились бы
        # в один, и читатель вывода («последнее wins») увидел бы `tested` там, где прибор проверял
        # `excluded` (ДИАГНОЗ круга H-0153: у имени факта обязан быть один владелец).
        if cited_neg == 1 and any(k == "цитата" for _, _, k in found_neg):
            print("EXTERNAL_DIR_REMOVAL=tested")
        else:
            print("САМОТЕСТ: снятое исключение не краснит — посадка не исполняема", file=sys.stderr)
            ok = False
        # Второе исключение переписки проверяется так же: настоящим файлом и его снятием. Иначе
        # «добавить каталог в кортеж» было бы формой записи, а не механизмом (тот же довод, что
        # посадил эту проверку в круге `H-0153`).
        os.makedirs(os.path.join(tmp, "cross-audit"))
        with open(os.path.join(tmp, "cross-audit", "planted3.md"), "w", encoding="utf-8") as fh:
            fh.write("чужое дерево: `docs/30-REPO-WALK.md`\n")
        cited_ca, found_ca = scan(["cross-audit/planted3.md"], set(), tmp)
        if cited_ca == 0 and not found_ca:
            print("EXTERNAL_DIR_2=excluded")
        else:
            print("САМОТЕСТ: каталог cross-audit/ не исключён", file=sys.stderr); ok = False
        saved = EXTERNAL_DIRS
        EXTERNAL_DIRS = ()
        try:
            cited_ca2, found_ca2 = scan(["cross-audit/planted3.md"], set(), tmp)
        finally:
            EXTERNAL_DIRS = saved
        if cited_ca2 == 1 and any(k == "цитата" for _, _, k in found_ca2):
            print("EXTERNAL_DIR_2_REMOVAL=tested")
        else:
            print("САМОТЕСТ: снятое второе исключение не краснит", file=sys.stderr)
            ok = False
        # Устаревшее разрешение: имя из ALLOWLIST появилось в дереве — находка обязана быть.
        _, stale = scan([rel], {"check-secrets.sh", "genesis.rs"}, tmp)
        if any(k == "устаревшее_разрешение" for _, _, k in stale):
            print("STALE_ALLOWLIST=caught")
        else:
            print("САМОТЕСТ: устаревшее разрешение не названо", file=sys.stderr)
            ok = False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("REFS_SELFTEST=%s" % ("ok" if ok else "fail"))
    return 0 if ok else 1


def main(argv):
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True).stdout.strip()
    if not root:
        print("ПРИБОР: вне git-репозитория", file=sys.stderr)
        return 2
    if "--selftest" in argv:
        return selftest(root)
    files, bases = tracked(root)
    md = [f for f in files if f.endswith(".md")]
    cited, found = scan(md, bases, root)
    empty = sum(1 for _, _, k in found if k == "пустая_причина")
    for f, s, k in found:
        print("НАХОДКА[%s] %s :: `%s`" % (k, f, s))
    # По одному ключу на строку: helper разбирает вывод построчно, и четыре ключа в одной
    # строке теряются вместе с тремя из них (ДИАГНОЗ цикла E-0131).
    for k, v in (("REFS_CITED", cited), ("REFS_MISSING", len(found)),
                 ("REFS_ALLOWED", len(ALLOWLIST)), ("REFS_ALLOWLIST_EMPTY", empty)):
        print("%s=%s" % (k, v))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
