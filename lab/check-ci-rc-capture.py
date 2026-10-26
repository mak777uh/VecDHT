#!/usr/bin/env python3
"""Прибор `E-0128`: захват кода возврата через `cmd; r=$?` несовместим с `bash -e`.

Что измеряется (и чем это НЕ является)
--------------------------------------

GitHub исполняет каждый `run:` как `bash -e {0}` (это печатает сам лог работы:
`shell: /usr/bin/bash -e {0}`). При `-e` упавшая простая команда обрывает скрипт в той же
строке, поэтому идиома

    python lab/что-то.py > "$L" 2>&1; r=$?

никогда не доходит до `r=$?`, если прибор вернулся ненулевым. Дальше не выполняется ничего:
ни печать отчёта, ни ветки `if [ "$r" -eq 0 ]`, ни `exit $r`. Код шага — единица, которую
оставил `-e`.

Отсюда два разных вреда, и их путают:

* вердикт для **действительно красного** прибора сохраняется (обрыв даёт ту же единицу), но
  отчёт теряется — по логам невозможно понять, что именно упало;
* вердикт для **ожидаемого** ненулевого кода ломается: шаг, который по замыслу обязан сойти
  нулём с названной веткой, краснеет молча. Это и есть наблюдение 2026-10-26: шаг «зеркало
  спеки» на runner'е находит `lab/check-spec-mirror.sh` вышедшим 1 по замыслу (зеркала вне git
  там нет), печатает `FAIL: зеркала … нет на месте`, и именно этот законный `1` обрывает шаг
  до ветки `MIRROR_ABSENT_ON_RUNNER=1`.

Класс отличается от `E-0127` (там grep без guard'а обрывал отчётный `while`): тот прибор
смотрит на концы труб, этот — на присваивания `$?`. Один и тот же файл может быть чист по
обоим, и зелёный `check-ci-report-greps.py` не говорит ничего про этот.

Границы прибора, названные до замера
------------------------------------

* Область — `.github/workflows/*.yml`. Файлы `lab/*.sh` здесь НЕ проверяются: они запускаются
  из helper'ов без `-e` (helper'ы берут код через `rc=${PIPESTATUS[0]}` и `note`), поэтому
  та же идиома в них безопасна. Единственное исключение найдено чтением, а не прибором, и
  закрывается в этом же цикле: `lab/check-spec-mirror.sh` стоит под собственным
  `set -euo pipefail` и содержит `diff "$ORIG" "$MIRROR" | head -40` (класс `E-0127`, не
  класс захвата). Оно проверяется не статикой, а исполнением: helper запускает сам этот
  скрипт на расходящемся зеркале и требует, чтобы последняя строка отчёта (`починить: …`)
  была напечатана, а код возврата остался единицей.
* Прибор статический: он находит форму, а не исполняет её. Исполнение — `bash -e` в helper'е
  (механика) и `extractstep` (запуск реального текста шага на хосте).
* `plant` меняет форму одной строки в КОПИИ дерева (снимает guard, ставит guard, разводит
  захват на две строки, включает `set +e`) и печатает `RCP_LANDED`. Он нужен, чтобы посадки
  были годны на дереве любого состояния: CI гоняет `selftest` на уже починном дереве, где
  буквы «снятия guard'а» нет, и проверка, построенная на букве, стала бы пустышкой.
* Молчание не успех: пустой каталог workflow'ов, пустой список блоков и ноль захватов
  дают `RCC_BLIND=1` и красных выход.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import sys
import tempfile

WF_DIR = os.path.join(".github", "workflows")

# `run: |`, `run: >-`, `run: |+`, а также форма `- run: |` (шаг без имени).
RUN_BLOCK = re.compile(r"^\s*(?:-\s+)?run:\s*[|>]")
# Однострочный `run: команда` — блок из одной строки, его тоже надо видеть.
RUN_INLINE = re.compile(r"^\s*(?:-\s+)?run:\s*\S")

# Находка: присваивание `$?`, отделённое точкой с запятой от команды, которая обязана его
# пережить. `;` здесь принципиальна: это не часть `||`, а отдельная команда в том же
# statement'е.
UNGUARDED = re.compile(r";\s*([A-Za-z_][A-Za-z0-9_]*)=\$\?\s*$")
# Правильная форма: код берётся из ветки `||`, где `-e` не срабатывает.
GUARDED = re.compile(r"\|\|\s*([A-Za-z_][A-Za-z0-9_]*)=\$\?")
# То же присваивание, но стоящее отдельной строкой сразу за командой: обрыв происходит на
# команде, до строки присваивания она не доходит. Фиксируется как находка, если предыдущая
# строка — не guard и не комментарий.
BARE_ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=\$\?\s*$")

SET_PLUS_E = re.compile(r"^\s*set\s+[+e][^e]*\b")
COND_LINE = re.compile(r"^\s*(if|elif|while|until)\b")
COMMENT = re.compile(r"^\s*#")
# Команда, которая не может вернуться ненулевым: её обрывать нечего.
NEVER_FAILS = re.compile(
    r"^\s*(echo|printf|:|true|export|set|local|cd|mkdir|touch|cat|tail|head|tee|unset)\b"
)


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read().replace("\r\n", "\n").split("\n")


def wf_files(root):
    d = os.path.join(root, WF_DIR)
    if not os.path.isdir(d):
        return None
    return sorted(
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith((".yml", ".yaml")) and os.path.isfile(os.path.join(d, n))
    )


def run_blocks(path):
    """`(номер_строки_заголовка, [(line0, текст)], base_indent)` для каждого `run:` в файле."""
    lines = read_lines(path)
    blocks = []
    i = 0
    while i < len(lines):
        if RUN_BLOCK.match(lines[i]):
            key_indent = len(lines[i]) - len(lines[i].lstrip())
            j = i + 1
            body = []
            while j < len(lines):
                line = lines[j]
                if line.strip() == "":
                    body.append((j, ""))
                elif (len(line) - len(line.lstrip())) > key_indent:
                    body.append((j, line))
                else:
                    break
                j += 1
            blocks.append((i, body, key_indent + 2))
            i = j if j > i else i + 1
        elif RUN_INLINE.match(lines[i]) and not RUN_BLOCK.match(lines[i]):
            blocks.append((i, [(i, lines[i].split("run:", 1)[1].strip())], 0))
            i += 1
        else:
            i += 1
    return blocks


def step_name_for(path, header_line0):
    """Имя шага, под которым лежит этот `run:` (строка `name:` непосредственно перед ним)."""
    lines = read_lines(path)
    for k in range(header_line0, max(header_line0 - 12, -1), -1):
        s = lines[k].strip()
        if s.startswith("- name:") or s.startswith("name:"):
            return s.split(":", 1)[1].strip().strip('"')
    return "(без имени)"


def scan_body(body, base_indent):
    """(находки, guard'ы, всего_захватов, set_plus_e) для одного блока.

    Находка — `(line0, фрагмент)`. Состояние `set +e` учитывается по порядку строк: capture
    до первой `set +e` считается, после — exemption (это отдельный факт, а не молчание).
    """
    findings = []
    guarded = 0
    total = 0
    saw_set_plus_e = False
    prev_cmd = None
    for ln0, line in body:
        text = line[base_indent:] if len(line) >= base_indent else line.strip()
        stripped = text.strip()
        if stripped == "":
            continue
        if SET_PLUS_E.match(text):
            saw_set_plus_e = True
        if COMMENT.match(text):
            continue
        if COND_LINE.match(text):
            prev_cmd = None
            continue
        m = UNGUARDED.search(text)
        if m:
            total += 1
            if GUARDED.search(text):
                guarded += 1
            elif not saw_set_plus_e:
                findings.append((ln0, stripped[:150]))
            prev_cmd = None
            continue
        if GUARDED.search(text):
            total += 1
            guarded += 1
            prev_cmd = None
            continue
        b = BARE_ASSIGN.match(text)
        if b:
            total += 1
            if (
                prev_cmd is not None
                and not GUARDED.search(prev_cmd)
                and not NEVER_FAILS.match(prev_cmd)
                and not saw_set_plus_e
            ):
                findings.append((ln0, f"присваивание $? отдельной строкой после `{prev_cmd.strip()[:80]}`"))
            prev_cmd = None
            continue
        prev_cmd = text
    return findings, guarded, total, saw_set_plus_e


def recount_lines(path):
    """Независимый пересчёт находок БЕЗ парсера YAML-блоков.

    Второй код обязывает к тому же числу другим путём: состояние `set +e` здесь сбрасывается
    на любой строке `run:` (это граница блока), а «предыдущая команда» помнится физически
    предыдущей непустой строкой. Расхождение block-сканера и этого кода значит, что один из
    двух съел строку или придумал её — ровно тот риск, который иначе остаётся невидимым,
    потому что оба кода молчат об одном и том же.
    """
    n = 0
    exempt = False
    prev = None
    for raw in read_lines(path):
        line = raw.strip()
        if line == "":
            continue
        is_header = bool(RUN_BLOCK.match(raw) or RUN_INLINE.match(raw))
        if is_header:
            exempt = False
            prev = None
            if RUN_BLOCK.match(raw):
                continue
            line = raw.split("run:", 1)[1].strip()
        if SET_PLUS_E.match(line):
            exempt = True
            prev = line
            continue
        if COMMENT.match(line):
            continue
        if COND_LINE.match(line):
            prev = None
            continue
        is_capture = bool(UNGUARDED.search(line) or GUARDED.search(line)
                          or BARE_ASSIGN.match(line))
        hit = False
        if UNGUARDED.search(line) and not GUARDED.search(line):
            hit = True
        elif BARE_ASSIGN.match(line):
            if prev is not None and not GUARDED.search(prev) and not NEVER_FAILS.match(prev):
                hit = True
        if hit and not exempt:
            n += 1
        prev = None if is_capture else line
    return n


def scan(root):
    files = wf_files(root)
    facts = {
        "RCC_FILES": 0,
        "RCC_RUN_BLOCKS": 0,
        "RCC_BLOCKS_SET_PLUS_E": 0,
        "RCC_CAPTURES": 0,
        "RCC_GUARDED": 0,
        "RCC_UNGUARDED": 0,
        "RCC_LINES_UNGUARDED": 0,
        "RCC_RECOUNT_EQ": 0,
        "RCC_BLIND": 0,
        "RCC_FAIL": 0,
    }
    per_file = []
    findings_all = []
    missing_dir = files is None
    if files:
        facts["RCC_FILES"] = len(files)
    for path in files or []:
        blocks = run_blocks(path)
        facts["RCC_RUN_BLOCKS"] += len(blocks)
        rel = os.path.relpath(path, root).replace("\\", "/")
        file_findings = []
        for header, body, indent in blocks:
            f, g, t, spe = scan_body(body, indent)
            facts["RCC_CAPTURES"] += t
            facts["RCC_GUARDED"] += g
            facts["RCC_UNGUARDED"] += len(f)
            if spe:
                facts["RCC_BLOCKS_SET_PLUS_E"] += 1
            for ln0, frag in f:
                item = f"{rel}:{ln0 + 1} [{step_name_for(path, header)}] {frag}"
                file_findings.append(item)
                findings_all.append(item)
        if file_findings:
            per_file.append((rel, len(file_findings)))
        facts["RCC_LINES_UNGUARDED"] += recount_lines(path)
    facts["_FINDINGS"] = findings_all
    facts["_PER_FILE"] = per_file
    facts["_MISSING_DIR"] = 1 if missing_dir else 0
    # Независимый построчный пересчёт обязан сойтись с block-уровнем: расхождение значит, что
    # извлечение блоков съело строку или придумала её.
    facts["RCC_RECOUNT_EQ"] = int(
        facts["RCC_LINES_UNGUARDED"] == facts["RCC_UNGUARDED"] and not missing_dir
    )
    # Слепота: ноль файлов, ноль блоков или ноль захватов — прибор ничего не увидел, и его
    # зелёный выход ничего не значит.
    facts["RCC_BLIND"] = int(
        missing_dir
        or facts["RCC_FILES"] == 0
        or facts["RCC_RUN_BLOCKS"] == 0
        or facts["RCC_CAPTURES"] == 0
    )
    facts["RCC_FAIL"] = int(
        facts["RCC_BLIND"] == 1
        or facts["RCC_UNGUARDED"] > 0
        or facts["RCC_RECOUNT_EQ"] != 1
    )
    return facts


def print_facts(facts, limit=20):
    order = [
        "RCC_FILES",
        "RCC_RUN_BLOCKS",
        "RCC_BLOCKS_SET_PLUS_E",
        "RCC_CAPTURES",
        "RCC_GUARDED",
        "RCC_UNGUARDED",
        "RCC_LINES_UNGUARDED",
        "RCC_RECOUNT_EQ",
        "RCC_BLIND",
        "RCC_FAIL",
    ]
    for k in order:
        print(f"{k}={facts[k]}")
    if facts["_PER_FILE"]:
        for rel, n in facts["_PER_FILE"]:
            print(f"RCC_UNGUARDED_FILE={rel} count={n}")
    else:
        print("RCC_UNGUARDED_FILE=none")
    for i, text in enumerate(facts["_FINDINGS"][:limit]):
        print(f"RCC_UNGUARDED_AT={text}")
    if len(facts["_FINDINGS"]) > limit:
        print(f"RCC_UNGUARDED_MORE={len(facts['_FINDINGS']) - limit}")
    elif facts["_FINDINGS"]:
        print("RCC_UNGUARDED_MORE=0")
    else:
        print("RCC_UNGUARDED_MORE=none")
    print(f"RCC_EXIT={1 if facts['RCC_FAIL'] else 0}")


# ------------------------------------------------------------------------ extractstep
def extractstep(root, needle, out):
    """Выписать тело шага, чьё имя содержит `needle`, в `out` (для запуска под `bash -e`).

    Проверка обязательна: ноль совпадений означал бы, что helper прогоняет пустой файл и
    получает зелёный ноль из ничего.
    """
    files = wf_files(root) or []
    hits = []
    for path in files:
        for header, body, indent in run_blocks(path):
            name = step_name_for(path, header)
            if needle.lower() in name.lower():
                hits.append((path, header, body, indent, name))
    rel = ""
    if len(hits) == 1:
        rel = os.path.relpath(hits[0][0], root).replace("\\", "/")
        _, _, body, indent, _ = hits[0]
        text = "\n".join((l[indent:] if len(l) >= indent else l.strip()) for _, l in body)
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text + "\n")
    print(f"RCS_NEEDLE={needle}")
    print(f"RCS_MATCHES={len(hits)}")
    print(f"RCS_FILE={rel if rel else 'MISSING'}")
    print(f"RCS_STEP={hits[0][4] if len(hits) == 1 else 'MISSING'}")
    print(f"RCS_BLOCK_LINES={len(hits[0][2]) if len(hits) == 1 else 'MISSING'}")
    print(f"RCS_OUT={out}")
    rc = 0 if len(hits) == 1 else 1
    print(f"RCS_EXIT={rc}")
    return rc


# ------------------------------------------------------------------------------- plant
def _split_capture(text):
    """(команда, переменная, форма) для строки-захвата; форма: unguarded|guarded|bare."""
    m = UNGUARDED.search(text)
    if m:
        return text[:m.start()].rstrip(), m.group(1), "unguarded"
    m = GUARDED.search(text)
    if m:
        return text[:m.start()].rstrip(), m.group(1), "guarded"
    m = BARE_ASSIGN.match(text)
    if m:
        return None, m.group(1), "bare"
    return None, None, None


def plant(root, file, kind):
    """Посадка одной дефектной/исправной формы в КОПИЮ дерева (живое не трогается).

    Форма выбирается по текущему состоянию строки, поэтому посадка работает и на дереве до
    починки, и после неё: CI гоняет самопроверку на починном дереве, где буквального
    «снятия guard'а» уже нет, и проверка, построенная на букве, тихо превратилась бы в
    посадку-пустышку. Выход 0 означает «байт изменён»; несостоявшаяся посадка красна, потому
    что молчаливая посадка неотличима от «страж не поймал».
    """
    print(f"RCP_FILE={file}")
    print(f"RCP_KIND={kind}")
    path = os.path.join(root, WF_DIR, file)
    if not os.path.isfile(path):
        print("RCP_LANDED=0")
        print("RCP_REASON=файла копии нет")
        print("RCP_EXIT=1")
        return 1
    lines = read_lines(path)
    landed = 0
    direction = "none"
    at = 0
    for i, raw in enumerate(lines):
        text = raw.strip()
        if text == "" or COMMENT.match(text):
            continue
        indent = raw[:len(raw) - len(text)]
        if kind == "flip":
            cmd, var, form = _split_capture(text)
            if form == "unguarded":
                lines[i] = f"{indent}{cmd} || {var}=$?"
                direction, landed, at = "to_guarded", 1, i + 1
                break
            if form == "guarded":
                lines[i] = f"{indent}{cmd}; {var}=$?"
                direction, landed, at = "to_unguarded", 1, i + 1
                break
        elif kind == "bare":
            cmd, var, form = _split_capture(text)
            if form in ("unguarded", "guarded"):
                lines[i] = f"{indent}{cmd}"
                lines.insert(i + 1, f"{indent}{var}=$?")
                direction, landed, at = "to_bare_assign", 1, i + 1
                break
        elif kind == "sete":
            if text == "set -uo pipefail":
                lines[i] = f"{indent}set +e"
                direction, landed, at = "to_set_plus_e", 1, i + 1
                break
    if landed:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines))
    print(f"RCP_LANDED={landed}")
    print(f"RCP_DIRECTION={direction}")
    print(f"RCP_LINE={at if landed else 'none'}")
    print(f"RCP_EXIT={0 if landed else 1}")
    return 0 if landed else 1


# ----------------------------------------------------------------------------- selftest
def dumpblocks(root, outdir):
    """Выписать каждый блок `run:` отдельным файлом — для `bash -n` из shell.

    Один парсер на два прибора (поиск находок и синтаксический свип) принципиален: если
    свип берёт блоки своим regex'ом, «все блоки синтаксичны» может означать «половину блоков
    не извлекли». Число файлов печатается наружу и сверяется с `RCC_RUN_BLOCKS`.
    """
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for path in wf_files(root) or []:
        rel = os.path.relpath(path, root).replace("\\", "/").replace("/", "_")
        for header, body, indent in run_blocks(path):
            text = "\n".join(
                (l[indent:] if len(l) >= indent else l.strip()) for _, l in body
            )
            with open(os.path.join(outdir, f"b{n:03d}_{rel}.sh"), "w",
                      encoding="utf-8", newline="\n") as fh:
                fh.write(text + "\n")
            n += 1
    print(f"RCD_OUTDIR={outdir}")
    print(f"RCD_BLOCKS={n}")
    print(f"RCD_EXIT={0 if n else 1}")
    return 0 if n else 1


def _wf(root, name, text):
    d = os.path.join(root, WF_DIR)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


STEP_A = """\
name: t
on: push
jobs:
  j:
    steps:
      - name: шаг с захватом без guard'а
        run: |
          set -uo pipefail
          L=/tmp/a.log
          python lab/x.py > "$L" 2>&1; r=$?
          echo "X_EXIT=$r"
          exit $r
"""

STEP_B = """\
name: t
on: push
jobs:
  j:
    steps:
      - name: шаг с guard'ом
        run: |
          set -uo pipefail
          L=/tmp/b.log
          r=0
          python lab/x.py > "$L" 2>&1 || r=$?
          echo "X_EXIT=$r"
          exit $r
"""

STEP_C = """\
name: t
on: push
jobs:
  j:
    steps:
      - name: шаг с set +e
        run: |
          set +e
          L=/tmp/c.log
          python lab/x.py > "$L" 2>&1; r=$?
          echo "X_EXIT=$r"
          exit 0
"""

STEP_D = """\
name: t
on: push
jobs:
  j:
    steps:
      - name: шаг с комментарием и отдельной строкой
        run: |
          set -uo pipefail
          python lab/x.py > /tmp/d.log 2>&1
          # python lab/y.py > /tmp/y.log 2>&1; r=$?
          r=$?
          exit $r
"""

STEP_E = """\
name: t
on: push
jobs:
  j:
    steps:
      - name: четвёртый файл тоже виден
        run: |
          set -uo pipefail
          python lab/z.py > /tmp/z.log 2>&1; rc=$?
          exit $rc
"""

# Форма, повторяющая живой шаг «зеркало спеки»: законный ненулевой код возврата прибора
# должен вести ветку `MIRROR_ABSENT_ON_RUNNER`, а не обрывать шаг.
STEP_MIRROR = """\
name: t
on: push
jobs:
  j:
    steps:
      - name: "НЕ ИСПОЛНЯЕТСЯ ЗДЕСЬ: зеркало спеки (живёт вне git, на runner его нет)"
        run: |
          set -uo pipefail
          L=/tmp/spec-mirror.log
          bash lab/check-spec-mirror.sh > "$L" 2>&1; r=$?
          cat "$L"
          if [ "$r" -eq 0 ]; then echo "::notice::MIRROR_OK=1"; exit 0; fi
          if grep -qF 'нет на месте' "$L"; then
            echo "::notice::MIRROR_ABSENT_ON_RUNNER=1"
            exit 0
          fi
          echo "::error::MIRROR_RC=$r"
          exit $r
"""


def _copy_wf(src_root, dst_root):
    d = os.path.join(src_root, WF_DIR)
    os.makedirs(os.path.join(dst_root, WF_DIR), exist_ok=True)
    for n in sorted(os.listdir(d)):
        if n.endswith((".yml", ".yaml")):
            with open(os.path.join(d, n), encoding="utf-8") as fh:
                text = fh.read()
            with open(os.path.join(dst_root, WF_DIR, n), "w",
                      encoding="utf-8", newline="\n") as fh:
                fh.write(text)


def selftest(base_root):
    checks = []
    with tempfile.TemporaryDirectory(prefix="rcc-selftest-") as tmp:
        # (a) находка без guard'а обязана быть названа адресом и файлом.
        root = os.path.join(tmp, "a")
        _wf(root, "a.yml", STEP_A)
        f = scan(root)
        checks.append((
            "a_unguarded_found",
            f["RCC_UNGUARDED"] == 1 and f["RCC_FAIL"] == 1
            and "a.yml" in f["_FINDINGS"][0] and "шаг с захватом" in f["_FINDINGS"][0],
            f"UNGUARDED={f['RCC_UNGUARDED']} FAIL={f['RCC_FAIL']} AT={f['_FINDINGS'][:1]}",
        ))
        # (b) та же строка с guard'ом — чисто, и прибор не слеп (захват он видел).
        root = os.path.join(tmp, "b")
        _wf(root, "b.yml", STEP_B)
        f = scan(root)
        checks.append((
            "b_guarded_clean",
            f["RCC_UNGUARDED"] == 0 and f["RCC_GUARDED"] == 1 and f["RCC_CAPTURES"] == 1
            and f["RCC_BLIND"] == 0 and f["RCC_FAIL"] == 0,
            f"GUARDED={f['RCC_GUARDED']} BLIND={f['RCC_BLIND']}",
        ))
        # (c) `set +e` в блоке: exemption посчитана, а не промолчана.
        root = os.path.join(tmp, "c")
        _wf(root, "c.yml", STEP_C)
        f = scan(root)
        checks.append((
            "c_set_plus_e_exempt",
            f["RCC_UNGUARDED"] == 0 and f["RCC_BLOCKS_SET_PLUS_E"] == 1
            and f["RCC_CAPTURES"] == 1,
            f"BLOCKS_SPE={f['RCC_BLOCKS_SET_PLUS_E']}",
        ))
        # (d) закомментированный grep-подобный текст не находится; присваивание $? отдельной
        #     строкой после команды — находится.
        root = os.path.join(tmp, "d")
        _wf(root, "d.yml", STEP_D)
        f = scan(root)
        checks.append((
            "d_comment_and_bare",
            f["RCC_UNGUARDED"] == 1 and "отдельной строкой" in f["_FINDINGS"][0]
            and "#" not in f["_FINDINGS"][0],
            f"UNGUARDED={f['RCC_UNGUARDED']} AT={f['_FINDINGS']}",
        ))
        # (e) пустой каталог workflow'ов — слепота красна.
        root = os.path.join(tmp, "e")
        os.makedirs(os.path.join(root, WF_DIR), exist_ok=True)
        f = scan(root)
        checks.append((
            "e_blind_dir_red",
            f["RCC_BLIND"] == 1 and f["RCC_FAIL"] == 1,
            f"BLIND={f['RCC_BLIND']} FAIL={f['RCC_FAIL']}",
        ))
        # (f) каталога workflow'ов нет вовсе — та же краснота, а не ноль.
        root = os.path.join(tmp, "f")
        os.makedirs(root, exist_ok=True)
        f = scan(root)
        checks.append((
            "f_no_dir_red",
            f["RCC_BLIND"] == 1 and f["RCC_FAIL"] == 1 and f["RCC_RECOUNT_EQ"] == 0,
            f"RECOUNT={f['RCC_RECOUNT_EQ']}",
        ))
        # (g) четвёртый файл с находкой обязан быть назван: перебор файлов, а не одного.
        root = os.path.join(tmp, "g")
        _wf(root, "a1.yml", STEP_A)
        _wf(root, "a2.yml", STEP_B)
        _wf(root, "a3.yml", STEP_E)
        f = scan(root)
        checks.append((
            "g_third_file_seen",
            f["RCC_FILES"] == 3 and f["RCC_UNGUARDED"] == 2
            and any("a3.yml" in x for x in f["_FINDINGS"])
            and f["RCC_RECOUNT_EQ"] == 1,
            f"FILES={f['RCC_FILES']} UNGUARDED={f['RCC_UNGUARDED']}",
        ))
        # (h) extractstep обязан краснеть на нуле совпадений и на двух.
        root = os.path.join(tmp, "h")
        _wf(root, "h1.yml", STEP_A)
        _wf(root, "h2.yml", STEP_A.replace("a.log", "a2.log"))
        _wf(root, "h3.yml", STEP_B)
        out = os.path.join(tmp, "step.txt")

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc_none = extractstep(root, "нет-такого-шага", out)
            rc_two = extractstep(root, "шаг с захватом", out)
            rc_one = extractstep(root, "шаг с guard'ом", out)
        checks.append((
            "h_extractstep_strict",
            rc_none == 1 and rc_two == 1 and rc_one == 0,
            f"rc_none={rc_none} rc_two={rc_two} rc_one={rc_one}",
        ))
        # (i) extractstep обязан отдать тело, пригодное для запуска: строка захвата в файле.
        root = os.path.join(tmp, "i")
        _wf(root, "s1.yml", STEP_MIRROR)
        out2 = os.path.join(tmp, "step-i.txt")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc_ext = extractstep(root, "зеркало спеки", out2)
        body_text = ""
        if rc_ext == 0:
            with open(out2, encoding="utf-8") as fh:
                body_text = fh.read()
        checks.append((
            "i_extractstep_body_usable",
            rc_ext == 0 and 'check-spec-mirror.sh > "$L" 2>&1; r=$?' in body_text
            and "MIRROR_ABSENT_ON_RUNNER" in body_text,
            f"rc={rc_ext} lines={len(body_text.splitlines())}",
        ))
        # (j) посадка в копию ЖИВОГО дерева и обратный ход. Форма выбирается по текущему
        #     состоянию строки, поэтому тест годен и до починки, и после неё: CI гоняет
        #     самопроверку на починном дереве, где буквального «снятия guard'а» уже нет, и
        #     проверка, построенная на букве, тихо превратилась бы в посадку-пустышку.
        #     Проверяются три вещи: байт изменён; находок сдвинулось ровно на один в нужную
        #     сторону; после возврата текста прибор снова даёт исходное число (иначе «находка»
        #     — артефакт перезаписи файла, а не формы строки).
        live = os.path.join(base_root, WF_DIR)
        src = None
        original = ""
        if os.path.isdir(live):
            root = os.path.join(tmp, "j")
            _copy_wf(base_root, root)
            src = os.path.join(root, WF_DIR, "verify.yml")
            with open(src, encoding="utf-8") as fh:
                original = fh.read()
            before = scan(root)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_flip = plant(root, "verify.yml", "flip")
            ptxt = buf.getvalue()
            after = scan(root)
            to_guarded = "RCP_DIRECTION=to_guarded" in ptxt
            with open(src, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(original)
            restored = scan(root)
            delta_ok = (
                after["RCC_UNGUARDED"] == before["RCC_UNGUARDED"] - 1
                if to_guarded
                else after["RCC_UNGUARDED"] == before["RCC_UNGUARDED"] + 1
            )
            checks.append((
                "j_live_tree_flip_and_restore",
                os.path.isdir(live) and rc_flip == 0
                and before["RCC_FILES"] == after["RCC_FILES"] == restored["RCC_FILES"] > 0
                and before["RCC_CAPTURES"] == after["RCC_CAPTURES"]
                and delta_ok and after["RCC_RECOUNT_EQ"] == 1
                and restored["RCC_UNGUARDED"] == before["RCC_UNGUARDED"]
                and restored["RCC_GUARDED"] == before["RCC_GUARDED"],
                f"before={before['RCC_UNGUARDED']} after={after['RCC_UNGUARDED']} "
                f"restored={restored['RCC_UNGUARDED']} dir={'to_guarded' if to_guarded else 'to_unguarded'}",
            ))
            # (k) та же копия, форма «присваивание $? отдельной строкой»: находка обязана
            #     появиться, быть названной этой формулировкой, и независимый пересчёт обязан
            #     её увидеть (иначе EQ краснел бы на легальном дереве с такой формой). Дельту
            #     числа находок здесь не требуют: на дереве до починки эта же посадка заменяет
            #     одну находку другой формой (было 24, стало 24), то есть требование «+1»
            #     проверяло бы форму дерева, а не прибор.
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_bare = plant(root, "verify.yml", "bare")
            bare = scan(root)
            checks.append((
                "k_bare_assign_plant",
                rc_bare == 0 and "RCP_LANDED=1" in buf.getvalue()
                and bare["RCC_UNGUARDED"] >= 1 and bare["RCC_FAIL"] == 1
                and any("отдельной строкой" in x for x in bare["_FINDINGS"])
                and bare["RCC_CAPTURES"] == before["RCC_CAPTURES"]
                and bare["RCC_RECOUNT_EQ"] == 1,
                f"UNGUARDED={bare['RCC_UNGUARDED']} EQ={bare['RCC_RECOUNT_EQ']} "
                f"AT={[x for x in bare['_FINDINGS'] if 'отдельной' in x][:1]}",
            ))
            # (l) exemption посчитан на живом дереве, а не промолчан: `set +e` в первом блоке
            #     обязан увеличить RCC_BLOCKS_SET_PLUS_E ровно на один и не добавить находок.
            with open(src, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(original)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_sete = plant(root, "verify.yml", "sete")
            sete = scan(root)
            checks.append((
                "l_sete_exemption_counted",
                rc_sete == 0 and "RCP_LANDED=1" in buf.getvalue()
                and sete["RCC_BLOCKS_SET_PLUS_E"] == before["RCC_BLOCKS_SET_PLUS_E"] + 1
                and sete["RCC_UNGUARDED"] <= before["RCC_UNGUARDED"]
                and sete["RCC_RECOUNT_EQ"] == 1,
                f"BLOCKS_SPE={before['RCC_BLOCKS_SET_PLUS_E']}->{sete['RCC_BLOCKS_SET_PLUS_E']} "
                f"UNGUARDED={sete['RCC_UNGUARDED']}",
            ))
        else:
            for name in ("j_live_tree_flip_and_restore", "k_bare_assign_plant",
                         "l_sete_exemption_counted"):
                checks.append((name, False, "workflow-каталога нет: посадка не состоялась"))
    failed = [name for name, ok, _ in checks if not ok]
    for name, ok, detail in checks:
        print(f"RCC_SELFTEST {name}={'ok' if ok else 'FAIL'} {detail}")
    print(f"RCC_SELFTEST total={len(checks)} passed={len(checks) - len(failed)}")
    print(f"RCC_SELFTEST_FIRED={len(failed)}")
    print(f"RCC_SELFTEST_RC={1 if failed else 0}")
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", nargs="?", default="check",
                    choices=["check", "selftest", "extractstep", "dumpblocks", "plant"])
    ap.add_argument("--dir", default=None, help="копия дерева (посадки, PRE_FIX)")
    ap.add_argument("--name", default=None, help="подстрока имени шага для extractstep")
    ap.add_argument("--file", default=None, help="имя workflow-файла для plant")
    ap.add_argument("--kind", default="flip", choices=["flip", "bare", "sete"],
                    help="форма посадки для plant")
    ap.add_argument("--out", default=None,
                    help="файл (extractstep) или каталог (dumpblocks) для записи")
    ap.add_argument("--limit", type=int, default=20)
    a = ap.parse_args()
    root = a.dir or os.getcwd()
    if a.mode == "selftest":
        return selftest(root)
    if a.mode == "plant":
        if not a.file:
            print("RCP_USAGE=нужен --file")
            print("RCP_EXIT=2")
            return 2
        return plant(root, a.file, a.kind)
    if a.mode == "dumpblocks":
        if not a.out:
            print("RCD_USAGE=нужен --out КАТАЛОГ")
            print("RCD_EXIT=2")
            return 2
        return dumpblocks(root, a.out)
    if a.mode == "extractstep":
        if not a.name or not a.out:
            print("RCS_USAGE=нужны --name и --out")
            print("RCS_EXIT=2")
            return 2
        return extractstep(root, a.name, a.out)
    facts = scan(root)
    print_facts(facts, a.limit)
    return 1 if facts["RCC_FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
