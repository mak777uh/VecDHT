#!/usr/bin/env python3
"""Страж отчётных труб в workflow-файлах (`E-0127`).

Почему он появился. GitHub исполняет содержимое `run:` как `bash -e`, то есть shell-опция
errexit включена ДО скрипта; наши шаги дополнительно ставят `set -uo pipefail`. Под этой парой
отчётный `grep`, который ничего не нашёл, возвращает единицу, труба под `pipefail` отдаёт её
наружу, а `-e` обрывает шаг в этой строке — ДО `exit $r`, которое и должно быть вердиктом.
Следствие измерено, а не предположено: в прогоне 40374535414 (коммит `8f0f676`) шаг
`cargo test --workspace` имеет статус `failure` при коде 1, хотя тот же шаг напечатал
`::notice::TEST_EXIT=0`; там же, где тесты падают по-настоящему (`72c5764`), шаг доходит до
`exit $r` и печатает 101. Минимальное воспроизводство (четыре формы, замерены в `E-0127`):

    printf 'test result: ok\\n' > /tmp/empty.log
    bash -e -c 'set -uo pipefail; grep -aE "^РАЗРЫВ " /tmp/empty.log | head -1; echo ДОШЛИ'
    # код 1, «ДОШЛИ» не напечатано

Что проверяется:

* отчётная позиция = statement с `grep` после которого в том же блоке `run:` есть ещё команды;
  последний statement шага — вердикт (`grep -F 'cargo build …' README.md …` в `release.yml`),
  он считается отдельно в `CRG_VERDICT_GREP` и `|| true` НЕ требует: его единица и есть провал;
* комментарий (`# …`), условие `if/elif/while/until` и `$(grep …)` внутри аргумента `echo` под
  `-e` шаг не обрывают — они не считаются (посадка (в) это доказывает);
* СПРЯТАННЫЙ, НО НЕВЕРНЫЙ Guard: `grep … || true | while …` разбирается как
  `grep … || (true | while …)`, то есть шаг зелёный, а рассылка `::notice::` пропадает даже тогда,
  когда grep нашёл строку (замерено: NOTICES=0 при совпадении). Такой guard считается дефектом и
  печатается в `CRG_MISPLACED`. Годная форма — `|| true` в КОНЦЕ трубы (для трубы с `{ …; }`
  допустим guard и внутри фигурных скобок, если после него там же стоит `;`).

Независимый пересчёт другим кодом и по другим правилам (`CRG_LINES_NOGUARD`): разбор по
физическим строкам, склеенным по backslash, без поиска блоков `run:` и без правила «последний
statement — вердикт». Поэтому он обязан равняться сумме `CRG_UNGUARDED + CRG_VERDICT_GREP`
(`CRG_RECOUNT_EQ=1`) и на до-починном, и на починном дереве: расхождение ловит как ослепление
прибора, так и перенос, который один из двух кодов не склеил.

Известная граница (записана в карточку цикла, а не в порог): гранулярность у прибора по statement'у.
Если в одном statement'е два `grep` и у одного есть guard, второй спрячется. Посадки на это нет,
потому что такой формы в дереве нет и фикс её не создаёт.

Деградирует в нули и краснеет: нет каталога `.github/workflows`, нет ни одного файла, файл не
читается, блок `run:` не найден ни в одном файле — всё это `CRG_BLIND=1` плюс `CRG_FAIL=1`,
потому что «ноль находок» от ослепшего прибора неотличим от «ноль находок» у здорового
(прецедент ДИАГНОЗ-1 и ДИАГНОЗ-2 из `E-0126`).

Употребление:
    python lab/check-ci-report-greps.py                  # проверка рабочего дерева
    python lab/check-ci-report-greps.py check --dir ROOT # копия дерева (посадки, PRE_FIX)
    python lab/check-ci-report-greps.py selftest         # пять посаженных дефектов на копиях
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile

WF_DIR = os.path.join(".github", "workflows")
GREP_TOKEN = re.compile(r"(?<![A-Za-z0-9_./-])grep(?=\s|-)")
GUARD = re.compile(r"\|\|\s*(true|:)")
COND = re.compile(r"^\s*(if|elif|while|until)\b")
RUN_BLOCK = re.compile(r"^\s*(?:-\s+)?run:\s*[|>]")
# Форма `- run: |` (шаг без имени) в дереве сейчас не встречается, но regex её обязан видеть:
# иначе следующий же такой шаг стал бы для прибора невидим, и его трубы не проверялись бы вовсе.
SUBST = re.compile(r"\$\(")


def wf_files(root):
    d = os.path.join(root, WF_DIR)
    if not os.path.isdir(d):
        return None
    return sorted(
        os.path.join(d, n)
        for n in os.listdir(d)
        if n.endswith((".yml", ".yaml")) and os.path.isfile(os.path.join(d, n))
    )


def misplaced_guard(text):
    """True, если `|| true` стоит НЕ в конце трубы, а до следующего `|` нет `;`."""
    for m in GUARD.finditer(text):
        tail = text[m.end():]
        p = tail.find("|")
        if p != -1 and ";" not in tail[:p]:
            return True
    return False


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read().replace("\r\n", "\n").split("\n")


def run_blocks(path):
    """Список блоков `(start_line0, [(line0, текст)])` для каждого `run: |` в файле."""
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
            blocks.append((i, body))
            i = j if j > i else i + 1
        else:
            i += 1
    return blocks


def statements(body, base_indent):
    r"""Логические statement'ы блока: `(первая строка, последняя строка, склейка)`."""
    out = []
    buf = []
    first = None
    last = None
    for ln0, line in body:
        text = line[base_indent:] if len(line) >= base_indent else line.strip()
        if text.strip() == "":
            if buf:
                out.append((first, last, " ".join(buf)))
                buf, first, last = [], None, None
            continue
        if first is None:
            first = ln0
        last = ln0
        if text.rstrip().endswith("\\"):
            buf.append(text.rstrip()[:-1].strip())
        else:
            buf.append(text.strip())
            out.append((first, last, " ".join(buf)))
            buf, first, last = [], None, None
    if buf:
        out.append((first, last, " ".join(buf)))
    return out


def is_grep_stmt(s):
    return bool(s) and not s.startswith("#") and bool(GREP_TOKEN.search(s))


def classify(path):
    """Находит отчётные grep'ы без годного `|| true` в одном файле.

    Возвращает (unguarded, misplaced, grep_statements, verdict_grep, subst_grep, run_blocks).
    """
    unguarded = []
    misplaced = []
    grep_stmts = 0
    verdict = 0
    subst = 0
    nblocks = 0
    for start0, body in run_blocks(path):
        nonblank = [ln for ln in body if ln[1].strip() != ""]
        if not nonblank:
            continue
        nblocks += 1
        base = min(len(ln) - len(ln.lstrip()) for _, ln in nonblank)
        stmts = statements(body, base)
        for idx, (ln0, ln_last, stmt) in enumerate(stmts):
            s = stmt.strip()
            if not is_grep_stmt(s):
                continue
            grep_stmts += 1
            if COND.match(s):
                continue
            if GUARD.search(s):
                if misplaced_guard(s):
                    misplaced.append((path, ln_last + 1, s[:90]))
                continue
            last = idx == len(stmts) - 1
            if SUBST.search(s) and not s.startswith("grep"):
                subst += 1
                continue
            if last:
                verdict += 1
                continue
            unguarded.append((path, ln0 + 1, s[:90]))
    return unguarded, misplaced, grep_stmts, verdict, subst, nblocks


def line_recount(root):
    """Независимый пересчёт: склеенные по backslash физические строки, без разбора `run:`.

    Правило грубее приборного: считается каждая строка с `grep`, в которой нет `|| true` вовсе,
    без знания о том, где блок кончается и какой statement в нём последний. Поэтому её смысл —
    равенство с суммой `CRG_UNGUARDED + CRG_VERDICT_GREP`, а не ноль. Возвращает -1, если хоть
    один файл не читается: молчание о непрочитанном файле не считается нулём.
    """
    files = wf_files(root) or []
    total = 0
    for f in files:
        try:
            lines = read_lines(f)
        except Exception:
            return -1
        buf = []
        for line in lines:
            s = line.strip()
            if s == "":
                if buf:
                    total += 1 if counts_for_recount(" ".join(buf)) else 0
                    buf = []
                continue
            if s.endswith("\\"):
                buf.append(s[:-1].strip())
            else:
                buf.append(s)
                total += 1 if counts_for_recount(" ".join(buf)) else 0
                buf = []
        if buf:
            total += 1 if counts_for_recount(" ".join(buf)) else 0
    return total


def counts_for_recount(joined):
    s = joined.strip()
    if not is_grep_stmt(s) or COND.match(s) or GUARD.search(s):
        return False
    head = s.split("grep", 1)[0]
    if "$(" in head:
        return False
    return True


def scan(root):
    facts = []
    files = wf_files(root)
    if files is None:
        for k in ("CRG_DIR_ABSENT", "CRG_FILES", "CRG_RUN_BLOCKS", "CRG_GREP_STATEMENTS",
                  "CRG_UNGUARDED", "CRG_MISPLACED", "CRG_VERDICT_GREP", "CRG_SUBST_GREP",
                  "CRG_LINES_NOGUARD", "CRG_RECOUNT_EQ", "CRG_UNREADABLE", "CRG_BLIND",
                  "CRG_FAIL"):
            facts.append("%s=0" % k)
        facts[0] = "CRG_DIR_ABSENT=1"
        facts[-2] = "CRG_BLIND=1"
        facts[-1] = "CRG_FAIL=1"
        facts.append("CRG_UNGUARDED_AT=none")
        return 1, facts
    facts.append("CRG_DIR_ABSENT=0")
    facts.append("CRG_FILES=%d" % len(files))
    unguarded = []
    misplaced = []
    grep_stmts = 0
    verdict = 0
    subst = 0
    blocks = 0
    unreadable = 0
    for f in files:
        try:
            u, m, g, v, s, b = classify(f)
        except Exception:
            unreadable += 1
            continue
        unguarded += u
        misplaced += m
        grep_stmts += g
        verdict += v
        subst += s
        blocks += b
    lines_n = line_recount(root)
    facts.append("CRG_RUN_BLOCKS=%d" % blocks)
    facts.append("CRG_GREP_STATEMENTS=%d" % grep_stmts)
    facts.append("CRG_UNGUARDED=%d" % len(unguarded))
    facts.append("CRG_MISPLACED=%d" % len(misplaced))
    facts.append("CRG_VERDICT_GREP=%d" % verdict)
    facts.append("CRG_SUBST_GREP=%d" % subst)
    facts.append("CRG_LINES_NOGUARD=%d" % lines_n)
    agree = 1 if lines_n == len(unguarded) + verdict else 0
    facts.append("CRG_RECOUNT_EQ=%d" % agree)
    facts.append("CRG_UNREADABLE=%d" % unreadable)
    if unguarded:
        for path, ln, snip in unguarded[:40]:
            rel = os.path.relpath(path, root).replace("\\", "/")
            facts.append("CRG_UNGUARDED_AT=%s:%d:%s" % (rel, ln, snip))
        if len(unguarded) > 40:
            facts.append("CRG_UNGUARDED_TRUNCATED=1")
    else:
        facts.append("CRG_UNGUARDED_AT=none")
    if misplaced:
        for path, ln, snip in misplaced[:20]:
            rel = os.path.relpath(path, root).replace("\\", "/")
            facts.append("CRG_MISPLACED_AT=%s:%d:%s" % (rel, ln, snip))
    else:
        facts.append("CRG_MISPLACED_AT=none")
    blind = 1 if (blocks == 0 or grep_stmts == 0 or unreadable or lines_n < 0) else 0
    facts.append("CRG_BLIND=%d" % blind)
    fail = 1 if (len(unguarded) or len(misplaced) or blind or not agree) else 0
    facts.append("CRG_FAIL=%d" % fail)
    return fail, facts


def print_facts(facts):
    for line in facts:
        print(line)


# ----------------------------------------------------------------------------- selftest

def _copy_wf(src_root, dst_root):
    d = os.path.join(dst_root, WF_DIR)
    os.makedirs(d, exist_ok=True)
    for f in wf_files(src_root) or []:
        shutil.copy(f, os.path.join(d, os.path.basename(f)))


def _write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


# Три годные формы guard'а из фикса + одна неверная. Файл синтетический, чтобы посадка работала
# и на починном дереве (иначе «снять guard с живой строки» стало бы невыполнимым by construction,
# как порог (9) в `E-0088`).
FORMS = """jobs:
  x:
    steps:
      - name: форма А — концевой || true
        run: |
          set -uo pipefail
          grep -aE '^CRG_A=' "$L" | tail -3 || true
          exit $r
      - name: форма Б — концевой || true у трубы с while
        run: |
          set -uo pipefail
          { echo "CRG_B=$r"; grep -aE '^CRG_B=' "$L"; } \\
            | while IFS= read -r n; do echo "::notice::${n:0:180}"; done || true
          exit $r
      - name: форма В — guard внутри фигурных скобок перед ;
        run: |
          set -uo pipefail
          { grep -aE '^CRG_C=' "$L" || true; } | tail -2 | while IFS= read -r n; do echo "$n"; done
          exit $r
      - name: форма Г — guard ДО трубы (ложная-green: notices теряются)
        run: |
          set -uo pipefail
          grep -aE '^CRG_D=' "$L" || true | while IFS= read -r n; do echo "::notice::$n"; done
          exit $r
"""

FORMS_BARE = """jobs:
  x:
    steps:
      - name: форма А без guard
        run: |
          set -uo pipefail
          grep -aE '^CRG_A=' "$L" | tail -3
          exit $r
      - name: форма Б без guard
        run: |
          set -uo pipefail
          { echo "CRG_B=$r"; grep -aE '^CRG_B=' "$L"; } \\
            | while IFS= read -r n; do echo "::notice::${n:0:180}"; done
          exit $r
      - name: форма В без guard
        run: |
          set -uo pipefail
          { grep -aE '^CRG_C=' "$L"; } | tail -2 | while IFS= read -r n; do echo "$n"; done
          exit $r
      - name: форма Г без guard (уже посчитана как misplaced)
        run: |
          set -uo pipefail
          grep -aE '^CRG_D=' "$L" | while IFS= read -r n; do echo "::notice::$n"; done
          exit $r
"""


def _scan_text(text, tmp):
    d = os.path.join(tmp, WF_DIR)
    os.makedirs(d, exist_ok=True)
    _write(os.path.join(d, "synthetic-forms.yml"), text)
    return scan(tmp)


def selftest(base_root):
    """Пять посадок; живое дерево не трогается."""
    src = wf_files(base_root)
    if not src:
        print("CRG_SELFTEST total=5 fired=0 reason=нет-исходника")
        return 1
    probe = os.path.join(base_root, WF_DIR, "verify.yml")
    if not os.path.isfile(probe):
        probe = src[0]
    results = []
    _rc_base, base_facts = scan(base_root)
    base_unguarded = _val(base_facts, "CRG_UNGUARDED")
    base_lines = _val(base_facts, "CRG_LINES_NOGUARD")

    # (а) три годные формы guard'а не дают находок, а misplaced-форма даёт ровно одну;
    #     если те же формы обезвредить, прибор обязан увидеть три.
    tmp = tempfile.mkdtemp(prefix="crg-a-")
    try:
        rc_g, f_g = _scan_text(FORMS, tmp)
        rc_b, f_b = _scan_text(FORMS_BARE, tmp)
        good_clean = (_val(f_g, "CRG_UNGUARDED") == 0 and _val(f_g, "CRG_GREP_STATEMENTS") == 4
                      and _val(f_g, "CRG_MISPLACED") == 1 and _val(f_g, "CRG_FAIL") == 1
                      and _val(f_g, "CRG_RECOUNT_EQ") == 1)
        bare_caught = (_val(f_b, "CRG_UNGUARDED") == 4
                       and _val(f_b, "CRG_MISPLACED") == 0
                       and _val(f_b, "CRG_FAIL") == 1)
        fired = 1 if (good_clean and bare_caught) else 0
        print("CRG_SELFTEST_A guarded_clean=%d bare_caught=%d" % (int(good_clean), int(bare_caught)))
        results.append(("a_guard_forms", 1, fired, rc_g))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # (б) вписать новую отчётную трубу в середину блока -> находка обязана появиться.
    tmp = tempfile.mkdtemp(prefix="crg-b-")
    try:
        _copy_wf(base_root, tmp)
        target = os.path.join(tmp, WF_DIR, os.path.basename(probe))
        with open(target, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().replace("\r\n", "\n").split("\n")
        anchor = next(i for i, l in enumerate(lines) if l.strip().startswith("exit $r"))
        lines.insert(anchor, '          grep -aE \'^CRG_PROBE_ONLY=\' "$L" | tail -3')
        _write(target, "\n".join(lines))
        rc, facts = scan(tmp)
        fired = 1 if (_val(facts, "CRG_UNGUARDED") == base_unguarded + 1
                      and _val(facts, "CRG_LINES_NOGUARD") == base_lines + 1
                      and any("CRG_PROBE_ONLY" in f for f in facts)) else 0
        results.append(("b_report_pipe", 1, fired, rc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # (в) тот же grep в комментарии -> находок не прибавляется (прибор не считает прозу).
    tmp = tempfile.mkdtemp(prefix="crg-c-")
    try:
        _copy_wf(base_root, tmp)
        target = os.path.join(tmp, WF_DIR, os.path.basename(probe))
        with open(target, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        _write(target, text + "\n          # grep -aE '^CRG_COMMENT_ONLY=' \"$L\" | tail -3\n")
        rc, facts = scan(tmp)
        fired = 1 if (_val(facts, "CRG_UNGUARDED") == base_unguarded
                      and not any("CRG_COMMENT_ONLY" in f for f in facts)) else 0
        results.append(("c_comment_not_counted", 1, fired, rc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # (г) пустой каталог workflow -> слепота обязана покраснеть, а не выдать чистый ноль.
    tmp = tempfile.mkdtemp(prefix="crg-d-")
    try:
        os.makedirs(os.path.join(tmp, WF_DIR))
        rc, facts = scan(tmp)
        fired = 1 if (_val(facts, "CRG_BLIND") == 1 and rc != 0) else 0
        results.append(("d_blind_dir_red", 1, fired, rc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # (д) четвёртый файл workflow с неспрятанной трубой -> обязан быть в переборе (и пересчёт тоже).
    tmp = tempfile.mkdtemp(prefix="crg-e-")
    try:
        _copy_wf(base_root, tmp)
        _write(os.path.join(tmp, WF_DIR, "extra-probe.yml"),
               "jobs:\n  x:\n    steps:\n      - run: |\n"
               "          set -uo pipefail\n"
               "          grep -aE '^CRG_PLANTED=' /dev/null | tail -2\n"
               "          exit 0\n")
        rc, facts = scan(tmp)
        grew = _val(facts, "CRG_UNGUARDED") == base_unguarded + 1
        grew &= _val(facts, "CRG_LINES_NOGUARD") == base_lines + 1
        fired = 1 if grew else 0
        results.append(("e_fourth_file_seen", 1, fired, rc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total = len(results)
    fired = sum(1 for r in results if r[2] == 1)
    for name, landed, got, _rc in results:
        print("CRG_SELFTEST_CASE %s landed=%d fired=%d" % (name, landed, got))
    print("CRG_SELFTEST total=%d fired=%d" % (total, fired))
    ok = 1 if fired == total else 0
    print("CRG_SELFTEST_OK=%d" % ok)
    return 0 if ok else 1


def _has(facts, key):
    return any(f.startswith(key + "=") for f in facts)


def _val(facts, key):
    for f in facts:
        if f.startswith(key + "="):
            try:
                return int(f.split("=", 1)[1])
            except ValueError:
                return -1
    return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="check", choices=["check", "selftest"])
    ap.add_argument("--dir", default=None)
    a = ap.parse_args()
    root = os.path.abspath(a.dir or os.path.dirname(os.path.dirname(__file__)))
    if a.mode == "selftest":
        return selftest(root)
    print("CRG_ROOT=%s" % root.replace("\\", "/"))
    rc, facts = scan(root)
    print_facts(facts)
    return rc


if __name__ == "__main__":
    sys.exit(main())
