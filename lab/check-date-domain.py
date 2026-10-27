#!/usr/bin/env python3
"""Прибор `E-0129`: даты контура берутся у хоста, а судят по ним машину в UTC.

Что измеряется (и чем это НЕ является)
--------------------------------------

Три дефекта одного корня — «прибор живёт в местном времени, а вердикт отдаёт чужому»:

1. `lab/library.py` и `lab/sources.py` штампуют и сравнивают даты через `date.today()`, то
   есть через **местную** дату хоста. Runner'ы GitHub живут в UTC. Хост владельца — UTC+3,
   поэтому запись, закрытая между 21:00 и 24:00 по местному, получает дату, которой в UTC
   ещё нет, и правило «дата сверки в будущем» краснит работу `verify` независимо от того,
   зелёный ли продукт. Наблюдение 2026-10-27: шаг `library check` покраснел именно так
   (`LIBCHECK records=39 read=39 errors=1`), а шесть шагов после него не исполнились вовсе.
2. `cmd_use` перезаписывает поле `opened` текущей датой при каждом переиспользовании записи.
   `opened` — дата, в которую источник был найден, и по ней `lab/cycle-gate.py` судит, не
   найден ли источник уже после формулировки гипотезы. Перезапись производит нарушение,
   которого не было: живое наблюдение — `CYCLE H-0127=FAIL нарушений=1` на записи L-0038,
   открытой 2026-10-26 и перезаписанной на 2026-10-27 при закрытии `E-0128`.
3. `cmd_audit` в `lab/cycle-gate.py` печатает `CYCLE H-xxxx=FAIL нарушений=N` и всегда
   возвращает ноль. Шаг в CI делает `exit $r`, поэтому вердикт, названный FAIL, покраснить
   работу не может. Это хвост `E-0127`, п. 3 (прибор знает форму, но не знает, есть ли в
   шаге чем вынести вердикт), и он закрывается этим же циклом.

Прибор проверяет **форму кода и данные индекса**, а не текущий час. Ключи `DDF_UTC_TODAY`,
`DDF_LOCAL_TODAY`, `DDF_DOMAIN_SPLIT` и `DDF_CLOSED_FIELD` — измерения: они зависят от момента
снятия и в таблицу ожиданий не входят (правило 7, пункт (е): вердикт обязан быть инвариантен
к расписанию).

Границы прибора, названные до замера
------------------------------------

* Правила 1…5 статические (читают исходники), правила 6…8 фактические (читают
  `lab/library/index.jsonl` и первый коммит строки в истории файла). Прибор не утверждает,
  что починка починила CI: это утверждает прогон `python lab/library.py check` под `TZ=UTC`
  в helper'е `lab/e0129-run.sh` (TZ=UTC — ровно окружение runner'а) и, отдельно, чтение
  чужого прогона.
* git-доказательство требует репозитория. Самопроверка работает на фикстурах без git и
  запускает сбор с `--no-git`; живой прогон требует его через `--require-git`, и отсутствие
  истории там, где оно обязательно, — находка, а не молчание.
* Фикстуры самопроверки **нормализуются** к чистой форме, а не копируются как есть: на
  сломанном дереве копия уже содержит дефект, и посадка, построенная на буквальной строке
  починки, стала бы пустышкой (урок `E-0128`, пункт подготовки 1). Поэтому `selftest` осмыслен
  и до починки, и после неё.
* Поле `closed` новое; его отсутствие у записей, закрытых до этого цикла, находкой не
  считается — иначе правка требовала бы переписать историю вместо кода.
* Прибор не судит другие классы: концы труб — `lab/check-ci-report-greps.py` (`E-0127`),
  захваты `$?` — `lab/check-ci-rc-capture.py` (`E-0128`). Зелёный один не говорит ничего
  про другой.

Молчание не успех: пустой индекс, непрочитанный файл правила и пропавшее git-доказательство
дают `DDF_BLIND=1` и красный выход.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT_LIVE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODE_FILES = ("lab/library.py", "lab/sources.py", "lab/cycle-gate.py")
# Правила 1 и 2 (местная дата и воронка) имеют область только там, где дату штампуют или
# сравнивают: `lab/cycle-gate.py` карточки читает и дат не производит, поэтому требовать от
# него функции `utc_today` — значело бы находку без дефекта (ДИАГНОЗ прогона: первый живой
# запуск прибора выдал «no-funnel: lab/cycle-gate.py» на чистом после починки дереве).
DATE_FILES = ("lab/library.py", "lab/sources.py")
# Дата принятия `ADR-0070` по UTC. Записи, чей первый коммит раньше неё, помечены местной
# датой хоста: переписывать их задним числом — значило бы подделать дату находки, поэтому
# они унаследованы и названы отдельным числом (DDF_LEGACY_LOCAL_STAMP).
CUTOVER = "2026-10-26"
INDEX_REL = os.path.join("lab", "library", "index.jsonl")
INDEX_GIT = "lab/library/index.jsonl"
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LOCAL_TODAY_RE = re.compile(r"date\.today\(\)")
UTC_FUNNEL_RE = re.compile(r"\butc_today\b")
OPENED_WRITE_RE = re.compile(r'^[ \t]*r\["opened"\][^\n]*\n', re.M)
CLOSED_SET_RE = re.compile(r'\["closed"\]\s*=\s*utc_today\(\)')
AUDIT_GATE_RE = re.compile(r"^\s*return 1 if bad_cards else 0\s*$", re.M)

# Буквы нормализации и посадок — константы, чтобы фикстура и посадка не разъезжались молча.
STAMP_SRC = "dt.date.today().isoformat()"
STAMP_DST = "utc_today()"
FUNNEL_DEF = ('def utc_today() -> str:\n'
              '    """Единственная дата контура: UTC (прибор E-0129)."""\n'
              '    return dt.datetime.now(dt.timezone.utc).date().isoformat()\n\n\n')
CLOSE_LINE = '    r["closed"] = utc_today()\n'
AUDIT_GATE_LINE = "    return 1 if bad_cards else 0\n"
AUDIT_FIX_BLOCK = "    bad_cards = 0\n" + AUDIT_GATE_LINE

# Измерительный шов: прибор умеет судить по назначенной дате, а не по настенным часам. Шов есть
# ТОЛЬКО у прибора — механизм (`lab/library.py`, `lab/sources.py`) дату пишет по настоящим часам и
# из окружения её не берёт, поэтому подделать запись он этим не может. Причина шва: PRE_FIX снимается
# с дерева пина, а дата пина фиксирована, и без шва число находок пина стало бы зависеть от того,
# в какой час прогнали helper (правило 7, пункт (е): факт годен в вердикт, только если он инвариантен
# к моменту снятия). Значение вне формата YYYY-MM-DD игнорируется — молчание шва красит прогон через
# `DDF_CLOCK_FROZEN=0`, а не через выдуманную дату.
CLOCK_ENV = "VEC_DHT_DDF_TODAY"


def utc_today() -> str:
    """Единственная дата контура: UTC, потому что runner'ы GitHub живут в UTC."""
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def measured_today() -> str:
    """Дата, по которой судит ПРИБОР: настоящие UTC-часы либо замороженное значение шва."""
    frozen = os.environ.get(CLOCK_ENV, "").strip()
    if DATE_RE.match(frozen):
        return frozen
    return utc_today()


def clock_frozen() -> int:
    return 1 if DATE_RE.match(os.environ.get(CLOCK_ENV, "").strip()) else 0


def read(path: str) -> str | None:
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def span(text: str, name: str):
    """Границы функции в строке: от `def name(` до следующего оператора нулевого отступа."""
    m = re.search(rf"^def {re.escape(name)}\(", text, re.M)
    if not m:
        return None
    start = m.start()
    nxt = re.search(r"\n(?=\S)", text[m.end():], re.M)
    return start, m.end() + nxt.start() if nxt else len(text)


def body(text: str, name: str) -> str:
    s = span(text, name)
    return text[s[0]:s[1]] if s else ""


def replace_last_in(text: str, lo: int, hi: int, old: str, new: str) -> str:
    i = text.rfind(old, lo, hi)
    return text[:i] + new + text[i + len(old):] if i >= 0 else text


# ------------------------------------------------------------------ правила 1…5
def check_code(root: str, findings: list[str]) -> dict[str, int]:
    facts = {"local_today_calls": 0, "funnel_files": 0, "legacy_local_stamp": 0,
             "use_writes_opened": 0,
             "close_no_closed": 0, "audit_no_gate": 0, "missing_files": 0}
    for rel in CODE_FILES:
        text = read(os.path.join(root, rel))
        if text is None:
            findings.append(f"blind: файл правила не прочитан — {rel}")
            facts["missing_files"] += 1
            continue
        if rel not in DATE_FILES:
            continue
        n = len(LOCAL_TODAY_RE.findall(text))
        facts["local_today_calls"] += n
        if n:
            findings.append(f"local-today: {rel} берёт дату у хоста ({n} вызова «date.today()»)")
        if UTC_FUNNEL_RE.search(text):
            facts["funnel_files"] += 1
        else:
            findings.append(f"no-funnel: {rel} не знает функции «utc_today» — дата снова местная")
    lib = read(os.path.join(root, "lab/library.py")) or ""
    if OPENED_WRITE_RE.search(body(lib, "cmd_use")):
        facts["use_writes_opened"] = 1
        findings.append("use-writes-opened: «cmd_use» перезаписывает «opened» — дата находки "
                        "источника стирается при каждом переиспользовании")
    seg = body(lib, "cmd_close")
    if seg and not CLOSED_SET_RE.search(seg):
        facts["close_no_closed"] = 1
        findings.append("close-no-closed: «cmd_close» не ставит «closed», и дата закрытия "
                        "неотличима от даты находки")
    audit = body(read(os.path.join(root, "lab/cycle-gate.py")) or "", "cmd_audit")
    if audit and not AUDIT_GATE_RE.search(audit):
        facts["audit_no_gate"] = 1
        findings.append("audit-no-gate: «cmd_audit» не возвращает ненулевой код по находкам — "
                        "названный FAIL не может покраснить шаг")
    return facts


# ------------------------------------------------------------------ git-доказательство
def added_dates(root: str) -> dict[str, str]:
    """Первый коммит, где строка записи появилась в файле, -> её дата в UTC.

    Один проход истории плюс `git show` по коммитам, тронувшим файл: 39 вызовов
    `git log -S` обошли бы историю целиком по числу записей.
    """
    if not os.path.isdir(os.path.join(root, ".git")):
        return {}
    try:
        log = subprocess.run(["git", "log", "--reverse", "--format=%H|%aI", "--", INDEX_GIT],
                             cwd=root, capture_output=True, text=True, timeout=180,
                             encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return {}
    if log.returncode != 0:
        return {}
    out: dict[str, str] = {}
    for line in log.stdout.splitlines():
        if "|" not in line:
            continue
        sha, iso = line.split("|", 1)
        try:
            when = dt.datetime.fromisoformat(iso).astimezone(dt.timezone.utc).date().isoformat()
        except ValueError:
            continue
        try:
            show = subprocess.run(["git", "show", f"{sha}:{INDEX_GIT}"], cwd=root,
                                  capture_output=True, text=True, timeout=180,
                                  encoding="utf-8", errors="replace")
        except (OSError, subprocess.SubprocessError):
            continue
        # `text=True` без явной кодировки декодирует вывод локальной страницей хоста
        # (на этом хосте — cp1251), потоковый читатель падает, а stdout становится None:
        # ДИАГНОЗ прогона — первый же запуск прибора умер на кириллице в diff, а не сообщил
        # о ней. Читаем UTF-8 явно и пустой вывод не считаем удачным.
        if show.returncode != 0 or show.stdout is None:
            continue
        for m in re.finditer(r'"id"\s*:\s*"(L-\d{4})"', show.stdout):
            out.setdefault(m.group(1), when)
    return out


# ------------------------------------------------------------------ правила 6…9
def check_data(root: str, today: str, added: dict[str, str], require_git: bool,
               findings: list[str]) -> dict[str, int]:
    facts = {"records": 0, "date_fields": 0, "dates_after_utc": 0, "opened_after_added": 0,
             "legacy_local_stamp": 0,
             "closed_before_opened": 0, "closed_field": 0, "blind": 0, "git_evidence": 0,
             "git_checked": 0}
    text = read(os.path.join(root, INDEX_REL))
    if text is None:
        findings.append("blind: индекс источников не прочитан")
        facts["blind"] = 1
        return facts
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            findings.append("blind: строка индекса не разобрана как JSON")
    facts["records"] = len(rows)
    if not rows:
        findings.append("blind: индекс пуст, правилам 6…8 не о чем судить")
        facts["blind"] = 1
    if added:
        facts["git_evidence"] = 1
    elif require_git:
        findings.append("blind: git-доказательство недоступно (нет репозитория или истории "
                        "файла), а прогон требует его")
        facts["blind"] = 1
    for r in rows:
        rid = str(r.get("id", "без id"))
        for k in ("verified", "opened", "closed"):
            v = str(r.get(k, ""))
            if not v:
                continue
            if not DATE_RE.match(v):
                findings.append(f"date-format: {rid}.{k}={v!r} вне формата YYYY-MM-DD")
                continue
            facts["date_fields"] += 1
            if v > today:
                facts["dates_after_utc"] += 1
                findings.append(f"date-after-utc: {rid}.{k}={v} позже сегодня по UTC ({today})")
        if r.get("closed"):
            facts["closed_field"] += 1
            if r.get("opened") and str(r["closed"]) < str(r["opened"]):
                facts["closed_before_opened"] += 1
                findings.append(f"closed-before-opened: {rid} закрыта {r['closed']} раньше, "
                                f"чем найдена {r['opened']}")
        if added.get(rid):
            facts["git_checked"] += 1
            if str(r.get("opened", "")) > added[rid]:
                if added[rid] >= CUTOVER:
                    facts["opened_after_added"] += 1
                    findings.append(f"opened-after-added: {rid} помечена открытой {r['opened']}, "
                                    f"а строка попала в файл {added[rid]}")
                else:
                    facts["legacy_local_stamp"] += 1
    return facts


def collect(root: str, require_git: bool) -> tuple[dict[str, int], list[str], str]:
    findings: list[str] = []
    facts = check_code(root, findings)
    facts.update(check_data(root, measured_today(), added_dates(root), require_git, findings))
    if not facts["records"] or facts["missing_files"] or (require_git and not facts["git_evidence"]):
        facts["blind"] = 1
    facts["findings"] = len(findings)
    facts["fail"] = 1 if (findings or facts["blind"]) else 0
    return facts, findings, measured_today()


def recount_local(root: str) -> int:
    """Независимый пересчёт: построчный поиск буквы, а не регулярка по всему тексту."""
    n = 0
    for rel in DATE_FILES:
        for line in (read(os.path.join(root, rel)) or "").splitlines():
            if "date.today()" in line:
                n += 1
    return n


def cmd_check(args) -> int:
    facts, findings, today = collect(args.root, args.require_git)
    rc = recount_local(args.root)
    eq = 1 if rc == facts["local_today_calls"] else 0
    if not eq:
        findings.insert(0, f"blind: независимый пересчёт локальных дат не сошёлся с прибором "
                           f"({rc} против {facts['local_today_calls']})")
        facts["findings"] = len(findings)
        facts["fail"] = 1
    printed = findings[: args.limit] if args.limit else findings
    print(f"DDF_ROOT_KIND={'живое' if os.path.abspath(args.root) == ROOT_LIVE else 'копия'}")
    print(f"DDF_FILES={len(CODE_FILES)}")
    print(f"DDF_DATE_FILES={len(DATE_FILES)}")
    print(f"DDF_LOCAL_TODAY_CALLS={facts['local_today_calls']}")
    print(f"DDF_CUTOVER={CUTOVER}")
    print(f"DDF_FUNNEL_FILES={facts['funnel_files']}")
    print(f"DDF_USE_WRITES_OPENED={facts['use_writes_opened']}")
    print(f"DDF_CLOSE_NO_CLOSED={facts['close_no_closed']}")
    print(f"DDF_AUDIT_NO_GATE={facts['audit_no_gate']}")
    print(f"DDF_RECORDS={facts['records']}")
    print(f"DDF_DATE_FIELDS={facts['date_fields']}")
    print(f"DDF_DATES_AFTER_UTC={facts['dates_after_utc']}")
    print(f"DDF_CLOCK_FROZEN={clock_frozen()}")
    print(f"DDF_CLOCK_DATE={measured_today()}")
    print(f"DDF_GIT_CHECKED={facts['git_checked']}")
    print(f"DDF_OPENED_AFTER_ADDED={facts['opened_after_added']}")
    print(f"DDF_LEGACY_LOCAL_STAMP={facts['legacy_local_stamp']}")
    print(f"DDF_CLOSED_BEFORE_OPENED={facts['closed_before_opened']}")
    print(f"DDF_GIT_EVIDENCE={facts['git_evidence']}")
    print(f"DDF_RECOUNT_EQ={eq}")
    print(f"DDF_FINDINGS={facts['findings']}")
    for f in printed:
        print(f"  НАХОДКА {f}")
    print(f"DDF_FINDINGS_PRINTED={len(printed)}")
    # Измерения, не входящие в таблицу ожиданий: зависят от момента снятия.
    print(f"DDF_UTC_TODAY={today}")
    print(f"DDF_LOCAL_TODAY={dt.date.today().isoformat()}")
    print(f"DDF_DOMAIN_SPLIT={1 if dt.date.today().isoformat() != today else 0}")
    print(f"DDF_CLOSED_FIELD={facts['closed_field']}")
    print(f"DDF_BLIND={facts['blind']}")
    print(f"DDF_FAIL={facts['fail']}")
    print(f"DDF_EXIT={facts['fail']}")
    return facts["fail"]


# ------------------------------------------------------------------ фикстуры
def normalize(text: str, rel: str) -> str:
    """Привести копию к чистой форме. Идемпотентно: работает и на сломанном дереве."""
    if rel == "lab/cycle-gate.py":
        s = span(text, "cmd_audit")
        if s and not AUDIT_GATE_RE.search(text[s[0]:s[1]]):
            return text[:s[0]] + replace_last_in(text, s[0], s[1], "    return 0\n",
                                                 AUDIT_FIX_BLOCK) + text[s[1]:]
        return text
    text = text.replace(STAMP_SRC, STAMP_DST)
    if "def utc_today(" not in text:
        m = re.search(r"^(?:def |class |@)", text, re.M)
        pos = m.start() if m else len(text.rstrip("\n")) + 1
        text = text[:pos] + FUNNEL_DEF + text[pos:]
    if rel == "lab/library.py":
        text = OPENED_WRITE_RE.sub("", text)
        s = span(text, "cmd_close")
        if s and not CLOSED_SET_RE.search(text[s[0]:s[1]]):
            text = (text[:s[0]] + replace_last_in(text, s[0], s[1], "    _rewrite(rows)",
                                                 CLOSE_LINE + "    _rewrite(rows)") + text[s[1]:])
    return text


def fixture(root: str) -> None:
    """Мини-дерево из нормализованных живых файлов плюс один чистый индекс."""
    for rel in CODE_FILES:
        src = read(os.path.join(ROOT_LIVE, rel)) or ""
        dst = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(normalize(src, rel))
    d = os.path.join(root, "lab", "library")
    os.makedirs(d, exist_ok=True)
    today = measured_today()
    row = {"id": "L-0001", "title": "чистая", "url": "https://example.com/a", "cite": "a",
           "verified": today, "depth": "текст выборочно", "kind": "спека", "gives": "g",
           "targets": ["H-0000"], "status": "изменено", "action": "E-0000: x", "cost_min": 1,
           "opened": today, "closed": today}
    with open(os.path.join(d, "index.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


# (kind, файл, что заменяем, чем, ожидаемая формулировка находки, по всему файлу?)
PLANTS = (
    ("local_today", "lab/library.py", "= " + STAMP_DST, "= " + STAMP_SRC, "local-today", False),
    ("no_funnel", "lab/library.py", "utc_today", "местная_дата", "no-funnel", True),
    ("use_writes_opened", "lab/library.py", "def cmd_use(args):\n",
     'def cmd_use(args):\n    r = {}\n    r["opened"] = utc_today()\n', "use-writes-opened", False),
    ("close_no_closed", "lab/library.py", CLOSE_LINE, "", "close-no-closed", False),
    ("audit_no_gate", "lab/cycle-gate.py", AUDIT_GATE_LINE, "    return 0\n", "audit-no-gate",
     False),
    ("date_after_utc", INDEX_REL, None, None, "date-after-utc", False),
    ("closed_before_opened", INDEX_REL, None, None, "closed-before-opened", False),
    ("blind_index", INDEX_REL, None, None, "blind", False),
    ("missing_file", "lab/sources.py", None, None, "blind", False),
)


def plant(root: str, kind: str, rel: str, old, new, expect: str, whole: bool) -> None:
    path = os.path.join(root, rel)
    if kind == "missing_file":
        os.remove(path)
        return
    if kind == "blind_index":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("")
        return
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if kind == "date_after_utc":
        text = replace_last_in(text, 0, len(text), measured_today(), "2999-01-01")
    elif kind == "closed_before_opened":
        text = replace_once_every(text, '"closed": "' + measured_today(), '"closed": "1999-01-01')
    else:
        if old not in text:
            raise SystemExit(f"SELFTEST остановлен: посадка {kind} не нашла строку {old!r}: "
                             "фикстура разошлась с прибором, проверка стала бы пустышкой")
        text = text.replace(old, new) if whole else text.replace(old, new, 1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def replace_once_every(text: str, old: str, new: str) -> str:
    return text.replace(old, new, 1)


def cmd_selftest(_args) -> int:
    total = passed = 0
    with tempfile.TemporaryDirectory() as base:
        clean = os.path.join(base, "clean")
        os.makedirs(clean)
        fixture(clean)
        facts, findings, _ = collect(clean, False)
        total += 1
        ok = facts["findings"] == 0 and facts["blind"] == 0
        passed += 1 if ok else 0
        print(f"SELFTEST чистое_дерево_не_валится: {'ОТБИТА' if ok else 'ВАЛИТСЯ'} "
              f"находок={facts['findings']} {findings or 'none'}")
        for kind, rel, old, new, expect, whole in PLANTS:
            total += 1
            d = os.path.join(base, kind)
            os.makedirs(d)
            fixture(d)
            plant(d, kind, rel, old, new, expect, whole)
            facts, findings, _ = collect(d, False)
            hit = any(f.startswith(expect) for f in findings)
            passed += 1 if hit else 0
            if not hit:
                print(f"  НЕ ОТБИТА посадка {kind}: ожидалась находка «{expect}», "
                      f"найдено {findings or 'none'}")
            print(f"PLANT_{kind.upper()}_FIRED={1 if hit else 0}")
        bad = 1 if passed != total else 0
        print(f"DDF_SELFTEST total={total} passed={passed}")
        print(f"DDF_SELFTEST_PLANTS={len(PLANTS)}")
        print(f"DDF_SELFTEST_EXIT={bad}")
        return bad


def main() -> int:
    ap = argparse.ArgumentParser(description="прибор E-0129: домен дат контура источников")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="проверить форму кода и даты индекса")
    c.add_argument("--root", default=ROOT_LIVE)
    c.add_argument("--require-git", action="store_true")
    c.add_argument("--limit", type=int, default=0, help="сколько находок печатать; 0 — все")
    s = sub.add_parser("selftest", help="посадки обязаны отбиваться, чистое дерево — нет")
    args = ap.parse_args()
    if args.cmd == "check":
        return cmd_check(args)
    return cmd_selftest(args)


if __name__ == "__main__":
    sys.exit(main())
