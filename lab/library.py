#!/usr/bin/env python3
"""Контур источников лаборатории: index.jsonl -> проверка, дайджест, след действия.

Формат записей — `lab/library/index.jsonl`, по одному JSON-объекту на строку.
Смысл файла один: у каждого утверждения, взятого не из нашего замера, есть строка
с ссылкой, датой сверки, глубиной чтения и — обязательно — действием. Инсайт без
действия не считается прочитанным; «прочитал и не повлияло» — тоже действие, но
с причиной.

Команды:
  check                 — машинная проверка индекса (exit 1 при любом нарушении)
  digest                — что не использовано + открытые вопросы спеки без сверки
  value [--cycles N]    — счётчики полезности контура и вердикт по заморозенному критерию
  add --json '{...}'    — добавить запись (только валидную)
  use ID --target T     — перевести в «в работе» и привязать к цели
  close ID --action A --what "..."  — закрыть со статусом изменено|не повлияло
  scan                  — триггерные фразы спеки, по которым сверка ещё не сделана
"""

import argparse
import datetime as dt
import json
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.environ.get("VEC_DHT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LIB_DEFAULT = os.path.join(ROOT, "lab", "library", "index.jsonl")
# Индекс можно указать явно: отрицательные контроли прогона проверяют испорченные
# копии, не трогая рабочий файл.
LIB = os.environ.get("VEC_DHT_LIBRARY") or _LIB_DEFAULT
SPEC = os.path.join(ROOT, "docs", "VecDHT-SPEC-v8.md")

STATUSES = ("не использован", "в работе", "изменено", "не повлияло")
DEPTHS = ("аннотация", "текст выборочно", "полный текст")
REQUIRED = ("id", "title", "url", "cite", "verified", "depth", "gives", "targets",
            "status", "action", "cost_min", "opened")
ID_RE = re.compile(r"^L-\d{4}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Действие обязано указывать, что именно изменено: номер цикла, ADR, § или порог.
ACTION_REF_RE = re.compile(r"(H-\d{4}|E-\d{4}|ADR-\d{4}|S-\d{4}|§|порог|PLAN|OPEN-QUESTIONS)")
# Бюджет одного шага сверки, минут (решение владельца 2026-10-23, ADR-0045).
COST_BUDGET_MIN = 30
STALE_WARN_DAYS, STALE_FAIL_DAYS = 7, 14
# Порог полезности заморожен ДО первого применения: 5 циклов, ноль «изменено» => декорация.
VALUE_WINDOW_CYCLES = 5

TRIGGERS = (
    "защиты нет", "не реализовано", "не измерено", "не проверя", "нет механизма",
    "не выполнено", "обещание", "не достаточн",
)


def fail(msg, errors):
    errors.append(msg)
    print(f"  FAIL  {msg}")


def target_exists(target):
    """Цель обязана жить в репозитории: H-/E-/ADR-/S- как файл, SPEC:... как §."""
    if target.startswith("SPEC:"):
        return True
    known_docs = {
        "PLAN": ("lab", "PLAN.md"),
        "OPEN-QUESTIONS": ("lab", "decisions", "OPEN-QUESTIONS.md"),
        "LAB-README": ("lab", "README.md"),
    }
    if target in known_docs:
        return os.path.isfile(os.path.join(ROOT, *known_docs[target]))
    m = re.match(r"^(H|E|S|ADR)-(\d{4})$", target)
    if not m:
        return False
    kind, num = m.group(1), m.group(2)
    dirs = {"H": ("lab", "hypotheses"), "E": ("lab", "experiments"),
            "S": ("lab", "notes"), "ADR": ("lab", "decisions")}
    d = os.path.join(ROOT, *dirs[kind])
    if not os.path.isdir(d):
        return False
    return any(f.startswith(f"{kind}-{num}") for f in os.listdir(d))


def load():
    rows = []
    if not os.path.isfile(LIB):
        return rows
    with open(LIB, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                rows.append({"_line": n, "_raw": line, "_error": str(e)})
                continue
            obj["_line"] = n
            rows.append(obj)
    return rows


def check_row(row, today, errors, warnings, seen_ids):
    rid = row.get("id", f"строка {row['_line']}")
    if "_error" in row:
        fail(f"{rid}: разобран не как JSON ({row['_error']})", errors)
        return
    for k in REQUIRED:
        if k not in row:
            fail(f"{rid}: нет обязательного поля «{k}»", errors)
    if not ID_RE.match(str(row.get("id", ""))):
        fail(f"{rid}: id вне формата L-NNNN", errors)
    if row.get("id") in seen_ids:
        fail(f"{rid}: id повторяется (строки {seen_ids.get(row.get('id'))} и {row['_line']})", errors)
    seen_ids[row.get("id")] = row["_line"]
    url = str(row.get("url", ""))
    if not url.startswith("https://"):
        fail(f"{rid}: ссылка обязана быть https (правило «ссылка важнее пересказа»)", errors)
    if not str(row.get("cite", "")).strip():
        fail(f"{rid}: нет устойчивого идентификатора (arXiv:/DOI:)", errors)
    v = str(row.get("verified", ""))
    if not DATE_RE.match(v):
        fail(f"{rid}: поле «verified» вне формата YYYY-MM-DD", errors)
    elif v > today:
        fail(f"{rid}: дата сверки {v} в будущем", errors)
    if row.get("depth") not in DEPTHS:
        fail(f"{rid}: глубина «{row.get('depth')}» вне списка {DEPTHS}", errors)
    if row.get("status") not in STATUSES:
        fail(f"{rid}: статус «{row.get('status')}» вне списка {list(STATUSES)}", errors)
    if not str(row.get("title", "")).strip() or not str(row.get("gives", "")).strip():
        fail(f"{rid}: пустые «title» или «gives»", errors)
    targets = row.get("targets") or []
    if not isinstance(targets, list):
        fail(f"{rid}: «targets» обязан быть списком", errors)
        targets = []
    for t in targets:
        if not target_exists(t):
            fail(f"{rid}: цель «{t}» не найдена в репозитории", errors)
    status, action = row.get("status"), str(row.get("action", ""))
    if status == "не использован" and targets:
        fail(f"{rid}: «не использован» не может иметь цели", errors)
    if status in ("в работе", "изменено", "не повлияло"):
        if not targets:
            fail(f"{rid}: статус «{status}» без цели — непонятно, что читали", errors)
        if not isinstance(row.get("cost_min"), int) or row["cost_min"] < 0:
            fail(f"{rid}: «cost_min» обязан быть целым и >= 0", errors)
        elif row["cost_min"] > COST_BUDGET_MIN:
            fail(f"{rid}: шаг сверки стоил {row['cost_min']} мин > бюджета {COST_BUDGET_MIN}", errors)
    if status == "изменено" and not ACTION_REF_RE.search(action):
        fail(f"{rid}: «изменено» без ссылки на изменённый артефакт (H-/E-/ADR-/§/порог/PLAN)", errors)
    if status == "не повлияло" and len(action.strip()) < 12:
        fail(f"{rid}: «не повлияло» без причины", errors)
    if status in ("не использован", "в работе") and action.strip():
        fail(f"{rid}: статус «{status}» уже содержит действие — это не закрытая запись", errors)
    if status == "в работе":
        opened = str(row.get("opened", ""))
        if not DATE_RE.match(opened):
            fail(f"{rid}: «в работе» без даты «opened»", errors)
        else:
            age = (dt.date.fromisoformat(today) - dt.date.fromisoformat(opened)).days
            if age > STALE_FAIL_DAYS:
                fail(f"{rid}: «в работе» висит {age} дн > {STALE_FAIL_DAYS} — закрой или сними", errors)
            elif age > STALE_WARN_DAYS:
                warnings.append(f"{rid}: «в работе» {age} дн (предел {STALE_FAIL_DAYS})")


def cmd_check(_args):
    today = dt.date.today().isoformat()
    rows = load()
    errors, warnings, seen = [], [], {}
    if not rows:
        print("ПРОВЕРКА записей=0 — индекс пуст, контур не работает")
        return 1
    for row in rows:
        check_row(row, today, errors, warnings, seen)
    for w in warnings:
        print(f"  WARN  {w}")
    used = [r for r in rows if r.get("status") != "не использован"]
    print(f"ПРОВЕРКА записей={len(rows)} прочитано={len(used)} ошибок={len(errors)} "
          f"предупреждений={len(warnings)}")
    print(f"LIBCHECK records={len(rows)} read={len(used)} errors={len(errors)} warns={len(warnings)}")
    return 1 if errors else 0


def scan_lines():
    """Триггерные фразы спеки: места, где обещание или отсутствие механизма.

    Раздел — тот, под заголовком которого лежит строка, а НЕ первый § внутри неё:
    текст §14.4, ссылающийся на §9.2, иначе приписывается не тому месту и сверка
    считается по чужому разделу (ДИАГНОЗ-1 механизма).
    """
    out = []
    if not os.path.isfile(SPEC):
        return out
    current = ""
    head_re = re.compile(r"^#{2,4}\s+(\d+(?:\.\d+)*)[\s.]")
    with open(SPEC, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            h = head_re.match(line)
            if h:
                current = h.group(1)
            low = line.lower()
            for t in TRIGGERS:
                if t in low:
                    out.append({"line": n, "trigger": t, "section": current,
                                "text": line.strip()[:140]})
                    break
    return out


def covered_sections(rows):
    cov = set()
    for r in rows:
        for t in (r.get("targets") or []):
            if t.startswith("SPEC:"):
                m = re.search(r"§\s?([\d.]+)", t)
                if m:
                    cov.add(m.group(1).rstrip("."))
    return cov


def cmd_digest(_args):
    rows = load()
    today = dt.date.today().isoformat()
    unused = [r for r in rows if r.get("status") == "не использован"]
    open_wip = [r for r in rows if r.get("status") == "в работе"]
    done = [r for r in rows if r.get("status") in ("изменено", "не повлияло")]
    changed = [r for r in rows if r.get("status") == "изменено"]
    print(f"ДАЙДЖЕСТ {today}: всего={len(rows)} не_использовано={len(unused)} "
          f"в_работе={len(open_wip)} закрыто={len(done)} с_действием_изменение={len(changed)}")
    print(f"LIBDIGEST total={len(rows)} unused={len(unused)} wip={len(open_wip)} "
          f"closed={len(done)} changed={len(changed)}")
    for r in unused:
        print(f"  НЕ ИСПОЛЬЗОВАН {r.get('id')} {r.get('title','')[:70]} -> {r.get('gives','')[:70]}")
    for r in open_wip:
        print(f"  В РАБОТЕ {r.get('id')} открыт {r.get('opened')} цели={','.join(r.get('targets') or [])}")
    cov = covered_sections(rows)
    hits = scan_lines()
    secs = {}
    for h in hits:
        if h["section"] and h["section"] not in secs:
            secs[h["section"]] = h
    uncov = [s for s in sorted(secs) if s not in cov]
    print(f"ТРИГГЕРЫ строк={len(hits)} разделов={len(secs)} без_литературной_сверки={len(uncov)} "
          f"сверено_разделов={len(cov)}")
    print(f"LIBTRIGGERS lines={len(hits)} sections={len(secs)} uncovered={len(uncov)} covered={len(cov)}")
    for s in uncov[:12]:
        h = secs[s]
        print(f"  СПРОСИ §{s}: {h['text'][:110]}")
    print("БЮДЖЕТ: один шаг сверки <= 30 мин, выход — строка «не повлияло» с причиной "
          "или правка гипотезы/порога ДО пре-регистрации")
    return 0


def cmd_value(args):
    rows = load()
    consulted = [r for r in rows if r.get("status") in ("изменено", "не повлияло")]
    changed = [r for r in rows if r.get("status") == "изменено"]
    cost = sum(int(r.get("cost_min", 0)) for r in consulted)
    print(f"ПОЛЕЗНОСТЬ прочитано_до_конца={len(consulted)} изменено={len(changed)} "
          f"не_повлияло={len(consulted) - len(changed)} суммарно_минут={cost} "
          f"цена_за_находку=" + (f"{cost // len(changed)}" if changed else "н/д"))
    if len(consulted) >= args.cycles:
        verdict = "КОНТУР ГОДЕН" if changed else "КОНТУР ДЕКОРАТИВЕН — снять обязательность (ADR-0045)"
        key = "ok" if changed else "decorative"
        print(f"ВЕРДИКТ по критерию (>= {args.cycles} закрытых записей): {verdict}")
    else:
        key = "not_ready"
        print(f"ВЕРДИКТ не готов: закрытых записей {len(consulted)} < {args.cycles}")
    print(f"LIBVALUE closed={len(consulted)} changed={len(changed)} minutes={cost} "
          f"window={args.cycles} verdict={key}")
    return 0


def cmd_add(args):
    try:
        row = json.loads(args.json)
    except json.JSONDecodeError as e:
        print(f"ADD отклонён: JSON не разобран ({e})")
        return 1
    row.setdefault("targets", [])
    row.setdefault("action", "")
    row.setdefault("status", "не использован")
    row.setdefault("cost_min", 0)
    row.setdefault("opened", dt.date.today().isoformat())
    errors, warnings, seen = [], [], {}
    for r in load():
        check_row(r, dt.date.today().isoformat(), errors, warnings, seen)
    before = len(errors)
    check_row(row, dt.date.today().isoformat(), errors, warnings, seen)
    if len(errors) > before:
        print(f"ADD отклонён: запись не проходит проверку ({len(errors) - before} ошибок)")
        return 1
    with open(LIB, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"ADD {row['id']} записан")
    return 0


def _rewrite(rows):
    with open(LIB, "w", encoding="utf-8") as fh:
        for r in rows:
            r.pop("_line", None)
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def cmd_use(args):
    rows = load()
    hit = [r for r in rows if r.get("id") == args.id]
    if not hit:
        print(f"USE: записи {args.id} нет")
        return 1
    r = hit[0]
    if args.target not in (r.get("targets") or []):
        r["targets"] = (r.get("targets") or []) + [args.target]
    r["status"] = "в работе"
    r["opened"] = dt.date.today().isoformat()
    r["action"] = ""
    _rewrite(rows)
    print(f"USE {args.id} -> цель {args.target}, статус «в работе»")
    return cmd_check(args)


def cmd_close(args):
    rows = load()
    hit = [r for r in rows if r.get("id") == args.id]
    if not hit:
        print(f"CLOSE: записи {args.id} нет")
        return 1
    r = hit[0]
    r["status"] = args.action
    r["action"] = args.what
    r["cost_min"] = args.cost
    _rewrite(rows)
    print(f"CLOSE {args.id} статус={args.action} минут={args.cost}")
    return cmd_check(args)


def cmd_scan(_args):
    cov = covered_sections(load())
    for h in scan_lines():
        mark = "есть сверка" if h["section"] and h["section"] in cov else "НЕТ СВЕРКИ"
        if not h["section"]:
            mark = "вне §"
        print(f"{mark} :{h['line']} §{h['section'] or '-'} [{h['trigger']}] {h['text'][:100]}")
    return 0


def _tokens(s):
    return {w for w in re.sub("[^a-z\\u0430-\\u044f\\u04510-9 ]", " ", str(s).lower()).split() if len(w) >= 4}


def cmd_verify(args):
    """Сверка ссылки с источником: id обязан существовать, а название — пересекаться.

    Пойманный живой случай: id, приписанный работе про eclipse-атаки, оказался
    статьёй про мюонный водород. Без этой проверки индекс мог бы хранить цитату,
    которая ни на что не ссылается.
    """
    import urllib.request

    rows = load()
    if args.id:
        rows = [r for r in rows if r.get("id") == args.id]
    checked = matched = mismatched = skipped = net = 0
    for r in rows:
        cite = str(r.get("cite", ""))
        m = re.match(r"^arXiv:(\d{4}\.\d{4,5})", cite)
        if not m:
            skipped += 1
            print(f"  ПРОПУСК {r.get('id')}: «{cite}» — не arXiv-id, сверку делает человек (DOI/Crossref)")
            continue
        url = f"http://export.arxiv.org/api/query?id_list={m.group(1)}"
        try:
            with urllib.request.urlopen(url, timeout=args.timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
        except Exception as e:  # сеть — не доказательство ошибки
            net += 1
            print(f"  СЕТЬ {r.get('id')}: сверка не выполнена ({type(e).__name__})")
            continue
        checked += 1
        titles = re.findall(r"<title>(.*?)</title>", body, re.S)
        got = " ".join(titles[1:2] or titles[:1]).strip()
        want, have = _tokens(r.get("title", "")), _tokens(got)
        overlap = len(want & have) / max(1, min(len(want), len(have)) or 1)
        if overlap >= args.min_overlap:
            matched += 1
            print(f"  СОВПАЛО {r.get('id')} ({overlap:.2f}) -> {got[:80]}")
        else:
            mismatched += 1
            print(f"  НЕ ТА СТАТЬЯ {r.get('id')} ({overlap:.2f}): ждали «{r.get('title','')[:60]}», "
                  f"arXiv отдаёт «{got[:60]}»")
    print(f"СВЕРКА проверено={checked} совпало={matched} не_то={mismatched} "
          f"пропущено={skipped} сеть_недоступна={net}")
    print(f"LIBVERIFY checked={checked} matched={matched} wrong={mismatched} "
          f"skipped={skipped} net_unavailable={net}")
    return 1 if mismatched else 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sub.add_parser("digest")
    sub.add_parser("scan")
    vf = sub.add_parser("verify")
    vf.add_argument("--id")
    vf.add_argument("--timeout", type=float, default=25.0)
    vf.add_argument("--min-overlap", type=float, default=0.34)
    v = sub.add_parser("value")
    v.add_argument("--cycles", type=int, default=VALUE_WINDOW_CYCLES)
    a = sub.add_parser("add")
    a.add_argument("--json", required=True)
    u = sub.add_parser("use")
    u.add_argument("id")
    u.add_argument("--target", required=True)
    c = sub.add_parser("close")
    c.add_argument("id")
    c.add_argument("--action", required=True, choices=("изменено", "не повлияло", "в работе"))
    c.add_argument("--what", required=True)
    c.add_argument("--cost", type=int, default=0)
    args = p.parse_args()
    return {"check": cmd_check, "digest": cmd_digest, "scan": cmd_scan, "value": cmd_value,
            "verify": cmd_verify, "add": cmd_add, "use": cmd_use, "close": cmd_close}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
