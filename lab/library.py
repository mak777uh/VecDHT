#!/usr/bin/env python3
"""Контур источников лаборатории: index.jsonl -> проверка, дайджест, след действия.

Формат записей — `lab/library/index.jsonl`, по одному JSON-объекту на строку.
Смысл файла один: у каждого утверждения, взятого не из нашего замера, есть строка
с ссылкой, датой сверки, глубиной чтения и — обязательно — действием. Инсайт без
действия не считается прочитанным; «прочитал и не повлияло» — тоже действие, но
с причиной.

Команды:
  check                 — машинная проверка индекса (exit 1 при любом нарушении)
  digest                — что не использовано + открытые вопросы спеки без сверки + классы источников
  verify [--id L-NNNN]  — машинная сверка ссылки с источником: для статьи arXiv-id обязан
                          принадлежать заявленному названию, для «реализации» — указанный
                          файл обязан существовать в указанном коммите чужого репозитория
  value [--cycles N]    — счётчики полезности контура и вердикт по заморозенному критерию
  add --json '{...}'    — добавить запись (только валидную)
  use ID --target T     — перевести в «в работе» и привязать к цели
  close ID --action A --what "..."  — закрыть со статусом изменено|не повлияло
  scan                  — триггерные фразы спеки, по которым сверка ещё не сделана

Класс записи («kind»): бумага | спека | реализация. У «реализации» обязательны «ref»
(sha коммита или тег, не ветка) и «path» — файл внутри репозитория, который читали.
"""

import argparse
import datetime as dt
import json
import os
import re
import sys
from urllib.parse import quote

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
# Класс источника (ADR-0048). «бумага» — статья, «спека» — чужой нормативный документ,
# «реализация» — чужой код. Разделение не для красоты: у первых двух проверяется, что id
# принадлежит заявленному названию, у третьего — что файл существует в заявленном коммите.
# Пересказ чужого кода без пина на коммит сверяет не источник, а мою память.
KINDS = ("бумага", "спека", "реализация")
REQUIRED = ("id", "title", "url", "cite", "verified", "depth", "kind", "gives", "targets",
            "status", "action", "cost_min", "opened")
ID_RE = re.compile(r"^L-\d{4}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Пин для класса «реализация»: полный/короткий sha либо имя тега. Ветку не принимаем —
# ветка указывает на код, которого завтра нет, и запись перестаёт быть проверяемой.
GH_REF_RE = re.compile(r"^(?:[0-9a-f]{7,40}|[vV]?\d[\w.\-]*)$")
GITHUB_URL_RE = re.compile(r"^https://github\.com/([\w.\-]+/[\w.\-]+)/")


def utc_today() -> str:
    """Единственная дата контура: сегодня по UTC (`E-0129`, `ADR-0070`).

    Runner'ы GitHub живут в UTC, хост владельца — UTC+3. Пока прибор штамповал и судил по
    местной дате, запись, закрытая между 21:00 и 24:00 по местному, получала дату, которой
    в UTC ещё нет, и шаг `library check` краснил работу `verify` на чужой машине при зелёном
    продукте (наблюдение 2026-10-27: `LIBCHECK records=39 read=39 errors=1`). Один домен для
    записи и для сверки — меньше всего спорно: поле обязано означать одно и то же число и
    здесь, и там.
    """
    return dt.datetime.now(dt.timezone.utc).date().isoformat()

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
    # `_line` есть только у строк, прочитанных из индекса (`load` его подставляет). У записи,
    # которую проверяют до записи на диск (`add`), его нет — и f-string в аргументе `dict.get`
    # вычисляется всегда, поэтому первая же попытка добавить запись роняла механизм с KeyError
    # (ДИАГНОЗ прогона: девять посаженных дефектов не включали «у строки нет `_line`», потому что
    # дефект «нет поля» сажался как пустое `gives`, а не как отсутствующий `id`).
    line = row.get("_line", "новый вход")
    rid = row.get("id") or f"строка {line}"
    if "_error" in row:
        fail(f"{rid}: разобран не как JSON ({row['_error']})", errors)
        return
    for k in REQUIRED:
        if k not in row:
            fail(f"{rid}: нет обязательного поля «{k}»", errors)
    if not ID_RE.match(str(row.get("id", ""))):
        fail(f"{rid}: id вне формата L-NNNN", errors)
    if row.get("id") in seen_ids:
        fail(f"{rid}: id повторяется (строки {seen_ids.get(row.get('id'))} и {line})", errors)
    seen_ids[row.get("id")] = line
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
    # Поля того же домена, что и «verified»: дат в записи теперь три (найдена, использована,
    # закрыта), и судить они обязаны по одному числу — UTC (`E-0129`).
    for k in ("closed", "used"):
        d = str(row.get(k, ""))
        if not d:
            continue
        if not DATE_RE.match(d):
            fail(f"{rid}: поле «{k}» вне формата YYYY-MM-DD", errors)
        elif d > today:
            fail(f"{rid}: дата «{k}» {d} в будущем", errors)
    o = str(row.get("opened", ""))
    # Правила «сверка не раньше находки» здесь НЕТ, хотя оно кажется естественным: шесть
    # исторических строк (L-0001…L-0005, L-0018) читали источник до того, как для него
    # завели запись, и новое правило покраснило бы историю, а не дефект. Порядок «найдено
    # раньше, чем добавлено в индекс» проверяет `lab/check-date-domain.py` — и только для строк,
    # открытых с даты принятия `ADR-0070` и далее, с независимым свидетельством из git.
    # Правило, которое требует переписать прошлое, чтобы стать зелёным, — это не правило, а
    # часы (`E-0129`, ДИАГНОЗ: прибор и механизм рассинхронизировались на 6 находках).
    if DATE_RE.match(o) and DATE_RE.match(str(row.get("closed", ""))) \
            and str(row["closed"]) < o:
        fail(f"{rid}: закрыта {row['closed']} раньше, чем найдена {o}", errors)
    if row.get("depth") not in DEPTHS:
        fail(f"{rid}: глубина «{row.get('depth')}» вне списка {DEPTHS}", errors)
    kind = row.get("kind")
    if kind not in KINDS:
        fail(f"{rid}: класс «{kind}» вне списка {list(KINDS)}", errors)
    elif kind == "реализация":
        # Класс проверяется по трём полям сразу: откуда (url), на какой код (ref), какой файл (path).
        m = GITHUB_URL_RE.match(url)
        if not m:
            fail(f"{rid}: класс «реализация» требует url вида https://github.com/<владелец>/<репозиторий>/…", errors)
        if not str(row.get("ref", "")).strip():
            fail(f"{rid}: класс «реализация» без пина «ref» (sha коммита или тег) — читать нечего", errors)
        elif not GH_REF_RE.match(str(row["ref"])):
            fail(f"{rid}: «ref»={row['ref']!r} не похож на sha или тег (ветка не принимается)", errors)
        if not str(row.get("path", "")).strip():
            fail(f"{rid}: класс «реализация» без «path» — непонятно, какой файл репозитория читали", errors)
    elif GITHUB_URL_RE.match(url):
        # Частный случай того же правила для «спеки»: ссылка на blob/master указывает
        # на файл, который завтра может быть другим, и запись перестаёт быть проверяемой.
        if not str(row.get("ref", "")).strip():
            fail(f"{rid}: ссылка на чужой репозиторий без пина «ref» (sha или тег, не ветка)", errors)
        if not str(row.get("path", "")).strip():
            fail(f"{rid}: ссылка на чужой репозиторий без «path» внутри него", errors)
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
    today = utc_today()
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
    today = utc_today()
    unused = [r for r in rows if r.get("status") == "не использован"]
    open_wip = [r for r in rows if r.get("status") == "в работе"]
    done = [r for r in rows if r.get("status") in ("изменено", "не повлияло")]
    changed = [r for r in rows if r.get("status") == "изменено"]
    print(f"ДАЙДЖЕСТ {today}: всего={len(rows)} не_использовано={len(unused)} "
          f"в_работе={len(open_wip)} закрыто={len(done)} с_действием_изменение={len(changed)}")
    print(f"LIBDIGEST total={len(rows)} unused={len(unused)} wip={len(open_wip)} "
          f"closed={len(done)} changed={len(changed)}")
    # Гистограмма классов. Отдельная строка, а не колонка в LIBDIGEST: формат LIBDIGEST
    # читает оракул E-0089, а «сколько у нас записей про чужой код» — то, чего в индексе
    # до 2026-10-23 не было вовсе (0 из 6), и молчание об этом проще заметить по нулю.
    by_kind = {k: sum(1 for r in rows if r.get("kind") == k) for k in KINDS}
    other = len(rows) - sum(by_kind.values())
    print(f"КЛАССЫ источников: " + " ".join(f"{k}={by_kind[k]}" for k in KINDS)
          + (f" без_класса={other}" if other else ""))
    print(f"LIBCLASSES paper={by_kind['бумага']} spec={by_kind['спека']} "
          f"impl={by_kind['реализация']} unknown={other}")
    if not by_kind["реализация"]:
        print("  ВНИМАНИЕ: ни одной записи о чужой кодовой реализации — решения про приём "
              "кадров, кэш и запреты сверяются только по бумагам и спекам")
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
    row.setdefault("opened", utc_today())
    errors, warnings, seen = [], [], {}
    for r in load():
        check_row(r, utc_today(), errors, warnings, seen)
    before = len(errors)
    check_row(row, utc_today(), errors, warnings, seen)
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
    # `opened` НЕ перезаписывается: это дата, в которую источник найден, и по ней
    # `lab/cycle-gate.py` судит, не найден ли источник уже после формулировки гипотезы
    # (`E-0129`). Прежняя строка `r["opened"] = utc_today()` стирала это доказательствие при
    # каждом переиспользовании и производила ложную находку; переиспользование теперь видно
    # по отдельному полю `used`.
    r["used"] = utc_today()
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
    # Дата закрытия — отдельное поле, а не новая версия `opened` (`E-0129`): иначе «когда
    # источник нашли» и «когда цикл его использовал» нельзя отличить друг от друга даже
    # глазами, и гейт круга судит по стертому следу.
    r["closed"] = utc_today()
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


def _gh_json(url, timeout):
    """Один GET к api.github.com. Возвращает (http_код, разобранный_json_или_None)."""
    import json as _json
    import urllib.request, urllib.error

    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "vecdht-lab-library"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    # сеть — не доказательство ошибки: недоступность фиксируется отдельным счётчиком


def cmd_verify(args):
    """Сверка ссылки с источником: id обязан существовать, а название — пересекаться.

    Пойманный живой случай: id, приписанный работе про eclipse-атаки, оказался
    статьёй про мюонный водород. Без этой проверки индекс мог бы хранить цитату,
    которая ни на что не ссылается.

    Класс «реализация» сверяется другим способом (ADR-0048): не названием, а тем,
    что указанный файл существует в указанном коммите чужого репозитория.
    """
    import urllib.request

    rows = load()
    if args.id:
        rows = [r for r in rows if r.get("id") == args.id]
    checked = matched = mismatched = skipped = net = 0
    ic = im = iw = isk = inet = 0
    def repo_target(r):
        """Ссылка на чужой репозиторий, которую можно сверить машинно: (владелец/репо, ref, path)."""
        if r.get("kind") != "реализация" and not GITHUB_URL_RE.match(str(r.get("url", ""))):
            return None
        m = GITHUB_URL_RE.match(str(r.get("url", "")))
        ref, path = str(r.get("ref", "")), str(r.get("path", ""))
        if not m or not GH_REF_RE.match(ref) or not path:
            return False  # формат негодный — это провал сверки, а не пропуск
        return (m.group(1), ref, path)

    for r in rows:
        cite = str(r.get("cite", ""))
        target = repo_target(r)
        if target is not None:
            ic += 1
            if target is False:
                iw += 1
                print(f"  НЕ ТОТ ПИН {r.get('id')}: url/ref/path не образуют проверяемую ссылку на код "
                      f"(url={str(r.get('url'))[:48]}, ref={str(r.get('ref'))[:16]}, "
                      f"path={str(r.get('path'))[:40]})")
                continue
            owner_repo, ref, path = target
            # `path` — список файлов через запятую (его печатает `sources.py code --paths a,b`),
            # а сверка резала всю строку как один путь и получала 404 на валидной записи: прибор
            # противоречил собственному форматеру, и ловушка выглядела как «кода нет» (ДИАГНОЗ
            # 2026-10-23, первый же прогон `verify` по первому же классу «реализация»).
            files = [p.strip() for p in path.split(",") if p.strip()]
            try:
                code_c, body_c = _gh_json(
                    f"https://api.github.com/repos/{owner_repo}/commits/{ref}", args.timeout)
                codes = []
                for one in files:
                    code_p, _ = _gh_json(
                        f"https://api.github.com/repos/{owner_repo}/contents/"
                        f"{quote(one, safe='')}?ref={quote(ref, safe='')}", args.timeout)
                    codes.append(code_p)
            except Exception as e:
                inet += 1
                print(f"  СЕТЬ {r.get('id')}: сверка кода не выполнена ({type(e).__name__})")
                continue
            if code_c in (404, 422) or any(c in (404, 422) for c in codes):
                iw += 1
                missed = [f for f, c in zip(files, codes) if c in (404, 422)]
                print(f"  НЕТ КОДА {r.get('id')}: {owner_repo} отдаёт commit={code_c} "
                      f"path={','.join(str(c) for c in codes)} (не найдено "
                      f"{ref[:12]}:{','.join(missed)[:44]})")
                continue
            if code_c >= 500 or any(c >= 500 for c in codes) or (body_c is None and code_c != 200):
                inet += 1
                print(f"  СЕТЬ {r.get('id')}: github api ответил {code_c}/{codes}, сверка не выполнена")
                continue
            if code_c == 200 and all(c == 200 for c in codes):
                im += 1
                when = str((body_c or {}).get("commit", {}).get("committer", {}).get("date", "?"))[:10]
                print(f"  ЕСТЬ КОД {r.get('id')}: {owner_repo} {ref[:12]} ({when}) -> "
                      f"{len(files)} файл(ов), {path[:44]}")
            else:
                iw += 1
                print(f"  НЕ ТОТ ПИН {r.get('id')}: commit={code_c} path={codes}")
            continue
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
    # Отдельная строка для класса «реализация»: формат LIBVERIFY выше заморожен оракулом
    # E-0089 и менять его нельзя, а наблюдаемость нового класса нужна.
    print(f"LIBVERIFY_IMPL checked={ic} matched={im} wrong={iw} skipped={isk} net_unavailable={inet}")
    return 1 if (mismatched or iw) else 0


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
