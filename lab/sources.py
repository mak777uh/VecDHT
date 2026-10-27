#!/usr/bin/env python3
"""Поиск источников по боли — шаг круга «литература и чужой код до эксперимента».

Зачем. До 2026-10-23 индекс пополнялся тогда, когда агент сам вспоминал поискать, а класс
«чужая кодовая реализация» не появился в нём ни разу: мы решали боль (дверь приёма кадров,
конечность кэшей, переживаемость запрета), у которой заведомо есть решённые в коде аналоги,
и не смотрели, как они сделаны. Этот инструмент превращает «посмотреть» в команду, а решение
«что из найденного годится» оставляет агенту: `gives` заполняется руками, и `add` не примет
строку с пустым `gives` — то есть прочитанное обязано быть сформулировано.

Команды:
  python lab/sources.py hunt "ban list persistence restart" [--github] [--paths banman.cpp,banlist.dat]
  python lab/sources.py arxiv "vector database poisoning attack" -n 8
  python lab/sources.py code "bitcoin/bitcoin" --paths src/banman.cpp   # пин + проверка файла

Черновик строки индекса печатается одной JSON-строкой; переносится в индекс только через
`python lab/library.py add --json '...'`, который проверяет схему.
"""

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# Одна дата на весь контур: UTC (`E-0129`). Черновик, датированный местным вечером хоста
# UTC+3, приходит на runner (он в UTC) с датой «завтра», и `library check` краснит работу
# `verify` при зелёном продукте. Ищем функцию в `lab/library.py`: скрипт запускают как
# `python lab/sources.py`, поэтому каталог `lab/` уже в sys.path[0].
from library import utc_today  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

UA = "vecdht-lab-sources"
BUDGET_MIN = 30  # тот же бюджет шага сверки, что в lab/library.py


def get(url, timeout=25.0):
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                              "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def gh_json(url, timeout=25.0):
    try:
        code, body = get(url, timeout)
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:
        return None, e.__class__.__name__
    if code is None:
        return None, body
    try:
        return code, json.loads(body)
    except Exception:
        return code, None


def draft(title, url, cite, kind, depth, note, **extra):
    today = utc_today()
    row = {"id": "L-NNNN", "title": title, "url": url, "cite": cite, "verified": today,
           "depth": depth, "kind": kind, "gives": note, "targets": [],
           "status": "не использован", "action": "", "cost_min": 0, "opened": today}
    row.update(extra)
    return row


def arxiv_query(terms):
    # `terms` — одна строка, а не список: обход её как `for w in args.terms` давал посимвольный
    # запрос (`I P   b l o c k...`), на который arXiv отвечал физикой и квериками. Инструмент
    # выглядел работающим и при этом гарантировал «в литературе ничего нет» (ДИАГНОЗ 2026-10-23).
    # Слово берётся как есть; точная фраза — через `--query`.
    return "all:" + " ".join(w for w in terms.split() if w)


def cmd_arxiv(args):
    q = arxiv_query(args.terms) if not args.query else args.query
    url = ("http://export.arxiv.org/api/query?search_query=" + urllib.parse.quote(q) +
           f"&start=0&max_results={args.n}")
    try:
        code, body = get(url, args.timeout)
    except Exception as e:
        print(f"СЕТЬ: arXiv не отвечает ({type(e).__name__}) — класс «бумага» сегодня недоступен")
        return 2
    entries = re.findall(r"<entry>(.*?)</entry>", body, re.S)
    print(f"ARXIV запрос={q!r} ответов={len(entries)}")
    for e in entries:
        t = re.search(r"<title>(.*?)</title>", e, re.S)
        i = re.search(r"<id>(.*?)</id>", e, re.S)
        s = re.search(r"<summary>(.*?)</summary>", e, re.S)
        title = re.sub(r"\s+", " ", t.group(1)).strip() if t else "?"
        link = i.group(1).strip() if i else "?"
        m = re.search(r"(\d{4}\.\d{4,5})", link)
        abstract = re.sub(r"\s+", " ", s.group(1)).strip()[:220] if s else ""
        print(json.dumps(draft(title, "https://arxiv.org/abs/" + (m.group(1) if m else ""),
                               "arXiv:" + (m.group(1) if m else ""), "бумага", "аннотация",
                               abstract), ensure_ascii=False))
    return 0


def cmd_hunt(args):
    """Один вызов на оба класса: статьи + репозитории (+ опционально проверка файлов)."""
    rc = 0
    if not args.github_only:
        rc = max(rc, cmd_arxiv(args))
    if args.github or args.github_only:
        rc = max(rc, cmd_code(args))
    print(f"БЮДЖЕТ: шаг сверки <= {BUDGET_MIN} мин; черновик без заполненного `gives` "
          f"в индекс не попадёт (`library.py add` его отклонит)")
    return rc


def cmd_code(args):
    if "/" in args.terms.replace(" ", "") and args.pinned:
        repos = [args.terms.replace(" ", "")]
    elif args.repo:
        repos = [args.repo]
    else:
        url = ("https://api.github.com/search/repositories?q=" +
               urllib.parse.quote(args.terms) + f"&per_page={min(args.n, 10)}")
        code, body = gh_json(url, args.timeout)
        if code is None:
            print(f"СЕТЬ: github не отвечает ({body}) — класс «реализация» сегодня недоступен")
            return 2
        if code != 200:
            print(f"GITHUB поиск отдал HTTP {code}")
            return 2
        items = (body or {}).get("items", [])
        print(f"GITHUB запрос={args.terms!r} репозиториев={len(items)}")
        repos = [i["full_name"] for i in items]
    paths = [p.strip() for p in (args.paths or "").split(",") if p.strip()]
    for repo in repos:
        c1, head = gh_json(f"https://api.github.com/repos/{repo}", args.timeout)
        if c1 == 403 or c1 == 429:
            print(f"  ЛИМИТ: github отдаёт {c1} на анонимные запросы — подождать час или "
                  f"искать через `--repo` с уже известным полным именем")
            return 2
        if c1 != 200 or not head:
            print(f"  РЕПО {repo}: HTTP {c1} — полный вид `владелец/репозиторий` не найден")
            continue
        branch = head.get("default_branch", "master")
        c2, commit = gh_json(f"https://api.github.com/repos/{repo}/commits/{branch}",
                             args.timeout)
        sha = (commit or {}).get("sha", "") if c2 == 200 else ""
        line = f"  РЕПО {repo} ветка={branch} пин={sha[:12]} звёзды={head.get('stargazers_count')}"
        found = []
        for p in paths:
            c3, _ = gh_json(f"https://api.github.com/repos/{repo}/contents/{urllib.parse.quote(p, safe='')}"
                            f"?ref={urllib.parse.quote(sha or branch, safe='')}", args.timeout)
            found.append(f"{p}:{c3}")
        print(line + (" файлы=" + " ".join(found) if found else ""))
        if not sha:
            continue
        # Черновик обязан сам проходить схему `library.py check`: класс «реализация» требует
        # `ref` и `path`, и до 2026-10-23 инструмент печатал строку, которую его же `add`
        # отклонял — агенту приходилось дописывать пин руками по памяти о выводе выше.
        print(json.dumps(draft(f"{repo} ({branch} @ {sha[:12]})",
                               f"https://github.com/{repo}/", f"github:{repo}@{sha[:12]}",
                               "реализация", "аннотация",
                               args.gives or "<что именно даёт этот код нашему решению>",
                               ref=sha, path=",".join(paths) if paths
                               else "<какой файл этого репозитория читали>"),
                         ensure_ascii=False))
    return 0


def cmd_selftest(args):
    """Офлайновая проверка самого инструмента: запрос, черновик, схема.

    Смысл в том, чтобы посимвольный запрос и черновик без пина ловились здесь, а не в
    рабочем круге: у обоих дефектов внешний вид был «инструмент отработал».
    """
    ok = True

    def chk(name, cond, detail=""):
        nonlocal ok
        print(("ХОРОШО " if cond else "ПЛОХО ") + name + (f" — {detail}" if detail else ""))
        ok = ok and cond

    q = arxiv_query("blocklist churn ban expiry")
    chk("запрос arXiv собирается по словам", q == "all:blocklist churn ban expiry", f"q={q!r}")
    chk("в запросе нет посимвольной нарезки", " b l " not in q and "l o c k" not in q, f"q={q!r}")
    row = draft("t", "https://github.com/a/b/", "github:a/b@0123456789ab", "реализация",
                "текст выборочно", "g", ref="0123456789abcdef0123456789abcdef01234567",
                path="src/x.cpp")
    need = ("id", "title", "url", "cite", "verified", "depth", "kind", "gives", "targets",
            "status", "action", "cost_min", "opened")
    chk("черновик реализации содержит все поля схемы", all(k in row for k in need),
        "нет " + ",".join(k for k in need if k not in row))
    chk("черновик реализации несёт пин и файл", bool(row.get("ref")) and bool(row.get("path")),
        f"ref={row.get('ref', '')[:12]!r} path={row.get('path')!r}")
    chk("черновик без пина не годится", "ref" not in draft("t", "https://github.com/a/b/",
        "c", "реализация", "аннотация", "g"))
    print(f"SOURCES_SELFTEST {'OK' if ok else 'FAIL'}")
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # `-n` и `--timeout` живут в общем родителе: только на верхнем уровне их не передать после
    # подкоманды, а именно так их показывал докстринг инструмента (ДИАГНОЗ 2026-10-23).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--timeout", type=float, default=25.0)
    common.add_argument("-n", type=int, default=6)
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hunt", parents=[common])
    h.add_argument("terms")
    h.add_argument("--github", action="store_true")
    h.add_argument("--github-only", action="store_true")
    h.add_argument("--paths", default="")
    h.add_argument("--repo", default="")
    h.add_argument("--query", default="")
    h.add_argument("--gives", default="")
    a = sub.add_parser("arxiv", parents=[common])
    a.add_argument("terms")
    a.add_argument("--query", default="")
    c = sub.add_parser("code", parents=[common])
    c.add_argument("terms")
    c.add_argument("--paths", default="")
    c.add_argument("--pinned", action="store_true")
    c.add_argument("--repo", default="")
    c.add_argument("--gives", default="")
    s = sub.add_parser("selftest", parents=[common])
    args = p.parse_args()
    args.timeout = getattr(args, "timeout", 25.0)
    if args.cmd == "hunt":
        return cmd_hunt(args)
    if args.cmd == "arxiv":
        return cmd_arxiv(args)
    if args.cmd == "selftest":
        return cmd_selftest(args)
    return cmd_code(args)


if __name__ == "__main__":
    sys.exit(main())
