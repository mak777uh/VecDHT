#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Статус-документ как проверяемое утверждение (`H-0143`, второй проход — `H-0147`).

`docs/STATUS-v1.md` читает посторонний, чтобы судить о готовности, — значит каждая его строка про
наличие или отсутствие возможности обязана иметь владельца в дереве. Прибор связывает двенадцать
таких строк с четырьмя видами доказательства: закрытая карточка с вердиктом `supports`, символ в
продукте, файл исполняемого теста и (для правила «у числа в прозе один владелец») имя стража,
который это число печатает.

Второй проход (`H-0147`) добавил восемь строк вне `S-01…S-04`: relay circuit v2 (`E-0145`),
производитель отзыва (`E-0120`), переживаемость `denylist.bin` (`E-0092`) и `revocation.bin`
(`E-0094`), дисковый аудит (`E-0108`), кап ячейки (`E-0088`), конечность таблицы провайдеров
(`E-0091`) и прогон стенда P1 (`E-0105`). Прежний прибор из четырёх строк посаженную ложь в этих
областях пропускал — это и есть названная дыра, а не удобство.

Строка, утверждающая наличие, требует всех доказательств своего класса; строка, утверждающая
отсутствие, — ни одного. Прибор проверяет и в одну, и в другую сторону: документ, который слабее
дерева и документ, который сильнее дерева, — оба находка, и у каждой своё имя причины
(`doc-missing`, `doc-contradicts`, `doc-stale`, `oracle-missing`).

Границы, названные до замера
----------------------------

* Прибор читает **названные формы**, а не смысл: свободный текст («Batch C», «P6») он не понимает,
  поэтому у каждого утверждения перечислены и положительная, и отрицательная форма. Новая
  формулировка обходит прибор так же, как обходила прежняя; это цена дешёвого стража, а не его
  обещание.
* Прибор не доказывает поведение: что `with_centroids` действительно загружает центроиды,
  доказывает `crates/vecdht-cli/tests/node_centroids.rs`, и прибор лишь требует, чтобы файл теста
  существовал и был назван. Красный тест при зелёном приборе возможен — носитель круга прогоняет
  оба теста отдельно и печатает их счёт.
* `--doc` существует затем, чтобы один и тот же прибор судил документ пина (файл из `git show`,
  вне рабочего дерева) и документ после починки на одних и тех же фактах дерева; без него «до» и
  «после» сравнивались бы на одном файле. Корень важен фактам, а не документу: пути владельцев
  относительны корня, и их отсутствие — находка, а не молчание.

Выход: 0 — все четыре строки согласованы с деревом; 1 — хотя бы одна расходится (печатает имена);
2 — документ или корень не читается.

`selftest` строит временное дерево и тридцать семь посаженных случаев: положительный контроль,
каждую из четырёх поломок документа, ослабленную карточку-владельца, пропавший символ, удалённый
тест, ослабленную карточку `S-03`, число в прозе, удалённое имя стража, отсутствующий документ,
пропавшую карточку второго утверждения и по три поломки на каждую из восьми строк второго прохода
(пропавшая фраза, посаженное противоречие, ослабленный владелец — карточка, символ или тест).
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import sys
import tempfile

DOC_DEFAULT = "docs/STATUS-v1.md"


class Claim:
    """Одно утверждение документа и его владельцы в дереве."""

    def __init__(self, cid, title, doc_yes, doc_no, facts):
        self.cid = cid
        self.title = title
        self.doc_yes = doc_yes      # все формы обязаны найтись: так звучит согласованная строка
        self.doc_no = doc_no        # ни одна не имеет права найтись: так звучит расхождение
        self.facts = facts          # [(kind, путь, образец)]


CLAIMS = [
    Claim(
        "S-01",
        "поставляемый бинарник грузит centroid.bin",
        [r"`centroid\.bin` is loaded", r"`E-0121`"],
        [r"does not load centroids"],
        [
            ("card", "lab/experiments/E-0121-*.md", None),
            ("contains", "crates/vecdht-cli/src/node_cmd.rs", r"\.with_centroids\("),
            ("file", "crates/vecdht-cli/tests/node_centroids.rs", None),
            ("contains", "crates/vecdht-cli/tests/node_centroids.rs", r"cluster_reassigned"),
        ],
    ),
    Claim(
        "S-02",
        "есть команда запуска узла: node run",
        [r"`node run` starts a node", r"`E-0119`"],
        [r'there is no "start a node" command', r"`node`[^.]{0,120}is P6"],
        [
            ("card", "lab/experiments/E-0119-*.md", None),
            ("contains", "crates/vecdht-cli/src/node_cmd.rs", r"NODE_READY"),
            ("file", "crates/vecdht-cli/tests/node_run.rs", None),
        ],
    ),
    Claim(
        "S-03",
        "CLI объявляет и фильтрует класс/направление: --class и --intent-dir",
        [r"accepts `--class` and `--intent-dir`", r"`crates/vecdht-cli/src/index_cmd\.rs`",
         r"`E-0144`"],
        [r"there are no CLI flags `--class`"],
        [
            # Владелец строки — карточка круга: флаг без закрытого измерения не доказательство.
            ("card", "lab/experiments/E-0144-*.md", None),
        ],
    ),
    Claim(
        "S-04",
        "счётчики стража цитат не переписаны в прозу",
        [r"check-artifact-refs\.py"],
        [r"\b\d{3,}\b backtick\s+citations?"],
        [
            ("contains", "lab/check-artifact-refs.py", r"REFS_CITED"),
        ],
    ),
    Claim(
        "S-05",
        "relay circuit v2 поднят",
        [r"circuit relay v2 from §16\.3 is up since `E-0145`", r"`Role::Relay` is a server"],
        [r"(?i)circuit relay v2 from §16\.3 is not up"],
        [
            ("card", "lab/experiments/E-0145-*.md", None),
            ("contains", "crates/vecdht-net/src/behaviour.rs", r"relay_server"),
            ("file", "crates/vecdht-net/tests/s163_relay_circuit.rs", None),
            ("contains", "crates/vecdht-net/tests/s163_relay_circuit.rs", r"p2p-circuit"),
        ],
    ),
    Claim(
        "S-06",
        "у отзыва есть производитель: vecdht-cli revoke → publish_revoke",
        [r"(?i)revocation has a producer since `E-0120`", r"`publish_revoke`"],
        [r"(?i)revocation has no producer"],
        [
            ("card", "lab/experiments/E-0120-*.md", None),
            ("contains", "crates/vecdht-cli/src/revoke_cmd.rs", r"publish_revoke"),
            ("file", "crates/vecdht-cli/tests/revoke_publish.rs", None),
        ],
    ),
    Claim(
        "S-07",
        "denylist.bin переживает рестарт и имеет предел",
        [r"`denylist\.bin` in the node directory", r"exactly\s+`18 \+ 32·N` bytes"],
        [r"(?i)the denylist does not survive"],
        [
            ("card", "lab/experiments/E-0092-*.md", None),
            ("contains", "crates/vecdht-node/src/denylist.rs", r"denylist\.bin"),
            ("file", "crates/vecdht-node/tests/denylist_durable_after_restart.rs", None),
        ],
    ),
    Claim(
        "S-08",
        "revocation.bin переживает рестарт и имеет предел",
        [r"`revocation\.bin` in the node directory", r"exactly `18 \+ 16·N` bytes"],
        [r"(?i)revocation does not survive"],
        [
            ("card", "lab/experiments/E-0094-*.md", None),
            ("contains", "crates/vecdht-node/src/revocation.rs", r"revocation\.bin"),
            ("file", "crates/vecdht-net/tests/revocation_durable_after_restart.rs", None),
        ],
    ),
    Claim(
        "S-09",
        "дисковый аудит — исполняемый тест",
        [r"(?i)the audit is an executable test: `E-0108`", r"`s13_disk_privacy`"],
        [r"(?i)the disk audit is not implemented"],
        [
            ("card", "lab/experiments/E-0108-*.md", None),
            ("file", "crates/vecdht-cli/tests/s13_disk_privacy.rs", None),
            ("contains", "crates/vecdht-cli/tests/s13_disk_privacy.rs", r"f32"),
        ],
    ),
    Claim(
        "S-10",
        "кап ячейки стал политикой допуска",
        [r"(?i)the cell cap became an admission policy", r"`max\(4096, ⌈2·live/16⌉\)`"],
        [r"(?i)the cell cap is not enforced"],
        [
            ("card", "lab/experiments/E-0088-*.md", None),
            ("contains", "crates/vecdht-node/src/admission.rs", r"cell_cap"),
            ("file", "crates/vecdht-node/tests/s14_cell_cap_enforced.rs", None),
        ],
    ),
    Claim(
        "S-11",
        "таблица провайдеров шарда конечна",
        [r"(?i)the shard provider table is finite", r"`provider_record_ttl = 420 s`"],
        [r"(?i)the provider table is monotone"],
        [
            ("card", "lab/experiments/E-0091-*.md", None),
            ("contains", "crates/vecdht-net/src/service.rs", r"provider_record_ttl"),
            ("file", "crates/vecdht-net/tests/s74_provider_cache_finite.rs", None),
        ],
    ),
    Claim(
        "S-12",
        "стенд P1 прогнан в release",
        [r"(?i)the stand was run in release: `E-0105`", r"192 cold resolves"],
        [r"(?i)the `P1` stand has not been run"],
        [
            # Строка сообщает о прогоне, а не о пройденном гейте: пре-регистрированный
            # фальсификатор `E-0105` сработал, и карточка закрыта вердиктом `refutes`. Поэтому
            # владелец — закрытая карточка (kind `card-closed`), а не карточка `supports`.
            ("card-closed", "lab/experiments/E-0105-*.md", None),
            ("file", "crates/vecdht-net/tests/s182_p1_scale.rs", None),
            ("contains", "crates/vecdht-net/tests/s182_p1_scale.rs", r"#\[ignore\b"),
        ],
    ),
]


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def card_facts(path):
    """status: closed и verdict: supports из frontmatter карточки."""
    text = read_text(path)
    head = text.split("---", 2)
    body = head[1] if len(head) >= 3 else text[:2000]
    status = re.search(r"^status:\s*(\S+)", body, re.M)
    verdict = re.search(r"^verdict:\s*(\S+)", body, re.M)
    st = status.group(1).strip("\"'") if status else "none"
    vd = verdict.group(1).strip("\"'") if verdict else "none"
    return st, vd


def check_fact(root, kind, rel, pattern):
    """Проверка одного владельца. Возвращает (ok, имя_провала)."""
    if kind == "card":
        hits = sorted(glob.glob(os.path.join(root, rel)))
        if not hits:
            return False, rel + ":нет карточки"
        status, verdict = card_facts(hits[0])
        if status not in ("closed", "completed") or verdict != "supports":
            return False, "%s:%s/%s" % (os.path.basename(hits[0]), status, verdict)
        return True, ""
    if kind == "card-closed":
        # Карточка закрыта любым вердиктом: строка сообщает о прогоне, а не о пройденном гейте.
        hits = sorted(glob.glob(os.path.join(root, rel)))
        if not hits:
            return False, rel + ":нет карточки"
        status, _ = card_facts(hits[0])
        if status not in ("closed", "completed"):
            return False, "%s:%s" % (os.path.basename(hits[0]), status)
        return True, ""
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return False, rel + ":нет файла"
    text = read_text(path)
    if kind == "contains":
        if re.search(pattern, text):
            return True, ""
        return False, rel + ":нет символа"
    if kind == "absent":
        if re.search(pattern, text):
            return False, rel + ":символ есть"
        return True, ""
    if kind == "file":
        return True, ""
    raise ValueError("неизвестный вид факта: " + kind)


def evaluate(root, doc_path):
    """Возвращает (код, строки вывода, факты)."""
    if not os.path.isdir(root):
        return 2, ["STATUS_EXIT=2", "STATUS_DOC=%s" % doc_path, "STATUS_ERROR=корень не каталог"], {}
    if not os.path.isfile(doc_path):
        return 2, ["STATUS_EXIT=2", "STATUS_DOC=%s" % doc_path, "STATUS_ERROR=документ не читается"], {}
    doc = read_text(doc_path)
    lines = []
    facts_total = 0
    facts_ok = 0
    missing = []
    stale = []
    reasons = []
    consistent = 0
    for claim in CLAIMS:
        failures = []
        for kind, rel, pattern in claim.facts:
            facts_total += 1
            ok, why = check_fact(root, kind, rel, pattern)
            if ok:
                facts_ok += 1
            else:
                failures.append(why)
                missing.append(why)
        if failures:
            verdict = "stale"
            reason = "oracle-missing"
        else:
            lack = [p for p in claim.doc_yes if not re.search(p, doc, re.S)]
            contra = [p for p in claim.doc_no if re.search(p, doc, re.S)]
            if lack:
                verdict, reason = "stale", "doc-missing"
            elif contra:
                verdict, reason = "stale", "doc-contradicts"
            else:
                verdict, reason = "consistent", ""
        if verdict == "stale":
            stale.append(claim.cid)
            reasons.append("%s:%s" % (claim.cid, reason))
        else:
            consistent += 1
        lines.append("ПРОВЕРКА %s %s %s %s" % (claim.cid, verdict, reason or "-", claim.title))
        if verdict == "stale" and failures:
            for f in failures:
                lines.append("ПРОВЕРКА %s провал %s" % (claim.cid, f))
        lines.append("STATUS_%s=%s" % (claim.cid.replace("-", ""), verdict))
    code = 1 if stale else 0
    try:
        shown = os.path.relpath(doc_path, root).replace(os.sep, "/")
    except ValueError:
        shown = doc_path.replace(os.sep, "/")
    if shown.startswith(".."):
        shown = doc_path.replace(os.sep, "/")
    out = [
        "STATUS_DOC=%s" % shown,
        "STATUS_CLAIMS=%d" % len(CLAIMS),
        "STATUS_CONSISTENT=%d" % consistent,
        "STATUS_STALE=%d" % len(stale),
        "STATUS_STALE_IDS=%s" % (",".join(stale) if stale else "none"),
        "STATUS_STALE_REASONS=%s" % (",".join(reasons) if reasons else "none"),
        "STATUS_FACTS=%d" % facts_total,
        "STATUS_FACTS_OK=%d" % facts_ok,
        "STATUS_FACTS_MISSING=%s" % (",".join(missing) if missing else "none"),
        "STATUS_OK=%d" % (1 if code == 0 else 0),
        "STATUS_EXIT=%d" % code,
    ]
    return code, lines + out, {"stale": stale, "facts": facts_total, "ok": facts_ok}


# --- самопроверка -------------------------------------------------------------------------

CLEAN_DOC = """# Status

The signing ceremony is a command (`E-0118`), `node run` starts a node from those files and
`centroid.bin` is loaded and `cluster_id` recomputed by the shipped binary (`E-0121`,
`E-0119`).

* paid intents: the CLI accepts `--class` and `--intent-dir` (`crates/vecdht-cli/src/index_cmd.rs`,
  `E-0144`), and there is no settlement.
* M6 guards — `lab/check-secrets.sh` and `lab/check-artifact-refs.py`; the guard prints its own
  counts, a stale allowance is a finding.
* The circuit relay v2 from §16.3 is up since `E-0145` (`Role::Relay` is a server, any role is a
  client).
* Revocation has a producer since `E-0120` (`vecdht-cli revoke` → `publish_revoke` over the control
  topic).
* `denylist.bin` in the node directory, exactly `18 + 32·N` bytes.
* `revocation.bin` in the node directory, exactly `18 + 16·N` bytes.
* The audit is an executable test: `E-0108` (`s13_disk_privacy`).
* The cell cap became an admission policy at `max(4096, ⌈2·live/16⌉)`.
* The shard provider table is finite; `provider_record_ttl = 420 s`.
* The stand was run in release: `E-0105` — 192 cold resolves.
"""


def build_tree(root):
    def put(rel, text):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    put("docs/STATUS-v1.md", CLEAN_DOC)
    put("lab/experiments/E-0121-a2.md", "---\nid: E-0121\nstatus: closed\nverdict: supports\n---\n# E\n")
    put("lab/experiments/E-0119-a1.md", "---\nid: E-0119\nstatus: closed\nverdict: supports\n---\n# E\n")
    put("crates/vecdht-cli/src/node_cmd.rs",
        "fn run() { let node = node.with_centroids(arc); }\nprintln!(\"NODE_READY listen=…\");\n")
    put("crates/vecdht-cli/tests/node_centroids.rs", "#[test] fn reassign() { cluster_reassigned(); }\n")
    put("crates/vecdht-cli/tests/node_run.rs", "#[test] fn ready() { NODE_READY(); }\n")
    put("lab/experiments/E-0144-a3.md", "---\nid: E-0144\nstatus: closed\nverdict: supports\n---\n# E\n")
    put("lab/check-artifact-refs.py", "REFS_CITED=1580\n")
    for cid in ("E-0145", "E-0120", "E-0092", "E-0094", "E-0108", "E-0088", "E-0091"):
        put("lab/experiments/%s-a.md" % cid,
            "---\nid: %s\nstatus: closed\nverdict: supports\n---\n# E\n" % cid)
    # `E-0105` закрыта `refutes`: фальсификатор стенда сработал, и строка `S-12` сообщает о
    # прогоне, а не о пройденном гейте — поэтому её владелец проверяется как закрытая карточка.
    put("lab/experiments/E-0105-a.md",
        "---\nid: E-0105\nstatus: completed\nverdict: refutes\n---\n# E\n")
    put("crates/vecdht-net/src/behaviour.rs", "fn build() { relay_server(); }\n")
    put("crates/vecdht-net/tests/s163_relay_circuit.rs",
        "#[test] fn circuit() { listen(\"/p2p/x/p2p-circuit/p2p/y\"); }\n")
    put("crates/vecdht-cli/src/revoke_cmd.rs", "fn revoke() { publish_revoke(&cert); }\n")
    put("crates/vecdht-cli/tests/revoke_publish.rs", "#[test] fn spreads() {}\n")
    put("crates/vecdht-node/src/denylist.rs", "const FILE: &str = \"denylist.bin\";\n")
    put("crates/vecdht-node/tests/denylist_durable_after_restart.rs", "#[test] fn durable() {}\n")
    put("crates/vecdht-node/src/revocation.rs", "const FILE: &str = \"revocation.bin\";\n")
    put("crates/vecdht-net/tests/revocation_durable_after_restart.rs", "#[test] fn durable() {}\n")
    put("crates/vecdht-cli/tests/s13_disk_privacy.rs", "#[test] fn scan() { no_f32_blocks(); }\n")
    put("crates/vecdht-node/src/admission.rs", "fn cap() { let cell_cap = max(4096, n); }\n")
    put("crates/vecdht-node/tests/s14_cell_cap_enforced.rs", "#[test] fn refused() {}\n")
    put("crates/vecdht-net/src/service.rs", "const TTL: u64 = provider_record_ttl;\n")
    put("crates/vecdht-net/tests/s74_provider_cache_finite.rs", "#[test] fn bounded() {}\n")
    put("crates/vecdht-net/tests/s182_p1_scale.rs", "#[test] #[ignore] fn stand() {}\n")


def selftest():
    base = tempfile.mkdtemp(prefix="status-claims-")
    cases = []

    def case(name, mutate, expect_stale, expect_exit):
        root = os.path.join(base, name)
        shutil.copytree(base + "/seed", root)
        mutate(root)
        code, out, _ = evaluate(root, os.path.join(root, DOC_DEFAULT))
        text = "\n".join(out)
        got = re.search(r"^STATUS_STALE_IDS=(.*)$", text, re.M)
        got = got.group(1) if got else "none"
        want = ",".join(expect_stale) if expect_stale else "none"
        ok = code == expect_exit and (expect_exit == 2 or got == want)
        cases.append((name, ok))
        if not ok:
            print("СЕЛФТЕСТ_СЛУЧАЙ %s FAIL код=%d ids=%s ожидалось код=%d ids=%s"
                  % (name, code, got, expect_exit, want))

    def doc(root):
        return os.path.join(root, DOC_DEFAULT)

    def append(text):
        def _m(root):
            with open(doc(root), "a", encoding="utf-8") as fh:
                fh.write(text)
        return _m

    def drop(pattern):
        def _m(root):
            t = read_text(doc(root))
            t2 = re.sub(pattern, "", t)
            assert t2 != t, "посадка не изменила документ: " + pattern
            with open(doc(root), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(t2)
        return _m

    def edit(rel, old, new):
        def _m(root):
            p = os.path.join(root, rel)
            t = read_text(p)
            assert old in t, "посадка не нашла строку " + old
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(t.replace(old, new, 1))
        return _m

    def remove(rel):
        def _m(root):
            os.remove(os.path.join(root, rel))
        return _m

    def missing_doc(root):
        os.remove(doc(root))

    clean = os.path.join(base, "seed")
    build_tree(clean)

    case("clean", lambda r: None, [], 0)
    case("doc-contradicts-centroids",
         append("\nThe shipping binary does not load centroids yet.\n"), ["S-01"], 1)
    case("doc-missing-centroids", drop(r"`centroid\.bin` is loaded"), ["S-01"], 1)
    case("doc-contradicts-node",
         append('\nThere is no "start a node" command; `node` is P6.\n'), ["S-02"], 1)
    case("doc-missing-node", drop(r"`node run` starts a node"), ["S-02"], 1)
    case("card-weakened",
         edit("lab/experiments/E-0121-a2.md", "verdict: supports", "verdict: refutes"), ["S-01"], 1)
    case("symbol-gone",
         edit("crates/vecdht-cli/src/node_cmd.rs", ".with_centroids(", ".without_centroids("), ["S-01"], 1)
    case("test-gone", remove("crates/vecdht-cli/tests/node_centroids.rs"), ["S-01"], 1)
    case("filter-card-pending",
         edit("lab/experiments/E-0144-a3.md", "verdict: supports", "verdict: pending"), ["S-03"], 1)
    case("prose-number",
         append("\nThe guard checks 1333 backtick citations.\n"), ["S-04"], 1)
    case("guard-unnamed", drop(r"check-artifact-refs\.py"), ["S-04"], 1)
    case("card-node-gone", remove("lab/experiments/E-0119-a1.md"), ["S-02"], 1)
    case("doc-absent", missing_doc, [], 2)

    # --- второй проход (`H-0147`): по три поломки на каждую из восьми новых строк ---------------
    case("relay-doc-missing",
         drop(r"circuit relay v2 from §16\.3 is up since `E-0145`"), ["S-05"], 1)
    case("relay-doc-contradicts",
         append("\nThe circuit relay v2 from §16.3 is not up yet.\n"), ["S-05"], 1)
    case("relay-symbol-gone",
         edit("crates/vecdht-net/src/behaviour.rs", "relay_server", "relay_off"), ["S-05"], 1)
    case("revoke-doc-missing",
         drop(r"evocation has a producer since `E-0120`"), ["S-06"], 1)
    case("revoke-doc-contradicts",
         append("\nRevocation has no producer.\n"), ["S-06"], 1)
    case("revoke-card-weakened",
         edit("lab/experiments/E-0120-a.md", "verdict: supports", "verdict: refutes"), ["S-06"], 1)
    case("denylist-doc-missing",
         drop(r"`denylist\.bin` in the node directory"), ["S-07"], 1)
    case("denylist-doc-contradicts",
         append("\nThe denylist does not survive a restart.\n"), ["S-07"], 1)
    case("denylist-test-gone",
         remove("crates/vecdht-node/tests/denylist_durable_after_restart.rs"), ["S-07"], 1)
    case("revocation-doc-missing",
         drop(r"exactly `18 \+ 16·N` bytes"), ["S-08"], 1)
    case("revocation-doc-contradicts",
         append("\nRevocation does not survive a restart.\n"), ["S-08"], 1)
    case("revocation-symbol-gone",
         edit("crates/vecdht-node/src/revocation.rs", "revocation.bin", "rvoc.bin"),
         ["S-08"], 1)
    case("privacy-doc-missing",
         drop(r"he audit is an executable test: `E-0108`"), ["S-09"], 1)
    case("privacy-doc-contradicts",
         append("\nThe disk audit is not implemented.\n"), ["S-09"], 1)
    case("privacy-card-weakened",
         edit("lab/experiments/E-0108-a.md", "verdict: supports", "verdict: pending"), ["S-09"], 1)
    case("cap-doc-missing",
         drop(r"he cell cap became an admission policy"), ["S-10"], 1)
    case("cap-doc-contradicts",
         append("\nThe cell cap is not enforced.\n"), ["S-10"], 1)
    case("cap-test-gone",
         remove("crates/vecdht-node/tests/s14_cell_cap_enforced.rs"), ["S-10"], 1)
    case("provider-doc-missing",
         drop(r"he shard provider table is finite"), ["S-11"], 1)
    case("provider-doc-contradicts",
         append("\nThe provider table is monotone.\n"), ["S-11"], 1)
    case("provider-symbol-gone",
         edit("crates/vecdht-net/src/service.rs", "provider_record_ttl", "prv_ttl"),
         ["S-11"], 1)
    case("p1-doc-missing",
         drop(r"he stand was run in release: `E-0105`"), ["S-12"], 1)
    case("p1-doc-contradicts",
         append("\nThe `P1` stand has not been run.\n"), ["S-12"], 1)
    case("p1-card-gone", remove("lab/experiments/E-0105-a.md"), ["S-12"], 1)

    total = len(cases)
    passed = sum(1 for _, ok in cases if ok)
    for name, ok in cases:
        print("СЕЛФТЕСТ_СЛУЧАЙ %s %s" % (name, "OK" if ok else "FAIL"))
    print("СЕЛФТЕСТ_ИТОГ total=%d passed=%d failed=%d" % (total, passed, total - passed))
    shutil.rmtree(base, ignore_errors=True)
    return 0 if passed == total else 1


def main(argv):
    ap = argparse.ArgumentParser(description="статус-документ против дерева (H-0143)")
    ap.add_argument("mode", nargs="?", default="check", choices=("check", "selftest"))
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--doc", default=None)
    ns = ap.parse_args(argv)
    if ns.mode == "selftest":
        return selftest()
    root = os.path.abspath(ns.root)
    doc = os.path.abspath(ns.doc) if ns.doc else os.path.join(root, DOC_DEFAULT)
    code, out, _ = evaluate(root, doc)
    print("\n".join(out))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
