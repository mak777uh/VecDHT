#!/usr/bin/env python3
"""repo-review.py — самопроверка репозитория после цикла (слово владельца 2026-10-24).

Что делает: проходит по всему дереву и ищет слабые подходы, которые уже случались в этом
репозитории, а не «вообще плохие практики»:

  stale-refs            ссылка `путь:строка` в документе указывает за конец файла;
  refs-pin-malformed    ссылка вида `путь@пин:строка`, где пин не похож на hex-хеш коммита;
  promise-double-definition один открытый пункт (`OPEN-V9-NN`) описан строкой списка в двух файлах;
  spec-code-line-citation нормативная спека (`docs/VecDHT-SPEC-v*.md`) ссылается на код номером
                        строки — форма, запрещённая §17.3 (`путь.rs:NN` и голое `:NNN`);
  closed-empty-result   карточка закрыта, а результата в ней нет (или остался заголовок-пустышка);
  testing-closed        гипотеза `testing`, а её эксперимент уже вынес вердикт;
  ignored-no-reason     `#[ignore]` без причины: отключённый тест без объяснения — это тишина;
  expect-orphans        таблица ожиданий без helper'а или карточки эксперимента;
  helper-orphans        helper цикла не назван в своей карточке (воспроизвести прогон нечем);
  missing-experiments   карточка гипотезы ссылается на несуществующий эксперимент;
  refs-dangling         поименованный дескриптор (`H-XXXX`, `E-XXXX`, `ADR-XXXX`, `L-XXXX`)
                        в tracked `.md` не разрешается ни в один артефакт (класс печатается
                        отдельной строкой `РАЗРЫВ`, в `REVIEW_FINDINGS` НЕ входит — см. ниже).

Плюс инвентарь без вердикта: размеры больших `.rs`, число `TODO/FIXME`, число `#[ignore]`.
Вывод детерминирован: `REVIEW_*`-факты и строки `НАХОДКА <класс>: <путь> — <причина>`.
`selftest` строит временное дерево с посаженными дефектами каждого класса и чистый контроль.

Про две формы ссылок на строку. `путь:строка` — ЖИВОЙ указатель: он обязан указывать в файл,
который существует сейчас, и на строку, которая в нём есть. `путь@пин:строка` — ИСТОРИЧЕСКИЙ
указатель: номер строки снят с дерева `пин`, а не с HEAD, поэтому сверять его с текущим файлом
бессмысленно (так устроены аудиторские срезы: `lab/notes/AUDIT-2026-10-25-repo-spec-readme.md`
цитирует README до переписки, а переписка сдвинула все номера). Цена формы: страж не проверяет,
что под историческим именем вообще лежал файл, — ловится только битый пин и только тем, что пин
назван. Число исторических ссылок печатается фактом `REVIEW_REFS_PINNED`, чтобы молчание не
выглядело проверкой.

Про разрешимость имён (находка 5 аудита 2026-10-25, `lab/notes/AUDIT-2026-10-25-repo-spec-readme.md`).
Дескриптор считается разрешённым, если под ним лежит файл: `lab/hypotheses/H-XXXX[-slug].md`,
`lab/experiments/E-XXXX[-slug].md`, `lab/decisions/ADR-XXXX[-slug].md`, запись `L-XXXX` в
`lab/library/index.jsonl`. Неразрешённый дескриптор — находка класса `refs-dangling`, она печатается
строкой `РАЗРЫВ …` и делает выход ненулевым. Исключение — явный и версионируемый список
`lab/ref-allow-list.txt`: номер, зарезервированный в очереди (`ADR-0039`…`ADR-0041`, кандидаты
`OPEN-QUESTIONS`), пропущенный намеренно (`E-0014`) или посаженный для самопроверки (`L-9001`),
обязан стоять там с ПРИЧИНОЙ; без причины запись списка ничего не разрешает.

Счётчики разрешимости — ОТДЕЛЬНЫЕ ключи (`REVIEW_REFS_UNRESOLVED_ALLOWED`,
`REVIEW_REFS_UNRESOLVED_VIOLATIONS`, `REVIEW_ID_*`), а `REVIEW_FINDINGS`, `REVIEW_REFS_UNRESOLVED`,
`REVIEW_TOP` и остальные ключи, замороженные в `lab/expectations/*.tsv` закрытых циклов, печатают
ровно то же, что печатали до этой правки: закрытый цикл обязан пере-проверяться прежним числом.

Запуск: python lab/repo-review.py [check|selftest|refselftest] [--root ПУТЬ]
Список разрешений по умолчанию берётся из проверяемого дерева; для прогона по чужому дереву
(архив старого коммита) можно задать файл переменной окружения `VEC_DHT_REF_ALLOW_LIST`.
"""
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SKIP_DIRS = {"target", ".git", "node_modules", "__pycache__"}
CLOSED_STATUS = {"supported", "refuted", "satisfies", "closed"}
BIG_RS_LINES = 1500
RESULT_MIN = 80
RESULT_HEADINGS = re.compile(r"^##\s+(Результат|Итог)\b", re.M | re.I)
HEADING_ANY = re.compile(r"^##\s+", re.M)
REF = re.compile(r"(?<![\w/.:-])([A-Za-z0-9_][A-Za-z0-9_./\\-]*\.(?:rs|py|sh|md|toml|jsonl|tsv|lean)):(\d+)")
# Историческая ссылка `путь@пин:строка`. `@` не входит в класс символов пути у `REF`, поэтому
# живая регулярная схема её не матчит и двойного счёта нет; проверка пина отделена.
REF_PIN = re.compile(r"(?<![\w/.:-])([A-Za-z0-9_][A-Za-z0-9_./\\-]*\.(?:rs|py|sh|md|toml|jsonl|tsv|lean))"
                     r"@([0-9A-Za-z_-]+):(\d+)")
PIN_HEX = re.compile(r"^[0-9a-f]{7,40}$")

# Определение открытого пункта: строка списка, где за id стоит тире и описание
# (`- **`OPEN-V9-11`** — published → expired по часам …`). Формат с `**` и без него равноправен.
PROMISE_DEF = re.compile(r"^\s*[-*+]\s+(?:\*\*)?\s*`?(OPEN-[A-Z0-9]+-\d+)`?\s*(?:\*\*)?\s*—", re.M)

# Нормативная спека не имеет права ссылаться на код номером строки (§17.3 `docs/VecDHT-SPEC-v8.md`).
# Две формы: `путь.rs:NN` (файл назван) и голое продолжение абзаца — код-спан `:NNN`, где файла нет.
# Первая снимается вместе с пином (`\.rs@`), иначе запрещённый жанр стал бы ещё и нечитаемым;
# вторая обязана стоять в код-спане, иначе под запрет попадёт любое «14:30» в прозе.
SPEC_DOC = re.compile(r"(^|[\\/])VecDHT-SPEC-v[0-9]+\.md$")
SPEC_LINE_REF = re.compile(r"\.rs(?![0-9A-Za-z]):[0-9]")
SPEC_LINE_SPAN = re.compile(r"`:[0-9]{2,5}")

# Дескриптор артефакта лаборатории: H-/E-/ADR-/L- плюс ровно четыре цифры и необязательная
# строчная буква-хвост (`H-0088b` — отдельный адрес, а не `H-0088`). Дефис после цифр означает
# имя файла (`ADR-0044-release-queue…md`), поэтому хвостом считается только [a-z].
DESCRIPTOR = re.compile(r"(?<![\w:./-])((?:ADR|[HEL])-\d{4})([a-z]?)")
DESCRIPTOR_ID = re.compile(r"^(?:ADR|[HEL])-\d{4}[a-z]?$")
ALLOW_LIST = os.path.join("lab", "ref-allow-list.txt")
ALLOW_LIST_ENV = "VEC_DHT_REF_ALLOW_LIST"
# Артефакт, которым разрешается дескриптор: каталог, маска файла и (для L-) индекс источников.
ID_DIRS = {
    "H": ("lab", "hypotheses"),
    "E": ("lab", "experiments"),
    "ADR": ("lab", "decisions"),
}


def read(path):
    try:
        return io.open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def walk(root, suffix):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(suffix):
                out.append(os.path.join(dirpath, name))
    return sorted(out)


def rel(root, path):
    return os.path.relpath(path, root).replace("\\", "/")


def front_matter(path):
    text = read(path)
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    head = text[3:end]
    body = text[end + 4:]
    data = {}
    for line in head.splitlines():
        m = re.match(r"^([a-z_]+):\s*(.*)$", line)
        if m:
            data[m.group(1)] = m.group(2).strip()
    return data, body


def section_text(body, pattern):
    m = pattern.search(body)
    if not m:
        return None
    rest = body[m.end():]
    nxt = HEADING_ANY.search(rest)
    return rest[:nxt.start()] if nxt else rest


def line_count(path):
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return -1


def check_refs(root):
    stale, ok, unresolved = [], 0, 0
    pinned, bad_pin = 0, []
    hits_cache = {}
    for path in walk(root, ".md"):
        text = read(path)
        for m in REF_PIN.finditer(text):
            ref, pin = m.group(1), m.group(2)
            pinned += 1
            if not PIN_HEX.match(pin):
                bad_pin.append((rel(root, path), "%s@%s:%s" % (ref, pin, m.group(3)),
                                "пин `%s` не похож на hex-хеш коммита (7–40)" % pin))
        for m in REF.finditer(text):
            ref, line_no = m.group(1), int(m.group(2))
            target = ref if os.path.isfile(os.path.join(root, ref)) else None
            if target is None:
                base = os.path.basename(ref)
                if base not in hits_cache:
                    # Кэш по имени: обход `**` для одного и того же basename повторялся десятки раз
                    # и превращал `check` в двухминутный прибор (мера — по `time` на хосте владельца).
                    hits_cache[base] = [p for p in glob.glob(os.path.join(root, "**", base), recursive=True)
                                        if os.path.isfile(p) and not any(s in p.split(os.sep) for s in SKIP_DIRS)]
                hits = hits_cache[base]
                if len(hits) == 1:
                    target = hits[0]
                else:
                    unresolved += 1
                    continue
            total = line_count(target)
            if total >= 0 and line_no > total:
                stale.append((rel(root, path), ref, line_no, total))
            else:
                ok += 1
    return ok, stale, unresolved, pinned, bad_pin


def check_spec_citations(root):
    """Нормативная спека ссылается на код именем символа, а не номером строки (§17.3). Класс
    родился из замера: в срезе `docs/VecDHT-SPEC-v8.md` до правки было 20 ссылок с номером строки,
    16 из них указывали мимо объекта, который называли (разброс — от трёх строк до 166), и при этом
    `REVIEW_REFS_STALE` был нулём — существующий прибор их не видел, потому что номер не вылезал за
    конец файла. Проверка «номер совпал с тем, что он называл» не реализуема без парсера Rust, зато
    запрет формы реализуем: в файле спеки номера строк продукта не встречается.

    Снимаются обе формы: `путь.rs:NN` (файл назван) и голое продолжение абзаца — код-спан `:NNN`.
    Пин `путь@коммит:строка` под запрет не попадает: снимок обязан его ставить, и требовать символ
    в аудитном срезе — значит заставлять его врать про чужое дерево."""
    hits = []
    for path in tracked_markdown(root)[0]:
        relp = rel(root, path).replace("\\", "/")
        if not SPEC_DOC.search(relp):
            continue
        text = read(path)
        for m in SPEC_LINE_REF.finditer(text):
            line = text[:m.start()].count("\n") + 1
            hits.append((relp, line, text[max(0, m.start() - 40):m.end() + 12].replace("\n", " / ")))
        for m in SPEC_LINE_SPAN.finditer(text):
            line = text[:m.start()].count("\n") + 1
            hits.append((relp, line, text[max(0, m.start() - 40):m.end() + 12].replace("\n", " / ")))
    hits.sort()
    facts = {"REVIEW_SPEC_LINE_CITES": len(hits)}
    findings = [("spec-code-line-citation", p,
                 "§17.3: спека не ссылается на код номером строки (строка %d: «%s»)" % (ln, frag))
                for p, ln, frag in hits]
    return facts, findings


def check_promises(root):
    """Открытый пункт (`OPEN-V9-NN`) обязан иметь ОДНО определение. Номер — это адрес обещания:
    два файла, где под одним номером напечатаны разные описания, — это уже два разных обещания,
    и читатель, который идёт по номеру в `OPEN-QUESTIONS`, получает не то, что ему обещали.
    Класс родился из собственной посадки: `lab/notes/DESIGN-2026-10-25-chain-binding.md` занял
    `OPEN-V9-11…13` под свои смыслы, тогда как п. 59 `OPEN-QUESTIONS` определил там часы,
    детектор `verifier_offline` и окно выплаты.

    Считается только форма «id — описание» в строке списка: упоминание номера в прозе определением
    не считается, иначе любой пересказ плодил бы находки. Проверка «номер упомянут, но нигде не
    определён» здесь сознательно НЕ делается: из 21 номера так не оформлены 10 (`OPEN-V9-1…10`
    описаны текстом спеки, а не списком), и находка была бы шумом до тех пор, пока реестр не
    станет одним файлом — это отдельный пункт очереди."""
    where = {}
    for path, text in ((p, read(p)) for p in tracked_markdown(root)[0]):
        for m in PROMISE_DEF.finditer(text):
            where.setdefault(m.group(1), set()).add(rel(root, path).replace("\\", "/"))
    doubles = sorted((k, sorted(v)) for k, v in where.items() if len(v) > 1)
    facts = {"REVIEW_PROMISE_IDS": len(where), "REVIEW_PROMISE_DOUBLE": len(doubles)}
    findings = [("promise-double-definition", p,
                 "%s определён в двух файлах: %s" % (k, ", ".join(v)))
                for k, v in doubles for p in v]
    return facts, findings


def tracked_markdown(root):
    """Размеченные файлы, которые видит git (`lab/ref-allow-list.txt` и находки считаются по
    закоммиченному дереву, а не по всему, что лежит на диске). Вне репозитория — временное дерево
    самопроверки или архив старого коммита — git отвечает ошибкой, и тогда берём обход
    файловой системы тем же `walk`, что и остальные проверки."""
    try:
        proc = subprocess.run(["git", "-C", root, "ls-files", "-z", "--", "*.md"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if proc.returncode != 0:
            raise OSError("git ls-files вернул %d" % proc.returncode)
        files = sorted(os.path.join(root, name.decode("utf-8", "replace"))
                       for name in proc.stdout.split(b"\0") if name)
        here = os.path.realpath(root) + os.sep
        files = [p for p in files
                 if os.path.isfile(p) and os.path.realpath(p).startswith(here)]
        if files:
            return files, "git"
    except Exception:
        pass
    return walk(root, ".md"), "walk"


def id_artefacts(root):
    """Номера, под которыми лежит артефакт: карточка гипотезы/эксперимента/решения или запись
    индекса источников. Имя файла с суффиксом (`H-0065.md` без slug) тоже артефакт."""
    have = {"H": set(), "E": set(), "ADR": set(), "L": set()}
    for kind, parts in ID_DIRS.items():
        d = os.path.join(root, *parts)
        for path in glob.glob(os.path.join(d, "%s-*.md" % kind)):
            m = re.match(r"^%s-(\d{4})" % kind, os.path.basename(path))
            if m:
                have[kind].add(m.group(1))
    index = os.path.join(root, "lab", "library", "index.jsonl")
    for line in read(index).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue  # испорченную строку уже разбирает `lab/library.py check`
        ident = rec.get("id") if isinstance(rec, dict) else None
        m = re.fullmatch(r"L-(\d{4})", ident or "")
        if m:
            have["L"].add(m.group(1))
    return have


def id_resolves(token, have):
    kind, serial = token.split("-", 1)
    num, tail = serial[:4], serial[4:]
    if tail:
        return False  # `H-0088b` — отдельный адрес: свой файл или запись списка разрешений
    return num in have.get(kind, set())


def load_allow_list(root):
    """`lab/ref-allow-list.txt`: `ID` плюс причина после `#`. Пустая причина — запись ничего
    не разрешает (список обязан объяснять, иначе он превращается в заглушку для глаз)."""
    path = os.environ.get(ALLOW_LIST_ENV) or os.path.join(root, ALLOW_LIST)
    allowed, unjustified, malformed, order = {}, [], [], []
    if not os.path.isfile(path):
        return allowed, unjustified, malformed, order, path, False
    for n, raw in enumerate(read(path).splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        head, sep, comment = line.partition("#")
        fields = head.split()
        if len(fields) > 1:
            malformed.append((n, line, "в строке больше одного идентификатора до `#`"))
            continue
        token = fields[0]
        if not DESCRIPTOR_ID.match(token):
            malformed.append((n, line, "не похоже на дескриптор артефакта"))
            continue
        reason = comment.strip() if sep else " ".join(fields[1:]).strip()
        if not reason:
            unjustified.append(token)
            continue
        if token not in allowed:
            order.append(token)
        allowed[token] = reason
    return allowed, unjustified, malformed, order, path, True


def check_descriptors(root):
    """Разрешимость именованных адресов в tracked `.md`. Считается по уникальным дескрипторам:
    одно висячее имя в двадцати файлах — это один адрес, а не двадцать находок."""
    files, mode = tracked_markdown(root)
    have = id_artefacts(root)
    mentions = {}
    for path in files:
        text = read(path)
        for m in DESCRIPTOR.finditer(text):
            token = m.group(1) + (m.group(2) or "")
            mentions.setdefault(token, set()).add(rel(root, path))
    allowed, unjustified, malformed, order, allow_path, allow_present = load_allow_list(root)
    resolved, violation_list, allowed_list = [], [], []
    for token in sorted(mentions):
        if id_resolves(token, have):
            resolved.append(token)
        elif token in allowed:
            allowed_list.append((token, allowed[token], sorted(mentions[token])))
        else:
            violation_list.append((token, sorted(mentions[token])))
    used = {t for t, _, _ in allowed_list}
    unused = [t for t in order if t not in used and t not in mentions]
    facts = {
        "REVIEW_ID_DOCS": len(files),
        "REVIEW_ID_SCAN": mode,
        "REVIEW_ID_TOKENS": len(mentions),
        "REVIEW_ID_RESOLVED": len(resolved),
        "REVIEW_REFS_UNRESOLVED_ALLOWED": len(allowed_list),
        "REVIEW_REFS_UNRESOLVED_VIOLATIONS": len(violation_list),
        "REVIEW_ALLOW_LIST_PRESENT": 1 if allow_present else 0,
        "REVIEW_ALLOW_LIST_ENTRIES": len(allowed) + len(unjustified),
        "REVIEW_ALLOW_LIST_UNJUSTIFIED": len(set(unjustified)),
        "REVIEW_ALLOW_LIST_MALFORMED": len(malformed),
        "REVIEW_ALLOW_LIST_UNUSED": len(unused),
    }
    detail = {
        "allow_path": allow_path,
        "unjustified": sorted(set(unjustified)),
        "malformed": malformed,
        "unused": unused,
    }
    return facts, violation_list, allowed_list, detail


def check_cards(root):
    findings = []
    experiments = {}
    for path in sorted(glob.glob(os.path.join(root, "lab", "experiments", "E-*.md"))):
        fm, _ = front_matter(path)
        eid = fm.get("id") or ""
        if eid:
            experiments[eid] = (path, fm)
    hyps = []
    for path in sorted(glob.glob(os.path.join(root, "lab", "hypotheses", "H-*.md"))):
        fm, body = front_matter(path)
        hyps.append((path, fm, body))
    for path, fm, body in hyps:
        status = fm.get("status", "").strip()
        if "lean" in fm and status in CLOSED_STATUS:
            text = section_text(body, RESULT_HEADINGS)
            if text is None:
                findings.append(("closed-empty-result", path,
                                 "нет раздела «Результат»/«Итог» при status=%s" % status))
            elif len(text.strip()) < RESULT_MIN or text.strip().lower().startswith("заполняется"):
                findings.append(("closed-empty-result", path,
                                 "раздел результата пуст или остался заготовкой при status=%s" % status))
    for path, fm, body in hyps:
        if fm.get("status", "").strip() != "testing":
            continue
        # `testing` при закрытом эксперименте — не всегда дефект: `H-0089` сознательно остаётся
        # testing, пока окно полезности не набрано, и объясняет это в разделе результата. Поэтому
        # находка ставится только там, где объяснения нет.
        explained = section_text(body, RESULT_HEADINGS)
        if explained is not None and len(explained.strip()) >= RESULT_MIN:
            continue
        for eid in sorted(set(re.findall(r"E-\d{4}", fm.get("experiments", "")))):
            if eid in experiments and experiments[eid][1].get("verdict", "").strip() not in ("", "pending"):
                verdict = experiments[eid][1].get("verdict")
                findings.append(("testing-closed", path,
                                 "status=testing, а %s уже вынес вердикт %s" % (eid, verdict)))
                break
    for path, fm, _ in hyps:
        for eid in sorted(set(re.findall(r"E-\d{4}", fm.get("experiments", "")))):
            if eid not in experiments:
                findings.append(("missing-experiments", path, "нет карточки эксперимента %s" % eid))
    for eid, (path, fm) in sorted(experiments.items()):
        verdict = fm.get("verdict", "").strip()
        if "result" in fm and verdict not in ("", "pending"):
            if fm.get("result", "").strip().lower() in ("", "null", '""'):
                findings.append(("closed-empty-result", path,
                                 "verdict=%s, а поле result пусто" % verdict))
    return findings, experiments


def check_ignored(root):
    annotations, findings = [], []
    for path in walk(root, ".rs"):
        lines = read(path).splitlines()
        for i, line in enumerate(lines):
            if not line.strip().startswith("#[ignore"):
                continue
            annotations.append((rel(root, path), i + 1))
            if not re.search(r'ignore[^\]]*"[^"]{10,}"', line):
                findings.append(("ignored-no-reason", path,
                                 "строка %d: #[ignore] без причины в кавычках" % (i + 1)))
    return annotations, findings


def check_orphans(root):
    findings = []
    for table in sorted(glob.glob(os.path.join(root, "lab", "expectations", "e*.tsv"))):
        tag = os.path.basename(table)[1:5]
        helper = os.path.join(root, "lab", "e%s-run.sh" % tag)
        cards = glob.glob(os.path.join(root, "lab", "experiments", "E-%s-*.md" % tag))
        if not os.path.isfile(helper):
            findings.append(("expect-orphans", table, "нет helper'а lab/e%s-run.sh" % tag))
        if not cards:
            findings.append(("expect-orphans", table, "нет карточки E-%s" % tag))
    for helper in sorted(glob.glob(os.path.join(root, "lab", "e*-run.sh"))):
        tag = os.path.basename(helper)[1:5]
        cards = glob.glob(os.path.join(root, "lab", "experiments", "E-%s-*.md" % tag))
        if not cards:
            findings.append(("helper-orphans", helper, "helper без карточки E-%s" % tag))
            continue
        fm, body = front_matter(cards[0])
        if "result" not in fm:
            continue  # историческая карточка: конвенция другая, не переписываем
        if os.path.basename(helper) not in read(cards[0]):
            findings.append(("helper-orphans", helper,
                             "не назван в карточке %s: прогон не воспроизводится" %
                             os.path.basename(cards[0])))
    return findings


def check_inventory(root):
    todos = 0
    big = []
    for path in walk(root, ".rs"):
        text = read(path)
        todos += len(re.findall(r"\b(?:TODO|FIXME|XXX)\b", text))
        n = text.count("\n") + 1
        if n > BIG_RS_LINES:
            big.append((rel(root, path), n))
    return todos, big


def review(root):
    findings = []
    ok, stale, unresolved, pinned, bad_pin = check_refs(root)
    for doc, ref, line_no, total in stale:
        findings.append(("stale-refs", os.path.join(root, doc),
                         "%s:%d, а в файле %d строк" % (ref, line_no, total)))
    for doc, ref, why in bad_pin:
        findings.append(("refs-pin-malformed", os.path.join(root, doc), "%s — %s" % (ref, why)))
    promise_facts, promise_findings = check_promises(root)
    findings += promise_findings
    spec_facts, spec_findings = check_spec_citations(root)
    findings += spec_findings
    card_findings, experiments = check_cards(root)
    findings += card_findings
    annotations, ign = check_ignored(root)
    findings += ign
    findings += check_orphans(root)
    todos, big = check_inventory(root)
    ref_facts, violations, allowed_list, ref_detail = check_descriptors(root)
    md = len(walk(root, ".md"))
    facts = {
        "REVIEW_MD_FILES": md,
        "REVIEW_REFS_OK": ok,
        "REVIEW_REFS_STALE": len(stale),
        "REVIEW_REFS_PINNED": pinned,
        "REVIEW_REFS_PIN_MALFORMED": len(bad_pin),
        "REVIEW_REFS_UNRESOLVED": unresolved,
        "REVIEW_CLOSED_EMPTY": sum(1 for f in findings if f[0] == "closed-empty-result"),
        "REVIEW_TESTING_CLOSED": sum(1 for f in findings if f[0] == "testing-closed"),
        "REVIEW_IGNORED": len(annotations),
        "REVIEW_IGNORED_NO_REASON": sum(1 for f in findings if f[0] == "ignored-no-reason"),
        "REVIEW_EXPECT_ORPHANS": sum(1 for f in findings if f[0] == "expect-orphans"),
        "REVIEW_HELPER_ORPHANS": sum(1 for f in findings if f[0] == "helper-orphans"),
        "REVIEW_MISSING_EXPERIMENTS": sum(1 for f in findings if f[0] == "missing-experiments"),
        "REVIEW_TODOS": todos,
        "REVIEW_BIG_RS": len(big),
    }
    facts.update(promise_facts)
    facts.update(spec_facts)
    facts.update(ref_facts)
    ranked = sorted(findings, key=lambda f: (f[0], rel(root, f[1]) if os.path.isabs(f[1]) else f[1]))
    facts["REVIEW_FINDINGS"] = len(ranked)
    if ranked:
        counts = {}
        for cls, _, _ in ranked:
            counts[cls] = counts.get(cls, 0) + 1
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        facts["REVIEW_TOP"] = "%s:%d" % top
    else:
        facts["REVIEW_TOP"] = "none:0"
    return facts, ranked, big, (violations, allowed_list, ref_detail)


def print_report(root, facts, ranked, big, refs=None):
    for key in sorted(facts):
        print("%s=%s" % (key, facts[key]))
    for path, n in sorted(big, key=lambda x: (-x[1], x[0])):
        print("ИНВЕНТАРЬ большой| %s строк=%d (порог %d)" % (path, n, BIG_RS_LINES))
    for cls, path, why in ranked:
        shown = rel(root, path) if os.path.isabs(path) else path.replace("\\", "/")
        print("НАХОДКА %s: %s — %s" % (cls, shown, why))
    if not refs:
        return
    violations, allowed_list, detail = refs
    # Отдельный префикс, а не `НАХОДКА`: класс `refs-dangling` не входит в `REVIEW_FINDINGS`,
    # чтобы закрытые циклы (`lab/expectations/e0101.tsv`) пере-проверялись прежним числом.
    for token, docs in violations:
        print("РАЗРЫВ refs-dangling: %s — артефакта нет, упомянут в %d файлах: %s" %
              (token, len(docs), ", ".join(docs[:4]) + ("" if len(docs) <= 4 else ", …")))
    for token, reason, docs in allowed_list:
        print("ПОЗВОЛЕНО refs-dangling: %s — %s (%d файлов: %s)" %
              (token, reason, len(docs), ", ".join(docs[:2]) + ("" if len(docs) <= 2 else ", …")))
    for line_no, text, why in detail["malformed"]:
        print("СПИСОК refs-allow-list: строка %d `%s` — %s" % (line_no, text, why))
    for token in detail["unjustified"]:
        print("СПИСОК refs-allow-list: %s — запись без причины, разрешения нет" % token)
    for token in detail["unused"]:
        print("СПИСОК refs-allow-list: %s — запись не упомянута ни в одном tracked .md" % token)


def make_tree(base):
    def put(relpath, text):
        full = os.path.join(base, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        io.open(full, "w", encoding="utf-8", newline="\n").write(text)
    put("docs/a.md", "Ссылка `lib.rs:999` уходит за конец.\n")
    put("crates/x/src/lib.rs", "fn a() {}\nfn b() {}\n")
    put("lab/hypotheses/H-0001-closed-empty.md",
        "---\nid: H-0001\nstatus: supported\nexperiments: [E-0001]\nlean:\n  решение: \"не применён\"\n---\n\n## Результат\n\n## Зачем\n")
    put("lab/experiments/E-0001-x.md",
        "---\nid: E-0001\nhypothesis: H-0001\nstatus: completed\nverdict: supports\nresult: null\n---\n")
    put("lab/hypotheses/H-0002-stuck.md",
        "---\nid: H-0002\nstatus: testing\nexperiments: [E-0002, E-0404]\nlean:\n  решение: \"не применён\"\n---\n")
    put("lab/experiments/E-0002-x.md",
        "---\nid: E-0002\nhypothesis: H-0002\nstatus: completed\nverdict: supports\nresult: \"итог есть\"\n---\n")
    put("lab/expectations/e0002.tsv", "X=1\n")
    put("lab/e0003-run.sh", "#!/usr/bin/env bash\n")
    put("crates/x/src/ign.rs", "fn t() {}\n#[ignore]\nfn slow() {}\n")
    return base


def selftest():
    tmp = tempfile.mkdtemp(prefix="repo-review-")
    planted = ["stale-refs", "closed-empty-result", "testing-closed",
               "ignored-no-reason", "expect-orphans", "helper-orphans",
               "missing-experiments"]
    try:
        facts, ranked, _, _ = review(make_tree(tmp))
        classes = {f[0] for f in ranked}
        missed = [c for c in planted if c not in classes]
        clean_root = tempfile.mkdtemp(prefix="repo-review-clean-")
        try:
            clean_facts, clean_ranked, _, _ = review(clean_root)
        finally:
            shutil.rmtree(clean_root, ignore_errors=True)
        clean_ok = clean_facts["REVIEW_FINDINGS"] == 0
        total = len(planted) + 1
        passed = total - len(missed) - (0 if clean_ok else 1)
        print("REVIEW_SELFTEST total=%d passed=%d" % (total, passed))
        for c in planted:
            mark = "ОТБИТ" if c in classes else "ПРОПУЩЕН"
            print("  КЕЙС %s: %s" % (c, mark))
        print("  КЕЙС чистое_дерево: %s (находок=%d)" %
              ("OK" if clean_ok else "ЛОЖНАЯ ТРЕВОГА", clean_facts["REVIEW_FINDINGS"]))
        return 0 if passed == total else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# Посадки для `refselftest`: (имя кейса, текст заметки, ожидаемый вердикт). `РАЗРЫВ` — обязан
# попасть в violations, `ВОШЁЛ` — в allowed (список разрешений работает), `ЧИСТО` — не попасть
# никуда (артефакт на месте: страж не имеет права валить заведомо разрешимое имя).
REF_DEFECTS = [
    ("гипотеза_без_карточки", "Отложено в `H-9001` без карточки.", "РАЗРЫВ"),
    ("эксперимент_без_карточки", "Порог заморожен в `E-9002`.", "РАЗРЫВ"),
    ("решение_без_файла", "Ждём слово владельца по `ADR-9003`.", "РАЗРЫВ"),
    ("источник_вне_индекса", "Ссылка на `L-9004`, записи нет.", "РАЗРЫВ"),
    ("хвост_буквой", "Очередь помечает `H-9005b`; карточка `H-9005` на месте, но адрес иной.",
     "РАЗРЫВ"),
    ("разрешено_с_причиной", "Резерв номера — `ADR-9006`.", "ВОШЁЛ"),
    ("разрешено_без_причины", "Дыра без объяснения — `E-9007`.", "РАЗРЫВ"),
    ("номер_скачки_файла", "Карточка лежит в `ADR-9001-reserved-slot.md`.", "ЧИСТО"),
    ("карточка_без_slug", "Гипотеза `H-9006`, файл `H-9006.md` без имени.", "ЧИСТО"),
    ("индекс_источников", "Подтверждено источником `L-9001`.", "ЧИСТО"),
    ("гипотеза_живая", "Измерено циклом `E-9001`, карточка `H-9001` рядом — оба на месте.", "ЧИСТО"),
]


def make_ref_tree(base):
    """Временное дерево: артефакты под настоящими номерами плюс одна заметка со всеми посадками."""
    def put(relpath, text):
        full = os.path.join(base, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        io.open(full, "w", encoding="utf-8", newline="\n").write(text)
    put("lab/hypotheses/H-9005-candidate.md", "---\nid: H-9005\nstatus: open\n---\n")
    put("lab/hypotheses/H-9006.md", "---\nid: H-9006\nstatus: open\n---\n")
    put("lab/experiments/E-9001-live.md", "---\nid: E-9001\nhypothesis: H-9005\nverdict: pending\n---\n")
    put("lab/decisions/ADR-9001-reserved-slot.md", "---\nid: ADR-9001\nstatus: proposed\n---\n")
    put("lab/library/index.jsonl", '{"id": "L-9001", "kind": "бумага"}\n')
    put("lab/ref-allow-list.txt",
        "# список разрешений для самопроверки\n"
        "ADR-9006   # резерв номера, заведенный в очереди этого дерева\n"
        "E-9007\n"
        "L-9009 не-идентификатор\n"
        "H-9010   # запись списка, которую никто не упоминает\n")
    note = "# Заметка с посаженными адресами\n\n"
    for _, text, _ in REF_DEFECTS:
        note += text + "\n\n"
    # Посадки формы ссылок (не дескрипторов): историческая ссылка обязана НЕ считаться stale,
    # битый пин — считаться находкой. `docs/spec.md` выше — одна строка, поэтому `:4000` без пина
    # был бы stale, и проверка `REVIEW_REFS_STALE == 0` ловит случай, когда пин не распознан.
    note += "Срез аудита: `docs/spec.md@2925bf2:4000` — номера сняты с дерева пина.\n\n"
    note += "Битый пин: `docs/spec.md@zz:1` — это находка, а не историческая ссылка.\n\n"
    # Посадка двойного определения открытого пункта: тот же номер описан в двух файлах. Это ровно
    # та ошибка, которую заметка волны 3 сделала по-настоящему (заняла `OPEN-V9-11…13` повторно).
    note += "- **`OPEN-V9-9001`** — первое определение, здесь оно выглядит владельцем номера.\n\n"
    put("lab/notes/refselftest.md", note)
    put("docs/spec.md", "# Спека в одной строке\n\n"
                        "- `OPEN-V9-9001` — второе определение того же номера, смысл другой.\n")
    # Посадка §17.3: нормативная спека не имеет права ссылаться на код номером строки. Сажаются
    # обе запрещённые формы (`путь.rs:NN` и голое `:NNN`), а рядом — две разрешённые: исторический
    # пин и обычное число формата. Кейс «валится» не проходит, если прибор считает их тоже.
    put("docs/VecDHT-SPEC-v8.md",
        "# Спека\n\n"
        "Живой указатель: `crates/x/src/lib.rs:1` — запрещённая форма.\n\n"
        "Голое продолжение абзаца: `:866…867` — тоже запрещённая.\n\n"
        "Снимок с пином: `crates/x/src/lib.rs@2925bf2:4000` — разрешён.\n\n"
        "Число формата: `18 + 16·N` байт, предел 4096 — не ссылка на строку.\n")
    return base


def ref_selftest():
    """Страж разрешимости обязан отбивать посаженные висячие адреса, пропускать разрешимые и
    не считать разрешением запись списка без причины."""
    saved = os.environ.pop(ALLOW_LIST_ENV, None)
    tmp = tempfile.mkdtemp(prefix="repo-review-refs-")
    try:
        facts, ranked, _, (violations, allowed_list, detail) = review(make_ref_tree(tmp))
        bad = {t for t, _ in violations}
        good = {t for t, _, _ in allowed_list}
        classes = {f[0] for f in ranked}
        fired, missed = 0, []
        for name, text, expect in REF_DEFECTS:
            token = DESCRIPTOR.search(text)
            token = (token.group(1) + (token.group(2) or "")) if token else "?"
            if expect == "РАЗРЫВ":
                hit = token in bad
            elif expect == "ВОШЁЛ":
                hit = token in good and token not in bad
            else:
                hit = token not in bad and token not in good
            if hit:
                fired += 1
            else:
                missed.append("%s(%s->%s)" % (name, token, expect))
            print("  КЕЙС %s [%s]: %s" % (name, expect, "ОТБИТ" if hit else "ПРОПУЩЕН"))
        checks = {
            "список_без_причины_не_разрешает": "E-9007" in bad,
            "строка_списка_некорректна": facts["REVIEW_ALLOW_LIST_MALFORMED"] >= 1,
            "строка_списка_не_использована": facts["REVIEW_ALLOW_LIST_UNUSED"] >= 1,
            "сканируется_tracked_дерево": facts["REVIEW_ID_DOCS"] >= 1,
            "исторический_пин_не_stale": (facts["REVIEW_REFS_PINNED"] == 3 and
                                          facts["REVIEW_REFS_STALE"] == 0),
            "битый_пин_валится": (facts["REVIEW_REFS_PIN_MALFORMED"] == 1 and
                                  "refs-pin-malformed" in classes),
            "номер_строки_в_спеке_валится": (facts["REVIEW_SPEC_LINE_CITES"] == 2 and
                                             "spec-code-line-citation" in classes),
            "двойное_определение_обещания_валится": (facts["REVIEW_PROMISE_DOUBLE"] == 1 and
                                                     "promise-double-definition" in classes),
            "выход_по_находкам_ненулевой": len(violations) > 0,
            "счётчики_сошлись": (facts["REVIEW_ID_TOKENS"] ==
                                 facts["REVIEW_ID_RESOLVED"] +
                                 facts["REVIEW_REFS_UNRESOLVED_ALLOWED"] +
                                 facts["REVIEW_REFS_UNRESOLVED_VIOLATIONS"]),
            "чистое_дерево_не_валится": _ref_clean_control(),
        }
        for name, ok in sorted(checks.items()):
            if ok:
                fired += 1
            else:
                missed.append(name)
            print("  ПРОВЕРКА %s: %s" % (name, "ОТБИТА" if ok else "ПРОПУЩЕНА"))
        total = len(REF_DEFECTS) + len(checks)
        passed = fired
        print("REFGUARD_DECOY_FIRED=%d/%d" % (fired, total))
        print("REFGUARD_SELFTEST total=%d passed=%d" % (total, passed))
        if missed:
            print("  ПРОПУЩЕНО: %s" % ", ".join(missed))
        return 0 if passed == total else 1
    finally:
        if saved is not None:
            os.environ[ALLOW_LIST_ENV] = saved
        shutil.rmtree(tmp, ignore_errors=True)


def _ref_clean_control():
    """Позитивный контроль: дерево, где все адреса разрешимы, обязано дать нуль разрывов. Без него
    удовлетворяет страж, который валит всё подряд."""
    root = tempfile.mkdtemp(prefix="repo-review-refs-clean-")
    try:
        def put(relpath, text):
            full = os.path.join(root, relpath)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            io.open(full, "w", encoding="utf-8", newline="\n").write(text)
        put("lab/hypotheses/H-0001-a.md", "См. `E-0001`, решение `ADR-0001`, источник `L-0001`.\n")
        put("lab/experiments/E-0001-a.md", "есть\n")
        put("lab/decisions/ADR-0001-a.md", "есть\n")
        put("lab/library/index.jsonl", '{"id": "L-0001"}\n')
        facts, _, _, (violations, _, _) = review(root)
        return facts["REVIEW_REFS_UNRESOLVED_VIOLATIONS"] == 0 and not violations
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main(argv):
    mode = "check"
    root = os.environ.get("VEC_DHT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    args = list(argv[1:])
    if args and not args[0].startswith("--"):
        mode = args.pop(0)
    if "--root" in args:
        root = args[args.index("--root") + 1]
    if mode == "selftest":
        return selftest()
    if mode == "refselftest":
        return ref_selftest()
    if mode != "check":
        print("режим %r неизвестен: check|selftest|refselftest" % mode)
        return 2
    facts, ranked, big, refs = review(root)
    print_report(root, facts, ranked, big, refs)
    # Висячий адрес — провал проверки (находка 5 аудита): раньше счётчик печатался, а выход
    # оставался нулевым. Нулевой список разрешений при этом не спасает: разрешение обязано быть
    # в version-controlled `lab/ref-allow-list.txt` с причиной.
    #
    # Тот же класс, второй его половиной: находки (`REVIEW_FINDINGS`) печатались, но на выход не
    # влияли — в логах есть строка `REVIEW_EXIT=0 REVIEW_FINDINGS=1` (`docs/METRICS.md`). Теперь
    # валит и то и другое: прибор, который видит слабость и молчит, — это не прибор.
    if facts["REVIEW_FINDINGS"] or facts["REVIEW_REFS_UNRESOLVED_VIOLATIONS"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
