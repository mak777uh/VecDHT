#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Страж формы, уникальности и разрешимости номеров пунктов `OPEN-QUESTIONS.md` (`H-0137`, `H-0133`).

Зачем: номер в этом файле — адрес, по которому владелец отвечает на вопрос. Два пункта с одним
номером делают вопрос недостижимым, а указатель на несуществующий номер уводит в пустоту. Цикл
`E-0136` опубликовал пункт заголовком `## 66. …`, не заметив, что `## п. 66. A4 закрыт` уже есть.

Что исправлено в формулировке v1 (и почему это отдельный записываемый факт). В доке v1 было
напечатано, что `lab/check-artifact-refs.py` «разрешает только ссылки вида п. NN» и потому не видит
неровный заголовок. Это неверно по чтению файла: страж цитат сверяет backtick-цитаты путей
(`file.rs:NNN`) с деревом и про нумерацию пунктов не знает ничего. То есть прибора у нумерации
очереди до `E-0137` не было совсем — и v1, написанный в том же цикле, был первым.

Что проверяется машинно (решающее, меняет выход):
  ФОРМА  — (а) заголовок-пункт обязан быть каноническим: `## п. <метка>. <Заголовок>`, где метка —
           число, число со строчной кириллической суффикс-буквой (`62а`) либо диапазон (`12–13`).
           Неровные предки той же метки (`## 36.`, `## Пункт 31:`, `## п.36.` без пробела,
           `## п. 36` без точки) — дефект формы.
           (б) ЖИРНАЯ СТРОКА-ЗАЯВКА `**N. …` внутри тела другого пункта — тоже заявка номера, и она
           дефектна по форме: её не индексирует ни один поисковик заголовков, а ссылка `п. N` на неё
           разрешается только по совпадению текста. Это ровно тот класс, который поймал `E-0133`:
           шесть строк `**40.`…`**45.` при сорока одном заголовке.
  ДУБЛЬ  — одна метка выдана дважды, в одной форме или в двух разных (пересечение доменов — число 40
           на дереве `89895f2`: заголовок раздела о порядке очереди и пункт про kad-запись).
  ВИСЯКИЙ УКАЗАТЕЛЬ (режим `--pointers`) — именованная ссылка вида «OPEN-QUESTIONS … п. N» в любом
           tracked-файле репозитория, для которой в очереди нет ни заголовка, ни жирной заявки.

Что проверяется не решающе (печатается счётом, выход не меняет):
  ПОВТОР-ЧИСЛА — разные метки с одним числом (`62` и `62а`). Это осознанный способ развести уже
           опубликованные номера без пере numbering хвоста, поэтому не дефект; но число занято, и
           правило обязано это печатать, а не прятать.
  ТОЛЬКО-ЖИРНЫЙ — указатель, который разрешается жирной строкой, а не заголовком. Он разрешим,
           поэтому не красит выход; он измеряет, сколько живых ссылок висят на неиндексируемой форме.
  ТАБЛИЦА — строки таблицы решений владельца (`| N | …`, числа 1…30). У них СВОЁ пространство
           номеров, и в uniqueness они не участвуют: иначе каждое решение таблицы даёт ложный дубль
           с пунктом того же числа. В разрешимости указателей — участвуют: на дереве `89895f2` из 87
           живых указателей 44 ведут именно в таблицу, и без этого домена прибор красен на 44
           ложных висячих. Это и есть опровергнутая «широкая» формулировка (цикл `E-0133`):
           наивное правило «жирная строка с числом — дефект везде» даёт 55 срабатываний в 12 файлах.

Чего здесь сознательно НЕТ: правила порядка (возрастания номеров). Оно измерено и отклонено:
файл содержит вторую очерёдность, начатую с 62, и monotonicity потребовала бы пере numbering
двенадцати опубликованных пунктов и примерно восемнадцати ссылок на них — цену, не лежащую на
критическом пути релиза. Класс дефекта, который поймал нас дважды (`E-0136`, `H-0114`), — уникальность,
а не возрастание; на посаженном убывающем номере страж молчит, и это отдельный проверяемый случай.

Также НЕ проверяется: заголовки без всякого номера (они не считаются пунктами); указатели внутри
закрытых карточек и логов (`lab/decisions`, `lab/experiments`, `lab/hypotheses`, `lab/notes`,
`lab/logs`, `lab/lean`) — они описывают день, когда были написаны, а не сегодняшнее дерево.

Употребление:
    python lab/check-oq-numbering.py [--file ПУТЬ] [--selftest] [--pointers]
Выход: 0 — чисто (для selftest: все посаженные дефекты отбиты, законные случаи не отбиты), 1 — есть
решающая находка, 2 — страж не смог прочитать файл или собрать список tracked-файлов (отказ
прибора, а не вердикт).
"""
import argparse
import io
import os
import re
import subprocess
import sys
import tempfile

DEFAULT = "lab/decisions/OPEN-QUESTIONS.md"

# Метка пункта: число, опциональный строчный кириллический суффикс, опциональный диапазон.
LABEL = r"\d{1,4}(?:[а-яё]{1,2})?(?:[–-]\d{1,4})?"
CANON = re.compile(r"^## п\. (%s)\. \S" % LABEL)
HEAD = re.compile(r"^## (.*)$")

# Заявка номера жирной строкой: число, точка, пробел. Число без точки (`**750 passed …**`) заявкой
# не считается — это замер в жирном тексте, и ложных срабатываний на нём больше, чем настоящих.
INLINE_CLAIM = re.compile(r"^\*\*(\d{1,4}(?:[а-яё]{1,2})?)\. ")
# Строка таблицы решений владельца: свой домен номеров, в uniqueness не участвует.
TABLE_ROW = re.compile(r"^\|\s*(\d{1,3})\s*\|")

# Заголовок обязан считаться пунктом, если он претендует на номер. Три исторические формы предков
# перечислены явно: `## 36. …`, `## Пункт 31: …`, `## Пункт 29 и 30 …` — их мы ловим, а не терпим.
CLAIMS = (re.compile(r"^\d"),
          re.compile(r"^п\.\s*%s" % LABEL),
          re.compile(r"^Пункт"),          # «Пункт 31:» и «Пункты 12–13:» — обе исторические формы
          )

FENCE = re.compile(r"^\s*```")

# Указатель на пункт. Разделитель диапазона — тире или дефис; точка (`п. 51.1`) диапазоном не
# считается: на дереве `89895f2` прочтение `51.1` как `51–1` раздуло счётчик с 90 до 238.
POINTER = re.compile(r"п\.\s*(\d{1,4})([а-яё]{0,2})?(?:\s*[–-]\s*(\d{1,4}))?")
POINTER_EN = re.compile(r"\bitems\s+(\d{1,4})\s+and\s+(\d{1,4})\b")
POINTER_LINE = "OPEN-QUESTIONS"
POINTER_EXCLUDE = ("lab/decisions/", "lab/experiments/", "lab/hypotheses/",
                   "lab/notes/", "lab/logs/", "lab/lean/")


def labels_of(text):
    """Числа, которые метка объявляет занятыми, и точная метка. Диапазон занимает оба конца."""
    m = re.match(r"^(%s)" % LABEL, text)
    if not m:
        return None, []
    lab = m.group(1)
    nums = [int(x) for x in re.findall(r"\d{1,4}", lab)]
    if len(nums) == 2 and (u"–" in lab or "-" in lab):
        lo, hi = sorted(nums)
        nums = list(range(lo, hi + 1))
    return lab, nums


def read_lines(path):
    try:
        return io.open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError as e:
        sys.stderr.write("страж не смог прочитать %s: %s\n" % (path, e))
        return None


def claims_of(lines):
    """Три домена номеров файла: заголовки-пункты, жирные заявки, числа строк таблицы решений."""
    heads, inlines, rows = [], [], []
    fence = False
    for n, line in enumerate(lines, 1):
        if FENCE.match(line):
            fence = not fence
            continue
        if fence:
            continue
        if line.startswith("|"):
            m = TABLE_ROW.match(line)
            if m:
                rows.append(int(m.group(1)))
            continue
        h = HEAD.match(line)
        if h:
            rest = h.group(1).strip()
            if not any(rx.match(rest) for rx in CLAIMS):
                continue              # заголовок не претендует на номер — вне области стража
            canon = CANON.match(line)
            if canon:
                lab, nums = labels_of(rest[len("п. "):])
            else:
                m = re.search(LABEL, rest)
                lab, nums = labels_of(m.group(0)) if m else (None, [])
            heads.append((n, line.strip(), lab, nums, bool(canon)))
            continue
        m = INLINE_CLAIM.match(line)
        if m:
            lab, nums = labels_of(m.group(1))
            inlines.append((n, line.strip(), lab, nums))
    return heads, inlines, rows


def scan(path):
    """Возвращает (находки, счётчики). Находка — кортеж (правило, номер строки, текст, пояснение)."""
    lines = read_lines(path)
    if lines is None:
        return None, None
    heads, inlines, rows = claims_of(lines)
    findings = []
    for n, text, lab, nums, canon in heads:
        if not canon:
            findings.append(("ФОРМА", n, text,
                             "не канонический заголовок-пункт; ожидаемое: `## п. <метка>. <Заголовок>`"))
    for n, text, lab, nums, in inlines:
        findings.append(("ФОРМА", n, text,
                         "номер %s объявлен жирной строкой, а не заголовком; ссылка `п. %s` "
                         "не индексируется" % (lab, lab)))
    seen = {}
    used = {}
    for n, text, lab, nums in [(n, t, l, nu) for n, t, l, nu, _ in heads] + inlines:
        if lab is None:
            continue
        if lab in seen:
            findings.append(("ДУБЛЬ", n, text,
                             "метка %s уже выдана на строке %d" % (lab, seen[lab])))
        else:
            seen[lab] = n
        for x in nums:
            used.setdefault(x, []).append(lab)
    findings.sort(key=lambda f: (f[1], f[0]))
    repeats = {x: labs for x, labs in used.items() if len(set(labs)) > 1}
    counts = {"пунктов": len(heads) + len(inlines), "inline": len(inlines), "таблица": len(rows),
              "дублей": sum(1 for f in findings if f[0] == "ДУБЛЬ"),
              "форм": sum(1 for f in findings if f[0] == "ФОРМА"),
              "повторов-чисел": len(repeats),
              "повторы": ",".join(sorted(str(x) for x in repeats)) or "none"}
    return findings, counts


def tracked_md():
    """Список tracked `.md` файлов, из которых указатель обязан разрешиться (область стража)."""
    try:
        out = subprocess.run(["git", "ls-files", "-z", "--", "*.md"],
                             capture_output=True, text=True, encoding="utf-8")
    except OSError as e:
        sys.stderr.write("страж не смог вызвать git ls-files: %s\n" % e)
        return None
    if out.returncode != 0:
        sys.stderr.write("страж не смог получить список файлов: %s\n" % (out.stderr or "").strip())
        return None
    return [p for p in out.stdout.split("\0")
            if p and not any(p.startswith(x) for x in POINTER_EXCLUDE)]


def pointers(queue, docs=None):
    """Разрешимость именованных указателей на очередь. Выход красит только висячий указатель."""
    lines = read_lines(queue)
    if lines is None:
        return None, None
    heads, inlines, rows = claims_of(lines)
    head_labels = {l for _, _, l, _, _ in heads if l}
    inline_labels = {l for _, _, l, _ in inlines if l}
    head_nums = {x for _, _, _, nu, _ in heads for x in nu}
    inline_nums = {x for _, _, _, nu in inlines for x in nu}
    # Числа таблицы решений владельца разрешают указатель, но не участвуют в уникальности: у них
    # своё пространство номеров, и исторические ссылки вида «п. 8» ведут именно в него (разведка
    # `E-0133`: без этого домена наивное правило даёт 44 ложных висячих указателя из 87).
    row_nums = set(rows)
    if docs is None:
        docs = tracked_md()
        if docs is None:
            return None, None
    findings = []
    total = 0
    via_inline = 0
    via_table = 0
    files = 0
    for path in docs:
        body = read_lines(path)
        if body is None:
            return None, None
        hit_in_file = 0
        for n, line in enumerate(body, 1):
            if POINTER_LINE not in line:
                continue
            targets = []
            for m in POINTER.finditer(line):
                num, suf, hi = int(m.group(1)), m.group(2) or "", m.group(3)
                if hi:
                    lo, up = sorted((num, int(hi)))
                    targets.extend((str(x), x) for x in range(lo, up + 1))
                else:
                    targets.append(("%d%s" % (num, suf), num))
            for m in POINTER_EN.finditer(line):
                for x in (int(m.group(1)), int(m.group(2))):
                    targets.append((str(x), x))
            for lab, num in targets:
                total += 1
                hit_in_file += 1
                if lab and lab in head_labels:
                    continue
                if num is not None and num in head_nums:
                    continue
                if lab and lab in inline_labels:
                    via_inline += 1
                    continue
                if num is not None and num in inline_nums:
                    via_inline += 1
                    continue
                if num is not None and num in row_nums:
                    via_table += 1
                    continue
                findings.append(("ВИСЯКИЙ-УКАЗАТЕЛЬ", "%s:%d" % (path, n), line.strip(),
                                 "п. %s не разрешается ни заголовком, ни жирной заявкой в %s"
                                 % (lab or num, queue)))
        if hit_in_file:
            files += 1
    findings.sort(key=lambda f: (f[1], f[2]))
    counts = {"указателей": total, "висях": len(findings), "только_inline": via_inline,
              "по_таблице": via_table, "файлов": files}
    return findings, counts


QUEUE_FIXTURE = """# Фикстура стража номеров

## п. 1. канонический пункт

## Итог

раздел без номера, страж его не считает пунктом

## п. 12–13. диапазон, канонический

| 7 | законная строка таблицы решений: свой домен, дубля нет |
| 8 | ещё одна строка таблицы того же домена |

## п. 51. канонический пункт под контроль «не диапазон»

## п.14. форма: нет пробела после «п.»

## 15. форма: голый номер

## Пункт 16: форма: слово «Пункт» с двоеточием

## п. 17 без точки на конце метки

## п. 18. дубль этот выдан дважды

## п. 18. дубль этот выдан дважды

текст другого пункта, внутри которого объявлена заявка:

**21. форма: заявка номера жирной строкой, а не заголовком**

## п. 22. канонический заголовок до пересечения доменов

**22. дубль: тот же номер во второй форме**

**750 passed / 0 failed** законный случай: число без точки заявкой не считается

## п. 20. законный пункт под суффикс-разводку

## п. 20а. отдельная опубликованная метка, повтор числа не дефект

## п. 99. законный пункт

## п. 5. убывающий номер — порядок страж не утверждает (посаженный контроль молчания)
"""

DOC_FIXTURE = """# Фикстура указателей

ссылка `OPEN-QUESTIONS` п. 1 — канонический пункт, законный случай
ссылка `OPEN-QUESTIONS.md` п. 12–13 — диапазон занимает оба конца, законный случай
ссылка `OPEN-QUESTIONS` п. 20а — разрешается точной меткой, законный случай
ссылка `OPEN-QUESTIONS` п. 51.1 — подпункт, а не диапазон: один указатель на 51
ссылка `OPEN-QUESTIONS` items 99 and 5 — английская форма, оба конца разрешимы
ссылка `OPEN-QUESTIONS` п. 7 — разрешается строкой таблицы, законный случай
ссылка `OPEN-QUESTIONS` п. 21 — посаженный случай только-жирного разрешения
ссылка `OPEN-QUESTIONS` п. 77 — посаженный случай висячего указателя
ссылка `OPEN-QUESTIONS` п. 30–31 — посаженный случай висячего диапазона
"""

# Посаженные дефекты: по одному на каждое решающее правило и на канал указателей.
PLANTED = ["п.14", "15. форма", "Пункт 16", "17 без точки", "18. дубль",
           "21. форма", "22. дубль", "п. 77", "30–31"]
# Законные случаи, отбитые быть не могут: не-пункт, диапазон, суффикс, таблица, число без точки,
# убывающий номер, подпункт `51.1` и английская форма указателя.
LEGAL = ["канонический пункт", "диапазон, канонический", "отдельная опубликованная метка",
         "раздел без номера", "строка таблицы решений", "750 passed", "убывающий номер",
         "подпункт, а не диапазон", "английская форма"]
# Ожидания к самой фикстуре: заявленные числа должны сойтись, иначе selftest проверяет не то.
EXPECT = {"inline": 2, "таблица": 2, "указателей": 12, "висях": 3, "только_inline": 1,
          "по_таблице": 1}


def selftest():
    tmp = tempfile.mkdtemp()
    q = os.path.join(tmp, "queue.md")
    d = os.path.join(tmp, "doc.md")
    try:
        with io.open(q, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(QUEUE_FIXTURE)
        with io.open(d, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(DOC_FIXTURE)
        findings, counts = scan(q)
        pfacts, pcounts = pointers(q, [d])
    finally:
        for p in (q, d):
            os.unlink(p)
        os.rmdir(tmp)
    if findings is None or pfacts is None:
        print("SELFTEST=отказ-прибора")
        return 2
    allf = findings + pfacts
    bad_lines = {f[1] for f in findings} | {f[1] for f in pfacts}
    caught = 0
    for want in PLANTED:
        if any(want in f[2] for f in allf):
            caught += 1
        else:
            print("МИМО посаженного: %s" % want)
    false = 0
    for want in LEGAL:
        hit = [f for f in findings if want in f[2] and f[0] in ("ФОРМА", "ДУБЛЬ")]
        phit = [f for f in pfacts if want in f[2]]
        if hit or phit:
            false += 1
            print("ЛОЖНОЕ на законном: %s :: %s" % (want, (hit or phit)[0][2]))
    wrong = 0
    merged = dict(counts)
    merged.update(pcounts)
    for k, v in EXPECT.items():
        if merged.get(k) != v:
            wrong += 1
            print("СЧЁТ фикстуры по ключу %s: %s, ожидалось %d" % (k, merged.get(k), v))
    print("PLANTED_TOTAL=%d" % len(PLANTED))
    print("PLANTED_CAUGHT=%d" % caught)
    print("PLANTED_FALSE=%d" % false)
    print("SELFTEST_Пунктов=%d Указателей=%d Строки_с_находками=%d Счёта_не_сошлось=%d"
          % (counts["пунктов"], pcounts["указателей"], len(bad_lines), wrong))
    return 0 if (caught == len(PLANTED) and false == 0 and wrong == 0) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=DEFAULT)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--pointers", action="store_true",
                    help="проверить разрешимость именованных указателей на очередь")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    if a.pointers:
        findings, counts = pointers(a.file)
        if findings is None:
            sys.exit(2)
        for rule, loc, line, why in findings:
            print("РАЗРЫВ %s %s: %s :: %s" % (rule, loc, why, line[:90]))
        print("ПРОВЕРКА_УКАЗАТЕЛЕЙ указателей=%d висях=%d только_inline=%d по_таблице=%d файлов=%d"
              % (counts["указателей"], counts["висях"], counts["только_inline"],
                 counts["по_таблице"], counts["файлов"]))
        sys.exit(1 if counts["висях"] else 0)
    findings, counts = scan(a.file)
    if findings is None:
        sys.exit(2)
    for rule, n, line, why in findings:
        print("РАЗРЫВ %s %s:%d: %s :: %s" % (rule, a.file, n, why, line[:90]))
    print("ПРОВЕРКА_НОМЕРОВ пунктов=%d inline=%d таблица=%d форм=%d дублей=%d повторов-чисел=%d%s"
          % (counts["пунктов"], counts["inline"], counts["таблица"], counts["форм"],
             counts["дублей"], counts["повторов-чисел"],
             " повтор:" + counts["повторы"] if counts["повторы"] != "none" else ""))
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
