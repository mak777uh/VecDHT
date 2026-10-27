#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Страж формы и уникальности номеров пунктов `OPEN-QUESTIONS.md` (H-0137).

Зачем: цикл `E-0136` опубликовал пункт заголовком `## 66. …`, не заметив, что `## п. 66. A4 закрыт`
уже существует; `lab/check-artifact-refs.py` такого заголовка не видит — он разрешает только ссылки
вида «п. NN» и не владеет ни формой, ни множеством заголовков. Номер в этом файле — адрес, по
которому владелец отвечает на вопрос, поэтому два пункта с одним номером делают вопрос недостижимым.

Что проверяется машинно (решающее, меняет выход):
  ФОРМА  — заголовок-пункт обязан быть каноническим: `## п. <метка>. <Заголовок>`, где метка —
           число, число со строчной кириллической суффикс-буквой (`62а`) либо диапазон
           (`12–13`). Неровные предки той же метки (`## 36.`, `## Пункт 31:`, `## п.36.` без
           пробела, `## п. 36` без точки) — дефект формы: ссылка `п. 36` на них не разрешается,
           а человеку они кажутся одним рядом, поэтому следующая вставка берёт занятый номер.
  ДУБЛЬ  — одна метка выдана дважды. Это ровно тот класс, который поймал `E-0136`.

Что проверяется не решающе (печатается счётом, выход не меняет):
  ПОВТОР-ЧИСЛА — разные метки с одним числом (`62` и `62а`). Такой заголовок — осознанный способ
           развести уже опубликованные номера без пере numbering хвоста, поэтому он не дефект;
           но число в нём занято, и правило обязано это печатать, а не прятать.

Чего здесь сознательно НЕТ: правила порядка (возрастания номеров). Оно измерено и отклонено:
файл содержит вторую очерёдность, начатую с 62, и monotonicity потребовала бы пере numbering
двенадцати опубликованных пунктов и примерно восемнадцати ссылок на них — цену, не лежащую на
критическом пути релиза. Класс дефекта, который поймал нас дважды (`E-0136`, `H-0114`), — уникальность,
а не возрастание; на посаженном убывающем номере страж молчит, и это отдельный проверяемый случай.

Также НЕ проверяется: заголовки без всякого номера (они не считаются пунктами), и то же в других
файлах репозитория — область стража один файл.

Употребление:
    python lab/check-oq-numbering.py [--file ПУТЬ] [--selftest]
Выход: 0 — чисто (для selftest: все посаженные дефекты отбиты, законные случаи не отбиты), 1 — есть
решающая находка, 2 — страж не смог прочитать файл (отказ прибора, а не вердикт).
"""
import argparse
import io
import os
import re
import sys
import tempfile

DEFAULT = "lab/decisions/OPEN-QUESTIONS.md"

# Метка пункта: число, опциональный строчный кириллический суффикс, опциональный диапазон.
LABEL = r"\d{1,4}(?:[а-яё]{1,2})?(?:[–-]\d{1,4})?"
CANON = re.compile(r"^## п\. (%s)\. \S" % LABEL)
HEAD = re.compile(r"^## (.*)$")

# Заголовок обязан считаться пунктом, если он претендует на номер. Три исторические формы предков
# перечислены явно: `## 36. …`, `## Пункт 31: …`, `## Пункт 29 и 30 …` — их мы ловим, а не терпим.
CLAIMS = (re.compile(r"^\d"),
          re.compile(r"^п\.\s*%s" % LABEL),
          re.compile(r"^Пункт"),          # «Пункт 31:» и «Пункты 12–13:» — обе исторические формы
          )

FENCE = re.compile(r"^\s*```")


def labels_of(text):
    """Числа, которые заголовок объявляет занятыми, и точная метка. Диапазон занимает оба конца."""
    m = re.match(r"^(%s)" % LABEL, text)
    if not m:
        return None, []
    lab = m.group(1)
    nums = [int(x) for x in re.findall(r"\d{1,4}", lab)]
    if len(nums) == 2:
        lo, hi = sorted(nums)
        nums = list(range(lo, hi + 1))
    return lab, nums


def scan(path):
    """Возвращает (находки, счётчики). Находка — кортеж (правило, номер строки, текст, пояснение)."""
    try:
        lines = io.open(path, encoding="utf-8").read().splitlines()
    except OSError as e:
        sys.stderr.write("страж не смог прочитать %s: %s\n" % (path, e))
        return None, None
    findings = []
    seen = {}                     # метка -> номер первого вхождения
    used = {}                     # число -> [меток, занявших его]
    items = 0
    fence = False
    for n, line in enumerate(lines, 1):
        if FENCE.match(line):
            fence = not fence
            continue
        if fence:
            continue
        h = HEAD.match(line)
        if not h:
            continue
        rest = h.group(1).strip()
        if not any(rx.match(rest) for rx in CLAIMS):
            continue              # заголовок не претендует на номер — вне области стража
        items += 1
        if CANON.match(line):
            lab, nums = labels_of(rest[len("п. "):])
        else:
            findings.append(("ФОРМА", n, line.strip(),
                             "не канонический заголовок-пункт; ожидаемое: `## п. <метка>. <Заголовок>`"))
            m = re.search(LABEL, rest)
            if not m:
                continue
            lab, nums = labels_of(m.group(0))
            if lab is None:
                continue
        if lab in seen:
            findings.append(("ДУБЛЬ", n, line.strip(),
                             "метка %s уже выдана на строке %d" % (lab, seen[lab])))
        else:
            seen[lab] = n
        for x in nums:
            used.setdefault(x, []).append(lab)
        # ПОВТОР-ЧИСЛА считается ниже по gathered used: это не решающая находка.
    repeats = {x: labs for x, labs in used.items() if len(set(labs)) > 1}
    counts = {"пунктов": items, "дублей": sum(1 for f in findings if f[0] == "ДУБЛЬ"),
              "форм": sum(1 for f in findings if f[0] == "ФОРМА"),
              "повторов-чисел": len(repeats),
              "повторы": ",".join(sorted(str(x) for x in repeats)) or "none"}
    return findings, counts


FIXTURE = """# Фикстура стража номеров

## п. 1. канонический пункт

## Итог

раздел без номера, страж его не считает пунктом

## п. 12–13. диапазон, канонический

## п.14. форма: нет пробела после «п.»

## 15. форма: голый номер

## Пункт 16: форма: слово «Пункт» с двоеточием

## п. 17 без точки на конце метки

## п. 18. дубль этот выдан дважды

## п. 18. дубль этот выдан дважды

## п. 20. законный суффикс

## п. 20а. отдельная опубликованная метка, повтор числа не дефект

## п. 99. законный пункт

## п. 5. убывающий номер — порядок страж не утверждает (посаженный контроль молчания)
"""


# Посаженные дефекты: ровно по одному на правило, включая форму-предка и форму «без точки».
PLANTED = ["п.14", "15", "Пункт 16", "17 без", "18"]
# Законные случаи, которые отбиты быть не могут: не-пункт, диапазон, суффикс, убывающий номер.
LEGAL = ["канонический пункт", "диапазон, канонический", "законный суффикс",
         "отдельная опубликованная метка", "убывающий номер"]


def selftest():
    fd, path = tempfile.mkstemp(suffix=".md", text=True)
    os.close(fd)
    try:
        with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(FIXTURE)
        findings, counts = scan(path)
    finally:
        os.unlink(path)
    if findings is None:
        print("SELFTEST=нет-файла")
        return 2
    bad_lines = {f[1] for f in findings}
    caught = 0
    for want in PLANTED:
        hit = [f for f in findings if want in f[2]]
        if hit:
            caught += 1
        else:
            print("МИМО посаженного: %s" % want)
    false = 0
    for want in LEGAL:
        hit = [f for f in findings if want in f[2] and f[0] in ("ФОРМА", "ДУБЛЬ")]
        if hit:
            false += 1
            print("ЛОЖНОЕ на законном: %s :: %s" % (want, hit[0][2]))
    print("PLANTED_TOTAL=%d" % len(PLANTED))
    print("PLANTED_CAUGHT=%d" % caught)
    print("PLANTED_FALSE=%d" % false)
    print("SELFTEST_Пунктов=%d Строки_с_находками=%d" % (counts["пунктов"], len(bad_lines)))
    return 0 if (caught == len(PLANTED) and false == 0) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=DEFAULT)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    findings, counts = scan(a.file)
    if findings is None:
        sys.exit(2)
    for rule, n, line, why in findings:
        print("РАЗРЫВ %s %s:%d: %s :: %s" % (rule, a.file, n, why, line[:90]))
    print("ПРОВЕРКА_НОМЕРОВ пунктов=%d форм=%d дублей=%d повторов-чисел=%d%s"
          % (counts["пунктов"], counts["форм"], counts["дублей"], counts["повторов-чисел"],
             " повтор:" + counts["повторы"] if counts["повторы"] != "none" else ""))
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
