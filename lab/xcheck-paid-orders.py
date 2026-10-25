#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""E-0111: независимая сверка порождённого документа векторов.

Скрипт читает `docs/PAID_ORDER-VECTORS.md` как его читает сторонний верификатор — то есть по
напечатанным в нём числам и командам — и проверяет два класса утверждений:

1. хеши трёх примеров канонизации пересчитываются из напечатанных нормализованных байтов чистой
   реализацией (`hashlib`), без доступа к Rust;
2. матрица состояний в документе не имеет пустых клеток;
3. копия матрицы в спеке (§V9.6) совпадает с порождённой клетка в клетку — это закрывает `OPEN-V9-9`,
   где раньше сверка была только глазами.

Для каждого класса есть посадка: три заведомо неверных способа сборки байтов обязаны дать другие
хеши, искусственно обнулённая клетка — быть пойманной, а подмена клетки копии на черновое значение —
быть посчитанной расхождением. Без посадок ноль находок означает молчание
прибора, а не чистоту (ДИАГНОЗ `E-0108`, `E-0089`).

Факты печатаются литеральными `KEY=value`, потому что `lab/threshold-lint.py` требует, чтобы каждый
ключ ожиданий встречался в источнике как `KEY=`.
"""
import hashlib
import os
import re
import sys

DOMAIN = b"vecdht/paid_order/v1"


def worked_examples(text):
    """[(tag, norm_hex, printed_hash)] из разделов `### W…`."""
    out = []
    for block in re.findall(r"^### W\d.*?(?=^### |\Z)", text, re.S | re.M):
        tag_m = re.search(r"`kind`:\s*`\w+`\s*\(байт\s*(\d+)\)", block)
        norm_m = re.search(r"нормализованные байты, hex:\s*`([0-9a-f]+)`", block)
        hash_m = re.search(r"`statement_hash`:\s*`([0-9a-f]+)`", block)
        if tag_m and norm_m and hash_m:
            out.append((int(tag_m.group(1)), norm_m.group(1), hash_m.group(1)))
    return out


def statement_hash(tag, norm_hex):
    return hashlib.sha256(DOMAIN + b"\x00" + bytes([tag]) + b"\x00" + bytes.fromhex(norm_hex)).hexdigest()


def decoy_hashes(tag, norm_hex):
    """Три заведомо неверных сборки тех же байтов: без домена, тег до разделителя, без тега.

    Для `tag = 0` (`lean_proof`) вариант «тег до разделителя» байт в байт равен правильному: оба
    дают `domain || 0x00 || 0x00 || 0x00 || norm`. Это не дефект разборки — декодер позиционный и
    читает `kind` по фиксированному смещению, — но это слепая зона посадки: на примере с тегом 0
    неверная реализация хеша не всплывает. Поэтому посадка считается по примерам с тегом ≠ 0, а
    совпадение на W1 печатается отдельным фактом.
    """
    norm = bytes.fromhex(norm_hex)
    return {
        "no_domain": hashlib.sha256(b"\x00" + bytes([tag]) + b"\x00" + norm).hexdigest(),
        "tag_before_separator": hashlib.sha256(DOMAIN + bytes([tag]) + b"\x00\x00" + norm).hexdigest(),
        "no_tag": hashlib.sha256(DOMAIN + b"\x00\x00" + norm).hexdigest(),
    }


def matrix_rows(text):
    """Строки матрицы: таблицы после заголовка «Матрица состояний»."""
    m = re.search(r"^## Матрица состояний\.*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        return []
    return table_rows(m.group(1))


def spec_matrix_rows(text):
    """Строки копии матрицы из спеки: таблица раздела `## §V9.6 …`.

    Раздел опознаётся по заголовку, а не по номеру строки, потому что спека правится кусками и
    смещение заголовка — не факт. Если заголовок не найден, возвращается пустой список: отсутствие
    копии это расхождение, и печатается оно отдельным фактом, а не молчанием.
    """
    m = re.search(r"^## §V9\.6[^\n]*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        return []
    return table_rows(m.group(1))


def table_rows(chunk):
    """Первая таблица куска текста, строки без заголовка-разделителя.

    Берётся именно первая таблица, потому что в §V9.6 за матрицей идёт вторая — таблица переходов,
    и смешивание двух дало бы расхождение там, где его нет.
    """
    rows = []
    started = False
    for line in chunk.splitlines():
        s = line.strip()
        if s.startswith("|"):
            started = True
            cells = [c.strip() for c in s.strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue  # строка-разделитель
            rows.append(cells)
        elif started:
            break
    # первая таблица — заголовок + данные; заголовок опознаётся по ключевому слову
    if rows and rows[0][0] in ("state \\ event", "state"):
        rows = rows[1:]
    return rows


def matrix_mismatch(doc_rows, spec_rows):
    """Число клеток, где две копии расходятся; строка без пары считается расхождением целиком."""
    doc = {r[0]: r[1:] for r in doc_rows}
    spec = {r[0]: r[1:] for r in spec_rows}
    bad = 0
    for state in sorted(set(doc) | set(spec)):
        a, b = doc.get(state), spec.get(state)
        if a is None or b is None:
            bad += 11
            continue
        # лишняя или недостающая клетка тоже расхождение: сравнивается максимум длин, а не 11
        for k in range(max(len(a), len(b))):
            if (a[k] if k < len(a) else None) != (b[k] if k < len(b) else None):
                bad += 1
    return bad


def empty_cells(rows):
    n = 0
    for r in rows:
        for c in r[1:]:
            if c == "":
                n += 1
    return n


def initiator_rows(chunk):
    """Строки таблицы инициаторов (§V9.6): переходы вида `src → tgt` в первом столбце.

    Сканируются ВСЕ pipe-строки куска, а не только вторая таблица: между матрицей и таблицей
    переходов есть проза, и «взять вторую таблицу» означало бы остановиться на первом разрыве и
    потерять ровно те строки, ради которых проверка написана. Матрица стрелок в первом столбце не
    содержит, поэтому фильтрация по `→` однозначно оставляет только таблицу инициаторов.
    Возвращает список пар `(источник, цель)` — декартово раскрытие перечислений через `/`.
    """
    pairs = []
    for line in chunk.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if all(set(c) <= set("-: ") for c in cells):
            continue
        first = cells[0].strip("` ")
        if "→" not in first:
            continue  # заголовок «переход | …», любые строки без стрелки, включая матрицу
        left, right = first.split("→", 1)
        srcs = [x.strip("` ") for x in left.split("/") if x.strip("` ")]
        tgts = [x.strip("` ") for x in right.split("/") if x.strip("` ")]
        for a in srcs:
            for b in tgts:
                pairs.append((a, b))
    return pairs


def init_unreachable(spec_text, doc_matrix):
    """Число объявленных переходов, цели которых нет ни в одной клетке строки источника матрицы.

    Матрица порождённая — норматив; таблица инициаторов — проза, которая может от неё отстать.
    Ровно на этом `E-0111`-класс: `expired → disputed` объявлен в таблице, но ни одна клетка
    строки `expired` не равна `disputed`, значит проза противоречит матрице.
    """
    m = re.search(r"^## §V9\.6[^\n]*\n(.*?)(?=^## |\Z)", spec_text, re.S | re.M)
    if not m:
        return -1, []
    rows = doc_matrix
    reach = {r[0]: set(r[1:]) for r in rows}
    bad = []
    for src, tgt in initiator_rows(m.group(1)):
        if src not in reach:
            bad.append((src, tgt, "нет_строки"))
        elif tgt not in reach[src]:
            bad.append((src, tgt, "цель_недостижима"))
    return len(bad), bad


def main(path):
    text = open(path, encoding="utf-8").read()
    ex = worked_examples(text)
    print(f"V9_WORKED_PARSED={len(ex)}")
    matches = 0
    for tag, norm_hex, printed in ex:
        if statement_hash(tag, norm_hex) == printed:
            matches += 1
    print(f"V9_W_PY_MATCHES={matches}")

    fired = 0
    total = 0
    for tag, norm_hex, printed in ex:
        for name, h in decoy_hashes(tag, norm_hex).items():
            if tag == 0 and name == "tag_before_separator":
                continue  # совпадение по построению, печатается отдельным фактом
            total += 1
            fired += 1 if h != printed else 0
    print(f"V9_W_DECOY_FIRED={1 if total > 0 and fired == total else 0}")
    # Слепая зона посадки: при теге 0 неверная сборка «тег до разделителя» даёт верный хеш. Факт
    # нужен, чтобы читатель не выводил из «прибор поймал всё» вывод, что поимеет любую ошибку.
    if ex:
        col = decoy_hashes(ex[0][0], ex[0][1])["tag_before_separator"] == ex[0][2]
        print(f"V9_W_TAG0_COLLISION={1 if col else 0}")
    else:
        print("V9_W_TAG0_COLLISION=0")

    rows = matrix_rows(text)
    print(f"V9_MATRIX_ROWS={len(rows)}")
    print(f"V9_DOC_EMPTY_CELLS={empty_cells(rows)}")
    planted = [list(r) for r in rows]
    if planted:
        planted[0][1] = ""
    print(f"V9_DOC_DECOY_FIRED={1 if empty_cells(planted) > empty_cells(rows) else 0}")

    # Копия матрицы в спеке (§V9.6) обязана совпадать с порождённой клетка в клетку. До этой строки
    # расхождение ловилось только глазами: ДИАГНОЗ-2 цикла `E-0111` нашёл его вручную на паре
    # `disputed × submit`. Посадка — ровно та же клетка с прежним черновым значением.
    spec_path = os.environ.get("V9_SPEC", "docs/VecDHT-SPEC-v9.md")
    try:
        spec_text = open(spec_path, encoding="utf-8").read()
    except OSError:
        spec_text = ""
    try:
        spec_rows = spec_matrix_rows(spec_text)
    except Exception:
        spec_rows = []
    print(f"V9_SPEC_ROWS={len(spec_rows)}")
    mismatch = matrix_mismatch(rows, spec_rows) if rows else -1
    print(f"V9_SPEC_DOC_MISMATCH={mismatch}")
    planted_spec = [list(r) for r in spec_rows]
    for r in planted_spec:
        if r[0] == "disputed":
            r[1] = "E_REPLAY"          # значение из черновика: ровно та ошибка, что поймали руками
    print(f"V9_SPEC_DECOY_FIRED={1 if spec_rows and matrix_mismatch(rows, planted_spec) > mismatch else 0}")

    # Таблица инициаторов (§V9.6, вторая) обязана объявлять только те переходы, чья цель реально
    # стоит в матрице. Это закрывает B3: строка `…/expired → disputed` противоречила матрице, и
    # `V9_SPEC_DOC_MISMATCH=0` этого не ловил, потому что сверялись матрица⇄матрица, а не
    # проза⇄матрица. Посадка — вставить в объявленный переход цель, которой нет в строке источника.
    unreachable, detail = init_unreachable(spec_text, rows) if spec_text else (-1, [])
    print(f"V9_INIT_UNREACHABLE={unreachable}")
    if detail:
        print("V9_INIT_DETAIL=" + "; ".join(f"{a}→{b}:{c}" for a, b, c in detail[:8]))
    # Посадка на порождённой матрице: убрать из строки `published` клетку `disputed` (её даёт
    # `verifier_offline`) — тогда объявленный в таблице переход `published → disputed` станет
    # недостижимым, и прибор обязан увидеть рост числа недостижимых целей. Слепая зона: если матрица
    # пуста, сверка не исполняется, и это печатается нулём фактов, а не молчанием.
    planted_matrix = [list(r) for r in rows]
    pub_row = next((r for r in planted_matrix if r[0] == "published"), None)
    if pub_row:
        for i in range(1, len(pub_row)):
            if pub_row[i] == "disputed":
                pub_row[i] = "E_STATE_UNKNOWN"
    decoy_unreach, _ = init_unreachable(spec_text, planted_matrix) if spec_text else (-1, [])
    print(f"V9_INIT_DECOY_FIRED={1 if spec_text and rows and decoy_unreach > unreachable else 0}")

    # Копия, разошедшаяся с генератором, — это провал команды, а не заметка: до этой строки скрипт
    # возвращал 0 всегда и расхождение можно было только прочитать.
    return 1 if mismatch > 0 or unreachable > 0 or (rows and not spec_rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs/PAID_ORDER-VECTORS.md"))
