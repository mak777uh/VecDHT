#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""E-0111: независимая сверка порождённого документа векторов.

Скрипт читает `docs/PAID_ORDER-VECTORS.md` как его читает сторонний верификатор — то есть по
напечатанным в нём числам и командам — и проверяет два класса утверждений:

1. хеши трёх примеров канонизации пересчитываются из напечатанных нормализованных байтов чистой
   реализацией (`hashlib`), без доступа к Rust;
2. матрица состояний в документе не имеет пустых клеток.

Для обоих классов есть посадка: три заведомо неверных способа сборки байтов обязаны дать другие
хеши, а искусственно обнулённая клетка — быть пойманной. Без посадок ноль находок означает молчание
прибора, а не чистоту (ДИАГНОЗ `E-0108`, `E-0089`).

Факты печатаются литеральными `KEY=value`, потому что `lab/threshold-lint.py` требует, чтобы каждый
ключ ожиданий встречался в источнике как `KEY=`.
"""
import hashlib
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
    rows = []
    for line in m.group(1).splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if all(set(c) <= set("-: ") for c in cells):
            continue  # строка-разделитель
        rows.append(cells)
    # первая таблица в разделе — заголовок + данные; заголовок опознаётся по ключевому слову
    if rows and rows[0][0] in ("state \\ event", "state"):
        rows = rows[1:]
    return rows


def empty_cells(rows):
    n = 0
    for r in rows:
        for c in r[1:]:
            if c == "":
                n += 1
    return n


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
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs/PAID_ORDER-VECTORS.md"))
