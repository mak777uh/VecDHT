#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Сторонний реализатор v9: пересобирает байты из текста спеки, не читая наш код.

Зачем этот файл. Определение готовности пакета v9 звучит так: человек, не видевший репозиторий,
открывает README, потом спеку и векторы, и по ним одним собирает минимальный клиент `paid_order`
- канонические байты заказа, `order_ref`, подачу, корень множества файлов, квитанцию, её подпись
и выведенный вердикт. Глазами это не проверяется: читатель всегда доедает текст до конца по памяти
о том, что он собирался там увидеть. Здесь вместо читателя стоит машина с двумя входами -
`docs/VecDHT-SPEC-v9.md` и `docs/PAID_ORDER-VECTORS.md`. Она не импортирует `vecdht-orders`, не
заглядывает в `crates/` и не принимает от генератора векторов раскладку в подарок.

Принцип, на котором держится прибор: **раскладка берётся из текста**. Домены читаются из напечатанных
формул, порядок и ширина полей - из таблицы §V9.2 в её печатном виде, терминатор `0x00` ставится
тогда и только тогда, когда о нём в колонке кодировки буквально написано. Формула подачи, формула
листа множества файлов и формула подписываемых байтов квитанции разбираются на токены и исполняются
как написаны. Если спека забудет терминатор, соврёт про длину домена или не напечатает вход,
пересобранные байты не совпадут с напечатанными, и прибор покраснеет. Подправить текст под уже
красивые числа он не позволит: текст - единственный источник.

Что печатается фактами (`V913_*`), и почему именно это:

* длина домена, заявленная в таблице, против длины строки, напечатанной в той же строке, и против
  домена из формулы `statement_hash` (эти три места обязаны совпасть: расхождение их - ровно тот
  класс ошибки, из-за которого две реализации расходятся по байтам);
* `canonical_record`, собранный по таблице, против напечатанного hex и против `order_ref`; при
  несовпадении печатается смещение первого различающегося байта, чтобы правку можно было назвать;
* нормализация §V9.3, применённая к напечатанному «грязному» входу, против напечатанных
  нормализованных байт и `statement_hash` - по всем трём примерам канонизации;
* формула подачи из §V9.4: напечатанные байты подачи разбираются по формуле токен за токеном и
  собираются обратно; отдельно печатается, напечатаны ли сами байты подачи и их входы в документе
  векторов (без них `submission_ref` невоспроизводим, и это не молчание, а факт со значением 0);
* корень множества файлов пересобирается из напечатанных листьев по напечатанной формуле; отдельно
  печатается число пар «путь + sha256 содержимого», потому что листья без них не вычисляются;
* канонический JSON квитанции: разобрать напечатанный JSON, сериализовать заново по правилам §V9.5
  (ASCII-порядок ключей, целые без дроби, разделители без пробелов), сверить побайтно; сверить
  множество ключей с перечнем, напечатанным в правиле; подписываемые байты выводятся из формулы;
* вердикт выводится правилами §V9.5 по их печатному списку, без судьи, и сверяется с напечатанным
  `derived_verdict` и `payout_allowed`;
* Ed25519: реализация в этом файле (из текста `RFC 8032`, без чужих библиотек), само-тест на
  опубликованном векторе TEST 1 того же RFC - иначе нулевой верификатор был бы молчанием, - сетка из 128 подписей (16 ключей на 8 длинах сообщения), где половина точек R имеет нечётный x: одна подпись этого не ловит, а без сетки верификатор, отвергающий половину честных подписей, прошёл бы как рабочий, -
  проверка подписей заказа и квитанции и посадка: инвертированный бит сообщения обязан быть отвергнут.

Команда:

    python lab/v9-independent-client.py [docs/PAID_ORDER-VECTORS.md] [docs/VecDHT-SPEC-v9.md]

Выход 0 - сошлось всё; 1 - хоть одна сверка не сошлась или хоть один нужный вход не напечатан;
2 - входы не разбираются (документ или спека переписаны так, что читать их нечем).
"""

import hashlib
import json
import os
import re
import sys
import unicodedata

BS = chr(92)
DQ = chr(34)
BAR = chr(0x2016)
MD = chr(0x2014)
TICK = chr(96)
PIPE = BS + "|"
T = b"\x00"
PHRASE_TERM = "затем " + TICK + "0x00" + TICK
V913_PREFIX = "V913_"
VERBOSE = os.environ.get("V913_VERBOSE") == "1"
# Строка «домен» из таблицы §V9.2: заявленная длина и напечатанная строка домена. Вертикальную
# черту таблицы в регулярном выражении нужно экранировать: без этого она читается как «или».
DOMAIN_ROW_RE = (PIPE + BS + "s*" + MD + BS + "s*" + PIPE + BS + "s*домен" + BS + "s*" + PIPE
                 + BS + "s*(" + BS + "d+)" + BS + "s*байт" + BS + "w*" + BS + "s*" + PIPE
                 + "([^|]+?)" + PIPE)

# Домены и теги `kind` не зашиты: их заполняет read_spec_constants из напечатанных формул и
# таблицы спеки. Зашить их сюда означало бы сверять прибор с самим собой.
DOMAIN_ORDER = None
DOMAIN_RECEIPT = None
DOMAIN_FILESET = None
KIND_TAGS = {}

_state = {"bad": 0}


def emit(key, value, note=""):
    print(V913_PREFIX + key + "=" + str(value))
    if note and VERBOSE:
        print("  # " + key + ": " + note)


def check(key, ok, note=""):
    """Печатает факт 0 или 1 и поднимает WORST, если единицы нет."""
    v = 1 if ok else 0
    emit(key, v, note)
    if v == 0:
        _state["bad"] = 1
    return v


def fail(key, note):
    """Факт заведомо красный: вход не напечатан, а значит сверка невозможна."""
    emit(key, 0, note)
    _state["bad"] = 1


def abort(reason):
    print("ВХОД_НЕ_РАЗОБРАН: " + str(reason), file=sys.stderr)
    return 2


def sha(bs):
    return hashlib.sha256(bs).digest()


def hx(bs):
    return bs.hex()


# ---------------------------------------------------------------------------
# Чтение носителя
# ---------------------------------------------------------------------------

def bullet(doc, label):
    m = re.search(r"^- " + re.escape(label) + ": `" + "([^" + TICK + "]+)" + TICK,
                  doc, re.MULTILINE)
    if m:
        return m.group(1).strip()
    m = re.search(r"^- " + re.escape(label) + ": ([^" + TICK + chr(10) + "]+)$",
                  doc, re.MULTILINE)
    return m.group(1).strip() if m else None


def vector_facts(doc, vid):
    for line in doc.splitlines():
        if '"id":"' + vid + '"' in line:
            return json.loads(line.strip()).get("facts", {})
    return None


def example(doc, *needles):
    """Последний бэковский hex из строки «- …», содержащей все переданные метки.

    Метки в порождённом документе обёрнуты в бэки и снабжены суффиксом «, hex», поэтому
    прежний шаблон с точным прилеганием молчал: прибор не находил напечатанные байты подачи
    и объявлял их отсутствующими. Поиск по всем меткам строки — честный способ отличить
    «не напечатано» от «напечатано не так, как я ожидал».
    """
    for line in doc.splitlines():
        if not line.startswith("- "):
            continue
        if all(n in line for n in needles):
            found = re.findall(TICK + "([0-9a-fA-F]{2,})" + TICK, line)
            if found:
                return found[-1]
    return None


def example_all(doc, *needles):
    """Все бэковые hex из строки «- …» с нужными метками (для списка листьев)."""
    for line in doc.splitlines():
        if line.startswith("- ") and all(n in line for n in needles):
            return re.findall(TICK + "([0-9a-f]{64})" + TICK, line)
    return []


def _example_unused(doc, label):
    m = re.search(r"^- " + re.escape(label) + "(?:[^" + TICK + "]*)?: " + TICK
                  + "([0-9a-fA-F]{2,})" + TICK, doc, re.MULTILINE)
    if m:
        return m.group(1)
    m = re.search(r"^- " + re.escape(label) + "(?:[^" + TICK + "]*)?: " + TICK
                  + "([^" + TICK + chr(10) + "]+)" + TICK, doc, re.MULTILINE)
    return m.group(1) if m else None


def w_section(doc, name):
    i = doc.index("### " + name + " ")
    nxt = doc.find("###", i + 5)
    body = doc[i:nxt] if nxt > 0 else doc[i:]

    def grab(pat):
        m = re.search(pat, body)
        return m.group(1) if m else None

    return {
        "tag": grab(r"тег `kind`: `[a-z_]+` \(байт (\d+)\)"),
        "raw": grab(r"raw .*hex: `([0-9a-f]+)`"),
        "norm": grab(r"нормализованные байты, hex: `([0-9a-f]+)`"),
        "len": grab(r"длина нормализованных байтов: (\d+)"),
        "hash": grab(r"`statement_hash`: `([0-9a-f]+)`"),
    }


# ---------------------------------------------------------------------------
# 0. Формулы спеки как исполняемый текст
# ---------------------------------------------------------------------------

def formula_tokens(spec, anchor):
    """Токены напечатанной формулы по якорю строки; разделитель токенов - та же черта, что в спеке.

    Строка вида `x = sha256( a BAR b )` отдаёт токены из-под `sha256(`; строка без `=` отдаётся
    целиком. Если якоря в тексте нет, функция падает: отсутствующая формула - сломанный вход,
    а не тихий ноль.
    """
    if anchor not in spec:
        raise ValueError("якорь %r в спеке не найден" % anchor)
    i = spec.index(anchor)
    start = spec.rfind(chr(10), 0, i) + 1
    end = spec.find(chr(10), i)
    if end < 0:
        end = len(spec)
    parts = [spec[start:end].strip()]
    while parts[-1].endswith(BAR):
        nxt = spec.find(chr(10), end + 1)
        if nxt < 0:
            nxt = len(spec)
        parts.append(spec[end + 1:nxt].strip())
        end = nxt
    line = " ".join(parts).strip()
    if "=" in line:
        rhs = line.split("=", 1)[1].strip()
        if not (rhs.startswith("sha256(") and rhs.endswith(")")):
            raise ValueError("формула %r не свёрнута в sha256(...): %r" % (anchor, line))
        rhs = rhs[len("sha256("):-1].strip()
    else:
        rhs = line
    return [t.strip() for t in rhs.split(BAR) if t.strip()]


def tok_kind(tok):
    """Классифицирует токен формулы: литерал, байт, uint, длина-префикс, вызов, поле.

    Неизвестный токен возвращается как ("unknown", ...): читающий обязан покраснеть, а не пропустить
    его молча.
    """
    if tok.startswith(DQ) and tok.endswith(DQ) and len(tok) >= 2:
        return ("lit", tok[1:-1].encode("utf-8"))
    m = re.fullmatch(r"0x([0-9a-fA-F]{2})", tok)
    if m:
        return ("byte", int(m.group(1), 16))
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_.]*):u8", tok)
    if m:
        # u8 однозначен: у одного байта нет порядка. u16/u32/u64 без суффикса остаются unknown,
        # потому что порядок байтов тогда не выводится из текста, а прибор не имеет права угадывать.
        return ("uint", m.group(1), 1)
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_.]*):u([0-9]+)le", tok)
    if m:
        return ("uint", m.group(1), int(m.group(2)) // 8)
    m = re.fullmatch(r"u32le\(len\(([A-Za-z0-9_.]+)\)\)", tok)
    if m:
        return ("lenprefix", m.group(1))
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_.]*)\((.*)\)", tok)
    if m:
        # Аргумент может сам быть вызовом: `concat(sorted(leaf_i))` — формула корня из §V9.4.
        # Прежний шаблон `[^()]*` классифицировал такой токен как unknown, и раздел множества
        # файлов краснел на исполнителе формулы, а не на тексте (E-0113). Имя и аргменты здесь
        # нужны только для класса токена: значение берётся из env по полной строке токена.
        return ("call", m.group(1), m.group(2).strip())
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", tok):
        return ("field", tok)
    return ("unknown", tok)


def domain_of(spec, anchor):
    """Первый строковый литерал формулы - это и есть домен, напечатанный в этом месте."""
    for t in formula_tokens(spec, anchor):
        k = tok_kind(t)
        if k[0] == "lit":
            return k[1]
    raise ValueError("в формуле %r нет напечатанного домена" % anchor)


def read_spec_constants(spec):
    """Собирает домены и теги `kind` из текста спеки; печатает, что прочитано, а что нет."""
    global DOMAIN_ORDER, DOMAIN_RECEIPT, DOMAIN_FILESET, KIND_TAGS
    for name, anchor in (("DOMAIN_ORDER", "statement_hash = sha256("),
                         ("DOMAIN_FILESET", "leaf(path, content) = sha256("),
                         ("DOMAIN_RECEIPT", "canonical_json(receipt)")):
        try:
            lit = domain_of(spec, anchor)
        except ValueError as e:
            fail(name + "_READ", str(e))
            continue
        globals()[name] = lit
        emit(name + "_READ", 1, "домен прочитан из напечатанной формулы")
        emit(name + "_BYTES", len(lit))
    row = [r for r in record_rows(spec) if r["field"] == "kind"]
    if not row:
        fail("KIND_TAGS_READ", "строки kind в таблице §V9.2 нет")
        return
    pairs = re.findall(r"([a-z_][a-z0-9_]*)\s*=\s*([0-9]+)", row[0]["rule"])
    KIND_TAGS.update(dict((n, int(t)) for (n, t) in pairs))
    emit("KIND_TAGS_READ", len(KIND_TAGS), "тегов kind прочитано из таблицы §V9.2")
    if len(KIND_TAGS) != 3:
        _state["bad"] = 1


# ---------------------------------------------------------------------------
# 1. Домен заказа
# ---------------------------------------------------------------------------

def check_domain(spec):
    row = re.search(DOMAIN_ROW_RE, spec, re.MULTILINE)
    if not row:
        fail("DOMAIN_ROW_READ", "в §V9.2 нет строки «домен» с заявленной длиной")
        return
    declared = int(row.group(1))
    emit("DOMAIN_DECLARED_BYTES", declared, "заявлено в таблице §V9.2")
    lit = re.search(r"`([^`]+)`", row.group(2))
    if not lit:
        fail("DOMAIN_ROW_LITERAL_READ", "в строке «домен» нет напечатанной строки домена")
        return
    row_domain = lit.group(1).encode("utf-8")
    emit("DOMAIN_ROW_BYTES", len(row_domain), "длина строки, напечатанной в таблице")
    check("DOMAIN_LEN_OK", declared == len(row_domain),
          "заявленная длина равна длине напечатанной строки")
    check("DOMAIN_ROW_VS_FORMULA_EQ", row_domain == DOMAIN_ORDER,
          "домен в таблице §V9.2 и в формуле statement_hash одинаков")


# ---------------------------------------------------------------------------
# 2. canonical_record по таблице §V9.2
# ---------------------------------------------------------------------------

def record_rows(spec):
    """Строки числовой части таблицы §V9.2: номер, поле, тип, кодировка, правило."""
    start = spec.index("## §V9.2")
    end = spec.index("## §V9.3")
    rows = []
    pat = PIPE + r"\s*(\d+)\s*" + PIPE
    for line in spec[start:end].splitlines():
        m = re.match(pat, line)
        if not m:
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) < 5:
            continue
        rows.append({"n": int(m.group(1)), "field": cols[1].strip(TICK),
                     "type": cols[2], "enc": cols[3], "rule": cols[4]})
    rows.sort(key=lambda r: r["n"])
    return rows


def width_of(cell):
    """Ширина поля в байтах, прочитанная из напечатанной колонки: `u128` или «32 байта»."""
    for name in ("u128", "u64", "u32", "u16", "u8"):
        if TICK + name + TICK in cell:
            return int(name[1:]) // 8
    m = re.search(r"\d+\s*байт", cell)
    if m:
        return int(re.sub(r"\D", "", m.group(0)))
    return None


def terminator_for(row):
    """Терминатор ставится только там, о чём в колонке кодировки буквально написано.

    Для `reward.asset` фраза про `0x00` ищется внутри той ветки тега, которая кодируется: общий
    придаточный в конце ячейки («в обоих случаях затем `0x00`») ветку `native` не покрывает, и на
    дереве до правки это дало 216 собранных байт против 217 напечатанных при первом расхождении на
    смещении 140 (`V913_RECORD_FIRST_DIFF_OFFSET`, E-0113). Прибор не дорисовывает то, чего в
    тексте нет: это ровно то место, где реализация и текст расходятся.
    """
    enc = row["enc"]
    if "не входит" in enc:
        return False
    if row["field"] == "reward.asset":
        native, sep, token = enc.partition("тег " + chr(96) + "1" + chr(96))
        return PHRASE_TERM in native
    return PHRASE_TERM in enc


def encode_field(row, val):
    field, enc = row["field"], row["enc"]
    if field == "kind":
        if val not in KIND_TAGS:
            raise ValueError("тег kind %r не прочитан из таблицы" % val)
        return bytes([KIND_TAGS[val]])
    if field == "reward.asset":
        if val["kind"] == "native":
            return b"\x00"
        return (b"\x01" + int(val["chain_id"]).to_bytes(8, "little")
                + bytes.fromhex(val["address"]))
    if "сырые байты" in enc or "verification key" in enc:
        return bytes.fromhex(val)
    if "LE длина" in enc:
        b = val.encode("utf-8") if isinstance(val, str) else bytes.fromhex(val)
        return len(b).to_bytes(4, "little") + b
    if "один байт" in enc:
        return bytes([0 if val in (False, "false", 0, "0") else 1])
    w = width_of(enc) or width_of(row["type"])
    if w and "little-endian" in enc:
        return int(val).to_bytes(w, "little")
    if w and "unix-секунды" in enc:
        return int(val).to_bytes(w, "little")
    raise ValueError("нет интерпретатора для поля %r: тип %r, кодировка %r" % (field, row["type"], enc))


def build_record(spec, inputs):
    """Собирает канонические байты заказа, подчиняясь таблице §V9.2 строка за строкой."""
    rows = record_rows(spec)
    emit("FIELDS_PARSED", len(rows), "строк полей в таблице §V9.2")
    if len(rows) != 13:
        _state["bad"] = 1
    row = re.search(DOMAIN_ROW_RE, spec, re.MULTILINE)
    lit = re.search(TICK + "([^" + TICK + "]+)" + TICK, row.group(2)).group(1).encode("utf-8") if row else DOMAIN_ORDER
    out = bytearray(lit)
    # Префикс берётся из строки «домен»: если там напечатано «затем 0x00», он и в сборке обязателен.
    if row and PHRASE_TERM in row.group(2):
        out += T
    missing = []
    for row in rows:
        if row["field"] not in inputs or inputs[row["field"]] is None:
            missing.append(row["field"])
            continue
        try:
            out += encode_field(row, inputs[row["field"]])
        except (ValueError, KeyError, TypeError) as e:
            missing.append(row["field"] + " (" + str(e) + ")")
            continue
        if terminator_for(row):
            out += T
    if missing:
        emit("INPUTS_MISSING", len(missing), "полей, по которым сборка неполна: " + "; ".join(missing))
        _state["bad"] = 1
    else:
        emit("INPUTS_MISSING", 0)
    return bytes(out)


def first_diff(a, b):
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return i
    return min(len(a), len(b))


# ---------------------------------------------------------------------------
# 3. Нормализация §V9.3 и пример канонизации
# ---------------------------------------------------------------------------

def normalize(raw):
    """Шаги нормализации §V9.3: NFC, переводы строк, хвостовой ASCII-пробел, хвостовые пустые строки.

    Шаг 4 снимает только ` ` и `\\t`: Unicode-пробел — содержание, а не хвост. Шаг 7: пустой
    результат — отказ (`None`, как и не-UTF-8), а не пустые байты: в Rust оба случая дают
    `E_STATEMENT_ENCODING`. Снятие хвостовых пустых строк идёт после снятия пробелов, иначе
    строка из одних пробелов пережила бы шаг 5.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text = unicodedata.normalize("NFC", text)
    text = text.replace(chr(13) + chr(10), chr(10)).replace(chr(13), chr(10))
    lines = [line.rstrip(" " + chr(9)) for line in text.split(chr(10))]
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return None
    return (chr(10).join(lines) + chr(10)).encode("utf-8")


def statement_hash_tokens(spec):
    return formula_tokens(spec, "statement_hash = sha256(")


def check_examples(doc, spec):
    toks = statement_hash_tokens(spec)
    emit("STATEMENT_FORMULA_TOKENS", len(toks), "токенов в напечатанной формуле statement_hash")
    same_norm = same_hash = 0
    for name in ("W1", "W2", "W3"):
        s = w_section(doc, name)
        if not (s["raw"] and s["norm"] and s["hash"] and s["tag"]):
            fail(name + "_INPUTS_PRINTED", "в пример канонизации не напечатан вход")
            continue
        rebuilt = normalize(bytes.fromhex(s["raw"]))
        want = bytes.fromhex(s["norm"])
        ok_norm = rebuilt == want
        emit(name + "_NORM_EQ", 1 if ok_norm else 0)
        env = {"kind_tag": int(s["tag"]), "normalize(raw)": want}
        mine = run_formula(toks, env)
        ok_hash = mine is not None and hx(sha(mine)) == s["hash"]
        emit(name + "_HASH_EQ", 1 if ok_hash else 0)
        same_norm += 1 if ok_norm else 0
        same_hash += 1 if ok_hash else 0
    emit("EXAMPLES", same_norm, "примеров канонизации собраны побайтно")
    emit("EXAMPLE_HASHES", same_hash, "statement_hash примеров сошлись")
    if same_norm != 3 or same_hash != 3:
        _state["bad"] = 1
    emit("NFC_UNICODE_VERSION", unicodedata.unidata_version,
         "версия Unicode, чей NFC применяет эта реализация")


# ---------------------------------------------------------------------------
# 4. Исполнение напечатанной формулы
# ---------------------------------------------------------------------------

def run_formula(tokens, env):
    """Собирает байты из токенов формулы; env даёт значения полей и вызовов.

    Токен, для которого в env нет значения, возвращает None: собрав байты наугад, прибор подтвердил
    бы собственную догадку, а не текст.
    """
    out = bytearray()
    skip = None
    for t in tokens:
        if skip is not None and t == skip:
            skip = None
            continue
        k = tok_kind(t)
        if k[0] == "lit":
            out += k[1]
        elif k[0] == "byte":
            out += bytes([k[1]])
        elif k[0] == "uint":
            if k[1] not in env:
                return None
            out += int(env[k[1]]).to_bytes(k[2], "little")
        elif k[0] == "lenprefix":
            # Формула пишет `u32le(len(x))` и тут же `x`: это один фрагмент байтов, а не два.
            b = env.get(k[1], env.get(t))
            if b is None:
                return None
            b = b.encode("utf-8") if isinstance(b, str) else b
            out += len(b).to_bytes(4, "little") + b
            skip = k[1]
        elif k[0] in ("field", "call"):
            if t not in env:
                return None
            b = env[t]
            if isinstance(b, bytes):
                out += b
            elif re.fullmatch("[0-9a-f]*", b):
                out += bytes.fromhex(b)
            else:
                out += b.encode("utf-8")
        else:
            return None
    return bytes(out)


def submission_widths(spec):
    """Ширины полей подачи из таблицы §V9.4: колонка «тип» той же таблицы, что и формула."""
    start = spec.index("## §V9.4")
    end = spec.index(BAR, start)
    w = {}
    for line in spec[start:end].splitlines():
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) < 2 or not cols[0].startswith(TICK):
            continue
        got = width_of(cols[1])
        if got:
            w[cols[0].strip(TICK)] = got
    emit("SUBMISSION_WIDTHS_READ", len(w), "ширин полей подачи прочитано из таблицы §V9.4")
    return w


def parse_formula(tokens, blob, env_out, widths=None):
    """Разбирает байты по токенам формулы; возвращает число неизрасходованных байтов."""
    pos = 0
    unknown = 0
    skip = None
    for t in tokens:
        if skip is not None and t == skip:
            skip = None
            continue
        k = tok_kind(t)
        if k[0] == "lit":
            if blob[pos:pos + len(k[1])] != k[1]:
                raise ValueError("литерал формулы не напечатан в начале байтов: %r" % t)
            pos += len(k[1])
        elif k[0] == "byte":
            if pos >= len(blob) or blob[pos] != k[1]:
                raise ValueError("ожидался байт %r на смещении %d" % (t, pos))
            pos += 1
        elif k[0] == "uint":
            env_out[k[1]] = int.from_bytes(blob[pos:pos + k[2]], "little")
            pos += k[2]
        elif k[0] == "lenprefix":
            n = int.from_bytes(blob[pos:pos + 4], "little")
            pos += 4
            s = blob[pos:pos + n].decode("utf-8")
            pos += n
            env_out[t] = s
            env_out[k[1]] = s
            skip = k[1]
        elif k[0] == "field":
            n = (widths or {}).get(t)
            if n is None:
                raise ValueError("ширина поля %r не напечатана в таблице 9.4" % t)
            env_out[t] = hx(blob[pos:pos + n])
            pos += n
        elif k[0] == "call":
            return pos, len(blob) - pos, unknown
        else:
            unknown += 1
            raise ValueError("формула содержит токен, который нечем прочитать: %r" % t)
        if pos > len(blob):
            raise ValueError("формула требует байтов больше, чем напечатано")
    return pos, len(blob) - pos, unknown


def check_submission(doc, spec):
    """Подача: байты из документа разбираются формулой §V9.4 и собираются обратно той же формулой."""
    try:
        toks = formula_tokens(spec, "0x01 " + BAR + " order_ref")
    except ValueError as e:
        fail("SUBMISSION_FORMULA_READ", str(e))
        return
    emit("SUBMISSION_FORMULA_TOKENS", len(toks), "токенов в напечатанной формуле подачи")
    sub_hex = example(doc, "canonical_bytes", "подачи")
    if not sub_hex:
        emit("SUBMISSION_BYTES_PRINTED", 0,
             "в документе векторов нет канонических байтов подачи: submission_ref невоспроизводим")
        _state["bad"] = 1
        return
    emit("SUBMISSION_BYTES_PRINTED", 1)
    vals = {}
    try:
        used, rest, _unknown = parse_formula(toks, bytes.fromhex(sub_hex), vals,
                                             submission_widths(spec))
        check("SUBMISSION_TAIL_OK", rest == 0,
              "разбор формулы израсходовал ровно напечатанные байты")
        again = run_formula(toks, vals)
        check("SUBMISSION_ROUNDTRIP_EQ", again is not None and hx(again) == sub_hex,
              "байты, собранные по той же формуле, равны напечатанным")
        v01 = vector_facts(doc, "V01") or {}
        check("SUBMISSION_REF_EQ", hx(sha(bytes.fromhex(sub_hex))) == v01.get("submission_ref"),
              "sha256 от собранных байт подачи = напечатанный submission_ref")
        emit("SUBMISSION_FIELDS_READ", len(vals), "полей подачи прочитано из байт по формуле")
    except ValueError as e:
        fail("SUBMISSION_PARSE_OK", str(e))


# ---------------------------------------------------------------------------
# 5. Множество файлов §V9.4
# ---------------------------------------------------------------------------

def check_fileset(doc, spec):
    try:
        leaf_toks = formula_tokens(spec, "leaf(path, content) = sha256(")
        root_toks = formula_tokens(spec, "concat(sorted(leaf_i))")
    except ValueError as e:
        fail("FILESET_FORMULA_READ", str(e))
        return
    emit("FILESET_LEAF_TOKENS", len(leaf_toks), "токенов в формуле листа")
    emit("FILESET_ROOT_TOKENS", len(root_toks), "токенов в формуле корня")
    pairs = re.findall(r"^- файл `([^`]+)` sha256 `([0-9a-f]{64})`", doc, re.MULTILINE)
    emit("FILESET_INPUTS_PRINTED", len(pairs),
         "пар «путь + sha256 содержимого» напечатано: без них листья не пересчитать")
    if not pairs:
        _state["bad"] = 1
        return
    printed_leaves = example_all(doc, "листья множества", "hex")
    emit("FILESET_LEAVES_PRINTED", len(printed_leaves),
         "листьев напечатано в разделе «Полный пример»")
    leaves = []
    for (path, content_hash) in pairs:
        env = {"path": path.encode("utf-8"), "sha256(content)": bytes.fromhex(content_hash)}
        body = run_formula(leaf_toks, env)
        if body is None:
            fail("FILESET_LEAF_BUILD", "формула листа не исполняется для пути %r" % path)
            return
        leaves.append(hx(sha(body)))
    if printed_leaves:
        check("FILESET_LEAVES_EQ", sorted(printed_leaves) == sorted(leaves),
              "листья, пересчитанные из напечатанных пар, равны напечатанным листьям")
    else:
        fail("FILESET_LEAVES_PRINTED_MISSING",
             "пар путей и хешей достаточно, но листья не напечатаны — сверка невозможна")
    root_body = run_formula(root_toks, {"concat(sorted(leaf_i))": b"".join(sorted(bytes.fromhex(l) for l in leaves))})
    if root_body is None:
        fail("FILESET_ROOT_BUILD", "формула корня не исполняется")
        return
    printed_root = bullet(doc, "artifact_set_hash подачи")
    v01 = vector_facts(doc, "V01") or {}
    want = v01.get("artifact_set_hash") or printed_root
    check("FILESET_ROOT_EQ", hx(sha(root_body)) == want,
          "корень, пересобранный из напечатанных пар, равен напечатанному artifact_set_hash")


# ---------------------------------------------------------------------------
# 6. Квитанция: канонический JSON, подписываемые байты, вывод вердикта
# ---------------------------------------------------------------------------

def canonical_json(obj):
    """§V9.5: ключи в ASCII-порядке, целые без дроби, разделителей нет."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def spec_json_keys(spec):
    """Список ключей, напечатанный в правиле канонического JSON (§V9.5)."""
    i = spec.index("ровно 13 ключей")
    block = spec[i:spec.index(";", i)]
    block = block[block.index(":"):]
    return re.findall(r"`([a-z][a-z0-9_]*)`", block)


def derive_verdict(receipt, order, allowlist, spec):
    """Правило §V9.5, шаг за шагом, в напечатанном порядке. Возвращает (вердикт, код, выплата)."""
    rules = len(re.findall(r"^(\d+)" + BS + ". ", spec[spec.index("**Правило вывода вердикта**"):
                                                          spec.index("## §V9.6")], re.MULTILINE))
    emit("DERIVE_RULES_PRINTED", rules, "нумерованных правил вывода вердикта в §V9.5")
    if receipt.get("image_digest") != order.get("verifier.image_digest"):
        return None, "E_IMAGE_UNAVAILABLE", False
    if int(receipt.get("budget_ms", -1)) != int(order.get("verifier.budget_seconds", 0)) * 1000:
        return None, "E_ORDER_MALFORMED", False
    if receipt.get("deterministic") is not True:
        return None, "E_RECEIPT_INVALID", False
    axioms = receipt.get("axioms", [])
    if order.get("kind") == "lean_proof":
        if any(a not in allowlist for a in axioms):
            return None, "E_AXIOM_NOT_ALLOWED", False
    elif axioms:
        return None, "E_AXIOM_NOT_ALLOWED", False
    if int(receipt.get("wall_clock_ms", 0)) > int(receipt.get("budget_ms", 0)):
        if int(receipt.get("exit_code", 0)) != 0:
            return "timeout", None, False
        return None, "E_BUDGET_EXCEEDED", False
    if int(receipt.get("exit_code", 1)) == 0:
        return "pass", None, True
    return "fail", None, False


def check_receipt(doc, spec, order):
    f = vector_facts(doc, "V01") or {}
    js = f.get("receipt_canonical_json")
    if not js:
        fail("RECEIPT_JSON_PRINTED", "в V01 нет напечатанного канонического JSON квитанции")
        return
    obj = json.loads(js)
    check("JSON_CANON_EQ", canonical_json(obj) == js,
          "сериализация по §V9.5 повторяет напечатанную байт в байт")
    declared = spec_json_keys(spec)
    emit("RECEIPT_FIELDS", len(obj), "ключей в напечатанном JSON квитанции")
    check("JSON_KEYS_MATCH_RULE", sorted(declared) == sorted(obj.keys()),
          "множество ключей JSON совпадает с перечнем правила §V9.5")
    emit("JSON_FLOAT_FIELDS", sum(1 for v in obj.values() if isinstance(v, float)),
         "дробных чисел в подписываемых байтах быть не должно")
    if any(isinstance(v, float) for v in obj.values()):
        _state["bad"] = 1
    toks = formula_tokens(spec, "canonical_json(receipt)")
    signed = run_formula(toks, {"canonical_json(receipt)": js.encode("utf-8")})
    if signed is None:
        fail("RECEIPT_SIGNED_BUILD", "формула подписываемых байтов квитанции не исполняется")
        return
    emit("RECEIPT_SIGNED_LEN", len(signed), "длина подписываемых байтов, собранная по формуле")
    keys = keypair_convention(doc)
    if keys is None:
        return
    sig = f.get("receipt_signature_hex")
    if sig and obj.get("verifier_pubkey"):
        check("RECEIPT_PUBKEY_EQ", keys.get("верификатор") == obj["verifier_pubkey"],
              "ключ верификатора выводим из напечатанного соглашения о ключах")
        check("RECEIPT_SIGNATURE_VALID",
              ed25519_verify(bytes.fromhex(sig), signed, bytes.fromhex(obj["verifier_pubkey"])),
              "подпись квитанции проходит по её подписываемым байтам")
        bad = bytearray(signed)
        bad[len(bad) // 2] ^= 1
        check("RECEIPT_SIGNATURE_DECOY", not ed25519_verify(bytes.fromhex(sig), bytes(bad),
                                                            bytes.fromhex(obj["verifier_pubkey"])),
              "инвертированный бит в сообщении отвергнут")
    allow_doc = re.findall(r"[A-Za-z_.]+", bullet(doc, "AXIOM_ALLOWLIST") or "")
    # Спека печатает список одной строкой, целиком заключённой в обратные кавычки, поэтому имена
    # читаются как содержимое двойных кавычек; молчаливый ноль здесь означал бы «сверки не было».
    allow_spec = []
    am = re.search(r"^.*AXIOM_ALLOWLIST\s*=\s*\[.*$", spec, re.MULTILINE)
    if am:
        seg = am.group(0)
        allow_spec = re.findall(r'"([A-Za-z_.]+)"', seg) or re.findall(r"`([A-Za-z_.]+)`", seg)
    emit("ALLOWLIST_DOC", "|".join(allow_doc))
    emit("ALLOWLIST_SPEC", "|".join(allow_spec))
    check("ALLOWLIST_SPEC_READ", len(allow_spec) > 0,
          "allowlist прочитан из строки спеки, а не из догадки")
    check("ALLOWLIST_SPEC_VS_DOC_EQ", allow_doc == allow_spec,
          "allowlist в спеке и в документе векторов назван одинаково")
    verdict, code, payout = derive_verdict(obj, order, allow_doc, spec)
    check("VERDICT_DERIVABLE", verdict == f.get("derived_verdict") and code is None,
          "выведено %r (код %r), напечатано %r" % (verdict, code, f.get("derived_verdict")))
    check("PAYOUT_ALLOWED_EQ", str(payout).lower() == str(f.get("payout_allowed")).lower())


# ---------------------------------------------------------------------------
# 7. Ключи и Ed25519
# ---------------------------------------------------------------------------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def inv(x):
    return pow(x, P - 2, P)


def xrecover(y, sign=0):
    """Корень по y с учётом знакового бита 255 (RFC 8032 5.1.3).

    Прежняя версия всегда выбирала чётный корень, из-за чего верификатор отвергал
    любую подпись, у которой R имеет нечётный x, то есть примерно половину честных
    подписей. Ошибка не всплывала, пока само-тест играл одним вектором.
    """
    xx = (y * y - 1) * inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if ((x & 1) != 0) != (sign != 0):
        x = P - x
    if x == 0 and sign:
        raise ValueError("знаковый бит выставлен при x = 0")
    return x


BY = 4 * inv(5) % P
BX = xrecover(BY)
BASE = (BX, BY)


def ed_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    # Скрученная форма Эдвардса с a = -1: -x^2 + y^2 = 1 + d x^2 y^2.
    # Закон сложения (Bernstein-Lange): x3 = (x1 y2 + y1 x2)/(1 + d x1 x2 y1 y2),
    # y3 = (y1 y2 - a x1 x2)/(1 - d x1 x2 y1 y2) = (y1 y2 + x1 x2)/(1 - d x1 x2 y1 y2).
    x = (x1 * y2 + y1 * x2) * inv(1 + D * x1 * x2 * y1 * y2)
    y = (y1 * y2 + x1 * x2) * inv(1 - D * x1 * x2 * y1 * y2)
    return (x % P, y % P)


def ed_mul(s, p):
    r = (0, 1)
    while s:
        if s & 1:
            r = ed_add(r, p)
        p = ed_add(p, p)
        s >>= 1
    return r


def ed_encode(pnt):
    x, y = pnt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decode_pnt(b):
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    x = xrecover(y, (b[31] >> 7) & 1)
    pnt = (x, y)
    if ed_encode(pnt) != b:
        raise ValueError("точка не приведена к канонической форме")
    return pnt


def sha512_int(b):
    return int.from_bytes(hashlib.sha512(b).digest(), "little")


def ed25519_verify(sig, msg, pk):
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        r = decode_pnt(sig[:32])
        a = decode_pnt(pk)
    except (ValueError, ZeroDivisionError):
        return False
    if int.from_bytes(sig[32:], "little") >= L:
        return False
    h = sha512_int(sig[:32] + pk + msg)
    left = ed_mul(int.from_bytes(sig[32:], "little"), BASE)
    right = ed_add(r, ed_mul(h, a))
    return ed_encode(left) == ed_encode(right)


def clamp(a):
    """Приведение скаляра по RFC 8032 6.1: обнулить три низших бита, выставить 254-й, снять 255-й."""
    return (a & ~7 & ((1 << 255) - 1)) | (1 << 254)


def ed25519_pubkey(seed):
    h = hashlib.sha512(seed).digest()
    a = clamp(int.from_bytes(h[:32], "little"))
    return ed_encode(ed_mul(a, BASE))


def ed25519_sign(msg, seed):
    h = hashlib.sha512(seed).digest()
    a = clamp(int.from_bytes(h[:32], "little"))
    pk = ed_encode(ed_mul(a, BASE))
    r = sha512_int(h[32:] + msg)
    rr = ed_encode(ed_mul(r, BASE))
    k = sha512_int(rr + pk + msg)
    s = (r + k * a) % L
    return rr + s.to_bytes(32, "little")


RFC8032_TEST1 = {
    "seed": bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    "pk": bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    "sig": bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    "msg": b"",
}


def check_ed25519_selftest():
    """Верификатор обязан проходить на опубликованном векторе того же RFC и отвергать посадку."""
    v = RFC8032_TEST1
    check("RFC8032_PUBKEY_EQ", hx(ed25519_pubkey(v["seed"])) == v["pk"].hex())
    check("RFC8032_VERIFY", ed25519_verify(v["sig"], v["msg"], v["pk"]))
    check("RFC8032_SIGN_EQ", hx(ed25519_sign(v["msg"], v["seed"])) == v["sig"].hex())
    bad = bytearray(v["msg"]) + b"\x01"
    check("RFC8032_DECOY_REJECTED", not ed25519_verify(v["sig"], bytes(bad), v["pk"]))
    # Один вектор не ловит выбор корня по знаковому биту: он проверяет ровно одну чётность x
    # у точки R. Прогоняем сетку seed x длина сообщения и требуем увидеть обе чётности.
    n = odd = even = ok = 0
    for seed in range(1, 17):
        sk = bytes([seed]) + b"\x00" * 30 + bytes([seed ^ 0xA5])
        pk = ed25519_pubkey(sk)
        for ln in (0, 1, 31, 32, 33, 63, 64, 128):
            msg = bytes((seed * 7 + i) % 251 for i in range(ln))
            sig = ed25519_sign(msg, sk)
            n += 1
            if sig[31] >> 7:
                odd += 1
            else:
                even += 1
            if ed25519_verify(sig, msg, pk):
                ok += 1
    emit("RFC8032_SWEEP_SIGS", n, "подписей в сетке само-теста")
    emit("RFC8032_SWEEP_ODD_X", odd, "подписей с нечётным x у точки R")
    emit("RFC8032_SWEEP_EVEN_X", even, "подписей с чётным x у точки R")
    check("RFC8032_SWEEP_ALL_VERIFY", ok == n,
          "верификатор принимает все подписи сетки (ловит выбор корня по знаковому биту)")
    check("RFC8032_SWEEP_BOTH_PARITIES", odd > 0 and even > 0,
          "само-тест покрывает обе чётности x, иначе одна ветка декодирования не проверена")


def keypair_convention(doc):
    """Соглашение о ключах напечатано в разделе «Общие входы»: seed в первый байт,
    seed xor 0xa5 в последний. Выводим из него публичные ключи и сверяем с напечатанными."""
    m = re.search(r"ключи: издатель seed = (\d+), подающий seed = (\d+), верификатор seed = (\d+)", doc)
    conv = re.search("seed xor (" + "0x[0-9a-fA-F]{2}" + ")", doc)
    emit("KEYPAIR_LAYOUT_WORDS", 1 if "первый байт" in doc and "последний" in doc else 0,
         "в документе напечатано, куда кладётся seed и что идёт в последний байт")
    if not m or not conv or "первый байт" not in doc:
        emit("KEYPAIR_CONVENTION_PRINTED", 0,
             "в документе нет напечатанного соглашения о ключах: подпись нельзя проверить без секретного ключа")
        _state["bad"] = 1
        return None
    emit("KEYPAIR_CONVENTION_PRINTED", 1)
    mask = int(conv.group(1), 16)
    names = ("издатель", "подающий", "верификатор")
    pub = {}
    for role, s in zip(names, [int(x) for x in m.groups()]):
        seed = bytes([s]) + b"\x00" * 30 + bytes([s ^ mask])
        pub[role] = hx(ed25519_pubkey(seed))
    check("PUBKEY_PUBLISHER_EQ", pub["издатель"] == bullet(doc, "publisher"),
          "ключ издателя выводим из напечатанного соглашения")
    return pub


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv):
    global SPEC
    doc_path = argv[1] if len(argv) > 1 else "docs/PAID_ORDER-VECTORS.md"
    spec_path = argv[2] if len(argv) > 2 else "docs/VecDHT-SPEC-v9.md"
    for pth in (doc_path, spec_path):
        if not os.path.isfile(pth):
            return abort("нет входа " + pth)
    doc = open(doc_path, encoding="utf-8").read()
    SPEC = spec = open(spec_path, encoding="utf-8").read()

    emit("TOOLCHAIN", sys.version.split()[0], "реализация, пересобирающая байты")
    emit("UNICODE_DATA", unicodedata.unidata_version, "версия Unicode-данных у этой реализации")

    try:
        read_spec_constants(spec)
        check_domain(spec)
        check_examples(doc, spec)

        v01 = vector_facts(doc, "V01")
        if v01 is None:
            return abort("вектор V01 не найден в документе")
        order = order_inputs(doc, v01)
        rebuilt = build_record(spec, order)
        printed = v01.get("canonical_record_hex", "")
        emit("RECORD_REBUILT_LEN", len(rebuilt))
        emit("RECORD_PRINTED_LEN", len(bytes.fromhex(printed)))
        check("RECORD_LEN_EQ", len(rebuilt) == len(bytes.fromhex(printed)))
        check("RECORD_EQ_DOC", hx(rebuilt) == printed,
              "байты, собранные по таблице §V9.2, равны напечатанным")
        if hx(rebuilt) != printed:
            d = first_diff(rebuilt, bytes.fromhex(printed))
            emit("RECORD_FIRST_DIFF_OFFSET", d)
            emit("RECORD_FIRST_DIFF_REBUILT", rebuilt[d:d + 8].hex())
            emit("RECORD_FIRST_DIFF_PRINTED", bytes.fromhex(printed)[d:d + 8].hex())
        check("ORDER_REF_EQ", hx(sha(rebuilt)) == v01.get("order_ref"),
              "sha256 от собранных байт = напечатанный order_ref")
        keys = keypair_convention(doc)
        if keys:
            sig = v01.get("order_signature_hex")
            if sig:
                check("ORDER_SIGNATURE_VALID",
                      ed25519_verify(bytes.fromhex(sig), rebuilt, bytes.fromhex(keys["издатель"])),
                      "подпись заказа проходит по байтам, собранным из спеки")
                bad = bytearray(rebuilt)
                bad[len(bad) // 2] ^= 1
                check("ORDER_SIGNATURE_DECOY",
                      not ed25519_verify(bytes.fromhex(sig), bytes(bad), bytes.fromhex(keys["издатель"])))
                printed_bytes = bytes.fromhex(printed)
                check("ORDER_SIG_OVER_PRINTED",
                      ed25519_verify(bytes.fromhex(sig), printed_bytes,
                                     bytes.fromhex(keys["издатель"])),
                      "подпись проходит над напечатанными байтами записи, то есть кодирование верное")
                check("ORDER_REF_OVER_PRINTED",
                      hx(sha(printed_bytes)) == v01.get("order_ref"),
                      "order_ref = sha256 от напечатанных байтов записи")

        check_submission(doc, spec)
        check_fileset(doc, spec)
        check_receipt(doc, spec, order)
        check_ed25519_selftest()
    except Exception as e:
        if os.environ.get("V913_DEBUG"):
            import traceback
            traceback.print_exc()
        return abort("%s: %s" % (type(e).__name__, e))

    emit("WORST", _state["bad"])
    emit("ALL_OK", 1 if _state["bad"] == 0 else 0)
    return _state["bad"]


def order_inputs(doc, v01):
    """Значения полей заказа из напечатанных общих входов; имена - из таблицы §V9.2."""
    amount = re.search(r"^- награда: (\d+) минимальных единиц, актив `([a-z_]+)` \(цепь (\d+)\)",
                       doc, re.MULTILINE)
    budget = re.search("^- бюджет: ([0-9]+) с", doc, re.MULTILINE)
    deadline = bullet(doc, "deadline")
    asset = None
    if amount:
        asset = {"kind": amount.group(2), "chain_id": int(amount.group(3)), "address": ""}
    return {
        "kind": v01.get("kind"),
        "statement_hash": v01.get("statement_hash"),
        "verifier.image_digest": bullet(doc, "образ"),
        "verifier.entrypoint": bullet(doc, "entrypoint"),
        "verifier.budget_seconds": int(budget.group(1)) if budget else None,
        "verifier.network": bullet(doc, "network"),
        "reward.amount": int(amount.group(1)) if amount else None,
        "reward.asset": asset,
        "reward.escrow_ref": bullet(doc, "escrow_ref"),
        "deadline": int(deadline.split()[0]) if deadline else None,
        "submit_limit": int(bullet(doc, "submit_limit")) if bullet(doc, "submit_limit") else None,
        "publisher": bullet(doc, "publisher"),
        "nonce": int(bullet(doc, "nonce заказа")) if bullet(doc, "nonce заказа") else None,
    }


SPEC = None

if __name__ == "__main__":
    sys.exit(main(sys.argv))
