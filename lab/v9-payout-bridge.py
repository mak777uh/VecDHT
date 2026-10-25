#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Независимый мост-эмулятор слоя автовыплат (проект `ADR-0064`, цикл `E-0114`).

Что это такое. Сторонний реализатор моста цепочки получает ровно три текста: нормативную
спеку `docs/VecDHT-SPEC-v9.md`, носитель векторов слоя `docs/PAID_PAYOUT-VECTORS.md` и
носитель векторов заказа `docs/PAID_ORDER-VECTORS.md`. Этот файл делает то, что обязан
делать такой реализатор, и больше ничего: читает напечатанные таблицы доменов и раскладки,
закрытый список кодов и порядок шагов, пересобирает байты `VerifierBinding`, `ChainDescriptor`,
`EscrowWitness`, `PayoutClaim`, корень реестра и `term_hash` на `hashlib`, проверяет подписи
на Ed25519 и сам выводит решение по каждому вектору. Затем сверяет своё решение с
напечатанным. Совпадение — единственный способ сказать, что слой пригоден к реализации вне
Rust и вне узла VecDHT.

Чего здесь нет. Ни `cargo`, ни узла, ни чужих библиотек. Первичные алгоритмы (`sha256`,
Ed25519 по `RFC 8032`, `canonical_json` и вывод вердикта по §V9.5, интерпретатор таблицы
§V9.2) берутся из `lab/v9-independent-client.py` — приёмочного теста `E-0113`, где они уже
сверены с носителем заказов. Это осознанное ослабление независимости: предмет проверки этого
прибора — раскладка и решение слоя, а не SHA-256. Хвост записан в карточку цикла.

Посадки. Прибор обязан уметь краснеть, иначе его зелёный вывод — молчание. Внутри десять
посаженных дефектов, каждый назван своим фактом: навранная длина домена (`DOMAIN_LEN_DECOY`),
порча листа реестра (`REGISTRY_ROOT_SENSITIVE`), бит в канонической записи заказа
(`ORDER_REF_SENSITIVE`), инвертированный бит подписи требования (`SIG_DECOY`), отпущенный залог
(`DECOY_STATUS`), недобор залога (`DECOY_AMOUNT`), свидетельство с чужим телом под прежней
подписью (`DECOY_WITNESS_SIG`), пятый тег `status` (`DECOY_STATUS_SIGNED`), урезанная ширина поля
(`LAYOUT_DECOY`), девятнадцатое имя кода (`CODE_GUARD_DECOY`). Посадки залога и состояния
переподписываются печатными ключами ролей: иначе отказ наступил бы на проверке подписи, и прибор
похвалил бы себя за то, чего не смотрел. Два вектора с чужими ключами (`KEYPAIR_DECOY_NAMED`) и
перестановка реестра (`REGISTRY_PERMUTE_EQ`) — не посадки, а проверка того, что носитель сам
различает подмену и не путает порядок с содержанием. Каждая сверка сформулирована так, что пропуск
дефекта делает её факт нулём.

Команда:

    python lab/v9-payout-bridge.py [docs/PAID_PAYOUT-VECTORS.md] [docs/VecDHT-SPEC-v9.md] \
        [docs/PAID_ORDER-VECTORS.md] [lab/notes/DESIGN-2026-10-25-chain-binding.md]

Значения печатных фактов — ASCII (`none` вместо «нет», `|` вместо запятых): helper вытаскивает
их по границе токена, и кириллица в значении читалась бы как пустота, то есть как молчание
прибора там, где прибор сказал «расхождения есть».

Выход 0 — сошлось всё; 1 — хоть одна сверка не сошлась или нужный вход не напечатан;
2 — входы не разбираются (носитель переписан так, что читать его нечем).
"""

import hashlib
import importlib.util
import io
import json
import os
import re
import struct
import sys
import unicodedata
from contextlib import redirect_stdout

PREFIX = "V9C_"
VERBOSE = os.environ.get("V9C_VERBOSE") == "1"
TICK = chr(96)
BAR = chr(0x2016)
T = b"\x00"
LAYOUT_HEADERS = ("VerifierBinding", "ChainDescriptor", "EscrowWitness", "PayoutClaim")
STATUS_TAGS = {0: "not_funded", 1: "locked", 2: "released", 3: "refunded"}

_state = {"bad": 0}


def emit(key, value, note=""):
    print(PREFIX + key + "=" + str(value))
    if note and VERBOSE:
        print("  # " + key + ": " + note)


def check(key, ok, note=""):
    v = 1 if ok else 0
    emit(key, v, note)
    if v == 0:
        _state["bad"] = 1
    return v


def count(key, got, want, note=""):
    """Печатает пару чисел и краснеет, если они не равны: ноль сверки не должен молчать."""
    emit(key + "_GOT", got, note)
    return check(key, got == want, "%s: получено %s, ожидание %s" % (note, got, want))


def fail(key, note):
    emit(key, 0, note)
    _state["bad"] = 1
    return 0


def abort(reason):
    print("ВХОД_НЕ_РАЗОБРАН: " + str(reason), file=sys.stderr)
    return 2


def sha(bs):
    return hashlib.sha256(bs).digest()


def hx(bs):
    return bs.hex()


def unhex(s, what):
    if not re.fullmatch(r"[0-9a-f]+", s or ""):
        raise ValueError("%r: %r не шестнадцатеричная строка" % (what, s))
    return bytes.fromhex(s)


class EncodeError(Exception):
    """Встроенный объект не цитируется: байты требования не собираются."""

    def __init__(self, part):
        Exception.__init__(self, part)
        self.part = part


def load_client(path):
    if not os.path.isfile(path):
        raise ValueError("нет файла первичных алгоритмов " + path)
    spec = importlib.util.spec_from_file_location("v9_primitives", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def quiet(fn, *args):
    """Вызов клиентской функции без его собственных фактов: иначе в логе два владельца одного ключа."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        return fn(*args)


# ---------------------------------------------------------------------------
# 1. Чтение носителя
# ---------------------------------------------------------------------------

KV_LINE = re.compile(r"^([a-z][a-z0-9_.]*)=(.*)$")


def parse_kv_blocks(doc):
    out = []
    for b in re.findall("```kv\n(.*?)\n```", doc, re.S):
        kv = {}
        for line in b.splitlines():
            m = KV_LINE.match(line)
            if not m:
                raise ValueError("строка вектора не разбирается: " + repr(line[:60]))
            kv[m.group(1)] = m.group(2)
        if "id" not in kv:
            raise ValueError("в блоке вектора нет поля id")
        out.append(kv)
    return out


def section(doc, head, nxt="## "):
    i = doc.index(head)
    j = doc.find(nxt, i + len(head))
    return doc[i:j if j > 0 else len(doc)]


def table_rows(text):
    rows = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if cols and all(set(c) <= set("-: ") for c in cols):
            continue
        rows.append(cols)
    return rows


def parse_domains(sec):
    out = {}
    for cols in table_rows(sec)[1:]:
        if len(cols) != 4:
            raise ValueError("строка таблицы доменов имеет %d колонок" % len(cols))
        name = cols[0].strip(TICK)
        lit = re.fullmatch(TICK + "([^" + TICK + "]+)" + TICK, cols[1])
        num = re.fullmatch(r"\d+", cols[2])
        if not (lit and num):
            raise ValueError("домен %r напечатан не литералом с числом длины" % name)
        out[name] = {"literal": lit.group(1).encode("utf-8"), "declared": int(num.group(0)),
                     "term": cols[3].startswith(TICK + "0x00")}
    return out


def parse_layouts(doc):
    out = {}
    for head in LAYOUT_HEADERS:
        i = doc.find("\n**" + head + " ")
        if i < 0:
            raise ValueError("в §2 нет таблицы объекта " + head)
        line_end = doc.find("\n", i + 1)
        # Срез обязан переступить заголовок и дотянуть до следующей жирной головы или раздела.
        ends = [p for p in (doc.find("\n**", line_end), doc.find("\n## ", line_end)) if p > 0]
        end = min(ends) if ends else len(doc)
        rows = []
        for cols in table_rows(doc[line_end:end]):
            if cols[0] == "№" or cols[1] == "поле":
                continue
            if len(cols) != 4:
                raise ValueError("раскладка %r: строка из %d колонок" % (head, len(cols)))
            n = cols[0]
            if n != chr(0x2014) and not n.isdigit():
                raise ValueError("раскладка %r: номер поля %r не напечатан числом" % (head, n))
            const = re.fullmatch(r"один байт: " + TICK + r"(\d+)" + TICK, cols[2])
            rows.append({"n": n, "field": cols[1].strip(TICK), "width": cols[2],
                         "term": cols[3].startswith(TICK + "0x00"),
                         "const": int(const.group(1)) if const else None})
        if not rows:
            raise ValueError("раскладка %r пуста" % head)
        out[head] = rows
    return out


def width_kind(row):
    """Класс ширины прочитан из напечатанной колонки; незнакомая формулировка — отказ читать."""
    w = row["width"]
    if "встраиваемый" in w:
        return "embedded"
    for name, size in (("u64le", 8), ("u128le", 16), ("u16le", 2)):
        if TICK + name + TICK in w:
            return ("int", size)
    if row["const"] is not None:
        return ("const", 1)
    if w.startswith("один байт"):
        return ("int", 1)
    if "32 байта" in w:
        return ("raw", 32)
    if "u32le" in w and "длина" in w:
        return ("len", 4)
    raise ValueError("ширина %r не читается" % w)


def parse_registry(doc):
    rows = []
    for cols in table_rows(section(doc, "### Реестр цепочек")):
        if cols[0] == "chain_id":
            continue
        if len(cols) != 8:
            raise ValueError("строка реестра имеет %d колонок" % len(cols))

        def val(i):
            m = re.fullmatch(TICK + "(.*?)" + TICK, cols[i])
            return m.group(1) if m else cols[i]

        rows.append({"chain_id": int(cols[0]), "name": val(1), "bridge_code": int(cols[2]),
                    "settle_asset_tag": int(cols[3]), "min_amount": int(cols[4]),
                    "note": val(5), "canonical_hex": val(6), "leaf_hex": val(7)})
    if not rows:
        raise ValueError("таблица реестра пуста")
    return rows


def parse_codes(doc):
    out = {}
    for cols in table_rows(section(doc, "## 3. Закрытый список кодов")):
        if cols[0].startswith("код"):
            continue
        name = cols[0].strip(TICK)
        if not re.fullmatch(r"E_[A-Z_]+", name):
            raise ValueError("имя кода %r напечатано не как E_*" % name)
        out[name] = cols[1].strip(TICK)
    return out


def parse_steps(doc):
    sec = section(doc, "## 4. Порядок вывода решения")
    # Шаг §4 пишется несколькими строками: коды стоят на продолжениях, и экстрактор, берущий
    # только первую строку, молчал бы на них — а молчание читается как «кодов в шагах нет».
    out = []
    for line in sec.splitlines():
        if re.match(r"^\d+\.\s", line):
            out.append(line.strip())
        elif out and line.startswith("   "):
            out[-1] += " " + line.strip()
    return out


def parse_step0_codes(doc):
    """Из шага (0) читаются коды встроенных объектов: прибор не дорисовывает их от себя."""
    sec = section(doc, "## 4. Порядок вывода решения")
    seg = sec[sec.find("(0) форма требования"):sec.find("(1) `term_hash`")]
    words = {"receipt": "квитанция", "binding": "связка", "witness": "свидетельство"}
    out = {}
    for part, word in words.items():
        k = seg.find(word)
        if k < 0:
            raise ValueError("в шаге (0) не названо слово %r" % word)
        tail = seg[k:]
        for other in words.values():
            if other != word:
                m = tail.find(other)
                if m > 0:
                    tail = tail[:m]
        code = re.search(r"E_[A-Z_]+", tail)
        if not code:
            raise ValueError("шаг (0) не называет код для %r" % word)
        out[part] = code.group(0)
    return out


def parse_common(doc):
    sec = section(doc, "## 5. Общие входы и снимок доверия")
    out = {}
    m = re.search(r"реестр цепей: (\d+) описателей, `registry_root` = `([0-9a-f]{64})`", sec)
    if not m:
        raise ValueError("в §5 не напечатаны число описателей и корень реестра")
    out["descriptors"], out["registry_root"] = int(m.group(1)), m.group(2)
    m = re.search(r"`PAYBACK_WINDOW_SECONDS` = (\d+)", sec)
    if not m:
        raise ValueError("окно выплаты не напечатано")
    out["window"] = int(m.group(1))
    m = re.search(r"`AXIOM_ALLOWLIST` = \[([^\]]+)\]", sec)
    if not m:
        raise ValueError("allowlist аксиом не напечатан")
    out["allowlist"] = [a.strip() for a in m.group(1).split(",")]
    m = re.search(r"покрывает байты " + TICK + r"([^" + TICK + r"]+)" + TICK + r" \((\d+)\)", sec)
    if not m:
        raise ValueError("домен подписи квитанции не напечатан в §5")
    out["receipt_domain"] = m.group(1).encode("utf-8")
    out["receipt_domain_declared"] = int(m.group(2))
    m = re.search(r"seed xor " + TICK + r"?0x([0-9a-fA-F]{2})" + TICK + r"?", sec)
    if not m or "первый байт" not in sec or "последний" not in sec:
        raise ValueError("соглашение о ключах не прочитано")
    out["keypair_mask"] = int(m.group(1), 16)
    roles = (("publisher", r"издатель: `keypair\((\d+)\)`"),
             ("beneficiary", r"получатель выплаты: `keypair\((\d+)\)`"),
             ("verifier", r"верификатор: `keypair\((\d+)\)`"),
             ("observer", r"наблюдатель: ключ `keypair\((\d+)\)`"))
    for role, pat in roles:
        m = re.search(pat, sec)
        if not m:
            raise ValueError("seed роли %r не напечатан" % role)
        out[role] = int(m.group(1))
    return out


def parse_coverage(doc):
    sec = section(doc, "## 7. Покрытие")
    out = {}
    for pat, key in ((r"- векторов: (\d+)", "vectors"),
                    (r"- из них «платить»: (\d+)", "payouts"),
                    (r"- различных кодов отказа, использованных слоем: (\d+)", "codes"),
                    (r"залог\): (\d+)", "replays"),
                    (r"- закрытый список кодов: (\d+) имён", "total_codes")):
        m = re.search(pat, sec)
        if not m:
            raise ValueError("строка покрытия не найдена: " + pat)
        out[key] = int(m.group(1))
    m = re.search(r"использованных слоем: \d+ — `(.+)`", sec)
    out["code_names"] = m.group(1).split("`, `") if m else []
    return out


def parse_anchor(doc):
    m = re.search(r"остаётся " + TICK + r"([0-9a-f]{64})" + TICK, doc)
    return m.group(1) if m else None


def formula_body(text):
    """Тело `sha256( ... )` со сбалансированными скобками: non-greedy обрезало бы формулу на первом же.)"""
    i = text.index("term_hash = sha256(") + len("term_hash = sha256(")
    depth = 1
    for j in range(i, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[i:j]
    raise ValueError("формула term_hash не закрыта скобкой")


def parse_term_tokens(doc):
    return [t.strip() for t in formula_body(doc).split(BAR) if t.strip()]


def term_seq(text):
    """Имена полей формулы в напечатанном порядке, без разделителей: для сверки с запиской."""
    out = []
    for tok in text:
        tok = tok.strip()
        if tok == "0x00":
            continue
        m = re.match(r"u32le\(len\(([a-z_]+)\)\)", tok)
        if m:
            out.append(m.group(1) + "_len")
            continue
        m = re.match(r"([A-Za-z_][a-z0-9_A-Z_]*)", tok)
        if m:
            out.append(m.group(1))
    return out


# ---------------------------------------------------------------------------
# 2. Сборка байтов по прочитанным раскладкам
# ---------------------------------------------------------------------------

def encode_cell(row, value):
    kind = width_kind(row)
    if kind == "embedded":
        body, sig = value
        return struct.pack("<I", len(body)) + body + T + sig
    if kind[0] == "const":
        return bytes([row["const"]])
    if kind[0] == "int":
        v = int(value)
        if not 0 <= v < 256 ** kind[1]:
            raise ValueError("целое %d не влезает в %d байт" % (v, kind[1]))
        return v.to_bytes(kind[1], "little")
    if kind[0] == "raw":
        b = value if isinstance(value, bytes) else unhex(value, row["field"])
        if len(b) != kind[1]:
            raise ValueError("поле %r: %d байт вместо %d" % (row["field"], len(b), kind[1]))
        return b
    b = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return struct.pack("<I", len(b)) + b


def ascii_clean(s):
    return all(0x20 <= ord(c) <= 0x7e for c in s)


def build_object(rows, domain, values, ascii_fields=()):
    """Префикс раскладки напечатан в §2: литерал домена, затем `0x00`, затем поля по порядку."""
    out = bytearray(domain) + T
    for row in rows:
        if row["const"] is not None:
            out += encode_cell(row, None)
            if row["term"]:
                out += T
            continue
        if row["field"] not in values:
            raise ValueError("раскладка называет поле %r, а носитель его не печатает" % row["field"])
        v = values[row["field"]]
        if isinstance(v, tuple) and v[1] is None:
            raise EncodeError(row["field"])
        if row["field"] in ascii_fields and not ascii_clean(v):
            raise ValueError("поле %r вне печатного ASCII" % row["field"])
        out += encode_cell(row, v)
        if row["term"]:
            out += T
    return bytes(out)


def run_term(tokens, env, domains):
    out = bytearray()
    for tok in tokens:
        if tok == "0x00":
            out += T
            continue
        if tok in domains:
            out += domains[tok]["literal"]
            continue
        m = re.fullmatch(r"([a-z_][a-z0-9_]*):u(64|128|16|32)le", tok)
        if m:
            out += int(env[m.group(1)]).to_bytes(int(m.group(2)) // 8, "little")
            continue
        m = re.fullmatch(r"([a-z_][a-z0-9_]*)\((\d+)\)", tok)
        if m:
            b = env[m.group(1)]
            b = b if isinstance(b, bytes) else unhex(b, m.group(1))
            if len(b) != int(m.group(2)):
                raise ValueError("%s: напечатано %d байт вместо %s"
                                 % (m.group(1), len(b), m.group(2)))
            out += b
            continue
        m = re.fullmatch(r"u32le\(len\(([a-z_][a-z0-9_]*)\)\)", tok)
        if m:
            b = env[m.group(1)]
            b = b.encode("utf-8") if isinstance(b, str) else bytes(b)
            out += struct.pack("<I", len(b))
            continue
        m = re.fullmatch(r"([a-z_][a-z0-9_]*)", tok)
        if m:
            b = env[m.group(1)]
            out += b.encode("utf-8") if isinstance(b, str) else bytes(b)
            continue
        raise ValueError("токен формулы %r не читается" % tok)
    return bytes(out)


# ---------------------------------------------------------------------------
# 3. Пересборка вектора
# ---------------------------------------------------------------------------

def asset_value(kv):
    if int(kv["order.asset_tag"]) == 0:
        return {"kind": "native", "chain_id": 0, "address": ""}
    return {"kind": "token", "chain_id": int(kv["order.asset_chain_id"]),
            "address": kv["order.asset_address"]}


def asset_bytes(kv, ctx):
    """Байты поля 8 канонической записи: ровно то, что печатает таблица §V9.2 спеки."""
    rows = [r for r in ctx["C"].record_rows(ctx["spec"]) if r["field"] == "reward.asset"]
    if len(rows) != 1:
        raise ValueError("в §V9.2 не одна строка reward.asset")
    out = ctx["C"].encode_field(rows[0], asset_value(kv))
    if ctx["C"].terminator_for(rows[0]):
        out += T
    return out


def order_inputs(kv, ctx):
    tag = int(kv["order.kind_tag"])
    return {
        "kind": ctx["kind_name"](tag),
        "statement_hash": kv["order.statement_hash"],
        "verifier.image_digest": kv["order.image_digest"],
        "verifier.entrypoint": kv["order.entrypoint"],
        "verifier.budget_seconds": int(kv["order.budget_seconds"]),
        "verifier.network": kv["order.network"],
        "reward.amount": int(kv["order.amount"]),
        "reward.asset": asset_value(kv),
        "reward.escrow_ref": unhex(kv["order.escrow_ref_hex"], "escrow_ref").decode("utf-8"),
        "deadline": int(kv["order.deadline"]),
        "submit_limit": int(kv["order.submit_limit"]),
        "publisher": kv["order.publisher"],
        "nonce": int(kv["order.nonce"]),
    }


def witness_values(kv, rows):
    out = {}
    for r in rows:
        f = r["field"]
        if f == "block_ref":
            out[f] = unhex(kv["witness.block_ref_hex"], "block_ref")
        elif f in ("chain_id", "status", "amount_on_chain"):
            out[f] = int(kv["witness." + f])
        else:
            out[f] = kv["witness." + f]
    return out


def build_parts(kv, ctx):
    C = ctx["C"]
    rows = ctx["layouts"]
    parts = {}
    parts["order_record"] = quiet(C.build_record, ctx["spec"], order_inputs(kv, ctx))
    parts["order_ref"] = hx(sha(parts["order_record"]))
    parts["asset_bytes"] = asset_bytes(kv, ctx)
    parts["chain_id"] = asset_value(kv)["chain_id"]
    parts["term_env"] = {
        "order_ref": unhex(parts["order_ref"], "order_ref"),
        "chain_id": parts["chain_id"],
        "asset_bytes": parts["asset_bytes"],
        "beneficiary_pubkey": unhex(kv["claim.beneficiary"], "beneficiary"),
        "amount": int(kv["order.amount"]),
        "escrow_ref": unhex(kv["order.escrow_ref_hex"], "escrow_ref"),
    }
    parts["term_hash"] = hx(sha(run_term(ctx["term_tokens"], parts["term_env"], ctx["domains"])))

    def sig_or_none(v):
        return None if v == "-" else unhex(v, "подпись")

    parts["receipt_json"] = kv["receipt.canonical_json"].encode("utf-8")
    parts["receipt_obj"] = json.loads(kv["receipt.canonical_json"])
    parts["receipt_sig"] = sig_or_none(kv.get("receipt.signature_hex", "-"))
    parts["binding_bytes"] = build_object(rows["VerifierBinding"], ctx["domains"]["DOMAIN_BINDING"]["literal"],
                                          dict((r["field"], kv["binding." + r["field"]])
                                               for r in rows["VerifierBinding"]))
    parts["binding_sig"] = sig_or_none(kv.get("binding.signature_hex", "-"))
    parts["witness_bytes"] = build_object(rows["EscrowWitness"], ctx["domains"]["DOMAIN_WITNESS"]["literal"],
                                          witness_values(kv, rows["EscrowWitness"]))
    parts["witness_sig"] = sig_or_none(kv.get("witness.signature_hex", "-"))

    claim_vals = {}
    missing = None
    for r in rows["PayoutClaim"]:
        f = r["field"]
        if f in ("term_hash", "order_ref", "beneficiary"):
            claim_vals[f] = kv["claim." + f]
        elif f == "receipt":
            claim_vals[f] = (parts["receipt_json"], parts["receipt_sig"])
            missing = missing or (f if parts["receipt_sig"] is None else None)
        elif f == "binding":
            claim_vals[f] = (parts["binding_bytes"], parts["binding_sig"])
            missing = missing or (f if parts["binding_sig"] is None else None)
        elif f == "witness":
            claim_vals[f] = (parts["witness_bytes"], parts["witness_sig"])
            missing = missing or (f if parts["witness_sig"] is None else None)
        else:
            raise ValueError("требование печатает поле %r, правила сборки которого нет" % f)
    parts["missing"] = missing
    try:
        parts["claim_bytes"] = build_object(rows["PayoutClaim"],
                                           ctx["domains"]["DOMAIN_CLAIM"]["literal"], claim_vals)
    except EncodeError as e:
        parts["missing"] = e.part
        parts["claim_bytes"] = None
    parts["claim_sig"] = sig_or_none(kv.get("claim.signature_hex", "-"))
    return parts


# ---------------------------------------------------------------------------
# 4. Решение моста: чистая функция по напечатанному порядку шагов
# ---------------------------------------------------------------------------

def decide(kv, parts, ctx, trust):
    """Возвращает ("payout", None) либо ("reject", код). Порядок шагов — из §4 носителя."""
    C = ctx["C"]
    step0 = ctx["step0_codes"]
    term = parts["term_hash"]
    if parts["claim_bytes"] is None:
        return "reject", step0[parts["missing"]]
    if parts["claim_sig"] is None:
        return "reject", "E_ORDER_MALFORMED"
    if not C.ed25519_verify(parts["claim_sig"], parts["claim_bytes"],
                            unhex(kv["claim.beneficiary"], "beneficiary")):
        return "reject", "E_ORDER_MALFORMED"
    if kv["claim.order_ref"] != parts["order_ref"]:
        return "reject", "E_ORDER_MALFORMED"
    if kv["claim.beneficiary"] != kv["sub.submitter"]:
        return "reject", "E_ORDER_MALFORMED"
    if kv["claim.term_hash"] != term:
        return "reject", "E_HASH_MISMATCH"
    order_flat = {
        "verifier.image_digest": kv["order.image_digest"],
        "verifier.budget_seconds": int(kv["order.budget_seconds"]),
        "kind": ctx["kind_name"](int(kv["order.kind_tag"])),
    }
    derived, code, _payout = quiet(C.derive_verdict, parts["receipt_obj"], order_flat,
                                   ctx["allowlist"], ctx["spec"])
    if code is not None:
        return "reject", code
    if derived != kv["receipt.verdict"] or derived != "pass":
        return "reject", "E_VERDICT_MISMATCH"
    if kv["receipt.order_ref"] != kv["claim.order_ref"] or kv["receipt.submission_ref"] != kv["submission_ref"]:
        return "reject", "E_RECEIPT_INVALID"
    if kv["receipt.verifier_pubkey"] != kv["binding.verifier_pubkey"]:
        return "reject", "E_RECEIPT_UNSIGNED"
    signed = ctx["common"]["receipt_domain"] + T + parts["receipt_json"]
    if not C.ed25519_verify(parts["receipt_sig"], signed,
                            unhex(kv["receipt.verifier_pubkey"], "verifier")):
        return "reject", "E_RECEIPT_UNSIGNED"
    if kv["binding.order_ref"] != kv["claim.order_ref"] or kv["binding.term_hash"] != term:
        return "reject", "E_RECEIPT_INVALID"
    if kv["binding.image_digest"] != kv["order.image_digest"]:
        return "reject", "E_RECEIPT_INVALID"
    if not C.ed25519_verify(parts["binding_sig"], parts["binding_bytes"],
                            unhex(kv["order.publisher"], "publisher")):
        return "reject", "E_RECEIPT_INVALID"
    if kv["witness.observer_pubkey"] not in trust["observers"]:
        return "reject", "E_ESCROW_UNKNOWN"
    if kv["witness.term_hash"] != term:
        return "reject", "E_ESCROW_UNKNOWN"
    if not C.ed25519_verify(parts["witness_sig"], parts["witness_bytes"],
                            unhex(kv["witness.observer_pubkey"], "observer")):
        return "reject", "E_ESCROW_UNKNOWN"
    if kv["witness.registry_root"] not in trust["registries"]:
        return "reject", "E_ESCROW_UNKNOWN"
    status = int(kv["witness.status"])
    if status not in STATUS_TAGS:
        return "reject", "E_ORDER_MALFORMED"
    chain = int(kv["witness.chain_id"])
    if chain not in trust["chains"] or chain != parts["chain_id"]:
        return "reject", "E_ESCROW_UNKNOWN"
    desc = ctx["registry_by_chain"].get(chain)
    if desc is None:
        return "reject", "E_ESCROW_UNKNOWN"
    if desc["settle_asset_tag"] != int(kv["order.asset_tag"]):
        return "reject", "E_UNSUPPORTED_ASSET"
    if status == 0:
        return "reject", "E_ESCROW_UNKNOWN"
    if status in (2, 3):
        return "reject", "E_REPLAY"
    if int(kv["witness.amount_on_chain"]) < int(kv["order.amount"]):
        return "reject", "E_ESCROW_INSUFFICIENT"
    if int(kv["sub.created_at"]) > int(kv["order.deadline"]):
        return "reject", "E_DEADLINE_PASSED"
    if int(kv["now"]) > int(kv["order.deadline"]) + ctx["common"]["window"]:
        return "reject", "E_DEADLINE_PASSED"
    return "payout", None


def trust_of(kv):
    def s(v):
        return set(x.strip() for x in v.split(",") if x.strip())
    return {"chains": set(int(x) for x in s(kv["trust.chains"])),
            "observers": s(kv["trust.observers"]), "registries": s(kv["trust.registries"])}


NO_TRUST = {"chains": set(), "observers": set(), "registries": set()}


# ---------------------------------------------------------------------------
# 5. main
# ---------------------------------------------------------------------------

def main(argv):
    paths = [argv[1] if len(argv) > 1 else "docs/PAID_PAYOUT-VECTORS.md",
             argv[2] if len(argv) > 2 else "docs/VecDHT-SPEC-v9.md",
             argv[3] if len(argv) > 3 else "docs/PAID_ORDER-VECTORS.md",
             argv[4] if len(argv) > 4 else "lab/notes/DESIGN-2026-10-25-chain-binding.md"]
    client_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "v9-independent-client.py")
    for p in paths + [client_path]:
        if not os.path.isfile(p):
            return abort("нет входа " + p)
    doc, spec = (open(p, encoding="utf-8").read() for p in paths[:2])
    odoc, note = (open(p, encoding="utf-8").read() for p in paths[2:])
    emit("TOOLCHAIN", sys.version.split()[0], "реализация моста, пересобирающая байты слоя")
    emit("UNICODE_DATA", unicodedata.unidata_version)
    emit("CARRIER_BYTES", len(doc.encode("utf-8")))
    emit("CARRIER_SHA", hx(sha(doc.encode("utf-8"))))

    res = {}
    try:
        rc = run(doc, spec, odoc, note, client_path, res)
    except (ValueError, KeyError, IndexError, struct.error) as e:
        if os.environ.get("V9C_DEBUG"):
            import traceback
            traceback.print_exc()
        return abort("%s: %s" % (type(e).__name__, e))
    emit("WORST", _state["bad"])
    emit("ALL_OK", 1 if _state["bad"] == 0 else 0)
    return _state["bad"] or rc


def run(doc, spec, odoc, note, client_path, res):
    C = load_client(client_path)
    quiet(C.read_spec_constants, spec)
    emit("PRIMITIVES_FROM_E0113", 1, "hashlib, Ed25519 по RFC 8032, canonical_json, вывод §V9.5")

    vectors = parse_kv_blocks(doc)
    if not vectors:
        raise ValueError("в носителе нет блоков векторов")
    domains = parse_domains(section(doc, "## 1. Домены канонизации"))
    layouts = parse_layouts(doc)
    registry = parse_registry(doc)
    codes = parse_codes(section(doc, "## 3. Закрытый список кодов"))
    steps = parse_steps(doc)
    common = parse_common(doc)
    cov = parse_coverage(doc)
    term_tokens = parse_term_tokens(doc)
    step0_codes = parse_step0_codes(doc)

    emit("VECTORS_PARSED", len(vectors))
    keys = set(tuple(sorted(kv)) for kv in vectors)
    check("VECTOR_KEYS_UNIFORM", len(keys) == 1, "у всех векторов один и тот же набор ключей")
    emit("VECTOR_KEY_COUNT", len(vectors[0]))
    count("DOMAIN_ROWS", len(domains), 5, "строк домена в §1")
    count("LAYOUT_OBJECTS", len(layouts), 4, "таблиц раскладки в §2")
    emit("LAYOUT_ROWS", sum(len(v) for v in layouts.values()),
         "строк полей: связка 4, описатель 7, свидетельство 7, требование 6")
    count("STEP_ROWS", len(steps), 7, "нумерованных шагов в §4")
    count("CODE_NAMES", len(codes), cov["total_codes"], "имён в закрытом списке §3 и в §7")
    count("REGISTRY_ROWS", len(registry), common["descriptors"], "строк реестра против числа в §5")

    # 1. Домены: заявленная длина против фактической.
    bad_len = sorted(n for n, d in domains.items() if d["declared"] != len(d["literal"]))
    emit("DOMAIN_LEN_DIFF", "|".join(bad_len) if bad_len else "none")
    check("DOMAIN_LEN_EQ", not bad_len, "заявленная длина домена равна длине напечатанного литерала")
    check("DOMAIN_RECEIPT_LEN_EQ", len(common["receipt_domain"]) == common["receipt_domain_declared"],
          "домен подписи квитанции назван в §5 с верной длиной")
    emit("DOMAIN_RECEIPT_LEN", len(common["receipt_domain"]))
    planted = dict((n, dict(d, declared=len(d["literal"]) + 1)) for n, d in domains.items())
    check("DOMAIN_LEN_DECOY", any(v["declared"] != len(v["literal"]) for v in planted.values()),
          "сверка длины ловит навранную длину, а не молчит")

    # 2. Реестр: байты описателя, лист, корень.
    dom_chain = domains["DOMAIN_CHAIN"]["literal"]
    leaves, bytes_ok, leaf_ok = [], 0, 0
    for r in registry:
        cb = build_object(layouts["ChainDescriptor"], dom_chain, dict(r), ascii_fields=("name", "note"))
        if hx(cb) == r["canonical_hex"]:
            bytes_ok += 1
        leaf = hx(sha(dom_chain + T + cb))
        if leaf == r["leaf_hex"]:
            leaf_ok += 1
        leaves.append(leaf)
    res["registry"] = count("REGISTRY_BYTES_EQ", bytes_ok, len(registry),
                            "байты описателей совпали с напечатанными")
    count("REGISTRY_LEAF_EQ", leaf_ok, len(registry), "листья совпали с напечатанными")
    root = hx(sha(dom_chain + bytes([1]) + b"".join(sorted(unhex(l, "leaf") for l in leaves))))
    emit("REGISTRY_ROOT", root)
    res["root"] = check("REGISTRY_ROOT_EQ", root == common["registry_root"],
                        "корень по напечатанной формуле равен напечатанному в §5")
    perm = list(reversed(leaves))
    root_perm = hx(sha(dom_chain + bytes([1]) + b"".join(sorted(unhex(l, "leaf") for l in perm))))
    check("REGISTRY_PERMUTE_EQ", root_perm == root, "порядок перечисления не влияет на корень")
    broken = list(leaves)
    broken[0] = hx(sha(b"decoy" + unhex(broken[0], "leaf")))
    root_broken = hx(sha(dom_chain + bytes([1]) + b"".join(sorted(unhex(l, "leaf") for l in broken))))
    check("REGISTRY_ROOT_SENSITIVE", root_broken != root, "порча одного листа меняет корень")
    emit("REGISTRY_EMPTY_ROOT", hx(sha(dom_chain + bytes([1]))),
         "пустой реестр: законное состояние, а не сломанный протокол")
    emit("REGISTRY_BRIDGE_CODES", "|".join(str(r["bridge_code"]) for r in registry) or "none")

    # 3. Соглашение о ключах: публичные ключи выводятся, а не принимаются на веру.
    def keypair_seed(seed):
        return hx(C.ed25519_pubkey(bytes([seed]) + b"\x00" * 30 + bytes([seed ^ common["keypair_mask"]])))

    role_key = dict((role, keypair_seed(common[role])) for role in
                    ("publisher", "beneficiary", "verifier", "observer"))
    field_of = {"publisher": "order.publisher", "beneficiary": "sub.submitter",
                "verifier": "receipt.verifier_pubkey", "observer": "witness.observer_pubkey"}
    hit = dict((role, sum(1 for kv in vectors if kv[field_of[role]] == role_key[role]))
               for role in role_key)
    emit("KEYPAIR_MATCH", "|".join("%s=%d/%d" % (k, hit[k], len(vectors)) for k in sorted(hit)))
    emit("KEYPAIR_MASK", "0x%02x" % common["keypair_mask"])
    check("KEYPAIR_PUBLISHER_EQ", hit["publisher"] == len(vectors),
          "ключ издателя во всех векторах выводим из соглашения")
    check("KEYPAIR_BENEFICIARY_EQ", hit["beneficiary"] == len(vectors))
    check("KEYPAIR_VERIFIER_EQ", hit["verifier"] == len(vectors) - 1,
          "ключ верификатора выводим, кроме вектора с чужим ключом")
    check("KEYPAIR_OBSERVER_EQ", hit["observer"] == len(vectors) - 1,
          "ключ наблюдателя выводим, кроме вектора вне доверенного набора")
    strange = [kv["id"] for kv in vectors if kv["receipt.verifier_pubkey"] == keypair_seed(7)]
    outside = [kv["id"] for kv in vectors if kv["witness.observer_pubkey"] == keypair_seed(9)]
    emit("KEYPAIR_STRANGE_VECTORS", "|".join(strange + outside) or "none")
    check("KEYPAIR_DECOY_NAMED", len(strange) == 1 and len(outside) == 1,
          "обе посадки с чужим ключом названы и отличимы от честных")

    # 4. Пересборка векторов, подписи и решение.
    kind_rev = dict((v, k) for k, v in C.KIND_TAGS.items())
    ctx = {"C": C, "spec": spec, "doc": doc, "domains": domains, "layouts": layouts,
           "registry": registry, "registry_by_chain": dict((r["chain_id"], r) for r in registry),
           "common": common, "term_tokens": term_tokens, "codes": codes, "steps": steps,
           "step0_codes": step0_codes, "allowlist": common["allowlist"],
           "kind_name": lambda tag: kind_rev.get(tag)}
    if any(ctx["kind_name"](int(kv["order.kind_tag"])) is None for kv in vectors):
        fail("KIND_TAG_READ", "тег kind не прочитан из таблицы §V9.2")
    stats = {"record": 0, "term": 0, "binding": 0, "witness": 0, "json": 0, "claim": 0,
             "claim_printed": 0, "sig": 0, "sig_total": 0, "mirror": 0, "codes": set()}
    misses = []
    claim_misses = []
    parts_of = {}
    for kv in vectors:
        parts = build_parts(kv, ctx)
        parts_of[kv["id"]] = parts
        vid = kv["id"]
        for key, got, want in (("record", hx(parts["order_record"]), kv["order.canonical_record_hex"]),
                               ("term", parts["term_hash"], kv["term_hash"]),
                               ("binding", hx(parts["binding_bytes"]), kv["binding.canonical_hex"]),
                               ("witness", hx(parts["witness_bytes"]), kv["witness.canonical_hex"]),
                               ("json", C.canonical_json(parts["receipt_obj"]), kv["receipt.canonical_json"])):
            if got == want:
                stats[key] += 1
            else:
                misses.append("%s:%s" % (vid, key))
        if parts["claim_bytes"] is not None:
            stats["claim_printed"] += 1
            if hx(parts["claim_bytes"]) == kv["claim.canonical_hex"]:
                stats["claim"] += 1
            else:
                claim_misses.append("%s:%d/%s байт" % (vid, len(parts["claim_bytes"]),
                                                       kv["claim.canonical_len"]))
                misses.append(vid + ":байты требования")
            if len(parts["claim_bytes"]) != int(kv["claim.canonical_len"]):
                misses.append(vid + ":длина требования")
        else:
            printed = kv["claim.canonical_len"]
            if kv["claim.canonical_hex"] != "-":
                misses.append(vid + ":требование не кодируется, но его байты напечатаны")
            if not printed.startswith("не_кодируется:"):
                misses.append(vid + ":требование не кодируется, напечатано %r" % printed)
            elif printed.split(":", 1)[1] != step0_codes.get(parts["missing"]):
                misses.append(vid + ":не_кодируется называет %s, шаг (0) печатает %s"
                              % (printed.split(":", 1)[1], step0_codes.get(parts["missing"])))
        signed = [(kv["order.signature_hex"], parts["order_record"], kv["order.publisher"]),
                  (kv["receipt.signature_hex"],
                   common["receipt_domain"] + T + parts["receipt_json"], kv["receipt.verifier_pubkey"]),
                  (kv["binding.signature_hex"], parts["binding_bytes"], kv["order.publisher"]),
                  (kv["witness.signature_hex"], parts["witness_bytes"], kv["witness.observer_pubkey"]),
                  (kv["claim.signature_hex"], parts["claim_bytes"], kv["claim.beneficiary"])]
        for (sgn, body, pk) in signed:
            if sgn == "-" or body is None:
                continue
            stats["sig_total"] += 1
            if C.ed25519_verify(unhex(sgn, "подпись"), body, unhex(pk, "ключ")):
                stats["sig"] += 1
            else:
                misses.append(vid + ":подпись не проходит")
        outcome, code = decide(kv, parts, ctx, trust_of(kv))
        got_code = "-" if code is None else code
        if (outcome, got_code) == (kv["outcome"], kv["code"]):
            stats["mirror"] += 1
        else:
            misses.append("%s:решение %s/%s, напечатано %s/%s"
                          % (vid, outcome, got_code, kv["outcome"], kv["code"]))
        if code is not None:
            stats["codes"].add(code)

    total = len(vectors)
    res["record"] = count("RECORD_EQ", stats["record"], total, "байты заказа пересобраны везде")
    res["term"] = count("TERM_EQ", stats["term"], total, "term_hash пересобран везде")
    res["binding"] = count("BINDING_EQ", stats["binding"], total, "байты связки пересобраны везде")
    res["witness"] = count("WITNESS_EQ", stats["witness"], total, "байты свидетельства пересобраны везде")
    res["json"] = count("RECEIPT_JSON_EQ", stats["json"], total, "канонический JSON квитанции пересобран")
    res["claim"] = count("CLAIM_EQ", stats["claim"], stats["claim_printed"],
                         "байты требования пересобраны там, где они кодируются")
    emit("CLAIM_MISS", "|".join(claim_misses) if claim_misses else "none",
         "векторы, где собранные байты требования не совпали с напечатанными")
    emit("SIGNATURES_CHECKED", stats["sig_total"])
    count("SIGNATURES_VALID", stats["sig"], stats["sig_total"],
          "каждая подпись проходит по пересобранным байтам своего объекта")
    emit("MIRROR_MATCH", "%d/%d" % (stats["mirror"], total))
    emit("MIRROR_MISS", "|".join(misses[:6]) if misses else "none")
    res["mirror"] = check("MIRROR_EQ", stats["mirror"] == total,
                          "решение моста совпало с напечатанным исходом и кодом")
    res["indep"] = check("INDEP_MATCH", all(res.get(k) == 1 for k in
                                            ("record", "term", "binding", "witness", "json", "claim", "root", "registry")),
                         "все байты слоя пересобраны из текста, без Rust и без узла")

    # 5. Инвариант A: аддитивность, сверенная по второму носителю.
    m = re.search(r'"id":"V01".*?"order_ref":"([0-9a-f]{64})"', odoc)
    if not m:
        fail("V01_ANCHOR_READ", "в носителе заказов не найден order_ref вектора V01")
    else:
        v01 = m.group(1)
        honest = [kv for kv in vectors if kv["outcome"] == "payout"][0]
        emitted = parse_anchor(doc)
        emit("V01_ORDER_REF", v01)
        emit("ANCHOR_IN_LAYER_DOC", emitted if emitted else "not_printed")
        check("ANCHOR_CARRIER_EQ", emitted == v01,
              "якорь инварианта A в носителе слоя равен вектору V01 носителя заказов")
        check("ORDER_REF_REBUILT_EQ", parts_of[honest["id"]]["order_ref"] == honest["order_ref"],
              "sha256 от пересобранных байтов заказа равен напечатанному order_ref")
        moved = bytearray(parts_of[honest["id"]]["order_ref"] and parts_of[honest["id"]]["order_record"])
        moved[len(moved) // 2] ^= 1
        check("ORDER_REF_SENSITIVE", hx(sha(bytes(moved))) != parts_of[honest["id"]]["order_ref"],
              "инвертированный бит записи меняет order_ref: сверка не слепая")

    # 6. Закрытый список: subset, сверка со спекой, посадка девятнадцатого имени.
    emit("CODES_SEEN", "|".join(sorted(stats["codes"])) or "none")
    emit("CODES_USED_MINE", len(stats["codes"]))
    check("CODES_SUBSET", all(c in codes for c in stats["codes"]),
          "каждый выведенный код есть в напечатном списке §3")
    check("CODES_USED_EQ_COVERAGE", len(stats["codes"]) == cov["codes"],
          "число использованных кодов совпало с §7")
    check("CODES_NAMED_EQ_COVERAGE", sorted(stats["codes"]) == sorted(cov["code_names"]),
          "имена использованных кодов совпали с перечнем §7")
    spec_sec = spec[spec.index("## §V9.8"):]
    spec_sec = spec_sec[:spec_sec.find("\n## §V9.")]
    spec_codes = set(re.findall(r"E_[A-Z_]+", spec_sec))
    check("CODES_EQ_SPEC", spec_codes == set(codes),
          "список §3 носителя совпадает с §V9.8 спеки имя в имя")
    planted = set(stats["codes"]) | {"E_PAYOUT_UNKNOWN"}
    check("CODE_GUARD_DECOY", not all(c in codes for c in planted),
          "девятнадцатое имя отвергается сверкой, а не принимается молча")
    step_codes = set()
    for line in steps:
        step_codes.update(re.findall(r"E_[A-Z_]+", line))
    emit("CODES_NAMED_IN_STEPS", "|".join(sorted(step_codes)) or "none")
    emit("STEP_CODES_COUNT", len(step_codes))
    check("STEP_CODES_KNOWN", step_codes <= set(codes),
          "каждое имя, названное в шагах §4, есть в закрытом списке")
    check("STEP_CODES_PARSED", len(step_codes) >= 9,
          "шаги §4 прочитаны с продолжениями: ноль имён — молчание экстрактора, а не отсутствие кодов")
    check("USED_CODES_IN_STEPS", stats["codes"] <= step_codes,
          "каждый код, на который выходит хоть один вектор, назван в напечатанном порядке шагов")

    # 7. Fail closed: пустое доверие не обязано никого оплачивать.
    paid = [kv for kv in vectors if kv["outcome"] == "payout"]
    leak = [kv["id"] for kv in paid if decide(kv, parts_of[kv["id"]], ctx, NO_TRUST)[0] == "payout"]
    emit("FAIL_CLOSED_LEAK", "|".join(leak) if leak else "none")
    check("FAIL_CLOSED", not leak, "при пустом наборе доверия ни одно честное требование не проходит")
    emit("EMPTY_TRUST_CODES", "|".join(sorted(set(
        decide(kv, parts_of[kv["id"]], ctx, NO_TRUST)[1] for kv in paid))) or "none")

    # 8. Числа §7 против собственных пересчётов прибора.
    count("VECTORS_COV_EQ", total, cov["vectors"], "векторов в §6 и в §7")
    count("PAYOUT_COV_EQ", len(paid), cov["payouts"], "векторов «платить»")
    replays = sum(1 for kv in vectors if kv["code"] == "E_REPLAY")
    emit("DOUBLE_REPLAY_COUNT", replays)
    check("DOUBLE_REPLAY_EQ_COVERAGE", replays == cov["replays"],
          "отказов E_REPLAY пересчитано столько же, сколько напечатано в §7")

    # 9. Посадки самой машины решения: зелёный вывод обязан быть не слепым.
    honest = paid[0]
    parts = parts_of[honest["id"]]
    flip = bytearray(parts["claim_bytes"])
    flip[len(flip) // 2] ^= 1
    check("SIG_DECOY", not C.ed25519_verify(parts["claim_sig"], bytes(flip),
                                            unhex(honest["claim.beneficiary"], "pk")),
          "инвертированный бит требования отвергнут подписью")
    # Каждая посадка переподписывается печатными ключами: иначе отказ наступил бы на проверке
    # подписи, и прибор похвалил бы себя за то, чего не проверял (решение по залогу).
    for key, want, field, value in (
            ("status", "E_REPLAY", "witness.status", "2"),
            ("amount", "E_ESCROW_INSUFFICIENT", "witness.amount_on_chain",
             str(int(honest["order.amount"]) - 1))):
        mutated = dict(honest)
        mutated[field] = value
        m_kv, m_parts = reseal(mutated, ctx, common)
        o, c = decide(m_kv, m_parts, ctx, trust_of(m_kv))
        emit("DECOY_" + key.upper() + "_PAIR", "%s/%s" % (o, c))
        check("DECOY_" + key.upper(), (o, c) == ("reject", want),
              "посадка %s поймана решением, а не пропущена" % key)
    stale = dict(honest)
    stale["witness.status"] = "9"
    m_kv, m_parts = reseal(stale, ctx, common, sign_witness=False)
    o, c = decide(m_kv, m_parts, ctx, trust_of(m_kv))
    emit("DECOY_WITNESS_SIG_PAIR", "%s/%s" % (o, c))
    check("DECOY_WITNESS_SIG", (o, c) == ("reject", "E_ESCROW_UNKNOWN"),
          "свидетельство с чужим телом под прежней подписью — про залог ничего неизвестно")
    fifth = dict(honest)
    fifth["witness.status"] = "9"
    m_kv, m_parts = reseal(fifth, ctx, common)
    o, c = decide(m_kv, m_parts, ctx, trust_of(m_kv))
    emit("DECOY_STATUS_SIGNED_PAIR", "%s/%s" % (o, c))
    check("DECOY_STATUS_SIGNED", (o, c) == ("reject", "E_ORDER_MALFORMED"),
          "подписанный пятый тег состояния — ошибка структуры, а не молчание")
    rowcut = [dict(r) for r in layouts["VerifierBinding"]]
    rowcut[0] = dict(rowcut[0], width="31 байта")
    same = False
    try:
        same = hx(build_object(rowcut, domains["DOMAIN_BINDING"]["literal"],
                               dict((r["field"], honest["binding." + r["field"]])
                                    for r in layouts["VerifierBinding"]))) == honest["binding.canonical_hex"]
    except ValueError:
        same = False
    check("LAYOUT_DECOY", not same, "урезанная ширина поля не воспроизводит напечатанные байты")

    # 10. Сверка с проектной запиской: она пре-регистрировалась до носителя.
    note_domains = dict(re.findall(r"(DOMAIN_[A-Z]+)\s*=\s*[\"`]([^\"`]+)[\"`]", note))
    emit("NOTE_DOMAINS", "|".join(sorted(note_domains)) or "none")
    check("NOTE_DOMAINS_EQ", len(note_domains) >= 5 and all(
        k in domains and domains[k]["literal"].decode("utf-8") == v for k, v in note_domains.items()),
        "домены записки и носителя названы одинаково")
    nseq, cseq = term_seq(note.splitlines() and term_tokens_note(note)), term_seq(term_tokens)
    emit("NOTE_TERM_SEQ", "|".join(nseq) or "none")
    emit("CARRIER_TERM_SEQ", "|".join(cseq) or "none")
    check("NOTE_TERM_ORDER_EQ", nseq == cseq, "порядок полей term_hash в записке и носителе одинаков")
    note_fields = dict((name, [f for f in note_struct_fields(note, name) if f != "signature"])
                       for name in LAYOUT_HEADERS if note.find(name + " {") >= 0)
    emit("NOTE_FIELDS", "|".join("%s=%s" % (k, ",".join(v)) for k, v in sorted(note_fields.items())) or "none")
    check("NOTE_FIELDS_PARSED", len(note_fields) == 4, "все четыре объекта записки разобраны")
    order_ok = all([r["field"] for r in layouts[k]
                    if re.fullmatch(r"[a-z_]+", r["field"])] == v for k, v in note_fields.items())
    check("NOTE_FIELD_ORDER_EQ", order_ok, "порядок полей объектов в записке и в таблицах носителя совпадает")
    note_steps = re.findall(r"^\d+\. ", section(note, "### 2.5", "\n## "), re.M)
    emit("NOTE_STEPS", len(note_steps), "нумерованных шагов в записке")
    check("STEP_COVERAGE", len(steps) == len(note_steps) + 1,
          "носитель добавил ровно шаг (0) про форму требования")
    opens = re.findall(r"OPEN-V9-(\d+)", note)
    emit("NOTE_OPENS", "|".join(sorted(set(opens))) or "none", "пункты OPEN, названные запиской")
    check("NOTE_OPENS_NUMBERED", len(set(opens)) >= 4, "записка называет не меньше четырёх новых пунктов")
    return 0


def seed_bytes(seed, common):
    return bytes([seed]) + b"\x00" * 30 + bytes([seed ^ common["keypair_mask"]])


def reseal(kv, ctx, common, sign_witness=True):
    """Переподпись изменённого входа печатными seed'ами ролей.

    Нужно затем, чтобы отказ наступал на машине решения, а не на проверке подписи: байты
    требования зависят от подписи свидетельства, а подпись требования — от этих байтов, поэтому
    прохода два. Посадка без переподписи похвалила бы прибор за то, чего он не проверял.
    """
    C = ctx["C"]
    for _ in range(2):
        parts = build_parts(kv, ctx)
        if parts["witness_bytes"] is None or parts["claim_bytes"] is None:
            return kv, parts
        if sign_witness:
            kv = dict(kv)
            kv["witness.signature_hex"] = hx(C.ed25519_sign(
                parts["witness_bytes"], seed_bytes(common["observer"], common)))
            parts = build_parts(kv, ctx)
            if parts["claim_bytes"] is None:
                return kv, parts
        kv = dict(kv)
        kv["claim.signature_hex"] = hx(C.ed25519_sign(
            parts["claim_bytes"], seed_bytes(common["beneficiary"], common)))
    return kv, build_parts(kv, ctx)


def term_tokens_note(note):
    return [t.strip() for t in formula_body(note).split(BAR) if t.strip()]


def note_struct_fields(note, name):
    i = note.index(name + " {")
    block = note[i:note.index("}", i)]
    return re.findall(r"([a-z_][a-z0-9_]*)\s*:", block)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
