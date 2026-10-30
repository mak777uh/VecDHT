#!/usr/bin/env python3
"""H-0160 / E-0160: страж ссылок на спеку — запрет номеров строк и проверяемая цитата.

Дыра, из которой прибор родился. Шесть шапок тестов ссылались на v8-спеку номером строки
(`§13.3 (строка 1351)`, `§4.2 (строка 148)` …). Номер строки не якорь: после `E-0086`, `E-0088`
и `E-0103` те же номера указывают на другие абзацы, а две цитаты §14.4 (iv) («per-cluster
admission cap в коде не реализован») дословно описывают состояние до `E-0088` и в текущей спеке
отсутствуют. Тесты оставались зелёными, шапки — нет. Ни один из стражей на это не смотрел:
`check-text-clean` ловит алфавиты, `check-artifact-refs` — пути, `check-ci-numbers` — числа
шапки CI.

Два правила, каждое с причиной:

(1) В `crates/**/*.rs` запрещена ссылка на номер строки: `строк[а-я]+` рядом с 3–4 цифрами.
    Одно- и двузначные числа разрешены: `строка 0` у `accept_ttl_boundary.rs` — строка таблицы
    аренды, а не спеки. Граница названа в H-0160: цифры в прозе карточек и логов не сканируются,
    там номер строки — исторический факт.

(2) Объявленная цитата `спека v8 §N.M: «…»` обязана буквально присутствовать в разделе §N.M
    файла `docs/VecDHT-SPEC-v8.md` после нормализации: снимаются `*` и бэктики, кавычки всех
    видов сводятся к одной, пробелы и переводы строк схлопываются. Цитата с вложенными `«»`
    формой не считается (регэксп её не захватывает) и остаётся на человеческом просмотре.

Чего прибор сознательно НЕ делает: он не требует цитаты у каждого упоминания `§`. В дереве 23
места, где `§` и `«…»` стоят рядом, и среди них есть пересказы таблиц §19.4 и §8.6, дословно в
спеке не лежащие; объявить их находками значило бы переписать полтора десятка шапок в круге,
который мерит другое. Поэтому в правило (2) попадает только форма с явной версией и двоеточием —
её и используют шапки после правки.

Код возврата: 0 — находок нет; 1 — находки напечатаны; 2 — спека или дерево не читаются.
`--selftest` исполняет шесть посаженных случаев на временном дереве и репозиторий не трогает.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC_REL = "docs/VecDHT-SPEC-v8.md"
SCAN_ROOT = "crates"

# Ссылка на номер строки спеки: `строка 1351`, `строки 1381–1384`, `строке 969`.
BAN = re.compile(r"строк[а-я]+\s+(\d{3,4})")
# Объявленная цитата: `Спека v8 §4.2: «…»`. Вложенные «» не допускаются — форма требует
# одной пары; карточка называет это границей, а не находкой.
CITE = re.compile(
    r"спека\s+v8\s+§(\d+\.\d+)(?:\s*\([^)]*\))?\s*:\s*«([^«»]+?)»",
    re.IGNORECASE | re.DOTALL,
)
HEADING = re.compile(r"^(#{2,4})\s+(\d+\.\d+)\s", re.MULTILINE)

QUOTES = {
    ord("«"): '"', ord("»"): '"', ord("„"): '"',
    ord("“"): '"', ord("”"): '"',
}


def norm(text: str) -> str:
    """Идентичность по разрешённой форме: разметка, кавычки и пробелы не различают цитату."""
    text = text.replace("*", "").replace("`", "")
    text = text.translate(QUOTES)
    return re.sub(r"\s+", " ", text).strip()


def load_sections(spec_path: Path) -> dict[str, str]:
    spec = spec_path.read_text(encoding="utf-8")
    heads = list(HEADING.finditer(spec))
    sections: dict[str, str] = {}
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(spec)
        sections.setdefault(m.group(2), spec[m.start():end])
    return {k: norm(v) for k, v in sections.items()}


def header_block(text: str) -> str:
    """Ведущая шапка `//!` одного файла; продолжения склеиваются в один текст."""
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped.startswith("//!"):
            break
        out.append(stripped[3:].strip())
    return "\n".join(out)


def collect(root: Path) -> tuple[list[str], dict[str, int]]:
    spec = root / SPEC_REL
    if not spec.is_file():
        raise SystemExit(f"SPEC_CITES_ERROR: нет {SPEC_REL}")
    sections = load_sections(spec)
    findings: list[str] = []
    files = refs = cites = ok = 0
    for path in sorted((root / SCAN_ROOT).rglob("*.rs")):
        files += 1
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        for no, line in enumerate(text.splitlines(), 1):
            if not line.lstrip().startswith("//"):
                continue
            for m in BAN.finditer(line):
                refs += 1
                findings.append(f"ССЫЛКА_НА_СТРОКУ {rel}:{no} {m.group(0)}")
        header = header_block(text)
        base = 0
        for m in CITE.finditer(header):
            cites += 1
            num, quote = m.group(1), norm(m.group(2))
            where = rel + ":" + str(text[:text.find("//!")].count("\n") + 1 + header[:m.start()].count("\n"))
            if num not in sections:
                findings.append(f"РАЗДЕЛ_НЕ_НАЙДЕН {where} §{num}")
                continue
            if quote not in sections[num]:
                findings.append(f"ЦИТАТА_НЕ_НАЙДЕНА {where} §{num}: {quote[:70]}")
                continue
            ok += 1
        base = base
    return findings, {"files": files, "refs": refs, "cites": cites, "ok": ok}


SELFTEST_SPEC = """### 4.2 NodeCert — роль вместо криптоидентичности

Правила проверки (один раз на соединение, затем кеш по `remote PeerId` до `valid_until`):

### 9.2 ShardMembership: самовалидируемая цепочка

* индекс в `sigs` — позиция подписанта в наборе **epoch−1** (для genesis — порядок ключей в
  `authorities` артефакта), а не в новом составе.
"""


def selftest() -> int:
    cases = []
    with tempfile.TemporaryDirectory(prefix="e0160-") as tmp:
        root = Path(tmp)
        (root / "docs").mkdir()
        (root / "docs" / "VecDHT-SPEC-v8.md").write_text(SELFTEST_SPEC, encoding="utf-8")
        test = root / "crates" / "x" / "tests" / "t.rs"
        test.parent.mkdir(parents=True)

        def run(body: str):
            test.write_text(body, encoding="utf-8")
            return collect(root)

        f, st = run('//! Спека v8 §4.2: «кеш по `remote PeerId` до `valid_until`».\n')
        cases.append(("верная цитата не краснеет", not f and st["cites"] == 1 and st["ok"] == 1))

        f, st = run('//! §13.3 (строка 1351) обещает.\n')
        cases.append(("ссылка на номер строки поймана", len(f) == 1 and st["refs"] == 1))

        f, st = run('//! Спека v8 §4.2: «такой фразы в разделе 4.2 нет».\n')
        cases.append(("неверная цитата поймана",
                      len(f) == 1 and "ЦИТАТА_НЕ_НАЙДЕНА" in f[0] and st["cites"] == 1))

        f, st = run('//! Спека v8 §9.99: «индекс в `sigs` — позиция подписанта».\n')
        cases.append(("несуществующий раздел пойман",
                      len(f) == 1 and "РАЗДЕЛ_НЕ_НАЙДЕН" in f[0]))

        f, st = run('//! Спека v8 §9.2: «индекс в `sigs` — позиция подписанта\n'
                    '//! в наборе epoch−1 (для genesis — порядок ключей в `authorities` артефакта)».\n')
        cases.append(("цитата через перевод строки склеена",
                      not f and st["cites"] == 1 and st["ok"] == 1))

        f, st = run('//! Порог (3): на бакет позже границы строка 0 выбрасывается.\n')
        cases.append(("двузначная строка таблицы не поймана", not f and st["refs"] == 0))

    passed = 0
    for i, (name, good) in enumerate(cases, 1):
        print(f"CASE_{i}={'ok' if good else 'fail'} {name}")
        passed += int(good)
    print(f"SELFTEST_CASES={len(cases)}")
    print(f"SELFTEST_PASS={passed}")
    return 0 if passed == len(cases) else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    try:
        findings, st = collect(ROOT)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"SPEC_CITES_ERROR: {exc}")
        return 2
    print(f"SPEC_CITES_FILES={st['files']}")
    print(f"SPEC_CITES_REFS={st['refs']}")
    print(f"SPEC_CITES_CITES={st['cites']}")
    print(f"SPEC_CITES_OK={st['ok']}")
    print(f"SPEC_CITES_FINDINGS={len(findings)}")
    for f in findings:
        print("НАХОДКА " + f)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
