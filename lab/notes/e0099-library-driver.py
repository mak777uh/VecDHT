# -*- coding: utf-8 -*-
"""Одна порция контура источников для H-0099: пять записей L-0018…L-0022 про тулчейны.

Каждая запись добавляется, переводится в «в работе» привязкой к цели и закрывается с действием —
ровно той механикой, которую проверяет `python lab/library.py check`. Script-драйвер нужен потому,
что `add --json` берёт строку из argv, а в тексте записей кириллица и табуляции: через shell-кавычки
такая строка портится молча.
"""
import json
import subprocess
import sys

ROOT = os.environ.get("VEC_DHT_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TODAY = "2026-10-24"

ROWS = [
    {
        "id": "L-0018",
        "title": "Kani 0.68.0: релизные ассеты только под Linux и macOS",
        "url": "https://github.com/model-checking/kani/blob/0d2328a93f0e0ff66132d6bfa1a7d884877cf862/README.md",
        "ref": "0d2328a93f0e0ff66132d6bfa1a7d884877cf862",
        "path": "README.md",
        "cite": "model-checking/kani, коммит тега kani-0.68.0 = 0d2328a9, README.md + список ассетов релиза (API, 2026-10-24)",
        "verified": TODAY,
        "depth": "текст выборочно",
        "kind": "реализация",
        "gives": ("Ограничение, которое переписало план: у Kani 0.68.0 ровно четыре publish-ассета — "
                  "x86_64 и aarch64 под unknown-linux-gnu и apple-darwin; Windows-сборки нет (размеры "
                  "138 862 660 и 140 315 343 Б у linux-тарголов). README того же коммита подтверждает "
                  "«Rust 1.58+; Linux or Mac». Значит «несколько независимых систем доказательств на "
                  "один коммит» физически исполнимы только на Linux-раннере, а рабочая станция (Windows) "
                  "может проверяет харнеси лишь на компиляцию — отсюда отдельный прибор "
                  "lab/kani-compile-check.sh с заглушкой API вместо молчания. Второе, что даёт источник: "
                  "харнеси живут в том же crate, что продукт, под #[cfg(kani)] и запускаются cargo kani, "
                  "то есть не нужен ни отдельный crate, ни правка wire-формата."),
        "targets": ["H-0099"],
        "status": "не использован",
        "action": "",
        "cost_min": 8,
        "opened": TODAY,
    },
    {
        "id": "L-0019",
        "title": "Verus 0.2026.10.18.7d82994: четыре ассета, включая x86-win, и тулчейн в version.json",
        "url": "https://github.com/verus-lang/verus/blob/7d829946231d6413a398f6e4160cdfe951261dad/INSTALL.md",
        "ref": "7d829946231d6413a398f6e4160cdfe951261dad",
        "path": "INSTALL.md",
        "cite": "verus-lang/verus, тег release/0.2026.10.18.7d82994 (sha 7d82994), INSTALL.md + ассеты релиза",
        "verified": TODAY,
        "depth": "текст выборочно",
        "kind": "реализация",
        "gives": ("Verus ставится на Windows — это меняет распределение ролей в контуре: локально "
                  "(1,05 с на модель, замерено этим циклом) исполняется Verus, в CI — Kani. Ассеты "
                  "релиза: x86-linux 486 844 228 Б, x86-win 541 405 822 Б, x86-macos, arm64-macos; "
                  "INSTALL.md называет MacOS, Windows и Ubuntu платформами первой поддержки. Второе "
                  "полезное: требуемый тулчейн зашит в version.json рядом с бинарем (у локальной "
                  "сборки это «1.99.1-x86_64-pc-windows-msvc»), поэтому CI читает номер оттуда, а не "
                  "хранит вторым числом в workflow: расхождение двух чисел иначе ловится только "
                  "красным прогоном."),
        "targets": ["H-0099"],
        "status": "не использован",
        "action": "",
        "cost_min": 8,
        "opened": TODAY,
    },
    {
        "id": "L-0020",
        "title": "Prusti (prusti/prusti): репозиторий активен, релизные бинари — август 2023",
        "url": "https://github.com/prusti/prusti/blob/22804f71443daba55b409fb0f4829d007a0f5fa0/README.md",
        "ref": "22804f71443daba55b409fb0f4829d007a0f5fa0",
        "path": "README.md",
        "cite": "prusti/prusti (бывш. viperproject/prusti-dev, API отвечает 301), main=22804f7, releases/latest=v-2023-08-22-1715",
        "verified": TODAY,
        "depth": "аннотация",
        "kind": "реализация",
        "gives": ("Факт, который отменяет прежнюю заметку лаборатории: во-первых, репозиторий живой "
                  "(pushed_at 2026-10-23, 1820 звёзд, ветка по умолчанию main), во-вторых, у него ЕСТЬ "
                  "windows-ассет prusti-release-windows.zip 137 509 973 Б — в отличие от Kani. Но "
                  "последний релиз датирован тегом v-2023-08-22-1715, то есть бинари трёхлетней давности "
                  "при активном main, а сам Prusti построен на Viper, которому нужна JVM. Для контура это "
                  "значит: ставить его можно только сборкой из исходников, и это не влезает в бюджет "
                  "сверки (30 минут). Отказ зафиксирован в ADR-0053 с причиной, а не молчанием."),
        "targets": ["H-0099"],
        "status": "не использован",
        "action": "",
        "cost_min": 5,
        "opened": TODAY,
    },
    {
        "id": "L-0021",
        "title": "Creusot 0.14.0: ни одного релизного ассета, цепочка opam + Why3 + Z3",
        "url": "https://github.com/creusot-rs/creusot/blob/18f2d371ecb0019d37ecbd25e67f474bed2dda00/README.md",
        "ref": "18f2d371ecb0019d37ecbd25e67f474bed2dda00",
        "path": "README.md",
        "cite": "creusot-rs/creusot, main=18f2d37, releases/latest=v0.14.0 (2026-10-12), assets=[]",
        "verified": TODAY,
        "depth": "аннотация",
        "kind": "реализация",
        "gives": ("Creusot переводит контракты на Rust-код в Why3 — по замыслу это то, чего не хватает "
                  "нашему мосту «модель ↔ код», потому что модель не нужно переписывать руками. Но "
                  "проверено по API: у релиза v0.14.0 список ассетов пуст, установка описана через opam "
                  "(OCaml + Why3 + Z3). Для контура, где каждый прибор обязан краснеть числом, это "
                  "означает цепочку зависимостей больше, чем предмет проверки: её поломка дала бы красный "
                  "круг без всякого утверждения о продукте. Отказ с причиной — в ADR-0053."),
        "targets": ["H-0099"],
        "status": "не использован",
        "action": "",
        "cost_min": 5,
        "opened": TODAY,
    },
    {
        "id": "L-0022",
        "title": "Flux: refinement-типы поверх Rust-кода, без единого релиза",
        "url": "https://github.com/flux-rs/flux/blob/1b04d5e6f8247766cfb0f9c6040c2944eb9c87c4/README.md",
        "ref": "1b04d5e6f8247766cfb0f9c6040c2944eb9c87c4",
        "path": "README.md",
        "cite": "flux-rs/flux, main=1b04d5e, releases=[], README (онлайн-демо)",
        "verified": TODAY,
        "depth": "аннотация",
        "kind": "реализация",
        "gives": ("Flux — refinement-типизация поверх Rust-кода (типы с чисельными предикатами), то есть ровно наш класс "
                  "задач: арифметика капа ячейки с предпосылкой про переполнение. Проверено по API: "
                  "ноль релизов, установка — сборка из исходников, публичный интерфейс — онлайн-демо. "
                  "Неподпираемый тулчейн в контуре, где гейт обязан быть числом, означал бы вердикт "
                  "«прибор есть» без возможности сказать, какой именно прибор исполнялся. Отказ с "
                  "причиной — в ADR-0053; возврат возможен отдельным циклом."),
        "targets": ["H-0099"],
        "status": "не использован",
        "action": "",
        "cost_min": 4,
        "opened": TODAY,
    },
]

ACTIONS = {
    "L-0018": ("изменено", "H-0099 / ADR-0053: план контура переписан под ограничение источника — работа kani в "
               ".github/workflows/formal.yml закреплена на ubuntu-24.04 и пином 0.68.0, харнеси легли в продукт "
               "(#[cfg(kani)] mod kani_harnesses в crates/vecdht-node/src/admission.rs, check-cfg в Cargo.toml), а "
               "локально заведён lab/kani-compile-check.sh, потому что на Windows Kani физически не исполняется"),
    "L-0019": ("изменено", "H-0099 / ADR-0053: роли в контуре поменялись местами — Verus исполняется локально "
               "(lab/verus-check.sh + lab/proofs/verus/cap_math.rs), а не в CI, и CI-работа verus читает номер "
               "тулчейна из version.json рядом с бинарем вместо второго числа в workflow; предпосылка о "
               "переполнении, названная моделью, легла в продукт как CELL_CAP_MAX_LIVE + debug_assert в admission.rs"),
    "L-0020": ("не повлияло", "Коду и CI не изменил ничего: отказ зафиксирован в ADR-0053 с причиной (релизные "
               "бинари 2023-08 при активном main, зависимость от JVM). Полез записью, потому что прежняя заметка "
               "о «мёртвом Prusti» была неверна в обеих половинах"),
    "L-0021": ("не повлияло", "Отказ в ADR-0053: пустой список ассетов и цепочка opam/OCaml/Why3 не влезают в "
               "бюджет сверки; к идее «контракт прямо на продукте» вернёмся через Verus, он её уже закрыл локально"),
    "L-0022": ("не повлияло", "Отказ в ADR-0053: ноль релизов => нечего пинить в CI; риск получить "
               "красный круг без утверждения о продукте"),
}


def run(*args):
    r = subprocess.run([sys.executable, "lab/library.py"] + list(args), cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8")
    return r.returncode, (r.stdout or "") + (r.stderr or "")


# `--reclose <id> …` повторяет закрытие для уже записанных карточек с тем же текстом действия:
# `library.py close` перезаписывает статус, а не требует новой записи, и единственный источник
# правды о том, чем источник повлиял, остаётся этот файл. Без режима пришлось бы вторым местом
# хранить ту же прозу — а расхождение двух копий прозы ловится только человеком.
if len(sys.argv) > 2 and sys.argv[1] == "--reclose":
    for rid in sys.argv[2:]:
        act, what = ACTIONS[rid]
        rc, out = run("close", rid, "--action", act, "--what", what)
        print(rid, "reclose rc=", rc, out.strip().splitlines()[-1] if out.strip() else "")
    sys.exit(0)

for row in ROWS:
    # Цель живёт в поле `targets` карточки-замысла, но в индекс она попадает только через `use`:
    # страж не принимает запись со статусом «не использован» и приписанной целью, потому что
    # «не использован» — это как раз состояние «цели нет». Без этого шага драйвер писал бы в
    # историю репозитория то, чего механизм ещё не проверял.
    payload = dict(row, targets=[], status="не использован")
    rc, out = run("add", "--json", json.dumps(payload, ensure_ascii=False))
    print(row["id"], "add rc=", rc, out.strip().splitlines()[-1] if out.strip() else "")
    if rc != 0:
        continue
    rc, out = run("use", row["id"], "--target", "H-0099")
    print("  use rc=", rc, out.strip().splitlines()[-1] if out.strip() else "")
    act, what = ACTIONS[row["id"]]
    rc, out = run("close", row["id"], "--action", act, "--what", what)
    print("  close rc=", rc, out.strip().splitlines()[-1] if out.strip() else "")

rc, out = run("check")
print("CHECK rc=", rc)
print(out[-1500:])
