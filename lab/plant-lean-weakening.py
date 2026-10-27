#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""H-0107 / E-0107: проба стража моделей на посаженном ослаблении именно этой формулировки.

`H-0093` завёл `lab/lean-check.py`: он сверяет печатаемое утверждение теоремы с замороженным
снимком (`lab/lean/frozen/<Модель>.statements.tsv`) и ловит аксиому вместо доказательства. Но
проверено это было на `CertLadder.lean` — на новой модели `Bounded.lean` механизм обязан ловить
ослабление собственным прогоном, иначе пункт (В) фальсификатора карточки не измерен.

Посаженный дефект выбран так, чтобы его нельзя было поймать компиляцией: квантор по всем 259
расписаниям заменяется квантором по трём первым. Теоремы от этого остаются истинными и
доказуемыми (`native_decide` проходит), а ∀-утверждение перестаёт быть ∀ — ровно тот класс
тихого ослабления, ради которого и существовала заморозка.

Пробел: временный корень собирается копией всего `lab/lean` (модели, `frozen/`, проект lake),
поэтому проверка идёт настоящим прибором, а не его пересказом.

Замеренный результат первой пробы (до правки прибора): `PLANT_CONTROL_OK=1 PLANT_APPLIED=1
PLANT_WEAK_EXIT=0 PLANT_CAUGHT=0` — то есть фальсификатор (В) карточки сработал по существу: страж
замораживал только подписи теорем, а формулировка ∀ жила в теле `def`, и её сужение было ему
невидимо. Правка прибора (`lab/lean-check.py`: под дайджест попали тела `def`/`abbrev`, печатается
`DEFS=`/`FROZEN_ROWS=`) обязана быть видна этим же прогоном: теперь `PLANT_WEAK_EXIT!=0`, а причина —
изменённое имя `propBounded`, не любая строка вывода.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_REL = os.path.join("VecDHT", "Bounded.lean")

WEAK_FROM = (
    "def propBounded (step : Ev \u2192 St \u2192 St) : Bool :=\n"
    "  legalStarts.all fun st => traces.all fun t => leB (card (run step t st).1) cap"
)
WEAK_TO = (
    "def propBounded (step : Ev \u2192 St \u2192 St) : Bool :=\n"
    "  legalStarts.all fun st => (traces.take 3).all fun t => leB (card (run step t st).1) cap"
)


def make_tree(base):
    """Копия настоящего `lab/lean` во временном корне: без заморозки проба была бы пустой."""
    dst = os.path.join(base, "lab")
    shutil.copytree(os.path.join(ROOT, "lab", "lean"), os.path.join(dst, "lean"))
    return dst


def run_check(root):
    p = subprocess.run(
        [sys.executable, os.path.join(ROOT, "lab", "lean-check.py"), "check", "--quiet",
         "--root", os.path.dirname(root)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    base = tempfile.mkdtemp(prefix="plant-lean-")
    try:
        root = make_tree(base)
        rc, out = run_check(root)
        control_ok = 1 if rc == 0 else 0
        print(f"PLANT_CONTROL_EXIT={rc}")
        print(f"PLANT_CONTROL_OK={control_ok}")

        path = os.path.join(root, "lean", MODEL_REL)
        text = io.open(path, encoding="utf-8").read()
        n = text.count(WEAK_FROM)
        print(f"PLANT_APPLIED={1 if n == 1 else 0}")
        if n != 1:
            print(f"PLANT_MATCHES={n}")
            print("PLANT_CAUGHT=0")
            print("PLANT_REASON_DIGEST_BAD=0")
            print("PLANT_REASON_NAMES_THE_DEF=0")
            print("PLANT_TOTAL=1 PLANT_OK=0")
            return 1
        io.open(path, "w", encoding="utf-8", newline="\n").write(text.replace(WEAK_FROM, WEAK_TO))

        rc2, out2 = run_check(root)
        caught = 1 if rc2 != 0 else 0
        # Причина обязана быть своя, а не любая: первый вариант искал подстроку «DIGEST» и ловил
        # `DIGEST_BAD=0` — то есть считал успехом строчку, говорящую об обратном. Теперь два
        # независимых признака: счётчик бракованных дайджестов ненулевой И изменённое имя — именно
        # ослабленный предикат свойства, а не случайная теорема.
        bad = 1 if re.search(r"DIGEST_BAD=[1-9]", out2) else 0
        named = 1 if re.search(
            r"STATEMENT: формулировка изменена после заморозки: \[[^\]]*propBounded", out2) else 0
        names = [ln for ln in out2.splitlines() if "ПРОТИВ Bounded" in ln]
        print(f"PLANT_WEAK_EXIT={rc2}")
        print(f"PLANT_CAUGHT={caught}")
        print(f"PLANT_REASON_DIGEST_BAD={bad}")
        print(f"PLANT_REASON_NAMES_THE_DEF={named}")
        print(f"PLANT_REPORT_LINES={len(names)}")
        for ln in names[:3]:
            print(f"# {ln.strip()[:160]}")
        ok = control_ok == 1 and caught == 1 and bad == 1 and named == 1
        print(f"PLANT_TOTAL=1 PLANT_OK={1 if ok else 0}")
        return 0 if ok else 1
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
