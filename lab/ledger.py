#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Баланс цикла: ресурсы как поток, который обязан сохраняться в зоне ответственности.

Слово владельца 2026-10-25: принцип разработки — не «сделать», а «не потратить зря и не вынести
за границу молча». Отсюда форма: у каждого ресурса (время, диск, RAM, внимание, информационный
выход наружу) есть приход, расход и остаток; расход без результата обязан быть напечатан числом,
пересечение границы — названо, а не подразумеваться.

Употребление:
    python lab/ledger.py report ЛОГ_ЦИКЛА [ЛОГ_ЦИКЛА...]      # баланс по печатным ключам
    python lab/ledger.py selftest                            # посаженные случаи
    python lab/ledger.py lint  ЛОГ_ЦИКЛА                     # только находки (выход 1 = есть)

Что читается из логов (ничего не домывается, молчание = провал):
  * `SECONDS_<этап>=N` и `<ЭТАП>_EXIT=N` — время и вердикт каждого этапа верификации;
  * `DISK_FREE_MB` / `RAM_FREE_MB` / `PAGEFILE_PEAK_MB` — носитель до и после;
  * `VERIFY_FAIL=` — итог блока; `STATUS_DLL_INIT_FAILED` — оборванные дочерние процессы;
  * `GATE_*`, `PRE_FIX_*` — что цикл потребил до замера; `REVIEW_FINDINGS` — что нашёл страж.

Инварианты баланса (печатными фактами):
  `LEDGER_WALL_TOTAL`      — сумма времени этапов; без неё «дешёвый цикл» неотличим от «тихого»;
  `LEDGER_SPENT_ON_FAILED` — секунды, отданные этапам с ненулевым выходом: это и есть «потрачено
                             зря», и оно обязано быть числом, а не ощущением;
  `LEDGER_FAILED_STAGES`   — сколько этапов закончилось ненулевым выходом;
  `LEDGER_INTERRUPTED`     — сколько процессов не стартовало/оборвалось (срыв блока, не отказ теста);
  `LEDGER_DISK_DELTA_MB`   — изменение свободного места (отрицательное = съели);
  `LEDGER_RAM_DELTA_MB`    — изменение свободной RAM между первой и последней меткой блока;
  `LEDGER_BOUNDARIES`      — сколько раз цикл объявил выход за границу (коммит спеки/пуш в логе
                             нет: их объявляет человек, и молчание прибора здесь не «успех»);
  `LEDGER_OK`              — 1 только если есть все этапы, нет оборванных процессов и итог нулевой.

Чего прибор НЕ делает: не судит, стоило ли тратить. Он делает расход видимым, потому что
несохранение ресурса в этой системе всегда начиналось с молчания: сорванный блок верификации
`E-0105` (114 оборванных процессов, 415 с) не был помечен никак, пока его не пересчитали руками.
"""

import os
import re
import sys

# Якорь — граница токена с обеих сторон (`^` или пробел слева, не «буква/точка» справа), а не начало
# строки: `workspace-verify.sh` печатает метки ресурсов в одну строку
# (`DISK_FREE_MB=… RAM_FREE_MB=… PAGEFILE_PEAK_MB=…`), и якорь только по началу строки молча
# терял два из трёх чисел. Тот же класс, что и в `E-0089`/`E-0105`.
STAGE_RE = re.compile(r"(?:^|[ \t])SECONDS_([a-z0-9_]+)=(\d+)(?![\w.])", re.MULTILINE)
EXIT_RE = re.compile(r"(?:^|[ \t])([A-Z][A-Z0-9_]*)_EXIT=(\d+)(?![\w.])", re.MULTILINE)
DISK_RE = re.compile(r"(?:^|[ \t])DISK_FREE_MB=(\d+)(?![\w.])", re.MULTILINE)
RAM_RE = re.compile(r"(?:^|[ \t])RAM_FREE_MB=(\d+)(?![\w.])", re.MULTILINE)
PF_RE = re.compile(r"(?:^|[ \t])PAGEFILE_PEAK_MB=(\d+)(?![\w.])", re.MULTILINE)
DLL_RE = re.compile(r"STATUS_DLL_INIT_FAILED")
GATE_RE = re.compile(r"(?:^|[ \t])GATE_[A-Z0-9_]*=", re.MULTILINE)
PREFIX_RE = re.compile(r"(?:^|[ \t])PRE_FIX\S*=", re.MULTILINE)

REQUIRED_STAGES = ("test", "clippy", "lean", "lean_selftest")


def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def balance(corpus):
    stages = {}
    for name, secs in STAGE_RE.findall(corpus):
        stages[name] = stages.get(name, 0) + int(secs)
    exits = {}
    for name, rc in EXIT_RE.findall(corpus):
        exits.setdefault(name, []).append(int(rc))
    failed = [k for k, v in exits.items() if v and max(v) != 0]
    disk = [int(x) for x in DISK_RE.findall(corpus)]
    ram = [int(x) for x in RAM_RE.findall(corpus)]
    pf = [int(x) for x in PF_RE.findall(corpus)]
    interrupted = len(DLL_RE.findall(corpus))
    wall = sum(stages.values())
    # Стоимость проваленного этапа считаем по тем же `SECONDS_*`, что и wall: иначе «дешёвый цикл»
    # неотличим от «тихого цикла, в котором ничего не исполнялось». Имя выхода `TEST_EXIT` и имя
    # времени `SECONDS_test` связывает строчная форма без суффикса.
    spent_failed = 0
    for k in failed:
        spent_failed += stages.get(k.replace("_EXIT", "").lower(), 0)
    missing = [s for s in REQUIRED_STAGES if s not in stages]
    real_failures = [k for k in failed if k != "VERIFY"]
    ok = 1 if (not missing and interrupted == 0 and not real_failures) else 0
    facts = [
        f"LEDGER_WALL_TOTAL={wall}",
        f"LEDGER_STAGES={len(stages)}",
        f"LEDGER_FAILED_STAGES={len(failed)}",
        f"LEDGER_SPENT_ON_FAILED={spent_failed}",
        f"LEDGER_INTERRUPTED={interrupted}",
        f"LEDGER_DISK_DELTA_MB={(disk[-1] - disk[0]) if len(disk) >= 2 else 'нет_двух_меток'}",
        f"LEDGER_RAM_DELTA_MB={(ram[-1] - ram[0]) if len(ram) >= 2 else 'нет_двух_меток'}",
        f"LEDGER_PAGEFILE_PEAK_MB={max(pf) if pf else 'нет_метки'}",
        f"LEDGER_GATE_RUNS={len(GATE_RE.findall(corpus))}",
        f"LEDGER_PREFIX_KEYS={len(PREFIX_RE.findall(corpus))}",
        f"LEDGER_MISSING_STAGES={len(missing)}",
        f"LEDGER_OK={ok}",
    ]
    notes = []
    if missing:
        notes.append("ЭТАПЫ НЕ ИСПОЛНЕНЫ: " + ",".join(missing))
    if interrupted:
        notes.append(f"ОБОРВАНО_ПРОЦЕССОВ={interrupted} — блок недействителен, расход не в счёт")
    if spent_failed:
        notes.append(f"ПОТРАЧЕНО_ВПУСТУЮ_С={spent_failed} — этапы с ненулевым выходом")
    # `LEDGER_SPENT_ON_FAILED=0` бывает двух родов: «этап дешёвый» и «для этапа нет метки
    # времени». Второе — молчание прибора, и выдать его за ноль нельзя (тот же класс, что `E0105_RUNS`).
    unknown = [k for k in failed if stages.get(k.replace("_EXIT", "").lower(), 0) == 0]
    if unknown:
        notes.append(
            "СТОИМОСТЬ_ПРОВАЛА_НЕИЗВЕСТНА: " + ",".join(unknown)
            + " — нет `SECONDS_<этап>` с тем же именем; ноль здесь значит «не мерялось», а не «дёшево»"
        )
    if len(disk) < 2:
        notes.append("НОСИТЕЛЬ: одна метка — приход/расход неразличимы")
    return facts, notes


def cmd_report(paths):
    if not paths:
        print("LEDGER_OK=0 — нет логов: молчание не считается балансом")
        return 2
    parts = []
    for p in paths:
        if not os.path.isfile(p):
            print(f"LEDGER_OK=0 — нет файла лога {p}: баланс неоткуда считать")
            return 2
        parts.append(read(p))
    corpus = "\n".join(parts)
    if not corpus.strip():
        print("LEDGER_OK=0 — логи пусты")
        return 2
    facts, notes = balance(corpus)
    print("### баланс цикла (LEDGER) ###")
    for f in facts:
        print(f)
    for n in notes:
        print(f"ВНИМАНИЕ: {n}")
    rc = 0 if facts[-1].endswith("=1") else 1
    print(f"LEDGER_EXIT={rc}")
    return rc


def cmd_lint(paths):
    facts, notes = balance("\n".join(read(p) for p in paths))
    bad = [n for n in notes if "ВПУСТУЮ" in n or "НЕ ИСПОЛНЕНЫ" in n]
    if not bad:
        print("LEDGER_LINT находок=0")
        return 0
    for b in bad:
        print(f"LEDGER НАХОДКА: {b}")
    print(f"LEDGER_LINT находок={len(bad)}")
    return 1


CASES = [
    # (имя, корпус, ожидаемый факт, ожидаемая находка в заметках или None)
    (
        "полный зелёный блок",
        "SECONDS_test=100\nTEST_EXIT=0\nSECONDS_clippy=10\nCLIPPY_EXIT=0\n"
        "SECONDS_lean=140\nLEAN_EXIT=0\nSECONDS_lean_selftest=137\nLEANGUARD_SELFTEST_EXIT=0\n"
        "DISK_FREE_MB=18000\nDISK_FREE_MB=17900\nRAM_FREE_MB=14000\nRAM_FREE_MB=13000\n"
        "PAGEFILE_PEAK_MB=7660\nVERIFY_FAIL=0\nGATE_H9=OK\n",
        "LEDGER_OK=1",
        None,
    ),
    (
        "проваленный этап показывает потраченное время",
        "SECONDS_test=90\nTEST_EXIT=101\nSECONDS_clippy=10\nCLIPPY_EXIT=0\n"
        "SECONDS_lean=140\nLEAN_EXIT=0\nSECONDS_lean_selftest=137\nLEANGUARD_SELFTEST_EXIT=0\n"
        "DISK_FREE_MB=18000\nDISK_FREE_MB=17900\nVERIFY_FAIL=1\n",
        "LEDGER_SPENT_ON_FAILED=90",
        "ПОТРАЧЕНО_ВПУСТУЮ_С=90",
    ),
    (
        "оборванные процессы = недействительный блок",
        "SECONDS_test=98\nTEST_EXIT=101\nSECONDS_clippy=8\nCLIPPY_EXIT=0\n"
        "SECONDS_lean=140\nLEAN_EXIT=0\nSECONDS_lean_selftest=137\nLEANGUARD_SELFTEST_EXIT=0\n"
        "STATUS_DLL_INIT_FAILED\nSTATUS_DLL_INIT_FAILED\nDISK_FREE_MB=1\nDISK_FREE_MB=2\n"
        "RAM_FREE_MB=1\nRAM_FREE_MB=2\nVERIFY_FAIL=1\n",
        "LEDGER_INTERRUPTED=2",
        "ОБОРВАНО_ПРОЦЕССОВ=2",
    ),
    (
        "тихий блок: этапов нет — это не баланс",
        "DISK_FREE_MB=18000\nDISK_FREE_MB=18000\n",
        "LEDGER_MISSING_STAGES=4",
        "ЭТАПЫ НЕ ИСПОЛНЕНЫ",
    ),
    (
        "одна метка носителя = приход неотделим от расхода",
        "SECONDS_test=1\nTEST_EXIT=0\nSECONDS_clippy=1\nCLIPPY_EXIT=0\nSECONDS_lean=1\nLEAN_EXIT=0\n"
        "SECONDS_lean_selftest=1\nLEANGUARD_SELFTEST_EXIT=0\nDISK_FREE_MB=18000\nVERIFY_FAIL=0\n",
        "LEDGER_DISK_DELTA_MB=нет_двух_меток",
        "НОСИТЕЛЬ: одна метка",
    ),
    (
        "стоимость прогона не пишется до измерения: итог нулевой, находок нет",
        "SECONDS_test=5\nTEST_EXIT=0\nSECONDS_clippy=5\nCLIPPY_EXIT=0\nSECONDS_lean=5\nLEAN_EXIT=0\n"
        "SECONDS_lean_selftest=5\nLEANGUARD_SELFTEST_EXIT=0\nDISK_FREE_MB=10\nDISK_FREE_MB=10\n"
        "RAM_FREE_MB=10\nRAM_FREE_MB=10\nVERIFY_FAIL=0\nGATE_X=1\nPRE_FIX_FOUND=0\n",
        "LEDGER_PREFIX_KEYS=1",
        None,
    ),
    (
        "метрики в одну строку: RAM читается по границе токена, а не по началу строки",
        "SECONDS_test=5\nTEST_EXIT=0\nSECONDS_clippy=5\nCLIPPY_EXIT=0\nSECONDS_lean=5\nLEAN_EXIT=0\n"
        "SECONDS_lean_selftest=5\nLEANGUARD_SELFTEST_EXIT=0\n"
        "DISK_FREE_MB=18000 RAM_FREE_MB=14000 PAGEFILE_PEAK_MB=7660\n"
        "DISK_FREE_MB=17900 RAM_FREE_MB=13000 PAGEFILE_PEAK_MB=7700\nVERIFY_FAIL=0\n",
        "LEDGER_RAM_DELTA_MB=-1000",
        None,
    ),
    (
        "метрики в одну строку: пик pagefile тоже извлечён (правило трёх чисел)",
        "SECONDS_test=5\nTEST_EXIT=0\nSECONDS_clippy=5\nCLIPPY_EXIT=0\nSECONDS_lean=5\nLEAN_EXIT=0\n"
        "SECONDS_lean_selftest=5\nLEANGUARD_SELFTEST_EXIT=0\n"
        "DISK_FREE_MB=18000 RAM_FREE_MB=14000 PAGEFILE_PEAK_MB=7660\n"
        "DISK_FREE_MB=17900 RAM_FREE_MB=13000 PAGEFILE_PEAK_MB=7700\nVERIFY_FAIL=0\n",
        "LEDGER_PAGEFILE_PEAK_MB=7700",
        None,
    ),
    (
        "промах без метки времени: ноль стоимости — это молчание, а не дёшево",
        "SECONDS_test=5\nTEST_EXIT=0\nSECONDS_clippy=5\nCLIPPY_EXIT=0\nSECONDS_lean=5\nLEAN_EXIT=0\n"
        "SECONDS_lean_selftest=5\nLEANGUARD_SELFTEST_EXIT=0\nDISK_FREE_MB=10\nDISK_FREE_MB=10\n"
        "VERIFY_EXIT=1\nVERIFY_FAIL=0\n",
        "LEDGER_SPENT_ON_FAILED=0",
        "СТОИМОСТЬ_ПРОВАЛА_НЕИЗВЕСТНА",
    ),
]


def cmd_selftest():
    bad = 0
    for name, corpus, want_fact, want_note in CASES:
        facts, notes = balance(corpus)
        got = [f for f in facts if f.split("=")[0] == want_fact.split("=")[0]]
        hit = want_fact in facts
        note_hit = (want_note is None) or any(want_note in n for n in notes)
        if not hit or not note_hit:
            bad += 1
            print(
                f"СЕЛФТЕСТ ПРОВАЛ: {name}: ждали «{want_fact}»"
                + (f" и заметку «{want_note}»" if want_note else "")
                + f", получили {got} / {notes}"
            )
        else:
            print(f"СЕЛФТЕСТ ok: {name}")
    # Посаженный дефект: отсутствие заметки о впустую потраченном времени = слепота прибора.
    facts, notes = balance("SECONDS_test=1\nTEST_EXIT=0\nDISK_FREE_MB=1\nDISK_FREE_MB=1\nVERIFY_FAIL=0\n")
    if any("ВПУСТУЮ" in n for n in notes):
        bad += 1
        print("СЕЛФТЕСТ ПРОВАЛ: ложная находка на чистом блоке")
    else:
        print("СЕЛФТЕСТ ok: чистый блок не рождает находку")
    print(f"LEDGER_SELFTEST total={len(CASES) + 1} passed={len(CASES) + 1 - bad}")
    return 0 if bad == 0 else 1


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[6])
        return 2
    cmd = argv[1]
    if cmd == "selftest":
        return cmd_selftest()
    if cmd == "report":
        return cmd_report(argv[2:])
    if cmd == "lint":
        return cmd_lint(argv[2:])
    print(f"LEDGER_OK=0 — неизвестная команда {cmd!r}")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
