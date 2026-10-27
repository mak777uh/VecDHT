#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Страж формальных моделей: компиляция, аксиомы по терминам доказательств, замороженные формулировки.

Интерфейс прежний — `bash lab/lean-check.sh` есть тонкая обёртка над `check` — и печатает те же
ключи (`LEAN_FILE=`, `LEAN_TOTAL=`, `LEAN_ALL_OK=`), чтобы `workspace-verify.sh` и закрытие цикла
не переписывать. Добавлены два счётка, которых в прежнем приборе не было.

Причина появления (`E-0093`, 2026-10-24). Прежний `lab/lean-check.sh` (bash + grep) считал `sorry`
и `axiom` как слова в исходнике. PRE_FIX этого цикла показывает, что оба счёта — про текст, а не про
доказательство: модель, где теорема выведена из объявленной аксиомы, печаталась как годная
(`OK=1`, `LEAN_ALL_OK=1`, выход 0), а ослабленная формулировка (`= 8` → `<= 8`) вообще ничем не
отличалась от годной, потому что сравнивать её было не с чем. Плюс измеренный факт о самих моделях:
`grep -c axiom` по пяти файлам даёт 0, а `#print axioms` по терминам доказательств — 93 теоремы из 115
зависят от аксиомы `native_decide`, то есть результат перебора Lean не перепроверяет, а принимает на
веру. Проверяемое утверждение «наши модели не содержат аксиом» было сформулировано не про тот объект.

Что делает прибор:

1. **Аксиомы по терминам.** Для каждой декларации `theorem`/`lemma` файла дописывается
   `#print axioms <namespace>.<имя>`, файл компилируется во временном каталоге, вывод разбирается.
   Классификация: `sorryAx` — провал; сторонняя (пользовательская) аксиома — провал;
   `*_native.native_decide.ax_*` — считается отдельно и НЕ является провалом (иначе весь инвентарь
   встал бы красным без права на объяснение); `propext`/`Classical.choice`/`Quot.sound` — стандартные
   аксиомы Lean, тоже считаются отдельно. Если по декларации не распечаталась ни одна из двух
   положенных строк — провал: прибор не имеет права молчать о том, чего не увидел.
2. **Формулировки под заморозкой.** `freeze` пишет в `lab/lean/frozen/<Модель>.statements.tsv`
   нормализованную формулировку каждой теоремы и её дайджест. `check` сверяет: изменённая, удалённая
   или появившаяся без заморозки формулировка — провал с именем теоремы. Это ровно то, что ядро Lean
   гарантировать не может (`L-0011`, Lean Atlas: type checker проверяет правильность доказательства,
   но не то, что утверждение выражает задуманное), поэтому проверяется отдельным дайджестом.

Употребление:
  python lab/lean-check.py check [--quiet] [--root DIR]
  python lab/lean-check.py freeze --cycle E-XXXX [--root DIR]
  python lab/lean-check.py selftest
"""
import argparse
import glob
import atexit
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.dirname(HERE)
# Каталог моделей для мутаторов и позитивных контролей. Когда прибор лежит в репозитории как
# `lab/lean-check.py`, это соседний `lab/lean/VecDHT` и ничего настраивать не надо; переменная
# окруждения нужна только для отладки прибора вне репозитория (до пре-регистрации он живёт в
# черновиках, и без неё самопроверка садила бы дефекты в пустой каталог).
MODELS_DIR = os.environ.get("LEAN_MODELS_DIR") or os.path.join(DEFAULT_ROOT, "lab", "lean", "VecDHT")
ELAN = os.environ.get("VEC_ELAN_BIN") or os.path.expanduser(os.path.join("~", ".elan", "bin"))
MINGW = os.environ.get("VEC_MINGW_BIN") or os.path.expanduser(os.path.join("~", "mingw64", "bin"))
# Рабочая станция — Windows, и два пути выше описывают её. Прибор обязан заводиться и на Linux
# (первый CI-прогон `formal.yml` запускает `bash lab/lean-check.sh` на ubuntu-24.04, где elan
# ставится в `$HOME/.elan/bin`), поэтому в список кандидатов добавлен домашний путь: на Windows
# `expanduser` даёт ровно тот же каталог, что и `ELAN`, а на Linux — единственный существующий.
# Фильтр `os.path.isdir` ниже означает, что несуществующий кандидат просто не попадает в PATH.
ELAN_CANDIDATES = (ELAN, MINGW, os.path.expanduser("~/.elan/bin"))
# Дочерние процессы обязаны писать и читаться в UTF-8: у Windows консоль по умолчанию cp1251, и
# первая же самопроверка прочитала «изменена после заморозки» как mojibake — дефект был отбит по
# коду возврата, но не по своей причине, потому что причина не совпала со строкой поиска.
_ENV = dict(os.environ, PYTHONIOENCODING="utf-8")

DECL_START = re.compile(r"^(theorem|lemma)\s+([^\s:(,]+)")
NS_RE = re.compile(r"^namespace\s+([A-Za-z0-9_.]+)", re.M)
END_RE = re.compile(r"^(end)\s+([A-Za-z0-9_.]+)", re.M)
AX_RE = re.compile(r"^'([^']+)' depends on axioms: \[([^\]]*)\]", re.M)
NO_AX_RE = re.compile(r"^'([^']+)' does not depend on any axioms", re.M)
STD_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
NATIVE_MARK = "_native.native_decide."
FROZEN_HEADER = "# lean-statement-digest v1"


def toolchain_missing():
    return shutil.which("lean") is None


def norm(text):
    """Формулировка без лишней вертикали: пробельные символы свёрнуты,comments вырезаны."""
    text = re.sub(r"--[^\n]*", "", text)
    return re.sub(r"\s+", " ", text).strip()


def statements(text):
    """[(kind, name, формулировка)] по исходнику модели.

    Формулировка — текст от начала декларации до первого `:=` на нулевой глубине скобок. Глубина
    нужна потому, что в наших моделях записи вида `{ key := k }` встречаются внутри самого
    утверждения: резать по первому `:=` означало бы отсекать половину формулировки и не замечать её
    изменения.
    """
    out = []
    lines = text.splitlines()
    n = len(lines)
    i = 0
    while i < n:
        m = DECL_START.match(lines[i])
        if not m:
            i += 1
            continue
        kind, name = m.group(1), m.group(2)
        depth, in_str = 0, False
        cj = ck = None
        j = i
        while j < n:
            line = lines[j]
            k = 0
            while k < len(line):
                ch = line[k]
                if in_str:
                    if ch == '"':
                        in_str = False
                elif ch == '"':
                    in_str = True
                elif ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                elif ch == ":" and line[k + 1:k + 2] == "=" and depth == 0:
                    cj, ck = j, k
                    break
                k += 1
            if cj is not None:
                break
            if j > i and DECL_START.match(lines[j]):
                cj, ck = j, None
                break
            j += 1
        if cj is None:
            cj = n
        block = "\n".join(lines[i:cj])
        if ck is not None:
            block = (block + "\n" if cj > i else "") + lines[cj][:ck]
        stmt = re.sub(r"^(theorem|lemma)\s+" + re.escape(name) + r"\b\s*", "", norm(block)).strip()
        out.append((kind, name, stmt))
        # шаг вперёд обязан быть: `:=` на той же строке, что и имя (наш частый случай), иначе
        # цикл читал бы одну декларацию вечно (дефект первой же редакции этого файла)
        i = cj if cj > i else i + 1
    return out


def count_decl_lines(text):
    return sum(1 for L in text.splitlines() if DECL_START.match(L))


def namespace_of(text):
    m = NS_RE.search(text)
    return m.group(1) if m else ""


def compile_source(path):
    t0 = time.time()
    # Lean пишет UTF-8; на Windows-локали `text=True` без явной кодировки расшифровал бы кириллицу
    # из сообщений как cp1251 (regex-и ASCII, поэтому молчание было бы незаметным).
    r = subprocess.run(["lean", path], capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return r.returncode, (r.stdout or "") + (r.stderr or ""), int((time.time() - t0) * 1000)


def augmented(text, ns, names):
    tail = "\n".join(f"#print axioms {ns}.{n}" if ns else f"#print axioms {n}" for n in names)
    return text + "\n-- #print axioms (страж E-0093, во временном файле, дерево не трогается)\n" + tail + "\n"


def temp_compile(text):
    fd, p = tempfile.mkstemp(suffix=".lean", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        return compile_source(p)
    finally:
        os.unlink(p)


def digest_of(pairs):
    block = "\n".join(f"{k}\t{n}\t{hashlib.sha256(s.encode('utf-8')).hexdigest()[:16]}"
                      for k, n, s in sorted(pairs, key=lambda x: x[1]))
    return hashlib.sha256(block.encode("utf-8")).hexdigest(), block


def frozen_path(root, model):
    return os.path.join(root, "lab", "lean", "frozen", os.path.basename(model) + ".statements.tsv")


def read_frozen(path):
    pairs = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3:
                pairs[parts[1]] = parts[2]
    return pairs


def cmd_check(args):
    root = args.root or DEFAULT_ROOT
    if toolchain_missing():
        print("LEAN_TOOLCHAIN=0 — компилятор Lean не найден в PATH (/c/Users/Admin/.elan/bin); "
              "модели СЕГОДНЯ не проверялись")
        print("LEAN_ALL_OK=0")
        return 2
    models = sorted(glob.glob(os.path.join(root, "lab", "lean", "VecDHT", "*.lean")))
    if not models:
        print("LEAN_ALL_OK=0 — каталог lab/lean/VecDHT пуст")
        return 1
    total = broken = 0
    sorry_total = sorryax_total = native_total = std_total = custom_total = clean_total = 0
    decls_total = 0
    digest_bad = 0
    ms_total = 0
    rc_all = 0
    for model in models:
        base = os.path.basename(model)
        src = open(model, encoding="utf-8").read()
        total += 1
        ns = namespace_of(src)
        pairs = statements(src)
        names = [n for _, n, _ in pairs]
        decl_lines = count_decl_lines(src)
        reasons = []
        if decl_lines != len(names):
            reasons.append(f"PARSER: деклараций {decl_lines}, разобрано имён {len(names)} — "
                           "имя не извлечено, счёт аксиом по нему ничего не проверяет")
        if not names:
            reasons.append("EMPTY: в модели нет ни одной теоремы — проверять нечего")
        rc, out, ms = temp_compile(augmented(src, ns, names))
        ms_total += ms
        errors = len(re.findall(r"error:", out))
        sorry_grep = len(re.findall(r"\bsorry\b", src))
        sorry_total += sorry_grep
        # Разбор вывода — тремя отдельными классами, чтобы отказ был по своей причине.
        # `Unknown constant` здесь означает не «модель сломана», а «страж потерял декларацию»:
        # имя разобрано неверно (например, теорема живёт во вложенном `namespace`), и счёт аксиом
        # по ней проверял бы пустоту. Это отдельный класс именно потому, что молчание прибора
        # опаснее красного гейта.
        unknown = re.findall(r"Unknown constant `([^`]+)`", out)
        native = sorry = custom = std = 0
        seen = set()
        missing = []
        if unknown:
            reasons.append(f"NAME: прибор молчит — разобранное имя декларации не найдено в модели: "
                           f"{unknown[:3]} (namespace разобран неверно)")
        elif rc != 0 or errors:
            reasons.append(f"COMPILE: выход {rc}, ошибок {errors}")
        else:
            for m in AX_RE.finditer(out):
                full, lst = m.group(1), m.group(2)
                items = [x.strip() for x in lst.split(",") if x.strip()]
                seen.add(full)
                if "sorryAx" in items:
                    sorry += 1
                    reasons.append(f"SORRY: {full} доказано через sorryAx")
                if any(NATIVE_MARK in x for x in items):
                    native += 1
                rest = [x for x in items if x not in STD_AXIOMS and NATIVE_MARK not in x
                        and x != "sorryAx"]
                if rest:
                    custom += 1
                    reasons.append(f"AXIOM: {full} зависит от пользовательской аксиомы {rest}")
                elif not any(NATIVE_MARK in x for x in items) and "sorryAx" not in items:
                    std += 1
            for m in NO_AX_RE.finditer(out):
                seen.add(m.group(1))
            missing = [f"{ns}.{n}" if ns else n for n in names
                       if (f"{ns}.{n}" if ns else n) not in seen]
            if missing:
                reasons.append(f"UNSEEN: прибор молчит — по декларациям нет ни строки об аксиомах: "
                               f"{missing[:3]}")
            sorryax_total += sorry
        decls_total += len(names)
        native_total += native
        std_total += std
        custom_total += custom
        clean_total += len(names) - native - sorry - custom - std
        # замороженные формулировки
        fp = frozen_path(root, model)
        if not os.path.isfile(fp):
            reasons.append("FROZEN: нет lab/lean/frozen/" + base +
                           ".statements.tsv — формулировки не замораживались, ослабление не увидеть")
            digest_bad += 1
        else:
            frozen = read_frozen(fp)
            now = {n: hashlib.sha256(s.encode("utf-8")).hexdigest()[:16] for _, n, s in pairs}
            changed = sorted(n for n, d in now.items() if n in frozen and frozen[n] != d)
            gone = sorted(n for n in frozen if n not in now)
            new = sorted(n for n in now if n not in frozen)
            if changed:
                reasons.append(f"STATEMENT: формулировка изменена после заморозки: {changed[:5]}")
                digest_bad += 1
            if gone:
                reasons.append(f"STATEMENT: теорема исчезла из модели: {gone[:5]}")
                digest_bad += 1
            if new:
                reasons.append(f"STATEMENT: декларация появилась без заморозки: {new[:5]}")
                digest_bad += 1
        ok = 0 if reasons else 1
        if not ok:
            broken += 1
            rc_all = 1
        print(f"LEAN_FILE={base} EXIT={rc} ERRORS={errors} SORRY={sorry_grep} SORRYAX={sorry} "
              f"NATIVE_AXIOMS={native} STD_AXIOMS={std} CUSTOM_AXIOMS={custom} "
              f"AXIOM_FREE={len(names) - native - sorry - custom - std} DECLS={len(names)} MS={ms} OK={ok}")
        # причина отказа печатается всегда, в том числе с `--quiet`: смысл этого прибора в том, что
        # отказ обязан быть назван, а `--quiet` в прежнем скрипте приглушал только дамп компилятора
        if not ok:
            for r in reasons:
                print(f"  ПРОТИВ {base}: {r}")
    print(f"LEAN_TOTAL={total} DECLS_TOTAL={decls_total} BROKEN={broken} SORRY_TOTAL={sorry_total} "
          f"SORRYAX_TOTAL={sorryax_total} "
          f"NATIVE_AXIOMS={native_total} STD_AXIOMS={std_total} CUSTOM_AXIOMS={custom_total} "
          f"AXIOM_FREE={clean_total} DIGEST_BAD={digest_bad} LEAN_MS_TOTAL={ms_total}")
    print("LEAN_ALL_OK=1" if rc_all == 0 else "LEAN_ALL_OK=0")
    return rc_all


def cmd_freeze(args):
    root = args.root or DEFAULT_ROOT
    outdir = os.path.join(root, "lab", "lean", "frozen")
    os.makedirs(outdir, exist_ok=True)
    models = sorted(glob.glob(os.path.join(root, "lab", "lean", "VecDHT", "*.lean")))
    if not models:
        print("FREEZE=0 — каталог lab/lean/VecDHT пуст")
        return 1
    n = 0
    for model in models:
        src = open(model, encoding="utf-8").read()
        pairs = statements(src)
        digest, block = digest_of(pairs)
        path = frozen_path(root, model)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"{FROZEN_HEADER}\n")
            fh.write(f"# cycle: {args.cycle or 'без цикла — правка вне замера запрещена'}\n")
            fh.write(f"# digest: {digest}\n")
            fh.write(block + "\n")
        n += 1
        print(f"FREEZE_FILE={os.path.basename(model)} DECLS={len(pairs)} DIGEST={digest[:16]}")
    print(f"FREEZE файлов={n} каталог=lab/lean/frozen")
    return 0


# ---------------------------------------------------------------- selftest
BAD_AXIOM = """namespace VecDHT.Axiom

axiom localBad : 1 = 2

theorem direct : 1 = 2 := localBad

end VecDHT.Axiom
"""
BAD_SORRY = """namespace VecDHT.Sorry

theorem shaky : 1 = 2 := by sorry

end VecDHT.Sorry
"""
BAD_EMPTY = """namespace VecDHT.Empty

def unused : Nat := 1

end VecDHT.Empty
"""
BAD_COMPILE = """namespace VecDHT.Broken

theorem oops : 1 = 1 :=

end VecDHT.Broken
"""
BAD_NAMESPACE = """namespace VecDHT.Outer
namespace Inner

theorem hidden : 1 = 1 := rfl

end Inner
end VecDHT.Outer
"""
GOOD_MINIMAL = """namespace VecDHT.Good

theorem safe : 1 = 1 := rfl

end VecDHT.Good
"""

WEAKEN_FROM = "theorem there_are_eight_names : ((List.range rungs).map nameOf).eraseDups.length = 8 := by"
WEAKEN_TO = "theorem there_are_eight_names : ((List.range rungs).map nameOf).eraseDups.length <= 8 := by"


def _tree(base, extra=None):
    root = os.path.join(base, "tree")
    d = os.path.join(root, "lab", "lean", "VecDHT")
    os.makedirs(d, exist_ok=True)
    n = 0
    for f in glob.glob(os.path.join(MODELS_DIR, "*.lean")):
        shutil.copy(f, d)
        n += 1
    if n == 0:
        raise RuntimeError(f"нет образцов моделей в {MODELS_DIR} — самопроверка нечего сажать, "
                           "и пустой временный каталог дал бы зелёный контроль")
    if extra:
        for name, text in extra.items():
            open(os.path.join(d, name), "w", encoding="utf-8").write(text)
    return root


def _run_check(root):
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "check", "--quiet", "--root", root],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", env=_ENV)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def _rmtree(path):
    shutil.rmtree(path, ignore_errors=True)


def cmd_selftest(args):
    if toolchain_missing():
        print("SELFTEST=0 — нет компилятора Lean, страж сегодня не проверялся")
        return 2
    if not glob.glob(os.path.join(MODELS_DIR, "*.lean")):
        print(f"SELFTEST=0 — в {MODELS_DIR} нет ни одного `.lean`: мутаторам нечего ломать, "
              "а позитивный контроль на пустом дереве был бы зелёным враньём")
        return 1
    base = tempfile.mkdtemp(prefix="leanguard-")
    # Уборка обязана случиться и на аварийном выходе: первая версия сносила дерево-копию только в
    # конце удачной ветки, поэтому любое исключение (а `selftest` их бросает намеренно — пустой
    # каталог моделей, не нашедшийся мутатор) оставляло после себя осевший каталог.
    atexit.register(_rmtree, base)
    defects = [
        ("аксиома в модели", {"Axiom.lean": BAD_AXIOM}, "пользовательской аксиомы"),
        ("sorry в модели", {"Sorry.lean": BAD_SORRY}, "SORRY:"),
        ("формулировка ослаблена", {"__weaken__": True}, "изменена после заморозки"),
        ("теорема удалена", {"__drop__": True}, "исчезла из модели"),
        ("теорема во вложенном namespace", {"Nested.lean": BAD_NAMESPACE}, "прибор молчит"),
        ("модель без деклараций", {"Empty.lean": BAD_EMPTY}, "нет ни одной теоремы"),
        ("модель не компилируется", {"Broken.lean": BAD_COMPILE}, "COMPILE"),
        ("нет замороженного дайджеста", {"Good.lean": GOOD_MINIMAL, "__unfrozen__": True},
         "FROZEN"),
    ]
    passed = 0
    for name, mutation, expect in defects:
        src = {k: v for k, v in mutation.items() if not k.startswith("__")}
        root = _tree(os.path.join(base, name.replace(" ", "_")), src)
        subprocess.run([sys.executable, os.path.abspath(__file__), "freeze", "--cycle", "selftest",
                        "--root", root], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=_ENV)
        d = os.path.join(root, "lab", "lean", "VecDHT")
        if mutation.get("__weaken__"):
            p = os.path.join(d, "CertLadder.lean")
            t = open(p, encoding="utf-8").read()
            if WEAKEN_FROM not in t:
                print(f"  ДЕФЕКТ {name}: ПОСАДКА НЕ СРАБОТАЛА — строка «{WEAKEN_FROM[:40]}…» "
                      "не найдена в CertLadder.lean (модель изменилась, мутатор устарел)")
                continue
            open(p, "w", encoding="utf-8").write(t.replace(WEAKEN_FROM, WEAKEN_TO))
        if mutation.get("__drop__"):
            # Удаление обязано снять ВСЮ декларацию: строку `theorem … := by` и все последующие
            # строки доказательства (они с отступом) вплоть до следующей строки нулевой колонки.
            # Первый вариант мутатора срезал только первую строку — `native_decide` оставался
            # сиротой, CertLadder переставал компилироваться, и дефект «теорема исчезла»
            # отрабатывался по чужой причине (COMPILE вместо STATEMENT).
            p = os.path.join(d, "CertLadder.lean")
            lines = open(p, encoding="utf-8").read().splitlines(True)
            start = next((i for i, L in enumerate(lines) if L.startswith(WEAKEN_FROM[:40])), None)
            if start is None:
                print(f"  ДЕФЕКТ {name}: ПОСАДКА НЕ СРАБОТАЛА — декларация не найдена")
                continue
            end = start + 1
            while end < len(lines) and (not lines[end].strip() or lines[end][:1].isspace()):
                end += 1
            open(p, "w", encoding="utf-8").write("".join(lines[:start] + lines[end:]))
        if mutation.get("__unfrozen__"):
            os.remove(frozen_path(root, "Good.lean"))
        rc, out = _run_check(root)
        hit = expect in out
        if rc != 0 and hit:
            passed += 1
            print(f"  ДЕФЕКТ {name}: rc={rc} ОТБИТ")
        else:
            print(f"  ДЕФЕКТ {name}: rc={rc} {'НЕ ОТБИТ' if rc == 0 else 'НЕ ПО СВОЕЙ ПРИЧИНЕ'} "
                  f"(ожидались слова «{expect}»)")
            # причина отказа обязана быть видна: без хвоста вывода этот самопроверка ровно тот
            # класс молчания, против которого она написана (первый запуск прочитал rc=2 как
            # «нет компилятора», хотя argparse ругался на свои аргументы)
            print("     вывод прибора: " + " / ".join(out.strip().splitlines()[-3:])[:400])
    # позитивный контроль: годное дерево проходит
    root = _tree(os.path.join(base, "good"))
    subprocess.run([sys.executable, os.path.abspath(__file__), "freeze", "--cycle", "selftest",
                    "--root", root], capture_output=True, text=True, encoding="utf-8",
                    errors="replace", env=_ENV)
    rc, out = _run_check(root)
    good = rc == 0
    print(f"  КОНТРОЛЬ годное дерево: rc={rc} {'ПРОЙДЕН' if good else 'ВАЛИТСЯ'}")
    # позитивный контроль: native_decide считается, но не валит гейт
    native = "NATIVE_AXIOMS=" in out
    print(f"  КОНТРОЛЬ native_decide посчитан как аксиома: {'ДА' if native else 'НЕТ'}")
    shutil.rmtree(base, ignore_errors=True)
    total = len(defects) + 2
    print(f"SELFTEST годное_дерево={'пройден' if good else 'ПРОВАЛ'} отбито={passed} из {len(defects)}")
    print(f"LEANGUARD_SELFTEST total={total} passed={passed + (1 if good else 0) + (1 if native else 0)}")
    return 0 if (good and passed == len(defects) and native) else 1


def main():
    # Печатать в UTF-8 независимо от того, запущен ли прибор из bash, из `workspace-verify.sh`
    # или из самопроверки: причины отказа по-русски попадают в append-only лог, и cp1251 сделал
    # бы из них mojibake, который не совпадёт с поисковой строкой (это и был первый прогон
    # самопроверки: дефекты отбивались, но «не по своей причине»).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    for p in ELAN_CANDIDATES:
        if os.path.isdir(p) and p not in os.environ.get("PATH", ""):
            os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")
    ap = argparse.ArgumentParser(description="страж формальных моделей Lean")
    # `--root` обязан быть у каждой подкоманды: у корневого парсера аргумент после подкоманды не
    # читается, argparse падает с кодом 2 — а 2 в этом приборе зарезервирован под «нет компилятора»,
    # и первый же selftest прочитал это как «Lean не найден» (ДИАГНОЗ: причину обязан называть текст,
    # а не код возврата).
    sp = ap.add_subparsers(dest="cmd", required=True)
    c = sp.add_parser("check")
    c.add_argument("--quiet", action="store_true")
    c.add_argument("--root", help="корень дерева (для selftest — временный)")
    f = sp.add_parser("freeze")
    f.add_argument("--cycle", default="")
    f.add_argument("--root", help="корень дерева (для selftest — временный)")
    st = sp.add_parser("selftest")
    st.add_argument("--root", help="корень дерева (для selftest — временный)")
    args = ap.parse_args()
    return {"check": cmd_check, "freeze": cmd_freeze, "selftest": cmd_selftest}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
