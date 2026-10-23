#!/usr/bin/env python3
"""Гейт круга: боль -> источники -> решение по рубрике Lean -> только потом оракул.

Причина появления. Контур источников (`ADR-0045`) и Lean (`lab/lean/`) существовали, но держались
на памяти агента: за пять циклов `H-0085`…`H-0091` не добавлено ни одной формальной модели,
в индексе не появилось ни одной записи о чужой кодовой реализации, а `lab/lean/` не проверялся
с момента его создания. Слово владельца 2026-10-23: механизм обязан применяться автоматически,
в том числе к агенту, который открыл репозиторий первым разом. Значит — не абзац в README,
а nonzero exit перед пре-регистрационным коммитом.

Команды:
  python lab/cycle-gate.py H-XXXX         — жёсткая проверка карточки перед пре-регистрацией
  python lab/cycle-gate.py audit -n N     — отчёт по последним N карточкам (кто под правилом)
  python lab/cycle-gate.py --selftest     — посаженные карточки: механизм обязан их отбить

Выход: 0 — круг оформлен, 1 — нарушено правило, 2 — карточка не найдена или прибор негоден.

Карточка обязана содержать (YAML-шапка): id, claim, falsifier, oracle, prior_art, lean.
Формат шапки:

  prior_art: ["L-0007", "L-0008"]        # либо ["не искали — <причина>"]
  prior_art_no_code: "<причина, почему чужой код не читали>"   # опционально
  lean:
    решение: применён                    # применён | не применён
    причина: "<почему>"
    модель: lab/lean/VecDHT/Denylist.lean
    пространство: да                     # четыре вопроса рубрики: да | нет
    без_времени: да
    для_всех: да
    дешевле_стенда: нет

Рубрика (`lab/lean-rubric.md`) отвечает не «нравится ли мне Lean», а «конечно ли пространство
и безвременно ли утверждение»: четыре «да» делают модель обязательной, и gate проверяет её
компиляцией и отсутствием `sorry`.
"""

import argparse
import glob
import io
import json
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

ROOT = os.environ.get("VEC_DHT_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "lab", "library", "index.jsonl")
LEAN_DIR = os.path.join(ROOT, "lab", "lean", "VecDHT")
REQUIRED_KEYS = ("id", "claim", "falsifier", "oracle", "prior_art", "lean")
# Точное совпадение, не подстрока: «не применён» содержит «применён», и проверка на подстроку
# превращала отказ в согласие (самопроверка selftest, случай «отказ при четырёх да»).
LEAN_APPLIED = ("применён", "применен", "сделан", "есть")
LEAN_SKIPPED = ("не применён", "не применен", "не применим", "неприменим", "не сделан", "не нужен")
# Карточки без ключа `lean:` созданы до механизма (2026-10-23) и не считаются нарушением —
# но в отчёте они помечены явно, чтобы «историч.» нельзя было принять за «проверено».
PRE_MECHANISM_NOTE = "историческая карточка (до механизма ADR-0048)"


def card_path(hid):
    hits = sorted(glob.glob(os.path.join(ROOT, "lab", "hypotheses", f"{hid}-*.md")))
    if len(hits) != 1:
        return None, hits
    return hits[0], hits


def front_matter(path):
    import yaml
    text = io.open(path, encoding="utf-8").read()
    parts = text.split("---")
    if len(parts) < 3:
        return None, "в файле нет YAML-шапки между линиями ---"
    try:
        return yaml.safe_load(parts[1]), None
    except Exception as e:
        return None, f"YAML-шапка не разобрана ({type(e).__name__}: {e})"


def load_index():
    rows = []
    if not os.path.isfile(INDEX):
        return rows, "нет индекса источников"
    for line in io.open(INDEX, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                return rows, "индекс содержит неразобранную строку"
    return rows, None


def check_prior_art(fm, rows, hid, bad, say):
    """Шаг круга «источники до эксперимента»: строки обязаны существовать, быть привязаны
    к этой гипотезе и быть начаты не позже её."""
    refs = fm.get("prior_art") or []
    if isinstance(refs, str):
        refs = [refs]
    if not isinstance(refs, list) or not refs:
        bad.append("prior_art пуст: шаг «литература и код до эксперимента» не сделан "
                   "(поиск — `python lab/library.py hunt`)")
        return
    excuse = [r for r in refs if str(r).startswith("не искали")]
    if excuse:
        if len(str(excuse[0])) < 25:
            bad.append(f"отказ от сверки сформулирован в {len(str(excuse[0]))} знаков — это не причина")
        say(f"ПРИОРАРТ {hid}: отказ от источников с причиной")
        return
    by_id = {r.get("id"): r for r in rows}
    card_date = str(fm.get("date", ""))
    kinds = set()
    for lid in refs:
        r = by_id.get(lid)
        if r is None:
            bad.append(f"prior_art называет {lid}, а в индексе такой строки нет")
            continue
        if hid not in (r.get("targets") or []):
            bad.append(f"{lid}: в targets нет {hid} — запись читают не для этой гипотезы")
        if r.get("status") == "не использован":
            bad.append(f"{lid}: статус «не использован» — строку перечислили, но не прочитали")
        opened = str(r.get("opened", ""))
        if card_date and opened and opened > card_date:
            bad.append(f"{lid}: открыта {opened} позже карточки {card_date} — источник найден "
                       f"после того, как гипотеза уже сформулирована")
        kinds.add(r.get("kind"))
    codeish = {"спека", "реализация"} - {None}
    if kinds and not (kinds & codeish):
        reason = str(fm.get("prior_art_no_code") or "")
        if len(reason) < 25:
            bad.append("ни одной записи класса «спека» или «реализация»: решаем боль, которую "
                       "кто-то уже решал кодом, и не смотрим, как (причина — prior_art_no_code, "
                       "поиск — `python lab/library.py hunt --github`)")
        else:
            say(f"ПРИОРАРТ {hid}: чужой код не читали, причина записана ({len(reason)} зн.)")
    say("ПРИОРАРТ " + f"{hid}: строк={len(refs)} классы={sorted(k for k in kinds if k)}")


def check_lean(fm, hid, bad, say, skip_lean):
    lean = fm.get("lean")
    if lean is None:
        bad.append(f"нет ключа `lean:` — решение по рубрике не принято, а «не принял» — не ответ")
        return
    if not isinstance(lean, dict):
        bad.append(f"`lean:` обязан быть блоком с полями рубрики, а не строкой ({lean!r})")
        return
    for q in ("пространство", "без_времени", "для_всех", "дешевле_стенда"):
        if str(lean.get(q, "")).strip().lower() not in ("да", "нет"):
            bad.append(f"вопрос рубрики «{q}» без ответа да|нет")
    answers = [str(lean.get(q, "")).strip().lower() == "да"
               for q in ("пространство", "без_времени", "для_всех", "дешевле_стенда")]
    required = all(answers)
    dec = str(lean.get("решение", "")).strip().lower()
    applied = dec in LEAN_APPLIED
    skipped = dec in LEAN_SKIPPED
    if not applied and not skipped:
        bad.append(f"`lean.решение`={dec!r} вне словаря применён|не применён")
    reason = str(lean.get("причина", "")).strip()
    if skipped:
        if required:
            bad.append("рубрика дала четыре «да», а модель не сделана: по `lab/lean-rubric.md` "
                       "в этом случае модель обязательна (конечное пространство, ∀-утверждение, "
                       "без времени)")
        if len(reason) < 25:
            bad.append(f"`lean.причина` отказа короче 25 знаков ({len(reason)})")
        say(f"LEAN {hid}: модель не сделана, рубрика обязательной не требует"
            if not required else f"LEAN {hid}: НАРУШЕНИЕ — рубрика требует модель")
        return
    model = str(lean.get("модель", "")).strip()
    if not model:
        bad.append("`lean.решение`=применён, а `lean.модель` не названа")
        return
    path = model if os.path.isabs(model) else os.path.join(ROOT, model)
    if not os.path.isfile(path):
        bad.append(f"модель {model} не найдена на диске")
        return
    text = io.open(path, encoding="utf-8").read()
    if re.search(r"\bsorry\b", text):
        bad.append(f"модель {model} содержит sorry — это незакрытая цель, а не проверка")
    if skip_lean:
        say(f"LEAN {hid}: компиляция пропущена по --skip-lean (в отчёте это НЕ проверка)")
        return
    env = dict(os.environ)
    # Пути тулчейна добавляем только если они есть: жёстко приписанный домашний каталог одного
    # хоста превращал бы проверку чужой машины в «нет Lean», а это другой отказ, чем «модель
    # не компилируется». Если `lean` уже в PATH — ничего не добавляем.
    if shutil.which("lean", path=env.get("PATH", "")) is None:
        extra = [p for p in ("/c/Users/Admin/.elan/bin", os.path.expanduser("~/.elan/bin"),
                             "/c/Users/Admin/mingw64/bin") if os.path.isdir(p)]
        if extra:
            env["PATH"] = os.pathsep.join(extra) + os.pathsep + env.get("PATH", "")
    try:
        p = subprocess.run(["lean", path], capture_output=True, text=True, env=env, timeout=600)
    except FileNotFoundError:
        bad.append("нет тулчейна Lean (elan) — пре-регистрация с моделью невозможна, "
                   "а «не компилировалось» не считается проверкой")
        return
    except subprocess.TimeoutExpired:
        bad.append(f"модель {model} не скомпилировалась за 600 с")
        return
    errs = len([l for l in (p.stdout + p.stderr).splitlines() if "error:" in l])
    if p.returncode != 0 or errs:
        bad.append(f"модель {model} не компилируется (rc={p.returncode}, error:={errs})")
        return
    say(f"LEAN {hid}: модель {os.path.basename(model)} компилируется, sorry=0, ошибок=0")


def cmd_gate(args):
    bad, out = [], []
    say = out.append
    path, hits = card_path(args.hid)
    if path is None:
        print(f"Карточка {args.hid} не найдена (совпадений {len(hits)}): {hits}")
        return 2
    fm, err = front_matter(path)
    if fm is None:
        print(f"CYCLE {args.hid} НЕ_РАЗОБРАНА: {err}")
        return 2
    missing = [k for k in REQUIRED_KEYS if k not in fm]
    if missing:
        bad.append(f"нет обязательных ключей: {missing}")
    rows, idx_err = load_index()
    if idx_err:
        bad.append(f"индекс источников: {idx_err}")
    if not str(fm.get("claim", "")).strip():
        bad.append("claim пуст")
    if not str(fm.get("falsifier", "")).strip():
        bad.append("falsifier пуст — невыполнимая проверка хуже отсутствия проверки "
                   "(ДИАГНОЗ-1 из E-0087)")
    if not str(fm.get("oracle", "")).strip():
        bad.append("oracle не назван")
    check_prior_art(fm, rows, args.hid, bad, say)
    check_lean(fm, args.hid, bad, say, args.skip_lean)
    for line in out:
        print(line)
    for b in bad:
        print(f"  НАРУШЕНИЕ: {b}")
    print(f"CYCLE {args.hid}={'OK' if not bad else 'FAIL'} нарушениий={len(bad)}")
    return 0 if not bad else 1


def cmd_audit(args):
    files = sorted(glob.glob(os.path.join(ROOT, "lab", "hypotheses", "H-*.md")))
    files = files[-args.n:] if args.n else files
    legacy = 0
    for path in files:
        fm, err = front_matter(path)
        m = re.search(r"(H-\d{4})", os.path.basename(path))
        hid = (fm or {}).get("id") or (m.group(1) if m else path)
        if fm is None:
            print(f"КАРТОЧКА {hid}: шапка не разобрана ({err})")
            continue
        if "lean" not in fm:
            legacy += 1
            print(f"КАРТОЧКА {hid}: {PRE_MECHANISM_NOTE}, prior_art={len(fm.get('prior_art') or [])}")
            continue
        rc = cmd_gate(type("A", (), {"hid": str(hid), "skip_lean": True})())
        print(f"КАРТОЧКА {hid}: под правилом, {'оформлена' if rc == 0 else 'НАРУШЕНИЯ'}")
    print(f"AUDIT карточек={len(files)} исторических={legacy} под_правилом={len(files) - legacy}")
    return 0


GOOD_CARD = {
    "id": "H-0000", "claim": "посаженный корректный круг", "falsifier": "посаженный фальсификатор",
    "oracle": "лабораторный тест", "date": "2026-10-23", "prior_art": ["L-0000"],
    "lean": {"решение": "не применён",
             "причина": "утверждение говорит о времени и байтах, модель его не задаст",
             "пространство": "нет", "без_времени": "нет",
             "для_всех": "да", "дешевле_стенда": "нет"},
}

# Четыре «да» + «применён»: ветка, в которой гейт обязан потребовать модель и скомпилировать её.
def _lean_applied(модель="lab/lean/VecDHT/Selftest.lean"):
    return {"решение": "применён", "причина": "конечное пространство, ∀-инвариант без времени",
            "модель": модель, "пространство": "да", "без_времени": "да",
            "для_всех": "да", "дешевле_стенда": "да"}


GOOD_MODEL = ("import Std\n\ndef f (n : Nat) : Nat := n + 1\n"
              "def ltB (a b : Nat) : Bool := if a < b then true else false\n\n"
              "theorem up : ((List.range 4).all (fun n => ltB n (f n))) = true := "
              "by native_decide\n")
SORRY_MODEL = ("import Std\n\ntheorem whatever : 1 = 1 := by sorry\n")
BROKEN_MODEL = ("import Std\n\ndef f (n : Nat) : Nat := n +\n")


# (название, мутация карточки, подстрока, по которой узнаём нужную причину отказа)
DEFECTS = [
    ("prior_art пуст", dict(prior_art=[]), "не сделан"),
    ("строки нет в индексе", dict(prior_art=["L-0099"]), "в индексе такой строки нет"),
    ("четыре да и отказ от модели", dict(lean={"решение": "не применён",
                                               "причина": "не захотел писать модель, лень",
                                               "пространство": "да", "без_времени": "да",
                                               "для_всех": "да", "дешевле_стенда": "да"}),
     "рубрика дала четыре «да»"),
    ("применён без модели", dict(lean={"решение": "применён", "причина": "х" * 30,
                                       "пространство": "да", "без_времени": "да",
                                       "для_всех": "да", "дешевле_стенда": "да"}),
     "`lean.модель` не названа"),
    ("нет ключа lean", {"__del__": "lean"}, "нет ключа `lean:`"),
    ("только статьи, код не читали", dict(prior_art=["L-0001"]), "ни одной записи класса"),
    # Модель — самая дорогая ветка гейта (она зовёт компилятор), и до 2026-10-23 ни один
    # посаженный дефект её не касался: «все дефекты отбиты» мог обеспечить и гейт, который
    # отвергает всё подряд. Ниже — три дефекта модели плюс позитивный контроль компиляции.
    ("модель названа, но её нет", dict(lean=_lean_applied(модель="lab/lean/VecDHT/Netu.lean")),
     "не найдена на диске"),
    ("модель с sorry", {"lean": _lean_applied(), "__model__": SORRY_MODEL},
     "содержит sorry"),
    ("модель не компилируется", {"lean": _lean_applied(), "__model__": BROKEN_MODEL,
                                 "__compile__": True},
     "не компилируется"),
]


def _use_root(root):
    globals()["ROOT"] = root
    globals()["INDEX"] = os.path.join(root, "lab", "library", "index.jsonl")


def _temp_lab():
    """Копия рабочего индекса + синтетическая строка L-0000 с целью H-0000.

    Без живой копии индекса selftest падал бы по причине «индекс не найден» и для годной
    карточки — невыполнимый по построению контроль (ДИАГНОЗ-1 из E-0087 уже про это).
    """
    import os
    root = tempfile.mkdtemp(prefix="cycle-gate-selftest-")
    os.makedirs(os.path.join(root, "lab", "hypotheses"))
    os.makedirs(os.path.join(root, "lab", "library"))
    os.makedirs(os.path.join(root, "lab", "lean", "VecDHT"))
    extra = {"id": "L-0000", "title": "самопроверка гейта", "url": "https://github.com/libp2p/specs",
             "cite": "github:libp2p/specs", "verified": "2026-10-23", "depth": "текст выборочно",
             "kind": "спека", "gives": "годная строка для позитивного контроля",
             "targets": ["H-0000"], "status": "в работе", "action": "", "cost_min": 1,
             "opened": "2026-10-23", "ref": "c750236de43cd8b246a824b377dfdb26bae686db",
             "path": "README.md"}
    with io.open(os.path.join(root, "lab", "library", "index.jsonl"), "w", encoding="utf-8") as fh:
        for r in load_index()[0] + [extra]:
            r.pop("_line", None)
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return root


def _gate(root, hid, skip_lean=True):
    saved = ROOT
    _use_root(root)
    buf = io.StringIO()
    real = sys.stdout
    try:
        sys.stdout = buf
        rc = cmd_gate(type("A", (), {"hid": hid, "skip_lean": skip_lean})())
    finally:
        sys.stdout = real
        _use_root(saved)
    return rc, buf.getvalue()


def cmd_selftest(_args):
    """Гейт обязан отбивать посаженные нарушения и пропускать годную карточку."""
    root = _temp_lab()
    try:
        import yaml
    except Exception:
        print("SELFTEST не выполнен: нет PyYAML")
        return 2
    path = os.path.join(root, "lab", "hypotheses", "H-0000-selftest.md")

    model_file = os.path.join(root, "lab", "lean", "VecDHT", "Selftest.lean")

    def write(fm):
        fm = dict(fm)
        drop = fm.pop("__del__", None)
        if drop:
            fm.pop(drop, None)
        body = fm.pop("__model__", None)
        if body is None:
            if os.path.isfile(model_file):
                os.remove(model_file)
        else:
            io.open(model_file, "w", encoding="utf-8").write(body)
        fm.pop("__compile__", None)
        with io.open(path, "w", encoding="utf-8") as fh:
            fh.write("---\n" + yaml.safe_dump(fm, allow_unicode=True, sort_keys=False) +
                     "\n---\n# посадка\n")

    write(GOOD_CARD)
    good_rc, text = _gate(root, "H-0000")
    print(f"  КОНТРОЛЬ годная карточка: rc={good_rc} "
          f"{'ПРОЙДЕН' if good_rc == 0 else 'СЕЛ — гейт блокирует заведомо годный круг'}")
    if good_rc != 0:
        print("".join("    | " + l + "\n" for l in text.splitlines()))
    ok = 1 if good_rc == 0 else 0
    for name, mutation, reason in DEFECTS:
        mutation = dict(mutation)
        compile_it = bool(mutation.get("__compile__", False))
        write(dict(GOOD_CARD, **mutation))
        rc, text = _gate(root, "H-0000", skip_lean=not compile_it)
        if rc == 0:
            mark = "СЕЛ"
        elif reason in text:
            mark = "ОТБИТ"
        else:
            mark = "ОТБИТ НЕ ПО ТОЙ ПРИЧИНЕ"
        print(f"  ДЕФЕКТ {name}: rc={rc} {mark}")
        if rc == 1 and reason not in text:
            print("    | " + " | ".join(l.strip() for l in text.splitlines()
                                        if "НАРУШЕНИЕ" in l)[:220])
        ok += 1 if (rc == 1 and reason in text) else 0
    # Позитивный контроль дорогой ветки: годная модель при четырёх «да» обязана ПРОЙТИ
    # компиляцию. Без него «все дефекты отбиты» удовлетворяет и гейт, который валит всё подряд.
    write(dict(GOOD_CARD, lean=_lean_applied(), __model__=GOOD_MODEL))
    rc_ok, text_ok = _gate(root, "H-0000", skip_lean=False)
    print(f"  КОНТРОЛЬ годная модель при четырёх «да»: rc={rc_ok} "
          f"{'ПРОЙДЕН' if rc_ok == 0 else 'СЕЛ — гейт валит заведомо годный круг'}")
    if rc_ok != 0:
        print("    | " + " | ".join(l.strip() for l in text_ok.splitlines())[:240])
    ok += 1 if rc_ok == 0 else 0
    shutil.rmtree(root, ignore_errors=True)
    total = len(DEFECTS) + 2
    print(f"SELFTEST годный_круг={'пропущен' if good_rc == 0 else 'заблокирован'} "
          f"отбито={ok} из {total}")
    print(f"CYCLEGATE_SELFTEST total={total} passed={ok} good_card_rc={good_rc}")
    return 0 if ok == total else 1


def main():
    # `cycle-gate.py H-0092` без подкоманды: агент, который впервые открыл репозиторий, обязан
    # угадать команду с первой попытки; argparse иначе съедает позиционный аргумент как выбор.
    if len(sys.argv) > 1 and re.match(r"^H-\d{4}$", sys.argv[1]):
        sys.argv.insert(1, "gate")
    # `--audit` вместо `audit`: докстринг долго обещал именно такую форму, и агент, который
    # читал только её, получал «invalid choice» — переводим ошибку в работу, а не в отказ.
    if len(sys.argv) > 1 and sys.argv[1] in ("--audit", "-a"):
        sys.argv[1] = "audit"
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    g = sub.add_parser("gate", help="проверить карточку H-XXXX")
    g.add_argument("hid")
    g.add_argument("--skip-lean", action="store_true")
    a = sub.add_parser("audit", help="отчёт по последним N карточкам")
    a.add_argument("-n", type=int, default=8)
    s = sub.add_parser("selftest", help="посаженные нарушения обязаны отбиваться")
    # обратная совместимость: `cycle-gate.py H-0092` без подкоманды
    args, extra = p.parse_known_args()
    if args.cmd == "gate":
        return cmd_gate(args)
    if args.cmd == "audit":
        return cmd_audit(args)
    if args.cmd == "selftest":
        return cmd_selftest(args)
    if extra and re.match(r"^H-\d{4}$", extra[0]):
        return cmd_gate(type("A", (), {"hid": extra[0], "skip_lean": "--skip-lean" in extra})())
    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
