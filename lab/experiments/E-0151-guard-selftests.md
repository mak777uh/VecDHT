---
id: E-0151
hypothesis: H-0151
status: closed
verdict: supports
base_commit: "7f0f23a"
started: "2026-10-29"
environment: "x86_64-pc-windows-gnu, хост владельца; Python 3, bash; сеть наружу не используется;
fixtures строятся в `mktemp -d`, рабочее дерево во время прогона не правится; продукт не трогается"
command: "bash lab/e0151-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0151.tsv run1.txt run2.txt`)"
threshold: "(1) пин: `PRE_FIX_PIN_FILE_ABSENT=1`, `PRE_FIX_PIN_GUARDS_SAME=1`, `PRE_FIX_RC=1`,
`PRE_FIX_GUARDS=14`, `PRE_FIX_WITHOUT=check-release-kit.sh,check-spec-mirror.sh,check-text-clean.sh`,
`PRE_FIX_UNWIRED=check-artifact-refs.py,check-secrets.sh`, `PRE_FIX_FINDINGS=5`; (2) рабочее дерево:
`POST_FIX_RC=0`, `POST_FIX_GUARDS=15`, `POST_FIX_WITHOUT=none`, `POST_FIX_UNWIRED=none`,
`POST_FIX_FINDINGS=0`; (3) каждая посадка исполняется: `KIT_SELFTEST_CASES=3`/`PASSED=3`,
`MIRROR_SELFTEST_CASES=4`/`PASSED=4`, `TEXT_SELFTEST_CASES=5`/`PASSED=5`, `REFS_SELFTEST=ok`,
`SECRETS_SELFTEST=ok`, `GSE_SELFTEST_CASES=3`/`PASSED=3`, `GSE_SELFTEST_DIRTY=1`, все `*_RC=0`;
(4) границы: `RUST_TOUCHED=0`, `WIRE_TOUCHED=0`; (5) соседние стражи зелёные (`KIT_EXIT`,
`MIRROR_EXIT`, `TEXTGUARD_ALL_EXIT`, `TEXTGUARD_CYCLE_EXIT`, `REVIEW_EXIT`, `LINT_LATEST_EXIT`,
`CLAIMS_EXIT`, `CONTOURS_EXIT`), `LINT_ORPHANS=0`, `TEXTGUARD_ALL_DIRTY=0`; (6) `DISK_GE_15000=1`;
(7) `WORST_RC=0`, `STABLE=1`. Порог заморожен до первого официального прогона
`lab/e0151-run.sh`; изменение любого числа — новая карточка."
---

# E-0151 — посадка дефекта у каждого стража

## Что проверяется

Гипотеза `H-0151`: зелёный страж без посаженной ошибки — зелёный по доверию. Круг заводит
мета-страж `lab/check-guard-selftests.py`, который берёт список приборов из каталога `lab/` по
префиксу `check-`, требует у каждого режим самопроверки и вызов этой самопроверки в контуре
(`verify.yml` или `workspace-verify.sh`), и даёт трём приборам режим, которого у них не было:
`check-release-kit.sh`, `check-spec-mirror.sh`, `check-text-clean.sh`. Самопроверки
`check-artifact-refs.py` и `check-secrets.sh` получают вызов в контуре.

## Почему это не косметика

Стражи — единственный исполняемый довод, что документы и CI не разошлись с деревом. Страж, который
не краснел ни разу, защищает так же, как выключенный: его ноль неотличим от «не смотрел».
Контрольная пара `E-0150` показала класс с другой стороны: прибор покраснел по неверной причине, и
рядом стоял оракул, который это назвал. У самого стража оракула нет — его заменяет посадка.

## Границы

* Мета-страж доказывает наличие режима и его вызов, а не качество посадки: узкая посадка может
  пропускать другой дефект того же прибора. Названо, а не обещано.
* Посадка `check-release-kit.sh` сажает пустой корень и один снятый флаг (`upload-artifact`);
  расхождение версий между носителями посажено не было — это граница, а не скрытая проверка.
* Список приборов берётся по префиксу `check-`; прибор с другим именем в счёт не попадёт —
  правило имени становится частью контракта.
* Продукт не трогается: круг правит `lab/` и `.github/workflows/`.

## Что считается вердиктом

Только факты порога: пара «пин: 14 приборов, 5 находок» против «после правки: 15 приборов,
0 находок», исполнение каждой посадки с кодом 0 и названными случаями, неизменность продукта.

## Результат

`supports`. Носитель — `lab/logs/e0151-all.log`.

Пин (`7f0f23a`, стражи побайтово равны дереву `3f47d0b`): 14 приборов, `PRE_FIX_FINDINGS=5`,
`PRE_FIX_RC=1`, мета-стража в пине нет — дыра названа отсутствием. Рабочее дерево `d5c99f3`:
`POST_FIX_GUARDS=15`, `POST_FIX_FINDINGS=0`, `POST_FIX_WITHOUT=none`, `POST_FIX_UNWIRED=none`.
Посадки: `KIT_SELFTEST_CASES=3`/`PASSED=3`, `MIRROR_SELFTEST_CASES=4`/`PASSED=4`,
`TEXT_SELFTEST_CASES=5`/`PASSED=5`, `REFS_SELFTEST=ok`, `SECRETS_SELFTEST=ok`,
`GSE_SELFTEST_CASES=3`/`PASSED=3` при `GSE_SELFTEST_DIRTY=1`; все `*_RC=0`. Соседние стражи зелёные,
`LINT_ORPHANS=0`, `TEXTGUARD_ALL_DIRTY=0`, `RUST_TOUCHED=0`, `WIRE_TOUCHED=0`.

Два официальных прогона на неизменном дереве: `ОЖИДАНИЙ=47 РАСХОЖДЕНИЙ=0`, `DIFF=none`, `WORST_RC=0`,
`STABLE=1` во втором. Полная верификация `bash lab/workspace-verify.sh E-0151`: блок на строке
180 326 файла `lab/logs/workspace-verify-2026-10-22.log` (2 548 строк), 136 срезов, 791 passed,
0 failed, 9 ignored, все самопроверки исполнены внутри контура (`KIT_SELFTEST_EXIT=0` …
`GSE_EXIT=0`), `VERIFY_FAIL=0`, `SECONDS_total=3181`.

Граница: посадка доказывает умение краснеть на названном дефекте, а не полноту класса; узкая посадка
проходит мета-стража. Это названо, а не спрятано.
