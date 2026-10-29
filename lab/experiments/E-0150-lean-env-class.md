---
id: E-0150
hypothesis: H-0150
status: testing
verdict: ""
base_commit: "10447f6"
started: "2026-10-29"
environment: "x86_64-pc-windows-gnu, хост владельца; Python 3, bash, elan и Lean v4.36.0-rc1;
сеть наружу не используется — неполное окружение изображается переменной `ELAN_TOOLCHAIN=__nope__`
(elan отвергает имя локально, без скачивания); продукт не правится"
command: "bash lab/e0150-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0150.tsv run1.txt run2.txt`)"
threshold: "(1) пин: `PIN_FOUND=1`, `PRE_FIX_PIN_RC=1`, `PRE_FIX_PIN_BROKEN=6`,
`PRE_FIX_PIN_ENV_LINES=0`; (2) новый страж на неполном окружении: `POST_FIX_PARTIAL_RC=3`,
`POST_FIX_PARTIAL_ENV=partial`, `POST_FIX_PARTIAL_BROKEN_LINES=0`, `POST_FIX_PARTIAL_ALL_OK=0`,
`POST_FIX_PARTIAL_REFUSED=1`; (3) контроль семантики на здоровом окружении: `POST_FIX_MODEL_RC=1`,
`POST_FIX_MODEL_ENV=ok`, `POST_FIX_MODEL_BROKEN=1`, `POST_FIX_MODEL_COMPILE=1`,
`POST_FIX_MODEL_ALL_OK=0`; (4) настоящее дерево: `LEAN_CHECK_EXIT=0`, `LEAN_ENV=ok`,
`LEAN_ENV_PROBE_EXIT=0`, `LEAN_TOTAL=6`, `BROKEN=0`, `DIGEST_BAD=0`, `NATIVE_AXIOMS=126`,
`STD_AXIOMS=18`, `AXIOM_FREE=4`, `LEAN_ALL_OK=1`; (5) самопроверка: `SELFTEST_EXIT=0`,
`SELFTEST_TOTAL=14`, `SELFTEST_PASSED=14`, `SELFTEST_FAILED=0`; (6) границы: `RUST_TOUCHED=0`,
`WIRE_TOUCHED=0`; (7) соседние стражи зелёные (`REVIEW_EXIT`, `LINT_LATEST_EXIT`,
`TEXTGUARD_ALL_EXIT`, `TEXTGUARD_CYCLE_EXIT`, `CLAIMS_EXIT`, `CONTOURS_EXIT`, `MIRROR_EXIT`,
`OQ_EXIT`, `DATE_EXIT`), `LINT_ORPHANS=0`, `TEXTGUARD_ALL_DIRTY=0`; (8) `DISK_GE_15000=1`;
(9) `WORST_RC=0`, `STABLE=1`. Порог заморожен до первого официального прогона
`lab/e0150-run.sh`; изменение любого числа — новая карточка."
---

# E-0150 — класс окружения в страже Lean

## Что проверяется

Гипотеза `H-0150`: прибор `lab/lean-check.py` обязан отличать «сломано окружение» от «сломаны
модели». Круг добавляет пробу `import Std` + `#check List`, печатает `LEAN_ENV=ok|partial` и на
отказе пробы возвращает код 3, не печатая `BROKEN`. Прежняя семантика в здоровом окружении
сохраняется: некомпилирующаяся модель даёт `BROKEN=1` и причину `COMPILE:`.

## Почему это не косметика

`E-0149` покраснел на неполном тулчейне: шесть моделей «сломались» за 1 678 мс, хотя сломано было
окружение. Вердикт цикла сказал бы «модели сломаны» — ложный класс отказа, который стоит часов
поиска и подрывает доверие к `LEAN_ALL_OK`. Обратная ошибка (молча пропустить неполное окружение)
хуже: зелёный страж перестал бы что-либо значить.

## Границы

* Проба — необходимое условие, а не полная диагностика: ядро, память и кодировка могут сломаться
  глубже, и тогда отказ снова станет модельным. Это названная граница.
* Код 3 новый; `workspace-verify.sh` краснит любой ненулевой этап, но причина теперь названа.
* Проба стоит один запуск `lean`; цена печатается и гейтом не является.
* Прибор не доказывает, что модели верны: он доказывает лишь, что в этом окружении отказ модели
  действительно относится к модели.

## Что считается вердиктом

Только факты порога. Содержание круга — пара «пин с неполным окружением печатает `BROKEN=6` и не
знает `LEAN_ENV`» против «новый страж печатает `LEAN_ENV=partial`, код 3 и ни одной строки
`BROKEN`», плюс контроль «в здоровом окружении сломанная модель по-прежнему `BROKEN=1` с причиной
`COMPILE:`» и неизменные числа настоящего дерева (`126/18/4`, `DIGEST_BAD=0`).
