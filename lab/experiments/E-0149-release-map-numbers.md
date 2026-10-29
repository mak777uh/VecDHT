---
id: E-0149
hypothesis: H-0149
status: closed
verdict: supports
base_commit: "fee5f70"
started: "2026-10-29"
environment: "x86_64-pc-windows-gnu, хост владельца; Python 3, bash и cargo; сеть наружу не
используется; PRE_FIX снимается из пина через `git show`; продукт не правится, но тест `gates_p4`
исполняется как носитель строки P4"
command: "bash lab/e0149-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0149.tsv run1.txt run2.txt`); носители — `python lab/check-release-map.py
selftest`, `python lab/check-release-map.py` и `cargo test -p vecdht-node --test gates_p4 --
--nocapture --test-threads=1`"
threshold: "(1) пин: `PIN_FOUND=1`, `PRE_FIX_GUARD_OLD=1`, `PRE_FIX_NONE_PASSES=1`,
`PRE_FIX_PREFIX_PASSES=1`, `PRE_FIX_LOG_UNSUPPORTED=1`; (2) стражи: `POST_FIX_NONE_CAUGHT=1`,
`POST_FIX_PREFIX_CAUGHT=1`, `POST_FIX_LOG_OK=1`, `SELFTEST_EXIT=0`, `SELFTEST_TOTAL=20`,
`SELFTEST_PASSED=20`, `SELFTEST_FAILED=0`; (3) строка P4: `P4_LOG_FOUND=1`, `P4_LOG_VALUE=5`,
`P4_TEST_EXIT=0`, `P4_NOW=5`, `P4_MATCH=1`; (4) карта: `MAP_EXIT=0`, `MAP_ROWS=16`, `ROWS_REGISTERED=16`,
`ROWS_UNREGISTERED=0`, `ROWS_MISSING=0`, `MAP_DUP=0`, `EIDS=25`, `EIDS_MISSING=0`, `EIDS_OPEN=0`,
`ADRS=3`, `ADRS_MISSING=0`, `PATHS=25`, `PATHS_MISSING=0`, `OWNERS=16`, `OWNERS_MISSING=0`,
`OWNERS_MISSING_IDS=none`, `FACTS=23`, `FACTS_OK=23`, `STALE=0`, `STALE_ROWS=none`; (5) числа:
`NUMBERS=43`, `NUMBERS_OK=43`, `NONE_ROWS=7`, `NUMBERS_UNDECLARED=0`, `NUMBERS_UNDECLARED_IDS=none`,
`NUMBERS_PHANTOM=0`, `NUMBERS_PHANTOM_IDS=none`, `PROV_BAD=0`; (6) границы: `WIRE_TOUCHED=0`,
`RUST_TOUCHED=0`; (7) соседние стражи зелёные (`SECRETS_EXIT`, `REFS_EXIT`, `CLAIMMAP_EXIT`,
`CLAIMS_EXIT`, `CONTOURS_EXIT`, `MIRROR_EXIT`, `GATE_AUDIT_EXIT`, `REVIEW_EXIT`, `LINT_LATEST_EXIT`,
`TEXTGUARD_ALL_EXIT`, `TEXTGUARD_CYCLE_EXIT`), `LINT_ORPHANS=0`, `TEXTGUARD_ALL_DIRTY=0`;
(8) `DISK_GE_15000=1`; (9) `WORST_RC=0`, `STABLE=1`. Порог заморожен до первого официального
прогона `lab/e0149-run.sh`; изменение любого числа — новая карточка."
---

# E-0149 — числа релиз-карты против своих носителей

## Что проверяется

Гипотеза `H-0149`: все числа девяти строк `docs/RELEASE-MAP-v1.md` связаны с носителями, семь строк
без чисел утверждают их отсутствие, а строка P4 получает сохранённый вывод теста вместо
необеспеченного разложения «4 с». Круг расширяет `lab/check-release-map.py` (целое число вместо
подстроки, `none` как утверждение, типы «не число», провенанс `log:`), заполняет
`lab/release-map-rows.tsv` 43 числами и доказывает тремя посаженными лжами, что старый страж их
пропускал.

## Почему это не косметика

Прошлый круг проверял числа только у одной строки. Остальные числа карты — тезисы о готовности,
которые читают как факты; без сверки подмена или округление в свою пользу не краснеют. Новый порог
называет цену: 43 числа, 7 строк `none`, 20 посадочных случаев и сохранённый носитель P4.

## Границы

Прибор проверяет наличие числа в носителе, а не смысл; реестр подписан нами, полнота не
доказывается; `@prev` наследует карточки для провенанса, но не имя владельца; классы «не число»
объявлены списком; поведение теста прибор не доказывает.

## Что считается вердиктом

Только факты, названные в пороге. Содержание круга — `PRE_FIX_NONE_PASSES=1`,
`PRE_FIX_PREFIX_PASSES=1`, `PRE_FIX_LOG_UNSUPPORTED=1` против `POST_FIX_NONE_CAUGHT=1`,
`POST_FIX_PREFIX_CAUGHT=1`, `POST_FIX_LOG_OK=1` и носитель `P4_LOG_VALUE=5`; покрытие —
`NUMBERS=43`, `NONE_ROWS=7`, `SELFTEST_PASSED=20` и нули находок.

## Поправка до официальных прогонов

Пин `cced85f` заморозил `PATHS=24` — это был мой ручной счёт. Предварительный прогон helper'а
напечатал `PATHS=25`. Независимый пересчёт карты тем же правилом отбора (обратные кавычки, есть
`/`, нет пробелов, не `/p2p`, не `<`) даёт те же 25 имён, каждое разрешается на диске; новых путей
этот круг в карту не добавлял (лог P4 живёт в реестре как `log:`, а не в тексте карты). По правилу
«свип покрывает ровно столько единиц, сколько насчитал прибор» замороженное число исправлено на 25
до первого официального прогона; пороги исхода (посадочные лжи, `P4_*`, `NUMBERS`, `NONE_ROWS`,
селфтест) не менялись. История: пин хранит 24, и это видно в `git show cced85f:…`.

Тот же предварительный прогон поймал вторую форму того же дефекта: таблица `want` внутри helper'а
повторяла замороженные ожидания третьей копией (карточка, `lab/expectations/e0149.tsv`, helper), и
исправление двух из трёх оставило helper с ручными 24. По правилу «у имени факта один владелец»
список `want` удалён: helper читает `lab/expectations/e0149.tsv` построчно и сверяет всё, кроме
`STABLE` (его печатает оракул второго прогона) и `WORST_RC` (итог того же блока). Владельцем
ожиданий теперь таблица; карточка описывает смысл порога, но чисел не дублирует.

## Результат

`supports`. Носитель — `lab/logs/e0149-all.log`.

Обе посаженные лжи старый страж пропускал, новый ловит: дописанное число «1 777» в строке без чисел
(`PRE_FIX_NONE_PASSES=1` → `POST_FIX_NONE_CAUGHT=1`), округлённое `2.25` вместо `2.2536` в реестре
(`PRE_FIX_PREFIX_PASSES=1` → `POST_FIX_PREFIX_CAUGHT=1`). Владелец `log:` старым стражем не
принимался вовсе (`PRE_FIX_LOG_UNSUPPORTED=1`), новый принимает сохранённый вывод и сверяет его с
текущим прогоном: `P4_LOG_VALUE=5`, `P4_NOW=5`, `P4_MATCH=1`, `P4_TEST_EXIT=0`. Самопроверка
`20/20`.

На исправленной карте: `MAP_ROWS=16`, `ROWS_REGISTERED=16`, `ROWS_UNREGISTERED=0`,
`ROWS_MISSING=0`, `MAP_DUP=0`; `EIDS=25`, `EIDS_MISSING=0`, `EIDS_OPEN=0`; `ADRS=3`,
`ADRS_MISSING=0`; `PATHS=25`, `PATHS_MISSING=0`; `OWNERS=16`, `OWNERS_MISSING=0`;
`FACTS=23`, `FACTS_OK=23`, `STALE=0`; `NUMBERS=43`, `NUMBERS_OK=43`, `NONE_ROWS=7`,
`NUMBERS_UNDECLARED=0`, `NUMBERS_PHANTOM=0`, `PROV_BAD=0`.

Два официальных прогона на неизменном дереве: `ОЖИДАНИЙ=64 РАСХОЖДЕНИЙ=0`, `WORST_RC=0`,
`STABLE=1` во втором. Полная верификация: `VERIFY_FAIL=0`, 136 срезов, 791 passed, 0 failed,
9 `#[ignore]`, `SECONDS_total=2140`, диск 12 360 МБ на момент блока (после очистки `target/` —
27 995 МБ). Lean: `BROKEN=0`, `DIGEST_BAD=0`, `LEAN_EXIT=0`. Продукт и провод не тронуты
(`RUST_TOUCHED=0`, `WIRE_TOUCHED=0`).

## Итог верификации и починка тулчейна

Первый блок верификации был красным не из-за круга: у тулчейна хоста
`leanprover--lean4---v4.36.0-rc1` отсутствовали `bin/lake.exe` и `lib/`, и все шесть моделей падали
на COMPILE за ~160 мс (`BROKEN=6`). По слову владельца тулчейн переустановлен: `elan` сам скачать не
смог (`[35] SSL connect error`), архив `lean-4.36.0-rc1-windows.zip` (889 657 541 байт) взят curl'ом
с того же релиза и распакован в каталог тулчейна (18 244 файла); `lake` — 5.0.0-src+c9afcdd.
На локальном 4.33.1 до этого получены те же `NATIVE_AXIOMS=126`, `STD_AXIOMS=18`, `AXIOM_FREE=4`,
`DIGEST_BAD=0` — две разные тулчейны согласны в классификации аксиом. Второй блок (4.33.1) прерван
ради переустановки и вердиктом не считается; зелёный — третий, на восстановленном замороженном
тулчейне.

## Диагнозы

1. Замороженный порог жил в трёх копиях — карточка, `lab/expectations/e0149.tsv` и список `want`
   внутри helper'а; исправление двух оставило третью с ручными `PATHS=24`. Список удалён, ожидания
   читаются из таблицы.
2. Запуск верификации без метки блока отбился usage-сообщением самого скрипта, а не этапом: метка
   обязательна (`LABEL="${1:?...}"`), helper обязан её передавать.
3. Страж моделей не отличает «модель не компилируется» от «тулчейн неполон» и печатает `BROKEN=6`
   там, где сломано окружение. Кандидат в очередь — `OPEN-QUESTIONS` п. 90.

Остатки: прибор сверяет наличие числа в носителе, а не смысл утверждения; реестр подписан нами,
полнота не доказывается; строка P4 утверждает ровно то, что печатает тест, — «из них 4 с на
доставку» из спеки снято как арифметика прозы (`OPEN-QUESTIONS` п. 89).
