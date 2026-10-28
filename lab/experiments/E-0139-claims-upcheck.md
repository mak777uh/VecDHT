---
id: E-0139
hypothesis: H-0139
status: closed
verdict: supports
base_commit: "46641f6"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; только bash и python — цикл не исполняет cargo и
не поднимает сеть, потому что измеряет связность собственного реестра с собственными носителями;
посадка работает копией `lab/claims.tsv` с `trap`-возвратом, носители (`docs/STATUS-v1.md`,
`README.md`, `README.ru.md`) во время прогона не трогаются; PRE_FIX исполняется посадкой пина
(`git show пин:файл` с перенаправлением в файл; форма `git checkout <пин> -- файл` отвергнута,
потому что пишет в индекс — см. раздел «Поправка») и доказательством числа строк пина через
`git show`; дата
карточки судится по UTC (`ADR-0070`)"
command: "bash lab/e0139-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0139.tsv`); PRE_FIX — тот же helper, посадка пина с `trap`-возвратом"
threshold: "(1) `python lab/cycle-gate.py gate H-0139` выход 0 (`GATE_H0139_OK=1`), диск ≥ 15 000 МБ
до прогона; (2) самопроверка исполняется: `PLANTED_TOTAL=8`, `PLANTED_CAUGHT=8`, `PLANTED_FALSE=0`,
`LEGAL_TOTAL=6`, `UP_PLANTED=3`, `UP_CAUGHT=3`, `UP_FALSE=0`, `SELFTEST_EXIT=0`; (3) PRE_FIX называет
дыру числом: `PRE_FIX_PIN_FOUND=1`, `PRE_FIX_PIN_ROWS=17`, `PRE_FIX_PIN_ROWS_LIVE=37`,
`PRE_FIX_PLANTED=1`, `PRE_FIX_EXIT=1`, `PRE_FIX_CLAIMS=17`, `PRE_FIX_TRIGGER_SENTENCES=26`,
`PRE_FIX_UNREGISTERED=20`, `PRE_FIX_UP_CARRIERS=3`, `PRE_FIX_VIOLATIONS=20`, все нисходящие ключи
(`DANGLING`, `CEILING`, `QUALIFIER`, `TYPE_BAD`, `LINK_BAD`, `GATE_RATIO`, `COND_LINK_BAD`) нули,
`PRE_FIX_CONDITIONS_TABLE=5`, `PRE_FIX_CONDITIONS_COVERED=5`, `PRE_FIX_READY_CARRIERS=3`,
`PRE_FIX_READY_VALUES=1`, `PRE_FIX_DIFFERS=1`, `PRE_FIX_TRIGGER_EQUALS_LIVE=1`; (4) живое дерево после
починки зелёное: `GUARD_EXIT=0`, `LIVE_CLAIMS=37`, `LIVE_TRIGGER_SENTENCES=26`, `LIVE_UNREGISTERED=0`,
`LIVE_UP_CARRIERS=3`, `LIVE_VIOLATIONS=0`, `LIVE_DANGLING=0`, `LIVE_CEILING=0`, `LIVE_QUALIFIER=0`,
`LIVE_TYPE_BAD=0`, `LIVE_LINK_BAD=0`, `LIVE_GATE_RATIO=0`, `LIVE_COND_LINK_BAD=0`,
`LIVE_CONDITIONS_TABLE=5`, `LIVE_CONDITIONS_COVERED=5`, `LIVE_READY_CARRIERS=3`, `LIVE_READY_VALUES=1`,
`LIVE_UNREGISTERED_LIST=none`, `CLAIMS_INSTRUMENT_EXISTS=1`, `CLAIMS_REGISTRY_ROWS=37`; (5) прибор
стоит в контуре и в CI: `VERIFY_WIRES_CLAIMS=1`, `CI_WIRES_CLAIMS=1`; (6) соседние стражи не
рассоединились: `SECRETS_EXIT=0`, `REFS_EXIT=0`, `CLAIMMAP_EXIT=0`, `CONTOURS_EXIT=0`,
`TEXTGUARD_ALL_EXIT=0`, `TEXTGUARD_ALL_DIRTY=0`, `TEXTGUARD_CYCLE_EXIT=0`, `MIRROR_EXIT=0`,
`LINT_EXIT=0`, `LINT_ORPHANS=0`, `GATE_AUDIT_EXIT=0`, `REVIEW_EXIT=0`; (7) продукт не тронут:
`RUST_TOUCHED=0`; (8) `WORST_RC=0` и два исполнения на неизменном дереве печатают один вектор —
`STABLE=1`. Порог заморожен до первого официального прогона `lab/e0139-run.sh`; изменение любого
числа — новая карточка. Вектор снимается на дереве починки до прогона полного контура: блок
`E-0139 · workspace-verify` появляется в контуре закрытия и сдвинул бы соседа `check-contours.py`
(`CLOSED_TOTAL`), поэтому постконтурное число печатается в носителе отдельно и в порог не входит."
---

# E-0139 — восходящая сверка реестра утверждений с носителями

Карточка заведена вместе с прибором (`lab/check-claims.py`, ключи `TRIGGER_SENTENCES`,
`UNREGISTERED`, `UP_CARRIERS`, `UNREGISTERED_LIST`) и таблицей ожиданий `lab/expectations/e0139.tsv`.
Утверждение, фальсификатор и оракул — в `lab/hypotheses/H-0139-claims-upcheck.md`; здесь лежит только
замороженный порог.

## Что уже измерено до официальных прогонов (разведка прибором)

Прибор прогнан на живом дереве при сборке. Три носителя печатают `TRIGGER_SENTENCES=26`, из них
`UNREGISTERED=20`, `UP_CARRIERS=3`, `CLAIMS=17`, `VIOLATIONS=20`, `DANGLING=0`, `CEILING=0`,
`CONDITIONS_TABLE=5`, `CONDITIONS_COVERED=5`, `READY_VALUES=1`, выход 1. Самопроверка: 8/8 нисходящих
посадок отбиты, `PLANTED_FALSE=0`, `LEGAL_TOTAL=6`, восходящих посажено 3 и поймано 3, `UP_FALSE=0`.

## Дыра, найденная уже этим кругом при сборке прибора

Первая версия восходящей сверки считывала заголовок `# Status of v1: gates, what closed them, and what
is not there` как утверждение: нормализация склеивала строку с следующим предложением, и ложная находка
уводила число дыры. Починка — заголовки markdown исключены из носителя до разрезки на предложения
(`body_for_up`), что изменило вектор разведки с `TRIGGER=28, UNREGISTERED=22` на `26` и `20`. Второй
находкой стал собственный лексикон прибора: тип `estimate` требовал слова `оценка` и не принимал
`оценкой`, а `NEGATION` для `not-done` знал только английские отрицания, поэтому русская строка «не
сделано, как есть» не проходила потолок и регистрировать её было нечем. Оба случая — тот же класс, что
у `E-0138`: проверка формы там, где надо проверять множество, и список слов там, где надо проверять
корень.

## Результат (измерено, носитель `lab/logs/e0139-all.log`)

Цепочка деревьев: пре-регистрация `21c0012` → починка `5c90c3b` (20 строк реестра) → починка
`55784fd` (форма печати: один ключ на строку, `none` вместо молчания) → починка `466c328`
(восстановление реестра в HEAD и отказ от посадкой через индекс). Третий коммит не был в тексте
карточки, см. «Поправка».

Два официальных исполнения на неизменном дереве `466c328`: `ОЖИДАНИЙ=69 РАСХОЖДЕНИЙ=0`, `STABLE=1`,
`WORST_RC=0`, `RUST_TOUCHED=0`; снимки различаются `DISK_FREE_MB` (17 116 и 17 114, ключ исключён из
сверки) и появляющимся во втором `STABLE=1`.

Самопроверка исполнением: `PLANTED_TOTAL=8`, `PLANTED_CAUGHT=8`, `PLANTED_FALSE=0`, `LEGAL_TOTAL=6`,
из них вверх-проб `UP_PLANTED=3`, `UP_CAUGHT=3`, `UP_FALSE=0`, `SELFTEST_EXIT=0`, `GUARD_EXIT=0`.

PRE_FIX посадкой пина: `PRE_FIX_PIN_ROWS=17` при `PRE_FIX_PIN_ROWS_LIVE=37`, `PRE_FIX_EXIT=1`,
`PRE_FIX_CLAIMS=17`, `PRE_FIX_TRIGGER_SENTENCES=26`, `PRE_FIX_UNREGISTERED=20`,
`PRE_FIX_VIOLATIONS=20`, все вниз-ключи (`DANGLING`, `CEILING`, `QUALIFIER`, `TYPE_BAD`, `LINK_BAD`,
`GATE_RATIO`, `COND_LINK_BAD`) нулевые, `PRE_FIX_DIFFERS=1`. Разбивка дыры по носителям посчитана
повторным вызовом прибора с реестром пина во временном каталоге: `README.md` 4, `README.ru.md` 8,
`docs/STATUS-v1.md` 8.

Живое дерево после починки: `CLAIMS=37`, `TRIGGER_SENTENCES=26`, `UNREGISTERED=0`, `VIOLATIONS=0`,
`UNREGISTERED_LIST=none`, `CONDITIONS_TABLE=5`, `CONDITIONS_COVERED=5`, `READY_CARRIERS=3`,
`READY_VALUES=1`, `GUARD_EXIT=0`. Равенство `PRE_FIX_TRIGGER_SENTENCES=26 = LIVE_TRIGGER_SENTENCES=26`
(`PRE_FIX_TRIGGER_EQUALS_LIVE=1`) — то, что отличает закрытие дыры от уничтожения текста: носители за
весь цикл не изменены ни одним байтом. Постановка в контур и в CI: `VERIFY_WIRES_CLAIMS=1`,
`CI_WIRES_CLAIMS=1`.

Полный контур `bash lab/workspace-verify.sh E-0139`: `VERIFY_FAIL=0`, 134 среза `^test result:`,
907 пройденных, 0 падений, 9 `#[ignore]`, `SECONDS_total=1672` (`SECONDS_test=1360`,
`SECONDS_clippy=6`, `SECONDS_lean=58`), `TEST_EXIT=0`, `CLIPPY_EXIT=0`, `LEAN_EXIT=0`, внутри контура
`CONTOURS_SELFTEST_EXIT=0` и `CONTOURS_EXIT=0`, диск 17 110 МБ до и 26 798 МБ после. Соседние стражи
цикла: `SECRETS_EXIT=0`, `REFS_EXIT=0`, `CLAIMMAP_EXIT=0`, `CONTOURS_EXIT=0`,
`TEXTGUARD_ALL_EXIT=0` при `файлов_с_грязью=0`, `TEXTGUARD_CYCLE_EXIT=0`, `MIRROR_EXIT=0`,
`LINT_EXIT=0`, `LINT_ORPHANS=0`, `GATE_AUDIT_EXIT=0`, `REVIEW_EXIT=0`.

## Поправка после исполнения (append-only; разделы выше не переписаны)

(а) Порог карточки предполагал два коммита починки, их оказалось три: `466c328` понадобился потому,
что `git checkout "$PIN" -- lab/claims.tsv` в посадчике кладёт blob пина в индекс, а следующий
`git commit` берёт индекс целиком — починка `5c90c3b` молча откатилась в HEAD, и повторный
`git checkout HEAD -- lab/claims.tsv` уничтожил её в рабочем дереве. Два исполнения того периода
сводились с таблицей ожиданиями (`РАСХОЖДЕНИЙ=0`), но мерили дерево без починки: сверка читает
вектор прогона, а не содержимое HEAD, и отличить одно от другого не может. Посадка переписана на
перенаправление `git show "$PIN:$REG" > "$REG"` с `trap`-возвратом, реестр восстановлен из `5c90c3b`,
исполнения повторены на дереве `466c328`. Правило круга: посадчик не имеет права трогать индекс, а
годовость починки в HEAD проверяется `git show HEAD:<файл>`, а не собственным коммитом.

(б) Вектор разведки `TRIGGER=28, UNREGISTERED=22` в разделе «Дыра, найденная уже этим кругом» оставлен
как напечатанный, но официальный порогу предшествовал измеренный `26 / 20`: нормализация склеивала
markdown-заголовок со следующим предложением, и два заголовка считались утверждениями. Разница
сохранена числом, а не стёрта, потому что иначе нельзя сказать, что починка заголовков убрала ровно
две ложные находки и ни одного настоящего факта.

(в) Первый прогон сведения по всем таблицам ожиданий дал 319 сирот вместо честных 27: в `--sources`
попал только helper, а не набор `crates`, `benches`, `lab`, который использует `--latest`. Число
сирот без названия перечитанного набора источников не факт, а artifact вызова — это записано в
`OPEN-QUESTIONS` п. 79 как требование к форме следующего круга.

## Итог исполнения

Вердикт `supports`: фальсификатор не сработал ни по одному пункту порога. Восходящее покрытие
реестра исполняется машиной (`lab/check-claims.py`, ключ `UNREGISTERED`, стоит в контуре и в CI),
20 найденных дыр закрыты 20 строками реестра без единого изменения носителей, а нуль `UNREGISTERED`
означает ровно то, что 26 сильных утверждений трёх носителей имеют строки. Остатки: закрытый список
признаков силы узнаёт только свои глаголы и обязан перечитываться, а полное сведение 43 таблиц
ожиданий до сих пор не исполняется контуром — кандидат `H-0140`.

## Поправка числа (append-only; разделы выше не переписаны)

В разделе выше напечатано «907» пройденных тестов. Это число не воспроизводится из блока контура
этого круга: пересчёт по строкам `^test result:` блока `########## E-0139 · workspace-verify ·
2026-10-28T04:14:29+03:00 ##########` даёт 134 среза, 786 пройденных тестов, 0 падений,
9 `#[ignore]`. Входы пересчёта печатаются одной командой, строки блока — 142883..144834 в
`lab/logs/workspace-verify-2026-10-22.log`:

    sed -n '142883,144834p' lab/logs/workspace-verify-2026-10-22.log | grep '^test result:' |       awk -F'[ ;]' '{s+=$4; c++} END {print "срезов=" c " passed=" s}'

Значение 907 попало в носитель из памяти о прежнем прогоне, а не из напечатанного вектора, — ровно
тот класс, против которого стоит правило «число обязано быть напечатано носителем». Остальные числа
того же абзаца (`VERIFY_FAIL=0`, 134 среза, 0 падений, 9 `#[ignore]`, `SECONDS_total=1672`,
`TEST_EXIT=0`, `CLIPPY_EXIT=0`, диск 17 110 МБ до и 26 798 МБ после) сверены с блоком и не изменены.
Вердикт круга от поправки не меняется: он держится на 69 замороженных ожиданиях при нуле расходов,
на `STABLE=1` и на зелёном контуре, а не на числе тестов.
