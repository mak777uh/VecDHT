---
id: E-0129
hypothesis: H-0129
status: completed
base_commit: "336e7d5"
started: "2026-10-26"
finished: "2026-10-27"
environment: "x86_64-pc-windows-gnu, хост владельца (UTC+3); bash + sed + awk + grep + python 3 из
PATH, PyYAML 6.0.3 (нужен `lab/cycle-gate.py`); PATH дополнен /c/Users/Admin/mingw64/bin. Код Rust
цикл не трогает (`CODE_CHANGED_RS=0`), `cargo` в helper'е не вызывается: предмет — текст двух файлов
механизма, индекс и часы процесса. Часовой пояс меняется исполнением с явным `TZ` (`UTC` и
`Australia/Sydney`), windows-python его уважает. Три перенесённые ловушки хоста: вывод `subprocess`
без явной кодировки декодируется локальной страницей (cp1251) и падает на кириллице; сводные
утверждения печатаются ключами, а не подписями; захват кода возврата — `r=0` + `cmd || r=$?`
(класс `E-0128`: точка с запятой убила бы этот helper на первой же красной команде)"
command: "bash lab/e0129-run.sh"
threshold: "(1) `python lab/cycle-gate.py H-0129` выход 0; диск >= 15 000 МБ до измерений и после
них (печатаются три числа: диск/RAM/pagefile). (2) PRE_FIX на дереве пина `336e7d5` из `git archive`
нынешним прибором с ЗАМОРОЖЕННЫМИ ЧАСАМИ (`VEC_DHT_DDF_TODAY=2026-10-26`):
`PRE_FIX_DDF_LOCAL_TODAY_CALLS=7`, `PRE_FIX_DDF_FUNNEL_FILES=0`, `PRE_FIX_DDF_USE_WRITES_OPENED=1`,
`PRE_FIX_DDF_CLOSE_NO_CLOSED=1`, `PRE_FIX_DDF_AUDIT_NO_GATE=1`, `PRE_FIX_DDF_DATES_AFTER_UTC=4`,
`PRE_FIX_DDF_LEGACY_LOCAL_STAMP=0`, `PRE_FIX_DDF_RECORDS=39`, `PRE_FIX_DDF_FINDINGS=11`,
`PRE_FIX_DDF_BLIND=0`, `PRE_FIX_DDF_CLOCK_FROZEN=1`, `PRE_FIX_DDF_CLOCK_DATE=2026-10-26`,
`PRE_FIX_DDF_EXIT=1`, `PRE_FIX_CLOCK_FROZEN_OK=1`. Требование `CLOCK_FROZEN=1` стоит в пороге
специально: без замороженных часов краснота пина держится только пока местный день не догнал UTC,
то есть завися от часа съёма (правило 7 (е)); ловушка сработала на этом же вечере — прогон после
00:00 UTC дал бы на пине `DATES_AFTER_UTC=0`. (3) Инвариантный свидетель местного домена в байтах
пина, пересчитанный независимо от прибора: `PRE_FIX_PIN_FUTURE_DATES=4` (столько полей дат в индексе
пина лежат позже его UTC-дня), `PRE_FIX_PIN_RECOUNT_EQ=1` (пересчёт сошёлся с прибором и число
ненулевое), `PRE_FIX_DOMAIN_DEFECT_WITNESSED=1` (свидетель + стирание `opened` + семь местных дат —
все три вместе). Краснота `library.py` пина в двух поясах (TZ=UTC против местного часа) в таблицу НЕ
входит и печатается только в носитель: у кода пина часового шва нет, а подделывать предмет измерения
нельзя. (4) Аудит пина без гейта: на посаженной карточке внутри копии пина
`PRE_FIX_AUDIT_PLANT_EXIT=0` при `PRE_FIX_AUDIT_PLANT_FAIL_LINES=1` — то есть вердикт напечатан, а
шаг зелёный: `PRE_FIX_AUDIT_PIN_SILENT=1`. (5) Живой прогон `python lab/check-date-domain.py check
--require-git` на починном дереве: `DDF_FILES=3`, `DDF_DATE_FILES=2`, `DDF_LOCAL_TODAY_CALLS=0`,
`DDF_CUTOVER=2026-10-26`, `DDF_FUNNEL_FILES=2`, `DDF_USE_WRITES_OPENED=0`, `DDF_CLOSE_NO_CLOSED=0`,
`DDF_AUDIT_NO_GATE=0`, `DDF_RECORDS=41`, `DDF_DATE_FIELDS=85`, `DDF_DATES_AFTER_UTC=0`,
`DDF_GIT_CHECKED=41`, `DDF_OPENED_AFTER_ADDED=0`, `DDF_LEGACY_LOCAL_STAMP=12`,
`DDF_CLOSED_BEFORE_OPENED=0`, `DDF_GIT_EVIDENCE=1`, `DDF_RECOUNT_EQ=1`, `DDF_FINDINGS=0`,
`DDF_FINDINGS_PRINTED=0`, `DDF_CLOSED_FIELD=3`, `DDF_BLIND=0`, `DDF_FAIL=0`, `DDF_EXIT=0`,
`DDF_CLOCK_FROZEN=0` (живое дерево судится по настоящим часам — шов только для PRE_FIX).
`DDF_UTC_TODAY`, `DDF_LOCAL_TODAY`, `DDF_DOMAIN_SPLIT` и точное значение `DDF_CLOSED_FIELD=3` —
счётчик полей, а не дата; сами даты в таблицу не входят. (6) Независимый пересчёт без прибора:
`SHELL_LOCAL_TODAY_LINES=0`, `SHELL_FUNNEL_LINES=11`, `SHELL_RECOUNT_EQ=1`, `CODE_CHANGED_RS=0`.
(7) Живой `library.py check` в двух поясах после починки: `LIBCHECK_UTC_EXIT=0`,
`LIBCHECK_UTC_ERRORS=0`, `LIBCHECK_HOST_EXIT=0`, `LIBCHECK_HOST_ERRORS=0`, `DOMAIN_MATCH=1` — оба
домена видят один и тот же зелёный индекс. (8) Запись дат на живом механизме в двух поясах (`UTC`,
`Australia/Sydney`), каждый раз на копии индекса через `VEC_DHT_LIBRARY`, цель `H-0128` (карточка
существует; посадка на ещё не заведенную карточку краснеет по проверке targets, а не по предмету):
по зонам `USE_OK_*=0`, `CLOSE_OK_*=0`, `USE_KEEPS_OPENED_*=1`, `USED_FIELD_*=1`,
`CLOSED_SHAPE_*=1`; сводные `WRITE_TZ_MATCH=1` (дата закрытия в UTC и в Сиднее одна),
`WRITE_KEEPS_OPENED=1`, `CLOSED_SHAPES_OK=1`. Само значение даты в таблице отсутствует — оно
меняется от часа снятия. (9) Гейт аудита на копии дерева: посадка красит
`AUDIT_PLANT_EXIT=1`, `AUDIT_PLANT_FAIL_LINES=1`, `AUDIT_PLANT_BAD_COUNT=1`, `AUDIT_GATE_FIRES=1`;
снятие зеленит `AUDIT_CLEAN_COPY_EXIT=0`; живое дерево `AUDIT_LIVE_EXIT=0`,
`AUDIT_LIVE_BAD_COUNT=0`. (10) Самопроверка прибора: `DDF_SELFTEST_EXIT=0`,
`DDF_SELFTEST_TOTAL=10`, `DDF_SELFTEST_PASSED=10`, `DDF_SELFTEST_PLANTS=9` и все девять
`PLANT_LOCAL_TODAY_FIRED`, `PLANT_NO_FUNNEL_FIRED`, `PLANT_USE_WRITES_OPENED_FIRED`,
`PLANT_CLOSE_NO_CLOSED_FIRED`, `PLANT_AUDIT_NO_GATE_FIRED`, `PLANT_DATE_AFTER_UTC_FIRED`,
`PLANT_CLOSED_BEFORE_OPENED_FIRED`, `PLANT_BLIND_INDEX_FIRED`, `PLANT_MISSING_FILE_FIRED` равны 1.
(11) Wiring и границы: `DDF_CI_STEPS=6` (страж и его самопроверка стоят в `verify.yml`),
`DDF_CONTOUR_BLOCK=2` (оба исполняются в `lab/workspace-verify.sh`),
`E0127_INSTRUMENT_UNTOUCHED=0`, `E0128_INSTRUMENT_UNTOUCHED=0`, `SPEC_V8_UNTOUCHED=0` — закрытые
приборы и спеки не переписаны (у классов разные правила, зелёный один не говорит ничего про другой).
(12) Всё измерение исполняется дважды внутри одного вызова helper'а на неизменном дереве, файлы
фактов совпадают построчно (`diff -q`) -> `STABLE=1`. Посадка неверного ожидания (`DDF_RECORDS` в
копию таблицы со значением 99) обязана покраснеть: `PLANT_EXPECT_RED=1`. Сверка
`lab/expectations/e0129.tsv` против двух файлов фактов: `ОЖИДАНИЙ=<EXPECT_ROWS> РАСХОЖДЕНИЙ=0`;
напечатанный `EXPECT_EXIT` в таблицу НЕ входит — он описывает саму сверку и был бы порогом,
невыполнимым по построению (урок `E-0128`, пункт 5), красноту держит `note`. (13) Полный контур
стражей, а не только названное в пороге: `lab/threshold-lint.py --latest` (СИРОТ=0),
`lab/repo-review.py check`, `bash lab/check-text-clean.sh`,
`python lab/check-ci-report-greps.py check`, `python lab/check-ci-rc-capture.py check`,
`python lab/check-claim-map.py`, `python lab/library.py check`,
`python lab/cycle-gate.py audit -n 5`, `python lab/check-date-domain.py check --require-git`,
разбор YAML `verify.yml`; вердикт — `VERIFY_FAIL=0`. Cargo-контур в этом цикле не вызывается
(`CODE_CHANGED_RS=0`), это lab-only прецедент `E-0127`/`E-0128`. Порог заморожен до официального
прогона `lab/e0129-run.sh`; изменение любого числа — новая карточка. Вне порога и записано честно:
зелёность или краснота `verify` на GitHub после пуша — факт ЧУЖОГО прогона, на хосте не наблюдаемый
(`L-0025`); часы хоста и часы раннера расходятся ровно в окне 21:00-24:00 по местному, и за окном
него наблюдение не воспроизводится; двенадцать записей, открытых до `DDF_CUTOVER`, остаются с
местной датой и переписаны не будут; тег и GitHub Release — красная зона владельца."
result: "Официальный прогон `lab/e0129-run.sh` на дереве `a831da2` (пин `336e7d5`), 2026-10-27T03:14
+03:00: `WORST_RC=0`, `STABLE=1`, `ОЖИДАНИЙ=94 РАСХОЖДЕНИЙ=0`, `PLANT_EXPECT_RED=1`, `EXPECT_ROWS=94`,
`EXPECT_EXIT=0`; цена одного вызова — 64 секунды. PRE_FIX на дереве пина: семь вызовов местной даты
(`PRE_FIX_DDF_LOCAL_TODAY_CALLS=7`), воронки нет (`PRE_FIX_DDF_FUNNEL_FILES=0`), `use` пишет `opened`
(`PRE_FIX_DDF_USE_WRITES_OPENED=1`), `close` без `closed` (`PRE_FIX_DDF_CLOSE_NO_CLOSED=1`), аудит без
гейта (`PRE_FIX_DDF_AUDIT_NO_GATE=1`), четыре поля дат позже дня пина
(`PRE_FIX_DDF_DATES_AFTER_UTC=4`, независимый пересчёт `PRE_FIX_PIN_FUTURE_DATES=4`,
`PRE_FIX_PIN_RECOUNT_EQ=1`), посадка красной карточки молчит (`PRE_FIX_AUDIT_PIN_SILENT=1` при
`PRE_FIX_AUDIT_PLANT_FAIL_LINES=1`), прибор красен (`PRE_FIX_DDF_EXIT=1`) и судит по замороженной дате
(`PRE_FIX_CLOCK_FROZEN_OK=1`). После починки: `DDF_LOCAL_TODAY_CALLS=0` при
`SHELL_LOCAL_TODAY_LINES=0` и `DDF_RECOUNT_EQ=1`, `DDF_FUNNEL_FILES=2`, `DDF_USE_WRITES_OPENED=0`,
`DDF_CLOSE_NO_CLOSED=0`, `DDF_AUDIT_NO_GATE=0`, `DDF_RECORDS=41`, `DDF_DATE_FIELDS=85`,
`DDF_DATES_AFTER_UTC=0`, `DDF_GIT_CHECKED=41`, `DDF_OPENED_AFTER_ADDED=0`,
`DDF_LEGACY_LOCAL_STAMP=12`, `DDF_CLOSED_BEFORE_OPENED=0`, `DDF_FINDINGS=0`, `DDF_BLIND=0`,
`DDF_EXIT=0`. `library.py check` даёт ноль ошибок в обоих доменах (`LIBCHECK_UTC_ERRORS=0`,
`LIBCHECK_HOST_ERRORS=0`, `DOMAIN_MATCH=1`); запись исполнена в двух часовых поясах, `opened` уцелел,
`used` и `closed` появились, дата одна на всех (`USE_KEEPS_OPENED_UTC=1`,
`USE_KEEPS_OPENED_AustraliaSydney=1`, `USED_FIELD_UTC=1`, `WRITE_TZ_MATCH=1`, `CLOSED_SHAPES_OK=1`);
гейт аудита красен на посадке и даёт ноль на чистой копии и на живом дереве (`AUDIT_GATE_FIRES=1`,
`AUDIT_PLANT_BAD_COUNT=1`, `AUDIT_CLEAN_COPY_EXIT=0`, `AUDIT_LIVE_EXIT=0`, `AUDIT_LIVE_BAD_COUNT=0`);
самопроверка 10 проверок из 10, девять посаженных дефектов отбиты все
(`DDF_SELFTEST_PLANTS=9`); прибор стоит в CI (`DDF_CI_STEPS=6`) и в контуре (`DDF_CONTOUR_BLOCK=2`);
продукт и спека не тронуты (`CODE_CHANGED_RS=0`, `SPEC_V8_UNTOUCHED=0`), закрытые приборы не
переписаны (`E0127_INSTRUMENT_UNTOUCHED=0`, `E0128_INSTRUMENT_UNTOUCHED=0`). Часы съёма вынесены в
носитель и не входят в порог: между подготовительными прогонами день по UTC перешёл на `2026-10-27`,
и наблюдение «пин под `TZ=UTC` красен» (строки 15…17 лога: `PRE_FIX_LIBCHECK_UTC_EXIT=1`,
`errors=1`, при `расхождение_доменов=1`) на том же дереве пина стало зелёным — замороженное ожидание
из него получилось бы часами, а не правилом."
verdict: supports
---

# E-0129 — домен дат контура источников: семь местных дат, стёртое `opened` и вердикт без гейта

## Что измеряется

1. **Домен даты в механизме.** `lab/check-date-domain.py` считает вызовы `date.today()` в двух файлах,
   которые дату штампуют (`lab/library.py`, `lab/sources.py`), требует в каждом из них воронку
   `utc_today()`, и судит все даты индекса по UTC-дню снятия. Число вызовов имеет независимый пересчёт
   построчным grep'ом (`SHELL_LOCAL_TODAY_LINES`), потому что «ноль находок» ослепшего прибора
   неотличим от «ноль находок» здорового.
2. **Стирание доказательства.** `cmd_use` писал `opened` поверх даты пре-регистрации. Проверяется
   исполнением в двух часовых поясах на копии индекса: `opened` обязан остаться прежним, `used` —
   появиться, `closed` — иметь форму YYYY-MM-DD и совпадать в UTC и в Сиднее.
3. **Вердикт без гейта.** `cmd_close` не ставил `closed`, а `cmd_audit` печатал
   `CYCLE …=FAIL нарушений=N` и возвращал ноль. Проверяется посадкой в копию дерева: с карточкой,
   нарушающей гейт, аудит обязан вернуть 1; без неё — 0; живое дерево обязано быть зелёным.

## Почему отдельный цикл, а не доделка `E-0127`/`E-0128`

Те два цикла чинили способ, каким шаг сообщает код возврата, и после них краснота `verify` обязана была
стать содержательной. Она стала: красным оказался шаг `library check` с `errors=1` на раннере и `errors=0`
на хосте при одних и тех же байтах индекса. Причина не в трубе и не в `$?`, а в календарном дне
процесса, и измеряется она другим прибором по другим правилам. Факт закреплен числами: закрытые приборы
этим циклом не переписаны (`E0127_INSTRUMENT_UNTOUCHED=0`, `E0128_INSTRUMENT_UNTOUCHED=0`).

## Ход цикла

Коммиты: пре-регистрация (прибор `lab/check-date-domain.py`, helper `lab/e0129-run.sh`, карточки,
`ADR-0070` `proposed`, записи `L-0040`/`L-0041`, `OPEN-QUESTIONS` п. 70, строка в `docs/PLAN-v1.md`) →
пре-регистрация таблицы `lab/expectations/e0129.tsv` → фикс (воронка `utc_today()` в двух файлах,
`use` больше не трогает `opened` и ставит `used`, `close` ставит `closed`, `audit` возвращает
`1 if bad_cards else 0`, даты трёх записей переведены в UTC, два шага в `verify.yml`, блок в
`lab/workspace-verify.sh`) → официальный прогон → закрытие.

## Что найдено и снято до заморозки

* **Правило, требующее переписать прошлое.** В подготовительном прогоне `check_row` красил шесть
  исторических записей за «сверку раньше находки»: те действительно читали источник до того, как для
  него завели строку. Правило удалено, порядок «найдено раньше, чем добавлено в индекс» остался за
  прибором и только для строк от `DDF_CUTOVER` и далее, с git-доказательством. ДИАГНОЗ зафиксирован
  комментарием в коде: правило, которое зеленеет лишь после правки истории, — это часы, а не правило.
* **Краснота, зависящая от часа съёма.** PRE_FIX пина задумывался судящим по живым часам и был красен
  только до полуночи UTC; после полуночи он дал бы `DATES_AFTER_UTC=0` — зелёный PRE_FIX на красном
  дереве. Снято замороженными часами прибора (`VEC_DHT_DDF_TODAY`, шов только у измерителя) и
  инвариантным независимым пересчётом `PRE_FIX_PIN_FUTURE_DATES`; краснота `library.py` пина из
  таблицы вынесена в носитель.
* **Полуночь случилась во время написания карточки.** Между подготовительным прогоном и пре-регистрацией
  день по UTC перешёл на `2026-10-27`, и живой прибор на хосте перестал видеть расхождение доменов
  (`DDF_DOMAIN_SPLIT=0` вместо `1`): то, что цикл утверждает, было видно за сутки до замера и перестало
  быть видно само — ровно тот класс фактов, который нельзя класть в замороженное ожидание. Пины PRE_FIX
  этим не задеты, потому что судят по замороженной дате пина. Заодно перешедшая полночь показала,
  какие две строки индекса правило красит по-настоящему: `L-0038` и `L-0039` открыты местным днём
  `2026-10-27` при git-дне добавления `2026-10-26`, то есть позже перехода и значит вне права на
  легаси-метку.
* **Исключение из «прошлое не переписывается».** Три метки приведены к дню, который доказывает git
  (`L-0038`/`L-0039`: сутки расхождения, первый коммит не раньше перехода; `L-0025`: трое суток, чего
  местный домен дать не мог, зато мог `cmd_use`, стёрший `opened`). Правка лежит в коммите
  пре-регистрации и названа в пункте 5 `ADR-0070`; двенадцать меток, открытых до перехода, не тронуты и
  по-прежнему считаются числом `DDF_LEGACY_LOCAL_STAMP=12`.
* **Посадка на несуществующую карточку.** `use L-0001 --target H-0129` на этапе подготовки падал по
  проверке targets, то есть краснел не по предмету цикла; цель переведена на `H-0128`.
* **Область правила о воронке.** Первый живой запуск требовал `utc_today` и от `lab/cycle-gate.py`,
  который дат не штампует, — находка без дефекта. Область правил 1 и 2 сужена до `DATE_FILES`
  (`DDF_DATE_FILES=2`).

## Результат

Вердикт — `supports`. Утверждение цикла исполнено, а не прочитано: на дереве пина (`336e7d5`) прибор
находит семь вызовов местной даты в двух штампующих файлах, отсутствие воронки, стирание `opened` при
`use`, отсутствие `closed` при `close`, молчание аудита при напечатанном `FAIL` и четыре поля дат позже
дня пина; на дереве фикса (`a831da2`) все те же сенсоры дают ноль, а независимый построчный пересчёт
совпадает с прибором (`DDF_RECOUNT_EQ=1`, `SHELL_LOCAL_TODAY_LINES=0`). Официальный прогон:
`WORST_RC=0`, `ОЖИДАНИЙ=94 РАСХОЖДЕНИЙ=0`, `STABLE=1`, `PLANT_EXPECT_RED=1`, цена — 64 секунды.

Что изменено в механизме: единственная дата контура — UTC через воронку `utc_today()` в `lab/library.py`
и `lab/sources.py`; `use` пишет `used` и не трогает доказательство пре-регистрации `opened`; `close`
пишет `closed`; `cmd_audit` возвращает `1 if bad_cards else 0`. Страж `lab/check-date-domain.py` стоит
двумя шагами в `verify.yml` (`DDF_CI_STEPS=6` вхождений) и блоком в `lab/workspace-verify.sh`
(`DDF_CONTOUR_BLOCK=2`); его самопроверка — 10 проверок из 10, девять посаженных дефектов отбиты.

Чего цикл не утверждал: что весь `verify` на GitHub зелёный — это факт чужого прогона (`L-0025`), он
перечитывается отдельно, и в носитель записан разбор прогона 40416488581, где красным остался шаг
`library check` именно по домену дат. Продукт и спека не тронуты (`CODE_CHANGED_RS=0`,
`SPEC_V8_UNTOUCHED=0`); закрытые приборы `E-0127`/`E-0128` не переписаны. Двенадцать исторических меток
остались с местным днём и названы числом `DDF_LEGACY_LOCAL_STAMP=12`; три метки (`L-0025`, `L-0038`,
`L-0039`) приведены к git-дню и названы в `ADR-0070` исключением, а не молчаливой правкой.

Самопойманный урок цикла: наблюдение «расхождение доменов» (`DDF_DOMAIN_SPLIT`) было красным за сутки
до замера и зелёным в момент замера, потому что полуночь UTC случилась между прогонами. Число,
зависящее от часа съёма, не может быть замороженным ожиданием — оно живёт в носителе.
