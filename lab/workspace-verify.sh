#!/usr/bin/env bash
# Верификация воркспейса для цикла: $1 = метка блока (например E-0061).
# Append-блок в lab/logs/workspace-verify-2026-10-22.log: cargo test --workspace + clippy -D warnings
# с настоящими exit-кодами. Helper исполняет команду целиком (урок e0049).
#
# Два дефекта, найденные ревью 2026-10-24 и закрытые здесь:
#  (1) `LIBDIGEST_EXIT=$?` после конвейера читал код `grep`, а не `python`: сводка могла упасть,
#      а закрытие видело 0. Теперь код берётся из `PIPESTATUS[0]`.
#  (2) Скрипт кончался без `exit`: при `TEST_EXIT=101` блок `E-0100` получил `EXIT=0`, то есть
#      helper'у и `WORST_RC` сообщалось «всё хорошо». Теперь любой ненулевой этап делает выход 1.
# Плюс `--no-fail-fast` (ДИАГНОЗ-2 `E-0087`): первый упавший target не должен скрывать остальные,
# иначе полный список поломок стоит второго двадцатиминутного прогона.
# Плюс секунды по этапам и `lab/disk-report.sh` в шапке: цена цикла и давление на носитель видны.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/c/Users/Admin/mingw64/bin:$PATH"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
LABEL="${1:?метка блока, например E-0061}"
LOG="lab/logs/workspace-verify-2026-10-22.log"
FAIL=0
note() { [ "${1:-1}" -ne 0 ] && FAIL=1; return 0; }
now() { date +%s; }
T0=$(now); BLOCK_T0=$T0
{
  echo "########## $LABEL · workspace-verify · $(date +%FT%T%:z) ##########"
  echo "### носитель до сборки ###"
  bash lab/disk-report.sh 2>&1
  echo "### cargo test --workspace ### $(date +%FT%T%:z)"
  cargo test -j 2 --workspace --no-fail-fast 2>&1
  rc=$?; echo "TEST_EXIT=$rc"; note $rc
  echo "SECONDS_test=$(( $(now) - T0 ))"; T0=$(now)
  echo "### clippy ### $(date +%FT%T%:z)"
  cargo clippy -j 2 --workspace --all-targets -- -D warnings 2>&1
  rc=$?; echo "CLIPPY_EXIT=$rc"; note $rc
  echo "SECONDS_clippy=$(( $(now) - T0 ))"; T0=$(now)
  # Формальные модели проверяются тем же закрытием цикла: без этой строки `lab/lean/` мог
  # сгнить незаметно — у helper'ов `e0078`/`e0079` они исполнялись один раз, в своём цикле.
  echo "### lean-check ### $(date +%FT%T%:z)"
  bash lab/lean-check.sh --quiet 2>&1
  rc=$?; echo "LEAN_EXIT=$rc"; note $rc
  echo "SECONDS_lean=$(( $(now) - T0 ))"; T0=$(now)
  # Страж моделей обязан самопроверяться тем же закрытием цикла, что и код: прибор, который
  # никто не гоняет с посаженными дефектами, через пять циклов превращается в зелёный текст.
  # Цена измерена в `E-0093`: 137,7…137,8 с (`SELFTEST_MS`), то есть девять тёплых прогонов
  # самих моделей — это самое дорогое, что есть в верификации после cargo. Оно оплачено тем,
  # что без посадок гейт «модели годны» не отличим от гейта «прибор молчит».
  echo "### lean-check selftest ### $(date +%FT%T%:z)"
  python lab/lean-check.py selftest 2>&1 | tail -14
  rc=${PIPESTATUS[0]}; echo "LEANGUARD_SELFTEST_EXIT=$rc"; note $rc
  echo "SECONDS_lean_selftest=$(( $(now) - T0 ))"; T0=$(now)
  # Контуры №2 и №3 формальной проверки (после Lean) входят в то же закрытие цикла, что и cargo:
  # прибор, который не гоняется на каждом цикле, через пять циклов становится зелёным текстом —
  # это ровно та причина, по которой `H-0093` посадил самопроверку в Lean-страж.
  # REQUIRED=1 здесь не случайность: без него отсутствующий бинарь Verus печатал бы SKIP, и
  # закрытие цикла молча перестало бы доказывать что-либо про арифметику приёма (`ADR-0053`).
  echo "### verus-check (required) ### $(date +%FT%T%:z)"
  VEC_DHT_VERUS_REQUIRED=1 bash lab/verus-check.sh --quiet 2>&1 | tail -8
  rc=${PIPESTATUS[0]}; echo "VERUS_EXIT=$rc"; note $rc
  echo "### verus-check selftest ### $(date +%FT%T%:z)"
  bash lab/verus-check.sh selftest 2>&1 | tail -8
  rc=${PIPESTATUS[0]}; echo "VERUS_SELFTEST_EXIT=$rc"; note $rc
  # Харнеси Kani под `#[cfg(kani)]` обычная сборка не видит вовсе, а Kani на Windows не
  # устанавливается. Локально проверяется хотя бы то, что они компилируются: иначе CI краснеет
  # через час на опечатке в типе. Сами утверждения проверяет Kani, и только в CI.
  echo "### kani-compile-check ### $(date +%FT%T%:z)"
  bash lab/kani-compile-check.sh 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "KCC_EXIT=$rc"; note $rc
  # Гейт круга (боль -> источники -> рубрика Lean -> оракул) и индекс источников проверяются
  # вместе с кодом: механизм, который никто не гоняет, через пять циклов превращается в текст.
  echo "### cycle-gate selftest ### $(date +%FT%T%:z)"
  python lab/cycle-gate.py selftest 2>&1
  rc=$?; echo "CYCLEGATE_EXIT=$rc"; note $rc
  # Приборы разбора фактов и порогов проверяются посаженными случаями на каждом закрытии: именно
  # они решают, будет ли вердикт прочитан правильно (`E-0084` — знак, `E-0088`/`E-0100` — метка
  # прогона, `E-0087` — хвост лога).
  echo "### instruments selftest ### $(date +%FT%T%:z)"
  python lab/expect.py --selftest 2>&1; rc=$?; echo "EXPECT_SELFTEST_EXIT=$rc"; note $rc
  python lab/facts.py selftest 2>&1; rc=$?; echo "FACTS_SELFTEST_EXIT=$rc"; note $rc
  python lab/threshold-lint.py --selftest 2>&1 | tail -3
  rc=${PIPESTATUS[0]}; echo "LINT_SELFTEST_EXIT=$rc"; note $rc
  bash lab/runlib.sh --selftest 2>&1 | tail -3
  rc=${PIPESTATUS[0]}; echo "RUNLIB_SELFTEST_EXIT=$rc"; note $rc
  # Баланс цикла (`lab/ledger.py`, слово владельца 2026-10-25: разработка = сохранение ресурса в
  # зоне ответственности): прибор обязан самопроверяться посаженными случаями, иначе он через пять
  # циклов становится зелёным текстом. Цена вопроса измерена в `E-0105`: сорванный блок верификации
  # стоил 415 с и 114 оборванных процессов, и ни один прибор этого расхода не показывал.
  echo "### ledger selftest ### $(date +%FT%T%:z)"
  python lab/ledger.py selftest 2>&1 | tail -3
  rc=${PIPESTATUS[0]}; echo "LEDGER_SELFTEST_EXIT=$rc"; note $rc
  # Самопроверка репозитория (слово владельца 2026-10-24): после каждого цикла — обход всего дерева
  # на классы слабостей, которые уже случались, и числа в лог. Находки не валят сборку (это
  # инвентарь, а не вердикт), но цикл обязан на них ответить до закрытия (`lab/PLAN.md` п. 8и).
  echo "### repo-review selftest ### $(date +%FT%T%:z)"
  python lab/repo-review.py selftest 2>&1 | tail -9
  rc=${PIPESTATUS[0]}; echo "REVIEW_SELFTEST_EXIT=$rc"; note $rc
  echo "### repo-review check ### $(date +%FT%T%:z)"
  python lab/repo-review.py check 2>&1
  rc=$?; echo "REVIEW_EXIT=$rc"; note $rc
  # Пороги самого свежего цикла: ключ, которого никто не печатает, — обещание, а не порог.
  python lab/threshold-lint.py --latest 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "LINT_LATEST_EXIT=$rc"; note $rc
  echo "SECONDS_formal_and_gates=$(( $(now) - T0 ))"; T0=$(now)
  echo "### library check+digest ### $(date +%FT%T%:z)"
  python lab/library.py check 2>&1
  rc=$?; echo "LIBCHECK_EXIT=$rc"; note $rc
  python lab/library.py digest 2>&1 | grep -E "^(LIBDIGEST|LIBCLASSES|КЛАССЫ|ДАЙДЖЕСТ)|ВНИМАНИЕ"
  rc=${PIPESTATUS[0]}; echo "LIBDIGEST_EXIT=$rc"; note $rc
  # Страж текста гоняется по ВСЕМУ дереву, а не по списку вызывающего: 2026-10-25 перебор нашёл
  # 23 слово-гибрида в 14 карточках `lab/`, и ни один прогон их не видел, потому что каждый раз
  # передавались только тронутые файлы. Цена — секунды, выгода — дефект алфавита не уезжает в main.
  # Карта «слово → id» §18.9 (условие 4 v1, `E-0123`): краснеет на клаузу без id, имени прибора
  # или пометки «не реализовано в v1» — и на ссылку, под которой нет карточки или файла теста.
  # Строка здесь затем, чтобы новый страж не сгнил за цикл: сам по себе он никому не нужен.
  echo "### claim map guard (18.9) ### $(date +%FT%T%:z)"
  python lab/check-claim-map.py --selftest 2>&1 | tail -2
  rc=${PIPESTATUS[0]}; echo "CLAIMMAP_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-claim-map.py 2>&1 | tail -1
  rc=${PIPESTATUS[0]}; echo "CLAIMMAP_EXIT=$rc"; note $rc
  # Реестр утверждений готовности (`H-0132`): строка `lab/claims.tsv` и её носитель сверяются вместе.
  # Тип свидетельства задаёт потолок слов, у названного гейта обязан быть свой носитель в той же
  # строке, а цифра готовности — одного владельца на все носители. Страж краснеет на тексте, выросшем
  # сверх строк: правка статус-документа без правки реестра перестаёт быть незаметной.
  echo "### claims registry guard ### $(date +%FT%T%:z)"
  python lab/check-claims.py --selftest 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "CLAIMS_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-claims.py 2>&1 | tail -12
  rc=${PIPESTATUS[0]}; echo "CLAIMS_EXIT=$rc"; note $rc
  # Сведение двух множеств: у карточки, закрытой вердиктом, обязан найтись блок прогона контура с
  # её меткой — или исключение с классом и напечатанной причиной (`H-0138`, `OPEN-QUESTIONS` п. 76).
  # Пять кругов жили без контура именно потому, что «вердикт» был словом, а не исполнением.
  echo "### contour coverage guard ### $(date +%FT%T%:z)"
  python lab/check-contours.py --selftest 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "CONTOURS_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-contours.py 2>&1 | tail -16
  rc=${PIPESTATUS[0]}; echo "CONTOURS_EXIT=$rc"; note $rc
  # Релиз-карта читается посторонним, чтобы решить, можно ли ставить тег. Её собственное обещание —
  # «строка называет прибор или id замера» — до `H-0148` было прозой: строка P3 противоречила своему
  # носителю (`E-0100` мерил 1M, а карта утверждала «фикстуру»). Страж связывает шестнадцать строк с
  # закрытыми карточками, ADR и файлами приборов и сверяет числа строки P3 с цитатным логом.
  echo "### release map guard ### $(date +%FT%T%:z)"
  python lab/check-release-map.py selftest 2>&1 | tail -3
  rc=${PIPESTATUS[0]}; echo "RELEASEMAP_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-release-map.py 2>&1 | tail -28
  rc=${PIPESTATUS[0]}; echo "RELEASEMAP_EXIT=$rc"; note $rc
  # Отчётные трубы workflow'ов проверяются здесь же, где и всё остальное: шаг, который краснеет от
  # собственного grep'а раньше вердикта, — это красный CI при зелёном продукте (`E-0127`). Прибор
  # обязан самопроверяться посаженными формами: гейт, который никто не гоняет с дефектом, через
  # пять циклов превращается в зелёный текст (тот же довод, что посадил самопроверку в `lean-check.py`).
  echo "### ci report-grep guard ### $(date +%FT%T%:z)"
  python lab/check-ci-report-greps.py selftest 2>&1 | tail -8
  rc=${PIPESTATUS[0]}; echo "CRG_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-ci-report-greps.py check 2>&1 | tail -4
  rc=${PIPESTATUS[0]}; echo "CRG_EXIT=$rc"; note $rc
  # Второй класс той же поломки (`E-0128`): `команда; r=$?` под `bash -e` обрывает шаг на
  # команде, не доходя до захвата. Здесь скрипт без `-e`, поэтому код берётся из PIPESTATUS,
  # а прибор смотрит на workflow-файлы, где `-e` стоит по умолчанию (его ставит GitHub).
  echo "### ci rc-capture guard ### $(date +%FT%T%:z)"
  python lab/check-ci-rc-capture.py selftest 2>&1 | tail -13
  rc=${PIPESTATUS[0]}; echo "RCC_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-ci-rc-capture.py check --limit 30 2>&1 | tail -4
  rc=${PIPESTATUS[0]}; echo "RCC_EXIT=$rc"; note $rc
  # Четвёртый класс расхождения слова и дерева (`E-0154`): шапка `verify.yml` обещала 764 теста, пока
  # внешний рецензент пересчитал дерево и получил 804. Число с командами в комментарии всё равно не
  # исполняется, а значит остаётся формой записи, а не механизмом. Прибор читает определения шапки и
  # пересчитывает их по дереву; самопроверка сажаем семью формами, включая «команду я не знаю»
  # и поддельные метки внутри `target/`.
  echo "### ci header-numbers guard ### $(date +%FT%T%:z)"
  python lab/check-ci-numbers.py --selftest 2>&1 | tail -10
  rc=${PIPESTATUS[0]}; echo "CIN_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-ci-numbers.py 2>&1 | tail -30
  rc=${PIPESTATUS[0]}; echo "CIN_EXIT=$rc"; note $rc
  # Третий класс красноты `verify` (`E-0129`): даты контура ставились местным часом хоста (UTC+3),
  # а runner судит по UTC, за записью, закрытой после 21:00 по хосту. Здесь добавлен `--require-git`:
  # на хосте полная история есть, и проверка «источник не мог быть найден раньше, чем его добавили в
  # индекс» исполнима; в CI тот же флаг дал бы ложную красноту на shallow-клоне (см. шаг в verify.yml).
  echo "### date-domain guard ### $(date +%FT%T%:z)"
  python lab/check-date-domain.py selftest 2>&1 | tail -12
  rc=${PIPESTATUS[0]}; echo "DDF_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-date-domain.py check --require-git 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "DDF_EXIT=$rc"; note $rc
  # Нумерация очереди: прибор заведён `E-0137`, вторую форму (жирная строка-заявка `**N. …`) он не
  # видел, и ни в том, ни в другом цикле в контуре не стоял — «прибор есть» отличается от «прибор
  # исполняется» только этой строкой (`E-0133`). Краснеет на неканоническом заголовке, на метке,
  # занятой в двух доменах, и на внешнем указателе `п. N`, под которым нет ни заголовка, ни заявки.
  echo "### oq numbering guard ### $(date +%FT%T%:z)"
  python lab/check-oq-numbering.py --selftest 2>&1 | tail -14
  rc=${PIPESTATUS[0]}; echo "OQNUM_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-oq-numbering.py 2>&1 | tail -8
  rc=${PIPESTATUS[0]}; echo "OQNUM_EXIT=$rc"; note $rc
  python lab/check-oq-numbering.py --pointers 2>&1 | tail -4
  rc=${PIPESTATUS[0]}; echo "OQPTR_EXIT=$rc"; note $rc
  # Боевой режим, а не только посадка (`H-0152`). `H-0151` доказал, что посадка есть у каждого
  # стража и что её зовёт контур; он не спросил, зовёт ли контур сам прибор. На `18a3a70` шесть
  # приборов стояли боевым шагом только в одном из двух контуров, и 2026-10-29 это стоило находки:
  # несуществующую цитату в носителе `E-0151` поймал ручной запуск стража цитат, потому что на
  # хосте он стоял только посадкой. Здесь — ровно те вызовы, которых не хватало хосту; паритет
  # затем проверяет `check-contour-parity.py` против реестра `lab/contour-parity.tsv`.
  echo "### battle runs, host contour ### $(date +%FT%T%:z)"
  python lab/check-artifact-refs.py 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "REFS_EXIT=$rc"; note $rc
  python lab/check-status-claims.py 2>&1 | tail -3
  rc=${PIPESTATUS[0]}; echo "STATUS_EXIT=$rc"; note $rc
  # История обязательна: именно в ней лежат токены из старых коммитов, а `--no-history` в CI — это
  # сокращение раннера, а не норма. Хост платит секундами и получает полный обход.
  bash lab/check-secrets.sh 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "SECRETS_EXIT=$rc"; note $rc
  # Зеркало живёт вне git: если каталога нет, контур обязан назвать это, а не промолчать и не
  # покраснеть от собственного отсутствия. Если каталог есть, расхождение — настоящий провал.
  if [ -d "${SPEC_MIRROR_DIR:-$HOME/OneDrive/Desktop}" ]; then
    bash lab/check-spec-mirror.sh 2>&1 | tail -6
    rc=${PIPESTATUS[0]}; echo "MIRROR_EXIT=$rc"; note $rc
  else
    echo "MIRROR_ABSENT_ON_HOST=1 — зеркало вне git и каталога нет; проверка остаётся обязанностью места с зеркалом"
    echo "MIRROR_EXIT=0"; note 0
  fi
  # Паритет самопроверяется посадками так же, как остальные стражи (`H-0151`): три посаженные
  # ошибки — снятый боевой вызов, пустая причина, чужая строка реестра.
  python lab/check-contour-parity.py --selftest 2>&1 | tail -5
  rc=${PIPESTATUS[0]}; echo "PARITY_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-contour-parity.py 2>&1 | tail -10
  rc=${PIPESTATUS[0]}; echo "PARITY_EXIT=$rc"; note $rc
  # Посадка обязана быть у КАЖДОГО стража `lab/check-*`, а не только у тех, кто вспомнил
  # завести `selftest` (`H-0151`): зелёный страж без посадки неотличим от выключенного.
  # Мета-страж считает список по каталогу, поэтому прибор, заведённый завтра, попадает в счёт
  # без правки. Цена — секунды: каждая посадка строит свой temp-корень, а не копию дерева.
  echo "### guard selftests ### $(date +%FT%T%:z)"
  bash lab/check-release-kit.sh --selftest 2>&1 | tail -4
  rc=${PIPESTATUS[0]}; echo "KIT_SELFTEST_EXIT=$rc"; note $rc
  bash lab/check-spec-mirror.sh --selftest 2>&1 | tail -5
  rc=${PIPESTATUS[0]}; echo "MIRROR_SELFTEST_EXIT=$rc"; note $rc
  bash lab/check-text-clean.sh --selftest 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "TEXTCLEAN_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-artifact-refs.py --selftest 2>&1 | tail -4
  rc=${PIPESTATUS[0]}; echo "REFS_SELFTEST_EXIT=$rc"; note $rc
  bash lab/check-secrets.sh --selftest 2>&1 | tail -3
  rc=${PIPESTATUS[0]}; echo "SECRETS_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-guard-selftests.py --selftest 2>&1 | tail -5
  rc=${PIPESTATUS[0]}; echo "GSE_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-guard-selftests.py 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "GSE_EXIT=$rc"; note $rc
  # Заморозка таблиц ожиданий (`H-0155`): подменённое ожидание обязано краснить страж, а не
  # молчать; исторические 19 названы базовой линией с коммитом и причиной (OQ п. 93).
  python lab/check-expect-freeze.py --selftest 2>&1 | tail -8
  rc=${PIPESTATUS[0]}; echo "EXPFREEZE_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-expect-freeze.py 2>&1 | tail -14
  rc=${PIPESTATUS[0]}; echo "EXPFREEZE_EXIT=$rc"; note $rc
  # Сравнение двух фактов, каждый из которых может быть `none` (`H-0156`): два молчания не
  # считаются равенством; исторический сайт e0146:80 назван реестром.
  python lab/check-none-compare.py --selftest 2>&1 | tail -8
  rc=${PIPESTATUS[0]}; echo "NONECMP_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-none-compare.py 2>&1 | tail -12
  rc=${PIPESTATUS[0]}; echo "NONECMP_EXIT=$rc"; note $rc
  echo "### text guard (--all) ### $(date +%FT%T%:z)"
  bash lab/check-text-clean.sh --all 2>&1 | grep -v "^ПОДОЗРЕНИЕ"
  rc=${PIPESTATUS[0]}; echo "TEXTGUARD_EXIT=$rc"; note $rc
  echo "### носитель после сборки ###"
  bash lab/disk-report.sh 2>&1
  echo "SECONDS_total=$(( $(now) - BLOCK_T0 )) "
  echo "VERIFY_FAIL=$FAIL"
} >> "$LOG" 2>&1
exit "$FAIL"
