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
  # Третий класс красноты `verify` (`E-0129`): даты контура ставились местным часом хоста (UTC+3),
  # а runner судит по UTC, за записью, закрытой после 21:00 по хосту. Здесь добавлен `--require-git`:
  # на хосте полная история есть, и проверка «источник не мог быть найден раньше, чем его добавили в
  # индекс» исполнима; в CI тот же флаг дал бы ложную красноту на shallow-клоне (см. шаг в verify.yml).
  echo "### date-domain guard ### $(date +%FT%T%:z)"
  python lab/check-date-domain.py selftest 2>&1 | tail -12
  rc=${PIPESTATUS[0]}; echo "DDF_SELFTEST_EXIT=$rc"; note $rc
  python lab/check-date-domain.py check --require-git 2>&1 | tail -6
  rc=${PIPESTATUS[0]}; echo "DDF_EXIT=$rc"; note $rc
  echo "### text guard (--all) ### $(date +%FT%T%:z)"
  bash lab/check-text-clean.sh --all 2>&1 | grep -v "^ПОДОЗРЕНИЕ"
  rc=${PIPESTATUS[0]}; echo "TEXTGUARD_EXIT=$rc"; note $rc
  echo "### носитель после сборки ###"
  bash lab/disk-report.sh 2>&1
  echo "SECONDS_total=$(( $(now) - BLOCK_T0 )) "
  echo "VERIFY_FAIL=$FAIL"
} >> "$LOG" 2>&1
exit "$FAIL"
