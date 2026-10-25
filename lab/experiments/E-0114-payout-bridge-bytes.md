---
id: E-0114
hypothesis: H-0114
status: closed
base_commit: "25556ae — голова очереди `H-0114` по `lab/decisions/OPEN-QUESTIONS.md` п. 60. На этом
дереве ещё нет ни носителя слоя, ни прибора, ни генератора: они лежат в рабочем дереве (файлы
`docs/PAID_PAYOUT-VECTORS.md`, `crates/vecdht-orders/tests/payout_claim_vectors.rs`,
`lab/v9-payout-bridge.py`, `lab/v9-payout-plant-decoy.py`, `lab/e0114-run.sh`,
`lab/expectations/e0114.tsv` и 900 строк слоя в `crates/vecdht-orders/src/lib.rs`), и этот коммит
пре-регистрации их закрепляет.PRE_FIX-контроль снят не на «прежнем тексте», а исполнением: носитель
в копии с прежней формулой `term_hash` (посадка `lab/v9-payout-plant-decoy.py`, 36 байт
расхождения в хвосте формулы, первое расхождение — смещение 3 534) краснеет на том же дереве
(`lab/logs/e0114-prefix.log`, 424 строки, три блока): выход 1, `V9CTL_TERM_EQ_GOT=0`,
`V9CTL_TERM_EQ=0`, `V9CTL_MIRROR_MATCH=4/31`, `V9CTL_MIRROR_EQ=0`, `V9CTL_INDEP_MATCH=0`,
`V9CTL_DECOY_STATUS=0`, `V9CTL_DECOY_AMOUNT=0`, `V9CTL_DECOY_WITNESS_SIG=0`,
`V9CTL_DECOY_STATUS_SIGNED=0`, `V9CTL_CODES_USED_MINE=4`, `V9CTL_ALL_OK=0`,
`V9CTL_CARRIER_SHA=ce81bb21…9faa` (280 493 байт против 280 457). Зелёное на той же копии
ограничивает область дефекта: `V9CTL_RECORD_EQ=1`, `V9CTL_BINDING_EQ=1`, `V9CTL_WITNESS_EQ=1`,
`V9CTL_SIGNATURES_VALID=1`, `V9CTL_KEYPAIR_MATCH=beneficiary=31/31|observer=30/31|publisher=31/31|
verifier=30/31`, `V9CTL_REGISTRY_ROOT=382bdb9d…eeaf` — расходится именно напечатанная формула
связки «заказ ⇄ деньги», а не носитель целиком. Второй блок того же снимка — прибор на носителе как
есть: `E0114_BRIDGE_EXIT=0`, 112 фактов, `V9C_TERM_EQ_GOT=31`, `V9C_MIRROR_MATCH=31/31`,
`V9C_ALL_OK=1`, `V9C_WORST=0`. Третий блок — генератор в temp: `V9P_GEN_EXIT=0`,
`V9P_FORMULA_EQ=31`, `V9P_ORDER_REF_UNCHANGED=1`, `V9P_DOC_SHA` = sha закоммиченного файла,
`V9C_CARRIER_REPRODUCED=1`."
started: "2026-10-25"
finished: "2026-10-25"
environment: "Windows, x8_64-pc-windows-gnu; rustc 1.99.1 (58cf8f9c3 2026-10-13); PATH обязан включать
/c/Users/Admin/mingw64/bin (miniconda-MinGW рвёт линковку на `GetHostNameW`), и это касается тоже
ad-hoc `cargo`-команд вне helper'а. CPython 3.13.11 с `unicodedata` 15.1.0 — версия входит в
печатные факты (`V9C_TOOLCHAIN`, `V9C_UNICODE_DATA`), потому что без неё «подпись проверена» было бы
утверждением без носителя. Сети, стенды и секреты не участвуют: у прибора нет ни ключей, ни доступа к
чужим узлам, он читает четыре текста и считает хеши; `crates/` он не открывает"
command: "bash lab/e0114-run.sh: (0) `python lab/cycle-gate.py gate H-0114` ДО прогона и носитель
(`lab/disk-report.sh`), (1) два прогона `V9C_VERBOSE=1 python lab/v9-payout-bridge.py
docs/PAID_PAYOUT-VECTORS.md docs/VecDHT-SPEC-v9.md docs/PAID_ORDER-VECTORS.md
lab/notes/DESIGN-2026-10-25-chain-binding.md` на неизменном дереве с литеральной печатью всех 112
ключей `V9C_*`, (2) `V9P_VECTORS_OUT=<temp> cargo test -q -p vecdht-orders --test
payout_claim_vectors -- --nocapture` — генератор носителя в temp (в `docs/` не пишет) и побайтная
сверка с закоммиченным носителем, плюс пины `PREV_*_SHA` против sha файла на дереве прогона,
(3) контроль посадки: `python lab/v9-payout-plant-decoy.py docs/PAID_PAYOUT-VECTORS.md` и прогон
прибора на копии — посадка исполняется на каждом замере, поэтому контроль не может протухнуть,
(4) `diff` двух прогонов против себя (`VECTOR_STABLE`), (5) `python lab/cycle-gate.py audit -n 5`,
(6) `bash lab/workspace-verify.sh E-0114`, (7) `bash lab/check-text-clean.sh` по девяти файлам цикла
и сверка `python lab/expect.py lab/expectations/e0114.tsv`, (8) носитель после прогона и баланс
цикла `python lab/ledger.py`"
threshold: "Заморожено вместе с `lab/expectations/e0114.tsv` (164 ожидания), прибором и helper'ом ДО
замерных прогонов; выведено из напечатанных §1/§2/§3/§4/§5/§7 носителя, из §2 записки и из
PRE_FIX-посадки, а не из прогона после правки. Зелёный прогон обязан дать:
`V9C_TERM_EQ_GOT=31`, `V9C_RECORD_EQ_GOT=31`, `V9C_BINDING_EQ_GOT=31`, `V9C_WITNESS_EQ_GOT=31`,
`V9C_CLAIM_EQ_GOT=29` (`V9C_CLAIM_MISS=none`), `V9C_RECEIPT_JSON_EQ_GOT=31`,
`V9C_SIGNATURES_CHECKED=150`, `V9C_MIRROR_MATCH=31/31` (`V9C_MIRROR_MISS=none`),
`V9C_VECTORS_PARSED=31`, `V9C_VECTOR_KEY_COUNT=71`, `V9C_LAYOUT_ROWS=24`, `V9C_STEP_ROWS_GOT=7`,
`V9C_CODE_NAMES_GOT=18`, `V9C_REGISTRY_ROWS_GOT=6`, `V9C_STEP_CODES_COUNT=10`,
`V9C_CODES_NAMED_IN_STEPS` ⊇ девяти имён, что увидел прибор, `V9C_DOUBLE_REPLAY_COUNT=12`,
`V9C_PAYOUT_COV_EQ_GOT=7`, `V9C_EMPTY_TRUST_CODES=E_ESCROW_UNKNOWN`, `V9C_FAIL_CLOSED_LEAK=none`,
четыре посадки `V9C_DECOY_*_PAIR` с ожидаемыми кодами (`reject/E_REPLAY`,
`reject/E_ESCROW_INSUFFICIENT`, `reject/E_ESCROW_UNKNOWN`, `reject/E_ORDER_MALFORMED`),
`V9C_KEYPAIR_STRANGE_VECTORS=P05|P10`, `V9C_REGISTRY_ROOT=382bdb9d…eeaf`,
`V9C_REGISTRY_EMPTY_ROOT=907fe091…b91be1`, `V9C_WORST=0`, `V9C_ALL_OK=1`,
`E0114_BRIDGE_EXIT=0`, `VECTOR_STABLE=1`. Инварианты (цикл не имеет права их двигать):
`V9C_V01_ORDER_REF=4167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac70`,
`V9C_ANCHOR_IN_LAYER_DOC` и `V9C_ANCHOR_CARRIER_EQ=1`, `V9P_ORDER_REF_UNCHANGED=1`,
`V9P_TERM_HASH=3bb1390594…653b6c`, `V9P_ORDER_REF=99a366a0…576047`, `V9P_CLAIM_LEN=1310`,
`V9P_CLAIM_SHA=87270a59…a38fff`, `V9C_DOC_SHA=11468b49…0eb88c`, `V9C_CARRIER_REPRODUCED=1`,
`V9C_SPEC_SHA=102fc69418f783a46bf397faea373b64c371a3382eab6c35f2910c31d3b532b7` (спека в этом цикле
не тронута; после правки §V9.7 этот пин обязан смениться, а зелёный набор `V9C_*` — нет).
Красный контроль обязан остаться красным: `V9CTL_IS_RED=1`, `V9CTL_BRIDGE_EXIT=1`,
`V9CTL_TERM_EQ=0`, `V9CTL_ALL_OK=0`, `V9CTL_MIRROR_MATCH=4/31`,
`V9CTL_DECOY_SHA=ce81bb21…9faa`. Ресурсный порог (9) называет три числа и не начинается с уборки
`target/`: свободный диск ≥ 15 000 МБ, RAM, peak pagefile — по PRE_FIX-снимку 29 541 / 8 279 / 7 660
МБ. Порог (11) про расписание: каждый ключ сверяется двумя прогонами на неизменном дереве, и в
вектор фактов не входят счётчики, зависящие от порядка шагов"
result: "прогон 2 на дереве b2cb93e: два прогона прибора, VECTOR_STABLE=1, V9C_ALL_OK=1, ОЖИДАНИЙ=164 РАСХОЖДЕНИЙ=0, VERIFY_EXIT=0 (759 passed / 0 failed / 9 ignored, 126 срезов), контроль посадки красный 4/31; байты заказа не двинулись"
verdict: supports
---

## Предмет замера

Первое, что здесь мерится прибором, а не разговором: байты автовыплаты обязаны собираться вне Rust.
Мост сторонней цепочки читает четыре напечатанных текста и должен получить те же `term_hash`, те же
канонические байты связки, свидетельства и требования, те же 150 проверенных подписей и то же
решение по каждому из 31 вектора, что печатает носитель. Если хоть один из этих пересчётов краснеет,
§V9.7 править нельзя: текст ещё не описывает байты, а только называет поля.

## Что уже известно до замера

Носитель воспроизводится из генератора побайтно (`V9C_CARRIER_REPRODUCED=1` в PRE_FIX-снимке),
инвариант аддитивности держится (`V9P_ORDER_REF_UNCHANGED=1`, якорь `4167d021…ac70`), и посадка
прежней формулы красит прибор. Незакрытое — два прогона на неизменном дереве, полная верификация
workspace и сверка 164 ожиданий; именно они дают вердикт, а не снятый выше контроль.

## Результат

Вердикт `supports`: слой стыковки цепочек описан так, что сторонний мост, читая только четыре
напечатанных текста, выводит те же байты и то же решение, что и Rust. Прогон 2 на дереве `b2cb93e`
(`lab/logs/e0114-all.log`, блок с 21:59) дал на двух прогонах прибора `VECTOR_STABLE=1`,
`E0114_BRIDGE_EXIT=0`, `V9C_TERM_EQ_GOT=31`, `V9C_CLAIM_EQ_GOT=29`, `V9C_SIGNATURES_CHECKED=150`,
`V9C_MIRROR_MATCH=31/31`, `V9C_DOUBLE_REPLAY_COUNT=12`, `V9C_EMPTY_TRUST_CODES=E_ESCROW_UNKNOWN`,
`V9C_FAIL_CLOSED_LEAK=none`, `V9C_REGISTRY_ROOT=382bdb9d…eeaf`, `V9C_WORST=0`, `V9C_ALL_OK=1`.
Инварианты не двинулись: `V9C_V01_ORDER_REF=4167d021…ac70`, `V9P_ORDER_REF_UNCHANGED=1`,
`V9C_CARRIER_REPRODUCED=1` при `V9P_DOC_SHA=11468b49…0eb88c`, `V9C_SPEC_SHA_UNCHANGED=1`.
Красный контроль остался красным на каждом прогоне: `V9CTL_BRIDGE_EXIT=1`, `V9CTL_IS_RED=1`,
`V9CTL_TERM_EQ_GOT=0`, `V9CTL_MIRROR_MATCH=4/31`. Аудит — `AUDIT_VIOLATIONS=0`; полная верификация —
`VERIFY_EXIT=0`, `VERIFY_FAIL=0` (126 срезов, 759 passed / 0 failed / 9 ignored, `CLIPPY_EXIT=0`,
`LEAN_EXIT=0`); страж текста — `TEXTGUARD_CYCLE_EXIT=0`; сверка замороженных порогов —
`ОЖИДАНИЙ=164 РАСХОЖДЕНИЙ=0`, `СВЕРКА_EXIT=0`. Ресурсный порог (9): диск 31 108 МБ при допуске
≥ 15 000, RAM 8 808 МБ, peak pagefile 7 660 МБ.

Чего этот вердикт не утверждает. Мост и Rust согласны о байтах и о решении функции
`check_payout_claim`; это не проверка реального контракта эскроу, наблюдателя или цепи — их в
репозитории нет (`OPEN-V9-8`), а `DEFAULT_TRUSTED_CHAINS = []` по-прежнему отправляет любое
требование в `E_ESCROW_UNKNOWN`. Функция чистая и не помнит выплат: «не больше одной выплаты» держит
журнал плательщика или контракт, а не слой (см. `review-panel/REGISTRY.md`, R-77). Lean-модель
эскроу этим циклом не трогалась: доказано для модели, соответствие модели и кода не проверено.

## ДИАГНОЗы

1. Прогон 1 был красным по обвязке, а не по свойству (коммит `b2cb93e`): экстрактор `pick()`
   helper'а не пропускал `|` и обрезал десять многозначных фактов; clippy валил тестовый модуль
   (`.err().expect()`), поэтому `VERIFY_EXIT=1` при `TEST_EXIT=0`. Оба исправлены без касания
   ожиданий; прогон 1 остался в логе как есть.
2. `RUN_EXIT=1` прогона 2 дал не замер, а баланс цикла: `lab/ledger.py` читает весь append-only лог
   цикла и считает провалом любой `<ИМЯ>_EXIT` с ненулевым максимумом. Туда попали (а) намеренно
   красный контроль `V9CTL_BRIDGE_EXIT=1` — его краснота и есть порог, (б) `VERIFY_EXIT=1` и
   `LEDGER_EXIT=1` прогона 1 из того же файла. Ни один из трёх не является провалом прогона 2:
   `LEDGER_SPENT_ON_FAILED=0`, `LEDGER_MISSING_STAGES=0`, `LEDGER_INTERRUPTED=0`. Ledger не входит в
   замороженные пороги карточки, поэтому вердикт выносится по ним. Чинить надо прибор, а не цикл:
   ledger обязан читать только последний блок прогона и не считать провалом выходы контроля
   посадки (имя `*CTL*_EXIT` или отдельный префикс для ожидаемо красных этапов). Это карточка
   плана реализации, а не повод переписывать лог.
