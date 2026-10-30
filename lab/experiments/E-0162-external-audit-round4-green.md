---
id: E-0162
status: closed
verdict: "supports"
date: "2026-10-30"
---

# E-0162 — зелёная часть 4-го круга: строгий декод, имена доменов, честные тексты

## Вопрос

Закрывается ли зелёная часть 4-го круга (m1, m2, m3, m5, T2, R3/m8) правкой, которая не меняет
провод, формат диска и golden-векторы, — и наблюдаемо ли каждое закрытие отдельным фактом:
строгий декод на новом тесте, красный на пине; шесть доменов без литералов при 19 именованных
определениях; текст `SigLength` без «32, 64»; README.en/README.ru без content-addressed и с
«одним провайдером на шард»; §14.2 с тремя «не реализовано в v1»; §7.7 без ротации через
`ArtifactAnnounce` как механизма v1?

## Порог

Заморожен в `lab/expectations/e0162.tsv` до первого официального прогона: на пине новый тест
красный (`PRE_FIX_TEST_RC=1`), после правки зелёный (`POST_FIX_TEST_RC=0`), `TEST_CASES=2`,
`TEST_PASS=2`, `BYTE_MUTATION_RC=0`, `WIRE_TEST_RC=0`, `GOLDEN_RC=0`; `TAIL_IMPL=1`,
`SIGLEN_MSG=1`, `SIGLEN32=0`, `DOMAIN_LITERALS=0`, `DOMAIN_NAMED=19`; README
(`README_PROVIDER=1`, `README_NODE_DECISION=1`, `README_CA=0`) и README.ru (`RU_PROVIDER=1`,
`RU_NODE_DECISION=1`, `RU_CA=0`); спека (`SPEC_RECOMP=0`, `SPEC_SIGFIELD=0`, `SPEC_PENALTY=0`,
`SPEC_NOT_V1=3`, `SPEC_PROVIDER=1`, `SPEC_TIMEOUT=1`, `SPEC_ARTIFACT=1`); границы правки
(`WIRE_SRC_TOUCHED=3`, `TESTS_TOUCHED=2`, `README_TOUCHED=2`, `SPEC_TOUCHED=1`, `CI_TOUCHED=1`,
`GOLDEN_CHANGED=0`); счётчики шапки CI (`CIN_TOTAL_ALL=808`, `CIN_CRATE_WIRE=59`,
`CIN_FINDINGS=0`, `CIN_EXIT=0`); соседние стражи и зеркало спеки 0; два прогона совпадают.

## Прогон

Пилот и два официальных прогона 2026-10-30 на неизменном дереве `2e76647` (пин пре-регистрации
`3d78272`), носитель `lab/e0162-run.sh` → `lab/logs/e0162-all.log`. Каждый прогон: PRE_FIX —
`git checkout <пин> -- crates/vecdht-wire/src/frame.rs` (trap возвращает HEAD) и прогон нового
теста на старом декодере; POST_FIX — тот же тест, `frame_byte_mutation`, весь `vecdht-wire` и
golden-векторы на живом дереве; затем факты текстов и границ. Оба официальных прогона совпали
побайтово (кроме строки `STABLE`), `WORST_RC=0`, `STABLE=1`, 46/46 фактов:

* PRE_FIX: `PRE_FIX_TEST_RC=1` — старый `decode_frame` принимает хвост, новый тест краснеет
  ровно на `TrailingBytes`; `POST_FIX_TEST_RC=0`, `TEST_CASES=2`, `TEST_PASS=2`;
* `BYTE_MUTATION_RC=0`, `WIRE_TEST_RC=0`, `GOLDEN_RC=0` — канонические кадры и golden прежние;
* `TAIL_IMPL=1` (единственное `TrailingBytes` в `frame.rs`), `SIGLEN_MSG=1`, `SIGLEN32=0`,
  `DOMAIN_LITERALS=0`, `DOMAIN_NAMED=19` (20-я строка — объявление трейта);
* README: `README_PROVIDER=1`, `README_NODE_DECISION=1`, `README_CA=0`; README.ru:
  `RU_PROVIDER=1`, `RU_NODE_DECISION=1`, `RU_CA=0`;
* спека: `SPEC_RECOMP=0`, `SPEC_SIGFIELD=0`, `SPEC_PENALTY=0`, `SPEC_NOT_V1=3`,
  `SPEC_PROVIDER=1`, `SPEC_TIMEOUT=1`, `SPEC_ARTIFACT=1`;
* границы: `WIRE_SRC_TOUCHED=3`, `TESTS_TOUCHED=2`, `README_TOUCHED=2`, `SPEC_TOUCHED=1`,
  `CI_TOUCHED=1`, `GOLDEN_CHANGED=0`;
* шапка CI: `CIN_TOTAL_ALL=808`, `CIN_CRATE_WIRE=59`, `CIN_FINDINGS=0`, `CIN_EXIT=0`;
* соседние стражи и зеркало: `CITES_EXIT=0`, `CLAIMMAP_EXIT=0`, `MIRROR_EXIT=0`, `GSE_EXIT=0`,
  `PARITY_EXIT=0`, `CONTOURS_EXIT=0`, `EXPECT_FREEZE_EXIT=0`, `TEXT_EXIT=0`, `CLAIMS_EXIT=0`;
* `DISK_READABLE=1`; диск после второго прогона `DISK_FREE_MB=7494` — ниже порога 15 000 МБ,
  поэтому блок `workspace-verify` ждёт `cargo clean` по слову владельца.

## Поправка

Первый блок контура (строки 217 862…220 603, дерево `b0f3d9a`) красный `VERIFY_FAIL=1` при
`SECONDS_total=3677`: единственная находка — `REVIEW_EXIT=1`, `REVIEW_TOP=closed-empty-result:1`,
`lab/hypotheses/H-0161-pull-admission.md` закрыта без раздела «Результат». Это артефакт
предыдущего цикла, не правка H-0162; раздел восстановлен по фактам блока 215 631 в этом же цикле.
Остальные секции блока зелёные (`TEST_EXIT`, `CLIPPY_EXIT`, `LEAN_ALL_OK=1`, `CIN_EXIT=0`,
`TEXTGUARD_EXIT=0`, самопроверки стражей 0). Закрытие — только по следующему зелёному блоку.

После зелёного блока remote `main` оказался впереди на 9 чужих коммитов `audit:`/`notes:`
(примечания и рекомендации, 1 375 строк markdown); цепь цикла перебазирована: пре-регистрация
`b1945c0`, правка `4c5ae18`, прогоны `e262b5e`, поправка `ede4316`, закрытие `c3e464b`.
Разница измеренного дерева `616e132` и `ede4316` — ровно эти 9 файлов, кода нет; на совмещённом
дереве лёгкие стражи зелёные (`REVIEW_FINDINGS=0`, `CONTOURS_EXIT=0`, `EF_FINDINGS=0`,
`CLAIMS_GUARD_EXIT=0`, `TEXTGUARD_EXIT=0`, `PARITET_НАХОДОК=0`, `CLAIMMAP_UNMAPPED=0`,
`SPEC_CITES_FINDINGS=0`, `CIN_EXIT=0`, зеркало OK). Тяжёлые секции блока (тесты, clippy, Lean)
этими файлами не затрагиваются: ни один крейт не менялся.

## Результат

`supports`. Блок контура строка 220 604 (`########## E-0162 · workspace-verify · 2026-10-30T22:05:45+03:00 ##########`), дерево `616e132`: 138 наборов, 795 passed, 0 failed, 9 ignored; `TEST_EXIT=0`, `CLIPPY_EXIT=0`, `LEAN_ALL_OK=1`, `CIN_EXIT=0`, `REVIEW_FINDINGS=0`, все самопроверки стражей 0, `TEXTGUARD_EXIT=0`, `VERIFY_FAIL=0`, `SECONDS_total=4051`. Диск после блока `DISK_FREE_MB=15448` — порог 15 000 пройден. Первый блок 220 603 был красным одной находкой `closed-empty-result` (`H-0161` без «Результата»); починка `616e132`, запись в «Поправке». Пилот и два официальных прогона носителя — `WORST_RC=0`, `STABLE=1`, 46/46 фактов на дереве `2e76647`.

## Границы

Провод (`encode_frame`, тела, трейлер) и формат диска не меняются; меняется приём
неканонического хвоста кадра. `Kind`, `Match`, `Publish`, `IntentTextRequest/Response` не
трогаются. T1, R1, R2, T3, T4-код, m4 и m6 этой карточкой не закрываются: они меняют провод,
замороженный список 18 кодов или являются отдельной карточкой CI. Числа шапки `verify.yml`
правятся только как следствие нового теста (2 `#[test]`), не как отдельное намерение.
