---
id: E-0144
hypothesis: H-0144
status: closed
verdict: "supports"
base_commit: "f1e3ade"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; bash, python и cargo — прибор прогоняет
юнит-тесты `vecdht-cli` и `vecdht-index` на настоящем `ShardStore`, собирает бинарник CLI для
help-строк и не поднимает сеть; PRE_FIX снимается из пина: исходники через `git show`, поведение —
бинарник пина, снимок `lab/logs/e0144-prefix.txt` (заморожен вместе с пином), дата карточки судится
по UTC (`ADR-0070`)"
command: "bash lab/e0144-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0144.tsv run1.txt run2.txt`); PRE_FIX — `git show <пин>:…` и бинарник пина;
носители — `cargo test -q -p vecdht-cli --lib <тест>` и `cargo test -q -p vecdht-index --lib`"
threshold: "(1) пин и диск: `PIN_FOUND=1`, `GATE_H0144_OK=1`, `DISK_GE_15000=1`; (2) дыра названа
пином: `PRE_FIX_FLAGS=0`, `PRE_FIX_INTENT=0`, `PRE_FIX_FILTER=0`, `PRE_FIX_ATTR=0`,
`PREFIX_LOG_ADD_CLASS=1`, `PREFIX_LOG_DIR_COLLISION=1`; (3) самопроверка стража статуса:
`SELFTEST_EXIT=0`, `SELFTEST_TOTAL=13`, `SELFTEST_PASSED=13`; (4) документ пина судится новым
владельцем `S-03`: `CHK_PREFIX_EXIT=1`, `CHK_PREFIX_STALE=1`, `CHK_PREFIX_IDS=S-03`,
`CHK_PREFIX_REASONS=S-03:oracle-missing`, `PRE_S01=consistent`, `PRE_S02=consistent`,
`PRE_S03=stale`, `PRE_S04=consistent`; (5) рабочий документ: `CHK_EXIT=0`, `CHK_STALE=0`,
`CHK_IDS=none`, `CHK_CLAIMS=4`, `CHK_FACTS=9`, `CHK_FACTS_OK=9`, `POST_S03=consistent`;
(6) носители: `ORACLE_FILTER_EXIT=0`, `ORACLE_FILTER_PASSED=1`, `ORACLE_ANY_EXIT=0`,
`ORACLE_ANY_PASSED=1`, `ORACLE_CLI_LIB_EXIT=0`, `ORACLE_INDEX_LIB_EXIT=0`; (7) ручки видны
оператору: `HELP_ADD_CLASS=1`, `HELP_SEARCH_CLASS=1`, `HELP_ADD_INTENT=1`, `HELP_SEARCH_INTENT=1`,
`DIR_IS_DIRECTORY=1`; (8) соседние стражи зелёные (`SECRETS_EXIT`, `REFS_EXIT`, `CLAIMMAP_EXIT`,
`CLAIMS_EXIT`, `CONTOURS_EXIT`, `MIRROR_EXIT`, `GATE_AUDIT_EXIT`, `REVIEW_EXIT`, `LINT_LATEST_EXIT`,
`TEXTGUARD_ALL_EXIT`, `TEXTGUARD_CYCLE_EXIT`), `LINT_ORPHANS=0`, `TEXTGUARD_ALL_DIRTY=0`,
`RUST_TOUCHED=2`; (9) `WORST_RC=0` и два исполнения на неизменном дереве печатают
один вектор — `STABLE=1`. Порог заморожен до первого прогона `lab/e0144-run.sh`; изменение любого
числа — новая карточка."
---

# E-0144 — флаги фильтра у CLI: `--class` и `--intent-dir`

## Что проверяется

Оператор может пометить запись как платную/бесплатную и как «куплю»/«продам» (`index add
--class/--intent-dir`) и искать с тем же фильтром (`index search --class/--intent-dir … any`).
Биты едут в `slot_attr` тем же WAL-фреймом, что у узла (§5.5), предикат применяется до усечения
`top_k` (§12.7), `Any/Any` повторяет прежний ответ. `--dir` остаётся каталогом шарда: имя из
очереди занято, и направление называется `--intent-dir` — это названо до пина бинарником пина
(`index search --dir T --dir buy` → «указан 2 раз»).

## Почему это не косметика

`docs/STATUS-v1.md` писал «флагов нет» — и это было правдой при механизме в дереве (`E-0100`):
узел фильтрует, а оператор не может ни выбрать класс, ни проверить, что флаг отображается в тот же
бит. Строка статуса после починки перестаёт быть «нет флагов» и становится владельцем
`crates/vecdht-cli/src/index_cmd.rs`; прежний страж искал `--class` в `args.rs`, где флагов команд
нет вовсе, — зелёный по неверному владельцу.

## Границы

Тест доказывает отображение и порядок на нашем хранилище, а не поведение узла на проводе. Клиент
по-прежнему не может машинно проверить, что узел применил фильтр. Цена не хранится: в `slot_attr`
её бита нет. `--intent-dir` — новое имя, а не обещанное очередью `--dir`; переименование каталога
не делается (оно сломало бы все команды).

## Результат (первый прогон носителя)

Порог выполнен; пять ключей шага (5) оставались красными ровно до закрытия этой карточки, потому что
`S-03` судится ею и до вердикта печатает `oracle-missing` — это и есть замороженная форма проверки,
а не дефект дерева. Пин: `PRE_FIX_FLAGS=0`, `PRE_FIX_INTENT=0`, `PRE_FIX_FILTER=0`, `PRE_FIX_ATTR=0`;
бинарник пина отвечает `ADD_CLASS_RC=1` и `SEARCH_DIR_RC=1` (`PREFIX_LOG_ADD_CLASS=1`,
`PREFIX_LOG_DIR_COLLISION=1`). Документ пина — ровно `S-03`, причина `oracle-missing`; `S-01`, `S-02`
и `S-04` согласованы. Самопроверка стража статуса 13 из 13. Носители зелёные: тест фильтра 1 из 1,
`Any/Any` 1 из 1, `vecdht-cli` lib 70 passed / 1 ignored, `vecdht-index` lib 86 passed. Ручки видны
в help обеих команд (`HELP_ADD_CLASS=1`, `HELP_SEARCH_CLASS=1`, `HELP_ADD_INTENT=1`,
`HELP_SEARCH_INTENT=1`), `--dir` остался каталогом (`DIR_IS_DIRECTORY=1`). Соседние стражи зелёные,
`LINT_ORPHANS=0`, `TEXTGUARD_ALL_DIRTY=0`, `RUST_TOUCHED=2`.

## Итог исполнения

Пре-регистрация — `298fa79`. Фикс: `ShardStore::publish_with_attr` (тот же WAL-путь, байт в теле
фрейма), `--class`/`--intent-dir` у `index add` и `index search`, предикат до усечения в обоих
поисках (включая оракул полного скана), объявление в `--show-entries`, два юнит-теста. Строка `S-03`
в `docs/STATUS-v1.md` переписана в положительную форму и называет владельца
`crates/vecdht-cli/src/index_cmd.rs`; страж статуса судит её карточкой круга.

Верификация `bash lab/workspace-verify.sh E-0144`: `VERIFY_FAIL=0`, 134 среза, 788 passed, 0 failed,
9 ignored; `TEST_EXIT=0`, `CLIPPY_EXIT=0`, `LEAN_EXIT=0`, `LEANGUARD_SELFTEST_EXIT=0`, `VERUS_EXIT=0`;
`SECONDS_total=2488`; диск 22 707 → 22 147 МБ. Официальные прогоны носителя — двумя исполнениями на
неизменном дереве после закрытия карточки: `ОЖИДАНИЙ=54 РАСХОЖДЕНИЙ=0`, `WORST_RC=0`,
`STABLE=none` → `STABLE=1`; их числа записаны в `lab/logs/e0144-all.log`.
