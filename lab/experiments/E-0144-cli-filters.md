---
id: E-0144
hypothesis: H-0144
status: pending
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
