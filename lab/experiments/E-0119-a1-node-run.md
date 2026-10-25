---
id: E-0119
hypothesis: H-0119
status: pending
base_commit: "f564a3e"
started: "2026-10-26"
finished: ""
environment: "x86_64-pc-windows-gnu, хост владельца; Rust из PATH (cargo/rustc), Python 3 из PATH, PYTHONIOENCODING=utf-8; debug-сборка инкрементально поверх дерева f564a3e; сеть — 127.0.0.1, QUIC, два процесса `node run` и агент в тесте"
command: "bash lab/e0119-run.sh"
threshold: "(1) `cycle-gate.py gate H-0119` выход 0, диск ≥ 15 000 МБ до и после; (2) `cargo test -q -p vecdht-cli --test node_run -- --test-threads=1` дважды на неизменном дереве: RESULT_EXIT=0, PASSED=2, FAILED=0 в каждом прогоне, наборы фактов совпали (STABLE=1); (3) `expect.py lab/expectations/e0119.tsv` по обоим прогонам: EXPECT_EXIT=0; (4) посадка `PASSED=1` в копию таблицы даёт EXPECT_EXIT=1 (PLANT_EXIT=1); (5) PRE_FIX: на дереве `f564a3e` в `crates/vecdht-cli/src/lib.rs` нет пути `node run` и нет файла `node_cmd.rs` (PRE_FIX_NO_NODE_RUN=1); (6) `cargo clippy -q -p vecdht-cli --all-targets -- -D warnings` выход 0; (7) стража текста на новых файлах цикла выход 0. Порог заморожен до первого прогона `lab/e0119-run.sh`; изменение любого числа — новая карточка."
result: "pending"
verdict: "pending"
---

## Pre-registration (до прогона)

Порог заморожен до первого прогона. Проверяется не «команда появилась», а то, что собранный ею
узел **обслуживает сеть** и **отказывается** там, где церемония не сходится с ключом, шардом или
составом.

Источник чисел — `crates/vecdht-cli/tests/node_run.rs`, два теста:

* `node_run_publishes_finds_and_survives_restart` — церемония через CLI, два процесса на шарде 0
  (primary и реплика), `Publish` и `Find` через `vecdht_net::Agent`; затем оба процесса гасятся,
  primary поднимается снова из того же `--dir` и **без bootstrap**, `Find` обязан найти запись.
  Реплика гасится намеренно: иначе «пережило рестарт» означало бы «пережил сосед».
* `node_run_refuses_incomplete_or_foreign_ceremony` — отсутствие `--cert`/`--genesis` (код 1,
  имя флага), кредашиал на другого владельца (код 2), подмена ёмкости члена в теле genesis
  (код 2: подпись порога над телом не сходится).

Замена, названная заранее: пункт «рестарт сохраняет отзыв и бан» из карточки A1 в этом цикле
**не измеряется** — производителя отзыва нет (A3), а переживание списков уже измерено
`E-0092`/`E-0094`. Здесь проверяется общий для обоих каталог (`--dir`) и то, что узел после
рестарта читает состояние с диска. Невыполненным этот пункт считается честно, а не «закрыт
соседним циклом».

PRE_FIX — пин `f564a3e` (предок дерева): на нём `node_cmd.rs` нет, а в диспетчере нет строки
`node_cmd::CMD_RUN`; поэтому «до» — ноль команд, а не красный тест, который нечем было получить.
