---
id: E-0121
hypothesis: H-0121
status: running
base_commit: "dc6a9d6"
started: "2026-10-26"
finished: ""
environment: "x86_64-pc-windows-gnu, хост владельца; Rust из PATH (cargo/rustc), Python 3 из PATH, PYTHONIOENCODING=utf-8; debug-сборка инкрементально поверх дерева dc6a9d6; сеть — 127.0.0.1, QUIC, два процесса `node run`, публикация и поиск настоящим `vecdht_net::Agent`"
command: "bash lab/e0121-run.sh"
threshold: "(1) `cycle-gate.py gate H-0121` выход 0, диск ≥ 15 000 МБ до и после; (2) `cargo test -q -p vecdht-cli --test node_centroids -- --test-threads=1 --nocapture` дважды на неизменном дереве: RESULT_EXIT=0, PASSED=2, FAILED=0 в каждом прогоне, наборы `CT_*`-фактов совпали (STABLE=1); (3) `expect.py lab/expectations/e0121.tsv` по обоим прогонам: EXPECT_EXIT=0 при `CT_MISSING_CODE=2`, `CT_MISSING_NAMED=1`, `CT_HONEST_REASSIGNED=0`, `CT_FORGED_REASSIGNED_GE1=1`, `CT_FORGED_UNVERIFIED_ZERO=1`, `CT_FORGED_CELL_HONEST=1`, `CT_STATUS_CLUSTER_FIELDS=1`; (4) посадка `CT_FORGED_REASSIGNED_GE1=0` в копию таблицы даёт EXPECT_EXIT=1 (PLANT_EXIT=1); (5) PRE_FIX: на дереве `dc6a9d6` в `crates/vecdht-cli/src/node_cmd.rs` нет ни `with_centroids`, ни поля `cluster_reassigned=` в строке `NODE_STATUS` (PRE_FIX_NO_CENTROIDS_WIRING=1); (6) `cargo clippy -q -p vecdht-cli --all-targets -- -D warnings` выход 0; (7) стража текста на новых файлах цикла выход 0. Порог заморожен до первого прогона `lab/e0121-run.sh`; изменение любого числа — новая карточка."
result: ""
verdict: ""
---

## Pre-registration (до прогона)

Порог заморожен до первого прогона. Проверяется не «флаг `--artifact` читается», а то, что
продуктовая команда `node run` пересчитывает присваивание на живом узле и что отсутствие
`centroid.bin` — отказ, а не тихий fail-open.

Источник чисел — `crates/vecdht-cli/tests/node_centroids.rs`, два теста:

* `node_run_refuses_artifact_without_centroids` — копия артефакта без `centroid.bin`: `node run`
  с полной церемонией возвращает код 2, и текст называет `centroid.bin`. Это «до»-утверждение
  карточки A2: без файла узел не стартует.
* `forged_cluster_id_is_reassigned_by_live_cli_node` — два процесса `node run` на шарде 0 с
  `--artifact` (теперь с центроидами). Честная публикация `Agent`'ом: `cluster_reassigned=0`.
  Затем второй `Agent` публикует тот же вектор, заявив **другой кластер того же шарда**
  (`honest ^ 1` при `honest < 16`). Проверяется: публикация принята, `Find` по пересчитанному
  кластеру находит запись с `cluster_id = honest`, `cluster_reassigned ≥ 1`,
  `cluster_unverified = 0`; оба счётчика присутствуют в `NODE_STATUS`.

Факты инвариантны к расписанию: коды и имена — формат; `cluster_reassigned` у честной публикации
по построению ноль (пересчёт совпал с подсказкой), у подделки — «не ноль» (проверяется
неравенством, а не точным числом: статус читается после получения квитанции, но число счётчиков
не зависит от того, сколько раз узел успел напечатать строку); `cluster_unverified` — ноль при
наличии центроидов; клетка записи проверяется поиском, а не счётчиком.

Замена, названная заранее: цена `assign` на publish-пути не перемеряется — она измерена `E-0103`;
здесь предмет — проводка и наблюдаемость, а не арифметика.

PRE_FIX — пин `dc6a9d6` (текущая вершина до фикса): на нём в `node_cmd.rs` нет `with_centroids`,
а строка `NODE_STATUS` не печатает `cluster_reassigned`/`cluster_unverified`. То есть «до» — это
ноль проводки, а не красный тест: оракул появляется вместе с проводкой.

## Результат

(заполняется после прогона)
