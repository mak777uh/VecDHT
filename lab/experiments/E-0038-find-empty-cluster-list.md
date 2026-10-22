---
id: E-0038
hypothesis: H-0038
status: planned
base_commit: "7b9c878"
started: null
finished: null
environment: null
command: "lab/e0038-run.sh — `cargo test -j 2 -p vecdht-node --test find_empty_cluster_list -- --nocapture`; контроль `cargo test -j 2 -p vecdht-node`"
threshold: "Успех — два одновременно: (1) пустой `Find` (clusters = []) от свежего ключа на primary: кадра `Error` нет, получен `MatchResult`, `matches.len() == 0`, `query_id` — эхо запроса; (2) квота: первый пропуск из (1) плюс четыре из следующих шести, шестой и седьмой того же ключа в ту же секунду — `QUOTA_FIND` с `retry_after_ms = 200` (формулировка H-0038 «пять пропущено, шестой отказ» держится кумулятивно: бакет 5, проверка (1) уже сняла один токен). Исход не-primary узла (порог (3)) только протоколируется: утверждений до прогона нет. Провал (1) = фальсификатор (а) или (б), провал (2) = (в)."
result: null
verdict: pending
---

# E-0038 — пустой список `Find`: подписанный пустой `MatchResult` без единого отказа, цена — токен

## Гипотеза

См. `H-0038`.

## Стенд (правок измерительного гейта нет)

Новый тестовый файл `crates/vecdht-node/tests/find_empty_cluster_list.rs`: тот же harness, что у
`find_admission_price.rs` (шард 7, primary после genesis, свежий ключ 203), пустой индекс — по
методу (исход не зависит от содержимого шарда), плюс второй узел на втором сиде порядка эпохи для
факт-записи о не-primary. Оракул скомпилирован (`--no-run`, EXIT=0) и прогнан через
`clippy -p vecdht-node --all-targets -D warnings` (EXIT=0) **до** commit'а пре-регистрации.
Правок продукта, квот и порогов нет.

## Прогон

(заполняется после прогона)

## Результат

(заполняется после прогона)

## Границы результата

(заполняется после прогона)
