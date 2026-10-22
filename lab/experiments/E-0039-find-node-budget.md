---
id: E-0039
hypothesis: H-0039
status: planned
base_commit: "78f6fcd"
started: null
finished: null
environment: null
command: "lab/e0039-run.sh — `cargo test -j 2 -p vecdht-node --test find_node_budget -- --nocapture`; инвентарь grep `reserve_admit`/`handle_find`; контроль `cargo test -j 2 -p vecdht-node`"
threshold: "Успех — четыре одновременно: (1) пачка 21 свежих ключа × 6 `Find` при одной секунде: ровно 105 пропущено, ровно 21 `QUOTA_FIND`, ноль иных исходов; (2) `stats.finds_allowed == 105`, `stats.rejected_find_quota == 21`, `stats.rejected_node_busy == 0`; (3) контраст сразу после пачки: 100 подряд `reserve_admit(0)` — `Allow`, 101-й — `NodeBusy { retry_after_ms: 10 }` (бакет §11.3.4 не тронут find'ами); (4) grep: единственная позиция вызова `reserve_admit` в `node.rs` — на пути записи (714), в теле `handle_find` — 0 вхождений. Провал (1) = (а)/(в), провал (2)–(3) = (б), провал (4) = (г)."
result: null
verdict: pending
---

# E-0039 — sybil-набор `Find`: 105 разрешённых поиска в секунду при узловом бюджете 100 admit/с

## Гипотеза

См. `H-0039`.

## Стенд (правок измерительного гейта нет)

Новый тестовый файл `crates/vecdht-node/tests/find_node_budget.rs`: harness
`find_admission_price.rs` (шард 7, primary после genesis, пустой индекс), 21 свежих ключа × 6
кадров при `testing::clock(0)`, сверка `admission.stats`, контрастный прогон `reserve_admit`.
Оракул скомпилирован (`--no-run`, EXIT=0) и проверен clippy до commit'а пре-регистрации.
Правок продукта, квот и порогов нет. Инвентарь (4) — grep в скрипте прогона.

## Прогон

(заполняется после прогона)

## Результат

(заполняется после прогона)

## Границы результата

(заполняется после прогона)
