---
id: E-0037
hypothesis: H-0037
status: planned
base_commit: "8209955"
started: null
finished: null
environment: null
command: "lab/e0037-run.sh — `cargo test -j 2 -p vecdht-wire --test find_cluster_list -- --nocapture`; `cargo test -j 2 -p vecdht-index --test find_cluster_list_amplification -- --nocapture`; `cargo test -j 2 -p vecdht-node --test find_admission_price -- --nocapture`; контроль `cargo test -j 2 -p vecdht-wire -p vecdht-index -p vecdht-node`; инвентарь grep по приёмному пути `Find`"
threshold: "Успех — четыре одновременно: (1) `Find` со списком 65 535 кластеров кодируется, декодируется побайтово без изменений, тело < MAX_BODY_LEN; (2) тело с 65 536 элементами не декодируется как валидный `Find` (variant ошибки записывается как факт; порог требует отказа, не variant'а); (3) для n ∈ {1, 16, 256, 1024, 4096} `search([0; n], top_k = n·69+1).len() == n·69` ровно и `search([0; 1024], 10).len() == 10`; (4) ровно 5 первых find каждого из двух свежих ключей пропущены, шестой — QUOTA_FIND/200, коды и ожидания обоих ключей идентичны. Плюс инвентарь (5): 0 проверок `clusters.len()` в приёмном пути вне guard'а `shard_of_cluster` (greps в лог, фактом цикла, порогом «не найдено ничего другого»). Провал (1) = фальсификатор (а), (2) = (б), (3) = (в), (4) = (г)."
result: null
verdict: pending
---

# E-0037 — раздутый список `Find`: кодек пропускает 65 535, дубликаты сканируются поштучно,
# admission берёт один токен независимо от длины

## Гипотеза

См. `H-0037`.

## Стенд (правок измерительного гейта нет)

Три новых тестовых файла без правок продукта:

- `crates/vecdht-wire/tests/find_cluster_list.rs` — пороги (1), (2): round-trip предельного
  u16-списка и отказ при 65 536 с записью фактического variant'а ошибки;
- `crates/vecdht-index/tests/find_cluster_list_amplification.rs` — порог (3): стенд гейта §19.1
  (шард 0, 1 104 = 16 × 69 записей), точное число hits против `n` дублей кластера, времена p50
  печатаются справочно и порогом не являются;
- `crates/vecdht-node/tests/find_admission_price.rs` — порог (4): harness `tests/admission.rs`
  (шард 7, primary после genesis), два свежих ключа, `[112]` против `[112; 4096]`, шесть find
  каждому при `testing::clock(0)`.

Инвентарь (5) — grep по `Find::decode_body`, `handle_find`, `check_find` на любые ограничения
длины списка. Правок `clusters_of_shard`, приёмного пути и квотных порогов нет.

## Прогон

(заполняется после прогона)

## Результат

(заполняется после прогона)

## Границы результата

(заполняется после прогона)
