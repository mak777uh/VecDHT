---
id: E-0034
hypothesis: H-0034
status: planned
base_commit: "0f29519"
started: null
finished: null
environment: null
command: "lab/e0034-run.sh — `cargo test -j 2 -p vecdht-crypto --test shard_number_admission -- --nocapture` (debug) + контроль `cargo test -j 2 -p vecdht-crypto` + grep-инвентари: сайты `clusters_of_shard(` и `is_valid_shard(` в нетестовом коде, число полей `pub shard: u16` против число диапазонных проверок в `messages.rs`, сайты сверки `.shard != self.shard` в `node.rs`"
threshold: "Успех — четыре одновременно: (1) сайтов вызова `clusters_of_shard` в нетестовом коде ровно 3, все в `cli/src/index_cmd.rs`, и у каждого номер прошёл `dir_and_shard` (`:88`) или взят из `group_by_shard`; (2) сайтов `is_valid_shard(` в нетестовом коде вне `vecdht-crypto` — 0; (3) `clusters_of_shard(64)` побайтово равно `clusters_of_shard(0)` и `clusters_of_shard(80)` равно `clusters_of_shard(16)`, и каждый снятый внедиапазонный номер, не вызвавший паники, равен списку шарда `shard % SHARDS`; (4) `catch_unwind` фиксирует панику при `shard = 4095` и её отсутствие при `shard = 4094` (граница `base + 16 = 65 536` в `u16`). Провал (1)/(2) = фальсификаторы (а)/(б): путь достижим из сети или guard всё-таки используется. Провал (3) = (в), провал (4) = (г). Распределение проверок по 13 сообщениям (3 из 13) снимается как факт, порогом не является."
result: null
verdict: pending
---

# E-0034 — номер шарда вне диапазона: маска в `clusters_of_shard`, 3 проверки на 13 сообщений

## Гипотеза

См. `H-0034`.

## Стенд (правок измерительного гейта нет)

Новый тестовый файл `crates/vecdht-crypto/tests/shard_number_admission.rs`: один тест, который по
набору номеров `{0, 1, 63, 64, 80, 128, 1024, 4094, 4095, 65535}` снимает либо список кластеров, либо
панику переполнения (`catch_unwind` с глушителем хука, чтобы прогон не обрывался на границе), и
сравнивает полученные списки со списками шарда `shard % SHARDS`. `crypto` зависит от `wire`, поэтому
и сообщения, и константы (`SHARDS`, `CLUSTERS_PER_SHARD`, `NLIST`) видны отсюда; сеть, корпус и
`candle` не поднимаются. Сборка debug — это часть замера: в release та же арифметика `u16` была бы
тихим кольцом вместо паники. Правок `clusters_of_shard`, `messages.rs`, `node.rs`, гейтных порогов нет.

## Прогон

(заполняется после прогона)

## Результат

(заполняется после прогона)

## Границы результата

(заполняется после прогона)
