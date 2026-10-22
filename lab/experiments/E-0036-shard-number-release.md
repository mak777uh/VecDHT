---
id: E-0036
hypothesis: H-0036
status: planned
base_commit: "eab6248"
started: null
finished: null
environment: null
command: "lab/e0036-run.sh — `cargo test -j 2 --release -p vecdht-crypto --test shard_number_release -- --nocapture` + контроль `cargo test -j 2 --release -p vecdht-crypto` и debug-проверка пропуска (`cargo test -j 2 -p vecdht-crypto --test shard_number_release`)"
threshold: "Успех — четыре одновременно: (1) паник по всему входу `u16` ровно 0; (2) пустых списков ровно 16 и их позиции побайтово равны `{4095 + 4096·k | k = 0…15}`; (3) среди непустых выходов несоответствий маске `clusters_of_shard(s % SHARDS)` ровно 0, все длины 16; (4) различных выходов ровно 65 (64 законных списка + пустой). Провал (1) = фальсификатор (а), (2) = (б), (3) = (в), (4) = (г). Перебор полный: 65 536 вызовов, release-профиль, debug-ветка теста ничего не утверждает."
result: null
verdict: pending
---

# E-0036 — `release`-профиль для `clusters_of_shard`: ноль паник, шестнадцать пустых списков, 65 выходов

## Гипотеза

См. `H-0036`.

## Стенд (правок измерительного гейта нет)

`crates/vecdht-crypto/tests/shard_number_release.rs`: один цикл по всем `0…65 535` входам,
`catch_unwind` с заглушённым panic-хуком, разбор на «паника / пустой список / непустой список»,
сравнение непустых с `clusters_of_shard(s % SHARDS)`, накопление множества различных выходов. В
debug-профиле тест печатает строку пропуска и не содержит утверждений. Константы берутся из
`vecdht-wire::constants`, `CLUSTERS_PER_SHARD` и `SHARDS` не переписываются в тест. Правок
`clusters_of_shard`, `Cargo.toml` (профили) и гейтных порогов нет.

## Прогон

(заполняется после прогона)

## Результат

(заполняется после прогона)

## Границы результата

(заполняется после прогона)
