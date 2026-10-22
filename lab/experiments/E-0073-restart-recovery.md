---
id: E-0073
hypothesis: H-0073
status: completed
base_commit: "51f79b1"
started: "2026-10-22T22:03:39+03:00"
finished: "2026-10-22T22:09:37+03:00"
environment: "Windows; MinGW gcc 16.2.0; rustc 1.99.1 (58cf8f9c3 2026-10-13); debug; RAYON_NUM_THREADS=2; один процесс; тройка сидов из 1..=16, primary эпохи 1 первым в speaker_order(2)"
command: "bash lab/e0073-run.sh"
threshold: "H-0073 (0)…(8): WAL/членство переживают рестарт, lease — нет; чтение идёт, запись даёт EPOCH_STALE; новая эпоха возвращает W=2; GC решает применённый mark; снапшот-барьер переживает reopen, partial не ломает open; группового коммита в publish-пути нет"
result: "1 passed; 0 failed; 1.10 s; пороги (0)…(8) совпали (два первых прогона упали на допущениях каркаса, пороги не менялись); КОНТРОЛЬ -p vecdht-node 133 ok; верификация воркспейса 577 ok, 85 бинарей, TEST_EXIT=0, CLIPPY_EXIT=0"
verdict: supports
---

## Pre-registration (до прогона)

Вопрос: §10 обещает порядок `op → WAL → fsync → память → ответ`, барьер снапшота
`partial → fsync → rename → fsync каталога → MANIFEST → удаление сегментов` и
восстановление `MANIFEST → снапшот → хвост WAL`; crash-матрица §10.5 (точки 1–10 +
property) уже живёт юнит-тестами `crash_matrix.rs` на уровне `ShardStore`. Лабораторно §10
не мерился ни разу. Композиция «store-восстановление + членство + lease §9.8 + W=2 §9.4»
не проверялась: переживает ли рестарт **узла** членство, теряется ли право писать, чем
определяется TTL после рестарта и обещает ли §10.2 групповой коммит, которого нет в
publish-пути.

Пороги (0)…(8) и фальсификаторы (а)…(н) заморожены в `H-0073` до первого прогона.
Входы: шард 7, детерминированная тройка из 1..=16 с primary эпохи 1 первым в
`speaker_order(2)`, PoW 8, TTL 225 (E — ttl 1), lease 6 / renew 2 / election 4, W=2, R=3,
`membership_threshold=2`; P — primary эпохи 1, H и S — реплики.

## Прогон

`bash lab/e0073-run.sh`, лог `lab/logs/e0073-all.log` (append-only). Три скриптовых
прогона; первые два упали на **допущениях каркаса**, а не на порогах, и остановились до
середины сценария:

1. `22:03:39` (`51f79b1`) — `Find` на попадание отдаёт не один кадр, а `MatchResult` +
   `RendezvousAccept` на каждую запись (§12.3); helper ждал один кадр (3 vs 1).
2. `22:06:22` (`138d2b5`) — helper ждал `matches:1`, но `Find` возвращал top-k кластера,
   а A и B лежали в одном кластере (2 vs 1). Прямая итерация показала третий изъян:
   «D не виден» нельзя проверить общим кластером — top-k вернёт живого соседа. Каркас
   получил изоляцию кластеров по вектору (`112 + vec % 8`) и top_k=1.
3. `22:09:34` (`1ec8bdf`) — **решающий**: `1 passed; 0 failed` за 1.10 с, EXIT=0.

Пороги и фальсификаторы не менялись; правились только helper'ы `find`/`cluster_of`.
До решающего прогона оракул компилировался `--no-run` (EXIT=0); clippy — в верификации
воркспейса ниже.

* КОНТРОЛЬ `-p vecdht-node` — 133 ok, 0 failed, 3 ignored, EXIT=0 (132 в блоке `E-0072`
  + новый оракул; исторические `heal_demotion_window`, `future_epoch_lease_freeze` и
  P5-гейт — ignored);
* ИНВЕНТАРЬ — см. (8): `GROUP_COMMIT_MS` только определение/реэкспорт/тест;
  `should_group_commit` — store, юнит-тест и bench, но не publish-путь узла; publish
  делает `stage_insert` → `commit` на каждый опс; `SystemTime`/`Instant` в
  `index`/`node` отсутствуют; wire не тронут; в `crash_matrix.rs` 11 тестов (10 точек +
  property); устаревшие оракулы — `#[ignore]`;
* ВЕРИФИКАЦИЯ — `bash lab/workspace-verify.sh E-0073` (22:12:23…22:22:34, 85 бинарей):
  **577 ok, `TEST_EXIT=0`, `CLIPPY_EXIT=0`**, 0 предупреждений (счёт `E-0072`: 576 ok /
  84 бинаря; +1 активный оракул, новых `#[ignore]` нет).

## Результат

| Порог | Что наблюдалось |
|---|---|
| (0) | A (bucket 1) и B (bucket 1) через P, W=2: у всех `applied_seq=2`, `len=2`, слоты A/B совпадают, `epoch()=1`, `lease{1,P,6}`, `serving_epoch(2)=Some(1)`, `last_snapshot_seq=0`, `replayed=0`; Find A у H — один `MatchResult{epoch:1, matches:1}` + приём |
| (1) | H закрыт и открыт: `applied_seq=2`, `len=2`, `replayed()=2`, слот A тот же, членство эпохи 1 с диска; `lease=None`, `lease_active(4)=false`, `serving_epoch(4)=None`; Find A — `MatchResult{epoch:1, matches:1}`, без pull/`ReplicateOp`/снапшота |
| (2) | `P.tick(4)` — ровно 2 `LeaseGrant{epoch:1, primary:P, expires_at_bucket:10}`, без `MembershipUpdate`; у H `lease{1,P,10}`, `serving_epoch(4)=Some(1)`; Publish C (bucket 4) — 2 `ReplicateOp`, ровно один `PublishAck{OK, epoch:1, seq:3}`; у всех `applied_seq=3`, `len=3`, слот C тот же |
| (3) | P закрыт и открыт: `applied_seq=3`, `len=3`, `replayed()=3`, членство эпохи 1; `lease=None`, `serving_epoch(4)=None`. Publish D (bucket 4) — ровно один `Error{EPOCH_STALE}`, без `ReplicateOp`/`PublishAck`, WAL не тронут. Find A — 1 match, Find D — 0: чтение переживает потерю lease |
| (4) | `P.tick(4)` — 2 `MembershipUpdate{epoch:2}`, в черновике ровно 1 подпись (P), без grant/op; прокачка ≤20 раундов — у всех `epoch()=2`, состав = `candidates::members(2, …)`, primary = `members[0]`, `lease{2,primary,10}`, `store.serving_epoch()=2`, `serving_epoch(4)=Some(2)`, `applied_seq=3` (adopt не пишет WAL). Publish D (bucket 5) — 2 `ReplicateOp`, один `PublishAck{OK, epoch:2, seq:4}`; у всех `applied_seq=4`, `len=4`, D виден с одним слотом |
| (5) | E (ttl 1, bucket 5) — seq 5, при `time_mark=0` видна у всех. `tick(6)` — ровно 2 `ReplicateOp{GcTick, seq:6}` + acks; у всех `applied_seq=6`, `time_mark_bucket=6`, `len=4`, E не находится, A находится |
| (6) | `flush_snapshot` — MANIFEST `{snapshot_seq:6, applied_seq:6, oldest_wal_needed:1, time_mark_bucket:6}`; на диске `snap.6.log`, `membership.00000000000000000001.log`, `membership.00000000000000000002.log`. Reopen: `replayed()=0` (WAL не переигран), `applied_seq=6`, `len=4`, mark 6, членство эпохи 2, `lease=None`, `serving_epoch(6)=None`; A видна, E нет; при `Clock` бакета 1000 — по-прежнему A 1 / E 0 |
| (7) | `Fault::SnapshotMid` → `flush_snapshot` вернул `Err`, `snap.6.partial` оставлен, `snap.6.log` цел, MANIFEST не сдвинулся (6). Reopen не падает: `replayed()=0`, `applied_seq=6`, `len=4`, A 1 / E 0 |
| (8) | Инвентарь: `GROUP_COMMIT_MS` — только `wal.rs:30`, реэкспорт `lib.rs:47`, тест `lib.rs:163–164`; таймера нет. `should_group_commit` — `store.rs:367`, юнит-тест `store.rs:667` и bench `benches/src/bench/index.rs:188`; в publish-пути узла вызовов нет. Publish узла: `handle_publish` → `stage_insert` (134) → `commit` (150) на каждый опс, то есть fsync на опс. `SystemTime`/`Instant` в `index`/`node` отсутствуют. `git diff HEAD --stat -- crates/vecdht-wire` пуст. `crash_matrix.rs` — 11 `#[test]` (точки 1–10 + property). `#[ignore]`: P5-гейт, `future_epoch_lease_freeze` (E-0067), `heal_demotion_window` (E-0069); `E-0070` активен — поправка к формулировке пре-регистрации |

Фальсификаторы (а)…(н) молчат: H не потерял записи и членство; до гранта H не обслуживал
эпоху и не писал; P без lease отказал именно `EPOCH_STALE`; черновик эпохи 2 нёс одну
подпись и разошёлся двумя конвертами; состав сошёлся с кандидатами; W=2 после
восстановления собрался; GC записал `GcTick` и не тронул A; reopen после снапшота не
переиграл WAL; partial не изменил состояние; TTL не отреагировал на `Clock 1000`;
wire не менялся; ни один `on_frame`/`tick` не вернул `Err`; группового коммита в
publish-пути не оказалось.

## Вердикт

`supports`. §10 в композиции с §9.8 и §9.4 работает: рестарт реплики поднимает WAL и
цепочку членства с диска (`replayed=2`), но **не** lease — чтение продолжается, запись
невозможна (`EPOCH_STALE`), и вернуть её может только новая эпоха. Рестарт primary
(`replayed=3`) не даёт «сам себе lease»: продление `tick(4)` выдаёт гранты репликам и
возвращает W=2, а принятая эпоха 2 восстанавливает право писать у её primary. Снапшот-барьер переживает reopen без переигрывания WAL (`replayed=0`),
восстанавливает `applied_seq`, `len` и `time_mark_bucket`; partial-снапшот (точка 3 §10.5)
на уровне узла не ломает open. TTL после рестарта решает применённый mark, а не часы:
`Clock 1000` не меняет ответ.

Находка вне порогов восстановления, зафиксированная инвентарём: **§10.2 обещает групповой
коммит** (`GROUP_COMMIT_MS = 5`, `GROUP_COMMIT_MAX = 32`, «~10× меньше syscall»), но в
publish-пути узла его нет: `handle_publish` делает `stage_insert` → `commit` на каждый опс,
`GROUP_COMMIT_MS` не читается нигде, а `should_group_commit` (порог по числу staged)
живёт только в store, юнит-тесте и bench — в пути узла его нет. `ShardStore::commit` умеет
сгруппировать всё staged в один fsync, но путь узла до него не доводит. Это не риск корректности — код
строже по durability и не медленнее по ACK, — а **недоставленная оптимизация**:
обещанного сокращения syscall нет. Восьмая спека-фикция семейства, вынесена в
`OPEN-QUESTIONS` (п. 8) с вариантами «подключить таймер», «убрать обещание», «оставить
как задел».

Границы: один шард, R=3, ручная доставка, один процесс и один хост; снапшот вручную на
6 опсах, а не порогом `SNAPSHOT_OPS=50_000`; ротация сегментов (64 МБ / 100 000 опсов)
не участвовала, удаление сегментов и `fsync` каталога не проверялись; точки 1–10
crash-матрицы остаются юнит-тестами `crash_matrix.rs`; ENOSPC, падение посреди MANIFEST,
несколько снапшотов подряд, libp2p-транспорт и возврат исключённого узла — вне замера.

## Что это не доказывает

Что групповой коммит не нужен под нагрузкой: цена fsync на опс (1–3 мс NVMe) и выигрыш
~10× не мерились, инвентарь говорит только об отсутствии пути. Что снапшот под
`SNAPSHOT_OPS` ведёт себя как ручной `flush_snapshot`. Что восстановление переживёт
несколько одновременных отставших реплик, `WalGap` после потери нескольких опсов подряд
и рестарт с `epoch < max_epoch_served` (это юнит-тест точки 10, не лабораторный замер).
Что read-repair, отсутствие которого показал `E-0072`, как-то связан с рестартом: здесь
чтение после рестарта тоже не ремонтирует, но это следствие того же разрыва §9.4, а не
новый факт.
