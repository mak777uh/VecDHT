---
id: H-0073
title: Рестарт узла — что переживает WAL, снапшот и GC, и что теряется с lease
status: preregistered
date: 2026-10-22
relates: [E-0072, H-0072, ADR-0017, E-0070, H-0070]
---

## Вопрос

§10 спеки обещает порядок `op → WAL → fsync → память → ответ`, барьер снапшота
`partial → fsync → rename → fsync каталога → MANIFEST → удаление сегментов` и
восстановление `MANIFEST → снапшот → хвост WAL`. Crash-матрица §10.5 (точки 1–10 плюс
property `recover(disk) == replay(all ops)`) уже измерена **юнит-тестами**
`crates/vecdht-index/tests/crash_matrix.rs` на уровне `ShardStore`. Лабораторно §10 не
мерился ни разу: карта `PLAN.md` держит строку «§10 — не измерено».

Вопрос: что переживает **рестарт узла** как целого — не только store, но и членство,
lease и право писать; как восстановление складывается с §9.8 (lease в RAM, маркер на
диске) и §9.4 (W=2); действительно ли срок жизни записи на восстановлении определяется
`TimeMark`/`GcTick`, а не часами; и не обещает ли §10.2 групповой коммит, которого в
publish-пути нет.

## Разведка (до пре-регистрации)

* `ShardNode::open` → `ShardStore::open` (MANIFEST → снапшот → хвост WAL, обрезка torn
  tail) + `load_chain` (перечитывает `membership.<epoch>.log` и заново валидирует всю
  цепочку; первый файл обязан быть genesis — так и есть, genesis персистится `adopt`).
* Lease не персистится: после reopen `lease = None`, `lease_active=false`,
  `serving_epoch(now)=None`. Чтение идёт (`handle_find` lease не требует), запись — нет
  (`handle_publish` → `EPOCH_STALE`). Вернуть право писать может только новая эпоха:
  `tick` при `lease=None` зовёт `propose_next` (ранг 0 в `speaker_order(epoch+1)`), и
  `adopt` выдаёт каждому `Lease::grant(epoch, primary, now, 6)` + `grant_epoch` (маркер).
* `GROUP_COMMIT_MS` встречается только в определении, реэкспорте и тесте константы;
  `should_group_commit` — только в bench и юнит-тесте store. Путь publish делает
  `stage_insert` → `commit` (fsync) на каждый опс; таймера группового коммита нет.
* `SystemTime`/`Instant` в `vecdht-index`/`vecdht-node` отсутствуют (только комментарий
  в `config.rs`); поиск и GC смотрят на применённый `time_mark_bucket`.

## Замороженные пороги (до первого прогона)

Оракул `crates/vecdht-node/tests/restart_recovery.rs`, ручная доставка, один процесс.
Шард 7, тройка сидов выбирается детерминированно из 1..=16 так, чтобы primary эпохи 1
был **первым в `speaker_order(2)`** (иначе рестарт-primary не успеет предложить эпоху
до истечения чужих lease). PoW 8, TTL 225 (E — ttl 1), lease 6 / renew 2 / election 4,
W=2, R=3, `membership_threshold=2`. P — primary эпохи 1, H и S — реплики.

| # | Предсказание |
|---|---|
| (0) | База: A (bucket 1) и B (bucket 1) опубликованы через P, W=2 собрался на H; оба `ReplicateOp` доставлены H и S. У всех: `applied_seq=2`, `len=2`, слоты A/B совпадают; `epoch()=1`, `lease{1,P,6}`, `serving_epoch(2)=Some(1)`; `last_snapshot_seq=0`, `replayed=0` |
| (1) | Рестарт реплики: H закрыт и открыт заново по тому же каталогу. `applied_seq=2`, `len=2`, `replayed=2`, слот A тот же; членство эпохи 1 поднято с диска; `lease=None`, `lease_active(4)=false`, `serving_epoch(4)=None`. `Find A` → один `MatchResult{epoch:1, matches:1}`; Find не порождает ни pull, ни `ReplicateOp` |
| (2) | Грант и W=2 после рестарта: `P.tick(4)` → ровно 2 `LeaseGrant{epoch:1, primary:P, expires_at_bucket:10}` (lease P продлён с 6 до 10), без `MembershipUpdate`; доставка H и S → у H `lease{1,P,10}`, `serving_epoch(4)=Some(1)`. Publish C (epoch 1, bucket 4) → ровно 2 `ReplicateOp`, доставка обеим; acks H,S → ровно один `PublishAck{OK, epoch:1, seq:3}`; у всех `applied_seq=3`, `len=3`, слот C тот же |
| (3) | Рестарт primary: P закрыт и открыт. `applied_seq=3`, `len=3`, `replayed=3`, членство эпохи 1; `lease=None`, `lease_active(4)=false`, `serving_epoch(4)=None`. Publish D (epoch 1, bucket 4) → ровно один `Error{EPOCH_STALE}`, без `ReplicateOp`/`PublishAck`, `applied_seq=3`. `Find A` → 1 match (чтение переживает потерю lease), `Find D` → 0 |
| (4) | Эпоха после рестарта: `P.tick(4)` → ровно 2 `MembershipUpdate{epoch:2}`, в черновике ровно 1 подпись (P), без `LeaseGrant`/`ReplicateOp`. Прокачка до неподвижной точки (≤20 раундов) → у всех трёх `epoch()=2`, состав равен `candidates::members(2, shard, holders, r, entries=3)`, primary — `members[0]`, `lease{2,primary,10}`, `store.serving_epoch()=2`, `serving_epoch(4)=Some(2)`, `applied_seq=3`. Publish D (epoch 2, bucket 5) → 2 `ReplicateOp`, ровно один `PublishAck{OK, epoch:2, seq:4}`; у всех `applied_seq=4`, `len=4`, D находится с одним и тем же слотом |
| (5) | GC без wall-clock: тот же primary публикует E (ttl 1, bucket 5) → `applied_seq=5`; `Find E` при `time_mark=0` → 1 match. `primary.tick(6)` → ровно 2 `ReplicateOp{op_kind:GcTick, seq:6}`, без `MembershipUpdate`/`LeaseGrant`; доставка → у всех `applied_seq=6`, `time_mark_bucket=6`, `len=4`. `Find E` → 0, `Find A` → 1 на всех трёх |
| (6) | Снапшот и reopen: `flush_snapshot` на primary → MANIFEST `{snapshot_seq:6, applied_seq:6, oldest_wal_needed:1, time_mark_bucket:6}`, `snap.6.log` существует. Reopen primary → `replayed()=0` (WAL не переигран), `applied_seq=6`, `len=4`, `time_mark_bucket=6`; членство эпохи 2 с диска; `lease=None`, `serving_epoch(6)=None`. `Find A` → 1, `Find E` → 0; `Find A` с `Clock` бакета 1000 → по-прежнему 1, `Find E` → 0 (TTL решает применённый mark, не часы) |
| (7) | Partial-снапшот: `fault=SnapshotMid`, `flush_snapshot` → `Err`, `snap.6.partial` существует, `snap.6.log` цел, MANIFEST не изменился (всё ещё 6). Reopen → open не падает, `replayed()=0`, `applied_seq=6`, `len=4`, `Find A` → 1, `Find E` → 0 |
| (8) | Инвентарь: группового коммита в publish-пути нет (`GROUP_COMMIT_MS` — только определение/реэкспорт/тест; `should_group_commit` — только bench и юнит-тест; publish делает stage→commit на опс); `SystemTime`/`Instant` в `vecdht-index`/`vecdht-node` отсутствуют; `git diff HEAD --stat -- crates/vecdht-wire` пуст; на диске `membership.1.log`, `membership.2.log`, `snap.6.log`, `snap.6.partial`; `E-0069`/`E-0070` остаются историческими `#[ignore]` |

## Фальсификаторы

- (а) H после рестарта теряет записи/слоты или членство (не эпоха 1) — порог (1) падает;
- (б) H до гранта отдаёт `serving_epoch(4)=Some(..)` или принимает запись — гейт §9.8 ослаблен, (1)/(2) падают;
- (в) P после рестарта выдаёт `PublishAck`/`ReplicateOp` без lease или отказ не `EPOCH_STALE` — (3) падает;
- (г) `P.tick(4)` не рождает черновик эпохи 2, рождает не 2 конверта или черновик с чужими подписями — (4) падает;
- (д) после прокачки состав/primary расходятся с кандидатами или не все на эпохе 2 — (4) падает;
- (е) D не собирает W=2 после восстановления или его слот расходится между узлами — (4) падает;
- (ж) GC не пишет `GcTick`, E видна после mark=6 или A исчезает — (5) падает;
- (и) reopen после снапшота переигрывает WAL (`replayed>0`) или теряет запись — (6) падает;
- (к) partial-снапшот ломает open или меняет `applied_seq`/`len` — (7) падает;
- (л) срок жизни A зависит от часов (`Find` при бакете 1000 теряет A) — (6) падает;
- (м) в wire появился новый `Kind`/поле или любой `on_frame` вернул `Err` — замер недействителен;
- (н) групповой коммит в publish-пути всё-таки есть — инвентарь (8) опровергает находку.

## Что это не доказывает

Один шард, R=3, ручная доставка, один процесс и один хост. Снапшот делается вручную на
6 опсах, а не порогом `SNAPSHOT_OPS=50_000`; ротация сегментов (64 МБ / 100 000 опсов)
не участвует, поэтому `oldest_wal_needed=1` и удаление сегментов не проверяется.
Точки crash-матрицы 1–10 остаются юнит-тестами `crash_matrix.rs` и здесь не
перемеряются: лабораторный вопрос — композиция store-восстановления с членством, lease
и W=2. ENOSPC, падение посреди MANIFEST, несколько снапшотов подряд, libp2p-транспорт,
рестарт с `epoch < max_epoch_served` (юнит-тест точки 10), возврат узла в состав после
исключения — вне замера.

## Вердикт

Ожидает прогона.
