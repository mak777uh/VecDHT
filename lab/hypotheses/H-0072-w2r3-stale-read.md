---
id: H-0072
title: Read у любой реплики — расхождение видно, read-repair нет, латает смена эпизоды
status: supported
date: 2026-10-22
relates: [H-0070, E-0070, ADR-0017]
---

## Вопрос

§9.4 обещает три вещи сразу: W=2 из R=3, read у любой живой реплики и «расхождения латаются
read-repair'ом при запросе и anti-entropy при смене эпизоды». W=2 измерен (`H-0070`/`E-0070`
базой), а два механизма латания — нет: в `handle_find` нет ни одного вызова `pull_request`
или `replicate`, `heard_wal_seq`/gossip-триггера догона в коде нет, и `pull_request`
вызывается только из `adopt` и продолжений pull/снапшота.

Вопрос: что именно видит читатель, когда вторая реплика W=2 не получила запись; латается ли
расхождение при чтении; и если нет — закрывает ли его смена эпизоды, то есть остаётся ли
«read у любого» корректным обещанием при слабой консистентности, а не тихой выдачей старой
версии навсегда.

## Замороженные пороги (до первого прогона)

Оракул `crates/vecdht-node/tests/w2r3_stale_read.rs`, ручная доставка, один процесс; шард 7,
сиды [1,2,3], PoW 8, TTL 225, lease 6, renew 2, election 4, W=2, R=3,
`membership_threshold=2`, `time_mark_every=512`.

Роли: `P` — primary эпохи 1 (первый в `candidates::ordered(1, …)`); `H` — та из двух оставшихся
реплик, чей ключ первым идёт в порядке эпохи 2 `[H,S]` (новый primary), `S` — вторая, отставшая.
База: Publish A на бакете 1; P выдаёт 2 `ReplicateOp` (H и S), но доставляется только H;
H отвечает `ReplicateAck`, P отправляет агенту ровно один `PublishAck{OK, epoch:1, seq:1}`.
S не получает ни кадра записи.

| # | Предсказание |
|---|---|
| (0) | **W=2, а не R=3:** P и H — `applied_seq=1`, `len=1`, `owner_slot(A)=Some`; S — `applied_seq=0`, `len=0`, `owner_slot(A)=None`; у S при этом `epoch()=1`, `lease{1,P,6}`, `serving_epoch(2)=Some(1)` — читать он готов, данных нет; ровно один `PublishAck{OK,1,1,slot}` |
| (1) | **Расхождение видно читателю:** Find A на H (бакет 2) → ровно 1 `MatchResult{epoch:1, responder:H, matches.len()=1}` (+ приёмы `RendezvousAccept` на найденное); Find A на S → ровно 1 `MatchResult{epoch:1, responder:S, matches.len()=0}`, и в ответе S **нет** ни `WalPullRequest`, ни `ReplicateOp`, ни `SnapshotOffer`; после Find S — `applied_seq=0`, `len=0` (read-repair не случился) |
| (2) | **Тишина не лечит:** `H.tick(2)`, `H.tick(3)`, `S.tick(2)`, `S.tick(3)`, `P.tick(2)`, `P.tick(3)` — пусты; `P.tick(4)` — ровно 2 `LeaseGrant` (H,S), epoch 1, и ни одного `ReplicateOp`/`WalPullRequest`; S по-прежнему `applied_seq=0`, `len=0` (продление lease не догоняет данные) |
| (3) | **Смена эпизоды латает:** H и S получают `peer_lost(P)` на 4; кадр epoch 2 `[H,S]` с подписями H,S (индексы эпохи 1) доставлен S от H → у S ровно 2 конверта: 1 `MembershipUpdate`→H + 1 `WalPullRequest`→H (`from_seq=0`, адресат — primary эпохи 2); S — `epoch()=2`, `serving_epoch(4)=Some(2)`, `lease{2,H}`, `applied_seq=0`. Кадр S→H даёт H ровно 2 конверта: `MembershipUpdate` epoch 2 + `LeaseGrant` epoch 2 от H, оба S, без pull (H — primary); H — `applied_seq=1`. Доставка этих двух S — пусто (равная эпоха молчит, lease принят). `WalPullRequest` S→H → ровно 1 `WalPullResponse` S `{primary_epoch:2, from_seq:0, to_seq:1, frames непусты}`; доставка S → пусто; S — `applied_seq=1`, `len=1`, `owner_slot(A)` совпадает с H |
| (4) | **После heal чтения сходятся:** Find A на S (бакет 5) и на H (бакет 5) → по одному `MatchResult{epoch:2, matches.len()=1}` с тем же owner и slot; расхождение (1) закрыто сменой эпизоды, а не чтением |
| (5) | **Кворум не собран — обещания нет:** отдельное трио; Publish B на бакете 1, оба `ReplicateOp` выброшены → ровно 2 `ReplicateOp`, `PublishAck` нет; P — `applied_seq=1`, `len=1`; H и S — `applied_seq=0`, `len=0`; Find B на P → 1 match (запись видна локально), на H → 0; `P.tick(2)`/`tick(3)` пусты, `P.tick(4)` — ровно 2 `LeaseGrant` и ни одного `ReplicateOp`; `applied_seq` P остаётся 1 (повтора записи нет) |
| (6) | **Инвентарь:** в `handle_find` нет `pull_request`/`replicate`/ремонта; `pull_request` вызывается только из `adopt`, `handle_pull_response`, `handle_snapshot_offer`, `install_snapshot`; `heard_wal_seq` в коде отсутствует; wire не тронут (`git diff` по `crates/vecdht-wire` пуст); строка §9.4 про read-repair остаётся обещанием без кода — это фиксируется как разрыв спека↔код, а не как провал порога |

## Фальсификаторы

- (а) Find на S вернул запись — порог (1) падает (опс всё-таки дошёл или ремонт есть);
- (б) Find на S породил `WalPullRequest`/`ReplicateOp`/`SnapshotOffer` — порог (1) падает;
- (в) `tick` изменил `S.applied_seq` или выдал ремонтный кадр — порог (2) падает;
- (г) смена эпохи не дала ровно один pull к новому primary — порог (3) падает;
- (д) pull не применил запись (S `applied_seq≠1` или `len≠1`) — порог (3) падает;
- (е) после heal чтения S и H расходятся — порог (4) падает;
- (ж) Publish без второго держателя дал `PublishAck` или потерял локальный WAL — порог (5) падает;
- (з) `tick` повторил `ReplicateOp` — порог (5) падает (это была бы репликация без ack, то есть W=1 с видом W=2);
- (и) в `handle_find` обнаружен ремонт — порог (6) падает (тогда read-repair в коде есть, и вопрос только в его наблюдаемости);
- (к) любой `on_frame`/`tick` вернул `Err` — замер недействителен.

## Что это не доказывает

libp2p-транспорт, рестарт узла и реальные часы не участвуют: доставка ручная, один процесс.
Расхождение >1 опса (несколько потерянных записей) не меряется — один WAL-фрейм. Read-repair
мог бы существовать вне `handle_find` (например, в транспорте или SDK) — инвентарь (6) смотрит
только путь узла. Снапшот-путь догона (`from_seq=0` при перекрытом WAL) не измеряется: у H нет
снапшота, поэтому ответ идёт хвостом WAL. Поведение при R<3 и при нескольких одновременных
отставших репликах — вне замера.

## Вердикт

**Подтверждена.** `E-0072`, зачётный прогон rev `47d5767`: `1 passed; 0 failed` за 0.83 с,
пороги (0)…(6) совпали с предсказанием с первого раза, поправок заморозки нет, фальсификаторы
(а)…(к) молчат. КОНТРОЛЬ `-p vecdht-node` 132 ok, EXIT=0 (131 + оракул; исторические
`E-0069`/`E-0067` и P5 — ignored). `finished` = mtime `lab/logs/e0072-all.log` 21:26:56.

Главное: read у любой реплики — обещание ответа, а не свежести. S при живом W=2 отвечает
`MatchResult{epoch:1, matches:0}`, и Find не порождает ни pull, ни `ReplicateOp`; тики и
продление lease не меняют `applied_seq`. Латает только смена эпизоды: `adopt` шлёт
`WalPullRequest` новому primary H, `WalPullResponse{primary_epoch:2, from_seq:0, to_seq:1}`
применяется, и после heal оба чтения дают `matches:1` эпохи 2. Publish без второго держателя
не даёт `PublishAck`, запись видна только у P, и `tick` её не ретраит.

Разрыв спека↔код: §9.4 обещает read-repair при запросе, в `handle_find` его нет (инвентарь (6));
вопрос вынесен в `OPEN-QUESTIONS` п. 7. Границы: один потерянный опс; снапшот-путь догона,
R<3, рестарт и libp2p — вне замера.
