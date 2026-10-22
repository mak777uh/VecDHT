---
id: E-0072
hypothesis: H-0072
status: completed
base_commit: "47d5767"
started: "2026-10-22T21:23:57+03:00"
finished: "2026-10-22T21:26:56+03:00"
environment: "Windows; MinGW gcc 16.2.0; rustc 1.99.1 (58cf8f9c3 2026-10-13); debug; RAYON_NUM_THREADS=2; один процесс, трио A (W=2 + heal) и трио B (кворум не собран)"
command: "bash lab/e0072-run.sh"
threshold: "H-0072 (0)…(6): W=2 держит primary+одна реплика; Find у отставшей видит 0 совпадений и не ремонтирует; тики/продление lease данные не догоняют; смена эпохи шлёт pull новому primary и применяет seq 1; после heal чтения сходятся; Publish без второго держателя не даёт PublishAck и не ретраится; инвентарь путей"
result: "1 passed; 0 failed; 0.83 s; пороги (0)…(6) совпали, фальсификаторы (а)…(к) молчат; КОНТРОЛЬ -p vecdht-node 132 ok, EXIT=0; верификация воркспейса 576 ok, 84 бинаря, TEST_EXIT=0, CLIPPY_EXIT=0"
verdict: supports
---

## Pre-registration (до прогона)

Вопрос: §9.4 обещает W=2 из R=3, read у любой живой реплики и «расхождения латаются
read-repair'ом при запросе и anti-entropy при смене эпизоды». W=2 уже измерен базой `E-0070`,
а два механизма латания — нет. В `handle_find` нет вызовов `pull_request`/`replicate`;
`pull_request` вызывается только из `adopt` и продолжений pull/снапшота; `heard_wal_seq` в коде
отсутствует.

Пороги (0)…(6) и фальсификаторы (а)…(к) заморожены в `H-0072` до первого прогона. Входы:
шард 7, сиды [1,2,3], PoW 8, TTL 225, lease 6 / renew 2 / election 4, W=2, R=3,
`membership_threshold=2`, `time_mark_every=512`; P — primary эпохи 1; H — реплика, чей ключ
первым идёт в составе эпохи 2 `[H,S]` (новый primary); S — отставшая. Publish A на бакете 1
доставлен P и H, но не S (W=2 закрыт).

## Прогон

`bash lab/e0072-run.sh`, лог `lab/logs/e0072-all.log` (append-only):

* BUILD `--no-run` — EXIT=0; RUN — `1 passed; 0 failed` за 0.83 с, EXIT=0 (с первого прогона,
  поправок заморозки нет);
* КОНТРОЛЬ `-p vecdht-node` — 132 ok, 0 failed, EXIT=0 (131 в блоке `E-0070` + новый оракул;
  исторические `heal_demotion_window`, `future_epoch_lease_freeze` и P5-гейт — ignored);
* ИНВЕНТАРЬ — в окне `handle_find` нет `pull_request`/`replicate(`/`SnapshotOffer`; все вызовы
  `pull_request` — `adopt` (570), продолжения pull (1244, 1249), снапшот (1283), ответ на pull
  (1320); `heard_wal_seq` отсутствует; `git diff HEAD --stat -- crates/vecdht-wire` пуст;
  строка §9.4 про read-repair на месте (996) — кода под ней нет;
* ВЕРИФИКАЦИЯ — `bash lab/workspace-verify.sh E-0072` (21:27:20…21:39:42, 84 бинаря):
  **576 ok, `TEST_EXIT=0`, `CLIPPY_EXIT=0`** (счёт E-0070: 575 ok / 83 бинаря; +1 активный
  оракул, новых `#[ignore]` нет).

## Результат

| Порог | Что наблюдалось |
|---|---|
| (0) | W=2: P и H — `applied_seq=1`, `len=1`, слот A совпадает; S — `applied_seq=0`, `len=0`, слота нет; при этом S на эпохе 1, `lease{1,P,6}`, `serving_epoch(2)=Some(1)`; ровно один `PublishAck{OK, epoch:1, seq:1}`, второго ack не потребовалось |
| (1) | Find A у H — один `MatchResult{epoch:1, matches:1}` + приём на найденное; у S — один `MatchResult{epoch:1, matches:0}` и больше ничего: ни `WalPullRequest`, ни `ReplicateOp`, ни `SnapshotOffer`; после Find S `applied_seq=0`, `len=0` — read-repair не случился |
| (2) | `tick(2)` и `tick(3)` на H, S и P пусты; `P.tick(4)` — ровно 2 `LeaseGrant` эпохи 1 (H,S), без `ReplicateOp`/pull; S по-прежнему `applied_seq=0`, `len=0`: продление lease не догоняет данные |
| (3) | `peer_lost(P)` у H и S на 4; цепочка эпохи 2 `[H,S]` (подписи H,S) доставлена S от H → ровно 2 конверта: `MembershipUpdate`→H + `WalPullRequest`→H (`from_seq=0`); S — `epoch()=2`, `serving_epoch(4)=Some(2)`, `lease{2,H}`, applied 0. Та же цепочка от S принята H → ровно 2 конверта S: `MembershipUpdate{2}` + `LeaseGrant{2,H}`, без pull (H — primary); доставка S пуста. Pull S→H → один `WalPullResponse{primary_epoch:2, from_seq:0, to_seq:1, frames≠∅}`; доставка S пуста; S — `applied_seq=1`, `len=1`, слот A тот же |
| (4) | Find A у S и H на бакете 5 — по одному `MatchResult{epoch:2, matches:1}` с тем же owner и slot; расхождение (1) закрыто сменой эпизоды, а не чтением |
| (5) | Трио B: Publish B, оба `ReplicateOp` выброшены → ровно 2 `ReplicateOp`, `PublishAck` нет; P — applied 1, len 1; H,S — applied 0, len 0; Find B у P — 1 match, у H — 0; `P.tick(2)`/`tick(3)` пусты, `tick(4)` — ровно 2 `LeaseGrant`, без `ReplicateOp`; applied P остаётся 1 |
| (6) | Инвентарь подтвердил: read-repair в пути узла отсутствует, догон — только adopt/продолжения; wire не тронут; §9.4 обещает read-repair, кода под обещанием нет |

Фальсификаторы (а)…(к) молчат: S не увидел запись при Find, Find не породил ремонт, тики и lease
не изменили `applied_seq`, смена эпизоды дала ровно один pull к новому primary и применила
запись, после heal чтения сошлись, Publish без кворума не дал OK и не ретраился, ни один
`on_frame`/`tick` не вернул `Err`.

## Вердикт

`supports`: read у любой реплики — это обещание *ответа*, а не обещание *свежести*. При живом
W=2 вторая реплика честно отвечает своей эпохой с нулём совпадений, и это видно читателю как
расхождение, а не маскируется. Латание в коде одно — anti-entropy при смене эпизоды: `adopt`
шлёт `WalPullRequest` новому primary, ответ несёт `primary_epoch` и хвост WAL, после применения
чтения сходятся. Read-repair'а при запросе в пути узла нет, хотя §9.4 его обещает; это разрыв
спека↔код (седьмая спека-фикция семейства), вынесенный в `OPEN-QUESTIONS` (п. 7).

Вторая половина §9.4 подтверждена как механизм: без второго держателя `PublishAck` не
отправляется, запись остаётся видимой только локально (P видит её при Find, H — нет), а `tick`
не ретраит `ReplicateOp` — «сам подтвердил» невозможно даже при живом lease.

Границы: один потерянный `ReplicateOp`, один шард, ручная доставка, один процесс; снапшот-путь
догона не участвовал (у H нет снапшота, ответ шёл хвостом WAL); R<3, рестарт, libp2p-транспорт
и несколько одновременных отставших реплик — вне замера.

## Что это не доказывает

Что расхождение когда-нибудь закроется без смены эпизоды: если lease продлевается, а эпоха не
меняется, отставшая реплика останется отставшей до следующего `adopt` или до TTL. Что
read-repair отсутствует и в SDK/транспорте: инвентарь смотрел только `vecdht-node`; но
единственное упоминание read-repair в репозитории — строка спеки. Что потеря нескольких опсов
подряд закроется тем же одним pull'ом: `apply_replicated` требует непрерывный `seq`, а
`WalGap`/повторные попытки не мерялись.
