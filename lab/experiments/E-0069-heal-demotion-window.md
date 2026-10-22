---
id: E-0069
hypothesis: H-0069
status: completed
base_commit: "4a6342e"
started: "2026-10-22T20:23:35+03:00"
finished: "2026-10-22T20:28:13+03:00"
environment: "Windows; MinGW gcc 16.2.0; rustc 1.99.1 (58cf8f9c3 2026-10-13); debug; RAYON_NUM_THREADS=2; один процесс, три трио"
command: "bash lab/e0069-run.sh"
threshold: "H-0069 (0)…(5): база A с раздельными P и Q/R; frame2 до lease — молчание, после expires — adopt; B с peer_lost у P — вечный epoch1 и пустая эпоха 2 из tick(6); C — ни одного кадра к P; (5) — инвентарь путей очистки unreachable"
result: "1 passed; 0 failed; 1.41 s; пороги (0)…(4) совпали, (5) подтверждён инвентарём; КОНТРОЛЬ -p vecdht-node 131 ok, EXIT=0; первый прогон — промах композиции порога (0), ДИАГНОЗ и поправка №1 (ee6ba8e) до второго замера; верификация воркспейса 575 ok, 82 бинаря, TEST_EXIT=0, CLIPPY_EXIT=0"
verdict: supports
---

## Pre-registration (до прогона)

Вопрос: выполняется ли обещание §9.8 «старые primary после resurrect демотируются сами,
когда принимают подписанную цепочку `ShardMembership` с большим epoch» — и при каких
событиях цепочка до узла вообще доходит?

Код на этом пути: `handle_membership` сверяет состав через `validate_with_candidates` против
**локального** `live_roster(now)` (`candidates::members(epoch, shard, roster, R, entries)`);
несовпадение даёт `MembersOutOfOrder`, погашенный молча (`Err(_) => Ok(Vec::new())`).
`unreachable` пополняется `peer_lost` и чистится только в `adopt` для членов принятой эпохи;
`peer_alive` в коде нет. `MembershipUpdate` рассылается из `propose_next`/`adopt` (и
ретранслируется ниже-пороговый черновик); вида «дай цепочку» нет.

Пороги (0)…(5) и фальсификаторы (а)…(з) заморожены в `H-0069` до первого прогона; поправка
№1 (после промаха композиции) — там же, пороги (1)…(5) не менялись.

Входы: шард 7, сиды [1,2,3], PoW 8, TTL 225, lease 6 / renew 2 / election 4, W=2, R=3;
три независимых трио A, B, C; эпоха 2 собирается двумя подписями эпохи 1 (Q,R).

## Прогон

`bash lab/e0069-run.sh`, лог `lab/logs/e0069-all.log` (append-only):

* первый прогон (20:23:35) — BUILD EXIT=0, RUN **EXIT=101**: порог (0) упал на композиции
  проверки (предикат `serving_epoch(4)=Some(1)` применён ко всем сидам, а Q,R уже на эпохе 2);
  ДИАГНОЗ дописан в лог, поправка №1 — в гипотезу, коммит `ee6ba8e` до второго замера;
* второй прогон (20:25:59) — BUILD EXIT=0, RUN `1 passed; 0 failed` за 1.41 с, EXIT=0;
* КОНТРОЛЬ `-p vecdht-node` — 131 ok, 0 failed, EXIT=0 (130 в блоке `E-0068` + оракул;
  два ignored — P5-гейт и исторический `E-0067`);
* ИНВЕНТАРЬ — `peer_alive`/`peer_reachable` не найдены; `unreachable` пишется в
  `peer_lost` и чистится только в `adopt`; `handle_membership` гасит `Err(_)`; ожидание
  состава — по `live_roster(now)`; `MembershipUpdate` рассылается из `propose_next`,
  `adopt` и ниже-порогового ретранслятора; строка §9.8 о resurrect на месте;
* ВЕРИФИКАЦИЯ — `bash lab/workspace-verify.sh E-0069` (20:28:25…20:39:11, 82 бинаря):
  **575 ok, `TEST_EXIT=0`, `CLIPPY_EXIT=0`**.

## Результат

| Порог | Что наблюдалось |
|---|---|
| (0) | P: `epoch()=1`, `serving_epoch(4)=Some(1)`, `lease{1,P,6}`, состав `[P,Q,R]`, applied 1; Q,R: `epoch()=2`, `serving_epoch(4)=Some(2)`, `lease{2,new_primary}`, applied 1 |
| (1) | `frame2` P на бакетах 4 и 5 → пустой ответ оба раза; `epoch()=1`, `serving_epoch(5)=Some(1)`, lease и состав не изменились: ожидание по `[P,Q,R]` — три члена против двух, `MembersOutOfOrder` погашен молча |
| (2) | `frame2` на бакете 6 → adopt: `epoch()=2`, `store.serving_epoch()=2`, `serving_epoch(6)=Some(2)`, состав `[Q,R]` без P, `is_member()=false`, `is_primary()=false`, `lease{2,new_primary}`; ответ ровно 2 `MembershipUpdate` (Q,R) + 1 `WalPullRequest` (new_primary); Publish на P → `NOT_OWNER`, applied 1 |
| (3) | B: P получил `peer_lost(Q)`/`peer_lost(R)`; `frame2` на 6 и 100 → пусто, `epoch()=1`, `serving_epoch` None; `tick(6)` → 2 `MembershipUpdate{epoch:2, members:[]}` (одна подпись, порога нет), `tick(100)` пуст; Publish на 100 → `EPOCH_STALE`; `unreachable` Q,R не снят |
| (4) | C: `tick` Q/R на 6, 8, 10, 11 → ни одного конверта к P; P остался `epoch()=1`, `serving_epoch(11)=None`, Publish → `EPOCH_STALE`; пересылать цепочку некому |
| (5) | Инвентарь подтвердил: `peer_alive` нет; `unreachable` чистится только в `adopt`; запроса цепочки нет; `MembershipUpdate` — только `propose_next`/`adopt`/ниже-пороговый ретранслятор |

Фальсификаторы (а)…(и) молчат: приёма на 4/5 нет, на 6 — есть; в B приёма нет ни на одной
доставке; форма `tick(6)` — пустая эпоха 2; в C кадров к P нет; путь очистки `unreachable`
вне `adopt` не найден; ответ на Publish — `NOT_OWNER`; ни один `on_frame`/`tick` не вернул `Err`.

## Вердикт

`supports`: обещание §9.8 выполняется, но только в узком окне. Если старый primary **не видел**
обрыва и цепочку ему доставили на бакете не раньше истечения его собственного lease, он
принимает эпоху 2 и демотируется (порог (2)). До этого момента приём молчаливый: локальный
`live_roster` ещё включает его самого, и детерминированное ожидание не совпадает с составом
цепочки (порог (1)). Если primary сам получил `peer_lost` на членов новой эпохи, он не может
принять цепочку никогда: `unreachable` чистится только в `adopt`, а `peer_alive` нет (порог (3)).
Если цепочку ему не переслали — пересылать некому: membership anti-entropy отсутствует, тики
живых членов адресованы только составу эпохи 2 (порог (4)). То есть «демотируются сами» верно
для механики принятия, но путь доставки цепочки после heal и снятие `unreachable` в §9.8 не
названы; это кандидат на ADR (механизм heal), а не на молчаливую правку.

## Что это не доказывает

Реальный транспорт и переподключение libp2p не участвуют: всё — ручная доставка, три `ShardNode`
в одном процессе; «повторная доставка после heal» моделируется внешним вызовом `on_frame`.
WAL-догон после adopt не меряется: проверен только факт `WalPullRequest`. Несколько ротаций
подряд, R<3, PoW 24 бита, рестарт, реальные часы — вне замера. Один процесс, один прогон
(первый — промах композиции, исправлен поправкой №1).
