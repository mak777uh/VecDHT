---
id: E-0068
hypothesis: H-0068
status: completed
base_commit: "e7ffd50"
started: "2026-10-22T20:02:46+03:00"
finished: "2026-10-22T20:05:28+03:00"
environment: "Windows; MinGW gcc 16.2.0; rustc 1.99.1 (58cf8f9c3 2026-10-13); debug; RAYON_NUM_THREADS=2; один прогон, один процесс"
command: "bash lab/e0068-run.sh"
threshold: "H-0068 (0)…(5): база W=2; future-грант отвергнут без заморозки; publish после него OK; same-epoch грант члена-не-primary не меняет lease и не гасит продление; ротация [Q,R] принимает эпоху 2 и её грант, P — future; новая эпоха пишет OK{2,3}"
result: "1 passed; 0 failed; 0.52 s; пороги (0)…(5) совпали, фальсификаторы (а)…(ж) молчат; КОНТРОЛЬ -p vecdht-node 130 ok, EXIT=0; верификация воркспейса 574 ok, TEST_EXIT=0, CLIPPY_EXIT=0; аномалий и отброшенных прогонов нет"
verdict: supports
---

## Pre-registration (до прогона)

Вопрос: закрывает ли `ADR-0016` veto-дыру `E-0067` и не ломает ли легитимную ротацию?
Решение принято в `lab/decisions/ADR-0016-lease-membership-binding.md`, правка §9.8 и зеркала
(`TEXT_SYNC_OK`) — в коммите пре-регистрации `e7ffd50`; пороги (0)…(5) и фальсификаторы
(а)…(ж) заморожены в `H-0068` до первого замера.

Код фикса: `Lease::verify` отвергает `g.epoch != have` (`Stale`/новый `Future`);
`handle_lease_grant` принимает только грант от primary принятого состава, иначе молчит.
Оракул `crates/vecdht-node/tests/lease_membership_binding.rs` — три независимых `ShardNode`,
ручная доставка конвертов; исторический оракул `E-0067` помечен `#[ignore]` как замер
поведения до фикса.

Входы: шард 7, кластер 112, сиды [1,2,3], PoW 8 бит (`testing::params`), TTL 225, lease
6 бакетов / renew 2, W=2, R=3; attacker — seed 77, агенты A=60, B=61, C=88; время —
`testing::clock`, без `sleep`.

## Прогон

`bash lab/e0068-run.sh`, лог `lab/logs/e0068-all.log` (append-only):

* BUILD `--no-run` — EXIT=0;
* RUN `--nocapture` — `1 passed; 0 failed; 0 ignored` за 0.52 с, EXIT=0;
* ИНВЕНТАРЬ — grep по `LeaseError::Future`, `mine != Some(lease.primary)` в
  `handle_lease_grant`, `#[ignore]` исторического оракула, юнит-тесту `Future`, строке §9.8;
* КОНТРОЛЬ `-p vecdht-node` — 130 ok, 0 failed, EXIT=0 (129 в блоке `E-0067`, минус
  исторический оракул в `#[ignore]`, плюс юнит `Future` и интеграционный оракул);
* ВЕРИФИКАЦИЯ — `bash lab/workspace-verify.sh E-0068` (фон, 80 бинарей): **574 ok,
  `TEST_EXIT=0`, `CLIPPY_EXIT=0`** (20:05:38…20:17:20), блок `E-0068 · workspace-verify`.

Один прогон, без повторов и отброшенных запусков; промахов заморозки не было.

## Результат

| Порог | Что наблюдалось |
|---|---|
| (0) | База W=2: Publish A (agent 60, epoch 1, бакет 1) → 2 `ReplicateOp`, ack → один `PublishAck{OK, epoch:1, seq:1}`; `applied_seq` 1/1/1 |
| (1) | Future-грант `{epoch:1000, expires:u32::MAX}` от seed 77 каждому → ровно один `EPOCH_STALE` на узел; `epoch()=1`, `lease_active(2)`, `serving_epoch(2)=Some(1)`, `lease.primary=P`, `applied_seq=1` |
| (2) | Publish B → 2 `ReplicateOp`, ack → `OK{epoch:1, seq:2}`; `applied_seq` 2/2/2, владелец B есть у всех — заморозки нет |
| (3) | Грант `{epoch:1, primary:Q, expires:u32::MAX}` от Q → пустой ответ у P и R; `lease.primary=P`, `expires=6`; `tick(4)` → ровно 2 `LeaseGrant{epoch:1, primary=P}`, реплики приняли молча; `serving_epoch(4)=Some(1)` |
| (4) | Q,R `peer_lost(P)` + подписанная эпоха 2 → `epoch()=2`, `store.serving_epoch()=2`, `serving_epoch(4)=Some(2)`, `lease{epoch:2, primary:members[0]}`; P — `epoch()=1`, `serving_epoch(4)=Some(1)`. Легитимный грант эпохи 2: реплика приняла молча, P — ровно `EPOCH_STALE`, без смены epoch/lease |
| (5) | Publish C на primary эпохи 2 → ровно 1 `ReplicateOp`, ack → `OK{epoch:2, seq:3}`; `applied_seq` Q/R=3, P=2; владелец C есть у Q/R, у P — нет |

Фальсификаторы (а)…(ж) не сработали: future-грант отвергнут и не заморозил; publish после
него собрал W=2; same-epoch грант члена-не-primary не подменил `lease.primary`/`expires` и не
погасил продление; ротация принята; P не принял грант эпохи 2 без членства; новая эпоха
пишет W=2; ни один `on_frame`/`tick` не вернул `Err`.

## Вердикт

`supports`: `ADR-0016` закрывает veto-дыру `E-0067` в обе стороны — future-грант от не-члена
и подмена `expires`/`primary` грантом члена-не-primary больше ничего не меняют. Легитимная
ротация не ломается: lease новой эпохи выдаёт `adopt` при принятии цепочки, поэтому грант —
только продление текущей эпохи. Демоция старого primary идёт через принятие членства, что
совпадает с новой формулировкой §9.8.

## Что это не доказывает

Heal не мерялся: порог (4) показывает лишь, что P не принимает эпоху 2 из гранта; каким
событием он примет подписанную цепочку при расходящемся live-roster — открытый вопрос
(`H-0069`). WAL-догон, реальная сеть, handshake §5.3, рестарт, несколько шардов, PoW 24 бита
не мерялись. Один прогон, один процесс.
