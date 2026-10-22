---
id: E-0067
hypothesis: H-0067
status: completed
base_commit: "20921de"
started: "2026-10-22T19:44:04+03:00"
finished: "2026-10-22T19:46:16+03:00"
environment: "Windows; MinGW gcc 16.2.0; rustc 1.99.1 (58cf8f9c3 2026-10-13); debug; RAYON_NUM_THREADS=2; один прогон, один процесс"
command: "bash lab/e0067-run.sh"
threshold: "H-0067 (0)…(5): грант будущей эпохи принимается от не-члена; lease_active/serving_epoch падают; publish → EPOCH_STALE без WAL; tick(6)/tick(1000) пусты; при expires=10 выбор возвращается ровно на 10"
result: "1 passed; 0 failed; 0.75 s; пороги (0)…(5) совпали, фальсификаторы (а)…(и) молчат; КОНТРОЛЬ -p vecdht-node 129 ok, EXIT=0; верификация воркспейса 573 ok, TEST_EXIT=0, CLIPPY_EXIT=0; аномалий и отброшенных прогонов нет"
verdict: supports
---

## Pre-registration (до прогона)

Вопрос §9.8: что делает узел с `LeaseGrant`, у которого `epoch` **больше** принятой
эпохи членства, и привязан ли грант к составу? `Lease::verify` отвергает только
`g.epoch < have` (`lease.rs:111-115`), а `handle_lease_grant` (`node.rs:605-628`)
сверяет лишь `grant.primary_ed25519 == from == lease.primary`. Если грант будущей эпохи
от произвольного ключа принимается, `lease_active` становится ложным (эпохи не
совпадают), `serving_epoch` — `None`, publish получает `EPOCH_STALE` без WAL, а `tick`
не продлевает lease и не предлагает следующую эпоху до чужого `expires_at_bucket`.

Оракул: `crates/vecdht-node/tests/future_epoch_lease_freeze.rs` — два независимых трио
по три `ShardNode` с ручной доставкой конвертов. Трио A: базовая запись, затем грант
Attacker (seed 77, вне состава) с `epoch=1000` и `expires=u32::MAX` всем трём. Трио B:
грант с `expires=10`, тики 9 и 10. Пороги (0)…(5) и фальсификаторы (а)…(и) заморожены в
`H-0067` этим коммитом.

Порог успеха: все шесть порогов совпали, фальсификаторы молчат. Провал: любой порог не
совпал или любой `on_frame` вернул `Err` (тогда сценарий недействителен, а не «протокол
опровергнут»).

Входы: шард 7, кластер 112, три сида [1,2,3], PoW 8 бит (`testing::params`), TTL 225,
lease 6 бакетов / renew 2 / election 4, W=2, R=3. Агенты: A=seed 60 (база), B=seed 61
(запись после гранта), C=seed 88 (поздняя запись). Время — `testing::clock`, без `sleep`.
Грант собирается `Lease::signed_frame(SHARD, &attacker, vec![0xAA; 34])`; доставка — с
`from=attacker.pubkey()`.

Что **не** проверяется: транспорт и handshake §5.3, рестарт как снятие заморозки, полное
восстановление после `expires` (только первый `MembershipUpdate`), грант текущей эпохи от
произвольного ключа, реальная сеть, 24 бита PoW. См. «Границы» в `H-0067`.

## Прогон

`bash lab/e0067-run.sh`, лог `lab/logs/e0067-all.log` (append-only):

* BUILD `--no-run` — EXIT=0;
* RUN `--nocapture` — `1 passed; 0 failed; 0 ignored` за 0.75 с, EXIT=0;
* ИНВЕНТАРЬ — grep по `Lease::verify` (`if let Some(have)`), `handle_lease_grant`
  (`self.lease = Some(lease)`), `lease_active`, `should_propose` (`base` из
  `expires_at_bucket`), `tick`; список юнит-тестов `lease.rs`;
* КОНТРОЛЬ `-p vecdht-node` — 129 ok, 0 failed, EXIT=0 (128 в блоке `E-0066` + 1 новый
  оракул);
* ВЕРИФИКАЦИЯ воркспейса — блок `E-0067 · workspace-verify` (19:46:30…19:56:48):
  **573 ok, TEST_EXIT=0, CLIPPY_EXIT=0** (+1 к 572 прошлого блока; 80 тестовых бинарей).

Один прогон, без повторов и отброшенных запусков; промахов заморозки не было.

## Результат

| Порог | Что наблюдалось |
|---|---|
| (0) | У всех трёх `serving_epoch(1)=1`; P принял `Publish` A (эпоха 1, бакет 1), вернул ровно два `ReplicateOp` и ни одного `PublishAck`; после доставки опсов Q и R и их ack'ов обратно — ровно один `PublishAck{OK, epoch=1, seq=1}`; `applied_seq` P/Q/R = 1/1/1 |
| (1) | Грант `epoch=1000, expires=u32::MAX` от Attacker (seed 77, вне состава) доставлен каждому на бакете 2: ответ каждого пуст, без `Error`; у всех `epoch()=1`, `lease_active(2)=false`, `serving_epoch(2)=None`, `applied_seq=1`; P остаётся primary, Q и R — нет |
| (2) | `Publish` B (эпоха 1, бакет 3) на P: ровно один `ProtocolError{code=EPOCH_STALE}`, ни `ReplicateOp`, ни `PublishAck`; `applied_seq` всех трёх = 1; `owner_slot(B)=None` у всех; `serving_epoch(3)=None` |
| (3) | `tick(6)` у всех трёх пуст: ни `LeaseGrant`, ни `MembershipUpdate`, ни `TimeMark`; epoch = 1, `serving_epoch(6)=None` |
| (4) | `tick(1000)` у всех трёх пуст; epoch = 1; `Publish` C (эпоха 1, бакет 1000) на P дал ровно `EPOCH_STALE`; `applied_seq` остался 1 |
| (5) | Второе трио, `expires=10`: до гранта у всех `serving_epoch(1)=1`; грант на бакете 2 принят молча, `lease_active(2)=false`, `serving_epoch(2)=None`; `tick(9)` у всех пуст; `tick(10)` у говорящего ранга 0 — ровно два `MembershipUpdate{epoch=2}`, ни одного `LeaseGrant`; epoch всех трёх = 1, `serving_epoch(10)=None` |

Фальсификаторы (а)…(и) не сработали: база дала `OK`; грант будущей эпохи принят без
`Error`; `lease_active` и `serving_epoch` упали; publish не прошёл и не тронул WAL;
тики 6 и 1000 пусты; при `expires=10` выбор вернулся ровно на 10; ни один `on_frame`
не вернул `Err`.

## Вердикт

`supports`: на первом же замере все шесть замороженных порогов совпали. `LeaseGrant` с
`epoch > have` — вторая половина fence, которой в коде нет: `Lease::verify` отвергает
только `g.epoch < have`, а `handle_lease_grant` проверяет самосогласованность подписи и
`from`, но не членство. Грант от произвольного ключа принимается молча, `lease_active`
падает из-за несовпадения эпох, `serving_epoch` становится `None`, запись отвечает
`EPOCH_STALE` до WAL, а `tick` не продлевает lease и не предлагает следующую эпоху до
чужого `expires_at_bucket`. Доставленный всем членам, один кадр останавливает и запись,
и выбор на срок, выбранный атакующим, при полном и живом составе.

## Что это не доказывает

Границы стенда: прямой `on_frame`, без handshake §5.3 и NodeCert; рестарт как снятие
заморозки не мерялся; после `expires=10` проверен только первый `MembershipUpdate`, а не
сбор порога, `adopt` и возврат `serving_epoch`; грант текущей эпохи от произвольного
ключа не проверялся; PoW 8 бит, один шард, R=3. Подробнее — «Границы» в `H-0067`.
Спека и код не менялись; кандидат ADR-0016 — следующий шаг.
