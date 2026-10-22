---
id: E-0067
hypothesis: H-0067
status: planned
base_commit: ""
started: ""
finished: ""
environment: ""
command: "bash lab/e0067-run.sh"
threshold: "H-0067 (0)…(5): грант будущей эпохи принимается от не-члена; lease_active/serving_epoch падают; publish → EPOCH_STALE без WAL; tick(6)/tick(1000) пусты; при expires=10 выбор возвращается ровно на 10"
result: ""
verdict: pending
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

Окружение и сырой вывод — в `lab/logs/e0067-all.log` (append-only): BUILD `--no-run` →
RUN `--nocapture` → ИНВЕНТАРЬ → КОНТРОЛЬ `-p vecdht-node`.

## Результат

Заполняется после прогона.

## Вердикт

`pending` до прогона.
