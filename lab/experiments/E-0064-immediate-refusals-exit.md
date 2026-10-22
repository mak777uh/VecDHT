---
id: E-0064
hypothesis: H-0064
status: proposed
verdict: pending
started: 2026-10-22
finished:
---

# E-0064 — немаскировка трёх оставшихся немедленных отказов на входе цели (§12.3): `Expired`, `WrongTarget`, `TtlOutOfPolicy` выходят из `serve_request` как `Spend(...)`

## План прогона

Оракул `crates/vecdht-node/tests/immediate_refusals_exit.rs`, helper `lab/e0064-run.sh`
(структура секций как в зелёных `e0062`/`e0063`: BUILD `--no-run` → RUN `--nocapture` →
ИНВЕНТАРЬ → КОНТРОЛЬ `-p vecdht-node`; helper исполняет команду целиком — урок `e0049`).
Живой одиночный primary, publish/Find → приём F0 (ttl=300, issued 0); мутанты собираются
сменой полей декодированного `RendezvousAccept` и пере-подписью КЛЮЧОМ УЗЛА (seed из
харнеса — урок `E-0060`), база (0б) — побайтовое равенство пере-подписи unchanged и F0.
Часы двигаются осознанно: now=20 = ровно грань исчезновения spent-памяти `E-0060`
(урок учтён: отказ на этой грани обязан быть `Expired`, не `AlreadySpent`). Лог:
`lab/logs/e0064-all.log` (append-only). Пороги (0а)…(8) заморожены в `H-0064` до первого
замера; коммит пре-регистрации пушится до измерений. Верификация воркспейса —
`lab/workspace-verify.sh E-0064`.

## Прогон (замеры ещё не выполнялись)

Замер не проводился: этот файл — пре-регистрация. Первый прогон —
`bash lab/e0064-run.sh` после коммита пре-регистрации.

## Результат: таблица порогов (0а)…(8) по H-0064

| Порог | Утверждение | Факт | Вердикт |
|---|---|---|---|
| (0а) | decode(F0): seeker=A, target=O, shard=7, issued=0, ttl=300 | | |
| (0б) | пере-подпись unchanged тела ключом N == F0 побайтово | | |
| (1) | честное предъявление при now=0 → `Ok` | | |
| (2) | F0 при now=20 → `Spend(Expired)`, не маскировано | | |
| (3) | чужой `target` (пере-подпись N) при now=0 → `Spend(WrongTarget)` | | |
| (4) | `ttl_sec := 0` (пере-подпись N) → `Spend(TtlOutOfPolicy(0))` | | |
| (5) | `ttl_sec := 301` при политике 300 → `Spend(TtlOutOfPolicy(301))` | | |
| (6) | `ttl_sec := 0` при now=20 → `Spend(TtlOutOfPolicy(0))` (политика раньше истечения) | | |
| (7) | тот же кадр (4) с ЧУЖИМ подписантом → `NotSignedByShardHolder` (маскирующая ветка единственная) | | |
| (8) | spend2.spent()==0 после (2)…(7); spend1: Ok → spent 1 → повтор `AlreadySpent` | | |
| (а)…(з) | фальсификаторы | | |
