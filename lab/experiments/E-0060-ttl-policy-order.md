---
id: E-0060
hypothesis: H-0060
status: proposed
verdict: pending
started: 2026-10-22
finished:
---

# E-0060 — полный набор проверок `Spend::consume` и его порядок: подпись → адресат → политика TTL → истечение → расход (§12.3)

## План прогона

Оракул `crates/vecdht-node/tests/ttl_policy_order.rs`, helper `lab/e0060-run.sh`
(helper исполняет команду целиком — урок `e0049`; структура секций как в зелёных
`e0058`/`e0059`: BUILD `--no-run` → RUN `--nocapture` → ИНВЕНТАРЬ → КОНТРОЛЬ
`-p vecdht-node`). Харнес — одиночный primary, живой приём бакета 0 из-под `Find`,
подделки — переиздание тела с другим `ttl_sec` и честной подписью издателя
(`sign_body(domain::RENDEZVOUS)`); расход — прямой `Spend::consume` (без входа
`present`: мерится приёмная сторона, а не гейт `ADR-0013`).
Лог: `lab/logs/e0060-all.log` (append-only). Пороги заморожены в `H-0060` до первого
замера; коммит пре-регистрации пушится до измерений.

## Прогон

(после прогона)

## Результат: таблица порогов

| Порог | Утверждение | Факт | Вердикт |
|---|---|---|---|
| (0) | f0@19 → Ok, spent==1 | | |
| (1) | ttl=0 → TtlOutOfPolicy(0), spent цел | | |
| (2) | ttl=301 при max=300 → TtlOutOfPolicy(301) | | |
| (3) | ttl=301 при max=315 → Ok (окно из карты) | | |
| (4) | wrong-target+ttl=0 → WrongTarget (до политики) | | |
| (5) | wrong-target+now=301 → WrongTarget (до истечения) | | |
| (6) | ttl=1: Ok@1, AlreadySpent@1, Expired@2, spent==0 | | |
| (7) | Unsigned → Unsigned; чужая подпись → BadSignature | | |
| (8) | f0@20 → Expired; spent базовой цели == 1 | | |
| (а)…(з) | фальсификаторы | | |

## Что это значит

(после прогона)

## Границы

(после прогона)
