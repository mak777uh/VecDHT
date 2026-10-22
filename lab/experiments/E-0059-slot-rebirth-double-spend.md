---
id: E-0059
hypothesis: H-0059
status: proposed
verdict: pending
started: 2026-10-22
finished:
---

# E-0059 — перерождение слота: второй lease после prune расходится вторично в прежнем Spend, повтор — AlreadySpent, мёртвый кадр — Expired

## План прогона

Оракул `crates/vecdht-node/tests/slot_rebirth_double_spend.rs`, helper `lab/e0059-run.sh`
(helper исполняет команду целиком — урок `e0049`; структура секций как в зелёных
`e0057`/`e0058`: BUILD `--no-run` → RUN `--nocapture` → ИНВЕНТАРЬ → КОНТРОЛЬ
`-p vecdht-node`). Харнес — одиночный primary + прямой `Spend::consume`; ключевая
арифметика расхода (`Key` с `issued_bucket`) на скрещивании `E-0057`×`E-0058`.
Лог: `lab/logs/e0059-all.log` (append-only). Пороги заморожены в `H-0059` до первого
замера; коммит пре-регистрации пушится до измерений.

## Прогон

(заполняется по числам `e0059-all.log`)

## Результат: таблица порогов

| Порог | Утверждение | Факт | Вердикт |
|---|---|---|---|
| (1) | f0@0 Ok + повтор AlreadySpent | | |
| (1b) | f20: bucket=20, байты ≠ f0, live 1, refused 0 | | |
| (2) | f40@40 Ok (spent==2) — слот возродился | | |
| (3) | повтор f40 AlreadySpent; f0@40 Expired | | |
| (а)…(з) | фальсификаторы | | |

## Что это значит

(после прогона)

## Границы

(после прогона)
