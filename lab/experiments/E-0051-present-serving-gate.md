---
id: E-0051
hypothesis: H-0051
verdict: accepted
status: completed
started: 2026-10-22
---

# E-0051 — приёмка v1-минимума предъявления (ADR-0013)

Цикл разработки: спека/ADR заморожены до кода (коммит `a3c1fc2`), реализация
(`present` в wire, `serve_request`/`encode_request_present` в session, golden-векторы
регнерированы — diff ровно на `body/frame.intent_text_request`) и оракул
`tests/present_serving_gate.rs` в одном коммите (green-main invariant: приёмочные пороги
то же самое, что пре-зарегистрированные в ADR). Прогон `lab/e0051-run.sh` (finished = mtime лога, 2026-10-22T11:12:31+03:00): RUN --nocapture все шесть
порогов зелёным, ИНВЕНТАРЬ (present в wire: struct+cap+codec; serve_request в session),
КОНТРОЛЬ wire+node+net EXIT=0. Workspace-verify 558 ok / CLIPPY_REAL_EXIT=0 (блок
E-0051/ADR-0013 в общем логе). Оракул E-0045 не переписан — добавлен аддендум, что
фикция закрыта на уровне входа обслуживания; golden-векторы: diff ровно две строки
intent_text_request (body 44→55, frame len 2c→37).
