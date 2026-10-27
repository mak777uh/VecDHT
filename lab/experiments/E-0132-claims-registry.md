---
id: E-0132
hypothesis: H-0132
status: pre-registered
verdict: pending
base_commit: "e411f59"
started: "2026-10-27"
environment: "x86_64-pc-windows-gnu, хост владельца; только bash и python — цикл не исполняет cargo и
не поднимает сеть, потому что измеряет связность текстов релизной очереди; посадка работает во
временном каталоге с поддельными носителями и карточками, чтобы не менять дерево прогона; PRE_FIX
исполняется возвратом пяти файлов пина с `trap`-возвратом; дата карточки судится по UTC (`ADR-0070`)"
command: "bash lab/e0132-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0132.tsv`); PRE_FIX — тот же helper, посадка `git checkout <пин пре-регистрации> --
lab/claims.tsv lab/check-claims.py docs/STATUS-v1.md README.md README.ru.md` с возвратом через trap"
threshold: "(1) `python lab/cycle-gate.py gate H-0132` выход 0 (`GATE_H0132_OK=1`), диск ≥ 15 000 МБ
до прогона; (2) посадка исполняется: `PLANTED_TOTAL=8`, `PLANTED_CAUGHT=8`, `PLANTED_FALSE=0`,
`LEGAL_TOTAL=5`, `SELFTEST_EXIT=0`; (3) PRE_FIX называет дыру числом: `PRE_FIX_PIN_FOUND=1`,
`PRE_FIX_EXIT=1`, `PRE_FIX_CLAIMS=16`, `PRE_FIX_VIOLATIONS=3`, `PRE_FIX_GATE_RATIO=1`,
`PRE_FIX_QUALIFIER=1`, `PRE_FIX_CEILING=1`, `PRE_FIX_READY_VALUES=2`, `PRE_FIX_COND_COVERED=5`,
`PRE_FIX_DIFFERS=1`; (4) живое дерево после починки зелёное: `GUARD_EXIT=0`, `LIVE_CLAIMS=17`,
`LIVE_VIOLATIONS=0`, `LIVE_DANGLING=0`, `LIVE_CEILING=0`, `LIVE_QUALIFIER=0`, `LIVE_TYPE_BAD=0`,
`LIVE_LINK_BAD=0`, `LIVE_GATE_RATIO=0`, `LIVE_COND_LINK_BAD=0`; (5) покрытие и один владелец:
`LIVE_COND_TABLE=5`, `LIVE_COND_COVERED=5`, `LIVE_READY_VALUES=1`, `LIVE_READY_CARRIERS=3`;
(6) прибор стоит в контуре и в CI: `VERIFY_WIRES_CLAIMS=1`, `CI_WIRES_CLAIMS=1`; (7) соседние стражи
не рассоединились: `SECRETS_EXIT=0`, `REFS_EXIT=0`, `CLAIMMAP_EXIT=0`, `TEXTGUARD_ALL_EXIT=0`,
`TEXTGUARD_ALL_DIRTY=0`, `TEXTGUARD_CYCLE_EXIT=0`, `MIRROR_EXIT=0`, `LINT_EXIT=0`, `LINT_ORPHANS=0`,
`GATE_AUDIT_EXIT=0`, `REVIEW_EXIT=0`; (8) продукт не тронут: `RUST_TOUCHED=0`; (9) `WORST_RC=0` и
два исполнения на неизменном дереве печатают один вектор — `STABLE=1`. Порог заморожен до первого
официального прогона `lab/e0132-run.sh`; изменение любого числа — новая карточка."
---

# E-0132 — соединённый реестр утверждений: типы свидетельств и потолок формулировки

Карточка заведена вместе с прибором (`lab/check-claims.py`, `lab/claims.tsv`, `lab/e0132-run.sh`) и
таблицей ожиданий `lab/expectations/e0132.tsv`. Утверждение, фальсификатор и оракул — в
`lab/hypotheses/H-0132-claims-registry.md`; здесь лежит только замороженный порог.

## Что уже измерено до официальных прогонов (разведка прибором)

Прибор прогнан на дереве пре-регистрации при сборке: `CLAIMS=16`, `VIOLATIONS=3`
(`QUALIFIER=1`, `GATE_RATIO=1`, `CEILING=1`), `CONDITIONS_TABLE=5`, `CONDITIONS_COVERED=5`,
`READY_CARRIERS=3`, `READY_VALUES=2`. Три нарушения — это одно предложение
`docs/STATUS-v1.md` («Gates P2–P5 are closed», фазы `P0`, `P2`, `P5` без носителей в своей строке)
и расхождение цифры готовности (78 в двух README против 85 в статус-документе). Самопроверка при
сборке: `PLANTED_TOTAL=8`, `PLANTED_CAUGHT=8`, `PLANTED_FALSE=0`, `LEGAL_TOTAL=5`.
