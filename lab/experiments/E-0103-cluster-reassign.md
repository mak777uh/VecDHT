---
id: E-0103
hypothesis: H-0103
status: planned
base_commit: "пре-регистрация H-0103 — этот коммит; правка продукта — следующий (хэши в § Ход)"
started: "2026-10-24"
finished: ""
environment: "Windows, x86_64-pc-windows-gnu; rustc 1.99.1; Python 3; RAYON_NUM_THREADS=2;
PATH включает /c/Users/Admin/mingw64/bin. Внешних файлов нет: сетка центроидов 1024×384 строится
в тесте из номера кластера, поэтому замер не зависит от весов и корпуса"
command: "bash lab/e0103-run.sh: gate H-0103 ДО прогона, два релизных прогона
`cargo test --release -p vecdht-node --test c103_cluster_reassign -- --nocapture`, извлечение
литеральных `C103_*`, `python lab/expect.py lab/expectations/e0103.tsv`, `audit -n 5`,
`bash lab/workspace-verify.sh E-0103`, стража текста, носитель до и после. PRE_FIX — отдельно:
`lab/logs/e0103-prefix.log`"
threshold: "Заморожено этим коммитом вместе с `lab/expectations/e0103.tsv` и прибором. Ожидания
выведены из спеки §7.2/§7.3 (ячейка — аргминимум L2²) и §6.1 (assign < 0.3 мс), а не из прогона:
`C103_MEASURED=1`; `C103_FORGED_ENTRY_CELL=117`, `C103_FORGED_CLAIMED_COUNT=0`,
`C103_REASSIGNED=1` (заявка 119, вектор в 117 при `BASE = 7·16`); `C103_HONEST_ENTRY_CELL=117`,
`C103_HONEST_REASSIGNED=0`; `C103_CROSS_SHARD_CODE=SHARD_MISMATCH`, `C103_CROSS_SHARD=1`,
`C103_CROSS_SHARD_STORE=0` (вектор в 132 = шард 8); `C103_NO_CENTROIDS_ENTRY_CELL=119`,
`C103_NO_CENTROIDS_UNVERIFIED=1`; `C103_ASSIGN_BUDGET_US=300`, `C103_ASSIGN_P50_LE_300US=1`;
`C103_EXIT=0`, `C103_RUNS=2`, `C103_VECTOR_STABLE=1`; `GATE_H0103_OK=1`, `AUDIT_VIOLATIONS=0`,
`VERIFY_EXIT=0`, `DISK_GE_15000=1`"
result: ""
verdict: ""
---

# E-0103 — узел пересчитывает `cluster_id` (§7.3)

## Pre-registration (до прогона)

Вопрос: выбирает ли ячейку индекса `vec_q` (геометрия) или `cluster_id` издателя (заявление)?
§7.3 говорит «пересчитывает и использует своё»; код до правки выбирал по заявлению. Оракул —
`crates/vecdht-node/tests/c103_cluster_reassign.rs`, пять тестов на живом `on_frame`-пути (не на
прямом вызове индекса, как `E-0079`): подделка в том же шарде, подделка в чужой шард, честный
контроль, fail-open без центроидов, цена `assign` в release против бюджета §6.1.

Сетка синтетическая и потому независимая от весов: строка кластера `c` — номер в первых двух
координатах (`c % 100 − 50`, `c / 100 − 5`), остальное нули. Все 1024 строки различны, `assign`
строки равен её номеру без tie-break; тест проверяет это до порогов, иначе пять фактов измеряли бы
не то. `BASE = 7·16 = 112`: `OWN = 117`, `CLAIMED = 119` (тот же шард), `CROSS = 132` (шард 8).

Что считается провалом: любое расхождение с `lab/expectations/e0103.tsv`; невозможность снять
PRE_FIX; разные векторы двух прогонов (`C103_VECTOR_STABLE=0` — факт зависит от расписания,
правило 7 (е)). Порог цены — только абсолютный (§6.1); медиана publish с центроидами и без
печатается рядом и вердиктом не является (правило 7 (д)).

## Ход

Заполняется после прогона.

## Результат

Заполняется после прогона.

## Вердикт

Заполняется после прогона.

## Что это не доказывает

Заполняется после прогона.
