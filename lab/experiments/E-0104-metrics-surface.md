---
id: E-0104
hypothesis: H-0104
status: pre-registered
base_commit: "e0856d5 — дерево без снимка наблюдения. PRE_FIX структурный: `git grep` по
`NodeMetrics|NetMetrics` на этом коммите даёт 0, файлов `*c104_metrics_closed.rs` нет. Слово
`metrics` на базе встречается один раз — `vecdht-embed/src/metrics.rs` (recall/nDCG для офлайн-оценки,
не наблюдение); поэтому PRE_FIX сформулирован по именам типа. Поверхность и приборы появляются
одним коммитом пре-регистрации"
started: "2026-10-25"
finished: ""
environment: "Windows, x86_64-pc-windows-gnu; rustc 1.99.1; Python 3; RAYON_NUM_THREADS=2;
PATH включает /c/Users/Admin/mingw64/bin. Debug-профиль намеренно: оракул проверяет
`debug_assert_eq!` (список имён и закрытость меток), которые в release выключены. Внешних файлов
нет: узел строится из тестовых сидов, QUIC-сервис слушает /ip4/127.0.0.1/udp/0, tokio — текущий
поток"
command: "bash lab/e0104-run.sh: gate H-0104 ДО прогона, два debug-прогона
`cargo test -p vecdht-node --test c104_metrics_closed -- --nocapture` и
`cargo test -p vecdht-net --test c104_metrics_closed -- --nocapture`, извлечение литеральных
`C104_*`, `python lab/expect.py lab/expectations/e0104.tsv`, `audit -n 5`,
`bash lab/workspace-verify.sh E-0104`, стража текста, носитель до и после"
threshold: "Заморожено вместе с `lab/expectations/e0104.tsv`, приборами и helper'ом до прогона.
Ожидания выведены из Приложения C (конечный список и закрытые причины `admit_drops_total`), §5.5
(цены в снимке нет), §14.4 (iv)/§7.3 (счётчики пересчёта), а не из прогона: `C104_MEASURED=1`;
`C104_NODE_NAMES=37`, `C104_NODE_EXACT=1`, `C104_NODE_RENDER_OK=1`, `C104_NODE_MAPPED=24`,
`C104_NODE_MEMORY_ROWS=6`, `C104_NODE_CENTROIDS_OBSERVABLE=1`, `C104_NODE_NO_PRICE=1`,
`C104_NODE_DOOR_SEPARATE=1`; `C104_NET_WIRING=1`, `C104_NET_FIXED=7`,
`C104_NET_DOOR_LABELS=22`, `C104_NET_LABELS_CLOSED=1`, `C104_NET_SUM=759`,
`C104_NET_SUM_OK=1`, `C104_NET_RENDER_OK=1`, `C104_NET_SIZE_STABLE=1`, `C104_NET_NO_PRICE=1`;
`C104_EXIT=0`, `C104_RUNS=2`, `C104_VECTOR_STABLE=1`; `GATE_H0104_OK=1`,
`AUDIT_VIOLATIONS=0`, `VERIFY_EXIT=0`, `DISK_GE_15000=1`"
result: ""
verdict: ""
---

# E-0104 — снимок метрик Приложения C (Batch B, часть 1)

## Pre-registration (до прогона)

Вопрос: можно ли снять Приложение C с живого продукта так, чтобы набор имён был конечен по
построению, поле не подменялось молча, а метка двери не открывала кардинальность заново? До этого
цикла снимать было нечем: счётчики существовали, поверхности наблюдения — нет.

Приборы: `crates/vecdht-node/tests/c104_metrics_closed.rs` (3 теста) и
`crates/vecdht-net/tests/c104_metrics_closed.rs` (3 теста). Оба — debug: `debug_assert` в модулях
(`pairs.len() == NAMES.len()`, метка ∈ `DoorReason::ALL`) в release выключен, и проверять его
release-прогоном значило бы проверять пустоту.

Что считается провалом: любое расхождение с `lab/expectations/e0104.tsv`; невозможность показать
PRE_FIX; разные векторы двух прогонов (правило 7 (е)). Отдельно: оракул маппинга обязан
различать поля **различными** числами — если два поля получат одно значение, тест пройдёт, ничего
не проверив, и это провал прибора, а не продукта.

Границы, названные заранее: это снимок, а не эндпоинт; метрики без источника в v1 в него не
входят и перечислены в `ADR-0059`; сетка и узлы тестовые, на 200 узлах прибор не исполняется
(это следующий цикл Batch B).

## Ход

_(заполняется при прогоне)_

## Прогон

_(заполняется при прогоне)_

## Результат

_(заполняется при прогоне)_

## Вердикт

_(заполняется при прогоне)_

## Что это не доказывает

_(заполняется при прогоне)_
