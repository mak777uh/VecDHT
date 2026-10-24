---
id: E-0098
hypothesis: H-0098
status: pre-registered
base_commit: "f9923c9 (продукт до правки: PRE_FIX-оракул прогнан здесь и заморожен в lab/logs/e0098-prefix.log)"
started: "2026-10-24"
finished: null
environment: "Windows, x86_64-pc-windows-gnu; rustc 1.99.1; Python 3 (PyYAML). Настоящий QUIC на loopback. Приборы: `cargo test -p vecdht-net --test s76_own_cert_expiry` (3 гейта), `cargo test -p vecdht-net --test s76b_own_cert_expiry_observe` (счётчик), `cargo test -p vecdht-net --lib own_cert_window` (граница), `python lab/cycle-gate.py`, `bash lab/workspace-verify.sh E-0098`. `RAYON_NUM_THREADS=2`, PATH включает `/c/Users/Admin/mingw64/bin`"
command: "bash lab/e0098-run.sh (заморожен этим коммитом; исполняется неизменяемой mktemp-копией).
Порядок: (0) PRE_FIX — статические счётчики `git show f9923c9:...service.rs` (`valid_until`,
`own_cert_expired`, `self_revoked`) и замороженный красный прогон оракула из
`lab/logs/e0098-prefix.log`; (1) `cargo test --test s76_own_cert_expiry` ×2; (2)
`cargo test --test s76b_own_cert_expiry_observe` ×2; (3) `cargo test -p vecdht-net --lib
own_cert_window` ×2; (4) `gate H-0098 --skip-lean` и `audit -n 5` ×2; (5) сверка вектора
`python lab/facts.py repro --strip-run`; (6) `bash lab/workspace-verify.sh E-0098`; затем
`bash lab/check-text-clean.sh <файлы цикла>` и `python lab/expect.py lab/expectations/e0098.tsv`.
Лог — `lab/logs/e0098-all.log` (append-only, контроль от отметки начала блока)"
threshold: "Заморожено этим коммитом вместе с `lab/expectations/e0098.tsv`, оракулом и helper'ом.
Ожидания выведены из поведения до правки (замороженный лог) и из устройства правки, а не из
будущего прогона. PRE_FIX: `PREFIX_VALID_UNTIL_HITS=0`, `PREFIX_OWN_CERT_EXPIRED_HITS=0` (своего
срока в сервисе нет), `PREFIX_SELF_REVOKED_HITS=17` (молчание отзыва есть), `PREFIX_ORACLE_PASSED=1`,
`PREFIX_ORACLE_FAILED=2`, `PREFIX_G1_CONSTRUCTED=1`, `PREFIX_G2_AFTER_EXPIRY_SERVED=1`,
`PREFIX_G3_FRESH_SERVED=1`. После правки: `S76_TOTAL=3`, `S76_PASSED=3` дважды, при
`S76_G1_CONSTRUCTED=0`, `S76_G2_AFTER_EXPIRY_SERVED=0`, `S76_G2_BEFORE_EXPIRY_SERVED=1`,
`S76_G3_FRESH_SERVED=1`; `S76B_TOTAL=1`, `S76B_PASSED=1`, `S76B_SELF_EXPIRED=1`,
`S76B_REFUSALS_GE_1=1`; юнит-тесты границы `UNIT_TOTAL=2`, `UNIT_PASSED=2`. `GATE_H0098_OK=1`,
`AUDIT_VIOLATIONS=0`, `AUDIT_CARDS=5`. `REPRO_VECTOR=1` — два прогона каждого прибора на неизменном
дереве дают одинаковый вектор (правило 7 (е)). `S76_IN_VERIFY=1` — оракул исполняется полной
верификацией, а не живёт отдельным файлом. `VERIFY_EXIT=0`, `TEXT_DIRTY_FILES=0`,
`DISK_GE_15000=1` фиксирует ресурсный порог (11) тройкой чисел и не подгоняется. Фальсификаторы —
шесть пунктов из `H-0098`"
result: null
verdict: pending
---

# E-0098 — политика просроченного собственного кредашиала: fail-stop и наблюдаемая причина

## Что замеряется

Что сервис знает собственный срок кредашиала и перестаёт говорить сам, а не только становится
недостижимым для новых handshake'ей; что граница окна исключающая; что годный кредашиал ведёт себя
как прежде; что причина наблюдаема числом; что провод не изменился.

## Почему PRE_FIX — замороженный прогон, а не пересказ

Оракул `s76` компилируется на базовом продукте: он не трогает новых имён API и проверяет только
поведение (построился ли сервис, обслужил ли Find). Поэтому его красный прогон на `f9923c9` — это
измерение дыры, а не мнение о ней: `G1_CONSTRUCTED=1` и `G2_AFTER_EXPIRY_SERVED=1` сняты исполнением.
Прогон заморожен в `lab/logs/e0098-prefix.log`; после правки продукт нельзя «раз-исправить», поэтому
helper печатает эти факты из замороженного файла, а не пересчитывает их на исправленном дереве.

## Границы

Провод, `NetConfig`, `revocation.bin` и порядок лесенки §4.2 не трогаются. Нижняя граница окна
(`valid_from` в будущем) в гипотезу не входит — это ошибка развёртывания с причиной `NotYetValid`
на двери соседа. Политика — fail-stop без завершения процесса: молчание и число, а не `panic`.
