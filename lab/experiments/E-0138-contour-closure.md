---
id: E-0138
hypothesis: H-0138
status: pre-registered
verdict: pending
base_commit: "10c0835"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; только bash и python — цикл не исполняет cargo и
не поднимает сеть, потому что измеряет связность собственных логов и карточек; посадка работает во
временном каталоге с поддельными логами и карточками, чтобы не менять дерево прогона; PRE_FIX
исполняется посадкой отсутствием (`lab/contour-exceptions.tsv` убирается во временный каталог,
`trap` возвращает) и проверкой `git ls-tree`, что на пине пре-регистрации файла нет; дата карточки
судится по UTC (`ADR-0070`)"
command: "bash lab/e0138-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0138.tsv`); PRE_FIX — тот же helper, посадка отсутствием с `trap`-возвратом"
threshold: "(1) `python lab/cycle-gate.py gate H-0138` выход 0 (`GATE_H0138_OK=1`), диск ≥ 15 000 МБ
до прогона; (2) самопроверка исполняется: `PLANTED_TOTAL=9`, `PLANTED_CAUGHT=9`, `PLANTED_FALSE=0`,
`LEGAL_TOTAL=4`, `ABSENT_UNEXPLAINED=8`, `ABSENT_OK=1`, `SELFTEST_EXIT=0`; (3) PRE_FIX называет дыру
числом: `PRE_FIX_PIN_FOUND=1`, `PRE_FIX_PIN_FILE_ABSENT=1`, `PRE_FIX_EXIT=1`,
`PRE_FIX_CLOSED_TOTAL=127`, `PRE_FIX_BLOCK_LABELS=73`, `PRE_FIX_COVERED=73`,
`PRE_FIX_MISSING_TOTAL=54`, `PRE_FIX_EXPLAINED=0`, `PRE_FIX_UNEXPLAINED=54`,
`PRE_FIX_EXCEPTIONS_ABSENT=1`, `PRE_FIX_REASON_EMPTY=0`, `PRE_FIX_ERA_TOTAL=0`,
`PRE_FIX_MODERN_TOTAL=0`, `PRE_FIX_VIOLATIONS=54`, `PRE_FIX_DIFFERS=1`; (4) живое дерево после
починки зелёное: `GUARD_EXIT=0`, `LIVE_FORM_FIRST=E-0049`, `LIVE_CLOSED_TOTAL=127`,
`LIVE_BLOCK_LABELS=73`, `LIVE_COVERED=73`, `LIVE_MISSING_TOTAL=54`, `LIVE_EXPLAINED=54`,
`LIVE_UNEXPLAINED=0`, `LIVE_VIOLATIONS=0`, `LIVE_EXCEPTIONS_ABSENT=0`, `LIVE_REASON_EMPTY=0`,
`LIVE_CLASS_BAD=0`, `LIVE_GHOST=0`, `LIVE_DUP=0`, `CONTOUR_GUARD_EXISTS=1`,
`CONTOUR_EXCEPTIONS_EXISTS=1`, `CONTOUR_EXCEPTIONS_ROWS=54`; (5) эры и их число: `LIVE_ERA_TOTAL=45`,
`LIVE_MODERN_TOTAL=9` — рост второго означает новую карточку, закрытую без контура; (6) прибор стоит
в контуре и в CI: `VERIFY_WIRES_CONTOURS=1`, `CI_WIRES_CONTOURS=1`; (7) соседние стражи не
рассоединились: `SECRETS_EXIT=0`, `REFS_EXIT=0`, `CLAIMMAP_EXIT=0`, `CLAIMS_EXIT=0`,
`TEXTGUARD_ALL_EXIT=0`, `TEXTGUARD_ALL_DIRTY=0`, `TEXTGUARD_CYCLE_EXIT=0`, `MIRROR_EXIT=0`,
`LINT_EXIT=0`, `LINT_ORPHANS=0`, `GATE_AUDIT_EXIT=0`, `REVIEW_EXIT=0`; (8) продукт не тронут:
`RUST_TOUCHED=0`; (9) `WORST_RC=0` и два исполнения на неизменном дереве печатают один вектор —
`STABLE=1`. Порог заморожен до первого официального прогона `lab/e0138-run.sh`; изменение любого
числа — новая карточка. Вектор снимается на дереве починки до прогона полного контура: блок
`E-0138 · workspace-verify` появляется в контуре закрытия и сдвинул бы `LIVE_BLOCK_LABELS`, поэтому
постконтурное число печатается в носителе отдельно и в порог не входит."
---

# E-0138 — сведение закрытых карточек с блоками контура

Карточка заведена вместе с прибором (`lab/check-contours.py`, `lab/contour-exceptions.tsv`,
`lab/e0138-run.sh`) и таблицей ожиданий `lab/expectations/e0138.tsv`. Утверждение, фальсификатор и
оракул — в `lab/hypotheses/H-0138-contour-closure.md`; здесь лежит только замороженный порог.

## Что уже измерено до официальных прогонов (разведка прибором)

Прибор прогнан на живом дереве при сборке. Сведение: `CLOSED_TOTAL=127`, `BLOCK_LABELS=73`,
`COVERED=73`, `MISSING_TOTAL=54`; с файлом исключений — `EXPLAINED=54`, `UNEXPLAINED=0`,
`ERA_TOTAL=45`, `MODERN_TOTAL=9`, `VIOLATIONS=0`, `FORM_FIRST=E-0049`. Посадка отсутствием (файл
исключений убран): `UNEXPLAINED=54`, `VIOLATIONS=54`, `EXCEPTIONS_ABSENT=1`, `REASON_EMPTY=0`,
выход 1. Самопроверка: `PLANTED_TOTAL=9`, `PLANTED_CAUGHT=9`, `PLANTED_FALSE=0`, `LEGAL_TOTAL=4`,
проба без файла — `ABSENT_UNEXPLAINED=8`.

Девять карточек класса «после-формы» (`E-0086`, `E-0089`, `E-0123`, `E-0131`, `E-0133`, `E-0134`,
`E-0135`, `E-0136`, `E-0137`) — те самые круги, что названы в `OPEN-QUESTIONS` п. 76: у них нет
блока `workspace-verify` ни в одном логе дерева, о чём печатает прибор, а не память автора.

## Дыра, найденная уже этим кругом при сборке прибора

Пока файла исключений в дереве не было, самопроверка читала живые исключения: путь решался
относительно текущего каталога оболочки, а не относительно названного `--root`, и временное дерево
получало чужой файл — `GHOST=53` вместо девяти посаженных нарушений. Починка решает путь относительно
корня (`os.path.join(root, …)` с проверкой существования), проба «файла нет» добавлена отдельным
случаем. Класс находки тот же, что у прибора `E-0137`: проверка формы там, где надо проверять
множество, и разрешение пути там, где надо брать названный корень.
