---
id: E-0147
hypothesis: H-0147
status: closed
verdict: "supports"
base_commit: "14fb924"
started: "2026-10-29"
environment: "x86_64-pc-windows-gnu, хост владельца; cargo и bash; Python 3; сеть наружу не
используется; PRE_FIX снимается из пина через `git show`"
command: "bash lab/e0147-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0147.tsv run1.txt run2.txt`); носители —
`python lab/check-status-claims.py selftest` и `python lab/check-status-claims.py --doc
docs/STATUS-v1.md`"
threshold: "(1) пин: `PIN_FOUND=1`, `PRE_FIX_GUARD_FOUND=1`, `PRE_FIX_PIN_CLAIMS=4`,
`PRE_FIX_LIE_PASSES=1`; (2) прибор: `POST_FIX_LIE_CAUGHT=1`, `POST_FIX_LIE_IDS=S-05`,
`STATUS_EXIT=0`, `STATUS_CLAIMS=12`, `STATUS_CONSISTENT=12`, `STATUS_STALE=0`,
`STATUS_FACTS=34`, `STATUS_FACTS_OK=34`, `STATUS_FACTS_MISSING=none`; (3) посадки:
`SELFTEST_TOTAL=37`, `SELFTEST_PASSED=37`, `SELFTEST_FAILED=0`; (4) границы: `WIRE_TOUCHED=0`,
`RUST_TOUCHED=0`; (5) соседние стражи зелёные (`SECRETS_EXIT`, `REFS_EXIT`, `CLAIMMAP_EXIT`,
`CLAIMS_EXIT`, `CONTOURS_EXIT`, `MIRROR_EXIT`, `GATE_AUDIT_EXIT`, `REVIEW_EXIT`,
`LINT_LATEST_EXIT`, `TEXTGUARD_ALL_EXIT`, `TEXTGUARD_CYCLE_EXIT`), `LINT_ORPHANS=0`,
`TEXTGUARD_ALL_DIRTY=0`; (6) `DISK_GE_15000=1`; (7) `WORST_RC=0` и два исполнения на неизменном
дереве печатают один вектор — `STABLE=1`. Порог заморожен до первого официального прогона
`lab/e0147-run.sh`; изменение любого числа — новая карточка."
---

# E-0147 — второй проход `docs/STATUS-v1.md`: восемь новых строк под владельцами

## Что проверяется

Гипотеза `H-0147`: несущие строки страницы статуса за пределами `S-01…S-04` можно связать с
деревом теми же четырьмя видами доказательства и тем же прибором; круг добавляет восемь строк
(relay `E-0145`, производитель отзыва `E-0120`, `denylist.bin` `E-0092`, `revocation.bin`
`E-0094`, дисковый аудит `E-0108`, кап ячейки `E-0088`, конечность таблицы провайдеров `E-0091`,
стенд P1 `E-0105`), посадочные случаи на каждую и доказывает, что прежний страж из четырёх строк
пропускал посаженную ложь в новых областях.

## Почему это не косметика

Второй проход был назван хвостом `E-0143` (`OPEN-QUESTIONS` п. 83: «текст документа не проверен на
остальные утверждения»). Пока строки держатся прозой, документ может утверждать возможность,
которой в дереве уже нет, и посторонний этого не узнает: страж проверяет только четыре строки.

## Границы

Прибор читает названные формы, а не смысл; поведение доказывают тесты, а не он. Строки-отсутствия
(«эндпоинта нет», «расчёта нет») вне круга: у отсутствия нет владельца-символа. Документ не
переписывается под прибор — при расхождении это находка.

## Что считается вердиктом

Только факты, названные в пороге. Содержание круга — пара `PRE_FIX_LIE_PASSES=1` /
`POST_FIX_LIE_CAUGHT=1`; покрытие — `STATUS_CONSISTENT=12` и `STATUS_FACTS_OK=STATUS_FACTS`.

## Результат

`supports`. Один и тот же документ с одной заменой («circuit relay v2 from §16.3 is up since
`E-0145`» → «…is not up since…») прошёл прежний страж пина нулём и не был назван ни одной строкой
(`PRE_FIX_PIN_CLAIMS=4`, `PRE_FIX_LIE_PASSES=1`, `PRE_FIX_LIE_IDS=none`), а новый страж на нём же
отказал и назвал `S-05` (`POST_FIX_LIE_CAUGHT=1`, `POST_FIX_LIE_IDS=S-05`). На настоящем документе
двенадцать строк из двенадцати согласованы (`STATUS_CLAIMS=12`, `STATUS_CONSISTENT=12`,
`STATUS_STALE=0`), все 34 владельца нашлись (`STATUS_FACTS=34`, `STATUS_FACTS_OK=34`,
`STATUS_FACTS_MISSING=none`). Самопроверка — 37 посаженных случаев, 37 отбито. Документ не
переписывался: все двенадцать формулировок нашлись как есть. Продукт и провод не тронуты
(`RUST_TOUCHED=0`, `WIRE_TOUCHED=0`).

## Итог исполнения

Носитель — `lab/logs/e0147-all.log`. Два официальных прогона на неизменном дереве после красной
пары `DISK_FREE_MB=5 910` (хост; порог не ослаблен): `WORST_RC=0`, `ОЖИДАНИЙ=35 РАСХОЖДЕНИЙ=0`
дважды, `VECTORS_EQUAL`, `STABLE=1`. Полная верификация зелёная на втором блоке (`VERIFY_FAIL=0`,
136 срезов, 791 passed, 0 failed, 9 `#[ignore]`, `SECONDS_total=2053`, диск 16 564 МБ); первый блок
был красным по соседнему тесту `an_agent_publishes_finds_and_opens_a_direct_session`
(`PowExhausted { bits: 20, attempts: 8 000 000 }`, вероятность хвоста `e^-8 ≈ 3·10⁻⁴` на исполнение;
три одиночных повтора прошли) — это флейк соседнего теста, а не свойство круга, и он назван в
носителе (ДИАГНОЗ-5) и в `OPEN-QUESTIONS` п. 87.

Что осталось: прибор понимает двенадцать названных форм, а не смысл; двадцать с лишним абзацев
документа держатся прозой; строки-отсутствия вне круга; `S-12` опирается на карточку, закрытую
`refutes` (вид факта `card-closed`), потому что строка сообщает о прогоне, а не о пройденном гейте.
