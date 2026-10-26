---
id: E-0120
hypothesis: H-0120
status: running
base_commit: "a251334"
started: "2026-10-26"
finished: "2026-10-26"
environment: "x86_64-pc-windows-gnu, хост владельца; Rust из PATH (cargo/rustc), Python 3 из PATH, PYTHONIOENCODING=utf-8; debug-сборка инкрементально поверх дерева a251334; сеть — 127.0.0.1, QUIC, два процесса `node run`, `revoke` CLI как эфемерный агент"
command: "bash lab/e0120-run.sh"
threshold: "(1) `cycle-gate.py gate H-0120` выход 0, диск ≥ 15 000 МБ до и после; (2) `cargo test -q -p vecdht-cli --test revoke_publish -- --test-threads=1 --nocapture` дважды на неизменном дереве: RESULT_EXIT=0, PASSED=2, FAILED=0 в каждом прогоне, наборы `RV_*`-фактов совпали (STABLE=1); (3) `expect.py lab/expectations/e0120.tsv` по обоим прогонам: EXPECT_EXIT=0 при `RV_BASELINE_DOOR_ZERO=1`, `RV_SIGS=3`, `RV_THRESHOLD=3`, `RV_LIVE_REVOCATIONS=1`, `RV_LIVE_FILE_NONEMPTY=1`, `RV_LIVE_DOOR_GT_BASELINE=1`, `RV_RESTART_REVOCATIONS=1`, `RV_RESTART_DOOR_GT=1`; (4) посадка `PASSED=1` в копию таблицы даёт EXPECT_EXIT=1 (PLANT_EXIT=1); (5) PRE_FIX: на дереве `a251334` в `crates/vecdht-cli/src/lib.rs` нет пути `revoke` и нет файла `revoke_cmd.rs` (PRE_FIX_NO_REVOKE_CMD=1); (6) `cargo clippy -q -p vecdht-cli --all-targets -- -D warnings` выход 0; (7) стража текста на новых файлах цикла выход 0. Порог заморожен до первого прогона `lab/e0120-run.sh`; изменение любого числа — новая карточка."
result: "pending"
verdict: "pending"
---

## Pre-registration (до прогона)

Порог заморожен до первого прогона. Проверяется не «команда отвечает нулём», а то, что отзыв,
собранный ею, **применяется живым узлом** и **переживает его рестарт**, а недонабранный порог не
становится документом.

Источник чисел — `crates/vecdht-cli/tests/revoke_publish.rs`, два теста:

* `revoke_applies_live_and_survives_restart` — церемония через CLI (5 ключей авторитета, порог 3),
  два процесса `node run` на шарде 0, baseline двери (`peers>0`, `door_refusals=0`), затем отзыв
  второго члена: офлайн-файл (`--out`) и рассылка эфемерным агентом (`--to`, control-тема).
  Отзываемый член на время рассылки погашен: живой, он узнал бы о своём отзыве по control-теме и
  замолчал бы сам, и рост `door_refusals` ничего бы не значил. Проверяется: `revocations` 0→1 без
  рестарта, `revocation.bin` в каталоге получателя, рост `door_refusals` при повторном предъявлении
  того же кредашиала, затем рестарт владельца из того же `--dir` без bootstrap — `revocations>0` и
  отказ повторяется.
* `revoke_refuses_below_threshold_and_foreign_keys` — 2 подписи при пороге 3 (код 2, файла нет),
  ключ вне набора авторитетов (код 2, файла нет), ни `--out`, ни `--to` (код 2), и контроль: три
  ключа с `--out` пишут файл.

Факты, попадающие в ожидания, инвариантны к расписанию: это либо «ноль/не ноль», либо точное
число из формата (`RV_SIGS=3`, `RV_THRESHOLD=3`), либо счётчик, который по построению равен 1
(один отзыв). Число отказов двери не фиксируется значением — только отношением «больше baseline»:
`E-0077` и `E-0088` показали, что абсолютные счётчики доставок зависят от расписания шагов.

Замена, названная заранее: пункт карточки A3 про ошибку записи `revocation.bin` (`H-0096`) здесь
**не измеряется** — это отдельный порог о поведении получателя при отказе диска, а не о
производителе. Отзыв собственного кредашиала (узел замолкает) тоже не измеряется: он уже
измерен `E-0094`.

PRE_FIX — пин `a251334` (предок дерева): на нём команды `revoke` нет ни файлом, ни в диспетчере.

## Результат

Ожидает прогона; заполняется после двух зелёных прогонов helper'а.
