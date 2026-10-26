---
id: E-0122
hypothesis: H-0122
status: completed
base_commit: "faac87e"
started: "2026-10-26"
finished: "2026-10-26"
environment: "x86_64-pc-windows-gnu, хост владельца; Rust из PATH, Python 3 из PATH, PYTHONIOENCODING=utf-8; debug-сборка `vecdht-cli`; сеть — 127.0.0.1, QUIC, три процесса `node run` и два CLI-клиента `agent publish`/`agent find`"
command: "bash lab/e0122-run.sh"
threshold: "(1) `cycle-gate.py gate H-0122` выход 0; диск ≥ 15 000 МБ до и после; (2) `cargo test -q -p vecdht-cli --test cli key_show` выход 0, PASSED=1, FAILED=0, `KEY_SHOW_SELFCHECK=1`; (3) `bash lab/two-hosts.sh selfcheck` дважды на неизменном дереве: `HOSTS_OK=1`, `HOSTS_PUBLISH_OK=1`, `HOSTS_FIND_OK=1`, `HOSTS_MATCH=1`, `D2=0`, `MATCHES=1`, `HOSTS_TEXT_SHARD=0`, наборы `HOSTS_*`-фактов совпали (STABLE=1); (4) `expect.py lab/expectations/e0122.tsv` по обоим прогонам: EXPECT_EXIT=0; (5) посадка `HOSTS_MATCH=0` в копию таблицы даёт EXPECT_EXIT=1 (PLANT_EXIT=1); (6) PRE_FIX: на дереве `faac87e` нет ни `key show` в `crates/vecdht-cli`, ни `lab/two-hosts.sh` (PRE_FIX_NO_KEY_SHOW=1, PRE_FIX_NO_SCRIPT=1); (7) README.md и README.ru.md называют `lab/two-hosts.sh` и прямо говорят, что двухмашинный прогон ещё не исполнялся (README_EN_OK=1, README_RU_OK=1); (8) `bash lab/check-text-clean.sh` на файлах цикла выход 0; (9) `bash lab/repo-review.py` выход 0. Порог заморожен до первого прогона `lab/e0122-run.sh`; изменение любого числа — новая карточка."
result: "helper `WORST_RC=0`: гейт 0, диск 28 284 → 28 267 МБ; PRE_FIX на `faac87e` — ни `key show`, ни `lab/two-hosts.sh` (`PRE_FIX_NO_KEY_SHOW=1`, `PRE_FIX_NO_SCRIPT=1`); `key_show_derives_the_same_names_the_node_uses` — `1 passed; 0 failed`; README.md и README.ru.md называют сценарий и прямо говорят, что двух хостов ещё не было (`README_EN_OK=1`, `README_RU_OK=1`); два прогона `selfcheck` по 39 с: `HOSTS_CEREMONY=1`, `HOSTS_TEXT_CLUSTER=9`, `HOSTS_TEXT_SHARD=0`, `HOSTS_PUBLISH_OK=1`, `HOSTS_FIND_OK=1`, `HOSTS_MATCH=1`, `HOSTS_OK=1`, `PUB_SLOT=0`, `FIND_SLOT=0`, `FIND_D2=0`, `FIND_MATCHES=1`, `OWNER_EQ=1`, `OWNER_LEN64=1`, `SLOT_EQ=1`, владелец `fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565`; `STABLE=1`; 28 ожиданий без расхождений; `PLANT_EXIT=1`; `TEXTGUARD_CYCLE_EXIT=0`. Один красный прогон до зелёной пары — дефект экстрактора (ДИАГНОЗ-1), порог не менялся. Полная верификация `VERIFY_FAIL=0`: 130 тестовых бинарей, 771 passed, 0 failed, 9 ignored, 1 499 с, диск 28 276 МБ до; страж референсов, Lean (5 файлов, 115 деклараций, 0 broken), Verus (8 verified), clippy и check-text-clean — выход 0; в том же прогоне гейт карточки и таблица из 28 ожиданий исполнены на третьем подряд зелёном `selfcheck`."
verdict: "supports"
---

## Pre-registration (до прогона)

Порог заморожен до первого прогона helper'а. Проверяется исполняемость сценария из README, а не
«скрипт существует»: три живых узла, публикация через primary, находка с другого узла.

**Предварительный разведочный прогон** (до заморозки порога, в вердикт не входит) лежит в
`lab/logs/e0122-two-hosts-selfcheck.log`: `HOSTS_OK=1`, публикация `owner=fa4834…9565 slot=0`,
находка тем же владельцем и слотом, `d2=0`, 39 с. Он показал, что сценарий исполнится; порог выше
написан после него и не подгонялся под числа: все ожидания — равенства и нули, а не отношения.

Факты инвариантны к расписанию: владелец и слот — выход церемонии и публикации; `d2 = 0` —
свойство принятой записи; число совпадений — формат ответа; время 39–40 с не входит ни в один факт
и не сравнивается (порогов по времени здесь нет).

## Поправки прибора (порог не менялся)

1. **ДИАГНОЗ-1: классификатор строки в экстракторе.** Первый прогон helper'а покраснел на шести
   фактах (`FIND_SLOT`/`FIND_D2`/`FIND_MATCHES` = `-1`, `OWNER_EQ` = 0): признак «это строка поиска»
   ставился в конце обработки строки, поэтому поля `OWNER`/`SLOT`/`D2`/`MATCHES` той же строки
   разбирались как поля публикации. Оракул при этом был зелёным: `HOSTS_FIND_OK=1`, `D2=0`,
   владелец и слот в stdout совпадали. Признак теперь берётся из `$1` до разбора полей; факты и порог
   те же. Красный прогон остался в `lab/logs/e0122-all.log`.
2. **Гейт и контур источников.** Первый запуск helper'а не дошёл до замера: гейт требовал, чтобы
   запись `L-0032` (RFC 8032) числила `H-0122` в `targets`. Запись дополнена целью и строкой о том,
   зачем она этой гипотезе; порог не менялся.

## Результат

Вердикт `supports`: все девять пунктов порога выполнены.

1. **Мост seed → имена.** Тест `key_show_derives_the_same_names_the_node_uses` зелёный: вывод
   команды равен `Identity::from_seed`/`keys::peer_id`, приватный ключ не печатается.
2. **Публикация и поиск между процессами.** Два прогона `lab/two-hosts.sh selfcheck` (39 и 39 с)
   подняли три узла, опубликовали через primary и нашли с другого узла: `OWNER_EQ=1`, `SLOT_EQ=1`,
   `FIND_D2=0`, `FIND_MATCHES=1`, `HOSTS_MATCH=1`, `HOSTS_OK=1`; `STABLE=1` — наборы фактов совпали.
3. **Текст в шарде сети.** `HOSTS_TEXT_CLUSTER=9`, `HOSTS_TEXT_SHARD=0` в обоих прогонах.
4. **Чувствительность таблицы.** Посадка `HOSTS_MATCH=0` даёт `PLANT_EXIT=1`; 28 ожиданий без
   расхождений.
5. **Честность README.** Оба README называют `lab/two-hosts.sh` и прямо говорят, что прогон на двух
   хостах ещё не исполнялся.

**Чего результат не говорит.** Это dry-run одной машины (все три узла на 127.0.0.1): NAT, relay и
поведение на двух настоящих хостах не проверены, время поиска в вердикт не входит, а наблюдаемая
шероховатость «`find` ждёт полный `--timeout`, когда один провайдер не отвечает» записана, но не
исправлена.
