---
id: E-0145
hypothesis: H-0145
status: closed
verdict: "supports"
base_commit: "b351dfe"
started: "2026-10-28"
environment: "x86_64-pc-windows-gnu, хост владельца; cargo и bash; стенд — один процесс,
`current_thread`, настоящий QUIC на loopback, три `NetService` (релей `Role::Relay`, цель-агент без
прямых listen-адресов, клиент-агент); PRE_FIX снимается из пина через `git show`; сеть наружу не
используется"
command: "bash lab/e0145-run.sh (дважды на неизменном дереве, затем `python lab/expect.py
lab/expectations/e0145.tsv run1.txt run2.txt`); носитель — `cargo test -q -p vecdht-net --test
s163_relay_circuit -- --nocapture --test-threads=1`"
threshold: "(1) пин и диск: `PIN_FOUND=1`, `GATE_H0145_OK=1`, `DISK_GE_15000=1`; (2) дыра названа
пином: `PRE_FIX_RELAY_FEATURE=0`, `PRE_FIX_RELAY_FIELD=0`, `PRE_FIX_RESERVE=0`, `PRE_FIX_RELAY_STATS=0`,
`PRE_FIX_TEST=0`; (3) продукт получил механизм: `RELAY_FEATURE=1`, `RELAY_CLIENT_FIELD=1`,
`RELAY_SERVER_FIELD=1`, `RESERVE_CIRCUIT=1`, `RELAY_STATS=1`; (4) носитель: `ORACLE_EXIT=0`,
`ORACLE_PASSED=2`, `ORACLE_FAILED=0`; (5) положительный контур: `target_direct_listeners=0`,
`positive_server_reservations=1`, `positive_server_circuits=1`, `positive_target_reservations=1`,
`positive_client_reservations=0`, `positive_client_circuits=1`,
`positive_auth_client_to_target=1`, `positive_auth_target_to_client=1`,
`positive_relay_auth_target=1`, `positive_relay_auth_client=1`, `positive_target_door_refusals=0`;
(6) отрицательный контроль: `negative_server_reservations=0`, `negative_server_circuits=0`,
`negative_target_reservations=0`, `negative_auth_client_to_target=0`; (7) границы: `WIRE_TOUCHED=0`,
`RUST_TOUCHED=3`, `LOCK_TOUCHED=1`; (8) соседние стражи зелёные (`SECRETS_EXIT`, `REFS_EXIT`,
`CLAIMMAP_EXIT`, `CLAIMS_EXIT`, `CONTOURS_EXIT`, `MIRROR_EXIT`, `GATE_AUDIT_EXIT`, `REVIEW_EXIT`,
`LINT_LATEST_EXIT`, `TEXTGUARD_ALL_EXIT`, `TEXTGUARD_CYCLE_EXIT`), `LINT_ORPHANS=0`,
`TEXTGUARD_ALL_DIRTY=0`; (9) `WORST_RC=0` и два исполнения на неизменном дереве печатают один
вектор — `STABLE=1`. Порог заморожен до первого прогона `lab/e0145-run.sh`; изменение любого
числа — новая карточка."
---

# E-0145 — circuit relay v2: контур проводит прикладной handshake

## Что проверяется

Релей (`Role::Relay`) принимает резервацию цели и проводит контур; цель не имеет прямых
listen-адресов, поэтому успешный handshake в обе стороны доказывает путь через релей; клиент знает
только адрес релея и `PeerId` цели. Отрицательная половина: тот же узел в роли агента не выдаёт
слот и не проводит контур. Wire, коды и формат кадров не меняются.

## Почему это не косметика

До правки `Role::Relay` был подписью без механизма: CLI принимал роль, DHT считал такого узла
сервером, а `agent.rs` на недостижимого пира отвечал «NAT без relay/DCUtR (§16.3)». Гейт P6
(§18.7) мерил бы путь, которого в дереве не было. Теперь WAN-замер имеет нижнюю половину, а
`docs/RELEASE-MAP-v1.md` может отличать «не проверено на двух машинах» от «не реализовано».

## Границы

Loopback без NAT и WAN-RTT; P6 двумя машинами не закрывается. Внешним адресом релея в v1 считается
его собственный listen-адрес — за NAT оператору нужен явный внешний адрес, и это открытая граница,
а не свойство. Лимиты библиотеки (120 с контура, 128 КиБ) не настраивались. DCUtR и AutoNAT не
включены: прямое соединение после контура не поднимается. Мультиплексирование нескольких
контуров не мерялось.

## Что считается вердиктом

Только факты, названные в пороге: слот и контур на релее, слот у цели, контур у клиента, handshake
в обе стороны, ноль прямых слушателей у цели, нули в отрицательном контроле, `WIRE_TOUCHED=0` и
`STABLE=1`. Время в порог не входит: deadline ограничивает ожидание, а не измеряет путь.

## Результат (первый прогон носителя)

Порог выполнен: два прогона на неизменном дереве дали `ОЖИДАНИЙ=49 РАСХОЖДЕНИЙ=0`, `WORST_RC=0`,
`STABLE=1`. Пин — пять нулей `PRE_FIX_*`; продукт — `RELAY_FEATURE=1`, `RELAY_CLIENT_FIELD=1`,
`RELAY_SERVER_FIELD=1`, `RESERVE_CIRCUIT=1`, `RELAY_STATS=1`. Носитель — `ORACLE_PASSED=2`,
`ORACLE_FAILED=0`: у цели `target_direct_listeners=0`, на релее
`positive_server_reservations=1` и `positive_server_circuits=1`, у цели
`positive_target_reservations=1`, у клиента `positive_client_reservations=0` и
`positive_client_circuits=1`, handshake — `positive_auth_client_to_target=1`,
`positive_auth_target_to_client=1`, `positive_relay_auth_target=1`,
`positive_relay_auth_client=1`, отказов двери `positive_target_door_refusals=0`. Отрицательный
контроль — четыре нуля. Границы — `WIRE_TOUCHED=0`, `RUST_TOUCHED=3`, `LOCK_TOUCHED=1`. Соседние
стражи зелёные, `LINT_ORPHANS=0`, `TEXTGUARD_ALL_DIRTY=0`.

## Итог исполнения

Пре-регистрация — `b60aa96`. Фикс — `7a7933d`: фича `relay`; `relay_client` у всех ролей;
`relay_server: Toggle<relay::Behaviour>` только при `role == Role::Relay`;
`reserve_circuit(relay)` строит `/p2p/<relay>/p2p-circuit` и слушает `Protocol::P2pCircuit`;
`relay_stats()` отдаёт четыре счётчика; релей объявляет каждый `NewListenAddr` внешним. Прибор —
`38da1ba`: якорь `grab` допускает префикс `МЕРЕНО` (ДИАГНОЗ-4). Wire v8, список 18 кодов и формат
кадров не тронуты.

Верификация `bash lab/workspace-verify.sh E-0145`: третий блок зелёный — `VERIFY_FAIL=0`, 135
срезов, 790 passed, 0 failed, 9 `#[ignore]`, `TEST_EXIT=0`, `CLIPPY_EXIT=0`, `LEAN_ALL_OK=1`,
`LEANGUARD_SELFTEST_EXIT=0`, `CYCLEGATE_EXIT=0`, `SECONDS_total=2513`. Первые два блока красные по
чужим для релея причинам: нагрузочный флейк `s53_door_branches` и сломанный дефолтный тулчейн Lean
`v4.36.0-rc1`; изолированный прогон и `ELAN_TOOLCHAIN=v4.33.1` это подтвердили. Оба блока остались
в `lab/logs/workspace-verify-2026-10-22.log`; вердикт опирается на зелёный. Числа прогонов и
ДИАГНОЗы — `lab/logs/e0145-all.log`.
