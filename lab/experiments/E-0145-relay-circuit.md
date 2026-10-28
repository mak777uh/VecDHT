---
id: E-0145
hypothesis: H-0145
status: pending
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
