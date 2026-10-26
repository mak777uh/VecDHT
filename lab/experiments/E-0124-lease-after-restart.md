---
id: E-0124
hypothesis: H-0124
status: in_progress
base_commit: "d8d3087"
started: "2026-10-26"
finished: ""
environment: "x86_64-pc-windows-gnu, хост владельца; Rust из PATH (cargo/rustc), Python 3 из PATH, PYTHONIOENCODING=utf-8; PATH дополнен /c/Users/Admin/mingw64/bin (иначе MinGW из miniconda рвёт линковку GetHostNameW); debug-сборка инкрементально поверх дерева d8d3087; сеть прибора — 127.0.0.1, QUIC, два процесса `node run` и настоящий `vecdht_net::Agent`"
command: "bash lab/e0124-run.sh"
threshold: "(1) `python lab/cycle-gate.py gate H-0124` выход 0; диск ≥ 15 000 МБ до и после, напечатаны три числа (диск/RAM/pagefile). (2) PRE_FIX на неизменном дереве `d8d3087` тем же прибором: `cargo test -q -p vecdht-node --test lease_after_restart -- --nocapture` краснеет, в фактах `LR_PRIMARY_SERVING=0`, `LR_PRIMARY_PUBLISH_OK=0`, `LR_LEASE_FILE=0`, `LR_PLANT_REJECTED=0`, и отказ назван `EPOCH_STALE` (`LR_PRE_REFUSAL=EPOCH_STALE`). (3) После правки оба прибора зелёные дважды на неизменном дереве (`--no-fail-fast`): `cargo test -q -p vecdht-node --test lease_after_restart` и `cargo test -q -p vecdht-cli --test node_lease_status`, FAILED=0, наборы `LR_*`-фактов совпали между прогонами (`STABLE=1`). (4) `python lab/expect.py lab/expectations/e0124.tsv` выход 0 при `LR_LEASE_FILE=1`, `LR_FILE_EQ_FRAME=1`, `LR_PRIMARY_SERVING=1`, `LR_PRIMARY_PUBLISH_OK=1`, `LR_EPOCH_UNCHANGED=1`, `LR_REPLICA_NO_LEASE=1`, `LR_REPLICA_PUBLISH_NOT_OWNER=1`, `LR_PLANT_REJECTED=3`, `LR_EXPIRED_GRANT_NOT_SERVING=1`, `LR_STATUS_LEASE_FIELD=1`, `LR_STATUS_SERVING_FIELD=1`, `LR_RESTART_PUBLISH_OK=1`, `LR_CLI_EPOCH_ONE=1`. (5) Посадка: `LR_PLANT_REJECTED=1` в копию таблицы даёт `expect.py` выход 1 (`PLANT_EXIT=1`). (6) Контракт `crates/vecdht-node/tests/restart_recovery.rs` переписан осознанно: пункт (3) гласит «рестарт без гранта» (файл удалён в тесте), в комментарии назван ADR-0065; `cargo test -q -p vecdht-node --test restart_recovery` выход 0. (7) Регрессия затронутых крейтов выход 0: `cargo test -q -p vecdht-node -p vecdht-cli -p vecdht-net --all-targets --no-fail-fast`, FAILED=0, игнорируемые релизные приборы не исполнены. (8) `cargo clippy -q -p vecdht-node -p vecdht-cli --all-targets -- -D warnings` выход 0; `bash lab/check-text-clean.sh` на файлах цикла выход 0; `python lab/repo-review.py` выход 0. (9) Полная верификация `bash lab/workspace-verify.sh E-0124` заканчивается `VERIFY_FAIL=0`. Порог заморожен до первого прогона `lab/e0124-run.sh`; изменение любого числа — новая карточка."
---

## Pre-registration (до прогона)

### Что проверяется и почему именно так

Рестарт primary сегодня стоит шарду смены эпохи: `open_with_admission` поднимает цепочку членства и
`grant_epoch`, но `lease` оставляет `None` (`node.rs::open_with_admission`), поэтому `serving_epoch`
— `None`, а `handle_publish` отвечает `EPOCH_STALE` тем же кодом, которым отказывает воскресший
primary из прошлой эпохи. Прибор обязан отличить «гранта нет» от «грант есть и он тот же»:
второй случай — это `PublishAck OK` на **той же** эпохе после reopen, и он же — единственная
причина, по которой пункт (4) `restart_recovery.rs` («tick после рестарта рождает черновик эпохи 2»)
перестаёт быть штатным путём.

### Развилка, которая решена до кода

`lease.bin` — ровно подписанный кадр `LeaseGrant`, тот же массив байтов, что уходит по проводу. Никакой
отдельной сериализации состояния: если бы на диске лежала собственная форма, проверка подписи при
открытии не значила бы ничего, а расхождение формы диска и провода стало бы второй дверью.
При открытии файл проходит `Lease::verify` против **принятой** эпохи (ADR-0016) и сверяется с
`membership.primary`, как это делает `handle_lease_grant`; посадка — чужая эпоха, битая подпись,
истёкший бакет, чужой шард, файл больше одного кадра.

Грант реплики не персистится: ей lease нужен только на агентском пути записи, который и так
отсекается `NOT_OWNER` раньше, чем успевает что-то перепутать.

### Что происходит с прежним контрактом

`restart_recovery.rs` фиксирует «lease в RAM не переживает рестарт» и строит на этом пункты (3)…(6)
(рестарт primary → `EPOCH_STALE` → тик рождает эпоху 2). Правка делает этот путь *не* штатным, и
подгонять под него тест нельзя. Решение, зафиксированное в ADR-0065: старый сценарий сохраняется
как ветка «рестарт **без** гранта» — в тесте файл гранта удаляется перед reopen, и все дальнейшие
переходы (эпоха 2, heal, GC) остаются измерением того же пути; ветка «рестарт **с** действующим
грантом» — новый файл `lease_after_restart.rs`. Удаление файла в тесте — не косметика: это ровно то
состояние, в котором узел поднимается после истечения `lease_buckets` или на дереве до этой правки.

### Ограничение, которое измеряется, а не замалчивается

Выигрывается окно `lease_buckets` (90 с), а не бессрочное право: после истечения бакета грант
недействителен, и поведение возвращается к PRE_FIX. Второй известный хвост — если кластер за время
отсутствия primary уже принял новую эпоху, восстановленный грант не совпадёт с его собственной
цепочкой, и узел возьмёт запись у себя, не собрав кворум: агент получит таймаут вместо чистого
отказа. Это свойство `w`-кворума, а не правки; наблюдаемость «у меня грант эпохи E, у мира E+1» —
`OPEN-QUESTIONS`.
