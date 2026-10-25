# Векторы платных заказов (v9)

Документ порождён `crates/vecdht-orders/tests/paid_order_vectors.rs`; правки в него вручную
не вносятся: следующий запуск перезапишет их. Каждое число здесь — результат исполнения кода,
а не оценка.

## Воспроизведение

```bash
cargo test -q -p vecdht-orders --test paid_order_vectors -- --nocapture
V9_VECTORS_OUT=docs/PAID_ORDER-VECTORS.md \
  cargo test -q -p vecdht-orders --test paid_order_vectors -- --nocapture
```

## Общие входы

- образ: `2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a`
- entrypoint: `/usr/local/bin/verify`
- бюджет: 120 с = 120000 мс
- network: `false`
- награда: 1000000 минимальных единиц, актив `native` (цепь 0)
- escrow_ref: `vecdht:escrow/0x01`
- deadline: 1800000000 (включителен)
- submit_limit: 8
- publisher: `00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590`
- nonce заказа: 7
- statement_hash: `6d37fa9fab2c40b1c1fc3af187be28a008c49380ab9a7e03cf892c181b56bc98`
- order_ref: `4167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac70`
- artifact_set_hash подачи: `a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39`
- AXIOM_ALLOWLIST: [propext, Classical.choice, Quot.sound]
- PAYBACK_WINDOW_SECONDS: 3600
- OFFLINE_FACTOR: 3
- DEFAULT_TRUSTED_CHAINS: []
- ключи: издатель seed = 1, подающий seed = 2, верификатор seed = 3; `keypair(seed)`
  кладёт `seed` в первый байт и `seed xor 0xa5` в последний (только для приборов).

## Векторы

### V01 — Полный путь: заказ, подача, квитанция, выплата

```json
{"id":"V01","title":"Полный путь: заказ, подача, квитанция, выплата","outcome":"accept","code":null,"action":null,"facts":{"kind":"lean_proof","statement_hex":"7468656f72656d206164645f7a65726f5f726967687420286e203a204e617429203a206e202b2030203d206e203a3d2062790a2020696e64756374696f6e206e20776974680a202020207c207a65726f203d3e2072666c0a202020207c2073756363206b206968203d3e2073696d70205b4e61742e737563635f6164642c2069685d0a","statement_hash":"6d37fa9fab2c40b1c1fc3af187be28a008c49380ab9a7e03cf892c181b56bc98","order_ref":"4167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac70","canonical_record_hex":"7665636468742f706169645f6f726465722f76310000006d37fa9fab2c40b1c1fc3af187be28a008c49380ab9a7e03cf892c181b56bc98002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f00000000000000000000000000000000120000007665636468743a657363726f772f307830310000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000","canonical_record_len":"217","order_signature_hex":"607850d9ed7da128ac703bd5290400f813b9070071c355f68f217d0c8c4df369978a0a094cab41dc3920d90340082a4aa4d276394e8d2cdfc1af61daeedce90e","artifact_set_hash":"a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39","submission_ref":"62a097ff571760f38fe43991dffcd4d63a1038144933f860497b15f9c56e3747","receipt_canonical_json":"{\"axioms\":[\"propext\",\"Classical.choice\"],\"budget_ms\":120000,\"deterministic\":true,\"exit_code\":0,\"image_digest\":\"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\",\"order_ref\":\"4167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac70\",\"stderr_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"stdout_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",\"submission_ref\":\"62a097ff571760f38fe43991dffcd4d63a1038144933f860497b15f9c56e3747\",\"toolchain\":\"leanprover/lean4:v4.9.1\",\"verdict\":\"pass\",\"verifier_pubkey\":\"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254\",\"wall_clock_ms\":41000}","receipt_signature_hex":"ef8e6237fcd78d67ad4e6b72e838b8d491c30f7bc26129d1540a6ad3490307692c2bacec3e642841ec1465a9d5184bf7c7ccd2737c225adc82da54e5523a6c03","derived_verdict":"pass","payout_allowed":"true","escrow":"locked, native, amount = reward.amount"}}
```

### V02 — Канонизация задания: CRLF, хвостовые пробелы, пустые строки, NFC

```json
{"id":"V02","title":"Канонизация задания: CRLF, хвостовые пробелы, пустые строки, NFC","outcome":"accept","code":null,"action":null,"facts":{"input_hex":"7468656f72656d2074203a2054727565203a3d206279207472697669616c20200d0a0d0a0d0a","normalized_hex":"7468656f72656d2074203a2054727565203a3d206279207472697669616c0a","normalized_len":"31","nfc_decomposed_hash":"eab689ac73e221d0ff8868c0903721b4f8980436359d453772bf431860dd3299","nfc_precomposed_hash":"eab689ac73e221d0ff8868c0903721b4f8980436359d453772bf431860dd3299","nfc_equal":"true","comments":"не вырезаются: комментарии остаются частью задания"}}
```

### V03 — statement_hash не совпал с пересчитанным

```json
{"id":"V03","title":"statement_hash не совпал с пересчитанным","outcome":"reject","code":"E_HASH_MISMATCH","action":"reject","facts":{"declared":"9999999999999999999999999999999999999999999999999999999999999999","computed":"6d37fa9fab2c40b1c1fc3af187be28a008c49380ab9a7e03cf892c181b56bc98"}}
```

### V04 — задание в канонической записи не проходит нормализацию (CRLF)

```json
{"id":"V04","title":"задание в канонической записи не проходит нормализацию (CRLF)","outcome":"reject","code":"E_STATEMENT_ENCODING","action":"reject","facts":{"statement_hex":"7468656f72656d2074203a2054727565203a3d206279207472697669616c0d0a"}}
```

### V05 — задание не декодируется как UTF-8

```json
{"id":"V05","title":"задание не декодируется как UTF-8","outcome":"reject","code":"E_STATEMENT_ENCODING","action":"reject","facts":{"input_hex":"fffe0041"}}
```

### V06 — Lean-задание содержит запрещённый маркер sorry

```json
{"id":"V06","title":"Lean-задание содержит запрещённый маркер sorry","outcome":"reject","code":"E_AXIOM_NOT_ALLOWED","action":"reject","facts":{"statement_hex":"7468656f72656d2074203a2054727565203a3d20627920736f7272790a","marker":"sorry"}}
```

### V07 — нулевой budget_seconds

```json
{"id":"V07","title":"нулевой budget_seconds","outcome":"reject","code":"E_ORDER_MALFORMED","action":"reject","facts":{"budget_seconds":"0"}}
```

### V08 — неизвестный тег kind

```json
{"id":"V08","title":"неизвестный тег kind","outcome":"reject","code":"E_ORDER_MALFORMED","action":"reject","facts":{"tag":"9","known_tags":"0=lean_proof, 1=test_conformance, 2=repro_run"}}
```

### V09 — путь файла артефакта с ..

```json
{"id":"V09","title":"путь файла артефакта с ..","outcome":"reject","code":"E_ARTIFACT_PATH","action":"reject","facts":{"path":"../etc/passwd"}}
```

### V10 — пустое множество файлов артефакта

```json
{"id":"V10","title":"пустое множество файлов артефакта","outcome":"reject","code":"E_ARTIFACT_EMPTY","action":"reject","facts":{"files":"0"}}
```

### V11 — artifact_hash подачи не совпал с пересчитанным множеством

```json
{"id":"V11","title":"artifact_hash подачи не совпал с пересчитанным множеством","outcome":"reject","code":"E_HASH_MISMATCH","action":"reject","facts":{"declared":"7777777777777777777777777777777777777777777777777777777777777777","computed":"a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39"}}
```

### V12 — подача после deadline

```json
{"id":"V12","title":"подача после deadline","outcome":"reject","code":"E_DEADLINE_PASSED","action":"ignore","facts":{"created_at":"1800000001","deadline":"1800000000","on_deadline_accepted":"true"}}
```

### V13 — повторная подача с тем же nonce того же подающего

```json
{"id":"V13","title":"повторная подача с тем же nonce того же подающего","outcome":"reject","code":"E_REPLAY","action":"retry","facts":{"nonce":"1","seen_nonces":"1","scope":"на подающего, не глобально"}}
```

### V14 — достигнут submit_limit заказа

```json
{"id":"V14","title":"достигнут submit_limit заказа","outcome":"reject","code":"E_SUBMIT_LIMIT","action":"ignore","facts":{"submit_limit":"8","seen_count":"8"}}
```

### V15 — подача без подписи подающего

```json
{"id":"V15","title":"подача без подписи подающего","outcome":"reject","code":"E_ORDER_MALFORMED","action":"reject","facts":{"signature":"null"}}
```

### V16 — image_digest квитанции не совпал с заказанным

```json
{"id":"V16","title":"image_digest квитанции не совпал с заказанным","outcome":"reject","code":"E_IMAGE_UNAVAILABLE","action":"retry","facts":{"receipt_image_digest":"5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b","order_image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"}}
```

### V17 — deterministic = false

```json
{"id":"V17","title":"deterministic = false","outcome":"reject","code":"E_RECEIPT_INVALID","action":"escalate","facts":{"deterministic":"false"}}
```

### V18 — аксиома вне AXIOM_ALLOWLIST

```json
{"id":"V18","title":"аксиома вне AXIOM_ALLOWLIST","outcome":"reject","code":"E_AXIOM_NOT_ALLOWED","action":"reject","facts":{"axioms":"[propext, mine.private]","allowlist":"propext, Classical.choice, Quot.sound"}}
```

### V19 — нулевой exit_code после потолка бюджета

```json
{"id":"V19","title":"нулевой exit_code после потолка бюджета","outcome":"reject","code":"E_BUDGET_EXCEEDED","action":"escalate","facts":{"wall_clock_ms":"120001","budget_ms":"120000","exit_code":"0"}}
```

### V20 — Квитанция timeout: поля согласованы, вердикт выведен, выплата закрыта

```json
{"id":"V20","title":"Квитанция timeout: поля согласованы, вердикт выведен, выплата закрыта","outcome":"accept","code":null,"action":null,"facts":{"wall_clock_ms":"120001","budget_ms":"120000","exit_code":"1","derived_verdict":"timeout","receipt_valid":"true","payout_allowed":"false","transition":"verifying --verdict_timeout--> timed_out"}}
```

### V21 — квитанция без подписи верификатора

```json
{"id":"V21","title":"квитанция без подписи верификатора","outcome":"reject","code":"E_RECEIPT_UNSIGNED","action":"escalate","facts":{"signature":"null"}}
```

### V22 — подпись квитанции не проходит по verifier_pubkey

```json
{"id":"V22","title":"подпись квитанции не проходит по verifier_pubkey","outcome":"reject","code":"E_RECEIPT_UNSIGNED","action":"escalate","facts":{"signature_hex":"427b3dcbd93c7b2cf010591ee0d859a0ff5a802efdc3560899b76636d980f297f2189938a8526e887629ff3864d53060eaca55f09c59432b640ab70809e18e0d","signing_bytes_len":"669"}}
```

### V23 — verdict = pass при exit_code = 1

```json
{"id":"V23","title":"verdict = pass при exit_code = 1","outcome":"reject","code":"E_VERDICT_MISMATCH","action":"escalate","facts":{"declared":"pass","derived":"fail","exit_code":"1"}}
```

### V24 — order_ref квитанции не совпал с заказом

```json
{"id":"V24","title":"order_ref квитанции не совпал с заказом","outcome":"reject","code":"E_RECEIPT_INVALID","action":"escalate","facts":{"receipt_order_ref":"72dca83553bf27868225ada9acecb4a4c7906c5e294bd17c56ec886b04a364e6","order_ref":"4167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac70"}}
```

### V25 — цепь залога вне DEFAULT_TRUSTED_CHAINS

```json
{"id":"V25","title":"цепь залога вне DEFAULT_TRUSTED_CHAINS","outcome":"reject","code":"E_ESCROW_UNKNOWN","action":"escalate","facts":{"chain_id":"8453","trusted_ship_default":"[]","with_trusted_8453":"ok"}}
```

### V26 — залог меньше награды заказа

```json
{"id":"V26","title":"залог меньше награды заказа","outcome":"reject","code":"E_ESCROW_INSUFFICIENT","action":"reject","facts":{"locked_amount":"999999","reward_amount":"1000000"}}
```

### V27 — актив залога не совпал с обещанным

```json
{"id":"V27","title":"актив залога не совпал с обещанным","outcome":"reject","code":"E_UNSUPPORTED_ASSET","action":"reject","facts":{"order_asset":"native","escrow_asset":"token"}}
```

### V28 — вторичная выдача по уже отпущенному залогу

```json
{"id":"V28","title":"вторичная выдача по уже отпущенному залогу","outcome":"reject","code":"E_REPLAY","action":"retry","facts":{"status":"released"}}
```

### V29 — имя аксиомы вне печатного ASCII

```json
{"id":"V29","title":"имя аксиомы вне печатного ASCII","outcome":"reject","code":"E_RECEIPT_INVALID","action":"escalate","facts":{"axiom_hex":"626164096178696f6d","canonical_json":"не сериализуется"}}
```

### V30 — пара (settled, submit) не определена

```json
{"id":"V30","title":"пара (settled, submit) не определена","outcome":"reject","code":"E_STATE_UNKNOWN","action":"escalate","facts":{"state":"settled","event":"submit"}}
```

## Три примера канонизации задания

Нормализация — пять шагов из §V9.3: UTF-8 → NFC → `\r\n` и `\r` в `\n` → снять
хвостовые ` ` и `\t` с каждой строки → снять хвостовые пустые строки и поставить ровно
один `\n` в конце. Комментарии не вырезаются. Рецепт ниже повторяет те же пять шагов
без доступа к коду:

```python
import unicodedata
def normalize(raw: bytes) -> bytes:  # §V9.3, шаги 1-5
    text = raw.decode("utf-8")            # шаг 1: невалидный UTF-8 — отказ
    text = unicodedata.normalize("NFC", text)  # шаг 2
    text = text.replace("\r\n", "\n").replace("\r", "\n")  # шаг 3
    lines = [l.rstrip(" \t") for l in text.split("\n")]  # шаг 4
    while lines and lines[-1] == "": lines.pop()  # шаг 5
    assert lines, "пустое после нормализации — E_STATEMENT_ENCODING"
    return ("\n".join(lines) + "\n").encode("utf-8")
```

Команды воспроизведения написаны для `python3`; там, где есть только `python`, —
заменить имя Interpreter'а, содержимое команды не меняется.


### W1 — `lean_proof`, CRLF, хвостовые пробелы, пустые строки в конце

- тег `kind`: `lean_proof` (байт 0)
- raw (то, что прислал издатель), hex: `7468656f72656d206164645f7a65726f5f726967687420286e203a204e617429203a206e202b2030203d206e203a3d2062790d0a2020696e64756374696f6e206e207769746820200d0a202020207c207a65726f203d3e2072666c0d0a202020207c2073756363206b206968203d3e2073696d70205b4e61742e737563635f6164642c2069685d0d0a0d0a0d0a`
- нормализованные байты, hex: `7468656f72656d206164645f7a65726f5f726967687420286e203a204e617429203a206e202b2030203d206e203a3d2062790a2020696e64756374696f6e206e20776974680a202020207c207a65726f203d3e2072666c0a202020207c2073756363206b206968203d3e2073696d70205b4e61742e737563635f6164642c2069685d0a`
- длина нормализованных байтов: 131
- `statement_hash`: `6d37fa9fab2c40b1c1fc3af187be28a008c49380ab9a7e03cf892c181b56bc98`
- воспроизведение:

```bash
python3 -c 'import hashlib; print(hashlib.sha256(b"vecdht/paid_order/v1\x00" + bytes([0]) + b"\x00" + bytes.fromhex("7468656f72656d206164645f7a65726f5f726967687420286e203a204e617429203a206e202b2030203d206e203a3d2062790a2020696e64756374696f6e206e20776974680a202020207c207a65726f203d3e2072666c0a202020207c2073756363206b206968203d3e2073696d70205b4e61742e737563635f6164642c2069685d0a")).hexdigest())'
```

текст нормализованного задания (не-ASCII символы показаны как `\u{…}`, а сами байты — hex выше): `theorem add_zero_right (n : Nat) : n + 0 = n := by\u{000a}  induction n with\u{000a}    | zero => rfl\u{000a}    | succ k ih => simp [Nat.succ_add, ih]\u{000a}`

### W2 — `test_conformance`, NFC: `e` + U+0301 схлопывается в U+00E9

- тег `kind`: `test_conformance` (байт 1)
- raw (то, что прислал издатель), hex: `2320746573742073756974653a206361666565cc8120636f6e666f726d616e63650d0a73746570733a0d0a20202d2069643a2072656f70656e5f61667465725f736e617073686f740d0a20202d2069643a2077616c5f6761705f64657465637465640d0a`
- нормализованные байты, hex: `2320746573742073756974653a2063616665c3a920636f6e666f726d616e63650a73746570733a0a20202d2069643a2072656f70656e5f61667465725f736e617073686f740a20202d2069643a2077616c5f6761705f64657465637465640a`
- длина нормализованных байтов: 95
- `statement_hash`: `6e3cdf66ab0de49106672ba9f380d727e6e500e63f573803d8876fe9d9a52dff`
- воспроизведение:

```bash
python3 -c 'import hashlib; print(hashlib.sha256(b"vecdht/paid_order/v1\x00" + bytes([1]) + b"\x00" + bytes.fromhex("2320746573742073756974653a2063616665c3a920636f6e666f726d616e63650a73746570733a0a20202d2069643a2072656f70656e5f61667465725f736e617073686f740a20202d2069643a2077616c5f6761705f64657465637465640a")).hexdigest())'
```

текст нормализованного задания (не-ASCII символы показаны как `\u{…}`, а сами байты — hex выше): `# test suite: cafe\u{00e9} conformance\u{000a}steps:\u{000a}  - id: reopen_after_snapshot\u{000a}  - id: wal_gap_detected\u{000a}`

### W3 — `repro_run`, манифест прогона: CR в конце строк и табуляция перед переводом

- тег `kind`: `repro_run` (байт 2)
- raw (то, что прислал издатель), hex: `7b0d0a202022636d64223a205b227368222c20222d63222c20226d616b65202d4320726570726f20636865636b225d2c0d0a20202273656564223a20300d0a7d090d0a`
- нормализованные байты, hex: `7b0a202022636d64223a205b227368222c20222d63222c20226d616b65202d4320726570726f20636865636b225d2c0a20202273656564223a20300a7d0a`
- длина нормализованных байтов: 62
- `statement_hash`: `1471cef64d8ab88c70567b83f7cebc7d189ec41a0d4ec6d185b58c8a26c64564`
- воспроизведение:

```bash
python3 -c 'import hashlib; print(hashlib.sha256(b"vecdht/paid_order/v1\x00" + bytes([2]) + b"\x00" + bytes.fromhex("7b0a202022636d64223a205b227368222c20222d63222c20226d616b65202d4320726570726f20636865636b225d2c0a20202273656564223a20300a7d0a")).hexdigest())'
```

текст нормализованного задания (не-ASCII символы показаны как `\u{…}`, а сами байты — hex выше): `{\u{000a}  "cmd": ["sh", "-c", "make -C repro check"],\u{000a}  "seed": 0\u{000a}}\u{000a}`

## Полный пример: заказ, подача, квитанция

Значения посчитаны исполнением; поля заказов — общие из раздела «Общие входы».

- `canonical_record` заказа, hex: `7665636468742f706169645f6f726465722f76310000006d37fa9fab2c40b1c1fc3af187be28a008c49380ab9a7e03cf892c181b56bc98002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f00000000000000000000000000000000120000007665636468743a657363726f772f307830310000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000`
- `order_ref` = sha256(выше): `4167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac70`
- подпись издателя над `canonical_record`, hex: `607850d9ed7da128ac703bd5290400f813b9070071c355f68f217d0c8c4df369978a0a094cab41dc3920d90340082a4aa4d276394e8d2cdfc1af61daeedce90e`
- `canonical_bytes` подачи, hex: `7665636468742f706169645f6f726465722f7631014167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac7000a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f390015000000697066733a2f2f626166796265696578616d706c650061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af00010000000000000000ffd1496b00000000`
- `submission_ref` = sha256(выше): `62a097ff571760f38fe43991dffcd4d63a1038144933f860497b15f9c56e3747`
- листья множества файлов (отсортированы по байтам), hex: `13ff4725d97fd1e637f1d4a143762b4f8823fa4acade3945a037edd930c11a5b` , `e2e3c21223387adf6c3801945aed048cbfbc6f0468e62b5a62efd7603a34e0d8`
- `artifact_hash` = корень множества: `a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39`
- подпись подающего, hex: `4acb37b807aff2e01e41f4a553e9418e1d2e2992b354eceea5d8078e884a66dbb7717ff9c6210807baf3d4da24a955fb17c6b8669dbe1b530a3d2d9ea2c8070e`

Квитанция:

```json
{"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"4167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac70","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"62a097ff571760f38fe43991dffcd4d63a1038144933f860497b15f9c56e3747","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
```

- длина подписываемых байтов (`domain || 0x00 || json`): 678
- hex подписываемых байтов: `7665636468742f706169645f6f726465725f726563656970742f7631007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2234313637643032316130393965366566636263653234323132313137373537313336656230383233653364643564373536656433613263616636663261633730222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2236326130393766663537313736306633386665343339393164666663643464363361313033383134343933336638363034393762313566396335366533373437222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d`
- `signature` (Ed25519, ключ seed = 3), hex: `7a61a38a9d0e3726e7591edcbe0a14c60d118aa5083702895721092815ab981c94820adf771cb80ec00d30dd401ed858057a115b69e0134b384fd6dbb131380c`
- выведенный вердикт: `pass`; заявленный: `pass`

## Матрица состояний

Клетка — состояние-приёмник либо код ошибки. Любое событие вне перечисленных одиннадцати
(тег `unknown`) даёт `E_STATE_UNKNOWN`: неопределённая пара — это ошибка, а не молчание.

| state \ event | submit | verify_started | verdict_pass | verdict_fail | verdict_timeout | verdict_error | released | refunded | deadline_reached | verifier_offline | appeal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| published | verifying | E_STATE_UNKNOWN | E_RECEIPT_INVALID | E_RECEIPT_INVALID | E_RECEIPT_INVALID | E_RECEIPT_INVALID | E_STATE_UNKNOWN | E_STATE_UNKNOWN | expired | disputed | E_STATE_UNKNOWN |
| verifying | E_REPLAY | E_STATE_UNKNOWN | pass | fail | timeout | error | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_DEADLINE_PASSED | disputed | E_STATE_UNKNOWN |
| pass | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | settled | E_VERDICT_MISMATCH | E_STATE_UNKNOWN | E_STATE_UNKNOWN | disputed |
| fail | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_VERDICT_MISMATCH | rejected | E_STATE_UNKNOWN | E_STATE_UNKNOWN | disputed |
| timeout | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_VERDICT_MISMATCH | rejected | E_STATE_UNKNOWN | E_STATE_UNKNOWN | disputed |
| error | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_VERDICT_MISMATCH | rejected | E_STATE_UNKNOWN | E_STATE_UNKNOWN | disputed |
| settled | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN |
| rejected | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN |
| expired | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_VERDICT_MISMATCH | rejected | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_STATE_UNKNOWN |
| disputed | E_STATE_UNKNOWN | E_STATE_UNKNOWN | pass | fail | timeout | error | E_VERDICT_MISMATCH | rejected | E_STATE_UNKNOWN | E_STATE_UNKNOWN | E_REPLAY |

## Покрытие закрытого списка кодов

| code | action | векторы |
| --- | --- | --- |
| E_ORDER_MALFORMED | reject | V07, V08, V15 |
| E_STATEMENT_ENCODING | reject | V04, V05 |
| E_HASH_MISMATCH | reject | V03, V11 |
| E_IMAGE_UNAVAILABLE | retry | V16 |
| E_BUDGET_EXCEEDED | escalate | V19 |
| E_REPLAY | retry | V13, V28 |
| E_SUBMIT_LIMIT | ignore | V14 |
| E_ESCROW_UNKNOWN | escalate | V25 |
| E_ESCROW_INSUFFICIENT | reject | V26 |
| E_RECEIPT_INVALID | escalate | V17, V24, V29 |
| E_RECEIPT_UNSIGNED | escalate | V21, V22 |
| E_VERDICT_MISMATCH | escalate | V23 |
| E_AXIOM_NOT_ALLOWED | reject | V06, V18 |
| E_DEADLINE_PASSED | ignore | V12 |
| E_ARTIFACT_PATH | reject | V09 |
| E_ARTIFACT_EMPTY | reject | V10 |
| E_UNSUPPORTED_ASSET | reject | V27 |
| E_STATE_UNKNOWN | escalate | V30 |
