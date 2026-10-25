# VecDHT v9 — векторы слоя стыковки цепочек (автовыплаты)

> Документ порождён кодом: `crates/vecdht-orders/tests/payout_claim_vectors.rs`.
> Руками здесь не правится ничего — ни один хеш, ни одна байтовая строка, ни один код.

Воспроизведение:

```sh
cargo test -q -p vecdht-orders --test payout_claim_vectors -- --nocapture
V9P_VECTORS_OUT=docs/PAID_PAYOUT-VECTORS.md \
    cargo test -q -p vecdht-orders --test payout_claim_vectors -- --nocapture
```

Что обязано уметь по этому документу: собрать `term_hash`, корень реестра, байты связки,
свидетельства и требования, проверить четыре подписи и вывести решение по каждому вектору,
не имея ни Rust, ни узла VecDHT. Если текст соврёт в ширине поля, в терминаторе или в
литерале домена — пересборка разойдётся с напечатанными байтами, и сверка покраснеет.

Инварианты слоя (проект `ADR-0064`, §V9.7):

1. **Аддитивность.** Байты `paid_order` не изменились ни на байт: `order_ref` вектора V01
   из `docs/PAID_ORDER-VECTORS.md` остаётся `4167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac70`.
2. **Нет судьи.** Вердикт выводится из полей квитанции (§V9.5), выплата — из байтов
   требования; ни один шаг не обращается к узлу и не спрашивает мнение.
3. **Реестр — данные.** Заказ и свидетельство пинят `registry_root`: новая цепь меняет
   корень, уже подписанные требования — нет.
4. **Закрытый список.** Слой использует ровно те имена, что перечислены в §3 ниже; ни одна
   ветка не вводит девятнадцатого кода.
5. **Fail closed.** Пустой набор доверия (цепи, наблюдатели, корни) — отказ по существующему
   коду, а не «протокол сломан».

## 1. Домены канонизации

| имя | литерал | длина литерала | терминатор после домена |
|---|---|---|---|
| DOMAIN_TERM | `vecdht/paid_order_term/v1` | 25 | `0x00` |
| DOMAIN_BINDING | `vecdht/paid_order_binding/v1` | 28 | `0x00` |
| DOMAIN_CHAIN | `vecdht/chain_registry/v1` | 24 | `0x00` |
| DOMAIN_WITNESS | `vecdht/escrow_witness/v1` | 24 | `0x00` |
| DOMAIN_CLAIM | `vecdht/payout_claim/v1` | 22 | `0x00` |

`term_hash` — единственная связка заказа с деньгами; пересчитывается из заказа и ключа
получателя по формуле (целые — little-endian; терминатор `0x00` стоит только после
домена, потому что остальные поля имеют фиксированную ширину, `asset_bytes` несёт свой
терминатор внутри, а `escrow_ref` предваряется длиной):

```
term_hash = sha256( DOMAIN_TERM ‖ 0x00 ‖ order_ref(32) ‖ chain_id:u64le ‖
                         asset_bytes ‖ beneficiary_pubkey(32) ‖ amount:u128le ‖
                         u32le(len(escrow_ref)) ‖ escrow_ref
)
```

Здесь `asset_bytes` — ровно байты поля 8 канонической записи заказа (тег ветки, для
`token` — `chain_id:u64le` и `address(20)`, затем терминатор `0x00`), то есть актив в
связке с деньгами и актив в заказе не могут разойтись, не разошедшись с `order_ref`.
`chain_id` для `native` — 0; для `token` он дублирует поле актива намеренно: ширина
`u64le` в `term_hash` стоит до `asset_bytes`, и читателю не нужно разбирать тег, чтобы
понять, на какой цепи деньги.

## 2. Раскладка объектов слоя

Префикс каждой раскладки: литерал домена, затем `0x00`, затем поля в номерованном порядке.
Колонка «ширина»: `32 байта` — сырые байты фиксированной длины, `u64le`/`u128le`/`u16le` —
целое little-endian, `один байт` — тег, `u32le длина ‖ тело` — непредельная строка или
байты, `встраиваемый` — `u32le длина ‖ тело ‖ 0x00 ‖ подпись(64)`. Терминатор ставится
ровно там, где он напечатан в последней колонке; `—` означает «поля на этом кончаются».

**VerifierBinding — подписывает издатель заказа**

| № | поле | ширина | терминатор `0x00` |
|---|---|---|---|
| 1 | `order_ref` | 32 байта | `0x00` |
| 2 | `verifier_pubkey` | 32 байта | `0x00` |
| 3 | `image_digest` | 32 байта | `0x00` |
| 4 | `term_hash` | 32 байта | — |

**ChainDescriptor — описатель одной цепи**

| № | поле | ширина | терминатор `0x00` |
|---|---|---|---|
| — | `тег записи` | один байт: `0` | `0x00` |
| 1 | `chain_id` | `u64le` | `0x00` |
| 2 | `name` | `u32le` длина ‖ ASCII без терминального нуля | `0x00` |
| 3 | `bridge_code` | `u16le` | `0x00` |
| 4 | `settle_asset_tag` | один байт | `0x00` |
| 5 | `min_amount` | `u128le` | `0x00` |
| 6 | `note` | `u32le` длина ‖ ASCII без терминального нуля | — |

Имя и заметка описателя обязаны быть печатным ASCII (`0x20…0x7e`): эти строки входят в
листья реестра, а значит их пересчитывает сторонний мост. Непечатный ASCII —
`E_ORDER_MALFORMED`, `settle_asset_tag > 1` — `E_UNSUPPORTED_ASSET`.

Листья и корень реестра — та же детерминированная сборка, что §V9.4 для множества файлов:

```
leaf(d)       = sha256( DOMAIN_CHAIN ‖ 0x00 ‖ canonical_bytes(d) )
registry_root = sha256( DOMAIN_CHAIN ‖ 0x01 ‖ concat(sorted(leaf_i)) )
пустой реестр = sha256( DOMAIN_CHAIN ‖ 0x01 )
```

Сортировка листьев — по байтовому порядку 32-байтовых хешей, поэтому порядок перечисления
описателей в реестре не влияет на корень. Дубликат `chain_id` — ошибка структуры
(`E_ORDER_MALFORMED`), а не «последний победил».

**EscrowWitness — подписывает наблюдатель эскроу**

| № | поле | ширина | терминатор `0x00` |
|---|---|---|---|
| 1 | `term_hash` | 32 байта | `0x00` |
| 2 | `chain_id` | `u64le` | `0x00` |
| 3 | `status` | один байт: `0` not_funded, `1` locked, `2` released, `3` refunded | `0x00` |
| 4 | `amount_on_chain` | `u128le` | `0x00` |
| 5 | `block_ref` | `u32le` длина ‖ непрозрачные байты | `0x00` |
| 6 | `registry_root` | 32 байта | `0x00` |
| 7 | `observer_pubkey` | 32 байта | — |

Состояний ровно четыре: `status` вне `{0, 1, 2, 3}` — ошибка структуры
(`E_ORDER_MALFORMED`), а не «неизвестное считается разблокированным». Тело `block_ref`
непрозрачно: мост его не разбирает, оно входит в байты и подпись свидетельства.

**PayoutClaim — подписывает получатель выплаты**

| № | поле | ширина | терминатор `0x00` |
|---|---|---|---|
| 1 | `term_hash` | 32 байта | `0x00` |
| 2 | `order_ref` | 32 байта | `0x00` |
| 3 | `receipt` | встраиваемый: тело = канонический JSON квитанции (§V9.5), подпись = 64 байта | `0x00` |
| 4 | `binding` | встраиваемый: тело по таблице выше, подпись издателя — 64 байта | `0x00` |
| 5 | `witness` | встраиваемый: тело по таблице выше, подпись наблюдателя — 64 байта | `0x00` |
| 6 | `beneficiary` | 32 байта | — |

Подписи встроенных объектов входят в байты требования: требование цитирует решения трёх
сторон целиком, иначе читатель не сможет проверить ни одну из подписей офлайн.

## 3. Закрытый список кодов

Слой стыковки не добавляет имён: ниже — ровно те 18, что объявлены §V9.8. Сверка проверяет
и обратное: множество кодов, напечатанных в векторах, обязано быть подмножеством этого
списка (прибор ловит девятнадцатое имя посадкой).

| код | действие узла |
|---|---|
| `E_ORDER_MALFORMED` | `reject` |
| `E_STATEMENT_ENCODING` | `reject` |
| `E_HASH_MISMATCH` | `reject` |
| `E_IMAGE_UNAVAILABLE` | `retry` |
| `E_BUDGET_EXCEEDED` | `escalate` |
| `E_REPLAY` | `retry` |
| `E_SUBMIT_LIMIT` | `ignore` |
| `E_ESCROW_UNKNOWN` | `escalate` |
| `E_ESCROW_INSUFFICIENT` | `reject` |
| `E_RECEIPT_INVALID` | `escalate` |
| `E_RECEIPT_UNSIGNED` | `escalate` |
| `E_VERDICT_MISMATCH` | `escalate` |
| `E_AXIOM_NOT_ALLOWED` | `reject` |
| `E_DEADLINE_PASSED` | `ignore` |
| `E_ARTIFACT_PATH` | `reject` |
| `E_ARTIFACT_EMPTY` | `reject` |
| `E_UNSUPPORTED_ASSET` | `reject` |
| `E_STATE_UNKNOWN` | `escalate` |

## 4. Порядок вывода решения

Порядок значим: при двух нарушениях наблюдатель обязан увидеть тот же код, что и любой
другой реализатор моста.

1. **(0) форма требования** — подпись бенефициара над байтами требования, `order_ref` равен
   заказу, `beneficiary` равен `submission.submitter`, встроенные объекты кодируются.
   Отсутствие подписи требования и нарушение его формы дают `E_ORDER_MALFORMED`;
   встроенный объект без подписи даёт свой код (квитанция — `E_RECEIPT_UNSIGNED`, связка —
   `E_RECEIPT_INVALID`, свидетельство — `E_ESCROW_UNKNOWN`).
2. **(1) `term_hash`** пересчитан из (заказ, получатель) и равен напечатанному, иначе
   `E_HASH_MISMATCH`.
3. **(2) вердикт** выведен из полей квитанции по §V9.5, равен напечатанному и есть `pass`;
   иначе `E_VERDICT_MISMATCH` либо код, который называет сам вывод. Ссылки квитанции на заказ
   и подачу не совпали — `E_RECEIPT_INVALID`.
4. **(3) ключ квитанции** равен ключу из связки издателя и подпись квитанции проходит; иначе
   `E_RECEIPT_UNSIGNED`.
5. **(4) связка** подписана издателем заказа и относится к этому заказу, его `term_hash` и
   образу; иначе `E_RECEIPT_INVALID`.
6. **(5) залог**: наблюдатель в доверенном наборе, свидетельство выдано про этот контракт,
   подпись наблюдателя проходит, корень реестра доверен. Каждый из этих четырёх отказов
   даёт `E_ESCROW_UNKNOWN`: квитанция при этом остаётся годной, поэтому называть её
   неподписанной было бы неправдой. Неизвестный тег `status` — `E_ORDER_MALFORMED`,
   затем состояние свидетельства исполняет
   `check_escrow` (§V9.7) — тот же судья и те же коды: `E_ESCROW_UNKNOWN`,
   `E_UNSUPPORTED_ASSET`, `E_ESCROW_INSUFFICIENT`, `E_REPLAY`.
7. **(6) часы**: `submission.created_at ≤ deadline` и `now ≤ deadline +`
   `PAYBACK_WINDOW_SECONDS = 3600`; иначе `E_DEADLINE_PASSED`.

## 5. Общие входы и снимок доверия

- реестр цепей: 6 описателей, `registry_root` = `382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf`
- доверенные цепи: `0,1,10,137,8453,42161`
- доверенный наблюдатель: ключ `keypair(5)`;
- верификатор: `keypair(3)`; издатель: `keypair(1)`; получатель выплаты: `keypair(2)`.
- `keypair(seed)` кладёт `seed` в первый байт и `seed xor 0xa5` в последний — соглашение
  из `docs/PAID_ORDER-VECTORS.md`, его же проверял `E-0113`;
- подпись — Ed25519 (`RFC 8032`) над байтами объекта без поля `signature`;
- подпись квитанции покрывает байты `vecdht/paid_order_receipt/v1` (28) затем `0x00` затем canonical_json(receipt);
  домен напечатан здесь, потому что мост проверяет квитанцию офлайн и не обязан
  открывать §V9.5;
- `PAYBACK_WINDOW_SECONDS` = 3600, `AXIOM_ALLOWLIST` = [propext, Classical.choice, Quot.sound]

### Реестр цепочек

Напечатаны и поля, и их байты, и листья: это вход для пересчёта корня без догадок.

| chain_id | name | bridge_code | settle_asset_tag | min_amount | note | canonical_bytes (hex) | leaf (hex) |
|---|---|---|---|---|---|---|---|
| 0 | `vecdht-native` | 1 | 0 | 1000 | `protocol native` | `7665636468742f636861696e5f72656769737472792f76310000000000000000000000000d0000007665636468742d6e6174697665000100000000e8030000000000000000000000000000000f00000070726f746f636f6c206e6174697665` | `730af410ccaac9d96bb5105c5be7a1965f684e2836a586b92a152cc1dea47a50` |
| 1 | `ethereum` | 2 | 1 | 1000 | `EVM-like, secp256k1` | `7665636468742f636861696e5f72656769737472792f763100000001000000000000000008000000657468657265756d000200000100e8030000000000000000000000000000001300000045564d2d6c696b652c20736563703235366b31` | `6a9f6b9b0c774bb851d52ab53ecc545056e45d494dabdbcc45e420ff5c393281` |
| 10 | `optimism` | 2 | 1 | 1000 | `EVM-like, secp256k1` | `7665636468742f636861696e5f72656769737472792f76310000000a0000000000000000080000006f7074696d69736d000200000100e8030000000000000000000000000000001300000045564d2d6c696b652c20736563703235366b31` | `9259774325417351bc395fe53ef65bd821ecec6de41b698fa73a8326ffdffb14` |
| 137 | `polygon` | 2 | 1 | 1000 | `EVM-like, secp256k1` | `7665636468742f636861696e5f72656769737472792f763100000089000000000000000007000000706f6c79676f6e000200000100e8030000000000000000000000000000001300000045564d2d6c696b652c20736563703235366b31` | `674498f39246e850887729d8992a7bcf715a922a45cc54b52fe2e3233cf93bf3` |
| 8453 | `base` | 2 | 1 | 1000 | `EVM-like, secp256k1` | `7665636468742f636861696e5f72656769737472792f76310000000521000000000000000400000062617365000200000100e8030000000000000000000000000000001300000045564d2d6c696b652c20736563703235366b31` | `b49dc7ad6d4bc819847ade9eb821c251250cc0153ef334b40b4c6354fbfdfd3c` |
| 42161 | `arbitrum` | 2 | 1 | 1000 | `EVM-like, secp256k1` | `7665636468742f636861696e5f72656769737472792f7631000000b1a40000000000000008000000617262697472756d000200000100e8030000000000000000000000000000001300000045564d2d6c696b652c20736563703235366b31` | `fe0a9938df669e657959980b2e2cc0a66540906bf05075c701341e1e16012469` |

### Байты честного требования (вектор P01)

- длина: 1310
- sha256 байтов требования: `87270a59f99faa759fd5dec12a6c2d7b7913461fd5d7c8b6665f21b09ea38fff`
- `term_hash`: `3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c`
- `order_ref`: `99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047`
- `beneficiary`: `61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af`

## 6. Векторы

Каждый блок — полный набор полей вектора: по ним требование пересобирается с нуля. Пустое
значение подписи напечатано как `-`. `outcome` — `payout` либо `reject`; `code` — напечатанный
код отказа (или `-`); он же и есть предсказание, против которого сверяется прибор.

### P01

```kv
title=Полный путь: связка, свидетельство, требование, выплата
id=P01
outcome=payout
code=-
now=1800003600
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493005e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=3c8f3e1286c0c871b505fa8781793ed00b1f95df7d0c6c7971046de22764b61f1e0ec33405d23333f8dbaa87a400d509a86a6760f9833845a1802a20d9a8d90e
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P02

```kv
title=требование без подписи бенефициара
id=P02
outcome=reject
code=E_ORDER_MALFORMED
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493005e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=-
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P03

```kv
title=term_hash требования не совпал с пересчитанным
id=P03
outcome=reject
code=E_HASH_MISMATCH
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=7777777777777777777777777777777777777777777777777777777777777777
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f76310077777777777777777777777777777777777777777777777777777777777777770099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493005e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=0c3ce3a47421e67b291be0679052a6cfe972445e73908e9aaba0505c272c5b12871b9b77c34d914610424e9ac8f3cbcd931177b44a90c8041c21ff17ae3d260d
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P04

```kv
title=квитанция заявляет pass при ненулевом exit_code
id=P04
outcome=reject
code=E_VERDICT_MISMATCH
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=1
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":1,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=9c89809144fc44f425405c06f340e9205e6e5e921c421ab1069cee5f17cb7785b5d6cb362ed32e83e91335434efebfcf34f023f02dad338e692ca7edf9618803
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a312c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d009c89809144fc44f425405c06f340e9205e6e5e921c421ab1069cee5f17cb7785b5d6cb362ed32e83e91335434efebfcf34f023f02dad338e692ca7edf961880300a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493005e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=8eb7b9b5d2a3bdd823b95d0d388678c9f018851e4193bd1c52788cbc30863b08855f6da12273fd8357086a671d2345b6b0fdd49c30650c41b185c3f7e5653803
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P05

```kv
title=квитанция подписана ключом, которого издатель не называл
id=P05
outcome=reject
code=E_RECEIPT_UNSIGNED
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=900c1e26f51717dad6c65a8799d87c9f07727783005b11ccb6584e5f144d5a02
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"900c1e26f51717dad6c65a8799d87c9f07727783005b11ccb6584e5f144d5a02","wall_clock_ms":41000}
receipt.signature_hex=898d963562c3b9f59a51eace695987088115f09607470f22886e60366acd047efa49a1ce49e92b7e30d8c71e594c38825f8cc196ea632cb9a9144404da1c8806
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2239303063316532366635313731376461643663363561383739396438376339663037373237373833303035623131636362363538346535663134346435613032222c2277616c6c5f636c6f636b5f6d73223a34313030307d00898d963562c3b9f59a51eace695987088115f09607470f22886e60366acd047efa49a1ce49e92b7e30d8c71e594c38825f8cc196ea632cb9a9144404da1c880600a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493005e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=7446c297601fa001a42abdc71cd7e0ccec85ce39e4dd358df2691c879b9634cb30aaf540081b97ff93080608b37dcd0f96b0d82d95f221c858fa2127992a2c07
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P06

```kv
title=квитанция в требовании без подписи
id=P06
outcome=reject
code=E_RECEIPT_UNSIGNED
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=-
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=-
claim.canonical_len=не_кодируется:E_RECEIPT_UNSIGNED
claim.signature_hex=-
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P07

```kv
title=связка верификатора не подписана издателем
id=P07
outcome=reject
code=E_RECEIPT_INVALID
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=-
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=-
claim.canonical_len=не_кодируется:E_RECEIPT_INVALID
claim.signature_hex=-
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P08

```kv
title=залог меньше обещанного
id=P08
outcome=reject
code=E_ESCROW_INSUFFICIENT
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=999999
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0005210000000000000001003f420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=ea60206e5c9e75cf6e20c6cb742d4f9f1b3eb776d73d44cf9e88a769fea629759883aec9ea7c1806dcad31e05f550a3fe6811cca98388e6c7902a354337c9e09
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0005210000000000000001003f420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e49300ea60206e5c9e75cf6e20c6cb742d4f9f1b3eb776d73d44cf9e88a769fea629759883aec9ea7c1806dcad31e05f550a3fe6811cca98388e6c7902a354337c9e090061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=be7e1eaba8d7cbb50584ee96c7acdfb407f279e03a45982081fc26ca260730be9bce2f31f37665c12f95e7d635c37202e2720fe9e59f4b5e26e05bcf7f662702
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P09

```kv
title=корень реестра в свидетельстве не доверен
id=P09
outcome=reject
code=E_ESCROW_UNKNOWN
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=5555555555555555555555555555555555555555555555555555555555555555
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a3138343030303030005555555555555555555555555555555555555555555555555555555555555555009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=4232adb4dfd4add2036f1f337ef9ed5c59021c88c0a51df4d74f3e76830c13f2cd8bd1841e026fd2f352958ab0e30265a4549ad9e1eb8c033215a1b5a585b105
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a3138343030303030005555555555555555555555555555555555555555555555555555555555555555009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493004232adb4dfd4add2036f1f337ef9ed5c59021c88c0a51df4d74f3e76830c13f2cd8bd1841e026fd2f352958ab0e30265a4549ad9e1eb8c033215a1b5a585b1050061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=cb46021f9c586fabaaa105bac0f02497da894d42e0356a051f4d5aed5200f3f802b48cfa00db6a16a192323a8640821b4e2b8be2a2aac0e050339f70d4ef3e0f
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P10

```kv
title=свидетельство выдал наблюдатель вне доверенного набора
id=P10
outcome=reject
code=E_ESCROW_UNKNOWN
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=8fc533ee5602b1f0ed2afb32596905d7d4ea7d2afc804388a8c3d2f7a20291ab
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf008fc533ee5602b1f0ed2afb32596905d7d4ea7d2afc804388a8c3d2f7a20291ab
witness.signature_hex=5c80aae9d6a401f3bf5d623ca8fbe5a95569483bfe9f292944677e9023ea78170b4a0703203f2f753001aae7901f9b6e6c9c1c59fad4b55d6140e4c931c5e508
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf008fc533ee5602b1f0ed2afb32596905d7d4ea7d2afc804388a8c3d2f7a20291ab005c80aae9d6a401f3bf5d623ca8fbe5a95569483bfe9f292944677e9023ea78170b4a0703203f2f753001aae7901f9b6e6c9c1c59fad4b55d6140e4c931c5e5080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=b0d269a1edfffbd2c29dc9fc625a5a0ba47767833448c7c449829a3f41bed9031c214a153460ed4b2f6743117e321c8181c46f8269d2124ad6436b16a9684505
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P11

```kv
title=свидетельство назвало неизвестный тег состояния
id=P11
outcome=reject
code=E_ORDER_MALFORMED
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=9
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000090040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=4d7a7eca18abd8b9d971ce934cf0f8e9bfbf667f98e04d9b812a8e4dcb67b0e91f21d1aee35b64993f8c7dc61e2d780cbcbbed7ab482a7a62b4685c3badc030e
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000090040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493004d7a7eca18abd8b9d971ce934cf0f8e9bfbf667f98e04d9b812a8e4dcb67b0e91f21d1aee35b64993f8c7dc61e2d780cbcbbed7ab482a7a62b4685c3badc030e0061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=17e75496908a5e3cc21e20825d5799b9fd82b3019fb9b17d3de5f7e0c2ca9c04830643396cb59adfc984a755cb43312d950330600138bafde88c2fba0447fd0f
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P12

```kv
title=требование после окна выплаты
id=P12
outcome=reject
code=E_DEADLINE_PASSED
now=1800003601
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493005e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=3c8f3e1286c0c871b505fa8781793ed00b1f95df7d0c6c7971046de22764b61f1e0ec33405d23333f8dbaa87a400d509a86a6760f9833845a1802a20d9a8d90e
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P13

```kv
title=подача позже срока заказа
id=P13
outcome=reject
code=E_DEADLINE_PASSED
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1800000001
sub.signature_hex=be72346c296a42dfa85951fb8546b12a5e8c8c525e8363e125fec9514f979985e8ca3739f93c5c5b16e75f4768becea4c1b3c70d1a5ad0942dab749539e37d0b
submission_ref=271ccfc1a941ecbd44a1322eeaa55554c792f91a2c8439de6a6f6341a98af202
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=271ccfc1a941ecbd44a1322eeaa55554c792f91a2c8439de6a6f6341a98af202
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"271ccfc1a941ecbd44a1322eeaa55554c792f91a2c8439de6a6f6341a98af202","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=65a6605067c6393deee249c93c01862e38217840eca9ad374c4d9a150e243b4be90336254711bb95ec9288fdaeb98b3f28688df406f29050cf0446c46f007503
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2232373163636663316139343165636264343461313332326565616135353535346337393266393161326338343339646536613666363334316139386166323032222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d0065a6605067c6393deee249c93c01862e38217840eca9ad374c4d9a150e243b4be90336254711bb95ec9288fdaeb98b3f28688df406f29050cf0446c46f00750300a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493005e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=5875ddba6c2f8e0c53cf1a2f133f6976a172148a126a8329b95f6917d82f3c55d63ae1505afb2ccbc07bda4a00fbc65990a6e0028a2d115a60288fe5e2f70f04
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P14

```kv
title=цепь 0: повторное требование на released, а не вторая выплата
id=P14
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=0
order.asset_chain_id=0
order.asset_address=-
order.escrow_ref_hex=636861696e303a657363726f772f30303030
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f0000000000000000000000000000000012000000636861696e303a657363726f772f303030300000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=292088ccdce2a3ea9249668095968b2573106d6911ff2b4f3b5a20fc610b5f4c61fe9f99efa533e7e21f8539489077befecd35a3ea5796e38cefb212a9fa810e
order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
sub.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=d9c1c8fc8abcf455939def720cc4449677109946b98f5534cd3e9190a95c19e84f113b97bfb0dde1bf91b97fa644cc0b70d5856974f74380e208017b0dea5b0f
submission_ref=b34ce42b7785efa09ffc1db359bcbcff3c4eb0ca8aeafd54694285ebe94e5e0d
receipt.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
receipt.submission_ref=b34ce42b7785efa09ffc1db359bcbcff3c4eb0ca8aeafd54694285ebe94e5e0d
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"b34ce42b7785efa09ffc1db359bcbcff3c4eb0ca8aeafd54694285ebe94e5e0d","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=f88d22bb88621a2a35cfa41a3b3fbc9656a5ba05fb6bd1c588a460680c8c555442319249dbdb5b18504f5404fde0caf23346dc05bd2ad09e3fc01a5e107e0b01
binding.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f763100610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc000d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
binding.signature_hex=ea20a21f331e3f05cdf766607e2c599be2a38794e5ba70cf3e9360aa44a2d51382a4edbeb023740fbeb59994172314c257092961c77fda9e812c6fe128c8c50e
witness.term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
witness.chain_id=0
witness.status=2
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400000000000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=4bb689c2092973b45235560e47008d938fc1550662b1d31e4afc82b5a6b5f77886c06e8c616561f1664f6534d2a5cb7517bb08c6c20a28b8973a6678c151e803
claim.term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
claim.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc000890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2236313037353165343334663537313831333965376430303736613461383735633934383761646636353131633734313935663433313133396237346437626330222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2262333463653432623737383565666130396666633164623335396263626366663363346562306361386165616664353436393432383565626539346535653064222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00f88d22bb88621a2a35cfa41a3b3fbc9656a5ba05fb6bd1c588a460680c8c555442319249dbdb5b18504f5404fde0caf23346dc05bd2ad09e3fc01a5e107e0b0100a00000007665636468742f706169645f6f726465725f62696e64696e672f763100610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc000d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400ea20a21f331e3f05cdf766607e2c599be2a38794e5ba70cf3e9360aa44a2d51382a4edbeb023740fbeb59994172314c257092961c77fda9e812c6fe128c8c50e00aa0000007665636468742f657363726f775f7769746e6573732f7631003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400000000000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493004bb689c2092973b45235560e47008d938fc1550662b1d31e4afc82b5a6b5f77886c06e8c616561f1664f6534d2a5cb7517bb08c6c20a28b8973a6678c151e8030061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=bc1c87c545d2dc3607fa5f92d9b9e8ee5943b06bf669cc945ddc88c0f20d52b3f0823764068e60d9eae20dd8bc811994efd7d19f4e7d5b36eb3608be5a82990d
term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P15

```kv
title=цепь 0: повторное требование на refunded, а не вторая выплата
id=P15
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=0
order.asset_chain_id=0
order.asset_address=-
order.escrow_ref_hex=636861696e303a657363726f772f30303030
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f0000000000000000000000000000000012000000636861696e303a657363726f772f303030300000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=292088ccdce2a3ea9249668095968b2573106d6911ff2b4f3b5a20fc610b5f4c61fe9f99efa533e7e21f8539489077befecd35a3ea5796e38cefb212a9fa810e
order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
sub.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=d9c1c8fc8abcf455939def720cc4449677109946b98f5534cd3e9190a95c19e84f113b97bfb0dde1bf91b97fa644cc0b70d5856974f74380e208017b0dea5b0f
submission_ref=b34ce42b7785efa09ffc1db359bcbcff3c4eb0ca8aeafd54694285ebe94e5e0d
receipt.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
receipt.submission_ref=b34ce42b7785efa09ffc1db359bcbcff3c4eb0ca8aeafd54694285ebe94e5e0d
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"b34ce42b7785efa09ffc1db359bcbcff3c4eb0ca8aeafd54694285ebe94e5e0d","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=f88d22bb88621a2a35cfa41a3b3fbc9656a5ba05fb6bd1c588a460680c8c555442319249dbdb5b18504f5404fde0caf23346dc05bd2ad09e3fc01a5e107e0b01
binding.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f763100610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc000d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
binding.signature_hex=ea20a21f331e3f05cdf766607e2c599be2a38794e5ba70cf3e9360aa44a2d51382a4edbeb023740fbeb59994172314c257092961c77fda9e812c6fe128c8c50e
witness.term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
witness.chain_id=0
witness.status=3
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400000000000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=20939bad693b62c000de1f829ec4ea786ce6f9027d2f203cffc04f8ca009aaf08c41b35e8b3dd06c116d0090d53bb18116967c50d894ed6eb4e715c468eab602
claim.term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
claim.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc000890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2236313037353165343334663537313831333965376430303736613461383735633934383761646636353131633734313935663433313133396237346437626330222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2262333463653432623737383565666130396666633164623335396263626366663363346562306361386165616664353436393432383565626539346535653064222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00f88d22bb88621a2a35cfa41a3b3fbc9656a5ba05fb6bd1c588a460680c8c555442319249dbdb5b18504f5404fde0caf23346dc05bd2ad09e3fc01a5e107e0b0100a00000007665636468742f706169645f6f726465725f62696e64696e672f763100610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc000d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400ea20a21f331e3f05cdf766607e2c599be2a38794e5ba70cf3e9360aa44a2d51382a4edbeb023740fbeb59994172314c257092961c77fda9e812c6fe128c8c50e00aa0000007665636468742f657363726f775f7769746e6573732f7631003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400000000000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e4930020939bad693b62c000de1f829ec4ea786ce6f9027d2f203cffc04f8ca009aaf08c41b35e8b3dd06c116d0090d53bb18116967c50d894ed6eb4e715c468eab6020061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=53f7a1b274be4468aa5b43b30e3910b9d15f5badf966c90849ffd2c63b643bb1cfad8fc6df1b14446eb53d1453feec7bc44b992fb6db9d85fb31aab123bb330b
term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P16

```kv
title=цепь 1: повторное требование на released, а не вторая выплата
id=P16
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=1
order.asset_address=0101010101010101010101010101010101010101
order.escrow_ref_hex=636861696e313a657363726f772f30303031
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001010000000000000001010101010101010101010101010101010101010012000000636861696e313a657363726f772f303030310000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=c0e32b11646a49c1ded895de54d26b5cba3580c3c8b7dfe2895a7feff359f760275192171c53d9caaa010e4304062b6f7dbb471b31e294d08b66d774750f3405
order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
sub.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=69c7880082229d7ced2ca1ed1362702b9fed8f0c9f88f7830264c351a8987a748b704855e92162125a99280a8d8c14eb1cc0d3be5a08e541adde5f9ae5cbd604
submission_ref=dde240342bbe17a8d6e04913606a302ac65ce4b01e6138b56c9b2894fd80bcc4
receipt.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
receipt.submission_ref=dde240342bbe17a8d6e04913606a302ac65ce4b01e6138b56c9b2894fd80bcc4
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"dde240342bbe17a8d6e04913606a302ac65ce4b01e6138b56c9b2894fd80bcc4","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=338f88b098b9d0be21d1a19e47929ed69dde66c6841033de7e3c9362bec5013ec9ec9bfd9120834b4b60068f1b8ed237cb490f42bd1d978b77eb13c3bf75ed0b
binding.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310017d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
binding.signature_hex=e05fa2d2049f2ab0bfd1de59ee16dbf7b3a660ff1c0808fc985f3ed3e694af0f168319c94c9b224700404d179159d604f76b4b6ac5af929331b34dfdc5ba520e
witness.term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
witness.chain_id=1
witness.status=2
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f763100745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc00010000000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=43a70fd8fc393e4f5c0078561a62f6f2eadd4b2230b2d0e0b4aa5a4c91f90de9533ed671349dafe77945f327e1b0744a94ffef83e188d6d3a89297c47d864604
claim.term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
claim.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f763100745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc0017d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b00890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2231376438643432356432336132343632353065373136396433303231613665646531343464663330356239303638656535396663323665333938646539633362222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2264646532343033343262626531376138643665303439313336303661333032616336356365346230316536313338623536633962323839346664383062636334222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00338f88b098b9d0be21d1a19e47929ed69dde66c6841033de7e3c9362bec5013ec9ec9bfd9120834b4b60068f1b8ed237cb490f42bd1d978b77eb13c3bf75ed0b00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310017d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc00e05fa2d2049f2ab0bfd1de59ee16dbf7b3a660ff1c0808fc985f3ed3e694af0f168319c94c9b224700404d179159d604f76b4b6ac5af929331b34dfdc5ba520e00aa0000007665636468742f657363726f775f7769746e6573732f763100745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc00010000000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e4930043a70fd8fc393e4f5c0078561a62f6f2eadd4b2230b2d0e0b4aa5a4c91f90de9533ed671349dafe77945f327e1b0744a94ffef83e188d6d3a89297c47d8646040061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=7e31fed85cf2c315960b45d2fdb5bbf8c3411370c43ffb5c49e97f4078e65d5207f692f5c446e06a0cad2d34de18b5627c0eaf834640d84d1e408e0aeba18a06
term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P17

```kv
title=цепь 1: повторное требование на refunded, а не вторая выплата
id=P17
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=1
order.asset_address=0101010101010101010101010101010101010101
order.escrow_ref_hex=636861696e313a657363726f772f30303031
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001010000000000000001010101010101010101010101010101010101010012000000636861696e313a657363726f772f303030310000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=c0e32b11646a49c1ded895de54d26b5cba3580c3c8b7dfe2895a7feff359f760275192171c53d9caaa010e4304062b6f7dbb471b31e294d08b66d774750f3405
order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
sub.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=69c7880082229d7ced2ca1ed1362702b9fed8f0c9f88f7830264c351a8987a748b704855e92162125a99280a8d8c14eb1cc0d3be5a08e541adde5f9ae5cbd604
submission_ref=dde240342bbe17a8d6e04913606a302ac65ce4b01e6138b56c9b2894fd80bcc4
receipt.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
receipt.submission_ref=dde240342bbe17a8d6e04913606a302ac65ce4b01e6138b56c9b2894fd80bcc4
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"dde240342bbe17a8d6e04913606a302ac65ce4b01e6138b56c9b2894fd80bcc4","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=338f88b098b9d0be21d1a19e47929ed69dde66c6841033de7e3c9362bec5013ec9ec9bfd9120834b4b60068f1b8ed237cb490f42bd1d978b77eb13c3bf75ed0b
binding.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310017d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
binding.signature_hex=e05fa2d2049f2ab0bfd1de59ee16dbf7b3a660ff1c0808fc985f3ed3e694af0f168319c94c9b224700404d179159d604f76b4b6ac5af929331b34dfdc5ba520e
witness.term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
witness.chain_id=1
witness.status=3
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f763100745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc00010000000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5f4051e9328fb33a04791bb21a5ad315a108cceef65cfc1568f86bbac356130005b491f398eab6fe2117daecd9d362a470941469c04a3734909949028a298c09
claim.term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
claim.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f763100745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc0017d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b00890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2231376438643432356432336132343632353065373136396433303231613665646531343464663330356239303638656535396663323665333938646539633362222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2264646532343033343262626531376138643665303439313336303661333032616336356365346230316536313338623536633962323839346664383062636334222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00338f88b098b9d0be21d1a19e47929ed69dde66c6841033de7e3c9362bec5013ec9ec9bfd9120834b4b60068f1b8ed237cb490f42bd1d978b77eb13c3bf75ed0b00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310017d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc00e05fa2d2049f2ab0bfd1de59ee16dbf7b3a660ff1c0808fc985f3ed3e694af0f168319c94c9b224700404d179159d604f76b4b6ac5af929331b34dfdc5ba520e00aa0000007665636468742f657363726f775f7769746e6573732f763100745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc00010000000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493005f4051e9328fb33a04791bb21a5ad315a108cceef65cfc1568f86bbac356130005b491f398eab6fe2117daecd9d362a470941469c04a3734909949028a298c090061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=4a2946ae80129931e31af9e5cba4adc796d3966dabb9d8ebca8ee3d3fdb712ab3c0cf4aecc454bac40e4c6703c5f4f855f87b447e021124f814daabacacb420d
term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P18

```kv
title=цепь 10: повторное требование на released, а не вторая выплата
id=P18
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=10
order.asset_address=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a
order.escrow_ref_hex=636861696e31303a657363726f772f30303061
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f0000000000000000000000000000010a000000000000000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0013000000636861696e31303a657363726f772f303030610000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=e4bfb5eb75641dff57064c5d97e1c699d1ac417dc16fe7666b955e99ecb3572e9cc506f7098af4460db10a3bc640f4e33cd1ac7010073049428fa8b2422b180d
order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
sub.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bcdf6c464e87654c922c108915f89f542f834a3df7445fbdd252adb7a7bd2db51112722f74ec04b3a3ef83fb5096c685ac924307e232b9a60b3452f8f85ab009
submission_ref=dadcd4304539c4e469e5291ef206ed160333465aa3611bc09860d4f94c8c496a
receipt.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
receipt.submission_ref=dadcd4304539c4e469e5291ef206ed160333465aa3611bc09860d4f94c8c496a
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"dadcd4304539c4e469e5291ef206ed160333465aa3611bc09860d4f94c8c496a","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=eeaf76c3770353b8e41aa738ec38138c68701492a24d32a74201a1c8dbc6a51c89dcd8a66658056739bc625a4b022784310748a9a752bda8cf197134fa865d0c
binding.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f7631003b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df346122200d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
binding.signature_hex=bb4664789f66c642b835d06a43edce75121a3f1d24cd7851e2f841cef76ebf86ed6ce9b8f5c17bd3ba43ea0e77764e04d7d7fdf70d654f17fbb1545b2838ef02
witness.term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
witness.chain_id=10
witness.status=2
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146000a0000000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=bc922adc00cde0ffc86b5f09dbc2c4e4bd5ed898f58e189f47e31712b7fbe6b143ddf484f45952e7f20eabdb3b0cf77325386fe95bd3a5a32388ee0fe9a59a08
claim.term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
claim.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146003b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df346122200890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2233623361633832623935356266643633396431373133306262303762326364626266643864623130636466373134303233636361303239646633343631323232222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2264616463643433303435333963346534363965353239316566323036656431363033333334363561613336313162633039383630643466393463386334393661222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00eeaf76c3770353b8e41aa738ec38138c68701492a24d32a74201a1c8dbc6a51c89dcd8a66658056739bc625a4b022784310748a9a752bda8cf197134fa865d0c00a00000007665636468742f706169645f6f726465725f62696e64696e672f7631003b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df346122200d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b14600bb4664789f66c642b835d06a43edce75121a3f1d24cd7851e2f841cef76ebf86ed6ce9b8f5c17bd3ba43ea0e77764e04d7d7fdf70d654f17fbb1545b2838ef0200aa0000007665636468742f657363726f775f7769746e6573732f7631007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146000a0000000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e49300bc922adc00cde0ffc86b5f09dbc2c4e4bd5ed898f58e189f47e31712b7fbe6b143ddf484f45952e7f20eabdb3b0cf77325386fe95bd3a5a32388ee0fe9a59a080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=cf42deaade4d839eb98d9e87843531846e6807f3b445562209f712e3e4d372b4dbe10dcefffe8be5df8351cd5fad412678fcd6357ad880249dc6400fcd202302
term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P19

```kv
title=цепь 10: повторное требование на refunded, а не вторая выплата
id=P19
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=10
order.asset_address=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a
order.escrow_ref_hex=636861696e31303a657363726f772f30303061
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f0000000000000000000000000000010a000000000000000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0013000000636861696e31303a657363726f772f303030610000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=e4bfb5eb75641dff57064c5d97e1c699d1ac417dc16fe7666b955e99ecb3572e9cc506f7098af4460db10a3bc640f4e33cd1ac7010073049428fa8b2422b180d
order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
sub.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bcdf6c464e87654c922c108915f89f542f834a3df7445fbdd252adb7a7bd2db51112722f74ec04b3a3ef83fb5096c685ac924307e232b9a60b3452f8f85ab009
submission_ref=dadcd4304539c4e469e5291ef206ed160333465aa3611bc09860d4f94c8c496a
receipt.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
receipt.submission_ref=dadcd4304539c4e469e5291ef206ed160333465aa3611bc09860d4f94c8c496a
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"dadcd4304539c4e469e5291ef206ed160333465aa3611bc09860d4f94c8c496a","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=eeaf76c3770353b8e41aa738ec38138c68701492a24d32a74201a1c8dbc6a51c89dcd8a66658056739bc625a4b022784310748a9a752bda8cf197134fa865d0c
binding.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f7631003b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df346122200d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
binding.signature_hex=bb4664789f66c642b835d06a43edce75121a3f1d24cd7851e2f841cef76ebf86ed6ce9b8f5c17bd3ba43ea0e77764e04d7d7fdf70d654f17fbb1545b2838ef02
witness.term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
witness.chain_id=10
witness.status=3
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146000a0000000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=20780c3183b2a8e3f73c20c7ec8762294e62b7c7ffffa2c4f11f26846305cff59f3918f558a3c7712c8e3c4a416967ed64ee5355d1c67fc679ca150dacdaaf00
claim.term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
claim.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146003b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df346122200890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2233623361633832623935356266643633396431373133306262303762326364626266643864623130636466373134303233636361303239646633343631323232222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2264616463643433303435333963346534363965353239316566323036656431363033333334363561613336313162633039383630643466393463386334393661222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00eeaf76c3770353b8e41aa738ec38138c68701492a24d32a74201a1c8dbc6a51c89dcd8a66658056739bc625a4b022784310748a9a752bda8cf197134fa865d0c00a00000007665636468742f706169645f6f726465725f62696e64696e672f7631003b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df346122200d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b14600bb4664789f66c642b835d06a43edce75121a3f1d24cd7851e2f841cef76ebf86ed6ce9b8f5c17bd3ba43ea0e77764e04d7d7fdf70d654f17fbb1545b2838ef0200aa0000007665636468742f657363726f775f7769746e6573732f7631007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146000a0000000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e4930020780c3183b2a8e3f73c20c7ec8762294e62b7c7ffffa2c4f11f26846305cff59f3918f558a3c7712c8e3c4a416967ed64ee5355d1c67fc679ca150dacdaaf000061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=ec3253829e83d4d09bb6cb83c079d78992c5e6718c3e6397e1bbac241f0263eb2042835c4cccbef0dc2f3586ce46a59dea6e87a83845d597ecc9a3cb17516507
term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P20

```kv
title=цепь 137: повторное требование на released, а не вторая выплата
id=P20
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=137
order.asset_address=8989898989898989898989898989898989898989
order.escrow_ref_hex=636861696e3133373a657363726f772f30303839
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001890000000000000089898989898989898989898989898989898989890014000000636861696e3133373a657363726f772f303038390000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=aa1cd32103b22ff5ddcd369d6bb402899d5927352d03acd69642791a52404788f30576a7d07cd6799c2785b3d4049f2049818d3ccedc4b7f3064db4dd1d9920c
order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
sub.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=87d7894b3fa7ec666eb324f116bb0d2eff5a615ea5505f1492852c19d44b1607cbed56fdecc60f53f2c0abb9ba046163efbfa5e9d2fb74a29fcb2e6dfec80500
submission_ref=dc4c1efe590b49a229a52c3cd4d9d8a44415265a00031923dcd611375cf6f98c
receipt.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
receipt.submission_ref=dc4c1efe590b49a229a52c3cd4d9d8a44415265a00031923dcd611375cf6f98c
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"dc4c1efe590b49a229a52c3cd4d9d8a44415265a00031923dcd611375cf6f98c","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=08db45b51b4f13441b54bbcf96c2dda1bf3acadc48d582b3ca056f8e35f3c2df6a97c7df14bc8bdddb683266cb44bd9857ec08fe2b1e3f4f6aceb25232f67506
binding.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f7631008200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
binding.signature_hex=7317a0d3b5cbf0ededc23d68d4d9bd42bcfd450e0c94c6b1feb4552880d9181b80f5ccb7bdaf14915bcc1e5c6db9a545109daa2c7146fb3eceb1f4a592215906
witness.term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
witness.chain_id=137
witness.status=2
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f763100b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af00890000000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=e5dce23390f9fde44a98f4c7d9f23f0870db7a447d79235e48dab2fcc88bd92f12a9514223a0ec538f06fe47eaef1d84a8a27c5944cf1f7469719da66e597005
claim.term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
claim.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f763100b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af008200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d00890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2238323030613439343232616661313766663365333136393365353836356461346631306233656130363536633538393831616438366437663433373131303164222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2264633463316566653539306234396132323961353263336364346439643861343434313532363561303030333139323364636436313133373563663666393863222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d0008db45b51b4f13441b54bbcf96c2dda1bf3acadc48d582b3ca056f8e35f3c2df6a97c7df14bc8bdddb683266cb44bd9857ec08fe2b1e3f4f6aceb25232f6750600a00000007665636468742f706169645f6f726465725f62696e64696e672f7631008200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af007317a0d3b5cbf0ededc23d68d4d9bd42bcfd450e0c94c6b1feb4552880d9181b80f5ccb7bdaf14915bcc1e5c6db9a545109daa2c7146fb3eceb1f4a59221590600aa0000007665636468742f657363726f775f7769746e6573732f763100b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af00890000000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e49300e5dce23390f9fde44a98f4c7d9f23f0870db7a447d79235e48dab2fcc88bd92f12a9514223a0ec538f06fe47eaef1d84a8a27c5944cf1f7469719da66e5970050061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=bea6e2f9d07c42d041e2487af2c94ab22442a62eacb22ffe1d05a4f02e7705322e28caebd6c6fd226718667146ba850fbe06868e29efddac93e6cfa6ce6c2b0f
term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P21

```kv
title=цепь 137: повторное требование на refunded, а не вторая выплата
id=P21
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=137
order.asset_address=8989898989898989898989898989898989898989
order.escrow_ref_hex=636861696e3133373a657363726f772f30303839
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001890000000000000089898989898989898989898989898989898989890014000000636861696e3133373a657363726f772f303038390000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=aa1cd32103b22ff5ddcd369d6bb402899d5927352d03acd69642791a52404788f30576a7d07cd6799c2785b3d4049f2049818d3ccedc4b7f3064db4dd1d9920c
order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
sub.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=87d7894b3fa7ec666eb324f116bb0d2eff5a615ea5505f1492852c19d44b1607cbed56fdecc60f53f2c0abb9ba046163efbfa5e9d2fb74a29fcb2e6dfec80500
submission_ref=dc4c1efe590b49a229a52c3cd4d9d8a44415265a00031923dcd611375cf6f98c
receipt.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
receipt.submission_ref=dc4c1efe590b49a229a52c3cd4d9d8a44415265a00031923dcd611375cf6f98c
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"dc4c1efe590b49a229a52c3cd4d9d8a44415265a00031923dcd611375cf6f98c","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=08db45b51b4f13441b54bbcf96c2dda1bf3acadc48d582b3ca056f8e35f3c2df6a97c7df14bc8bdddb683266cb44bd9857ec08fe2b1e3f4f6aceb25232f67506
binding.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f7631008200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
binding.signature_hex=7317a0d3b5cbf0ededc23d68d4d9bd42bcfd450e0c94c6b1feb4552880d9181b80f5ccb7bdaf14915bcc1e5c6db9a545109daa2c7146fb3eceb1f4a592215906
witness.term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
witness.chain_id=137
witness.status=3
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f763100b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af00890000000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=550679268c1d8ff0c8a930767eab7ad35232721ae638848e97e9adf114e32b7fddc786a9ae173031cdb6c06f7bd36c19c651cbe30daf26102d89f7149fda1605
claim.term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
claim.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f763100b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af008200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d00890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2238323030613439343232616661313766663365333136393365353836356461346631306233656130363536633538393831616438366437663433373131303164222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2264633463316566653539306234396132323961353263336364346439643861343434313532363561303030333139323364636436313133373563663666393863222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d0008db45b51b4f13441b54bbcf96c2dda1bf3acadc48d582b3ca056f8e35f3c2df6a97c7df14bc8bdddb683266cb44bd9857ec08fe2b1e3f4f6aceb25232f6750600a00000007665636468742f706169645f6f726465725f62696e64696e672f7631008200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af007317a0d3b5cbf0ededc23d68d4d9bd42bcfd450e0c94c6b1feb4552880d9181b80f5ccb7bdaf14915bcc1e5c6db9a545109daa2c7146fb3eceb1f4a59221590600aa0000007665636468742f657363726f775f7769746e6573732f763100b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af00890000000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e49300550679268c1d8ff0c8a930767eab7ad35232721ae638848e97e9adf114e32b7fddc786a9ae173031cdb6c06f7bd36c19c651cbe30daf26102d89f7149fda16050061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=2c890712ff12fa6e2924cc480f89e7c1d83ceff884f9e5a01203ae7407b9da7e46b7d9dfe8d9a7a7b932a8c77ac855f763d6d4fcdc9c04e23c7697368ccb300c
term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P22

```kv
title=цепь 8453: повторное требование на released, а не вторая выплата
id=P22
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=2
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=f8c1f63b20e833417bc04f17541cd25b8c0ec679f648e52098dd37bb05a58b5c3fd926f514b8143f9cebd3182327f4bae92c331a7805fe4084e3f0efbae7c60a
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e49300f8c1f63b20e833417bc04f17541cd25b8c0ec679f648e52098dd37bb05a58b5c3fd926f514b8143f9cebd3182327f4bae92c331a7805fe4084e3f0efbae7c60a0061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=a12c9e255b2548524bbcce000f424e7d9b15d9321dd883c08e3280bfb42fb2933278c43d53817f5b8863443159a38342ca4ccbcdfea270d873bcacd045645a03
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P23

```kv
title=цепь 8453: повторное требование на refunded, а не вторая выплата
id=P23
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=3
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=e3d3afd78a24ed94619c571064ffe202e1d3049d7a287588555772023c8169625cf6cbcceac09d45627bf08aa0bd688e4cfadbc9afac27e38afce46417022608
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e49300e3d3afd78a24ed94619c571064ffe202e1d3049d7a287588555772023c8169625cf6cbcceac09d45627bf08aa0bd688e4cfadbc9afac27e38afce464170226080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=b7c8ec615e7465c1031e7c310158408438af94c7da45b6814d233447c42df4ff4bba516c2bf85c57c4df4d1864abbd035c07eecc9dae4b03f811f231b6fb530a
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P24

```kv
title=цепь 42161: повторное требование на released, а не вторая выплата
id=P24
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=42161
order.asset_address=b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1
order.escrow_ref_hex=636861696e34323136313a657363726f772f61346231
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001b1a4000000000000b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b10016000000636861696e34323136313a657363726f772f613462310000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=45ddb4a4b7175c58be612fc9b9aecaf67fd6f298e9aa3239133575fea00190993d8e2df90be793b1ddaac623177e5aacbc2c95d7253c1dc315bfb5337dc16c04
order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
sub.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=3406b426a55a049ce44529415993ff952e787718b4662bc1ee503bf6e308f04ebc3c0be603868e86d7d8652c6991c9feb64d2d2683dc8e04c999827555da680f
submission_ref=22d600649c404db5992c1e13f1a2f2f841c98dc9034ec9909d0b6268e186f5e2
receipt.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
receipt.submission_ref=22d600649c404db5992c1e13f1a2f2f841c98dc9034ec9909d0b6268e186f5e2
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"22d600649c404db5992c1e13f1a2f2f841c98dc9034ec9909d0b6268e186f5e2","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=2cbc0e2d9a8f22a63e222aab0a27220e9f30f093a0eaeaa98aee1b7bbed447f52fc2dbf07a337cf32a729ae77159b8afc89bd0fc98fe84af9b3954eb7155760d
binding.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f763100a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
binding.signature_hex=3753f10d909a1e79c13adc3428b00bab35530878097fee66201714ca672b5dae86802935537147920aa47bda5e2c775f4d3021be16f9f4a22e7fe68f51d18c04
witness.term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
witness.chain_id=42161
witness.status=2
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f763100c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde00b1a400000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=45e054be4b6b78a98150c3fde539cb71d5c87cc45435fa69b26e07442b007d07710c4ae4c4f1c26c052bd3dff044b5c5c97fbfc83c7699f85acea92ea7719c0c
claim.term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
claim.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f763100c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde00a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b00890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2261376461353937393834303236343231396131313237323065656631383065303865633533656364316364653337356639646133323033303333313163643562222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2232326436303036343963343034646235393932633165313366316132663266383431633938646339303334656339393039643062363236386531383666356532222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d002cbc0e2d9a8f22a63e222aab0a27220e9f30f093a0eaeaa98aee1b7bbed447f52fc2dbf07a337cf32a729ae77159b8afc89bd0fc98fe84af9b3954eb7155760d00a00000007665636468742f706169645f6f726465725f62696e64696e672f763100a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde003753f10d909a1e79c13adc3428b00bab35530878097fee66201714ca672b5dae86802935537147920aa47bda5e2c775f4d3021be16f9f4a22e7fe68f51d18c0400aa0000007665636468742f657363726f775f7769746e6573732f763100c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde00b1a400000000000000020040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e4930045e054be4b6b78a98150c3fde539cb71d5c87cc45435fa69b26e07442b007d07710c4ae4c4f1c26c052bd3dff044b5c5c97fbfc83c7699f85acea92ea7719c0c0061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=1697b39ad2dfaacceb9e46c323a07968f60fef32eb18b421d29cdc75d06f841b95f26b85daa00bcc7725b54cc3f86c480bb6be197ce7441c7b66c2792ffe810d
term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P25

```kv
title=цепь 42161: повторное требование на refunded, а не вторая выплата
id=P25
outcome=reject
code=E_REPLAY
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=42161
order.asset_address=b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1
order.escrow_ref_hex=636861696e34323136313a657363726f772f61346231
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001b1a4000000000000b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b10016000000636861696e34323136313a657363726f772f613462310000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=45ddb4a4b7175c58be612fc9b9aecaf67fd6f298e9aa3239133575fea00190993d8e2df90be793b1ddaac623177e5aacbc2c95d7253c1dc315bfb5337dc16c04
order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
sub.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=3406b426a55a049ce44529415993ff952e787718b4662bc1ee503bf6e308f04ebc3c0be603868e86d7d8652c6991c9feb64d2d2683dc8e04c999827555da680f
submission_ref=22d600649c404db5992c1e13f1a2f2f841c98dc9034ec9909d0b6268e186f5e2
receipt.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
receipt.submission_ref=22d600649c404db5992c1e13f1a2f2f841c98dc9034ec9909d0b6268e186f5e2
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"22d600649c404db5992c1e13f1a2f2f841c98dc9034ec9909d0b6268e186f5e2","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=2cbc0e2d9a8f22a63e222aab0a27220e9f30f093a0eaeaa98aee1b7bbed447f52fc2dbf07a337cf32a729ae77159b8afc89bd0fc98fe84af9b3954eb7155760d
binding.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f763100a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
binding.signature_hex=3753f10d909a1e79c13adc3428b00bab35530878097fee66201714ca672b5dae86802935537147920aa47bda5e2c775f4d3021be16f9f4a22e7fe68f51d18c04
witness.term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
witness.chain_id=42161
witness.status=3
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f763100c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde00b1a400000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=9a569f43a002a8ee38c823b23beddca8376144a38f5c94492ce6316a9f19ee8960131111a7f324441e0f7914860cd7b469f6ce7c690316925a3228f647a19d0d
claim.term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
claim.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f763100c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde00a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b00890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2261376461353937393834303236343231396131313237323065656631383065303865633533656364316364653337356639646133323033303333313163643562222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2232326436303036343963343034646235393932633165313366316132663266383431633938646339303334656339393039643062363236386531383666356532222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d002cbc0e2d9a8f22a63e222aab0a27220e9f30f093a0eaeaa98aee1b7bbed447f52fc2dbf07a337cf32a729ae77159b8afc89bd0fc98fe84af9b3954eb7155760d00a00000007665636468742f706169645f6f726465725f62696e64696e672f763100a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde003753f10d909a1e79c13adc3428b00bab35530878097fee66201714ca672b5dae86802935537147920aa47bda5e2c775f4d3021be16f9f4a22e7fe68f51d18c0400aa0000007665636468742f657363726f775f7769746e6573732f763100c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde00b1a400000000000000030040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493009a569f43a002a8ee38c823b23beddca8376144a38f5c94492ce6316a9f19ee8960131111a7f324441e0f7914860cd7b469f6ce7c690316925a3228f647a19d0d0061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=f906872d218ef9d5dd70411507ab17e6fc96ab8dfa9a9acd1cf176ff4007c969b8e25d741c05dcbf6adb219d37e1fb1a065773810686ef8338829436c7756a06
term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P26

```kv
title=цепь 0: выплата проходит, когда залог залочен и реестр доверен
id=P26
outcome=payout
code=-
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=0
order.asset_chain_id=0
order.asset_address=-
order.escrow_ref_hex=636861696e303a657363726f772f30303030
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f0000000000000000000000000000000012000000636861696e303a657363726f772f303030300000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=292088ccdce2a3ea9249668095968b2573106d6911ff2b4f3b5a20fc610b5f4c61fe9f99efa533e7e21f8539489077befecd35a3ea5796e38cefb212a9fa810e
order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
sub.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=d9c1c8fc8abcf455939def720cc4449677109946b98f5534cd3e9190a95c19e84f113b97bfb0dde1bf91b97fa644cc0b70d5856974f74380e208017b0dea5b0f
submission_ref=b34ce42b7785efa09ffc1db359bcbcff3c4eb0ca8aeafd54694285ebe94e5e0d
receipt.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
receipt.submission_ref=b34ce42b7785efa09ffc1db359bcbcff3c4eb0ca8aeafd54694285ebe94e5e0d
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"b34ce42b7785efa09ffc1db359bcbcff3c4eb0ca8aeafd54694285ebe94e5e0d","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=f88d22bb88621a2a35cfa41a3b3fbc9656a5ba05fb6bd1c588a460680c8c555442319249dbdb5b18504f5404fde0caf23346dc05bd2ad09e3fc01a5e107e0b01
binding.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f763100610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc000d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
binding.signature_hex=ea20a21f331e3f05cdf766607e2c599be2a38794e5ba70cf3e9360aa44a2d51382a4edbeb023740fbeb59994172314c257092961c77fda9e812c6fe128c8c50e
witness.term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
witness.chain_id=0
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400000000000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=39add9a7514d647c40f5799c170cde23ea54850d3a82eb12b39f54e076d150a44c81ccbea27340558dd3f10380aa790e205fb40aefdfb564eb3928e5fa93880f
claim.term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
claim.order_ref=610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc0
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc000890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2236313037353165343334663537313831333965376430303736613461383735633934383761646636353131633734313935663433313133396237346437626330222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2262333463653432623737383565666130396666633164623335396263626366663363346562306361386165616664353436393432383565626539346535653064222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00f88d22bb88621a2a35cfa41a3b3fbc9656a5ba05fb6bd1c588a460680c8c555442319249dbdb5b18504f5404fde0caf23346dc05bd2ad09e3fc01a5e107e0b0100a00000007665636468742f706169645f6f726465725f62696e64696e672f763100610751e434f5718139e7d0076a4a875c9487adf6511c74195f431139b74d7bc000d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400ea20a21f331e3f05cdf766607e2c599be2a38794e5ba70cf3e9360aa44a2d51382a4edbeb023740fbeb59994172314c257092961c77fda9e812c6fe128c8c50e00aa0000007665636468742f657363726f775f7769746e6573732f7631003c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb400000000000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e4930039add9a7514d647c40f5799c170cde23ea54850d3a82eb12b39f54e076d150a44c81ccbea27340558dd3f10380aa790e205fb40aefdfb564eb3928e5fa93880f0061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=ca37d9204b766d59fad5e37f80b2ce354c6886cc7a4525189373856eb01ba8ca661736d88741fcac5641312bce805b38c7359ff529c24aba9e716927c0098102
term_hash=3c5fa2bb1799cb5aeb212f84f89dfb31aa490a8660d21896a1769466dcb4eeb4
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P27

```kv
title=цепь 1: выплата проходит, когда залог залочен и реестр доверен
id=P27
outcome=payout
code=-
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=1
order.asset_address=0101010101010101010101010101010101010101
order.escrow_ref_hex=636861696e313a657363726f772f30303031
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001010000000000000001010101010101010101010101010101010101010012000000636861696e313a657363726f772f303030310000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=c0e32b11646a49c1ded895de54d26b5cba3580c3c8b7dfe2895a7feff359f760275192171c53d9caaa010e4304062b6f7dbb471b31e294d08b66d774750f3405
order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
sub.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=69c7880082229d7ced2ca1ed1362702b9fed8f0c9f88f7830264c351a8987a748b704855e92162125a99280a8d8c14eb1cc0d3be5a08e541adde5f9ae5cbd604
submission_ref=dde240342bbe17a8d6e04913606a302ac65ce4b01e6138b56c9b2894fd80bcc4
receipt.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
receipt.submission_ref=dde240342bbe17a8d6e04913606a302ac65ce4b01e6138b56c9b2894fd80bcc4
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"dde240342bbe17a8d6e04913606a302ac65ce4b01e6138b56c9b2894fd80bcc4","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=338f88b098b9d0be21d1a19e47929ed69dde66c6841033de7e3c9362bec5013ec9ec9bfd9120834b4b60068f1b8ed237cb490f42bd1d978b77eb13c3bf75ed0b
binding.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310017d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
binding.signature_hex=e05fa2d2049f2ab0bfd1de59ee16dbf7b3a660ff1c0808fc985f3ed3e694af0f168319c94c9b224700404d179159d604f76b4b6ac5af929331b34dfdc5ba520e
witness.term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
witness.chain_id=1
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f763100745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc00010000000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=0b0ed3bf341f2fa602c5d2e74f91bbb6d1bec0cbc7420307eb3e00e622ab1cfe31f500abadb0ce17ab24c16ebb3f7da08935cab62099997536b4cdaa2555a001
claim.term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
claim.order_ref=17d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f763100745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc0017d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b00890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2231376438643432356432336132343632353065373136396433303231613665646531343464663330356239303638656535396663323665333938646539633362222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2264646532343033343262626531376138643665303439313336303661333032616336356365346230316536313338623536633962323839346664383062636334222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00338f88b098b9d0be21d1a19e47929ed69dde66c6841033de7e3c9362bec5013ec9ec9bfd9120834b4b60068f1b8ed237cb490f42bd1d978b77eb13c3bf75ed0b00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310017d8d425d23a246250e7169d3021a6ede144df305b9068ee59fc26e398de9c3b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc00e05fa2d2049f2ab0bfd1de59ee16dbf7b3a660ff1c0808fc985f3ed3e694af0f168319c94c9b224700404d179159d604f76b4b6ac5af929331b34dfdc5ba520e00aa0000007665636468742f657363726f775f7769746e6573732f763100745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc00010000000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493000b0ed3bf341f2fa602c5d2e74f91bbb6d1bec0cbc7420307eb3e00e622ab1cfe31f500abadb0ce17ab24c16ebb3f7da08935cab62099997536b4cdaa2555a0010061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=2e2e4aceea1814a7da3885e5c5cc4bcd4c243546da285074f9a05d52ade5967e719dfdbfd1552a10e30e3a50da04b8301869c15e1c31ee25c82aa5be5e60b10d
term_hash=745cc180edd5cf6545a1b142c3bb8019d344282b0e9228a692c2d57182cf7bfc
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P28

```kv
title=цепь 10: выплата проходит, когда залог залочен и реестр доверен
id=P28
outcome=payout
code=-
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=10
order.asset_address=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a
order.escrow_ref_hex=636861696e31303a657363726f772f30303061
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f0000000000000000000000000000010a000000000000000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0013000000636861696e31303a657363726f772f303030610000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=e4bfb5eb75641dff57064c5d97e1c699d1ac417dc16fe7666b955e99ecb3572e9cc506f7098af4460db10a3bc640f4e33cd1ac7010073049428fa8b2422b180d
order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
sub.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bcdf6c464e87654c922c108915f89f542f834a3df7445fbdd252adb7a7bd2db51112722f74ec04b3a3ef83fb5096c685ac924307e232b9a60b3452f8f85ab009
submission_ref=dadcd4304539c4e469e5291ef206ed160333465aa3611bc09860d4f94c8c496a
receipt.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
receipt.submission_ref=dadcd4304539c4e469e5291ef206ed160333465aa3611bc09860d4f94c8c496a
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"dadcd4304539c4e469e5291ef206ed160333465aa3611bc09860d4f94c8c496a","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=eeaf76c3770353b8e41aa738ec38138c68701492a24d32a74201a1c8dbc6a51c89dcd8a66658056739bc625a4b022784310748a9a752bda8cf197134fa865d0c
binding.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f7631003b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df346122200d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
binding.signature_hex=bb4664789f66c642b835d06a43edce75121a3f1d24cd7851e2f841cef76ebf86ed6ce9b8f5c17bd3ba43ea0e77764e04d7d7fdf70d654f17fbb1545b2838ef02
witness.term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
witness.chain_id=10
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146000a0000000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=a433354396f9fb87d95948798f09ee335ae219f044346f416336c711e8df97fac57011193617147995839e1629f954ad49757b7a410cd0469e2f81f3b6c2800a
claim.term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
claim.order_ref=3b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df3461222
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146003b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df346122200890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2233623361633832623935356266643633396431373133306262303762326364626266643864623130636466373134303233636361303239646633343631323232222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2264616463643433303435333963346534363965353239316566323036656431363033333334363561613336313162633039383630643466393463386334393661222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00eeaf76c3770353b8e41aa738ec38138c68701492a24d32a74201a1c8dbc6a51c89dcd8a66658056739bc625a4b022784310748a9a752bda8cf197134fa865d0c00a00000007665636468742f706169645f6f726465725f62696e64696e672f7631003b3ac82b955bfd639d17130bb07b2cdbbfd8db10cdf714023cca029df346122200d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b14600bb4664789f66c642b835d06a43edce75121a3f1d24cd7851e2f841cef76ebf86ed6ce9b8f5c17bd3ba43ea0e77764e04d7d7fdf70d654f17fbb1545b2838ef0200aa0000007665636468742f657363726f775f7769746e6573732f7631007f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146000a0000000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e49300a433354396f9fb87d95948798f09ee335ae219f044346f416336c711e8df97fac57011193617147995839e1629f954ad49757b7a410cd0469e2f81f3b6c2800a0061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=2974598fa0c72a0f9ee247ba6c143703b474ab53172bcca715704418ded2606837614fe79f05605e0a93f63433b79f928f0e017fea161921ea482324053e770c
term_hash=7f040a67858014705b165c498862d11e2f3b82953e99974b6af04431ed47b146
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P29

```kv
title=цепь 137: выплата проходит, когда залог залочен и реестр доверен
id=P29
outcome=payout
code=-
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=137
order.asset_address=8989898989898989898989898989898989898989
order.escrow_ref_hex=636861696e3133373a657363726f772f30303839
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001890000000000000089898989898989898989898989898989898989890014000000636861696e3133373a657363726f772f303038390000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=aa1cd32103b22ff5ddcd369d6bb402899d5927352d03acd69642791a52404788f30576a7d07cd6799c2785b3d4049f2049818d3ccedc4b7f3064db4dd1d9920c
order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
sub.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=87d7894b3fa7ec666eb324f116bb0d2eff5a615ea5505f1492852c19d44b1607cbed56fdecc60f53f2c0abb9ba046163efbfa5e9d2fb74a29fcb2e6dfec80500
submission_ref=dc4c1efe590b49a229a52c3cd4d9d8a44415265a00031923dcd611375cf6f98c
receipt.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
receipt.submission_ref=dc4c1efe590b49a229a52c3cd4d9d8a44415265a00031923dcd611375cf6f98c
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"dc4c1efe590b49a229a52c3cd4d9d8a44415265a00031923dcd611375cf6f98c","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=08db45b51b4f13441b54bbcf96c2dda1bf3acadc48d582b3ca056f8e35f3c2df6a97c7df14bc8bdddb683266cb44bd9857ec08fe2b1e3f4f6aceb25232f67506
binding.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f7631008200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
binding.signature_hex=7317a0d3b5cbf0ededc23d68d4d9bd42bcfd450e0c94c6b1feb4552880d9181b80f5ccb7bdaf14915bcc1e5c6db9a545109daa2c7146fb3eceb1f4a592215906
witness.term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
witness.chain_id=137
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f763100b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af00890000000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=3313bc6d46d2eff6438e1aca6a6f4b93f98cd4b5c81f2134bd8c7ff1e6f5e249b56e4dae8d69a4c5c4b619bc2c57196fd1de66bd1946ebd3a54148dc90d2ca04
claim.term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
claim.order_ref=8200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f763100b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af008200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d00890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2238323030613439343232616661313766663365333136393365353836356461346631306233656130363536633538393831616438366437663433373131303164222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2264633463316566653539306234396132323961353263336364346439643861343434313532363561303030333139323364636436313133373563663666393863222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d0008db45b51b4f13441b54bbcf96c2dda1bf3acadc48d582b3ca056f8e35f3c2df6a97c7df14bc8bdddb683266cb44bd9857ec08fe2b1e3f4f6aceb25232f6750600a00000007665636468742f706169645f6f726465725f62696e64696e672f7631008200a49422afa17ff3e31693e5865da4f10b3ea0656c58981ad86d7f4371101d00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af007317a0d3b5cbf0ededc23d68d4d9bd42bcfd450e0c94c6b1feb4552880d9181b80f5ccb7bdaf14915bcc1e5c6db9a545109daa2c7146fb3eceb1f4a59221590600aa0000007665636468742f657363726f775f7769746e6573732f763100b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af00890000000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493003313bc6d46d2eff6438e1aca6a6f4b93f98cd4b5c81f2134bd8c7ff1e6f5e249b56e4dae8d69a4c5c4b619bc2c57196fd1de66bd1946ebd3a54148dc90d2ca040061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=dbba8491d6a1a08836a6612079d21892ee84399bbdb79246760acc899dbe1ad0205653d06f2cd659d2d0b72b592df60554f03d24591b6b438a8621a84ed82503
term_hash=b82065751b029bd6e97e106c5f63950d3c09986727833808e2caa66d83edd2af
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P30

```kv
title=цепь 8453: выплата проходит, когда залог залочен и реестр доверен
id=P30
outcome=payout
code=-
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=8453
order.asset_address=0505050505050505050505050505050505050505
order.escrow_ref_hex=636861696e383435333a657363726f772f32313035
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001052100000000000005050505050505050505050505050505050505050015000000636861696e383435333a657363726f772f323130350000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=4667c2ad496379eadd469baa1681c95211c847aa4a587d64f9346d01d6da49e6fd20663458f5b57d80c3ea56dabd67c1809b31cb98247bae7045805f151a3208
order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=bc2117dfb2ca450db441ec9877184158f172039d2817304d4039613d7426c564e113fbd9b36e4efc708217c4ecf772460f1303dd2e86c08c3c83a7d48560970a
submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
receipt.submission_ref=7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"7689b3ca6be4f41d7c8a9a9c6c355b90dab12bf85b89ac313daa6b1abd2bc7b6","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d
binding.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
binding.signature_hex=6c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a89803
witness.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
witness.chain_id=8453
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=5e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe08
claim.term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
claim.order_ref=99a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa70890576047
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c0099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2239396133363661306563326262643236313336356237666234656138623666306532386134646232633863663564323533643261613730383930353736303437222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2237363839623363613662653466343164376338613961396336633335356239306461623132626638356238396163333133646161366231616264326263376236222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d00a6b97001582a3d3405f26cedb0e9b8826b8f9a2d97185df8439d50b4fcceaa9ce5da192d868b61bb809267ae49e6e8ccd70cc0bdfdcb05c320f375015136ba0d00a00000007665636468742f706169645f6f726465725f62696e64696e672f76310099a366a0ec2bbd261365b7fb4ea8b6f0e28a4db2c8cf5d253d2aa7089057604700d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c006c8068bfc31464cbe50253fc9fce659d068a3cfae0323c5a39af39389f932ea87be46e8740f61863911a5ce2a7bcf70350f0cb077ec45dc5d6a0879754a8980300aa0000007665636468742f657363726f775f7769746e6573732f7631003bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c00052100000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493005e71e5587b58c384dfe21908ab3b7c8e66b81439002ef2d08448a5dae1b255e70a3ee3745be1aa5b5052a9a2d05ac6bf3d39dff345fc5053d0baad33c73ffe080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=3c8f3e1286c0c871b505fa8781793ed00b1f95df7d0c6c7971046de22764b61f1e0ec33405d23333f8dbaa87a400d509a86a6760f9833845a1802a20d9a8d90e
term_hash=3bb1390594b4c87cc00ef5be0604cf0833e614bbdb1449d931d5a68d46653b6c
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

### P31

```kv
title=цепь 42161: выплата проходит, когда залог залочен и реестр доверен
id=P31
outcome=payout
code=-
now=1800000000
order.kind_tag=0
order.statement_hash=99a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d
order.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
order.entrypoint=/usr/local/bin/verify
order.budget_seconds=120
order.network=0
order.amount=1000000
order.asset_tag=1
order.asset_chain_id=42161
order.asset_address=b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1
order.escrow_ref_hex=636861696e34323136313a657363726f772f61346231
order.deadline=1800000000
order.submit_limit=8
order.publisher=00cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590
order.nonce=7
order.canonical_record_hex=7665636468742f706169645f6f726465722f763100000099a0653d6fe0a848ba2c7ec6ed810e3bdf66718d47cb4d0760b653cb9769fe0d002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00150000002f7573722f6c6f63616c2f62696e2f766572696679007800000000000040420f000000000000000000000000000001b1a4000000000000b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b10016000000636861696e34323136313a657363726f772f613462310000d2496b000000000008000000cb8388ab9f58c59acd16df6248dec39b0cf0221d03d699c65ffbeed35d6590000700000000000000
order.signature_hex=45ddb4a4b7175c58be612fc9b9aecaf67fd6f298e9aa3239133575fea00190993d8e2df90be793b1ddaac623177e5aacbc2c95d7253c1dc315bfb5337dc16c04
order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
sub.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
sub.artifact_hash=a04418601fbbc82886e5a6a4496a08542c34766a791af6a4d2cbe8eb602a0f39
sub.artifact_uri=ipfs://bafybeiexample
sub.submitter=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
sub.nonce=1
sub.created_at=1799999999
sub.signature_hex=3406b426a55a049ce44529415993ff952e787718b4662bc1ee503bf6e308f04ebc3c0be603868e86d7d8652c6991c9feb64d2d2683dc8e04c999827555da680f
submission_ref=22d600649c404db5992c1e13f1a2f2f841c98dc9034ec9909d0b6268e186f5e2
receipt.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
receipt.submission_ref=22d600649c404db5992c1e13f1a2f2f841c98dc9034ec9909d0b6268e186f5e2
receipt.verdict=pass
receipt.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
receipt.toolchain=leanprover/lean4:v4.9.1
receipt.axioms=["propext"]
receipt.wall_clock_ms=41000
receipt.budget_ms=120000
receipt.exit_code=0
receipt.stdout_sha256=3333333333333333333333333333333333333333333333333333333333333333
receipt.stderr_sha256=4444444444444444444444444444444444444444444444444444444444444444
receipt.deterministic=true
receipt.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
receipt.canonical_json={"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","order_ref":"a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b","stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444","stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333","submission_ref":"22d600649c404db5992c1e13f1a2f2f841c98dc9034ec9909d0b6268e186f5e2","toolchain":"leanprover/lean4:v4.9.1","verdict":"pass","verifier_pubkey":"d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254","wall_clock_ms":41000}
receipt.signature_hex=2cbc0e2d9a8f22a63e222aab0a27220e9f30f093a0eaeaa98aee1b7bbed447f52fc2dbf07a337cf32a729ae77159b8afc89bd0fc98fe84af9b3954eb7155760d
binding.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
binding.verifier_pubkey=d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254
binding.image_digest=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a
binding.term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
binding.canonical_hex=7665636468742f706169645f6f726465725f62696e64696e672f763100a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
binding.signature_hex=3753f10d909a1e79c13adc3428b00bab35530878097fee66201714ca672b5dae86802935537147920aa47bda5e2c775f4d3021be16f9f4a22e7fe68f51d18c04
witness.term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
witness.chain_id=42161
witness.status=1
witness.amount_on_chain=1000000
witness.block_ref_hex=626c6f636b3a3138343030303030
witness.registry_root=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
witness.observer_pubkey=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.canonical_hex=7665636468742f657363726f775f7769746e6573732f763100c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde00b1a400000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
witness.signature_hex=46bf2316b3b9404c01bd55a0895dcbabdd2624c5a7a4f38a1fca8bf79426d900c42a1807bcceb0fcf1f8e7076515567031d4a1de1232f9801dc316a882885608
claim.term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
claim.order_ref=a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b
claim.beneficiary=61380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_hex=7665636468742f7061796f75745f636c61696d2f763100c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde00a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b00890200007b226178696f6d73223a5b2270726f70657874225d2c226275646765745f6d73223a3132303030302c2264657465726d696e6973746963223a747275652c22657869745f636f6465223a302c22696d6167655f646967657374223a2232613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261326132613261222c226f726465725f726566223a2261376461353937393834303236343231396131313237323065656631383065303865633533656364316364653337356639646133323033303333313163643562222c227374646572725f736861323536223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c227374646f75745f736861323536223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c227375626d697373696f6e5f726566223a2232326436303036343963343034646235393932633165313366316132663266383431633938646339303334656339393039643062363236386531383666356532222c22746f6f6c636861696e223a226c65616e70726f7665722f6c65616e343a76342e392e31222c2276657264696374223a2270617373222c2276657269666965725f7075626b6579223a2264353365633238366332636338636334333461663564643963306638623166656462353230343565623166333739613138613762653666313135653965323534222c2277616c6c5f636c6f636b5f6d73223a34313030307d002cbc0e2d9a8f22a63e222aab0a27220e9f30f093a0eaeaa98aee1b7bbed447f52fc2dbf07a337cf32a729ae77159b8afc89bd0fc98fe84af9b3954eb7155760d00a00000007665636468742f706169645f6f726465725f62696e64696e672f763100a7da5979840264219a112720eef180e08ec53ecd1cde375f9da320303311cd5b00d53ec286c2cc8cc434af5dd9c0f8b1fedb52045eb1f379a18a7be6f115e9e254002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde003753f10d909a1e79c13adc3428b00bab35530878097fee66201714ca672b5dae86802935537147920aa47bda5e2c775f4d3021be16f9f4a22e7fe68f51d18c0400aa0000007665636468742f657363726f775f7769746e6573732f763100c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde00b1a400000000000000010040420f00000000000000000000000000000e000000626c6f636b3a313834303030303000382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf009e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e4930046bf2316b3b9404c01bd55a0895dcbabdd2624c5a7a4f38a1fca8bf79426d900c42a1807bcceb0fcf1f8e7076515567031d4a1de1232f9801dc316a8828856080061380396c5184d8c25c6e419d6135f0bc275457bcd50c4ce1c8764ca19c6a9af
claim.canonical_len=1310
claim.signature_hex=be3e183185051febf6cfdd03f10dc2095a89ac635eca76d9e8f56024838e09ae35139fe08655d589204adba8e37a3ed542ba120d2ba984b627b2b5eb2d211f09
term_hash=c4a6b6ee5a96f77feb2ae470fc64f66b6a99446e1c98d93292b0312deea7ffde
trust.chains=0,1,10,137,8453,42161
trust.observers=9e584d56e34bd4dd3c2fc8866c796b1907db9cd8f11811f559d69ea07513e493
trust.registries=382bdb9d8c718277c1c37c676ffacb8e5abb8a679b89b06c67348ff6f62aeeaf
```

## 7. Покрытие

- векторов: 31
- из них «платить»: 7
- различных кодов отказа, использованных слоем: 9 — `E_DEADLINE_PASSED`, `E_ESCROW_INSUFFICIENT`, `E_ESCROW_UNKNOWN`, `E_HASH_MISMATCH`, `E_ORDER_MALFORMED`, `E_RECEIPT_INVALID`, `E_RECEIPT_UNSIGNED`, `E_REPLAY`, `E_VERDICT_MISMATCH`
- отказов `E_REPLAY` (повторное требование на распорядившийся залог): 12
- закрытый список кодов: 18 имён; ни одного нового слой не ввёл
