---
id: H-0161
status: open
verdict: ""
date: "2026-10-30"
claim: "`WalPullRequest` не списывает узловой admission: `handle_pull_request` (`crates/vecdht-node/src/node.rs`)
читает манифест и сегменты WAL, не вызывая `reserve_admit`, поэтому 101-й запрос хвоста с одного
пира при бюджете 100 admits/с получает `WalPullResponse`, а не `E_BUSY`. После правки
`reserve_admit` стоит в `handle_pull_request` после проверки шарда и до чтения манифеста, отказ
возвращает `Error{code: BUSY, retry_after_ms}` тем же путём, что publish; чужой шард по-прежнему
отбрасывается бесплатно (проверка шарда раньше списания). Тест `s11_pull_admission` на пине
красный, после правки зелёный; wire, спека и формат диска не тронуты."
falsifier: "Ложь, если хотя бы одно: (а) на пине в теле `handle_pull_request` уже есть `reserve_admit`
или тест на пине зелёный — карточка мерит не то; (б) после правки вызов стоит вне тела
`handle_pull_request` или до проверки `req.shard != self.shard`; (в) после правки тест красный или
`TEST_CASES`/`TEST_PASS` не 2/2; (г) отказ не наблюдаем как `err_code::BUSY` с `retry_after_ms > 0`;
(д) чужой шард списывает токен (после отказа по шарду бюджет не тронут); (е) `WIRE_TOUCHED` или
`SPEC_TOUCHED` не 0 — правка вышла за узел; (ж) замороженная таблица `lab/expectations/e0161.tsv`
расходится с фактами носителя; (з) два прогона на неизменном дереве дают разные факты
(`STABLE=0`); (и) соседние стражи (`check-guard-selftests`, `check-contour-parity`,
`check-contours`, `check-expect-freeze`, `check-text-clean`, `check-claims`) краснеют."
oracle: "bash lab/e0161-run.sh дважды на неизменном дереве. PRE_FIX — `node.rs` пина через
`git checkout <пин> -- crates/vecdht-node/src/node.rs` с trap-возвратом: в теле
`handle_pull_request` вызова нет (`PRE_FIX_ADMIT_IN_PULL=0`), тест на старом коде красный
(`PRE_FIX_TEST_RC=1`). POST — живое дерево: вызов есть (`POST_FIX_ADMIT_IN_PULL=1`), тест зелёный
(`POST_FIX_TEST_RC=0`), `TEST_CASES=2`, `TEST_PASS=2`, отдельный прогон чужого шарда
(`FOREIGN_FREE=1`), `BUSY_CODE=1`; границы продукта/спеки, соседние стражи и диск печатаются
фактами; замороженная таблица `lab/expectations/e0161.tsv` сверяет каждый факт."
experiments: []
prior_art: "не искали: предмет — собственная дыра приёма WAL-запроса в собственном узле;
внешняя литература не знает ни `handle_pull_request`, ни нашего бюджета 100 admits/с"
prior_art_no_code: "чужого кода не переносили: правка в своём узле, тест свой"
lean:
  решение: "не применён"
  причина: "утверждение о порядке списания квоты в конкретном обработчике; Lean доказывал бы
  модель admission, а не то, что вызов стоит в нужной ветке Rust-кода"
  модель: ""
  пространство: "нет"
  без_времени: "нет"
  для_всех: "нет"
  дешевле_стенда: "нет"
supersedes: null
---

# H-0161 — `WalPullRequest` стоит узлового admission, как publish

## Боль

§11.3.4 называет узловой бюджет 100 admits/с общим для приёма, и `E_BUSY` — наблюдаемый отказ.
Publish резервирует токен до вытеснения (`node.rs:869`), а `handle_pull_request` (`node.rs:1266`)
не резервирует ничего: запрос хвоста WAL — самый дорогой из дешёвых (манифест, `list_segments`,
чтение сегментов) — обслуживается сто раз в секунду с одного пира и не стоит узлу ни одного
токена. Аудит 4-го круга назвал это D4 и оставил в зелёной зоне: механизм уже есть, правка —
одна строка плюс тест, тела и wire не меняются.

## Что проверяется

Правка: в `handle_pull_request` после `if req.shard != self.shard { return Ok(Vec::new()); }` и до
`self.store.manifest()` взять `now_sec` (dispatch передаёт `Clock`, обработчик получает `now.sec`),
вызвать `self.admission.borrow_mut().reserve_admit(now_sec)`; при `Some(code)` вернуть
`self.err(from, code, verdict.retry_after_ms())` — тем же путём, что publish.

Тест `crates/vecdht-node/tests/s11_pull_admission.rs`, два случая:

* `pull_request_costs_node_budget` — сто pull'ов с одного пира дают `WalPullResponse`, сто первый —
  `Error` с `code == err_code::BUSY` и `retry_after_ms > 0`, счётчик
  `admission.stats.rejected_node_busy` вырос на 1;
* `foreign_shard_pull_is_free` — запрос чужого шарда отбрасывается до списания: после него сто
  pull'ов своего шарда всё ещё проходят.

Списание идёт после проверки шарда намеренно: чужой шард — не работа узла, и цена отказа не
должна конкурировать с ценой обслуживания.

## Границы

Правка не вводит отдельный бюджет для pull и не меняет §11.3.4: pull тратит тот же узловой бакет,
что publish, поэтому легитимный heal ограничен теми же 100 запросами в секунду (кусок WAL —
`max_bytes ≤ MAX_BODY_LEN/2`, холодный снапшот — серия таких же запросов). Отказ наблюдаем, но
счётчик `rejected_node_busy` общий с publish: по нему нельзя сказать, какой вид кадра упёрся в
бюджет. Подпись `WalPullResponse` (D1) и гейты эпохи остаются красными и этой карточкой не
трогаются.

## Следующее

Заполняется после прогонов и блока контура.
