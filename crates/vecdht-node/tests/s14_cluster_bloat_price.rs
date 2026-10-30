//! Оракул `H-0079`/`E-0079` — §14.4 (iv) «надувание кластеров»: цена вектора, у которого
//! спека признавала отсутствие защиты — до `E-0088`.
//!
//! Спека v8 §14.4 (iv): «per-cluster admission cap реализован как локальная политика приёма
//! (`E-0088`, гейты (1), (3), (5), (7); `ADR-0044` решение 5)». Историческую редакцию с
//! признанием отсутствия цитирует карточка `E-0079`; здесь честная работа — **измерить цену**
//! того, что было: сколько стоило надувание тому, кто надувает, и каждому, кто потом ищет.
//!
//! Три вещи до прогона были неочевидны и пришли из формальной модели `lab/lean/VecDHT/Admission.lean`
//! (правило, принятое владельцем после `E-0078`):
//!
//! * `admit_ignores_signature` — подпись `Publish` стоит **под условием самого флага**
//!   (`node.rs:685`), поэтому заявленный `owner_ed25519` в неподписанном кадре никем не
//!   подтверждается: тест (1);
//! * `displacement_is_always_admitted` — перепубликация с другим `cluster_id` переезжает между
//!   posting list'ами, не увеличивая `total`, то есть горячую ячейку можно собирать из уже
//!   принятых записей: тест (2);
//! * `pow_input` не содержит `cluster_id` (`crypto/src/pow.rs:63…77`) — переезд не требует новой
//!   работы сверх уже уплаченной: тест (2), вторая половина.
//!
//! Что здесь **не** проверяется (границы, а не недоработка): сеть и реальный LibP2p-`from`,
//! `POW_BITS = 24` (меряется 18 и 20, 22 — только в зонде (5в)), GPU, другая ОС, и главное — сам
//! proposed cap: живой код его не содержит, поэтому тест (6) прогоняет три политики **поверх снятого
//! трейса**, а не против изменённого узла. Пороги заморожены в
//! `lab/hypotheses/H-0079-cluster-bloat-price.md` до первого замера.
//!
//! Профиль сборки важен и является границей: прогон идёт `unoptimized + debuginfo` (`cargo test`
//! по умолчанию), поэтому **абсолютные** времена (мкс на запись, нс на хеш) — это цена этого хоста в
//! этом профиле, а не production-латентность. Всё, чем гейтуется этот оракул, от профиля не зависит:
//! линейность скана по размеру ячейки, усиление по длине списка, потолок ячейки, refusal-коды и
//! три политики капа. Release-перемерка абсолютных чисел оформлена как отдельная работа, не как
//! правка порога.

use std::time::Instant;

use vecdht_crypto::{intent_id, pow_input, pow_ok};
use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Clock, Params, ShardNode};
use vecdht_wire::messages::{err_code, Codec, Find, ProtocolError, Publish};
use vecdht_wire::DIM;

const SHARD: u16 = 7;
/// Первый кластер шарда: `shard_of_cluster` делит на 16, «удобный» ноль скрыл бы ошибку маршрута.
const BASE: u16 = SHARD * 16;
const SEEDS: [u8; 3] = [1, 2, 3];
/// Дешёвый PoW для путей приёма: политический пол 18…24 измеряется отдельно, тестом (5).
const POW: u32 = 8;
const TTL: u16 = 225;

fn params() -> Params {
    testing::params(POW)
}

/// Узел шарда, принявший genesis эпохи 1 (тот же порядок, что в `tests/admission.rs`).
fn primary_on(dir_name: &str, p: Params) -> (ShardNode, std::path::PathBuf) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = dir(dir_name);
    let mut n = testing::node(&d, SHARD, seed, p, &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "писать умеет только primary эпизоды");
    (n, d)
}

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

/// Кадр честной публикации от агента с сидом `agent` в кластер `cluster`.
fn publish_frame(agent: u8, vec_seed: u8, cluster: u16, bucket: u32, bits: u32) -> Vec<u8> {
    let id = testing::identity(agent);
    testing::PublishSpec {
        agent: &id,
        vec_q: &testing::vector(vec_seed),
        cluster_id: cluster,
        shard: SHARD,
        epoch: 1,
        published_bucket: bucket,
        ttl_buckets: TTL,
        bits,
    }
    .frame()
}

/// Кадр `Publish`, **заявляющий чужой ключ** как `owner_ed25519`, без подписи (§5.3: она
/// опциональна, и узел проверяет её только если стоит флаг).
///
/// PoW приходится майнить заново — вход `pow_input` содержит owner. Это и есть весь вопрос:
/// сколько стоит подделка, если она не стоит секрета.
fn foreign_owner_frame(owner: &[u8; 32], vec_q: &[i8; DIM], cluster: u16, bucket: u32) -> Vec<u8> {
    let intent = intent_id(vec_q, testing::PREPROCESSING_VERSION);
    let expires = bucket + u32::from(TTL);
    let input = pow_input(owner, SHARD, 1, &intent, expires);
    Publish {
        preprocessing_version: testing::PREPROCESSING_VERSION,
        cluster_id: cluster,
        vec_q: *vec_q,
        owner_ed25519: *owner,
        ttl_buckets: TTL,
        published_bucket: bucket,
        pow_bits: POW as u8,
        pow_nonce: testing::mine(&input, POW),
        intent_id: intent,
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

fn find_frame(agent: u8, clusters: &[u16], query_seed: u8, query_id: u64) -> Vec<u8> {
    let id = testing::identity(agent);
    Find {
        preprocessing_version: testing::PREPROCESSING_VERSION,
        query_vector: testing::vector(query_seed),
        clusters: clusters.to_vec(),
        top_k: 64,
        query_id,
        requester_ed25519: id.pubkey(),
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

/// p-й перцентиль по неотсортированной выборке (копирует и сортирует — выборки маленькие).
fn percentile_us(mut samples: Vec<u64>, p: usize) -> u64 {
    assert!(!samples.is_empty(), "перцентиль по пустой выборке не определён");
    samples.sort_unstable();
    let idx = (samples.len() - 1) * p / 100;
    samples[idx]
}

/// (1) Неподписанный `Publish` с чужим `owner_ed25519` заменяет чужую запись и тратит квоту
/// её автора. Фальсификатор (1д): узел отказывает такому кадру — тогда «подделка ничего не
/// даёт» верно, а модель `admit_ignores_signature` транскрибирует код неверно.
#[test]
fn an_unsigned_publish_under_a_foreign_owner_replaces_their_record() {
    let (mut n, d) = primary_on("bloat-foreign", params());
    let victim = testing::identity(101);
    let attacker = testing::identity(102);
    let me = victim.pubkey();

    // Жертва пишет честно: вектор `vector(1)` в базовый кластер.
    let replies = n
        .on_frame(me, &publish_frame(101, 1, BASE, 0, POW), Clock::at(0))
        .expect("честный publish");
    assert!(error_to(&replies, me).is_none(), "контрольная запись обязана пройти");
    let slot = n.store.index.owner_slot(&me).expect("запись жертвы жива");
    assert_eq!(n.store.index.entry(slot).expect("живой slot").vec_q, testing::vector(1));

    // Атакующий публикуется **от имени жертвы** со своим вектором, не имея её ключа.
    let stolen = testing::vector(99);
    let frame = foreign_owner_frame(&me, &stolen, BASE + 1, 1);
    let replies = n
        .on_frame(attacker.pubkey(), &frame, Clock::at(16))
        .expect("неподписанный кадр");
    let forged_refused = error_to(&replies, attacker.pubkey());
    assert!(
        forged_refused.is_none(),
        "фальсификатор (1д): узел отказал неподписанному кадру с чужим owner — {forged_refused:?}",
    );
    let after = n.store.index.entry(slot).expect("живой slot");
    assert_eq!(after.vec_q, stolen, "запись жертвы обязана быть заменена вектором атакующего");
    assert_eq!(after.cluster_id, BASE + 1, "и переехать в заявленный атакующим кластер");
    assert_eq!(n.store.len(), 1, "подмена не занимает второй slot");

    // Токен списывается у жертвы: бакет §11.3.1 считается по обоим — `from` и заявленному
    // owner, — поэтому чужими кадрами можно посадить квоту владельца без его ключа.
    let mut accepted = 0usize;
    for i in 0..25 {
        let f = foreign_owner_frame(&me, &testing::vector(90 + (i % 8) as u8), BASE, 2);
        if n.on_frame(attacker.pubkey(), &f, Clock::at(32))
            .expect("спам")
            .iter()
            .find(|e| e.to == attacker.pubkey())
            .is_none()
        {
            accepted += 1;
        }
    }
    let replies = n
        .on_frame(me, &publish_frame(101, 2, BASE, 2, POW), Clock::at(32))
        .expect("попытка жертвы");
    let err = error_to(&replies, me).expect("квота жертвы исчерпана чужими кадрами — фальсификатор (1е)");
    assert_eq!(err.code, err_code::QUOTA_PUBLISH, "отказ обязан быть именно квотой: {err:?}");

    // Через секунду токен пополняется — жертва восстанавливает свой вектор. Отношение сил
    // «по одному токену в секунду у обеих сторон» печатается, а не утверждается.
    let replies = n
        .on_frame(me, &publish_frame(101, 1, BASE, 2, POW), Clock::at(33))
        .expect("восстановление");
    assert!(error_to(&replies, me).is_none(), "жертва обязана суметь перезаписать себя");
    assert_eq!(n.store.index.entry(slot).expect("живой slot").vec_q, testing::vector(1));
    eprintln!(
        "## (1) подмена прошла: принято чужих кадров в бакет жертвы = {accepted} из 25, \
         отказ жертвы = {}, запись восстановлена на следующий токен ##",
        err.code
    );
    remove(&d);
}

/// (2) Переезд между ячейками не требует новой работы: `cluster_id` не входит в `pow_input`,
/// а гейт вместимости пропускает перепубликацию (§11.3.2), поэтому горячую ячейку можно
/// собирать из уже принятых записей, не увеличивая `total`.
///
/// Фальсификатор (2а): узел отвергает перепубликацию с другим `cluster_id` (требование
/// стабильности кластера) — тогда «собери ячейку из чужих записей» неверно.
#[test]
fn changing_cluster_id_costs_no_new_pow() {
    let mut p = params();
    p.max_live_per_shard = 8;
    let (mut n, d) = primary_on("bloat-move", p);

    // Четыре честные записи — в четырёх разных ячейках одного шарда.
    for (i, agent) in (20..24u8).enumerate() {
        let replies = n
            .on_frame(
                testing::identity(agent).pubkey(),
                &publish_frame(agent, 1, BASE + i as u16, 0, POW),
                Clock::at(0),
            )
            .expect("честный publish");
        assert!(error_to(&replies, testing::identity(agent).pubkey()).is_none());
    }
    assert_eq!(n.store.len(), 4);
    for i in 0..4u16 {
        assert_eq!(n.store.index.cluster_len(BASE + i), 1, "раскладка до переезда");
    }

    // (2а) Переезд через живой путь: та же запись, другой кластер того же шарда.
    let mut refused = 0usize;
    for (i, agent) in (20..24u8).enumerate() {
        let id = testing::identity(agent);
        let replies = n
            .on_frame(
                id.pubkey(),
                &publish_frame(agent, 1, BASE, ((64 + i) as u32) / 16, POW),
                Clock::at(64 + i as u64),
            )
            .expect("перепубликация");
        if error_to(&replies, id.pubkey()).is_some() {
            refused += 1;
        }
    }
    assert_eq!(refused, 0, "фальсификатор (2а): перепубликация в другой кластер отвергнута");
    assert_eq!(n.store.len(), 4, "переезд не увеличивает число живых записей");
    assert_eq!(n.store.index.cluster_len(BASE), 4, "и складывает их в одну ячейку");
    assert_eq!(n.evictor.evicted, 0, "вместимость шарда на переезд не реагирует");

    // (2б) Тот же переезд как правка байта в **уже оплаченном** кадре: `cluster_id` не входит
    // в `pow_input`, поэтому новый nonce не нужен — стоимость переезда равна нулю.
    let frame = publish_frame(20, 1, BASE, 5, POW);
    let mut msg = Publish::decode(&frame).expect("decode своего кадра");
    assert_eq!(msg.cluster_id, BASE);
    msg.cluster_id = BASE + 2;
    let replies = n
        .on_frame(testing::identity(20).pubkey(), &msg.encode_unsigned(), Clock::at(80))
        .expect("переезд без новой работы");
    assert!(
        error_to(&replies, testing::identity(20).pubkey()).is_none(),
        "фальсификатор (2б): узел потребовал новую PoW за смену кластера"
    );
    assert_eq!(n.store.index.cluster_len(BASE), 3);
    assert_eq!(n.store.index.cluster_len(BASE + 2), 1);
    eprintln!(
        "## (2) переезд: 4 записи в одной ячейке при total {}, evicted {}; смена cluster_id в \
         оплаченном кадре прошла без нового nonce ##",
        n.store.len(),
        n.evictor.evicted
    );
    remove(&d);
}

/// (3) Потолок надувания = вместимость шарда, а не размер ячейки: при `max_live_per_shard = 240`
/// одна ячейка доходит ровно до 240. Фальсификатор (3а): ячейка останавливается раньше —
/// значит per-cluster лимит в коде всё-таки есть и формулировка §14.4 (iv) устарела.
#[test]
fn one_cell_grows_to_the_shard_cap() {
    let mut p = params();
    let cap = 200u64;
    p.max_live_per_shard = cap;
    let (mut n, d) = primary_on("bloat-cap", p);

    let t0 = Instant::now();
    let mut refused = 0usize;
    let mut codes = Vec::new();
    // 210 независимых ключей в один кластер: сиды 20..=229 не заняты авторитетами и холдерами.
    for i in 0..210u64 {
        let agent = 20 + i as u8;
        let id = testing::identity(agent);
        // Секунда растёт каждые 100 кадров — узловой бюджет 100 admits/с (§11.3.4) не должен
        // подменять собой измеряемый лимит.
        let sec = i / 100;
        let replies = n
            .on_frame(id.pubkey(), &publish_frame(agent, 1, BASE, (sec / 16) as u32, POW), Clock::at(sec))
            .expect("publish");
        if let Some(err) = error_to(&replies, id.pubkey()) {
            refused += 1;
            codes.push(err.code);
        }
    }
    let wall = t0.elapsed().as_millis();

    let cell = n.store.index.cluster_len(BASE) as u64;
    assert_eq!(cell, cap, "фальсификатор (3а): ячейка остановилась раньше вместимости шарда — {cell} < {cap}");
    assert_eq!(n.store.len() as u64, cap, "второй лимит (пер-кластерный) не проявился");
    assert_eq!(n.store.index.cluster_len(BASE + 1), 0, "флуд шёл ровно в одну ячейку");
    eprintln!(
        "## (3) потолок: cluster_len = {cell} = max_live_per_shard ({cap}), отказов {refused}, \
         коды {codes:?}; 210 кадров живым путём за {wall} мс (evicted {}) ##",
        n.evictor.evicted
    );
    remove(&d);
}

/// (4) Цена скана: линейна по размеру ячейки и по длине списка кластеров в запросе.
///
/// Ячейки наполняются **на уровне индекса** (`ShardStore::publish`), потому что `testing::identity`
/// даёт только 256 ключей, а здесь нужен размер до 4 096; то, что живой путь такие размеры
/// пропускает, — отдельный факт, измеренный тестом (3) и оцененный арифметикой теста (5).
#[test]
fn find_scan_price_scales_with_cell_size_and_list_length() {
    let mut p = params();
    p.max_live_per_shard = 6_000;
    let (mut n, d) = primary_on("bloat-scan", p);

    let ladder = [16u64, 64, 256, 1_024, 4_096];
    let mut med = Vec::new();
    let mut p95 = Vec::new();
    let mut filled = 0u64;
    for (j, size) in ladder.iter().enumerate() {
        let cluster = BASE + j as u16;
        for i in 0..*size {
            // Владелец обязан быть уникальным по всему тесту: `insert` дедуплицирует по
            // `(owner, shard)` и при повторе **переезжает** (ивф, `ivf.rs:322…328`), поэтому
            // одинаковые литералы во второй ячейке просто съели бы первую (ДИАГНОЗ-1).
            let mut owner = [0u8; 32];
            owner[0..8].copy_from_slice(&(filled + i).to_le_bytes());
            owner[31] = 0xB7;
            let mut vec_q = [0i8; DIM];
            for (k, x) in vec_q.iter_mut().enumerate() {
                *x = ((k as i32 + i as i32) % 200 - 100) as i8;
            }
            n.store
                .publish(vecdht_index::IndexEntry {
                    owner_ed25519: owner,
                    vec_q,
                    cluster_id: cluster,
                    published_bucket: 0,
                    ttl_buckets: TTL,
                })
                .expect("запись в индексе");
        }
        assert_eq!(n.store.index.cluster_len(cluster) as u64, *size, "ячейка наполнена");
        filled += size;
    }

    // Скан одной ячейки: 15 прогонов `Store::search` напрямую — это чистая стоимость перебора.
    let q = testing::vector(1);
    let mut per_record = Vec::new();
    for (j, size) in ladder.iter().enumerate() {
        let cluster = BASE + j as u16;
        let mut samples = Vec::new();
        for _ in 0..15 {
            let t = Instant::now();
            let hits = n.store.search(&q, &[cluster], 64);
            samples.push(t.elapsed().as_micros().max(1) as u64);
            assert_eq!(hits.len() as u64, (*size).min(64), "отбор top_k=64");
        }
        let m = percentile_us(samples.clone(), 50);
        per_record.push((m as f64) / (*size as f64));
        med.push(m);
        p95.push(percentile_us(samples, 95));
    }
    assert!(
        med.windows(2).all(|w| w[1] > w[0]),
        "фальсификатор (4а): скан не растёт вместе с ячейкой — медианы {med:?}"
    );
    // Линейность по двум последним точкам лестницы (4 096 / 1 024 = 4× записи).
    let slope = (med[4] as f64) / (med[3] as f64);
    assert!(
        (2.0..=8.0).contains(&slope),
        "фальсификатор (4б): рост скана не линеен — 4× записей дали {slope}× времени (медианы {med:?})"
    );

    // Усиление длиной списка: `search` не дедуплирует кластеры (`ivf.rs:475…497`), а guard
    // `shard_of_cluster` дубликаты пропускает — измерено `E-0037` для квоты, здесь — для CPU.
    let hot = BASE + 4;
    let one = percentile_us(
        (0..15)
            .map(|_| {
                let t = Instant::now();
                n.store.search(&q, &[hot], 64);
                t.elapsed().as_micros().max(1) as u64
            })
            .collect(),
        50,
    );
    let many = percentile_us(
        (0..15)
            .map(|_| {
                let list = vec![hot; 256];
                let t = Instant::now();
                n.store.search(&q, &list, 64);
                t.elapsed().as_micros().max(1) as u64
            })
            .collect(),
        50,
    );
    let gain = (many as f64) / (one as f64);
    assert!(gain >= 100.0, "фальсификатор (4в): 256 копий кластера не усиливают скан — {gain:.1}×");

    // Живой `Find` целиком (decode + скан + до 64 Ed25519-приёма) на пустой и на горячей ячейке.
    let mut live = Vec::new();
    for (label, cluster) in [("пустая", BASE + 15), ("горячая 4096", hot)] {
        let frame = find_frame(200, &[cluster], 1, 1);
        let t = Instant::now();
        let replies = n.on_frame(testing::identity(200).pubkey(), &frame, Clock::at(160)).expect("find");
        live.push((label, t.elapsed().as_micros() as u64, replies.len()));
    }
    eprintln!(
        "## (4) скан: медианы {med:?} мкс при лестнице {ladder:?}; п95 {p95:?}; \
         мкс/запись {per_record:?}; 256 копий одной ячейки: {one} → {many} мкс (усиление {gain:.1}×); \
         живой Find: {live:?} ##"
    );
    remove(&d);
}

/// (5) Цена одной принятой записи: PoW при реальной сложности манифеста и полный путь приёма
/// узлом с fsync. `24` не меряется — это 16× от 20 бит, и в логе он помечен как экстраполяция,
/// а не измерение.
///
/// ДИАГНОЗ-2 (первый прогон, `lab/logs/e0079-all.log`): замороженный порог (5) требовал
/// `t(20)/t(18) ∈ [1.6, 3.2]` при одном холодном прогоне; получено 0.97×. Тогда это было списано на
/// ramp частоты CPU (замечание о том же живёт в `crypto/src/pow.rs`, `BLAKE3_MHZ_CORE_FALLBACK`).
/// ДИАГНОЗ-5 (второй прогон + зонд (5в)) показал настоящую причину: на одном входе все три сложности
/// остановились на **одном и том же nonce**, то есть отношение времён — жребий одной выборки из
/// геометрического распределения, а не свойство майнера; гейт при этом держит сложность ровно как
/// `2^-bits` (проход A зонда). Порог (5) не двигался: холодный подсчёт выполняется ровно как
/// предписано, печатается с явным вердиктом и остаётся **невыполненным**. Функцию проверки — «работа
/// за биты действительно берётся» — несёт зонд (5в) на шести независимых входах.
#[test]
fn the_price_of_one_accepted_record() {
    let owner = testing::identity(101).pubkey();
    let intent = intent_id(&testing::vector(3), testing::PREPROCESSING_VERSION);
    let input = pow_input(&owner, SHARD, 1, &intent, 1 + u32::from(TTL));

    // Прогрев процессора и отдельный замер скорости хеширования. `ns/попытка` ниже берётся из
    // фактического числа попыток (nonce+1), а не из теоретических 2^bits.
    for _ in 0..200_000 {
        std::hint::black_box(pow_ok(&input, std::hint::black_box(7), 8));
    }
    let t = Instant::now();
    for i in 0..2_000_000u64 {
        std::hint::black_box(pow_ok(&input, std::hint::black_box(i), 24));
    }
    let rate_ns = t.elapsed().as_nanos() as f64 / 2_000_000f64;

    // Замороженный подсчёт (5): один холодный прогон 18 → 20 бит, как предписано пре-регистрацией.
    let mut cold = Vec::new();
    for bits in [18u32, 20] {
        let t = Instant::now();
        let nonce = testing::mine(&input, bits);
        let ms = t.elapsed().as_millis() as u64;
        assert!(pow_ok(&input, nonce, bits), "nonce обязан проходить проверку");
        cold.push((bits, ms, nonce));
    }
    let (lo, hi) = (cold[0].1.max(1), cold[1].1.max(1));
    let frozen_ratio = (hi as f64) / (lo as f64);
    let frozen_ok = (1.6..=3.2).contains(&frozen_ratio);

    // ДИАГНОЗ-5 (второй прогон, вместе с зондом (5в)): прогретый min-of-3 на ОДНОМ входе не годится
    // как проверка майнера, и числа это показывают сами — все три уровня остановились на одном и том
    // же nonce. Число попыток у геометрического распределения имеет среднеквадратичное отклонение,
    // равное среднему, поэтому отношение времён одного входа — жребий, а не свойство майнера.
    // Проверка сложности вынесена в зонд (5в): там шесть независимых входов и там доля принятых
    // nonce сверяется с 2^-bits. Отношение ниже остаётся печатью, а не гейтом; замороженный порог (5)
    // при этом не двигался и его вердикт печатается отдельно.
    let mut warmed: Vec<(u32, u64, u64)> = Vec::new();
    for bits in [18u32, 20, 22] {
        let mut best = u64::MAX;
        let mut nonce = 0u64;
        for _ in 0..3 {
            let t = Instant::now();
            let n = testing::mine(&input, bits);
            assert!(pow_ok(&input, n, bits), "минированный nonce обязан проходить проверку");
            let us = t.elapsed().as_micros() as u64;
            if us < best {
                best = us;
                nonce = n;
            }
        }
        warmed.push((bits, best, nonce));
    }
    let w_ratio: Vec<f64> = warmed
        .windows(2)
        .map(|w| (w[1].1 as f64) / (w[0].1.max(1) as f64))
        .collect();
    let per_hash: Vec<(u32, u64, f64)> = warmed
        .iter()
        .map(|(b, us, nonce)| (*b, nonce + 1, (*us as f64 * 1_000.0) / (nonce + 1) as f64))
        .collect();
    // Цена одной принятой записи по измеренной скорости хеширования: среднее число попыток = 2^bits.
    // Это вывод из двух измеренных величин (rate и 2^bits), а не отдельное измерение.
    let pow_price: Vec<(u32, f64)> = [18u32, 20, 24]
        .iter()
        .map(|b| (*b, rate_ns * (1u64 << b) as f64 / 1e9))
        .collect();
    eprintln!(
        "## (5а) один вход, min-of-3: {warmed:?} мкс (бит, мкс, nonce); попытки/цена {per_hash:?}; \
         отношения {w_ratio:?} — ДИАГНОЗ-5, не гейт; цена записи по измеренному хешрейту \
         (бит, с CPU на одну запись в среднем) {pow_price:?} ##",
    );

    // Полный путь приёма: 200 честных publish через узел с fsync — это то, что платит
    // атакующий за каждую запись ячейки, плюс то, что тратит узел.
    let (mut n, d) = primary_on("bloat-price", params());
    let t0 = Instant::now();
    let mut samples = Vec::new();
    for i in 0..200u64 {
        let agent = 30 + i as u8;
        let id = testing::identity(agent);
        let sec = i / 100;
        let t = Instant::now();
        let replies = n
            .on_frame(id.pubkey(), &publish_frame(agent, 1, BASE + 3, (sec / 16) as u32, POW), Clock::at(sec))
            .expect("publish");
        assert!(error_to(&replies, id.pubkey()).is_none());
        samples.push(t.elapsed().as_micros().max(1) as u64);
    }
    let wall = t0.elapsed().as_millis();
    let accept_med = percentile_us(samples.clone(), 50);
    let accept_p95 = percentile_us(samples, 95);
    // Порог (5) инструментальная часть: если приём мерцает вне [100 мкс, 20 мс], замер цены
    // атаки бессмыслен — это дефект прогона (fsync, антивирус, другой процесс), а не протокол.
    assert!(
        (100..=20_000).contains(&accept_med),
        "порог (5): медиана приёма = {accept_med} мкс вне [100 мкс, 20 мс] — прогон не пригоден"
    );

    // Цена скана надутого кластера выводится из (4): мкс/запись × размер ячейки; здесь меряется
    // только цена приёма, потому что именно её платит атакующий за каждую запись ячейки.
    eprintln!(
        "## (5) цена записи. ЗАМОРОЖЕННЫЙ ПОРОГ (5): холодный одиночный прогон 18 бит = {lo} мс, \
         20 бит = {hi} мс, nonce {} и {}, отношение {frozen_ratio:.2}× при интервале [1.6, 3.2] → {} \
         (ДИАГНОЗ-2 и ДИАГНОЗ-5: один вход — одна выборка геометрического распределения с СКО, равным \
         среднему; порог не двигался и не выполнен). Хешрейт {rate_ns:.1} нс/попытка — debug-профиль, \
         абсолютные секунды не являются ценой в бою. Приём узлом (полный путь с fsync): медиана \
         {accept_med} мкс, п95 {accept_p95} мкс, 200 кадров за {wall} мс ##",
        cold[0].2,
        cold[1].2,
        if frozen_ok { "ВЫПОЛНЕН" } else { "НЕ ВЫПОЛНЕН" },
    );
    remove(&d);
}

/// (5в) Зонд инструмента, оформленный как ДИАГНОЗ-5, а не как новый порог: в первом прогоне
/// прогретая лестница 18/20/22 дала времена с отношением ~1.0 вместо 4×, и nonce на всех трёх
/// уровнях оказался один и тот же. Возможных объяснений два — «гейт `pow_ok` не держит
/// сложность» (тогда цена записи из (5) фиктивна и это находка крипто-слоя) или «один невезучий
/// вход» (тогда дефект в методе замера: один вход = одна выборка, а у геометрического
/// распределения дисперсия равна среднему). Зонд различает их напрямую:
///
/// * проход A — доля принятых nonce при четырёх сложностях на одном и том же входе: `pow_ok`
///   обязан давать ~2^-bits, иначе гейт сломан;
/// * проход B — шесть **независимых** PoW-входов, на каждом минирование при 18/20/22 битах:
///   отношения счит по уровням и время; именно здесь видно, что «один вход, один nonce» —
///   выборка объёмом одна, а не постоянная майнера.
///
/// Порога у зонда нет: он обязан напечатать, а замораживать по нему утверждение задним числом
/// нельзя (`lab/README.md`, правило о ДИАГНОЗе в сильной форме).
#[test]
fn the_pow_gate_carries_difficulty_and_one_input_is_not_a_sample() {
    const RANGE: u64 = 100_000;
    let owner = testing::identity(101).pubkey();
    let intent = intent_id(&testing::vector(3), testing::PREPROCESSING_VERSION);
    let input = pow_input(&owner, SHARD, 1, &intent, 1 + u32::from(TTL));

    // Проход A: сколько nonce из 0..RANGE проходят при каждой сложности. Ожидание — RANGE / 2^bits.
    let mut accept = Vec::new();
    for bits in [8u32, 10, 12, 14] {
        let hits = (0..RANGE).filter(|n| pow_ok(&input, *n, bits)).count();
        accept.push((bits, hits as u64, RANGE / (1u64 << bits)));
    }

    // Проход B: шесть независимых входов × три сложности. `vec_seed` и сид автора меняются
    // вместе, поэтому `intent_id`, а с ним и `pow_input`, различны — это шесть разных задач.
    let mut ladder = Vec::new();
    for seed in 150..156u8 {
        let who = testing::identity(seed);
        let it = intent_id(&testing::vector(seed), testing::PREPROCESSING_VERSION);
        let inp = pow_input(&who.pubkey(), SHARD, 1, &it, 1 + u32::from(TTL));
        let mut row = Vec::new();
        for bits in [18u32, 20, 22] {
            let t = Instant::now();
            let nonce = testing::mine(&inp, bits);
            row.push((bits, t.elapsed().as_micros() as u64, nonce));
        }
        ladder.push(row);
    }
    let sum: Vec<(u32, u64, u64)> = (0..3)
        .map(|i| (ladder[0][i].0, ladder.iter().map(|r| r[i].1).sum(), ladder.iter().map(|r| r[i].2).sum()))
        .collect();
    let ratios: Vec<f64> = sum.windows(2).map(|w| (w[1].1 as f64) / (w[0].1.max(1) as f64)).collect();

    eprintln!(
        "## (5в) зонд: A) принятых nonce из {RANGE} при [8,10,12,14] битах — {accept:?} \
         (ожидание ~{}/2^bits); B) шесть независимых входов, сумма мкс и сумма nonce по уровням \
         {sum:?}, отношения соседних уровней {ratios:?} (ожидаемое ~4.0) ##",
        RANGE,
    );
}

/// (6) Proposed per-cluster cap — это **три** разные политики, и две из них сломаны. Живой код
/// cap не содержит, поэтому политики прогоняются симулятором поверх снятого трейса; форма
/// симулятора совпадает с `lab/lean/VecDHT/Admission.lean` (`admitX`/`admitA`/`admitM`), и
/// это correspondence-часть, а не замена замеру.
#[test]
fn per_cluster_cap_is_three_policies_and_two_are_broken() {
    const CAP: usize = 2_000;
    const MAX_CELL: usize = 8;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Kind {
        /// Новая запись.
        Fresh,
        /// Продление в той же ячейке (§11.3.2: перепубликация раз в TTL/2).
        Renew,
        /// Переезд в другую ячейку.
        Move,
    }

    // Трейс: честная ротация (продления) + атака (переезды в одну ячейку) + флуд новых записей.
    let mut trace: Vec<(usize, usize, Kind)> = Vec::new();
    for k in 0..60usize {
        let cell = k % 16;
        trace.push((k, cell, Kind::Fresh));
        trace.push((k, cell, Kind::Renew));
        trace.push((k, cell, Kind::Renew));
    }
    for k in 0..40usize {
        trace.push((k, 0, Kind::Move));
    }
    for k in 60..80usize {
        trace.push((k, 0, Kind::Fresh));
    }
    // ДИАГНОЗ-1 (первый прогон): в исходном трейсе не было ни одного продления **внутри полной
    // ячейки** — все они приходились на ячейку из одной записи, поэтому строгая форма ничего не
    // ломала и порог (6б) был недостижим. Первая попытка добрать сцену в ячейку 3 тоже не годилась:
    // её счёт зависит от двери (переезды уносят ключи 3/19/35 в нулевую ячейку не при всех
    // политиках), и сравнивать политики на разной наполненности нельзя. Сцена вынесена в ячейку
    // `BATTLE`, которую ни одна предыдущая сцена не трогает: до неё все три двери доводят
    // наполнение одинаково. Пороги не двигались — расширена только выборка.
    const BATTLE: usize = 100;
    for k in 80..96usize {
        trace.push((k, BATTLE, Kind::Fresh));
    }
    // Продления только по тем ключам, которые точно приняты при всех трёх политиках (первые
    // `MAX_CELL`): продление ключа, которого в профиле нет, честным не бывает, и оно смешало бы
    // «строгая форма ломает продления» с «форма отказывает несуществующей записи».
    for k in 80..(80 + MAX_CELL) {
        trace.push((k, BATTLE, Kind::Renew));
    }

    // Три политики над одной дверью вместимости (`admit`): льготу перепубликации в капле
    // размеров менять нельзя — это и есть предмет решения.
    fn door_capacity(profile: &[(usize, usize)], key: usize) -> bool {
        profile.len() < CAP || profile.iter().any(|r| r.0 == key)
    }
    fn cell(profile: &[(usize, usize)], c: usize) -> usize {
        profile.iter().filter(|r| r.1 == c).count()
    }
    fn place(profile: &[(usize, usize)], key: usize) -> Option<usize> {
        profile.iter().find(|r| r.0 == key).map(|r| r.1)
    }
    fn admit(door: usize, profile: &[(usize, usize)], key: usize, c: usize) -> bool {
        if !door_capacity(profile, key) {
            return false;
        }
        match door {
            0 => !(MAX_CELL <= cell(profile, c) && !profile.iter().any(|r| r.0 == key)),
            1 => !(MAX_CELL <= cell(profile, c)),
            _ => !(place(profile, key) != Some(c) && MAX_CELL <= cell(profile, c)),
        }
    }
    fn put(profile: &mut Vec<(usize, usize)>, key: usize, c: usize) {
        if let Some(r) = profile.iter_mut().find(|r| r.0 == key) {
            r.1 = c;
        } else {
            profile.push((key, c));
        }
    }

    let mut report = Vec::new();
    for door in 0..3usize {
        let mut profile: Vec<(usize, usize)> = Vec::new();
        let mut refused_renew = 0usize;
        let mut refused_fresh = 0usize;
        let mut refused_move = 0usize;
        for (key, c, kind) in &trace {
            if admit(door, &profile, *key, *c) {
                put(&mut profile, *key, *c);
            } else {
                match kind {
                    Kind::Renew => refused_renew += 1,
                    Kind::Fresh => refused_fresh += 1,
                    Kind::Move => refused_move += 1,
                }
            }
        }
        let hot = (0..16).map(|c| cell(&profile, c)).max().unwrap_or(0);
        report.push((door, hot, refused_renew, refused_move, refused_fresh, profile.len(), cell(&profile, BATTLE)));
    }
    let [x, a, m] = report.try_into().expect("три политики");

    // (6а) Льгота как у нынешнего гейта вместимости: кап пропускает переезды → ячейка выше cap.
    assert!(x.1 > MAX_CELL, "фальсификатор (6а): политика с льготой не протекла — {x:?}");
    assert_eq!(x.2, 0, "честные продления при ней не должны отвергаться");
    // (6б) Кап без льготы: течь нет, но продление в своей полной ячейке отвергнуто — это ломает
    // §11.3.2 (запись не может обновиться, а TTL у неё общий).
    assert_eq!(a.1, MAX_CELL, "строгая форма обязана держать cap — {a:?}");
    assert!(a.2 > 0, "фальсификатор (6б): строгая форма не ломает продления — {a:?}");
    // (6в) Кап с учётом переезда: cap держится и продления живы.
    assert_eq!(m.1, MAX_CELL, "форма с учётом переезда обязана держать cap — {m:?}");
    assert_eq!(m.2, 0, "форма с учётом переезда обязана пропускать продления — {m:?}");
    assert!(m.3 > 0, "форма с учётом переезда обязана отвергать переезд в полную ячейку — {m:?}");
    eprintln!(
        "## (6) три политики на трейсе {} кадров: льготa {} → горячая ячейка {}, продлений отвергнуто \
         {}; строгая {} → {}, {}; с учётом переезда {} → {}, продлений {}, переездов {}. Боевая \
         ячейка (свежие + продления в ней): [{}, {}, {}]. Профиль: [{}, {}, {}] записей. \
         Соответствие модели: admitX/admitA/admitM в Admission.lean ##",
        trace.len(),
        x.0, x.1, x.2,
        a.0, a.1, a.2,
        m.0, m.1, m.2, m.3,
        x.6, a.6, m.6,
        x.5, a.5, m.5
    );
}
