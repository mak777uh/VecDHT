//! `E-0026` (`H-0025`) — байты на границе узла на один запрос.
//!
//! Все семь закрытых рычагов цены (`E-0013`…`E-0024`) измеряли, сколько и чем считает узел **у себя**.
//! Эта запись измеряет то, что проходит через границу узла на один запрос, — ось, на которой внешний
//! архитектурный отзыв построил свой главный аргумент («Метод В: bytes transferred per query; если
//! \> 5–10 МБ — архитектура не выживет») и которую спека до сих пор держала как оценку в таблице §5.4
//! («`MatchResult (top-32)` ~1.3 КБ») и как слова в §13.1 («запрос раскрывает ~14 узлам…»).
//!
//! Сеть не поднимается: байты считают настоящие энкодеры — `vecdht_wire::Codec` (тело → кадр →
//! подпись) и `vecdht_net::codec::{encode_request, encode_response}` (префикс длины запроса и
//! счётчик батча ответа), то есть ровно те же функции, что вызывает `FrameCodec` в libp2p-стриме.
//! Подписи настоящие, ed25519, по каноническим байтам тела, и каждая проверяется `verify_body`.
//! Транспортный слой (QUIC/Noise/Yamux, заголовки стрима) в счёт не входит — это объявленный
//! недоучёт, а не часть измерения.
//!
//! Форма трафика взята из протокола и из точки гейта `E-0012`, а не из головы:
//!
//! * 16 владельцев (`MAX_OWNERS`, бюджет §7.5) — 16 × `Find` вверх, групповая заявка по кластерам
//!   (`clusters` = все 16 кластеров шарда, `H-0010`/`E-0011`);
//! * ответ владельца = **один батч**: подписанный `MatchResult` плюс по одному подписанному
//!   `RendezvousAccept` на каждую строку результата (§12.3; `crates/vecdht-node/src/node.rs`,
//!   `handle_find`: «приём — отдельный кадр 0x50 на каждую найденную запись», `Vec<Envelope>`
//!   размером `1 + matches.len()`). В пре-регистрации `H-0025` этого члена не было; он добавлен в
//!   стенд до прогона и помечен в `E-0026` как дополнение к измеряемому пути, а не как изменение
//!   порогов;
//! * `top_k` ∈ {32, 64} = `top_k_default` и `top_k_max` эталонного манифеста (узел к тому же
//!   обрезает `top_k` по `top_k_max`, поэтому рука 64 — физический потолок ответа);
//! * `IntentTextRequest`/`Response` на 32 пира (§12.6 «intent_text fan-out (32 пира)») с
//!   **настоящими текстами того же корпуса**: медиана, p95, максимум по корпусу и верхняя граница
//!   §6.6 (1000 Б).
//!
//! Руки «векторы по сети» контрфактические: протокол v8 их не делает. Они нужны ровно для одного
//! утверждения — нарушает ли «Метод А» отзыва его же выживательный порог, если рефайн делать по сети.
//!
//! Запуск: `./lab/e0026-run.sh`. Тексты корпуса опциональны: без файла печатается рука по лимиту
//! §6.6, и это худший случай по построению.

use std::path::{Path, PathBuf};

use vecdht_artifact::reference_manifest;
use vecdht_crypto::sig::verify_body;
use vecdht_net::codec::{encode_request, encode_response};
use vecdht_node::testing::{identity, PREPROCESSING_VERSION};
use vecdht_wire::{
    domain, CLUSTERS_PER_SHARD, Codec, DIM, ED25519_SIG_LEN, Find, IntentTextRequest,
    IntentTextResponse, Kind, Match, MatchResult, RendezvousAccept, SHARDS, MAX_INTENT_TEXT_BYTES,
    NLIST,
};

/// Бюджет §7.5 в точке гейта `E-0012`: 16 выбранных ячеек = 16 владельцев.
const OWNERS: usize = 16;
/// §12.6: «intent_text fan-out (32 пира)».
const INTENT_PEERS: usize = 32;
/// `top_k_default` и `top_k_max` эталонного манифеста; сверяются с манифестом ассертом.
const TOP_K_DEFAULT: usize = 32;
const TOP_K_MAX: usize = 64;
/// Контрфактика: размер канонической записи (§8.2) и код руки `m = 24` из `E-0023`.
const RECORD_BYTES: usize = 424;
const PQ_BYTES: usize = 24;
/// Число кандидатов в точке гейта (nprobe = 16), измеренное `E-0012`. Нужно только для рук
/// «PQ-код / целая запись на каждого кандидата».
const CANDIDATES_50K: f64 = 12_558.8;
const CANDIDATES_807K: f64 = 204_715.6;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
/// Порог выживания отзыва: нижняя граница диапазона 5–10 МБ.
const KILL_MB: usize = 5 * MIB;
/// Условие (3b) гипотезы: «PQ-код на всех кандидатах» обязана быть не ниже этого числа байт.
const PQ_FLOOR_MB: usize = 4 * MIB;
/// Строка §5.4: `MatchResult (top-32)` ~1.3 КБ.
const SPEC_MATCH_TOP32: f64 = 1300.0;

fn corpus_path(default: &str) -> Option<PathBuf> {
    let p = std::env::var("VEC_DHT_EGRESS_CORPUS").unwrap_or_else(|_| default.to_string());
    let path = PathBuf::from(&p);
    path.exists().then_some(path)
}

/// Реальные тексты корпуса: распределение длин и три представителя (медиана / p95 / максимум).
struct Texts {
    n: usize,
    mean: f64,
    median_len: usize,
    p95_len: usize,
    max_len: usize,
    median: Vec<u8>,
    p95: Vec<u8>,
    max: Vec<u8>,
    over_cap: usize,
}

fn load_texts(path: &Path) -> Texts {
    let raw = std::fs::read_to_string(path).expect("тексты корпуса читаются");
    let mut lines: Vec<&str> = raw.lines().map(|l| l.trim_end_matches('\r')).collect();
    lines.retain(|l| !l.is_empty());
    let n = lines.len();
    assert!(n > 0, "пустой файл текстов");
    let mut lens: Vec<usize> = lines.iter().map(|l| l.len()).collect();
    let sum: usize = lens.iter().sum();
    lens.sort_unstable();
    let pct = |q: usize| lens[(q * n).min(n - 1)];
    let (median_len, p95_len, max_len) = (pct(50), pct(95), *lens.last().unwrap());
    let over_cap = lens.iter().filter(|l| **l > MAX_INTENT_TEXT_BYTES).count();
    // Представитель — первая строка нужной длины: сама по себе реальная, из того же корпуса.
    let pick = |want: usize| -> Vec<u8> {
        lines
            .iter()
            .find(|l| l.len() == want)
            .map(|l| l.as_bytes().to_vec())
            .unwrap_or_default()
    };
    Texts {
        n,
        mean: sum as f64 / n as f64,
        median_len,
        p95_len,
        max_len,
        median: pick(median_len),
        p95: pick(p95_len),
        max: pick(max_len),
        over_cap,
    }
}

/// Один сегмент пути: кадры и байты на проводе, с разложением на состав.
#[derive(Default, Clone, Copy)]
struct Seg {
    frames: usize,
    wire: usize,
    bodies: usize,
    sigs: usize,
    counters: usize,
}

impl Seg {
    /// Кадр на проводе: 4 байта своей длины (префикс запроса или длина кадра в батче) + кадр.
    fn add_frame(&mut self, frame: &[u8], body: usize, signed: bool) {
        self.frames += 1;
        self.counters += 4;
        self.wire += 4 + frame.len();
        self.bodies += body;
        self.sigs += if signed { 1 + ED25519_SIG_LEN } else { 0 };
    }

    /// Запрос: ровно один кадр, помеченный префиксом длины.
    fn add_request(&mut self, frame: &[u8], body: usize, signed: bool) {
        self.add_frame(frame, body, signed);
    }

    /// Счётчик кадров батча ответа — 4 байта на батч, один раз на батч.
    fn add_batch_counter(&mut self) {
        self.counters += 4;
        self.wire += 4;
    }
}

/// Ответ одного владельца ровно той формы, что собирает `ShardNode::handle_find`: один батч,
/// в нём подписанный `MatchResult` + по подписанному `RendezvousAccept` на строку (§12.3).
struct OwnerAnswer {
    mr_frame: Vec<u8>,
    mr_body: usize,
    acc_frames: Vec<Vec<u8>>,
    acc_bodies: Vec<usize>,
}

fn owner_answer(shard: u16, rows: usize, epoch: u64, query_id: u64, seeker: [u8; 32]) -> OwnerAnswer {
    let m = reference_manifest();
    let node = identity(shard as u8);
    let matches: Vec<Match> = (0..rows)
        .map(|i| Match {
            owner_ed25519: identity(i as u8 + 1).pubkey(),
            // Кластеры этого шарда: контракт сортировки (`d2` ASC, затем `slot` ASC) соблюдён
            // по построению, потому что `d2` и `slot` растут вместе.
            cluster_id: shard * CLUSTERS_PER_SHARD + (i as u16 % CLUSTERS_PER_SHARD),
            d2: i as u32,
            slot: i as u32,
        })
        .collect();
    let res = MatchResult {
        shard,
        epoch,
        query_id,
        responder_ed25519: node.pubkey(),
        matches,
    };
    res.check_sort_contract().expect("контракт сортировки нарушен до подписания");
    let mr_body = res.body_bytes();
    let sig = node.sign_body(domain::MATCH, Kind::MatchResult, &mr_body);
    assert!(
        verify_body(&node.pubkey(), domain::MATCH, Kind::MatchResult, &mr_body, &sig)
            .expect("ключ подписанта валиден"),
        "подпись `MatchResult` не проходит проверку — счёт байтов идёт по невалидному кадру"
    );
    let mr_frame = res.encode_signed(&sig);
    assert_eq!(
        MatchResult::decode(&mr_frame).expect("кадр `MatchResult` разбирается"),
        res,
        "`MatchResult` не переживает round-trip — байтовый счёт не имеет смысла"
    );

    let mut acc_frames = Vec::with_capacity(rows);
    let mut acc_bodies = Vec::with_capacity(rows);
    for mt in &res.matches {
        let acc = RendezvousAccept {
            seeker,
            target: mt.owner_ed25519,
            shard,
            slot: mt.slot,
            issued_bucket: 41,
            ttl_sec: m.query.rendezvous_ttl_sec as u16,
        };
        let body = acc.body_bytes();
        let sig = node.sign_body(domain::RENDEZVOUS, Kind::RendezvousAccept, &body);
        assert!(
            verify_body(&node.pubkey(), domain::RENDEZVOUS, Kind::RendezvousAccept, &body, &sig)
                .expect("ключ подписанта валиден"),
            "подпись `RendezvousAccept` не проходит проверку"
        );
        let frame = acc.encode_signed(&sig);
        assert_eq!(
            RendezvousAccept::decode(&frame).expect("кадр приёма разбирается"),
            acc,
            "`RendezvousAccept` не переживает round-trip"
        );
        acc_bodies.push(body.len());
        acc_frames.push(frame);
    }
    OwnerAnswer { mr_frame, mr_body: mr_body.len(), acc_frames, acc_bodies }
}

/// Полный путь одного запроса при заданных `top_k` и руке текстов.
#[derive(Clone)]
struct PathBytes {
    top_k: usize,
    rows: usize,
    up_find: Seg,
    down_match: Seg,
    down_accept: Seg,
    up_text: Seg,
    down_text: Seg,
    text_arm: &'static str,
}

impl PathBytes {
    fn segs(&self) -> [(&'static str, Seg); 5] {
        [
            ("вверх  Find", self.up_find),
            ("вниз   MatchResult", self.down_match),
            ("вниз   RendezvousAccept", self.down_accept),
            ("вверх  IntentTextRequest", self.up_text),
            ("вниз   IntentTextResponse", self.down_text),
        ]
    }
    fn total(&self) -> usize {
        self.segs().iter().map(|(_, s)| s.wire).sum()
    }
    /// Что уходит **с одного узла-владельца** на запрос: его `Find` и его батч ответа.
    fn per_owner(&self) -> usize {
        (self.up_find.wire + self.down_match.wire + self.down_accept.wire) / OWNERS
    }
}

fn measure_path(top_k: usize, text: &[u8], text_arm: &'static str) -> PathBytes {
    let m = reference_manifest();
    let rows = top_k;
    let epoch = 1u64;
    let query_id = 0x0E00_2600u64;
    let agent = identity(200);
    let mut up_find = Seg::default();
    let mut down_match = Seg::default();
    let mut down_accept = Seg::default();

    for s in 0..OWNERS {
        let shard = s as u16;
        let find = Find {
            preprocessing_version: PREPROCESSING_VERSION,
            query_vector: [1i8; DIM],
            clusters: (0..CLUSTERS_PER_SHARD).map(|i| shard * CLUSTERS_PER_SHARD + i).collect(),
            top_k: top_k as u16,
            query_id,
            requester_ed25519: agent.pubkey(),
            tlv: Vec::new(),
        };
        let body = find.body_bytes();
        let frame = find.encode_unsigned();
        assert_eq!(
            Find::decode(&frame).expect("кадр `Find` разбирается"),
            find,
            "`Find` не переживает round-trip — байтовый счёт не имеет смысла"
        );
        up_find.add_request(
            &encode_request(&frame).expect("запрос влезает в кадр"),
            body.len(),
            false,
        );

        let a = owner_answer(shard, rows, epoch, query_id, agent.pubkey());
        // Один батч на владельца: MatchResult + все приёмы (§12.3).
        let mut frames = Vec::with_capacity(1 + a.acc_frames.len());
        frames.push(a.mr_frame.clone());
        frames.extend(a.acc_frames.iter().cloned());
        let batch = encode_response(&frames).expect("батч владельца влезает");
        let before_match = down_match.wire;
        let before_accept = down_accept.wire;
        down_match.add_batch_counter();
        down_match.add_frame(&a.mr_frame, a.mr_body, true);
        for (f, bl) in a.acc_frames.iter().zip(&a.acc_bodies) {
            down_accept.add_frame(f, *bl, true);
        }
        // Учёт по сегментам обязан совпасть с реальным байтом энкодера, а не с арифметикой автора.
        assert_eq!(
            batch.len(),
            (down_match.wire - before_match) + (down_accept.wire - before_accept),
            "разложение ответа по сегментам разошлось с настоящим батчем"
        );
    }

    let mut up_text = Seg::default();
    let mut down_text = Seg::default();
    for i in 0..INTENT_PEERS {
        let owner = identity(i as u8 + 1);
        let req = IntentTextRequest { query_id, target_ed25519: owner.pubkey(), slot: i as u32 };
        let body = req.body_bytes();
        let frame = req.encode_unsigned();
        assert_eq!(
            IntentTextRequest::decode(&frame).expect("кадр `IntentTextRequest` разбирается"),
            req,
            "`IntentTextRequest` не переживает round-trip"
        );
        up_text.add_request(&encode_request(&frame).expect("запрос влезает"), body.len(), false);

        let resp = IntentTextResponse {
            owner_ed25519: owner.pubkey(),
            model_version: m.model_version.clone(),
            preprocessing_version: PREPROCESSING_VERSION,
            text: text.to_vec(),
        };
        let body = resp.body_bytes();
        let sig = owner.sign_body(domain::TEXT, Kind::IntentTextResponse, &body);
        assert!(
            verify_body(&owner.pubkey(), domain::TEXT, Kind::IntentTextResponse, &body, &sig)
                .expect("ключ подписанта валиден"),
            "подпись текста не проходит проверку"
        );
        let frame = resp.encode_signed(&sig);
        assert_eq!(
            IntentTextResponse::decode(&frame).expect("кадр `IntentTextResponse` разбирается"),
            resp,
            "`IntentTextResponse` не переживает round-trip"
        );
        down_text.add_batch_counter();
        down_text.add_frame(&frame, body.len(), true);
    }

    PathBytes {
        top_k,
        rows,
        up_find,
        down_match,
        down_accept,
        up_text,
        down_text,
        text_arm,
    }
}

fn print_path(p: &PathBytes, corpus: &str) {
    let total = p.total();
    println!(
        "  [{corpus}] top_k={:<3} строк/владелец={:<4} рука текстов={:<12} всего/запрос {:>8.1} КБ ({:>6.3} МБ)",
        p.top_k,
        p.rows,
        p.text_arm,
        total as f64 / KIB as f64,
        total as f64 / MIB as f64,
    );
    for (name, seg) in p.segs() {
        println!(
            "        {name:<24} кадров {:>4}  байт на проводе {:>9.1} КБ  ({:>5.1} % пути)",
            seg.frames,
            seg.wire as f64 / KIB as f64,
            100.0 * seg.wire as f64 / total as f64,
        );
    }
    println!(
        "        на одного владельца: {:>6.2} КБ ({} байт); RPS-потолок узла при uplink 100 Мбит/с = {:.0}",
        p.per_owner() as f64 / KIB as f64,
        p.per_owner(),
        12_500_000.0 / p.per_owner() as f64,
    );
    let frames: usize = p.segs().iter().map(|(_, s)| s.frames).sum();
    let sigs: usize = p.segs().iter().map(|(_, s)| s.sigs).sum();
    let heads = frames * 8;
    let counters: usize = p.segs().iter().map(|(_, s)| s.counters).sum();
    let bodies: usize = p.segs().iter().map(|(_, s)| s.bodies).sum();
    println!(
        "        состав: тела {bodies} Б ({:.1} %), подписи {sigs} Б ({:.1} %), заголовки кадров {heads} Б ({:.1} %), префиксы/счётчики {counters} Б ({:.1} %)",
        100.0 * bodies as f64 / total as f64,
        100.0 * sigs as f64 / total as f64,
        100.0 * heads as f64 / total as f64,
        100.0 * counters as f64 / total as f64,
    );
    let cross_check = bodies + sigs + heads + counters;
    println!(
        "        контроль состава: сумма частей {cross_check} против общего пути {total} ⇒ {}",
        if cross_check == total { "совпало" } else { "РАСХОЖДЕНИЕ" },
    );
}

/// Контрфактические руки «содержимое по сети»: raw-payload без кадрирования, то есть нижняя
/// граница — с кадрами и подписями было бы только больше.
fn counterfactuals(candidates: f64) {
    for r in [100usize, 1024] {
        let bytes = r * DIM * OWNERS;
        println!(
            "  контрфактика: int8-рефайн по сети, R={r:<5} на владельца ⇒ {:>7.2} МБ (raw, без кадрирования)",
            bytes as f64 / MIB as f64
        );
    }
    println!(
        "  контрфактика: PQ-код ({PQ_BYTES} Б) на всех кандидатов гейта {candidates:>10.1} ⇒ {:>7.2} МБ",
        candidates * PQ_BYTES as f64 / MIB as f64
    );
    println!(
        "  контрфактика: целые записи ({RECORD_BYTES} Б) на тех же кандидатов ⇒ {:>7.2} МБ",
        candidates * RECORD_BYTES as f64 / MIB as f64
    );
}

fn pass(v: &bool) -> &'static str {
    if *v { "PASS" } else { "FAIL" }
}

#[test]
fn egress_bytes_per_query() {
    let m = reference_manifest();
    println!(
        "E-0026 (H-0025): байты на границе узла на один запрос. Владельцев {OWNERS}, кластеров в \
         заявке {}, nlist {}, шардов {}, DIM {DIM}, top_k = {{default {}, max {}}}, intent_text \
         fan-out {INTENT_PEERS}, preprocessing_version {PREPROCESSING_VERSION}, модель {:?}",
        CLUSTERS_PER_SHARD,
        NLIST,
        SHARDS,
        m.query.top_k_default,
        m.query.top_k_max,
        m.model_version,
    );
    assert_eq!(m.query.top_k_default as usize, TOP_K_DEFAULT);
    assert_eq!(m.query.top_k_max as usize, TOP_K_MAX);
    assert_eq!(m.query.intent_text_max_bytes as usize, MAX_INTENT_TEXT_BYTES);

    // ── контроль корректности: арифметика `MatchResult` и сверка со строкой §5.4 ────────────
    for rows in [TOP_K_DEFAULT, TOP_K_MAX] {
        let a = owner_answer(7, rows, 1, 0x0E00_2600, identity(200).pubkey());
        let expected = 8 + 52 + 42 * rows + 1 + ED25519_SIG_LEN;
        assert_eq!(
            a.mr_frame.len(),
            expected,
            "`MatchResult` не совпал с арифметикой 42 Б/строка + 52 Б тела + 8 Б заголовка + 65 Б подписи"
        );
        assert_eq!(
            a.mr_body,
            52 + 42 * rows,
            "тело `MatchResult` вне арифметики контракта: 2+8+8+32+2 Б шапки + 42 Б на строку"
        );
        assert_eq!(a.acc_bodies.iter().sum::<usize>(), 76 * rows);
        for bl in &a.acc_bodies {
            assert_eq!(*bl, 76, "тело приёма обязано быть ровно 76 Б (32+32+2+4+4+2)");
        }
        if rows == TOP_K_DEFAULT {
            let dev = a.mr_frame.len() as f64 / SPEC_MATCH_TOP32 - 1.0;
            println!(
                "  сноска §5.4: `MatchResult (top-32)` измерено {} Б против оценки спеки ~1,3 КБ ⇒ \
                 расхождение {:.1} %{} (порог пометки — 10 %)",
                a.mr_frame.len(),
                100.0 * dev,
                if dev.abs() > 0.10 { " — СТРОКА СПЕКИ ТРЕБУЕТ ПЕРЕПИСИ" } else { "" },
            );
            // Вторая строка той же таблицы: «RendezvousAccept 78 байт тело + 64 подпись».
            let one = owner_answer(7, 1, 1, 0x0E00_2600, identity(200).pubkey());
            println!(
                "  сноска §5.4: `RendezvousAccept` измерено {} Б тела и {} Б кадра (8 заголовок + \
                 тело + 1 флаг + 64 подпись) против «78 тело + 64 подпись» ⇒ {}",
                one.acc_bodies[0],
                one.acc_frames[0].len(),
                if one.acc_bodies[0] == 78 { "совпало" } else { "СТРОКА ТРЕБУЕТ ПЕРЕПИСИ" },
            );
        }
    }

    let mut report: Vec<(String, String, usize, usize)> = Vec::new();
    for (name, n_records, candidates) in [
        ("807 596", 807_596usize, CANDIDATES_807K),
        ("50 000", 50_000usize, CANDIDATES_50K),
    ] {
        // Записей на шард: карта `E-0012` ровна по кластерам (16 на шард), но не по записям
        // (`E-0016`: 460 … 1242 документа на шард на 50k). Для числа строк в ответе важен только
        // вопрос «не обрезается ли top_k», поэтому берётся среднее и проверяется, что оно выше
        // top_k_max.
        let records_per_shard = n_records / SHARDS as usize;
        println!("\n Корпус {name}: {n_records} записей, в среднем {records_per_shard} на шард");
        assert!(
            records_per_shard >= TOP_K_MAX,
            "шард короче top_k_max — строки `MatchResult` обрезались бы, и руки неверны"
        );

        let path = corpus_path(if name == "50 000" {
            "C:/Users/Admin/models/p0-msmarco/corpus-50k.txt"
        } else {
            "C:/Users/Admin/models/p0-msmarco/corpus-807k-superset.txt"
        });
        let arms: Vec<(&'static str, Vec<u8>)> = match &path {
            Some(p) => {
                let t = load_texts(p);
                println!(
                    "  настоящие тексты ({}): {} строк, средняя длина {:.1} Б, медиана {}, p95 {}, \
                     максимум {}, строк длиннее лимита §6.6: {}",
                    p.display(),
                    t.n,
                    t.mean,
                    t.median_len,
                    t.p95_len,
                    t.max_len,
                    t.over_cap,
                );
                assert!(
                    t.max_len <= MAX_INTENT_TEXT_BYTES,
                    "в корпусе есть тексты длиннее лимита §6.6 ({MAX_INTENT_TEXT_BYTES}) — контракт \
                     publish их бы отверг (строк таких: {})",
                    t.over_cap
                );
                vec![
                    ("медиана", t.median.clone()),
                    ("p95", t.p95.clone()),
                    ("максимум", t.max.clone()),
                    ("лимит §6.6", vec![b'x'; MAX_INTENT_TEXT_BYTES]),
                ]
            }
            None => {
                println!("  тексты корпуса недоступны — печатается верхняя граница §6.6");
                vec![("лимит §6.6", vec![b'x'; MAX_INTENT_TEXT_BYTES])]
            }
        };

        for (arm, text) in &arms {
            for top_k in [TOP_K_DEFAULT, TOP_K_MAX] {
                let p = measure_path(top_k, text, arm);
                print_path(&p, name);
                report.push((name.to_string(), arm.to_string(), top_k, p.total()));
            }
        }
        counterfactuals(candidates);

        // §13.1: «запрос раскрывает ~14 узлам». Считаем, скольким пирам запрос реально что-то шлёт.
        let cap_text = vec![b'x'; MAX_INTENT_TEXT_BYTES];
        let p = measure_path(TOP_K_MAX, &cap_text, "лимит §6.6");
        let touched = OWNERS + INTENT_PEERS;
        println!(
            "  сноска §13.1: затронутых пира на запрос {touched} (16 владельцев + 32 text-пира) \
             против «~14 узлам» ⇒ {}",
            if (touched as f64 - 14.0).abs() <= 2.0 { "совпало" } else { "СТРОКА ТРЕБУЕТ ПЕРЕПИСИ" },
        );
        println!(
            "      вверх на пир-агента: {:.1} КБ; вниз агенту: {:.1} КБ (сумма пути {:.1} КБ)",
            (p.up_find.wire + p.up_text.wire) as f64 / KIB as f64,
            (p.down_match.wire + p.down_accept.wire + p.down_text.wire) as f64 / KIB as f64,
            p.total() as f64 / KIB as f64,
        );
    }

    // ── условия успеха `H-0025` (пороги зафиксированы до прогона) ───────────────────────────
    println!("\nУСЛОВИЯ H-0025 (807 596; байты приложения, транспорт QUIC/Noise не учтён):");
    let worst = |corpus: &str, top_k: usize| -> usize {
        report
            .iter()
            .filter(|(c, _, k, _)| c.as_str() == corpus && *k == top_k)
            .map(|(_, _, _, t)| *t)
            .max()
            .unwrap_or(0)
    };
    let median_arm = |corpus: &str, top_k: usize| -> usize {
        report
            .iter()
            .find(|(c, a, k, _)| c.as_str() == corpus && a.as_str() == "медиана" && *k == top_k)
            .map(|(_, _, _, t)| *t)
            .unwrap_or(0)
    };
    let c1 = worst("807 596", TOP_K_MAX);
    let c2 = worst("807 596", TOP_K_DEFAULT);
    let int8_1024 = 1024 * DIM * OWNERS;
    let int8_100 = 100 * DIM * OWNERS;
    let pq_807k = (CANDIDATES_807K * PQ_BYTES as f64) as usize;
    println!(
        "  (1) протокольный путь, top_k = 64, худшая рука текстов = {:.0} КБ ≤ 1 МБ ⇒ {}",
        c1 as f64 / KIB as f64,
        if c1 <= MIB { "PASS" } else { "FAIL" }
    );
    println!(
        "      top_k = 64: по медиане текстов {:.0} КБ, по лимиту §6.6 {:.0} КБ",
        median_arm("807 596", TOP_K_MAX) as f64 / KIB as f64,
        c1 as f64 / KIB as f64,
    );
    println!(
        "  (2) протокольный путь, top_k = 32, худшая рука текстов = {:.0} КБ ≤ 1 МБ ⇒ {}",
        c2 as f64 / KIB as f64,
        if c2 <= MIB { "PASS" } else { "FAIL" }
    );
    println!(
        "  (3a) int8-рефайн R=1024 по сети = {:.2} МБ > 5 МБ ⇒ {}",
        int8_1024 as f64 / MIB as f64,
        if int8_1024 > KILL_MB { "PASS" } else { "FAIL" }
    );
    println!(
        "  (3b) PQ-код на всех кандидатах 807k = {:.2} МБ ≥ 4 МБ ⇒ {}",
        pq_807k as f64 / MIB as f64,
        if pq_807k >= PQ_FLOOR_MB { "PASS" } else { "FAIL" }
    );
    println!(
        "  (3c) int8-рефайн R=100 = {:.0} КБ ≥ 5× протокольного пути ({:.0} КБ, ×{:.1}) ⇒ {}",
        int8_100 as f64 / KIB as f64,
        c1 as f64 / KIB as f64,
        int8_100 as f64 / c1.max(1) as f64,
        if int8_100 >= 5 * c1 { "PASS" } else { "FAIL" }
    );
    let verdict = [
        c1 <= MIB,
        c2 <= MIB,
        int8_1024 > KILL_MB,
        pq_807k >= PQ_FLOOR_MB,
        int8_100 >= 5 * c1,
    ];
    println!(
        "\n  ИТОГ: (1) {} (2) {} (3a) {} (3b) {} (3c) {} — все пять пунктов выше: {}",
        pass(&verdict[0]),
        pass(&verdict[1]),
        pass(&verdict[2]),
        pass(&verdict[3]),
        pass(&verdict[4]),
        if verdict.iter().all(|v| *v) { "ГИПОТЕЗА ПОДТВЕРЖДЕНА" } else { "ЕСТЬ НАРУШЕННЫЕ УСЛОВИЯ — см. выше" },
    );

    // Фальсификатор `H-0025` (а)/(б)/(в) — проверяется отдельно от условий успеха: именно он
    // определяет вердикт, а не пять пунктов выше.
    println!("\nФАЛЬСИФИКАТОР H-0025 (807 596):");
    println!(
        "  (а) протокольный путь > 1 МБ ⇒ {}",
        if c1 > MIB { "НАРУШЕН" } else { "не нарушен" }
    );
    println!(
        "  (б) векторный рефайн R=100 укладывается в 1 МБ ({:.0} КБ) ⇒ {}",
        int8_100 as f64 / KIB as f64,
        if int8_100 <= MIB { "НАРУШЕН" } else { "не нарушен" }
    );
    println!(
        "  (в) R=1024 остаётся ниже 5 МБ ({:.2} МБ) ⇒ {}",
        int8_1024 as f64 / MIB as f64,
        if int8_1024 < KILL_MB { "НАРУШЕН" } else { "не нарушен" }
    );
    println!(
        "  (б') справочно: та же рука без владельцев по отдельности — 100 векторов суммарно = {:.0} КБ",
        100.0 * DIM as f64 / KIB as f64
    );
}
