//! D2 — векторы платных заказов, порождённые кодом.
//!
//! Документ `docs/PAID_ORDER-VECTORS.md` не пишется руками: его печатает этот тест. Причина та же,
//! что гоняла нас по всему лабу — число, которое никто не исполнял, есть вымысел. Здесь каждый хеш,
//! каждая строка канонической записи, каждый код ошибки и каждая ячейка матрицы состояний получены
//! вызовом функции из `vecdht-orders`, поэтому читатель, повторяющий команду воспроизведения, обязан
//! сойтись с документом байт в байт.
//!
//! Воспроизведение:
//!     cargo test -q -p vecdht-orders --test paid_order_vectors -- --nocapture
//!     V9_VECTORS_OUT=docs/PAID_ORDER-VECTORS.md cargo test -q -p vecdht-orders \
//!         --test paid_order_vectors -- --nocapture
//!
//! Что считается провалом прибора: векторов меньше 12; хоть один код из закрытого списка не
//! воспроизведён; на месте оказался не тот код, что заявлен; документ не записан, когда для этого
//! задана переменная окружения.

use vecdht_orders::*;

/// Байтовый шаблон `[v; 32]` — чтобы читатель мог собрать тот же массив сам, без hex-парсера.
fn pattern(v: u8) -> Hash {
    [v; 32]
}

/// Печатать текст, не внося в документ символов чужих алфавитов: док-guard (§стража текста) ловит
/// латиницу с диакритикой в русском тексте, а пример W2 именно про неё. Сами байты при этом
/// напечатаны hex — читатель видит и то, и другое.
fn ascii_debug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() && !c.is_control() {
            out.push(c);
        } else {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        }
    }
    out
}

fn stmt() -> Vec<u8> {
    normalize_statement(
        b"theorem add_zero_right (n : Nat) : n + 0 = n := by\n  induction n with\n    | zero => rfl\n    | succ k ih => simp [Nat.succ_add, ih]\n",
    )
    .unwrap()
}

fn base_order() -> PaidOrder {
    let (sk, vk) = keypair(1);
    let statement = stmt();
    let mut o = PaidOrder {
        kind: Kind::LeanProof,
        statement_hash: statement_hash(Kind::LeanProof, &statement).unwrap(),
        statement,
        verifier: VerifierSpec {
            image_digest: pattern(0x2a),
            entrypoint: "/usr/local/bin/verify".to_string(),
            budget_seconds: 120,
            network: false,
        },
        reward: Reward {
            amount: 1_000_000,
            asset: Asset::Native,
            escrow_ref: b"vecdht:escrow/0x01".to_vec(),
        },
        deadline: 1_800_000_000,
        submit_limit: 8,
        publisher: *vk.as_bytes(),
        nonce: 7,
        signature: None,
    };
    o.sign(&sk);
    o
}

fn files() -> Vec<ArtifactFile> {
    vec![
        ArtifactFile { path: "Proof.lean".to_string(), content_sha256: pattern(0x11) },
        ArtifactFile { path: "lake-manifest.json".to_string(), content_sha256: pattern(0x22) },
    ]
}

fn base_submission(o: &PaidOrder) -> Submission {
    let (sk, vk) = keypair(2);
    let mut s = Submission {
        order_ref: o.order_ref(),
        artifact_hash: artifact_set_hash(&files()).unwrap(),
        artifact_uri: "ipfs://bafybeiexample".to_string(),
        submitter: *vk.as_bytes(),
        nonce: 1,
        created_at: 1_799_999_999,
        signature: None,
    };
    s.sign(&sk);
    s
}

/// Квитанция, собранная так, как её собрал бы верификатор: поля измерены, подпись — последнее.
fn make_receipt(o: &PaidOrder, s: &Submission, verdict: Verdict, exit_code: i32, wall: u64, axioms: &[&str]) -> Receipt {
    let (sk, vk) = keypair(3);
    let mut r = Receipt {
        order_ref: o.order_ref(),
        submission_ref: s.submission_ref(),
        verdict,
        image_digest: o.verifier.image_digest,
        toolchain: "leanprover/lean4:v4.9.1".to_string(),
        axioms: axioms.iter().map(|a| a.to_string()).collect(),
        wall_clock_ms: wall,
        budget_ms: u64::from(o.verifier.budget_seconds) * 1_000,
        exit_code,
        stdout_sha256: pattern(0x33),
        stderr_sha256: pattern(0x44),
        deterministic: true,
        verifier_pubkey: *vk.as_bytes(),
        signature: None,
    };
    r.sign(&sk);
    r
}

fn escrow_locked(o: &PaidOrder) -> EscrowState {
    EscrowState {
        chain_id: o.reward.asset.chain_id(),
        asset: o.reward.asset.clone(),
        amount: o.reward.amount,
        status: EscrowStatus::Locked,
    }
}

// ---------------------------------------------------------------------------
// Три нормативных примера канонизации (§3.2.4 задачи)
// ---------------------------------------------------------------------------

/// Один пример канонизации: что издатель положил в поле, что осталось после пяти шагов, и хеш.
/// `raw` намеренно грязный в каждом из трёх примеров — иначе пример не учит ничему, кроме «уже
/// правильно».
struct Worked {
    id: &'static str,
    kind: Kind,
    note: &'static str,
    raw: Vec<u8>,
    norm: Vec<u8>,
    hash: Hash,
}

fn worked() -> Vec<Worked> {
    let cases: [(&str, Kind, &str, Vec<u8>); 3] = [
        (
            "W1",
            Kind::LeanProof,
            "CRLF, хвостовые пробелы, пустые строки в конце",
            b"theorem add_zero_right (n : Nat) : n + 0 = n := by\r\n  induction n with  \r\n    | zero => rfl\r\n    | succ k ih => simp [Nat.succ_add, ih]\r\n\r\n\r\n".to_vec(),
        ),
        (
            // `e` + U+0301 против U+00E9: два способа закодировать один и тот же символ, один хеш.
            "W2",
            Kind::TestConformance,
            "NFC: `e` + U+0301 схлопывается в U+00E9",
            b"# test suite: cafe\x65\xcc\x81 conformance\r\nsteps:\r\n  - id: reopen_after_snapshot\r\n  - id: wal_gap_detected\r\n".to_vec(),
        ),
        (
            "W3",
            Kind::ReproRun,
            "манифест прогона: CR в конце строк и табуляция перед переводом",
            b"{\r\n  \"cmd\": [\"sh\", \"-c\", \"make -C repro check\"],\r\n  \"seed\": 0\r\n}\t\r\n".to_vec(),
        ),
    ];
    cases
        .into_iter()
        .map(|(id, kind, note, raw)| {
            let norm = normalize_statement(&raw).expect("пример нормализуется");
            let hash = statement_hash(kind, &raw).expect("пример хешируется");
            Worked { id, kind, note, raw, norm, hash }
        })
        .collect()
}

/// Свойства, без которых примеры не примеры, а декорация: нормализация идемпотентна, а хеш
/// грязного и чистого входа один (иначе «две кодировки одного смысла» из §V9.3 — ложь).
fn worked_props(ws: &[Worked]) -> (bool, bool) {
    let mut idempotent = true;
    let mut stable = true;
    for w in ws {
        if normalize_statement(&w.norm).unwrap() != w.norm {
            idempotent = false;
        }
        if statement_hash(w.kind, &w.norm).unwrap() != w.hash {
            stable = false;
        }
    }
    (idempotent, stable)
}

/// Команда воспроизведения для читателя без Rust: домен, разделители `0x00`, байт-тег `kind` и
/// нормализованные байты (hex) собраны в одну строку. `python3` взят потому, что он есть и на
/// Windows, и на POSIX, а `xxd` — нет. Порядок байтов ровно такой, как в §V9.3:
/// `domain || 0x00 || kind_tag || 0x00 || normalized` — два разделителя вокруг тега, а не три нуля.
fn worked_hash_command(w: &Worked) -> String {
    format!(
        "python3 -c 'import hashlib; print(hashlib.sha256(b\"vecdht/paid_order/v1\\x00\" + bytes([{}]) + b\"\\x00\" + bytes.fromhex(\"{}\")).hexdigest())'",
        w.kind.tag(),
        hex_lower(&w.norm)
    )
}

struct Vector {
    id: &'static str,
    title: &'static str,
    accept: bool,
    code: Option<ErrorCode>,
    facts: Vec<(&'static str, String)>,
}

impl Vector {
    fn to_json(&self) -> String {
        let mut top: Vec<String> = Vec::new();
        top.push(format!("\"id\":\"{}\"", self.id));
        top.push(format!("\"title\":\"{}\"", esc(self.title)));
        top.push(format!("\"outcome\":\"{}\"", if self.accept { "accept" } else { "reject" }));
        top.push(match self.code {
            Some(c) => format!("\"code\":\"{}\",\"action\":\"{}\"", c.as_str(), c.action().as_str()),
            None => "\"code\":null,\"action\":null".to_string(),
        });
        let f: Vec<String> = self.facts.iter().map(|(k, v)| format!("\"{}\":\"{}\"", k, esc(v))).collect();
        top.push(format!("\"facts\":{{{}}}", f.join(",")));
        format!("{{{}}}", top.join(","))
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Вектор-отказ: код берётся из фактической ошибки, а сверка с заявленным — проверка самого прибора.
fn reject(id: &'static str, title: &'static str, want: ErrorCode, got: OrderError, facts: Vec<(&'static str, String)>) -> Vector {
    assert_eq!(got.code, want, "{id}: ждали {}, прибор выдал {}", want.as_str(), got.code.as_str());
    assert!(!got.reason.is_empty(), "{id}: у отказа обязана быть причина");
    Vector { id, title, accept: false, code: Some(want), facts }
}

fn accept(id: &'static str, title: &'static str, facts: Vec<(&'static str, String)>) -> Vector {
    Vector { id, title, accept: true, code: None, facts }
}

fn s(v: impl std::fmt::Display) -> String {
    v.to_string()
}

fn vectors() -> Vec<Vector> {
    let mut out: Vec<Vector> = Vec::new();
    let o = base_order();
    let (pub_sk, pub_vk) = keypair(1);
    let (sub_sk, sub_vk) = keypair(2);
    let (ver_sk, ver_vk) = keypair(3);
    let sub = base_submission(&o);

    // V01 — единственный полный путь: заказ принят, подача принята, квитанция годна, выплата открыта.
    {
        let order = o.clone();
        order.check().expect("V01: заказ обязан пройти структурную проверку");
        assert!(order.verify_publisher(&pub_vk), "V01: подпись издателя обязана пройти");
        check_submission(&order, &sub, &files(), &sub_vk, &[], 0).expect("V01: подача обязана быть принята");
        let r = make_receipt(&order, &sub, Verdict::Pass, 0, 41_000, &["propext", "Classical.choice"]);
        r.validate(&order, &sub, &ver_vk).expect("V01: квитанция обязана быть годной");
        assert!(r.payout_allowed(&order, &sub, &ver_vk, order.deadline + PAYBACK_WINDOW_SECONDS));
        check_escrow(&order, &escrow_locked(&order), &[0]).expect("V01: эскроу обязан совпасть с заказом");
        out.push(accept("V01", "Полный путь: заказ, подача, квитанция, выплата", vec![
            ("kind", order.kind.as_str().to_string()),
            ("statement_hex", hex_lower(&order.statement)),
            ("statement_hash", hex_lower(&order.statement_hash)),
            ("order_ref", hex_lower(&order.order_ref())),
            ("canonical_record_hex", hex_lower(&order.canonical_record())),
            ("canonical_record_len", s(order.canonical_record().len())),
            ("order_signature_hex", hex_lower(order.signature.as_ref().unwrap())),
            ("artifact_set_hash", hex_lower(&sub.artifact_hash)),
            ("submission_ref", hex_lower(&sub.submission_ref())),
            ("receipt_canonical_json", String::from_utf8(r.canonical_json().unwrap()).unwrap()),
            ("receipt_signature_hex", hex_lower(r.signature.as_ref().unwrap())),
            ("derived_verdict", r.derive(&order).unwrap().as_str().to_string()),
            ("payout_allowed", s(true)),
            ("escrow", "locked, native, amount = reward.amount".to_string()),
        ]));
    }

    // V02 — канонизация: CRLF, хвостовые пробелы, хвостовые пустые строки и NFC-эквивалентность.
    {
        let raw = "theorem t : True := by trivial  \r\n\r\n\r\n";
        let norm = normalize_statement(raw.as_bytes()).unwrap();
        let h1 = statement_hash(Kind::LeanProof, "e\u{301} t".as_bytes()).unwrap();
        let h2 = statement_hash(Kind::LeanProof, "\u{e9} t".as_bytes()).unwrap();
        assert_eq!(h1, h2, "V02: NFC обязан схлопнуть decomposed и precomposed");
        out.push(accept("V02", "Канонизация задания: CRLF, хвостовые пробелы, пустые строки, NFC", vec![
            ("input_hex", hex_lower(raw.as_bytes())),
            ("normalized_hex", hex_lower(&norm)),
            ("normalized_len", s(norm.len())),
            ("nfc_decomposed_hash", hex_lower(&h1)),
            ("nfc_precomposed_hash", hex_lower(&h2)),
            ("nfc_equal", s(true)),
            ("comments", "не вырезаются: комментарии остаются частью задания".to_string()),
        ]));
    }

    // V03 — обещанный хеш задания не совпал с посчитанным.
    {
        let mut bad = o.clone();
        bad.statement_hash = pattern(0x99);
        out.push(reject(
            "V03",
            "statement_hash не совпал с пересчитанным",
            ErrorCode::E_HASH_MISMATCH,
            bad.check().unwrap_err(),
            vec![
                ("declared", hex_lower(&bad.statement_hash)),
                ("computed", hex_lower(&statement_hash(bad.kind, &bad.statement).unwrap())),
            ],
        ));
    }

    // V04 — заказ хранит задание не в нормализованной форме.
    {
        let mut bad = o.clone();
        bad.statement = b"theorem t : True := by trivial\r\n".to_vec();
        bad.statement_hash = statement_hash(bad.kind, &bad.statement).unwrap();
        bad.sign(&pub_sk);
        out.push(reject(
            "V04",
            "задание в канонической записи не проходит нормализацию (CRLF)",
            ErrorCode::E_STATEMENT_ENCODING,
            bad.check().unwrap_err(),
            vec![("statement_hex", hex_lower(&bad.statement))],
        ));
    }

    // V05 — задание не является UTF-8.
    {
        let raw: &[u8] = &[0xff, 0xfe, 0x00, 0x41];
        out.push(reject(
            "V05",
            "задание не декодируется как UTF-8",
            ErrorCode::E_STATEMENT_ENCODING,
            normalize_statement(raw).unwrap_err(),
            vec![("input_hex", hex_lower(raw))],
        ));
    }

    // V06 — в Lean-задании есть `sorry`: просить награду за недоказанное нельзя.
    {
        let mut bad = o.clone();
        bad.statement = normalize_statement(b"theorem t : True := by sorry\n").unwrap();
        bad.statement_hash = statement_hash(bad.kind, &bad.statement).unwrap();
        bad.sign(&pub_sk);
        out.push(reject(
            "V06",
            "Lean-задание содержит запрещённый маркер sorry",
            ErrorCode::E_AXIOM_NOT_ALLOWED,
            bad.check().unwrap_err(),
            vec![("statement_hex", hex_lower(&bad.statement)), ("marker", "sorry".to_string())],
        ));
    }

    // V07 — нулевой бюджет: заказ, который нельзя исполнить с потолком.
    {
        let mut bad = o.clone();
        bad.verifier.budget_seconds = 0;
        bad.sign(&pub_sk);
        out.push(reject(
            "V07",
            "нулевой budget_seconds",
            ErrorCode::E_ORDER_MALFORMED,
            bad.check().unwrap_err(),
            vec![("budget_seconds", "0".to_string())],
        ));
    }

    // V08 — неизвестный тег kind.
    {
        out.push(reject(
            "V08",
            "неизвестный тег kind",
            ErrorCode::E_ORDER_MALFORMED,
            Kind::from_tag(9).unwrap_err(),
            vec![("tag", "9".to_string()), ("known_tags", "0=lean_proof, 1=test_conformance, 2=repro_run".to_string())],
        ));
    }

    // V09 — путь файла артефакта выходит за дерево.
    {
        let bad_files = vec![ArtifactFile { path: "../etc/passwd".to_string(), content_sha256: pattern(0x11) }];
        out.push(reject(
            "V09",
            "путь файла артефакта с ..",
            ErrorCode::E_ARTIFACT_PATH,
            artifact_set_hash(&bad_files).unwrap_err(),
            vec![("path", "../etc/passwd".to_string())],
        ));
    }

    // V10 — пустое множество файлов: проверять нечем.
    {
        out.push(reject(
            "V10",
            "пустое множество файлов артефакта",
            ErrorCode::E_ARTIFACT_EMPTY,
            artifact_set_hash(&[]).unwrap_err(),
            vec![("files", "0".to_string())],
        ));
    }

    // V11 — обещанный хеш артефакта не совпал с содержимым.
    {
        let mut late = sub.clone();
        late.artifact_hash = pattern(0x77);
        late.sign(&sub_sk);
        out.push(reject(
            "V11",
            "artifact_hash подачи не совпал с пересчитанным множеством",
            ErrorCode::E_HASH_MISMATCH,
            check_submission(&o, &late, &files(), &sub_vk, &[], 0).unwrap_err(),
            vec![
                ("declared", hex_lower(&late.artifact_hash)),
                ("computed", hex_lower(&artifact_set_hash(&files()).unwrap())),
            ],
        ));
    }

    // V12 — подача на секунду позже срока. Граница включительна, и это проверено с обеих сторон.
    {
        let mut late = sub.clone();
        late.created_at = o.deadline + 1;
        late.sign(&sub_sk);
        let mut on_time = sub.clone();
        on_time.created_at = o.deadline;
        on_time.sign(&sub_sk);
        assert!(check_submission(&o, &on_time, &files(), &sub_vk, &[99], 0).is_ok(), "V12: подача ровно в deadline законна");
        out.push(reject(
            "V12",
            "подача после deadline",
            ErrorCode::E_DEADLINE_PASSED,
            check_submission(&o, &late, &files(), &sub_vk, &[], 0).unwrap_err(),
            vec![
                ("created_at", s(late.created_at)),
                ("deadline", s(o.deadline)),
                ("on_deadline_accepted", s(true)),
            ],
        ));
    }

    // V13 — повтор той же пары (submitter, nonce): идемпотентность приёма подач.
    {
        out.push(reject(
            "V13",
            "повторная подача с тем же nonce того же подающего",
            ErrorCode::E_REPLAY,
            check_submission(&o, &sub, &files(), &sub_vk, &[sub.nonce], 1).unwrap_err(),
            vec![("nonce", s(sub.nonce)), ("seen_nonces", s(sub.nonce)), ("scope", "на подающего, не глобально".to_string())],
        ));
    }

    // V14 — предел подач заказа исчерпан.
    {
        out.push(reject(
            "V14",
            "достигнут submit_limit заказа",
            ErrorCode::E_SUBMIT_LIMIT,
            check_submission(&o, &sub, &files(), &sub_vk, &[], o.submit_limit).unwrap_err(),
            vec![("submit_limit", s(o.submit_limit)), ("seen_count", s(o.submit_limit))],
        ));
    }

    // V15 — подача без подписи. Подпись — структурное правило записи подачи, поэтому код
    // E_ORDER_MALFORMED, а не код из квитанционной части списка.
    {
        let mut unsigned = sub.clone();
        unsigned.signature = None;
        out.push(reject(
            "V15",
            "подача без подписи подающего",
            ErrorCode::E_ORDER_MALFORMED,
            check_submission(&o, &unsigned, &files(), &sub_vk, &[], 0).unwrap_err(),
            vec![("signature", "null".to_string())],
        ));
    }

    // V16 — квитанция не с того образа, который заказан.
    {
        let mut r = make_receipt(&o, &sub, Verdict::Pass, 0, 41_000, &[]);
        r.image_digest = pattern(0x5b);
        r.sign(&ver_sk);
        out.push(reject(
            "V16",
            "image_digest квитанции не совпал с заказанным",
            ErrorCode::E_IMAGE_UNAVAILABLE,
            r.validate(&o, &sub, &ver_vk).unwrap_err(),
            vec![
                ("receipt_image_digest", hex_lower(&r.image_digest)),
                ("order_image_digest", hex_lower(&o.verifier.image_digest)),
            ],
        ));
    }

    // V17 — прогон не детерминирован: результат нельзя повторить, значит нельзя и оплатить.
    {
        let mut r = make_receipt(&o, &sub, Verdict::Pass, 0, 41_000, &[]);
        r.deterministic = false;
        r.sign(&ver_sk);
        out.push(reject(
            "V17",
            "deterministic = false",
            ErrorCode::E_RECEIPT_INVALID,
            r.validate(&o, &sub, &ver_vk).unwrap_err(),
            vec![("deterministic", "false".to_string())],
        ));
    }

    // V18 — kernel назвал аксиому вне allowlist.
    {
        let r = make_receipt(&o, &sub, Verdict::Pass, 0, 41_000, &["propext", "mine.private"]);
        out.push(reject(
            "V18",
            "аксиома вне AXIOM_ALLOWLIST",
            ErrorCode::E_AXIOM_NOT_ALLOWED,
            r.validate(&o, &sub, &ver_vk).unwrap_err(),
            vec![("axioms", "[propext, mine.private]".to_string()), ("allowlist", AXIOM_ALLOWLIST.join(", "))],
        ));
    }

    // V19 — exit_code = 0 после потолка бюджета: противоречие полей, а не вердикт.
    {
        let mut r = make_receipt(&o, &sub, Verdict::Pass, 0, u64::from(o.verifier.budget_seconds) * 1_000 + 1, &[]);
        r.sign(&ver_sk);
        out.push(reject(
            "V19",
            "нулевой exit_code после потолка бюджета",
            ErrorCode::E_BUDGET_EXCEEDED,
            r.validate(&o, &sub, &ver_vk).unwrap_err(),
            vec![("wall_clock_ms", s(r.wall_clock_ms)), ("budget_ms", s(r.budget_ms)), ("exit_code", s(r.exit_code))],
        ));
    }

    // V20 — таймаут как выведенный вердикт: он законен, но выплаты по нему нет.
    {
        let r = make_receipt(&o, &sub, Verdict::Timeout, 1, u64::from(o.verifier.budget_seconds) * 1_000 + 1, &[]);
        r.validate(&o, &sub, &ver_vk).expect("V20: корректный timeout обязан пройти вывод");
        assert!(!r.payout_allowed(&o, &sub, &ver_vk, o.deadline), "V20: по timeout не платят");
        out.push(accept("V20", "Квитанция timeout: поля согласованы, вердикт выведен, выплата закрыта", vec![
            ("wall_clock_ms", s(r.wall_clock_ms)),
            ("budget_ms", s(r.budget_ms)),
            ("exit_code", s(r.exit_code)),
            ("derived_verdict", r.derive(&o).unwrap().as_str().to_string()),
            ("receipt_valid", s(r.is_valid_for(&o, &sub, &ver_vk))),
            ("payout_allowed", s(false)),
            ("transition", "verifying --verdict_timeout--> timed_out".to_string()),
        ]));
    }

    // V21 — квитанция без подписи.
    {
        let mut r = make_receipt(&o, &sub, Verdict::Pass, 0, 41_000, &[]);
        r.signature = None;
        out.push(reject(
            "V21",
            "квитанция без подписи верификатора",
            ErrorCode::E_RECEIPT_UNSIGNED,
            r.validate(&o, &sub, &ver_vk).unwrap_err(),
            vec![("signature", "null".to_string())],
        ));
    }

    // V22 — подпись есть, но битая.
    {
        let mut r = make_receipt(&o, &sub, Verdict::Pass, 0, 41_000, &[]);
        let mut bytes = r.signature.unwrap();
        bytes[0] ^= 0x01;
        r.signature = Some(bytes);
        out.push(reject(
            "V22",
            "подпись квитанции не проходит по verifier_pubkey",
            ErrorCode::E_RECEIPT_UNSIGNED,
            r.validate(&o, &sub, &ver_vk).unwrap_err(),
            vec![("signature_hex", hex_lower(&bytes)), ("signing_bytes_len", s(r.signing_bytes().len()))],
        ));
    }

    // V23 — заявленный вердикт не равен выведенному.
    {
        let mut r = make_receipt(&o, &sub, Verdict::Pass, 0, 41_000, &[]);
        r.exit_code = 1;
        r.sign(&ver_sk);
        out.push(reject(
            "V23",
            "verdict = pass при exit_code = 1",
            ErrorCode::E_VERDICT_MISMATCH,
            r.validate(&o, &sub, &ver_vk).unwrap_err(),
            vec![
                ("declared", r.verdict.as_str().to_string()),
                ("derived", r.derive(&o).unwrap().as_str().to_string()),
                ("exit_code", s(r.exit_code)),
            ],
        ));
    }

    // V24 — квитанция ссылается на другой заказ.
    {
        let mut other = o.clone();
        other.nonce += 1;
        other.sign(&pub_sk);
        let r = make_receipt(&other, &sub, Verdict::Pass, 0, 41_000, &[]);
        out.push(reject(
            "V24",
            "order_ref квитанции не совпал с заказом",
            ErrorCode::E_RECEIPT_INVALID,
            r.validate(&o, &sub, &ver_vk).unwrap_err(),
            vec![("receipt_order_ref", hex_lower(&r.order_ref)), ("order_ref", hex_lower(&o.order_ref()))],
        ));
    }

    // V25 — эскроу на цепи, которую узел не наблюдает: fail closed.
    {
        let mut tok = o.clone();
        tok.reward.asset = Asset::Token { chain_id: 8453, address: [0x11; 20] };
        tok.reward.escrow_ref = b"base:0x1111".to_vec();
        tok.sign(&pub_sk);
        let st = EscrowState { chain_id: 8453, asset: tok.reward.asset.clone(), amount: tok.reward.amount, status: EscrowStatus::Locked };
        assert!(check_escrow(&tok, &st, &[8453]).is_ok(), "V25: с названным наблюдателем та же проверка проходит");
        out.push(reject(
            "V25",
            "цепь залога вне DEFAULT_TRUSTED_CHAINS",
            ErrorCode::E_ESCROW_UNKNOWN,
            check_escrow(&tok, &st, DEFAULT_TRUSTED_CHAINS).unwrap_err(),
            vec![
                ("chain_id", s(st.chain_id)),
                ("trusted_ship_default", "[]".to_string()),
                ("with_trusted_8453", "ok".to_string()),
            ],
        ));
    }

    // V26 — заложено меньше обещанного.
    {
        let mut st = escrow_locked(&o);
        st.amount = o.reward.amount - 1;
        out.push(reject(
            "V26",
            "залог меньше награды заказа",
            ErrorCode::E_ESCROW_INSUFFICIENT,
            check_escrow(&o, &st, &[0]).unwrap_err(),
            vec![("locked_amount", s(st.amount)), ("reward_amount", s(o.reward.amount))],
        ));
    }

    // V27 — актив залога не тот, что в заказе.
    {
        let mut st = escrow_locked(&o);
        st.asset = Asset::Token { chain_id: 0, address: [0x22; 20] };
        out.push(reject(
            "V27",
            "актив залога не совпал с обещанным",
            ErrorCode::E_UNSUPPORTED_ASSET,
            check_escrow(&o, &st, &[0]).unwrap_err(),
            vec![("order_asset", "native".to_string()), ("escrow_asset", "token".to_string())],
        ));
    }

    // V28 — распорядились уже отпущенным залогом.
    {
        let mut st = escrow_locked(&o);
        st.status = EscrowStatus::Released;
        out.push(reject(
            "V28",
            "вторичная выдача по уже отпущенному залогу",
            ErrorCode::E_REPLAY,
            check_escrow(&o, &st, &[0]).unwrap_err(),
            vec![("status", st.status.as_str().to_string())],
        ));
    }

    // V29 — имя аксиомы с управляющим символом: JSON квитанции обязан быть пересобираем байт в байт.
    {
        let mut r = make_receipt(&o, &sub, Verdict::Pass, 0, 41_000, &["propext"]);
        r.axioms = vec!["bad\taxiom".to_string()];
        r.sign(&ver_sk);
        out.push(reject(
            "V29",
            "имя аксиомы вне печатного ASCII",
            ErrorCode::E_RECEIPT_INVALID,
            r.validate(&o, &sub, &ver_vk).unwrap_err(),
            vec![("axiom_hex", hex_lower(b"bad\taxiom")), ("canonical_json", "не сериализуется".to_string())],
        ));
    }

    // V30 — неопределённая пара (состояние, событие): «не знаю» это код ошибки, а не молчание.
    {
        let code = match step(State::Settled, Event::Submit) {
            Outcome::Error(c) => c,
            Outcome::To(st) => panic!("V30: из settled в submit ожидали ошибку, получили {}", st.as_str()),
        };
        out.push(reject(
            "V30",
            "пара (settled, submit) не определена",
            ErrorCode::E_STATE_UNKNOWN,
            OrderError::new(code, "переход не определён", None),
            vec![("state", State::Settled.as_str().to_string()), ("event", Event::Submit.as_str().to_string())],
        ));
    }

    out
}

/// Матрица 10 × 11, собранная вызовами `step`: пустых клеток в документе быть не может.
fn matrix_rows() -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut head: Vec<String> = vec![String::from("state \\ event")];
    for e in ALL_EVENTS {
        head.push(e.as_str().to_string());
    }
    lines.push(format!("| {} |", head.join(" | ")));
    lines.push(format!("| {} |", vec!["---"; head.len()].join(" | ")));
    for st in ALL_STATES {
        let mut row: Vec<String> = vec![st.as_str().to_string()];
        for e in ALL_EVENTS {
            row.push(match step(st, e) {
                Outcome::To(next) => next.as_str().to_string(),
                Outcome::Error(code) => code.as_str().to_string(),
            });
        }
        assert_eq!(row.len(), head.len(), "в матрице не бывает пустых клеток");
        lines.push(format!("| {} |", row.join(" | ")));
    }
    lines
}

/// Раздел с тремя нормативными примерами канонизации (§3.2.4 задачи). Каждый пример даёт читателю
/// и грязный вход, и чистый, и команду, которой чистый вход превращается в напечатанный хеш.
#[allow(clippy::vec_init_then_push)] // строки добавляются по мере сборки разделов, это не размер известен заранее
fn worked_rows(ws: &[Worked]) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    lines.push("Нормализация — пять шагов из §V9.3: UTF-8 → NFC → `\\r\\n` и `\\r` в `\\n` → снять".to_string());
    lines.push("хвостовые ` ` и `\\t` с каждой строки → снять хвостовые пустые строки и поставить ровно".to_string());
    lines.push("один `\\n` в конце. Комментарии не вырезаются. Рецепт ниже повторяет те же пять шагов".to_string());
    lines.push("без доступа к коду:".to_string());
    lines.push(String::new());
    lines.push("```python".to_string());
    lines.push("import unicodedata".to_string());
    lines.push("def normalize(raw: bytes) -> bytes:  # §V9.3, шаги 1-5".to_string());
    lines.push("    text = raw.decode(\"utf-8\")            # шаг 1: невалидный UTF-8 — отказ".to_string());
    lines.push("    text = unicodedata.normalize(\"NFC\", text)  # шаг 2".to_string());
    lines.push("    text = text.replace(\"\\r\\n\", \"\\n\").replace(\"\\r\", \"\\n\")  # шаг 3".to_string());
    lines.push("    lines = [l.rstrip(\" \\t\") for l in text.split(\"\\n\")]  # шаг 4".to_string());
    lines.push("    while lines and lines[-1] == \"\": lines.pop()  # шаг 5".to_string());
    lines.push("    assert lines, \"пустое после нормализации — E_STATEMENT_ENCODING\"".to_string());
    lines.push("    return (\"\\n\".join(lines) + \"\\n\").encode(\"utf-8\")".to_string());
    lines.push("```".to_string());
    lines.push(String::new());
    lines.push("Команды воспроизведения написаны для `python3`; там, где есть только `python`, —".to_string());
    lines.push("заменить имя Interpreter'а, содержимое команды не меняется.".to_string());
    lines.push(String::new());
    for w in ws {
        lines.push(String::new());
        lines.push(format!("### {} — `{}`, {}", w.id, w.kind.as_str(), w.note));
        lines.push(String::new());
        lines.push(format!("- тег `kind`: `{}` (байт {})", w.kind.as_str(), w.kind.tag()));
        lines.push(format!("- raw (то, что прислал издатель), hex: `{}`", hex_lower(&w.raw)));
        lines.push(format!("- нормализованные байты, hex: `{}`", hex_lower(&w.norm)));
        lines.push(format!("- длина нормализованных байтов: {}", w.norm.len()));
        lines.push(format!("- `statement_hash`: `{}`", hex_lower(&w.hash)));
        lines.push("- воспроизведение:".to_string());
        lines.push(String::new());
        lines.push("```bash".to_string());
        lines.push(worked_hash_command(w));
        lines.push("```".to_string());
        lines.push(String::new());
        lines.push(format!(
            "текст нормализованного задания (не-ASCII символы показаны как `\\u{{…}}`, а сами байты — hex выше): `{}`",
            ascii_debug(&String::from_utf8_lossy(&w.norm)).replace('\n', "\\n")
        ));
    }
    lines
}

/// Один заказ → одна подача → одна квитанция, байт в байт: всё, что нужно стороннему клиенту,
/// чтобы сверить свой канонический кодировщик с нашим, не читая Rust.
fn full_example_rows() -> Vec<String> {
    let o = base_order();
    let s = base_submission(&o);
    let r = make_receipt(&o, &s, Verdict::Pass, 0, 41_000, &["propext"]);
    let mut leaves: Vec<String> = files()
        .iter()
        .map(|f| {
            let mut c: Vec<u8> = Vec::new();
            c.extend_from_slice(b"vecdht/paid_order_fileset/v1");
            c.push(0x00);
            c.extend_from_slice(f.path.as_bytes());
            c.push(0x00);
            c.extend_from_slice(&f.content_sha256);
            sha256_hex(&c)
        })
        .collect();
    leaves.sort_unstable();
    let mut lines: Vec<String> = Vec::new();
    lines.push("Значения посчитаны исполнением; поля заказов — общие из раздела «Общие входы».".to_string());
    lines.push(String::new());
    lines.push(format!("- `canonical_record` заказа, hex: `{}`", hex_lower(&o.canonical_record())));
    lines.push(format!("- `order_ref` = sha256(выше): `{}`", hex_lower(&o.order_ref())));
    lines.push(format!("- подпись издателя над `canonical_record`, hex: `{}`", hex_lower(&o.signature.unwrap())));
    lines.push(format!("- `canonical_bytes` подачи, hex: `{}`", hex_lower(&s.canonical_bytes())));
    lines.push(format!("- `submission_ref` = sha256(выше): `{}`", hex_lower(&s.submission_ref())));
    // Входы пересчёта листьев: без пары «путь + sha256 содержимого» сторонний читатель не может
    // вычислить `leaf(path, content)` ни при каком описании формулы, то есть корень множества для
    // него остаётся утверждением. Порядок — тот же, что в самой подаче (не отсортирован), чтобы
    // читатель видел: сортировка происходит по листьям, а не по тому, как напечатаны пути (E-0113).
    for f in files() {
        lines.push(format!("- файл `{}` sha256 `{}`", f.path, hex_lower(&f.content_sha256)));
    }
    lines.push(format!("- листья множества файлов (отсортированы по байтам), hex: `{}`", leaves.join("` , `")));
    lines.push(format!("- `artifact_hash` = корень множества: `{}`", hex_lower(&s.artifact_hash)));
    lines.push(format!("- подпись подающего, hex: `{}`", hex_lower(&s.signature.unwrap())));
    lines.push(String::new());
    lines.push("Квитанция:".to_string());
    lines.push(String::new());
    lines.push("```json".to_string());
    lines.push(String::from_utf8(r.canonical_json().unwrap()).unwrap());
    lines.push("```".to_string());
    lines.push(String::new());
    lines.push(format!("- длина подписываемых байтов (`domain || 0x00 || json`): {}", r.signing_bytes().len()));
    lines.push(format!("- hex подписываемых байтов: `{}`", hex_lower(&r.signing_bytes())));
    lines.push(format!("- `signature` (Ed25519, ключ seed = 3), hex: `{}`", hex_lower(&r.signature.unwrap())));
    lines.push(format!("- выведенный вердикт: `{}`; заявленный: `{}`", r.derive(&o).unwrap().as_str(), r.verdict.as_str()));
    lines
}

fn coverage_rows(vs: &[Vector]) -> Vec<String> {
    let mut lines = vec![String::from("| code | action | векторы |"), String::from("| --- | --- | --- |")];
    for c in ErrorCode::all() {
        let ids: Vec<&str> = vs.iter().filter(|v| v.code == Some(c)).map(|v| v.id).collect();
        assert!(!ids.is_empty(), "код {} не воспроизведён ни одним вектором", c.as_str());
        lines.push(format!("| {} | {} | {} |", c.as_str(), c.action().as_str(), ids.join(", ")));
    }
    lines
}

fn render_doc(vs: &[Vector], ws: &[Worked]) -> String {
    let o = base_order();
    let mut d: Vec<String> = Vec::new();
    d.push("# Векторы платных заказов (v9)".to_string());
    d.push(String::new());
    d.push("Документ порождён `crates/vecdht-orders/tests/paid_order_vectors.rs`; правки в него вручную".to_string());
    d.push("не вносятся: следующий запуск перезапишет их. Каждое число здесь — результат исполнения кода,".to_string());
    d.push("а не оценка.".to_string());
    d.push(String::new());
    d.push("## Воспроизведение".to_string());
    d.push(String::new());
    d.push("```bash".to_string());
    d.push("cargo test -q -p vecdht-orders --test paid_order_vectors -- --nocapture".to_string());
    d.push("V9_VECTORS_OUT=docs/PAID_ORDER-VECTORS.md \\".to_string());
    d.push("  cargo test -q -p vecdht-orders --test paid_order_vectors -- --nocapture".to_string());
    d.push("```".to_string());
    d.push(String::new());
    d.push("## Общие входы".to_string());
    d.push(String::new());
    d.push(format!("- образ: `{}`", hex_lower(&o.verifier.image_digest)));
    d.push(format!("- entrypoint: `{}`", o.verifier.entrypoint));
    d.push(format!("- бюджет: {} с = {} мс", o.verifier.budget_seconds, u64::from(o.verifier.budget_seconds) * 1_000));
    d.push(format!("- network: `{}`", o.verifier.network));
    d.push(format!("- награда: {} минимальных единиц, актив `native` (цепь {})", o.reward.amount, o.reward.asset.chain_id()));
    d.push(format!("- escrow_ref: `{}`", String::from_utf8_lossy(&o.reward.escrow_ref)));
    d.push(format!("- deadline: {} (включителен)", o.deadline));
    d.push(format!("- submit_limit: {}", o.submit_limit));
    d.push(format!("- publisher: `{}`", hex_lower(&o.publisher)));
    d.push(format!("- nonce заказа: {}", o.nonce));
    d.push(format!("- statement_hash: `{}`", hex_lower(&o.statement_hash)));
    d.push(format!("- order_ref: `{}`", hex_lower(&o.order_ref())));
    d.push(format!("- artifact_set_hash подачи: `{}`", hex_lower(&artifact_set_hash(&files()).unwrap())));
    d.push(format!("- AXIOM_ALLOWLIST: [{}]", AXIOM_ALLOWLIST.join(", ")));
    d.push(format!("- PAYBACK_WINDOW_SECONDS: {}", PAYBACK_WINDOW_SECONDS));
    d.push(format!("- OFFLINE_FACTOR: {}", OFFLINE_FACTOR));
    d.push(format!("- DEFAULT_TRUSTED_CHAINS: {:?}", DEFAULT_TRUSTED_CHAINS));
    d.push("- ключи: издатель seed = 1, подающий seed = 2, верификатор seed = 3; `keypair(seed)`\n  кладёт `seed` в первый байт и `seed xor 0xa5` в последний (только для приборов).".to_string());
    d.push(String::new());
    d.push("## Векторы".to_string());
    for v in vs {
        d.push(String::new());
        d.push(format!("### {} — {}", v.id, v.title));
        d.push(String::new());
        d.push("```json".to_string());
        d.push(v.to_json());
        d.push("```".to_string());
    }
    d.push(String::new());
    d.push("## Три примера канонизации задания".to_string());
    d.push(String::new());
    d.extend(worked_rows(ws));
    d.push(String::new());
    d.push("## Полный пример: заказ, подача, квитанция".to_string());
    d.push(String::new());
    d.extend(full_example_rows());
    d.push(String::new());
    d.push("## Матрица состояний".to_string());
    d.push(String::new());
    d.push("Клетка — состояние-приёмник либо код ошибки. Любое событие вне перечисленных одиннадцати".to_string());
    d.push("(тег `unknown`) даёт `E_STATE_UNKNOWN`: неопределённая пара — это ошибка, а не молчание.".to_string());
    d.push(String::new());
    d.extend(matrix_rows());
    d.push(String::new());
    d.push("## Покрытие закрытого списка кодов".to_string());
    d.push(String::new());
    d.extend(coverage_rows(vs));
    d.push(String::new());
    let mut doc = d.join("\n");
    if !doc.ends_with('\n') {
        doc.push('\n');
    }
    doc
}

#[test]
fn vectors_cover_the_closed_list_and_reproduce() {
    let vs = vectors();
    assert!(vs.len() >= 12, "векторов обязано быть не меньше 12, а то {}", vs.len());
    let mut ids: Vec<&str> = vs.iter().map(|v| v.id).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), before, "id векторов не повторяются");

    let covered = ErrorCode::all()
        .iter()
        .filter(|c| vs.iter().any(|v| v.code == Some(**c)))
        .count();
    println!("V9_VECTORS={}", vs.len());
    println!("V9_CODES_COVERED={covered}/{}", ErrorCode::all().len());
    assert_eq!(covered, ErrorCode::all().len(), "каждый код закрытого списка обязан быть воспроизведён");

    // Три примера канонизации: их хеши печатаются фактами, потому что helper сверяет их с
    // независимой реализацией на python (hashlib), а не с самим собой.
    let ws = worked();
    assert_eq!(ws.len(), 3, "примеров канонизации ровно три (§3.2.4 задачи)");
    let (idempotent, stable) = worked_props(&ws);
    assert!(idempotent, "нормализация идемпотентна: нормализованное байт-в-байт снова нормализовано");
    assert!(stable, "хеш грязного входа равен хешу его нормализованной формы");
    println!("V9_WORKED=3");
    println!("V9_W1_TAG={}", ws[0].kind.tag());
    println!("V9_W1_NORM_HEX={}", hex_lower(&ws[0].norm));
    println!("V9_W1_SHA={}", hex_lower(&ws[0].hash));
    println!("V9_W2_TAG={}", ws[1].kind.tag());
    println!("V9_W2_NORM_HEX={}", hex_lower(&ws[1].norm));
    println!("V9_W2_SHA={}", hex_lower(&ws[1].hash));
    println!("V9_W3_TAG={}", ws[2].kind.tag());
    println!("V9_W3_NORM_HEX={}", hex_lower(&ws[2].norm));
    println!("V9_W3_SHA={}", hex_lower(&ws[2].hash));
    println!("V9_W_NORM_IDEMPOTENT={}", i32::from(idempotent));
    println!("V9_W_HASH_STABLE={}", i32::from(stable));

    // Якоря полного примера: если канонический кодировщик сдвинется хоть на байт, изменится и этот
    // вектор, и `V9_VECTORS_SHA`. Frozen в `lab/expectations/e0111.tsv`.
    let fo = base_order();
    let fs = base_submission(&fo);
    let fr = make_receipt(&fo, &fs, Verdict::Pass, 0, 41_000, &["propext"]);
    println!("V9_ORDER_REF={}", hex_lower(&fo.order_ref()));
    println!("V9_SUBMISSION_REF={}", hex_lower(&fs.submission_ref()));
    println!("V9_ARTIFACT_ROOT={}", hex_lower(&fs.artifact_hash));
    println!("V9_RECEIPT_JSON_SHA={}", sha256_hex(&fr.canonical_json().unwrap()));

    let doc = render_doc(&vs, &ws);
    println!("V9_DOC_BYTES={}", doc.len());
    println!("V9_VECTORS_SHA={}", sha256_hex(doc.as_bytes()));

    match std::env::var("V9_VECTORS_OUT") {
        Ok(path) => {
            // Cargo запускает тест из корня пакета, поэтому относительный путь отсчитывается от
            // корня репозитория: `docs/PAID_ORDER-VECTORS.md` означает то, что написано в команде.
            let given = std::path::Path::new(&path);
            let full = if given.is_absolute() {
                given.to_path_buf()
            } else {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(given)
            };
            if let Some(dir) = full.parent() {
                std::fs::create_dir_all(dir).expect("каталог документа создаётся");
            }
            std::fs::write(&full, doc.as_bytes()).unwrap_or_else(|e| panic!("документ не записан в {}: {e}", full.display()));
            println!("V9_DOC_WRITTEN={}", full.display());
        }
        Err(_) => println!("V9_DOC_WRITTEN=нет_переменной_V9_VECTORS_OUT"),
    }
}
