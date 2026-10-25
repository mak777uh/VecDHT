//! D3 — векторы слоя стыковки цепочек, порождённые кодом.
//!
//! Документ `docs/PAID_PAYOUT-VECTORS.md` не пишется руками: его печатает этот тест. Причина та же,
//! что гоняла `E-0111` и `E-0113`: число, которое никто не исполнял, есть вымысел, а «мост проверит
//! офлайн» — обещание, пока его байты не собраны вне узла. Здесь каждый `term_hash`, каждый корень
//! реестра, каждая каноническая байтовая строка связки, свидетельства и требования, каждая подпись и
//! каждый код отказа получены вызовом функции из `vecdht-orders`.
//!
//! Воспроизведение:
//!     cargo test -q -p vecdht-orders --test payout_claim_vectors -- --nocapture
//!     V9P_VECTORS_OUT=docs/PAID_PAYOUT-VECTORS.md cargo test -q -p vecdht-orders \
//!         --test payout_claim_vectors -- --nocapture
//!
//! Префиксы фактов: `V9P_*` печатает только этот генератор, `V9C_*` — только сторонний прибор
//! `lab/v9-payout-bridge.py`. Два владельца одного имени в одном логе дают молчание там, где обязан
//! быть отказ (правило сверки по границе токена), поэтому имена не пересекаются ни на одном ключе.
//!
//! Что считается провалом прибора: векторов меньше 12; хоть один id повторяется; набор печатаемых
//! ключей разошёлся между векторами (читатель, разбирающий блок по ключам, получил бы молчание там,
//! где обязан получить отказ); покрытие кодов вышел за закрытый список; якорь `V9_ORDER_REF` из
//! `E-0111` сдвинулся — инвариант аддитивности (`ADR-0064`) требует, чтобы байты заказа не менялись
//! от появления слоя; документ не записан, когда для этого задана переменная окружения.

use vecdht_orders::*;

const CARRIER: &str = "docs/PAID_PAYOUT-VECTORS.md";

/// Порядок байтов `term_hash` — единственный список, из которого §1 носителя печатает формулу
/// и по которому `term_bytes_per_formula` собирает байты для сверки с `vecdht_orders::term_hash`.
/// До появления этого списка текст формулы разошёлся с кодом: он обещал разделители `0x00` между
/// полями, которых в реализации нет. Заметил это не рецензент, а сторонний прибор, читающий только
/// напечатанное. Теперь печатный порядок и исполняемый порядок — один источник.
const TERM_TOKENS: &[&str] = &[
    "DOMAIN_TERM",
    "0x00",
    "order_ref(32)",
    "chain_id:u64le",
    "asset_bytes",
    "beneficiary_pubkey(32)",
    "amount:u128le",
    "u32le(len(escrow_ref))",
    "escrow_ref",
];

/// Байты `term_hash` ровно по напечатанной формуле: `DOMAIN_TERM`, терминатор, затем девять
/// токенов списком выше. Отдельная от `lib` сборка — иначе сверка ничего не сверяет.
fn term_bytes_per_formula(order: &PaidOrder, beneficiary: &PubKey) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(DOMAIN_TERM);
    v.push(0x00);
    v.extend_from_slice(&order.order_ref());
    v.extend_from_slice(&order.reward.asset.chain_id().to_le_bytes());
    v.extend_from_slice(&order.reward.asset.canonical_bytes());
    v.extend_from_slice(beneficiary);
    v.extend_from_slice(&order.reward.amount.to_le_bytes());
    v.extend_from_slice(&(order.reward.escrow_ref.len() as u32).to_le_bytes());
    v.extend_from_slice(&order.reward.escrow_ref);
    v
}

/// Байтовый шаблон `[v; 32]` — чтобы читатель мог собрать тот же массив сам, без hex-парсера.
fn pattern(v: u8) -> Hash {
    [v; 32]
}

// ---------------------------------------------------------------------------
// Фикстуры
// ---------------------------------------------------------------------------

/// Шесть зарегистрированных цепей: нативная протокола плюс пять EVM-подобных. Имена и заметки —
/// печатный ASCII по правилу §2 носителя: эти строки входят в листья реестра, а значит их пересчитывает
/// сторонний мост, которому нечего сказать о кодировке имён.
fn registry() -> Vec<ChainDescriptor> {
    let mut out = vec![ChainDescriptor {
        chain_id: 0,
        name: "vecdht-native".to_string(),
        bridge_code: 1,
        settle_asset_tag: 0,
        min_amount: 1_000,
        note: "protocol native".to_string(),
    }];
    for (id, name) in [(1u64, "ethereum"), (10, "optimism"), (137, "polygon"), (8453, "base"), (42161, "arbitrum")] {
        out.push(ChainDescriptor {
            chain_id: id,
            name: name.to_string(),
            bridge_code: 2,
            settle_asset_tag: 1,
            min_amount: 1_000,
            note: "EVM-like, secp256k1".to_string(),
        });
    }
    out
}

/// Один заказ на указанной цепи: токен с адресом-шаблоном, кроме нативной цепи протокола.
fn order_on(chain: u64) -> PaidOrder {
    let (sk, vk) = keypair(1);
    let statement = normalize_statement(
        b"theorem payout_layer_is_additive (n : Nat) : n + 0 = n := by\n  induction n with\n    | zero => rfl\n    | succ k ih => simp [Nat.succ_add, ih]\n",
    )
    .unwrap();
    let asset = if chain == 0 {
        Asset::Native
    } else {
        Asset::Token { chain_id: chain, address: [chain as u8; 20] }
    };
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
            escrow_ref: format!("chain{chain}:escrow/{:0>4x}", chain).into_bytes(),
            asset,
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

/// Тот самый заказ-якорь из `docs/PAID_ORDER-VECTORS.md` (вектор V01): он пересобирается здесь
/// независимо, чтобы инвариант аддитивности проверялся из двух файлов, а не из одного.
const V01_ORDER_REF: &str = "4167d021a099e6efcbce24212117757136eb0823e3dd5d756ed3a2caf6f2ac70";

fn v01_order() -> PaidOrder {
    let (sk, vk) = keypair(1);
    let statement = normalize_statement(
        b"theorem add_zero_right (n : Nat) : n + 0 = n := by\n  induction n with\n    | zero => rfl\n    | succ k ih => simp [Nat.succ_add, ih]\n",
    )
    .unwrap();
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

/// Снимок доверия моста: что он считает цепями, наблюдателями и реестрами. Это состояние моста,
/// а не протокола, — и именно его носитель печатает, чтобы сторонний читатель вывел то же решение.
#[derive(Clone)]
struct TrustSnapshot {
    chains: Vec<u64>,
    observers: Vec<PubKey>,
    registries: Vec<Hash>,
}

impl TrustSnapshot {
    fn view(&self) -> BridgeTrust<'_> {
        BridgeTrust { chains: &self.chains, observers: &self.observers, registries: &self.registries }
    }
}

/// Полный снимок одного вектора: заказ, подача, требование (со встроенными объектами), часы и доверие.
/// Всё, что нужно решению, живёт здесь — сторонний читатель восстанавливает вектор по напечатанным
/// полям и больше ни к чему не обращается.
struct Fixture {
    id: &'static str,
    title: &'static str,
    order: PaidOrder,
    sub: Submission,
    claim: PayoutClaim,
    now: u64,
    trust: TrustSnapshot,
    /// Ключ, которым переподписывать квитанцию после правки её полей. У посадки с чужим ключом
    /// верификатора он свой, иначе «подделка» стала бы проверкой нашего же подписчика.
    receipt_key: u8,
}

fn base_submission(order: &PaidOrder) -> Submission {
    let (sk, vk) = keypair(2);
    let files = vec![
        ArtifactFile { path: "Proof.lean".to_string(), content_sha256: pattern(0x11) },
        ArtifactFile { path: "lake-manifest.json".to_string(), content_sha256: pattern(0x22) },
    ];
    let mut s = Submission {
        order_ref: order.order_ref(),
        artifact_hash: artifact_set_hash(&files).unwrap(),
        artifact_uri: "ipfs://bafybeiexample".to_string(),
        submitter: *vk.as_bytes(),
        nonce: 1,
        created_at: 1_799_999_999,
        signature: None,
    };
    s.sign(&sk);
    s
}

fn pass_receipt(order: &PaidOrder, sub: &Submission, verifier: &PubKey) -> Receipt {
    let (sk, _) = keypair(3);
    let mut r = Receipt {
        order_ref: order.order_ref(),
        submission_ref: sub.submission_ref(),
        verdict: Verdict::Pass,
        image_digest: order.verifier.image_digest,
        toolchain: "leanprover/lean4:v4.9.1".to_string(),
        axioms: vec!["propext".to_string()],
        wall_clock_ms: 41_000,
        budget_ms: u64::from(order.verifier.budget_seconds) * 1_000,
        exit_code: 0,
        stdout_sha256: pattern(0x33),
        stderr_sha256: pattern(0x44),
        deterministic: true,
        verifier_pubkey: *verifier,
        signature: None,
    };
    r.sign(&sk);
    r
}

/// Собрать честный вектор: цепь, состояние залога, часы. Всё остальное — посадки поверх него.
fn fixture(id: &'static str, title: &'static str, chain: u64, status: u8, now: u64) -> Fixture {
    let root = registry_root(&registry()).unwrap();
    let order = order_on(chain);
    let sub = base_submission(&order);
    let (_, ver_vk) = keypair(3);
    let (_, obs_vk) = keypair(5);
    let receipt = pass_receipt(&order, &sub, ver_vk.as_bytes());
    let mut binding = VerifierBinding::for_order(&order, &sub.submitter, ver_vk.as_bytes());
    binding.sign(&keypair(1).0);
    let state = EscrowState {
        chain_id: order.reward.asset.chain_id(),
        asset: order.reward.asset.clone(),
        amount: order.reward.amount,
        status: match status {
            0 => EscrowStatus::NotFunded,
            2 => EscrowStatus::Released,
            3 => EscrowStatus::Refunded,
            _ => EscrowStatus::Locked,
        },
    };
    let mut witness =
        EscrowWitness::for_state(&order, &sub.submitter, &state, obs_vk.as_bytes(), root, b"block:18400000");
    witness.sign(&keypair(5).0);
    let mut claim = PayoutClaim::assemble(&order, &sub, receipt, binding, witness);
    assert!(claim.sign(&keypair(2).0).is_ok(), "{id}: честное требование обязано кодироваться");
    Fixture {
        id,
        title,
        order,
        sub,
        claim,
        now,
        trust: TrustSnapshot {
            chains: registry().iter().map(|d| d.chain_id).collect(),
            observers: vec![*obs_vk.as_bytes()],
            registries: vec![root],
        },
        receipt_key: 3,
    }
}

/// Переподписать встроенные объекты после правки их полей — но только те, что ещё подписаны.
/// Подпись, снятая посадкой, остаётся снятой: иначе подделка «без подписи» починила бы сама себя.
fn resign_parts(f: &mut Fixture) {
    let c = &mut f.claim;
    if c.receipt.signature.is_some() {
        c.receipt.sign(&keypair(f.receipt_key).0);
    }
    if c.binding.signature.is_some() {
        c.binding.sign(&keypair(1).0);
    }
    if c.witness.signature.is_some() {
        c.witness.sign(&keypair(5).0);
    }
}

/// Подписать требование. Требование, которое не кодируется, обязано остаться неподписанным: подпись
/// над пустотой создала бы вектор, чья подпись ничего не покрывает.
fn resign_claim(f: &mut Fixture) {
    if f.claim.signature.is_some() {
        match f.claim.sign(&keypair(2).0) {
            Ok(()) => {}
            Err(_) => f.claim.signature = None,
        }
    }
}

fn resign(f: &mut Fixture) {
    resign_parts(f);
    resign_claim(f);
}

impl Fixture {
    fn decision(&self) -> Result<(), OrderError> {
        check_payout_claim(&self.claim, &self.order, &self.sub, &self.trust.view(), self.now)
    }
}

// ---------------------------------------------------------------------------
// Векторы
// ---------------------------------------------------------------------------

fn vectors() -> Vec<Fixture> {
    let mut out: Vec<Fixture> = Vec::new();

    // P01 — честная выплата на токене 8453: все четыре подписи проходят, решение — платить.
    out.push(fixture("P01", "Полный путь: связка, свидетельство, требование, выплата", 8453, 1, 1_800_003_600));

    // Печать id и заголовка посадок: векторов ровно столько, сколько заявлено веток, и имя вектора
    // обязано быть напечатано литералом (линт порогов требует литеральных ключей в источнике).

    {
        let mut f = fixture("P02", "требование без подписи бенефициара", 8453, 1, 1_800_000_000);
        f.claim.signature = None;
        out.push(f);
    }
    {
        let mut f = fixture("P03", "term_hash требования не совпал с пересчитанным", 8453, 1, 1_800_000_000);
        f.claim.term_hash = pattern(0x77);
        resign(&mut f);
        out.push(f);
    }
    {
        let mut f = fixture("P04", "квитанция заявляет pass при ненулевом exit_code", 8453, 1, 1_800_000_000);
        f.claim.receipt.exit_code = 1;
        resign(&mut f);
        out.push(f);
    }
    {
        // Квитанция подписана честной (для своего ключа) подписью, но ключом, которого издатель в
        // связке не называл: шаг (3) обязан умереть на E_RECEIPT_UNSIGNED, а не «не доверен ключ».
        let mut f = fixture("P05", "квитанция подписана ключом, которого издатель не называл", 8453, 1, 1_800_000_000);
        let (sk, vk) = keypair(7);
        f.claim.receipt.verifier_pubkey = *vk.as_bytes();
        f.claim.receipt.sign(&sk);
        f.receipt_key = 7;
        resign_claim(&mut f);
        out.push(f);
    }
    {
        let mut f = fixture("P06", "квитанция в требовании без подписи", 8453, 1, 1_800_000_000);
        f.claim.receipt.signature = None;
        resign_claim(&mut f);
        out.push(f);
    }
    {
        let mut f = fixture("P07", "связка верификатора не подписана издателем", 8453, 1, 1_800_000_000);
        f.claim.binding.signature = None;
        resign_claim(&mut f);
        out.push(f);
    }
    {
        let mut f = fixture("P08", "залог меньше обещанного", 8453, 1, 1_800_000_000);
        f.claim.witness.amount_on_chain = f.order.reward.amount - 1;
        resign(&mut f);
        out.push(f);
    }
    {
        let mut f = fixture("P09", "корень реестра в свидетельстве не доверен", 8453, 1, 1_800_000_000);
        f.claim.witness.registry_root = pattern(0x55);
        resign(&mut f);
        out.push(f);
    }
    {
        // Свидетельство подписано честно, но чужим ключом: доверенного набора это не меняет.
        let mut f = fixture("P10", "свидетельство выдал наблюдатель вне доверенного набора", 8453, 1, 1_800_000_000);
        let (sk, vk) = keypair(9);
        f.claim.witness.observer_pubkey = *vk.as_bytes();
        f.claim.witness.sign(&sk);
        resign_claim(&mut f);
        out.push(f);
    }
    {
        let mut f = fixture("P11", "свидетельство назвало неизвестный тег состояния", 8453, 1, 1_800_000_000);
        f.claim.witness.status = 9;
        resign(&mut f);
        out.push(f);
    }
    {
        let f = fixture("P12", "требование после окна выплаты", 8453, 1, 1_800_003_601);
        out.push(f);
    }
    {
        // Подача позже срока: меняется подача, а значит и ссылка квитанции на неё.
        let mut f = fixture("P13", "подача позже срока заказа", 8453, 1, 1_800_000_000);
        f.sub.created_at = f.order.deadline + 1;
        f.sub.sign(&keypair(2).0);
        f.claim.receipt.submission_ref = f.sub.submission_ref();
        resign(&mut f);
        out.push(f);
    }

    // P14..P25 — переисполнение залога на шести цепях: released и refunded дают один и тот же код,
    // и ни один из них не «проходит молча». Это и есть ответ на «что будет при двойной выплате».
    for chain in registry().iter().map(|d| d.chain_id) {
        for (status, label) in [(2u8, "released"), (3, "refunded")] {
            let id = format!("P{}", out.len() + 1);
            let title = format!("цепь {chain}: повторное требование на {label}, а не вторая выплата");
            out.push(fixture(
                Box::leak(id.into_boxed_str()),
                Box::leak(title.into_boxed_str()),
                chain,
                status,
                1_800_000_000,
            ));
        }
    }
    // P26..P31 — честная выплата на каждой из шести цепей: тот же вывод, что у P01, но актив разный,
    // включая нативную цепь протокола (её `chain_id` = 0, и это тоже данные реестра).
    for chain in registry().iter().map(|d| d.chain_id) {
        let id = format!("P{}", out.len() + 1);
        let title = format!("цепь {chain}: выплата проходит, когда залог залочен и реестр доверен");
        out.push(fixture(
            Box::leak(id.into_boxed_str()),
            Box::leak(title.into_boxed_str()),
            chain,
            1,
            1_800_000_000,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Печатные поля вектора
// ---------------------------------------------------------------------------

fn hex_or_dash(v: &Option<Sig>) -> String {
    match v {
        Some(s) => hex_lower(s),
        None => "-".to_string(),
    }
}

/// Печатаемые поля вектора. Порядок ключей нормативен: носитель обязан печатать один и тот же набор
/// для каждого вектора, иначе разбор блока по ключам даст молчание там, где обязан дать отказ.
fn fields(f: &Fixture) -> Vec<(String, String)> {
    let c = &f.claim;
    let mut o: Vec<(String, String)> = Vec::new();
    let mut p = |k: &str, v: String| o.push((k.to_string(), v));
    p("id", f.id.to_string());
    p("title", f.title.to_string());
    let decision = f.decision();
    p("outcome", if decision.is_ok() { "payout".to_string() } else { "reject".to_string() });
    p("code", match &decision {
        Ok(()) => "-".to_string(),
        Err(e) => e.code.as_str().to_string(),
    });
    p("now", f.now.to_string());

    p("order.kind_tag", f.order.kind.tag().to_string());
    p("order.statement_hash", hex_lower(&f.order.statement_hash));
    p("order.image_digest", hex_lower(&f.order.verifier.image_digest));
    p("order.entrypoint", f.order.verifier.entrypoint.clone());
    p("order.budget_seconds", f.order.verifier.budget_seconds.to_string());
    p("order.network", u8::from(f.order.verifier.network).to_string());
    p("order.amount", f.order.reward.amount.to_string());
    p("order.asset_tag", match f.order.reward.asset {
        Asset::Native => "0".to_string(),
        Asset::Token { .. } => "1".to_string(),
    });
    p("order.asset_chain_id", f.order.reward.asset.chain_id().to_string());
    p("order.asset_address", match &f.order.reward.asset {
        Asset::Native => "-".to_string(),
        Asset::Token { address, .. } => hex_lower(address),
    });    p("order.escrow_ref_hex", hex_lower(&f.order.reward.escrow_ref));
    p("order.deadline", f.order.deadline.to_string());
    p("order.submit_limit", f.order.submit_limit.to_string());
    p("order.publisher", hex_lower(&f.order.publisher));
    p("order.nonce", f.order.nonce.to_string());
    p("order.canonical_record_hex", hex_lower(&f.order.canonical_record()));
    p("order.signature_hex", hex_or_dash(&f.order.signature));
    p("order_ref", hex_lower(&f.order.order_ref()));

    p("sub.order_ref", hex_lower(&f.sub.order_ref));
    p("sub.artifact_hash", hex_lower(&f.sub.artifact_hash));
    p("sub.artifact_uri", f.sub.artifact_uri.clone());
    p("sub.submitter", hex_lower(&f.sub.submitter));
    p("sub.nonce", f.sub.nonce.to_string());
    p("sub.created_at", f.sub.created_at.to_string());
    p("sub.signature_hex", hex_or_dash(&f.sub.signature));
    p("submission_ref", hex_lower(&f.sub.submission_ref()));

    p("receipt.order_ref", hex_lower(&c.receipt.order_ref));
    p("receipt.submission_ref", hex_lower(&c.receipt.submission_ref));
    p("receipt.verdict", c.receipt.verdict.as_str().to_string());
    p("receipt.image_digest", hex_lower(&c.receipt.image_digest));
    p("receipt.toolchain", c.receipt.toolchain.clone());
    p("receipt.axioms", format!(
        "[{}]",
        c.receipt.axioms.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(",")
    ));
    p("receipt.wall_clock_ms", c.receipt.wall_clock_ms.to_string());
    p("receipt.budget_ms", c.receipt.budget_ms.to_string());
    p("receipt.exit_code", c.receipt.exit_code.to_string());
    p("receipt.stdout_sha256", hex_lower(&c.receipt.stdout_sha256));
    p("receipt.stderr_sha256", hex_lower(&c.receipt.stderr_sha256));
    p("receipt.deterministic", c.receipt.deterministic.to_string());
    p("receipt.verifier_pubkey", hex_lower(&c.receipt.verifier_pubkey));
    p("receipt.canonical_json", String::from_utf8(c.receipt.canonical_json().unwrap()).unwrap());
    p("receipt.signature_hex", hex_or_dash(&c.receipt.signature));

    p("binding.order_ref", hex_lower(&c.binding.order_ref));
    p("binding.verifier_pubkey", hex_lower(&c.binding.verifier_pubkey));
    p("binding.image_digest", hex_lower(&c.binding.image_digest));
    p("binding.term_hash", hex_lower(&c.binding.term_hash));
    p("binding.canonical_hex", hex_lower(&c.binding.canonical_bytes()));
    p("binding.signature_hex", hex_or_dash(&c.binding.signature));

    p("witness.term_hash", hex_lower(&c.witness.term_hash));
    p("witness.chain_id", c.witness.chain_id.to_string());
    p("witness.status", c.witness.status.to_string());
    p("witness.amount_on_chain", c.witness.amount_on_chain.to_string());
    p("witness.block_ref_hex", hex_lower(&c.witness.block_ref));
    p("witness.registry_root", hex_lower(&c.witness.registry_root));
    p("witness.observer_pubkey", hex_lower(&c.witness.observer_pubkey));
    p("witness.canonical_hex", hex_lower(&c.witness.canonical_bytes()));
    p("witness.signature_hex", hex_or_dash(&c.witness.signature));

    p("claim.term_hash", hex_lower(&c.term_hash));
    p("claim.order_ref", hex_lower(&c.order_ref));
    p("claim.beneficiary", hex_lower(&c.beneficiary));
    match c.canonical_bytes() {
        Ok(b) => {
            p("claim.canonical_hex", hex_lower(&b));
            p("claim.canonical_len", b.len().to_string());
        }
        Err(e) => {
            p("claim.canonical_hex", "-".to_string());
            p("claim.canonical_len", format!("не_кодируется:{}", e.code.as_str()));
        }
    }
    p("claim.signature_hex", hex_or_dash(&c.signature));

    p("term_hash", hex_lower(&term_hash(&f.order, &f.sub.submitter)));
    p("trust.chains", f.trust.chains.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","));
    p("trust.observers", f.trust.observers.iter().map(|k| hex_lower(&k[..])).collect::<Vec<_>>().join(","));
    p("trust.registries", f.trust.registries.iter().map(|k| hex_lower(&k[..])).collect::<Vec<_>>().join(","));
    o
}

// ---------------------------------------------------------------------------
// Печатный текст носителя
// ---------------------------------------------------------------------------

fn domain_rows() -> Vec<String> {
    let rows: [(&str, &[u8]); 5] = [
        ("DOMAIN_TERM", DOMAIN_TERM),
        ("DOMAIN_BINDING", DOMAIN_BINDING),
        ("DOMAIN_CHAIN", DOMAIN_CHAIN),
        ("DOMAIN_WITNESS", DOMAIN_WITNESS),
        ("DOMAIN_CLAIM", DOMAIN_CLAIM),
    ];
    let mut out = vec![
        "| имя | литерал | длина литерала | терминатор после домена |".to_string(),
        "|---|---|---|---|".to_string(),
    ];
    for (name, bytes) in rows {
        out.push(format!(
            "| {name} | `{}` | {} | `0x00` |",
            String::from_utf8_lossy(bytes),
            bytes.len()
        ));
    }
    out
}

/// Раскладка объекта слоя. Таблица — нормативный текст: читатель собирает байты по колонкам «ширина»
/// и «терминатор», и если колонка соврёт, пересборка разойдётся с напечатанными байтами требования.
fn layout_rows(obj: &str, rows: &[(&str, &str, &str, &str)]) -> Vec<String> {
    let mut out = vec![format!("**{obj}**"), String::new(), "| № | поле | ширина | терминатор `0x00` |".to_string(), "|---|---|---|---|".to_string()];
    for (n, field, width, term) in rows {
        out.push(format!("| {n} | `{field}` | {width} | {term} |"));
    }
    out.push(String::new());
    out
}

fn registry_rows() -> Vec<String> {
    let mut out = vec![
        "| chain_id | name | bridge_code | settle_asset_tag | min_amount | note | canonical_bytes (hex) | leaf (hex) |".to_string(),
        "|---|---|---|---|---|---|---|---|".to_string(),
    ];
    for d in registry() {
        let bytes = d.canonical_bytes().unwrap();
        let parts: [&[u8]; 3] = [DOMAIN_CHAIN, &[0x00], &bytes];
        let leaf = sha256_hex(&parts.concat());
        out.push(format!(
            "| {} | `{}` | {} | {} | {} | `{}` | `{}` | `{}` |",
            d.chain_id, d.name, d.bridge_code, d.settle_asset_tag, d.min_amount, d.note, hex_lower(&bytes), leaf
        ));
    }
    out
}

fn code_rows() -> Vec<String> {
    let mut out = vec!["| код | действие узла |".to_string(), "|---|---|".to_string()];
    for c in ErrorCode::all() {
        out.push(format!("| `{}` | `{}` |", c.as_str(), c.action().as_str()));
    }
    out
}

fn vector_block(f: &Fixture) -> Vec<String> {
    let mut out = vec![format!("### {f}", f = f.id), String::new(), "```kv".to_string()];
    out.push(format!("title={}", f.title));
    for (k, v) in fields(f) {
        if k == "title" {
            continue;
        }
        out.push(format!("{k}={v}"));
    }
    out.push("```".to_string());
    out.push(String::new());
    out
}

fn render_doc(vs: &[Fixture]) -> String {
    let mut d: Vec<String> = Vec::new();
    d.push("# VecDHT v9 — векторы слоя стыковки цепочек (автовыплаты)".to_string());
    d.push(String::new());
    d.push("> Документ порождён кодом: `crates/vecdht-orders/tests/payout_claim_vectors.rs`.".to_string());
    d.push("> Руками здесь не правится ничего — ни один хеш, ни одна байтовая строка, ни один код.".to_string());
    d.push(String::new());
    d.push("Воспроизведение:".to_string());
    d.push(String::new());
    d.push("```sh".to_string());
    d.push("cargo test -q -p vecdht-orders --test payout_claim_vectors -- --nocapture".to_string());
    d.push(format!("V9P_VECTORS_OUT={CARRIER} \\"));
    d.push("    cargo test -q -p vecdht-orders --test payout_claim_vectors -- --nocapture".to_string());
    d.push("```".to_string());
    d.push(String::new());
    d.push("Что обязано уметь по этому документу: собрать `term_hash`, корень реестра, байты связки,".to_string());
    d.push("свидетельства и требования, проверить четыре подписи и вывести решение по каждому вектору,".to_string());
    d.push("не имея ни Rust, ни узла VecDHT. Если текст соврёт в ширине поля, в терминаторе или в".to_string());
    d.push("литерале домена — пересборка разойдётся с напечатанными байтами, и сверка покраснеет.".to_string());
    d.push(String::new());
    d.push("Инварианты слоя (проект `ADR-0064`, §V9.7):".to_string());
    d.push(String::new());
    d.push("1. **Аддитивность.** Байты `paid_order` не изменились ни на байт: `order_ref` вектора V01".to_string());
    d.push(format!("   из `docs/PAID_ORDER-VECTORS.md` остаётся `{V01_ORDER_REF}`."));
    d.push("2. **Нет судьи.** Вердикт выводится из полей квитанции (§V9.5), выплата — из байтов".to_string());
    d.push("   требования; ни один шаг не обращается к узлу и не спрашивает мнение.".to_string());
    d.push("3. **Реестр — данные.** Заказ и свидетельство пинят `registry_root`: новая цепь меняет".to_string());
    d.push("   корень, уже подписанные требования — нет.".to_string());
    d.push("4. **Закрытый список.** Слой использует ровно те имена, что перечислены в §3 ниже; ни одна".to_string());
    d.push("   ветка не вводит девятнадцатого кода.".to_string());
    d.push("5. **Fail closed.** Пустой набор доверия (цепи, наблюдатели, корни) — отказ по существующему".to_string());
    d.push("   коду, а не «протокол сломан».".to_string());
    d.push(String::new());
    d.push("## 1. Домены канонизации".to_string());
    d.push(String::new());
    d.extend(domain_rows());
    d.push(String::new());
    d.push("`term_hash` — единственная связка заказа с деньгами; пересчитывается из заказа и ключа".to_string());
    d.push("получателя по формуле (целые — little-endian; терминатор `0x00` стоит только после".to_string());
    d.push("домена, потому что остальные поля имеют фиксированную ширину, `asset_bytes` несёт свой".to_string());
    d.push("терминатор внутри, а `escrow_ref` предваряется длиной):".to_string());
    d.push(String::new());
    d.push("```".to_string());
    // Формула печатается из того же списка токенов, по которому `term_bytes_per_formula` собирает
    // байты для сверки с кодом: расхождение текста и реализации не может остаться молчаливым.
    // Разрыв строк — по границам токенов, он не влияет на байты.
    let joined: Vec<String> = TERM_TOKENS.iter().map(|t| t.to_string()).collect();
    let groups = [(0usize, 4usize), (4, 7), (7, joined.len())];
    for (gi, &(a, b)) in groups.iter().enumerate() {
        let mut body = joined[a..b].join(" ‖ ");
        // Разрыв строки обязан оставлять разделитель: читатель, который режет формулу по `‖`,
        // не должен получить токен из двух полей, склеенных переводом строки.
        if gi + 1 < groups.len() {
            body.push_str(" ‖");
        }
        d.push(if gi == 0 {
            format!("term_hash = sha256( {body}")
        } else {
            format!("                         {body}")
        });
    }
    d.push(")".to_string());
    d.push("```".to_string());
    d.push(String::new());
    d.push("Здесь `asset_bytes` — ровно байты поля 8 канонической записи заказа (тег ветки, для".to_string());
    d.push("`token` — `chain_id:u64le` и `address(20)`, затем терминатор `0x00`), то есть актив в".to_string());
    d.push("связке с деньгами и актив в заказе не могут разойтись, не разошедшись с `order_ref`.".to_string());
    d.push("`chain_id` для `native` — 0; для `token` он дублирует поле актива намеренно: ширина".to_string());
    d.push("`u64le` в `term_hash` стоит до `asset_bytes`, и читателю не нужно разбирать тег, чтобы".to_string());
    d.push("понять, на какой цепи деньги.".to_string());
    d.push(String::new());
    d.push("## 2. Раскладка объектов слоя".to_string());
    d.push(String::new());
    d.push("Префикс каждой раскладки: литерал домена, затем `0x00`, затем поля в номерованном порядке.".to_string());
    d.push("Колонка «ширина»: `32 байта` — сырые байты фиксированной длины, `u64le`/`u128le`/`u16le` —".to_string());
    d.push("целое little-endian, `один байт` — тег, `u32le длина ‖ тело` — непредельная строка или".to_string());
    d.push("байты, `встраиваемый` — `u32le длина ‖ тело ‖ 0x00 ‖ подпись(64)`. Терминатор ставится".to_string());
    d.push("ровно там, где он напечатан в последней колонке; `—` означает «поля на этом кончаются».".to_string());
    d.push(String::new());
    d.extend(layout_rows("VerifierBinding — подписывает издатель заказа", &[
        ("1", "order_ref", "32 байта", "`0x00`"),
        ("2", "verifier_pubkey", "32 байта", "`0x00`"),
        ("3", "image_digest", "32 байта", "`0x00`"),
        ("4", "term_hash", "32 байта", "—"),
    ]));
    d.extend(layout_rows("ChainDescriptor — описатель одной цепи", &[
        ("—", "тег записи", "один байт: `0`", "`0x00`"),
        ("1", "chain_id", "`u64le`", "`0x00`"),
        ("2", "name", "`u32le` длина ‖ ASCII без терминального нуля", "`0x00`"),
        ("3", "bridge_code", "`u16le`", "`0x00`"),
        ("4", "settle_asset_tag", "один байт", "`0x00`"),
        ("5", "min_amount", "`u128le`", "`0x00`"),
        ("6", "note", "`u32le` длина ‖ ASCII без терминального нуля", "—"),
    ]));
    d.push("Имя и заметка описателя обязаны быть печатным ASCII (`0x20…0x7e`): эти строки входят в".to_string());
    d.push("листья реестра, а значит их пересчитывает сторонний мост. Непечатный ASCII —".to_string());
    d.push("`E_ORDER_MALFORMED`, `settle_asset_tag > 1` — `E_UNSUPPORTED_ASSET`.".to_string());
    d.push(String::new());
    d.push("Листья и корень реестра — та же детерминированная сборка, что §V9.4 для множества файлов:".to_string());
    d.push(String::new());
    d.push("```".to_string());
    d.push("leaf(d)       = sha256( DOMAIN_CHAIN ‖ 0x00 ‖ canonical_bytes(d) )".to_string());
    d.push("registry_root = sha256( DOMAIN_CHAIN ‖ 0x01 ‖ concat(sorted(leaf_i)) )".to_string());
    d.push("пустой реестр = sha256( DOMAIN_CHAIN ‖ 0x01 )".to_string());
    d.push("```".to_string());
    d.push(String::new());
    d.push("Сортировка листьев — по байтовому порядку 32-байтовых хешей, поэтому порядок перечисления".to_string());
    d.push("описателей в реестре не влияет на корень. Дубликат `chain_id` — ошибка структуры".to_string());
    d.push("(`E_ORDER_MALFORMED`), а не «последний победил».".to_string());
    d.push(String::new());
    d.extend(layout_rows("EscrowWitness — подписывает наблюдатель эскроу", &[
        ("1", "term_hash", "32 байта", "`0x00`"),
        ("2", "chain_id", "`u64le`", "`0x00`"),
        ("3", "status", "один байт: `0` not_funded, `1` locked, `2` released, `3` refunded", "`0x00`"),
        ("4", "amount_on_chain", "`u128le`", "`0x00`"),
        ("5", "block_ref", "`u32le` длина ‖ непрозрачные байты", "`0x00`"),
        ("6", "registry_root", "32 байта", "`0x00`"),
        ("7", "observer_pubkey", "32 байта", "—"),
    ]));
    d.push("Состояний ровно четыре: `status` вне `{0, 1, 2, 3}` — ошибка структуры".to_string());
    d.push("(`E_ORDER_MALFORMED`), а не «неизвестное считается разблокированным». Тело `block_ref`".to_string());
    d.push("непрозрачно: мост его не разбирает, оно входит в байты и подпись свидетельства.".to_string());
    d.push(String::new());
    d.extend(layout_rows("PayoutClaim — подписывает получатель выплаты", &[
        ("1", "term_hash", "32 байта", "`0x00`"),
        ("2", "order_ref", "32 байта", "`0x00`"),
        ("3", "receipt", "встраиваемый: тело = канонический JSON квитанции (§V9.5), подпись = 64 байта", "`0x00`"),
        ("4", "binding", "встраиваемый: тело по таблице выше, подпись издателя — 64 байта", "`0x00`"),
        ("5", "witness", "встраиваемый: тело по таблице выше, подпись наблюдателя — 64 байта", "`0x00`"),
        ("6", "beneficiary", "32 байта", "—"),
    ]));
    d.push("Подписи встроенных объектов входят в байты требования: требование цитирует решения трёх".to_string());
    d.push("сторон целиком, иначе читатель не сможет проверить ни одну из подписей офлайн.".to_string());
    d.push(String::new());
    d.push("## 3. Закрытый список кодов".to_string());
    d.push(String::new());
    d.push("Слой стыковки не добавляет имён: ниже — ровно те 18, что объявлены §V9.8. Сверка проверяет".to_string());
    d.push("и обратное: множество кодов, напечатанных в векторах, обязано быть подмножеством этого".to_string());
    d.push("списка (прибор ловит девятнадцатое имя посадкой).".to_string());
    d.push(String::new());
    d.extend(code_rows());
    d.push(String::new());
    d.push("## 4. Порядок вывода решения".to_string());
    d.push(String::new());
    d.push("Порядок значим: при двух нарушениях наблюдатель обязан увидеть тот же код, что и любой".to_string());
    d.push("другой реализатор моста.".to_string());
    d.push(String::new());
    d.push("1. **(0) форма требования** — подпись бенефициара над байтами требования, `order_ref` равен".to_string());
    d.push("   заказу, `beneficiary` равен `submission.submitter`, встроенные объекты кодируются.".to_string());
    d.push("   Отсутствие подписи требования и нарушение его формы дают `E_ORDER_MALFORMED`;".to_string());
    d.push("   встроенный объект без подписи даёт свой код (квитанция — `E_RECEIPT_UNSIGNED`, связка —".to_string());
    d.push("   `E_RECEIPT_INVALID`, свидетельство — `E_ESCROW_UNKNOWN`).".to_string());
    d.push("2. **(1) `term_hash`** пересчитан из (заказ, получатель) и равен напечатанному, иначе".to_string());
    d.push("   `E_HASH_MISMATCH`.".to_string());
    d.push("3. **(2) вердикт** выведен из полей квитанции по §V9.5, равен напечатанному и есть `pass`;".to_string());
    d.push("   иначе `E_VERDICT_MISMATCH` либо код, который называет сам вывод. Ссылки квитанции на заказ".to_string());
    d.push("   и подачу не совпали — `E_RECEIPT_INVALID`.".to_string());
    d.push("4. **(3) ключ квитанции** равен ключу из связки издателя и подпись квитанции проходит; иначе".to_string());
    d.push("   `E_RECEIPT_UNSIGNED`.".to_string());
    d.push("5. **(4) связка** подписана издателем заказа и относится к этому заказу, его `term_hash` и".to_string());
    d.push("   образу; иначе `E_RECEIPT_INVALID`.".to_string());
    d.push("6. **(5) залог**: наблюдатель в доверенном наборе, свидетельство выдано про этот контракт,".to_string());
    d.push("   подпись наблюдателя проходит, корень реестра доверен. Каждый из этих четырёх отказов".to_string());
    d.push("   даёт `E_ESCROW_UNKNOWN`: квитанция при этом остаётся годной, поэтому называть её".to_string());
    d.push("   неподписанной было бы неправдой. Неизвестный тег `status` — `E_ORDER_MALFORMED`,".to_string());
    d.push("   затем состояние свидетельства исполняет".to_string());
    d.push("   `check_escrow` (§V9.7) — тот же судья и те же коды: `E_ESCROW_UNKNOWN`,".to_string());
    d.push("   `E_UNSUPPORTED_ASSET`, `E_ESCROW_INSUFFICIENT`, `E_REPLAY`.".to_string());
    d.push("7. **(6) часы**: `submission.created_at ≤ deadline` и `now ≤ deadline +`".to_string());
    d.push(format!("   `PAYBACK_WINDOW_SECONDS = {PAYBACK_WINDOW_SECONDS}`; иначе `E_DEADLINE_PASSED`."));
    d.push(String::new());
    d.push("## 5. Общие входы и снимок доверия".to_string());
    d.push(String::new());
    d.push(format!(
        "- реестр цепей: {} описателей, `registry_root` = `{}`",
        registry().len(),
        hex_lower(&registry_root(&registry()).unwrap())
    ));
    d.push(format!("- доверенные цепи: `{}`", registry().iter().map(|d| d.chain_id.to_string()).collect::<Vec<_>>().join(",")));
    d.push("- доверенный наблюдатель: ключ `keypair(5)`;".to_string());
    d.push("- верификатор: `keypair(3)`; издатель: `keypair(1)`; получатель выплаты: `keypair(2)`.".to_string());
    d.push("- `keypair(seed)` кладёт `seed` в первый байт и `seed xor 0xa5` в последний — соглашение".to_string());
    d.push("  из `docs/PAID_ORDER-VECTORS.md`, его же проверял `E-0113`;".to_string());
    d.push("- подпись — Ed25519 (`RFC 8032`) над байтами объекта без поля `signature`;".to_string());
    d.push(format!(
        "- подпись квитанции покрывает байты `{}` ({}) затем `0x00` затем canonical_json(receipt);",
        String::from_utf8_lossy(DOMAIN_RECEIPT),
        DOMAIN_RECEIPT.len()
    ));
    d.push("  домен напечатан здесь, потому что мост проверяет квитанцию офлайн и не обязан".to_string());
    d.push("  открывать §V9.5;".to_string());
    d.push(format!("- `PAYBACK_WINDOW_SECONDS` = {PAYBACK_WINDOW_SECONDS}, `AXIOM_ALLOWLIST` = [{}]", AXIOM_ALLOWLIST.join(", ")));
    d.push(String::new());
    d.push("### Реестр цепочек".to_string());
    d.push(String::new());
    d.push("Напечатаны и поля, и их байты, и листья: это вход для пересчёта корня без догадок.".to_string());
    d.push(String::new());
    d.extend(registry_rows());
    d.push(String::new());
    d.push("### Байты честного требования (вектор P01)".to_string());
    d.push(String::new());
    let cb = vs[0].claim.canonical_bytes().unwrap();
    d.push(format!("- длина: {}", cb.len()));
    d.push(format!("- sha256 байтов требования: `{}`", sha256_hex(&cb)));
    d.push(format!("- `term_hash`: `{}`", hex_lower(&term_hash(&vs[0].order, &vs[0].sub.submitter))));
    d.push(format!("- `order_ref`: `{}`", hex_lower(&vs[0].order.order_ref())));
    d.push(format!("- `beneficiary`: `{}`", hex_lower(&vs[0].sub.submitter)));
    d.push(String::new());
    d.push("## 6. Векторы".to_string());
    d.push(String::new());
    d.push("Каждый блок — полный набор полей вектора: по ним требование пересобирается с нуля. Пустое".to_string());
    d.push("значение подписи напечатано как `-`. `outcome` — `payout` либо `reject`; `code` — напечатанный".to_string());
    d.push("код отказа (или `-`); он же и есть предсказание, против которого сверяется прибор.".to_string());
    d.push(String::new());
    for v in vs {
        d.extend(vector_block(v));
    }
    d.push("## 7. Покрытие".to_string());
    d.push(String::new());
    let mut codes: Vec<&str> = Vec::new();
    let mut payouts = 0usize;
    let mut replays = 0usize;
    for v in vs {
        match v.decision() {
            Ok(()) => payouts += 1,
            Err(e) => {
                codes.push(e.code.as_str());
                if e.code == ErrorCode::E_REPLAY {
                    replays += 1;
                }
            }
        }
    }
    codes.sort_unstable();
    codes.dedup();
    d.push(format!("- векторов: {}", vs.len()));
    d.push(format!("- из них «платить»: {payouts}"));
    d.push(format!("- различных кодов отказа, использованных слоем: {} — `{}`", codes.len(), codes.join("`, `")));
    d.push(format!("- отказов `E_REPLAY` (повторное требование на распорядившийся залог): {replays}"));
    d.push(format!("- закрытый список кодов: {} имён; ни одного нового слой не ввёл", ErrorCode::all().len()));
    d.push(String::new());
    let mut doc = d.join("\n");
    if !doc.ends_with('\n') {
        doc.push('\n');
    }
    doc
}

// ---------------------------------------------------------------------------
// Прибор
// ---------------------------------------------------------------------------

#[test]
fn payout_vectors_are_reproducible_and_close_the_list() {
    let vs = vectors();
    assert!(vs.len() >= 12, "векторов обязано быть не меньше 12, а то {}", vs.len());
    let mut ids: Vec<&str> = vs.iter().map(|v| v.id).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), before, "id векторов не повторяются");

    // Инвариант аддитивности: заказ-якорь из `E-0111` пересобран здесь независимо и обязан дать ровно
    // тот же `order_ref`, что печатает `docs/PAID_ORDER-VECTORS.md`.
    let anchor = v01_order();
    let anchor_hex = hex_lower(&anchor.order_ref());
    println!("V9P_V01_ORDER_REF={anchor_hex}");
    println!("V9P_ORDER_REF_UNCHANGED={}", i32::from(anchor_hex == V01_ORDER_REF));
    assert_eq!(anchor_hex, V01_ORDER_REF, "байты заказа изменились от появления слоя — это не аддитивность");

    // Каждый вектор печатает один и тот же набор ключей, и байты требования напечатаны всегда (для
    // некодирующихся посадок — `-` с причиной, а не отсутствующая строка).
    let mut keys_per_vector: Vec<usize> = Vec::new();
    for v in &vs {
        let f = fields(v);
        keys_per_vector.push(f.len());
        assert!(f.iter().any(|(k, _)| k == "claim.canonical_hex"), "{}: нет байтов требования", v.id);
        assert!(f.iter().any(|(k, _)| k == "code"), "{}: нет предсказания кода", v.id);
        if v.claim.signature.is_some() {
            assert!(!v.claim.canonical_bytes().unwrap().is_empty(), "{}: пустые байты при непустой подписи", v.id);
        }
    }
    assert!(keys_per_vector.windows(2).all(|w| w[0] == w[1]), "набор ключей у всех векторов обязан быть одинаков");
    println!("V9P_VECTORS={}", vs.len());
    println!("V9P_VECTOR_KEYS={}", keys_per_vector[0]);

    // Покрытие: имена, которые печатает слой, — подмножество закрытого списка; нового имени нет.
    let all = ErrorCode::all();
    let mut used: Vec<&str> = Vec::new();
    let mut replays = 0usize;
    let mut payouts = 0usize;
    for v in &vs {
        match v.decision() {
            Ok(()) => payouts += 1,
            Err(e) => {
                assert!(all.iter().any(|c| c.as_str() == e.code.as_str()), "код вне закрытого списка: {}", e.code.as_str());
                used.push(e.code.as_str());
                if e.code == ErrorCode::E_REPLAY {
                    replays += 1;
                }
            }
        }
    }
    used.sort_unstable();
    used.dedup();
    println!("V9P_CODE_TOTAL={}", all.len());
    println!("V9P_CODES_USED={}", used.len());
    println!("V9P_CODES_SUBSET=1");
    println!("V9P_PAYOUTS={payouts}");
    println!("V9P_DOUBLE_REPLAY={replays}");
    assert_eq!(all.len(), 18, "закрытый список из 18 имён");
    assert!(payouts >= 7, "честных выплат обязано быть не меньше семи (шесть цепей + P01), а то {payouts}");
    assert_eq!(replays, 12, "переисполнение залога: шесть цепей на два состояния");
    assert!(!used.contains(&"E_PAYOUT_UNKNOWN"), "девятнадцатое имя не должно встретиться никогда");

    let root = registry_root(&registry()).unwrap();
    println!("V9P_REGISTRY_ROOT={}", hex_lower(&root));
    println!("V9P_DOMAINS=5");
    println!("V9P_RECEIPT_KEYS=13");
    let p01 = &vs[0];
    println!("V9P_ORDER_REF={}", hex_lower(&p01.order.order_ref()));
    println!("V9P_TERM_HASH={}", hex_lower(&term_hash(&p01.order, &p01.sub.submitter)));
    let cb = p01.claim.canonical_bytes().unwrap();
    println!("V9P_CLAIM_LEN={}", cb.len());
    println!("V9P_CLAIM_SHA={}", sha256_hex(&cb));
    // Двойной пересчёт: тот же вход — те же байты, ни одного скрытого состояния.
    assert_eq!(registry_root(&registry()).unwrap(), root, "корень реестра стабилен");
    assert_eq!(vs[0].claim.canonical_bytes().unwrap(), cb, "байты требования воспроизводимы");

    // Напечатанная формула обязана собираться в те же байты, что считает реализация: сверка
    // исполняется на каждом векторе до записи документа, поэтому §1 не имеет права врать молча.
    for v in &vs {
        let printed = term_hash(&v.order, &v.sub.submitter);
        assert_eq!(
            sha256_hex(&term_bytes_per_formula(&v.order, &v.sub.submitter)),
            hex_lower(&printed),
            "{}: напечатанная формула term_hash расходится с кодом",
            v.id
        );
    }
    println!("V9P_FORMULA_EQ={}", vs.len());
    println!("V9P_TERM_TOKENS={}", TERM_TOKENS.len());

    let doc = render_doc(&vs);
    println!("V9P_DOC_BYTES={}", doc.len());
    println!("V9P_DOC_SHA={}", sha256_hex(doc.as_bytes()));

    match std::env::var("V9P_VECTORS_OUT") {
        Ok(path) => {
            let given = std::path::Path::new(&path);
            let full = if given.is_absolute() {
                given.to_path_buf()
            } else {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(given)
            };
            if let Some(dir) = full.parent() {
                std::fs::create_dir_all(dir).expect("каталог документа создаётся");
            }
            std::fs::write(&full, doc.as_bytes())
                .unwrap_or_else(|e| panic!("документ не записан в {}: {e}", full.display()));
            println!("V9P_DOC_WRITTEN={}", full.display());
        }
        Err(_) => println!("V9P_DOC_WRITTEN=нет_переменной_V9P_VECTORS_OUT"),
    }
}
