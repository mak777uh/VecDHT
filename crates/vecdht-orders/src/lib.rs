//! VecDHT v9, приложение «платные заказы» (§V9, `ADR-0061`).
//!
//! Модуль отвечает на один вопрос: **можно ли выплатить награду по квитанции, не привлекая
//! человека**. Ответ должен быть функцией от байтов, а не от мнения, поэтому здесь живут:
//!
//! * канонизация задания и записи заказа → `statement_hash`, `order_digest` (он же `order_ref`);
//! * канонизация подачи и множество-хеш артефакта → `submission_ref`;
//! * канонический JSON квитанции, её подпись и **правило вывода вердикта** (`Receipt::derive`);
//! * тотальная машина состояний (`step`) — любая пара (состояние, событие) имеет исход, «не знаю»
//!   = `E_STATE_UNKNOWN`, а не неопределённое поведение;
//! * закрытый список кодов ошибок и действие узла для каждого.
//!
//! Чего здесь сознательно нет: сети, хранилища артефактов, блокчейна и самого верификатора.
//! VecDHT по §V9.0 занимается поиском и публикацией записей; `lock/release/refund` — интерфейс,
//! который реализует эскроу-сторона (спека §V9.7), а не этот модуль.
//!
//! Хеш-функция этого приложения — SHA-256, а не blake3, который стоит в wire-формате v8 (§5.2).
//! Причина внешняя, а не вкусовая: `image_digest` — это digest манифеста OCI, и он sha256 по
//! определению; `stdout_sha256`/`stderr_sha256` обязан уметь посчитать любой `sha256sum`; вердикт
//! должен воспроизводить сторонний верификатор (§V9.10, горизонт H3), у которого нет нашего codec.
//! Два домена никогда не смешиваются: байты заказа не попадают в `sig_input` индекса, и наоборот.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Префикс домена для хеша канонического задания (§V9.3).
pub const DOMAIN_STATEMENT: &[u8] = b"vecdht/paid_order/v1";
/// Префикс домена для хеша канонической записи заказа (§V9.2). Тот же, что и у задания: запись
/// начинается с domain-строки, а дальше идёт `kind || 0x00 || …`, поэтому столкновение с хешем
/// «голого» текста исключено по построению.
pub const DOMAIN_ORDER: &[u8] = b"vecdht/paid_order/v1";
/// Префикс домена для bytes-под-письмо квитанции (§V9.5).
pub const DOMAIN_RECEIPT: &[u8] = b"vecdht/paid_order_receipt/v1";
/// Префикс домена для хеша множества файлов артефакта (§V9.4).
pub const DOMAIN_FILESET: &[u8] = b"vecdht/paid_order_fileset/v1";

/// Три класса задач, для которых вердикт — детерминированная функция от артефакта и образа
/// (`docs/PAID_ORDERS.md` §1, классы A–D; класс C в v9 идёт под тегом `test_conformance`,
/// класс E и «найди уязвимость» в протокол не входят).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    LeanProof,
    TestConformance,
    ReproRun,
}

impl Kind {
    /// Кодовый байт канонической записи. Совпадает с порядком объявления; других значений нет.
    pub fn tag(self) -> u8 {
        match self {
            Kind::LeanProof => 0,
            Kind::TestConformance => 1,
            Kind::ReproRun => 2,
        }
    }

    pub fn from_tag(v: u8) -> Result<Self, OrderError> {
        match v {
            0 => Ok(Kind::LeanProof),
            1 => Ok(Kind::TestConformance),
            2 => Ok(Kind::ReproRun),
            other => Err(OrderError::new(ErrorCode::E_ORDER_MALFORMED, "неизвестный тег kind", Some(other.to_string()))),
        }
    }

    /// ASCII-имя: оно входит в JSON квитанции и в тексты векторов.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::LeanProof => "lean_proof",
            Kind::TestConformance => "test_conformance",
            Kind::ReproRun => "repro_run",
        }
    }
}

/// Allowlist аксиом для `kind = lean_proof` (§V9.5). Это три аксиомы ядра Lean 4 — `propext`,
/// `Classical.choice`, `Quoted.sound`; они не «разрешены по догадке»: прибор читает список аксиом,
/// который назвал kernel, и сверяет с этим множеством.
///
/// `OPEN`: привязка к конкретной версии тулчейна (digest образа) появляется вместе с первым
/// опубликованным образом верификатора — см. §V9.10, горизонт H2.
pub const AXIOM_ALLOWLIST: [&str; 3] = ["propext", "Classical.choice", "Quoted.sound"];

/// Запрещённые маркеры в тексте Lean-задания (§V9.9, proof farming).
pub const FORBIDDEN_MARKERS: [&str; 2] = ["sorry", "admit"];

// ---------------------------------------------------------------------------
// Ошибки: закрытый список + действие узла
// ---------------------------------------------------------------------------

/// Закрытый список кодов ошибок (§V9.8). Новый код — только через ADR: сторонний клиент обязан
/// уметь распознать всякий код, который может встретить.
///
/// Имена вариантов — нормативные строки спеки (`E_ORDER_MALFORMED`), а не стиль Rust: их печатает
/// квитанция и по ним сверяется сторонний клиент, поэтому они оставлены как есть намеренно.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Запись не декодируется или нарушает структурное правило.
    E_ORDER_MALFORMED,
    /// Задание не проходит канонизацию (§V9.3): не UTF-8, недопустимый символ, пустой после нормализации.
    E_STATEMENT_ENCODING,
    /// Обещанный хеш не совпал с посчитанным (задание, артефакт или order_ref).
    E_HASH_MISMATCH,
    /// Узел не может достать образ по `verifier.image_digest` (§V9.2, правило 4).
    E_IMAGE_UNAVAILABLE,
    /// Проверка вышла за `budget_seconds`.
    E_BUDGET_EXCEEDED,
    /// Повторная подача с тем же `(submitter, nonce)` или повторная квитанция на тот же `submission_ref`.
    E_REPLAY,
    /// Достигнут `submit_limit` заказа.
    E_SUBMIT_LIMIT,
    /// `reward.escrow_ref` на цепи, которую узел не отслеживает, — fail closed (§V9.7).
    E_ESCROW_UNKNOWN,
    /// Эскроу найден, но заложенной суммы меньше, чем обещано заказом (§V9.7).
    E_ESCROW_INSUFFICIENT,
    /// Квитанция не проходит проверку формы (не подписана, битый JSON, неизвестный verdict).
    E_RECEIPT_INVALID,
    /// Подпись квитанции не проходит проверку по `verifier_pubkey`.
    E_RECEIPT_UNSIGNED,
    /// Поля квитанции дают вердикт, отличный от напечатанного в `verdict` (§V9.5).
    E_VERDICT_MISMATCH,
    /// Список аксиом вне `AXIOM_ALLOWLIST` (или содержит `sorry`/`admit` в задании).
    E_AXIOM_NOT_ALLOWED,
    /// Событие пришло после `deadline` (включительно; §V9.2, правило 3).
    E_DEADLINE_PASSED,
    /// Два файла артефакта с одним путём, либо путь абсолютный / с `..` / с обратным слэшем.
    E_ARTIFACT_PATH,
    /// Множество файлов артефакта пусто.
    E_ARTIFACT_EMPTY,
    /// `reward.asset` описан вне поддерживаемого в v9 набора.
    E_UNSUPPORTED_ASSET,
    /// Пара (состояние, событие) не определена — «не знаю» это ошибка, а не поведение по умолчанию.
    E_STATE_UNKNOWN,
}

impl ErrorCode {
    /// Что обязан сделать узел, увидев эту ошибку (§V9.8).
    pub fn action(self) -> NodeAction {
        use ErrorCode::*;
        match self {
            E_ORDER_MALFORMED | E_STATEMENT_ENCODING | E_HASH_MISMATCH | E_UNSUPPORTED_ASSET
            | E_ARTIFACT_PATH | E_ARTIFACT_EMPTY | E_AXIOM_NOT_ALLOWED | E_ESCROW_INSUFFICIENT => NodeAction::Reject,
            E_IMAGE_UNAVAILABLE | E_REPLAY => NodeAction::Retry,
            E_SUBMIT_LIMIT | E_DEADLINE_PASSED => NodeAction::Ignore,
            E_BUDGET_EXCEEDED | E_ESCROW_UNKNOWN | E_RECEIPT_INVALID | E_RECEIPT_UNSIGNED
            | E_VERDICT_MISMATCH | E_STATE_UNKNOWN => NodeAction::Escalate,
        }
    }

    pub fn as_str(self) -> &'static str {
        use ErrorCode::*;
        match self {
            E_ORDER_MALFORMED => "E_ORDER_MALFORMED",
            E_STATEMENT_ENCODING => "E_STATEMENT_ENCODING",
            E_HASH_MISMATCH => "E_HASH_MISMATCH",
            E_IMAGE_UNAVAILABLE => "E_IMAGE_UNAVAILABLE",
            E_BUDGET_EXCEEDED => "E_BUDGET_EXCEEDED",
            E_REPLAY => "E_REPLAY",
            E_SUBMIT_LIMIT => "E_SUBMIT_LIMIT",
            E_ESCROW_UNKNOWN => "E_ESCROW_UNKNOWN",
            E_ESCROW_INSUFFICIENT => "E_ESCROW_INSUFFICIENT",
            E_RECEIPT_INVALID => "E_RECEIPT_INVALID",
            E_RECEIPT_UNSIGNED => "E_RECEIPT_UNSIGNED",
            E_VERDICT_MISMATCH => "E_VERDICT_MISMATCH",
            E_AXIOM_NOT_ALLOWED => "E_AXIOM_NOT_ALLOWED",
            E_DEADLINE_PASSED => "E_DEADLINE_PASSED",
            E_ARTIFACT_PATH => "E_ARTIFACT_PATH",
            E_ARTIFACT_EMPTY => "E_ARTIFACT_EMPTY",
            E_UNSUPPORTED_ASSET => "E_UNSUPPORTED_ASSET",
            E_STATE_UNKNOWN => "E_STATE_UNKNOWN",
        }
    }

    /// Все коды — для прибора, который проверяет, что векторы покрывают список целиком.
    pub fn all() -> [ErrorCode; 18] {
        use ErrorCode::*;
        [
            E_ORDER_MALFORMED, E_STATEMENT_ENCODING, E_HASH_MISMATCH, E_IMAGE_UNAVAILABLE,
            E_BUDGET_EXCEEDED, E_REPLAY, E_SUBMIT_LIMIT, E_ESCROW_UNKNOWN, E_ESCROW_INSUFFICIENT,
            E_RECEIPT_INVALID, E_RECEIPT_UNSIGNED, E_VERDICT_MISMATCH, E_AXIOM_NOT_ALLOWED,
            E_DEADLINE_PASSED, E_ARTIFACT_PATH, E_ARTIFACT_EMPTY, E_UNSUPPORTED_ASSET,
            E_STATE_UNKNOWN,
        ]
    }
}

/// Действие узла. Четверо: отвергнуть запись, повторить попытку позже, промолчать, увести эпизод в
/// `disputed`. Пятого нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAction {
    Reject,
    Retry,
    Ignore,
    Escalate,
}

impl NodeAction {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeAction::Reject => "reject",
            NodeAction::Retry => "retry",
            NodeAction::Ignore => "ignore",
            NodeAction::Escalate => "escalate",
        }
    }
}

/// Ошибка с причиной: код — машинный, текст — человеческий, детали — для журнала узла.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderError {
    pub code: ErrorCode,
    pub reason: &'static str,
    pub detail: Option<String>,
}

impl OrderError {
    pub fn new(code: ErrorCode, reason: &'static str, detail: Option<String>) -> Self {
        Self { code, reason, detail }
    }

    pub fn action(&self) -> NodeAction {
        self.code.action()
    }
}

impl std::fmt::Display for OrderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            Some(d) => write!(f, "{}: {} [{d}]", self.code.as_str(), self.reason),
            None => write!(f, "{}: {}", self.code.as_str(), self.reason),
        }
    }
}

impl std::error::Error for OrderError {}

// ---------------------------------------------------------------------------
// Канонизация задания (§V9.3)
// ---------------------------------------------------------------------------

/// Нормативная нормализация текста задания. Порядок шагов фиксирован, потому что он влияет на хеш:
///
/// 1. вход обязан быть валидным UTF-8;
/// 2. NFC (Unicode Normalization Form C) — через `unicode-normalization`;
/// 3. `\r\n` и `\r` сводятся к `\n`;
/// 4. с каждой строки снимаются хвостовые ASCII-пробелы (` `, `\t`);
/// 5. хвостовые пустые строки снимаются, файл заканчивается ровно одним `\n`;
/// 6. комментарии — часть задания: ни один язык в v9 не имеет здесь описанного синтаксиса
///    комментариев, поэтому ничего не вырезается;
/// 7. результат обязан быть непустым.
pub fn normalize_statement(raw: &[u8]) -> Result<Vec<u8>, OrderError> {
    let text = std::str::from_utf8(raw)
        .map_err(|e| OrderError::new(ErrorCode::E_STATEMENT_ENCODING, "задание не в UTF-8", Some(e.to_string())))?;
    let nfc: String = text.chars().nfc().collect();
    let lf = nfc.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<&str> = lf
        .split('\n')
        .map(|l| l.trim_end_matches([' ', '\t']))
        .collect();
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    if lines.is_empty() {
        return Err(OrderError::new(ErrorCode::E_STATEMENT_ENCODING, "задание пусто после нормализации", None));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    Ok(out.into_bytes())
}

/// `statement_hash = sha256(DOMAIN_STATEMENT || 0x00 || kind_tag || 0x00 || normalized)`.
///
/// Два решения, записанные здесь потому, что на них реализации расходятся чаще всего:
/// * доменное разделение делает хеш привязанным к классу задачи, то есть **один и тот же текст в
///   `lean_proof` и в `repro_run` — это два разных задания** (§V9.2, правило 2);
/// * хеш считается по нормализованным байтам, поэтому две кодировки одного смысла дают один хеш
///   ровно в той степени, в какой шаг 1–5 их схлопывает. Полностью «смысловой» канонизации нет:
///   `a ∧ b` и `b ∧ a` — разные задания, и это не дефект, а следствие правила «вердикт — функция
///   от байтов» (§V9.2, правило 1).
pub fn statement_hash(kind: Kind, raw: &[u8]) -> Result<[u8; 32], OrderError> {
    let norm = normalize_statement(raw)?;
    Ok(sha256_chain(&[
        DOMAIN_STATEMENT,
        &[0x00],
        &[kind.tag()],
        &[0x00],
        &norm,
    ]))
}

// ---------------------------------------------------------------------------
// Запись заказа (§V9.2)
// ---------------------------------------------------------------------------

pub type Hash = [u8; 32];
pub type PubKey = [u8; 32];
pub type Sig = [u8; 64];

/// Как верификатор исполняется: образ, точка входа, потолок времени, есть ли сеть.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierSpec {
    /// digest манифеста OCI — sha256 по определению формата, поэтому в v9 он и sha256-хеш.
    pub image_digest: Hash,
    pub entrypoint: String,
    pub budget_seconds: u32,
    /// `false` по умолчанию; `true` требует отдельного ADR, потому что ломает воспроизводимость.
    pub network: bool,
}

/// Актив награды. v9 знает ровно две формы; всё остальное — `E_UNSUPPORTED_ASSET`, а не «неизвестный
/// контракт»: узел не вправе угадывать чужой asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asset {
    Native,
    Token { chain_id: u64, address: [u8; 20] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reward {
    /// 16 байт little-endian в канонической записи. Дробых единиц нет: минимальная единица актива.
    pub amount: u128,
    pub asset: Asset,
    /// Ссылка на эскроу (адрес контракта + опциональный id слота). Узел её не исполняет, только
    /// проверяет, что цепь известна (§V9.7).
    pub escrow_ref: Vec<u8>,
}

/// Запись платного заказа. Поля идут в канонической записи именно в этом порядке (§V9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidOrder {
    pub kind: Kind,
    /// Каноническое утверждение/набор тестов/манифест прогона — байты после `normalize_statement`.
    pub statement: Vec<u8>,
    pub statement_hash: Hash,
    pub verifier: VerifierSpec,
    pub reward: Reward,
    /// Unix-секунды. **Включительно**: подача в `deadline` законна, в `deadline + 1` — нет.
    pub deadline: u64,
    pub submit_limit: u16,
    pub publisher: PubKey,
    /// Область воспроизведения — **на издателя** (per publisher), не глобально: узел не хранит
    /// глобальный счётчик и не может его проверить.
    pub nonce: u64,
    /// Подпись издателя над `canonical_record()` (без этого поля). Заполняется при публикации.
    pub signature: Option<Sig>,
}

impl PaidOrder {
    /// Канонические байты записи, **не включая** `signature`.
    pub fn canonical_record(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(DOMAIN_ORDER);
        w.push(0x00);
        w.push(self.kind.tag());
        w.push(0x00);
        w.extend_from_slice(&self.statement_hash);
        w.push(0x00);
        w.extend_from_slice(&self.verifier.image_digest);
        w.push(0x00);
        push_string(&mut w, &self.verifier.entrypoint);
        w.push(0x00);
        w.extend_from_slice(&self.verifier.budget_seconds.to_le_bytes());
        w.push(0x00);
        w.push(u8::from(self.verifier.network));
        w.push(0x00);
        w.extend_from_slice(&self.reward.amount.to_le_bytes());
        w.push(0x00);
        match &self.reward.asset {
            Asset::Native => w.push(0),
            Asset::Token { chain_id, address } => {
                w.push(1);
                w.extend_from_slice(&chain_id.to_le_bytes());
                w.extend_from_slice(address);
            }
        }
        w.push(0x00);
        push_bytes(&mut w, &self.reward.escrow_ref);
        w.push(0x00);
        w.extend_from_slice(&self.deadline.to_le_bytes());
        w.push(0x00);
        w.extend_from_slice(&self.submit_limit.to_le_bytes());
        w.push(0x00);
        w.extend_from_slice(&self.publisher);
        w.push(0x00);
        w.extend_from_slice(&self.nonce.to_le_bytes());
        w
    }

    /// `order_digest` = `order_ref`: один и тот же хеш используется и как идентификатор записи в
    /// подаче/квитанции, и как ключ эскроу. Два имени на один хеш — источник путаницы, поэтому
    /// второго хеша в v9 нет.
    pub fn order_ref(&self) -> Hash {
        sha256(&self.canonical_record())
    }

    /// Байты, которые подписывает издатель.
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.canonical_record()
    }

    pub fn sign(&mut self, key: &SigningKey) {
        self.signature = Some(key.sign(&self.signing_bytes()).to_bytes());
    }

    /// Структурная проверка заказа. Делает ровно то, что обещает spec: форма, совпадение хеша,
    /// непустой entrypoint, ненулевой бюджет, корректный путь nowhere-поле.
    pub fn check(&self) -> Result<(), OrderError> {
        if self.statement.is_empty() {
            return Err(OrderError::new(ErrorCode::E_STATEMENT_ENCODING, "задание пустое", None));
        }
        if self.statement != normalize_statement(&self.statement)? {
            return Err(OrderError::new(
                ErrorCode::E_STATEMENT_ENCODING,
                "задание не в нормализованной форме",
                None,
            ));
        }
        let want = statement_hash(self.kind, &self.statement)?;
        if want != self.statement_hash {
            return Err(OrderError::new(ErrorCode::E_HASH_MISMATCH, "statement_hash не совпал", None));
        }
        if self.verifier.entrypoint.trim().is_empty() {
            return Err(OrderError::new(ErrorCode::E_ORDER_MALFORMED, "пустой entrypoint", None));
        }
        if self.verifier.budget_seconds == 0 {
            return Err(OrderError::new(ErrorCode::E_ORDER_MALFORMED, "нулевой бюджет", None));
        }
        if self.reward.escrow_ref.is_empty() {
            return Err(OrderError::new(ErrorCode::E_ESCROW_UNKNOWN, "пустой escrow_ref", None));
        }
        if self.deadline == 0 {
            return Err(OrderError::new(ErrorCode::E_ORDER_MALFORMED, "deadline не задан", None));
        }
        if self.kind == Kind::LeanProof {
            let text = String::from_utf8_lossy(&self.statement);
            for m in FORBIDDEN_MARKERS {
                if contains_word(&text, m) {
                    return Err(OrderError::new(
                        ErrorCode::E_AXIOM_NOT_ALLOWED,
                        "задание содержит запрещённый маркер",
                        Some(m.to_string()),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn verify_publisher(&self, publisher: &VerifyingKey) -> bool {
        match &self.signature {
            Some(bytes) => Signature::from_slice(bytes)
                .map(|s| publisher.verify(&self.signing_bytes(), &s).is_ok())
                .unwrap_or(false),
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Подача (§V9.4)
// ---------------------------------------------------------------------------

/// Один файл артефакта: путь и sha256 содержимого.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactFile {
    pub path: String,
    pub content_sha256: Hash,
}

/// Проверить путь: относительный, POSIX, без `..`, без ведущего `/` и без обратных слэшей.
fn check_path(path: &str) -> Result<(), OrderError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(OrderError::new(ErrorCode::E_ARTIFACT_PATH, "недопустимый путь файла", Some(path.to_string())));
    }
    Ok(())
}

/// Хеш множества файлов артефакта. Правило записано прямо, потому что «Merkle root» без правила —
/// это то место, где две реализации расходятся:
///
/// * листья: `sha256(DOMAIN_FILESET || 0x00 || path || 0x00 || content_sha256)`;
/// * листья сортируются по байтовому порядку и склеиваются;
/// * корень: `sha256(DOMAIN_FILESET || 0x01 || concat(leaves))`.
///
/// Пустое множество — ошибка, а не хеш от пустого входа: заказ без артефакта нечем проверить.
pub fn artifact_set_hash(files: &[ArtifactFile]) -> Result<Hash, OrderError> {
    if files.is_empty() {
        return Err(OrderError::new(ErrorCode::E_ARTIFACT_EMPTY, "пустое множество файлов", None));
    }
    let mut seen: Vec<&str> = Vec::with_capacity(files.len());
    let mut leaves: Vec<Hash> = Vec::with_capacity(files.len());
    for f in files {
        check_path(&f.path)?;
        if seen.contains(&f.path.as_str()) {
            return Err(OrderError::new(ErrorCode::E_ARTIFACT_PATH, "дубликат пути", Some(f.path.clone())));
        }
        seen.push(&f.path);
        leaves.push(sha256_chain(&[DOMAIN_FILESET, &[0x00], f.path.as_bytes(), &[0x00], &f.content_sha256]));
    }
    leaves.sort_unstable();
    let mut concat: Vec<u8> = Vec::with_capacity(1 + leaves.len() * 32);
    concat.extend_from_slice(DOMAIN_FILESET);
    concat.push(0x01);
    for l in &leaves {
        concat.extend_from_slice(l);
    }
    Ok(sha256(&concat))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub order_ref: Hash,
    /// root множества файлов (§V9.4).
    pub artifact_hash: Hash,
    /// content-addressed URI; узел её не разрешает, только пересылает.
    pub artifact_uri: String,
    pub submitter: PubKey,
    pub nonce: u64,
    pub created_at: u64,
    pub signature: Option<Sig>,
}

impl Submission {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(DOMAIN_ORDER);
        w.push(0x01);
        w.extend_from_slice(&self.order_ref);
        w.push(0x00);
        w.extend_from_slice(&self.artifact_hash);
        w.push(0x00);
        push_string(&mut w, &self.artifact_uri);
        w.push(0x00);
        w.extend_from_slice(&self.submitter);
        w.push(0x00);
        w.extend_from_slice(&self.nonce.to_le_bytes());
        w.push(0x00);
        w.extend_from_slice(&self.created_at.to_le_bytes());
        w
    }

    pub fn submission_ref(&self) -> Hash {
        sha256(&self.canonical_bytes())
    }

    pub fn sign(&mut self, key: &SigningKey) {
        self.signature = Some(key.sign(&self.canonical_bytes()).to_bytes());
    }

    pub fn verify(&self, submitter: &VerifyingKey) -> bool {
        match &self.signature {
            Some(bytes) => Signature::from_slice(bytes)
                .map(|s| submitter.verify(&self.canonical_bytes(), &s).is_ok())
                .unwrap_or(false),
            None => false,
        }
    }
}

/// Проверка подачи против заказа и против журнала издателя. Функция честная: состояние (список
/// уже виденных nonce этого подавшего и число принятых подач) ей передают, потому что узел не
/// вправе его выдумывать — он его помнит. Порядок проверок зафиксирован спекой: тот, кто реализует
/// клиента, обязан получить тот же код при том же положении дел.
///
/// Подпись подачи — структурное правило её записи, поэтому её отсутствие даёт `E_ORDER_MALFORMED`,
/// а не отдельный код: коды квитанции говорят про квитанцию.
pub fn check_submission(
    order: &PaidOrder,
    sub: &Submission,
    files: &[ArtifactFile],
    submitter: &VerifyingKey,
    seen_nonces: &[u64],
    seen_count: u16,
) -> Result<(), OrderError> {
    if !sub.verify(submitter) {
        return Err(OrderError::new(ErrorCode::E_ORDER_MALFORMED, "подпись подачи не проходит или отсутствует", None));
    }
    if sub.submitter != *submitter.as_bytes() {
        return Err(OrderError::new(ErrorCode::E_ORDER_MALFORMED, "ключ подачи не равен подписавшему", None));
    }
    if sub.order_ref != order.order_ref() {
        return Err(OrderError::new(ErrorCode::E_HASH_MISMATCH, "подача ссылается на другой заказ", None));
    }
    // `deadline` включительно: подача ровно в `deadline` законна, на секунду позже — нет.
    if sub.created_at > order.deadline {
        return Err(OrderError::new(
            ErrorCode::E_DEADLINE_PASSED,
            "подача после срока",
            Some(format!("{}, срок {}", sub.created_at, order.deadline)),
        ));
    }
    if seen_nonces.contains(&sub.nonce) {
        return Err(OrderError::new(
            ErrorCode::E_REPLAY,
            "тот же (submitter, nonce) уже принят",
            Some(sub.nonce.to_string()),
        ));
    }
    if seen_count >= order.submit_limit {
        return Err(OrderError::new(
            ErrorCode::E_SUBMIT_LIMIT,
            "предел подач заказа исчерпан",
            Some(format!("{}, лимит {}", seen_count, order.submit_limit)),
        ));
    }
    let want = artifact_set_hash(files)?;
    if want != sub.artifact_hash {
        return Err(OrderError::new(
            ErrorCode::E_HASH_MISMATCH,
            "хеш множества файлов не совпал с поданным",
            None,
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Квитанция (§V9.5) — ядро протокола
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Timeout,
    Error,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Timeout => "timeout",
            Verdict::Error => "error",
        }
    }

    /// Разбор имени вердикта из квитанции. Реализован как `FromStr`, чтобы `"pass".parse::<Verdict>()`
    /// работал у стороннего клиента без отдельного имени: четыре строки ниже — нормативны (§V9.7).
    pub fn parse_name(s: &str) -> Result<Self, OrderError> {
        match s {
            "pass" => Ok(Verdict::Pass),
            "fail" => Ok(Verdict::Fail),
            "timeout" => Ok(Verdict::Timeout),
            "error" => Ok(Verdict::Error),
            other => Err(OrderError::new(ErrorCode::E_RECEIPT_INVALID, "неизвестный verdict", Some(other.to_string()))),
        }
    }
}

impl core::str::FromStr for Verdict {
    type Err = OrderError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Verdict::parse_name(s)
    }
}

/// Квитанция верификатора. Пустой `axioms` для не-Lean допустим: поле существует, чтобы kernel
/// назвал аксиомы, а не чтобы верификатор их сочинял.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub order_ref: Hash,
    pub submission_ref: Hash,
    /// Заявленный вердикт. Обязан совпасть с `derive()` — иначе квитанция невалидна.
    pub verdict: Verdict,
    pub image_digest: Hash,
    /// Точная версия тулчейна; для `lean_proof` — версия Lean и, если использовалась, commit mathlib.
    pub toolchain: String,
    pub axioms: Vec<String>,
    /// Замерено верификатором, целые миллисекунды.
    pub wall_clock_ms: u64,
    /// Объявлено заказом, целые миллисекунды: `budget_seconds * 1000`.
    pub budget_ms: u64,
    pub exit_code: i32,
    pub stdout_sha256: Hash,
    pub stderr_sha256: Hash,
    pub deterministic: bool,
    pub verifier_pubkey: PubKey,
    pub signature: Option<Sig>,
}

impl Receipt {
    /// Канонический JSON. Правило сериализации записано полностью, потому что «два независимых
    /// верификатора должны сойтись байт в байт» — это про сериализацию, а не про криптографию:
    ///
    /// * ключи в ASCII-порядке, перечислены ниже;
    /// * целые числа — десятичные без ведущего нуля, `exit_code` может быть отрицательным;
    /// * хеши — нижний регистр hex без разделителей;
    /// * булевы — `true`/`false`;
    /// * `toolchain` и имена аксиом обязаны быть печатным ASCII (иначе `E_RECEIPT_INVALID`), поэтому
    ///   правило экранирования строк — только `"` и `\`;
    /// * `axioms` — массив строк в том порядке, который назвал kernel; пустой массив пишется `[]`;
    /// * поля `signature` в подписываемых байтах **нет**.
    pub fn canonical_json(&self) -> Result<Vec<u8>, OrderError> {
        if !printable_ascii(&self.toolchain) {
            return Err(OrderError::new(ErrorCode::E_RECEIPT_INVALID, "toolchain вне печатного ASCII", None));
        }
        for a in &self.axioms {
            if !printable_ascii(a) {
                return Err(OrderError::new(ErrorCode::E_RECEIPT_INVALID, "имя аксиомы вне печатного ASCII", Some(a.clone())));
            }
        }
        let mut s = String::new();
        s.push('{');
        push_kv(&mut s, "axioms", &format!("[{}]", self.axioms.iter().map(|a| quote(a)).collect::<Vec<_>>().join(",")));
        s.push(',');
        push_kv(&mut s, "budget_ms", &self.budget_ms.to_string());
        s.push(',');
        push_kv(&mut s, "deterministic", if self.deterministic { "true" } else { "false" });
        s.push(',');
        push_kv(&mut s, "exit_code", &self.exit_code.to_string());
        s.push(',');
        push_kv(&mut s, "image_digest", &quote(&hex_lower(&self.image_digest)));
        s.push(',');
        push_kv(&mut s, "order_ref", &quote(&hex_lower(&self.order_ref)));
        s.push(',');
        push_kv(&mut s, "stderr_sha256", &quote(&hex_lower(&self.stderr_sha256)));
        s.push(',');
        push_kv(&mut s, "stdout_sha256", &quote(&hex_lower(&self.stdout_sha256)));
        s.push(',');
        push_kv(&mut s, "submission_ref", &quote(&hex_lower(&self.submission_ref)));
        s.push(',');
        push_kv(&mut s, "toolchain", &quote(&self.toolchain));
        s.push(',');
        push_kv(&mut s, "verdict", &quote(self.verdict.as_str()));
        s.push(',');
        push_kv(&mut s, "verifier_pubkey", &quote(&hex_lower(&self.verifier_pubkey)));
        s.push(',');
        push_kv(&mut s, "wall_clock_ms", &self.wall_clock_ms.to_string());
        s.push('}');
        Ok(s.into_bytes())
    }

    /// Байты под письмо: домен + канонический JSON.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(DOMAIN_RECEIPT);
        v.push(0x00);
        v.extend_from_slice(&self.canonical_json().unwrap_or_default());
        v
    }

    pub fn sign(&mut self, key: &SigningKey) {
        self.signature = Some(key.sign(&self.signing_bytes()).to_bytes());
    }

    /// **Правило вывода вердикта** (§V9.5). Порядок значим: он определяет, какой код ошибки увидит
    /// наблюдатель, когда нарушено сразу несколько правил.
    ///
    /// 1. `image_digest ≠` заказа → `error` (`E_IMAGE_UNAVAILABLE` у узла, квитанция невалидна);
    /// 2. `budget_ms ≠ budget_seconds · 1000` → `error` (верификатор не вправе сам себе поднять или
    ///    опустить потолок);
    /// 3. `deterministic = false` → `error` (аттестат «у меня получилось один раз» выплату не даёт);
    /// 4. `axioms` вне allowlist (для `lean_proof`) или непустой у не-Lean класса без объяснения —
    ///    `error` (`E_AXIOM_NOT_ALLOWED`);
    /// 5. `wall_clock_ms > budget_ms` → `timeout` (ровно то определение, что просил заказчик:
    ///    timeout iff measured > budget);
    /// 6. иначе `exit_code == 0` → `pass`, nonzero → `fail`.
    pub fn derive(&self, order: &PaidOrder) -> Result<Verdict, OrderError> {
        if self.image_digest != order.verifier.image_digest {
            return Err(OrderError::new(ErrorCode::E_IMAGE_UNAVAILABLE, "image_digest не совпал с заказом", None));
        }
        let declared = u64::from(order.verifier.budget_seconds).saturating_mul(1_000);
        if self.budget_ms != declared {
            return Err(OrderError::new(
                ErrorCode::E_ORDER_MALFORMED,
                "budget_ms не равен заказу",
                Some(format!("{}, ждало {}", self.budget_ms, declared)),
            ));
        }
        if !self.deterministic {
            return Err(OrderError::new(ErrorCode::E_RECEIPT_INVALID, "прогон не детерминирован", None));
        }
        if order.kind == Kind::LeanProof {
            for a in &self.axioms {
                if !AXIOM_ALLOWLIST.contains(&a.as_str()) {
                    return Err(OrderError::new(ErrorCode::E_AXIOM_NOT_ALLOWED, "аксиома вне allowlist", Some(a.clone())));
                }
            }
        } else if !self.axioms.is_empty() {
            return Err(OrderError::new(ErrorCode::E_AXIOM_NOT_ALLOWED, "не-Lean класс назвал аксиомы", None));
        }
        if self.wall_clock_ms > self.budget_ms {
            // Прогон вышел за потолок заказа. Если при этом команды не было (exit_code ≠ 0) — это
            // и есть таймаут: он выводится из измеренных полей, а не из заявленного вердикта. Если
            // же квитанция показывает успешное завершение (`exit_code = 0`) после потолка, поля
            // противоречат друг другу: «успех», которого не могло быть. Такой исход не вердикт,
            // а ошибка, и узел её эскалирует — выплатить по ней нельзя.
            if self.exit_code == 0 {
                return Err(OrderError::new(
                    ErrorCode::E_BUDGET_EXCEEDED,
                    "exit_code=0 после потолка бюджета",
                    Some(format!("wall {} > budget {}", self.wall_clock_ms, self.budget_ms)),
                ));
            }
            return Ok(Verdict::Timeout);
        }
        Ok(if self.exit_code == 0 { Verdict::Pass } else { Verdict::Fail })
    }

    /// Диагностика квитанции с названием причины (§V9.8). Те же условия, что у `is_valid_for`, но
    /// возвращает код: узел обязан уметь сказать, почему именно он не платит.
    pub fn validate(&self, order: &PaidOrder, submission: &Submission, verifier: &VerifyingKey) -> Result<(), OrderError> {
        self.canonical_json()?;
        if self.order_ref != order.order_ref() || self.submission_ref != submission.submission_ref() {
            return Err(OrderError::new(
                ErrorCode::E_RECEIPT_INVALID,
                "квитанция ссылается на другой заказ или подачу",
                None,
            ));
        }
        match &self.signature {
            None => {
                return Err(OrderError::new(ErrorCode::E_RECEIPT_UNSIGNED, "квитанция без подписи", None));
            }
            Some(bytes) => {
                if self.verifier_pubkey != *verifier.as_bytes() {
                    return Err(OrderError::new(
                        ErrorCode::E_RECEIPT_UNSIGNED,
                        "verifier_pubkey не совпал с доверенным ключом",
                        None,
                    ));
                }
                let ok = Signature::from_slice(bytes)
                    .map(|s| verifier.verify(&self.signing_bytes(), &s).is_ok())
                    .unwrap_or(false);
                if !ok {
                    return Err(OrderError::new(ErrorCode::E_RECEIPT_UNSIGNED, "подпись квитанции не проходит", None));
                }
            }
        }
        let derived = self.derive(order)?;
        if derived != self.verdict {
            return Err(OrderError::new(
                ErrorCode::E_VERDICT_MISMATCH,
                "выведенный вердикт не равен заявленному",
                Some(format!("{} != {}", derived.as_str(), self.verdict.as_str())),
            ));
        }
        Ok(())
    }

    /// Квитанция годна к выплате тогда и только тогда, когда выполняются все четыре условия:
    /// подпись проходит, образ совпадает с заказом, вердикт выводится из полей и равен заявленному,
    /// ссылка на заказ/подачу настоящая. Именно эта функция — «автоматически, без судьи».
    pub fn is_valid_for(&self, order: &PaidOrder, submission: &Submission, verifier: &VerifyingKey) -> bool {
        self.validate(order, submission, verifier).is_ok()
    }

    /// Условие выплаты (§V9.7): pass ∧ годная квитанция ∧ подача в срок ∧ не выплачено ∧ эскроу
    /// проверен. Предпоследнее и последнее — свойства не квитанции, а журнала и наблюдателя, поэтому
    /// здесь их нет: первый проверяет сторона, которая помит `order_ref → payout`, вторая —
    /// `check_escrow` перед `Escrow::release`. Полное условие собирает вызывающий, и спека перечисляет
    /// все пять.
    pub fn payout_allowed(&self, order: &PaidOrder, submission: &Submission, verifier: &VerifyingKey, now: u64) -> bool {
        self.verdict == Verdict::Pass
            && submission.created_at <= order.deadline
            && now <= order.deadline + PAYBACK_WINDOW_SECONDS
            && self.is_valid_for(order, submission, verifier)
    }
}

/// Окно, в котором выплата ещё возможна после `deadline`: результат проверки мог прийти после срока.
/// Число — не измерение и не обещание скорости сети, а параметр протокола; его изменение ломает
/// совместимость и требует ADR.
pub const PAYBACK_WINDOW_SECONDS: u64 = 3_600;

// ---------------------------------------------------------------------------
// Эскроу (§V9.7) — интерфейс, а не кошелёк
// ---------------------------------------------------------------------------

/// Наблюдатель обязан вернуть состояние залога по `order_ref`. Четыре состояния, пятого нет:
/// «не знаю» — это `Err(OrderError)`, а не состояние.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowStatus {
    /// Ни один перевод по этому заказу не найден.
    NotFunded,
    /// Залог лежит на адресе эскроу и ещё не тронут.
    Locked,
    /// Залог уже отпущен исполнителю.
    Released,
    /// Залог уже возвращён издателю.
    Refunded,
}

impl EscrowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            EscrowStatus::NotFunded => "not_funded",
            EscrowStatus::Locked => "locked",
            EscrowStatus::Released => "released",
            EscrowStatus::Refunded => "refunded",
        }
    }
}

/// Что наблюдатель нашёл по ссылке заказа. `chain_id` — число цепи, `amount` — минимальные
/// единицы актива, ровно как в заказе: дробых величин в протоколе нет.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowState {
    pub chain_id: u64,
    pub asset: Asset,
    pub amount: u128,
    pub status: EscrowStatus,
}

/// Три операции интерфейса. Узел их не исполняет — он не держит ключей и не подписывает переводы;
/// узел решает, разрешена ли операция, и передаёт решение стороне, которая перевод делает.
pub trait Escrow {
    /// Что лежит по ссылке заказа. Ошибку возвращает, если цепь неизвестна или наблюдатель недоступен:
    /// отсутствие ответа — это `Err`, а не `NotFunded`.
    fn lookup(&self, order: &PaidOrder) -> Result<EscrowState, OrderError>;
    /// Отпустить залог исполнителю. Разрешена только после годной квитанции с `pass`.
    fn release(&self, order: &PaidOrder, to: &PubKey) -> Result<(), OrderError>;
    /// Вернуть залог издателю. Разрешена при `fail`/`timeout`/`error`, истечении срока и по спору.
    fn refund(&self, order: &PaidOrder) -> Result<(), OrderError>;
}

/// Цепи, которые узел умеет наблюдать в v9. Пустой список — это не незавершённость, а fail-closed
/// поведение: без наблюдателя узел не вправе решить, что залог есть. Ненулевой список появляется
/// только вместе с реализованным наблюдателем и отдельным ADR.
pub const DEFAULT_TRUSTED_CHAINS: &[u64] = &[];

impl Asset {
    /// Актив живёт на одной цепи: `Native` — нативная цепь протокола, у неё номер 0 (§V9.2).
    pub fn chain_id(&self) -> u64 {
        match self {
            Asset::Native => 0,
            Asset::Token { chain_id, .. } => *chain_id,
        }
    }
}

/// Сверка заказа с тем, что нашёл наблюдатель. Порядок проверок зафиксирован: сначала «умеем ли
/// мы смотреть на эту цепь», потом «что именно там лежит», потом «сколько». Меня местами — и
/// сторонний клиент получит другой код при том же положении дел.
pub fn check_escrow(order: &PaidOrder, state: &EscrowState, trusted: &[u64]) -> Result<(), OrderError> {
    let want = order.reward.asset.chain_id();
    if !trusted.contains(&want) || state.chain_id != want {
        return Err(OrderError::new(
            ErrorCode::E_ESCROW_UNKNOWN,
            "цепь залога неизвестна или не совпала с заказом",
            Some(format!("заказ {}, залог {}", want, state.chain_id)),
        ));
    }
    if state.asset != order.reward.asset {
        return Err(OrderError::new(
            ErrorCode::E_UNSUPPORTED_ASSET,
            "актив залога не тот, что обещан заказом",
            None,
        ));
    }
    match state.status {
        EscrowStatus::NotFunded => Err(OrderError::new(
            ErrorCode::E_ESCROW_UNKNOWN,
            "по ссылке заказа залога нет",
            None,
        )),
        EscrowStatus::Released | EscrowStatus::Refunded => Err(OrderError::new(
            ErrorCode::E_REPLAY,
            "залог уже распорядили",
            Some(state.status.as_str().to_string()),
        )),
        EscrowStatus::Locked => {
            if state.amount < order.reward.amount {
                return Err(OrderError::new(
                    ErrorCode::E_ESCROW_INSUFFICIENT,
                    "заложено меньше обещанного",
                    Some(format!("{}, ждали {}", state.amount, order.reward.amount)),
                ));
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Тотальная машина состояний (§V9.6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Published,
    Verifying,
    Passed,
    Failed,
    TimedOut,
    Errored,
    Settled,
    Rejected,
    Expired,
    Disputed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Published => "published",
            State::Verifying => "verifying",
            State::Passed => "pass",
            State::Failed => "fail",
            State::TimedOut => "timeout",
            State::Errored => "error",
            State::Settled => "settled",
            State::Rejected => "rejected",
            State::Expired => "expired",
            State::Disputed => "disputed",
        }
    }

    /// Терминальных состояний ровно два: залог либо отпущен исполнителю (`settled`), либо возвращён
    /// издателю (`rejected`). `expired` терминальным не является: срок вышел, а залог ещё у узла, и
    /// из него остался ровно один переход — `refunded → rejected`.
    pub fn terminal(self) -> bool {
        matches!(self, State::Settled | State::Rejected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Исполнитель подал артефакт.
    Submit,
    /// Верификатор начал прогон.
    VerifyStarted,
    /// Квитанция выдана (какой именно — см. `Outcome::advance`).
    VerdictGiven(Verdict),
    /// Эскроу отпустил выплату.
    Released,
    /// Эскроу вернул залог заказчику.
    Refunded,
    /// Наступил deadline и подач не было.
    DeadlineReached,
    /// Верификатор недоступен дольше `budget × OFFLINE_FACTOR`.
    VerifierOffline,
    /// Апелляция по форме квитанции (только по receipt, не по «мне не понравилось»).
    Appeal,
    /// Любое иное событие. Нужен, чтобы функция была тотальной снаружи.
    Unknown,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Event::Submit => "submit",
            Event::VerifyStarted => "verify_started",
            Event::VerdictGiven(Verdict::Pass) => "verdict_pass",
            Event::VerdictGiven(Verdict::Fail) => "verdict_fail",
            Event::VerdictGiven(Verdict::Timeout) => "verdict_timeout",
            Event::VerdictGiven(Verdict::Error) => "verdict_error",
            Event::Released => "released",
            Event::Refunded => "refunded",
            Event::DeadlineReached => "deadline_reached",
            Event::VerifierOffline => "verifier_offline",
            Event::Appeal => "appeal",
            Event::Unknown => "unknown",
        }
    }
}

/// Во сколько «раз в N» верификатор обязан молчать, чтобы эпизод стал спорным. Параметр протокола,
/// не измерение.
pub const OFFLINE_FACTOR: u64 = 3;

/// Исход перехода: новое состояние либо код ошибки. Определённого поведения «по умолчанию» нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    To(State),
    Error(ErrorCode),
}

/// Все состояния и все события — для прибора, который проверяет полноту матрицы.
pub const ALL_STATES: [State; 10] = [
    State::Published,
    State::Verifying,
    State::Passed,
    State::Failed,
    State::TimedOut,
    State::Errored,
    State::Settled,
    State::Rejected,
    State::Expired,
    State::Disputed,
];

pub const ALL_EVENTS: [Event; 11] = [
    Event::Submit,
    Event::VerifyStarted,
    Event::VerdictGiven(Verdict::Pass),
    Event::VerdictGiven(Verdict::Fail),
    Event::VerdictGiven(Verdict::Timeout),
    Event::VerdictGiven(Verdict::Error),
    Event::Released,
    Event::Refunded,
    Event::DeadlineReached,
    Event::VerifierOffline,
    Event::Appeal,
];

/// Тотальный переход (§V9.6). Матрица 10 × 11 заполнена целиком: у каждой пары есть исход, а всё,
/// что не имеет смысла, возвращает код ошибки — узел тогда действует по `ErrorCode::action()`
/// (reject / retry / ignore / escalate). «Остаться в состоянии молча» не является исходом.
pub fn step(state: State, event: Event) -> Outcome {
    use Event::*;
    use ErrorCode::*;
    use Outcome::*;
    use State::*;
    match state {
        Published => match event {
            Submit => To(Verifying),
            DeadlineReached => To(Expired),
            VerifierOffline => To(Disputed),
            VerdictGiven(_) => Error(E_RECEIPT_INVALID),
            _ => Error(E_STATE_UNKNOWN),
        },
        Verifying => match event {
            VerdictGiven(Verdict::Pass) => To(Passed),
            VerdictGiven(Verdict::Fail) => To(Failed),
            VerdictGiven(Verdict::Timeout) => To(TimedOut),
            VerdictGiven(Verdict::Error) => To(Errored),
            VerifierOffline => To(Disputed),
            // Подача, пока предыдущая ещё проверяется, отклоняется и может быть повторена позже;
            // срок относится к приёму подач, а не к прогону, поэтому он здесь игнорируется.
            Submit => Error(E_REPLAY),
            DeadlineReached => Error(E_DEADLINE_PASSED),
            _ => Error(E_STATE_UNKNOWN),
        },
        Passed => match event {
            Released => To(Settled),
            Appeal => To(Disputed),
            Refunded => Error(E_VERDICT_MISMATCH),
            _ => Error(E_STATE_UNKNOWN),
        },
        Failed | TimedOut | Errored => match event {
            // Выплата отпускается только по `pass`; попытка отпустить её по иному вердикту —
            // расхождение квитанции с полями, а не «странное состояние».
            Released => Error(E_VERDICT_MISMATCH),
            Refunded => To(Rejected),
            Appeal => To(Disputed),
            _ => Error(E_STATE_UNKNOWN),
        },
        Expired => match event {
            Released => Error(E_VERDICT_MISMATCH),
            Refunded => To(Rejected),
            _ => Error(E_STATE_UNKNOWN),
        },
        Disputed => match event {
            // Спор разрешается повторной проверкой по receipt: вердикт снова выводится из полей.
            VerdictGiven(Verdict::Pass) => To(Passed),
            VerdictGiven(Verdict::Fail) => To(Failed),
            VerdictGiven(Verdict::Timeout) => To(TimedOut),
            VerdictGiven(Verdict::Error) => To(Errored),
            Released => Error(E_VERDICT_MISMATCH),
            Refunded => To(Rejected),
            Appeal => Error(E_REPLAY),
            _ => Error(E_STATE_UNKNOWN),
        },
        Settled | Rejected => Error(E_STATE_UNKNOWN),
    }
}

// ---------------------------------------------------------------------------
// Мелкие примитивы канонизации
// ---------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn sha256_chain(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Длина строки — u32 little-endian, затем UTF-8 без терминального нуля.
fn push_string(w: &mut Vec<u8>, s: &str) {
    w.extend_from_slice(&(s.len() as u32).to_le_bytes());
    w.extend_from_slice(s.as_bytes());
}

fn push_bytes(w: &mut Vec<u8>, b: &[u8]) {
    w.extend_from_slice(&(b.len() as u32).to_le_bytes());
    w.extend_from_slice(b);
}

fn push_kv(s: &mut String, key: &str, value: &str) {
    s.push('"');
    s.push_str(key);
    s.push_str("\":");
    s.push_str(value);
}

/// Экранирование строки JSON: в v9 поля-строки обязаны быть печатным ASCII, поэтому достаточно
/// двух замен. Кто захочет положить в `toolchain` что-то с управляющим символом — получит
/// `E_RECEIPT_INVALID`, а не двусмысленный escape.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

/// sha256 в нижнем hex — то, что сторонний клиент проверяет командой `sha256sum`. Функция
/// публичная намеренно: векторы (§V9.9) обязаны быть пересчитываемы без доступа к приватным
/// примитивам crate.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&sha256(bytes))
}

/// Печатный ASCII (0x20…0x7e). Нужен потому, что JSON квитанции не экранирует управляющие символы:
/// сторонний читатель обязан сойтись с нами в байтах строки, а не только в её видимой части.
fn printable_ascii(s: &str) -> bool {
    s.is_ascii() && !s.chars().any(|c| (c as u32) < 0x20 || (c as u32) == 0x7f)
}

/// Целое слово, а не подстрока: `assumed_sorry_free` не должно считаться вхождением `sorry`.
fn contains_word(hay: &str, word: &str) -> bool {
    hay.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| tok == word)
}

/// Публичный ключ из секретного — для векторов и тестов (32-байтный seed).
pub fn keypair(seed: u8) -> (SigningKey, VerifyingKey) {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = seed ^ 0xa5;
    let sk = SigningKey::from_bytes(&bytes);
    let vk: VerifyingKey = sk.verifying_key();
    (sk, vk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order() -> PaidOrder {
        let (sk, vk) = keypair(1);
        let statement = normalize_statement(b"theorem foo : True := by trivial").unwrap();
        let mut o = PaidOrder {
            kind: Kind::LeanProof,
            statement_hash: statement_hash(Kind::LeanProof, b"theorem foo : True := by trivial").unwrap(),
            statement,
            verifier: VerifierSpec {
                image_digest: sha256(b"image-1"),
                entrypoint: "/usr/local/bin/verify".to_string(),
                budget_seconds: 120,
                network: false,
            },
            reward: Reward {
                amount: 1_000,
                asset: Asset::Native,
                escrow_ref: b"base:0xabc".to_vec(),
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

    fn submission(o: &PaidOrder) -> Submission {
        let (sk, vk) = keypair(2);
        let files = vec![
            ArtifactFile { path: "proof.lean".to_string(), content_sha256: sha256(b"a") },
            ArtifactFile { path: "lakefile.lean".to_string(), content_sha256: sha256(b"bb") },
        ];
        let mut s = Submission {
            order_ref: o.order_ref(),
            artifact_hash: artifact_set_hash(&files).unwrap(),
            artifact_uri: "ipfs://bafytest".to_string(),
            submitter: *vk.as_bytes(),
            nonce: 1,
            created_at: 1_799_999_999,
            signature: None,
        };
        s.sign(&sk);
        s
    }

    fn receipt(o: &PaidOrder, s: &Submission, verdict: Verdict, wall: u64, axioms: Vec<String>) -> Receipt {
        let (sk, vk) = keypair(3);
        let mut r = Receipt {
            order_ref: o.order_ref(),
            submission_ref: s.submission_ref(),
            verdict,
            image_digest: o.verifier.image_digest,
            toolchain: "leanprover/lean4:v4.9.1".to_string(),
            axioms,
            wall_clock_ms: wall,
            budget_ms: u64::from(o.verifier.budget_seconds) * 1_000,
            exit_code: if verdict == Verdict::Pass { 0 } else { 1 },
            stdout_sha256: sha256(b"stdout"),
            stderr_sha256: sha256(b"stderr"),
            deterministic: true,
            verifier_pubkey: *vk.as_bytes(),
            signature: None,
        };
        r.sign(&sk);
        r
    }

    #[test]
    fn statement_hash_covers_kind_and_is_nfc_stable() {
        let a = statement_hash(Kind::LeanProof, b"e\xcc\x81x").unwrap();
        let b = statement_hash(Kind::LeanProof, "\u{e9}x".as_bytes()).unwrap();
        assert_eq!(a, b, "NFC обязан схлопнуть decomposed и precomposed");
        let c = statement_hash(Kind::ReproRun, b"e\xcc\x81x").unwrap();
        assert_ne!(a, c, "kind входит в хеш");
    }

    #[test]
    fn normalization_is_line_and_space_only() {
        assert_eq!(normalize_statement(b"a\r\nb  \n\n\n").unwrap(), b"a\nb\n");
        assert_eq!(normalize_statement(b"a\t\nb").unwrap(), b"a\nb\n");
        assert!(normalize_statement(b"   ").is_err());
        assert!(normalize_statement(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn order_check_and_signature_round_trip() {
        let o = order();
        o.check().unwrap();
        let (_, vk) = keypair(1);
        assert!(o.verify_publisher(&vk));
        let (_, wrong) = keypair(9);
        assert!(!o.verify_publisher(&wrong));
        assert_eq!(o.order_ref(), sha256(&o.canonical_record()));
    }

    #[test]
    fn order_ref_changes_with_every_field() {
        let base = order();
        let mut other = base.clone();
        other.nonce += 1;
        assert_ne!(base.order_ref(), other.order_ref());
        other = base.clone();
        other.verifier.network = true;
        assert_ne!(base.order_ref(), other.order_ref());
    }

    #[test]
    fn forbidden_marker_in_lean_statement_is_rejected() {
        let mut o = order();
        o.statement = normalize_statement(b"theorem foo : True := by sorry").unwrap();
        o.statement_hash = statement_hash(Kind::LeanProof, &o.statement).unwrap();
        let e = o.check().unwrap_err();
        assert_eq!(e.code, ErrorCode::E_AXIOM_NOT_ALLOWED);
    }

    #[test]
    fn artifact_set_is_order_independent() {
        let a = ArtifactFile { path: "a.lean".to_string(), content_sha256: sha256(b"1") };
        let z = ArtifactFile { path: "z.lean".to_string(), content_sha256: sha256(b"2") };
        assert_eq!(
            artifact_set_hash(&[a.clone(), z.clone()]).unwrap(),
            artifact_set_hash(&[z.clone(), a.clone()]).unwrap()
        );
        assert_eq!(artifact_set_hash(&[a.clone(), a.clone()]).unwrap_err().code, ErrorCode::E_ARTIFACT_PATH);
        assert_eq!(artifact_set_hash(&[]).unwrap_err().code, ErrorCode::E_ARTIFACT_EMPTY);
        let bad = ArtifactFile { path: "../x".to_string(), content_sha256: sha256(b"1") };
        assert_eq!(artifact_set_hash(&[bad]).unwrap_err().code, ErrorCode::E_ARTIFACT_PATH);
    }

    #[test]
    fn receipt_json_is_key_ordered_and_float_free() {
        let o = order();
        let s = submission(&o);
        let r = receipt(&o, &s, Verdict::Pass, 9_000, vec!["propext".to_string()]);
        let j = String::from_utf8(r.canonical_json().unwrap()).unwrap();
        assert!(j.starts_with(r#"{"axioms":["propext"],"budget_ms":120000,"deterministic":true,"exit_code":0,"image_digest":"#));
        assert!(!j.contains("signature"), "подпись не входит в подписываемые байты");
        for key in ["budget_ms", "wall_clock_ms", "exit_code"] {
            let needle = format!("{}{}{}", '"', key, '"');
            let at = j.find(&needle).unwrap_or_else(|| panic!("нет ключа {key}: {j}"));
            let value: String = j[at..]
                .chars()
                .skip_while(|c| *c != ':')
                .skip(1)
                .take_while(|c| *c != ',' && *c != '}')
                .collect();
            assert!(!value.contains('.'), "{key} обязан быть целым: {value}");
        }
        let order = ["axioms", "budget_ms", "deterministic", "exit_code", "image_digest",
                     "order_ref", "stderr_sha256", "stdout_sha256", "submission_ref", "toolchain",
                     "verdict", "verifier_pubkey", "wall_clock_ms"];
        let mut prev = 0usize;
        for k in &order {
            let at = j.find(&format!("{}{}{}", '"', k, '"'))
                .unwrap_or_else(|| panic!("нет ключа {k}: {j}"));
            assert!(at > prev, "{k} идёт не по ASCII-порядку: {j}");
            prev = at;
        }
    }

    #[test]
    fn verdict_is_derivable_from_fields() {
        let o = order();
        let s = submission(&o);
        assert_eq!(receipt(&o, &s, Verdict::Pass, 9_000, vec![]).derive(&o).unwrap(), Verdict::Pass);
        assert_eq!(receipt(&o, &s, Verdict::Timeout, 121_001, vec![]).derive(&o).unwrap(), Verdict::Timeout);
        // Вердикт выводится из полей, а не из заявленного: заявленный fail при exit_code=0 даёт pass,
        // заявленный pass при exit_code≠0 — fail. Расхождение с заявленным ловит `is_valid_for`.
        let (sk, vk) = keypair(3);
        let mut claimed_fail = receipt(&o, &s, Verdict::Fail, 9_000, vec![]);
        claimed_fail.exit_code = 0;
        claimed_fail.sign(&sk);
        assert_eq!(claimed_fail.derive(&o).unwrap(), Verdict::Pass, "exit_code=0 даёт pass независимо от заявленного");
        assert!(!claimed_fail.is_valid_for(&o, &s, &vk), "выведенный pass против заявленного fail — квитанция не годна");
        let mut claimed_pass = receipt(&o, &s, Verdict::Pass, 9_000, vec![]);
        claimed_pass.exit_code = 2;
        claimed_pass.sign(&sk);
        assert_eq!(claimed_pass.derive(&o).unwrap(), Verdict::Fail, "заявленный pass при nonzero exit не выплачивается");
        assert!(!claimed_pass.is_valid_for(&o, &s, &vk), "расхождение заявленного и выведенного — не годная квитанция");
        assert!(!claimed_pass.payout_allowed(&o, &s, &vk, 1_800_003_000), "выплата по выведенному fail закрыта");
        let mut r = receipt(&o, &s, Verdict::Pass, 9_000, vec![]);
        r.image_digest = sha256("другой образ".as_bytes());
        assert_eq!(r.derive(&o).unwrap_err().code, ErrorCode::E_IMAGE_UNAVAILABLE);
        r = receipt(&o, &s, Verdict::Pass, 9_000, vec![]);
        r.budget_ms = 119_000;
        assert_eq!(r.derive(&o).unwrap_err().code, ErrorCode::E_ORDER_MALFORMED);
        r = receipt(&o, &s, Verdict::Pass, 9_000, vec![]);
        r.deterministic = false;
        assert_eq!(r.derive(&o).unwrap_err().code, ErrorCode::E_RECEIPT_INVALID);
        r = receipt(&o, &s, Verdict::Pass, 9_000, vec!["mine.private".to_string()]);
        assert_eq!(r.derive(&o).unwrap_err().code, ErrorCode::E_AXIOM_NOT_ALLOWED);
    }

    #[test]
    fn validity_requires_signature_digest_and_derived_verdict() {
        let o = order();
        let s = submission(&o);
        let (_, vk) = keypair(3);
        let good = receipt(&o, &s, Verdict::Pass, 9_000, vec!["Classical.choice".to_string()]);
        assert!(good.is_valid_for(&o, &s, &vk));
        assert!(good.payout_allowed(&o, &s, &vk, 1_800_003_000));
        let mut claimed_fail = good.clone();
        claimed_fail.verdict = Verdict::Fail;
        // подпись на битых байтах не проходит, поэтому и is_valid_for обязана отказать
        assert!(!claimed_fail.is_valid_for(&o, &s, &vk));
        let mut unsigned = good.clone();
        unsigned.signature = None;
        assert!(!unsigned.is_valid_for(&o, &s, &vk));
        let (_, stranger) = keypair(4);
        assert!(!good.is_valid_for(&o, &s, &stranger));
        let mut late_submit = s.clone();
        late_submit.created_at = o.deadline + 1;
        assert!(!good.payout_allowed(&o, &late_submit, &vk, o.deadline));
    }

    #[test]
    fn state_machine_is_total_over_the_matrix() {
        let mut to = 0usize;
        let mut err = 0usize;
        for s in ALL_STATES {
            for e in ALL_EVENTS {
                match step(s, e) {
                    Outcome::To(_) => to += 1,
                    Outcome::Error(_) => err += 1,
                }
            }
        }
        assert_eq!(to + err, ALL_STATES.len() * ALL_EVENTS.len(), "матрица заполнена целиком");
        assert_eq!(step(State::Published, Event::Unknown), Outcome::Error(ErrorCode::E_STATE_UNKNOWN));
        assert!(!State::Expired.terminal(), "expired ждёт возврата залога");
        assert!(State::Settled.terminal() && State::Rejected.terminal());
        assert_eq!(step(State::Passed, Event::Released), Outcome::To(State::Settled));
        assert_eq!(step(State::Failed, Event::Released), Outcome::Error(ErrorCode::E_VERDICT_MISMATCH));
        assert_eq!(step(State::Disputed, Event::VerdictGiven(Verdict::Pass)), Outcome::To(State::Passed));
    }

    #[test]
    fn every_error_code_has_a_defined_action() {
        for c in ErrorCode::all() {
            let _ = c.action().as_str();
            assert!(!c.as_str().is_empty());
        }
        assert_eq!(ErrorCode::all().len(), 18, "список кодов закрыт");
    }

    #[test]
    fn budget_overrun_with_zero_exit_is_a_field_contradiction() {
        let o = order();
        let s = submission(&o);
        // exit_code = 0 после потолка: «успех», которого не могло быть.
        let mut r = receipt(&o, &s, Verdict::Timeout, 121_000, vec![]);
        r.exit_code = 0;
        r.sign(&keypair(3).0);
        assert_eq!(r.derive(&o).unwrap_err().code, ErrorCode::E_BUDGET_EXCEEDED);
        // Тот же overrun при nonzero exit — это таймаут, выводимый из измеренных полей.
        let t = receipt(&o, &s, Verdict::Timeout, 121_000, vec![]);
        assert_eq!(t.derive(&o).unwrap(), Verdict::Timeout);
        assert!(t.is_valid_for(&o, &s, &keypair(3).1));
    }

    #[test]
    fn validate_names_the_reason_is_valid_for_hides() {
        let o = order();
        let s = submission(&o);
        let (sk, vk) = keypair(3);
        let mut unsigned = receipt(&o, &s, Verdict::Pass, 9_000, vec![]);
        unsigned.signature = None;
        assert_eq!(unsigned.validate(&o, &s, &vk).unwrap_err().code, ErrorCode::E_RECEIPT_UNSIGNED);
        let mut other_order = order();
        other_order.nonce += 1;
        assert_eq!(
            receipt(&o, &s, Verdict::Pass, 9_000, vec![]).validate(&other_order, &s, &vk).unwrap_err().code,
            ErrorCode::E_RECEIPT_INVALID
        );
        let mut stranger = receipt(&o, &s, Verdict::Pass, 9_000, vec![]);
        stranger.verifier_pubkey = *keypair(7).1.as_bytes();
        stranger.sign(&sk);
        assert_eq!(stranger.validate(&o, &s, &vk).unwrap_err().code, ErrorCode::E_RECEIPT_UNSIGNED);
        assert!(receipt(&o, &s, Verdict::Pass, 9_000, vec![]).validate(&o, &s, &vk).is_ok());
    }

    #[test]
    fn escrow_is_fail_closed_before_it_is_about_money() {
        let mut o = order();
        o.reward.asset = Asset::Token { chain_id: 8453, address: [0x11; 20] };
        let locked = EscrowState { chain_id: 8453, asset: o.reward.asset.clone(), amount: 1_000, status: EscrowStatus::Locked };
        // Пустой доверенный список v9: узел не наблюдает ни одной цепи — и не платит ни по чему.
        assert_eq!(check_escrow(&o, &locked, DEFAULT_TRUSTED_CHAINS).unwrap_err().code, ErrorCode::E_ESCROW_UNKNOWN);
        assert!(check_escrow(&o, &locked, &[8453]).is_ok());
        let mut thin = locked.clone();
        thin.amount = 999;
        assert_eq!(check_escrow(&o, &thin, &[8453]).unwrap_err().code, ErrorCode::E_ESCROW_INSUFFICIENT);
        let mut spent = locked.clone();
        spent.status = EscrowStatus::Released;
        assert_eq!(check_escrow(&o, &spent, &[8453]).unwrap_err().code, ErrorCode::E_REPLAY);
        let mut foreign = locked.clone();
        foreign.asset = Asset::Native;
        assert_eq!(check_escrow(&o, &foreign, &[8453]).unwrap_err().code, ErrorCode::E_UNSUPPORTED_ASSET);
        let mut wrong_chain = locked.clone();
        wrong_chain.chain_id = 1;
        assert_eq!(check_escrow(&o, &wrong_chain, &[8453]).unwrap_err().code, ErrorCode::E_ESCROW_UNKNOWN);
    }
}

