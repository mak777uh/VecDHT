//! Общий харнес и корпус проб двери для цикла `E-0095`.
//!
//! Каталог `tests/door_corpus/` не является отдельным test-таргетом: cargo собирает бинарники только
//! из файлов непосредственно в `tests/`, поэтому этот модуль подключается двумя файлами через
//! `#[path]`:
//!
//! * `door_reason_observable.rs` — свидетели дыры (провод и `errors`), обязаны быть зелёными и ДО,
//!   и ПОСЛЕ фикса: они и есть гейт совместимости (8);
//! * `door_reason_counters.rs` — гейты счётчика причин; он до фикса не компилируется, потому что
//!   зовёт `door_refusals()`, которого ещё нет.
//!
//! Корпус проб вынесен сюда, а не скопирован, по той же причине, по которой §5.1 требует один
//! кодек: два списка проб неминуемо разъезжаются, и «тот же корпус, что на PRE_FIX» перестаёт
//! значить что-либо. Разъезд проверяется числом — `dr_frame_digest` из первого файла обязан
//! совпасть с `dc_frame_digest` из второго.
//!
//! Всё, что здесь печатается и измеряется, — коды, длины, побайтовые свёртки и булевы решения.
//! Временем не меряется ничего: `dr_g2_steps` (число шагов до доставки отзыва) на двух прогонах
//! одного дерева дал 3 и 5, поэтому ни в вектор воспроизводимости, ни в таблицу ожиданий он не
//! входит (правило 7 пункт (е); урок `E-0091`, где вектор содержал счётчики, зависимые от
//! расписания).

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::{Multiaddr, PeerId};
use vecdht_artifact::reference_manifest;
use vecdht_crypto::cert::{sign_cert_identity, sign_revoke_identity};
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::{candidates, testing, Clock, ShardNode};
use vecdht_wire::cert::{NodeCert, CERT_VERSION, MAX_CERT_SHARDS};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{CertRevoke, Codec, Handshake, ProtocolError, Role};

pub const SHARD: u16 = 7;
/// Второй шард — им владеет сторона, рассылающая отзыв, чтобы её членство не пересекалось с дверью.
pub const SHARD_B: u16 = 9;
pub const SEEDS: [u8; 3] = [1, 2, 3];
pub const POW: u32 = 8;
/// Носитель проб: вне ростера, кредашиал выдаётся именно ему.
pub const PEER_SEED: u8 = 77;
/// Контроль годности DR_G3: другой транспорт, чтобы один PeerId не спор с самим собой.
pub const HEALTHY_SEED: u8 = 88;

/// Формулировки thiserror, которыми продукт уже описывает причину: `HandshakeError`
/// (`handshake.rs:31…52`) и `CertError` (`cert.rs:19…39`), дословно из атрибутов `#[error(...)]`
/// — список сверен с исходником, а не по памяти (урок `E-0094`: текст, которого нет в коде,
/// делает счётчик нулём по построению). Укорочены до уникальной подстроки там, где дальше идёт
/// интерполяция.
pub const CAUSE_WORDS: [&str; 20] = [
    "другая сеть: genesis_hash",
    "другая модель:",
    "другой preprocessing_version:",
    "не даёт права нести кредашиал",
    "обязана нести кредашиал",
    "кредашиал не разобран:",
    "кредашиал отвергнут:",
    "кредашиал выдан другому PeerId",
    "не совпал с ключом транспорта",
    "транспортный ключ не Ed25519",
    "protocol version",
    "genesis mismatch: cert says",
    "valid authority signatures, need",
    "not valid yet: now=",
    "expired: now=",
    "cert is revoked by nonce",
    "cert does not cover shard",
    "is not allowed here",
    "capacity is zero",
    "malformed cert bytes",
];

/// Причина, которой дверь отказывает данной пробе, — та самая формулировка из кода. `None` у проб,
/// у которых имя совпало бы с собственной жалобой инициатора («кредашиал не разобран: …» — и у
/// отказа, и у ответа-ошибки, который инициатор не может разобрать как `Handshake`), и у пробы
/// «мусор вместо кадра», где отказа на проводе нет вовсе. Такие пробы вне счётчика имён: иначе
/// прибор считал бы совпадение текста там, где проверяет наблюдаемость причины.
///
/// Столкновения ожидаемых причин — это факт кода, а не дефект списка: `cert_sigs_over` и
/// `cert_below_threshold` дают одну ветку (`cert.rs:140…141` переиспользует `BelowThreshold` для
/// «подписей больше предела»), `cert_from_after_until` и `cert_not_yet_valid` дают `NotYetValid`.
/// Гейт (4) требует, чтобы оба столкновения были видны в таблице, а не сглажены.
pub static PROBE_CAUSES: [(&str, Option<&str>); 20] = [
    ("cert_version", Some("protocol version")),
    ("cert_genesis", Some("genesis mismatch: cert says")),
    ("cert_zero_capacity", Some("capacity is zero")),
    ("cert_shards_over", Some("malformed cert bytes")),
    ("cert_not_yet_valid", Some("not valid yet: now=")),
    ("cert_expired", Some("expired: now=")),
    ("cert_below_threshold", Some("valid authority signatures, need")),
    ("cert_sigs_over", Some("valid authority signatures, need")),
    ("cert_from_after_until", Some("not valid yet: now=")),
    ("cert_other_peer_id", Some("кредашиал выдан другому PeerId")),
    ("cert_owner_mismatch", Some("не совпал с ключом транспорта")),
    ("cert_undecodable", None),
    ("cert_wrong_role", Some("is not allowed here")),
    ("agent_with_cert", Some("не даёт права нести кредашиал")),
    ("missing_cert", Some("обязана нести кредашиал")),
    ("hs_genesis", Some("другая сеть: genesis_hash")),
    ("hs_model", Some("другая модель:")),
    ("hs_preprocessing", Some("другой preprocessing_version:")),
    ("frame_bad_kind", Some("for frame kind")),
    ("junk_frame", None),
];

/// Строка корпуса для свёртки. Вынесена из тела теста сюда: `dr_frame_digest` и
/// `dc_frame_digest` обязаны сойтись байт в байт, а два отдельных `format!` разъезжаются ровно так
/// же, как разъехались два скопированных корпуса (гейт (5) цикла `E-0095`).
pub fn refusal_row(label: &str, code: &str, retry_after_ms: u32, shard: u16, raw: &[u8]) -> String {
    format!("{label}={code}:{retry_after_ms}:{shard}:{}", hex::encode(raw))
}

/// Строка молчаливой пробы: отказа на проводе нет, и в свёртку идёт не кадр, а само молчание.
pub fn silent_row(label: &str) -> String {
    format!("{label}=без-ответа")
}

/// Имя причины, которым дверь обязана записать данную пробу (`DoorReason::name()`). `None` — у
/// пробы `junk_frame`: её отбивает транспортный кодек до `on_request`, и записи на двери быть не
/// должно вовсе.
///
/// Таблица заведена здесь, а не в файле счётчиков, по той же причине, что и корпус: два независимых
/// списка проб и их имён неминуемо разъезжаются, и `счётчик сошёлся с числом отказов` превращается
/// в пересказ самого себя.
///
/// Первая редакция таблицы была выведена из кода верификатора и ошиблась в пяти пробах: часть
/// причин отсекает сам декодер кредашиала. Замороженные значения этого не отменяют — расхождение
/// напечатано отдельным фактом и вошло в `ДИАГНОЗ` (`lab/expectations/e0095.tsv` правке внутри
/// замерного цикла не подлежит).
pub static PROBE_REASONS: [(&str, Option<&str>); 20] = [
    // Пять проб переатрибутированы ПО ЗАМЕРУ, а не по assumption (ДИАГНОЗ цикла): их отбивает
    // `NodeCert::decode` раньше верификатора — `cert.rs:78…80` версия, `:86…88` `MAX_CERT_SHARDS`,
    // `:102…104` число подписей > 16, `:110…112` `valid_until <= valid_from`. Имя у них общее:
    // общим именем `cert_undecodable`. Ветки `cert.rs:140…141` («подписей больше предела» =
    // `BelowThreshold`) и `valid_from > valid_until` = `NotYetValid` с провода недостижимы.
    ("cert_version", Some("cert_undecodable")),
    ("cert_genesis", Some("cert_genesis_mismatch")),
    ("cert_zero_capacity", Some("cert_zero_capacity")),
    ("cert_shards_over", Some("cert_undecodable")),
    ("cert_not_yet_valid", Some("cert_not_yet_valid")),
    ("cert_expired", Some("cert_expired")),
    ("cert_below_threshold", Some("cert_below_threshold")),
    ("cert_sigs_over", Some("cert_undecodable")),
    ("cert_from_after_until", Some("cert_undecodable")),
    ("cert_other_peer_id", Some("cert_peer_id_mismatch")),
    ("cert_owner_mismatch", Some("cert_owner_mismatch")),
    ("cert_undecodable", Some("cert_undecodable")),
    ("cert_wrong_role", Some("cert_wrong_role")),
    ("agent_with_cert", Some("agent_with_cert")),
    ("missing_cert", Some("missing_cert")),
    ("hs_genesis", Some("genesis_mismatch")),
    ("hs_model", Some("model_mismatch")),
    ("hs_preprocessing", Some("preprocessing_mismatch")),
    ("frame_bad_kind", Some("frame_undecodable")),
    ("junk_frame", None),
];

pub fn probe_reason_name(label: &str) -> Option<&'static str> {
    PROBE_REASONS
        .iter()
        .find(|(l, _)| *l == label)
        .and_then(|(_, r)| *r)
}

pub fn probe_cause(label: &str) -> Option<&'static str> {
    PROBE_CAUSES
        .iter()
        .find(|(l, _)| *l == label)
        .and_then(|(_, c)| *c)
}

pub fn dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("vecdht-e0095-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("временный каталог теста");
    p
}

/// Каталог с `Drop`-гардом (урок `E-0085` ДИАГНОЗ-2 и `E-0094`: `dir()` без гарда оставил
/// осевшие каталоги, и гейт конечности мерил себя, а не продукт).
pub struct TmpDir(PathBuf);

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl TmpDir {
    pub fn new(name: &str) -> Self {
        Self(dir(name))
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

pub fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

pub fn cfg(listen: Multiaddr) -> NetConfig {
    NetConfig {
        listen: vec![listen],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-e0095/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
        revoked_dir: None,
    }
}

pub fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

/// Primary шарда по порядку §9.3: узел выводит его из ростера, тест не вправе назначить primary
/// первым сидом — иначе на его месте оказался бы `NOT_OWNER`, а не проверяемая причина.
pub fn primary_seed(shard: u16) -> u8 {
    let order = candidates::ordered(1, shard, &testing::holders(&SEEDS));
    *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("primary — один из тестовых сидов")
}

pub fn index_service(seed: u8, shard: u16, dir: &Path, listen: Multiaddr) -> NetService {
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let mut node = ShardNode::open(
        dir,
        shard,
        id.clone(),
        peer.to_bytes(),
        testing::params(POW),
        testing::authority_set(),
        testing::holders(&SEEDS),
    )
    .expect("открыть узел шарда");
    let now_bucket = Clock::at(now_sec()).bucket;
    node.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(shard, &SEEDS, 0)),
        testing::clock(now_bucket),
    )
    .expect("genesis");
    let cert = testing::node_cert(seed, peer.to_bytes(), vec![shard], Role::IndexNode, 0, u32::MAX);
    NetService::new(
        id,
        Role::IndexNode,
        Some(cert),
        vec![node],
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис узла")
}

pub fn agent_service(seed: u8, listen: Multiaddr) -> NetService {
    NetService::new(
        testing::identity(seed),
        Role::Agent,
        None,
        Vec::new(),
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис агента")
}

/// Узел с кредашиалом произвольной формы: роли узла, шардов не держит — «просроченный сам» для
/// гейта DR_G3.
pub fn raw_cert_service(seed: u8, listen: Multiaddr, cert: NodeCert) -> NetService {
    NetService::new(
        testing::identity(seed),
        Role::IndexNode,
        Some(cert),
        Vec::new(),
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис с кредашиалом")
}

pub async fn wait_listen(s: &mut NetService) -> Multiaddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(a) = s.listen_addrs().first() {
            return a.clone();
        }
        assert!(tokio::time::Instant::now() < deadline, "listener не поднялся за 10 с");
        s.step().await;
    }
}

pub async fn pump_until<F>(a: &mut NetService, b: &mut NetService, mut done: F)
where
    F: FnMut(&NetService, &NetService) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !done(a, b) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "состояние не наступило за 30 с; ошибки A={:?} B={:?}",
            a.take_errors(),
            b.take_errors()
        );
        a.step().await;
        b.step().await;
    }
}

/// Приветствие двери с заданными полями заголовка и произвольными байтами кредашиала. По умолчанию
/// всё корректно, чтобы отказ был именно по тому, что испорчено в пробе.
pub fn greeting(role: Role, cert_bytes: Vec<u8>, genesis_hash: [u8; 32], model: &str, prep: u16) -> Vec<u8> {
    Handshake {
        role,
        preprocessing_version: prep,
        model_version: model.to_string(),
        genesis_hash,
        cert: cert_bytes,
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

pub fn cert_bytes(c: &NodeCert) -> Vec<u8> {
    c.encode()
}

pub fn good_greeting(role: Role, cert: Option<&NodeCert>) -> Vec<u8> {
    greeting(
        role,
        cert.map(cert_bytes).unwrap_or_default(),
        testing::genesis_hash(),
        &reference_manifest().model_version,
        testing::PREPROCESSING_VERSION,
    )
}

/// Отправить кадр и дождаться первого `Error`: (код, `retry_after_ms`, `шард`, сырые байты кадра).
/// Байты нужны гейту побайтового совпадения: «провода не касались» доказывается длиной и свёрткой,
/// а не обещанием.
pub async fn ask_error(
    node: &mut NetService,
    peer: &mut NetService,
    target: PeerId,
    frame: Vec<u8>,
    label: &str,
) -> Option<(String, u32, u16, Vec<u8>)> {
    let _ = peer.take_inbox();
    assert!(peer.send_frame(target, frame), "{label}: пир не может отправить кадр");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut frames: Vec<(PeerId, Vec<u8>)> = Vec::new();
    while tokio::time::Instant::now() < deadline {
        node.step().await;
        peer.step().await;
        frames.extend(peer.take_inbox());
        if let Some((_, raw)) = frames
            .iter()
            .find(|(_, f)| decode_frame(f).is_ok_and(|k| k.header.kind == Kind::Error))
        {
            let e = ProtocolError::decode(raw).expect("кадр Error разобрался");
            return Some((e.code, e.retry_after_ms, e.shard, raw.clone()));
        }
    }
    None
}

pub fn base_cert(peer: PeerId) -> NodeCert {
    testing::node_cert(PEER_SEED, peer.to_bytes(), vec![SHARD], Role::IndexNode, 0, u32::MAX)
}

/// Переподписать тело порогом: изменённое поле без переподписи дало бы отказ по подписи, а не по
/// этому полю (`E-0085`, тот же приём).
pub fn resign(mut c: NodeCert) -> NodeCert {
    c.authority_sigs.clear();
    for a in testing::authorities().iter().take(testing::authority_set().threshold) {
        c = sign_cert_identity(&c, a);
    }
    c
}

pub fn revoke_for(nonce: [u8; 16]) -> CertRevoke {
    let mut r = CertRevoke {
        nonce,
        revoked_at: now_sec() as u32,
        reason: "e0095".to_string(),
        authority_sigs: Vec::new(),
    };
    for a in testing::authorities().iter().take(testing::authority_set().threshold) {
        r = sign_revoke_identity(&r, a);
    }
    r
}

/// Сколько записей стороны содержат ХОТЬ ОДНО имя причины из `CAUSE_WORDS`.
pub fn cause_records(records: &[String]) -> usize {
    records
        .iter()
        .filter(|r| CAUSE_WORDS.iter().any(|w| r.contains(w)))
        .count()
}

/// Названа ли в записях стороны ИМЕННО та причина, которой дверь отказала данной пробе.
pub fn names_cause(records: &[String], cause: &str) -> bool {
    records.iter().any(|r| r.contains(cause))
}

pub fn digest(rows: &[String]) -> String {
    hex::encode(vecdht_crypto::ids::content_hash(rows.join("\n").as_bytes()))
}

/// Набор кодов — для печатной строки сравнения: порядок задаёт `BTreeSet`, поэтому строка
/// инвариантна к порядку проб.
pub fn code_set(codes: &BTreeSet<String>) -> String {
    codes.iter().cloned().collect::<Vec<_>>().join(",")
}

/// Корпус из двадцати проб к живой двери. Один список на оба файла приборов — см. шапку модуля.
///
/// Состав: двенадцать кредашиальных причин (из них две пары заведомо дают одну и ту же ветку кода),
/// четыре причины заголовка, роль и комплект («агент с кредашиалом», «узлу кредашиала не досталось»),
/// один кадр с незнакомым видом (`BAD_ENUM`) — итого девятнадцать отказов; двадцатая проба «мусор
/// вместо кадра» отказа на проводе не получает вообще, ей отвечает молчание: её отбивает
/// `FrameCodec::read_request` (`codec.rs:221…227`) ещё до `on_request`.
pub fn probe_corpus(agent_peer: PeerId) -> Vec<(&'static str, Vec<u8>)> {
    let ap = agent_peer;
    let now = now_sec() as u32;
    let c_version = {
        let mut c = base_cert(ap);
        c.version = CERT_VERSION + 1;
        resign(c)
    };
    let c_genesis = {
        let mut c = base_cert(ap);
        c.genesis_hash = [9u8; 32];
        resign(c)
    };
    let c_capacity = {
        let mut c = base_cert(ap);
        c.capacity_entries = 0;
        resign(c)
    };
    let c_shards = {
        let mut c = base_cert(ap);
        c.shards = (0..=(MAX_CERT_SHARDS as u16)).collect();
        resign(c)
    };
    let c_notyet = testing::node_cert(
        PEER_SEED,
        ap.to_bytes(),
        vec![SHARD],
        Role::IndexNode,
        now + 3_600,
        now + 7_200,
    );
    let c_expired = testing::node_cert(
        PEER_SEED,
        ap.to_bytes(),
        vec![SHARD],
        Role::IndexNode,
        0,
        now - 1,
    );
    let c_few_sigs = {
        let mut c = base_cert(ap);
        c.authority_sigs.truncate(testing::authority_set().threshold - 1);
        c
    };
    let c_many_sigs = {
        let mut c = base_cert(ap);
        while c.authority_sigs.len() < 17 {
            c.authority_sigs.push([0xeeu8; 64]);
        }
        c
    };
    let c_time_order = {
        let mut c = base_cert(ap);
        c.valid_from = now + 3_600;
        c.valid_until = now;
        resign(c)
    };
    let c_other_peer = testing::node_cert(
        PEER_SEED,
        vec![0u8; 32],
        vec![SHARD],
        Role::IndexNode,
        0,
        u32::MAX,
    );
    let c_owner_mismatch = {
        // Кредашиал на этом транспорте, но `owner_ed25519` — другой ключ: порог подписывает
        // тело корректно, отказ обязан быть именно по владельцу.
        let mut c = base_cert(ap);
        c.owner_ed25519 = testing::identity(11).pubkey();
        resign(c)
    };
    let c_wrong_role = {
        // Заголовок говорит «IndexNode», кредашиал подписан как «Agent»: `verify_cert` роли не
        // смотрит, расхождение ловит `handshake.rs:152…158` -> `CertRejected(WrongRole)`.
        let mut c = base_cert(ap);
        c.role = Role::Agent;
        resign(c)
    };
    let mut junk_cert = base_cert(ap).encode();
    junk_cert.truncate(4);
    let model = reference_manifest().model_version.clone();

    vec![
        ("cert_version", good_greeting(Role::IndexNode, Some(&c_version))),
        ("cert_genesis", good_greeting(Role::IndexNode, Some(&c_genesis))),
        ("cert_zero_capacity", good_greeting(Role::IndexNode, Some(&c_capacity))),
        ("cert_shards_over", good_greeting(Role::IndexNode, Some(&c_shards))),
        ("cert_not_yet_valid", good_greeting(Role::IndexNode, Some(&c_notyet))),
        ("cert_expired", good_greeting(Role::IndexNode, Some(&c_expired))),
        ("cert_below_threshold", good_greeting(Role::IndexNode, Some(&c_few_sigs))),
        ("cert_sigs_over", good_greeting(Role::IndexNode, Some(&c_many_sigs))),
        ("cert_from_after_until", good_greeting(Role::IndexNode, Some(&c_time_order))),
        ("cert_other_peer_id", good_greeting(Role::IndexNode, Some(&c_other_peer))),
        ("cert_owner_mismatch", good_greeting(Role::IndexNode, Some(&c_owner_mismatch))),
        (
            "cert_undecodable",
            greeting(
                Role::IndexNode,
                junk_cert.clone(),
                testing::genesis_hash(),
                &model,
                testing::PREPROCESSING_VERSION,
            ),
        ),
        ("cert_wrong_role", good_greeting(Role::IndexNode, Some(&c_wrong_role))),
        ("agent_with_cert", good_greeting(Role::Agent, Some(&base_cert(ap)))),
        ("missing_cert", good_greeting(Role::IndexNode, None)),
        (
            "hs_genesis",
            greeting(Role::IndexNode, cert_bytes(&base_cert(ap)), [7u8; 32], &model, testing::PREPROCESSING_VERSION),
        ),
        (
            "hs_model",
            greeting(
                Role::IndexNode,
                cert_bytes(&base_cert(ap)),
                testing::genesis_hash(),
                "0.0.0-e0095",
                testing::PREPROCESSING_VERSION,
            ),
        ),
        (
            "hs_preprocessing",
            greeting(
                Role::IndexNode,
                cert_bytes(&base_cert(ap)),
                testing::genesis_hash(),
                &model,
                testing::PREPROCESSING_VERSION ^ 0x5a5a,
            ),
        ),
        // Контроль различимости: у этой пробы код иной уже сегодня.
        // Кадр с геометрией, которой кодек не откажет, но с незнакомым видом: это единственный
        // способ дойти до ветки `BAD_ENUM` в `on_request` (service.rs:647) — мусор ниже по
        // проводам отбивает сам `FrameCodec::read_request` и до двери не доходит вовсе.
        ("frame_bad_kind", vec![0x99, vecdht_wire::frame::PROTOCOL_VERSION, 0, 0, 0, 0, 0, 0]),
        ("junk_frame", vec![0xf7u8; 24]),
    ]
}
