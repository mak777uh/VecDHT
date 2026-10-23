//! Оракул `H-0094`/`E-0094` — релиз-блокер (4), часть A из `ADR-0044`: переживаемость отзыва
//! кредашиала перезапуском процесса.
//!
//! Дыра измерена чтением кода, а не памятью (`lab/hypotheses/H-0094-…md`, раздел «Что уже известно
//! из разведки»): `revoked: BTreeSet<[u8; 16]>` создаётся пустым в `NetService::new`
//! (`service.rs:143`, `:277`) и никогда не кладётся на диск, а `self_revoked` сбрасывается в
//! `false`. Обещание §11.4/§4.2 «отзыв необратим» и §9.8 «узел после отзыва своего кредашиала
//! молчит» поэтому живут ровно до первого рестарта: (а) узел, отказавший отозванному пиру, после
//! перезапуска принимает его снова; (б) узел, собственный кредашиал которого отозван, после
//! перезапуска возобновляет обслуживание.
//!
//! Форма фактов — булевы решения двери, длина множества и размер файла: ни один гейт не зависит от
//! часов и от порядка шагов (правило 7, пункт (е)), поэтому весь вектор обязан совпасть в двух
//! прогонах на неизменном дереве. Время в этом файле — только дедлайны ожидания, они в вектор не
//! входят и печатаются как факт, а не как проверка.
//!
//! Границы оракула, названные до заморозки.
//!
//! * Рестарт здесь — пересоздание `NetService` с тем же каталогом состояния в том же процессе, а не
//!   смена ОС-процесса. Из такого замера следует «состояние читается с диска», если второй экземпляр
//!   действительно поднимает его из файла (гейты (2) и (4) сверяют с этим числом записей в файле), и
//!   не следует «переживает гибель машины» — тот же оговоркой ограничена правка `E-0092`.
//! * Узел, созданный в **другом** каталоге, остаётся в неведении: подписка на `CONTROL_TOPIC`
//!   истории не имеет. Гейт (10) карточки называет это числом, а не обещанием.
//! * У отзыва нет производителя в продукте (`publish_revoke` не вызывается ни одним файлом, кроме
//!   тестов) — это Batch C и `OPEN-QUESTIONS` п. 45, здесь проверяется переживаемость уже
//!   исполненного отзыва.
//!
//! Исполнимость на дереве ДО правки. Гейты (1)…(4) этого файла используют только существующий API,
//! поэтому PRE_FIX доходит до всех четырёх и печатает вектор дыры. Гейты переживаемости, предела и
//! битого файла приходят вместе с фиксом: параметра каталога состояния ещё нет, и попытка их
//! написать — ошибка компиляции, а не красный тест; этот факт helper снимает как
//! `pre_fix_compile=1` и складывает в `lab/logs/e0094-oracle-before-fix.txt`.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use vecdht_artifact::reference_manifest;
use vecdht_crypto::cert::sign_revoke_identity;
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::{candidates, testing, ShardNode};
use vecdht_wire::frame::Kind;
use vecdht_wire::messages::{domain, CertRevoke, Codec, Role};

const SHARD: u16 = 7;
/// Шард наблюдателя: другой, чем у носителя отзыва, чтобы членство и провайдер-записи не
/// пересекались (та же пара, что в стенде `E-0085`).
const SHARD_B: u16 = 9;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
/// Носитель отозванного кредашиала. Его `nonce` — `[seed; 16]` (`testing::node_cert`), поэтому
/// отзыв ровно этого ключа собирается прямо из сида.
const CARRIER_SEED: u8 = 2;
/// Наблюдатель, у которого стоит дверь. Обязан быть другой личностью, чем носитель.
const WATCHER_SEED: u8 = 3;
/// Чистые пиры стенда молчания: не участвуют в отзыве и служат меркой «узел жив». Сиды взяты
/// вне пары носитель/наблюдатель, чтобы `PeerId` не пересекался.
const FRESH_SEED: u8 = 1;
const FRESH2_SEED: u8 = 77;
/// Агент, чей кадр публикуется в gossip: нужен только чтобы было что отправлять, когда узел
/// «замолчал». Личность произвольная, главное — не участник ростера шардов стенда.
const AGENT_SEED: u8 = 77;
/// Имя файла состояния отзыва. Здесь это предсказание оракула, а не константа продукта: если фикс
/// выберет другое имя, гейт (2) упадёт и это будет фактом цикла, а не поводом править тест.
const FILE: &str = "revocation.bin";
/// Цена переживаемости: заголовок 8 magic + 2 версия + 4 количество + 4 tag и ровно 16 байт на
/// `nonce`. Число зафиксировано карточкой до пре-регистрации.
const HEADER: u64 = 18;

/// Каталог удаляется при выходе из области видимости: PRE_FIX паникует в конце тела, и ручной
/// `remove` последней строкой оставил бы мусор — дефект метода из `E-0085` ДИАГНОЗ-2.
struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Tmp {
    /// Новый каталог. `fresh = false` — оставить то, что на диске: ровно это и называется
    /// «перезапуск с тем же хранилищем».
    fn new(tag: &str, fresh: bool) -> Self {
        let p = std::env::temp_dir().join(format!("vecdht-e0094-{}-{tag}", std::process::id()));
        if fresh {
            let _ = std::fs::remove_dir_all(&p);
        }
        std::fs::create_dir_all(&p).expect("временный каталог теста");
        Self(p)
    }
}

/// Сколько байт занимает файл состояния в каталоге; 0 — файла нет. Поиск по префиксу имени, а не
/// по константе продукта: на дереве до правки такого файла не существует, и оракул обязан это
/// померить, а не не компилироваться.
fn state_file_bytes(dir: &Path) -> u64 {
    let p = dir.join(FILE);
    std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
}

fn now_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("часы после эпохи")
        .as_secs()
}

fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

/// Конфигурация стенда: тот же набор, что у `E-0085`, с коротким `poll_interval` — он входит в
/// цену ожидания, но не в пороги.
fn cfg(listen: Multiaddr) -> NetConfig {
    NetConfig {
        listen: vec![listen],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-e0094/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
    }
}

/// Узел шарда, у которого состояние отзыва ищется в каталоге `dir`: тот же харнес, что у стенда
/// отзывов `E-0085` (genesis-эпоха, кредашиал `0..u32::MAX`, один держимый шард).
fn index_service_shard(seed: u8, shard: u16, dir: &Path, listen: Multiaddr) -> NetService {
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
    node.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(shard, &SEEDS, 0)),
        testing::clock(0),
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

async fn wait_listen(s: &mut NetService) -> Multiaddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(a) = s.listen_addrs().first() {
            return a.clone();
        }
        assert!(tokio::time::Instant::now() < deadline, "listener не поднялся за 10 с");
        s.step().await;
    }
}

async fn pump_until<F>(a: &mut NetService, b: &mut NetService, mut done: F)
where
    F: FnMut(&NetService, &NetService) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        if done(a, b) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "состояние не наступило за 40 с; ошибки A={:?} B={:?}",
            a.take_errors(),
            b.take_errors()
        );
        a.step().await;
        b.step().await;
    }
}

/// Пауза фиксированной длины в шагах event loop: используется там, где ожидаемый исход —
/// «ничего не происходит», и ждать надо ровно столько, сколько хватает на наступление обратного.
async fn settle(a: &mut NetService, b: &mut NetService, secs: u64) {
    let until = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < until {
        a.step().await;
        b.step().await;
    }
}

fn revoke_for(nonce: [u8; 16]) -> CertRevoke {
    let mut r = CertRevoke {
        nonce,
        revoked_at: now_sec() as u32,
        reason: "E-0094: переживаемость отзыва".to_string(),
        authority_sigs: Vec::new(),
    };
    for a in testing::authorities()
        .iter()
        .take(testing::authority_set().threshold)
    {
        r = sign_revoke_identity(&r, a);
    }
    r
}

/// Подписанный кадр `Publish` агента — payload для `publish_gossip`: у «молчания» узла обязан быть
/// измеряемый объект, и это не `send_frame` (без пира он падает по транспорту, а не по отзыву).
fn signed_publish(bucket: u32) -> Vec<u8> {
    let agent = testing::identity(AGENT_SEED);
    let spec = testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(3),
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch: 1,
        published_bucket: bucket,
        ttl_buckets: 225,
        bits: POW,
    };
    let msg = spec.msg(Vec::new());
    let sig = agent.sign_body(domain::PUBLISH, Kind::Publish, &msg.body_bytes());
    msg.encode_signed(&sig)
}

/// Primary шарда по порядку §9.3: узел выводит его из ростера, и тест не вправе назначить primary
/// первым сидом — иначе публикация получила бы `NOT_OWNER`. Стенду этот факт нужен только как
/// контроль идентификаторов, поэтому функция вызывается в ассерте сборки.
fn primary_seed(shard: u16) -> u8 {
    let order = candidates::ordered(1, shard, &testing::holders(&SEEDS));
    *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("primary — один из тестовых сидов")
}

#[test]
fn revoked_peer_is_refused_before_restart_and_accepted_after_it() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut bad: Vec<String> = Vec::new();
        let nonce = [CARRIER_SEED; 16];
        let dc = Tmp::new("carrier", true);
        let dw = Tmp::new("watcher", true);

        // Сборка стенда: носитель и наблюдатель, настоящий QUIC на loopback.
        let mut carrier = index_service_shard(CARRIER_SEED, SHARD, &dc.0, quic_addr());
        let mut watcher = index_service_shard(WATCHER_SEED, SHARD_B, &dw.0, quic_addr());
        let _ca = wait_listen(&mut carrier).await;
        let wa = wait_listen(&mut watcher).await;
        carrier.dial(wa.clone()).expect("dial наблюдателя");
        let (cp, wp) = (carrier.peer_id(), watcher.peer_id());
        assert_ne!(cp, wp, "(О10) узел и наблюдатель — одна личность, стенд невозможно собрать");
        // Порядок §9.3 печатается как факт стенда, гейтом не является: отзыв проверяется дверью,
        // а не правом подписывать кадры членства.
        let (p7, p9) = (primary_seed(SHARD), primary_seed(SHARD_B));
        println!(
            "RV_G0: rv_g0_primary_shard7={p7} rv_g0_primary_shard9={p9} rv_g0_carrier={CARRIER_SEED} \
             rv_g0_watcher={WATCHER_SEED}"
        );
        pump_until(&mut carrier, &mut watcher, |x, y| {
            x.is_authenticated(&wp) && y.is_authenticated(&cp)
        })
        .await;

        // Отзыв доходит: носитель рассылает его о собственном ключе (gossip не возвращает
        // сообщение отправителю, поэтому сам носитель о своём отзыве ещё не знает).
        let revoke = revoke_for(nonce);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        while !(watcher.revocation_count() == 1 && watcher.is_revoked_nonce(&nonce)) {
            assert!(tokio::time::Instant::now() < deadline, "(О10) отзыв не дошёл за 40 с");
            let _ = carrier.publish_revoke(&revoke);
            carrier.step().await;
            watcher.step().await;
        }
        let count_before = watcher.revocation_count();
        let file_before = state_file_bytes(&dw.0);
        println!(
            "RV_G1: rv_g1_count_before={count_before} rv_g1_file_before={file_before} \
             rv_g1_carrier_knows={}",
            if carrier.is_revoked_nonce(&nonce) { 1 } else { 0 }
        );
        if (count_before, file_before) != (1, HEADER + 16) {
            bad.push(format!(
                "(1) состояние отзыва до рестарта: ожидалось count=1 file={} получено count={count_before} file={file_before}",
                HEADER + 16
            ));
        }

        // Дверь отказывает до рестарта: соединение сброшено применённым отзывом, и повторный
        // дозвон не приводит к аутентификации.
        settle(&mut carrier, &mut watcher, 2).await;
        carrier.dial(wa.clone()).expect("повторный dial наблюдателя");
        settle(&mut carrier, &mut watcher, 6).await;
        let denied_before_restart = !watcher.is_authenticated(&cp);
        println!(
            "RV_G1b: rv_g1b_denied_before_restart={}",
            if denied_before_restart { 1 } else { 0 }
        );
        if !denied_before_restart {
            bad.push("(1) не выполнен: дверь не отказывает отозванному пиру до рестарта".to_string());
        }

        // Перезапуск наблюдателя: тот же каталог, тот же сид, новый `NetService`.
        let wa_addr_old = wa.clone();
        drop(watcher);
        let mut watcher2 = index_service_shard(WATCHER_SEED, SHARD_B, &dw.0, quic_addr());
        let wa2 = wait_listen(&mut watcher2).await;
        let count_after = watcher2.revocation_count();
        let knows_after = watcher2.is_revoked_nonce(&nonce);
        let file_after = state_file_bytes(&dw.0);
        println!(
            "RV_G2: rv_g2_count_after={count_after} rv_g2_knows_after={knows_after} \
             rv_g2_file_after={file_after} rv_g2_addr_changed={}",
            if wa_addr_old != wa2 { 1 } else { 0 }
        );

        // И следствие для двери: принимает ли перезапущенный наблюдатель тот же отозванный пир.
        carrier.dial(wa2.clone()).expect("dial перезапущенного наблюдателя");
        settle(&mut carrier, &mut watcher2, 8).await;
        let accepted = watcher2.is_authenticated(&cp);
        let carrier_self_revoked = carrier.is_self_revoked();
        println!(
            "RV_G3: rv_g3_accepted_after_restart={} rv_g3_carrier_self_revoked={} \
             rv_g3_watcher2_count={}",
            if accepted { 1 } else { 0 },
            if carrier_self_revoked { 1 } else { 0 },
            watcher2.revocation_count()
        );
        if accepted {
            bad.push("(2) не выполнен: перезапущенный наблюдитель принял отозванный кредашиал".to_string());
        }
        if count_after != 1 || !knows_after {
            bad.push("(2) не выполнен: множество отзывов не поднято с диска".to_string());
        }
        if file_after != file_before {
            bad.push(format!(
                "(2) не выполнен: размер файла состояния изменился без нового отзыва: было {file_before}, стало {file_after}"
            ));
        }

        // Граница (10): узел в ДРУГОМ каталоге остаётся в неведении — подписка на control-тему
        // истории не имеет, и фикс этого не меняет.
        let dw3 = Tmp::new("watcher-fresh", true);
        let mut watcher3 = index_service_shard(WATCHER_SEED, SHARD_B, &dw3.0, quic_addr());
        let _ = wait_listen(&mut watcher3).await;
        let fresh_knows = watcher3.is_revoked_nonce(&nonce);
        println!(
            "RV_G4: rv_g4_fresh_dir_knows={} rv_g4_fresh_dir_count={} rv_g4_fresh_file={}",
            if fresh_knows { 1 } else { 0 },
            watcher3.revocation_count(),
            state_file_bytes(&dw3.0)
        );
        if fresh_knows {
            bad.push("(10) не выполнен: свежий каталог «знает» отзыв, которого там не было — стенд сломан".to_string());
        }

        drop(watcher3);
        drop(watcher2);
        drop(carrier);
        assert!(bad.is_empty(), "гейты не выполнены: {bad:?}");
    });
}

#[test]
fn self_revoked_silence_survives_restart() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut bad: Vec<String> = Vec::new();
        let nonce = [CARRIER_SEED; 16];
        let dc = Tmp::new("self-carrier", true);
        let dc3 = Tmp::new("self-carrier-fresh", true);
        let dw = Tmp::new("self-watcher", true);
        let df = Tmp::new("self-fresh", true);
        let df2 = Tmp::new("self-fresh-2", true);

        let mut carrier = index_service_shard(CARRIER_SEED, SHARD, &dc.0, quic_addr());
        let mut watcher = index_service_shard(WATCHER_SEED, SHARD_B, &dw.0, quic_addr());
        let mut fresh = index_service_shard(FRESH_SEED, SHARD, &df.0, quic_addr());
        let mut fresh2 = index_service_shard(FRESH2_SEED, SHARD, &df2.0, quic_addr());
        let _ca = wait_listen(&mut carrier).await;
        let wa = wait_listen(&mut watcher).await;
        let fa = wait_listen(&mut fresh).await;
        let _fa2 = wait_listen(&mut fresh2).await;

        // Носитель замолкает: наблюдатель рассылает отзыв о его ключе, пока носитель его не
        // примет.
        carrier.dial(wa).expect("dial наблюдателя");
        pump_until(&mut carrier, &mut watcher, |x, y| {
            x.is_authenticated(&y.peer_id()) && y.is_authenticated(&x.peer_id())
        })
        .await;
        let revoke = revoke_for(nonce);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        while !carrier.is_self_revoked() {
            assert!(tokio::time::Instant::now() < deadline, "(О10) отзыв о себе не дошёл");
            let _ = watcher.publish_revoke(&revoke);
            carrier.step().await;
            watcher.step().await;
        }
        // Живое молчание до рестарта. `send_frame` проверяет `self_revoked` раньше, чем таблицу
        // пиров, поэтому он измерим без соединения. `publish_gossip` в гейт не входит: без
        // mesh-пиров он падает по своей причине (`InsufficientPeers`), и первый PRE_FIX это
        // показал — контроль на чистом каталоге давал то же самое, что и отозванный узел.
        let silent_send = !carrier.send_frame(watcher.peer_id(), signed_publish(0));
        let self_revoked_live = carrier.is_self_revoked();
        let file_before = state_file_bytes(&dc.0);
        println!(
            "RV_G5: rv_g5_self_revoked={} rv_g5_silent_send={} rv_g5_count={} \
             rv_g5_file_before={file_before}",
            if self_revoked_live { 1 } else { 0 },
            if silent_send { 1 } else { 0 },
            carrier.revocation_count()
        );
        if !silent_send || !self_revoked_live {
            bad.push("(3) не выполнен: отозванный узел не замолчал — стенд иной, чем заявлено".to_string());
        }

        // Перезапуск носителя: тот же каталог, тот же сид. Молчание меряется живым рукопожатием с
        // чистим пиром: здоровый узел обязан аутентифицироваться, молчащий — нет.
        let cp2 = carrier.peer_id();
        drop(carrier);
        let mut carrier2 = index_service_shard(CARRIER_SEED, SHARD, &dc.0, quic_addr());
        let _ = wait_listen(&mut carrier2).await;
        let fp = fresh.peer_id();
        carrier2.dial(fa).expect("dial чистого пира после рестарта");
        settle(&mut carrier2, &mut fresh, 12).await;
        let self_revoked_after = carrier2.is_self_revoked();
        let served = carrier2.is_authenticated(&fp);
        let peer_agrees = fresh.is_authenticated(&cp2);
        let load_errors = carrier2
            .take_errors()
            .iter()
            .filter(|e| e.contains("отозван"))
            .count();
        println!(
            "RV_G6: rv_g6_self_revoked_after={} rv_g6_serves_after_restart={} \
             rv_g6_peer_agrees={} rv_g6_count_after={} rv_g6_file_after={} rv_g6_load_errors={load_errors}",
            if self_revoked_after { 1 } else { 0 },
            if served { 1 } else { 0 },
            if peer_agrees { 1 } else { 0 },
            carrier2.revocation_count(),
            state_file_bytes(&dc.0)
        );
        if !self_revoked_after {
            bad.push("(3) не выполнен: молчание не пережило перезапуск — self_revoked сброшен".to_string());
        }
        if served || peer_agrees {
            bad.push("(3) не выполнен: возобновивший работу узел аутентифицируется и обслуживает".to_string());
        }

        // Контроль годности замера: тот же сид в ЧИСТОМ каталоге обязан говорить с чистым пиром.
        // Без него гейт (6) неотличим от «узел после рестарта ни с кем не знакомится» — та же
        // форма ошибки, что ДИАГНОЗ-1 у `E-0092`.
        let mut carrier3 = index_service_shard(CARRIER_SEED, SHARD, &dc3.0, quic_addr());
        let _ca3 = wait_listen(&mut carrier3).await;
        let fa2 = fresh2.listen_addrs().first().cloned().expect("listener чистого пира 2");
        carrier3.dial(fa2).expect("dial второго чистого пира");
        pump_until(&mut carrier3, &mut fresh2, |x, y| {
            x.is_authenticated(&y.peer_id()) && y.is_authenticated(&x.peer_id())
        })
        .await;
        let control = carrier3.is_authenticated(&fresh2.peer_id());
        println!(
            "RV_G7: rv_g7_fresh_control_serves={} rv_g7_control_self_revoked={} \
             rv_g7_control_file={}",
            if control { 1 } else { 0 },
            if carrier3.is_self_revoked() { 1 } else { 0 },
            state_file_bytes(&dc3.0)
        );
        if !control {
            bad.push("(3) контроль не пройден: узел с чистого каталога не аутентифицируется — гейт (6) меряет не отзыв".to_string());
        }
        drop(carrier3);
        drop(carrier2);
        drop(fresh2);
        drop(fresh);
        drop(watcher);
        assert!(bad.is_empty(), "гейты не выполнены: {bad:?}");
    });
}
