//! H-0091 / E-0091 · оракул: таблица провайдеров шарда обязана быть конечной.
//!
//! `E-0085` гейт (в) (`s53_door_branches.rs:838…841`) измерил, и `E-0086` перенёс в спеку (§4.2
//! `:185…190`) обратное: «запись о том, что шард кем-то предоставляется, монотонна и переживает
//! отзыв того, кто её внёс». Здесь тот же факт доводится до числа на **смерти по транспорту**
//! (§9.8), потому что смерть, а не отзыв — обычный случай: пир соединялся, объявил шард, умер.
//!
//! Гейт (3) — единственный, который обязан быть красным до правки. Гейты (1), (2), (4), (5)
//! собирают стенд и охраняют его от ложной чистки: живой провайдер обязан остаться в кэше, иначе
//! фикс сделает резолв шарда дороже, чем дыра.
//!
//! Стенд: один процесс, настоящий QUIC на loopback, `current_thread`, реальные настенные часы —
//! тот же харнес, что `E-0085`. API в файле только существующий (`provider_peers`,
//! `is_authenticated`, `find_providers`, `take_errors`, `kad_peer_count`): новых имён до правки не
//! существует, и оракул обязан компилироваться в пре-регистрационном коммите (порог (1)).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use vecdht_artifact::reference_manifest;
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::{testing, Clock, ShardNode};
use vecdht_wire::messages::Role;

const SHARD: u16 = 7;
/// Шард наблюдателя: другой, чем у провайдеров, чтобы его собственная провайдер-запись не
/// пересеклась с измеряемым множеством.
const SHARD_B: u16 = 9;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
/// Сколько шагов наблюдения ОТДЕЛЯЕТ факт смерти от вердикта (гейт (3)): 200 шагов по
/// `poll_interval` = 5 мс — это ~1 с шаговой стены, при лимите 30 с по часам. Выбор не временной
/// (правило 7 пункт (д): время сюда не входит), а счётчик шагов фиксирует, что чистка не обязана
/// ждать следующего часа.
const DEATH_STEPS: usize = 200;
/// Окно сборки стенда: handshake двух узлов + два объявления шарда + один резолв.
const SETUP_LIMIT: Duration = Duration::from_secs(60);
const DEATH_LIMIT: Duration = Duration::from_secs(30);

/// Каталог теста с Drop-гардом: `E-0085` оставил 13 осевших каталогов именно потому, что его
/// `dir()` гарда не имел (ДИАГНОЗ-2 того цикла) — правило перенесено сюда заранее.
struct Tmp(PathBuf);

impl Tmp {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("vecdht-s74-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("временный каталог теста");
        Self(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

fn cfg(listen: Multiaddr) -> NetConfig {
    NetConfig {
        listen: vec![listen],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-e0091/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
    }
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

/// Узел одного шарда с genesis-эпохой и кредашиалом `0..u32::MAX` — тот же конструктор, что в
/// `E-0085` (`s53_door_branches.rs:106…136`).
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

async fn wait_listen(s: &mut NetService) -> Multiaddr {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(a) = s.listen_addrs().first() {
            return a.clone();
        }
        assert!(Instant::now() < deadline, "listener не поднялся за 10 с");
        s.step().await;
    }
}

/// Один шаг стенда из трёх сервисов и, при смене секунды, резолв провайдеров наблюдателем.
/// `last_query` ведёт вызывающий: переспрос обязан быть не чаще раза в секунду, иначе тест мерит
/// скорость Kad-пути, а не состояние таблицы.
async fn round(pa: &mut NetService, pb: &mut NetService, w: &mut NetService, last_query: &mut u64) {
    pa.step().await;
    pb.step().await;
    w.step().await;
    let now = now_sec();
    if now != *last_query {
        *last_query = now;
        w.find_providers(SHARD).expect("kad-запрос провайдеров шарда");
    }
}

/// Тот же шаг для стенда без провайдера A: `drop` убивает его сервис вместе с соединением.
async fn round_without_a(pb: &mut NetService, w: &mut NetService, last_query: &mut u64) {
    pb.step().await;
    w.step().await;
    let now = now_sec();
    if now != *last_query {
        *last_query = now;
        w.find_providers(SHARD).expect("kad-запрос провайдеров шарда");
    }
}

/// Гейты (1)…(5): сборка → смерть провайдера A по транспорту → его нет в таблице провайдеров, а B
/// остался. Красный до правки ровно на (3).
#[test]
fn a_provider_that_dies_leaves_the_shard_provider_table() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let da = Tmp::new("prov-a");
        let db = Tmp::new("prov-b");
        let dw = Tmp::new("watcher");
        let mut pa = index_service_shard(1, SHARD, da.path(), quic_addr());
        let mut pb = index_service_shard(2, SHARD, db.path(), quic_addr());
        let mut w = index_service_shard(3, SHARD_B, dw.path(), quic_addr());
        let aa = wait_listen(&mut pa).await;
        let ab = wait_listen(&mut pb).await;
        let _aw = wait_listen(&mut w).await;
        let (ap, bp) = (pa.peer_id(), pb.peer_id());
        assert_ne!(ap, bp, "(1) провайдеры A и B — одна личность: сидам не хватает различия");

        w.dial(aa).expect("dial провайдера A");
        w.dial(ab).expect("dial провайдера B");

        // (1) предпосылка: оба провайдера шарда видны в таблице наблюдателя. Без этого измерения
        // нет, и падать обязан именно этот ассерт, а не гейт дыры.
        let mut last_query = 0u64;
        let deadline = Instant::now() + SETUP_LIMIT;
        let mut peers = Vec::new();
        loop {
            round(&mut pa, &mut pb, &mut w, &mut last_query).await;
            if w.is_authenticated(&ap) && w.is_authenticated(&bp) {
                peers = w.provider_peers(SHARD);
                if peers.contains(&ap) && peers.contains(&bp) {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "(1) стенд не собрался: handshake A={} B={}, провайдеров={}, kad-пиров={}, ошибки={:?} / {:?}",
                w.is_authenticated(&ap),
                w.is_authenticated(&bp),
                peers.len(),
                w.kad_peer_count(),
                w.take_errors(),
                pb.take_errors(),
            );
        }
        let len_before = w.provider_peers(SHARD).len();
        println!(
            "MERE g1_setup=1 g1_cache_len={len_before} g1_kad_peers={} \
             g1_announce_a={} g1_announce_b={}",
            w.kad_peer_count(),
            pa.provider_announcements,
            pb.provider_announcements,
        );

        // (2) предпосылка §9.8: смерть доказывается событием транспорта, а не тишиной.
        drop(pa);
        let deadline = Instant::now() + DEATH_LIMIT;
        loop {
            round_without_a(&mut pb, &mut w, &mut last_query).await;
            if !w.is_authenticated(&ap) {
                break;
            }
            assert!(Instant::now() < deadline, "(2) наблюдатель не забыл убитый пир за 30 с");
        }
        let len_at_death = w.provider_peers(SHARD).len();
        let has_dead_at_death = w.provider_peers(SHARD).contains(&ap);

        // (3)…(5): ещё DEATH_STEPS шагов — и вердикт по содержимому таблицы.
        for _ in 0..DEATH_STEPS {
            round_without_a(&mut pb, &mut w, &mut last_query).await;
        }
        let after = w.provider_peers(SHARD);
        let errs = w.take_errors();
        let dials = errs.iter().filter(|e| e.contains("dial")).count();
        println!(
            "MERE g2_dead_gone_from_handshake=1 g3_has_dead_at_death={} g3_has_dead_after={} \
             g4_live_present={} g5_len_at_death={len_at_death} g5_len_after={} g5_kad_peers={} \
             g5_errors_total={} g5_dial_errors={dials} ##",
            if has_dead_at_death { 1 } else { 0 },
            if after.contains(&ap) { 1 } else { 0 },
            if after.contains(&bp) { 1 } else { 0 },
            after.len(),
            w.kad_peer_count(),
            errs.len(),
        );
        assert!(
            !after.contains(&ap),
            "(3) мёртвый провайдер остался в таблице: `provider_peers` монотонен ({})",
            after.len()
        );
        assert!(after.contains(&bp), "(4) фикс потерял живого провайдера: {:?}", after);
        assert_eq!(after.len(), 1, "(5) bound: длина таблицы обязана равняться числу живых провайдеров");
    })
}

/// Граница цикла (только печать, вердикта не порождает): мёртвый пир возвращается в таблицу, если
/// наблюдатель переспрашивает DHT, пока kad-запись жива у хранящего узла. Это свойство чужого
/// хранилища, а не нашего кэша, и оно в `OPEN-QUESTIONS` как предпосылка к стенду `P1` (§7.4
/// называет `provider_record_ttl = 420 с`, кода у этого числа до `E-0091` не было).
#[test]
fn re_asking_the_dht_can_bring_the_dead_provider_back() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let da = Tmp::new("requery-a");
        let dw = Tmp::new("requery-w");
        let mut pa = index_service_shard(1, SHARD, da.path(), quic_addr());
        let mut w = index_service_shard(3, SHARD_B, dw.path(), quic_addr());
        let aa = wait_listen(&mut pa).await;
        let _aw = wait_listen(&mut w).await;
        let ap = pa.peer_id();
        w.dial(aa).expect("dial провайдера");

        let mut last_query = 0u64;
        let deadline = Instant::now() + SETUP_LIMIT;
        loop {
            pa.step().await;
            w.step().await;
            let now = now_sec();
            if now != last_query {
                last_query = now;
                w.find_providers(SHARD).expect("kad-запрос");
            }
            if w.provider_peers(SHARD).contains(&ap) {
                break;
            }
            assert!(Instant::now() < deadline, "(6) стенд переспроса не собрался");
        }
        drop(pa);
        let deadline = Instant::now() + DEATH_LIMIT;
        loop {
            w.step().await;
            if !w.is_authenticated(&ap) {
                break;
            }
            assert!(Instant::now() < deadline, "(6) наблюдатель не забыл убитый пир");
        }
        for _ in 0..DEATH_STEPS {
            w.step().await;
        }
        let after_prune = w.provider_peers(SHARD);
        // Переспрос DHT: тот же самый запрос, что делался до смерти.
        w.find_providers(SHARD).expect("kad-запрос после смерти");
        for _ in 0..DEATH_STEPS {
            w.step().await;
        }
        let after_requery = w.provider_peers(SHARD);
        println!(
            "MERE g6_after_prune={} g6_after_requery={} g6_dead_back={}",
            after_prune.len(),
            after_requery.len(),
            if after_requery.contains(&ap) { 1 } else { 0 },
        );
        // Проверки нет: это граница метода, а не утверждение о продукте.
    })
}
