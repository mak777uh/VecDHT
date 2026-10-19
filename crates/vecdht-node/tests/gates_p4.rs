//! Гейты P4 (§19.1) — четыре сценария, ради которых и написан `vecdht-node`:
//!
//! ```text
//! kill primary → handoff < 10 с
//! реплики сходятся при W=2 / R=3
//! рестарт с epoch < max_epoch_served → отказ обслуживать
//! уход всех → seed отдаёт снапшот (§9.5)
//! ```
//!
//! Всё измеряется в секундах `LocalNet`, а не в `sleep`: один часовой интервал, одна стоимость
//! доставки (`LATENCY = 1 с`), `tick` строго на границе 16-секундного бакета (§19.1 — гейты
//! обязаны мерить *протокольное* время handoff, а не задержку localhost). Пороги гейтов — числа
//! из плана, и менять их ради зелёного вывода нельзя: если сценарий не проходит, это дефект
//! протокола или реализации.
//!
//! PoW майнится под сложность 8 из тестового манифеста: узел обязан следовать артефакту (§11.2),
//! и именно поэтому 24 бита «для честности» здесь были бы багом, а не экономией.

use std::path::PathBuf;

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_index::StoreError;
use vecdht_node::net::LocalNet;
use vecdht_node::{Addr, Lease, Params, candidates, membership, testing};
use vecdht_wire::codec::{DIM, MAX_BODY_LEN};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, PublishAck, ProtocolError, WalPullRequest, domain, err_code};

/// Шард 7, а не 0: кластеры 112..127, и ни один тест не «пройдёт» случайно из-за захардкоженного
/// нуля в проверке `shard_of_cluster`.
const SHARD: u16 = 7;
const CLUSTER: u16 = 112;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;
const LATENCY: u64 = 1;
/// Гейт P4: от факта смерти primary до подтверждённой записи у нового primary.
const HANDOFF_GATE_SEC: u64 = 10;
/// Окно ожидания ack: четыре перехода кворума + запас на переживание election-тишины. Это не
/// порог гейта, а горизонт наблюдателя: `probe` возвращает `None`, если за окно подтверждения не
/// пришло.
const ACK_WAIT_SEC: u64 = 8;
/// Сколько секунд агент повторяет попытку записи в гейте 1: заведомо больше порога handoff, чтобы
/// «не дождались» означало «протокол не справился», а не «тесту не хватило цикла».
const PUBLISH_WINDOW_SEC: u64 = 30;

fn params() -> Params {
    testing::params(POW)
}

// --- каркас ------------------------------------------------------------------

struct Swarm {
    net: LocalNet,
    /// Каталоги узлов: тест обязан убрать их сам, иначе temp забьётся после прогона.
    dirs: Vec<PathBuf>,
}

/// Три держателя шарда + genesis эпохи 1, подписанный авторитетом из артефакта (§15.2).
///
/// Genesis вносится каждому узлу напрямую (`on_frame`), а не «через DHT»: источник истины для
/// членства — порог подписей в теле перехода, а не тот, кто принёс кадр (§9.2).
fn swarm(tag: &str) -> Swarm {
    let p = params();
    let mut net = LocalNet::new(LATENCY);
    let mut dirs = Vec::new();
    for seed in SEEDS {
        let d = dir(&format!("{tag}-{seed}"));
        dirs.push(d.clone());
        net.add(testing::node(&d, SHARD, seed, p, &SEEDS));
    }
    let frame = testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0));
    let carrier = testing::identity(9).pubkey();
    let addrs = net.addrs();
    for addr in addrs {
        let replies = net.node_mut(&addr).unwrap().on_frame(carrier, &frame, 0).expect("genesis");
        for env in replies {
            net.send(addr, env.to, env.frame);
        }
    }
    assert!(net.settle(30), "после genesis сеть обязана замолчать: {:?}", net.errors);
    assert!(net.errors.is_empty(), "ошибки диспетчера: {:?}", net.errors);
    Swarm { net, dirs }
}

impl Swarm {
    fn primary(&self) -> Addr {
        let v: Vec<Addr> = self
            .net
            .addrs()
            .into_iter()
            .filter(|a| self.net.node(a).map(|n| n.is_primary()).unwrap_or(false))
            .collect();
        assert_eq!(v.len(), 1, "primary обязан быть ровно один, а их {}", v.len());
        v[0]
    }

    fn epoch(&self, addr: &Addr) -> Option<u64> {
        self.net.node(addr).and_then(|n| n.epoch())
    }

    fn clean(self) {
        let dirs = self.dirs;
        for d in &dirs {
            remove(d);
        }
    }
}

/// Кадр, пришедший агенту, если это кадр нужного типа.
fn kind_of(frame: &[u8]) -> Kind {
    decode_frame(frame).expect("агент обязан получать разбираемые кадры").header.kind
}

/// Одна попытка записи: `Publish` всем держателям шарда из рандеву-кэша (§7.3).
///
/// Эпизода берётся у каждого адресата отдельно и `published_bucket` — текущий бакет сети, а не
/// локальные часы агента (§9.6): публикация, улетевшая в прошлую эпоху, обязана быть отвергнута,
/// и именно это делает гейт 1 осмысленным. `ttl_buckets = 225` — час TTL (§2).
fn publish_once(net: &mut LocalNet, agent: &Identity, v: &[i8; DIM]) {
    let bucket = net.now_bucket();
    for addr in net.addrs() {
        let epoch = match net.node(&addr).and_then(|n| n.epoch()) {
            Some(e) if e > 0 => e,
            _ => continue,
        };
        let frame = testing::PublishSpec {
            agent,
            vec_q: v,
            cluster_id: CLUSTER,
            shard: SHARD,
            epoch,
            published_bucket: bucket,
            ttl_buckets: 225,
            bits: POW,
        }
        .frame();
        net.send(agent.pubkey(), addr, frame);
    }
}

/// Забрать почту агента и вернуть последний `PublishAck`. Почта вычищается целиком: ack, который
/// замер не увидел вовремя, не должен «всплыть» в следующем и превратить «подтверждения нет» в
/// подтверждение чужой записи.
fn take_ack(net: &mut LocalNet, agent: &Identity) -> Option<PublishAck> {
    let mut ack = None;
    for (_, frame) in net.take(&agent.pubkey()) {
        if kind_of(&frame) == Kind::PublishAck {
            ack = Some(PublishAck::decode(&frame).expect("PublishAck обязан разбираться"));
        }
    }
    ack
}

/// Полный цикл записи: одна попытка и ожидание подтверждения.
///
/// Ждать приходится столько, сколько стоит кворум, а не один переход: честный путь — `Publish` →
/// primary → `ReplicateOp` реплике → `ReplicateAck` → `PublishAck` агенту, то есть минимум четыре
/// доставки по `LATENCY` (§9.4). `None` по истечении окна и есть честный ответ гейта
/// «подтверждения нет».
fn probe(net: &mut LocalNet, agent: &Identity, v: &[i8; DIM]) -> Option<PublishAck> {
    net.take(&agent.pubkey());
    publish_once(net, agent, v);
    for _ in 0..ACK_WAIT_SEC {
        net.step(1);
        if let Some(a) = take_ack(net, agent) {
            return Some(a);
        }
    }
    None
}

// --- гейт 1: kill primary → handoff < 10 с -------------------------------------

#[test]
fn killed_primary_is_replaced_in_under_ten_seconds() {
    let mut s = swarm("handoff");
    let agent = testing::identity(77);
    let v = testing::vector(3);
    let old = s.primary();
    let old_epoch = s.epoch(&old).unwrap();

    // `LocalNet::kill` = процесс умер, соединение закрыто: оставшимся узлам приходит
    // `peer_lost`, и именно это отличает гейт от «ждём истечения lease в 90 с» (§9.8).
    s.net.kill(&old);
    let killed_at = s.net.now_sec();

    // Агент пишет раз в секунду, пока election идёт: `probe` с полным окном ожидания измерил бы
    // не handoff, а кратность окна. Замер останавливается на первом же ack, и `now_sec()` берётся
    // в момент, когда ack *пришёл агенту*, — то есть время handoff включает четыре перехода
    // доставки: запрос, репликацию, подтверждение реплики и ack агенту.
    s.net.take(&agent.pubkey());
    let mut ack: Option<(u64, PublishAck)> = None;
    for _ in 0..PUBLISH_WINDOW_SEC {
        publish_once(&mut s.net, &agent, &v);
        s.net.step(1);
        if let Some(a) = take_ack(&mut s.net, &agent) {
            assert_eq!(a.error_code, "OK", "подтверждение должно быть успешным: {:?}", a);
            ack = Some((s.net.now_sec(), a));
            break;
        }
    }
    let (ack_at, ack) = ack.expect("запись обязаны подтвердить за окно поиска");
    let handoff = ack_at - killed_at;
    let new = s.primary();
    let new_epoch = s.epoch(&new).unwrap();

    // Гейт обязан печатать измеренное число, а не только молча проходить: «< 10 с» без замера
    // неотличимо от «тест ничего не измеряет» (§19.1).
    println!("handoff = {handoff} с при пороге {HANDOFF_GATE_SEC} с");
    assert!(handoff < HANDOFF_GATE_SEC, "handoff занял {handoff} с при гейте {HANDOFF_GATE_SEC}");
    assert_ne!(new, old, "мёртвый узел не может остаться primary");
    assert_eq!(new_epoch, old_epoch + 1, "переход обязан идти к следующей эпизоде, а не через неё");
    assert_eq!(ack.epoch, new_epoch, "ack несёт ту эпизоду, которая теперь обслуживает");
    // Кворум собрался без мёртвого: `peer_acks_needed = w - 1 = 1`, и этот один — живая реплика.
    assert!(s.net.dropped > 0, "кадры на убитый узел обязаны считаться потерянными");
    assert!(s.net.settle(30), "после handoff трафик обязан улечься");
    assert!(s.net.errors.is_empty(), "ошибки диспетчера: {:?}", s.net.errors);
    let others = s.net.addrs();
    for a in &others {
        if *a != old {
            assert_eq!(s.epoch(a), Some(new_epoch), "все выжившие приняли одну и ту же эпизоду");
        }
    }
    s.clean();
}

// --- гейт 2: W=2 / R=3 ---------------------------------------------------------

#[test]
fn three_replicas_converge_and_quorum_needs_a_second_copy() {
    let mut s = swarm("w2r3");
    // Разные владельцы — разные записи: один и тот же owner это дедупликация по slot, а не три
    // записи (§8.2).
    let owners: Vec<Identity> = (0..3u8).map(|i| testing::identity(10 + i)).collect();
    let mut acked: Vec<u64> = Vec::new();
    for (i, agent) in owners.iter().enumerate() {
        let ack = probe(&mut s.net, agent, &testing::vector(10 + i as u8))
            .expect("при R=3 и живой реплике кворум W=2 собирается");
        assert_eq!(ack.error_code, "OK");
        acked.push(ack.seq);
    }
    assert!(acked.windows(2).all(|w| w[0] < w[1]), "seq растут без пропусков: {acked:?}");
    assert!(s.net.settle(30), "anti-entropy обязана догнать и замолчать");

    let addrs = s.net.addrs();
    let seqs: Vec<u64> = addrs.iter().map(|a| s.net.node(a).unwrap().applied_seq()).collect();
    assert!(seqs.iter().all(|q| *q == seqs[0]), "три реплики сходятся на одном applied_seq: {seqs:?}");
    assert!(seqs[0] >= 3, "три insert должны быть видны всем: {seqs:?}");

    // Идемпотентность по seq и общий slot: `owner → slot` — часть контракта §8.2, и расхождение
    // здесь означает, что read-repair потом никогда не сведёт реплики.
    let mut slots: Vec<Vec<Option<u32>>> = Vec::new();
    let mut hits: Vec<Vec<(u32, u32)>> = Vec::new();
    for a in &addrs {
        let n = s.net.node(a).unwrap();
        slots.push(owners.iter().map(|o| n.store.index.owner_slot(&o.pubkey())).collect());
        hits.push(n.store.search(&testing::vector(10), &[CLUSTER], 5));
    }
    assert!(slots.windows(2).all(|w| w[0] == w[1]), "slot обязан совпасть на всех репликах: {slots:?}");
    assert!(slots[0].iter().all(|x| x.is_some()), "каждая запись получила slot: {:?}", slots[0]);
    assert!(
        hits.windows(2).all(|w| w[0] == w[1]),
        "выдача поиска одинакова: разное — это разошедшийся индекс"
    );

    // Вторая половина гейта: кворум — это «сам + ещё один», а не «сам записал».
    let primary = s.primary();
    let peers = s.net.node(&primary).unwrap().peers();
    assert_eq!(peers.len(), 2);
    for p in peers {
        s.net.kill(&p);
    }
    let before = s.net.node(&primary).unwrap().applied_seq();
    let last = &owners[2];
    assert!(
        probe(&mut s.net, last, &testing::vector(12)).is_none(),
        "без второй копии подтверждать нечем: W=2 из R=3 не превращается в W=1"
    );
    let after = s.net.node(&primary).unwrap().applied_seq();
    assert!(after > before, "WAL primary записан: отказ в ack — это не откат записи (§10.1)");
    assert!(s.net.settle(40), "одинокий primary не должен бесконечно переспрашивать мёртвых");
    assert!(s.net.errors.is_empty(), "ошибки диспетчера: {:?}", s.net.errors);
    s.clean();
}

// --- гейт 3: рестарт с epoch < max_epoch_served --------------------------------

#[test]
fn a_restarted_node_with_a_stale_epoch_refuses_to_serve() {
    let p = params();
    let d = dir("fencing");
    // Узел под тестом — primary эпохи 1, иначе вместо отказа обслуживать мы бы получили
    // `NOT_OWNER` и проверяли бы не то.
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let primary_seed = SEEDS
        .iter()
        .copied()
        .find(|s| testing::identity(*s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — это один из тестовых сидов");
    let mut n = testing::node(&d, SHARD, primary_seed, p, &SEEDS);
    let carrier = testing::identity(9).pubkey();
    n.on_frame(carrier, &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)), 0)
        .expect("genesis");
    assert!(n.is_primary());
    assert_eq!(n.serving_epoch(0), Some(1), "lease + durable-маркер = обслуживаем (§9.2)");

    // Симулируем, что эта эпизода уже ушла в прошлое: узел честно подтвердил эпоху 2 на диск.
    assert!(n.store.grant_epoch(2).unwrap());
    drop(n);

    // Рестарт «из резервной копии»: маркер на месте, а цепочка членства откатилась к эпохе 1.
    let mut stale = testing::node(&d, SHARD, primary_seed, p, &SEEDS);
    assert_eq!(stale.epoch(), Some(1), "цепочка перезагружается с диска и валидируется заново");
    assert_eq!(stale.serving_epoch(1), None, "без lease не обслуживаем");

    // Выдаём lease ровно той эпизоды, которую помнит цепочка: fencing обязан сработать на диске.
    let grant = Lease::grant(1, stale.me(), 1, p.lease_buckets)
        .signed_frame(SHARD, &stale.id, testing::DHT_PEER_ID.to_vec());
    let replies = stale.on_frame(stale.me(), &grant, 1).expect("lease");
    assert!(replies.is_empty(), "грант от самого primary реплике не пересылается");
    assert!(stale.lease_active(1), "lease по форме правильный: эпоха == принятой, срок не вышел");
    assert_eq!(
        stale.serving_epoch(1),
        None,
        "дисковый маркер старше цепочки — обслуживать нельзя, каким бы валидным ни был lease"
    );

    let agent = testing::identity(77);
    let frame = testing::PublishSpec {
        agent: &agent,
        vec_q: &testing::vector(5),
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch: 1,
        published_bucket: 1,
        ttl_buckets: 225,
        bits: POW,
    }
    .frame();
    let replies = stale.on_frame(agent.pubkey(), &frame, 1).expect("publish");
    assert_eq!(replies.len(), 1);
    let err = ProtocolError::decode(&replies[0].frame).expect("агенту вернулся Error");
    assert_eq!(err.code, err_code::EPOCH_STALE, "ровно этот код обещан §12.1: {err:?}");
    assert!(
        matches!(
            stale.store.grant_epoch(1),
            Err(StoreError::StaleEpoch { given: 1, saved: 2 })
        ),
        "откатить эпизоду перезапуск не может — маркер на диске (§9.2)"
    );

    // Восстановление: узел обязан догнать цепочку, а не «вспомнить» эпизоду из RAM.
    let other = testing::identity(*SEEDS.iter().find(|s| **s != primary_seed).unwrap());
    let list = candidates::expected_update(2, SHARD, &testing::holders(&SEEDS), p.r, 0, 1);
    let draft = membership::build_update(&list, Vec::new());
    let idx = order
        .iter()
        .position(|h| h.owner_ed25519 == other.pubkey())
        .expect("подписант обязан быть участником эпохи 1");
    let sig = other.sign_domain(domain::MEMBER, &draft.unsigned_body());
    let upd = membership::build_update(&list, vec![(idx as u8, sig)]);
    stale.on_frame(other.pubkey(), &testing::signed_frame(&upd), 1).expect("цепочка эпохи 2");
    assert_eq!(stale.epoch(), Some(2));
    assert_eq!(stale.serving_epoch(1), Some(2), "цепочка догнала диск — обслуживание вернулось");
    remove(&d);
}

// --- гейт 4: уход всех → seed отдаёт снапшот -----------------------------------

#[test]
fn when_everyone_leaves_a_seed_serves_the_snapshot() {
    let mut s = swarm("seed-snapshot");
    let agent = testing::identity(61);
    for i in 0..2u8 {
        assert!(
            probe(&mut s.net, &agent, &testing::vector(20 + i)).is_some(),
            "до ухода данные обязаны быть записаны"
        );
    }
    let seed = s.net.addrs()[0];
    let applied = s.net.node(&seed).unwrap().applied_seq();
    assert!(applied > 0, "пустой шард нечему делиться — тест обязан проверить неоткуда");

    // Все трое объявляют уход в одном бакете (§9.5, п.2): каждый исключает себя из следующего
    // состава, каждый подписывает собственный уход.
    let bucket = s.net.now_bucket();
    let mut drafts = Vec::new();
    let addrs = s.net.addrs();
    for addr in addrs {
        drafts.push((addr, s.net.node_mut(&addr).unwrap().leave(bucket, 0).expect("leave")));
    }
    for (from, envs) in drafts {
        for env in envs {
            s.net.send(from, env.to, env.frame);
        }
    }

    assert!(s.net.settle(60), "пустой переход обязан разойтись и замолчать: {:?}", s.net.errors);
    for addr in s.net.addrs() {
        let n = s.net.node(&addr).unwrap();
        assert_eq!(n.epoch(), Some(2), "объявить свободным можно только следующей эпизодой");
        assert!(n.membership.as_ref().unwrap().is_empty(), "состав пустой: шард объявлен свободным");
        assert!(n.store.last_snapshot_seq > 0, "seed обязан успеть опубликовать снапшот (§9.5, п.2)");
    }

    // Свежий узел (ничего не знает, цепочки нет) просит состояние с `from_seq = 0` — это и есть
    // холодный путь: `0 < oldest_wal_needed`, и seed отвечает кусками `SnapshotOffer` (§9.7).
    let f_dir = dir("seed-snapshot-new");
    let f = testing::node(&f_dir, SHARD, 9, params(), &SEEDS);
    let f_addr = s.net.add(f);
    let req = WalPullRequest {
        shard: SHARD,
        from_seq: 0,
        to_seq: 0,
        max_bytes: (MAX_BODY_LEN / 2) as u32,
    }
    .encode_unsigned();
    s.net.send(f_addr, seed, req);
    assert!(s.net.settle(120), "холодная отдача снапшота обязана закончиться: {:?}", s.net.errors);

    let seed_node = s.net.node(&seed).unwrap();
    let new_node = s.net.node(&f_addr).unwrap();
    assert_eq!(new_node.applied_seq(), seed_node.applied_seq(), "догнать обязан полностью");
    assert!(!new_node.store.is_empty(), "пустой индекс — это не установленный снапшот");
    assert_eq!(new_node.store.len(), seed_node.store.len());
    assert_eq!(
        new_node.store.search(&testing::vector(20), &[CLUSTER], 5),
        seed_node.store.search(&testing::vector(20), &[CLUSTER], 5),
        "после установки снапшота выдача поиска обязана совпасть побайтово-по-слотам"
    );
    assert!(s.net.errors.is_empty(), "ошибки диспетчера: {:?}", s.net.errors);
    remove(&f_dir);
    s.clean();
}
