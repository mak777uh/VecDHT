//! H-0145 / `E-0145`: §16.3 — circuit relay v2 как транспорт, а не как обещание.
//!
//! Спека требует, чтобы два агента за NAT дозвонились друг другу через релей (§16.3), а гейт
//! P6 мерил этот путь на WAN. WAN-половина — красная зона владельца (две машины, §18.7), но
//! ей предшествует зелёный вопрос: **несёт ли релей вообще прикладной трафик**? До этого цикла
//! ответ был «нет»: в `Cargo.toml` не было фичи `relay`, в `Behaviour` — ни одной половины
//! circuit relay v2, `Role::Relay` был ролью без механизма.
//!
//! Стенд: один процесс, настоящий QUIC на loopback, `current_thread`, три `NetService` —
//! релей (`Role::Relay`), цель (агент **без единого прямого listen-адреса**) и клиент (агент).
//! Цель резервирует слот на релее и получает `/p2p-circuit`-адрес; клиент знает только адрес
//! релея и `PeerId` цели. Единица измерения — факт транспорта: соединение установлено,
//! прикладной handshake сошёлся на обеих сторонах, счётчики relay-событий ненулевые. Времени
//! в порогах нет: deadline только ограничивает ожидание, а не является мерой.
//!
//! Оракул двусторонний. Положительная половина без отрицательной доказывала бы лишь, что
//! «где-то соединилось»: вторая половина поднимает релей в роли агента (серверная половина
//! выключена ролью) и требует, чтобы резервация и контур **не** состоялись. Если бы сервер
//! работал у всех ролей, отрицательная половина покраснела бы — именно этого не должно быть.
//!
//! Чего этот файл не делает: не поднимает NAT, не меряет WAN-RTT и не закрывает гейт P6
//! (§18.7: две машины — красная зона). Он доказывает нижнюю половину: релей проводит байты
//! приложения, и делает это только там, где включён ролью.

use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use vecdht_artifact::reference_manifest;
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::testing;
use vecdht_wire::messages::Role;

/// Сиды вне тестовых авторитетов (1…5) и вне ростеров других тестов.
const RELAY_SEED: u8 = 201;
const TARGET_SEED: u8 = 202;
const CLIENT_SEED: u8 = 203;

fn quic_addr() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")
}

fn cfg(listen: Vec<Multiaddr>) -> NetConfig {
    NetConfig {
        listen,
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-e0145/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
        revoked_dir: None,
    }
}

/// Сервис без шардов. Агент и цель кредашиала не требуют; релей — требует (`handshake::greeting`
/// отвергает `Relay` без `NodeCert`), поэтому ему выдаётся настоящий сертификат тестовых
/// авторитетов, а не обходной путь.
fn service(seed: u8, role: Role, listen: Vec<Multiaddr>) -> NetService {
    let id = testing::identity(seed);
    let peer = keys::peer_id(&id);
    let cert = if role == Role::Agent {
        None
    } else {
        Some(testing::node_cert(seed, peer.to_bytes(), vec![7], role, 0, u32::MAX))
    };
    NetService::new(
        id,
        role,
        cert,
        Vec::new(),
        testing::authority_set(),
        cfg(listen),
    )
    .expect("сервис стенда")
}

/// Дождаться прямого (не `/p2p-circuit`) listen-адреса и вернуть его с `/p2p/<peer-id>`.
async fn wait_relay_addr(relay: &mut NetService) -> Multiaddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        relay.step().await;
        if let Some(a) = relay
            .listen_addrs()
            .iter()
            .find(|a| !a.iter().any(|p| matches!(p, Protocol::P2pCircuit)))
        {
            return a.clone().with(Protocol::P2p(relay.peer_id()));
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "релей не открыл прямой listen-адрес за 20 с; ошибки: {:?}",
            relay.take_errors()
        );
    }
}

fn is_circuit(a: &Multiaddr) -> bool {
    a.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

#[test]
fn a_circuit_relay_carries_the_application_handshake() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut relay = service(RELAY_SEED, Role::Relay, vec![quic_addr()]);
        // Цель НЕ слушает напрямую: единственный путь к ней — контур на релее.
        let mut target = service(TARGET_SEED, Role::Agent, Vec::new());
        let mut client = service(CLIENT_SEED, Role::Agent, vec![quic_addr()]);
        let (relay_peer, target_peer, client_peer) =
            (relay.peer_id(), target.peer_id(), client.peer_id());

        let relay_addr = wait_relay_addr(&mut relay).await;
        // Клиент резервации ещё не участвует: слот просит цель.
        target.reserve_circuit(relay_addr.clone()).expect("резервация цели");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            relay.step().await;
            target.step().await;
            let srv_res = relay.relay_stats();
            let cli_res = target.relay_stats();
            if srv_res.0 > 0 && cli_res.2 > 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "резервация не состоялась за 20 с: релей {srv_res:?}, цель {cli_res:?}, ошибки {:?} / {:?}",
                relay.take_errors(),
                target.take_errors()
            );
        }

        // Полный адрес цели: адрес релея + `/p2p-circuit` + `PeerId` цели. Клиент не знает
        // ни одного прямого адреса цели — их у неё нет.
        let circuit_to_target = relay_addr
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(target_peer));
        assert!(
            target.listen_addrs().iter().filter(|a| !is_circuit(a)).count() == 0,
            "у цели не должно быть прямых слушателей, иначе успех не доказывает релей"
        );
        assert!(
            circuit_to_target
                .iter()
                .any(|p| matches!(p, Protocol::P2p(id) if id == relay_peer)),
            "адрес контура обязан нести /p2p/<relay-id>, иначе клиент не знал бы, кого просить"
        );
        client.dial(circuit_to_target).expect("dial через контур");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            relay.step().await;
            target.step().await;
            client.step().await;
            if client.is_authenticated(&target_peer) && target.is_authenticated(&client_peer) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "handshake через контур не сошёлся за 20 с; ошибки: {:?} / {:?} / {:?}",
                relay.take_errors(),
                target.take_errors(),
                client.take_errors()
            );
        }

        let srv_res = relay.relay_stats();
        let tgt_res = target.relay_stats();
        let cli_res = client.relay_stats();
        let target_direct = target.listen_addrs().iter().filter(|a| !is_circuit(a)).count();
        println!("МЕРЕНО target_direct_listeners={target_direct}");
        println!("МЕРЕНО positive_server_reservations={}", srv_res.0);
        println!("МЕРЕНО positive_server_circuits={}", srv_res.1);
        println!("МЕРЕНО positive_target_reservations={}", tgt_res.2);
        println!("МЕРЕНО positive_client_reservations={}", cli_res.2);
        println!("МЕРЕНО positive_client_circuits={}", cli_res.3);
        println!(
            "МЕРЕНО positive_auth_client_to_target={}",
            u8::from(client.is_authenticated(&target_peer))
        );
        println!(
            "МЕРЕНО positive_auth_target_to_client={}",
            u8::from(target.is_authenticated(&client_peer))
        );
        println!("МЕРЕНО positive_relay_auth_target={}", u8::from(relay.is_authenticated(&target_peer)));
        println!("МЕРЕНО positive_relay_auth_client={}", u8::from(relay.is_authenticated(&client_peer)));
        println!("МЕРЕНО positive_target_door_refusals={}", target.door_refusal_total());

        assert_eq!(target_direct, 0);
        assert!(srv_res.0 > 0, "сервер релея принял слот");
        assert!(tgt_res.2 > 0, "цель получила слот");
        assert!(srv_res.1 > 0, "сервер релея провёл контур");
        assert!(cli_res.3 > 0, "клиент открыл контур");
        assert_eq!(cli_res.2, 0, "клиент не резервировал слот — он только дозванивался");
        assert!(client.is_authenticated(&target_peer));
        assert!(target.is_authenticated(&client_peer));
        assert_eq!(target.door_refusal_total(), 0, "релейный путь не должен упираться в дверь");
    });
}

#[test]
fn a_non_relay_role_does_not_relay_circuits() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        // Тот же релей, но в роли агента: серверная половина выключена ролью.
        let mut fake = service(RELAY_SEED, Role::Agent, vec![quic_addr()]);
        let mut target = service(TARGET_SEED, Role::Agent, Vec::new());
        let mut client = service(CLIENT_SEED, Role::Agent, vec![quic_addr()]);
        let target_peer = target.peer_id();
        let fake_addr = wait_relay_addr(&mut fake).await;
        target.reserve_circuit(fake_addr.clone()).expect("резервация цели");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        while tokio::time::Instant::now() < deadline {
            fake.step().await;
            target.step().await;
        }
        let circuit_to_target = fake_addr
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(target_peer));
        client.dial(circuit_to_target).expect("dial в пустоту");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        while tokio::time::Instant::now() < deadline {
            fake.step().await;
            target.step().await;
            client.step().await;
        }
        let fake_stats = fake.relay_stats();
        let target_stats = target.relay_stats();
        println!("МЕРЕНО negative_server_reservations={}", fake_stats.0);
        println!("МЕРЕНО negative_server_circuits={}", fake_stats.1);
        println!("МЕРЕНО negative_target_reservations={}", target_stats.2);
        println!(
            "МЕРЕНО negative_auth_client_to_target={}",
            u8::from(client.is_authenticated(&target_peer))
        );

        assert_eq!(fake_stats.0, 0, "агент не принимает резервации");
        assert_eq!(fake_stats.1, 0, "агент не проводит контуры");
        assert_eq!(target_stats.2, 0, "слот не выдан");
        assert!(!client.is_authenticated(&target_peer), "контура нет — соединения нет");
    });
}
