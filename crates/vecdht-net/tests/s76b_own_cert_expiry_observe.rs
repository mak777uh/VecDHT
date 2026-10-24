//! H-0098 / E-0098: причина собственного молчания наблюдаема **числом**.
//!
//! Файл появляется вместе с правкой: до неё имён `is_self_expired` и
//! `own_cert_expired_refusals` нет. Гейт держит не только поведение (молчание), но и то, что
//! оператор видит состояние срока и счётчик отказов — иначе «молчание» неотличимо от «сети нет».

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use vecdht_artifact::reference_manifest;
use vecdht_net::{keys, NetConfig, NetService};
use vecdht_node::testing;
use vecdht_wire::messages::Role;

const SHARD: u16 = 7;

fn cfg(listen: Multiaddr) -> NetConfig {
    NetConfig {
        listen: vec![listen],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-net-test/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
        revoked_dir: None,
    }
}

fn now_sec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы после эпохи").as_secs()
}

#[test]
fn g4_a_closed_window_is_observable_by_number() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let until = (now_sec() as u32) + 3;
        let id = testing::identity(1);
        let peer = keys::peer_id(&id);
        let cert =
            testing::node_cert(1, peer.to_bytes(), vec![SHARD], Role::IndexNode, 0, until);
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес");
        let mut svc = NetService::new(
            id,
            Role::IndexNode,
            Some(cert),
            Vec::new(),
            testing::authority_set(),
            cfg(addr),
        )
        .expect("сервис с ещё годным кредашиалом");

        let before = svc.is_self_expired();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        while now_sec() as u32 <= until {
            assert!(tokio::time::Instant::now() < deadline, "часы не пошли");
            svc.step().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let after = svc.is_self_expired();

        let other = keys::peer_id(&testing::identity(9));
        let frame_refused = !svc.send_frame(other, vec![1, 2, 3]);
        let n1 = svc.own_cert_expired_refusals();
        let gossip_refused = svc.publish_gossip(SHARD, vec![1]).is_err();
        let n2 = svc.own_cert_expired_refusals();

        println!("S76B_SELF_EXPIRED={}", u8::from(after));
        println!("S76B_REFUSALS_GE_1={}", u8::from(n2 >= 1));
        println!("S76B_BEFORE_EXPIRED={}", u8::from(before));
        println!("S76B_REFUSALS={n1}->{n2}");

        assert!(!before, "до закрытия окна срок не истёк");
        assert!(after, "после закрытия окна `is_self_expired` обязан быть истинным");
        assert!(frame_refused, "после окна кадр не отправляется");
        assert!(gossip_refused, "после окна публикация отклоняется");
        assert!(n2 >= 2, "оба отказа обязаны быть посчитаны: {n1}->{n2}");
    });
}
