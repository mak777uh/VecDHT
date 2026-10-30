//! D4 / H-0161: догонка WAL — работа узла и тратит узловой бюджет §11.3.4.
//!
//! `WalPullRequest` не подписан (§5.3) и не имеет per-key квоты, поэтому единственный барьер
//! против потока pull'ов с одного адреса — узловой бюджет. Тест смотрит на байты ответа: «узел
//! промолчал» и «узел отказал кодом §5.5» — разные утверждения, и второе обязано быть видно.
//!
//! Шард 7 — тот же, что в гейтах P4: ноль в качестве «удобного» значения скрыл бы ошибку
//! маршрута (§7.4).

use vecdht_index::testing::{dir, remove};
use vecdht_node::{testing, Envelope};
use vecdht_wire::messages::{err_code, Codec, ProtocolError, WalPullRequest, WalPullResponse};

const SHARD: u16 = 7;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn pull_frame(shard: u16) -> Vec<u8> {
    WalPullRequest { shard, from_seq: 0, to_seq: 0, max_bytes: 1024 }.encode_unsigned()
}

/// Код `Error`, адресованного пиру, если узел ответил отказом.
fn error_to(replies: &[Envelope], peer: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == peer)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

#[test]
fn pull_request_costs_node_budget() {
    let d = dir("s11-pull-budget");
    let mut n = testing::node(&d, SHARD, 1, testing::params(POW), &SEEDS);
    let peer = testing::identity(60).pubkey();
    let frame = pull_frame(SHARD);
    for i in 0..100 {
        let replies = n.on_frame(peer, &frame, testing::clock(0)).expect("pull в пределах бюджета");
        let resp = replies.iter().find(|e| e.to == peer).expect("ответ на pull");
        WalPullResponse::decode(&resp.frame)
            .unwrap_or_else(|e| panic!("pull №{i}: ответ не WalPullResponse: {e:?}"));
        assert!(error_to(&replies, peer).is_none(), "pull №{i} обязан пройти в пределах burst");
    }
    let replies = n.on_frame(peer, &frame, testing::clock(0)).expect("101-й pull");
    let err = error_to(&replies, peer).expect("101-й pull в ту же секунду обязан получить Error");
    assert_eq!(err.code, err_code::BUSY);
    assert!(err.retry_after_ms > 0, "BUSY обязан назвать срок повтора");
    assert_eq!(n.admission.borrow().stats.rejected_node_busy, 1);
    remove(&d);
}

#[test]
fn foreign_shard_pull_is_free() {
    let d = dir("s11-pull-foreign");
    let mut n = testing::node(&d, SHARD, 1, testing::params(POW), &SEEDS);
    let peer = testing::identity(61).pubkey();
    let foreign = n.on_frame(peer, &pull_frame(SHARD + 1), testing::clock(0)).expect("чужой шард");
    assert!(foreign.is_empty(), "чужой шард не обслуживается и не получает ответа: {foreign:?}");
    let frame = pull_frame(SHARD);
    for i in 0..100 {
        let replies = n.on_frame(peer, &frame, testing::clock(0)).expect("свой шард");
        assert!(error_to(&replies, peer).is_none(), "pull №{i} после чужого шарда обязан пройти");
    }
    assert_eq!(n.admission.borrow().stats.rejected_node_busy, 0, "чужой шард не тратил бюджет");
    remove(&d);
}
