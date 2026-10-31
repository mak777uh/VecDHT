//! H-0165 / D3: кусок снапшота принимается только по полномочию принятой эпохи.
//!
//! `SnapshotOffer` — «пояс», а не гарантия (§9.5): подпись куска доказывает автора, но не право
//! кормить приёмник. До сборки дверь обязана проверить две вещи: `epoch` куска равен принятой
//! эпохе (тёплый узел) и отправитель — член именно этой эпохи; узел без эпохи (холодный старт)
//! верит только держателю своего ростера (§9.7).
//!
//! Куски синтетические, файл заведомо длиннее одного куска: неполный набор наблюдается ровно
//! одним ответом `WalPullRequest` («дай дальше»), а отброшенный кусок — молчанием. Хеш файла до
//! сборки не проверяется, поэтому синтетике достаточно любого `content_hash`.

use vecdht_crypto::Identity;
use vecdht_index::testing::{dir, remove};
use vecdht_node::net::Envelope;
use vecdht_node::testing;
use vecdht_node::{Addr, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{Codec, SnapshotOffer, domain};

const SHARD: u16 = 7;
const POW: u32 = 8;
const SEEDS: [u8; 3] = [1, 2, 3];
/// Файл длиннее одного куска: `Assembler` остаётся неполным, и «дай дальше» — наблюдаемое
/// принятие, а не установка.
const TOTAL: u32 = 100;

fn offer(epoch: u64, offset: u32, len: usize) -> SnapshotOffer {
    SnapshotOffer {
        shard: SHARD,
        epoch,
        snapshot_seq: 1,
        oldest_wal_needed: 1,
        applied_seq: 1,
        next_slot: 1,
        time_mark_bucket: 1,
        total_len: TOTAL,
        offset,
        content_hash: [7u8; 32],
        chunk: vec![0xA5; len],
    }
}

fn signed(id: &Identity, offer: &SnapshotOffer) -> Vec<u8> {
    let sig = id.sign_body(domain::SNAPSHOT, Kind::SnapshotOffer, &offer.body_bytes());
    offer.encode_signed(&sig)
}

/// Тёплый узел: цепочка эпохи 1 принята, узел — её член.
fn warm(tag: &str) -> (ShardNode, std::path::PathBuf) {
    let d = dir(tag);
    let mut n = testing::node(&d, SHARD, 1, testing::params(POW), &SEEDS);
    let genesis = testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0));
    let carrier = testing::identity(9).pubkey();
    n.on_frame(carrier, &genesis, testing::clock(0)).expect("genesis");
    assert_eq!(n.epoch(), Some(1), "сцена обязана быть тёплой");
    (n, d)
}

/// Принятие куска наблюдаемо ответом «дай дальше» на адрес отправителя.
fn was_accepted(replies: &[Envelope], from: Addr) -> bool {
    replies.iter().any(|e| {
        e.to == from && decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::WalPullRequest)
    })
}

#[test]
fn honest_member_offer_is_accepted() {
    let (mut n, d) = warm("d3-honest");
    let member = testing::identity(2);
    let from = member.pubkey();
    assert_ne!(from, n.me(), "сцена: отправитель — не сам узел");
    let replies = n
        .on_frame(from, &signed(&member, &offer(1, 0, 1)), testing::clock(1))
        .expect("кадр не ломает узел");
    assert!(
        was_accepted(&replies, from),
        "член принятой эпохи с равной эпохой обязан пройти: {replies:?}"
    );
    assert_eq!(n.applied_seq(), 0, "неполный набор ещё не поставил снапшот");
    remove(&d);
}

#[test]
fn offer_with_another_epoch_is_dropped() {
    let (mut n, d) = warm("d3-epoch");
    let member = testing::identity(2);
    let from = member.pubkey();
    let replies = n
        .on_frame(from, &signed(&member, &offer(2, 0, 1)), testing::clock(1))
        .expect("кадр не ломает узел");
    assert!(replies.is_empty(), "кусок чужой эпохи обязан молчать: {replies:?}");
    assert_eq!(n.applied_seq(), 0);
    assert_eq!(n.store.len(), 0);
    // Тот же отправитель с равной эпохой проходит: отброшена эпоха, а не отправитель.
    let replies = n
        .on_frame(from, &signed(&member, &offer(1, 0, 1)), testing::clock(1))
        .expect("кадр не ломает узел");
    assert!(was_accepted(&replies, from), "равная эпоха того же члена: {replies:?}");
    remove(&d);
}

#[test]
fn offer_from_non_member_is_dropped() {
    let (mut n, d) = warm("d3-member");
    let attacker = testing::identity(251);
    let from = attacker.pubkey();
    assert!(
        !n.membership.as_ref().unwrap().is_member(&from),
        "сцена: ключ не входит в эпоху 1"
    );
    let replies = n
        .on_frame(from, &signed(&attacker, &offer(1, 0, 1)), testing::clock(1))
        .expect("кадр не ломает узел");
    assert!(
        replies.is_empty(),
        "подпись чужим ключом не даёт права кормить снапшот: {replies:?}"
    );
    assert_eq!(n.applied_seq(), 0);
    assert_eq!(n.store.len(), 0);
    // Член с тем же кадром проходит: отброшен именно не-член.
    let member = testing::identity(2);
    let replies = n
        .on_frame(member.pubkey(), &signed(&member, &offer(1, 0, 1)), testing::clock(1))
        .expect("кадр не ломает узел");
    assert!(was_accepted(&replies, member.pubkey()), "член эпохи: {replies:?}");
    remove(&d);
}

#[test]
fn cold_node_trusts_only_roster_holder() {
    let d = dir("d3-cold");
    let mut n = testing::node(&d, SHARD, 1, testing::params(POW), &SEEDS);
    assert_eq!(n.epoch(), None, "сцена: у узла нет принятой эпохи");
    // Сверять `epoch` куска холодному узлу не с чем: право даёт ростер, а не число.
    let holder = testing::identity(2);
    let replies = n
        .on_frame(holder.pubkey(), &signed(&holder, &offer(9, 0, 1)), testing::clock(1))
        .expect("кадр не ломает узел");
    assert!(
        was_accepted(&replies, holder.pubkey()),
        "держатель ростера обязан пройти: {replies:?}"
    );
    let attacker = testing::identity(252);
    let replies = n
        .on_frame(attacker.pubkey(), &signed(&attacker, &offer(9, 1, 1)), testing::clock(1))
        .expect("кадр не ломает узел");
    assert!(replies.is_empty(), "не-ростер не кормит холодный старт: {replies:?}");
    assert_eq!(n.applied_seq(), 0);
    remove(&d);
}
