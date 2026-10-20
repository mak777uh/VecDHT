//! Состав libp2p-поведения узла (§4.1, §7.4, §5.3).
//!
//! Четыре независимых механизма, и каждый отвечает ровно за одно:
//!
//! * `frames` — кадры v8 по прямому соединению (publish/find/replication);
//! * `kad` — 64 ключа провайдеров шардов (§7.4), а не адреса узлов: адрес даёт транспорт;
//! * `identify` — адреса и публичный ключ пира, чтобы Kademlia умела дозвониться, а не
//!   только знать `PeerId`;
//! * `gossip` — темы шардов для широковещательных `Publish`/`Find`/`MembershipUpdate`.
//!
//! `request-response` выбран вместо ручных substream'ов не из удобства: у него уже есть
//! таймаут запроса, лимит одновременных стримов и отдельный `InboundFailure`, то есть отказ
//! доставки — наблюдаемое событие, а не тишина. `Find` отвечает батчем кадров
//! (`MatchResult` + приёмы), поэтому `Response = Vec<Vec<u8>>`.

use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, kad, request_response};

use crate::codec::FrameCodec;

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub frames: request_response::Behaviour<FrameCodec>,
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub gossip: gossipsub::Behaviour,
}
