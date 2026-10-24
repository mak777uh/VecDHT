//! VecDHT v8 — транспортный слой (спека §4, §5.3, §7.4).
//!
//! Здесь заканчивается «байты по проводу» и начинается протокол. Граница проведена так:
//!
//! * [`codec`] не знает типов сообщений — он передаёт кадры v8 как есть, потому что подпись
//!   считается по каноническим байтам тела (§5.2), и перекодирование на транспорте меняло бы
//!   вход проверки;
//! * [`keys`] связывает прикладной Ed25519-ключ с libp2p-идентичностью, не вводя собственной
//!   деривации `PeerId` (§4.1);
//! * [`handshake`] проверяет `NodeCert` и его привязку к транспорту (§4.2);
//! * [`door`] даёт имени причины отказа конечный тип и локальный журнал причин (§4.2; `E-0095`);
//! * [`provider_cache`] держит конечную таблицу провайдеров шарда (§7.4, §P5; `E-0091`);
//! * [`service`] владеет `ShardNode`'ами, Kademlia-провайдерами шардов (§7.4), gossip-темами
//!   и event loop'ом; вся протокольная логика остаётся в `vecdht-node`;
//! * [`agent`] — клиентская половина §12: publish/find/session поверх того же транспорта, чтобы
//!   CLI и SDK не собирали кадры и не дублировали проверки подписей.
//!
//! Транспорт — QUIC с TCP+Noise+Yamux запасным путём, как в P1 §19.1. `request-response`
//! несёт кадры, потому что `Find` отвечает батчем (`MatchResult` + приёмы), и ответ «сколько
//! угодно кадров» — не поток, а сообщение с счётчиком.
//!
//! Честная граница v1: relay/DCUtR в спеке описаны (§16.3), но здесь не подняты; адреса
//! распространяются Kademlia/identify, а не hole-punching. Это не влияет на локальные
//! гейты, но означает, что путь через NAT без прямого dial пока не проверен.

#![forbid(unsafe_code)]

pub mod agent;
pub mod behaviour;
pub mod codec;
pub mod door;
pub mod handshake;
pub mod keys;
pub mod provider_cache;
pub mod service;

pub use agent::{
    Agent, AgentConfig, AgentError, FindOutcome, FindQuery, FoundMatch, NetworkParams,
    PublishReceipt, PublishRequest, RendezvousGrant, SessionInfo, ShardAnswer, ShardFailure,
};
pub use door::{DoorLedger, DoorReason};
pub use handshake::{HandshakeError, PeerIdentity};
pub use service::{shard_topic, NetConfig, NetError, NetService, Step};
