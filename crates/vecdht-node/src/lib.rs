//! VecDHT v8 — узел индексирующего шарда (спека §9.2–§9.8, §10, §12).
//!
//! Crate делится ровно по границе ответственности, а не по размеру файлов:
//!
//! * [`candidates`] — кто вообще имеет право держать шард (§9.3);
//! * [`membership`] — самовалидируемая цепочка эпизод и её пороги (§9.2);
//! * [`lease`] — грант primary и fencing по `epoch` (§9.8);
//! * [`snapshot`] — кусковая передача снапшота и установка с диска (§9.5, §10.4);
//! * [`node`] — машина состояний шарда, собирающая всё предыдущее;
//! * [`admission`] — локальная политика приёма и вытеснение (§11.3);
//! * [`rendezvous`] — одноразовые приёмы §12.3: выпуск на шарде и расход у цели;
//! * [`session`] — подписанные тексты интентов между агентами (§6.6, §12.4);
//! * [`net`] — транспорт в процессе, на котором стоят гейты §19.1;
//! * [`testing`] — дешёвый PoW и эталонное genesis для этих гейтов.
//!
//! Библиотеки здесь нет в смысле «асинхронного сервиса»: ни одного потока, ни одного таймера, ни
//! одного wall-clock внутри протокола. Время приходит параметром `now_bucket` извне (§9.6), и
//! именно поэтому handoff измерим: `kill primary → handoff < 10 с` — это счётчик бакетов, а не
//! `sleep` в тесте.
//!
//! ```
//! use vecdht_node::{Holder, Params, testing};
//!
//! let params: Params = testing::params(8);
//! let roster: Vec<Holder> = testing::holders(&[1, 2, 3]);
//! // Состав шарда — функция от эпохи, а не договорённость участников (§9.3).
//! let list = vecdht_node::expected_update(1, 0, &roster, params.r, 0, 100);
//! let upd = testing::genesis_update(0, &[1, 2, 3], 100);
//! let chain = testing::chain(0, 8);
//! let m = chain.validate_with_candidates(None, &upd, &roster, 0).unwrap();
//! assert_eq!(m.primary(), Some(list.members[0].owner_ed25519));
//! ```

#![forbid(unsafe_code)]

pub mod admission;
pub mod candidates;
pub mod config;
pub mod denylist;
pub mod lease;
pub mod membership;
pub mod metrics;
pub mod net;
pub mod node;
pub mod rendezvous;
pub mod revocation;
pub mod session;
pub mod snapshot;
pub mod testing;

pub use admission::{Admission, Candidate, Evictor, SharedAdmission, Verdict};
pub use candidates::{expected_update, keeper, members, Holder, MemberList};
pub use config::{bucket_of, buckets, Clock, ParamError, Params};
pub use denylist::MAX_DENYLIST;
pub use lease::{Lease, LeaseError};
pub use membership::{Chain, Membership, MembershipError, GENESIS_EPOCH};
pub use net::{Addr, Envelope, LocalNet};
pub use node::{NodeError, ShardNode};
pub use rendezvous::{AcceptError, Grant, Issuer, Spend, MAX_ACCEPTS};
pub use revocation::{Insert as RevocationInsert, RevocationError, Revocations, MAX_REVOCATIONS};
pub use session::{IntentText, TextError};
