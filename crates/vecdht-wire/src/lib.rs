//! VecDHT v8 — кодек и набор сообщений (спека §5).
//!
//! Один ручной little-endian кодек с TLV-хвостом. Реализован ровно один раз, в Rust:
//! PythonSDK вызывает его через PyO3 и сам ничего не кодирует. Так межъязыковой риск
//! расхождения канонических байтов исчезает по построению (в v7.5 он существовал и с prost,
//! потому что protobuf не byte-deterministic).
//!
//! Плавающая точка в этом crate отсутствует: все числа целые.

#![forbid(unsafe_code)]

pub mod cert;
pub mod codec;
pub mod constants;
pub mod frame;
pub mod messages;

pub use cert::{NodeCert, CERT_VERSION, MAX_CERT_SHARDS};

pub use codec::{DecodeError, Reader, Writer, DIM, MAX_BODY_LEN, MAX_VAR_LEN};
pub use constants::{
    shard_of, shard_provider_key, CLUSTERS_PER_SHARD, MAX_D2, NLIST, Q_SCALE, SHARDS,
    TIME_BUCKET_SEC,
};
pub use frame::{
    decode_frame, encode_frame, parse_header, sig_input, Frame, Header, Kind, ED25519_SIG_LEN,
    FLAG_RESERVED_MASK, FLAG_SIGNED, MAX_SIG_LEN, PROTOCOL_VERSION,
};
pub use messages::{
    domain, err_code, ArtifactAnnounce, CertRevoke, Codec, DeleteOp, Find, GcTick, Handshake,
    InsertOp, IntentTextRequest, IntentTextResponse, LeaseGrant, LeaveNotice, Match, MatchResult,
    Member,
    MembershipUpdate, OpKind, ProtocolError, Publish, PublishAck, RendezvousAccept, ReplicateOp,
    Role, Tlv, TimeMark, WalPullRequest, WalPullResponse, MAX_INTENT_TEXT_BYTES, TLV_BATCH_HINT,
    TLV_ROLE_SLOT,
};
