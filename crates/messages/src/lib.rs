// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! messages: payload encode/decode for the M1 Ceph messages (spec: doc/spec/osd-lifecycle.md,
//! msgr2.md section 8/15, cephx.md section 9). Sans-IO: operates on the front/middle/data
//! segments of a msgr2 MESSAGE frame; the 41-byte `ceph_msg_header2` is [`Header2`].
//!
//! Every message type implements [`Message`] (`MSG_TYPE`, header `HEAD_VERSION`/`COMPAT_VERSION`,
//! `encode(features)`, `decode(header_version, front, middle, data)`); [`decode_any`] dispatches
//! on the header type id, unknown types come back as [`Message::Unknown`] (log + drop, never reset).

mod any;
mod command_reply;
mod dedup;
mod header;
mod mgr;
mod mon;
mod msg;
mod osd;
mod pool;
mod pool_stats;
mod statfs;
pub mod types;

pub use any::{
    Message as AnyMessage, SHARED_FRONT_MIN, decode_any, decode_with_header,
    decode_with_header_owned, decode_with_header_shared,
};
pub use command_reply::CommandReplyView;
pub use dedup::*;
pub use header::Header2;
pub use mgr::*;
pub use mon::*;
pub use msg::{Message, Segments, front_segments, front_with};
pub use osd::*;
pub use pool::*;
pub use pool_stats::*;
pub use statfs::*;
pub use types::*;

pub use denc::{Error, Result};

/// Message type ids (msgr2.md section 15).
pub mod ty {
    pub const PING: u16 = 2;
    /// Dedup info listing (croit fork `wip-ifed-dedup`).
    pub const OSD_DEDUP_LIST: u16 = 137;
    pub const OSD_DEDUP_LIST_REPLY: u16 = 138;
    pub const MON_MAP: u16 = 4;
    pub const MON_GET_MAP: u16 = 5;
    pub const MON_GET_OSDMAP: u16 = 6;
    pub const MON_SUBSCRIBE: u16 = 15;
    pub const MON_SUBSCRIBE_ACK: u16 = 16;
    pub const GET_POOL_STATS: u16 = 58;
    pub const GET_POOL_STATS_REPLY: u16 = 59;
    pub const STATFS: u16 = 13;
    pub const STATFS_REPLY: u16 = 14;
    pub const AUTH: u16 = 17;
    pub const AUTH_REPLY: u16 = 18;
    pub const MON_GET_VERSION: u16 = 19;
    pub const MON_GET_VERSION_REPLY: u16 = 20;
    pub const OSD_MAP: u16 = 41;
    pub const POOLOP_REPLY: u16 = 48;
    pub const POOLOP: u16 = 49;
    pub const MON_COMMAND: u16 = 50;
    pub const MON_COMMAND_ACK: u16 = 51;
    pub const LOG: u16 = 52;
    pub const LOG_ACK: u16 = 53;
    pub const CONFIG: u16 = 62;
    pub const GET_CONFIG: u16 = 63;
    pub const OSD_PING: u16 = 70;
    pub const OSD_BOOT: u16 = 71;
    pub const OSD_FAILURE: u16 = 72;
    pub const OSD_ALIVE: u16 = 73;
    pub const OSD_MARK_ME_DOWN: u16 = 74;
    pub const OSD_FULL: u16 = 75;
    pub const MON_GET_PURGED_SNAPS: u16 = 76;
    pub const MON_GET_PURGED_SNAPS_REPLY: u16 = 77;
    pub const OSD_PG_TEMP: u16 = 78;
    pub const OSD_BEACON: u16 = 79;
    pub const PGSTATS: u16 = 87;
    pub const COMMAND: u16 = 97;
    pub const COMMAND_REPLY: u16 = 98;
    pub const OSD_PG_CREATED: u16 = 116;
    pub const OSD_PG_READY_TO_MERGE: u16 = 122;
    pub const OSD_MARK_ME_DEAD: u16 = 123;
    pub const MGR_OPEN: u16 = 0x700;
    pub const MGR_CONFIGURE: u16 = 0x701;
    pub const MGR_REPORT: u16 = 0x702;
    pub const MGR_MAP: u16 = 0x704;
    pub const MGR_CLOSE: u16 = 0x708;
    pub const MGR_COMMAND: u16 = 0x709;
    pub const MGR_COMMAND_REPLY: u16 = 0x70a;
}
