// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! replwire: object_info_t, SnapSet, ObjectStore Transaction wire, recovery ops, MOSDRepOp/Push/Pull/
//! Backfill/Reserve and scrub messages, EC shard scrub digests (spec: replication.md, scrub.md, ec.md 7.7).
//!
//! Sans-IO. Everything owned by sibling crates (pg_log_entry_t, pg_stat_t, hit-set history) stays
//! opaque bytes here; the osd layer decodes it with `pgwire`.

pub mod ecscrub;
pub mod interval;
pub mod msgs;
pub mod oi;
pub mod pgmeta;
pub mod recovery;
pub mod scrubmsgs;
pub mod snap;
pub mod txn;

pub use interval::IntervalSet;
pub use msgs::*;
pub use oi::{ChunkInfo, ObjectInfo, ObjectManifest, WatchInfo, flag};
pub use recovery::{ObjectRecoveryInfo, ObjectRecoveryProgress, PullOp, PushOp, PushReplyOp};
pub use scrubmsgs::{
    MOSDRepScrub, MOSDRepScrubMap, MOSDScrub2, MOSDScrubReserve, ScrubMap, ScrubObject,
};
pub use snap::{SnapContext, SnapSet};
pub use txn::{
    Cx, DEFAULT_PAGE, Data, LazyOp, OmapKv, OmapKvIter, Op, OpStream, Ox, SPLIT_MIN, Transaction,
    TxnOp, TxnOpG,
};

pub use denc::{Error, Result};

use bytes::Bytes;
use messages::{Message, Segments};

messages::message_enum! {
    /// Any replication data-path message.
    #[derive(Debug, Clone, PartialEq)]
    pub enum ReplMsg {
    RepOp => MOSDRepOp,
    RepOpReply => MOSDRepOpReply,
    UpdateLogMissing => MOSDPGUpdateLogMissing,
    UpdateLogMissingReply => MOSDPGUpdateLogMissingReply,
    Pct => MOSDPGPCT,
    Push => MOSDPGPush,
    PushReply => MOSDPGPushReply,
    Pull => MOSDPGPull,
    RecoveryDelete => MOSDPGRecoveryDelete,
    RecoveryDeleteReply => MOSDPGRecoveryDeleteReply,
    Scan => MOSDPGScan,
    Backfill => MOSDPGBackfill,
    BackfillRemove => MOSDPGBackfillRemove,
    BackfillReserve => MBackfillReserve,
    RecoveryReserve => MRecoveryReserve,
    ScrubReserve => MOSDScrubReserve,
    RepScrub => MOSDRepScrub,
    RepScrubMap => MOSDRepScrubMap,
    Scrub2 => MOSDScrub2,
    ForceRecovery => MOSDForceRecovery,
    }
}

/// Decode a replication message by header type id and version. `Ok(None)` = not one of ours.
pub fn decode_repl(ty: u16, version: u16, seg: &Segments) -> Result<Option<ReplMsg>> {
    if ty == <MOSDRepOp as Message>::MSG_TYPE {
        // the transaction stays a shared slice of the rx buffer (applied locally, no copy)
        let m = MOSDRepOp::decode_shared(
            version,
            &seg.front_bytes()?,
            Bytes::copy_from_slice(&seg.middle),
            seg.data.clone(),
        )?;
        return Ok(Some(ReplMsg::RepOp(m)));
    }
    if ty == <MOSDPGPush as Message>::MSG_TYPE
        && let Some(f) = seg.front_shared()
    {
        // a large received front is one shared rx run: keep every push payload a slice of it (no copy)
        return MOSDPGPush::decode_shared(version, f).map(|m| Some(ReplMsg::Push(m)));
    }
    ReplMsg::decode_known(ty, version, &seg.front_bytes()?, &seg.middle, &seg.data).transpose()
}
