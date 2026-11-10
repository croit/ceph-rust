// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pg_notify_t, pg_query_t, pg_lease_t, pg_lease_ack_t (spec peering.md 2.6).

use crate::history::PgHistory;
use crate::info::PgInfo;
use crate::intervals::PastIntervals;
use denc::types::{Eversion, ShardId, Timespan};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Result};

/// PG feature bits advertised in notifies (`osd/pg_features.h`).
pub mod pg_features {
    /// pg_committed_to (PCT) support.
    pub const PCT: u64 = 1;
    /// All features of a classic main OSD.
    pub const CLASSIC_ALL: u64 = 1;
}

/// pg_notify_t, ENCODE v4 compat 2.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PgNotify {
    /// Epoch of the query being answered, or the sender's epoch if unsolicited.
    pub query_epoch: u32,
    pub epoch_sent: u32,
    pub info: PgInfo,
    /// Target shard.
    pub to: ShardId,
    /// Must equal `info.pgid.shard`.
    pub from: ShardId,
    pub past_intervals: PastIntervals,
    pub pg_features: u64,
}

impl PgNotify {
    pub const STRUCT_V: u8 = 4;
    pub const STRUCT_COMPAT: u8 = 2;
    /// Reply for a PG we do not have (peering.md 5.4).
    pub fn dne(info: PgInfo, to: ShardId, query_epoch: u32, epoch_sent: u32) -> Self {
        let from = info.pgid.shard;
        PgNotify {
            query_epoch,
            epoch_sent,
            info,
            to,
            from,
            past_intervals: PastIntervals::default(),
            pg_features: pg_features::CLASSIC_ALL,
        }
    }
}

impl Encode for PgNotify {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            e.u32(self.query_epoch)?;
            e.u32(self.epoch_sent)?;
            self.info.encode(e)?;
            self.to.encode(e)?;
            self.from.encode(e)?;
            self.past_intervals.encode(e)?;
            e.u64(self.pg_features)
        })
    }
}
impl<'a> Decode<'a> for PgNotify {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(2, Self::STRUCT_COMPAT, |d, v| {
            Ok(PgNotify {
                query_epoch: d.u32()?,
                epoch_sent: d.u32()?,
                info: PgInfo::decode(d)?,
                to: ShardId::decode(d)?,
                from: ShardId::decode(d)?,
                past_intervals: if v >= 3 {
                    PastIntervals::decode(d)?
                } else {
                    PastIntervals::default()
                },
                pg_features: if v >= 4 { d.u64()? } else { 0 },
            })
        })
    }
}

/// pg_query_t type: raw i32 (a default-constructed reference query carries -1, so every value
/// round-trips).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueryType(pub i32);
impl QueryType {
    pub const INFO: QueryType = QueryType(0);
    pub const LOG: QueryType = QueryType(1);
    /// Unused on the wire by main.
    pub const MISSING: QueryType = QueryType(4);
    pub const FULLLOG: QueryType = QueryType(5);
}

/// pg_query_t, ENCODE v3 compat 3 (featured; features are ignored).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgQuery {
    pub ty: QueryType,
    /// Meaningful for LOG only.
    pub since: Eversion,
    /// Sender's history; the receiver merges it.
    pub history: PgHistory,
    pub epoch_sent: u32,
    pub to: ShardId,
    pub from: ShardId,
}

impl PgQuery {
    pub const STRUCT_V: u8 = 3;
    pub const STRUCT_COMPAT: u8 = 3;
}

impl Encode for PgQuery {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            e.i32(self.ty.0)?;
            self.since.encode(e)?;
            self.history.encode(e)?;
            e.u32(self.epoch_sent)?;
            self.to.encode(e)?;
            self.from.encode(e)
        })
    }
}
impl<'a> Decode<'a> for PgQuery {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(3, Self::STRUCT_COMPAT, |d, _| {
            Ok(PgQuery {
                ty: QueryType(d.i32()?),
                since: Eversion::decode(d)?,
                history: PgHistory::decode(d)?,
                epoch_sent: d.u32()?,
                to: ShardId::decode(d)?,
                from: ShardId::decode(d)?,
            })
        })
    }
}

/// pg_lease_t (v1, c1). Durations are relative to the sender's monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PgLease {
    pub readable_until: Timespan,
    pub readable_until_ub: Timespan,
    pub interval: Timespan,
}
impl Encode for PgLease {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.readable_until.encode(e)?;
            self.readable_until_ub.encode(e)?;
            self.interval.encode(e)
        })
    }
}
impl<'a> Decode<'a> for PgLease {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(PgLease {
                readable_until: Timespan::decode(d)?,
                readable_until_ub: Timespan::decode(d)?,
                interval: Timespan::decode(d)?,
            })
        })
    }
}

/// pg_lease_ack_t (v1, c1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PgLeaseAck {
    pub readable_until_ub: Timespan,
}
impl Encode for PgLeaseAck {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| self.readable_until_ub.encode(e))
    }
}
impl<'a> Decode<'a> for PgLeaseAck {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(PgLeaseAck {
                readable_until_ub: Timespan::decode(d)?,
            })
        })
    }
}
