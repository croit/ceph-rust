// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pg_info_t and pg_hit_set_history_t (spec peering.md 2.3).

use crate::IntervalSet;
use crate::history::PgHistory;
use crate::stat::PgStat;
use denc::types::{Eversion, Hobject, PgT, ShardId, SpgT, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Result};
use std::collections::BTreeMap;

/// pg_hit_set_info_t (v2, c1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgHitSetInfo {
    pub begin: UTime,
    pub end: UTime,
    pub version: Eversion,
    pub using_gmt: bool,
}
impl Default for PgHitSetInfo {
    fn default() -> Self {
        PgHitSetInfo {
            begin: UTime::default(),
            end: UTime::default(),
            version: Eversion::default(),
            using_gmt: true,
        }
    }
}
impl Encode for PgHitSetInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(2, 1, |e| {
            self.begin.encode(e)?;
            self.end.encode(e)?;
            self.version.encode(e)?;
            e.bool(self.using_gmt)
        })
    }
}
impl<'a> Decode<'a> for PgHitSetInfo {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, v| {
            let begin = UTime::decode(d)?;
            let end = UTime::decode(d)?;
            let version = Eversion::decode(d)?;
            let using_gmt = if v >= 2 { d.bool()? } else { false };
            Ok(PgHitSetInfo {
                begin,
                end,
                version,
                using_gmt,
            })
        })
    }
}

/// pg_hit_set_history_t (v1, c1). Always empty for croit-flashstore-osd; the wire still carries the legacy
/// `current_last_stamp` (utime) and `current_info` which are written as zeros and ignored on read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgHitSetHistory {
    pub current_last_update: Eversion,
    pub history: Vec<PgHitSetInfo>,
}
impl Encode for PgHitSetHistory {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.current_last_update.encode(e)?;
            UTime::default().encode(e)?;
            PgHitSetInfo::default().encode(e)?;
            self.history.encode(e)
        })
    }
}
impl<'a> Decode<'a> for PgHitSetHistory {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            let current_last_update = Eversion::decode(d)?;
            UTime::decode(d)?;
            PgHitSetInfo::decode(d)?;
            Ok(PgHitSetHistory {
                current_last_update,
                history: Vec::decode(d)?,
            })
        })
    }
}

/// pg_info_t, ENCODE v34 compat 26.
#[derive(Debug, Clone, PartialEq)]
pub struct PgInfo {
    /// pg + shard (`pgid.pgid` is field 1, `pgid.shard` field 12 on the wire).
    pub pgid: SpgT,
    pub last_update: Eversion,
    pub last_complete: Eversion,
    pub log_tail: Eversion,
    pub stats: PgStat,
    pub history: PgHistory,
    pub purged_snaps: IntervalSet<u64>,
    pub last_epoch_started: u32,
    pub last_user_version: u64,
    pub hit_set: PgHitSetHistory,
    /// `Hobject::MAX()` = fully backfilled; `Hobject::MIN()` = backfill not started.
    pub last_backfill: Hobject,
    pub last_interval_started: u32,
    /// EC partial writes; empty for replicated pools.
    pub partial_writes_last_complete: BTreeMap<ShardId, (Eversion, Eversion)>,
    /// Replicated primary writes the activation epoch here; receivers ignore it.
    pub partial_writes_last_complete_epoch: u32,
}

impl Default for PgInfo {
    fn default() -> Self {
        PgInfo::new(SpgT::default())
    }
}

impl PgInfo {
    pub const STRUCT_V: u8 = 34;
    pub const STRUCT_COMPAT: u8 = 26;

    /// Info for `pgid` with everything default and `last_backfill` = MAX. With
    /// `history.epoch_created == 0` this is the DNE reply (peering.md 2.3).
    pub fn new(pgid: SpgT) -> Self {
        PgInfo {
            pgid,
            last_update: Default::default(),
            last_complete: Default::default(),
            log_tail: Default::default(),
            stats: Default::default(),
            history: Default::default(),
            purged_snaps: Default::default(),
            last_epoch_started: 0,
            last_user_version: 0,
            hit_set: Default::default(),
            last_backfill: Hobject::MAX(),
            last_interval_started: 0,
            partial_writes_last_complete: Default::default(),
            partial_writes_last_complete_epoch: 0,
        }
    }
    /// "PG does not exist" reply info.
    pub fn dne(pgid: SpgT) -> Self {
        Self::new(pgid)
    }
    pub fn is_empty(&self) -> bool {
        self.last_update.version == 0
    }
    pub fn dne_flag(&self) -> bool {
        self.history.epoch_created == 0
    }
    pub fn has_missing(&self) -> bool {
        self.last_complete != self.last_update
    }
    pub fn is_incomplete(&self) -> bool {
        self.last_backfill != Hobject::MAX()
    }
}

impl Encode for PgInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            self.pgid.pgid.encode(e)?;
            self.last_update.encode(e)?;
            self.last_complete.encode(e)?;
            self.log_tail.encode(e)?;
            Hobject::default().encode(e)?; // legacy last_backfill
            self.stats.encode(e)?;
            self.history.encode(e)?;
            self.purged_snaps.encode(e)?;
            e.u32(self.last_epoch_started)?;
            e.u64(self.last_user_version)?;
            self.hit_set.encode(e)?;
            self.pgid.shard.encode(e)?;
            self.last_backfill.encode(e)?;
            e.bool(true)?; // last_backfill_bitwise
            e.u32(self.last_interval_started)?;
            self.partial_writes_last_complete.encode(e)?;
            e.u32(self.partial_writes_last_complete_epoch)
        })
    }
}

impl<'a> Decode<'a> for PgInfo {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(26, Self::STRUCT_COMPAT, |d, v| {
            let pg = PgT::decode(d)?;
            let last_update = Eversion::decode(d)?;
            let last_complete = Eversion::decode(d)?;
            let log_tail = Eversion::decode(d)?;
            Hobject::decode(d)?;
            let stats = PgStat::decode(d)?;
            let history = PgHistory::decode(d)?;
            let purged_snaps = IntervalSet::decode(d)?;
            let last_epoch_started = d.u32()?;
            let last_user_version = d.u64()?;
            let hit_set = PgHitSetHistory::decode(d)?;
            let shard = ShardId::decode(d)?;
            let last_backfill = Hobject::decode(d)?;
            d.bool()?;
            let last_interval_started = if v >= 32 {
                d.u32()?
            } else {
                last_epoch_started
            };
            let partial_writes_last_complete = if v >= 33 {
                Decode::decode(d)?
            } else {
                Default::default()
            };
            let partial_writes_last_complete_epoch = if v >= 34 { d.u32()? } else { 0 };
            Ok(PgInfo {
                pgid: SpgT { pgid: pg, shard },
                last_update,
                last_complete,
                log_tail,
                stats,
                history,
                purged_snaps,
                last_epoch_started,
                last_user_version,
                hit_set,
                last_backfill,
                last_interval_started,
                partial_writes_last_complete,
                partial_writes_last_complete_epoch,
            })
        })
    }
}
