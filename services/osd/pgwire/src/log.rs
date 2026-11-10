// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pg_log_entry_t, pg_log_t, pg_log_dup_t, ObjectModDesc, ObjectCleanRegions
//! (spec pglog.md 2, 3).

use crate::IntervalSet;
use denc::types::{Eversion, Hobject, OsdReqId, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};
use std::collections::{BTreeMap, VecDeque};

/// `pg_log_entry_t` op values (pglog.md 2.1). Kept as a raw i32 newtype because decoding must
/// round-trip every byte pattern (the default-constructed entry has op 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LogOp(pub i32);

impl LogOp {
    pub const MODIFY: LogOp = LogOp(1);
    pub const CLONE: LogOp = LogOp(2);
    pub const DELETE: LogOp = LogOp(3);
    pub const LOST_REVERT: LogOp = LogOp(5);
    pub const LOST_DELETE: LogOp = LogOp(6);
    pub const LOST_MARK: LogOp = LogOp(7);
    pub const PROMOTE: LogOp = LogOp(8);
    pub const CLEAN: LogOp = LogOp(9);
    pub const ERROR: LogOp = LogOp(10);
    pub const REPLACE: LogOp = LogOp(11);

    /// 1..=11 except the obsolete 4.
    pub fn is_known(self) -> bool {
        (1..=11).contains(&self.0) && self.0 != 4
    }
    pub fn is_update(self) -> bool {
        matches!(
            self,
            Self::CLONE
                | Self::MODIFY
                | Self::PROMOTE
                | Self::CLEAN
                | Self::LOST_REVERT
                | Self::LOST_MARK
                | Self::REPLACE
        )
    }
    pub fn is_delete(self) -> bool {
        matches!(self, Self::DELETE | Self::LOST_DELETE)
    }
    pub fn is_error(self) -> bool {
        self == Self::ERROR
    }
    /// Name as the `dump_json` of the reference prints it.
    pub fn name(self) -> &'static str {
        match self {
            Self::MODIFY => "modify",
            Self::CLONE => "clone",
            Self::DELETE => "delete",
            Self::LOST_REVERT => "l_revert",
            Self::LOST_DELETE => "l_delete",
            Self::LOST_MARK => "l_mark",
            Self::PROMOTE => "promote",
            Self::CLEAN => "clean",
            Self::ERROR => "error",
            Self::REPLACE => "replace",
            _ => "unknown",
        }
    }
}

/// `shard_id_set`: 128-bit bitset, wire = two varints (one per 64-bit word).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShardIdSet(pub [u64; 2]);
impl ShardIdSet {
    pub fn is_empty(&self) -> bool {
        self.0 == [0, 0]
    }
}
impl Encode for ShardIdSet {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.varint(self.0[0])?;
        e.varint(self.0[1])
    }
}
impl<'a> Decode<'a> for ShardIdSet {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(ShardIdSet([d.varint()?, d.varint()?]))
    }
}

/// ObjectModDesc: opaque for replicated pools (spec 2.2). The body `bl` of EC rollback info is
/// stored/forwarded verbatim. `version` is the envelope version (== compat).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectModDesc {
    pub version: u8,
    pub can_local_rollback: bool,
    pub rollback_info_completed: bool,
    pub bl: Vec<u8>,
}
impl Default for ObjectModDesc {
    /// Matches the reference default: rollbackable, no info yet.
    fn default() -> Self {
        ObjectModDesc {
            version: 1,
            can_local_rollback: true,
            rollback_info_completed: false,
            bl: vec![],
        }
    }
}
impl ObjectModDesc {
    /// What a replicated primary ships on every entry: `01 01 06 00 00 00 | 00 | 00 | 00 00 00 00`.
    pub fn unrollbackable() -> Self {
        ObjectModDesc {
            version: 1,
            can_local_rollback: false,
            rollback_info_completed: false,
            bl: vec![],
        }
    }
}
impl Encode for ObjectModDesc {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(self.version, self.version, |e| {
            e.bool(self.can_local_rollback)?;
            e.bool(self.rollback_info_completed)?;
            e.bytes(&self.bl)
        })
    }
}
impl<'a> Decode<'a> for ObjectModDesc {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        // struct_v == compat for this type: read it from the envelope header without consuming.
        let rest = d.peek_rest();
        let version = *rest.first().ok_or(Error::Eof {
            needed: 1,
            remaining: 0,
        })?;
        d.versioned_min(1, u8::MAX, |d, _| {
            Ok(ObjectModDesc {
                version,
                can_local_rollback: d.bool()?,
                rollback_info_completed: d.bool()?,
                bl: d.bytes()?.to_vec(),
            })
        })
    }
}

/// ObjectCleanRegions (v1, c1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectCleanRegions {
    /// Byte ranges unchanged: start -> length.
    pub clean_offsets: IntervalSet<u64>,
    pub clean_omap: bool,
    pub new_object: bool,
}

impl Default for ObjectCleanRegions {
    /// Nothing known dirty: `[0, 2^64-1)`, omap clean, not new.
    fn default() -> Self {
        ObjectCleanRegions {
            clean_offsets: BTreeMap::from([(0, u64::MAX)]),
            clean_omap: true,
            new_object: false,
        }
    }
}

impl ObjectCleanRegions {
    /// `osd_object_clean_region_max_num_intervals` default.
    pub const MAX_INTERVALS: usize = 10;

    /// Everything dirty: always a safe value to ship.
    pub fn fully_dirty() -> Self {
        ObjectCleanRegions {
            clean_offsets: BTreeMap::new(),
            clean_omap: false,
            new_object: true,
        }
    }
    pub fn is_clean_range(&self, off: u64, len: u64) -> bool {
        let end = off.saturating_add(len);
        self.clean_offsets
            .range(..=off)
            .next_back()
            .is_some_and(|(s, l)| s.saturating_add(*l) >= end)
    }
    /// Remove `[off, off+len)` from the clean set, then limit the number of intervals.
    pub fn mark_data_region_dirty(&mut self, off: u64, len: u64) {
        if len == 0 {
            return;
        }
        let end = off.saturating_add(len);
        let mut out = BTreeMap::new();
        for (s, l) in &self.clean_offsets {
            let e = s.saturating_add(*l);
            if e <= off || *s >= end {
                out.insert(*s, *l);
                continue;
            }
            if *s < off {
                out.insert(*s, off - *s);
            }
            if e > end {
                out.insert(end, e - end);
            }
        }
        self.clean_offsets = out;
        self.trim(Self::MAX_INTERVALS);
    }
    pub fn mark_omap_dirty(&mut self) {
        self.clean_omap = false;
    }
    pub fn mark_new_object(&mut self) {
        self.new_object = true;
    }
    /// Intersect clean sets, AND clean_omap (`new_object` unchanged). One merge sweep over both sorted sets: linear in
    /// their sizes (a peer's set may hold many intervals); with overlapping (malformed) input every piece still lies in
    /// both sets, so the result never claims more clean bytes than either side.
    pub fn merge(&mut self, o: &ObjectCleanRegions) {
        let mut out = BTreeMap::new();
        let (mut a, mut b) = (
            self.clean_offsets.iter().peekable(),
            o.clean_offsets.iter().peekable(),
        );
        while let (Some(&(s, l)), Some(&(os, ol))) = (a.peek(), b.peek()) {
            let (e, oe) = (s.saturating_add(*l), os.saturating_add(*ol));
            let (x, y) = ((*s).max(*os), e.min(oe));
            if x < y {
                out.insert(x, y - x);
            }
            if e <= oe {
                a.next();
            } else {
                b.next();
            }
        }
        self.clean_offsets = out;
        self.clean_omap &= o.clean_omap;
        self.trim(Self::MAX_INTERVALS);
    }
    /// Keep the `max` longest intervals: drops the shortest, the earlier start first among equal lengths. One selection
    /// pass (linear), whatever the number of intervals.
    pub fn trim(&mut self, max: usize) {
        let n = self.clean_offsets.len();
        if n <= max {
            return;
        }
        if max == 0 {
            self.clean_offsets.clear();
            return;
        }
        let mut v: Vec<(u64, u64)> = self.clean_offsets.iter().map(|(s, l)| (*l, *s)).collect();
        v.select_nth_unstable(n - max);
        self.clean_offsets = v[n - max..].iter().map(|(l, s)| (*s, *l)).collect();
    }
}
impl Encode for ObjectCleanRegions {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.clean_offsets.encode(e)?;
            e.bool(self.clean_omap)?;
            e.bool(self.new_object)
        })
    }
}
impl<'a> Decode<'a> for ObjectCleanRegions {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(ObjectCleanRegions {
                clean_offsets: Decode::decode(d)?,
                clean_omap: d.bool()?,
                new_object: d.bool()?,
            })
        })
    }
}

/// pg_log_op_return_item_t: i32 rval + bufferlist (no envelope).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogOpReturnItem {
    pub rval: i32,
    pub outdata: Vec<u8>,
}
impl Encode for LogOpReturnItem {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.i32(self.rval)?;
        e.bytes(&self.outdata)
    }
}
impl<'a> Decode<'a> for LogOpReturnItem {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(LogOpReturnItem {
            rval: d.i32()?,
            outdata: d.bytes()?.to_vec(),
        })
    }
}

/// pg_log_entry_t, ENCODE v15 compat 4.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogEntry {
    pub op: LogOp,
    pub soid: Hobject,
    pub version: Eversion,
    /// Version of the object this entry replaced (0'0 = did not exist).
    pub prior_version: Eversion,
    /// Only for `LOST_REVERT` (wire slot #4; `prior_version` then travels in slot #7).
    pub reverting_to: Eversion,
    pub reqid: OsdReqId,
    pub mtime: UTime,
    /// CLONE: encoded `vector<snapid_t>`; else usually empty.
    pub snaps: Vec<u8>,
    pub user_version: u64,
    pub mod_desc: ObjectModDesc,
    pub extra_reqids: Vec<(OsdReqId, u64)>,
    /// Written at its own slot for ERROR entries, at the v14 slot otherwise.
    pub return_code: i32,
    /// Return codes of `extra_reqids`, keyed by its index; an absent index means 0. Only on the wire when
    /// `extra_reqids` is non-empty.
    pub extra_reqid_return_codes: BTreeMap<u32, i32>,
    pub clean_regions: ObjectCleanRegions,
    pub op_returns: Vec<LogOpReturnItem>,
    pub written_shards: ShardIdSet,
    /// Second, unused `shard_id_set` of v15 (always written empty).
    pub shards_unused: ShardIdSet,
}

impl LogEntry {
    pub const STRUCT_V: u8 = 15;
    pub const STRUCT_COMPAT: u8 = 4;
    /// Oldest struct_v we decode (v<7 carried `snaps` only for CLONE in another layout).
    pub const OLDEST_V: u8 = 7;

    /// Entry for a replicated pool as a primary ships it: unrollbackable mod_desc and the default clean regions
    /// (nothing known dirty); pass [`Self::with_regions`] to state the clean ranges.
    pub fn new(op: LogOp, soid: Hobject, version: Eversion, prior_version: Eversion) -> Self {
        Self::with_regions(op, soid, version, prior_version, Default::default())
    }
    /// [`Self::new`] with the given clean regions.
    pub fn with_regions(
        op: LogOp,
        soid: Hobject,
        version: Eversion,
        prior_version: Eversion,
        clean_regions: ObjectCleanRegions,
    ) -> Self {
        LogEntry {
            op,
            soid,
            version,
            prior_version,
            reverting_to: Default::default(),
            reqid: Default::default(),
            mtime: Default::default(),
            snaps: vec![],
            user_version: 0,
            mod_desc: ObjectModDesc::unrollbackable(),
            extra_reqids: vec![],
            return_code: 0,
            extra_reqid_return_codes: BTreeMap::new(),
            clean_regions,
            op_returns: vec![],
            written_shards: Default::default(),
            shards_unused: Default::default(),
        }
    }
    /// Starting point of [`Decode`]: all fields empty, `clean_regions` fully dirty. The default clean regions are
    /// never built because the wire value replaces them (v<13 has none = fully dirty).
    fn decode_base(op: LogOp) -> Self {
        LogEntry {
            op,
            soid: Hobject::default(),
            version: Eversion::default(),
            prior_version: Eversion::default(),
            reverting_to: Eversion::default(),
            reqid: OsdReqId::default(),
            mtime: UTime::default(),
            snaps: Vec::new(),
            user_version: 0,
            mod_desc: ObjectModDesc::default(),
            extra_reqids: Vec::new(),
            return_code: 0,
            extra_reqid_return_codes: BTreeMap::new(),
            clean_regions: ObjectCleanRegions::fully_dirty(),
            op_returns: Vec::new(),
            written_shards: ShardIdSet::default(),
            shards_unused: ShardIdSet::default(),
        }
    }
    pub fn is_update(&self) -> bool {
        self.op.is_update()
    }
    pub fn is_delete(&self) -> bool {
        self.op.is_delete()
    }
    pub fn is_error(&self) -> bool {
        self.op.is_error()
    }
    /// Entry changes the object index (everything but ERROR).
    pub fn object_is_indexed(&self) -> bool {
        !self.op.is_error()
    }
    /// Used for dup detection: reqid set and op in {MODIFY, DELETE, ERROR, REPLACE}.
    pub fn reqid_is_indexed(&self) -> bool {
        self.reqid != OsdReqId::default()
            && matches!(
                self.op,
                LogOp::MODIFY | LogOp::DELETE | LogOp::ERROR | LogOp::REPLACE
            )
    }
}

impl Encode for LogEntry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            e.i32(self.op.0)?;
            self.soid.encode(e)?;
            self.version.encode(e)?;
            if self.op == LogOp::LOST_REVERT {
                self.reverting_to.encode(e)?;
            } else {
                self.prior_version.encode(e)?;
            }
            self.reqid.encode(e)?;
            self.mtime.encode(e)?;
            if self.op == LogOp::LOST_REVERT {
                self.prior_version.encode(e)?;
            }
            e.bytes(&self.snaps)?;
            e.u64(self.user_version)?;
            self.mod_desc.encode(e)?;
            self.extra_reqids.encode(e)?;
            if self.op == LogOp::ERROR {
                e.i32(self.return_code)?;
            }
            if !self.extra_reqids.is_empty() {
                self.extra_reqid_return_codes.encode(e)?;
            }
            self.clean_regions.encode(e)?;
            if self.op != LogOp::ERROR {
                e.i32(self.return_code)?;
            }
            self.op_returns.encode(e)?;
            self.written_shards.encode(e)?;
            self.shards_unused.encode(e)
        })
    }
}

impl<'a> Decode<'a> for LogEntry {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(Self::OLDEST_V, Self::STRUCT_COMPAT, |d, v| {
            let mut x = LogEntry::decode_base(LogOp(d.i32()?));
            x.soid = Hobject::decode(d)?;
            x.version = Eversion::decode(d)?;
            if x.op == LogOp::LOST_REVERT {
                x.reverting_to = Eversion::decode(d)?;
            } else {
                x.prior_version = Eversion::decode(d)?;
            }
            x.reqid = OsdReqId::decode(d)?;
            x.mtime = UTime::decode(d)?;
            if x.op == LogOp::LOST_REVERT {
                x.prior_version = Eversion::decode(d)?;
            }
            x.snaps = d.bytes()?.to_vec();
            if v >= 8 {
                x.user_version = d.u64()?;
            }
            if v >= 9 {
                x.mod_desc = ObjectModDesc::decode(d)?;
            }
            if v >= 10 {
                x.extra_reqids = Decode::decode(d)?;
            }
            if v >= 11 && x.op == LogOp::ERROR {
                x.return_code = d.i32()?;
            }
            if v >= 12 && !x.extra_reqids.is_empty() {
                x.extra_reqid_return_codes = Decode::decode(d)?;
            }
            // v<13 carries no clean regions: the fully-dirty base stays
            if v >= 13 {
                x.clean_regions = ObjectCleanRegions::decode(d)?;
            }
            if v >= 14 && x.op != LogOp::ERROR {
                x.return_code = d.i32()?;
            }
            if v >= 14 {
                x.op_returns = Decode::decode(d)?;
            }
            if v >= 15 {
                x.written_shards = ShardIdSet::decode(d)?;
                x.shards_unused = ShardIdSet::decode(d)?;
            }
            Ok(x)
        })
    }
}

/// pg_log_dup_t, ENCODE v2 compat 1.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogDup {
    pub reqid: OsdReqId,
    pub version: Eversion,
    pub user_version: u64,
    pub return_code: i32,
    pub op_returns: Vec<LogOpReturnItem>,
}
impl LogEntry {
    /// The dup records a trimmed entry leaves: its own, then one per extra request id (that id's recorded
    /// return code, 0 when unset, no op returns).
    /// The one definition shared by the PG's trim, the persisted-log loader and the memory store.
    pub fn dups(&self) -> impl Iterator<Item = LogDup> + '_ {
        std::iter::once(LogDup::from_entry(self)).chain(self.extra_dups())
    }

    /// The dup records of the extra request ids only (copy-from / merged classic entries): the entry's version, the
    /// id's own user version and result, no op returns. Also the PG log's extra-caller index.
    pub fn extra_dups(&self) -> impl Iterator<Item = LogDup> + '_ {
        self.extra_reqids
            .iter()
            .enumerate()
            .map(|(i, (r, uv))| LogDup {
                reqid: *r,
                version: self.version,
                user_version: *uv,
                // the parent's result; an indexed override only replaces a non-negative one (an error stays)
                return_code: if self.return_code < 0 {
                    self.return_code
                } else {
                    self.extra_reqid_return_codes
                        .get(&(i as u32))
                        .copied()
                        .unwrap_or(self.return_code)
                },
                op_returns: vec![],
            })
    }
}

impl LogDup {
    /// Dup record of a trimmed entry.
    pub fn from_entry(e: &LogEntry) -> Self {
        LogDup {
            reqid: e.reqid,
            version: e.version,
            user_version: e.user_version,
            return_code: e.return_code,
            op_returns: e.op_returns.clone(),
        }
    }
}
impl Encode for LogDup {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(2, 1, |e| {
            self.reqid.encode(e)?;
            self.version.encode(e)?;
            e.u64(self.user_version)?;
            e.i32(self.return_code)?;
            self.op_returns.encode(e)
        })
    }
}
impl<'a> Decode<'a> for LogDup {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, v| {
            Ok(LogDup {
                reqid: OsdReqId::decode(d)?,
                version: Eversion::decode(d)?,
                user_version: d.u64()?,
                return_code: d.i32()?,
                op_returns: if v >= 2 { Decode::decode(d)? } else { vec![] },
            })
        })
    }
}

/// pg_log_t, ENCODE v7 compat 3: the log window `(tail, head]`, oldest entry first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgLog {
    pub head: Eversion,
    pub tail: Eversion,
    pub log: VecDeque<LogEntry>,
    /// Replicated: always == head.
    pub can_rollback_to: Eversion,
    /// Replicated: always == head.
    pub rollback_info_trimmed_to: Eversion,
    pub dups: VecDeque<LogDup>,
}

impl PgLog {
    pub const STRUCT_V: u8 = 7;
    pub const STRUCT_COMPAT: u8 = 3;

    /// Empty log at `at` (head = tail = rollback bounds = `at`).
    pub fn empty_at(at: Eversion) -> Self {
        PgLog {
            head: at,
            tail: at,
            can_rollback_to: at,
            rollback_info_trimmed_to: at,
            ..Default::default()
        }
    }

    /// Slice with all entries `> since` (spec 6.6). Tail = version of our newest entry <= `since`
    /// (our tail if none), so a receiver whose entries above that differ can detect divergence.
    pub fn copy_after(&self, since: Eversion) -> PgLog {
        let start = self.log.partition_point(|e| e.version <= since);
        self.slice(start)
    }

    /// Newest `max` entries, tail rewritten to the version just before the first sent entry.
    pub fn copy_up_to(&self, max: usize) -> PgLog {
        self.slice(self.log.len().saturating_sub(max))
    }

    /// Slice from entry `start` on, tail = version of the entry before it (our tail at the front).
    fn slice(&self, start: usize) -> PgLog {
        let tail = if start == 0 {
            self.tail
        } else {
            self.log[start - 1].version
        };
        PgLog {
            head: self.head,
            tail,
            log: self.log.range(start..).cloned().collect(),
            can_rollback_to: self.can_rollback_to,
            rollback_info_trimmed_to: self.rollback_info_trimmed_to,
            dups: self.dups.clone(),
        }
    }

    /// Answer to `pg_query_t` LOG(since): `copy_after(since)`, or the full log when
    /// `since != 0'0 && since < tail` (spec 6.6).
    pub fn answer_log_query(&self, since: Eversion) -> PgLog {
        if since != Eversion::default() && since < self.tail {
            self.clone()
        } else {
            self.copy_after(since)
        }
    }
}

impl Encode for PgLog {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            self.head.encode(e)?;
            self.tail.encode(e)?;
            self.log.encode(e)?;
            self.can_rollback_to.encode(e)?;
            self.rollback_info_trimmed_to.encode(e)?;
            self.dups.encode(e)
        })
    }
}
impl<'a> Decode<'a> for PgLog {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(4, Self::STRUCT_COMPAT, |d, v| {
            let head = Eversion::decode(d)?;
            let tail = Eversion::decode(d)?;
            let log = VecDeque::decode(d)?;
            let can_rollback_to = if v >= 5 { Eversion::decode(d)? } else { head };
            let rollback_info_trimmed_to = if v >= 6 { Eversion::decode(d)? } else { head };
            let dups = if v >= 7 {
                Decode::decode(d)?
            } else {
                VecDeque::new()
            };
            Ok(PgLog {
                head,
                tail,
                log,
                can_rollback_to,
                rollback_info_trimmed_to,
                dups,
            })
        })
    }
}

#[cfg(test)]
mod clean_region_tests {
    use super::*;

    /// xorshift64*: seeded, reproducible.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    fn set(r: &mut Rng, n: usize) -> IntervalSet<u64> {
        let mut out = BTreeMap::new();
        let mut at = 0u64;
        for _ in 0..n {
            at += r.next() % 64;
            let l = 1 + r.next() % 64;
            out.insert(at, l);
            at += l;
        }
        out
    }

    /// The quadratic definition: pairwise intersection, then repeatedly drop the shortest (earlier start first).
    fn reference(a: &IntervalSet<u64>, b: &IntervalSet<u64>, max: usize) -> IntervalSet<u64> {
        let mut out = BTreeMap::new();
        for (s, l) in a {
            for (os, ol) in b {
                let (x, y) = ((*s).max(*os), (s + l).min(os + ol));
                if x < y {
                    out.insert(x, y - x);
                }
            }
        }
        while out.len() > max {
            let s = *out.iter().min_by_key(|(s, l)| (**l, **s)).unwrap().0;
            out.remove(&s);
        }
        out
    }

    #[test]
    fn linear_merge_and_trim_match_the_definition() {
        let mut r = Rng(0x5eed_0c12);
        for i in 0..500 {
            let (a, b) = (set(&mut r, i % 40), set(&mut r, (i * 7) % 40));
            let mut x = ObjectCleanRegions {
                clean_offsets: a.clone(),
                clean_omap: true,
                new_object: false,
            };
            x.merge(&ObjectCleanRegions {
                clean_offsets: b.clone(),
                clean_omap: i % 2 == 0,
                new_object: false,
            });
            assert_eq!(
                x.clean_offsets,
                reference(&a, &b, ObjectCleanRegions::MAX_INTERVALS)
            );
            assert_eq!(x.clean_omap, i % 2 == 0);
            let mut y = ObjectCleanRegions {
                clean_offsets: a.clone(),
                ..Default::default()
            };
            y.trim(i % 5);
            assert_eq!(y.clean_offsets, reference(&a, &a, i % 5));
        }
    }

    /// E11: a peer set with 200k intervals merges and trims in linear time (the old trim was quadratic: minutes).
    #[test]
    fn huge_peer_set_is_linear() {
        let peer: IntervalSet<u64> = (0..200_000u64).map(|i| (i * 4, 2)).collect();
        let mut x = ObjectCleanRegions::default();
        let t = std::time::Instant::now();
        x.merge(&ObjectCleanRegions {
            clean_offsets: peer,
            clean_omap: true,
            new_object: false,
        });
        assert_eq!(x.clean_offsets.len(), ObjectCleanRegions::MAX_INTERVALS);
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
    }
}
