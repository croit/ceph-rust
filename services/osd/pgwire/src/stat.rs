// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pg_stat_t, object_stat_collection_t, object_stat_sum_t (spec peering.md 2.4).

use crate::IntervalSet;
use denc::types::{Eversion, PgShard, PgT, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};
use std::collections::{BTreeMap, BTreeSet};

macro_rules! stat_sum {
    (i64: [$($a:ident),*]; i32: [$($b:ident),*]; i64b: [$($c:ident),*]) => {
        /// object_stat_sum_t: 28 x i64, 4 x i32, 8 x i64 (the raw little-endian memory image).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct ObjectStatSum {
            $(pub $a: i64,)* $(pub $b: i32,)* $(pub $c: i64,)*
        }
        impl ObjectStatSum {
            /// `(name, value)` of every field in wire order (names as `dump_json` prints them).
            pub fn fields(&self) -> Vec<(&'static str, i64)> {
                vec![$((stringify!($a), self.$a),)* $((stringify!($b), self.$b as i64),)* $((stringify!($c), self.$c),)*]
            }
            /// Add `o`'s counters (merge of two PGs); the mode flags are OR-ed.
            pub fn add(&mut self, o: &Self) {
                $(self.$a = self.$a.wrapping_add(o.$a);)* $(self.$b = self.$b.max(o.$b);)* $(self.$c = self.$c.wrapping_add(o.$c);)*
            }
            /// Divide into `parts` sums (split of a PG): every counter evenly, the remainder one each to the first
            /// parts, so the parts add up to `self`; the mode flags are copied.
            pub fn split(&self, parts: usize) -> Vec<Self> {
                let n = parts.max(1) as i64;
                (0..n)
                    .map(|i| {
                        let mut p = *self;
                        $(p.$a = self.$a.div_euclid(n) + i64::from(i < self.$a.rem_euclid(n));)*
                        $(p.$c = self.$c.div_euclid(n) + i64::from(i < self.$c.rem_euclid(n));)*
                        p
                    })
                    .collect()
            }
            fn encode_body<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
                $(e.i64(self.$a)?;)* $(e.i32(self.$b)?;)* $(e.i64(self.$c)?;)*
                Ok(())
            }
            fn decode_body(d: &mut Decoder<'_>) -> Result<Self> {
                Ok(ObjectStatSum { $($a: d.i64()?,)* $($b: d.i32()?,)* $($c: d.i64()?,)* })
            }
        }
    };
}

stat_sum! {
    i64: [num_bytes, num_objects, num_object_clones, num_object_copies,
        num_objects_missing_on_primary, num_objects_degraded, num_objects_unfound,
        num_read, num_read_kb, num_write, num_write_kb, num_scrub_errors,
        num_objects_recovered, num_bytes_recovered, num_keys_recovered,
        num_shallow_scrub_errors, num_deep_scrub_errors, num_objects_dirty, num_whiteouts,
        num_objects_omap, num_objects_hit_set_archive, num_objects_misplaced,
        num_bytes_hit_set_archive, num_flush, num_flush_kb, num_evict, num_evict_kb,
        num_promote];
    i32: [num_flush_mode_high, num_flush_mode_low, num_evict_mode_some, num_evict_mode_full];
    i64b: [num_objects_pinned, num_objects_missing, num_legacy_snapsets,
        num_large_omap_objects, num_objects_manifest, num_omap_bytes, num_omap_keys,
        num_objects_repaired]
}

impl ObjectStatSum {
    pub const STRUCT_V: u8 = 20;
    pub const STRUCT_COMPAT: u8 = 14;
}

impl Encode for ObjectStatSum {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| self.encode_body(e))
    }
}
impl<'a> Decode<'a> for ObjectStatSum {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        // Only the v20 raw image is supported (older field-by-field layouts are not on any
        // supported peer, see spec clarification).
        d.versioned_min(Self::STRUCT_V, Self::STRUCT_COMPAT, |d, _| {
            Self::decode_body(d)
        })
    }
}

/// Client io of one message on the primary (spec pg-io-stats.md 1): the `num_read` / `num_read_kb` / `num_write` /
/// `num_write_kb` delta, counted per sub-op, KiB rounded up per sub-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoCount {
    pub rd: i64,
    pub rd_kb: i64,
    pub wr: i64,
    pub wr_kb: i64,
}

impl IoCount {
    /// Bytes in KiB, rounded up.
    #[inline]
    pub fn kb(bytes: u64) -> i64 {
        bytes.div_ceil(1024) as i64
    }
    /// One read sub-op of `bytes`.
    #[inline]
    pub fn read(&mut self, bytes: u64) {
        self.rd += 1;
        self.rd_kb += Self::kb(bytes);
    }
    /// One write sub-op of `bytes`.
    #[inline]
    pub fn write(&mut self, bytes: u64) {
        self.wr += 1;
        self.wr_kb += Self::kb(bytes);
    }
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

impl ObjectStatSum {
    /// Add a message's client io (primary, at op completion / write submission).
    #[inline]
    pub fn add_io(&mut self, io: &IoCount) {
        self.num_read = self.num_read.wrapping_add(io.rd);
        self.num_read_kb = self.num_read_kb.wrapping_add(io.rd_kb);
        self.num_write = self.num_write.wrapping_add(io.wr);
        self.num_write_kb = self.num_write_kb.wrapping_add(io.wr_kb);
    }
}

/// object_stat_collection_t (v2, c2): the sum + a legacy empty per-category map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ObjectStatCollection {
    pub sum: ObjectStatSum,
}
impl Encode for ObjectStatCollection {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(2, 2, |e| {
            self.sum.encode(e)?;
            e.u32(0)
        })
    }
}
impl<'a> Decode<'a> for ObjectStatCollection {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(2, 2, |d, _| {
            let sum = ObjectStatSum::decode(d)?;
            let n = d.u32()?;
            if n != 0 {
                return Err(Error::BadValue("object_stat_collection per-category stats"));
            }
            Ok(ObjectStatCollection { sum })
        })
    }
}

/// pg_stat_t, ENCODE v31 compat 22.
#[derive(Debug, Clone, PartialEq)]
pub struct PgStat {
    pub version: Eversion,
    pub reported_seq: u64,
    pub reported_epoch: u32,
    /// All 64 state bits (see [`crate::state`]); the wire splits low/high 32 bits.
    pub state: u64,
    pub log_start: Eversion,
    pub ondisk_log_start: Eversion,
    pub created: u32,
    pub last_epoch_clean: u32,
    pub parent: PgT,
    pub parent_split_bits: u32,
    pub last_scrub: Eversion,
    pub last_scrub_stamp: UTime,
    pub stats: ObjectStatCollection,
    pub log_size: i64,
    pub ondisk_log_size: i64,
    pub up: Vec<i32>,
    pub acting: Vec<i32>,
    pub last_fresh: UTime,
    pub last_change: UTime,
    pub last_active: UTime,
    pub last_clean: UTime,
    pub last_unstale: UTime,
    pub mapping_epoch: u32,
    pub last_deep_scrub: Eversion,
    pub last_deep_scrub_stamp: UTime,
    pub stats_invalid: bool,
    pub last_clean_scrub_stamp: UTime,
    pub last_became_active: UTime,
    pub dirty_stats_invalid: bool,
    pub up_primary: i32,
    pub acting_primary: i32,
    pub omap_stats_invalid: bool,
    pub hitset_stats_invalid: bool,
    pub blocked_by: Vec<i32>,
    pub last_undegraded: UTime,
    pub last_fullsized: UTime,
    pub hitset_bytes_stats_invalid: bool,
    pub last_peered: UTime,
    pub last_became_peered: UTime,
    pub pin_stats_invalid: bool,
    pub snaptrimq_len: u32,
    pub purged_snaps: IntervalSet<u64>,
    pub manifest_stats_invalid: bool,
    pub avail_no_missing: Vec<PgShard>,
    pub object_location_counts: BTreeMap<BTreeSet<PgShard>, i32>,
    pub last_scrub_duration: i32,
    pub scrub_scheduled_at: UTime,
    pub scrub_sched_duration_seconds: i32,
    /// 0 unknown, 1 not_queued, 2 active, 3 scheduled, 4 queued, 5 blocked.
    pub scrub_sched_status: u16,
    pub scrub_is_active: bool,
    pub scrub_is_deep: bool,
    pub scrub_is_periodic: bool,
    pub objects_scrubbed: i64,
    pub scrub_duration: f64,
    pub objects_trimmed: i64,
    pub snaptrim_duration: f64,
    pub log_dups_size: i64,
    pub scrub_osd_to_respond: u16,
    pub scrub_ordinal_of_requested_replica: u8,
    pub scrub_num_to_reserve: u8,
    pub last_degraded: UTime,
    /// Copy of `PgHistory::last_deep_scrub_start_stamp` (croit fork `wip-ifed-dedup`, v32, dedup-listing.md 5.2); encoded
    /// (v32) only when set, so a PG without it keeps the upstream v31 bytes.
    pub last_deep_scrub_start_stamp: UTime,
}

impl Default for PgStat {
    fn default() -> Self {
        PgStat {
            version: Default::default(),
            reported_seq: 0,
            reported_epoch: 0,
            state: 0,
            log_start: Default::default(),
            ondisk_log_start: Default::default(),
            created: 0,
            last_epoch_clean: 0,
            parent: Default::default(),
            parent_split_bits: 0,
            last_scrub: Default::default(),
            last_scrub_stamp: Default::default(),
            stats: Default::default(),
            log_size: 0,
            ondisk_log_size: 0,
            up: vec![],
            acting: vec![],
            last_fresh: Default::default(),
            last_change: Default::default(),
            last_active: Default::default(),
            last_clean: Default::default(),
            last_unstale: Default::default(),
            mapping_epoch: 0,
            last_deep_scrub: Default::default(),
            last_deep_scrub_stamp: Default::default(),
            stats_invalid: false,
            last_clean_scrub_stamp: Default::default(),
            last_became_active: Default::default(),
            dirty_stats_invalid: false,
            up_primary: -1,
            acting_primary: -1,
            omap_stats_invalid: false,
            hitset_stats_invalid: false,
            blocked_by: vec![],
            last_undegraded: Default::default(),
            last_fullsized: Default::default(),
            hitset_bytes_stats_invalid: false,
            last_peered: Default::default(),
            last_became_peered: Default::default(),
            pin_stats_invalid: false,
            snaptrimq_len: 0,
            purged_snaps: Default::default(),
            manifest_stats_invalid: false,
            avail_no_missing: vec![],
            object_location_counts: Default::default(),
            last_scrub_duration: 0,
            scrub_scheduled_at: Default::default(),
            scrub_sched_duration_seconds: 0,
            scrub_sched_status: 0,
            scrub_is_active: false,
            scrub_is_deep: false,
            scrub_is_periodic: false,
            objects_scrubbed: 0,
            scrub_duration: 0.0,
            objects_trimmed: 0,
            snaptrim_duration: 0.0,
            log_dups_size: 0,
            scrub_osd_to_respond: 0,
            scrub_ordinal_of_requested_replica: 0,
            scrub_num_to_reserve: 0,
            last_degraded: Default::default(),
            last_deep_scrub_start_stamp: Default::default(),
        }
    }
}

impl PgStat {
    pub const STRUCT_V: u8 = 31;
    /// With `last_deep_scrub_start_stamp` (fork); compat unchanged, so upstream decoders skip the field.
    pub const STRUCT_V_START_STAMP: u8 = 32;
    pub const STRUCT_COMPAT: u8 = 22;

    /// State string as the mgr shows it.
    pub fn state_string(&self) -> String {
        crate::state::state_string(self.state)
    }
}

impl Encode for PgStat {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        let start = self.last_deep_scrub_start_stamp != UTime::default();
        let v = if start {
            Self::STRUCT_V_START_STAMP
        } else {
            Self::STRUCT_V
        };
        e.versioned(v, Self::STRUCT_COMPAT, |e| {
            self.version.encode(e)?;
            e.u64(self.reported_seq)?;
            e.u32(self.reported_epoch)?;
            e.u32(self.state as u32)?;
            self.log_start.encode(e)?;
            self.ondisk_log_start.encode(e)?;
            e.u32(self.created)?;
            e.u32(self.last_epoch_clean)?;
            self.parent.encode(e)?;
            e.u32(self.parent_split_bits)?;
            self.last_scrub.encode(e)?;
            self.last_scrub_stamp.encode(e)?;
            self.stats.encode(e)?;
            e.i64(self.log_size)?;
            e.i64(self.ondisk_log_size)?;
            self.up.encode(e)?;
            self.acting.encode(e)?;
            self.last_fresh.encode(e)?;
            self.last_change.encode(e)?;
            self.last_active.encode(e)?;
            self.last_clean.encode(e)?;
            self.last_unstale.encode(e)?;
            e.u32(self.mapping_epoch)?;
            self.last_deep_scrub.encode(e)?;
            self.last_deep_scrub_stamp.encode(e)?;
            e.bool(self.stats_invalid)?;
            self.last_clean_scrub_stamp.encode(e)?;
            self.last_became_active.encode(e)?;
            e.bool(self.dirty_stats_invalid)?;
            e.i32(self.up_primary)?;
            e.i32(self.acting_primary)?;
            e.bool(self.omap_stats_invalid)?;
            e.bool(self.hitset_stats_invalid)?;
            self.blocked_by.encode(e)?;
            self.last_undegraded.encode(e)?;
            self.last_fullsized.encode(e)?;
            e.bool(self.hitset_bytes_stats_invalid)?;
            self.last_peered.encode(e)?;
            self.last_became_peered.encode(e)?;
            e.bool(self.pin_stats_invalid)?;
            e.u32(self.snaptrimq_len)?;
            e.u32((self.state >> 32) as u32)?;
            self.purged_snaps.encode(e)?;
            e.bool(self.manifest_stats_invalid)?;
            self.avail_no_missing.encode(e)?;
            self.object_location_counts.encode(e)?;
            e.i32(self.last_scrub_duration)?;
            self.scrub_scheduled_at.encode(e)?;
            e.i32(self.scrub_sched_duration_seconds)?;
            e.u16(self.scrub_sched_status)?;
            e.bool(self.scrub_is_active)?;
            e.bool(self.scrub_is_deep)?;
            e.bool(self.scrub_is_periodic)?;
            e.i64(self.objects_scrubbed)?;
            e.f64(self.scrub_duration)?;
            e.i64(self.objects_trimmed)?;
            e.f64(self.snaptrim_duration)?;
            e.i64(self.log_dups_size)?;
            e.u16(self.scrub_osd_to_respond)?;
            e.u8(self.scrub_ordinal_of_requested_replica)?;
            e.u8(self.scrub_num_to_reserve)?;
            self.last_degraded.encode(e)?;
            if start {
                self.last_deep_scrub_start_stamp.encode(e)?;
            }
            Ok(())
        })
    }
}

impl<'a> Decode<'a> for PgStat {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(22, Self::STRUCT_COMPAT, |d, v| {
            let mut s = PgStat {
                version: Decode::decode(d)?,
                reported_seq: d.u64()?,
                reported_epoch: d.u32()?,
                state: d.u32()? as u64,
                log_start: Decode::decode(d)?,
                ondisk_log_start: Decode::decode(d)?,
                created: d.u32()?,
                last_epoch_clean: d.u32()?,
                parent: Decode::decode(d)?,
                parent_split_bits: d.u32()?,
                last_scrub: Decode::decode(d)?,
                last_scrub_stamp: Decode::decode(d)?,
                stats: Decode::decode(d)?,
                log_size: d.i64()?,
                ondisk_log_size: d.i64()?,
                up: Decode::decode(d)?,
                acting: Decode::decode(d)?,
                last_fresh: Decode::decode(d)?,
                last_change: Decode::decode(d)?,
                last_active: Decode::decode(d)?,
                last_clean: Decode::decode(d)?,
                last_unstale: Decode::decode(d)?,
                mapping_epoch: d.u32()?,
                last_deep_scrub: Decode::decode(d)?,
                last_deep_scrub_stamp: Decode::decode(d)?,
                stats_invalid: d.bool()?,
                last_clean_scrub_stamp: Decode::decode(d)?,
                last_became_active: Decode::decode(d)?,
                dirty_stats_invalid: d.bool()?,
                up_primary: d.i32()?,
                acting_primary: d.i32()?,
                omap_stats_invalid: d.bool()?,
                hitset_stats_invalid: d.bool()?,
                blocked_by: Decode::decode(d)?,
                last_undegraded: Decode::decode(d)?,
                last_fullsized: Decode::decode(d)?,
                hitset_bytes_stats_invalid: d.bool()?,
                last_peered: Decode::decode(d)?,
                last_became_peered: Decode::decode(d)?,
                pin_stats_invalid: d.bool()?,
                ..Default::default()
            };
            if v >= 23 {
                s.snaptrimq_len = d.u32()?;
            }
            if v >= 24 {
                s.state |= (d.u32()? as u64) << 32;
                s.purged_snaps = Decode::decode(d)?;
            }
            if v >= 25 {
                s.manifest_stats_invalid = d.bool()?;
            }
            if v >= 26 {
                s.avail_no_missing = Decode::decode(d)?;
                s.object_location_counts = Decode::decode(d)?;
            }
            if v >= 27 {
                s.last_scrub_duration = d.i32()?;
                s.scrub_scheduled_at = Decode::decode(d)?;
                s.scrub_sched_duration_seconds = d.i32()?;
                s.scrub_sched_status = d.u16()?;
                s.scrub_is_active = d.bool()?;
                s.scrub_is_deep = d.bool()?;
                s.scrub_is_periodic = d.bool()?;
                s.objects_scrubbed = d.i64()?;
            }
            if v >= 28 {
                s.scrub_duration = d.f64()?;
                s.objects_trimmed = d.i64()?;
                s.snaptrim_duration = d.f64()?;
            }
            if v >= 29 {
                s.log_dups_size = d.i64()?;
            }
            if v >= 30 {
                s.scrub_osd_to_respond = d.u16()?;
                s.scrub_ordinal_of_requested_replica = d.u8()?;
                s.scrub_num_to_reserve = d.u8()?;
            }
            if v >= 31 {
                s.last_degraded = Decode::decode(d)?;
            }
            if v >= 32 {
                s.last_deep_scrub_start_stamp = Decode::decode(d)?;
            }
            Ok(s)
        })
    }
}

#[cfg(test)]
mod start_stamp_tests {
    use super::*;

    #[test]
    fn v31_bytes_without_the_stamp_v32_with_it() {
        let a = denc::to_vec(&PgStat::default()).unwrap();
        assert_eq!((a[0], a[1]), (31, 22));
        let s = PgStat {
            last_deep_scrub_start_stamp: UTime { sec: 14, nsec: 15 },
            ..Default::default()
        };
        let b = denc::to_vec(&s).unwrap();
        assert_eq!((b[0], b[1], b.len()), (32, 22, a.len() + 8));
        assert_eq!(&b[a.len()..], &[14, 0, 0, 0, 15, 0, 0, 0]);
        let d: PgStat = denc::from_slice(&b).unwrap();
        assert_eq!(d.last_deep_scrub_start_stamp, s.last_deep_scrub_start_stamp);
        let d: PgStat = denc::from_slice(&a).unwrap();
        assert_eq!(d.last_deep_scrub_start_stamp, UTime::default());
    }
}
