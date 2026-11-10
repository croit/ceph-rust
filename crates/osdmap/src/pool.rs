// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pg_pool_t, pool_snap_info_t, pool_opts_t (spec osdmap.md 2).

use crate::hash::{crush_hash32_2, stable_mask, stable_mod};
use crate::interval::IntervalSet;
use denc::types::{PgT, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};
use std::collections::{BTreeMap, BTreeSet};

pub const TYPE_REPLICATED: u8 = 1;
pub const TYPE_ERASURE: u8 = 3;

pub mod flags {
    pub const HASHPSPOOL: u64 = 1 << 0;
    pub const FULL: u64 = 1 << 1;
    pub const EC_OVERWRITES: u64 = 1 << 2;
    pub const INCOMPLETE_CLONES: u64 = 1 << 3;
    pub const NODELETE: u64 = 1 << 4;
    pub const NOPGCHANGE: u64 = 1 << 5;
    pub const NOSIZECHANGE: u64 = 1 << 6;
    pub const WRITE_FADVISE_DONTNEED: u64 = 1 << 7;
    pub const NOSCRUB: u64 = 1 << 8;
    pub const NODEEP_SCRUB: u64 = 1 << 9;
    pub const FULL_QUOTA: u64 = 1 << 10;
    pub const NEARFULL: u64 = 1 << 11;
    pub const BACKFILLFULL: u64 = 1 << 12;
    pub const SELFMANAGED_SNAPS: u64 = 1 << 13;
    pub const POOL_SNAPS: u64 = 1 << 14;
    pub const CREATING: u64 = 1 << 15;
    pub const EIO: u64 = 1 << 16;
    pub const BULK: u64 = 1 << 17;
    pub const CRIMSON: u64 = 1 << 18;
    pub const EC_OPTIMIZATIONS: u64 = 1 << 19;
    pub const CLIENT_SPLIT_READS: u64 = 1 << 20;
    pub const OMAP: u64 = 1 << 21;
}

/// Top pg_pool_t struct_v we encode.
pub const POOL_V_TOP: u8 = 33;
/// Oldest struct_v decoded.
pub const POOL_V_MIN: u8 = 24;

/// pool_snap_info_t, ENV(2,2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PoolSnapInfo {
    pub snapid: u64,
    pub stamp: UTime,
    pub name: Vec<u8>,
}
impl Encode for PoolSnapInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(2, 2, |e| {
            e.u64(self.snapid)?;
            self.stamp.encode(e)?;
            e.bytes(&self.name)
        })
    }
}
impl<'a> Decode<'a> for PoolSnapInfo {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(2, 2, |d, _| {
            Ok(PoolSnapInfo {
                snapid: d.u64()?,
                stamp: UTime::decode(d)?,
                name: d.bytes()?.to_vec(),
            })
        })
    }
}

/// pool_opts_t value.
#[derive(Debug, Clone, PartialEq)]
pub enum OptVal {
    Str(String),
    Int(i64),
    Double(f64),
}

/// pool_opts_t, ENV(2,1): ascending key order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PoolOpts(pub BTreeMap<i32, OptVal>);

impl Encode for PoolOpts {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(2, 1, |e| {
            e.count(self.0.len())?;
            for (k, v) in &self.0 {
                e.i32(*k)?;
                match v {
                    OptVal::Str(s) => {
                        e.i32(0)?;
                        s.encode(e)?;
                    }
                    OptVal::Int(i) => {
                        e.i32(1)?;
                        e.i64(*i)?;
                    }
                    OptVal::Double(f) => {
                        e.i32(2)?;
                        e.f64(*f)?;
                    }
                }
            }
            Ok(())
        })
    }
}
impl<'a> Decode<'a> for PoolOpts {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, v| {
            let n = d.count()?;
            let mut m = BTreeMap::new();
            for _ in 0..n {
                let k = d.i32()?;
                let val = match d.i32()? {
                    0 => OptVal::Str(String::decode(d)?),
                    1 if v >= 2 => OptVal::Int(d.i64()?),
                    1 => OptVal::Int(d.i32()? as i64),
                    2 => OptVal::Double(d.f64()?),
                    t => return Err(Error::BadMarker(t as u8)),
                };
                m.insert(k, val);
            }
            Ok(PoolOpts(m))
        })
    }
}

/// pg_merge_meta_t, ENV(1,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgMergeMeta {
    pub source_pgid: PgT,
    pub ready_epoch: u32,
    pub last_epoch_started: u32,
    pub last_epoch_clean: u32,
    pub source_version: (u64, u32),
    pub target_version: (u64, u32),
}
impl Encode for PgMergeMeta {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.source_pgid.encode(e)?;
            e.u32(self.ready_epoch)?;
            e.u32(self.last_epoch_started)?;
            e.u32(self.last_epoch_clean)?;
            e.u64(self.source_version.0)?;
            e.u32(self.source_version.1)?;
            e.u64(self.target_version.0)?;
            e.u32(self.target_version.1)
        })
    }
}
impl<'a> Decode<'a> for PgMergeMeta {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(PgMergeMeta {
                source_pgid: PgT::decode(d)?,
                ready_epoch: d.u32()?,
                last_epoch_started: d.u32()?,
                last_epoch_clean: d.u32()?,
                source_version: (d.u64()?, d.u32()?),
                target_version: (d.u64()?, d.u32()?),
            })
        })
    }
}

/// Stretch-pool peering constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeeringCrush {
    pub bucket_count: u32,
    pub bucket_target: u32,
    pub bucket_barrier: u32,
    pub mandatory_member: i32,
}
impl Default for PeeringCrush {
    fn default() -> Self {
        PeeringCrush {
            bucket_count: 0,
            bucket_target: 0,
            bucket_barrier: 0,
            mandatory_member: 0x7fff_ffff,
        }
    }
}
impl PeeringCrush {
    fn dec(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(PeeringCrush {
            bucket_count: d.u32()?,
            bucket_target: d.u32()?,
            bucket_barrier: d.u32()?,
            mandatory_member: d.i32()?,
        })
    }
}

/// shard_id_set: 128-bit set (bits 0..127).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShardIdSet(pub [u64; 2]);
impl ShardIdSet {
    pub fn contains(&self, s: usize) -> bool {
        s < 128 && self.0[s / 64] >> (s % 64) & 1 == 1
    }
    pub fn insert(&mut self, s: usize) {
        if s < 128 {
            self.0[s / 64] |= 1 << (s % 64);
        }
    }
    pub fn count(&self) -> usize {
        (self.0[0].count_ones() + self.0[1].count_ones()) as usize
    }
}

/// pg_pool_t.
#[derive(Debug, Clone, PartialEq)]
pub struct PgPool {
    pub ptype: u8,
    pub size: u8,
    pub crush_rule: u8,
    pub object_hash: u8,
    pub pg_num: u32,
    pub pgp_num: u32,
    pub last_change: u32,
    pub snap_seq: u64,
    pub snap_epoch: u32,
    pub snaps: BTreeMap<u64, PoolSnapInfo>,
    pub removed_snaps: IntervalSet,
    pub auid: u64,
    pub flags: u64,
    pub crash_replay_interval: u32,
    pub min_size: u8,
    pub quota_max_bytes: u64,
    pub quota_max_objects: u64,
    pub tiers: BTreeSet<u64>,
    pub tier_of: i64,
    pub cache_mode: u8,
    pub read_tier: i64,
    pub write_tier: i64,
    pub properties: BTreeMap<String, String>,
    /// Whole HitSet::Params envelope, verbatim (cache tiering is out of scope).
    pub hit_set_params: Vec<u8>,
    pub hit_set_period: u32,
    pub hit_set_count: u32,
    pub stripe_width: u32,
    pub target_max_bytes: u64,
    pub target_max_objects: u64,
    pub cache_target_dirty_ratio_micro: u32,
    pub cache_target_full_ratio_micro: u32,
    pub cache_min_flush_age: u32,
    pub cache_min_evict_age: u32,
    pub erasure_code_profile: String,
    pub last_force_op_resend_preluminous: u32,
    pub min_read_recency_for_promote: u32,
    pub expected_num_objects: u64,
    pub cache_target_dirty_high_ratio_micro: u32,
    pub min_write_recency_for_promote: u32,
    pub use_gmt_hitset: bool,
    pub fast_read: bool,
    pub hit_set_grade_decay_rate: u32,
    pub hit_set_search_last_n: u32,
    pub opts: PoolOpts,
    pub last_force_op_resend_prenautilus: u32,
    pub application_metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub create_time: UTime,
    pub pg_num_target: u32,
    pub pgp_num_target: u32,
    pub pg_num_pending: u32,
    pub last_force_op_resend: u32,
    pub pg_autoscale_mode: u8,
    pub last_pg_merge_meta: PgMergeMeta,
    pub peering_crush: PeeringCrush,
    pub nonprimary_shards: ShardIdSet,
    pub shard_mapping: Vec<i8>,
    pub ec_data_shard_count: Option<u8>,
    pub ec_coding_shard_count: Option<u8>,
}

/// Empty HitSet::Params: ENV(1,1){u8 type=0}.
pub const HIT_SET_NONE: [u8; 7] = [1, 1, 1, 0, 0, 0, 0];

impl Default for PgPool {
    fn default() -> Self {
        PgPool {
            ptype: TYPE_REPLICATED,
            size: 0,
            crush_rule: 0,
            object_hash: crate::hash::STR_HASH_RJENKINS,
            pg_num: 0,
            pgp_num: 0,
            last_change: 0,
            snap_seq: 0,
            snap_epoch: 0,
            snaps: BTreeMap::new(),
            removed_snaps: IntervalSet::default(),
            auid: 0,
            flags: 0,
            crash_replay_interval: 0,
            min_size: 0,
            quota_max_bytes: 0,
            quota_max_objects: 0,
            tiers: BTreeSet::new(),
            tier_of: -1,
            cache_mode: 0,
            read_tier: -1,
            write_tier: -1,
            properties: BTreeMap::new(),
            hit_set_params: HIT_SET_NONE.to_vec(),
            hit_set_period: 0,
            hit_set_count: 0,
            stripe_width: 0,
            target_max_bytes: 0,
            target_max_objects: 0,
            cache_target_dirty_ratio_micro: 0,
            cache_target_full_ratio_micro: 0,
            cache_min_flush_age: 0,
            cache_min_evict_age: 0,
            erasure_code_profile: String::new(),
            last_force_op_resend_preluminous: 0,
            min_read_recency_for_promote: 0,
            expected_num_objects: 0,
            cache_target_dirty_high_ratio_micro: 0,
            min_write_recency_for_promote: 0,
            use_gmt_hitset: true,
            fast_read: false,
            hit_set_grade_decay_rate: 0,
            hit_set_search_last_n: 0,
            opts: PoolOpts::default(),
            last_force_op_resend_prenautilus: 0,
            application_metadata: BTreeMap::new(),
            create_time: UTime::default(),
            pg_num_target: 0,
            pgp_num_target: 0,
            pg_num_pending: 0,
            last_force_op_resend: 0,
            pg_autoscale_mode: 0,
            last_pg_merge_meta: PgMergeMeta::default(),
            peering_crush: PeeringCrush::default(),
            nonprimary_shards: ShardIdSet::default(),
            shard_mapping: Vec::new(),
            ec_data_shard_count: None,
            ec_coding_shard_count: None,
        }
    }
}

impl PgPool {
    pub fn is_replicated(&self) -> bool {
        self.ptype == TYPE_REPLICATED
    }
    pub fn is_erasure(&self) -> bool {
        self.ptype == TYPE_ERASURE
    }
    /// Replicated pools compact their sets; EC positions are shard ids.
    pub fn can_shift_osds(&self) -> bool {
        self.is_replicated()
    }
    pub fn has_flag(&self, f: u64) -> bool {
        self.flags & f != 0
    }
    /// 2^cbits(pg_num-1) - 1 (u32 math; pg_num 0 -> 0xFFFFFFFF).
    pub fn pg_num_mask(&self) -> u32 {
        stable_mask(self.pg_num)
    }
    pub fn pgp_num_mask(&self) -> u32 {
        stable_mask(self.pgp_num)
    }
    /// Raw seed -> actual pg seed.
    pub fn raw_pg_to_pg(&self, pg: PgT) -> PgT {
        PgT::new(
            pg.pool,
            stable_mod(pg.seed, self.pg_num, self.pg_num_mask()),
        )
    }
    /// Placement seed (spec 4.2).
    pub fn raw_pg_to_pps(&self, pg: PgT) -> u32 {
        let s = stable_mod(pg.seed, self.pgp_num, self.pgp_num_mask());
        if self.has_flag(flags::HASHPSPOOL) {
            crush_hash32_2(s, pg.pool as u32)
        } else {
            s.wrapping_add(pg.pool as u32)
        }
    }
    /// Effective data shard count for optimized EC (spec 2.1 fields 59/60).
    pub fn ec_k(&self) -> usize {
        match self.ec_data_shard_count {
            Some(k) => k as usize,
            None => self.nonprimary_shards.count() + 1,
        }
    }
}

impl PgPool {
    /// struct_v the mon uses for `features` (spec osdmap 2): 33 with SERVER_UMBRELLA, 32 with SERVER_TENTACLE only,
    /// else 29 (30 for a stretch pool). `features` 0 = all. Ladders below nautilus are out of scope (never joined).
    pub fn version_for(&self, features: u64) -> u8 {
        use denc::features::{SERVER_TENTACLE, SERVER_UMBRELLA, have, have_or_all};
        if have_or_all(features, SERVER_UMBRELLA) {
            POOL_V_TOP
        } else if have(features, SERVER_TENTACLE) {
            32
        } else if self.peering_crush.bucket_count != 0 {
            30
        } else {
            29
        }
    }

    /// Encode as struct_v `v` (29..=33, [`PgPool::version_for`]): byte-exact with the mon's encoding for the same
    /// features, which the incremental `full_crc` check needs (spec osdmap 3.3).
    pub fn encode_v<B: BufMut>(&self, e: &mut Encoder<B>, v: u8) -> Result<()> {
        e.versioned(v, 5, |e| {
            e.u8(self.ptype)?;
            e.u8(self.size)?;
            e.u8(self.crush_rule)?;
            e.u8(self.object_hash)?;
            e.u32(self.pg_num)?;
            e.u32(self.pgp_num)?;
            // lpg_num, lpgp_num: always written 0 (spec 2.1 field 7).
            e.u32(0)?;
            e.u32(0)?;
            e.u32(self.last_change)?;
            e.u64(self.snap_seq)?;
            e.u32(self.snap_epoch)?;
            self.snaps.encode(e)?;
            self.removed_snaps.encode(e)?;
            e.u64(self.auid)?;
            e.u64(if v >= 33 {
                self.flags
            } else {
                self.flags & !flags::CLIENT_SPLIT_READS
            })?;
            e.u32(self.crash_replay_interval)?;
            e.u8(self.min_size)?;
            e.u64(self.quota_max_bytes)?;
            e.u64(self.quota_max_objects)?;
            self.tiers.encode(e)?;
            e.i64(self.tier_of)?;
            e.u8(self.cache_mode)?;
            e.i64(self.read_tier)?;
            e.i64(self.write_tier)?;
            self.properties.encode(e)?;
            e.raw(&self.hit_set_params)?;
            e.u32(self.hit_set_period)?;
            e.u32(self.hit_set_count)?;
            e.u32(self.stripe_width)?;
            e.u64(self.target_max_bytes)?;
            e.u64(self.target_max_objects)?;
            e.u32(self.cache_target_dirty_ratio_micro)?;
            e.u32(self.cache_target_full_ratio_micro)?;
            e.u32(self.cache_min_flush_age)?;
            e.u32(self.cache_min_evict_age)?;
            self.erasure_code_profile.encode(e)?;
            e.u32(self.last_force_op_resend_preluminous)?;
            e.u32(self.min_read_recency_for_promote)?;
            e.u64(self.expected_num_objects)?;
            e.u32(self.cache_target_dirty_high_ratio_micro)?;
            e.u32(self.min_write_recency_for_promote)?;
            e.bool(self.use_gmt_hitset)?;
            e.bool(self.fast_read)?;
            e.u32(self.hit_set_grade_decay_rate)?;
            e.u32(self.hit_set_search_last_n)?;
            self.opts.encode(e)?;
            e.u32(self.last_force_op_resend_prenautilus)?;
            self.application_metadata.encode(e)?;
            self.create_time.encode(e)?;
            e.u32(self.pg_num_target)?;
            e.u32(self.pgp_num_target)?;
            e.u32(self.pg_num_pending)?;
            // Two reserved epochs: always written 0 (spec 2.1 field 52).
            e.u32(0)?;
            e.u32(0)?;
            e.u32(self.last_force_op_resend)?;
            e.u8(self.pg_autoscale_mode)?;
            self.last_pg_merge_meta.encode(e)?;
            let stretch = self.peering_crush.bucket_count != 0;
            if v >= 31 {
                e.u8(u8::from(stretch))?;
            }
            if v == 30 || (v >= 31 && stretch) {
                e.u32(self.peering_crush.bucket_count)?;
                e.u32(self.peering_crush.bucket_target)?;
                e.u32(self.peering_crush.bucket_barrier)?;
                e.i32(self.peering_crush.mandatory_member)?;
            }
            if v >= 32 {
                e.varint(self.nonprimary_shards.0[0])?;
                e.varint(self.nonprimary_shards.0[1])?;
            }
            if v >= 33 {
                self.shard_mapping.encode(e)?;
                self.ec_data_shard_count.encode(e)?;
                self.ec_coding_shard_count.encode(e)?;
            }
            Ok(())
        })
    }
}

impl Encode for PgPool {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        self.encode_v(e, POOL_V_TOP)
    }
}

impl<'a> Decode<'a> for PgPool {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(POOL_V_MIN, 5, |d, v| {
            let mut p = PgPool {
                ptype: d.u8()?,
                size: d.u8()?,
                crush_rule: d.u8()?,
                object_hash: d.u8()?,
                pg_num: d.u32()?,
                pgp_num: d.u32()?,
                ..PgPool::default()
            };
            d.skip(8)?; // lpg_num, lpgp_num
            p.last_change = d.u32()?;
            p.snap_seq = d.u64()?;
            p.snap_epoch = d.u32()?;
            p.snaps = BTreeMap::decode(d)?;
            p.removed_snaps = IntervalSet::decode(d)?;
            p.auid = d.u64()?;
            p.flags = d.u64()?;
            p.crash_replay_interval = d.u32()?;
            p.min_size = d.u8()?;
            p.quota_max_bytes = d.u64()?;
            p.quota_max_objects = d.u64()?;
            p.tiers = BTreeSet::decode(d)?;
            p.tier_of = d.i64()?;
            p.cache_mode = d.u8()?;
            p.read_tier = d.i64()?;
            p.write_tier = d.i64()?;
            p.properties = BTreeMap::decode(d)?;
            {
                let rest = d.peek_rest();
                let start = d.position();
                d.versioned(1, |d, _| d.skip(d.remaining()))?;
                p.hit_set_params = rest[..d.position() - start].to_vec();
            }
            p.hit_set_period = d.u32()?;
            p.hit_set_count = d.u32()?;
            p.stripe_width = d.u32()?;
            p.target_max_bytes = d.u64()?;
            p.target_max_objects = d.u64()?;
            p.cache_target_dirty_ratio_micro = d.u32()?;
            p.cache_target_full_ratio_micro = d.u32()?;
            p.cache_min_flush_age = d.u32()?;
            p.cache_min_evict_age = d.u32()?;
            p.erasure_code_profile = String::decode(d)?;
            p.last_force_op_resend_preluminous = d.u32()?;
            p.min_read_recency_for_promote = d.u32()?;
            p.expected_num_objects = d.u64()?;
            p.cache_target_dirty_high_ratio_micro = d.u32()?;
            p.min_write_recency_for_promote = d.u32()?;
            p.use_gmt_hitset = d.bool()?;
            p.fast_read = d.bool()?;
            p.hit_set_grade_decay_rate = d.u32()?;
            p.hit_set_search_last_n = d.u32()?;
            p.opts = PoolOpts::decode(d)?;
            if v >= 25 {
                p.last_force_op_resend_prenautilus = d.u32()?;
            }
            if v >= 26 {
                p.application_metadata = BTreeMap::decode(d)?;
            }
            if v >= 27 {
                p.create_time = UTime::decode(d)?;
            }
            if v >= 28 {
                p.pg_num_target = d.u32()?;
                p.pgp_num_target = d.u32()?;
                p.pg_num_pending = d.u32()?;
                d.skip(8)?;
                p.last_force_op_resend = d.u32()?;
                p.pg_autoscale_mode = d.u8()?;
            } else {
                p.pg_num_target = p.pg_num;
                p.pgp_num_target = p.pgp_num;
                p.pg_num_pending = p.pg_num;
                p.last_force_op_resend = p.last_force_op_resend_prenautilus;
                p.pg_autoscale_mode = 1;
            }
            if v >= 29 {
                p.last_pg_merge_meta = PgMergeMeta::decode(d)?;
            }
            if v == 30 || (v >= 31 && d.u8()? != 0) {
                p.peering_crush = PeeringCrush::dec(d)?;
            }
            if v >= 32 {
                p.nonprimary_shards = ShardIdSet([d.varint()?, d.varint()?]);
            }
            if v >= 33 {
                p.shard_mapping = Vec::decode(d)?;
                p.ec_data_shard_count = Option::decode(d)?;
                p.ec_coding_shard_count = Option::decode(d)?;
            }
            if p.snap_seq > 0 && p.flags & (flags::SELFMANAGED_SNAPS | flags::POOL_SNAPS) == 0 {
                p.flags |= if p.removed_snaps.is_empty() {
                    flags::POOL_SNAPS
                } else {
                    flags::SELFMANAGED_SNAPS
                };
            }
            Ok(p)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        let m = |n| PgPool {
            pg_num: n,
            ..PgPool::default()
        };
        assert_eq!(m(8).pg_num_mask(), 7);
        assert_eq!(m(12).pg_num_mask(), 15);
        assert_eq!(m(1).pg_num_mask(), 0);
        assert_eq!(m(0).pg_num_mask(), u32::MAX);
    }

    #[test]
    fn default_roundtrip() {
        let p = PgPool::default();
        let b = p.encode_to_vec().unwrap();
        let q: PgPool = denc::from_slice(&b).unwrap();
        assert_eq!(p, q);
    }
}
