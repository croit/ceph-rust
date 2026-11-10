// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shared payload structs: OSDSuperblock + CompatSet, osd_stat_t family, LogEntry (spec
//! osd-lifecycle.md 1.3, 2.8, 8.4).

use denc::types::{EntityAddrVec, EntityName, Timespan, UTime, Uuid};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};
use std::collections::BTreeMap;

/// `interval_set<T>` wire form = `map<start, len>`.
pub type IntervalSet<T> = BTreeMap<T, T>;

/// `EntityName` (not `entity_name_t`): `u32 type` + `string id`. Used by MGetConfig and LogEntry.name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CephEntityNamePayload<I> {
    pub ty: u32,
    pub id: I,
}
pub type CephEntityName = CephEntityNamePayload<String>;
pub type ByteCephEntityName = CephEntityNamePayload<Vec<u8>>;

impl<I: AsRef<[u8]>> Encode for CephEntityNamePayload<I> {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u32(self.ty)?;
        e.bytes(self.id.as_ref())
    }
}
impl<'a, I: Decode<'a>> Decode<'a> for CephEntityNamePayload<I> {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            ty: d.u32()?,
            id: I::decode(d)?,
        })
    }
}

/// `signedspan` (std::chrono nanoseconds) wire form: i32 sec + i32 nsec, truncated toward zero,
/// nsec carries the sign of sec.
pub fn span_from_nanos(ns: i64) -> Timespan {
    Timespan {
        sec: (ns / 1_000_000_000) as i32,
        nsec: (ns % 1_000_000_000) as i32,
    }
}

/// Inverse of [`span_from_nanos`].
pub fn span_to_nanos(t: Timespan) -> i64 {
    t.sec as i64 * 1_000_000_000 + t.nsec as i64
}

// ---------------------------------------------------------------- CompatSet / OSDSuperblock

/// One feature set: bitmask (bit `id`) + `id -> name`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeatureSet {
    pub mask: u64,
    pub names: BTreeMap<u64, String>,
}

impl FeatureSet {
    /// Build from `(id, name)` pairs; `id` must be in `1..64` (bit 0 is never set on the wire, and the mask is a `u64`,
    /// so an out-of-range id is a programming error and asserts instead of shifting out of the mask).
    pub fn new(feats: &[(u64, &str)]) -> Self {
        let mut s = FeatureSet::default();
        for &(id, n) in feats {
            assert!((1..64).contains(&id), "feature id {id} out of range 1..64");
            s.mask |= 1u64 << id;
            s.names.insert(id, n.to_owned());
        }
        s
    }
}

impl Encode for FeatureSet {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u64(self.mask & !1)?;
        self.names.encode(e)
    }
}
impl<'a> Decode<'a> for FeatureSet {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(FeatureSet {
            mask: d.u64()?,
            names: BTreeMap::decode(d)?,
        })
    }
}

/// `CompatSet`: compat, ro_compat, incompat feature sets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompatSet {
    pub compat: FeatureSet,
    pub ro_compat: FeatureSet,
    pub incompat: FeatureSet,
}

impl CompatSet {
    /// The OSD feature set as sent in MOSDBoot (matches a real OSD byte for byte; includes id 11
    /// "sharded objects", which the spec lists as in-memory only but is on the wire).
    pub fn osd_initial() -> Self {
        CompatSet {
            compat: FeatureSet::default(),
            ro_compat: FeatureSet::default(),
            incompat: FeatureSet::new(&[
                (1, "initial feature set(~v.18)"),
                (2, "pginfo object"),
                (3, "object locator"),
                (4, "last_epoch_clean"),
                (5, "categories"),
                (6, "hobjectpool"),
                (7, "biginfo"),
                (8, "leveldbinfo"),
                (9, "leveldblog"),
                (10, "snapmapper"),
                (11, "sharded objects"),
                (12, "transaction hints"),
                (13, "pg meta object"),
                (14, "explicit missing set"),
                (15, "fastinfo pg attr"),
                (16, "deletes in missing set"),
                (17, "new snapmapper key structure"),
            ]),
        }
    }
}

impl Encode for CompatSet {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        self.compat.encode(e)?;
        self.ro_compat.encode(e)?;
        self.incompat.encode(e)
    }
}
impl<'a> Decode<'a> for CompatSet {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(CompatSet {
            compat: FeatureSet::decode(d)?,
            ro_compat: FeatureSet::decode(d)?,
            incompat: FeatureSet::decode(d)?,
        })
    }
}

/// OSDSuperblock wire form (v11, compat 5); sent inside MOSDBoot.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OsdSuperblock {
    pub cluster_fsid: Uuid,
    pub whoami: i32,
    pub current_epoch: u32,
    pub weight: f64,
    pub compat_features: CompatSet,
    pub clean_thru: u32,
    /// `mounted` (JSON: last_epoch_mounted).
    pub mounted: u32,
    pub osd_fsid: Uuid,
    pub purged_snaps_last: u32,
    pub last_purged_snaps_scrub: UTime,
    pub cluster_osdmap_trim_lower_bound: u32,
    /// Set of stored map epochs (`interval_set<epoch>`); empty for a never-booted OSD.
    pub mapc: IntervalSet<u32>,
}

impl OsdSuperblock {
    pub const STRUCT_V: u8 = 11;
    pub const STRUCT_COMPAT: u8 = 5;
}

impl Encode for OsdSuperblock {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            self.cluster_fsid.encode(e)?;
            e.i32(self.whoami)?;
            e.u32(self.current_epoch)?;
            e.u32(0)?; // oldest_map (legacy)
            e.u32(0)?; // newest_map (legacy)
            e.f64(self.weight)?;
            self.compat_features.encode(e)?;
            e.u32(self.clean_thru)?;
            e.u32(self.mounted)?;
            self.osd_fsid.encode(e)?;
            e.u32(0)?; // last_epoch_marked_full
            e.u32(0)?; // pool_last_epoch_marked_full (empty)
            e.u32(self.purged_snaps_last)?;
            self.last_purged_snaps_scrub.encode(e)?;
            e.u32(self.cluster_osdmap_trim_lower_bound)?;
            self.mapc.encode(e)
        })
    }
}
impl<'a> Decode<'a> for OsdSuperblock {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(Self::STRUCT_V, Self::STRUCT_COMPAT, |d, _v| {
            let cluster_fsid = Uuid::decode(d)?;
            let whoami = d.i32()?;
            let current_epoch = d.u32()?;
            d.skip(8)?;
            let weight = d.f64()?;
            let compat_features = CompatSet::decode(d)?;
            let clean_thru = d.u32()?;
            let mounted = d.u32()?;
            let osd_fsid = Uuid::decode(d)?;
            d.skip(4)?; // last_epoch_marked_full
            let n = d.count()?;
            // pool_last_epoch_marked_full: 8 B per entry assumed; map<i64,u32> would be 12 (doc/90-open-questions.md 62)
            d.skip(n.checked_mul(8).ok_or(Error::TooLong)?)?;
            let purged_snaps_last = d.u32()?;
            let last_purged_snaps_scrub = UTime::decode(d)?;
            let cluster_osdmap_trim_lower_bound = d.u32()?;
            let mapc = BTreeMap::decode(d)?;
            Ok(OsdSuperblock {
                cluster_fsid,
                whoami,
                current_epoch,
                weight,
                compat_features,
                clean_thru,
                mounted,
                osd_fsid,
                purged_snaps_last,
                last_purged_snaps_scrub,
                cluster_osdmap_trim_lower_bound,
                mapc,
            })
        })
    }
}

// ---------------------------------------------------------------- osd_stat_t family

/// store_statfs_t (v1, c1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoreStatfs {
    pub total: u64,
    pub available: u64,
    pub internally_reserved: u64,
    pub allocated: i64,
    pub data_stored: i64,
    pub data_compressed: i64,
    pub data_compressed_allocated: i64,
    pub data_compressed_original: i64,
    pub omap_allocated: i64,
    pub internal_metadata: i64,
}

impl Encode for StoreStatfs {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.u64(self.total)?;
            e.u64(self.available)?;
            e.u64(self.internally_reserved)?;
            e.i64(self.allocated)?;
            e.i64(self.data_stored)?;
            e.i64(self.data_compressed)?;
            e.i64(self.data_compressed_allocated)?;
            e.i64(self.data_compressed_original)?;
            e.i64(self.omap_allocated)?;
            e.i64(self.internal_metadata)
        })
    }
}
impl<'a> Decode<'a> for StoreStatfs {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, _| {
            Ok(StoreStatfs {
                total: d.u64()?,
                available: d.u64()?,
                internally_reserved: d.u64()?,
                allocated: d.i64()?,
                data_stored: d.i64()?,
                data_compressed: d.i64()?,
                data_compressed_allocated: d.i64()?,
                data_compressed_original: d.i64()?,
                omap_allocated: d.i64()?,
                internal_metadata: d.i64()?,
            })
        })
    }
}

/// pow2_hist_t (v1, c1): `vec<i32>`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pow2Hist(pub Vec<i32>);

impl Encode for Pow2Hist {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| self.0.encode(e))
    }
}
impl<'a> Decode<'a> for Pow2Hist {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, _| Ok(Pow2Hist(Vec::decode(d)?)))
    }
}

/// objectstore_perf_stat_t (spec pg-io-stats.md 4): commit / apply latency in ns. Encoded v2/c2 as two u64 ns when the
/// peer has `OS_PERF_STAT_NS`, else v1/c1 as two u32 ms (floor); v1 decodes as ms * 10^6. v21 daemons do not advertise the
/// feature (CEPH_FEATURES_ALL has bit 17 clear), so mgr sessions get v1 from classic OSDs and from us alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ObjectstorePerfStat {
    pub os_commit_latency_ns: u64,
    pub os_apply_latency_ns: u64,
}

impl Encode for ObjectstorePerfStat {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        if e.features() & denc::features::OS_PERF_STAT_NS == denc::features::OS_PERF_STAT_NS {
            e.versioned(2, 2, |e| {
                e.u64(self.os_commit_latency_ns)?;
                e.u64(self.os_apply_latency_ns)
            })
        } else {
            let ms = |ns: u64| (ns / 1_000_000).min(u64::from(u32::MAX)) as u32;
            e.versioned(1, 1, |e| {
                e.u32(ms(self.os_commit_latency_ns))?;
                e.u32(ms(self.os_apply_latency_ns))
            })
        }
    }
}
impl<'a> Decode<'a> for ObjectstorePerfStat {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(2, |d, v| {
            Ok(if v >= 2 {
                ObjectstorePerfStat {
                    os_commit_latency_ns: d.u64()?,
                    os_apply_latency_ns: d.u64()?,
                }
            } else {
                ObjectstorePerfStat {
                    os_commit_latency_ns: u64::from(d.u32()?) * 1_000_000,
                    os_apply_latency_ns: u64::from(d.u32()?) * 1_000_000,
                }
            })
        })
    }
}

/// One `hb_pingtime` entry; arrays index 0/1/2 = 1/5/15-sample values (microseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HbPingtime {
    pub osd: i32,
    pub last_update: u32,
    pub back_pingtime: [u32; 3],
    pub back_min: [u32; 3],
    pub back_max: [u32; 3],
    pub back_last: u32,
    pub front_pingtime: [u32; 3],
    pub front_min: [u32; 3],
    pub front_max: [u32; 3],
    pub front_last: u32,
}

impl HbPingtime {
    fn enc<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.i32(self.osd)?;
        e.u32(self.last_update)?;
        for a in [self.back_pingtime, self.back_min, self.back_max] {
            a.iter().try_for_each(|v| e.u32(*v))?;
        }
        e.u32(self.back_last)?;
        for a in [self.front_pingtime, self.front_min, self.front_max] {
            a.iter().try_for_each(|v| e.u32(*v))?;
        }
        e.u32(self.front_last)
    }
    fn dec(d: &mut Decoder<'_>) -> Result<Self> {
        let mut r = HbPingtime {
            osd: d.i32()?,
            last_update: d.u32()?,
            ..Default::default()
        };
        for a in [&mut r.back_pingtime, &mut r.back_min, &mut r.back_max] {
            for v in a.iter_mut() {
                *v = d.u32()?;
            }
        }
        r.back_last = d.u32()?;
        for a in [&mut r.front_pingtime, &mut r.front_min, &mut r.front_max] {
            for v in a.iter_mut() {
                *v = d.u32()?;
            }
        }
        r.front_last = d.u32()?;
        Ok(r)
    }
}

/// osd_stat_t (v14, compat 2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OsdStat {
    pub kb: i64,
    pub kb_used: i64,
    pub kb_avail: i64,
    pub snap_trim_queue_len: i32,
    pub num_snap_trimming: i32,
    pub hb_peers: Vec<i32>,
    pub op_queue_age_hist: Pow2Hist,
    pub os_perf_stat: ObjectstorePerfStat,
    pub up_from: u32,
    pub seq: u64,
    pub num_pgs: u32,
    pub kb_used_data: i64,
    pub kb_used_omap: i64,
    pub kb_used_meta: i64,
    pub statfs: StoreStatfs,
    pub os_alerts: BTreeMap<i32, BTreeMap<String, String>>,
    pub num_shards_repaired: u64,
    pub num_osds: u32,
    pub num_per_pool_osds: u32,
    pub num_per_pool_omap_osds: u32,
    pub hb_pingtime: Vec<HbPingtime>,
}

impl OsdStat {
    pub const STRUCT_V: u8 = 14;
    pub const STRUCT_COMPAT: u8 = 2;

    /// M1 stat for a single OSD from statfs: legacy kb fields derived per spec 8.4, num_osds=1.
    pub fn from_statfs(statfs: StoreStatfs, up_from: u32, seq: u64) -> Self {
        let used = statfs.total.saturating_sub(statfs.available);
        OsdStat {
            kb: (statfs.total >> 10) as i64,
            kb_used: (used >> 10) as i64,
            kb_avail: (statfs.available >> 10) as i64,
            up_from,
            seq,
            kb_used_data: statfs.allocated >> 10,
            kb_used_omap: statfs.omap_allocated >> 10,
            kb_used_meta: statfs.internal_metadata >> 10,
            statfs,
            num_osds: 1,
            num_per_pool_osds: 1,
            // spec 8.4 #21: no per-pool OMAP allocation estimator, so the mgr uses primary PG deep-scrub totals
            num_per_pool_omap_osds: 0,
            ..Default::default()
        }
    }
}

impl Encode for OsdStat {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            e.i64(self.kb)?;
            e.i64(self.kb_used)?;
            e.i64(self.kb_avail)?;
            e.i32(self.snap_trim_queue_len)?;
            e.i32(self.num_snap_trimming)?;
            self.hb_peers.encode(e)?;
            e.u32(0)?; // legacy num_hb_out (empty vec)
            self.op_queue_age_hist.encode(e)?;
            self.os_perf_stat.encode(e)?;
            e.u32(self.up_from)?;
            e.u64(self.seq)?;
            e.u32(self.num_pgs)?;
            e.i64(self.kb_used_data)?;
            e.i64(self.kb_used_omap)?;
            e.i64(self.kb_used_meta)?;
            self.statfs.encode(e)?;
            self.os_alerts.encode(e)?;
            e.u64(self.num_shards_repaired)?;
            e.u32(self.num_osds)?;
            e.u32(self.num_per_pool_osds)?;
            e.u32(self.num_per_pool_omap_osds)?;
            e.count(self.hb_pingtime.len())?;
            self.hb_pingtime.iter().try_for_each(|h| h.enc(e))
        })
    }
}
impl<'a> Decode<'a> for OsdStat {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(Self::STRUCT_V, Self::STRUCT_COMPAT, |d, _| {
            let kb = d.i64()?;
            let kb_used = d.i64()?;
            let kb_avail = d.i64()?;
            let snap_trim_queue_len = d.i32()?;
            let num_snap_trimming = d.i32()?;
            let hb_peers = Vec::<i32>::decode(d)?;
            let n = d.count()?;
            d.skip(n.checked_mul(4).ok_or(Error::TooLong)?)?; // legacy num_hb_out
            let op_queue_age_hist = Pow2Hist::decode(d)?;
            let os_perf_stat = ObjectstorePerfStat::decode(d)?;
            let up_from = d.u32()?;
            let seq = d.u64()?;
            let num_pgs = d.u32()?;
            let kb_used_data = d.i64()?;
            let kb_used_omap = d.i64()?;
            let kb_used_meta = d.i64()?;
            let statfs = StoreStatfs::decode(d)?;
            let os_alerts = BTreeMap::decode(d)?;
            let num_shards_repaired = d.u64()?;
            let num_osds = d.u32()?;
            let num_per_pool_osds = d.u32()?;
            let num_per_pool_omap_osds = d.u32()?;
            let n = d.count()?;
            let mut hb_pingtime = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                hb_pingtime.push(HbPingtime::dec(d)?);
            }
            Ok(OsdStat {
                kb,
                kb_used,
                kb_avail,
                snap_trim_queue_len,
                num_snap_trimming,
                hb_peers,
                op_queue_age_hist,
                os_perf_stat,
                up_from,
                seq,
                num_pgs,
                kb_used_data,
                kb_used_omap,
                kb_used_meta,
                statfs,
                os_alerts,
                num_shards_repaired,
                num_osds,
                num_per_pool_osds,
                num_per_pool_omap_osds,
                hb_pingtime,
            })
        })
    }
}

// ---------------------------------------------------------------- LogEntry

/// Cluster-log priorities (`LogEntry.prio`). Values confirmed against ceph-dencoder (see spec U6).
pub mod clog {
    pub const DEBUG: u16 = 0;
    pub const INFO: u16 = 1;
    pub const SEC: u16 = 2;
    pub const WARN: u16 = 3;
    pub const ERROR: u16 = 4;
}

/// LogEntry (v5, compat 5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogEntryPayload<I> {
    pub name: CephEntityNamePayload<I>,
    pub rank: EntityName,
    pub addrs: EntityAddrVec,
    pub stamp: UTime,
    pub seq: u64,
    pub prio: u16,
    pub msg: String,
    pub channel: String,
}
pub type LogEntry = LogEntryPayload<String>;
pub type ByteLogEntry = LogEntryPayload<Vec<u8>>;

impl<I: AsRef<[u8]>> Encode for LogEntryPayload<I> {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(5, 5, |e| {
            self.name.encode(e)?;
            self.rank.encode(e)?;
            self.addrs.encode(e)?;
            self.stamp.encode(e)?;
            e.u64(self.seq)?;
            e.u16(self.prio)?;
            self.msg.encode(e)?;
            self.channel.encode(e)
        })
    }
}
impl<'a, I: Decode<'a>> Decode<'a> for LogEntryPayload<I> {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(5, 5, |d, _| {
            Ok(Self {
                name: CephEntityNamePayload::decode(d)?,
                rank: EntityName::decode(d)?,
                addrs: EntityAddrVec::decode(d)?,
                stamp: UTime::decode(d)?,
                seq: d.u64()?,
                prio: d.u16()?,
                msg: String::decode(d)?,
                channel: String::decode(d)?,
            })
        })
    }
}
