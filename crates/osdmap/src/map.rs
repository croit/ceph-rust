// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! OSDMap full encoding (spec osdmap.md 1): byte-exact decode/encode + crc.

use crate::PoolName;
use crate::consts::{WEIGHT_IN, map_flags, osd_state, release};
use crate::error::{Error, Result};
use crate::interval::IntervalSet;
use crate::pool::PgPool;
use denc::types::{EntityAddr, EntityAddrVec, Fsid, PgT, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub const OUTER_V: u8 = 8;
pub const OUTER_COMPAT: u8 = 7;
/// Oldest outer struct_v accepted; older ones are the classic pre-envelope encoding.
pub const OUTER_MIN: u8 = 7;
pub const CLIENT_V_TOP: u8 = 10;
/// Oldest client-part version decoded (addrvec era).
pub const CLIENT_V_MIN: u8 = 8;
/// Oldest osd-part version decoded (addrvec era).
pub const OSD_V_MIN: u8 = 7;

/// Canonical exact-blocklist key; range keys retain their CIDR type.
pub(crate) fn blocklist_key(mut address: EntityAddr, required_release: u8) -> EntityAddr {
    address.ty = if required_release != 0 && required_release < release::NAUTILUS {
        EntityAddr::TYPE_LEGACY
    } else {
        EntityAddr::TYPE_ANY
    };
    address
}

/// osd_info_t (no envelope; u8 struct_v = 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OsdInfo {
    pub last_clean_begin: u32,
    pub last_clean_end: u32,
    pub up_from: u32,
    pub up_thru: u32,
    pub down_at: u32,
    pub lost_at: u32,
}
impl Encode for OsdInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        e.u32(self.last_clean_begin)?;
        e.u32(self.last_clean_end)?;
        e.u32(self.up_from)?;
        e.u32(self.up_thru)?;
        e.u32(self.down_at)?;
        e.u32(self.lost_at)
    }
}
impl<'a> Decode<'a> for OsdInfo {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        let _v = d.u8()?;
        Ok(OsdInfo {
            last_clean_begin: d.u32()?,
            last_clean_end: d.u32()?,
            up_from: d.u32()?,
            up_thru: d.u32()?,
            down_at: d.u32()?,
            lost_at: d.u32()?,
        })
    }
}

/// osd_xinfo_t, ENV(4,1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OsdXInfo {
    pub down_stamp: UTime,
    pub laggy_probability: u32,
    pub laggy_interval: u32,
    pub features: u64,
    pub old_weight: u32,
    pub last_purged_snaps_scrub: UTime,
    pub dead_epoch: u32,
}
impl Encode for OsdXInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(4, 1, |e| {
            self.down_stamp.encode(e)?;
            e.u32(self.laggy_probability)?;
            e.u32(self.laggy_interval)?;
            e.u64(self.features)?;
            e.u32(self.old_weight)?;
            self.last_purged_snaps_scrub.encode(e)?;
            e.u32(self.dead_epoch)
        })
    }
}
impl<'a> Decode<'a> for OsdXInfo {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned_min(1, 1, |d, v| {
            let mut x = OsdXInfo {
                down_stamp: UTime::decode(d)?,
                laggy_probability: d.u32()?,
                laggy_interval: d.u32()?,
                ..Default::default()
            };
            if v >= 2 {
                x.features = d.u64()?;
            }
            if v >= 3 {
                x.old_weight = d.u32()?;
            }
            if v >= 4 {
                x.last_purged_snaps_scrub = UTime::decode(d)?;
                x.dead_epoch = d.u32()?;
            }
            Ok(x)
        })
    }
}

/// Decoded OSDMap.
#[derive(Debug, Clone, PartialEq)]
pub struct OsdMap {
    pub fsid: Fsid,
    pub epoch: u32,
    pub created: UTime,
    pub modified: UTime,
    pub pools: BTreeMap<i64, PgPool>,
    pub pool_name: BTreeMap<i64, PoolName>,
    pub pool_max: i32,
    pub flags: u32,
    pub max_osd: i32,
    pub osd_state: Vec<u32>,
    pub osd_weight: Vec<u32>,
    pub client_addrs: Vec<EntityAddrVec>,
    pub pg_temp: BTreeMap<PgT, Vec<i32>>,
    pub primary_temp: BTreeMap<PgT, i32>,
    /// Empty = nobody has non-default affinity; else length max_osd.
    pub osd_primary_affinity: Vec<u32>,
    /// CRUSH map blob in the encoding the mon stored for this epoch (see [`Self::crush_blob`]); private so that the
    /// decoded cache below can never go stale.
    // Incremental epochs retain the immutable blob until CRUSH is replaced.
    crush: Arc<Vec<u8>>,
    /// Decoded form of `crush` (lazy), always built from the current blob ([`OsdMap::set_crush`]).
    pub(crate) crush_cache: crate::crushmap::CrushCache,
    pub erasure_code_profiles: BTreeMap<String, BTreeMap<String, String>>,
    pub pg_upmap: BTreeMap<PgT, Vec<i32>>,
    pub pg_upmap_items: BTreeMap<PgT, Vec<(i32, i32)>>,
    pub crush_version: u32,
    pub new_removed_snaps: BTreeMap<i64, IntervalSet>,
    pub new_purged_snaps: BTreeMap<i64, IntervalSet>,
    pub last_up_change: UTime,
    pub last_in_change: UTime,
    pub pg_upmap_primaries: BTreeMap<PgT, i32>,
    // osd-only part
    pub hb_back_addrs: Vec<EntityAddrVec>,
    pub osd_info: Vec<OsdInfo>,
    pub blocklist: BTreeMap<EntityAddr, UTime>,
    pub cluster_addrs: Vec<EntityAddrVec>,
    pub cluster_snapshot_epoch: u32,
    pub cluster_snapshot: String,
    pub osd_uuid: Vec<Fsid>,
    pub osd_xinfo: Vec<OsdXInfo>,
    pub hb_front_addrs: Vec<EntityAddrVec>,
    pub nearfull_ratio: f32,
    pub full_ratio: f32,
    pub backfillfull_ratio: f32,
    pub require_min_compat_client: u8,
    pub require_osd_release: u8,
    pub removed_snaps_queue: BTreeMap<i64, IntervalSet>,
    pub crush_node_flags: BTreeMap<i32, u32>,
    pub device_class_flags: BTreeMap<i32, u32>,
    pub stretch_mode_enabled: bool,
    pub stretch_bucket_count: u32,
    pub degraded_stretch_mode: u32,
    pub recovering_stretch_mode: u32,
    pub stretch_mode_bucket: i32,
    /// CIDR ranges (nonce = prefix bits, spec 5.4); private so that the prefix index below stays in step.
    range_blocklist: BTreeMap<EntityAddr, UTime>,
    /// Prefix index of `range_blocklist` (derived, keeps equal).
    range_index: RangeIndex,
    pub allow_crimson: bool,
}

impl Default for OsdMap {
    fn default() -> Self {
        OsdMap {
            fsid: Fsid::default(),
            epoch: 0,
            created: UTime::default(),
            modified: UTime::default(),
            pools: BTreeMap::new(),
            pool_name: BTreeMap::new(),
            pool_max: 0,
            flags: 0,
            max_osd: 0,
            osd_state: vec![],
            osd_weight: vec![],
            client_addrs: vec![],
            pg_temp: BTreeMap::new(),
            primary_temp: BTreeMap::new(),
            osd_primary_affinity: vec![],
            crush: Arc::default(),
            crush_cache: Default::default(),
            erasure_code_profiles: BTreeMap::new(),
            pg_upmap: BTreeMap::new(),
            pg_upmap_items: BTreeMap::new(),
            crush_version: 1,
            new_removed_snaps: BTreeMap::new(),
            new_purged_snaps: BTreeMap::new(),
            last_up_change: UTime::default(),
            last_in_change: UTime::default(),
            pg_upmap_primaries: BTreeMap::new(),
            hb_back_addrs: vec![],
            osd_info: vec![],
            blocklist: BTreeMap::new(),
            cluster_addrs: vec![],
            cluster_snapshot_epoch: 0,
            cluster_snapshot: String::new(),
            osd_uuid: vec![],
            osd_xinfo: vec![],
            hb_front_addrs: vec![],
            nearfull_ratio: 0.0,
            full_ratio: 0.0,
            backfillfull_ratio: 0.0,
            require_min_compat_client: 0,
            require_osd_release: 0,
            removed_snaps_queue: BTreeMap::new(),
            crush_node_flags: BTreeMap::new(),
            device_class_flags: BTreeMap::new(),
            stretch_mode_enabled: false,
            stretch_bucket_count: 0,
            degraded_stretch_mode: 0,
            recovering_stretch_mode: 0,
            stretch_mode_bucket: 0,
            range_blocklist: BTreeMap::new(),
            range_index: RangeIndex::default(),
            allow_crimson: false,
        }
    }
}

/// Ceph crc32c seed (all ones).
const CRC_SEED: u32 = 0xFFFF_FFFF;

/// crc over `front ++ tail` with Ceph seed semantics (spec 1.4).
pub fn crc_front_tail(front: &[u8], tail: &[u8]) -> u32 {
    crc::crc32c(crc::crc32c(CRC_SEED, front), tail)
}

impl OsdMap {
    /// Decode a full map; verifies the crc when outer struct_v >= 8.
    /// Rejects `max_osd` above [`crate::consts::MAX_OSD_SLOTS`] before decoding
    /// per-OSD arrays or allocating their defaults.
    pub fn decode_from(buf: &[u8]) -> Result<Self> {
        Self::decode_opts(buf, true)
    }

    /// Decode with optional crc verification.
    pub fn decode_opts(buf: &[u8], verify_crc: bool) -> Result<Self> {
        let mut d = Decoder::new(buf);
        let m = Self::decode_inner(&mut d, verify_crc)?;
        if d.remaining() != 0 {
            return Err(denc::Error::TrailingBytes(d.remaining()).into());
        }
        Ok(m)
    }

    fn decode_inner(d: &mut Decoder<'_>, verify_crc: bool) -> Result<Self> {
        let base = d.peek_rest();
        let start = d.position();
        if let Some(&v) = base.first()
            && v < OUTER_MIN
        {
            return Err(Error::Classic(v));
        }
        let mut crc_err = None;
        let mut m = d.versioned(OUTER_COMPAT, |d, outer_v| {
            let mut m = OsdMap::default();
            d.versioned_min(CLIENT_V_MIN, 1, |d, v| m.decode_client(d, v))?;
            d.versioned_min(OSD_V_MIN, 1, |d, v| m.decode_osd(d, v))?;
            if outer_v >= 8 {
                let crc_off = d.position() - start;
                let stored = d.u32()?;
                if verify_crc {
                    let computed = crc_front_tail(&base[..crc_off], d.peek_rest());
                    if computed != stored {
                        crc_err = Some(Error::BadCrc { stored, computed });
                    }
                }
            }
            // Decode-time flag side effects (spec 1.3).
            m.apply_release_flags();
            Ok(m)
        })?;
        if let Some(e) = crc_err {
            return Err(e);
        }
        m.normalize_blocklist(m.require_osd_release);
        m.check_max_osd()?;
        m.fixup_lengths();
        Ok(m)
    }

    fn decode_client(&mut self, d: &mut Decoder<'_>, v: u8) -> denc::Result<()> {
        self.fsid = Fsid::decode(d)?;
        self.epoch = d.u32()?;
        self.created = UTime::decode(d)?;
        self.modified = UTime::decode(d)?;
        self.pools = BTreeMap::decode(d)?;
        self.pool_name = BTreeMap::decode(d)?;
        self.pool_max = d.i32()?;
        self.flags = d.u32()?;
        self.max_osd = d.i32()?;
        if self.max_osd > crate::consts::MAX_OSD_SLOTS {
            return Err(denc::Error::BadValue("max_osd exceeds MAX_OSD_SLOTS"));
        }
        self.osd_state = Vec::decode(d)?;
        self.osd_weight = Vec::decode(d)?;
        self.client_addrs = Vec::decode(d)?;
        self.pg_temp = BTreeMap::decode(d)?;
        self.primary_temp = BTreeMap::decode(d)?;
        self.osd_primary_affinity = Vec::decode(d)?;
        self.crush = Arc::new(Vec::<u8>::decode(d)?);
        self.crush_cache = Default::default();
        self.erasure_code_profiles = BTreeMap::decode(d)?;
        self.pg_upmap = BTreeMap::decode(d)?;
        self.pg_upmap_items = BTreeMap::decode(d)?;
        self.crush_version = d.u32()?;
        self.new_removed_snaps = BTreeMap::decode(d)?;
        self.new_purged_snaps = BTreeMap::decode(d)?;
        if v >= 9 {
            self.last_up_change = UTime::decode(d)?;
            self.last_in_change = UTime::decode(d)?;
        }
        if v >= 10 {
            self.pg_upmap_primaries = BTreeMap::decode(d)?;
        }
        Ok(())
    }

    fn decode_osd(&mut self, d: &mut Decoder<'_>, v: u8) -> denc::Result<()> {
        self.hb_back_addrs = Vec::decode(d)?;
        self.osd_info = Vec::decode(d)?;
        self.blocklist = BTreeMap::decode(d)?;
        self.cluster_addrs = Vec::decode(d)?;
        self.cluster_snapshot_epoch = d.u32()?;
        self.cluster_snapshot = String::decode(d)?;
        self.osd_uuid = Vec::decode(d)?;
        self.osd_xinfo = Vec::decode(d)?;
        self.hb_front_addrs = Vec::decode(d)?;
        self.nearfull_ratio = d.f32()?;
        self.full_ratio = d.f32()?;
        self.backfillfull_ratio = d.f32()?;
        self.require_min_compat_client = d.u8()?;
        self.require_osd_release = d.u8()?;
        self.removed_snaps_queue = BTreeMap::decode(d)?;
        if v >= 8 {
            self.crush_node_flags = BTreeMap::decode(d)?;
        }
        if v >= 9 {
            self.device_class_flags = BTreeMap::decode(d)?;
        }
        if v >= 10 {
            self.stretch_mode_enabled = d.bool()?;
            self.stretch_bucket_count = d.u32()?;
            self.degraded_stretch_mode = d.u32()?;
            self.recovering_stretch_mode = d.u32()?;
            self.stretch_mode_bucket = d.i32()?;
        }
        if v >= 11 {
            self.range_blocklist = BTreeMap::decode(d)?;
            self.range_index = RangeIndex::build(&self.range_blocklist);
        }
        if v >= 12 {
            self.allow_crimson = d.bool()?;
        }
        Ok(())
    }

    /// Release-derived flag bits (also used when `require_osd_release` is raised).
    pub(crate) fn apply_release_flags(&mut self) {
        if self.require_osd_release >= release::NAUTILUS {
            self.flags |= map_flags::PGLOG_HARDLIMIT;
        }
        if self.require_osd_release >= release::LUMINOUS {
            self.flags &= !(map_flags::REQUIRE_JEWEL
                | map_flags::REQUIRE_KRAKEN
                | map_flags::REQUIRE_LUMINOUS);
            self.flags |= map_flags::RECOVERY_DELETES;
        }
    }

    /// Exact blocklist entries describe endpoints independently of messenger
    /// protocol. Establish the same key domain used by incremental apply and
    /// lookup after checking the CRC of the original wire bytes.
    pub(crate) fn normalize_blocklist(&mut self, release: u8) {
        self.blocklist = std::mem::take(&mut self.blocklist)
            .into_iter()
            .map(|(address, expiry)| (blocklist_key(address, release), expiry))
            .collect();
    }

    /// Wire acceptance of `max_osd` (spec osdmap 1.3): never negative and never above the length of the per-osd state
    /// array decoded with it (every encoder writes `osd_state` with exactly `max_osd` entries). Bounds what
    /// [`Self::fixup_lengths`] allocates by bytes actually present on the wire.
    fn check_max_osd(&self) -> Result<()> {
        if self.max_osd < 0 || self.max_osd as usize > self.osd_state.len() {
            return Err(Error::Invalid(
                "max_osd exceeds the decoded osd_state array",
            ));
        }
        Ok(())
    }

    /// Make per-osd arrays exactly max_osd long (tolerates short input).
    fn fixup_lengths(&mut self) {
        self.resize_osd_arrays(self.max_osd.max(0) as usize);
    }

    /// Resize every per-osd array to `n` (spec 1.7): grow appends defaults, shrink truncates.
    fn resize_osd_arrays(&mut self, n: usize) {
        self.osd_state.resize(n, 0);
        self.osd_weight.resize(n, 0);
        self.client_addrs.resize(n, EntityAddrVec::default());
        self.hb_back_addrs.resize(n, EntityAddrVec::default());
        self.hb_front_addrs.resize(n, EntityAddrVec::default());
        self.cluster_addrs.resize(n, EntityAddrVec::default());
        self.osd_info.resize(n, OsdInfo::default());
        self.osd_xinfo.resize(n, OsdXInfo::default());
        self.osd_uuid.resize(n, Fsid::default());
        if !self.osd_primary_affinity.is_empty() {
            self.osd_primary_affinity.resize(n, WEIGHT_IN);
        }
    }

    fn encode_client(&self, e: &mut Encoder<Vec<u8>>, features: u64) -> denc::Result<()> {
        // spec osdmap 1.3: 10 with SERVER_REEF, else 9 (nautilus+; older ladders never joined)
        let v = if denc::features::have_or_all(features, denc::features::SERVER_REEF) {
            CLIENT_V_TOP
        } else {
            9
        };
        e.versioned(v, 1, |e| {
            self.fsid.encode(e)?;
            e.u32(self.epoch)?;
            self.created.encode(e)?;
            self.modified.encode(e)?;
            e.u32(self.pools.len() as u32)?;
            for (id, p) in &self.pools {
                e.i64(*id)?;
                p.encode_v(e, p.version_for(features))?;
            }
            self.pool_name.encode(e)?;
            e.i32(self.pool_max)?;
            e.u32(self.flags)?;
            e.i32(self.max_osd)?;
            self.osd_state.encode(e)?;
            self.osd_weight.encode(e)?;
            self.client_addrs.encode(e)?;
            self.pg_temp.encode(e)?;
            self.primary_temp.encode(e)?;
            self.osd_primary_affinity.encode(e)?;
            self.crush.as_ref().encode(e)?;
            self.erasure_code_profiles.encode(e)?;
            self.pg_upmap.encode(e)?;
            self.pg_upmap_items.encode(e)?;
            e.u32(self.crush_version)?;
            self.new_removed_snaps.encode(e)?;
            self.new_purged_snaps.encode(e)?;
            self.last_up_change.encode(e)?;
            self.last_in_change.encode(e)?;
            if v >= 10 {
                self.pg_upmap_primaries.encode(e)?;
            }
            Ok(())
        })
    }

    /// osd-only part version (top ladder, spec 1.3).
    pub fn osd_part_version(&self) -> u8 {
        let mut v = 9;
        if self.stretch_mode_enabled {
            v = v.max(10);
        }
        if !self.range_blocklist.is_empty() {
            v = v.max(11);
        }
        if self.allow_crimson {
            v = v.max(12);
        }
        v
    }

    fn encode_osd(&self, e: &mut Encoder<Vec<u8>>) -> denc::Result<()> {
        let ov = self.osd_part_version();
        e.versioned(ov, 1, |e| {
            self.hb_back_addrs.encode(e)?;
            self.osd_info.encode(e)?;
            self.blocklist.encode(e)?;
            self.cluster_addrs.encode(e)?;
            e.u32(self.cluster_snapshot_epoch)?;
            self.cluster_snapshot.encode(e)?;
            self.osd_uuid.encode(e)?;
            self.osd_xinfo.encode(e)?;
            self.hb_front_addrs.encode(e)?;
            e.f32(self.nearfull_ratio)?;
            e.f32(self.full_ratio)?;
            e.f32(self.backfillfull_ratio)?;
            e.u8(self.require_min_compat_client)?;
            e.u8(self.require_osd_release)?;
            self.removed_snaps_queue.encode(e)?;
            self.crush_node_flags.encode(e)?;
            self.device_class_flags.encode(e)?;
            if ov >= 10 {
                e.bool(self.stretch_mode_enabled)?;
                e.u32(self.stretch_bucket_count)?;
                e.u32(self.degraded_stretch_mode)?;
                e.u32(self.recovering_stretch_mode)?;
                e.i32(self.stretch_mode_bucket)?;
            }
            if ov >= 11 {
                self.range_blocklist.encode(e)?;
            }
            if ov >= 12 {
                e.bool(self.allow_crimson)?;
            }
            Ok(())
        })
    }

    /// Encode the full map (top versions) incl. crc. Always uses all features.
    pub fn encode_full(&self) -> Result<Vec<u8>> {
        self.encode_with_features(0)
    }

    /// Encode the full map as the mon does for `features` (an incremental's `encode_features`; 0 = all), incl. crc:
    /// the client part and pool versions follow the release ladder (spec osdmap 1.3, 2), the CRUSH blob is stored
    /// already re-encoded for the incremental (step 25).
    pub fn encode_with_features(&self, features: u64) -> Result<Vec<u8>> {
        Ok(self.encode_denc(features)?)
    }

    /// [`Self::encode_with_features`] without the crate error wrapper, so [`Encode`] reports the original cause.
    fn encode_denc(&self, features: u64) -> denc::Result<Vec<u8>> {
        let mut e = Encoder::new();
        self.encode_client(&mut e, features)?;
        self.encode_osd(&mut e)?;
        let mut body = e.into_vec();
        // crc covers the outer header (incl. total length) + body, crc excluded.
        let len = u32::try_from(body.len() + 4).map_err(|_| denc::Error::TooLong)?;
        let mut out = Vec::with_capacity(body.len() + 10);
        out.push(OUTER_V);
        out.push(OUTER_COMPAT);
        out.extend_from_slice(&len.to_le_bytes());
        out.append(&mut body);
        let crc = crc_front_tail(&out, &[]);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    /// CRC of the map re-encoded for `features` (what the mon stores in `full_crc`; 0 = all features).
    pub fn crc(&self, features: u64) -> Result<u32> {
        let b = self.encode_with_features(features)?;
        let n = b.len();
        Ok(u32::from_le_bytes([b[n - 4], b[n - 3], b[n - 2], b[n - 1]]))
    }

    // ---- accessors -------------------------------------------------------

    /// Raw `osd_state` word, 0 for an id outside `0..max_osd`. A per-osd array shorter than `max_osd` reads as 0
    /// (spec 1.7 defaults) instead of panicking, so every accessor below tolerates a hand-built map.
    pub fn raw_state(&self, o: i32) -> u32 {
        if o < 0 || o >= self.max_osd {
            return 0;
        }
        self.osd_state.get(o as usize).copied().unwrap_or(0)
    }
    pub fn exists(&self, o: i32) -> bool {
        self.raw_state(o) & osd_state::EXISTS != 0
    }
    /// `noup` for `o` from any source (spec osd-lifecycle.md 3.2): the global map flag, the OSD's own state bit (only
    /// while it exists), the `ceph osd set-group` flags of a CRUSH bucket on its location
    /// ([`crush::CrushMap::location_ids`]) or of its device class. An undecodable CRUSH map contributes nothing.
    pub fn is_noup(&self, o: i32) -> bool {
        if self.flags & map_flags::NOUP != 0
            || (self.exists(o) && self.raw_state(o) & osd_state::NOUP != 0)
        {
            return true;
        }
        if self.crush_node_flags.is_empty() && self.device_class_flags.is_empty() {
            return false;
        }
        let Some(c) = self.crush_state() else {
            return false;
        };
        let by_node = !self.crush_node_flags.is_empty()
            && c.map.location_ids(o).iter().any(|b| {
                self.crush_node_flags
                    .get(b)
                    .is_some_and(|f| f & osd_state::NOUP != 0)
            });
        by_node
            || c.map.class_map.get(&o).is_some_and(|cls| {
                *cls >= 0
                    && self
                        .device_class_flags
                        .get(cls)
                        .is_some_and(|f| f & osd_state::NOUP != 0)
            })
    }
    pub fn is_up(&self, o: i32) -> bool {
        self.exists(o) && self.raw_state(o) & osd_state::UP != 0
    }
    /// The mons marked the OSD full.
    pub fn is_full(&self, o: i32) -> bool {
        self.exists(o) && self.raw_state(o) & osd_state::FULL != 0
    }
    /// 16.16 weight, 0 if the id is invalid.
    pub fn weight(&self, o: i32) -> u32 {
        if o < 0 || o >= self.max_osd {
            return 0;
        }
        self.osd_weight.get(o as usize).copied().unwrap_or(0)
    }
    pub fn is_in(&self, o: i32) -> bool {
        self.exists(o) && self.weight(o) != 0
    }
    pub fn is_out(&self, o: i32) -> bool {
        !self.is_in(o)
    }
    pub fn primary_affinity(&self, o: i32) -> u32 {
        if o < 0 || o >= self.max_osd {
            return WEIGHT_IN;
        }
        self.osd_primary_affinity
            .get(o as usize)
            .copied()
            .unwrap_or(WEIGHT_IN)
    }
    pub fn num_osd(&self) -> usize {
        (0..self.max_osd).filter(|&o| self.exists(o)).count()
    }
    pub fn num_up_osd(&self) -> usize {
        (0..self.max_osd).filter(|&o| self.is_up(o)).count()
    }
    pub fn pool(&self, id: i64) -> Option<&PgPool> {
        self.pools.get(&id)
    }
    pub fn pool_id_by_name(&self, name: &str) -> Option<i64> {
        self.pool_id_by_name_bytes(name.as_bytes())
    }
    /// Exact name-table lookup; pool-definition existence is checked separately.
    pub fn pool_id_by_name_bytes(&self, name: &[u8]) -> Option<i64> {
        self.pool_name
            .iter()
            .find(|(_, n)| n.as_bytes() == name)
            .map(|(id, _)| *id)
    }

    /// Resize all per-osd arrays (spec 1.7): grow appends defaults, shrink truncates.
    pub fn set_max_osd(&mut self, n: i32) {
        let n = n.max(0);
        self.max_osd = n;
        self.resize_osd_arrays(n as usize);
    }

    /// Blocklist match for a client address (spec 5.4).
    pub fn is_blocklisted(&self, a: &EntityAddr) -> bool {
        if self.blocklist.is_empty() && self.range_index.is_empty() {
            return false; // hot path: every client op asks
        }
        let k = blocklist_key(*a, self.require_osd_release);
        if self.blocklist.contains_key(&k) {
            return true;
        }
        let mut ip_only = k;
        ip_only.data[0] = 0;
        ip_only.data[1] = 0;
        ip_only.nonce = 0;
        self.blocklist.contains_key(&ip_only) || self.range_index.matches(&k)
    }

    /// CIDR ranges in the blocklist (spec 5.4: nonce holds the prefix length).
    pub fn range_blocklist(&self) -> &BTreeMap<EntityAddr, UTime> {
        &self.range_blocklist
    }

    /// Add a CIDR range to the blocklist.
    pub fn insert_range_blocklist(&mut self, a: EntityAddr, t: UTime) {
        // a re-added range only renews its expiry: indexed once per list entry
        if self.range_blocklist.insert(a, t).is_none() {
            self.range_index.insert(&a);
        }
    }

    /// Remove a CIDR range from the blocklist.
    pub(crate) fn remove_range_blocklist(&mut self, a: &EntityAddr) {
        if self.range_blocklist.remove(a).is_some() {
            self.range_index.remove(a);
        }
    }
}

/// Prefix index of [`OsdMap::range_blocklist`]: the masked addresses per present prefix length and family, so a client
/// address costs one lookup per prefix length in use instead of a comparison per range entry.
#[derive(Clone, Debug, Default)]
struct RangeIndex {
    v4: Vec<(u8, HashMap<u32, u32>)>,
    v6: Vec<(u8, HashMap<u128, u32>)>,
}

impl RangeIndex {
    fn build(list: &BTreeMap<EntityAddr, UTime>) -> Self {
        let mut ix = RangeIndex::default();
        for a in list.keys() {
            ix.insert(a);
        }
        ix
    }
    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
    fn insert(&mut self, a: &EntityAddr) {
        if let Some(ip) = a.ipv4() {
            let (bits, v) = (
                a.nonce.min(32) as u8,
                u32::from_be_bytes(ip) & v4_mask(a.nonce),
            );
            insert_masked(&mut self.v4, bits, v);
        } else if let Some(ip) = a.ipv6() {
            let (bits, v) = (
                a.nonce.min(128) as u8,
                u128::from_be_bytes(ip) & v6_mask(a.nonce),
            );
            insert_masked(&mut self.v6, bits, v);
        }
    }
    fn remove(&mut self, a: &EntityAddr) {
        if let Some(ip) = a.ipv4() {
            remove_masked(
                &mut self.v4,
                a.nonce.min(32) as u8,
                u32::from_be_bytes(ip) & v4_mask(a.nonce),
            );
        } else if let Some(ip) = a.ipv6() {
            remove_masked(
                &mut self.v6,
                a.nonce.min(128) as u8,
                u128::from_be_bytes(ip) & v6_mask(a.nonce),
            );
        }
    }
    fn matches(&self, a: &EntityAddr) -> bool {
        if let Some(ip) = a.ipv4() {
            let x = u32::from_be_bytes(ip);
            return self
                .v4
                .iter()
                .any(|&(bits, ref set)| set.contains_key(&(x & v4_mask(u32::from(bits)))));
        }
        if let Some(ip) = a.ipv6() {
            let x = u128::from_be_bytes(ip);
            return self
                .v6
                .iter()
                .any(|&(bits, ref set)| set.contains_key(&(x & v6_mask(u32::from(bits)))));
        }
        false
    }
}

impl PartialEq for RangeIndex {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

fn insert_masked<T: Eq + std::hash::Hash>(groups: &mut Vec<(u8, HashMap<T, u32>)>, bits: u8, v: T) {
    // counted: two list entries (different address/port/type) can share one masked prefix
    match groups.iter_mut().find(|(b, _)| *b == bits) {
        Some((_, set)) => *set.entry(v).or_insert(0) += 1,
        None => groups.push((bits, HashMap::from([(v, 1)]))),
    }
}

fn remove_masked<T: Eq + std::hash::Hash>(groups: &mut Vec<(u8, HashMap<T, u32>)>, bits: u8, v: T) {
    let Some(i) = groups.iter().position(|(b, _)| *b == bits) else {
        return;
    };
    let set = &mut groups[i].1;
    if let Some(n) = set.get_mut(&v) {
        *n -= 1;
        if *n == 0 {
            set.remove(&v);
        }
    }
    if set.is_empty() {
        groups.remove(i);
    }
}

/// Top `bits` bits of a 32-bit address (bits = 0 matches everything).
fn v4_mask(bits: u32) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits.min(32))
    }
}

/// Top `bits` bits of a 128-bit address (bits = 0 matches everything).
fn v6_mask(bits: u32) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits.min(128))
    }
}

impl<'a> Decode<'a> for OsdMap {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        OsdMap::decode_inner(d, true).map_err(|e| match e {
            Error::Denc(e) => e,
            Error::BadCrc { .. } => denc::Error::BadValue("osdmap crc mismatch"),
            Error::Classic(_) => denc::Error::BadValue("classic osdmap encoding"),
            _ => denc::Error::BadValue("osdmap"),
        })
    }
}
impl Encode for OsdMap {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.raw(&self.encode_denc(0)?)
    }
}

impl OsdMap {
    /// CRUSH map blob as stored for this epoch.
    pub fn crush_blob(&self) -> &[u8] {
        &self.crush
    }

    /// Replace the CRUSH blob (invalidates the decoded cache).
    pub fn set_crush(&mut self, blob: Vec<u8>) {
        self.crush = Arc::new(blob);
        self.crush_cache = Default::default();
    }

    /// Replace the blob with one whose decoded form is already known (spec 3.2 step 25).
    pub(crate) fn set_crush_decoded(&mut self, blob: Vec<u8>, map: crush::CrushMap) {
        self.crush = Arc::new(blob);
        self.crush_cache = crate::crushmap::CrushCache::with(map);
    }

    /// Decoded CRUSH map (decoded on first use). `None` if empty/undecodable.
    pub fn crush_state(&self) -> Option<&std::sync::Arc<crate::CrushState>> {
        self.crush_cache.get(&self.crush)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(bits: u32, ip: [u8; 4]) -> EntityAddr {
        EntityAddr::v4(EntityAddr::TYPE_CIDR, bits, ip, 0)
    }

    fn client(ip: [u8; 4]) -> EntityAddr {
        EntityAddr::v4(EntityAddr::TYPE_ANY, 0, ip, 7)
    }

    /// Independent reference for spec 5.4: keep the top `bits` bits.
    fn masked4(x: u32, bits: u32) -> u32 {
        if bits >= 32 {
            x
        } else {
            x & !(u32::MAX >> bits)
        }
    }

    fn masked6(x: u128, bits: u32) -> u128 {
        if bits >= 128 {
            x
        } else {
            x & !(u128::MAX >> bits)
        }
    }

    fn v6(addr: [u8; 16]) -> EntityAddr {
        EntityAddr::v6(EntityAddr::TYPE_ANY, 0, addr, 3, 0)
    }

    /// The prefix index answers exactly like a scan over the entries (spec 5.4).
    #[test]
    fn range_index_matches_a_scan() {
        let mut m = OsdMap::default();
        for (bits, ip) in [
            (0, [0; 4]),
            (8, [10, 0, 0, 0]),
            (16, [10, 1, 0, 0]),
            (24, [192, 168, 1, 0]),
            (32, [172, 16, 0, 1]),
        ] {
            m.insert_range_blocklist(range(bits, ip), UTime::default());
        }
        let mut net = [0u8; 16];
        net[0] = 0xfd;
        m.insert_range_blocklist(
            EntityAddr::v6(EntityAddr::TYPE_CIDR, 8, net, 0, 0),
            UTime::default(),
        );
        let scan = |a: &EntityAddr| {
            m.range_blocklist().keys().any(|e| {
                if let (Some(r), Some(x)) = (e.ipv4(), a.ipv4()) {
                    masked4(u32::from_be_bytes(r), e.nonce)
                        == masked4(u32::from_be_bytes(x), e.nonce)
                } else if let (Some(r), Some(x)) = (e.ipv6(), a.ipv6()) {
                    masked6(u128::from_be_bytes(r), e.nonce)
                        == masked6(u128::from_be_bytes(x), e.nonce)
                } else {
                    false
                }
            })
        };
        let mut addrs: Vec<EntityAddr> = [
            [10, 1, 2, 3],
            [10, 2, 2, 3],
            [192, 168, 1, 9],
            [192, 168, 2, 9],
            [172, 16, 0, 1],
            [172, 16, 0, 2],
            [255, 255, 255, 255],
        ]
        .iter()
        .map(|ip| client(*ip))
        .collect();
        let mut inside = [0u8; 16];
        inside[0] = 0xfd;
        let mut outside = inside;
        outside[0] = 0xfe;
        addrs.push(v6(inside));
        addrs.push(v6(outside));
        for a in &addrs {
            assert_eq!(m.is_blocklisted(a), scan(a), "{a:?}");
        }
        assert!(m.is_blocklisted(&v6(inside)) && !m.is_blocklisted(&v6(outside)));
    }

    /// Removing an entry drops it from the index as well (spec 3.2 step 21).
    #[test]
    fn range_index_remove_forgets_the_prefix() {
        let mut m = OsdMap::default();
        let r = range(16, [10, 1, 0, 0]);
        m.insert_range_blocklist(r, UTime::default());
        assert!(m.is_blocklisted(&client([10, 1, 2, 3])));
        m.remove_range_blocklist(&r);
        assert!(!m.is_blocklisted(&client([10, 1, 2, 3])));
        assert!(m.range_blocklist().is_empty());
        // a second entry of the same prefix length keeps the group alive
        let (a, b) = (range(24, [10, 1, 2, 0]), range(24, [10, 1, 3, 0]));
        m.insert_range_blocklist(a, UTime::default());
        m.insert_range_blocklist(b, UTime::default());
        m.remove_range_blocklist(&a);
        assert!(m.is_blocklisted(&client([10, 1, 3, 4])));
        assert!(!m.is_blocklisted(&client([10, 1, 2, 4])));
    }

    /// Two list entries with one masked prefix (different host bits): removing one keeps the other blocking, and a
    /// re-added entry is counted once.
    #[test]
    fn range_index_counts_entries_sharing_a_prefix() {
        let mut m = OsdMap::default();
        let (a, b) = (range(24, [10, 1, 2, 0]), range(24, [10, 1, 2, 9]));
        m.insert_range_blocklist(a, UTime::default());
        m.insert_range_blocklist(b, UTime::default());
        m.insert_range_blocklist(b, UTime::default());
        m.remove_range_blocklist(&a);
        assert!(
            m.is_blocklisted(&client([10, 1, 2, 4])),
            "b still blocks the prefix"
        );
        m.remove_range_blocklist(&b);
        assert!(!m.is_blocklisted(&client([10, 1, 2, 4])));
    }
}
