// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! OSDMap::Incremental: decode/encode (spec 3.1) and apply (3.2, 3.3).

use crate::PoolName;
use crate::consts::{WEIGHT_IN, osd_state, release};
use crate::error::{Error, Result};
use crate::interval::IntervalSet;
use crate::map::{
    OUTER_COMPAT, OUTER_MIN, OUTER_V, OsdMap, OsdXInfo, blocklist_key, crc_front_tail,
};
use crate::pool::PgPool;
use denc::types::{EntityAddr, EntityAddrVec, Fsid, PgT, UTime};
use denc::{Decode, Decoder, Encode, Encoder};
use std::collections::{BTreeMap, BTreeSet};

/// `mutate_allow_crimson` values.
pub const CRIMSON_NONE: u8 = 0;
pub const CRIMSON_SET: u8 = 1;
pub const CRIMSON_CLEAR: u8 = 2;

#[derive(Debug, Clone, PartialEq)]
pub struct Incremental {
    pub fsid: Fsid,
    pub epoch: u32,
    pub modified: UTime,
    pub new_pool_max: i64,
    pub new_flags: i32,
    pub fullmap: Vec<u8>,
    pub crush: Vec<u8>,
    pub new_max_osd: i32,
    pub new_pools: BTreeMap<i64, PgPool>,
    pub new_pool_names: BTreeMap<i64, PoolName>,
    pub old_pools: BTreeSet<i64>,
    pub new_up_client: BTreeMap<i32, EntityAddrVec>,
    pub new_state: BTreeMap<i32, u32>,
    pub new_weight: BTreeMap<i32, u32>,
    pub new_pg_temp: BTreeMap<PgT, Vec<i32>>,
    pub new_primary_temp: BTreeMap<PgT, i32>,
    pub new_primary_affinity: BTreeMap<i32, u32>,
    pub new_erasure_code_profiles: BTreeMap<String, BTreeMap<String, String>>,
    pub old_erasure_code_profiles: Vec<String>,
    pub new_pg_upmap: BTreeMap<PgT, Vec<i32>>,
    pub old_pg_upmap: BTreeSet<PgT>,
    pub new_pg_upmap_items: BTreeMap<PgT, Vec<(i32, i32)>>,
    pub old_pg_upmap_items: BTreeSet<PgT>,
    pub new_removed_snaps: BTreeMap<i64, IntervalSet>,
    pub new_purged_snaps: BTreeMap<i64, IntervalSet>,
    pub new_last_up_change: UTime,
    pub new_last_in_change: UTime,
    pub new_pg_upmap_primary: BTreeMap<PgT, i32>,
    pub old_pg_upmap_primary: BTreeSet<PgT>,
    // osd-only part
    pub new_hb_back_up: BTreeMap<i32, EntityAddrVec>,
    pub new_up_thru: BTreeMap<i32, u32>,
    pub new_last_clean_interval: BTreeMap<i32, (u32, u32)>,
    pub new_lost: BTreeMap<i32, u32>,
    pub new_blocklist: BTreeMap<EntityAddr, UTime>,
    pub old_blocklist: Vec<EntityAddr>,
    pub new_up_cluster: BTreeMap<i32, EntityAddrVec>,
    pub cluster_snapshot: String,
    pub new_uuid: BTreeMap<i32, Fsid>,
    pub new_xinfo: BTreeMap<i32, OsdXInfo>,
    pub new_hb_front_up: BTreeMap<i32, EntityAddrVec>,
    pub encode_features: u64,
    pub new_nearfull_ratio: f32,
    pub new_full_ratio: f32,
    pub new_backfillfull_ratio: f32,
    pub new_require_min_compat_client: u8,
    pub new_require_osd_release: u8,
    pub new_crush_node_flags: BTreeMap<i32, u32>,
    pub new_device_class_flags: BTreeMap<i32, u32>,
    pub change_stretch_mode: bool,
    pub new_stretch_bucket_count: u32,
    pub new_degraded_stretch_mode: u32,
    pub new_recovering_stretch_mode: u32,
    pub new_stretch_mode_bucket: i32,
    pub stretch_mode_enabled: bool,
    pub new_range_blocklist: BTreeMap<EntityAddr, UTime>,
    pub old_range_blocklist: Vec<EntityAddr>,
    pub mutate_allow_crimson: u8,
    /// Whether the encoding carried crcs (outer struct_v >= 8).
    pub has_crc: bool,
    /// inc_crc as stored on the wire (recomputed on encode).
    pub inc_crc: u32,
    /// CRC of the resulting full map as encoded by the mon.
    pub full_crc: u32,
}

impl Default for Incremental {
    fn default() -> Self {
        Incremental {
            fsid: Fsid::default(),
            epoch: 0,
            modified: UTime::default(),
            new_pool_max: -1,
            new_flags: -1,
            fullmap: vec![],
            crush: vec![],
            new_max_osd: -1,
            new_pools: BTreeMap::new(),
            new_pool_names: BTreeMap::new(),
            old_pools: BTreeSet::new(),
            new_up_client: BTreeMap::new(),
            new_state: BTreeMap::new(),
            new_weight: BTreeMap::new(),
            new_pg_temp: BTreeMap::new(),
            new_primary_temp: BTreeMap::new(),
            new_primary_affinity: BTreeMap::new(),
            new_erasure_code_profiles: BTreeMap::new(),
            old_erasure_code_profiles: vec![],
            new_pg_upmap: BTreeMap::new(),
            old_pg_upmap: BTreeSet::new(),
            new_pg_upmap_items: BTreeMap::new(),
            old_pg_upmap_items: BTreeSet::new(),
            new_removed_snaps: BTreeMap::new(),
            new_purged_snaps: BTreeMap::new(),
            new_last_up_change: UTime::default(),
            new_last_in_change: UTime::default(),
            new_pg_upmap_primary: BTreeMap::new(),
            old_pg_upmap_primary: BTreeSet::new(),
            new_hb_back_up: BTreeMap::new(),
            new_up_thru: BTreeMap::new(),
            new_last_clean_interval: BTreeMap::new(),
            new_lost: BTreeMap::new(),
            new_blocklist: BTreeMap::new(),
            old_blocklist: vec![],
            new_up_cluster: BTreeMap::new(),
            cluster_snapshot: String::new(),
            new_uuid: BTreeMap::new(),
            new_xinfo: BTreeMap::new(),
            new_hb_front_up: BTreeMap::new(),
            encode_features: u64::MAX,
            new_nearfull_ratio: -1.0,
            new_full_ratio: -1.0,
            new_backfillfull_ratio: -1.0,
            new_require_min_compat_client: 0xFF,
            new_require_osd_release: 0xFF,
            new_crush_node_flags: BTreeMap::new(),
            new_device_class_flags: BTreeMap::new(),
            change_stretch_mode: false,
            new_stretch_bucket_count: 0,
            new_degraded_stretch_mode: 0,
            new_recovering_stretch_mode: 0,
            new_stretch_mode_bucket: 0,
            stretch_mode_enabled: false,
            new_range_blocklist: BTreeMap::new(),
            old_range_blocklist: vec![],
            mutate_allow_crimson: CRIMSON_NONE,
            has_crc: true,
            inc_crc: 0,
            full_crc: 0,
        }
    }
}

impl Incremental {
    /// Decode; verifies `inc_crc` when outer struct_v >= 8.
    /// Rejects `new_max_osd` above [`crate::consts::MAX_OSD_SLOTS`] before apply
    /// can allocate per-OSD arrays.
    pub fn decode_from(buf: &[u8]) -> Result<Self> {
        Self::decode_opts(buf, true)
    }

    pub fn decode_opts(buf: &[u8], verify_crc: bool) -> Result<Self> {
        if let Some(&v) = buf.first()
            && v < OUTER_MIN
        {
            return Err(Error::Classic(v));
        }
        let mut d = Decoder::new(buf);
        let mut crc_err = None;
        let inc = d.versioned(OUTER_COMPAT, |d, outer_v| {
            let mut inc = Incremental::default();
            d.versioned_min(7, 1, |d, v| inc.decode_client(d, v))?;
            d.versioned_min(7, 1, |d, v| inc.decode_osd(d, v))?;
            inc.has_crc = outer_v >= 8;
            if inc.has_crc {
                let off = d.position();
                inc.inc_crc = d.u32()?;
                if verify_crc {
                    let computed = crc_front_tail(&buf[..off], d.peek_rest());
                    if computed != inc.inc_crc {
                        crc_err = Some(Error::BadCrc {
                            stored: inc.inc_crc,
                            computed,
                        });
                    }
                }
                inc.full_crc = d.u32()?;
            }
            Ok(inc)
        })?;
        if let Some(e) = crc_err {
            return Err(e);
        }
        if d.remaining() != 0 {
            return Err(denc::Error::TrailingBytes(d.remaining()).into());
        }
        Ok(inc)
    }

    fn decode_client(&mut self, d: &mut Decoder<'_>, v: u8) -> denc::Result<()> {
        self.fsid = Fsid::decode(d)?;
        self.epoch = d.u32()?;
        self.modified = UTime::decode(d)?;
        self.new_pool_max = d.i64()?;
        self.new_flags = d.i32()?;
        self.fullmap = Vec::decode(d)?;
        self.crush = Vec::decode(d)?;
        self.new_max_osd = d.i32()?;
        if self.new_max_osd > crate::consts::MAX_OSD_SLOTS {
            return Err(denc::Error::BadValue("new_max_osd exceeds MAX_OSD_SLOTS"));
        }
        self.new_pools = BTreeMap::decode(d)?;
        self.new_pool_names = BTreeMap::decode(d)?;
        self.old_pools = BTreeSet::decode(d)?;
        self.new_up_client = BTreeMap::decode(d)?;
        self.new_state = BTreeMap::decode(d)?;
        self.new_weight = BTreeMap::decode(d)?;
        self.new_pg_temp = BTreeMap::decode(d)?;
        self.new_primary_temp = BTreeMap::decode(d)?;
        self.new_primary_affinity = BTreeMap::decode(d)?;
        self.new_erasure_code_profiles = BTreeMap::decode(d)?;
        self.old_erasure_code_profiles = Vec::decode(d)?;
        self.new_pg_upmap = BTreeMap::decode(d)?;
        self.old_pg_upmap = BTreeSet::decode(d)?;
        self.new_pg_upmap_items = BTreeMap::decode(d)?;
        self.old_pg_upmap_items = BTreeSet::decode(d)?;
        self.new_removed_snaps = BTreeMap::decode(d)?;
        self.new_purged_snaps = BTreeMap::decode(d)?;
        if v >= 8 {
            self.new_last_up_change = UTime::decode(d)?;
            self.new_last_in_change = UTime::decode(d)?;
        }
        if v >= 9 {
            self.new_pg_upmap_primary = BTreeMap::decode(d)?;
            self.old_pg_upmap_primary = BTreeSet::decode(d)?;
        }
        Ok(())
    }

    fn decode_osd(&mut self, d: &mut Decoder<'_>, v: u8) -> denc::Result<()> {
        self.new_hb_back_up = BTreeMap::decode(d)?;
        self.new_up_thru = BTreeMap::decode(d)?;
        self.new_last_clean_interval = BTreeMap::decode(d)?;
        self.new_lost = BTreeMap::decode(d)?;
        self.new_blocklist = BTreeMap::decode(d)?;
        self.old_blocklist = Vec::decode(d)?;
        self.new_up_cluster = BTreeMap::decode(d)?;
        self.cluster_snapshot = String::decode(d)?;
        self.new_uuid = BTreeMap::decode(d)?;
        self.new_xinfo = BTreeMap::decode(d)?;
        self.new_hb_front_up = BTreeMap::decode(d)?;
        self.encode_features = d.u64()?;
        self.new_nearfull_ratio = d.f32()?;
        self.new_full_ratio = d.f32()?;
        self.new_backfillfull_ratio = d.f32()?;
        self.new_require_min_compat_client = d.u8()?;
        self.new_require_osd_release = d.u8()?;
        if v >= 8 {
            self.new_crush_node_flags = BTreeMap::decode(d)?;
        }
        if v >= 9 {
            self.new_device_class_flags = BTreeMap::decode(d)?;
        }
        if v >= 10 {
            self.change_stretch_mode = d.bool()?;
            self.new_stretch_bucket_count = d.u32()?;
            self.new_degraded_stretch_mode = d.u32()?;
            self.new_recovering_stretch_mode = d.u32()?;
            self.new_stretch_mode_bucket = d.i32()?;
            self.stretch_mode_enabled = d.bool()?;
        }
        if v >= 11 {
            self.new_range_blocklist = BTreeMap::decode(d)?;
            self.old_range_blocklist = Vec::decode(d)?;
        }
        if v >= 12 {
            self.mutate_allow_crimson = d.u8()?;
        }
        Ok(())
    }

    fn osd_part_version(&self) -> u8 {
        let mut v = 9;
        if self.change_stretch_mode {
            v = v.max(10);
        }
        if !self.new_range_blocklist.is_empty() || !self.old_range_blocklist.is_empty() {
            v = v.max(11);
        }
        if self.mutate_allow_crimson != CRIMSON_NONE {
            v = v.max(12);
        }
        v
    }

    /// Encode (top versions); `inc_crc` is recomputed, `full_crc` is emitted as stored.
    pub fn encode_inc(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        e.versioned(9, 1, |e| {
            self.fsid.encode(e)?;
            e.u32(self.epoch)?;
            self.modified.encode(e)?;
            e.i64(self.new_pool_max)?;
            e.i32(self.new_flags)?;
            self.fullmap.encode(e)?;
            self.crush.encode(e)?;
            e.i32(self.new_max_osd)?;
            self.new_pools.encode(e)?;
            self.new_pool_names.encode(e)?;
            self.old_pools.encode(e)?;
            self.new_up_client.encode(e)?;
            self.new_state.encode(e)?;
            self.new_weight.encode(e)?;
            self.new_pg_temp.encode(e)?;
            self.new_primary_temp.encode(e)?;
            self.new_primary_affinity.encode(e)?;
            self.new_erasure_code_profiles.encode(e)?;
            self.old_erasure_code_profiles.encode(e)?;
            self.new_pg_upmap.encode(e)?;
            self.old_pg_upmap.encode(e)?;
            self.new_pg_upmap_items.encode(e)?;
            self.old_pg_upmap_items.encode(e)?;
            self.new_removed_snaps.encode(e)?;
            self.new_purged_snaps.encode(e)?;
            self.new_last_up_change.encode(e)?;
            self.new_last_in_change.encode(e)?;
            self.new_pg_upmap_primary.encode(e)?;
            self.old_pg_upmap_primary.encode(e)
        })?;
        let vo = self.osd_part_version();
        e.versioned(vo, 1, |e| {
            self.new_hb_back_up.encode(e)?;
            self.new_up_thru.encode(e)?;
            self.new_last_clean_interval.encode(e)?;
            self.new_lost.encode(e)?;
            self.new_blocklist.encode(e)?;
            self.old_blocklist.encode(e)?;
            self.new_up_cluster.encode(e)?;
            self.cluster_snapshot.encode(e)?;
            self.new_uuid.encode(e)?;
            self.new_xinfo.encode(e)?;
            self.new_hb_front_up.encode(e)?;
            e.u64(self.encode_features)?;
            e.f32(self.new_nearfull_ratio)?;
            e.f32(self.new_full_ratio)?;
            e.f32(self.new_backfillfull_ratio)?;
            e.u8(self.new_require_min_compat_client)?;
            e.u8(self.new_require_osd_release)?;
            self.new_crush_node_flags.encode(e)?;
            self.new_device_class_flags.encode(e)?;
            if vo >= 10 {
                e.bool(self.change_stretch_mode)?;
                e.u32(self.new_stretch_bucket_count)?;
                e.u32(self.new_degraded_stretch_mode)?;
                e.u32(self.new_recovering_stretch_mode)?;
                e.i32(self.new_stretch_mode_bucket)?;
                e.bool(self.stretch_mode_enabled)?;
            }
            if vo >= 11 {
                self.new_range_blocklist.encode(e)?;
                self.old_range_blocklist.encode(e)?;
            }
            if vo >= 12 {
                e.u8(self.mutate_allow_crimson)?;
            }
            Ok(())
        })?;
        let mut body = e.into_vec();
        let len = u32::try_from(body.len() + 8).map_err(|_| denc::Error::TooLong)?;
        let mut out = Vec::with_capacity(body.len() + 14);
        out.push(OUTER_V);
        out.push(OUTER_COMPAT);
        out.extend_from_slice(&len.to_le_bytes());
        out.append(&mut body);
        let crc = crc_front_tail(&out, &self.full_crc.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&self.full_crc.to_le_bytes());
        Ok(out)
    }
}

fn osd_idx(m: &OsdMap, o: i32) -> Result<usize> {
    if o < 0 || o >= m.max_osd {
        return Err(Error::Invalid("osd id out of range"));
    }
    Ok(o as usize)
}

impl OsdMap {
    /// Apply an incremental in place (spec 3.2). On error the map may be
    /// partially modified; use [`apply_incremental_checked`](Self::apply_incremental_checked)
    /// for a transactional variant incl. the crc check.
    pub fn apply_incremental(&mut self, inc: &Incremental) -> Result<()> {
        // Also enforce admission for incrementals constructed in memory.
        if inc.new_max_osd > crate::consts::MAX_OSD_SLOTS {
            return Err(denc::Error::BadValue("new_max_osd exceeds MAX_OSD_SLOTS").into());
        }
        if inc.epoch != self.epoch.wrapping_add(1) {
            return Err(Error::Gap {
                have: self.epoch,
                inc: inc.epoch,
            });
        }
        if inc.epoch == 1 {
            self.fsid = inc.fsid;
        } else if inc.fsid != self.fsid {
            return Err(Error::FsidMismatch);
        }
        // 1
        self.epoch = inc.epoch;
        self.modified = inc.modified;
        // 2
        if !inc.fullmap.is_empty() {
            let full = OsdMap::decode_from(&inc.fullmap)?;
            if full.fsid != inc.fsid {
                return Err(Error::FsidMismatch);
            }
            if full.epoch != inc.epoch {
                return Err(Error::Invalid(
                    "embedded full map epoch differs from incremental",
                ));
            }
            *self = full;
            return Ok(());
        }
        // 3-4
        if inc.new_flags >= 0 {
            self.flags = inc.new_flags as u32;
        }
        if inc.new_max_osd >= 0 {
            self.set_max_osd(inc.new_max_osd);
        }
        // 5-6
        if inc.new_pool_max != -1 {
            self.pool_max = inc.new_pool_max as i32;
        }
        for (id, p) in &inc.new_pools {
            let mut p = p.clone();
            p.last_change = self.epoch;
            self.pools.insert(*id, p);
        }
        // 7
        self.new_removed_snaps = inc.new_removed_snaps.clone();
        self.new_purged_snaps = inc.new_purged_snaps.clone();
        for (pool, s) in &inc.new_removed_snaps {
            self.removed_snaps_queue
                .entry(*pool)
                .or_default()
                .union_with(s);
        }
        for (pool, s) in &inc.new_purged_snaps {
            if let Some(q) = self.removed_snaps_queue.get_mut(pool) {
                q.subtract(s);
                if q.is_empty() {
                    self.removed_snaps_queue.remove(pool);
                }
            }
        }
        // 8
        let zero = UTime::default();
        if inc.new_last_up_change != zero {
            self.last_up_change = inc.new_last_up_change;
        }
        if inc.new_last_in_change != zero {
            self.last_in_change = inc.new_last_in_change;
        }
        // 9-10
        for (id, n) in &inc.new_pool_names {
            self.pool_name.insert(*id, n.clone());
        }
        for id in &inc.old_pools {
            self.pools.remove(id);
            self.pool_name.remove(id);
        }
        // 11
        for (&o, &w) in &inc.new_weight {
            let i = osd_idx(self, o)?;
            self.osd_weight[i] = w;
            if w != 0 {
                self.osd_state[i] |= osd_state::EXISTS;
                self.osd_state[i] &= !(osd_state::AUTOOUT | osd_state::NEW);
                self.osd_xinfo[i].old_weight = 0;
            }
        }
        // 12
        for (&o, &a) in &inc.new_primary_affinity {
            let i = osd_idx(self, o)?;
            if self.osd_primary_affinity.is_empty() {
                self.osd_primary_affinity = vec![WEIGHT_IN; self.max_osd as usize];
            }
            self.osd_primary_affinity[i] = a;
        }
        // 13
        for n in &inc.old_erasure_code_profiles {
            self.erasure_code_profiles.remove(n);
        }
        for (n, p) in &inc.new_erasure_code_profiles {
            self.erasure_code_profiles.insert(n.clone(), p.clone());
        }
        // 14
        for (&o, &s) in &inc.new_state {
            let i = osd_idx(self, o)?;
            let s = if s == 0 { osd_state::UP } else { s };
            if self.is_up(o) && s & osd_state::UP != 0 {
                self.osd_info[i].down_at = self.epoch;
                self.osd_xinfo[i].down_stamp = self.modified;
            }
            if self.exists(o) && s & osd_state::EXISTS != 0 {
                self.osd_uuid[i] = Fsid::default();
                self.osd_info[i] = Default::default();
                self.osd_xinfo[i] = OsdXInfo::default();
                if !self.osd_primary_affinity.is_empty() {
                    self.osd_primary_affinity[i] = WEIGHT_IN;
                }
                self.client_addrs[i] = EntityAddrVec::default();
                self.hb_back_addrs[i] = EntityAddrVec::default();
                self.hb_front_addrs[i] = EntityAddrVec::default();
                self.cluster_addrs[i] = EntityAddrVec::default();
                self.osd_state[i] = 0;
            } else {
                self.osd_state[i] ^= s;
            }
        }
        // 15-16
        for (&o, a) in &inc.new_up_client {
            let i = osd_idx(self, o)?;
            let back = inc
                .new_hb_back_up
                .get(&o)
                .ok_or(Error::Invalid("new_up_client without hb_back"))?;
            let front = inc
                .new_hb_front_up
                .get(&o)
                .ok_or(Error::Invalid("new_up_client without hb_front"))?;
            self.osd_state[i] |= osd_state::EXISTS | osd_state::UP;
            self.osd_state[i] &= !osd_state::STOP;
            self.client_addrs[i] = a.clone();
            self.hb_back_addrs[i] = back.clone();
            self.hb_front_addrs[i] = front.clone();
            self.osd_info[i].up_from = self.epoch;
        }
        for (&o, a) in &inc.new_up_cluster {
            let i = osd_idx(self, o)?;
            self.cluster_addrs[i] = a.clone();
        }
        // 17
        for (&o, &t) in &inc.new_up_thru {
            let i = osd_idx(self, o)?;
            self.osd_info[i].up_thru = t;
        }
        for (&o, &(b, e)) in &inc.new_last_clean_interval {
            let i = osd_idx(self, o)?;
            self.osd_info[i].last_clean_begin = b;
            self.osd_info[i].last_clean_end = e;
        }
        for (&o, &l) in &inc.new_lost {
            let i = osd_idx(self, o)?;
            self.osd_info[i].lost_at = l;
        }
        // 18
        for (&o, x) in &inc.new_xinfo {
            let i = osd_idx(self, o)?;
            self.osd_xinfo[i] = *x;
        }
        for (&o, u) in &inc.new_uuid {
            let i = osd_idx(self, o)?;
            self.osd_uuid[i] = *u;
        }
        // 19
        for (pg, v) in &inc.new_pg_temp {
            if v.is_empty() {
                self.pg_temp.remove(pg);
            } else {
                self.pg_temp.insert(*pg, v.clone());
            }
        }
        for (pg, &p) in &inc.new_primary_temp {
            if p == -1 {
                self.primary_temp.remove(pg);
            } else {
                self.primary_temp.insert(*pg, p);
            }
        }
        // 20
        for (pg, v) in &inc.new_pg_upmap {
            self.pg_upmap.insert(*pg, v.clone());
        }
        for (pg, v) in &inc.new_pg_upmap_items {
            self.pg_upmap_items.insert(*pg, v.clone());
        }
        for (pg, &p) in &inc.new_pg_upmap_primary {
            self.pg_upmap_primaries.insert(*pg, p);
        }
        for pg in &inc.old_pg_upmap {
            self.pg_upmap.remove(pg);
        }
        for pg in &inc.old_pg_upmap_items {
            self.pg_upmap_items.remove(pg);
        }
        for pg in &inc.old_pg_upmap_primary {
            self.pg_upmap_primaries.remove(pg);
        }
        // 21
        // The wire keeps connection address types, but the held map uses the
        // release's protocol-independent blocklist domain. Include a release
        // change carried by this incremental before matching removals.
        let blocklist_release = if inc.new_require_osd_release == 0xff {
            self.require_osd_release
        } else {
            inc.new_require_osd_release
        };
        if blocklist_release != self.require_osd_release {
            self.normalize_blocklist(blocklist_release);
        }
        for (a, t) in &inc.new_blocklist {
            // Duplicate additions preserve the held expiry; they are not renewals.
            self.blocklist
                .entry(blocklist_key(*a, blocklist_release))
                .or_insert(*t);
        }
        for a in &inc.old_blocklist {
            self.blocklist.remove(&blocklist_key(*a, blocklist_release));
        }
        for (a, t) in &inc.new_range_blocklist {
            self.insert_range_blocklist(*a, *t);
        }
        for a in &inc.old_range_blocklist {
            self.remove_range_blocklist(a);
        }
        // 22
        for (&k, &v) in &inc.new_crush_node_flags {
            if v == 0 {
                self.crush_node_flags.remove(&k);
            } else {
                self.crush_node_flags.insert(k, v);
            }
        }
        for (&k, &v) in &inc.new_device_class_flags {
            if v == 0 {
                self.device_class_flags.remove(&k);
            } else {
                self.device_class_flags.insert(k, v);
            }
        }
        // 23
        if inc.cluster_snapshot.is_empty() {
            self.cluster_snapshot.clear();
            self.cluster_snapshot_epoch = 0;
        } else {
            self.cluster_snapshot = inc.cluster_snapshot.clone();
            self.cluster_snapshot_epoch = inc.epoch;
        }
        // 24
        if inc.new_nearfull_ratio >= 0.0 {
            self.nearfull_ratio = inc.new_nearfull_ratio;
        }
        if inc.new_backfillfull_ratio >= 0.0 {
            self.backfillfull_ratio = inc.new_backfillfull_ratio;
        }
        if inc.new_full_ratio >= 0.0 {
            self.full_ratio = inc.new_full_ratio;
        }
        if inc.new_require_min_compat_client > release::UNKNOWN
            && inc.new_require_min_compat_client != 0xFF
        {
            self.require_min_compat_client = inc.new_require_min_compat_client;
        }
        if inc.new_require_osd_release != 0xFF {
            self.require_osd_release = inc.new_require_osd_release;
            self.apply_release_flags();
        }
        // 25
        if !inc.crush.is_empty() {
            let cm = crush::CrushMap::decode(&inc.crush)
                .map_err(|_| Error::Invalid("incremental crush map undecodable"))?;
            // The decode recomputed max_devices like the mon does: 1 + highest device id in any bucket or in the name map
            // (verified on 32 real crush-bearing epochs, incl. a purge where the inc wire value 4 became 3 in the stored
            // full map).
            // The mon stores the map re-encoded for the incremental's features (ADR 0017).
            // Decode keeps short weight positions compact; the canonical form pads them to bucket
            // size like classic CrushWrapper does. Classic carries the blob in a bufferlist (u32
            // length), so a canonical form beyond that is unencodable there too: refuse it before
            // materializing it.
            let blob = if inc.encode_features != 0 {
                if cm.encoded_len_with_features(inc.encode_features) > u64::from(u32::MAX) {
                    return Err(Error::Invalid(
                        "incremental crush map canonical encoding exceeds u32 length",
                    ));
                }
                cm.encode_with_features(inc.encode_features)
            } else {
                inc.crush.clone()
            };
            // device_class_flags only for classes the new map still has.
            self.device_class_flags
                .retain(|k, _| cm.class_name.contains_key(k));
            self.set_crush_decoded(blob, cm);
            if self.require_osd_release >= release::LUMINOUS {
                self.crush_version = self.crush_version.wrapping_add(1);
            }
        }
        // 26-27
        if inc.change_stretch_mode {
            self.stretch_bucket_count = inc.new_stretch_bucket_count;
            self.degraded_stretch_mode = inc.new_degraded_stretch_mode;
            self.recovering_stretch_mode = inc.new_recovering_stretch_mode;
            self.stretch_mode_bucket = inc.new_stretch_mode_bucket;
            self.stretch_mode_enabled = inc.stretch_mode_enabled;
        }
        match inc.mutate_allow_crimson {
            CRIMSON_SET => self.allow_crimson = true,
            CRIMSON_CLEAR => self.allow_crimson = false,
            _ => {}
        }
        Ok(())
    }

    /// Transactional apply: works on a copy, then (if the inc carries crcs)
    /// re-encodes and compares against `full_crc` (spec 3.3, ADR 0017).
    /// `FullCrcMismatch` means: discard, request the full map from the mon.
    pub fn apply_incremental_checked(&self, inc: &Incremental) -> Result<OsdMap> {
        let mut m = self.clone();
        m.apply_incremental(inc)?;
        if inc.has_crc && inc.fullmap.is_empty() {
            let computed = m.crc(inc.encode_features)?;
            if computed != inc.full_crc {
                return Err(Error::FullCrcMismatch {
                    expected: inc.full_crc,
                    computed,
                });
            }
        }
        Ok(m)
    }
}
