// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! OSD <-> mon / OSD <-> OSD messages (spec osd-lifecycle.md sections 3, 4, 5, 7).

use crate::meta;
use crate::msg::{Message, Segments, front_with, get_psm, put_psm};
use crate::types::{IntervalSet, OsdSuperblock};
use denc::types::{EntityAddrVec, PgT, Timespan, UTime, Uuid};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Result};
use std::collections::BTreeMap;

/// MOSDMap (41, hv=4 hc=3). Map bodies are opaque encoded `OSDMap::Incremental` / `OSDMap` blobs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDMap {
    pub fsid: Uuid,
    pub incremental_maps: BTreeMap<u32, Vec<u8>>,
    pub maps: BTreeMap<u32, Vec<u8>>,
    /// Sender's lowest stored epoch (formerly `oldest_map`).
    pub cluster_osdmap_trim_lower_bound: u32,
    pub newest_map: u32,
}
impl MOSDMap {
    /// Lowest and highest epoch carried (over incrementals and fulls).
    pub fn epoch_range(&self) -> Option<(u32, u32)> {
        let k = self.incremental_maps.keys().chain(self.maps.keys());
        k.clone().min().zip(k.max()).map(|(a, b)| (*a, *b))
    }
}
impl Message for MOSDMap {
    meta!(41, 4, 3);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            self.fsid.encode(e)?;
            self.incremental_maps.encode(e)?;
            self.maps.encode(e)?;
            e.u32(self.cluster_osdmap_trim_lower_bound)?;
            e.u32(self.newest_map)?;
            e.u32(0) // gap_removed_snaps (always empty)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let fsid = Uuid::decode(&mut d)?;
        let incremental_maps = BTreeMap::<u32, Vec<u8>>::decode(&mut d)?;
        let maps = BTreeMap::<u32, Vec<u8>>::decode(&mut d)?;
        let (lb, newest) = if v >= 2 { (d.u32()?, d.u32()?) } else { (0, 0) };
        // hv>=4 appends `gap_removed_snaps` (an empty interval set): nothing after it is read, so trailing
        // bytes are ignored.
        Ok(MOSDMap {
            fsid,
            incremental_maps,
            maps,
            cluster_osdmap_trim_lower_bound: lb,
            newest_map: newest,
        })
    }
}

/// MMonGetOSDMap (6): request full/incremental epoch ranges (0/0 = not requested).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMonGetOSDMap {
    pub version: u64,
    pub full_first: u32,
    pub full_last: u32,
    pub inc_first: u32,
    pub inc_last: u32,
}
impl Message for MMonGetOSDMap {
    meta!(6, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            e.u32(self.full_first)?;
            e.u32(self.full_last)?;
            e.u32(self.inc_first)?;
            e.u32(self.inc_last)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MMonGetOSDMap {
            version: get_psm(&mut d)?,
            full_first: d.u32()?,
            full_last: d.u32()?,
            inc_first: d.u32()?,
            inc_last: d.u32()?,
        })
    }
}

/// MOSDBoot (71, hv=7 hc=7). Field order on the wire: back, cluster, boot_epoch, front.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MOSDBoot {
    /// PSM `version` = osdmap epoch we hold.
    pub version: u64,
    pub sb: OsdSuperblock,
    pub hb_back_addrs: EntityAddrVec,
    pub cluster_addrs: EntityAddrVec,
    pub boot_epoch: u32,
    pub hb_front_addrs: EntityAddrVec,
    pub metadata: BTreeMap<String, String>,
    pub osd_features: u64,
}
impl Message for MOSDBoot {
    meta!(71, 7, 7);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            self.sb.encode(e)?;
            self.hb_back_addrs.encode(e)?;
            self.cluster_addrs.encode(e)?;
            e.u32(self.boot_epoch)?;
            self.hb_front_addrs.encode(e)?;
            self.metadata.encode(e)?;
            e.u64(self.osd_features)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDBoot {
            version: get_psm(&mut d)?,
            sb: OsdSuperblock::decode(&mut d)?,
            hb_back_addrs: EntityAddrVec::decode(&mut d)?,
            cluster_addrs: EntityAddrVec::decode(&mut d)?,
            boot_epoch: d.u32()?,
            hb_front_addrs: EntityAddrVec::decode(&mut d)?,
            metadata: BTreeMap::decode(&mut d)?,
            osd_features: if v >= 7 { d.u64()? } else { 0 },
        })
    }
}

/// MOSDAlive (73, hv=1): ask for `up_thru >= want`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDAlive {
    /// PSM `version` = our current map epoch.
    pub version: u64,
    pub want: u32,
}
impl Message for MOSDAlive {
    meta!(73, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            e.u32(self.want)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDAlive {
            version: get_psm(&mut d)?,
            want: d.u32()?,
        })
    }
}

/// MOSDBeacon (79, hv=3 hc=1). Must be sent every `osd_beacon_report_interval` while up.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDBeacon {
    /// PSM `version` = our current map epoch.
    pub version: u64,
    pub pgs: Vec<PgT>,
    pub min_last_epoch_clean: u32,
    pub last_purged_snaps_scrub: UTime,
    pub osd_beacon_report_interval: i32,
}
impl Message for MOSDBeacon {
    meta!(79, 3, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            self.pgs.encode(e)?;
            e.u32(self.min_last_epoch_clean)?;
            self.last_purged_snaps_scrub.encode(e)?;
            e.i32(self.osd_beacon_report_interval)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let version = get_psm(&mut d)?;
        let pgs = Vec::decode(&mut d)?;
        let min_last_epoch_clean = d.u32()?;
        let last_purged_snaps_scrub = if v >= 2 {
            UTime::decode(&mut d)?
        } else {
            UTime::default()
        };
        let osd_beacon_report_interval = if v >= 3 { d.i32()? } else { 0 };
        Ok(MOSDBeacon {
            version,
            pgs,
            min_last_epoch_clean,
            last_purged_snaps_scrub,
            osd_beacon_report_interval,
        })
    }
}

/// MOSDMarkMeDown (74, hv=4 hc=3); the mon's ack uses the same message with `request_ack=false`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDMarkMeDown {
    pub version: u64,
    pub fsid: Uuid,
    pub target_osd: i32,
    /// Our public addrs as in the OSDMap.
    pub target_addrs: EntityAddrVec,
    pub epoch: u32,
    pub request_ack: bool,
    pub down_and_dead: bool,
}
impl Message for MOSDMarkMeDown {
    meta!(74, 4, 3);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            self.fsid.encode(e)?;
            e.i32(self.target_osd)?;
            self.target_addrs.encode(e)?;
            e.u32(self.epoch)?;
            e.bool(self.request_ack)?;
            e.bool(self.down_and_dead)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDMarkMeDown {
            version: get_psm(&mut d)?,
            fsid: Uuid::decode(&mut d)?,
            target_osd: d.i32()?,
            target_addrs: EntityAddrVec::decode(&mut d)?,
            epoch: d.u32()?,
            request_ack: d.bool()?,
            down_and_dead: if v >= 4 { d.bool()? } else { false },
        })
    }
}

/// MOSDMarkMeDead (123, hv=1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDMarkMeDead {
    pub version: u64,
    pub fsid: Uuid,
    pub target_osd: i32,
    pub epoch: u32,
}
impl Message for MOSDMarkMeDead {
    meta!(123, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            self.fsid.encode(e)?;
            e.i32(self.target_osd)?;
            e.u32(self.epoch)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDMarkMeDead {
            version: get_psm(&mut d)?,
            fsid: Uuid::decode(&mut d)?,
            target_osd: d.i32()?,
            epoch: d.u32()?,
        })
    }
}

/// MOSDFailure (72, hv=4 hc=4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDFailure {
    /// PSM `version` = osdmap epoch.
    pub version: u64,
    pub fsid: Uuid,
    pub target_osd: i32,
    /// Target's public addrs as in our OSDMap.
    pub target_addrs: EntityAddrVec,
    pub epoch: u32,
    pub flags: u8,
    pub failed_for: i32,
}
impl MOSDFailure {
    /// Failure report (clear = cancel / "still alive").
    pub const FLAG_FAILED: u8 = 1;
    /// Known dead, not a timeout.
    pub const FLAG_IMMEDIATE: u8 = 2;
    /// Cancel message flags (alone).
    pub const FLAG_ALIVE: u8 = 0;
}
impl Message for MOSDFailure {
    meta!(72, 4, 4);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            self.fsid.encode(e)?;
            e.i32(self.target_osd)?;
            self.target_addrs.encode(e)?;
            e.u32(self.epoch)?;
            e.u8(self.flags)?;
            e.i32(self.failed_for)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDFailure {
            version: get_psm(&mut d)?,
            fsid: Uuid::decode(&mut d)?,
            target_osd: d.i32()?,
            target_addrs: EntityAddrVec::decode(&mut d)?,
            epoch: d.u32()?,
            flags: d.u8()?,
            failed_for: d.i32()?,
        })
    }
}

/// MOSDFull (75): PSM(0), map_epoch, state (NEARFULL 1<<5, BACKFILLFULL 1<<6, FULL 1<<4).
/// Header version is not given in the spec; 1/1 assumed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDFull {
    pub version: u64,
    pub map_epoch: u32,
    pub state: u32,
}
impl Message for MOSDFull {
    meta!(75, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            e.u32(self.map_epoch)?;
            e.u32(self.state)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDFull {
            version: get_psm(&mut d)?,
            map_epoch: d.u32()?,
            state: d.u32()?,
        })
    }
}

/// MOSDPing (70, hv=5 hc=4; not a PSM). `delta_ub` etc. are hv>=5.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPing {
    pub fsid: Uuid,
    pub map_epoch: u32,
    pub op: u8,
    pub ping_stamp: UTime,
    /// Zero bytes appended after `delta_ub` (see [`MOSDPing::pad_len_for`]).
    pub pad_len: u32,
    pub up_from: u32,
    pub mono_ping_stamp: Timespan,
    pub mono_send_stamp: Timespan,
    pub delta_ub: Option<Timespan>,
}
impl MOSDPing {
    pub const HEARTBEAT: u8 = 0;
    pub const START_HEARTBEAT: u8 = 1;
    pub const YOU_DIED: u8 = 2;
    pub const STOP_HEARTBEAT: u8 = 3;
    pub const PING: u8 = 4;
    pub const PING_REPLY: u8 = 5;

    /// Padding length for `osd_heartbeat_min_size`: `max(0, min_size - 29)`.
    pub fn pad_len_for(min_size: u32) -> u32 {
        min_size.saturating_sub(29)
    }
}

/// Zero bytes for [`MOSDPing`] padding: written in bounded steps so a `pad_len` taken from the wire never turns into a
/// per-message heap allocation.
const PAD_ZEROS: [u8; 4096] = [0; 4096];

fn put_zero_pad<B: BufMut>(e: &mut Encoder<B>, len: u32) -> Result<()> {
    let mut left = len as usize;
    while left > 0 {
        let n = left.min(PAD_ZEROS.len());
        e.raw(&PAD_ZEROS[..n])?;
        left -= n;
    }
    Ok(())
}
impl Message for MOSDPing {
    meta!(70, 5, 4);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            self.fsid.encode(e)?;
            e.u32(self.map_epoch)?;
            e.u8(self.op)?;
            self.ping_stamp.encode(e)?;
            e.u32(self.pad_len)?;
            e.u32(self.up_from)?;
            self.mono_ping_stamp.encode(e)?;
            self.mono_send_stamp.encode(e)?;
            self.delta_ub.encode(e)?;
            put_zero_pad(e, self.pad_len)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let mut p = MOSDPing {
            fsid: Uuid::decode(&mut d)?,
            map_epoch: d.u32()?,
            op: d.u8()?,
            ping_stamp: UTime::decode(&mut d)?,
            pad_len: d.u32()?,
            ..Default::default()
        };
        if v >= 5 {
            p.up_from = d.u32()?;
            p.mono_ping_stamp = Timespan::decode(&mut d)?;
            p.mono_send_stamp = Timespan::decode(&mut d)?;
            p.delta_ub = Option::decode(&mut d)?;
        }
        // The declared padding is still part of the wire layout, even though
        // its contents do not affect heartbeat processing.
        d.skip(p.pad_len as usize)?;
        Ok(p)
    }
}

/// MOSDPGTemp (78, hv=2 hc=1): ask the mon to set pg_temp (empty vec clears).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGTemp {
    pub version: u64,
    pub map_epoch: u32,
    pub pg_temp: BTreeMap<PgT, Vec<i32>>,
    pub forced: bool,
}
impl Message for MOSDPGTemp {
    meta!(78, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            e.u32(self.map_epoch)?;
            self.pg_temp.encode(e)?;
            e.bool(self.forced)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGTemp {
            version: get_psm(&mut d)?,
            map_epoch: d.u32()?,
            pg_temp: BTreeMap::decode(&mut d)?,
            forced: if v >= 2 { d.bool()? } else { false },
        })
    }
}

/// MOSDPGCreated (116, hv=1): tell the mon a pg was created.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGCreated {
    pub version: u64,
    pub pgid: PgT,
}
impl Message for MOSDPGCreated {
    meta!(116, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            self.pgid.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGCreated {
            version: get_psm(&mut d)?,
            pgid: PgT::decode(&mut d)?,
        })
    }
}

/// MOSDPGReadyToMerge (122, hv=1 hc=0): the primary of a merge source and target reports both clean (`ready`) or
/// the merge impossible (split-merge.md 6.2). `pgid` is always the SOURCE; versions / epochs are 0 when not ready.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGReadyToMerge {
    /// PSM `version`: the sender's current osdmap epoch.
    pub version: u64,
    pub pgid: PgT,
    pub source_version: denc::types::Eversion,
    pub target_version: denc::types::Eversion,
    pub last_epoch_started: u32,
    pub last_epoch_clean: u32,
    pub ready: bool,
}
impl Message for MOSDPGReadyToMerge {
    meta!(122, 1, 0);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            self.pgid.encode(e)?;
            self.source_version.encode(e)?;
            self.target_version.encode(e)?;
            e.u32(self.last_epoch_started)?;
            e.u32(self.last_epoch_clean)?;
            e.bool(self.ready)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGReadyToMerge {
            version: get_psm(&mut d)?,
            pgid: PgT::decode(&mut d)?,
            source_version: denc::types::Eversion::decode(&mut d)?,
            target_version: denc::types::Eversion::decode(&mut d)?,
            last_epoch_started: d.u32()?,
            last_epoch_clean: d.u32()?,
            ready: d.bool()?,
        })
    }
}

/// MMonGetPurgedSnaps (76, hv=1): request purged-snap intervals for epochs `[start, last]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMonGetPurgedSnaps {
    pub version: u64,
    pub start: u32,
    pub last: u32,
}
impl Message for MMonGetPurgedSnaps {
    meta!(76, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            e.u32(self.start)?;
            e.u32(self.last)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MMonGetPurgedSnaps {
            version: get_psm(&mut d)?,
            start: d.u32()?,
            last: d.u32()?,
        })
    }
}

/// MMonGetPurgedSnapsReply (77, hv=1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMonGetPurgedSnapsReply {
    pub version: u64,
    pub start: u32,
    /// Highest epoch covered by this reply.
    pub last: u32,
    /// epoch -> pool -> interval_set<snapid>.
    pub purged_snaps: BTreeMap<u32, BTreeMap<i64, IntervalSet<u64>>>,
}
impl Message for MMonGetPurgedSnapsReply {
    meta!(77, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            e.u32(self.start)?;
            e.u32(self.last)?;
            self.purged_snaps.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MMonGetPurgedSnapsReply {
            version: get_psm(&mut d)?,
            start: d.u32()?,
            last: d.u32()?,
            purged_snaps: BTreeMap::decode(&mut d)?,
        })
    }
}

#[cfg(test)]
mod pad_tests {
    use super::*;

    /// Counts writes and refuses any slice above the shared zero chunk: a pad written in one piece (one allocation of
    /// the wire-controlled `pad_len`) fails here.
    struct Sink(usize);
    impl BufMut for Sink {
        fn len(&self) -> usize {
            self.0
        }
        fn put_slice(&mut self, s: &[u8]) -> Result<()> {
            assert!(s.len() <= PAD_ZEROS.len(), "pad written in one piece");
            assert!(s.iter().all(|b| *b == 0));
            self.0 += s.len();
            Ok(())
        }
        fn patch(&mut self, _pos: usize, _s: &[u8]) {}
    }

    /// MSG-04: `pad_len` comes from the wire, so the padding must come from one shared zero chunk, never from a temporary
    /// buffer of `pad_len` bytes.
    #[test]
    fn huge_ping_padding_is_written_in_bounded_steps() {
        const PAD: u32 = 1_000_003;
        let mut e = Encoder::from_buf(Sink(0));
        put_zero_pad(&mut e, PAD).unwrap();
        assert_eq!(e.len(), PAD as usize);
    }
}
