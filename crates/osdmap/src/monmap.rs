// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! MonMap and mon_info_t (spec osdmap.md 7).

use denc::types::{EntityAddrVec, Fsid, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Result};
use std::collections::{BTreeMap, BTreeSet};

pub const MONMAP_V_TOP: u8 = 10;
pub const MONMAP_COMPAT: u8 = 6;
/// Oldest MonMap struct_v decoded (older layouts are out of scope).
pub const MONMAP_V_MIN: u8 = 6;

pub const ELECTION_CLASSIC: u8 = 1;
pub const ELECTION_DISALLOW: u8 = 2;
pub const ELECTION_CONNECTIVITY: u8 = 3;

/// mon_info_t, ENV(6,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MonInfo {
    pub name: String,
    pub public_addrs: EntityAddrVec,
    pub priority: u16,
    pub weight: u16,
    pub crush_loc: BTreeMap<String, String>,
    pub time_added: UTime,
}

impl Encode for MonInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(6, 1, |e| {
            self.name.encode(e)?;
            self.public_addrs.encode(e)?;
            e.u16(self.priority)?;
            e.u16(self.weight)?;
            self.crush_loc.encode(e)?;
            self.time_added.encode(e)
        })
    }
}
impl<'a> Decode<'a> for MonInfo {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(3, 1, |d, v| {
            let mut m = MonInfo {
                name: String::decode(d)?,
                public_addrs: EntityAddrVec::decode(d)?,
                ..Default::default()
            };
            if v >= 2 {
                m.priority = d.u16()?;
            }
            if v >= 4 {
                m.weight = d.u16()?;
            }
            if v >= 5 {
                m.crush_loc = BTreeMap::decode(d)?;
            }
            if v >= 6 {
                m.time_added = UTime::decode(d)?;
            }
            Ok(m)
        })
    }
}

/// mon_feature_t, ENV(1,1){u64}.
fn enc_feat<B: BufMut>(e: &mut Encoder<B>, f: u64) -> Result<()> {
    e.versioned(1, 1, |e| e.u64(f))
}
fn dec_feat(d: &mut Decoder<'_>) -> Result<u64> {
    d.versioned_min(1, 1, |d, _| d.u64())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonMap {
    pub fsid: Fsid,
    pub epoch: u32,
    pub last_changed: UTime,
    pub created: UTime,
    pub persistent_features: u64,
    pub optional_features: u64,
    pub mon_info: BTreeMap<String, MonInfo>,
    pub ranks: Vec<String>,
    pub min_mon_release: u8,
    pub removed_ranks: BTreeSet<u32>,
    pub election_strategy: u8,
    pub disallowed_leaders: BTreeSet<String>,
    pub stretch_mode_enabled: bool,
    pub tiebreaker_mon: String,
    pub stretch_marked_down_mons: BTreeSet<String>,
    pub auth_epoch: u32,
    pub auth_service_cipher: i32,
    pub auth_allowed_ciphers: Vec<i32>,
    pub auth_preferred_cipher: i32,
}

impl Default for MonMap {
    fn default() -> Self {
        MonMap {
            fsid: Fsid::default(),
            epoch: 0,
            last_changed: UTime::default(),
            created: UTime::default(),
            persistent_features: 0,
            optional_features: 0,
            mon_info: BTreeMap::new(),
            ranks: vec![],
            min_mon_release: 0,
            removed_ranks: BTreeSet::new(),
            election_strategy: ELECTION_CLASSIC,
            disallowed_leaders: BTreeSet::new(),
            stretch_mode_enabled: false,
            tiebreaker_mon: String::new(),
            stretch_marked_down_mons: BTreeSet::new(),
            auth_epoch: 0,
            auth_service_cipher: 1,
            auth_allowed_ciphers: vec![1, 2],
            auth_preferred_cipher: 1,
        }
    }
}

impl MonMap {
    pub fn decode_from(buf: &[u8]) -> Result<Self> {
        denc::from_slice(buf)
    }
    pub fn encode_to(&self) -> Result<Vec<u8>> {
        self.encode_to_vec()
    }
    /// Rank of a mon by name.
    pub fn rank_of(&self, name: &str) -> Option<usize> {
        self.ranks.iter().position(|n| n == name)
    }
    pub fn num_mons(&self) -> usize {
        self.ranks.len()
    }
}

impl Encode for MonMap {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(MONMAP_V_TOP, MONMAP_COMPAT, |e| {
            self.fsid.encode(e)?;
            e.u32(self.epoch)?;
            self.last_changed.encode(e)?;
            self.created.encode(e)?;
            enc_feat(e, self.persistent_features)?;
            enc_feat(e, self.optional_features)?;
            self.mon_info.encode(e)?;
            self.ranks.encode(e)?;
            e.u8(self.min_mon_release)?;
            self.removed_ranks.encode(e)?;
            e.u8(self.election_strategy)?;
            self.disallowed_leaders.encode(e)?;
            e.bool(self.stretch_mode_enabled)?;
            self.tiebreaker_mon.encode(e)?;
            self.stretch_marked_down_mons.encode(e)?;
            e.u32(self.auth_epoch)?;
            e.i32(self.auth_service_cipher)?;
            let mut c = self.auth_allowed_ciphers.clone();
            c.sort_unstable();
            c.encode(e)?;
            e.i32(self.auth_preferred_cipher)
        })
    }
}

impl<'a> Decode<'a> for MonMap {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(MONMAP_V_MIN, MONMAP_COMPAT, |d, v| {
            let mut m = MonMap {
                fsid: Fsid::decode(d)?,
                epoch: d.u32()?,
                last_changed: UTime::decode(d)?,
                created: UTime::decode(d)?,
                persistent_features: dec_feat(d)?,
                optional_features: dec_feat(d)?,
                mon_info: BTreeMap::decode(d)?,
                ranks: Vec::decode(d)?,
                ..Default::default()
            };
            if v >= 7 {
                m.min_mon_release = d.u8()?;
            }
            if v >= 8 {
                m.removed_ranks = BTreeSet::decode(d)?;
                m.election_strategy = d.u8()?;
                m.disallowed_leaders = BTreeSet::decode(d)?;
            }
            if v >= 9 {
                m.stretch_mode_enabled = d.bool()?;
                m.tiebreaker_mon = String::decode(d)?;
                m.stretch_marked_down_mons = BTreeSet::decode(d)?;
            }
            if v >= 10 {
                m.auth_epoch = d.u32()?;
                m.auth_service_cipher = d.i32()?;
                m.auth_allowed_ciphers = Vec::decode(d)?;
                m.auth_preferred_cipher = d.i32()?;
            }
            Ok(m)
        })
    }
}
