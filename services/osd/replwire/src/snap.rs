// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! SnapContext and SnapSet (spec replication.md 5.2, 5.3).

use crate::interval::IntervalSet;
use denc::types::SnapId;
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Result};
use std::collections::BTreeMap;

/// SnapContext: raw `u64 seq` + `vec<u64> snaps` (no envelope, verified with ceph-dencoder).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapContext {
    pub seq: u64,
    /// Descending.
    pub snaps: Vec<u64>,
}

impl SnapContext {
    /// Valid iff seq <= MAXSNAP, snaps strictly descending, no zero, snaps[0] <= seq.
    pub fn is_valid(&self) -> bool {
        if self.seq > SnapId::MAXSNAP.0 || self.snaps.contains(&0) {
            return false;
        }
        if self.snaps.first().is_some_and(|&s| s > self.seq) {
            return false;
        }
        self.snaps.windows(2).all(|w| w[0] > w[1])
    }
}

impl Encode for SnapContext {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u64(self.seq)?;
        self.snaps.encode(e)
    }
}
impl<'a> Decode<'a> for SnapContext {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(SnapContext {
            seq: d.u64()?,
            snaps: Vec::<u64>::decode(d)?,
        })
    }
}

/// SnapSet (xattr `snapset` on heads; ENV v3 compat 2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapSet {
    pub seq: u64,
    /// Clone ids ascending.
    pub clones: Vec<SnapId>,
    pub clone_overlap: BTreeMap<SnapId, IntervalSet>,
    pub clone_size: BTreeMap<SnapId, u64>,
    /// Per clone: the snaps it serves, descending (v >= 3; empty map when decoded from v2).
    pub clone_snaps: BTreeMap<SnapId, Vec<SnapId>>,
}

impl SnapSet {
    pub const STRUCT_V: u8 = 3;
    pub const STRUCT_COMPAT: u8 = 2;

    /// `should_whiteout`: clones exist, or the snap context would create one.
    pub fn should_whiteout(&self, snapc: &SnapContext) -> bool {
        !self.clones.is_empty() || snapc.snaps.first().is_some_and(|&s| s > self.seq)
    }
}

impl Encode for SnapSet {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            e.u64(self.seq)?;
            e.u8(1)?; // head_exists (legacy)
            e.u32(0)?; // legacy snaps
            self.clones.encode(e)?;
            self.clone_overlap.encode(e)?;
            self.clone_size.encode(e)?;
            self.clone_snaps.encode(e)
        })
    }
}
impl<'a> Decode<'a> for SnapSet {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(2, Self::STRUCT_V, |d, v| {
            let seq = d.u64()?;
            let _head_exists = d.u8()?;
            let _legacy_snaps = Vec::<SnapId>::decode(d)?;
            let clones = Vec::<SnapId>::decode(d)?;
            let clone_overlap = BTreeMap::decode(d)?;
            let clone_size = BTreeMap::decode(d)?;
            let clone_snaps = if v >= 3 {
                BTreeMap::decode(d)?
            } else {
                BTreeMap::new()
            };
            Ok(SnapSet {
                seq,
                clones,
                clone_overlap,
                clone_size,
                clone_snaps,
            })
        })
    }
}
