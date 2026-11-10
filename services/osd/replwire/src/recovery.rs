// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Recovery structures: ObjectRecoveryInfo, ObjectRecoveryProgress, PushOp, PullOp, PushReplyOp
//! (spec replication.md 6.2).

use crate::interval::IntervalSet;
use crate::oi::ObjectInfo;
use crate::snap::SnapSet;
use bytes::Bytes;
use denc::types::{Eversion, Hobject};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Result};
use std::collections::BTreeMap;

/// ObjectRecoveryInfo (ENV v4 compat 1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectRecoveryInfo {
    pub soid: Hobject,
    pub version: Eversion,
    /// `u64::MAX` = unknown (a pull request lets the source fill it in).
    pub size: u64,
    pub oi: ObjectInfo,
    /// Head's SnapSet when `soid` is a clone, else default.
    pub ss: SnapSet,
    pub copy_subset: IntervalSet,
    pub clone_subset: BTreeMap<Hobject, IntervalSet>,
    /// v>=3: false when the receiver has no copy.
    pub object_exist: bool,
    /// v>=4.
    pub num_omap_keys: u64,
}

impl Encode for ObjectRecoveryInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(4, 1, |e| {
            self.soid.encode(e)?;
            self.version.encode(e)?;
            e.u64(self.size)?;
            self.oi.encode(e)?;
            self.ss.encode(e)?;
            self.copy_subset.encode(e)?;
            self.clone_subset.encode(e)?;
            e.bool(self.object_exist)?;
            e.u64(self.num_omap_keys)
        })
    }
}
impl<'a> Decode<'a> for ObjectRecoveryInfo {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 4, |d, v| {
            let mut r = ObjectRecoveryInfo {
                soid: Hobject::decode(d)?,
                version: Eversion::decode(d)?,
                size: d.u64()?,
                oi: ObjectInfo::decode(d)?,
                ss: SnapSet::decode(d)?,
                copy_subset: crate::interval::decode_checked(d)?,
                clone_subset: {
                    let m: BTreeMap<Hobject, IntervalSet> = BTreeMap::decode(d)?;
                    if m.values()
                        .any(|s| crate::interval::checked_total(s).is_none())
                    {
                        return Err(denc::Error::BadValue(
                            "clone_subset: malformed interval set",
                        ));
                    }
                    m
                },
                object_exist: true,
                num_omap_keys: 0,
            };
            if v >= 3 {
                r.object_exist = d.bool()?;
            }
            if v >= 4 {
                r.num_omap_keys = d.u64()?;
            }
            Ok(r)
        })
    }
}

/// ObjectRecoveryProgress (ENV v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRecoveryProgress {
    pub first: bool,
    pub data_complete: bool,
    pub data_recovered_to: u64,
    pub omap_recovered_to: Vec<u8>,
    pub omap_complete: bool,
}

impl Default for ObjectRecoveryProgress {
    /// Start of a recovery: `first`, nothing done.
    fn default() -> Self {
        ObjectRecoveryProgress {
            first: true,
            data_complete: false,
            data_recovered_to: 0,
            omap_recovered_to: Vec::new(),
            omap_complete: false,
        }
    }
}
impl ObjectRecoveryProgress {
    pub fn is_complete(&self) -> bool {
        self.data_complete && self.omap_complete
    }
}

impl Encode for ObjectRecoveryProgress {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.bool(self.first)?;
            e.bool(self.data_complete)?;
            e.u64(self.data_recovered_to)?;
            e.bytes(&self.omap_recovered_to)?;
            e.bool(self.omap_complete)
        })
    }
}
impl<'a> Decode<'a> for ObjectRecoveryProgress {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(ObjectRecoveryProgress {
                first: d.bool()?,
                data_complete: d.bool()?,
                data_recovered_to: d.u64()?,
                omap_recovered_to: d.bytes()?.to_vec(),
                omap_complete: d.bool()?,
            })
        })
    }
}

/// PullOp (ENV v1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PullOp {
    pub soid: Hobject,
    pub recovery_info: ObjectRecoveryInfo,
    pub recovery_progress: ObjectRecoveryProgress,
}
impl Encode for PullOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.soid.encode(e)?;
            self.recovery_info.encode(e)?;
            self.recovery_progress.encode(e)
        })
    }
}
impl<'a> Decode<'a> for PullOp {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(PullOp {
                soid: Hobject::decode(d)?,
                recovery_info: ObjectRecoveryInfo::decode(d)?,
                recovery_progress: ObjectRecoveryProgress::decode(d)?,
            })
        })
    }
}

/// PushOp (ENV v1). Wire order: ... recovery_info, **after_progress**, before_progress.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PushOp {
    pub soid: Hobject,
    pub version: Eversion,
    /// Concatenation of the `data_included` ranges in interval order.
    pub data: Bytes,
    pub data_included: IntervalSet,
    pub omap_header: Vec<u8>,
    pub omap_entries: BTreeMap<Vec<u8>, Vec<u8>>,
    pub attrset: BTreeMap<Vec<u8>, Vec<u8>>,
    pub recovery_info: ObjectRecoveryInfo,
    pub after_progress: ObjectRecoveryProgress,
    pub before_progress: ObjectRecoveryProgress,
}

impl PushOp {
    /// Throttle cost: data bytes + omap bytes (+ per-object cost added by the caller).
    pub fn cost(&self, per_object: u64) -> u64 {
        let omap: usize = self
            .omap_entries
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();
        self.data.len() as u64 + omap as u64 + per_object
    }
    /// Invariant (spec 6.2): `data_included` is well formed and len(data) == sum of its lengths. The decoder refuses
    /// a peer push that breaks it; locally built pushes are checked by the receiver too.
    pub fn data_consistent(&self) -> bool {
        crate::interval::checked_total(&self.data_included) == Some(self.data.len() as u64)
    }
}

impl Encode for PushOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.soid.encode(e)?;
            self.version.encode(e)?;
            e.bytes(&self.data)?;
            self.data_included.encode(e)?;
            e.bytes(&self.omap_header)?;
            self.omap_entries.encode(e)?;
            self.attrset.encode(e)?;
            self.recovery_info.encode(e)?;
            self.after_progress.encode(e)?;
            self.before_progress.encode(e)
        })
    }
}
impl<'a> Decode<'a> for PushOp {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Self::decode_in(d, None)
    }
}

impl PushOp {
    /// Decode with `shared` = the whole front segment the decoder runs over (a received push, see
    /// [`MOSDPGPush::decode_shared`](crate::MOSDPGPush::decode_shared)): the payload becomes a slice of it. `None`
    /// copies it into an owned buffer (`denc::from_slice`, tests).
    pub(crate) fn decode_in(d: &mut Decoder<'_>, shared: Option<&Bytes>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            let soid = Hobject::decode(d)?;
            let version = Eversion::decode(d)?;
            let at = d.position() + 4; // payload starts after its u32 length
            let raw = d.bytes()?;
            let data = match shared {
                Some(f) => f.slice(at..at + raw.len()),
                None => Bytes::copy_from_slice(raw),
            };
            let op = PushOp {
                soid,
                version,
                data,
                data_included: crate::interval::decode_checked(d)?,
                omap_header: d.bytes()?.to_vec(),
                omap_entries: BTreeMap::decode(d)?,
                attrset: BTreeMap::decode(d)?,
                recovery_info: ObjectRecoveryInfo::decode(d)?,
                after_progress: ObjectRecoveryProgress::decode(d)?,
                before_progress: ObjectRecoveryProgress::decode(d)?,
            };
            // the receiver slices `data` by these intervals in order: they must cover it exactly (spec 6.2)
            if !op.data_consistent() {
                return Err(denc::Error::BadValue(
                    "PushOp: data length != sum of data_included",
                ));
            }
            Ok(op)
        })
    }
}

/// PushReplyOp (ENV v1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PushReplyOp {
    pub soid: Hobject,
}
impl Encode for PushReplyOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| self.soid.encode(e))
    }
}
impl<'a> Decode<'a> for PushReplyOp {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(PushReplyOp {
                soid: Hobject::decode(d)?,
            })
        })
    }
}
