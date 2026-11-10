// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pg_missing_t / pg_missing_item and the missing-set maintenance rules (spec pglog.md 4, 4.1).

use crate::log::{LogEntry, LogOp, ObjectCleanRegions};
use denc::types::{Eversion, Hobject};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Result};
use std::collections::BTreeMap;

/// pg_missing_item. Always encoded in the modern (octopus) form; both forms decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingItem {
    pub need: Eversion,
    pub have: Eversion,
    /// 1 = DELETE.
    pub flags: u8,
    pub clean_regions: ObjectCleanRegions,
}

impl MissingItem {
    pub const FLAG_DELETE: u8 = 1;
    pub fn new(need: Eversion, have: Eversion, is_delete: bool) -> Self {
        MissingItem {
            need,
            have,
            flags: if is_delete { Self::FLAG_DELETE } else { 0 },
            clean_regions: ObjectCleanRegions::fully_dirty(),
        }
    }
    pub fn is_delete(&self) -> bool {
        self.flags & Self::FLAG_DELETE != 0
    }
}

const MARKER: Eversion = Eversion {
    version: u64::MAX,
    epoch: u32::MAX,
};

impl Encode for MissingItem {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        Eversion::default().encode(e)?;
        MARKER.encode(e)?;
        self.need.encode(e)?;
        self.have.encode(e)?;
        e.u8(self.flags)?;
        self.clean_regions.encode(e)
    }
}
impl<'a> Decode<'a> for MissingItem {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        let e0 = Eversion::decode(d)?;
        let e1 = Eversion::decode(d)?;
        if e1 == MARKER {
            Ok(MissingItem {
                need: Eversion::decode(d)?,
                have: Eversion::decode(d)?,
                flags: d.u8()?,
                clean_regions: ObjectCleanRegions::decode(d)?,
            })
        } else {
            // legacy: 0'0 (ignored), need, have, flags (clean regions unknown = fully dirty)
            let _ = e0;
            Ok(MissingItem {
                need: e1,
                have: Eversion::decode(d)?,
                flags: d.u8()?,
                clean_regions: ObjectCleanRegions::fully_dirty(),
            })
        }
    }
}

/// pg_missing_t, ENCODE v5 compat 2.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgMissing {
    pub missing: BTreeMap<Hobject, MissingItem>,
    pub may_include_deletes: bool,
}

impl PgMissing {
    pub const STRUCT_V: u8 = 5;
    pub const STRUCT_COMPAT: u8 = 2;

    pub fn len(&self) -> usize {
        self.missing.len()
    }
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty()
    }
    pub fn is_missing(&self, oid: &Hobject) -> bool {
        self.missing.contains_key(oid)
    }
    /// Smallest `need` over all items (`oldest_need`); `None` when empty.
    pub fn oldest_need(&self) -> Option<Eversion> {
        self.missing.values().map(|i| i.need).min()
    }
    /// add(oid, need, have, is_delete): fully dirty clean regions.
    pub fn add(&mut self, oid: Hobject, need: Eversion, have: Eversion, is_delete: bool) {
        self.missing
            .insert(oid, MissingItem::new(need, have, is_delete));
    }
    /// revise_need: need := ..., have unchanged (0'0 if the item is created), fully dirty.
    pub fn revise_need(&mut self, oid: Hobject, need: Eversion, is_delete: bool) {
        let it = self
            .missing
            .entry(oid)
            .or_insert_with(|| MissingItem::new(need, Eversion::default(), is_delete));
        it.need = need;
        it.flags = if is_delete {
            MissingItem::FLAG_DELETE
        } else {
            0
        };
        it.clean_regions = ObjectCleanRegions::fully_dirty();
    }
    pub fn revise_have(&mut self, oid: &Hobject, have: Eversion) {
        if let Some(it) = self.missing.get_mut(oid) {
            it.have = have;
        }
    }
    /// got(oid, v): the object is now present at `v` (>= need, or a delete item).
    pub fn got(&mut self, oid: &Hobject, v: Eversion) -> bool {
        match self.missing.get(oid) {
            Some(it) if it.need <= v || it.is_delete() => {
                self.missing.remove(oid);
                true
            }
            _ => false,
        }
    }
    pub fn rm(&mut self, oid: &Hobject) {
        self.missing.remove(oid);
    }

    /// `add_next_event` (spec 4.1). The caller guarantees `e.soid <= last_backfill`.
    pub fn add_next_event(&mut self, e: &LogEntry) {
        if e.op == LogOp::ERROR {
            return;
        }
        let is_delete = e.op.is_delete();
        let is_new = e.prior_version == Eversion::default() || e.op == LogOp::CLONE;
        if !self.may_include_deletes && is_delete {
            // pre-luminous mode: delete entries remove the object from missing
            self.missing.remove(&e.soid);
            return;
        }
        match self.missing.get_mut(&e.soid) {
            Some(it) if is_new => *it = MissingItem::new(e.version, Eversion::default(), is_delete),
            Some(it) => {
                it.need = e.version;
                it.flags = if is_delete {
                    MissingItem::FLAG_DELETE
                } else {
                    0
                };
                if e.op == LogOp::LOST_REVERT {
                    it.clean_regions = ObjectCleanRegions::fully_dirty();
                } else {
                    it.clean_regions.merge(&e.clean_regions);
                }
            }
            None => {
                let it = if is_new {
                    MissingItem::new(e.version, Eversion::default(), is_delete)
                } else {
                    MissingItem {
                        need: e.version,
                        have: e.prior_version,
                        flags: if is_delete {
                            MissingItem::FLAG_DELETE
                        } else {
                            0
                        },
                        clean_regions: if e.op == LogOp::LOST_REVERT {
                            ObjectCleanRegions::fully_dirty()
                        } else {
                            e.clean_regions.clone()
                        },
                    }
                };
                self.missing.insert(e.soid.clone(), it);
            }
        }
    }
}

impl Encode for PgMissing {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            self.missing.encode(e)?;
            e.bool(self.may_include_deletes)
        })
    }
}
impl<'a> Decode<'a> for PgMissing {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(2, Self::STRUCT_COMPAT, |d, v| {
            let missing = Decode::decode(d)?;
            let may_include_deletes = if v >= 4 { d.bool()? } else { false };
            Ok(PgMissing {
                missing,
                may_include_deletes,
            })
        })
    }
}
