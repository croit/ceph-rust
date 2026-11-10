// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw`, lifecycle shard objects (spec/cls_rgw.md s8): `lc.<n>` in the log pool, omap keyed
//! by the (opaque) bucket string, value `cls_rgw_lc_entry`; the omap header carries
//! `cls_rgw_lc_obj_head`. Methods `lc_get_entry`, `lc_set_entry`, `lc_rm_entry`,
//! `lc_get_next_entry`, `lc_list_entries`, `lc_put_head`, `lc_get_head`.

use super::index::read_omap;
use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeMap;

type D<T> = denc::Result<T>;

env_struct!(
    /// `cls_rgw_lc_entry` (1,1): value of a shard omap key.
    LcEntry (1, 1) { bucket: Vec<u8>, start_time: u64, status: u32 });

/// Method wrapper (2,2) around one [`LcEntry`] (`set_entry_op`, `rm_entry_op`, `get_entry_ret`,
/// `get_next_entry_ret`). Older senders (struct_v < 2) used `pair<string bucket, int status>`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LcEntryEnv(pub LcEntry);
impl Encode for LcEntryEnv {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(2, 2, |e| self.0.encode(e))
    }
}
impl<'a> Decode<'a> for LcEntryEnv {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        d.versioned(2, |d, v| {
            if v < 2 {
                let bucket = Vec::<u8>::decode(d)?;
                let status = d.u32()?;
                Ok(LcEntryEnv(LcEntry {
                    bucket,
                    start_time: 0,
                    status,
                }))
            } else {
                Ok(LcEntryEnv(LcEntry::decode(d)?))
            }
        })
    }
}

env_struct!(LcMarkerOp (1, 1) { marker: Vec<u8> });

/// `cls_rgw_lc_obj_head` (2,2): omap header of a shard object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LcHead {
    pub start_date: u64,
    pub marker: Vec<u8>,
    pub shard_rollover_date: u64,
}
impl Encode for LcHead {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(2, 2, |e| {
            e.u64(self.start_date)?;
            self.marker.encode(e)?;
            e.u64(self.shard_rollover_date)
        })
    }
}
impl<'a> Decode<'a> for LcHead {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        d.versioned(2, |d, v| {
            Ok(LcHead {
                start_date: d.u64()?,
                marker: Vec::<u8>::decode(d)?,
                shard_rollover_date: if v >= 2 { d.u64()? } else { 0 },
            })
        })
    }
}
env_struct!(LcPutHeadOp (1, 1) { head: LcHead });
env_struct!(LcGetHeadRet (1, 1) { head: LcHead });

/// `cls_rgw_lc_list_entries_op` (3,1); remembers the sender's struct_v (`compat_v`), which the
/// reply echoes as its own envelope version and form.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LcListOp {
    pub marker: Vec<u8>,
    pub max_entries: u32,
    pub compat_v: u8,
}
impl Encode for LcListOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(3, 1, |e| {
            self.marker.encode(e)?;
            e.u32(self.max_entries)
        })
    }
}
impl<'a> Decode<'a> for LcListOp {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        d.versioned(3, |d, v| {
            Ok(LcListOp {
                marker: Vec::<u8>::decode(d)?,
                max_entries: d.u32()?,
                compat_v: v,
            })
        })
    }
}

/// `cls_rgw_lc_list_entries_ret`: version <= 2 = `map<bucket, status>` (+ bool), else
/// `vector<entry>` (+ bool). The bool is always written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcListRet {
    pub entries: Vec<LcEntry>,
    pub is_truncated: bool,
    pub compat_v: u8,
}
impl Default for LcListRet {
    fn default() -> Self {
        LcListRet {
            entries: Vec::new(),
            is_truncated: false,
            compat_v: 3,
        }
    }
}
impl Encode for LcListRet {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(self.compat_v, 1, |e| {
            if self.compat_v <= 2 {
                let mut m: BTreeMap<&[u8], i32> = BTreeMap::new();
                for x in &self.entries {
                    m.entry(x.bucket.as_slice()).or_insert(x.status as i32); // insert: first wins
                }
                e.count(m.len())?;
                for (k, v) in m {
                    k.encode(e)?;
                    e.i32(v)?;
                }
            } else {
                self.entries.encode(e)?;
            }
            e.bool(self.is_truncated)
        })
    }
}
impl<'a> Decode<'a> for LcListRet {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        d.versioned(3, |d, v| {
            let mut r = LcListRet {
                compat_v: v,
                ..Default::default()
            };
            if v <= 2 {
                let m = BTreeMap::<Vec<u8>, i32>::decode(d)?;
                r.entries = m
                    .into_iter()
                    .map(|(bucket, s)| LcEntry {
                        bucket,
                        start_time: 0,
                        status: s as u32,
                    })
                    .collect();
            } else {
                r.entries = Vec::decode(d)?;
            }
            if v >= 2 {
                r.is_truncated = d.bool()?;
            }
            Ok(r)
        })
    }
}

/// `lc_get_entry` (RD): exact key lookup; `ENOENT` when missing, `EIO` when undecodable.
pub fn lc_get_entry<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: LcMarkerOp = dec_op(input)?;
    let e: LcEntry = read_omap(c, &op.marker)?;
    enc(&LcEntryEnv(e))
}

/// `lc_set_entry` (RW): upsert under the entry's bucket string.
pub fn lc_set_entry<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: LcEntryEnv = dec_op(input)?;
    c.omap_set(&[(&op.0.bucket, &enc(&op.0)?)])?;
    Ok(())
}

/// `lc_rm_entry` (RW): a missing key is fine (`ENOENT` only for an absent object).
pub fn lc_rm_entry<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: LcEntryEnv = dec_op(input)?;
    c.omap_remove_key(&op.0.bucket)?;
    Ok(())
}

/// `lc_get_next_entry` (RD): first entry strictly after `marker`; none = a default (empty) entry,
/// success.
pub fn lc_get_next_entry<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: LcMarkerOp = dec_op(input)?;
    let (vals, _) = c.omap_get_vals(&op.marker, b"", 1)?;
    let entry = match vals.values().next() {
        Some(v) => LcEntry::decode(&mut Decoder::new(v)).eio()?,
        None => LcEntry::default(),
    };
    enc(&LcEntryEnv(entry))
}

/// `lc_list_entries` (RD): page after `marker`, at most `max_entries` (omap cap 1024). A value
/// that is not a `cls_rgw_lc_entry` is retried as the legacy `pair<string, i32>`.
pub fn lc_list_entries<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: LcListOp = dec_op(input)?;
    let (vals, more) = c.omap_get_vals(&op.marker, b"", op.max_entries as u64)?;
    let mut ret = LcListRet {
        is_truncated: more,
        compat_v: op.compat_v,
        ..Default::default()
    };
    for v in vals.values() {
        let e = match LcEntry::decode(&mut Decoder::new(v)) {
            Ok(e) => e,
            Err(_) => {
                let mut d = Decoder::new(v);
                let bucket = Vec::<u8>::decode(&mut d).eio()?;
                let status = d.u32().eio()?;
                LcEntry {
                    bucket,
                    start_time: 0,
                    status,
                }
            }
        };
        ret.entries.push(e);
    }
    enc(&ret)
}

/// `lc_put_head` (RW): the omap header.
pub fn lc_put_head<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: LcPutHeadOp = dec_op(input)?;
    c.omap_set_header(&enc(&op.head)?)?;
    Ok(())
}

/// `lc_get_head` (RD): input not decoded; empty header = zero head; undecodable = `EINVAL`.
pub fn lc_get_head<C: ClsCtx>(c: &mut C, _input: &[u8]) -> R {
    let h = c.omap_get_header()?;
    let head = if h.is_empty() {
        LcHead::default()
    } else {
        LcHead::decode(&mut Decoder::new(&h)).inval()?
    };
    enc(&LcGetHeadRet { head })
}
