// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw_gc` (spec/cls_rgw_gc.md): RGW garbage-collection queue on top of [`crate::queue`].
//! Entries are `cls_rgw_gc_obj_info`; "urgent" (deferred) tags live in the queue head (and spill
//! to xattr `cls_queue_urgent_data`).

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use crate::queue::{self, Head};
use crate::rgw::types::ObjKey;
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeMap;

const URGENT_XATTR: &str = "cls_queue_urgent_data";
const LIST_DEFAULT_MAX: u64 = 128;

/// `cls_rgw_obj` (2,1): pool, key.name, loc, key (v2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GcObj {
    pub pool: Vec<u8>,
    pub key: ObjKey,
    pub loc: Vec<u8>,
}
impl Encode for GcObj {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.pool.encode(e)?;
            self.key.name.encode(e)?;
            self.loc.encode(e)?;
            self.key.encode(e)
        })
    }
}
impl<'a> Decode<'a> for GcObj {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let mut o = GcObj {
                pool: Vec::<u8>::decode(d)?,
                ..Default::default()
            };
            o.key.name = Vec::<u8>::decode(d)?;
            o.loc = Vec::<u8>::decode(d)?;
            if v >= 2 {
                o.key = ObjKey::decode(d)?;
            }
            Ok(o)
        })
    }
}
env_struct!(
    /// `cls_rgw_obj_chain`
    GcChain (1, 1) { objs: Vec<GcObj> });
env_struct!(
    /// `cls_rgw_gc_obj_info`: the queue entry payload.
    GcObjInfo (1, 1) { tag: Vec<u8>, chain: GcChain, time: UTime });
env_struct!(QueueInitOp (1, 1) { size: u64, num_deferred_entries: u64 });
env_struct!(SetEntryOp (1, 1) { expiration_secs: u32, info: GcObjInfo });
/// `cls_rgw_gc_queue_defer_entry_op`: same layout as [`SetEntryOp`].
pub type DeferEntryOp = SetEntryOp;
env_struct!(RemoveEntriesOp (1, 1) { num_entries: u64 });

/// `cls_rgw_gc_list_op` (2,1): `expired_only` defaults to TRUE for v1 encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListOp {
    pub marker: Vec<u8>,
    pub max: u32,
    pub expired_only: bool,
}
impl Default for ListOp {
    fn default() -> Self {
        ListOp {
            marker: Vec::new(),
            max: 0,
            expired_only: true,
        }
    }
}
impl Encode for ListOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.marker.encode(e)?;
            e.u32(self.max)?;
            e.bool(self.expired_only)
        })
    }
}
impl<'a> Decode<'a> for ListOp {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let mut o = ListOp {
                marker: Vec::<u8>::decode(d)?,
                max: d.u32()?,
                ..Default::default()
            };
            if v >= 2 {
                o.expired_only = d.bool()?;
            }
            Ok(o)
        })
    }
}

/// `cls_rgw_gc_list_ret` (2,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListRet {
    pub entries: Vec<GcObjInfo>,
    pub next_marker: Vec<u8>,
    pub truncated: bool,
}
impl Encode for ListRet {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.entries.encode(e)?;
            self.next_marker.encode(e)?;
            e.bool(self.truncated)
        })
    }
}
impl<'a> Decode<'a> for ListRet {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let entries = Vec::decode(d)?;
            let next_marker = if v >= 2 {
                Vec::<u8>::decode(d)?
            } else {
                Vec::new()
            };
            Ok(ListRet {
                entries,
                next_marker,
                truncated: d.bool()?,
            })
        })
    }
}

env_struct! {
    /// `cls_rgw_gc_urgent_data` (1,1): deferred tags (tag -> new expiry) kept outside the ring.
    UrgentData (1, 1) {
        urgent_data_map: BTreeMap<Vec<u8>, UTime>,
        num_urgent_data_entries: u32,
        num_head_urgent_entries: u32,
        num_xattr_urgent_entries: u32,
    }
}

fn urgent_of(h: &Head) -> Result<UrgentData, Errno> {
    if h.bl_urgent_data.is_empty() {
        Ok(UrgentData::default())
    } else {
        dec_op(&h.bl_urgent_data)
    }
}
/// xattr spill map; `None` when absent (ENOENT/ENODATA).
fn read_xattr_map<C: ClsCtx>(c: &mut C) -> Result<Option<BTreeMap<Vec<u8>, UTime>>, Errno> {
    match c.getxattr(URGENT_XATTR) {
        Err(ENOENT) | Err(ENODATA) => Ok(None),
        Err(e) => Err(e),
        Ok(b) => Ok(Some(dec_op(&b)?)),
    }
}
fn plus_secs(t: UTime, secs: u32) -> UTime {
    UTime {
        sec: t.sec.wrapping_add(secs),
        nsec: t.nsec,
    }
}

/// `rgw_gc_queue_init`: size + deferral limit; head urgent size = `rgw_gc_max_deferred_entries_size` (21.2.0; the dev tree uses 0), overflow spills to the xattr.
pub fn queue_init<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: QueueInitOp = dec_op(input)?;
    let urgent = UrgentData {
        num_urgent_data_entries: op.num_deferred_entries as u32,
        ..Default::default()
    };
    queue::init(
        c,
        &queue::InitOp {
            queue_size: op.size,
            max_urgent_data_size: c.config().rgw_gc_max_deferred_entries_size,
            bl_urgent_data: enc(&urgent)?,
        },
    )?;
    Ok(())
}

/// `rgw_gc_queue_enqueue`: the entry time is OSD now + expiration_secs (client time ignored).
pub fn queue_enqueue<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let mut op: SetEntryOp = dec_op(input)?;
    op.info.time = plus_secs(c.now(), op.expiration_secs);
    let mut h = queue::read_head(c)?;
    queue::enqueue(c, &mut h, &[enc(&op.info)?])?;
    queue::write_head(c, &h)?;
    Ok(())
}

/// Stale-entry test shared by list/remove: `true` = skip (a later deferral supersedes the entry).
fn superseded(map: &BTreeMap<Vec<u8>, UTime>, info: &GcObjInfo) -> bool {
    map.get(&info.tag).is_some_and(|t| *t > info.time)
}

pub fn queue_list_entries<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ListOp = dec_op(input)?;
    let h = queue::read_head(c)?;
    let urgent = urgent_of(&h)?;
    let now = c.now();
    let max = if op.max == 0 {
        LIST_DEFAULT_MAX
    } else {
        op.max as u64
    };
    let (mut list_max, mut start) = (max, op.marker.clone());
    let mut ret = ListRet::default();
    let mut num = 0u64;
    let (mut truncated, mut next);
    let mut xmap: Option<Option<BTreeMap<Vec<u8>, UTime>>> = None; // loaded lazily
    loop {
        let l = queue::list(c, &h, list_max, &start, b"")?;
        truncated = l.is_truncated;
        next = l.next_marker;
        if l.entries.is_empty() {
            break;
        }
        for qe in &l.entries {
            let info: GcObjInfo = dec_op(&qe.data)?;
            let in_head = urgent.urgent_data_map.contains_key(&info.tag);
            if in_head && superseded(&urgent.urgent_data_map, &info) {
                continue;
            }
            if !in_head && urgent.num_xattr_urgent_entries > 0 {
                if xmap.is_none() {
                    xmap = Some(read_xattr_map(c)?);
                }
                if let Some(Some(m)) = &xmap
                    && superseded(m, &info)
                {
                    continue;
                }
            }
            if !op.expired_only || info.time <= now {
                ret.entries.push(info);
            }
            num += 1;
        }
        if num < max && truncated {
            list_max = max - num;
            start = next.clone();
        } else {
            break;
        }
    }
    ret.truncated = truncated;
    if truncated {
        ret.next_marker = next;
    }
    enc(&ret)
}

pub fn queue_remove_entries<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: RemoveEntriesOp = dec_op(input)?;
    let mut h = queue::read_head(c)?;
    let mut urgent = urgent_of(&h)?;
    let n = if op.num_entries == 0 {
        LIST_DEFAULT_MAX
    } else {
        op.num_entries
    };
    // the +1 yields the marker just past the n-th counted entry
    let want = n.wrapping_add(1); // u64 from the client: wraps like classic
    let (mut list_max, mut start) = (want, Vec::new());
    let mut counted = 0u64;
    let mut end_marker = Vec::new();
    let mut xmap: Option<Option<BTreeMap<Vec<u8>, UTime>>> = None;
    loop {
        let l = queue::list(c, &h, list_max, &start, b"")?;
        if l.entries.is_empty() {
            break;
        }
        let mut last_marker = Vec::new();
        for qe in &l.entries {
            let info: GcObjInfo = dec_op(&qe.data)?;
            last_marker = qe.marker.clone();
            let mut found = false;
            if let Some(t) = urgent.urgent_data_map.get(&info.tag).copied() {
                found = true;
                if t > info.time {
                    continue;
                } else if t == info.time {
                    urgent.urgent_data_map.remove(&info.tag);
                    urgent.num_head_urgent_entries = urgent.num_head_urgent_entries.wrapping_sub(1);
                }
            }
            if !found && urgent.num_xattr_urgent_entries > 0 {
                if xmap.is_none() {
                    xmap = Some(read_xattr_map(c)?);
                }
                if let Some(Some(m)) = xmap.as_mut()
                    && let Some(t) = m.get(&info.tag).copied()
                {
                    if t > info.time {
                        continue;
                    } else if t == info.time {
                        // in-memory only (upstream does not write the spill map back here)
                        m.remove(&info.tag);
                        urgent.num_xattr_urgent_entries =
                            urgent.num_xattr_urgent_entries.wrapping_sub(1);
                    }
                }
            }
            counted += 1;
        }
        if counted < want {
            if !l.is_truncated {
                end_marker = l.next_marker;
                break;
            }
            list_max = want - counted;
            start = l.next_marker;
        } else {
            end_marker = last_marker;
            break;
        }
    }
    if !end_marker.is_empty() {
        queue::remove(c, &mut h, &end_marker)?;
    }
    h.bl_urgent_data = enc(&urgent)?;
    queue::write_head(c, &h)?;
    Ok(())
}

/// `rgw_gc_queue_update_entry` (defer). RGW passes 0 deferral slots, so this ends in `-ENOSPC`
/// unless the tag is already known; kept for parity.
pub fn queue_update_entry<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let mut op: DeferEntryOp = dec_op(input)?;
    op.info.time = plus_secs(c.now(), op.expiration_secs);
    let mut h = queue::read_head(c)?;
    let mut urgent: UrgentData = dec_op(&h.bl_urgent_data)?;
    // a tag already in the spill map is updated there; the head's urgent blob stays as stored
    let mut in_xattr = false;
    if let Some(t) = urgent.urgent_data_map.get_mut(&op.info.tag) {
        *t = op.info.time;
    } else if let Some(mut m) = read_xattr_map(c)?
        && let Some(t) = m.get_mut(&op.info.tag)
    {
        *t = op.info.time;
        in_xattr = true;
        c.setxattr(URGENT_XATTR, &enc(&m)?)?;
    } else {
        urgent
            .urgent_data_map
            .insert(op.info.tag.clone(), op.info.time);
        urgent.num_head_urgent_entries = urgent.num_head_urgent_entries.wrapping_add(1);
        if enc(&urgent)?.len() as u64 > h.max_urgent_data_size {
            // does not fit in the head: spill to the xattr map
            urgent.urgent_data_map.remove(&op.info.tag);
            urgent.num_head_urgent_entries = urgent.num_head_urgent_entries.wrapping_sub(1);
            let mut m = read_xattr_map(c)?.unwrap_or_default();
            m.insert(op.info.tag.clone(), op.info.time);
            urgent.num_xattr_urgent_entries = urgent.num_xattr_urgent_entries.wrapping_add(1);
            c.setxattr(URGENT_XATTR, &enc(&m)?)?;
        }
    }
    if urgent
        .num_head_urgent_entries
        .wrapping_add(urgent.num_xattr_urgent_entries)
        > urgent.num_urgent_data_entries
    {
        return Err(ENOSPC);
    }
    if !in_xattr {
        h.bl_urgent_data = enc(&urgent)?;
    }
    queue::write_head(c, &h)?;
    Ok(())
}
