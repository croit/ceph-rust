// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw`, legacy omap garbage collection (spec/cls_rgw.md s9): `gc_set_entry`,
//! `gc_defer_entry`, `gc_list`, `gc_remove`. RGW falls back to these when the queue-backed
//! `rgw_gc` class is unavailable and still lists them on every GC pass.
//!
//! Two keys per entry, both holding the same `cls_rgw_gc_obj_info`: `0_<tag>` (name index) and
//! `1_<sec:011>.<nsec:09>` (time index = expiry time).

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use crate::rgw_gc::{GcObjInfo, ListOp, ListRet, SetEntryOp};
use denc::types::UTime;
use denc::{Decode, Decoder};

env_struct!(
    /// `cls_rgw_gc_defer_entry_op` (1,1)
    DeferTagOp (1, 1) { expiration_secs: u32, tag: Vec<u8> });
env_struct!(
    /// `cls_rgw_gc_remove_op` (1,1)
    RemoveTagsOp (1, 1) { tags: Vec<Vec<u8>> });

const LIST_DEFAULT: u32 = 128;

fn name_key(tag: &[u8]) -> Vec<u8> {
    [b"0_".as_slice(), tag].concat()
}
fn time_key(t: UTime) -> Vec<u8> {
    format!("1_{:011}.{:09}", t.sec, t.nsec).into_bytes()
}

fn get_info<C: ClsCtx>(c: &mut C, key: &[u8]) -> Result<GcObjInfo, Errno> {
    GcObjInfo::decode(&mut Decoder::new(&c.omap_get_val(key)?)).eio()
}

/// `gc_update_entry`: drop the old time key (when the tag is known), stamp `now + secs`, write both
/// keys. The old entry's absence or garbage is ignored.
fn update_entry<C: ClsCtx>(c: &mut C, secs: u32, mut info: GcObjInfo) -> Result<(), Errno> {
    if let Ok(old) = get_info(c, &name_key(&info.tag)) {
        match c.omap_remove_key(&time_key(old.time)) {
            Ok(()) | Err(ENOENT) => {}
            Err(e) => return Err(e),
        }
    }
    let now = c.now();
    info.time = UTime::new(now.sec.wrapping_add(secs), now.nsec);
    let v = enc(&info)?;
    c.omap_set(&[(&name_key(&info.tag), &v), (&time_key(info.time), &v)])
}

/// `gc_set_entry` (RW).
pub fn gc_set_entry<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: SetEntryOp = dec_op(input)?;
    update_entry(c, op.expiration_secs, op.info)?;
    Ok(())
}

/// `gc_defer_entry` (RW): re-arm an existing tag (`ENOENT` if unknown).
pub fn gc_defer_entry<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: DeferTagOp = dec_op(input)?;
    let info = get_info(c, &name_key(&op.tag))?;
    update_entry(c, op.expiration_secs, info)?;
    Ok(())
}

/// `gc_list` (RD): time-index entries after `marker` (a full omap key; empty = from `1_`), only the
/// expired ones when `expired_only`. `max` 0 = 128 (omap cap 1024). Stops, not truncated, at the
/// first key past the cutoff or outside the time index; `next_marker` is set only when truncated.
pub fn gc_list<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ListOp = dec_op(input)?;
    let max = if op.max != 0 { op.max } else { LIST_DEFAULT };
    let start: Vec<u8> = if op.marker.is_empty() {
        b"1_".to_vec()
    } else {
        op.marker.clone()
    };
    let end = op.expired_only.then(|| time_key(c.now()));
    let (vals, more) = c.omap_get_vals(&start, b"", max as u64)?;
    let mut ret = ListRet {
        truncated: more,
        ..Default::default()
    };
    let mut last = None;
    for (k, v) in &vals {
        if end.as_ref().is_some_and(|e| k.as_slice() >= e.as_slice()) || !k.starts_with(b"1_") {
            ret.truncated = false;
            return enc(&ret);
        }
        ret.entries
            .push(GcObjInfo::decode(&mut Decoder::new(v)).eio()?);
        last = Some(k);
    }
    if ret.truncated
        && let Some(k) = last
    {
        ret.next_marker = k.clone();
    }
    enc(&ret)
}

/// `gc_remove` (RW): per tag remove both keys; unknown tags are skipped.
pub fn gc_remove<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: RemoveTagsOp = dec_op(input)?;
    for tag in &op.tags {
        let info = match get_info(c, &name_key(tag)) {
            Ok(i) => i,
            Err(ENOENT) => continue,
            Err(e) => return Err(e),
        };
        match c.omap_remove_key(&time_key(info.time)) {
            Ok(()) | Err(ENOENT) => {}
            Err(e) => return Err(e),
        }
        match c.omap_remove_key(&name_key(tag)) {
            Ok(()) | Err(ENOENT) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Vec::new())
}
