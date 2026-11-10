// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `timeindex` (spec/cls_log.md s5): omap index keyed by time for object-expiry hints.
//! Key `1_<sec:010>.<usec:06>_<key_ext>`, value = raw bytes, no header.

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use crate::log::{prefix_cmp, time_prefix};
use denc::types::UTime;

const PREFIX: &[u8] = b"1_";
pub const MAX_LIST: usize = 1000;
pub const MAX_TRIM: u64 = MAX_LIST as u64;
/// `sscanf("%255s")` limit for the key extension on list.
const KEY_EXT_MAX: usize = 255;

env_struct!(
    /// `cls_timeindex_entry` (1,1)
    Entry (1, 1) { key_ts: UTime, key_ext: Vec<u8>, value: Vec<u8> });
env_struct!(
    /// `cls_timeindex_add_op` (1,1)
    AddOp (1, 1) { entries: Vec<Entry> });
env_struct!(
    /// `cls_timeindex_list_op` (1,1)
    ListOp (1, 1) { from_time: UTime, marker: Vec<u8>, to_time: UTime, max_entries: i32 });
env_struct!(
    /// `cls_timeindex_list_ret` (1,1)
    ListRet (1, 1) { entries: Vec<Entry>, marker: Vec<u8>, truncated: bool });
env_struct!(
    /// `cls_timeindex_trim_op` (1,1)
    TrimOp (1, 1) { from_time: UTime, to_time: UTime, from_marker: Vec<u8>, to_marker: Vec<u8> });

pub fn add<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: AddOp = dec_op(input)?;
    for e in &op.entries {
        let mut k = time_prefix(e.key_ts);
        k.extend_from_slice(e.key_ext.as_slice());
        c.omap_set(&[(&k, &e.value)])?;
    }
    Ok(())
}

/// `sscanf(key, "1_%d.%d_%255s")` as upstream: the parsed microseconds become NANOseconds of the
/// returned timestamp (bug-compat), the extension stops at whitespace and at 255 bytes. `None`:
/// the pattern did not match (the entry is skipped).
fn parse_key(k: &[u8]) -> Option<(UTime, Option<Vec<u8>>)> {
    let rest = k.strip_prefix(PREFIX)?;
    let int = |s: &[u8]| -> Option<(i32, usize)> {
        let mut i = 0;
        if matches!(s.first(), Some(b'-' | b'+')) {
            i = 1;
        }
        let ds = i;
        while i < s.len() && s[i].is_ascii_digit() {
            i += 1;
        }
        if i == ds {
            return None;
        }
        let v: i128 = std::str::from_utf8(&s[..i]).ok()?.parse().ok()?;
        Some((v.clamp(i32::MIN as i128, i32::MAX as i128) as i32, i))
    };
    let (sec, n1) = int(rest)?;
    let rest = rest[n1..].strip_prefix(b".")?;
    let (usec, n2) = int(rest)?;
    // sscanf matched 2 items only (no "_" or nothing after it): the extension buffer keeps its previous content
    let Some(rest) = rest[n2..].strip_prefix(b"_") else {
        return Some((utime_ctor(sec, usec), None));
    };
    let rest = &rest[rest
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(rest.len())..];
    if rest.is_empty() {
        return Some((utime_ctor(sec, usec), None));
    }
    let end = rest
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(rest.len())
        .min(KEY_EXT_MAX);
    Some((utime_ctor(sec, usec), Some(rest[..end].to_vec())))
}

/// `utime_t(int sec, int nsec)`: fields cast to u32; carries only when nsec is STRICTLY above 1e9,
/// sec saturates at u32::MAX (unlike `UTime::normalized`).
fn utime_ctor(sec: i32, nsec: i32) -> UTime {
    const G: u64 = 1_000_000_000;
    let (s, n) = (sec as u32 as u64, nsec as u32 as u64);
    if n > G {
        UTime::new((s + n / G).min(u32::MAX as u64) as u32, (n % G) as u32)
    } else {
        UTime::new(s as u32, n as u32)
    }
}

pub fn list<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ListOp = dec_op(input)?;
    let from = if op.marker.is_empty() {
        time_prefix(op.from_time)
    } else {
        op.marker.clone()
    };
    let boundary = op.to_time >= op.from_time;
    let to = if boundary {
        time_prefix(op.to_time)
    } else {
        Vec::new()
    };
    // negative int -> huge size_t upstream -> capped; 0 -> no entries requested
    let max = if op.max_entries < 0 {
        MAX_LIST
    } else {
        (op.max_entries as usize).min(MAX_LIST)
    };
    let (vals, more) = c.omap_get_vals(&from, PREFIX, max as u64)?;
    let mut ret = ListRet {
        truncated: more,
        ..Default::default()
    };
    let mut stale_ext: Vec<u8> = Vec::new(); // the C `keyext` stack buffer survives across entries
    for (k, v) in &vals {
        if boundary && prefix_cmp(k, &to).is_ge() {
            ret.truncated = false;
            break;
        }
        if let Some((ts, ext)) = parse_key(k) {
            if let Some(e) = ext {
                stale_ext = e;
            }
            ret.entries.push(Entry {
                key_ts: ts,
                key_ext: stale_ext.clone(),
                value: v.clone(),
            });
        }
        ret.marker = k.clone();
    }
    enc(&ret)
}

pub fn trim<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: TrimOp = dec_op(input)?;
    let from = if op.from_marker.is_empty() {
        time_prefix(op.from_time)
    } else {
        op.from_marker.clone()
    };
    // the end is a PREFIX bound: keys starting with to_marker / the to_time stamp are removed
    let to = if op.to_marker.is_empty() {
        time_prefix(op.to_time)
    } else {
        op.to_marker.clone()
    };
    let (vals, _) = c.omap_get_vals(&from, PREFIX, MAX_TRIM)?;
    let mut removed = false;
    for k in vals.keys() {
        if prefix_cmp(k, &to).is_gt() {
            break;
        }
        c.omap_remove_key(k)?;
        removed = true;
    }
    if !removed {
        return Err(ENODATA);
    }
    Ok(())
}
