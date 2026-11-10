// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw`, raw index access (spec/cls_rgw.md s7): `bi_get`, `bi_put`, `bi_put_entries`,
//! `bi_list` (incl. the reshard-log branch) and the in-index bilog methods `bi_log_list`,
//! `bi_log_trim`, `bi_log_resync`, `bi_log_stop`. Used by dynamic resharding, `radosgw-admin bi *`
//! and multisite sync.

use super::index::{ERR_BUSY_RESHARDING, bilog_append_id_ver, guard, read_header, write_header};
use super::keys;
use super::types::*;
use crate::ctx::ClsCtx;
use crate::errno::*;
use std::collections::BTreeMap;

/// `bi_list` page cap.
const MAX_BI_LIST: u32 = 1000;

/// `bi_type`: class of an index key (after stripping `prefix`). Quirk (bug-compat): the numbering
/// follows the prefix table, so a bilog key (`0_`) reports Plain, `2001_` ReshardDeleted and the
/// end sentinel `9999_` the out-of-range value 5; unknown special keys are Invalid.
pub(super) fn bi_type(key: &[u8], prefix: &[u8]) -> u8 {
    let s = key.get(prefix.len()..).unwrap_or(&[]);
    if s.first() != Some(&keys::BI_PREFIX) {
        return bi::PLAIN;
    }
    const TABLE: [&[u8]; 5] = [b"0_", b"1000_", b"1001_", b"2001_", b"9999_"];
    for (i, t) in TABLE.iter().enumerate() {
        if s[1..].starts_with(t) {
            return (i + 1) as u8; // 1 Plain, 2 Instance, 3 OLH, 4 ReshardDeleted, 5 sentinel
        }
    }
    bi::INVALID
}

/// `rgw_cls_bi_entry::get_info`: decode the value and say whether it is accounted in the stats
/// (and with which category / stat deltas). A value that does not decode is `EIO` (classic would
/// throw).
fn get_info(ty: u8, data: &[u8]) -> Result<Option<(u8, CategoryStats)>, Errno> {
    match ty {
        bi::OLH => {
            dec_stored::<OlhEntry>(data)?;
            return Ok(None);
        }
        bi::RESHARD_DELETED => {
            dec_stored::<DeletedEntry>(data)?;
            return Ok(None);
        }
        _ => {}
    }
    let e: DirEntry = dec_stored(data)?;
    let acc = match ty {
        bi::PLAIN => e.exists && e.flags == 0,
        bi::INSTANCE => e.exists,
        _ => false,
    };
    Ok(acc.then(|| {
        (
            e.meta.category,
            CategoryStats {
                num_entries: 1,
                total_size: e.meta.accounted_size,
                total_size_rounded: super::keys::round4096(e.meta.accounted_size),
                actual_size: e.meta.size,
            },
        )
    }))
}

// ---------------------------------------------------------------- bi_get / bi_put / bi_put_entries

/// `bi_get` (RD). Type Instance with an empty instance resolves to the plain key (classic).
pub fn bi_get<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: BiGetOp = dec_op(input)?;
    let idx = match op.ty {
        bi::PLAIN => op.key.name.clone(),
        bi::INSTANCE => keys::obj_index_key(&op.key),
        bi::OLH => keys::olh_key(&op.key),
        _ => return Err(EINVAL),
    };
    let data = c.omap_get_val(&idx)?;
    enc(&BiGetRet {
        entry: BiEntry {
            ty: op.ty,
            idx,
            data,
        },
    })
}

/// `bi_put` (RW): unconditional raw write (or delete for ReshardDeleted); no guard, no stats, no
/// header write. Primitive failures are swallowed: always 0.
pub fn bi_put<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: BiPutOp = dec_op(input)?;
    let e = op.entry;
    let _ = if e.ty == bi::RESHARD_DELETED {
        c.omap_remove_key(&e.idx)
    } else {
        c.omap_set(&[(&e.idx, &e.data)])
    };
    Ok(())
}

/// `bi_put_entries` (RW): bulk raw write used by reshard. Stats of written entries are added to
/// the header (and with `check_existing` those of the overwritten ones subtracted), header ver+1.
pub fn bi_put_entries<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: BiPutEntriesOp = dec_op(input)?;
    if op.entries.len() as u64 > c.config().osd_max_omap_entries_per_request {
        return Err(E2BIG);
    }
    let mut h = read_header(c)?;
    guard(c, &h, ERR_BUSY_RESHARDING)?;

    if op.check_existing {
        let mut idxs: Vec<&[u8]> = op.entries.iter().map(|e| e.idx.as_slice()).collect();
        idxs.sort_unstable();
        idxs.dedup();
        let vals = c.omap_get_vals_by_keys(&idxs)?;
        for (idx, data) in &vals {
            if let Some((cat, st)) = get_info(bi_type(idx, b""), data)? {
                h.stats.entry(cat).or_default().sub(&st);
            }
        }
    }
    let mut new_vals: BTreeMap<&[u8], &[u8]> = BTreeMap::new();
    for e in &op.entries {
        if e.ty == bi::RESHARD_DELETED {
            let _ = c.omap_remove_key(&e.idx); // not fatal
            continue;
        }
        if let Some((cat, st)) = get_info(e.ty, &e.data)? {
            h.stats.entry(cat).or_default().add(&st);
        }
        new_vals.entry(&e.idx).or_insert(&e.data); // duplicates: first wins, both counted
    }
    let pairs: Vec<(&[u8], &[u8])> = new_vals.into_iter().collect();
    c.omap_set(&pairs)?;
    write_header(c, &mut h)?;
    Ok(())
}

// ---------------------------------------------------------------- bi_list

struct Page {
    entries: Vec<BiEntry>,
    more: bool,
}

/// `list_plain_entries_help`: one `get_vals` page of plain entries; stops at `end_key`
/// (exclusive, empty = none) or when a decoded entry's name sorts after the name filter.
/// Returns (count, end_key_reached).
fn plain_help<C: ClsCtx>(
    c: &mut C,
    p: &mut Page,
    name_filter: &[u8],
    start_after: &[u8],
    end_key: &[u8],
    max: u32,
) -> Result<(u32, bool), Errno> {
    let (vals, more) = c.omap_get_vals(start_after, name_filter, max as u64)?;
    p.more = more;
    let mut count = 0u32;
    for (k, v) in vals {
        if !end_key.is_empty() && k.as_slice() >= end_key {
            p.more = false;
            return Ok((count, true));
        }
        let e: DirEntry = dec_stored(&v)?;
        if !name_filter.is_empty() && e.key.name.as_slice() > name_filter {
            p.more = false;
            return Ok((count, true));
        }
        p.entries.push(BiEntry {
            ty: bi::PLAIN,
            idx: k,
            data: v,
        });
        count += 1;
        if count >= max {
            return Ok((count, false));
        }
    }
    Ok((count, false))
}

/// Plain entries below (`low`) or above the special area.
fn plain_entries<C: ClsCtx>(
    c: &mut C,
    p: &mut Page,
    name_filter: &[u8],
    marker: &[u8],
    max: u32,
    low: bool,
) -> Result<u32, Errno> {
    p.more = false;
    if low {
        if marker < &[keys::BI_PREFIX][..] {
            let (n, _) = plain_help(c, p, name_filter, marker, &[keys::BI_PREFIX], max)?;
            return Ok(n);
        }
        return Ok(0);
    }
    let start = if marker > keys::END {
        marker
    } else {
        keys::END
    };
    let (n, _) = plain_help(c, p, name_filter, start, &[], max)?;
    Ok(n)
}

/// Instance (`inst`) or olh entries of one name (or all): start after the later of the region
/// start and the marker, include the exact first key when a name is given and the marker has not
/// moved past it, stop at the first key outside the region / of another name.
fn special_entries<C: ClsCtx>(
    c: &mut C,
    p: &mut Page,
    inst: bool,
    name: &[u8],
    marker: &[u8],
    mut max: u32,
) -> Result<u32, Errno> {
    let (region, ty) = if inst {
        (keys::INSTANCE, bi::INSTANCE)
    } else {
        (keys::OLH, bi::OLH)
    };
    let first_idx = if inst {
        keys::instance_key(&ObjKey::from_bytes(name, b""), false)
    } else {
        keys::olh_key(&ObjKey::from_bytes(name, b""))
    };
    let region_start = if name.is_empty() {
        region.to_vec()
    } else {
        first_idx
    };
    let filter = region_start.clone();
    let start_after = if region_start.as_slice() > marker {
        region_start
    } else {
        marker.to_vec()
    };
    let first = match c.omap_get_val(&start_after) {
        Ok(v) => Some(v),
        Err(ENOENT) => None,
        Err(e) => return Err(e),
    };
    let found_first = first.is_some() && start_after.as_slice() != marker && max > 0;
    if found_first {
        max -= 1;
    }
    let mut vals = BTreeMap::new();
    if max > 0 {
        let (v, more) = c.omap_get_vals(&start_after, b"", max as u64)?;
        vals = v;
        p.more = more;
    }
    if found_first && let Some(v) = first {
        vals.insert(start_after, v);
    }
    let mut count = 0;
    for (k, v) in vals {
        if !k.starts_with(&filter) {
            p.more = false;
            return Ok(count);
        }
        let ename = if inst {
            dec_stored::<DirEntry>(&v)?.key.name
        } else {
            dec_stored::<OlhEntry>(&v)?.key.name
        };
        if !name.is_empty() && ename != name {
            p.more = false;
            return Ok(count);
        }
        p.entries.push(BiEntry {
            ty,
            idx: k,
            data: v,
        });
        count += 1;
    }
    Ok(count)
}

/// `bi_list` (RD): plain-low, instance, olh, plain-high segments in key order (each only while the
/// previous one did not signal `more`), or the reshard log with `reshardlog`.
pub fn bi_list<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: BiListOp = dec_op(input)?;
    let max = op.max.min(MAX_BI_LIST);
    let mut ret = BiListRet::default();
    if op.reshardlog {
        reshard_log_list(c, &op.marker, max, &mut ret)?;
        return enc(&ret);
    }
    let (name, marker) = (op.name_filter.as_slice(), op.marker.as_slice());
    let mut p = Page {
        entries: Vec::new(),
        more: false,
    };
    // Later segments always get room for at least one entry: when the page is exactly full they
    // still probe for more (a hit makes `count > max` -> truncated), like classic's wrapped room.
    let room = |count: u32| max.saturating_sub(count).max(1);
    let mut count = plain_entries(c, &mut p, name, marker, max, true)?;
    if !p.more && count <= max {
        count += special_entries(c, &mut p, true, name, marker, room(count))?;
    }
    if !p.more && count <= max {
        count += special_entries(c, &mut p, false, name, marker, room(count))?;
    }
    if !p.more && count <= max {
        // the high region keeps the plain `more` flag of its own call
        let mut hi = Page {
            entries: Vec::new(),
            more: false,
        };
        count += plain_entries(c, &mut hi, name, marker, room(count), false)?;
        p.entries.append(&mut hi.entries);
        p.more = hi.more;
    }
    ret.is_truncated = count > max || p.more;
    p.entries.truncate(max as usize);
    ret.entries = p.entries;
    enc(&ret)
}

/// Reshard-log listing: keys `80 "2001_" idx`, value = stored bi_entry; stops (not truncated) at
/// `80 "9999_"`. A non-ReshardDeleted entry gets its type from the original key.
fn reshard_log_list<C: ClsCtx>(
    c: &mut C,
    marker: &[u8],
    max: u32,
    ret: &mut BiListRet,
) -> Result<(), Errno> {
    let mut start = keys::RESHARD_LOG.to_vec();
    start.extend_from_slice(marker);
    let (vals, more) = c.omap_get_vals(&start, b"", max as u64)?;
    ret.is_truncated = more;
    for (k, v) in vals {
        if k.as_slice() >= keys::END {
            ret.is_truncated = false;
            return Ok(());
        }
        let mut e: BiEntry = dec_stored(&v)?;
        if e.ty != bi::RESHARD_DELETED {
            e.ty = bi_type(&k, keys::RESHARD_LOG);
        }
        ret.entries.push(e);
    }
    Ok(())
}

// ---------------------------------------------------------------- bilog (in-index)

/// `bi_log_list` (RD): entries strictly after `marker` (an id, without the key prefix); stops
/// (not truncated) past the bilog namespace. `max` is capped by the omap primitive.
pub fn bi_log_list<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: BiLogListOp = dec_op(input)?;
    let mut start = keys::BILOG.to_vec();
    start.extend_from_slice(&op.marker);
    let end: &[u8] = keys::INSTANCE; // first byte of the next namespace
    let (vals, more) = c.omap_get_vals(&start, b"", op.max as u64)?;
    let mut ret = BiLogListRet {
        truncated: more,
        ..Default::default()
    };
    for (k, v) in vals {
        if k.as_slice() > end {
            ret.truncated = false;
            break;
        }
        ret.entries.push(dec_stored(&v)?);
    }
    enc(&ret)
}

/// `bi_log_trim` (RW): remove `(start_marker, end_marker]`; `ENODATA` when nothing is in range
/// (the caller loops until then). Does not touch the header. Empty end = through the namespace.
pub fn bi_log_trim<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: BiLogTrimOp = dec_op(input)?;
    let mut begin = keys::BILOG.to_vec();
    begin.extend_from_slice(&op.start_marker);
    let end = if op.end_marker.is_empty() {
        keys::INSTANCE.to_vec()
    } else {
        let mut k = keys::BILOG.to_vec();
        k.extend_from_slice(&op.end_marker);
        k.push(0); // one past the end marker
        k
    };
    let (first, _) = c.omap_get_keys(&begin, 1)?;
    let Some(first) = first.into_iter().next() else {
        return Err(ENODATA);
    };
    if end < first {
        return Err(ENODATA);
    }
    c.omap_remove_range(&first, &end)?;
    Ok(())
}

fn bilog_marker_entry<C: ClsCtx>(c: &mut C, opcode: u8, stopped: bool) -> Result<(), Errno> {
    let mut h = read_header(c)?;
    let e = BiLogEntry {
        timestamp: c.now(),
        op: opcode,
        state: state::COMPLETE,
        ..Default::default()
    };
    let id_ver = h.ver;
    bilog_append_id_ver(c, &mut h, e, id_ver)?;
    h.syncstopped = stopped;
    write_header(c, &mut h)?;
    Ok(())
}

/// `bi_log_resync` (RW): log a RESYNC marker and re-enable bilog writing. Input ignored.
pub fn bi_log_resync<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Result<(), Errno> {
    bilog_marker_entry(c, op::RESYNC, false)
}

/// `bi_log_stop` (RW): log a SYNCSTOP marker and stop bilog writing (`syncstopped`). Input ignored.
pub fn bi_log_stop<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Result<(), Errno> {
    bilog_marker_entry(c, op::SYNCSTOP, true)
}
