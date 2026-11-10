// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw`, bucket-index shard methods (spec/cls_rgw.md s4-s9): init, guard, list, prepare/
//! complete, tag timeout, update_stats, suggest, check/rebuild, resharding control.
//!
//! Index object = omap + header (`DirHeader`). Reads see the message-start state (cls.md s4), so a
//! handler never observes its own writes; the in-memory header carries the running updates and is
//! persisted by `write_header` (ver += 1) where classic does so.

use super::keys::{self, round4096};
use super::types::*;
use crate::ctx::{ClsCtx, OmapMap, omap_scan};
use crate::errno::*;
use crate::registry::Reply;
use denc::types::UTime;
use denc::{Decode, Decoder, Encode};
use std::ops::ControlFlow::{Break, Continue};

/// `CLS_RGW_ERR_BUSY_RESHARDING` (not an errno; RGW maps it and retries).
pub const ERR_BUSY_RESHARDING: Errno = -2300;
/// bucket_list "advance and retry": truncated listing that produced no entry (output delivered).
pub const ADVANCE_AND_RETRY: Errno = EFBIG;
/// bucket_list: max `get_vals` attempts per call.
const LIST_MAX_ATTEMPTS: usize = 8;
const DEFAULT_TAG_TIMEOUT: u64 = 120;

// ---------------------------------------------------------------- header + entry helpers

/// `read_bucket_header`: empty/absent -> default header; decode failure -> `EIO`.
pub(super) fn read_header<C: ClsCtx>(c: &mut C) -> Result<DirHeader, Errno> {
    let b = c.omap_get_header()?;
    if b.is_empty() {
        Ok(DirHeader::default())
    } else {
        dec_stored(&b)
    }
}

/// `write_bucket_header`: every header write bumps `ver` by one (wrapping).
pub(super) fn write_header<C: ClsCtx>(c: &mut C, h: &mut DirHeader) -> Result<(), Errno> {
    h.ver = h.ver.wrapping_add(1);
    c.omap_set_header(&enc(h)?)
}

/// `guard_bucket_resharding`: `err` while a reshard blocks writes, else `Ok`.
pub(super) fn guard<C: ClsCtx>(c: &C, h: &DirHeader, err: Errno) -> Result<(), Errno> {
    let thr = c.config().rgw_reshardlog_threshold;
    if h.new_instance.in_progress()
        || (h.new_instance.in_logrecord() && h.reshardlog_entries as u64 >= thr)
    {
        Err(err)
    } else {
        Ok(())
    }
}

/// Set an index key; while the shard is IN_LOGRECORD also write the reshard-log twin and count it.
pub(super) fn write_raw<C: ClsCtx>(
    c: &mut C,
    h: &mut DirHeader,
    idx: &[u8],
    value: &[u8],
) -> Result<(), Errno> {
    if h.new_instance.in_logrecord() {
        let log = enc(&BiEntry {
            ty: bi::INVALID,
            idx: idx.to_vec(),
            data: value.to_vec(),
        })?;
        c.omap_set(&[(idx, value), (&keys::reshard_log_key(idx), &log)])?;
        h.reshardlog_entries = h.reshardlog_entries.wrapping_add(1);
        Ok(())
    } else {
        c.omap_set(&[(idx, value)])
    }
}
pub(super) fn write_entry<C: ClsCtx, T: Encode>(
    c: &mut C,
    h: &mut DirHeader,
    idx: &[u8],
    e: &T,
) -> Result<(), Errno> {
    write_raw(c, h, idx, &enc(e)?)
}

/// Remove an index key (+ reshard-log tombstone while IN_LOGRECORD).
pub(super) fn remove_entry<C: ClsCtx>(
    c: &mut C,
    h: &mut DirHeader,
    idx: &[u8],
    key: &ObjKey,
) -> Result<(), Errno> {
    c.omap_remove_key(idx)?;
    if h.new_instance.in_logrecord() {
        h.reshardlog_entries = h.reshardlog_entries.wrapping_add(1);
        let log = enc(&BiEntry {
            ty: bi::RESHARD_DELETED,
            idx: idx.to_vec(),
            data: enc(&DeletedEntry { key: key.clone() })?,
        })?;
        c.omap_set(&[(&keys::reshard_log_key(idx), &log)])?;
    }
    Ok(())
}

/// Read + decode one omap value (`ENOENT` missing, `EIO` undecodable).
pub(super) fn read_omap<C: ClsCtx, T: for<'a> Decode<'a>>(c: &mut C, k: &[u8]) -> Result<T, Errno> {
    dec_stored(&c.omap_get_val(k)?)
}

/// `read_key_entry`: resolves a plain VER_MARKER placeholder to the instance entry. Returns the
/// index key finally read (also on failure: the last one tried) and the entry.
pub(super) fn read_key_entry<C: ClsCtx>(
    c: &mut C,
    key: &ObjKey,
    special_dm: bool,
) -> (Vec<u8>, Result<DirEntry, Errno>) {
    let mut idx = keys::obj_index_key(key);
    let mut e: DirEntry = match read_omap(c, &idx) {
        Ok(e) => e,
        Err(er) => return (idx, Err(er)),
    };
    if key.instance.is_empty() && e.flags & flag::VER_MARKER != 0 {
        if special_dm {
            let i2 = keys::instance_key(key, true);
            let r = read_omap::<C, DirEntry>(c, &i2);
            idx = i2;
            if let Ok(x) = r {
                return (idx, Ok(x));
            }
        }
        idx = keys::instance_key(key, false);
        match read_omap(c, &idx) {
            Ok(x) => e = x,
            Err(er) => return (idx, Err(er)),
        }
    }
    (idx, Ok(e))
}

pub(super) fn unaccount(h: &mut DirHeader, e: &DirEntry) {
    if e.exists {
        let s = h.stats.entry(e.meta.category).or_default();
        s.num_entries = s.num_entries.wrapping_sub(1);
        s.total_size = s.total_size.wrapping_sub(e.meta.accounted_size);
        s.total_size_rounded = s
            .total_size_rounded
            .wrapping_sub(round4096(e.meta.accounted_size));
        s.actual_size = s.actual_size.wrapping_sub(e.meta.size);
    }
}
fn account_add(h: &mut DirHeader, m: &DirEntryMeta) {
    let s = h.stats.entry(m.category).or_default();
    s.num_entries = s.num_entries.wrapping_add(1);
    s.total_size = s.total_size.wrapping_add(m.accounted_size);
    s.total_size_rounded = s
        .total_size_rounded
        .wrapping_add(round4096(m.accounted_size));
    s.actual_size = s.actual_size.wrapping_add(m.size);
}

/// Append a bilog entry (`log_index_operation`); `h.max_marker` is advanced in memory.
pub(super) fn bilog_append<C: ClsCtx>(
    c: &mut C,
    h: &mut DirHeader,
    e: BiLogEntry,
) -> Result<(), Errno> {
    let id_ver = e.index_ver;
    bilog_append_id_ver(c, h, e, id_ver)
}

/// Like [`bilog_append`] with an explicit index version for the key (resync/stop: the key uses
/// `header.ver` while the stored entry keeps `index_ver` 0).
pub(super) fn bilog_append_id_ver<C: ClsCtx>(
    c: &mut C,
    h: &mut DirHeader,
    mut e: BiLogEntry,
    id_ver: u64,
) -> Result<(), Errno> {
    let id = keys::bilog_id(id_ver, c.current_version(), c.subop_num());
    e.id = id.clone();
    if id > h.max_marker {
        h.max_marker = id.clone();
    }
    c.omap_set(&[(&keys::bilog_key(&id), &enc(&e)?)])
}

// ---------------------------------------------------------------- init / header-only methods

/// `bucket_init_index` and `bucket_init_index2` (same handler).
pub fn init_index<C: ClsCtx>(c: &mut C, _input: &[u8]) -> R {
    match c.omap_get_header() {
        Ok(h) if !h.is_empty() => return Err(EINVAL),
        Ok(_) | Err(ENODATA) | Err(ENOENT) => {}
        Err(e) => return Err(e),
    }
    let mut h = DirHeader::default();
    write_header(c, &mut h)?;
    Ok(Vec::new())
}

pub fn set_tag_timeout<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: TagTimeoutOp = dec_op(input)?;
    let mut h = read_header(c)?;
    h.tag_timeout = op.tag_timeout;
    write_header(c, &mut h)?;
    Ok(())
}

pub fn update_stats<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: UpdateStatsOp = dec_op(input)?;
    let mut h = read_header(c)?;
    for (cat, s) in &op.stats {
        let dest = h.stats.entry(*cat).or_default();
        if op.absolute {
            *dest = *s;
        } else {
            dest.add(s);
        }
    }
    for (cat, s) in &op.dec_stats {
        let dest = h.stats.entry(*cat).or_default();
        if op.absolute {
            return Err(EINVAL);
        }
        dest.sub(s);
    }
    write_header(c, &mut h)?;
    Ok(())
}

// ---------------------------------------------------------------- resharding control

pub fn guard_bucket_resharding<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: GuardOp = dec_op(input)?;
    let h = read_header(c)?;
    guard(c, &h, op.ret_err)?;
    Ok(())
}

pub fn set_bucket_resharding<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: SetReshardingOp = dec_op(input)?;
    let mut h = read_header(c)?;
    h.new_instance.reshard_status = op.entry.reshard_status;
    write_header(c, &mut h)?;
    Ok(())
}

pub fn clear_bucket_resharding<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let _: EmptyOp = dec_op(input)?;
    let mut h = read_header(c)?;
    h.new_instance = InstanceEntry::default();
    write_header(c, &mut h)?;
    Ok(())
}

pub fn get_bucket_resharding<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let _: EmptyOp = dec_op(input)?;
    let h = read_header(c)?;
    enc(&GetReshardingRet {
        new_instance: h.new_instance,
    })
}

/// Drop the whole reshard-log range; `ENODATA` when it is empty (caller loops until then). Input
/// is not decoded.
pub fn reshard_log_trim<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Result<(), Errno> {
    let mut h = read_header(c)?;
    let (ks, _) = c.omap_get_keys(keys::RESHARD_LOG, 1)?;
    let Some(first) = ks.into_iter().next() else {
        return Err(ENODATA);
    };
    if keys::END < first.as_slice() {
        return Err(ENODATA);
    }
    c.omap_remove_range(&first, keys::END)?;
    h.reshardlog_entries = 0;
    write_header(c, &mut h)?;
    Ok(())
}

// ---------------------------------------------------------------- bucket_list

/// `get_obj_vals`: omap read that transparently skips the special (0x80) namespace.
fn get_obj_vals<C: ClsCtx>(
    c: &mut C,
    start: &[u8],
    prefix: &[u8],
    n: u64,
) -> Result<(OmapMap, bool), Errno> {
    let (mut ks, mut more) = c.omap_get_vals(start, prefix, n)?;
    let (Some(first), Some(last)) = (ks.keys().next(), ks.keys().next_back()) else {
        return Ok((ks, more));
    };
    let fb = first.first().copied().unwrap_or(0);
    let lb = last.first().copied().unwrap_or(0);
    if lb < keys::BI_PREFIX || fb > keys::BI_PREFIX {
        return Ok((ks, more)); // all before or all after the special area
    }
    let doomed: Vec<Vec<u8>> = ks
        .range(vec![keys::BI_PREFIX]..vec![keys::BI_PREFIX + 1])
        .map(|(k, _)| k.clone())
        .collect();
    for k in doomed {
        ks.remove(&k);
    }
    if n as usize == ks.len() || !more {
        return Ok((ks, more));
    }
    let mut new_start = vec![keys::BI_PREFIX + 1];
    if let Some(l) = ks.keys().next_back()
        && new_start < *l
    {
        new_start = l.clone();
    }
    let (more_keys, m2) = c.omap_get_vals(&new_start, prefix, n - ks.len() as u64)?;
    ks.extend(more_keys);
    more = m2;
    Ok((ks, more))
}

/// `encode_list_index_key`: map a client marker to the omap key to start after.
fn list_start_key<C: ClsCtx>(c: &mut C, key: &ObjKey) -> Result<Vec<u8>, Errno> {
    if key.instance.is_empty() {
        return Ok(key.name.clone());
    }
    let mut tmp = key.clone();
    if tmp.instance == b"null" {
        tmp.instance.clear();
    }
    match read_omap::<C, DirEntry>(c, &keys::instance_key(&tmp, false)) {
        Ok(e) => Ok(keys::list_key(&e)),
        Err(ENOENT) => Ok(keys::after_versions(&key.name)),
        Err(e) => Err(e),
    }
}

fn starts_with(hay: &[u8], needle: &[u8]) -> bool {
    hay.starts_with(needle)
}
fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// `bucket_list` (RD). Returns `-EFBIG` WITH output when truncated without any entry.
pub fn bucket_list<C: ClsCtx>(c: &mut C, input: &[u8]) -> Reply {
    match bucket_list_inner(c, input) {
        Ok(r) => r,
        Err(e) => Reply {
            ret: e,
            out: Vec::new(),
        },
    }
}

fn bucket_list_inner<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Reply, Errno> {
    let op: ListOp = dec_op(input)?;
    let mut ret = ListRet {
        dir: Dir {
            header: read_header(c)?,
            m: Default::default(),
        },
        ..Default::default()
    };
    let want = op.num_entries as usize;
    if want == 0 {
        return Ok(Reply {
            ret: 0,
            out: enc(&ret)?,
        });
    }
    let prefix = op.filter_prefix.as_slice();
    let delim = op.delimiter.as_slice();
    let has_delim = !delim.is_empty();

    let mut start_after = list_start_key(c, &op.start_obj)?;
    let mut marker_key = ObjKey::default();
    let mut prev_key: Vec<u8> = Vec::new();
    let mut prev_prefix: Vec<u8> = Vec::new();
    let mut done = false;
    let mut more = true;

    if has_delim && start_after.as_slice() > prefix && start_after.ends_with(delim) {
        start_after = keys::after_delim(&start_after); // skip a returned common prefix
    }

    let mut attempt = 0;
    while attempt < LIST_MAX_ATTEMPTS && more && !done && ret.dir.m.len() < want {
        attempt += 1;
        let (batch, m) = get_obj_vals(c, &start_after, prefix, (want - ret.dir.m.len()) as u64)?;
        more = m;
        done = batch.is_empty();
        let batch: Vec<(Vec<u8>, Vec<u8>)> = batch.into_iter().collect();
        let mut i = 0;
        while i < batch.len() {
            let (k, v) = &batch[i];
            let entry: DirEntry = dec_op(v)?; // undecodable value fails the call (EINVAL)
            start_after = k.clone();
            marker_key = entry.key.clone();
            let Some(key) = keys::decode_list_key(k) else {
                i += 1;
                continue;
            };
            if !entry.is_valid() {
                i += 1;
                continue;
            }
            // skip noncurrent versions, delete markers and the start name itself
            if !op.list_versions && (!entry.is_visible() || op.start_obj.name == key.name) {
                start_after = keys::after_versions(&key.name);
                marker_key = ObjKey::from_bytes(&start_after, b"");
                i = batch.partition_point(|(bk, _)| bk < &start_after);
                continue;
            }
            if has_delim && let Some(pos) = find_from(&key.name, delim, prefix.len()) {
                let prefix_key = key.name[..pos + delim.len()].to_vec();
                if prefix_key == prev_prefix {
                    i += 1;
                    continue;
                }
                prev_prefix = prefix_key.clone();
                if ret.dir.m.len() < want {
                    let proxy = DirEntry {
                        key: ObjKey::from_bytes(&prefix_key, b""),
                        flags: flag::COMMON_PREFIX,
                        ..Default::default()
                    };
                    ret.dir.m.insert(prefix_key.clone(), proxy);
                }
                start_after = keys::after_delim(&prefix_key);
                marker_key = ObjKey::from_bytes(&start_after, b"");
                i = batch.partition_point(|(bk, _)| bk < &start_after);
                continue;
            }
            if ret.dir.m.len() < want && *k != prev_key {
                ret.dir.m.insert(k.clone(), entry);
                prev_key = k.clone();
            }
            i += 1;
        }
    }
    ret.is_truncated = more && !done;
    if ret.is_truncated {
        ret.marker = marker_key;
    }
    let out = enc(&ret)?;
    let r = if ret.is_truncated && ret.dir.m.is_empty() {
        ADVANCE_AND_RETRY
    } else {
        0
    };
    Ok(Reply { ret: r, out })
}

// ---------------------------------------------------------------- prepare / complete

/// `bucket_prepare_op` (RW): register a pending tag on the key's entry. Header is NOT written.
pub fn prepare_op<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ObjPrepareOp = dec_op(input)?;
    if op.tag.is_empty() {
        return Err(EINVAL);
    }
    let mut h = read_header(c)?;
    guard(c, &h, ERR_BUSY_RESHARDING)?;
    let (idx, r) = read_key_entry(c, &op.key, false);
    let mut entry = match r {
        Ok(e) => e,
        Err(ENOENT) => DirEntry {
            key: op.key.clone(),
            ver: EntryVer::default(),
            exists: false,
            locator: op.locator.clone(),
            ..Default::default()
        },
        Err(e) => return Err(e),
    };
    entry.pending_insert(
        &op.tag,
        PendingInfo {
            state: state::PENDING_MODIFY,
            timestamp: c.now(),
            op: op.op,
        },
    );
    write_entry(c, &mut h, &idx, &entry)?;
    Ok(Vec::new())
}

/// `complete_remove_obj`: unaccount + remove one entry named in `remove_objs`.
fn complete_remove_obj<C: ClsCtx>(c: &mut C, h: &mut DirHeader, key: &ObjKey) -> Result<(), Errno> {
    let (idx, r) = read_key_entry(c, key, false);
    let e = r?;
    unaccount(h, &e);
    remove_entry(c, h, &idx, key)
}

/// `bucket_complete_op` (RW): second half of a PUT/DELETE; accounts, clears the pending tag and
/// rewrites the header (ver += 1).
pub fn complete_op<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let mut op: ObjCompleteOp = dec_op(input)?;
    let mut h = read_header(c).map_err(|_| EINVAL)?; // any header read error -> EINVAL (bug-compat)
    guard(c, &h, ERR_BUSY_RESHARDING)?;

    let (idx, r) = read_key_entry(c, &op.key, false);
    let (mut entry, ondisk) = match r {
        Ok(e) => (e, true),
        Err(ENOENT) => (
            DirEntry {
                key: op.key.clone(),
                ver: op.ver,
                meta: op.meta.clone(),
                locator: op.locator.clone(),
                ..Default::default()
            },
            false,
        ),
        Err(e) => return Err(e),
    };
    entry.index_ver = h.ver;
    entry.flags &= flag::VER; // reset: the entry may previously have been a delete marker

    if !op.op_tag.is_empty() && !entry.pending_erase(&op.op_tag) {
        return Err(EINVAL);
    }
    if !op.op_tag.is_empty() && op.op == op::CANCEL {
        // tagged cancel: nothing else to decide
    } else if op.ver.pool == entry.ver.pool && op.ver.epoch != 0 && op.ver.epoch <= entry.ver.epoch
    {
        op.op = op::CANCEL; // old epoch, skip
    }
    let default_log = op.log_op && !h.syncstopped;
    let mut log_op = default_log;
    entry.ver = op.ver;

    if op.op == op::CANCEL {
        log_op = false;
        if !op.op_tag.is_empty() {
            if !entry.exists && entry.pending.is_empty() {
                remove_entry(c, &mut h, &idx, &entry.key)?; // last tag gone, never completed: drop
            } else {
                write_entry(c, &mut h, &idx, &entry)?; // persist the removed pending tag
            }
        }
    } else if op.op == op::DEL {
        unaccount(&mut h, &entry);
        entry.meta = op.meta.clone();
        if !ondisk {
            log_op = false; // nothing to erase
        } else if entry.pending.is_empty() {
            remove_entry(c, &mut h, &idx, &entry.key)?;
        } else {
            entry.exists = false;
            write_entry(c, &mut h, &idx, &entry)?;
        }
    } else if op.op == op::ADD {
        unaccount(&mut h, &entry); // overwritten entry
        entry.meta = op.meta.clone();
        entry.key = op.key.clone();
        entry.exists = true;
        entry.tag = op.op_tag.clone();
        account_add(&mut h, &op.meta);
        write_entry(c, &mut h, &idx, &entry)?;
    }

    if log_op {
        let ts = entry.meta.mtime;
        let index_ver = h.ver;
        bilog_append(
            c,
            &mut h,
            BiLogEntry {
                object: op.key.name.clone(),
                instance: op.key.instance.clone(),
                timestamp: ts,
                op: op.op,
                ver: entry.ver,
                state: state::COMPLETE,
                index_ver,
                tag: op.op_tag.clone(),
                bilog_flags: op.bilog_flags,
                zones_trace: op.zones_trace.clone(),
                ..Default::default()
            },
        )?;
    }
    for k in &op.remove_objs {
        let _ = complete_remove_obj(c, &mut h, k); // best effort: a failing extra key is skipped
    }
    write_header(c, &mut h)?;
    Ok(Vec::new())
}

// ---------------------------------------------------------------- dir_suggest_changes

const SUGGEST_REMOVE: u8 = b'r';
const SUGGEST_UPDATE: u8 = b'u';
const SUGGEST_LOG_OP: u8 = 0x80;

fn utime_ns(t: UTime) -> u128 {
    t.sec as u128 * 1_000_000_000 + t.nsec as u128
}

/// `dir_suggest_changes` (RW): repair suggestions from listing; input = records until the end:
/// u8 op (+0x80 = log), dir_entry.
pub fn dir_suggest_changes<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let mut h = read_header(c)?;
    guard(c, &h, ERR_BUSY_RESHARDING)?;
    let cfg = c.config().rgw_pending_bucket_index_op_expiration;
    let timeout_s = if h.tag_timeout != 0 {
        h.tag_timeout
    } else if cfg != 0 {
        cfg
    } else {
        DEFAULT_TAG_TIMEOUT
    };
    let timeout_ns = timeout_s as u128 * 1_000_000_000;
    let now = c.now();
    let mut header_changed = false;
    let mut d = Decoder::new(input);
    while !d.is_empty() {
        let opb = d.u8().inval()?;
        let mut change = DirEntry::decode(&mut d).inval()?;
        let log_op = opb & SUGGEST_LOG_OP != 0;
        let opc = opb & 0x7f;
        let key = keys::obj_index_key(&change.key);
        let disk_bytes = match c.omap_get_val(&key) {
            Ok(b) => b,
            Err(ENOENT) => continue,
            Err(_) => return Err(EINVAL),
        };
        let mut disk = DirEntry::default();
        if !disk_bytes.is_empty() {
            disk = DirEntry::decode(&mut Decoder::new(&disk_bytes)).inval()?;
            // drop (in memory) pending ops whose tag timeout expired
            disk.pending
                .retain(|(_, p)| utime_ns(now) <= utime_ns(p.timestamp) + timeout_ns);
        }
        if change.index_ver < disk.index_ver {
            continue; // a pending op completed since the suggestion was made
        }
        if !disk.pending.is_empty() {
            continue;
        }
        if disk.exists {
            let s = h.stats.entry(disk.meta.category).or_default();
            s.num_entries = s.num_entries.wrapping_sub(1);
            s.total_size = s.total_size.wrapping_sub(disk.meta.accounted_size);
            s.total_size_rounded = s
                .total_size_rounded
                .wrapping_sub(round4096(disk.meta.accounted_size));
            s.actual_size = s.actual_size.wrapping_sub(disk.meta.size);
            header_changed = true;
        }
        h.stats.entry(change.meta.category).or_default(); // indexing creates the slot
        match opc {
            SUGGEST_REMOVE => {
                remove_entry(c, &mut h, &key, &change.key)?;
                if log_op && disk.exists && !h.syncstopped {
                    let index_ver = h.ver;
                    bilog_append(
                        c,
                        &mut h,
                        BiLogEntry {
                            object: disk.key.name.clone(),
                            instance: disk.key.instance.clone(),
                            timestamp: disk.meta.mtime,
                            op: op::DEL,
                            tag: disk.tag.clone(),
                            ver: disk.ver,
                            state: state::COMPLETE,
                            index_ver,
                            ..Default::default()
                        },
                    )?;
                }
            }
            SUGGEST_UPDATE => {
                account_add(&mut h, &change.meta);
                header_changed = true;
                change.index_ver = h.ver;
                write_entry(c, &mut h, &key, &change)?;
                if log_op && !h.syncstopped {
                    let index_ver = h.ver;
                    bilog_append(
                        c,
                        &mut h,
                        BiLogEntry {
                            object: change.key.name.clone(),
                            instance: change.key.instance.clone(),
                            timestamp: change.meta.mtime,
                            op: op::ADD,
                            tag: change.tag.clone(),
                            ver: change.ver,
                            state: state::COMPLETE,
                            index_ver,
                            ..Default::default()
                        },
                    )?;
                }
            }
            _ => {}
        }
    }
    if header_changed {
        write_header(c, &mut h)?;
    }
    Ok(Vec::new())
}

// ---------------------------------------------------------------- check / rebuild

/// Scan entries `[start_after, ...)` in pages; `stop` ends a region (first key for which it
/// returns true), `f` sees every other (key, value).
fn scan<C: ClsCtx>(
    c: &mut C,
    start_after: Vec<u8>,
    prefix: &[u8],
    stop: impl Fn(&[u8]) -> bool,
    mut f: impl FnMut(&[u8], &[u8]) -> Result<(), Errno>,
) -> Result<(), Errno> {
    omap_scan(c, &start_after, prefix, u64::MAX, |_, k, v| {
        if stop(&k) {
            return Ok(Break(()));
        }
        f(&k, &v)?;
        Ok(Continue(()))
    })?;
    Ok(())
}

fn calc_header<C: ClsCtx>(c: &mut C, existing: &DirHeader) -> Result<DirHeader, Errno> {
    let mut calc = DirHeader {
        tag_timeout: existing.tag_timeout,
        ver: existing.ver,
        syncstopped: existing.syncstopped,
        ..Default::default()
    };
    // plain entries: low region, then the region above the special area
    let mut count = |v: &[u8], plain: bool| -> Result<(), Errno> {
        let e: DirEntry = dec_stored(v)?;
        if e.exists && (!plain || e.flags == 0) {
            account_add(&mut calc, &e.meta);
        }
        Ok(())
    };
    scan(
        c,
        Vec::new(),
        b"",
        |k| k.first().is_some_and(|b| *b >= keys::BI_PREFIX),
        |_, v| count(v, true),
    )?;
    scan(c, keys::END.to_vec(), b"", |_| false, |_, v| count(v, true))?;
    // instance entries
    scan(
        c,
        keys::INSTANCE.to_vec(),
        keys::INSTANCE,
        |k| !starts_with(k, keys::INSTANCE),
        |_, v| count(v, false),
    )?;
    Ok(calc)
}

pub fn check_index<C: ClsCtx>(c: &mut C, _input: &[u8]) -> R {
    let existing = read_header(c)?;
    let calculated = calc_header(c, &existing)?;
    enc(&CheckIndexRet {
        existing_header: existing,
        calculated_header: calculated,
    })
}

pub fn rebuild_index<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Result<(), Errno> {
    let existing = read_header(c)?;
    guard(c, &existing, ERR_BUSY_RESHARDING)?;
    let mut calc = calc_header(c, &existing)?;
    write_header(c, &mut calc)?;
    Ok(())
}
