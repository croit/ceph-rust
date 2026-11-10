// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw`, versioned objects (spec/cls_rgw.md s6): `bucket_link_olh`, `bucket_unlink_instance`,
//! `bucket_read_olh_log`, `bucket_trim_olh_log`, `bucket_clear_olh`.
//!
//! Per name N the index holds: a plain VER_MARKER placeholder at `N`, per-instance DATA entries in
//! the special area (`80 "1000_" N 00 i <inst>`; null delete markers get a `00 d` suffix), a LIST
//! copy per instance next to `N` (newest first) and the OLH entry (`80 "1001_" N`). All handlers
//! work on in-memory copies and write them back; reads see message-start state (cls.md s4), so a
//! handler never re-reads what it wrote.

use super::index::{
    ERR_BUSY_RESHARDING, bilog_append, guard, read_header, read_key_entry, read_omap, remove_entry,
    write_entry, write_header,
};
use super::keys;
use super::types::*;
use crate::ctx::ClsCtx;
use crate::errno::*;
use crate::registry::Reply;
use denc::types::UTime;

fn ns(t: UTime) -> u64 {
    (t.sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(t.nsec as u64)
}

/// Header write that classic does when no bilog entry is appended: only while IN_LOGRECORD (the
/// reshard-log counter lives in the header); otherwise the header is left alone (no ver bump).
fn write_header_while_logrecord<C: ClsCtx>(c: &mut C, h: &mut DirHeader) -> Result<(), Errno> {
    if h.new_instance.in_logrecord() {
        write_header(c, h)
    } else {
        Ok(())
    }
}

/// `BIVerObjEntry`: one object instance (data entry + list entry).
struct VerObj {
    key: ObjKey,
    /// Index key of the data entry as last read/written (set even when the read failed).
    idx: Vec<u8>,
    e: DirEntry,
    initialized: bool,
}
impl VerObj {
    fn new(key: ObjKey) -> Self {
        VerObj {
            key,
            idx: Vec::new(),
            e: DirEntry::default(),
            initialized: false,
        }
    }

    /// `init(check_delete_marker)`: resolves a plain VER_MARKER to the instance entry; a null
    /// instance may be a delete marker (separate `00 d` key) when `check_dm`.
    fn init<C: ClsCtx>(&mut self, c: &mut C, check_dm: bool) -> Result<(), Errno> {
        let (idx, r) = read_key_entry(c, &self.key, check_dm && self.key.instance.is_empty());
        self.idx = idx;
        self.e = r?;
        self.initialized = true;
        Ok(())
    }

    fn init_as_delete_marker(&mut self, meta: &DirEntryMeta) {
        self.e.key = self.key.clone();
        self.e.flags = flag::DELETE_MARKER;
        self.e.meta = meta.clone();
        self.e.tag = "delete-marker".into();
        self.initialized = true;
    }

    fn unlink_list_entry<C: ClsCtx>(&self, c: &mut C, h: &mut DirHeader) -> Result<(), Errno> {
        let idx = keys::list_key(&self.e);
        remove_entry(c, h, &idx, &self.e.key)
    }

    fn unlink<C: ClsCtx>(&self, c: &mut C, h: &mut DirHeader, key: &ObjKey) -> Result<(), Errno> {
        remove_entry(c, h, &self.idx, key)
    }

    fn write_entries<C: ClsCtx>(
        &mut self,
        c: &mut C,
        h: &mut DirHeader,
        set: u16,
        reset: u16,
    ) -> Result<(), Errno> {
        if !self.initialized {
            self.init(c, true)?;
        }
        self.e.flags = (self.e.flags & !reset) | set;
        let special_dm = self.e.is_delete_marker() && self.e.key.instance.is_empty();
        self.idx = keys::instance_key(&self.key, special_dm);
        write_obj_entries(c, h, &self.e, &self.idx)
    }

    /// Store the instance as version `epoch` (flags VER [| CURRENT]); a previous list entry (old
    /// versioned_epoch) is removed first.
    fn write<C: ClsCtx>(
        &mut self,
        c: &mut C,
        h: &mut DirHeader,
        epoch: u64,
        current: bool,
    ) -> Result<(), Errno> {
        if self.e.versioned_epoch > 0 {
            self.unlink_list_entry(c, h)?;
        }
        let mut flags = flag::VER;
        if current {
            flags |= flag::CURRENT;
        }
        self.e.versioned_epoch = epoch;
        self.write_entries(c, h, flags, 0)
    }

    fn demote_current<C: ClsCtx>(&mut self, c: &mut C, h: &mut DirHeader) -> Result<(), Errno> {
        self.write_entries(c, h, 0, flag::CURRENT)
    }

    /// Next older version of the same name (first list key after this entry's list key).
    fn find_next_key<C: ClsCtx>(&self, c: &mut C) -> Result<Option<ObjKey>, Errno> {
        let list_idx = keys::list_key(&self.e);
        let (m, _) = c.omap_get_vals(&list_idx, &self.key.name, 1)?;
        let Some((_, v)) = m.iter().next_back() else {
            return Ok(None);
        };
        let next: DirEntry = dec_op(v).map_err(|_| EIO)?;
        Ok((next.key.name == self.key.name).then_some(next.key))
    }
}

/// Instance data entry (+ list entry when the keys differ; they always do for real instances).
fn write_obj_entries<C: ClsCtx>(
    c: &mut C,
    h: &mut DirHeader,
    e: &DirEntry,
    instance_idx: &[u8],
) -> Result<(), Errno> {
    write_entry(c, h, instance_idx, e)?;
    let list_idx = keys::list_key(e);
    if instance_idx != list_idx.as_slice() {
        write_entry(c, h, &list_idx, e)?;
    }
    Ok(())
}

/// `BIOLHEntry`.
struct Olh {
    idx: Vec<u8>,
    e: OlhEntry,
}
impl Olh {
    fn new(key: &ObjKey) -> Self {
        Olh {
            idx: keys::olh_key(key),
            e: OlhEntry::default(),
        }
    }
    /// Read; absent = default entry (`found` false). Other errors returned.
    fn init<C: ClsCtx>(&mut self, c: &mut C) -> Result<bool, Errno> {
        match read_omap::<C, OlhEntry>(c, &self.idx) {
            Ok(e) => {
                self.e = e;
                Ok(true)
            }
            Err(ENOENT) => Ok(false),
            Err(e) => Err(e),
        }
    }
    /// `start_modify`: false = the candidate epoch is older than the olh's (stale).
    fn start_modify(&mut self, candidate: u64, replace: bool) -> bool {
        if candidate < self.e.epoch {
            return false;
        }
        if replace {
            self.e.epoch = candidate;
        }
        true
    }
    fn update_log(&mut self, op: u8, tag: &[u8], key: &ObjKey, dm: bool, epoch: u64) {
        let epoch = if epoch == 0 { self.e.epoch } else { epoch };
        self.e
            .pending_log
            .entry(epoch)
            .or_default()
            .push(OlhLogEntry {
                epoch,
                op,
                op_tag: tag.to_owned(),
                key: key.clone(),
                delete_marker: dm,
            });
    }
    fn write<C: ClsCtx>(&self, c: &mut C, h: &mut DirHeader) -> Result<(), Errno> {
        write_entry(c, h, &self.idx, &self.e)
    }
}

/// Placeholder at the plain key of a versioned name.
fn write_version_marker<C: ClsCtx>(
    c: &mut C,
    h: &mut DirHeader,
    key: &ObjKey,
) -> Result<(), Errno> {
    let e = DirEntry {
        key: key.clone(),
        flags: flag::VER_MARKER,
        ..Default::default()
    };
    write_entry(c, h, &key.name, &e)
}

/// A pre-versioning plain object becomes the null-instance version; always (re)writes the marker.
/// `versioned_epoch` is replaced by the entry's mtime (ns) when a plain object existed.
fn convert_plain_entry_to_versioned<C: ClsCtx>(
    c: &mut C,
    h: &mut DirHeader,
    key: &ObjKey,
    demote_current: bool,
    instance_only: bool,
    versioned_epoch: &mut u64,
) -> Result<(), Errno> {
    if !key.instance.is_empty() {
        return Err(EINVAL);
    }
    let (_, r) = read_key_entry(c, key, false);
    match r {
        Err(ENOENT) => {}
        Err(e) => return Err(e),
        Ok(mut entry) => {
            *versioned_epoch = ns(entry.meta.mtime);
            entry.versioned_epoch = *versioned_epoch;
            entry.flags |= flag::VER;
            if demote_current {
                entry.flags &= !flag::CURRENT;
            }
            let new_idx = keys::instance_key(key, false);
            if instance_only {
                write_entry(c, h, &new_idx, &entry)?;
            } else {
                write_obj_entries(c, h, &entry, &new_idx)?;
            }
        }
    }
    write_version_marker(c, h, key)
}

fn name_only(key: &ObjKey) -> ObjKey {
    ObjKey {
        name: key.name.clone(),
        instance: Vec::new(),
    }
}

fn finish<C: ClsCtx>(
    c: &mut C,
    h: &mut DirHeader,
    log_op: bool,
    e: BiLogEntry,
) -> Result<(), Errno> {
    if !log_op || h.syncstopped {
        return write_header_while_logrecord(c, h);
    }
    bilog_append(c, h, e)?;
    write_header(c, h)
}

fn reply(r: Result<(), Errno>, out: Vec<u8>) -> Reply {
    Reply {
        ret: r.err().unwrap_or(0),
        out,
    }
}

/// `bucket_link_olh` (RW). No output.
pub fn link_olh<C: ClsCtx>(c: &mut C, input: &[u8]) -> Reply {
    reply(link_olh_inner(c, input), Vec::new())
}

fn link_olh_inner<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: LinkOlhOp = dec_op(input)?;
    let mut h = read_header(c)?;
    guard(c, &h, ERR_BUSY_RESHARDING)?;

    let mut obj = VerObj::new(op.key.clone());
    let r = obj.init(c, op.delete_marker);
    // `existed`: the instance was specified and found (a delete of an unknown instance mints one)
    let mut existed = r.is_ok();
    match r {
        Ok(()) => {}
        Err(ENOENT) if op.delete_marker => {}
        Err(e) => return Err(e),
    }
    let mut olh = Olh::new(&op.key);
    let olh_found = olh.init(c)?;
    let now_epoch = ns(c.now());

    if existed && op.unmod_since != UTime::default() {
        let mut mtime = obj.e.meta.mtime;
        let mut unmod = op.unmod_since;
        if !op.high_precision_time {
            mtime.nsec = 0;
            unmod.nsec = 0;
        }
        if mtime >= unmod {
            olh.update_log(olh_op::STALE, &op.op_tag, &op.key, false, now_epoch);
            olh.write(c, &mut h)?;
            return Ok(()); // no header write, no bilog
        }
    }

    let removing;
    if op.key.instance.is_empty() {
        // null instance: data and delete marker live under separate keys; drop the other kind
        let mut other = VerObj::new(op.key.clone());
        let r = other.init(c, !op.delete_marker);
        existed = r.is_ok() && !other.e.is_delete_marker();
        if r.is_ok() && other.e.is_delete_marker() != op.delete_marker {
            other.unlink_list_entry(c, &mut h)?;
        }
        removing = existed && op.delete_marker;
        if !removing {
            other.unlink(c, &mut h, &op.key)?;
        }
    } else {
        removing = existed && !obj.e.is_delete_marker() && op.delete_marker;
    }

    if op.delete_marker {
        obj.init_as_delete_marker(&op.meta);
    }

    let prev_epoch = olh.e.epoch;
    // a non-zero op.olh_epoch comes from multisite sync
    let candidate = if op.olh_epoch != 0 {
        op.olh_epoch
    } else {
        now_epoch
    };

    if olh.start_modify(candidate, true) {
        // newer epoch, or same epoch and the instance sorts after the current head: new head
        let promote = olh.e.epoch > prev_epoch
            || (olh.e.epoch == prev_epoch && olh.e.key.instance >= op.key.instance);
        if olh_found {
            if op.olh_tag != olh.e.tag {
                if !olh.e.pending_removal {
                    return Err(ECANCELED);
                }
                olh.e.tag = op.olh_tag.clone(); // pending removal: a new olh generation
            }
            if promote && olh.e.exists && olh.e.key != op.key {
                let mut old = VerObj::new(olh.e.key.clone());
                old.demote_current(c, &mut h)?;
            }
            olh.e.pending_removal = false;
        } else {
            let instance_only = op.key.instance.is_empty() && op.delete_marker;
            let mut versioned_epoch = candidate;
            convert_plain_entry_to_versioned(
                c,
                &mut h,
                &name_only(&op.key),
                promote,
                instance_only,
                &mut versioned_epoch,
            )?;
            olh.e.tag = op.olh_tag.clone();
            if op.key.instance.is_empty() {
                obj.e.versioned_epoch = versioned_epoch;
            }
        }
        olh.update_log(
            olh_op::LINK_OLH,
            &op.op_tag,
            &op.key,
            op.delete_marker,
            now_epoch,
        );
        if removing {
            olh.update_log(
                olh_op::REMOVE_INSTANCE,
                &op.op_tag,
                &op.key,
                false,
                now_epoch,
            );
        }
        if promote {
            olh.e.key = op.key.clone();
            olh.e.delete_marker = op.delete_marker;
        }
        olh.e.exists = true;
        let epoch = olh.e.epoch;
        obj.write(c, &mut h, epoch, promote)?;
        olh.write(c, &mut h)?;
    } else {
        // stale: the version is stored but never becomes head
        obj.write(c, &mut h, candidate, false)?;
        if removing {
            olh.update_log(
                olh_op::REMOVE_INSTANCE,
                &op.op_tag,
                &op.key,
                false,
                now_epoch,
            );
        } else {
            olh.update_log(olh_op::STALE, &op.op_tag, &op.key, false, now_epoch);
        }
        olh.write(c, &mut h)?;
    }

    let (owner, owner_display_name) = if op.delete_marker {
        (
            obj.e.meta.owner.clone(),
            obj.e.meta.owner_display_name.clone(),
        )
    } else {
        Default::default()
    };
    let index_ver = h.ver;
    let entry = BiLogEntry {
        object: op.key.name.clone(),
        instance: op.key.instance.clone(),
        timestamp: obj.e.meta.mtime,
        op: if op.delete_marker {
            op::LINK_OLH_DM
        } else {
            op::LINK_OLH
        },
        ver: EntryVer {
            pool: -1,
            epoch: candidate,
        },
        state: state::COMPLETE,
        index_ver,
        tag: op.op_tag.clone(),
        bilog_flags: op.bilog_flags | BILOG_VERSIONED_OP,
        owner,
        owner_display_name,
        zones_trace: op.zones_trace.clone(),
        ..Default::default()
    };
    finish(c, &mut h, op.log_op, entry)
}

/// `bucket_unlink_instance` (RW): permanent delete of one version. No output.
/// `olh_tag` of the request is decoded but NOT checked here (classic).
pub fn unlink_instance<C: ClsCtx>(c: &mut C, input: &[u8]) -> Reply {
    reply(unlink_instance_inner(c, input), Vec::new())
}

fn unlink_instance_inner<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: UnlinkInstanceOp = dec_op(input)?;
    let dest_key = op.key.clone();
    let mut h = read_header(c)?;
    guard(c, &h, ERR_BUSY_RESHARDING)?;

    let mut obj = VerObj::new(dest_key.clone());
    let mut olh = Olh::new(&dest_key);
    obj.init(c, true)?; // ENOENT = the instance is gone
    let olh_found = olh.init(c)?;

    let now_epoch = ns(c.now());
    let candidate = if op.olh_epoch != 0 {
        op.olh_epoch
    } else {
        now_epoch
    };

    if !olh_found {
        let mut versioned_epoch = candidate.wrapping_sub(1);
        convert_plain_entry_to_versioned(
            c,
            &mut h,
            &name_only(&dest_key),
            true,
            false,
            &mut versioned_epoch,
        )?;
        olh.e.key = dest_key.clone();
        olh.e.delete_marker = false;
        olh.e.tag = op.olh_tag.clone();
        obj.e.versioned_epoch = versioned_epoch;
    }

    if olh.start_modify(candidate, false) {
        if olh.e.key == dest_key {
            // removing the current head: promote the next older version, or empty the olh
            match obj.find_next_key(c)? {
                Some(next_key) => {
                    let mut next = VerObj::new(next_key.clone());
                    next.init(c, true)?;
                    let next_epoch = next.e.versioned_epoch;
                    next.write(c, &mut h, next_epoch, true)?;
                    let dm = next.e.is_delete_marker();
                    olh.e.key = next_key.clone();
                    olh.e.delete_marker = dm;
                    olh.update_log(olh_op::LINK_OLH, &op.op_tag, &next_key, dm, now_epoch);
                    olh.e.epoch = next_epoch;
                }
                None => {
                    // keep the name: it drives hash placement when the key is resharded
                    let next_key = name_only(&dest_key);
                    olh.e.key = next_key.clone();
                    olh.e.delete_marker = false;
                    if olh.e.epoch == 0 {
                        olh.e.epoch = candidate;
                    }
                    olh.update_log(olh_op::UNLINK_OLH, &op.op_tag, &next_key, false, now_epoch);
                    olh.e.exists = false;
                    olh.e.pending_removal = true;
                }
            }
        }
        if !obj.e.is_delete_marker() {
            olh.update_log(
                olh_op::REMOVE_INSTANCE,
                &op.op_tag,
                &op.key,
                false,
                now_epoch,
            );
        } else {
            olh.update_log(olh_op::STALE, &op.op_tag, &op.key, true, now_epoch);
            // a delete marker has no data object: its instance entry is ours to remove
            obj.unlink(c, &mut h, &op.key)?;
        }
        obj.unlink_list_entry(c, &mut h)?;
    } else {
        obj.unlink_list_entry(c, &mut h)?;
        if obj.e.is_delete_marker() {
            olh.update_log(olh_op::STALE, &op.op_tag, &op.key, true, now_epoch);
            return olh.write(c, &mut h); // no bilog, no header
        }
        olh.update_log(
            olh_op::REMOVE_INSTANCE,
            &op.op_tag,
            &op.key,
            false,
            now_epoch,
        );
    }
    olh.write(c, &mut h)?;

    let index_ver = h.ver;
    let entry = BiLogEntry {
        object: op.key.name.clone(),
        instance: op.key.instance.clone(),
        timestamp: obj.e.meta.mtime,
        op: op::UNLINK_INSTANCE,
        ver: EntryVer {
            pool: -1,
            epoch: candidate,
        },
        state: state::COMPLETE,
        index_ver,
        tag: op.op_tag.clone(),
        bilog_flags: op.bilog_flags | BILOG_VERSIONED_OP,
        zones_trace: op.zones_trace.clone(),
        ..Default::default()
    };
    finish(c, &mut h, op.log_op, entry)
}

/// Max epochs (map keys, not vector entries) returned by one `bucket_read_olh_log`.
const MAX_OLH_LOG_EPOCHS: usize = 1000;

fn read_olh_checked<C: ClsCtx>(c: &mut C, key: &ObjKey, tag: &[u8]) -> Result<OlhEntry, Errno> {
    if !key.instance.is_empty() {
        return Err(EINVAL);
    }
    let e = match read_omap::<C, OlhEntry>(c, &keys::olh_key(key)) {
        Ok(e) => e,
        Err(ENOENT) => OlhEntry::default(),
        Err(e) => return Err(e),
    };
    if e.tag != tag {
        return Err(ECANCELED);
    }
    Ok(e)
}

/// `bucket_read_olh_log` (RD): pending log entries with epoch > ver_marker, at most 1000 epochs.
pub fn read_olh_log<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ReadOlhLogOp = dec_op(input)?;
    let olh = read_olh_checked(c, &op.olh, &op.olh_tag)?;
    let mut ret = ReadOlhLogRet::default();
    let mut it = olh.pending_log.range((
        std::ops::Bound::Excluded(op.ver_marker),
        std::ops::Bound::Unbounded,
    ));
    for (k, v) in it.by_ref().take(MAX_OLH_LOG_EPOCHS) {
        ret.log.insert(*k, v.clone());
    }
    ret.is_truncated = it.next().is_some();
    if !op.get_stales {
        // truncation was counted before filtering
        ret.log.retain(|_, v| {
            v.retain(|e| e.op != olh_op::STALE);
            !v.is_empty()
        });
    }
    enc(&ret)
}

/// `bucket_trim_olh_log` (RW): drop pending epochs <= ver. The header is not rewritten. An absent
/// olh with an empty tag is (re)written as an empty entry (classic).
pub fn trim_olh_log<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: TrimOlhLogOp = dec_op(input)?;
    let mut olh = read_olh_checked(c, &op.olh, &op.olh_tag)?;
    olh.pending_log = olh.pending_log.split_off(&op.ver.wrapping_add(1));
    if op.ver == u64::MAX {
        olh.pending_log.clear();
    }
    let mut h = read_header(c)?;
    guard(c, &h, ERR_BUSY_RESHARDING)?;
    write_entry(c, &mut h, &keys::olh_key(&op.olh), &olh)?;
    Ok(())
}

/// `bucket_clear_olh` (RW): remove the olh entry and the VER_MARKER placeholder (header untouched).
pub fn clear_olh<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ClearOlhOp = dec_op(input)?;
    if !op.key.instance.is_empty() {
        return Err(EINVAL);
    }
    let mut h = read_header(c)?;
    guard(c, &h, ERR_BUSY_RESHARDING)?;
    let olh = read_olh_checked(c, &op.key, &op.olh_tag)?;
    remove_entry(c, &mut h, &keys::olh_key(&op.key), &olh.key)?;
    let plain: DirEntry = match read_omap(c, &op.key.name) {
        Ok(e) => e,
        Err(ENOENT) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    if plain.flags & flag::VER_MARKER == 0 {
        return Ok(Vec::new());
    }
    remove_entry(c, &mut h, &op.key.name, &plain.key)?;
    Ok(Vec::new())
}
