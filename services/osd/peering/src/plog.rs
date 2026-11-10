// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG log with indices, the missing set with change tracking, and the divergence algorithms
//! (spec pglog.md 4.1, 6, 7): append, trim, rewind_divergent_log, merge_log, proc_replica_log.
//! All mutations of durable state append matching [`StoreOp`]s to a caller-provided list.

use crate::store::StoreOp;
use crate::types::Config;
use denc::types::{Eversion, Hobject, OsdReqId};
use pgwire::{LogDup, LogEntry, LogOp, MissingItem, PgInfo, PgLog, PgMissing};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

// ---- missing set -----------------------------------------------------------------------------

/// `pg_missing_t` plus an index on `need` (O(log n) `oldest_need`) and change tracking so the
/// persistence layer writes deltas.
#[derive(Debug, Clone, Default)]
pub struct MissingSet {
    m: PgMissing,
    need_idx: BTreeMap<Eversion, u32>,
    dirty: BTreeSet<Hobject>,
    cleared: bool,
    /// Bumped by every content change; with `id` a cheap "did anything change" probe for views derived from the set
    /// ([`crate::Pg::unfound_resume_due`]).
    ver: u64,
    id: SetId,
}

/// Identity of one `MissingSet` value: every new set, default or clone gets a fresh one, so equal `(id, ver)` stamps
/// never come from two sets with different content (a replaced set can match the old one's change count).
#[derive(Debug)]
struct SetId(u64);

impl Default for SetId {
    fn default() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        SetId(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl Clone for SetId {
    fn clone(&self) -> Self {
        SetId::default()
    }
}

impl MissingSet {
    pub fn new(may_include_deletes: bool) -> Self {
        MissingSet {
            m: PgMissing {
                missing: BTreeMap::new(),
                may_include_deletes,
            },
            ..Default::default()
        }
    }
    pub fn from_wire(m: PgMissing) -> Self {
        let mut s = MissingSet {
            m,
            ..Default::default()
        };
        for it in s.m.missing.values() {
            *s.need_idx.entry(it.need).or_default() += 1;
        }
        s
    }
    pub fn wire(&self) -> &PgMissing {
        &self.m
    }
    pub fn to_wire(&self) -> PgMissing {
        self.m.clone()
    }
    pub fn may_include_deletes(&self) -> bool {
        self.m.may_include_deletes
    }
    pub fn len(&self) -> usize {
        self.m.len()
    }
    pub fn is_empty(&self) -> bool {
        self.m.is_empty()
    }
    pub fn get(&self, oid: &Hobject) -> Option<&MissingItem> {
        self.m.missing.get(oid)
    }
    pub fn contains(&self, oid: &Hobject) -> bool {
        self.m.missing.contains_key(oid)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Hobject, &MissingItem)> {
        self.m.missing.iter()
    }
    pub fn oldest_need(&self) -> Option<Eversion> {
        self.need_idx.keys().next().copied()
    }

    fn track<R>(&mut self, oid: &Hobject, f: impl FnOnce(&mut PgMissing) -> R) -> R {
        let before = self.m.missing.get(oid).map(|i| i.need);
        let r = f(&mut self.m);
        self.ver += 1;
        let after = self.m.missing.get(oid).map(|i| i.need);
        if before != after {
            if let Some(b) = before
                && let Some(c) = self.need_idx.get_mut(&b)
            {
                *c -= 1;
                if *c == 0 {
                    self.need_idx.remove(&b);
                }
            }
            if let Some(a) = after {
                *self.need_idx.entry(a).or_default() += 1;
            }
        }
        self.dirty.insert(oid.clone());
        r
    }
    pub fn add(&mut self, oid: Hobject, need: Eversion, have: Eversion, is_delete: bool) {
        let o = oid.clone();
        self.track(&o, |m| m.add(oid, need, have, is_delete));
    }
    pub fn revise_need(&mut self, oid: Hobject, need: Eversion, is_delete: bool) {
        let o = oid.clone();
        self.track(&o, |m| m.revise_need(oid, need, is_delete));
    }
    pub fn revise_have(&mut self, oid: &Hobject, have: Eversion) {
        self.track(oid, |m| m.revise_have(oid, have));
    }
    /// Object recovered at `v`.
    pub fn got(&mut self, oid: &Hobject, v: Eversion) -> bool {
        self.track(oid, |m| m.got(oid, v))
    }
    pub fn rm(&mut self, oid: &Hobject) {
        self.track(oid, |m| m.rm(oid));
    }
    /// Reset `have` to 0'0 and mark fully dirty (divergent case 1).
    pub fn forget_have(&mut self, oid: &Hobject) {
        self.track(oid, |m| {
            if let Some(it) = m.missing.get_mut(oid) {
                it.have = Eversion::default();
                it.clean_regions = pgwire::ObjectCleanRegions::fully_dirty();
            }
        });
    }
    pub fn add_next_event(&mut self, e: &LogEntry) {
        let o = e.soid.clone();
        self.track(&o, |m| m.add_next_event(e));
        if e.op.is_delete() && self.m.may_include_deletes {
            debug_assert!(
                self.m.missing.get(&e.soid).is_some_and(|i| i.is_delete()),
                "delete entry {} did not produce a delete item: {:?}",
                e.version,
                self.m.missing.get(&e.soid)
            );
        }
    }
    pub fn set_item(&mut self, oid: Hobject, item: MissingItem) {
        let o = oid.clone();
        self.track(&o, |m| {
            m.missing.insert(oid, item);
        });
    }
    pub fn clear(&mut self) {
        self.m.missing.clear();
        self.need_idx.clear();
        self.dirty.clear();
        self.cleared = true;
        self.ver += 1;
    }
    /// Content generation: changes whenever the set changes or is replaced by another set.
    pub fn stamp(&self) -> (u64, u64) {
        (self.id.0, self.ver)
    }
    /// Rewrite the whole persisted set with the next `take_ops` (clear + every item), e.g. after a split.
    pub fn rewrite_all(&mut self) {
        self.cleared = true;
        self.dirty = self.m.missing.keys().cloned().collect();
    }
    pub fn set_may_include_deletes(&mut self, v: bool) {
        if self.m.may_include_deletes != v {
            self.m.may_include_deletes = v;
            // persisted with the next full clear/replace; also rewrite everything
            self.cleared = true;
            self.dirty.extend(self.m.missing.keys().cloned());
        }
    }
    /// Persistence delta since the last call.
    pub fn take_ops(&mut self, out: &mut Vec<StoreOp>) {
        if self.cleared {
            self.cleared = false;
            out.push(StoreOp::MissingClear {
                may_include_deletes: self.m.may_include_deletes,
            });
        }
        if !self.dirty.is_empty() {
            let d: Vec<_> = std::mem::take(&mut self.dirty)
                .into_iter()
                .map(|k| {
                    let v = self.m.missing.get(&k).cloned();
                    (k, v)
                })
                .collect();
            out.push(StoreOp::Missing(d));
        }
    }
    pub fn is_dirty(&self) -> bool {
        self.cleared || !self.dirty.is_empty()
    }
}

// ---- indexed log -----------------------------------------------------------------------------

/// Request id -> (version, user_version, return code) of its last dup record, number of its records.
type DupIdx = HashMap<OsdReqId, ((Eversion, u64, i32), u32), foldhash::fast::RandomState>;

/// Result of [`IndexedLog::trim_ex`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trimmed {
    /// Version of the oldest dup record kept after the trim (`None`: no dup record is kept). Every older dup record is
    /// gone, so the store drops the persisted dups below it as one key range without reading them. A dropped and a
    /// kept record of the same version (extra request ids) both persist.
    pub dups_from: Option<Eversion>,
    /// The persisted dups cannot be derived from "trimmed entries at or above `dups_from`": a trimmed entry older than
    /// the dup window was not made a dup but lies above a kept (older) record, or a dropped and a kept record share a
    /// version. The PG then also sends the full dup list ([`crate::store::StoreOp::LogDups`]). Rare: only a trim far
    /// beyond the window, or extra request ids on the boundary entry.
    pub dups_rewrite: bool,
}

/// Object -> (version of its newest non-ERROR entry, that entry deletes it).
type Objects = HashMap<Hobject, (Eversion, bool), foldhash::fast::RandomState>;
/// Caller -> (version, user_version, return_code) of its newest indexed entry.
type Callers = HashMap<OsdReqId, (Eversion, u64, i32), foldhash::fast::RandomState>;

/// Index one log entry (newest non-ERROR entry of an object, newest indexed caller).
fn index_entry(
    objects: &mut Objects,
    callers: &mut Callers,
    extra_callers: &mut Callers,
    e: &LogEntry,
) {
    if e.object_is_indexed() {
        let v = (e.version, e.is_delete());
        match objects.get_mut(&e.soid) {
            Some(x) => *x = v,
            None => {
                objects.insert(e.soid.clone(), v);
            }
        }
    }
    if e.reqid_is_indexed() {
        callers.insert(e.reqid, (e.version, e.user_version, e.return_code));
    }
    for d in e.extra_dups() {
        extra_callers.insert(d.reqid, (d.version, d.user_version, d.return_code));
    }
}

/// The PG log window `(tail, head]` with object and caller indices.
#[derive(Debug, Clone, Default)]
pub struct IndexedLog {
    pub log: PgLog,
    objects: Objects,
    callers: Callers,
    /// Extra callers of copy-from / merged classic entries. Main request ids take precedence over extras.
    extra_callers: Callers,
    /// Last dup record (by position) of each request id and the number of records of that id (`log.dups` holds up to 3000
    /// records: the miss case of a dup lookup, i.e. every new client write, must not scan them; a merge can hold the same
    /// record twice). Exactly the answer of a backwards scan of `log.dups`. Kept in step by `trim` and `reindex_dups`
    /// (every other change of `log.dups`).
    dup_idx: DupIdx,
}

impl IndexedLog {
    pub fn new(log: PgLog) -> Self {
        let mut l = IndexedLog {
            log,
            ..Default::default()
        };
        l.reindex();
        l
    }
    pub fn head(&self) -> Eversion {
        self.log.head
    }
    pub fn tail(&self) -> Eversion {
        self.log.tail
    }
    pub fn len(&self) -> usize {
        self.log.log.len()
    }
    pub fn is_empty(&self) -> bool {
        self.log.log.is_empty()
    }
    pub fn entries(&self) -> &VecDeque<LogEntry> {
        &self.log.log
    }
    /// RAM estimate in bytes (operator `dump_mempools`): entries with their heap parts, dup records, and the two
    /// indexes (object -> version, caller -> result). Cheap on a data core: struct sizes x counts, the heap parts
    /// averaged over at most `SAMPLE` evenly spread entries / dups (a degraded PG holds up to 10000 entries).
    pub fn mem_bytes(&self) -> u64 {
        use std::mem::size_of;
        const SAMPLE: usize = 32;
        let name = |h: &Hobject| h.key.len() + h.oid.len() + h.nspace.len();
        let rets =
            |r: &[pgwire::LogOpReturnItem]| r.iter().map(|o| o.outdata.len() + 24).sum::<usize>();
        // sum of `f` over a sample, scaled to all of `v`
        fn scaled<'a, T: 'a>(
            v: impl ExactSizeIterator<Item = &'a T>,
            f: impl Fn(&T) -> usize,
        ) -> usize {
            let n = v.len();
            let step = n.div_ceil(SAMPLE).max(1);
            let (sum, k) = v.step_by(step).fold((0, 0), |(s, k), x| (s + f(x), k + 1));
            (sum * n).checked_div(k).unwrap_or(0)
        }
        let log = &self.log.log;
        let heap = scaled(log.iter(), |e| {
            name(&e.soid)
                + e.snaps.len()
                + e.mod_desc.bl.len()
                + e.extra_reqids.len() * size_of::<(OsdReqId, u64)>()
                + rets(&e.op_returns)
        });
        let names = scaled(log.iter(), |e| name(&e.soid));
        let avg_name = names.checked_div(log.len()).unwrap_or(0);
        let dup_heap = scaled(self.log.dups.iter(), |d| rets(&d.op_returns));
        let b = log.len() * size_of::<LogEntry>()
            + heap
            + self.log.dups.len() * size_of::<LogDup>()
            + dup_heap
            // index slots: BTree node share / hash slot on top of the key
            + self.objects.len() * (size_of::<Hobject>() + avg_name + size_of::<Eversion>() + 16)
            + (self.callers.len() + self.extra_callers.len()) * (size_of::<OsdReqId>() + 32 + 16)
            + self.dup_idx.len() * (size_of::<OsdReqId>() + 40 + 16);
        b as u64
    }
    pub fn reindex(&mut self) {
        self.reindex_dups();
        // the index maps move out: no per-entry clone of the log's heap parts
        let mut objects = std::mem::take(&mut self.objects);
        let mut callers = std::mem::take(&mut self.callers);
        let mut extra_callers = std::mem::take(&mut self.extra_callers);
        objects.clear();
        callers.clear();
        extra_callers.clear();
        for e in &self.log.log {
            index_entry(&mut objects, &mut callers, &mut extra_callers, e);
        }
        self.objects = objects;
        self.callers = callers;
        self.extra_callers = extra_callers;
    }
    /// Rebuild the dup index after `log.dups` was changed from outside (merge, replace).
    pub fn reindex_dups(&mut self) {
        self.dup_idx.clear();
        for d in &self.log.dups {
            Self::dup_add(&mut self.dup_idx, d);
        }
    }
    fn dup_add(ix: &mut DupIdx, d: &LogDup) {
        let s = ix
            .entry(d.reqid)
            .or_insert(((d.version, d.user_version, d.return_code), 0));
        *s = ((d.version, d.user_version, d.return_code), s.1 + 1);
    }
    /// Append an entry newer than head.
    pub fn append(&mut self, e: LogEntry) {
        debug_assert!(e.version > self.log.head);
        self.log.head = e.version;
        self.log.can_rollback_to = e.version;
        self.log.rollback_info_trimmed_to = e.version;
        index_entry(
            &mut self.objects,
            &mut self.callers,
            &mut self.extra_callers,
            &e,
        );
        self.log.log.push_back(e);
    }
    /// EC: append an entry newer than head and leave `can_rollback_to` / `rollback_info_trimmed_to` where they are
    /// (they advance only by roll-forward, adr 0040).
    pub fn append_keep(&mut self, e: LogEntry) {
        debug_assert!(e.version > self.log.head);
        self.log.head = e.version;
        index_entry(
            &mut self.objects,
            &mut self.callers,
            &mut self.extra_callers,
            &e,
        );
        self.log.log.push_back(e);
    }
    /// Newest non-ERROR entry version for an object in the log window.
    pub fn newest_for(&self, oid: &Hobject) -> Option<Eversion> {
        self.objects.get(oid).map(|x| x.0)
    }
    /// Version of the object as it exists now according to the log window: the newest non-ERROR
    /// entry's version, or `None` if the object is absent or was deleted by that entry.
    pub fn existing_version(&self, oid: &Hobject) -> Option<Eversion> {
        self.window_version(oid).flatten()
    }
    /// What the log window says about `oid` in one lookup: `None` = no entry in the window (ask the store), `Some(v)` =
    /// [`Self::existing_version`] (`Some(None)`: the newest entry deleted it).
    pub fn window_version(&self, oid: &Hobject) -> Option<Option<Eversion>> {
        let &(v, deleted) = self.objects.get(oid)?;
        debug_assert_eq!(
            self.log
                .log
                .binary_search_by(|e| e.version.cmp(&v))
                .ok()
                .map(|i| self.log.log[i].is_delete()),
            Some(deleted),
            "object index out of step with the log"
        );
        Some((!deleted).then_some(v))
    }
    /// Duplicate detection: version, user_version, return code of an earlier request.
    pub fn find_reqid(&self, r: &OsdReqId) -> Option<(Eversion, u64, i32)> {
        if let Some(x) = self.callers.get(r) {
            return Some(*x);
        }
        if let Some(x) = self.extra_callers.get(r) {
            return Some(*x);
        }
        let hit = self.dup_idx.get(r).map(|x| x.0);
        debug_assert_eq!(
            hit,
            self.log.dups.iter().rev().find(|d| d.reqid == *r).map(|d| (
                d.version,
                d.user_version,
                d.return_code
            )),
            "dup index out of step"
        );
        hit
    }
    /// RETURNVEC results of an earlier request (log entry, else dup record).
    pub fn find_op_returns(&self, r: &OsdReqId) -> Vec<pgwire::LogOpReturnItem> {
        if let Some(c) = self.callers.get(r) {
            return self
                .log
                .log
                .binary_search_by(|e| e.version.cmp(&c.0))
                .ok()
                .map(|i| self.log.log[i].op_returns.clone())
                .unwrap_or_default();
        }
        // Extra requests have their own result and user version, but no per-op return vector.
        if self.extra_callers.contains_key(r) {
            return Vec::new();
        }
        self.log
            .dups
            .iter()
            .rev()
            .find(|d| d.reqid == *r)
            .map(|d| d.op_returns.clone())
            .unwrap_or_default()
    }
    /// Number of entries with `version <= to`. Searched from the front: a trim takes a short, hot prefix of a log of
    /// thousands of entries (usually one per write), a binary search over the whole log touches a cold cache line per step.
    fn prefix_le(&self, to: Eversion) -> usize {
        let l = &self.log.log;
        let mut hi = 1usize;
        while hi <= l.len() && l[hi - 1].version <= to {
            hi <<= 1;
        }
        // l[..hi / 2] are all <= to, l[hi - 1] (if there) is not
        let (mut lo, mut hi) = (hi >> 1, hi.min(l.len()));
        while lo < hi {
            let m = (lo + hi) / 2;
            if l[m].version <= to {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        lo
    }
    /// Remove entries `<= to`, producing dup records (spec 6.3); drops the oldest dup records over the tracked count.
    pub fn trim(&mut self, to: Eversion, cfg: &Config) -> Trimmed {
        self.trim_ex(to, cfg)
    }

    /// [`Self::trim`]; the dup records are appended to `log.dups` in place (no intermediate list, one clone per record).
    pub fn trim_ex(&mut self, to: Eversion, cfg: &Config) -> Trimmed {
        if to <= self.log.tail {
            return Trimmed {
                dups_from: self.log.dups.front().map(|d| d.version),
                dups_rewrite: false,
            };
        }
        let head_v = self.log.head.version;
        let earliest = if head_v < cfg.log_dups_tracked {
            0
        } else {
            head_v.saturating_sub(cfg.log_dups_tracked.saturating_sub(1))
        };
        let n = self.prefix_le(to);
        let mut skipped = None;
        for e in self.log.log.range(..n) {
            if self.objects.get(&e.soid).is_some_and(|x| x.0 == e.version) {
                self.objects.remove(&e.soid);
            }
            if self.callers.get(&e.reqid).map(|c| c.0) == Some(e.version) {
                self.callers.remove(&e.reqid);
            }
            for (r, _) in &e.extra_reqids {
                if self.extra_callers.get(r).map(|c| c.0) == Some(e.version) {
                    self.extra_callers.remove(r);
                }
            }
            if e.version.version >= earliest {
                for d in e.dups() {
                    Self::dup_add(&mut self.dup_idx, &d);
                    self.log.dups.push_back(d);
                }
            } else {
                skipped = Some(e.version);
            }
        }
        self.log.log.drain(..n);
        self.log.tail = to;
        let over = self
            .log
            .dups
            .len()
            .saturating_sub(cfg.log_dups_tracked as usize);
        let drop = over.min(cfg.pg_log_trim_max as usize);
        // the oldest records go: the indexed (last) record of an id goes only with its last copy
        let mut last_dropped = None;
        for d in self.log.dups.drain(..drop) {
            if let Some(s) = self.dup_idx.get_mut(&d.reqid) {
                s.1 -= 1;
                if s.1 == 0 {
                    self.dup_idx.remove(&d.reqid);
                }
            }
            last_dropped = Some(d.version);
        }
        let dups_from = self.log.dups.front().map(|d| d.version);
        Trimmed {
            dups_from,
            dups_rewrite: dups_from
                .is_some_and(|f| skipped.is_some_and(|s| s >= f) || last_dropped == Some(f)),
        }
    }
    /// Entries to send after `since` (spec 6.6). The slice tail is accurate: the version of
    /// our newest entry <= `since` (our own tail if none), so a receiver whose entries above
    /// `since` differ from ours can detect the divergence. Same rule as `pgwire::PgLog::copy_after`.
    pub fn copy_after(&self, since: Eversion) -> PgLog {
        let idx = self.log.log.partition_point(|e| e.version <= since);
        let tail = if idx == 0 {
            self.log.tail
        } else {
            self.log.log[idx - 1].version
        };
        PgLog {
            head: self.log.head,
            tail,
            log: self.log.log.range(idx..).cloned().collect(),
            can_rollback_to: self.log.can_rollback_to,
            rollback_info_trimmed_to: self.log.rollback_info_trimmed_to,
            dups: self.log.dups.clone(),
        }
    }
    /// The last `max` entries (backfill slice, spec 6.6) with matching dups.
    pub fn copy_up_to(&self, max: usize, dups_tracked: u64) -> PgLog {
        let n = self.log.log.len();
        let skip = n.saturating_sub(max);
        let tail = if skip == 0 {
            self.log.tail
        } else {
            self.log.log[skip - 1].version
        };
        let mut dups = self.log.dups.clone();
        for e in self.log.log.range(..skip) {
            dups.extend(e.dups());
        }
        let min_v = self
            .log
            .head
            .version
            .saturating_sub(dups_tracked.saturating_sub(1));
        dups.retain(|d| d.version.version >= min_v);
        PgLog {
            head: self.log.head,
            tail,
            log: self.log.log.range(skip..).cloned().collect(),
            can_rollback_to: self.log.can_rollback_to,
            rollback_info_trimmed_to: self.log.rollback_info_trimmed_to,
            dups,
        }
    }
    /// The newest non-ERROR entry of an object in the log window.
    pub fn entry_for(&self, oid: &Hobject) -> Option<&LogEntry> {
        let v = self.objects.get(oid)?.0;
        let idx = self.log.log.binary_search_by(|e| e.version.cmp(&v)).ok()?;
        Some(&self.log.log[idx])
    }
    /// Remove and return entries with `version.version > v`: a rewind compares the version only, an entry re-issued in a
    /// newer interval carries a larger epoch at the same version (spec pglog 1, 7.1).
    fn split_above_version(&mut self, v: u64) -> Vec<LogEntry> {
        let idx = self.log.log.partition_point(|e| e.version.version <= v);
        self.log.log.split_off(idx).into()
    }
    /// Remove and return entries with `version > v` (full eversion order): the merge cut compares eversions (spec 7.2).
    fn split_after(&mut self, v: Eversion) -> Vec<LogEntry> {
        let idx = self.log.log.partition_point(|e| e.version <= v);
        self.log.log.split_off(idx).into()
    }
}

/// Set `info.last_complete` and `info.stats.stats.sum.num_objects_missing` from the missing set: the two go together
/// (spec pglog 6.4 for activation, 7.2 step 4 for a merge / rewind). Every member publishes its own count; the primary
/// uses it (with `|last_update| diff`) to choose the authoritative log and the async-recovery targets.
pub fn recompute_last_complete(log: &IndexedLog, info: &mut PgInfo, missing: &MissingSet) {
    info.stats.stats.sum.num_objects_missing = missing.len() as i64;
    match missing.oldest_need() {
        None => info.last_complete = info.last_update,
        Some(n) => {
            let idx = log.log.log.partition_point(|e| e.version < n);
            info.last_complete = if idx == 0 {
                if n > log.log.tail {
                    log.log.tail
                } else {
                    Eversion::default()
                }
            } else {
                log.log.log[idx - 1].version
            };
        }
    }
}

// ---- divergence ------------------------------------------------------------------------------

/// EC shard rules of the divergent-entry processing (adr 0040): geometry for the rollback executor plus the
/// authoritative log's `can_rollback_to` (entries at or below it can no longer be rolled back).
#[derive(Debug, Clone, Copy)]
pub struct EcRoll {
    pub ctx: crate::ecroll::EcCtx,
    pub olog_crt: Eversion,
}

/// Case 4 of spec pglog 7.3: undo every divergent entry of one object, newest first. `None` = some entry cannot be
/// rolled back (version at or below the auth `can_rollback_to`, unrollbackable or unparsable `mod_desc`).
fn rollback_object(ec: &EcRoll, es: &[LogEntry]) -> Option<crate::ecroll::Rollback> {
    let mut all = crate::ecroll::Rollback::default();
    for e in es.iter().rev() {
        if e.version <= ec.olog_crt {
            return None;
        }
        let r = crate::ecroll::rollback_entry(&ec.ctx, e).ok()?;
        all.shard_ops.extend(r.shard_ops);
        all.snap_ops.extend(r.snap_ops);
    }
    Some(all)
}

/// Stash deletion for entries whose object was removed outright (spec ec.md 7.6 `trim_after_remove`).
fn stash_cleanup_ops(ec: &EcRoll, es: &[LogEntry], ops: &mut Vec<StoreOp>) {
    let mut v = Vec::new();
    for e in es {
        if let Ok(c) = crate::ecroll::cleanup_entry(&ec.ctx, e) {
            v.extend(c);
        }
    }
    if !v.is_empty() {
        ops.push(StoreOp::Shard(v));
    }
}

/// Per-object processing of divergent entries (spec 7.3); `ec` enables case 4 and the stash cleanup.
fn process_divergent(
    log: &IndexedLog,
    info: &PgInfo,
    missing: &mut MissingSet,
    ops: &mut Vec<StoreOp>,
    divergent: Vec<LogEntry>,
    ec: Option<&EcRoll>,
) {
    let mut by_obj: BTreeMap<Hobject, Vec<LogEntry>> = BTreeMap::new();
    for e in divergent {
        if e.op == LogOp::ERROR {
            continue;
        }
        by_obj.entry(e.soid.clone()).or_default().push(e);
    }
    // A newer authoritative partial write may not have touched an NP shard. It cannot replace that shard's
    // divergent bytes: we must still roll those back (or recover their prior version). Build the shard-local
    // view once, rather than scanning the log again for every divergent object.
    let written = ec
        .filter(|ec| ec.ctx.opt && ec.ctx.np && !by_obj.is_empty())
        .map(|ec| {
            let mut written = BTreeMap::new();
            for e in &log.log.log {
                if e.object_is_indexed() && ec.ctx.written(e) {
                    written.insert(&e.soid, e.version);
                }
            }
            written
        });
    for (oid, mut es) in by_obj {
        if oid > info.last_backfill {
            continue;
        }
        let prior = es[0].prior_version;
        // what a recovery of the object must reach: the prior version, or a newer authoritative entry that skipped our
        // NP shard (it left the prior shard bytes valid, but the object, and so the recovery source, is at that version;
        // `add_next_event` keeps a missing item's need at the newest entry the same way)
        let need = log.newest_for(&oid).map_or(prior, |v| v.max(prior));
        if let Some(ec) = ec.filter(|e| e.ctx.opt) {
            // mode O (spec 6.2): partial writes that skipped our shard left nothing here to undo; the object's prior
            // version still comes from the first divergent entry
            es.retain(|e| ec.ctx.written(e));
            if es.is_empty() {
                if prior == Eversion::default() {
                    missing.rm(&oid);
                    ops.push(StoreOp::RemoveObject(oid.clone()));
                } else if let Some(it) = missing.get(&oid) {
                    if it.have == prior {
                        missing.rm(&oid);
                    } else {
                        missing.revise_need(oid.clone(), need, false);
                    }
                }
                continue;
            }
        }
        let first = &es[0];
        let last = es.last().unwrap();
        let known_absent = !missing.contains(&oid) && last.is_delete();
        let newest = match &written {
            Some(written) => written.get(&oid).copied(),
            None => log.newest_for(&oid),
        };
        if newest.is_some_and(|v| v >= first.version) {
            // case 1: a newer, authoritative entry exists
            if missing.contains(&oid) {
                missing.forget_have(&oid);
            }
            if !known_absent {
                ops.push(StoreOp::RemoveObject(oid.clone()));
            }
            if let Some(ec) = ec {
                stash_cleanup_ops(ec, &es, ops);
            }
        } else if prior == Eversion::default() || first.op == LogOp::CLONE {
            // case 2: created by divergent writes
            missing.rm(&oid);
            if !known_absent {
                ops.push(StoreOp::RemoveObject(oid.clone()));
            }
            if let Some(ec) = ec {
                stash_cleanup_ops(ec, &es, ops);
            }
        } else if let Some(it) = missing.get(&oid) {
            // case 3
            if it.have == prior {
                missing.rm(&oid);
            } else {
                missing.revise_need(oid.clone(), need, false);
            }
        } else if let Some(rb) = ec.and_then(|ec| rollback_object(ec, &es)) {
            // case 4 (EC): every divergent entry is rollbackable and above the auth `can_rollback_to`: undo them, the
            // object is back at its prior version and not missing
            if !rb.shard_ops.is_empty() {
                ops.push(StoreOp::Shard(rb.shard_ops));
            }
            if !rb.snap_ops.is_empty() {
                ops.push(StoreOp::SnapMap(rb.snap_ops));
            }
        } else {
            // case 5: delete local copy, recover the prior version
            if !known_absent {
                ops.push(StoreOp::RemoveObject(oid.clone()));
            }
            if let Some(ec) = ec {
                stash_cleanup_ops(ec, &es, ops);
            }
            missing.add(oid.clone(), need, Eversion::default(), false);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// Logs do not overlap: the receiver needs a full backfill.
    NoOverlap,
}

/// `rewind_divergent_log(newhead)` (spec 7.1). Err if `newhead < tail`.
pub fn rewind_divergent_log(
    log: &mut IndexedLog,
    info: &mut PgInfo,
    missing: &mut MissingSet,
    ops: &mut Vec<StoreOp>,
    newhead: Eversion,
) -> Result<(), MergeError> {
    rewind_divergent_log_x(log, info, missing, ops, newhead, None)
}

/// [`rewind_divergent_log`] for an EC shard: rollbackable divergent entries are rolled back (case 4) and the stash
/// of removed objects is cleaned (`ctx`: geometry of the pool and our shard).
pub fn rewind_divergent_log_ec(
    log: &mut IndexedLog,
    info: &mut PgInfo,
    missing: &mut MissingSet,
    ops: &mut Vec<StoreOp>,
    newhead: Eversion,
    ctx: crate::ecroll::EcCtx,
) -> Result<(), MergeError> {
    rewind_divergent_log_x(log, info, missing, ops, newhead, Some(ctx))
}

fn rewind_divergent_log_x(
    log: &mut IndexedLog,
    info: &mut PgInfo,
    missing: &mut MissingSet,
    ops: &mut Vec<StoreOp>,
    newhead: Eversion,
    ec: Option<crate::ecroll::EcCtx>,
) -> Result<(), MergeError> {
    if newhead < log.log.tail {
        return Err(MergeError::NoOverlap);
    }
    info.last_complete = info.last_complete.min(newhead);
    let divergent = log.split_above_version(newhead.version);
    // entries at or below the local `can_rollback_to` (before the clamp) have given up their stash: never roll back
    // into them (cannot happen with a correct primary, which never rewinds below `pg_committed_to`; fail safe)
    let crt0 = log.log.can_rollback_to;
    log.log.head = newhead;
    log.log.can_rollback_to = log.log.can_rollback_to.min(newhead);
    log.log.rollback_info_trimmed_to = log.log.rollback_info_trimmed_to.min(newhead);
    info.last_update = newhead;
    ops.push(StoreOp::LogRewind { to: newhead });
    log.reindex();
    let er = ec.map(|ctx| EcRoll {
        ctx,
        olog_crt: crt0,
    });
    process_divergent(log, info, missing, ops, divergent, er.as_ref());
    recompute_last_complete(log, info, missing);
    Ok(())
}

fn merge_dups(l: &mut VecDeque<LogDup>, o: &VecDeque<LogDup>, tail: Eversion) -> bool {
    let before = l.clone();
    if l.is_empty() {
        l.extend(o.iter().cloned());
    } else {
        let newest = l.back().unwrap().version;
        let oldest = l.front().unwrap().version;
        l.extend(o.iter().filter(|d| d.version > newest).cloned());
        for d in o.iter().rev().filter(|d| d.version < oldest) {
            l.push_front(d.clone());
        }
    }
    l.retain(|d| d.version <= tail);
    *l != before
}

/// `merge_log(oinfo, olog)` (spec 7.2): adopt the authoritative log `olog`.
pub fn merge_log(
    log: &mut IndexedLog,
    info: &mut PgInfo,
    missing: &mut MissingSet,
    ops: &mut Vec<StoreOp>,
    oinfo: &PgInfo,
    olog: &PgLog,
) -> Result<bool, MergeError> {
    merge_log_x(log, info, missing, ops, oinfo, olog, None)
}

/// [`merge_log`] for an EC shard (adr 0040): divergent entries roll back, `can_rollback_to` := head while
/// `rollback_info_trimmed_to` keeps the stash cleanup debt of our older entries.
pub fn merge_log_ec(
    log: &mut IndexedLog,
    info: &mut PgInfo,
    missing: &mut MissingSet,
    ops: &mut Vec<StoreOp>,
    oinfo: &PgInfo,
    olog: &PgLog,
    ctx: crate::ecroll::EcCtx,
) -> Result<bool, MergeError> {
    merge_log_x(log, info, missing, ops, oinfo, olog, Some(ctx))
}

fn merge_log_x(
    log: &mut IndexedLog,
    info: &mut PgInfo,
    missing: &mut MissingSet,
    ops: &mut Vec<StoreOp>,
    oinfo: &PgInfo,
    olog: &PgLog,
    ec: Option<crate::ecroll::EcCtx>,
) -> Result<bool, MergeError> {
    let ec_rit = log.log.rollback_info_trimmed_to;
    let ec_crt = log.log.can_rollback_to;
    let (h, t) = (log.log.head, log.log.tail);
    if log.log.log.is_empty() && h == t {
        // empty local log: contiguous only if the auth log starts at (or before) our position
        if olog.tail > h {
            return Err(MergeError::NoOverlap);
        }
    } else if olog.head < t || olog.tail > h {
        return Err(MergeError::NoOverlap);
    }
    let mut changed = false;
    let orig_tail = t;
    // 1. extend the tail backwards
    if olog.tail < t {
        let n = olog.log.partition_point(|e| e.version <= t);
        for e in olog.log.range(..n).rev() {
            log.log.log.push_front(e.clone());
        }
        log.log.tail = olog.tail;
        info.log_tail = olog.tail;
        changed = true;
        log.reindex();
        // persisted as a full replace below (tail change)
    }
    // 2. stats / hit set
    if info.last_backfill == Hobject::MAX() {
        let (seq, ep) = (
            info.stats.reported_seq.max(oinfo.stats.reported_seq),
            info.stats.reported_epoch.max(oinfo.stats.reported_epoch),
        );
        info.stats = oinfo.stats.clone();
        info.stats.reported_seq = seq;
        info.stats.reported_epoch = ep;
    }
    info.hit_set = oinfo.hit_set.clone();
    let tail_changed = olog.tail < orig_tail;
    // 3. rewind if we are ahead
    if olog.head < log.log.head {
        // EC: the divergent entries roll back (case 4) and removed objects give up their stash, as on MOSDPGInfo
        rewind_divergent_log_x(log, info, missing, ops, olog.head, ec)?;
        changed = true;
    } else if olog.head > log.log.head {
        // 4. find the cut: newest auth entry <= our head, bounded below by max(ot, orig_tail)
        let lower = olog.tail.max(orig_tail);
        let idx = olog.log.partition_point(|e| e.version <= log.log.head);
        let cut = if idx == 0 {
            lower
        } else {
            olog.log[idx - 1].version.max(lower)
        };
        let opt = ec.filter(|c| c.opt);
        if let Some(ctx) = opt {
            // mode O (classic merge_log): our kept entries roll forward to the cut (stash cleanup + pwlc) before the
            // auth entries are appended; the new entries are never rolled back into (crt = rit = head below).
            // Resolve their generations before splitting: a divergent delete/replace may have moved a common
            // entry's object into its stash. Pending EC_OMAP must reach that stash before rollback restores it.
            let es = &log.log.log;
            let i0 = es.partition_point(|e| e.version <= ec_rit);
            let mut prev = if i0 == 0 {
                log.log.tail
            } else {
                es[i0 - 1].version
            };
            let mut rm = Vec::new();
            for (j, e) in es
                .iter()
                .enumerate()
                .skip(i0)
                .take_while(|(_, e)| e.version <= cut)
            {
                if let Ok(c) = crate::ecopt::rollforward_entry(&ctx, es, j) {
                    rm.extend(c);
                }
                crate::ecopt::partial_write(info, &ctx, prev, e);
                prev = e.version;
            }
            if !rm.is_empty() {
                ops.push(StoreOp::Shard(rm));
            }
        }
        let divergent = log.split_after(cut);
        if log.log.head > cut || !divergent.is_empty() {
            ops.push(StoreOp::LogRewind { to: cut });
            log.log.head = cut;
        }
        let mut appended = Vec::new();
        for e in olog.log.iter().filter(|e| e.version > cut) {
            if e.op != LogOp::ERROR && e.soid <= info.last_backfill {
                if !missing.may_include_deletes() && e.is_delete() {
                    // no delete item can track it: the delete happens here (spec 7.2 step 4)
                    missing.rm(&e.soid);
                    ops.push(StoreOp::RemoveObject(e.soid.clone()));
                } else {
                    crate::ecopt::add_next_event(missing, ec.as_ref(), e);
                }
            }
            log.append(e.clone());
            appended.push(e.clone());
        }
        if !appended.is_empty() {
            ops.push(if ec.is_some() {
                StoreOp::LogAppendKeep(appended)
            } else {
                StoreOp::LogAppend(appended)
            });
        }
        log.reindex();
        let er = ec.map(|ctx| EcRoll {
            ctx,
            olog_crt: olog.can_rollback_to.max(ec_crt),
        });
        process_divergent(log, info, missing, ops, divergent, er.as_ref());
        log.log.head = olog.head;
        info.last_update = olog.head;
        log.log.can_rollback_to = olog.head;
        log.log.rollback_info_trimmed_to = olog.head;
        // the head can be newer than the last entry (split children): persist it explicitly
        ops.push(StoreOp::LogSetHead(olog.head));
        if opt.is_some() {
            ops.push(StoreOp::LogCursors {
                can_rollback_to: olog.head,
                rollback_info_trimmed_to: olog.head,
            });
        } else if ec.is_some() {
            // EC: nothing can be rolled back into the new entries, but our older entries still owe their stash
            // cleanup (their stash is intact): `rollback_info_trimmed_to` stays at or below the cut
            let rit = ec_rit.min(cut);
            log.log.rollback_info_trimmed_to = rit;
            ops.push(StoreOp::LogCursors {
                can_rollback_to: olog.head,
                rollback_info_trimmed_to: rit,
            });
        }
        changed = true;
    }
    info.last_user_version = oinfo.last_user_version;
    info.purged_snaps = oinfo.purged_snaps.clone();
    // 5. dups
    if merge_dups(&mut log.log.dups, &olog.dups, log.log.tail) {
        log.reindex_dups();
        changed = true;
        ops.push(StoreOp::LogDups(log.log.dups.iter().cloned().collect()));
    }
    if tail_changed {
        // simplest durable form of a tail extension: rewrite the log
        ops.push(StoreOp::LogReplace(Box::new(log.log.clone())));
    }
    info.log_tail = log.log.tail;
    recompute_last_complete(log, info, missing);
    Ok(changed)
}

/// Primary: bring a peer's reported log/missing in line with the authoritative log (spec 7.5).
/// `oinfo.last_update` / `last_complete` and `omissing` are updated.
pub fn proc_replica_log(
    our: &IndexedLog,
    oinfo: &mut PgInfo,
    olog: &PgLog,
    omissing: &mut MissingSet,
) {
    proc_replica_log_x(our, oinfo, olog, omissing, None)
}

/// [`proc_replica_log`] for an EC peer (`ctx` = pool geometry and the PEER's shard): the peer rolls its rollbackable
/// divergent entries back (case 4) instead of recovering their objects, so those objects are not missing on it.
pub fn proc_replica_log_ec(
    our: &IndexedLog,
    oinfo: &mut PgInfo,
    olog: &PgLog,
    omissing: &mut MissingSet,
    ctx: crate::ecroll::EcCtx,
) {
    proc_replica_log_x(our, oinfo, olog, omissing, Some(ctx))
}

fn proc_replica_log_x(
    our: &IndexedLog,
    oinfo: &mut PgInfo,
    olog: &PgLog,
    omissing: &mut MissingSet,
    ec: Option<crate::ecroll::EcCtx>,
) {
    if oinfo.last_update < our.log.tail {
        return; // no overlap: backfill
    }
    if oinfo.last_update != our.log.head {
        let limit = olog.tail.max(our.log.tail);
        let idx = our
            .log
            .log
            .partition_point(|e| e.version <= oinfo.last_update);
        let lu = if idx == 0 {
            limit
        } else {
            our.log.log[idx - 1].version.max(limit)
        };
        if lu < oinfo.last_update {
            // the store ops of the peer's divergent entries are dropped: it runs the rewind itself (spec 7.5)
            let mut copy = IndexedLog::new(olog.clone());
            let mut sink = Vec::new();
            // `lu` is never below the copy's tail (bounded by `olog.tail`): the rewind itself writes `lu` into oinfo
            if rewind_divergent_log_x(&mut copy, oinfo, omissing, &mut sink, lu, ec).is_ok() {
                // 21.2.0 B5: partial-write coverage past the rolled-back head is void
                crate::ecopt::clamp_pwlc(oinfo, lu);
            }
        }
    }
    match omissing.oldest_need() {
        None => oinfo.last_complete = oinfo.last_update,
        Some(n) => {
            let idx = olog.log.partition_point(|e| e.version < n);
            oinfo.last_complete = if idx == 0 {
                Eversion::default()
            } else {
                olog.log[idx - 1].version
            };
            if oinfo.last_complete > oinfo.last_update {
                oinfo.last_complete = oinfo.last_update;
            }
        }
    }
}

/// `denc` of `entries` (a repop's `logbl`, byte-identical to encoding the `Vec`) and the slice of every entry in it: the
/// local store writes the slices (`StoreOp::LogAppendFast`), no second encoding.
pub(crate) fn encode_log_entries(
    entries: &[pgwire::LogEntry],
) -> denc::Result<(bytes::Bytes, Vec<bytes::Bytes>)> {
    use denc::Encode;
    let mut at = Vec::with_capacity(entries.len());
    let bl: bytes::Bytes = denc::encode_exact(denc::features::ALL, |e| {
        e.count(entries.len())?;
        for x in entries {
            let a = e.len();
            x.encode(e)?;
            at.push((a, e.len()));
        }
        Ok(())
    })?
    .into();
    let encs = at.into_iter().map(|(a, b)| bl.slice(a..b)).collect();
    Ok((bl, encs))
}

/// The entries of a repop's `logbl` (like `denc::from_slice::<Vec<LogEntry>>`) and the slice of each.
pub(crate) fn decode_log_entries(
    bl: &bytes::Bytes,
) -> denc::Result<(Vec<pgwire::LogEntry>, Vec<bytes::Bytes>)> {
    use denc::Decode;
    let mut d = denc::Decoder::new(bl);
    let n = d.count()?;
    // capacity from the peer's count is bounded: the vectors grow with the entries actually decoded
    let cap = n.min(1024);
    let (mut es, mut encs) = (Vec::with_capacity(cap), Vec::with_capacity(cap));
    for _ in 0..n {
        let a = d.position();
        es.push(pgwire::LogEntry::decode(&mut d)?);
        encs.push(bl.slice(a..d.position()));
    }
    if d.remaining() != 0 {
        return Err(denc::Error::TrailingBytes(d.remaining()));
    }
    Ok((es, encs))
}

#[cfg(test)]
mod enc_tests {
    use super::*;
    use denc::types::{Eversion, Hobject};

    #[test]
    fn trim_prefix_search_equals_the_binary_search() {
        for n in 0..40u64 {
            let mut l = IndexedLog::default();
            for v in 0..n {
                l.append(pgwire::LogEntry::with_regions(
                    pgwire::LogOp::MODIFY,
                    Hobject::default(),
                    Eversion::new(3, 10 + 2 * v),
                    Eversion::default(),
                    pgwire::ObjectCleanRegions::fully_dirty(),
                ));
            }
            for to in 0..(10 + 2 * n + 3) {
                let to = Eversion::new(3, to);
                assert_eq!(
                    l.prefix_le(to),
                    l.log.log.partition_point(|e| e.version <= to),
                    "log of {n}, to {to:?}"
                );
            }
        }
    }

    #[test]
    fn log_entry_slices_match_the_vec_encoding() {
        let es: Vec<pgwire::LogEntry> = (1..5u64)
            .map(|v| {
                let h = Hobject {
                    oid: format!("rbd_data.{v:08x}").into_bytes(),
                    ..Hobject::default()
                };
                let mut e = pgwire::LogEntry::with_regions(
                    pgwire::LogOp::MODIFY,
                    h,
                    Eversion::new(7, v),
                    Eversion::new(7, v - 1),
                    pgwire::ObjectCleanRegions::fully_dirty(),
                );
                e.user_version = v * 3;
                e
            })
            .collect();
        let (bl, encs) = encode_log_entries(&es).unwrap();
        assert_eq!(
            bl.to_vec(),
            denc::to_vec(&es).unwrap(),
            "byte-identical to the Vec encoding"
        );
        let (back, encs2) = decode_log_entries(&bl).unwrap();
        assert_eq!(back, es);
        assert_eq!(encs, encs2);
        for (e, b) in es.iter().zip(&encs) {
            assert_eq!(b.to_vec(), denc::to_vec(e).unwrap());
        }
        let mut t = bl.to_vec();
        t.push(0);
        assert!(
            decode_log_entries(&t.into()).is_err(),
            "trailing bytes refused like from_slice"
        );
        assert!(decode_log_entries(&bl.slice(..bl.len() - 1)).is_err());
    }
}
