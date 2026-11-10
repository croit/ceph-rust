// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Foreign owner overlays and immutable worker snapshots. RocksDB and SplinterDB
//! reuse these mechanics in distinct selected buffer instances. Native LSM uses
//! direct-owned buffers in `olsm::mem`, independently of either Cargo feature.
//!
//! Ops must be applied in LSN order (WAL order); a later op overrides an earlier one. A range tombstone drops the
//! object's covered entries when applied, so every entry left in the memtable is newer than every range tombstone
//! of the memtable covering it (module invariant of [`crate::olsm`]).

use crate::olsm::mem::{ENTRY_RAM, MKey, Probe};
use crate::olsm::{RangeT, Val, ranges_add, ranges_find};
use bytes::Bytes;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

/// RAM charged per object: its map header, range list and hash slot.
pub const OBJ_RAM: usize = size_of::<u64>() + size_of::<ObjMem>() + size_of::<usize>();

/// One object's buffered omap ops.
#[derive(Clone, Debug, Default)]
pub struct ObjMem {
    pub map: BTreeMap<MKey, Val>,
    /// Range tombstones of this object, sorted, disjoint.
    pub ranges: Vec<RangeT>,
    pub(crate) revision: (u64, u64),
}

type ObjectSlot = std::sync::Arc<ObjMem>;

/// Active or frozen memtable of one shard.
#[derive(Debug, Default)]
pub struct Memtable {
    stamp: (u64, u64),
    objs: HashMap<u64, ObjectSlot>,
    bytes: usize,
    entries: usize,
    lsn_lo: u64,
    lsn_hi: u64,
}

fn ent_ram(k: &[u8], v: &Val) -> usize {
    k.len() + v.as_ref().map_or(0, |v| v.len()) + ENTRY_RAM
}

fn range_ram(r: &RangeT) -> usize {
    r.first.len() + r.end.as_ref().map_or(0, |e| e.len()) + size_of::<RangeT>()
}

impl Memtable {
    /// Identity/version for resumable external-base scans.
    pub(crate) fn scan_stamp(&self) -> (u64, u64) {
        self.stamp
    }
    pub fn new() -> Memtable {
        Memtable::default()
    }
    /// No op applied (every op leaves its object's entry; lsn 0 is a valid lsn: S7 upgrade batch on a fresh store).
    pub fn is_empty(&self) -> bool {
        self.objs.is_empty()
    }
    /// RAM charged (keys, values, map slots, ranges, objects).
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    /// Oldest / newest LSN applied (0 = none).
    pub fn lsn_lo(&self) -> u64 {
        self.lsn_lo
    }
    pub fn lsn_hi(&self) -> u64 {
        self.lsn_hi
    }
    pub fn obj(&self, id: u64) -> Option<&ObjMem> {
        self.objs.get(&id).map(|o| &**o)
    }
    pub(crate) fn snapshot(&self, id: u64) -> Option<std::sync::Arc<ObjMem>> {
        self.objs.get(&id).cloned()
    }
    /// Object ids in ascending order (flush order).
    pub fn sorted_ids(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.objs.keys().copied().collect();
        v.sort_unstable();
        v
    }

    fn obj_mut(&mut self, lsn: u64, id: u64) -> &mut ObjMem {
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            if self.stamp.0 == 0 {
                self.stamp.0 = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            self.stamp.1 += 1;
        }
        debug_assert!(
            lsn >= self.lsn_hi,
            "memtable ops out of LSN order: {lsn} < {}",
            self.lsn_hi
        );
        if self.objs.is_empty() {
            self.lsn_lo = lsn;
        }
        self.lsn_hi = lsn;
        let bytes = &mut self.bytes;
        let o = self.objs.entry(id).or_insert_with(|| {
            *bytes += OBJ_RAM;
            ObjectSlot::default()
        });
        let o = std::sync::Arc::make_mut(o);
        o.revision.0 = lsn;
        o.revision.1 += 1;
        o
    }

    /// Insert into one object's map; returns the RAM delta and whether the key is new.
    #[inline]
    fn set(o: &mut ObjMem, key: Bytes, val: Val) -> (isize, bool) {
        let add = ent_ram(&key, &val) as isize;
        match o.map.entry(MKey::new(key.clone())) {
            Entry::Vacant(e) => {
                e.insert(val);
                (add, true)
            }
            // an overwrite replaces the key handle too (the map keeps its own): it may slice an older WAL record
            Entry::Occupied(e) => {
                let (k, v) = e.remove_entry();
                o.map.insert(MKey::new(key), val);
                (add - ent_ram(&k.key, &v) as isize, false)
            }
        }
    }

    fn apply(&mut self, lsn: u64, id: u64, kvs: impl IntoIterator<Item = (Bytes, Val)>) {
        let o = self.obj_mut(lsn, id);
        let (mut d, mut n) = (0isize, 0usize);
        for (k, v) in kvs {
            let (dd, new) = Self::set(o, k, v);
            d += dd;
            n += new as usize;
        }
        self.bytes = self.bytes.wrapping_add_signed(d);
        self.entries += n;
    }

    /// Put one key.
    #[cfg(test)]
    pub fn put(&mut self, lsn: u64, id: u64, key: Bytes, val: Bytes) {
        self.apply(lsn, id, [(key, Some(val))]);
    }

    /// Put a batch of one op (keys in any order).
    pub fn put_batch(&mut self, lsn: u64, id: u64, kvs: impl IntoIterator<Item = (Bytes, Bytes)>) {
        self.apply(lsn, id, kvs.into_iter().map(|(k, v)| (k, Some(v))));
    }

    /// Point delete (tombstone).
    pub fn del(&mut self, lsn: u64, id: u64, key: Bytes) {
        self.apply(lsn, id, [(key, None)]);
    }

    /// Range delete `[first, end)` of object `id` (`end = None`: to the last key; `first` empty + `None` = clear).
    pub fn del_range(&mut self, lsn: u64, id: u64, first: Bytes, end: Option<Bytes>) {
        let o = self.obj_mut(lsn, id);
        let mut freed = 0usize;
        let mut gone = 0usize;
        if first.is_empty() && end.is_none() {
            gone = o.map.len();
            freed = o.map.iter().map(|(k, v)| ent_ram(&k.key, v)).sum();
            o.map.clear();
        } else {
            let dead: Vec<MKey> = match &end {
                Some(e) => o
                    .map
                    .range::<[u8], _>((Bound::Included(&first[..]), Bound::Excluded(&e[..]))),
                None => o
                    .map
                    .range::<[u8], _>((Bound::Included(&first[..]), Bound::Unbounded)),
            }
            .map(|(k, _)| k.clone())
            .collect();
            for k in dead {
                if let Some(v) = o.map.remove(&k) {
                    freed += ent_ram(&k.key, &v);
                    gone += 1;
                }
            }
        }
        let before: usize = o.ranges.iter().map(range_ram).sum();
        ranges_add(&mut o.ranges, RangeT { id, first, end });
        let after: usize = o.ranges.iter().map(range_ram).sum();
        self.bytes = self.bytes + after - before - freed;
        self.entries -= gone;
    }

    /// What this memtable says about `(id, key)`.
    pub fn probe(&self, id: u64, key: &[u8]) -> Probe {
        let Some(o) = self.objs.get(&id) else {
            return Probe::Pass;
        };
        if let Some(v) = o.map.get(key) {
            return Probe::Hit(v.clone());
        }
        if ranges_find(&o.ranges, id, key).is_some() {
            return Probe::Covered;
        }
        Probe::Pass
    }
}

/// Only the RocksDB-selected state owns these buffers. The native manifest may
/// still describe the durable publication frontier, but never stores overlays.
#[derive(Debug, Default)]
pub(crate) struct Buffers {
    pub active: Memtable,
    pub frozen: Option<std::sync::Arc<Memtable>>,
}

impl Buffers {
    pub fn freeze(&mut self) {
        assert!(self.frozen.is_none());
        self.frozen = Some(std::sync::Arc::new(std::mem::take(&mut self.active)));
    }

    pub fn bytes(&self) -> usize {
        self.active.bytes() + self.frozen.as_ref().map_or(0, |f| f.bytes())
    }

    pub fn floor(&self) -> Option<u64> {
        self.frozen
            .as_ref()
            .map(|f| f.lsn_lo())
            .or_else(|| (!self.active.is_empty()).then(|| self.active.lsn_lo()))
    }

    pub fn is_empty(&self) -> bool {
        self.active.is_empty() && self.frozen.is_none()
    }
}

impl crate::olsm::wire::OOp {
    #[cfg(feature = "splinterdb")]
    pub(crate) fn apply_splinter(&self, mem: &mut Memtable, lsn: u64) {
        self.apply_rocks(mem, lsn);
    }
    pub(crate) fn apply_rocks(&self, mem: &mut Memtable, lsn: u64) {
        use crate::olsm::wire::{DelIter, OOp, PutIter};
        match self {
            OOp::Put { id, blob, .. } => mem.put_batch(lsn, *id, PutIter::new(blob)),
            OOp::Del { id, blob } => {
                for key in DelIter::new(blob) {
                    mem.del(lsn, *id, key);
                }
            }
            OOp::Range { id, first, end } => mem.del_range(lsn, *id, first.clone(), end.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rocks_snapshot_is_immutable_across_mutation_range_clear_and_freeze() {
        let mut buffers = Buffers::default();
        buffers
            .active
            .put(1, 7, Bytes::from_static(b"a"), Bytes::from_static(b"old"));
        let snapshot = buffers.active.snapshot(7).unwrap();
        let revision = snapshot.revision;
        buffers
            .active
            .put(2, 7, Bytes::from_static(b"a"), Bytes::from_static(b"new"));
        assert_eq!(
            snapshot.map.get(&b"a"[..]).unwrap().as_deref(),
            Some(&b"old"[..])
        );
        assert_ne!(buffers.active.snapshot(7).unwrap().revision, revision);
        assert!(!std::sync::Arc::ptr_eq(
            &snapshot,
            &buffers.active.snapshot(7).unwrap()
        ));
        buffers.active.del_range(3, 7, Bytes::new(), None);
        assert_eq!(buffers.active.probe(7, b"a"), Probe::Covered);
        assert_eq!(
            snapshot.map.get(&b"a"[..]).unwrap().as_deref(),
            Some(&b"old"[..])
        );
        buffers.freeze();
        assert!(buffers.active.is_empty());
        assert_eq!(buffers.floor(), Some(1));
        assert_eq!(buffers.frozen.as_ref().unwrap().lsn_hi(), 3);
        buffers
            .active
            .put(4, 9, Bytes::from_static(b"b"), Bytes::from_static(b"other"));
        assert_eq!(buffers.floor(), Some(1));
        buffers.frozen = None;
        assert_eq!(buffers.floor(), Some(4));
        assert!(buffers.bytes() > 0);
    }
}
