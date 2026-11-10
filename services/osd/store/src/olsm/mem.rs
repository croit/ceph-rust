// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The shard's omap write buffer (adr 0610 (1)): per object an ordered map key -> value / point tombstone plus the
//! object's range tombstones (sorted, disjoint). Keys and values are [`Bytes`] slices of the caller's buffers.
//!
//! Ops must be applied in LSN order (WAL order); a later op overrides an earlier one. A range tombstone drops the
//! object's covered entries when applied, so every entry left in the memtable is newer than every range tombstone
//! of the memtable covering it (module invariant of [`crate::olsm`]).

use super::{RangeT, Val, key_prefix, ranges_add, ranges_find};
use bytes::Bytes;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

/// RAM charged per entry on top of its key and value bytes: the map slot (key + value handles); B-tree leaves are
/// about two thirds full on average, hence the factor 3/2.
pub const ENTRY_RAM: usize = (size_of::<MKey>() + size_of::<Val>()) * 3 / 2;

/// Memtable key: the key bytes (a slice of the caller's buffer) plus its first 8 bytes inline, so most comparisons
/// of a map descent stay in the map node instead of dereferencing the key buffer. Orders exactly like the bytes.
#[derive(Clone, Debug)]
pub struct MKey {
    pre: u64,
    pub key: Bytes,
}

impl MKey {
    pub fn new(key: Bytes) -> MKey {
        MKey {
            pre: key_prefix(&key),
            key,
        }
    }
}

impl PartialEq for MKey {
    fn eq(&self, o: &Self) -> bool {
        self.pre == o.pre && self.key == o.key
    }
}
impl Eq for MKey {}
impl PartialOrd for MKey {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for MKey {
    #[inline]
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        // Zero padding makes equal prefixes ambiguous ("a" vs "a\0"): the byte comparison decides then.
        self.pre
            .cmp(&o.pre)
            .then_with(|| self.key[..].cmp(&o.key[..]))
    }
}
impl std::borrow::Borrow<[u8]> for MKey {
    fn borrow(&self) -> &[u8] {
        &self.key
    }
}
/// RAM charged per object: its map header, range list and hash slot.
pub const OBJ_RAM: usize = size_of::<u64>() + size_of::<ObjMem>() + size_of::<usize>();

/// One object's buffered omap ops.
#[derive(Debug, Default)]
pub struct ObjMem {
    pub map: BTreeMap<MKey, Val>,
    /// Range tombstones of this object, sorted, disjoint.
    pub ranges: Vec<RangeT>,
}

/// Answer of one source for one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// The source holds an entry (value or point tombstone): it decides.
    Hit(Val),
    /// A range tombstone of the source covers the key: absent.
    Covered,
    /// Ask the next older source.
    Pass,
}

/// Active or frozen memtable of one shard.
#[derive(Debug, Default)]
pub struct Memtable {
    objs: HashMap<u64, ObjMem>,
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
    pub fn entries(&self) -> usize {
        self.entries
    }
    /// Oldest / newest LSN applied (0 = none).
    pub fn lsn_lo(&self) -> u64 {
        self.lsn_lo
    }
    pub fn lsn_hi(&self) -> u64 {
        self.lsn_hi
    }
    pub fn obj(&self, id: u64) -> Option<&ObjMem> {
        self.objs.get(&id)
    }
    /// Object ids in ascending order (flush order).
    pub fn sorted_ids(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.objs.keys().copied().collect();
        v.sort_unstable();
        v
    }

    fn obj_mut(&mut self, lsn: u64, id: u64) -> &mut ObjMem {
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
        self.objs.entry(id).or_insert_with(|| {
            *bytes += OBJ_RAM;
            ObjMem::default()
        })
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

#[cfg(test)]
mod isolation_tests {
    use super::*;

    #[test]
    fn native_memtable_owns_objects_even_with_rocksdb_compiled() {
        let mut mem = Memtable::new();
        mem.put(
            1,
            9,
            Bytes::from_static(b"key"),
            Bytes::from_static(b"value"),
        );
        let object = mem.objs.remove(&9).unwrap();
        assert_eq!(
            std::any::type_name_of_val(&object),
            std::any::type_name::<ObjMem>(),
            "native LSM must not acquire RocksDB snapshot ownership"
        );
        assert_eq!(
            size_of::<ObjMem>(),
            size_of::<BTreeMap<MKey, Val>>() + size_of::<Vec<RangeT>>(),
            "native objects must not carry RocksDB revision fields"
        );
        assert_eq!(
            size_of::<Memtable>(),
            size_of::<HashMap<u64, ObjMem>>() + 2 * size_of::<usize>() + 2 * size_of::<u64>(),
            "native memtables must not carry RocksDB identity/stamp fields"
        );
    }
}
