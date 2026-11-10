// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Decoded object-state cache of one PG (adr 0160 D5): `(object_info, snapset)` of idle heads, so an op on a hot
//! object skips `load_state` (two attribute lookups + decode). Read cache only: it holds what the store holds.
//!
//! * Filled by a `load_state` miss and, write-through, by the engine when an object's last in-flight write finished
//!   (the post-write state the engine already keeps while writes are in flight).
//! * Valid only for one generation of the PG ([`crate::Env::obj_cache`]): the PG changes it on every txn that may touch
//!   an object and is not the replicated client write path (recovery, rollback, repair, EC, split/merge, removal),
//!   both when it is queued and when it commits. A new generation drops everything (coarse on purpose).
//! * Bounded: two generations of `cap / 2` heads each (hits in the older one move to the newer one; when the newer
//!   one is full the older one is dropped). Approximate LRU, no per-entry bookkeeping, no allocation after warm-up.

use crate::types::ObjState;
use denc::types::Hobject;
use std::collections::HashMap;

type FastMap<K, V> = HashMap<K, V, foldhash::fast::RandomState>;

/// Bytes one cached head costs at full load: one hash table slot (key + value + control byte) at the table's 7/8 load
/// factor. Heap parts (object name, snap vectors, xattrs in `object_info`) are not counted (adr 0160 D5).
pub const OBJ_HEAD_BYTES: u64 = ((std::mem::size_of::<(Hobject, ObjState)>() + 1) * 8 / 7) as u64;

/// Capacity in heads of one PG's cache whose two tables must fit `bytes` (0 = too small, off): each table gets
/// `bytes / 2`, rounded down to its power-of-two bucket count, and holds 7/8 of its buckets before the generations swap
/// (so it never grows past them).
pub fn obj_cache_cap(bytes: u64) -> usize {
    let slot = (std::mem::size_of::<(Hobject, ObjState)>() + 1) as u64;
    let buckets = bytes / 2 / slot;
    if buckets < 8 {
        return 0;
    }
    let buckets = 1u64 << buckets.ilog2();
    (2 * buckets / 8 * 7) as usize
}

#[derive(Default)]
pub(crate) struct ObjCache {
    /// Generation the entries belong to (0 = none yet).
    gen_: u64,
    /// Capacity in heads (0 = off).
    cap: usize,
    new: FastMap<Hobject, ObjState>,
    old: FastMap<Hobject, ObjState>,
}

impl ObjCache {
    /// Align with the PG's current `(generation, capacity)`; `None` = off. Returns the generation when the cache is on.
    pub(crate) fn sync(&mut self, cur: Option<(u64, usize)>) -> Option<u64> {
        let (g, cap) = cur.filter(|c| c.1 > 0).unwrap_or((0, 0));
        if g != self.gen_ || cap != self.cap {
            if cap < self.cap {
                // A reduced budget must release the old bucket arrays too.
                self.new = FastMap::default();
                self.old = FastMap::default();
            } else {
                self.clear();
            }
            self.gen_ = g;
            self.cap = cap;
        }
        (cap > 0).then_some(g)
    }

    pub(crate) fn clear(&mut self) {
        self.new.clear();
        self.old.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.new.len() + self.old.len()
    }

    /// A copy of the cached state of `head` (a hit in the older half moves it to the newer one).
    pub(crate) fn get_cloned(&mut self, head: &Hobject) -> Option<ObjState> {
        if let Some(s) = self.new.get(head) {
            return Some(s.clone());
        }
        let (k, v) = self.old.remove_entry(head)?;
        let s = v.clone();
        self.put(k, v);
        Some(s)
    }

    /// Take the cached state of `head` out (a write: its post-write state comes back with [`Self::put`]).
    pub(crate) fn take(&mut self, head: &Hobject) -> Option<ObjState> {
        self.new.remove(head).or_else(|| self.old.remove(head))
    }

    pub(crate) fn put(&mut self, head: Hobject, st: ObjState) {
        if self.cap == 0 {
            return;
        }
        self.old.remove(&head);
        if self.new.len() >= (self.cap / 2).max(1) && !self.new.contains_key(&head) {
            std::mem::swap(&mut self.new, &mut self.old);
            self.new.clear();
        }
        self.new.insert(head, st);
    }

    pub(crate) fn remove(&mut self, head: &Hobject) {
        self.new.remove(head);
        self.old.remove(head);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hobject {
        Hobject {
            oid: vec![n],
            ..Default::default()
        }
    }

    #[test]
    fn bounded_and_recent_hits_survive() {
        let mut c = ObjCache::default();
        assert_eq!(c.sync(Some((7, 4))), Some(7));
        for i in 0..4 {
            c.put(h(i), ObjState::default());
        }
        assert!(c.len() <= 4);
        // 0 and 1 rotated into the older half; a hit on 0 keeps it, 1 falls out with the next rotation
        assert!(c.get_cloned(&h(0)).is_some());
        c.put(h(4), ObjState::default());
        c.put(h(5), ObjState::default());
        assert!(c.len() <= 4);
        assert!(c.get_cloned(&h(1)).is_none());
        assert!(c.get_cloned(&h(5)).is_some());
    }

    #[test]
    fn new_generation_or_off_drops_everything() {
        let mut c = ObjCache::default();
        c.sync(Some((1, 8)));
        c.put(h(1), ObjState::default());
        assert_eq!(c.sync(Some((1, 8))), Some(1));
        assert!(c.get_cloned(&h(1)).is_some());
        assert_eq!(c.sync(Some((2, 8))), Some(2));
        assert!(c.get_cloned(&h(1)).is_none());
        c.put(h(1), ObjState::default());
        assert_eq!(c.sync(None), None);
        assert_eq!(c.len(), 0);
        c.put(h(1), ObjState::default());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn shrinking_or_disabling_releases_the_old_table_budget() {
        let mut c = ObjCache::default();
        for next in [Some((2, 4)), None] {
            c.sync(Some((1, 1024)));
            for i in 0..1024u32 {
                c.put(
                    Hobject {
                        oid: i.to_le_bytes().to_vec(),
                        ..Default::default()
                    },
                    ObjState::default(),
                );
            }
            assert!(c.new.capacity() + c.old.capacity() >= 1024);
            // Ordinary generation invalidation keeps the warm tables.
            let capacity = c.new.capacity() + c.old.capacity();
            c.sync(Some((2, 1024)));
            assert_eq!(c.new.capacity() + c.old.capacity(), capacity);
            c.sync(next);
            assert_eq!(c.len(), 0);
            assert_eq!(c.new.capacity() + c.old.capacity(), 0);
        }
    }

    #[test]
    fn take_and_remove() {
        let mut c = ObjCache::default();
        c.sync(Some((1, 8)));
        c.put(h(1), ObjState::default());
        c.put(h(2), ObjState::default());
        assert!(c.take(&h(1)).is_some());
        assert!(c.get_cloned(&h(1)).is_none());
        c.remove(&h(2));
        assert_eq!(c.len(), 0);
    }
    #[test]
    fn cap_for_bytes_fits_the_tables() {
        assert_eq!(obj_cache_cap(0), 0);
        assert_eq!(obj_cache_cap(13 * OBJ_HEAD_BYTES), 0);
        for bytes in [16 * OBJ_HEAD_BYTES, 1 << 20, 3 << 20, 5_000_000] {
            let cap = obj_cache_cap(bytes);
            assert!(
                cap > 0 && cap as u64 * OBJ_HEAD_BYTES <= bytes,
                "{bytes}: {cap}"
            );
            // within 2x of the share (power-of-two rounding)
            assert!(
                2 * cap as u64 * OBJ_HEAD_BYTES + 2 * OBJ_HEAD_BYTES > bytes / 2,
                "{bytes}: {cap}"
            );
            let mut c = ObjCache::default();
            c.sync(Some((1, cap)));
            for i in 0..(3 * cap) as u32 {
                c.put(
                    Hobject {
                        oid: i.to_le_bytes().to_vec(),
                        ..Default::default()
                    },
                    ObjState::default(),
                );
            }
            let slot = std::mem::size_of::<(Hobject, ObjState)>() as u64 + 1;
            let used = (c.new.capacity() + c.old.capacity()) as u64 * slot * 8 / 7;
            assert!(used <= bytes, "{bytes}: tables {used}");
        }
    }
}
