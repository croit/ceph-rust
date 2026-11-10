// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Min-heap of `(deadline, key)` entries; the key -> heap-position table is supplied by the owner, so keyed owners
//! ([`std::collections::BTreeMap`]) and dense slot owners ([`crate::SlotIndex`]'s table) share one heap implementation.
use std::collections::BTreeMap;

/// Where a registered key lives: unregistered, registered without a deadline, or its heap index.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Slot {
    Unknown,
    Idle,
    At(usize),
}

/// Key -> [`Slot`] table. Implementors choose the layout; [`Heap`] keeps the order.
pub(crate) trait Positions<K> {
    fn slot_of(&self, key: &K) -> Slot;
    /// Store an in-heap position, or the idle marker, for a key that is registered.
    fn store_slot(&mut self, key: K, position: Option<usize>);
    /// Register `key`; `false` when it already is.
    fn register_key(&mut self, key: K) -> bool;
    fn drop_key(&mut self, key: K);
    /// Registered keys: the heap capacity target, which is what keeps updates allocation-free.
    fn registered(&self) -> usize;
}

#[derive(Debug)]
pub(crate) struct Heap<K: Copy + Ord, T: Copy + Ord, P> {
    positions: P,
    entries: Vec<(T, K)>,
    /// Reused collect buffer of [`Self::due`]; keeps its peak capacity, so a query allocates only its result.
    due_buf: Vec<(T, K)>,
}

impl<K: Copy + Ord, T: Copy + Ord, P: Default> Default for Heap<K, T, P> {
    fn default() -> Self {
        Self {
            positions: P::default(),
            entries: Vec::new(),
            due_buf: Vec::new(),
        }
    }
}

impl<K: Copy + Ord, T: Copy + Ord, P: Positions<K>> Heap<K, T, P> {
    /// Reserve one reusable heap slot for a live owner; call only on creation.
    pub(crate) fn register(&mut self, key: K) {
        if !self.positions.register_key(key) {
            return;
        }
        let needed = self.positions.registered();
        if self.entries.capacity() < needed {
            self.entries.reserve(needed - self.entries.len());
        }
    }

    pub(crate) fn unregister(&mut self, key: K) {
        self.set(key, None);
        self.positions.drop_key(key);
    }

    /// Update a registered owner. A removed owner may still have a dirty notification; ignore it.
    pub(crate) fn set(&mut self, key: K, deadline: Option<T>) {
        match (self.positions.slot_of(&key), deadline) {
            (Slot::At(i), Some(d)) => {
                if self.entries[i].0 != d {
                    self.entries[i].0 = d;
                    self.fix(i);
                }
            }
            (Slot::At(i), None) => {
                self.positions.store_slot(key, None);
                let last = self.entries.pop().unwrap();
                if i < self.entries.len() {
                    self.entries[i] = last;
                    self.positions.store_slot(last.1, Some(i));
                    self.fix(i);
                }
            }
            (Slot::Idle, Some(d)) => {
                let i = self.entries.len();
                self.entries.push((d, key));
                self.positions.store_slot(key, Some(i));
                self.fix(i);
            }
            (Slot::Idle, None) | (Slot::Unknown, _) => {}
        }
    }

    /// Earliest `(deadline, key)`; equal deadlines break on the key.
    pub(crate) fn first(&self) -> Option<(T, K)> {
        self.entries.first().copied()
    }

    /// Non-consuming due query; skip entire heap subtrees later than `now`. Earliest deadline first, then key. The
    /// collect buffer is reused, so only the result vector is allocated.
    pub(crate) fn due(&mut self, now: T) -> Vec<K> {
        let mut due = std::mem::take(&mut self.due_buf);
        due.clear();
        self.collect_due(0, now, &mut due);
        due.sort_unstable();
        self.due_buf = due;
        self.due_buf.iter().map(|&(_, key)| key).collect()
    }

    fn collect_due(&self, i: usize, now: T, out: &mut Vec<(T, K)>) {
        let Some(&(d, k)) = self.entries.get(i) else {
            return;
        };
        if d > now {
            return;
        }
        out.push((d, k));
        self.collect_due(2 * i + 1, now, out);
        self.collect_due(2 * i + 2, now, out);
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.entries.swap(a, b);
        self.positions.store_slot(self.entries[a].1, Some(a));
        self.positions.store_slot(self.entries[b].1, Some(b));
    }

    fn fix(&mut self, mut i: usize) {
        if i > 0 && self.entries[i] < self.entries[(i - 1) / 2] {
            while i > 0 && self.entries[i] < self.entries[(i - 1) / 2] {
                let parent = (i - 1) / 2;
                self.swap(i, parent);
                i = parent;
            }
        } else {
            while 2 * i + 1 < self.entries.len() {
                let mut child = 2 * i + 1;
                if child + 1 < self.entries.len() && self.entries[child + 1] < self.entries[child] {
                    child += 1;
                }
                if self.entries[i] <= self.entries[child] {
                    break;
                }
                self.swap(i, child);
                i = child;
            }
        }
    }
}

impl<K: Copy + Ord> Positions<K> for BTreeMap<K, Option<usize>> {
    fn slot_of(&self, key: &K) -> Slot {
        match self.get(key) {
            None => Slot::Unknown,
            Some(None) => Slot::Idle,
            Some(Some(position)) => Slot::At(*position),
        }
    }

    fn store_slot(&mut self, key: K, position: Option<usize>) {
        self.insert(key, position);
    }

    fn register_key(&mut self, key: K) -> bool {
        // never overwrite: a registered key may hold a heap position
        match self.entry(key) {
            std::collections::btree_map::Entry::Occupied(_) => false,
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(None);
                true
            }
        }
    }

    fn drop_key(&mut self, key: K) {
        self.remove(&key);
    }

    fn registered(&self) -> usize {
        self.len()
    }
}
