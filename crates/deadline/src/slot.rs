// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The dense-owner variant of [`crate::Index`]: owners are slot numbers (a request queue's slots) and the heap
//! position lives in a table indexed by the slot, so set/clear locate it in O(1) instead of an ordered-map lookup.
use crate::heap::{Heap, Positions, Slot};

/// Table entries: slot not registered, registered without a deadline, else the heap index.
const UNREGISTERED: usize = usize::MAX;
const IDLE: usize = usize::MAX - 1;

/// Deadline index for owners that are dense slot numbers (a request queue's slots).
#[derive(Debug)]
pub struct SlotIndex<T: Copy + Ord = u64> {
    heap: Heap<usize, T, Table>,
}

/// Slot -> heap position table (the dense counterpart of [`crate::Index`]'s ordered map).
#[derive(Debug, Default)]
struct Table {
    positions: Vec<usize>,
    registered: usize,
}

impl<T: Copy + Ord> Default for SlotIndex<T> {
    fn default() -> Self {
        Self {
            heap: Default::default(),
        }
    }
}

impl<T: Copy + Ord> SlotIndex<T> {
    /// Reserve one reusable heap slot for a live owner; call only on creation (the table grows to the largest slot).
    pub fn register(&mut self, slot: usize) {
        self.heap.register(slot);
    }

    /// Release an owner; a deadline it still holds is dropped.
    pub fn unregister(&mut self, slot: usize) {
        self.heap.unregister(slot);
    }

    /// Update a registered owner. A removed owner may still have a dirty notification; ignore it.
    pub fn set(&mut self, slot: usize, deadline: Option<T>) {
        self.heap.set(slot, deadline);
    }

    /// Earliest `(deadline, slot)`; equal deadlines break on the slot.
    pub fn first(&self) -> Option<(T, usize)> {
        self.heap.first()
    }
}

impl Positions<usize> for Table {
    fn slot_of(&self, slot: &usize) -> Slot {
        match self.positions.get(*slot) {
            None | Some(&UNREGISTERED) => Slot::Unknown,
            Some(&IDLE) => Slot::Idle,
            Some(&position) => Slot::At(position),
        }
    }

    fn store_slot(&mut self, slot: usize, position: Option<usize>) {
        self.positions[slot] = position.unwrap_or(IDLE);
    }

    fn register_key(&mut self, slot: usize) -> bool {
        if slot >= self.positions.len() {
            self.positions.resize(slot + 1, UNREGISTERED);
        }
        if self.positions[slot] != UNREGISTERED {
            return false;
        }
        self.positions[slot] = IDLE;
        self.registered += 1;
        true
    }

    fn drop_key(&mut self, slot: usize) {
        if let Some(p) = self.positions.get_mut(slot)
            && *p != UNREGISTERED
        {
            *p = UNREGISTERED;
            self.registered -= 1;
        }
    }

    fn registered(&self) -> usize {
        self.registered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A repeated `register` of a slot that holds a deadline keeps it.
    #[test]
    fn register_again_keeps_a_queued_deadline() {
        let mut q = SlotIndex::<u32>::default();
        q.register(1);
        q.set(1, Some(5));
        q.register(1);
        assert_eq!(q.first(), Some((5, 1)));
        q.set(1, None);
        assert_eq!(q.first(), None);
    }

    #[test]
    fn slot_updates_match_the_ordered_index() {
        let mut q = SlotIndex::default();
        let mut reference = crate::Index::<usize>::default();
        let mut model = BTreeMap::new();
        for slot in 0..1000 {
            q.register(slot);
            reference.register(slot);
        }
        let mut seed = 13u64;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let slot = ((seed >> 32) % 1000) as usize;
            let d = (seed & 3 != 0).then_some(seed % 1000);
            q.set(slot, d);
            reference.set(slot, d);
            match d {
                Some(d) => model.insert(slot, d),
                None => model.remove(&slot),
            };
            assert_eq!(q.first(), reference.first());
            assert_eq!(q.first(), model.iter().map(|(&k, &d)| (d, k)).min());
        }
        for slot in 0..1000 {
            q.unregister(slot);
        }
        assert_eq!(q.first(), None);
        q.register(7);
        q.set(7, Some(1));
        q.unregister(7);
        q.set(7, Some(2));
        q.set(5000, Some(3));
        assert_eq!(
            q.first(),
            None,
            "removed or unknown slots cannot resurrect deadlines"
        );
    }
}
