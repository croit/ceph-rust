// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Optional mixed-SQ accounting. READ completion is exact; ordinary prefixes
//! skip READ holes. Capacity is reclaimed only through contiguous done entries.
use super::{NO_SLOT, SendQueue};
use crate::completion::{FAILED, READ_DONE, READ_PENDING};
use bytes::Bytes;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

#[derive(Debug, Default)]
struct Entry {
    read: bool,
    done: bool,
    state: Option<Arc<AtomicU8>>,
}

#[derive(Debug)]
pub(super) struct ReadLedger {
    entries: Box<[Entry]>,
    /// Exclusive ordinary prefix already accounted, including skipped READs.
    covered: u32,
    pending: u32,
}

impl SendQueue {
    /// Control operation before any WR is posted. SEND-only queues allocate no
    /// READ ledger. Its fixed capacity is shared with all ordinary SQ work.
    pub(crate) fn enable_reads(&mut self) {
        assert_eq!(self.outstanding(), 0);
        assert!(self.reads.is_none());
        self.reads = Some(ReadLedger {
            entries: (0..self.slots.len()).map(|_| Entry::default()).collect(),
            covered: self.next,
            pending: 0,
        });
    }

    pub(crate) fn pending_reads(&self) -> u32 {
        self.reads.as_ref().map_or(0, |r| r.pending)
    }

    pub(crate) fn next_sequence(&self) -> u32 {
        self.next
    }

    /// Commit an accepted, always-signalled READ. Its CQ never substitutes for
    /// ordinary tail signalling: preserve both ordinary signal bookkeeping fields.
    pub(crate) fn push_read(&mut self, state: Arc<AtomicU8>) -> u32 {
        let (uncovered, last_signal) = (self.uncovered, self.last_signal);
        let seq = self.push_signaled(NO_SLOT);
        self.uncovered = uncovered;
        self.last_signal = last_signal;
        let reads = self.reads.as_mut().expect("READ-prepared SQ");
        let i = seq as usize % reads.entries.len();
        assert!(!reads.entries[i].read && !reads.entries[i].done);
        reads.entries[i] = Entry {
            read: true,
            done: false,
            state: Some(state),
        };
        reads.pending += 1;
        seq
    }
}

impl ReadLedger {
    pub(super) fn fail(&self) {
        for state in self.entries.iter().filter_map(|e| e.state.as_ref()) {
            let _ =
                state.compare_exchange(READ_PENDING, FAILED, Ordering::Release, Ordering::Relaxed);
        }
    }

    pub(super) fn complete(
        &mut self,
        sq: &mut SendQueue,
        seq: u32,
        free: &mut impl FnMut(u32),
        lease: &mut impl FnMut(Bytes),
        success: bool,
    ) {
        if sq.retired(seq) {
            return;
        }
        let n = self.entries.len() as u32;
        let entry = &mut self.entries[(seq % n) as usize];
        if entry.read {
            if let Some(state) = entry.state.take() {
                // Remove the old attempt's reference before publishing ready:
                // the same prepared owner may immediately be reused elsewhere.
                self.pending -= 1;
                entry.done = true;
                let next = if success { READ_DONE } else { FAILED };
                let _ = state.compare_exchange(
                    READ_PENDING,
                    next,
                    Ordering::Release,
                    Ordering::Relaxed,
                );
            }
        } else if seq.wrapping_sub(self.covered) < sq.next.wrapping_sub(self.covered) {
            // Each ordinary entry is visited once, even across many READ holes.
            while self.covered != seq.wrapping_add(1) {
                let i = (self.covered % n) as usize;
                if !self.entries[i].read {
                    let slot = std::mem::replace(&mut sq.slots[i], NO_SLOT);
                    if slot != NO_SLOT {
                        free(slot);
                    }
                    for b in sq.leases[i].iter_mut().filter_map(Option::take) {
                        lease(b);
                    }
                    if let Some(marker) = sq.markers[i].take() {
                        marker.finish(success);
                    }
                    self.entries[i].done = true;
                }
                self.covered = self.covered.wrapping_add(1);
            }
        }
        while sq.oldest != sq.next {
            let i = (sq.oldest % n) as usize;
            if !self.entries[i].done {
                break;
            }
            self.entries[i] = Entry::default();
            if self.covered == sq.oldest {
                self.covered = self.covered.wrapping_add(1);
            }
            sq.oldest = sq.oldest.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> Arc<AtomicU8> {
        Arc::new(AtomicU8::new(READ_PENDING))
    }

    #[test]
    fn ordinary_completion_cannot_release_read_or_reuse_its_position() {
        let mut sq = SendQueue::new(4);
        sq.enable_reads();
        let owner = state();
        let read = sq.push_read(owner.clone());
        let ordinary = sq.push(7, true).0;
        let mut freed = Vec::new();
        sq.complete(ordinary, |s| freed.push(s));
        assert_eq!(freed, [7]);
        assert_eq!(owner.load(Ordering::Acquire), READ_PENDING);
        assert_eq!(sq.outstanding(), 2);
        assert!(!sq.retired(read));
        sq.complete(read, |_| panic!("already freed"));
        assert_eq!(owner.load(Ordering::Acquire), READ_DONE);
        assert_eq!(sq.outstanding(), 0);
        assert_eq!(sq.pending_reads(), 0);
    }

    #[test]
    fn exact_read_cq_does_not_hide_an_ordinary_unsignalled_tail() {
        let mut sq = SendQueue::new(8);
        sq.enable_reads();
        let ordinary = sq.push(3, false).0;
        let read = sq.push_read(state());
        assert!(!sq.covered());
        sq.complete(read, |_| panic!("READ does not retire ordinary work"));
        assert!(!sq.retired(ordinary));
        let (end, signal) = sq.push(NO_SLOT, true);
        assert!(signal);
        let mut freed = Vec::new();
        sq.complete(end, |s| freed.push(s));
        assert_eq!(freed, [3]);
        assert_eq!(sq.outstanding(), 0);
    }

    #[test]
    fn read_holes_survive_wrap_duplicates_and_owner_reuse() {
        let mut sq = SendQueue::new(4);
        sq.next = u32::MAX - 1;
        sq.oldest = sq.next;
        sq.last_signal = sq.next;
        sq.enable_reads();
        let a = state();
        let b = state();
        let first = sq.push_read(a.clone());
        let second = sq.push_read(b.clone());
        let ordinary = sq.push(8, true).0;
        sq.complete(second, |_| panic!());
        assert_eq!(b.load(Ordering::Acquire), READ_DONE);
        b.store(READ_PENDING, Ordering::Release); // reused by another connection
        sq.complete(second, |_| panic!("duplicate"));
        sq.complete(ordinary, |_| {});
        assert_eq!(sq.outstanding(), 3);
        sq.complete(first, |_| panic!());
        assert_eq!(sq.outstanding(), 0);
        sq.fail_markers();
        assert_eq!(b.load(Ordering::Acquire), READ_PENDING);
        for _ in 0..8 {
            let seq = sq.push_read(state());
            sq.complete(seq, |_| panic!());
            assert_eq!(sq.outstanding(), 0);
        }
    }

    #[test]
    fn failed_read_cannot_be_published_by_later_success_and_drain_is_exact_once() {
        let mut sq = SendQueue::new(4);
        sq.enable_reads();
        let owner = state();
        let read = sq.push_read(owner.clone());
        let ordinary = sq.push(9, true).0;
        sq.complete(ordinary, |s| assert_eq!(s, 9));
        sq.fail_markers();
        sq.complete(read, |_| panic!());
        assert_eq!(owner.load(Ordering::Acquire), FAILED);
        let pending = state();
        sq.push_read(pending.clone());
        sq.push(10, true);
        let mut freed = Vec::new();
        sq.drain(|s| freed.push(s), drop);
        assert_eq!(freed, [10]);
        assert_eq!(pending.load(Ordering::Acquire), FAILED);
        assert_eq!(sq.outstanding(), 0);
    }

    #[test]
    fn read_mode_covers_credit_and_inline_tails_without_changing_send_only() {
        let mut ordinary = SendQueue::new(8);
        assert!(!ordinary.push_control().1);
        assert!(!ordinary.push_wr(NO_SLOT, false, true).1);
        let mut mixed = SendQueue::new(8);
        mixed.enable_reads();
        let (credit, signalled) = mixed.push_control();
        assert!(signalled);
        let read = mixed.push_read(state());
        mixed.complete(read, |_| panic!());
        mixed.complete(credit, |_| panic!());
        assert_eq!(mixed.outstanding(), 0);
        let (inline, signalled) = mixed.push_wr(NO_SLOT, false, true);
        assert!(signalled);
        mixed.complete(inline, |_| panic!());
        assert_eq!(mixed.outstanding(), 0);
    }

    #[test]
    fn every_mixed_completion_permutation_preserves_exact_read_and_capacity() {
        fn permutations(order: &mut [u32; 6], start: usize) {
            if start != order.len() {
                for i in start..order.len() {
                    order.swap(start, i);
                    permutations(order, start + 1);
                    order.swap(start, i);
                }
                return;
            }
            let mut sq = SendQueue::new(8);
            sq.enable_reads();
            let owners = [state(), state(), state()];
            for (i, owner) in owners.iter().enumerate() {
                assert_eq!(sq.push_read(owner.clone()), i as u32 * 2);
                assert_eq!(sq.push(i as u32, true).0, i as u32 * 2 + 1);
            }
            let mut seen = [false; 6];
            let mut freed = [0; 3];
            for &seq in order.iter() {
                seen[seq as usize] = true;
                sq.complete(seq, |slot| freed[slot as usize] += 1);
                // Independent contract oracle: READs need their own CQ; an
                // ordinary entry needs any ordinary CQ at or beyond itself.
                let proved: [bool; 6] = std::array::from_fn(|i| {
                    if i % 2 == 0 {
                        seen[i]
                    } else {
                        (i..6).any(|j| j % 2 == 1 && seen[j])
                    }
                });
                let first_unproved = proved.iter().position(|p| !p).unwrap_or(6);
                assert_eq!(
                    sq.outstanding(),
                    (6 - first_unproved) as u32,
                    "{order:?} at {seq}"
                );
                for i in 0..3 {
                    assert_eq!(owners[i].load(Ordering::Acquire) == READ_DONE, seen[i * 2]);
                    assert_eq!(freed[i], u32::from(proved[i * 2 + 1]));
                }
            }
            assert_eq!(sq.pending_reads(), 0);
            assert_eq!(sq.outstanding(), 0);
        }
        permutations(&mut [0, 1, 2, 3, 4, 5], 0);
    }
}
