// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Send-queue accounting of one connection. Send WRs are mostly unsignaled; a signaled completion (or any error
//! completion: after QP ERR every WR completes) retires all WRs up to its sequence number in posting order, which RC
//! guarantees. Each WR may hold one send-arena slot until it retires. Fixed capacity, no allocation after creation.
//!
//! Zero-copy lease: a WR whose SGE points into registered payload memory (not the arena) may hold a [`Bytes`] reference
//! to that memory ([`SendQueue::lease`]); it is dropped exactly when the WR retires (the HCA has read the bytes), or handed
//! out by [`SendQueue::drain`] when the QP goes away (the caller drops it only after the QP is destroyed). A lease holder
//! counts like a slot holder for the signal rule.
//!
//! Signal rule: every half depth (the queue never fills with WRs that cannot retire), and the last WR of a posting batch
//! (`end`) whenever an unsignaled WR holding a slot or a lease was posted since the last signal. So no slot or lease is
//! ever held by an unsignaled tail: once the sender stops, its slots and leases retire with one completion (`tx`
//! invariant I1). Under streaming a batch ends where credits run out, so this adds about one signal per credit return
//! (half a window, 8 x 64 KiB at the default window): 1 CQE per ~512 KiB.
use bytes::Bytes;
#[cfg(feature = "memory-windows")]
mod read;

/// No slot (inline or credit-only SEND).
pub const NO_SLOT: u32 = u32::MAX;

#[derive(Debug)]
pub struct SendQueue {
    /// Slot per outstanding WR, indexed by sequence number modulo capacity.
    slots: Box<[u32]>,
    /// Zero-copy leases per outstanding WR (same index; a WR has at most two SGEs), dropped when the WR retires.
    leases: Box<[[Option<Bytes>; 2]]>,
    #[cfg(feature = "memory-windows")]
    markers: Box<[Option<crate::completion::Marker>]>,
    #[cfg(feature = "memory-windows")]
    reads: Option<read::ReadLedger>,
    /// Sequence number of the next WR to post.
    next: u32,
    /// Sequence number of the oldest outstanding WR.
    oldest: u32,
    /// Sequence number of the last signaled WR (+1), for the signal interval.
    last_signal: u32,
    /// An unsignaled WR holding a slot was posted after the last signaled WR.
    uncovered: bool,
}

impl SendQueue {
    pub fn new(depth: u32) -> SendQueue {
        // slots are indexed by `seq % depth` and `seq` wraps at 2^32: only a power of two keeps the index continuous there
        assert!(depth >= 2 && depth.is_power_of_two());
        SendQueue {
            slots: vec![NO_SLOT; depth as usize].into_boxed_slice(),
            leases: (0..depth).map(|_| [None, None]).collect(),
            #[cfg(feature = "memory-windows")]
            markers: (0..depth).map(|_| None).collect(),
            #[cfg(feature = "memory-windows")]
            reads: None,
            next: 0,
            oldest: 0,
            last_signal: 0,
            uncovered: false,
        }
    }

    pub fn outstanding(&self) -> u32 {
        self.next.wrapping_sub(self.oldest)
    }

    pub fn full(&self) -> bool {
        self.outstanding() as usize == self.slots.len()
    }

    /// WRs that can still be posted.
    pub fn room(&self) -> u32 {
        self.slots.len() as u32 - self.outstanding()
    }

    /// Record a WR holding `slot`; returns (sequence number, signal it). `end`: the caller posts nothing after it for
    /// now (last WR of a [`crate::tx::Tx::send`] call); signaled if a slot would otherwise stay behind (module docs).
    pub fn push(&mut self, slot: u32, end: bool) -> (u32, bool) {
        self.uncovered |= slot != NO_SLOT;
        self.push_with(slot, end && self.must_cover_tail())
    }

    fn must_cover_tail(&self) -> bool {
        #[cfg(feature = "memory-windows")]
        if self.reads.is_some() {
            return true;
        }
        self.uncovered
    }

    /// Control/credit SENDs hold no payload, but a READ CQ cannot retire their
    /// ordinary SQ positions. Cover them explicitly on READ-prepared queues.
    #[cfg(feature = "verbs")]
    pub(crate) fn push_control(&mut self) -> (u32, bool) {
        #[cfg(feature = "memory-windows")]
        let force = self.reads.is_some();
        #[cfg(not(feature = "memory-windows"))]
        let force = false;
        self.push_with(NO_SLOT, force)
    }

    /// Record a zero-copy WR (no slot; its SGE points into caller memory that a [`SendQueue::lease`] on it or on a later
    /// WR keeps alive); signaled like a slot holder.
    pub fn push_zc(&mut self, end: bool) -> (u32, bool) {
        self.uncovered = true;
        self.push_with(NO_SLOT, end)
    }

    /// Record a WR that may hold a slot and/or point SGEs at leased payload memory (`zc`); returns (sequence number, signal
    /// it). Signaled like [`SendQueue::push`] / [`SendQueue::push_zc`]: at `end` when anything it holds would otherwise
    /// stay behind the last signal.
    pub fn push_wr(&mut self, slot: u32, zc: bool, end: bool) -> (u32, bool) {
        self.uncovered |= zc || slot != NO_SLOT;
        self.push_with(slot, end && self.must_cover_tail())
    }

    /// Keep `b` alive until the last pushed WR retires: the memory of every zero-copy WR posted up to it. That WR must be
    /// covered by a signal (pushed with `end`, or followed by a signaled one) so the lease cannot stay behind.
    pub fn lease(&mut self, b: Bytes) {
        debug_assert!(self.outstanding() > 0);
        self.lease_at(self.next.wrapping_sub(1), b);
    }

    /// Keep `b` alive until WR `seq` retires (the last WR whose SGE points into `b`). At most two leases per WR (its SGEs).
    pub fn lease_at(&mut self, seq: u32, b: Bytes) {
        assert!(!self.retired(seq), "lease on a retired WR");
        let n = self.slots.len() as u32;
        let l = &mut self.leases[(seq % n) as usize];
        let free = l
            .iter_mut()
            .find(|x| x.is_none())
            .expect("two leases per WR");
        *free = Some(b);
    }

    /// Leases held by outstanding WRs.
    pub fn leases(&self) -> usize {
        self.leases.iter().flatten().filter(|l| l.is_some()).count()
    }

    /// Record a WR that is always signaled (the close fence, [`crate::fence`]); returns its sequence number.
    pub fn push_signaled(&mut self, slot: u32) -> u32 {
        self.push_with(slot, true).0
    }

    /// Attach a preallocated typed completion to the last pushed, signalled WR.
    #[cfg(feature = "memory-windows")]
    pub(crate) fn mark(&mut self, marker: crate::completion::Marker) {
        assert!(self.outstanding() > 0);
        debug_assert_eq!(self.last_signal, self.next, "typed work must be signalled");
        let i = (self.next.wrapping_sub(1) % self.slots.len() as u32) as usize;
        assert!(self.markers[i].is_none());
        self.markers[i] = Some(marker);
    }

    fn push_with(&mut self, slot: u32, force: bool) -> (u32, bool) {
        debug_assert!(!self.full());
        let seq = self.next;
        let n = self.slots.len() as u32;
        self.slots[(seq % n) as usize] = slot;
        self.next = seq.wrapping_add(1);
        let signal = force || self.next.wrapping_sub(self.last_signal) >= n / 2;
        if signal {
            self.last_signal = self.next;
            self.uncovered = false;
        }
        (seq, signal)
    }

    /// No slot is held by a WR behind the last signaled one (`tx` invariant I1).
    pub fn covered(&self) -> bool {
        !self.uncovered
    }

    /// WR `seq` (posted earlier) is retired: completed itself or covered by a later completion.
    pub fn retired(&self, seq: u32) -> bool {
        seq.wrapping_sub(self.oldest) >= self.outstanding()
    }

    /// Retire every outstanding WR (the QP is being destroyed, the HCA may still read): `free` gets each held slot,
    /// `lease` each held lease; the caller releases both only after the QP is gone.
    pub fn drain(&mut self, mut free: impl FnMut(u32), mut lease: impl FnMut(Bytes)) {
        #[cfg(feature = "memory-windows")]
        if let Some(reads) = self.reads.take() {
            reads.fail();
        }
        if self.outstanding() > 0 {
            self.retire(self.next.wrapping_sub(1), &mut free, &mut lease, false);
        }
    }

    /// WR `seq` completed: retire it and every older WR; `free` gets each held slot, their leases are dropped (the HCA
    /// has read the memory).
    pub fn complete(&mut self, seq: u32, mut free: impl FnMut(u32)) {
        self.retire(seq, &mut free, &mut drop::<Bytes>, true);
    }

    /// Fail observers after a connection fault without releasing any slot/source that the NIC may still access.
    #[cfg(feature = "memory-windows")]
    pub(crate) fn fail_markers(&mut self) {
        if let Some(reads) = &self.reads {
            reads.fail();
        }
        for marker in self.markers.iter_mut().filter_map(Option::take) {
            marker.finish(false);
        }
    }

    /// Provider completion status applies to typed owners retired by this CQE; failures never grant reuse.
    #[cfg(feature = "memory-windows")]
    pub(crate) fn complete_status(&mut self, seq: u32, free: impl FnMut(u32), success: bool) {
        self.retire(seq, &mut { free }, &mut drop::<Bytes>, success);
    }

    fn retire(
        &mut self,
        seq: u32,
        free: &mut impl FnMut(u32),
        lease: &mut impl FnMut(Bytes),
        _success: bool,
    ) {
        #[cfg(feature = "memory-windows")]
        if let Some(mut reads) = self.reads.take() {
            reads.complete(self, seq, free, lease, _success);
            self.reads = Some(reads);
            return;
        }
        let n = self.slots.len() as u32;
        if self.retired(seq) {
            return; // already retired (an error completion of an older WR after a later signaled one)
        }
        while self.oldest != seq.wrapping_add(1) {
            let i = (self.oldest % n) as usize;
            let s = self.slots[i];
            if s != NO_SLOT {
                free(s);
            }
            for b in self.leases[i].iter_mut().filter_map(Option::take) {
                lease(b);
            }
            #[cfg(feature = "memory-windows")]
            if let Some(marker) = self.markers[i].take() {
                marker.finish(_success);
            }
            self.oldest = self.oldest.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals_and_retires_in_order() {
        let mut q = SendQueue::new(8);
        let mut sig = Vec::new();
        for s in 0..8 {
            let (seq, signal) = q.push(if s % 2 == 0 { s } else { NO_SLOT }, false);
            if signal {
                sig.push(seq);
            }
        }
        assert!(q.full());
        assert_eq!(sig, vec![3, 7]);
        let mut freed = Vec::new();
        q.complete(3, |s| freed.push(s));
        assert_eq!(freed, vec![0, 2]);
        assert_eq!(q.outstanding(), 4);
        q.complete(2, |s| freed.push(s));
        assert_eq!(freed.len(), 2, "stale completion ignored");
        q.complete(7, |s| freed.push(s));
        assert_eq!(freed, vec![0, 2, 4, 6]);
        assert_eq!(q.outstanding(), 0);
    }

    #[test]
    fn batch_end_signals_only_when_a_slot_would_stay_behind() {
        let mut q = SendQueue::new(256);
        assert_eq!(q.push(NO_SLOT, true), (0, false), "nothing held");
        assert_eq!(q.push(5, false), (1, false));
        assert!(!q.covered());
        assert_eq!(q.push(NO_SLOT, true), (2, true), "inline end covers slot 5");
        assert!(q.covered());
        assert_eq!(q.push(6, true), (3, true));
        let mut freed = Vec::new();
        q.complete(3, |s| freed.push(s));
        assert_eq!((freed, q.outstanding()), (vec![5, 6], 0));
    }

    #[test]
    #[should_panic]
    fn depth_must_be_a_power_of_two() {
        SendQueue::new(6);
    }

    #[test]
    fn sequence_wraps() {
        let mut q = SendQueue::new(4);
        q.next = u32::MAX - 1;
        q.oldest = u32::MAX - 1;
        q.last_signal = u32::MAX - 1;
        let a = q.push(1, false).0;
        let b = q.push(2, false).0;
        let c = q.push(3, false).0;
        assert_eq!((a, b, c), (u32::MAX - 1, u32::MAX, 0));
        let mut freed = Vec::new();
        q.complete(c, |s| freed.push(s));
        assert_eq!(freed, vec![1, 2, 3]);
        q.push(4, false);
        q.drain(|s| freed.push(s), drop);
        assert_eq!((freed.len(), q.outstanding()), (4, 0));
    }
    #[cfg(feature = "memory-windows")]
    #[test]
    fn typed_marker_retires_with_sends_and_never_aliases_wrapped_sequences() {
        use crate::completion::{BINDING, BOUND, FAILED, Marker};
        use std::sync::{
            Arc,
            atomic::{AtomicU8, Ordering},
        };
        let mut q = SendQueue::new(4);
        q.next = u32::MAX;
        q.oldest = u32::MAX;
        q.last_signal = u32::MAX;
        q.push(7, false);
        let first = Arc::new(AtomicU8::new(BINDING));
        let seq = q.push_signaled(NO_SLOT);
        assert_eq!(seq, 0);
        q.mark(Marker {
            state: first.clone(),
            ready: BOUND,
            retire_qp: None,
            source: None,
        });
        let mut free = Vec::new();
        q.complete_status(u32::MAX, |s| free.push(s), true);
        assert_eq!(first.load(Ordering::Acquire), BINDING);
        q.complete_status(seq, |s| free.push(s), true);
        assert_eq!(first.load(Ordering::Acquire), BOUND);
        assert_eq!(free, vec![7]);
        // Model a later full wrap after all earlier WRs retired; the old handle's marker is independent of seq 0.
        q.next = 0;
        q.oldest = 0;
        q.last_signal = 0;
        let second = Arc::new(AtomicU8::new(BINDING));
        let seq = q.push_signaled(NO_SLOT);
        q.mark(Marker {
            state: second.clone(),
            ready: BOUND,
            retire_qp: None,
            source: None,
        });
        q.complete_status(seq, |_| {}, false);
        assert_eq!(second.load(Ordering::Acquire), FAILED);
        assert_eq!(first.load(Ordering::Acquire), BOUND);
    }

    #[cfg(feature = "memory-windows")]
    #[test]
    fn later_send_completion_retires_typed_work_and_drain_marks_failure() {
        use crate::completion::{BINDING, BOUND, FAILED, Marker};
        use std::sync::{
            Arc,
            atomic::{AtomicU8, Ordering},
        };
        let mut q = SendQueue::new(8);
        let state = Arc::new(AtomicU8::new(BINDING));
        q.push_signaled(NO_SLOT);
        q.mark(Marker {
            state: state.clone(),
            ready: BOUND,
            retire_qp: None,
            source: None,
        });
        let later = q.push_signaled(3);
        let mut free = Vec::new();
        q.complete_status(later, |s| free.push(s), true);
        assert_eq!(free, vec![3]);
        assert_eq!(state.load(Ordering::Acquire), BOUND);
        q.complete_status(later, |_| panic!("no double free"), false);
        assert_eq!(
            state.load(Ordering::Acquire),
            BOUND,
            "old errors cannot rewrite a retired marker"
        );
        let state = Arc::new(AtomicU8::new(BINDING));
        q.push_signaled(NO_SLOT);
        q.mark(Marker {
            state: state.clone(),
            ready: BOUND,
            retire_qp: None,
            source: None,
        });
        q.drain(|_| {}, drop);
        assert_eq!(state.load(Ordering::Acquire), FAILED);
    }
}
