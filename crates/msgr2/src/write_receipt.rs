// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Bounded application receipts for exact socket-write completion.
use std::cell::Cell;
use std::rc::Rc;

/// Socket acceptance differs from peer acknowledgement and queue acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStatus {
    Pending,
    Written,
    /// The messenger session discarded this message before its write completed.
    Discarded,
}
#[derive(Debug, Clone, Copy)]
struct State {
    generation: u64,
    leased: bool,
    status: WriteStatus,
    next_free: Option<usize>,
}
#[derive(Debug, Clone)]
pub(crate) struct WriteToken {
    slot: Rc<Cell<State>>,
    generation: u64,
}
impl WriteToken {
    pub(crate) fn pending(&self) -> bool {
        let state = self.slot.get();
        state.generation == self.generation && state.leased && state.status == WriteStatus::Pending
    }
    pub(crate) fn complete(&self, status: WriteStatus) {
        let mut state = self.slot.get();
        if state.generation == self.generation && state.status == WriteStatus::Pending {
            state.status = status;
            self.slot.set(state);
        }
    }
}
/// A message's write receipt, valid across lossless messenger carrier replacement.
/// Dropping it returns its startup-sized tracking slot. Replayed messages cannot
/// complete a slot reused by a later receipt. No payload is retained here.
/// `Written` means the final wire byte was accepted by the socket, or the peer
/// acknowledged the message sequence (which proves delivery even if a carrier
/// reset lost local write accounting). Session reset/disposal completes any
/// remaining pending receipt as `Discarded`; lossless replay keeps it pending.
#[derive(Debug)]
pub struct WriteReceipt(pub(crate) WriteToken, Rc<Cell<Option<usize>>>, usize);
impl WriteReceipt {
    pub fn status(&self) -> WriteStatus {
        self.0.slot.get().status
    }
}
impl Drop for WriteReceipt {
    fn drop(&mut self) {
        let mut state = self.0.slot.get();
        state.leased = false;
        // Exhausted generations retire permanently rather than blocking other
        // free slots or allowing an old replay token to complete a new receipt.
        if state.generation != u64::MAX {
            state.next_free = self.1.replace(Some(self.2));
        }
        self.0.slot.set(state);
    }
}
#[derive(Debug, Default)]
pub(crate) struct WritePool {
    slots: Vec<Rc<Cell<State>>>,
    // Intrusive free stack: taking/returning a receipt touches one slot and
    // allocates nothing. Receipts keep the head alive if they outlive the pool.
    free: Option<Rc<Cell<Option<usize>>>>,
    #[cfg(test)]
    take_probes: Cell<usize>,
}
impl WritePool {
    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }
    pub(crate) fn configure(&mut self, capacity: usize) -> bool {
        if !self.slots.is_empty() {
            return self.slots.len() == capacity;
        }
        self.slots = (0..capacity)
            .map(|index| {
                Rc::new(Cell::new(State {
                    generation: 0,
                    leased: false,
                    status: WriteStatus::Discarded,
                    next_free: (index + 1 < capacity).then_some(index + 1),
                }))
            })
            .collect();
        self.free = Some(Rc::new(Cell::new((capacity != 0).then_some(0))));
        true
    }
    pub(crate) fn take(&self) -> Option<WriteReceipt> {
        let free = self.free.as_ref()?;
        let index = free.get()?;
        let slot = &self.slots[index];
        #[cfg(test)]
        self.take_probes.set(self.take_probes.get() + 1);
        let mut state = slot.get();
        state.generation = state.generation.checked_add(1)?;
        free.set(state.next_free);
        state.next_free = None;
        state.leased = true;
        state.status = WriteStatus::Pending;
        slot.set(state);
        Some(WriteReceipt(
            WriteToken {
                slot: slot.clone(),
                generation: state.generation,
            },
            free.clone(),
            index,
        ))
    }
}
impl Drop for WritePool {
    fn drop(&mut self) {
        for slot in &self.slots {
            let mut state = slot.get();
            if state.status == WriteStatus::Pending {
                state.status = WriteStatus::Discarded;
                slot.set(state);
            }
        }
    }
}

/// Admission refusal retaining ownership of the original message.
#[derive(Debug)]
pub enum SendError {
    /// Connection readiness or bounded queue/receipt pressure; retry is possible.
    Temporary(crate::Message),
    /// The message cannot fit the connection's configured frame limits.
    FrameLimit(crate::Message),
}
impl SendError {
    pub fn into_message(self) -> crate::Message {
        match self {
            Self::Temporary(message) | Self::FrameLimit(message) => message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_admission_probes_are_linear_for_fill_pressure_and_reuse() {
        for capacity in [64, 4096, 1] {
            let mut pool = WritePool::default();
            assert!(pool.configure(capacity));
            let mut receipts: Vec<_> = (0..capacity).map(|_| pool.take().unwrap()).collect();
            assert_eq!(pool.take_probes.get(), capacity, "initial fill");
            for _ in 0..capacity {
                assert!(pool.take().is_none());
            }
            assert_eq!(
                pool.take_probes.get(),
                capacity,
                "full admission touches no slot"
            );
            // Release slots in a different order from admission, then refill.
            receipts.reverse();
            receipts.clear();
            receipts.extend((0..capacity).map(|_| pool.take().unwrap()));
            assert_eq!(pool.take_probes.get(), 2 * capacity, "refill");
            assert!(receipts.iter().all(|r| r.status() == WriteStatus::Pending));
        }
    }

    #[test]
    fn receipt_reuse_rejects_old_replay_token_and_pool_drop_discards() {
        let mut pool = WritePool::default();
        assert!(pool.configure(1));
        let first = pool.take().unwrap();
        let replay = first.0.clone();
        replay.complete(WriteStatus::Written);
        assert_eq!(first.status(), WriteStatus::Written);
        assert!(
            pool.take().is_none(),
            "completion does not release a live receipt"
        );
        drop(first);
        let next = pool.take().unwrap();
        replay.complete(WriteStatus::Written);
        assert!(!replay.pending());
        assert_eq!(next.status(), WriteStatus::Pending);
        assert!(pool.configure(1));
        assert!(!pool.configure(2));
        assert!(pool.take().is_none());
        drop(pool);
        assert_eq!(next.status(), WriteStatus::Discarded);
        // The receipt may outlive its pool and an old replay token.
        drop((next, replay));
    }

    #[test]
    fn exhausted_receipt_slot_retires_without_blocking_other_slots() {
        let mut pool = WritePool::default();
        assert!(pool.configure(2));
        let mut state = pool.slots[0].get();
        state.generation = u64::MAX - 1;
        pool.slots[0].set(state);
        let last = pool.take().unwrap();
        let old = last.0.clone();
        drop(last);
        let other = pool.take().unwrap();
        assert!(pool.take().is_none());
        old.complete(WriteStatus::Written);
        assert_eq!(other.status(), WriteStatus::Pending);
        drop(other);
        assert!(pool.take().is_some());
    }
}
