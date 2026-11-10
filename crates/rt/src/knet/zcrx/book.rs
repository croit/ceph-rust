// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Lease and refill accounting of one zcrx core (doc/spec/knet-zcrx.md sections 3, 4). Pure bookkeeping, no kernel
//! calls, so the rules are testable anywhere.
//!
//! A fragment the kernel delivered is either consumed at once (copied into the decoder or a lent segment buffer) and
//! refilled in the same loop iteration, or *held*: the connection's input is throttled (`Driver::input_ready` false),
//! so the fragment waits. A held fragment stays in the area (a lease) while the held area bytes fit the lease budget;
//! beyond it the fragment is copied into owned memory and refilled at once, so the area never runs dry because of the
//! OSD (pressure degrades to copy speed, never to a stall). The budget is the area minus what the kernel needs to keep
//! the queue going: the NIC ring's posted chunks plus one socket's receive queue.
use std::collections::VecDeque;

/// Area sizing and lease budget of one zcrx queue (all bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizing {
    pub area: usize,
    pub budget: usize,
}

/// `ring_bytes`: NIC rx ring entries x chunk; `rmem`: one socket's receive queue ceiling (`tcp_rmem` max). The kernel
/// side (`ring_bytes + rmem`) is the reserve; the area is twice it (the same again for leases), rounded to whole chunks
/// and at most `max_chunks` chunks (one refill entry per chunk; the kernel caps the refill ring). The area is transport
/// memory like the copy path's buffer ring and hold storage, whose roles it takes over; it is not drawn from the ingress
/// pools (adr 0175) because phase 1 copies every fragment out before the OSD owns its bytes (leases into the store
/// are phase 2, open point O4, and charge the pools there).
pub fn sizing(ring_bytes: usize, rmem: usize, chunk: usize, max_chunks: usize) -> Sizing {
    let reserve = ring_bytes + rmem;
    let chunk = chunk.max(1);
    let area = (2 * reserve)
        .next_multiple_of(chunk)
        .min(max_chunks * chunk);
    Sizing {
        area,
        budget: area.saturating_sub(reserve),
    }
}

/// One held fragment of a connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Held {
    /// Still in the area (refilled when it is consumed).
    Area { off: u64, len: u32 },
    /// Copied out because the lease budget was used up (the area chunk went back at once).
    Owned(Vec<u8>),
}

impl Held {
    pub fn bytes(&self) -> usize {
        match self {
            Held::Area { len, .. } => *len as usize,
            Held::Owned(v) => v.len(),
        }
    }
}

/// Held-bytes accounting of a core.
#[derive(Debug, Default)]
pub struct Book {
    budget: usize,
    /// Area bytes held now.
    held: usize,
    /// Highest `held` seen.
    pub held_max: usize,
    /// Bytes copied out because the budget was used up.
    pub converted: u64,
}

impl Book {
    pub fn new(budget: usize) -> Book {
        Book {
            budget,
            ..Book::default()
        }
    }

    /// May a fragment of `len` bytes stay in the area? False = copy it out (counted) and refill it now.
    pub fn lease(&mut self, len: usize) -> bool {
        if self.held + len > self.budget {
            self.converted += len as u64;
            return false;
        }
        self.held += len;
        self.held_max = self.held_max.max(self.held);
        true
    }

    /// A leased fragment was consumed (and is refilled by the caller).
    pub fn release(&mut self, len: usize) {
        debug_assert!(len <= self.held);
        self.held -= len;
    }

    pub fn held(&self) -> usize {
        self.held
    }
}

/// Producer side of the refill ring: entries are written as fragments come back, the tail is published once per loop
/// iteration (one release store instead of one per fragment). One entry per delivered fragment; the kernel consumes
/// entries when its page pool refills, so a full ring keeps the rest in a local backlog until the head moves.
#[derive(Debug, Default)]
pub struct Refill {
    tail: u32,
    unpublished: u32,
    /// Entries written / publishes so far.
    pub entries: u64,
    pub batches: u64,
}

impl Refill {
    /// Free entries of a ring of `size` entries whose consumer is at `head`.
    pub fn room(&self, head: u32, size: u32) -> u32 {
        size - self.tail.wrapping_sub(head)
    }

    /// Index of the next entry (the caller writes it before the next `publish`).
    pub fn take_slot(&mut self) -> u32 {
        let i = self.tail;
        self.tail = self.tail.wrapping_add(1);
        self.unpublished += 1;
        self.entries += 1;
        i
    }

    /// The tail to publish, if entries were written since the last call.
    pub fn publish(&mut self) -> Option<u32> {
        if self.unpublished == 0 {
            return None;
        }
        self.unpublished = 0;
        self.batches += 1;
        Some(self.tail)
    }
}

/// Held fragments of one connection, in stream order.
#[derive(Debug, Default)]
pub struct Pending {
    q: VecDeque<Held>,
    bytes: usize,
}

impl Pending {
    pub fn push(&mut self, h: Held) {
        self.bytes += h.bytes();
        self.q.push_back(h);
    }
    pub fn pop(&mut self) -> Option<Held> {
        let h = self.q.pop_front()?;
        self.bytes -= h.bytes();
        Some(h)
    }
    /// Put a partly consumed fragment back at the front.
    pub fn unpop(&mut self, h: Held) {
        self.bytes += h.bytes();
        self.q.push_front(h);
    }
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizing_keeps_the_kernel_reserve() {
        // twice the reserve, half stays for the kernel
        let s = sizing(2048 * 4096, 6 << 20, 4096, 32768);
        assert_eq!(s.area, 2 * (2048 * 4096 + (6 << 20)));
        assert_eq!(s.area - s.budget, 2048 * 4096 + (6 << 20));
        // whole chunks
        let s = sizing(0, 4097, 4096, 32768);
        assert_eq!((s.area, s.budget), (12288, 12288 - 4097));
        // capped by the refill ring
        let s = sizing(64 << 20, 6 << 20, 4096, 32768);
        assert_eq!(s.area, 128 << 20);
        // reserve above the cap: nothing may be leased
        let s = sizing(100 << 20, 60 << 20, 4096, 32768);
        assert_eq!((s.area, s.budget), (128 << 20, 0));
    }

    #[test]
    fn lease_budget_converts_beyond_it() {
        let mut b = Book::new(10_000);
        assert!(b.lease(4096));
        assert!(b.lease(4096));
        assert!(!b.lease(4096), "third chunk exceeds the budget");
        assert_eq!(b.converted, 4096);
        assert_eq!(b.held(), 8192);
        b.release(4096);
        assert!(b.lease(1000));
        assert_eq!(b.held(), 5096);
        assert_eq!(b.held_max, 8192);
        b.release(4096);
        b.release(1000);
        assert_eq!(b.held(), 0);
    }

    #[test]
    fn zero_budget_copies_everything() {
        let mut b = Book::new(0);
        assert!(!b.lease(1));
        assert_eq!(b.held(), 0);
        assert_eq!(b.converted, 1);
    }

    #[test]
    fn refill_publishes_once_per_batch_and_wraps() {
        let mut r = Refill {
            tail: u32::MAX - 1,
            ..Refill::default()
        };
        assert_eq!(r.publish(), None);
        assert_eq!(r.take_slot(), u32::MAX - 1);
        assert_eq!(r.take_slot(), u32::MAX);
        assert_eq!(r.take_slot(), 0);
        assert_eq!(r.publish(), Some(1));
        assert_eq!(r.publish(), None);
        assert_eq!((r.entries, r.batches), (3, 1));
        // the kernel consumed up to u32::MAX: two entries in flight of a 4-entry ring
        assert_eq!(r.room(u32::MAX, 4), 2);
        assert_eq!(r.room(1, 4), 4);
    }

    #[test]
    fn pending_keeps_order_and_bytes() {
        let mut p = Pending::default();
        p.push(Held::Area { off: 0, len: 100 });
        p.push(Held::Owned(vec![1; 50]));
        assert_eq!(p.bytes(), 150);
        let h = p.pop().unwrap();
        assert_eq!(h, Held::Area { off: 0, len: 100 });
        p.unpop(Held::Area { off: 60, len: 40 });
        assert_eq!(p.bytes(), 90);
        assert_eq!(p.pop(), Some(Held::Area { off: 60, len: 40 }));
        assert_eq!(p.pop(), Some(Held::Owned(vec![1; 50])));
        assert!(p.is_empty());
        assert_eq!(p.bytes(), 0);
    }
}
