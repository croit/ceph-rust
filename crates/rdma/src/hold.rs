// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Receive throttling of one connection (0469-rdma-transport, design D7): while the upper layer cannot take input, the
//! connection HOLDS its completed receive slots. A held slot is neither delivered nor re-posted, so no credit is owed
//! for it and the peer runs out of credits: backpressure without touching the other connections of the core.
//!
//! Invariant: the peer posts at most `window` SENDs (data and credit-only) before credits come back, and only data
//! SENDs are held (credit-only ones are consumed and re-posted at once), so at most `window` slots are held per
//! connection. The queue is sized to the window up front and never grows; an overflow is a peer protocol violation
//! (session fault), not a reason to allocate. Slots are held in arrival order and released in that order, so the stream
//! stays in order across pause and resume.
//!
//! Lending (client receive helpers, 0469-rdma-transport "Client receive threading"): held bytes from the front may be
//! lent to another thread ([`Hold::lend`]); a lent slot stays held (not re-posted, not replayed) until [`Hold::settle`]
//! consumes its lent bytes. A lend grows while open (newer held bytes are appended) and is consumed from the front step
//! by step, so slots return while the borrower still works on later ones; [`Hold::unlend`] ends it and holds what was not
//! consumed again. The front slot may be partly consumed (`off`): a lend can end inside a slot.

/// What the upper layer asks of the receive path after it saw a data slot, answered from inside the poll so the rest of
/// the same completion batch is held by the connection instead of being copied by the upper layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Flow {
    /// The slot was taken; keep delivering.
    #[default]
    Go,
    /// The slot was taken (or copied out); hold every later data slot of this connection ([`Hold::pause`]).
    Pause,
    /// The slot was not taken: hold it and every later one, no copy ([`Hold::pause`], [`Hold::push`]).
    Keep,
}

/// More slots held than the window: the peer ignored its credits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// Slots (receive slot index, byte length) of one connection that arrived while it was paused, oldest first.
#[derive(Debug)]
pub struct Hold {
    q: Box<[(u32, u32)]>,
    head: u32,
    len: u32,
    paused: bool,
    /// Bytes of the front slot already consumed.
    off: u32,
    /// Bytes lent from the front (after `off`), 0 = no lend open.
    lent: u32,
}

impl Hold {
    /// Room for `window` held slots.
    pub fn new(window: u32) -> Hold {
        assert!(window > 0);
        Hold {
            q: vec![(0, 0); window as usize].into_boxed_slice(),
            head: 0,
            len: 0,
            paused: false,
            off: 0,
            lent: 0,
        }
    }

    pub fn paused(&self) -> bool {
        self.paused
    }

    /// Hold arriving data slots from now on (idempotent).
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Stop holding; the caller drains with [`Hold::pop`] before it handles newer arrivals.
    pub fn resume(&mut self) {
        self.paused = false;
    }

    /// Slots held right now.
    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Keep a completed data slot. Only called while paused or while older slots are still queued.
    pub fn push(&mut self, slot: u32, len: u32) -> Result<(), Full> {
        let n = self.q.len() as u32;
        if self.len == n {
            return Err(Full);
        }
        self.q[((self.head + self.len) % n) as usize] = (slot, len);
        self.len += 1;
        Ok(())
    }

    /// Oldest held slot, left in place: (slot, bytes of it already consumed, byte length).
    pub fn front(&self) -> Option<(u32, u32, u32)> {
        (self.len != 0).then(|| {
            let (slot, len) = self.q[self.head as usize];
            (slot, self.off, len)
        })
    }

    /// Oldest held slot (whole, whatever of it was consumed).
    pub fn pop(&mut self) -> Option<(u32, u32)> {
        if self.len == 0 {
            return None;
        }
        let v = self.q[self.head as usize];
        self.lent = self.lent.saturating_sub(v.1 - self.off);
        self.off = 0;
        self.head = (self.head + 1) % self.q.len() as u32;
        self.len -= 1;
        Some(v)
    }

    /// Bytes lent now (0 = no lend open).
    pub fn lent(&self) -> u32 {
        self.lent
    }

    /// Lend held bytes not lent yet (those after the lent ones; a lend grows while open), at most `max` bytes in at most
    /// `parts` slot parts: `range(slot, offset, length)` per part, oldest first. Returns the bytes lent now.
    pub fn lend(&mut self, max: u32, parts: u32, mut range: impl FnMut(u32, u32, u32)) -> u32 {
        let n = self.q.len() as u32;
        // bytes from the start of the front slot that are consumed or lent already
        let mut skip = self.off + self.lent;
        let mut total = 0;
        let mut count = 0;
        for i in 0..self.len {
            if total == max || count == parts {
                break;
            }
            let (slot, len) = self.q[((self.head + i) % n) as usize];
            if skip >= len {
                skip -= len;
                continue;
            }
            let take = (len - skip).min(max - total);
            range(slot, skip, take);
            total += take;
            count += 1;
            skip = 0;
        }
        self.lent += total;
        total
    }

    /// Consume `left` lent bytes from the front, one step per call: a slot they cover to its end is popped and returned
    /// (re-post it); a slot they end inside keeps its rest held (lent bytes of it stay lent). None once `left` is 0.
    pub fn settle(&mut self, left: &mut u32) -> Option<u32> {
        debug_assert!(*left <= self.lent);
        let left_now = (*left).min(self.lent);
        if left_now == 0 || self.len == 0 {
            *left = 0;
            return None;
        }
        let (slot, len) = self.q[self.head as usize];
        let rest = len - self.off;
        if left_now >= rest {
            *left = left_now - rest;
            // `pop` already removes this slot's lent bytes (`len - off`) from `lent`.
            self.pop();
            return Some(slot);
        }
        self.off += left_now;
        self.lent -= left_now;
        *left = 0;
        None
    }

    /// End the lend: lent bytes not consumed are held again (the next lend or the replay starts with them).
    pub fn unlend(&mut self) {
        self.lent = 0;
    }

    /// Empty the queue of a connection that goes away: `slot(index, lent)` per held slot, oldest first; `lent` = an open
    /// lend still covers bytes of it (a borrower may read it).
    pub fn drain(&mut self, mut slot: impl FnMut(u32, bool)) {
        let mut lent = self.lent;
        let mut off = self.off;
        while let Some((s, len)) = self.pop() {
            slot(s, lent > 0);
            lent = lent.saturating_sub(len - off);
            off = 0;
        }
        self.lent = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credit::Credits;

    #[test]
    fn settle_consumes_the_lent_bytes_of_a_whole_slot() {
        let mut h = Hold::new(4);
        h.push(21, 262).unwrap();
        h.push(22, 262).unwrap();
        h.pause();
        let mut parts = 0;
        assert_eq!(h.lend(524, 4, |_, _, _| parts += 1), 524);
        assert_eq!(parts, 2);
        assert_eq!(h.lent(), 524);
        let mut left = 262;
        assert_eq!(h.settle(&mut left), Some(21));
        assert_eq!(left, 0);
        assert_eq!(h.lent(), 262, "a settled slot's lent bytes are consumed");
        assert_eq!(h.len(), 1);
        // The rest still replays: resume must not see a stale lend.
        let mut left = 262;
        assert_eq!(h.settle(&mut left), Some(22));
        assert_eq!(h.lent(), 0);
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn a_held_slot_survives_a_resume_until_it_is_delivered_or_drained() {
        let mut h = Hold::new(4);
        // The owner answered Keep: the slot is held and the stream is paused.
        h.push(11, 262).unwrap();
        h.pause();
        assert_eq!(h.len(), 1);
        // Re-delivery starts, but the slot must stay held until it is popped after delivery.
        h.resume();
        assert_eq!(h.front(), Some((11, 0, 262)));
        assert_eq!(h.len(), 1);
        h.pop();
        assert_eq!(h.len(), 0);
        // A drained stream reports every held slot, so detach can count the loss instead of hiding it.
        h.push(12, 262).unwrap();
        let mut seen = 0;
        h.drain(|_, _| seen += 1);
        assert_eq!(seen, 1);
    }

    #[test]
    fn fifo_wraps_and_overflows() {
        let mut h = Hold::new(3);
        for round in 0..5 {
            for i in 0..3 {
                h.push(round * 10 + i, 1).unwrap();
            }
            assert_eq!(h.push(99, 1), Err(Full));
            for i in 0..3 {
                assert_eq!(h.pop(), Some((round * 10 + i, 1)));
            }
            assert_eq!(h.pop(), None);
        }
    }

    /// Settle all of `n` lent bytes; the re-posted slots in order.
    fn settle_all(h: &mut Hold, mut n: u32) -> Vec<u32> {
        let mut out = Vec::new();
        while let Some(slot) = h.settle(&mut n) {
            out.push(slot);
        }
        assert_eq!(n, 0);
        out
    }

    /// A lend covers whole slots and ends inside one; settle pops the covered slots, the partly lent slot keeps its
    /// rest (offset) for the next lend or replay.
    #[test]
    fn lend_settles_whole_slots_and_keeps_the_rest_of_a_partial_one() {
        let mut h = Hold::new(4);
        h.pause();
        for (slot, len) in [(7, 100), (8, 100), (9, 50)] {
            h.push(slot, len).unwrap();
        }
        let mut got = Vec::new();
        assert_eq!(h.lend(150, 8, |s, o, l| got.push((s, o, l))), 150);
        assert_eq!(got, [(7, 0, 100), (8, 0, 50)]);
        assert_eq!(settle_all(&mut h, 150), [7]);
        assert_eq!((h.lent(), h.len()), (0, 2));
        assert_eq!(h.front(), Some((8, 50, 100)));
        got.clear();
        assert_eq!(h.lend(1000, 8, |s, o, l| got.push((s, o, l))), 100);
        assert_eq!(got, [(8, 50, 50), (9, 0, 50)]);
        assert_eq!(settle_all(&mut h, 100), [8, 9]);
        assert!(h.is_empty() && h.lent() == 0 && h.front().is_none());
        // popping a partly consumed slot (teardown) resets the offset
        h.push(1, 10).unwrap();
        h.lend(4, 8, |_, _, _| {});
        settle_all(&mut h, 4);
        assert_eq!(h.front(), Some((1, 4, 10)));
        assert_eq!(h.pop(), Some((1, 10)));
        h.push(2, 10).unwrap();
        assert_eq!(h.front(), Some((2, 0, 10)));
    }

    /// Drain of a connection that goes away flags exactly the slots an open lend still covers (from a partly consumed
    /// front slot on), and leaves nothing held or lent.
    #[test]
    fn drain_flags_the_slots_an_open_lend_covers() {
        let mut h = Hold::new(8);
        h.pause();
        for slot in 1..=4 {
            h.push(slot, 100).unwrap();
        }
        // half of slot 1 consumed, then 150 bytes lent: the rest of slot 1 and all of slot 2
        h.lend(50, 8, |_, _, _| {});
        settle_all(&mut h, 50);
        assert_eq!(h.lend(150, 8, |_, _, _| {}), 150);
        let mut got = Vec::new();
        h.drain(|s, lent| got.push((s, lent)));
        assert_eq!(got, [(1, true), (2, true), (3, false), (4, false)]);
        assert!(h.is_empty() && h.lent() == 0);
        // no lend open: nothing flagged
        h.push(5, 10).unwrap();
        got.clear();
        h.drain(|s, lent| got.push((s, lent)));
        assert_eq!(got, [(5, false)]);
    }

    /// An open lend grows by the slots held after it (bounded by bytes and parts), is consumed from the front while
    /// it is open (slots return before the borrower is done), and `unlend` holds what was not consumed again.
    #[test]
    fn open_lend_grows_settles_progressively_and_unlends_the_rest() {
        let mut h = Hold::new(8);
        h.pause();
        h.push(1, 100).unwrap();
        let mut got = Vec::new();
        assert_eq!(h.lend(1000, 8, |s, o, l| got.push((s, o, l))), 100);
        // nothing new held: nothing more to lend
        assert_eq!(h.lend(1000, 8, |_, _, _| panic!("nothing new")), 0);
        for slot in 2..=4 {
            h.push(slot, 100).unwrap();
        }
        // grows by at most 2 parts
        assert_eq!(h.lend(1000, 2, |s, o, l| got.push((s, o, l))), 200);
        assert_eq!(got, [(1, 0, 100), (2, 0, 100), (3, 0, 100)]);
        // slot 1 and half of slot 2 consumed while the lend stays open
        assert_eq!(settle_all(&mut h, 150), [1]);
        assert_eq!((h.lent(), h.front()), (150, Some((2, 50, 100))));
        // grows again, bounded by bytes: half of slot 4 (the lend ends inside it)
        got.clear();
        assert_eq!(h.lend(50, 8, |s, o, l| got.push((s, o, l))), 50);
        assert_eq!(got, [(4, 0, 50)]);
        assert_eq!(h.lent(), 200);
        assert_eq!(settle_all(&mut h, 50), [2]);
        // end: slots 3 and 4 were lent, not consumed: held again from their start, replay order unchanged
        h.unlend();
        assert_eq!((h.lent(), h.len(), h.front()), (0, 2, Some((3, 0, 100))));
        got.clear();
        assert_eq!(h.lend(1000, 8, |s, o, l| got.push((s, o, l))), 200);
        assert_eq!(got, [(3, 0, 100), (4, 0, 100)]);
    }

    /// Sender and a receiver that pauses: the receiver holds at most one window, never returns a credit for a held
    /// slot, and after resume every byte arrives in order and the sender makes progress again.
    #[test]
    fn paused_receiver_holds_one_window_and_resumes_in_order() {
        const W: u32 = 8;
        let mut tx = Credits::new(W, W);
        let mut rx = Credits::new(W, W);
        let mut hold = Hold::new(W);
        let mut wire: Vec<(u32, u32)> = Vec::new(); // (seq, imm) of data SENDs in flight
        let mut sent = 0u32;
        let mut delivered: Vec<u32> = Vec::new();

        hold.pause();
        // Sender pushes as much as its credits allow; the receiver consumes all arrivals into the hold.
        for _ in 0..100 {
            while tx.can_send_data() {
                wire.push((sent, tx.take_data()));
                sent += 1;
            }
            for (seq, imm) in wire.drain(..) {
                rx.on_recv(imm).unwrap();
                hold.push(seq, 1).expect("peer cannot exceed its window");
            }
            // credit-only SENDs flow, but nothing was re-posted, so nothing is owed
            assert!(!rx.want_credit_only());
        }
        assert!(hold.len() <= W);
        assert_eq!(hold.len(), W - 1, "one credit stays reserved");
        assert_eq!(rx.owed(), 0);
        assert!(!tx.can_send_data(), "sender is blocked by credits");

        hold.resume();
        while let Some((seq, _)) = hold.pop() {
            delivered.push(seq);
            rx.on_reposted();
        }
        assert_eq!(delivered, (0..W - 1).collect::<Vec<_>>());
        assert!(rx.want_credit_only());
        tx.on_recv(rx.take_credit_only()).unwrap();
        assert!(
            tx.can_send_data(),
            "credits came back after the slots were re-posted"
        );
    }
}
