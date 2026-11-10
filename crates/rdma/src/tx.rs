// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Send side of one core, sans-IO: the core-wide pool of send-arena slots ([`Tx`]), the send state of one connection
//! ([`Sender`]) and the wake-up of connections a send was refused for. [`crate::verbs::Core`] copies and posts what
//! [`Tx::send`] plans and feeds completions back; the model tests below run the same calls without hardware.
//!
//! Invariants:
//! - I1 (retire): when [`Tx::send`] / [`Tx::send_zc`] returns, no WR holding a send slot or a zero-copy lease is behind
//!   the last signaled WR of its queue (the last WR of every call that posted an unsignaled slot or lease holder is
//!   signaled, [`SendQueue::push`], [`SendQueue::push_zc`]). A sender that stops posting gets every slot back, and every
//!   leased payload released, with the completion of that WR: within one round trip.
//! - Lease (zero copy, [`Tx::send_zc`]): the SENDs point into caller memory registered with the HCA, no slot is taken;
//!   the caller attaches one reference to that memory to the last WR of the call ([`SendQueue::lease`]). It is released
//!   only when that WR retires (all earlier WRs of the queue retire with or before it, RC completes in order), and handed
//!   back by [`SendQueue::drain`] when the connection goes away (released after the QP is destroyed). Never twice.
//! - I2 (wake): a connection refused for lack of send slots joins the core's wait queue (FIFO, at most once). Whenever the
//!   pool has free slots, [`Tx::wake`] reports `Writable` to queued connections in queue order, at most one per free slot,
//!   no matter which connection's completion (or [`Tx::reclaim`]) freed them.
//! - Refusals for credits or a full send queue wait for the connection's own progress (a credit SEND of its peer, its own
//!   signaled completion): [`Sender::unblock`].
//!
//! Gather ([`Tx::gather`]): a call offers a list of segments (output chunks, in stream order). Each SEND takes up to one
//! peer slot of the stream, laid out by [`Sender::shape`]: consecutive copy segments are packed into one part (one send
//! slot, one credit, one work request, one receive slot and completion at the peer; the byte stream is unchanged), a
//! zero-copy segment is a part of its own, and with two SGEs a SEND holds one copy part and one by-reference part (a packed
//! header and the first payload bytes). Credits, queue room and slots are accounted per SEND, never per segment. The last
//! SEND of a call is signaled when anything it or an earlier one holds would otherwise stay behind (I1).
//!
//! No allocation after creation: the pool and the wait queue hold at most `slots` resp. `sessions` entries.
use crate::credit::Credits;
use crate::ring::{NO_SLOT, SendQueue};
use bytes::Bytes;
use std::collections::VecDeque;

/// Why [`Tx::send`] stopped before taking everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stall {
    /// No peer credit for a data SEND.
    Credits,
    /// The connection's send queue is full.
    Queue,
    /// The core has no free send slot.
    Slots,
}

/// One input segment of a gathered send: `len` stream bytes (an empty one is skipped), `zc` when they lie in registered memory and may be
/// sent by reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seg {
    pub len: usize,
    pub zc: bool,
}

/// A position in the gathered stream: byte `off` of segment `seg`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pos {
    pub seg: usize,
    pub off: usize,
}

impl Pos {
    /// Skip finished and empty segments: afterwards `seg` is at a segment with bytes left, or `segs.len()` (the end).
    pub fn normalize(&mut self, segs: &[Seg]) {
        while self.seg < segs.len() && self.off == segs[self.seg].len {
            self.seg += 1;
            self.off = 0;
        }
    }

    /// Move `n` bytes forward (`n` must not pass the end of `segs`); the position stays normalized.
    pub fn advance(&mut self, segs: &[Seg], mut n: usize) {
        while n > 0 {
            let left = segs[self.seg].len - self.off;
            if n >= left {
                n -= left;
                self.seg += 1;
                self.off = 0;
            } else {
                self.off += n;
                n = 0;
            }
        }
        self.normalize(segs);
    }
}

/// One SGE of a planned SEND: `len` stream bytes, by reference (`zc`, inside one segment) or copied (any number of
/// consecutive copy segments, packed together).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Part {
    pub len: usize,
    pub zc: bool,
}

/// One planned SEND of `len` stream bytes starting at `from`, laid out as `parts[..nparts]` in stream order: copy parts go
/// together into `slot` (or are posted inline when `slot` is [`NO_SLOT`] and `inline`), zero-copy parts become SGEs that
/// point into their segment. Post with work request id `seq`, immediate `imm`, signaled or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wr {
    pub seq: u32,
    pub slot: u32,
    pub from: Pos,
    pub len: usize,
    pub nparts: usize,
    pub parts: [Part; 2],
    pub imm: u32,
    pub signal: bool,
    pub inline: bool,
}

impl Wr {
    pub fn parts(&self) -> &[Part] {
        &self.parts[..self.nparts]
    }
}

/// The next SEND before credits, queue room and a slot are taken.
#[derive(Clone, Copy, Debug)]
struct Shape {
    start: Pos,
    len: usize,
    nparts: usize,
    parts: [Part; 2],
    end: Pos,
    inline: bool,
    /// Needs a send slot (has a copy part and is not inline).
    slot: bool,
    zc: bool,
}

/// Result of [`Tx::send`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sent {
    /// Stream bytes taken.
    pub taken: usize,
    /// WRs posted.
    pub posts: u32,
    /// Why it stopped early (`None`: all taken or a post failed).
    pub stall: Option<Stall>,
    /// A post failed (the QP is in error).
    pub failed: bool,
}

/// Send state of one connection.
#[derive(Debug)]
pub struct Sender {
    pub sq: SendQueue,
    /// A send was refused: report `Writable` when that changes.
    pub blocked: bool,
    /// In the core's wait queue for send slots.
    waiting: bool,
    /// Largest SEND the peer accepts.
    peer_slot: u32,
    /// Largest SEND posted inline (no slot).
    inline: u32,
    /// SGEs per SEND the QP was created with (1 or 2).
    max_sge: u32,
}

impl Sender {
    pub fn new(sq_depth: u32, peer_slot: u32, inline: u32, max_sge: u32) -> Sender {
        Sender {
            sq: SendQueue::new(sq_depth),
            blocked: false,
            waiting: false,
            peer_slot,
            inline,
            max_sge: max_sge.clamp(1, 2),
        }
    }

    /// A fresh send state with the same shape (test: a new connection that reuses a QP number).
    #[cfg(all(test, feature = "verbs", target_os = "linux"))]
    pub(crate) fn renewed(&self, sq_depth: u32) -> Sender {
        Sender::new(sq_depth, self.peer_slot, self.inline, self.max_sge)
    }

    /// Lay out the next SEND of the stream from `from`: up to one peer slot of bytes, in stream order, as at most
    /// `max_sge` parts. Consecutive copy segments are packed into one copy part (one slot, one SEND, one credit); a
    /// zero-copy segment is a part of its own, so with two SGEs a packed header and the first bytes of a payload by
    /// reference travel together. `None` at the end of the stream.
    fn shape(&self, segs: &[Seg], from: Pos) -> Option<Shape> {
        let cap = self.peer_slot as usize;
        let mut p = from;
        p.normalize(segs);
        if p.seg >= segs.len() {
            return None;
        }
        let start = p;
        let mut parts = [Part::default(); 2];
        let (mut np, mut len) = (0, 0);
        while p.seg < segs.len() && len < cap {
            let sg = segs[p.seg];
            let n = (sg.len - p.off).min(cap - len);
            if np > 0 && !sg.zc && !parts[np - 1].zc {
                parts[np - 1].len += n;
            } else {
                if np == self.max_sge as usize {
                    break;
                }
                parts[np] = Part { len: n, zc: sg.zc };
                np += 1;
            }
            len += n;
            p.advance(segs, n);
        }
        let zc = parts[..np].iter().any(|x| x.zc);
        let inline = np == 1 && !zc && len <= self.inline as usize;
        Some(Shape {
            start,
            len,
            nparts: np,
            parts,
            end: p,
            inline,
            slot: !inline && parts[..np].iter().any(|x| !x.zc),
            zc,
        })
    }

    /// After the connection's own progress (a send completion, a credit SEND of the peer): true when a refused send can
    /// go on now (`Writable` is due; the flag is cleared). A connection in the slot wait queue is woken by [`Tx::wake`]
    /// in queue order only, so its own completions do not let it overtake earlier waiters.
    pub fn unblock(&mut self, credits: &Credits) -> bool {
        if self.blocked && !self.waiting && !self.sq.full() && credits.can_send_data() {
            self.blocked = false;
            return true;
        }
        false
    }

    /// After [`Tx::send_zc`] took `taken` (> 0) bytes of `b`: lease them to the last WR pushed; `b` keeps the rest. No
    /// allocation when the whole buffer went out (moved); a partial take splits `b` (a refcount, plus one shared header
    /// the first time a `Vec`-backed `Bytes` is split, bytes crate).
    pub fn lease(&mut self, b: &mut Bytes, taken: usize) {
        debug_assert!(taken > 0 && taken <= b.len());
        let l = if taken == b.len() {
            std::mem::take(b)
        } else {
            b.split_to(taken)
        };
        self.sq.lease(l);
    }

    /// Taken off the core's wait queue by [`Tx::wake`]: true when `Writable` is due (it is still blocked; cleared).
    pub fn dequeued(&mut self) -> bool {
        self.waiting = false;
        std::mem::take(&mut self.blocked)
    }
}

/// Send-arena slots of one core and the connections waiting for them.
#[derive(Debug)]
pub struct Tx {
    free: Vec<u32>,
    waiting: VecDeque<u32>,
}

impl Tx {
    /// `slots` send slots, at most `sessions` connections.
    pub fn new(slots: u32, sessions: u32) -> Tx {
        Tx {
            free: (0..slots).rev().collect(),
            waiting: VecDeque::with_capacity(sessions as usize),
        }
    }

    /// Free send slots.
    pub fn free(&self) -> usize {
        self.free.len()
    }

    /// Why the next SEND `w` cannot be posted (`pending` WRs are about to be pushed to `s.sq`, their slots already taken).
    fn refuse(&self, s: &Sender, cr: &Credits, w: &Shape, pending: u32) -> Option<Stall> {
        if !cr.can_send_data() {
            return Some(Stall::Credits);
        }
        if s.sq.room() <= pending {
            return Some(Stall::Queue);
        }
        (w.slot && self.free.is_empty()).then_some(Stall::Slots)
    }

    /// Plan SENDs for `len` stream bytes of connection `key` while credits, its send queue and the slot pool allow; `post`
    /// copies and posts each one (false: the post failed, stop). A refusal marks the connection blocked; one for lack of
    /// slots queues it for [`Tx::wake`].
    pub fn send(
        &mut self,
        key: u32,
        s: &mut Sender,
        cr: &mut Credits,
        len: usize,
        post: impl FnMut(Wr) -> bool,
    ) -> Sent {
        self.gather(
            key,
            s,
            cr,
            &[Seg { len, zc: false }][..usize::from(len > 0)],
            post,
        )
    }

    /// Zero copy: [`Tx::send`] of one segment that stays in caller memory registered with the HCA (no slot, never inline:
    /// every [`Wr`] has `slot` [`NO_SLOT`], its one part is `zc`). When WRs were posted (`posts > 0`), the caller must attach
    /// a reference to that memory to the last one ([`SendQueue::lease`]) before anything else is pushed: it is released
    /// when the WR retires (module docs, Lease).
    pub fn send_zc(
        &mut self,
        key: u32,
        s: &mut Sender,
        cr: &mut Credits,
        len: usize,
        post: impl FnMut(Wr) -> bool,
    ) -> Sent {
        self.gather(
            key,
            s,
            cr,
            &[Seg { len, zc: true }][..usize::from(len > 0)],
            post,
        )
    }

    /// Plan SENDs for the stream `segs` (consecutive pieces, in order) of connection `key`: each SEND takes up to one peer
    /// slot of bytes laid out by [`Sender::shape`] (small segments packed, a zero-copy segment by reference), as long as
    /// credits, the send queue and the slot pool allow. One credit and one WR per SEND, however many segments it packs.
    /// `post` stages/posts each one (false: the post failed, stop). `Sent::taken` counts the bytes of the SENDs `post`
    /// accepted, from the start of `segs`.
    pub fn gather(
        &mut self,
        key: u32,
        s: &mut Sender,
        cr: &mut Credits,
        segs: &[Seg],
        mut post: impl FnMut(Wr) -> bool,
    ) -> Sent {
        let mut r = Sent::default();
        let mut cur = s.shape(segs, Pos::default());
        while let Some(w) = cur {
            if let Some(why) = self.refuse(s, cr, &w, 0) {
                s.blocked = true;
                if why == Stall::Slots && !s.waiting {
                    s.waiting = true;
                    debug_assert!(self.waiting.len() < self.waiting.capacity());
                    self.waiting.push_back(key);
                }
                r.stall = Some(why);
                break;
            }
            let slot = if w.slot {
                self.free.pop().expect("refuse() saw a free slot")
            } else {
                NO_SLOT
            };
            let imm = cr.take_data();
            let next = s.shape(segs, w.end);
            // signal this WR when the next one cannot follow (I1)
            let end = next.is_none_or(|n| self.refuse(s, cr, &n, 1).is_some());
            let (seq, signal) = s.sq.push_wr(slot, w.zc, end);
            if !post(Wr {
                seq,
                slot,
                from: w.start,
                len: w.len,
                nparts: w.nparts,
                parts: w.parts,
                imm,
                signal,
                inline: w.inline,
            }) {
                r.failed = true;
                break;
            }
            r.posts += 1;
            r.taken += w.len;
            cur = next;
        }
        r
    }

    /// Send completion `seq` of `s` (signaled, or any error completion): retire it and every older WR, their slots go
    /// back to the pool.
    pub fn completed(&mut self, s: &mut Sender, seq: u32) {
        let free = &mut self.free;
        s.sq.complete(seq, |slot| free.push(slot));
    }

    #[cfg(feature = "memory-windows")]
    pub(crate) fn completed_status(&mut self, s: &mut Sender, seq: u32, success: bool) {
        s.sq.complete_status(seq, |slot| self.free.push(slot), success);
    }

    /// Slots of a destroyed QP (its WRs will never complete): back to the pool, waiters are woken by the next
    /// [`Tx::wake`].
    pub fn reclaim(&mut self, slots: &[u32]) {
        self.free.extend_from_slice(slots);
    }

    /// The connection `key` goes away: drop it from the wait queue (not on the data path: detach).
    pub fn forget(&mut self, key: u32, s: &Sender) {
        if s.waiting {
            self.waiting.retain(|&k| k != key);
        }
    }

    /// Wake connections waiting for send slots (I2): pops the queue in order while there are more free slots than
    /// connections woken. `woke(key)` looks the connection up and calls [`Sender::dequeued`] on it: true = it reports
    /// `Writable` (a connection that is gone or already unblocked does not count). Returns the connections woken.
    pub fn wake(&mut self, mut woke: impl FnMut(u32) -> bool) -> usize {
        let mut n = 0;
        while n < self.free.len()
            && let Some(key) = self.waiting.pop_front()
        {
            n += usize::from(woke(key));
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credit::Imm;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    const SLOT: u32 = 64 * 1024;
    const INLINE: u32 = 256;

    /// A core with connections and a lossless HCA + peer: every posted SEND arrives, signaled ones complete, the peer
    /// returns credits half a window at a time (the credit-only rule of [`crate::credit`]).
    struct Model {
        tx: Tx,
        conns: Vec<Conn>,
        /// Signaled completions per connection.
        signals: Vec<u32>,
    }

    struct Conn {
        s: Sender,
        cr: Credits,
        window: u32,
        /// Posted SENDs: (seq, signaled), not yet completed by the model HCA.
        wire: Vec<(u32, bool)>,
        /// Data SENDs the peer received and has not returned a credit for.
        owed: u32,
    }

    impl Model {
        fn new(slots: u32, depth: u32, windows: &[u32]) -> Model {
            Model {
                tx: Tx::new(slots, windows.len() as u32),
                conns: windows
                    .iter()
                    .map(|&w| Conn {
                        s: Sender::new(depth, SLOT, INLINE, 1),
                        cr: Credits::new(w, w),
                        window: w,
                        wire: Vec::new(),
                        owed: 0,
                    })
                    .collect(),
                signals: vec![0; windows.len()],
            }
        }

        /// `Core::send` of `len` bytes on connection `i`; returns the bytes taken.
        fn send(&mut self, i: usize, len: usize) -> usize {
            let c = &mut self.conns[i];
            let wire = &mut c.wire;
            let r = self.tx.send(i as u32, &mut c.s, &mut c.cr, len, |w| {
                assert_eq!(w.inline, w.slot == NO_SLOT);
                wire.push((w.seq, w.signal));
                true
            });
            assert!(c.s.sq.covered(), "I1: a slot holder behind the last signal");
            r.taken
        }

        /// One round trip, in `Core::poll` order: the peer receives everything posted and returns credits (whole halves
        /// of the window), the HCA completes the signaled WRs, waiters are woken. Returns the connections that got
        /// `Writable`.
        fn round(&mut self) -> Vec<usize> {
            let mut writable = Vec::new();
            for (i, c) in self.conns.iter_mut().enumerate() {
                c.owed += c.wire.len() as u32;
                let half = (c.window / 2).max(2);
                if c.owed >= half {
                    let k = c.owed / half * half;
                    c.owed -= k;
                    c.cr.on_recv(Imm::Credits(k).encode()).unwrap();
                    if c.s.unblock(&c.cr) {
                        writable.push(i);
                    }
                }
                for (seq, signal) in std::mem::take(&mut c.wire) {
                    if signal {
                        self.signals[i] += 1;
                        self.tx.completed(&mut c.s, seq);
                        if c.s.unblock(&c.cr) {
                            writable.push(i);
                        }
                    }
                }
            }
            let conns = &mut self.conns;
            self.tx.wake(|k| {
                let woke = conns.get_mut(k as usize).is_some_and(|c| c.s.dequeued());
                if woke {
                    writable.push(k as usize);
                }
                woke
            });
            writable
        }
    }

    /// B2: a connection that posts a short burst (far below the signal interval) and goes quiet gets every slot back
    /// within one round trip (I1).
    #[test]
    fn quiet_sender_returns_every_slot_within_one_round_trip() {
        let mut m = Model::new(64, 256, &[64]);
        assert_eq!(m.send(0, 10 * SLOT as usize), 10 * SLOT as usize);
        m.round();
        assert_eq!(m.tx.free(), 64, "slots held by an unsignaled tail");
        assert_eq!(m.conns[0].s.sq.outstanding(), 0);
    }

    /// B1: a connection refused for lack of slots is woken by the completion of ANOTHER connection (I2).
    #[test]
    fn slot_starved_connection_is_woken_by_another_connections_completion() {
        // send queue depth 8 signals every 4th WR: A's completion arrives with or without I1
        let mut m = Model::new(4, 8, &[64, 64]);
        assert_eq!(m.send(0, 4 * SLOT as usize), 4 * SLOT as usize);
        assert_eq!(m.send(1, SLOT as usize), 0, "pool empty");
        let woke = m.round();
        assert_eq!(m.tx.free(), 4);
        assert!(woke.contains(&1), "B not woken: {woke:?}");
        assert_eq!(m.send(1, SLOT as usize), SLOT as usize);
    }

    /// Waiters are woken in queue order, at most one per free slot; a woken connection that loses the race queues again.
    #[test]
    fn waiters_wake_fifo_one_per_free_slot() {
        let mut m = Model::new(2, 8, &[64, 64, 64, 64]);
        assert_eq!(m.send(0, 2 * SLOT as usize), 2 * SLOT as usize);
        for i in [3, 1, 2] {
            assert_eq!(m.send(i, SLOT as usize), 0);
        }
        let woke = m.round(); // A's 2 slots come back: the first two waiters
        assert_eq!(woke, vec![3, 1]);
        assert_eq!(m.send(3, SLOT as usize), SLOT as usize);
        assert_eq!(m.send(1, SLOT as usize), SLOT as usize);
        assert_eq!(m.round(), vec![2]);
    }

    /// The two stalls together: pool smaller than two windows, one connection posts a burst and goes quiet, the other
    /// streams 64 MiB driven only by `Writable` events (as the knet and rados-rt drivers do).
    #[test]
    fn quiet_burst_does_not_stall_a_large_transfer_on_the_same_core() {
        let mut m = Model::new(24, 256, &[16, 16]);
        assert_eq!(m.send(0, 12 * SLOT as usize), 12 * SLOT as usize);
        let total = 64usize << 20;
        let mut sent = m.send(1, total);
        let mut rounds = 0;
        while sent < total {
            rounds += 1;
            assert!(
                rounds < 10_000,
                "stalled at {sent} of {total} bytes, free slots {}",
                m.tx.free()
            );
            if m.round().contains(&1) {
                sent += m.send(1, total - sent);
            }
        }
        m.round();
        assert_eq!(m.tx.free(), 24, "every slot back once both are quiet");
    }

    /// Cost of I1 under streaming: signaled WRs per 4 MiB message (header chunk, 64 data SENDs, inline epilogue) stay at
    /// about one per credit return (half a window).
    #[test]
    fn signals_per_4mib_message_stay_rare() {
        let mut m = Model::new(171, 256, &[16]);
        let msgs = 16;
        for _ in 0..msgs {
            for chunk in [300usize, 4 << 20, 100] {
                let mut sent = m.send(0, chunk);
                while sent < chunk {
                    if m.round().contains(&0) {
                        sent += m.send(0, chunk - sent);
                    }
                }
            }
        }
        m.round();
        let per_msg = m.signals[0] as f64 / msgs as f64;
        diag::diag!("signaled WRs per 4 MiB message: {per_msg:.1} (66 SENDs)");
        assert!(per_msg <= 64.0 / 8.0 + 3.0, "{per_msg} signals per message");
        assert_eq!(m.tx.free(), 171);
    }

    #[test]
    fn refused_for_credits_waits_for_own_credit_return() {
        let mut m = Model::new(64, 256, &[3]);
        // window 3: one data credit stays reserved, two SENDs go
        assert_eq!(m.send(0, 3 * SLOT as usize), 2 * SLOT as usize);
        assert!(m.conns[0].s.blocked);
        assert_eq!(m.round(), vec![0], "credit return wakes it");
        assert_eq!(m.tx.free(), 64);
    }

    /// A payload buffer that counts its release (the last reference dropped) and poisons its bytes then, as a reused
    /// allocation would.
    struct Payload {
        data: Vec<u8>,
        released: Arc<AtomicUsize>,
    }

    impl AsRef<[u8]> for Payload {
        fn as_ref(&self) -> &[u8] {
            &self.data
        }
    }

    impl Drop for Payload {
        fn drop(&mut self) {
            self.data.fill(0xee);
            self.released.fetch_add(1, Relaxed);
        }
    }

    fn payload(len: usize) -> (Bytes, Arc<AtomicUsize>) {
        let released = Arc::new(AtomicUsize::new(0));
        let b = Bytes::from_owner(Payload {
            data: vec![7; len],
            released: released.clone(),
        });
        (b, released)
    }

    impl Model {
        /// `Core::send_bytes` on the zero-copy path: plan, post (the model HCA records the WRs), lease the posted prefix.
        fn send_zc(&mut self, i: usize, b: &mut Bytes) -> usize {
            let c = &mut self.conns[i];
            let wire = &mut c.wire;
            let r = self
                .tx
                .send_zc(i as u32, &mut c.s, &mut c.cr, b.len(), |w| {
                    assert_eq!((w.slot, w.inline), (NO_SLOT, false));
                    assert!(w.len <= SLOT as usize);
                    wire.push((w.seq, w.signal));
                    true
                });
            if r.taken > 0 {
                c.s.lease(b, r.taken);
            }
            assert!(
                c.s.sq.covered(),
                "I1: a lease holder behind the last signal"
            );
            r.taken
        }
    }

    /// The lease is released by the retirement of the WR that holds it, not earlier (an older unsignaled WR completing,
    /// the caller dropping its handle), and exactly once.
    #[test]
    fn lease_released_only_on_retirement() {
        let mut m = Model::new(64, 256, &[16]);
        let (mut b, released) = payload(4 * SLOT as usize);
        assert_eq!(m.send_zc(0, &mut b), 4 * SLOT as usize);
        assert!(b.is_empty(), "the whole buffer moved into the lease");
        drop(b);
        assert_eq!(m.tx.free(), 64, "zero copy takes no send slot");
        let wire = m.conns[0].wire.clone();
        assert_eq!(wire.len(), 4);
        assert_eq!(
            wire.iter().map(|w| w.1).collect::<Vec<_>>(),
            [false, false, false, true],
            "only the lease holder is signaled"
        );
        // an older WR retiring on its own (e.g. an error completion) does not release the lease
        m.tx.completed(&mut m.conns[0].s, wire[1].0);
        assert_eq!(released.load(Relaxed), 0);
        assert_eq!(m.conns[0].s.sq.leases(), 1);
        m.round();
        assert_eq!(released.load(Relaxed), 1);
        assert_eq!(m.conns[0].s.sq.leases(), 0);
        // a stale completion after retirement changes nothing
        m.tx.completed(&mut m.conns[0].s, wire[3].0);
        assert_eq!(released.load(Relaxed), 1, "released twice");
    }

    /// A large payload taken in several calls (credits run out): every call leases its prefix, the buffer is released
    /// once, after the WR of the last part retired; the stream never takes a slot.
    #[test]
    fn partial_takes_keep_the_buffer_until_the_last_part_retires() {
        let mut m = Model::new(8, 256, &[16]);
        let total = 64 * SLOT as usize;
        let (mut b, released) = payload(total);
        let mut sent = m.send_zc(0, &mut b);
        assert!(sent < total, "credits must split the payload");
        let mut calls = 1;
        while sent < total {
            assert_eq!(released.load(Relaxed), 0, "released while parts are unsent");
            if m.round().contains(&0) {
                sent += m.send_zc(0, &mut b);
                calls += 1;
            }
            assert_eq!(m.tx.free(), 8);
        }
        assert!(calls > 4);
        drop(b);
        assert_eq!(
            released.load(Relaxed),
            0,
            "the last part is still in flight"
        );
        m.round();
        assert_eq!(released.load(Relaxed), 1);
        assert_eq!(m.conns[0].s.sq.leases(), 0);
    }

    /// Fault / close: `drain` hands every outstanding lease out (the caller drops them after the QP is destroyed);
    /// nothing is released before, nothing twice, and a late completion after the drain releases nothing.
    #[test]
    fn drain_hands_out_every_lease_once() {
        let mut m = Model::new(64, 256, &[16]);
        let (mut a, ra) = payload(3 * SLOT as usize);
        let (mut b, rb) = payload(2 * SLOT as usize);
        m.send_zc(0, &mut a);
        assert_eq!(m.send(0, 100), 100, "a copied chunk between the two");
        m.send_zc(0, &mut b);
        drop((a, b));
        let late = m.conns[0].wire.last().unwrap().0;
        let (mut slots, mut leases) = (Vec::new(), Vec::new());
        m.conns[0].s.sq.drain(|s| slots.push(s), |l| leases.push(l));
        assert_eq!(leases.len(), 2);
        assert_eq!(
            (ra.load(Relaxed), rb.load(Relaxed)),
            (0, 0),
            "QP not destroyed yet"
        );
        m.tx.completed(&mut m.conns[0].s, late);
        assert_eq!(m.conns[0].s.sq.leases(), 0);
        drop(leases); // the QP is gone
        assert_eq!((ra.load(Relaxed), rb.load(Relaxed)), (1, 1));
        m.tx.reclaim(&slots);
        assert_eq!(m.tx.free(), 64);
    }

    /// Zero-copy and copied SENDs mixed on one connection while a second one streams: every slot comes back, every lease
    /// is released, within one round trip once both are quiet (I1 covers leases).
    #[test]
    fn mixed_streams_release_everything_when_quiet() {
        let mut m = Model::new(16, 256, &[16, 16]);
        let mut rel = Vec::new();
        for k in 0..8 {
            let (mut b, r) = payload((k + 1) * 40_000);
            let mut done = 0;
            let len = b.len();
            while done < len {
                done += m.send_zc(0, &mut b);
                m.send(1, SLOT as usize);
                if done < len {
                    m.round();
                }
            }
            rel.push(r);
        }
        m.round();
        assert!(rel.iter().all(|r| r.load(Relaxed) == 1));
        assert_eq!(m.tx.free(), 16);
        assert_eq!(m.conns[0].s.sq.outstanding(), 0);
    }

    // ---- gathered sends: packing small segments, two SGEs ----

    /// Stream bytes of segment `i`: byte `k` of segment `i` is `(i * 31 + k) as u8`, so a reordered or overlapping read
    /// shows.
    fn byte(seg: usize, k: usize) -> u8 {
        (seg * 31 + k) as u8
    }

    /// What the HCA puts on the wire for `w`: the bytes of its SGEs in order, read the way the executor in `verbs` reads
    /// them (copy parts walk consecutive segments, zero-copy parts stay inside their segment).
    fn wire_bytes(segs: &[Seg], w: &Wr) -> Vec<u8> {
        let mut pos = w.from;
        let mut out = Vec::new();
        for p in w.parts() {
            if p.zc {
                assert!(segs[pos.seg].zc && pos.off + p.len <= segs[pos.seg].len);
            }
            let mut left = p.len;
            while left > 0 {
                let sg = segs[pos.seg];
                assert!(
                    !p.zc || sg.zc,
                    "a copy part must not read a zero-copy segment"
                );
                let n = left.min(sg.len - pos.off);
                out.extend((pos.off..pos.off + n).map(|k| byte(pos.seg, k)));
                pos.advance(segs, n);
                left -= n;
            }
        }
        assert_eq!(out.len(), w.len);
        out
    }

    struct Run {
        wrs: Vec<Wr>,
        sent: Sent,
        tx: Tx,
        cr: Credits,
    }

    fn gather(segs: &[Seg], peer_slot: u32, sge: u32, window: u32, slots: u32) -> Run {
        let mut tx = Tx::new(slots, 4);
        let mut s = Sender::new(1 << 16, peer_slot, INLINE, sge);
        let mut cr = Credits::new(window, window);
        let mut wrs = Vec::new();
        let sent = tx.gather(0, &mut s, &mut cr, segs, |w| {
            wrs.push(w);
            true
        });
        assert!(s.sq.covered(), "I1: a holder behind the last signal");
        Run { wrs, sent, tx, cr }
    }

    fn copy(len: usize) -> Seg {
        Seg { len, zc: false }
    }

    fn zc(len: usize) -> Seg {
        Seg { len, zc: true }
    }

    #[test]
    fn small_chunks_share_one_send_one_credit_one_slot() {
        let segs = vec![copy(300); 100]; // 30000 B
        let r = gather(&segs, SLOT, 1, 16, 8);
        assert_eq!(
            (r.sent.posts, r.sent.taken, r.sent.stall),
            (1, 30_000, None)
        );
        let w = &r.wrs[0];
        assert_eq!((w.nparts, w.parts[0].len, w.inline), (1, 30_000, false));
        assert_ne!(w.slot, NO_SLOT);
        assert_eq!(r.tx.free(), 7, "one slot for 100 chunks");
        assert_eq!(
            r.cr.clone(),
            {
                let mut c = Credits::new(16, 16);
                c.take_data();
                c
            },
            "one credit, not one per chunk"
        );
    }

    #[test]
    fn packed_sends_are_full_slots_and_the_stream_is_byte_exact() {
        let segs = vec![copy(1000); 200]; // 200000 B -> 3 full slots + rest
        let r = gather(&segs, SLOT, 1, 16, 8);
        let lens: Vec<usize> = r.wrs.iter().map(|w| w.len).collect();
        assert_eq!(lens, vec![65_536, 65_536, 65_536, 3_392]);
        let wire: Vec<u8> = r.wrs.iter().flat_map(|w| wire_bytes(&segs, w)).collect();
        let want: Vec<u8> = segs
            .iter()
            .enumerate()
            .flat_map(|(i, s)| (0..s.len).map(move |k| byte(i, k)))
            .collect();
        assert_eq!(wire, want);
        assert_eq!(r.sent.taken, 200_000);
    }

    #[test]
    fn a_tiny_packed_run_is_posted_inline() {
        let r = gather(&[copy(100), copy(50)], SLOT, 1, 16, 8);
        assert_eq!(r.wrs.len(), 1);
        assert!(r.wrs[0].inline && r.wrs[0].slot == NO_SLOT && r.tx.free() == 8);
    }

    #[test]
    fn header_and_first_payload_share_a_send_with_two_sges() {
        let segs = [copy(300), zc(1 << 20), copy(100)];
        let r = gather(&segs, SLOT, 2, 64, 8);
        let first = &r.wrs[0];
        assert_eq!(
            first.parts(),
            &[
                Part {
                    len: 300,
                    zc: false
                },
                Part {
                    len: SLOT as usize - 300,
                    zc: true
                }
            ]
        );
        // header + payload + epilogue: ceil((300 + 1 MiB + 100) / 64 KiB) SENDs, the last one [zc tail, copy 100]
        assert_eq!(
            r.wrs.len(),
            (300 + (1 << 20) + 100usize).div_ceil(SLOT as usize)
        );
        let last = r.wrs.last().unwrap();
        assert_eq!(last.nparts, 2);
        assert!(last.parts[0].zc && !last.parts[1].zc && last.parts[1].len == 100);
        assert!(r.wrs.iter().all(|w| w.nparts <= 2));
        // one send queue entry per SEND; the copy parts of a SEND share one slot
        assert_eq!(r.tx.free(), 8 - 2, "first and last SEND hold a slot");
        let wire: Vec<u8> = r.wrs.iter().flat_map(|w| wire_bytes(&segs, w)).collect();
        assert_eq!(wire.len(), 300 + (1 << 20) + 100);
    }

    #[test]
    fn one_sge_keeps_a_header_and_its_payload_apart() {
        let segs = [copy(300), zc(1 << 20), copy(100)];
        let r = gather(&segs, SLOT, 1, 64, 8);
        assert!(r.wrs.iter().all(|w| w.nparts == 1));
        assert_eq!(r.wrs[0].len, 300);
        assert_eq!(r.wrs.len(), 1 + 16 + 1);
    }

    #[test]
    fn credits_are_taken_per_send_and_a_stall_resumes_at_a_send_boundary() {
        // window 3: two data SENDs fit (one credit stays reserved); each carries a full slot of packed 500 B chunks
        let segs = vec![copy(500); 1000];
        let r = gather(&segs, SLOT, 1, 3, 8);
        assert_eq!(r.sent.stall, Some(Stall::Credits));
        assert_eq!((r.sent.posts, r.sent.taken), (2, 2 * SLOT as usize));
        // the caller offers the rest after the taken prefix (it ends inside a chunk): the stream goes on seamlessly
        let mut pos = Pos::default();
        pos.advance(&segs, r.sent.taken);
        assert_ne!(pos.off, 0, "the prefix ends inside a chunk");
        let mut rest = segs[pos.seg..].to_vec();
        rest[0].len -= pos.off;
        let r2 = gather(&rest, SLOT, 1, 4096, 4096);
        assert_eq!(r.sent.taken + r2.sent.taken, 500_000);
        let wire: Vec<u8> = r.wrs.iter().flat_map(|w| wire_bytes(&segs, w)).collect();
        assert_eq!(wire.len(), 2 * SLOT as usize);
        let want: Vec<u8> = (0..wire.len()).map(|k| byte(k / 500, k % 500)).collect();
        assert_eq!(wire, want);
    }

    /// Random layouts, 1 and 2 SGEs, slot sizes: the stream the HCA would put on the wire is the input, byte for byte, in
    /// order; every SEND is within the slot; stalls are only for credits.
    #[test]
    fn random_layouts_reproduce_the_stream() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut rnd = move |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 11) as usize % n
        };
        for round in 0..300 {
            let n = 1 + rnd(40);
            let segs: Vec<Seg> = (0..n)
                .map(|_| match rnd(4) {
                    0 => zc(1 + rnd(300_000)),
                    1 => copy(1 + rnd(100)),
                    2 if rnd(6) == 0 => copy(0),
                    2 => copy(1 + rnd(5000)),
                    _ => copy(1 + rnd(70_000)),
                })
                .collect();
            let slot = [4096u32, 9000, SLOT][rnd(3)];
            let sge = 1 + rnd(2) as u32;
            let total: usize = segs.iter().map(|s| s.len).sum();
            let r = gather(&segs, slot, sge, 4096, 4096);
            assert_eq!(r.sent.taken, total, "round {round}");
            let mut wire = Vec::with_capacity(total);
            for w in &r.wrs {
                assert!(w.len <= slot as usize && w.nparts as u32 <= sge);
                assert_eq!(w.parts().iter().map(|p| p.len).sum::<usize>(), w.len);
                wire.extend(wire_bytes(&segs, w));
            }
            let want: Vec<u8> = segs
                .iter()
                .enumerate()
                .flat_map(|(i, s)| (0..s.len).map(move |k| byte(i, k)))
                .collect();
            assert!(wire == want, "round {round}: stream differs");
            // fewer SENDs than segments whenever small ones were packed
            assert!(r.wrs.len() <= segs.len() + total / slot as usize + 1);
        }
    }

    /// A post that fails ends the plan: the bytes of the SENDs before it count as taken, the failed one does not.
    #[test]
    fn a_failed_post_stops_the_plan_at_a_send_boundary() {
        let segs = vec![copy(40_000); 8];
        let mut tx = Tx::new(8, 2);
        let mut s = Sender::new(256, SLOT, INLINE, 1);
        let mut cr = Credits::new(16, 16);
        let mut k = 0;
        let r = tx.gather(0, &mut s, &mut cr, &segs, |_| {
            k += 1;
            k < 3
        });
        assert!(r.failed && r.stall.is_none());
        assert_eq!((r.posts, r.taken), (2, 2 * SLOT as usize));
    }

    /// Two zero-copy segments end in the same SEND: both leases ride on it and are released with it.
    #[test]
    fn two_leases_on_one_send_release_together() {
        let (a, ra) = payload(100);
        let (b, rb) = payload(100);
        let mut q = SendQueue::new(8);
        let (seq, _) = q.push_wr(NO_SLOT, true, true);
        q.lease_at(seq, a);
        q.lease_at(seq, b);
        assert_eq!(q.leases(), 2);
        q.complete(seq, |_| {});
        assert_eq!((ra.load(Relaxed), rb.load(Relaxed)), (1, 1));
        assert_eq!(q.leases(), 0);
    }

    #[test]
    #[should_panic(expected = "two leases per WR")]
    fn a_third_lease_on_one_send_is_a_bug() {
        let mut q = SendQueue::new(8);
        let (seq, _) = q.push_wr(NO_SLOT, true, true);
        for _ in 0..3 {
            q.lease_at(seq, Bytes::from_static(b"x"));
        }
    }
}
