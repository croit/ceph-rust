// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Receive-credit window of one RDMA connection (0469-rdma-transport, design D7).
//!
//! One credit = one receive slot the peer posted for us. Every SEND (data or credit-only) consumes one. Credits come back
//! in the immediate of the peer's SENDs. One credit is reserved for a credit-only SEND, so two sides that both run out
//! can always return credits to each other. Our side owes the peer one credit per consumed slot, counted only after the
//! slot is re-posted. A credit-only SEND goes out when the owed count reaches half of the window the grant will have once
//! a pending shrink is done (at least two), so returning the slot of a credit-only SEND never ping-pongs. That rule is
//! deadlock-free for windows of at least [`MIN_WINDOW`] (a window of 2 is not: a side blocked on its single data credit
//! would wait for a return that is owed below the threshold).
//!
//! The window is dynamic (the per-core grant policy is [`crate::grant`]). The immediate of a SEND carries one of three
//! messages (top two bits = kind, the rest a count):
//! - kind 0 CREDITS: `n` credits returned (more than were consumed = the window grew);
//! - kind 1 REVOKE: the sender of the SEND asks the receiver to give `n` credits back; the receiver answers with exactly
//!   one SURRENDER;
//! - kind 2 SURRENDER: the sender gives `k <= n` credits back (taken from its unused ones, `k` may be 0); the credits it
//!   could not give stay with the revoker, which stops returning credits for as many consumed slots (lazy shrink).
//!
//! At most one REVOKE is unanswered per direction. Control SENDs are credit-only SENDs that return no credits: a REVOKE
//! and a SURRENDER are sent only with a spare credit, never with the reserved one (when both sides revoke at once and both
//! answered with the last credit, each would owe the other credits it could not send).

/// Smallest window of a connection (the initial grant, advertised in the endpoint record).
pub const MIN_WINDOW: u32 = 3;
/// Largest number of credits the sender side accepts as held (sanity bound: a peer's window is its own configuration).
pub const MAX_PEER_WINDOW: u32 = 1 << 16;

const KIND_SHIFT: u32 = 30;
const COUNT_MASK: u32 = (1 << KIND_SHIFT) - 1;

/// Decoded immediate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Imm {
    Credits(u32),
    Revoke(u32),
    Surrender(u32),
}

impl Imm {
    pub fn encode(self) -> u32 {
        let (k, n) = match self {
            Imm::Credits(n) => (0, n),
            Imm::Revoke(n) => (1, n),
            Imm::Surrender(n) => (2, n),
        };
        debug_assert!(n <= COUNT_MASK);
        (k << KIND_SHIFT) | n
    }

    pub fn decode(v: u32) -> Option<Imm> {
        let n = v & COUNT_MASK;
        match v >> KIND_SHIFT {
            0 => Some(Imm::Credits(n)),
            1 => Some(Imm::Revoke(n)),
            2 => Some(Imm::Surrender(n)),
            _ => None,
        }
    }
}

/// Credit state of one connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credits {
    /// Slots we granted the peer: its unused credits, SENDs in flight, and consumed slots we owe a credit for.
    granted: u32,
    /// Peer slots we may still consume.
    avail: u32,
    /// Our re-posted slots not yet returned to the peer.
    owed: u32,
    /// Credits we will not return for the next consumed slots (shrink the peer could not give back itself).
    lazy: u32,
    /// Credits to ask back, not yet announced.
    to_revoke: u32,
    /// Credits asked back in the REVOKE awaiting its answer (0 = none).
    out_revoke: u32,
    /// Peer asked for credits back: the credits we give (answer to send).
    answer: Option<u32>,
}

/// The peer violated the credit protocol (more credits than possible, a bad control message): session fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overflow;

impl Credits {
    pub fn new(granted: u32, peer_window: u32) -> Credits {
        Credits {
            granted,
            avail: peer_window,
            owed: 0,
            lazy: 0,
            to_revoke: 0,
            out_revoke: 0,
            answer: None,
        }
    }

    /// A data SEND may be posted (one credit stays reserved for a credit-only SEND).
    pub fn can_send_data(&self) -> bool {
        self.avail >= 2
    }

    /// Consume a credit for a data SEND; returns the immediate (credits returned with it).
    pub fn take_data(&mut self) -> u32 {
        debug_assert!(self.can_send_data());
        self.avail -= 1;
        Imm::Credits(std::mem::take(&mut self.owed)).encode()
    }

    /// SEND_WITH_INV consumes a data credit, but has no immediate field to return owed credits.
    pub fn take_invalidation(&mut self) {
        debug_assert!(self.can_send_data());
        self.avail -= 1;
    }

    /// Owed credits at which a credit-only SEND is due: half of the window the grant will have after a pending shrink,
    /// not of the granted credits (a lazy shrink waits for the peer to consume credits it cannot spend; a threshold of
    /// the larger grant would never be reached: seed 9367 of `tests/protocol_model.rs`), at least two.
    fn due_at(&self) -> u32 {
        (self.effective() / 2).max(2)
    }

    /// Slots still to re-post before a credit-only SEND is due (at least 1): the credit-return unit of this window.
    pub fn until_due(&self) -> u32 {
        self.due_at().saturating_sub(self.owed).max(1)
    }

    /// A credit-only SEND is due.
    pub fn want_credit_only(&self) -> bool {
        self.avail >= 1 && self.owed >= self.due_at()
    }

    /// Consume the reserved credit for a credit-only SEND; returns the immediate.
    pub fn take_credit_only(&mut self) -> u32 {
        debug_assert!(self.avail >= 1);
        self.avail -= 1;
        Imm::Credits(std::mem::take(&mut self.owed)).encode()
    }

    /// A control SEND (REVOKE or SURRENDER) is due and can go out. Both need a spare credit: a control SEND returns no
    /// credits, so it never spends the reserved one (two sides whose REVOKEs cross would both answer with their last
    /// credit, owe each other credits and could not send the return: deadlock).
    pub fn want_control(&self) -> bool {
        self.avail >= 2 && (self.answer.is_some() || (self.out_revoke == 0 && self.to_revoke > 0))
    }

    /// Consume a credit for the control SEND [`Credits::want_control`] announced; returns the immediate. The answer to the
    /// peer's REVOKE goes first.
    pub fn take_control(&mut self) -> u32 {
        debug_assert!(self.want_control());
        self.avail -= 1;
        match self.answer.take() {
            Some(k) => Imm::Surrender(k).encode(),
            None => {
                let n = std::mem::take(&mut self.to_revoke);
                self.out_revoke = n;
                Imm::Revoke(n).encode()
            }
        }
    }

    /// A SEND from the peer arrived carrying `imm`. Returns how many credits of our grant the message took back for good
    /// (a SURRENDER), for the pool's accounting.
    pub fn on_recv(&mut self, imm: u32) -> Result<u32, Overflow> {
        match Imm::decode(imm).ok_or(Overflow)? {
            Imm::Credits(n) => match self.avail.checked_add(n) {
                Some(a) if a <= MAX_PEER_WINDOW => {
                    self.avail = a;
                    Ok(0)
                }
                _ => Err(Overflow),
            },
            Imm::Revoke(n) => {
                if self.answer.is_some() {
                    return Err(Overflow);
                }
                // keep enough to send data after the answer left (it costs one credit): MIN_WINDOW - 1 remain
                let k = n.min(self.avail.saturating_sub(MIN_WINDOW + 1));
                self.avail -= k;
                self.answer = Some(k);
                Ok(0)
            }
            Imm::Surrender(k) => {
                if self.out_revoke == 0 || k > self.out_revoke {
                    return Err(Overflow);
                }
                self.granted -= k;
                self.lazy += self.out_revoke - k;
                self.out_revoke = 0;
                Ok(k)
            }
        }
    }

    /// One of our slots consumed by the peer is posted again. Returns 1 when its credit is dropped to realize a shrink
    /// (the grant got smaller), 0 when the credit is owed to the peer.
    pub fn on_reposted(&mut self) -> u32 {
        if self.lazy > 0 {
            self.lazy -= 1;
            self.granted -= 1;
            1
        } else {
            self.owed += 1;
            0
        }
    }

    /// Credits the window will have once the pending shrink is done.
    pub fn effective(&self) -> u32 {
        self.granted - self.lazy - self.out_revoke - self.to_revoke
    }

    /// The pool lends `n` more credits (backed by posted slots): they are returned with the next SEND.
    pub fn grow(&mut self, n: u32) {
        self.granted += n;
        self.owed += n;
    }

    /// Withdraw up to `n` credits of a pending shrink (the policy wants a bigger window again); returns how many of `n`
    /// are still to be granted with [`Credits::grow`].
    pub fn cancel_shrink(&mut self, mut n: u32) -> u32 {
        for f in [&mut self.to_revoke, &mut self.lazy] {
            let t = n.min(*f);
            *f -= t;
            n -= t;
        }
        n
    }

    /// Shrink the window by `n` (at most `effective() - MIN_WINDOW`): credits we still owe the peer are dropped at once,
    /// the rest is asked back (REVOKE). Returns how many credits of the grant were dropped at once.
    pub fn shrink(&mut self, n: u32) -> u32 {
        debug_assert!(n <= self.effective());
        let t = n.min(self.owed);
        self.owed -= t;
        self.granted -= t;
        self.to_revoke += n - t;
        t
    }

    /// Drop up to `n` credits that are owed but not sent yet, keeping the minimum window; returns how many.
    pub fn drop_owed(&mut self, n: u32) -> u32 {
        let t = n
            .min(self.owed)
            .min(self.effective().saturating_sub(MIN_WINDOW));
        self.owed -= t;
        self.granted -= t;
        t
    }

    /// Credits granted to the peer (including those a pending shrink has not taken back yet).
    pub fn granted(&self) -> u32 {
        self.granted
    }

    pub fn avail(&self) -> u32 {
        self.avail
    }

    /// Credits given up in the answer to the peer's REVOKE that is not sent yet (they already left `avail`; the model
    /// tests balance the credits of both ends with it).
    pub fn answer_k(&self) -> u32 {
        self.answer.unwrap_or(0)
    }

    pub fn owed(&self) -> u32 {
        self.owed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Two endpoints exchanging SENDs through an in-order "wire"; returns false on a deadlock.
    fn run(window: u32, a_msgs: u32, b_msgs: u32) -> bool {
        let mut s = [Credits::new(window, window), Credits::new(window, window)];
        let mut left = [a_msgs, b_msgs];
        let mut wire: [VecDeque<u32>; 2] = Default::default();
        for _ in 0..100_000 {
            let mut progress = false;
            for i in 0..2 {
                let j = 1 - i;
                // receive one SEND from j, re-post its slot
                if let Some(imm) = wire[j].pop_front() {
                    s[i].on_recv(imm).unwrap();
                    s[i].on_reposted();
                    progress = true;
                }
                if left[i] > 0 && s[i].can_send_data() {
                    let imm = s[i].take_data();
                    wire[i].push_back(imm);
                    left[i] -= 1;
                    progress = true;
                } else if s[i].want_credit_only() {
                    let imm = s[i].take_credit_only();
                    wire[i].push_back(imm);
                    progress = true;
                }
            }
            if !progress {
                return left == [0, 0];
            }
        }
        false
    }

    #[test]
    fn no_deadlock_one_or_both_directions() {
        for w in [MIN_WINDOW, 4, 5, 8, 32] {
            assert!(run(w, 1000, 0), "one way w={w}");
            assert!(run(w, 1000, 1000), "both ways w={w}");
            assert!(run(w, 3, 997), "skewed w={w}");
        }
    }

    #[test]
    fn invalidation_spends_data_credit_without_losing_owed_returns() {
        let mut a = Credits::new(4, 4);
        let mut b = Credits::new(4, 4);
        a.on_reposted();
        a.on_reposted();
        assert_eq!(a.owed(), 2);
        a.take_invalidation();
        assert_eq!(a.owed(), 2);
        b.on_recv(Imm::Credits(0).encode()).unwrap();
        b.on_reposted();
        assert!(a.want_credit_only());
        let returned = a.take_credit_only();
        assert_eq!(Imm::decode(returned), Some(Imm::Credits(2)));
        b.on_recv(returned).unwrap();
        b.on_reposted();
        assert_eq!(a.owed(), 0);
        assert!(b.can_send_data());
    }

    #[test]
    fn a_window_of_two_deadlocks_so_the_minimum_is_three() {
        // one data credit, the return owed below the credit-only threshold of two
        assert!(!run(2, 10, 0));
        assert!(run(MIN_WINDOW, 10, 0));
    }

    #[test]
    fn idle_is_quiet_and_overflow_detected() {
        let mut c = Credits::new(8, 8);
        assert!(!c.want_credit_only());
        for _ in 0..3 {
            c.on_reposted();
        }
        assert!(!c.want_credit_only());
        c.on_reposted();
        assert!(c.want_credit_only());
        assert_eq!(Imm::decode(c.take_credit_only()), Some(Imm::Credits(4)));
        // the peer may return more than it consumed (a grown window) but never more than the sanity bound
        assert_eq!(c.on_recv(Imm::Credits(2).encode()), Ok(0));
        assert_eq!(c.avail(), 9);
        assert_eq!(
            c.on_recv(Imm::Credits(MAX_PEER_WINDOW).encode()),
            Err(Overflow)
        );
        assert_eq!(c.on_recv(3 << KIND_SHIFT), Err(Overflow), "unknown kind");
        while c.can_send_data() {
            c.take_data();
        }
        assert_eq!(c.avail(), 1, "one credit reserved");
    }

    #[test]
    fn imm_roundtrip() {
        for i in [
            Imm::Credits(0),
            Imm::Credits(COUNT_MASK),
            Imm::Revoke(7),
            Imm::Surrender(0),
        ] {
            assert_eq!(Imm::decode(i.encode()), Some(i));
        }
    }

    /// Shrink with a peer that is idle (holds all credits): REVOKE, SURRENDER of what it can spare, the rest is dropped
    /// lazily when slots are consumed.
    #[test]
    fn revoke_surrender_and_lazy_shrink() {
        // we (r) granted 16, the peer (p) has all 16 unused
        let mut r = Credits::new(16, 16);
        let mut p = Credits::new(16, 16);
        assert_eq!(r.effective(), 16);
        // no owed credits: everything is asked back
        assert_eq!(r.shrink(13), 0);
        assert_eq!(r.effective(), 3);
        assert!(r.want_control());
        let revoke = r.take_control();
        assert_eq!(Imm::decode(revoke), Some(Imm::Revoke(13)));
        assert!(!r.want_control(), "one REVOKE at a time");
        // p receives it: spares avail - (MIN_WINDOW + 1) = 12, answers, p's SEND costs it one credit
        assert_eq!(p.on_recv(revoke), Ok(0));
        assert!(p.want_control());
        let ans = p.take_control();
        assert_eq!(Imm::decode(ans), Some(Imm::Surrender(12)));
        assert_eq!(p.avail(), 16 - 12 - 1);
        // r takes the 12 back for good; 1 more is to be dropped lazily
        assert_eq!(r.on_recv(ans), Ok(12));
        assert_eq!(r.granted(), 4);
        assert_eq!(r.effective(), 3);
        assert_eq!(
            r.on_reposted(),
            1,
            "the slot of the surrender SEND itself is dropped"
        );
        assert_eq!(r.granted(), 3);
        assert_eq!(r.on_reposted(), 0);
    }

    /// Both sides revoke at once: each answers the other's REVOKE. Spending the reserved credit on the answer left both at
    /// 0 credits owing each other credits (found by `tests/protocol_model.rs`, seed 3144): the answer needs a spare credit.
    #[test]
    fn crossing_revokes_leave_the_reserved_credit() {
        let mut a = Credits::new(5, 3);
        let mut b = Credits::new(5, 3);
        assert_eq!((a.shrink(2), b.shrink(2)), (0, 0));
        let (ra, rb) = (a.take_control(), b.take_control());
        assert_eq!((a.avail(), b.avail()), (2, 2));
        a.on_recv(rb).unwrap();
        b.on_recv(ra).unwrap();
        assert!(a.want_control() && b.want_control());
        let (sa, sb) = (a.take_control(), b.take_control());
        assert_eq!((a.avail(), b.avail()), (1, 1), "the reserved credit stays");
        a.on_recv(sb).unwrap();
        b.on_recv(sa).unwrap();
        assert_eq!((a.avail(), b.avail()), (1, 1));
    }

    #[test]
    fn the_answer_waits_for_a_spare_credit() {
        let mut c = Credits::new(8, 8);
        c.on_recv(Imm::Revoke(2).encode()).unwrap();
        while c.can_send_data() {
            c.take_data();
        }
        assert_eq!(c.avail(), 1);
        assert!(!c.want_control(), "only the reserved credit is left");
        c.on_recv(Imm::Credits(1).encode()).unwrap();
        assert!(c.want_control());
        assert_eq!(Imm::decode(c.take_control()), Some(Imm::Surrender(2)));
        assert_eq!(c.avail(), 1);
    }

    #[test]
    fn unsolicited_or_duplicate_control_is_a_fault() {
        let mut r = Credits::new(8, 8);
        assert_eq!(r.on_recv(Imm::Surrender(1).encode()), Err(Overflow));
        r.shrink(2);
        r.take_control();
        assert_eq!(
            r.on_recv(Imm::Surrender(3).encode()),
            Err(Overflow),
            "more than asked"
        );
        let mut p = Credits::new(8, 8);
        assert_eq!(p.on_recv(Imm::Revoke(1).encode()), Ok(0));
        assert_eq!(
            p.on_recv(Imm::Revoke(1).encode()),
            Err(Overflow),
            "answer not sent yet"
        );
    }

    #[test]
    fn owed_credits_are_dropped_at_once_and_a_shrink_can_be_cancelled() {
        let mut c = Credits::new(10, 10);
        for _ in 0..4 {
            c.on_reposted();
        }
        assert_eq!(c.shrink(6), 4, "4 owed dropped at once, 2 asked back");
        assert_eq!((c.granted(), c.effective(), c.owed()), (6, 4, 0));
        // the policy changes its mind: the 2 unannounced credits are kept, one more is granted
        assert_eq!(c.cancel_shrink(3), 1);
        assert_eq!(c.effective(), 6);
        c.grow(1);
        assert_eq!((c.granted(), c.owed()), (7, 1));
    }
}
