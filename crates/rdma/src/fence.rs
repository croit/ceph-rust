// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Close fence of one connection (0469-rdma-transport): send WRs are mostly unsignaled, and destroying a QP flushes the WRs
//! the HCA has not finished, so a graceful close must not destroy the QP while posted output may still be on the wire.
//! The fence is one signaled zero-length SEND posted behind the last output. RC completes it only after the peer's HCA
//! acknowledged it, and completions retire in posting order, so its completion means every earlier SEND arrived in the
//! peer's receive slots. The QP is destroyed after that completion (or a QP fault, which is handled as an abort).
//!
//! State machine ([`Fence::step`], called again after every `Writable`): nothing outstanding -> `Done`; send queue full or
//! no peer credit -> `Blocked` (retry on the next progress); otherwise post the fence (`Post`) -> `Pending` until its
//! completion retires it ([`Fence::completed`], reported once) -> `Done`.
use crate::credit::Credits;
use crate::ring::{NO_SLOT, SendQueue};

/// The loud message of a close fence that did not complete within the linger limit (shared by the OSD and the client).
pub fn timeout_message(limit: std::time::Duration, conn: u64) -> String {
    format!(
        "WARNING TIMEOUT rdma close fence exceeded {}s (conn {conn:#x})",
        limit.as_secs_f64()
    )
}

/// What the caller does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing is in flight: the QP can go now.
    Done,
    /// The fence is posted, its completion has not come: wait for it.
    Pending,
    /// The fence cannot be posted (send queue full or no peer credit): call again after the next send progress.
    Blocked,
    /// Post a signaled zero-length SEND with work request id `seq` and immediate `imm`, then wait ([`Step::Pending`] next).
    Post { seq: u32, imm: u32 },
}

/// Fence state of one connection.
#[derive(Debug, Default)]
pub struct Fence {
    /// Sequence number of the posted fence WR.
    seq: Option<u32>,
    /// The completion was reported.
    reported: bool,
}

impl Fence {
    /// Advance the fence; on [`Step::Post`] the WR is already accounted in `sq` and `credits`.
    pub fn step(&mut self, sq: &mut SendQueue, credits: &mut Credits) -> Step {
        if let Some(s) = self.seq {
            return if sq.retired(s) {
                Step::Done
            } else {
                Step::Pending
            };
        }
        if sq.outstanding() == 0 {
            return Step::Done;
        }
        if sq.full() || !credits.can_send_data() {
            return Step::Blocked;
        }
        let imm = credits.take_data();
        let seq = sq.push_signaled(NO_SLOT);
        self.seq = Some(seq);
        Step::Post { seq, imm }
    }

    /// True once, when the fence WR retired (call after send completions were applied to `sq`).
    pub fn completed(&mut self, sq: &SendQueue) -> bool {
        match self.seq {
            Some(s) if !self.reported && sq.retired(s) => {
                self.reported = true;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(depth: u32, window: u32, peer: u32) -> (Fence, SendQueue, Credits) {
        (
            Fence::default(),
            SendQueue::new(depth),
            Credits::new(window, peer),
        )
    }

    fn send(sq: &mut SendQueue, c: &mut Credits) {
        c.take_data();
        sq.push(NO_SLOT, false);
    }

    #[test]
    fn idle_connection_is_done_at_once() {
        let (mut f, mut sq, mut c) = fresh(8, 8, 8);
        assert_eq!(f.step(&mut sq, &mut c), Step::Done);
        assert!(!f.completed(&sq));
    }

    #[test]
    fn posts_waits_for_its_completion_then_done() {
        let (mut f, mut sq, mut c) = fresh(8, 8, 8);
        for _ in 0..3 {
            send(&mut sq, &mut c); // unsignaled output
        }
        let Step::Post { seq, imm } = f.step(&mut sq, &mut c) else {
            panic!("outstanding output needs a fence");
        };
        assert_eq!((seq, imm), (3, 0));
        assert_eq!(c.avail(), 8 - 4, "the fence consumed a credit");
        assert_eq!(f.step(&mut sq, &mut c), Step::Pending);
        assert!(!f.completed(&sq));
        sq.complete(seq, |_| {});
        assert!(f.completed(&sq));
        assert!(!f.completed(&sq), "reported once");
        assert_eq!(f.step(&mut sq, &mut c), Step::Done);
    }

    #[test]
    fn fence_returns_owed_credits() {
        let (mut f, mut sq, mut c) = fresh(8, 8, 8);
        send(&mut sq, &mut c);
        c.on_reposted();
        c.on_reposted();
        assert!(matches!(f.step(&mut sq, &mut c), Step::Post { imm: 2, .. }));
    }

    #[test]
    fn blocked_without_queue_room_then_done_once_retired() {
        let (mut f, mut sq, mut c) = fresh(4, 8, 8);
        for _ in 0..4 {
            send(&mut sq, &mut c);
        }
        assert!(sq.full());
        assert_eq!(f.step(&mut sq, &mut c), Step::Blocked);
        sq.complete(3, |_| {}); // everything retired
        assert_eq!(f.step(&mut sq, &mut c), Step::Done, "nothing in flight");
    }

    #[test]
    fn blocked_without_credit_then_posts_when_one_returns() {
        let (mut f, mut sq, mut c) = fresh(8, 8, 3);
        send(&mut sq, &mut c);
        send(&mut sq, &mut c); // avail 1: only the reserved credit is left
        assert_eq!(f.step(&mut sq, &mut c), Step::Blocked);
        c.on_recv(1).unwrap(); // the peer returned a credit
        assert!(matches!(f.step(&mut sq, &mut c), Step::Post { .. }));
    }

    #[test]
    fn older_signaled_completion_does_not_complete_the_fence() {
        let (mut f, mut sq, mut c) = fresh(8, 8, 8);
        for _ in 0..4 {
            send(&mut sq, &mut c); // seq 3 is signaled (half depth)
        }
        let Step::Post { seq, .. } = f.step(&mut sq, &mut c) else {
            panic!("post");
        };
        assert_eq!(seq, 4);
        sq.complete(3, |_| {});
        assert!(!f.completed(&sq), "older WR retired, the fence has not");
        sq.complete(4, |_| {});
        assert!(f.completed(&sq));
    }
}
