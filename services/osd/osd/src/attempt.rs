// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Per-connection RDMA placement attempt owner (ADR 0471, spec
//! rdma-placement-runtime.md "Server ownership and SQ order").
//!
//! A destination descriptor is accepted only for the exact negotiated READY
//! placement session, the plain READ shape of the op, its transaction and a
//! fresh retry identity. The accepted attempt then has one terminal home on
//! the link: the op's reply, its drop, the client's CANCEL and the session
//! loss all route here, before any RMA may start.

use opwire::MOSDOpReply;
use rdma::placement::{ControlRecord, WindowDescriptor};
use std::collections::HashMap;

/// Why a descriptor was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The middle segment is not one exact v1 descriptor record.
    Shape,
    /// The descriptor's transaction differs from the frame's tid.
    Tid,
    /// The descriptor's generation is not this session's (or there is none).
    Session,
    /// A live attempt already holds this `(tid, retry)` on the session.
    Alias,
}

/// One accepted attempt.
#[derive(Debug)]
struct Attempt {
    /// The checked destination grant as offered by the client.
    grant: WindowDescriptor,
    /// The client's CANCEL was accepted: no further WRITE may be posted for it.
    cancelled: bool,
    /// The terminal reply, held until the transport reports the outcome
    /// (its source pieces are moved to the transport with the `IoCmd`).
    reply: Option<MOSDOpReply>,
}

/// Every accepted placement attempt of one link, keyed by `(tid, retry)`.
///
/// The owner lives with the link: close, socket loss and session supersession
/// drop it with the link, which is the terminal state for every live attempt
/// (the client re-advertises on the new session or faults its window).
#[derive(Default)]
pub struct Attempts {
    live: HashMap<(u64, u32), Attempt>,
}

impl Attempts {
    /// Accept the descriptor in `middle` for session `session` and transaction
    /// `tid`: exact record shape, matching generation and transaction, fresh
    /// retry identity. Records the checked grant and returns the attempt's
    /// retry number to mark the op with.
    pub fn admit(&mut self, session: u64, tid: u64, middle: &[u8]) -> Result<u32, Reject> {
        if session == 0 {
            return Err(Reject::Session);
        }
        let d = WindowDescriptor::decode(middle).map_err(|_| Reject::Shape)?;
        if d.attempt.tid != tid {
            return Err(Reject::Tid);
        }
        if d.attempt.connection != session {
            return Err(Reject::Session);
        }
        if self.live.contains_key(&(tid, d.attempt.retry)) {
            return Err(Reject::Alias);
        }
        self.live.insert(
            (tid, d.attempt.retry),
            Attempt {
                grant: d,
                cancelled: false,
                reply: None,
            },
        );
        Ok(d.attempt.retry)
    }

    /// A CANCEL record on this session: the matching live attempt becomes
    /// `Cancelled` (terminal). Returns the retired attempt's `(tid, retry)`; a
    /// late, foreign or malformed CANCEL finds nothing and retires nothing.
    pub fn cancel(
        &mut self,
        session: u64,
        record: &[u8; ControlRecord::ENCODED_LEN],
    ) -> Option<(u64, u32)> {
        let Ok((kind, r)) = ControlRecord::decode(record) else {
            return None;
        };
        if kind != ControlRecord::CANCEL || r.attempt.connection != session {
            return None;
        }
        let a = self.live.get_mut(&(r.attempt.tid, r.attempt.retry))?;
        if a.grant.rkey != r.rkey || a.cancelled {
            return None;
        }
        a.cancelled = true;
        Some((r.attempt.tid, r.attempt.retry))
    }

    /// The attempt's op reached a terminal PG state (reply sent, drop, EAGAIN):
    /// the home is vacated. True when the attempt was on the link.
    pub fn done(&mut self, tid: u64, retry: u32) -> bool {
        self.live.remove(&(tid, retry)).is_some()
    }

    /// The checked destination grant of a live attempt (for the WRITE-to-reply handoff).
    pub fn grant(&self, tid: u64, retry: u32) -> Option<WindowDescriptor> {
        self.live.get(&(tid, retry)).map(|a| a.grant)
    }

    /// A matching CANCEL has closed WRITE admission. The attempt stays live
    /// until the transport proves retirement of its accepted WRITEs.
    pub fn cancelled(&self, tid: u64, retry: u32) -> bool {
        self.live.get(&(tid, retry)).is_some_and(|a| a.cancelled)
    }

    /// Store the terminal reply of a live attempt: its source pieces move to the
    /// transport, the reply (with empty outdata) is kept here until the outcome.
    /// True when the attempt was live.
    pub fn store_reply(&mut self, tid: u64, retry: u32, reply: MOSDOpReply) -> bool {
        self.live
            .get_mut(&(tid, retry))
            .map(|a| a.reply = Some(reply))
            .is_some()
    }

    /// Retrieve and remove the stored terminal reply of a live attempt.
    pub fn take_reply(&mut self, tid: u64, retry: u32) -> Option<MOSDOpReply> {
        self.live
            .get_mut(&(tid, retry))
            .and_then(|a| a.reply.take())
    }

    /// No live attempt is recorded on the link; later ordinary output may resume.
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(session: u64, tid: u64, retry: u32, rkey: u32) -> Vec<u8> {
        WindowDescriptor {
            attempt: rdma::placement::WindowAttempt {
                connection: session,
                tid,
                retry,
            },
            range: rdma::memory::MemoryRange::new(0x1000, 2 << 20).unwrap(),
            rkey,
        }
        .encode()
        .to_vec()
    }

    fn cancel_record(
        session: u64,
        tid: u64,
        retry: u32,
        rkey: u32,
    ) -> [u8; ControlRecord::ENCODED_LEN] {
        ControlRecord {
            attempt: rdma::placement::WindowAttempt {
                connection: session,
                tid,
                retry,
            },
            rkey,
        }
        .encode(ControlRecord::CANCEL)
    }

    #[test]
    fn admit_needs_the_exact_session_transaction_and_a_fresh_retry() {
        let mut a = Attempts::default();
        assert_eq!(a.admit(5, 7, &descriptor(5, 7, 0, 99)), Ok(0));
        // same session and tid, a fresh retry: a distinct attempt
        assert_eq!(a.admit(5, 7, &descriptor(5, 7, 1, 99)), Ok(1));
        // the same (tid, retry) aliasing a live attempt: refused
        assert_eq!(a.admit(5, 7, &descriptor(5, 7, 0, 99)), Err(Reject::Alias));
        // a descriptor claiming another session's generation: refused
        assert_eq!(
            a.admit(5, 7, &descriptor(6, 7, 2, 99)),
            Err(Reject::Session)
        );
        // no session at all (lossy): refused
        assert_eq!(
            a.admit(0, 7, &descriptor(0, 7, 3, 99)),
            Err(Reject::Session)
        );
        // a descriptor for the frame's tid only: refused
        assert_eq!(a.admit(5, 8, &descriptor(5, 7, 4, 99)), Err(Reject::Tid));
        // not one exact record: refused
        assert_eq!(
            a.admit(5, 7, &descriptor(5, 7, 5, 99)[..43]),
            Err(Reject::Shape)
        );
        let mut bad = descriptor(5, 7, 6, 99);
        bad[2] = 1; // reserved
        assert_eq!(a.admit(5, 7, &bad), Err(Reject::Shape));
        // both admitted attempts vacate through their (tid, retry)
        assert!(a.done(7, 0) && a.done(7, 1));
    }

    #[test]
    fn cancel_retires_only_the_matching_live_attempt() {
        let mut a = Attempts::default();
        a.admit(5, 7, &descriptor(5, 7, 0, 99)).unwrap();
        // a CANCEL for an unknown attempt retires nothing
        assert_eq!(a.cancel(5, &cancel_record(5, 9, 0, 99)), None);
        // a CANCEL claiming another session's generation retires nothing
        assert_eq!(a.cancel(5, &cancel_record(6, 7, 0, 99)), None);
        // a CANCEL with a foreign rkey retires nothing
        assert_eq!(a.cancel(5, &cancel_record(5, 7, 0, 100)), None);
        // the matching one: terminal, returns its (tid, retry)
        assert_eq!(a.cancel(5, &cancel_record(5, 7, 0, 99)), Some((7, 0)));
        // a second CANCEL for the same attempt finds no live attempt
        assert_eq!(a.cancel(5, &cancel_record(5, 7, 0, 99)), None);
        // a RETIRED record is not a CANCEL here
        let retired = ControlRecord {
            attempt: rdma::placement::WindowAttempt {
                connection: 5,
                tid: 7,
                retry: 1,
            },
            rkey: 99,
        }
        .encode(ControlRecord::RETIRED);
        assert_eq!(a.cancel(5, &retired), None);
    }

    #[test]
    fn done_vacates_the_home_once() {
        let mut a = Attempts::default();
        a.admit(5, 7, &descriptor(5, 7, 0, 99)).unwrap();
        assert!(a.done(7, 0));
        assert!(!a.done(7, 0));
    }

    #[test]
    fn a_reply_after_cancel_still_vacates_the_home() {
        let mut a = Attempts::default();
        a.admit(5, 7, &descriptor(5, 7, 0, 99)).unwrap();
        assert_eq!(a.cancel(5, &cancel_record(5, 7, 0, 99)), Some((7, 0)));
        // the op's reply races the CANCEL: it leaves the same home
        assert!(a.done(7, 0));
    }
}
