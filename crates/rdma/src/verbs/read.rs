// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Signalled host RDMA READ with exact CQ identity on the existing RC SQ.
//! This primitive grants neither remote source access nor object durability.
use super::{Core, HostDestination, SharedHostRegistration, ffi, post_failure, wr_id};
use crate::completion::{IDLE, READ_DONE, READ_PENDING};
use crate::memory::MemoryRange;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
};

pub(super) mod buffer;
pub use buffer::{PendingReadBuffer, PreparedReadBuffer, ReadBufferPostError, SharedReadBuffer};

#[cfg(all(test, feature = "fault-inject"))]
mod tests;

static QUARANTINED_TARGETS: AtomicU64 = AtomicU64::new(0);

/// Targets permanently retained after abandonment or uncertain completion.
pub fn quarantined_read_targets() -> u64 {
    QUARANTINED_TARGETS.load(Ordering::Relaxed)
}

pub(super) fn count_quarantined(n: usize) {
    QUARANTINED_TARGETS.fetch_add(n as u64, Ordering::Relaxed);
}

/// Numeric source bounds and opaque key from an authenticated, live peer grant.
#[derive(Clone, Copy, Debug)]
pub struct RemoteReadSource {
    range: MemoryRange,
    rkey: u32,
}

impl RemoteReadSource {
    /// # Safety
    /// The same authenticated RC peer/attempt must authorize this readable
    /// source range. Its bytes must be immutable and its registration/grant live
    /// until this READ completes or both QPs retire. No numeric validation can
    /// establish authorization, lifetime, revocation or source producer ordering.
    pub unsafe fn from_raw_parts(address: u64, length: u64, rkey: u32) -> io::Result<Self> {
        Ok(Self {
            range: MemoryRange::new(address, length)?,
            rkey,
        })
    }

    pub fn range(self) -> MemoryRange {
        self.range
    }

    pub fn subrange(self, offset: u64, length: u64) -> io::Result<Self> {
        Ok(Self {
            range: self.range.subrange(offset, length)?,
            rkey: self.rkey,
        })
    }
}

/// An exclusive, initialized host destination prepared on a control thread.
/// The completion identity is reused across successful transfers, without an
/// allocation, payload copy or provider registration in the posting path.
#[derive(Debug)]
pub struct ReadTarget {
    destination: HostDestination,
    completion: Arc<AtomicU8>,
}

impl ReadTarget {
    pub fn prepare(destination: HostDestination) -> Self {
        Self {
            destination,
            completion: Arc::new(AtomicU8::new(IDLE)),
        }
    }

    pub fn destination(&self) -> &HostDestination {
        &self.destination
    }
    pub fn destination_mut(&mut self) -> &mut HostDestination {
        &mut self.destination
    }
    pub fn into_destination(self) -> HostDestination {
        self.destination
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadState {
    Pending,
    Complete,
    Failed,
}

/// Posting refusal returns the exact unaccepted destination to the caller.
#[derive(Debug)]
pub struct ReadPostError {
    pub error: io::Error,
    pub target: ReadTarget,
}

/// No CPU access until the exact successful READ CQE. Completion establishes
/// local host DMA retirement, not integrity, a peer source-release protocol,
/// GPU visibility, a successful object operation or a durable acknowledgement.
#[derive(Debug)]
pub struct ReadHandle {
    read: PendingRead,
    /// The QP the READ was posted on: its number and the connection generation ([`wr_id`] epoch), since a QP
    /// number is reused after a destroy. Only that exact QP's destroy proves the NIC stopped writing the target
    /// ([`Core::abandon_read`]).
    qpn: u32,
    epoch: u32,
}

impl ReadHandle {
    pub fn state(&self) -> ReadState {
        self.read.state()
    }

    /// Return the same prepared allocation only after exact successful CQ
    /// retirement. Failed/pending states retain ownership and provide no bytes.
    pub fn into_target(self) -> Result<ReadTarget, Self> {
        let Self { read, qpn, epoch } = self;
        read.into_target().map_err(|read| Self { read, qpn, epoch })
    }
}

/// The posted target and its completion state, without the QP identity (owners that never abandon a READ onto a QP,
/// e.g. [`PendingReadBuffer`], keep only this). Dropped before success = quarantined for good (counted).
#[derive(Debug)]
pub(super) struct PendingRead {
    target: Option<ReadTarget>,
}

impl PendingRead {
    pub(super) fn state(&self) -> ReadState {
        match self
            .target
            .as_ref()
            .expect("READ owns target")
            .completion
            .load(Ordering::Acquire)
        {
            READ_PENDING => ReadState::Pending,
            READ_DONE => ReadState::Complete,
            _ => ReadState::Failed,
        }
    }

    pub(super) fn into_target(mut self) -> Result<ReadTarget, Self> {
        if self.state() != ReadState::Complete {
            return Err(self);
        }
        let target = self.target.take().expect("completed READ owns target");
        target.completion.store(IDLE, Ordering::Relaxed);
        Ok(target)
    }
}

impl Drop for PendingRead {
    fn drop(&mut self) {
        if self.target.is_some() && self.state() != ReadState::Complete {
            // A fault is not QP-quiescence proof. Preserve the exact allocation,
            // MR and device; never deregister them in CQ progress or after a timer.
            QUARANTINED_TARGETS.fetch_add(1, Ordering::Relaxed);
            std::mem::forget(self.target.take().expect("uncertain READ owns target"));
        }
    }
}

impl Core {
    /// Give up on a READ without waiting for its success (it failed, or its session ends) and return its destination
    /// to `registration` once the NIC provably cannot write it any more: a completed READ's range at once; otherwise
    /// the range stays claimed by the exact QP the READ was posted on (number and generation, carried by the handle)
    /// and is released after that QP was destroyed ([`Core::detach`], then the control thread's teardown), or kept
    /// forever if that teardown is uncertain. Without QP proof (that QP is gone or its number now names a newer
    /// connection, or the destination is not a child of `registration`) the range is quarantined for good (loud,
    /// counted). No provider call or allocation beyond the QP's retained list.
    pub fn abandon_read(
        &mut self,
        mut handle: ReadHandle,
        registration: &mut SharedHostRegistration,
    ) {
        if handle.state() == ReadState::Complete {
            if let Ok(target) = handle.into_target()
                && let Err(destination) = registration.reclaim(target.into_destination())
            {
                diag::diag!(
                    "WARNING rdma: completed READ destination rejected by its registration"
                );
                drop(destination);
            }
            return;
        }
        let qpn = handle.qpn;
        let Some(c) = self.conns.get_mut(&qpn).filter(|c| c.epoch == handle.epoch) else {
            diag::diag!(
                "WARNING rdma: qpn {qpn} generation {}: abandoned READ without its QP: destination quarantined for good",
                handle.epoch
            );
            return; // `handle` drops: quarantined, counted
        };
        let target = handle.read.target.take().expect("READ owns target");
        match registration.retain_range(target.destination) {
            Ok(range) => c.qp.retained().reads.push(range),
            Err(destination) => {
                diag::diag!(
                    "WARNING rdma: qpn {qpn}: abandoned READ destination is not a child of the registration: quarantined for good"
                );
                handle.read.target = Some(ReadTarget {
                    destination,
                    completion: target.completion,
                });
            }
        }
    }

    /// Read a whole prepared host range, always signalled, on the same SQ as
    /// SEND/WRITE/MW work. Consumes no SEND credit. Local admission backpressure
    /// returns `WouldBlock`; provider rejection faults the connection and returns
    /// this unaccepted target, while earlier accepted work remains retained.
    pub fn read(
        &mut self,
        qpn: u32,
        target: ReadTarget,
        source: RemoteReadSource,
    ) -> Result<ReadHandle, ReadPostError> {
        let reject = |error, target| Err(ReadPostError { error, target });
        let range = target.destination.range();
        if range.length() != source.range.length() || range.length() > u64::from(u32::MAX) {
            return reject(io::ErrorKind::InvalidInput.into(), target);
        }
        if self.broken.is_some() {
            return reject(io::ErrorKind::ConnectionAborted.into(), target);
        }
        let Some(c) = self.conns.get_mut(&qpn) else {
            return reject(io::ErrorKind::NotConnected.into(), target);
        };
        if c.faulted {
            return reject(io::ErrorKind::ConnectionAborted.into(), target);
        }
        let depth = c.qp.read_depths().outgoing();
        if depth == 0 {
            return reject(io::ErrorKind::Unsupported.into(), target);
        }
        let (dev, lkey) = target.destination.read_registration();
        if !Arc::ptr_eq(dev, &c.qp.dev) {
            return reject(io::ErrorKind::InvalidInput.into(), target);
        }
        if c.tx.sq.full() || c.tx.sq.pending_reads() >= u32::from(depth) {
            c.read_waiting = true;
            return reject(io::ErrorKind::WouldBlock.into(), target);
        }
        let seq = c.tx.sq.next_sequence();
        // SAFETY: exclusive initialized target, live writable MR in the same
        // PD; unsafe RemoteReadSource construction requires the live peer grant.
        let post = || unsafe {
            ffi::rv_post_read(
                c.qp.p,
                wr_id(c.epoch, seq),
                range.address(),
                range.length() as u32,
                lkey,
                source.range.address(),
                source.rkey,
            )
        };
        #[cfg(test)]
        let rc = self.read_post_error.take().unwrap_or_else(post);
        #[cfg(not(test))]
        let rc = post();
        self.stats.tx_doorbells += 1;
        if rc != 0 {
            c.fail();
            self.stats.faults += 1;
            self.post_failed.push(qpn);
            return reject(post_failure(rc), target);
        }
        target.completion.store(READ_PENDING, Ordering::Release);
        let accepted = c.tx.sq.push_read(target.completion.clone());
        debug_assert_eq!(accepted, seq);
        Ok(ReadHandle {
            read: PendingRead {
                target: Some(target),
            },
            qpn,
            epoch: c.epoch,
        })
    }
}
