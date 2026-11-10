// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Source-pull READ destinations (adr 0665) of one core on one RDMA device: one arena,
//! registered once at start. A pull READs exactly its length into a range claimed from the arena
//! ([`::rdma::source_pull::Ring`]); after the READ the range is the op's data segment as [`Bytes`] (no copy, 4 KiB
//! aligned: a direct-IO write view) and returns to the arena when its last reference drops, on whatever core.
//! No room = the pull waits (FIFO, never an error); a released payload rings this core while pulls wait. A READ the core
//! gives up on keeps its range until its QP is destroyed (then the range returns, [`PullArena::abandon`]); placement is
//! first fit, so such a range shrinks the room instead of blocking it.
use crate::wake::Wake;
use ::rdma::host_memory::{ForeignHostAllocation, ForeignHostLease};
use ::rdma::source_pull::{DEST_ALIGN, MAX_TRANSFER, Ring};
use ::rdma::verbs::{Core, Device, HostDestination, ReadHandle, SharedHostRegistration};
use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering, fence};

/// Arena bytes per core and device: the largest PUT ([`MAX_TRANSFER`]) always fits once earlier payloads are released.
pub const ARENA: u64 = MAX_TRANSFER as u64;
/// Payloads of one arena in use at once (READs in flight plus pulled data the store still holds).
const LEASES: usize = 64;

/// One pull the OSD asked for ([`osd::IoCmd::SourcePullRead`]).
#[derive(Clone, Copy, Debug)]
pub(super) struct Pull {
    pub conn: u64,
    pub tid: u64,
    pub source: u64,
    pub rkey: u32,
    pub length: u32,
}

/// The pull destinations of one core on one device.
pub(super) struct PullArena {
    reg: SharedHostRegistration,
    ring: Ring,
    /// Pulls waiting for room or READ admission, oldest first. A later pull never overtakes them (a large one is not
    /// starved by small ones).
    pub waiting: VecDeque<Pull>,
    /// Set while pulls wait: a released payload rings `wake`.
    starved: Arc<AtomicBool>,
    wake: Arc<Wake>,
}

impl std::fmt::Debug for PullArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PullArena")
            .field("waiting", &self.waiting.len())
            .finish_non_exhaustive()
    }
}

/// A pulled payload owned by its `Bytes`: the range returns to the arena when the last reference drops.
struct Payload {
    lease: Option<ForeignHostLease>,
    starved: Arc<AtomicBool>,
    wake: Arc<Wake>,
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        self.lease.as_ref().map_or(&[], ForeignHostLease::buffer)
    }
}

impl Drop for Payload {
    fn drop(&mut self) {
        drop(self.lease.take());
        // pairs with the fence in `PullArena::starve`: either the core sees the released range on its retry, or this
        // sees the flag and rings
        fence(Ordering::SeqCst);
        if self.starved.load(Ordering::Relaxed) {
            self.wake.ring();
        }
    }
}

impl PullArena {
    /// Allocate and register the arena (control path, once per core and device).
    pub fn register(dev: &Arc<Device>, wake: Arc<Wake>) -> std::io::Result<PullArena> {
        let mut backing = vec![0u8; (ARENA + DEST_ALIGN) as usize];
        let base = backing.as_mut_ptr() as u64;
        let address = base.next_multiple_of(DEST_ALIGN);
        // SAFETY: `backing` is an initialized, writable heap allocation owned by the allocation handle from here on; the
        // aligned subrange lies inside it (DEST_ALIGN spare bytes) and the heap buffer never moves.
        let allocation = unsafe { ForeignHostAllocation::from_raw_parts(address, ARENA, backing) }
            .map_err(|e| std::io::Error::other(e.error.to_string()))?;
        let reg =
            SharedHostRegistration::register(dev, allocation, LEASES, None).map_err(|e| e.error)?;
        Ok(PullArena {
            reg,
            ring: Ring::default(),
            waiting: VecDeque::new(),
            starved: Arc::new(AtomicBool::new(false)),
            wake,
        })
    }

    /// A registered destination of exactly `length` bytes, first fit; `None` = no gap fits now.
    pub fn claim(&mut self, length: u32) -> Option<HostDestination> {
        let base = self.reg.range().address();
        let mut ends = [0u64; LEASES];
        let mut n = 0;
        for (end, range) in ends.iter_mut().zip(self.reg.claimed()) {
            *end = range.end() - base;
            n += 1;
        }
        let reg = &mut self.reg;
        self.ring
            .place(ARENA, u64::from(length), &ends[..n], |offset| {
                reg.try_lease(offset, u64::from(length))
            })
    }

    /// A pull READ the core no longer waits for (failed, or its session ends): its range returns to this arena once
    /// the QP it was posted on was destroyed ([`Core::abandon_read`]).
    pub fn abandon(&mut self, core: &mut Core, handle: ReadHandle) {
        core.abandon_read(handle, &mut self.reg);
    }

    /// An unposted destination goes back unchanged.
    pub fn give_back(&mut self, destination: HostDestination) {
        if let Err(destination) = self.reg.reclaim(destination) {
            // not ours (cannot happen): dropping it retires its window, this arena keeps one lease slot less
            eprintln!(
                "knet: rdma: source-pull destination {destination:?} is not of this arena: dropped"
            );
        }
    }

    /// The range of a READ that completed (exact CQ) as the op's data.
    pub fn publish(&mut self, destination: HostDestination) -> Result<Bytes, HostDestination> {
        let lease = self.reg.reclaim_range(destination)?;
        Ok(Bytes::from_owner(Payload {
            lease: Some(lease),
            starved: self.starved.clone(),
            wake: self.wake.clone(),
        }))
    }

    /// Pulls are about to wait: from now on a released payload rings this core. The caller retries once after this
    /// (a range released just before it is seen by that retry).
    pub fn starve(&self) {
        self.starved.store(true, Ordering::Relaxed);
        fence(Ordering::SeqCst);
    }

    /// No pull waits any more.
    pub fn fed(&self) {
        if self.waiting.is_empty() {
            self.starved.store(false, Ordering::Relaxed);
        }
    }
}
