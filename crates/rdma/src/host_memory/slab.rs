// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Bounded exclusive range ownership below a future shared host registration.
//! This module registers no MR and authorizes no device access by itself.
use super::ForeignHostAllocation;
use crate::memory::{MemoryRange, MemoryRangeError};
use std::{
    cell::UnsafeCell,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct Backing {
    range: MemoryRange,
    allocation: UnsafeCell<ForeignHostAllocation>,
    occupied: Box<[AtomicBool]>,
}

// SAFETY: the allocation remains stable and is never borrowed as a whole while
// shared. Only the controller creates leases; their checked ranges are disjoint.
// Each lease exclusively owns its range until Drop release-publishes retirement.
// Recovering the whole allocation requires unique Arc ownership, excluding both
// leases and provider backing retainers. No external aliases are permitted by
// ForeignHostAllocation's construction contract.
unsafe impl Sync for Backing {}

/// Cold setup failure returns the original allocation, without provider calls.
#[derive(Debug)]
pub struct ForeignHostSlabRejected {
    pub error: io::Error,
    pub allocation: ForeignHostAllocation,
}

/// Nonallocating range-claim rejection. Overlap includes quarantined claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostRangeLeaseError {
    Range(MemoryRangeError),
    Capacity,
}

impl fmt::Display for HostRangeLeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Range(error) => error.fmt(f),
            Self::Capacity => f.write_str("foreign host range lease capacity exhausted"),
        }
    }
}
impl std::error::Error for HostRangeLeaseError {}

/// One controller for independently owned, checked nonoverlapping host ranges.
/// Setup preallocates the complete claim ledger; claim/release neither allocate
/// nor lock. Admission scans bounded metadata, never payload bytes.
///
/// There is no whole-allocation CPU view. Provider wrappers must retain both
/// their exact range lease and a backing retainer through device retirement;
/// these memory owners alone do not establish MR/MW or GPU support.
pub struct ForeignHostSlab {
    backing: Arc<Backing>,
    ranges: Vec<Option<MemoryRange>>,
}

impl fmt::Debug for ForeignHostSlab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForeignHostSlab")
            .field("range", &self.range())
            .field("capacity", &self.ranges.len())
            .finish_non_exhaustive()
    }
}

impl ForeignHostSlab {
    /// Consume the exclusive allocation on a control path. Zero capacity and
    /// metadata reservation failure return that exact allocation unchanged.
    pub fn new(
        allocation: ForeignHostAllocation,
        capacity: usize,
    ) -> Result<Self, ForeignHostSlabRejected> {
        let mut ranges = Vec::new();
        let mut occupied = Vec::new();
        let reserve = || -> io::Result<_> {
            if capacity == 0 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            ranges
                .try_reserve_exact(capacity)
                .map_err(io::Error::other)?;
            occupied
                .try_reserve_exact(capacity)
                .map_err(io::Error::other)?;
            Ok((ranges, occupied))
        };
        let (mut ranges, mut occupied) = match reserve() {
            Ok(storage) => storage,
            Err(error) => return Err(ForeignHostSlabRejected { error, allocation }),
        };
        ranges.resize(capacity, None);
        occupied.extend((0..capacity).map(|_| AtomicBool::new(false)));
        Ok(Self {
            backing: Arc::new(Backing {
                range: allocation.range(),
                allocation: UnsafeCell::new(allocation),
                occupied: occupied.into_boxed_slice(),
            }),
            ranges,
        })
    }

    pub fn range(&self) -> MemoryRange {
        self.backing.range
    }

    /// Keep the allocation mapped without granting CPU or device access. A
    /// provider must retain this guard until its MR deregistration is proved.
    pub fn retain_backing(&self) -> ForeignHostBacking {
        ForeignHostBacking {
            backing: Arc::clone(&self.backing),
        }
    }

    /// Whether only this controller and the given provider retainer own the
    /// allocation. Count owners rather than occupied slots: lease Drop clears
    /// its slot before releasing its backing Arc on another thread.
    #[cfg(any(test, all(feature = "memory-windows", target_os = "linux")))]
    pub(crate) fn is_exclusive_with(&self, backing: &ForeignHostBacking) -> bool {
        Arc::ptr_eq(&self.backing, &backing.backing) && Arc::strong_count(&self.backing) == 2
    }

    /// Claim an exact nonempty byte range. Adjacent ranges may coexist. A
    /// retired slot is reused only after acquiring its lease's Drop store;
    /// ranges still owned by another thread or quarantined cannot overlap.
    pub fn try_lease(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<ForeignHostLease, HostRangeLeaseError> {
        self.claim_where(offset, length, |_| true)
    }

    pub(crate) fn claim_where(
        &mut self,
        offset: u64,
        length: u64,
        eligible: impl Fn(usize) -> bool,
    ) -> Result<ForeignHostLease, HostRangeLeaseError> {
        let range = self
            .range()
            .subrange(offset, length)
            .map_err(HostRangeLeaseError::Range)?;
        let mut free = None;
        for (slot, previous) in self.ranges.iter_mut().enumerate() {
            if !self.backing.occupied[slot].load(Ordering::Acquire) {
                *previous = None;
                if eligible(slot) {
                    free.get_or_insert(slot);
                }
            } else if previous
                .is_some_and(|old| old.address() < range.end() && range.address() < old.end())
            {
                return Err(HostRangeLeaseError::Range(MemoryRangeError::Overlap));
            }
        }
        let slot = free.ok_or(HostRangeLeaseError::Capacity)?;
        self.ranges[slot] = Some(range);
        // Only this controller sets occupied. A subsequent controller load
        // cannot observe a false older than this store (write/read coherence).
        self.backing.occupied[slot].store(true, Ordering::Relaxed);
        Ok(ForeignHostLease {
            backing: Arc::clone(&self.backing),
            range,
            slot,
        })
    }

    /// The ranges claimed now (live or quarantined leases), in slot order; at most the slab capacity. A range whose
    /// lease is dropping concurrently may still be listed (a later claim sees it free).
    pub fn claimed(&self) -> impl Iterator<Item = MemoryRange> + '_ {
        self.ranges
            .iter()
            .zip(self.backing.occupied.iter())
            .filter(|(_, occupied)| occupied.load(Ordering::Acquire))
            .filter_map(|(range, _)| *range)
    }

    #[cfg(all(feature = "memory-windows", target_os = "linux"))]
    pub(crate) fn slot_is_occupied(&self, slot: usize) -> bool {
        self.backing.occupied[slot].load(Ordering::Acquire)
    }

    /// Recover the exclusive allocation only after all leases and registration
    /// retainers are gone. Busy rejection returns the complete controller.
    pub fn try_into_allocation(self) -> Result<ForeignHostAllocation, Self> {
        match Arc::try_unwrap(self.backing) {
            Ok(backing) => Ok(backing.allocation.into_inner()),
            Err(backing) => Err(Self {
                backing,
                ranges: self.ranges,
            }),
        }
    }
}

/// Provider lifetime guard without whole-allocation byte access. Retaining
/// mapping is distinct from owning a range or proving device retirement.
pub struct ForeignHostBacking {
    backing: Arc<Backing>,
}

impl ForeignHostBacking {
    pub fn range(&self) -> MemoryRange {
        self.backing.range
    }
}

impl fmt::Debug for ForeignHostBacking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForeignHostBacking")
            .field("range", &self.range())
            .finish_non_exhaustive()
    }
}

/// Exclusive initialized CPU bytes in one slab range, transferable between
/// threads. Safe byte access cannot create a reference to a sibling's range.
/// Provider owners must consume this handle while device access is possible
/// and return it only after their retirement/integrity contract is satisfied.
#[must_use]
pub struct ForeignHostLease {
    backing: Arc<Backing>,
    range: MemoryRange,
    slot: usize,
}

impl fmt::Debug for ForeignHostLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForeignHostLease")
            .field("range", &self.range)
            .finish_non_exhaustive()
    }
}

impl ForeignHostLease {
    #[cfg(all(feature = "memory-windows", target_os = "linux"))]
    pub(crate) fn slot(&self) -> usize {
        self.slot
    }

    pub fn range(&self) -> MemoryRange {
        self.range
    }

    pub fn buffer(&self) -> &[u8] {
        // SAFETY: construction checked this initialized subrange, its parent
        // length fits isize, and no overlapping lease can exist. No reference
        // to the whole allocation is materialized, including through its owner.
        unsafe {
            std::slice::from_raw_parts(
                self.range.address() as *const u8,
                self.range.length() as usize,
            )
        }
    }

    pub fn buffer_mut(&mut self) -> &mut [u8] {
        // SAFETY: the same exact-range contract, with an exclusive lease borrow.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.range.address() as *mut u8,
                self.range.length() as usize,
            )
        }
    }

    /// Permanently retain an uncertain device owner's exact backing and claim.
    /// No timeout, controller drop or later lease may release/reuse this range.
    /// This is retention, not a provider retirement or GPU capability proof.
    pub fn quarantine(self) {
        std::mem::forget(self);
    }
}

impl Drop for ForeignHostLease {
    fn drop(&mut self) {
        // Safe references derived from this lease ended before Drop. Provider
        // wrappers may reach Drop only after their separate device proof.
        self.backing.occupied[self.slot].store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct Owner {
        bytes: Vec<u8>,
        released: Arc<AtomicUsize>,
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn provider_release_waits_for_reclaimed_ranges_and_their_dropping_owners() {
        let (allocation, _, _) = allocation();
        let mut slab = ForeignHostSlab::new(allocation, 1).unwrap();
        let provider = slab.retain_backing();
        assert!(slab.is_exclusive_with(&provider));
        let lease = slab.try_lease(0, 32).unwrap();
        assert!(!slab.is_exclusive_with(&provider));
        // Stage the interval inside ForeignHostLease::drop after publishing
        // slot retirement but before releasing its allocation owner.
        slab.backing.occupied[lease.slot].store(false, Ordering::Release);
        assert_eq!(slab.claimed().count(), 0);
        assert!(!slab.is_exclusive_with(&provider));
        drop(lease);
        assert!(slab.is_exclusive_with(&provider));
        drop(provider);
        drop(slab.try_into_allocation().unwrap());
    }

    fn allocation() -> (ForeignHostAllocation, Arc<AtomicUsize>, u64) {
        let released = Arc::new(AtomicUsize::new(0));
        let mut owner = Owner {
            bytes: vec![0x5a; 96],
            released: released.clone(),
        };
        let address = owner.bytes.as_mut_ptr() as u64;
        // SAFETY: the moved owner retains these initialized, exclusive bytes.
        let allocation =
            unsafe { ForeignHostAllocation::from_raw_parts(address, 96, owner) }.unwrap();
        (allocation, released, address)
    }

    #[test]
    fn slab_rejects_overlap_bounds_and_exhaustion_without_losing_claims() {
        let (allocation, released, address) = allocation();
        let mut slab = ForeignHostSlab::new(allocation, 2).unwrap();
        let left = slab.try_lease(0, 32).unwrap();
        let right = slab.try_lease(32, 32).unwrap();
        assert_eq!(left.buffer().len(), 32);
        assert_eq!(left.buffer().as_ptr() as u64, address);
        assert_eq!(right.buffer().as_ptr() as u64, address + 32);
        for (offset, length) in [(0, 1), (31, 2), (32, 1), (1, 62)] {
            assert_eq!(
                slab.try_lease(offset, length).unwrap_err(),
                HostRangeLeaseError::Range(MemoryRangeError::Overlap)
            );
        }
        assert_eq!(
            slab.try_lease(64, 32).unwrap_err(),
            HostRangeLeaseError::Capacity
        );
        for (offset, length, error) in [
            (0, 0, MemoryRangeError::Empty),
            (96, 1, MemoryRangeError::Outside),
            (95, 2, MemoryRangeError::Outside),
            (u64::MAX, 1, MemoryRangeError::Overflow),
        ] {
            assert_eq!(
                slab.try_lease(offset, length).unwrap_err(),
                HostRangeLeaseError::Range(error)
            );
        }
        drop(left);
        let replacement = slab.try_lease(0, 32).unwrap();
        assert_eq!(replacement.range().address(), address);
        drop((right, replacement));
        let allocation = slab.try_into_allocation().unwrap();
        assert!(allocation.buffer().iter().all(|&b| b == 0x5a));
        drop(allocation);
        assert_eq!(released.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn disjoint_cpu_writers_and_reader_do_not_materialize_a_whole_buffer() {
        let (allocation, released, _) = allocation();
        let mut slab = ForeignHostSlab::new(allocation, 3).unwrap();
        let mut left = slab.try_lease(0, 32).unwrap();
        let mut middle = slab.try_lease(32, 32).unwrap();
        let mut right = slab.try_lease(64, 32).unwrap();
        let arrived = Arc::new(Barrier::new(3));
        let resume = Arc::new(Barrier::new(3));
        let writers: Vec<_> = [(left, 1), (middle, 2)]
            .into_iter()
            .map(|(mut lease, byte)| {
                let (arrived, resume) = (arrived.clone(), resume.clone());
                std::thread::spawn(move || {
                    lease.buffer_mut().fill(byte);
                    arrived.wait();
                    resume.wait();
                    lease
                })
            })
            .collect();
        arrived.wait();
        right.buffer_mut().fill(3);
        let right_matches = right.buffer().iter().all(|&b| b == 3);
        let overlapping = slab.try_lease(31, 2);
        // Release and join every writer before asserting, even on failure.
        resume.wait();
        let mut writers = writers.into_iter();
        left = writers.next().unwrap().join().unwrap();
        middle = writers.next().unwrap().join().unwrap();
        assert!(right_matches);
        assert!(matches!(
            overlapping,
            Err(HostRangeLeaseError::Range(MemoryRangeError::Overlap))
        ));
        assert!(left.buffer().iter().all(|&b| b == 1));
        assert!(middle.buffer().iter().all(|&b| b == 2));
        drop((left, middle, right));
        let allocation = slab.try_into_allocation().unwrap();
        assert_eq!(&allocation.buffer()[..32], &[1; 32]);
        assert_eq!(&allocation.buffer()[32..64], &[2; 32]);
        assert_eq!(&allocation.buffer()[64..], &[3; 32]);
        drop(allocation);
        assert_eq!(released.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn release_acquire_handoff_makes_previous_range_writes_visible_before_join() {
        let (allocation, released, _) = allocation();
        let mut slab = ForeignHostSlab::new(allocation, 1).unwrap();
        let mut first = slab.try_lease(0, 32).unwrap();
        let worker = std::thread::spawn(move || {
            first.buffer_mut().fill(0x19);
            drop(first);
        });
        let started = std::time::Instant::now();
        let next = loop {
            match slab.try_lease(0, 32) {
                Ok(next) => break Some(next),
                Err(HostRangeLeaseError::Range(MemoryRangeError::Overlap)) => {
                    if started.elapsed() >= std::time::Duration::from_secs(10) {
                        diag::diag!("WARNING TIMEOUT foreign host lease handoff exceeded 10s");
                        break None;
                    }
                    std::thread::yield_now();
                }
                Err(error) => panic!("unexpected handoff rejection: {error}"),
            }
        };
        // Read before join: only the slot's release/acquire handshake orders
        // these payload writes. Joining first would hide a missing atomic edge.
        let observed = next.as_ref().map(|lease| lease.buffer()[0]);
        worker.join().unwrap();
        assert_eq!(observed, Some(0x19));
        drop(next);
        drop(slab.try_into_allocation().unwrap());
        assert_eq!(released.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn busy_recovery_preserves_controller_and_exact_original_allocation() {
        let (allocation, released, address) = allocation();
        let mut slab = ForeignHostSlab::new(allocation, 1).unwrap();
        let mut lease = slab.try_lease(7, 13).unwrap();
        let slab = slab.try_into_allocation().unwrap_err();
        lease.buffer_mut().fill(7);
        assert_eq!(released.load(Ordering::Relaxed), 0);
        drop(lease);
        let allocation = slab.try_into_allocation().unwrap();
        assert_eq!(allocation.buffer().as_ptr() as u64, address);
        assert_eq!(&allocation.buffer()[7..20], &[7; 13]);
        assert!(allocation.buffer()[..7].iter().all(|&b| b == 0x5a));
        assert!(allocation.buffer()[20..].iter().all(|&b| b == 0x5a));
        drop(allocation);
        assert_eq!(released.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn backing_retainer_blocks_recovery_without_granting_cpu_access() {
        let (allocation, released, _) = allocation();
        let slab = ForeignHostSlab::new(allocation, 1).unwrap();
        let backing = slab.retain_backing();
        assert_eq!(backing.range(), slab.range());
        let slab = slab.try_into_allocation().unwrap_err();
        drop(backing);
        drop(slab.try_into_allocation().unwrap());
        assert_eq!(released.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn controller_drop_keeps_each_live_range_until_its_last_owner_retires() {
        let (allocation, released, _) = allocation();
        let mut slab = ForeignHostSlab::new(allocation, 2).unwrap();
        let mut left = slab.try_lease(0, 32).unwrap();
        let right = slab.try_lease(32, 32).unwrap();
        drop(slab);
        left.buffer_mut().fill(9);
        assert!(right.buffer().iter().all(|&b| b == 0x5a));
        drop(left);
        assert_eq!(released.load(Ordering::Relaxed), 0);
        drop(right);
        assert_eq!(released.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn quarantine_retains_exact_owner_and_prevents_later_overlapping_claim() {
        let (allocation, released, _) = allocation();
        let mut slab = ForeignHostSlab::new(allocation, 2).unwrap();
        slab.try_lease(0, 32).unwrap().quarantine();
        assert_eq!(
            slab.try_lease(0, 1).unwrap_err(),
            HostRangeLeaseError::Range(MemoryRangeError::Overlap)
        );
        let other = slab.try_lease(32, 32).unwrap();
        drop(other);
        let slab = slab.try_into_allocation().unwrap_err();
        drop(slab);
        assert_eq!(released.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn setup_rejections_return_the_original_owner_without_provider_work() {
        for capacity in [0, usize::MAX] {
            let (allocation, released, address) = allocation();
            let rejected = ForeignHostSlab::new(allocation, capacity).unwrap_err();
            assert_eq!(rejected.allocation.buffer().as_ptr() as u64, address);
            assert_eq!(released.load(Ordering::Relaxed), 0);
            drop(rejected);
            assert_eq!(released.load(Ordering::Relaxed), 1);
        }
    }

    #[cfg(feature = "memory-windows")]
    #[test]
    fn repeated_range_claim_release_and_rejections_allocate_nothing() {
        let (allocation, _, _) = allocation();
        let mut slab = ForeignHostSlab::new(allocation, 2).unwrap();
        let (_, allocations) = crate::test_alloc::count(|| {
            for offset in 0..1024 {
                let offset = offset % 64;
                let mut lease = slab.try_lease(offset, 16).unwrap();
                lease.buffer_mut().fill(0x37);
                assert_eq!(
                    slab.try_lease(offset, 1).unwrap_err(),
                    HostRangeLeaseError::Range(MemoryRangeError::Overlap)
                );
                drop(lease);
            }
        });
        assert_eq!(allocations, 0);
    }
}
