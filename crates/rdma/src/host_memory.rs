// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Retained foreign CPU-addressable host allocations, independent of verbs.
//! GPU/device memory must use a separate export/visibility/integrity contract.
mod slab;
pub use slab::{
    ForeignHostBacking, ForeignHostLease, ForeignHostSlab, ForeignHostSlabRejected,
    HostRangeLeaseError,
};

use crate::memory::{MemoryRange, MemoryRangeError};
use std::fmt;

/// Numeric rejection returns the original owner before any allocation or provider call.
#[derive(Debug)]
pub struct ForeignHostAllocationRejected<O> {
    pub error: MemoryRangeError,
    pub owner: O,
}

/// Exclusive, initialized foreign host bytes and the object retaining their
/// allocation lifetime. Neither a numeric-address cache nor a borrowed pointer.
/// Registration consumes this handle; uncertainty must retain it permanently.
pub struct ForeignHostAllocation {
    range: MemoryRange,
    owner: Box<dyn Send + Sync>,
}

impl fmt::Debug for ForeignHostAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForeignHostAllocation")
            .field("range", &self.range)
            .finish_non_exhaustive()
    }
}

impl ForeignHostAllocation {
    /// Retain an externally managed host allocation without copying its bytes.
    /// Numeric validation cannot establish mapping, ownership or accessibility.
    ///
    /// # Safety
    /// If numeric validation succeeds, `owner` must retain the same writable,
    /// initialized host allocation at
    /// `address..address+length`, stable until that owner is dropped. This must
    /// be one CPU-addressable allocation with no external concurrent device
    /// access. The address must carry writable pointer provenance (for Rust
    /// Vec storage, obtain it from `as_mut_ptr`, not an immutable slice pointer).
    /// No alias may read, write, free, unmap or relocate it while this handle or
    /// any registration/window derived from it exists; access must go through
    /// these exclusive handles. An owning derived CPU view may delegate its
    /// exact range to a foreign consumer while retaining that range owner; all
    /// such accesses must end before the owner can return to provider use.
    /// Arbitrary byte writes must preserve the owner's
    /// and its destructor's validity. The retained resources must be safe to release
    /// on a control thread. GPU memory does not satisfy this contract.
    pub unsafe fn from_raw_parts<O: Send + Sync + 'static>(
        address: u64,
        length: u64,
        owner: O,
    ) -> Result<Self, ForeignHostAllocationRejected<O>> {
        let range = match MemoryRange::new(address, length) {
            Ok(range) if length <= isize::MAX as u64 => range,
            Ok(_) => {
                return Err(ForeignHostAllocationRejected {
                    error: MemoryRangeError::Overflow,
                    owner,
                });
            }
            Err(error) => return Err(ForeignHostAllocationRejected { error, owner }),
        };
        Ok(Self {
            range,
            owner: Box::new(owner),
        })
    }

    pub fn range(&self) -> MemoryRange {
        self.range
    }

    /// Initialized bytes, accessible only while this allocation is unregistered
    /// or held by the unbound exclusive destination that contains it.
    pub fn buffer(&self) -> &[u8] {
        // SAFETY: construction retains one initialized CPU allocation and
        // excludes external aliases; length fits isize and the address space.
        unsafe {
            std::slice::from_raw_parts(
                self.range.address() as *const u8,
                self.range.length() as usize,
            )
        }
    }

    pub fn buffer_mut(&mut self) -> &mut [u8] {
        // SAFETY: same retained allocation contract, with exclusive access.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.range.address() as *mut u8,
                self.range.length() as usize,
            )
        }
    }

    /// Release the exclusive allocation wrapper to its original lifetime owner.
    /// This object can be recovered from a registration only after provider
    /// retirement. Dropping the returned owner may free the allocation.
    pub fn into_owner(self) -> Box<dyn Send + Sync> {
        self.owner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct Storage {
        bytes: Vec<u8>,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Storage {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn retained_host_owner_preserves_identity_and_releases_exactly_once() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut storage = Storage {
            bytes: vec![0x5a; 4096],
            dropped: dropped.clone(),
        };
        let address = storage.bytes.as_mut_ptr() as u64;
        // SAFETY: the moved Storage owns these initialized bytes exclusively.
        let mut allocation =
            unsafe { ForeignHostAllocation::from_raw_parts(address, 4096, storage) }.unwrap();
        assert_eq!(allocation.buffer().as_ptr() as u64, address);
        allocation.buffer_mut()[1] = 0xa5;
        assert_eq!(allocation.buffer()[1], 0xa5);
        let owner = allocation.into_owner();
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn numeric_rejection_returns_the_exact_owner_without_dereferencing() {
        let dropped = Arc::new(AtomicUsize::new(0));
        for (address, length) in [(0, 1), (1, 0), (u64::MAX, 1), (1, isize::MAX as u64 + 1)] {
            let storage = Storage {
                bytes: vec![1; 8],
                dropped: dropped.clone(),
            };
            let original = storage.bytes.as_ptr();
            // SAFETY: invalid bounds reject before accessing the intentionally
            // unmapped numeric address; no successful foreign handle is built.
            let rejected =
                unsafe { ForeignHostAllocation::from_raw_parts(address, length, storage) }
                    .unwrap_err();
            assert_eq!(rejected.owner.bytes.as_ptr(), original);
            drop(rejected.owner);
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
    }
}
