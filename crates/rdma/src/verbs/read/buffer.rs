// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Reusable aligned DMA backing with shared Bytes publication after retirement.
//! Registration stays live while consumer references prevent DMA reuse.
use super::{Core, HostDestination, PendingRead, ReadState, ReadTarget, RemoteReadSource};
use crate::{host_memory::ForeignHostAllocation, memory::MemoryRange, verbs::Device};
use bytes::{Bytes, BytesMut};
use std::{cell::UnsafeCell, fmt, io, sync::Arc};

const ALIGN: usize = 4096;

enum Backing {
    Writable(BytesMut),
    Shared(Bytes),
}

pub(in crate::verbs) struct BufferOwner {
    backing: UnsafeCell<Option<Backing>>,
}

// SAFETY: the private Arc in the registration is a lifetime retainer only.
// Exactly one typed READ or WRITE prepared/pending/shared wrapper controls access. Pending
// exposes no bytes; Shared permits only immutable Bytes clones; conversion back
// to writable consumes that wrapper and requires Bytes::try_into_mut success.
unsafe impl Send for BufferOwner {}
unsafe impl Sync for BufferOwner {}

impl fmt::Debug for BufferOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never inspect bytes: Debug may run while NIC DMA is active.
        f.debug_struct("BufferOwner").finish_non_exhaustive()
    }
}

impl BufferOwner {
    pub(in crate::verbs) fn allocate(length: usize) -> io::Result<(Arc<Self>, MemoryRange)> {
        let capacity = length
            .checked_add(ALIGN)
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if length == 0 || length > u32::MAX as usize {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut allocation = BytesMut::zeroed(capacity);
        // Always split strictly inside the allocation, including an already
        // aligned base. Shared metadata is prepared here, not on publication.
        let offset = ALIGN - (allocation.as_ptr() as usize % ALIGN);
        let mut bytes = allocation.split_off(offset);
        bytes.truncate(length);
        drop(allocation);
        let range = MemoryRange::new(bytes.as_mut_ptr() as u64, length as u64)?;
        Ok((
            Arc::new(Self {
                backing: UnsafeCell::new(Some(Backing::Writable(bytes))),
            }),
            range,
        ))
    }

    pub(in crate::verbs) fn freeze(&self) {
        // SAFETY: consumes the pending wrapper after exact successful READ CQ,
        // or remote WRITE peer retirement plus successful LOCAL_INV;
        // no CPU view existed in Writable/Pending and no other mutator exists.
        let backing = unsafe { &mut *self.backing.get() };
        let Some(Backing::Writable(bytes)) = backing.take() else {
            unreachable!("only retired writable DMA backing can publish");
        };
        *backing = Some(Backing::Shared(bytes.freeze()));
    }

    pub(in crate::verbs) fn bytes(&self) -> &Bytes {
        // SAFETY: only the Shared wrapper calls this; it cannot be consumed for
        // reuse while this reference lives. Registration never reads this cell.
        match unsafe { &*self.backing.get() } {
            Some(Backing::Shared(bytes)) => bytes,
            _ => unreachable!("bytes require completed publication"),
        }
    }

    pub(in crate::verbs) fn thaw(&self) -> bool {
        // SAFETY: consumes the sole Shared wrapper. External Bytes clones may
        // exist, so only the public exclusive conversion can authorize DMA reuse.
        let backing = unsafe { &mut *self.backing.get() };
        let Some(Backing::Shared(bytes)) = backing.take() else {
            unreachable!("only shared publication can return to writable");
        };
        match bytes.try_into_mut() {
            Ok(bytes) => {
                *backing = Some(Backing::Writable(bytes));
                true
            }
            Err(bytes) => {
                *backing = Some(Backing::Shared(bytes));
                false
            }
        }
    }
}

/// Cold-prepared aligned host target. Allocation, zero initialization,
/// Bytes metadata and MR registration happen once in prepare, before posting.
#[derive(Debug)]
pub struct PreparedReadBuffer {
    target: ReadTarget,
    owner: Arc<BufferOwner>,
}

impl PreparedReadBuffer {
    /// Allocate initialized host storage with 4 KiB alignment and register it
    /// once on the control thread. Length is nonzero and fits one READ's u32
    /// byte count. No MW or GPU import is created.
    pub fn prepare(device: &Arc<Device>, length: usize) -> io::Result<Self> {
        let (owner, range) = BufferOwner::allocate(length)?;
        // SAFETY: private owner retains this stable initialized allocation;
        // typed phases exclude all CPU access while the registration is in DMA
        // use. Published immutable views retain Bytes backing and must all end
        // before thaw allows another READ. Device/GPU memory is not accepted.
        let allocation = unsafe {
            ForeignHostAllocation::from_raw_parts(range.address(), range.length(), owner.clone())
        }
        .map_err(|e| io::Error::from(e.error))?;
        let destination =
            HostDestination::register_foreign(device, allocation).map_err(|e| e.error)?;
        Ok(Self {
            target: ReadTarget::prepare(destination),
            owner,
        })
    }

    pub fn range(&self) -> MemoryRange {
        self.target.destination().range()
    }

    #[cfg(all(test, feature = "fault-inject"))]
    pub(super) fn test_owner(&self) -> std::sync::Weak<dyn Send + Sync> {
        let owner: Arc<dyn Send + Sync> = self.owner.clone();
        Arc::downgrade(&owner)
    }
}

/// Rejected posting returns the same registration, allocation and prepared metadata.
#[derive(Debug)]
pub struct ReadBufferPostError {
    pub error: io::Error,
    pub buffer: PreparedReadBuffer,
}

/// In-flight DMA. No byte accessor. Abandonment follows ReadHandle's retention
/// contract and cannot free backing that the provider may still write.
#[derive(Debug)]
pub struct PendingReadBuffer {
    handle: PendingRead,
    owner: Arc<BufferOwner>,
}

impl PendingReadBuffer {
    pub fn state(&self) -> ReadState {
        self.handle.state()
    }

    /// Publish after exact successful local CQ retirement. This is not integrity
    /// verification or durable object completion; the object path must supply both.
    pub fn try_finish(self) -> Result<SharedReadBuffer, Self> {
        let Self { handle, owner } = self;
        match handle.into_target() {
            Ok(target) => {
                owner.freeze();
                Ok(SharedReadBuffer { target, owner })
            }
            Err(handle) => Err(Self { handle, owner }),
        }
    }
}

/// CPU-readable shared payload after local READ completion. Cloning Bytes adds
/// only references. A consumer (including an NVMe write view) may keep those
/// references after this wrapper drops; the allocation remains alive.
#[derive(Debug)]
pub struct SharedReadBuffer {
    target: ReadTarget,
    owner: Arc<BufferOwner>,
}

impl SharedReadBuffer {
    pub fn bytes(&self) -> &Bytes {
        self.owner.bytes()
    }
    pub fn range(&self) -> MemoryRange {
        self.target.destination().range()
    }

    /// Reuse the original registration only when every consumer clone/slice is
    /// gone. Refusal retains publication unchanged. No hidden wait or copying
    /// fallback; callers resume after their consumer's ownership retires.
    pub fn try_reuse(self) -> Result<PreparedReadBuffer, Self> {
        if !self.owner.thaw() {
            return Err(self);
        }
        Ok(PreparedReadBuffer {
            target: self.target,
            owner: self.owner,
        })
    }
}

impl Core {
    /// Consume one whole prepared buffer for a signalled READ. Rejection returns
    /// its exact owner; success exposes only the pending handle until exact CQ
    /// retirement. Uses the same source grant and admission rules as `read`.
    #[cfg_attr(
        test,
        expect(
            clippy::result_large_err,
            reason = "test-only injected registration fields enlarge the unchanged owner returned on admission refusal; boxing would allocate on backpressure"
        )
    )]
    pub fn read_buffer(
        &mut self,
        qpn: u32,
        buffer: PreparedReadBuffer,
        source: RemoteReadSource,
    ) -> Result<PendingReadBuffer, ReadBufferPostError> {
        let PreparedReadBuffer { target, owner } = buffer;
        match self.read(qpn, target, source) {
            Ok(handle) => Ok(PendingReadBuffer {
                handle: handle.read,
                owner,
            }),
            Err(rejected) => Err(ReadBufferPostError {
                error: rejected.error,
                buffer: PreparedReadBuffer {
                    target: rejected.target,
                    owner,
                },
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_backing_refuses_reuse_until_all_slices_release_without_allocations() {
        for length in [1, 4095, 4096, 65536, 1024 * 1024] {
            let (owner, range) = BufferOwner::allocate(length).unwrap();
            assert_eq!(range.address() % ALIGN as u64, 0);
            for _ in 0..8 {
                let (_, allocations) = crate::test_alloc::count(|| {
                    owner.freeze();
                    let clone = owner.bytes().clone();
                    let slice = clone.slice(0..1);
                    assert_eq!(clone.as_ptr() as u64, range.address());
                    assert!(!owner.thaw());
                    drop(clone);
                    assert!(!owner.thaw());
                    drop(slice);
                    assert!(owner.thaw());
                });
                assert_eq!(allocations, 0);
            }
        }
    }

    #[test]
    fn shared_payload_outlives_the_registration_lifetime_owner() {
        let (owner, range) = BufferOwner::allocate(4096).unwrap();
        owner.freeze();
        let payload = owner.bytes().clone();
        drop(owner);
        assert_eq!(payload.as_ptr() as u64, range.address());
        assert!(payload.iter().all(|b| *b == 0));
    }

    #[test]
    fn invalid_capacity_is_rejected_before_allocation() {
        for length in [0, usize::MAX] {
            let (result, allocations) = crate::test_alloc::count(|| BufferOwner::allocate(length));
            assert!(result.is_err());
            assert_eq!(allocations, 0);
        }
    }
}
