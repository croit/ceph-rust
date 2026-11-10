// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Reusable remote-WRITE targets published as shared storage payloads only after
//! peer retirement and exact LOCAL_INV completion. No object success is implied.
use super::super::{
    AdvertisedWindow, Core, Device, HostDestination, LocalWindow, UnboundWindow, WindowAttempt,
    WindowDescriptor, WindowState, read::buffer::BufferOwner,
};
use crate::{host_memory::ForeignHostAllocation, memory::MemoryRange};
use bytes::Bytes;
use std::{io, sync::Arc};

/// Aligned initialized host target with an MR and reusable type-2 MW prepared
/// on the control thread. No payload or provider allocation occurs on BIND,
/// publication or exclusive recovery. This is not GPU memory.
#[derive(Debug)]
pub struct PreparedWriteBuffer {
    window: UnboundWindow,
    owner: Arc<BufferOwner>,
}

impl PreparedWriteBuffer {
    /// Allocate 4 KiB-aligned host backing and prepare registration/window once.
    /// The initialized length must be nonzero and fit u32. A new attempt can
    /// overwrite it only after all prior shared consumers have released it.
    pub fn prepare(device: &Arc<Device>, length: usize) -> io::Result<Self> {
        let (owner, range) = BufferOwner::allocate(length)?;
        // SAFETY: this private owner retains initialized stable host bytes.
        // Typed phases expose no CPU view while a peer can write. After
        // retirement immutable Bytes clones prevent thaw until all are gone.
        let allocation = unsafe {
            ForeignHostAllocation::from_raw_parts(range.address(), range.length(), owner.clone())
        }
        .map_err(|error| io::Error::from(error.error))?;
        let destination = HostDestination::register_foreign_prepared(device, allocation)
            .map_err(|error| error.error)?;
        let window = UnboundWindow::allocate(destination).map_err(|error| error.error)?;
        Ok(Self { window, owner })
    }

    pub fn range(&self) -> MemoryRange {
        self.window.range()
    }
}

/// BIND admission refusal preserves the exact prepared registration/window.
#[derive(Debug)]
pub struct WriteBufferBindError {
    pub error: io::Error,
    pub buffer: PreparedWriteBuffer,
}

/// Unadvertised WRITE target. No CPU bytes or remote key are exposed. An unused
/// binding still requires successful local invalidation before recovery.
#[derive(Debug)]
pub struct LocalWriteBuffer {
    local: LocalWindow,
    owner: Arc<BufferOwner>,
}

impl LocalWriteBuffer {
    pub fn state(&self) -> WindowState {
        self.local.state()
    }

    /// Publish only after successful BIND on the same live QP. Refusal returns
    /// the unchanged local owner, with no allocation or copying fallback.
    #[expect(
        clippy::result_large_err,
        reason = "return the exact owner without allocation"
    )]
    pub fn advertise(
        self,
        core: &Core,
        attempt: WindowAttempt,
    ) -> Result<AdvertisedWriteBuffer, Self> {
        let Self { local, owner } = self;
        match local.advertise(core, attempt) {
            Ok(window) => Ok(AdvertisedWriteBuffer { window, owner }),
            Err(local) => Err(Self { local, owner }),
        }
    }

    pub fn invalidate(&mut self, core: &mut Core) -> io::Result<()> {
        self.local.invalidate(core)
    }

    /// Recover an unused binding only after exact successful LOCAL_INV. This
    /// does not publish bytes or turn cancelled work into an object success.
    #[expect(
        clippy::result_large_err,
        reason = "return the exact owner without allocation"
    )]
    pub fn try_recover(self) -> Result<PreparedWriteBuffer, Self> {
        let Self { local, owner } = self;
        match local.into_unbound() {
            Ok(window) => Ok(PreparedWriteBuffer { window, owner }),
            Err(local) => Err(Self { local, owner }),
        }
    }
}

/// Advertised WRITE target. Peer retirement and successful LOCAL_INV are both
/// required before publishing CPU-readable bytes. Drop of unfinished work uses
/// the existing window quarantine, retaining registration and backing.
#[derive(Debug)]
pub struct AdvertisedWriteBuffer {
    window: AdvertisedWindow,
    owner: Arc<BufferOwner>,
}

impl AdvertisedWriteBuffer {
    pub fn descriptor(&self) -> WindowDescriptor {
        self.window.descriptor()
    }
    pub fn state(&self) -> WindowState {
        self.window.state()
    }

    /// # Safety
    /// Authenticate this attempt on the exact live QP and prove that the peer
    /// stopped admission and retired every accepted WRITE, or retire both QP
    /// endpoints. Matching numeric fields or a timeout do not supply this proof.
    pub unsafe fn confirm_peer_retired_unchecked(
        &mut self,
        attempt: WindowAttempt,
        rkey: u32,
    ) -> bool {
        // SAFETY: the caller supplies the existing window retirement contract.
        unsafe { self.window.confirm_peer_retired_unchecked(attempt, rkey) }
    }

    pub fn invalidate(&mut self, core: &mut Core) -> io::Result<()> {
        self.window.invalidate(core)
    }

    /// Publish the initialized full allocation after retirement. A peer may
    /// have written only a prefix: callers must separately validate transferred
    /// extents and integrity before submitting an object write. No durability
    /// or object completion is asserted by this memory-ownership transition.
    #[expect(
        clippy::result_large_err,
        reason = "return the exact owner without allocation"
    )]
    pub fn try_finish(self) -> Result<SharedWriteBuffer, Self> {
        let Self { window, owner } = self;
        match window.into_unbound() {
            Ok(window) => {
                owner.freeze();
                Ok(SharedWriteBuffer { window, owner })
            }
            Err(window) => Err(Self { window, owner }),
        }
    }
}

/// Shared host payload with the original registration/window retained. Bytes
/// clones and kernel write views keep the allocation alive independently and
/// prevent another DMA into it until exclusive recovery succeeds.
#[derive(Debug)]
pub struct SharedWriteBuffer {
    window: UnboundWindow,
    owner: Arc<BufferOwner>,
}

impl SharedWriteBuffer {
    pub fn bytes(&self) -> &Bytes {
        self.owner.bytes()
    }

    /// Refuse reuse while any clone/slice/view exists. No waiting, payload copy,
    /// new registration, provider allocation or metadata allocation is used.
    pub fn try_reuse(self) -> Result<PreparedWriteBuffer, Self> {
        if !self.owner.thaw() {
            return Err(self);
        }
        Ok(PreparedWriteBuffer {
            window: self.window,
            owner: self.owner,
        })
    }
}

impl Core {
    /// Bind the full prepared target for remote WRITE on this live QP. Posting
    /// uses the existing exact window CQ owner and never grants a parent rkey.
    #[cfg_attr(
        test,
        expect(
            clippy::result_large_err,
            reason = "injected test registration fields enlarge the exact owner; boxing would allocate on admission refusal"
        )
    )]
    pub fn bind_write_buffer(
        &mut self,
        qpn: u32,
        buffer: PreparedWriteBuffer,
    ) -> Result<LocalWriteBuffer, WriteBufferBindError> {
        let range = buffer.range();
        let PreparedWriteBuffer { window, owner } = buffer;
        match self.bind_window(qpn, window, range) {
            Ok(local) => Ok(LocalWriteBuffer { local, owner }),
            Err(error) => Err(WriteBufferBindError {
                error: error.error,
                buffer: PreparedWriteBuffer {
                    window: error.window,
                    owner,
                },
            }),
        }
    }
}

#[cfg(all(test, feature = "fault-inject"))]
mod tests {
    use super::*;
    use crate::verbs::{Event, RemoteWriteTarget, WriteSource, WriteState};
    use std::{
        io::Write,
        time::{Duration, Instant},
    };

    fn poll(core: &mut Core, start: Instant) {
        if start.elapsed() >= Duration::from_secs(10) {
            let message = "WARNING TIMEOUT reusable WRITE buffer exceeded 10s (owned RXE)";
            diag::diag!("{message}");
            if let Ok(path) = std::env::var("WARNINGS_FILE") {
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .unwrap();
                writeln!(file, "{message}").unwrap();
            }
            panic!("{message}");
        }
        core.poll(|_, event| assert!(!matches!(event, Event::Fault(_)), "{event:?}"));
    }

    fn device() -> Arc<Device> {
        let ip = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .unwrap()
            .parse()
            .unwrap();
        Device::open(crate::gid_of(ip)).unwrap()
    }

    #[test]
    #[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_write_buffer_reuses_registration_window_and_metadata_without_allocating() {
        let dev = device();
        let (mut sender, mut receiver, qs, qr) = crate::verbs::rxe_tests::linked(&dev);
        let mut source = WriteSource::register(&dev, Bytes::from(vec![0x93; 4096])).unwrap();
        let mut buffer = PreparedWriteBuffer::prepare(&dev, 4096).unwrap();
        let owner = Arc::downgrade(&buffer.owner);
        let address = buffer.range().address();
        let mut first_key = None;
        let mut key_wrapped = false;
        for tid in 1..=260 {
            let (result, allocations) =
                crate::test_alloc::count(|| receiver.bind_write_buffer(qr, buffer).unwrap());
            assert_eq!(allocations, 0);
            let local = result;
            let start = Instant::now();
            while local.state() == WindowState::Binding {
                poll(&mut receiver, start);
            }
            let attempt = WindowAttempt {
                connection: 1,
                tid,
                retry: 0,
            };
            let (result, allocations) =
                crate::test_alloc::count(|| local.advertise(&receiver, attempt).unwrap());
            assert_eq!(allocations, 0);
            let mut published = result;
            let descriptor = published.descriptor();
            let oldest = *first_key.get_or_insert(descriptor);
            if tid > 1 && oldest.rkey == descriptor.rkey {
                key_wrapped = true;
                // SAFETY: intentionally mismatching retired attempt must be refused.
                assert!(!unsafe {
                    published.confirm_peer_retired_unchecked(oldest.attempt, oldest.rkey)
                });
            }
            // SAFETY: owned live pair and exact retained advertised target.
            let target = unsafe {
                RemoteWriteTarget::from_raw_parts(address, 4096, descriptor.rkey).unwrap()
            };
            let range = source.range();
            let (result, allocations) =
                crate::test_alloc::count(|| sender.write(qs, source, range, target));
            assert_eq!(allocations, 0);
            let handle = result.unwrap();
            let start = Instant::now();
            while handle.state() == WriteState::Pending {
                poll(&mut sender, start);
            }
            source = handle.into_source().unwrap();
            // SAFETY: every accepted WRITE retired; no future admission for this attempt.
            assert!(unsafe { published.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
            let (result, allocations) =
                crate::test_alloc::count(|| published.invalidate(&mut receiver));
            assert_eq!(allocations, 0);
            result.unwrap();
            let start = Instant::now();
            while published.state() == WindowState::Invalidating {
                poll(&mut receiver, start);
            }
            let (result, allocations) =
                crate::test_alloc::count(|| published.try_finish().unwrap());
            assert_eq!(allocations, 0);
            let shared = result;
            assert!(shared.bytes().iter().all(|b| *b == 0x93));
            let (next, allocations) = crate::test_alloc::count(|| {
                let clone = shared.bytes().clone();
                let shared = shared.try_reuse().unwrap_err();
                drop(clone);
                shared.try_reuse().unwrap()
            });
            assert_eq!(allocations, 0);
            buffer = next;
            assert_eq!(buffer.range().address(), address);
        }
        assert!(key_wrapped);
        drop(buffer);
        assert!(
            owner.upgrade().is_none(),
            "retired registration releases its owner"
        );
    }

    #[test]
    #[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_write_buffer_lost_invalidation_cq_never_publishes_or_releases_backing() {
        let dev = device();
        let (_sender, mut receiver, _, qr) = crate::verbs::rxe_tests::linked(&dev);
        let buffer = PreparedWriteBuffer::prepare(&dev, 4096).unwrap();
        let owner = Arc::downgrade(&buffer.owner);
        let local = receiver.bind_write_buffer(qr, buffer).unwrap();
        let start = Instant::now();
        while local.state() == WindowState::Binding {
            poll(&mut receiver, start);
        }
        let attempt = WindowAttempt {
            connection: 1,
            tid: 1,
            retry: 0,
        };
        let mut published = local.advertise(&receiver, attempt).unwrap();
        let descriptor = published.descriptor();
        // SAFETY: descriptor never escaped this test; no peer WR was admitted.
        assert!(unsafe { published.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        published.invalidate(&mut receiver).unwrap();
        receiver.inject_cq_error(-5);
        receiver.poll(|_, _| {});
        assert_eq!(published.state(), WindowState::Failed);
        let published = published.try_finish().unwrap_err();
        drop(published);
        drop(receiver);
        assert!(
            owner.upgrade().is_some(),
            "uncertain DMA retains the exact backing"
        );
    }
}
