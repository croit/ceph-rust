// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Exclusive host storage and type-2 window ownership for destinations and
//! READ-only source grants. GPU registration is a separate path.
use super::{Device, TEARDOWN_FAILURES, ffi, report_teardown};
use crate::host_memory::ForeignHostAllocation;
use crate::memory::MemoryRange;
use std::{fmt, io, ptr, sync::Arc};

#[cfg(feature = "memory-windows")]
mod local;
#[cfg(feature = "memory-windows")]
pub use local::ReadVerification;
#[cfg(feature = "memory-windows")]
mod shared;
#[cfg(feature = "memory-windows")]
mod source;
#[cfg(feature = "memory-windows")]
pub use crate::placement::{WindowAttempt, WindowDescriptor};
#[cfg(feature = "memory-windows")]
pub(super) use local::count_quarantined_windows;
#[cfg(feature = "memory-windows")]
pub use local::{
    AdvertisedWindow, LocalWindow, ReleaseHook, WindowBindError, WindowState, quarantined_windows,
};
#[cfg(feature = "memory-windows")]
pub use shared::{
    RetainedRange, SharedHostRegistration, SharedRegistrationRejected, SharedReleaseError,
};
#[cfg(feature = "memory-windows")]
pub use source::{AdvertisedReadSource, LocalReadSource, ReadSourceDescriptor};
#[cfg(feature = "memory-windows")]
pub use source::{
    AdvertisedSharedReadSource, LocalSharedReadSource, PreparedReadSource, ReadSourcePool,
    ReadSourcePoolReturnError, ReadSourcePoolTicket, ReadSourceRegistrationError,
    SharedReadSourceBindError,
};

/// Failed registration returns the exact original allocation without advertising any address to a peer.
#[derive(Debug)]
pub struct DestinationRegistrationError {
    pub error: io::Error,
    pub buffer: Vec<u8>,
}

/// Foreign registration rejection returns the same retained allocation.
#[derive(Debug)]
pub struct ForeignDestinationRegistrationError {
    pub error: io::Error,
    pub allocation: ForeignHostAllocation,
}

enum HostBacking {
    Owned(Vec<u8>),
    Foreign(Box<ForeignHostAllocation>),
    #[cfg(feature = "memory-windows")]
    Leased(crate::host_memory::ForeignHostLease),
    // Constructed and retained only inside the typed immutable source wrappers.
    // Never exposed through a public HostDestination or UnboundWindow value.
    #[cfg(feature = "memory-windows")]
    ReadOnly(bytes::Bytes),
    #[cfg(feature = "memory-windows")]
    ReadOnlyArena(Box<(bytes::Bytes, Arc<super::ZcMem>)>),
    /// A parent MR registered elsewhere (a GPU region), only borrowed here. The
    /// registration travels with this destination through the window/attempt
    /// owner chain so the MR outlives every provider reference; retirement
    /// never deregisters it. It also carries this destination's own release watch
    /// ([`HostDestination::borrowed_release_watch`]).
    #[cfg(feature = "gpu")]
    Borrowed(crate::gpu::BorrowedRegion),
}
impl HostBacking {
    fn buffer(&self) -> &[u8] {
        match self {
            Self::Owned(b) => b,
            Self::Foreign(b) => b.buffer(),
            #[cfg(feature = "memory-windows")]
            Self::Leased(b) => b.buffer(),
            #[cfg(feature = "memory-windows")]
            Self::ReadOnly(b) => b,
            #[cfg(feature = "memory-windows")]
            Self::ReadOnlyArena(owner) => &owner.0,
            #[cfg(feature = "gpu")]
            Self::Borrowed(..) => unreachable!("borrowed GPU region exposes no host buffer"),
        }
    }
    fn buffer_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Owned(b) => b,
            Self::Foreign(b) => b.buffer_mut(),
            #[cfg(feature = "memory-windows")]
            Self::Leased(b) => b.buffer_mut(),
            #[cfg(feature = "memory-windows")]
            Self::ReadOnly(_) | Self::ReadOnlyArena(_) => {
                unreachable!("immutable source never exposes a destination")
            }
            #[cfg(feature = "gpu")]
            Self::Borrowed(..) => unreachable!("borrowed GPU region exposes no host buffer"),
        }
    }
}

/// One initialized host allocation or independent shared-parent range for a
/// future MW binding. Construction/final release are control operations. CPU
/// access is safe while unbound; binding consumes this exclusive range owner.
pub struct HostDestination {
    dev: Arc<Device>,
    backing: Option<HostBacking>,
    range: MemoryRange,
    mr: *mut ffi::Opaque,
    prepared: Option<Box<PreparedWindow>>,
    #[cfg(feature = "memory-windows")]
    shared: Option<shared::SharedOwner>,
    #[cfg(test)]
    dereg_error: Option<i32>,
}

// SAFETY: moving Vec, retained foreign owner or shared range lease does not
// move backing bytes. Range access is exclusive; shared siblings are disjoint.
// Provider objects support control-thread movement.
// Foreign construction requires a thread-safe lifetime owner and stable CPU
// allocation. The registration has no remote access or exposed key.
unsafe impl Send for HostDestination {}

impl fmt::Debug for HostDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostDestination")
            .field("range", &self.range)
            .finish_non_exhaustive()
    }
}

impl HostDestination {
    #[cfg(feature = "memory-windows")]
    pub(super) fn read_registration(&self) -> (&Arc<Device>, u32) {
        // SAFETY: an unbound destination owns a live, locally writable MR.
        (&self.dev, unsafe { ffi::rv_lkey(self.mr) })
    }

    /// Register exclusive initialized host storage. No per-operation registration or address-based cache.
    pub fn register(
        dev: &Arc<Device>,
        mut buffer: Vec<u8>,
    ) -> Result<Self, DestinationRegistrationError> {
        let address = buffer.as_mut_ptr();
        let range = match MemoryRange::new(address as u64, buffer.len() as u64) {
            Ok(range) => range,
            Err(error) => {
                return Err(DestinationRegistrationError {
                    error: error.into(),
                    buffer,
                });
            }
        };
        // SAFETY: Vec owns initialized writable host memory, whose allocation is retained unchanged in this handle.
        let mr = unsafe { ffi::rv_reg_destination(dev.p, address.cast(), range.length()) };
        if mr.is_null() {
            return Err(DestinationRegistrationError {
                error: io::Error::last_os_error(),
                buffer,
            });
        }
        Ok(Self {
            dev: dev.clone(),
            backing: Some(HostBacking::Owned(buffer)),
            range,
            mr,
            prepared: None,
            #[cfg(feature = "memory-windows")]
            shared: None,
            #[cfg(test)]
            dereg_error: None,
        })
    }

    /// Prepare both MR and reusable type-2 MW on a control thread. No provider
    /// allocation is needed when consuming this destination for a READ attempt.
    /// MW allocation precedes MR registration, so rejection returns the original
    /// allocation without needing to deregister potentially active backing.
    pub fn register_prepared(
        dev: &Arc<Device>,
        buffer: Vec<u8>,
    ) -> Result<Self, DestinationRegistrationError> {
        if let Err(error) = MemoryRange::new(buffer.as_ptr() as u64, buffer.len() as u64) {
            return Err(DestinationRegistrationError {
                error: error.into(),
                buffer,
            });
        }
        let mut prepared = match PreparedWindow::allocate(dev) {
            Ok(prepared) => prepared,
            Err(error) => return Err(DestinationRegistrationError { error, buffer }),
        };
        match Self::register(dev, buffer) {
            Ok(mut destination) => {
                destination.prepared = Some(prepared);
                Ok(destination)
            }
            Err(error) => {
                if prepared.retire().is_err() {
                    // No MR was attached, but a refused MW release still owns its PD.
                    std::mem::forget(dev.clone());
                }
                Err(error)
            }
        }
    }

    /// Whether a control-thread-prepared, locally inaccessible MW is available.
    pub fn window_prepared(&self) -> bool {
        self.prepared.is_some()
    }

    /// Register retained foreign host bytes and prepare their reusable MW on
    /// this control thread. CPU/GPU address inference and payload copies are
    /// absent; the caller has already supplied an exclusive host-memory owner.
    pub fn register_foreign_prepared(
        dev: &Arc<Device>,
        allocation: ForeignHostAllocation,
    ) -> Result<Self, ForeignDestinationRegistrationError> {
        let mut prepared = match PreparedWindow::allocate(dev) {
            Ok(prepared) => prepared,
            Err(error) => return Err(ForeignDestinationRegistrationError { error, allocation }),
        };
        match Self::register_foreign(dev, allocation) {
            Ok(mut destination) => {
                destination.prepared = Some(prepared);
                Ok(destination)
            }
            Err(error) => {
                if prepared.retire().is_err() {
                    std::mem::forget(dev.clone());
                }
                Err(error)
            }
        }
    }

    /// Register exclusive retained host storage without allocating a window.
    /// Locally initiated READs need this MR only; callers requiring a prepared
    /// remote grant use `register_foreign_prepared` on the control thread.
    pub fn register_foreign(
        dev: &Arc<Device>,
        allocation: ForeignHostAllocation,
    ) -> Result<Self, ForeignDestinationRegistrationError> {
        let range = allocation.range();
        // SAFETY: the exclusive host allocation is retained until deregistration
        // or quarantine. Construction checked numeric bounds and CPU slice size.
        let mr =
            unsafe { ffi::rv_reg_destination(dev.p, range.address() as *mut _, range.length()) };
        if mr.is_null() {
            let error = io::Error::last_os_error();
            return Err(ForeignDestinationRegistrationError { error, allocation });
        }
        Ok(Self {
            dev: dev.clone(),
            backing: Some(HostBacking::Foreign(Box::new(allocation))),
            range,
            mr,
            prepared: None,
            #[cfg(feature = "memory-windows")]
            shared: None,
            #[cfg(test)]
            dereg_error: None,
        })
    }

    /// Wrap a parent MR registered elsewhere (a GPU region) as a placement
    /// destination and prepare its reusable MW. The MR is borrowed: retirement
    /// deallocates the window but never deregisters the parent; the registration
    /// owner keeps it until every attempt has retired.
    ///
    /// The destination must not outlive the registration that owns `mr`.
    #[cfg(feature = "gpu")]
    pub(crate) fn register_borrowed_mr_prepared(
        dev: &Arc<Device>,
        region: Arc<crate::gpu::GpuRegion>,
        range: MemoryRange,
    ) -> io::Result<Self> {
        Self::register_borrowed_prepared(dev, crate::gpu::BorrowedRegion::new(region), range)
    }

    /// [`Self::register_borrowed_mr_prepared`] with the borrow (and what it holds) supplied by the caller.
    #[cfg(feature = "gpu")]
    pub(crate) fn register_borrowed_prepared(
        dev: &Arc<Device>,
        borrowed: crate::gpu::BorrowedRegion,
        range: MemoryRange,
    ) -> io::Result<Self> {
        let mr = borrowed.region().mr_handle();
        if mr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "borrowed destination MR is null",
            ));
        }
        let prepared = PreparedWindow::allocate(dev)?;
        Ok(Self {
            dev: dev.clone(),
            backing: Some(HostBacking::Borrowed(borrowed)),
            range,
            mr,
            prepared: Some(prepared),
            #[cfg(feature = "memory-windows")]
            shared: None,
            #[cfg(test)]
            dereg_error: None,
        })
    }

    /// Whether this destination borrows its MR from a registration owner (GPU).
    #[cfg(feature = "gpu")]
    pub fn is_borrowed(&self) -> bool {
        matches!(self.backing, Some(HostBacking::Borrowed(..)))
    }

    /// Narrow (or restore) the range a borrowed destination exposes to its next READ. One GPU registration
    /// owns one parent MR and serves several concurrent windows: each window is its own prepared
    /// destination, positioned over a sub-range of the region (the registration owner refuses a window that
    /// overlaps one still outstanding). `EINVAL` when this destination is not borrowed or `range` leaves the region.
    #[cfg(feature = "gpu")]
    pub fn set_borrowed_range(&mut self, range: MemoryRange) -> io::Result<()> {
        let region = self
            .borrowed_region()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        if !MemoryRange::new(region.address(), region.length())
            .is_ok_and(|whole| whole.contains(range.address(), range.length()))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.range = range;
        Ok(())
    }

    /// Dies when this borrowed destination is gone, wherever it went: back to its owner, retired, or released
    /// with the QP that retained it after its session ended ([`super::Core::abandon_window`]); a quarantined window keeps
    /// it alive for good. `None` when not borrowed. An observer that sees it dead issues an acquire fence before
    /// relying on it.
    #[cfg(feature = "gpu")]
    pub fn borrowed_release_watch(&self) -> Option<std::sync::Weak<()>> {
        match self.backing.as_ref()? {
            HostBacking::Borrowed(borrowed) => Some(borrowed.release_watch()),
            _ => None,
        }
    }

    /// The registration's release watch ([`crate::gpu::GpuRegion::release_watch`]): dies after the parent MR is
    /// deregistered. `None` when not borrowed.
    #[cfg(feature = "gpu")]
    pub fn borrowed_region_watch(&self) -> Option<std::sync::Weak<()>> {
        Some(self.borrowed_region()?.release_watch())
    }

    /// [`crate::gpu::GpuRegion::notify_window_release`] of the borrowed region; no effect when not borrowed.
    #[cfg(feature = "gpu")]
    pub fn borrowed_notify_window_release(&self, notify: impl Fn() + Send + Sync + 'static) {
        if let Some(region) = self.borrowed_region() {
            region.notify_window_release(notify);
        }
    }

    /// A new prepared window over the whole borrowed region (same parent MR): replaces a window the owner lost to
    /// a QP teardown. Control call (allocates a MW). `EINVAL` when not borrowed.
    #[cfg(feature = "gpu")]
    pub fn borrowed_sibling(&self) -> io::Result<Self> {
        let region = self
            .borrowed_region()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let range = MemoryRange::new(region.address(), region.length())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Self::register_borrowed_mr_prepared(&self.dev, Arc::clone(region), range)
    }

    /// A PUT source over `range` of the borrowed region ([`crate::gpu::GpuSource`]). `EINVAL` when not borrowed
    /// or `range` leaves the region.
    #[cfg(feature = "gpu")]
    pub fn borrowed_source(&self, range: MemoryRange) -> io::Result<crate::gpu::GpuSource> {
        let region = self
            .borrowed_region()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        crate::gpu::GpuSource::new(Arc::clone(region), range)
    }

    /// Without GPU support no destination borrows its MR.
    #[cfg(not(feature = "gpu"))]
    pub fn is_borrowed(&self) -> bool {
        false
    }

    /// CPU bytes of a borrowed host-visible region at `[offset, offset + len)` relative to the region start.
    /// Only that subrange is borrowed, never the whole region. `None` = not borrowed, real device memory (no host
    /// mapping), or outside the region.
    #[cfg(all(feature = "gpu", feature = "memory-windows"))]
    pub(crate) fn borrowed_host_bytes(&self, offset: u64, len: usize) -> Option<&[u8]> {
        // SAFETY: the caller checks the receipt of a completed READ over exactly this subrange: the window's
        // retirement proof fenced every peer write into it, and the registration owner keeps every other
        // outstanding window disjoint from it, so nothing writes it while the slice lives.
        unsafe { self.borrowed_region()?.host_subrange(offset, len) }
    }

    /// CPU address and length of the whole borrowed region (host mock or CPU-readable DMA-BUF), `None` for
    /// device memory. No slice is formed: windows may be written by peers meanwhile.
    #[cfg(feature = "gpu")]
    pub fn borrowed_host_span(&self) -> Option<(u64, u64)> {
        self.borrowed_region()?.host_span()
    }

    #[cfg(feature = "gpu")]
    fn borrowed_region(&self) -> Option<&Arc<crate::gpu::GpuRegion>> {
        match self.backing.as_ref()? {
            HostBacking::Borrowed(borrowed) => Some(borrowed.region()),
            _ => None,
        }
    }

    pub fn is_foreign(&self) -> bool {
        self.backing
            .as_ref()
            .is_some_and(|backing| !matches!(backing, HostBacking::Owned(_)) && !self.is_borrowed())
    }

    pub fn range(&self) -> MemoryRange {
        self.range
    }

    /// Initialized host bytes. This unbound handle cannot be used for device access concurrently.
    pub fn buffer(&self) -> &[u8] {
        self.backing
            .as_ref()
            .expect("live destination owns its allocation")
            .buffer()
    }

    /// Modify initialized bytes without resizing or relocating the registration.
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        self.backing
            .as_mut()
            .expect("live destination owns its allocation")
            .buffer_mut()
    }

    /// Deregister and recover the exact allocation. A refused deregistration retains backing until process exit and
    /// returns its error; it cannot grant reuse of potentially device-accessible memory.
    /// Foreign backing is unsupported and is safely released on this error;
    /// use `into_foreign` to recover its retained owner instead.
    pub fn into_buffer(mut self) -> io::Result<Vec<u8>> {
        if self.is_foreign() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.retire()?;
        match self
            .backing
            .take()
            .expect("retired destination owns its allocation")
        {
            HostBacking::Owned(buffer) => Ok(buffer),
            HostBacking::Foreign(_) => unreachable!("foreign backing rejected before retirement"),
            #[cfg(feature = "memory-windows")]
            HostBacking::Leased(_) => unreachable!("shared backing rejected before retirement"),
            #[cfg(feature = "memory-windows")]
            HostBacking::ReadOnly(_) | HostBacking::ReadOnlyArena(_) => {
                unreachable!("immutable source never exposes a destination")
            }
            #[cfg(feature = "gpu")]
            HostBacking::Borrowed(..) => unreachable!("borrowed GPU region has no host buffer"),
        }
    }

    /// Return the original foreign allocation after MW/MR teardown. An owned
    /// Vec or shared range destination is unsupported and safely released on
    /// this error. Recover a shared parent through its registration controller.
    pub fn into_foreign(mut self) -> io::Result<ForeignHostAllocation> {
        if !matches!(self.backing, Some(HostBacking::Foreign(_))) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.retire()?;
        match self
            .backing
            .take()
            .expect("retired destination owns its allocation")
        {
            HostBacking::Foreign(allocation) => Ok(*allocation),
            HostBacking::Owned(_) => unreachable!("owned backing rejected before retirement"),
            #[cfg(feature = "memory-windows")]
            HostBacking::Leased(_) => unreachable!("shared backing rejected before retirement"),
            #[cfg(feature = "memory-windows")]
            HostBacking::ReadOnly(_) | HostBacking::ReadOnlyArena(_) => {
                unreachable!("immutable source never exposes a destination")
            }
            #[cfg(feature = "gpu")]
            HostBacking::Borrowed(..) => unreachable!("borrowed GPU region has no host buffer"),
        }
    }

    /// Retire MW then MR and release either kind of retained host backing.
    /// Provider uncertainty retains the backing and device instead.
    pub fn release(mut self) -> io::Result<()> {
        self.retire()
    }

    fn retire(&mut self) -> io::Result<()> {
        if self.mr.is_null() {
            return Ok(());
        }
        if let Some(mut prepared) = self.prepared.take()
            && let Err(error) = prepared.retire()
        {
            // Keep the parent MR and its backing if MW teardown is uncertain.
            std::mem::forget(self.backing.take());
            #[cfg(feature = "memory-windows")]
            std::mem::forget(self.shared.take());
            std::mem::forget(self.dev.clone());
            self.mr = ptr::null_mut();
            return Err(error);
        }
        if self.is_borrowed() {
            // The registration owner (GPU region) deregisters after this
            // destination and every attempt are gone; never double-deregister.
            self.mr = ptr::null_mut();
            return Ok(());
        }
        #[cfg(feature = "memory-windows")]
        if self.shared.is_some() || matches!(self.backing, Some(HostBacking::ReadOnlyArena(_))) {
            // This range no longer has a MW. Its shared parent owns the MR;
            // field destruction retires only this memory claim and parent Arc.
            self.mr = ptr::null_mut();
            return Ok(());
        }
        // SAFETY: no MW remains bound or allocated on this exclusively owned MR.
        let rc = unsafe { ffi::rv_dereg(self.mr) };
        #[cfg(test)]
        let rc = self.dereg_error.take().unwrap_or(rc);
        self.mr = ptr::null_mut();
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::from_raw_os_error(rc.abs());
        TEARDOWN_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::mem::forget(self.backing.take());
        std::mem::forget(self.dev.clone());
        report_teardown(format_args!(
            "rdma: host destination deregistration failed: {error} (backing and device retained)"
        ));
        Err(error)
    }
}

impl Drop for HostDestination {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}

/// Provider resource prepared once per destination. It never owns backing by
/// itself: callers retain the parent/PD if release fails.
struct PreparedWindow {
    mw: *mut ffi::Opaque,
    #[cfg(feature = "memory-windows")]
    completion: Arc<std::sync::atomic::AtomicU8>,
    #[cfg(test)]
    dealloc_error: Option<i32>,
}

impl PreparedWindow {
    fn allocate(dev: &Device) -> io::Result<Box<Self>> {
        // SAFETY: the caller retains the device/PD through release.
        let mw = unsafe { ffi::rv_alloc_window(dev.p) };
        if mw.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Box::new(Self {
            mw,
            #[cfg(feature = "memory-windows")]
            completion: Arc::new(std::sync::atomic::AtomicU8::new(crate::completion::IDLE)),
            #[cfg(test)]
            dealloc_error: None,
        }))
    }

    fn retire(&mut self) -> io::Result<()> {
        // SAFETY: the resource has never been bound, or LOCAL_INV completed
        // after ordered peer retirement before it was returned to this owner.
        let rc = unsafe { ffi::rv_dealloc_window(self.mw) };
        #[cfg(test)]
        let rc = self.dealloc_error.take().unwrap_or(rc);
        self.mw = ptr::null_mut();
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::from_raw_os_error(rc.abs());
        TEARDOWN_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        report_teardown(format_args!(
            "rdma: prepared window deallocation failed: {error} (parent and device retained)"
        ));
        Err(error)
    }
}

/// Window allocation rejection returns the unchanged parent registration.
#[derive(Debug)]
pub struct WindowAllocationError {
    pub error: io::Error,
    pub destination: HostDestination,
}

/// Unbound type-2 MW and its exclusive host parent on one PD. No key or remote permission is exposed.
/// Allocate/release on a control thread; binding consumes this handle and excludes CPU access.
pub struct UnboundWindow {
    destination: Option<HostDestination>,
    resource: Option<Box<PreparedWindow>>,
}

// SAFETY: the window is unbound and exclusively retains its movable parent; verbs handles are thread-safe.
unsafe impl Send for UnboundWindow {}

impl fmt::Debug for UnboundWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnboundWindow")
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}

impl UnboundWindow {
    /// The retained initialized parent range, without exposing its bytes or key.
    pub fn range(&self) -> MemoryRange {
        self.destination
            .as_ref()
            .expect("window retains parent")
            .range()
    }

    /// Allocate on the parent's PD. Rejection retains the parent's exact allocation and MR for the caller.
    pub fn allocate(mut destination: HostDestination) -> Result<Self, WindowAllocationError> {
        let prepared = match destination.prepared.take() {
            Some(prepared) => prepared,
            None => match PreparedWindow::allocate(&destination.dev) {
                Ok(prepared) => prepared,
                Err(error) => return Err(WindowAllocationError { error, destination }),
            },
        };
        Ok(Self {
            destination: Some(destination),
            resource: Some(prepared),
        })
    }

    #[cfg(feature = "memory-windows")]
    pub(super) fn completion(&self) -> &Arc<std::sync::atomic::AtomicU8> {
        &self.resource.as_ref().expect("window resource").completion
    }

    #[cfg(feature = "memory-windows")]
    pub(super) fn mw(&self) -> *mut ffi::Opaque {
        self.resource.as_ref().expect("window resource").mw
    }

    /// Return a safe unbound window to its parent for a later attempt without
    /// provider calls or allocation. Bound windows reach this type only after
    /// successful LOCAL_INV, with peer retirement required if advertised.
    pub fn into_prepared_destination(mut self) -> HostDestination {
        let mut destination = self.destination.take().expect("window retains parent");
        assert!(
            destination.prepared.is_none(),
            "one prepared MW per destination"
        );
        destination.prepared = self.resource.take();
        destination
    }

    /// Deallocate the unbound window before returning its unchanged parent registration.
    /// Uncertain deallocation permanently retains the window, parent and backing instead of granting reuse.
    pub fn into_destination(mut self) -> io::Result<HostDestination> {
        self.retire()?;
        Ok(self
            .destination
            .take()
            .expect("retired window retains parent"))
    }

    fn retire(&mut self) -> io::Result<()> {
        let Some(mut resource) = self.resource.take() else {
            return Ok(());
        };
        if let Err(error) = resource.retire() {
            std::mem::forget(self.destination.take());
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for UnboundWindow {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> Arc<Device> {
        let ip: std::net::IpAddr = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .expect("FLASHSTORE_TEST_RDMA_ADDR")
            .parse()
            .expect("RDMA address is an IP");
        Device::open(crate::gid_of(ip)).expect("device")
    }

    /// Reuses the identical provider MW and completion marker across the 8-bit
    /// rkey cycle. This never advertises a descriptor; advertised retry safety
    /// additionally requires the runtime's ordered peer-retirement proof.
    #[test]
    #[cfg(feature = "memory-windows")]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_prepared_window_reuses_provider_and_marker_without_allocating() {
        use super::super::{Core, Event, WindowState};
        let dev = device();
        let (mut core, mut peer, qpn, peer_qpn) = super::super::rxe_tests::linked(&dev);
        let destination = HostDestination::register_prepared(&dev, vec![0x5a; 4096]).unwrap();
        let original = destination.buffer().as_ptr();
        let range = destination.range().subrange(512, 2048).unwrap();
        let mut window = UnboundWindow::allocate(destination).unwrap();
        let provider = window.mw();
        let marker = Arc::as_ptr(window.completion());
        let wait = |core: &mut Core, local: &LocalWindow, expected| {
            let start = std::time::Instant::now();
            while local.state() != expected {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(10),
                    "WARNING TIMEOUT prepared window completion exceeded 10s"
                );
                core.poll(|_, event| assert!(!matches!(event, Event::Fault(_)), "{event:?}"));
            }
        };
        for _ in 0..260 {
            let (bound, allocations) =
                crate::test_alloc::count(|| core.bind_window(qpn, window, range));
            assert_eq!(allocations, 0);
            let mut bound = bound.unwrap();
            wait(&mut core, &bound, WindowState::Bound);
            let (result, allocations) = crate::test_alloc::count(|| bound.invalidate(&mut core));
            assert_eq!(allocations, 0);
            result.unwrap();
            wait(&mut core, &bound, WindowState::Retired);
            let (recycled, allocations) = crate::test_alloc::count(|| {
                let destination = bound.into_unbound().unwrap().into_prepared_destination();
                assert!(destination.window_prepared());
                assert_eq!(destination.buffer().as_ptr(), original);
                UnboundWindow::allocate(destination).unwrap()
            });
            assert_eq!(allocations, 0);
            window = recycled;
            assert_eq!(window.mw(), provider);
            assert_eq!(Arc::as_ptr(window.completion()), marker);
        }
        let destination = window.into_prepared_destination();
        let buffer = destination.into_buffer().unwrap();
        assert_eq!(buffer.as_ptr(), original);
        drop(core.detach(qpn));
        drop(peer.detach(peer_qpn));
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_foreign_destination_returns_exact_retained_host_allocation() {
        let dev = device();
        let mut bytes = vec![0x5au8; 4096];
        let address = bytes.as_mut_ptr() as u64;
        let owner = Arc::new(bytes);
        // SAFETY: the retained Arc keeps the initialized allocation stable;
        // this test accesses no original bytes until the foreign owner retires.
        let allocation =
            unsafe { ForeignHostAllocation::from_raw_parts(address, 4096, owner.clone()) }.unwrap();
        let mut destination = HostDestination::register_foreign_prepared(&dev, allocation).unwrap();
        assert!(destination.is_foreign());
        assert!(destination.window_prepared());
        assert_eq!(destination.buffer().as_ptr() as u64, address);
        destination.buffer_mut()[19] = 0xa5;
        let window = UnboundWindow::allocate(destination).unwrap();
        let destination = window.into_prepared_destination();
        let returned = destination.into_foreign().unwrap();
        assert_eq!(returned.buffer().as_ptr() as u64, address);
        assert_eq!(returned.buffer()[19], 0xa5);
        assert_eq!(Arc::strong_count(&owner), 2);
        drop(returned.into_owner());
        assert_eq!(Arc::strong_count(&owner), 1);
        assert_eq!(owner[19], 0xa5);
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_foreign_destination_retains_owner_on_uncertain_provider_release() {
        let dev = device();
        for fail_mw in [false, true] {
            let mut bytes = vec![0x5au8; 4096];
            let address = bytes.as_mut_ptr() as u64;
            let owner = Arc::new(bytes);
            // SAFETY: exclusive foreign access; the original Arc is used only
            // for reference counts and is not dereferenced after construction.
            let allocation =
                unsafe { ForeignHostAllocation::from_raw_parts(address, 4096, owner.clone()) }
                    .unwrap();
            let mut destination =
                HostDestination::register_foreign_prepared(&dev, allocation).unwrap();
            if fail_mw {
                destination.prepared.as_mut().unwrap().dealloc_error = Some(5);
            } else {
                destination.dereg_error = Some(5);
            }
            assert_eq!(
                destination.into_foreign().unwrap_err().raw_os_error(),
                Some(5)
            );
            assert_eq!(
                Arc::strong_count(&owner),
                2,
                "uncertain provider access retains the owner"
            );
        }
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_prepared_window_failed_release_retains_parent_and_device() {
        let dev = device();
        let references = Arc::strong_count(&dev);
        let failures = super::super::teardown_failures();
        let mut destination = HostDestination::register_prepared(&dev, vec![0x5a; 4096]).unwrap();
        destination.prepared.as_mut().unwrap().dealloc_error = Some(5);
        assert_eq!(
            destination.into_buffer().unwrap_err().raw_os_error(),
            Some(5)
        );
        assert_eq!(Arc::strong_count(&dev), references + 1);
        assert_eq!(super::super::teardown_failures(), failures + 1);
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_destination_registration_preserves_original_buffer_and_bounds() {
        let dev = device();
        let references = Arc::strong_count(&dev);
        let mut buffer = Vec::with_capacity(16384);
        buffer.extend((0..8192).map(|i| (i % 251) as u8));
        let (address, capacity) = (buffer.as_ptr(), buffer.capacity());
        let mut destination = HostDestination::register(&dev, buffer).expect("register");
        assert_eq!(destination.range().address(), address as u64);
        assert_eq!(destination.range().length(), 8192);
        assert_eq!(destination.buffer().len(), 8192);
        assert_eq!(destination.buffer()[4095], (4095 % 251) as u8);
        destination.buffer_mut()[1] = 0xa5;
        // Moving the control handle must never move or grow the registered allocation.
        let moved = Box::new(destination);
        assert_eq!(moved.buffer().as_ptr(), address);
        let destination = *moved;
        let buffer = destination.into_buffer().expect("deregister");
        assert_eq!(buffer.as_ptr(), address);
        assert_eq!(buffer.capacity(), capacity);
        assert_eq!(buffer.len(), 8192);
        assert_eq!(buffer[1], 0xa5);
        assert_eq!(Arc::strong_count(&dev), references);

        let empty = Vec::with_capacity(64);
        let address = empty.as_ptr();
        let rejected = HostDestination::register(&dev, empty).unwrap_err();
        assert_eq!(rejected.error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(rejected.buffer.as_ptr(), address);
        assert_eq!(rejected.buffer.capacity(), 64);
        assert!(rejected.buffer.is_empty());
        drop(HostDestination::register(&dev, vec![0; 4096]).expect("register and drop"));
        assert_eq!(Arc::strong_count(&dev), references);
    }

    /// Real deregistration runs first; the hook then exercises uncertain ownership without leaving a live test MR.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_destination_uncertain_deregistration_never_returns_the_buffer() {
        let dev = device();
        for explicit in [false, true] {
            let references = Arc::strong_count(&dev);
            let failures = super::super::teardown_failures();
            let mut destination = HostDestination::register(&dev, vec![0; 4096]).expect("register");
            destination.dereg_error = Some(5);
            if explicit {
                assert_eq!(
                    destination.into_buffer().unwrap_err().raw_os_error(),
                    Some(5)
                );
            } else {
                drop(destination);
            }
            assert_eq!(
                Arc::strong_count(&dev),
                references + 1,
                "provider/backing retained"
            );
            assert_eq!(super::super::teardown_failures(), failures + 1);
        }
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_destination_unbound_window_preserves_parent_and_releases_in_order() {
        let dev = device();
        let references = Arc::strong_count(&dev);
        let mut buffer = Vec::with_capacity(16384);
        buffer.extend((0..8192).map(|i| (i % 251) as u8));
        let (address, capacity) = (buffer.as_ptr(), buffer.capacity());
        let destination = HostDestination::register(&dev, buffer).expect("parent registration");
        let parent_mr = destination.mr;
        let window = UnboundWindow::allocate(destination).expect("type-2 allocation");
        assert_eq!(Arc::strong_count(&dev), references + 1);
        let moved = Box::new(window);
        let destination = (*moved).into_destination().expect("MW deallocation");
        assert_eq!(destination.mr, parent_mr);
        let buffer = destination.into_buffer().expect("parent deregistration");
        assert_eq!(buffer.as_ptr(), address);
        assert_eq!(buffer.len(), 8192);
        assert_eq!(buffer.capacity(), capacity);
        assert!(
            buffer
                .iter()
                .enumerate()
                .all(|(i, b)| *b == (i % 251) as u8)
        );
        assert_eq!(Arc::strong_count(&dev), references);
        drop(
            UnboundWindow::allocate(HostDestination::register(&dev, vec![0; 4096]).unwrap())
                .unwrap(),
        );
        assert_eq!(Arc::strong_count(&dev), references);
    }

    /// Provider cleanup runs first; injected errno verifies ownership policy, not a physical MW failure.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_destination_uncertain_window_deallocation_retains_parent() {
        let dev = device();
        for explicit in [false, true] {
            let references = Arc::strong_count(&dev);
            let failures = super::super::teardown_failures();
            let mut window = UnboundWindow::allocate(
                HostDestination::register(&dev, vec![0; 4096]).expect("parent registration"),
            )
            .expect("type-2 allocation");
            window.resource.as_mut().unwrap().dealloc_error = Some(5);
            if explicit {
                assert_eq!(
                    window.into_destination().unwrap_err().raw_os_error(),
                    Some(5)
                );
            } else {
                drop(window);
            }
            assert_eq!(
                Arc::strong_count(&dev),
                references + 1,
                "parent/device retained"
            );
            assert_eq!(super::super::teardown_failures(), failures + 1);
        }
    }

    /// /dev/full deterministically rejects writes; only the child test's stderr changes, never the parent's.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_destination_retention_survives_failed_stderr() {
        let stderr = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("/dev/full");
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--ignored",
                "--nocapture",
                "verbs::destination::tests::rxe_destination_uncertain_",
                "--test-threads=1",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(stderr)
            .status()
            .expect("run isolated destination teardown test");
        assert!(
            status.success(),
            "teardown must retain ownership even when stderr cannot be written: {status}"
        );
    }
}
