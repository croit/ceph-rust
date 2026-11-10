// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Device memory for GPUDirect RDMA (adr 0665, phase P1).
//!
//! A region is registered with the HCA as an MR and exported as a bounded rkey. The OSD never learns whether the
//! backing is GPU VRAM or a host buffer: it RDMA-WRITEs into a destination region (`GpuAccess::Write`, used by GET)
//! or RDMA-READs from a source region (`GpuAccess::Read`, used by PUT).
//!
//! Two backings exist:
//! - [`Backing::Dmabuf`]: real device memory through `ibv_reg_dmabuf_mr` (GPU VRAM, or `udmabuf` in the lab mock).
//!   Requires a provider with DMA-BUF support; the lab ConnectX-4 rejects it, so the GPU host must be newer.
//! - [`Backing::Host`]: a host allocation registered with the same access bits (the functional GPU mock until the
//!   hardware arrives). The RDMA behaviour is identical; only the registration call differs.
//!
//! Registration is a control-plane call and never runs per operation. [`GpuRegistry`] keeps one registration per
//! range while a caller holds it; the MR is deregistered when the last owner drops it. A failed deregistration
//! retains the MR, its backing and the device (the same rule as the host arenas).
//!
//! Lifetime: the MR pins the backing pages. The caller keeps the buffer alive and does not free or reuse it while an
//! operation that names a key of it is in flight; the transport's retirement proof owns that interval. The client
//! never exports the parent rkey: a GET destination and a PUT source ([`GpuSource`]) are type-2 MWs bound on the
//! parent over exactly their sub-range (write-only resp. READ-only). A provider that refuses `IBV_ACCESS_MW_BIND` on
//! a DMA-BUF MR refuses the registration itself (rdma-core does not list the bit for DMA-BUF); a direct
//! sub-range MR per attempt would be the fallback, not built (adr 0665).
use crate::verbs::{
    Device, dmabuf_register, mr_deregister, mr_identity, mr_register_access, teardown_failure,
};
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// `IBV_ACCESS_LOCAL_WRITE`.
pub const ACCESS_LOCAL_WRITE: c_int = 1;
/// `IBV_ACCESS_REMOTE_WRITE`.
pub const ACCESS_REMOTE_WRITE: c_int = 2;
/// `IBV_ACCESS_REMOTE_READ`.
pub const ACCESS_REMOTE_READ: c_int = 4;
/// `IBV_ACCESS_MW_BIND`: a placement destination binds a type-2 MW to this parent.
pub const ACCESS_MW_BIND: c_int = 1 << 4;

/// Direction of a region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GpuAccess {
    /// A peer RDMA-READs this region (PUT source). The local owner writes it before the transfer.
    Read,
    /// A peer RDMA-WRITEs this region (GET destination). Local and remote write.
    Write,
    /// The segment serves both directions, as one NIXL VRAM_SEG does: a peer writes it (GET) and reads it
    /// (source-pull PUT). Both directions use attempt-bound type-2 windows.
    Both,
}

impl GpuAccess {
    fn bits(self) -> c_int {
        match self {
            // A source is written locally (by the GPU/CPU) before the peer reads it; some providers require the
            // local-write bit on every MR. The exported right stays READ-only.
            Self::Read => ACCESS_LOCAL_WRITE | ACCESS_REMOTE_READ | ACCESS_MW_BIND,
            // A GET destination is bound into a type-2 MW; the parent needs BIND, exactly like the
            // host destination (`rv_reg_destination`). Remote write is granted by the MW, not the
            // parent. A direct-rkey destination would add REMOTE_WRITE instead.
            Self::Write => ACCESS_LOCAL_WRITE | ACCESS_MW_BIND,
            Self::Both => {
                ACCESS_LOCAL_WRITE | ACCESS_REMOTE_READ | ACCESS_REMOTE_WRITE | ACCESS_MW_BIND
            }
        }
    }
}

/// What backs a registered region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backing {
    /// Device memory through `ibv_reg_dmabuf_mr`.
    Dmabuf,
    /// Host memory registered with the same access bits: the functional GPU mock.
    Host,
    /// DMA-BUF the caller declares CPU-readable (host-backed, e.g. `udmabuf`): registered like
    /// [`Backing::Dmabuf`] and additionally mapped read-only for the source-pull CRC. Device memory
    /// stays [`Backing::Dmabuf`]: its bytes are not CPU-readable, so a store from it is refused.
    DmabufHost,
}

/// One registered region. Deregistered when the last `Arc` drops.
#[derive(Debug)]
pub struct GpuRegion {
    _dev: Arc<Device>,
    mr: *mut crate::verbs::Opaque,
    address: u64,
    length: u64,
    lkey: u32,
    rkey: u32,
    access: GpuAccess,
    backing: Backing,
    /// Read-only CPU mapping of a [`Backing::DmabufHost`] region, unmapped with the region.
    host: Option<HostMapping>,
    /// A failed deregistration retains the MR, its backing and the device reference.
    retain: bool,
    /// Dies after a successful deregistration ([`Self::release_watch`]); kept alive for good when it failed.
    alive: Arc<()>,
    /// Called after each borrowed window of this region died ([`Self::notify_window_release`]).
    window_release: OnceLock<WindowReleaseNotify>,
}

/// The owner's wake-up for [`GpuRegion::notify_window_release`].
struct WindowReleaseNotify(Arc<dyn Fn() + Send + Sync>);

impl std::fmt::Debug for WindowReleaseNotify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WindowReleaseNotify")
    }
}

/// A borrowed window's hold on its region ([`crate::verbs::HostDestination::borrowed_release_watch`]): `alive`
/// dies with the window, then the region's owner is notified ([`GpuRegion::notify_window_release`]). A
/// quarantined window is forgotten with this hold: its watch stays alive and nobody is notified.
#[derive(Debug)]
pub(crate) struct BorrowedRegion {
    region: Option<Arc<GpuRegion>>,
    alive: Option<Arc<()>>,
    /// The hold of the PUT source this window serves ([`GpuSource`]): it stays reserved until its last attempt
    /// window is gone.
    source: Option<Arc<BorrowedRegion>>,
}

impl BorrowedRegion {
    pub(crate) fn new(region: Arc<GpuRegion>) -> Self {
        Self {
            region: Some(region),
            alive: Some(Arc::new(())),
            source: None,
        }
    }

    pub(crate) fn region(&self) -> &Arc<GpuRegion> {
        self.region.as_ref().expect("live borrowed window")
    }

    pub(crate) fn release_watch(&self) -> Weak<()> {
        Arc::downgrade(self.alive.as_ref().expect("live borrowed window"))
    }
}

impl Drop for BorrowedRegion {
    fn drop(&mut self) {
        // The owner's wake-up may release the registration at once (synchronously, rados-ffi): every hold on the
        // parent (region, PUT source) and the watch are gone before it runs, so it never sees the MR still alive.
        let notify = self
            .region()
            .window_release
            .get()
            .map(|notify| Arc::clone(&notify.0));
        drop(self.source.take());
        drop(self.region.take());
        drop(self.alive.take());
        if let Some(notify) = notify {
            (notify)();
        }
    }
}

/// The READ-only source of one source-pull PUT (adr 0665): exactly `range` of a registered
/// region. Every attempt of the write binds its own READ-only type-2 MW over this range ([`Self::window`]) on the QP
/// of the session it goes to, and each such window holds the source. [`Self::release_watch`] dies when the source
/// and every window made from it are gone (retired, or released with the QP that kept it); then the registration
/// owner is notified ([`GpuRegion::notify_window_release`]). No CPU byte of the region is read.
#[derive(Clone, Debug)]
pub struct GpuSource {
    hold: Arc<BorrowedRegion>,
    range: crate::memory::MemoryRange,
}

impl GpuSource {
    /// The source over `range`, which must lie inside `region`.
    pub fn new(region: Arc<GpuRegion>, range: crate::memory::MemoryRange) -> io::Result<Self> {
        if !crate::memory::MemoryRange::new(region.address, region.length)
            .is_ok_and(|whole| whole.contains(range.address(), range.length()))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            hold: Arc::new(BorrowedRegion::new(region)),
            range,
        })
    }

    /// The peer-visible range (region address space: iova of a DMA-BUF, host address of the mock).
    pub fn range(&self) -> crate::memory::MemoryRange {
        self.range
    }

    /// Dies when this source and every window made from it are gone. An observer that sees it dead issues an
    /// acquire fence before relying on it.
    pub fn release_watch(&self) -> Weak<()> {
        self.hold.release_watch()
    }

    /// A prepared, unbound window over exactly [`Self::range`] for one attempt (allocates a MW: control call).
    /// It holds this source until it is gone; its own release watch
    /// ([`crate::verbs::HostDestination::borrowed_release_watch`]) dies with the window.
    pub fn window(&self) -> io::Result<crate::verbs::HostDestination> {
        let region = Arc::clone(self.hold.region());
        let mut borrowed = BorrowedRegion::new(region);
        borrowed.source = Some(Arc::clone(&self.hold));
        crate::verbs::HostDestination::register_borrowed_prepared(
            &self.hold.region()._dev,
            borrowed,
            self.range,
        )
    }
}

/// Read-only `mmap` of a host-backed DMA-BUF: the bytes the CRC needs, never written here.
#[derive(Debug)]
struct HostMapping {
    ptr: *const u8,
    len: usize,
}

// SAFETY: the mapping is only read through `&[u8]`; the owner keeps the dmabuf alive for the region's lifetime.
unsafe impl Send for HostMapping {}
// SAFETY: see Send.
unsafe impl Sync for HostMapping {}

impl Drop for HostMapping {
    fn drop(&mut self) {
        // SAFETY: ptr/len come from the mmap in `map_read_only` and are unmapped exactly once.
        unsafe { libc::munmap(self.ptr as *mut c_void, self.len) };
    }
}

// SAFETY: MR handles are thread-safe libibverbs objects; the registration only reads its immutable fields and
// deregisters once, in Drop, with the last reference.
unsafe impl Send for GpuRegion {}
// SAFETY: see Send.
unsafe impl Sync for GpuRegion {}

impl GpuRegion {
    /// Register `[offset, offset + length)` of `fd` at `address` (the iova a peer uses). Control call.
    ///
    /// The dmabuf must stay alive until the last owner drops the region. `EOPNOTSUPP`/`EINVAL` means the provider
    /// cannot register DMA-BUF memory (ConnectX-4 rejects it); use [`Self::register_host`] for the mock.
    pub fn register(
        dev: &Arc<Device>,
        fd: RawFd,
        offset: u64,
        address: u64,
        length: u64,
        access: GpuAccess,
    ) -> io::Result<Arc<Self>> {
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero-length DMA-BUF region",
            ));
        }
        let mr = dmabuf_register(dev, fd, offset, address, length, access.bits())?;
        Ok(Self::wrap(
            dev,
            mr,
            access,
            Backing::Dmabuf,
            None,
            Some((address, length)),
        ))
    }

    /// Register a DMA-BUF the caller declares **CPU-readable** (host-backed, e.g. `udmabuf`) and map it
    /// read-only. Same contract as [`Self::register`], plus: the bytes behind `fd` are readable host memory,
    /// so a source-pull store can compute the descriptor CRC over them. Real device memory must not use this.
    pub fn register_readable(
        dev: &Arc<Device>,
        fd: RawFd,
        offset: u64,
        address: u64,
        length: u64,
        access: GpuAccess,
    ) -> io::Result<Arc<Self>> {
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero-length DMA-BUF region",
            ));
        }
        let host = match map_read_only(fd, offset, length) {
            Ok(host) => host,
            Err(error) => {
                diag::diag!(
                    "rdma: mmap of the host-readable DMA-BUF failed (fd {fd}, offset {offset}, length {length}): {error}"
                );
                return Err(error);
            }
        };
        let mr = match dmabuf_register(dev, fd, offset, address, length, access.bits()) {
            Ok(mr) => mr,
            Err(error) => {
                // ibv_reg_dmabuf_mr's errno is the whole answer: EOPNOTSUPP means the provider cannot
                // register this DMA-BUF at all, EINVAL means the descriptor (alignment, access flags).
                diag::diag!(
                    "rdma: ibv_reg_dmabuf_mr failed (fd {fd}, offset {offset}, address {address:#x}, length {length}, access {:#x}): {error}",
                    access.bits()
                );
                return Err(error); // the mapping drops with this error
            }
        };
        Ok(Self::wrap(
            dev,
            mr,
            access,
            Backing::DmabufHost,
            Some(host),
            Some((address, length)),
        ))
    }

    /// Register host memory as the GPU-memory mock (same access bits and rkey contract). Control call.
    ///
    /// # Safety
    /// `address..address + length` must be initialized, writable host memory that stays mapped and owned by the
    /// caller until the last owner drops the region.
    pub unsafe fn register_host(
        dev: &Arc<Device>,
        address: u64,
        length: u64,
        access: GpuAccess,
    ) -> io::Result<Arc<Self>> {
        if length == 0 || address == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero-length or null GPU-mock region",
            ));
        }
        let mr = mr_register_access(dev, address as *mut c_void, length, access.bits())?;
        Ok(Self::wrap(dev, mr, access, Backing::Host, None, None))
    }

    /// `iova` overrides the peer-visible address and length. A DMA-BUF MR has no user virtual address, so
    /// the provider leaves `ibv_mr->addr` at 0: the iova of the registration call is the only valid value.
    fn wrap(
        dev: &Arc<Device>,
        mr: *mut crate::verbs::Opaque,
        access: GpuAccess,
        backing: Backing,
        host: Option<HostMapping>,
        iova: Option<(u64, u64)>,
    ) -> Arc<Self> {
        // SAFETY: the registration returned a live MR.
        let (lkey, rkey, address, length) = unsafe { mr_identity(mr) };
        let (address, length) = iova.unwrap_or((address, length));
        Arc::new(Self {
            _dev: dev.clone(),
            mr,
            address,
            length,
            lkey,
            rkey,
            access,
            backing,
            host,
            retain: false,
            alive: Arc::new(()),
            window_release: OnceLock::new(),
        })
    }

    /// Call `notify` each time a borrowed window of this region dies (back to nowhere: retired, or released
    /// with the QP that kept it after its session ended), after its release watch died. Set once by the
    /// registration owner before it lends any window; a later call is ignored. Runs on the thread that drops the
    /// window (owner, callback or QP control thread), so it must only wake a waiter.
    pub fn notify_window_release(&self, notify: impl Fn() + Send + Sync + 'static) {
        let _ = self
            .window_release
            .set(WindowReleaseNotify(Arc::new(notify)));
    }

    /// Dies once the MR is deregistered (field drop after [`Drop::drop`]); a failed deregistration keeps it alive
    /// for good. The proof a registration owner gives its caller before the memory may be freed. An observer that
    /// sees it dead issues an acquire fence before relying on the deregistration.
    pub fn release_watch(&self) -> Weak<()> {
        Arc::downgrade(&self.alive)
    }

    /// Address a peer uses in the WRITE/READ.
    pub fn address(&self) -> u64 {
        self.address
    }
    /// Registered length.
    pub fn length(&self) -> u64 {
        self.length
    }
    /// Local key for a local SGE.
    pub fn lkey(&self) -> u32 {
        self.lkey
    }
    /// Remote key a peer uses. Read-only or write-only per [`GpuAccess`]; never a parent key with more rights.
    pub fn rkey(&self) -> u32 {
        self.rkey
    }
    /// Direction of the registration.
    pub fn access(&self) -> GpuAccess {
        self.access
    }
    /// Backing of the registration.
    pub fn backing(&self) -> Backing {
        self.backing
    }

    /// CPU address and length of the host-visible bytes (host mock or CPU-readable DMA-BUF), `None` for real
    /// device memory. No slice is formed: a peer may be writing other parts of the region.
    pub fn host_span(&self) -> Option<(u64, u64)> {
        match self.backing {
            Backing::Dmabuf => None,
            Backing::DmabufHost => self.host.as_ref().map(|h| (h.ptr as u64, h.len as u64)),
            Backing::Host => Some((self.address, self.length)),
        }
    }

    /// CPU bytes `[offset, offset + len)` of the region (relative to its start), `None` for real device memory or
    /// a range outside the region. Only these bytes are borrowed; the rest of the region is never aliased.
    ///
    /// The GPU mock registers caller-owned host memory, so the receipt of a placed READ can be checked here exactly
    /// like on a host destination. Device memory has no CPU mapping on the client: its check belongs to the device
    /// (the caller's CUDA fence and read), never to a host pointer.
    ///
    /// # Safety
    /// No peer and no local writer may write this subrange while the returned slice lives: the caller must own the
    /// completion that fenced the transfer into it (the retirement proof of the window over exactly these bytes).
    pub unsafe fn host_subrange(&self, offset: u64, len: usize) -> Option<&[u8]> {
        let (base, length) = self.host_span()?;
        let end = offset.checked_add(len as u64)?;
        if end > length {
            return None;
        }
        // SAFETY: inside the mapped (DmabufHost) or caller-retained (Host, `register_host` contract) range; the
        // caller guarantees no writer for this subrange while the slice lives.
        Some(unsafe { std::slice::from_raw_parts((base + offset) as *const u8, len) })
    }

    /// MR handle for the destination owner (same crate).
    pub(crate) fn mr_handle(&self) -> *mut crate::verbs::Opaque {
        self.mr
    }

    /// Wrap this region as a placement destination (GET) and prepare its
    /// reusable MW on this control thread. The destination retains this region
    /// (and therefore the MR) through every window/attempt owner; retirement
    /// deallocates the window, never the MR before the last destination is gone.
    pub fn destination(self: &Arc<Self>) -> io::Result<crate::verbs::HostDestination> {
        let range = crate::memory::MemoryRange::new(self.address, self.length).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("GPU region range: {e:?}"),
            )
        })?;
        crate::verbs::HostDestination::register_borrowed_mr_prepared(
            &self._dev,
            Arc::clone(self),
            range,
        )
    }
}

impl Drop for GpuRegion {
    fn drop(&mut self) {
        if self.retain {
            std::mem::forget(self._dev.clone());
            return;
        }
        // SAFETY: the last Arc is gone; no core and no detached QP can post with this MR any more.
        let rc = unsafe { mr_deregister(self.mr) };
        if rc == 0 {
            return;
        }
        self.retain = true;
        // The MR stays registered: the release watch must never report it gone.
        std::mem::forget(self.alive.clone());
        teardown_failure(format_args!(
            "rdma: GPU region deregistration failed: {} (registration retained)",
            io::Error::from_raw_os_error(rc.abs())
        ));
        std::mem::forget(self._dev.clone());
    }
}

/// Map `length` bytes at `offset` of `fd` read-only (`MAP_SHARED`: the owner's writes are visible).
fn map_read_only(fd: RawFd, offset: u64, length: u64) -> io::Result<HostMapping> {
    let len = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "region too large"))?;
    // SAFETY: mmap with a valid fd is the caller's contract; the result is checked below.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            offset as libc::off_t,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(HostMapping {
        ptr: ptr as *const u8,
        len,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Key {
    Dmabuf {
        dev: u64,
        ino: u64,
        offset: u64,
        address: u64,
        length: u64,
        access: GpuAccess,
    },
    Host {
        address: u64,
        length: u64,
        access: GpuAccess,
    },
}

impl Key {
    fn of(
        fd: RawFd,
        offset: u64,
        address: u64,
        length: u64,
        access: GpuAccess,
    ) -> io::Result<Self> {
        // SAFETY: `st` is plain storage for fstat; a valid fd is the caller's contract.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self::Dmabuf {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            offset,
            address,
            length,
            access,
        })
    }
}

/// One registration per range while an owner holds it.
#[derive(Debug, Default)]
pub struct GpuRegistry {
    regions: Mutex<HashMap<Key, Weak<GpuRegion>>>,
}

impl GpuRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the live DMA-BUF registration for this range, or register it. Control call.
    pub fn get_or_register(
        &self,
        dev: &Arc<Device>,
        fd: RawFd,
        offset: u64,
        address: u64,
        length: u64,
        access: GpuAccess,
    ) -> io::Result<Arc<GpuRegion>> {
        let key = Key::of(fd, offset, address, length, access)?;
        self.get_or_insert(key, || {
            GpuRegion::register(dev, fd, offset, address, length, access)
        })
    }

    /// Return the live host-mock registration for this range, or register it. Control call.
    ///
    /// # Safety
    /// Same contract as [`GpuRegion::register_host`].
    pub unsafe fn get_or_register_host(
        &self,
        dev: &Arc<Device>,
        address: u64,
        length: u64,
        access: GpuAccess,
    ) -> io::Result<Arc<GpuRegion>> {
        let key = Key::Host {
            address,
            length,
            access,
        };
        // SAFETY: forwarded caller contract.
        self.get_or_insert(key, || unsafe {
            GpuRegion::register_host(dev, address, length, access)
        })
    }

    fn get_or_insert(
        &self,
        key: Key,
        register: impl FnOnce() -> io::Result<Arc<GpuRegion>>,
    ) -> io::Result<Arc<GpuRegion>> {
        let mut regions = self.regions.lock().expect("GPU registry poisoned");
        if let Some(region) = regions.get(&key).and_then(Weak::upgrade) {
            return Ok(region);
        }
        let region = register()?;
        regions.insert(key, Arc::downgrade(&region));
        regions.retain(|_, weak| weak.strong_count() > 0);
        Ok(region)
    }

    /// Live registrations currently held by callers.
    pub fn len(&self) -> usize {
        let mut regions = self.regions.lock().expect("GPU registry poisoned");
        regions.retain(|_, weak| weak.strong_count() > 0);
        regions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_access_masks_match_verbs_abi_and_allow_window_binding() {
        // ibv_access_flags: LOCAL_WRITE=1, REMOTE_WRITE=2, REMOTE_READ=4,
        // REMOTE_ATOMIC=8, MW_BIND=16. Check numeric ABI values independently.
        assert_eq!(ACCESS_MW_BIND, 1 << 4);
        assert_eq!(GpuAccess::Read.bits(), 1 | 4 | 16);
        assert_eq!(GpuAccess::Write.bits(), 1 | 16);
        assert_eq!(GpuAccess::Both.bits(), 1 | 2 | 4 | 16);
        for access in [GpuAccess::Read, GpuAccess::Write, GpuAccess::Both] {
            assert_ne!(access.bits() & 16, 0);
            assert_eq!(
                access.bits() & 8,
                0,
                "GPU registration never grants atomics"
            );
        }
    }
}
