// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! nvme: completion-based block device abstraction (L0 of the storage engine, see doc/design/storage-engine.md).
//!
//! One `BlockDev` value = one per-core queue handle. No locks, no threads, no async: the owner calls
//! `submit_*` (buffer ownership moves into the device) and later `poll(now)`, which returns finished IOs
//! together with their buffers. Time is passed in by the caller (sans-IO, adr 0015).
//! Implementations: `store::dev::SimDev` (in-memory, fault injection), `SpdkDev` (feature `spdk`) and `KernelDev`
//! (feature `kernel`, the default tier, adr 0169) in production, and `filedev::FileDev` (regular file / block device via pread/pwrite + fdatasync; DEV/LAB ONLY).

// carries the native DPDK link line (single owner of the archives)
#[cfg(feature = "spdk")]
extern crate dpdk_link as _;

pub mod health;

#[cfg(any(feature = "spdk", test))]
pub mod dmapool;
#[cfg(feature = "spdk")]
pub mod spdk;
/// Learned service time of a polled queue: when an idle core may sleep while commands are in flight.
#[cfg(any(feature = "spdk", test))]
pub mod svc;

#[cfg(all(unix, feature = "lab"))]
pub mod filedev;

/// Unit tests that `fork` (children keep every open descriptor, so a `flock` another test owns until they exit) and
/// tests that expect an exclusive open to be released take this lock for their whole scope.
#[cfg(all(test, unix, any(feature = "lab", feature = "spdk", feature = "kernel")))]
pub(crate) mod testlock {
    use std::sync::{Mutex, MutexGuard, PoisonError};

    static FORK_VS_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) fn guard() -> MutexGuard<'static, ()> {
        FORK_VS_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Kernel admin passthrough for identity + SMART of kernel-owned NVMe nodes (`file:` lab devices, `kernel:` devices, hwcheck).
#[cfg(all(unix, any(feature = "lab", feature = "kprobe", feature = "kernel")))]
pub mod kprobe;

/// `kernel:` devices: NVMe namespace on the kernel nvme driver through io_uring (adr 0169). Linux only.
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod kdev;
#[cfg(all(feature = "kernel", not(target_os = "linux")))]
#[path = "kdev_stub.rs"]
pub mod kdev;

/// Exclusive admission + driver rebind of one NVMe PCI function to a userspace driver (prep, `nvme-rebind`). Linux only.
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub mod pcibind;

/// Write-view guard: in debug and `viewguard` builds the memory under live zero-copy write views, checked on every free
/// by a guarding allocator; a no-op otherwise.
#[cfg(any(
    debug_assertions,
    feature = "viewguard",
    all(feature = "kernel", target_os = "linux")
))]
pub mod viewguard;

/// Format NVM scope check (FNA: does a format of one namespace wipe the others?); no deps, always on.
pub mod fna;

/// PCI allow-list helpers (EAL args, canonical BDF); no deps, always on.
pub mod pciallow;

/// SPDK PCI claim taken before DPDK maps the device (a second opener would stop DMA of the owner on uio hosts).
#[cfg(all(unix, any(feature = "lab", feature = "spdk", feature = "kernel")))]
pub mod pcilock;

/// SPDK multi-process roles and locks: one controller shared by several processes, one namespace each. DEBUG/TESTING
/// ONLY (feature `spdk-mp`, adr 0463): production = one OSD per controller (adr 0103).
#[cfg(all(unix, feature = "spdk-mp"))]
pub mod spdkmp;

#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel"))]
pub mod any;

/// Cross-core return of pooled read buffers handed out as shared data ([`IoBuf::into_shared`]).
#[cfg(any(feature = "spdk", test, all(feature = "kernel", target_os = "linux")))]
mod shelf;

/// Monotonic nanoseconds, caller-supplied.
pub type Nanos = u64;

/// Device/namespace geometry as seen through one queue handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Logical block size in bytes (512 or 4096 typical).
    pub lba_size: u32,
    /// Namespace capacity in LBAs.
    pub lba_count: u64,
    /// Atomic write unit power-fail in LBAs (>= 1). Writes of <= this many LBAs are never torn.
    pub awupf_lbas: u32,
    /// Atomic write unit normal in LBAs (>= awupf_lbas).
    pub awun_lbas: u32,
    /// Volatile write cache present. PLP devices: false (write completion == durable).
    pub vwc: bool,
    /// Largest single IO in LBAs accepted by submit_*.
    pub max_xfer_lbas: u32,
    /// Deallocate (DSM) supported.
    pub dealloc: bool,
    /// Write Zeroes supported.
    pub write_zeroes: bool,
}

/// NVMe write-command FUA bit (CDW12 bit 30; SPDK `SPDK_NVME_IO_FLAGS_FORCE_UNIT_ACCESS`, asserted in `csrc/shim.c`).
pub const IO_FLAG_FUA: u32 = 1 << 30;

/// IO flags for every durable write (and write-zeroes): a device with a volatile write cache (lab override
/// `--allow-vwc`, adr 0008) must complete each write to stable media (FUA) before the ack; PLP devices need none.
pub fn write_io_flags(g: &Geometry) -> u32 {
    if g.vwc { IO_FLAG_FUA } else { 0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Write,
    Read,
    Deallocate,
    WriteZeroes,
}

/// Completion-time failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    /// Unrecovered media error.
    Media,
    /// Command aborted / queue torn down.
    Aborted,
    /// Other NVMe status (raw sct<<8 | sc).
    Status(u16),
    /// Kernel errno of a completion (direct mode, or a failed passthrough submit): not an NVMe status.
    Errno(i32),
}

/// NVMe completion status (`sct << 8 | sc`; higher bits are carried through into [`IoError::Status`]) -> store error.
/// sct 2 = media and data integrity; generic sc 7 (abort requested) and 8 (aborted, SQ deleted) = [`IoError::Aborted`].
pub fn nvme_status_err(raw: u16) -> IoError {
    let (sct, sc) = ((raw >> 8) & 7, raw & 0xff);
    if sct == 2 {
        IoError::Media
    } else if sct == 0 && (sc == 7 || sc == 8) {
        IoError::Aborted
    } else {
        IoError::Status(raw)
    }
}

/// Kernel errno of a failed completion -> store error: a medium / data-integrity errno is [`IoError::Media`], a cancelled,
/// timed-out or interrupted command [`IoError::Aborted`], everything else keeps its errno (a full filesystem `ENOSPC`, a
/// quota `EDQUOT`, an `EIO`): the store must be able to tell "device full" from "device failing".
#[cfg(any(feature = "lab", all(feature = "kernel", target_os = "linux"), test))]
pub(crate) fn errno_err(e: i32) -> IoError {
    match e {
        libc::ENODATA | libc::EILSEQ => IoError::Media,
        libc::ECANCELED | libc::ETIMEDOUT | libc::ENOLINK | libc::EINTR => IoError::Aborted,
        e => IoError::Errno(e),
    }
}

/// Result of a backend's native submit call (`0` = queued, else the driver's negative errno): a rejected submit queued
/// nothing, so it is never a failed controller. `-ENOMEM` = the driver's request pool is exhausted (behaves like a full
/// queue), `-EINVAL` = the driver refused the command shape (a caller bug; the shape checks of [`Geometry::check_io`]
/// catch it first), anything else means the queue is gone.
#[cfg(any(feature = "spdk", test))]
pub(crate) fn submit_errno(r: i32) -> SubmitError {
    match r {
        r if r == -libc::ENOMEM => SubmitError::QueueFull,
        r if r == -libc::EINVAL => SubmitError::Invalid,
        _ => SubmitError::Dead,
    }
}

/// NVM command set opcodes.
#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
pub(crate) const NVM_WRITE: u8 = 0x01;
#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
pub(crate) const NVM_READ: u8 = 0x02;
#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
pub(crate) const NVM_WRITE_ZEROES: u8 = 0x08;
#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
pub(crate) const NVM_DSM: u8 = 0x09;

#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
impl Op {
    /// The NVM opcode that carries this operation.
    pub(crate) const fn nvme_opcode(self) -> u8 {
        match self {
            Op::Write => NVM_WRITE,
            Op::Read => NVM_READ,
            Op::Deallocate => NVM_DSM,
            Op::WriteZeroes => NVM_WRITE_ZEROES,
        }
    }
}

/// Text of a completion status for the first-failure log: `sct=.. sc=.. dnr=..` (layout `sct << 8 | sc`, DNR at bit
/// `dnr_shift`: 17 in the SPDK shim, 14 in a passthrough result).
#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux"), test))]
pub(crate) fn status_text(raw: i32, dnr_shift: u32) -> String {
    format!(
        "nvme status raw=0x{raw:x} sct={} sc={} dnr={}",
        (raw >> 8) & 7,
        raw & 0xff,
        (raw >> dnr_shift) & 1
    )
}

/// The loud first-failure line of a device (once per device): `store` names the device, `detail` the backend's view of
/// the failed command.
#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
pub(crate) fn log_first_failure(
    store: std::fmt::Arguments<'_>,
    op: Op,
    lba: u64,
    detail: std::fmt::Arguments<'_>,
) {
    eprintln!(
        "ERROR {store}: first failed completion: op {op:?} (nvme opcode 0x{:02x}) lba {lba} {detail}",
        op.nvme_opcode()
    );
}

/// Submission-time failure (nothing was queued).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// Queue depth exhausted; retry after `poll`.
    QueueFull,
    /// LBA range beyond capacity.
    OutOfRange,
    /// Zero length, buffer length != nlba * lba_size, or > max_xfer_lbas.
    Invalid,
    /// Op not supported by device.
    Unsupported,
    /// Device is dead (crashed sim, failed controller).
    Dead,
}

/// Rejected submission; the buffer (if any) is handed back to the caller.
#[derive(Debug)]
pub struct Rejected<B> {
    pub err: SubmitError,
    pub buf: Option<B>,
}

/// Logical block size of the emulated (file) and required (kernel) namespace.
pub const LBA: u32 = 4096;

/// Exact-size bin of a 4 KiB-multiple buffer of at most `max_blocks` blocks (`len / 4096`; SPDK dmapool, kdev arena).
#[inline]
#[cfg(any(feature = "spdk", test, all(feature = "kernel", target_os = "linux")))]
pub(crate) fn block_class(len: usize, max_blocks: usize) -> Option<usize> {
    (len != 0 && len.is_multiple_of(4096) && len / 4096 <= max_blocks).then_some(len / 4096)
}

impl Geometry {
    /// Namespace capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.lba_count * self.lba_size as u64
    }

    /// Shape of one data IO: `nlba` non-zero LBAs at `lba`, no more than [`Geometry::max_xfer_lbas`]. Every backend
    /// rejects with this one check before it hands the command to its driver.
    pub fn check_io(&self, lba: u64, nlba: u64) -> Result<(), SubmitError> {
        if nlba == 0 || nlba > u64::from(self.max_xfer_lbas) {
            return Err(SubmitError::Invalid);
        }
        self.check_range(lba, nlba)
    }

    /// `[lba, lba + nlba)` is a non-empty range inside the namespace.
    pub fn check_range(&self, lba: u64, nlba: u64) -> Result<(), SubmitError> {
        if nlba == 0 {
            return Err(SubmitError::Invalid);
        }
        match lba.checked_add(nlba) {
            Some(e) if e <= self.lba_count => Ok(()),
            _ => Err(SubmitError::OutOfRange),
        }
    }
}

impl<B> Rejected<B> {
    /// Rejection `err` handing `buf` back.
    pub fn new(err: SubmitError, buf: Option<B>) -> Rejected<B> {
        Rejected { err, buf }
    }
}

pub type Submit<B> = Result<(), Rejected<B>>;

/// Finished IO. `buf` is returned for read/write (write buffers come back untouched, reads filled).
#[derive(Debug)]
pub struct Completion<B> {
    pub tag: u64,
    pub op: Op,
    pub result: Result<(), IoError>,
    pub buf: Option<B>,
}

/// Shape checks of an [`IoBuf::copy_from_slice_crc32c`]: the buffer and the source have one length, a whole number of blocks.
pub(crate) fn assert_crc_copy(dst_len: usize, src_len: usize, block_bytes: usize, blocks: usize) {
    assert!(block_bytes > 0);
    assert_eq!(dst_len, src_len);
    assert_eq!(
        src_len,
        block_bytes.checked_mul(blocks).expect("size overflow")
    );
}

/// Concatenate `parts` into the front of `dst` and zero the rest (the body of [`IoBuf::copy_from_slices_zero_tail`]; writes
/// only, so `dst` may be uninitialized). Panics if the parts do not fit.
pub(crate) fn copy_parts_zero_tail(dst: &mut [std::mem::MaybeUninit<u8>], parts: &[&[u8]]) {
    let total = parts
        .iter()
        .try_fold(0usize, |n, p| n.checked_add(p.len()))
        .expect("size overflow");
    assert!(total <= dst.len());
    let (head, tail) = dst.split_at_mut(total);
    let mut off = 0;
    for p in parts {
        // SAFETY: `off + p.len() <= total` stays inside `head`; inputs cannot alias the exclusively borrowed `dst`.
        unsafe {
            std::ptr::copy_nonoverlapping(p.as_ptr(), head.as_mut_ptr().add(off).cast(), p.len())
        };
        off += p.len();
    }
    tail.fill(std::mem::MaybeUninit::new(0));
}

/// DMA-able buffer. Length is a multiple of the LBA size when used for IO.
pub trait IoBuf {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];
    /// Completely overwrite the buffer without exposing its previous contents.
    fn copy_from_slice(&mut self, src: &[u8]) {
        assert_eq!(self.len(), src.len());
        self.as_mut_slice().copy_from_slice(src);
    }
    /// Concatenate the supplied initialized parts and zero the remainder of the buffer.
    fn copy_from_slices_zero_tail(&mut self, parts: &[&[u8]]) {
        let dst = self.as_mut_slice();
        // SAFETY: `MaybeUninit<u8>` has the layout of `u8`; the callee only writes.
        let dst = unsafe { &mut *(dst as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) };
        copy_parts_zero_tail(dst, parts);
    }
    /// Completely overwrite the buffer and checksum each equally sized block in one pass.
    /// Each checksum slot initially contains its seed and is replaced by the resulting CRC32C.
    fn copy_from_slice_crc32c(&mut self, src: &[u8], block_bytes: usize, crcs: &mut [u32]) {
        assert_crc_copy(self.len(), src.len(), block_bytes, crcs.len());
        for ((s, d), c) in src
            .chunks(block_bytes)
            .zip(self.as_mut_slice().chunks_mut(block_bytes))
            .zip(crcs)
        {
            *c = crc::crc32c_copy_dma(*c, s, d);
        }
    }
    /// Hand the buffer (filled: a completed read) to shared immutable ownership without a copy: the bytes stay where the
    /// device put them and nobody can write them again (`Bytes` has no mutable access). The buffer goes back to its pool
    /// when the last reference drops, on whichever thread that is.
    fn into_shared(self) -> bytes::Bytes
    where
        Self: Sized + Send + 'static,
    {
        pin(self.len());
        bytes::Bytes::from_owner(Owned(self))
    }
}

static PINNED_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PINNED_PIECES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `(pieces, bytes)` of IO buffers held as shared read data now ([`IoBuf::into_shared`]): reply queues, transport
/// sends, retained prefetch runs. The copy path returns the device buffer to its pool at once; these stay out of every
/// pool until the last reference drops, so the process memory envelope reports them (`dump_mempools` `read_shared`).
pub fn shared_pinned() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (PINNED_PIECES.load(Relaxed), PINNED_BYTES.load(Relaxed))
}

/// A `len`-byte buffer became shared data (every owner of an `into_shared` calls it once and [`unpin`] when it drops).
fn pin(len: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    PINNED_PIECES.fetch_add(1, Relaxed);
    PINNED_BYTES.fetch_add(len as u64, Relaxed);
}

fn unpin(len: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    PINNED_PIECES.fetch_sub(1, Relaxed);
    PINNED_BYTES.fetch_sub(len as u64, Relaxed);
}

/// An [`IoBuf`] as the owner of a `Bytes` ([`IoBuf::into_shared`]).
struct Owned<B: IoBuf>(B);

impl<B: IoBuf> Drop for Owned<B> {
    fn drop(&mut self) {
        unpin(self.0.len());
    }
}

impl<B: IoBuf> AsRef<[u8]> for Owned<B> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl IoBuf for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn as_slice(&self) -> &[u8] {
        self
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }
    fn into_shared(self) -> bytes::Bytes {
        bytes::Bytes::from(self)
    }
}

/// Per-core queue handle to an NVMe namespace.
pub trait BlockDev {
    /// `Send + 'static`: a completed read buffer may leave the core as shared reply data ([`IoBuf::into_shared`]).
    type Buf: IoBuf + Send + 'static;

    fn geometry(&self) -> Geometry;
    /// Zeroed buffer of `len` bytes suitable for IO on this device.
    fn alloc_buf(&mut self, len: usize) -> Self::Buf;
    /// Like [`BlockDev::alloc_buf`] but contents unspecified: the caller overwrites the whole buffer (skips the zeroing).
    fn alloc_buf_uninit(&mut self, len: usize) -> Self::Buf {
        self.alloc_buf(len)
    }
    /// Like [`BlockDev::alloc_buf_uninit`] for deferrable store memory (asynchronous reads, staged write copies: may be
    /// held without IO in flight): `None` when a device whose buffers
    /// come from a bounded DMA budget (SPDK hugepages, adr 0175 am. 4) has none to spare within its read gate now; the
    /// caller postpones the IO and retries at its next progress step (backpressure, never a wait for memory). Memory
    /// comes back as IO in flight completes and its data is released, and with [`BlockDev::release_pooled`] on every
    /// core. The store allocates through this and [`BlockDev::try_alloc_io_uninit`] only.
    fn try_alloc_buf_uninit(&mut self, len: usize) -> Option<Self::Buf> {
        Some(self.alloc_buf_uninit(len))
    }
    /// [`BlockDev::try_alloc_buf_uninit`] for in-flight IO memory: allocated right before a device submit and released
    /// by its completion (WAL records, tree pages, checkpoint, omap runs, store moves, synchronous reads, deferred write
    /// copies); admitted within the whole budget, of which deferrable memory never takes the last quarter.
    fn try_alloc_io_uninit(&mut self, len: usize) -> Option<Self::Buf> {
        Some(self.alloc_buf_uninit(len))
    }
    /// Give buffer memory this core keeps for reuse back to a bounded DMA budget when another core ran short (and take
    /// over buffers other cores returned). Called by the store on every core at each sweep; cheap when idle.
    fn release_pooled(&mut self) {}
    /// Can this device read into ordinary process memory ([`BlockDev::alloc_buf_ram_uninit`])? The store sizes its data
    /// cache from the memory envelope only then (adr 0633-data-cache-envelope); a device that reads only into a bounded DMA pool
    /// (SPDK hugepages) keeps the cache at the prefetch floor.
    fn ram_reads(&self) -> bool {
        false
    }
    /// Read buffer (contents unspecified) in ordinary process memory, faulted in on first use, never taken from a bounded
    /// DMA pool: for reads whose bytes may stay in a long-lived cache. Called only when [`BlockDev::ram_reads`].
    fn alloc_buf_ram_uninit(&mut self, len: usize) -> Self::Buf {
        self.alloc_buf_uninit(len)
    }
    /// Hand memory back that [`BlockDev::alloc_buf_ram_uninit`] buffers no longer use (the data cache evicted): a device that
    /// keeps registered cache memory unregisters and unmaps its unused chunks. Cheap when there is nothing to hand back.
    fn trim_ram(&mut self) {}
    /// A write buffer that views `data` in place (zero copy, adr 0061 am. 4) when the device can DMA straight from that
    /// memory; `None` = the caller copies into [`BlockDev::alloc_buf_uninit`]. The buffer keeps `data` alive (immutable
    /// `Bytes`: nobody can change it) until it comes back in a completion; it is never written by the CPU.
    fn view_buf(&mut self, data: &bytes::Bytes) -> Option<Self::Buf> {
        let _ = data;
        None
    }
    /// Free submission slots on this queue.
    fn queue_space(&self) -> usize;
    /// Total submission slots of this queue (a txn needing more can never be admitted).
    fn queue_depth(&self) -> usize;

    /// Write `buf` (length = nlba * lba_size) at `lba`.
    fn submit_write(&mut self, lba: u64, buf: Self::Buf, tag: u64) -> Submit<Self::Buf>;
    /// Read `buf.len() / lba_size` LBAs from `lba` into `buf`.
    fn submit_read(&mut self, lba: u64, buf: Self::Buf, tag: u64) -> Submit<Self::Buf>;
    /// Submitted commands reach the device only at the end of the core loop's pass instead of at submit: the thread's
    /// flush ([`kdev::flush`](crate::kdev::flush), kernel tier) or [`BlockDev::issue`] (SPDK doorbell batching, adr 0004
    /// am. 1). The store then seals an idle WAL's unit at the end of the pass (all txns of the pass in one unit at no
    /// latency cost); a device that issues at submit gets it sealed at submit (any later seal adds latency, adr 0021
    /// am. 67). Default false.
    fn submits_at_flush(&self) -> bool {
        false
    }
    /// Hand the commands submitted since the last call to the device (one doorbell write for the whole pass). The store
    /// calls it at the end of the core loop's pass, after its WAL seal. [`BlockDev::poll`] issues as well, so a caller
    /// that only polls (tools, synchronous setup loops) never strands a command. Default: nothing (the device issued at
    /// submit, or the thread's flush does it).
    fn issue(&mut self) {}
    /// Idle core with commands of this queue in flight (polled devices without a completion wake-up): `Some(d)` = the
    /// earliest in-flight command may complete in `d` by the queue's learned service times (zero: it is due, poll),
    /// `None` = no estimate (nothing in flight, or every command is past its learned bound): the caller keeps its
    /// own policy. Default `None`.
    fn wait_hint(&mut self) -> Option<std::time::Duration> {
        None
    }
    /// Runtime deallocate shape of this queue (adr 0642): what one [`BlockDev::submit_deallocate`] may carry.
    /// [`DeallocLimits::NONE`] = no runtime deallocate (the default; setup-time [`BlockDev::deallocate_all`] is separate).
    fn dealloc_limits(&self) -> DeallocLimits {
        DeallocLimits::NONE
    }
    /// Deallocate `ranges` (`(lba, nlba)`, each `nlba >= 1`) in one command: at most
    /// [`DeallocLimits::max_ranges`] ranges and [`DeallocLimits::max_lbas`] LBAs in total, one completion
    /// (`Op::Deallocate`, no buffer). Deallocated LBAs read back undefined: callers never rely on their contents. The
    /// device does not order this command against others in flight: the caller keeps the LBAs out of every other IO until
    /// the completion.
    fn submit_deallocate(&mut self, ranges: &[(u64, u32)], tag: u64) -> Submit<Self::Buf>;
    /// Deallocate the whole namespace (`mkfs`: the FTL forgets every previously mapped LBA, like BlueStore's
    /// `bluestore_discard_on_mkfs`). Synchronous, setup only. Default: DSM via [`dsm_deallocate_all`]; a backend
    /// without `Geometry::dealloc` but with another whole-device discard overrides it. Returns the LBAs deallocated.
    fn deallocate_all(&mut self) -> Result<u64, String> {
        dsm_deallocate_all(self)
    }
    fn submit_write_zeroes(&mut self, lba: u64, nlba: u32, tag: u64) -> Submit<Self::Buf>;

    /// Reap finished IOs into `out`; returns how many were appended. `now` = caller clock.
    fn poll(&mut self, now: Nanos, out: &mut Vec<Completion<Self::Buf>>) -> usize;

    /// Earliest time at which `poll` may produce a completion, if known (simulated devices). Lets callers
    /// that have nothing else to do advance a virtual clock instead of spinning.
    fn next_deadline(&self) -> Option<Nanos> {
        None
    }

    /// Device failed permanently (simulated power loss, dead controller, failed qpair or io_uring submit error):
    /// outstanding IOs may never complete. Latched: once true it stays true.
    fn is_dead(&self) -> bool {
        false
    }
}

/// Bound of a queue teardown's drain (`Drop` of a device queue). The owner drained its IO before, so this only matters on
/// a hung device. It equals the Linux NVMe driver's default command timeout (`nvme_core.io_timeout`), by which a healthy
/// controller has completed or aborted every command. A command still in flight after it has its buffer leaked (never
/// freed under DMA) and a `WARNING TIMEOUT` line reported.
#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
pub(crate) const TEARDOWN_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Teardown drain of a device queue: `reap` until `inflight` is 0 or [`TEARDOWN_WAIT`] passed. On the timeout the
/// `WARNING TIMEOUT` line is printed and `leak` forgets the buffers of the commands still in flight (the device may
/// still DMA into them). Returns whether the queue drained.
#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
pub(crate) fn drain_or_leak<Q>(
    q: &mut Q,
    inflight: impl Fn(&Q) -> usize,
    mut reap: impl FnMut(&mut Q),
    leak: impl FnOnce(&mut Q),
) -> bool {
    let t0 = std::time::Instant::now();
    while inflight(q) > 0 {
        if t0.elapsed() >= TEARDOWN_WAIT {
            eprintln!(
                "WARNING TIMEOUT nvme queue teardown exceeded {:.3}s ({} commands in flight: their buffers are leaked)",
                TEARDOWN_WAIT.as_secs_f64(),
                inflight(q)
            );
            leak(q);
            return false;
        }
        reap(q);
        std::hint::spin_loop();
    }
    true
}

/// Latched device failure (failed submit ring or qpair, a completion for a slot that holds no command): tripped once,
/// loud once, never cleared. [`BlockDev::is_dead`] reads it.
#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
#[derive(Debug, Default)]
pub(crate) struct DeadLatch(bool);

#[cfg(any(feature = "spdk", all(feature = "kernel", target_os = "linux")))]
impl DeadLatch {
    /// Latch dead; the first trip prints `ERROR <who>: <why>, device latched dead`.
    pub(crate) fn trip(&mut self, who: impl std::fmt::Display, why: std::fmt::Arguments) {
        if !self.0 {
            eprintln!("ERROR {who}: {why}, device latched dead");
        }
        self.0 = true;
    }

    /// A completion named a slot that holds no command: the slot table is out of sync with the device; never guess,
    /// fail-stop.
    pub(crate) fn empty_slot(&mut self, who: impl std::fmt::Display, slot: u32) {
        self.trip(who, format_args!("completion for empty slot {slot}"));
    }

    pub(crate) fn get(&self) -> bool {
        self.0
    }
}

/// Largest range one deallocate (DSM) command may carry: the range length field (NVMe NVM command set, Dataset
/// Management range, dword 1) is 32 bits of LBAs.
pub const DSM_MAX_LBAS: u64 = u32::MAX as u64;
/// Most ranges of one Dataset Management command (NR, 8 bits, zero-based).
pub const DSM_MAX_RANGES: u32 = 256;
/// Bytes of one Dataset Management range descriptor (context attributes, length, starting LBA).
pub const DSM_RANGE_BYTES: usize = 16;
/// Largest LBA count one NVMe command's NLB field can carry (16 bits, zero-based): write zeroes, and the passthrough
/// read/write of the kernel tier. Larger IO is split by the caller (the store works in [`Geometry::max_xfer_lbas`]).
pub const NLB_MAX: u32 = 65536;

/// What one runtime deallocate command of a queue may carry ([`BlockDev::dealloc_limits`], adr 0642).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeallocLimits {
    /// Ranges per command; 0 = no runtime deallocate.
    pub max_ranges: u32,
    /// LBAs per range.
    pub range_lbas: u32,
    /// LBAs per command, all ranges together.
    pub max_lbas: u64,
    /// Deallocation granularity in LBAs (>= 1): ranges should start and end on its multiples; the device may ignore what
    /// it cannot deallocate whole.
    pub gran_lbas: u64,
    /// Command path for the startup line (`dsm`, `uring-discard`, ...), or `off(<why>)`.
    pub via: &'static str,
}

impl DeallocLimits {
    /// No runtime deallocate.
    pub const NONE: DeallocLimits = DeallocLimits {
        max_ranges: 0,
        range_lbas: 0,
        max_lbas: 0,
        gran_lbas: 1,
        via: "off(device)",
    };
    /// One NVMe Dataset Management command: [`DSM_MAX_RANGES`] ranges of at most [`DSM_MAX_LBAS`] each, granularity 1.
    pub const DSM: DeallocLimits = DeallocLimits {
        max_ranges: DSM_MAX_RANGES,
        range_lbas: u32::MAX,
        max_lbas: DSM_MAX_LBAS * DSM_MAX_RANGES as u64,
        gran_lbas: 1,
        via: "dsm",
    };

    /// One NVMe Dataset Management command under the controller's reported limits (`0` = none reported): ranges per
    /// command (DMRL), LBAs per range (DMRSL), LBAs per command (DMSL), deallocate granularity in LBAs.
    pub fn nvme(ranges: u32, range_lbas: u32, total_lbas: u64, gran_lbas: u64) -> DeallocLimits {
        let max_ranges = if ranges == 0 {
            DSM_MAX_RANGES
        } else {
            ranges.min(DSM_MAX_RANGES)
        };
        let range_lbas = if range_lbas == 0 {
            u32::MAX
        } else {
            range_lbas
        };
        let all = u64::from(range_lbas) * u64::from(max_ranges);
        DeallocLimits {
            max_ranges,
            range_lbas,
            max_lbas: if total_lbas == 0 {
                all
            } else {
                total_lbas.min(all)
            },
            gran_lbas: gran_lbas.max(1),
            via: "dsm",
        }
    }

    /// The same shape, off: `via` says why.
    pub fn off(why: &'static str) -> DeallocLimits {
        DeallocLimits {
            via: why,
            ..DeallocLimits::NONE
        }
    }

    pub fn is_on(&self) -> bool {
        self.max_ranges > 0
    }

    /// Ranges that fit one command: count, per-range length and total.
    pub fn check(&self, ranges: &[(u64, u32)]) -> Result<(), SubmitError> {
        if self.max_ranges == 0 {
            return Err(SubmitError::Unsupported);
        }
        if ranges.is_empty() || ranges.len() > self.max_ranges as usize {
            return Err(SubmitError::Invalid);
        }
        let mut total = 0u64;
        for &(_, n) in ranges {
            if n == 0 || n > self.range_lbas {
                return Err(SubmitError::Invalid);
            }
            total += u64::from(n);
        }
        if total > self.max_lbas {
            return Err(SubmitError::Invalid);
        }
        Ok(())
    }
}

/// Dataset Management range list (deallocate): 16 bytes per range (context attributes 0, length, starting LBA) into
/// `out` (at least `ranges.len() * 16` bytes).
pub fn dsm_ranges_into(ranges: &[(u64, u32)], out: &mut [u8]) {
    for (i, &(lba, nlba)) in ranges.iter().enumerate() {
        let d = &mut out[i * DSM_RANGE_BYTES..(i + 1) * DSM_RANGE_BYTES];
        d[0..4].fill(0);
        d[4..8].copy_from_slice(&nlba.to_le_bytes());
        d[8..16].copy_from_slice(&lba.to_le_bytes());
    }
}

/// Split `[0, lba_count)` into `(lba, nlba)` deallocate ranges of at most `max` LBAs (clamped to `1..=`[`DSM_MAX_LBAS`]).
pub fn dsm_chunks(lba_count: u64, max: u64) -> impl Iterator<Item = (u64, u32)> {
    let max = max.clamp(1, DSM_MAX_LBAS);
    (0..lba_count.div_ceil(max)).map(move |i| {
        let lba = i * max;
        (lba, (lba_count - lba).min(max) as u32)
    })
}

/// Largest single-range deallocate one command of `l` carries, rounded down to the deallocate granularity
/// ([`DSM_MAX_LBAS`] when `l` reports no limit).
fn dsm_chunk_lbas(l: &DeallocLimits) -> u64 {
    if !l.is_on() {
        return DSM_MAX_LBAS;
    }
    let max = u64::from(l.range_lbas).min(l.max_lbas).min(DSM_MAX_LBAS);
    if max >= l.gran_lbas {
        max / l.gran_lbas * l.gran_lbas
    } else {
        max
    }
}

/// [`BlockDev::deallocate_all`] by DSM deallocate: one range per command, sized to the device's
/// [`BlockDev::dealloc_limits`] (per-range and per-command LBAs, granularity; e.g. the queue's discard_max_hw_bytes on
/// the kernel tier), kept outstanding up to the queue depth. A device without deallocate or any failed range is an
/// error. Returns the number of LBAs deallocated.
pub fn dsm_deallocate_all<D: BlockDev + ?Sized>(dev: &mut D) -> Result<u64, String> {
    dsm_deallocate_all_within(dev, DEALLOCATE_ALL_WAIT)
}

/// Bound of the wait for the next completion of a whole-namespace deallocate (mkfs, setup only). A device that stops
/// completing fails the format with a loud `WARNING TIMEOUT` instead of hanging it; a healthy controller has finished every command well before the Linux NVMe
/// driver's command timeout, which bounds a command that hangs it.
const DEALLOCATE_ALL_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// [`dsm_deallocate_all`] with an explicit drain bound (unit tests use a short one).
fn dsm_deallocate_all_within<D: BlockDev + ?Sized>(
    dev: &mut D,
    wait: std::time::Duration,
) -> Result<u64, String> {
    let g = dev.geometry();
    if !g.dealloc {
        return Err("device does not support deallocate".into());
    }
    let mut chunks = dsm_chunks(g.lba_count, dsm_chunk_lbas(&dev.dealloc_limits())).peekable();
    let mut out = Vec::new();
    let mut inflight = 0usize;
    // a simulated device completes at its own clock: poll at its next deadline so the queue progresses
    let mut now = 0;
    // the bound is on progress, not on the whole drain: a large namespace may take longer than `wait` in total
    let mut last = std::time::Instant::now();
    while chunks.peek().is_some() || inflight > 0 {
        while let Some(&(lba, nlba)) = chunks.peek() {
            if dev.queue_space() == 0 {
                break;
            }
            dev.submit_deallocate(&[(lba, nlba)], lba)
                .map_err(|e| format!("deallocate lba {lba} +{nlba}: {:?}", e.err))?;
            chunks.next();
            inflight += 1;
        }
        if let Some(d) = dev.next_deadline() {
            now = now.max(d);
        }
        out.clear();
        dev.poll(now, &mut out);
        if !out.is_empty() {
            last = std::time::Instant::now();
        } else if last.elapsed() >= wait {
            eprintln!(
                "WARNING TIMEOUT deallocate-all exceeded {}s without a completion ({inflight} deallocate commands in \
                 flight, device stopped completing)",
                wait.as_secs_f64()
            );
            return Err(format!(
                "deallocate-all did not complete: no completion within {}s, {inflight} commands in flight",
                wait.as_secs_f64()
            ));
        }
        for c in out.drain(..) {
            inflight -= 1;
            c.result
                .map_err(|e| format!("deallocate lba {}: {e:?}", c.tag))?;
        }
    }
    Ok(g.lba_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text_decodes_layout() {
        // sct 2 (media), sc 0x81, error bit 16, DNR bit 17
        assert_eq!(
            status_text(0x10000 | 0x20000 | (2 << 8) | 0x81, 17),
            "nvme status raw=0x30281 sct=2 sc=129 dnr=1"
        );
        assert!(status_text(0x10000 | 0x0007, 17).ends_with("dnr=0"));
    }

    fn geo(vwc: bool) -> Geometry {
        Geometry {
            lba_size: 4096,
            lba_count: 1,
            awupf_lbas: 1,
            awun_lbas: 1,
            vwc,
            max_xfer_lbas: 1,
            dealloc: true,
            write_zeroes: true,
        }
    }

    #[test]
    fn volatile_cache_forces_fua_on_writes() {
        assert_eq!(write_io_flags(&geo(true)), 1 << 30);
        assert_eq!(
            write_io_flags(&geo(false)),
            0,
            "PLP device: no flag, no cost"
        );
    }

    #[test]
    fn dsm_chunks_cover_range_at_the_32_bit_limit() {
        let m = DSM_MAX_LBAS;
        assert_eq!(dsm_chunks(0, m).count(), 0);
        assert_eq!(dsm_chunks(10, m).collect::<Vec<_>>(), [(0, 10)]);
        assert_eq!(dsm_chunks(m, m).collect::<Vec<_>>(), [(0, u32::MAX)]);
        assert_eq!(
            dsm_chunks(m + 1, u64::MAX).collect::<Vec<_>>(),
            [(0, u32::MAX), (m, 1)]
        );
        // five full chunks + a tail: contiguous, no gap, no overlap
        let n = 5 * m + 7;
        let v: Vec<_> = dsm_chunks(n, m).collect();
        assert_eq!(v.len(), 6);
        let mut next = 0;
        for (l, c) in v {
            assert_eq!(l, next);
            next += u64::from(c);
        }
        assert_eq!(next, n);
    }

    #[test]
    fn whole_device_chunks_fit_the_device_limits() {
        // PM1743 15.36 TB on the kernel tier: discard_max_hw_bytes 2^41 - 4096, 256 segments, granularity 32 MiB,
        // 4 KiB LBA; one 2^32-1 LBA range was rejected as Invalid by the limit check (croit-flashstore-tool prepare, 2026-11-03)
        let hw = ((1u64 << 41) - 4096) / 4096;
        let l = DeallocLimits::nvme(256, hw as u32, hw, 8192);
        let n = 3_750_232_064u64;
        let v: Vec<_> = dsm_chunks(n, dsm_chunk_lbas(&l)).collect();
        assert!(v.iter().all(|&(_, c)| l.check(&[(0, c)]).is_ok()));
        assert!(
            v.iter().all(|&(lba, _)| lba % 8192 == 0),
            "every range starts on the granularity"
        );
        assert_eq!(v.len(), 7);
        assert_eq!(v.iter().map(|&(_, c)| u64::from(c)).sum::<u64>(), n);
        // granularity rounds the chunk down, no limit = the 32-bit range maximum
        assert_eq!(dsm_chunk_lbas(&DeallocLimits::nvme(1, 1000, 1000, 64)), 960);
        assert_eq!(dsm_chunk_lbas(&DeallocLimits::DSM), DSM_MAX_LBAS);
        assert_eq!(dsm_chunk_lbas(&DeallocLimits::NONE), DSM_MAX_LBAS);
    }

    #[test]
    fn status_decode_is_one_policy() {
        assert_eq!(nvme_status_err(0x0281), IoError::Media);
        assert_eq!(nvme_status_err(0x0007), IoError::Aborted);
        assert_eq!(
            nvme_status_err(0x0008),
            IoError::Aborted,
            "aborted by SQ deletion"
        );
        assert_eq!(nvme_status_err(0x0107), IoError::Status(0x0107));
        assert_eq!(nvme_status_err(0x0002), IoError::Status(2));
    }

    #[test]
    fn errno_mapping_keeps_fs_errors_apart_from_media() {
        assert_eq!(errno_err(libc::ENOSPC), IoError::Errno(libc::ENOSPC));
        assert_eq!(errno_err(libc::EDQUOT), IoError::Errno(libc::EDQUOT));
        assert_eq!(errno_err(libc::EIO), IoError::Errno(libc::EIO));
        assert_eq!(errno_err(libc::EILSEQ), IoError::Media);
        assert_eq!(errno_err(libc::ETIMEDOUT), IoError::Aborted);
    }

    #[test]
    fn submit_errno_separates_shape_from_a_dead_queue() {
        assert_eq!(submit_errno(-12), SubmitError::QueueFull);
        assert_eq!(submit_errno(-22), SubmitError::Invalid);
        assert_eq!(submit_errno(-5), SubmitError::Dead);
    }

    #[test]
    fn check_io_enforces_the_one_shape_every_backend_shares() {
        let mut g = geo(false);
        g.lba_count = 16;
        g.max_xfer_lbas = 4;
        assert_eq!(g.check_io(0, 4), Ok(()));
        assert_eq!(g.check_io(12, 4), Ok(()));
        assert_eq!(g.check_io(13, 4), Err(SubmitError::OutOfRange));
        assert_eq!(g.check_io(0, 0), Err(SubmitError::Invalid));
        assert_eq!(
            g.check_io(0, 5),
            Err(SubmitError::Invalid),
            "above max_xfer_lbas"
        );
    }

    /// A device that completes only when the polled clock reaches a command's simulated deadline (the shape of the store's
    /// `SimDev`), and that can be told to never complete at all.
    struct ClockDev {
        geo: Geometry,
        inflight: Vec<(u64, u64)>,
        now: u64,
        completes: bool,
        /// LBAs per deallocate command (`None` = one DSM command covers the namespace).
        chunk: Option<u32>,
        /// Wall time each poll takes; non-zero = a slow but healthy device whose every other poll finds nothing.
        poll_sleep: std::time::Duration,
        polls: u32,
    }

    impl BlockDev for ClockDev {
        type Buf = Vec<u8>;
        fn geometry(&self) -> Geometry {
            self.geo
        }
        fn alloc_buf(&mut self, len: usize) -> Vec<u8> {
            vec![0; len]
        }
        fn queue_space(&self) -> usize {
            8 - self.inflight.len()
        }
        fn queue_depth(&self) -> usize {
            8
        }
        fn submit_write(&mut self, _lba: u64, buf: Vec<u8>, _tag: u64) -> Submit<Vec<u8>> {
            Err(Rejected::new(SubmitError::Unsupported, Some(buf)))
        }
        fn submit_read(&mut self, _lba: u64, buf: Vec<u8>, _tag: u64) -> Submit<Vec<u8>> {
            Err(Rejected::new(SubmitError::Unsupported, Some(buf)))
        }
        fn dealloc_limits(&self) -> DeallocLimits {
            match self.chunk {
                None => DeallocLimits::DSM,
                Some(n) => DeallocLimits {
                    max_ranges: 1,
                    range_lbas: n,
                    max_lbas: u64::from(n),
                    gran_lbas: 1,
                    via: "test",
                },
            }
        }
        fn submit_deallocate(&mut self, ranges: &[(u64, u32)], tag: u64) -> Submit<Vec<u8>> {
            let lba = ranges[0].0;
            self.inflight.push((tag, lba + 100));
            Ok(())
        }
        fn submit_write_zeroes(&mut self, _lba: u64, _nlba: u32, _tag: u64) -> Submit<Vec<u8>> {
            Err(Rejected::new(SubmitError::Unsupported, None))
        }
        fn poll(&mut self, now: Nanos, out: &mut Vec<Completion<Vec<u8>>>) -> usize {
            self.now = self.now.max(now);
            self.polls += 1;
            if !self.poll_sleep.is_zero() {
                std::thread::sleep(self.poll_sleep);
                if self.polls.is_multiple_of(2) {
                    return 0;
                }
            }
            let due = if self.completes { self.now } else { 0 };
            let n0 = out.len();
            self.inflight.retain(|&(tag, deadline)| {
                if deadline <= due {
                    out.push(Completion {
                        tag,
                        op: Op::Deallocate,
                        result: Ok(()),
                        buf: None,
                    });
                    false
                } else {
                    true
                }
            });
            out.len() - n0
        }
        fn next_deadline(&self) -> Option<Nanos> {
            self.inflight.iter().map(|&(_, d)| d).min()
        }
    }

    /// Run `f` on a worker thread: a hang fails the test instead of wedging the suite (the pre-fix behaviour).
    fn within<T: Send + 'static>(
        wait: std::time::Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(wait)
            .unwrap_or_else(|_| panic!("no result within {wait:?}"))
    }

    #[test]
    fn deallocate_all_drives_a_virtual_clock() {
        let mut d = ClockDev {
            geo: geo(true),
            inflight: Vec::new(),
            now: 0,
            completes: true,
            chunk: None,
            poll_sleep: std::time::Duration::ZERO,
            polls: 0,
        };
        d.geo.lba_count = 4096;
        let n = within(std::time::Duration::from_secs(10), move || {
            dsm_deallocate_all(&mut d)
        });
        assert_eq!(n, Ok(4096));
    }

    #[test]
    fn deallocate_all_times_out_on_a_device_that_stops_completing() {
        let mut d = ClockDev {
            geo: geo(true),
            inflight: Vec::new(),
            now: 0,
            completes: false,
            chunk: None,
            poll_sleep: std::time::Duration::ZERO,
            polls: 0,
        };
        d.geo.lba_count = 4096;
        let e = within(std::time::Duration::from_secs(10), move || {
            dsm_deallocate_all_within(&mut d, std::time::Duration::from_millis(50)).unwrap_err()
        });
        assert!(e.contains("did not complete"), "{e}");
    }

    #[test]
    fn deallocate_all_bounds_progress_not_the_whole_drain() {
        // 8 commands completing one per second poll, every poll takes 20 ms: ~320 ms in total, longer than the 50 ms bound,
        // yet the device never stalls for 50 ms
        let mut d = ClockDev {
            geo: geo(true),
            inflight: Vec::new(),
            now: 0,
            completes: true,
            chunk: Some(512),
            poll_sleep: std::time::Duration::from_millis(20),
            polls: 0,
        };
        d.geo.lba_count = 4096;
        let n = within(std::time::Duration::from_secs(10), move || {
            dsm_deallocate_all_within(&mut d, std::time::Duration::from_millis(50))
        });
        assert_eq!(n, Ok(4096));
    }
}
