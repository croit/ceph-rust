// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! libibverbs data path (feature `verbs`, Linux).
//!
//! Split by thread (0469-rdma-transport): control calls (device open, MR registration, CQ/SRQ/QP create, connect,
//! destroy) are blocking ioctls and run on a control thread: [`Device`], [`Core::new`], [`Qp`]. A data-path core owns
//! one [`Core`] and drives it from a single thread: the send calls ([`Core::send`], [`Core::send_bytes`],
//! [`Core::write`]), the CQ polls ([`Core::poll`], [`Core::poll_flow`]) and the connection bookkeeping
//! ([`Core::attach`], [`Core::detach`], [`Core::fence`]). Those post work requests and poll the CQ (no syscalls, no
//! locks, no allocation after warm-up).
//!
//! Send progress follows [`crate::tx`]: every send slot handed to the HCA comes back within one completion round trip
//! once the sender stops posting (I1), and a connection refused for lack of send slots gets [`Event::Writable`] when
//! slots come free from any connection of the core (I2, FIFO).
use crate::credit::MIN_WINDOW;
use crate::fence::{Fence, Step};
use crate::grant::{GrantCfg, GrantStats, Permit, Pool, Sid, TICK};
use crate::hold::{Flow, Hold};
use crate::memory::{MemoryRange, registration_ranges};
use crate::provider;
use crate::qpn::QpnMap;
#[cfg(feature = "memory-windows")]
use crate::ring::NO_SLOT;
use crate::tx::{Pos, Seg, Sender, Sent, Stall, Tx, Wr};
use crate::{Endpoint, Release};
use bytes::{Buf, Bytes};
use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::io::{self, IoSlice};
use std::os::fd::RawFd;
use std::sync::Arc;

#[cfg(feature = "gpu")]
pub(crate) use ffi::Opaque;

mod destination;
#[cfg(feature = "memory-windows")]
mod read;
#[cfg(feature = "memory-windows")]
mod read_limits;
#[cfg(all(test, feature = "memory-windows"))]
mod read_upgrade_tests;
#[cfg(feature = "memory-windows")]
mod receipt;
#[cfg(feature = "memory-windows")]
mod write;
pub use destination::{
    DestinationRegistrationError, ForeignDestinationRegistrationError, HostDestination,
    UnboundWindow, WindowAllocationError,
};
#[cfg(feature = "memory-windows")]
pub use read::{
    PendingReadBuffer, PreparedReadBuffer, ReadBufferPostError, ReadHandle, ReadPostError,
    ReadState, ReadTarget, RemoteReadSource, SharedReadBuffer, quarantined_read_targets,
};
#[cfg(feature = "memory-windows")]
pub use read_limits::{ReadDepths, ReadLimits};

#[cfg(feature = "memory-windows")]
pub use destination::{
    AdvertisedReadSource, AdvertisedSharedReadSource, AdvertisedWindow, LocalReadSource,
    LocalSharedReadSource, LocalWindow, PreparedReadSource, ReadSourceDescriptor, ReadSourcePool,
    ReadSourcePoolReturnError, ReadSourcePoolTicket, ReadSourceRegistrationError, ReadVerification,
    ReleaseHook, RetainedRange, SharedHostRegistration, SharedReadSourceBindError,
    SharedRegistrationRejected, SharedReleaseError, WindowAttempt, WindowBindError,
    WindowDescriptor, WindowState, quarantined_windows,
};
#[cfg(feature = "memory-windows")]
pub use receipt::{ReadReceipt, RetirementKind, RetirementRecord};
#[cfg(feature = "memory-windows")]
pub use write::{
    AdvertisedWriteBuffer, LocalWriteBuffer, PlacedReadWrite, PreparedWriteBuffer,
    RemoteWriteTarget, SharedWriteBuffer, WriteBufferBindError, WriteHandle, WritePostError,
    WriteSource, WriteSourceRegistrationError, WriteSourcesRegistrationError, WriteState,
    quarantined_write_sources,
};

/// Placement is uncompiled in ordinary transport builds, so it cannot own a quarantined window.
#[cfg(not(feature = "memory-windows"))]
pub fn quarantined_windows() -> u64 {
    0
}

/// Placement is uncompiled in ordinary transport builds, so it cannot own a quarantined WRITE source.
#[cfg(not(feature = "memory-windows"))]
pub fn quarantined_write_sources() -> u64 {
    0
}

/// A failed provider post has already faulted the connection. Preserve its errno
/// as the cause without exposing a retryable admission error to the caller.
#[cfg(feature = "memory-windows")]
fn post_failure(rc: c_int) -> io::Error {
    debug_assert!(rc < 0);
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        io::Error::from_raw_os_error(-rc),
    )
}

mod ffi {
    use super::*;
    #[repr(C)]
    pub struct Opaque {
        _p: [u8; 0],
    }
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Wc {
        pub wr_id: u64,
        pub status: u32,
        pub opcode: u32,
        pub byte_len: u32,
        pub flags: u32,
        pub imm: u32,
        pub qp_num: u32,
        pub vendor_err: u32,
        pub pad: u32,
    }
    /// `struct rv_send` of shim.c: one SEND_WITH_IMM with up to two SGEs.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct SendWr {
        pub wr_id: u64,
        pub addr: [u64; 2],
        pub len: [u32; 2],
        pub lkey: [u32; 2],
        pub imm: u32,
        /// 1 signaled, 2 inline
        pub flags: u32,
        pub nsge: u32,
        pub pad: u32,
    }
    /// `struct rv_recv` of shim.c.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RecvWr {
        pub wr_id: u64,
        pub addr: u64,
        pub len: u32,
        pub lkey: u32,
    }
    unsafe extern "C" {
        #[cfg(test)]
        pub fn rv_posted_prefix(
            first: *const Opaque,
            stride: usize,
            n: c_int,
            bad: *const Opaque,
        ) -> c_int;
        pub fn rv_open_gid(gid: *const u8) -> *mut Opaque;
        pub fn rv_close(d: *mut Opaque);
        pub fn rv_name(d: *mut Opaque) -> *const c_char;
        pub fn rv_active_mtu(d: *mut Opaque) -> c_int;
        pub fn rv_type2_mw_probe(d: *mut Opaque) -> c_int;
        pub fn rv_alloc_window(d: *mut Opaque) -> *mut Opaque;
        pub fn rv_dealloc_window(mw: *mut Opaque) -> c_int;
        #[cfg(feature = "memory-windows")]
        pub fn rv_post_window_bind(
            qp: *mut Opaque,
            mw: *mut Opaque,
            mr: *mut Opaque,
            id: u64,
            addr: u64,
            len: u64,
            read_only: c_int,
        ) -> c_int;
        #[cfg(feature = "memory-windows")]
        pub fn rv_post_window_invalidate(qp: *mut Opaque, mw: *mut Opaque, id: u64) -> c_int;
        #[cfg(feature = "memory-windows")]
        pub fn rv_post_send_invalidate(qp: *mut Opaque, id: u64, rkey: u32) -> c_int;
        #[cfg(feature = "memory-windows")]
        pub fn rv_post_write(
            qp: *mut Opaque,
            id: u64,
            source: u64,
            length: u32,
            lkey: u32,
            target: u64,
            rkey: u32,
        ) -> c_int;
        #[cfg(feature = "memory-windows")]
        pub fn rv_post_read(
            qp: *mut Opaque,
            id: u64,
            target: u64,
            length: u32,
            lkey: u32,
            source: u64,
            rkey: u32,
        ) -> c_int;
        #[cfg(all(test, feature = "fault-inject", feature = "memory-windows"))]
        pub fn rv_test_read_source(d: *mut Opaque, addr: *const c_void, len: u64) -> *mut Opaque;
        #[cfg(all(test, feature = "fault-inject", feature = "memory-windows"))]
        pub fn rv_test_mr_rkey(mr: *mut Opaque) -> u32;
        #[cfg(feature = "memory-windows")]
        pub fn rv_window_rkey(mw: *mut Opaque) -> u32;
        pub fn rv_reg(d: *mut Opaque, addr: *mut c_void, len: u64) -> *mut Opaque;
        pub fn rv_reg_destination(d: *mut Opaque, addr: *mut c_void, len: u64) -> *mut Opaque;
        #[cfg(feature = "memory-windows")]
        pub fn rv_reg_read_window_source(
            d: *mut Opaque,
            addr: *const c_void,
            len: u64,
        ) -> *mut Opaque;
        pub fn rv_dereg(m: *mut Opaque) -> c_int;
        pub fn rv_lkey(m: *mut Opaque) -> u32;
        #[cfg(feature = "gpu")]
        pub fn rv_reg_dmabuf(
            d: *mut Opaque,
            fd: c_int,
            offset: u64,
            iova: u64,
            len: u64,
            access: c_int,
        ) -> *mut Opaque;
        #[cfg(feature = "gpu")]
        pub fn rv_reg_access(
            d: *mut Opaque,
            addr: *mut c_void,
            len: u64,
            access: c_int,
        ) -> *mut Opaque;
        #[cfg(feature = "gpu")]
        pub fn rv_rkey(m: *mut Opaque) -> u32;
        #[cfg(feature = "gpu")]
        pub fn rv_mr_addr(m: *mut Opaque) -> u64;
        #[cfg(feature = "gpu")]
        pub fn rv_mr_len(m: *mut Opaque) -> u64;
        pub fn rv_comp_vectors(d: *mut Opaque) -> c_int;
        pub fn rv_max_cqe(d: *mut Opaque) -> c_int;
        pub fn rv_cq(d: *mut Opaque, depth: c_int, vec: c_int) -> *mut Opaque;
        pub fn rv_cq_destroy(c: *mut Opaque) -> c_int;
        pub fn rv_cq_fd(c: *mut Opaque) -> c_int;
        pub fn rv_cq_arm(c: *mut Opaque) -> c_int;
        pub fn rv_cq_ack(c: *mut Opaque) -> c_int;
        pub fn rv_cq_ack_events(c: *mut Opaque, n: u32);
        pub fn rv_srq(d: *mut Opaque, depth: c_int) -> *mut Opaque;
        pub fn rv_srq_destroy(q: *mut Opaque) -> c_int;
        pub fn rv_qp(
            d: *mut Opaque,
            cq: *mut Opaque,
            srq: *mut Opaque,
            sq: c_int,
            inl: *mut u32,
            sge: *mut u32,
            read_access: c_int,
        ) -> *mut Opaque;
        pub fn rv_qp_destroy(q: *mut Opaque) -> c_int;
        pub fn rv_qp_num(q: *mut Opaque) -> u32;
        pub fn rv_qp_connect(
            d: *mut Opaque,
            q: *mut Opaque,
            rqpn: u32,
            rgid: *const u8,
            rpsn: u32,
            lpsn: u32,
            mtu: c_int,
            timeout: c_int,
            retry: c_int,
            rnr: c_int,
            tclass: c_int,
            read_out: u8,
            read_in: u8,
            rtr: *mut c_int,
        ) -> c_int;
        #[cfg(feature = "memory-windows")]
        pub fn rv_read_limits(
            d: *mut Opaque,
            init: *mut c_int,
            response: *mut c_int,
            sge: *mut c_int,
        ) -> c_int;
        #[cfg(feature = "memory-windows")]
        pub fn rv_qp_read_depths(q: *mut Opaque, outgoing: *mut u8, incoming: *mut u8) -> c_int;
        pub fn rv_qp_err(q: *mut Opaque) -> c_int;
        pub fn rv_async_wait(d: *mut Opaque, stop: c_int) -> c_int;
        pub fn rv_async_next(d: *mut Opaque, ty: *mut c_int, qpn: *mut u32) -> c_int;
        pub fn rv_async_ack(d: *mut Opaque);
        pub fn rv_gid_index(d: *mut Opaque) -> c_int;
        pub fn rv_event_str(ty: c_int) -> *const c_char;
        pub fn rv_efd() -> c_int;
        pub fn rv_efd_signal(fd: c_int);
        pub fn rv_fd_close(fd: c_int);
        pub fn rv_post_send(
            q: *mut Opaque,
            wr_id: u64,
            addr: u64,
            len: u32,
            lkey: u32,
            imm: u32,
            signaled: c_int,
            inl: c_int,
        ) -> c_int;
        pub fn rv_post_send_list(
            q: *mut Opaque,
            w: *const SendWr,
            n: c_int,
            posted: *mut c_int,
        ) -> c_int;
        pub fn rv_post_srq_recv_list(
            q: *mut Opaque,
            w: *const RecvWr,
            n: c_int,
            posted: *mut c_int,
        ) -> c_int;
        pub fn rv_poll(c: *mut Opaque, out: *mut Wc, n: c_int) -> c_int;
        pub fn rv_wc_str(status: c_int) -> *const c_char;
    }
}

/// Provider resource teardown failures in this process (each is also logged).
static TEARDOWN_FAILURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Refused QP teardown while a local window still pins it, or failed QP/CQ/SRQ/MR teardown calls.
/// Resources whose retirement cannot be proved stay allocated. Nonzero indicates an ownership-order bug
/// or provider failure; the control thread and its QPs must end before the core.
pub fn teardown_failures() -> u64 {
    TEARDOWN_FAILURES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Cores left allocated by [`Core::leak`] in this process.
static LEAKED_CORES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Cores whose CQ, SRQ and arenas were left allocated because their owner could not confirm that no other QP used them
/// any more ([`Core::leak`]). Nonzero = a control thread hung at a teardown; memory is lost, nothing is corrupted.
pub fn leaked_cores() -> u64 {
    LEAKED_CORES.load(std::sync::atomic::Ordering::Relaxed)
}

fn os_err(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// Register a DMA-BUF region as an MR (GPUDirect RDMA, adr 0665). Control call. `access` is the ibv bitmask; `iova` is
/// the address a peer uses. Fails with `EOPNOTSUPP` when the provider cannot register DMA-BUF memory.
#[cfg(feature = "gpu")]
pub(crate) fn dmabuf_register(
    dev: &Device,
    fd: RawFd,
    offset: u64,
    iova: u64,
    len: u64,
    access: c_int,
) -> io::Result<*mut ffi::Opaque> {
    // SAFETY: valid device; the shim forwards to ibv_reg_dmabuf_mr, which pins the dmabuf and returns a new MR.
    let mr = unsafe { ffi::rv_reg_dmabuf(dev.p, fd, offset, iova, len, access) };
    if mr.is_null() {
        return Err(os_err("ibv_reg_dmabuf_mr"));
    }
    Ok(mr)
}

/// Register host memory with explicit access bits (the GPU mock: a host region stands in for device memory).
#[cfg(feature = "gpu")]
pub(crate) fn mr_register_access(
    dev: &Device,
    addr: *mut c_void,
    len: u64,
    access: c_int,
) -> io::Result<*mut ffi::Opaque> {
    // SAFETY: the caller owns `addr..addr+len` for the registration lifetime; the shim forwards to ibv_reg_mr.
    let mr = unsafe { ffi::rv_reg_access(dev.p, addr, len, access) };
    if mr.is_null() {
        return Err(os_err("ibv_reg_mr (GPU mock)"));
    }
    Ok(mr)
}

/// Keys, address and length of an MR (control call, valid until deregistration).
#[cfg(feature = "gpu")]
pub(crate) unsafe fn mr_identity(mr: *mut ffi::Opaque) -> (u32, u32, u64, u64) {
    // SAFETY: caller holds a live MR.
    unsafe {
        (
            ffi::rv_lkey(mr),
            ffi::rv_rkey(mr),
            ffi::rv_mr_addr(mr),
            ffi::rv_mr_len(mr),
        )
    }
}

/// Deregister an MR; returns 0 or the provider errno (negative).
#[cfg(feature = "gpu")]
pub(crate) unsafe fn mr_deregister(mr: *mut ffi::Opaque) -> c_int {
    // SAFETY: caller holds the last reference to the MR.
    unsafe { ffi::rv_dereg(mr) }
}

/// Account a failed teardown and print the loud line (same rule as the arenas).
#[cfg(feature = "gpu")]
pub(crate) fn teardown_failure(message: std::fmt::Arguments<'_>) {
    TEARDOWN_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    report_teardown(message);
}

/// Teardown must not unwind before retaining uncertain resources if stderr is closed or nonblocking.
fn report_teardown(message: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let _ = writeln!(io::stderr().lock(), "{message}");
}

/// One RDMA device + port + RoCEv2 GID + protection domain. libibverbs objects are thread-safe (rdma-core), so the
/// handle is shared between the control thread and the cores.
#[derive(Debug)]
pub struct Device {
    p: *mut ffi::Opaque,
    gid: [u8; 16],
    fatal: std::sync::atomic::AtomicBool,
}

// SAFETY: libibverbs contexts and PDs may be used from any thread (rdma-core thread-safety guarantee); the pointer is
// only freed in Drop, after every Arc holder is gone.
unsafe impl Send for Device {}
// SAFETY: see Send; all calls through `p` are thread-safe verbs.
unsafe impl Sync for Device {}

/// Port active MTU too small for RDMA (RoCE path MTU >= [`crate::MIN_PATH_MTU`] is required, 0470-rdma-ops).
pub const ERR_MTU: &str = "RoCE active MTU below 1024";

impl Device {
    /// Device whose port carries the RoCEv2 GID `gid` (the msgr2 TCP local address). Control call. Fails with
    /// [`ERR_MTU`] when the port's active MTU is below [`crate::MIN_PATH_MTU`], with `AddrNotAvailable` when the host
    /// has RoCE ports but none carries the GID (the address is not configured now; it may be later), with `ENODEV` when
    /// it has no RoCE port at all.
    pub fn open(gid: [u8; 16]) -> io::Result<Arc<Device>> {
        // SAFETY: `gid` is 16 readable bytes; the returned pointer is owned by the Device.
        let p = unsafe { ffi::rv_open_gid(gid.as_ptr()) };
        if p.is_null() {
            return Err(os_err("no RDMA port with this RoCEv2 GID"));
        }
        let d = Device {
            p,
            gid,
            fatal: std::sync::atomic::AtomicBool::new(false),
        };
        // SAFETY: valid device handle
        if d.active_mtu() < crate::MIN_PATH_MTU {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{}: {ERR_MTU}", d.name()),
            ));
        }
        Ok(Arc::new(d))
    }

    /// Active MTU of the port in bytes (256, 512, 1024, 2048 or 4096; 128 when the port reports none, which
    /// [`Device::open`] refuses).
    pub fn active_mtu(&self) -> u32 {
        // SAFETY: valid device handle; rv_active_mtu returns an enum ibv_mtu (1 = 256 .. 5 = 4096)
        let e = unsafe { ffi::rv_active_mtu(self.p) };
        128u32 << e.clamp(0, 5) as u32
    }

    /// A fatal shared-resource async event invalidates completion ownership on
    /// this device; every core must stop using it and notify its sessions.
    pub(crate) fn failed(&self) -> bool {
        self.fatal.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Probe type-2 MW availability by allocating and releasing a real provider window. Control-plane call only.
    /// Returns `Ok(false)` when the provider explicitly reports the operation unsupported. Resource or teardown errors
    /// are returned so a transient allocation failure cannot silently disable a requested placement configuration.
    pub fn probe_type2_mw(&self) -> io::Result<bool> {
        // SAFETY: a valid device handle; the shim allocates and releases one temporary type-2 MW in this PD.
        match unsafe { ffi::rv_type2_mw_probe(self.p) } {
            1 => Ok(true),
            0 => Ok(false),
            e => Err(io::Error::from_raw_os_error(-e)),
        }
    }

    pub fn name(&self) -> String {
        // SAFETY: rv_name returns a NUL-terminated string inside the device struct, alive as long as `self`.
        unsafe { CStr::from_ptr(ffi::rv_name(self.p)) }
            .to_string_lossy()
            .into_owned()
    }

    pub fn gid(&self) -> [u8; 16] {
        self.gid
    }

    /// Index of [`Device::gid`] in the port's GID table now (control call). The kernel rebuilds the table when the
    /// netdev's addresses change, so the index of the open is never trusted: one query confirms it, a changed table is
    /// scanned again (`rv_qp_connect` does the same before every RTR). `AddrNotAvailable`: the GID is not on the port
    /// (the local address is gone); RDMA connects fail until it is back.
    pub fn gid_index(&self) -> io::Result<u32> {
        // SAFETY: valid device handle
        let rc = unsafe { ffi::rv_gid_index(self.p) };
        if rc < 0 {
            return Err(io::Error::from_raw_os_error(-rc));
        }
        Ok(rc as u32)
    }

    /// Completion vectors (interrupt lines) of the device, at least 1.
    pub fn comp_vectors(&self) -> u32 {
        // SAFETY: valid device handle
        unsafe { ffi::rv_comp_vectors(self.p) }.max(1) as u32
    }

    /// Maximum CQ entries reported by this provider at device open.
    pub fn max_cqe(&self) -> u32 {
        // SAFETY: valid device handle; immutable ibv_query_device result.
        unsafe { ffi::rv_max_cqe(self.p) }.max(0) as u32
    }
}

/// The async-event thread of a device (control plane): reads the device's async event channel and reports every
/// `IBV_EVENT_QP_LAST_WQE_REACHED` by QP number to `last_wqe` (an SRQ QP moved to ERR consumes no receive WQE any more and
/// the completions of the ones it consumed are in the CQ: the owning core drains the CQ, then the QP may be destroyed).
/// CQ/SRQ/device-fatal events permanently fail the device and wake its cores; shared resource ownership can no
/// longer be proved. Other events are logged (`COMM_EST` is not: the first SEND on an RTR QP; `GID table change` is: the GID index is
/// re-resolved at every connect, [`Device::gid_index`]). Every event is acknowledged right after `last_wqe` returned
/// (`ibv_destroy_qp` waits for the acknowledgements of its QP's events: once a destroy returned, every event of that QP has
/// been reported). A broken channel is logged: without it no last-WQE event arrives any more, so every later teardown of
/// one of this device's QPs runs into its drain limit. Dropping it stops and joins the thread.
#[derive(Debug)]
pub struct AsyncEvents {
    stop: c_int,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl AsyncEvents {
    /// Start the thread: `last_wqe` gets each last-WQE QP number, `fatal` runs once per fatal event, after the device
    /// is marked failed ([`Device::failed`]) and before the event is acknowledged.
    pub fn start(
        dev: Arc<Device>,
        last_wqe: impl Fn(u32) + Send + 'static,
        fatal: impl Fn() + Send + 'static,
    ) -> io::Result<AsyncEvents> {
        // SAFETY: plain eventfd
        let stop = unsafe { ffi::rv_efd() };
        if stop < 0 {
            return Err(io::Error::from_raw_os_error(-stop));
        }
        let thread = std::thread::Builder::new()
            .name("rdma-async".into())
            .spawn(move || {
                let run = provider::async_events(
                    // SAFETY: valid device (Arc held by this thread), `stop` stays open until the thread is joined
                    || unsafe { ffi::rv_async_wait(dev.p, stop) },
                    // SAFETY: valid device; out pointers are valid
                    |ty, qpn| unsafe { ffi::rv_async_next(dev.p, ty, qpn) },
                    // SAFETY: valid device; an event was read (rc 1, 2 or 3) and not acknowledged yet
                    || unsafe { ffi::rv_async_ack(dev.p) },
                    last_wqe,
                    |ty, qpn, resource_failed| {
                        if resource_failed {
                            dev.fatal.store(true, std::sync::atomic::Ordering::Release);
                            fatal();
                            report_teardown(format_args!(
                                "WARNING rdma: {}: fatal async event: every RDMA session of the device faults, new connections stay TCP until restart",
                                dev.name()
                            ));
                        }
                        if ty != COMM_EST {
                            // SAFETY: static string of libibverbs
                            let what = unsafe { CStr::from_ptr(ffi::rv_event_str(ty)) };
                            report_teardown(format_args!(
                                "rdma: {}: async event {} (qp {qpn})",
                                dev.name(),
                                what.to_string_lossy()
                            ));
                        }
                    },
                );
                if let Err(e) = run {
                    report_teardown(format_args!(
                        "rdma: {}: async event channel failed: {e} (no event arrives any more: QP teardowns run into their drain limit)",
                        dev.name()
                    ));
                }
            });
        match thread {
            Ok(t) => Ok(AsyncEvents {
                stop,
                thread: Some(t),
            }),
            Err(e) => {
                // SAFETY: our eventfd, no thread uses it
                unsafe { ffi::rv_fd_close(stop) };
                Err(e)
            }
        }
    }
}

/// `IBV_EVENT_COMM_EST`.
const COMM_EST: c_int = 8;

impl Drop for AsyncEvents {
    fn drop(&mut self) {
        // SAFETY: our eventfd
        unsafe { ffi::rv_efd_signal(self.stop) };
        if let Some(t) = self.thread.take()
            && t.join().is_err()
        {
            diag::diag!("rdma: async event thread panicked");
        }
        // SAFETY: the thread is gone
        unsafe { ffi::rv_fd_close(self.stop) };
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: last reference; every MR/CQ/SRQ/QP holds an Arc<Device> and is destroyed first.
        unsafe { ffi::rv_close(self.p) }
    }
}

/// Page-aligned buffer of `n` slots of `slot` bytes, registered for local access.
#[derive(Debug)]
struct Arena {
    _dev: Arc<Device>,
    base: *mut u8,
    layout: std::alloc::Layout,
    mr: *mut ffi::Opaque,
    lkey: u32,
    slot: u32,
    /// A core could not retire every provider user: leave this MR and allocation intact on drop.
    retain: bool,
    #[cfg(test)]
    dereg_error: Option<c_int>,
}

impl Arena {
    fn new(dev: &Arc<Device>, n: u32, slot: u32) -> io::Result<Arena> {
        let len = n as usize * slot as usize;
        let layout = std::alloc::Layout::from_size_align(len.max(4096), 4096)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: non-zero size layout
        let base = unsafe { std::alloc::alloc_zeroed(layout) };
        if base.is_null() {
            return Err(io::Error::from(io::ErrorKind::OutOfMemory));
        }
        // SAFETY: [base, base+len) is allocated and outlives the MR (deregistered in Drop before dealloc)
        let mr = unsafe { ffi::rv_reg(dev.p, base.cast(), len as u64) };
        if mr.is_null() {
            let e = os_err("ibv_reg_mr (RLIMIT_MEMLOCK?)");
            // SAFETY: allocated above with `layout`
            unsafe { std::alloc::dealloc(base, layout) };
            return Err(e);
        }
        Ok(Arena {
            _dev: dev.clone(),
            base,
            layout,
            mr,
            // SAFETY: valid MR
            lkey: unsafe { ffi::rv_lkey(mr) },
            slot,
            retain: false,
            #[cfg(test)]
            dereg_error: None,
        })
    }

    fn addr(&self, i: u32) -> u64 {
        self.base as u64 + i as u64 * self.slot as u64
    }

    /// # Safety
    /// The slot must not be owned by the HCA (not posted, or its WR completed).
    unsafe fn slice_mut(&mut self, i: u32, len: usize) -> &mut [u8] {
        // a length the provider reported is checked before it gets here ([`crate::provider::recv_len`])
        debug_assert!(len <= self.slot as usize, "slice beyond its arena slot");
        // SAFETY: caller guarantees exclusive CPU ownership; i < n and len <= slot by construction
        unsafe {
            std::slice::from_raw_parts_mut(self.base.add(i as usize * self.slot as usize), len)
        }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        if !self.retain {
            // SAFETY: the core retired the QPs and SRQ using this arena before dropping it.
            let rc = unsafe { ffi::rv_dereg(self.mr) };
            #[cfg(test)]
            let rc = self.dereg_error.take().unwrap_or(rc);
            if rc == 0 {
                // SAFETY: no provider registration or user remains; allocated with this layout.
                unsafe { std::alloc::dealloc(self.base, self.layout) };
                return;
            }
            TEARDOWN_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            report_teardown(format_args!(
                "rdma: arena deregistration failed: {} (backing retained)",
                io::Error::from_raw_os_error(rc.abs())
            ));
        }
        // Keep the provider context, MR and allocation alive when retirement is uncertain.
        std::mem::forget(self._dev.clone());
    }
}

/// Caller memory registered with the device once at start (the payload hugepage heap): SENDs of stream bytes inside it
/// post an SGE that points at the bytes ([`Core::send_bytes`], zero copy) instead of copying them into the send arena.
/// Local access only: no rkey is ever handed out (design D2). Never registered per op.
#[derive(Debug)]
pub struct ZcMem {
    _dev: Arc<Device>,
    /// (checked range, lkey, MR), sorted by start, non-overlapping.
    regions: Vec<(MemoryRange, u32, *mut ffi::Opaque)>,
    /// Owned caller memory, when registered through `register_owned`. Dropped after MR deregistration.
    owner: Option<Bytes>,
    #[cfg(feature = "memory-windows")]
    read_windows: bool,
}

// SAFETY: MR handles are thread-safe verbs objects; lookups only read `regions`, dereg runs in Drop with the last Arc.
unsafe impl Send for ZcMem {}
// SAFETY: see Send.
unsafe impl Sync for ZcMem {}

impl ZcMem {
    /// Register permanently mapped host `(addr, len)` ranges. Control call. Overlapping, null, empty or overflowing
    /// ranges are refused before registering any MR. An empty list is a valid disabled registration.
    ///
    /// # Safety
    /// Every range must be initialized host memory that remains mapped at that address until process exit (including
    /// after a refused deregistration). A posted source must remain immutable until its SENDs/WRITEs retire or the QP is destroyed.
    /// Use [`Self::register_owned`] for application allocations whose lifetime is not permanent.
    pub unsafe fn register(dev: &Arc<Device>, ranges: &[(u64, u64)]) -> io::Result<Arc<ZcMem>> {
        Self::register_ranges(dev, ranges, None, false)
    }

    /// Register immutable host memory and retain its allocation until deregistration. Control call, not per SEND.
    /// No address cache: the registration owns `data`, including after the application drops its references. Empty
    /// data is rejected. GPU memory is not representable by `Bytes` and is not supported by this API.
    pub fn register_owned(dev: &Arc<Device>, data: Bytes) -> io::Result<Arc<ZcMem>> {
        let ranges = [(data.as_ptr() as u64, data.len() as u64)];
        Self::register_ranges(dev, &ranges, Some(data), false)
    }

    /// Cold-register permanent host source arenas with MW_BIND permission.
    /// This only prepares parent MRs; it does not create windows or authorize
    /// a remote peer. Source pieces must remain owned and immutable until the
    /// READ grant and all peer accesses have safely retired.
    ///
    /// # Safety
    /// The initialized host mappings must remain mapped until process exit,
    /// including after failed provider deregistration. This is not a GPU API.
    #[cfg(feature = "memory-windows")]
    pub unsafe fn register_read_windows(
        dev: &Arc<Device>,
        ranges: &[(u64, u64)],
    ) -> io::Result<Arc<ZcMem>> {
        Self::register_ranges(dev, ranges, None, true)
    }

    fn register_ranges(
        dev: &Arc<Device>,
        ranges: &[(u64, u64)],
        owner: Option<Bytes>,
        read_windows: bool,
    ) -> io::Result<Arc<ZcMem>> {
        let sorted = registration_ranges(ranges)?;
        let mut m = ZcMem {
            _dev: dev.clone(),
            regions: Vec::with_capacity(sorted.len()),
            owner,
            #[cfg(feature = "memory-windows")]
            read_windows,
        };
        for range in sorted {
            // SAFETY: register requires permanent host backing; register_owned retains immutable `Bytes` in `owner`.
            // Numeric bounds of every range were checked before the first provider call.
            let mr = if read_windows {
                #[cfg(feature = "memory-windows")]
                {
                    // SAFETY: permanent initialized mapping is required by the caller.
                    unsafe {
                        ffi::rv_reg_read_window_source(
                            dev.p,
                            range.address() as *const c_void,
                            range.length(),
                        )
                    }
                }
                #[cfg(not(feature = "memory-windows"))]
                unreachable!("READ-window registration requires memory-windows")
            } else {
                // SAFETY: the original registration contracts retain this mapping.
                unsafe { ffi::rv_reg(dev.p, range.address() as *mut c_void, range.length()) }
            };
            if mr.is_null() {
                return Err(os_err("ibv_reg_mr of the payload heap (RLIMIT_MEMLOCK?)"));
            }
            // SAFETY: valid MR
            let lkey = unsafe { ffi::rv_lkey(mr) };
            m.regions.push((range, lkey, mr));
        }
        Ok(Arc::new(m))
    }

    /// lkey of the region that holds all of `[addr, addr + len)`.
    pub fn lkey(&self, addr: u64, len: usize) -> Option<u32> {
        let i = self
            .regions
            .partition_point(|r| r.0.address() <= addr)
            .checked_sub(1)?;
        let (range, lkey, _) = self.regions[i];
        range.contains(addr, len as u64).then_some(lkey)
    }

    /// Registered bytes.
    pub fn bytes(&self) -> u64 {
        self.regions.iter().map(|r| r.0.length()).sum()
    }

    pub fn regions(&self) -> usize {
        self.regions.len()
    }
}

impl Drop for ZcMem {
    fn drop(&mut self) {
        let mut failed = false;
        for r in &self.regions {
            // SAFETY: valid MR; the last Arc is gone, so no core and no detached QP can post with it any more
            let rc = unsafe { ffi::rv_dereg(r.2) };
            if rc != 0 {
                failed = true;
                TEARDOWN_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                report_teardown(format_args!(
                    "rdma: payload MR deregistration failed (code {rc}); backing and device retained"
                ));
            }
        }
        if failed {
            // A refused deregistration must not leave an MR over freed/reused pages. Permanent ranges remain mapped
            // by register's unsafe contract; owned allocations and the PD/context stay alive here as well.
            if let Some(owner) = self.owner.take() {
                std::mem::forget(owner);
            }
            std::mem::forget(self._dev.clone());
        }
    }
}

/// Per-core sizing.
#[derive(Clone, Copy, Debug)]
pub struct CoreCfg {
    /// SRQ depth = receive slots of the core; the sum of the credits granted to all sessions never exceeds it.
    pub srq_depth: u32,
    /// Receive slot size = largest SEND the peer may post (advertised in [`Endpoint::slot`]).
    pub slot: u32,
    /// Send slots of the core (copy targets of outgoing stream bytes).
    pub tx_slots: u32,
    /// Largest receive window one session may hold (sessions start at [`crate::credit::MIN_WINDOW`], [`crate::grant`]).
    pub max_window: u32,
    /// Optional bound on QPs this core may adopt. The CQ and grant pool reserve
    /// for this many sessions, never for more than the SRQ can admit.
    pub session_limit: Option<u32>,
    /// Send queue depth per QP.
    pub sq_depth: u32,
    /// Requested inline size (granted size may be smaller).
    pub inline: u32,
    /// Completion vector of the core's CQ, taken modulo the device's vectors: give each core of a process its own index so
    /// the cores' completion events spread over the device's interrupt lines instead of all using vector 0.
    pub comp_vector: u32,
    /// IPv4 TOS of the RoCEv2 packets (fixed, hwcheck `RDMA_DEFAULT_TOS`).
    pub tos: u8,
    /// Local ACK timeout exponent, retry count, RNR retry count (ibv_modify_qp(3)).
    pub timeout: u8,
    pub retry: u8,
    pub rnr_retry: u8,
}

impl Default for CoreCfg {
    fn default() -> Self {
        CoreCfg {
            srq_depth: 4096,
            slot: crate::DEFAULT_SLOT,
            tx_slots: 4096,
            max_window: crate::DEFAULT_MAX_WINDOW,
            session_limit: None,
            sq_depth: 256,
            inline: 256,
            comp_vector: 0,
            tos: 106,
            timeout: 14,
            retry: 7,
            rnr_retry: 6,
        }
    }
}

impl CoreCfg {
    /// Sessions the receive pool holds at the minimum window ([`crate::grant::GrantCfg::capacity`]).
    pub fn max_sessions(&self) -> u32 {
        let available = crate::grant::GrantCfg::capacity(self.srq_depth);
        self.session_limit
            .map_or(available, |limit| available.min(limit))
    }

    /// Default tuning with the arenas sized to `bytes` of registered memory ([`crate::budget::size`]).
    pub fn for_budget(bytes: u64) -> Result<CoreCfg, crate::budget::TooSmall> {
        let d = CoreCfg::default();
        let s = crate::budget::size(bytes, d.slot, d.max_window)?;
        Ok(CoreCfg {
            srq_depth: s.rx,
            tx_slots: s.tx,
            max_window: s.window,
            ..d
        })
    }
}

/// Receive CQEs plus every SQ completion that can be outstanding without owner progress.
/// Peer grants can fill the whole SQ, independently of our local receive window.
/// QP ERR produces completions for unsignalled SENDs as well as local window WRs.
fn cq_per_session(cfg: CoreCfg) -> u64 {
    u64::from(cfg.sq_depth)
}

/// Reserve only sessions whose worst-case SQ completions fit the provider's
/// CQ. The SRQ still has its full receive arena; admission uses the smaller
/// session bound, so no completion can overflow a provider-limited CQ.
fn fit_cq_sessions(mut cfg: CoreCfg, max_cqe: u32) -> io::Result<CoreCfg> {
    let per_session = cq_per_session(cfg);
    let available = u64::from(max_cqe).checked_sub(u64::from(cfg.srq_depth));
    let sessions = available
        .and_then(|n| n.checked_div(per_session))
        .unwrap_or(0);
    if sessions == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "RDMA provider CQ cannot hold the receive arena and one session SQ",
        ));
    }
    cfg.session_limit = Some(cfg.max_sessions().min(sessions as u32));
    Ok(cfg)
}

fn cq_depth(cfg: CoreCfg) -> io::Result<c_int> {
    let required = u64::from(cfg.srq_depth) + u64::from(cfg.max_sessions()) * cq_per_session(cfg);
    c_int::try_from(required).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "required RDMA CQ depth exceeds the verbs API limit",
        )
    })
}

/// Raw CQ/SRQ handles a control thread needs to create QPs for a core.
#[derive(Clone, Copy, Debug)]
pub struct CoreHandles {
    cq: *mut ffi::Opaque,
    srq: *mut ffi::Opaque,
    cfg: CoreCfg,
}

// SAFETY: CQ and SRQ handles are thread-safe verbs objects; QP creation from the control thread is allowed while the core
// polls the CQ. The Core outlives every QP created with these handles (Core::drop asserts no attached connection).
unsafe impl Send for CoreHandles {}

/// An RC QP in INIT (created on the control thread), then connected; attached to its core afterwards.
#[derive(Debug)]
pub struct Qp {
    dev: Arc<Device>,
    p: *mut ffi::Opaque,
    qpn: u32,
    psn: u32,
    inline: u32,
    /// SGEs per SEND the QP accepts (1 or 2).
    sge: u32,
    /// What the HCA may still access through this QP after it left its core: released only after the QP is destroyed,
    /// kept forever if the destroy failed. Allocated on first use (detach, abandoned READ: cold paths).
    retained: Option<Box<Retained>>,
    #[cfg(feature = "memory-windows")]
    window_identity: Arc<crate::completion::WindowQpScope>,
    /// The QP reached RTR: SENDs of its peer may have landed in the SRQ.
    connected: std::cell::Cell<bool>,
    #[cfg(feature = "memory-windows")]
    read_depths: Cell<ReadDepths>,
    #[cfg(feature = "memory-windows")]
    read_limits: Option<ReadLimits>,
    #[cfg(test)]
    destroy_error: Option<c_int>,
}

/// Owners a QP keeps alive until it is destroyed ([`Qp::retained`]).
#[derive(Debug, Default)]
struct Retained {
    /// Zero-copy leases of WRs still outstanding when the QP was detached ([`Core::detach`]) and the registration they
    /// point into (the HCA may read them).
    leases: Vec<Bytes>,
    zc: Option<Arc<ZcMem>>,
    /// Destination ranges of READs abandoned without a successful CQE ([`Core::abandon_read`]) (the HCA may write them).
    #[cfg(feature = "memory-windows")]
    reads: Vec<RetainedRange>,
    /// Windows bound on this QP and abandoned without a retirement proof ([`Core::abandon_window`]): the peer may
    /// still hold their key. Teardown deallocates their MWs once the QP is in ERR ([`Qp::release_windows`]).
    #[cfg(feature = "memory-windows")]
    windows: Vec<(LocalWindow, Option<ReleaseHook>)>,
    /// Parents (MR and backing) of those windows after their MW went: released after the QP's destroy, then their
    /// hook runs ([`Qp::release_parents`]).
    #[cfg(feature = "memory-windows")]
    parents: Vec<(UnboundWindow, Option<ReleaseHook>)>,
}

// SAFETY: a QP is used by one thread at a time (control thread for setup/teardown, owning core for posting); moved, never
// shared.
unsafe impl Send for Qp {}

impl Qp {
    /// Create in INIT on the core's CQ + SRQ. Control call.
    pub fn create(dev: &Arc<Device>, h: CoreHandles, psn: u32) -> io::Result<Qp> {
        Self::create_inner(dev, h, psn, false)
    }

    /// [`Qp::create`] for a QP that must accept **incoming** RDMA READs from its
    /// peer (`qp_access_flags` includes `IBV_ACCESS_REMOTE_READ`). A source-pull
    /// PUT reads the client's memory, so the client's QP needs this; the OSD's
    /// reader QP does not.
    #[cfg(feature = "memory-windows")]
    pub fn create_read_responder(dev: &Arc<Device>, h: CoreHandles, psn: u32) -> io::Result<Qp> {
        Self::create_inner(dev, h, psn, true)
    }

    fn create_inner(
        dev: &Arc<Device>,
        h: CoreHandles,
        psn: u32,
        read_access: bool,
    ) -> io::Result<Qp> {
        let mut inl = h.cfg.inline;
        let mut sge = MAX_SGE;
        // SAFETY: valid device, CQ, SRQ; `inl` and `sge` are valid out pointers
        let p = unsafe {
            ffi::rv_qp(
                dev.p,
                h.cq,
                h.srq,
                h.cfg.sq_depth as c_int,
                &mut inl,
                &mut sge,
                c_int::from(read_access),
            )
        };
        if p.is_null() {
            return Err(os_err("ibv_create_qp"));
        }
        Ok(Qp {
            dev: dev.clone(),
            p,
            // SAFETY: valid QP
            qpn: unsafe { ffi::rv_qp_num(p) },
            psn: psn & 0xff_ffff,
            #[cfg(feature = "memory-windows")]
            window_identity: Arc::new(crate::completion::WindowQpScope::default()),
            inline: inl,
            sge: sge.clamp(1, MAX_SGE),
            retained: None,
            connected: std::cell::Cell::new(false),
            #[cfg(feature = "memory-windows")]
            read_depths: Cell::new(ReadDepths::default()),
            #[cfg(feature = "memory-windows")]
            read_limits: None,
            #[cfg(test)]
            destroy_error: None,
        })
    }

    /// Our handover record.
    pub fn endpoint(&self, h: &CoreHandles) -> Endpoint {
        Endpoint {
            qpn: self.qpn,
            psn: self.psn,
            gid: self.dev.gid,
            window: crate::credit::MIN_WINDOW,
            slot: h.cfg.slot,
            mtu: self.dev.active_mtu(),
            reads: {
                #[cfg(feature = "memory-windows")]
                {
                    self.read_offer(h)
                }
                #[cfg(not(feature = "memory-windows"))]
                {
                    None
                }
            },
        }
    }

    /// INIT -> RTR -> RTS towards `peer` at the smaller of both active MTUs ([`crate::path_mtu`]). Control call. Fails
    /// with `Unsupported` when the pair has no common path MTU (an older peer without MTU field is always 4096). A
    /// failure after RTR leaves a QP that may have received ([`Qp::to_err`] then waits for its last-WQE event).
    pub fn connect(&self, h: &CoreHandles, peer: &Endpoint) -> io::Result<()> {
        self.connect_inner(h, peer, 0, 0)
    }

    /// [`Qp::connect`] with negotiated READ depths (spec rdma-read-offer.md):
    /// `outgoing` = READs this QP may post, `incoming` = READs the peer may post
    /// into it. Both are programmed into `max_rd_atomic` / `max_dest_rd_atomic`,
    /// so a peer can only READ when both sides agreed. Control call.
    #[cfg(feature = "memory-windows")]
    pub fn connect_with_read_depths(
        &self,
        h: &CoreHandles,
        peer: &Endpoint,
        depths: ReadDepths,
    ) -> io::Result<()> {
        self.connect_inner(h, peer, depths.outgoing(), depths.incoming())
    }

    fn connect_inner(
        &self,
        h: &CoreHandles,
        peer: &Endpoint,
        read_out: u8,
        read_in: u8,
    ) -> io::Result<()> {
        // A second failed transition must never clear prior RTR ownership:
        // that QP may already have consumed shared-SRQ receive slots.
        if self.connected.get() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "QP already reached RTR; retire it before reconnecting",
            ));
        }
        let c = &h.cfg;
        let mtu = crate::path_mtu(self.dev.active_mtu(), peer.mtu).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "peer did not advertise a path MTU (older version, 4096) and the local port is below 4096",
            )
        })?;
        let mut rtr = 0;
        // SAFETY: valid device and QP; peer.gid is 16 readable bytes; `rtr` is a valid out pointer
        let rc = unsafe {
            ffi::rv_qp_connect(
                self.dev.p,
                self.p,
                peer.qpn,
                peer.gid.as_ptr(),
                peer.psn,
                self.psn,
                mtu.trailing_zeros() as c_int - 7, // enum ibv_mtu: 256 = 1 .. 4096 = 5
                c.timeout as c_int,
                c.retry as c_int,
                c.rnr_retry as c_int,
                c.tos as c_int,
                read_out,
                read_in,
                &mut rtr,
            )
        };
        self.connected.set(rtr != 0);
        if rc < 0 {
            return Err(io::Error::from_raw_os_error(-rc));
        }
        #[cfg(feature = "memory-windows")]
        self.read_depths.set(ReadDepths {
            outgoing: read_out,
            incoming: read_in,
        });
        Ok(())
    }

    pub fn qpn(&self) -> u32 {
        self.qpn
    }

    /// First step of the teardown of a QP on a core's SRQ (control call): to ERR, so it consumes no receive WQE any more
    /// and its outstanding WRs flush. Returns whether the caller must wait for its `IBV_EVENT_QP_LAST_WQE_REACHED`
    /// ([`AsyncEvents`]) and have the owning core drain the CQ before [`Qp::destroy`]: some providers (mlx5) drop the
    /// completions of a destroyed QP that are still in the CQ, and the receive slots they consumed would never be posted
    /// again. A QP that was never connected received nothing: no wait.
    pub fn to_err(&mut self) -> io::Result<bool> {
        if self.p.is_null() {
            return Ok(false);
        }
        // SAFETY: valid QP
        let rc = unsafe { ffi::rv_qp_err(self.p) };
        if rc < 0 {
            return Err(io::Error::from_raw_os_error(-rc));
        }
        Ok(self.connected.get())
    }

    /// QP to ERR (flushes outstanding WRs), then destroy. Control call: runs on the control thread ([`crate::control`]).
    /// Idempotent. A QP of a running core's SRQ is destroyed only after [`Qp::to_err`], its last-WQE event and a CQ
    /// drain of the core.
    fn teardown(&mut self) -> io::Result<()> {
        if self.p.is_null() {
            return Ok(());
        }
        #[cfg(feature = "memory-windows")]
        {
            self.release_windows();
            let bindings = self
                .window_identity
                .bindings
                .load(std::sync::atomic::Ordering::Acquire);
            if bindings != 0 {
                // A type-2 MW retains a provider QP reference. Its ownership must retire before destroying the QP;
                // some providers wait inside destroy instead of returning EBUSY. No local invalidation proof exists.
                // SAFETY: valid retained QP; stop peer traffic/flush queued work while retaining every dependent owner.
                let err_rc = unsafe { ffi::rv_qp_err(self.p) };
                self.p = std::ptr::null_mut();
                TEARDOWN_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.quarantine_retained();
                std::mem::forget(self.dev.clone());
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "{bindings} unretired memory windows retain the QP (QP and owners quarantined; to_err={err_rc})"
                    ),
                ));
            }
        }
        // SAFETY: valid QP, not used afterwards (pointer cleared below)
        let rc = unsafe {
            ffi::rv_qp_err(self.p);
            ffi::rv_qp_destroy(self.p)
        };
        // The provider was actually torn down so the test can clean up; inject uncertainty only in ownership handling.
        #[cfg(test)]
        let rc = self.destroy_error.take().unwrap_or(rc);
        self.p = std::ptr::null_mut();
        if rc != 0 {
            TEARDOWN_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // the HCA may still access the leased payloads and READ destinations: never release them (nor their
            // registrations)
            self.quarantine_retained();
            std::mem::forget(self.dev.clone());
            return Err(io::Error::from_raw_os_error(rc.abs()));
        }
        // destroyed: no WR of this QP reads the payloads or writes the READ destinations any more
        #[cfg(feature = "memory-windows")]
        self.release_parents();
        self.retained = None;
        Ok(())
    }

    /// After a successful destroy: release each abandoned window's parent MR and backing; its hook runs only when
    /// that release succeeded (an uncertain deregistration keeps the backing and drops the hook un-run).
    #[cfg(feature = "memory-windows")]
    fn release_parents(&mut self) {
        let Some(retained) = self.retained.as_mut() else {
            return;
        };
        for (parent, hook) in std::mem::take(&mut retained.parents) {
            if parent
                .into_destination()
                .and_then(HostDestination::release)
                .is_ok()
                && let Some(hook) = hook
            {
                hook.run();
            }
        }
    }

    /// Abandoned windows ([`Core::abandon_window`]): move the QP to ERR (it serves no peer READ or WRITE through
    /// them any more; idempotent, the control thread did it before the drain), then deallocate their MWs, which
    /// returns their QP bindings so the destroy can follow. Each parent stays until the destroy succeeded.
    #[cfg(feature = "memory-windows")]
    fn release_windows(&mut self) {
        let Some(retained) = self.retained.as_mut() else {
            return;
        };
        if retained.windows.is_empty() {
            return;
        }
        // SAFETY: valid QP, still owned here.
        unsafe { ffi::rv_qp_err(self.p) };
        for (window, hook) in std::mem::take(&mut retained.windows) {
            // SAFETY: the window's QP is this one and is in ERR (above).
            if let Some(parent) = unsafe { window.release_on_err_qp() } {
                retained.parents.push((parent, hook));
            }
        }
    }

    /// The owners kept until destroy, allocated on first use.
    fn retained(&mut self) -> &mut Retained {
        self.retained.get_or_insert_with(Box::default)
    }

    /// Uncertain teardown: every retained owner stays for the process lifetime; abandoned READ ranges are counted.
    fn quarantine_retained(&mut self) {
        let Some(retained) = self.retained.take() else {
            return;
        };
        #[cfg(feature = "memory-windows")]
        let (reads, parents) = (retained.reads.len(), retained.parents.len());
        // Forgotten before anything is reported: the NIC may still access these owners, so no unwind out of the
        // diagnostics below may drop them.
        std::mem::forget(retained);
        #[cfg(feature = "memory-windows")]
        {
            read::count_quarantined(reads);
            destination::count_quarantined_windows(parents);
            if reads != 0 {
                report_teardown(format_args!(
                    "WARNING rdma: qpn {}: teardown uncertain: {reads} READ destination range(s) quarantined for good",
                    self.qpn
                ));
            }
            if parents != 0 {
                report_teardown(format_args!(
                    "WARNING rdma: qpn {}: teardown uncertain: {parents} abandoned window parent(s) quarantined for good",
                    self.qpn
                ));
            }
        }
    }

    /// Tear the QP down and report the result (Drop does the same and ignores it).
    pub fn destroy(mut self) -> io::Result<()> {
        self.teardown()
    }
}

impl Drop for Qp {
    fn drop(&mut self) {
        // Fallback for shutdown paths (`Core::drop`); a running data path hands QPs to the control thread instead.
        if self.teardown().is_err() {
            report_teardown(format_args!("rdma: qp {} destroy failed", self.qpn));
        }
    }
}

/// A detached connection: `qp` goes to ERR on the control thread, its last-WQE event comes, the core drains the CQ
/// ([`Core::quiesced`], [`Core::drained`]), the control thread destroys it, then `held` comes back with [`Core::reclaim`].
#[derive(Debug)]
pub struct Detached {
    pub qp: Qp,
    pub held: Release,
}

/// Per-connection state on the core.
#[derive(Debug)]
struct Conn {
    qp: Qp,
    /// Credit state in the core's grant pool.
    sid: Sid,
    /// The session's slot of the process-wide limit, given back when the connection ends.
    _permit: Permit,
    /// Send queue and the refused-send state ([`crate::tx`]).
    tx: Sender,
    /// Receive slots kept while the connection is paused ([`Core::pause`]); at most `max_window`.
    hold: Hold,
    faulted: bool,
    #[cfg(feature = "memory-windows")]
    accept_remote_inv: bool,
    #[cfg(feature = "memory-windows")]
    read_waiting: bool,
    /// In the core's `touched` list (owes credits or a control SEND at the end of the pass).
    touched: bool,
    /// Close fence ([`Core::fence`]).
    fence: Fence,
    /// Core clock (ns) when a send was first refused for lack of credits since the last `Writable`.
    credit_since: Option<u64>,
    /// Generation of this connection in its SENDs' work-request ids ([`wr_id`]).
    epoch: u32,
}

impl Conn {
    /// Make pending typed work fail without releasing NIC-accessible slots, sources or registrations.
    fn fail(&mut self) {
        self.faulted = true;
        #[cfg(feature = "memory-windows")]
        self.tx.sq.fail_markers();
    }

    /// Used by detach and every core shutdown path before connection bookkeeping can drop its source leases.
    fn transfer_sources(&mut self, zc: Option<&Arc<ZcMem>>, free: impl FnMut(u32)) {
        let qp = &mut self.qp;
        self.tx
            .sq
            .drain(free, |lease| qp.retained().leases.push(lease));
        if let Some(retained) = qp.retained.as_mut()
            && !retained.leases.is_empty()
        {
            retained.zc = zc.cloned();
        }
    }
}

/// A refused send of `c` is going on: close its credit-stall interval.
fn end_credit_stall(c: &mut Conn, stats: &mut Stats, now_ns: u64) {
    if let Some(t) = c.credit_since.take() {
        stats.credit_stall_ns += now_ns.saturating_sub(t);
        stats.credit_unblocks += 1;
    }
}

/// Counters and fault state after a [`Tx::send`] / [`Tx::send_zc`] of `qpn`.
fn account(
    c: &mut Conn,
    stats: &mut Stats,
    post_failed: &mut Vec<u32>,
    now_ns: u64,
    qpn: u32,
    r: &Sent,
) {
    match r.stall {
        Some(Stall::Credits) => {
            stats.credit_stalls += 1;
            c.credit_since.get_or_insert(now_ns);
        }
        Some(Stall::Queue | Stall::Slots) => stats.queue_stalls += 1,
        None => {}
    }
    if r.failed {
        c.fail();
        stats.faults += 1;
        post_failed.push(qpn);
    }
    stats.tx_sends += u64::from(r.posts);
    stats.tx_bytes += r.taken as u64;
}

/// Key-bearing receive on the exact provider QP that owns a memory-window scope. The key alone
/// is not a retirement receipt; the upper layer must match an authenticated attempt.
#[derive(Debug)]
pub struct RemoteInvalidation {
    key: u32,
    #[cfg(feature = "memory-windows")]
    identity: Arc<crate::completion::WindowQpScope>,
}

impl RemoteInvalidation {
    pub fn key(&self) -> u32 {
        self.key
    }
}

/// What [`Core::poll`] reports per connection (keyed by QPN).
#[derive(Debug)]
pub enum Event<'a> {
    /// Stream bytes, in order. Valid during the callback only (the slot is re-posted right after).
    Data(&'a [u8]),
    /// A peer invalidated a local type-2 window. The owner must validate its attempt and rkey
    /// before treating this as a receipt; the event alone never permits memory reuse.
    RemoteInvalidated(RemoteInvalidation),
    /// A previously refused SEND or READ may make progress now, or the close fence of the connection completed: call
    /// [`Core::fence`] again if one is open.
    Writable,
    /// QP error, protocol violation: session fault. Reported once; detach the connection.
    Fault(String),
}

// The shim normalizes verbs WC flags to bit 0 = immediate data, bit 1 = invalidation.
// The SEND-only stream uses the immediate field for receive-credit accounting.
const WC_WITH_IMM: u32 = 1;

fn valid_stream_receive(flags: u32) -> bool {
    flags == WC_WITH_IMM
}

/// Send what the session owes its peer now: control SENDs of the grant policy, credit-only SENDs once half a window is
/// due ([`Pool::next_send`]), while the send queue has room.
fn flush_conn(
    c: &mut Conn,
    pool: &mut Pool,
    stats: &mut Stats,
    post_failed: &mut Vec<u32>,
    qpn: u32,
) {
    while !c.faulted && !c.tx.sq.full() {
        let Some(imm) = pool.next_send(c.sid) else {
            break;
        };
        let (seq, sig) = c.tx.sq.push_control();
        // SAFETY: valid QP; zero-length SEND has no SGE
        let rc = unsafe {
            ffi::rv_post_send(c.qp.p, wr_id(c.epoch, seq), 0, 0, 0, imm, sig as c_int, 0)
        };
        stats.tx_doorbells += 1;
        if rc < 0 {
            c.fail();
            stats.faults += 1;
            post_failed.push(qpn);
        } else {
            stats.credit_only += 1;
        }
    }
}

/// Data-path counters of one core.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Bytes handed to the callback (`Event::Data`), replayed slots included.
    /// `rx_bytes - rx_delivered` are slots that never reached the driver.
    pub rx_delivered: u64,
    /// Bytes of slots whose delivery completed (the callback took the data or
    /// parked the rest itself). `rx_bytes - rx_completed` are slots still held.
    pub rx_completed: u64,
    pub tx_sends: u64,
    pub rx_sends: u64,
    pub credit_only: u64,
    /// Sends refused for lack of peer credits.
    pub credit_stalls: u64,
    /// Sends refused for a full send queue or no free send slot.
    pub queue_stalls: u64,
    pub faults: u64,
    /// Time connections spent credit-blocked (ns): first refusal for lack of credits to the next `Writable`. The clock is
    /// the caller's [`Core::tick`] time, so the resolution is one poll loop pass.
    pub credit_stall_ns: u64,
    /// Credit-stall intervals that ended (`Writable` after a credit refusal).
    pub credit_unblocks: u64,
    /// Connections woken from the send-slot wait queue.
    pub slot_wakeups: u64,
    /// SENDs and stream bytes posted zero copy ([`Core::send_bytes`]): the SGE points into registered payload memory.
    pub zc_sends: u64,
    pub zc_bytes: u64,
    /// Chunks of at least the zero-copy threshold that were copied because they are not in registered memory.
    pub zc_misses: u64,
    /// Chunks (segments) offered to the send calls and taken completely: `tx_sends / tx_chunks` is the SENDs per chunk
    /// (below 1 when small chunks are packed).
    pub tx_chunks: u64,
    /// `ibv_post_send` calls on the send queues: SEND lists, credit/fence SENDs and opt-in window/WRITE WRs.
    /// With only SEND enabled, `tx_doorbells / tx_bytes` is the SEND doorbell cost per byte.
    pub tx_doorbells: u64,
    /// Accepted RDMA WRITE work requests; excludes SEND and local window operations.
    pub tx_write_wrs: u64,
    /// Bytes covered by accepted WRITE requests; excludes rejected posts and SEND bytes.
    pub tx_write_bytes: u64,
    /// WRITE provider post calls, including failed calls; no call is made on SQ admission refusal.
    pub tx_write_doorbells: u64,
    /// WRITE admission refusals because the shared SQ is full; counts calls, not stall intervals.
    pub tx_write_sq_stalls: u64,
    /// SENDs with two SGEs (packed header + payload by reference).
    pub tx_sge2: u64,
    /// `ibv_post_srq_recv` calls (receive slots re-posted per call: `rx_sends / rx_doorbells`).
    pub rx_doorbells: u64,
    /// Completion channel events consumed by [`Core::ack`] (wake-ups of an idle core).
    pub wakes: u64,
    /// `ibv_ack_cq_events` calls (the events are acknowledged in batches).
    pub wake_acks: u64,
    /// `ibv_post_srq_recv` calls that lost receive slots: the core is broken, every connection faults.
    pub rx_post_failures: u64,
    /// `ibv_poll_cq` calls that returned an error: the core is broken, every connection faults.
    pub cq_errors: u64,
    /// Receive slots withheld from the SRQ at a detach because an open lend still covered them (owner bug: `unlend` after
    /// the borrower finished, before the detach): never re-posted under a reader; the core is broken.
    pub rx_withheld: u64,
    /// Data receive slots held because the upper layer could not take input ([`crate::hold::Flow`] Pause / Keep): not
    /// re-posted, no credit owed until resumed.
    pub rx_held: u64,
    /// Receive completions of detached (or faulted) connections: their slots are posted again, nothing is delivered.
    pub rx_orphans: u64,
    /// Send completions of a destroyed QP whose number a new connection reuses (older generation, [`wr_id`]): ignored.
    pub tx_stale: u64,
}

/// [`Stats`] plus the grant policy counters ([`GrantStats`]) of one core, and the credits granted now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transport {
    pub stats: Stats,
    pub grants: GrantStats,
    /// Sum of the granted windows of all sessions now.
    pub granted: u32,
}

/// State of one core's receive pool and sessions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub sessions: u32,
    /// Sessions the pool holds at the minimum window.
    pub capacity: u32,
    /// Receive slots (SRQ depth) and the credits granted out of them.
    pub slots: u32,
    pub granted: u32,
    /// Sum of the current windows of the live sessions: equals `granted` unless credits are held by no session.
    pub session_credits: u32,
    /// Receive slots held for connections the OSD does not take input from.
    pub held: u32,
}

const RECV: u64 = 1 << 63;

/// Work-request id of a SEND: the connection's generation (bits 32..63, below [`RECV`]) and its send-queue sequence. A
/// completion whose generation is not the connection's belongs to a destroyed QP whose number a new QP reuses (flush
/// completions a provider keeps after the destroy): ignored, counted ([`Stats::tx_stale`]).
fn wr_id(epoch: u32, seq: u32) -> u64 {
    (u64::from(epoch) << 32) | u64::from(seq)
}

/// Generations are 31 bits (bit 63 of a work-request id is [`RECV`]).
const EPOCH_MASK: u32 = 0x7fff_ffff;

/// WRs per list post (one doorbell): send lists of one call, receive reposts of one poll batch. Equals `RV_BATCH` in
/// shim.c.
const BATCH: usize = 64;
/// Completions of one poll pass. Equals the `rv_poll` batch in shim.c.
const WC_BATCH: usize = 32;
/// SGEs per SEND the transport uses: a packed header run and the first bytes of a payload by reference.
const MAX_SGE: u32 = 2;
/// Segments one gathered send plans at a time (the send calls loop over longer lists).
const SEGS: usize = 512;
/// Completion channel events acknowledged per `ibv_ack_cq_events` call (a locked call).
const ACK_BATCH: u32 = 32;

/// One planned segment's memory: where it starts and, for a zero-copy one, the lkey of the registration it lies in.
#[derive(Clone, Copy, Debug)]
struct SegRef {
    ptr: *const u8,
    lkey: u32,
}

/// The receive arena as the posting code needs it (plain values: the arena itself stays borrowed while a received slot is
/// handed out).
#[derive(Clone, Copy, Debug)]
struct RxMem {
    base: u64,
    slot: u32,
    lkey: u32,
}

impl RxMem {
    fn addr(&self, i: u32) -> u64 {
        self.base + u64::from(i) * u64::from(self.slot)
    }
}

/// Offered SENDs/bytes not confirmed accepted after a provider error.
/// An unknown prefix keeps all offered data unconfirmed; SQ leases still pin
/// every possible provider user through faulted-QP retirement.
#[derive(Clone, Copy, Debug, Default)]
struct Lost {
    wrs: u32,
    bytes: usize,
}

/// Post the staged SEND list with one doorbell and clear it. A provider that takes only a prefix leaves the rest in
/// [`Lost`]; the caller treats the connection as faulted.
fn post_staged(
    qp: *mut ffi::Opaque,
    wrs: &mut Vec<ffi::SendWr>,
    lens: &mut Vec<u32>,
    stats: &mut Stats,
) -> Lost {
    if wrs.is_empty() {
        return Lost::default();
    }
    let mut posted: c_int = 0;
    // SAFETY: valid QP; `wrs` holds `wrs.len()` (<= BATCH) initialized entries whose addresses are registered or inline
    // and stay valid until this call returns
    let rc = unsafe { ffi::rv_post_send_list(qp, wrs.as_ptr(), wrs.len() as c_int, &mut posted) };
    stats.tx_doorbells += 1;
    let posted = if rc < 0 {
        posted.max(0) as usize
    } else {
        wrs.len()
    };
    let lost = Lost {
        wrs: (wrs.len() - posted) as u32,
        bytes: lens[posted..].iter().map(|&l| l as usize).sum(),
    };
    wrs.clear();
    lens.clear();
    lost
}

/// Post the queued receive slots to the SRQ with one doorbell and clear the queue. Slots the provider did not take are
/// lost to the SRQ (reported as an error).
fn post_recvs(
    srq: *mut ffi::Opaque,
    rx: RxMem,
    rq: &mut Vec<u32>,
    stats: &mut Stats,
) -> io::Result<()> {
    if rq.is_empty() {
        return Ok(());
    }
    let mut w = [ffi::RecvWr::default(); BATCH];
    for (x, &s) in w.iter_mut().zip(rq.iter()) {
        *x = ffi::RecvWr {
            wr_id: RECV | u64::from(s),
            addr: rx.addr(s),
            len: rx.slot,
            lkey: rx.lkey,
        };
    }
    let n = rq.len();
    let mut posted: c_int = 0;
    // SAFETY: valid SRQ; each slot is CPU-free (just consumed or never posted) and inside the registered arena
    let rc = unsafe { ffi::rv_post_srq_recv_list(srq, w.as_ptr(), n as c_int, &mut posted) };
    stats.rx_doorbells += 1;
    rq.clear();
    if rc < 0 {
        return Err(io::Error::new(
            io::Error::from_raw_os_error(-rc).kind(),
            format!(
                "ibv_post_srq_recv: {} of {n} receive slots lost: {}",
                n - posted.max(0) as usize,
                io::Error::from_raw_os_error(-rc)
            ),
        ));
    }
    Ok(())
}

/// Status text of an errored completion, with the vendor error.
fn wc_text(w: &ffi::Wc) -> String {
    // SAFETY: rv_wc_str returns a static string
    let s = unsafe { CStr::from_ptr(ffi::rv_wc_str(w.status as c_int)) }.to_string_lossy();
    format!("{s} (vendor err {:#x})", w.vendor_err)
}

/// [`post_recvs`] on the data path: a failure is [`rx_lost`].
fn post_recvs_logged(srq: *mut ffi::Opaque, rx: RxMem, rq: &mut Vec<u32>, stats: &mut Stats) {
    if let Err(e) = post_recvs(srq, rx, rq, stats) {
        rx_lost(stats, &e);
    }
}

/// Receive slots the SRQ did not take are gone: the credits granted out of the SRQ depth are no longer backed, so every
/// connection of the core faults at the next poll ([`Core::poll_flow`]); counted and logged, never a silent credit loss.
fn rx_lost(stats: &mut Stats, e: &io::Error) {
    stats.rx_post_failures += 1;
    diag::diag!("rdma: {e}: every connection of the core faults");
}

/// Copy the next `dst.len()` stream bytes from `pos` into `dst`.
fn copy_run(segs: &[SegRef], tsegs: &[Seg], pos: &mut Pos, dst: &mut [u8]) {
    let mut done = 0;
    while done < dst.len() {
        let n = (tsegs[pos.seg].len - pos.off).min(dst.len() - done);
        // SAFETY: the segment memory is valid for its length for the whole send call (caller contract) and does not
        // overlap `dst` (send arena or inline staging)
        unsafe {
            std::ptr::copy_nonoverlapping(
                segs[pos.seg].ptr.add(pos.off),
                dst.as_mut_ptr().add(done),
                n,
            );
        }
        pos.advance(tsegs, n);
        done += n;
    }
}

/// One core's RDMA resources. Field order = drop order: connections (must be detached), then CQ/SRQ users, arenas last.
#[derive(Debug)]
pub struct Core {
    conns: QpnMap<Conn>,
    cq: *mut ffi::Opaque,
    srq: *mut ffi::Opaque,
    rx: Arena,
    rxm: RxMem,
    tx: Arena,
    /// Free send slots of `tx` and the connections waiting for one.
    txq: Tx,
    cfg: CoreCfg,
    /// Credit grants of all sessions of the core ([`crate::grant`]).
    pool: Pool,
    /// Caller's clock (ns) at the last grant tick.
    last_tick: Option<u64>,
    /// Caller's clock (ns) at the last [`Core::tick`] (0 before the first): the time of stall accounting.
    now_ns: u64,
    /// Connections that owe credits or a control SEND at the end of the pass (each once: [`Conn::touched`]).
    touched: Vec<u32>,
    /// Generation of the next attached connection ([`wr_id`]).
    next_epoch: u32,
    /// QPs in ERR whose last-WQE event came ([`Core::quiesced`]): their completions are in the CQ; ready for destroy
    /// ([`Core::drained`]) after the next poll pass that empties the CQ.
    draining: Vec<Detached>,
    drained: Vec<Detached>,
    /// Connections whose send post failed, to be reported by the next poll.
    post_failed: Vec<u32>,
    wc: [ffi::Wc; WC_BATCH],
    pub stats: Stats,
    /// Registered payload memory for zero-copy SENDs and the smallest chunk sent that way ([`Core::set_zero_copy`]);
    /// `None` = every byte is copied into the send arena.
    zc: Option<(Arc<ZcMem>, usize)>,
    /// Receive slots consumed and waiting to be posted again with one doorbell ([`Core::repost`]); posted before any
    /// credit for them leaves.
    rq: Vec<u32>,
    /// The send call being planned: memory and shape of its segments, and the last WR (sequence number) that points into
    /// each zero-copy one. Preallocated, reused by every call.
    segs: Vec<SegRef>,
    tsegs: Vec<Seg>,
    seg_seq: Vec<u32>,
    /// SENDs planned but not posted yet (one list per call, `BATCH` at most) and the stream bytes of each.
    wrs: Vec<ffi::SendWr>,
    wr_lens: Vec<u32>,
    /// Inline staging: one `cfg.inline` buffer per staged SEND whose inline bytes lie in several segments.
    istage: Box<[u8]>,
    /// Completion channel events read and not acknowledged yet (acknowledged `ACK_BATCH` at a time and before the CQ is
    /// destroyed).
    unacked: u32,
    /// The completion vector the CQ was created on.
    vector: u32,
    /// Core-wide failure (receive slots lost, CQ poll error): every connection faults, none is attached any more.
    broken: Option<String>,
    /// Test hook: the next CQ poll returns this provider error ([`Core::inject_cq_error`]).
    #[cfg(test)]
    cq_error: Option<c_int>,
    #[cfg(all(test, feature = "memory-windows"))]
    write_post_error: Option<c_int>,
    #[cfg(all(test, feature = "memory-windows"))]
    read_post_error: Option<c_int>,
}

// SAFETY: a Core is built on the starting thread and then used by its one owning core thread only; the verbs objects
// behind its raw pointers are thread-safe (rdma-core) and nothing of it is shared or aliased.
unsafe impl Send for Core {}

impl Core {
    /// CQ, SRQ, both arenas; posts every receive slot. Control call (run before the core starts polling).
    pub fn new(dev: &Arc<Device>, cfg: CoreCfg) -> io::Result<Core> {
        assert!(
            cfg.max_window >= MIN_WINDOW
                && cfg.max_window <= cfg.srq_depth
                && cfg.slot >= crate::MIN_SLOT
        );
        let cfg = fit_cq_sessions(cfg, dev.max_cqe())?;
        let cqe = cq_depth(cfg)?;
        let rx = Arena::new(dev, cfg.srq_depth, cfg.slot)?;
        let tx = Arena::new(dev, cfg.tx_slots, cfg.slot)?;
        let vector = cfg.comp_vector % dev.comp_vectors();
        // SAFETY: valid device
        let cq = unsafe { ffi::rv_cq(dev.p, cqe, vector as c_int) };
        if cq.is_null() {
            return Err(os_err("ibv_create_cq"));
        }
        // SAFETY: valid device
        let srq = unsafe { ffi::rv_srq(dev.p, cfg.srq_depth as c_int) };
        if srq.is_null() {
            let e = os_err("ibv_create_srq");
            // SAFETY: created above, unused
            unsafe { ffi::rv_cq_destroy(cq) };
            return Err(e);
        }
        let mut c = Core {
            conns: QpnMap::with_capacity_and_hasher(
                cfg.max_sessions() as usize,
                Default::default(),
            ),
            cq,
            srq,
            rxm: RxMem {
                base: rx.base as u64,
                slot: rx.slot,
                lkey: rx.lkey,
            },
            rx,
            tx,
            txq: Tx::new(cfg.tx_slots, cfg.max_sessions()),
            cfg,
            pool: Pool::new(GrantCfg {
                depth: cfg.srq_depth,
                max_window: cfg.max_window,
                max_sessions: cfg.max_sessions(),
            }),
            last_tick: None,
            now_ns: 0,
            touched: Vec::with_capacity(cfg.max_sessions() as usize),
            next_epoch: 0,
            draining: Vec::new(),
            drained: Vec::new(),
            post_failed: Vec::with_capacity(8),
            wc: [ffi::Wc::default(); WC_BATCH],
            stats: Stats::default(),
            zc: None,
            rq: Vec::with_capacity(BATCH),
            segs: Vec::with_capacity(SEGS),
            tsegs: Vec::with_capacity(SEGS),
            seg_seq: vec![0; SEGS],
            wrs: Vec::with_capacity(BATCH),
            wr_lens: Vec::with_capacity(BATCH),
            istage: vec![0; BATCH * cfg.inline as usize].into_boxed_slice(),
            unacked: 0,
            vector,
            broken: None,
            #[cfg(test)]
            cq_error: None,
            #[cfg(all(test, feature = "memory-windows"))]
            write_post_error: None,
            #[cfg(all(test, feature = "memory-windows"))]
            read_post_error: None,
        };
        for i in 0..cfg.srq_depth {
            c.rq.push(i);
            if c.rq.len() == BATCH {
                post_recvs(c.srq, c.rxm, &mut c.rq, &mut c.stats)?;
            }
        }
        post_recvs(c.srq, c.rxm, &mut c.rq, &mut c.stats)?;
        Ok(c)
    }

    /// The completion vector of the core's CQ (the configured one modulo the device's vectors).
    pub fn comp_vector(&self) -> u32 {
        self.vector
    }

    pub fn handles(&self) -> CoreHandles {
        CoreHandles {
            cq: self.cq,
            srq: self.srq,
            cfg: self.cfg,
        }
    }

    /// Device and protection domain shared by this core's QPs and destination registrations.
    pub fn device(&self) -> &Arc<Device> {
        &self.rx._dev
    }

    /// Queue a consumed receive slot for the next list post (one doorbell per batch, [`Core::flush_recvs`]).
    fn queue_recv(&mut self, slot: u32) {
        self.rq.push(slot);
        if self.rq.len() == BATCH {
            self.flush_recvs();
        }
    }

    /// Post the queued receive slots. Runs before any credit for them is sent, and at the end of every poll pass.
    fn flush_recvs(&mut self) {
        post_recvs_logged(self.srq, self.rxm, &mut self.rq, &mut self.stats);
    }

    /// Adopt a connected QP with its slot of the session limit. Refused (the permit is dropped) when the receive pool has no
    /// room left for the minimum window of one more session (the credits granted never exceed the SRQ depth).
    pub fn attach(&mut self, qp: Qp, peer: &Endpoint, permit: Permit) -> Result<(), Qp> {
        if self.conns.contains_key(&qp.qpn) || self.broken.is_some() || self.rx._dev.failed() {
            return Err(qp);
        }
        let Some(sid) = self.pool.admit(qp.qpn, peer.window) else {
            return Err(qp);
        };
        let qpn = qp.qpn;
        let epoch = self.next_epoch;
        self.next_epoch = (epoch + 1) & EPOCH_MASK;
        let tx = Sender::new(
            self.cfg.sq_depth,
            peer.slot.min(self.cfg.slot),
            qp.inline.min(self.cfg.inline),
            qp.sge,
        );
        #[cfg(feature = "memory-windows")]
        let tx = {
            let mut tx = tx;
            if qp.read_depths().outgoing() != 0 {
                tx.sq.enable_reads();
            }
            tx
        };
        self.conns.insert(
            qpn,
            Conn {
                qp,
                sid,
                _permit: permit,
                tx,
                hold: Hold::new(self.cfg.max_window),
                faulted: false,
                #[cfg(feature = "memory-windows")]
                accept_remote_inv: false,
                #[cfg(feature = "memory-windows")]
                read_waiting: false,
                touched: false,
                fence: Fence::default(),
                credit_since: None,
                epoch,
            },
        );
        Ok(())
    }

    /// Close fence of `qpn` ([`crate::fence`]): call after the last output was offered to [`Core::send`], again after every
    /// [`Event::Writable`], and destroy the QP ([`Core::detach`]) on [`Step::Done`]. Posts one signaled zero-length SEND
    /// behind the posted output; [`Step::Pending`] until its completion arrives. An unknown or faulted connection is `Done`
    /// (a QP fault is an abort, the output is gone anyway).
    pub fn fence(&mut self, qpn: u32) -> Step {
        let Some(c) = self.conns.get_mut(&qpn) else {
            return Step::Done;
        };
        if c.faulted {
            return Step::Done;
        }
        // the fence SEND returns the owed credits like any data SEND: their slots are posted first (see `gather_send`)
        self.flush_recvs();
        let Some(c) = self.conns.get_mut(&qpn) else {
            return Step::Done;
        };
        match c.fence.step(&mut c.tx.sq, self.pool.credits(c.sid)) {
            Step::Post { seq, imm } => {
                // SAFETY: valid QP; zero-length SEND has no SGE
                let rc =
                    unsafe { ffi::rv_post_send(c.qp.p, wr_id(c.epoch, seq), 0, 0, 0, imm, 1, 0) };
                self.stats.tx_doorbells += 1;
                if rc < 0 {
                    c.fail();
                    self.stats.faults += 1;
                    self.post_failed.push(qpn);
                    return Step::Done;
                }
                Step::Pending
            }
            Step::Blocked => {
                c.tx.blocked = true;
                Step::Blocked
            }
            s => s,
        }
    }

    /// Accept remote invalidation completions for a negotiated placement session. The caller
    /// must validate each reported rkey against its active attempt before retiring any window.
    #[cfg(feature = "memory-windows")]
    pub fn enable_remote_invalidation(&mut self, qpn: u32) -> io::Result<()> {
        let c = self
            .conns
            .get_mut(&qpn)
            .ok_or(io::ErrorKind::NotConnected)?;
        if c.faulted || !c.qp.connected.get() || self.broken.is_some() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        c.accept_remote_inv = true;
        Ok(())
    }

    /// Post a signalled, zero-byte SEND_WITH_INV after earlier WRs on this RC SQ. It consumes
    /// one peer receive credit but cannot carry returned credits; the usual credit-only SEND
    /// returns those after receive-slot reposting. Caller must supply a live peer grant for this
    /// QP and attempt. This primitive does not implement the placement reply protocol.
    ///
    /// # Safety
    /// `rkey` must be an authenticated, live remote type-2 window key for this QP. The caller
    /// must stop all later writes to that grant and preserve its attempt ordering.
    #[cfg(feature = "memory-windows")]
    pub unsafe fn send_invalidate(&mut self, qpn: u32, rkey: u32) -> io::Result<()> {
        if self.broken.is_some() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let c = self
            .conns
            .get_mut(&qpn)
            .ok_or(io::ErrorKind::NotConnected)?;
        if c.faulted || !c.qp.connected.get() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let credits = self.pool.credits(c.sid);
        if c.tx.sq.full() || !credits.can_send_data() {
            c.tx.blocked = true;
            if c.tx.sq.full() {
                self.stats.queue_stalls += 1;
            } else {
                self.stats.credit_stalls += 1;
                c.credit_since.get_or_insert(self.now_ns);
            }
            return Err(io::ErrorKind::WouldBlock.into());
        }
        credits.take_invalidation();
        let seq = c.tx.sq.push_signaled(NO_SLOT);
        // SAFETY: connected QP and caller-supplied live peer key; no local buffer is referenced.
        let rc = unsafe { ffi::rv_post_send_invalidate(c.qp.p, wr_id(c.epoch, seq), rkey) };
        self.stats.tx_doorbells += 1;
        if rc != 0 {
            c.fail();
            self.stats.faults += 1;
            self.post_failed.push(qpn);
            return Err(post_failure(rc));
        }
        self.stats.tx_sends += 1;
        Ok(())
    }

    /// Remove a connection. Its QP goes to the control thread for teardown; the send slots still held by its send queue
    /// and the receive credits its peer may still use (it can land SENDs in the shared SRQ until the QP is destroyed:
    /// lent to another session now, they would leave that session's peer without a posted slot, an RNR) come back
    /// through [`Core::reclaim`] after the QP is destroyed. No lend may be open ([`Core::lend`]): the owner ends it
    /// with [`Core::unlend`] once the borrower is done with the lent bytes, then detaches.
    pub fn detach(&mut self, qpn: u32) -> Option<Detached> {
        // Slots consumed but never re-posted at this point are a receive window the peer could not use; a
        // short-lived connection that goes quiet with them queued is how one frame per run goes missing.
        if !self.rq.is_empty() {
            diag::diag!(
                "WARNING rdma: qpn {qpn} detached with {} receive slot(s) queued but never posted",
                self.rq.len()
            );
        }
        let mut c = self.conns.remove(&qpn)?;
        let credits = self.pool.remove(c.sid);
        self.txq.forget(qpn, &c.tx);
        let mut slots = Vec::new();
        // zero-copy leases go with the QP: released after it is destroyed, together with the registration
        c.transfer_sources(self.zc.as_ref().map(|z| &z.0), |s| slots.push(s));
        // Held receive slots belong to the shared SRQ: give them back, never deliver them. A slot an open lend still
        // covers may be read by its borrower: never re-posted (the HCA would overwrite it under the reader); withheld for
        // good, which breaks the core like any receive slot loss (loud, counted).
        let lent = c.hold.lent();
        debug_assert_eq!(
            lent, 0,
            "detach of qpn {qpn} with {lent} lent bytes: unlend once the borrower is done, then detach"
        );
        let mut withheld = 0;
        let mut dropped = 0;
        c.hold.drain(|slot, lent| {
            if lent {
                withheld += 1;
            } else {
                dropped += 1;
                self.queue_recv(slot);
            }
        });
        if dropped != 0 {
            // Held bytes never reached the owner: this is the frame loss the store bench sees as a seq gap.
            diag::diag!(
                "WARNING rdma: qpn {qpn} detached with {dropped} undelivered held receive slot(s): their bytes are lost"
            );
        }
        self.flush_recvs();
        if withheld != 0 {
            self.stats.rx_withheld += withheld;
            let why =
                format!("qpn {qpn} detached with an open lend: {withheld} receive slots withheld");
            diag::diag!("rdma: {why}: every connection of the core faults");
            self.broken.get_or_insert(why);
        }
        Some(Detached {
            qp: c.qp,
            held: Release { slots, credits },
        })
    }

    /// Stop consuming receive slots of `qpn`: data that arrives from now on is kept (slot not re-posted, so no credit
    /// is returned and the peer blocks on credits) until [`Core::resume`]. Credit-only SENDs and send completions are
    /// still processed, so the connection can keep sending. Other connections of the core are unaffected. At most one
    /// credit window of slots is held (see [`crate::hold`]). Idempotent; no-op for an unknown connection.
    pub fn pause(&mut self, qpn: u32) {
        if let Some(c) = self.conns.get_mut(&qpn) {
            c.hold.pause();
        }
    }

    /// Whether `qpn` holds arriving data ([`Core::pause`]).
    pub fn paused(&self, qpn: u32) -> bool {
        self.conns.get(&qpn).is_some_and(|c| c.hold.paused())
    }

    /// Slots currently held for `qpn`.
    pub fn held(&self, qpn: u32) -> u32 {
        self.conns.get(&qpn).map_or(0, |c| c.hold.len())
    }

    /// Undo [`Core::pause`]: report the held data in arrival order (`ev` gets [`Event::Data`] only, valid during the
    /// call), re-post the slots and return their credits. Newer data is reported by later polls, so order is kept. The
    /// answer to each slot works as in [`Core::poll_flow`]: `Pause` re-posts the slot and keeps the rest held, `Keep`
    /// keeps that slot too (the connection stays paused either way, nothing is copied). A faulted connection drops its
    /// held data. Returns the number of slots released. No-op while a lend is open ([`Core::lend`]); a slot partly
    /// consumed by a lend is reported from its first unconsumed byte.
    /// Slots still held for `qpn` (after a `resume`: non-zero means the stream must
    /// stay held, e.g. because its bytes are lent to a receive helper).
    pub fn held_slots(&self, qpn: u32) -> u32 {
        self.conns.get(&qpn).map_or(0, |c| c.hold.len())
    }

    pub fn resume(&mut self, qpn: u32, mut ev: impl FnMut(u32, Event<'_>) -> Flow) -> usize {
        let Some(c) = self.conns.get_mut(&qpn) else {
            return 0;
        };
        if c.hold.lent() != 0 {
            return 0;
        }
        c.hold.resume();
        let mut n = 0;
        while let Some(c) = self.conns.get_mut(&qpn)
            && let Some((slot, off, len)) = c.hold.front()
        {
            if c.faulted {
                // A faulted stream is torn down by the owner: keep its slots here so `detach` returns them and
                // counts the loss, instead of popping them as delivered (their bytes would vanish silently).
                c.hold.pause();
                break;
            }
            // SAFETY: held completed receive: the slot is CPU-owned until re-posted below
            let data = unsafe { self.rx.slice_mut(slot, len as usize) };
            self.stats.rx_delivered += (len - off) as u64;
            let flow = ev(qpn, Event::Data(&data[off as usize..]));
            let Some(c) = self.conns.get_mut(&qpn) else {
                break;
            };
            if flow == Flow::Keep {
                c.hold.pause();
                break;
            }
            self.stats.rx_completed += len as u64;
            c.hold.pop();
            if flow == Flow::Pause {
                c.hold.pause();
            }
            self.repost(slot, qpn);
            n += 1;
            if flow == Flow::Pause {
                break;
            }
        }
        self.flush_credits();
        n
    }

    /// Lend held data of paused `qpn` not lent yet (oldest first, at most `max` bytes in at most `parts` slot parts) to a
    /// byte-work thread: `range` gets the address and length of each lent part of a receive slot. An open lend grows by
    /// later calls. The lent bytes stay valid and unchanged (not re-posted, not replayed by [`Core::resume`]) until
    /// [`Core::settle`] consumes them; the borrower must be done with them before that, [`Core::detach`] of the
    /// connection or the drop of the core. Returns the bytes lent now; 0 for an unknown or faulted connection or nothing
    /// new held.
    pub fn lend(
        &mut self,
        qpn: u32,
        max: usize,
        parts: usize,
        mut range: impl FnMut(*const u8, usize),
    ) -> usize {
        let Some(c) = self.conns.get_mut(&qpn) else {
            return 0;
        };
        if c.faulted {
            return 0;
        }
        let rx = &self.rx;
        let max = u32::try_from(max).unwrap_or(u32::MAX);
        let parts = u32::try_from(parts).unwrap_or(u32::MAX);
        c.hold.lend(max, parts, |slot, off, len| {
            range((rx.addr(slot) + u64::from(off)) as *const u8, len as usize)
        }) as usize
    }

    /// `bytes` lent bytes from the front were consumed (the lend stays open): slots they cover to their end are
    /// re-posted (their credits are owed to the peer as after a delivery, so they return while the borrower works on
    /// later ones); a slot they end inside stays held with its rest. The connection stays paused.
    pub fn settle(&mut self, qpn: u32, bytes: usize) {
        let mut left = u32::try_from(bytes).unwrap_or(u32::MAX);
        while let Some(slot) = self
            .conns
            .get_mut(&qpn)
            .and_then(|c| c.hold.settle(&mut left))
        {
            self.repost(slot, qpn);
        }
        self.flush_credits();
    }

    /// Receive slots `qpn` may still re-post before its credits go out in a credit-only SEND (at least 1): the unit in
    /// which a borrower's progress returns credits ([`Core::settle`]). 1 for an unknown connection.
    pub fn credit_gap(&mut self, qpn: u32) -> usize {
        match self.conns.get(&qpn) {
            Some(c) => self.pool.credits(c.sid).until_due() as usize,
            None => 1,
        }
    }

    /// End the lend of `qpn`: lent bytes not consumed are held again ([`Core::resume`] replays them first).
    pub fn unlend(&mut self, qpn: u32) {
        if let Some(c) = self.conns.get_mut(&qpn) {
            c.hold.unlend();
        }
    }

    /// Report a refused send that may make progress now.
    fn writable(&mut self, qpn: u32, ev: &mut impl FnMut(u32, Event<'_>)) {
        if let Some(c) = self.conns.get_mut(&qpn)
            && c.tx.unblock(self.pool.credits(c.sid))
        {
            end_credit_stall(c, &mut self.stats, self.now_ns);
            ev(qpn, Event::Writable);
        }
    }

    /// Re-post a consumed receive slot (the SRQ is shared) and owe its credit to `qpn`'s peer.
    ///
    /// Order per receive completion: the upper layer works on the slot in place (`Event::Data` borrows it: copy-out,
    /// checksum, dispatch), the slot is posted again, and only then the credit is owed and, once half a window is due,
    /// sent from here (a credit-only SEND per completion that crosses the threshold, not one pass after the batch). A
    /// connection that could not send (send queue full) stays in `touched` for the pass-end retry.
    fn repost(&mut self, slot: u32, qpn: u32) {
        self.queue_recv(slot);
        let Some(c) = self.conns.get_mut(&qpn) else {
            return;
        };
        self.pool.on_reposted(c.sid);
        if !self.pool.due(c.sid) {
            return;
        }
        // a credit leaves only after every consumed slot of the batch is posted again (no RNR): the list goes out now,
        // with this slot, one doorbell for the slots consumed since the last one
        post_recvs_logged(self.srq, self.rxm, &mut self.rq, &mut self.stats);
        flush_conn(
            c,
            &mut self.pool,
            &mut self.stats,
            &mut self.post_failed,
            qpn,
        );
        if self.pool.due(c.sid) && !c.touched {
            c.touched = true;
            self.touched.push(qpn);
        }
    }

    /// A detached QP is in ERR and its last-WQE event came (or it was never connected): every receive completion it
    /// will ever cause is in the CQ. It is handed out by [`Core::drained`] after the next poll pass that empties the CQ
    /// (that pass re-posts the slots those completions consumed); only then may it be destroyed.
    pub fn quiesced(&mut self, qp: Qp, held: Release) {
        self.draining.push(Detached { qp, held });
    }

    /// QPs wait for a poll pass that drains their completions ([`Core::quiesced`]) or for their destroy
    /// ([`Core::drained`]): the owner keeps polling.
    pub fn tearing_down(&self) -> bool {
        !self.draining.is_empty() || !self.drained.is_empty()
    }

    /// Next QP whose completions are drained ([`Core::quiesced`]): destroy it on the control thread, then
    /// [`Core::reclaim`] what it held.
    pub fn drained(&mut self) -> Option<Detached> {
        self.drained.pop()
    }

    /// What a destroyed QP held ([`Core::detach`]; its completions were drained before the destroy, [`Core::drained`]):
    /// its send slots and receive credits are free again (connections waiting for slots are woken by the next
    /// [`Core::poll`]).
    pub fn reclaim(&mut self, held: &Release) {
        self.txq.reclaim(&held.slots);
        self.pool.release(held.credits);
    }

    /// Install this core's registration once, on its own protection domain. Replacing a registration could deregister
    /// memory still used by outstanding SENDs, so it is refused. Call during setup, before sending source payloads.
    /// Chunks of at least `min` bytes inside it go zero copy; `min` of one send slot keeps small chunks on the copy path.
    pub fn set_zero_copy(&mut self, mem: Arc<ZcMem>, min: usize) -> io::Result<()> {
        if !Arc::ptr_eq(&self.rx._dev, &mem._dev) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero-copy registration belongs to another protection domain",
            ));
        }
        if self.zc.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "zero-copy registration is already installed",
            ));
        }
        self.zc = Some((mem, min.max(1)));
        Ok(())
    }

    /// Add `b` to the send call being planned. A chunk of at least the zero-copy threshold inside registered memory
    /// (`zc_ok`) is sent by reference; a large chunk outside it counts a miss and is copied.
    fn push_seg(&mut self, b: &[u8], zc_ok: bool) {
        let lkey = match &self.zc {
            Some((mem, min)) if zc_ok && b.len() >= *min => {
                let lkey = mem.lkey(b.as_ptr() as u64, b.len());
                if lkey.is_none() {
                    self.stats.zc_misses += 1;
                }
                lkey
            }
            _ => None,
        };
        self.segs.push(SegRef {
            ptr: b.as_ptr(),
            lkey: lkey.unwrap_or(0),
        });
        self.tsegs.push(Seg {
            len: b.len(),
            zc: lkey.is_some(),
        });
    }

    /// Segments of the planned call that were taken completely, given `taken` bytes from its start.
    fn chunks_done(&self, mut taken: usize) -> u64 {
        let mut n = 0;
        for s in &self.tsegs {
            if s.len > taken {
                break;
            }
            taken -= s.len;
            n += 1;
        }
        n
    }

    /// Plan, stage and post the SENDs of the segments in `segs`/`tsegs` on `qpn`, as many as credits, the send queue and
    /// the send slots allow. The SENDs are chained into one list per `BATCH` and posted with one doorbell
    /// ([`post_staged`]); a SEND takes one credit however many segments it packs. The segment memory must stay valid
    /// until this returns. `Sent::taken` is the stream prefix actually posted: a provider that refuses part of a list
    /// (QP in error) makes the connection faulted and the refused SENDs do not count.
    fn gather_send(&mut self, qpn: u32) -> Sent {
        let Some(c) = self.conns.get_mut(&qpn) else {
            return Sent::default();
        };
        if c.faulted {
            return Sent::default();
        }
        // every data SEND returns the credits owed so far: post the slots queued by this poll pass first (the upper layer
        // sends from inside the data event), or the peer could use a credit before its slot is posted (RNR)
        self.flush_recvs();
        let Some(c) = self.conns.get_mut(&qpn) else {
            return Sent::default();
        };
        let (qp, epoch) = (c.qp.p, c.epoch);
        let (segs, tsegs, seg_seq) = (&self.segs, &self.tsegs, &mut self.seg_seq);
        let (wrs, lens, istage) = (&mut self.wrs, &mut self.wr_lens, &mut self.istage);
        let (arena, stats) = (&mut self.tx, &mut self.stats);
        let inl = self.cfg.inline as usize;
        let mut lost = Lost::default();
        let mut r = self
            .txq
            .gather(qpn, &mut c.tx, self.pool.credits(c.sid), tsegs, |w: Wr| {
                if wrs.len() == BATCH {
                    let l = post_staged(qp, wrs, lens, stats);
                    lost.wrs += l.wrs;
                    lost.bytes += l.bytes;
                    if l.wrs > 0 {
                        return false;
                    }
                }
                let mut sw = ffi::SendWr {
                    wr_id: wr_id(epoch, w.seq),
                    imm: w.imm,
                    flags: u32::from(w.signal) | (u32::from(w.inline) << 1),
                    nsge: w.nparts as u32,
                    ..Default::default()
                };
                let mut pos = w.from;
                let mut slot_off = 0usize;
                for (k, part) in w.parts().iter().enumerate() {
                    sw.len[k] = part.len as u32;
                    let sg = segs[pos.seg];
                    if part.zc {
                        sw.addr[k] = sg.ptr as u64 + pos.off as u64;
                        sw.lkey[k] = sg.lkey;
                        seg_seq[pos.seg] = w.seq;
                        stats.zc_bytes += part.len as u64;
                        pos.advance(tsegs, part.len);
                    } else if w.inline && tsegs[pos.seg].len - pos.off >= part.len {
                        // inline bytes in one segment: the provider copies them at post time
                        sw.addr[k] = sg.ptr as u64 + pos.off as u64;
                        pos.advance(tsegs, part.len);
                    } else if w.inline {
                        // inline bytes spread over several segments: stage them contiguously
                        let at = wrs.len() * inl;
                        let dst = &mut istage[at..at + part.len];
                        copy_run(segs, tsegs, &mut pos, dst);
                        sw.addr[k] = dst.as_ptr() as u64;
                    } else {
                        // SAFETY: a free slot is not owned by the HCA; the part fits the slot (a SEND is at most the peer's
                        // slot, which is at most ours)
                        let dst = unsafe { arena.slice_mut(w.slot, slot_off + part.len) };
                        copy_run(segs, tsegs, &mut pos, &mut dst[slot_off..]);
                        sw.addr[k] = arena.addr(w.slot) + slot_off as u64;
                        sw.lkey[k] = arena.lkey;
                        slot_off += part.len;
                    }
                }
                if w.parts().iter().any(|p| p.zc) {
                    stats.zc_sends += 1;
                }
                stats.tx_sge2 += u64::from(w.nparts == 2);
                wrs.push(sw);
                lens.push(w.len as u32);
                true
            });
        let l = post_staged(qp, wrs, lens, stats);
        lost.wrs += l.wrs;
        lost.bytes += l.bytes;
        if lost.wrs > 0 {
            r.failed = true;
            r.posts -= lost.wrs.min(r.posts);
            r.taken -= lost.bytes.min(r.taken);
        }
        account(
            c,
            &mut self.stats,
            &mut self.post_failed,
            self.now_ns,
            qpn,
            &r,
        );
        r
    }

    /// Give the zero-copy parts of the taken prefix to the WRs that read them: the reference is dropped when that WR
    /// retires (the HCA has read the bytes), or handed out with the QP on detach.
    fn lease(&mut self, qpn: u32, seg: usize, part: Bytes) {
        if let Some(c) = self.conns.get_mut(&qpn) {
            c.tx.sq.lease_at(self.seg_seq[seg], part);
        }
    }

    /// Copy as much of `data` as credits, send queue and send slots allow into SENDs on `qpn`; returns the bytes taken
    /// (a stream: the caller offers the rest later, after [`Event::Writable`]). 0 for an unknown or faulted connection.
    pub fn send(&mut self, qpn: u32, data: &[u8]) -> usize {
        self.send_vectored(qpn, &[IoSlice::new(data)])
    }

    /// [`Core::send`] of several slices as one stream: consecutive small slices are packed into one SEND (one credit, one
    /// send slot, one work request), so a header and the data behind it do not cost a SEND each. Returns the bytes taken,
    /// a prefix of the concatenation. Always the copy path: the slices are borrowed for this call only.
    pub fn send_vectored(&mut self, qpn: u32, bufs: &[IoSlice<'_>]) -> usize {
        let mut total = 0;
        for win in bufs.chunks(SEGS) {
            self.segs.clear();
            self.tsegs.clear();
            let mut want = 0;
            for b in win {
                self.push_seg(b, false);
                want += b.len();
            }
            if want == 0 {
                continue;
            }
            let r = self.gather_send(qpn);
            self.stats.tx_chunks += self.chunks_done(r.taken);
            total += r.taken;
            if r.taken < want {
                break;
            }
        }
        total
    }

    /// [`Core::send`] of owned chunks, in order: the front of `chunks` is consumed up to the bytes taken (whole chunks
    /// popped, a partly taken one advanced). Small chunks are packed into shared SENDs; a chunk of at least the zero-copy
    /// threshold inside registered payload memory ([`Core::set_zero_copy`]) is not copied: its SENDs point into it
    /// (segmented to the peer's slot size, with a packed header in front of it as a first SGE when the QP has two) and a
    /// reference to the posted part is leased to the WR that reads its last bytes until that WR retires ([`crate::tx`],
    /// Lease); on detach the leases go with the QP and are released after it is destroyed. Everything else takes the copy
    /// path. Returns the bytes taken.
    pub fn send_chunks(&mut self, qpn: u32, chunks: &mut VecDeque<Bytes>) -> usize {
        let mut total = 0;
        loop {
            self.segs.clear();
            self.tsegs.clear();
            let mut want = 0;
            for b in chunks.iter().take(SEGS) {
                self.push_seg(b, true);
                want += b.len();
            }
            if self.tsegs.is_empty() {
                break;
            }
            let r = self.gather_send(qpn);
            self.stats.tx_chunks += self.chunks_done(r.taken);
            total += r.taken;
            let mut left = r.taken;
            for i in 0..self.tsegs.len() {
                let len = self.tsegs[i].len;
                let take = len.min(left);
                if take == 0 && len > 0 {
                    break;
                }
                left -= take;
                if take == len {
                    let b = chunks.pop_front().unwrap_or_default();
                    if self.tsegs[i].zc {
                        self.lease(qpn, i, b);
                    }
                } else if let Some(b) = chunks.front_mut() {
                    if self.tsegs[i].zc {
                        let part = b.split_to(take);
                        self.lease(qpn, i, part);
                    } else {
                        b.advance(take);
                    }
                }
            }
            if r.taken < want {
                break;
            }
        }
        total
    }

    /// [`Core::send_chunks`] of one chunk; `b` is advanced past the bytes taken (returned).
    pub fn send_bytes(&mut self, qpn: u32, b: &mut Bytes) -> usize {
        self.segs.clear();
        self.tsegs.clear();
        self.push_seg(b, true);
        let r = self.gather_send(qpn);
        self.stats.tx_chunks += self.chunks_done(r.taken);
        if r.taken > 0 {
            if self.tsegs[0].zc {
                let part = if r.taken == b.len() {
                    std::mem::take(b)
                } else {
                    b.split_to(r.taken)
                };
                self.lease(qpn, 0, part);
            } else {
                b.advance(r.taken);
            }
        }
        r.taken
    }

    /// Poll the CQ once (up to 32 completions), report events, re-post consumed receive slots and return credits, wake
    /// connections waiting for send slots (also after [`Core::reclaim`]). Returns the number of completions and events
    /// reported without one (post failures, wake-ups).
    pub fn poll(&mut self, mut ev: impl FnMut(u32, Event<'_>)) -> usize {
        self.poll_flow(|qpn, e| {
            ev(qpn, e);
            Flow::Go
        })
    }

    /// [`Core::poll`] where the answer to a data event may pause the connection at once ([`Flow`]): the slots that
    /// follow in the same batch are held, in order, without the caller copying them.
    pub fn poll_flow(&mut self, mut cb: impl FnMut(u32, Event<'_>) -> Flow) -> usize {
        let last = Cell::new(Flow::Go);
        let mut ev = |qpn: u32, e: Event<'_>| last.set(cb(qpn, e));
        #[cfg(feature = "fault-inject")]
        if !self.conns.is_empty() && crate::fault::take_qp_err() {
            // the lowest QP number of this core: deterministic for a given set of connections
            if let Some(c) = self.conns.values_mut().min_by_key(|c| c.qp.qpn()) {
                diag::diag!("rdma: fault-inject: QP {} to ERR", c.qp.qpn());
                let _ = c.qp.to_err();
            }
        }
        // a post that failed (QP in error) completes nothing: report it here, once per connection
        let failed = self.post_failed.len();
        while let Some(qpn) = self.post_failed.pop() {
            ev(qpn, Event::Fault("post send failed".into()));
        }
        let mut failed = failed + self.fault_broken(&mut ev);
        // QPs quiesced before this poll: their completions are in the CQ now
        let quiesced = self.draining.len();
        let k = if self.rx._dev.failed() {
            // A CQ_ERR CQ is unusable; its contents cannot grant successful
            // retirement. fault_broken already failed every typed owner.
            0
        } else {
            // SAFETY: valid CQ; `wc` has room for WC_BATCH entries.
            unsafe { ffi::rv_poll(self.cq, self.wc.as_mut_ptr(), WC_BATCH as c_int) }
        };
        #[cfg(test)]
        let k = self.cq_error.take().unwrap_or(k);
        // a poll error loses completions of unknown connections (receive slots, send slots, credits): the core is broken
        let k = if k < 0 {
            self.stats.cq_errors += 1;
            if self.broken.is_none() {
                let why = format!("ibv_poll_cq failed ({k}): completions lost");
                diag::diag!("rdma: {why}: every connection of the core faults");
                self.broken = Some(why);
            }
            failed += self.fault_broken(&mut ev);
            0
        } else {
            k as usize
        };
        for i in 0..k {
            let w = self.wc[i];
            let qpn = w.qp_num;
            let recv = w.wr_id & RECV != 0;
            if recv {
                let slot = w.wr_id as u32;
                if w.status == 0 {
                    #[cfg(feature = "memory-windows")]
                    if w.flags == 2
                        && w.byte_len == 0
                        && self.conns.get(&qpn).is_some_and(|c| c.accept_remote_inv)
                    {
                        if let Some(c) = self.conns.get_mut(&qpn)
                            && !c.faulted
                        {
                            self.stats.rx_sends += 1;
                            // No immediate field: an invalidation returns zero credits.
                            // Reposting below makes its consumed receive slot owed as usual.
                            if self.pool.on_recv(c.sid, 0, false).is_ok() {
                                ev(
                                    qpn,
                                    Event::RemoteInvalidated(RemoteInvalidation {
                                        key: w.imm,
                                        identity: c.qp.window_identity.clone(),
                                    }),
                                );
                                self.writable(qpn, &mut ev);
                            } else {
                                c.fail();
                                self.stats.faults += 1;
                                ev(
                                    qpn,
                                    Event::Fault("invalid invalidation credit state".into()),
                                );
                            }
                        }
                        self.repost(slot, qpn);
                        continue;
                    }
                    if !valid_stream_receive(w.flags) {
                        if let Some(c) = self.conns.get_mut(&qpn)
                            && !c.faulted
                        {
                            c.fail();
                            self.stats.faults += 1;
                            ev(
                                qpn,
                                Event::Fault(format!(
                                    "receive lacks SEND_WITH_IMM credit field or carries an unexpected invalidation (opcode={}, raw_flags={}, flags={}, len={})",
                                    w.opcode, w.pad, w.flags, w.byte_len
                                )),
                            );
                        }
                        self.repost(slot, qpn);
                        continue;
                    }
                    // The provider's byte count must fit the posted slot: a longer SEND completes with a local length
                    // error (non-zero status), so a clean completion that reports more is a provider defect. Never slice
                    // the slot with it: the excess lies in the neighbouring slot or past the arena.
                    let Some(len) = provider::recv_len(w.byte_len, self.rxm.slot) else {
                        if let Some(c) = self.conns.get_mut(&qpn)
                            && !c.faulted
                        {
                            c.fail();
                            self.stats.faults += 1;
                            ev(
                                qpn,
                                Event::Fault(format!(
                                    "receive completion reports {} bytes for a {}-byte slot",
                                    w.byte_len, self.rxm.slot
                                )),
                            );
                        }
                        self.repost(slot, qpn);
                        continue;
                    };
                    // SAFETY: completed receive: the slot is CPU-owned until re-posted below, and `len` fits it
                    let data = unsafe { self.rx.slice_mut(slot, len) };
                    if let Some(c) = self.conns.get_mut(&qpn)
                        && !c.faulted
                    {
                        self.stats.rx_sends += 1;
                        self.stats.rx_bytes += data.len() as u64;
                        // Credits returned by the peer count at arrival, paused or not: a paused connection keeps
                        // sending.
                        match self.pool.on_recv(c.sid, w.imm, w.byte_len > 0) {
                            Ok(grown) => {
                                if grown {
                                    // credit-blocked peer: the lent credits (backed by free slots, not by this one) go
                                    // out before the work on this data, after the slots consumed so far are posted
                                    post_recvs_logged(
                                        self.srq,
                                        self.rxm,
                                        &mut self.rq,
                                        &mut self.stats,
                                    );
                                    flush_conn(
                                        c,
                                        &mut self.pool,
                                        &mut self.stats,
                                        &mut self.post_failed,
                                        qpn,
                                    );
                                }
                                if !data.is_empty() {
                                    let mut hold_it = c.hold.paused();
                                    if !hold_it {
                                        last.set(Flow::Go);
                                        self.stats.rx_delivered += data.len() as u64;
                                        ev(qpn, Event::Data(data));
                                        if last.get() != Flow::Keep {
                                            self.stats.rx_completed += w.byte_len as u64;
                                        }
                                        match last.get() {
                                            Flow::Go => {}
                                            Flow::Pause => c.hold.pause(),
                                            Flow::Keep => {
                                                c.hold.pause();
                                                hold_it = true;
                                            }
                                        }
                                    }
                                    if hold_it {
                                        if c.hold.push(slot, w.byte_len).is_ok() {
                                            // held: not re-posted, no credit owed
                                            self.stats.rx_held += 1;
                                            self.writable(qpn, &mut ev);
                                            continue;
                                        }
                                        c.fail();
                                        self.stats.faults += 1;
                                        ev(qpn, Event::Fault("peer sent beyond its window".into()));
                                    }
                                }
                                self.writable(qpn, &mut ev);
                            }
                            Err(_) => {
                                c.fail();
                                self.stats.faults += 1;
                                ev(
                                    qpn,
                                    Event::Fault("peer returned more credits than granted".into()),
                                );
                            }
                        }
                    } else {
                        self.stats.rx_orphans += 1;
                    }
                } else if let Some(c) = self.conns.get_mut(&qpn)
                    && !c.faulted
                {
                    // an errored receive (a SEND longer than the slot, a remote error) puts the QP in ERR; with no
                    // send outstanding no flush completion follows, so this is the only place to report it
                    c.fail();
                    self.stats.faults += 1;
                    ev(
                        qpn,
                        Event::Fault(format!("receive completion: {}", wc_text(&w))),
                    );
                }
                // SRQ slots are re-posted even for errored/unknown QPs: the SRQ is shared
                self.repost(slot, qpn);
                continue;
            }
            let Some(c) = self.conns.get_mut(&qpn) else {
                continue;
            };
            if (w.wr_id >> 32) as u32 != c.epoch {
                self.stats.tx_stale += 1;
                continue;
            }
            // a credit/control SEND waits only for SQ room (`flush_conn`): one the full SQ deferred is rescheduled by
            // the completion that retires from it, even when no application SEND waits and no window changes
            let was_full = c.tx.sq.full();
            #[cfg(not(feature = "memory-windows"))]
            self.txq.completed(&mut c.tx, w.wr_id as u32);
            #[cfg(feature = "memory-windows")]
            self.txq
                .completed_status(&mut c.tx, w.wr_id as u32, w.status == 0 && !c.faulted);
            if was_full && w.status == 0 && !c.faulted && !c.touched && self.pool.due(c.sid) {
                c.touched = true;
                self.touched.push(qpn);
            }
            let fenced = c.fence.completed(&c.tx.sq);
            #[cfg(feature = "memory-windows")]
            let read_writable = !c.faulted
                && c.read_waiting
                && !c.tx.sq.full()
                && c.tx.sq.pending_reads() < u32::from(c.qp.read_depths().outgoing());
            #[cfg(feature = "memory-windows")]
            if read_writable {
                c.read_waiting = false;
            }
            #[cfg(not(feature = "memory-windows"))]
            let read_writable = false;
            if w.status != 0 && !c.faulted {
                c.fail();
                self.stats.faults += 1;
                ev(
                    qpn,
                    Event::Fault(format!("send completion: {}", wc_text(&w))),
                );
            } else if w.status == 0
                && (c.tx.unblock(self.pool.credits(c.sid)) || fenced || read_writable)
            {
                // (after a fault the flush completions only retire WRs: no Writable follows the one Fault)
                end_credit_stall(c, &mut self.stats, self.now_ns);
                ev(qpn, Event::Writable);
            }
        }
        // slots freed by any connection (above, or reclaimed) go to the slot waiters in queue order (tx I2)
        let (conns, stats, now) = (&mut self.conns, &mut self.stats, self.now_ns);
        let woken = self.txq.wake(|qpn| {
            let woke = conns
                .get_mut(&qpn)
                .is_some_and(|c| c.tx.dequeued() && !c.faulted);
            if woke {
                if let Some(c) = conns.get_mut(&qpn) {
                    end_credit_stall(c, stats, now);
                }
                ev(qpn, Event::Writable);
            }
            woke
        });
        self.stats.slot_wakeups += woken as u64;
        self.flush_credits();
        if k < self.wc.len() && quiesced != 0 {
            // the CQ was empty: the completions of the QPs quiesced before this pass are processed, their slots posted
            // again (flush above)
            self.drained.extend(self.draining.drain(..quiesced));
        }
        // receive slots lost by a post of this pass
        k + failed + woken + self.fault_broken(&mut ev)
    }

    /// A core-wide failure breaks every connection: receive slots lost to the SRQ (the credits granted out of its depth
    /// are no longer backed) or a CQ poll error (completions lost). Once seen, every connection faults (reported once
    /// each) and [`Core::attach`] refuses new ones. Returns the faults reported now.
    fn fault_broken(&mut self, ev: &mut impl FnMut(u32, Event<'_>)) -> usize {
        if self.broken.is_none() && self.rx._dev.failed() {
            self.broken = Some(
                "fatal RDMA device/CQ/SRQ asynchronous event: completion ownership lost".into(),
            );
        }
        if self.broken.is_none() && self.stats.rx_post_failures != 0 {
            self.broken = Some("receive slots lost (ibv_post_srq_recv failed)".into());
        }
        let Some(why) = &self.broken else {
            return 0;
        };
        let mut n = 0;
        for (&qpn, c) in self.conns.iter_mut() {
            if !c.faulted {
                c.fail();
                self.stats.faults += 1;
                ev(qpn, Event::Fault(why.clone()));
                n += 1;
            }
        }
        n
    }

    /// The core-wide failure, if any ([`Core::fault_broken`]).
    pub fn broken(&self) -> Option<&str> {
        self.broken.as_deref()
    }

    /// Credit-only SENDs for connections that owe the peer half a window, and the control SENDs of the grant policy (a
    /// REVOKE, the answer to one).
    fn flush_credits(&mut self) {
        self.flush_recvs();
        while let Some(qpn) = self.touched.pop() {
            if let Some(c) = self.conns.get_mut(&qpn) {
                c.touched = false;
                flush_conn(
                    c,
                    &mut self.pool,
                    &mut self.stats,
                    &mut self.post_failed,
                    qpn,
                );
            }
        }
    }

    /// Grant policy step ([`crate::grant`]): call from the core loop with a monotonic clock in ns; it acts once per
    /// [`TICK`]. Lends credits to sessions that use their window, takes them back from idle ones, and sends the credit
    /// and control SENDs that follow.
    pub fn tick(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
        if self
            .last_tick
            .is_some_and(|t| now_ns.saturating_sub(t) < TICK.as_nanos() as u64)
        {
            return;
        }
        self.last_tick = Some(now_ns);
        let (conns, touched) = (&mut self.conns, &mut self.touched);
        self.pool.tick(|qpn| {
            if let Some(c) = conns.get_mut(&qpn)
                && !c.touched
            {
                c.touched = true;
                touched.push(qpn);
            }
        });
        self.flush_credits();
    }

    /// Data-path and grant-policy counters of the core, and the credits granted now.
    pub fn transport(&self) -> Transport {
        Transport {
            stats: self.stats,
            grants: self.pool.stats,
            granted: self.pool.granted(),
        }
    }

    pub fn connections(&self) -> usize {
        self.conns.len()
    }

    /// Send slots not held by any posted WR.
    pub fn free_tx_slots(&self) -> usize {
        self.txq.free()
    }

    /// Most sessions this core can hold: their minimum windows fill the receive pool.
    pub fn max_connections(&self) -> usize {
        self.pool.capacity()
    }

    /// Sessions, receive pool and credits right now (`rdma status`).
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            sessions: self.conns.len() as u32,
            capacity: self.pool.capacity() as u32,
            slots: self.cfg.srq_depth,
            granted: self.pool.granted(),
            session_credits: self.pool.sessions_iter().map(|(_, g, _)| g).sum(),
            held: self.conns.values().map(|c| c.hold.len()).sum(),
        }
    }

    /// Completion channel fd (non-blocking): readable after an armed CQ got a completion. Lives as long as the core.
    pub fn fd(&self) -> RawFd {
        // SAFETY: valid CQ created with a channel
        unsafe { ffi::rv_cq_fd(self.cq) }
    }

    /// Request one channel event for the next completion. Completions that arrived before arming raise no event:
    /// poll once more after `arm` and sleep on `fd` only if that poll found nothing.
    pub fn arm(&mut self) -> io::Result<()> {
        // SAFETY: valid CQ
        let rc = unsafe { ffi::rv_cq_arm(self.cq) };
        if rc < 0 {
            Err(io::Error::from_raw_os_error(-rc))
        } else {
            Ok(())
        }
    }

    /// After `fd` became readable: consume one pending channel event (one read; the CQ is disarmed again). The event is
    /// acknowledged with the next batch (`ACK_BATCH` events per locked `ibv_ack_cq_events`; the rest before the CQ is
    /// destroyed). An armed CQ raises at most one event per arming, so one read per wake drains it; a second one that is
    /// still queued keeps the fd readable and is consumed by the next wake. Returns the events consumed (0 or 1).
    pub fn ack(&mut self) -> usize {
        // SAFETY: valid CQ; the fd is non-blocking
        let n = unsafe { ffi::rv_cq_ack(self.cq) }.max(0) as u32;
        self.stats.wakes += u64::from(n);
        self.unacked += n;
        if self.unacked >= ACK_BATCH {
            self.flush_acks();
        }
        n as usize
    }

    /// Acknowledge the events read so far (the CQ cannot be destroyed before).
    fn flush_acks(&mut self) {
        if self.unacked > 0 {
            // SAFETY: valid CQ; `unacked` events were read from its channel and not acknowledged yet
            unsafe { ffi::rv_cq_ack_events(self.cq, self.unacked) };
            self.stats.wake_acks += 1;
            self.unacked = 0;
        }
    }
}

impl Core {
    /// Reject the next WRITE after admission, before provider acceptance.
    #[cfg(all(test, feature = "memory-windows"))]
    pub(crate) fn inject_write_post_error(&mut self, rc: c_int) {
        assert!(rc < 0);
        self.write_post_error = Some(rc);
    }
    /// Shutdown only: destroy owned QPs after moving all in-flight SEND ownership into them.
    fn teardown_qps(&mut self) -> bool {
        let mut failed = false;
        let teardown = |qp: &mut Qp| {
            if let Err(error) = qp.teardown() {
                report_teardown(format_args!(
                    "rdma: qp {} destroy failed: {error} (owners retained)",
                    qp.qpn
                ));
                true
            } else {
                false
            }
        };
        for (_, mut c) in self.conns.drain() {
            c.transfer_sources(self.zc.as_ref().map(|z| &z.0), |_| {});
            failed |= teardown(&mut c.qp);
        }
        for mut detached in self.draining.drain(..).chain(self.drained.drain(..)) {
            failed |= teardown(&mut detached.qp);
        }
        failed
    }
}

#[cfg(test)]
impl Core {
    /// Test hook: the next CQ poll returns the provider error `rc` (negative).
    pub(crate) fn inject_cq_error(&mut self, rc: c_int) {
        self.cq_error = Some(rc);
    }

    /// Test hook: connection `qpn` is replaced by a new one with the same QP number, as after a destroy and a create that
    /// reuses the number: new generation, fresh send queue (the old one's slots back, as at a detach).
    pub(crate) fn reuse_qpn(&mut self, qpn: u32) {
        let epoch = self.next_epoch;
        self.next_epoch = (epoch + 1) & EPOCH_MASK;
        let c = self.conns.get_mut(&qpn).expect("attached");
        self.txq.forget(qpn, &c.tx);
        let mut slots = Vec::new();
        c.tx.sq.drain(|s| slots.push(s), drop);
        c.tx = c.tx.renewed(self.cfg.sq_depth);
        #[cfg(feature = "memory-windows")]
        if c.qp.read_depths().outgoing() != 0 {
            c.tx.sq.enable_reads();
        }
        c.epoch = epoch;
        self.txq.reclaim(&slots);
    }

    /// Test hook: a receive post fails as a provider's would (its slots are lost).
    pub(crate) fn inject_rx_post_failure(&mut self) {
        rx_lost(
            &mut self.stats,
            &io::Error::other("injected receive post failure"),
        );
    }
}

impl Core {
    /// Teardown when the owner cannot confirm that no other QP uses the CQ/SRQ (the control thread did not answer the
    /// retire of this core: it may still hold pooled QPs on them or be creating one). The core's own connections are torn
    /// down (their QPs are its own); the CQ, SRQ, both arenas and the device reference stay allocated for the life of the
    /// process, so a QP of the control thread never touches freed provider or receive memory. Loud and counted
    /// ([`leaked_cores`]).
    pub fn leak(mut self, why: &str) {
        self.teardown_qps();
        self.flush_acks();
        LEAKED_CORES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        report_teardown(format_args!(
            "rdma: core teardown: CQ, SRQ and {} MiB registered memory left allocated: {why}",
            (self.rx.layout.size() + self.tx.layout.size()) >> 20
        ));
        std::mem::forget(self);
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        // Remaining connections and QPs not destroyed yet: tear down here (shutdown path, not a data-path core any more).
        let mut retain = self.teardown_qps();
        self.flush_acks();
        // SAFETY: valid SRQ/CQ, not used afterwards; arenas are freed after (field order). The owner guarantees no QP
        // references them any more; a refusal (a QP still does) leaves them allocated and is reported.
        let rc = unsafe {
            [
                ("srq", ffi::rv_srq_destroy(self.srq)),
                ("cq", ffi::rv_cq_destroy(self.cq)),
            ]
        };
        for (what, rc) in rc {
            if rc != 0 {
                retain = true;
                TEARDOWN_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                report_teardown(format_args!(
                    "rdma: core teardown: {what} destroy failed: {} (still used by a QP: left allocated)",
                    io::Error::from_raw_os_error(rc.abs())
                ));
            }
        }
        self.rx.retain = retain;
        self.tx.retain = retain;
    }
}

#[cfg(test)]
#[path = "verbs_rxe_tests.rs"]
mod rxe_tests;
