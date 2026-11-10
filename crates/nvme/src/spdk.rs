// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! SPDK-backed `BlockDev` (feature `spdk`). One `SpdkCtrlr` per attached controller+namespace, one
//! `SpdkDev` (own io qpair, own completion ring) per core. Build-checked in the devcontainer; no NVMe there.
//!
//! Threading: SPDK env init once per process (`env_init`). `SpdkDev` is `Send` so it can be created on one
//! thread and moved to its core, but it must only ever be used by one thread at a time.

use crate::dmapool::{self, Pool};
use crate::svc::{Class, SvcTimes, Window};
use crate::{
    BlockDev, Completion, DSM_MAX_RANGES, DSM_RANGE_BYTES, DeallocLimits, Geometry, IoBuf, Nanos,
    Op, Rejected, Submit, SubmitError, dsm_ranges_into, nvme_status_err,
};
use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::Arc;

#[repr(C)]
#[derive(Default)]
struct RawInfo {
    lba_size: u32,
    lba_count: u64,
    awupf_lbas: u32,
    awun_lbas: u32,
    vwc: u32,
    max_xfer_lbas: u32,
    dealloc: u32,
    write_zeroes: u32,
    dsm_ranges: u32,
    dsm_range_lbas: u32,
    dsm_total_lbas: u64,
    dsm_gran_lbas: u32,
}

#[repr(C)]
#[derive(Default)]
struct RawLbafs {
    cur: u32,
    cur_lbads: u32,
    cur_ms: u32,
    best4k: i32,
    nlbaf: u32,
    pi: u32,
}

#[repr(C)]
#[derive(Default)]
struct RawNsScope {
    fna: u32,
    active: u32,
    allocated: i32,
    ns_mgmt: u32,
    multi_ctrl: u32,
}

#[repr(C)]
struct RawIdent {
    model: [u8; 41],
    serial: [u8; 21],
    fw: [u8; 9],
}

#[repr(C)]
struct NvsCtrlr {
    _p: [u8; 0],
}
#[repr(C)]
struct NvsQ {
    _p: [u8; 0],
}

unsafe extern "C" {
    fn nvs_env_init(
        name: *const c_char,
        core_mask: *const c_char,
        shm_id: c_int,
        mem_mb: c_int,
        pci: *const *const c_char,
        npci: usize,
        env_context: *const c_char,
    ) -> c_int;
    fn nvs_env_post_init() -> c_int;
    #[cfg(feature = "spdk-mp")]
    fn nvs_connect(trid: *const c_char) -> *mut NvsCtrlr;
    #[cfg(feature = "spdk-mp")]
    fn nvs_admin_poll(c: *mut NvsCtrlr) -> c_int;
    fn nvs_is_primary() -> c_int;
    fn nvs_lbaf_query(c: *mut NvsCtrlr, out: *mut RawLbafs) -> c_int;
    fn nvs_format(c: *mut NvsCtrlr, lbaf: u32) -> c_int;
    fn nvs_attach(trid: *const c_char, nsid: u32, out: *mut RawInfo) -> *mut NvsCtrlr;
    fn nvs_detach(c: *mut NvsCtrlr);
    fn nvs_q_open(c: *mut NvsCtrlr, depth: u32) -> *mut NvsQ;
    fn nvs_q_close(q: *mut NvsQ);
    fn nvs_q_write(
        q: *mut NvsQ,
        slot: u32,
        buf: *mut c_void,
        lba: u64,
        n: u32,
        io_flags: u32,
    ) -> c_int;
    fn nvs_q_read(q: *mut NvsQ, slot: u32, buf: *mut c_void, lba: u64, n: u32) -> c_int;
    fn nvs_q_dealloc(q: *mut NvsQ, slot: u32, ranges: *const c_void, n: u16) -> c_int;
    fn nvs_q_write_zeroes(q: *mut NvsQ, slot: u32, lba: u64, n: u32, io_flags: u32) -> c_int;
    fn nvs_q_poll(q: *mut NvsQ) -> c_int;
    fn nvs_q_pop(q: *mut NvsQ, slot: *mut u32, status: *mut i32) -> c_int;
    fn nvs_ident(c: *mut NvsCtrlr, out: *mut RawIdent) -> c_int;
    fn nvs_ns_scope(c: *mut NvsCtrlr, out: *mut RawNsScope) -> c_int;
    fn nvs_smart(c: *mut NvsCtrlr, out: *mut u8) -> c_int;
    fn nvs_dma_alloc(len: usize, align: usize) -> *mut c_void;
    fn nvs_dma_free(p: *mut c_void);
    fn nvs_dma_ok(p: *const c_void, len: usize) -> c_int;
}

#[derive(Debug)]
pub enum SpdkError {
    EnvInit,
    Attach,
    QueueOpen,
    /// Another process holds the device (SPDK PCI claim, [`crate::pcilock`]).
    InUse(String),
}

/// Initialize the SPDK/DPDK environment (hugepages, PCI access). Call once, before `SpdkCtrlr::attach`.
/// `allowed` = PCI addresses of the configured NVMe device(s): DPDK probes ONLY these (P0 safety: never a blank
/// probe of the whole host, non-approved NIC ports etc.); empty or malformed list is refused.
/// `mem_mb = 0` keeps SPDK's default. Uses no IOMMU requirement itself; vfio/uio binding is the host's job.
pub fn env_init(
    name: &str,
    core_mask: Option<&str>,
    mem_mb: i32,
    allowed: &[&str],
) -> Result<(), SpdkError> {
    env_init_raw(name, core_mask, -1, mem_mb, allowed, None)
}

#[cfg(feature = "spdk-mp")]
/// Multi-process role of this process for a shared controller (adr 0463, [`crate::spdkmp`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MpRole {
    /// `croit-flashstore-osd spdk-primary`: constructs the controller (caller holds the PCI claim and the start lock).
    Primary,
    /// OSD / tool on one namespace: needs a running primary, never becomes one.
    Secondary,
}

#[cfg(feature = "spdk-mp")]
/// [`env_init`] in SPDK multi-process mode for the controller at `addr` (shm id and DPDK file prefix derived from the
/// PCI address). A secondary registers itself first ([`crate::spdkmp`]) and is refused when no primary runs: DPDK would
/// otherwise attach to a stale config. `mem_mb` only sizes the primary's initial reservation (secondaries grow on demand
/// through the primary).
pub fn env_init_mp(
    name: &str,
    core_mask: Option<&str>,
    mem_mb: i32,
    addr: &str,
    role: MpRole,
) -> Result<(), String> {
    use crate::spdkmp;
    let shm = spdkmp::shm_id(addr)?;
    let ctx = match role {
        MpRole::Primary => "--proc-type=primary",
        MpRole::Secondary => {
            spdkmp::hold_secondary_at(&spdkmp::mp_lock_path(addr)?)?;
            let cfg = spdkmp::runtime_config(shm);
            if !spdkmp::primary_alive(&cfg) {
                return Err(format!(
                    "no spdk-primary runs for {addr} ({} not locked): start `croit-flashstore-osd spdk-primary --dev spdk:{addr}` first",
                    cfg.display()
                ));
            }
            "--proc-type=secondary"
        }
    };
    env_init_raw(name, core_mask, shm, mem_mb, &[addr], Some(ctx))
        .map_err(|e| format!("spdk env ({role:?}, shm id {shm}): {e:?}"))?;
    let primary = unsafe { nvs_is_primary() } == 1;
    if primary != (role == MpRole::Primary) {
        return Err(format!(
            "spdk env: came up as the wrong process type (primary={primary}, wanted {role:?})"
        ));
    }
    Ok(())
}

/// Lowest CPU in this thread's affinity mask (`None` if it cannot be read: SPDK's default then applies).
fn first_allowed_cpu() -> Option<usize> {
    // SAFETY: zeroed cpu_set_t is valid; sched_getaffinity fills it for the calling thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return None;
        }
        (0..libc::CPU_SETSIZE as usize).find(|&c| libc::CPU_ISSET(c, &set))
    }
}

fn env_init_raw(
    name: &str,
    core_mask: Option<&str>,
    shm_id: i32,
    mem_mb: i32,
    allowed: &[&str],
    env_context: Option<&str>,
) -> Result<(), SpdkError> {
    let list = crate::pciallow::allow_list(allowed).map_err(|e| {
        eprintln!("spdk env: {e}");
        SpdkError::EnvInit
    })?;
    eprintln!("{name}: SPDK env PCI allow-list: {}", list.join(","));
    let n = CString::new(name).map_err(|_| SpdkError::EnvInit)?;
    // default main lcore = first CPU this process may run on (SPDK's default lcore 0 fails under a cpuset without CPU 0:
    // containers, taskset, systemd CPUAffinity)
    let m = match core_mask {
        Some(m) => Some(m.to_owned()),
        None => first_allowed_cpu().map(|c| format!("[{c}]")),
    }
    .map(|m| CString::new(m).unwrap());
    let cs: Vec<CString> = list
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();
    let ptrs: Vec<*const c_char> = cs.iter().map(|c| c.as_ptr()).collect();
    let ctx = env_context.map(|c| CString::new(c).unwrap());
    let r = unsafe {
        nvs_env_init(
            n.as_ptr(),
            m.as_ref().map_or(std::ptr::null(), |m| m.as_ptr()),
            shm_id,
            mem_mb,
            ptrs.as_ptr(),
            ptrs.len(),
            ctx.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(SpdkError::EnvInit)
    }
}

/// Finish SPDK's environment on top of a DPDK EAL that the process already initialized (daemon: crate `net` owns
/// `rte_eal_init`, one EAL for NIC and NVMe, adr 0004). Use instead of [`env_init`].
pub fn env_init_shared() -> Result<(), SpdkError> {
    if unsafe { nvs_env_post_init() } == 0 {
        Ok(())
    } else {
        Err(SpdkError::EnvInit)
    }
}

#[cfg(feature = "spdk-mp")]
static PRIMARY_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "spdk-mp")]
extern "C" fn primary_on_stop(_: c_int) {
    PRIMARY_STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(feature = "spdk-mp")]
/// What the running primary reports to its caller (printed in the caller's `--format`).
#[derive(Debug)]
pub enum PrimaryNotice {
    /// The admin queue poll failed (`nvs_admin_poll` rc); the primary keeps polling. Reported once per failure run.
    AdminFailed(i32),
    /// SIGTERM / SIGINT while secondaries run: the stop is refused (stop them first; SIGKILL forces).
    StopRefused(String),
}

#[cfg(feature = "spdk-mp")]
/// `croit-flashstore-osd spdk-primary`: the multi-process primary of the controller at `addr` (adr 0463). Takes the PCI claim
/// and the start lock, constructs the controller, calls `ready` (secondaries may attach now), then polls the admin queue
/// every `poll_ms` (AERs, cleanup of dead secondaries' io queues) until SIGTERM / SIGINT. A stop while secondaries run
/// is refused and reported through `notice` (stop the OSDs first; SIGKILL forces); the start lock is held from the
/// check until the process exits (the caller must exit after return), so no secondary attaches in between.
pub fn run_primary(
    addr: &str,
    mem_mb: i32,
    poll_ms: u64,
    ready: impl FnOnce(),
    mut notice: impl FnMut(PrimaryNotice),
) -> Result<(), String> {
    use crate::spdkmp;
    crate::pcilock::claim(addr)?;
    let mp = spdkmp::mp_lock_path(addr)?;
    let start = spdkmp::begin_primary_at(&mp)?;
    env_init_mp(
        "croit-flashstore-spdk-primary",
        None,
        mem_mb,
        addr,
        MpRole::Primary,
    )?;
    let t = CString::new(format!("trtype:PCIe traddr:{addr}")).map_err(|e| e.to_string())?;
    let c = unsafe { nvs_connect(t.as_ptr()) };
    if c.is_null() {
        return Err(format!("spdk connect {addr} failed"));
    }
    // SAFETY: the handler only stores an atomic.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            primary_on_stop as extern "C" fn(c_int) as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            primary_on_stop as extern "C" fn(c_int) as libc::sighandler_t,
        );
    }
    drop(start);
    ready();
    let mut failed = false;
    let exit_lock = loop {
        let r = unsafe { nvs_admin_poll(c) };
        if r < 0 && !failed {
            notice(PrimaryNotice::AdminFailed(r));
        }
        failed = r < 0;
        if PRIMARY_STOP.swap(false, std::sync::atomic::Ordering::Relaxed) {
            match spdkmp::begin_primary_at(&mp) {
                Ok(g) => break g,
                Err(e) => notice(PrimaryNotice::StopRefused(e)),
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(poll_ms));
    };
    unsafe { nvs_detach(c) };
    // released by the process exit: a secondary starting before that would outlive the primary
    std::mem::forget(exit_lock);
    Ok(())
}

/// Per-thread pool of DMA buffers (module `dmapool`: exact-size bins up to 1 MiB, size classes above): pool hits avoid
/// `spdk_dma_malloc` and `spdk_dma_free` (`rte_free` memsets the whole block).
struct ThreadPool {
    pool: Pool,
    /// This thread's return inbox ([`dmapool::RETURNS`]); `None` = no inbox left (its buffers are pooled by their droppers).
    owner: Option<u16>,
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        // the thread ends: refuse further returns and release what is parked or came back meanwhile
        if let Some(o) = self.owner {
            for (p, key) in dmapool::RETURNS.retire(o) {
                free_block(p, dmapool::key_bytes(key));
            }
        }
        self.pool.drain(&mut free_block);
    }
}

/// Release a block of `bytes` (its allocated size) to DPDK.
fn free_block(p: usize, bytes: usize) {
    // SAFETY: a parked block was allocated by `nvs_dma_alloc` and is owned by the pool.
    unsafe { nvs_dma_free(p as *mut c_void) };
    dmapool::BUDGET.give(bytes);
}

/// What a fresh heap block is admitted within ([`dmapool::DmaBudget`], adr 0175 am. 4). Nothing waits: a refused
/// store request is postponed by its caller and retried at its next progress step, which polls completions.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// Deferrable store memory (asynchronous reads, staged write copies; may be held without IO in flight): the read
    /// gate.
    Data,
    /// In-flight IO memory (allocated right before a device submit, released by its completion): the whole budget.
    Io,
    /// No store (tools, tests): counted, never refused.
    Always,
}

/// Count `n` bytes in the DMA budget ([`dmapool::DmaBudget`]) before the heap is asked. When the budget refuses, the
/// request trades this thread's parked blocks (its return inbox included) for itself, only as many as it needs; a data
/// request still refused becomes the budget's `want`, which every other core's store sweep gives parked blocks back
/// for.
fn admit(n: usize, class: Admit) -> bool {
    let b = &dmapool::BUDGET;
    let fits = || match class {
        Admit::Data => b.try_take(n),
        Admit::Io => b.try_take_io(n),
        Admit::Always => {
            b.take(n);
            true
        }
    };
    if fits() {
        return true;
    }
    let _ = POOL.try_with(|t| {
        let t = &mut *t.borrow_mut();
        if let Some(o) = t.owner {
            t.pool.adopt_returns(o, &mut free_block);
        }
        t.pool.trim(n as u64, &mut free_block);
    });
    if fits() {
        return true;
    }
    if class == Admit::Data {
        b.note_data_short(n);
    } else {
        b.note_io_short();
    }
    false
}

/// A block of `n` bytes from the DPDK heap (counted by [`admit`]); null when the heap has none.
fn heap_block(n: usize) -> *mut u8 {
    // SAFETY: plain allocation; the block is owned by the returned buffer.
    unsafe { nvs_dma_alloc(n, 4096) as *mut u8 }
}

/// The heap refused a request within the budget (fragmentation, another heap user): this thread's parked blocks and
/// return inbox go back to DPDK now, every other pool's at its next operation or its owner's next
/// [`DmaBuf::release_pooled`] (the store sweep of every core).
fn reclaim() {
    Pool::pressure();
    let _ = POOL.try_with(|t| {
        let t = &mut *t.borrow_mut();
        if let Some(o) = t.owner {
            t.pool.adopt_returns(o, &mut free_block);
        }
        t.pool.drain(&mut free_block);
    });
}

thread_local! {
    static POOL: std::cell::RefCell<ThreadPool> = std::cell::RefCell::new(ThreadPool { pool: Pool::new(), owner: crate::shelf::my_owner() });
}

/// DMA-able buffer (hugepage memory from `spdk_dma_malloc`, 4 KiB aligned).
#[derive(Debug)]
pub struct DmaBuf {
    ptr: *mut u8,
    len: usize,
    // Safe byte slices must never expose uninitialized allocation contents. Device reads bypass slices;
    // successful completion initializes the entire buffer. CPU access initializes a fresh buffer lazily.
    initialized: std::cell::Cell<bool>,
    /// Zero-copy write view of a received payload (adr 0061 am. 4): `ptr` points into these immutable bytes, which
    /// stay alive with the buffer; never written by the CPU, never pooled or freed here.
    view: Option<bytes::Bytes>,
    /// In-flight IO memory ([`DmaBuf::try_new_io_uninit`]): leaves zero-copy as shared data only within the read gate
    /// ([`dmapool::DmaBudget::share`]), so memory held without IO in flight never exceeds the gate.
    io: bool,
    /// Return inbox of the thread that allocated the buffer ([`dmapool::RETURNS`]): where a shared read buffer goes
    /// when its last reference drops on another core.
    owner: Option<u16>,
}

// SAFETY: one owner at a time (a queue handle / store, or the `Bytes` of `into_shared`); `initialized` is only touched by
// that owner; DMA free is thread-safe (DPDK heap) and a pool return lands in the dropping thread's pool.
unsafe impl Send for DmaBuf {}

/// A filled buffer owned by a `Bytes` ([`IoBuf::into_shared`]): a pooled size goes back to its allocating core
/// ([`dmapool::RETURNS`]) when the last reference drops (else the allocating core would refill its pool from the DPDK heap
/// while the sending core's pool fills).
struct SharedDma(std::mem::ManuallyDrop<DmaBuf>);

impl AsRef<[u8]> for SharedDma {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for SharedDma {
    fn drop(&mut self) {
        let b = &*self.0;
        crate::unpin(b.len);
        let bytes = b.block_bytes();
        let home = b.view.is_none()
            && b.owner
                .zip(dmapool::shelf_key(b.len))
                .is_some_and(|(owner, key)| dmapool::RETURNS.put(owner, b.ptr as usize, key));
        // on its way home (`home`): the allocating core adopts it at its next allocation or store sweep
        if !home {
            // SAFETY: dropped exactly once, here; not touched afterwards.
            unsafe { std::mem::ManuallyDrop::drop(&mut self.0) };
        }
        // after the block is home or freed: a waiter woken here finds it
        dmapool::BUDGET.unshare(bytes);
    }
}

impl DmaBuf {
    /// Write buffer viewing `data` in place, if the device can DMA from it (registered hugepage memory, dword
    /// aligned, whole LBAs are the caller's business).
    pub fn view(data: &bytes::Bytes) -> Option<DmaBuf> {
        // SAFETY: plain address lookups in SPDK's memory map, no access to the bytes.
        if unsafe { nvs_dma_ok(data.as_ptr().cast(), data.len()) } == 0 {
            return None;
        }
        Some(DmaBuf {
            ptr: data.as_ptr() as *mut u8,
            len: data.len(),
            initialized: std::cell::Cell::new(true),
            view: Some(data.clone()),
            io: false,
            owner: None,
        })
    }

    /// A zero-copy view (see [`DmaBuf::view`]).
    pub fn is_view(&self) -> bool {
        self.view.is_some()
    }

    fn assert_owned(&self) {
        assert!(
            self.view.is_none(),
            "CPU write into a zero-copy payload view"
        );
    }

    /// Zeroed buffer.
    pub fn new(len: usize) -> DmaBuf {
        let b = Self::new_uninit(len);
        // SAFETY: the buffer owns `len` bytes.
        unsafe { std::ptr::write_bytes(b.ptr, 0, len) };
        b.initialized.set(true);
        b
    }

    /// Buffer with unspecified contents (recycled from the thread's pool when possible) outside the store: tools and
    /// tests, counted in the DMA budget but never refused. The store allocates through [`DmaBuf::try_new_uninit`] /
    /// [`DmaBuf::try_new_io_uninit`] only, so an empty heap here is a tool sized beyond its hugepages: a panic naming
    /// the numbers.
    pub fn new_uninit(len: usize) -> DmaBuf {
        Self::alloc(len, Admit::Always).unwrap_or_else(|| Self::exhausted(len))
    }

    /// Buffer with unspecified contents for deferrable store memory (asynchronous reads, staged write copies): `None` when
    /// the read gate of the DMA budget is full or the heap refuses even after this thread's parked blocks went back; until room for it exists,
    /// every other pool gives back parked blocks at its next store sweep. The caller postpones and retries
    /// (backpressure); it never waits for memory.
    pub fn try_new_uninit(len: usize) -> Option<DmaBuf> {
        Self::alloc(len, Admit::Data)
    }

    /// [`DmaBuf::try_new_uninit`] for in-flight IO memory (allocated right before a device submit, released by its
    /// completion: WAL records, tree pages, checkpoint, omap runs, synchronous reads, deferred write copies), admitted
    /// within the whole budget: the last quarter, which deferrable memory never takes, holds only IO in flight.
    pub fn try_new_io_uninit(len: usize) -> Option<DmaBuf> {
        Self::alloc(len, Admit::Io)
    }

    fn alloc(len: usize, class: Admit) -> Option<DmaBuf> {
        // read buffers of this core that went out as reply data and were dropped on another core come back first
        let (owner, hit) = POOL
            .try_with(|t| {
                let mut t = t.borrow_mut();
                if let Some(o) = t.owner {
                    t.pool.adopt_returns(o, &mut free_block);
                }
                (t.owner, t.pool.take(len, &mut free_block))
            })
            .unwrap_or((None, None));
        if let Some((p, initialized)) = hit {
            return Some(DmaBuf {
                ptr: p as *mut u8,
                len,
                initialized: std::cell::Cell::new(initialized),
                view: None,
                io: class == Admit::Io,
                owner,
            });
        }
        // Large buffers are allocated at their class size; only `len` bytes are ever exposed. The device read or the
        // CPU copy initializes them (`initialized`), so allocation does not zero (`spdk_dma_malloc`, not `zmalloc`).
        let n = dmapool::alloc_len(len).max(1);
        let b = &dmapool::BUDGET;
        if !admit(n, class) {
            return None;
        }
        let mut p = heap_block(n);
        if p.is_null() {
            b.note_heap_short();
            reclaim();
            p = heap_block(n);
        }
        if p.is_null() {
            b.untake(n);
            return None;
        }
        dmapool::count_unpooled(len);
        Some(DmaBuf {
            ptr: p,
            len,
            initialized: std::cell::Cell::new(false),
            view: None,
            io: class == Admit::Io,
            owner,
        })
    }

    /// The heap had no block for a tool's allocation ([`DmaBuf::new_uninit`]) even after this thread's parked blocks
    /// went back.
    #[cold]
    fn exhausted(len: usize) -> ! {
        let b = &dmapool::BUDGET;
        panic!(
            "DMA heap exhausted: spdk_dma_malloc({len}) failed (budget {} held {} shared {} bytes); raise the hugepages",
            b.limit(),
            b.held(),
            b.shared()
        )
    }

    /// Give back what this thread no longer needs: take over its return inbox (read buffers dropped on other cores);
    /// after memory pressure anywhere, release every parked block, else the parked blocks above the read gate or in the
    /// way of a refused request ([`dmapool::DmaBudget::want`]). Cheap when there is nothing to do; the store calls it on
    /// every core at each sweep, so a core without allocations gives memory back within one sweep.
    pub fn release_pooled() {
        let _ = POOL.try_with(|t| {
            let t = &mut *t.borrow_mut();
            t.pool.release(t.owner, &mut free_block);
        });
    }

    /// Bytes this buffer holds from the DPDK heap (its class size); 0 for a payload view.
    fn block_bytes(&self) -> usize {
        if self.view.is_some() {
            0
        } else {
            dmapool::alloc_len(self.len).max(1)
        }
    }

    fn initialize(&self) {
        if !self.initialized.get() {
            // SAFETY: owns len bytes. No slice has been exposed while initialized is false; neither this
            // buffer nor a slice of it can be used by the CPU while ownership is held by an in-flight IO.
            unsafe { std::ptr::write_bytes(self.ptr, 0, self.len) };
            self.initialized.set(true);
        }
    }
}

impl Drop for DmaBuf {
    fn drop(&mut self) {
        if self.view.is_some() {
            return; // a payload view: the bytes belong to their owner
        }
        let kept = POOL
            .try_with(|p| {
                p.borrow_mut().pool.put(
                    self.len,
                    (self.ptr as usize, self.initialized.get()),
                    &mut free_block,
                )
            })
            .unwrap_or(false);
        if kept {
            return;
        }
        free_block(self.ptr as usize, dmapool::alloc_len(self.len).max(1));
    }
}

impl IoBuf for DmaBuf {
    fn len(&self) -> usize {
        self.len
    }
    fn as_slice(&self) -> &[u8] {
        self.initialize();
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.assert_owned();
        self.initialize();
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
    fn copy_from_slice(&mut self, src: &[u8]) {
        self.assert_owned();
        assert_eq!(self.len, src.len());
        // SAFETY: owned allocation of exactly src.len() bytes; the borrow of self excludes aliasing.
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr, self.len) };
        self.initialized.set(true);
    }
    fn copy_from_slice_crc32c(&mut self, src: &[u8], block_bytes: usize, crcs: &mut [u32]) {
        self.assert_owned();
        crate::assert_crc_copy(self.len, src.len(), block_bytes, crcs.len());
        // SAFETY: the buffer owns the allocation; MaybeUninit never exposes uninitialized bytes.
        let dst = unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.len) };
        for ((s, d), c) in src
            .chunks(block_bytes)
            .zip(dst.chunks_mut(block_bytes))
            .zip(crcs)
        {
            *c = crc::crc32c_copy_dma_uninit(*c, s, d);
        }
        // Every byte was written by the copy kernel, including fresh allocation/pool misses.
        self.initialized.set(true);
    }
    fn copy_from_slices_zero_tail(&mut self, parts: &[&[u8]]) {
        self.assert_owned();
        // SAFETY: the buffer owns `len` bytes; the callee only writes.
        let dst = unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.len) };
        crate::copy_parts_zero_tail(dst, parts);
        self.initialized.set(true);
    }
    fn into_shared(self) -> bytes::Bytes {
        if self.view.is_none() && !dmapool::BUDGET.share(self.block_bytes(), self.io) {
            // the in-transit share of the DMA budget is full (or in-flight IO memory above the read gate): the data
            // leaves as a heap copy, the block stays home
            return bytes::Bytes::copy_from_slice(self.as_slice());
        }
        crate::pin(self.len);
        bytes::Bytes::from_owner(SharedDma(std::mem::ManuallyDrop::new(self)))
    }
}

/// Controller handle; the flag latches the first failed-completion log of the device (shared by all its queues).
struct CtrlrInner(*mut NvsCtrlr, std::sync::atomic::AtomicBool);
// Controller handle is shared between per-core queue handles; SPDK serializes qpair allocation internally.
unsafe impl Send for CtrlrInner {}
unsafe impl Sync for CtrlrInner {}
impl Drop for CtrlrInner {
    fn drop(&mut self) {
        unsafe { nvs_detach(self.0) }
    }
}

/// Attached controller + namespace.
#[derive(Clone)]
pub struct SpdkCtrlr {
    inner: Arc<CtrlrInner>,
    geo: Geometry,
    /// Runtime deallocate shape (DSM limits of the controller, preferred granularity of the namespace).
    dl: DeallocLimits,
    trid: String,
    nsid: u32,
}

impl std::fmt::Debug for SpdkCtrlr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpdkCtrlr").field("geo", &self.geo).finish()
    }
}

impl SpdkCtrlr {
    /// Probe + attach by PCI address, e.g. `"0000:03:00.0"`, and identify controller/namespace
    /// (VWC, AWUN/AWUPF, LBA format, capacity). Takes the SPDK PCI claim first ([`crate::pcilock`]): a device owned
    /// by another process is refused before DPDK maps it (on uio hosts that mapping would stop the owner's DMA).
    pub fn attach_pci(addr: &str, nsid: u32) -> Result<SpdkCtrlr, SpdkError> {
        crate::pcilock::claim(addr).map_err(SpdkError::InUse)?;
        Self::attach(&format!("trtype:PCIe traddr:{addr}"), nsid)
    }

    #[cfg(feature = "spdk-mp")]
    /// [`attach_pci`](Self::attach_pci) as a multi-process secondary ([`env_init_mp`]): the primary holds the PCI
    /// claim, this process claims the namespace exclusively instead ([`crate::spdkmp`]).
    pub fn attach_pci_shared(addr: &str, nsid: u32) -> Result<SpdkCtrlr, SpdkError> {
        crate::spdkmp::claim_ns(addr, nsid).map_err(SpdkError::InUse)?;
        Self::attach(&format!("trtype:PCIe traddr:{addr}"), nsid)
    }

    /// Attach with a full SPDK transport-id string.
    pub fn attach(trid: &str, nsid: u32) -> Result<SpdkCtrlr, SpdkError> {
        let t = CString::new(trid).map_err(|_| SpdkError::Attach)?;
        let mut info = RawInfo::default();
        let c = unsafe { nvs_attach(t.as_ptr(), nsid, &mut info) };
        if c.is_null() {
            return Err(SpdkError::Attach);
        }
        let geo = Geometry {
            lba_size: info.lba_size,
            lba_count: info.lba_count,
            awupf_lbas: info.awupf_lbas.max(1),
            awun_lbas: info.awun_lbas.max(1),
            vwc: info.vwc != 0,
            max_xfer_lbas: info.max_xfer_lbas.max(1),
            dealloc: info.dealloc != 0,
            write_zeroes: info.write_zeroes != 0,
        };
        let dl = if geo.dealloc {
            DeallocLimits::nvme(
                info.dsm_ranges,
                info.dsm_range_lbas,
                info.dsm_total_lbas,
                u64::from(info.dsm_gran_lbas),
            )
        } else {
            DeallocLimits::off("off(namespace without deallocate)")
        };
        Ok(SpdkCtrlr {
            inner: Arc::new(CtrlrInner(c, std::sync::atomic::AtomicBool::new(false))),
            geo,
            dl,
            trid: trid.to_owned(),
            nsid,
        })
    }

    pub fn geometry(&self) -> Geometry {
        self.geo
    }

    /// Current LBA format of the namespace (data size, metadata bytes per LBA, PI type) and the index of the best
    /// 4096 B + 0 metadata format, if the namespace offers one.
    pub fn lba_format(&self) -> LbaFormat {
        let mut r = RawLbafs::default();
        unsafe { nvs_lbaf_query(self.inner.0, &mut r) };
        LbaFormat {
            index: r.cur,
            data_bytes: r.cur_lbads,
            meta_bytes: r.cur_ms,
            pi: r.pi,
            best_4k: (r.best4k >= 0).then_some(r.best4k as u32),
            formats: r.nlbaf,
        }
    }

    /// Format NVM to the 4096 B / no-metadata format when the namespace has another one (DESTROYS the namespace
    /// content; the caller decides whether that is allowed). Re-attaches afterwards so the geometry is fresh.
    /// Returns the old format when a format ran, `None` when the namespace already was 4096+0 (PI off).
    pub fn ensure_4k(self) -> Result<(SpdkCtrlr, Option<LbaFormat>), String> {
        let f = self.lba_format();
        if f.data_bytes == 4096 && f.meta_bytes == 0 && f.pi == 0 {
            return Ok((self, None));
        }
        if Arc::strong_count(&self.inner) != 1 {
            return Err("ensure_4k: io queues are still open on this controller".into());
        }
        if unsafe { nvs_is_primary() } != 1 {
            return Err(format!(
                "namespace is {}+{}, not 4096+0, and the controller is shared (adr 0463): format it while no OSD uses the controller (nvme-cli, or a non-shared `spdk:` spec)",
                f.data_bytes, f.meta_bytes
            ));
        }
        let Some(lbaf) = f.best_4k else {
            return Err("namespace has no 4096-byte LBA format without metadata".into());
        };
        // never a format that also wipes other namespaces (FNA format-all, adr 0103)
        crate::fna::check_format_scope(&self.ns_scope(), self.nsid)?;
        let r = unsafe { nvs_format(self.inner.0, lbaf) };
        if r != 0 {
            return Err(format!("Format NVM (lbaf {lbaf}) failed: {r}"));
        }
        // fresh controller state: detach (we hold the only handle), attach again; on failure nothing is kept
        let (trid, nsid) = (self.trid.clone(), self.nsid);
        drop(self);
        let new = SpdkCtrlr::attach(&trid, nsid).map_err(|e| format!("re-attach: {e:?}"))?;
        let n = new.lba_format();
        if n.data_bytes != 4096 || n.meta_bytes != 0 {
            return Err(format!(
                "format did not take: now {}+{}",
                n.data_bytes, n.meta_bytes
            ));
        }
        Ok((new, Some(f)))
    }

    /// Format NVM scope of the controller (FNA, namespace counts), for [`crate::fna::check_format_scope`].
    pub fn ns_scope(&self) -> crate::fna::NsScope {
        let mut r = RawNsScope::default();
        unsafe { nvs_ns_scope(self.inner.0, &mut r) };
        crate::fna::NsScope {
            fna: r.fna as u8,
            active: r.active,
            allocated: u32::try_from(r.allocated).ok(),
            ns_mgmt: r.ns_mgmt != 0,
            multi_ctrl: r.multi_ctrl != 0,
        }
    }

    /// Identify Controller strings (model / serial / firmware).
    pub fn ident(&self) -> crate::health::Ident {
        let mut r = RawIdent {
            model: [0; 41],
            serial: [0; 21],
            fw: [0; 9],
        };
        unsafe { nvs_ident(self.inner.0, &mut r) };
        crate::health::Ident::from_raw(&r.model, &r.serial, &r.fw)
    }

    /// Get Log Page 0x02 (SMART / Health), admin command; safe while io queues run on other threads.
    pub fn smart_log(&self) -> Result<[u8; 512], String> {
        let mut b = [0u8; 512];
        match unsafe { nvs_smart(self.inner.0, b.as_mut_ptr()) } {
            0 => Ok(b),
            e => Err(format!("get log page 0x02 failed ({e})")),
        }
    }

    /// Allocate an io qpair (call from the thread/core that will own it) with `depth` outstanding IOs.
    pub fn open_queue(&self, depth: u32) -> Result<SpdkDev, SpdkError> {
        let q = unsafe { nvs_q_open(self.inner.0, depth) };
        if q.is_null() {
            return Err(SpdkError::QueueOpen);
        }
        Ok(SpdkDev {
            q,
            _ctrlr: self.inner.clone(),
            geo: self.geo,
            dl: self.dl,
            slots: (0..depth).map(|_| None).collect(),
            free: (0..depth).rev().collect(),
            unstamped: Vec::with_capacity(depth as usize),
            stashed: (0, 0, 0),
            epoch: std::time::Instant::now(),
            last_poll: 0,
            svc: Box::default(),
            win: None,
            dead: crate::DeadLatch::default(),
            trid: self.trid.clone(),
            nsid: self.nsid,
        })
    }
}

struct Pending {
    tag: u64,
    op: Op,
    buf: Option<DmaBuf>,
    class: Class,
    /// Doorbell time (ns since `SpdkDev::epoch`; set when the command is issued).
    issued: u64,
    lba: u64,
    nlba: u32,
}

/// Per-core queue handle (one io qpair).
pub struct SpdkDev {
    q: *mut NvsQ,
    _ctrlr: Arc<CtrlrInner>,
    geo: Geometry,
    dl: DeallocLimits,
    slots: Vec<Option<Pending>>,
    free: Vec<u32>,
    /// Slots of commands in the SQ whose doorbell is not written yet (qpair `delay_cmd_submit`): the next `nvs_q_poll`
    /// writes it, and they are stamped with its time.
    unstamped: Vec<u32>,
    /// Completions `issue` moved into the shim ring: (count, poll before, poll that saw them).
    stashed: (usize, u64, u64),
    /// Service-time learning (adr 0004 am. 1): clock origin, time of the last CQ check, learned bounds, cached window
    /// of the in-flight commands (`None` = recompute).
    epoch: std::time::Instant,
    last_poll: u64,
    svc: Box<SvcTimes>,
    win: Option<Window>,
    /// Latched: the qpair failed (`nvs_q_poll` < 0) or a completion named an empty slot.
    dead: crate::DeadLatch,
    /// Transport id and namespace of the device (first-failure log).
    trid: String,
    nsid: u32,
}

impl std::fmt::Debug for SpdkDev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpdkDev")
            .field("inflight", &(self.slots.len() - self.free.len()))
            .finish()
    }
}

// Moved to its owning core once, then used by that thread only.
unsafe impl Send for SpdkDev {}

impl Drop for SpdkDev {
    fn drop(&mut self) {
        // Drain so SPDK never calls back into freed state; the buffers of commands the device never completes are
        // leaked (it may still DMA into them).
        crate::drain_or_leak(
            self,
            |d| d.slots.len() - d.free.len(),
            |d| {
                d.reap(&mut Vec::new());
            },
            |d| {
                for p in d.slots.iter_mut().flatten() {
                    std::mem::forget(p.buf.take());
                }
            },
        );
        unsafe { nvs_q_close(self.q) }
    }
}

impl SpdkDev {
    fn clock(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }

    /// The doorbell for the unstamped commands is written at `now`.
    fn stamp(&mut self, now: u64) {
        for i in 0..self.unstamped.len() {
            let s = self.unstamped[i] as usize;
            if let Some(p) = self.slots[s].as_mut() {
                p.issued = now;
                if let Some(w) = self.win.as_mut() {
                    w.add(&self.svc, p.class, now);
                }
            }
        }
        self.unstamped.clear();
    }

    fn reap(&mut self, out: &mut Vec<Completion<DmaBuf>>) -> usize {
        let n0 = out.len();
        let now = self.clock();
        self.stamp(now);
        let r = unsafe { nvs_q_poll(self.q) };
        let (mut early, early_prev, early_seen) = std::mem::take(&mut self.stashed);
        let prev = std::mem::replace(&mut self.last_poll, now);
        if r < 0 {
            // qpair failure, latched: `is_dead` fail-stops the store. SPDK completes the outstanding IOs as aborted
            // into the shim ring (popped below and on later polls); the shim returns the ring count when it is > 0.
            self.dead
                .trip("spdk store", format_args!("qpair failed ({r})"));
        }
        if r <= 0 {
            return 0;
        }
        let (mut slot, mut st) = (0u32, 0i32);
        while unsafe { nvs_q_pop(self.q, &mut slot, &mut st) } != 0 {
            let Some(p) = self.slots[slot as usize].take() else {
                self.dead.empty_slot("spdk store", slot);
                continue;
            };
            self.free.push(slot);
            // the first ones were found by `issue` (FIFO shim ring)
            let (pv, seen) = if early > 0 {
                early -= 1;
                (early_prev, early_seen)
            } else {
                (prev, now)
            };
            self.svc.learn(p.class, p.issued, pv, seen);
            self.win = None;
            let result = if st == 0 {
                if p.op == Op::Read
                    && let Some(b) = &p.buf
                {
                    // A successful NVMe read filled every byte. Failed reads retain lazy initialization.
                    b.initialized.set(true);
                }
                Ok(())
            } else {
                if !self
                    ._ctrlr
                    .1
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    crate::log_first_failure(
                        format_args!("spdk store {} nsid {}", self.trid, self.nsid),
                        p.op,
                        p.lba,
                        format_args!(
                            "blocks {} bytes {} ({})",
                            p.nlba,
                            u64::from(p.nlba) * u64::from(self.geo.lba_size),
                            crate::status_text(st, 17),
                        ),
                    );
                }
                Err(nvme_status_err((st & 0xffff) as u16))
            };
            out.push(Completion {
                tag: p.tag,
                op: p.op,
                result,
                buf: p.buf,
            });
        }
        out.len() - n0
    }

    fn submit_inner(
        &mut self,
        op: Op,
        lba: u64,
        nlba: u32,
        tag: u64,
        mut buf: Option<DmaBuf>,
        dsm: &[u8],
    ) -> Result<(), Rejected<DmaBuf>> {
        let Some(slot) = self.free.pop() else {
            return Err(Rejected::new(SubmitError::QueueFull, buf));
        };
        let p = buf
            .as_mut()
            .map_or(std::ptr::null_mut(), |b| b.ptr as *mut c_void);
        let class = Class::of(op, u64::from(nlba) * u64::from(self.geo.lba_size));
        let wf = crate::write_io_flags(&self.geo);
        let r = unsafe {
            match op {
                Op::Write => nvs_q_write(self.q, slot, p, lba, nlba, wf),
                Op::Read => nvs_q_read(self.q, slot, p, lba, nlba),
                Op::Deallocate => nvs_q_dealloc(
                    self.q,
                    slot,
                    dsm.as_ptr().cast(),
                    (dsm.len() / DSM_RANGE_BYTES) as u16,
                ),
                Op::WriteZeroes => nvs_q_write_zeroes(self.q, slot, lba, nlba, wf),
            }
        };
        if r != 0 {
            self.free.push(slot);
            // nothing was queued: a shape rejection is not a failed controller (the shape checks run first)
            return Err(Rejected::new(crate::submit_errno(r), buf));
        }
        self.slots[slot as usize] = Some(Pending {
            tag,
            op,
            buf,
            class,
            issued: 0,
            lba,
            nlba,
        });
        self.unstamped.push(slot);
        Ok(())
    }

    fn rw(&mut self, op: Op, lba: u64, buf: DmaBuf, tag: u64) -> Submit<DmaBuf> {
        let ls = self.geo.lba_size as usize;
        if buf.len == 0 || !buf.len.is_multiple_of(ls) {
            return Err(Rejected::new(SubmitError::Invalid, Some(buf)));
        }
        let n = buf.len / ls;
        if let Err(err) = self.geo.check_io(lba, n as u64) {
            return Err(Rejected::new(err, Some(buf)));
        }
        self.submit_inner(op, lba, n as u32, tag, Some(buf), &[])
    }
}

impl BlockDev for SpdkDev {
    fn is_dead(&self) -> bool {
        self.dead.get()
    }
    type Buf = DmaBuf;

    fn geometry(&self) -> Geometry {
        self.geo
    }
    fn alloc_buf(&mut self, len: usize) -> DmaBuf {
        DmaBuf::new(len)
    }
    fn alloc_buf_uninit(&mut self, len: usize) -> DmaBuf {
        DmaBuf::new_uninit(len)
    }
    fn try_alloc_buf_uninit(&mut self, len: usize) -> Option<DmaBuf> {
        DmaBuf::try_new_uninit(len)
    }
    fn try_alloc_io_uninit(&mut self, len: usize) -> Option<DmaBuf> {
        DmaBuf::try_new_io_uninit(len)
    }
    fn release_pooled(&mut self) {
        DmaBuf::release_pooled()
    }
    fn view_buf(&mut self, data: &bytes::Bytes) -> Option<DmaBuf> {
        if !data.len().is_multiple_of(self.geo.lba_size as usize) {
            return None;
        }
        DmaBuf::view(data)
    }
    fn queue_space(&self) -> usize {
        self.free.len()
    }
    fn queue_depth(&self) -> usize {
        self.slots.len()
    }
    fn submit_write(&mut self, lba: u64, buf: DmaBuf, tag: u64) -> Submit<DmaBuf> {
        self.rw(Op::Write, lba, buf, tag)
    }
    fn submit_read(&mut self, lba: u64, buf: DmaBuf, tag: u64) -> Submit<DmaBuf> {
        if buf.is_view() {
            // a device read into immutable payload bytes: never
            return Err(Rejected::new(SubmitError::Invalid, Some(buf)));
        }
        self.rw(Op::Read, lba, buf, tag)
    }
    fn dealloc_limits(&self) -> DeallocLimits {
        self.dl
    }
    /// One DSM carrying every range (SPDK copies the list into its request).
    fn submit_deallocate(&mut self, ranges: &[(u64, u32)], tag: u64) -> Submit<DmaBuf> {
        if let Err(err) = self.dl.check(ranges) {
            return Err(Rejected::new(err, None));
        }
        let mut total = 0u64;
        for &(lba, n) in ranges {
            if let Err(err) = self.geo.check_range(lba, u64::from(n)) {
                return Err(Rejected::new(err, None));
            }
            total += u64::from(n);
        }
        let mut list = [0u8; DSM_MAX_RANGES as usize * DSM_RANGE_BYTES];
        let list = &mut list[..ranges.len() * DSM_RANGE_BYTES];
        dsm_ranges_into(ranges, list);
        let nlba = u32::try_from(total).unwrap_or(u32::MAX);
        self.submit_inner(Op::Deallocate, ranges[0].0, nlba, tag, None, list)
    }
    fn submit_write_zeroes(&mut self, lba: u64, nlba: u32, tag: u64) -> Submit<DmaBuf> {
        if !self.geo.write_zeroes {
            return Err(Rejected::new(SubmitError::Unsupported, None));
        }
        // the command carries the count in NVMe's 16-bit NLB field
        if nlba == 0 || nlba > crate::NLB_MAX {
            return Err(Rejected::new(SubmitError::Invalid, None));
        }
        if let Err(err) = self.geo.check_range(lba, u64::from(nlba)) {
            return Err(Rejected::new(err, None));
        }
        self.submit_inner(Op::WriteZeroes, lba, nlba, tag, None, &[])
    }
    /// The SQ doorbell is written once per pass (qpair `delay_cmd_submit`, adr 0004 am. 1): the store seals its WAL
    /// unit at the end of the pass like on the kernel tier.
    fn submits_at_flush(&self) -> bool {
        true
    }
    fn issue(&mut self) {
        if self.unstamped.is_empty() {
            return;
        }
        let now = self.clock();
        self.stamp(now);
        // writes the SQ doorbell; completions it finds wait in the shim ring for the next `poll`
        let r = unsafe { nvs_q_poll(self.q) };
        if r < 0 {
            self.dead
                .trip("spdk store", format_args!("qpair failed ({r})"));
        }
        let prev = std::mem::replace(&mut self.last_poll, now);
        if r > 0 && self.stashed.0 == 0 {
            self.stashed = (r as usize, prev, now);
        }
    }
    fn wait_hint(&mut self) -> Option<std::time::Duration> {
        if self.free.len() == self.slots.len() {
            return None;
        }
        // the next poll issues the unstamped commands / hands out the completions `issue` already found
        if !self.unstamped.is_empty() || self.stashed.0 > 0 {
            return Some(std::time::Duration::ZERO);
        }
        let w = match self.win {
            Some(w) => w,
            None => {
                let mut w = Window::EMPTY;
                for p in self.slots.iter().flatten() {
                    w.add(&self.svc, p.class, p.issued);
                }
                self.win = Some(w);
                w
            }
        };
        w.hint(self.clock())
    }
    fn poll(&mut self, _now: Nanos, out: &mut Vec<Completion<DmaBuf>>) -> usize {
        // nothing in flight = nothing to reap: an idle qpair costs no MMIO/CQ scan (one core polls many shard queues)
        if self.free.len() == self.slots.len() {
            return 0;
        }
        self.reap(out)
    }
}

/// Namespace LBA format as reported by Identify Namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LbaFormat {
    pub index: u32,
    pub data_bytes: u32,
    pub meta_bytes: u32,
    /// Protection information type in use (0 = none).
    pub pi: u32,
    /// Best 4096+0 format of the namespace.
    pub best_4k: Option<u32>,
    pub formats: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Allocator-only local tests: no PCI probing, devices, hugepages or lab network.
    fn init() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            unsafe extern "C" {
                fn rte_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
            }
            let args: Vec<CString> = [
                "nvme-dma-test",
                "--no-pci",
                "--no-huge",
                "--in-memory",
                "--iova-mode=va",
                "--no-telemetry",
                "-m",
                "256",
            ]
            .iter()
            .map(|s| CString::new(*s).unwrap())
            .collect();
            let mut ptrs: Vec<_> = args.iter().map(|s| s.as_ptr().cast_mut()).collect();
            // SAFETY: owned C strings stay alive through EAL initialization; test-only, once per process.
            assert!(unsafe { rte_eal_init(ptrs.len() as c_int, ptrs.as_mut_ptr()) } >= 0);
            // DMA allocation uses the EAL heap; no SPDK memory registration or PCI attachment is needed.
        });
    }

    #[test]
    fn initialized_buffers_are_zeroed_after_reuse() {
        init();
        let mut b = DmaBuf::new(4096);
        b.as_mut_slice().fill(0xa5);
        drop(b);
        let b = DmaBuf::new(4096);
        assert!(b.as_slice().iter().all(|v| *v == 0));
    }

    #[test]
    fn uninit_cpu_access_and_rejected_reads_are_initialized() {
        init();
        let mut b = DmaBuf::new_uninit((dmapool::MAX_SMALL_BLK + 1) * 4096);
        assert!(
            !b.initialized.get(),
            "pool miss must not eagerly initialize"
        );
        assert!(b.as_mut_slice().iter().all(|v| *v == 0));
        assert!(b.initialized.get());
        let b = DmaBuf::new_uninit((dmapool::MAX_SMALL_BLK + 1) * 4096);
        assert!(b.as_slice().iter().all(|v| *v == 0));
    }

    #[test]
    fn uninitialized_pool_entries_stay_uninitialized() {
        init();
        // Tests each have their own thread-local pool. Reuse must preserve initialization state.
        let b = DmaBuf::new_uninit(8192);
        assert!(!b.initialized.get());
        let p = b.ptr;
        drop(b);
        let b = DmaBuf::new_uninit(8192);
        assert_eq!(b.ptr, p);
        assert!(!b.initialized.get());
    }

    #[test]
    fn large_buffers_recycle_within_their_class_without_exposing_the_class_tail() {
        init();
        let b = DmaBuf::new_uninit(4 << 20);
        let p = b.ptr;
        drop(b);
        let hits = |k: usize| {
            dmapool::counters()
                .into_iter()
                .find(|(n, _)| *n == format!("c{k}_hits"))
                .unwrap()
                .1
        };
        let before = hits(4096);
        let b = DmaBuf::new_uninit(4 << 20);
        assert_eq!(b.ptr, p);
        assert_eq!(b.len(), 4 << 20);
        assert!(hits(4096) > before);
        drop(b);
        // a shorter length of the same class reuses the block and exposes only its own length
        let mut b = DmaBuf::new_uninit((3 << 20) + 4096);
        assert_eq!(b.ptr, p);
        assert_eq!(b.as_mut_slice().len(), (3 << 20) + 4096);
    }

    #[test]
    fn growing_an_initialized_large_buffer_requires_initializing_the_tail() {
        init();
        let short = (3 << 20) + 4096;
        let mut b = DmaBuf::new_uninit(short);
        b.copy_from_slice(&vec![0x5a; short]);
        let ptr = b.ptr;
        drop(b);
        let b = DmaBuf::new_uninit(4 << 20);
        assert_eq!(b.ptr, ptr);
        assert!(!b.initialized.get());
        assert!(b.as_slice().iter().all(|v| *v == 0));
    }

    #[test]
    fn full_overwrite_initializes_fresh_dma_and_anybuf_without_zero_slice_access() {
        init();
        // Larger than the pool: always a fresh uninitialized allocation.
        let size = (dmapool::MAX_SMALL_BLK + 1) * 4096;
        let b = DmaBuf::new_uninit(size);
        assert!(!b.initialized.get());
        let mut b = crate::any::AnyBuf::Dma(b);
        let src = vec![0xa7; size];
        let mut crcs: Vec<u32> = (0..size / 4096).map(|i| i as u32).collect();
        b.copy_from_slice_crc32c(&src, 4096, &mut crcs);
        assert_eq!(b.as_slice(), &src);
        for (i, c) in crcs.iter().enumerate() {
            assert_eq!(*c, crc::crc32c(i as u32, &src[i * 4096..(i + 1) * 4096]));
        }
        b.copy_from_slices_zero_tail(&[b"head", b"body"]);
        assert_eq!(&b.as_slice()[..8], b"headbody");
        assert!(b.as_slice()[8..].iter().all(|v| *v == 0));
        b.copy_from_slice(&src);
        assert_eq!(b.as_slice(), &src);
    }

    #[test]
    fn invalid_full_initialization_checks_leave_fresh_buffer_unexposed() {
        init();
        let size = (dmapool::MAX_SMALL_BLK + 1) * 4096;
        let mut b = DmaBuf::new_uninit(size);
        let src = vec![0x28; size];
        let bad_crc_shape = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b.copy_from_slice_crc32c(&src, 4096, &mut [0u32; 1]);
        }));
        assert!(bad_crc_shape.is_err());
        assert!(!b.initialized.get());
        let bad_parts = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b.copy_from_slices_zero_tail(&[&src, b"too much"]);
        }));
        assert!(bad_parts.is_err());
        assert!(!b.initialized.get());
        b.copy_from_slice(&src);
        assert!(b.initialized.get());
        assert_eq!(b.as_slice(), &src);
    }

    #[test]
    fn shared_read_buffers_return_to_their_allocating_core_by_class() {
        init();
        // 20 MiB: the 24 MiB class, used by no other test here
        let mut b = DmaBuf::new_uninit(20 << 20);
        b.copy_from_slice(&vec![0x5a; 20 << 20]);
        let ptr = b.ptr as usize;
        let shared = b.into_shared();
        assert_eq!(shared.as_ptr() as usize, ptr, "handed over by reference");
        assert!(shared.iter().all(|v| *v == 0x5a));
        // the last reference drops on another core
        std::thread::spawn(move || drop(shared)).join().unwrap();
        // The return key knows the class, not how much of it the earlier read filled.
        let b = DmaBuf::new_uninit((22 << 20) + 4096);
        assert_eq!(b.ptr as usize, ptr);
        assert!(
            !b.initialized.get(),
            "the longer buffer includes an uninitialized tail"
        );
        assert!(b.as_slice().iter().all(|v| *v == 0));
        let shared = b.into_shared();
        std::thread::spawn(move || drop(shared)).join().unwrap();
        // memory pressure frees the returned blocks too (they are in the pool by then)
        POOL.with(|t| {
            let mut t = t.borrow_mut();
            let o = t.owner.unwrap();
            t.pool.adopt_returns(o, &mut free_block);
            t.pool.drain(&mut free_block);
        });
        let b = DmaBuf::new_uninit(20 << 20);
        assert!(!b.initialized.get(), "fresh block after the drain");
    }

    #[test]
    fn a_whole_large_read_of_shared_buffers_comes_home_without_a_single_free() {
        init();
        // 768 buffers of 124 KiB (a 93 MiB read in device commands; the bin no other test uses): far more than any
        // fixed slot count, all dropped on another core
        let len = 31 * 4096;
        let bufs: Vec<_> = (0..768).map(|_| DmaBuf::new_uninit(len)).collect();
        let mut ptrs: Vec<usize> = bufs.iter().map(|b| b.ptr as usize).collect();
        let shared: Vec<_> = bufs.into_iter().map(IoBuf::into_shared).collect();
        std::thread::spawn(move || drop(shared)).join().unwrap();
        let again: Vec<_> = (0..768).map(|_| DmaBuf::new_uninit(len)).collect();
        let mut got: Vec<usize> = again.iter().map(|b| b.ptr as usize).collect();
        ptrs.sort_unstable();
        got.sort_unstable();
        assert_eq!(
            got, ptrs,
            "every buffer came back to the core that allocated it"
        );
        assert!(again.iter().all(|b| b.initialized.get()));
    }

    #[test]
    #[ignore = "paired local fresh-DMA zeroing/copy benchmark; no device IO"]
    fn perf_fresh_dma_full_init() {
        init();
        let size = (dmapool::MAX_SMALL_BLK + 1) * 4096;
        let src = vec![0x9c; size];
        let seeds: Vec<u32> = (0..size / 4096).map(|i| i as u32).collect();
        let expected: Vec<u32> = src
            .chunks(4096)
            .zip(&seeds)
            .map(|(s, c)| crc::crc32c(*c, s))
            .collect();
        for sample in 0..5 {
            let mut old_ns = 0u128;
            let mut new_ns = 0u128;
            for iteration in 0..40 {
                // Alternate ordering; allocation is excluded. Oversize bypasses the Rust pool.
                for new in if iteration % 2 == 0 {
                    [false, true]
                } else {
                    [true, false]
                } {
                    let mut b = DmaBuf::new_uninit(size);
                    let mut crcs = seeds.clone();
                    let start = std::time::Instant::now();
                    if new {
                        b.copy_from_slice_crc32c(std::hint::black_box(&src), 4096, &mut crcs);
                    } else {
                        for ((s, d), c) in src
                            .chunks(4096)
                            .zip(b.as_mut_slice().chunks_mut(4096))
                            .zip(&mut crcs)
                        {
                            *c = crc::crc32c_copy_dma(*c, s, d);
                        }
                    }
                    let ns = start.elapsed().as_nanos();
                    if new {
                        new_ns += ns;
                    } else {
                        old_ns += ns;
                    }
                    assert_eq!(b.as_slice(), &src);
                    assert_eq!(crcs, expected);
                }
            }
            println!(
                "fresh_dma sample={sample} bytes={size} old_ns={} new_ns={} old_zero_bytes={size} new_zero_bytes=0",
                old_ns / 40,
                new_ns / 40
            );
        }
    }

    #[test]
    #[ignore = "allocator microbenchmark; run explicitly, no device required"]
    fn dma_pool_miss_bench() {
        init();
        for len in [4096, 256 << 10] {
            // Bypass the Rust pool: this isolates precisely the C allocation fallback.
            let t0 = std::time::Instant::now();
            let rounds = 20_000;
            for _ in 0..rounds {
                // SAFETY: allocate/free paired; only the pointer is observed before initialization.
                let p = unsafe { nvs_dma_alloc(len, 4096) };
                assert!(!p.is_null());
                std::hint::black_box(p);
                unsafe { nvs_dma_free(p) };
            }
            eprintln!(
                "dma_pool_miss len={len} ns/op={:.1}",
                t0.elapsed().as_nanos() as f64 / rounds as f64
            );
        }
    }
}
