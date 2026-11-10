// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! eal-heap: the DPDK EAL hugepage heap of the SPDK builds (adr 0061 am. 4, adr 0076): a memory-only EAL for the kernel NVMe
//! backend ([`eal_init`]), a global allocator wrapper that places payload-sized allocations in EAL memory ([`HugeAlloc`],
//! recycled by size class), heap statistics for the store's DMA budget ([`eal_heap_stats`]) and the process-lifetime
//! mapped ranges an RDMA device registers for zero-copy sends ([`pinned_ranges`]). No NIC code: networking is kernel TCP.
//! The DPDK archives are linked once by crate `dpdk-link` (feature `spdk`).
#![cfg(feature = "spdk")]

// carries the native DPDK link line (single owner of the archives)
extern crate dpdk_link as _;

use core::ffi::{CStr, c_char, c_int, c_void};
use std::ffi::CString;

unsafe extern "C" {
    fn nv_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
    fn nv_errno() -> c_int;
    fn nv_strerror(e: c_int) -> *const c_char;
}

/// EAL error: negative return code or rte_errno.
#[derive(Debug)]
pub struct Error(pub String);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

fn err(what: &str, code: c_int) -> Error {
    // SAFETY: rte_strerror returns a valid static/thread-local C string.
    let s = unsafe { CStr::from_ptr(nv_strerror(code.abs())) };
    Error(format!("{what}: {} ({code})", s.to_string_lossy()))
}

/// Initialise the EAL (once per process). `args[0]` is the program name.
pub fn eal_init(args: &[&str]) -> Result<(), Error> {
    let cs: Vec<CString> = args.iter().map(|a| CString::new(*a).unwrap()).collect();
    let mut ptrs: Vec<*mut c_char> = cs.iter().map(|c| c.as_ptr().cast_mut()).collect();
    ptrs.push(core::ptr::null_mut());
    // SAFETY: argv is NUL-terminated array of valid C strings that outlive the call (EAL may permute it).
    let r = unsafe { nv_eal_init(args.len() as c_int, ptrs.as_mut_ptr()) };
    if r < 0 {
        // SAFETY: plain getter.
        return Err(err("rte_eal_init", unsafe { nv_errno() }));
    }
    Ok(())
}

unsafe extern "C" {
    fn nv_big_alloc(size: usize, align: usize, zero: c_int) -> *mut c_void;
    fn nv_big_free(p: *mut c_void);
    fn nv_is_dpdk_mem(p: *const c_void) -> c_int;
    fn nv_pinned_ranges(out: *mut u64, max: c_int) -> c_int;
    fn nv_heap_stats(out: *mut u64);
}

/// `(addr, len)` of the EAL memory that stays mapped for the life of the process (preallocated at init, never freed),
/// adjacent segments merged: what an RDMA device may register once for zero-copy sends of heap payloads. Empty before
/// `eal_init`. Not on a data path.
pub fn pinned_ranges() -> Vec<(u64, u64)> {
    let mut max = 64;
    loop {
        let mut out = vec![0u64; 2 * max];
        // SAFETY: `out` has room for `max` pairs; the walk only reads the memseg lists.
        let n = unsafe { nv_pinned_ranges(out.as_mut_ptr(), max as c_int) };
        if n >= 0 {
            return out
                .as_chunks::<2>()
                .0
                .iter()
                .take(n as usize)
                .map(|&[a, l]| (a, l))
                .collect();
        }
        max *= 4;
    }
}

/// True if `p` points into DPDK-managed (hugepage) memory.
#[inline]
pub fn is_dpdk_mem(p: *const u8) -> bool {
    // SAFETY: only compares the address against the EAL memory segment lists.
    unsafe { nv_is_dpdk_mem(p.cast()) != 0 }
}

static HUGE_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static HUGE_LIMIT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(512 << 20);
static HUGE_USED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Maximum of `HUGE_USED` since start (raised only when a reservation succeeds, i.e. on EAL allocations).
static HUGE_PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static HUGE_FALLBACKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Start placing large allocations ([`HUGE_MIN`] and up) in DPDK memory. Call once after `eal_init`.
pub fn enable_huge_alloc() {
    enable_huge_alloc_with_budget(512 << 20);
}

/// Enable mapped payload allocations within a process-wide byte budget. Call once after EAL init,
/// before starting worker threads. Budget exhaustion falls back to the inner allocator/copy TX.
pub fn enable_huge_alloc_with_budget(bytes: usize) {
    // the pool's queues come from the inner allocator: created before large allocations switch to DPDK memory
    POOL.get_or_init(|| Park::new(bytes));
    HUGE_LIMIT.store(bytes, std::sync::atomic::Ordering::Relaxed);
    HUGE_READY.store(true, std::sync::atomic::Ordering::Release);
}

/// Configured mapped payload allocation mode (individual small/fallback buffers can still copy).
pub fn huge_alloc_enabled() -> bool {
    HUGE_READY.load(std::sync::atomic::Ordering::Acquire)
}

/// `(total, free, largest free block)` bytes of the EAL malloc heap, all sockets: the hugepages that payloads and SPDK
/// DMA buffers share (adr 0076). Call only after `eal_init` (or the SPDK env init, which brings the EAL up).
pub fn eal_heap_stats() -> (u64, u64, u64) {
    let mut h = [0u64; 3];
    // SAFETY: the EAL is initialized (caller contract); writes 3 u64.
    unsafe { nv_heap_stats(h.as_mut_ptr()) };
    (h[0], h[1], h[2])
}

/// `(live requested bytes, cap, fallback allocations)` for diagnostics; EAL overhead is additional.
pub fn huge_alloc_stats() -> (usize, usize, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (
        HUGE_USED.load(Relaxed),
        HUGE_LIMIT.load(Relaxed),
        HUGE_FALLBACKS.load(Relaxed),
    )
}

// Recycled payload blocks (adr 0061 am. 4, adr 0163 am.; large classes: adr 0163 am. 2): every client write / read
// reply allocates and frees one payload-sized block; `rte_free` zeroes the whole block (DPDK keeps free memory zeroed
// for rte_zmalloc) and `rte_malloc` searches the heap: ~0.4 ms of memset per 4 MiB op on whatever core drops the
// payload, 64 MiB for an object-sized payload. Requests of `HUGE_MIN..=CLASSES.last()` (alignment <= 4096) are allocated
// at the size of the smallest class that fits (payload + header slack, steps <= 1.8x up to 4 MiB, <= 1.5x above up to
// the 128 MiB object limit) and parked on free in a lock-free queue per class; the next allocation of the class takes
// one (any core). Bytes stay counted in `HUGE_USED` while parked, so the budget bounds parked plus live bytes, and every
// block that was ever live at once can be parked: a queue holds `budget / class` blocks (adr 0061 am. 10). A fixed
// slot count (16) overflowed in bursts of client writes (35-50 payload blocks freed in one PG-core iteration, each
// overflow `rte_free` zeroing its block there, doc/perf/payload-heap-20261025.md). Blocks are really freed only when the
// budget is short for another request (`pool_release`: the shortfall only, each `rte_free` zeroes its block on the
// calling core). Waste: a block is at most 1.8x (<= 4 MiB) / 1.5x (above) the request; exact 128 KiB requests (checkpoint
// arena chunks of one 128 KiB device write, store `fzarena`) have their own class (in 192 KiB they wasted a third).
const CLASSES: [usize; 20] = [
    128 << 10,
    192 << 10,
    320 << 10,
    576 << 10,
    832 << 10,
    1088 << 10,
    (1536 + 64) << 10,
    (2048 + 64) << 10,
    (3072 + 64) << 10,
    (4096 + 64) << 10,
    (6144 + 64) << 10,
    (8192 + 64) << 10,
    (12288 + 64) << 10,
    (16384 + 64) << 10,
    (24576 + 64) << 10,
    (32768 + 64) << 10,
    (49152 + 64) << 10,
    (65536 + 64) << 10,
    (98304 + 64) << 10,
    (131072 + 64) << 10,
];

/// Parked blocks (addresses) per class.
struct Park(Box<[crossbeam_queue::ArrayQueue<usize>]>);

impl Park {
    /// Room for every block of each class that fits `budget` at once (at least one).
    fn new(budget: usize) -> Self {
        Self(
            CLASSES
                .iter()
                .map(|c| crossbeam_queue::ArrayQueue::new((budget / c).max(1)))
                .collect(),
        )
    }
    fn take(&self, c: usize) -> *mut u8 {
        self.0[c]
            .pop()
            .map_or(core::ptr::null_mut(), |a| a as *mut u8)
    }
    /// False when the queue is full (only when the budget grew after [`Park::new`]).
    fn put(&self, c: usize, p: *mut u8) -> bool {
        self.0[c].push(p as usize).is_ok()
    }
}

/// The payload pool, sized by the first [`enable_huge_alloc_with_budget`] (before any block is allocated in DPDK memory).
static POOL: std::sync::OnceLock<Park> = std::sync::OnceLock::new();

#[expect(clippy::declare_interior_mutable_const)]
const ZERO_CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Per class: allocations served from the pool.
static POOL_HITS: [std::sync::atomic::AtomicU64; CLASSES.len()] = [ZERO_CTR; CLASSES.len()];
/// Per class: allocations not served from the pool (a fresh `rte_malloc`, or the inner allocator when the budget is out).
static POOL_MISSES: [std::sync::atomic::AtomicU64; CLASSES.len()] = [ZERO_CTR; CLASSES.len()];
/// Per class: `rte_free` calls (released for a budget shortfall, or no room in the pool): each zeroes the whole block.
static POOL_FREES: [std::sync::atomic::AtomicU64; CLASSES.len()] = [ZERO_CTR; CLASSES.len()];
/// Requests the pool does not cover (over-aligned, above the last class): allocations tried in DPDK memory / `rte_free` calls.
static UNPOOLED_ALLOCS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static UNPOOLED_FREES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Payload pool counters as `(name, value)` for `perf dump` (logger `flashstore_payload_pool`): `used_bytes` / `limit_bytes`
/// / `fallbacks` repeat [`huge_alloc_stats`], `used_peak_bytes` the maximum of `used_bytes`, `parked_bytes` (inside
/// `used_bytes`), `unpooled_*` the requests no class covers, per class `c<KiB>_hits|misses|frees` (frees = `rte_free`
/// calls, each one zeroes the whole block). Once the pool is enabled (EAL up): `eal_heap_total_bytes`,
/// `eal_heap_free_bytes`, `eal_heap_largest_free_bytes` of the EAL malloc heap, which SPDK DMA buffers share (adr 0076).
pub fn huge_pool_counters() -> Vec<(String, u64)> {
    use std::sync::atomic::Ordering::Relaxed;
    let (used, limit, fallbacks) = huge_alloc_stats();
    let mut v = vec![
        ("used_bytes".to_owned(), used as u64),
        ("limit_bytes".to_owned(), limit as u64),
        ("fallbacks".to_owned(), fallbacks),
        ("used_peak_bytes".to_owned(), HUGE_PEAK.load(Relaxed) as u64),
        ("parked_bytes".to_owned(), PARKED.load(Relaxed) as u64),
        ("unpooled_allocs".to_owned(), UNPOOLED_ALLOCS.load(Relaxed)),
        ("unpooled_frees".to_owned(), UNPOOLED_FREES.load(Relaxed)),
    ];
    for (c, size) in CLASSES.iter().enumerate() {
        let k = size >> 10;
        v.push((format!("c{k}_hits"), POOL_HITS[c].load(Relaxed)));
        v.push((format!("c{k}_misses"), POOL_MISSES[c].load(Relaxed)));
        v.push((format!("c{k}_frees"), POOL_FREES[c].load(Relaxed)));
    }
    // the pool is enabled only after the EAL is up
    if HUGE_READY.load(std::sync::atomic::Ordering::Acquire) {
        let (total, free, largest) = eal_heap_stats();
        v.push(("eal_heap_total_bytes".to_owned(), total));
        v.push(("eal_heap_free_bytes".to_owned(), free));
        v.push(("eal_heap_largest_free_bytes".to_owned(), largest));
    }
    v
}

/// Alignment of every pooled block (page aligned: serves 4 KiB-aligned IO buffers of the kernel NVMe tier as well).
const BLOCK_ALIGN: usize = 4096;

/// Class index of a request (`None`: not pooled: over-aligned or above the last class).
#[inline]
fn class_of(l: core::alloc::Layout) -> Option<usize> {
    if l.align() > BLOCK_ALIGN {
        return None;
    }
    CLASSES.iter().position(|c| *c >= l.size())
}

/// A parked block of class `c`, if any.
fn pool_take(c: usize) -> *mut u8 {
    let p = POOL.get().map_or(core::ptr::null_mut(), |q| q.take(c));
    if !p.is_null() {
        PARKED.fetch_sub(CLASSES[c], std::sync::atomic::Ordering::Relaxed);
    }
    p
}

/// Park `p` (a class-`c` block); false when there is no room.
fn pool_put(c: usize, p: *mut u8) -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    // counted before the block is visible: a concurrent take subtracts it
    PARKED.fetch_add(CLASSES[c], Relaxed);
    let parked = POOL.get().is_some_and(|q| q.put(c, p));
    if !parked {
        PARKED.fetch_sub(CLASSES[c], Relaxed);
    }
    parked
}

/// Bytes of parked blocks (inside `HUGE_USED`).
static PARKED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

thread_local! {
    /// EAL heap calls of this thread since the last [`eal_diag_take`]: `[rte_malloc calls, bytes, rte_free calls, bytes]`.
    /// Each `rte_free` zeroes its block on the calling core (stall diagnostics, `NV_PHASE`).
    static EAL_OPS: core::cell::Cell<[u64; 4]> = const { core::cell::Cell::new([0; 4]) };
}

fn eal_note(i: usize, bytes: usize) {
    // `try_with`: the allocator also runs while thread-locals are torn down
    let _ = EAL_OPS.try_with(|c| {
        let mut v = c.get();
        v[i] += 1;
        v[i + 1] += bytes as u64;
        c.set(v);
    });
}

/// EAL heap calls of this thread since the previous call, `[rte_malloc calls, bytes, rte_free calls, bytes]` (each
/// `rte_free` zeroes its block on this core), and reset.
pub fn eal_diag_take() -> [u64; 4] {
    EAL_OPS.try_with(|c| c.replace([0; 4])).unwrap_or([0; 4])
}

/// `rte_free` of a parked class-`c` block taken out of the pool.
fn free_parked(c: usize, p: *mut u8) {
    use std::sync::atomic::Ordering::Relaxed;
    // SAFETY: a parked block was allocated by nv_big_alloc at CLASSES[c] bytes, and it is ours now.
    unsafe { nv_big_free(p.cast()) };
    eal_note(2, CLASSES[c]);
    HUGE_USED.fetch_sub(CLASSES[c], Relaxed);
    POOL_FREES[c].fetch_add(1, Relaxed);
}

/// Budget exhausted: really free parked blocks until `need` bytes are released, and return the bytes released (0 when
/// the parked blocks cannot cover `need`: nothing is freed for a request that falls back anyway). `rte_free` zeroes
/// its block on the calling core, so the cost is the bytes freed, not the bytes parked: the smallest parked block of at
/// least `need` first; without one, the largest smaller blocks until `need` is covered (freed < 2 `need`). Freeing
/// every parked block instead cost a PG core 7-14 ms for one parked 128 MiB block (doc/perf/bmix-tail-20261025.md).
fn pool_release(need: usize) -> usize {
    if PARKED.load(std::sync::atomic::Ordering::Relaxed) < need {
        return 0;
    }
    let first = CLASSES
        .iter()
        .position(|c| *c >= need)
        .unwrap_or(CLASSES.len());
    for (c, &size) in CLASSES.iter().enumerate().skip(first) {
        let p = pool_take(c);
        if !p.is_null() {
            free_parked(c, p);
            return size;
        }
    }
    let mut got = 0;
    for c in (0..first).rev() {
        while got < need {
            let p = pool_take(c);
            if p.is_null() {
                break;
            }
            free_parked(c, p);
            got += CLASSES[c];
        }
    }
    got
}

unsafe fn try_huge(l: core::alloc::Layout, zero: c_int) -> *mut u8 {
    use std::sync::atomic::Ordering::Relaxed;
    // rte_malloc accepts unsigned alignment. Never truncate a valid Rust layout's
    // alignment in the shim: let the inner allocator handle it instead.
    if l.align() > core::ffi::c_uint::MAX as usize {
        return core::ptr::null_mut();
    }
    let class = class_of(l);
    let size = if let Some(c) = class {
        let p = pool_take(c);
        if !p.is_null() {
            POOL_HITS[c].fetch_add(1, Relaxed);
            if zero != 0 {
                // SAFETY: a parked class-c block of CLASSES[c] >= l.size() bytes, now ours.
                unsafe { core::ptr::write_bytes(p, 0, l.size()) };
            }
            return p;
        }
        POOL_MISSES[c].fetch_add(1, Relaxed);
        CLASSES[c]
    } else {
        UNPOOLED_ALLOCS.fetch_add(1, Relaxed);
        l.size()
    };
    let cap = HUGE_LIMIT.load(Relaxed);
    let reserve = || match HUGE_USED.try_update(Relaxed, Relaxed, |used| {
        used.checked_add(size).filter(|n| *n <= cap)
    }) {
        Ok(prev) => {
            HUGE_PEAK.fetch_max(prev + size, Relaxed);
            true
        }
        Err(_) => false,
    };
    let reserved = reserve() || {
        let short = (HUGE_USED.load(Relaxed) + size).saturating_sub(cap);
        pool_release(short) > 0 && reserve()
    };
    if reserved {
        // SAFETY: forwarded allocation contract. Reservation is released on failure or deallocation.
        let p = unsafe {
            nv_big_alloc(
                size,
                if class.is_some() {
                    BLOCK_ALIGN
                } else {
                    l.align()
                },
                zero,
            )
        };
        if !p.is_null() {
            eal_note(0, size);
            return p.cast();
        }
        HUGE_USED.fetch_sub(size, Relaxed);
    }
    HUGE_FALLBACKS.fetch_add(1, Relaxed);
    core::ptr::null_mut()
}

/// Allocations of at least this many bytes go to the EAL heap once enabled (message payloads: 4 MiB objects, 128 KiB+
/// extents; everything smaller stays in the inner allocator).
pub const HUGE_MIN: usize = 128 * 1024;

/// Global allocator wrapper: small allocations go to `A` (e.g. mimalloc), large ones to `rte_malloc` after
/// [`enable_huge_alloc`], so payload `Vec`s/`Bytes` are DMA-able (SPDK writes by reference, RDMA zero-copy sends)
/// instead of being copied. Frees dispatch on the address (`is_dpdk_mem`), so buffers allocated before
/// the switch are released by `A` as before.
#[derive(Debug)]
pub struct HugeAlloc<A>(pub A);

// SAFETY: forwards to `A` or to the thread-safe rte_malloc heap; every pointer is released by the allocator that made it
// (decided by the address), sizes/alignments are passed through unchanged.
unsafe impl<A: core::alloc::GlobalAlloc> core::alloc::GlobalAlloc for HugeAlloc<A> {
    unsafe fn alloc(&self, l: core::alloc::Layout) -> *mut u8 {
        if l.size() >= HUGE_MIN && HUGE_READY.load(std::sync::atomic::Ordering::Acquire) {
            // SAFETY: plain allocation call; null falls back to `A`.
            let p = unsafe { try_huge(l, 0) };
            if !p.is_null() {
                return p.cast();
            }
        }
        // SAFETY: same contract as ours.
        unsafe { self.0.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: core::alloc::Layout) -> *mut u8 {
        if l.size() >= HUGE_MIN && HUGE_READY.load(std::sync::atomic::Ordering::Acquire) {
            // SAFETY: as in `alloc`.
            let p = unsafe { try_huge(l, 1) };
            if !p.is_null() {
                return p.cast();
            }
        }
        // SAFETY: same contract as ours.
        unsafe { self.0.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: core::alloc::Layout) {
        if l.size() >= HUGE_MIN && is_dpdk_mem(p) {
            if let Some(c) = class_of(l) {
                if pool_put(c, p) {
                    return; // parked, still counted in HUGE_USED
                }
                // SAFETY: allocated by nv_big_alloc at CLASSES[c] bytes (the address is in EAL memory).
                unsafe { nv_big_free(p.cast()) };
                eal_note(2, CLASSES[c]);
                HUGE_USED.fetch_sub(CLASSES[c], std::sync::atomic::Ordering::Relaxed);
                POOL_FREES[c].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            // SAFETY: allocated by nv_big_alloc (the address is in EAL memory).
            unsafe { nv_big_free(p.cast()) };
            eal_note(2, l.size());
            HUGE_USED.fetch_sub(l.size(), std::sync::atomic::Ordering::Relaxed);
            UNPOOLED_FREES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            // SAFETY: allocated by `A` with this layout.
            unsafe { self.0.dealloc(p, l) };
        }
    }
    unsafe fn realloc(&self, p: *mut u8, l: core::alloc::Layout, new: usize) -> *mut u8 {
        if l.size() < HUGE_MIN && new < HUGE_MIN {
            // SAFETY: small -> small stays in `A`.
            return unsafe { self.0.realloc(p, l, new) };
        }
        // SAFETY: valid layout (size/align from the caller's, new size > 0 and fits isize by the caller's contract).
        let nl = unsafe { core::alloc::Layout::from_size_align_unchecked(new, l.align()) };
        // SAFETY: allocate, copy the common prefix, release the old block.
        unsafe {
            let np = self.alloc(nl);
            if !np.is_null() {
                core::ptr::copy_nonoverlapping(p, np, l.size().min(new));
                self.dealloc(p, l);
            }
            np
        }
    }
}
#[cfg(test)]
mod pool_class_tests {
    use super::*;
    use core::alloc::Layout;

    fn lay(n: usize, a: usize) -> Layout {
        Layout::from_size_align(n, a).unwrap()
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn alignment_beyond_eal_unsigned_range_falls_back() {
        let layout = lay(HUGE_MIN, 1usize << 32);
        // SAFETY: valid nonzero layout; unsupported alignment must be rejected
        // before any EAL access, so this test needs no initialized EAL heap.
        assert!(unsafe { try_huge(layout, 0) }.is_null());
    }

    #[test]
    fn classes_cover_128k_to_object_limit_with_header_slack() {
        const M: usize = 1 << 20;
        let class = |n: usize| class_of(lay(n, 1)).map(|c| CLASSES[c]);
        assert_eq!(class_of(lay(HUGE_MIN, 1)), Some(0));
        assert_eq!(
            class(HUGE_MIN),
            Some(HUGE_MIN),
            "exact 128 KiB blocks (device-write sized chunks) waste nothing"
        );
        assert_eq!(class(HUGE_MIN + 1), Some(192 << 10));
        assert_eq!(class_of(lay(1 << 20, 1)), Some(5));
        assert_eq!(class_of(lay((1 << 20) + 24, 8)), Some(5));
        assert_eq!(class(4 * M), Some(4 * M + (64 << 10)));
        assert_eq!(class(4 * M + (64 << 10)), Some(4 * M + (64 << 10)));
        // object-sized payloads (64 / 128 MiB + header) land in their own class
        assert_eq!(class(64 * M + 4096), Some(64 * M + (64 << 10)));
        assert_eq!(class(128 * M), Some(128 * M + (64 << 10)));
        assert_eq!(class(128 * M + (64 << 10)), Some(128 * M + (64 << 10)));
        assert_eq!(class(128 * M + (64 << 10) + 1), None);
        assert_eq!(class_of(lay(1 << 20, 4096)), Some(5));
        assert_eq!(class_of(lay(1 << 20, 8192)), None);
        assert!(CLASSES.windows(2).all(|w| w[0] < w[1]));
        // waste bound: <= 1.8x up to 4 MiB, <= 1.5x above
        assert!(CLASSES.windows(2).all(|w| {
            let max = if w[1] <= 4 * M + (64 << 10) { 18 } else { 15 };
            w[1] * 10 <= w[0] * max
        }));
    }

    #[test]
    fn park_holds_every_block_the_budget_admits() {
        const G: usize = 1 << 30;
        let park = Park::new(G);
        // as many blocks of a class as fit the budget at once, for every class
        for (c, &size) in CLASSES.iter().enumerate() {
            assert_eq!(park.0[c].capacity(), G / size);
        }
        let c = 3; // 576 KiB: b-fill bursts freed 35-50 of these in one PG-core iteration (16 slots before)
        let n = G / CLASSES[c];
        for i in 0..n {
            assert!(park.put(c, (0x10000 + i * 4096) as *mut u8));
        }
        assert!(
            !park.put(c, 0x9000 as *mut u8),
            "more blocks than the budget admits"
        );
        let mut got: Vec<*mut u8> = (0..n).map(|_| park.take(c)).collect();
        got.sort();
        assert!(
            got.iter()
                .enumerate()
                .all(|(i, p)| *p as usize == 0x10000 + i * 4096)
        );
        assert!(park.take(c).is_null());
        // a class larger than the budget still has one place (never reached: its reservation fails)
        let small = Park::new(CLASSES[0]);
        assert_eq!(small.0[CLASSES.len() - 1].capacity(), 1);
    }

    #[test]
    fn parked_blocks_are_per_class() {
        let park = Park::new(1 << 30);
        let (a, b) = (0x1000 as *mut u8, 0x2000 as *mut u8);
        assert!(park.take(15).is_null());
        assert!(park.put(15, a));
        assert!(park.take(16).is_null());
        assert!(park.put(16, b));
        assert_eq!(park.take(15), a);
        assert!(park.take(15).is_null());
        assert_eq!(park.take(16), b);
    }
}
