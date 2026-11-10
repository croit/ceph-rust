// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Per-thread recycling of SPDK DMA buffers (adr 0163 am. 3). `spdk_dma_free` is `rte_free`, which memsets the whole
//! block (DPDK keeps free heap memory zeroed) and `spdk_dma_malloc` searches the heap: ~0.4 ms of memset per 4 MiB.
//!
//! Small buffers (whole 4 KiB blocks, up to [`MAX_SMALL_BLK`]) recycle through exact-size bins. Larger buffers (any
//! length above the small range up to the last class) are allocated at the size of the smallest class that fits
//! (steps <= 1.5x) and parked per class. Thread-per-core: the owner thread allocates and frees; a foreign free lands
//! in that thread's pool. Parked bytes per thread are bounded by [`CAP_BYTES`]; a DMA allocation the heap refuses
//! (fragmentation, another heap user) bumps a process-wide epoch, every pool drops its parked blocks at its next
//! operation or at its owner's next [`crate::spdk::DmaBuf::release_pooled`] (the store sweep of every core).
//!
//! DMA budget (adr 0175 am. 4, [`DmaBudget`]): every block DMA buffers hold from the DPDK heap (live, parked, in a
//! return inbox) counts against one process-wide budget, the store's share of the EAL heap. Two kinds of store memory:
//! deferrable memory (asynchronous reads, staged write copies, parked blocks, shared data in transit: may be held without
//! IO in flight) is admitted only within [`READ_GATE_QUARTERS`] of it ([`DmaBudget::try_take`]); in-flight IO memory
//! (allocated right before a device submit, released by its completion: WAL records, tree pages, checkpoint, omap runs,
//! synchronous reads, deferred write copies) within all of it ([`DmaBudget::try_take_io`]). Memory held without IO in
//! flight therefore never exceeds the gate, and a refused IO request (at most a quarter) always has IO in flight ahead
//! of it whose completion frees memory. Nothing waits for memory while holding IO memory: a refused request is postponed
//! by its caller and retried at its next progress step. Read data that leaves the store zero-copy (shared reply data in
//! transit) holds at most [`SHARE_QUARTERS`] of it; beyond, it leaves as a heap copy. The budget, not the heap, is what a busy OSD runs
//! into: a request refused at the gate trades its own core's parked blocks for its request ([`Pool::trim`], only as
//! many as it needs) and leaves its size as [`DmaBudget::want`]: until room for it exists, freed blocks do not park and
//! every store sweep gives back parked blocks. No drain storm: a full drain of every pool (memsets under the DPDK heap
//! lock on all cores) is left to a real heap refusal.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Exact-size bins for 1..=this many whole 4 KiB blocks (1 MiB).
pub(crate) const MAX_SMALL_BLK: usize = 256;
/// Bytes parked per thread (small and large); beyond this buffers go back to DPDK.
pub(crate) const CAP_BYTES: usize = 256 << 20;
/// Parked bytes per large class are at most `max(SLOT_BYTES, 2 class)`.
const SLOT_BYTES: usize = 128 << 20;
const MAX_SLOTS: usize = 16;
const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;

/// Large classes: steps <= 1.5x from 1 MiB to the 128 MiB object limit + 64 KiB header slack.
pub(crate) const CLASSES: [usize; 15] = [
    3 * MIB / 2,
    2 * MIB,
    3 * MIB,
    4 * MIB,
    6 * MIB,
    8 * MIB,
    12 * MIB,
    16 * MIB,
    24 * MIB,
    32 * MIB,
    48 * MIB,
    64 * MIB,
    96 * MIB,
    128 * MIB,
    128 * MIB + 64 * KIB,
];

/// Index of the smallest large class that holds `len` bytes (`None`: not a large buffer, or above the last class).
#[inline]
pub(crate) fn large_class(len: usize) -> Option<usize> {
    if len <= MAX_SMALL_BLK * 4096 {
        return None;
    }
    CLASSES.iter().position(|c| *c >= len)
}

/// Exact-size bin of a small buffer.
#[inline]
pub(crate) fn small_class(len: usize) -> Option<usize> {
    crate::block_class(len, MAX_SMALL_BLK)
}

/// Parking slots of large class `c`.
pub(crate) const fn slots_of(c: usize) -> usize {
    let n = SLOT_BYTES / CLASSES[c];
    if n < 2 {
        2
    } else if n > MAX_SLOTS {
        MAX_SLOTS
    } else {
        n
    }
}

/// Bytes the allocator is asked for (and the budget counts): the class size of a large buffer, else `len`.
#[inline]
pub fn alloc_len(len: usize) -> usize {
    large_class(len).map_or(len, |c| CLASSES[c])
}

#[expect(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);
/// Per large class: allocations served from the pool / not served / `spdk_dma_free` calls (each one memsets the block).
static HITS: [AtomicU64; CLASSES.len()] = [ZERO; CLASSES.len()];
static MISSES: [AtomicU64; CLASSES.len()] = [ZERO; CLASSES.len()];
static FREES: [AtomicU64; CLASSES.len()] = [ZERO; CLASSES.len()];
/// Allocations above the last class / `spdk_dma_free` calls of them.
static UNPOOLED_ALLOCS: AtomicU64 = AtomicU64::new(0);
static UNPOOLED_FREES: AtomicU64 = AtomicU64::new(0);
/// Large bytes currently parked, all threads.
static PARKED_LARGE: AtomicU64 = AtomicU64::new(0);
/// Bumped on a failed DMA allocation: every pool drops its parked blocks at its next operation.
pub(crate) static EPOCH: AtomicU64 = AtomicU64::new(0);
static PRESSURE_DRAINS: AtomicU64 = AtomicU64::new(0);

/// Quarters of the budget deferrable store memory is admitted within (asynchronous reads, staged write copies, parked
/// blocks, shared data in transit: memory that may be held without IO in flight): everything held plus the request stays
/// within three quarters. The last quarter only ever holds in-flight IO memory (allocated right before a device submit,
/// released by its completion: [`DmaBudget::try_take_io`]), so it always drains, whatever the deferrable side holds.
pub const READ_GATE_QUARTERS: u64 = 3;
/// Quarters of the budget shared read data in transit may hold zero-copy ([`DmaBudget::share`]): at most half, so the
/// store's own read pipeline keeps at least a quarter (gate minus share) whatever the network and the peers hold. Data
/// in transit waits for the network and, on an EC primary, for the shards of other OSDs; if it could hold the whole
/// gate, two OSDs whose reads each wait for the other's sub-read would wait for each other forever.
pub const SHARE_QUARTERS: u64 = 2;

/// DMA memory accounting of the process (adr 0175 am. 4): bytes DMA buffers hold from the DPDK heap (`held`: live,
/// parked, in a return inbox; touched only on `spdk_dma_malloc|free`), the budget they share, and the bytes of shared
/// read data in transit. One static instance ([`BUDGET`]); tests make their own.
#[derive(Debug)]
pub struct DmaBudget {
    /// Store DMA budget in bytes; 0 = none set (tools, tests: only the heap limits).
    limit: AtomicU64,
    held: AtomicU64,
    held_peak: AtomicU64,
    /// Block bytes of DMA buffers that left the store zero-copy as shared data and are still referenced.
    shared: AtomicU64,
    shared_peak: AtomicU64,
    /// Deferrable / in-flight IO memory refused (gate / budget full after this thread traded its parked blocks; the caller postpones)
    /// / heap requests refused within the budget (NULL: fragmentation, other heap users).
    data_short: AtomicU64,
    io_short: AtomicU64,
    heap_short: AtomicU64,
    /// Shared read data copied to heap memory because the in-transit share was full.
    share_copies: AtomicU64,
    /// Largest data request refused at the gate that still has no room ([`DmaBudget::want`]); 0 = none.
    want: AtomicU64,
}

impl Default for DmaBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaBudget {
    pub const fn new() -> Self {
        DmaBudget {
            limit: AtomicU64::new(0),
            held: AtomicU64::new(0),
            held_peak: AtomicU64::new(0),
            shared: AtomicU64::new(0),
            shared_peak: AtomicU64::new(0),
            data_short: AtomicU64::new(0),
            io_short: AtomicU64::new(0),
            heap_short: AtomicU64::new(0),
            share_copies: AtomicU64::new(0),
            want: AtomicU64::new(0),
        }
    }

    /// Set the budget (bytes; 0 = none).
    pub fn set_limit(&self, bytes: u64) {
        self.limit.store(bytes, Relaxed);
    }

    pub fn limit(&self) -> u64 {
        self.limit.load(Relaxed)
    }

    pub fn held(&self) -> u64 {
        self.held.load(Relaxed)
    }

    /// Bytes of shared read data in transit (block bytes).
    pub fn shared(&self) -> u64 {
        self.shared.load(Relaxed)
    }

    /// What fresh data allocations are admitted within ([`READ_GATE_QUARTERS`]); `u64::MAX` without a budget.
    pub fn read_gate(&self) -> u64 {
        match self.limit() {
            0 => u64::MAX,
            l => l / 4 * READ_GATE_QUARTERS,
        }
    }

    /// Bytes of the largest data request refused at the gate for which no room exists yet (0 = none): set by the
    /// refusal ([`DmaBudget::note_data_short`]), cleared once everything held leaves room for it (an admission at
    /// least that large, or a pool that gave back enough, [`DmaBudget::settle_want`]). While set, every pool gives
    /// parked blocks back and frees instead of parking, on whichever core: a refused core whose own pool is empty is
    /// not left waiting for parked memory of another core that allocates nothing.
    pub fn want(&self) -> u64 {
        self.want.load(Relaxed)
    }

    /// Everything held plus the refused request waiting for room ([`DmaBudget::want`]) is above the read gate: freed
    /// blocks go back to the heap instead of parking.
    #[inline]
    pub fn above_gate(&self) -> bool {
        self.held().saturating_add(self.want()) > self.read_gate()
    }

    /// Clear [`DmaBudget::want`] when everything held leaves room for it now (its request is admitted at its retry).
    pub fn settle_want(&self) {
        let w = self.want();
        if w != 0 && self.held().saturating_add(w) <= self.read_gate() {
            let _ = self.want.compare_exchange(w, 0, Relaxed, Relaxed);
        }
    }

    fn share_cap(&self) -> u64 {
        match self.limit() {
            0 => u64::MAX,
            l => l / 4 * SHARE_QUARTERS,
        }
    }

    /// Count `bytes` the heap is asked for, unconditionally (tools and tests: no store, nothing to postpone).
    pub fn take(&self, bytes: usize) {
        let h = self.held.fetch_add(bytes as u64, Relaxed) + bytes as u64;
        self.held_peak.fetch_max(h, Relaxed);
    }

    /// Count `bytes` (true) when everything held plus them stays within `cap`; else nothing counted (false).
    fn take_within(&self, bytes: usize, cap: u64) -> bool {
        let n = bytes as u64;
        match self
            .held
            .try_update(Relaxed, Relaxed, |h| h.checked_add(n).filter(|&t| t <= cap))
        {
            Ok(h) => {
                self.held_peak.fetch_max(h + n, Relaxed);
                true
            }
            Err(_) => false,
        }
    }

    /// Admit `bytes` the heap is asked for by deferrable store memory: counted and true while everything held stays within the
    /// read gate, else nothing counted and false. An admission at least as large as [`DmaBudget::want`] clears it.
    pub fn try_take(&self, bytes: usize) -> bool {
        if !self.take_within(bytes, self.read_gate()) {
            return false;
        }
        let w = self.want();
        if w != 0 && bytes as u64 >= w {
            let _ = self.want.compare_exchange(w, 0, Relaxed, Relaxed);
        }
        true
    }

    /// Admit `bytes` the heap is asked for by in-flight IO memory (allocated right before a device submit, released by its
    /// completion): counted and true while everything held stays within the budget (no budget: always), else nothing
    /// counted and false.
    pub fn try_take_io(&self, bytes: usize) -> bool {
        let cap = match self.limit() {
            0 => u64::MAX,
            l => l,
        };
        self.take_within(bytes, cap)
    }

    /// A data request of `bytes` was refused at the gate (the caller postpones it): it becomes [`DmaBudget::want`]
    /// when it is the largest one waiting.
    pub fn note_data_short(&self, bytes: usize) {
        self.data_short.fetch_add(1, Relaxed);
        self.want.fetch_max(bytes as u64, Relaxed);
    }

    /// An in-flight IO request was refused (the caller postpones it; everything held is above the gate, so every store
    /// sweep gives parked blocks back).
    pub fn note_io_short(&self) {
        self.io_short.fetch_add(1, Relaxed);
    }

    /// `bytes` went back to the DPDK heap.
    pub fn give(&self, bytes: usize) {
        self.held.fetch_sub(bytes as u64, Relaxed);
    }

    /// A counted request of `bytes` the heap did not serve.
    pub fn untake(&self, bytes: usize) {
        self.held.fetch_sub(bytes as u64, Relaxed);
    }

    /// The heap refused a request within the budget (fragmentation, other heap users).
    pub fn note_heap_short(&self) {
        self.heap_short.fetch_add(1, Relaxed);
    }

    /// A shared read buffer of `bytes` block bytes may leave zero-copy: counted and true while the data in transit stays
    /// within [`SHARE_QUARTERS`] of the budget and, for in-flight IO memory (`io`: it stops being in flight here), while
    /// everything held stays within the read gate; false = it leaves as a heap copy (counted as `share_copies`). So
    /// memory held without IO in flight never exceeds the read gate.
    pub fn share(&self, bytes: usize, io: bool) -> bool {
        let cap = self.share_cap();
        let n = bytes as u64;
        if !(io && self.held() > self.read_gate())
            && let Ok(s) = self
                .shared
                .try_update(Relaxed, Relaxed, |s| s.checked_add(n).filter(|&t| t <= cap))
        {
            self.shared_peak.fetch_max(s + n, Relaxed);
            return true;
        }
        self.share_copies.fetch_add(1, Relaxed);
        false
    }

    /// The last reference of a shared buffer of `bytes` block bytes dropped.
    pub fn unshare(&self, bytes: usize) {
        self.shared.fetch_sub(bytes as u64, Relaxed);
    }

    fn counters(&self, v: &mut Vec<(String, u64)>) {
        for (n, c) in [
            ("budget_bytes", &self.limit),
            ("held_bytes", &self.held),
            ("held_peak_bytes", &self.held_peak),
            ("shared_bytes", &self.shared),
            ("shared_peak_bytes", &self.shared_peak),
            ("data_short", &self.data_short),
            ("io_short", &self.io_short),
            ("heap_short", &self.heap_short),
            ("share_copies", &self.share_copies),
            ("want_bytes", &self.want),
        ] {
            v.push((n.to_owned(), c.load(Relaxed)));
        }
    }
}

/// The process's DMA accounting: the SPDK side's share of the EAL heap (adr 0076, adr 0175 am. 4).
pub static BUDGET: DmaBudget = DmaBudget::new();

/// Set the store DMA budget (bytes; the daemon derives it at start: EAL heap free once SPDK and every device queue are
/// set up, less the payload budget). 0 = none.
pub fn set_budget(bytes: u64) {
    BUDGET.set_limit(bytes);
}

/// Pool counters as `(name, value)` for `perf dump` (logger `flashstore_dma_pool`): `budget_bytes` (the store DMA budget,
/// 0 = none), `held_bytes` (gauge: bytes from the DPDK heap, live + parked + in transit) and `held_peak_bytes` (its
/// maximum since start), `shared_bytes` / `shared_peak_bytes` (shared read data in transit zero-copy), `data_short`
/// (deferrable store memory postponed: the read gate was full after this core traded its parked blocks), `io_short`
/// (in-flight IO memory postponed: the whole budget was in use), `heap_short` (the heap refused a request within the
/// budget), `share_copies` (shared read data copied to heap memory: the in-transit share was full), `want_bytes` (gauge:
/// the largest refused data request still without room, [`DmaBudget::want`]), `parked_large_bytes` (gauge), `pressure_drains` (heap refusals within the budget: each asks every pool to drop its
/// parked blocks; expected 0), `return_hits` (shared read buffers taken back by the core that allocated them, any size) / `return_refused` (owner
/// gone or without an inbox: the dropping thread pools the buffer instead), `unpooled_allocs|frees` (above the last
/// class), per large class `c<KiB>_hits|misses|frees` (frees = `spdk_dma_free` calls = memsets; steady state ~ 0).
/// Buffers up to 1 MiB (exact-size bins) have no class counters.
pub fn counters() -> Vec<(String, u64)> {
    let ret = RETURNS.stats();
    let mut v = Vec::new();
    BUDGET.counters(&mut v);
    v.extend([
        ("parked_large_bytes".to_owned(), PARKED_LARGE.load(Relaxed)),
        ("pressure_drains".to_owned(), PRESSURE_DRAINS.load(Relaxed)),
        ("return_hits".to_owned(), ret.0),
        ("return_refused".to_owned(), ret.1),
        ("unpooled_allocs".to_owned(), UNPOOLED_ALLOCS.load(Relaxed)),
        ("unpooled_frees".to_owned(), UNPOOLED_FREES.load(Relaxed)),
    ]);
    for (c, size) in CLASSES.iter().enumerate() {
        let k = size >> 10;
        v.push((format!("c{k}_hits"), HITS[c].load(Relaxed)));
        v.push((format!("c{k}_misses"), MISSES[c].load(Relaxed)));
        v.push((format!("c{k}_frees"), FREES[c].load(Relaxed)));
    }
    v
}

/// A parked block: address and whether the entire pooled allocation is initialized.
type Parked = (usize, bool);

/// The calling thread's parked buffers. `free` releases a block to DPDK.
pub(crate) struct Pool {
    small: Vec<Vec<Parked>>,
    large: Vec<Vec<Parked>>,
    bytes: usize,
    epoch_src: &'static AtomicU64,
    epoch: u64,
    budget: &'static DmaBudget,
}

impl Pool {
    pub(crate) fn new() -> Pool {
        Self::with(&EPOCH, &BUDGET)
    }

    fn with(epoch_src: &'static AtomicU64, budget: &'static DmaBudget) -> Pool {
        Pool {
            small: vec![Vec::new(); MAX_SMALL_BLK + 1],
            large: (0..CLASSES.len())
                .map(|c| Vec::with_capacity(slots_of(c)))
                .collect(),
            bytes: 0,
            epoch_src,
            epoch: epoch_src.load(Relaxed),
            budget,
        }
    }

    /// Release every parked block (memory pressure).
    pub(crate) fn drain(&mut self, free: &mut dyn FnMut(usize, usize)) {
        self.epoch = self.epoch_src.load(Relaxed);
        if self.bytes == 0 {
            return;
        }
        for (n, v) in self.small.iter_mut().enumerate() {
            for (p, _) in v.drain(..) {
                free(p, n * 4096);
            }
        }
        for (c, v) in self.large.iter_mut().enumerate() {
            for (p, _) in v.drain(..) {
                PARKED_LARGE.fetch_sub(CLASSES[c] as u64, Relaxed);
                FREES[c].fetch_add(1, Relaxed);
                free(p, CLASSES[c]);
            }
        }
        self.bytes = 0;
    }

    /// Another thread hit memory pressure since this pool last looked: drop everything.
    #[inline]
    fn follow_epoch(&mut self, free: &mut dyn FnMut(usize, usize)) {
        if self.epoch != self.epoch_src.load(Relaxed) {
            self.drain(free);
        }
    }

    /// Take over `owner`'s return inbox; when the heap refused an allocation since this pool last looked, release every
    /// parked block, the adopted ones included, else give back parked blocks while everything held (plus the refused
    /// request waiting for room, [`DmaBudget::want`]) is above the budget's read gate (the owner's periodic call: an idle
    /// core gives memory back too, within one store sweep of a refusal on any core).
    pub(crate) fn release(&mut self, owner: Option<u16>, free: &mut dyn FnMut(usize, usize)) {
        let pressure = self.epoch != self.epoch_src.load(Relaxed);
        if let Some(o) = owner {
            self.adopt_returns(o, free);
        }
        if pressure {
            self.drain(free);
        } else {
            self.trim(0, free);
        }
    }

    /// Give parked blocks back, largest first, while everything held plus `need` bytes (at least the refused request
    /// waiting for room, [`DmaBudget::want`]) is above the budget's read gate: a request refused at the gate trades this
    /// core's parked blocks for its request, only as many as it needs; the sweep of every other core does the same for
    /// the waiting request. Then [`DmaBudget::settle_want`]. No budget: nothing to do.
    pub(crate) fn trim(&mut self, need: u64, free: &mut dyn FnMut(usize, usize)) {
        let b = self.budget;
        let over = || b.held().saturating_add(need.max(b.want())) > b.read_gate();
        for c in (0..CLASSES.len()).rev() {
            while self.bytes > 0 && over() {
                let Some((p, _)) = self.large[c].pop() else {
                    break;
                };
                self.bytes -= CLASSES[c];
                PARKED_LARGE.fetch_sub(CLASSES[c] as u64, Relaxed);
                FREES[c].fetch_add(1, Relaxed);
                free(p, CLASSES[c]);
            }
        }
        for (n, v) in self.small.iter_mut().enumerate().rev() {
            while self.bytes > 0 && over() {
                let Some((p, _)) = v.pop() else {
                    break;
                };
                self.bytes -= n * 4096;
                free(p, n * 4096);
            }
        }
        b.settle_want();
    }

    /// Start a drain on all pools after the heap refused an allocation within the budget (the caller drains its own
    /// pool).
    #[cfg(feature = "spdk")]
    pub(crate) fn pressure() {
        EPOCH.fetch_add(1, Relaxed);
        PRESSURE_DRAINS.fetch_add(1, Relaxed);
    }

    /// A parked buffer for a request of `len` bytes.
    #[inline]
    pub(crate) fn take(
        &mut self,
        len: usize,
        free: &mut dyn FnMut(usize, usize),
    ) -> Option<Parked> {
        if let Some(c) = small_class(len) {
            self.follow_epoch(free);
            let r = self.small[c].pop()?;
            self.bytes -= len;
            return Some(r);
        }
        let c = large_class(len)?;
        self.follow_epoch(free);
        let r = self.large[c].pop();
        if r.is_some() {
            self.bytes -= CLASSES[c];
            PARKED_LARGE.fetch_sub(CLASSES[c] as u64, Relaxed);
            HITS[c].fetch_add(1, Relaxed);
        } else {
            MISSES[c].fetch_add(1, Relaxed);
        }
        r
    }

    /// Park the block of a `len`-byte buffer; false when it must be freed (class full, thread cap, everything held above
    /// the budget's read gate, not pooled).
    #[inline]
    pub(crate) fn put(
        &mut self,
        len: usize,
        block: Parked,
        free: &mut dyn FnMut(usize, usize),
    ) -> bool {
        if let Some(c) = small_class(len) {
            self.follow_epoch(free);
            if self.bytes + len > CAP_BYTES || self.budget.above_gate() {
                return false;
            }
            self.bytes += len;
            self.small[c].push(block);
            return true;
        }
        let Some(c) = large_class(len) else {
            if len > MAX_SMALL_BLK * 4096 {
                UNPOOLED_FREES.fetch_add(1, Relaxed);
            }
            return false;
        };
        self.follow_epoch(free);
        if self.large[c].len() >= slots_of(c)
            || self.bytes + CLASSES[c] > CAP_BYTES
            || self.budget.above_gate()
        {
            FREES[c].fetch_add(1, Relaxed);
            return false;
        }
        self.bytes += CLASSES[c];
        PARKED_LARGE.fetch_add(CLASSES[c] as u64, Relaxed);
        // A short buffer initialized only its visible prefix, not the class-sized allocation.
        // A later borrower may request more bytes from this same class.
        self.large[c].push((block.0, block.1 && len == CLASSES[c]));
        true
    }
}

/// Count a large allocation that no class covers.
#[cfg(feature = "spdk")]
pub(crate) fn count_unpooled(len: usize) {
    if len > MAX_SMALL_BLK * 4096 && large_class(len).is_none() {
        UNPOOLED_ALLOCS.fetch_add(1, Relaxed);
    }
}

/// Return key of a `len`-byte buffer: its small bin (`1..=MAX_SMALL_BLK`) or `MAX_SMALL_BLK + 1 +` its large class.
#[inline]
pub(crate) fn shelf_key(len: usize) -> Option<usize> {
    small_class(len).or_else(|| large_class(len).map(|c| MAX_SMALL_BLK + 1 + c))
}

/// Allocated bytes of a buffer returned under key `key`.
pub(crate) fn key_bytes(key: usize) -> usize {
    if key <= MAX_SMALL_BLK {
        key * 4096
    } else {
        CLASSES[key - MAX_SMALL_BLK - 1]
    }
}

/// Per-owner return inboxes of pooled buffers that went out as shared read data (`IoBuf::into_shared`): the dropping
/// core pushes, the allocating core takes the chain over into its pool ([`Pool::adopt_returns`]); see `crate::shelf`.
pub(crate) static RETURNS: crate::shelf::Returns = crate::shelf::Returns::new();

impl Pool {
    /// Take over what other threads returned to `owner`'s inbox; blocks the pool refuses (thread cap, class full) go
    /// back to DPDK through `free`. Small contents are initialized; large returns carry a class key, not the initialized prefix length.
    pub(crate) fn adopt_returns(&mut self, owner: u16, free: &mut dyn FnMut(usize, usize)) {
        for (p, key) in RETURNS.take_all(owner) {
            let n = key_bytes(key);
            if !self.put(n, (p, key <= MAX_SMALL_BLK), free) {
                free(p, n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nofree(_: usize, _: usize) {}

    #[test]
    fn classes_are_ascending_page_aligned_and_step_at_most_1_5x() {
        assert!(CLASSES.windows(2).all(|w| w[0] < w[1]));
        assert!(CLASSES.iter().all(|c| c % 4096 == 0));
        assert!(CLASSES[0] > MAX_SMALL_BLK * 4096);
        assert!(CLASSES[0] * 2 <= MAX_SMALL_BLK * 4096 * 3);
        assert!(CLASSES.windows(2).all(|w| w[1] * 2 <= w[0] * 3));
        assert!(*CLASSES.last().unwrap() >= (128 << 20) + (64 << 10));
    }

    #[test]
    fn class_lookup_rounds_up_to_the_smallest_fitting_class() {
        assert_eq!(large_class(MAX_SMALL_BLK * 4096), None);
        assert_eq!(large_class(MAX_SMALL_BLK * 4096 + 1), Some(0));
        assert_eq!(large_class(4 << 20), Some(3));
        assert_eq!(alloc_len(4 << 20), 4 << 20);
        assert_eq!(alloc_len((4 << 20) + 1), 6 << 20);
        assert_eq!(alloc_len((4 << 20) + 4096), 6 << 20);
        assert_eq!(large_class(128 << 20), Some(13));
        assert_eq!(large_class(*CLASSES.last().unwrap()), Some(14));
        assert_eq!(large_class(*CLASSES.last().unwrap() + 1), None);
        assert_eq!(alloc_len(200 << 20), 200 << 20);
        assert_eq!(alloc_len(8192), 8192);
        assert_eq!(small_class(4096), Some(1));
        assert_eq!(small_class(MAX_SMALL_BLK * 4096), Some(MAX_SMALL_BLK));
        assert_eq!(small_class(4097), None);
        assert_eq!(small_class(0), None);
    }

    #[test]
    fn slots_are_sized_by_bytes_and_bounded() {
        assert_eq!(slots_of(0), MAX_SLOTS);
        assert_eq!(slots_of(CLASSES.len() - 1), 2);
        for (c, size) in CLASSES.iter().enumerate() {
            assert!((2..=MAX_SLOTS).contains(&slots_of(c)));
            assert!(slots_of(c) * size <= SLOT_BYTES.max(2 * size));
        }
        // the thread cap holds two blocks of every class below 128 MiB
        assert!(2 * CLASSES[CLASSES.len() - 2] <= CAP_BYTES);
    }

    #[test]
    fn large_blocks_recycle_across_lengths_of_one_class() {
        let mut p = Pool::new();
        assert!(p.take(4 << 20, &mut nofree).is_none());
        assert!(p.put(4 << 20, (0x1000, true), &mut nofree));
        // same class: 3 MiB + 4 KiB .. 4 MiB
        assert_eq!(p.take((3 << 20) + 4096, &mut nofree), Some((0x1000, true)));
        assert!(p.take(4 << 20, &mut nofree).is_none());
        assert_eq!(p.bytes, 0);
    }

    #[test]
    fn a_short_large_buffer_does_not_initialize_its_class_tail() {
        let mut p = Pool::new();
        let short = (3 << 20) + 4096;
        assert!(p.put(short, (0x1000, true), &mut nofree));
        assert_eq!(p.take(4 << 20, &mut nofree), Some((0x1000, false)));
    }

    #[test]
    fn class_slots_and_thread_cap_bound_parked_bytes() {
        let mut p = Pool::new();
        let c = large_class(64 << 20).unwrap();
        for i in 0..slots_of(c) {
            assert!(p.put(64 << 20, (0x1000 * (i + 1), false), &mut nofree));
        }
        assert!(!p.put(64 << 20, (0xdead000, false), &mut nofree));
        assert!(p.bytes <= CAP_BYTES);
        // the thread cap also stops small bins
        let mut p = Pool::new();
        let mut parked = 0;
        while p.put(
            MAX_SMALL_BLK * 4096,
            (0x1000 * (parked + 1), true),
            &mut nofree,
        ) {
            parked += 1;
        }
        assert_eq!(parked * MAX_SMALL_BLK * 4096, CAP_BYTES);
        assert!(!p.put(2 << 20, (0x2000, true), &mut nofree));
    }

    #[test]
    fn pressure_epoch_drains_every_pool_at_its_next_operation() {
        static TEST_EPOCH: AtomicU64 = AtomicU64::new(0);
        let mut a = Pool::with(&TEST_EPOCH, &BUDGET);
        let mut b = Pool::with(&TEST_EPOCH, &BUDGET);
        assert!(a.put(8 << 20, (0x1000, true), &mut nofree));
        assert!(b.put(8 << 20, (0x2000, true), &mut nofree));
        assert!(b.put(4096, (0x3000, true), &mut nofree));
        TEST_EPOCH.fetch_add(1, Relaxed);
        let mut freed = Vec::new();
        assert!(b.take(8 << 20, &mut |p, _| freed.push(p)).is_none());
        freed.sort_unstable();
        assert_eq!(freed, [0x2000, 0x3000]);
        assert_eq!(b.bytes, 0);
        let mut freed = Vec::new();
        assert!(a.take(8 << 20, &mut |p, _| freed.push(p)).is_none());
        assert_eq!(freed, [0x1000]);
    }

    #[test]
    fn return_keys_follow_the_pool_bins_and_classes() {
        assert_eq!(shelf_key(4096), Some(1));
        assert_eq!(shelf_key(MAX_SMALL_BLK * 4096), Some(MAX_SMALL_BLK));
        assert_eq!(shelf_key(4097), None);
        assert_eq!(shelf_key(200 << 20), None);
        for (c, size) in CLASSES.iter().enumerate() {
            let k = shelf_key(*size).unwrap();
            assert_eq!(key_bytes(k), *size);
            assert_eq!(shelf_key(size - 4096 * usize::from(c > 0)), Some(k));
        }
    }

    #[test]
    fn returned_blocks_are_adopted_by_class_and_the_thread_cap_still_applies() {
        use std::alloc::{Layout, alloc, dealloc};
        let l = Layout::from_size_align(4096, 4096).unwrap();
        // SAFETY: valid non-zero layout; the blocks are only parked as addresses and freed below.
        let blk = || unsafe { alloc(l) as usize };
        let owner = crate::shelf::my_owner().unwrap();
        let (a, b, c) = (blk(), blk(), blk());
        // a 3 MiB + 4 KiB buffer comes back for any length of its class (4 MiB class), an 8 KiB one in its bin
        assert!(RETURNS.put(owner, a, shelf_key((3 << 20) + 4096).unwrap()));
        assert!(RETURNS.put(owner, b, shelf_key(8192).unwrap()));
        let mut p = Pool::new();
        p.adopt_returns(owner, &mut nofree);
        assert_eq!(p.take(4096, &mut nofree), None);
        assert_eq!(p.take(4 << 20, &mut nofree), Some((a, false)));
        assert_eq!(p.take(4 << 20, &mut nofree), None);
        assert_eq!(p.take(8192, &mut nofree), Some((b, true)));
        // over the thread cap the block is freed, not parked
        p.bytes = CAP_BYTES;
        assert!(RETURNS.put(owner, c, shelf_key(8192).unwrap()));
        let mut freed = Vec::new();
        p.adopt_returns(owner, &mut |x, _| freed.push(x));
        assert_eq!(freed, [c]);
        for x in [a, b, c] {
            // SAFETY: allocated above with `l`.
            unsafe { dealloc(x as *mut u8, l) };
        }
    }

    #[test]
    fn released_blocks_report_their_allocated_size() {
        let mut p = Pool::new();
        assert!(p.put(3 * 4096, (0x1000, true), &mut nofree));
        // a 5 MiB buffer sits in the 6 MiB class
        assert!(p.put(5 << 20, (0x2000, true), &mut nofree));
        let mut freed = Vec::new();
        p.drain(&mut |a, n| freed.push((a, n)));
        freed.sort_unstable();
        assert_eq!(freed, [(0x1000, 3 * 4096), (0x2000, 6 << 20)]);
    }

    fn counter(b: &DmaBudget, name: &str) -> u64 {
        let mut v = Vec::new();
        b.counters(&mut v);
        v.into_iter().find(|(n, _)| n == name).unwrap().1
    }

    #[test]
    fn deferrable_memory_is_admitted_within_three_quarters_and_io_within_all() {
        // no budget: only the heap limits
        let none = DmaBudget::new();
        assert!(none.try_take(1 << 40));
        assert!(none.try_take_io(1 << 40));
        assert!(!none.above_gate());
        let b = DmaBudget::new();
        b.set_limit(400 << 20);
        assert_eq!(b.read_gate(), 300 << 20);
        assert!(b.try_take(200 << 20));
        assert!(b.try_take(100 << 20));
        assert!(!b.try_take(4096), "read gate full");
        assert_eq!(b.held(), 300 << 20, "a refused request is not counted");
        assert!(
            b.try_take_io(100 << 20),
            "the last quarter is in-flight IO's"
        );
        assert!(!b.try_take_io(4096), "budget full");
        assert_eq!(b.held(), 400 << 20);
        b.give(150 << 20);
        assert!(b.try_take(50 << 20));
        assert!(!b.try_take(4096));
        assert_eq!(counter(&b, "held_peak_bytes"), 400 << 20);
        assert_eq!(counter(&b, "budget_bytes"), 400 << 20);
    }

    #[test]
    fn a_refused_data_request_is_wanted_until_room_exists_for_it() {
        let b = DmaBudget::new();
        b.set_limit(400 << 20);
        assert!(b.try_take(296 << 20));
        assert!(!b.above_gate());
        b.note_data_short(8 << 20);
        b.note_data_short(1 << 20);
        assert_eq!(b.want(), 8 << 20, "the largest refused request");
        assert!(b.above_gate(), "no parking while it has no room");
        b.settle_want();
        assert_eq!(b.want(), 8 << 20, "still no room");
        b.give(4 << 20);
        b.settle_want();
        assert_eq!(b.want(), 0, "room for it now: it is admitted at its retry");
        assert!(!b.above_gate());
        b.note_data_short(8 << 20);
        assert!(b.try_take(4 << 20), "a smaller request leaves it waiting");
        assert_eq!(b.want(), 8 << 20);
        b.give(12 << 20);
        assert!(b.try_take(8 << 20));
        assert_eq!(b.want(), 0, "admitted");
        assert_eq!(counter(&b, "data_short"), 3);
    }

    #[test]
    fn shared_data_in_transit_holds_at_most_half_the_budget() {
        assert!(DmaBudget::new().share(1 << 40, true), "no budget: no cap");
        let b = DmaBudget::new();
        b.set_limit(400 << 20);
        assert!(b.share(150 << 20, false));
        assert!(b.share(50 << 20, false));
        assert!(!b.share(4096, false), "beyond half: a heap copy");
        assert_eq!(b.shared(), 200 << 20);
        b.unshare(50 << 20);
        assert!(b.share(4096, false));
        // in-flight IO memory stops being in flight when it leaves shared: only within the read gate
        assert!(b.try_take(300 << 20));
        assert!(b.try_take_io(4096));
        assert!(!b.share(4096, true), "held above the gate: a heap copy");
        assert!(
            b.share(4096, false),
            "deferrable memory was admitted within the gate already"
        );
        b.give(4096);
        assert!(b.share(4096, true), "held within the gate");
        assert_eq!(counter(&b, "share_copies"), 2);
        assert_eq!(counter(&b, "shared_peak_bytes"), 200 << 20);
        // the store pipeline keeps a quarter whatever is in transit
        assert!(b.read_gate() - b.share_cap() >= b.limit() / 4);
    }

    #[test]
    fn release_takes_returns_over_and_drains_only_after_pressure() {
        use std::alloc::{Layout, alloc, dealloc};
        static TEST_EPOCH: AtomicU64 = AtomicU64::new(0);
        let l = Layout::from_size_align(4096, 4096).unwrap();
        let owner = crate::shelf::my_owner().unwrap();
        let mut p = Pool::with(&TEST_EPOCH, &BUDGET);
        assert!(p.put(8 << 20, (0x1000, true), &mut nofree));
        let mut freed = Vec::new();
        p.release(Some(owner), &mut |a, _| freed.push(a));
        assert!(freed.is_empty(), "no pressure: parked blocks stay");
        // SAFETY: valid non-zero layout; parked as an address and freed below.
        let a = unsafe { alloc(l) as usize };
        assert!(RETURNS.put(owner, a, shelf_key(8192).unwrap()));
        TEST_EPOCH.fetch_add(1, Relaxed);
        p.release(Some(owner), &mut |x, _| freed.push(x));
        freed.sort_unstable();
        let mut want = vec![0x1000, a];
        want.sort_unstable();
        assert_eq!(
            freed, want,
            "the returned block goes back with the parked one"
        );
        assert_eq!(p.bytes, 0);
        // SAFETY: allocated above with `l`.
        unsafe { dealloc(a as *mut u8, l) };
    }

    #[test]
    fn freed_blocks_go_back_to_the_heap_while_everything_held_is_above_the_read_gate() {
        static TEST_BUDGET: DmaBudget = DmaBudget::new();
        let mut p = Pool::with(&EPOCH, &TEST_BUDGET);
        TEST_BUDGET.set_limit(400 << 20);
        TEST_BUDGET.take(310 << 20);
        assert!(TEST_BUDGET.above_gate());
        assert!(!p.put(8 << 20, (0x1000, true), &mut nofree));
        assert!(!p.put(4096, (0x2000, true), &mut nofree));
        assert_eq!(p.bytes, 0);
        TEST_BUDGET.give(10 << 20);
        assert!(!TEST_BUDGET.above_gate(), "at the gate: parking again");
        assert!(p.put(8 << 20, (0x1000, true), &mut nofree));
        assert!(p.put(4096, (0x2000, true), &mut nofree));
        TEST_BUDGET.set_limit(0);
        TEST_BUDGET.take(1 << 40);
        assert!(!TEST_BUDGET.above_gate(), "no budget: only the thread cap");
    }

    #[test]
    fn a_full_read_gate_trades_parked_blocks_largest_first_and_only_as_many_as_needed() {
        static TB: DmaBudget = DmaBudget::new();
        static TEST_EPOCH: AtomicU64 = AtomicU64::new(0);
        let mut p = Pool::with(&TEST_EPOCH, &TB);
        TB.set_limit(400 << 20);
        TB.take(300 << 20); // at the gate: the parked blocks below are part of it
        assert!(p.put(8 << 20, (0x1000, true), &mut nofree));
        assert!(p.put(2 << 20, (0x2000, true), &mut nofree));
        assert!(p.put(4096, (0x3000, true), &mut nofree));
        let mut freed = Vec::new();
        let mut free = |a, n| {
            freed.push(a);
            TB.give(n);
        };
        // a 1 MiB read: one 8 MiB block makes room
        p.trim(1 << 20, &mut free);
        assert_eq!(TB.held(), 292 << 20);
        // the sweep gives nothing back at or below the gate, then exactly what is above it
        p.release(None, &mut free);
        TB.take(9 << 20);
        p.release(None, &mut free);
        assert_eq!(TB.held(), 299 << 20);
        // nothing left above the gate: the 4 KiB block stays parked, no epoch moved (no other pool drained)
        p.release(None, &mut free);
        assert_eq!(freed, [0x1000, 0x2000]);
        assert_eq!(p.bytes, 4096);
        assert_eq!(TEST_EPOCH.load(Relaxed), 0);
    }

    /// Codex review P1-2: core A parks most of the gate and allocates nothing, core B (empty pool) is refused. A's next
    /// sweep gives back what B needs (before: A's sweep freed nothing while everything held was below the gate, and B
    /// was refused for good).
    #[test]
    fn a_refusal_makes_the_sweep_of_another_core_give_back_parked_blocks() {
        static TB: DmaBudget = DmaBudget::new();
        static TEST_EPOCH: AtomicU64 = AtomicU64::new(0);
        TB.set_limit(32 << 20);
        let mut a = Pool::with(&TEST_EPOCH, &TB);
        for i in 0..24 {
            TB.take(1 << 20);
            assert!(a.put(1 << 20, (0x1000 * (i + 1), true), &mut nofree));
        }
        assert_eq!(TB.held(), 24 << 20, "the whole gate is parked on core A");
        // core B: nothing parked to trade, refused
        let mut b = Pool::with(&TEST_EPOCH, &TB);
        b.trim(1 << 20, &mut |_, n| TB.give(n));
        assert!(!TB.try_take(1 << 20));
        TB.note_data_short(1 << 20);
        // core A's sweep: exactly the room B needs goes back, nothing more
        a.release(None, &mut |_, n| TB.give(n));
        assert_eq!(TB.held(), 23 << 20);
        assert_eq!(TB.want(), 0, "room for B: settled");
        // B's retry is admitted
        assert!(TB.try_take(1 << 20));
        assert_eq!(TEST_EPOCH.load(Relaxed), 0, "no drain of every pool");
    }

    #[test]
    fn buffers_above_the_last_class_are_not_pooled() {
        let mut p = Pool::new();
        assert!(!p.put(200 << 20, (0x1000, true), &mut nofree));
        assert!(p.take(200 << 20, &mut nofree).is_none());
    }
}
