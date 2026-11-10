// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Bounded cross-core ingress ownership. Moving an envelope does not return its reservation.
pub mod order;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::{Mutex, OnceLock, PoisonError};

const COUNT: u64 = 1 << 48;
const BYTE_MASK: u64 = COUNT - 1;
/// [`Pool::used`] flag: the pool holds an input that must stay its single reservation (one above the pool's capacity
/// or the link's cap, spec msgr2.md 8.2). It reads above any finite limit and [`Pool::fits`]/[`Pool::take`] test it, so
/// ordinary inputs are refused while it is set.
const ALONE: u64 = 1 << 63;
const WINDOW_BYTES: u64 = 64 << 20;
const MAX_INPUT_BYTES: u64 = 768 << 20;
const WINDOW_COUNT: usize = 128;
/// Largest slot count `Window::used` holds: one more wraps the byte field into the count field.
const MAX_WINDOW_SLOTS: u64 = u64::MAX / COUNT;
/// [`Pool::head`] when no frame waits.
const NO_TICKET: u64 = u64::MAX;

/// Bytes to subtract from [`Pool::used`] for `bytes` of a lease: an [`ALONE`] lease clears the tag in the same RMW.
fn sub_charge(bytes: u64, alone: bool) -> u64 {
    if alone { bytes | ALONE } else { bytes }
}

/// Wake-up of a core that holds input for lack of space: called (from the core that frees it) when an ingress
/// reservation is released or a frame waiter leaves. A wake may be spurious; the woken core retries and parks again.
pub trait Waker: Send + Sync + std::fmt::Debug {
    fn wake(&self);
}

/// A core's registration for ingress releases: its [`Waker`] plus an `armed` flag that a wake from any pool clears.
///
/// The core parks refused inputs on their pools while it retries them (check, park, re-check). Its
/// idle re-check before a sleep is then pure: a release after a registration drains that registration, disarms the
/// parker and wakes the core, so "armed and nothing ready" means every refused input is still registered. A hold that
/// was not parked ([`disarm`](Self::disarm)) and a wake both make the idle re-check fail: the core retries (and parks)
/// once more instead of sleeping unregistered. One flag per core, not per pool: a core waits on several pools (client,
/// peer, control, relay windows), and a wake from one of them must not hide that another registration is gone.
#[derive(Debug)]
pub struct Parker {
    waker: Arc<dyn Waker>,
    armed: AtomicBool,
}

impl Parker {
    pub fn new(waker: Arc<dyn Waker>) -> Arc<Self> {
        Arc::new(Self {
            waker,
            armed: AtomicBool::new(false),
        })
    }

    /// Start of a pass that retries every held input and parks the refused ones. A store only after a wake or an
    /// unparked hold (the busy loop pays one relaxed load).
    pub fn arm(&self) {
        if !self.armed.load(Ordering::Relaxed) {
            self.armed.store(true, Ordering::SeqCst);
        }
    }

    /// A refused input was held without parking: the next idle re-check must not sleep before it is retried.
    pub fn disarm(&self) {
        self.armed.store(false, Ordering::Relaxed);
    }

    /// No wake and no unparked hold since the last [`arm`](Self::arm). The sleeper loads it after it announced its
    /// sleep and fenced; a waking pool clears it before it pokes (SeqCst on both sides: one of them sees the other).
    pub fn armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    fn wake(&self) {
        self.armed.store(false, Ordering::SeqCst);
        self.waker.wake();
    }
}

/// Wake registration of a hand-off from other threads to one core (admin socket commands, adopted sockets): a sender
/// [`queue`](Self::queue)s before it publishes the hand-off and [`ring`](Self::ring)s after; the core calls
/// [`take`](Self::take) per hand-off it removes and re-checks [`waiting`](Self::waiting) after it announced its sleep. The
/// waker's fence pairs with the announcement (`rt::wake`): either the re-check sees the count or the ring sees the
/// sleep. Without a waker (installed once, later than the first hand-off may be) a ring wakes nobody.
#[derive(Debug, Default)]
pub struct Doorbell {
    queued: AtomicUsize,
    wake: OnceLock<Arc<dyn Waker>>,
}

impl Doorbell {
    /// Install the receiving core's waker (once; later calls keep the first).
    pub fn set_waker(&self, w: Arc<dyn Waker>) {
        let _ = self.wake.set(w);
    }

    /// A sender is about to publish one hand-off.
    pub fn queue(&self) {
        self.queued.fetch_add(1, Ordering::Relaxed);
    }

    /// A sender published its hand-off: wake the receiver.
    pub fn ring(&self) {
        if let Some(w) = self.wake.get() {
            w.wake();
        }
    }

    /// The receiver removed one hand-off, or a sender's publish failed after [`queue`](Self::queue).
    pub fn take(&self) {
        self.queued.fetch_sub(1, Ordering::Relaxed);
    }

    /// A hand-off is queued or being published.
    pub fn waiting(&self) -> bool {
        self.queued.load(Ordering::Relaxed) != 0
    }
}

/// Aggregate byte allowance of a group of windows (the process memory envelope, doc/design/memory-envelope.md).
#[derive(Debug)]
#[repr(align(64))]
struct Pool {
    limit: u64,
    used: AtomicU64,
    stalls: AtomicU64,
    /// Connections whose message frame waits for space (see [`FrameGate::admit`]).
    waiters: AtomicU32,
    /// Tickets of the waiting frames ([`Waiter`]), oldest first: only the oldest is admitted, whichever core retries
    /// first, so the links of all cores take turns in arrival order ([`FrameGate::admit`]).
    queue: Mutex<Tickets>,
    /// The oldest waiting ticket ([`NO_TICKET`]: none), written under `queue`: the admit path's one load.
    head: AtomicU64,
    /// Frames that had to wait at their header, ever.
    waits: AtomicU64,
    /// Cores that wait for a release ([`Pool::try_or_park`]); drained by the next release.
    parked: Mutex<Vec<Arc<Parker>>>,
    /// `parked.len()`: the release path's one load when nobody waits.
    parked_len: AtomicU32,
}

impl Pool {
    fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicU64::new(0),
            stalls: AtomicU64::new(0),
            waiters: AtomicU32::new(0),
            queue: Mutex::new(Tickets::default()),
            head: AtomicU64::new(NO_TICKET),
            waits: AtomicU64::new(0),
            parked: Mutex::new(Vec::new()),
            parked_len: AtomicU32::new(0),
        })
    }

    /// `attempt`; when it fails and a parker is given: register it for the next release, then attempt once more.
    ///
    /// No lost wake (Dekker): the parker stores `parked_len` (SeqCst) and fences (SeqCst) before the re-check; a
    /// release frees space with SeqCst RMWs (`Window::used`, `Pool::used`, `Pool::waiters`) and then loads
    /// `parked_len` (SeqCst), without a fence of its own. If that load misses the registration, it precedes the store
    /// in the single SeqCst order, so the freeing RMWs precede the parker's fence and the re-check's loads observe
    /// them. Otherwise the release drains the registration and wakes the parker.
    fn try_or_park<T>(
        &self,
        parker: Option<&Arc<Parker>>,
        attempt: impl Fn() -> Option<T>,
    ) -> Option<T> {
        attempt().or_else(|| {
            self.park(parker?);
            attempt()
        })
    }

    /// Register `p` for the next release (idempotent; the cold side of [`try_or_park`](Self::try_or_park)).
    fn park(&self, p: &Arc<Parker>) {
        let mut v = self.parked.lock().unwrap_or_else(PoisonError::into_inner);
        if !v.iter().any(|q| Arc::ptr_eq(q, p)) {
            v.push(p.clone());
        }
        self.parked_len.store(v.len() as u32, Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }

    /// Space was freed (or a queue place left) by a SeqCst RMW just before: wake every parked core. One load when
    /// nobody waits; no fence (see [`try_or_park`](Self::try_or_park)).
    fn released(&self) {
        if self.parked_len.load(Ordering::SeqCst) == 0 {
            return;
        }
        let woken = {
            let mut v = self.parked.lock().unwrap_or_else(PoisonError::into_inner);
            self.parked_len.store(0, Ordering::SeqCst);
            std::mem::take(&mut *v)
        };
        for w in woken {
            w.wake();
        }
    }

    /// SOFT limit (osd_memory_target is a target, not a hard cap): an input is admitted while the pool is below its
    /// limit, so the pool overshoots by at most one input per concurrent admitter, any input size makes progress
    /// (no "pool empty" rule, no starvation of large inputs) and the pool brakes smoothly instead of freezing.
    /// A frame larger than the limit itself, or one marked `alone`, is admitted only while it is everything the pool
    /// holds: the window marks it `alone`, keeping the pool as its single oversized reservation (spec msgr2.md 8.2).
    fn fits(&self, bytes: u64, alone: bool) -> bool {
        let used = self.used.load(Ordering::Acquire);
        if alone {
            // An exclusive reservation still occupies the pool before any bytes join.
            return used == 0;
        }
        bytes == 0 || (used & ALONE == 0 && used < self.limit)
    }

    /// May a frame be admitted now: a newcomer (`None`) only while no frame waits, a waiting frame only as the oldest.
    /// A departing head stores the next one before its `released` (SeqCst both): a core that parked after it saw an
    /// older head is woken by that release (see [`try_or_park`](Self::try_or_park)).
    fn turn(&self, wait: Option<&Waiter>) -> bool {
        self.head.load(Ordering::SeqCst) == wait.map_or(NO_TICKET, |w| w.ticket)
    }

    fn take(&self, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        // a tagged pool ([`ALONE`]) refuses ordinary inputs: the bit puts `old` above any finite limit, and an
        // unlimited pool (shard windows) tests it directly
        let mut old = self.used.load(Ordering::Acquire);
        while old & ALONE == 0 && old < self.limit {
            match self.used.compare_exchange_weak(
                old,
                old + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next) => old = next,
            }
        }
        self.stalls.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Add `bytes` for an input that is alone in the pool, tagged [`ALONE`] for the rest of its lease: only into an
    /// empty pool, so the pool never holds an oversized input next to another one and ordinary inputs are refused until
    /// the lease drops (classic's one-message-above-the-max rule, spec msgr2.md 8.2).
    fn take_alone(&self, bytes: u64) -> bool {
        debug_assert!(bytes < ALONE, "alone charge reaches the flag");
        if self
            .used
            .compare_exchange(0, bytes | ALONE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }
        self.stalls.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Subtract a lease's bytes, clearing [`ALONE`] in the same RMW when the lease holds it: the pool becomes
    /// available to ordinary inputs again.
    fn release(&self, bytes: u64, alone: bool) {
        debug_assert!(bytes < ALONE, "released charge reaches the flag");
        // SeqCst stands in for the fence before `released` loads `parked_len` ([`Self::try_or_park`])
        self.used
            .fetch_sub(sub_charge(bytes, alone), Ordering::SeqCst);
        self.released();
    }

    /// Subtract `bytes` of a lease that stays: a refused data segment was charged with its frame at the preamble and
    /// is held by nobody now (spec msgr2.md 8.2). An [`ALONE`] lease keeps its tag, the rest of it is still the pool's
    /// single reservation.
    fn shrink(&self, bytes: u64) {
        debug_assert!(bytes < ALONE, "shrunk charge reaches the flag");
        self.used.fetch_sub(bytes, Ordering::SeqCst);
        self.released();
    }

    /// Undo a provisional charge. Other cores may have observed it and parked,
    /// even though no input was admitted; returning that space must wake them.
    fn undo(&self, bytes: u64, alone: bool) {
        self.used
            .fetch_sub(sub_charge(bytes, alone), Ordering::SeqCst);
        self.released();
    }
}

/// Occupancy of one aggregate pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolStat {
    /// Bytes reserved, without the internal [`ALONE`] tag.
    pub used: u64,
    pub limit: u64,
    /// Reservations refused because the pool was full (backpressure events).
    pub stalls: u64,
    /// Connections waiting for space right now (frame headers parsed, body not yet admitted).
    pub waiters: u32,
    /// Frames that waited at their header since start.
    pub waits: u64,
}

/// Waiting frames of a pool in arrival order.
#[derive(Debug, Default)]
struct Tickets {
    next: u64,
    q: std::collections::VecDeque<u64>,
}

/// A connection waiting for pool space, with its place in the pool's arrival order; newcomers queue behind it and older
/// waiters go first ([`FrameGate::admit`]). Dropping it (admitted, or the connection went away) releases the place.
#[derive(Debug)]
pub struct Waiter {
    pool: Arc<Pool>,
    ticket: u64,
}

impl Waiter {
    fn new(pool: &Arc<Pool>) -> Self {
        let ticket = {
            let mut t = pool.queue.lock().unwrap_or_else(PoisonError::into_inner);
            let ticket = t.next;
            t.next += 1;
            t.q.push_back(ticket);
            if t.q.len() == 1 {
                pool.head.store(ticket, Ordering::SeqCst);
            }
            ticket
        };
        pool.waiters.fetch_add(1, Ordering::AcqRel);
        pool.waits.fetch_add(1, Ordering::Relaxed);
        Self {
            pool: pool.clone(),
            ticket,
        }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        {
            let mut t = self
                .pool
                .queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if t.q.front() == Some(&self.ticket) {
                t.q.pop_front();
                let next = t.q.front().copied().unwrap_or(NO_TICKET);
                self.pool.head.store(next, Ordering::SeqCst);
            } else if let Some(i) = t.q.iter().position(|&x| x == self.ticket) {
                t.q.remove(i);
            }
        }
        self.pool.waiters.fetch_sub(1, Ordering::SeqCst);
        // the next waiter's turn (or the newcomers' when none is left): wake the cores that hold them
        self.pool.released();
    }
}

/// Admission of message frames at their header, before any body byte is assembled (doc/design/memory-envelope.md,
/// G1): a frame's front is reserved in the frame window of its pool group once its preamble is parsed. A full pool
/// refuses; the connection stops reading and retries. While any connection waits, newcomers wait too (a stream of
/// small frames cannot starve a large one), and the waiting frames are admitted oldest first across all cores: a
/// release wakes every core that holds a waiter, and without the order the first core to retry won, so links shared a
/// core's turns instead of getting their own (doc/perf/w4m-gap-20261102.md: 20 vs 30 % of the ops per connection).
///
/// A frame above its pool's capacity or above the link's admission cap is never refused for its size: it waits until
/// nothing else of the pool is in flight and is then admitted alone, the pool overshooting to the frame's size. It
/// keeps the pool as its single reservation then ([`ALONE`]): ordinary frames stay refused until the alone lease drops
/// (classic's one-message-above-the-max rule, spec msgr2.md 5, 8.2).
///
/// One admission decision per frame, at its preamble, on the whole declared size (adr 0175 am. 3): the lease `admit`
/// returns covers the whole frame (adr 0688-split-frame-memory-reservation); a data segment the probe refuses is given
/// back ([`shrink`](Self::shrink)) — never a second admission, so no frame holds a front while it waits for the rest.
#[derive(Clone, Debug)]
pub struct FrameGate {
    window: Arc<Window>,
    parker: Option<Arc<Parker>>,
}

impl FrameGate {
    /// The core that owns the connections using this gate: woken when a refused frame may fit.
    pub fn with_parker(mut self, p: Arc<Parker>) -> Self {
        self.parker = Some(p);
        self
    }

    /// Byte allowance of the frame window's pool: a frame declaring more than this is admitted alone
    /// ([`FrameGate::admit`]) instead of sharing the pool.
    pub fn capacity(&self) -> u64 {
        self.window.pool.limit
    }

    /// Would a frame of `bytes` with waiter `wait` (`None`: a newcomer) be admitted now (the sleeper's re-check before
    /// it blocks)? `alone`: the frame is above its pool capacity or the link's admission cap and takes the pool by
    /// itself (spec msgr2.md 8.2).
    pub fn ready(&self, bytes: usize, alone: bool, wait: Option<&Waiter>) -> bool {
        self.window.pool.turn(wait) && self.window.ready(bytes, alone)
    }

    /// The frame's one admission decision: `bytes` = its whole declared size, `alone` = the frame is above the pool or the link cap and takes the pool as its single
    /// reservation, decided from its whole declared size.
    pub fn admit(
        &self,
        bytes: usize,
        alone: bool,
        wait: &mut Option<Waiter>,
    ) -> Option<IngressLease> {
        let w = &self.window;
        let lease = w.pool.try_or_park(self.parker.as_ref(), || {
            // a newcomer queues behind the waiting connections, a waiting one behind the older ones
            if !w.pool.turn(wait.as_ref()) {
                return None;
            }
            w.reserve(bytes, alone)
        });
        match lease {
            Some(_) => *wait = None,
            None if wait.is_none() => *wait = Some(Waiter::new(&w.pool)),
            None => {}
        }
        lease
    }

    /// Give part of `lease` back: the data segment of a frame that was charged as a whole but refused by the probe is
    /// held by nobody (spec msgr2.md 8.2, the buffered/secure path).
    pub fn shrink(&self, lease: &IngressLease, bytes: usize) {
        let w = &self.window;
        assert!(
            Arc::ptr_eq(&lease.window, w),
            "frame reservation of another window"
        );
        let bytes = bytes as u64;
        if bytes == 0 {
            return;
        }
        let old = w.charges[lease.slot].fetch_sub(bytes, Ordering::SeqCst);
        debug_assert!(old & BYTE_MASK >= bytes);
        let used = w.used.fetch_sub(bytes, Ordering::SeqCst);
        debug_assert!(used & BYTE_MASK >= bytes);
        // the lease keeps its [`ALONE`] tag: the rest of it is still the pool's single reservation
        w.pool.shrink(bytes);
    }
}

#[repr(align(64))]
struct Window {
    pool: Arc<Pool>,
    count_limit: u64,
    input_limit: u64,
    /// Byte allowance of the window (shard windows [`WINDOW_BYTES`]; a frame window `u64::MAX`: only the pool bounds it).
    byte_cap: u64,
    /// A frame window of the ingress gate (spec msgr2.md 8.2): a frame above the pool's capacity is admitted alone.
    frames: bool,
    used: AtomicU64,
    slots: Box<[AtomicU64]>,
    refs: Box<[AtomicU32]>,
    charges: Box<[AtomicU64]>,
}

impl std::fmt::Debug for Window {
    /// One line: the slot arrays are internal state, not log content.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Window")
            .field("count_limit", &self.count_limit)
            .field("input_limit", &self.input_limit)
            .field("byte_cap", &self.byte_cap)
            .field("used", &self.used.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Window {
    fn new(pool: &Arc<Pool>, count: usize, input_limit: u64, byte_cap: u64) -> Arc<Self> {
        Self::with_kind(pool, count, input_limit, byte_cap, false)
    }

    /// A frame window: no per-input size limit (`input_limit`), bytes bounded by its pool only, and a frame above the
    /// pool's capacity admitted alone (spec msgr2.md 5, 8.2).
    fn frame(pool: &Arc<Pool>, count: usize) -> Arc<Self> {
        Self::with_kind(pool, count, u64::MAX, u64::MAX, true)
    }

    fn with_kind(
        pool: &Arc<Pool>,
        count: usize,
        input_limit: u64,
        byte_cap: u64,
        frames: bool,
    ) -> Arc<Self> {
        assert!(
            (1..=MAX_WINDOW_SLOTS as usize).contains(&count),
            "window slot count out of the packed count field"
        );
        let cap = count.div_ceil(64) * 64;
        Arc::new(Self {
            pool: pool.clone(),
            count_limit: count as u64,
            input_limit,
            byte_cap,
            frames,
            used: AtomicU64::new(0),
            slots: (0..cap / 64).map(|_| AtomicU64::new(0)).collect(),
            refs: (0..cap).map(|_| AtomicU32::new(0)).collect(),
            charges: (0..cap).map(|_| AtomicU64::new(0)).collect(),
        })
    }

    fn fits(&self, used: u64, bytes: u64, alone: bool) -> bool {
        if alone {
            // alone: nothing else is in the window (a newcomer: no count, no bytes)
            return used & BYTE_MASK == 0 && used / COUNT == 0;
        }
        bytes <= self.input_limit
            && used / COUNT < self.count_limit
            && ((used & BYTE_MASK) + bytes <= self.byte_cap || used == 0)
    }

    /// Would a reservation of `bytes` be admitted now: window allowance and its pool?
    fn ready(&self, bytes: usize, alone: bool) -> bool {
        let bytes = bytes as u64;
        let alone = alone || (self.frames && bytes > self.pool.limit);
        self.fits(self.used.load(Ordering::Acquire), bytes, alone) && self.pool.fits(bytes, alone)
    }

    /// Grow `slot`'s reservation by `bytes` with no allowance check, for a charge that was decided with the input
    /// itself (a frame's admitted data segment, a retained relay frame): the caller guarantees the bytes belong to it
    /// and the pool may overshoot by them (adr 0175 am. 1, am. 3).
    fn extend(&self, slot: usize, bytes: usize) {
        let bytes = bytes as u64;
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            // The byte field must never carry into the count field: refuse before the add.
            assert!(
                (used & BYTE_MASK) + bytes < COUNT,
                "ingress byte counter exhausted"
            );
            match self.used.compare_exchange_weak(
                used,
                used + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(next) => used = next,
            }
        }
        self.pool.used.fetch_add(bytes, Ordering::AcqRel);
        self.charges[slot].fetch_add(bytes, Ordering::Release);
    }

    /// Reserve `bytes` (the frame's front: its one admission decision decided the frame, adr 0175 am. 3); the caller
    /// checked the order ([`Pool::turn`]).
    fn reserve(self: &Arc<Self>, bytes: usize, alone: bool) -> Option<IngressLease> {
        let bytes = bytes as u64;
        // a frame larger than the pool itself can only be alone, whoever asks
        let alone = alone || (self.frames && bytes > self.pool.limit);
        // Refuse without publishing a provisional window charge when the pool
        // already rules admission out. A racing change is checked by take below.
        let pool_used = self.pool.used.load(Ordering::Acquire);
        let pool_refuses = if alone {
            pool_used != 0
        } else {
            bytes != 0 && (pool_used & ALONE != 0 || pool_used >= self.pool.limit)
        };
        if pool_refuses {
            self.pool.stalls.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut used = self.used.load(Ordering::Acquire);
        // A lost CAS means another producer or a release progressed: retry until the window really refuses.
        loop {
            if !self.fits(used, bytes, alone) {
                return None;
            }
            let charge = COUNT + bytes;
            match self.used.compare_exchange(
                used,
                used + charge,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let taken = if alone {
                        self.pool.take_alone(bytes)
                    } else {
                        self.pool.take(bytes)
                    };
                    if !taken {
                        self.undo(charge);
                        return None;
                    }
                    for bank in 0..self.slots.len() {
                        let bitmap = &self.slots[bank];
                        let mut occupied = bitmap.load(Ordering::Acquire);
                        loop {
                            let offset = (!occupied).trailing_zeros() as usize;
                            if offset == 64 {
                                break;
                            }
                            let slot = bank * 64 + offset;
                            let bit = 1 << offset;
                            match bitmap.compare_exchange(
                                occupied,
                                occupied | bit,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            ) {
                                Ok(_) => {
                                    self.charges[slot].store(charge, Ordering::Release);
                                    self.refs[slot].store(1, Ordering::Release);
                                    return Some(IngressLease {
                                        window: self.clone(),
                                        slot,
                                        alone,
                                    });
                                }
                                Err(next) => occupied = next,
                            }
                        }
                    }
                    self.undo(charge);
                    self.pool.undo(bytes, alone);
                    return None;
                }
                Err(next) => used = next,
            }
        }
    }

    /// Undo a provisional window charge that another core may already have observed.
    fn undo(&self, charge: u64) {
        self.used.fetch_sub(charge, Ordering::SeqCst);
        self.pool.released();
    }
}

/// Created once for the OSD and shared by its connection cores. Each physical store shard has its own allowance.
#[derive(Clone, Debug)]
pub struct IngressCredits {
    windows: Arc<[Arc<Window>]>,
    pools: Arc<[Arc<Pool>]>,
    /// Index of the first frame window (= number of shard windows); frame windows follow, one per pool.
    shard_windows: usize,
}

/// Held until a ready receiver accepts/discards the input, including every send retry.
#[derive(Debug)]
pub struct IngressLease {
    window: Arc<Window>,
    slot: usize,
    /// The lease holds its pool's [`ALONE`] tag (decided with the frame's size at admission): dropping or shrinking it
    /// must keep the pool exclusive until the whole lease is gone.
    alone: bool,
}

/// Ownership metadata excluded from payload equality and encoding.
#[derive(Clone, Debug, Default)]
pub struct InputGuard(pub Option<IngressLease>);

impl PartialEq for InputGuard {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for InputGuard {}

impl IngressCredits {
    pub fn new(shards: usize) -> Self {
        Self::with_count(shards, WINDOW_COUNT)
    }

    pub fn with_count(shards: usize, count: usize) -> Self {
        Self::with_limits(shards, count, MAX_INPUT_BYTES)
    }

    /// Byte relays retain one authenticated frame plus their bounded raw receive window.
    pub fn relay() -> Self {
        Self::with_limits(1, 32, 1 << 36)
    }

    fn with_limits(shards: usize, count: usize, input_limit: u64) -> Self {
        Self::grouped(&[(shards, u64::MAX)], count, input_limit)
    }

    /// Windows in groups `(windows, byte limit)`; the windows of a group share one aggregate byte pool, so the bytes
    /// reserved by a group never exceed its limit (except one input alone in an empty pool). Groups stay separate so
    /// that one class of input cannot starve another (adr 0084 am. 2).
    pub fn partitioned(groups: &[(usize, u64)]) -> Self {
        Self::grouped(groups, WINDOW_COUNT, MAX_INPUT_BYTES)
    }

    /// Like [`partitioned`](Self::partitioned), plus one FRAME window per group (appended after all shard windows, in
    /// group order, see [`frame_gate`](Self::frame_gate)): `frames` slots, bytes bounded by the group pool only. A
    /// connection reserves there when a message frame's preamble is parsed, before any body byte is assembled.
    pub fn with_frames(groups: &[(usize, u64)], frames: usize) -> Self {
        let mut c = Self::grouped(groups, WINDOW_COUNT, MAX_INPUT_BYTES);
        let mut windows = c.windows.to_vec();
        // A frame window bounds no single frame: the pool decides, and a frame above the pool is admitted alone. A
        // frame waits for space at its header, so it never fails for its own size (spec msgr2.md 8.2).
        windows.extend(c.pools.iter().map(|p| Window::frame(p, frames)));
        c.windows = windows.into();
        c
    }

    /// Were frame windows built ([`with_frames`](Self::with_frames))?
    pub fn has_frames(&self) -> bool {
        self.windows.len() > self.shard_windows
    }

    /// Admission of message frames of group `group` (must have been built by [`with_frames`](Self::with_frames)).
    pub fn frame_gate(&self, group: usize) -> FrameGate {
        assert!(
            self.windows.len() > self.shard_windows && group < self.pools.len(),
            "no frame window"
        );
        FrameGate {
            window: self.windows[self.shard_windows + group].clone(),
            parker: None,
        }
    }

    fn grouped(groups: &[(usize, u64)], count: usize, input_limit: u64) -> Self {
        assert!(!groups.is_empty() && groups.iter().all(|g| g.0 > 0));
        assert!((1..=WINDOW_COUNT).contains(&count));
        let pools: Vec<Arc<Pool>> = groups.iter().map(|g| Pool::new(g.1)).collect();
        let windows: Arc<[Arc<Window>]> = groups
            .iter()
            .zip(&pools)
            .flat_map(|(g, pool)| std::iter::repeat_n(pool, g.0))
            .map(|pool| Window::new(pool, count, input_limit, WINDOW_BYTES))
            .collect();
        Self {
            shard_windows: windows.len(),
            windows,
            pools: pools.into(),
        }
    }

    /// Occupancy of every group pool, in group order.
    pub fn pool_stats(&self) -> Vec<PoolStat> {
        self.pools
            .iter()
            .map(|p| PoolStat {
                used: p.used.load(Ordering::Acquire) & BYTE_MASK,
                limit: p.limit,
                stalls: p.stalls.load(Ordering::Relaxed),
                waiters: p.waiters.load(Ordering::Acquire),
                waits: p.waits.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Number of independent shard windows (frame windows excluded).
    pub fn windows(&self) -> usize {
        self.shard_windows
    }

    pub fn idle(&self) -> bool {
        self.windows
            .iter()
            .all(|w| w.used.load(Ordering::Acquire) == 0)
    }

    pub fn ready(&self, shard: usize, bytes: usize) -> bool {
        self.windows
            .get(shard)
            .is_some_and(|w| w.ready(bytes, false))
    }

    /// [`ready`](Self::ready), and when it is not: register `parker` for the next release of the window's pool and
    /// re-check. A holder that sleeps on the result is woken by whichever core frees space.
    pub fn ready_or_park(&self, shard: usize, bytes: usize, parker: &Arc<Parker>) -> bool {
        self.windows.get(shard).is_some_and(|w| {
            w.pool
                .try_or_park(Some(parker), || w.ready(bytes, false).then_some(()))
                .is_some()
        })
    }

    pub fn reserve(&self, shard: usize, bytes: usize) -> Option<IngressLease> {
        self.windows.get(shard)?.reserve(bytes, false)
    }
}

impl Clone for IngressLease {
    fn clone(&self) -> Self {
        let old = self.window.refs[self.slot].fetch_add(1, Ordering::Relaxed);
        assert!(
            old > 0 && old < u32::MAX,
            "invalid ingress reservation reference count"
        );
        Self {
            window: self.window.clone(),
            slot: self.slot,
            alone: self.alone,
        }
    }
}

impl PartialEq for IngressLease {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.window, &other.window) && self.slot == other.slot
    }
}

impl Drop for IngressLease {
    fn drop(&mut self) {
        let window = &self.window;
        if window.refs[self.slot].fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let charge = window.charges[self.slot].load(Ordering::Acquire);
        window.slots[self.slot / 64].fetch_and(!(1 << (self.slot % 64)), Ordering::Release);
        // SeqCst RMWs: they stand in for a fence before `released` loads `parked_len` (Pool::try_or_park)
        let old = window.used.fetch_sub(charge, Ordering::SeqCst);
        debug_assert!(old / COUNT > 0 && (old & BYTE_MASK) >= (charge & BYTE_MASK));
        window.pool.release(charge & BYTE_MASK, self.alone);
    }
}

impl IngressLease {
    /// Conservatively charge completed frames as well as the raw fragment that owns their reservation.
    /// Only the connection owner grows relay charges; clones in other actors release the final aggregate charge.
    pub fn retain_frame(&self, bytes: usize) {
        assert!(bytes as u64 <= self.window.input_limit);
        self.window.extend(self.slot, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct Count(AtomicU32);
    impl Waker for Count {
        fn wake(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn rollback_of_a_provisional_pool_charge_wakes_waiters() {
        let credits = IngressCredits::partitioned(&[(1, 100)]);
        let pool = &credits.pools[0];
        // A provisional pool charge is visible before slot allocation fails and rolls it back.
        pool.used.store(100, Ordering::Release);
        let w = Arc::new(Count::default());
        let parker = Parker::new(w.clone());
        parker.arm();
        assert!(!credits.ready_or_park(0, 1, &parker));
        pool.undo(100, false);
        assert!(!parker.armed(), "rollback must invalidate the sleep check");
        assert_eq!(w.0.load(Ordering::SeqCst), 1);
        assert!(credits.ready(0, 1));
    }

    #[test]
    fn rollback_of_a_provisional_window_slot_wakes_waiters() {
        let credits = IngressCredits::with_count(1, 1);
        let window = &credits.windows[0];
        // The last window slot was reserved, but taking the pool charge failed.
        window.used.store(COUNT, Ordering::Release);
        let w = Arc::new(Count::default());
        let parker = Parker::new(w.clone());
        parker.arm();
        assert!(!credits.ready_or_park(0, 1, &parker));
        window.undo(COUNT);
        assert!(!parker.armed(), "rollback must invalidate the sleep check");
        assert_eq!(w.0.load(Ordering::SeqCst), 1);
        assert!(credits.ready(0, 1));
    }

    /// A refusal while room exists is a bug: 4 threads hold at most 8 leases each in a 128-slot window.
    #[test]
    fn reserve_never_refuses_while_the_window_has_room() {
        let credits = IngressCredits::new(1);
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let c = credits.clone();
                std::thread::spawn(move || {
                    let mut held = std::collections::VecDeque::new();
                    for i in 0..200_000u32 {
                        if held.len() == 8 || (i % 3 == 2 && !held.is_empty()) {
                            held.pop_front();
                        }
                        match c.reserve(0, 64) {
                            Some(l) => held.push_back(l),
                            None => panic!(
                                "thread {t}: refused at iteration {i} with {} held",
                                held.len()
                            ),
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(credits.idle());
    }

    #[test]
    fn release_wakes_the_parked_holder_once() {
        let credits = IngressCredits::with_count(1, 2);
        let w = Arc::new(Count::default());
        let waker = Parker::new(w.clone());
        let a = credits.reserve(0, 8).unwrap();
        let b = credits.reserve(0, 8).unwrap();
        assert!(!credits.ready_or_park(0, 8, &waker));
        assert!(
            !credits.ready_or_park(0, 8, &waker),
            "idempotent registration"
        );
        assert_eq!(w.0.load(Ordering::SeqCst), 0);
        waker.arm();
        assert!(waker.armed());
        drop(a);
        assert_eq!(w.0.load(Ordering::SeqCst), 1);
        assert!(!waker.armed(), "a wake disarms: the idle re-check retries");
        assert!(credits.ready_or_park(0, 8, &waker));
        drop(b);
        assert_eq!(w.0.load(Ordering::SeqCst), 1, "nobody parked: no wake");
    }

    #[test]
    fn frame_waiter_leaving_wakes_the_queue_behind_it() {
        let credits = IngressCredits::with_frames(&[(1, 100)], 4);
        let w = Arc::new(Count::default());
        let gate = credits.frame_gate(0).with_parker(Parker::new(w.clone()));
        let full = gate.admit(100, false, &mut None).unwrap();
        let mut first = None;
        assert!(gate.admit(1, false, &mut first).is_none() && first.is_some());
        let mut second = None;
        assert!(gate.admit(1, false, &mut second).is_none());
        assert!(!gate.ready(1, false, first.as_ref()));
        drop(full);
        assert!(
            w.0.load(Ordering::SeqCst) >= 1,
            "the release wakes the core"
        );
        assert!(gate.ready(1, false, first.as_ref()));
        assert!(
            !gate.ready(1, false, second.as_ref()),
            "the second waits for the first"
        );
        assert!(!gate.ready(1, false, None), "a newcomer waits behind both");
    }

    /// Two cores (gates with their own parkers) share a pool: the waiting frames go in arrival order, whichever core
    /// retries first, and each admission wakes the cores so the next in line can go (doc/perf/w4m-gap-20261102.md:
    /// without the order the first core to retry won, so links shared their core's turns).
    #[test]
    fn frame_waiters_are_admitted_in_arrival_order_across_cores() {
        let credits = IngressCredits::with_frames(&[(1, 100)], 64);
        let (w0, w1) = (Arc::new(Count::default()), Arc::new(Count::default()));
        let core0 = credits.frame_gate(0).with_parker(Parker::new(w0.clone()));
        let core1 = credits.frame_gate(0).with_parker(Parker::new(w1.clone()));
        let full = core0.admit(100, false, &mut None).unwrap();
        // arrival: a (core 1), b (core 0), c (core 0)
        let (mut a, mut b, mut c) = (None, None, None);
        assert!(core1.admit(50, false, &mut a).is_none());
        assert!(core0.admit(50, false, &mut b).is_none());
        assert!(core0.admit(50, false, &mut c).is_none());
        drop(full);
        // core 0 retries first: neither of its links is at its turn
        assert!(core0.admit(50, false, &mut b).is_none() && b.is_some());
        assert!(core0.admit(50, false, &mut c).is_none() && c.is_some());
        let woken0 = w0.0.load(Ordering::SeqCst);
        let la = core1.admit(50, false, &mut a).expect("a is the oldest");
        assert!(a.is_none());
        assert!(
            w0.0.load(Ordering::SeqCst) > woken0,
            "a's admission wakes core 0 for b"
        );
        assert!(core0.ready(50, false, b.as_ref()) && !core0.ready(50, false, c.as_ref()));
        let lb = core0.admit(50, false, &mut b).expect("b after a");
        // the pool is at its limit: c is at its turn but waits for space
        assert!(!core0.ready(50, false, c.as_ref()));
        assert!(core0.admit(50, false, &mut c).is_none());
        drop(la);
        let lc = core0.admit(50, false, &mut c).expect("c after space frees");
        assert_eq!(credits.pool_stats()[0].waiters, 0);
        drop((lb, lc));
        assert!(credits.idle());
    }

    /// A waiter that goes away (connection closed) leaves the order intact: from the middle nobody moves up, from the
    /// head the next one takes the turn, and the last one gone lets newcomers in.
    #[test]
    fn a_departing_waiter_hands_on_its_turn() {
        let credits = IngressCredits::with_frames(&[(1, 100)], 64);
        let w = Arc::new(Count::default());
        let gate = credits.frame_gate(0).with_parker(Parker::new(w.clone()));
        let full = gate.admit(100, false, &mut None).unwrap();
        let (mut a, mut b, mut c, mut d) = (None, None, None, None);
        for x in [&mut a, &mut b, &mut c, &mut d] {
            assert!(gate.admit(10, false, x).is_none() && x.is_some());
        }
        drop(b.take());
        drop(full);
        assert!(gate.ready(10, false, a.as_ref()) && !gate.ready(10, false, c.as_ref()));
        // c's core retries (refused, parks), then the head goes away: c takes the turn and its core is woken
        assert!(gate.admit(10, false, &mut c).is_none());
        let woken = w.0.load(Ordering::SeqCst);
        drop(a.take());
        assert!(
            w.0.load(Ordering::SeqCst) > woken,
            "the departure wakes the core"
        );
        assert!(gate.ready(10, false, c.as_ref()) && !gate.ready(10, false, d.as_ref()));
        let lc = gate.admit(10, false, &mut c).expect("c's turn");
        assert!(gate.ready(10, false, d.as_ref()) && !gate.ready(10, false, None));
        drop(d.take());
        assert!(gate.ready(10, false, None), "nobody waits: newcomers go");
        assert_eq!(credits.pool_stats()[0].waiters, 0);
        drop(lc);
        assert!(credits.idle());
    }

    #[test]
    fn saturated_shard_preserves_other_shards_count_and_byte_allowance() {
        let credits = IngressCredits::new(2);
        let a: Vec<_> = (0..WINDOW_COUNT)
            .map(|_| credits.reserve(0, 4096).unwrap())
            .collect();
        assert!(!credits.ready(0, 4096));
        assert!(credits.reserve(0, 4096).is_none());
        assert!(credits.reserve(1, 4096).is_some());
        drop(a);
        let large = credits.reserve(0, 512 << 20).unwrap();
        assert!(credits.reserve(0, 1).is_none());
        assert!(credits.reserve(1, 4096).is_some());
        drop(large);
        assert!(credits.reserve(0, WINDOW_BYTES as usize).is_some());
    }

    #[test]
    fn group_pool_bounds_the_sum_and_keeps_groups_independent() {
        let mb = 1usize << 20;
        let credits = IngressCredits::partitioned(&[(2, 100 << 20), (2, 100 << 20)]);
        let a = credits.reserve(0, 60 * mb).unwrap();
        // soft limit: below the limit any input is admitted, so the pool may overshoot by one input
        let b = credits.reserve(1, 60 * mb).unwrap();
        assert_eq!(credits.pool_stats()[0].used, 120 << 20);
        // above the limit the pool refuses, whichever window asks
        assert!(!credits.ready(0, 1));
        assert!(credits.reserve(0, 1).is_none());
        assert!(credits.reserve(1, 1).is_none());
        // the other group is untouched
        let c = credits.reserve(2, 60 * mb).unwrap();
        let s = credits.pool_stats();
        assert_eq!((s[0].used, s[1].used), (120 << 20, 60 << 20));
        assert_eq!(s[0].stalls, 2);
        drop(a);
        assert!(credits.ready(0, 60 * mb));
        // retained frame bytes count against the pool until the last clone is gone
        b.retain_frame(50 * mb);
        assert_eq!(credits.pool_stats()[0].used, 110 << 20);
        drop(b);
        drop(c);
        assert!(credits.idle());
        assert!(credits.pool_stats().iter().all(|p| p.used == 0));
    }

    #[test]
    fn frame_gate_reserves_before_assembly_and_queues_newcomers_behind_a_waiter() {
        let mb = 1usize << 20;
        let credits = IngressCredits::with_frames(&[(2, 100 << 20)], 4096);
        assert_eq!(credits.windows(), 2);
        let gate = credits.frame_gate(0);
        let (mut a, mut b, mut c) = (None, None, None);
        let big = gate.admit(100 * mb, false, &mut a).unwrap();
        assert!(gate.admit(60 * mb, false, &mut b).is_none());
        assert_eq!(credits.pool_stats()[0].waiters, 1);
        // a small newcomer queues behind the waiting large frame (no starvation of large frames)
        assert!(gate.admit(mb, false, &mut c).is_none());
        assert_eq!(credits.pool_stats()[0].waiters, 2);
        drop(big);
        let second = gate.admit(60 * mb, false, &mut b).unwrap();
        assert!(b.is_none());
        let third = gate.admit(mb, false, &mut c).unwrap();
        assert_eq!(credits.pool_stats()[0].waiters, 0);
        // many more frames than a shard window holds (128) are fine in the frame window
        drop((second, third));
        let held: Vec<_> = (0..1000)
            .map(|_| gate.admit(1024, false, &mut None).unwrap())
            .collect();
        assert_eq!(credits.pool_stats()[0].used, 1000 * 1024);
        drop(held);
        assert!(credits.idle());
        // a connection that goes away while waiting releases its place
        let held = gate.admit(100 * mb, false, &mut None).unwrap();
        let mut gone = None;
        assert!(gate.admit(mb, false, &mut gone).is_none());
        drop(gone);
        assert_eq!(credits.pool_stats()[0].waiters, 0);
        drop(held);
    }

    /// A frame above its pool's capacity is never refused for its size: it waits until it is all the pool holds and
    /// then takes the pool as its single reservation (spec msgr2.md 8.2, classic's one-message-above-the-max rule).
    #[test]
    fn a_frame_above_the_pool_capacity_is_admitted_alone() {
        let mb = 1usize << 20;
        let credits = IngressCredits::with_frames(&[(1, 4 * mb as u64)], 8);
        let gate = credits.frame_gate(0);
        let small = gate.admit(mb, false, &mut None).unwrap();
        // above the capacity while another frame is in flight: it waits (refused, no fault)
        let mut wait = None;
        assert!(gate.admit(8 * mb, false, &mut wait).is_none() && wait.is_some());
        assert!(!gate.ready(8 * mb, false, wait.as_ref()));
        // a newcomer queues behind it, so the pool can drain
        let mut second = None;
        assert!(gate.admit(1, false, &mut second).is_none() && second.is_some());
        drop(small);
        let big = gate
            .admit(8 * mb, false, &mut wait)
            .expect("alone in the empty pool");
        assert_eq!(credits.pool_stats()[0].used, 8 * mb as u64);
        assert!(
            !gate.ready(1, false, None),
            "the pool holds the oversize frame alone"
        );
        drop(big);
        let next = gate
            .admit(1, false, &mut second)
            .expect("the waiter after it");
        drop(next);
        assert!(credits.idle());
    }

    /// An input admitted alone keeps the pool as its single reservation until it drops (classic holds its throttle for
    /// a message above the max): ordinary inputs are refused, however much room the pool has left below its limit
    /// (spec msgr2.md 8.2).
    #[test]
    fn an_alone_input_keeps_the_pool_as_its_single_reservation() {
        let credits = IngressCredits::with_frames(&[(1, 100)], 8);
        let w = Arc::new(Count::default());
        let gate = credits.frame_gate(0).with_parker(Parker::new(w.clone()));
        let alone = gate.admit(20, true, &mut None).expect("empty pool");
        assert_eq!(credits.pool_stats()[0].used, 20, "the tag is not a byte");
        // 20 of 100 bytes are held: an ordinary input still waits for the whole lease to go
        let mut wait = None;
        assert!(gate.admit(5, false, &mut wait).is_none() && wait.is_some());
        assert!(!gate.ready(5, false, wait.as_ref()));
        assert_eq!(w.0.load(Ordering::SeqCst), 0, "nothing was released yet");
        drop(alone);
        assert!(
            w.0.load(Ordering::SeqCst) > 0,
            "clearing the tag wakes the parked cores"
        );
        drop(wait);
        assert_eq!(credits.pool_stats()[0].used, 0);
        let next = gate.admit(5, false, &mut None).expect("the pool is free");
        drop(next);
        assert!(credits.idle());
    }

    /// Exclusivity belongs to the reservation, whatever bytes it holds.
    #[test]
    fn a_zero_byte_alone_lease_keeps_and_releases_exclusivity() {
        let credits = IngressCredits::with_frames(&[(1, 100)], 8);
        let gate = credits.frame_gate(0);
        let alone = gate.admit(0, true, &mut None).expect("empty pool");
        // A second window shares the pool, independently of the first window's slot count.
        assert!(credits.reserve(0, 1).is_none());
        assert!(
            !credits.ready(0, 101),
            "a zero-byte tag still occupies the pool"
        );
        drop(alone);
        drop(credits.reserve(0, 1).expect("exclusivity was released"));
        assert_eq!(credits.pool_stats()[0].used, 0);
        assert!(credits.idle());

        // Dropping a fresh zero-byte lease must also clear exactly the tag it took.
        drop(gate.admit(0, true, &mut None).expect("empty pool"));
        drop(credits.reserve(0, 1).expect("zero-byte lease released"));
        assert!(credits.idle());
    }

    /// A lease that keeps the pool shrinks like any other, but the pool stays exclusive until the lease is gone.
    #[test]
    fn shrinking_an_alone_lease_keeps_the_pool_exclusive() {
        let credits = IngressCredits::with_frames(&[(1, 100)], 8);
        let gate = credits.frame_gate(0);
        let alone = gate.admit(20, true, &mut None).expect("empty pool");
        gate.shrink(&alone, 5);
        assert_eq!(credits.pool_stats()[0].used, 15);
        let mut wait = None;
        assert!(!gate.ready(5, false, None));
        assert!(gate.admit(5, false, &mut wait).is_none() && wait.is_some());
        drop(wait);
        drop(alone);
        assert_eq!(credits.pool_stats()[0].used, 0);
        let next = gate.admit(5, false, &mut None).expect("the pool is free");
        drop(next);
        assert!(credits.idle());
    }

    /// A frame above the pool is decided alone at its preamble on its whole declared size: it keeps the pool exclusive
    /// until it drops and gives back exactly what it held (spec msgr2.md 8.2, adr 0175 am. 3).
    #[test]
    fn an_alone_frame_keeps_the_pool_until_it_drops() {
        let mb = 1usize << 20;
        let credits = IngressCredits::with_frames(&[(1, 4 * mb as u64)], 8);
        let gate = credits.frame_gate(0);
        let frame = gate.admit(9 * mb, true, &mut None).expect("empty pool");
        assert_eq!(credits.pool_stats()[0].used, 9 * mb as u64);
        assert!(!gate.ready(1, false, None), "the pool holds it alone");
        assert!(gate.admit(1, false, &mut None).is_none());
        drop(frame);
        assert_eq!(credits.pool_stats()[0].used, 0);
        drop(gate.admit(1, false, &mut None));
        assert!(credits.idle());
    }

    /// While an alone lease is held, no ordinary admission of the same pool ever succeeds, whichever thread asks.
    #[test]
    fn no_ordinary_admission_passes_an_alone_lease_under_contention() {
        let credits = IngressCredits::with_frames(&[(1, 100)], 8);
        let gate = credits.frame_gate(0);
        let alone = gate.admit(20, true, &mut None).expect("empty pool");
        let released = AtomicBool::new(false);
        let refusals = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let (g, rel, n) = (gate.clone(), &released, &refusals);
            scope.spawn(move || {
                while !rel.load(Ordering::SeqCst) {
                    assert!(
                        g.admit(5, false, &mut None).is_none(),
                        "ordinary input admitted next to an alone lease"
                    );
                    n.fetch_add(1, Ordering::SeqCst);
                }
            });
            // the holder keeps the pool while another core hammers it
            while refusals.load(Ordering::SeqCst) < 1000 {
                std::hint::spin_loop();
            }
            released.store(true, Ordering::SeqCst);
        });
        assert!(refusals.load(Ordering::SeqCst) > 0);
        drop(alone);
        let next = gate
            .admit(5, false, &mut None)
            .expect("the pool is free after the alone lease");
        drop(next);
        assert!(credits.idle());
    }

    #[test]
    fn an_input_larger_than_the_pool_is_admitted_below_the_limit() {
        let credits = IngressCredits::partitioned(&[(1, 8 << 20)]);
        let small = credits.reserve(0, 1 << 20).unwrap();
        // 1 MiB < 8 MiB limit: the 32 MiB input passes (overshoot), the next one waits
        let big = credits.reserve(0, 32 << 20).unwrap();
        assert!(credits.reserve(0, 1).is_none());
        drop(small);
        assert!(credits.reserve(0, 1).is_none());
        drop(big);
        assert!(credits.reserve(0, 32 << 20).is_some());
        assert!(credits.pool_stats()[0].used == 0);
    }

    #[test]
    fn readiness_matches_oversized_shard_admission_below_the_pool_limit() {
        let credits = IngressCredits::partitioned(&[(2, 8 << 20)]);
        let small = credits.reserve(0, 1 << 20).unwrap();
        let parker = Parker::new(Arc::new(Count::default()));
        parker.arm();
        assert!(credits.ready(1, 32 << 20));
        assert!(credits.ready_or_park(1, 32 << 20, &parker));
        let big = credits.reserve(1, 32 << 20).unwrap();
        assert!(!credits.ready(0, 1));
        drop((small, big));
        assert!(credits.idle());
    }

    #[test]
    fn readiness_matches_implicit_oversized_frame_exclusivity() {
        let credits = IngressCredits::with_frames(&[(1, 8 << 20)], 8);
        let small = credits.reserve(0, 1 << 20).unwrap();
        let gate = credits.frame_gate(0);
        assert!(!gate.ready(32 << 20, false, None));
        assert!(gate.admit(32 << 20, false, &mut None).is_none());
        drop(small);
        assert!(gate.ready(32 << 20, false, None));
        let big = gate.admit(32 << 20, false, &mut None).unwrap();
        assert!(!gate.ready(1, false, None));
        drop(big);
        assert!(credits.idle());
    }

    #[test]
    fn moving_a_reservation_does_not_return_it_and_drop_returns_it_once() {
        let credits = IngressCredits::new(1);
        let lease = credits.reserve(0, WINDOW_BYTES as usize).unwrap();
        let outbox = Some(lease);
        assert!(!credits.ready(0, 1));
        let backlog = outbox;
        assert!(!credits.ready(0, 1));
        let receiver = backlog;
        let replica = receiver.as_ref().unwrap().clone();
        assert!(!credits.ready(0, 1));
        drop(receiver);
        assert!(!credits.ready(0, 1));
        drop(replica);
        assert!(credits.ready(0, WINDOW_BYTES as usize));
    }

    #[test]
    fn authenticated_frame_charge_survives_raw_fragment_and_actor_clones() {
        let credits = IngressCredits::relay();
        let raw = credits.reserve(0, 4096).unwrap();
        let actor = raw.clone();
        raw.retain_frame(WINDOW_BYTES as usize);
        let queued = actor.clone();
        assert!(!credits.ready(0, 1));
        drop(raw);
        drop(actor);
        assert!(!credits.ready(0, 1));
        queued.retain_frame(8192);
        assert!(!credits.ready(0, 1));
        drop(queued);
        assert!(credits.idle());
        assert!(credits.reserve(0, WINDOW_BYTES as usize).is_some());
    }

    /// Debug of a held lease stays one line: the per-slot arrays are internal, not log content.
    #[test]
    fn formatting_a_held_lease_stays_compact() {
        let credits = IngressCredits::with_frames(&[(1, 1 << 20)], 4096);
        let lease = credits.frame_gate(0).admit(1, false, &mut None).unwrap();
        let printed = format!("{:?}", InputGuard(Some(lease)));
        assert!(printed.len() < 1024, "{printed}");
    }

    /// The count field above the 48-bit byte field holds `MAX_WINDOW_SLOTS` slots; one more wraps it, so a window
    /// without slots (every admission refused forever) and one beyond the field are both construction errors.
    #[test]
    fn a_frame_window_takes_the_largest_slot_count_the_count_field_holds() {
        let credits = IngressCredits::with_frames(&[(1, 1 << 20)], MAX_WINDOW_SLOTS as usize);
        assert!(credits.frame_gate(0).admit(1, false, &mut None).is_some());
    }

    #[test]
    #[should_panic(expected = "window slot count")]
    fn a_frame_window_without_slots_is_refused() {
        let _ = IngressCredits::with_frames(&[(1, 1 << 20)], 0);
    }

    #[test]
    #[should_panic(expected = "window slot count")]
    fn a_frame_window_above_the_packed_count_is_refused() {
        let _ = IngressCredits::with_frames(&[(1, 1 << 20)], MAX_WINDOW_SLOTS as usize + 1);
    }

    /// The byte field must never carry into the count field: a refused retained charge leaves the reservation as it
    /// was, so the lease still returns exactly the bytes it held.
    #[test]
    fn a_retained_charge_that_would_carry_into_the_count_is_refused_first() {
        let credits = IngressCredits::relay();
        let lease = credits.reserve(0, 1).unwrap();
        let limit = lease.window.input_limit as usize;
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for _ in 0..COUNT / limit as u64 {
                lease.retain_frame(limit);
            }
        }));
        assert!(
            refused.is_err(),
            "a charge beyond the byte field is refused"
        );
        drop(lease);
        assert!(credits.idle());
        assert!(credits.pool_stats().iter().all(|p| p.used == 0));
    }

    /// `fits` rejects an impossible size; the charge packed from it is only formed after that check.
    #[test]
    fn a_reservation_larger_than_any_input_is_refused_instead_of_overflowing() {
        let credits = IngressCredits::new(1);
        assert!(credits.reserve(0, usize::MAX).is_none());
        assert!(credits.idle());
    }

    #[test]
    fn independent_producers_return_all_count_and_byte_reservations() {
        let credits = IngressCredits::new(2);
        std::thread::scope(|scope| {
            for producer in 0..4 {
                let credits = &credits;
                scope.spawn(move || {
                    // Finite attempts include reservation contention; no producer waits for another.
                    for _ in 0..10_000 {
                        if let Some(lease) = credits.reserve(producer % 2, 4096) {
                            let actor = lease.clone();
                            drop(lease);
                            drop(actor);
                        }
                    }
                });
            }
        });
        assert!(credits.idle());
        for shard in 0..2 {
            let held: Vec<_> = (0..WINDOW_COUNT)
                .map(|_| credits.reserve(shard, 4096).unwrap())
                .collect();
            assert!(credits.reserve(shard, 1).is_none());
            drop(held);
        }
        assert!(credits.idle());
    }
}
