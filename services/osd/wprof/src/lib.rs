// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Exclusive per-stage CPU time of the write path (bench `osd::xcore_tests::w4k`, doc/perf/w4k-cpu.md).
//! `span(S::X)` opens a stage; the time of nested spans is subtracted from the parent, so the stages add up to the
//! time inside the outermost span. Without feature `on` (production and every normal build) `span` is a no-op
//! zero-sized guard: no clock read, no thread-local.

/// Stages, in write-path order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum S {
    /// Client / peer message body decode.
    Decode,
    /// OSD op gate (epoch, role, tracker) before the engine.
    Gate,
    /// Op engine: dup check, object context, op interpretation, completion.
    Opexec,
    /// Op engine transaction encode (`encode_txn`).
    TxnEnc,
    /// PG: log entry, info, trim, repop message build (primary `submit_write`).
    PgLog,
    /// PG `handle_msg`: replica repop logic (log append, txn), primary reply handling.
    PeerIn,
    /// Peer message encode + hand-over (repop, replica reply).
    Send,
    /// Client reply encode + hand-over.
    Reply,
    /// storeadapt: PG txn -> store ops (translator).
    Translate,
    /// Store: object-level staging (`run_txn`).
    StoreStage,
    /// Store: validate + tree apply.
    Tree,
    /// Store: data writes, WAL unit build + device submit.
    Wal,
    /// Store poll: completions, durability, commit callbacks.
    Poll,
    /// EC primary: `ec_submit_write` (txn decode, plan, bookkeeping).
    EcPlan,
    /// EC primary: sub-read ask / reply / assemble (shard columns) of the RMW read.
    EcRead,
    /// EC primary: `ec_generate` (encode, shard txns, log entries, sub-write build).
    EcGen,
    /// Simulated NVMe device (submit, completion, buffer alloc): stands in for hardware, not OSD CPU.
    Dev,
}

/// Number of stages: one per [`S`] variant, so the last variant stays last.
pub const COUNT: usize = S::Dev as usize + 1;

/// Per stage: (ns, spans, heap allocations).
pub type Acc = [(f64, u64, u64); COUNT];
pub const NAMES: [&str; COUNT] = [
    "decode",
    "gate",
    "opexec",
    "txn encode",
    "pg log/repop build",
    "pg peer msg in",
    "peer msg encode+send",
    "client reply encode+send",
    "translate",
    "store stage",
    "store tree apply",
    "wal+data submit",
    "store poll/commit",
    "ec plan (submit_write)",
    "ec rmw read (ask/reply/assemble)",
    "ec generate+fanout",
    "sim device (not OSD CPU)",
];

/// Key classes of tree mutations (store key layout, `store::obj::keys`; pgmeta omap names, `storeadapt::meta`).
pub const KCLS: usize = 16;
pub const KNAMES: [&str; KCLS] = [
    "C coll",
    "N/L name",
    "n onode",
    "a _ (oi)",
    "a snapset",
    "a other",
    "h omap hdr",
    "e extent",
    "o pglog entry",
    "o dup",
    "o _info/_loghead/..",
    "o other omap",
    "p fragment",
    "d inline",
    "f bitmap chunk",
    "other",
];

/// Byte offset of the name part of an id-keyed key (`store::obj::keys::idkey`: tag, id u64 BE, sub tag).
const KEY_NAME: usize = 1 + core::mem::size_of::<u64>() + 1;

/// Class of a tree key.
pub fn kclass(k: &[u8]) -> usize {
    let sub = |n: usize| k.get(n..).unwrap_or(&[]);
    match k.first() {
        Some(b'C') => 0,
        Some(b'N' | b'L') => 1,
        Some(b'n') => 2,
        Some(b'a') => match sub(KEY_NAME) {
            b"_" => 3,
            b"snapset" => 4,
            _ => 5,
        },
        Some(b'h') => 6,
        Some(b'e') => 7,
        Some(b'o') => {
            let u = sub(KEY_NAME);
            if u.first().is_some_and(u8::is_ascii_digit) {
                8
            } else if u.starts_with(b"dup_") {
                9
            } else if u.starts_with(b"_") {
                10
            } else {
                11
            }
        }
        Some(b'p') => 12,
        Some(b'd') => 13,
        Some(b'f') => 14,
        _ => 15,
    }
}

/// Kind of a tree mutation: the row of [`KAcc`], so a caller cannot index past the rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kop {
    /// Key inserted or value overwritten.
    Put,
    /// Key removed.
    Del,
    /// Key range removed.
    DelRange,
}

impl Kop {
    /// Number of kinds: one per variant, so the last variant stays last.
    pub const COUNT: usize = Kop::DelRange as usize + 1;
    /// Report names, in [`Kop`] order.
    pub const NAMES: [&str; Kop::COUNT] = ["put", "del", "range del"];
}

/// Per [`Kop`] and key class: (count, key+value bytes, ns).
pub type KAcc = [[(u64, u64, f64); KCLS]; Kop::COUNT];

/// Empty [`KAcc`].
pub const KACC_ZERO: KAcc = [[(0, 0, 0.0); KCLS]; Kop::COUNT];

/// Wall time over which the tick rate is measured on the first use in the process (x86_64 TSC only).
#[cfg(all(feature = "on", target_arch = "x86_64"))]
const CALIBRATION: std::time::Duration = std::time::Duration::from_millis(50);

#[cfg(all(
    feature = "on",
    not(any(target_arch = "aarch64", target_arch = "x86_64"))
))]
compile_error!(
    "wprof `on` times with rdtsc (x86_64) or cntvct_el0 (aarch64); no other target has a counter"
);

#[cfg(all(feature = "on", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod on {
    use super::{Acc, COUNT, Kop, S};
    use std::cell::{Cell, RefCell};
    use std::marker::PhantomData;

    /// Counter tick of this thread's clock.
    #[inline(always)]
    fn now() -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            let t: u64;
            // SAFETY: reading the virtual counter is side-effect free.
            unsafe {
                core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack, preserves_flags))
            };
            t
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: rdtsc has no preconditions.
            unsafe { core::arch::x86_64::_rdtsc() }
        }
    }

    /// Counter ticks per second, read from the register (aarch64) or measured against the wall clock (x86_64).
    fn measure_rate() -> f64 {
        #[cfg(target_arch = "aarch64")]
        {
            let f: u64;
            // SAFETY: side-effect free register read.
            unsafe {
                core::arch::asm!(
                    "mrs {}, cntfrq_el0",
                    out(reg) f,
                    options(nomem, nostack, preserves_flags)
                )
            };
            f as f64
        }
        #[cfg(target_arch = "x86_64")]
        {
            let t0 = std::time::Instant::now();
            let c0 = now();
            while t0.elapsed() < super::CALIBRATION {}
            (now() - c0) as f64 / t0.elapsed().as_secs_f64()
        }
    }

    /// `ticks` at `f` ticks per second, in ns.
    fn to_ns(ticks: u64, f: f64) -> f64 {
        ticks as f64 * 1e9 / f
    }

    /// A span record: (stage, start ticks, ticks of nested spans, allocations at start, allocations of nested spans).
    type Entry = (S, u64, u64, u64, u64);

    /// Span nesting capacity per thread: each stage at most twice on one call chain; deeper nesting is a call-site
    /// bug (recursion through a span).
    const DEPTH: usize = 2 * COUNT;

    /// Placeholder of the stack slots above `open`.
    const EMPTY: Entry = (S::Decode, 0, 0, 0, 0);

    struct St {
        /// (ticks, spans, allocations) per stage, exclusive of nested spans.
        acc: [(u64, u64, u64); COUNT],
        /// Open spans, innermost at `open - 1`.
        stack: [Entry; DEPTH],
        /// Open spans on this thread.
        open: usize,
    }

    /// Counter ticks per second (one constant-rate counter per process). The first call measures it (a 50 ms busy
    /// loop on x86_64, once per process), so every caller takes it before its start tick: the loop is never booked to
    /// a span or a mutation.
    fn rate() -> f64 {
        static F: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
        *F.get_or_init(|| {
            let f = measure_rate();
            assert!(
                f.is_finite() && f > 0.0,
                "wprof: unusable counter rate {f} ticks/s (counter does not advance?)"
            );
            f
        })
    }

    thread_local! {
        static ST: RefCell<St> = const {
            RefCell::new(St {
                acc: [(0, 0, 0); COUNT],
                stack: [EMPTY; DEPTH],
                open: 0,
            })
        };
        static ALLOCS: Cell<u64> = const { Cell::new(0) };
    }

    /// Stage of the innermost open span of this thread (`None` outside any span or while the table is borrowed).
    pub fn current() -> Option<S> {
        ST.try_with(|st| {
            st.try_borrow()
                .ok()
                .and_then(|st| st.open.checked_sub(1).map(|i| st.stack[i].0))
        })
        .ok()
        .flatten()
    }

    /// One heap allocation happened on this thread (called by the bench's counting allocator).
    #[inline(always)]
    pub fn note_alloc() {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
    }

    fn allocs() -> u64 {
        ALLOCS.try_with(Cell::get).unwrap_or(0)
    }

    /// Guard of one open stage. Zero-sized and `!Send`: a guard cannot book its time to another thread's table.
    #[derive(Debug)]
    pub struct Span(PhantomData<*const ()>);

    /// Open stage `s`. The time until the guard drops is booked to `s`, exclusive of nested spans.
    #[inline(always)]
    pub fn span(s: S) -> Span {
        // The first use in the process calibrates the tick rate; it must stay outside the span it opens.
        rate();
        ST.with(|st| {
            let st = &mut *st.borrow_mut();
            assert!(st.open < DEPTH, "wprof: span nesting deeper than {DEPTH}");
            let a = allocs();
            let e: Entry = (s, now(), 0, a, 0);
            st.stack[st.open] = e;
            st.open += 1;
        });
        Span(PhantomData)
    }

    impl Drop for Span {
        #[inline(always)]
        fn drop(&mut self) {
            let t = now();
            let al = allocs();
            ST.with(|st| {
                let st = &mut *st.borrow_mut();
                if st.open == 0 {
                    return;
                }
                st.open -= 1;
                let (s, t0, child, a0, child_a) = st.stack[st.open];
                let el = t.saturating_sub(t0);
                let n = al.saturating_sub(a0);
                let a = &mut st.acc[s as usize];
                a.0 += el.saturating_sub(child);
                a.1 += 1;
                a.2 += n.saturating_sub(child_a);
                if st.open > 0 {
                    let p = &mut st.stack[st.open - 1];
                    p.2 += el;
                    p.4 += n;
                }
            });
        }
    }

    thread_local! {
        static KA: RefCell<super::KAcc> = const { RefCell::new(super::KACC_ZERO) };
    }

    /// Guard of one tree mutation (`kop`): books count, bytes and time to its key class. `!Send`, see [`Span`].
    #[derive(Debug)]
    pub struct KSpan {
        /// Keeps the guard on the thread that opened it (`!Send`), like [`Span`].
        _thread: PhantomData<*const ()>,
        op: Kop,
        cls: u8,
        bytes: u64,
        t0: u64,
        /// Ticks per second, read before `t0` so the first-use calibration stays outside the mutation.
        rate: f64,
    }

    /// One tree mutation of kind `op`; `bytes` = key + value length.
    #[inline(always)]
    pub fn kop(op: Kop, key: &[u8], bytes: usize) -> KSpan {
        let rate = rate();
        let t0 = now();
        KSpan {
            _thread: PhantomData,
            op,
            cls: super::kclass(key) as u8,
            bytes: bytes as u64,
            t0,
            rate,
        }
    }

    impl Drop for KSpan {
        fn drop(&mut self) {
            let el = to_ns(now().saturating_sub(self.t0), self.rate);
            KA.with(|k| {
                let e = &mut k.borrow_mut()[self.op as usize][self.cls as usize];
                e.0 += 1;
                e.1 += self.bytes;
                e.2 += el;
            });
        }
    }

    /// Take (and clear) this thread's tree-mutation table.
    pub fn take_keys() -> super::KAcc {
        KA.with(|k| std::mem::replace(&mut *k.borrow_mut(), super::KACC_ZERO))
    }

    /// Take (and clear) this thread's accumulators: (ns, spans, allocations) per stage.
    pub fn take() -> Acc {
        let f = rate();
        ST.with(|st| {
            let st = &mut *st.borrow_mut();
            let mut out = [(0.0, 0, 0); COUNT];
            for (o, a) in out.iter_mut().zip(st.acc.iter_mut()) {
                *o = (to_ns(a.0, f), a.1, a.2);
                *a = (0, 0, 0);
            }
            out
        })
    }
}

#[cfg(all(feature = "on", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub use on::{KSpan, Span, current, kop, note_alloc, span, take, take_keys};

#[cfg(not(feature = "on"))]
mod off {
    use super::{Acc, COUNT, Kop, S};
    use std::marker::PhantomData;

    #[derive(Debug)]
    pub struct Span(PhantomData<*const ()>);
    #[inline(always)]
    pub fn span(_: S) -> Span {
        Span(PhantomData)
    }
    pub fn take() -> Acc {
        [(0.0, 0, 0); COUNT]
    }
    pub fn current() -> Option<S> {
        None
    }
    #[inline(always)]
    pub fn note_alloc() {}
    #[derive(Debug)]
    pub struct KSpan(PhantomData<*const ()>);
    #[inline(always)]
    pub fn kop(_: Kop, _: &[u8], _: usize) -> KSpan {
        KSpan(PhantomData)
    }
    pub fn take_keys() -> super::KAcc {
        super::KACC_ZERO
    }
}
#[cfg(not(feature = "on"))]
pub use off::{KSpan, Span, current, kop, note_alloc, span, take, take_keys};

/// Is the accounting compiled in?
pub const ENABLED: bool = cfg!(feature = "on");

#[cfg(all(
    test,
    feature = "on",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
mod tests {
    use super::*;

    fn burn(us: u64) {
        let t = std::time::Instant::now();
        while t.elapsed().as_micros() < us as u128 {}
    }

    /// Every allocation on this thread is counted, as in the bench (which books allocs/op per stage).
    struct CountingAlloc;

    // SAFETY: forwards to the system allocator unchanged; the counter is a thread-local `Cell`.
    unsafe impl std::alloc::GlobalAlloc for CountingAlloc {
        unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
            note_alloc();
            unsafe { std::alloc::System.alloc(l) }
        }
        unsafe fn alloc_zeroed(&self, l: std::alloc::Layout) -> *mut u8 {
            note_alloc();
            unsafe { std::alloc::System.alloc_zeroed(l) }
        }
        unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, n: usize) -> *mut u8 {
            note_alloc();
            unsafe { std::alloc::System.realloc(p, l, n) }
        }
        unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
            unsafe { std::alloc::System.dealloc(p, l) }
        }
    }

    #[global_allocator]
    static A: CountingAlloc = CountingAlloc;

    #[test]
    fn exclusive_times_add_up() {
        let _ = take();
        let w = std::time::Instant::now();
        {
            let _a = span(S::Gate);
            burn(200);
            {
                let _b = span(S::Opexec);
                burn(300);
            }
            burn(100);
        }
        let wall = w.elapsed().as_secs_f64() * 1e9;
        let t = take();
        let (g, o) = (t[S::Gate as usize], t[S::Opexec as usize]);
        assert_eq!((g.1, o.1), (1, 1));
        assert!(g.0 > 0.0 && o.0 > 0.0, "gate {} ns, opexec {} ns", g.0, o.0);
        // Relations, not absolute windows: the wall clock of the same block carries the same preemption. Booking the
        // child to the parent too (600 + 300 us) is off by half; a loaded runner only overshoots both alike.
        let rel = (g.0 + o.0 - wall).abs() / wall;
        assert!(rel < 0.2, "gate+opexec {} ns vs wall {wall} ns", g.0 + o.0);
        assert_eq!(take()[S::Gate as usize], (0.0, 0, 0));
    }

    #[test]
    fn booked_times_are_finite_and_advance() {
        let _ = take();
        {
            let _s = span(S::Tree);
            burn(100);
        }
        let t = take();
        let (ns, n, _) = t[S::Tree as usize];
        assert_eq!(n, 1);
        assert!(ns.is_finite() && ns > 0.0, "tree {ns} ns");
        assert!(t.iter().all(|e| e.0.is_finite()));
    }

    #[test]
    fn span_books_no_allocation_of_its_own() {
        // A fresh thread: the first push of the span stack must not allocate after the counter was read.
        std::thread::spawn(|| {
            let _ = take();
            {
                let _s = span(S::Tree);
            }
            let t = take();
            assert_eq!(t[S::Tree as usize].1, 1);
            assert_eq!(t[S::Tree as usize].2, 0);
        })
        .join()
        .unwrap();
    }

    /// The 50 ms first-use calibration is booked to no span (it runs before the span's start tick).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn calibration_is_not_inside_a_span() {
        let limit = CALIBRATION.as_secs_f64() * 5e8;
        std::thread::spawn(move || {
            let s = span(S::Tree);
            drop(s);
            let (ns, n, _) = take()[S::Tree as usize];
            assert_eq!(n, 1);
            assert!(
                ns < limit,
                "tree span booked {ns} ns of the {CALIBRATION:?} calibration"
            );
        })
        .join()
        .unwrap();
    }

    /// Same for a tree mutation that is the thread's first use (no span around it).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn calibration_is_not_inside_a_mutation() {
        let limit = CALIBRATION.as_secs_f64() * 5e8;
        std::thread::spawn(move || {
            drop(kop(Kop::Put, b"nobj", 9));
            let (n, _, ns) = take_keys()[Kop::Put as usize][kclass(b"nobj")];
            assert_eq!(n, 1);
            assert!(
                ns < limit,
                "put booked {ns} ns of the {CALIBRATION:?} calibration"
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn kop_books_only_its_own_row() {
        for op in [Kop::Put, Kop::Del, Kop::DelRange] {
            let _ = take_keys();
            drop(kop(op, b"nkey", 7));
            let k = take_keys();
            for (row, entries) in k.iter().enumerate() {
                let n: u64 = entries.iter().map(|e| e.0).sum();
                assert_eq!(
                    n,
                    u64::from(row as u8 == op as u8),
                    "{op:?} booked row {row}"
                );
            }
        }
    }

    /// A span guard dropped on another thread would book its time to the wrong table: both guards are `!Send`.
    trait AmbiguousIfSend<A> {
        fn probe() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

    #[test]
    fn guards_are_not_send() {
        // Fails to compile when either guard is `Send` (the `A` of the probe turns ambiguous).
        let _ = <Span as AmbiguousIfSend<_>>::probe;
        let _ = <KSpan as AmbiguousIfSend<_>>::probe;
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "latency slot")]
    fn lat_rejects_an_unknown_slot() {
        lat(LCOUNT, lat_t0());
    }
}

/// Latency slots (LAB): wall time between two points of one operation, summed per thread ([`lat_t0`], [`lat`]).
pub const LCOUNT: usize = 8;
pub const LNAMES: [&str; LCOUNT] = [
    "repop submit->local durable",
    "repop submit->peer ack",
    "repop submit->complete",
    "repop local durable->complete",
    "ec write submit->generate",
    "ec rmw read asked->all shards in",
    "ec shard sub-read in->reply",
    "ec shard sub-write in->commit reply",
];

/// Start of a latency span (ns since an arbitrary origin; 0 when accounting is off).
#[inline(always)]
pub fn lat_t0() -> u64 {
    #[cfg(feature = "on")]
    {
        static O: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        O.get_or_init(std::time::Instant::now).elapsed().as_nanos() as u64 + 1
    }
    #[cfg(not(feature = "on"))]
    {
        0
    }
}

#[cfg(feature = "on")]
thread_local! {
    static LAT: std::cell::Cell<[(u64, u64); LCOUNT]> = const { std::cell::Cell::new([(0, 0); LCOUNT]) };
}

/// Book `now - t0` to latency slot `slot` (no-op when off or `t0 == 0`).
#[inline(always)]
pub fn lat(slot: usize, t0: u64) {
    #[cfg(feature = "on")]
    {
        debug_assert!(slot < LCOUNT, "latency slot {slot} out of range");
        if t0 != 0 && slot < LCOUNT {
            let d = lat_t0().saturating_sub(t0);
            LAT.with(|l| {
                let mut a = l.get();
                a[slot].0 += d;
                a[slot].1 += 1;
                l.set(a);
            });
        }
    }
    #[cfg(not(feature = "on"))]
    {
        let _ = (slot, t0);
    }
}

/// This thread's latency sums `(ns, count)` since the last call.
pub fn take_lat() -> [(u64, u64); LCOUNT] {
    #[cfg(feature = "on")]
    {
        LAT.with(|l| l.replace([(0, 0); LCOUNT]))
    }
    #[cfg(not(feature = "on"))]
    {
        [(0, 0); LCOUNT]
    }
}
