// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! CPU per replicated 4k client write, no hardware (doc/perf/w4k-cpu.md): three OSDs (size 3, `NV_W4K_CORES` cores each,
//! own simulated NVMe), one client on the primary, peer frames moved by hand. The device runs in virtual time, so wall
//! time of the calls into the OSDs is pure CPU. Stage times come from `wprof` spans (exclusive, test builds only);
//! msgr2 framing (crc mode, rev 2.1) of every moved frame runs through the real encoder/decoder and is timed apart.
//! `cargo test --release -p osd --lib w4k_bench -- --ignored --nocapture`
//! NV_W4K_LIVE=1 (with `lab/w4k-alloc-sites.sh`, LIVE=1): bytes each allocation site still holds after the measured writes (what the run retains; ~36 KB per write: simulated media of blocks the store never reuses, msgr2 session replay queues the hand-moved frames never ack, see doc/perf/w4k-cpu.md).
//! env: NV_W4K_OPS (measured writes, 4000), NV_W4K_WARM (12000), NV_W4K_OBJS (objects, 512), NV_W4K_CORES (2),
//! NV_W4K_SIZE (4096), NV_W4K_READ (0; 1 = measured ops are reads), NV_W4K_QD (1), NV_W4K_ROUNDS (1), NV_W4K_PGS (8), NV_W4K_FRAMING (1: msgr2 framing of moved frames), NV_W4K_TRACKER (1; 0 = osd_enable_op_tracker=false). NV_W4K_TRACE (op-trace sampling 1 of N ops, flashstore_trace_sample; unset = off). NV_W4K_CONF ("key=val ..." runtime config of every OSD, e.g. flashstore_obj_cache=false).
use super::*;
use std::time::Instant;
use wprof::{COUNT, NAMES};

// production allocator (croit-flashstore-osd feature `mimalloc`): allocation cost is a large share of the write path; counts the
// allocations of every stage (`wprof::note_alloc`)
#[cfg(not(feature = "perf4-plain-allocator"))]
struct CountingAlloc;

/// Allocation sites (NV_W4K_SITES=1, x86_64 / aarch64 with frame pointers: `RUSTFLAGS="-C force-frame-pointers=yes"`): the
/// return addresses above the allocator, counted in a fixed table (no allocation inside the allocator).
#[cfg_attr(feature = "perf4-plain-allocator", expect(dead_code))]
mod sites {
    use std::cell::{Cell, UnsafeCell};
    const N: usize = 1 << 14;
    const D: usize = 10;
    pub struct Table(UnsafeCell<([[usize; D]; N], [u64; N])>);
    // SAFETY: allocator access is gated by thread-local ON/LIVE on the single bench thread.
    unsafe impl Sync for Table {}
    pub static T: Table = Table(UnsafeCell::new(([[0; D]; N], [0; N])));
    thread_local! {
        static ON: Cell<bool> = const { Cell::new(false) };
        static LIVE: Cell<bool> = const { Cell::new(false) };
        static STACK: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }

    /// Confine allocator bookkeeping to the bench thread, including unwind cleanup.
    pub struct Tracking(std::marker::PhantomData<*mut ()>);
    static OWNER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    impl Tracking {
        pub fn begin() -> Self {
            assert!(
                OWNER
                    .compare_exchange(
                        false,
                        true,
                        std::sync::atomic::Ordering::Acquire,
                        std::sync::atomic::Ordering::Relaxed
                    )
                    .is_ok(),
                "allocation-site tables already have a bench owner"
            );
            // Cold path: pthread_getattr_np allocates on the main thread, so the
            // bounds are cached here, never queried from inside the allocator.
            STACK.set(stack_bounds());
            Self(std::marker::PhantomData)
        }
        pub fn start_round(&self, sites: bool, live: bool) {
            ON.set(false);
            LIVE.set(false);
            reset();
            ON.set(sites || live);
            LIVE.set(live);
        }
        pub fn stop_notes(&self) {
            ON.set(false);
        }
    }
    impl Drop for Tracking {
        fn drop(&mut self) {
            ON.set(false);
            LIVE.set(false);
            STACK.set((0, 0));
            OWNER.store(false, std::sync::atomic::Ordering::Release);
        }
    }

    #[inline(always)]
    fn fp() -> usize {
        let r: usize;
        #[cfg(target_arch = "x86_64")]
        // SAFETY: reads a register.
        unsafe {
            core::arch::asm!("mov {}, rbp", out(reg) r, options(nomem, nostack))
        };
        #[cfg(target_arch = "aarch64")]
        // SAFETY: reads a register.
        unsafe {
            core::arch::asm!("mov {}, x29", out(reg) r, options(nomem, nostack))
        };
        r
    }

    /// Live allocations (NV_W4K_LIVE=1): pointer -> (site index, size), open addressing.
    /// `LIVE_BYTES[site]` = bytes of that site still allocated: what a run retains per op.
    const PN: usize = 1 << 21;
    type PtrTables = ([usize; PN], [(u32, u32); PN], [i64; N]);
    pub struct Ptrs(UnsafeCell<PtrTables>);
    // SAFETY: only the bench thread touches it, see `Table`.
    unsafe impl Sync for Ptrs {}
    pub static P: Ptrs = Ptrs(UnsafeCell::new(([0; PN], [(0, 0); PN], [0; N])));
    const GONE: usize = 1;

    pub fn track(p: *mut u8, site: usize, size: usize) {
        if site == usize::MAX || !LIVE.get() {
            return;
        }
        // SAFETY: single thread, see `Ptrs`.
        let (ptrs, info, live) = unsafe { &mut *P.0.get() };
        let mut i = (p as usize >> 4).wrapping_mul(0x9e3779b97f4a7c15) >> 43;
        for _ in 0..PN {
            if ptrs[i] == 0 || ptrs[i] == GONE {
                ptrs[i] = p as usize;
                info[i] = (site as u32, size as u32);
                live[site] += size as i64;
                return;
            }
            i = (i + 1) % PN;
        }
    }

    pub fn untrack(p: *mut u8) {
        if !LIVE.get() {
            return;
        }
        // SAFETY: single thread, see `Ptrs`.
        let (ptrs, info, live) = unsafe { &mut *P.0.get() };
        let mut i = (p as usize >> 4).wrapping_mul(0x9e3779b97f4a7c15) >> 43;
        for _ in 0..PN {
            if ptrs[i] == p as usize {
                ptrs[i] = GONE;
                live[info[i].0 as usize] -= i64::from(info[i].1);
                return;
            }
            if ptrs[i] == 0 {
                return;
            }
            i = (i + 1) % PN;
        }
    }

    /// The `top` sites by live bytes: (bytes, return addresses).
    pub fn top_live(top: usize) -> Vec<(u64, [usize; D])> {
        // SAFETY: single thread, see `Table`, `Ptrs`.
        let (keys, _) = unsafe { &*T.0.get() };
        let live = unsafe { &(*P.0.get()).2 };
        let mut v: Vec<(u64, [usize; D])> = (0..N)
            .filter(|&i| live[i] > 0)
            .map(|i| (live[i] as u64, keys[i]))
            .collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.0));
        v.truncate(top);
        v
    }

    /// Site index of the current allocation (`usize::MAX` = not recorded).
    #[inline(never)]
    pub fn note() -> usize {
        if !ON.get() {
            return usize::MAX;
        }
        let mut key = [0usize; D];
        key[0] = wprof::current().map_or(255, |s| s as usize);
        let (lo, hi) = STACK.get();
        read_frames(fp(), lo, hi, &mut key);
        let h = key.iter().fold(0xcbf29ce484222325u64, |h, &x| {
            (h ^ x as u64).wrapping_mul(0x100000001b3)
        }) as usize;
        // SAFETY: single thread, see `Table`.
        let (keys, counts) = unsafe { &mut *T.0.get() };
        let mut i = h % N;
        for _ in 0..N {
            if counts[i] == 0 {
                keys[i] = key;
                counts[i] = 1;
                return i;
            }
            if keys[i] == key {
                counts[i] += 1;
                return i;
            }
            i = (i + 1) % N;
        }
        usize::MAX
    }

    /// The calling thread's stack range, as the production heap profiler uses it.
    /// May allocate (glibc, main thread): call only outside allocator tracking.
    fn stack_bounds() -> (usize, usize) {
        #[cfg(target_os = "linux")]
        // SAFETY: queries this thread's attributes; no allocator bookkeeping is needed.
        return unsafe {
            let mut attr: libc::pthread_attr_t = std::mem::zeroed();
            if libc::pthread_getattr_np(libc::pthread_self(), &mut attr) != 0 {
                (usize::MAX, usize::MAX)
            } else {
                let (mut address, mut size) = (std::ptr::null_mut(), 0usize);
                let rc = libc::pthread_attr_getstack(&attr, &mut address, &mut size);
                libc::pthread_attr_destroy(&mut attr);
                if rc != 0 {
                    (usize::MAX, usize::MAX)
                } else {
                    (address as usize, (address as usize).saturating_add(size))
                }
            }
        };
        #[cfg(target_os = "macos")]
        // SAFETY: Darwin returns the upper stack address and stack size of this thread.
        return unsafe {
            let thread = libc::pthread_self();
            let hi = libc::pthread_get_stackaddr_np(thread) as usize;
            let size = libc::pthread_get_stacksize_np(thread);
            (hi.saturating_sub(size), hi)
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        (usize::MAX, usize::MAX)
    }

    fn frame_in_bounds(f: usize, lo: usize, hi: usize) -> bool {
        f >= lo
            && f.is_multiple_of(std::mem::align_of::<usize>())
            && f.checked_add(2 * size_of::<usize>())
                .is_some_and(|end| end <= hi)
    }

    fn read_frames(mut f: usize, lo: usize, hi: usize, key: &mut [usize; D]) {
        let mut n = 1;
        let mut skip = 1;
        let mut prev = 0;
        while n < D && f > prev && frame_in_bounds(f, lo, hi) {
            // SAFETY: both words of this aligned frame record lie within this thread's mapped stack.
            // The bench is built with frame pointers; the chain is read only on its owning thread.
            let (next, ret) = unsafe { (*(f as *const usize), *((f + 8) as *const usize)) };
            if skip > 0 {
                skip -= 1;
            } else {
                key[n] = ret;
                n += 1;
            }
            if next <= f {
                break;
            }
            prev = f;
            f = next;
        }
    }

    #[test]
    fn terminal_frame_sentinel_is_not_subtracted() {
        let frame = [1usize, 42];
        let mut key = [0; D];
        let (lo, hi) = stack_bounds();
        read_frames(frame.as_ptr() as usize, lo, hi, &mut key);
        assert_eq!(key, [0; D]);
    }

    #[test]
    fn frame_records_must_fit_the_stack_before_dereference() {
        assert!(frame_in_bounds(16, 16, 32));
        assert!(!frame_in_bounds(8, 16, 32));
        assert!(!frame_in_bounds(24, 16, 32));
        assert!(!frame_in_bounds(17, 16, 40));
        assert!(!frame_in_bounds(usize::MAX - 7, 0, usize::MAX));
        // Invalid/unmapped candidates must stop without dereferencing them.
        for f in [0, 8, usize::MAX - 7] {
            let mut key = [0; D];
            let (lo, hi) = stack_bounds();
            read_frames(f, lo, hi, &mut key);
            assert_eq!(key, [0; D]);
        }
    }

    #[test]
    fn tracking_is_thread_local_and_cleared_on_drop() {
        let tracking = Tracking::begin();
        tracking.start_round(true, true);
        assert!(ON.get() && LIVE.get());
        // Bookkeeping only stores this address as a key; it never dereferences it.
        let key = 16usize;
        track(key as *mut u8, 0, 32);
        std::thread::spawn(move || {
            untrack(key as *mut u8);
            assert!(!ON.get() && !LIVE.get());
        })
        .join()
        .unwrap();
        // SAFETY: this test holds the Tracking owner; the other thread has no access.
        assert!(unsafe { &(*P.0.get()).0 }.contains(&key));
        tracking.stop_notes();
        assert!(!ON.get() && LIVE.get());
        drop(tracking);
        assert!(!ON.get() && !LIVE.get());
    }

    /// The `top` most frequent sites: (count, return addresses).
    pub fn top(top: usize) -> Vec<(u64, [usize; D])> {
        // SAFETY: single thread, see `Table`.
        let (keys, counts) = unsafe { &*T.0.get() };
        let mut v: Vec<(u64, [usize; D])> = (0..N)
            .filter(|&i| counts[i] > 0)
            .map(|i| (counts[i], keys[i]))
            .collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.0));
        v.truncate(top);
        v
    }

    /// `top` sites: by live bytes with NV_W4K_LIVE=1, else by allocation count.
    pub fn report(top: usize) -> Vec<(u64, [usize; D])> {
        if LIVE.get() {
            // SAFETY: single thread, see `Ptrs`.
            let live = unsafe { &(*P.0.get()).2 };
            eprintln!(
                "LIVE total {} bytes in {} sites, {} negative",
                live.iter().filter(|x| **x > 0).sum::<i64>(),
                live.iter().filter(|x| **x != 0).count(),
                live.iter().filter(|x| **x < 0).sum::<i64>()
            );
            top_live(top)
        } else {
            self::top(top)
        }
    }

    fn reset() {
        // SAFETY: Tracking::begin owns the tables before enabling allocator access.
        // Old rounds may retain pointers whose frees occur after tracking stops.
        unsafe {
            (*P.0.get()).0.fill(0);
            (*P.0.get()).2.fill(0);
        };
        let (keys, counts) = unsafe { &mut *T.0.get() };
        keys.iter_mut().for_each(|k| *k = [0; D]);
        counts.iter_mut().for_each(|c| *c = 0);
    }
}

// SAFETY: forwards to mimalloc unchanged; the counter is a thread-local `Cell`.
#[cfg(not(feature = "perf4-plain-allocator"))]
unsafe impl std::alloc::GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        #[cfg(feature = "perf4-overlay-allocations")]
        crate::ops::ec_overlay_keys_tests::note_alloc(l.size());
        wprof::note_alloc();
        let s = sites::note();
        let p = unsafe { mimalloc::MiMalloc.alloc(l) };
        sites::track(p, s, l.size());
        p
    }
    unsafe fn alloc_zeroed(&self, l: std::alloc::Layout) -> *mut u8 {
        #[cfg(feature = "perf4-overlay-allocations")]
        crate::ops::ec_overlay_keys_tests::note_alloc(l.size());
        wprof::note_alloc();
        let s = sites::note();
        let p = unsafe { mimalloc::MiMalloc.alloc_zeroed(l) };
        sites::track(p, s, l.size());
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        sites::untrack(p);
        unsafe { mimalloc::MiMalloc.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, n: usize) -> *mut u8 {
        #[cfg(feature = "perf4-overlay-allocations")]
        crate::ops::ec_overlay_keys_tests::note_alloc(n);
        wprof::note_alloc();
        let s = sites::note();
        sites::untrack(p);
        let q = unsafe { mimalloc::MiMalloc.realloc(p, l, n) };
        sites::track(q, s, n);
        q
    }
}

#[global_allocator]
#[cfg(not(feature = "perf4-plain-allocator"))]
static ALLOC: CountingAlloc = CountingAlloc;

fn ec_pdw() -> &'static str {
    match std::env::var("NV_W4K_PDW").as_deref() {
        Ok("auto") => "auto",
        Ok("always") => "always",
        _ => "off",
    }
}

fn env(k: &str, d: usize) -> usize {
    std::env::var(k)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(d)
}

type Sp = wprof::Acc;

/// Wall clock around the calls into the OSDs (ns, calls).
#[derive(Default, Clone, Copy)]
struct Acc {
    ns: u128,
    n: u64,
}

const PRIM: usize = 0;
const FILL_IO: usize = 256 << 10;
const REPL: usize = 1;

struct Cl {
    n: Vec<Mc>,
    acc: BTreeMap<(i32, usize, i32), u64>,
    /// Peer frames not yet delivered because the receiving link holds an input (backpressure: the OSD stops reading
    /// that link until it resumes it), by `(to, core, from)`, in order.
    backlog: BTreeMap<(i32, usize, i32), std::collections::VecDeque<crate::osd::TestFrame>>,
    frames: u64,
    /// wprof stage sums by role (primary / replica).
    sp: [Sp; 2],
    /// Tree mutations by op kind and key class, by role.
    ka: [wprof::KAcc; 2],
    /// Wall time of calls into the OSDs by role, framing tx / rx.
    wall: [Acc; 2],
    /// `next_timer` after each call that worked, by role (not in `wall`).
    tq: [Acc; 2],
    tx: Acc,
    rx: Acc,
    enc: msgr2::Encoder,
    dec: msgr2::Decoder,
    framing: bool,
    primary: i32,
    pgs: u32,
    /// 0 = replicated, 1 = EC k2m1 legacy (mode L1), 2 = EC k2m1 optimized (mode O).
    ec: usize,
    /// Idle 1 ms ticks the settle loops needed (a write that waits for a timer shows here).
    ticks: u64,
    /// Length of one idle tick (`NV_W4K_TICK_US`, read once: not a per-settle getenv).
    tick: Duration,
    /// Blocking device reads by role of the OSD that did them.
    sync: [u64; 2],
    /// `require_osd_release` of the map (tentacle+ = EC sub-read replies with a DATA segment).
    release: u8,
}

static MISS0: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static MISS0_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn add(sp: &mut Sp, o: Sp) {
    for (a, b) in sp.iter_mut().zip(o) {
        a.0 += b.0;
        a.1 += b.1;
        a.2 += b.2;
    }
}

impl Cl {
    fn new(cores: usize, framing: bool, pgs: u32, ec: usize) -> Cl {
        let mut c = Cl {
            n: (0..3).map(|w| Mc::with_wal(w, cores, 1 << 15)).collect(),
            acc: BTreeMap::new(),
            backlog: BTreeMap::new(),
            frames: 0,
            sp: [[(0.0, 0, 0); COUNT]; 2],
            ka: [wprof::KACC_ZERO; 2],
            wall: [Acc::default(); 2],
            tq: [Acc::default(); 2],
            tx: Acc::default(),
            rx: Acc::default(),
            enc: msgr2::Encoder::new(msgr2::Revision::V21),
            dec: msgr2::Decoder::new(msgr2::Revision::V21),
            framing,
            primary: 0,
            pgs,
            ec,
            ticks: 0,
            tick: Duration::from_micros(env("NV_W4K_TICK_US", 1000) as u64),
            sync: [0; 2],
            release: release::UMBRELLA,
        };
        if ec > 0 {
            for m in &mut c.n {
                for o in &mut m.osds {
                    for (k, v) in [
                        ("ec_enable_pools", "all"),
                        ("ec_enable_primary", "true"),
                        ("ec_enable_optimized", if ec == 2 { "all" } else { "off" }),
                        (
                            "ec_enable_optimized_primary",
                            if ec == 2 { "true" } else { "false" },
                        ),
                        ("ec_pdw", ec_pdw()),
                    ] {
                        o.conf.set(crate::config::Level::Override, k, v).unwrap();
                    }
                    o.pg_apply_ec_cfg();
                }
            }
        }
        c
    }

    /// Run `f` (a call into OSD `who`), booking its wall time and wprof spans to the role of `who`.
    fn call<R>(&mut self, who: i32, core: usize, f: impl FnOnce(&mut Vec<Mc>) -> R) -> R {
        self.call_if(who, core, |n| (f(n), true))
    }

    /// [`Self::call`] booking only when `f` reports that it did work (polls that find nothing are idle spins).
    /// After a call that worked, the core loop asks `core` for its next deadline (`rt::pg_core`): timed apart (`tq`).
    fn call_if<R>(
        &mut self,
        who: i32,
        core: usize,
        f: impl FnOnce(&mut Vec<Mc>) -> (R, bool),
    ) -> R {
        let role = if who == self.primary { PRIM } else { REPL };
        let _ = wprof::take();
        let _ = wprof::take_keys();
        let s0 = store::dbg::SYNC_CALLS.load(std::sync::atomic::Ordering::Relaxed);
        let t = Instant::now();
        let (r, work) = f(&mut self.n);
        self.sync[role] += store::dbg::SYNC_CALLS.load(std::sync::atomic::Ordering::Relaxed) - s0;
        let ns = t.elapsed().as_nanos();
        if work {
            let a = &mut self.wall[role];
            a.ns += ns;
            a.n += 1;
            add(&mut self.sp[role], wprof::take());
            let k = wprof::take_keys();
            for (a, b) in self.ka[role].iter_mut().flatten().zip(k.iter().flatten()) {
                a.0 += b.0;
                a.1 += b.1;
                a.2 += b.2;
            }
            let t = Instant::now();
            std::hint::black_box(self.n[who as usize].osds[core].next_timer());
            self.tq[role].ns += t.elapsed().as_nanos();
            self.tq[role].n += 1;
        }
        r
    }

    fn map(&self, epoch: u32) -> OsdMap {
        let mut m = real_map();
        m.epoch = epoch;
        m.pools.retain(|id, _| matches!(id, 1 | 4));
        m.pool_name.retain(|id, _| matches!(id, 1 | 4));
        for p in m.pools.values_mut() {
            p.size = 3;
            p.min_size = 2;
        }
        let np = self.pgs;
        if let Some(p) = m.pools.get_mut(&4) {
            p.pg_num = np;
            p.pgp_num = np;
            p.pg_num_pending = np;
            p.pg_num_target = np;
        }
        if self.ec > 0 {
            let p = m.pools.get_mut(&4).unwrap();
            p.ptype = osdmap::pool::TYPE_ERASURE;
            p.size = 3;
            p.min_size = 2;
            p.stripe_width = 8192;
            p.erasure_code_profile = "w4k".into();
            p.flags &= !osdmap::pool::flags::OMAP;
            p.flags |= osdmap::pool::flags::EC_OVERWRITES;
            if self.ec == 2 {
                p.flags |= osdmap::pool::flags::EC_OPTIMIZATIONS;
                p.nonprimary_shards.insert(1);
            }
            let prof = [
                ("plugin", "isa"),
                ("technique", "reed_sol_van"),
                ("k", "2"),
                ("m", "1"),
            ];
            m.erasure_code_profiles.insert(
                "w4k".into(),
                prof.iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
            );
        }
        m.osd_state = vec![osd_state::EXISTS | osd_state::UP; 3];
        m.osd_weight = vec![0x10000; 3];
        m.require_osd_release = self.release;
        m.osd_uuid = vec![Uuid([9; 16]); 3];
        for (i, n) in self.n.iter().enumerate() {
            let o = &n.osds[0];
            m.client_addrs[i] = o.public_addrs.clone();
            m.cluster_addrs[i] = o.cluster_addrs.clone();
            m.hb_back_addrs[i] = o.hb_back_addrs.clone();
            m.hb_front_addrs[i] = o.hb_front_addrs.clone();
        }
        for inf in m.osd_info.iter_mut() {
            inf.up_from = 10;
            inf.up_thru = epoch;
            inf.down_at = 0;
        }
        m
    }

    /// msgr2 framing of one moved frame (what the sockets would carry), timed apart.
    fn frame(&mut self, ty: u16, ver: u16, segs: &messages::Segments, tid: u64) {
        if !self.framing {
            return;
        }
        let hb = msgr2::MsgHeader2 {
            seq: 1,
            tid,
            msg_type: ty,
            priority: 127,
            version: ver,
            data_pre_padding_len: 0,
            data_off: 0,
            ack_seq: 0,
            flags: 1,
            compat_version: 1,
            reserved: 0,
        };
        let (mut out, mut chunks) = (Vec::new(), Vec::new());
        let t = Instant::now();
        // as the connection does: large data / spliced front runs by reference (crc only)
        self.enc
            .encode_message_rope(
                &hb.to_bytes(),
                &segs.front,
                &segs.front_zc,
                &segs.front_hints,
                &segs.middle,
                &segs.data,
                &Default::default(),
                &mut out,
                &mut chunks,
            )
            .unwrap();
        self.tx.ns += t.elapsed().as_nanos();
        self.tx.n += 1;
        // (the socket gathers the runs; not timed)
        let mut wire = Vec::new();
        for c in &chunks {
            wire.extend_from_slice(c);
        }
        wire.extend_from_slice(&out);
        let t = Instant::now();
        self.dec.feed(&wire);
        std::hint::black_box(self.dec.poll_owned().unwrap().unwrap());
        self.rx.ns += t.elapsed().as_nanos();
        self.rx.n += 1;
    }

    /// Hops and store polls of every core of every node; true if anything moved.
    fn pump(&mut self) -> bool {
        let mut progress = false;
        for w in 0..3usize {
            for i in 0..self.n[w].n {
                // retained inputs (backpressure) resume first, as the core loop does (`rt::pg_core`)
                let t = self.n[w].t;
                progress |= self.call_if(w as i32, i, |n| {
                    let r = n[w].osds[i].resume_inputs(t);
                    (r, r)
                });
                loop {
                    let t = self.n[w].t;
                    let moved = self.call_if(w as i32, i, |n| {
                        let Some((dst, m)) = n[w].osds[i].poll_xmsg() else {
                            return (false, false);
                        };
                        n[w].osds[dst].on_xmsg_send_first(i, m, t);
                        n[w].osds[dst].apply_late();
                        (true, true)
                    });
                    if !moved {
                        break;
                    }
                    progress = true;
                }
                let t = self.n[w].t;
                let p = self.call_if(w as i32, i, |n| {
                    let p = n[w].osds[i].poll_store(t);
                    (p, p)
                });
                progress |= p;
            }
        }
        progress
    }

    /// Let simulated time pass for every node alike: device completions, timers.
    fn tick(&mut self, d: Duration) {
        for w in 0..3usize {
            self.n[w].t += d;
            let t = self.n[w].t;
            for i in 0..self.n[w].n {
                self.n[w].osds[i].pg.store.with_store(|s| s.idle());
                if self.n[w].osds[i].next_timer().is_some_and(|x| x <= t) {
                    self.call(w as i32, i, |n| n[w].osds[i].on_timer(t));
                }
            }
        }
    }

    fn exchange(&mut self) -> bool {
        let mut moved = false;
        let accepted: BTreeMap<(i32, usize, u64), i32> = self
            .acc
            .iter()
            .map(|(&(r, c, s), &l)| ((r, c, l), s))
            .collect();
        for from in 0..3i32 {
            let mut frames = Vec::new();
            {
                let x = &mut self.n[from as usize];
                for (c, o) in x.osds.iter_mut().enumerate() {
                    let out = std::mem::take(&mut o.t.out);
                    for f in out {
                        match o.links.get(&f.0).map(|l| l.purpose) {
                            Some(crate::osd::Purpose::Peer(to)) => frames.push((to, f)),
                            Some(crate::osd::Purpose::Accepted)
                                if let Some(&to) = accepted.get(&(from, c, f.0)) =>
                            {
                                frames.push((to, f))
                            }
                            _ => o.t.out.push(f),
                        }
                    }
                    // the frames are delivered below (in order, no loss): nothing stays queued on the connections (no wire here)
                    for l in o.links.values_mut() {
                        if matches!(
                            l.purpose,
                            crate::osd::Purpose::Peer(_) | crate::osd::Purpose::Accepted
                        ) {
                            l.conn.harness_delivered_all();
                        }
                    }
                }
            }
            for (to, f) in frames {
                // one connection per OSD pair: a peer's frames arrive in order on one core (round robin reordered repops)
                let core = from as usize % self.n[to as usize].n;
                self.backlog
                    .entry((to, core, from))
                    .or_default()
                    .push_back(f);
            }
            for to in 0..3i32 {
                for core in 0..self.n[to as usize].n {
                    moved |= self.deliver(from, to, core);
                }
            }
        }
        moved
    }

    /// Deliver the backlog of `from` -> `to` (core `core`) in order while the receiving link reads (a held input stops
    /// it, as a real driver stops reading the socket). `true` = something was delivered.
    fn deliver(&mut self, from: i32, to: i32, core: usize) -> bool {
        let key = (to, core, from);
        let mut moved = false;
        loop {
            let y = &mut self.n[to as usize];
            let live = self
                .acc
                .get(&key)
                .copied()
                .filter(|l| y.osds[core].links.contains_key(l));
            if live.is_some_and(|l| y.osds[core].links[&l].pending_input.is_some()) {
                return moved;
            }
            let Some((_, tid, (ty, ver, _), segs)) =
                self.backlog.get_mut(&key).and_then(|q| q.pop_front())
            else {
                return moved;
            };
            moved = true;
            self.frames += 1;
            self.frame(ty, ver, &segs, tid);
            let y = &mut self.n[to as usize];
            let t = y.t;
            let link = match live {
                Some(l) => l,
                None => {
                    let ip = [10, 1, 0, 4 + from as u8];
                    let l =
                        y.osds[core].on_accept(Listener::Cluster, crate::osd::sock4(ip, 41000), t);
                    y.osds[core].links.get_mut(&l).unwrap().peer = Some(msgr2::PeerInfo {
                        name: EntityName::osd(i64::from(from)),
                        addrs: addr(ip, 6801, 555 + from as u32),
                        features: u64::MAX,
                        lossy: false,
                        resumed: false,
                        global_id: 1,
                        auth_name: None,
                    });
                    self.acc.insert(key, l);
                    l
                }
            };
            self.call(to, core, |n| {
                n[to as usize].osds[core].set_now(t);
                n[to as usize].osds[core].on_unknown_message(link, tid, ty, ver, &segs)
            });
        }
    }

    fn settle(&mut self) {
        let mut quiet = 0;
        for _ in 0..200_000 {
            let p = self.pump();
            let e = self.exchange();
            if p || e {
                quiet = 0;
                continue;
            }
            quiet += 1;
            if quiet > 3 {
                return;
            }
            self.ticks += 1;
            self.tick(self.tick);
        }
        panic!("cluster did not settle");
    }

    fn run_for(&mut self, d: Duration) {
        let end = self.n[0].t + d;
        while self.n[0].t < end {
            self.tick(Duration::from_millis(100));
            self.settle();
        }
    }

    fn up(&mut self) {
        let m = self.map(10);
        for n in self.n.iter_mut() {
            n.deliver(m.clone());
        }
        self.settle();
        let map = self.n[0].osds[0].osdmap().unwrap().clone();
        let np = map.pool(4).unwrap().pg_num;
        let mut by: [Vec<u32>; 3] = Default::default();
        for seed in 0..np {
            let a = map.pg_to_up_acting(PgT::new(4, seed));
            by[a.acting_primary as usize].push(seed);
        }
        for (w, seeds) in by.into_iter().enumerate() {
            if !seeds.is_empty() {
                self.n[w].create_pgs(4, seeds);
            }
        }
        let tm = self.n.iter().map(|n| n.t).max().unwrap();
        for n in self.n.iter_mut() {
            n.t = tm;
        }
        self.settle();
        // peering of many PGs takes longer than a fixed wait: until every primary PG of the pool is active (bounded)
        let limit = Duration::from_secs(120);
        let t0 = self.n[0].t;
        self.run_for(Duration::from_secs(5));
        while !self.all_active() {
            if self.n[0].t - t0 > limit {
                eprintln!(
                    "WARNING TIMEOUT w4k_bench peering exceeded {:.3}s (virtual; {np} PGs of pool 4)",
                    limit.as_secs_f64()
                );
                for (w, m) in self.n.iter().enumerate() {
                    for (c, o) in m.osds[..m.n].iter().enumerate() {
                        let stuck: Vec<String> = o
                            .pg
                            .set
                            .pgs()
                            .filter(|(s, p)| s.pgid.pool == 4 && p.is_primary() && !p.is_active())
                            .take(4)
                            .map(|(s, p)| {
                                format!("{}.{:x}:{:#x}", s.pgid.pool, s.pgid.seed, p.state_bits())
                            })
                            .collect();
                        let held = o
                            .links
                            .values()
                            .filter(|l| l.pending_input.is_some())
                            .count();
                        eprintln!("w4k: osd.{w} core {c}: inactive {stuck:?} held links {held}");
                    }
                }
                let backlog: usize = self.backlog.values().map(|q| q.len()).sum();
                eprintln!("w4k: undelivered peer frames {backlog}");
                break;
            }
            self.run_for(Duration::from_secs(1));
        }
    }

    /// Every primary PG of pool 4 (on its acting primary) is active.
    fn all_active(&self) -> bool {
        self.n.iter().all(|m| {
            m.osds[..m.n].iter().all(|o| {
                o.pg.set
                    .pgs()
                    .filter(|(s, p)| s.pgid.pool == 4 && p.is_primary())
                    .all(|(_, p)| p.is_active())
            })
        })
    }

    /// Snapshot of every counter (the measured part is the difference to the one after the warm-up).
    /// Device (read cmds, read blocks, write cmds, write blocks) summed over the 3 OSDs.
    fn dev_stats(&self) -> [u64; 4] {
        let mut a = [0u64; 4];
        for m in &self.n {
            let s = m.disk.stats();
            a[0] += s.reads;
            a[1] += s.read_lbas;
            a[2] += s.writes;
            a[3] += s.write_lbas;
        }
        a
    }

    fn snap(&self) -> (/* sp */ [Sp; 2], [Acc; 2], Acc, Acc, u64) {
        (self.sp, self.wall, self.tx, self.rx, self.frames)
    }

    /// Store checkpoints, used and held bytes summed over the 3 OSDs (held = freed blocks waiting for a checkpoint).
    fn store_space(&self) -> (u64, u64, u64) {
        let mut r = (0, 0, 0);
        for m in &self.n {
            for o in &m.osds[..m.n] {
                o.pg.store.with_store(|s| {
                    let f = s.statfs();
                    r.0 += s
                        .perf_counters()
                        .iter()
                        .find(|p| p.0 == "ckpt_ends")
                        .map_or(0, |p| p.2);
                    r.1 += f.held_bytes;
                    r.2 += f.used_bytes;
                });
            }
        }
        r
    }

    /// Store polls that reaped durable PG txns and those txns, by role (primary / replicas summed).
    fn commit_passes(&self) -> [(u64, u64); 2] {
        let mut r = [(0, 0); 2];
        for (w, m) in self.n.iter().enumerate() {
            for o in &m.osds[..m.n] {
                let x = &mut r[usize::from(w != 0)];
                x.0 += o.pg.c.commit_polls;
                x.1 += o.pg.c.commits;
            }
        }
        r
    }

    /// Object-state cache (hits, misses) of the primary OSD, all cores.
    fn obj_cache_hm(&self) -> (u64, u64) {
        let o = &self.n[0].osds[..self.n[0].n];
        (
            o.iter().map(|o| o.perf.op.obj_cache_hit).sum(),
            o.iter().map(|o| o.perf.op.obj_cache_miss).sum(),
        )
    }

    /// Tree page splits by role (primary / replicas summed).
    fn splits(&self) -> [u64; 2] {
        let mut r = [0; 2];
        for (w, m) in self.n.iter().enumerate() {
            for o in &m.osds[..m.n] {
                r[usize::from(w != 0)] += o.pg.store.with_store(|s| s.tree_stats().splits);
            }
        }
        r
    }
}

#[test]
#[ignore]
fn w4k_bench() {
    if !wprof::ENABLED {
        panic!("run as a test of the osd crate (wprof feature on)");
    }
    let (ops, warm, nobj) = (
        env("NV_W4K_OPS", 4000),
        env("NV_W4K_WARM", 12000),
        env("NV_W4K_OBJS", 512),
    );
    let (cores, size, qd, rounds, pgs, framing) = (
        env("NV_W4K_CORES", 2),
        env("NV_W4K_SIZE", 4096),
        env("NV_W4K_QD", 1),
        env("NV_W4K_ROUNDS", 1),
        env("NV_W4K_PGS", 8),
        env("NV_W4K_FRAMING", 1) != 0,
    );
    // NV_W4K_READ=1: the measured ops read `size` bytes of the objects the warm-up wrote
    let reads = env("NV_W4K_READ", 0) != 0;
    let mut sp: [Sp; 2] = [[(0.0, 0, 0); COUNT]; 2];
    let mut wall = [Acc::default(); 2];
    let (mut tx, mut rx) = (Acc::default(), Acc::default());
    let (mut harness_ns, mut done, mut frames) = (0u128, 0u64, 0u64);
    let mut ka_tot = [wprof::KACC_ZERO; 2];
    let mut split_n = [0u64; 2];
    let mut passes = [(0u64, 0u64); 2];
    let mut space = (0u64, 0u64, 0u64);
    let mut stores = [0u64; 2];
    let mut ticks = 0u64;
    let mut tq = [Acc::default(); 2];
    let mut sync_calls = 0u64;
    let mut vtime = Duration::ZERO;
    let mut all_lat: Vec<u32> = Vec::new();
    let mut sync_role = [0u64; 2];
    let mut pf_tot = [0u64; 3];
    // device commands / blocks (reads, writes) over the 3 OSDs in the measured phase
    let mut dev_tot = [0u64; 4];
    let tracking = sites::Tracking::begin();
    // object-state cache (adr 0160 D5) hits / misses of the primary OSD in the measured phase
    let mut obj_hm = (0u64, 0u64);
    for _ in 0..rounds {
        let mut c = Cl::new(cores, framing, pgs as u32, env("NV_W4K_EC", 0));
        c.up();
        if env("NV_W4K_NVPEERS", 1) != 0 {
            // the fake handshake carries no boot metadata: every OSD of the bench runs croit-flashstore-osd
            for m in &mut c.n {
                for o in &mut m.osds {
                    o.pg.peer_nv = (0..3).collect();
                    let _ = o.pg.set.set_flashstore_peers(o.pg.peer_nv.clone());
                }
            }
        }
        if env("NV_W4K_TRACKER", 1) == 0 {
            for m in &mut c.n {
                for o in &mut m.osds {
                    o.conf
                        .set(
                            crate::config::Level::Override,
                            "osd_enable_op_tracker",
                            "false",
                        )
                        .unwrap();
                    o.refresh_obs_conf();
                }
            }
        }
        if let Ok(kvs) = std::env::var("NV_W4K_CONF") {
            for (k, v) in kvs.split_whitespace().filter_map(|kv| kv.split_once('=')) {
                for m in &mut c.n {
                    for o in &mut m.osds {
                        o.conf.set(crate::config::Level::Override, k, v).unwrap();
                        o.refresh_obs_conf();
                    }
                }
            }
        }
        if let Ok(n) = std::env::var("NV_W4K_TRACE") {
            for m in &mut c.n {
                for o in &mut m.osds {
                    o.conf
                        .set(
                            crate::config::Level::Override,
                            "flashstore_trace_sample",
                            &n,
                        )
                        .unwrap();
                    o.refresh_obs_conf();
                }
            }
        }
        c.up();
        let map = c.n[0].osds[0].osdmap().unwrap().clone();
        if std::env::var("NV_W4K_DBG").is_ok() {
            for seed in 0..pgs as u32 {
                eprintln!(
                    "pg 4.{seed} acting {:?}",
                    map.pg_to_up_acting(PgT::new(4, seed))
                );
            }
            eprintln!(
                "info {:?}",
                peering::map::ec_pool_info(&map, map.pool(4).unwrap())
            );
            eprintln!(
                "pool {:?}",
                map.pool(4)
                    .map(|p| (p.ptype, p.size, p.crush_rule, p.flags))
            );
            for (w, m) in c.n.iter().enumerate() {
                eprintln!("osd{w} ec status {:?}", m.osds[0].pg.set.is_passive(4));
            }
        }
        let mut names = Vec::new();
        let mut i = 0u64;
        while names.len() < nobj {
            let name = format!("rbd_data.5f3a2b8c4d.{i:016x}");
            i += 1;
            let raw = map
                .object_to_raw_pg(4, name.as_bytes(), b"", b"", -1)
                .unwrap();
            let pg = PgT::new(4, pgwire::pgmath::object_pg(raw.seed, pgs as u32));
            if map.pg_to_up_acting(pg).acting_primary == 0 {
                names.push(name);
            }
        }
        let mut links: Vec<(usize, u64)> = (0..cores).map(|k| (k, c.n[0].client(k))).collect();
        let mut rng = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let lats: std::rc::Rc<std::cell::RefCell<Vec<u32>>> = Default::default();
        let sent_at: std::rc::Rc<std::cell::RefCell<BTreeMap<u64, Duration>>> = Default::default();
        let (lats_c, sent_c) = (lats.clone(), sent_at.clone());
        let payload: Vec<u8> = (0..size).map(|i| (i * 31) as u8).collect();
        let mut tid = 1u64;
        // NV_W4K_FILL=1: every object is written whole first (256 KiB writes), so the measured writes overwrite real data
        // (EC: RMW reads hit the device, like a prefilled rbd image)
        let fill_pay: Vec<u8> = (0..FILL_IO).map(|i| (i * 7) as u8).collect();
        let mut run = |c: &mut Cl, n: usize, fill: bool, rd: bool| {
            let (mut sent, mut got, mut idle) = (0usize, 0usize, 0);
            while got < n {
                idle += 1;
                if idle >= 1000 {
                    for (w, m) in c.n.iter().enumerate() {
                        for (i, o) in m.osds.iter().enumerate() {
                            for seed in 0..pgs as u32 {
                                for sh in [-1i8, 0, 1, 2] {
                                    let s = SpgT {
                                        pgid: PgT::new(4, seed),
                                        shard: denc::types::ShardId(sh),
                                    };
                                    if let Some(p) = o.pg.set.pg(s) {
                                        eprintln!(
                                            "osd{w} core{i} {s:?} state {:#x} held {} refusal {:?} ec client reads {}",
                                            p.state_bits(),
                                            p.repops_held(),
                                            p.refusal(),
                                            p.ec_client_reads()
                                        );
                                    }
                                }
                            }
                        }
                    }
                    for (i, o) in c.n[0].osds.iter().enumerate() {
                        for (s, e) in o.pg.eng.iter() {
                            eprintln!("core{i} {s:?} {}", e.dump_state());
                        }
                        eprintln!("core{i} {}", o.pg.store.with_store(|s| s.diag()));
                    }
                    {
                        use std::sync::atomic::Ordering::Relaxed;
                        use store::dbg::*;
                        eprintln!(
                            "pf submit {} served {} expired {}",
                            PF_SUBMIT.load(Relaxed),
                            PF_SERVED.load(Relaxed),
                            PF_EXPIRED.load(Relaxed)
                        );
                    }
                    panic!("stalled: sent {sent} got {got}");
                }
                let mut batch = Vec::new();
                while sent < n && sent - got + batch.len() < qd {
                    let r = next();
                    let per = (4 << 20) / FILL_IO;
                    let (obj, off, pl) = if fill {
                        (
                            &names[sent / per],
                            ((sent % per) * FILL_IO) as u64,
                            &fill_pay,
                        )
                    } else if reads {
                        // reads walk the objects in order (rados bench seq): more objects than the EC read cache holds never
                        // hit it; whole objects from offset 0
                        (&names[sent % nobj], 0, &payload)
                    } else {
                        let off = ((r >> 20) % (4 << 20) / size as u64) * size as u64;
                        (&names[(r % nobj as u64) as usize], off, &payload)
                    };
                    let o = if rd {
                        OsdOp::read(off, size as u64)
                    } else {
                        OsdOp::write(off, pl.clone())
                    };
                    batch.push(c.n[0].op(4, obj, vec![o]));
                    sent += 1;
                }
                for op in batch {
                    let k = (tid as usize) % cores;
                    // links time out in the fake handshake after ~10 s of virtual time: replace them
                    if !c.n[0].osds[k].links.contains_key(&links[k].1) {
                        links[k].1 = c.n[0].client(k);
                    }
                    let (core, link) = links[k];
                    let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
                    c.frame(ty, ver, &segs, tid);
                    sent_c.borrow_mut().insert(tid, c.n[0].t);
                    let t = c.n[0].t;
                    c.call(0, core, |n| {
                        n[0].osds[core].set_now(t);
                        n[0].osds[core].on_unknown_message(link, tid, ty, ver, &segs)
                    });
                    tid += 1;
                }
                c.settle();
                for &(core, link) in &links {
                    let r = c.n[0].replies(core, link);
                    for (rtid, rep) in &r {
                        if let Some(t0) = sent_c.borrow_mut().remove(rtid) {
                            lats_c.borrow_mut().push((c.n[0].t - t0).as_micros() as u32);
                        }
                        assert_eq!(rep.result, 0);
                        if rd {
                            assert_eq!(rep.ops[0].outdata.len(), size, "short read");
                        }
                    }
                    if !r.is_empty() {
                        idle = 0;
                    }
                    got += r.len();
                }
            }
        };
        if env("NV_W4K_FILL", 0) != 0 {
            run(&mut c, nobj * ((4 << 20) / FILL_IO), true, false);
        }
        run(&mut c, warm, false, false);
        let sites_on = env("NV_W4K_SITES", 0) != 0;
        let before = c.snap();
        let obj_hm0 = c.obj_cache_hm();
        let splits0 = c.splits();
        let passes0 = c.commit_passes();
        let ticks0 = c.ticks;
        let tq0 = c.tq;
        let vt0 = c.n[0].t;
        let sync_r0 = c.sync;
        for x in store::dbg::MISS_TAG.iter() {
            x.store(0, std::sync::atomic::Ordering::Relaxed);
        }
        MISS0.store(
            store::dbg::MISS_CALLS.load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );
        MISS0_NS.store(
            store::dbg::MISS_NS.load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );
        let sync0 = store::dbg::SYNC_CALLS.load(std::sync::atomic::Ordering::Relaxed);
        let pf0 = pf_counts();
        let dev0 = c.dev_stats();
        c.ka = [wprof::KACC_ZERO; 2];
        let live_on = env("NV_W4K_LIVE", 0) != 0;
        tracking.start_round(sites_on, live_on);
        lats.borrow_mut().clear();
        let t0 = Instant::now();
        run(&mut c, ops, false, reads);
        all_lat.extend(lats.borrow().iter().copied());
        tracking.stop_notes();
        let el = t0.elapsed().as_nanos();
        let mut timed = 0u128;
        let after = c.snap();
        let obj_hm1 = c.obj_cache_hm();
        obj_hm.0 += obj_hm1.0 - obj_hm0.0;
        obj_hm.1 += obj_hm1.1 - obj_hm0.1;
        let splits1 = c.splits();
        let passes1 = c.commit_passes();
        for r in 0..2 {
            passes[r].0 += passes1[r].0 - passes0[r].0;
            passes[r].1 += passes1[r].1 - passes0[r].1;
        }
        space = c.store_space();
        split_n[0] += splits1[0] - splits0[0];
        split_n[1] += splits1[1] - splits0[1];
        ticks += c.ticks - ticks0;
        for r in 0..2 {
            tq[r].ns += c.tq[r].ns - tq0[r].ns;
            tq[r].n += c.tq[r].n - tq0[r].n;
            timed += c.tq[r].ns - tq0[r].ns;
        }
        vtime += c.n[0].t - vt0;
        sync_role[0] += c.sync[0] - sync_r0[0];
        sync_role[1] += c.sync[1] - sync_r0[1];
        sync_calls += store::dbg::SYNC_CALLS.load(std::sync::atomic::Ordering::Relaxed) - sync0;
        for (a, (x, y)) in pf_tot.iter_mut().zip(pf_counts().iter().zip(pf0)) {
            *a += x - y;
        }
        for (a, (x, y)) in dev_tot.iter_mut().zip(c.dev_stats().iter().zip(dev0)) {
            *a += x - y;
        }
        for (a, b) in ka_tot
            .iter_mut()
            .flatten()
            .flatten()
            .zip(c.ka.iter().flatten().flatten())
        {
            a.0 += b.0;
            a.1 += b.1;
            a.2 += b.2;
        }
        for (r, st) in stores.iter_mut().enumerate() {
            *st += after.0[r][wprof::S::Tree as usize].1 - before.0[r][wprof::S::Tree as usize].1;
        }
        for r in 0..2 {
            for (k, s) in sp[r].iter_mut().enumerate() {
                s.0 += after.0[r][k].0 - before.0[r][k].0;
                s.1 += after.0[r][k].1 - before.0[r][k].1;
                s.2 += after.0[r][k].2 - before.0[r][k].2;
            }
            wall[r].ns += after.1[r].ns - before.1[r].ns;
            wall[r].n += after.1[r].n - before.1[r].n;
            timed += after.1[r].ns - before.1[r].ns;
        }
        if env("NV_W4K_LIVE", 0) != 0 {
            // what the cluster still holds after the measured writes (before it is dropped)
            print_sites(ops as u64);
        }
        tx.ns += after.2.ns - before.2.ns;
        tx.n += after.2.n - before.2.n;
        rx.ns += after.3.ns - before.3.ns;
        rx.n += after.3.n - before.3.n;
        timed += (after.2.ns - before.2.ns) + (after.3.ns - before.3.ns);
        harness_ns += el.saturating_sub(timed);
        frames += after.4 - before.4;
        done += ops as u64;
    }
    let us = |ns: f64| ns / done as f64 / 1000.0;
    println!(
        "w4k: {done} {} of {size} B, size 3, {cores} cores/osd, QD {qd}, {:.1} frames/op, msgr2 framing {}",
        if reads { "reads" } else { "writes" },
        frames as f64 / done as f64,
        if framing { "on" } else { "off" }
    );
    println!(
        "| stage | primary us/op | replicas us/op (2 summed) | per replica | allocs/op primary | allocs/op per replica |"
    );
    println!("|---|---|---|---|---|---|");
    let (mut sp_p, mut sp_r) = (0.0, 0.0);
    for k in 0..COUNT {
        let (p, r) = (sp[PRIM][k].0, sp[REPL][k].0);
        sp_p += p;
        sp_r += r;
        let al = |n: u64| n as f64 / done as f64;
        println!(
            "| {} | {:.2} | {:.2} | {:.2} | {:.1} | {:.1} |",
            NAMES[k],
            us(p),
            us(r),
            us(r) / 2.0,
            al(sp[PRIM][k].2),
            al(sp[REPL][k].2) / 2.0
        );
    }
    let dev = wprof::S::Dev as usize;
    let (dp, dr) = (sp[PRIM][dev].0, sp[REPL][dev].0);
    // the simulated device stands in for hardware: its time is not OSD CPU
    let (wp, wr) = (wall[PRIM].ns as f64 - dp, wall[REPL].ns as f64 - dr);
    let (sp_p, sp_r) = (sp_p - dp, sp_r - dr);
    println!(
        "| other (OSD code outside spans: loops, links, timers, glue) | {:.2} | {:.2} | {:.2} |",
        us(wp - sp_p),
        us(wr - sp_r),
        us(wr - sp_r) / 2.0
    );
    println!(
        "| OSD total | {:.2} | {:.2} | {:.2} |",
        us(wp),
        us(wr),
        us(wr) / 2.0
    );
    println!(
        "| msgr2 frame encode+crc (tx), {:.1} frames/op | {:.2} | | |",
        tx.n as f64 / done as f64,
        us(tx.ns as f64)
    );
    println!(
        "| msgr2 frame crc+decode (rx) | {:.2} | | |",
        us(rx.ns as f64)
    );
    println!(
        "| total CPU (3 OSDs + framing) | {:.2} | | |",
        us(wp + wr + (tx.ns + rx.ns) as f64)
    );
    println!(
        "| harness + sim device (not OSD CPU) | {:.2} | | |",
        us(harness_ns as f64)
    );
    println!(
        "| timer query (`next_timer` after each busy call, as the core loop; not in OSD total), {:.1} / {:.1} calls/op | {:.2} | {:.2} | {:.2} |",
        tq[PRIM].n as f64 / done as f64,
        tq[REPL].n as f64 / done as f64 / 2.0,
        us(tq[PRIM].ns as f64),
        us(tq[REPL].ns as f64),
        us(tq[REPL].ns as f64) / 2.0
    );
    all_lat.sort_unstable();
    let pct = |p: f64| {
        all_lat
            .get(((all_lat.len() as f64 * p) as usize).min(all_lat.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0)
    };
    println!(
        "client latency (virtual us, tick-quantized): p50 {} p99 {} p99.9 {} p99.99 {} max {}",
        pct(0.5),
        pct(0.99),
        pct(0.999),
        pct(0.9999),
        all_lat.last().copied().unwrap_or(0)
    );
    let d = done as f64;
    println!(
        "object-state cache (primary, {pgs} PGs): {} hits {} misses, hit rate {:.1} %",
        obj_hm.0,
        obj_hm.1,
        100.0 * obj_hm.0 as f64 / (obj_hm.0 + obj_hm.1).max(1) as f64
    );
    println!(
        "virtual time (sim device + ticks): {:.1} us per write = {:.0} writes/s at QD {qd}",
        vtime.as_secs_f64() * 1e6 / d,
        d / vtime.as_secs_f64()
    );
    println!(
        "data prefetch per write (3 OSDs): submitted {:.2}, served {:.2}, expired {:.2}",
        pf_tot[0] as f64 / d,
        pf_tot[1] as f64 / d,
        pf_tot[2] as f64 / d
    );
    println!(
        "device per write (3 OSDs): reads {:.2} cmds / {:.1} KiB, writes {:.2} cmds / {:.1} KiB",
        dev_tot[0] as f64 / d,
        dev_tot[1] as f64 * 4.0 / d,
        dev_tot[2] as f64 / d,
        dev_tot[3] as f64 * 4.0 / d
    );
    {
        use std::sync::atomic::Ordering::Relaxed;
        let tags: Vec<String> = store::dbg::MISS_TAG
            .iter()
            .enumerate()
            .filter_map(|(i, x)| {
                let v = x.load(Relaxed);
                (v > 0).then(|| format!("{i:#04x}:{v}"))
            })
            .collect();
        println!(
            "blocking tree-miss waits (measured phase, lab feature): {} calls, {:.1} ms spun, by tag [{}]",
            store::dbg::MISS_CALLS.load(Relaxed) - MISS0.load(Relaxed),
            (store::dbg::MISS_NS.load(Relaxed) - MISS0_NS.load(Relaxed)) as f64 / 1e6,
            tags.join(" ")
        );
    }
    println!(
        "blocking device reads on the PG core per write: {:.2} (primary {:.2}, 2 shards {:.2})",
        sync_calls as f64 / d,
        sync_role[0] as f64 / d,
        sync_role[1] as f64 / d
    );
    println!(
        "idle settle ticks per write: {:.3} x {} us, minus 4 quiet (EC mode {}, pdw {})",
        ticks as f64 / d,
        env("NV_W4K_TICK_US", 1000),
        env("NV_W4K_EC", 0),
        ec_pdw()
    );
    println!(
        "store submits per client write: primary {:.2}, per replica {:.2}",
        stores[PRIM] as f64 / d,
        stores[REPL] as f64 / d / 2.0
    );
    let each = |p: (u64, u64)| p.1 as f64 / p.0.max(1) as f64;
    println!(
        "commit passes (store polls with durable txns) per client write: primary {:.2} ({:.2} txns each), per replica {:.2} ({:.2} txns each)",
        passes[PRIM].0 as f64 / d,
        each(passes[PRIM]),
        passes[REPL].0 as f64 / d / 2.0,
        each(passes[REPL])
    );
    println!(
        "tree page splits per client write: primary {:.3}, per replica {:.3}",
        split_n[PRIM] as f64 / d,
        split_n[REPL] as f64 / d / 2.0
    );
    let (ckpts, held, used) = space;
    println!(
        "store space (3 OSDs, end of the last round): checkpoints {ckpts}, used {:.1} MiB, held for the next checkpoint {:.1} MiB",
        used as f64 / f64::from(1 << 20),
        held as f64 / f64::from(1 << 20)
    );
    println!("| tree mutation | primary n/op | B/op | ns each | replica n/op | B/op | ns each |");
    println!("|---|---|---|---|---|---|---|");
    for (o, name) in wprof::Kop::NAMES.iter().enumerate() {
        for (k, kname) in wprof::KNAMES.iter().enumerate().take(wprof::KCLS) {
            let (p, r) = (ka_tot[PRIM][o][k], ka_tot[REPL][o][k]);
            if p.0 + r.0 == 0 {
                continue;
            }
            let each = |x: (u64, u64, f64)| if x.0 == 0 { 0.0 } else { x.2 / x.0 as f64 };
            println!(
                "| {name} {} | {:.2} | {:.0} | {:.0} | {:.2} | {:.0} | {:.0} |",
                kname,
                p.0 as f64 / d,
                p.1 as f64 / d,
                each(p),
                r.0 as f64 / d / 2.0,
                r.1 as f64 / d / 2.0,
                each(r)
            );
        }
    }
    if env("NV_W4K_SITES", 0) != 0 {
        print_sites(done);
    }
}

/// NV_W4K_SITES=1 output: `SITE <count> <addr>...` (absolute) and the load base of the test binary, for
/// `addr2line -f -C -i -e <binary> <addr - base>`.
fn print_sites(done: u64) {
    #[cfg(target_os = "macos")]
    {
        // macOS: absolute addresses + load address of the image: `atos -o <binary> -l <LOAD> <addr>...`
        unsafe extern "C" {
            fn _dyld_get_image_header(i: u32) -> *const u8;
        }
        // SAFETY: image 0 is the main executable.
        let load = unsafe { _dyld_get_image_header(0) } as usize;
        println!("LOAD {load:#x} ops {done}");
        println!("STAGES {}", NAMES.join("|"));
        for (n, k) in sites::report(400) {
            let a: Vec<String> = k[1..].iter().map(|x| format!("{x:#x}")).collect();
            println!(
                "SITE {:.2} {} {}",
                n as f64 / done as f64,
                k[0],
                a.join(" ")
            );
        }
        return;
    }
    #[cfg_attr(target_os = "macos", expect(unreachable_code))]
    let base = std::fs::read_to_string("/proc/self/maps")
        .ok()
        .and_then(|m| {
            let exe = std::env::current_exe().ok()?;
            let exe = exe.to_string_lossy().to_string();
            m.lines()
                .find(|l| l.contains(&exe) && l.split_whitespace().nth(2) == Some("00000000"))
                .map(str::to_string)
        })
        .and_then(|l| usize::from_str_radix(l.split('-').next()?, 16).ok())
        .unwrap_or(0);
    println!("BASE {base:#x} ops {done}");
    println!("STAGES {}", NAMES.join("|"));
    for (n, k) in sites::report(400) {
        let a: Vec<String> = k[1..]
            .iter()
            .map(|x| format!("{:#x}", x.wrapping_sub(base)))
            .collect();
        println!(
            "SITE {:.2} {} {}",
            n as f64 / done as f64,
            k[0],
            a.join(" ")
        );
    }
}

/// Data prefetch counters (submitted, served, expired), process wide.
fn pf_counts() -> [u64; 3] {
    use std::sync::atomic::Ordering::Relaxed;
    [
        store::dbg::PF_SUBMIT.load(Relaxed),
        store::dbg::PF_SERVED.load(Relaxed),
        store::dbg::PF_EXPIRED.load(Relaxed),
    ]
}

/// EC k2m1 client reads end to end (3 OSDs, real framing): whole objects, partial and unaligned ranges, reads past the
/// end; sub-read replies as struct v3 (tentacle+ map) and v1 (older map), so both reply shapes feed the assembly.
/// Debug builds also check every fused reply crc hint (`CrcHint::new`).
#[test]
fn ec_client_read_roundtrip() {
    for rel in [release::UMBRELLA, release::SQUID] {
        let mut c = Cl::new(2, true, 4, 1);
        c.release = rel;
        c.up();
        let map = c.n[0].osds[0].osdmap().unwrap().clone();
        assert_eq!(map.require_osd_release, rel);
        let mut names = Vec::new();
        let mut i = 0u64;
        while names.len() < 4 {
            let name = format!("ecrd.{i}");
            i += 1;
            let raw = map
                .object_to_raw_pg(4, name.as_bytes(), b"", b"", -1)
                .unwrap();
            let pg = PgT::new(4, pgwire::pgmath::object_pg(raw.seed, 4));
            if map.pg_to_up_acting(pg).acting_primary == 0 {
                names.push(name);
            }
        }
        let sizes = [20_000usize, 65_536, 1 << 20, (4 << 20) - 4096];
        let datas: Vec<Vec<u8>> = sizes
            .iter()
            .enumerate()
            .map(|(k, n)| (0..*n).map(|j| (j * 7 + k * 13 + j / 4096) as u8).collect())
            .collect();
        let link = c.n[0].client(0);
        let mut tid = 1u64;
        let mut one = |c: &mut Cl, op: OsdOp, obj: &str| -> MOSDOpReply {
            let m = c.n[0].op(4, obj, vec![op]);
            let (ty, ver, _c, segs) = ClientMsg::Op(m).encode(u64::MAX).unwrap();
            let t = c.n[0].t;
            c.call(0, 0, |n| {
                n[0].osds[0].set_now(t);
                n[0].osds[0].on_unknown_message(link, tid, ty, ver, &segs)
            });
            tid += 1;
            for _ in 0..200 {
                c.settle();
                let mut r = c.n[0].replies(0, link);
                if let Some((_, rep)) = r.pop() {
                    return rep;
                }
                c.tick(Duration::from_millis(5));
            }
            panic!("no reply for {obj}");
        };
        for (obj, d) in names.iter().zip(&datas) {
            let r = one(&mut c, OsdOp::writefull(d.clone()), obj);
            assert_eq!(r.result, 0);
        }
        for (obj, d) in names.iter().zip(&datas) {
            let n = d.len() as u64;
            for (off, len) in [
                (0, n),
                (0, 0),
                (1, 8191),
                (4095, 12_289),
                (n / 3, n / 2),
                (n - 5, 100),
                (n + 10, 10),
            ] {
                let r = one(&mut c, OsdOp::read(off, len), obj);
                assert_eq!(r.result, 0, "{obj} {off}+{len} release {rel}");
                let end = if len == 0 { n } else { (off + len).min(n) };
                let want = if off >= n {
                    &[][..]
                } else {
                    &d[off as usize..end as usize]
                };
                assert!(
                    r.ops[0].outdata[..] == *want,
                    "{obj} {off}+{len} release {rel}: wrong bytes"
                );
            }
        }
    }
}

#[test]
fn write_ordered_direct_reads_are_rejected_before_role_dispatch() {
    for ec in [false, true] {
        let mut c = Cl::new(2, true, 4, if ec { 2 } else { 0 });
        c.up();
        for enabled in [false, true] {
            for node in &mut c.n {
                for o in &mut node.osds {
                    o.conf
                        .set(
                            crate::config::Level::Override,
                            "ec_optimized_direct",
                            if enabled { "true" } else { "false" },
                        )
                        .unwrap();
                }
            }
            for flag in [
                opwire::flag::EC_DIRECT_READ,
                opwire::flag::BALANCE_READS,
                opwire::flag::LOCALIZE_READS,
            ] {
                for node in 0..c.n.len() {
                    let core = 0;
                    let link = c.n[node].client(core);
                    let mut op = c.n[node].op(4, "ordered-direct", vec![OsdOp::read(0, 1)]);
                    op.flags |= flag | opwire::flag::RWORDERED;
                    let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
                    c.call(node as i32, core, |nodes| {
                        nodes[node].osds[core].on_unknown_message(link, 901, ty, ver, &segs)
                    });
                    c.settle();
                    let replies = c.n[node].replies(core, link);
                    assert_eq!(
                        replies.len(),
                        1,
                        "ec={ec} enabled={enabled} node={node} flag={flag}"
                    );
                    assert_eq!(replies[0].1.result, -opwire::errno::EINVAL);
                }
            }
        }
    }
}

/// EC direct read (`EC_DIRECT_READ`, `ec_optimized_direct`): the reply goes through the client-reply sender (data by
/// reference, one piece per op, no flattening) and its wire bytes decode to what the client expects: every READ /
/// SPARSE_READ its bytes in op order, GET_INTERNAL_VERSIONS the shard versions, on the PG core and across cores.
#[test]
fn ec_direct_read_reply_carries_every_op_on_the_wire() {
    let mut c = Cl::new(2, true, 4, 2);
    c.up();
    for node in &mut c.n {
        for o in &mut node.osds {
            o.conf
                .set(
                    crate::config::Level::Override,
                    "ec_optimized_direct",
                    "true",
                )
                .unwrap();
        }
    }
    let oid = (0..100)
        .map(|i| format!("dr-{i}"))
        .find(|name| {
            // osd.0 holds data shard 0 (bytes [0, 4096) of every stripe: k=2, stripe 8192)
            let op = c.n[0].op(4, name, vec![]);
            c.n[0].osds[0]
                .osdmap()
                .unwrap()
                .pg_to_up_acting(op.pgid.pgid)
                .acting
                .first()
                == Some(&0)
        })
        .unwrap();
    let data: Vec<u8> = (0..8192u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let owner = c.n[0].owner(4, c.n[0].op(4, &oid, vec![]).pgid.pgid.seed);
    let mut tid = 900;
    for core in [owner, 1 - owner] {
        let link = c.n[0].client(core);
        let mut send = |c: &mut Cl, op: opwire::MOSDOp| -> MOSDOpReply {
            let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
            c.frame(ty, ver, &segs, tid);
            let now = c.n[0].t;
            c.call(0, core, |nodes| {
                nodes[0].osds[core].set_now(now);
                nodes[0].osds[core].on_unknown_message(link, tid, ty, ver, &segs);
            });
            tid += 1;
            c.settle();
            c.n[0].replies(core, link).pop().expect("reply").1
        };
        let w = c.n[0].op(4, &oid, vec![OsdOp::writefull(data.clone())]);
        assert_eq!(send(&mut c, w).result, 0);
        let mut op = c.n[0].op(
            4,
            &oid,
            vec![
                OsdOp::read(0, 100),
                OsdOp::new(opwire::op::GET_INTERNAL_VERSIONS),
                OsdOp::read(200, 300),
                OsdOp::sparse_read(10, 20),
            ],
        );
        op.flags |= opwire::flag::EC_DIRECT_READ;
        // a shard serves only warm pages: the first attempt may answer EAGAIN (the client reads via the primary)
        // and loads them; the next one is served
        let r = send(&mut c, op.clone());
        assert!(
            r.result == 0 || r.result == -opwire::errno::EAGAIN,
            "core {core}"
        );
        c.tick(Duration::from_millis(10));
        let r = send(&mut c, op);
        assert_eq!(r.result, 0, "core {core}");
        assert_eq!(r.ops.len(), 4);
        assert_eq!(r.ops[0].outdata[..], data[..100], "core {core}");
        assert!(!r.ops[1].outdata.is_empty(), "versions echoed");
        assert_eq!(r.ops[2].outdata[..], data[200..500], "core {core}");
        let sp: opwire::payload::SparseReadOut = denc::from_slice(&r.ops[3].outdata).unwrap();
        assert_eq!(sp.extents.into_iter().collect::<Vec<_>>(), vec![(10, 20)]);
        assert_eq!(sp.data[..], data[10..30]);
    }
}

/// Fencing (client-ops 5.2 #10) on the EC direct-read fast path: `pg_direct_read` answers object data without the
/// engine's precheck, so it must apply the blocklist itself. A client blocklisted after its session was accepted keeps
/// reading through EC_DIRECT_READ without the check (an RBD client the operator fenced keeps reading its images on EC
/// pools while `ec_optimized_direct` is on).
#[test]
fn ec_direct_read_is_refused_for_a_blocklisted_client() {
    use denc::types::UTime;
    const EBLOCKLISTED: i32 = -108;
    let mut c = Cl::new(2, true, 4, 2);
    c.up();
    for node in &mut c.n {
        for o in &mut node.osds {
            o.conf
                .set(
                    crate::config::Level::Override,
                    "ec_optimized_direct",
                    "true",
                )
                .unwrap();
        }
    }
    let oid = (0..100)
        .map(|i| format!("bl-{i}"))
        .find(|name| {
            // osd.0 holds data shard 0 (bytes [0, 4096) of every stripe: k=2, stripe 8192)
            let op = c.n[0].op(4, name, vec![]);
            c.n[0].osds[0]
                .osdmap()
                .unwrap()
                .pg_to_up_acting(op.pgid.pgid)
                .acting
                .first()
                == Some(&0)
        })
        .unwrap();
    let data: Vec<u8> = (0..8192u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let owner = c.n[0].owner(4, c.n[0].op(4, &oid, vec![]).pgid.pgid.seed);
    let mut tid = 900;
    // one message on the PG's core; the client link is created once per `core` (`10.9.0.1 + core`)
    let link = c.n[0].client(owner);
    let mut send = |c: &mut Cl, op: opwire::MOSDOp| -> MOSDOpReply {
        let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        c.frame(ty, ver, &segs, tid);
        let now = c.n[0].t;
        c.call(0, owner, |nodes| {
            nodes[0].osds[owner].set_now(now);
            nodes[0].osds[owner].on_unknown_message(link, tid, ty, ver, &segs);
        });
        tid += 1;
        c.settle();
        c.n[0].replies(owner, link).pop().expect("reply").1
    };
    let w = c.n[0].op(4, &oid, vec![OsdOp::writefull(data.clone())]);
    assert_eq!(send(&mut c, w).result, 0);
    let mut op = c.n[0].op(4, &oid, vec![OsdOp::read(0, 100)]);
    op.flags |= opwire::flag::EC_DIRECT_READ;
    // warm the shard: the first attempt may answer EAGAIN, the next one is served
    let _ = send(&mut c, op.clone());
    c.tick(Duration::from_millis(10));
    assert_eq!(send(&mut c, op.clone()).result, 0, "fast path serves it");
    // epoch 11: the client's ip-only address is blocklisted; the session stays (fencing is per op)
    let mut m = c.map(11);
    m.blocklist.insert(
        EntityAddr::v4(EntityAddr::TYPE_ANY, 0, [10, 9, 0, 1 + owner as u8], 0),
        UTime::default(),
    );
    for n in &mut c.n {
        n.deliver(m.clone());
    }
    c.settle();
    assert_eq!(
        send(&mut c, op).result,
        EBLOCKLISTED,
        "EC direct read of a blocklisted client"
    );
}

#[test]
fn capability_network_uses_socket_peer_across_cores() {
    use opexec::caps::Caps;
    for (ec, secure) in [0, 2]
        .into_iter()
        .flat_map(|ec| [false, true].map(|secure| (ec, secure)))
    {
        let mut c = Cl::new(2, true, 4, ec);
        if secure {
            let secret = msgr2::ConnSecret::new(&[7; 64]).unwrap();
            c.enc.set_secure(&secret, msgr2::Role::Client).unwrap();
            c.dec.set_secure(&secret, msgr2::Role::Server).unwrap();
        }
        c.up();
        for node in &mut c.n {
            for o in &mut node.osds {
                o.conf
                    .set(
                        crate::config::Level::Override,
                        "ec_optimized_direct",
                        "true",
                    )
                    .unwrap();
            }
        }
        let oid = (0..100)
            .map(|i| format!("cidr-{i}"))
            .find(|name| {
                let op = c.n[0].op(4, name, vec![]);
                c.n[0].osds[0]
                    .osdmap()
                    .unwrap()
                    .pg_to_up_acting(op.pgid.pgid)
                    .acting_primary
                    == 0
            })
            .unwrap();
        let core = 1 - c.n[0].owner(4, c.n[0].op(4, &oid, vec![]).pgid.pgid.seed);
        let seed = c.n[0].client(core);
        let op = c.n[0].op(4, &oid, vec![OsdOp::writefull(vec![9; 8192])]);
        let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let now = c.n[0].t;
        c.call(0, core, |nodes| {
            nodes[0].osds[core].set_now(now);
            nodes[0].osds[core].on_unknown_message(seed, 809, ty, ver, &segs);
        });
        c.settle();
        assert_eq!(
            c.n[0]
                .replies(core, seed)
                .pop()
                .expect("seed write")
                .1
                .result,
            0
        );
        for allowed in [false, true] {
            let link = c.n[0].client(core);
            let o = &mut c.n[0].osds[core];
            let l = o.links.get_mut(&link).unwrap();
            l.peer.as_mut().unwrap().addrs = addr([10, 42, 0, 8], 4500, 1);
            l.caps = Some(Arc::new(
                Caps::parse(if allowed {
                    "allow r network 10.9.0.0/24"
                } else {
                    "allow r network 10.42.0.0/24"
                })
                .unwrap(),
            ));
            o.link_ready_info(link, crate::osd::Purpose::Accepted);
            let info = o.links[&link].info.as_ref().unwrap();
            assert_ne!(info.addr, info.peer_addr);
            assert_eq!(info.peer_addr, o.links[&link].conn.target());
            for direct in [false, true] {
                if direct && ec == 0 {
                    continue;
                }
                let mut op = c.n[0].op(4, &oid, vec![OsdOp::read(0, 1)]);
                if direct {
                    op.flags |= opwire::flag::EC_DIRECT_READ;
                }
                let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
                c.frame(ty, ver, &segs, 810);
                let now = c.n[0].t;
                c.call(0, core, |nodes| {
                    nodes[0].osds[core].set_now(now);
                    nodes[0].osds[core].on_unknown_message(link, 810, ty, ver, &segs);
                });
                c.settle();
                let reply = c.n[0]
                    .replies(core, link)
                    .pop()
                    .expect("capability reply")
                    .1;
                if allowed {
                    assert_eq!(reply.result, 0, "ec={ec} secure={secure} direct={direct}");
                } else {
                    assert_eq!(
                        reply.result,
                        -opwire::errno::EPERM,
                        "ec={ec} direct={direct}"
                    );
                }
            }
        }
    }
}

/// Pool EIO fences both the normal engine and the EC direct-read fast path.
#[test]
fn eio_pool_fences_normal_and_direct_object_requests() {
    for ec in [0, 2] {
        let mut c = Cl::new(2, true, 4, ec);
        c.up();
        for node in &mut c.n {
            for o in &mut node.osds {
                o.conf
                    .set(
                        crate::config::Level::Override,
                        "ec_optimized_direct",
                        "true",
                    )
                    .unwrap();
            }
        }
        let oid = (0..100)
            .map(|i| format!("eio-{i}"))
            .find(|name| {
                let op = c.n[0].op(4, name, vec![]);
                let m = c.n[0].osds[0]
                    .osdmap()
                    .unwrap()
                    .pg_to_up_acting(op.pgid.pgid);
                m.acting_primary == 0 && (ec == 0 || m.acting.first() == Some(&0))
            })
            .unwrap();
        let core = c.n[0].owner(4, c.n[0].op(4, &oid, vec![]).pgid.pgid.seed);
        let link = c.n[0].client(core);
        let mut tid = 2000;
        let mut send = |c: &mut Cl, op: opwire::MOSDOp| {
            let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
            c.call(0, core, |nodes| {
                nodes[0].osds[core].on_unknown_message(link, tid, ty, ver, &segs)
            });
            tid += 1;
            c.settle();
            c.n[0].replies(core, link)
        };
        let op = c.n[0].op(4, &oid, vec![OsdOp::writefull(vec![7; 8192])]);
        assert_eq!(send(&mut c, op)[0].1.result, 0);
        let mut m = c.map(11);
        m.pools.get_mut(&4).unwrap().flags |= osdmap::pool::flags::EIO;
        for n in &mut c.n {
            n.deliver(m.clone());
        }
        c.settle();
        for direct in [false, true] {
            if direct && ec == 0 {
                continue;
            }
            for supports in [false, true] {
                let mut op = c.n[0].op(4, &oid, vec![OsdOp::read(0, 100)]);
                if direct {
                    op.flags |= opwire::flag::EC_DIRECT_READ;
                }
                if supports {
                    op.flags |= opwire::flag::SUPPORTSPOOLEIO;
                }
                let r = send(&mut c, op);
                if supports {
                    assert!(r.is_empty(), "ec={ec} direct={direct}");
                } else {
                    assert_eq!(
                        r[0].1.result,
                        -opwire::errno::EIO,
                        "ec={ec} direct={direct}"
                    );
                }
            }
        }
    }
}
