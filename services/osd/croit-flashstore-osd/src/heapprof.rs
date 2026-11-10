// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! LAB ONLY (feature `heapprof`, adr 0024; build profiles `heapprof` / `heapsys` of lab/build-host-build.sh): heap profile
//! of the daemon for the RSS growth hunt (doc/perf/osd-rss-growth-20261029.md).
//!
//! [`Prof`] wraps the global allocator (mimalloc with feature `mimalloc`, else the system allocator). It counts the live
//! bytes of every allocation and records the allocation site (return addresses of the frame-pointer chain; build with
//! `-C force-frame-pointers=yes`) of every live block of at least [`BIG`] bytes and of one in [`RATE`] smaller blocks.
//! The small blocks are picked by address, so a free knows without a lookup whether its block is recorded; a recorded
//! small block counts [`RATE`] times.
//!
//! `NV_HEAPPROF_OUT=DIR` starts a thread that appends a snapshot every `NV_HEAPPROF_SECS` (10) s to
//! `DIR/heapprof.<pid>.jsonl`: one `heap` record (live bytes and blocks, VmRSS / RssAnon / HugetlbPages, load base of
//! the executable) and one `site` record for each of the `NV_HEAPPROF_TOP` (60) sites with the most live bytes (frames
//! relative to the load base). `lab/heapprof-report.sh` symbolizes the sites and ranks their growth between snapshots.
//! The tables (64 MiB block table, 15 MiB site table, mapped at start, touched as used) are RSS outside `live`.
use std::alloc::{GlobalAlloc, Layout};
use std::cell::{Cell, UnsafeCell};
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicU64, AtomicUsize};
use std::time::{Duration, Instant};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("heapprof walks frame pointers of x86_64 and aarch64 only");

#[cfg(feature = "mimalloc")]
const INNER: mimalloc::MiMalloc = mimalloc::MiMalloc;
#[cfg(not(feature = "mimalloc"))]
const INNER: std::alloc::System = std::alloc::System;

/// Blocks of at least this size are all recorded.
pub const BIG: usize = 16 << 10;
/// One in `RATE` smaller blocks is recorded (by address).
pub const RATE: i64 = 64;
/// Return addresses kept per site.
const DEPTH: usize = 24;
/// Block table: `SHARDS` spin-locked open-addressing shards of `SLOTS` entries (key = block address, 0 = empty).
const SHARDS: usize = 1024;
const SLOTS: usize = 4096;
/// Site table entries; entry 0 collects the blocks of sites that found no free entry.
const NSITES: usize = 1 << 16;
const SIZE_BITS: u32 = 40;

/// The profiling global allocator (`main.rs`).
#[derive(Debug)]
pub struct Prof;

// SAFETY: every call goes to the inner allocator with the caller's layout; the bookkeeping never allocates.
unsafe impl GlobalAlloc for Prof {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: forwarded contract.
        let p = unsafe { INNER.alloc(l) };
        if !p.is_null() {
            on_alloc(p as usize, l.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        // SAFETY: forwarded contract.
        let p = unsafe { INNER.alloc_zeroed(l) };
        if !p.is_null() {
            on_alloc(p as usize, l.size());
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // before the free: once freed, another thread may get the address and record it
        on_free(p as usize, l.size());
        // SAFETY: forwarded contract.
        unsafe { INNER.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        on_free(p as usize, l.size());
        // SAFETY: forwarded contract.
        let q = unsafe { INNER.realloc(p, l, n) };
        if q.is_null() {
            on_alloc(p as usize, l.size()); // the old block stays
        } else {
            on_alloc(q as usize, n);
        }
        q
    }
}

/// Live bytes / blocks of all allocations, striped per thread (no shared cache line on the hot path).
#[repr(align(128))]
struct Stripe {
    bytes: AtomicI64,
    blocks: AtomicI64,
}
const STRIPES: usize = 64;
static LIVE: [Stripe; STRIPES] = [const {
    Stripe {
        bytes: AtomicI64::new(0),
        blocks: AtomicI64::new(0),
    }
}; STRIPES];
static NEXT_STRIPE: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static STRIPE: Cell<usize> = const { Cell::new(usize::MAX) };
    /// This thread's stack `[lo, hi)`; `(0, 0)` = not queried yet, `(MAX, MAX)` = unknown (no walk).
    static STACK: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

fn stripe() -> &'static Stripe {
    let i = STRIPE.with(|s| {
        let mut i = s.get();
        if i == usize::MAX {
            i = NEXT_STRIPE.fetch_add(1, Relaxed) % STRIPES;
            s.set(i);
        }
        i
    });
    &LIVE[i]
}

#[repr(C)]
struct Shard {
    lock: AtomicBool,
    len: UnsafeCell<usize>,
    keys: UnsafeCell<[usize; SLOTS]>,
    /// site << SIZE_BITS | size
    vals: UnsafeCell<[u64; SLOTS]>,
}

#[repr(C)]
struct Site {
    hash: AtomicU64,
    depth: AtomicUsize,
    frames: UnsafeCell<[usize; DEPTH]>,
    live: AtomicI64,
    blocks: AtomicI64,
    /// Bytes ever allocated here (weighted).
    total: AtomicU64,
}

static TABLE: AtomicPtr<Shard> = AtomicPtr::new(std::ptr::null_mut());
static SITES: AtomicPtr<Site> = AtomicPtr::new(std::ptr::null_mut());
static SITE_LOCK: AtomicBool = AtomicBool::new(false);
/// Recorded-size blocks a full shard refused (not in any site).
static DROPPED: AtomicU64 = AtomicU64::new(0);

fn lock(l: &AtomicBool) {
    while l
        .compare_exchange_weak(false, true, Acquire, Relaxed)
        .is_err()
    {
        std::hint::spin_loop();
    }
}

fn unlock(l: &AtomicBool) {
    l.store(false, Release);
}

/// splitmix64 finalizer of the block address: shard (bits 54..64), slot (40..52), small-block pick (26..32).
fn mix(p: usize) -> u64 {
    let mut z = (p as u64).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// How often a block of `size` at hash `h` counts when recorded; 0 = not recorded.
fn weight(h: u64, size: usize) -> i64 {
    if size >= BIG {
        1
    } else if (h >> 26) & (RATE as u64 - 1) == 0 {
        RATE
    } else {
        0
    }
}

fn shard(t: *mut Shard, h: u64) -> &'static Shard {
    // SAFETY: `t` is the mapped table of SHARDS shards (all-zero = valid empty shard); the index is < SHARDS.
    unsafe { &*t.add((h >> 54) as usize % SHARDS) }
}

fn slot(h: u64) -> usize {
    (h >> 40) as usize & (SLOTS - 1)
}

/// Record block `p` (hash `h`); false = shard full (7/8).
fn insert(t: *mut Shard, h: u64, p: usize, val: u64) -> bool {
    let s = shard(t, h);
    lock(&s.lock);
    // SAFETY: the shard lock gives exclusive access to len / keys / vals.
    let (len, keys, vals) = unsafe { (&mut *s.len.get(), &mut *s.keys.get(), &mut *s.vals.get()) };
    let ok = *len < SLOTS - SLOTS / 8;
    if ok {
        let mut i = slot(h);
        while keys[i] != 0 {
            i = (i + 1) & (SLOTS - 1);
        }
        keys[i] = p;
        vals[i] = val;
        *len += 1;
    }
    unlock(&s.lock);
    ok
}

/// Forget block `p` (hash `h`): its value, `None` = not recorded. Linear probing with backward-shift deletion.
fn remove(t: *mut Shard, h: u64, p: usize) -> Option<u64> {
    let s = shard(t, h);
    lock(&s.lock);
    // SAFETY: the shard lock gives exclusive access to len / keys / vals.
    let (len, keys, vals) = unsafe { (&mut *s.len.get(), &mut *s.keys.get(), &mut *s.vals.get()) };
    let mut i = slot(h);
    let found = loop {
        match keys[i] {
            0 => break None,
            k if k == p => break Some(vals[i]),
            _ => i = (i + 1) & (SLOTS - 1),
        }
    };
    if found.is_some() {
        let mut j = i;
        loop {
            j = (j + 1) & (SLOTS - 1);
            if keys[j] == 0 {
                break;
            }
            // the entry at j may fill the hole at i unless its home lies cyclically in (i, j]
            let home = slot(mix(keys[j]));
            if (j > i && (home <= i || home > j)) || (j < i && home <= i && home > j) {
                keys[i] = keys[j];
                vals[i] = vals[j];
                i = j;
            }
        }
        keys[i] = 0;
        *len -= 1;
    }
    unlock(&s.lock);
    found
}

fn site(i: usize) -> Option<&'static Site> {
    let t = SITES.load(Acquire);
    if t.is_null() {
        return None;
    }
    // SAFETY: `t` is the mapped site table of NSITES entries (all-zero = valid empty site); the index is < NSITES.
    Some(unsafe { &*t.add(i % NSITES) })
}

/// Site index of the stack `f` (entry 0 when the table has no room).
fn intern(f: &[usize]) -> usize {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &a in f {
        h = (h ^ a as u64).wrapping_mul(0x0000_0100_0000_01B3);
    }
    let h = mix(h as usize) | 1;
    let mut i = (h >> 40) as usize & (NSITES - 1);
    for _ in 0..NSITES {
        if i != 0 {
            let Some(s) = site(i) else { return 0 };
            match s.hash.load(Acquire) {
                x if x == h => return i,
                0 => {
                    lock(&SITE_LOCK);
                    let x = s.hash.load(Relaxed);
                    if x == 0 {
                        // SAFETY: an unpublished entry (hash 0) is written only under SITE_LOCK; readers wait for the hash.
                        unsafe { (&mut *s.frames.get())[..f.len()].copy_from_slice(f) };
                        s.depth.store(f.len(), Relaxed);
                        s.hash.store(h, Release);
                    }
                    unlock(&SITE_LOCK);
                    if x == 0 || x == h {
                        return i;
                    }
                }
                _ => {}
            }
        }
        i = (i + 1) & (NSITES - 1);
    }
    0
}

#[inline(always)]
fn frame_pointer() -> usize {
    let fp: usize;
    // SAFETY: reads a register.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) fp, options(nomem, nostack, preserves_flags))
    };
    // SAFETY: reads a register.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags))
    };
    fp
}

/// An address in the calling function (the frame chain starts at its caller).
#[inline(always)]
fn pc() -> usize {
    let pc: usize;
    // SAFETY: computes an address, touches nothing.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("lea {}, [rip]", out(reg) pc, options(nomem, nostack, preserves_flags))
    };
    // SAFETY: computes an address, touches nothing.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("adr {}, .", out(reg) pc, options(nomem, nostack, preserves_flags))
    };
    pc
}

fn stack_bounds() -> (usize, usize) {
    // SAFETY: attribute queries of the calling thread (glibc allocates through malloc, never through this allocator).
    unsafe {
        let mut a: libc::pthread_attr_t = std::mem::zeroed();
        if libc::pthread_getattr_np(libc::pthread_self(), &mut a) != 0 {
            return (usize::MAX, usize::MAX);
        }
        let (mut addr, mut size) = (std::ptr::null_mut(), 0usize);
        let r = libc::pthread_attr_getstack(&a, &mut addr, &mut size);
        libc::pthread_attr_destroy(&mut a);
        if r != 0 {
            return (usize::MAX, usize::MAX);
        }
        (addr as usize, addr as usize + size)
    }
}

/// An address in the function the allocator was inlined into, then the return addresses of the frame-pointer chain,
/// innermost first; stops at the first frame record outside this thread's stack (a function built without frame pointers
/// breaks the chain there).
#[inline(always)]
fn backtrace(out: &mut [usize; DEPTH]) -> usize {
    let (lo, hi) = STACK.with(|c| {
        let mut b = c.get();
        if b.1 == 0 {
            b = stack_bounds();
            c.set(b);
        }
        b
    });
    let mut fp = frame_pointer();
    out[0] = pc();
    let mut n = 1;
    while n < DEPTH && fp >= lo && fp.saturating_add(16) <= hi && fp.is_multiple_of(8) {
        // SAFETY: the frame record lies inside this thread's mapped stack (checked above).
        let (next, ret) = unsafe { (*(fp as *const usize), *((fp + 8) as *const usize)) };
        if ret == 0 {
            break;
        }
        out[n] = ret;
        n += 1;
        if next <= fp {
            break;
        }
        fp = next;
    }
    n
}

#[inline(always)]
fn on_alloc(p: usize, size: usize) {
    let s = stripe();
    s.bytes.fetch_add(size as i64, Relaxed);
    s.blocks.fetch_add(1, Relaxed);
    let h = mix(p);
    let w = weight(h, size);
    let t = TABLE.load(Acquire);
    if w == 0 || t.is_null() {
        return;
    }
    let mut f = [0usize; DEPTH];
    let n = backtrace(&mut f);
    let i = intern(&f[..n]);
    let size = size.min((1 << SIZE_BITS) - 1);
    if !insert(t, h, p, (i as u64) << SIZE_BITS | size as u64) {
        DROPPED.fetch_add(1, Relaxed);
        return;
    }
    if let Some(s) = site(i) {
        s.live.fetch_add(size as i64 * w, Relaxed);
        s.blocks.fetch_add(w, Relaxed);
        s.total.fetch_add(size as u64 * w as u64, Relaxed);
    }
}

#[inline(always)]
fn on_free(p: usize, size: usize) {
    let s = stripe();
    s.bytes.fetch_sub(size as i64, Relaxed);
    s.blocks.fetch_sub(1, Relaxed);
    let h = mix(p);
    let w = weight(h, size);
    let t = TABLE.load(Acquire);
    if w == 0 || t.is_null() {
        return;
    }
    if let Some(v) = remove(t, h, p)
        && let Some(s) = site((v >> SIZE_BITS) as usize)
    {
        s.live
            .fetch_sub((v & ((1 << SIZE_BITS) - 1)) as i64 * w, Relaxed);
        s.blocks.fetch_sub(w, Relaxed);
    }
}

fn map(len: usize) -> *mut u8 {
    // SAFETY: a fresh private anonymous mapping (zero-filled = empty tables).
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        std::ptr::null_mut()
    } else {
        p.cast()
    }
}

/// Map the tables (once): blocks allocated from here on are recorded. False = not mapped (only the counters run).
fn init() -> bool {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let s = map(NSITES * size_of::<Site>());
        let t = map(SHARDS * size_of::<Shard>());
        if !s.is_null() && !t.is_null() {
            SITES.store(s.cast(), Release);
            TABLE.store(t.cast(), Release);
        }
    });
    !TABLE.load(Acquire).is_null()
}

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

/// Start of the profile (`main`, before the daemon's threads): tables, and with `NV_HEAPPROF_OUT` the snapshot thread.
pub fn start() {
    if !init() {
        eprintln!(
            "croit-flashstore-osd: heapprof: tables not mapped: live counters only, no sites"
        );
    }
    let Some(dir) = std::env::var_os("NV_HEAPPROF_OUT") else {
        eprintln!("croit-flashstore-osd: heapprof: NV_HEAPPROF_OUT unset: no snapshots");
        return;
    };
    let secs = env_u64("NV_HEAPPROF_SECS", 10).max(1);
    let top = env_u64("NV_HEAPPROF_TOP", 60) as usize;
    let path = std::path::Path::new(&dir).join(format!("heapprof.{}.jsonl", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!(
            "croit-flashstore-osd: heapprof: {}: {e}: no snapshots",
            path.display()
        );
        return;
    }
    eprintln!(
        "croit-flashstore-osd: heapprof: snapshot every {secs} s -> {} (blocks >= {BIG} B all, smaller 1 in {RATE})",
        path.display()
    );
    let base = load_base();
    let t0 = Instant::now();
    let spawned = std::thread::Builder::new()
        .name("heapprof".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(secs));
                if let Err(e) = append(&path, &snapshot(t0.elapsed().as_secs(), base, top)) {
                    eprintln!(
                        "croit-flashstore-osd: heapprof: {}: {e}: snapshots stop",
                        path.display()
                    );
                    return;
                }
            }
        });
    if let Err(e) = spawned {
        eprintln!("croit-flashstore-osd: heapprof: snapshot thread: {e}");
    }
}

fn append(path: &std::path::Path, s: &str) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(s.as_bytes())
}

/// Load address of the executable (its mapping at file offset 0): frame address - base = address in the ELF file.
fn load_base() -> usize {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let me = start as fn() as usize;
    let range = |r: &str| {
        let (a, b) = r.split_once('-')?;
        Some((
            usize::from_str_radix(a, 16).ok()?,
            usize::from_str_radix(b, 16).ok()?,
        ))
    };
    let exe = maps.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (a, b) = range(f.first()?)?;
        (a..b)
            .contains(&me)
            .then(|| f.get(5).map(|p| p.to_string()))?
    });
    maps.lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.get(2) == Some(&"00000000") && f.get(5).map(|p| p.to_string()) == exe)
                .then(|| range(f[0]).map(|r| r.0))?
        })
        .unwrap_or(0)
}

/// `VmRSS`, `RssAnon`, `HugetlbPages` of this process in KiB.
fn status_kb() -> [u64; 3] {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let v = |k: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(k))
            .and_then(|r| r.split_whitespace().next()?.parse().ok())
            .unwrap_or(0)
    };
    [v("VmRSS:"), v("RssAnon:"), v("HugetlbPages:")]
}

/// One snapshot: the `heap` record and the `site` records of the `top` sites by live bytes (JSON lines).
fn snapshot(t: u64, base: usize, top: usize) -> String {
    let (live, blocks) = LIVE.iter().fold((0i64, 0i64), |(a, b), s| {
        (a + s.bytes.load(Relaxed), b + s.blocks.load(Relaxed))
    });
    let [rss, anon, huge] = status_kb();
    let mut rows: Vec<(i64, usize)> = Vec::new();
    let (mut used, mut tracked) = (0usize, 0i64);
    for i in 0..NSITES {
        let Some(s) = site(i) else { break };
        if i != 0 && s.hash.load(Acquire) == 0 {
            continue;
        }
        used += 1;
        let l = s.live.load(Relaxed);
        tracked += l;
        if l > 0 {
            rows.push((l, i));
        }
    }
    rows.sort_unstable_by_key(|r| std::cmp::Reverse(*r));
    rows.truncate(top);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{{\"rec\":\"heap\",\"t\":{t},\"pid\":{},\"live\":{live},\"blocks\":{blocks},\"tracked\":{tracked},\"sites\":{used},\"dropped\":{},\"rss_kb\":{rss},\"anon_kb\":{anon},\"huge_kb\":{huge},\"base\":\"{base:#x}\",\"big\":{BIG},\"rate\":{RATE}}}",
        std::process::id(),
        DROPPED.load(Relaxed)
    );
    for (l, i) in rows {
        let Some(s) = site(i) else { break };
        let d = s.depth.load(Relaxed).min(DEPTH);
        // SAFETY: published frames (hash seen above with Acquire) never change.
        let f = unsafe { &(&*s.frames.get())[..d] };
        let frames: Vec<String> = f
            .iter()
            .map(|a| format!("\"{:#x}\"", a.wrapping_sub(base)))
            .collect();
        let _ = writeln!(
            o,
            "{{\"rec\":\"site\",\"t\":{t},\"site\":{i},\"live\":{l},\"blocks\":{},\"total\":{},\"frames\":[{}]}}",
            s.blocks.load(Relaxed),
            s.total.load(Relaxed),
            frames.join(",")
        );
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Insert / remove with collisions in one shard: every recorded block is found until removed, removed ones are gone.
    #[test]
    fn block_table_backward_shift() {
        let t = map(SHARDS * size_of::<Shard>()).cast::<Shard>();
        assert!(!t.is_null());
        // addresses of one shard, many sharing a home slot
        let mut keys: Vec<usize> = Vec::new();
        let mut p = 0x1000usize;
        while keys.len() < 600 {
            if (mix(p) >> 54) as usize % SHARDS == 7 {
                keys.push(p);
            }
            p += 16;
        }
        for (n, &k) in keys.iter().enumerate() {
            assert!(insert(t, mix(k), k, n as u64));
        }
        for (n, &k) in keys.iter().enumerate().filter(|(n, _)| n.is_multiple_of(3)) {
            assert_eq!(remove(t, mix(k), k), Some(n as u64));
        }
        for (n, &k) in keys.iter().enumerate() {
            let want = (!n.is_multiple_of(3)).then_some(n as u64);
            assert_eq!(remove(t, mix(k), k), want, "key {n}");
        }
        assert_eq!(unsafe { *(*t.add(7)).len.get() }, 0);
    }

    /// A big block is recorded at its allocation site while it lives and leaves the site when freed.
    #[test]
    fn big_block_site_live_while_held() {
        assert!(init());
        let v: Vec<u8> = Vec::with_capacity(3 << 20);
        let p = v.as_ptr() as usize;
        let h = mix(p);
        let val = remove(TABLE.load(Acquire), h, p).expect("recorded");
        assert_eq!(val & ((1 << SIZE_BITS) - 1), 3 << 20);
        let s = site((val >> SIZE_BITS) as usize).unwrap();
        assert!(s.depth.load(Relaxed) >= 1, "no frame");
        assert!(s.live.load(Relaxed) >= 3 << 20);
        // put it back for the free
        assert!(insert(TABLE.load(Acquire), h, p, val));
        let snap = snapshot(1, load_base(), 5);
        assert!(snap.starts_with("{\"rec\":\"heap\",\"t\":1,"), "{snap}");
        assert!(
            snap.contains(&format!("\"site\":{},", val >> SIZE_BITS)),
            "{snap}"
        );
        // the records for lab/heapprof-report.sh (lab/heapprof-selftest.sh symbolizes them against this test binary)
        print!("{snap}");
        drop(v);
        assert_eq!(remove(TABLE.load(Acquire), h, p), None);
    }
}
