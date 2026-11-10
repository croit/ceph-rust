// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Independent allocation high-water and aggregate remote-permit regression (no device access).
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use store::obj::keys::omap_key;
use store::runs::{PoolShare, RunBuilder, RunPool, RunSet};

struct Measured;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn add(n: usize) {
    let live = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for Measured {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            add(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe {
            System.dealloc(p, l);
        }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, n) };
        if !q.is_null() {
            if n >= l.size() {
                add(n - l.size());
            } else {
                LIVE.fetch_sub(l.size() - n, Ordering::Relaxed);
            }
        }
        q
    }
}
#[global_allocator]
static ALLOC: Measured = Measured;

#[test]
fn helper_reservation_covers_tiny_multipart_publication_and_pool_credit_lifetime() {
    let pool = Arc::new(RunPool::default());
    let a = PoolShare::join(pool.clone(), 4096);
    let b = PoolShare::join(pool.clone(), 4096);
    let permit = a.reserve_helper(6000).unwrap();
    assert!(
        b.reserve_helper(3000).is_none(),
        "aggregate, not per-owner bound"
    );
    drop(a);
    assert_eq!(
        pool.helper_bytes(),
        6000,
        "owner drop cannot release a remotely pinned job"
    );
    drop(permit);
    assert_eq!(pool.helper_bytes(), 0);
    let permit = b.reserve_helper(4096).unwrap();
    assert!(b.reserve_helper(1).is_none());
    drop(permit);

    std::thread::scope(|scope| {
        for _ in 0..4 {
            let share = &b;
            let pool = &pool;
            scope.spawn(move || {
                for _ in 0..1000 {
                    if let Some(credit) = share.reserve_helper(1024) {
                        assert!(pool.helper_bytes() <= 4096);
                        drop(credit);
                    }
                }
            });
        }
    });
    assert_eq!(pool.helper_bytes(), 0);

    let mut s = RunSet::default();
    const N: usize = 4096;
    for i in 0..N {
        let mut r = RunBuilder::default();
        r.push(&omap_key(1, &(i as u32).to_be_bytes()), &[], &[0], b"v");
        s.insert(i as u64 + 1, r.finish(1).unwrap());
        if i % 64 == 63 {
            let mut c = s.compaction(1, 64, usize::MAX, 0, &[]).unwrap();
            while !c.step(128) {}
            assert!(s.swap_in(c));
        }
    }
    // 64 inputs with 64 live source-record parts each, not merely 64 large batch parts.
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let mut c = s.compaction(1, 64, usize::MAX, 0, &[]).unwrap();
    let reservation = c.reservation();
    while !c.step(128) {}
    c.finish_output();
    for i in (0..N).step_by(2) {
        s.kill(&omap_key(1, &(i as u32).to_be_bytes()));
    }
    assert!(s.swap_in(c));
    let growth = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    eprintln!("multipart publication allocation growth={growth} reserved={reservation}");
    assert!(
        growth <= reservation,
        "publication peak {growth} > reservation {reservation}"
    );
    assert_eq!(
        s.entries(),
        N,
        "late kills remain in the compacted blob's dead bitmap"
    );
    assert_eq!(
        s.floor(),
        Some(2),
        "killed first part must leave the WAL floor"
    );
    assert_eq!(s.scan(&omap_key(1, b""), &omap_key(2, b"")).count(), N / 2);
}
