// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Track actual deallocation of a completed heap buffer across issuer teardown.
#![cfg(all(feature = "kernel", target_os = "linux"))]

use nvme::IoBuf;
use nvme::kdev::KBuf;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Tracked;
static WATCH: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);

// SAFETY: allocations are delegated unchanged to System. Only the watched
// allocation's deallocation is counted, without allocating or dereferencing it.
unsafe impl GlobalAlloc for Tracked {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: caller supplies a valid allocation layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == WATCH.load(Ordering::Relaxed) {
            FREED.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: same pointer/layout pair returned by System.
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOC: Tracked = Tracked;

#[test]
fn issuer_exit_frees_parked_heap_buffers() {
    std::thread::spawn(|| {
        let b = KBuf::new_heap_uninit(4096);
        WATCH.store(b.as_slice().as_ptr() as usize, Ordering::Relaxed);
        drop(b);
        assert_eq!(FREED.load(Ordering::Relaxed), 0, "buffer should be pooled");
    })
    .join()
    .unwrap();
    assert_eq!(
        FREED.load(Ordering::Relaxed),
        1,
        "issuer must free its pool"
    );
    WATCH.store(0, Ordering::Relaxed);
}
