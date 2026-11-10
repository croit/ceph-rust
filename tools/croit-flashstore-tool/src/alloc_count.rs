// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Lab-only allocation counter (`--features alloc-count`): wraps the global allocator, counts calls so the bench can
//! report heap allocations per txn.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub static ALLOCS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "mimalloc")]
type Inner = mimalloc::MiMalloc;
#[cfg(not(feature = "mimalloc"))]
type Inner = std::alloc::System;

pub struct Counting(pub Inner);

impl Counting {
    #[cfg(feature = "mimalloc")]
    pub const fn new() -> Self {
        Counting(mimalloc::MiMalloc)
    }
    #[cfg(not(feature = "mimalloc"))]
    pub const fn new() -> Self {
        Counting(std::alloc::System)
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        unsafe { self.0.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        unsafe { self.0.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { self.0.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        unsafe { self.0.realloc(p, l, n) }
    }
}

pub fn count() -> u64 {
    ALLOCS.load(Relaxed)
}
