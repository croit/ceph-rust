// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Thread-local Rust allocation counts (and bytes requested) for codec and decoder regression tests; not compiled into
//! the store library.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
    static BYTES: Cell<Option<usize>> = const { Cell::new(None) };
}

struct Counting;

fn count(bytes: usize) {
    let _ = COUNT.try_with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1));
        }
    });
    let _ = BYTES.try_with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + bytes));
        }
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        count(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        count(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        count(n);
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

pub(crate) fn allocations(f: impl FnOnce()) -> usize {
    COUNT.with(|c| c.set(Some(0)));
    f();
    COUNT.with(|c| c.replace(None).unwrap())
}

/// Bytes the allocations of `f` requested (the capacity of a `Vec::with_capacity`, not what it filled).
pub(crate) fn allocated_bytes(f: impl FnOnce()) -> usize {
    BYTES.with(|c| c.set(Some(0)));
    f();
    BYTES.with(|c| c.replace(None).unwrap())
}
