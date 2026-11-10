// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}
struct Alloc;
fn count() {
    if COUNTING.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
    }
}
unsafe impl GlobalAlloc for Alloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static A: Alloc = Alloc;

/// Allocations made by `body` on this thread.
fn allocations(body: impl FnOnce()) -> usize {
    ALLOCS.with(|n| n.set(0));
    COUNTING.with(|c| c.set(true));
    body();
    COUNTING.with(|c| c.set(false));
    ALLOCS.with(Cell::get)
}

#[test]
fn live_deadline_changes_and_cancellation_allocate_nothing() {
    let mut index = deadline::Index::default();
    for k in 0..1000 {
        index.register(k);
    }
    let allocs = allocations(|| {
        for round in 0..100 {
            for k in 0..1000 {
                index.set(k, Some((999 - k + round) as u64));
                std::hint::black_box(index.first());
            }
            for k in 0..1000 {
                index.set(k, None);
            }
        }
    });
    assert_eq!(allocs, 0);
}

/// A due query allocates its result vector only; the collect buffer is filled once and reused after that.
#[test]
fn due_queries_allocate_one_result_vector_and_reuse_their_collect_buffer() {
    let mut index = deadline::Index::default();
    for key in 0..1000u64 {
        index.register(key);
        index.set(key, Some(key));
    }
    std::hint::black_box(index.due(500));
    let allocs = allocations(|| {
        for _ in 0..2 {
            std::hint::black_box(index.due(500));
        }
    });
    assert_eq!(allocs, 2);
}

#[test]
fn live_slot_deadline_changes_and_cancellation_allocate_nothing() {
    let mut index = deadline::SlotIndex::default();
    for slot in 0..1000 {
        index.register(slot);
    }
    let allocs = allocations(|| {
        for round in 0..100 {
            for slot in 0..1000 {
                index.set(slot, Some((999 - slot + round) as u64));
                std::hint::black_box(index.first());
            }
            for slot in 0..1000 {
                index.set(slot, None);
            }
        }
    });
    assert_eq!(allocs, 0);
}
