// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Impossible collection counts must fail before reserving attacker-sized vectors.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct MeasuredAllocator;

thread_local! {
    static LARGEST: Cell<Option<usize>> = const { Cell::new(None) };
}

fn record(size: usize) {
    let _ = LARGEST.try_with(|largest| {
        if let Some(previous) = largest.get() {
            largest.set(Some(previous.max(size)));
        }
    });
}

// SAFETY: every allocation operation delegates unchanged to the system allocator.
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        // SAFETY: the caller supplies the allocation layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout belong to a delegated allocation.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        // SAFETY: the caller supplies the allocation layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        // SAFETY: the pointer and layout belong to a delegated allocation.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

#[test]
fn impossible_collection_counts_do_not_allocate_entry_vectors() {
    let mut wire = 4096u32.to_le_bytes().to_vec();
    wire.resize(4100, 0);
    let decoders = [
        |bytes: &[u8]| rustyrbd::decode_children_list_reply(bytes).is_err(),
        |bytes: &[u8]| rustyrbd::decode_children_set_reply(bytes).is_err(),
        |bytes: &[u8]| rustyrbd::decode_trash_list_reply(bytes).is_err(),
    ];
    let allocations = decoders.map(|decode| {
        LARGEST.set(Some(0));
        let rejected = decode(&wire);
        let largest = LARGEST.replace(None).unwrap();
        assert!(rejected);
        largest
    });
    assert_eq!(
        allocations, [0; 3],
        "impossible counts reserved entry vectors"
    );
}
