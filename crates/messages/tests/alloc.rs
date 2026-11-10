// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Allocation regressions for sizes a peer controls (review MSG-05).

use denc::types::Uuid;
use messages::{MGetPoolStats, Message};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

struct Counting;
// SAFETY: every operation delegates unchanged pointer/layout contracts to the system allocator. The per-thread const
// Cells neither allocate nor recurse.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            let _ = BYTES.try_with(|n| n.set(n.get() + layout.size()));
        }
        // SAFETY: caller supplies the allocator's valid layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: allocation and layout came from this same system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `f` and report (result, allocated bytes on this thread).
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    BYTES.set(0);
    TRACK.set(true);
    let v = f();
    TRACK.set(false);
    (v, BYTES.get())
}

/// MSG-05: a counted name list must not be reserved from the declared count. The front declares 250 000 names (4 wire
/// bytes each) and its first name is malformed, so the decode stops right after the reservation: only the bounded first
/// reservation (4096 * `size_of::<Vec<u8>>()`) may have been allocated, not 250 000 * 24 B.
#[test]
fn pool_stats_name_count_does_not_preallocate() {
    let count = 250_000u32;
    let mut front = MGetPoolStats {
        version: 0,
        fsid: Uuid([7; 16]),
        pools: Vec::new(),
    }
    .encode(0)
    .unwrap()
    .front;
    front[34..38].copy_from_slice(&count.to_le_bytes());
    front.resize(38 + count as usize * 4, 0);
    front[38..42].copy_from_slice(&u32::MAX.to_le_bytes());
    let (decoded, bytes) = measure(|| MGetPoolStats::decode(1, &front, &[], &[]));
    assert!(decoded.is_err());
    assert!(
        bytes < 256 * 1024,
        "decode reserved {bytes} bytes from one counted request"
    );
}
