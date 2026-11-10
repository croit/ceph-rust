// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Object-map serialization allocation gate. Keep one test: counters are process-global.

use cls::rbd::bitvec::{BLOCK, ObjMap};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static MEASURING: AtomicBool = AtomicBool::new(false);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
struct Track;

// SAFETY: the allocator forwards every pointer, layout and size unchanged to System.
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if MEASURING.load(Ordering::Relaxed) {
            REALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Track = Track;

#[test]
fn object_map_encoding_never_grows_its_output_allocation() {
    // Include empty maps, partial bytes, CRC block boundaries, and a multi-MiB resize.
    for count in [0, 1, 4, (BLOCK * 4) as u64, (BLOCK * 4 + 1) as u64, 1 << 24] {
        let map = ObjMap::new(count, 1);
        for crc in [false, true] {
            REALLOCS.store(0, Ordering::Relaxed);
            MEASURING.store(true, Ordering::Relaxed);
            let encoded = map.encode_opt(crc);
            MEASURING.store(false, Ordering::Relaxed);
            let reallocations = REALLOCS.load(Ordering::Relaxed);
            assert_eq!(
                reallocations, 0,
                "count={count}, crc={crc}: serialization grew its output allocation"
            );
            assert_eq!(ObjMap::decode_crc(&encoded).unwrap(), (map.clone(), crc));
        }
    }
}
