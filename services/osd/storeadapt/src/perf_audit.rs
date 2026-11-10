// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Test-only comparative fixture; runs unchanged against the baseline's queued_input_bytes.
use super::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::time::Instant;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}
struct Meter;
fn charge(n: usize) {
    if TRACK.try_with(Cell::get).unwrap_or(false) {
        let _ = CALLS.try_with(|v| v.set(v.get() + 1));
        let _ = BYTES.try_with(|v| v.set(v.get() + n));
    }
}
// SAFETY: unchanged allocator operation delegated to System.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        charge(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        charge(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        charge(n);
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;

#[test]
#[ignore = "local release accounting allocator/CPU comparison; no hardware throughput claim"]
fn perf_queued_metadata_size() {
    let mut log = pgwire::PgLog::default();
    for i in 1..=128 {
        let mut e = pgwire::LogEntry {
            version: Eversion::new(1, i),
            ..Default::default()
        };
        e.mod_desc.bl = vec![0x36; 4096];
        log.log.push_back(e);
    }
    let wire_len = denc::to_vec(&log).unwrap().len();
    let txn = StoreTxn {
        ops: vec![StoreOp::LogReplace(Box::new(log))],
    };
    let expected = std::mem::size_of::<StoreOp>() + wire_len;
    assert_eq!(queued_input_bytes(&txn), expected);
    for sample in 0..5 {
        CALLS.set(0);
        BYTES.set(0);
        TRACK.set(true);
        let start = Instant::now();
        for _ in 0..100 {
            assert_eq!(black_box(queued_input_bytes(black_box(&txn))), expected);
        }
        let ns = start.elapsed().as_nanos();
        TRACK.set(false);
        println!(
            "metadata_count sample={sample} allocations={} requested_bytes={} ns_per_call={} wire_len={wire_len}",
            CALLS.get(),
            BYTES.get(),
            ns / 100
        );
    }
}
