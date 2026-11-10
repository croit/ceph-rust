// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Dispatch borrows the client input even when the method immediately rejects it.
mod common;

use common::*;
use opwire::OsdOp;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const INPUT_SIZE: usize = 65_539;
static TRACK: AtomicBool = AtomicBool::new(false);
static PAYLOAD_ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Alloc;

// SAFETY: forwards allocation and deallocation unchanged to System; only counts sizes.
unsafe impl GlobalAlloc for Alloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) && layout.size() == INPUT_SIZE {
            PAYLOAD_ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Alloc = Alloc;

#[test]
fn rejected_class_input_is_not_copied_by_dispatch() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    run(
        &mut pg,
        &mut eng,
        1,
        1,
        client(7),
        mkop(b"o", vec![OsdOp::create(false)]),
    );
    let input = vec![b'x'; INPUT_SIZE];
    let op = mkop(b"o", vec![OsdOp::call(b"hello", b"say_hello", &input)]);
    PAYLOAD_ALLOCS.store(0, Ordering::Relaxed);
    TRACK.store(true, Ordering::Relaxed);
    let mut outs = run(&mut pg, &mut eng, 1, 2, client(7), op);
    TRACK.store(false, Ordering::Relaxed);
    let allocations = PAYLOAD_ALLOCS.load(Ordering::Relaxed);
    let reply = reply_of(&mut outs, 1, 2).expect("reply");
    assert_eq!(reply.result, -opwire::errno::EINVAL);
    assert_eq!(allocations, 0, "dispatch must borrow the method input");
}
