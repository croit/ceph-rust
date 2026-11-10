// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Allocation behaviour of the receive path (review msgr2 C4/C7): admitting and retiring a MESSAGE must not touch the
//! heap, and a receive buffer that cannot be allocated is reported as such instead of as a peer protocol violation.
use msgr2::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
mod common;

thread_local! {
    /// Count allocations of this thread.
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static LARGE_ALLOCS: Cell<usize> = const { Cell::new(0) };
    /// Fail every allocation of at least this many bytes on this thread (0: never).
    static FAIL_AT: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: allocation, zeroed allocation, reallocation and deallocation are delegated unchanged to the system allocator;
// the thread-local counters only observe them.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if fails(layout.size()) {
            return core::ptr::null_mut();
        }
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
            if layout.size() >= 64 << 10 {
                LARGE_ALLOCS.set(LARGE_ALLOCS.get() + 1);
            }
        }
        // SAFETY: caller supplies the allocator's valid layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if fails(layout.size()) {
            return core::ptr::null_mut();
        }
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
            if layout.size() >= 64 << 10 {
                LARGE_ALLOCS.set(LARGE_ALLOCS.get() + 1);
            }
        }
        // SAFETY: caller supplies the allocator's valid layout.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) && new_size >= 64 << 10 {
            LARGE_ALLOCS.set(LARGE_ALLOCS.get() + 1);
        }
        // SAFETY: `ptr`/`layout` came from this same system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr`/`layout` came from this same system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

fn fails(size: usize) -> bool {
    FAIL_AT
        .try_with(|at| at.get() != 0 && size >= at.get())
        .unwrap_or(false)
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

#[test]
fn rope_fallback_does_not_allocate_a_payload_temporary() {
    use bytes::Bytes;
    let run = Bytes::from(vec![0x5a; 1 << 20]);
    let front = [1, 2, 3];
    let rope = [(1, run.clone()), (1, run.clone()), (3, run)];
    let secret = ConnSecret::new(&[7; 64]).unwrap();
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            if !secure && rev == Revision::V21 {
                continue; // reference-sharing path, not the fallback
            }
            let mut enc = Encoder::new(rev);
            let mut dec = Decoder::new(rev);
            if secure {
                enc.set_secure(&secret, Role::Client).unwrap();
                dec.set_secure(&secret, Role::Server).unwrap();
            }
            let header = MsgHeader2::default().to_bytes();
            let mut out = Vec::with_capacity(4 << 20);
            let mut chunks = Vec::new();
            LARGE_ALLOCS.set(0);
            let (result, _) = measure(|| {
                enc.encode_message_rope(
                    &header,
                    &front,
                    &rope,
                    &Default::default(),
                    &[],
                    &Bytes::new(),
                    &Default::default(),
                    &mut out,
                    &mut chunks,
                )
            });
            result.unwrap();
            assert_eq!(
                LARGE_ALLOCS.get(),
                0,
                "{rev:?} secure={secure}: plaintext staging"
            );
            assert!(chunks.is_empty());
            dec.feed(&out);
            let frame = dec.poll_owned().unwrap().unwrap();
            let expected = [
                front[..1].to_vec(),
                rope[0].1.to_vec(),
                rope[1].1.to_vec(),
                front[1..].to_vec(),
                rope[2].1.to_vec(),
            ]
            .concat();
            assert_eq!(frame.segs[1].as_ref(), expected);
        }
    }
}

/// Heap allocations of `f` on this thread.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    ALLOCS.set(0);
    TRACK.set(true);
    let v = f();
    TRACK.set(false);
    (v, ALLOCS.get())
}

/// A dispatch guard holds one MESSAGE's credit for its whole lifetime: the receive path of every dispatch domain (the
/// OSD's client path) must not heap-allocate per admitted message.
#[test]
fn message_admission_and_retirement_do_not_allocate() {
    let mut budget = DispatchBudget::new(1 << 20, 16).unwrap();
    drop(budget.try_acquire(1024).unwrap());
    let ((), allocs) = measure(|| {
        for _ in 0..16 {
            drop(budget.try_acquire(1024).unwrap());
        }
    });
    assert_eq!(allocs, 0, "one allocation per admitted MESSAGE");
}

/// A receive segment buffer that cannot be allocated (local out-of-memory) is `Error::AllocationFailed`, not a peer
/// protocol violation; the decoder still faults, nothing else changes.
#[test]
fn a_failed_receive_segment_allocation_is_not_a_peer_fault() {
    const BODY: usize = 8 << 20;
    let h = MsgHeader2::default().to_bytes();
    let mut wire = Vec::new();
    Encoder::new(Revision::V21)
        .encode_message(&h, &[], &[], &vec![7; BODY], &mut wire)
        .unwrap();
    let mut d = Decoder::new(Revision::V21);
    d.set_limits(Limits::wire_shape());
    FAIL_AT.set(1 << 20);
    // preamble, header2 and its crc, then the first data bytes: sizing the data segment is the first large allocation
    d.feed(&wire[..PREAMBLE_LEN + payload::HEADER2_LEN + 4 + 3]);
    FAIL_AT.set(0);
    assert_eq!(d.poll().err(), Some(Error::AllocationFailed(BODY)));
}

/// Draining the ordinary priority queue must preserve its backing allocation
/// for the next send, including when the next message uses another priority.
#[test]
fn serialized_sends_reuse_drained_priority_queue_storage() {
    use common::*;
    use denc::types::EntityName;
    let mut a = Node::new(EntityName::CLIENT, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(7), 1024);
    events(&mut c);
    events(&mut s);
    assert!(c.send_message(Message::default()));
    c.poll_output_chunks();
    let mut allocations = 0;
    for priority in [0, 127, 255, 64, 0, 1, 255, 127] {
        let (accepted, count) = measure(|| {
            c.send_message(Message {
                priority,
                ..Default::default()
            })
        });
        assert!(accepted);
        allocations += count;
        c.poll_output_chunks();
    }
    // Framing and sent/replay storage are outside the admission count.
    assert_eq!(allocations, 0, "priority queue allocations per eight sends");
    assert!(c.configure_write_receipts(16));
    for priority in [255, 64, 127, 0] {
        let (receipt, count) = measure(|| {
            c.send_message_tracked(Message {
                priority,
                ..Default::default()
            })
            .ok()
        });
        assert!(receipt.is_some());
        assert_eq!(count, 0, "tracked priority queue admission allocates");
        c.poll_output_chunks();
    }
}
