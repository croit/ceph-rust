// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Descriptor allocation and ownership regression for block-fragmented READs.
use bytes::Bytes;
use opwire::OsdOp;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy, Default, Debug)]
struct Counts {
    allocations: usize,
    reallocations: usize,
}
thread_local! {
    static ACTIVE: Cell<Option<Counts>> = const { Cell::new(None) };
}
struct Counting;
fn record(reallocation: bool) {
    let _ = ACTIVE.try_with(|active| {
        if let Some(mut count) = active.get() {
            if reallocation {
                count.reallocations += 1;
            } else {
                count.allocations += 1;
            }
            active.set(Some(count));
        }
    });
}
// SAFETY: every operation delegates unchanged pointer/layout contracts to the
// system allocator. The per-thread const Cell neither allocates nor recurses.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(false);
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(false);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(true);
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn count(call: impl FnOnce()) -> Counts {
    ACTIVE.with(|active| {
        assert!(active.get().is_none());
        active.set(Some(Counts::default()));
    });
    call();
    ACTIVE.with(|active| active.take().unwrap())
}

#[test]
fn owned_read_piece_vector_reserves_once_and_preserves_payload_and_crc_ownership() {
    for nonempty in [0, 1, 2, 31, 256] {
        let mut parts = vec![(Bytes::new(), Some(42))];
        for i in 0..nonempty {
            let bytes = Bytes::from(vec![i as u8; 37]);
            let hint = (i % 2 == 0).then(|| crc::crc32c(!0, &bytes));
            parts.push((bytes, hint));
            parts.push((Bytes::new(), None));
        }
        let expected = parts.clone();
        let generic_input = parts.clone();
        let mut generic = OsdOp::read(0, (37 * nonempty) as u64);
        let mut owned = generic.clone();
        owned.outdata_block_crcs = Some(vec![123]);
        let generic_counts = count(|| generic.set_outdata_parts(generic_input));
        let owned_counts = count(|| owned.set_outdata_vec(parts));
        assert_eq!(owned, generic, "empty filtering and hint binding differ");
        assert_eq!(owned.outdata_len(), nonempty * 37);
        assert_eq!(owned_counts.allocations, usize::from(nonempty > 1));
        assert_eq!(owned_counts.reallocations, 0);
        assert!(owned.outdata_block_crcs.is_none());
        let (first, first_hint, more, _) = owned.take_outdata();
        let actual: Vec<_> = std::iter::once((first, first_hint))
            .chain(more)
            .filter(|(bytes, _)| !bytes.is_empty())
            .collect();
        assert_eq!(actual.len(), nonempty);
        for ((bytes, hint), (original, crc)) in actual
            .iter()
            .zip(expected.iter().filter(|(b, _)| !b.is_empty()))
        {
            assert_eq!(bytes.as_ptr(), original.as_ptr(), "payload was copied");
            assert_eq!(bytes.len(), original.len());
            assert_eq!(hint.of(bytes), *crc);
        }
        println!("READ pieces={nonempty}: generic={generic_counts:?} owned={owned_counts:?}");
    }
    // A general constant-memory iterator of empty descriptors must not reserve
    // based on its pre-filter length. Keep that API's allocation behavior.
    let mut operation = OsdOp::default();
    let counts =
        count(|| operation.set_outdata_parts(std::iter::repeat_n((Bytes::new(), None), 100_000)));
    assert_eq!((counts.allocations, counts.reallocations), (0, 0));
}
