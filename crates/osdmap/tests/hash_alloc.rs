// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `hash_key` for a namespaced object must not touch the heap (spec osdmap 5.2): it runs once per object mapping on
//! the client and OSD send paths, where one allocation per object is a measurable cost. The counter is local to the
//! measuring thread.
use osdmap::hash::{STR_HASH_LINUX, STR_HASH_RJENKINS, hash_key, str_hash};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

thread_local! {
    static ALLOCS: Cell<Option<usize>> = const { Cell::new(None) };
}

struct Counting;

fn count() {
    let _ = ALLOCS.try_with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1));
        }
    });
}

// SAFETY: forwards every call to the system allocator unchanged, only counting.
unsafe impl GlobalAlloc for Counting {
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
static A: Counting = Counting;

/// Heap allocations of `f` on this thread.
fn allocations(f: impl FnOnce()) -> usize {
    ALLOCS.with(|c| c.set(Some(0)));
    f();
    ALLOCS.with(|c| c.replace(None).unwrap())
}

/// The segment-wise hash is the hash of the joined buffer (spec 5.2), for every length around the 12-byte chunk
/// boundary and for both hash types.
#[test]
fn namespaced_hash_matches_the_joined_buffer() {
    for ns in [&b"n"[..], b"a/b", b"a-longer-namespace"] {
        for len in 0..40usize {
            let key = vec![b'k'; len];
            let mut joined = ns.to_vec();
            joined.push(0x1f);
            joined.extend_from_slice(&key);
            for ty in [STR_HASH_LINUX, STR_HASH_RJENKINS] {
                assert_eq!(
                    hash_key(ty, ns, &key),
                    str_hash(ty, &joined),
                    "type {ty}, ns {ns:?}, key len {len}"
                );
                assert_eq!(hash_key(ty, b"", &key), str_hash(ty, &key));
            }
        }
    }
}

#[test]
fn namespaced_hash_does_not_allocate() {
    let ns = b"a/namespace";
    let key = b"object-name-of-typical-length";
    // warm up (first-touch of any lazily initialised hash state)
    black_box(hash_key(STR_HASH_RJENKINS, ns, key));
    let allocs = allocations(|| {
        let mut acc = 0u32;
        for _ in 0..1000 {
            acc = acc.wrapping_add(hash_key(STR_HASH_RJENKINS, ns, key));
            acc = acc.wrapping_add(hash_key(STR_HASH_LINUX, ns, key));
        }
        black_box(acc);
    });
    assert_eq!(allocs, 0, "a namespaced object hash allocated");
}
