// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Per-thread recycled byte vectors for the keys and values a txn stages (adr 0006 / 0031: no allocation on the hot
//! path). A write builds ~10 short-lived `Vec<u8>` (tree keys, encoded values); they travel through the staging map and
//! the `Record` and are dead once the record is applied and encoded. [`give`] takes them back, [`take`] hands them out
//! empty with their capacity kept, so the steady state allocates nothing. Thread-local: no lock, no sharing; a vector that
//! is given on another thread than it was taken on simply joins that thread's pool.
//!
//! Bounds: at most [`KEEP`] vectors per thread, none above [`MAX_CAP`] bytes of capacity (a big value is freed, not
//! parked). Worst case parked memory is `KEEP * MAX_CAP` per thread (4 MiB); the typical key/value is tens of bytes.

use std::cell::RefCell;

/// Vectors parked per thread: one write stages ~10, a unit of 16 txns in flight stays well below.
const KEEP: usize = 256;
/// Largest capacity parked.
const MAX_CAP: usize = 16 << 10;

thread_local! {
    static POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// An empty vector with room for at least `cap` bytes: a parked one when there is one, else a new allocation.
pub fn take(cap: usize) -> Vec<u8> {
    let mut v = POOL
        .try_with(|p| p.borrow_mut().pop())
        .ok()
        .flatten()
        .unwrap_or_default();
    v.reserve(cap);
    v
}

/// Park `v` for reuse (contents dropped, capacity kept).
pub fn give(mut v: Vec<u8>) {
    if v.capacity() == 0 || v.capacity() > MAX_CAP {
        return;
    }
    v.clear();
    let _ = POOL.try_with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < KEEP {
            p.push(v);
        }
    });
}

/// Parked vectors of this thread (tests, diagnostics).
pub fn parked() -> usize {
    POOL.try_with(|p| p.borrow().len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_given_vector_comes_back_empty_with_its_capacity_and_address() {
        let mut v = take(100);
        v.extend_from_slice(b"stale bytes that must never be visible");
        let (p, c) = (v.as_ptr(), v.capacity());
        give(v);
        let w = take(10);
        assert!(w.is_empty(), "a recycled vector carries no old bytes");
        assert_eq!((w.as_ptr(), w.capacity()), (p, c), "same allocation");
        give(w);
    }

    #[test]
    fn take_reserves_the_asked_capacity_even_from_a_small_parked_vector() {
        give(Vec::with_capacity(8));
        let v = take(1000);
        assert!(v.capacity() >= 1000 && v.is_empty());
    }

    #[test]
    fn the_pool_is_bounded_in_count_and_in_vector_size() {
        POOL.with(|p| p.borrow_mut().clear());
        for _ in 0..KEEP + 50 {
            give(Vec::with_capacity(16));
        }
        assert_eq!(parked(), KEEP);
        POOL.with(|p| p.borrow_mut().clear());
        give(Vec::with_capacity(MAX_CAP + 1));
        give(Vec::new());
        assert_eq!(
            parked(),
            0,
            "oversized and empty-capacity vectors are not parked"
        );
    }

    #[test]
    fn pools_are_per_thread() {
        give(Vec::with_capacity(32));
        let here = parked();
        let there = std::thread::spawn(parked).join().unwrap();
        assert!(here >= 1);
        assert_eq!(there, 0);
    }
}
