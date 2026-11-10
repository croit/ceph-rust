// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Bounded lock-free single-producer single-consumer ring: the cross-core channel (ADR 0006).
//! Building block of the `rt::mesh` cores and lanes, the knet RX copy paths, the rdma control thread and the
//! rados-rt read-teardown worker.

use std::cell::{Cell, UnsafeCell};
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering, fence};

/// Pads `T` so a position written by one thread shares no line with another's. On x86_64 and aarch64 the
/// adjacent-line prefetcher pairs cache lines, so two positions need 128 bytes to stay apart.
#[cfg_attr(any(target_arch = "x86_64", target_arch = "aarch64"), repr(align(128)))]
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    repr(align(64))
)]
struct Pad<T>(T);

struct Ring<T> {
    buf: Box<[UnsafeCell<MaybeUninit<T>>]>,
    mask: usize,
    head: Pad<AtomicUsize>, // consumer position
    tail: Pad<AtomicUsize>, // producer position
    /// The producer found the ring full and waits for space ([`Producer::push_or_want`], [`Consumer::take_want`]).
    want: Pad<AtomicBool>,
}

impl<T> Ring<T> {
    fn capacity(&self) -> usize {
        self.mask + 1
    }
}

// SAFETY: the producer and the consumer thread share the `Arc<Ring<T>>` and hand slots over via release/acquire on
// head and tail, so a slot has one owner at a time; values move between threads (`T: Send`). `Send` follows from the
// fields.
unsafe impl<T: Send> Sync for Ring<T> {}

impl<T> Drop for Ring<T> {
    fn drop(&mut self) {
        let (mut h, t) = (*self.head.0.get_mut(), *self.tail.0.get_mut());
        while h != t {
            // SAFETY: slots in [head, tail) are initialised.
            unsafe { self.buf[h & self.mask].get_mut().assume_init_drop() };
            h = h.wrapping_add(1);
        }
    }
}

/// Producer half.
#[derive(Debug)]
pub struct Producer<T> {
    ring: Arc<Ring<T>>,
    /// Cached consumer position: conservative, refreshed only when the cached window is full.
    head_cache: usize,
    /// This producer registered a space wake that is still pending ([`push_or_want`](Self::push_or_want)).
    want_registered: bool,
}

/// Consumer half.
#[derive(Debug)]
pub struct Consumer<T> {
    ring: Arc<Ring<T>>,
    /// Cached producer position: refreshed only when it equals the consumer's own position.
    tail_cache: Cell<usize>,
}

impl<T> std::fmt::Debug for Ring<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ring(cap={})", self.capacity())
    }
}

/// Create a ring with capacity `cap` (rounded up to a power of two, min 2); [`Producer::capacity`] reports the
/// effective capacity.
///
/// # Panics
/// When the rounded capacity does not fit in `usize` (`cap > 2^63` on 64-bit). The buffer is allocated here, so an
/// overflowing capacity is a caller bug that must not turn into a ring that panics on its first push.
pub fn channel<T: Send>(cap: usize) -> (Producer<T>, Consumer<T>) {
    let cap = cap.max(2).checked_next_power_of_two().unwrap_or_else(|| {
        panic!("spsc: capacity {cap} cannot be rounded up to a power of two that fits in usize")
    });
    channel_power_of_two(cap)
}

/// Construct a caller-validated power-of-two ring, including capacity one.
/// Existing `channel` callers retain their minimum-two rounding policy.
///
/// # Panics
/// When `cap` is not a positive power of two.
pub fn channel_power_of_two<T: Send>(cap: usize) -> (Producer<T>, Consumer<T>) {
    assert!(
        cap.is_power_of_two(),
        "capacity must be a positive power of two"
    );
    let r = Arc::new(Ring {
        buf: (0..cap)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect(),
        mask: cap - 1,
        head: Pad(AtomicUsize::new(0)),
        tail: Pad(AtomicUsize::new(0)),
        want: Pad(AtomicBool::new(false)),
    });
    (
        Producer {
            ring: r.clone(),
            head_cache: 0,
            want_registered: false,
        },
        Consumer {
            ring: r,
            tail_cache: Cell::new(0),
        },
    )
}

impl<T> Producer<T> {
    /// Effective ring capacity: `cap` rounded up to a power of two, min 2 (exactly the requested power of two for
    /// [`channel_power_of_two`]). Callers admit against this, not against
    /// their own rounding of the requested capacity.
    pub fn capacity(&self) -> usize {
        self.ring.capacity()
    }

    /// Push; hands the value back when full. A success also drops a still pending space-wake registration of this
    /// producer: it no longer waits, so the consumer must not be poked.
    pub fn push(&mut self, v: T) -> Result<(), T> {
        let r = &*self.ring;
        let t = r.tail.0.load(Ordering::Relaxed);
        // Cached head is conservative: refresh only when the cached window is full.
        if t.wrapping_sub(self.head_cache) > r.mask {
            self.head_cache = r.head.0.load(Ordering::Acquire);
            if t.wrapping_sub(self.head_cache) > r.mask {
                return Err(v);
            }
        }
        // SAFETY: slot t is free (consumer is past it) and only this producer writes it.
        unsafe { (*r.buf[t & r.mask].get()).write(v) };
        r.tail.0.store(t.wrapping_add(1), Ordering::Release);
        if self.want_registered {
            // Only a producer that blocked once pays this (one not-taken branch, no store for the others): a plain push
            // after a failed `push_or_want` must not leave the consumer reporting a waiter that is gone.
            self.want_registered = false;
            // Relaxed suffices: this producer is the only writer of `want`, and it is not waiting any more, so the
            // consumer may either see the registration (one useless poke) or the clear.
            r.want.0.store(false, Ordering::Relaxed);
        }
        Ok(())
    }

    /// [`push`](Self::push); on a full ring the producer registers for a space wake, fences and tries once more
    /// (Dekker with [`Consumer::take_want`]: either this retry sees the consumer's pop or the consumer sees the
    /// registration). `Err`: still full, and the consumer's next `take_want` after a pop reports it, once.
    pub fn push_or_want(&mut self, v: T) -> Result<(), T> {
        let v = match self.push(v) {
            Ok(()) => return Ok(()),
            Err(v) => v,
        };
        self.want_registered = true;
        self.ring.want.0.store(true, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        // A retry that finds space clears the registration inside `push`.
        self.push(v)
    }

    /// Values pushed so far (wrapping count). With [`Producer::consumed`] and the consumer's
    /// [`Consumer::published`] / [`Consumer::popped`], an owner on another thread tells whether either side moved
    /// since it last looked (a sleep/wake protocol), without touching the slots.
    pub fn pushed(&self) -> usize {
        self.ring.tail.0.load(Ordering::Relaxed)
    }

    /// Values the consumer has popped so far (wrapping count, acquire).
    pub fn consumed(&self) -> usize {
        self.ring.head.0.load(Ordering::Acquire)
    }

    /// A push would succeed now (fresh look at the consumer's position).
    pub fn has_space(&self) -> bool {
        let r = &*self.ring;
        r.tail
            .0
            .load(Ordering::Relaxed)
            .wrapping_sub(r.head.0.load(Ordering::Acquire))
            <= r.mask
    }
}

impl<T> Consumer<T> {
    /// Borrow the oldest published value without releasing its slot to the producer.
    pub fn peek(&self) -> Option<&T> {
        let h = self.next_index()?;
        let r = &*self.ring;
        // SAFETY: the acquire in `next_index` observed the initialization; the producer cannot reuse this slot
        // before pop advances head. The returned borrow prevents a mutable pop while the reference is live.
        Some(unsafe { (*r.buf[h & r.mask].get()).assume_init_ref() })
    }

    /// Inspect the currently published slots without consuming them. The
    /// consumer borrow pins every visited slot; the producer cannot overwrite
    /// any of them until this consumer advances its head.
    pub fn visit(&self, mut visit: impl FnMut(&T)) {
        let ring = &*self.ring;
        let mut head = ring.head.0.load(Ordering::Relaxed);
        let tail = ring.tail.0.load(Ordering::Acquire);
        while head != tail {
            // SAFETY: acquire published these slots and this shared consumer
            // borrow excludes pop, so every item remains initialized and owned.
            visit(unsafe { (*ring.buf[head & ring.mask].get()).assume_init_ref() });
            head = head.wrapping_add(1);
        }
    }

    /// True when nothing is published (acquire: sees a value published before the producer's later fence).
    #[inline]
    pub fn is_empty(&self) -> bool {
        let r = &*self.ring;
        r.head.0.load(Ordering::Relaxed) == r.tail.0.load(Ordering::Acquire)
    }

    /// Values the producer has published so far (wrapping count, acquire; see [`Producer::pushed`]).
    pub fn published(&self) -> usize {
        self.ring.tail.0.load(Ordering::Acquire)
    }

    /// Values popped so far (wrapping count).
    pub fn popped(&self) -> usize {
        self.ring.head.0.load(Ordering::Relaxed)
    }

    /// Pop the oldest value.
    pub fn pop(&mut self) -> Option<T> {
        let h = self.next_index()?;
        let r = &*self.ring;
        // SAFETY: slot h was published by the producer (acquire in `next_index`) and is read once.
        let v = unsafe { (*r.buf[h & r.mask].get()).assume_init_read() };
        r.head.0.store(h.wrapping_add(1), Ordering::Release);
        Some(v)
    }

    /// Index of the oldest published value; refreshes the cached producer position when the cache says empty.
    fn next_index(&self) -> Option<usize> {
        let r = &*self.ring;
        let h = r.head.0.load(Ordering::Relaxed);
        if h == self.tail_cache.get() {
            self.tail_cache.set(r.tail.0.load(Ordering::Acquire));
            if h == self.tail_cache.get() {
                return None;
            }
        }
        Some(h)
    }

    /// The producer registered for a space wake ([`Producer::push_or_want`]); clears the registration. Call after the
    /// pops that freed space, behind one `fence(SeqCst)` (one fence may cover many rings).
    pub fn take_want(&self) -> bool {
        let w = &self.ring.want.0;
        w.load(Ordering::Relaxed) && w.swap(false, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn opt_in_single_slot_preserves_default_minimum_two() {
        let (mut default_tx, mut default_rx) = super::channel(1);
        default_tx.push(1).unwrap();
        default_tx.push(2).unwrap();
        assert!(default_tx.push(3).is_err());
        assert_eq!(default_rx.pop(), Some(1));
        assert_eq!(default_rx.pop(), Some(2));
        let (mut tx, mut rx) = super::channel_power_of_two(1);
        for value in 0..1000 {
            tx.push(value).unwrap();
            assert!(tx.push(value + 1).is_err());
            assert_eq!(rx.peek(), Some(&value));
            assert_eq!(rx.pop(), Some(value));
            assert!(rx.is_empty());
        }
    }
    #[test]
    fn cached_windows_refresh_at_full_and_empty_boundaries() {
        let (mut p, mut c) = super::channel(4);
        for v in 0..4 {
            p.push(v).unwrap();
        }
        assert_eq!(p.head_cache, 0);
        assert!(!c.is_empty()); // Wake rechecks always observe the published tail.
        assert_eq!(c.peek(), Some(&0));
        assert_eq!(c.tail_cache.get(), 4);
        assert_eq!(c.pop(), Some(0));
        assert_eq!(c.pop(), Some(1));
        p.push(4).unwrap(); // Refresh the conservative full window.
        assert_eq!(p.head_cache, 2);
        p.push(5).unwrap();
        assert!(p.push(6).is_err());
        for v in 2..6 {
            assert_eq!(c.pop(), Some(v));
        }
        assert_eq!(c.peek(), None);
        p.push(6).unwrap();
        assert!(!c.is_empty());
        assert_eq!(c.peek(), Some(&6));
        assert_eq!(c.pop(), Some(6));
        assert_eq!(c.pop(), None);
    }

    /// Positions count every push and pop on both halves, across the index wrap.
    #[test]
    fn positions_count_pushes_and_pops() {
        let (mut p, mut c) = super::channel::<u32>(2);
        for round in 0..5 {
            assert_eq!((p.pushed(), c.published()), (2 * round, 2 * round));
            p.push(1).unwrap();
            p.push(2).unwrap();
            assert_eq!((p.pushed(), c.published()), (2 * round + 2, 2 * round + 2));
            assert_eq!((c.popped(), p.consumed()), (2 * round, 2 * round));
            c.pop().unwrap();
            c.pop().unwrap();
            assert_eq!((c.popped(), p.consumed()), (2 * round + 2, 2 * round + 2));
        }
    }

    /// Space wake: a producer that finds the ring full registers once; the consumer's pop reports it once; a retry that
    /// finds space leaves no registration behind.
    #[test]
    fn a_full_push_registers_one_space_wake() {
        let (mut p, mut c) = super::channel::<u32>(2);
        assert_eq!(p.push_or_want(1), Ok(()));
        assert_eq!(p.push_or_want(2), Ok(()));
        assert!(!c.take_want(), "no producer waited");
        assert_eq!(p.push_or_want(3), Err(3));
        assert!(!p.has_space());
        assert_eq!(c.pop(), Some(1));
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        assert!(
            c.take_want(),
            "the pop that frees space reports the waiting producer"
        );
        assert!(!c.take_want(), "once");
        assert!(p.has_space());
        assert_eq!(p.push_or_want(3), Ok(()));
        assert_eq!(c.pop(), Some(2));
        assert!(!c.take_want());
    }

    #[test]
    fn fifo_full_and_threads() {
        let (mut p, mut c) = super::channel::<u32>(4);
        for i in 0..4 {
            p.push(i).unwrap();
        }
        assert_eq!(p.push(9), Err(9));
        assert_eq!(c.pop(), Some(0));
        p.push(4).unwrap();
        assert_eq!(
            (1..5).map(|_| c.pop().unwrap()).collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        assert_eq!(c.pop(), None);

        let (mut p, mut c) = super::channel::<u64>(64);
        let t = std::thread::spawn(move || {
            for i in 0..100_000u64 {
                let mut v = i;
                while let Err(b) = p.push(v) {
                    v = b;
                    std::hint::spin_loop();
                }
            }
        });
        let mut next = 0;
        while next < 100_000 {
            if let Some(v) = c.pop() {
                assert_eq!(v, next);
                next += 1;
            }
        }
        t.join().unwrap();
    }

    /// Callers admit against the effective capacity, not against their own rounding of the requested one.
    #[test]
    fn capacity_reports_the_effective_ring_size() {
        assert_eq!(super::channel::<u8>(0).0.capacity(), 2);
        assert_eq!(super::channel::<u8>(1).0.capacity(), 2);
        assert_eq!(super::channel::<u8>(3).0.capacity(), 4);
        assert_eq!(super::channel::<u8>(5).0.capacity(), 8);
    }

    /// The ring allocates its buffer up front: a capacity whose rounding overflows `usize` must fail at construction
    /// with the requested capacity, not build a zero-length ring whose first push panics.
    #[test]
    #[should_panic(expected = "spsc: capacity")]
    fn an_over_capacity_ring_fails_loudly_at_construction() {
        let _ = super::channel::<u8>((1usize << 63) + 1);
    }

    /// Adjacent-line prefetchers (x86_64, aarch64) load the line next to an accessed one, so a producer's `tail` store
    /// must not pull the consumer's `head` line: the padded positions need 128 bytes there.
    #[test]
    fn positions_are_two_cache_lines_apart_on_prefetching_targets() {
        let want = if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            128
        } else {
            64
        };
        assert_eq!(
            std::mem::align_of::<super::Pad<u8>>(),
            want,
            "adjacent-line prefetcher distance"
        );
    }

    /// A registration left by a failed `push_or_want` must not survive a later successful plain `push`: the consumer
    /// would report a waiter that is not waiting any more and poke it once.
    #[test]
    fn a_plain_push_after_a_full_want_clears_the_registration() {
        let (mut p, mut c) = super::channel::<u32>(2);
        assert_eq!(p.push_or_want(1), Ok(()));
        assert_eq!(p.push_or_want(2), Ok(()));
        assert_eq!(p.push_or_want(3), Err(3));
        assert_eq!(c.pop(), Some(1));
        // Space is free again; a plain push succeeds without the want protocol.
        p.push(3).unwrap();
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        assert!(
            !c.take_want(),
            "a successful push drops the pending registration"
        );
        assert_eq!(c.pop(), Some(2));
        assert_eq!(c.pop(), Some(3));
    }

    #[test]
    fn drops_remaining() {
        let a = std::sync::Arc::new(());
        let (mut p, c) = super::channel::<std::sync::Arc<()>>(4);
        p.push(a.clone()).unwrap();
        assert_eq!(std::sync::Arc::strong_count(&a), 2);
        drop((p, c));
        assert_eq!(std::sync::Arc::strong_count(&a), 1);
    }
}
