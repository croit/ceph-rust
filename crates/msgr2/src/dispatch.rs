// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optional logical MESSAGE dispatch credit; independent of physical buffer ownership.
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::Waker;

/// A dispatch-domain configuration or admission failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchError {
    /// The finite count must be positive.
    InvalidCount,
    /// Another logical holder currently prevents admission.
    NoCredit,
    /// The sum of logical bytes cannot be represented.
    Overflow,
    /// The wake generation has exhausted its representable range; never wrap/ABA.
    GenerationExhausted,
}

#[derive(Debug)]
struct State {
    target: u64,
    max_count: usize,
    bytes: AtomicU64,
    count: AtomicUsize,
    generation: AtomicU64,
    armed: AtomicBool,
    pending_wake: AtomicBool,
    wake: OnceLock<Waker>,
    /// Released large receive buffers, bounded by `target` (see [`crate::rxpool`]).
    shelf: Arc<crate::rxpool::Shelf>,
}

impl State {
    fn changed(&self) {
        // Saturate explicitly; arm/admission report exhaustion rather than silently wrapping.
        let _ = self
            .generation
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1));
        if self.armed.swap(false, Ordering::SeqCst) {
            // Publish before loading wake: attach must observe either this flag or a later wake.
            self.pending_wake.store(true, Ordering::Release);
            self.notify();
        }
    }
    fn notify(&self) {
        if let Some(wake) = self.wake.get()
            && self.pending_wake.swap(false, Ordering::AcqRel)
        {
            wake.wake_by_ref();
        }
    }
}

/// Shared optional client domain. Zero byte target disables bytes, not finite count.
#[derive(Debug)]
pub struct DispatchBudget(Arc<State>);

impl DispatchBudget {
    /// Create a domain before transport construction; attach its reactor waker once ready.
    pub fn new(target: u64, max_count: usize) -> Result<Self, DispatchError> {
        if max_count == 0 {
            return Err(DispatchError::InvalidCount);
        }
        Ok(Self(Arc::new(State {
            target,
            max_count,
            bytes: AtomicU64::new(0),
            count: AtomicUsize::new(0),
            generation: AtomicU64::new(0),
            armed: AtomicBool::new(false),
            pending_wake: AtomicBool::new(false),
            wake: OnceLock::new(),
            shelf: Arc::new(crate::rxpool::Shelf::new(target)),
        })))
    }

    pub(crate) fn shelf(&self) -> Arc<crate::rxpool::Shelf> {
        self.0.shelf.clone()
    }

    /// Attach exactly one Send+Sync owner-reactor waker; replay any armed early retirement.
    /// On duplicate attachment return the supplied waker without changing the original.
    pub fn attach_waker(&mut self, wake: Waker) -> Result<(), Waker> {
        self.0.wake.set(wake)?;
        self.0.notify();
        Ok(())
    }

    /// Snapshot before attempting admission, then use it with [`Self::arm`] on NoCredit.
    pub fn generation(&self) -> u64 {
        self.0.generation.load(Ordering::SeqCst)
    }

    /// Arm the shared reactor. True requires immediate retry; false permits sleep.
    /// The reactor retries all blocked peers before sleeping; this is not a per-peer registry.
    pub fn arm(&mut self, observed: u64) -> Result<bool, DispatchError> {
        self.0.armed.store(true, Ordering::SeqCst);
        let current = self.generation();
        if current != observed || current == u64::MAX {
            self.0.armed.store(false, Ordering::SeqCst);
            if current == u64::MAX {
                return Err(DispatchError::GenerationExhausted);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Reserve one MESSAGE from the sole admission owner. Guards may retire on any thread.
    ///
    /// The budget is deliberately not Clone; share its unique owner only within the
    /// reactor. This keeps failed admission side-effect-free without a lock or packed counters.
    ///
    /// ```compile_fail
    /// let shared = std::sync::Arc::new(msgr2::DispatchBudget::new(8, 4).unwrap());
    /// shared.try_acquire(1); // admission requires the unique mutable owner
    /// ```
    pub fn try_acquire(&mut self, charge: u64) -> Result<DispatchGuard, DispatchError> {
        let s = &self.0;
        if self.generation() == u64::MAX {
            return Err(DispatchError::GenerationExhausted);
        }
        let count = s.count.load(Ordering::Acquire);
        if count >= s.max_count {
            return Err(DispatchError::NoCredit);
        }
        let mut used = s.bytes.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(charge).ok_or(DispatchError::Overflow)?;
            if s.target != 0 && next > s.target && !(count == 0 && used == 0) {
                return Err(DispatchError::NoCredit);
            }
            // Only guard drops race this owner: count can only decrease since our check.
            // Observing count0 implies bytes0, since Drop subtracts bytes before count.
            match s
                .bytes
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => used = actual,
            }
        }
        s.count.fetch_add(1, Ordering::AcqRel);
        Ok(DispatchGuard {
            state: Some(self.0.clone()),
            charge,
        })
    }
}

/// Logical lifetime only: releases its charge when dropped (on any thread). Default is allocation-free; equality
/// ignores accounting identity.
#[derive(Debug, Default)]
pub struct DispatchGuard {
    /// The domain whose counters this guard holds, `None` for a default/absent guard.
    state: Option<Arc<State>>,
    charge: u64,
}

impl Drop for DispatchGuard {
    fn drop(&mut self) {
        let Some(state) = &self.state else {
            return;
        };
        state.bytes.fetch_sub(self.charge, Ordering::AcqRel);
        state.count.fetch_sub(1, Ordering::AcqRel);
        state.changed();
    }
}

impl PartialEq for DispatchGuard {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for DispatchGuard {}
impl DispatchGuard {
    /// Logical charge held by this guard, if any (including a counted zero-byte MESSAGE).
    pub fn charge(&self) -> Option<u64> {
        self.state.as_ref().map(|_| self.charge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::task::Wake;
    #[derive(Default)]
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn budget(target: u64, count: usize) -> (DispatchBudget, Arc<Counter>) {
        let mut b = DispatchBudget::new(target, count).unwrap();
        let c = Arc::new(Counter::default());
        b.attach_waker(c.clone().into()).unwrap();
        (b, c)
    }
    #[test]
    fn count_zero_holders_and_cross_thread_retirement() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<DispatchGuard>();
        send_sync::<DispatchBudget>();
        assert_eq!(DispatchGuard::default().charge(), None);
        assert!(matches!(
            DispatchBudget::new(1, 0),
            Err(DispatchError::InvalidCount)
        ));
        let (mut b, _) = budget(8, 2);
        let zero = b.try_acquire(0).unwrap();
        assert_eq!(zero.charge(), Some(0));
        assert_eq!(b.try_acquire(9), Err(DispatchError::NoCredit));
        let full = b.try_acquire(8).unwrap();
        assert_eq!(b.try_acquire(0), Err(DispatchError::NoCredit));
        // a guard retires on any thread
        std::thread::spawn(move || drop(full)).join().unwrap();
        assert_eq!(b.0.bytes.load(Ordering::Acquire), 0);
        assert_eq!(b.0.count.load(Ordering::Acquire), 1);
        drop(zero);
        let over = b.try_acquire(9).unwrap();
        assert_eq!(b.try_acquire(0), Err(DispatchError::NoCredit));
        drop(over);
        assert_eq!(b.0.count.load(Ordering::Acquire), 0);
    }
    #[test]
    fn disabled_bytes_still_checks_total_and_count() {
        let (mut b, _) = budget(0, 2);
        let max = b.try_acquire(u64::MAX).unwrap();
        assert_eq!(b.try_acquire(1), Err(DispatchError::Overflow));
        let zero = b.try_acquire(0).unwrap();
        assert_eq!(b.try_acquire(0), Err(DispatchError::NoCredit));
        drop((max, zero));
        assert_eq!(b.0.bytes.load(Ordering::Acquire), 0);
        assert_eq!(b.0.count.load(Ordering::Acquire), 0);
    }
    #[test]
    fn retirement_before_after_registration_and_before_waker_attachment() {
        let (mut b, c) = budget(1, 1);
        let p = b.try_acquire(1).unwrap();
        let observed = b.generation();
        drop(p);
        assert_eq!(b.arm(observed), Ok(true));
        let p = b.try_acquire(1).unwrap();
        assert_eq!(b.arm(b.generation()), Ok(false));
        drop(p);
        assert_eq!(c.0.load(Ordering::Relaxed), 1);
        let mut early = DispatchBudget::new(1, 1).unwrap();
        let p = early.try_acquire(1).unwrap();
        assert_eq!(early.arm(early.generation()), Ok(false));
        drop(p);
        let c = Arc::new(Counter::default());
        early.attach_waker(c.clone().into()).unwrap();
        assert_eq!(c.0.load(Ordering::Relaxed), 1);
        assert!(early.attach_waker(c.clone().into()).is_err());
    }
    #[test]
    fn failed_admission_does_not_wake_itself_or_prevent_sleep() {
        let (mut b, c) = budget(8, 4);
        let full = b.try_acquire(8).unwrap();
        for _ in 0..100 {
            let observed = b.generation();
            assert_eq!(b.try_acquire(1), Err(DispatchError::NoCredit));
            assert_eq!(b.generation(), observed);
            assert_eq!(b.arm(observed), Ok(false));
            assert_eq!(c.0.load(Ordering::Relaxed), 0);
        }
        std::thread::spawn(move || drop(full)).join().unwrap();
        assert_eq!(c.0.load(Ordering::Relaxed), 1);
        assert!(b.try_acquire(1).is_ok());
    }
    #[test]
    fn concurrent_retirement_and_registration_cannot_lose_progress() {
        for _ in 0..100 {
            let (mut b, c) = budget(8, 4);
            let p = b.try_acquire(8).unwrap();
            let observed = b.generation();
            let barrier = Arc::new(Barrier::new(2));
            let remote = barrier.clone();
            let t = std::thread::spawn(move || {
                remote.wait();
                drop(p);
            });
            barrier.wait();
            let retry = b.arm(observed).unwrap();
            t.join().unwrap();
            assert!(retry || c.0.load(Ordering::Relaxed) > 0);
            let p = b.try_acquire(9).unwrap();
            assert_eq!(b.try_acquire(0), Err(DispatchError::NoCredit));
            drop(p);
            assert_eq!(b.0.bytes.load(Ordering::Acquire), 0);
            assert_eq!(b.0.count.load(Ordering::Acquire), 0);
        }
    }
    #[test]
    fn attach_racing_retirement_replays_exactly_one_wake() {
        for _ in 0..100 {
            let mut b = DispatchBudget::new(1, 1).unwrap();
            let p = b.try_acquire(1).unwrap();
            assert_eq!(b.arm(b.generation()), Ok(false));
            let barrier = Arc::new(Barrier::new(2));
            let remote = barrier.clone();
            let t = std::thread::spawn(move || {
                remote.wait();
                drop(p);
            });
            let c = Arc::new(Counter::default());
            barrier.wait();
            b.attach_waker(c.clone().into()).unwrap();
            t.join().unwrap();
            assert_eq!(c.0.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn admission_racing_foreign_retirement_conserves_bytes_and_count() {
        for charge in [0, 4, 8] {
            for _ in 0..32 {
                let (mut b, _) = budget(7, 3);
                let old = b.try_acquire(4).unwrap();
                let barrier = Arc::new(Barrier::new(2));
                let remote = barrier.clone();
                let t = std::thread::spawn(move || {
                    remote.wait();
                    drop(old);
                });
                barrier.wait();
                let result = b.try_acquire(charge);
                t.join().unwrap();
                let p = match result {
                    Ok(p) => p,
                    Err(DispatchError::NoCredit) => b.try_acquire(charge).unwrap(),
                    Err(other) => panic!("unexpected error {other:?}"),
                };
                assert_eq!(b.0.bytes.load(Ordering::Acquire), charge);
                assert_eq!(b.0.count.load(Ordering::Acquire), 1);
                drop(p);
                assert_eq!(b.0.bytes.load(Ordering::Acquire), 0);
                assert_eq!(b.0.count.load(Ordering::Acquire), 0);
            }
        }
    }
    #[test]
    fn generation_exhaustion_never_wraps_or_silently_sleeps() {
        let (mut b, c) = budget(8, 2);
        b.0.generation.store(u64::MAX - 1, Ordering::Release);
        let p = b.try_acquire(1).unwrap();
        assert_eq!(b.arm(u64::MAX - 1), Ok(false));
        drop(p);
        assert_eq!(b.generation(), u64::MAX);
        assert_eq!(c.0.load(Ordering::Relaxed), 1);
        assert_eq!(b.arm(u64::MAX), Err(DispatchError::GenerationExhausted));
        assert_eq!(b.try_acquire(0), Err(DispatchError::GenerationExhausted));
    }
}
