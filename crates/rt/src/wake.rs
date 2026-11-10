// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Wake-up of a core that sleeps in its io_uring (kernel tier idle mode): mesh senders poke an eventfd the sleeper has an
//! io_uring read on, so a cross-core message does not wait for the idle cap. The flag keeps the cost off the busy path:
//! a syscall only when the target announced it is going to sleep.
//!
//! No lost wake (Dekker): the sleeper stores `sleeping`, fences, then re-checks its inbox before it blocks
//! ([`KNet::wait_if`](crate::knet::KNet::wait_if)); a sender publishes the message, fences, then loads `sleeping`. Either
//! the sleeper sees the message or the sender sees the flag; the eventfd counter keeps a poke that arrives before the
//! sleeper is inside the kernel.
//!
//! One write per sleep: the sender that finds the flag set also clears it (`swap`) and only that sender writes; later
//! senders see the flag clear and skip the syscall. No lost wake: let sender B be one that skipped. B published its
//! message M (a), fenced, then loaded the flag and read `false` (b). The first sender A swapped the flag to `false` and
//! then wrote, so the sleeper S is woken (the eventfd counter holds the poke until S reads it) and runs again. S can only
//! block again through `set_sleeping(true)` (c), fence, inbox re-check (d). B read `false`, so (b) precedes (c) in the
//! single order of the SeqCst fences and flag accesses; with (a) before (b) and (c) before (d), (a) precedes (d): the
//! re-check sees M, or S's next sleep finds the flag set by B's successors. If instead S stored `true` first, B reads
//! `true` and takes the swap path itself. A stale sender (it loaded `true` in an earlier sleep) may clear the flag of a
//! later sleep: its write follows its swap and ends that sleep, so the argument above applies to it unchanged.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};

/// One core's wake handle (shared between the sleeper and every sender).
#[derive(Debug)]
pub struct Wake {
    fd: OwnedFd,
    sleeping: AtomicBool,
    /// CLOCK_MONOTONIC ns of the first poke of the current sleep (0 = none): the sleeper measures its wake latency.
    poked: AtomicU64,
    /// eventfd writes issued to this core (a syscall each; the sleeper reports the delta, see [`Wake::writes`]).
    writes: AtomicU64,
}

impl Wake {
    /// New handle with its eventfd (blocking: io_uring polls it; a write never blocks below a counter of 2^64-2).
    pub fn new() -> io::Result<Arc<Wake>> {
        // SAFETY: eventfd(2) returns a fresh fd or -1.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Arc::new(Wake {
            // SAFETY: valid fresh fd, owned from here.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            sleeping: AtomicBool::new(false),
            poked: AtomicU64::new(0),
            writes: AtomicU64::new(0),
        }))
    }

    /// Raw fd (the sleeper reads it).
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The owner announces it is about to sleep (then re-checks its inbox) / is awake.
    pub fn set_sleeping(&self, on: bool) {
        self.sleeping.store(on, Ordering::Relaxed);
        if on {
            fence(Ordering::SeqCst);
        }
    }

    /// The owner after a sleep: ns from the first poke to now (the wake latency it paid), `None` = no poke ended it.
    pub fn take_poke(&self) -> Option<u64> {
        let p = self.poked.swap(0, Ordering::Relaxed);
        (p != 0).then(|| mono_ns().saturating_sub(p))
    }

    /// Cumulative eventfd writes (= wake syscalls) senders issued to this core.
    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    /// Wake the owner if it sleeps (call after the message is published).
    #[inline]
    pub fn poke(&self) {
        fence(Ordering::SeqCst);
        if self.sleeping.load(Ordering::Relaxed) && self.sleeping.swap(false, Ordering::Relaxed) {
            let _ = self
                .poked
                .compare_exchange(0, mono_ns(), Ordering::Relaxed, Ordering::Relaxed);
            self.writes.fetch_add(1, Ordering::Relaxed);
            let one = 1u64;
            // SAFETY: writing 8 bytes to an eventfd we own.
            unsafe { libc::write(self.fd.as_raw_fd(), (&raw const one).cast(), 8) };
        }
    }
}

impl Wake {
    /// End the owner's current sleep, or its next one if it is awake (the eventfd counter keeps the write): for a release
    /// the owner's sleep re-check does not see, such as the stop flag. Async-signal-safe (one `write`, no clock, no
    /// allocation, no atomics): callable from a signal handler.
    pub fn ring(&self) {
        let one = 1u64;
        // SAFETY: writing 8 bytes to an eventfd we own.
        unsafe { libc::write(self.fd.as_raw_fd(), (&raw const one).cast(), 8) };
    }
}

/// A core that holds input for lack of ingress space is woken by the core that frees it.
impl ingress::Waker for Wake {
    fn wake(&self) {
        self.poke();
    }
}

/// Monotonic ns on one process-wide timeline (every core: the poker stamps, the sleeper reads); `fastclock` (rdtsc with
/// an invariant TSC), never 0 (0 = no poke). A wake-latency measurement: read only on a poke of a sleeper and on its wake.
fn mono_ns() -> u64 {
    static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    (crate::fastclock::since(*BASE.get_or_init(std::time::Instant::now)).as_nanos() as u64).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readable(w: &Wake) -> bool {
        let mut p = libc::pollfd {
            fd: w.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd, no wait.
        unsafe { libc::poll(&raw mut p, 1, 0) == 1 }
    }

    #[test]
    fn poke_only_when_sleeping() {
        let w = Wake::new().unwrap();
        w.poke();
        assert!(!readable(&w), "awake owner: no syscall, nothing to read");
        w.set_sleeping(true);
        w.poke();
        assert!(readable(&w));
        let mut v = 0u64;
        // SAFETY: reading 8 bytes from our (readable) eventfd into a u64.
        assert_eq!(unsafe { libc::read(w.raw_fd(), (&raw mut v).cast(), 8) }, 8);
        assert!(!readable(&w), "read resets the counter");
        w.set_sleeping(false);
    }

    /// A ring before the sleep ends that sleep at once (sleep inventory row 6: the stop flag).
    #[test]
    fn a_ring_ends_the_next_sleep() {
        let w = Wake::new().unwrap();
        w.ring();
        assert!(
            readable(&w),
            "the counter keeps the ring for the next sleep"
        );
        let mut v = 0u64;
        // SAFETY: reading 8 bytes from our (readable) eventfd into a u64.
        assert_eq!(unsafe { libc::read(w.raw_fd(), (&raw mut v).cast(), 8) }, 8);
        assert_eq!(v, 1);
    }

    #[test]
    fn one_write_per_sleep() {
        let w = Wake::new().unwrap();
        w.set_sleeping(true);
        w.poke();
        w.poke();
        w.poke();
        assert_eq!(w.writes(), 1, "later senders see the cleared flag");
        let mut v = 0u64;
        // SAFETY: reading 8 bytes from our eventfd into a u64.
        assert_eq!(unsafe { libc::read(w.raw_fd(), (&raw mut v).cast(), 8) }, 8);
        assert_eq!(v, 1);
        w.set_sleeping(true); // the next sleep is woken again
        w.poke();
        assert_eq!(w.writes(), 2);
    }

    /// Stress of the protocol in the module comment: pokers publish into an inbox and poke; the sleeper drains,
    /// announces, re-checks, blocks on the eventfd. A lost wake blocks it past the (loud) limit.
    #[test]
    fn no_lost_wake_under_stress() {
        const PER: u64 = 100_000;
        const SENDERS: u64 = 3;
        const LIMIT_MS: i32 = 10_000;
        let w = Wake::new().unwrap();
        let inbox = Arc::new(AtomicU64::new(0));
        let senders: Vec<_> = (0..SENDERS)
            .map(|_| {
                let (w, inbox) = (w.clone(), inbox.clone());
                std::thread::spawn(move || {
                    for i in 0..PER {
                        inbox.fetch_add(1, Ordering::Release); // publish
                        w.poke();
                        if i % 64 == 0 {
                            std::thread::yield_now();
                        }
                    }
                })
            })
            .collect();
        let mut got = 0u64;
        let mut announces = 0u64;
        while got < PER * SENDERS {
            got += inbox.swap(0, Ordering::Acquire);
            if got >= PER * SENDERS {
                break;
            }
            w.set_sleeping(true);
            announces += 1;
            if inbox.load(Ordering::Acquire) != 0 {
                w.set_sleeping(false);
                continue;
            }
            let mut p = libc::pollfd {
                fd: w.raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            let r = unsafe { libc::poll(&raw mut p, 1, LIMIT_MS) };
            w.set_sleeping(false);
            if r == 0 {
                eprintln!(
                    "WARNING TIMEOUT wake stress sleeper exceeded {}s (lost wake)",
                    LIMIT_MS / 1000
                );
                panic!(
                    "lost wake: sleeper blocked with {got} of {} messages",
                    PER * SENDERS
                );
            }
            let mut v = 0u64;
            // SAFETY: reading 8 bytes from our eventfd.
            unsafe { libc::read(w.raw_fd(), (&raw mut v).cast(), 8) };
        }
        for s in senders {
            s.join().unwrap();
        }
        assert!(
            w.writes() <= announces,
            "one write per announcement at most ({} writes, {announces} announcements)",
            w.writes()
        );
    }

    #[test]
    fn take_poke_measures_only_a_poke_of_a_sleeper() {
        let w = Wake::new().unwrap();
        w.poke();
        assert_eq!(w.take_poke(), None, "awake owner: no stamp");
        w.set_sleeping(true);
        w.poke();
        std::thread::sleep(std::time::Duration::from_millis(2));
        w.poke(); // a second poke keeps the first stamp
        let ns = w.take_poke().expect("poked while sleeping");
        assert!(ns >= 2_000_000, "from the first poke: {ns}");
        assert_eq!(w.take_poke(), None, "taken once");
        w.set_sleeping(false);
    }
}
