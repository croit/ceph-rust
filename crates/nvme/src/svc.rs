// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Learned device service time of a polled queue (SPDK, adr 0004 am. 1): when may an issued command complete?
//!
//! A polled device has no completion wake-up. A core that is idle while commands are in flight either spins (CPU per
//! op of the whole device time) or sleeps on a timer (latency when it oversleeps). [`SvcTimes`] learns, per command
//! class (opcode x transfer size), a low and a high bound of the service time from the completions the queue
//! observes; [`Window`] folds the in-flight commands into "the earliest may complete at" / "the latest is overdue
//! after". The core loop sleeps until the earliest bound minus its own wake latency, spins inside the window, and
//! falls back to its age-based policy once every in-flight command is past its high bound (stall, error path).
//!
//! Bounds: asymmetric moving averages of the samples, the low one moves down by 1/4 and up by 1/16 of the distance
//! (sits near the 20th percentile), the high one mirrored (near the 80th), the same estimator as the store-span latency
//! of adr 0162. A sample is the midpoint between the last poll before the completion was seen and the poll that saw
//! it: exact while the core spins, and when it overslept a completion the sample falls below the sleep end, so the
//! low bound moves down (the next sleep is shorter). Nothing here reads a clock: callers pass ns of one monotonic
//! clock.
use crate::Op;
use std::time::Duration;

/// Transfer-size buckets: 4 KiB << b for b in 0..SIZE_BUCKETS (the last one takes everything larger).
const SIZE_BUCKETS: usize = 8;
/// Opcode groups: read, write (write zeroes included), other (deallocate).
const OPS: usize = 3;

/// Command class of a submission: opcode group x transfer-size bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Class(u8);

impl Class {
    pub fn of(op: Op, bytes: u64) -> Class {
        let o = match op {
            Op::Read => 0,
            Op::Write | Op::WriteZeroes => 1,
            Op::Deallocate => 2,
        };
        let pages = (bytes >> 12).max(1);
        let b = (63 - pages.leading_zeros() as usize).min(SIZE_BUCKETS - 1);
        Class((o * SIZE_BUCKETS + b) as u8)
    }
}

/// Learned service-time bounds per class (ns; 0 = no sample yet).
#[derive(Debug, Clone, Default)]
pub struct SvcTimes {
    lo: [u64; OPS * SIZE_BUCKETS],
    hi: [u64; OPS * SIZE_BUCKETS],
}

impl SvcTimes {
    /// One completion of class `c`, issued at `issued`, not complete at the poll at `prev` (0 = none since the issue),
    /// complete at the poll at `seen`.
    pub fn learn(&mut self, c: Class, issued: u64, prev: u64, seen: u64) {
        let from = prev.max(issued);
        let s = (from / 2 + seen / 2).saturating_sub(issued);
        let i = c.0 as usize;
        let lo = self.lo[i];
        self.lo[i] = if lo == 0 {
            s
        } else if s < lo {
            lo - (lo - s) / 4
        } else {
            lo + (s - lo) / 16
        };
        let hi = self.hi[i];
        self.hi[i] = if hi == 0 {
            s
        } else if s > hi {
            hi + (s - hi) / 4
        } else {
            hi - (hi - s) / 16
        };
    }

    /// Bounds of class `c` (`None` before its first sample).
    pub fn bounds(&self, c: Class) -> Option<(u64, u64)> {
        let i = c.0 as usize;
        (self.lo[i] != 0).then(|| (self.lo[i], self.hi[i].max(self.lo[i])))
    }
}

/// The in-flight commands folded: earliest low bound, latest high bound (ns, absolute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub first: u64,
    pub last: u64,
}

impl Window {
    pub const EMPTY: Window = Window {
        first: u64::MAX,
        last: 0,
    };

    /// Add a command of class `c` issued at `issued`. A class without samples counts as due at once and overdue
    /// at once: it never lets the core sleep on a guess, and alone it leaves the decision to the caller's fallback.
    pub fn add(&mut self, t: &SvcTimes, c: Class, issued: u64) {
        let (lo, hi) = t.bounds(c).unwrap_or((0, 0));
        self.first = self.first.min(issued.saturating_add(lo));
        self.last = self.last.max(issued.saturating_add(hi));
    }

    /// Wait hint at `now`: `Some(d)` = the earliest command may complete in `d` (zero: inside the window, poll),
    /// `None` = nothing in flight or every command is past its high bound.
    pub fn hint(&self, now: u64) -> Option<Duration> {
        if self.first == u64::MAX || now >= self.last {
            return None;
        }
        Some(Duration::from_nanos(self.first.saturating_sub(now)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_split_opcode_and_size() {
        assert_eq!(Class::of(Op::Read, 4096), Class(0));
        assert_eq!(Class::of(Op::Read, 8192), Class(1));
        assert_eq!(Class::of(Op::Read, 12288), Class(1));
        assert_eq!(Class::of(Op::Write, 4096), Class(8));
        assert_eq!(Class::of(Op::WriteZeroes, 4096), Class(8));
        assert_eq!(Class::of(Op::Write, 256 << 10), Class(8 + 6));
        assert_eq!(Class::of(Op::Write, 64 << 20), Class(8 + 7));
        assert_eq!(Class::of(Op::Deallocate, 0), Class(16));
    }

    #[test]
    fn spinning_samples_converge_between_the_bounds() {
        let mut t = SvcTimes::default();
        let c = Class::of(Op::Read, 4096);
        assert_eq!(t.bounds(c), None);
        // exact samples (prev poll 1 us before the completion was seen), 60..=80 us
        for i in 0..400u64 {
            let lat = 60_000 + (i * 7919) % 20_001;
            let issued = i * 1_000_000;
            t.learn(c, issued, issued + lat - 1000, issued + lat);
        }
        let (lo, hi) = t.bounds(c).unwrap();
        assert!((60_000..70_000).contains(&lo), "lo {lo}");
        assert!((70_000..=80_000).contains(&hi), "hi {hi}");
    }

    #[test]
    fn an_overslept_completion_pulls_the_low_bound_down() {
        let mut t = SvcTimes::default();
        let c = Class::of(Op::Read, 4096);
        t.learn(c, 0, 69_000, 70_000);
        // the core slept from 1 us after the issue until 90 us: the completion is somewhere in between
        t.learn(c, 1_000_000, 1_001_000, 1_090_000);
        let (lo, _) = t.bounds(c).unwrap();
        assert!(lo < 70_000 - 5_000, "lo {lo}");
    }

    #[test]
    fn window_sleeps_until_the_earliest_and_gives_up_after_the_latest() {
        let mut t = SvcTimes::default();
        let r = Class::of(Op::Read, 4096);
        t.learn(r, 0, 59_000, 60_000);
        t.learn(r, 0, 99_000, 100_000);
        let (lo, hi) = t.bounds(r).unwrap();
        let mut w = Window::EMPTY;
        assert_eq!(w.hint(0), None);
        w.add(&t, r, 1_000_000);
        w.add(&t, r, 1_010_000);
        assert_eq!(w.first, 1_000_000 + lo);
        assert_eq!(w.last, 1_010_000 + hi);
        assert_eq!(w.hint(1_000_000), Some(Duration::from_nanos(lo)));
        assert_eq!(w.hint(1_000_000 + lo + 1), Some(Duration::ZERO));
        assert_eq!(w.hint(1_010_000 + hi), None);
        // an unlearned class: due at once, overdue at once
        let mut u = Window::EMPTY;
        u.add(&t, Class::of(Op::Deallocate, 0), 5);
        assert_eq!(u.hint(5), None);
        u.add(&t, r, 5);
        assert_eq!(u.hint(5), Some(Duration::ZERO));
    }
}
