// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Bounded retry hints for a shard FIFO head, never a residency/validation proof.

const LIMIT: usize = 4096;
const STALL_NS: u64 = 30_000_000_000;

#[derive(Debug)]
pub(crate) struct Dependencies {
    owner: Option<u64>,
    capture: bool,
    overflow: bool,
    pages: Vec<u64>,
    done: [u64; LIMIT / 64],
    left: usize,
    armed: bool,
    deadline: u64,
    final_retry_used: bool,
}

impl Default for Dependencies {
    fn default() -> Self {
        Self {
            owner: None,
            capture: false,
            overflow: false,
            pages: Vec::new(),
            done: [0; LIMIT / 64],
            left: 0,
            armed: false,
            deadline: 0,
            final_retry_used: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Readiness {
    Untracked,
    Waiting(u64),
    Retry(u64),
}

impl Dependencies {
    pub fn active(&self) -> bool {
        self.owner.is_some()
    }

    pub fn begin(&mut self, token: u64, now: u64) {
        assert!(!self.capture, "dependency capture cannot nest");
        if self.owner != Some(token) {
            self.deadline = now.saturating_add(STALL_NS);
            self.final_retry_used = false;
        }
        self.owner = Some(token);
        self.capture = true;
        self.overflow = false;
        self.armed = false;
        self.left = 0;
        self.pages.clear();
    }

    pub fn miss(&mut self, addr: u64) {
        if self.capture {
            if self.pages.len() == LIMIT {
                self.overflow = true;
            } else {
                self.pages.push(addr);
            }
        }
    }

    pub fn finish(&mut self, blocked: bool) {
        assert!(self.capture);
        self.capture = false;
        if !blocked || self.overflow || self.pages.is_empty() {
            self.owner = None;
            self.pages.clear();
            return;
        }
        self.pages.sort_unstable();
        self.pages.dedup();
        self.done.fill(0);
        self.left = self.pages.len();
        self.armed = true;
    }

    pub fn page(&mut self, addr: u64, failed: bool, now: u64) {
        // A completion during capture makes its observations ambiguous. Fall
        // back to ordinary progress retries instead of trusting a partial set.
        if self.capture {
            self.overflow = true;
            return;
        }
        if self.owner.is_none() {
            return;
        }
        if let Ok(i) = self.pages.binary_search(&addr) {
            if failed {
                self.armed = false;
            } else if self.done[i / 64] & (1 << (i % 64)) == 0 {
                self.done[i / 64] |= 1 << (i % 64);
                self.left -= 1;
                self.deadline = now.saturating_add(STALL_NS);
                self.final_retry_used = false;
            }
        }
    }

    /// A tracked page finally acquired DMA memory and was submitted: its device wait starts now.
    pub fn submitted_after_memory(&mut self, addr: u64, now: u64) {
        if self.owner.is_some() && self.pages.binary_search(&addr).is_ok() {
            self.deadline = now.saturating_add(STALL_NS);
            self.final_retry_used = false;
        }
    }

    /// `addr` is one of the pages the tracked head waits for.
    pub fn tracks(&self, addr: u64) -> bool {
        self.owner.is_some() && !self.capture && self.pages.binary_search(&addr).is_ok()
    }

    pub fn invalidate(&mut self) {
        // Unknown/stale wakes permit revalidation, not a new stall deadline.
        self.armed = false;
        if self.capture {
            self.overflow = true;
        }
    }

    pub fn readiness(&self, token: u64) -> Readiness {
        if self.owner != Some(token) {
            Readiness::Untracked
        } else if self.armed && self.left != 0 {
            Readiness::Waiting(self.deadline)
        } else {
            Readiness::Retry(self.deadline)
        }
    }

    pub fn final_retry_available(&self) -> bool {
        !self.final_retry_used
    }

    pub fn retry_started(&mut self, token: u64, now: u64) {
        if self.owner == Some(token) && now >= self.deadline {
            self.final_retry_used = true;
        }
    }

    pub fn clear(&mut self, token: u64) {
        if self.owner == Some(token) {
            self.owner = None;
            self.armed = false;
            self.pages.clear();
        }
    }

    /// Embedded tracking state plus retained address capacity, active or not.
    pub fn bytes(&self) -> u64 {
        (size_of::<Self>() + self.pages.capacity() * size_of::<u64>()) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_for_exact_members_and_ignores_duplicate_completions() {
        let mut d = Dependencies::default();
        assert!(!d.active());
        d.begin(7, 0);
        for a in [10, 20, 10, 30] {
            d.miss(a);
        }
        d.finish(true);
        d.page(99, false, 100);
        assert_eq!(d.readiness(7), Readiness::Waiting(STALL_NS));
        d.page(10, false, 200);
        d.page(10, false, 300);
        assert_eq!(d.readiness(7), Readiness::Waiting(STALL_NS + 200));
        d.page(30, false, 400);
        d.page(20, false, 500);
        assert_eq!(d.readiness(7), Readiness::Retry(STALL_NS + 500));
        assert_eq!(d.readiness(8), Readiness::Untracked);
        d.clear(8);
        assert!(d.active());
        d.clear(7);
        assert!(!d.active());
    }

    #[test]
    fn failures_and_invalidations_revalidate_without_renewing_stall() {
        let mut d = Dependencies::default();
        d.begin(1, 0);
        d.miss(10);
        d.miss(20);
        d.finish(true);
        d.page(99, true, 100);
        assert_eq!(d.readiness(1), Readiness::Waiting(STALL_NS));
        d.page(10, true, 200);
        assert_eq!(d.readiness(1), Readiness::Retry(STALL_NS));
        d.begin(1, 300);
        d.miss(20);
        d.finish(true);
        d.invalidate();
        d.begin(1, 400);
        d.miss(20);
        d.finish(true);
        assert_eq!(d.readiness(1), Readiness::Waiting(STALL_NS));
        d.page(20, false, STALL_NS + 100);
        assert_eq!(d.readiness(1), Readiness::Retry(2 * STALL_NS + 100));
    }

    #[test]
    fn bounded_capture_and_retained_memory_include_embedded_state() {
        let mut d = Dependencies::default();
        assert_eq!(d.bytes(), size_of::<Dependencies>() as u64);
        d.begin(1, 0);
        d.finish(true);
        assert_eq!(d.readiness(1), Readiness::Untracked);
        d.begin(1, 0);
        for a in 0..=LIMIT as u64 {
            d.miss(a);
        }
        d.finish(true);
        assert_eq!(d.readiness(1), Readiness::Untracked);
        let bytes = d.bytes();
        assert!(bytes <= (size_of::<Dependencies>() + LIMIT * 8) as u64);
        d.begin(2, 100);
        d.miss(10);
        d.finish(false);
        assert_eq!(d.readiness(2), Readiness::Untracked);
        assert_eq!(d.bytes(), bytes);
    }

    #[test]
    fn completion_during_capture_falls_back() {
        let mut d = Dependencies::default();
        d.begin(1, 0);
        d.miss(10);
        d.page(10, false, 1);
        d.finish(true);
        assert_eq!(d.readiness(1), Readiness::Untracked);
    }

    #[test]
    fn invalidation_keeps_real_completion_progress_after_a_pause() {
        let mut d = Dependencies::default();
        d.begin(1, 0);
        d.miss(10);
        d.miss(20);
        d.finish(true);
        d.invalidate();
        d.page(10, false, STALL_NS + 50);
        d.page(20, false, STALL_NS + 100);
        assert_eq!(d.readiness(1), Readiness::Retry(2 * STALL_NS + 100));
        d.begin(1, STALL_NS + 101);
        d.miss(30);
        d.finish(true);
        assert_eq!(d.readiness(1), Readiness::Waiting(2 * STALL_NS + 100));
    }

    #[test]
    fn stale_hints_get_one_final_attempt_not_infinite_timeout_extensions() {
        let mut d = Dependencies::default();
        d.begin(1, 0);
        d.miss(10);
        d.finish(true);
        d.invalidate();
        assert!(d.final_retry_available());
        d.retry_started(1, STALL_NS + 1);
        d.begin(1, STALL_NS + 1);
        d.miss(20);
        d.finish(true);
        d.invalidate();
        assert!(!d.final_retry_available());
        assert_eq!(d.readiness(1), Readiness::Retry(STALL_NS));
        d.page(20, false, STALL_NS + 2);
        assert!(d.final_retry_available());
    }
}
