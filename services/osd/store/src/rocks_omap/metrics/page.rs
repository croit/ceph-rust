// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Constant-count page stages; the disabled path must not acquire clocks.
use super::{Profile, nanos, thread_cpu_ns};
use std::time::Instant;

pub(in crate::rocks_omap) struct PageTimer<'a> {
    profile: &'a Profile,
    phase: usize,
    wall_at: Instant,
    cpu_at: Option<u64>,
    wall: [u64; 4],
    cpu: [u64; 4],
    cpu_valid: bool,
}

impl<'a> PageTimer<'a> {
    pub fn start(profile: &'a Profile) -> Option<Self> {
        Self::start_with(profile, || (Instant::now(), thread_cpu_ns()))
    }

    fn start_with(
        profile: &'a Profile,
        clock: impl FnOnce() -> (Instant, Option<u64>),
    ) -> Option<Self> {
        if !profile.enabled {
            return None;
        }
        let (wall_at, cpu_at) = clock();
        Some(Self {
            profile,
            phase: 0,
            wall_at,
            cpu_at,
            wall: [0; 4],
            cpu: [0; 4],
            cpu_valid: cpu_at.is_some(),
        })
    }

    pub fn mark(&mut self, next_phase: usize) {
        self.mark_at(next_phase, Instant::now(), thread_cpu_ns());
    }

    fn mark_at(&mut self, next_phase: usize, wall: Instant, cpu: Option<u64>) {
        self.wall[self.phase] =
            self.wall[self.phase].saturating_add(nanos(wall.duration_since(self.wall_at)));
        match (self.cpu_at, cpu) {
            (Some(a), Some(b)) if a <= b => {
                self.cpu[self.phase] = self.cpu[self.phase].saturating_add(b - a)
            }
            _ => self.cpu_valid = false,
        }
        self.wall_at = wall;
        self.cpu_at = cpu;
        self.phase = next_phase;
    }

    pub fn finish(self, success: bool) {
        self.finish_at(success, Instant::now(), thread_cpu_ns());
    }

    fn finish_at(mut self, success: bool, wall: Instant, cpu: Option<u64>) {
        self.mark_at(self.phase, wall, cpu);
        self.profile
            .record_page(self.wall, self.cpu_valid.then_some(self.cpu), success);
    }
}

#[cfg(test)]
mod tests {
    use super::super::profile;
    use super::*;
    use std::time::Duration;

    #[test]
    fn disabled_page_profile_never_calls_clock_and_stages_are_exclusive() {
        let off = Profile::default();
        assert!(PageTimer::start_with(&off, || panic!("disabled clock")).is_none());
        let p = Profile::new(true);
        let at = Instant::now();
        let mut t = PageTimer::start_with(&p, || (at, Some(100))).unwrap();
        t.mark_at(1, at + Duration::from_nanos(10), Some(103));
        t.mark_at(2, at + Duration::from_nanos(30), Some(108));
        t.mark_at(3, at + Duration::from_nanos(90), Some(151));
        t.finish_at(true, at + Duration::from_nanos(100), Some(154));
        let s = p.sample();
        assert_eq!(&s[48..56], &[10, 3, 20, 5, 60, 43, 10, 3]);
        assert_eq!(&s[44..48], &[1, 0, 1, 0]);
    }

    #[test]
    fn page_refusal_records_reached_stages_but_bad_cpu_invalidates_whole_sample() {
        let p = Profile::new(true);
        let at = Instant::now();
        for bad in [None, Some(99)] {
            let mut t = PageTimer::start_with(&p, || (at, Some(100))).unwrap();
            t.mark_at(1, at + Duration::from_nanos(10), Some(110));
            // Initial-position failure skips the walk but still destroys iterator.
            t.mark_at(3, at + Duration::from_nanos(30), bad);
            t.finish_at(false, at + Duration::from_nanos(35), Some(140));
        }
        let s = p.sample();
        assert_eq!(&s[48..56], &[20, 0, 40, 0, 0, 0, 10, 0]);
        assert_eq!(&s[44..48], &[2, 2, 0, 2]);
        assert_eq!(
            s[profile::CPU_SAMPLES],
            0,
            "write and page CPU samples differ"
        );
    }
}
