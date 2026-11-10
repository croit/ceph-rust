// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
//! Coarse foreign-worker attribution, not per-key tracing or a drain certificate.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub(super) const APPLY: usize = 0;
pub(super) const DATA_BARRIER: usize = 1;
pub(super) const WATERMARK: usize = 2;
pub(super) const WATERMARK_BARRIER: usize = 3;
pub(super) const POINT_READ: usize = 4;
pub(super) const SCAN: usize = 5;
pub(super) const SAMPLE: usize = 6;
const STAGES: usize = 7;
pub(crate) const FIELDS: usize = STAGES * 4 + 7;

// Counters sum across shards; maxima take max. Perf export is a best-effort
// snapshot: concurrent increments of separate fields are not an atomic record.
pub(crate) const NAMES: [(&str, bool); FIELDS] = [
    ("splinter_apply_count", false),
    ("splinter_apply_wall_ns", false),
    ("splinter_apply_cpu_ns", false),
    ("splinter_apply_wall_ns_max", true),
    ("splinter_data_barrier_count", false),
    ("splinter_data_barrier_wall_ns", false),
    ("splinter_data_barrier_cpu_ns", false),
    ("splinter_data_barrier_wall_ns_max", true),
    ("splinter_watermark_count", false),
    ("splinter_watermark_wall_ns", false),
    ("splinter_watermark_cpu_ns", false),
    ("splinter_watermark_wall_ns_max", true),
    ("splinter_watermark_barrier_count", false),
    ("splinter_watermark_barrier_wall_ns", false),
    ("splinter_watermark_barrier_cpu_ns", false),
    ("splinter_watermark_barrier_wall_ns_max", true),
    ("splinter_point_read_count", false),
    ("splinter_point_read_wall_ns", false),
    ("splinter_point_read_cpu_ns", false),
    ("splinter_point_read_wall_ns_max", true),
    ("splinter_scan_count", false),
    ("splinter_scan_wall_ns", false),
    ("splinter_scan_cpu_ns", false),
    ("splinter_scan_wall_ns_max", true),
    ("splinter_sample_count", false),
    ("splinter_sample_wall_ns", false),
    ("splinter_sample_cpu_ns", false),
    ("splinter_sample_wall_ns_max", true),
    ("splinter_flush_queue_count", false),
    ("splinter_flush_queue_ns", false),
    ("splinter_flush_queue_ns_max", true),
    ("splinter_read_queue_count", false),
    ("splinter_read_queue_ns", false),
    ("splinter_read_queue_ns_max", true),
    ("splinter_timing_cpu_clock_errors", false),
];

#[derive(Debug)]
pub(super) struct Timings {
    values: [AtomicU64; FIELDS],
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            values: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

fn nanos(d: std::time::Duration) -> u64 {
    d.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn cpu_ns() -> Option<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: initialized writable timespec, thread-local CPU clock, no retained pointer.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) } != 0 {
        return None;
    }
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(t.tv_nsec).ok()?)
}

impl Timings {
    pub(super) fn start(&self, stage: usize) -> Timer<'_> {
        Timer {
            timings: self,
            stage,
            wall: Instant::now(),
            cpu: cpu_ns(),
        }
    }

    fn add(&self, i: usize, value: u64) {
        // Each counter has one writer (the file worker). Snapshots only read.
        let old = self.values[i].load(Ordering::Relaxed);
        self.values[i].store(old.saturating_add(value), Ordering::Relaxed);
    }

    fn record(&self, stage: usize, wall: u64, cpu: Option<u64>) {
        let i = stage * 4;
        self.add(i, 1);
        self.add(i + 1, wall);
        if let Some(cpu) = cpu {
            self.add(i + 2, cpu);
        } else {
            self.add(FIELDS - 1, 1);
        }
        self.values[i + 3].fetch_max(wall, Ordering::Relaxed);
    }

    pub(super) fn dequeued(&self, read: bool, enqueued: Instant) {
        let i = STAGES * 4 + usize::from(read) * 3;
        let wall = nanos(enqueued.elapsed());
        self.add(i, 1);
        self.add(i + 1, wall);
        self.values[i + 2].fetch_max(wall, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> [u64; FIELDS] {
        std::array::from_fn(|i| self.values[i].load(Ordering::Relaxed))
    }
}

pub(super) struct Timer<'a> {
    timings: &'a Timings,
    stage: usize,
    wall: Instant,
    cpu: Option<u64>,
}

impl Drop for Timer<'_> {
    fn drop(&mut self) {
        let cpu = cpu_ns()
            .zip(self.cpu)
            .and_then(|(end, start)| end.checked_sub(start));
        self.timings
            .record(self.stage, nanos(self.wall.elapsed()), cpu);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_stage_totals_maxima_and_missing_cpu_are_not_zero_success() {
        let t = Timings::default();
        t.record(APPLY, 40, Some(25));
        t.record(APPLY, 20, Some(10));
        t.record(DATA_BARRIER, 90, None);
        let s = t.snapshot();
        assert_eq!(&s[..8], &[2, 60, 35, 40, 1, 90, 0, 90]);
        assert_eq!(s[FIELDS - 1], 1);
        assert_eq!(s[8..FIELDS - 1], [0; FIELDS - 9]);
    }

    #[test]
    fn returning_an_error_still_records_the_attempted_stage() {
        let t = Timings::default();
        let fail = || -> Result<(), ()> {
            let _span = t.start(WATERMARK_BARRIER);
            Err(())
        };
        assert!(fail().is_err());
        assert_eq!(t.snapshot()[WATERMARK_BARRIER * 4], 1);
        assert_eq!(t.snapshot()[APPLY * 4], 0);
    }

    #[test]
    fn read_and_flush_queue_counts_are_independent_of_service_stages() {
        let t = Timings::default();
        let queued = Instant::now() - std::time::Duration::from_millis(1);
        t.dequeued(false, queued);
        t.dequeued(true, queued);
        t.dequeued(true, queued);
        let s = t.snapshot();
        assert_eq!(s[..STAGES * 4], [0; STAGES * 4]);
        assert_eq!(s[STAGES * 4], 1);
        assert_eq!(s[STAGES * 4 + 3], 2);
        assert!(s[STAGES * 4 + 1] >= 1_000_000);
        assert_eq!(s[STAGES * 4 + 1], s[STAGES * 4 + 2]);
        assert!(s[STAGES * 4 + 4] >= s[STAGES * 4 + 5]);
        assert_eq!(s[FIELDS - 1], 0);
    }
}
