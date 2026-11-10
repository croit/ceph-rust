// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Worker-observed DB diagnostics. Missing/error/stale samples are not zero debt.
//! No property query or filesystem call runs on a shard owner/admin snapshot.
use super::*;
use std::sync::LazyLock;

mod page;
pub(super) use page::PageTimer;
mod handoff;
pub(super) use handoff::{Handoff, enqueue_stamp_with};

pub(super) mod profile {
    pub const LEN: usize = 72;
    pub const ENABLED: usize = 0;
    pub const VALID: usize = 1;
    pub const ERRORS: usize = 2;
    pub const BUILD_NS: usize = 12;
    pub const WRITE_NS: usize = 13;
    pub const BUILD_CPU_NS: usize = 14;
    pub const WRITE_CPU_NS: usize = 15;
    pub const CPU_SAMPLES: usize = 16;
    pub const CPU_ERRORS: usize = 17;
    pub const QUEUE_NS: usize = 18;
    pub const COMPLETION_NS: usize = 19;
    pub const PUBLICATION_NS: usize = 20;
    pub const BACKPRESSURE_NS: usize = 21;
    pub const BACKPRESSURE_INTERVALS: usize = 22;
    pub const POINTS: usize = 23;
    pub const RANGES: usize = 24;
    pub const BATCH_BYTES: usize = 25;
    pub const AGE_NS: usize = 26;
    pub const FREEZES: usize = 27;
    pub const FREEZE_BYTES: usize = 28;
    pub const FREEZE_UNDURABLE: usize = 29;
    pub const FREEZE_ENQUEUES: usize = 30;
    pub const FREEZE_WAIT_NS: usize = 31;
    pub const FREEZE_TRACK_ERRORS: usize = 32;
    pub const FREEZE_BUCKETS: usize = 33;
    pub const BATCH_BUCKETS: usize = 38;
    pub const BATCH_FAILURES: usize = 43;
    pub const PAGE_ATTEMPTS: usize = 44;
    pub const PAGE_FAILURES: usize = 45;
    pub const PAGE_CPU_SAMPLES: usize = 46;
    pub const PAGE_CPU_ERRORS: usize = 47;
    // Four (elapsed, CPU) pairs: setup, positioning, walk/output, iterator drop.
    pub const PAGE_STAGES: usize = 48;
    pub const HANDOFF_ACCEPTED: usize = 56;
    pub const HANDOFF_DEQUEUED: usize = 57;
    pub const HANDOFF_READY: usize = 58;
    pub const HANDOFF_PUBLISHED: usize = 59;
    pub const HANDOFF_CONSUMED: usize = 60;
    pub const HANDOFF_SUCCESS: usize = 61;
    pub const HANDOFF_REFUSED: usize = 62;
    pub const HANDOFF_FAILED: usize = 63;
    pub const HANDOFF_SAMPLES: usize = 64;
    pub const HANDOFF_ERRORS: usize = 65;
    pub const HANDOFF_FULL_RETRIES: usize = 66;
    // A→B, B→C, C→D, D→E, A→E; not additive with existing worker stages.
    pub const HANDOFF_REQUEST_NS: usize = 67;
}

/// Opt-in worker profiling. Property/ticker reads stay on the existing cold
/// diagnostic cadence. Lifetime work counters are independently sampled totals.
#[derive(Debug)]
pub(super) struct Profile {
    pub enabled: bool,
    sequence: AtomicU64,
    at: AtomicU64,
    values: [AtomicU64; profile::LEN],
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            enabled: false,
            sequence: AtomicU64::new(0),
            at: AtomicU64::new(0),
            values: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl Profile {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Self::default()
        }
    }

    pub fn add(&self, index: usize, value: u64) {
        if self.enabled {
            self.values[index].fetch_add(value, Ordering::Relaxed);
        }
    }

    pub fn elapsed(&self, index: usize, start: Instant) {
        self.add(index, nanos(start.elapsed()));
    }

    pub fn record_cpu(&self, start: Option<u64>, built: Option<u64>, end: Option<u64>) {
        match (start, built, end) {
            (Some(a), Some(b), Some(c)) if a <= b && b <= c => {
                self.add(profile::BUILD_CPU_NS, b - a);
                self.add(profile::WRITE_CPU_NS, c - b);
                self.add(profile::CPU_SAMPLES, 1);
            }
            _ => self.add(profile::CPU_ERRORS, 1),
        }
    }

    pub fn record_freeze(&self, bytes: u64, undurable: bool) {
        self.add(profile::FREEZES, 1);
        self.add(profile::FREEZE_BYTES, bytes);
        self.add(profile::FREEZE_UNDURABLE, u64::from(undurable));
        self.add(profile::FREEZE_BUCKETS + size_bucket(bytes), 1);
    }

    pub fn record_batch(&self, bytes: u64, failed: bool) {
        self.add(profile::BATCH_BUCKETS + size_bucket(bytes), 1);
        self.add(profile::BATCH_FAILURES, u64::from(failed));
    }

    fn record_page(&self, wall: [u64; 4], cpu: Option<[u64; 4]>, success: bool) {
        self.add(profile::PAGE_ATTEMPTS, 1);
        self.add(profile::PAGE_FAILURES, u64::from(!success));
        self.add(
            if cpu.is_some() {
                profile::PAGE_CPU_SAMPLES
            } else {
                profile::PAGE_CPU_ERRORS
            },
            1,
        );
        for (i, elapsed) in wall.into_iter().enumerate() {
            self.add(profile::PAGE_STAGES + 2 * i, elapsed);
            if let Some(cpu) = cpu {
                self.add(profile::PAGE_STAGES + 2 * i + 1, cpu[i]);
            }
        }
    }

    fn observe(&self, db: &Database) {
        if !self.enabled {
            return;
        }
        use rocksdb_lib::statistics::Ticker;
        let properties = [
            "rocksdb.num-files-at-level0",
            "rocksdb.num-immutable-mem-table",
            "rocksdb.actual-delayed-write-rate",
        ]
        .map(|name| {
            db.db
                .property_value(name)
                .ok()
                .flatten()?
                .trim()
                .parse::<u64>()
                .ok()
        });
        let tickers = db.statistics.as_ref().map(|s| {
            [
                Ticker::StallMicros,
                Ticker::WalFileSynced,
                Ticker::WalFileBytes,
                Ticker::CompactReadBytes,
                Ticker::CompactWriteBytes,
                Ticker::FlushWriteBytes,
            ]
            .map(|t| s.0.get_ticker_count(t))
        });
        self.observe_values(properties, tickers);
    }

    fn observe_values(&self, properties: [Option<u64>; 3], tickers: Option<[u64; 6]>) {
        let valid = properties.iter().all(Option::is_some) && tickers.is_some();
        self.sequence.fetch_add(1, Ordering::SeqCst);
        for (dst, value) in self.values[3..6].iter().zip(properties) {
            dst.store(value.unwrap_or(0), Ordering::SeqCst);
        }
        for (dst, value) in self.values[6..12].iter().zip(tickers.unwrap_or_default()) {
            dst.store(value, Ordering::SeqCst);
        }
        if !valid {
            self.values[profile::ERRORS].fetch_add(1, Ordering::SeqCst);
        }
        self.values[profile::VALID].store(u64::from(valid), Ordering::SeqCst);
        self.at.store(now_ns(), Ordering::SeqCst);
        self.sequence.fetch_add(1, Ordering::SeqCst);
    }

    pub fn sample(&self) -> [u64; profile::LEN] {
        if !self.enabled {
            return [0; profile::LEN];
        }
        let first = self.sequence.load(Ordering::SeqCst);
        let mut out = self.values.each_ref().map(|v| v.load(Ordering::SeqCst));
        let at = self.at.load(Ordering::SeqCst);
        out[profile::ENABLED] = 1;
        out[profile::AGE_NS] = if at == 0 {
            u64::MAX
        } else {
            now_ns().saturating_sub(at)
        };
        if at == 0 || first & 1 != 0 || first != self.sequence.load(Ordering::SeqCst) {
            out[profile::VALID] = 0;
        }
        out
    }
}

/// Disjoint, inclusive upper bounds; these are counts, not cumulative buckets.
fn size_bucket(bytes: u64) -> usize {
    [4096, 65536, 1048576, 8388608]
        .into_iter()
        .position(|end| bytes <= end)
        .unwrap_or(4)
}

pub(super) fn nanos(d: Duration) -> u64 {
    d.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// A failed/unsupported clock is counted, never presented as a valid zero CPU
/// duration. Only the DB worker calls this, at constant-count profile boundaries.
pub(super) fn thread_cpu_ns() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid initialized output; this clock observes the calling thread.
        if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) } == 0 {
            let seconds = u64::try_from(ts.tv_sec).ok()?;
            let nanos = u64::try_from(ts.tv_nsec).ok()?;
            return (nanos < 1_000_000_000)
                .then(|| seconds.saturating_mul(1_000_000_000).saturating_add(nanos));
        }
    }
    None
}

const PROPERTIES: [&str; 9] = [
    "rocksdb.mem-table-flush-pending",
    "rocksdb.compaction-pending",
    "rocksdb.num-running-flushes",
    "rocksdb.num-running-compactions",
    "rocksdb.estimate-pending-compaction-bytes",
    "rocksdb.is-write-stopped",
    "rocksdb.cur-size-all-mem-tables",
    "rocksdb.block-cache-usage",
    "rocksdb.total-sst-files-size",
];

fn now_ns() -> u64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_nanos().min(u128::from(u64::MAX - 1)) as u64 + 1
}

#[derive(Debug, Default)]
pub(super) struct Metrics {
    pub profile: Profile,
    sequence: AtomicU64,
    at: AtomicU64,
    valid: AtomicBool,
    values: [AtomicU64; 9],
    errors: AtomicU64,
    /// Worker attempts and elapsed nanoseconds: materialize, points, page,
    /// diagnostics (properties plus allocated-file enumeration), then charged
    /// native memtable bytes materialized and configured block-cache capacity.
    /// Final four counters: owner query attempts, successful read enqueues,
    /// pending-work query misses, consumed worker completion messages.
    work: [AtomicU64; 14],
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Sample {
    pub valid: bool,
    pub age_ns: u64,
    pub values: [u64; 9],
    pub errors: u64,
    pub work: [u64; 14],
}

impl Default for Sample {
    fn default() -> Self {
        Self {
            valid: false,
            age_ns: u64::MAX,
            values: [0; 9],
            errors: 0,
            work: [0; 14],
        }
    }
}

impl Metrics {
    pub fn new_profiled(enabled: bool) -> Self {
        Self {
            profile: Profile::new(enabled),
            ..Self::default()
        }
    }
    pub fn event(&self, index: usize) {
        self.work[index].fetch_add(1, Ordering::Relaxed);
    }
    pub fn record(&self, kind: usize, started: Instant) {
        self.work[2 * kind].fetch_add(1, Ordering::Relaxed);
        self.work[2 * kind + 1].fetch_add(
            started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }

    pub fn materialized_bytes(&self, bytes: usize) {
        self.work[8].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn cache_capacity(&self, bytes: usize) {
        self.work[9].store(bytes as u64, Ordering::Relaxed);
    }

    pub fn observe(&self, db: &Database) {
        self.observe_properties(|name| db.db.property_int_value(name).ok().flatten());
        self.profile.observe(db);
    }

    fn observe_properties(&self, mut read: impl FnMut(&str) -> Option<u64>) {
        let mut values = [0; 9];
        let valid = PROPERTIES
            .iter()
            .zip(&mut values)
            .all(|(name, value)| match read(name) {
                Some(n) => {
                    *value = n;
                    true
                }
                None => false,
            });
        // Cold (4Hz) diagnostics: a single total order prevents mixed generations
        // without spinning, locks, or a DB call on the snapshot reader.
        self.sequence.fetch_add(1, Ordering::SeqCst);
        if !valid {
            self.errors.fetch_add(1, Ordering::SeqCst);
        }
        for (dst, src) in self.values.iter().zip(values) {
            dst.store(src, Ordering::SeqCst);
        }
        self.valid.store(valid, Ordering::SeqCst);
        self.at.store(now_ns(), Ordering::SeqCst);
        self.sequence.fetch_add(1, Ordering::SeqCst);
    }

    pub fn sample(&self) -> Sample {
        let first = self.sequence.load(Ordering::SeqCst);
        if first & 1 != 0 {
            return self.invalid_sample();
        }
        let at = self.at.load(Ordering::SeqCst);
        let sample = Sample {
            valid: at != 0 && self.valid.load(Ordering::SeqCst),
            age_ns: if at == 0 {
                u64::MAX
            } else {
                now_ns().saturating_sub(at)
            },
            values: self.values.each_ref().map(|n| n.load(Ordering::SeqCst)),
            errors: self.errors.load(Ordering::SeqCst),
            work: self.work.each_ref().map(|n| n.load(Ordering::Relaxed)),
        };
        if self.sequence.load(Ordering::SeqCst) != first {
            self.invalid_sample()
        } else {
            sample
        }
    }

    fn invalid_sample(&self) -> Sample {
        Sample {
            errors: self.errors.load(Ordering::SeqCst),
            work: self.work.each_ref().map(|n| n.load(Ordering::Relaxed)),
            ..Sample::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn size_buckets_have_fixed_inclusive_bounds_and_count_failures_separately() {
        let p = Profile::new(true);
        for (bytes, expected) in [
            (0, 0),
            (4096, 0),
            (4097, 1),
            (65536, 1),
            (65537, 2),
            (1048576, 2),
            (1048577, 3),
            (8388608, 3),
            (8388609, 4),
            (u64::MAX, 4),
        ] {
            assert_eq!(size_bucket(bytes), expected);
            p.record_batch(bytes, expected == 4);
        }
        p.record_freeze(4096, true);
        p.record_freeze(1048577, false);
        let s = p.sample();
        assert_eq!(&s[38..43], &[2; 5]);
        assert_eq!(s[43], 2);
        assert_eq!(&s[27..30], &[2, 1052673, 1]);
        assert_eq!(&s[33..38], &[1, 0, 0, 1, 0]);
        let off = Profile::default();
        off.record_batch(u64::MAX, true);
        off.record_freeze(4096, true);
        off.record_page([9; 4], Some([8; 4]), false);
        assert_eq!(off.sample(), [0; profile::LEN]);
    }
    #[test]
    fn profiling_defaults_off_and_clock_failures_are_not_successful_zero_samples() {
        let off = Profile::default();
        off.add(profile::BUILD_NS, 7);
        off.record_cpu(Some(1), Some(2), Some(3));
        assert_eq!(off.sample(), [0; profile::LEN]);

        let on = Profile::new(true);
        on.record_cpu(Some(10), Some(17), Some(23));
        on.record_cpu(None, Some(20), Some(30));
        on.record_cpu(Some(40), Some(39), Some(50));
        let s = on.sample();
        assert_eq!(s[profile::BUILD_CPU_NS], 7);
        assert_eq!(s[profile::WRITE_CPU_NS], 6);
        assert_eq!(s[profile::CPU_SAMPLES], 1);
        assert_eq!(s[profile::CPU_ERRORS], 2);
        assert_eq!(s[profile::VALID], 0);
        assert_eq!(s[profile::AGE_NS], u64::MAX);
    }

    #[test]
    fn profile_properties_missing_and_in_progress_never_report_valid_zero_debt() {
        let p = Profile::new(true);
        p.observe_values([Some(3), Some(4), Some(5)], Some([6, 7, 8, 9, 10, 11]));
        let s = p.sample();
        assert_eq!(s[profile::VALID], 1);
        assert_eq!(&s[3..12], &[3, 4, 5, 6, 7, 8, 9, 10, 11]);
        p.observe_values([Some(0), None, Some(0)], Some([0; 6]));
        assert_eq!(p.sample()[profile::VALID], 0);
        assert_eq!(p.sample()[profile::ERRORS], 1);
        p.observe_values([Some(0); 3], None);
        assert_eq!(p.sample()[profile::VALID], 0);
        p.observe_values([Some(0); 3], Some([0; 6]));
        assert_eq!(p.sample()[profile::VALID], 1);
        assert_eq!(p.sample()[profile::ERRORS], 2);
        p.sequence.fetch_add(1, Ordering::SeqCst);
        assert_eq!(p.sample()[profile::VALID], 0);
    }
    #[test]
    fn missing_and_in_progress_samples_are_explicitly_invalid() {
        let metrics = Metrics::default();
        assert!(!metrics.sample().valid);
        assert_eq!(metrics.sample().age_ns, u64::MAX);
        metrics.sequence.store(1, Ordering::Release);
        assert!(!metrics.sample().valid);
    }

    #[test]
    fn missing_property_invalidates_the_whole_sample_and_next_success_recovers() {
        let metrics = Metrics::default();
        metrics.observe_properties(|_| Some(17));
        assert!(metrics.sample().valid);
        assert_eq!(metrics.sample().values, [17; 9]);
        metrics.observe_properties(|name| (name != PROPERTIES[4]).then_some(0));
        assert!(!metrics.sample().valid);
        assert_eq!(metrics.sample().errors, 1);
        metrics.observe_properties(|_| Some(0));
        assert!(metrics.sample().valid);
        assert_eq!(metrics.sample().errors, 1);
        assert!(metrics.sample().age_ns < u64::MAX);
        metrics.sequence.fetch_add(1, Ordering::SeqCst);
        assert!(!metrics.sample().valid);
        assert_eq!(
            metrics.sample().errors,
            1,
            "contention must not reset a lifetime counter"
        );
    }
}
