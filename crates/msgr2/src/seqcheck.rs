// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Receive-side message sequence check (doc/spec/msgr2.md "seq"): a seq <= `in_seq` is a duplicate (dropped, the read
//! loop continues), a seq > `in_seq + 1` is a gap (accepted, `in_seq` jumps). Both are counted process-wide
//! ([`counters`], exposed by the OSD `perf dump` logger `flashstore_msgr`) and logged once per connection and kind per
//! [`LOG_INTERVAL`], with the number of incidents suppressed since the last line.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Minimum spacing of two log lines of one kind on one connection.
pub(crate) const LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Counter names by [`Seq::idx`].
const NAMES: [&str; 2] = ["seq_dup_dropped", "seq_gaps"];
static COUNT: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Process-wide `(name, value)` counters: `seq_dup_dropped` (messages dropped as already seen) and `seq_gaps`
/// (messages that arrived with a seq beyond the next expected one).
pub fn counters() -> [(&'static str, u64); 2] {
    std::array::from_fn(|i| (NAMES[i], COUNT[i].load(Ordering::Relaxed)))
}

/// Verdict of one received message seq against the session's `in_seq`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Seq {
    Next,
    /// Accepted although `in_seq + 1` was expected.
    Gap,
    Dup,
}

impl Seq {
    /// Index of an incident kind in [`NAMES`], [`COUNT`] and the limiters; `None` for a message in order.
    fn idx(self) -> Option<usize> {
        match self {
            Seq::Next => None,
            Seq::Dup => Some(0),
            Seq::Gap => Some(1),
        }
    }
}

pub(crate) fn classify(in_seq: u64, seq: u64) -> Seq {
    if seq <= in_seq {
        Seq::Dup
    } else if seq > in_seq + 1 {
        Seq::Gap
    } else {
        Seq::Next
    }
}

/// Time of the last log line of one kind and the incidents since.
#[derive(Default, Debug)]
struct Limiter {
    last: Option<Duration>,
    pending: u64,
}

/// Per-connection rate limiter of the incident log lines (one [`Limiter`] per kind).
#[derive(Default, Debug)]
pub(crate) struct SeqLog([Limiter; 2]);

impl SeqLog {
    /// Counts the incident; returns `Some(suppressed since the last line)` when a line is due at `now`.
    pub(crate) fn note(&mut self, v: Seq, now: Duration) -> Option<u64> {
        let i = v.idx()?;
        COUNT[i].fetch_add(1, Ordering::Relaxed);
        let l = &mut self.0[i];
        if l.last.is_none_or(|t| now.saturating_sub(t) >= LOG_INTERVAL) {
            l.last = Some(now);
            Some(std::mem::take(&mut l.pending))
        } else {
            l.pending += 1;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_the_spec() {
        assert_eq!(classify(5, 6), Seq::Next);
        assert_eq!(classify(5, 5), Seq::Dup);
        assert_eq!(classify(5, 1), Seq::Dup);
        assert_eq!(classify(5, 8), Seq::Gap);
        assert_eq!(classify(0, 1), Seq::Next);
    }

    #[test]
    fn one_line_per_interval_and_kind_with_suppressed_count() {
        let [(_, d0), (_, g0)] = counters();
        let mut l = SeqLog::default();
        let t = Duration::from_secs(100);
        assert_eq!(l.note(Seq::Next, t), None);
        assert_eq!(l.note(Seq::Dup, t), Some(0));
        assert_eq!(l.note(Seq::Dup, t + Duration::from_secs(1)), None);
        assert_eq!(l.note(Seq::Dup, t + Duration::from_secs(2)), None);
        // the other kind has its own limiter
        assert_eq!(l.note(Seq::Gap, t + Duration::from_secs(2)), Some(0));
        assert_eq!(l.note(Seq::Dup, t + LOG_INTERVAL), Some(2));
        let c = counters();
        // other tests in this process may count too: at least ours
        assert!(c[0].1 >= d0 + 4 && c[1].1 > g0);
    }
}
