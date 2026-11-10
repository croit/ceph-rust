// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optional page-only queue endpoints. These are elapsed intervals, not CPU time
//! or complete client RPC latency. Counters reconcile only at settled points.
use super::{Profile, profile};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(in crate::rocks_omap) struct Handoff {
    queued: Instant,
    dequeued: Instant,
    ready: Option<Instant>,
    publishing: Option<Instant>,
}

pub(in crate::rocks_omap) fn enqueue_stamp_with(
    profile: &Profile,
    clock: impl FnOnce() -> Instant,
) -> Option<Instant> {
    profile.enabled.then(clock)
}

impl Handoff {
    pub fn dequeued(profile: &Profile, queued: Option<Instant>) -> Option<Self> {
        Self::dequeued_with(profile, queued, Instant::now)
    }

    fn dequeued_with(
        profile: &Profile,
        queued: Option<Instant>,
        clock: impl FnOnce() -> Instant,
    ) -> Option<Self> {
        if !profile.enabled {
            return None;
        }
        let queued = queued?;
        let dequeued = clock();
        profile.add(profile::HANDOFF_DEQUEUED, 1);
        Some(Self {
            queued,
            dequeued,
            ready: None,
            publishing: None,
        })
    }

    pub fn ready(&mut self, profile: &Profile) {
        self.ready_with(profile, Instant::now);
    }

    fn ready_with(&mut self, profile: &Profile, clock: impl FnOnce() -> Instant) {
        if profile.enabled {
            self.ready = Some(clock());
            profile.add(profile::HANDOFF_READY, 1);
        }
    }

    pub fn publishing_with(&mut self, profile: &Profile, clock: impl FnOnce() -> Instant) {
        if profile.enabled {
            self.publishing = Some(clock());
        }
    }

    pub fn consumed(self, profile: &Profile, outcome: Option<usize>) {
        self.consumed_with(profile, outcome, Instant::now);
    }

    fn consumed_with(
        self,
        profile: &Profile,
        outcome: Option<usize>,
        clock: impl FnOnce() -> Instant,
    ) {
        if !profile.enabled {
            return;
        }
        // E is read before accounting or owner cache/refusal/failure handling.
        let consumed = clock();
        profile.add(profile::HANDOFF_CONSUMED, 1);
        let Some(outcome) = outcome else {
            profile.add(profile::HANDOFF_ERRORS, 1);
            return;
        };
        profile.add(outcome, 1);
        let intervals = self.intervals(consumed);
        if let Some(intervals) = intervals {
            for (i, ns) in intervals.into_iter().enumerate() {
                profile.add(profile::HANDOFF_REQUEST_NS + i, ns);
            }
            profile.add(profile::HANDOFF_SAMPLES, 1);
        } else {
            profile.add(profile::HANDOFF_ERRORS, 1);
        }
    }

    fn intervals(&self, consumed: Instant) -> Option<[u64; 5]> {
        let ready = self.ready?;
        let publishing = self.publishing?;
        Some([
            checked_nanos(self.dequeued.checked_duration_since(self.queued)?)?,
            checked_nanos(ready.checked_duration_since(self.dequeued)?)?,
            checked_nanos(publishing.checked_duration_since(ready)?)?,
            checked_nanos(consumed.checked_duration_since(publishing)?)?,
            checked_nanos(consumed.checked_duration_since(self.queued)?)?,
        ])
    }
}

fn checked_nanos(duration: Duration) -> Option<u64> {
    duration.as_nanos().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_handoff_endpoints_partition_elapsed_time_and_count_outcomes() {
        let p = Profile::new(true);
        let base = Instant::now();
        let tick = |n| base + Duration::from_nanos(n);
        for outcome in [
            profile::HANDOFF_SUCCESS,
            profile::HANDOFF_REFUSED,
            profile::HANDOFF_FAILED,
        ] {
            let a = enqueue_stamp_with(&p, || tick(10));
            let mut t = Handoff::dequeued_with(&p, a, || tick(17)).unwrap();
            t.ready_with(&p, || tick(30));
            t.publishing_with(&p, || tick(31));
            t.publishing_with(&p, || tick(32));
            t.publishing_with(&p, || tick(34));
            assert_eq!(t.intervals(tick(51)), Some([7, 13, 4, 17, 41]));
            t.consumed_with(&p, Some(outcome), || tick(51));
        }
        let s = p.sample();
        assert_eq!(&s[61..66], &[1, 1, 1, 3, 0]);
        assert_eq!(&s[67..72], &[21, 39, 12, 51, 123]);
        assert_eq!(s[60], 3);
        assert_eq!(s[56], 0, "only actual request pushes count acceptance");
        assert_eq!(s[59], 0, "a timestamp is not successful publication");
    }

    #[test]
    fn missing_reversed_equal_and_overflow_handoff_ticks_are_distinct() {
        let p = Profile::new(true);
        let at = Instant::now();
        let mut equal = Handoff::dequeued_with(&p, Some(at), || at).unwrap();
        equal.ready_with(&p, || at);
        equal.publishing_with(&p, || at);
        assert_eq!(equal.intervals(at), Some([0; 5]));
        equal.consumed_with(&p, Some(profile::HANDOFF_SUCCESS), || at);
        for bad in 0..4 {
            let mut t = Handoff {
                queued: at,
                dequeued: at,
                ready: Some(at),
                publishing: Some(at),
            };
            match bad {
                0 => t.queued += Duration::from_nanos(1),
                1 => t.dequeued += Duration::from_nanos(1),
                2 => t.ready = Some(at + Duration::from_nanos(1)),
                _ => t.publishing = Some(at + Duration::from_nanos(1)),
            }
            t.consumed_with(&p, Some(profile::HANDOFF_SUCCESS), || at);
        }
        for missing in 0..2 {
            let mut t = Handoff::dequeued_with(&p, Some(at), || at).unwrap();
            if missing == 0 {
                t.publishing_with(&p, || at); // C absent, D present.
            } else {
                t.ready_with(&p, || at); // C present, D absent.
            }
            t.consumed_with(&p, Some(profile::HANDOFF_REFUSED), || at);
        }
        assert_eq!(
            checked_nanos(Duration::from_nanos(u64::MAX)),
            Some(u64::MAX)
        );
        assert_eq!(checked_nanos(Duration::from_secs(u64::MAX)), None);
        let s = p.sample();
        assert_eq!(s[64], 1);
        assert_eq!(s[65], 6);
        assert_eq!(&s[67..72], &[0; 5]);
    }

    #[test]
    fn unexpected_handoff_outcome_is_an_error_not_an_operation_failure() {
        let p = Profile::new(true);
        let at = Instant::now();
        let mut t = Handoff::dequeued_with(&p, Some(at), || at).unwrap();
        t.ready_with(&p, || at);
        t.publishing_with(&p, || at);
        t.consumed_with(&p, None, || at);
        let s = p.sample();
        assert_eq!(&s[60..66], &[1, 0, 0, 0, 0, 1]);
        assert_eq!(&s[67..72], &[0; 5]);
    }

    #[test]
    fn disabled_handoff_never_calls_added_clocks_or_records_zero_samples() {
        let p = Profile::default();
        assert!(enqueue_stamp_with(&p, || panic!("disabled enqueue clock")).is_none());
        assert!(Handoff::dequeued_with(&p, None, || panic!("disabled dequeue clock")).is_none());
        let at = Instant::now();
        let mut t = Handoff {
            queued: at,
            dequeued: at,
            ready: None,
            publishing: None,
        };
        t.ready_with(&p, || panic!("disabled ready clock"));
        t.publishing_with(&p, || panic!("disabled publication clock"));
        t.consumed_with(&p, Some(profile::HANDOFF_SUCCESS), || {
            panic!("disabled consume clock")
        });
        assert_eq!(p.sample(), [0; profile::LEN]);
    }

    #[test]
    fn actual_full_completion_ring_retains_ready_and_only_final_publish_attempt() {
        use crate::rocks_omap::{Completion, Response, err, push_response_with};
        let p = Profile::new(true);
        let base = Instant::now();
        let tick = |n| base + Duration::from_nanos(n);
        let mut trace = Handoff::dequeued_with(&p, Some(tick(10)), || tick(17)).unwrap();
        trace.ready_with(&p, || tick(30));
        let (mut tx, mut rx) = rtrb::RingBuffer::new(1);
        tx.push(Response::unprofiled(Completion::Failed(err("occupant"))))
            .unwrap();
        let mut response = Response {
            value: Completion::Failed(err("request failure")),
            handoff: Some(trace),
        };
        for n in [31, 32] {
            response = match push_response_with(&mut tx, response, &p, || tick(n)) {
                Err(rtrb::PushError::Full(response)) => response,
                Ok(()) => panic!("full ring accepted response"),
            };
            assert_eq!(response.handoff.as_ref().unwrap().ready, Some(tick(30)));
            assert_eq!(p.sample()[profile::HANDOFF_PUBLISHED], 0);
        }
        drop(rx.pop().unwrap());
        push_response_with(&mut tx, response, &p, || tick(34)).unwrap();
        let response = rx.pop().unwrap();
        assert!(matches!(response.value, Completion::Failed(_)));
        response
            .handoff
            .unwrap()
            .consumed_with(&p, Some(profile::HANDOFF_FAILED), || tick(51));
        let s = p.sample();
        assert_eq!(&s[59..67], &[1, 1, 0, 0, 1, 1, 0, 2]);
        assert_eq!(&s[67..72], &[7, 13, 4, 17, 41]);
    }
}
