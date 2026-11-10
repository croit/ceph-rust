// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
#[test]
fn wide_wait_preserves_budget_and_unlimited_is_not_a_timer() {
    let mut q = queue(2, 2);
    let end = time::deadline_after(1, 1u64 << 32).unwrap();
    let finite = q.submit(MapBarrierRequest::Epoch(6), end).unwrap();
    let unlimited = q
        .submit(MapBarrierRequest::Epoch(6), time::NO_DEADLINE)
        .unwrap();
    q.progress(end - 1, FSID, 4, 2).unwrap();
    assert_eq!(q.next_deadline_us(), Some(end));
    assert_eq!(q.poll_into(&mut [None]), 0);
    q.progress(end, FSID, 4, 2).unwrap();
    let done = take(&mut q);
    assert_eq!(done.token, finite);
    assert!(matches!(
        done.outcome,
        MapBarrierOutcome::Failed {
            error: MapBarrierError::Deadline,
            ..
        }
    ));
    assert_eq!(q.next_deadline_us(), None);
    q.progress(MAX_TIME, FSID, 6, 2).unwrap();
    assert_eq!(take(&mut q).token, unlimited);
    assert_eq!(q.poll_into(&mut [None]), 0);
}
const FSID: Uuid = Uuid([7; 16]);
fn queue(slots: usize, attempts: u32) -> MapBarrierQueue {
    let mut q = MapBarrierQueue::new(
        FSID,
        MapBarrierLimits {
            slots,
            query_attempts: attempts,
        },
    )
    .unwrap();
    q.progress(1, FSID, 4, slots).unwrap();
    q
}
fn take(q: &mut MapBarrierQueue) -> MapBarrierCompletion {
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    out[0].take().unwrap()
}
#[test]
fn wait_hint_preserves_fresh_later_query_reached_targets_and_abandoned_cleanup() {
    let mut q = queue(2, 2);
    assert!(q.can_wait(1, FSID, 4, true));
    let first = q.submit(MapBarrierRequest::Latest, 100).unwrap();
    assert!(!q.can_wait(1, FSID, 4, true));
    q.mark_query(10).unwrap();
    assert!(q.can_wait(1, FSID, 4, true));
    let later = q.submit(MapBarrierRequest::Latest, 100).unwrap();
    assert!(q.can_wait(1, FSID, 4, true)); // Cannot join an already captured query.
    q.on_version(10, 6, 1).unwrap();
    assert!(!q.can_wait(1, FSID, 4, true)); // Later caller needs its fresh query.
    q.mark_query(11).unwrap();
    assert!(q.can_wait(1, FSID, 4, true));
    assert!(!q.can_wait(2, FSID, 6, true));
    q.progress(2, FSID, 6, 0).unwrap();
    assert!(!q.can_wait(2, FSID, 6, true));
    q.progress(2, FSID, 6, 2).unwrap();
    assert!(!q.can_wait(2, FSID, 6, true));
    assert_eq!(take(&mut q).token, first);
    assert!(q.can_wait(2, FSID, 6, true));
    assert!(!q.can_wait(100, FSID, 6, true));
    q.cancel(later).unwrap();
    assert!(!q.can_wait(2, FSID, 6, true));
    assert_eq!(take(&mut q).token, later);
    assert!(!q.can_wait(2, FSID, 6, true)); // Empty entries still need query detach.
    assert_eq!(q.take_abandoned_query(), Some(11));
    assert!(q.can_wait(2, FSID, 6, true));
    assert!(!q.can_wait(1, FSID, 6, true));
    assert!(!q.can_wait(2, Uuid([8; 16]), 6, true));
    assert!(!q.can_wait(2, FSID, 5, true));
    assert!(!q.can_wait(MAX_TIME + 1, FSID, 6, true));
}
#[test]
fn latest_is_fresh_and_query_boundary_does_not_absorb_later_callers() {
    let mut q = queue(4, 2);
    let a = q.submit(MapBarrierRequest::Latest, 100).unwrap();
    let b = q.submit(MapBarrierRequest::Latest, 100).unwrap();
    assert_eq!(q.poll_into(&mut [None]), 0);
    assert!(q.needs_query());
    q.mark_query(10).unwrap();
    let later = q.submit(MapBarrierRequest::Latest, 100).unwrap();
    assert!(!q.needs_query());
    assert_eq!(q.on_version(9, 99, 1), Ok(false));
    q.on_version(10, 6, 1).unwrap();
    assert!(q.needs_query());
    assert_eq!(q.wanted_epoch(), Some(6));
    q.progress(2, FSID, 8, 4).unwrap();
    for token in [a, b] {
        let c = take(&mut q);
        assert_eq!(c.token, token);
        assert_eq!(
            c.outcome,
            MapBarrierOutcome::Reached {
                fsid: FSID,
                target_epoch: 6,
                observed_epoch: 8
            }
        );
    }
    assert_eq!(q.poll_into(&mut [None]), 0);
    q.mark_query(11).unwrap();
    q.on_version(11, 9, 1).unwrap();
    q.progress(3, FSID, 9, 4).unwrap();
    assert_eq!(take(&mut q).token, later);
}
#[test]
fn fixed_wait_completion_credit_and_occupied_output_cells() {
    let mut q = queue(1, 1);
    let token = q.submit(MapBarrierRequest::Epoch(3), 20).unwrap();
    assert!(!q.needs_query());
    assert_eq!(q.outstanding(), 1);
    assert_eq!(
        q.submit(MapBarrierRequest::Latest, 20).unwrap_err().reason,
        MapBarrierError::NoCredit
    );
    let c = take(&mut q);
    assert_eq!(c.token, token);
    let next = q.submit(MapBarrierRequest::Epoch(5), 20).unwrap();
    assert_eq!(q.cancel(token), Err(MapBarrierError::Stale));
    q.progress(2, FSID, 5, 1).unwrap();
    let mut out = [Some(c)];
    assert_eq!(q.poll_into(&mut out), 0);
    assert_eq!(q.outstanding(), 1);
    assert_eq!(out[0], Some(c));
    assert_eq!(take(&mut q).token, next);
    assert_eq!(q.outstanding(), 0);
}
#[test]
fn deadlines_win_even_on_malformed_late_reply_and_targets_survive_wait_failure() {
    let mut q = queue(3, 1);
    q.submit(MapBarrierRequest::Latest, 5).unwrap();
    q.mark_query(1).unwrap();
    q.progress(5, FSID, 4, 0).unwrap();
    let later = q.submit(MapBarrierRequest::Latest, 10).unwrap();
    q.on_version(1, 0, u64::MAX).unwrap();
    assert_eq!(q.error(), None);
    assert_eq!(
        take(&mut q).outcome,
        MapBarrierOutcome::Failed {
            error: MapBarrierError::Deadline,
            target_epoch: None
        }
    );
    q.mark_query(2).unwrap();
    q.on_version(2, 8, 1).unwrap();
    q.progress(10, FSID, 8, 3).unwrap();
    let c = take(&mut q);
    assert_eq!(c.token, later);
    assert_eq!(
        c.outcome,
        MapBarrierOutcome::Failed {
            error: MapBarrierError::Deadline,
            target_epoch: Some(8)
        }
    );
}
#[test]
fn monitor_loss_retries_finitely_without_resetting_deadline_or_known_target() {
    let mut q = queue(3, 2);
    q.submit(MapBarrierRequest::Latest, 50).unwrap();
    q.mark_query(1).unwrap();
    q.monitor_lost();
    assert_eq!(q.next_deadline_us(), Some(50));
    assert!(q.needs_query());
    q.mark_query(2).unwrap();
    assert_eq!(q.on_version(1, 100, 1), Ok(false));
    q.monitor_lost();
    assert_eq!(
        take(&mut q).outcome,
        MapBarrierOutcome::Failed {
            error: MapBarrierError::MonitorLost,
            target_epoch: None
        }
    );
    q.submit(MapBarrierRequest::Latest, 50).unwrap();
    q.mark_query(3).unwrap();
    q.on_version(3, 6, 1).unwrap();
    q.monitor_lost();
    assert!(!q.needs_query());
    q.progress(2, FSID, 6, 3).unwrap();
    assert!(matches!(
        take(&mut q).outcome,
        MapBarrierOutcome::Reached {
            target_epoch: 6,
            ..
        }
    ));
}
#[test]
fn cancellation_and_expiry_release_the_single_monitor_correlation() {
    let mut q = queue(2, 1);
    let a = q.submit(MapBarrierRequest::Latest, 10).unwrap();
    let b = q.submit(MapBarrierRequest::Latest, 10).unwrap();
    q.mark_query(9).unwrap();
    q.cancel(a).unwrap();
    assert_eq!(q.take_abandoned_query(), None);
    q.cancel(b).unwrap();
    assert_eq!(q.take_abandoned_query(), Some(9));
    assert_eq!(q.take_abandoned_query(), None);
    assert_eq!(q.on_version(9, 100, 1), Ok(false));
    take(&mut q);
    take(&mut q);
    q.submit(MapBarrierRequest::Latest, 10).unwrap();
    q.mark_query(10).unwrap();
    q.progress(10, FSID, 4, 0).unwrap();
    assert_eq!(q.take_abandoned_query(), Some(10));
    q.progress(10, FSID, 4, 2).unwrap();
    assert!(matches!(
        take(&mut q).outcome,
        MapBarrierOutcome::Failed {
            error: MapBarrierError::Deadline,
            ..
        }
    ));
}
#[test]
fn invalid_identity_clock_map_and_protocol_are_sticky_but_owned_completions_stay() {
    for error in [
        MapBarrierError::Clock,
        MapBarrierError::Fsid,
        MapBarrierError::MapRegression,
        MapBarrierError::Protocol,
    ] {
        let mut q = queue(2, 1);
        q.submit(MapBarrierRequest::Epoch(4), 50).unwrap();
        let complete = take(&mut q);
        q.submit(MapBarrierRequest::Latest, 50).unwrap();
        q.mark_query(1).unwrap();
        match error {
            MapBarrierError::Clock => {
                assert_eq!(q.progress(0, FSID, 4, 2), Err(error));
            }
            MapBarrierError::Fsid => {
                assert_eq!(q.progress(2, Uuid([8; 16]), 4, 2), Err(error));
            }
            MapBarrierError::MapRegression => {
                assert_eq!(q.progress(2, FSID, 3, 2), Err(error));
            }
            _ => {
                assert_eq!(q.on_version(1, u64::from(u32::MAX) + 1, 0), Err(error));
            }
        }
        assert_eq!(q.error(), Some(error));
        assert_eq!(
            q.submit(MapBarrierRequest::Latest, 50).unwrap_err().reason,
            error
        );
        assert_eq!(
            take(&mut q).outcome,
            MapBarrierOutcome::Failed {
                error,
                target_epoch: None
            }
        );
        assert!(matches!(
            complete.outcome,
            MapBarrierOutcome::Reached {
                target_epoch: 4,
                ..
            }
        ));
    }
}
#[test]
fn extreme_epochs_close_and_foreign_tokens_are_passive() {
    let mut q = queue(2, 1);
    let mut foreign = queue(1, 1);
    let token = foreign.submit(MapBarrierRequest::Epoch(4), 50).unwrap();
    assert_eq!(q.cancel(token), Err(MapBarrierError::Stale));
    assert_eq!(
        q.submit(MapBarrierRequest::Epoch(0), 50)
            .unwrap_err()
            .reason,
        MapBarrierError::InvalidEpoch
    );
    assert_eq!(
        q.submit(MapBarrierRequest::Latest, MAX_TIME + 1)
            .unwrap_err()
            .reason,
        MapBarrierError::Overflow
    );
    q.submit(MapBarrierRequest::Latest, 50).unwrap();
    q.mark_query(u64::MAX).unwrap();
    q.on_version(u64::MAX, u64::from(u32::MAX), 0).unwrap();
    q.progress(2, FSID, u32::MAX, 2).unwrap();
    assert!(matches!(
        take(&mut q).outcome,
        MapBarrierOutcome::Reached {
            target_epoch: u32::MAX,
            ..
        }
    ));
    q.submit(MapBarrierRequest::Latest, 50).unwrap();
    q.close();
    assert!(matches!(
        take(&mut q).outcome,
        MapBarrierOutcome::Failed {
            error: MapBarrierError::Closed,
            ..
        }
    ));
}
#[test]
fn rotating_budget_does_not_skip_waiters_permanently() {
    let mut q = queue(4, 1);
    for _ in 0..4 {
        q.submit(MapBarrierRequest::Epoch(8), 10).unwrap();
    }
    for _ in 0..4 {
        q.progress(2, FSID, 8, 1).unwrap();
        assert!(matches!(
            take(&mut q).outcome,
            MapBarrierOutcome::Reached {
                target_epoch: 8,
                ..
            }
        ));
    }
}

#[test]
fn independent_get_version_front_vectors_and_legacy_reply() {
    use messages::{MMonGetVersion, MMonGetVersionReply, Message};
    let request = MMonGetVersion {
        handle: 0x0807060504030201,
        what: "osdmap".into(),
    };
    let wire = request.encode(0).unwrap();
    assert_eq!(
        wire.front,
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x06\0\0\0osdmap"
    );
    assert!(wire.middle.is_empty() && wire.data.is_empty());
    let bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08\x11\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0";
    let reply = MMonGetVersionReply::decode(2, bytes, b"", b"").unwrap();
    assert_eq!(
        (reply.handle, reply.version, reply.oldest_version),
        (request.handle, 17, 2)
    );
    assert_eq!(reply.encode(0).unwrap().front, bytes);
    assert_eq!(
        MMonGetVersionReply::decode(1, &bytes[..16], b"", b"")
            .unwrap()
            .oldest_version,
        0
    );
}

#[test]
fn cancel_at_observed_deadline_expires_unvisited_slot_and_preserves_target() {
    let mut q = queue(1, 1);
    let token = q.submit(MapBarrierRequest::Epoch(8), 10).unwrap();
    q.progress(10, FSID, 8, 0).unwrap();
    q.cancel(token).unwrap();
    assert_eq!(
        take(&mut q).outcome,
        MapBarrierOutcome::Failed {
            error: MapBarrierError::Deadline,
            target_epoch: Some(8)
        }
    );
}

#[cfg(feature = "lab")]
#[test]
fn lab_counter_counts_only_matched_valid_live_confirmations_behind_the_target() {
    let mut q = queue(2, 2);
    q.submit(MapBarrierRequest::Latest, 10).unwrap();
    q.mark_query(1).unwrap();
    assert_eq!(q.on_version(99, 8, 1), Ok(false));
    assert_eq!(q.lab_lagged_queries(), 0);
    q.on_version(1, 4, 1).unwrap();
    take(&mut q);
    assert_eq!(q.lab_lagged_queries(), 0);
    q.submit(MapBarrierRequest::Latest, 10).unwrap();
    q.mark_query(2).unwrap();
    q.on_version(2, 8, 1).unwrap();
    assert_eq!(q.lab_lagged_queries(), 1);
    q.progress(2, FSID, 8, 2).unwrap();
    take(&mut q);
    q.submit(MapBarrierRequest::Latest, 10).unwrap();
    q.mark_query(3).unwrap();
    q.progress(10, FSID, 8, 0).unwrap();
    q.on_version(3, u64::MAX, 1).unwrap();
    assert_eq!(q.lab_lagged_queries(), 1);
}

#[test]
fn compatible_version_queries_survive_repeated_losses_and_wait_for_catchup() {
    let mut q = MapBarrierQueue::new_compatible(FSID, 2).unwrap();
    q.progress(1, FSID, 4, 2).unwrap();
    let first = q.submit(MapBarrierRequest::Latest, 100).unwrap();
    for handle in 1..=6 {
        q.mark_query(handle).unwrap();
        q.monitor_lost();
        assert_eq!(q.next_deadline_us(), Some(100));
        assert_eq!(q.poll_into(&mut [None]), 0);
        assert!(q.needs_query());
    }
    q.mark_query(7).unwrap();
    assert_eq!(q.on_version(1, 99, 1), Ok(false));
    q.on_version(7, 6, 1).unwrap();
    q.progress(20, FSID, 5, 2).unwrap();
    assert_eq!(q.poll_into(&mut [None]), 0);
    q.progress(21, FSID, 6, 2).unwrap();
    let done = take(&mut q);
    assert_eq!(done.token, first);
    assert!(matches!(
        done.outcome,
        MapBarrierOutcome::Reached {
            target_epoch: 6,
            observed_epoch: 6,
            ..
        }
    ));
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.poll_into(&mut [None]), 0);
}
#[test]
fn compatible_recovery_keeps_deadline_and_cancel_close_are_once_only() {
    for action in 0..3 {
        let mut q = MapBarrierQueue::new_compatible(FSID, 1).unwrap();
        q.progress(1, FSID, 4, 1).unwrap();
        let token = q.submit(MapBarrierRequest::Latest, 10).unwrap();
        for handle in 1..=4 {
            q.mark_query(handle).unwrap();
            q.monitor_lost();
        }
        match action {
            0 => q.progress(10, FSID, 4, 1).unwrap(),
            1 => q.cancel(token).unwrap(),
            _ => q.close(),
        }
        let done = take(&mut q);
        let expected = match action {
            0 => MapBarrierError::Deadline,
            1 => MapBarrierError::Cancelled,
            _ => MapBarrierError::Closed,
        };
        assert_eq!(
            done.outcome,
            MapBarrierOutcome::Failed {
                error: expected,
                target_epoch: None
            }
        );
        assert_eq!(q.poll_into(&mut [None]), 0);
    }
}

#[test]
fn reconnect_waits_for_monitor_without_hiding_deadline_results_or_query_cleanup() {
    let mut q = queue(2, 2);
    let token = q.submit(MapBarrierRequest::Latest, 100).unwrap();
    assert!(q.can_wait(1, FSID, 4, false));
    assert!(!q.can_wait(1, FSID, 4, true));
    assert!(!q.can_wait(100, FSID, 4, false));
    q.mark_query(10).unwrap();
    q.monitor_lost();
    assert!(q.can_wait(1, FSID, 4, false));
    assert!(!q.can_wait(1, FSID, 4, true));
    q.cancel(token).unwrap();
    assert!(!q.can_wait(1, FSID, 4, false));
    assert_eq!(take(&mut q).token, token);
    assert!(q.can_wait(1, FSID, 4, false));
    q.submit(MapBarrierRequest::Epoch(4), 100).unwrap();
    assert!(!q.can_wait(1, FSID, 4, false));
}

#[test]
fn selective_completion_preserves_other_tokens_and_rejects_stale_generation() {
    let mut q = queue(2, 2);
    let first = q.submit(MapBarrierRequest::Epoch(4), 100).unwrap();
    let second = q.submit(MapBarrierRequest::Epoch(5), 100).unwrap();
    assert!(q.is_full());
    assert!(q.token_waiting(second));
    assert_eq!(q.poll_token(second), Ok(None));
    assert_eq!(q.poll_token(first).unwrap().unwrap().token, first);
    assert!(!q.is_full());
    let next = q.submit(MapBarrierRequest::Latest, 100).unwrap();
    assert_eq!(q.poll_token(first), Err(MapBarrierError::Stale));
    assert!(!q.token_waiting(first));
    assert!(q.token_waiting(next));
    q.progress(2, FSID, 5, 2).unwrap();
    assert_eq!(q.poll_token(second).unwrap().unwrap().token, second);
    assert_eq!(q.outstanding(), 1);
}
