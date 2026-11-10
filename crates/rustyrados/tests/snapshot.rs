// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use denc::types::Uuid;
use messages::{MPoolOpReply, PoolOperation};
use rustyrados::*;
fn fsid() -> Uuid {
    Uuid::parse("01020304-0506-0708-090a-0b0c0d0e0f10").unwrap()
}
fn queue(slots: usize) -> SnapshotQueue {
    SnapshotQueue::new(
        fsid(),
        SnapshotLimits {
            slots,
            bytes: slots as u64 * 16,
            response_bytes: 16,
        },
    )
    .unwrap()
}
fn request() -> SnapshotRequest {
    SnapshotRequest {
        pool: 7,
        operation: SnapshotOperation::Allocate,
    }
}
fn reply(id: u64, epoch: u32) -> MPoolOpReply {
    MPoolOpReply {
        version: 99,
        fsid: fsid(),
        result: 0,
        epoch,
        response_data: id.to_le_bytes().to_vec(),
    }
}
fn take(q: &mut SnapshotQueue) -> SnapshotCompletion {
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    out[0].take().unwrap()
}
#[test]
fn allocation_waits_for_map_and_service_fence_is_distinct_from_epoch() {
    let mut q = queue(1);
    let t = q.submit(request(), 100).unwrap();
    let m = q.prepare(t).unwrap();
    assert_eq!(m.operation, PoolOperation::AllocateSelfManagedSnap);
    assert_eq!(m.version, 0);
    assert_eq!(m.pool, 7);
    q.mark_sent(t, 7).unwrap();
    assert!(q.on_reply(7, reply(42, 5), 1, 4).unwrap());
    assert_eq!(q.poll_into(&mut [None]), 0);
    assert_eq!(q.observed_service_version(), 99);
    q.monitor_lost();
    assert_eq!(q.prepare(t).unwrap_err(), SnapshotQueueError::AlreadySent);
    q.progress(2, 5, 1).unwrap();
    let result = take(&mut q);
    assert_eq!(result.token, t);
    assert!(matches!(
        result.outcome,
        SnapshotOutcome::Completed(SnapshotReply {
            snapshot_id: Some(42),
            epoch: 5,
            result: 0,
            ..
        })
    ));
    assert_eq!(q.charged_bytes(), 0);
    let remove = q
        .submit(
            SnapshotRequest {
                pool: 7,
                operation: SnapshotOperation::Remove { snapid: 42 },
            },
            100,
        )
        .unwrap();
    let m = q.prepare(remove).unwrap();
    assert_eq!(m.operation, PoolOperation::RemoveSelfManagedSnap);
    assert_eq!(m.snapid, 42);
    assert_eq!(m.version, 99);
}
#[test]
fn known_allocation_is_retained_on_deadline_cancel_and_close_before_map_convergence() {
    for end in 0..3 {
        let mut q = queue(1);
        let t = q.submit(request(), 10).unwrap();
        q.mark_sent(t, 1).unwrap();
        q.on_reply(1, reply(42, 20), 5, 1).unwrap();
        match end {
            0 => {
                q.progress(10, 1, 1).unwrap();
            }
            1 => q.cancel(t).unwrap(),
            _ => q.close(),
        }
        assert_eq!(q.charged_bytes(), 16);
        let result = take(&mut q);
        let observed = match result.outcome {
            SnapshotOutcome::Deadline {
                possibly_sent: true,
                reply,
            } if end == 0 => reply,
            SnapshotOutcome::Canceled {
                possibly_sent: true,
                reply,
            } if end != 0 => reply,
            _ => panic!("incorrect certainty"),
        };
        assert_eq!(observed.unwrap().snapshot_id, Some(42));
        assert_eq!(q.outstanding(), 0);
        assert_eq!(q.charged_bytes(), 0);
        assert_eq!(q.poll_into(&mut [None]), 0);
    }
}
#[test]
fn monitor_loss_never_replays_handed_off_allocation_but_keeps_unsent_and_verified_work() {
    let mut q = queue(3);
    let sent = q.submit(request(), 100).unwrap();
    let queued = q.submit(request(), 100).unwrap();
    let verified = q.submit(request(), 100).unwrap();
    q.mark_sent(sent, 1).unwrap();
    q.mark_sent(verified, 2).unwrap();
    q.on_reply(2, reply(44, 3), 1, 1).unwrap();
    q.monitor_lost();
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Failed {
            error: SnapshotQueueError::MonitorLost,
            possibly_sent: true,
            reply: None
        }
    ));
    assert_eq!(q.prepare(sent).unwrap_err(), SnapshotQueueError::Stale);
    assert!(q.prepare(queued).is_ok());
    assert_eq!(
        q.prepare(verified).unwrap_err(),
        SnapshotQueueError::AlreadySent
    );
    assert!(!q.on_reply(1, reply(99, 1), 2, 1).unwrap());
    q.progress(3, 3, 3).unwrap();
    let done = take(&mut q);
    assert_eq!(done.token, verified);
    assert!(matches!(
        done.outcome,
        SnapshotOutcome::Completed(SnapshotReply {
            snapshot_id: Some(44),
            ..
        })
    ));
    q.cancel(queued).unwrap();
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Canceled {
            possibly_sent: false,
            reply: None
        }
    ));
}
#[test]
fn remote_error_waits_for_map_and_late_success_cannot_overtake_deadline() {
    let mut q = queue(1);
    let t = q.submit(request(), 10).unwrap();
    q.mark_sent(t, 1).unwrap();
    let r = MPoolOpReply {
        result: -22,
        response_data: vec![3, 4],
        ..reply(42, 2)
    };
    q.on_reply(1, r, 1, 1).unwrap();
    assert_eq!(q.poll_into(&mut [None]), 0);
    q.progress(2, 2, 1).unwrap();
    assert!(
        matches!(take(&mut q).outcome,SnapshotOutcome::Completed(SnapshotReply {result:-22,snapshot_id:None,data,..}) if data==[3,4])
    );
    let t = q.submit(request(), 10).unwrap();
    q.mark_sent(t, 2).unwrap();
    assert!(!q.on_reply(2, reply(42, 2), 10, 2).unwrap());
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Deadline {
            possibly_sent: true,
            reply: None
        }
    ));
}
#[test]
fn admission_ownership_credits_stale_tokens_and_wire_identity_never_reuse() {
    let mut q = queue(1);
    for bad in [
        SnapshotRequest {
            pool: -1,
            ..request()
        },
        SnapshotRequest {
            pool: i64::from(u32::MAX) + 1,
            ..request()
        },
        SnapshotRequest {
            operation: SnapshotOperation::Remove { snapid: 0 },
            ..request()
        },
        SnapshotRequest {
            operation: SnapshotOperation::Remove {
                snapid: opwire::SNAPDIR,
            },
            ..request()
        },
    ] {
        let rejected = q.submit(bad, 100).unwrap_err();
        assert_eq!(rejected.reason, SnapshotQueueError::InvalidRequest);
        assert_eq!(rejected.request, bad);
    }
    let t = q.submit(request(), 100).unwrap();
    assert_eq!(t.sequence(), 1);
    q.cancel(t).unwrap();
    assert_eq!(
        q.submit(request(), 100).unwrap_err().reason,
        SnapshotQueueError::NoCredit
    );
    let mut out = [Some(SnapshotCompletion {
        token: t,
        outcome: SnapshotOutcome::Canceled {
            possibly_sent: false,
            reply: None,
        },
    })];
    assert_eq!(q.poll_into(&mut out), 0);
    assert_eq!(q.charged_bytes(), 16);
    take(&mut q);
    let next = q.submit(request(), 100).unwrap();
    assert_ne!(next, t);
    assert_eq!(q.prepare(t).unwrap_err(), SnapshotQueueError::Stale);
    q.mark_sent(next, 5).unwrap();
    q.on_reply(5, reply(42, 0), 1, 0).unwrap();
    take(&mut q);
    let last = q.submit(request(), 100).unwrap();
    assert_eq!(
        q.mark_sent(last, 5).unwrap_err(),
        SnapshotQueueError::Identity
    );
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Failed {
            error: SnapshotQueueError::Identity,
            possibly_sent: true,
            ..
        }
    ));
}
#[test]
fn malformed_known_reply_and_clock_or_map_regression_fail_closed_preserving_verified_id() {
    for kind in 0..5 {
        let mut q = queue(1);
        let t = q.submit(request(), 100).unwrap();
        q.mark_sent(t, 1).unwrap();
        let mut r = reply(42, 1);
        match kind {
            0 => r.fsid = Uuid::default(),
            1 => r.response_data = vec![0; 8],
            2 => r.response_data = vec![1; 7],
            3 => r.response_data = Vec::with_capacity(32),
            _ => r.response_data = u64::MAX.to_le_bytes().to_vec(),
        }
        assert!(q.on_reply(1, r, 1, 1).is_err());
        assert!(q.error().is_some());
        assert!(matches!(
            take(&mut q).outcome,
            SnapshotOutcome::Failed {
                possibly_sent: true,
                reply: None,
                ..
            }
        ));
    }
    for map_regression in [false, true] {
        let mut q = queue(1);
        let t = q.submit(request(), 100).unwrap();
        q.mark_sent(t, 1).unwrap();
        q.on_reply(1, reply(42, 10), 5, 5).unwrap();
        assert!(
            q.progress(
                if map_regression { 6 } else { 4 },
                if map_regression { 4 } else { 5 },
                1
            )
            .is_err()
        );
        assert!(matches!(
            take(&mut q).outcome,
            SnapshotOutcome::Failed {
                possibly_sent: true,
                reply: Some(SnapshotReply {
                    snapshot_id: Some(42),
                    ..
                }),
                ..
            }
        ));
        assert_eq!(q.poll_into(&mut [None]), 0);
    }
}
#[test]
fn unknown_reply_does_not_advance_fence_and_budgeted_map_barrier_respects_deadline() {
    let mut q = queue(2);
    assert!(
        !q.on_reply(
            99,
            MPoolOpReply {
                fsid: Uuid::default(),
                ..reply(42, 20)
            },
            1,
            1
        )
        .unwrap()
    );
    assert_eq!(q.observed_service_version(), 0);
    assert_eq!(q.error(), None);
    let a = q.submit(request(), 10).unwrap();
    let b = q.submit(request(), 10).unwrap();
    q.mark_sent(a, 1).unwrap();
    q.mark_sent(b, 2).unwrap();
    q.on_reply(1, reply(42, 2), 2, 1).unwrap();
    q.on_reply(2, reply(43, 2), 2, 1).unwrap();
    assert_eq!(q.progress(10, 2, 1).unwrap(), 1);
    assert_eq!(q.next_deadline(), Some(10));
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Deadline { reply: Some(_), .. }
    ));
    assert_eq!(q.progress(10, 2, 1).unwrap(), 1);
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Deadline { reply: Some(_), .. }
    ));
}

#[test]
fn removal_has_empty_success_payload_and_foreign_tokens_or_duplicates_cannot_change_it() {
    let mut q = queue(1);
    let token = q
        .submit(
            SnapshotRequest {
                pool: 7,
                operation: SnapshotOperation::Remove { snapid: 42 },
            },
            100,
        )
        .unwrap();
    let mut other = queue(1);
    let foreign = other.submit(request(), 100).unwrap();
    assert_eq!(q.prepare(foreign).unwrap_err(), SnapshotQueueError::Stale);
    assert_eq!(q.cancel(foreign), Err(SnapshotQueueError::Stale));
    q.mark_sent(token, 1).unwrap();
    let r = MPoolOpReply {
        version: 12,
        fsid: fsid(),
        result: 0,
        epoch: 6,
        response_data: vec![],
    };
    assert!(q.on_reply(1, r, 1, 5).unwrap());
    assert!(!q.on_reply(1, reply(999, 99), 2, 5).unwrap());
    assert_eq!(q.observed_service_version(), 12);
    assert_eq!(q.error(), None);
    q.progress(3, 6, 1).unwrap();
    assert!(
        matches!(take(&mut q).outcome,SnapshotOutcome::Completed(SnapshotReply {result:0,snapshot_id:None,epoch:6,data}) if data.is_empty())
    );
    let token = q
        .submit(
            SnapshotRequest {
                pool: 7,
                operation: SnapshotOperation::Remove { snapid: 42 },
            },
            100,
        )
        .unwrap();
    q.mark_sent(token, 2).unwrap();
    assert_eq!(
        q.on_reply(2, reply(1, 6), 4, 6),
        Err(SnapshotQueueError::Protocol)
    );
}

#[test]
fn reserved_head_selector_is_never_an_allocated_or_removable_snapshot_identity() {
    let mut q = queue(2);
    for snapid in [opwire::NOSNAP, opwire::SNAPDIR] {
        assert_eq!(
            q.submit(
                SnapshotRequest {
                    pool: 7,
                    operation: SnapshotOperation::Remove { snapid }
                },
                100
            )
            .unwrap_err()
            .reason,
            SnapshotQueueError::InvalidRequest
        );
    }
    assert_eq!(q.outstanding(), 0);
    let largest = q
        .submit(
            SnapshotRequest {
                pool: 7,
                operation: SnapshotOperation::Remove {
                    snapid: opwire::NOSNAP - 1,
                },
            },
            100,
        )
        .unwrap();
    q.cancel(largest).unwrap();
    take(&mut q);
    let token = q.submit(request(), 100).unwrap();
    q.mark_sent(token, 11).unwrap();
    assert_eq!(
        q.on_reply(11, reply(opwire::NOSNAP, 5), 1, 4),
        Err(SnapshotQueueError::Protocol)
    );
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Failed {
            error: SnapshotQueueError::Protocol,
            possibly_sent: true,
            reply: None
        }
    ));
}
