// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use denc::types::Uuid;
use messages::{MPoolOpReply, PoolOperation};
use rustyrados::*;
fn queue(slots: usize, bytes: u64) -> SnapshotQueue {
    SnapshotQueue::new(
        Uuid([7; 16]),
        SnapshotLimits {
            slots,
            bytes,
            response_bytes: 8,
        },
    )
    .unwrap()
}
fn request(operation: NamedSnapshotOperation, name: Vec<u8>) -> NamedSnapshotRequest {
    NamedSnapshotRequest {
        pool: 7,
        operation,
        name,
    }
}
fn reply(result: i32, epoch: u32) -> MPoolOpReply {
    MPoolOpReply {
        version: 91,
        fsid: Uuid([7; 16]),
        result,
        epoch,
        response_data: vec![],
    }
}
fn take(q: &mut SnapshotQueue) -> SnapshotCompletion {
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    out[0].take().unwrap()
}
#[test]
fn owned_name_capacity_stays_charged_until_public_completion_consumption() {
    let mut q = queue(2, 24);
    let mut name = Vec::with_capacity(16);
    name.extend_from_slice(&[255, 65]);
    let token = q
        .submit_named(request(NamedSnapshotOperation::Create, name), 100)
        .unwrap();
    assert_eq!(q.charged_bytes(), 24);
    let mut other = Vec::with_capacity(8);
    other.extend_from_slice(b"other");
    let ptr = other.as_ptr();
    let rejected = q
        .submit_named(request(NamedSnapshotOperation::Remove, other), 100)
        .unwrap_err();
    assert_eq!(rejected.reason, SnapshotQueueError::NoCredit);
    assert_eq!(rejected.request.name.as_ptr(), ptr);
    assert_eq!(rejected.request.name.capacity(), 8);
    let wire = q.prepare(token).unwrap();
    assert_eq!(wire.operation, PoolOperation::CreateNamedSnap);
    assert_eq!(wire.name, [255, 65]);
    assert_eq!(wire.snapid, 0);
    q.mark_sent(token, 11).unwrap();
    q.on_reply(11, reply(0, 5), 1, 4).unwrap();
    assert_eq!(q.poll_into(&mut [None]), 0);
    q.progress(2, 5, 2).unwrap();
    assert_eq!(q.charged_bytes(), 24);
    let done = take(&mut q);
    assert_eq!(done.token, token);
    assert!(matches!(
        done.outcome,
        SnapshotOutcome::Completed(SnapshotReply {
            snapshot_id: None,
            result: 0,
            ..
        })
    ));
    assert_eq!(q.charged_bytes(), 0);
    let token = q.submit_named(rejected.request, 100).unwrap();
    assert_eq!(
        q.prepare(token).unwrap().operation,
        PoolOperation::RemoveNamedSnap
    );
    assert_eq!(q.prepare(token).unwrap().version, 91);
}
#[test]
fn empty_name_is_preserved_and_nul_rejection_returns_original_storage() {
    let mut q = queue(2, 32);
    let mut name = Vec::with_capacity(9);
    name.extend_from_slice(&[65, 0, 255]);
    let ptr = name.as_ptr();
    let rejected = q
        .submit_named(request(NamedSnapshotOperation::Create, name), 100)
        .unwrap_err();
    assert_eq!(rejected.reason, SnapshotQueueError::InvalidRequest);
    assert_eq!(rejected.request.name.as_ptr(), ptr);
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
    let token = q
        .submit_named(request(NamedSnapshotOperation::Create, vec![]), 100)
        .unwrap();
    assert_eq!(token.sequence(), 1);
    assert!(q.prepare(token).unwrap().name.is_empty());
    q.cancel(token).unwrap();
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Canceled {
            possibly_sent: false,
            reply: None
        }
    ));
    assert_eq!(q.charged_bytes(), 0);
}
#[test]
fn successful_named_reply_cannot_fabricate_allocated_id_from_unexpected_data() {
    let mut q = queue(1, 16);
    let token = q
        .submit_named(
            request(NamedSnapshotOperation::Create, b"name".to_vec()),
            100,
        )
        .unwrap();
    q.mark_sent(token, 11).unwrap();
    let mut r = reply(0, 5);
    r.response_data = 42u64.to_le_bytes().to_vec();
    assert_eq!(q.on_reply(11, r, 1, 4), Err(SnapshotQueueError::Protocol));
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Failed {
            error: SnapshotQueueError::Protocol,
            possibly_sent: true,
            reply: None
        }
    ));
    assert_eq!(q.charged_bytes(), 0);
}
#[test]
fn remote_error_map_barrier_loss_and_deadline_preserve_named_status_without_replay() {
    let mut q = queue(2, 64);
    let token = q
        .submit_named(
            request(NamedSnapshotOperation::Remove, b"name".to_vec()),
            10,
        )
        .unwrap();
    q.mark_sent(token, 11).unwrap();
    q.on_reply(11, reply(-1, 5), 1, 4).unwrap();
    q.monitor_lost();
    assert_eq!(q.poll_into(&mut [None]), 0);
    assert_eq!(
        q.prepare(token).unwrap_err(),
        SnapshotQueueError::AlreadySent
    );
    q.progress(10, 5, 2).unwrap();
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Deadline {
            possibly_sent: true,
            reply: Some(SnapshotReply {
                result: -1,
                snapshot_id: None,
                ..
            })
        }
    ));
    assert_eq!(q.charged_bytes(), 0);
    let token = q
        .submit_named(
            request(NamedSnapshotOperation::Create, b"new".to_vec()),
            100,
        )
        .unwrap();
    q.mark_sent(token, 12).unwrap();
    q.monitor_lost();
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Failed {
            error: SnapshotQueueError::MonitorLost,
            possibly_sent: true,
            reply: None
        }
    ));
}
#[test]
fn named_and_selfmanaged_share_slots_bytes_and_monotonic_identity_domain() {
    let mut q = queue(1, 16);
    let token = q
        .submit_named(request(NamedSnapshotOperation::Create, b"n".to_vec()), 100)
        .unwrap();
    let selfmanaged = SnapshotRequest {
        pool: 7,
        operation: SnapshotOperation::Allocate,
    };
    assert_eq!(
        q.submit(selfmanaged, 100).unwrap_err().reason,
        SnapshotQueueError::NoCredit
    );
    q.mark_sent(token, 11).unwrap();
    q.on_reply(11, reply(0, 4), 1, 4).unwrap();
    take(&mut q);
    let token = q.submit(selfmanaged, 100).unwrap();
    assert_eq!(
        q.prepare(token).unwrap().operation,
        PoolOperation::AllocateSelfManagedSnap
    );
    assert_eq!(q.mark_sent(token, 11), Err(SnapshotQueueError::Identity));
    assert!(matches!(
        take(&mut q).outcome,
        SnapshotOutcome::Failed {
            possibly_sent: true,
            error: SnapshotQueueError::Identity,
            ..
        }
    ));
}
