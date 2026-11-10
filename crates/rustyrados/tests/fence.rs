// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::PgT;
use opwire::{MOSDOpReply, flag};
use rustyrados::*;

fn target() -> Target {
    Target {
        pool: 7,
        object: b"obj".to_vec(),
        namespace: vec![],
        locator: vec![],
    }
}
fn write() -> WriteRequest {
    WriteRequest {
        target: target(),
        operation: WriteOperation::WriteFull,
        payload: Bytes::from_static(b"abc"),
    }
}
fn route() -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 7,
        osd: 2,
        session: 3,
        pg: PgT { pool: 7, seed: 4 },
        hash: 55,
        epoch: 9,
        features: 0,
        generation: 1,
        pool: rustyrados::PoolRoute::Replicated,
    }
}
fn finish(q: &mut ObjectQueue, token: RequestToken, status: i32) {
    let d = q.dispatch(token, route()).unwrap();
    let mut r = MOSDOpReply::for_request(&d.message, 9);
    r.result = status;
    r.ops[0].rval = status;
    assert!(q.reply(token, 2, 3, r).unwrap());
}

#[test]
fn fence_waits_for_earlier_hole_but_excludes_reads_and_later_writes() {
    let mut q = ObjectQueue::new(4, 100, 0).unwrap();
    let a = q.submit_write(write()).unwrap();
    let _read = q
        .submit(ReadRequest {
            target: target(),
            offset: 0,
            length: 16,
        })
        .unwrap();
    let b = q.submit_write(write()).unwrap();
    let f = q.fence();
    let _later = q.submit_write(write()).unwrap();
    finish(&mut q, b, 0);
    assert_eq!(q.fence_status(f), Ok(FenceStatus::Pending));
    finish(&mut q, a, 0);
    assert_eq!(q.fence_status(f), Ok(FenceStatus::Ready(Ok(()))));
    assert_eq!(q.outstanding(), 4); // result consumption not required for durability
}

#[test]
fn early_ack_is_pending_and_unknown_after_send_survives_result_poll() {
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    let t = q.submit_write(write()).unwrap();
    let f = q.fence();
    let d = q.dispatch(t, route()).unwrap();
    let mut early = MOSDOpReply::for_request(&d.message, 9);
    early.flags &= !u64::from(flag::ONDISK);
    assert!(!q.reply(t, 2, 3, early).unwrap());
    assert_eq!(q.fence_status(f), Ok(FenceStatus::Pending));
    q.cancel(t).unwrap();
    q.poll_into(&mut [None]);
    assert_eq!(
        q.fence_status(f),
        Ok(FenceStatus::Ready(Err((
            t.tid(),
            WriteFailure::PossiblySent
        ))))
    );
    assert_eq!(q.charged_bytes(), 0);
    assert_eq!(q.fence_status(q.fence()), q.fence_status(f)); // prefix failure is sticky
}

#[test]
fn earliest_admitted_failure_wins_even_if_it_completes_later() {
    let mut q = ObjectQueue::new(2, 100, 0).unwrap();
    let a = q.submit_write(write()).unwrap();
    let b = q.submit_write(write()).unwrap();
    let f = q.fence();
    finish(&mut q, b, -5);
    assert_eq!(q.fence_status(f), Ok(FenceStatus::Pending));
    finish(&mut q, a, -13);
    q.poll_into(&mut [None, None]);
    assert_eq!(
        q.fence_status(f),
        Ok(FenceStatus::Ready(Err((
            a.tid(),
            WriteFailure::Remote {
                result: -13,
                op_result: -13
            }
        ))))
    );
}

#[test]
fn earlier_fence_excludes_later_error_and_foreign_queue_is_stale() {
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    let empty = q.fence();
    let a = q.submit_write(write()).unwrap();
    let first = q.fence();
    finish(&mut q, a, 0);
    q.poll_into(&mut [None]);
    let b = q.submit_write(write()).unwrap();
    q.cancel(b).unwrap();
    q.poll_into(&mut [None]);
    assert_eq!(q.fence_status(first), Ok(FenceStatus::Ready(Ok(()))));
    assert_eq!(q.fence_status(empty), Ok(FenceStatus::Ready(Ok(()))));
    assert_eq!(
        q.fence_status(q.fence()),
        Ok(FenceStatus::Ready(Err((b.tid(), WriteFailure::Unsent))))
    );
    let other = ObjectQueue::new(1, 100, 0).unwrap();
    assert_eq!(other.fence_status(first), Err(DriverError::Stale));
}

#[test]
fn retirement_is_explicit_complete_and_invalidates_old_fence_epoch() {
    let mut q = ObjectQueue::new(2, 100, 7).unwrap();
    let a = q.submit_write(write()).unwrap();
    let early = q.fence();
    assert_eq!(q.retire_fence(early), Err(DriverError::FenceBusy));
    let b = q.submit_write(write()).unwrap();
    q.cancel(a).unwrap();
    assert_eq!(q.retire_fence(early), Err(DriverError::FenceBusy)); // later admission outside capture
    q.cancel(b).unwrap();
    let all = q.fence();
    assert!(matches!(
        q.fence_status(all),
        Ok(FenceStatus::Ready(Err(_)))
    ));
    q.retire_fence(all).unwrap();
    assert_eq!(q.fence_status(all), Err(DriverError::Stale));
    assert_eq!(q.fence_status(early), Err(DriverError::Stale));
    let mut out = [None, None];
    assert_eq!(q.poll_into(&mut out), 2);
    assert_eq!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::CanceledUnsent
    );
    let c = q.submit_write(write()).unwrap();
    assert!(c.tid() > b.tid());
    let d = q.dispatch(c, route()).unwrap();
    assert_eq!(d.message.client_inc, 7);
    q.reply(c, 2, 3, MOSDOpReply::for_request(&d.message, 9))
        .unwrap();
    assert_eq!(q.fence_status(q.fence()), Ok(FenceStatus::Ready(Ok(()))));
}

#[test]
fn local_first_attempt_failure_keeps_unsent_fence_until_explicit_retirement() {
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    let t = q.submit_write(write()).unwrap();
    let f = q.fence();
    let d = q.dispatch(t, route()).unwrap();
    q.reject_unaccepted(d, LocalRequestError::OutputLimit)
        .unwrap();
    assert_eq!(
        q.fence_status(f),
        Ok(FenceStatus::Ready(Err((t.tid(), WriteFailure::Unsent))))
    );
    assert!(q.charged_bytes() > 0);
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert_eq!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::LocalRejected {
            error: LocalRequestError::OutputLimit,
            possibly_sent: false
        }
    );
    assert_eq!(q.charged_bytes(), 0);
    q.retire_fence(f).unwrap();
    let next = q.submit_write(write()).unwrap();
    let next_fence = q.fence();
    finish(&mut q, next, 0);
    assert_eq!(q.fence_status(next_fence), Ok(FenceStatus::Ready(Ok(()))));
}
