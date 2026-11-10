// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::PgT;
use opwire::MOSDOpReply;
use rustyrados::*;
fn request() -> ReadRequest {
    ReadRequest {
        target: Target {
            pool: 7,
            object: b"deadline".to_vec(),
            namespace: vec![],
            locator: vec![],
        },
        offset: 0,
        length: 16,
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

#[test]
fn deadline_order_budget_and_unsent_certainty_are_explicit() {
    let mut q = ObjectQueue::new(3, 100, 0).unwrap();
    let a = q.submit(request()).unwrap();
    let b = q.submit(request()).unwrap();
    let c = q.submit(request()).unwrap();
    q.set_deadline_us(a, 30, 30).unwrap();
    q.set_deadline_us(b, 10, 10).unwrap();
    q.set_deadline_us(c, 20, 20).unwrap();
    assert_eq!(q.next_deadline_us(), Some(10));
    assert_eq!(q.expire_us(9, 3), 0);
    assert_eq!(q.expire_us(30, 1), 1);
    assert_eq!(q.next_deadline_us(), Some(20));
    let mut out = [None];
    q.poll_into(&mut out);
    let done = out[0].take().unwrap();
    assert_eq!(done.token, b);
    assert_eq!(
        done.outcome,
        ReadOutcome::Deadline {
            possibly_sent: false
        }
    );
    assert_eq!(q.expire_us(30, 0), 0);
    assert_eq!(q.expire_us(30, 2), 2);
    assert_eq!(q.next_deadline_us(), None);
}

#[test]
fn retry_keeps_absolute_deadline_and_timeout_between_attempts_is_possibly_sent() {
    let mut q = ObjectQueue::with_retry_limit(1, 100, 0, 3).unwrap();
    let t = q.submit(request()).unwrap();
    q.set_deadline_us(t, 10, 10).unwrap();
    assert_eq!(
        q.set_deadline_us(t, 20, 20),
        Err(DriverError::DeadlineAlreadySet)
    );
    q.dispatch(t, route()).unwrap();
    q.retry(t).unwrap();
    assert_eq!(q.next_deadline_us(), Some(10));
    assert_eq!(
        q.set_deadline_us(t, 30, 30),
        Err(DriverError::AlreadyDispatched)
    );
    assert_eq!(q.expire_us(10, 1), 1);
    assert_eq!(q.dispatch(t, route()).unwrap_err(), DriverError::Stale);
    let mut out = [None];
    q.poll_into(&mut out);
    assert_eq!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::Deadline {
            possibly_sent: true
        }
    );
}

#[test]
fn terminal_timer_clears_before_slot_reuse_and_old_token_cannot_change_it() {
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    let a = q.submit(request()).unwrap();
    q.set_deadline_us(a, 10, 10).unwrap();
    q.cancel(a).unwrap();
    assert_eq!(q.next_deadline_us(), None);
    q.poll_into(&mut [None]);
    let b = q.submit(request()).unwrap();
    q.set_deadline_us(b, 100, 100).unwrap();
    assert_eq!(q.set_deadline_us(a, 0, 0), Err(DriverError::Stale));
    assert_eq!(q.expire_us(10, 10), 0);
    assert!(q.is_pending(b));
}

#[test]
fn reply_and_expiry_race_publishes_exactly_one_result() {
    for reply_first in [true, false] {
        let mut q = ObjectQueue::new(1, 100, 0).unwrap();
        let t = q.submit(request()).unwrap();
        q.set_deadline_us(t, 10, 10).unwrap();
        let d = q.dispatch(t, route()).unwrap();
        let mut r = MOSDOpReply::for_request(&d.message, 9);
        let mut e = r.ops[0].extent();
        e.length = 0;
        r.ops[0].set_extent(e);
        if reply_first {
            q.reply(t, 2, 3, r).unwrap();
            assert_eq!(q.expire_us(10, 1), 0);
        } else {
            assert_eq!(q.expire_us(10, 1), 1);
            assert_eq!(q.reply(t, 2, 3, r), Err(DriverError::Stale));
        }
        assert_eq!(q.poll_into(&mut [None, None]), 1);
        assert_eq!(q.poll_into(&mut [None]), 0);
    }
}

#[test]
fn timed_out_write_fence_never_claims_durability() {
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    let t = q
        .submit_write(WriteRequest {
            target: request().target,
            operation: WriteOperation::Append,
            payload: Bytes::from_static(b"append"),
        })
        .unwrap();
    q.set_deadline_us(t, 10, 10).unwrap();
    let f = q.fence();
    q.dispatch(t, route()).unwrap();
    q.expire_us(10, 1);
    q.poll_into(&mut [None]);
    assert_eq!(
        q.fence_status(f),
        Ok(FenceStatus::Ready(Err((
            t.tid(),
            WriteFailure::PossiblySent
        ))))
    );
}
