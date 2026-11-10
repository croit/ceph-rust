// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::PgT;
use opwire::{MOSDOpReply, flag, op};
use rustyrados::*;

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
fn request(operation: WriteOperation, payload: Bytes) -> WriteRequest {
    WriteRequest {
        target: Target {
            pool: 7,
            object: b"write".to_vec(),
            namespace: vec![],
            locator: vec![],
        },
        operation,
        payload,
    }
}

#[test]
fn eagain_mutation_redrive_requires_opt_in_and_keeps_logical_ownership() {
    for enabled in [false, true] {
        let mut q = ObjectQueue::with_retry_limit(1, 100, 0, 3).unwrap();
        if enabled {
            q.enable_mutation_retries().unwrap();
        }
        let token = q
            .submit_write(request(WriteOperation::Append, Bytes::from_static(b"once")))
            .unwrap();
        q.set_deadline_us(token, 100, 100).unwrap();
        let first = q.dispatch(token, route()).unwrap();
        let mut again = MOSDOpReply::for_request(&first.message, 9);
        again.result = -11;
        assert_eq!(
            q.reply_for_recovery(token, 2, 3, again),
            Ok(if enabled {
                ReplyAction::Recover
            } else {
                ReplyAction::Completed
            })
        );
        let mut out = [None];
        if enabled {
            assert_eq!(q.poll_into(&mut out), 0);
            q.retry(token).unwrap();
            let next = q.dispatch(token, route()).unwrap();
            assert_eq!(next.token, token);
            assert_ne!(next.wire_tid(), first.wire_tid());
            assert_eq!(next.message.ops, first.message.ops);
            assert_eq!(q.deadline_us(token), Some(100));
            assert_eq!(
                q.reply_for_recovery(token, 2, 3, MOSDOpReply::for_request(&next.message, 9)),
                Ok(ReplyAction::Completed)
            );
        }
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(
            matches!(out[0].as_ref().unwrap().outcome,ReadOutcome::Remote {result,..} if result==if enabled {0} else {-11})
        );
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn owned_write_variants_encode_expected_extent_and_shared_input() {
    for (operation, code, offset) in [
        (WriteOperation::Write { offset: 19 }, op::WRITE, 19),
        (WriteOperation::WriteFull, op::WRITEFULL, 0),
        (WriteOperation::Append, op::APPEND, 0),
    ] {
        let data = Bytes::from(vec![42; 16]);
        let ptr = data.as_ptr();
        let mut q = ObjectQueue::new(1, 100, 4).unwrap();
        let t = q.submit_write(request(operation, data)).unwrap();
        let d = q.dispatch(t, route()).unwrap();
        assert_eq!(d.message.ops[0].op, code);
        assert_eq!(d.message.ops[0].extent().offset, offset);
        assert_eq!(d.message.ops[0].extent().length, 16);
        assert_eq!(d.message.ops[0].indata.as_ptr(), ptr);
        assert_eq!(
            (d.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
            flag::WRITE | flag::ONDISK | flag::RWORDERED
        );
        assert_eq!(d.message.snapid, opwire::NOSNAP);
        let retained = d.message.ops[0].indata.clone();
        q.cancel(t).unwrap();
        q.poll_into(&mut [None]);
        assert_eq!(&retained[..], &[42; 16]); // transport lease survives logical reclamation
    }
}

#[test]
fn early_ack_cannot_publish_write_success_or_release_credit() {
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    let t = q
        .submit_write(request(
            WriteOperation::WriteFull,
            Bytes::from_static(b"abc"),
        ))
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    let mut early = MOSDOpReply::for_request(&d.message, 9);
    early.flags &= !u64::from(flag::ONDISK);
    assert!(!q.reply(t, 2, 3, early).unwrap());
    assert!(q.is_pending(t));
    assert!(q.charged_bytes() >= 3);
    assert_eq!(q.poll_into(&mut [None]), 0);
    let durable = MOSDOpReply::for_request(&d.message, 9);
    assert!(q.reply(t, 2, 3, durable.clone()).unwrap());
    assert_eq!(q.reply(t, 2, 3, durable), Err(DriverError::Stale));
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert!(matches!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::Remote { result: 0, .. }
    ));
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn write_rejection_returns_payload_and_checks_overflow() {
    let bytes = Bytes::from(vec![7; 16]);
    let ptr = bytes.as_ptr();
    let mut q = ObjectQueue::new(1, 1, 0).unwrap();
    let rejected = q
        .submit_write(request(WriteOperation::Append, bytes))
        .unwrap_err();
    assert_eq!(rejected.reason, AdmissionError::NoCredit);
    assert_eq!(rejected.request.payload.as_ptr(), ptr);
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    assert_eq!(
        q.submit_write(request(
            WriteOperation::Write { offset: u64::MAX },
            Bytes::from_static(b"ab")
        ))
        .unwrap_err()
        .reason,
        AdmissionError::InvalidExtent
    );
    let t = q
        .submit_write(request(WriteOperation::WriteFull, Bytes::new()))
        .unwrap();
    assert_eq!(
        q.dispatch(t, route()).unwrap().message.ops[0]
            .extent()
            .length,
        0
    );
}

#[test]
fn mutations_never_retry_and_negative_reply_remains_distinct_from_unknown_outcome() {
    let mut q = ObjectQueue::with_retry_limit(2, 100, 0, 8).unwrap();
    let a = q
        .submit_write(request(WriteOperation::Append, Bytes::from_static(b"ab")))
        .unwrap();
    let d = q.dispatch(a, route()).unwrap();
    assert_eq!(q.retry(a), Err(DriverError::UnsupportedRetry));
    let mut error = MOSDOpReply::for_request(&d.message, 9);
    error.result = -13;
    error.ops[0].rval = -13;
    q.reply(a, 2, 3, error).unwrap();
    let b = q
        .submit_write(request(WriteOperation::Append, Bytes::from_static(b"ab")))
        .unwrap();
    q.dispatch(b, route()).unwrap();
    q.cancel(b).unwrap();
    let mut out = [None, None];
    q.poll_into(&mut out);
    assert!(matches!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::Remote { result: -13, .. }
    ));
    assert_eq!(out[1].as_ref().unwrap().outcome, ReadOutcome::PossiblySent);
}

#[test]
fn write_reply_with_unexpected_output_is_not_published() {
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    let t = q
        .submit_write(request(WriteOperation::Append, Bytes::new()))
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    let mut bad = MOSDOpReply::for_request(&d.message, 9);
    bad.ops[0].outdata = Bytes::from_static(b"bad");
    assert_eq!(q.reply(t, 2, 3, bad), Err(DriverError::InvalidReply));
    assert!(q.is_pending(t));
    assert_eq!(q.poll_into(&mut [None]), 0);
}

#[test]
fn explicit_mutation_retry_requires_deadline_and_keeps_immutable_request_identity() {
    let mut q = ObjectQueue::with_retry_limit(1, 100, 9, 2).unwrap();
    q.enable_mutation_retries().unwrap();
    let t = q
        .submit_write(request(WriteOperation::Append, Bytes::from_static(b"once")))
        .unwrap();
    assert_eq!(
        q.enable_mutation_retries(),
        Err(DriverError::AlreadyDispatched)
    );
    let first = q.dispatch(t, route()).unwrap();
    assert_eq!(q.retry(t), Err(DriverError::DeadlineRequired));
    q.cancel(t).unwrap();
    q.poll_into(&mut [None]);
    let t = q
        .submit_write(request(WriteOperation::Append, Bytes::from_static(b"once")))
        .unwrap();
    q.set_deadline_us(t, 100, 100).unwrap();
    let a = q.dispatch(t, route()).unwrap();
    let credit = q.charged_bytes();
    q.retry(t).unwrap();
    let changed = ReadRoute {
        direct_read: false,
        osd: 5,
        session: 7,
        epoch: 10,
        ..route()
    };
    let b = q.dispatch(t, changed).unwrap();
    assert_eq!(a.token, b.token);
    assert_eq!(a.message.reqid, b.message.reqid);
    assert_eq!(a.message.client_inc, b.message.client_inc);
    assert_eq!(a.message.oid, b.message.oid);
    assert_eq!(a.message.ops, b.message.ops);
    assert_eq!(b.message.retry_attempt, 1);
    assert_eq!(
        a.message.ops[0].indata.as_ptr(),
        b.message.ops[0].indata.as_ptr()
    );
    assert_eq!(q.charged_bytes(), credit);
    assert_eq!(q.next_deadline_us(), Some(100));
    assert_eq!(
        q.reply(t, 2, 3, MOSDOpReply::for_request(&a.message, 9)),
        Err(DriverError::Stale)
    );
    assert_eq!(q.retry(t), Err(DriverError::RetryExhausted));
    q.reply(t, 5, 7, MOSDOpReply::for_request(&b.message, 10))
        .unwrap();
    assert_eq!(q.poll_into(&mut [None]), 1);
    assert_eq!(first.message.ops[0].op, op::APPEND);
}

#[test]
fn blocklisted_append_is_never_retried_even_when_lost_reply_retries_enabled() {
    let mut q = ObjectQueue::with_retry_limit(1, 100, 0, 3).unwrap();
    q.enable_mutation_retries().unwrap();
    let token = q
        .submit_write(request(WriteOperation::Append, Bytes::from_static(b"once")))
        .unwrap();
    q.set_deadline_us(token, 100, 100).unwrap();
    let fence = q.fence();
    let dispatch = q.dispatch(token, route()).unwrap();
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
    reply.result = -108;
    reply.ops[0].rval = 0;
    reply.flags = u64::from(flag::ACK);
    assert_eq!(
        q.reply_for_recovery(token, 2, 3, reply),
        Ok(ReplyAction::Completed)
    );
    assert!(q.retry(token).is_err());
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert_eq!(out[0].as_ref().unwrap().token, token);
    assert!(matches!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::Remote {
            result: -108,
            op_result: 0,
            ..
        }
    ));
    assert!(matches!(
        q.fence_status(fence),
        Ok(FenceStatus::Ready(Err((
            _,
            WriteFailure::Remote { result: -108, .. }
        ))))
    ));
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
    q.retire_fence(fence).unwrap();
}
