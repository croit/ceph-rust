// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::PgT;
use opwire::{MOSDOpReply, flag};
use rustyrados::*;

fn request() -> ReadRequest {
    ReadRequest {
        target: Target {
            pool: 7,
            object: vec![b'o', 0, 255],
            namespace: vec![0, 1],
            locator: vec![],
        },
        offset: 10,
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

fn reply(dispatch: &ReadDispatch, data: Bytes) -> MOSDOpReply {
    let mut r = MOSDOpReply::for_request(&dispatch.message, 9);
    let mut extent = r.ops[0].extent();
    extent.length = data.len() as u64;
    r.ops[0].set_extent(extent);
    r.ops[0].outdata = data;
    r.user_version = 123;
    r
}

fn again(dispatch: &ReadDispatch) -> MOSDOpReply {
    let mut r = reply(dispatch, Bytes::new());
    r.result = -11;
    r
}

#[test]
fn validated_eagain_retains_original_read_until_bounded_redrive_completes() {
    let mut q = ReadQueue::with_retry_limit(1, 100, 12, 2).unwrap();
    let token = q.submit(request()).unwrap();
    q.set_deadline_us(token, 1_000, 1_000).unwrap();
    let first = q.dispatch(token, route()).unwrap();
    let charge = q.charged_bytes();
    assert_eq!(
        q.reply_for_recovery(token, 2, 3, again(&first)),
        Ok(ReplyAction::Recover)
    );
    assert_eq!(q.poll_into(&mut [None]), 0);
    assert_eq!(q.deadline_us(token), Some(1_000));
    assert_eq!(q.charged_bytes(), charge);
    q.retry(token).unwrap();
    let next = q.dispatch(token, route()).unwrap();
    assert_eq!(next.token, first.token);
    assert_eq!(next.message.ops[0].extent(), first.message.ops[0].extent());
    assert_eq!(next.message.retry_attempt, 1);
    assert_eq!(
        q.reply_for_recovery(token, 2, 3, again(&first)),
        Err(DriverError::Stale)
    );
    assert_eq!(
        q.reply_for_recovery(token, 2, 3, again(&next)),
        Ok(ReplyAction::Completed)
    );
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert!(matches!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::Remote { result: -11, .. }
    ));
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn malformed_eagain_never_recovers_and_negative_subop_alone_is_terminal() {
    let mut q = ReadQueue::with_retry_limit(1, 100, 0, 2).unwrap();
    let token = q.submit(request()).unwrap();
    q.set_deadline_us(token, 100, 100).unwrap();
    let first = q.dispatch(token, route()).unwrap();
    for invalid in 0..4 {
        let mut r = again(&first);
        match invalid {
            0 => r.oid.push(0),
            1 => r.ops.clear(),
            2 => r.ops[0].outdata = Bytes::from_static(b"x"),
            _ => r.flags = 0,
        }
        assert_eq!(
            q.reply_for_recovery(token, 2, 3, r),
            Err(DriverError::InvalidReply)
        );
        assert!(q.is_pending(token));
    }
    let mut r = reply(&first, Bytes::new());
    r.result = -5;
    r.ops[0].rval = -11;
    assert_eq!(
        q.reply_for_recovery(token, 2, 3, r),
        Ok(ReplyAction::Completed)
    );
}

#[test]
fn default_reply_and_missing_deadline_publish_exact_eagain() {
    for recovery in [false, true] {
        let mut q = ReadQueue::with_retry_limit(1, 100, 0, 2).unwrap();
        let token = q.submit(request()).unwrap();
        if !recovery {
            q.set_deadline_us(token, 100, 100).unwrap();
        }
        let first = q.dispatch(token, route()).unwrap();
        if recovery {
            assert_eq!(
                q.reply_for_recovery(token, 2, 3, again(&first)),
                Ok(ReplyAction::Completed)
            );
        } else {
            assert_eq!(q.reply(token, 2, 3, again(&first)), Ok(true));
        }
        let mut out = [None];
        q.poll_into(&mut out);
        assert!(matches!(
            out[0].as_ref().unwrap().outcome,
            ReadOutcome::Remote { result: -11, .. }
        ));
    }
}

#[test]
fn parallel_out_of_order_results_move_owned_payloads() {
    let mut q = ReadQueue::new(2, 100, 12).unwrap();
    let a = q.submit(request()).unwrap();
    let b = q.submit(request()).unwrap();
    let da = q.dispatch(a, route()).unwrap();
    let db = q.dispatch(b, route()).unwrap();
    assert_eq!(da.message.client_inc, 12);
    assert_eq!(da.message.reqid.inc, 12);
    assert_eq!(da.message.reqid.tid, 0); // implicit peer identity + header TID
    assert_eq!(
        (da.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
        flag::READ | flag::ONDISK
    );
    assert_ne!(a.tid(), b.tid());
    let data = Bytes::from(vec![9u8; 11]);
    let ptr = data.as_ptr();
    q.reply(b, 2, 3, reply(&db, data)).unwrap();
    q.reply(a, 2, 3, reply(&da, Bytes::new())).unwrap();
    let mut out = [None, None];
    assert_eq!(q.poll_into(&mut out), 2);
    assert_eq!(out[0].as_ref().unwrap().token, b);
    match &out[0].as_ref().unwrap().outcome {
        ReadOutcome::Remote {
            data, user_version, ..
        } => {
            assert_eq!(data.as_ptr(), ptr); // no result-boundary copy
            assert_eq!(data.len(), 11);
            assert_eq!(*user_version, 123);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn credit_covers_unconsumed_completion_and_rejection_preserves_request() {
    let mut q = ReadQueue::new(1, 100, 0).unwrap();
    let a = q.submit(request()).unwrap();
    q.cancel(a).unwrap();
    assert!(!q.is_pending(a));
    let rejected = q.submit(request()).unwrap_err();
    assert_eq!(rejected.reason, AdmissionError::NoCredit);
    assert_eq!(rejected.request, request());
    assert_eq!(q.outstanding(), 1);
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    let b = q.submit(rejected.request).unwrap();
    assert!(q.is_pending(b));
    assert!(!q.is_pending(a));
    assert!(b.tid() > a.tid());
    assert_eq!(q.cancel(a), Err(DriverError::Stale));
    q.cancel(b).unwrap();
    assert_eq!(q.poll_into(&mut out), 0); // do not overwrite caller's completion
    out[0] = None;
    assert_eq!(q.poll_into(&mut out), 1);
}

#[test]
fn extent_and_target_validation_happen_before_admission() {
    let mut q = ReadQueue::new(2, 100, 0).unwrap();
    let mut r = request();
    r.length = 0; // Ceph interprets zero as to-EOF; cannot admit without output bound
    assert_eq!(
        q.submit(r).unwrap_err().reason,
        AdmissionError::InvalidExtent
    );
    let mut r = request();
    r.offset = u64::MAX;
    assert_eq!(
        q.submit(r).unwrap_err().reason,
        AdmissionError::InvalidExtent
    );
    let mut r = request();
    r.target.pool = -1;
    assert_eq!(
        q.submit(r).unwrap_err().reason,
        AdmissionError::InvalidTarget
    );
    let mut r = request();
    r.target.object.clear();
    assert_eq!(
        q.submit(r).unwrap_err().reason,
        AdmissionError::InvalidTarget
    );
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn target_capacity_is_charged_and_bytes_recover_after_poll() {
    let mut q = ReadQueue::new(1, 100, 0).unwrap();
    let mut r = request();
    r.target.object.reserve(1000);
    assert_eq!(q.submit(r).unwrap_err().reason, AdmissionError::NoCredit);
    for _ in 0..1000 {
        let t = q.submit(request()).unwrap();
        q.cancel(t).unwrap();
        assert!(q.charged_bytes() >= 16);
        assert_eq!(q.poll_into(&mut [None]), 1);
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn unsupported_routes_are_passive_and_do_not_consume_handoff() {
    let mut q = ReadQueue::new(1, 100, 0).unwrap();
    let t = q.submit(request()).unwrap();
    for bad in [
        ReadRoute {
            generation: 1,
            pool: rustyrados::PoolRoute::Erasure(denc::types::ShardId::NO_SHARD),
            ..route()
        },
        ReadRoute {
            direct_read: false,
            base_pool: 8,
            ..route()
        },
        ReadRoute {
            session: 0,
            ..route()
        },
        ReadRoute { osd: -1, ..route() },
    ] {
        assert_eq!(q.dispatch(t, bad).unwrap_err(), DriverError::InvalidRoute);
    }
    q.cancel(t).unwrap();
    let mut out = [None];
    q.poll_into(&mut out);
    assert_eq!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::CanceledUnsent
    );
}

#[test]
fn stale_and_malformed_replies_cannot_complete_or_publish_data() {
    let mut q = ReadQueue::new(1, 100, 0).unwrap();
    let t = q.submit(request()).unwrap();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(
        q.dispatch(t, route()).unwrap_err(),
        DriverError::AlreadyDispatched
    );
    let good = reply(&d, Bytes::from_static(b"abc"));
    assert_eq!(q.reply(t, 2, 4, good.clone()), Err(DriverError::Stale));
    assert_eq!(q.reply(t, 1, 3, good.clone()), Err(DriverError::Stale));
    let mut bad = good.clone();
    bad.retry_attempt = 1;
    assert_eq!(q.reply(t, 2, 3, bad), Err(DriverError::Stale));
    let mut variants = Vec::new();
    let mut bad = good.clone();
    bad.oid.push(0);
    variants.push(bad);
    let mut bad = good.clone();
    bad.pgid.seed += 1;
    variants.push(bad);
    let mut bad = good.clone();
    bad.ops.clear();
    variants.push(bad);
    let mut bad = good.clone();
    bad.ops.push(bad.ops[0].clone());
    variants.push(bad);
    let mut bad = good.clone();
    bad.flags = 0;
    variants.push(bad);
    let mut bad = good.clone();
    bad.ops[0].op = opwire::op::WRITE;
    variants.push(bad);
    let mut bad = good.clone();
    bad.ops[0].outdata = Bytes::from(vec![0; 17]);
    variants.push(bad);
    let mut bad = good.clone();
    bad.result = -2;
    variants.push(bad);
    let mut bad = good.clone();
    bad.ops[0].rval = -5;
    variants.push(bad);
    let mut bad = good.clone();
    bad.result = 3;
    variants.push(bad);
    let mut bad = good.clone();
    let mut e = bad.ops[0].extent();
    e.length += 1;
    bad.ops[0].set_extent(e);
    variants.push(bad);
    for bad in variants {
        assert_eq!(q.reply(t, 2, 3, bad), Err(DriverError::InvalidReply));
    }
    assert_eq!(q.poll_into(&mut [None]), 0);
    q.reply(t, 2, 3, good.clone()).unwrap();
    assert_eq!(q.reply(t, 2, 3, good), Err(DriverError::Stale));
    assert_eq!(q.cancel(t), Err(DriverError::Stale));
    assert_eq!(q.poll_into(&mut [None, None]), 1);
}

#[test]
fn error_and_cancellation_certainty_stay_distinct() {
    let mut q = ReadQueue::new(2, 100, 0).unwrap();
    let a = q.submit(request()).unwrap();
    let d = q.dispatch(a, route()).unwrap();
    let mut err = reply(&d, Bytes::new());
    err.result = -2;
    err.ops[0].rval = -2;
    q.reply(a, 2, 3, err).unwrap();
    let b = q.submit(request()).unwrap();
    q.dispatch(b, route()).unwrap();
    q.cancel(b).unwrap();
    let mut out = [None, None];
    q.poll_into(&mut out);
    assert!(matches!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::Remote { result: -2, .. }
    ));
    assert_eq!(out[1].as_ref().unwrap().outcome, ReadOutcome::PossiblySent);
}

#[test]
fn foreign_queue_token_is_rejected_even_when_slot_and_tid_match() {
    let mut a = ReadQueue::new(1, 100, 0).unwrap();
    let mut b = ReadQueue::new(1, 100, 0).unwrap();
    let ta = a.submit(request()).unwrap();
    let tb = b.submit(request()).unwrap();
    assert_eq!(ta.tid(), tb.tid());
    assert_eq!(b.cancel(ta), Err(DriverError::Stale));
    b.cancel(tb).unwrap();
}

#[test]
fn retry_preserves_identity_context_credit_and_excludes_old_replies() {
    let mut q = ReadQueue::with_retry_limit(1, 100, 77, 2).unwrap();
    let t = q.submit(request()).unwrap();
    let first = q.dispatch(t, route()).unwrap();
    let old_reply = reply(&first, Bytes::from_static(b"old"));
    let charged = q.charged_bytes();
    q.retry(t).unwrap();
    assert_eq!(q.reply(t, 2, 3, old_reply.clone()), Err(DriverError::Stale));
    assert_eq!(q.retry(t), Err(DriverError::NotDispatched));
    let new_route = ReadRoute {
        direct_read: false,
        osd: 4,
        session: 9,
        epoch: 10,
        pg: PgT {
            seed: 8,
            ..route().pg
        },
        ..route()
    };
    let second = q.dispatch(t, new_route).unwrap();
    assert_eq!(first.token, second.token);
    assert_eq!(first.message.reqid, second.message.reqid);
    assert_eq!(first.message.client_inc, second.message.client_inc);
    assert_eq!(first.message.ops, second.message.ops);
    assert_eq!(first.message.oid, second.message.oid);
    assert_eq!(first.message.oloc, second.message.oloc);
    assert_eq!(second.message.retry_attempt, 1);
    assert_ne!(second.message.flags & flag::RETRY, 0);
    assert_eq!(q.charged_bytes(), charged);
    assert_eq!(q.outstanding(), 1);
    assert_eq!(q.reply(t, 2, 3, old_reply), Err(DriverError::Stale));
    let current = reply(&second, Bytes::from_static(b"new"));
    let mut stale = current.clone();
    stale.retry_attempt = 0;
    assert_eq!(q.reply(t, 4, 9, stale), Err(DriverError::Stale));
    let mut unknown = current.clone();
    unknown.retry_attempt = -1;
    assert_eq!(q.reply(t, 4, 9, unknown), Err(DriverError::Stale));
    q.reply(t, 4, 9, current).unwrap();
    assert_eq!(q.retry(t), Err(DriverError::Stale));
    assert_eq!(q.poll_into(&mut [None, None]), 1);
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn cancel_between_attempts_remains_possibly_sent() {
    let mut q = ReadQueue::with_retry_limit(1, 100, 0, 2).unwrap();
    let t = q.submit(request()).unwrap();
    q.dispatch(t, route()).unwrap();
    q.retry(t).unwrap();
    q.cancel(t).unwrap();
    let mut out = [None];
    q.poll_into(&mut out);
    assert_eq!(out[0].as_ref().unwrap().outcome, ReadOutcome::PossiblySent);
}

#[test]
fn retry_budget_and_invalid_routes_do_not_consume_extra_credit_or_attempts() {
    assert!(ReadQueue::with_retry_limit(1, 100, 0, 0).is_none());
    assert!(ReadQueue::with_retry_limit(1, 100, 0, u32::MAX).is_none());
    let mut q = ReadQueue::with_retry_limit(1, 100, 0, 2).unwrap();
    let t = q.submit(request()).unwrap();
    assert_eq!(q.retry(t), Err(DriverError::NotDispatched));
    q.dispatch(t, route()).unwrap();
    q.retry(t).unwrap();
    assert_eq!(
        q.dispatch(
            t,
            ReadRoute {
                generation: 1,
                pool: rustyrados::PoolRoute::Erasure(denc::types::ShardId::NO_SHARD),
                ..route()
            }
        )
        .unwrap_err(),
        DriverError::InvalidRoute
    );
    let second = q.dispatch(t, route()).unwrap();
    assert_eq!(second.message.retry_attempt, 1);
    assert_eq!(q.retry(t), Err(DriverError::RetryExhausted));
    q.reply(t, 2, 3, reply(&second, Bytes::new())).unwrap();
    assert_eq!(q.poll_into(&mut [None]), 1);
}

#[test]
fn default_has_one_attempt_and_same_connection_retry_ignores_old_attempt() {
    let mut default = ReadQueue::new(1, 100, 0).unwrap();
    let t = default.submit(request()).unwrap();
    default.dispatch(t, route()).unwrap();
    assert_eq!(default.retry(t), Err(DriverError::RetryExhausted));
    let mut q = ReadQueue::with_retry_limit(1, 100, 0, 2).unwrap();
    let t = q.submit(request()).unwrap();
    let first = q.dispatch(t, route()).unwrap();
    q.retry(t).unwrap();
    let second = q.dispatch(t, route()).unwrap();
    assert_eq!(
        q.reply(t, 2, 3, reply(&first, Bytes::new())),
        Err(DriverError::Stale)
    );
    q.reply(t, 2, 3, reply(&second, Bytes::new())).unwrap();
}

#[test]
fn local_unaccepted_rejection_is_typed_once_and_prior_attempts_stay_uncertain() {
    for retry in [false, true] {
        let mut q = ReadQueue::with_retry_limit(1, 100, 12, 2).unwrap();
        let token = q.submit(request()).unwrap();
        q.set_deadline_us(token, 1000, 1000).unwrap();
        let first = q.dispatch(token, route()).unwrap();
        let current = if retry {
            q.retry(token).unwrap();
            let current = q.dispatch(token, route()).unwrap();
            assert_eq!(
                q.reject_unaccepted(first, LocalRequestError::OutputLimit),
                Err(DriverError::Stale)
            );
            current
        } else {
            first
        };
        q.reject_unaccepted(current, LocalRequestError::FrameLimit)
            .unwrap();
        assert_eq!(q.next_deadline_us(), None);
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        let done = out[0].take().unwrap();
        assert_eq!(done.token, token);
        assert_eq!(
            done.outcome,
            ReadOutcome::LocalRejected {
                error: LocalRequestError::FrameLimit,
                possibly_sent: retry
            }
        );
        assert_eq!(q.poll_into(&mut out), 0);
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn retained_dispatch_identities_survive_retry_cancellation_and_slot_reuse() {
    let mut input = request();
    input.target.locator = b"locator".to_vec();
    let object = input.target.object.clone();
    let namespace = input.target.namespace.clone();
    let locator = input.target.locator.clone();
    let addresses = (
        input.target.object.as_ptr(),
        input.target.namespace.as_ptr(),
        input.target.locator.as_ptr(),
    );
    let mut queue = ReadQueue::with_retry_limit(1, 4096, 12, 4).unwrap();
    let token = queue.submit(input).unwrap();
    let first = queue.dispatch(token, route()).unwrap();
    queue.retry(token).unwrap();
    let second = queue.dispatch(token, route()).unwrap();
    for dispatch in [&first, &second] {
        assert_eq!(
            (
                dispatch.message.oid.as_ptr(),
                dispatch.message.oloc.nspace.as_ptr(),
                dispatch.message.oloc.key.as_ptr()
            ),
            addresses
        );
        assert_eq!(dispatch.message.oid, object);
        assert_eq!(dispatch.message.oloc.nspace, namespace);
        assert_eq!(dispatch.message.oloc.key, locator);
    }
    queue.cancel(token).unwrap();
    let mut completed = [None];
    assert_eq!(queue.poll_into(&mut completed), 1);
    assert_eq!(completed[0].as_ref().unwrap().token, token);
    let mut replacement = request();
    replacement.target.object = b"replacement".to_vec();
    let next = queue.submit(replacement).unwrap();
    assert_ne!(token, next);
    assert_eq!(queue.request(next).unwrap().target.object, b"replacement");
    drop(queue);
    let (encoded, _, more) = second.message.encode_parts_version(9, 0).unwrap();
    assert!(more.is_empty());
    let decoded = opwire::MOSDOp::decode_shared(9, &encoded.front, &encoded.data).unwrap();
    assert_eq!(
        (decoded.oid, decoded.oloc.nspace, decoded.oloc.key),
        (object.clone(), namespace, locator)
    );
    let retained = first.message.oid.clone();
    drop(first);
    drop(second);
    assert_eq!(retained.as_ptr(), addresses.0);
    assert_eq!(retained, object);
    let explicit: RequestIdentity = object.clone().into();
    assert_eq!(explicit, retained);
}
