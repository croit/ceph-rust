// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::PgT;
use opwire::{MOSDOpReply, OsdOp, flag, op};
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
fn request(classes: bool) -> CompoundRequest {
    CompoundRequest {
        target: Target {
            pool: 7,
            object: b"compound-retry".to_vec(),
            namespace: vec![0, 255],
            locator: b"key".to_vec(),
        },
        access: Access::Read,
        context: RequestContext {
            snapid: 17,
            ..Default::default()
        },
        operations: if classes {
            vec![
                OsdOp::call(b"rbd", b"get_size", &opwire::NOSNAP.to_le_bytes()),
                OsdOp::call(b"rbd", b"get_features", &opwire::NOSNAP.to_le_bytes()),
            ]
        } else {
            vec![OsdOp::read(19, 4), OsdOp::getxattr(b"bin")]
        },
        max_output_bytes: 64,
    }
}
fn reply(d: &ReadDispatch) -> MOSDOpReply {
    let mut r = MOSDOpReply::for_request(&d.message, d.route.epoch);
    for (i, o) in r.ops.iter_mut().enumerate() {
        o.outdata = match o.op {
            op::READ => Bytes::from_static(b"read"),
            op::GETXATTR => Bytes::from_static(&[255, 0]),
            op::CALL => {
                if i == 0 {
                    let mut v = vec![22];
                    v.extend_from_slice(&1_234_567u64.to_le_bytes());
                    v.into()
                } else {
                    vec![0; 16].into()
                }
            }
            _ => unreachable!(),
        };
        if matches!(o.op, op::READ | op::CALL) {
            let mut e = o.extent();
            e.length = o.outdata.len() as u64;
            o.set_extent(e);
        }
    }
    r
}
#[test]
fn readonly_data_and_class_retry_keep_original_image_snapshot_credit_and_deadline() {
    for family in 0..3 {
        let mut q = ObjectQueue::with_retry_limit(1, 8192, 9, 3).unwrap();
        let mut request = request(family != 0);
        if family == 2 {
            request.operations = vec![
                OsdOp::call(b"version", b"read", b""),
                OsdOp::call(b"journal", b"get_order", b""),
            ];
        }
        let t = q.submit_compound(request).unwrap();
        q.set_deadline_us(t, 100, 100).unwrap();
        let charged = q.charged_bytes();
        let fence = q.fence();
        let old = q.dispatch(t, route()).unwrap();
        q.retry(t).unwrap();
        assert_eq!(q.deadline_us(t), Some(100));
        assert_eq!(q.charged_bytes(), charged);
        let fresh_route = ReadRoute {
            session: 4,
            epoch: 10,
            hash: 57,
            ..route()
        };
        let fresh = q.dispatch(t, fresh_route).unwrap();
        assert_eq!(fresh.token, old.token);
        assert_eq!(fresh.message.retry_attempt, 1);
        assert_eq!(fresh.message.flags, old.message.flags | flag::RETRY);
        assert_eq!(fresh.message.ops, old.message.ops);
        assert_eq!(fresh.message.snapid, 17);
        assert_eq!(fresh.message.oloc, old.message.oloc);
        assert_eq!(fresh.message.reqid, old.message.reqid);
        assert_eq!(
            fresh.message.ops[0].indata.as_ptr(),
            old.message.ops[0].indata.as_ptr()
        );
        assert_eq!(q.reply(t, 2, 3, reply(&old)), Err(DriverError::Stale));
        assert!(q.is_pending(t));
        assert_eq!(q.fence_status(fence), Ok(FenceStatus::Ready(Ok(()))));
        assert!(q.reply(t, 2, 4, reply(&fresh)).unwrap());
        assert_eq!(q.reply(t, 2, 4, reply(&fresh)), Err(DriverError::Stale));
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(
            matches!(&out[0].as_ref().unwrap().outcome,ReadOutcome::RemoteCompound{result:0,operations,..} if operations.len()==2)
        );
        assert_eq!(q.charged_bytes(), 0);
        assert_eq!(q.retry(t), Err(DriverError::Stale));
    }
}
#[test]
fn readonly_retry_requires_deadline_and_finite_attempts_and_preserves_expired_certainty() {
    let mut q = ObjectQueue::with_retry_limit(1, 8192, 9, 2).unwrap();
    let t = q.submit_compound(request(true)).unwrap();
    q.dispatch(t, route()).unwrap();
    assert_eq!(q.retry(t), Err(DriverError::DeadlineRequired));
    q.cancel(t).unwrap();
    q.poll_into(&mut [None]);
    let t = q.submit_compound(request(false)).unwrap();
    q.set_deadline_us(t, 100, 100).unwrap();
    q.dispatch(t, route()).unwrap();
    q.retry(t).unwrap();
    q.dispatch(
        t,
        ReadRoute {
            session: 4,
            ..route()
        },
    )
    .unwrap();
    assert_eq!(q.retry(t), Err(DriverError::RetryExhausted));
    assert_eq!(q.deadline_us(t), Some(100));
    assert!(q.expire_token_us(t, 100).unwrap());
    let mut out = [None];
    q.poll_into(&mut out);
    assert_eq!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::Deadline {
            possibly_sent: true
        }
    );
    assert_eq!(q.charged_bytes(), 0);
    let mut mutation = request(true);
    mutation.access = Access::ReadWrite;
    mutation.context.snapid = opwire::NOSNAP;
    let t = q.submit_compound(mutation).unwrap();
    q.set_deadline_us(t, 200, 200).unwrap();
    q.dispatch(t, route()).unwrap();
    assert_eq!(q.retry(t), Err(DriverError::UnsupportedRetry));
}
#[test]
fn explicit_fail_eagain_and_per_op_error_remain_terminal_with_owned_prefix_output() {
    for per_op in [false, true] {
        let mut q = ObjectQueue::with_retry_limit(1, 8192, 9, 3).unwrap();
        let t = q.submit_compound(request(false)).unwrap();
        q.set_deadline_us(t, 100, 100).unwrap();
        q.set_fail_on_eagain(t, !per_op).unwrap();
        let d = q.dispatch(t, route()).unwrap();
        let mut r = reply(&d);
        r.result = if per_op { 0 } else { -11 };
        r.ops[1].rval = -11;
        r.ops[1].outdata = Bytes::new();
        assert_eq!(q.reply_for_recovery(t, 2, 3, r), Ok(ReplyAction::Completed));
        let mut out = [None];
        q.poll_into(&mut out);
        assert!(
            matches!(&out[0].as_ref().unwrap().outcome,ReadOutcome::RemoteCompound{result,operations,..} if *result==if per_op{0}else{-11} && operations[0].outdata.as_ref()==b"read" && operations[1].rval == -11)
        );
        assert_eq!(q.retry(t), Err(DriverError::Stale));
    }
}

#[test]
fn compound_overall_eagain_drops_intermediate_prefix_and_retains_final_attempt_only() {
    for classes in [false, true] {
        for exhausted in [false, true] {
            let mut q = ObjectQueue::with_retry_limit(1, 8192, 9, 2).unwrap();
            let t = q.submit_compound(request(classes)).unwrap();
            q.set_deadline_us(t, 100, 100).unwrap();
            let first = q.dispatch(t, route()).unwrap();
            let charged = q.charged_bytes();
            let mut intermediate = reply(&first);
            intermediate.result = -11;
            intermediate.ops[1].rval = -11;
            intermediate.ops[1].outdata = Bytes::new();
            let prefix = intermediate.ops[0].outdata.clone();
            assert_eq!(
                q.reply_for_recovery(t, 2, 3, intermediate),
                Ok(ReplyAction::Recover)
            );
            assert_eq!(q.poll_into(&mut [None]), 0);
            assert_eq!(q.charged_bytes(), charged);
            assert_eq!(q.deadline_us(t), Some(100));
            q.retry(t).unwrap();
            let next = q.dispatch(t, route()).unwrap();
            assert_eq!(next.token, first.token);
            assert_eq!(next.message.ops, first.message.ops);
            assert_eq!(next.message.snapid, 17);
            assert_eq!(next.message.retry_attempt, 1);
            let mut final_reply = reply(&next);
            let mut bytes = prefix.to_vec();
            bytes[0] ^= 1;
            final_reply.ops[0].outdata = bytes.into();
            let final_data = final_reply.ops[0].outdata.clone();
            if exhausted {
                final_reply.result = -11;
                final_reply.ops[1].rval = -11;
                final_reply.ops[1].outdata = Bytes::new();
            }
            assert_eq!(
                q.reply_for_recovery(t, 2, 3, final_reply),
                Ok(ReplyAction::Completed)
            );
            let mut out = [None];
            assert_eq!(q.poll_into(&mut out), 1);
            let ReadOutcome::RemoteCompound {
                result, operations, ..
            } = &out[0].as_ref().unwrap().outcome
            else {
                panic!("compound")
            };
            assert_eq!(*result, if exhausted { -11 } else { 0 });
            assert_eq!(operations[0].outdata, final_data);
            assert_ne!(operations[0].outdata, prefix);
            assert_eq!(q.charged_bytes(), 0);
        }
    }
}

#[test]
fn compound_eagain_terminal_without_deadline_or_budget_or_recovery_api() {
    for case in 0..3 {
        let mut q =
            ObjectQueue::with_retry_limit(1, 8192, 9, if case == 1 { 1 } else { 3 }).unwrap();
        let t = q.submit_compound(request(false)).unwrap();
        if case != 0 {
            q.set_deadline_us(t, 100, 100).unwrap();
        }
        let d = q.dispatch(t, route()).unwrap();
        let mut r = reply(&d);
        r.result = -11;
        if case == 2 {
            assert_eq!(q.reply(t, 2, 3, r), Ok(true));
        } else {
            assert_eq!(q.reply_for_recovery(t, 2, 3, r), Ok(ReplyAction::Completed));
        }
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(
            matches!(&out[0].as_ref().unwrap().outcome, ReadOutcome::RemoteCompound{result:-11,operations,..} if operations[0].outdata.as_ref()==b"read")
        );
    }
}

#[test]
fn compound_eagain_validates_every_descriptor_and_bound_before_recovery() {
    for case in 0..5 {
        let mut q = ObjectQueue::with_retry_limit(1, 8192, 9, 3).unwrap();
        let t = q.submit_compound(request(false)).unwrap();
        q.set_deadline_us(t, 100, 100).unwrap();
        let d = q.dispatch(t, route()).unwrap();
        let mut r = reply(&d);
        r.result = -11;
        match case {
            0 => r.ops[1].op = op::SETXATTR,
            1 => r.ops[1].flags ^= 1,
            2 => {
                let mut e = r.ops[0].extent();
                e.offset += 1;
                r.ops[0].set_extent(e);
            }
            3 => r.ops[1].outdata = vec![0; 65].into(),
            4 => r.pgid.seed += 1,
            _ => unreachable!(),
        }
        if case == 3 {
            assert_eq!(q.reply_for_recovery(t, 2, 3, r), Ok(ReplyAction::Completed));
            let mut out = [None];
            assert_eq!(q.poll_into(&mut out), 1);
            assert!(matches!(
                out[0].as_ref().unwrap().outcome,
                ReadOutcome::ReplyTooLarge {
                    result: -11,
                    bytes: 69,
                    limit: 64,
                    ..
                }
            ));
            assert!(q.retry(t).is_err());
            assert_eq!(q.charged_bytes(), 0);
            continue;
        }
        assert_eq!(
            q.reply_for_recovery(t, 2, 3, r),
            Err(DriverError::InvalidReply)
        );
        assert_eq!(q.poll_into(&mut [None]), 0);
        assert!(q.is_pending(t));
        let mut valid = reply(&d);
        valid.result = -11;
        assert_eq!(
            q.reply_for_recovery(t, 2, 3, valid),
            Ok(ReplyAction::Recover)
        );
    }
}

#[test]
fn fail_on_eagain_is_frozen_on_wire_but_does_not_disable_session_retry() {
    for scalar in [false, true] {
        let mut q = ObjectQueue::with_retry_limit(1, 8192, 9, 3).unwrap();
        let t = if scalar {
            q.submit(ReadRequest {
                target: request(false).target,
                offset: 0,
                length: 4,
            })
            .unwrap()
        } else {
            q.submit_compound(request(false)).unwrap()
        };
        q.set_deadline_us(t, 100, 100).unwrap();
        assert_eq!(q.request_flags(t).unwrap() & flag::FAIL_ON_EAGAIN, 0);
        q.set_fail_on_eagain(t, true).unwrap();
        q.set_fail_on_eagain(t, false).unwrap();
        q.set_fail_on_eagain(t, true).unwrap();
        let first = q.dispatch(t, route()).unwrap();
        assert_ne!(first.message.flags & flag::FAIL_ON_EAGAIN, 0);
        assert_eq!(
            q.set_fail_on_eagain(t, false),
            Err(DriverError::AlreadyDispatched)
        );
        q.retry(t).unwrap();
        let next = q
            .dispatch(
                t,
                ReadRoute {
                    session: 4,
                    ..route()
                },
            )
            .unwrap();
        assert_ne!(next.message.flags & flag::FAIL_ON_EAGAIN, 0);
        assert_ne!(q.request_flags(t).unwrap() & flag::FAIL_ON_EAGAIN, 0);
        let mut r = if scalar {
            MOSDOpReply::for_request(&next.message, next.route.epoch)
        } else {
            reply(&next)
        };
        r.result = -11;
        assert_eq!(q.reply_for_recovery(t, 2, 4, r), Ok(ReplyAction::Completed));
        q.poll_into(&mut [None]);
        assert_eq!(q.set_fail_on_eagain(t, false), Err(DriverError::Stale));
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn compound_mutation_eagain_requires_opt_in_and_preserves_logical_ownership() {
    for enabled in [false, true] {
        let mut q = ObjectQueue::with_retry_limit(1, 8192, 9, 3).unwrap();
        if enabled {
            q.enable_mutation_retries().unwrap();
        }
        let mut req = request(true);
        req.access = Access::ReadWrite;
        req.context.snapid = opwire::NOSNAP;
        let t = q.submit_compound(req).unwrap();
        q.set_deadline_us(t, 100, 100).unwrap();
        let d = q.dispatch(t, route()).unwrap();
        let mut r = reply(&d);
        r.result = -11;
        assert_eq!(
            q.reply_for_recovery(t, 2, 3, r),
            Ok(if enabled {
                ReplyAction::Recover
            } else {
                ReplyAction::Completed
            })
        );
        let mut out = [None];
        if enabled {
            assert_eq!(q.poll_into(&mut out), 0);
            q.retry(t).unwrap();
            let next = q.dispatch(t, route()).unwrap();
            assert_ne!(next.wire_tid(), d.wire_tid());
            assert_eq!(next.token, d.token);
            assert_eq!(next.message.ops, d.message.ops);
            assert_eq!(q.deadline_us(t), Some(100));
            assert_eq!(
                q.reply_for_recovery(t, 2, 3, reply(&next)),
                Ok(ReplyAction::Completed)
            );
        }
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(matches!(
            &out[0].as_ref().unwrap().outcome,
            ReadOutcome::RemoteCompound { result, .. } if *result == if enabled {0} else {-11}
        ));
        assert_eq!(q.charged_bytes(), 0);
    }
}
