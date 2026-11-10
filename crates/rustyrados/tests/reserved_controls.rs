// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use rustyrados::*;
fn target() -> Target {
    Target {
        pool: 1,
        object: vec![1],
        namespace: vec![],
        locator: vec![],
    }
}
fn read() -> ReadRequest {
    ReadRequest {
        target: target(),
        offset: 0,
        length: 4,
    }
}
fn control() -> ControlRequest {
    ControlRequest {
        target: target(),
        operation: ControlOperation::Ping {
            cookie: 1,
            generation: 0,
        },
    }
}
fn queue() -> ObjectQueue {
    ObjectQueue::with_control_reserve(1, 5, 1, 1, 0, 1).unwrap()
}
fn route() -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 1,
        osd: 1,
        session: 1,
        pg: denc::types::PgT {
            pool: 1,
            ..Default::default()
        },
        hash: 0,
        epoch: 1,
        features: 0,
        generation: 1,
        pool: rustyrados::PoolRoute::Replicated,
    }
}
#[test]
fn held_application_results_cannot_starve_reserved_slots_or_bytes() {
    let mut q = queue();
    let data = q.submit(read()).unwrap();
    q.cancel(data).unwrap();
    assert_eq!(q.charged_bytes(), 5);
    assert_eq!(
        q.submit(read()).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    let renewal = q.submit_reserved_control(control()).unwrap();
    assert_eq!(
        rustyrados::sequence_of_tid(renewal.tid()),
        rustyrados::sequence_of_tid(data.tid()) + 1
    );
    q.cancel(renewal).unwrap();
    assert_eq!(q.reserved_control_bytes(), 1);
    assert_eq!(q.reserved_control_outstanding(), 1);
    assert_eq!(
        q.submit_reserved_control(control()).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert_eq!(out[0].as_ref().unwrap().token, data);
    assert_eq!(q.charged_bytes(), 1);
    let next = q.submit(read()).unwrap();
    assert_eq!(
        rustyrados::sequence_of_tid(next.tid()),
        rustyrados::sequence_of_tid(renewal.tid()) + 1
    );
    assert!(q.take_reserved_completion(renewal).is_some());
    assert!(q.take_reserved_completion(renewal).is_none());
    assert_eq!(q.reserved_control_bytes(), 0);
    assert_eq!(q.charged_bytes(), 5);
}
#[test]
fn reserved_quota_cannot_borrow_application_credit_and_rejection_preserves_input() {
    let mut q = queue();
    let mut large = control();
    large.target.object = vec![2, 3];
    let ptr = large.target.object.as_ptr();
    let rejected = q.submit_reserved_control(large).unwrap_err();
    assert_eq!(rejected.reason, AdmissionError::NoCredit);
    assert_eq!(rejected.request.target.object.as_ptr(), ptr);
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
    let reserved = q.submit_reserved_control(control()).unwrap();
    assert_eq!(rustyrados::sequence_of_tid(reserved.tid()), 1);
    assert!(q.submit(read()).is_ok());
}
#[test]
fn public_poll_skips_internal_results_and_exact_take_cannot_steal_user_results() {
    let mut q = ObjectQueue::with_control_reserve(2, 10, 2, 2, 0, 1).unwrap();
    let a = q.submit(read()).unwrap();
    let b = q.submit(read()).unwrap();
    let c = q.submit_reserved_control(control()).unwrap();
    let d = q.submit_reserved_control(control()).unwrap();
    assert!(q.take_reserved_completion(c).is_none());
    q.cancel(c).unwrap();
    q.cancel(b).unwrap();
    q.cancel(d).unwrap();
    q.cancel(a).unwrap();
    assert!(q.take_reserved_completion(a).is_none());
    let mut other = queue();
    let foreign = other.submit_reserved_control(control()).unwrap();
    other.cancel(foreign).unwrap();
    assert!(q.take_reserved_completion(foreign).is_none());
    let mut out = [None, None, None];
    assert_eq!(q.poll_into(&mut out), 2);
    assert_eq!(out[0].as_ref().unwrap().token, b);
    assert_eq!(out[1].as_ref().unwrap().token, a);
    assert!(out[2].is_none());
    assert_eq!(q.outstanding(), 2);
    assert_eq!(q.take_reserved_completion(d).unwrap().token, d);
    assert_eq!(q.take_reserved_completion(c).unwrap().token, c);
    let next = q.submit_reserved_control(control()).unwrap();
    assert!(q.take_reserved_completion(c).is_none());
    assert!(q.is_pending(next));
}
#[test]
fn internal_deadline_results_retain_credit_until_exact_consumption() {
    let mut q = queue();
    let c = q.submit_reserved_control(control()).unwrap();
    q.set_deadline_us(c, 10, 10).unwrap();
    assert_eq!(q.expire_us(10, 1), 1);
    assert_eq!(q.poll_into(&mut [None]), 0);
    assert_eq!(q.reserved_control_outstanding(), 1);
    let result = q.take_reserved_completion(c).unwrap();
    assert!(matches!(
        result.outcome,
        ReadOutcome::Deadline {
            possibly_sent: false
        }
    ));
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
    assert!(q.submit_reserved_control(control()).is_ok());
}
#[test]
fn internal_registration_durability_and_failures_do_not_change_application_fence() {
    let mut q = queue();
    let prefix = q.fence();
    let mut register = control();
    register.operation = ControlOperation::Register {
        cookie: 1,
        timeout_seconds: 30,
    };
    let c = q.submit_reserved_control(register).unwrap();
    assert_eq!(q.fence(), prefix);
    assert_eq!(q.fence_status(prefix), Ok(FenceStatus::Ready(Ok(()))));
    let d = q.dispatch(c, route()).unwrap();
    let mut reply = opwire::MOSDOpReply::for_request(&d.message, 1);
    reply.flags &= !u64::from(opwire::flag::ONDISK);
    q.reply(c, 1, 1, reply.clone()).unwrap();
    assert!(q.take_reserved_completion(c).is_none());
    reply.flags |= u64::from(opwire::flag::ONDISK);
    q.reply(c, 1, 1, reply).unwrap();
    assert!(q.take_reserved_completion(c).is_some());
    let mut register = control();
    register.operation = ControlOperation::Register {
        cookie: 1,
        timeout_seconds: 30,
    };
    let c = q.submit_reserved_control(register).unwrap();
    q.cancel(c).unwrap();
    assert_eq!(q.fence_status(prefix), Ok(FenceStatus::Ready(Ok(()))));
    q.retire_fence(prefix).unwrap();
    assert!(q.take_reserved_completion(c).is_some());
    // Explicit application controls retain their prior fence semantics.
    let mut register = control();
    register.operation = ControlOperation::Register {
        cookie: 1,
        timeout_seconds: 30,
    };
    let c = q.submit_control(register).unwrap();
    let prefix = q.fence();
    assert_eq!(q.fence_status(prefix), Ok(FenceStatus::Pending));
    q.cancel(c).unwrap();
    assert!(matches!(
        q.fence_status(prefix),
        Ok(FenceStatus::Ready(Err(_)))
    ));
}
#[test]
fn constructors_and_no_reserve_defaults_preserve_identity_and_bounds() {
    assert!(ObjectQueue::with_control_reserve(usize::MAX, 1, 1, 1, 0, 1).is_none());
    assert!(ObjectQueue::with_control_reserve(1, u64::MAX, 1, 1, 0, 1).is_none());
    assert!(ObjectQueue::with_control_reserve(1, 1, 0, 1, 0, 1).is_none());
    let mut q = ObjectQueue::new(1, 5, 0).unwrap();
    assert_eq!(
        q.submit_reserved_control(control()).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    assert_eq!(
        rustyrados::sequence_of_tid(q.submit(read()).unwrap().tid()),
        1
    );
}

#[test]
fn completed_application_write_fence_retires_while_internal_registration_is_pending() {
    let mut q = queue();
    let user = q
        .submit_write(WriteRequest {
            target: target(),
            operation: WriteOperation::WriteFull,
            payload: bytes::Bytes::from_static(b"abc"),
        })
        .unwrap();
    let d = q.dispatch(user, route()).unwrap();
    q.reply(user, 1, 1, opwire::MOSDOpReply::for_request(&d.message, 1))
        .unwrap();
    let prefix = q.fence();
    let mut r = control();
    r.operation = ControlOperation::Register {
        cookie: 1,
        timeout_seconds: 30,
    };
    let internal = q.submit_reserved_control(r).unwrap();
    assert!(internal.tid() > user.tid());
    assert_eq!(q.fence(), prefix);
    assert_eq!(q.fence_status(prefix), Ok(FenceStatus::Ready(Ok(()))));
    q.retire_fence(prefix).unwrap();
    assert!(q.is_pending(internal));
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert_eq!(out[0].as_ref().unwrap().token, user);
    q.cancel(internal).unwrap();
    assert_eq!(q.fence_status(q.fence()), Ok(FenceStatus::Ready(Ok(()))));
    assert!(q.take_reserved_completion(internal).is_some());
}

#[test]
fn reserved_contextual_registration_uses_server_default_and_private_completions() {
    let mut q = ObjectQueue::with_control_reserve(1, 4096, 1, 4096, 0, 1).unwrap();
    let mut snapshots = Vec::with_capacity(16);
    snapshots.extend([9, 7]);
    let context = RequestContext {
        snap_sequence: 9,
        snapshots,
        ..Default::default()
    };
    let t = q
        .submit_reserved_control_with_context(
            ControlRequest {
                target: target(),
                operation: ControlOperation::Register {
                    cookie: 1,
                    timeout_seconds: 0,
                },
            },
            context,
        )
        .unwrap();
    assert!(q.charged_bytes() >= 16 * 8);
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(d.message.ops[0].watch().timeout, 0);
    assert_eq!(d.message.snap_seq, 9);
    assert_eq!(d.message.snaps, vec![9, 7]);
    let r = opwire::MOSDOpReply::for_request(&d.message, 1);
    assert!(q.reply(t, 1, 1, r).unwrap());
    assert_eq!(q.poll_into(&mut [None]), 0);
    assert!(q.take_reserved_completion(t).is_some());
    assert_eq!(q.reserved_control_outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn control_private_guard_is_ordered_validated_and_removed_without_hiding_public_status() {
    for kind in 0..4 {
        for version in [0, 37] {
            for result in [0, -34] {
                let mut q = ObjectQueue::with_control_reserve(1, 4096, 1, 4096, 0, 1).unwrap();
                let operation = match kind {
                    0 => ControlOperation::Register {
                        cookie: 1,
                        timeout_seconds: 0,
                    },
                    1 => ControlOperation::Unwatch { cookie: 1 },
                    2 => ControlOperation::Notify {
                        cookie: 1,
                        timeout_seconds: 1,
                        payload: b"input".as_slice().into(),
                    },
                    3 => ControlOperation::NotifyAck {
                        cookie: 1,
                        notify_id: 2,
                        response: b"ack".as_slice().into(),
                    },
                    _ => unreachable!(),
                };
                let token = q
                    .submit_reserved_control_with_context(
                        ControlRequest {
                            target: target(),
                            operation,
                        },
                        RequestContext {
                            control_assert_version: version,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                let d = q.dispatch(token, route()).unwrap();
                let prefix = usize::from(version != 0);
                assert_eq!(d.message.ops.len(), prefix + 1);
                if prefix != 0 {
                    assert_eq!(d.message.ops[0], opwire::OsdOp::assert_version(version));
                }
                let public = &d.message.ops[prefix];
                assert_eq!(
                    public.op,
                    match kind {
                        0 | 1 => opwire::op::WATCH,
                        2 => opwire::op::NOTIFY,
                        3 => opwire::op::NOTIFY_ACK,
                        _ => unreachable!(),
                    }
                );
                let mut reply = opwire::MOSDOpReply::for_request(&d.message, 1);
                reply.result = result;
                reply.user_version = 73;
                if prefix != 0 && result < 0 {
                    reply.ops[0].rval = result;
                }
                if kind == 2 && result == 0 {
                    reply.ops[prefix].outdata = 9u64.to_le_bytes().to_vec().into();
                }
                let mut malformed = Vec::new();
                let mut missing = reply.clone();
                missing.ops.clear();
                malformed.push(missing);
                let mut extra = reply.clone();
                extra.ops.push(opwire::OsdOp::assert_version(11));
                malformed.push(extra);
                if prefix != 0 {
                    let mut stripped = reply.clone();
                    stripped.ops.remove(0);
                    malformed.push(stripped);
                    let mut private_only = reply.clone();
                    private_only.ops.truncate(1);
                    malformed.push(private_only);
                    let mut wrong_guard = reply.clone();
                    wrong_guard.ops[0] = opwire::OsdOp::stat();
                    malformed.push(wrong_guard);
                    let mut guard_data = reply.clone();
                    guard_data.ops[0].outdata = vec![1].into();
                    malformed.push(guard_data);
                    let mut swapped = reply.clone();
                    swapped.ops.swap(0, 1);
                    malformed.push(swapped);
                } else {
                    let mut injected = reply.clone();
                    injected.ops.insert(0, opwire::OsdOp::assert_version(37));
                    malformed.push(injected);
                }
                for bad in malformed {
                    assert_eq!(q.reply(token, 1, 1, bad), Err(DriverError::InvalidReply));
                    assert!(q.take_reserved_completion(token).is_none());
                }
                assert!(q.reply(token, 1, 1, reply.clone()).unwrap());
                let done = q.take_reserved_completion(token).unwrap();
                let ReadOutcome::Remote {
                    result: actual,
                    op_result,
                    user_version,
                    data,
                } = done.outcome
                else {
                    panic!("control result must contain only the public descriptor")
                };
                assert_eq!((actual, op_result, user_version), (result, 0, 73));
                assert_eq!(data, reply.ops[prefix].outdata);
                assert!(q.take_reserved_completion(token).is_none());
                assert_eq!(q.charged_bytes(), 0);
                assert_eq!(q.poll_into(&mut [None]), 0);
            }
        }
    }
}
