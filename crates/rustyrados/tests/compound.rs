// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::{PgT, UTime};
use opwire::{MOSDOpReply, OsdOp, flag, op, opflag};
use rustyrados::*;

fn request(operations: Vec<OsdOp>, access: Access) -> CompoundRequest {
    CompoundRequest {
        target: Target {
            pool: 7,
            object: b"metadata".to_vec(),
            namespace: vec![255, 0],
            locator: vec![],
        },
        access,
        context: RequestContext::default(),
        operations,
        max_output_bytes: 64,
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
fn ordered_payloads_context_and_descriptors_are_captured_and_owned() {
    let payload = Bytes::from(vec![42; 16]);
    let ptr = payload.as_ptr();
    let mut write = OsdOp::writefull(vec![42; 16]);
    write.indata = payload;
    let mut r = request(
        vec![write, OsdOp::setxattr(b"bin", &[255, 0]), OsdOp::stat()],
        Access::ReadWrite,
    );
    r.context.snap_sequence = 10;
    r.context.snapshots = vec![9, 4];
    r.context.mtime = UTime::new(123, 4);
    let mut q = ObjectQueue::new(1, 4096, 19).unwrap();
    let t = q.submit_compound(r).unwrap();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(
        d.message.ops.iter().map(|o| o.op).collect::<Vec<_>>(),
        vec![op::WRITEFULL, op::SETXATTR, op::STAT]
    );
    assert_eq!(d.message.ops[0].indata.as_ptr(), ptr);
    assert_eq!(d.message.snaps, vec![9, 4]);
    assert_eq!(d.message.snap_seq, 10);
    assert_eq!(d.message.mtime, UTime::new(123, 4));
    assert_eq!(d.message.oloc.nspace, vec![255, 0]);
    assert_eq!(
        (d.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
        flag::READ | flag::WRITE | flag::RWORDERED | flag::ONDISK | flag::RETURNVEC
    );
    assert_eq!(q.retry(t), Err(DriverError::UnsupportedRetry));
}

#[test]
fn rejections_preserve_owned_input_and_unsupported_lifecycles_are_passive() {
    let mut q = ObjectQueue::new(1, 1, 0).unwrap();
    let r = request(
        vec![OsdOp::call(b"hello", b"say_hello", b"world")],
        Access::ReadWrite,
    );
    let ptr = r.operations[0].indata.as_ptr();
    let rejected = q.submit_compound(r).unwrap_err();
    assert_eq!(rejected.reason, AdmissionError::NoCredit);
    assert_eq!(rejected.request.operations[0].indata.as_ptr(), ptr);
    let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
    // Cache controls have their own supported admission contract; lifecycle
    // messages and PG listings still require their dedicated owner paths.
    for code in [op::WATCH, op::NOTIFY, op::PGNLS, 0xffff] {
        assert_eq!(
            q.submit_compound(request(vec![OsdOp::new(code)], Access::ReadWrite))
                .unwrap_err()
                .reason,
            AdmissionError::UnsupportedOperation
        );
    }
    assert_eq!(q.outstanding(), 0);
}

#[test]
fn access_extent_class_input_and_snapshot_validation_are_local() {
    let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
    for r in [
        request(vec![], Access::Read),
        request(vec![OsdOp::writefull(vec![])], Access::Read),
        request(
            vec![OsdOp::call(b"hello", b"record_hello", b"world")],
            Access::Read,
        ),
        // 255 is the longest class name the u8 wire prefix can carry; `OsdOp::call` refuses longer input
        // before it reaches this queue.
        request(vec![OsdOp::call(&[42; 255], b"say", b"")], Access::Read),
    ] {
        assert_eq!(
            q.submit_compound(r).unwrap_err().reason,
            AdmissionError::InvalidOperation
        );
    }
    assert_eq!(
        q.submit_compound(request(vec![OsdOp::read(u64::MAX, 1)], Access::Read))
            .unwrap_err()
            .reason,
        AdmissionError::InvalidExtent
    );
    let mut r = request(vec![OsdOp::stat()], Access::Read);
    r.context.snapshots = vec![3];
    r.context.snap_sequence = 3;
    assert_eq!(
        q.submit_compound(r).unwrap_err().reason,
        AdmissionError::InvalidSnapshot
    );
    let mut r = request(vec![OsdOp::writefull(vec![])], Access::Write);
    r.context.snapid = 3;
    assert_eq!(
        q.submit_compound(r).unwrap_err().reason,
        AdmissionError::InvalidSnapshot
    );
    let mut r = request(vec![OsdOp::writefull(vec![])], Access::Write);
    r.context.snap_sequence = 3;
    r.context.snapshots = vec![3, 3];
    assert_eq!(
        q.submit_compound(r).unwrap_err().reason,
        AdmissionError::InvalidSnapshot
    );
    let mut r = request(vec![OsdOp::stat()], Access::Read);
    r.context.snapid = 7;
    let t = q.submit_compound(r).unwrap();
    assert_eq!(q.dispatch(t, route()).unwrap().message.snapid, 7);
}

#[test]
fn positive_results_failok_and_negative_prefix_outputs_are_not_flattened() {
    let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
    let mut missing = OsdOp::getxattr(b"absent");
    missing.flags = opflag::FAILOK;
    let t = q
        .submit_compound(request(
            vec![missing, OsdOp::call(b"hello", b"write_return_data", b"")],
            Access::ReadWrite,
        ))
        .unwrap();
    let f = q.fence();
    let d = q.dispatch(t, route()).unwrap();
    let mut reply = MOSDOpReply::for_request(&d.message, 9);
    reply.result = 42;
    reply.ops[0].rval = -61;
    reply.ops[1].rval = 42;
    reply.ops[1].outdata = Bytes::from(vec![9; 5]);
    let mut extent = reply.ops[1].extent();
    extent.length = 5;
    reply.ops[1].set_extent(extent);
    let ptr = reply.ops[1].outdata.as_ptr();
    let mut early = reply.clone();
    early.flags &= !u64::from(flag::ONDISK);
    assert!(!q.reply(t, 2, 3, early).unwrap());
    assert_eq!(q.fence_status(f), Ok(FenceStatus::Pending));
    assert!(q.reply(t, 2, 3, reply).unwrap());
    let mut out = [None];
    q.poll_into(&mut out);
    match &out[0].as_ref().unwrap().outcome {
        ReadOutcome::RemoteCompound {
            result, operations, ..
        } => {
            assert_eq!(*result, 42);
            assert_eq!(operations[0].rval, -61);
            assert_eq!(operations[1].rval, 42);
            assert_eq!(operations[1].outdata.as_ptr(), ptr);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(matches!(q.fence_status(f), Ok(FenceStatus::Ready(Err(_)))));
    q.retire_fence(f).unwrap();
    let t = q
        .submit_compound(request(
            vec![OsdOp::read(0, 8), OsdOp::getxattr(b"absent")],
            Access::Read,
        ))
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    let mut reply = MOSDOpReply::for_request(&d.message, 9);
    reply.result = -61;
    reply.ops[1].rval = -61;
    reply.ops[0].outdata = Bytes::from_static(b"prefix");
    let mut extent = reply.ops[0].extent();
    extent.length = 6;
    reply.ops[0].set_extent(extent);
    q.reply(t, 2, 3, reply).unwrap();
    q.poll_into(&mut out); // caller still owns occupied output
    out[0] = None;
    q.poll_into(&mut out);
    assert!(
        matches!(&out[0].as_ref().unwrap().outcome, ReadOutcome::RemoteCompound { result: -61, operations, .. } if &operations[0].outdata[..] == b"prefix")
    );
}

#[test]
fn response_shape_flags_and_output_budget_are_checked_before_publication() {
    let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
    let mut r = request(vec![OsdOp::stat(), OsdOp::getxattr(b"x")], Access::Read);
    r.max_output_bytes = 4;
    let t = q.submit_compound(r).unwrap();
    let d = q.dispatch(t, route()).unwrap();
    let good = MOSDOpReply::for_request(&d.message, 9);
    let mut bad = good.clone();
    bad.ops.pop();
    assert_eq!(q.reply(t, 2, 3, bad), Err(DriverError::InvalidReply));
    let mut bad = good.clone();
    bad.ops[0].op = op::READ;
    assert_eq!(q.reply(t, 2, 3, bad), Err(DriverError::InvalidReply));
    let mut bad = good.clone();
    bad.ops[0].flags = opflag::FAILOK;
    assert_eq!(q.reply(t, 2, 3, bad), Err(DriverError::InvalidReply));
    let mut bad = good;
    bad.ops[1].outdata = Bytes::from_static(b"12345");
    assert_eq!(q.poll_into(&mut [None]), 0);
    assert!(q.is_pending(t));
    assert_eq!(q.reply(t, 2, 3, bad), Ok(true));
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert_eq!(
        out[0].take().unwrap().outcome,
        ReadOutcome::ReplyTooLarge {
            result: 0,
            user_version: 0,
            bytes: 5,
            limit: 4
        }
    );
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn dynamic_output_budget_is_per_request_and_preserves_survivors_and_write_uncertainty() {
    for write in [false, true] {
        let mut operations = vec![OsdOp::read(4, 0)];
        if write {
            operations.insert(0, OsdOp::writefull(vec![42; 16]));
        }
        let mut req = request(
            operations,
            if write {
                Access::ReadWrite
            } else {
                Access::Read
            },
        );
        req.max_output_bytes = 0;
        let mut q = ObjectQueue::new(2, 8192, 1).unwrap();
        let token = q.submit_compound(req).unwrap();
        let fence = q.fence();
        let dispatch = q.dispatch(token, route()).unwrap();
        let mut response = MOSDOpReply::for_request(&dispatch.message, 9);
        response.user_version = 31337;
        let output = response.ops.last_mut().unwrap();
        output.outdata = Bytes::from_static(b"tail");
        let mut extent = output.extent();
        extent.length = 4;
        output.set_extent(extent);
        let mut malformed = response.clone();
        let op = malformed.ops.last_mut().unwrap();
        let mut extent = op.extent();
        extent.offset += 1;
        op.set_extent(extent);
        assert_eq!(
            q.reply(token, 2, 3, malformed),
            Err(DriverError::InvalidReply)
        );
        assert!(q.is_pending(token));
        assert_eq!(q.reply(token, 2, 3, response.clone()), Ok(true));
        assert_eq!(q.reply(token, 2, 3, response), Err(DriverError::Stale));
        assert_eq!(q.outstanding(), 1);
        assert!(q.charged_bytes() > 0);
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert_eq!(
            out[0].take().unwrap().outcome,
            ReadOutcome::ReplyTooLarge {
                result: 0,
                user_version: 31337,
                bytes: 4,
                limit: 0
            }
        );
        assert_eq!(q.outstanding(), 0);
        assert_eq!(q.charged_bytes(), 0);
        if write {
            assert_eq!(
                q.fence_status(fence),
                Ok(FenceStatus::Ready(Err((
                    token.tid(),
                    WriteFailure::PossiblySent
                ))))
            );
        }
        let next = q
            .submit_compound(request(vec![OsdOp::read(0, 4)], Access::Read))
            .unwrap();
        let d = q.dispatch(next, route()).unwrap();
        let mut reply = MOSDOpReply::for_request(&d.message, 9);
        reply.ops[0].outdata = Bytes::from_static(b"good");
        assert_eq!(q.reply(next, 2, 3, reply), Ok(true));
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(
            matches!(&out[0].as_ref().unwrap().outcome,ReadOutcome::RemoteCompound{operations,..} if operations[0].outdata.as_ref()==b"good")
        );
        assert_eq!(q.outstanding(), 0);
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn opted_in_compound_retry_preserves_snapshot_mtime_order_and_payloads() {
    let mut q = ObjectQueue::with_retry_limit(1, 4096, 7, 2).unwrap();
    q.enable_mutation_retries().unwrap();
    let mut r = request(
        vec![
            OsdOp::writefull(vec![42; 16]),
            OsdOp::setxattr(b"x", &[0, 255]),
        ],
        Access::ReadWrite,
    );
    r.context.snap_sequence = 10;
    r.context.snapshots = vec![9, 4];
    r.context.mtime = UTime::new(100, 4);
    let t = q.submit_compound(r).unwrap();
    q.set_deadline_us(t, 100, 100).unwrap();
    let a = q.dispatch(t, route()).unwrap();
    q.retry(t).unwrap();
    let b = q
        .dispatch(
            t,
            ReadRoute {
                session: 4,
                ..route()
            },
        )
        .unwrap();
    assert_eq!(a.token, b.token);
    assert_eq!(a.message.snaps, b.message.snaps);
    assert_eq!(a.message.snap_seq, b.message.snap_seq);
    assert_eq!(a.message.mtime, b.message.mtime);
    assert_eq!(a.message.ops, b.message.ops);
    assert_eq!(b.message.retry_attempt, 1);
    assert_eq!(q.next_deadline_us(), Some(100));
}

#[test]
fn reserved_selectors_cannot_enter_a_captured_write_snapshot_context() {
    let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
    for selector in [opwire::NOSNAP, opwire::SNAPDIR] {
        for with_list in [false, true] {
            let mut r = request(vec![OsdOp::writefull(vec![1])], Access::Write);
            r.context.snap_sequence = selector;
            if with_list {
                r.context.snapshots = vec![selector];
            }
            assert_eq!(
                q.submit_compound(r).unwrap_err().reason,
                AdmissionError::InvalidSnapshot
            );
        }
    }
    let mut r = request(vec![OsdOp::writefull(vec![1])], Access::Write);
    r.context.snap_sequence = opwire::NOSNAP - 1;
    r.context.snapshots = vec![opwire::NOSNAP - 1];
    assert!(q.submit_compound(r).is_ok());
}

#[test]
fn lock_readers_do_not_enter_write_fences_and_mutations_wait_for_durability() {
    let mut q = ObjectQueue::new(2, 8192, 0).unwrap();
    let reader = LockOperation::GetInfo {
        name: b"n".to_vec(),
    }
    .build(128)
    .unwrap();
    let read = q
        .submit_compound(reader.into_compound(request(vec![], Access::Read).target, 1024))
        .unwrap();
    let d = q.dispatch(read, route()).unwrap();
    assert_eq!(
        (d.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
        flag::READ | flag::ONDISK | flag::RETURNVEC
    );
    assert_eq!(q.retry(read), Err(DriverError::DeadlineRequired));
    assert_eq!(q.fence_status(q.fence()), Ok(FenceStatus::Ready(Ok(()))));
    let call = LockOperation::Unlock {
        name: b"n".to_vec(),
        cookie: vec![0xff, 0],
    }
    .build(128)
    .unwrap();
    let t = q
        .submit_compound(call.into_compound(request(vec![], Access::Read).target, 0))
        .unwrap();
    let f = q.fence();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(
        (d.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
        flag::READ | flag::WRITE | flag::RWORDERED | flag::ONDISK | flag::RETURNVEC
    );
    let mut early = MOSDOpReply::for_request(&d.message, 9);
    early.flags &= !u64::from(flag::ONDISK);
    assert!(!q.reply(t, 2, 3, early).unwrap());
    assert_eq!(q.fence_status(f), Ok(FenceStatus::Pending));
    assert!(
        q.reply(t, 2, 3, MOSDOpReply::for_request(&d.message, 9))
            .unwrap()
    );
    assert_eq!(q.fence_status(f), Ok(FenceStatus::Ready(Ok(()))));
}

#[test]
fn lock_assertion_is_one_ordered_server_vector_and_preserves_remote_failure() {
    let assertion = LockOperation::Assert {
        name: b"n".to_vec(),
        kind: LockKind::Exclusive,
        cookie: vec![0xff, 0],
        tag: b"tag".to_vec(),
    }
    .build(128)
    .unwrap()
    .into_op();
    let mut q = ObjectQueue::new(1, 8192, 0).unwrap();
    // The client sends one transaction; the OSD owns rollback, never a client read/write emulation.
    let t = q
        .submit_compound(request(
            vec![
                OsdOp::writefull(b"before-assert".to_vec()),
                assertion,
                OsdOp::setxattr(b"after", b"x"),
            ],
            Access::ReadWrite,
        ))
        .unwrap();
    let f = q.fence();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(
        d.message.ops.iter().map(|o| o.op).collect::<Vec<_>>(),
        vec![op::WRITEFULL, op::CALL, op::SETXATTR]
    );
    let mut r = MOSDOpReply::for_request(&d.message, 9);
    r.result = -16;
    r.ops[1].rval = -16;
    q.reply(t, 2, 3, r).unwrap();
    let mut out = [None];
    q.poll_into(&mut out);
    let ReadOutcome::RemoteCompound {
        result, operations, ..
    } = &out[0].as_ref().unwrap().outcome
    else {
        panic!()
    };
    assert!(matches!(
        LockReply::decode(
            LockReplyKind::Empty,
            *result,
            operations[1].rval,
            operations[1].outdata.clone(),
            LockDecodeLimits {
                bytes: 0,
                entries: 0
            }
        )
        .unwrap(),
        LockReply::Remote {
            result: -16,
            op_result: -16,
            ..
        }
    ));
    assert!(matches!(q.fence_status(f), Ok(FenceStatus::Ready(Err(_)))));
}

#[test]
fn lock_no_credit_returns_the_same_encoded_input() {
    let operation = LockOperation::Acquire {
        name: b"n".to_vec(),
        kind: LockKind::Exclusive,
        cookie: vec![0xff, 0],
        tag: vec![],
        description: vec![],
        duration: std::time::Duration::ZERO,
        renew: LockRenew::New,
    };
    let call = operation.build(1024).unwrap();
    let request = call.into_compound(request(vec![], Access::Read).target, 1024);
    let ptr = request.operations[0].indata.as_ptr();
    let mut q = ObjectQueue::new(1, 1, 0).unwrap();
    let rejected = q.submit_compound(request).unwrap_err();
    assert_eq!(rejected.reason, AdmissionError::NoCredit);
    assert_eq!(rejected.request.operations[0].indata.as_ptr(), ptr);
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn blocklisted_remote_error_is_terminal_and_failed_write_fence_survives_drain() {
    for (operations, access) in [
        (vec![OsdOp::writefull(vec![99; 16])], Access::ReadWrite),
        (vec![OsdOp::read(0, 16)], Access::Read),
    ] {
        let mut q = ObjectQueue::with_retry_limit(1, 4096, 19, 3).unwrap();
        let token = q.submit_compound(request(operations, access)).unwrap();
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
        assert!(
            matches!(&out[0].as_ref().unwrap().outcome,ReadOutcome::RemoteCompound {result:-108,operations,..} if operations[0].rval==0)
        );
        assert_eq!(q.outstanding(), 0);
        assert_eq!(q.charged_bytes(), 0);
        assert_eq!(q.poll_into(&mut [None]), 0);
        if access == Access::ReadWrite {
            assert!(matches!(
                q.fence_status(fence),
                Ok(FenceStatus::Ready(Err((
                    _,
                    WriteFailure::Remote { result: -108, .. }
                ))))
            ));
        } else {
            assert_eq!(q.fence_status(fence), Ok(FenceStatus::Ready(Ok(()))));
        }
        q.retire_fence(fence).unwrap();
    }
}

#[test]
fn early_error_echo_does_not_relax_success_or_nonempty_prefix_output_validation() {
    for code in [op::READ, op::SYNC_READ] {
        let mut read = OsdOp::read(7, 16);
        read.op = code;
        let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
        let token = q
            .submit_compound(request(vec![read], Access::Read))
            .unwrap();
        let dispatch = q.dispatch(token, route()).unwrap();
        let good = MOSDOpReply::for_request(&dispatch.message, 9);
        let mut bad = good.clone(); // A success cannot echo nonzero length with no data.
        assert_eq!(
            q.reply(token, 2, 3, bad.clone()),
            Err(DriverError::InvalidReply)
        );
        bad.result = -108;
        let mut extent = bad.ops[0].extent();
        extent.offset = 8;
        bad.ops[0].set_extent(extent);
        assert_eq!(q.reply(token, 2, 3, bad), Err(DriverError::InvalidReply));
        let mut bad = good.clone();
        bad.result = -108;
        bad.ops[0].outdata = Bytes::from_static(b"a");
        assert_eq!(q.reply(token, 2, 3, bad), Err(DriverError::InvalidReply));
        let mut bad = good.clone();
        bad.result = -108;
        bad.ops[0].rval = 1;
        assert_eq!(q.reply(token, 2, 3, bad), Err(DriverError::InvalidReply));
        let mut prefix = good;
        prefix.result = -13;
        prefix.ops[0].outdata = Bytes::from_static(b"a");
        let mut extent = prefix.ops[0].extent();
        extent.length = 1;
        prefix.ops[0].set_extent(extent);
        assert_eq!(
            q.reply_for_recovery(token, 2, 3, prefix),
            Ok(ReplyAction::Completed)
        );
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(
            matches!(&out[0].as_ref().unwrap().outcome,ReadOutcome::RemoteCompound {result:-13,operations,..} if &operations[0].outdata[..]==b"a")
        );
    }
}

#[test]
fn pinned_class_readers_preserve_snapshots_output_and_never_enter_write_fences() {
    for (class, method) in [
        (&b"rbd"[..], &b"get_size"[..]),
        (b"rbd", b"metadata_list"),
        (b"rbd", b"object_map_load"),
        (b"rbd", b"mirror_image_list"),
        (b"hello", b"say_hello"),
        (b"hello", b"replay"),
        (b"lock", b"get_info"),
    ]
    .into_iter()
    .chain(stock_readers())
    {
        let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
        let fence = q.fence();
        let mut r = request(vec![OsdOp::call(class, method, b"opaque")], Access::Read);
        r.context.snapid = 17;
        let input = r.operations[0].indata.clone();
        let t = q.submit_compound(r).unwrap();
        let d = q.dispatch(t, route()).unwrap();
        assert_eq!(
            (d.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
            flag::READ | flag::ONDISK | flag::RETURNVEC
        );
        assert_eq!(d.message.snapid, 17);
        assert_eq!(d.message.ops[0].indata, input);
        assert_eq!(q.fence_status(q.fence()), Ok(FenceStatus::Ready(Ok(()))));
        assert_eq!(q.fence_status(fence), Ok(FenceStatus::Ready(Ok(()))));
        assert_eq!(q.retry(t), Err(DriverError::DeadlineRequired));
        let payload = Bytes::from_static(&[0, 255, 1]);
        let ptr = payload.as_ptr();
        let mut reply = MOSDOpReply::for_request(&d.message, 9);
        reply.flags = u64::from(flag::ACK);
        reply.ops[0].outdata = payload;
        let mut extent = reply.ops[0].extent();
        extent.length = 3;
        reply.ops[0].set_extent(extent);
        assert!(q.reply(t, 2, 3, reply).unwrap());
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        let ReadOutcome::RemoteCompound {
            result, operations, ..
        } = &out[0].as_ref().unwrap().outcome
        else {
            panic!("class result")
        };
        assert_eq!(*result, 0);
        assert_eq!(operations[0].outdata.as_ptr(), ptr);
        assert_eq!(operations[0].outdata.as_ref(), &[0, 255, 1]);
        assert_eq!(q.charged_bytes(), 0);
    }
}
// Own interface expectations; no dependency on a Ceph checkout at test time.
fn stock_readers() -> impl Iterator<Item = (&'static [u8], &'static [u8])> {
    [
        ("journal", "get_order get_splay_width get_pool_id get_minimum_set get_active_set get_client client_list get_next_tag_tid get_tag tag_list"),
        ("version", "read check_conds"),
        ("refcount", "read"),
        ("cas", "references_chunk"),
        ("otp", "otp_get otp_get_result get_current_time"),
        ("cmpomap", "cmp_vals"),
        ("log", "list info"),
        ("timeindex", "list"),
        ("queue", "queue_get_capacity queue_list_entries"),
        ("2pc_queue", "2pc_queue_get_capacity 2pc_queue_get_topic_stats 2pc_queue_list_reservations 2pc_queue_list_entries"),
        ("rgw_gc", "rgw_gc_queue_list_entries"),
        ("fifo", "get_meta part_list get_part_info"),
        ("sem_set", "list"),
        ("user", "list_buckets get_header account_resource_get account_resource_list"),
        ("rgw", "bucket_list bucket_check_index bucket_read_olh_log obj_check_attrs_prefix obj_check_mtime bi_get bi_list bi_log_list user_usage_log_read gc_list lc_get_entry lc_get_next_entry lc_get_head lc_list_entries reshard_list reshard_get guard_bucket_resharding get_bucket_resharding"),
    ].into_iter().flat_map(|(class, methods)| methods.split_ascii_whitespace().map(move |method| (class.as_bytes(), method.as_bytes())))
}

#[test]
fn stock_class_aliases_remain_conservative_and_rejected_requests_keep_ownership() {
    assert_eq!(stock_readers().count(), 54);
    for (class, method) in stock_readers() {
        for (class, method) in [
            ([class, b"\0"].concat(), method.to_vec()),
            (class.to_vec(), [method, b"\0"].concat()),
            (class.to_ascii_uppercase(), method.to_vec()),
            (class.to_vec(), method.to_ascii_uppercase()),
            (b"custom".to_vec(), method.to_vec()),
            (class.to_vec(), [method, b"_extra"].concat()),
        ] {
            assert_eq!(pinned_class_access(&class, &method), Access::ReadWrite);
            let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
            let r = request(vec![OsdOp::call(&class, &method, b"opaque")], Access::Read);
            let ptr = r.operations[0].indata.as_ptr();
            let e = q.submit_compound(r).unwrap_err();
            assert_eq!(e.reason, AdmissionError::InvalidOperation);
            assert_eq!(e.request.operations[0].indata.as_ptr(), ptr);
            assert_eq!(q.outstanding(), 0);
            assert_eq!(q.charged_bytes(), 0);
        }
    }
}
#[test]
fn class_mutators_unknowns_and_byte_aliases_cannot_claim_readonly_admission() {
    for (class, method) in [
        (&b"rbd"[..], &b"set_size"[..]),
        (b"rbd", b"create"),
        (b"rbd", b"get_size\0"),
        (b"rbd\0", b"get_size"),
        (b"RBD", b"get_size"),
        (b"rbd", b"GET_SIZE"),
        (b"rbd", b"get_size_extra"),
        (b"foreign", b"get_size"),
        (b"rbd", b"unknown"),
        (b"hello", b"write_return_data"),
        (b"hello", b"bad_writer"),
        (b"lock", b"lock"),
        (b"journal", b"guard_append"),
        (b"journal", b"client_register"),
        (b"version", b"inc_conds"),
        (b"refcount", b"get"),
        (b"cas", b"chunk_get_ref"),
        (b"otp", b"otp_check"),
        (b"cmpomap", b"cmp_set_vals"),
        (b"log", b"trim"),
        (b"timeindex", b"add"),
        (b"queue", b"queue_enqueue"),
        (b"2pc_queue", b"2pc_queue_reserve"),
        (b"rgw_gc", b"rgw_gc_queue_remove_entries"),
        (b"fifo", b"part_push"),
        (b"sem_set", b"increment"),
        (b"user", b"set_buckets_info"),
        (b"rgw", b"obj_store_pg_ver"),
        (b"cephfs", b"accumulate_inode_metadata"),
        (b"numops", b"add"),
    ] {
        let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
        let r = request(vec![OsdOp::call(class, method, b"opaque")], Access::Read);
        let ptr = r.operations[0].indata.as_ptr();
        let rejected = q.submit_compound(r).unwrap_err();
        assert_eq!(rejected.reason, AdmissionError::InvalidOperation);
        assert_eq!(rejected.request.operations[0].indata.as_ptr(), ptr);
        assert_eq!(q.outstanding(), 0);
        let t = q
            .submit_compound(request(
                vec![OsdOp::call(class, method, b"opaque")],
                Access::ReadWrite,
            ))
            .unwrap();
        let fence = q.fence();
        let d = q.dispatch(t, route()).unwrap();
        assert_eq!(
            (d.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
            flag::READ | flag::WRITE | flag::RWORDERED | flag::ONDISK | flag::RETURNVEC
        );
        let mut early = MOSDOpReply::for_request(&d.message, 9);
        early.flags = u64::from(flag::ACK);
        let mut extent = early.ops[0].extent();
        extent.length = 0;
        early.ops[0].set_extent(extent);
        assert!(!q.reply(t, 2, 3, early.clone()).unwrap());
        assert_eq!(q.fence_status(fence), Ok(FenceStatus::Pending));
        early.flags |= u64::from(flag::ONDISK);
        assert!(q.reply(t, 2, 3, early).unwrap());
    }
}

#[test]
fn tail_zero_truncate_reply_is_narrowly_validated_and_normalized() {
    for kind in 0..8 {
        let zero = OsdOp::zero(9, if kind == 6 { 0 } else { 20 });
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        let token = q
            .submit_compound(request(vec![zero], Access::Write))
            .unwrap();
        let dispatch = q.dispatch(token, route()).unwrap();
        let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
        reply.ops[0].op = op::TRUNCATE;
        match kind {
            1 => reply.ops[0].u[0] ^= 1,
            2 => reply.ops[0].flags ^= opflag::FAILOK,
            3 => reply.ops[0].outdata = Bytes::from_static(b"bad"),
            4 => reply.ops[0].rval = 1,
            5 => reply.ops[0].op = op::DELETE,
            7 => {
                reply.result = -5;
                reply.ops[0].rval = -5;
            }
            _ => {}
        }
        if kind != 0 && kind != 7 {
            assert_eq!(q.reply(token, 2, 3, reply), Err(DriverError::InvalidReply));
            assert_eq!(q.outstanding(), 1);
        } else {
            assert_eq!(q.reply(token, 2, 3, reply), Ok(true));
            let mut out = [None];
            assert_eq!(q.poll_into(&mut out), 1);
            let ReadOutcome::RemoteCompound {
                result, operations, ..
            } = &out[0].as_ref().unwrap().outcome
            else {
                panic!("compound");
            };
            assert_eq!(*result, if kind == 7 { -5 } else { 0 });
            assert_eq!(operations[0].op, op::ZERO);
            assert_eq!(operations[0].extent().offset, 9);
            assert_eq!(operations[0].extent().length, 20);
        }
    }
}

#[test]
fn sparse_reply_validates_shape_range_and_preserves_payload_ownership() {
    for kind in 0..12 {
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        let mut requested = OsdOp::sparse_read(4, 6);
        if kind == 10 {
            requested.flags |= opflag::FAILOK;
        }
        let token = q
            .submit_compound(request(vec![requested], Access::Read))
            .unwrap();
        let dispatch = q.dispatch(token, route()).unwrap();
        let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
        let mut sparse = opwire::SparseReadOut {
            extents: [(4, 2), (9, 1)].into(),
            data: vec![0xff, 0, 1],
        };
        match kind {
            3 => {
                sparse.extents = [(3, 3)].into();
            }
            4 => {
                sparse.extents = [(8, 3)].into();
            }
            5 => {
                sparse.data.push(2);
            }
            6 => {
                sparse = Default::default();
            }
            _ => {}
        }
        reply.ops[0].outdata = Bytes::from(denc::to_vec(&sparse).unwrap());
        let mut e = reply.ops[0].extent();
        e.length = sparse.data.len() as u64;
        if kind == 1 {
            e.offset += 1;
        }
        if kind == 2 {
            e.length += 1;
        }
        reply.ops[0].set_extent(e);
        if kind == 7 {
            reply.ops[0].outdata = Bytes::from_static(b"bad");
        }
        if kind == 8 {
            reply.result = -2;
            reply.ops[0] = dispatch.message.ops[0].clone(); // unexecuted errno echo
        }
        if kind == 9 {
            reply.result = -5;
            reply.ops[0].rval = -5; // executed failure; raw details retained
        }
        if kind == 10 {
            reply.ops[0].rval = -5;
            reply.ops[0].outdata = Bytes::from_static(b"error details");
        }
        if kind == 11 {
            let mut raw = reply.ops[0].outdata.to_vec();
            raw.push(0);
            reply.ops[0].outdata = Bytes::from(raw);
        }
        let ptr = reply.ops[0].outdata.as_ptr();
        if matches!(kind, 1..=5 | 7 | 11) {
            assert_eq!(q.reply(token, 2, 3, reply), Err(DriverError::InvalidReply));
            assert_eq!(q.outstanding(), 1);
        } else {
            assert_eq!(q.reply(token, 2, 3, reply), Ok(true));
            let mut out = [None];
            assert_eq!(q.poll_into(&mut out), 1);
            assert_eq!(out[0].as_ref().unwrap().token, token);
            let ReadOutcome::RemoteCompound { operations, .. } = &out[0].as_ref().unwrap().outcome
            else {
                panic!("compound");
            };
            assert_eq!(operations[0].outdata.as_ptr(), ptr);
            assert_eq!(q.outstanding(), 0);
        }
    }
}

#[test]
fn zero_length_reads_retain_remote_semantics_output_caps_and_ownership() {
    for code in [op::READ, op::SYNC_READ] {
        for kind in 0..10 {
            let mut requested = OsdOp::read(
                if kind == 5 { u64::MAX } else { 4 },
                if kind == 9 { 2 } else { 0 },
            );
            requested.op = code;
            let mut r = request(vec![requested], Access::Read);
            if kind == 4 {
                r.max_output_bytes = 2;
            }
            let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
            let token = q.submit_compound(r).unwrap();
            let dispatch = q.dispatch(token, route()).unwrap();
            assert_eq!(
                dispatch.message.ops[0].extent().length,
                if kind == 9 { 2 } else { 0 }
            );
            let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
            reply.ops[0].outdata = Bytes::from_static(b"abc");
            let mut extent = reply.ops[0].extent();
            extent.length = 3;
            if kind == 1 {
                extent.length = 0;
                reply.ops[0].outdata = Bytes::new();
            }
            if kind == 2 {
                extent.offset += 1;
            }
            if kind == 3 {
                extent.length = 2;
            }
            reply.ops[0].set_extent(extent);
            if kind == 6 {
                reply.result = -2;
                reply.ops[0] = dispatch.message.ops[0].clone();
            }
            if kind == 7 {
                reply.result = -5;
                reply.ops[0].rval = -5;
                reply.ops[0].outdata = Bytes::new();
            }
            if kind == 8 {
                reply.ops[0].flags ^= opflag::FAILOK;
            }
            let pointer = reply.ops[0].outdata.as_ptr();
            if kind == 4 {
                assert_eq!(q.reply(token, 2, 3, reply), Ok(true));
                let mut out = [None];
                assert_eq!(q.poll_into(&mut out), 1);
                assert_eq!(
                    out[0].take().unwrap().outcome,
                    ReadOutcome::ReplyTooLarge {
                        result: 0,
                        user_version: 0,
                        bytes: 3,
                        limit: 2
                    }
                );
                assert_eq!(q.charged_bytes(), 0);
            } else if matches!(kind, 2 | 3 | 5 | 8 | 9) {
                assert_eq!(q.reply(token, 2, 3, reply), Err(DriverError::InvalidReply));
                assert_eq!(q.outstanding(), 1);
            } else {
                assert_eq!(q.reply(token, 2, 3, reply), Ok(true));
                let mut out = [None];
                assert_eq!(q.poll_into(&mut out), 1);
                let result = out[0].take().unwrap();
                assert_eq!(result.token, token);
                let ReadOutcome::RemoteCompound { operations, .. } = result.outcome else {
                    panic!("compound");
                };
                assert_eq!(operations[0].outdata.as_ptr(), pointer);
                assert_eq!(q.outstanding(), 0);
                assert_eq!(q.charged_bytes(), 0);
            }
        }
    }
}

#[test]
fn zero_length_sparse_read_requires_empty_remote_range() {
    for nonempty in [false, true] {
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        let token = q
            .submit_compound(request(vec![OsdOp::sparse_read(4, 0)], Access::Read))
            .unwrap();
        let dispatch = q.dispatch(token, route()).unwrap();
        let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
        let result = if nonempty {
            opwire::SparseReadOut {
                extents: [(4, 1)].into(),
                data: vec![1],
            }
        } else {
            opwire::SparseReadOut::default()
        };
        reply.ops[0].outdata = Bytes::from(denc::to_vec(&result).unwrap());
        let mut extent = reply.ops[0].extent();
        extent.length = result.data.len() as u64;
        reply.ops[0].set_extent(extent);
        assert_eq!(
            q.reply(token, 2, 3, reply),
            if nonempty {
                Err(DriverError::InvalidReply)
            } else {
                Ok(true)
            }
        );
    }
}

#[test]
fn cache_pin_controls_are_payload_free_captured_writes_and_never_reads() {
    for code in [op::CACHE_PIN, op::CACHE_UNPIN] {
        let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
        assert!(
            q.submit_compound(request(vec![OsdOp::new(code)], Access::Read))
                .is_err()
        );
        assert_eq!(q.outstanding(), 0);
        let mut r = request(vec![OsdOp::new(code)], Access::Write);
        r.target.locator = b"cache-route".to_vec();
        r.context.snap_sequence = 12;
        r.context.snapshots = vec![12, 9];
        r.context.mtime = UTime::new(8, 4);
        r.context.full_policy = FullPolicy::Try;
        let token = q.submit_compound(r).unwrap();
        let d = q.dispatch(token, route()).unwrap();
        assert_eq!(d.message.ops.len(), 1);
        assert_eq!(d.message.ops[0].op, code);
        assert_eq!(d.message.ops[0].flags, 0);
        assert!(d.message.ops[0].indata.is_empty());
        assert_eq!(d.message.snap_seq, 12);
        assert_eq!(d.message.snaps, vec![12, 9]);
        assert_eq!(d.message.mtime, UTime::new(8, 4));
        assert_eq!(d.message.oloc.nspace, vec![255, 0]);
        assert_eq!(d.message.oloc.key, b"cache-route");
        assert_eq!(
            (d.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
            flag::WRITE | flag::RWORDERED | flag::ONDISK | flag::RETURNVEC | flag::FULL_TRY
        );
        assert_eq!(q.retry(token), Err(DriverError::UnsupportedRetry));
        let fence = q.fence();
        let reply = MOSDOpReply::for_request(&d.message, 9);
        let mut early = reply.clone();
        early.flags &= !u64::from(flag::ONDISK);
        assert!(!q.reply(token, 2, 3, early).unwrap());
        assert_eq!(q.fence_status(fence), Ok(FenceStatus::Pending));
        assert!(q.reply(token, 2, 3, reply).unwrap());
        assert_eq!(q.fence_status(fence), Ok(FenceStatus::Ready(Ok(()))));
    }
}

/// CephFS truncate (MDS data worker): TRIMTRUNC carries only truncate_size/seq, admits as a write and its empty reply completes.
#[test]
fn trimtrunc_write_is_admitted_and_completes() {
    let mut trim = OsdOp::new(op::TRIMTRUNC);
    trim.set_extent(opwire::Extent {
        truncate_size: 4096,
        truncate_seq: 2,
        ..Default::default()
    });
    let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
    let token = q
        .submit_compound(request(vec![trim], Access::Write))
        .unwrap();
    let dispatch = q.dispatch(token, route()).unwrap();
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
    reply.flags |= u64::from(flag::ONDISK);
    assert_eq!(q.reply(token, 2, 3, reply), Ok(true));
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
}
