// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
use bytes::Bytes;
use denc::types::PgT;
use opwire::{MOSDOpReply, OsdOp, flag};
use rustyrados::*;
fn request(policy: ReplicaReadPolicy, flags: u32, mask: bool) -> CompoundRequest {
    CompoundRequest {
        target: Target {
            pool: 7,
            object: b"policy".to_vec(),
            namespace: vec![0, 255],
            locator: b"key".to_vec(),
        },
        access: Access::Read,
        context: RequestContext {
            read_policy: policy,
            osd_flags: flags,
            mask_replica_reads: mask,
            snapid: 17,
            ..Default::default()
        },
        operations: vec![OsdOp::read(19, 4)],
        max_output_bytes: 4,
    }
}
fn route(osd: i32) -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 7,
        osd,
        session: 3,
        pg: PgT::new(7, 1),
        hash: 17,
        epoch: 9,
        generation: 1,
        features: 0,
        pool: PoolRoute::Replicated,
    }
}
#[test]
fn global_caller_and_exec_mask_provenance_survive_admission() {
    for (policy, explicit, masked, expected) in [
        (ReplicaReadPolicy::Balance, 0, false, flag::BALANCE_READS),
        (
            ReplicaReadPolicy::Localize,
            flag::BALANCE_READS,
            false,
            flag::BALANCE_READS | flag::LOCALIZE_READS,
        ),
        (
            ReplicaReadPolicy::Balance,
            flag::RWORDERED | flag::LOCALIZE_READS,
            false,
            0,
        ),
        (ReplicaReadPolicy::Balance, flag::LOCALIZE_READS, true, 0),
        (
            ReplicaReadPolicy::Default,
            flag::LOCALIZE_READS,
            false,
            flag::LOCALIZE_READS,
        ),
    ] {
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        let token = q
            .submit_compound(request(policy, explicit | flag::FULL_FORCE, masked))
            .unwrap();
        let d = q.dispatch(token, route(0)).unwrap();
        assert_eq!(
            d.message.flags & (flag::BALANCE_READS | flag::LOCALIZE_READS),
            expected
        );
        assert_ne!(d.message.flags & flag::FULL_FORCE, 0);
        assert_ne!(d.message.flags & flag::READ, 0);
        assert_eq!(d.message.flags & flag::WRITE, 0);
        assert_eq!(d.message.snapid, 17);
    }
}
#[test]
fn write_policy_does_not_add_global_replica_flags() {
    let mut r = request(ReplicaReadPolicy::Balance, flag::LOCALIZE_READS, false);
    r.access = Access::Write;
    r.context.snapid = opwire::NOSNAP;
    r.operations = vec![OsdOp::writefull_bytes(Bytes::from_static(b"once"))];
    r.max_output_bytes = 0;
    let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
    let token = q.submit_compound(r).unwrap();
    let d = q.dispatch(token, route(0)).unwrap();
    assert_eq!(d.message.flags & flag::BALANCE_READS, 0);
    assert_ne!(d.message.flags & flag::LOCALIZE_READS, 0); // caller flag is forwarded, selection ignores it
    assert_ne!(d.message.flags & flag::WRITE, 0);
}
#[test]
fn eagain_fallback_renews_only_wire_identity_and_clears_both_replica_policies() {
    let mut q = ObjectQueue::with_retry_limit(2, 4096, 7, 3).unwrap();
    let token = q
        .submit_compound(request(
            ReplicaReadPolicy::Balance,
            flag::LOCALIZE_READS,
            false,
        ))
        .unwrap();
    q.set_deadline_us(token, 1000, 1000).unwrap();
    let first = q.dispatch(token, route(2)).unwrap();
    let charge = q.charged_bytes();
    let mut again = MOSDOpReply::for_request(&first.message, 9);
    again.result = -11;
    assert_eq!(
        q.reply_for_recovery(token, 2, 3, again.clone()),
        Ok(ReplyAction::Recover)
    );
    assert_eq!(q.poll_into(&mut [None]), 0);
    q.retry(token).unwrap();
    let primary = q.dispatch(token, route(0)).unwrap();
    assert_eq!(primary.token, token);
    assert!(primary.wire_tid() > first.wire_tid());
    assert_eq!(q.wire_tid(token), Some(primary.wire_tid()));
    assert_eq!(
        primary.message.flags & (flag::BALANCE_READS | flag::LOCALIZE_READS),
        0
    );
    assert_eq!(primary.message.ops, first.message.ops);
    assert_eq!(primary.message.snapid, 17);
    assert_eq!(q.deadline_us(token), Some(1000));
    assert_eq!(q.charged_bytes(), charge);
    assert_eq!(
        q.reply_for_recovery(token, 2, 3, again),
        Err(DriverError::Stale)
    );
    q.retry(token).unwrap(); // ordinary map/session retry keeps the fallback's wire ID
    let next = q.dispatch(token, route(0)).unwrap();
    assert_eq!(next.wire_tid(), primary.wire_tid());
    assert_eq!(
        next.message.flags & (flag::BALANCE_READS | flag::LOCALIZE_READS),
        0
    );
    let mut reply = MOSDOpReply::for_request(&next.message, 9);
    reply.ops[0].outdata = Bytes::from_static(b"data");
    assert_eq!(
        q.reply_for_recovery(token, 0, 3, reply),
        Ok(ReplyAction::Completed)
    );
    let mut done = [None];
    assert_eq!(q.poll_into(&mut done), 1);
    assert_eq!(done[0].as_ref().unwrap().token, token);
    assert_eq!(q.charged_bytes(), 0);
}
#[test]
fn malformed_eagain_cannot_change_routing_or_wire_identity() {
    let mut q = ObjectQueue::with_retry_limit(1, 4096, 7, 2).unwrap();
    let token = q
        .submit_compound(request(ReplicaReadPolicy::Balance, 0, false))
        .unwrap();
    q.set_deadline_us(token, 1000, 1000).unwrap();
    let first = q.dispatch(token, route(2)).unwrap();
    let mut reply = MOSDOpReply::for_request(&first.message, 9);
    reply.result = -11;
    reply.oid.push(1);
    assert_eq!(
        q.reply_for_recovery(token, 2, 3, reply),
        Err(DriverError::InvalidReply)
    );
    q.retry(token).unwrap();
    let next = q.dispatch(token, route(2)).unwrap();
    assert_eq!(next.wire_tid(), first.wire_tid());
    assert_ne!(next.message.flags & flag::BALANCE_READS, 0);
}

#[test]
fn primary_owned_notify_ack_does_not_inherit_object_replica_policy() {
    let mut q = ObjectQueue::with_retry_limit(1, 4096, 1, 2).unwrap();
    let t = q
        .submit_control_with_context(
            ControlRequest {
                target: request(ReplicaReadPolicy::Default, 0, false).target,
                operation: ControlOperation::NotifyAck {
                    cookie: 42,
                    notify_id: 71,
                    response: Bytes::from_static(b"ack"),
                },
            },
            RequestContext {
                read_policy: ReplicaReadPolicy::Balance,
                osd_flags: flag::LOCALIZE_READS,
                ..Default::default()
            },
        )
        .unwrap();
    q.set_deadline_us(t, 1000, 1000).unwrap();
    let first = q.dispatch(t, route(0)).unwrap();
    assert_eq!(
        first.message.flags & (flag::BALANCE_READS | flag::LOCALIZE_READS),
        0
    );
    let mut reply = MOSDOpReply::for_request(&first.message, 9);
    reply.result = -11;
    assert_eq!(
        q.reply_for_recovery(t, 0, 3, reply),
        Ok(ReplyAction::Recover)
    );
    q.retry(t).unwrap();
    let next = q.dispatch(t, route(0)).unwrap();
    assert_eq!(next.message.ops, first.message.ops);
    assert_ne!(next.wire_tid(), first.wire_tid());
    assert_eq!(next.token, t);
    assert_eq!(
        q.reply_for_recovery(t, 0, 3, MOSDOpReply::for_request(&next.message, 9)),
        Ok(ReplyAction::Completed)
    );
    let mut done = [None];
    assert_eq!(q.poll_into(&mut done), 1);
    assert_eq!(q.deadline_us(t), None);
}

#[test]
fn legacy_exec_separates_read_snapshot_and_wire_from_mutation_ownership() {
    for legacy in [false, true] {
        let mut r = request(ReplicaReadPolicy::Balance, 0, false);
        r.context.legacy_reply = legacy;
        r.operations = vec![OsdOp::call(b"custom", b"method", &[])];
        r.max_output_bytes = 64;
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        if !legacy {
            assert_eq!(
                q.submit_compound(r).unwrap_err().reason,
                AdmissionError::InvalidOperation
            );
            continue;
        }
        let t = q.submit_compound(r).unwrap();
        let dispatch = q.dispatch(t, route(0)).unwrap();
        assert_eq!(dispatch.message.snapid, 17);
        assert_eq!(dispatch.message.snap_seq, 0);
        assert!(dispatch.message.snaps.is_empty());
        assert_ne!(dispatch.message.flags & flag::READ, 0);
        assert_ne!(dispatch.message.flags & flag::BALANCE_READS, 0);
        assert_eq!(dispatch.message.flags & (flag::WRITE | flag::RETURNVEC), 0);
        assert_eq!(q.fence_status(q.fence()), Ok(FenceStatus::Pending));
    }
}
