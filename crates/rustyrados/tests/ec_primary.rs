// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
use bytes::Bytes;
use denc::types::{PgT, ShardId};
use opwire::{MOSDOpReply, OsdOp, flag, op};
use rustyrados::*;
fn target() -> Target {
    Target {
        pool: 701,
        object: b"rbd_data.image.0000000000000000".to_vec(),
        namespace: vec![],
        locator: vec![],
    }
}
fn route(shard: i8) -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 701,
        osd: 27,
        session: 3,
        pg: PgT::new(701, 5),
        hash: 0x1234,
        epoch: 9,
        generation: 1,
        features: 0,
        pool: PoolRoute::Erasure(ShardId(shard)),
    }
}
#[test]
fn ec_wire_carries_shard_and_scalar_write_waits_for_durability() {
    let mut q = ObjectQueue::new(1, 65536, 7).unwrap();
    let token = q
        .submit_write(WriteRequest {
            target: target(),
            operation: WriteOperation::Write { offset: 4096 },
            payload: Bytes::from(vec![42; 4096]),
        })
        .unwrap();
    let d = q.dispatch(token, route(2)).unwrap();
    // Both pinned peers' ordinary formats carry the same SPG proof.
    for version in [8, 9] {
        let wire = d.message.encode_version(version, 0).unwrap();
        let decoded = opwire::MOSDOp::decode_shared(version, &wire.front, &wire.data).unwrap();
        assert_eq!(decoded.pgid.shard, ShardId(2));
        assert_eq!(decoded.pgid.pgid, PgT::new(701, 5));
        assert_eq!(decoded.hash, 0x1234);
        assert_ne!(
            decoded.flags & 0x0800_0000,
            0,
            "both pinned peers receive SUPPORTSPOOLEIO"
        );
        assert_eq!(decoded.ops[0].indata.len(), 4096);
    }
    let mut r = MOSDOpReply::for_request(&d.message, 9);
    r.flags &= !u64::from(flag::ONDISK);
    assert!(!q.reply(token, 27, 3, r).unwrap());
    assert!(
        q.reply(token, 27, 3, MOSDOpReply::for_request(&d.message, 9))
            .unwrap()
    );
}
#[test]
fn same_session_shard_change_rejects_old_attempt_and_keeps_identity() {
    let mut q = ObjectQueue::with_retry_limit(1, 65536, 7, 3).unwrap();
    let token = q
        .submit(ReadRequest {
            target: target(),
            offset: 4096,
            length: 4,
        })
        .unwrap();
    q.set_deadline_us(token, 100, 100).unwrap();
    let a = q.dispatch(token, route(1)).unwrap();
    q.retry(token).unwrap();
    let b = q
        .dispatch(
            token,
            ReadRoute {
                epoch: 10,
                generation: 2,
                ..route(2)
            },
        )
        .unwrap();
    assert_eq!(a.message.reqid, b.message.reqid);
    assert_eq!(q.deadline_us(token), Some(100));
    assert_eq!(
        q.reply(token, 27, 3, MOSDOpReply::for_request(&a.message, 9)),
        Err(DriverError::Stale)
    );
    let mut r = MOSDOpReply::for_request(&b.message, 10);
    r.ops[0].outdata = Bytes::from_static(b"data");
    let mut extent = r.ops[0].extent();
    extent.length = 4;
    r.ops[0].set_extent(extent);
    assert!(q.reply(token, 27, 3, r).unwrap());
}
#[test]
fn ec_unsupported_operations_reach_primary_and_preserve_server_errno() {
    for scalar in [false, true] {
        let mut q = ObjectQueue::new(1, 65536, 7).unwrap();
        let token = if scalar {
            q.submit_write(WriteRequest {
                target: target(),
                operation: WriteOperation::Write { offset: 1 },
                payload: Bytes::from_static(b"unaligned"),
            })
            .unwrap()
        } else {
            let omap = OsdOp {
                op: op::OMAP_CLEAR,
                ..Default::default()
            };
            q.submit_compound(CompoundRequest {
                target: target(),
                access: Access::Write,
                context: Default::default(),
                operations: vec![omap],
                max_output_bytes: 0,
            })
            .unwrap()
        };
        let d = q.dispatch(token, route(1)).unwrap();
        let mut r = MOSDOpReply::for_request(&d.message, 9);
        r.result = -95;
        r.ops[0].rval = -95;
        assert!(q.reply(token, 27, 3, r).unwrap());
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        match &out[0].as_ref().unwrap().outcome {
            ReadOutcome::Remote {
                result, op_result, ..
            } => assert_eq!((*result, *op_result), (-95, -95)),
            ReadOutcome::RemoteCompound {
                result, operations, ..
            } => assert_eq!((*result, operations[0].rval), (-95, -95)),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn ec_pg_reads_keep_raw_hash_shard_flags_and_remote_errors() {
    for opcode in [op::PG_HITSET_LS, op::PG_HITSET_GET, op::SCRUBLS] {
        for result in [-95, -2, -22, 0, 4] {
            if result > 0 && opcode != op::PG_HITSET_GET {
                continue;
            }
            let mut q = ObjectQueue::with_retry_limit(1, 65536, 7, 3).unwrap();
            let operation = OsdOp::new(opcode);
            let request = if opcode == op::SCRUBLS {
                // A captured PG seed can exceed pg_num after a map merge;
                // the transport normalizes placement while preserving wire hash.
                PgOpRequest::by_pgid(701, vec![], 0x1234, operation, 1024)
            } else {
                PgOpRequest::by_hash(701, vec![], 0x1234, operation, 1024)
            };
            let token = q.submit_pg_operation(request).unwrap();
            q.set_deadline_us(token, 100, 100).unwrap();
            let old = q.dispatch(token, route(1)).unwrap();
            assert_eq!(old.message.flags & flag::PGOP != 0, opcode == op::SCRUBLS);
            assert_ne!(old.message.flags & flag::IGNORE_OVERLAY, 0);
            q.retry(token).unwrap();
            let d = q.dispatch(token, route(2)).unwrap();
            assert_eq!(d.message.pgid.shard, ShardId(2));
            assert_eq!(d.message.pgid.pgid, PgT::new(701, 5));
            assert_eq!(d.message.hash, 0x1234);
            assert_eq!(d.message.reqid, old.message.reqid);
            assert_eq!(q.deadline_us(token), Some(100));
            assert_eq!(
                q.reply(token, 27, 3, MOSDOpReply::for_request(&old.message, 9)),
                Err(DriverError::Stale)
            );
            let mut reply = MOSDOpReply::for_request(&d.message, 9);
            reply.result = result;
            reply.ops[0].rval = result.min(0);
            if result > 0 {
                reply.ops[0].outdata = Bytes::from_static(b"data");
            }
            assert!(q.reply(token, 27, 3, reply).unwrap());
            let mut out = [None];
            assert_eq!(q.poll_into(&mut out), 1);
            assert!(matches!(out[0].as_ref().unwrap().outcome,
                ReadOutcome::Remote { result: actual, op_result, .. }
                if actual == result && op_result == result.min(0)));
            assert_eq!(q.charged_bytes(), 0);
        }
    }
}

#[test]
fn direct_ec_reply_lengths_are_independent_but_bounded_and_fallback_keeps_owner() {
    use denc::Encode;
    for sparse in [false, true] {
        for direct in [false, true] {
            let mut q = ObjectQueue::with_retry_limit(1, 65536, 7, 3).unwrap();
            let token = q
                .submit_compound(CompoundRequest {
                    target: target(),
                    access: Access::Read,
                    context: RequestContext {
                        read_policy: ReplicaReadPolicy::Balance,
                        ..Default::default()
                    },
                    operations: vec![if sparse {
                        OsdOp::sparse_read(100, 4)
                    } else {
                        OsdOp::read(100, 4)
                    }],
                    max_output_bytes: 1024,
                })
                .unwrap();
            q.set_deadline_us(token, 1000, 1000).unwrap();
            let mut selected = route(0);
            selected.direct_read = direct;
            let dispatch = q.dispatch(token, selected).unwrap();
            assert_eq!(dispatch.message.flags & flag::EC_DIRECT_READ != 0, direct);
            let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
            reply.ops[0].outdata = if sparse {
                opwire::SparseReadOut {
                    extents: [(101, 2)].into_iter().collect(),
                    data: b"ab".to_vec(),
                }
                .encode_to_vec()
                .unwrap()
                .into()
            } else {
                Bytes::from_static(b"ab")
            };
            // Keep the requested length 4; only 2 data bytes were returned.
            assert_eq!(
                q.reply_for_recovery(token, 27, 3, reply),
                if direct {
                    Ok(ReplyAction::Completed)
                } else {
                    Err(DriverError::InvalidReply)
                }
            );
            if !direct {
                q.cancel(token).unwrap();
            }
            assert_eq!(q.poll_into(&mut [None]), 1);
            assert_eq!(q.charged_bytes(), 0);
        }
    }
    let mut q = ObjectQueue::with_retry_limit(1, 65536, 7, 3).unwrap();
    let token = q
        .submit_compound(CompoundRequest {
            target: target(),
            access: Access::Read,
            context: RequestContext {
                read_policy: ReplicaReadPolicy::Balance,
                ..Default::default()
            },
            operations: vec![OsdOp::read(100, 4)],
            max_output_bytes: 4,
        })
        .unwrap();
    q.set_deadline_us(token, 1000, 1000).unwrap();
    let mut selected = route(0);
    selected.direct_read = true;
    let dispatch = q.dispatch(token, selected).unwrap();
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
    reply.result = -11;
    assert_eq!(
        q.reply_for_recovery(token, 27, 3, reply),
        Ok(ReplyAction::Recover)
    );
    q.retry(token).unwrap();
    let fallback = q.dispatch(token, route(1)).unwrap();
    assert_eq!(fallback.token, dispatch.token);
    assert_ne!(fallback.wire_tid(), dispatch.wire_tid());
    assert_eq!(
        fallback.message.flags & (flag::BALANCE_READS | flag::EC_DIRECT_READ | flag::FORCE_OSD),
        0
    );
    assert_eq!(fallback.message.ops, dispatch.message.ops);
    assert_eq!(q.deadline_us(token), Some(1000));
}

#[test]
fn interval_retry_of_single_direct_retains_wire_identity_and_returns_to_primary() {
    let mut q = ObjectQueue::with_retry_limit(1, 65536, 7, 3).unwrap();
    let token = q
        .submit_compound(CompoundRequest {
            target: target(),
            access: Access::Read,
            context: RequestContext {
                read_policy: ReplicaReadPolicy::Balance,
                ..Default::default()
            },
            operations: vec![OsdOp::read(100, 4)],
            max_output_bytes: 4,
        })
        .unwrap();
    q.set_deadline_us(token, 1000, 1000).unwrap();
    let mut selected = route(0);
    selected.direct_read = true;
    let original = q.dispatch(token, selected).unwrap();
    q.retry(token).unwrap();
    let mut changed = route(2);
    changed.generation += 1;
    let fallback = q.dispatch(token, changed).unwrap();
    assert_eq!(fallback.token, original.token);
    assert_eq!(fallback.wire_tid(), original.wire_tid());
    assert_eq!(fallback.message.pgid.shard, denc::types::ShardId(2));
    assert_eq!(
        fallback.message.flags & (flag::BALANCE_READS | flag::EC_DIRECT_READ | flag::FORCE_OSD),
        0
    );
    assert_eq!(q.deadline_us(token), Some(1000));
    assert_eq!(
        q.reply_for_recovery(token, 27, 3, MOSDOpReply::for_request(&original.message, 9)),
        Err(DriverError::Stale)
    );
}

#[test]
fn direct_sparse_reply_cannot_return_extents_beyond_its_clipped_logical_end() {
    use denc::Encode;
    let mut queue = ObjectQueue::new(1, 65536, 7).unwrap();
    let token = queue
        .submit_compound(CompoundRequest {
            target: target(),
            access: Access::Read,
            context: RequestContext {
                read_policy: ReplicaReadPolicy::Balance,
                ..Default::default()
            },
            operations: vec![OsdOp::sparse_read(100, 4)],
            max_output_bytes: 1024,
        })
        .unwrap();
    let mut selected = route(0);
    selected.direct_read = true;
    let dispatch = queue.dispatch(token, selected).unwrap();
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
    let mut extent = reply.ops[0].extent();
    extent.length = 2;
    reply.ops[0].set_extent(extent);
    reply.ops[0].outdata = opwire::SparseReadOut {
        extents: [(103, 1)].into_iter().collect(),
        data: b"x".to_vec(),
    }
    .encode_to_vec()
    .unwrap()
    .into();
    assert_eq!(
        queue.reply_for_recovery(token, 27, 3, reply),
        Err(DriverError::InvalidReply)
    );
    assert_eq!(queue.poll_into(&mut [None]), 0);
    assert!(queue.is_pending(token));
    queue.cancel(token).unwrap();
    assert_eq!(queue.poll_into(&mut [None]), 1);
    assert_eq!(queue.charged_bytes(), 0);
}
