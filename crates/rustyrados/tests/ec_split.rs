// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
use bytes::Bytes;
use denc::types::{Eversion, PgT, ShardId};
use opwire::{MOSDOpReply, OsdOp, flag, op};
use rustyrados::*;

fn route(osd: i32, shard: i8) -> ReadRoute {
    ReadRoute {
        base_pool: 7,
        direct_read: false,
        osd,
        session: 30 + shard as u64,
        pg: PgT::new(7, 3),
        hash: 42,
        epoch: 9,
        features: 0,
        generation: 1,
        pool: PoolRoute::Erasure(ShardId(shard)),
    }
}
fn start(operations: Vec<OsdOp>) -> (ObjectQueue, EcSplitRead) {
    start_with_layout(
        operations,
        EcReadLayout {
            chunk_size: 4096,
            pool_size: 3,
            raw_to_shard: vec![ShardId(0), ShardId(1)],
            acting: vec![27, 28, 29],
        },
    )
}
fn start_with_layout(operations: Vec<OsdOp>, layout: EcReadLayout) -> (ObjectQueue, EcSplitRead) {
    let mut queue = ObjectQueue::with_retry_limit(1, 1_000_000, 7, 3).unwrap();
    let token = queue
        .submit_compound(CompoundRequest {
            target: Target {
                pool: 7,
                object: b"split".to_vec(),
                namespace: vec![],
                locator: vec![],
            },
            access: Access::Read,
            context: RequestContext {
                read_policy: ReplicaReadPolicy::Balance,
                ..Default::default()
            },
            operations,
            max_output_bytes: 100_000,
        })
        .unwrap();
    queue.set_deadline_us(token, 1000, 1000).unwrap();
    let parent = queue.dispatch(token, route(27, 0)).unwrap();
    let split = EcSplitRead::new(parent, layout).unwrap();
    (queue, split)
}
fn respond(
    queue: &mut ObjectQueue,
    split: &mut EcSplitRead,
    index: usize,
    result: i32,
    output: Bytes,
    version: u64,
) -> EcChildProgress {
    let (osd, shard) = split.child_target(index).unwrap();
    let mut selected = route(osd, shard.0);
    selected.direct_read = true;
    let wire = split.prepare_child(queue, index, selected).unwrap();
    let dispatch = split.child_dispatch(index).unwrap();
    assert!(dispatch.is_split_child());
    assert_ne!(wire, split.token().tid());
    assert_eq!(
        dispatch.message.flags & (flag::EC_DIRECT_READ | flag::FORCE_OSD | flag::FAIL_ON_EAGAIN),
        flag::EC_DIRECT_READ | flag::FORCE_OSD | flag::FAIL_ON_EAGAIN
    );
    assert_eq!(dispatch.message.flags & flag::BALANCE_READS, 0);
    assert_eq!(
        dispatch.message.ops.last().unwrap().op,
        op::GET_INTERNAL_VERSIONS
    );
    assert!(dispatch.message.ops.last().unwrap().indata.is_empty());
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
    reply.result = result;
    reply.user_version = 73;
    reply.replay_version = Eversion::new(9, 81);
    if result >= 0 {
        for operation in &mut reply.ops {
            if operation.op == op::GET_INTERNAL_VERSIONS {
                let versions = if shard.0 == 0 {
                    [
                        (ShardId(0), Eversion::new(9, 100)),
                        (ShardId(1), Eversion::new(9, 100)),
                        (ShardId(2), Eversion::new(9, 100)),
                    ]
                    .into_iter()
                    .collect::<std::collections::BTreeMap<_, _>>()
                } else {
                    [(shard, Eversion::new(9, version))].into_iter().collect()
                };
                operation.outdata = denc::to_vec(&versions).unwrap().into();
            } else {
                operation.outdata = output.clone();
            }
        }
    }
    split.mark_sent(index).unwrap();
    split
        .receive_child(index, wire, osd, selected.session, reply)
        .unwrap()
}
#[test]
fn dense_wrap_reassembles_logical_order_and_hides_internal_queries() {
    let (mut queue, mut split) = start(vec![OsdOp::read(6000, 6000)]);
    assert_eq!(split.child_count(), 2);
    let token = split.token();
    assert_eq!(
        respond(&mut queue, &mut split, 1, 0, vec![b'b'; 2192].into(), 100),
        EcChildProgress::Pending
    );
    assert_eq!(queue.poll_into(&mut [None]), 0);
    assert_eq!(
        respond(&mut queue, &mut split, 0, 0, vec![b'a'; 3808].into(), 100),
        EcChildProgress::Ready
    );
    let EcSplitResult::Complete(completed) = split.assemble().unwrap() else {
        panic!("consistent versions")
    };
    queue.complete_split(completed).unwrap();
    let mut output = [None];
    assert_eq!(queue.poll_into(&mut output), 1);
    let done = output[0].take().unwrap();
    assert_eq!(done.token, token);
    let ReadOutcome::RemoteCompound {
        publication,
        result,
        user_version,
        replay_version,
        operations,
    } = done.outcome
    else {
        panic!("compound result")
    };
    assert_eq!(publication, ReadPublication::EcSplit);
    assert_eq!(
        (result, user_version, replay_version),
        (0, 73, Eversion::new(9, 81))
    );
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].op, op::READ);
    assert_eq!(&operations[0].outdata[..2192], vec![b'b'; 2192]);
    assert_eq!(&operations[0].outdata[2192..], vec![b'a'; 3808]);
    assert_eq!(operations[0].extent().length, 6000);
    assert_eq!(queue.charged_bytes(), 0);
}
#[test]
fn sparse_union_coalesces_cross_shard_adjacency_in_logical_data_order() {
    let (mut queue, mut split) = start(vec![OsdOp::sparse_read(6000, 6000)]);
    let a = denc::to_vec(&opwire::SparseReadOut {
        extents: [(8192, 3808)].into_iter().collect(),
        data: vec![b'a'; 3808],
    })
    .unwrap()
    .into();
    let b = denc::to_vec(&opwire::SparseReadOut {
        extents: [(6000, 2192)].into_iter().collect(),
        data: vec![b'b'; 2192],
    })
    .unwrap()
    .into();
    assert_eq!(
        respond(&mut queue, &mut split, 0, 0, a, 100),
        EcChildProgress::Pending
    );
    assert_eq!(
        respond(&mut queue, &mut split, 1, 0, b, 100),
        EcChildProgress::Ready
    );
    let EcSplitResult::Complete(completed) = split.assemble().unwrap() else {
        panic!("consistent versions")
    };
    queue.complete_split(completed).unwrap();
    let mut output = [None];
    assert_eq!(queue.poll_into(&mut output), 1);
    let ReadOutcome::RemoteCompound { operations, .. } = output[0].take().unwrap().outcome else {
        panic!("compound")
    };
    assert_eq!(operations.len(), 1);
    let view = denc::from_slice::<opwire::SparseReadOut>(&operations[0].outdata).unwrap();
    assert_eq!(view.extents, [(6000, 6000)].into_iter().collect());
    assert_eq!(&view.data[..2192], vec![b'b'; 2192]);
    assert_eq!(&view.data[2192..], vec![b'a'; 3808]);
    assert_eq!(operations[0].extent().length, 6000);
}
#[test]
fn mismatch_and_eagain_never_publish_partial_data() {
    for (result, version) in [(0, 101), (-11, 100)] {
        let (mut queue, mut split) = start(vec![OsdOp::read(6000, 6000)]);
        respond(&mut queue, &mut split, 0, 0, vec![b'a'; 3808].into(), 100);
        respond(
            &mut queue,
            &mut split,
            1,
            result,
            vec![b'b'; 2192].into(),
            version,
        );
        assert!(matches!(split.assemble(), Ok(EcSplitResult::Retry)));
        assert_eq!(queue.poll_into(&mut [None]), 0);
        let token = split.token();
        let ids: Vec<_> = split.wire_ids().collect();
        queue.retry_at_primary(token).unwrap();
        let ordinary = queue.dispatch(token, route(27, 0)).unwrap();
        assert_eq!(
            ordinary.message.flags & (flag::BALANCE_READS | flag::EC_DIRECT_READ | flag::FORCE_OSD),
            0
        );
        assert!(!ids.contains(&ordinary.wire_tid()));
        assert_eq!(queue.deadline_us(token), Some(1000));
    }
}
#[test]
fn hard_errors_precede_eagain_in_canonical_shard_order() {
    for (raw_to_shard, errors) in [ShardId(0), ShardId(1)]
        .into_iter()
        .map(|first| [first, ShardId(1 - first.0)])
        .flat_map(|mapping| {
            [(-11, -2), (-13, -5), (-5, -11), (0, -13)]
                .into_iter()
                .map(move |errors| (mapping, errors))
        })
    {
        let (mut queue, mut split) = start_with_layout(
            vec![OsdOp::read(6000, 6000)],
            EcReadLayout {
                chunk_size: 4096,
                pool_size: 3,
                raw_to_shard: raw_to_shard.to_vec(),
                acting: vec![27, 28, 29],
            },
        );
        let token = split.token();
        respond(&mut queue, &mut split, 1, errors.1, Bytes::new(), 100);
        assert_eq!(queue.poll_into(&mut [None]), 0);
        respond(&mut queue, &mut split, 0, errors.0, Bytes::new(), 100);
        let EcSplitResult::Complete(completed) = split.assemble().unwrap() else {
            panic!("hard error wins");
        };
        queue.complete_split(completed).unwrap();
        let mut output = [None];
        assert_eq!(queue.poll_into(&mut output), 1);
        let done = output[0].take().unwrap();
        assert_eq!(done.token, token);
        let ReadOutcome::RemoteCompound {
            publication,
            result,
            user_version,
            operations,
            ..
        } = done.outcome
        else {
            panic!("compound");
        };
        assert_eq!(
            result,
            if errors.0 >= 0 || errors.0 == -11 {
                errors.1
            } else {
                errors.0
            }
        );
        assert_eq!(publication, ReadPublication::EcSplit);
        assert_eq!(user_version, 73);
        assert!(operations.is_empty());
        assert_eq!(queue.poll_into(&mut [None]), 0);
        assert_eq!(queue.charged_bytes(), 0);
    }
}
#[test]
fn dense_short_read_stops_at_first_missing_logical_piece() {
    let (mut queue, mut split) = start(vec![OsdOp::read(6000, 6000)]);
    respond(&mut queue, &mut split, 0, 0, vec![b'a'; 3808].into(), 100);
    respond(&mut queue, &mut split, 1, 0, vec![b'b'; 31].into(), 100);
    let EcSplitResult::Complete(completed) = split.assemble().unwrap() else {
        panic!("consistent");
    };
    queue.complete_split(completed).unwrap();
    let mut output = [None];
    queue.poll_into(&mut output);
    let ReadOutcome::RemoteCompound { operations, .. } = output[0].take().unwrap().outcome else {
        panic!("compound");
    };
    assert_eq!(operations[0].outdata, vec![b'b'; 31]);
    assert_eq!(operations[0].extent().length, 31);
}
#[test]
fn child_rearm_keeps_wire_id_but_rejects_previous_attempt() {
    let (mut queue, mut split) = start(vec![OsdOp::read(6000, 6000)]);
    let mut selected = route(28, 1);
    selected.direct_read = true;
    let wire = split.prepare_child(&mut queue, 1, selected).unwrap();
    let old = MOSDOpReply::for_request(&split.child_dispatch(1).unwrap().message, 9);
    split.mark_sent(1).unwrap();
    split.rearm_child(1).unwrap();
    assert!(!split.all_sent());
    assert_eq!(split.prepare_child(&mut queue, 1, selected).unwrap(), wire);
    let current = split.child_dispatch(1).unwrap();
    assert_eq!(current.message.retry_attempt, 1);
    assert_ne!(current.message.flags & flag::RETRY, 0);
    split.mark_sent(1).unwrap();
    assert_eq!(
        split.receive_child(1, wire, selected.osd, selected.session, old),
        Err(DriverError::Stale)
    );
}
#[test]
fn terminal_parent_cannot_publish_already_assembled_child_output() {
    let (mut queue, mut split) = start(vec![OsdOp::read(6000, 6000)]);
    respond(&mut queue, &mut split, 0, 0, vec![b'a'; 3808].into(), 100);
    respond(&mut queue, &mut split, 1, 0, vec![b'b'; 2192].into(), 100);
    let EcSplitResult::Complete(completed) = split.assemble().unwrap() else {
        panic!("consistent");
    };
    queue.cancel(split.token()).unwrap();
    assert_eq!(queue.complete_split(completed), Err(DriverError::Stale));
    assert_eq!(queue.poll_into(&mut [None]), 1);
    assert_eq!(queue.poll_into(&mut [None]), 0);
    assert_eq!(queue.charged_bytes(), 0);
}
#[test]
fn nonidentity_mapping_preserves_logical_data_and_canonical_version_keys() {
    let (mut queue, mut split) = start_with_layout(
        vec![OsdOp::read(6000, 6000)],
        EcReadLayout {
            chunk_size: 4096,
            pool_size: 3,
            raw_to_shard: vec![ShardId(1), ShardId(0)],
            acting: vec![27, 28, 29],
        },
    );
    respond(&mut queue, &mut split, 0, 0, vec![b'b'; 2192].into(), 100);
    respond(&mut queue, &mut split, 1, 0, vec![b'a'; 3808].into(), 100);
    let EcSplitResult::Complete(completed) = split.assemble().unwrap() else {
        panic!("consistent canonical versions");
    };
    queue.complete_split(completed).unwrap();
    let mut output = [None];
    queue.poll_into(&mut output);
    let ReadOutcome::RemoteCompound { operations, .. } = output[0].take().unwrap().outcome else {
        panic!("compound");
    };
    assert_eq!(&operations[0].outdata[..2192], vec![b'b'; 2192]);
    assert_eq!(&operations[0].outdata[2192..], vec![b'a'; 3808]);
}
#[test]
fn missing_canonical_version_is_a_whole_read_retry() {
    let (mut queue, mut split) = start(vec![OsdOp::read(6000, 6000)]);
    respond(&mut queue, &mut split, 0, 0, vec![b'a'; 3808].into(), 100);
    let mut selected = route(28, 1);
    selected.direct_read = true;
    let tid = split.prepare_child(&mut queue, 1, selected).unwrap();
    let dispatch = split.child_dispatch(1).unwrap();
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
    reply.ops[0].outdata = vec![b'b'; 2192].into();
    reply.ops.last_mut().unwrap().outdata = 0u32.to_le_bytes().to_vec().into();
    split.mark_sent(1).unwrap();
    assert_eq!(
        split.receive_child(1, tid, 28, selected.session, reply),
        Ok(EcChildProgress::Ready)
    );
    assert!(matches!(split.assemble(), Ok(EcSplitResult::Retry)));
    assert_eq!(queue.poll_into(&mut [None]), 0);
}
#[test]
fn primary_only_child_reply_must_match_the_ordinary_compound_shape() {
    let (mut queue, mut split) = start(vec![
        OsdOp::read(0, 4096),
        OsdOp::call(b"hello", b"say_hello", b""),
    ]);
    assert_eq!(split.child_count(), 1, "the primary shard is the reference");
    let mut selected = route(27, 0);
    selected.direct_read = true;
    let wire = split.prepare_child(&mut queue, 0, selected).unwrap();
    let dispatch = split.child_dispatch(0).unwrap();
    assert_eq!(
        dispatch
            .message
            .ops
            .iter()
            .map(|operation| operation.op)
            .collect::<Vec<_>>(),
        [op::READ, op::CALL, op::GET_INTERNAL_VERSIONS]
    );
    let request = dispatch.message.clone();
    let versions = [(ShardId(0), Eversion::new(9, 100))]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let reply = |data: usize, extent: u64| {
        let mut reply = MOSDOpReply::for_request(&request, 9);
        reply.result = 0;
        reply.ops[0].outdata = vec![7; 4096].into();
        reply.ops[1].outdata = vec![1; data].into();
        let mut declared = reply.ops[1].extent();
        declared.length = extent;
        reply.ops[1].set_extent(declared);
        reply.ops[2].outdata = denc::to_vec(&versions).unwrap().into();
        reply
    };
    split.mark_sent(0).unwrap();
    // assemble() publishes the reference child's primary-only ops as an ordinary compound result, so a CALL whose
    // extent does not describe its data must never be admitted.
    assert_eq!(
        split.receive_child(0, wire, 27, selected.session, reply(4, 0)),
        Err(DriverError::InvalidReply)
    );
    assert_eq!(
        split.receive_child(0, wire, 27, selected.session, reply(4, 4)),
        Ok(EcChildProgress::Ready)
    );
}

#[test]
fn malformed_version_map_or_foreign_sparse_extent_never_publish() {
    for sparse in [false, true] {
        let operation = if sparse {
            OsdOp::sparse_read(6000, 6000)
        } else {
            OsdOp::read(6000, 6000)
        };
        let (mut queue, mut split) = start(vec![operation]);
        let mut selected = route(28, 1);
        selected.direct_read = true;
        let tid = split.prepare_child(&mut queue, 1, selected).unwrap();
        let dispatch = split.child_dispatch(1).unwrap();
        let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
        if sparse {
            reply.ops[0].outdata = denc::to_vec(&opwire::SparseReadOut {
                extents: [(8192, 1)].into_iter().collect(),
                data: vec![1],
            })
            .unwrap()
            .into();
            reply.ops.last_mut().unwrap().outdata = 0u32.to_le_bytes().to_vec().into();
        } else {
            reply.ops.last_mut().unwrap().outdata = Bytes::from_static(&[1]);
        }
        split.mark_sent(1).unwrap();
        assert_eq!(
            split.receive_child(1, tid, 28, selected.session, reply),
            Err(DriverError::InvalidReply)
        );
        assert_eq!(queue.poll_into(&mut [None]), 0);
    }
}

#[test]
fn failok_data_errors_survive_split_assembly_without_partial_output() {
    for sparse in [false, true] {
        for failed_shard in [0, 1] {
            let mut read = if sparse {
                OsdOp::sparse_read(0, 8192)
            } else {
                OsdOp::read(0, 8192)
            };
            read.flags = opwire::opflag::FAILOK;
            let (mut queue, mut split) = start(vec![read, OsdOp::read(0, 4)]);
            for index in 0..split.child_count() {
                let (osd, shard) = split.child_target(index).unwrap();
                let mut selected = route(osd, shard.0);
                selected.direct_read = true;
                let tid = split.prepare_child(&mut queue, index, selected).unwrap();
                let dispatch = split.child_dispatch(index).unwrap();
                let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
                assert_eq!(reply.result, 0);
                for operation in &mut reply.ops {
                    if operation.op == op::GET_INTERNAL_VERSIONS {
                        let versions = [
                            (ShardId(0), Eversion::new(9, 100)),
                            (ShardId(1), Eversion::new(9, 100)),
                        ]
                        .into_iter()
                        .collect::<std::collections::BTreeMap<_, _>>();
                        operation.outdata = denc::to_vec(&versions).unwrap().into();
                    } else if operation.flags & opwire::opflag::FAILOK != 0 {
                        if shard.0 == failed_shard {
                            operation.rval = -5;
                        } else if sparse {
                            operation.outdata = denc::to_vec(&opwire::SparseReadOut {
                                extents: [(u64::from(shard.0 as u8) * 4096, 4096)]
                                    .into_iter()
                                    .collect(),
                                data: vec![7; 4096],
                            })
                            .unwrap()
                            .into();
                        } else {
                            operation.outdata = vec![7; 4096].into();
                        }
                    } else {
                        operation.outdata = Bytes::from_static(b"good");
                    }
                }
                split.mark_sent(index).unwrap();
                split
                    .receive_child(index, tid, osd, selected.session, reply)
                    .unwrap();
            }
            let EcSplitResult::Complete(completed) = split.assemble().unwrap() else {
                panic!("matching versions must complete");
            };
            queue.complete_split(completed).unwrap();
            let mut output = [None];
            assert_eq!(queue.poll_into(&mut output), 1);
            let ReadOutcome::RemoteCompound {
                result, operations, ..
            } = output[0].take().unwrap().outcome
            else {
                panic!("compound completion");
            };
            assert_eq!(result, 0, "FAILOK preserves overall success");
            assert_eq!(operations[0].rval, -5, "failed read must not become EOF");
            assert!(operations[0].outdata.is_empty(), "no partial failed read");
            assert_eq!(operations[1].rval, 0);
            assert_eq!(operations[1].outdata, b"good".as_slice());
        }
    }
}
