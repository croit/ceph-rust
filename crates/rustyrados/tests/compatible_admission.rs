// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use opwire::{MOSDOpReply, OsdOp, op};
use rustyrados::*;

fn target() -> Target {
    Target {
        pool: 1,
        object: b"o".to_vec(),
        namespace: Vec::new(),
        locator: Vec::new(),
    }
}
fn read(length: u32) -> ReadRequest {
    ReadRequest {
        target: target(),
        offset: 0,
        length,
    }
}
fn compound(operations: Vec<OsdOp>, access: Access, cap: u32) -> CompoundRequest {
    CompoundRequest {
        target: target(),
        access,
        context: Default::default(),
        operations,
        max_output_bytes: cap,
    }
}
fn route() -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 1,
        osd: 1,
        session: 2,
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
fn consume(q: &mut ReadQueue) -> ReadCompletion {
    let mut output = [None];
    assert_eq!(q.poll_into(&mut output), 1);
    output[0].take().unwrap()
}

#[test]
fn immutable_compatible_preflight_validates_before_acceptance_without_soft_ceiling() {
    let mut request = compound(vec![OsdOp::read(0, 4)], Access::Read, 128 << 20);
    assert_eq!(request.preflight(4), Err(AdmissionError::NoCredit));
    assert_eq!(request.preflight_compatible(), Ok(4));
    request.target.object.clear();
    assert_eq!(request.preflight_compatible(), Ok(4));
    request.target.pool = -1;
    assert_eq!(
        request.preflight_compatible(),
        Err(AdmissionError::InvalidTarget)
    );
    request.target = target();
    request.operations = vec![OsdOp::read(u64::MAX, 4)];
    assert_eq!(
        request.preflight_compatible(),
        Err(AdmissionError::InvalidExtent)
    );
    request.operations = vec![OsdOp::new(0xffff)];
    assert_eq!(
        request.preflight_compatible(),
        Err(AdmissionError::UnsupportedOperation)
    );
    request.operations = vec![OsdOp::read(0, 128 << 20)];
    assert_eq!(request.preflight_compatible(), Ok(128 << 20));
}

#[test]
fn compatible_constructor_is_explicit_and_strict_metadata_ceiling_remains() {
    let mut strict = ReadQueue::new(2, 4, 1).unwrap();
    assert_eq!(
        strict.submit(read(4)).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    let mut logical = ReadQueue::with_compatible_admission(2, 4, 0, 1, 1).unwrap();
    let first = logical.submit(read(4)).unwrap();
    assert_eq!(logical.charged_bytes(), 4);
    assert_eq!(
        logical.submit(read(1)).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    assert_eq!(logical.outstanding(), 1);
    logical.cancel(first).unwrap();
    assert_eq!(logical.charged_bytes(), 4); // terminal result still reserves native slot
    let held = consume(&mut logical);
    assert_eq!(logical.charged_bytes(), 0);
    let next = logical.submit(read(4)).unwrap();
    assert_eq!(
        sequence_of_tid(next.tid()),
        sequence_of_tid(first.tid()) + 1
    ); // rejected candidate consumed no identity
    drop(held);
    assert!(ReadQueue::with_control_reserve(1, 0, 1, 1, 1, 1).is_none());
    assert!(ReadQueue::with_compatible_control_reserve(1, 0, 0, 1, 1, 1, 1).is_some());
}

#[test]
fn pending_oversize_front_progresses_after_retirement_and_control_is_independent() {
    let mut q = ReadQueue::with_compatible_control_reserve(2, 4, 0, 1, 1, 1, 1).unwrap();
    let ordinary = q.submit(read(3)).unwrap();
    let rejected = q.submit(read(128 << 20)).unwrap_err();
    assert_eq!(rejected.reason, AdmissionError::NoCredit);
    q.cancel(ordinary).unwrap();
    let rejected = q.submit(rejected.request).unwrap_err();
    assert_eq!(rejected.reason, AdmissionError::NoCredit);
    consume(&mut q);
    let oversized = q.submit(rejected.request).unwrap();
    assert_eq!(q.charged_bytes(), 128 << 20);
    let control = q
        .submit_reserved_control(ControlRequest {
            target: target(),
            operation: ControlOperation::Ping {
                cookie: 1,
                generation: 0,
            },
        })
        .unwrap();
    assert_eq!(q.reserved_control_bytes(), 1);
    assert_eq!(
        q.submit(read(1)).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    q.cancel(oversized).unwrap();
    consume(&mut q);
    // A control holder does not prevent application-domain idle/sole oversize.
    let again = q.submit(read(128 << 20)).unwrap();
    assert_eq!(q.reserved_control_outstanding(), 1);
    q.cancel(again).unwrap();
    consume(&mut q);
    q.cancel(control).unwrap();
    q.take_reserved_completion(control).unwrap();
    assert_eq!((q.outstanding(), q.charged_bytes()), (0, 0));
}

#[test]
fn zero_target_disables_only_bytes_and_zero_byte_calls_still_occupy_slots() {
    let mut q = ReadQueue::with_compatible_admission(2, 0, 0, 1, 1).unwrap();
    let first = q.submit(read(128 << 20)).unwrap();
    let second = q.submit(read(128 << 20)).unwrap();
    assert_eq!(q.charged_bytes(), 256 << 20);
    assert_eq!(
        q.submit(read(1)).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    for token in [first, second] {
        q.cancel(token).unwrap();
        consume(&mut q);
    }
    let call = compound(
        vec![OsdOp::call(b"hello", b"say_hello", &[7; 4096])],
        Access::Read,
        31 << 20,
    );
    assert_eq!(call.logical_byte_charge(), Ok(0));
    let token = q.submit_compound(call).unwrap();
    assert_eq!(q.charged_bytes(), 0);
    let mut constrained = ReadQueue::with_compatible_admission(2, 1, 0, 1, 1).unwrap();
    let zero = constrained
        .submit_compound(compound(vec![OsdOp::stat()], Access::Read, 31 << 20))
        .unwrap();
    assert_eq!(
        constrained.submit(read(2)).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    constrained.cancel(zero).unwrap();
    consume(&mut constrained);
    assert!(constrained.submit(read(2)).is_ok());
    q.cancel(token).unwrap();
    consume(&mut q);
}

#[test]
fn declared_128m_reply_allowance_does_not_charge_a_small_requested_extent() {
    let mut q = ReadQueue::with_compatible_admission(1, 4, 0, 1, 1).unwrap();
    let token = q
        .submit_compound(compound(vec![OsdOp::read(0, 4)], Access::Read, 128 << 20))
        .unwrap();
    assert_eq!(q.charged_bytes(), 4);
    let dispatch = q.dispatch(token, route()).unwrap();
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 1);
    reply.ops[0].outdata = b"data".to_vec().into();
    q.reply(token, 1, 2, reply).unwrap();
    let held = consume(&mut q);
    assert_eq!(q.charged_bytes(), 0);
    let next = q.submit(read(4)).unwrap(); // held result is outside operation credit
    assert!(
        matches!(&held.outcome, ReadOutcome::RemoteCompound { operations, .. } if operations[0].outdata.as_ref() == b"data")
    );
    q.cancel(next).unwrap();
    consume(&mut q);
}

fn publish_call_and_reenter(q: &mut ReadQueue, depth: u8) {
    let token = q
        .submit_compound(compound(
            vec![OsdOp::call(b"hello", b"say_hello", b"input")],
            Access::Read,
            31 << 20,
        ))
        .unwrap();
    let dispatch = q.dispatch(token, route()).unwrap();
    let mut reply = MOSDOpReply::for_request(&dispatch.message, 1);
    reply.ops[0].set_extent(Default::default()); // CALL reply reports actual output length.
    q.reply(token, 1, 2, reply).unwrap();
    let held = consume(q);
    assert_eq!((q.outstanding(), q.charged_bytes()), (0, 0));
    if depth < 3 {
        publish_call_and_reenter(q, depth + 1);
    }
    assert!(matches!(held.outcome, ReadOutcome::RemoteCompound { .. }));
}
#[test]
fn native_retirement_precedes_result_handoff_and_nested_application_reentry() {
    let mut q = ReadQueue::with_compatible_admission(1, 1, 0, 1, 1).unwrap();
    publish_call_and_reenter(&mut q, 0);
    assert_eq!((q.outstanding(), q.charged_bytes()), (0, 0));
}

#[test]
fn logical_charge_sum_and_invalid_extent_fail_without_slot_or_tid_mutation() {
    let mut q = ReadQueue::with_compatible_admission(1, 0, 0, 1, 1).unwrap();
    let overflow = compound(
        vec![
            OsdOp::read(0, i64::MAX as u64),
            OsdOp::read(0, i64::MAX as u64),
            OsdOp::read(0, 2),
        ],
        Access::Read,
        4,
    );
    assert_eq!(
        overflow.logical_byte_charge(),
        Err(AdmissionError::NoCredit)
    );
    assert_eq!(
        q.submit_compound(overflow).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    let invalid = compound(vec![OsdOp::read(0, u64::MAX)], Access::Read, 4);
    assert_eq!(
        q.submit_compound(invalid).unwrap_err().reason,
        AdmissionError::InvalidExtent
    );
    assert_eq!((q.outstanding(), q.charged_bytes()), (0, 0));
    assert_eq!(sequence_of_tid(q.submit(read(1)).unwrap().tid()), 1);
    assert_eq!(
        compound(vec![OsdOp::new(0xffff)], Access::Read, 4).logical_byte_charge(),
        Err(AdmissionError::UnsupportedOperation)
    );
}

#[test]
fn total_counter_overflow_does_not_spend_reserved_control_or_application_identity() {
    let mut q = ReadQueue::with_compatible_control_reserve(2, 0, 0, 1, 1, 1, 1).unwrap();
    let large = q
        .submit_compound(compound(
            vec![
                OsdOp::read(0, i64::MAX as u64),
                OsdOp::read(0, i64::MAX as u64),
            ],
            Access::Read,
            4,
        ))
        .unwrap();
    assert_eq!(q.charged_bytes(), u64::MAX - 1);
    let control = q
        .submit_reserved_control(ControlRequest {
            target: target(),
            operation: ControlOperation::Ping {
                cookie: 1,
                generation: 0,
            },
        })
        .unwrap();
    assert_eq!(q.charged_bytes(), u64::MAX);
    assert_eq!(
        q.submit(read(1)).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    assert_eq!(q.outstanding(), 2);
    q.cancel(control).unwrap();
    q.take_reserved_completion(control).unwrap();
    let last = q.submit(read(1)).unwrap();
    assert_eq!(
        sequence_of_tid(last.tid()),
        sequence_of_tid(control.tid()) + 1
    );
    q.cancel(large).unwrap();
    consume(&mut q);
    q.cancel(last).unwrap();
    consume(&mut q);
    assert_eq!((q.outstanding(), q.charged_bytes()), (0, 0));
}

#[test]
fn operation_family_charges_use_actual_contract_fields_not_reply_allowances() {
    for code in [
        op::STAT,
        op::ASSERT_VER,
        op::ISDIRTY,
        op::LIST_SNAPS,
        op::LIST_WATCHERS,
        op::CHECKSUM,
        op::CALL,
        op::OMAP_GET_KEYS,
        op::OMAP_GET_VALS,
        op::OMAP_GET_HEADER,
        op::OMAP_GET_VALS_BY_KEYS,
        op::OMAP_CMP,
        op::CACHE_FLUSH,
        op::CACHE_TRY_FLUSH,
        op::CACHE_EVICT,
        op::TIER_FLUSH,
        op::TIER_EVICT,
        op::SET_CHUNK,
        op::NOTIFY,
        op::NOTIFY_ACK,
        op::PGLS,
        op::PGLS_FILTER,
        op::PGNLS,
        op::PGNLS_FILTER,
        op::PG_HITSET_LS,
        op::PG_HITSET_GET,
        op::SCRUBLS,
    ] {
        let mut operation = OsdOp::read(0, 99);
        operation.op = code;
        operation.indata = vec![3; 7].into();
        assert_eq!(
            compound(vec![operation], Access::ReadWrite, 31 << 20).logical_byte_charge(),
            Ok(0),
            "zero family {code}"
        );
    }
    for code in [
        op::WRITE,
        op::WRITEFULL,
        op::APPEND,
        op::WRITESAME,
        op::ZERO,
        op::TRUNCATE,
        op::TRIMTRUNC,
        op::DELETE,
        op::CREATE,
        op::ROLLBACK,
        op::SET_ALLOC_HINT,
        op::SETXATTR,
        op::RMXATTR,
        op::OMAP_SET_VALS,
        op::OMAP_SET_HEADER,
        op::OMAP_RM_KEYS,
        op::OMAP_RM_KEY_RANGE,
        op::OMAP_CLEAR,
        op::TMAPUP,
        op::CACHE_PIN,
        op::CACHE_UNPIN,
        op::UNDIRTY,
        op::TIER_PROMOTE,
        op::UNSET_MANIFEST,
        op::COPY_FROM,
        op::COPY_FROM2,
        op::SET_REDIRECT,
        op::WATCH,
    ] {
        let mut operation = OsdOp::read(0, 99);
        operation.op = code;
        operation.indata = vec![3; 7].into();
        assert_eq!(
            compound(vec![operation], Access::ReadWrite, 31 << 20).logical_byte_charge(),
            Ok(7),
            "input family {code}"
        );
    }
    for code in [op::READ, op::SYNC_READ, op::SPARSE_READ, op::CMPEXT] {
        let mut operation = OsdOp::read(0, 13);
        operation.op = code;
        assert_eq!(
            compound(vec![operation], Access::ReadWrite, 31 << 20).logical_byte_charge(),
            Ok(13)
        );
    }
    for code in [op::GETXATTR, op::GETXATTRS, op::CMPXATTR] {
        let mut operation = OsdOp::setxattr(b"name", b"value");
        operation.op = code;
        assert_eq!(
            compound(vec![operation], Access::ReadWrite, 31 << 20).logical_byte_charge(),
            Ok(9)
        );
    }
    let repeated = OsdOp::writesame(0, 4096, vec![9; 16]);
    assert_eq!(
        compound(vec![repeated], Access::Write, 0).logical_byte_charge(),
        Ok(16)
    );
}

#[test]
fn independent_count_target_holds_zero_byte_calls_until_completion_consumption() {
    for byte_target in [0, 1] {
        for remote_reply in [false, true] {
            let mut q = ReadQueue::with_compatible_admission(3, byte_target, 1, 1, 1).unwrap();
            let call = || {
                compound(
                    vec![OsdOp::call(b"hello", b"say_hello", b"input")],
                    Access::Read,
                    32,
                )
            };
            let first = q.submit_compound(call()).unwrap();
            assert_eq!(q.charged_bytes(), 0);
            let rejected = q.submit_compound(call()).unwrap_err();
            assert_eq!(rejected.reason, AdmissionError::NoCredit);
            assert_eq!(rejected.request.operations, call().operations);
            assert_eq!(rejected.request.target, target());
            assert_eq!(rejected.request.max_output_bytes, 32);
            if remote_reply {
                let dispatch = q.dispatch(first, route()).unwrap();
                let mut reply = MOSDOpReply::for_request(&dispatch.message, 1);
                reply.ops[0].set_extent(Default::default());
                q.reply(first, 1, 2, reply).unwrap();
            } else {
                q.cancel(first).unwrap();
            }
            assert_eq!((q.outstanding(), q.charged_bytes()), (1, 0));
            let rejected = q.submit_compound(rejected.request).unwrap_err();
            assert_eq!(rejected.reason, AdmissionError::NoCredit);
            let held = consume(&mut q);
            let next = q.submit_compound(rejected.request).unwrap();
            assert_eq!(
                sequence_of_tid(next.tid()),
                sequence_of_tid(first.tid()) + 1
            );
            assert_eq!((q.outstanding(), q.charged_bytes()), (1, 0));
            q.cancel(next).unwrap();
            consume(&mut q);
            drop(held);
        }
    }
}

#[test]
fn count_and_control_reserve_have_independent_occupancy() {
    let mut q = ReadQueue::with_compatible_control_reserve(3, 0, 1, 1, 1, 1, 1).unwrap();
    let control = q
        .submit_reserved_control(ControlRequest {
            target: target(),
            operation: ControlOperation::Ping {
                cookie: 1,
                generation: 0,
            },
        })
        .unwrap();
    let call = || {
        compound(
            vec![OsdOp::call(b"hello", b"say_hello", b"")],
            Access::Read,
            1,
        )
    };
    let first = q.submit_compound(call()).unwrap();
    assert_eq!((q.outstanding(), q.reserved_control_outstanding()), (2, 1));
    assert_eq!(
        q.submit_compound(call()).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    q.cancel(control).unwrap();
    q.take_reserved_completion(control).unwrap();
    assert_eq!(
        q.submit_compound(call()).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    q.cancel(first).unwrap();
    assert_eq!(
        q.submit_compound(call()).unwrap_err().reason,
        AdmissionError::NoCredit
    );
    consume(&mut q);
    let next = q.submit_compound(call()).unwrap();
    assert_eq!(
        sequence_of_tid(next.tid()),
        sequence_of_tid(first.tid()) + 1
    );
    q.cancel(next).unwrap();
    consume(&mut q);
}

#[test]
fn count_target_never_expands_finite_storage() {
    for count_target in [0, u64::MAX] {
        let mut q = ReadQueue::with_compatible_admission(1, 0, count_target, 1, 1).unwrap();
        let first = q.submit(read(1)).unwrap();
        assert_eq!(
            q.submit(read(1)).unwrap_err().reason,
            AdmissionError::NoCredit
        );
        q.cancel(first).unwrap();
        consume(&mut q);
        assert_eq!(
            sequence_of_tid(q.submit(read(1)).unwrap().tid()),
            sequence_of_tid(first.tid()) + 1
        );
    }
}

#[test]
fn mapext_admission_wire_snapshot_and_reply_preserve_extent_map_semantics() {
    use bytes::Bytes;
    use denc::Encode;
    let map = std::collections::BTreeMap::from([(10u64, 2u64), (14, 1)])
        .encode_to_vec()
        .unwrap();
    assert!(map.len() > 16);
    for pool in [
        PoolRoute::Replicated,
        PoolRoute::Erasure(denc::types::ShardId(1)),
    ] {
        let mut operation = OsdOp::new(op::MAPEXT);
        operation.set_extent(opwire::Extent {
            offset: 9,
            length: 16,
            ..Default::default()
        });
        let mut request = compound(vec![operation], Access::Read, 128);
        request.context.snapid = 42;
        assert!(request.preflight(4096).is_ok());
        assert_eq!(request.preflight_compatible(), Ok(16));
        let mut q = ReadQueue::with_compatible_admission(1, 128, 0, 1, 2).unwrap();
        let token = q.submit_compound(request).unwrap();
        assert_eq!(q.charged_bytes(), 16);
        let route = ReadRoute { pool, ..route() };
        let dispatch = q.dispatch(token, route).unwrap();
        assert_eq!(dispatch.message.pgid.shard, pool.shard());
        assert_eq!(dispatch.message.snapid, 42);
        assert_eq!(dispatch.message.ops[0].op, op::MAPEXT);
        assert_eq!(dispatch.message.ops[0].extent().length, 16);
        assert!(dispatch.message.ops[0].indata.is_empty());
        let mut reply = MOSDOpReply::for_request(&dispatch.message, 1);
        let result = if pool == PoolRoute::Replicated {
            0
        } else {
            -95
        };
        reply.result = result;
        reply.ops[0].rval = result;
        if result == 0 {
            reply.ops[0].outdata = Bytes::from(map.clone());
        }
        assert!(q.reply(token, 1, 2, reply).unwrap());
        let ReadOutcome::RemoteCompound {
            result: actual,
            operations,
            ..
        } = consume(&mut q).outcome
        else {
            panic!("expected ordinary MAPEXT result")
        };
        assert_eq!(actual, result);
        assert_eq!(operations[0].extent().length, 16);
        if result == 0 {
            assert_eq!(operations[0].outdata.as_ref(), map);
        }
        assert_eq!(q.charged_bytes(), 0);
    }
}
#[test]
fn mapext_validates_request_shape_and_keeps_full_checked_range_budget() {
    let mut operation = OsdOp::new(op::MAPEXT);
    operation.set_extent(opwire::Extent {
        length: u64::MAX,
        ..Default::default()
    });
    let mut request = compound(vec![operation], Access::Read, 64);
    assert_eq!(request.preflight_compatible(), Ok(u64::MAX));
    let mut extent = request.operations[0].extent();
    extent.offset = 1;
    request.operations[0].set_extent(extent);
    assert_eq!(
        request.preflight_compatible(),
        Err(AdmissionError::InvalidExtent)
    );
    extent.offset = 0;
    extent.length = 1;
    request.operations[0].set_extent(extent);
    request.operations[0].indata = bytes::Bytes::from_static(b"invalid");
    assert_eq!(
        request.preflight_compatible(),
        Err(AdmissionError::InvalidExtent)
    );
    request.operations[0].indata = bytes::Bytes::new();
    request.access = Access::Write;
    assert_eq!(
        request.preflight_compatible(),
        Err(AdmissionError::InvalidOperation)
    );
}
