// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
use denc::types::{PgT, UTime};
use opwire::{MOSDOp, MOSDOpReply, OsdOp, flag};
use rustyrados::*;

fn cases() -> Vec<(u64, Vec<u64>, bool)> {
    let max = opwire::NOSNAP - 1;
    vec![
        (9, vec![8, 8], false),
        (9, vec![7, 8], false),
        (9, vec![10], false),
        (9, vec![0, 1], false),
        (9, vec![0, 0], false),
        (0, vec![0], true),
        (9, vec![8, 0], true),
        (0, vec![], true),
        (max, vec![max], true),
        (max, vec![], true),
        (opwire::NOSNAP, vec![], false),
        (u64::MAX, vec![], false),
        (9, vec![opwire::NOSNAP], false),
        (9, vec![8, u64::MAX], false),
    ]
}
fn request(sequence: u64, ids: &[u64]) -> CompoundRequest {
    CompoundRequest {
        target: Target {
            pool: 7,
            object: b"snapshot-write".to_vec(),
            namespace: vec![],
            locator: vec![],
        },
        access: Access::ReadWrite,
        context: RequestContext {
            snap_sequence: sequence,
            snapshots: ids.to_vec(),
            mtime: UTime::new(123, 9),
            ..Default::default()
        },
        operations: vec![OsdOp::writefull(b"data".to_vec())],
        max_output_bytes: 0,
    }
}
fn route(session: u64) -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 7,
        osd: 2,
        session,
        pg: PgT { pool: 7, seed: 4 },
        hash: 55,
        epoch: 9,
        features: 0,
        generation: 1,
        pool: PoolRoute::Replicated,
    }
}
fn assert_wire(dispatch: &ReadDispatch, sequence: u64, ids: &[u64]) {
    for version in [8, 9] {
        let wire = dispatch.message.encode_version(version, 0).unwrap();
        let decoded = MOSDOp::decode_shared(version, &wire.front, &wire.data).unwrap();
        assert_eq!(decoded.snap_seq, sequence);
        assert_eq!(decoded.snaps, ids);
        assert_eq!(decoded.snapid, opwire::NOSNAP);
        assert_eq!(decoded.ops[0].indata.as_ref(), b"data");
        assert_eq!(decoded.mtime, UTime::new(123, 9));
    }
}

#[test]
fn strict_preflight_and_queue_keep_predicate_while_compatible_paths_accept_all_contexts() {
    for (sequence, ids, valid) in cases() {
        let r = request(sequence, &ids);
        assert_eq!(r.preflight_compatible(), Ok(4));
        if valid {
            assert!(r.preflight(8192).is_ok());
        } else {
            assert_eq!(r.preflight(8192), Err(AdmissionError::InvalidSnapshot));
        }
        let mut strict = ObjectQueue::new(1, 8192, 19).unwrap();
        match strict.submit_compound(r) {
            Ok(token) => {
                assert!(valid);
                strict.cancel(token).unwrap();
                strict.poll_into(&mut [None]);
            }
            Err(rejected) => {
                assert!(!valid);
                assert_eq!(rejected.reason, AdmissionError::InvalidSnapshot);
            }
        }
        let mut compatible = ObjectQueue::with_compatible_admission(1, 8192, 0, 19, 1).unwrap();
        let token = compatible.submit_compound(request(sequence, &ids)).unwrap();
        assert_wire(
            &compatible.dispatch(token, route(3)).unwrap(),
            sequence,
            &ids,
        );
    }
}

#[test]
fn compatible_context_preserves_owned_wire_and_remote_error_or_normalized_success_through_retry() {
    for (sequence, original, _) in cases() {
        for result in [-22, -85, 0] {
            let mut caller = original.clone();
            let mut queue = ObjectQueue::with_compatible_admission(1, 8192, 0, 19, 3).unwrap();
            queue.enable_mutation_retries().unwrap();
            let token = queue.submit_compound(request(sequence, &caller)).unwrap();
            caller.fill(u64::MAX);
            caller.clear();
            queue.set_deadline_us(token, 100, 100).unwrap();
            let fence = queue.fence();
            let charge = queue.charged_bytes();
            let first = queue.dispatch(token, route(3)).unwrap();
            assert_wire(&first, sequence, &original);
            queue.retry(token).unwrap();
            let next = queue.dispatch(token, route(4)).unwrap();
            assert_wire(&next, sequence, &original);
            assert_eq!(next.message.reqid, first.message.reqid);
            assert_eq!(next.wire_tid(), first.wire_tid());
            assert_eq!(next.message.retry_attempt, 1);
            assert_eq!(queue.deadline_us(token), Some(100));
            assert_eq!(queue.charged_bytes(), charge);
            assert_eq!(
                queue.reply(token, 2, 3, MOSDOpReply::for_request(&first.message, 9)),
                Err(DriverError::Stale)
            );
            let mut reply = MOSDOpReply::for_request(&next.message, 9);
            reply.result = result;
            reply.ops[0].rval = result;
            reply.user_version = 77;
            if result == 0 {
                let mut early = reply.clone();
                early.flags &= !u64::from(flag::ONDISK);
                assert!(!queue.reply(token, 2, 4, early).unwrap());
                assert_eq!(queue.poll_into(&mut [None]), 0);
            }
            // A success can represent server context substitution/filtering. The
            // client must not replace it with a locally predicted context errno.
            assert!(queue.reply(token, 2, 4, reply.clone()).unwrap());
            assert_eq!(queue.reply(token, 2, 4, reply), Err(DriverError::Stale));
            assert_eq!(
                queue.fence_status(fence),
                Ok(FenceStatus::Ready(if result == 0 {
                    Ok(())
                } else {
                    Err((
                        token.tid(),
                        WriteFailure::Remote {
                            result,
                            op_result: result,
                        },
                    ))
                }))
            );
            let mut output = [None];
            assert_eq!(queue.poll_into(&mut output), 1);
            assert!(matches!(output[0].as_ref().unwrap().outcome,
                ReadOutcome::RemoteCompound { result: actual, user_version: 77, .. } if actual == result));
            assert_eq!(queue.charged_bytes(), 0);
            assert_eq!(queue.poll_into(&mut [None]), 0);
        }
    }
}

#[test]
fn compatible_context_policy_keeps_head_access_read_and_operation_shape_validation() {
    let mut r = request(9, &[8, 8]);
    r.context.snapid = 7;
    assert_eq!(
        r.preflight_compatible(),
        Err(AdmissionError::InvalidSnapshot)
    );
    r.context.snapid = opwire::NOSNAP;
    r.access = Access::Read;
    r.operations = vec![OsdOp::read(0, 4)];
    assert_eq!(
        r.preflight_compatible(),
        Err(AdmissionError::InvalidSnapshot)
    );
    r.access = Access::ReadWrite;
    r.operations.clear();
    assert_eq!(r.preflight_compatible(), Ok(0));
    assert_eq!(r.preflight(8192), Err(AdmissionError::InvalidOperation));
}
