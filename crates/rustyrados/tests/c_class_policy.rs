// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
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
fn request(read_api: bool, mode: Option<WriteOpReply>) -> CompoundRequest {
    CompoundRequest {
        target: Target {
            pool: 7,
            object: b"class".to_vec(),
            namespace: vec![],
            locator: vec![],
        },
        access: if mode.is_some() {
            Access::ReadWrite
        } else {
            Access::Read
        },
        context: RequestContext {
            read_op: read_api.then_some(ReadOpReply::ReturnVector),
            write_op: mode,
            ..Default::default()
        },
        operations: vec![OsdOp::call(b"custom", b"unknown", b"input")],
        max_output_bytes: 64,
    }
}
#[test]
fn explicit_read_api_forwards_unknown_class_with_read_wire_policy_but_no_mutation_replay() {
    let mut queue = ObjectQueue::with_retry_limit(1, 8192, 201, 3).unwrap();
    assert_eq!(
        queue
            .submit_compound(request(false, None))
            .unwrap_err()
            .reason,
        AdmissionError::InvalidOperation
    );
    let token = queue.submit_compound(request(true, None)).unwrap();
    queue.set_deadline_us(token, 100, 100).unwrap();
    let dispatch = queue.dispatch(token, route()).unwrap();
    assert_eq!(
        (dispatch.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
        flag::READ | flag::ONDISK | flag::RETURNVEC
    );
    assert_eq!(queue.retry(token), Err(DriverError::UnsupportedRetry));
    let mut early = MOSDOpReply::for_request(&dispatch.message, 9);
    early.flags &= !u64::from(flag::ONDISK);
    early.ops[0].set_extent(Default::default());
    assert!(!queue.reply(token, 2, 3, early).unwrap());
    assert!(queue.is_pending(token));
    let mut durable = MOSDOpReply::for_request(&dispatch.message, 9);
    durable.ops[0].set_extent(Default::default());
    assert!(queue.reply(token, 2, 3, durable).unwrap());
    assert_eq!(queue.poll_into(&mut [None]), 1);
    assert_eq!(queue.charged_bytes(), 0);
}
#[test]
fn read_api_is_exclusive_and_does_not_admit_ordinary_writes() {
    let mut queue = ObjectQueue::new(1, 8192, 202).unwrap();
    let mut wrong_access = request(true, Some(WriteOpReply::Legacy));
    assert_eq!(
        queue.submit_compound(wrong_access).unwrap_err().reason,
        AdmissionError::InvalidOperation
    );
    wrong_access = request(true, None);
    wrong_access.context.legacy_reply = true;
    assert_eq!(
        queue.submit_compound(wrong_access).unwrap_err().reason,
        AdmissionError::InvalidOperation
    );
    let mut ordinary = request(true, None);
    ordinary.operations = vec![OsdOp::writefull(vec![1])];
    assert_eq!(
        queue.submit_compound(ordinary).unwrap_err().reason,
        AdmissionError::InvalidOperation
    );
    assert_eq!((queue.outstanding(), queue.charged_bytes()), (0, 0));
}
#[test]
fn c_write_call_suppression_is_narrow_and_default_vector_remains_strict() {
    for (mode, overall, data, accepted) in [
        (WriteOpReply::Legacy, 0, vec![], true),
        (WriteOpReply::ReturnVector, 0, vec![], false),
        (WriteOpReply::Legacy, 1, vec![], false),
        (WriteOpReply::Legacy, 0, vec![1, 2], false),
    ] {
        let mut queue = ObjectQueue::new(1, 8192, 203).unwrap();
        let mut req = request(false, Some(mode));
        req.operations.insert(0, OsdOp::writefull(vec![9]));
        let token = queue.submit_compound(req).unwrap();
        let dispatch = queue.dispatch(token, route()).unwrap();
        assert_eq!(dispatch.message.flags & flag::READ, 0);
        let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
        reply.result = overall;
        reply.ops[1].rval = 42;
        let mut extent = reply.ops[1].extent();
        extent.length = 18;
        reply.ops[1].set_extent(extent);
        reply.ops[1].outdata = data.into();
        if accepted {
            assert!(queue.reply(token, 2, 3, reply).unwrap());
            let mut out = [None];
            assert_eq!(queue.poll_into(&mut out), 1);
            assert!(
                matches!(&out[0].as_ref().unwrap().outcome,ReadOutcome::RemoteCompound {result:0,operations,..} if operations[1].op==op::CALL&&operations[1].rval==42&&operations[1].outdata.is_empty())
            );
        } else {
            assert_eq!(
                queue.reply(token, 2, 3, reply),
                Err(DriverError::InvalidReply)
            );
            assert!(queue.is_pending(token));
            queue.cancel(token).unwrap();
            queue.poll_into(&mut [None]);
        }
        assert_eq!(queue.charged_bytes(), 0);
    }
}
#[test]
fn c_read_legacy_suppresses_only_successful_empty_mutating_call() {
    for (mode, overall, data, accepted) in [
        (ReadOpReply::Legacy, 0, vec![], true),
        (ReadOpReply::ReturnVector, 0, vec![], false),
        (ReadOpReply::Legacy, 42, vec![], false),
        (ReadOpReply::Legacy, 0, vec![1], false),
    ] {
        let mut queue = ObjectQueue::new(1, 8192, 204).unwrap();
        let mut req = request(true, None);
        req.context.read_op = Some(mode);
        let token = queue.submit_compound(req).unwrap();
        let dispatch = queue.dispatch(token, route()).unwrap();
        assert_eq!(
            (dispatch.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
            flag::READ
                | flag::ONDISK
                | if mode == ReadOpReply::Legacy {
                    0
                } else {
                    flag::RETURNVEC
                }
        );
        let mut reply = MOSDOpReply::for_request(&dispatch.message, 9);
        reply.result = overall;
        reply.ops[0].rval = 42;
        let mut extent = reply.ops[0].extent();
        extent.length = 18;
        reply.ops[0].set_extent(extent);
        reply.ops[0].outdata = data.into();
        if accepted {
            assert!(queue.reply(token, 2, 3, reply).unwrap());
        } else {
            assert_eq!(
                queue.reply(token, 2, 3, reply),
                Err(DriverError::InvalidReply)
            );
            queue.cancel(token).unwrap();
        }
        assert_eq!(queue.poll_into(&mut [None]), 1);
        assert_eq!(queue.charged_bytes(), 0);
    }
}
