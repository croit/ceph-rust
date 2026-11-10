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
fn request(operations: Vec<OsdOp>, access: Access, legacy_reply: bool) -> CompoundRequest {
    CompoundRequest {
        target: Target {
            pool: 7,
            object: b"legacy-call".to_vec(),
            namespace: vec![0, 255],
            locator: vec![],
        },
        access,
        context: RequestContext {
            legacy_reply,
            ..Default::default()
        },
        operations,
        max_output_bytes: 64,
    }
}

#[test]
fn legacy_reply_omits_returnvec_only_when_selected() {
    for legacy in [false, true] {
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        let t = q
            .submit_compound(request(
                vec![OsdOp::call(b"hello", b"say_hello", b"world")],
                Access::Read,
                legacy,
            ))
            .unwrap();
        let d = q.dispatch(t, route()).unwrap();
        assert_eq!(d.message.ops[0].op, op::CALL);
        let flags = d.message.flags;
        assert_eq!(
            flags & (flag::READ | flag::ONDISK),
            flag::READ | flag::ONDISK
        );
        assert_eq!(
            flags & flag::RETURNVEC,
            if legacy { 0 } else { flag::RETURNVEC }
        );
        q.cancel(t).unwrap();
        q.poll_into(&mut [None]);
    }
}

#[test]
fn legacy_reply_is_restricted_to_a_single_call() {
    let mut q = ObjectQueue::new(1, 4096, 2).unwrap();
    for r in [
        request(vec![OsdOp::stat()], Access::Read, true),
        request(
            vec![OsdOp::call(b"hello", b"say_hello", b""), OsdOp::stat()],
            Access::Read,
            true,
        ),
        request(vec![OsdOp::writefull(vec![1])], Access::Write, true),
    ] {
        assert_eq!(
            q.submit_compound(r).unwrap_err().reason,
            AdmissionError::InvalidOperation
        );
    }
    assert_eq!(q.outstanding(), 0);
    // A single CALL is the one admitted legacy shape; default stays unrestricted.
    let t = q
        .submit_compound(request(
            vec![OsdOp::call(b"hello", b"say_hello", b"")],
            Access::Read,
            true,
        ))
        .unwrap();
    q.cancel(t).unwrap();
    q.poll_into(&mut [None]);
    assert!(
        q.submit_compound(request(
            vec![OsdOp::stat(), OsdOp::stat()],
            Access::Read,
            false
        ))
        .is_ok()
    );
}

#[test]
fn legacy_mutation_call_waits_for_durable_ack_and_keeps_suppressed_result() {
    let mut q = ObjectQueue::new(1, 4096, 3).unwrap();
    let t = q
        .submit_compound(request(
            vec![OsdOp::call(b"hello", b"write_return_data", b"payload")],
            Access::ReadWrite,
            true,
        ))
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(
        (d.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
        flag::READ | flag::ONDISK
    );
    // Early ACK: no write success before ONDISK.
    let mut early = MOSDOpReply::for_request(&d.message, 9);
    early.flags &= !u64::from(flag::ONDISK);
    early.ops[0].rval = 42;
    let mut extent = early.ops[0].extent();
    extent.length = 18;
    early.ops[0].set_extent(extent);
    assert!(!q.reply(t, 2, 3, early).unwrap());
    assert!(q.is_pending(t));
    assert_eq!(q.poll_into(&mut [None]), 0);
    // Durable legacy reply: the server suppresses the data but retains the
    // executed per-op status and declared descriptor length.
    let mut durable = MOSDOpReply::for_request(&d.message, 9);
    durable.ops[0].rval = 42;
    let mut e = durable.ops[0].extent();
    e.length = 18;
    durable.ops[0].set_extent(e);
    assert!(q.reply(t, 2, 3, durable).unwrap());
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert!(matches!(
        &out[0].as_ref().unwrap().outcome,
        ReadOutcome::RemoteCompound { result: 0, operations, .. }
            if operations.len() == 1
                && operations[0].op == op::CALL
                && operations[0].rval == 42
                && operations[0].extent().length == 18
                && operations[0].outdata.is_empty()
    ));
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn retry_preserves_legacy_and_default_reply_mode() {
    for legacy in [false, true] {
        let mut q = ObjectQueue::with_retry_limit(1, 8192, 4, 3).unwrap();
        let t = q
            .submit_compound(request(
                vec![OsdOp::call(b"version", b"read", b"")],
                Access::Read,
                legacy,
            ))
            .unwrap();
        q.set_deadline_us(t, 100, 100).unwrap();
        let first = q.dispatch(t, route()).unwrap();
        q.retry(t).unwrap();
        let fresh = q
            .dispatch(
                t,
                ReadRoute {
                    session: 4,
                    epoch: 10,
                    ..route()
                },
            )
            .unwrap();
        let expected = flag::READ | flag::ONDISK | if legacy { 0 } else { flag::RETURNVEC };
        assert_eq!(
            (first.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
            expected
        );
        assert_eq!(
            (fresh.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
            expected | flag::RETRY
        );
        assert_eq!(fresh.message.ops, first.message.ops);
        assert_eq!(fresh.message.reqid, first.message.reqid);
    }
}

#[test]
fn legacy_suppression_guard_rejects_malformed_mismatches() {
    // The only accepted mismatch is the narrow legacy suppression shape
    // (legacy single-CALL write, overall 0, nonnegative per-op, empty data).
    // Every malformed variant of the same length/data mismatch is rejected.
    for case in 0..5u8 {
        let (legacy, class, method, read, result, rval, data) = match case {
            // Default vector mode keeps strict descriptor/data equality.
            0 => (
                false,
                &b"hello"[..],
                &b"write_return_data"[..],
                false,
                0,
                42,
                0,
            ),
            // Pure Read legacy: the exception is write-only.
            1 => (true, &b"hello"[..], &b"say_hello"[..], true, 0, 0, 0),
            // Nonzero overall result.
            2 => (
                true,
                &b"hello"[..],
                &b"write_return_data"[..],
                false,
                1,
                42,
                0,
            ),
            // Negative overall result.
            3 => (
                true,
                &b"hello"[..],
                &b"write_return_data"[..],
                false,
                -5,
                42,
                0,
            ),
            // Nonempty mismatched data.
            4 => (
                true,
                &b"hello"[..],
                &b"write_return_data"[..],
                false,
                0,
                42,
                3,
            ),
            _ => unreachable!(),
        };
        let mut q = ObjectQueue::new(1, 4096, 6).unwrap();
        let t = q
            .submit_compound(request(
                vec![OsdOp::call(class, method, b"payload")],
                if read {
                    Access::Read
                } else {
                    Access::ReadWrite
                },
                legacy,
            ))
            .unwrap();
        let d = q.dispatch(t, route()).unwrap();
        let mut r = MOSDOpReply::for_request(&d.message, 9);
        r.result = result;
        r.ops[0].rval = rval;
        if data > 0 {
            r.ops[0].outdata = vec![7; data].into();
        }
        let mut e = r.ops[0].extent();
        e.length = 18;
        r.ops[0].set_extent(e);
        assert_eq!(
            q.reply(t, 2, 3, r),
            Err(DriverError::InvalidReply),
            "case {case}"
        );
        assert!(q.is_pending(t));
        q.cancel(t).unwrap();
        q.poll_into(&mut [None]);
    }
}

#[test]
fn default_returnvec_keeps_positive_class_status_and_output() {
    let mut q = ObjectQueue::new(1, 4096, 5).unwrap();
    let t = q
        .submit_compound(request(
            vec![OsdOp::call(b"hello", b"write_return_data", b"payload")],
            Access::ReadWrite,
            false,
        ))
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    assert_ne!(d.message.flags & flag::RETURNVEC, 0);
    let mut r = MOSDOpReply::for_request(&d.message, 9);
    let outdata: Bytes = b"you might see this".to_vec().into();
    r.ops[0].outdata = outdata.clone();
    r.ops[0].rval = 42;
    let mut e = r.ops[0].extent();
    e.length = 18;
    r.ops[0].set_extent(e);
    assert!(q.reply(t, 2, 3, r).unwrap());
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert!(matches!(
        &out[0].as_ref().unwrap().outcome,
        ReadOutcome::RemoteCompound { result: 0, operations, .. }
            if operations[0].rval == 42
                && operations[0].outdata == outdata
    ));
    assert_eq!(q.charged_bytes(), 0);
}
