// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
use bytes::Bytes;
use denc::types::{ObjectLocator, PgT};
use opwire::{MOSDOpReply, OsdOp, RequestRedirect, flag};
use rustyrados::*;

fn target() -> Target {
    Target {
        pool: 7,
        object: b"redirected\0object".to_vec(),
        namespace: vec![0, 255],
        locator: b"placement-key".to_vec(),
    }
}
fn route(pool: u64) -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 7,
        osd: 2,
        session: 3,
        pg: PgT { pool, seed: 4 },
        hash: 55,
        epoch: 9,
        generation: 1,
        features: 0,
        pool: PoolRoute::Replicated,
    }
}
fn submit(q: &mut ObjectQueue, kind: usize) -> RequestToken {
    match kind {
        0 => q
            .submit(ReadRequest {
                target: target(),
                offset: 19,
                length: 4,
            })
            .unwrap(),
        1 => q
            .submit_write(WriteRequest {
                target: target(),
                operation: WriteOperation::Append,
                payload: Bytes::from_static(b"once"),
            })
            .unwrap(),
        2 | 3 => q
            .submit_compound(CompoundRequest {
                target: target(),
                access: if kind == 2 {
                    Access::Read
                } else {
                    Access::Write
                },
                context: RequestContext {
                    snapid: if kind == 2 { 17 } else { opwire::NOSNAP },
                    snap_sequence: if kind == 2 { 0 } else { 23 },
                    snapshots: if kind == 2 { vec![] } else { vec![19, 11] },
                    ..Default::default()
                },
                operations: if kind == 2 {
                    vec![OsdOp::read(19, 4)]
                } else {
                    vec![OsdOp::writefull_bytes(Bytes::from_static(b"once"))]
                },
                max_output_bytes: if kind == 2 { 4 } else { 0 },
            })
            .unwrap(),
        4 => q
            .submit_control(ControlRequest {
                target: target(),
                operation: ControlOperation::Register {
                    cookie: 42,
                    timeout_seconds: 30,
                },
            })
            .unwrap(),
        _ => unreachable!(),
    }
}
fn redirect(d: &ReadDispatch) -> MOSDOpReply {
    let mut reply = MOSDOpReply::for_request(&d.message, d.route.epoch);
    // A redirect can omit ordinary operation results. The effective locator is
    // reset by ordinary reference routing; server readonly-cache redirects fall
    // back to the captured base pool with cache/overlay bypass.
    reply.ops.clear();
    reply.redirect = Some(RequestRedirect {
        oloc: ObjectLocator {
            pool: 99,
            key: b"other-key".to_vec(),
            ..Default::default()
        },
        redirect_object: b"other-object".to_vec(),
    });
    reply
}
#[test]
fn redirects_retain_all_request_kinds_and_allocate_distinct_wire_identities() {
    for kind in 0..5 {
        let mut q = ObjectQueue::with_retry_limit(2, 4096, 12, 1).unwrap();
        let token = submit(&mut q, kind);
        q.set_deadline_us(token, 1000, 1000).unwrap();
        let first = q.dispatch(token, route(8)).unwrap();
        assert_eq!(first.wire_tid(), token.tid());
        assert_ne!(first.message.flags & 0x0040_0000, 0); // KNOWN_REDIR, both pins.
        let charged = q.charged_bytes();
        let mut current = first;
        for attempt in 1..=3 {
            let old_wire = current.wire_tid();
            let old_reply = redirect(&current);
            assert_eq!(
                q.reply_for_recovery(token, 2, 99, old_reply.clone()),
                Err(DriverError::Stale)
            );
            let Ok(ReplyAction::Redirected { wire_tid }) =
                q.reply_for_recovery(token, 2, 3, old_reply.clone())
            else {
                panic!("redirect must retain kind {kind}");
            };
            assert!(wire_tid > old_wire);
            assert_eq!(q.target(token), Some(&target()));
            assert_eq!(q.deadline_us(token), Some(1000));
            assert_eq!(q.charged_bytes(), charged);
            assert_eq!(q.poll_into(&mut [None]), 0);
            let next = q.dispatch(token, route(7)).unwrap();
            assert_eq!(next.token, token);
            assert_eq!(next.wire_tid(), wire_tid);
            assert_eq!(next.message.retry_attempt, attempt);
            assert_eq!(next.message.oid, current.message.oid);
            assert_eq!(next.message.oloc.pool, 7);
            assert_eq!(next.message.oloc.key, current.message.oloc.key);
            assert_eq!(next.message.oloc.nspace, current.message.oloc.nspace);
            assert_eq!(next.message.ops, current.message.ops);
            assert_eq!(next.message.reqid, current.message.reqid);
            assert_eq!(next.message.snapid, current.message.snapid);
            assert_eq!(next.message.snap_seq, current.message.snap_seq);
            assert_eq!(next.message.snaps, current.message.snaps);
            assert_eq!(next.message.mtime, current.message.mtime);
            let bypass = flag::REDIRECTED | flag::IGNORE_CACHE | flag::IGNORE_OVERLAY;
            assert_eq!(next.message.flags & bypass, bypass);
            assert_eq!(
                q.reply_for_recovery(token, 2, 3, old_reply),
                Err(DriverError::Stale)
            );
            current = next;
        }
        let fresh = submit(&mut q, 0);
        assert!(fresh.tid() > current.wire_tid());
        let mut reply = MOSDOpReply::for_request(&current.message, 9);
        if kind == 0 || kind == 2 {
            reply.ops[0].outdata = Bytes::from_static(b"data");
        }
        assert_eq!(
            q.reply_for_recovery(token, 2, 3, reply),
            Ok(ReplyAction::Completed)
        );
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert_eq!(out[0].as_ref().unwrap().token, token);
        let outcome = &out[0].as_ref().unwrap().outcome;
        assert!(
            if kind == 2 || kind == 3 {
                matches!(outcome, ReadOutcome::RemoteCompound { result: 0, .. })
            } else {
                matches!(outcome, ReadOutcome::Remote { result: 0, .. })
            },
            "kind {kind}: {outcome:?}"
        );
        q.cancel(fresh).unwrap();
        out[0] = None;
        assert_eq!(q.poll_into(&mut out), 1);
        assert_eq!(q.charged_bytes(), 0);
    }
}
#[test]
fn redirect_preserves_cancellation_and_original_deadline() {
    for expire in [false, true] {
        let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
        let token = submit(&mut q, 1);
        q.set_deadline_us(token, 1000, 1000).unwrap();
        let d = q.dispatch(token, route(8)).unwrap();
        assert!(matches!(
            q.reply_for_recovery(token, 2, 3, redirect(&d)),
            Ok(ReplyAction::Redirected { .. })
        ));
        if expire {
            q.expire_token_us(token, 1000).unwrap();
        } else {
            q.cancel(token).unwrap();
        }
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert_eq!(out[0].as_ref().unwrap().token, token);
        if expire {
            assert!(matches!(
                out[0].as_ref().unwrap().outcome,
                ReadOutcome::Deadline {
                    possibly_sent: true
                }
            ));
        } else {
            assert!(matches!(
                out[0].as_ref().unwrap().outcome,
                ReadOutcome::PossiblySent
            ));
        }
        assert_eq!(q.poll_into(&mut out), 0);
        assert_eq!(q.charged_bytes(), 0);
    }
}
