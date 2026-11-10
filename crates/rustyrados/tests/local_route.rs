// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::PgT;
use rustyrados::*;
fn route() -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 7,
        osd: 0,
        session: 10,
        pg: PgT { pool: 7, seed: 1 },
        hash: 3,
        epoch: 1,
        features: 0,
        generation: 1,
        pool: rustyrados::PoolRoute::Replicated,
    }
}
fn request() -> WriteRequest {
    WriteRequest {
        target: Target {
            pool: 7,
            object: b"append".to_vec(),
            namespace: vec![0, 255],
            locator: b"key".to_vec(),
        },
        operation: WriteOperation::Append,
        payload: Bytes::from_static(b"once"),
    }
}
#[test]
fn overlay_pool_is_on_wire_while_base_identity_and_unaccepted_attempt_remain_owned() {
    let mut q = ObjectQueue::new(1, 4096, 9).unwrap();
    let token = q.submit_write(request()).unwrap();
    let mut r = route();
    r.pg.pool = 8;
    let mut dispatch = q.dispatch(token, r).unwrap();
    assert_eq!(q.target(token).unwrap().pool, 7);
    assert_eq!(dispatch.route.base_pool, 7);
    assert_eq!(dispatch.message.oloc.pool, 8);
    assert_eq!(dispatch.message.pgid.pgid.pool, 8);
    let request_id = dispatch.message.reqid;
    r.pg.pool = 9;
    r.generation += 1;
    q.refresh_unaccepted(&mut dispatch, r).unwrap();
    assert_eq!(dispatch.message.oloc.pool, 9);
    assert_eq!(dispatch.message.reqid, request_id);
    assert_eq!(dispatch.message.retry_attempt, 0);
    assert_eq!(q.target(token).unwrap().pool, 7);
}
#[test]
fn explicit_ignore_overlay_cannot_be_bypassed_by_a_cross_pool_route() {
    let mut q = ObjectQueue::new(1, 4096, 9).unwrap();
    let target = request().target;
    let token = q
        .submit_compound(CompoundRequest {
            target,
            access: Access::Read,
            context: RequestContext {
                osd_flags: opwire::flag::IGNORE_OVERLAY,
                ..Default::default()
            },
            operations: vec![opwire::OsdOp::read(0, 1)],
            max_output_bytes: 1,
        })
        .unwrap();
    let mut foreign = route();
    foreign.pg.pool = 8;
    assert_eq!(
        q.dispatch(token, foreign).unwrap_err(),
        DriverError::InvalidRoute
    );
    assert_eq!(q.dispatch(token, route()).unwrap().message.retry_attempt, 0);
}
#[test]
fn unaccepted_append_retargets_without_retry_permission_budget_identity_or_payload_change() {
    let mut q = ObjectQueue::with_retry_limit(1, 4096, 9, 1).unwrap();
    let t = q.submit_write(request()).unwrap();
    q.set_deadline_us(t, 100, 100).unwrap();
    q.set_full_policy(t, FullPolicy::Try).unwrap();
    let fence = q.fence();
    let charge = q.charged_bytes();
    let mut d = q.dispatch(t, route()).unwrap();
    let old = d.message.clone();
    let fresh = ReadRoute {
        direct_read: false,
        osd: 2,
        session: 20,
        pg: PgT {
            seed: 2,
            ..route().pg
        },
        hash: 17,
        epoch: 8,
        features: 42,
        ..route()
    };
    q.refresh_unaccepted(&mut d, fresh).unwrap();
    assert_eq!(d.token, t);
    assert_eq!(d.route, fresh);
    assert_eq!(d.message.osdmap_epoch, 8);
    assert_eq!(d.message.hash, 17);
    assert_eq!(d.message.pgid.pgid, fresh.pg);
    assert_eq!(d.message.features, 42);
    assert_eq!(d.message.retry_attempt, 0);
    assert_eq!(d.message.flags, old.flags);
    assert_eq!(d.message.reqid, old.reqid);
    assert_eq!(d.message.oid, old.oid);
    assert_eq!(d.message.oloc, old.oloc);
    assert_eq!(d.message.ops, old.ops);
    assert_eq!(d.message.ops[0].indata.as_ptr(), old.ops[0].indata.as_ptr());
    assert_eq!(q.charged_bytes(), charge);
    assert_eq!(q.deadline_us(t), Some(100));
    assert_eq!(q.fence_status(fence), Ok(FenceStatus::Pending));
    assert_eq!(q.retry(t), Err(DriverError::UnsupportedRetry));
    assert_eq!(
        q.set_full_policy(t, FullPolicy::Force),
        Err(DriverError::AlreadyDispatched)
    );
    q.cancel(t).unwrap();
    let mut out = [None];
    q.poll_into(&mut out);
    assert_eq!(out[0].as_ref().unwrap().outcome, ReadOutcome::PossiblySent);
    assert_eq!(q.refresh_unaccepted(&mut d, fresh), Err(DriverError::Stale));
    assert_eq!(q.charged_bytes(), 0);
}
#[test]
fn invalid_refresh_preserves_queue_and_original_owned_dispatch() {
    let mut q = ObjectQueue::with_retry_limit(1, 4096, 9, 1).unwrap();
    let t = q.submit_write(request()).unwrap();
    q.set_deadline_us(t, 100, 100).unwrap();
    let mut d = q.dispatch(t, route()).unwrap();
    let original = d.message.clone();
    for bad in [
        ReadRoute {
            generation: 1,
            pool: rustyrados::PoolRoute::Erasure(denc::types::ShardId::NO_SHARD),
            ..route()
        },
        ReadRoute {
            session: 0,
            ..route()
        },
        ReadRoute {
            epoch: 0,
            ..route()
        },
        ReadRoute {
            direct_read: false,
            base_pool: 99,
            ..route()
        },
    ] {
        assert_eq!(
            q.refresh_unaccepted(&mut d, bad),
            Err(DriverError::InvalidRoute)
        );
        assert_eq!(d.message, original);
        assert_eq!(d.route, route());
        assert_eq!(q.deadline_us(t), Some(100));
    }
    d.message.retry_attempt = 1;
    assert_eq!(
        q.refresh_unaccepted(&mut d, route()),
        Err(DriverError::Stale)
    );
    d.message.retry_attempt = 0;
    let mut other = ObjectQueue::new(1, 4096, 9).unwrap();
    d.token = other.submit_write(request()).unwrap();
    assert_eq!(
        q.refresh_unaccepted(&mut d, route()),
        Err(DriverError::Stale)
    );
    d.token = t;
    d.route.session = 99;
    assert_eq!(
        q.refresh_unaccepted(&mut d, route()),
        Err(DriverError::Stale)
    );
    d.route = route();
    q.refresh_unaccepted(
        &mut d,
        ReadRoute {
            epoch: 2,
            ..route()
        },
    )
    .unwrap();
    assert_eq!(d.message.retry_attempt, 0);
    assert!(q.expire_token_us(t, 100).unwrap());
    let mut out = [None];
    q.poll_into(&mut out);
    assert_eq!(
        out[0].as_ref().unwrap().outcome,
        ReadOutcome::Deadline {
            possibly_sent: true
        }
    );
}
#[test]
fn refresh_rebuilds_compound_from_immutable_snapshot_context_instead_of_mutated_wire_data() {
    let mut q = ObjectQueue::with_retry_limit(1, 4096, 9, 1).unwrap();
    let t = q
        .submit_compound(CompoundRequest {
            target: request().target,
            access: Access::Write,
            context: RequestContext {
                snap_sequence: 59,
                snapshots: vec![57, 50],
                mtime: denc::types::UTime::new(123, 456),
                ..Default::default()
            },
            operations: vec![opwire::OsdOp::append(b"once".to_vec())],
            max_output_bytes: 0,
        })
        .unwrap();
    q.set_full_policy(t, FullPolicy::Force).unwrap();
    q.set_deadline_us(t, 100, 100).unwrap();
    let mut d = q.dispatch(t, route()).unwrap();
    let mut expected = d.message.clone();
    let fresh = ReadRoute {
        epoch: 2,
        ..route()
    };
    expected.osdmap_epoch = 2;
    d.message.ops.clear();
    d.message.snap_seq = 1;
    d.message.snaps.clear();
    d.message.client_inc = 88;
    d.message.flags = 0;
    q.refresh_unaccepted(&mut d, fresh).unwrap();
    assert_eq!(d.message, expected);
    assert_eq!(q.deadline_us(t), Some(100));
}
