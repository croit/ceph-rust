// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::PgT;
use opwire::flag;
use rustyrados::*;
fn target() -> Target {
    Target {
        pool: 7,
        object: b"map-gate".to_vec(),
        namespace: vec![],
        locator: vec![],
    }
}
fn route() -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 7,
        osd: 0,
        session: 1,
        pg: PgT { pool: 7, seed: 0 },
        hash: 0,
        epoch: 1,
        features: 0,
        generation: 1,
        pool: rustyrados::PoolRoute::Replicated,
    }
}
fn write(q: &mut ObjectQueue) -> RequestToken {
    q.submit_write(WriteRequest {
        target: target(),
        operation: WriteOperation::Append,
        payload: Bytes::from_static(b"once"),
    })
    .unwrap()
}
#[test]
fn fullness_policy_is_exact_immutable_across_retry_and_reset_on_slot_reuse() {
    for (policy, expected) in [
        (FullPolicy::Wait, 0),
        (FullPolicy::Try, flag::FULL_TRY),
        (FullPolicy::Force, flag::FULL_FORCE),
    ] {
        let mut q = ObjectQueue::with_retry_limit(1, 4096, 1, 2).unwrap();
        q.enable_mutation_retries().unwrap();
        let t = write(&mut q);
        q.set_deadline_us(t, 100, 100).unwrap();
        q.set_full_policy(t, policy).unwrap();
        assert_eq!(
            q.request_flags(t),
            Some(flag::WRITE | flag::RWORDERED | expected)
        );
        let d = q.dispatch(t, route()).unwrap();
        assert_eq!(
            (d.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
            flag::WRITE | flag::RWORDERED | flag::ONDISK | expected
        );
        assert_eq!(
            q.set_full_policy(t, FullPolicy::Wait),
            Err(DriverError::AlreadyDispatched)
        );
        q.retry(t).unwrap();
        assert_eq!(
            q.set_full_policy(t, FullPolicy::Wait),
            Err(DriverError::AlreadyDispatched)
        );
        let retry = q.dispatch(t, route()).unwrap();
        assert_eq!(retry.token, t);
        assert_eq!(retry.message.flags, d.message.flags | flag::RETRY);
        q.cancel(t).unwrap();
        assert_eq!(q.set_full_policy(t, policy), Err(DriverError::Stale));
        q.poll_into(&mut [None]);
        let fresh = write(&mut q);
        assert_eq!(q.request_flags(fresh), Some(flag::WRITE | flag::RWORDERED));
        assert_eq!(q.set_full_policy(t, policy), Err(DriverError::Stale));
    }
}
#[test]
fn readwrite_classification_matches_encoded_message_and_foreign_token_is_passive() {
    let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
    let mut other = ObjectQueue::new(1, 4096, 1).unwrap();
    let foreign = write(&mut other);
    let t = q
        .submit_compound(CompoundRequest {
            target: target(),
            access: Access::ReadWrite,
            context: Default::default(),
            operations: vec![
                opwire::OsdOp::read(0, 1),
                opwire::OsdOp::writefull(b"x".to_vec()),
            ],
            max_output_bytes: 1,
        })
        .unwrap();
    assert_eq!(
        q.set_full_policy(foreign, FullPolicy::Force),
        Err(DriverError::Stale)
    );
    let before = q.request_flags(t).unwrap();
    assert_eq!(before, flag::READ | flag::WRITE | flag::RWORDERED);
    assert_eq!(
        (q.dispatch(t, route()).unwrap().message.flags)
            & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
        before | flag::RETURNVEC | flag::ONDISK
    );
}
#[test]
fn base_pool_eio_precedes_fullness_and_ping_pause_policy_does_not_change_its_write_route() {
    use osdmap::{
        OsdMap,
        consts::map_flags as mf,
        pool::{PgPool, flags as pf},
    };
    let mut map = OsdMap::default();
    map.pools.insert(
        7,
        PgPool {
            flags: pf::EIO | pf::FULL,
            read_tier: 8,
            write_tier: 9,
            ..Default::default()
        },
    );
    for flags in [
        flag::READ,
        flag::WRITE,
        flag::WRITE | flag::FULL_TRY,
        flag::WRITE | flag::FULL_FORCE,
    ] {
        assert_eq!(
            map_request_gate(&map, 7, flags),
            Err(LocalRequestError::PoolIo)
        );
    }
    map.pools.get_mut(&7).unwrap().flags = pf::FULL;
    let mut q = ObjectQueue::new(1, 4096, 9).unwrap();
    let token = q
        .submit_control(ControlRequest {
            target: target(),
            operation: ControlOperation::Ping {
                cookie: 1,
                generation: 0,
            },
        })
        .unwrap();
    assert_eq!(q.request_flags(token), Some(flag::WRITE));
    let flags = q.request_gate_context(token).unwrap().pausing_flags();
    assert_eq!(map_request_gate(&map, 7, flags), Ok(false));
    map.flags = mf::PAUSEWR;
    assert_eq!(map_request_gate(&map, 7, flags), Ok(false));
    map.flags = mf::PAUSERD;
    assert_eq!(map_request_gate(&map, 7, flags), Ok(true));
    assert_eq!(q.fence_status(q.fence()), Ok(FenceStatus::Ready(Ok(()))));
}
#[test]
fn map_gate_truth_table_distinguishes_pause_full_quota_and_unrelated_pool() {
    use osdmap::{
        OsdMap,
        consts::map_flags as mf,
        pool::{PgPool, flags as pf},
    };
    // Expected booleans are independent from production bit expressions.
    for (map_flag, pool_flag, read_wait, write_wait) in [
        (0, 0, false, false),
        (mf::PAUSERD, 0, true, false),
        (mf::PAUSEWR, 0, false, true),
        (mf::FULL, 0, false, true),
        (0, pf::FULL, false, true),
        (0, pf::FULL | pf::FULL_QUOTA, false, true),
        (0, pf::FULL_QUOTA, false, false),
        (mf::NEARFULL, 0, false, false),
        (0, pf::NEARFULL | pf::BACKFILLFULL, false, false),
        (mf::PAUSERD | mf::PAUSEWR | mf::FULL, pf::FULL, true, true),
    ] {
        let mut map = OsdMap::default();
        map.flags = map_flag;
        let pool = PgPool {
            flags: pool_flag,
            ..Default::default()
        };
        map.pools.insert(7, pool);
        map.pools.insert(8, PgPool::default());
        for (access, reads, writes) in [
            (flag::READ, true, false),
            (flag::WRITE, false, true),
            (flag::READ | flag::WRITE, true, true),
        ] {
            assert_eq!(
                map_pauses_request(&map, 7, access),
                (reads && read_wait) || (writes && write_wait)
            );
            for override_flag in [flag::FULL_TRY, flag::FULL_FORCE] {
                let expected = (reads && map_flag & mf::PAUSERD != 0)
                    || (writes && map_flag & mf::PAUSEWR != 0);
                assert_eq!(
                    map_pauses_request(&map, 7, access | override_flag),
                    expected
                );
            }
        }
        assert!(!map_pauses_request(&map, 99, flag::READ | flag::WRITE));
        if map_flag == 0 {
            assert!(!map_pauses_request(&map, 8, flag::WRITE));
        }
    }
}
#[test]
fn compound_captured_fullness_policy_is_in_initial_flags_and_slot_reuse_is_default() {
    for (policy, flags) in [
        (FullPolicy::Wait, 0),
        (FullPolicy::Try, flag::FULL_TRY),
        (FullPolicy::Force, flag::FULL_FORCE),
    ] {
        let mut q = ObjectQueue::with_retry_limit(1, 4096, 91, 2).unwrap();
        q.enable_mutation_retries().unwrap();
        let token = q
            .submit_compound(CompoundRequest {
                target: target(),
                access: Access::ReadWrite,
                context: RequestContext {
                    full_policy: policy,
                    ..Default::default()
                },
                operations: vec![opwire::OsdOp::writefull(vec![9])],
                max_output_bytes: 0,
            })
            .unwrap();
        q.set_deadline_us(token, 100, 100).unwrap();
        assert_eq!(
            q.request_flags(token),
            Some(flag::READ | flag::WRITE | flag::RWORDERED | flags)
        );
        let sent = q.dispatch(token, route()).unwrap();
        assert_eq!(
            (sent.message.flags) & !(opwire::flag::KNOWN_REDIR | opwire::flag::SUPPORTSPOOLEIO),
            flag::READ | flag::WRITE | flag::RWORDERED | flag::ONDISK | flag::RETURNVEC | flags
        );
        assert_eq!(
            q.set_full_policy(token, FullPolicy::Wait),
            Err(DriverError::AlreadyDispatched)
        );
        q.retry(token).unwrap();
        assert_eq!(
            q.dispatch(token, route()).unwrap().message.flags,
            sent.message.flags | flag::RETRY
        );
        q.cancel(token).unwrap();
        q.poll_into(&mut [None]);
        let fresh = write(&mut q);
        assert_eq!(q.request_flags(fresh), Some(flag::WRITE | flag::RWORDERED));
    }
}
