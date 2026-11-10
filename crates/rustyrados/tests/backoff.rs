// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use denc::types::{Hobject, PgT, ShardId, SnapId, SpgT};
use opwire::{MOSDBackoff, consts::backoff};
use rustyrados::*;
fn target(name: &[u8]) -> Target {
    Target {
        pool: 7,
        object: name.to_vec(),
        namespace: vec![],
        locator: vec![],
    }
}
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
fn bound(name: &[u8]) -> Hobject {
    Hobject {
        pool: 7,
        oid: name.to_vec(),
        hash: 55,
        snap: SnapId(opwire::NOSNAP),
        ..Hobject::MIN()
    }
}
fn block(begin: Hobject, end: Hobject) -> MOSDBackoff {
    MOSDBackoff {
        pgid: SpgT {
            pgid: route().pg,
            shard: ShardId::NO_SHARD,
        },
        map_epoch: 9,
        op: backoff::BLOCK,
        id: 0,
        begin,
        end,
    }
}

#[test]
fn overlay_backoff_compares_effective_pool_without_rewriting_application_target() {
    let mut r = route();
    r.pg.pool = 8;
    let mut begin = bound(b"a");
    begin.pool = 8;
    let mut end = bound(b"c");
    end.pool = 8;
    let mut message = block(begin, end);
    message.pgid.pgid = r.pg;
    assert!(BackoffTable::contains(
        &message,
        r,
        &target(b"b"),
        opwire::NOSNAP
    ));
    let mut table = BackoffTable::new(1, 4096);
    table.on_message(r.osd, r.session, message.clone()).unwrap();
    assert!(table.blocked(r, &target(b"b"), opwire::NOSNAP));
    message.begin.pool = 7;
    message.end.pool = 7;
    assert!(!BackoffTable::contains(
        &message,
        r,
        &target(b"b"),
        opwire::NOSNAP
    ));
}
#[test]
fn point_half_open_range_and_exact_ack_echo() {
    let mut table = BackoffTable::new(2, 1000);
    let b = block(bound(b"a"), bound(b"c"));
    let ack = table.on_message(2, 3, b.clone()).unwrap().unwrap();
    let mut expected = b.clone();
    expected.op = backoff::ACK_BLOCK;
    assert_eq!(ack, expected);
    assert!(table.blocked(route(), &target(b"a"), opwire::NOSNAP));
    assert!(table.blocked(route(), &target(b"b"), opwire::NOSNAP));
    assert!(!table.blocked(route(), &target(b"c"), opwire::NOSNAP));
    let mut release = b;
    release.op = backoff::UNBLOCK;
    table.on_message(2, 3, release).unwrap();
    table
        .on_message(2, 3, block(bound(b"b"), bound(b"b")))
        .unwrap();
    assert!(table.blocked(route(), &target(b"b"), opwire::NOSNAP));
    assert!(!table.blocked(route(), &target(b"a"), opwire::NOSNAP));
}

#[test]
fn namespace_key_snapshot_and_reversed_hash_match_full_hobject_order() {
    let mut table = BackoffTable::new(1, 1000);
    let mut object = bound(b"object");
    object.key = b"key".to_vec();
    object.nspace = vec![255, 0];
    object.snap = SnapId(17);
    table
        .on_message(2, 3, block(object.clone(), object.clone()))
        .unwrap();
    let t = Target {
        pool: 7,
        object: b"object".to_vec(),
        locator: b"key".to_vec(),
        namespace: vec![255, 0],
    };
    assert!(table.blocked(route(), &t, 17));
    assert!(!table.blocked(route(), &t, 18));
    assert!(!table.blocked(
        ReadRoute {
            hash: 56,
            ..route()
        },
        &t,
        17
    ));
    let mut other = t.clone();
    other.namespace = vec![];
    assert!(!table.blocked(route(), &other, 17));
    table.reset_session(2, 3);
    let low = Hobject {
        pool: 7,
        hash: 2,
        ..Hobject::MIN()
    };
    let high = Hobject {
        pool: 7,
        hash: 1,
        ..Hobject::MIN()
    }; // reversed hash 2 < reversed hash 1
    table.on_message(2, 3, block(low, high)).unwrap();
    assert!(table.blocked(
        ReadRoute { hash: 2, ..route() },
        &target(b"a"),
        opwire::NOSNAP
    ));
    assert!(!table.blocked(
        ReadRoute { hash: 1, ..route() },
        &target(b"a"),
        opwire::NOSNAP
    ));
}

#[test]
fn duplicate_conflicting_id_and_quota_never_evict_existing_block() {
    let mut table = BackoffTable::new(1, 1000);
    let b = block(bound(b"a"), bound(b"z"));
    table.on_message(2, 3, b.clone()).unwrap();
    let charged = table.charged_bytes();
    assert!(table.on_message(2, 3, b.clone()).unwrap().is_some());
    assert_eq!(table.charged_bytes(), charged);
    let mut conflict = b.clone();
    conflict.map_epoch += 1;
    assert_eq!(table.on_message(2, 3, conflict), Err(BackoffError::Invalid));
    let mut another = b.clone();
    another.id = 1;
    assert_eq!(table.on_message(2, 3, another), Err(BackoffError::NoCredit));
    assert!(table.blocked(route(), &target(b"b"), opwire::NOSNAP));
    let mut tiny = BackoffTable::new(1, 0);
    assert_eq!(tiny.on_message(2, 3, b), Err(BackoffError::NoCredit));
}

#[test]
fn stale_unblock_cannot_clear_replacement_session_and_reset_releases_credit() {
    let mut table = BackoffTable::new(1, 1000);
    let b = block(Hobject::MIN(), Hobject::MAX());
    table.on_message(2, 3, b.clone()).unwrap();
    table.reset_session(2, 3);
    assert_eq!(table.charged_bytes(), 0);
    table.on_message(2, 4, b.clone()).unwrap();
    let mut release = b;
    release.op = backoff::UNBLOCK;
    assert_eq!(table.on_message(2, 3, release.clone()).unwrap(), None);
    assert!(table.blocked(
        ReadRoute {
            session: 4,
            ..route()
        },
        &target(b"b"),
        opwire::NOSNAP
    ));
    table.on_message(2, 4, release).unwrap();
    assert_eq!(table.charged_bytes(), 0);
    assert!(!table.blocked(
        ReadRoute {
            session: 4,
            ..route()
        },
        &target(b"b"),
        opwire::NOSNAP
    ));
}

#[test]
fn blocked_dispatch_preserves_token_credit_attempt_and_deadline() {
    let mut table = BackoffTable::new(1, 1000);
    let b = block(bound(b"a"), bound(b"z"));
    table.on_message(2, 3, b.clone()).unwrap();
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    let t = q
        .submit(ReadRequest {
            target: target(b"b"),
            offset: 0,
            length: 16,
        })
        .unwrap();
    q.set_deadline_us(t, 100, 100).unwrap();
    let credit = q.charged_bytes();
    assert_eq!(
        q.dispatch_with_backoff(t, route(), &table).unwrap_err(),
        DriverError::BackedOff
    );
    assert_eq!(q.charged_bytes(), credit);
    assert_eq!(q.next_deadline_us(), Some(100));
    let mut release = b;
    release.op = backoff::UNBLOCK;
    table.on_message(2, 3, release).unwrap();
    let d = q.dispatch_with_backoff(t, route(), &table).unwrap();
    assert_eq!(d.token, t);
    assert_eq!(d.message.retry_attempt, 0);
}

#[test]
fn ec_backoff_spgs_never_block_other_shards_or_replicated_routes() {
    let mut table = BackoffTable::new(2, 1000);
    let mut b = block(bound(b"a"), bound(b"c"));
    b.pgid.shard = ShardId(2);
    let ack = table.on_message(2, 3, b.clone()).unwrap().unwrap();
    assert_eq!(ack.pgid.shard, ShardId(2));
    for shard in [0, 1, 2] {
        let r = ReadRoute {
            pool: PoolRoute::Erasure(ShardId(shard)),
            ..route()
        };
        assert_eq!(
            BackoffTable::contains(&b, r, &target(b"b"), opwire::NOSNAP),
            shard == 2
        );
        assert_eq!(table.blocked(r, &target(b"b"), opwire::NOSNAP), shard == 2);
    }
    assert!(!table.blocked(route(), &target(b"b"), opwire::NOSNAP));
    let mut stale_release = b.clone();
    stale_release.pgid.shard = ShardId(1);
    stale_release.op = backoff::UNBLOCK;
    assert_eq!(
        table.on_message(2, 3, stale_release),
        Err(BackoffError::Invalid)
    );
    let mut release = b;
    release.op = backoff::UNBLOCK;
    table.on_message(2, 3, release).unwrap();
    assert!(!table.blocked(
        ReadRoute {
            pool: PoolRoute::Erasure(ShardId(2)),
            ..route()
        },
        &target(b"b"),
        opwire::NOSNAP
    ));
}

#[test]
fn map_revalidation_drops_only_stale_ec_range_and_returns_credit() {
    let mut table = BackoffTable::new(2, 1000);
    for (id, shard) in [(0, 1), (1, 2)] {
        let mut b = block(bound(b"a"), bound(b"c"));
        b.id = id;
        b.pgid.shard = ShardId(shard);
        table.on_message(2, 3, b).unwrap();
    }
    let before = table.charged_bytes();
    table.retain(|_, _, b| b.pgid.shard == ShardId(2));
    assert!(table.charged_bytes() < before);
    assert!(table.block_for_id(2, 3, 0).is_none());
    assert!(table.block_for_id(2, 3, 1).is_some());
    assert!(!table.blocked(
        ReadRoute {
            pool: PoolRoute::Erasure(ShardId(1)),
            ..route()
        },
        &target(b"b"),
        opwire::NOSNAP
    ));
    assert!(table.blocked(
        ReadRoute {
            pool: PoolRoute::Erasure(ShardId(2)),
            ..route()
        },
        &target(b"b"),
        opwire::NOSNAP
    ));
}

#[test]
fn compatible_population_and_bytes_follow_server_ownership_with_exact_release() {
    let mut table = BackoffTable::new_compatible();
    let mut messages = Vec::new();
    for id in 0..129 {
        let mut b = block(bound(&vec![b'a'; 512]), bound(&vec![b'z'; 512]));
        b.id = id;
        table.on_message(2, 3, b.clone()).unwrap();
        messages.push(b);
    }
    let total = 129 * 1024;
    assert_eq!(table.charged_bytes(), total);
    table.on_message(2, 3, messages[0].clone()).unwrap();
    assert_eq!(table.charged_bytes(), total);
    // Same ID on another connection is separately owned and cannot gate this one.
    table.on_message(2, 4, messages[0].clone()).unwrap();
    let mut release = messages[0].clone();
    release.op = backoff::UNBLOCK;
    table.on_message(2, 3, release.clone()).unwrap();
    table.on_message(2, 3, release).unwrap();
    assert_eq!(table.charged_bytes(), total);
    assert!(table.block_for_id(2, 3, 0).is_none());
    assert!(table.block_for_id(2, 4, 0).is_some());
    table.retain(|_, session, b| session == 4 || b.id % 2 == 0);
    assert_eq!(table.charged_bytes(), 65 * 1024);
    table.reset_session(2, 3);
    assert_eq!(table.charged_bytes(), 1024);
    table.clear();
    assert_eq!(table.charged_bytes(), 0);
    assert!(table.block_for_id(2, 4, 0).is_none());
}

#[test]
fn strict_initial_population_and_byte_limits_remain_hard() {
    let b = block(bound(b"a"), bound(b"z"));
    let mut table = BackoffTable::new(1, 2);
    table.on_message(2, 3, b.clone()).unwrap();
    let mut next = b.clone();
    next.id = 1;
    assert_eq!(table.on_message(2, 3, next), Err(BackoffError::NoCredit));
    table.reset_session(2, 3);
    let large = block(bound(b"aa"), bound(b"zz"));
    assert_eq!(table.on_message(2, 3, large), Err(BackoffError::NoCredit));
    assert_eq!(table.charged_bytes(), 0);
    table.on_message(2, 3, b).unwrap();
    assert_eq!(table.charged_bytes(), 2);
}

#[test]
fn compatible_identity_conflicts_and_current_session_range_gates_are_exact() {
    let mut table = BackoffTable::new_compatible();
    let b = block(bound(b"a"), bound(b"c"));
    table.on_message(2, 3, b.clone()).unwrap();
    table
        .on_message(2, 4, block(bound(b"x"), bound(b"z")))
        .unwrap();
    let charged = table.charged_bytes();
    let mut conflict = b.clone();
    conflict.map_epoch += 1;
    assert_eq!(table.on_message(2, 3, conflict), Err(BackoffError::Invalid));
    let mut wrong_release = b.clone();
    wrong_release.op = backoff::UNBLOCK;
    wrong_release.pgid.shard = ShardId(0);
    assert_eq!(
        table.on_message(2, 3, wrong_release),
        Err(BackoffError::Invalid)
    );
    assert_eq!(table.charged_bytes(), charged);
    assert_eq!(table.block_for_id(2, 3, 0), Some(&b));
    assert!(table.blocked(route(), &target(b"b"), opwire::NOSNAP));
    assert!(!table.blocked(
        ReadRoute {
            session: 4,
            ..route()
        },
        &target(b"b"),
        opwire::NOSNAP
    ));
    assert!(!table.blocked(
        ReadRoute { osd: 3, ..route() },
        &target(b"b"),
        opwire::NOSNAP
    ));
    table.reset_session(2, 3);
    assert_eq!(table.charged_bytes(), 2);
    assert!(table.blocked(
        ReadRoute {
            session: 4,
            ..route()
        },
        &target(b"y"),
        opwire::NOSNAP
    ));
    table.reset_session(2, 4);
    assert_eq!(table.charged_bytes(), 0);
}

#[test]
fn retained_credit_counts_owned_clone_instead_of_input_spare_capacity() {
    for compatible in [false, true] {
        let mut table = if compatible {
            BackoffTable::new_compatible()
        } else {
            BackoffTable::new(1, 2)
        };
        let mut begin = bound(b"a");
        begin.oid.reserve(8192);
        let mut end = bound(b"z");
        end.oid.reserve(8192);
        let message = block(begin, end);
        table.on_message(2, 3, message).unwrap();
        assert_eq!(table.charged_bytes(), 2);
        table.reset_session(2, 3);
        assert_eq!(table.charged_bytes(), 0);
    }
}
