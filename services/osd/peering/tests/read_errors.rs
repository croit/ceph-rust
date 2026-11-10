// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Local read errors never turn into "new object", "absent" or "nothing to do" in the write / recovery / push
//! paths (adr 0042).
mod common;
use common::*;
use denc::types::{Eversion, Hobject};
use peering::{Body, WriteErr};
use replwire::{MOSDPGPush, ObjectRecoveryInfo, ObjectRecoveryProgress, PushOp, ReplMsg};
use std::collections::BTreeMap;

fn damage(s: &mut Sim, osd: i32, name: &str) {
    s.nodes
        .get_mut(&osd)
        .unwrap()
        .store
        .pgs
        .get_mut(&spg(1, 0))
        .unwrap()
        .objects
        .get_mut(&hobj(1, name))
        .unwrap()
        .xattrs
        .insert(b"_".to_vec(), vec![0xff; 3]);
}

/// Unreadable object_info of an existing object: a write is refused (EIO), never logged with prior version 0'0.
#[test]
fn write_to_object_with_unreadable_info_is_refused() {
    // log trimmed: the prior version of "x" can only come from the store
    let mut s = cluster_cfg(81, &[0, 1, 2], 1, 3, 2, 1, |c| {
        c.min_pg_log_entries = 10;
        c.pg_log_trim_min = 1;
        c.pg_log_trim_max = 50;
        c.log_dups_tracked = 20;
    });
    let pg = spg(1, 0);
    let mut tids = vec![s.write_obj(1, 0, "x", b"hello").unwrap()];
    for i in 0..60 {
        tids.push(s.write_obj(1, 0, &format!("f{i}"), b"f").unwrap());
        s.run_for(MS);
    }
    s.wait_writes(&tids, pg);
    s.run_for(2_000 * MS);
    let primary = s.primary_of(pg.pgid);
    let head = s.pg(primary, pg).unwrap().info().last_update;
    damage(&mut s, primary, "x");
    assert_eq!(
        s.write_obj(1, 0, "x", b"world"),
        Err(WriteErr::TooBig(5)),
        "EIO, not a silent 0'0 prior"
    );
    assert_eq!(
        s.pg(primary, pg).unwrap().info().last_update,
        head,
        "no log entry"
    );
    // a genuinely new object still works
    assert!(s.write_obj(1, 0, "y", b"new").is_ok());
}

/// The primary's own copy of an object a peer misses is damaged: recovery must not skip it forever; it pulls the
/// object from the other replica and then completes the push.
#[test]
fn recovery_with_damaged_primary_copy_repulls_from_peer() {
    let mut s = cluster(82, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let acting = s.acting_of(pg.pgid);
    let (primary, victim) = (acting[0], acting[2]);
    s.kill(victim);
    s.run_for(300 * MS);
    let t = s.write_obj(1, 0, "x", b"payload").unwrap();
    s.wait_writes(&[t], pg);
    damage(&mut s, primary, "x");
    s.restart(victim);
    s.run_until(120_000 * MS, "victim has x", |s| {
        s.nodes[&victim]
            .store
            .objects(pg)
            .get(&hobj(1, "x"))
            .is_some_and(|o| o.data == b"payload")
    });
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    let p = s.pg(primary, pg).unwrap();
    assert!(
        p.counters().errors.keys().any(|k| k.contains("re-pulling")),
        "counted: {:?}",
        p.counters().errors
    );
}

/// A partial push (kept ranges come from the local copy) onto an unreadable local copy is refused: applying it
/// would zero the unpushed ranges.
#[test]
fn partial_push_onto_unreadable_local_copy_is_refused() {
    let mut s = cluster(83, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let big = vec![7u8; 4096];
    let t = s.write_obj(1, 0, "x", &big).unwrap();
    s.wait_writes(&[t], pg);
    let primary = s.primary_of(pg.pgid);
    let replica = s.acting_of(pg.pgid)[1];
    damage(&mut s, replica, "x");
    let before = s.nodes[&replica].store.objects(pg);
    let v = s.pg(primary, pg).unwrap().info().last_update;
    let ri = ObjectRecoveryInfo {
        soid: hobj(1, "x"),
        version: v,
        size: 4096,
        copy_subset: BTreeMap::from([(0, 100)]),
        object_exist: true,
        ..Default::default()
    };
    let op = PushOp {
        soid: hobj(1, "x"),
        version: v,
        data: vec![1u8; 100].into(),
        data_included: BTreeMap::from([(0, 100)]),
        recovery_info: ri,
        before_progress: ObjectRecoveryProgress::default(),
        after_progress: ObjectRecoveryProgress {
            first: false,
            data_complete: false,
            data_recovered_to: 100,
            omap_recovered_to: vec![],
            omap_complete: false,
        },
        ..Default::default()
    };
    let m = MOSDPGPush {
        pgid: pg,
        map_epoch: s.epoch(),
        pushes: vec![op],
        cost: 0,
        from: denc::types::PgShard {
            osd: primary,
            shard: denc::types::ShardId::NO_SHARD,
        },
        min_epoch: s.epoch(),
        is_repair: false,
    };
    s.capture = true;
    s.inject(primary, replica, Body::Repl(ReplMsg::Push(m)));
    s.run_for(2_000 * MS);
    let r = s.pg(replica, pg).unwrap();
    assert!(
        r.counters()
            .errors
            .keys()
            .any(|k| k.contains("partial push")),
        "errors {:?} discards {:?}",
        r.counters().errors,
        r.counters().discards
    );
    let after = s.nodes[&replica].store.objects(pg);
    assert_eq!(
        before.get(&hobj(1, "x")).map(|o| &o.data),
        after.get(&hobj(1, "x")).map(|o| &o.data),
        "nothing applied"
    );
    assert!(
        !s.captured
            .iter()
            .any(|(_, _, b)| matches!(b, Body::Repl(ReplMsg::PushReply(_)))),
        "no ack for a refused push"
    );
    let _ = (Eversion::default(), Hobject::MIN());
}
