// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Log algorithms in isolation (spec pglog.md 4.1, 6, 7).
#![expect(clippy::field_reassign_with_default)]
use denc::types::{Eversion, Hobject, SnapId};
use peering::plog::*;
use peering::{Config, StoreOp};
use pgwire::*;

fn ev(e: u32, v: u64) -> Eversion {
    Eversion::new(e, v)
}
fn h(name: &str) -> Hobject {
    Hobject::new(
        name.as_bytes(),
        SnapId::NOSNAP,
        name.bytes().map(|b| b as u32).sum(),
        1,
        b"",
    )
}
fn ent(op: LogOp, name: &str, v: Eversion, prior: Eversion) -> LogEntry {
    LogEntry::new(op, h(name), v, prior)
}
fn mk(entries: Vec<LogEntry>, tail: Eversion) -> IndexedLog {
    let head = entries.last().map_or(tail, |e| e.version);
    IndexedLog::new(PgLog {
        head,
        tail,
        log: entries.into(),
        can_rollback_to: head,
        rollback_info_trimmed_to: head,
        dups: Default::default(),
    })
}
fn info_for(log: &IndexedLog) -> PgInfo {
    let mut i = PgInfo::new(denc::types::SpgT::default());
    i.last_update = log.head();
    i.last_complete = log.head();
    i.log_tail = log.tail();
    i.history.epoch_created = 1;
    i
}
fn removed(ops: &[StoreOp]) -> Vec<String> {
    ops.iter()
        .filter_map(|o| match o {
            StoreOp::RemoveObject(h) => Some(String::from_utf8_lossy(&h.oid).to_string()),
            _ => None,
        })
        .collect()
}

/// An offline NP shard can keep an unacknowledged full write while a replacement primary commits a partial write
/// to the same object on other shards. That newer log entry supplies no replacement bytes for this shard.
fn np_merge_skipped_authoritative_write(rollbackable: bool) {
    let prior = ev(1, 1);
    let common = ent(LogOp::MODIFY, "a", prior, Eversion::default());
    let mut divergent = ent(LogOp::MODIFY, "a", ev(2, 2), prior);
    if rollbackable {
        let mut builder = ec::moddesc::ModDescBuilder::new();
        builder.append(8192);
        let (bl, version, _) = builder.finish();
        divergent.mod_desc = ObjectModDesc {
            version,
            can_local_rollback: true,
            rollback_info_completed: true,
            bl,
        };
    } else {
        divergent.mod_desc = ObjectModDesc::unrollbackable();
    }
    let mut local = mk(vec![common.clone(), divergent], Eversion::default());
    local.log.can_rollback_to = prior;
    local.log.rollback_info_trimmed_to = prior;
    let mut replacement = ent(LogOp::MODIFY, "a", ev(3, 3), prior);
    replacement.written_shards.0[0] = 0b1101;
    // The first write in the new interval is forced-all per PG (not per object). A write to b consumes that
    // flag, then an in-place update to a can legitimately skip NP1, whose authoritative a bytes are unchanged.
    let mut authoritative = mk(
        vec![
            common,
            ent(LogOp::MODIFY, "b", ev(3, 2), Eversion::default()),
            replacement,
        ],
        Eversion::default(),
    );
    authoritative.log.can_rollback_to = prior;
    authoritative.log.rollback_info_trimmed_to = prior;
    let ctx = peering::ecroll::EcCtx {
        stripe_width: 8192,
        chunk: 4096,
        shard: 1,
        opt: true,
        k: 2,
        raw: 1,
        np: true,
        np_set: 0b10,
        epoch: 4,
    };
    let mut info = info_for(&local);
    let mut missing = MissingSet::new(true);
    let mut ops = Vec::new();
    merge_log_ec(
        &mut local,
        &mut info,
        &mut missing,
        &mut ops,
        &info_for(&authoritative),
        &authoritative.log,
        ctx,
    )
    .unwrap();
    assert_eq!(local.head(), ev(3, 3));
    if rollbackable {
        assert!(
            removed(&ops).is_empty(),
            "the prior shard must survive: {ops:?}"
        );
        assert!(
            !missing.contains(&h("a")),
            "rollback restores the prior shard"
        );
        assert!(
            ops.iter().any(|op| matches!(op,
                StoreOp::Shard(shard_ops) if shard_ops.iter().any(|op| matches!(op,
                    peering::store::ShardOp::Truncate { soid, size: 4096, .. } if *soid == h("a")
                ))
            )),
            "the divergent write must be undone: {ops:?}"
        );
    } else {
        assert_eq!(removed(&ops), vec!["a"]);
        let item = missing
            .get(&h("a"))
            .expect("removed shard must be recovered");
        // the object is at the skipped authoritative version: recovery sources hold that version, not the prior one
        assert_eq!(item.need, ev(3, 3));
        assert_eq!(item.have, Eversion::default());
    }
}

#[test]
fn np_merge_skipped_authoritative_write_rolls_back_divergence() {
    np_merge_skipped_authoritative_write(true);
}

#[test]
fn np_merge_skipped_authoritative_write_recovers_unrollbackable_divergence() {
    np_merge_skipped_authoritative_write(false);
}

#[test]
fn extending_merge_rolls_common_omap_forward_to_divergent_delete_stash() {
    use ec::moddesc::{EcOmap, ModDescBuilder, OmapUp};
    use peering::store::ShardOp;
    let created = ent(LogOp::MODIFY, "a", ev(1, 1), Eversion::default());
    let mut common = ent(LogOp::MODIFY, "a", ev(1, 2), ev(1, 1));
    let mut builder = ModDescBuilder::new();
    builder.ec_omap(&EcOmap {
        ups: vec![OmapUp::Insert(vec![(b"acked".to_vec(), b"value".to_vec())])],
        ..Default::default()
    });
    let (bl, version, _) = builder.finish();
    common.mod_desc = ObjectModDesc {
        version,
        can_local_rollback: true,
        rollback_info_completed: true,
        bl,
    };
    let mut deleted = ent(LogOp::DELETE, "a", ev(2, 3), common.version);
    let mut builder = ModDescBuilder::new();
    builder.delete(deleted.version.version);
    let (bl, version, _) = builder.finish();
    deleted.mod_desc = ObjectModDesc {
        version,
        can_local_rollback: true,
        rollback_info_completed: true,
        bl,
    };
    // The acknowledged omap update is still in the journal; the divergent delete moved its object to gen 3.
    let mut local = mk(
        vec![created.clone(), common.clone(), deleted],
        Eversion::default(),
    );
    local.log.can_rollback_to = created.version;
    local.log.rollback_info_trimmed_to = created.version;
    let mut authoritative = mk(
        vec![
            created,
            common.clone(),
            ent(LogOp::MODIFY, "b", ev(3, 4), Eversion::default()),
        ],
        Eversion::default(),
    );
    authoritative.log.can_rollback_to = common.version;
    authoritative.log.rollback_info_trimmed_to = common.version;
    let ctx = peering::ecroll::EcCtx {
        stripe_width: 8192,
        chunk: 4096,
        opt: true,
        k: 2,
        np_set: 0b10,
        epoch: 4,
        ..Default::default()
    };
    let mut info = info_for(&local);
    let mut missing = MissingSet::new(true);
    let mut ops = Vec::new();
    merge_log_ec(
        &mut local,
        &mut info,
        &mut missing,
        &mut ops,
        &info_for(&authoritative),
        &authoritative.log,
        ctx,
    )
    .unwrap();
    let shard_ops: Vec<_> = ops
        .iter()
        .filter_map(|op| match op {
            StoreOp::Shard(ops) => Some(ops.iter()),
            _ => None,
        })
        .flatten()
        .collect();
    let omap = shard_ops
        .iter()
        .position(|op| {
            matches!(op,
                ShardOp::Omap { soid, generation: 3, .. } if *soid == h("a")
            )
        })
        .expect("acknowledged omap must be applied to the delete stash");
    let restore = shard_ops.iter().position(|op| matches!(op,
        ShardOp::Rename { soid, from_gen: 3, to_gen: peering::ecroll::LIVE } if *soid == h("a")
    )).expect("divergent delete must be rolled back");
    assert!(
        omap < restore,
        "update the stash before it becomes the live object"
    );
    assert!(!missing.contains(&h("a")));
}

#[test]
fn rewind_divergent_cases() {
    // our log: a@1 (create), b@2 (create), a@3 (modify a), c@4 (create), b@5 delete
    let mut log = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::MODIFY, "b", ev(1, 2), ev(0, 0)),
            ent(LogOp::MODIFY, "a", ev(1, 3), ev(1, 1)),
            ent(LogOp::MODIFY, "c", ev(1, 4), ev(0, 0)),
            ent(LogOp::DELETE, "b", ev(1, 5), ev(1, 2)),
        ],
        ev(0, 0),
    );
    let mut info = info_for(&log);
    let mut missing = MissingSet::new(true);
    let mut ops = vec![];
    rewind_divergent_log(&mut log, &mut info, &mut missing, &mut ops, ev(1, 2)).unwrap();
    assert_eq!(log.head(), ev(1, 2));
    assert_eq!(info.last_update, ev(1, 2));
    // c: created by a divergent write -> removed, no missing item
    // a: modified by a divergent write -> removed locally + missing(need=prior 1'1, have 0)
    // b: deleted by a divergent write (prior 1'2) and the delete is not "known absent" because b is
    //    not missing and the last divergent op is a delete -> known absent: nothing removed; case 5 adds need 1'2
    let r = removed(&ops);
    assert!(r.contains(&"c".to_string()), "{r:?}");
    assert!(r.contains(&"a".to_string()), "{r:?}");
    assert!(
        !r.contains(&"b".to_string()),
        "known-absent object is not deleted again: {r:?}"
    );
    assert!(!missing.contains(&h("c")));
    let a = missing.get(&h("a")).unwrap();
    assert_eq!((a.need, a.have), (ev(1, 1), ev(0, 0)));
    let b = missing.get(&h("b")).unwrap();
    assert_eq!(b.need, ev(1, 2));
    assert!(
        ops.iter()
            .any(|o| matches!(o, StoreOp::LogRewind { to } if *to == ev(1, 2)))
    );
    // last_complete follows the oldest need
    assert_eq!(info.last_complete, ev(0, 0));
}

#[test]
fn rewind_object_already_missing_with_matching_have_is_dropped() {
    let mut log = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::MODIFY, "a", ev(1, 2), ev(1, 1)),
        ],
        ev(0, 0),
    );
    let mut info = info_for(&log);
    let mut missing = MissingSet::new(true);
    // we only have a@1 but the log said 2: missing(need 1'2, have 1'1)
    missing.add(h("a"), ev(1, 2), ev(1, 1), false);
    info.last_complete = ev(1, 1);
    let mut ops = vec![];
    rewind_divergent_log(&mut log, &mut info, &mut missing, &mut ops, ev(1, 1)).unwrap();
    assert!(
        missing.is_empty(),
        "have == prior: we hold the prior version already"
    );
    assert!(removed(&ops).is_empty());
    assert_eq!(info.last_complete, info.last_update);
}

#[test]
fn rewind_below_tail_is_an_error() {
    let mut log = mk(vec![ent(LogOp::MODIFY, "a", ev(1, 5), ev(0, 0))], ev(1, 4));
    let mut info = info_for(&log);
    let mut missing = MissingSet::new(true);
    assert!(
        rewind_divergent_log(&mut log, &mut info, &mut missing, &mut vec![], ev(1, 2)).is_err()
    );
}

#[test]
fn merge_log_extends_head_and_tail_and_sets_missing() {
    // we are behind: our log (3,5], auth (1,8]
    let mut log = mk(
        vec![
            ent(LogOp::MODIFY, "x", ev(2, 4), ev(0, 0)),
            ent(LogOp::MODIFY, "y", ev(2, 5), ev(0, 0)),
        ],
        ev(2, 3),
    );
    let mut info = info_for(&log);
    let auth = mk(
        vec![
            ent(LogOp::MODIFY, "w", ev(1, 2), ev(0, 0)),
            ent(LogOp::MODIFY, "z", ev(1, 3), ev(0, 0)),
            ent(LogOp::MODIFY, "x", ev(2, 4), ev(0, 0)),
            ent(LogOp::MODIFY, "y", ev(2, 5), ev(0, 0)),
            ent(LogOp::MODIFY, "x", ev(3, 6), ev(2, 4)),
            ent(LogOp::DELETE, "y", ev(3, 7), ev(2, 5)),
            ent(LogOp::MODIFY, "n", ev(3, 8), ev(0, 0)),
        ],
        ev(1, 1),
    );
    let oinfo = info_for(&auth);
    let mut missing = MissingSet::new(true);
    let mut ops = vec![];
    merge_log(
        &mut log,
        &mut info,
        &mut missing,
        &mut ops,
        &oinfo,
        &auth.log,
    )
    .unwrap();
    assert_eq!(log.head(), ev(3, 8));
    assert_eq!(log.tail(), ev(1, 1), "tail extended backwards");
    assert_eq!(log.len(), 7);
    assert_eq!(info.last_update, ev(3, 8));
    // new entries: x modified (have prior 2'4), y deleted, n created
    let x = missing.get(&h("x")).unwrap();
    assert_eq!((x.need, x.have), (ev(3, 6), ev(2, 4)));
    assert!(missing.get(&h("y")).unwrap().is_delete());
    assert_eq!(missing.get(&h("n")).unwrap().have, ev(0, 0));
    assert_eq!(missing.len(), 3);
    // last_complete = newest entry before the oldest need (3'6) = 2'5
    assert_eq!(info.last_complete, ev(2, 5));
    // delta tracking
    let mut d = vec![];
    missing.take_ops(&mut d);
    assert!(matches!(&d[0], StoreOp::Missing(v) if v.len() == 3));
    d.clear();
    missing.take_ops(&mut d);
    assert!(d.is_empty());
}

/// PG-P6: `num_objects_missing` follows the missing set at the same step as `last_complete` (spec pglog 6.4 and 7.2
/// step 4): a replica reports its own count, not the primary's stats copied in step 2 of the merge.
#[test]
fn merge_log_publishes_the_missing_count() {
    let mut log = mk(vec![ent(LogOp::MODIFY, "x", ev(2, 4), ev(0, 0))], ev(2, 3));
    // a fully backfilled peer: step 2 adopts the authoritative stats
    let mut info = info_for(&log);
    info.last_backfill = Hobject::MAX();
    let auth = mk(
        vec![
            ent(LogOp::MODIFY, "x", ev(2, 4), ev(0, 0)),
            ent(LogOp::MODIFY, "y", ev(3, 5), ev(0, 0)),
            ent(LogOp::MODIFY, "z", ev(3, 6), ev(0, 0)),
        ],
        ev(2, 3),
    );
    let mut oinfo = info_for(&auth);
    oinfo.stats.stats.sum.num_objects_missing = 42;
    let mut missing = MissingSet::new(true);
    let mut ops = vec![];
    merge_log(
        &mut log,
        &mut info,
        &mut missing,
        &mut ops,
        &oinfo,
        &auth.log,
    )
    .unwrap();
    assert_eq!(missing.len(), 2);
    assert_eq!(info.stats.stats.sum.num_objects_missing, 2);
}

/// Spec pglog 7.2 step 4: without `may_include_deletes` an appended delete entry removes the object (no delete item can
/// track it), as the classic merge does; leaving the local copy would keep a deleted object alive on this shard.
#[test]
fn merge_log_without_delete_items_removes_deleted_objects() {
    let mut log = mk(vec![ent(LogOp::MODIFY, "y", ev(2, 5), ev(0, 0))], ev(2, 4));
    let mut info = info_for(&log);
    let auth = mk(
        vec![
            ent(LogOp::MODIFY, "y", ev(2, 5), ev(0, 0)),
            ent(LogOp::DELETE, "y", ev(3, 6), ev(2, 5)),
        ],
        ev(2, 4),
    );
    let oinfo = info_for(&auth);
    let mut missing = MissingSet::new(false);
    let mut ops = vec![];
    merge_log(
        &mut log,
        &mut info,
        &mut missing,
        &mut ops,
        &oinfo,
        &auth.log,
    )
    .unwrap();
    assert_eq!(log.head(), ev(3, 6));
    assert!(
        missing.is_empty(),
        "no delete item without may_include_deletes"
    );
    assert_eq!(
        removed(&ops),
        vec!["y".to_string()],
        "the deleted object goes"
    );
}

#[test]
fn merge_log_detects_divergence_with_accurate_tail() {
    // we have 1'1..1'3 + divergent 2'4; auth has 1'1..1'3 then 3'4, 3'5
    let mut log = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::MODIFY, "b", ev(1, 2), ev(0, 0)),
            ent(LogOp::MODIFY, "c", ev(1, 3), ev(0, 0)),
            ent(LogOp::MODIFY, "a", ev(2, 4), ev(1, 1)),
        ],
        ev(0, 0),
    );
    let mut info = info_for(&log);
    let auth_full = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::MODIFY, "b", ev(1, 2), ev(0, 0)),
            ent(LogOp::MODIFY, "c", ev(1, 3), ev(0, 0)),
            ent(LogOp::MODIFY, "d", ev(3, 4), ev(0, 0)),
            ent(LogOp::MODIFY, "a", ev(3, 5), ev(1, 1)),
        ],
        ev(0, 0),
    );
    // the primary sends copy_after(our last_update): the slice tail must expose the divergence
    let slice = auth_full.copy_after(ev(2, 4));
    assert_eq!(slice.tail, ev(1, 3), "tail = auth's newest entry <= since");
    let oinfo = info_for(&auth_full);
    let mut missing = MissingSet::new(true);
    let mut ops = vec![];
    merge_log(&mut log, &mut info, &mut missing, &mut ops, &oinfo, &slice).unwrap();
    assert_eq!(log.head(), ev(3, 5));
    assert_eq!(log.len(), 5);
    assert!(log.entries().iter().all(|e| e.version != ev(2, 4)));
    // a: divergent write replaced by the newer auth entry -> case 1: removed locally, needs 3'5
    assert!(removed(&ops).contains(&"a".to_string()));
    let a = missing.get(&h("a")).unwrap();
    assert_eq!(a.need, ev(3, 5));
    assert_eq!(a.have, ev(0, 0), "content not trustworthy after divergence");
}

#[test]
fn merge_log_without_overlap_is_refused() {
    let mut log = mk(vec![ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0))], ev(0, 0));
    let mut info = info_for(&log);
    let auth = mk(
        vec![ent(LogOp::MODIFY, "b", ev(1, 20), ev(0, 0))],
        ev(1, 10),
    );
    let oinfo = info_for(&auth);
    let r = merge_log(
        &mut log,
        &mut info,
        &mut MissingSet::new(true),
        &mut vec![],
        &oinfo,
        &auth.log,
    );
    assert!(r.is_err());
}

#[test]
fn proc_replica_log_computes_peer_missing() {
    // authoritative: 1'1 a, 1'2 b, 2'3 a(modify)
    let ours = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::MODIFY, "b", ev(1, 2), ev(0, 0)),
            ent(LogOp::MODIFY, "a", ev(2, 3), ev(1, 1)),
        ],
        ev(0, 0),
    );
    // peer got 1'1, 1'2 and a divergent 1'3 b-modify; it also misses object "a" (from before)
    let peer = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::MODIFY, "b", ev(1, 2), ev(0, 0)),
            ent(LogOp::MODIFY, "b", ev(1, 3), ev(1, 2)),
        ],
        ev(0, 0),
    );
    let mut pinfo = info_for(&peer);
    let mut pmiss = MissingSet::new(true);
    proc_replica_log(&ours, &mut pinfo, &peer.log, &mut pmiss);
    assert_eq!(
        pinfo.last_update,
        ev(1, 2),
        "rewound to the last shared entry"
    );
    assert!(
        pmiss.get(&h("b")).is_some(),
        "divergent modify of b: recover prior version"
    );
    assert_eq!(pmiss.get(&h("b")).unwrap().need, ev(1, 2));
    assert_eq!(pinfo.last_complete, ev(1, 1));
}

#[test]
fn trim_makes_dups_and_bounds_them() {
    let cfg = {
        let mut c = Config::new(0);
        c.log_dups_tracked = 4;
        c.pg_log_trim_max = 100;
        c
    };
    let mut entries = vec![];
    for i in 1..=10u64 {
        let mut e = ent(LogOp::MODIFY, "o", ev(1, i), ev(1, i.saturating_sub(1)));
        e.reqid.tid = i;
        entries.push(e);
    }
    let mut log = mk(entries, ev(0, 0));
    log.trim(ev(1, 8), &cfg);
    assert_eq!(log.len(), 2);
    assert_eq!(log.tail(), ev(1, 8));
    // earliest dup version = head(10) - 4 + 1 = 7 -> entries 7 and 8 become dups, older are dropped
    assert_eq!(
        log.log
            .dups
            .iter()
            .map(|d| d.version.version)
            .collect::<Vec<_>>(),
        vec![7, 8]
    );
    assert_eq!(
        log.find_reqid(&{
            let mut r = denc::types::OsdReqId::default();
            r.tid = 8;
            r
        })
        .map(|x| x.0.version),
        Some(8)
    );
    // trimming to the tail or below is a no-op
    log.trim(ev(1, 8), &cfg);
    assert_eq!(log.log.dups.len(), 2);
}

#[test]
fn op_returns_survive_trim_into_dups() {
    let cfg = Config::new(0);
    let mut entries = vec![];
    for i in 1..=10u64 {
        let mut e = ent(LogOp::MODIFY, "o", ev(1, i), ev(1, i - 1));
        e.reqid.tid = i;
        entries.push(e);
    }
    entries[7].op_returns = vec![LogOpReturnItem {
        rval: 3,
        outdata: b"zz".to_vec(),
    }];
    let rid = entries[7].reqid;
    let mut log = mk(entries, ev(0, 0));
    assert_eq!(log.find_op_returns(&rid)[0].outdata, b"zz");
    log.trim(ev(1, 9), &cfg);
    assert_eq!(log.len(), 1);
    assert_eq!(log.find_op_returns(&rid)[0].rval, 3);
}

#[test]
fn existing_version_treats_deleted_objects_as_absent() {
    let log = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::DELETE, "a", ev(1, 2), ev(1, 1)),
            ent(LogOp::MODIFY, "b", ev(1, 3), ev(0, 0)),
        ],
        ev(0, 0),
    );
    assert_eq!(log.existing_version(&h("a")), None);
    assert_eq!(log.newest_for(&h("a")), Some(ev(1, 2)));
    assert_eq!(log.existing_version(&h("b")), Some(ev(1, 3)));
    assert_eq!(log.existing_version(&h("zz")), None);
}

#[test]
fn window_version_separates_unknown_from_deleted() {
    // unknown to the window (ask the store) differs from deleted by the window's newest entry (absent, no store read)
    let mut log = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::DELETE, "a", ev(1, 2), ev(1, 1)),
            ent(LogOp::MODIFY, "b", ev(1, 3), ev(0, 0)),
        ],
        ev(0, 0),
    );
    assert_eq!(log.window_version(&h("a")), Some(None));
    assert_eq!(log.window_version(&h("b")), Some(Some(ev(1, 3))));
    assert_eq!(log.window_version(&h("zz")), None);
    // an object whose entries were trimmed is unknown again
    log.trim(ev(1, 3), &Config::new(0));
    assert_eq!(log.window_version(&h("b")), None);
}

#[test]
fn mem_bytes_grows_with_entries_and_object_names() {
    let es = |n: u64, name: &str| -> Vec<LogEntry> {
        (1..=n)
            .map(|i| ent(LogOp::MODIFY, &format!("{name}{i}"), ev(1, i), ev(0, 0)))
            .collect()
    };
    let small = mk(es(10, "a"), ev(0, 0)).mem_bytes();
    let more = mk(es(100, "a"), ev(0, 0)).mem_bytes();
    let longer = mk(es(10, &"a".repeat(200)), ev(0, 0)).mem_bytes();
    assert!(small > 10 * 100, "entries cost at least their struct size");
    assert!(more > small * 8 && more < small * 12, "linear in entries");
    assert!(longer > small + 10 * 190, "names are counted");
    assert_eq!(mk(vec![], ev(0, 0)).mem_bytes(), 0);
}

/// The dup index answers exactly like a backwards scan of `log.dups`, also when the same record is held twice (a merge
/// joins the dups its sources each copied from one split parent) and the trim drops one copy of it.
#[test]
fn dup_index_equals_the_scan_with_duplicate_records() {
    let cfg = {
        let mut c = Config::new(0);
        c.log_dups_tracked = 4;
        c.pg_log_trim_max = 100;
        c
    };
    let rq = |t: u64| {
        let mut r = denc::types::OsdReqId::default();
        r.tid = t;
        r
    };
    let dup = |t: u64, v: u64| LogDup {
        reqid: rq(t),
        version: ev(1, v),
        user_version: v,
        return_code: 0,
        op_returns: vec![],
    };
    let mut entries = vec![];
    for i in 3..=10u64 {
        let mut e = ent(LogOp::MODIFY, "o", ev(1, i), ev(1, i - 1));
        e.reqid.tid = 100 + i;
        entries.push(e);
    }
    let mut pl = mk(entries, ev(1, 2)).log;
    pl.dups = [dup(1, 1), dup(1, 1), dup(2, 2), dup(2, 2)].into();
    let mut log = IndexedLog::new(pl);
    let scan = |log: &IndexedLog, t: u64| {
        log.log
            .dups
            .iter()
            .rev()
            .find(|d| d.reqid == rq(t))
            .map(|d| d.version)
    };
    // 1 dup added (entry 7 is within the last 4 of head 10), 1 of the 5 records dropped: one copy of (1, 1) remains
    log.trim(ev(1, 7), &cfg);
    assert_eq!(log.log.dups.len(), 4);
    assert_eq!(scan(&log, 1), Some(ev(1, 1)));
    for t in [1, 2, 107, 3, 99] {
        assert_eq!(
            log.find_reqid(&rq(t)).map(|x| x.0),
            scan(&log, t),
            "reqid tid {t}"
        );
    }
    // the last copies go
    log.trim(ev(1, 9), &cfg);
    assert_eq!(log.log.dups.len(), 4);
    for t in [1, 2, 107, 108, 109] {
        assert_eq!(
            log.find_reqid(&rq(t)).map(|x| x.0),
            scan(&log, t),
            "reqid tid {t}"
        );
    }
    assert_eq!(log.find_reqid(&rq(1)), None);
}

/// Classic peer (mixed acting set): dup records encoded by a classic OSD (ceph-dencoder `pg_log_dup_t` vectors, inside a
/// classic `pg_log_t` v7 frame) decode, re-encode byte-identical, and once merged from the authoritative log they answer
/// a resent request (spec pglog.md 7.4, client-ops.md 5.6): the newest record of the request id wins.
#[test]
fn classic_dup_records_merge_and_answer_resends() {
    let data = |p: &str| {
        std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../testdata/pgwire")
                .join(p),
        )
        .unwrap()
    };
    // classic empty pg_log_t: struct_v 7, compat 3, len, head, tail, log [], can_rollback_to, rollback_info_trimmed_to,
    // dups [] (u32 count last): splice the two classic dup records of client.777.8:999 in
    let empty = data("pg_log_t/1.bin");
    let (d2, d3) = (data("pg_log_dup_t/2.bin"), data("pg_log_dup_t/3.bin"));
    let mut body = empty[6..empty.len() - 4].to_vec();
    body.extend_from_slice(&2u32.to_le_bytes());
    body.extend_from_slice(&d2);
    body.extend_from_slice(&d3);
    let mut bytes = empty[..2].to_vec();
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&body);
    let classic: PgLog = denc::from_slice(&bytes).unwrap();
    assert_eq!(denc::Encode::encode_to_vec(&classic).unwrap(), bytes);
    assert_eq!(classic.dups.len(), 2);
    let rid = denc::types::OsdReqId {
        name: denc::types::EntityName::client(777),
        tid: 999,
        inc: 8,
    };
    assert!(
        classic
            .dups
            .iter()
            .all(|d| d.reqid == rid && d.version == ev(1, 2))
    );
    // the authoritative log of a classic primary: entries 1'3..1'5 over tail 1'2, the classic dup records below it
    let entries = |from: u64| {
        (from..=5)
            .map(|v| ent(LogOp::MODIFY, "o", ev(1, v), ev(1, v - 1)))
            .collect::<Vec<_>>()
    };
    let mut auth = mk(entries(3), ev(1, 2)).log;
    auth.dups = classic.dups.clone();
    // we (a peer that missed 1'4, 1'5) hold 1'3 only, no dup records
    let mut log = mk(entries(3).into_iter().take(1).collect(), ev(1, 2));
    let mut info = info_for(&log);
    assert_eq!(log.find_reqid(&rid), None);
    let oinfo = info_for(&IndexedLog::new(auth.clone()));
    let (mut missing, mut ops) = (MissingSet::new(true), vec![]);
    merge_log(&mut log, &mut info, &mut missing, &mut ops, &oinfo, &auth).unwrap();
    assert_eq!(log.head(), ev(1, 5));
    assert_eq!(log.find_reqid(&rid), Some((ev(1, 2), 2, -2)));
    assert!(
        ops.iter()
            .any(|o| matches!(o, StoreOp::LogDups(d) if d.len() == 2)),
        "the merged dup records are persisted"
    );
}

/// `trim_ex` reports the oldest kept dup record (`dups_from`): every dropped record is below it (the store drops the
/// persisted dups below it as one range); `None` when no record is kept.
#[test]
fn trim_dups_from_is_the_first_kept_record() {
    let cfg = |tracked: u64| {
        let mut c = Config::new(0);
        c.log_dups_tracked = tracked;
        c.pg_log_trim_max = 100;
        c
    };
    let dup = |t: u64, v: u64| {
        let mut r = denc::types::OsdReqId::default();
        r.tid = t;
        LogDup {
            reqid: r,
            version: ev(1, v),
            user_version: v,
            return_code: 0,
            op_returns: vec![],
        }
    };
    let log_with = |dups: Vec<LogDup>| {
        let entries: Vec<LogEntry> = (11..=20u64)
            .map(|i| {
                let mut e = ent(LogOp::MODIFY, "o", ev(1, i), ev(1, i - 1));
                e.reqid.tid = 100 + i;
                e
            })
            .collect();
        let mut pl = mk(entries, ev(1, 10)).log;
        pl.dups = dups.into();
        IndexedLog::new(pl)
    };
    // head 20, tracked 5: entries 11..=13 are older than the window (no dups), the 3 oldest of the 8 records go
    let mut log = log_with((1..=8u64).map(|v| dup(v, v)).collect());
    let t = log.trim_ex(ev(1, 13), &cfg(5));
    assert_eq!(log.log.dups.len(), 5);
    assert_eq!(t.dups_from, Some(log.log.dups[0].version));
    assert_eq!(t.dups_from, Some(ev(1, 4)));
    // the version of a kept record is where the oldest kept starts, also when it shares it with a dropped one
    let mut log = log_with(vec![dup(1, 1), dup(2, 2), dup(3, 2), dup(4, 3)]);
    let t = log.trim_ex(ev(1, 11), &cfg(2));
    assert_eq!(t.dups_from, Some(log.log.dups[0].version));
    // nothing tracked: no record is kept
    let mut log = log_with((1..=4u64).map(|v| dup(v, v)).collect());
    let t = log.trim_ex(ev(1, 12), &cfg(0));
    assert!(log.log.dups.is_empty());
    assert_eq!(t.dups_from, None);
}

#[test]
fn proc_replica_log_clamps_peer_pwlc_to_the_rolled_back_head() {
    // 21.2.0 B5: the primary rolls the peer back from 1'3 to 1'2; its pwlc entries must not point past 1'2
    let ours = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::MODIFY, "b", ev(1, 2), ev(0, 0)),
        ],
        ev(0, 0),
    );
    let peer = mk(
        vec![
            ent(LogOp::MODIFY, "a", ev(1, 1), ev(0, 0)),
            ent(LogOp::MODIFY, "b", ev(1, 2), ev(0, 0)),
            ent(LogOp::MODIFY, "b", ev(1, 3), ev(1, 2)),
        ],
        ev(0, 0),
    );
    let mut pinfo = info_for(&peer);
    let w = &mut pinfo.partial_writes_last_complete;
    w.insert(denc::types::ShardId(1), (ev(1, 1), ev(1, 3))); // to past the new head: to = 1'2
    w.insert(denc::types::ShardId(2), (ev(1, 3), ev(1, 3))); // both past: from follows to
    w.insert(denc::types::ShardId(3), (ev(1, 1), ev(1, 2))); // already inside: unchanged
    w.insert(
        denc::types::ShardId(4),
        (peering::ecopt::PWLC_INVALID, peering::ecopt::PWLC_INVALID),
    ); // sentinel stays
    proc_replica_log(&ours, &mut pinfo, &peer.log, &mut MissingSet::new(true));
    assert_eq!(pinfo.last_update, ev(1, 2));
    let w = &pinfo.partial_writes_last_complete;
    assert_eq!(w[&denc::types::ShardId(1)], (ev(1, 1), ev(1, 2)));
    assert_eq!(w[&denc::types::ShardId(2)], (ev(1, 2), ev(1, 2)));
    assert_eq!(w[&denc::types::ShardId(3)], (ev(1, 1), ev(1, 2)));
    assert_eq!(
        w[&denc::types::ShardId(4)],
        (peering::ecopt::PWLC_INVALID, peering::ecopt::PWLC_INVALID)
    );
}

/// A classic copy-from entry remembers source requests too: promotion must answer their resends without executing
/// them again, and an extra request must not inherit the destination request's RETURNVEC payload.
#[test]
fn extra_requests_survive_adoption_trim_and_backfill_slice() {
    let rid = |tid| denc::types::OsdReqId {
        tid,
        ..Default::default()
    };
    let mut copied = ent(LogOp::MODIFY, "dest", ev(1, 1), Eversion::default());
    copied.reqid = rid(1);
    copied.user_version = 40;
    copied.return_code = 7;
    copied.op_returns = vec![LogOpReturnItem {
        rval: 7,
        outdata: b"destination-result".to_vec(),
    }];
    copied.extra_reqids = vec![(rid(2), 21), (rid(3), 22)];
    copied.extra_reqid_return_codes.insert(0, -17);
    let mut auth = mk(vec![copied], Eversion::default());
    auth.append(ent(LogOp::MODIFY, "other", ev(1, 2), Eversion::default()));
    let mut adopted = IndexedLog::default();
    let mut info = info_for(&adopted);
    let mut missing = MissingSet::new(true);
    merge_log(
        &mut adopted,
        &mut info,
        &mut missing,
        &mut vec![],
        &info_for(&auth),
        &auth.log,
    )
    .unwrap();
    let check = |log: &IndexedLog| {
        assert_eq!(log.find_reqid(&rid(1)), Some((ev(1, 1), 40, 7)));
        assert_eq!(log.find_reqid(&rid(2)), Some((ev(1, 1), 21, -17)));
        assert_eq!(log.find_reqid(&rid(3)), Some((ev(1, 1), 22, 7)));
        assert_eq!(log.find_op_returns(&rid(1)).len(), 1);
        assert!(log.find_op_returns(&rid(2)).is_empty());
        assert!(log.find_op_returns(&rid(3)).is_empty());
    };
    check(&adopted);
    // The copied entry is excluded from the slice; all three request ids must be represented as dup records.
    let slice = IndexedLog::new(adopted.copy_up_to(1, 100));
    assert_eq!(slice.log.dups.len(), 3);
    check(&slice);
    adopted.trim(ev(1, 1), &Config::new(0));
    check(&adopted);
    // Trimming an entry outside the dup window removes its extra-callers index too (no stale duplicate hits).
    let mut old = auth.clone();
    let mut cfg = Config::new(0);
    cfg.log_dups_tracked = 0;
    old.trim(ev(1, 1), &cfg);
    assert_eq!(old.find_reqid(&rid(2)), None);
    assert_eq!(old.find_reqid(&rid(3)), None);
}

#[test]
fn extra_requests_append_rewind_and_newest_result() {
    let rid = denc::types::OsdReqId {
        tid: 900,
        ..Default::default()
    };
    let mut first = ent(LogOp::MODIFY, "a", ev(1, 1), Eversion::default());
    first.extra_reqids.push((rid, 10));
    let mut log = mk(vec![first], Eversion::default());
    let mut failed = ent(LogOp::ERROR, "b", ev(1, 2), Eversion::default());
    failed.return_code = -5;
    failed.extra_reqids.push((rid, 20));
    // An error on the merged operation wins over a successful recorded source result.
    failed.extra_reqid_return_codes.insert(0, 0);
    log.append(failed);
    assert_eq!(log.find_reqid(&rid), Some((ev(1, 2), 20, -5)));
    let mut info = info_for(&log);
    rewind_divergent_log(
        &mut log,
        &mut info,
        &mut MissingSet::new(true),
        &mut vec![],
        ev(1, 1),
    )
    .unwrap();
    assert_eq!(log.find_reqid(&rid), Some((ev(1, 1), 10, 0)));
    // A newer extra reference remains indexed while the older reference is trimmed.
    let mut newer = ent(LogOp::MODIFY, "c", ev(2, 2), Eversion::default());
    newer.extra_reqids.push((rid, 30));
    log.append(newer);
    log.trim(ev(1, 1), &Config::new(0));
    assert_eq!(log.find_reqid(&rid), Some((ev(2, 2), 30, 0)));
    assert!(log.find_op_returns(&rid).is_empty());
}
