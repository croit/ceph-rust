// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Recovery source deletion follows the final local durable transaction, including EC reconstruction.
use crate::pg::Pending;
use crate::recovery::PullInfo;
use crate::*;
use denc::types::{Eversion, Hobject, PgShard, PgT, ShardId, SnapId, SpgT};
use pgwire::{PeeringMsg, PgInfo, state};
use replwire::{
    MOSDPGBackfill, MOSDPGBackfillRemove, MOSDPGPush, ObjectRecoveryInfo, ObjectRecoveryProgress,
    PushOp,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn primary(ec: bool) -> (Pg, MemStore, PgShard) {
    let spg = SpgT {
        pgid: PgT::new(1, 0),
        shard: if ec { ShardId(0) } else { ShardId::NO_SHARD },
    };
    let acting = if ec { vec![0, 1, 2] } else { vec![0] };
    let mut map = synth::SynthMap::new(5).with_pool(1, acting.len() as u32, 1, 1);
    for osd in 0..4 {
        map = map.with_osd(osd, 1);
    }
    map.up_override.insert(spg.pgid, acting.clone());
    if ec {
        let pool = map.pools.get_mut(&1).unwrap();
        pool.is_erasure = true;
        pool.ec = Some(Arc::new(pgwire::EcPoolInfo {
            k: 2,
            m: 1,
            stripe_width: 8192,
            chunk_size: 4096,
            supported: true,
            chunk_mapping: vec![0, 1, 2],
            ..Default::default()
        }));
    }
    let mut pg = Pg::blank(
        Arc::new(Config::new(0)),
        spg,
        map.into_handle(),
        PgInfo::new(spg),
    );
    pg.acting = acting.clone();
    pg.up = acting;
    pg.acting_primary = 0;
    pg.up_primary = 0;
    pg.st = St::Primary(PSt::Active(ASt::Recovering));
    pg.state = state::ACTIVE | state::PEERED | state::RECOVERING;
    let source = PgShard {
        osd: 3,
        shard: spg.shard,
    };
    pg.prim.stray_set.insert(source);
    let mut store = MemStore::new();
    store.submit(
        spg,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    (pg, store, source)
}

fn purges(actions: &[Action]) -> bool {
    actions.iter().any(|a| {
        matches!(a,
            Action::Send(s) if matches!(&s.body, Body::Peering(PeeringMsg::MOSDPGRemove(_)))
        )
    })
}

fn persists(actions: Vec<Action>) -> Vec<(u64, StoreTxn)> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            Action::Persist { token, txn, .. } => Some((token, txn)),
            _ => None,
        })
        .collect()
}

/// A consumed recovery push has no negative acknowledgement. Dropping it at failsafe leaves the sender's
/// recovery op in flight forever if no map interval changes. Classic fail-stops instead.
#[test]
fn failsafe_recovery_push_stops_instead_of_silently_losing_the_op() {
    for ec in [None, Some(false), Some(true)] {
        let (mut pg, store) = backfill_target(ec);
        pg.local_full.failsafe = true;
        pg.take_actions();
        pg.on_push(
            pg.acting_primary,
            1,
            pgwire::msgs::PRIO_DEFAULT,
            MOSDPGPush {
                pgid: pg.spg,
                map_epoch: 5,
                min_epoch: 5,
                from: PgShard {
                    osd: pg.acting_primary,
                    shard: pg.primary_shard(),
                },
                pushes: vec![PushOp {
                    soid: Hobject::new(b"pending-recovery", SnapId::NOSNAP, 7, 1, b""),
                    version: Eversion::new(5, 1),
                    ..Default::default()
                }],
                ..Default::default()
            },
            &store,
        );
        let actions = pg.take_actions();
        assert!(
            actions.iter().any(|a| matches!(a, Action::Fatal { .. })),
            "{ec:?}: {actions:?}"
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Persist { .. } | Action::Send(_)))
        );
    }
}

#[test]
fn final_recovery_pull_keeps_source_until_local_durable_completion() {
    let (mut pg, mut store, source) = primary(false);
    let oid = Hobject::new(b"last-copy", SnapId::NOSNAP, 7, 1, b"");
    let version = Eversion::new(4, 1);
    pg.info.last_update = version;
    pg.missing
        .add(oid.clone(), version, Eversion::default(), false);
    let info = ObjectRecoveryInfo {
        soid: oid.clone(),
        version,
        size: 7,
        copy_subset: BTreeMap::from([(0, 7)]),
        ..Default::default()
    };
    pg.rec.pulls.insert(
        oid.clone(),
        PullInfo {
            from: source.osd,
            info: info.clone(),
            progress: ObjectRecoveryProgress::default(),
            stat: Default::default(),
        },
    );
    pg.on_push(
        source.osd,
        1,
        pgwire::msgs::PRIO_DEFAULT,
        MOSDPGPush {
            pgid: pg.spg,
            from: source,
            map_epoch: 5,
            min_epoch: 5,
            pushes: vec![PushOp {
                soid: oid.clone(),
                version,
                data: b"durable".to_vec().into(),
                data_included: BTreeMap::from([(0, 7)]),
                recovery_info: info,
                after_progress: ObjectRecoveryProgress {
                    first: false,
                    data_complete: true,
                    omap_complete: true,
                    data_recovered_to: 7,
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        },
        &store,
    );
    pg.after_event(&store);
    let actions = pg.take_actions();
    assert!(
        !purges(&actions),
        "source deletion must wait for the recovered data to commit"
    );
    assert_eq!(pg.state_bits() & state::CLEAN, 0);
    let pending = persists(actions);
    assert!(
        pending.len() >= 2,
        "recovery data followed by a nonempty durable fence"
    );
    let last = pending.len() - 1;
    for (i, (token, txn)) in pending.into_iter().enumerate() {
        assert!(!txn.ops.is_empty());
        store.submit(pg.spg, &txn);
        pg.on_commit(i as u64 + 1, token, &store);
        let actions = pg.take_actions();
        if i == last {
            assert!(
                purges(&actions),
                "source can retire after the fence commits"
            );
        } else {
            assert!(!purges(&actions));
        }
    }
    assert_ne!(pg.state_bits() & state::CLEAN, 0);
    assert_eq!(store.objects(pg.spg)[&oid].data, b"durable");
}

#[test]
fn recovery_completion_fence_covers_both_pool_types_and_rejects_old_intervals() {
    for ec in [false, true] {
        for reset in [false, true] {
            let (mut pg, mut store, _) = primary(ec);
            // The local recovery apply is already visible but its durable callback is outstanding.
            pg.txn.push(StoreOp::RemoveObject(Hobject::new(
                b"recovery-temp",
                SnapId::NOSNAP,
                7,
                1,
                b"",
            )));
            pg.flush(Pending::Plain).unwrap();
            pg.all_recovered();
            let actions = pg.take_actions();
            assert!(!purges(&actions), "ec={ec}: purge before local durability");
            assert_eq!(pg.state_bits() & state::CLEAN, 0);
            let pending = persists(actions);
            assert_eq!(pending.len(), 2);
            if reset {
                pg.enter_reset();
                pg.last_peering_reset += 1;
            }
            for (i, (token, txn)) in pending.into_iter().enumerate() {
                store.submit(pg.spg, &txn);
                pg.on_commit(i as u64 + 1, token, &store);
                let actions = pg.take_actions();
                assert_eq!(purges(&actions), i == 1 && !reset, "ec={ec} reset={reset}");
            }
            assert_eq!(pg.state_bits() & state::CLEAN != 0, !reset);
        }
    }
}

#[test]
fn recovery_completion_fence_rejects_a_superseded_round_in_the_same_interval() {
    let (mut pg, mut store, _) = primary(false);
    for name in [b"first".as_slice(), b"second".as_slice()] {
        pg.st = St::Primary(PSt::Active(ASt::Recovering));
        pg.txn.push(StoreOp::RemoveObject(Hobject::new(
            name,
            SnapId::NOSNAP,
            7,
            1,
            b"",
        )));
        pg.flush(Pending::Plain).unwrap();
        pg.all_recovered();
    }
    let actions = pg.take_actions();
    assert!(!purges(&actions));
    let pending = persists(actions);
    assert_eq!(pending.len(), 4);
    for (i, (token, txn)) in pending.into_iter().enumerate() {
        store.submit(pg.spg, &txn);
        pg.on_commit(i as u64 + 1, token, &store);
        let actions = pg.take_actions();
        assert_eq!(
            purges(&actions),
            i == 3,
            "only the latest recovered round may retire sources"
        );
        assert_eq!(pg.state_bits() & state::CLEAN != 0, i == 3);
    }
}

/// `None`: replicated; `Some(optimized)`: legacy or optimized EC. The target is osd.0, led by osd.1.
fn backfill_target(ec: Option<bool>) -> (Pg, MemStore) {
    let spg = SpgT {
        pgid: PgT::new(1, 0),
        shard: if ec.is_some() {
            ShardId(1)
        } else {
            ShardId::NO_SHARD
        },
    };
    let acting = if ec.is_some() {
        vec![1, 0, 2]
    } else {
        vec![1, 0]
    };
    let mut map = synth::SynthMap::new(5).with_pool(1, acting.len() as u32, 1, 1);
    for osd in 0..3 {
        map = map.with_osd(osd, 1);
    }
    map.up_override.insert(spg.pgid, acting);
    if let Some(optimized) = ec {
        let pool = map.pools.get_mut(&1).unwrap();
        pool.is_erasure = true;
        pool.ec = Some(Arc::new(pgwire::EcPoolInfo {
            k: 2,
            m: 1,
            stripe_width: 8192,
            chunk_size: 4096,
            supported: true,
            optimized,
            chunk_mapping: vec![0, 1, 2],
            ..Default::default()
        }));
    }
    let mut info = PgInfo::new(spg);
    info.last_backfill = Hobject::MIN();
    let mut pg = Pg::blank(Arc::new(Config::new(0)), spg, map.into_handle(), info);
    assert!(pg.refusal().is_none());
    assert_eq!(pg.acting_primary, 1);
    pg.st = St::ReplicaActive;
    pg.state = state::ACTIVE | state::PEERED;
    pg.created_in_store = true;
    pg.persisted_epoch = 5;
    let mut store = MemStore::new();
    store.submit(
        spg,
        &StoreTxn {
            ops: vec![
                StoreOp::CreatePg,
                StoreOp::PutInfo(Box::new(pg.info.clone())),
                StoreOp::PutEpoch(5),
            ],
        },
    );
    (pg, store)
}

fn backfill_message(pg: &Pg, op: u32, last_backfill: Hobject) -> MOSDPGBackfill {
    MOSDPGBackfill {
        op,
        map_epoch: pg.map_epoch(),
        query_epoch: pg.last_peering_reset(),
        pgid: pg.spg,
        last_backfill,
        compat_stats: denc::to_vec(&pgwire::ObjectStatCollection::default()).unwrap(),
        stats: denc::to_vec(&pgwire::PgStat::default()).unwrap(),
    }
}

fn finish_acks(actions: &[Action]) -> Vec<(i32, MOSDPGBackfill)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(s) => match &s.body {
                Body::Repl(replwire::ReplMsg::Backfill(m))
                    if m.op == MOSDPGBackfill::OP_FINISH_ACK =>
                {
                    assert_eq!(s.tid, 0);
                    Some((s.to, m.clone()))
                }
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Replica data and backfill metadata may only be changed by the current acting primary. Exercise the shared
/// handlers for replicated, legacy EC and optimized EC pools, with an authorized control for every message.
#[test]
fn recovery_and_backfill_reject_nonprimary_senders() {
    use replwire::{MOSDPGScan, ReplMsg};

    for ec in [None, Some(false), Some(true)] {
        for kind in 0..5 {
            for sender in [2, 1] {
                let (mut pg, mut store) = backfill_target(ec);
                let oid = Hobject::new(b"acknowledged", SnapId::NOSNAP, 7, 1, b"");
                store.pgs.get_mut(&pg.spg).unwrap().objects.insert(
                    oid.clone(),
                    MemObj {
                        data: b"original".to_vec(),
                        ..Default::default()
                    },
                );
                let message = match kind {
                    0 => {
                        let v = Eversion::new(5, 1);
                        let oi = replwire::ObjectInfo {
                            soid: oid.clone(),
                            version: v,
                            size: 4,
                            ..Default::default()
                        };
                        ReplMsg::Push(MOSDPGPush {
                            pgid: pg.spg,
                            map_epoch: 5,
                            min_epoch: 5,
                            from: PgShard {
                                osd: sender,
                                shard: pg.primary_shard(),
                            },
                            pushes: vec![PushOp {
                                soid: oid.clone(),
                                version: v,
                                data: b"new!".to_vec().into(),
                                data_included: BTreeMap::from([(0, 4)]),
                                attrset: BTreeMap::from([(
                                    b"_".to_vec(),
                                    denc::to_vec(&oi).unwrap(),
                                )]),
                                recovery_info: ObjectRecoveryInfo {
                                    soid: oid.clone(),
                                    version: v,
                                    size: 4,
                                    oi,
                                    copy_subset: BTreeMap::from([(0, 4)]),
                                    ..Default::default()
                                },
                                before_progress: ObjectRecoveryProgress::default(),
                                after_progress: ObjectRecoveryProgress {
                                    first: false,
                                    data_complete: true,
                                    omap_complete: true,
                                    data_recovered_to: 4,
                                    ..Default::default()
                                },
                                ..Default::default()
                            }],
                            ..Default::default()
                        })
                    }
                    1 | 2 => ReplMsg::Backfill(backfill_message(
                        &pg,
                        if kind == 1 {
                            MOSDPGBackfill::OP_PROGRESS
                        } else {
                            MOSDPGBackfill::OP_FINISH
                        },
                        Hobject::MAX(),
                    )),
                    3 => ReplMsg::BackfillRemove(MOSDPGBackfillRemove {
                        pgid: pg.spg,
                        map_epoch: 5,
                        ls: vec![(oid.clone(), Eversion::default())],
                    }),
                    _ => ReplMsg::Scan(MOSDPGScan {
                        pgid: pg.spg,
                        map_epoch: 5,
                        query_epoch: 5,
                        op: MOSDPGScan::OP_GET_DIGEST,
                        begin: Hobject::MIN(),
                        end: Hobject::MAX(),
                        from: PgShard {
                            osd: sender,
                            shard: pg.primary_shard(),
                        },
                        digest: None,
                    }),
                };
                pg.handle_msg(
                    0,
                    Inbound {
                        from: sender,
                        tid: 1,
                        prio: pgwire::msgs::PRIO_DEFAULT,
                        ingress: Default::default(),
                        body: Box::new(Body::Repl(message)),
                    },
                    &store,
                );
                let actions = pg.take_actions();
                if sender == 2 {
                    assert!(
                        persists(actions.clone()).is_empty(),
                        "{ec:?} kind {kind}: unauthorized mutation"
                    );
                    assert!(
                        !actions.iter().any(|a| matches!(a, Action::Send(_))),
                        "{ec:?} kind {kind}: unauthorized reply"
                    );
                    assert_eq!(pg.info.last_backfill, Hobject::MIN());
                } else if kind == 4 {
                    assert!(actions.iter().any(|a| matches!(a, Action::Send(s) if matches!(&s.body, Body::Repl(ReplMsg::Scan(_))))));
                } else {
                    assert!(
                        !persists(actions).is_empty(),
                        "{ec:?} kind {kind}: primary command must persist"
                    );
                }
            }
        }
    }
}

/// A late blank response from a previously cancelled source must not cancel the replacement source's pull.
#[test]
fn blank_pull_reply_only_cancels_its_own_source() {
    let (mut pg, store, source) = primary(false);
    let oid = Hobject::new(b"missing", SnapId::NOSNAP, 7, 1, b"");
    let need = Eversion::new(4, 1);
    pg.missing
        .add(oid.clone(), need, Eversion::default(), false);
    pg.rec.pulls.insert(
        oid.clone(),
        PullInfo {
            from: source.osd,
            info: ObjectRecoveryInfo {
                soid: oid.clone(),
                version: need,
                ..Default::default()
            },
            progress: ObjectRecoveryProgress::default(),
            stat: Default::default(),
        },
    );
    let blank = |from| MOSDPGPush {
        pgid: pg.spg,
        map_epoch: 5,
        min_epoch: 5,
        from: PgShard {
            osd: from,
            shard: pg.spg.shard,
        },
        pushes: vec![PushOp {
            soid: oid.clone(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let foreign = blank(2);
    let own = blank(source.osd);
    pg.on_push(2, 1, pgwire::msgs::PRIO_DEFAULT, foreign, &store);
    assert_eq!(pg.rec.pulls[&oid].from, source.osd);
    assert!(!pg.rec.failed_sources.contains(&(2, oid.clone())));
    assert!(pg.missing.contains(&oid));
    pg.on_push(source.osd, 1, pgwire::msgs::PRIO_DEFAULT, own, &store);
    assert!(!pg.rec.pulls.contains_key(&oid));
    assert!(pg.rec.failed_sources.contains(&(source.osd, oid)));
}

#[test]
fn backfill_finish_ack_waits_for_durable_metadata_and_prior_removals() {
    for ec in [None, Some(false), Some(true)] {
        let (mut pg, mut store) = backfill_target(ec);
        let stale = Hobject::new(b"stale", SnapId::NOSNAP, 7, 1, b"");
        let recovered = Hobject::new(b"recovered", SnapId::NOSNAP, 8, 1, b"");
        let objects = &mut store.pgs.get_mut(&pg.spg).unwrap().objects;
        for oid in [&stale, &recovered] {
            objects.insert(
                oid.clone(),
                MemObj {
                    data: b"durable".to_vec(),
                    ..Default::default()
                },
            );
        }
        pg.on_backfill_remove(
            1,
            MOSDPGBackfillRemove {
                pgid: pg.spg,
                map_epoch: 5,
                ls: vec![(stale.clone(), Eversion::default())],
            },
        );
        pg.on_backfill(
            1,
            backfill_message(&pg, MOSDPGBackfill::OP_PROGRESS, recovered.clone()),
        );
        pg.on_backfill(
            1,
            backfill_message(&pg, MOSDPGBackfill::OP_FINISH, Hobject::MAX()),
        );
        let actions = pg.take_actions();
        assert!(
            finish_acks(&actions).is_empty(),
            "{ec:?}: completion before durable PG info"
        );
        // A crash now retains an incomplete target: the primary must not have been told it is complete.
        assert!(store.load_pg(pg.spg).unwrap().info.is_incomplete());
        let pending = persists(actions);
        assert_eq!(pending.len(), 3);
        for (i, (token, txn)) in pending.into_iter().enumerate() {
            store.submit(pg.spg, &txn);
            pg.on_commit(i as u64 + 1, token, &store);
            let acks = finish_acks(&pg.take_actions());
            if i < 2 {
                assert!(
                    acks.is_empty(),
                    "{ec:?}: earlier transaction cannot acknowledge FINISH"
                );
                assert!(store.load_pg(pg.spg).unwrap().info.is_incomplete());
            } else {
                assert_eq!(acks.len(), 1);
                let (to, ack) = &acks[0];
                assert_eq!(*to, 1);
                assert_eq!(ack.pgid, pg.primary_spg());
                assert_eq!(ack.query_epoch, 5);
                assert_eq!(ack.last_backfill, Hobject::MAX());
                assert!(!store.load_pg(pg.spg).unwrap().info.is_incomplete());
                assert!(store.object(pg.spg, &stale).is_none());
                assert_eq!(store.object(pg.spg, &recovered).unwrap().data, b"durable");
            }
        }
    }
}

#[test]
fn backfill_finish_ack_drops_old_intervals_and_keeps_the_request_epoch() {
    for ec in [None, Some(false), Some(true)] {
        for reset in [false, true] {
            let (mut pg, mut store) = backfill_target(ec);
            let mut finish = backfill_message(&pg, MOSDPGBackfill::OP_FINISH, Hobject::MAX());
            finish.query_epoch = 4;
            pg.on_backfill(1, finish);
            let actions = pg.take_actions();
            assert!(finish_acks(&actions).is_empty());
            let pending = persists(actions);
            assert_eq!(pending.len(), 1);
            if reset {
                pg.enter_reset();
                pg.last_peering_reset += 1;
            }
            let (token, txn) = &pending[0];
            store.submit(pg.spg, txn);
            pg.on_commit(1, *token, &store);
            let acks = finish_acks(&pg.take_actions());
            assert_eq!(acks.len(), usize::from(!reset), "{ec:?} reset={reset}");
            if !reset {
                assert_eq!(acks[0].1.query_epoch, 4);
            }
        }
    }
}

fn queue_recovery_txn(pg: &mut Pg) -> (u64, StoreTxn) {
    pg.txn.push(StoreOp::RemoveObject(Hobject::new(
        b"recovery-temp",
        SnapId::NOSNAP,
        7,
        1,
        b"",
    )));
    pg.flush(Pending::Plain).unwrap();
    persists(pg.take_actions()).remove(0)
}

#[test]
fn activation_after_an_interval_change_fences_a_still_uncommitted_recovery_txn() {
    for ec in [false, true] {
        let (mut pg, mut store, _) = primary(ec);
        // Recovery txn queued, its commit outstanding; the missing sets are already empty.
        let (token, txn) = queue_recovery_txn(&mut pg);
        pg.enter_reset();
        pg.last_peering_reset += 1;
        pg.st = St::Primary(PSt::Active(ASt::Activating));
        pg.on_activate_complete();
        let actions = pg.take_actions();
        assert!(!purges(&actions), "ec={ec}: purge before durability");
        assert_eq!(pg.state_bits() & state::CLEAN, 0, "ec={ec}");
        let fence = persists(actions);
        assert_eq!(fence.len(), 1, "ec={ec}: activation must queue the fence");
        for (i, (t, x)) in [(token, txn)].into_iter().chain(fence).enumerate() {
            store.submit(pg.spg, &x);
            pg.on_commit(i as u64 + 1, t, &store);
        }
        assert_eq!(pg.recovery_writes, pg.recovery_fenced);
        assert_ne!(pg.state_bits() & state::CLEAN, 0, "ec={ec}");
    }
}

#[test]
fn activation_without_recovery_writes_goes_clean_without_a_fence() {
    let (mut pg, _store, _) = primary(false);
    pg.st = St::Primary(PSt::Active(ASt::Activating));
    pg.on_activate_complete();
    let _ = pg.take_actions();
    assert!(pg.prim.recovery_complete.is_none(), "no fence queued");
    assert_ne!(pg.state_bits() & state::CLEAN, 0, "clean at once");
}

/// Replicated primary osd.0 recovering replica osd.1 (acting [0, 1]); `obj` = local copy at that version (if any).
fn recovering_pair(obj: Option<(&Hobject, Eversion)>) -> (Pg, MemStore, PgShard) {
    let spg = SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    };
    let acting = vec![0, 1];
    let mut map = synth::SynthMap::new(5).with_pool(1, 2, 1, 1);
    for osd in 0..2 {
        map = map.with_osd(osd, 1);
    }
    map.up_override.insert(spg.pgid, acting.clone());
    let mut pg = Pg::blank(
        Arc::new(Config::new(0)),
        spg,
        map.into_handle(),
        PgInfo::new(spg),
    );
    pg.acting = acting.clone();
    pg.up = acting;
    pg.acting_primary = 0;
    pg.up_primary = 0;
    pg.st = St::Primary(PSt::Active(ASt::Recovering));
    pg.state = state::ACTIVE | state::PEERED | state::RECOVERING;
    let peer = PgShard {
        osd: 1,
        shard: ShardId::NO_SHARD,
    };
    pg.prim.acting_recovery_backfill = [pg.me, peer].into();
    let mut store = MemStore::new();
    store.submit(
        spg,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    if let Some((oid, v)) = obj {
        let oi = replwire::ObjectInfo {
            soid: oid.clone(),
            version: v,
            size: 4,
            ..Default::default()
        };
        store.pgs.get_mut(&spg).unwrap().objects.insert(
            oid.clone(),
            crate::store::MemObj {
                data: b"data".to_vec(),
                xattrs: BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]),
                omap: BTreeMap::new(),
                omap_header: Vec::new(),
            },
        );
        pg.info.last_update = v;
        pg.pg_committed_to = v;
    }
    (pg, store, peer)
}

fn pushes_to(actions: &[Action], osd: i32) -> Vec<(Hobject, Eversion)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(s) if s.to == osd => match &s.body {
                Body::Repl(replwire::ReplMsg::Push(m)) => Some(m),
                _ => None,
            },
            _ => None,
        })
        .flat_map(|m| m.pushes.iter().map(|p| (p.soid.clone(), p.version)))
        .collect()
}

/// P10: the peer's missing item lags our copy (its `need` is older than the version we hold): the current version is
/// pushed (classic pushes the object as it is), never skipped for good with recovery stuck in `recovering`.
#[test]
fn recovery_pushes_the_current_version_when_the_peer_need_lags() {
    let oid = Hobject::new(b"newer", SnapId::NOSNAP, 7, 1, b"");
    let (old, cur) = (Eversion::new(4, 1), Eversion::new(4, 2));
    let (mut pg, store, peer) = recovering_pair(Some((&oid, cur)));
    let mut pm = MissingSet::new(true);
    pm.add(oid.clone(), old, Eversion::default(), false);
    pg.prim.peer_missing.insert(peer, pm);
    pg.rec.cap = 3; // the lease a core's budget would hand out
    pg.recovery_step(&store);
    let actions = pg.take_actions();
    assert_eq!(pushes_to(&actions, 1), vec![(oid, cur)]);
}

/// A clone is pushed with its head's SnapSet (the receiver builds the snap mapper entry from it). While our own head is
/// still missing, that SnapSet is stale or absent: the clone waits until the head is recovered (classic "still missing
/// on primary"); afterwards it goes out.
#[test]
fn a_clone_is_not_pushed_while_its_head_is_missing_on_the_primary() {
    let clone = Hobject::new(b"snapped", SnapId(3), 7, 1, b"");
    let head = Hobject::new(b"snapped", SnapId::NOSNAP, 7, 1, b"");
    let (cv, hv) = (Eversion::new(4, 1), Eversion::new(4, 2));
    let (mut pg, store, peer) = recovering_pair(Some((&clone, cv)));
    pg.info.last_update = hv;
    pg.pg_committed_to = hv;
    pg.missing.add(head.clone(), hv, Eversion::default(), false);
    let mut pm = MissingSet::new(true);
    pm.add(clone.clone(), cv, Eversion::default(), false);
    pg.prim.peer_missing.insert(peer, pm);
    pg.rec.cap = 3;
    pg.recovery_step(&store);
    let actions = pg.take_actions();
    assert!(
        pushes_to(&actions, 1).is_empty(),
        "clone pushed with a stale head SnapSet: {actions:?}"
    );
    pg.missing.got(&head, hv);
    pg.recovery_step(&store);
    let actions = pg.take_actions();
    assert_eq!(pushes_to(&actions, 1), vec![(clone, cv)]);
}

/// Mixed recovery may skip an unchanged omap initially. If data needs a temp, the sender must resend it before
/// the rename; otherwise recovery acknowledges the new data with every unchanged omap key silently deleted.
#[test]
fn clean_omap_survives_multi_chunk_recovery_and_single_chunk_recovery() {
    for budget in [4, 16] {
        let (mut pg, mut target) = backfill_target(None);
        let oid = Hobject::new(b"clean-omap", SnapId::NOSNAP, 7, 1, b"");
        let old = Eversion::new(4, 1);
        let current = Eversion::new(4, 2);
        let keys = BTreeMap::from([(b"key".to_vec(), b"value".to_vec())]);
        let mut oi = replwire::ObjectInfo::new(oid.clone());
        oi.version = old;
        oi.size = 16;
        target.pgs.get_mut(&pg.spg).unwrap().objects.insert(
            oid.clone(),
            crate::store::MemObj {
                data: b"XXXXXXXXXXXXXXXX".to_vec(),
                xattrs: BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]),
                omap: keys.clone(),
                omap_header: b"header".to_vec(),
            },
        );
        let mut source = target.clone();
        oi.version = current;
        let object = source
            .pgs
            .get_mut(&pg.spg)
            .unwrap()
            .objects
            .get_mut(&oid)
            .unwrap();
        object.data = b"0123456789abcdef".to_vec();
        object
            .xattrs
            .insert(b"_".to_vec(), denc::to_vec(&oi).unwrap());
        pg.info.last_update = current;
        pg.missing.add(oid.clone(), current, old, false);
        let info = source.recovery_info(pg.spg, &oid).unwrap();
        let mut progress = ObjectRecoveryProgress {
            omap_complete: true,
            ..Default::default()
        };
        let mut chunks = 0;
        loop {
            let op = source
                .build_push(pg.spg, &info, &progress, budget, 100)
                .unwrap();
            progress = op.after_progress.clone();
            pg.on_push(
                1,
                chunks + 1,
                pgwire::msgs::PRIO_DEFAULT,
                MOSDPGPush {
                    pgid: pg.spg,
                    map_epoch: 5,
                    min_epoch: 5,
                    from: PgShard {
                        osd: 1,
                        shard: ShardId::NO_SHARD,
                    },
                    pushes: vec![op],
                    ..Default::default()
                },
                &target,
            );
            let actions = pg.take_actions();
            assert!(
                !actions.iter().any(|a| matches!(a, Action::Send(s)
                if matches!(&s.body, Body::Repl(replwire::ReplMsg::PushReply(_))))),
                "recovery acknowledgement precedes durability"
            );
            for (token, txn) in persists(actions) {
                target.submit(pg.spg, &txn);
                pg.on_commit(chunks + 1, token, &target);
            }
            pg.take_actions();
            chunks += 1;
            if progress.is_complete() {
                break;
            }
            assert!(chunks < 10);
        }
        let got = &target.objects(pg.spg)[&oid];
        assert_eq!(got.data, b"0123456789abcdef");
        assert_eq!(
            got.omap, keys,
            "budget={budget}: unchanged omap lost during recovery"
        );
        assert_eq!(got.omap_header, b"header");
        assert!(!pg.missing.contains(&oid));
    }
}

/// P10: our copy is absent although our missing set says we have it and the peer needs it: it becomes missing here
/// (classic `primary_error`) and is pulled from a holder, loudly; never a silent skip.
#[test]
fn recovery_turns_an_absent_local_copy_into_a_local_missing_item() {
    let oid = Hobject::new(b"gone", SnapId::NOSNAP, 7, 1, b"");
    let need = Eversion::new(4, 1);
    let (mut pg, store, peer) = recovering_pair(None);
    pg.info.last_update = need;
    pg.pg_committed_to = need;
    let mut pm = MissingSet::new(true);
    pm.add(oid.clone(), need, Eversion::default(), false);
    pg.prim.peer_missing.insert(peer, pm);
    pg.rec.cap = 3; // the lease a core's budget would hand out
    pg.recovery_step(&store);
    let actions = pg.take_actions();
    assert!(pushes_to(&actions, 1).is_empty());
    assert!(pg.missing.contains(&oid), "lost local copy is missing now");
    assert!(
        pg.counters().errors.contains_key(
            "recovery: local copy absent or older than needed, re-pulling from a peer"
        )
    );
}

/// A pulled object is no longer missing once its last chunk arrived, but the store holds it only after that apply: a
/// peer that misses it too is pushed to after the commit, never from an early read that takes the not-yet-applied
/// object for a lost local copy (live, case 21 mixed gate 2026-11-01: a fresh primary + a fresh replica after a remap
/// "repaired" every object it pulled, pulled it twice, OSD_TOO_MANY_REPAIRS). Spec replication.md 6.6.
#[test]
fn a_pulled_object_is_pushed_once_its_local_apply_committed() {
    let oid = Hobject::new(b"pulled", SnapId::NOSNAP, 7, 1, b"");
    let v = Eversion::new(4, 1);
    let (mut pg, mut store, peer) = recovering_pair(None);
    pg.info.last_update = v;
    pg.pg_committed_to = v;
    pg.missing.add(oid.clone(), v, Eversion::default(), false);
    let mut pm = MissingSet::new(true);
    pm.add(oid.clone(), v, Eversion::default(), false);
    pg.prim.peer_missing.insert(peer, pm);
    pg.rec.cap = 3; // the lease a core's budget would hand out
    let source = PgShard {
        osd: 2,
        shard: ShardId::NO_SHARD,
    };
    let oi = replwire::ObjectInfo {
        soid: oid.clone(),
        version: v,
        size: 4,
        ..Default::default()
    };
    let info = ObjectRecoveryInfo {
        soid: oid.clone(),
        version: v,
        size: 4,
        copy_subset: BTreeMap::from([(0, 4)]),
        oi: oi.clone(),
        ..Default::default()
    };
    pg.rec.pulls.insert(
        oid.clone(),
        PullInfo {
            from: source.osd,
            info: info.clone(),
            progress: ObjectRecoveryProgress::default(),
            stat: Default::default(),
        },
    );
    // `Pg::handle_msg`: the pull response, then the event's recovery pass, before the driver queues the txn
    pg.on_push(
        source.osd,
        1,
        pgwire::msgs::PRIO_DEFAULT,
        MOSDPGPush {
            pgid: pg.spg,
            from: source,
            map_epoch: 5,
            min_epoch: 5,
            pushes: vec![PushOp {
                soid: oid.clone(),
                version: v,
                data: b"data".to_vec().into(),
                data_included: BTreeMap::from([(0, 4)]),
                attrset: BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]),
                recovery_info: info,
                after_progress: ObjectRecoveryProgress {
                    first: false,
                    data_complete: true,
                    omap_complete: true,
                    data_recovered_to: 4,
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        },
        &store,
    );
    pg.after_event(&store);
    let actions = pg.take_actions();
    assert!(!pg.missing.contains(&oid), "recovered here");
    assert!(
        pg.counters().errors.is_empty(),
        "{:?}",
        pg.counters().errors
    );
    assert!(pg.damaged().next().is_none(), "never taken for damage");
    assert!(
        pushes_to(&actions, 1).is_empty(),
        "nothing pushed before the local apply is in the store"
    );
    for (i, (token, txn)) in persists(actions).into_iter().enumerate() {
        store.submit(pg.spg, &txn);
        pg.on_commit(i as u64 + 1, token, &store);
    }
    let actions = pg.take_actions();
    assert_eq!(pushes_to(&actions, 1), vec![(oid, v)]);
    assert!(
        pg.counters().errors.is_empty(),
        "{:?}",
        pg.counters().errors
    );
    assert_eq!(pg.shards_repaired(), 0);
}

/// R5: a reply's `last_complete_ondisk` is the value taken when its entry was appended, never re-sampled at commit:
/// two log updates appended, the first commits, its reply must not claim the second (not durable yet).
#[test]
fn reply_last_complete_ondisk_is_the_enqueue_value() {
    let (mut pg, store) = backfill_target(None);
    pg.info.last_backfill = Hobject::MAX();
    let oid = Hobject::new(b"err", SnapId::NOSNAP, 7, 1, b"");
    let ulm = |v: u64| replwire::MOSDPGUpdateLogMissing {
        map_epoch: 5,
        pgid: SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        },
        rep_tid: v,
        entries: denc::to_vec(&vec![pgwire::LogEntry {
            op: pgwire::LogOp::ERROR,
            soid: oid.clone(),
            version: Eversion::new(5, v),
            return_code: -2,
            ..Default::default()
        }])
        .unwrap(),
        min_epoch: 5,
        ..Default::default()
    };
    pg.on_update_log_missing(1, 1, ulm(1));
    pg.on_update_log_missing(1, 2, ulm(2));
    let pending = persists(pg.take_actions());
    assert_eq!(pending.len(), 2, "one store txn per update");
    assert_eq!(pg.info.last_complete, Eversion::new(5, 2));
    pg.on_commit(1, pending[0].0, &store);
    let lcod: Vec<Eversion> = pg
        .take_actions()
        .into_iter()
        .filter_map(|a| match a {
            Action::Send(s) => match s.body {
                Body::Repl(replwire::ReplMsg::UpdateLogMissingReply(r)) => {
                    Some(r.last_complete_ondisk)
                }
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(lcod, vec![Eversion::new(5, 1)]);
}

/// Our missing objects start in (kicked first, then needed version, then oid) order, `cap - inflight` per pass; a pass
/// at the cap starts nothing and asks for another pass when an op completes.
#[test]
fn recovery_pulls_start_in_need_order_and_nothing_at_the_cap() {
    let (mut pg, store, peer) = recovering_pair(None);
    let mut pi = PgInfo::new(pg.spg);
    pi.last_update = Eversion::new(4, 9);
    pi.last_backfill = Hobject::MAX();
    pg.prim.peer_info.insert(peer, pi);
    let obj = |n: &str| Hobject::new(n.as_bytes(), SnapId::NOSNAP, 7, 1, b"");
    // oid order a..e, needed versions descending: need order is e, d, c, b, a
    for (i, n) in ["a", "b", "c", "d", "e"].into_iter().enumerate() {
        pg.missing.add(
            obj(n),
            Eversion::new(4, 9 - i as u64),
            Eversion::default(),
            false,
        );
    }
    pg.info.last_update = Eversion::new(4, 9);
    pg.pg_committed_to = Eversion::new(4, 9);
    pg.rec.kick.insert(obj("b")); // a write waits for b: first
    pg.rec.cap = 3;
    pg.rec.wants = false;
    pg.recovery_step(&store);
    let started: BTreeSet<Hobject> = pg.rec.pulls.keys().cloned().collect();
    assert_eq!(started, BTreeSet::from([obj("b"), obj("e"), obj("d")]));
    assert!(
        pg.rec.wants,
        "over the cap: another pass when one completes"
    );
    // at the cap: nothing more starts, a later pass is still requested
    let _ = pg.take_actions();
    pg.rec.wants = false;
    pg.recovery_step(&store);
    assert_eq!(pg.rec.pulls.len(), 3);
    assert!(pg.take_actions().is_empty());
    assert!(pg.rec.wants);
}

/// Micro bench (`cargo test -p peering --release recovery_step_cost -- --ignored --nocapture`): ns per
/// `recovery_step` event with 100k missing objects and cap 10, at the cap and one below it.
#[test]
#[ignore = "micro bench"]
fn recovery_step_cost_with_a_large_missing_set() {
    let (mut pg, store, peer) = recovering_pair(None);
    let mut pi = PgInfo::new(pg.spg);
    pi.last_update = Eversion::new(4, 1);
    pi.last_backfill = Hobject::MAX();
    pg.prim.peer_info.insert(peer, pi);
    for n in 0..100_000u64 {
        let oid = Hobject::new(format!("o{n:06}").as_bytes(), SnapId::NOSNAP, 7, 1, b"");
        pg.missing
            .add(oid, Eversion::new(4, 1), Eversion::default(), false);
    }
    pg.rec.cap = 10;
    pg.recovery_step(&store);
    assert_eq!(pg.rec.pulls.len(), 10);
    let _ = pg.take_actions();
    let t = std::time::Instant::now();
    for _ in 0..20 {
        pg.recovery_step(&store);
    }
    eprintln!("at cap: {} ns/event", t.elapsed().as_nanos() / 20);
    let first = pg.rec.pulls.keys().next().cloned().unwrap();
    let t = std::time::Instant::now();
    for _ in 0..20 {
        pg.rec.pulls.remove(&first);
        pg.recovery_step(&store);
    }
    eprintln!("one below cap: {} ns/event", t.elapsed().as_nanos() / 20);
}

/// A recovery deferred mid-pull (`cancel_inflight`) and granted again starts a new pull of the same object from the same
/// source; a late continuation chunk of the dropped pull must not be taken as a reply of the new one (two streams would
/// interleave in one temp object, and the rename on the old stream's last chunk would install the mix as recovered).
#[test]
fn a_stale_chunk_of_a_cancelled_pull_does_not_join_the_new_pull() {
    let (mut pg, store, source) = primary(false);
    let oid = Hobject::new(b"big", SnapId::NOSNAP, 7, 1, b"");
    let v = Eversion::new(4, 1);
    pg.info.last_update = v;
    pg.missing.add(oid.clone(), v, Eversion::default(), false);
    let info = ObjectRecoveryInfo {
        soid: oid.clone(),
        version: v,
        size: 12,
        copy_subset: BTreeMap::from([(0, 12)]),
        ..Default::default()
    };
    // the new pull: just sent, nothing received yet
    pg.rec.pulls.insert(
        oid.clone(),
        PullInfo {
            from: source.osd,
            info: info.clone(),
            progress: ObjectRecoveryProgress::default(),
            stat: Default::default(),
        },
    );
    let mid = |to: u64| ObjectRecoveryProgress {
        first: false,
        data_recovered_to: to,
        ..Default::default()
    };
    // chunk 2 of the dropped pull (bytes 4..8) arrives first
    pg.on_push(
        source.osd,
        1,
        pgwire::msgs::PRIO_DEFAULT,
        MOSDPGPush {
            pgid: pg.spg,
            from: source,
            map_epoch: 5,
            min_epoch: 5,
            pushes: vec![PushOp {
                soid: oid.clone(),
                version: v,
                data: b"old2".to_vec().into(),
                data_included: BTreeMap::from([(4, 4)]),
                recovery_info: info,
                before_progress: mid(4),
                after_progress: mid(8),
                ..Default::default()
            }],
            ..Default::default()
        },
        &store,
    );
    let actions = pg.take_actions();
    let pulls = actions
        .iter()
        .filter(|a| {
            matches!(a, Action::Send(s) if matches!(&s.body, Body::Repl(replwire::ReplMsg::Pull(_))))
        })
        .count();
    assert_eq!(pulls, 0, "no second pull stream");
    assert_eq!(
        pg.rec.pulls[&oid].progress,
        ObjectRecoveryProgress::default(),
        "the new pull still waits for its first chunk"
    );
    assert!(
        persists(actions)
            .iter()
            .all(|(_, t)| !t.ops.iter().any(|o| matches!(o, StoreOp::ApplyTxn { .. }))),
        "nothing of the stale chunk is applied"
    );
    assert!(pg.missing.contains(&oid));
}

/// Object metadata can remain readable while a later data/omap read fails. Both the first push and a continuation
/// must put the primary's copy into recovery, rather than retrying that broken source forever. A version change or a
/// queued removal is no damage and leaves the primary's copy alone.
#[test]
fn recovery_payload_read_failure_pulls_a_healthy_peer() {
    use crate::plog::MissingSet;
    use crate::store::StoreReadError;
    use replwire::{MOSDPGPushReply, PushReplyOp, ReplMsg};

    for continuation in [false, true] {
        for error in [
            StoreReadError::Corrupt,
            StoreReadError::Io,
            StoreReadError::VersionMismatch,
            StoreReadError::NoObject,
        ] {
            let damaged = matches!(error, StoreReadError::Corrupt | StoreReadError::Io);
            let (mut pg, mut store, _) = primary(false);
            let oid = Hobject::new(b"payload-read-error", SnapId::NOSNAP, 7, 1, b"");
            let version = Eversion::new(4, 1);
            let target = PgShard {
                osd: 1,
                shard: ShardId::NO_SHARD,
            };
            let healthy = PgShard {
                osd: 2,
                shard: ShardId::NO_SHARD,
            };
            pg.acting = vec![0, 1, 2];
            pg.up = pg.acting.clone();
            pg.info.last_backfill = Hobject::MAX();
            pg.info.last_update = version;
            pg.prim.acting_recovery_backfill = [pg.me, target, healthy].into_iter().collect();
            for peer in [target, healthy] {
                pg.prim.peer_info.insert(
                    peer,
                    PgInfo {
                        last_update: version,
                        last_backfill: Hobject::MAX(),
                        ..PgInfo::new(pg.spg)
                    },
                );
                pg.prim.peer_missing.insert(peer, MissingSet::new(true));
            }
            pg.prim.peer_missing.get_mut(&target).unwrap().add(
                oid.clone(),
                Eversion::new(3, 1), // sending our current copy is valid even when the target needs an older version
                Eversion::default(),
                false,
            );
            pg.rec.cap = 4;
            Arc::make_mut(&mut pg.cfg).recovery_max_chunk = 4;
            store.pgs.get_mut(&pg.spg).unwrap().objects.insert(
                oid.clone(),
                MemObj {
                    data: b"payload".to_vec(),
                    xattrs: BTreeMap::from([(
                        b"_".to_vec(),
                        denc::to_vec(&replwire::ObjectInfo {
                            soid: oid.clone(),
                            version,
                            size: 7,
                            ..Default::default()
                        })
                        .unwrap(),
                    )]),
                    ..Default::default()
                },
            );
            if continuation {
                pg.recovery_step(&store);
                assert!(pg.rec.pushes.contains_key(&(oid.clone(), target.osd)));
                pg.take_actions();
            }
            *store.push_error.borrow_mut() = Some(error.clone());
            if continuation {
                pg.on_push_reply(
                    target.osd,
                    pgwire::msgs::PRIO_DEFAULT,
                    MOSDPGPushReply {
                        replies: vec![PushReplyOp { soid: oid.clone() }],
                        ..Default::default()
                    },
                    &store,
                );
            } else {
                pg.recovery_step(&store);
            }
            if !damaged {
                // a newer local version or a queued removal is no damage: our copy must not become missing
                assert!(
                    !pg.missing.contains(&oid),
                    "continuation={continuation}, error={error:?}: readable primary marked missing"
                );
                continue;
            }
            assert!(
                pg.missing.contains(&oid),
                "continuation={continuation}, error={error:?}: unreadable primary must become missing"
            );
            assert!(
                pg.prim.peer_missing[&target].contains(&oid),
                "no false completion at the target"
            );
            assert_eq!(pg.missing.get(&oid).unwrap().need, version);
            pg.recovery_step(&store);
            assert_eq!(pg.rec.pulls[&oid].from, healthy.osd);
            assert!(pg.take_actions().iter().any(|a| matches!(a,
                Action::Send(s) if s.to == healthy.osd && matches!(&s.body, Body::Repl(ReplMsg::Pull(m)) if m.pulls.iter().any(|p| p.soid == oid))
            )), "repair must pull the healthy third copy");
        }
    }
}

/// Reservations belong to the acting primary. A different up OSD must neither consume a scarce remote slot nor
/// release the primary's slot/space while its recovery is running. Exercise dispatch and authorized controls.
#[test]
fn recovery_reservations_reject_nonprimary_senders() {
    use crate::pg::RepRes;
    use replwire::{MBackfillReserve, MRecoveryReserve, ReplMsg};

    for ec in [None, Some(false), Some(true)] {
        for backfill in [false, true] {
            for release in [false, true] {
                for sender in [2, 1] {
                    let (mut pg, store) = backfill_target(ec);
                    if release {
                        pg.rep_res = RepRes::Recovering { backfill };
                        pg.bf_space = 8192;
                    }
                    let before_res = pg.rep_res;
                    let before_space = pg.bf_space;
                    let msg = if backfill {
                        let mut m = MBackfillReserve::reply(
                            pg.spg,
                            5,
                            if release {
                                MBackfillReserve::RELEASE
                            } else {
                                MBackfillReserve::REQUEST
                            },
                        );
                        m.primary_num_bytes = 32768;
                        ReplMsg::BackfillReserve(m)
                    } else {
                        ReplMsg::RecoveryReserve(MRecoveryReserve::reply(
                            pg.spg,
                            5,
                            if release {
                                MRecoveryReserve::RELEASE
                            } else {
                                MRecoveryReserve::REQUEST
                            },
                        ))
                    };
                    pg.handle_msg(
                        0,
                        Inbound {
                            from: sender,
                            tid: 0,
                            prio: pgwire::msgs::PRIO_DEFAULT,
                            ingress: Default::default(),
                            body: Box::new(Body::Repl(msg)),
                        },
                        &store,
                    );
                    let actions = pg.take_actions();
                    let slot_action = actions.iter().any(|a| matches!(a, Action::Resv(_)));
                    if sender != pg.acting_primary {
                        assert_eq!(
                            pg.rep_res, before_res,
                            "{ec:?} backfill={backfill} release={release}: foreign request changes slot state"
                        );
                        assert_eq!(
                            pg.bf_space, before_space,
                            "foreign request changes reserved space"
                        );
                        assert!(
                            !slot_action,
                            "foreign request manipulates OSD-wide reserver"
                        );
                    } else {
                        assert!(slot_action, "acting primary must drive the reserver");
                        assert_eq!(
                            pg.rep_res,
                            if release {
                                RepRes::NotRecovering
                            } else if backfill {
                                RepRes::WaitBackfill
                            } else {
                                RepRes::WaitRecovery
                            }
                        );
                        if release {
                            assert_eq!(pg.bf_space, 0);
                        } else if backfill {
                            assert!(pg.bf_space > 0);
                        }
                    }
                }
            }
        }
    }
}

/// NT-deadcode-02: a replica's backfill scan digest lists at most `osd_backfill_scan_max` objects (was a fixed 512).
#[test]
fn backfill_scan_digest_follows_osd_backfill_scan_max() {
    use replwire::{MOSDPGScan, ReplMsg};

    let (mut pg, mut store) = backfill_target(None);
    for i in 0..5 {
        let oid = Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b"");
        let oi = replwire::ObjectInfo {
            soid: oid.clone(),
            version: Eversion::new(4, u64::from(i) + 1),
            ..Default::default()
        };
        store.pgs.get_mut(&pg.spg).unwrap().objects.insert(
            oid,
            MemObj {
                xattrs: BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]),
                ..Default::default()
            },
        );
    }
    let mut cfg = (*pg.cfg).clone();
    cfg.backfill_scan_min = 1;
    cfg.backfill_scan_max = 2;
    pg.cfg = Arc::new(cfg);
    let scan = MOSDPGScan {
        pgid: pg.spg,
        map_epoch: 5,
        query_epoch: 5,
        op: MOSDPGScan::OP_GET_DIGEST,
        begin: Hobject::MIN(),
        end: Hobject::MAX(),
        from: PgShard {
            osd: 1,
            shard: pg.primary_shard(),
        },
        digest: None,
    };
    pg.handle_msg(
        0,
        Inbound {
            from: 1,
            tid: 1,
            prio: pgwire::msgs::PRIO_DEFAULT,
            ingress: Default::default(),
            body: Box::new(Body::Repl(ReplMsg::Scan(scan))),
        },
        &store,
    );
    let digests: Vec<usize> = pg
        .take_actions()
        .iter()
        .filter_map(|a| match a {
            Action::Send(s) => match &s.body {
                Body::Repl(ReplMsg::Scan(m)) if m.op == MOSDPGScan::OP_DIGEST => {
                    m.digest.as_ref().map(Vec::len)
                }
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(digests, vec![2]);
}

/// Sent `(type, tid, prio)` of the repl messages in `actions`.
fn repl_sends(actions: &[Action]) -> Vec<(u16, u64, u16)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(s) if matches!(s.body, Body::Repl(_)) => {
                Some((s.body.msg_type(), s.tid, s.prio))
            }
            _ => None,
        })
        .collect()
}

/// NT-flags-05: classic answers a recovery request with the request's header priority (push reply, the push serving
/// a pull, a pull continuation, the next push chunk after a push reply); a locally derived class or the default 127
/// would move the work into another classic mclock class.
#[test]
fn recovery_replies_echo_the_request_priority() {
    use replwire::{MOSDPGPull, MOSDPGPushReply, PullOp, PushReplyOp, ty};
    const PRIO: u16 = 10;
    // replica: the durable push reply echoes the push's priority
    let (mut pg, mut target) = backfill_target(None);
    let oid = Hobject::new(b"echo", SnapId::NOSNAP, 7, 1, b"");
    let v = Eversion::new(4, 1);
    let mut oi = replwire::ObjectInfo::new(oid.clone());
    oi.version = v;
    oi.size = 4;
    let mut source = target.clone();
    source.pgs.get_mut(&pg.spg).unwrap().objects.insert(
        oid.clone(),
        crate::store::MemObj {
            data: b"echo".to_vec(),
            xattrs: BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]),
            ..Default::default()
        },
    );
    pg.info.last_update = v;
    pg.missing.add(oid.clone(), v, Eversion::default(), false);
    let info = source.recovery_info(pg.spg, &oid).unwrap();
    let progress = ObjectRecoveryProgress {
        omap_complete: true,
        ..Default::default()
    };
    let op = source
        .build_push(pg.spg, &info, &progress, 1 << 20, 100)
        .unwrap();
    let from = PgShard {
        osd: 1,
        shard: ShardId::NO_SHARD,
    };
    pg.on_push(
        1,
        7,
        PRIO,
        MOSDPGPush {
            pgid: pg.spg,
            map_epoch: 5,
            min_epoch: 5,
            from,
            pushes: vec![op],
            ..Default::default()
        },
        &target,
    );
    let mut sent = Vec::new();
    for (token, txn) in persists(pg.take_actions()) {
        target.submit(pg.spg, &txn);
        pg.on_commit(1, token, &target);
        sent.extend(repl_sends(&pg.take_actions()));
    }
    assert_eq!(sent, vec![(ty::PUSH_REPLY, 7, PRIO)]);
    // the push answering a pull echoes the pull's priority
    pg.on_pull(
        1,
        8,
        PRIO,
        MOSDPGPull {
            pgid: pg.spg,
            map_epoch: 5,
            min_epoch: 5,
            from,
            pulls: vec![PullOp {
                soid: oid.clone(),
                recovery_info: info,
                recovery_progress: progress,
            }],
            ..Default::default()
        },
        &target,
    );
    assert_eq!(repl_sends(&pg.take_actions()), vec![(ty::PUSH, 8, PRIO)]);

    // primary: a new push carries the local class (mclock best effort here), the next chunk the reply's priority
    let oid = Hobject::new(b"chunked", SnapId::NOSNAP, 7, 1, b"");
    let (old, cur) = (Eversion::new(4, 1), Eversion::new(4, 2));
    let (mut pg, store, peer) = recovering_pair(Some((&oid, cur)));
    Arc::make_mut(&mut pg.cfg).recovery_max_chunk = 2;
    let mut pm = MissingSet::new(true);
    pm.add(oid.clone(), old, Eversion::default(), false);
    pg.prim.peer_missing.insert(peer, pm);
    pg.rec.cap = 3;
    pg.recovery_step(&store);
    assert_eq!(repl_sends(&pg.take_actions()), vec![(ty::PUSH, 0, 5)]);
    pg.on_push_reply(
        peer.osd,
        PRIO,
        MOSDPGPushReply {
            pgid: pg.spg,
            map_epoch: 5,
            min_epoch: 5,
            from: peer,
            replies: vec![PushReplyOp { soid: oid }],
            ..Default::default()
        },
        &store,
    );
    assert_eq!(repl_sends(&pg.take_actions()), vec![(ty::PUSH, 0, PRIO)]);
}
