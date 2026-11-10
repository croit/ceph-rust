// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Past-interval bounds at the peering call points (peering.md 3.8): an implausible (history, past_intervals) pair
//! stops only that PG (INCOMPLETE, no outbound message, no client service); a plausible one peers normally, a later
//! interval that repairs the pair resumes it, split children run the check themselves, a stopped PG stays deletable
//! and the operator escape releases it through a Reset restart.
use denc::types::{PgShard, PgT, ShardId, SpgT};
use peering::synth::SynthMap;
use peering::{
    Action, Body, BoundsStoppedPg, Config, Inbound, MemStore, PSt, PgSet, PgStoreOps, St, StoreOp,
    body_spgs,
};
use pgwire::state as pgs;
use pgwire::{
    CompactInterval, MOSDPGNotify2, MOSDPGRemove, PastIntervals, PeeringMsg, PgInfo, PgNotify,
};
use std::collections::BTreeSet;

const POOL: u64 = 1;

fn spg(seed: u32) -> SpgT {
    SpgT {
        pgid: PgT::new(POOL, seed),
        shard: ShardId::NO_SHARD,
    }
}

/// `past(first, last)` covers `[first, last + 1)`; a smallest acting set keeps the prior set simple.
fn past(first: u32, last: u32) -> PastIntervals {
    let acting = BTreeSet::from([PgShard {
        osd: 1,
        shard: ShardId::NO_SHARD,
    }]);
    PastIntervals {
        first,
        last,
        all_participants: acting.clone(),
        intervals: vec![CompactInterval {
            first,
            last,
            acting,
        }],
    }
}

/// Maps 2..=6 with seed 0 and 1 on [0,1]; history lec 3, sis 6 -> required `[3,6)`.
fn set() -> (PgSet, MemStore) {
    let store = MemStore::new();
    let mut set = PgSet::new(Config::new(0));
    for e in 2..=6 {
        let _ = set.handle_map(0, map(e, [vec![0, 1], vec![0, 1]]), &store);
    }
    (set, store)
}

fn map(epoch: u32, up: [Vec<i32>; 2]) -> peering::MapHandle {
    let mut m = SynthMap::new(epoch);
    for o in 0..3 {
        m = m.with_osd(o, 1);
    }
    m = m.with_pool(POOL, 2, 1, 2);
    for (seed, v) in up.into_iter().enumerate() {
        m.up_override.insert(PgT::new(POOL, seed as u32), v);
    }
    m.into_handle()
}

/// Create info from osd.1 (Notify2) for `seed`.
fn notify(set: &mut PgSet, store: &MemStore, seed: u32, p: PastIntervals) -> Vec<Action> {
    let s = spg(seed);
    let mut info = PgInfo::new(s);
    info.history.epoch_created = 1;
    info.history.epoch_pool_created = 1;
    info.history.last_epoch_started = 3;
    info.history.last_epoch_clean = 3;
    info.history.same_interval_since = 6;
    info.history.same_up_since = 6;
    info.history.same_primary_since = 6;
    let mut n = PgNotify::dne(info, ShardId::NO_SHARD, 6, 6);
    n.past_intervals = p;
    set.handle_msg(
        0,
        Inbound {
            ingress: Default::default(),
            from: 1,
            tid: 0,
            prio: pgwire::msgs::PRIO_DEFAULT,
            body: Box::new(Body::Peering(PeeringMsg::from(MOSDPGNotify2 {
                spgid: s,
                notify: n,
            }))),
        },
        store,
    )
}

fn stopped0() -> Vec<BoundsStoppedPg> {
    vec![BoundsStoppedPg {
        spg: spg(0),
        required: (3, 6),
        past: (3, 5),
    }]
}

fn outbound(acts: &[Action]) -> usize {
    acts.iter()
        .filter(|a| matches!(a, Action::Send(_) | Action::PgTemp { .. }))
        .count()
}

/// Outbound messages about PG `pgid` in a batch.
fn outbound_of(acts: &[Action], pgid: PgT) -> Vec<&Action> {
    acts.iter()
        .filter(|a| match a {
            Action::Send(s) => body_spgs(&s.body).iter().any(|g| g.pgid == pgid),
            Action::PgTemp { pgid: p, .. } => *p == pgid,
            _ => false,
        })
        .collect()
}

#[test]
fn plausible_bounds_do_not_stop() {
    let (mut s, store) = set();
    let _ = notify(&mut s, &store, 0, past(3, 5));
    let pg = s.pg(spg(0)).expect("created");
    assert!(!pg.past_bounds_stopped());
    assert_eq!(pg.past_bounds_stop(), None);
    assert!(s.bounds_stopped().is_empty());
    let notes = s.take_notices().join("\n");
    assert!(!notes.contains("implausible"), "{notes}");
}

#[test]
fn implausible_bounds_stop_only_that_pg() {
    let (mut s, store) = set();
    // seed 0: stored end 5, current interval starts at 6 -> case 4
    let acts = notify(&mut s, &store, 0, past(3, 4));
    let pg = s.pg(spg(0)).expect("created");
    assert!(pg.past_bounds_stopped());
    assert_eq!(
        pg.past_bounds_stop(),
        Some(((3, 6), (3, 5))),
        "required vs stored range"
    );
    assert_ne!(pg.state_bits() & pgs::INCOMPLETE, 0);
    assert_eq!(outbound(&acts), 0, "no state derived from the bad pair");
    let notes = s.take_notices().join("\n");
    assert!(
        notes.contains("ERROR 1.0 past interval bounds implausible: required [3,6) past [3,5): past intervals end differs from the required end; PG stopped (inactive)"),
        "{notes}"
    );
    assert_eq!(
        s.bounds_stopped(),
        stopped0(),
        "health alert input names the stopped PG and both ranges"
    );

    // a healthy PG of the same OSD keeps peering
    let _ = notify(&mut s, &store, 1, past(3, 5));
    let good = s.pg(spg(1)).expect("created");
    assert!(!good.past_bounds_stopped());
    assert_eq!(good.past_bounds_stop(), None);
    assert_eq!(s.bounds_stopped(), stopped0());
}

#[test]
fn a_later_interval_with_plausible_bounds_resumes_the_pg() {
    let (mut s, store) = set();
    notify(&mut s, &store, 0, past(3, 4));
    assert!(s.pg(spg(0)).unwrap().past_bounds_stopped());
    let _ = s.take_notices();
    // new interval: acting moves to [0,2]; the old interval is appended to the set, sis becomes 7
    let acts = s.handle_map(0, map(7, [vec![0, 2], vec![0, 1]]), &store);
    let pg = s.pg(spg(0)).unwrap();
    assert!(
        !pg.past_bounds_stopped(),
        "recomputed from the durable pair"
    );
    assert_eq!(pg.past_intervals().bounds(), (3, 7));
    assert_eq!(
        pg.machine_state(),
        St::Primary(PSt::GetInfo),
        "normal peering starts again"
    );
    assert!(s.bounds_stopped().is_empty(), "health alert clears");
    let notes = s.take_notices().join("\n");
    assert!(!notes.contains("implausible"), "{notes}");
    assert!(!acts.is_empty());
}

/// Epoch `epoch` with pool 1 at pg_num 4: parent 0 splits into seeds 0 and 2. Child 2 is a replica here, so without its
/// own bounds check it would send a Notify on its first ActMap.
fn map_split(epoch: u32) -> peering::MapHandle {
    let mut m = SynthMap::new(epoch);
    for o in 0..3 {
        m = m.with_osd(o, 1);
    }
    m = m.with_pool(POOL, 2, 1, 4);
    for (seed, v) in [
        (0, vec![0, 1]),
        (1, vec![0, 1]),
        (2, vec![1, 0]),
        (3, vec![0, 1]),
    ] {
        m.up_override.insert(PgT::new(POOL, seed), v);
    }
    m.into_handle()
}

/// A map without the pool: every PG of it sees no pool (spec 7.5, pool deleted).
fn map_without_pool(epoch: u32) -> peering::MapHandle {
    let mut m = SynthMap::new(epoch);
    for o in 0..3 {
        m = m.with_osd(o, 1);
    }
    m.into_handle()
}

/// Apply every `Persist` of a batch and hand the commit back, until none is left (the driver's store side).
fn settle(s: &mut PgSet, store: &mut MemStore, acts: Vec<Action>) {
    // commit callbacks a removal cascade may produce (removal -> PgRemoved -> nothing); a bound against a loop
    const ROUNDS: usize = 16;
    let mut q = acts;
    for _ in 0..ROUNDS {
        let mut more = Vec::new();
        let mut any = false;
        for a in q.drain(..) {
            if let Action::Persist { spg, token, txn } = a {
                store.submit(spg, &txn);
                more.extend(s.on_commit(0, spg, token, store));
                any = true;
            }
        }
        if !any {
            return;
        }
        q = more;
    }
    panic!("persist cascade did not settle");
}

/// A split copies the parent's (history, past intervals) pair, which can be implausible for the new interval too: every
/// child runs the same check before it can act, and a stopped child sends nothing (peering.md 3.8).
#[test]
fn split_of_a_stopped_pg_yields_stopped_children_that_send_nothing() {
    let (mut s, store) = set();
    // lec 3, sis 6, stored past [5,6): the parent stops (start 5 > required start 3)
    let _ = notify(&mut s, &store, 0, past(5, 5));
    assert!(s.pg(spg(0)).unwrap().past_bounds_stopped());
    let _ = s.take_notices();
    // split at epoch 7: the closed interval makes the parent's past [5,7), required [3,7): still implausible
    let acts = s.handle_map(0, map_split(7), &store);
    let parent = s.pg(spg(0)).unwrap();
    assert!(parent.past_bounds_stopped());
    assert_eq!(parent.past_bounds_stop(), Some(((3, 7), (5, 7))));
    let child = s.pg(spg(2)).expect("split child");
    assert_eq!(
        child.past_bounds_stop(),
        Some(((3, 7), (5, 7))),
        "the child copies the parent's pair and runs the check"
    );
    assert_ne!(
        child.state_bits() & pgs::INCOMPLETE,
        0,
        "child stopped, not peering"
    );
    assert_eq!(child.machine_state(), St::Reset);
    assert!(
        outbound_of(&acts, PgT::new(POOL, 2)).is_empty(),
        "a stopped replica child sends no notify: {acts:?}"
    );
    let notes = s.take_notices().join("\n");
    assert!(
        notes.contains("ERROR 1.2 past interval bounds implausible"),
        "the child itself reports the stop: {notes}"
    );
    let stopped: Vec<PgT> = s.bounds_stopped().iter().map(|b| b.spg.pgid).collect();
    assert_eq!(stopped, vec![PgT::new(POOL, 0), PgT::new(POOL, 2)]);
}

/// A runtime `osd_skip_check_past_interval_bounds` change re-evaluates stopped PGs and releases them through the Reset
/// transition a new interval start uses: the PG peers again, the alert is gone (peering.md 3.8).
#[test]
fn runtime_operator_escape_releases_a_stopped_pg() {
    let (mut s, store) = set();
    let _ = notify(&mut s, &store, 0, past(3, 4));
    assert!(s.pg(spg(0)).unwrap().past_bounds_stopped());
    assert_eq!(s.bounds_stopped(), stopped0());
    let _ = s.take_notices();
    s.set_skip_past_bounds_check(true);
    s.push_cfg_to_pgs();
    let acts = s.recheck_past_bounds(0, &store);
    let pg = s.pg(spg(0)).unwrap();
    assert!(!pg.past_bounds_stopped(), "the escape releases the PG");
    assert_eq!(pg.state_bits() & pgs::INCOMPLETE, 0);
    assert_eq!(
        pg.machine_state(),
        St::Primary(PSt::GetInfo),
        "peering restarted through Reset"
    );
    assert!(s.bounds_stopped().is_empty(), "alert gone");
    assert!(
        !outbound_of(&acts, PgT::new(POOL, 0)).is_empty(),
        "GetInfo queries its peers again"
    );
}

/// A stopped PG stays deletable when its pool is deleted: the removal is the only write, the pair is never repaired
/// (peering.md 3.8, 7.5).
#[test]
fn pool_deletion_removes_a_stopped_pg() {
    let (mut s, mut store) = set();
    // lec 3, sis 6, stored past [5,6): closing the interval at the pool-gone map keeps start 5 > required start 3,
    // so the PG is still stopped when it sees no pool
    let _ = notify(&mut s, &store, 0, past(5, 5));
    assert!(s.pg(spg(0)).unwrap().past_bounds_stopped());
    let acts = s.handle_map(0, map_without_pool(7), &store);
    let pg = s.pg(spg(0)).unwrap();
    assert!(pg.is_deleting(), "pool gone: DeleteStart from the stop");
    let writes: Vec<Vec<StoreOp>> = acts
        .iter()
        .filter_map(|a| match a {
            Action::Persist { spg: w, txn, .. } if *w == spg(0) => Some(txn.ops.clone()),
            _ => None,
        })
        .collect();
    // the interval close persists its own state first; the removal is the last write and nothing follows it
    let last = writes.last().expect("a removal transaction");
    assert!(
        matches!(last.as_slice(), [StoreOp::RemovePg]),
        "the removal writes only the removal, nothing that repairs the pair: {last:?}"
    );
    settle(&mut s, &mut store, acts);
    assert!(s.pg(spg(0)).is_none(), "the stopped PG is gone");
    assert!(store.list_pgs().iter().all(|p| p.pgid.pool != POOL));
}

/// Epoch `epoch` with pool 1 placed on `[1,2]`: this OSD leaves the acting set and keeps its copy as a stray.
fn stray_map(epoch: u32) -> peering::MapHandle {
    let mut m = SynthMap::new(epoch);
    for o in 0..3 {
        m = m.with_osd(o, 1);
    }
    m = m.with_pool(POOL, 2, 1, 2);
    m.up_override.insert(PgT::new(POOL, 0), vec![1, 2]);
    m.into_handle()
}

fn remove(epoch: u32, spg: SpgT) -> Inbound {
    Inbound {
        ingress: Default::default(),
        from: 1,
        tid: 0,
        prio: pgwire::msgs::PRIO_DEFAULT,
        body: Box::new(Body::Peering(PeeringMsg::from(MOSDPGRemove {
            epoch,
            pgs: vec![spg],
        }))),
    }
}

/// MOSDPGRemove reaches a stopped PG too, both while it is still mapped (stopped in Reset / Primary(Incomplete)) and
/// after a map made it a stray: it writes only the removal (peering.md 3.8, 7.5).
#[test]
fn mosdpgremove_removes_a_stopped_pg() {
    let (mut s, mut store) = set();
    // lec 3, sis 6, stored past [5,6): closing the interval keeps start 5 > required start 3, so the PG stays stopped
    let _ = notify(&mut s, &store, 0, past(5, 5));
    assert!(s.pg(spg(0)).unwrap().past_bounds_stopped());
    let _ = s.handle_map(0, stray_map(7), &store);
    let pg = s.pg(spg(0)).unwrap();
    assert!(pg.past_bounds_stopped(), "still stopped");
    assert!(
        !pg.is_deleting(),
        "leaving the mapping alone deletes nothing"
    );
    let mut unauthorized = remove(s.epoch(), spg(0));
    unauthorized.from = 2;
    let acts = s.handle_msg(0, unauthorized, &store);
    assert!(
        !s.pg(spg(0)).unwrap().is_deleting(),
        "only the primary may remove a stopped copy"
    );
    settle(&mut s, &mut store, acts);
    let acts = s.handle_msg(0, remove(s.epoch(), spg(0)), &store);
    assert!(s.pg(spg(0)).unwrap().is_deleting());
    let writes: Vec<Vec<StoreOp>> = acts
        .iter()
        .filter_map(|a| match a {
            Action::Persist { spg: w, txn, .. } if *w == spg(0) => Some(txn.ops.clone()),
            _ => None,
        })
        .collect();
    let last = writes.last().expect("a removal transaction");
    assert!(
        matches!(last.as_slice(), [StoreOp::RemovePg]),
        "only the removal: {last:?}"
    );
    settle(&mut s, &mut store, acts);
    assert!(s.pg(spg(0)).is_none());
}

/// Bounds-stopped mapped copies retain the deliberate removal exception, with primary authorization.
#[test]
fn primary_can_remove_a_mapped_stopped_copy() {
    let (mut s, mut store) = set();
    let _ = notify(&mut s, &store, 0, past(5, 5));
    let _ = s.handle_map(0, map(7, [vec![1, 0], vec![1, 0]]), &store);
    assert!(s.pg(spg(0)).unwrap().past_bounds_stopped());
    assert!(s.pg(spg(0)).unwrap().acting().contains(&0));
    let acts = s.handle_msg(0, remove(s.epoch(), spg(0)), &store);
    assert!(s.pg(spg(0)).unwrap().is_deleting());
    settle(&mut s, &mut store, acts);
    assert!(s.pg(spg(0)).is_none());
}

/// A removal from before the current interval is stale on a stopped PG just as on a healthy one (7.3): the copy that
/// rejoined the acting set since must not be deleted. A current removal still removes it (peering.md 3.8, 7.5).
#[test]
fn stale_removal_on_a_stopped_pg_is_discarded() {
    let (mut s, mut store) = set();
    let _ = notify(&mut s, &store, 0, past(5, 5));
    assert!(s.pg(spg(0)).unwrap().past_bounds_stopped());
    let _ = s.handle_map(0, stray_map(7), &store);
    let reset = s.pg(spg(0)).unwrap().last_peering_reset();
    assert!(reset > 6, "a new interval started");
    let acts = s.handle_msg(0, remove(6, spg(0)), &store);
    let pg = s.pg(spg(0)).unwrap();
    assert!(!pg.is_deleting(), "a stale removal deletes nothing");
    assert_eq!(pg.counters().discards.get("old peering message"), Some(&1));
    assert!(
        !acts.iter().any(|a| matches!(
            a,
            Action::Persist { spg: w, txn, .. }
                if *w == spg(0) && matches!(txn.ops.as_slice(), [StoreOp::RemovePg])
        )),
        "no removal written: {acts:?}"
    );
    let acts = s.handle_msg(0, remove(reset, spg(0)), &store);
    assert!(
        s.pg(spg(0)).unwrap().is_deleting(),
        "a current removal still removes it"
    );
    settle(&mut s, &mut store, acts);
    assert!(s.pg(spg(0)).is_none());
}

/// A pending removal is never restarted: the runtime operator escape re-evaluates stopped PGs, but a PG already
/// deleting keeps its removal and completes it without peering or an outbound message (peering.md 3.8, 7.5).
#[test]
fn runtime_escape_does_not_restart_a_deleting_pg() {
    let (mut s, mut store) = set();
    let _ = notify(&mut s, &store, 0, past(5, 5));
    // osd.1 becomes the acting primary: only it may remove the stopped copy
    let _ = s.handle_map(0, map(7, [vec![1, 0], vec![1, 0]]), &store);
    assert!(s.pg(spg(0)).unwrap().past_bounds_stopped());
    let acts = s.handle_msg(0, remove(s.epoch(), spg(0)), &store);
    assert!(s.pg(spg(0)).unwrap().is_deleting());
    s.set_skip_past_bounds_check(true);
    s.push_cfg_to_pgs();
    let acts2 = s.recheck_past_bounds(0, &store);
    let pg = s.pg(spg(0)).unwrap();
    assert!(pg.is_deleting(), "the removal stays pending");
    assert_eq!(pg.machine_state(), St::ToDelete, "not restarted");
    assert_eq!(outbound(&acts2), 0, "nothing goes out: {acts2:?}");
    assert!(
        !acts2.iter().any(|a| matches!(
            a,
            Action::Persist { txn, .. } if matches!(txn.ops.as_slice(), [StoreOp::RemovePg])
        )),
        "no second removal written: {acts2:?}"
    );
    settle(&mut s, &mut store, acts);
    settle(&mut s, &mut store, acts2);
    assert!(s.pg(spg(0)).is_none(), "the removal completes");
}
