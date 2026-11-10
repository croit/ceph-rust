// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! A PG copy being deleted when a new map puts its OSD back into the PG (adr 0071 am. 3): the messages of the new
//! interval wait for the delete and are routed after it (the PG is created from the sender's create info). None is
//! dropped: without a resend timer a lost activation log or notify would leave the PG peering forever.
mod common;
use common::*;
use denc::types::PgT;
use std::collections::BTreeMap;

const POOL: u64 = 1;

/// pg 1.0 of a size-3 pool on four OSDs. Its replica `x` is moved to the spare OSD; once the PG is clean there the
/// primary removes x's stray copy, whose delete commit is held for 3 s. While it is held, `remap` maps the PG onto x
/// again. The pool must get clean with x holding the PG, and x must not have dropped a message of the new interval.
fn remove_then_remap(seed: u64, remap: impl Fn(&[i32], i32) -> Vec<i32>) {
    let mut s = cluster(seed, &[0, 1, 2, 3], POOL, 3, 2, 1);
    let pg = PgT::new(POOL, 0);
    let me = spg(POOL, 0);
    let mut model = BTreeMap::new();
    let mut tids = vec![];
    for i in 0..8 {
        let name = format!("o{i}");
        let d = vec![i as u8; 64 + i * 7];
        tids.push(s.write_obj(POOL, 0, &name, &d).expect("write accepted"));
        model.insert(name, d);
        s.run_for(MS / 2);
    }
    s.wait_writes(&tids, me);
    let up = s.up_of(pg);
    let x = up[2];
    let spare = (0..4).find(|o| !up.contains(o)).expect("a spare OSD");
    s.remove_commit_delay = 3_000 * MS;
    let moved: Vec<i32> = up.iter().map(|&o| if o == x { spare } else { o }).collect();
    s.set_up_override(pg, moved);
    s.run_until(30_000 * MS, "x deletes its stray copy", |s| {
        s.pg(x, me).is_some_and(|p| p.is_deleting())
    });
    let dropped_before: u64 = s.nodes[&x].set.dropped.values().sum();
    // the next interval maps the PG onto x again while x's copy is still being deleted
    s.set_up_override(pg, remap(&up, x));
    s.run_until(60_000 * MS, "pool clean after the remap", |s| {
        s.pool_clean(POOL) && s.pg(x, me).is_some_and(|p| !p.is_deleting())
    });
    assert!(
        s.removed.contains(&(x, me)),
        "x deleted the old copy before it held the PG again"
    );
    let dropped: BTreeMap<_, _> = s.nodes[&x].set.dropped.clone();
    assert_eq!(
        dropped.values().sum::<u64>(),
        dropped_before,
        "x dropped messages of the new interval: {dropped:?}"
    );
    s.assert_replicas_equal(POOL, 0, &model);
}

/// x returns as a replica: the primary's query and activation log reach x only after its delete.
#[test]
fn deleting_copy_remapped_as_replica_gets_the_activation() {
    for seed in [71, 72, 73] {
        remove_then_remap(seed, |up, _| up.to_vec());
    }
}

/// x returns as the primary: the notifies of the replicas create its PG once the delete is done.
#[test]
fn deleting_copy_remapped_as_primary_gets_the_notifies() {
    for seed in [74, 75, 76] {
        remove_then_remap(seed, |up, x| {
            let mut v = vec![x];
            v.extend(up.iter().copied().filter(|&o| o != x));
            v
        });
    }
}

/// While x's copy is deleted, a map does not route the messages waiting for it again (only `PgRemoved` does): every
/// pass re-ran the receive side effects for stale messages, e.g. took the primary's waiting query as proof that x's
/// session to the primary works while it was down (held queries flowed again, the back-off restarted).
#[test]
fn deleting_copy_keeps_its_waiting_messages_across_maps() {
    let mut s = cluster(77, &[0, 1, 2, 3], POOL, 3, 2, 1);
    let pg = PgT::new(POOL, 0);
    let me = spg(POOL, 0);
    let up = s.up_of(pg);
    let (p, x) = (up[0], up[2]);
    let spare = (0..4).find(|o| !up.contains(o)).expect("a spare OSD");
    s.remove_commit_delay = 3_000 * MS;
    let moved: Vec<i32> = up.iter().map(|&o| if o == x { spare } else { o }).collect();
    s.set_up_override(pg, moved);
    s.run_until(30_000 * MS, "x deletes its stray copy", |s| {
        s.pg(x, me).is_some_and(|p| p.is_deleting())
    });
    s.set_up_override(pg, up.clone());
    s.run_until(
        2_000 * MS,
        "the primary's query waits for x's delete",
        |s| s.nodes[&x].set.parked_msgs().1 > 0,
    );
    // x's session to the primary goes down: nothing from the primary reaches x until it is back
    s.partition(p, x);
    s.link_now(x, p, false);
    let faults = s.nodes[&x].set.peer_stats.faults;
    let waiting = s.nodes[&x].set.parked_msgs().1;
    s.new_epoch(|_| {});
    s.new_epoch(|_| {});
    s.run_for(100 * MS);
    assert!(
        s.pg(x, me).is_some_and(|p| p.is_deleting()),
        "the delete commit is still held"
    );
    assert_eq!(s.nodes[&x].set.parked_msgs().1, waiting);
    // still lost: a repeated fault is not a new loss
    s.link_now(x, p, false);
    assert_eq!(
        s.nodes[&x].set.peer_stats.faults, faults,
        "a map routed the waiting query again and took it as a message from the primary"
    );
    s.heal();
    s.link_now(x, p, true);
    s.run_until(60_000 * MS, "pool clean after the remap", |s| {
        s.pool_clean(POOL) && s.pg(x, me).is_some_and(|p| !p.is_deleting())
    });
}

/// OQ 127 (storeadapt `deferred`, adr 0021 am. 23): x re-creates its copy while the deletion of the old one waits for
/// space, so its store keeps every txn of the new copy unapplied and unacknowledged (here: 5 s). Nothing of the PG may be
/// served meanwhile: x does not ack its activation, the primary does not go active (no client read is served), no client
/// write is accepted. Once x's txns are durable the pool gets clean and x holds every acknowledged write.
#[test]
fn recreated_copy_waiting_for_its_old_deletion_keeps_the_pg_inactive() {
    for seed in [81, 82, 83] {
        let mut s = cluster(seed, &[0, 1, 2, 3], POOL, 3, 2, 1);
        let pg = PgT::new(POOL, 0);
        let me = spg(POOL, 0);
        let mut model = BTreeMap::new();
        let mut tids = vec![];
        for i in 0..8 {
            let name = format!("o{i}");
            let d = vec![i as u8; 64 + i * 7];
            tids.push(s.write_obj(POOL, 0, &name, &d).expect("write accepted"));
            model.insert(name, d);
            s.run_for(MS / 2);
        }
        s.wait_writes(&tids, me);
        let up = s.up_of(pg);
        let (p, x) = (up[0], up[2]);
        let spare = (0..4).find(|o| !up.contains(o)).expect("a spare OSD");
        let moved: Vec<i32> = up.iter().map(|&o| if o == x { spare } else { o }).collect();
        s.set_up_override(pg, moved);
        s.run_until(30_000 * MS, "x deleted its stray copy", |s| {
            s.removed.contains(&(x, me))
        });
        let until = s.now + 5_000 * MS;
        s.pg_commit_hold = Some((x, me, until));
        s.set_up_override(pg, up.clone());
        s.run_until(2_000 * MS, "x re-created its copy", |s| {
            s.pg(x, me).is_some()
        });
        while s.now + 200 * MS < until {
            assert!(
                s.pg(x, me).is_some_and(|g| !g.is_active()),
                "seed {seed}: x active before its re-create is durable"
            );
            assert!(
                s.pg(p, me).is_none_or(|g| !g.is_active()),
                "seed {seed}: primary active while x's activation is not durable"
            );
            assert!(
                s.write_obj(POOL, 0, "late", b"late").is_err(),
                "seed {seed}: write accepted while x's copy is not durable"
            );
            s.run_for(100 * MS);
        }
        s.pg_commit_hold = None;
        s.run_until(
            60_000 * MS,
            "pool clean after x's re-create is durable",
            |s| s.pool_clean(POOL),
        );
        let tid = s
            .write_obj(POOL, 0, "after", b"after")
            .expect("write accepted");
        model.insert("after".into(), b"after".to_vec());
        s.wait_writes(&[tid], me);
        s.run_until(60_000 * MS, "pool clean", |s| s.pool_clean(POOL));
        assert!(s.acting_of(pg).contains(&x));
        s.assert_replicas_equal(POOL, 0, &model);
    }
}
