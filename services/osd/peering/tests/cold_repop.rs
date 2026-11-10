// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! A replica parks a repop whose objects have cold tree pages (probe `PgStoreOps::warm`, adr 0021 am. 8) instead of
//! applying it with the core spinning on the page loads: nothing applied while cold, order kept, every copy identical
//! afterwards, and a repop whose loads never complete stays held (never applied or acked because time passed).
mod common;
use common::*;
use std::collections::BTreeMap;

fn kv(a: u8, b: u8, v: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
    (a..b).map(|i| (vec![b'k', i], vec![v; 4])).collect()
}

fn omap_of(s: &Sim, osd: i32) -> BTreeMap<Vec<u8>, Vec<u8>> {
    s.nodes[&osd].store.objects(spg(1, 0))[&hobj(1, "o")]
        .omap
        .clone()
}

fn setup(seed: u64) -> (Sim, Vec<i32>) {
    let mut s = cluster(seed, &[0, 1, 2], 1, 3, 2, 1);
    s.classic_all();
    let acting = s.acting_of(spg(1, 0).pgid);
    let t = s
        .write_ops(
            1,
            0,
            "o",
            &[EcOp::Touch, EcOp::OmapSet(kv(0, 10, 1))],
            Some(0),
        )
        .unwrap();
    s.wait_writes(&[t], spg(1, 0));
    (s, acting)
}

#[test]
fn cold_pages_hold_the_repop_in_order_then_it_applies() {
    let (mut s, acting) = setup(101);
    let slow = acting[2];
    s.nodes[&slow].store.warm_waits.set(5);
    let mut tids = vec![];
    for i in 0..4u8 {
        tids.push(
            s.write_ops(1, 0, "o", &[EcOp::OmapSet(kv(20 + i, 21 + i, i))], Some(0))
                .unwrap(),
        );
    }
    s.run_for(MS);
    assert_eq!(
        omap_of(&s, slow).len(),
        10,
        "nothing applied on the replica while its pages are cold"
    );
    s.wait_writes(&tids, spg(1, 0));
    s.run_for(500 * MS);
    assert_eq!(
        s.nodes[&slow].store.warm_waits.get(),
        0,
        "probes ran to warm"
    );
    let want = omap_of(&s, acting[0]);
    assert_eq!(want.len(), 14);
    for o in &acting {
        assert_eq!(omap_of(&s, *o), want, "osd.{o}");
    }
    assert!(s.classic_violations().is_empty());
}

/// Pages whose loads never complete (a stuck device) hold the repop: nothing applied, the client write not acked, never
/// applied because time passed; the hold is a slow op. When the loads complete, it applies and is acked.
#[test]
fn pages_that_never_load_hold_the_repop_until_they_do() {
    let (mut s, acting) = setup(102);
    let slow = acting[1];
    let pg = spg(1, 0);
    s.nodes[&slow].store.warm_waits.set(u32::MAX);
    let t = s
        .write_ops(1, 0, "o", &[EcOp::OmapSet(kv(30, 31, 9))], Some(0))
        .unwrap();
    s.run_for(2 * peering::REPOP_HELD_COMPLAINT_NS);
    assert!(!s.is_acked(pg, t), "no ack without the replica's commit");
    assert_eq!(
        omap_of(&s, slow).len(),
        10,
        "nothing applied on the replica"
    );
    let since = s.pg(slow, pg).unwrap().repops_held_since().expect("held");
    assert!(s.now - since >= peering::REPOP_HELD_COMPLAINT_NS);
    let (n, oldest) = s.nodes[&slow]
        .set
        .repops_held_slow(s.now, peering::REPOP_HELD_COMPLAINT_NS);
    assert_eq!((n, oldest), (1, s.now - since), "counts as a slow op");
    assert_eq!(
        s.nodes[&slow].store.leases.borrow().len(),
        1,
        "the held head keeps one residency lease (what its probes load stays resident)"
    );
    s.nodes[&slow].store.warm_waits.set(0);
    s.wait_writes(&[t], pg);
    let want = omap_of(&s, acting[0]);
    for o in &acting {
        assert_eq!(omap_of(&s, *o), want, "osd.{o}");
    }
    assert_eq!(want.len(), 11);
    for o in &acting {
        assert!(
            s.nodes[o].store.leases.borrow().is_empty(),
            "osd.{o}: the lease goes when the head applies"
        );
    }
}

#[test]
fn an_interval_change_releases_the_lease_of_a_held_repop() {
    // adr 0043 am. 18: the residency lease of a held head pins store memory; the op is gone with the interval
    let (mut s, acting) = setup(104);
    let slow = acting[1];
    s.nodes[&slow].store.warm_waits.set(u32::MAX);
    s.write_ops(1, 0, "o", &[EcOp::OmapSet(kv(50, 51, 9))], Some(0))
        .unwrap();
    s.run_for(100 * MS);
    assert_eq!(s.nodes[&slow].store.leases.borrow().len(), 1, "held");
    s.mark_down(acting[2]);
    s.run_for(100 * MS);
    assert!(
        s.nodes[&slow].store.leases.borrow().is_empty(),
        "the new interval released the old head's lease"
    );
    s.nodes[&slow].store.warm_waits.set(0);
}

#[test]
fn a_cold_log_head_holds_the_repop_like_cold_object_pages() {
    // `PgStoreOps::warm_log` (adr 0021 am. 30): the pgmeta page the entry is appended to is probed with the object pages
    let (mut s, acting) = setup(103);
    let slow = acting[2];
    s.nodes[&slow].store.log_waits.set(5);
    let mut tids = vec![];
    for i in 0..3u8 {
        tids.push(
            s.write_ops(1, 0, "o", &[EcOp::OmapSet(kv(40 + i, 41 + i, i))], Some(0))
                .unwrap(),
        );
    }
    s.run_for(MS);
    assert_eq!(
        omap_of(&s, slow).len(),
        10,
        "nothing applied on the replica while its log head is cold"
    );
    s.wait_writes(&tids, spg(1, 0));
    s.run_for(500 * MS);
    assert_eq!(
        s.nodes[&slow].store.log_waits.get(),
        0,
        "probes ran to warm"
    );
    assert!(s.nodes[&slow].store.log_calls.get() > 5);
    let want = omap_of(&s, acting[0]);
    assert_eq!(want.len(), 13);
    for o in &acting {
        assert_eq!(omap_of(&s, *o), want, "osd.{o}");
    }
    assert!(s.classic_violations().is_empty());
}

#[test]
fn held_repops_yield_after_one_persist_and_capacity_cannot_force_apply() {
    let (mut s, acting) = setup(104);
    let slow = acting[2];
    s.nodes[&slow].store.warm_waits.set(1_000_000);
    for i in 0..8u8 {
        s.write_ops(1, 0, "o", &[EcOp::OmapSet(kv(60 + i, 61 + i, i))], Some(0))
            .unwrap();
    }
    s.run_for(5 * MS);
    assert_eq!(omap_of(&s, slow).len(), 10);
    let now = s.now;
    let n = s.nodes.get_mut(&slow).unwrap();
    n.store.warm_waits.set(0);
    n.store.admission_paused.set(true);
    for _ in 0..1000 {
        let acts = n.set.retry_repops(now, &n.store);
        assert!(
            !acts
                .iter()
                .any(|a| matches!(a, peering::Action::Persist { .. }))
        );
    }
    n.store.admission_paused.set(false);
    let acts = n.set.retry_repops(now, &n.store);
    assert_eq!(
        acts.iter()
            .filter(|a| matches!(a, peering::Action::Persist { .. }))
            .count(),
        1,
        "driver must submit this persist and recheck capacity before the next held apply"
    );
    assert!(n.set.repops_waiting());
}

fn held(s: &Sim, osd: i32) -> usize {
    s.pg(osd, spg(1, 0)).map_or(0, |p| p.repops_held())
}

fn assert_copies_equal(s: &Sim, acting: &[i32], n: usize) {
    let want = omap_of(s, acting[0]);
    assert_eq!(want.len(), n);
    for o in acting {
        assert_eq!(omap_of(s, *o), want, "osd.{o}");
    }
}

/// A PG that leaves its core with a held head (merge strand / core move, `PgSet::detach`, adr 0636): the held queue and
/// its residency lease end with the old instance; no slow op stays counted.
#[test]
fn a_detached_pg_releases_its_held_queue_and_lease() {
    let (mut s, acting) = setup(110);
    let slow = acting[1];
    s.nodes[&slow].store.warm_waits.set(u32::MAX);
    s.write_ops(1, 0, "o", &[EcOp::OmapSet(kv(70, 71, 9))], Some(0))
        .unwrap();
    s.run_for(100 * MS);
    assert_eq!(held(&s, slow), 1);
    assert_eq!(s.nodes[&slow].store.leases.borrow().len(), 1, "held");
    assert!(s.nodes[&slow].set.repops_waiting());
    s.call(slow, |set, now, store| set.detach(now, spg(1, 0), store));
    assert!(
        s.nodes[&slow].store.leases.borrow().is_empty(),
        "the detach released the held head's lease"
    );
    assert!(!s.nodes[&slow].set.repops_waiting());
    assert_eq!(s.nodes[&slow].set.repops_held_slow(s.now, 0), (0, 0));
}

/// A replica killed while it holds repops (adr 0636): nothing of the queue was logged, applied or acked; the new interval
/// ends the writes at the primary (EAGAIN, the client resends; the entries stay in the surviving logs), and the restarted
/// replica recovers them.
#[test]
fn a_replica_killed_with_held_repops_recovers_them_after_restart() {
    let (mut s, acting) = setup(107);
    let slow = acting[2];
    let pg = spg(1, 0);
    s.nodes[&slow].store.warm_waits.set(u32::MAX);
    let tids: Vec<u64> = (0..4u8)
        .map(|i| {
            s.write_ops(1, 0, "o", &[EcOp::OmapSet(kv(80 + i, 81 + i, i))], Some(0))
                .unwrap()
        })
        .collect();
    s.run_for(100 * MS);
    assert_eq!(held(&s, slow), 4);
    assert_eq!(omap_of(&s, slow).len(), 10, "nothing applied while held");
    assert!(tids.iter().all(|t| !s.is_acked(pg, *t)));
    s.kill(slow);
    s.run_until(10_000 * MS, "writes ended", |s| {
        tids.iter().all(|t| {
            s.acked
                .iter()
                .chain(&s.failed)
                .any(|w| (w.0, w.1) == (pg, *t))
        })
    });
    s.nodes[&slow].store.warm_waits.set(0);
    s.restart(slow);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    assert_copies_equal(&s, &acting, 14);
    assert!(s.nodes[&slow].store.leases.borrow().is_empty());
    assert!(s.acks.acks > 0 && s.classic_violations().is_empty());
}

/// The primary's link to a replica that holds a repop partitions and heals (adr 0636): the later repops arrive in order
/// behind the held head, apply in log order once the loads complete, and are acked once each (Sim ack checker).
#[test]
fn repops_of_a_healed_link_queue_behind_the_held_head() {
    let (mut s, acting) = setup(108);
    let (p, slow) = (acting[0], acting[1]);
    let pg = spg(1, 0);
    s.nodes[&slow].store.warm_waits.set(u32::MAX);
    let mut tids = vec![
        s.write_ops(1, 0, "o", &[EcOp::OmapSet(kv(90, 91, 0))], Some(0))
            .unwrap(),
    ];
    s.run_for(50 * MS);
    assert_eq!(held(&s, slow), 1);
    s.partition(p, slow);
    for i in 1..4u8 {
        tids.push(
            s.write_ops(1, 0, "o", &[EcOp::OmapSet(kv(90 + i, 91 + i, i))], Some(0))
                .unwrap(),
        );
    }
    s.run_for(100 * MS);
    assert_eq!(held(&s, slow), 1, "the partition holds the later repops");
    s.heal_link(p, slow);
    s.run_for(50 * MS);
    assert_eq!(held(&s, slow), 4, "they queue behind the held head");
    assert_eq!(omap_of(&s, slow).len(), 10);
    s.nodes[&slow].store.warm_waits.set(0);
    s.wait_writes(&tids, pg);
    s.run_for(200 * MS);
    assert_eq!(held(&s, slow), 0);
    assert_copies_equal(&s, &acting, 14);
    assert!(s.acks.acks >= 8 && s.classic_violations().is_empty());
}

/// Duplicated repop deliveries (session replay, adr 0636) around held heads: a duplicate queues behind a held head like
/// any repop and is dropped when it reaches the head; never applied or acked twice (Sim ack checker).
#[test]
fn duplicated_repops_around_held_heads_are_acked_once() {
    let (mut s, acting) = setup(109);
    let slow = acting[2];
    s.dup_percent = 50;
    s.dup_kind = 2;
    s.nodes[&slow].store.warm_waits.set(20);
    let tids: Vec<u64> = (0..8u8)
        .map(|i| {
            s.write_ops(
                1,
                0,
                "o",
                &[EcOp::OmapSet(kv(100 + i, 101 + i, i))],
                Some(0),
            )
            .unwrap()
        })
        .collect();
    s.wait_writes(&tids, spg(1, 0));
    s.run_for(500 * MS);
    assert_eq!(
        s.nodes[&slow].store.warm_waits.get(),
        0,
        "probes ran to warm"
    );
    assert_eq!(held(&s, slow), 0);
    assert_copies_equal(&s, &acting, 18);
    assert!(s.acks.acks >= 16 && s.acks.violations.is_empty());
}

/// The queue bound (`REPOP_WAIT_MSGS`, adr 0636) forces the load verdict of the head: a replica whose loads never
/// complete still applies in order (one forced head per bound hit), the queue never exceeds the bound, and once the
/// loads complete every write completes with identical copies.
#[test]
fn the_queue_bound_forces_held_heads_whose_loads_never_complete() {
    let (mut s, acting) = setup(111);
    let slow = acting[1];
    let pg = spg(1, 0);
    s.nodes[&slow].store.warm_waits.set(u32::MAX);
    let n = 80u8;
    let tids: Vec<u64> = (0..n)
        .map(|i| {
            s.write_ops(
                1,
                0,
                &format!("b{i}"),
                &[EcOp::Touch, EcOp::Write(0, vec![i; 64])],
                Some(0),
            )
            .unwrap()
        })
        .collect();
    let mut most = 0;
    for _ in 0..500 {
        s.run_for(MS);
        most = most.max(held(&s, slow));
    }
    assert_eq!(
        most, 63,
        "the queue reached the bound (the 64th message forces the head) and never exceeded it"
    );
    assert!(
        s.is_acked(pg, tids[0]),
        "the forced head applied and was acked"
    );
    assert!(
        !s.is_acked(pg, tids[n as usize - 1]),
        "the rest waits for its loads"
    );
    s.nodes[&slow].store.warm_waits.set(0);
    s.wait_writes(&tids, pg);
    s.run_for(200 * MS);
    assert_eq!(held(&s, slow), 0);
    let objs = |o: i32| s.nodes[&o].store.objects(pg).len();
    for o in &acting {
        assert_eq!(objs(*o), objs(acting[0]), "osd.{o}");
    }
    assert!(s.classic_violations().is_empty());
}
