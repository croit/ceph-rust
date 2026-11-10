// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! A primary that starts a new interval with sub-writes still unanswered reports each of them
//! (`Action::SubWritesAborted`: peer, its shard, tid): the driver returns their repop credits on that event (adr 0084
//! am. 5), there is no expiry timer. Answered sub-writes are not reported; replicated and EC alike.
mod common;
use common::*;

const POOL: u64 = 1;

/// A new interval with the same members and roles: the pool's min_size changes.
fn new_interval(s: &mut Sim) {
    s.new_epoch(|m| {
        let p = m.pools.get_mut(&POOL).unwrap();
        p.min_size = if p.min_size == 2 { 3 } else { 2 };
    });
}

/// One member cannot hear the primary while a write is in flight; then a new interval. Exactly the sub-write that
/// member never answered is reported, once, at the interval change.
fn unanswered_sub_write_is_reported(s: &mut Sim, data: &[u8]) {
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let acting = s.acting_of(lead.pgid);
    let lost = acting[2];
    assert_ne!(lost, prim);
    let t0 = s.write_obj(POOL, 0, "a", data).unwrap();
    s.wait_writes(&[t0], lead);
    s.run_for(100 * MS);
    assert!(
        s.subwrites_aborted.is_empty(),
        "answered sub-writes are never reported"
    );
    s.partition(prim, lost);
    let t = s.write_obj(POOL, 0, "b", data).unwrap();
    s.run_for(200 * MS);
    assert!(
        !s.is_acked(lead, t),
        "the write waits for the partitioned member"
    );
    assert!(
        s.subwrites_aborted.is_empty(),
        "nothing is aborted without a new interval"
    );
    new_interval(s);
    s.run_for(50 * MS);
    assert_eq!(
        s.subwrites_aborted,
        vec![(lost, s.spg_on(lost, POOL, 0), t)],
        "exactly the unanswered sub-write (the other member answered)"
    );
    s.heal();
    s.run_until(10_000 * MS, "pool clean", |s| {
        s.quiet() && s.pool_clean(POOL)
    });
}

#[test]
fn unanswered_replicated_sub_writes_are_reported_at_the_new_interval() {
    let mut s = cluster(91, &[0, 1, 2], POOL, 3, 2, 1);
    unanswered_sub_write_is_reported(&mut s, b"payload");
}

#[test]
fn unanswered_ec_sub_writes_are_reported_at_the_new_interval() {
    let mut s = Sim::new(92);
    for o in [0, 1, 2] {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_primary = true;
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec(POOL, 2, 1, 4096, true, 1);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    // a full stripe: every shard gets a sub-write
    unanswered_sub_write_is_reported(&mut s, &[5u8; 8192]);
}
