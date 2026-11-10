// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Read lease across OSD restarts (fresh per-process monotonic clocks) and the LAGGY diagnostics (peering.md 8.2).
mod common;
use common::*;
use denc::types::PgT;
use peering::Mono;
use pgwire::state as pgs;
use std::collections::BTreeMap;

const OSDS: [i32; 3] = [0, 1, 2];

/// Longest stretch (ms) an active primary PG of pool 1 was not readable on its own clock, sampled every 100 ms for
/// `dur`, with a write to every PG per sample.
fn worst_unreadable(s: &mut Sim, dur: Mono, pg_num: u32) -> (u64, String) {
    let mut since: BTreeMap<u32, Mono> = BTreeMap::new();
    let mut worst = (0, String::new());
    let end = s.now + dur;
    let mut i = 0usize;
    while s.now < end {
        for seed in 0..pg_num {
            let _ = s.write_obj(1, seed, &format!("o{}", i % 50), &[i as u8; 64]);
        }
        i += 1;
        s.run_for(100 * MS);
        for seed in 0..pg_num {
            let prim = s.primary_of(PgT::new(1, seed));
            let now = s.node_now(prim);
            let p = s.pg(prim, s.lead_spg(1, seed));
            if p.is_some_and(|p| p.state_bits() & pgs::ACTIVE != 0 && !p.is_readable(now)) {
                let t0 = *since.entry(seed).or_insert(s.now);
                if s.now - t0 > worst.0 {
                    worst = (s.now - t0, format!("pg 1.{seed:x} on osd.{prim}"));
                }
            } else {
                since.remove(&seed);
            }
        }
    }
    (worst.0 / MS, worst.1)
}

/// Every OSD restarts (crash + boot with a new process clock) under writes: no active primary loses its lease.
#[test]
fn restart_with_fresh_clocks_keeps_primaries_readable() {
    for seed in 1..3u64 {
        for victim in OSDS {
            let pg_num = 8;
            let mut s = cluster(seed, &OSDS, 1, 3, 2, pg_num);
            s.fresh_clocks = true;
            for o in OSDS {
                s.call(o, |set, _, _| {
                    set.set_flashstore_peers(OSDS.into_iter().collect())
                });
            }
            s.run_for(20_000 * MS);
            s.kill(victim);
            s.run_for(3_000 * MS);
            s.restart(victim);
            assert!(
                s.node_now(victim) < s.node_now((victim + 1) % 3),
                "fresh clock"
            );
            let (w, what) = worst_unreadable(&mut s, 60_000 * MS, pg_num);
            assert!(
                w <= 200,
                "seed {seed} victim osd.{victim}: {what} unreadable for {w} ms\n{}",
                s.dump()
            );
        }
    }
}

/// A PG that loses its lease logs why (renewal age, per-peer ack age) and how long it stayed LAGGY.
#[test]
fn laggy_episode_is_logged_with_peer_ack_ages() {
    let mut s = cluster(14, &OSDS, 1, 3, 2, 1);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let mute = s
        .acting_of(pg.pgid)
        .into_iter()
        .find(|o| *o != prim)
        .unwrap();
    s.run_for(2_000 * MS);
    let _ = s.nodes.get_mut(&prim).unwrap().set.take_notices();
    s.block_all_from.insert(mute);
    s.run_for(20_000 * MS);
    assert!(s.pg(prim, pg).unwrap().state_bits() & pgs::LAGGY != 0);
    let notes = s
        .nodes
        .get_mut(&prim)
        .unwrap()
        .set
        .take_notices()
        .join("\n");
    assert!(
        notes.contains("laggy (readable until -")
            && notes.contains("renewal sent")
            && notes.contains(&format!("osd.{mute} ")),
        "{notes}"
    );
    s.heal();
    s.run_for(10_000 * MS);
    assert!(s.pg(prim, pg).unwrap().is_readable(s.now));
    assert_eq!(s.pg(prim, pg).unwrap().state_bits() & pgs::LAGGY, 0);
    let notes = s
        .nodes
        .get_mut(&prim)
        .unwrap()
        .set
        .take_notices()
        .join("\n");
    assert!(notes.contains("laggy cleared after"), "{notes}");
}

/// A replica that hears the primary's renewals late logs the gap (forward path), the primary logs the acks it misses.
#[test]
fn late_lease_is_logged_on_the_replica() {
    let mut s = cluster(15, &OSDS, 1, 3, 2, 1);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let rep = s
        .acting_of(pg.pgid)
        .into_iter()
        .find(|o| *o != prim)
        .unwrap();
    s.run_for(10_000 * MS);
    let _ = s.nodes.get_mut(&rep).unwrap().set.take_notices();
    s.partition(prim, rep);
    s.run_for(20_000 * MS);
    s.heal();
    s.run_for(2_000 * MS);
    let notes = s.nodes.get_mut(&rep).unwrap().set.take_notices().join("\n");
    assert!(
        notes.contains(&format!("lease from osd.{prim} ")),
        "{notes}"
    );
    assert!(s.pg(prim, pg).unwrap().is_readable(s.node_now(prim)));
}

/// Time (ms) from now until the new primary of pool 1 / PG 0 (not `old`) is readable on its own clock.
fn ms_until_new_primary_readable(s: &mut Sim, old: i32) -> u64 {
    let t0 = s.now;
    s.run_until(40_000 * MS, "new primary readable", |s| {
        let p = s.primary_of(PgT::new(1, 0));
        p != old
            && s.pg(p, s.lead_spg(1, 0))
                .is_some_and(|x| x.is_readable(s.node_now(p)))
    });
    (s.now - t0) / MS
}

/// A primary marked down while it still runs (`osd down` under noup, a heartbeat false positive) may serve reads until
/// its lease runs out: the new primary holds WAIT for the prior bound. Once that OSD marked itself dead
/// (MOSDMarkMeDead -> osd_xinfo.dead_epoch > up_from) nothing can be read under the old lease and WAIT ends with that
/// map (peering.md 8.2 prior_readable_down_osds).
#[test]
fn dead_prior_primary_ends_wait_early() {
    let mut waited = [0u64; 2];
    for (i, dead) in [false, true].into_iter().enumerate() {
        let mut s = cluster(21, &OSDS, 1, 3, 2, 1);
        s.run_for(5_000 * MS);
        let old = s.primary_of(PgT::new(1, 0));
        s.mark_down(old);
        if dead {
            s.run_for(300 * MS);
            s.new_epoch(|m| {
                let e = m.epoch;
                m.osds.get_mut(&old).unwrap().dead_epoch = e;
            });
        }
        waited[i] = ms_until_new_primary_readable(&mut s, old);
        let p = s.primary_of(PgT::new(1, 0));
        assert_eq!(
            s.pg(p, s.lead_spg(1, 0)).unwrap().state_bits() & pgs::WAIT,
            0
        );
    }
    // default lease 16 s, renewed every 8 s: the alive-but-down primary's promise reaches >= 8 s past the down mark
    assert!(waited[0] >= 6_000, "no dead mark: waited {} ms", waited[0]);
    assert!(
        waited[1] <= 2_000,
        "dead mark: waited {} ms (no dead mark: {})",
        waited[1],
        waited[0]
    );
}

/// The pool option `read_lease_interval` sets the lease length of its PGs (classic: pool option, else
/// osd_heartbeat_grace x osd_pool_default_read_lease_ratio): the WAIT after losing an alive primary is bounded by it.
#[test]
fn pool_read_lease_interval_bounds_the_wait() {
    let mut s = cluster(22, &OSDS, 1, 3, 2, 1);
    s.new_epoch(|m| m.pools.get_mut(&1).unwrap().read_lease_ns = Some(2_000 * MS));
    // promises made under the old 16 s lease stay binding until they run out
    s.run_for(20_000 * MS);
    let old = s.primary_of(PgT::new(1, 0));
    s.mark_down(old);
    let w = ms_until_new_primary_readable(&mut s, old);
    assert!(w <= 2_500, "lease 2 s: waited {w} ms");
}
