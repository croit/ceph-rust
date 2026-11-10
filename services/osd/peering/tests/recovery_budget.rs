// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `osd_recovery_max_active` is an OSD-wide budget (adr 0031 am. 10, spec replication.md 7.5): the recovery / backfill ops
//! in flight on one OSD never exceed it, whatever the number of PGs; every PG still recovers; a changed limit applies at
//! run time; no unit leaks.
mod common;
use common::*;
use std::collections::BTreeMap;

fn small_logs(c: &mut peering::Config) {
    c.min_pg_log_entries = 10;
    c.pg_log_trim_min = 1;
    c.pg_log_trim_max = 50;
    c.log_dups_tracked = 20;
    c.recovery_max_active = 2;
}

fn fill(s: &mut Sim, pg: u32, n: usize, tag: &str) -> BTreeMap<String, Vec<u8>> {
    let mut model = BTreeMap::new();
    let mut tids = vec![];
    for i in 0..n {
        let name = format!("{tag}{i}");
        let d: Vec<u8> = (0..100 + i * 13)
            .map(|j| ((i * 131 + j * 7) % 251) as u8)
            .collect();
        tids.push(s.write_obj(1, pg, &name, &d).expect("write accepted"));
        model.insert(name, d);
        s.run_for(MS / 2);
    }
    s.wait_writes(&tids, spg(1, pg));
    model
}

fn max_ops(s: &Sim) -> usize {
    s.nodes
        .values()
        .map(|n| n.set.rec_ops().0)
        .max()
        .unwrap_or(0)
}

/// 8 PGs recover (log recovery and backfill, small logs) onto a restarted OSD with `recovery_max_active` 2: no OSD ever has
/// more than 2 ops in flight, the budget is used (2 reached), everything converges and nothing is left behind.
#[test]
fn recovery_ops_are_bounded_per_osd() {
    let mut s = cluster_cfg(91, &[0, 1, 2], 1, 3, 2, 8, small_logs);
    let mut model = BTreeMap::new();
    for pg in 0..8u32 {
        model.insert(pg, fill(&mut s, pg, 3, &format!("p{pg}_")));
    }
    s.kill(2);
    s.run_for(300 * MS);
    for pg in 0..8u32 {
        model
            .get_mut(&pg)
            .unwrap()
            .extend(fill(&mut s, pg, 40, &format!("q{pg}_")));
    }
    s.restart(2);
    let (mut peak, end) = (0, s.now + 200_000 * MS);
    while s.now < end && !s.pool_clean(1) {
        s.run_for(MS / 4);
        peak = peak.max(max_ops(&s));
        assert!(
            max_ops(&s) <= 2,
            "{} recovery ops in flight on one OSD, limit 2",
            max_ops(&s)
        );
    }
    assert!(s.pool_clean(1), "{}", s.dump());
    assert_eq!(peak, 2, "the budget is used");
    s.run_for(2_000 * MS);
    for n in s.nodes.values() {
        assert_eq!(n.set.rec_ops().0, 0, "ops left behind");
        assert_eq!(n.set.rec_held(), 0, "recovery units leaked");
    }
    for (pg, m) in model {
        s.assert_replicas_equal(1, pg, &m);
    }
}

/// A raised `osd_recovery_max_active` applies to a recovery in progress, a lowered one is reached as ops finish.
#[test]
fn runtime_change_applies() {
    let mut s = cluster_cfg(92, &[0, 1, 2], 1, 3, 2, 8, small_logs);
    for pg in 0..8u32 {
        fill(&mut s, pg, 3, &format!("p{pg}_"));
    }
    s.kill(2);
    s.run_for(300 * MS);
    for pg in 0..8u32 {
        fill(&mut s, pg, 60, &format!("q{pg}_"));
    }
    s.restart(2);
    let mut peak_low = 0;
    for _ in 0..200 {
        s.run_for(MS / 4);
        peak_low = peak_low.max(max_ops(&s));
    }
    assert!(peak_low <= 2, "limit 2, saw {peak_low}");
    for n in s.nodes.values_mut() {
        n.set.set_recovery_max_active(6);
    }
    let (mut peak_high, end) = (0, s.now + 200_000 * MS);
    while s.now < end && !s.pool_clean(1) && peak_high < 3 {
        s.run_for(MS / 4);
        peak_high = peak_high.max(max_ops(&s));
        assert!(max_ops(&s) <= 6);
    }
    assert!(
        peak_high > 2,
        "the raised limit was never used (peak {peak_high})"
    );
    for n in s.nodes.values_mut() {
        n.set.set_recovery_max_active(1);
    }
    s.run_until(200_000 * MS, "clean", |s| s.pool_clean(1));
}

/// PG-L4: `osd_recovery_sleep` paces recovery invocations OSD-wide: after an op started, the next one waits the sleep
/// interval, even though the op budget has room. The default (mclock/`_ssd` 0) is no pacing.
#[test]
fn recovery_sleep_paces_the_next_invocation() {
    let mut s = cluster_cfg(93, &[0, 1, 2], 1, 3, 2, 1, |c| {
        small_logs(c);
        c.recovery_max_active = 1;
        c.recovery_sleep = 2_000_000_000;
        c.recovery_sleep_degraded = 2_000_000_000;
    });
    fill(&mut s, 0, 3, "a");
    s.kill(2);
    s.run_for(300 * MS);
    fill(&mut s, 0, 40, "b");
    let push = replwire::ty::PUSH;
    let pushes = |s: &Sim| s.stats.msgs_by_type.get(&push).copied().unwrap_or(0);
    s.restart(2);
    s.run_until(120_000 * MS, "first recovery op", |s| pushes(s) > 0);
    let n0 = pushes(&s);
    // the quiet window covers the first op's commit: a second invocation must not start
    s.run_for(1_500 * MS);
    assert_eq!(pushes(&s), n0, "no new recovery op inside the sleep");
    s.run_for(1_000 * MS);
    assert!(pushes(&s) > n0, "the next invocation runs after the sleep");
    s.run_until(180_000 * MS, "clean", |s| s.pool_clean(1));
}
