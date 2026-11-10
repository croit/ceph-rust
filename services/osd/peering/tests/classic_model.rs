// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Classic-peer model scenarios: randomized split/merge storms, interval churn, quick restarts, pg_temp/upmap changes
//! and reservation flags with classic OSDs in the acting sets. The model itself (tests/common/classic.rs, spec
//! doc/spec/classic-peer-model.md) fails a run at the first message that would abort a classic ceph-osd; it is on for
//! every Sim, these tests only drive the situations that expose such messages.
mod common;
use common::*;
use denc::types::PgT;
use std::collections::BTreeMap;

const POOL: u64 = 1;

/// Seeds per storm test (`STORM_N` overrides the default: bigger hunts without editing).
fn n(default: u64) -> u64 {
    std::env::var("STORM_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Settle the cluster after a storm: everything up, in, no overrides, no merge pending.
fn calm(s: &mut Sim, osds: &[i32]) {
    for o in osds {
        if !s.nodes[o].alive {
            s.restart(*o);
        }
    }
    s.new_epoch(|m| {
        for o in m.osds.values_mut() {
            o.in_ = true;
        }
        m.up_override.clear();
        m.pg_temp.clear();
        m.rb = Default::default();
        for p in m.pools.values_mut() {
            p.pg_num_pending = p.pg_num;
        }
    });
    let pgp = s.pool_pg_num(POOL);
    s.set_pgp_num(POOL, pgp);
}

fn settle(s: &mut Sim, seed: u64) {
    // Every message of the convergence runs through the checker; the pool must also settle (active+clean, merges and
    // splits done, nothing in flight): liveness of the PG machinery (found by the storms: placeholder history leak,
    // recovery message gating, map trimming). `STORM_LAX=1` = message verdicts only.
    s.run_for(20_000 * MS);
    if std::env::var("STORM_LAX").is_err() && !(s.pool_settled(POOL) && s.quiet()) {
        s.run_until(240_000 * MS, &format!("seed {seed}: pool settled"), |s| {
            s.pool_settled(POOL) && s.quiet()
        });
    }
}

#[derive(Clone, Copy)]
struct Knobs {
    /// Percent of storm steps that split.
    split: u64,
    merge: u64,
    kill: u64,
    out: u64,
    temp: u64,
    flags: u64,
}

const ALL: Knobs = Knobs {
    split: 12,
    merge: 12,
    kill: 12,
    out: 8,
    temp: 8,
    flags: 8,
};
const SPLIT_ONLY: Knobs = Knobs {
    split: 25,
    merge: 0,
    kill: 6,
    out: 0,
    temp: 0,
    flags: 0,
};
const MERGE_HEAVY: Knobs = Knobs {
    split: 8,
    merge: 30,
    kill: 8,
    out: 0,
    temp: 0,
    flags: 0,
};

/// `STORM_ALL=1`: a failing seed is reported (`FAILSEED n`) and the hunt goes on with the next one.
fn storm(
    seed: u64,
    osds: &[i32],
    classic: Option<&[i32]>,
    size: u32,
    steps: usize,
    k: Knobs,
) -> BTreeMap<String, u64> {
    if std::env::var("STORM_ALL").is_err() {
        return storm_run(seed, osds, classic, size, steps, k);
    }
    std::panic::catch_unwind(|| storm_run(seed, osds, classic, size, steps, k)).unwrap_or_else(
        |_| {
            eprintln!("FAILSEED {seed}");
            BTreeMap::new()
        },
    )
}

/// One randomized storm. `classic`: None = every OSD is a classic stand-in; Some = only these (the rest are croit-flashstore-osd).
fn storm_run(
    seed: u64,
    osds: &[i32],
    classic: Option<&[i32]>,
    size: u32,
    steps: usize,
    k: Knobs,
) -> BTreeMap<String, u64> {
    eprintln!("storm seed {seed}");
    if std::env::var("STORM_ONLY").is_ok_and(|v| v != seed.to_string()) {
        return BTreeMap::new();
    }
    let mut s = cluster(seed, osds, POOL, size, size.min(2), 4);
    if let Some(c) = classic {
        s.classic_set(c);
    }
    let mut rng = Rng::new(seed ^ 0x5151);
    if std::env::var("STORM_OFF").is_ok() {
        s.classic_off();
    }
    // jitter profile of this seed: slow shard queues / fast heartbeats are the dangerous ones
    if let Some(c) = s.classic.as_mut() {
        c.fatal = std::env::var("STORM_SOFT").is_err();
    }
    s.max_latency = rng.range(1, 6) * MS;
    let mut dead: Vec<i32> = vec![];
    let mut cnt = 0u32;
    for _ in 0..steps {
        let r = rng.range(0, 99);
        let n = s.pool_pg_num(POOL);
        let pend = s.map().pools[&POOL].pg_num_pending;
        let pgp = *s.map().pgp.get(&POOL).unwrap_or(&n);
        let mut acc = k.split;
        if r < acc {
            if n < 64 && pend == n {
                let target = (n + rng.range(1, n.max(2) as u64) as u32).min(64);
                s.set_pg_num(POOL, target);
            }
        } else if r < {
            acc += k.merge;
            acc
        } {
            if n > 2 && pend == n && pgp >= n - 1 {
                s.set_pgp_num(POOL, n - 1);
                s.begin_merge(POOL);
            } else if pgp < n {
                s.set_pgp_num(POOL, (pgp + 1 + rng.range(0, 3) as u32).min(n));
            }
        } else if r < {
            acc += k.kill;
            acc
        } {
            if !dead.is_empty() && rng.range(0, 1) == 0 {
                let o = dead.remove(rng.range(0, dead.len() as u64 - 1) as usize);
                s.restart(o);
            } else if dead.len() + 1 < osds.len() {
                let o = osds[rng.range(0, osds.len() as u64 - 1) as usize];
                if s.nodes[&o].alive {
                    s.kill(o);
                    dead.push(o);
                }
            }
        } else if r < {
            acc += k.out;
            acc
        } {
            let o = osds[rng.range(0, osds.len() as u64 - 1) as usize];
            if s.map().osds[&o].in_ {
                s.mark_out(o);
            } else {
                s.mark_in(o);
            }
        } else if r < {
            acc += k.temp;
            acc
        } {
            let pg = PgT::new(POOL, rng.range(0, n as u64 - 1) as u32);
            if rng.range(0, 2) == 0 {
                s.clear_up_override(pg);
            } else {
                let o = osds[rng.range(0, osds.len() as u64 - 1) as usize];
                s.set_up_override(pg, vec![o]);
            }
        } else if r < {
            acc += k.flags;
            acc
        } {
            s.new_epoch(|m| {
                m.rb.norecover = !m.rb.norecover;
                m.rb.nobackfill = !m.rb.nobackfill && rng.range(0, 1) == 0;
            });
        } else {
            for _ in 0..rng.range(1, 6) {
                cnt += 1;
                let name = format!("o{}", rng.range(0, 200));
                let len = rng.range(1, 400) as usize;
                let d: Vec<u8> = (0..len).map(|j| ((cnt as usize + j) % 251) as u8).collect();
                let _ = s.write_named(POOL, &name, &d);
            }
        }
        s.run_for(rng.range(0, 60) * MS);
    }
    calm(&mut s, osds);
    settle(&mut s, seed);
    for v in s.classic_violations() {
        eprintln!("{v}");
    }
    assert!(s.classic_violations().is_empty());
    if let Some(c) = s.classic.as_ref().filter(|_| size > 1) {
        assert!(
            c.checked > 100,
            "seed {seed}: only {} deliveries",
            c.checked
        );
    }
    let mut out = BTreeMap::new();
    if let Some(c) = s.classic.as_ref() {
        out.extend(c.cov.clone());
        out.extend(
            c.unchecked
                .iter()
                .map(|(k, v)| (format!("unchecked: {k}"), *v)),
        );
    }
    out
}

#[test]
fn storm_split_only_all_classic() {
    for seed in 0..n(12) {
        let _ = storm(1000 + seed, &[0, 1, 2, 3], None, 3, 40, SPLIT_ONLY);
    }
}

#[test]
fn storm_all_knobs_all_classic() {
    for seed in 0..n(12) {
        let _ = storm(2000 + seed, &[0, 1, 2, 3], None, 3, 50, ALL);
    }
}

#[test]
fn storm_merge_heavy_all_classic() {
    for seed in 0..n(8) {
        let _ = storm(3000 + seed, &[0, 1, 2, 3], None, 3, 50, MERGE_HEAVY);
    }
}

/// Mixed: osd.0 and osd.1 stand for croit-flashstore-osd, the rest are classic.
#[test]
fn storm_all_knobs_mixed() {
    for seed in 0..n(12) {
        let _ = storm(4000 + seed, &[0, 1, 2, 3, 4], Some(&[2, 3, 4]), 3, 50, ALL);
    }
}

/// Which cells of the state x event table the storms reach (run with --nocapture for the report). A cell that is never
/// reached is a gap of the scenarios, not of the table.
#[test]
fn table_coverage() {
    let mut cov: BTreeMap<String, u64> = BTreeMap::new();
    for seed in 0..10 {
        for (k, v) in storm(6000 + seed, &[0, 1, 2, 3], None, 3, 50, ALL) {
            *cov.entry(k).or_default() += v;
        }
        for (k, v) in storm(6100 + seed, &[0, 1, 2, 3, 4], Some(&[2, 3, 4]), 3, 50, ALL) {
            *cov.entry(k).or_default() += v;
        }
    }
    for (k, v) in &cov {
        eprintln!("COV {v:>8} {k}");
    }
    for must in [
        "Stray Query H",
        "Stray Log H",
        "RepNot Info H",
        "RepNot Lease H",
        "RepNot RrReq H",
        "ActOther Notify H",
        "ActOther Info H",
        "ActOther LeaseAck H",
        "GetInfo Notify H",
    ] {
        assert!(cov.contains_key(must), "cell never reached: {must}");
    }
}

/// Found by the model: the new primary of a split child that never held the parent (parent pinned elsewhere by pg_temp /
/// upmap, the child maps by CRUSH to us) is made by a peer's Notify in the split epoch. It had no gate (only local splits
/// made one) and queried the classic parent holders with the split epoch stamp: their child sits in Reset => abort.
#[test]
fn child_primary_without_the_parent_is_gated_too() {
    // storm seed found by the model (osd.1 croit-flashstore-osd child Notify created the child on croit-flashstore-osd osd.0, which then queried classic
    // osd.4 holding the parent): fails without `gate_created_child`
    let _ = storm(6107, &[0, 1, 2, 3, 4], Some(&[2, 3, 4]), 3, 50, ALL);
}

#[test]
fn storm_size_2_and_1() {
    for seed in 0..n(6) {
        let _ = storm(5000 + seed, &[0, 1, 2], Some(&[1, 2]), 2, 40, ALL);
        let _ = storm(5100 + seed, &[0, 1, 2], Some(&[1]), 1, 30, SPLIT_ONLY);
    }
}

/// Storm seeds that exposed a bug, each with the storm configuration it was found in (all settle strictly).
#[test]
fn storm_regressions() {
    let four = &[0, 1, 2, 3];
    // map trimming: a PG created from a message stamped with a trimmed epoch kept the sender's older interval start,
    // its peers discarded its pulls as old (primary stuck Recovering with unfound objects)
    let _ = storm(2012, four, None, 3, 50, ALL);
    // merge placeholder took the source's history les: no complete copy reached it, the merged PG stayed Incomplete
    let _ = storm(5018, &[0, 1, 2], Some(&[1, 2]), 2, 40, ALL);
    let _ = storm(3011, four, None, 3, 50, MERGE_HEAVY);
    // recovery data messages are stale by map_epoch only: a stray restarted after the primary's interval began must
    // serve the primary's Pull (an unfound object held by it never recovered)
    let _ = storm(4577, four, None, 3, 50, MERGE_HEAVY);
    // model gaps: a PG leaving ToDelete into a new interval where it is primary peers (GetInfo, not Stray); a pg_num
    // change that merges two OTHER PGs is no interval for this one
    let _ = storm(2387, four, None, 3, 50, ALL);
    let _ = storm(1464, four, None, 3, 40, SPLIT_ONLY);
    let _ = storm(2871, four, None, 3, 50, ALL);
    // a replica's GRANT crosses the primary's RELEASE (the RELEASE was parked for the map): not a new wait state
    let _ = storm(8891, &[0, 1, 2], Some(&[1, 2]), 2, 40, ALL);
    // a replica's REVOKE reached the primary in WaitRemoteRecoveryReserved: the primary deferred at once and the GRANT
    // of its request in flight reached it in WaitLocalRecoveryReserved (classic ignores that REVOKE)
    let _ = storm(4073, &[0, 1, 2, 3, 4], Some(&[2, 3, 4]), 3, 50, ALL);
}
