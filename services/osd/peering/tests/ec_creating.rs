// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! New EC pools whose PGs are led by an croit-flashstore-osd primary with shard-only (classic stand-in) peers: every PG must
//! leave `creating` without any further map (lab-c case 16: one PG of a new pool stayed in GetInfo ~10 min).
mod common;
use common::*;
use denc::types::PgT;

fn run(seed: u64, pools: u64, churn: bool) {
    let mut s = Sim::new(seed);
    for o in 0..6 {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_primary = o < 2;
        });
    }
    s.run_for(50 * MS);
    for p in 1..=pools {
        for pg in 0..4u32 {
            // an croit-flashstore-osd (osd.0/1) leads, shard-only OSDs hold the rest
            let lead = (pg % 2) as i32;
            let up = vec![lead, 2 + (pg as i32) % 4, 2 + (pg as i32 + 1) % 4];
            s.set_up_override(PgT::new(p, pg), up);
        }
        s.create_pool_ec(p, 2, 1, 4096, true, 4);
        if churn {
            s.run_for(((seed + p) % 7) * 3 * MS);
        }
    }
    for p in 1..=pools {
        s.run_until(30_000 * MS, &format!("pool {p} clean (seed {seed})"), |s| {
            s.pool_clean(p)
        });
    }
}

#[test]
fn new_ec_pools_with_shard_only_peers_leave_creating() {
    for seed in 0..40 {
        run(seed, 4, false);
        run(seed + 100, 4, true);
    }
}
