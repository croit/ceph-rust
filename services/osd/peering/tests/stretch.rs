// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Stretch pools (doc/spec/stretch.md): the oracle scenarios (sec 9) in the simulator. Layout = the oracle's: osd.0/1
//! in dc1 (-3), osd.2/3 in dc2 (-10), barrier type datacenter (8).
mod common;
use common::*;
use denc::types::PgT;
use pgwire::NONE_OSD;
use pgwire::state as pgs;
use std::collections::BTreeMap;

const POOL: u64 = 1;
const DC1: i32 = -3;
const DC2: i32 = -10;

fn sites(s: &mut Sim) {
    s.new_epoch(|m| m.barrier = BTreeMap::from([(0, DC1), (1, DC1), (2, DC2), (3, DC2)]));
}

/// `osd pool stretch set` / the mon's stretch mode transitions: one map with the pool's stretch fields.
fn set_stretch(s: &mut Sim, count: u32, member: i32, min_size: Option<u32>) -> u32 {
    s.new_epoch(|m| {
        let p = m.pools.get_mut(&POOL).unwrap();
        p.crush_rule = 1;
        p.peering_crush_bucket_count = count;
        p.peering_crush_bucket_target = 2;
        p.peering_crush_bucket_barrier = 8;
        p.peering_crush_mandatory_member = member;
        if let Some(x) = min_size {
            p.min_size = x;
        }
    })
}

/// P0: replicated size 4 / min_size 2 over both sites, then made a stretch pool (C 2, Tg 2).
fn rep_stretch(seed: u64) -> Sim {
    let mut s = Sim::new(seed);
    for o in 0..4 {
        s.add_osd(o);
    }
    sites(&mut s);
    s.run_for(50 * MS);
    s.create_pool(POOL, 4, 2, 8);
    s.run_until(60_000 * MS, "pool clean", |s| s.pool_clean(POOL));
    set_stretch(&mut s, 2, NONE_OSD, None);
    s.run_until(60_000 * MS, "stretch pool clean", |s| s.pool_clean(POOL));
    s
}

fn ec_stretch(seed: u64, opt: bool) -> Sim {
    let mut s = Sim::new(seed);
    for o in 0..4 {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_enable_optimized = ec::EcEnable::All;
            c.ec_primary = true;
            c.ec_opt_primary = true;
        });
    }
    sites(&mut s);
    s.run_for(50 * MS);
    if opt {
        s.create_pool_ec_opt(POOL, 2, 2, 4096, true, 4);
    } else {
        s.create_pool_ec(POOL, 2, 2, 4096, true, 4);
    }
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    s
}

/// Every PG's primary and acting members run the current map's acting set, finished peering, with `bit` set.
fn all_members(s: &Sim, bit: u64) -> bool {
    let map = s.map();
    let n = map.pools[&POOL].pg_num;
    (0..n).all(|seed| {
        let mp = peering::PgMapView::pg_mapping(&*map, PgT::new(POOL, seed));
        mp.acting_primary >= 0
            && mp.acting.iter().filter(|o| **o != NONE_OSD).all(|o| {
                s.pg(*o, s.spg_on(*o, POOL, seed)).is_some_and(|p| {
                    p.acting() == mp.acting.as_slice()
                        && p.map_epoch() == map.epoch
                        && p.state_bits() & bit != 0
                        && p.state_bits() & pgs::PEERING == 0
                })
            })
    })
}

fn assert_none_active(s: &Sim) {
    let map = s.map();
    for seed in 0..map.pools[&POOL].pg_num {
        let mp = peering::PgMapView::pg_mapping(&*map, PgT::new(POOL, seed));
        for o in mp.acting.iter().filter(|o| **o != NONE_OSD) {
            let p = s.pg(*o, s.spg_on(*o, POOL, seed)).unwrap();
            assert_eq!(
                p.state_bits() & pgs::ACTIVE,
                0,
                "pg {seed} on osd.{o}: {}",
                p.state_string()
            );
        }
    }
}

fn wait_peered(s: &mut Sim, why: &str) {
    s.run_until(60_000 * MS, why, |s| all_members(s, pgs::PEERED));
    // stays peered: nothing moves it to ACTIVE within the interval
    s.run_for(3000 * MS);
    assert!(all_members(s, pgs::PEERED), "{why}: left PEERED");
    assert_none_active(s);
}

fn wait_active(s: &mut Sim, why: &str) {
    s.run_until(60_000 * MS, why, |s| all_members(s, pgs::ACTIVE));
}

/// P1: one site down. acting [0,1] meets min_size 2 but spans one site: PEERED on primary AND replica, les not
/// advanced, client writes refused (stretch.md 3.2-3.4).
#[test]
fn p1_one_site_stays_peered() {
    let mut s = rep_stretch(1);
    let les_before: Vec<u32> = (0..8)
        .map(|seed| {
            let p = s.primary_of(PgT::new(POOL, seed));
            s.pg(p, spg(POOL, seed)).unwrap().info().last_epoch_started
        })
        .collect();
    s.new_epoch(|m| {
        m.osds.get_mut(&2).unwrap().up = false;
        m.osds.get_mut(&3).unwrap().up = false;
    });
    wait_peered(&mut s, "P1 peered");
    for seed in 0..8 {
        let p = s.primary_of(PgT::new(POOL, seed));
        let pg = s.pg(p, spg(POOL, seed)).unwrap();
        assert_eq!(
            pg.info().last_epoch_started,
            les_before[seed as usize],
            "pg {seed}: les advanced"
        );
        assert!(
            s.write_obj(POOL, seed, "p1", b"x").is_err(),
            "pg {seed}: write accepted"
        );
    }
}

/// P2: the same with C 1: ACTIVE (undersized), writes work.
#[test]
fn p2_count_one_goes_active() {
    let mut s = rep_stretch(2);
    s.new_epoch(|m| {
        m.osds.get_mut(&2).unwrap().up = false;
        m.osds.get_mut(&3).unwrap().up = false;
    });
    wait_peered(&mut s, "P1 peered");
    set_stretch(&mut s, 1, NONE_OSD, None);
    wait_active(&mut s, "P2 active");
    let tid = s.write_obj(POOL, 0, "p2", b"x").unwrap();
    s.wait_writes(&[tid], spg(POOL, 0));
}

/// P3: C 3 > 2 sites with every OSD up: PEERED forever; back to C 2: active+clean.
#[test]
fn p3_count_above_sites_peered_with_all_up() {
    let mut s = rep_stretch(3);
    set_stretch(&mut s, 3, NONE_OSD, None);
    wait_peered(&mut s, "P3 peered");
    assert!(s.write_obj(POOL, 1, "p3", b"x").is_err());
    set_stretch(&mut s, 2, NONE_OSD, None);
    s.run_until(60_000 * MS, "P3 back clean", |s| s.pool_clean(POOL));
}

/// M1/M2: stretch mode degraded = C 1 + mandatory surviving site + min_size 1: ACTIVE on the surviving site; a
/// mandatory member that is the lost site keeps it PEERED.
#[test]
fn m2_degraded_mandatory_member() {
    let mut s = rep_stretch(4);
    s.new_epoch(|m| {
        m.osds.get_mut(&2).unwrap().up = false;
        m.osds.get_mut(&3).unwrap().up = false;
    });
    wait_peered(&mut s, "M1 peered");
    set_stretch(&mut s, 1, DC2, Some(1));
    wait_peered(&mut s, "mandatory = lost site");
    set_stretch(&mut s, 1, DC1, Some(1));
    wait_active(&mut s, "M2 active");
    let tid = s.write_obj(POOL, 3, "m2", b"x").unwrap();
    s.wait_writes(&[tid], spg(POOL, 3));
    // M3: site back, healthy again
    s.new_epoch(|m| {
        for o in [2, 3] {
            let e = m.epoch;
            let x = m.osds.get_mut(&o).unwrap();
            x.up = true;
            x.up_from = e;
        }
    });
    set_stretch(&mut s, 2, NONE_OSD, Some(2));
    s.run_until(60_000 * MS, "M3 clean", |s| s.pool_clean(POOL));
}

/// EC (legacy and optimized, stretch.md 8.1): same writeable rule; a NONE hole adds bucket 0.
fn ec_rules(opt: bool, seed: u64) {
    let mut s = ec_stretch(seed, opt);
    // C 3 > 2 sites with all up: PEERED
    set_stretch(&mut s, 3, NONE_OSD, Some(2));
    wait_peered(&mut s, "EC C3 peered");
    // C 2: active again
    set_stretch(&mut s, 2, NONE_OSD, Some(2));
    wait_active(&mut s, "EC C2 active");
    // C 1 with a mandatory site that holds no member of the acting set: PEERED
    s.new_epoch(|m| m.barrier = BTreeMap::from([(0, DC1), (1, DC1), (2, DC1), (3, DC1)]));
    set_stretch(&mut s, 1, DC2, Some(2));
    wait_peered(&mut s, "EC mandatory missing");
    set_stretch(&mut s, 1, DC1, Some(2));
    wait_active(&mut s, "EC mandatory present");
}

#[test]
fn ec_legacy_writeable_rule() {
    ec_rules(false, 5);
}

#[test]
fn ec_optimized_writeable_rule() {
    ec_rules(true, 6);
}

/// Replicated acting choice (stretch.md 4): sites A = {0,1,2}, B = {3,4,5}; the (empty) PG lived on [0,1,2,3], then
/// CRUSH moves it to [0,4] (4 is usable: nothing was written). Plain choice fills with strays 1,2 in osd order = three
/// members in A; the stretch choice breaks the 1:1 tie towards the later head (3, in B), then fills A to its cap 2.
#[test]
fn acting_choice_caps_per_site() {
    let mut s = Sim::new(7);
    for o in 0..6 {
        s.add_osd(o);
    }
    s.new_epoch(|m| {
        m.barrier = BTreeMap::from([(0, DC1), (1, DC1), (2, DC1), (3, DC2), (4, DC2), (5, DC2)])
    });
    let pg = PgT::new(POOL, 0);
    s.set_up_override(pg, vec![0, 1, 2, 3]);
    s.run_for(50 * MS);
    s.create_pool(POOL, 4, 2, 1);
    s.run_until(60_000 * MS, "pool clean", |s| s.pool_clean(POOL));
    set_stretch(&mut s, 2, NONE_OSD, None);
    s.run_until(60_000 * MS, "stretch pool clean", |s| s.pool_clean(POOL));
    s.new_epoch(|m| {
        m.rb.nobackfill = true;
        m.up_override.insert(pg, vec![0, 4]);
    });
    s.run_until(60_000 * MS, "remapped acting", |s| {
        s.map().pg_temp.contains_key(&pg) && all_members(s, pgs::ACTIVE)
    });
    s.run_for(3000 * MS);
    assert_eq!(s.acting_of(pg), vec![0, 4, 3, 1]);
    assert!(all_members(&s, pgs::ACTIVE));
}

/// Async recovery (stretch.md 5): the only member of site B is behind; removing it from the acting set would leave one
/// site (can_peer false), so it stays in (synchronous recovery) and the PG goes ACTIVE.
#[test]
fn async_recovery_keeps_the_last_member_of_a_site() {
    let mut s = Sim::new(8);
    for o in 0..4 {
        s.add_osd_cfg(o, |c| c.async_recovery_min_cost = 1);
    }
    sites(&mut s);
    s.run_for(50 * MS);
    s.create_pool(POOL, 4, 2, 4);
    s.run_until(60_000 * MS, "pool clean", |s| s.pool_clean(POOL));
    set_stretch(&mut s, 2, NONE_OSD, None);
    s.run_until(60_000 * MS, "stretch pool clean", |s| s.pool_clean(POOL));
    s.new_epoch(|m| {
        m.osds.get_mut(&2).unwrap().up = false;
        m.osds.get_mut(&3).unwrap().up = false;
    });
    wait_peered(&mut s, "one site");
    set_stretch(&mut s, 1, NONE_OSD, None);
    wait_active(&mut s, "C 1");
    for seed in 0..4 {
        let tids: Vec<u64> = (0..5)
            .map(|i| {
                s.write_obj(POOL, seed, &format!("o{seed}-{i}"), b"payload")
                    .unwrap()
            })
            .collect();
        s.wait_writes(&tids, spg(POOL, seed));
    }
    s.new_epoch(|m| {
        m.rb.norecover = true;
        let e = m.epoch;
        let x = m.osds.get_mut(&2).unwrap();
        x.up = true;
        x.up_from = e;
        let p = m.pools.get_mut(&POOL).unwrap();
        p.peering_crush_bucket_count = 2;
    });
    wait_active(&mut s, "site B member kept");
    for seed in 0..4 {
        assert!(s.acting_of(PgT::new(POOL, seed)).contains(&2), "pg {seed}");
    }
}
