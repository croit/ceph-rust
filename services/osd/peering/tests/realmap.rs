// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The real OsdMap adapter and a cluster whose PG placement comes from a real decoded OsdMap
//! (reference lab map: 3 OSDs, pools with 32 PGs).
mod common;
use common::*;
use denc::types::PgT;
use peering::synth::SynthMap;
use peering::{PgMapView, RealMap};
use pgwire::OsdMapView;
use std::sync::Arc;

fn real() -> Arc<osdmap::OsdMap> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/osdmap/full/0091.bin");
    Arc::new(osdmap::OsdMap::decode_from(&std::fs::read(p).unwrap()).unwrap())
}

#[test]
fn real_map_adapter_matches_osdmap() {
    let m = real();
    let rm = RealMap::new(m.clone());
    assert_eq!(rm.epoch(), 91);
    for o in 0..m.max_osd {
        assert_eq!(rm.is_up(o), m.is_up(o));
        assert_eq!(rm.exists(o), m.exists(o));
        assert_eq!(rm.up_from(o), m.osd_info[o as usize].up_from);
        assert_eq!(rm.up_thru(o), m.osd_info[o as usize].up_thru);
        assert_eq!(rm.lost_at(o), 0);
    }
    assert!(!rm.exists(99) && !rm.is_up(-1));
    for (id, p) in &m.pools {
        let pp = rm.pool(*id as u64).unwrap();
        assert_eq!(
            (pp.size, pp.min_size, pp.pg_num),
            (p.size as u32, p.min_size as u32, p.pg_num)
        );
        assert_eq!(pp.is_erasure, p.ptype == osdmap::pool::TYPE_ERASURE);
        for seed in 0..p.pg_num {
            let pg = PgT::new(*id as u64, seed);
            let want = m.pg_to_up_acting(pg);
            // the per-op placement check, before (computed) and after (memoized) the full mapping
            for o in -1..=m.max_osd {
                let pos = (
                    want.acting.iter().position(|&x| x == o),
                    want.acting_primary,
                );
                assert_eq!(rm.acting_pos(pg, o), pos, "{pg} osd.{o}");
            }
            let got = rm.pg_mapping(pg);
            assert_eq!(rm.acting_pos(pg, got.acting_primary).1, got.acting_primary);
            assert_eq!(
                (got.up, got.up_primary, got.acting, got.acting_primary),
                (want.up, want.up_primary, want.acting, want.acting_primary)
            );
        }
    }
    assert!(rm.pool(1234).is_none());
    assert!(rm.flags().sortbitwise);
}

/// PG placement of pool 1 (32 PGs, size 3) from the real CRUSH mapping; everything else is the
/// simulator. All 32 PGs must reach active+clean and replicate writes.
#[test]
fn cluster_on_real_crush_placement() {
    let m = real();
    let rm = RealMap::new(m.clone());
    let mut s = Sim::new(77);
    for o in 0..3 {
        s.add_osd(o);
    }
    s.run_for(50 * MS);
    // pin the real placement via up_override, then create the pool
    let mut overrides = Vec::new();
    for seed in 0..32 {
        let pg = PgT::new(1, seed);
        overrides.push((pg, rm.pg_mapping(pg).up));
    }
    s.new_epoch(|sm: &mut SynthMap| {
        for (pg, up) in overrides {
            sm.up_override.insert(pg, up);
        }
    });
    s.create_pool(1, 3, 2, 32);
    s.run_until(120_000 * MS, "all 32 pgs clean", |s| s.pool_clean(1));
    // primaries are spread like the real mapping
    let mut per_osd = [0; 3];
    for seed in 0..32 {
        per_osd[s.primary_of(PgT::new(1, seed)) as usize] += 1;
        assert_eq!(
            s.up_of(PgT::new(1, seed)),
            rm.pg_mapping(PgT::new(1, seed)).up
        );
    }
    assert!(per_osd.iter().all(|n| *n > 0), "{per_osd:?}");
    let mut tids = vec![];
    for i in 0..32u32 {
        tids.push((
            i,
            s.write_obj(1, i, &format!("o{i}"), &[i as u8; 64]).unwrap(),
        ));
        s.run_for(MS);
    }
    s.run_for(1000 * MS);
    for (i, t) in tids {
        assert!(s.is_acked(common::spg(1, i), t), "pg 1.{i}");
    }
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
}

/// The per-epoch mapping memo: repeated lookups equal a fresh CRUSH run, and a changed map (new epoch with a pg_temp, a
/// grown pg_num) is a new `RealMap` whose mappings follow it while the old handle keeps answering for its own epoch.
#[test]
fn real_map_memo_is_per_epoch() {
    let m = real();
    let rm = RealMap::new(m.clone());
    let pg = PgT::new(1, 5);
    let first = rm.pg_mapping(pg);
    for _ in 0..3 {
        assert_eq!(rm.pg_mapping(pg), first);
        assert_eq!(rm.pg_mapping(pg), peering::map::crush_mapping(&m, pg));
    }
    let mut n = (*m).clone();
    n.epoch += 1;
    let temp: Vec<i32> = first.acting.iter().rev().copied().collect();
    assert_ne!(temp, first.acting);
    n.pg_temp.insert(pg, temp.clone());
    let p1 = n.pools.get_mut(&1).unwrap();
    p1.pg_num *= 2;
    p1.pgp_num *= 2;
    let new_pg = PgT::new(1, p1.pg_num - 1);
    let n = Arc::new(n);
    let rn = RealMap::new(n.clone());
    assert_eq!(rn.pg_mapping(pg).acting, temp);
    assert_eq!(rn.pg_mapping(pg), peering::map::crush_mapping(&n, pg));
    assert_eq!(
        rn.pg_mapping(new_pg),
        peering::map::crush_mapping(&n, new_pg)
    );
    assert!(!rn.pg_mapping(new_pg).up.is_empty());
    assert!(
        rm.pg_mapping(new_pg).up.is_empty(),
        "the old epoch has no such PG"
    );
    assert_eq!(
        rm.pg_mapping(pg),
        first,
        "the old handle keeps its epoch's mapping"
    );
}

/// Any cache tiering field of a decoded pool marks it `tiered` (adr 0168); an untiered pool never is.
#[test]
fn real_map_marks_tiered_pools() {
    let m = real();
    assert!(!RealMap::new(m.clone()).pool(1).unwrap().tiered);
    let set: [fn(&mut osdmap::pool::PgPool); 5] = [
        |p| p.tier_of = 2,
        |p| p.read_tier = 2,
        |p| p.write_tier = 2,
        |p| p.cache_mode = 1,
        |p| {
            p.tiers.insert(2);
        },
    ];
    for f in set {
        let mut n = (*m).clone();
        f(n.pools.get_mut(&1).unwrap());
        let rn = RealMap::new(Arc::new(n));
        assert!(rn.pool(1).unwrap().tiered);
        assert!(!rn.pool(2).is_some_and(|p| p.tiered));
    }
}

/// Tracker 74943 gate: ISA pools are listed only when the map holds at least two distinct (k, m) shapes.
#[test]
fn isa_distinct_km_pools_needs_two_shapes() {
    let mut m = (*real()).clone();
    let ec = |m: &mut osdmap::OsdMap, id: i64, prof: &str, k: u32, mm: u32, plugin: &str| {
        let p = m.pools.get_mut(&id).unwrap();
        p.ptype = osdmap::pool::TYPE_ERASURE;
        p.size = (k + mm) as u8;
        p.min_size = (k + 1) as u8;
        p.stripe_width = k * 4096;
        p.erasure_code_profile = prof.into();
        p.flags &= !osdmap::pool::flags::OMAP;
        p.flags |= osdmap::pool::flags::EC_OVERWRITES;
        m.erasure_code_profiles.insert(
            prof.into(),
            [
                ("plugin", plugin.to_string()),
                ("technique", "reed_sol_van".into()),
                ("k", k.to_string()),
                ("m", mm.to_string()),
            ]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b))
            .collect(),
        );
    };
    assert!(
        peering::map::isa_distinct_km_pools(&m).is_empty(),
        "the lab map has one ISA 2+1 pool"
    );
    ec(&mut m, 1, "p21", 2, 1, "isa");
    assert!(
        peering::map::isa_distinct_km_pools(&m).is_empty(),
        "one shape"
    );
    ec(&mut m, 4, "p32", 3, 2, "isa");
    assert_eq!(
        peering::map::isa_distinct_km_pools(&m),
        vec![(1, 2, 1), (4, 3, 2), (7, 2, 1)]
    );
    ec(&mut m, 4, "j32", 3, 2, "jerasure");
    assert!(
        peering::map::isa_distinct_km_pools(&m).is_empty(),
        "jerasure pool does not count"
    );
}

/// Stretch lookups of the real adapter go through the decoded CRUSH map of the epoch and the pool's own rule
/// (doc/spec/stretch.md 2.1, 3.1).
#[test]
fn real_map_stretch_buckets_and_can_peer() {
    use crush::*;
    let mut m = (*real()).clone();
    let mut c = CrushMap::new();
    c.type_map = std::collections::BTreeMap::from([
        (0, "osd".into()),
        (1, "host".into()),
        (8, "datacenter".into()),
        (11, "root".into()),
    ]);
    c.add_bucket(Bucket::straw2(-2, 1, &[(0, 1)]));
    c.add_bucket(Bucket::straw2(-4, 1, &[(1, 1)]));
    c.add_bucket(Bucket::straw2(-5, 1, &[(2, 1)]));
    c.add_bucket(Bucket::straw2(-3, 8, &[(-2, 1), (-4, 1)]));
    c.add_bucket(Bucket::straw2(-10, 8, &[(-5, 1)]));
    c.add_bucket(Bucket::straw2(-1, 11, &[(-3, 2), (-10, 1)]));
    c.add_rule(
        0,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -1, 0),
                Step::new(OP_CHOOSELEAF_FIRSTN, 0, 1),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    let mut blob = Vec::new();
    crush::codec::encode(&c, &mut blob);
    m.set_crush(blob);
    let (&id, p) = m.pools.iter_mut().next().unwrap();
    p.crush_rule = 0;
    p.peering_crush.bucket_count = 2;
    p.peering_crush.bucket_target = 2;
    p.peering_crush.bucket_barrier = 8;
    let rm = RealMap::new(Arc::new(m));
    let pp = rm.pool(id as u64).unwrap();
    assert!(pp.is_stretch());
    assert_eq!(pp.crush_rule, 0);
    assert_eq!(rm.barrier_bucket(0, 8, 0), -3);
    assert_eq!(rm.barrier_bucket(2, 8, 0), -10);
    assert_eq!(rm.barrier_bucket(2, 8, 5), 0);
    assert!(pgwire::can_peer(&rm, &pp, &[0, 2]));
    assert!(!pgwire::can_peer(&rm, &pp, &[0, 1]));
}
