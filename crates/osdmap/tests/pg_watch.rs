// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! PgWatch over a real map (real CRUSH): every applied epoch counts, not only the newest map (spec rados-client
//! 22-mutation-retry.md, interval resend rule).

use denc::types::PgT;
use osdmap::consts::osd_state;
use osdmap::*;
use std::path::Path;

fn base() -> OsdMap {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/osdmap/full/0091.bin");
    OsdMap::decode_from(&std::fs::read(p).unwrap()).unwrap()
}

/// A replicated PG with two acting OSDs: (pg, primary, other).
fn pick(m: &OsdMap) -> (PgT, i32, i32) {
    for (&id, pool) in &m.pools {
        if !pool.is_replicated() || pool.size < 2 || pool.pg_num < 2 {
            continue;
        }
        for seed in 0..pool.pg_num {
            let pg = PgT::new(id as u64, seed);
            let a = m.pg_to_up_acting(pg);
            if a.acting.len() >= 2 && a.acting_primary == a.acting[0] {
                return (pg, a.acting[0], a.acting[1]);
            }
        }
    }
    panic!("no replicated pg with two acting osds in the fixture");
}

fn next(m: &OsdMap, f: impl FnOnce(&mut OsdMap)) -> OsdMap {
    let mut n = m.clone();
    n.epoch += 1;
    f(&mut n);
    n
}

#[test]
fn primary_away_and_back_between_two_checks_is_a_new_interval() {
    let m1 = base();
    let (pg, a, b) = pick(&m1);
    let mut w = PgWatch::default();
    w.observe(None, &m1);
    w.track(pg, m1.epoch);
    let m2 = next(&m1, |n| {
        n.pg_temp.insert(pg, vec![b, a]);
    });
    let m3 = next(&m2, |n| {
        n.pg_temp.remove(&pg);
    });
    assert_eq!(m2.pg_to_up_acting(pg).acting_primary, b);
    w.observe(Some(&m1), &m2);
    w.observe(Some(&m2), &m3);
    // newest map: same primary as at the send (a primary-only check of the newest map misses it) ...
    assert_eq!(m3.pg_to_up_acting(pg).acting_primary, a);
    // ... but the PG had two new intervals since the send epoch
    assert_eq!(w.interval_since(pg), Some(m3.epoch));
    assert!(w.interval_since(pg).unwrap() > m1.epoch);
}

#[test]
fn unrelated_changes_keep_the_interval() {
    let m1 = base();
    let (pg, _, _) = pick(&m1);
    let other = (0..m1.pools[&(pg.pool as i64)].pg_num)
        .map(|s| PgT::new(pg.pool, s))
        .find(|o| *o != pg)
        .unwrap();
    let mut w = PgWatch::default();
    w.observe(None, &m1);
    w.track(pg, m1.epoch);
    let o = m1.pg_to_up_acting(other).acting;
    let m2 = next(&m1, |n| {
        // another PG of the same pool moves, another pool changes its size
        n.pg_temp.insert(other, o.iter().rev().copied().collect());
        if let Some((_, p)) = n.pools.iter_mut().find(|(id, _)| **id != pg.pool as i64) {
            p.size = p.size.saturating_add(1);
        }
        n.modified.sec += 1;
    });
    w.observe(Some(&m1), &m2);
    assert_eq!(w.interval_since(pg), Some(0));
}

#[test]
fn split_moving_objects_is_a_new_interval_without_a_mapping_change() {
    let m1 = base();
    let (pg, _, _) = pick(&m1);
    let pool_id = pg.pool as i64;
    let pg_num = m1.pools[&pool_id].pg_num;
    let mut w = PgWatch::default();
    w.observe(None, &m1);
    w.track(pg, m1.epoch);
    // double pg_num, pgp_num unchanged: placement of the old seed stays, its objects split to the child
    let m2 = next(&m1, |n| {
        n.pools.get_mut(&pool_id).unwrap().pg_num = pg_num * 2
    });
    assert_eq!(m1.pg_to_up_acting(pg), m2.pg_to_up_acting(pg));
    let moved = (0..10_000).map(|i| format!("obj-{i}")).find(|name| {
        let old = m1.object_to_pg(pool_id, name.as_bytes(), b"", b"", -1);
        let new = m2.object_to_pg(pool_id, name.as_bytes(), b"", b"", -1);
        old.ok() == Some(pg) && new.ok() != Some(pg)
    });
    assert!(
        moved.is_some(),
        "an object of the PG maps to a child after the split"
    );
    w.observe(Some(&m1), &m2);
    assert_eq!(w.interval_since(pg), Some(m2.epoch));
}

#[test]
fn osd_down_up_flap_and_gap_and_late_tracking() {
    let m1 = base();
    let (pg, a, _) = pick(&m1);
    let mut w = PgWatch::default();
    w.observe(None, &m1);
    w.track(pg, m1.epoch);
    w.track(pg, m1.epoch); // two requests of the same PG
    let m2 = next(&m1, |n| n.osd_state[a as usize] &= !osd_state::UP);
    let m3 = next(&m2, |n| {
        n.osd_state[a as usize] |= osd_state::UP;
        n.osd_info[a as usize].up_from = n.epoch;
    });
    w.observe(Some(&m1), &m2);
    w.observe(Some(&m2), &m3);
    assert_eq!(m3.pg_to_up_acting(pg), m1.pg_to_up_acting(pg));
    assert_eq!(w.interval_since(pg), Some(m3.epoch));
    // one request left: still followed; gap (m3 -> m5, m4 missed): new interval at m5
    w.untrack(pg);
    let m5 = next(&next(&m3, |_| {}), |_| {});
    w.observe(Some(&m3), &m5);
    assert_eq!(w.interval_since(pg), Some(m5.epoch));
    // a request routed before the watch's epoch: unknown history = new interval now
    w.untrack(pg);
    assert_eq!(w.interval_since(pg), None);
    w.track(pg, m3.epoch);
    assert_eq!(w.interval_since(pg), Some(m5.epoch));
    // adjacent unchanged map after the gap: baseline taken lazily, nothing new
    let m6 = next(&m5, |_| {});
    w.observe(Some(&m5), &m6);
    assert_eq!(w.interval_since(pg), Some(m5.epoch));
}

/// An install identity that does not advance (repeated generation after a re-created owner, reordered install,
/// counter reset) cannot be compared against the stored intervals: it is a gap (fresh baseline), never a panic.
#[test]
fn non_advancing_install_generation_is_a_gap() {
    let first = base();
    let (pg, _, _) = pick(&first);
    let mut watch = PgWatch::default();
    watch.observe_generation(None, &first, 1);
    watch.track(pg, first.epoch);
    let second = next(&first, |_| {});
    // the same generation again
    watch.observe_generation(Some(&first), &second, 1);
    assert_eq!(watch.interval_since(pg), Some(second.epoch));
    assert_eq!(watch.interval_generation(pg), Some(1));
    // a lower generation (reordered install) is the same case
    let third = next(&second, |_| {});
    watch.observe_generation(Some(&second), &third, 0);
    assert_eq!(watch.interval_since(pg), Some(third.epoch));
    assert_eq!(watch.interval_generation(pg), Some(0));
    // the owner advances again: an adjacent unchanged map keeps the interval
    let fourth = next(&third, |_| {});
    watch.observe_generation(Some(&third), &fourth, 1);
    assert_eq!(watch.interval_since(pg), Some(third.epoch));
}

#[test]
fn same_epoch_replacements_track_exact_interval_generation_without_refresh_resends() {
    let first = base();
    let (pg, a, b) = pick(&first);
    let mut watch = PgWatch::default();
    watch.observe_generation(None, &first, 1);
    watch.track(pg, first.epoch);
    watch.observe_generation(Some(&first), &first, 2);
    assert_eq!(watch.interval_generation(pg), Some(0));
    let mut away = first.clone();
    away.pg_temp.insert(pg, vec![b, a]);
    watch.observe_generation(Some(&first), &away, 3);
    assert_eq!(watch.interval_since(pg), Some(first.epoch));
    assert_eq!(watch.interval_generation(pg), Some(3));
    watch.observe_generation(Some(&away), &first, 4);
    assert_eq!(watch.interval_generation(pg), Some(4));
    watch.observe_generation(Some(&first), &first, 5);
    assert_eq!(watch.interval_generation(pg), Some(4));
    watch.untrack(pg);
    watch.track(pg, first.epoch);
    assert_eq!(watch.interval_generation(pg), Some(0));
}

#[test]
fn stretch_constraints_start_intervals_without_changing_placement() {
    let original = base();
    let (pg, _, _) = pick(&original);
    let mut baseline = original;
    let pool = baseline.pools.get_mut(&(pg.pool as i64)).unwrap();
    pool.peering_crush = osdmap::pool::PeeringCrush {
        bucket_count: 1,
        bucket_target: 1,
        bucket_barrier: 1,
        mandatory_member: osdmap::consts::ITEM_NONE,
    };
    for field in 0..4 {
        let updated = next(&baseline, |m| {
            let c = &mut m.pools.get_mut(&(pg.pool as i64)).unwrap().peering_crush;
            match field {
                0 => c.bucket_count = 2,
                1 => c.bucket_target = 2,
                2 => c.bucket_barrier = 2,
                3 => c.mandatory_member = -1,
                _ => unreachable!(),
            }
        });
        assert_eq!(baseline.pg_to_up_acting(pg), updated.pg_to_up_acting(pg));
        assert_eq!(
            baseline.pool(pg.pool as i64).unwrap().last_force_op_resend,
            updated.pool(pg.pool as i64).unwrap().last_force_op_resend
        );
        let mut watch = PgWatch::default();
        watch.observe(None, &baseline);
        watch.track(pg, baseline.epoch);
        watch.observe(Some(&baseline), &updated);
        assert_eq!(
            watch.interval_since(pg),
            Some(updated.epoch),
            "field {field}"
        );
        // Even a return to the original policy must retain the intervening reset.
        let restored = next(&updated, |m| {
            m.pools.get_mut(&(pg.pool as i64)).unwrap().peering_crush =
                baseline.pool(pg.pool as i64).unwrap().peering_crush;
        });
        watch.observe(Some(&updated), &restored);
        assert_eq!(watch.interval_since(pg), Some(restored.epoch));
    }
}

#[test]
fn ec_optimization_change_starts_interval_without_changing_placement() {
    let mut baseline = base();
    let pg = baseline
        .pools
        .iter()
        .find_map(|(&id, pool)| {
            (pool.is_erasure() && pool.pg_num > 0).then_some(PgT::new(id as u64, 0))
        })
        .expect("EC pool in fixture");
    baseline.pools.get_mut(&(pg.pool as i64)).unwrap().flags &=
        !osdmap::pool::flags::EC_OPTIMIZATIONS;
    let updated = next(&baseline, |m| {
        m.pools.get_mut(&(pg.pool as i64)).unwrap().flags |= osdmap::pool::flags::EC_OPTIMIZATIONS;
    });
    assert_eq!(baseline.pg_to_up_acting(pg), updated.pg_to_up_acting(pg));
    let mut watch = PgWatch::default();
    watch.observe(None, &baseline);
    watch.track(pg, baseline.epoch);
    watch.observe(Some(&baseline), &updated);
    assert_eq!(watch.interval_since(pg), Some(updated.epoch));
}
