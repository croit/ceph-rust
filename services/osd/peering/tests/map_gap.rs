// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG loading over an incomplete stored map history (oq 14: 28 of 32 PGs of a new pool removed at boot). A PG may only be
//! removed when a map at or after its own epoch lacks its pool; a gap or a too-short history must never remove it.
mod common;
use common::*;

const POOL2: u64 = 2;
const PGS2: u32 = 8;

/// One OSD, pool 1 clean, then pool 2 created (epoch returned) and clean.
fn setup(seed: u64) -> (Sim, u32) {
    let mut s = cluster(seed, &[0], 1, 1, 1, 4);
    s.new_epoch(|_| {});
    s.new_epoch(|_| {});
    s.create_pool(POOL2, 1, 1, PGS2);
    let created = s.epoch();
    s.run_until(60_000 * MS, "pool 2 clean", |s| s.pool_clean(POOL2));
    (s, created)
}

fn stored(s: &Sim) -> usize {
    (0..PGS2)
        .filter(|i| s.nodes[&0].store.pgs.contains_key(&spg(POOL2, *i)))
        .count()
}

/// The stored maps around the pool's creation and the PGs' own epoch are missing: they start at the first map after the
/// gap, keep their data and serve.
#[test]
fn pgs_of_a_pool_created_inside_a_map_gap_survive_a_restart() {
    let (mut s, created) = setup(5);
    assert_eq!(stored(&s), PGS2 as usize);
    s.kill(0);
    let cur = s.epoch();
    s.restart_maps(0, |e| e < created || e >= cur);
    assert_eq!(stored(&s), PGS2 as usize, "{}", s.trace_of("removed"));
    s.run_until(60_000 * MS, "pool 2 clean again", |s| s.pool_clean(POOL2));
    assert_eq!(stored(&s), PGS2 as usize);
}

/// The stored history ends before the pool existed (the chain stopped at a hole): the PGs are kept on disk, not loaded,
/// and reported; before, their start map was an older one without the pool and they were removed.
#[test]
fn pgs_newer_than_the_stored_history_are_kept_not_removed() {
    let (mut s, created) = setup(6);
    s.kill(0);
    s.restart_maps(0, |e| e < created);
    let notes = s.nodes.get_mut(&0).unwrap().set.take_notices();
    assert_eq!(stored(&s), PGS2 as usize);
    for i in 0..PGS2 {
        assert!(s.pg(0, spg(POOL2, i)).is_none());
    }
    assert_eq!(
        notes
            .iter()
            .filter(|n| n.starts_with("ERROR") && n.contains("kept on disk"))
            .count(),
        PGS2 as usize,
        "{notes:?}"
    );
    s.run_for(2_000 * MS);
    assert_eq!(stored(&s), PGS2 as usize);
}

/// Cluster-wide trimming proves obsolete prior intervals no longer constrain peering. A very old
/// copy must not wait for a down participant of an interval that predates that proof.
#[test]
fn cluster_trim_gap_retires_obsolete_prior_participants() {
    use denc::types::PgShard;
    use peering::synth::SynthMap;
    use peering::{Config, MemStore, PSt, PersistedPg, Pg, St};
    use pgwire::{CompactInterval, PastIntervals, PgInfo};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    for erasure in [false, true] {
        let mut id = spg(1, 0);
        if erasure {
            id.shard = denc::types::ShardId(0);
        }
        let mut old = SynthMap::new(5)
            .with_pool(1, if erasure { 2 } else { 1 }, 1, 1)
            .with_osd(0, 1)
            .with_osd(1, 1);
        if erasure {
            let pool = old.pools.get_mut(&1).unwrap();
            pool.is_erasure = true;
            pool.ec_k = 1;
            pool.ec = Some(Arc::new(pgwire::EcPoolInfo {
                k: 1,
                m: 1,
                stripe_width: 4096,
                chunk_size: 4096,
                supported: true,
                ..Default::default()
            }));
        }
        let members = |osd| {
            if erasure {
                vec![osd, pgwire::NONE_OSD]
            } else {
                vec![osd]
            }
        };
        old.up_override.insert(id.pgid, members(1));
        let mut current = old.clone();
        current.epoch = 100;
        current.osds.get_mut(&1).unwrap().up = false;
        current.up_override.insert(id.pgid, members(0));
        current.osds.get_mut(&0).unwrap().up_thru = 100;
        let mut info = PgInfo::new(id);
        info.history.epoch_created = 1;
        info.history.epoch_pool_created = 1;
        info.history.last_epoch_clean = 2;
        info.history.last_epoch_started = 3;
        info.history.same_interval_since = 4;
        let acting = BTreeSet::from([PgShard {
            osd: 1,
            shard: id.shard,
        }]);
        let persisted = PersistedPg {
            info,
            log: Default::default(),
            missing: Default::default(),
            past_intervals: PastIntervals {
                first: 2,
                last: 3,
                all_participants: acting.clone(),
                intervals: vec![CompactInterval {
                    first: 2,
                    last: 3,
                    acting,
                }],
            },
            epoch: 5,
        };
        // Neither an unrelated retained map, a PG clean at the floor nor a PG whose persisted map is the floor
        // itself (no interval change seen: classic keeps the intervals) takes the gap rule.
        for (floor, clean, at) in [(99, 2, 5), (101, 2, 5), (100, 100, 5), (100, 2, 100)] {
            let cfg = Arc::new(Config::new(0));
            cfg.cluster_trim
                .store(floor, std::sync::atomic::Ordering::Relaxed);
            let mut p = persisted.clone();
            p.info.history.last_epoch_clean = clean;
            p.epoch = at;
            let pg = Pg::load(cfg, id, p, current.clone().into_handle(), 0);
            assert!(
                !pg.past_intervals().is_empty(),
                "floor={floor}, clean={clean}, persisted at {at}"
            );
        }
        for retained_old in [false, true] {
            let cfg = Arc::new(Config::new(0));
            cfg.cluster_trim
                .store(100, std::sync::atomic::Ordering::Relaxed);
            let mut pg = Pg::load(
                cfg,
                id,
                persisted.clone(),
                if retained_old {
                    old.clone().into_handle()
                } else {
                    current.clone().into_handle()
                },
                0,
            );
            let store = MemStore::new();
            if retained_old {
                pg.advance_map(0, current.clone().into_handle(), &store);
            }
            pg.act_map(0, &store);
            assert_ne!(pg.machine_state(), St::Primary(PSt::Down));
            assert!(
                pg.past_intervals().is_empty(),
                "obsolete intervals survived (retained_old={retained_old}): {:?}",
                pg.past_intervals()
            );
        }
    }
}
