// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Open question 13d in the full Sim: messages stamped with epochs older than the kept map cache.
mod common;
use common::*;
use denc::types::PgT;
use std::collections::BTreeMap;

const POOL: u64 = 1;

/// Both holders of the PG lag by far more than the map cache while the new primary (no PG yet) runs ahead and the
/// interval changes several times. Their first messages carry the old epochs: the new primary must park them, load the
/// old maps, replay every interval and end up active+clean without losing an acked write.
#[test]
fn lagging_holders_create_pg_on_a_new_primary_without_losing_acked_writes() {
    lagging_holders(32);
}

/// Same, the replay in chunks of 3 epochs (commit acks of the held PG must not be lost between the chunks).
#[test]
fn lagging_holders_chunked_replay() {
    lagging_holders(3);
}

fn lagging_holders(chunk: u32) {
    let mut s = cluster_cfg(7, &[0, 1, 2, 3], POOL, 3, 2, 1, |c| c.old_map_chunk = chunk);
    let pg = PgT::new(POOL, 0);
    let mp = peering::PgMapView::pg_mapping(&*s.map(), pg);
    let x = (0..4).find(|o| !mp.acting.contains(o)).expect("outsider");
    let holders: Vec<i32> = mp.acting.clone();
    let mut want: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..20 {
        let name = format!("o-{i}");
        let d = vec![i as u8; 100 + i];
        s.write_named(POOL, &name, &d).expect("write");
        want.insert(name, d);
    }
    s.run_for(1_000 * MS);
    assert!(s.acked.len() >= 20, "all writes acked before the lag");
    for h in &holders {
        s.hold_maps.insert(*h);
    }
    // the outsider becomes primary; several interval changes follow, then plain churn past the map cache
    let [a, b, c] = [holders[0], holders[1], holders[2]];
    s.set_up_override(pg, vec![x, a, b]);
    s.set_up_override(pg, vec![x, b, c]);
    s.set_up_override(pg, vec![x, c, a]);
    for _ in 0..30 {
        s.mark_out(x);
        s.mark_in(x);
    }
    s.set_up_override(pg, vec![x, a, b]);
    s.run_for(2_000 * MS);
    for h in &holders {
        s.release_maps(*h);
    }
    s.run_until(120_000 * MS, "pool settled", |s| {
        s.pool_settled(POOL) && s.quiet()
    });
    assert!(s.old_map_reqs > 0, "the lagging messages needed old maps");
    s.assert_layout(POOL, &want);
    s.assert_persisted_consistent();
}
