// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Ceph 21.2.0 vulnerability window and active-rebuild span (peering.md 9.6): latched by the primary, persisted with
//! the PG info, shared with the replicas, mirrored into pg_stat_t, sampled into `PgSet::latch_perf`.
mod common;
use common::*;
use pgwire::PgHistory;

fn hist(s: &Sim, osd: i32, pg: denc::types::SpgT) -> PgHistory {
    s.nodes[&osd].set.pg(pg).unwrap().info().history.clone()
}

fn latches(h: &PgHistory) -> [denc::types::UTime; 6] {
    [
        h.last_degraded,
        h.last_clean,
        h.vuln_window_reported,
        h.last_rebuild_active_start,
        h.rebuild_span_reported,
        h.rebuild_active_accum,
    ]
}

#[test]
fn replica_down_opens_window_recovery_closes_it() {
    let mut s = cluster(4101, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let p = s.primary_of(pg.pgid);
    let h0 = hist(&s, p, pg);
    assert!(!h0.vuln_open() && !h0.rebuild_open(), "{h0:?}");
    // creation latched every window field at the creation stamp
    assert_eq!(h0.vuln_window_reported, h0.last_scrub_stamp);
    let perf0 = s.nodes[&p].set.latch_perf();

    let r = (0..3).find(|o| *o != p).unwrap();
    s.mark_down(r);
    s.run_until(10_000 * MS, "degraded", |s| {
        s.pool_state_strings(1)
            .iter()
            .all(|st| st.contains("undersized"))
    });
    s.run_for(200 * MS);
    let mut tids = vec![];
    for i in 0..8 {
        if let Ok(t) = s.write_named(1, &format!("o{i}"), &[i as u8; 512]) {
            tids.push(t);
        }
    }
    s.wait_writes(&tids, pg);
    let hd = hist(&s, p, pg);
    assert!(hd.vuln_open(), "window open while undersized: {hd:?}");
    assert!(hd.last_degraded > h0.vuln_window_reported);
    let (_, st) = &s.pgstats[&pg];
    assert_eq!(
        st.last_degraded, hd.last_degraded,
        "pg_stat_t mirrors history"
    );

    s.mark_up(r);
    s.run_until(30_000 * MS, "clean again", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    let p2 = s.primary_of(pg.pgid);
    let h = hist(&s, p2, pg);
    assert!(!h.vuln_open(), "closed at clean: {h:?}");
    assert_eq!(h.last_degraded, hd.last_degraded, "onset never moves");
    assert_eq!(h.last_clean, h.vuln_window_reported);
    assert!(!h.rebuild_open() && h.rebuild_active_accum == Default::default());
    assert!(
        h.rebuild_span_reported > hd.last_degraded,
        "recovery ran as one rebuild episode: {h:?}"
    );
    let perf = s.nodes[&p2].set.latch_perf();
    assert_eq!(
        perf.vulnerability.n,
        perf0.vulnerability.n + u64::from(p2 == p),
        "one window sample on the primary that closed it"
    );
    assert!(perf.vulnerability.min_ns >= 1_000_000);
    // every member got the closed history (mark-clean shares it after the stats publish)
    for o in 0..3 {
        assert_eq!(latches(&hist(&s, o, pg)), latches(&h), "osd.{o}");
    }
    // the primary's stored peer copies (pg query peer_info) carry the shared latches (peering.md 9.7)
    let prim = s.nodes[&p2].set.pg(pg).unwrap();
    assert_eq!(prim.peer_infos().count(), 2);
    for (o, i) in prim.peer_infos() {
        assert_eq!(latches(&i.history), latches(&h), "peer_info osd.{o}");
    }
    let (_, st) = &s.pgstats[&pg];
    assert_eq!(st.last_degraded, h.last_degraded);
    s.assert_persisted_consistent();

    // a clean publish that closes nothing leaves the history alone
    s.run_for(12_000 * MS);
    assert_eq!(latches(&hist(&s, p2, pg)), latches(&h));
}
