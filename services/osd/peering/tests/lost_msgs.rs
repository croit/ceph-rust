// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Peering messages lost with a msgr session (adr 0071): redrive on fault/connect, per-peer back-off; a silent loss
//! (peer restart) is left to the new interval.
mod common;
use common::*;
use denc::types::PgT;
use peering::PEER_BACKOFF_MAX;
use pgwire::ty;

const OSDS: [i32; 3] = [0, 1, 2];

fn drop_first(s: &mut Sim, types: &[u16]) {
    for a in OSDS {
        for b in OSDS {
            if a != b {
                for t in types {
                    s.drop_next.push((a, b, *t));
                }
            }
        }
    }
}

fn pool_active(s: &Sim, pool: u64) -> bool {
    let map = s.map();
    let Some(pp) = map.pools.get(&pool) else {
        return false;
    };
    (0..pp.pg_num).all(|seed| {
        let mp = peering::PgMapView::pg_mapping(&*map, PgT::new(pool, seed));
        mp.acting_primary >= 0
            && s.pg(mp.acting_primary, s.lead_spg(pool, seed))
                .is_some_and(|p| p.state_bits() & pgwire::state::ACTIVE != 0)
    })
}

fn redrives(s: &Sim) -> u64 {
    s.nodes
        .values()
        .map(|n| n.set.peer_stats.redriven_msgs)
        .sum()
}

fn new_pool_with_losses(seed: u64, types: &[u16], faults: bool) -> Sim {
    let mut s = cluster(seed, &OSDS, 1, 3, 2, 4);
    // all croit-flashstore-osd: activations are redriven too (never to classic peers)
    for o in OSDS {
        s.call(o, |set, _, _| {
            set.set_flashstore_peers(OSDS.into_iter().collect())
        });
    }
    s.drop_faults = faults;
    drop_first(&mut s, types);
    s.create_pool(2, 3, 2, 8);
    s
}

/// The first query between every pair is lost and the msgr reports the fault: the PGs go active+clean without a repeer.
#[test]
fn lost_query_on_link_fault_is_redriven() {
    let mut s = new_pool_with_losses(71, &[ty::PG_QUERY2], true);
    let t0 = s.now;
    s.run_until(5_000 * MS, "pool clean after lost queries", |s| {
        s.pool_clean(2)
    });
    assert!(s.dropped_lost > 0, "nothing was dropped");
    assert!(redrives(&s) > 0);
    assert!(s.now - t0 < 5_000 * MS);
    s.assert_no_roundtrip_mismatch();
}

/// A lossless cluster session loses frames only with the peer's process (adr 0071 am. 2): a silent loss is a peer that
/// restarted. Its new incarnation is a new interval for every PG it is in, peering starts over and the PGs go clean
/// without any timer (none exists: a loss nothing reports is left to the map).
#[test]
fn query_lost_with_a_restarting_peer_is_covered_by_the_new_interval() {
    let mut s = new_pool_with_losses(72, &[ty::PG_QUERY2], false);
    s.run_for(3_000 * MS);
    assert!(s.dropped_lost > 0, "nothing was dropped");
    assert!(!s.pool_clean(2), "lost queries: peering cannot complete");
    assert_eq!(redrives(&s), 0, "no fault was reported: nothing to redrive");
    // every pair lost a query: each OSD restarts once (a new interval for every PG), nothing else is lost
    s.drop_next.clear();
    for o in OSDS {
        s.kill(o);
        s.run_for(200 * MS);
        s.restart(o);
        s.run_for(200 * MS);
    }
    s.run_until(60_000 * MS, "pool clean after the restarts", |s| {
        s.pool_clean(2)
    });
    s.assert_persisted_consistent();
}

/// Lost answers (notify, log) and lost activations / activation acks (log, info) are covered by the same redrive.
#[test]
fn lost_answers_and_activation_are_redriven() {
    let mut s = new_pool_with_losses(73, &[ty::PG_NOTIFY2, ty::PG_LOG, ty::PG_INFO2], true);
    s.run_until(60_000 * MS, "pool clean after lost answers", |s| {
        s.pool_clean(2)
    });
    assert!(s.dropped_lost > 0);
    s.assert_persisted_consistent();
}

/// A peer that is up in the map (nodown) but unreachable: every peering message to it (queries, redriven activations)
/// is bounded by the per-peer back-off, and nothing is queried once the map marks it down.
#[test]
fn messages_to_an_unreachable_peer_are_bounded() {
    let mut s = cluster(75, &OSDS, 1, 3, 2, 8);
    for o in OSDS {
        s.call(o, |set, _, _| {
            set.set_flashstore_peers(OSDS.into_iter().collect())
        });
    }
    s.unreachable.insert(2);
    s.mark_out(2); // new interval; osd.2 stays up (prior set, pg_temp keeps it acting): peering waits for it
    let to_dead = |s: &Sim, t: Option<u16>| -> u64 {
        s.sent
            .iter()
            .filter(|((f, to, ty), _)| *f != 2 && *to == 2 && t.is_none_or(|t| t == *ty))
            .map(|(_, n)| *n)
            .sum()
    };
    let start = to_dead(&s, None);
    let dur = 600_000 * MS;
    s.run_for(dur);
    let sent = to_dead(&s, None) - start;
    let rounds: u64 = s.nodes.values().map(|n| n.set.peer_stats.redrives).sum();
    assert!(rounds > 0, "nothing probed the peer");
    // per sender: 8 PGs x (one probe per back-off step 0, 1, 2, ... capped at PEER_BACKOFF_MAX + slack)
    let steps = 8 + dur / PEER_BACKOFF_MAX;
    assert!(
        sent <= 2 * 8 * (steps + 4),
        "{sent} messages to the unreachable peer in {} s: {:?}",
        dur / 1_000 / MS,
        s.sent
    );
    assert!(
        to_dead(&s, Some(ty::PG_NOTIFY2)) < 100,
        "stray notifies repeated per inbound message"
    );
    // the map marks it down: nothing is queried any more, the pool goes active without it
    s.mark_down(2);
    s.run_until(30_000 * MS, "active without osd.2", |s| pool_active(s, 1));
    let after = to_dead(&s, Some(ty::PG_QUERY2));
    s.run_for(300_000 * MS);
    assert_eq!(
        to_dead(&s, Some(ty::PG_QUERY2)),
        after,
        "queries to a peer the map marks down"
    );
}
