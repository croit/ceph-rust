// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
mod common;
use common::*;

fn run_clean(osds: &[i32], size: u32, min: u32, pgs: u32, seed: u64) -> Sim {
    let s = cluster(seed, osds, 1, size, min, pgs);
    s.assert_no_roundtrip_mismatch();
    s
}

#[test]
fn size1_converges() {
    let s = run_clean(&[0], 1, 1, 4, 1);
    for st in s.pool_state_strings(1) {
        assert_eq!(st, "active+clean");
    }
}

#[test]
fn size2_converges() {
    let s = run_clean(&[0, 1], 2, 1, 8, 2);
    for st in s.pool_state_strings(1) {
        assert_eq!(st, "active+clean");
    }
}

#[test]
fn size3_converges() {
    let s = run_clean(&[0, 1, 2], 3, 2, 8, 3);
    for st in s.pool_state_strings(1) {
        assert_eq!(st, "active+clean");
    }
    s.assert_persisted_consistent();
}

#[test]
fn dump_size3() {
    let s = run_clean(&[0, 1, 2], 3, 2, 2, 3);
    println!("{}\nmsgs by type: {:?}", s.dump(), s.stats.msgs_by_type);
}

/// Review regression (adr 0064 am. 1): a runtime wall re-anchor reached only the PgSet; every loaded PG kept its own copy
/// of the old base (PG stat stamps, scrub stamps and schedule lagged).
#[test]
fn wall_base_change_reaches_loaded_pgs() {
    let mut s = run_clean(&[0], 1, 1, 2, 7);
    let pg = spg(1, 0);
    let base = 1_700_000_000_000_000_000u64;
    let step = 40_000_000_000u64;
    let n = s.nodes.get_mut(&0).unwrap();
    n.set.set_wall_base(base);
    let st = n.store.clone();
    let a = n.set.pg_mut(pg).unwrap().build_pg_stat(&st).last_fresh;
    n.set.set_wall_base(base + step);
    let b = n.set.pg_mut(pg).unwrap().build_pg_stat(&st).last_fresh;
    let ns = |t: denc::types::UTime| u64::from(t.sec) * 1_000_000_000 + u64::from(t.nsec);
    assert_eq!(ns(b) - ns(a), step, "{a:?} -> {b:?}");
}

/// `flashstore_peering_trace_ms`: a primary whose peering took at least that long notes the time per phase; off by default.
#[test]
fn peering_trace_notes_slow_peerings() {
    let mut s = cluster_cfg(31, &[0, 1, 2], 1, 3, 2, 4, |c| c.peer_trace_ns = 1);
    let mut s0 = cluster(31, &[0, 1, 2], 1, 3, 2, 4);
    let notes = |s: &mut Sim| -> Vec<String> {
        s.nodes
            .values_mut()
            .flat_map(|n| n.set.take_notices())
            .filter(|n| n.contains(" peering "))
            .collect()
    };
    assert!(notes(&mut s0).is_empty(), "off by default");
    let n = notes(&mut s);
    assert!(!n.is_empty());
    assert!(
        n.iter()
            .all(|l| l.contains(" ms (e") && l.contains("GetInfo")),
        "{n:?}"
    );
}
