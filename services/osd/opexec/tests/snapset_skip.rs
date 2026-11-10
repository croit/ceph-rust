// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! A write that leaves the head's SnapSet as it is does not set the `snapset` attribute again (perf-w4k); everything
//! that changes it or rebuilds the head does.
mod common;
use common::*;
use opwire::OsdOp;

/// `(setattr names, whole-object ops)` of the v9 blob of write `n`.
fn txn_attrs(pg: &TPg, n: usize) -> Vec<Vec<u8>> {
    let t = replwire::Transaction::decode(&[], &pg.txns[n], 4096).unwrap();
    t.ops
        .iter()
        .filter_map(|o| match &o.op {
            replwire::TxnOp::SetAttr { name, .. } => Some(name.to_vec()),
            replwire::TxnOp::SetAttrs { attrs, .. } => {
                Some(attrs.iter().flat_map(|(n, _)| n.to_vec()).collect())
            }
            _ => None,
        })
        .collect()
}

fn go(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, op: opwire::MOSDOp) {
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    let r = reply_of(&mut outs, 1, tid).expect("reply");
    assert_eq!(r.result, 0);
}

fn with_snapc(mut op: opwire::MOSDOp, seq: u64, snaps: &[u64]) -> opwire::MOSDOp {
    op.snap_seq = seq;
    op.snaps = snaps.to_vec();
    op
}

#[test]
fn overwrite_keeps_the_stored_snapset_but_create_clone_and_rollback_set_it() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let has = |pg: &TPg, n: usize, a: &[u8]| txn_attrs(pg, n).iter().any(|x| x == a);
    // creation: object info and snapset
    go(
        &mut pg,
        &mut eng,
        1,
        mkop(b"o", vec![OsdOp::write(0, vec![1; 100])]),
    );
    assert!(has(&pg, 0, b"_") && has(&pg, 0, b"snapset"));
    // plain overwrites: object info only
    go(
        &mut pg,
        &mut eng,
        2,
        mkop(b"o", vec![OsdOp::write(50, vec![2; 100])]),
    );
    go(
        &mut pg,
        &mut eng,
        3,
        mkop(b"o", vec![OsdOp::write(0, vec![3; 10])]),
    );
    for n in [1, 2] {
        assert!(has(&pg, n, b"_"), "write {n}");
        assert!(
            !has(&pg, n, b"snapset"),
            "write {n} rewrote an unchanged snapset"
        );
    }
    // a newer snap context clones the head: the snapset changes
    go(
        &mut pg,
        &mut eng,
        4,
        with_snapc(mkop(b"o", vec![OsdOp::write(0, vec![4; 10])]), 5, &[5]),
    );
    assert!(has(&pg, 3, b"snapset"));
    // the next overwrite under the same context is plain again
    go(
        &mut pg,
        &mut eng,
        5,
        with_snapc(mkop(b"o", vec![OsdOp::write(0, vec![5; 10])]), 5, &[5]),
    );
    assert!(!has(&pg, 4, b"snapset"));
    // an overwrite inside the clone's remaining overlap shrinks it: the snapset changes
    go(
        &mut pg,
        &mut eng,
        51,
        with_snapc(mkop(b"o", vec![OsdOp::write(50, vec![6; 10])]), 5, &[5]),
    );
    assert!(has(&pg, 5, b"snapset"));
    // a newer seq without a new snap moves only the seq: the snapset changes, then stays
    go(
        &mut pg,
        &mut eng,
        52,
        with_snapc(mkop(b"o", vec![OsdOp::write(50, vec![7; 10])]), 6, &[5]),
    );
    assert!(has(&pg, 6, b"snapset"));
    go(
        &mut pg,
        &mut eng,
        53,
        with_snapc(mkop(b"o", vec![OsdOp::write(50, vec![8; 10])]), 6, &[5]),
    );
    assert!(!has(&pg, 7, b"snapset"));
    // rollback replaces the head from the clone: the snapset is set again, and stays readable
    go(
        &mut pg,
        &mut eng,
        6,
        with_snapc(mkop(b"o", vec![OsdOp::rollback(5)]), 5, &[5]),
    );
    assert!(has(&pg, 8, b"snapset"));
    // (list-snaps after a rollback: golden 23_snap_rollback)
}
