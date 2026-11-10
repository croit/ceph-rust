// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Large client writes take the local skeleton path (payload shared with the request, not copied into the txn blob):
//! the stored object must be exactly what a plain write stores, for aligned, unaligned and mixed large writes.
mod common;
use common::*;
use opwire::OsdOp;

fn pat(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn result(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, op: opwire::MOSDOp) -> i32 {
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    outs.extend(settle(pg, eng));
    reply_of(&mut outs, 1, tid).expect("reply").result
}

#[test]
fn large_writes_land_byte_exact() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let a = pat(4 << 20, 1);
    assert!(a.len() >= replwire::SPLIT_MIN);
    let w = OsdOp::write(0, a.clone());
    assert_eq!(result(&mut pg, &mut eng, 1, mkop(b"big", vec![w])), 0);
    // unaligned large overwrite in the middle + a small write in the same message
    let b = pat(100_001, 9);
    let ops = vec![
        OsdOp::write(12_345, b.clone()),
        OsdOp::write(5, b"hello".to_vec()),
    ];
    assert_eq!(result(&mut pg, &mut eng, 2, mkop(b"big", ops)), 0);
    let mut want = a;
    want[12_345..12_345 + b.len()].copy_from_slice(&b);
    want[5..10].copy_from_slice(b"hello");
    let objs = pg.store.objects(pg.spg);
    let o = objs.values().next().expect("object");
    assert_eq!(o.data.len(), want.len());
    assert!(o.data == want, "object content differs");
}

#[test]
fn two_large_writes_in_one_message_keep_op_order() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let (a, b) = (pat(70_000, 3), pat(80_000, 4));
    // overlap: the later op wins
    let ops = vec![OsdOp::write(0, a.clone()), OsdOp::write(60_000, b.clone())];
    assert_eq!(result(&mut pg, &mut eng, 1, mkop(b"two", ops)), 0);
    let mut want = a;
    want.resize(60_000 + b.len(), 0);
    want[60_000..].copy_from_slice(&b);
    let objs = pg.store.objects(pg.spg);
    assert!(objs.values().next().expect("object").data == want);
}
