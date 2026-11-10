// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! RC-SPARSEEMPTY108: sparse zero range is empty; ordinary read zero means EOF.
mod common;
use common::*;
use opexec::Engine;
use opwire::{MOSDOpReply, OsdOp, SparseReadOut};

fn go(pg: &mut TPg, engine: &mut Engine, tid: u64, name: &[u8], ops: Vec<OsdOp>) -> MOSDOpReply {
    let mut request = mkop(name, ops);
    request.flags |= opwire::flag::READ | opwire::flag::RETURNVEC;
    let mut out = run(pg, engine, 1, tid, client(7), request);
    reply_of(&mut out, 1, tid).expect("completed reply")
}
fn empty(op: &OsdOp, offset: u64) {
    assert_eq!(op.rval, 0);
    assert_eq!(op.extent().offset, offset);
    assert_eq!(op.extent().length, 0);
    assert_eq!(op.outdata.as_ref(), &[0; 8]);
    assert_eq!(
        denc::from_slice::<SparseReadOut>(&op.outdata).unwrap(),
        SparseReadOut::default()
    );
}
#[test]
fn sparse_zero_never_reads_tail_or_warms_data_even_with_mutation() {
    let mut pg = TPg::new();
    let mut engine = engine(&pg);
    assert_eq!(
        go(
            &mut pg,
            &mut engine,
            1,
            b"sparse",
            vec![OsdOp::writefull(b"head-tail".to_vec())]
        )
        .result,
        0
    );
    for (i, offset) in [0, 3, 9, 100, u64::MAX].into_iter().enumerate() {
        pg.probes.borrow_mut().clear();
        let reply = go(
            &mut pg,
            &mut engine,
            2 + i as u64,
            b"sparse",
            vec![OsdOp::sparse_read(offset, 0)],
        );
        assert_eq!(reply.result, 0);
        empty(&reply.ops[0], offset);
        assert!(pg.probes.borrow().is_empty(), "empty sparse data probe");
    }
    pg.probes.borrow_mut().clear();
    let reply = go(
        &mut pg,
        &mut engine,
        7,
        b"sparse",
        vec![OsdOp::sparse_read(u64::MAX, 0), OsdOp::read(0, 1)],
    );
    assert_eq!(reply.result, 0);
    empty(&reply.ops[0], u64::MAX);
    assert_eq!(reply.ops[1].outdata.as_ref(), b"h");
    assert_eq!(
        *pg.probes.borrow(),
        vec![(0, 1)],
        "empty range must not widen another read's probe"
    );
    pg.probes.borrow_mut().clear();
    let reply = go(
        &mut pg,
        &mut engine,
        8,
        b"sparse",
        vec![OsdOp::sparse_read(2, 0), OsdOp::writefull(b"next".to_vec())],
    );
    assert_eq!(reply.result, 0);
    empty(&reply.ops[0], 2);
    assert!(
        pg.probes.borrow().is_empty(),
        "mixed empty sparse data probe"
    );
    let reply = go(&mut pg, &mut engine, 9, b"sparse", vec![OsdOp::read(0, 0)]);
    assert_eq!(reply.ops[0].outdata.as_ref(), b"next");
}
#[test]
fn sparse_empty_missing_bounded_and_plain_zero_read_contracts_remain_distinct() {
    let mut pg = TPg::new();
    let mut engine = engine(&pg);
    assert_eq!(
        go(&mut pg, &mut engine, 1, b"empty", vec![OsdOp::create(true)]).result,
        0
    );
    let reply = go(
        &mut pg,
        &mut engine,
        2,
        b"empty",
        vec![OsdOp::sparse_read(0, 0)],
    );
    assert_eq!(reply.result, 0);
    empty(&reply.ops[0], 0);
    let reply = go(
        &mut pg,
        &mut engine,
        3,
        b"missing",
        vec![OsdOp::sparse_read(0, 0)],
    );
    assert_eq!(reply.result, -opwire::errno::ENOENT);
    assert_eq!(
        go(
            &mut pg,
            &mut engine,
            4,
            b"sparse",
            vec![OsdOp::writefull(b"head-tail".to_vec())]
        )
        .result,
        0
    );
    let mut sync = OsdOp::read(2, 0);
    sync.op = opwire::op::SYNC_READ;
    let reply = go(
        &mut pg,
        &mut engine,
        5,
        b"sparse",
        vec![
            OsdOp::sparse_read(2, 2),
            OsdOp::read(2, 0),
            sync,
            OsdOp::sparse_read(2, 0),
        ],
    );
    assert_eq!(reply.result, 0);
    let sparse = denc::from_slice::<SparseReadOut>(&reply.ops[0].outdata).unwrap();
    assert_eq!(sparse.extents, [(2, 2)].into());
    assert_eq!(sparse.data, b"ad");
    assert_eq!(reply.ops[1].outdata.as_ref(), b"ad-tail");
    assert_eq!(reply.ops[2].outdata.as_ref(), b"ad-tail");
    empty(&reply.ops[3], 2);
}
