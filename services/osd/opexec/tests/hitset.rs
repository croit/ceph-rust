// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! PG_HITSET_LS / PG_HITSET_GET on a pool without hit sets (spec client-ops-misc.md 3).
mod common;
use common::*;
use opwire::{MOSDOpReply, OsdOp, errno, flag, op};

fn go(pg: &mut TPg, tid: u64, ops: Vec<OsdOp>) -> MOSDOpReply {
    let mut eng = engine(pg);
    let mut m = mkop(b"", ops);
    m.flags = flag::READ | flag::ONDISK;
    let mut out = run(pg, &mut eng, 1, tid, client(7), m);
    reply_of(&mut out, 1, tid).expect("reply")
}
fn get(sec: u32) -> OsdOp {
    let mut o = OsdOp::new(op::PG_HITSET_GET);
    o.u[..4].copy_from_slice(&sec.to_le_bytes());
    o
}

fn check(ec: bool) {
    let mut pg = TPg::new();
    pg.ec = ec;
    let r = go(&mut pg, 1, vec![OsdOp::new(op::PG_HITSET_LS)]);
    assert_eq!((r.result, r.ops[0].rval), (0, 0));
    assert_eq!(r.ops[0].outdata.as_ref(), [0, 0, 0, 0]);
    let r = go(&mut pg, 2, vec![get(12345)]);
    assert_eq!((r.result, r.ops[0].rval), (-errno::ENOENT, 0));
    assert!(r.ops[0].outdata.is_empty());
    // ops run in order and the first error aborts
    let r = go(&mut pg, 3, vec![get(1), OsdOp::new(op::PG_HITSET_LS)]);
    assert_eq!(r.result, -errno::ENOENT);
    assert!(r.ops[1].outdata.is_empty());
    let r = go(&mut pg, 4, vec![OsdOp::new(op::PG_HITSET_LS), get(1)]);
    assert_eq!(r.ops[0].outdata.as_ref(), [0, 0, 0, 0]);
    assert_eq!(r.result, -errno::ENOENT);
}

#[test]
fn hitset_ops_replicated() {
    check(false);
}

#[test]
fn hitset_ops_ec() {
    check(true);
}

#[test]
fn unknown_pg_opcode_returns_einval() {
    for ec in [false, true] {
        let mut pg = TPg::new();
        pg.ec = ec;
        // Valid RD/PG family bits, but no method with this opcode.
        let unknown = OsdOp::new(op::MODE_RD | op::TYPE_PG | 0xff);
        let r = go(&mut pg, 1, vec![unknown, OsdOp::new(op::PG_HITSET_LS)]);
        assert_eq!(r.result, -errno::EINVAL, "ec={ec}");
        assert!(r.ops[1].outdata.is_empty(), "execution stops at failure");
    }
}

#[test]
fn pg_errors_leave_per_op_rvals_zero() {
    for ec in [false, true] {
        let mut pg = TPg::new();
        pg.ec = ec;
        let mut missing = get(1);
        missing.flags |= opwire::opflag::FAILOK;
        let r = go(&mut pg, 1, vec![missing, OsdOp::new(op::PG_HITSET_LS)]);
        assert_eq!(r.result, -errno::ENOENT);
        assert!(r.ops.iter().all(|o| o.rval == 0), "ec={ec}");
        assert!(r.ops[1].outdata.is_empty(), "PG ops ignore FAILOK");
    }
}
