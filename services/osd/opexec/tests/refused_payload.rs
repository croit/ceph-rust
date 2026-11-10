// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! An op whose data segment was refused at intake (msgr2 data probe, client-ops 5.4.1) never executes without it.
mod common;
use common::*;
use denc::types::EntityAddr;
use opexec::ClientReq;
use opwire::{OsdOp, errno};

fn req(tid: u64, op: opwire::MOSDOp) -> ClientReq {
    let a = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 9, [10, 0, 0, 5], 0);
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(op),
        who: client(7),
        addr: a,
        peer_addr: a,
        features: 0x3f17_ffff_fffd_ffff,
    }
}

/// The refusal stands when the limit at the engine would admit the declared size (raised between intake and here):
/// -EMSGSIZE, nothing logged, nothing written; the same object takes an ordinary write afterwards.
#[test]
fn a_refused_payload_is_answered_emsgsize_below_the_limit() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut op = mkop(b"obj", vec![OsdOp::write(0, Vec::new())]);
    op.refused_data = 1 << 20;
    eng.on_op(&mut pg, req(1, op));
    let mut o = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut o, 1, 1).unwrap().result, -errno::EMSGSIZE);
    assert!(pg.entries.is_empty(), "nothing logged");
    assert!(pg.store.objects(pg.spg).is_empty(), "nothing written");
    eng.on_op(
        &mut pg,
        req(2, mkop(b"obj", vec![OsdOp::write(0, b"x".to_vec())])),
    );
    let mut o = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut o, 1, 2).unwrap().result, 0);
}
