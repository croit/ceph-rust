// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! `getxattr` / `rmxattr` take `name_len` bytes and ignore `value_len` (client-ops 16.3); `setxattr` stays strict.
mod common;
use common::*;
use opwire::OsdOp;

fn go(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, ops: Vec<OsdOp>) -> opwire::MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), mkop(b"o", ops));
    reply_of(&mut outs, 1, tid).expect("reply")
}

/// `op` with `value_len` set as a client that declared bytes it did not send.
fn claiming(mut op: OsdOp, value_len: u32) -> OsdOp {
    let mut x = op.xattr();
    x.value_len = value_len;
    op.set_xattr(x);
    op
}

#[test]
fn getxattr_and_rmxattr_consume_only_the_name() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        go(&mut pg, &mut eng, 1, vec![OsdOp::setxattr(b"k", b"v")]).result,
        0
    );
    // getxattr: value_len says 99, indata holds only the 1-byte name -> the stored value comes back
    let r = go(
        &mut pg,
        &mut eng,
        2,
        vec![claiming(OsdOp::getxattr(b"k"), 99)],
    );
    assert_eq!(r.result, 0);
    assert_eq!(r.ops[0].outdata, &b"v"[..]);
    assert_eq!(
        r.ops[0].xattr().value_len,
        1,
        "reply carries the value length"
    );
    // a missing attribute is ENODATA, not the length error
    let r = go(
        &mut pg,
        &mut eng,
        3,
        vec![claiming(OsdOp::getxattr(b"nx"), 99)],
    );
    assert_eq!(r.result, -opwire::errno::ENODATA);
    // rmxattr ignores value_len too
    let r = go(
        &mut pg,
        &mut eng,
        4,
        vec![claiming(OsdOp::rmxattr(b"k"), 99)],
    );
    assert_eq!(r.result, 0);
    assert_eq!(
        go(&mut pg, &mut eng, 5, vec![OsdOp::getxattr(b"k")]).result,
        -opwire::errno::ENODATA
    );
    // setxattr still needs the declared value bytes
    let mut short = OsdOp::setxattr(b"k", b"v");
    short.indata = b"k".to_vec().into();
    assert_eq!(
        go(&mut pg, &mut eng, 6, vec![short]).result,
        -opwire::errno::EINVAL
    );
}
