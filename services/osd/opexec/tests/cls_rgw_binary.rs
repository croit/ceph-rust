// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Preserved RGW attributes keep their byte names through the production executor.
mod common;
use common::*;
use denc::Encoder;
use opwire::OsdOp;

#[test]
fn rgw_remove_preserves_binary_attributes_through_executor() {
    let mut pg = TPg::new();
    let mut engine = engine(&pg);
    let oid = b"binary-rgw";
    let mut out = run(
        &mut pg,
        &mut engine,
        1,
        1,
        client(7),
        mkop(
            oid,
            vec![
                OsdOp::writefull(b"payload".to_vec()),
                OsdOp::setxattr(b"user.rgw.\xff", b"first"),
                OsdOp::setxattr(b"user.rgw.\xfe", b"second"),
                OsdOp::setxattr(b"discard", b"unrelated"),
            ],
        ),
    );
    assert_eq!(reply_of(&mut out, 1, 1).unwrap().result, 0);
    let mut input = Encoder::new();
    input
        .versioned(1, 1, |e| {
            e.u32(1)?;
            e.bytes(b"user.rgw.")
        })
        .unwrap();
    let mut out = run(
        &mut pg,
        &mut engine,
        1,
        2,
        client(7),
        mkop(
            oid,
            vec![OsdOp::call(b"rgw", b"obj_remove", &input.into_vec())],
        ),
    );
    assert_eq!(reply_of(&mut out, 1, 2).unwrap().result, 0);
    let mut out = run(
        &mut pg,
        &mut engine,
        1,
        3,
        client(7),
        mkop(
            oid,
            vec![
                OsdOp::getxattr(b"user.rgw.\xff"),
                OsdOp::getxattr(b"user.rgw.\xfe"),
            ],
        ),
    );
    let reply = reply_of(&mut out, 1, 3).unwrap();
    assert_eq!(reply.result, 0);
    assert_eq!(reply.ops[0].outdata.as_ref(), b"first");
    assert_eq!(reply.ops[1].outdata.as_ref(), b"second");
}
