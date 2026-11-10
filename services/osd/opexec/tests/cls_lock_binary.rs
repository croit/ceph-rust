// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Independent raw class inputs through the production executor; no lock-codec dependency.
mod common;
use common::*;
use denc::{Decoder, Encoder};
use opexec::Engine;
use opwire::{MOSDOpReply, OsdOp, opflag};

fn call(method: &[u8], input: &[u8]) -> OsdOp {
    OsdOp::call(b"lock", method, input)
}
fn input(fields: &[&[u8]], kind: bool, acquire: bool) -> Vec<u8> {
    let mut e = Encoder::new();
    e.versioned(1, 1, |e| {
        for (index, field) in fields.iter().enumerate() {
            e.bytes(field)?;
            if index == 0 && kind {
                e.u8(1)?;
            }
        }
        if acquire {
            e.u32(0)?;
            e.u32(0)?;
            e.u8(0)?;
        }
        Ok(())
    })
    .unwrap();
    e.into_vec()
}
fn go(pg: &mut TPg, engine: &mut Engine, tid: u64, ops: Vec<OsdOp>) -> MOSDOpReply {
    let mut out = run(pg, engine, 1, tid, client(7), mkop(b"binary-lock", ops));
    reply_of(&mut out, 1, tid).unwrap()
}
#[test]
fn raw_lock_class_preserves_binary_names_values_and_atomic_rollback() {
    let mut pg = TPg::new();
    let mut engine = engine(&pg);
    let name = b"\xffn\0alias";
    let canonical = b"\xffn";
    let cookie = b"\xfe\0c";
    let tag = b"\xfd\0t";
    let acquired = go(
        &mut pg,
        &mut engine,
        1,
        vec![call(
            b"lock",
            &input(&[name, cookie, tag, b"\xfc\0d"], true, true),
        )],
    );
    assert_eq!(acquired.result, 0);
    let listed = go(&mut pg, &mut engine, 2, vec![call(b"list_locks", b"")]);
    assert_eq!(listed.result, 0);
    assert_eq!(
        &listed.ops[0].outdata[..],
        b"\x01\x01\x0a\0\0\0\x01\0\0\0\x02\0\0\0\xffn"
    );
    let info = go(
        &mut pg,
        &mut engine,
        3,
        vec![
            call(b"get_info", &input(&[canonical], false, false)),
            OsdOp::getxattr(b"lock.\xffn"),
        ],
    );
    assert_eq!(info.result, 0);
    assert_eq!(
        info.ops[0].outdata, info.ops[1].outdata,
        "stored xattr and info preserve same binary fields"
    );
    assert!(
        info.ops[0]
            .outdata
            .windows(7)
            .any(|w| w == b"\x03\0\0\0\xfd\0t")
    );
    assert!(
        info.ops[0]
            .outdata
            .windows(7)
            .any(|w| w == b"\x03\0\0\0\xfc\0d")
    );
    let failed = go(
        &mut pg,
        &mut engine,
        4,
        vec![
            OsdOp::setxattr(b"rolled-back", b"bad"),
            call(b"assert_locked", &input(&[name, b"\xfe", tag], true, false)),
        ],
    );
    assert_eq!(failed.result, -16);
    let mut absent = OsdOp::getxattr(b"rolled-back");
    absent.flags = opflag::FAILOK;
    let check = go(
        &mut pg,
        &mut engine,
        5,
        vec![
            absent,
            call(
                b"assert_locked",
                &input(&[canonical, cookie, tag], true, false),
            ),
        ],
    );
    assert_eq!(check.result, 0);
    assert_eq!(check.ops[0].rval, -61);
    let changed = go(
        &mut pg,
        &mut engine,
        6,
        vec![call(
            b"set_cookie",
            &input(&[name, cookie, tag, b"\xfb\0new"], true, false),
        )],
    );
    assert_eq!(changed.result, 0);
    let unlocked = go(
        &mut pg,
        &mut engine,
        7,
        vec![call(
            b"unlock",
            &input(&[canonical, b"\xfb\0new"], false, false),
        )],
    );
    assert_eq!(unlocked.result, 0);
    let empty = go(
        &mut pg,
        &mut engine,
        8,
        vec![call(b"get_info", &input(&[canonical], false, false))],
    );
    assert_eq!(empty.result, 0);
    let mut d = Decoder::new(&empty.ops[0].outdata);
    d.versioned(1, |d, _| {
        assert_eq!(d.u32()?, 0);
        assert_eq!(d.u8()?, 1);
        assert_eq!(d.bytes()?, tag);
        assert!(d.is_empty());
        Ok(())
    })
    .unwrap();
    assert!(d.is_empty());
}
/// A class call's writes are only known after it ran; they must still pass the
/// store's room check: no room for one more entry -> ENOSPC, nothing applied.
#[test]
fn class_call_writes_are_refused_when_the_store_has_no_room() {
    let mut pg = TPg::new();
    let mut engine = engine(&pg);
    assert_eq!(
        go(&mut pg, &mut engine, 1, vec![OsdOp::create(false)]).result,
        0
    );
    pg.room_entries = Some(0);
    let refused = go(
        &mut pg,
        &mut engine,
        2,
        vec![call(b"lock", &input(&[b"n", b"c", b"t", b"d"], true, true))],
    );
    assert_eq!(refused.result, -28, "no room for the lock xattr");
    pg.room_entries = None;
    let mut absent = OsdOp::getxattr(b"lock.n");
    absent.flags = opflag::FAILOK;
    let check = go(&mut pg, &mut engine, 3, vec![absent]);
    assert_eq!(check.result, 0);
    assert_eq!(check.ops[0].rval, -61, "refused call left no lock behind");
}
