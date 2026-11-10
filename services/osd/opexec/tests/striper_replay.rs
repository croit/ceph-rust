// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! libcephsqlite / SimpleRADOSStriper op sequences (create, lock, open, write, unlock) through the production executor
//! (doc/spec/client-ops.md 11.4, cls_lock.md): the `.mgr` pool database of the mgr devicehealth module.
mod common;
use common::*;
use denc::Encoder;
use opexec::Engine;
use opwire::{MOSDOpReply, OsdOp, consts::cmp};

fn lock_in(unlock: bool) -> Vec<u8> {
    let mut e = Encoder::new();
    e.versioned(1, 1, |e| {
        e.bytes(b"striper.lock")?;
        if unlock {
            e.bytes(b"cookie")?;
        } else {
            e.u8(1)?; // exclusive
            e.bytes(b"cookie")?;
            e.bytes(b"")?; // tag
            e.bytes(b"SimpleRADOSStriper")?; // description
            e.u32(30)?; // duration utime sec
            e.u32(0)?;
            e.u8(0)?; // flags
        }
        Ok(())
    })
    .unwrap();
    e.into_vec()
}

fn go(pg: &mut TPg, eng: &mut Engine, tid: u64, ops: Vec<OsdOp>) -> MOSDOpReply {
    go_as(pg, eng, tid, 7, ops)
}

fn go_as(pg: &mut TPg, eng: &mut Engine, tid: u64, who: i64, ops: Vec<OsdOp>) -> MOSDOpReply {
    let mut out = run(
        pg,
        eng,
        1,
        tid,
        client(who),
        mkop(b"main.db.0000000000000000", ops),
    );
    reply_of(&mut out, 1, tid).expect("every op message is answered")
}

fn eq_str(name: &[u8], v: &[u8]) -> OsdOp {
    OsdOp::cmpxattr(name, v, cmp::EQ, cmp::MODE_STRING)
}

fn create() -> Vec<OsdOp> {
    vec![
        OsdOp::create(true),
        OsdOp::setxattr(b"striper.version", b"0"),
        OsdOp::setxattr(b"striper.excl", b""),
        OsdOp::setxattr(b"striper.size", b"0"),
        OsdOp::setxattr(b"striper.allocated", b"0"),
        OsdOp::setxattr(b"striper.layout.stripe_unit", b"1"),
        OsdOp::setxattr(b"striper.layout.stripe_count", b"1"),
        OsdOp::setxattr(b"striper.layout.object_size", b"4194304"),
    ]
}

fn lock(addr: &[u8]) -> Vec<OsdOp> {
    vec![
        OsdOp::call(b"lock", b"lock", &lock_in(false)),
        eq_str(b"striper.excl", b""),
        OsdOp::setxattr(b"striper.excl", addr),
    ]
}

fn unlock(addr: &[u8]) -> Vec<OsdOp> {
    vec![
        eq_str(b"striper.excl", addr),
        OsdOp::setxattr(b"striper.excl", b""),
        OsdOp::call(b"lock", b"unlock", &lock_in(true)),
    ]
}

fn open() -> Vec<OsdOp> {
    ["excl", "size", "allocated", "version"]
        .iter()
        .map(|n| OsdOp::getxattr(format!("striper.{n}").as_bytes()))
        .collect()
}

#[test]
fn striper_create_lock_open_write_unlock_cycle() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let r = go(&mut pg, &mut eng, 1, create());
    assert_eq!(r.result, 0, "exclusive create with empty/numeric xattrs");
    assert_eq!(
        go(&mut pg, &mut eng, 2, create()).result,
        -17,
        "second create = EEXIST"
    );
    for round in 0..2u64 {
        let t = 10 + round * 10;
        let r = go(&mut pg, &mut eng, t, lock(b"addr1"));
        assert_eq!(
            r.result, 0,
            "lock + cmpxattr(empty) + setxattr round {round}"
        );
        let r = go(&mut pg, &mut eng, t + 1, open());
        assert_eq!(r.result, 0);
        assert_eq!(&r.ops[0].outdata[..], b"addr1");
        assert_eq!(&r.ops[3].outdata[..], b"0");
        let r = go(
            &mut pg,
            &mut eng,
            t + 2,
            vec![
                OsdOp::write(0, vec![7; 4096]),
                OsdOp::setxattr(b"striper.size", b"4096"),
            ],
        );
        assert_eq!(r.result, 0);
        // a second locker is refused while the first holds the lock
        let r = go_as(&mut pg, &mut eng, t + 3, 8, lock(b"addr2"));
        assert_eq!(r.result, -16, "EBUSY");
        let r = go(&mut pg, &mut eng, t + 4, unlock(b"addr1"));
        assert_eq!(r.result, 0, "unlock round {round}");
    }
    let r = go(&mut pg, &mut eng, 90, open());
    assert_eq!(
        (&r.ops[0].outdata[..], &r.ops[1].outdata[..]),
        (&b""[..], &b"4096"[..])
    );
}

/// A failing guard rolls the lock taken in the same message back.
#[test]
fn striper_guard_failure_rolls_the_lock_back() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(go(&mut pg, &mut eng, 1, create()).result, 0);
    let _ = go(
        &mut pg,
        &mut eng,
        3,
        vec![OsdOp::setxattr(b"striper.excl", b"stale")],
    );
    let r = go(&mut pg, &mut eng, 4, lock(b"addr2"));
    assert_eq!(r.result, -125);
    // the rolled back lock is free again: after the stale guard is cleared a second client gets in
    let _ = go(
        &mut pg,
        &mut eng,
        5,
        vec![OsdOp::setxattr(b"striper.excl", b"")],
    );
    let r = go_as(&mut pg, &mut eng, 6, 8, lock(b"addr3"));
    assert_eq!(r.result, 0);
}
