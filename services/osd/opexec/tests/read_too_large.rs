// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! A reply op's payload carries a u32 length on the wire: a read range past it (only reachable with an
//! `osd_max_object_size` above 4 GiB, or a corrupt stored size) is refused up front, never truncated or answered from
//! a short store read.

mod common;
use common::*;
use denc::types::{Hobject, SnapId};
use opexec::Engine;
use opwire::{OsdOp, errno};
use replwire::ObjectInfo;

/// Just past u32::MAX.
const BIG: u64 = (1 << 32) + 4096;

fn head(oid: &str) -> Hobject {
    let mut h = Hobject::new(
        oid.as_bytes(),
        SnapId::NOSNAP,
        0x1234_5678,
        POOL as i64,
        b"",
    );
    h.set_key(b"");
    h
}

fn put(pg: &mut TPg, eng: &mut Engine) {
    let mut outs = run(
        pg,
        eng,
        1,
        1,
        client(7),
        mkop(b"o", vec![OsdOp::writefull(b"hello".to_vec())]),
    );
    assert_eq!(reply_of(&mut outs, 1, 1).expect("reply").result, 0);
    // the stored object_info says the object is larger than a reply payload can carry
    let o = pg
        .store
        .pgs
        .get_mut(&pg.spg)
        .expect("pg")
        .objects
        .get_mut(&head("o"))
        .expect("object");
    let mut oi: ObjectInfo = denc::from_slice(o.xattrs.get(b"_".as_slice()).expect("oi")).unwrap();
    oi.size = BIG;
    o.xattrs
        .insert(b"_".to_vec(), denc::to_vec(&oi).expect("oi encodes"));
    pg.foreign();
}

#[test]
fn read_of_a_range_past_the_reply_length_is_refused() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    put(&mut pg, &mut eng);
    let mut outs = run(
        &mut pg,
        &mut eng,
        1,
        2,
        client(7),
        mkop(b"o", vec![OsdOp::read(0, 0)]),
    );
    assert_eq!(
        reply_of(&mut outs, 1, 2).expect("reply").result,
        -errno::EFBIG
    );
}

#[test]
fn sparse_read_of_a_range_past_the_reply_length_is_refused() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    put(&mut pg, &mut eng);
    let mut outs = run(
        &mut pg,
        &mut eng,
        1,
        2,
        client(7),
        mkop(b"o", vec![OsdOp::sparse_read(0, BIG)]),
    );
    assert_eq!(
        reply_of(&mut outs, 1, 2).expect("reply").result,
        -errno::EFBIG
    );
}
