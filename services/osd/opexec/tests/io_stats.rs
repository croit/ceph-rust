// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Client io counters of the primary (`num_read`, `num_read_kb`, `num_write`, `num_write_kb`; spec pg-io-stats.md 1):
//! per sub-op, KiB rounded up, a failed message counts nothing, FAILOK keeps the counts, cls primitives count like
//! the ops they stand for.
mod common;
use common::*;
use opexec::Engine;
use opwire::{OsdOp, consts::opflag};
use pgwire::IoCount;
use std::collections::{BTreeMap, BTreeSet};

/// Run one message, return (result, io it counted).
fn io_of(pg: &mut TPg, eng: &mut Engine, tid: u64, oid: &str, ops: Vec<OsdOp>) -> (i32, IoCount) {
    let before = pg.io;
    let mut outs = run(pg, eng, 1, tid, client(7), mkop(oid.as_bytes(), ops));
    let r = reply_of(&mut outs, 1, tid).expect("reply").result;
    let a = pg.io;
    (
        r,
        IoCount {
            rd: a.rd - before.rd,
            rd_kb: a.rd_kb - before.rd_kb,
            wr: a.wr - before.wr,
            wr_kb: a.wr_kb - before.wr_kb,
        },
    )
}

fn io(rd: i64, rd_kb: i64, wr: i64, wr_kb: i64) -> IoCount {
    IoCount {
        rd,
        rd_kb,
        wr,
        wr_kb,
    }
}

#[test]
fn kb_rounds_up_per_sub_op() {
    assert_eq!(IoCount::kb(0), 0);
    assert_eq!(IoCount::kb(1), 1);
    assert_eq!(IoCount::kb(1024), 1);
    assert_eq!(IoCount::kb(1025), 2);
    let mut s = pgwire::ObjectStatSum::default();
    s.add_io(&io(1, 2, 3, 4));
    s.add_io(&io(1, 2, 3, 4));
    assert_eq!(
        (s.num_read, s.num_read_kb, s.num_write, s.num_write_kb),
        (2, 4, 6, 8)
    );
}

#[test]
fn data_reads_and_writes() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    // create by write (general executor), then an overwrite (plain-overwrite fast path): both one write each
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            1,
            "a",
            vec![OsdOp::write(0, vec![1; 5000])]
        ),
        (0, io(0, 0, 1, 5))
    );
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            2,
            "a",
            vec![OsdOp::write(0, vec![2; 100])]
        ),
        (0, io(0, 0, 1, 1))
    );
    // read: bytes actually read (clipped to the object)
    assert_eq!(
        io_of(&mut pg, &mut eng, 3, "a", vec![OsdOp::read(0, 3000)]),
        (0, io(1, 3, 0, 0))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 4, "a", vec![OsdOp::read(4000, 8192)]),
        (0, io(1, 1, 0, 0))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 5, "a", vec![OsdOp::sparse_read(0, 2048)]),
        (0, io(1, 2, 0, 0))
    );
    // per sub-op, not per message
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            6,
            "a",
            vec![OsdOp::read(0, 10), OsdOp::stat(), OsdOp::read(0, 2000)]
        ),
        (0, io(3, 3, 0, 0))
    );
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            7,
            "a",
            vec![OsdOp::writefull(vec![3; 2048])]
        ),
        (0, io(0, 0, 1, 2))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 8, "a", vec![OsdOp::append(vec![4; 1])]),
        (0, io(0, 0, 1, 1))
    );
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            9,
            "a",
            vec![OsdOp::write(0, vec![5; 10]), OsdOp::read(0, 10)]
        ),
        (0, io(1, 1, 1, 1))
    );
}

#[test]
fn metadata_ops_and_size_changes() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    // CREATE counts nothing, SETXATTR one write without KiB
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            1,
            "m",
            vec![OsdOp::create(false), OsdOp::setxattr(b"k", &[7; 10])]
        ),
        (0, io(0, 0, 1, 0))
    );
    // GETXATTR: KiB of the value; STAT: no KiB
    assert_eq!(
        io_of(&mut pg, &mut eng, 2, "m", vec![OsdOp::getxattr(b"k")]),
        (0, io(1, 1, 0, 0))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 3, "m", vec![OsdOp::stat()]),
        (0, io(1, 0, 0, 0))
    );
    // CMPXATTR: KiB of the stored value
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            4,
            "m",
            vec![OsdOp::cmpxattr(b"k", &[7; 10], 1, 1)]
        ),
        (1, io(1, 1, 0, 0))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 5, "m", vec![OsdOp::rmxattr(b"k")]),
        (0, io(0, 0, 1, 0))
    );
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            6,
            "m",
            vec![OsdOp::write(0, vec![1; 4096])]
        )
        .1,
        io(0, 0, 1, 4)
    );
    // ZERO inside the object, TRUNCATE, ZERO past the end (no-op: nothing), DELETE: one write, no KiB
    assert_eq!(
        io_of(&mut pg, &mut eng, 7, "m", vec![OsdOp::zero(0, 100)]),
        (0, io(0, 0, 1, 0))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 8, "m", vec![OsdOp::truncate(1000)]),
        (0, io(0, 0, 1, 0))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 9, "m", vec![OsdOp::zero(5000, 100)]).1,
        io(0, 0, 0, 0)
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 10, "m", vec![OsdOp::delete()]),
        (0, io(0, 0, 1, 0))
    );
}

#[test]
fn omap_ops() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = BTreeMap::from([(b"key".to_vec(), vec![9; 3000])]);
    let set = OsdOp::omap_set_vals(&kv);
    let set_kb = IoCount::kb(set.indata.len() as u64);
    assert_eq!(
        io_of(&mut pg, &mut eng, 1, "o", vec![set]),
        (0, io(0, 0, 1, set_kb))
    );
    // reads: KiB of the encoded reply (entries + count + more flag)
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            2,
            "o",
            vec![OsdOp::omap_get_vals(b"", 10, b"")]
        ),
        (0, io(1, 3, 0, 0))
    );
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            3,
            "o",
            vec![OsdOp::omap_get_keys(b"", 10)]
        ),
        (0, io(1, 1, 0, 0))
    );
    assert_eq!(
        io_of(
            &mut pg,
            &mut eng,
            4,
            "o",
            vec![OsdOp::omap_set_header(vec![1; 5])]
        ),
        (0, io(0, 0, 1, 0))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 5, "o", vec![OsdOp::omap_get_header()]),
        (0, io(1, 1, 0, 0))
    );
    let rm = OsdOp::omap_rm_keys(&BTreeSet::from([b"key".to_vec()]));
    assert_eq!(
        io_of(&mut pg, &mut eng, 6, "o", vec![rm]),
        (0, io(0, 0, 1, 0))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 7, "o", vec![OsdOp::omap_clear()]),
        (0, io(0, 0, 1, 0))
    );
    // no omap any more: header read and clear count nothing
    assert_eq!(
        io_of(&mut pg, &mut eng, 8, "o", vec![OsdOp::omap_get_header()]),
        (0, io(0, 0, 0, 0))
    );
    assert_eq!(
        io_of(&mut pg, &mut eng, 9, "o", vec![OsdOp::omap_clear()]).1,
        io(0, 0, 0, 0)
    );
}

#[test]
fn failed_message_counts_nothing_failok_keeps_counts() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    io_of(
        &mut pg,
        &mut eng,
        1,
        "f",
        vec![OsdOp::write(0, vec![1; 2048])],
    );
    // a read of a missing object is refused before execution
    assert_eq!(
        io_of(&mut pg, &mut eng, 2, "nope", vec![OsdOp::read(0, 10)]).1,
        io(0, 0, 0, 0)
    );
    // the second sub-op fails: the first one's read is dropped with the message
    let (r, d) = io_of(
        &mut pg,
        &mut eng,
        3,
        "f",
        vec![OsdOp::read(0, 10), OsdOp::getxattr(b"missing")],
    );
    assert!(r < 0);
    assert_eq!(d, io(0, 0, 0, 0));
    // FAILOK: the failed getxattr still counts its read (no KiB), the message succeeds
    let mut g = OsdOp::getxattr(b"missing");
    g.flags |= opflag::FAILOK;
    assert_eq!(
        io_of(&mut pg, &mut eng, 4, "f", vec![g, OsdOp::read(0, 2048)]),
        (0, io(2, 2, 0, 0))
    );
    // a failed write (log-only entry: the guard compares unequal) counts nothing
    let guard = OsdOp::cmpxattr(b"missing", b"x", 1, 1);
    let (r, d) = io_of(
        &mut pg,
        &mut eng,
        5,
        "f",
        vec![OsdOp::write(0, vec![1; 10]), guard],
    );
    assert!(r < 0);
    assert_eq!(d, io(0, 0, 0, 0));
}

#[test]
fn cls_call_counts_its_primitives_not_itself() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = BTreeMap::from([(b"x".to_vec(), b"5".to_vec())]);
    io_of(&mut pg, &mut eng, 1, "c", vec![OsdOp::omap_set_vals(&kv)]);
    let mut e = denc::Encoder::new();
    e.bytes(b"x").unwrap();
    e.bytes(b"1").unwrap();
    // numops.add: one omap point read + one omap set
    let add = OsdOp::call(b"numops", b"add", &e.into_vec());
    assert_eq!(
        io_of(&mut pg, &mut eng, 2, "c", vec![add]),
        (0, io(1, 1, 1, 1))
    );
    // a method without store access counts nothing
    let hello = OsdOp::call(b"hello", b"say_hello", b"");
    assert_eq!(
        io_of(&mut pg, &mut eng, 3, "c", vec![hello]),
        (0, io(0, 0, 0, 0))
    );
}
