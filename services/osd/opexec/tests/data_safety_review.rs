// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Regression tests for the op-executor findings of the OSD data-safety review 2026-11-03
//! (doc/reviews/2026-11-03-osd-data-safety-review.md, sections 4, 7, 11, 15, 16).
mod common;
use common::*;
use denc::types::{Hobject, SnapId};
use opwire::{MOSDOp, MOSDOpReply, OsdOp, consts::csum, consts::op as code, errno};
use replwire::{ObjectInfo, SnapSet};

fn mk(oid: &str, ops: Vec<OsdOp>) -> MOSDOp {
    mkop(oid.as_bytes(), ops)
}

fn with_snapc(mut op: MOSDOp, seq: u64, snaps: &[u64]) -> MOSDOp {
    op.snap_seq = seq;
    op.snaps = snaps.to_vec();
    op
}

fn go(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, op: MOSDOp) -> MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    reply_of(&mut outs, 1, tid).expect("reply")
}

fn obj(oid: &str, snap: SnapId) -> Hobject {
    let mut h = Hobject::new(oid.as_bytes(), snap, 0x1234_5678, POOL as i64, b"");
    h.set_key(b"");
    h
}

fn head(oid: &str) -> Hobject {
    obj(oid, SnapId::NOSNAP)
}

fn state(pg: &TPg, oid: &str) -> (ObjectInfo, SnapSet) {
    let objs = pg.store.objects(pg.spg);
    let o = objs.get(&head(oid)).expect("head exists");
    let oi = denc::from_slice(o.xattrs.get(b"_".as_slice()).expect("oi")).unwrap();
    let ss = denc::from_slice(o.xattrs.get(b"snapset".as_slice()).expect("ss")).unwrap();
    (oi, ss)
}

/// `op` with the CephFS truncate hint `(seq, size)`.
fn with_hint(mut op: OsdOp, seq: u32, size: u64) -> OsdOp {
    let mut e = op.extent();
    e.truncate_seq = seq;
    e.truncate_size = size;
    op.set_extent(e);
    op
}

fn checksum(off: u64, len: u64, chunk: u32) -> OsdOp {
    let mut o = OsdOp::new(code::CHECKSUM);
    o.set_checksum(opwire::Checksum {
        offset: off,
        length: len,
        chunk_size: chunk,
        ty: csum::CRC32C,
    });
    o.indata = 0u32.to_le_bytes().to_vec().into();
    o
}

/// #4: rollback takes size, digests and the omap flag from the clone, never its truncate_seq / truncate_size (spec
/// client-ops 8.3): the head's truncate sequence must not go backwards, else a delayed write that carries the newer
/// truncate hint truncates the rolled-back content again.
#[test]
fn rollback_keeps_the_head_truncate_hint() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let w = mk("r", vec![OsdOp::write(0, vec![b'A'; 8192])]);
    assert_eq!(go(&mut pg, &mut eng, 1, w).result, 0);
    // snap 5, then a CephFS truncate (seq 2, size 4 KiB): clone 5 keeps 8 KiB and seq 0
    let t = with_snapc(
        mk("r", vec![with_hint(OsdOp::truncate(4096), 2, 4096)]),
        5,
        &[5],
    );
    assert_eq!(go(&mut pg, &mut eng, 2, t).result, 0);
    let (oi, ss) = state(&pg, "r");
    assert_eq!((oi.size, oi.truncate_seq, ss.clones.len()), (4096, 2, 1));
    // rollback to snap 5: the clone's content and size, the head's truncate hint
    let rb = with_snapc(mk("r", vec![OsdOp::rollback(5)]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 3, rb).result, 0);
    let (oi, _) = state(&pg, "r");
    assert_eq!(
        (oi.size, oi.truncate_seq, oi.truncate_size),
        (8192, 2, 4096),
        "rollback took the clone's truncate hint"
    );
    // a delayed write carrying the hint the head has seen already: no second truncate
    let late = with_snapc(
        mk(
            "r",
            vec![with_hint(OsdOp::write(0, b"x".to_vec()), 2, 4096)],
        ),
        5,
        &[5],
    );
    assert_eq!(go(&mut pg, &mut eng, 4, late).result, 0);
    assert_eq!(
        state(&pg, "r").0.size,
        8192,
        "stale truncate clipped the rolled-back data"
    );
}

/// #7: after a failed write the engine drops the head's projected state while later writes of the head are still in
/// flight; the snap trimmer must not plan from the store state then (it does not hold those writes yet, the step
/// would revert their object info and SnapSet). It waits for the drain and plans from the reloaded state.
#[test]
fn snap_trim_waits_for_writes_in_flight_after_a_failed_write() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            1,
            mk("t", vec![OsdOp::write(0, b"AAAA".to_vec())])
        )
        .result,
        0
    );
    // snap 5 taken: the next write clones
    let w = with_snapc(mk("t", vec![OsdOp::write(0, b"B".to_vec())]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 2, w).result, 0);
    let clone = obj("t", SnapId(5));
    assert!(pg.store.objects(pg.spg).contains_key(&clone));
    // two writes in flight: W1 fails in the backend, W2 (planned before that) commits and grows the object
    pg.hold = true;
    let out = run(
        &mut pg,
        &mut eng,
        1,
        3,
        client(7),
        mk("t", vec![OsdOp::write(0, b"XX".to_vec())]),
    );
    assert!(out.is_empty());
    let out = run(
        &mut pg,
        &mut eng,
        1,
        4,
        client(7),
        mk("t", vec![OsdOp::write(4, b"DDDD".to_vec())]),
    );
    assert!(out.is_empty());
    let held = pg.held_tids();
    assert_eq!(held.len(), 2);
    let mut out = pg.release(&mut eng, held[0], -errno::EIO);
    assert_eq!(
        reply_of(&mut out, 1, 3).expect("W1 reply").result,
        -errno::EIO
    );
    // snap 5 removed: the trimmer runs while W2 is still in flight
    pg.removed = vec![(5, 1)];
    pg.trim = Some((5, vec![clone.clone()]));
    eng.trim_kick(&mut pg);
    assert_eq!(
        pg.held_tids(),
        vec![held[1]],
        "trim step planned from the store state while a write of the head is in flight"
    );
    let mut out = pg.release(&mut eng, held[1], 0);
    assert_eq!(reply_of(&mut out, 1, 4).expect("W2 reply").result, 0);
    // the trimmer's retry plans from the reloaded state
    for _ in 0..8 {
        pg.now += 2 * peering::SEC;
        let now = pg.now;
        eng.tick(&mut pg, now);
        while let Some(&t) = pg.held_tids().first() {
            pg.release(&mut eng, t, 0);
        }
        if pg.trim.is_none() {
            break;
        }
    }
    assert!(pg.trim.is_none(), "snap 5 never finished trimming");
    let (oi, ss) = state(&pg, "t");
    assert_eq!(oi.size, 8, "the trim step reverted W2's size");
    assert!(ss.clones.is_empty(), "{ss:?}");
    assert!(!pg.store.objects(pg.spg).contains_key(&clone));
    let r = go(&mut pg, &mut eng, 5, mk("t", vec![OsdOp::read(0, 100)]));
    assert_eq!(r.ops[0].outdata, &b"BAAADDDD"[..]);
}

/// #7 sibling: a failed trim step drops the head state it projected (it never happened), like a failed client write:
/// an op that arrives while a write planned on top of it is still in flight waits instead of planning from it.
#[test]
fn failed_snap_trim_step_drops_its_projected_head_state() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let w = mk("f", vec![OsdOp::write(0, b"AAAA".to_vec())]);
    assert_eq!(go(&mut pg, &mut eng, 1, w).result, 0);
    let w = with_snapc(mk("f", vec![OsdOp::write(0, b"B".to_vec())]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 2, w).result, 0);
    let clone = obj("f", SnapId(5));
    pg.hold = true;
    pg.removed = vec![(5, 1)];
    pg.trim = Some((5, vec![clone.clone()]));
    eng.trim_kick(&mut pg);
    let step = pg.held_tids();
    assert_eq!(step.len(), 1, "trim step submitted");
    // W3 is planned on top of the step's projected state (pipelined); then the step fails
    let out = run(
        &mut pg,
        &mut eng,
        1,
        3,
        client(7),
        mk("f", vec![OsdOp::write(4, b"CC".to_vec())]),
    );
    assert!(out.is_empty());
    let w3 = pg.held_tids()[1];
    pg.trim = None;
    pg.release(&mut eng, step[0], -errno::EIO);
    // W4 must wait for W3 (the cached state is gone) instead of planning from the failed step's SnapSet
    let out = run(
        &mut pg,
        &mut eng,
        1,
        4,
        client(7),
        mk("f", vec![OsdOp::write(6, b"DD".to_vec())]),
    );
    assert!(out.is_empty());
    assert_eq!(
        pg.held_tids(),
        vec![w3],
        "W4 planned from a trim step that failed"
    );
}

/// #11: DELETE of a whiteout head removes it (result 0, log DELETE) unless the delete would leave a whiteout again
/// (spec client-ops 7.2 delete).
#[test]
fn delete_removes_a_whiteout_head_unless_it_whiteouts_again() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let w = mk("w", vec![OsdOp::write(0, b"one".to_vec())]);
    assert_eq!(go(&mut pg, &mut eng, 1, w).result, 0);
    let d = with_snapc(mk("w", vec![OsdOp::delete()]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 2, d).result, 0);
    assert!(state(&pg, "w").0.is_whiteout());
    // the clone still exists: the delete would whiteout again -> ENOENT, nothing changes
    let n = pg.entries.len();
    let d = with_snapc(mk("w", vec![OsdOp::delete()]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 3, d).result, -errno::ENOENT);
    assert!(state(&pg, "w").0.is_whiteout());
    assert_eq!(pg.entries.last().unwrap().op, pgwire::LogOp::ERROR);
    assert_eq!(pg.entries.len(), n + 1);
    // the clone is gone and the head's SnapSet lists none (a whiteout left behind): the delete removes the head
    {
        let p = pg.store.pgs.get_mut(&pg.spg).expect("pg");
        p.objects.remove(&obj("w", SnapId(5)));
        let h = p.objects.get_mut(&head("w")).expect("head");
        let mut ss: SnapSet = denc::from_slice(&h.xattrs[b"snapset".as_slice()]).unwrap();
        ss.clones.clear();
        ss.clone_size.clear();
        ss.clone_overlap.clear();
        ss.clone_snaps.clear();
        h.xattrs
            .insert(b"snapset".to_vec(), denc::to_vec(&ss).unwrap());
    }
    pg.foreign();
    let d = with_snapc(mk("w", vec![OsdOp::delete()]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 4, d).result, 0, "whiteout delete");
    assert_eq!(pg.entries.last().unwrap().op, pgwire::LogOp::DELETE);
    assert!(!pg.store.objects(pg.spg).contains_key(&head("w")));
    let d = mk("w", vec![OsdOp::delete()]);
    assert_eq!(go(&mut pg, &mut eng, 5, d).result, -errno::ENOENT);
}

/// #15: a store read shorter than the committed object size is a local failure (EIO), never a silently shortened
/// READ / SPARSE_READ / CHECKSUM / CMPEXT / cls read reply (the copy path's rule).
#[test]
fn short_store_read_is_eio() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let w = mk("s", vec![OsdOp::write(0, b"0123456789".to_vec())]);
    assert_eq!(go(&mut pg, &mut eng, 1, w).result, 0);
    // the store holds fewer bytes than the object info says (a store or view bug)
    pg.store
        .pgs
        .get_mut(&pg.spg)
        .expect("pg")
        .objects
        .get_mut(&head("s"))
        .expect("head")
        .data
        .truncate(6);
    pg.foreign();
    let ops = [
        OsdOp::read(0, 10),
        OsdOp::read(4, 0),
        OsdOp::sparse_read(0, 10),
        checksum(0, 10, 0),
        OsdOp::call(b"hello", b"replay", b""),
        // the missing bytes must not compare as zeros
        OsdOp::cmpext(6, vec![0; 4]),
    ];
    for (i, op) in ops.into_iter().enumerate() {
        let name = code::name(op.op).unwrap_or("?");
        let r = go(&mut pg, &mut eng, 10 + i as u64, mk("s", vec![op]));
        assert_eq!(r.result, -errno::EIO, "{name}: short read answered");
    }
    // what the store does hold stays readable
    let r = go(&mut pg, &mut eng, 20, mk("s", vec![OsdOp::read(0, 6)]));
    assert_eq!((r.result, &r.ops[0].outdata[..]), (0, &b"012345"[..]));
}

/// #15 boundary: reads inside a mutating message see the committed content, clipped to the message's working size
/// (golden 33_vis_size_exist): a read beyond the committed size of an object the message grew is not short.
#[test]
fn read_after_growing_write_in_the_same_message_is_not_short() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let w = mk("g", vec![OsdOp::write(0, b"q".to_vec())]);
    assert_eq!(go(&mut pg, &mut eng, 1, w).result, 0);
    let mut m = mk(
        "g",
        vec![
            OsdOp::write(0, b"abcdef".to_vec()),
            OsdOp::read(0, 10),
            OsdOp::sparse_read(0, 10),
            checksum(0, 0, 0),
        ],
    );
    m.flags |= opwire::flag::RETURNVEC;
    let r = go(&mut pg, &mut eng, 2, m);
    assert_eq!(r.result, 0);
    assert_eq!(r.ops[1].outdata, &b"q"[..]);
}

/// 16.1 (E7/F3): the reply shape of `checksum` — `u32 count` is always there on the count-0 paths; only a range past
/// the object end that is not the (0,0) whole-object shortcut answers with no outdata at all.
#[test]
fn checksum_zero_chunk_count_and_whole_object_reply() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let data = b"0123456789abcdef";
    let w = mk("c", vec![OsdOp::write(0, data.to_vec())]);
    assert_eq!(go(&mut pg, &mut eng, 1, w).result, 0);
    let count = |r: &MOSDOpReply| {
        if r.ops[0].outdata.is_empty() {
            None
        } else {
            Some(opwire::ChecksumOut::decode(csum::CRC32C, &r.ops[0].outdata).unwrap())
        }
    };
    // whole object: one value over all 16 bytes
    let r = go(&mut pg, &mut eng, 2, mk("c", vec![checksum(0, 0, 0)]));
    assert_eq!(r.result, 0);
    let out = count(&r).expect("u32 count present");
    assert_eq!(out.values.len(), 1);
    assert_eq!(out.values[0], u64::from(crc::crc32c(0, data)));
    // offset > 0, length 0: nothing to checksum -> count 0 (four zero bytes), NOT the rest of the object
    let r = go(&mut pg, &mut eng, 3, mk("c", vec![checksum(4, 0, 0)]));
    assert_eq!(r.result, 0);
    assert_eq!(r.ops[0].outdata.to_vec(), vec![0u8; 4]);
    assert!(count(&r).unwrap().values.is_empty());
    // whole object on an empty object -> count 0
    assert_eq!(
        go(&mut pg, &mut eng, 4, mk("e", vec![OsdOp::create(false)])).result,
        0
    );
    let r = go(&mut pg, &mut eng, 5, mk("e", vec![checksum(0, 0, 0)]));
    assert_eq!(r.result, 0);
    assert_eq!(
        r.ops[0].outdata.to_vec(),
        vec![0u8; 4],
        "empty object: count 0"
    );
    // any other range past the end: success with no outdata
    for (i, (off, len)) in [(16, 4), (4, 16), (0, 0)].into_iter().enumerate() {
        let r = go(
            &mut pg,
            &mut eng,
            10 + i as u64,
            mk("e", vec![checksum(off, len, 0)]),
        );
        assert_eq!(r.result, 0, "{off} {len}");
        if off > 0 || len > 0 {
            assert!(r.ops[0].outdata.is_empty(), "{off} {len}: no outdata");
        }
    }
}

/// 16.1 (E7/F3): a length that reaches past the end is clipped, and the clipped length is re-checked against
/// chunk_size; `offset == 0 && length == 0` with chunk_size > 0 stays EINVAL.
#[test]
fn checksum_clips_and_rechecks_chunk_alignment() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            1,
            mk("c", vec![OsdOp::write(0, b"0123456789".to_vec())])
        )
        .result,
        0
    );
    // length 12 with chunk 4 clips to 10 -> not a multiple of 4
    let r = go(&mut pg, &mut eng, 2, mk("c", vec![checksum(4, 12, 4)]));
    assert_eq!(r.result, -errno::EINVAL);
    // length 8 with chunk 4 inside the object: two values
    let r = go(&mut pg, &mut eng, 3, mk("c", vec![checksum(0, 8, 4)]));
    assert_eq!(r.result, 0);
    let out = opwire::ChecksumOut::decode(csum::CRC32C, &r.ops[0].outdata).unwrap();
    assert_eq!(out.values.len(), 2);
}

/// #16: checksum validates the chunk rules (chunk_size > 0: length != 0 and a multiple of chunk_size) before the
/// object-end shortcut (spec client-ops 7.1, black-box note in 15).
#[test]
fn checksum_validates_chunk_rules_before_the_object_end() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let w = mk("c", vec![OsdOp::write(0, b"abcdefghijklmnop".to_vec())]);
    assert_eq!(go(&mut pg, &mut eng, 1, w).result, 0);
    let cases = [
        (100, 0, 8, -errno::EINVAL),
        (100, 12, 8, -errno::EINVAL),
        (16, 0, 4, -errno::EINVAL),
        (100, 16, 8, 0),
        (100, 0, 0, 0),
        (0, 0, 8, -errno::EINVAL),
    ];
    for (i, (off, len, chunk, want)) in cases.into_iter().enumerate() {
        let r = go(
            &mut pg,
            &mut eng,
            10 + i as u64,
            mk("c", vec![checksum(off, len, chunk)]),
        );
        assert_eq!(r.result, want, "checksum {off} {len} {chunk}");
        if want == 0 {
            assert!(r.ops[0].outdata.is_empty(), "past the end: empty outdata");
        }
    }
    // an empty object: the chunk rules still come first
    let w = mk("e", vec![OsdOp::create(false)]);
    assert_eq!(go(&mut pg, &mut eng, 30, w).result, 0);
    let r = go(&mut pg, &mut eng, 31, mk("e", vec![checksum(0, 0, 8)]));
    assert_eq!(r.result, -errno::EINVAL);
    let r = go(&mut pg, &mut eng, 32, mk("e", vec![checksum(0, 0, 0)]));
    assert_eq!(r.result, 0);
    assert_eq!(
        r.ops[0].outdata.to_vec(),
        vec![0u8; 4],
        "whole empty: count 0"
    );
}

/// #16: errors raised after the op vector ran (RETURNVEC -EOVERFLOW, local store -ENOSPC) are plain replies: nothing
/// is applied or logged (classic black-box: EOVERFLOW replay_version 0'0, no entry; adr 0021 S4 for no-room), so a
/// resend executes again and, with nothing changed in between, gets the same answer.
#[test]
fn overflow_and_no_room_are_plain_replies_and_resends_repeat_them() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let w = mk("v", vec![OsdOp::write(0, vec![b'a'; 100])]);
    assert_eq!(go(&mut pg, &mut eng, 1, w).result, 0);
    let n = pg.entries.len();
    let overflow = || {
        let mut m = mk(
            "v",
            vec![OsdOp::write(0, b"d".to_vec()), OsdOp::read(0, 65)],
        );
        m.flags |= opwire::flag::RETURNVEC;
        m
    };
    for tid in [2, 2] {
        let r = go(&mut pg, &mut eng, tid, overflow());
        assert_eq!(r.result, -errno::EOVERFLOW);
        assert_eq!(r.replay_version, denc::types::Eversion::default());
        assert_eq!(pg.entries.len(), n, "EOVERFLOW logged");
    }
    pg.room = false;
    for tid in [3, 3] {
        let w = mk("v", vec![OsdOp::write(0, b"z".to_vec())]);
        let r = go(&mut pg, &mut eng, tid, w);
        assert_eq!(r.result, -errno::ENOSPC);
        assert_eq!(pg.entries.len(), n, "ENOSPC logged");
    }
    pg.room = true;
    let r = go(&mut pg, &mut eng, 4, mk("v", vec![OsdOp::read(0, 1)]));
    assert_eq!(r.ops[0].outdata, &b"a"[..], "nothing applied");
}

/// Invalid on-disk overlap intervals must fail at the state-load boundary, before
/// write/rollback arithmetic can panic or wrap. Touching and empty intervals remain valid.
#[test]
fn malformed_clone_overlap_is_reported_before_mutation() {
    use std::collections::BTreeMap;
    for rollback in [false, true] {
        for overlap in [
            BTreeMap::from([(1, u64::MAX)]),
            BTreeMap::from([(0, 4), (2, 4)]),
        ] {
            let mut pg = TPg::new();
            let mut eng = engine(&pg);
            assert_eq!(
                go(
                    &mut pg,
                    &mut eng,
                    1,
                    mk("overlap", vec![OsdOp::writefull(b"original".to_vec())])
                )
                .result,
                0
            );
            let w = with_snapc(mk("overlap", vec![OsdOp::write(0, b"X".to_vec())]), 5, &[5]);
            assert_eq!(go(&mut pg, &mut eng, 2, w).result, 0);
            let (_, mut ss) = state(&pg, "overlap");
            // Valid interval sets may touch and contain zero lengths: neither
            // shape may become a reason to reject classic object metadata.
            ss.clone_overlap
                .insert(SnapId(5), BTreeMap::from([(0, 1), (1, 1), (3, 0)]));
            let h = head("overlap");
            let set_snapset = |pg: &mut TPg, ss: &SnapSet| {
                pg.store
                    .pgs
                    .get_mut(&pg.spg)
                    .unwrap()
                    .objects
                    .get_mut(&h)
                    .unwrap()
                    .xattrs
                    .insert(b"snapset".to_vec(), denc::to_vec(ss).unwrap());
                pg.foreign();
            };
            set_snapset(&mut pg, &ss);
            assert!(opexec::exec::load_state(&pg, pg.spg, &h).is_ok());
            ss.clone_overlap.insert(SnapId(5), overlap);
            set_snapset(&mut pg, &ss);
            let txns = pg.txns.len();
            let op = if rollback {
                OsdOp::rollback(5)
            } else {
                OsdOp::write(1, b"Y".to_vec())
            };
            let req = with_snapc(mk("overlap", vec![op]), 5, &[5]);
            assert_eq!(go(&mut pg, &mut eng, 3, req).result, -errno::EIO);
            assert_eq!(
                pg.txns.len(),
                txns,
                "malformed metadata must never be rewritten"
            );
            assert_eq!(state(&pg, "overlap").1, ss);
        }
    }
}
