// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Pool snapshots (`rados mksnap`, snap.md / client-ops 5.7.1): in pool-snap mode the POOL's snap context drives
//! clone-on-write, the client's is ignored (unless ENFORCE_SNAPC); reads at a pool snap id, rollback, removal.
mod common;
use common::*;
use denc::types::{Hobject, SnapId};
use opexec::Engine;
use opwire::{MOSDOp, MOSDOpReply, NOSNAP, OsdOp, SNAPDIR, errno, flag as mflag};
use replwire::{SnapContext, SnapSet};

fn go(pg: &mut TPg, eng: &mut Engine, tid: u64, op: MOSDOp) -> MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    reply_of(&mut outs, 1, tid).expect("reply")
}

fn mk(ops: Vec<OsdOp>) -> MOSDOp {
    mkop(b"o", ops)
}

fn at(snap: u64, ops: Vec<OsdOp>) -> MOSDOp {
    let mut m = mk(ops);
    m.snapid = snap;
    m
}

fn snapset(pg: &TPg) -> SnapSet {
    let mut h = Hobject::new(b"o", SnapId::NOSNAP, 0x1234_5678, 1, b"");
    h.set_key(b"");
    let o = pg.store.objects(pg.spg).get(&h).cloned().expect("head");
    denc::from_slice(o.xattrs.get(b"snapset".as_slice()).expect("snapset")).unwrap()
}

fn pool_snaps(pg: &mut TPg, seq: u64, snaps: &[u64]) {
    pg.pool_snaps = Some(SnapContext {
        seq,
        snaps: snaps.to_vec(),
    });
}

fn read_at(pg: &mut TPg, eng: &mut Engine, tid: u64, snap: u64) -> MOSDOpReply {
    go(pg, eng, tid, at(snap, vec![OsdOp::read(0, 100)]))
}

#[test]
fn writes_use_the_pool_snap_context_not_the_clients() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    // pool in pool-snap mode, no snap yet
    pool_snaps(&mut pg, 0, &[]);
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            1,
            mk(vec![OsdOp::writefull(b"v1".to_vec())])
        )
        .result,
        0
    );
    // mksnap -> snap 1; the client knows nothing about it (empty snapc) and still gets a clone
    pool_snaps(&mut pg, 1, &[1]);
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            2,
            mk(vec![OsdOp::writefull(b"v2".to_vec())])
        )
        .result,
        0
    );
    let ss = snapset(&pg);
    assert_eq!(ss.seq, 1);
    assert_eq!(ss.clones, vec![SnapId(1)]);
    assert_eq!(ss.clone_snaps[&SnapId(1)], vec![SnapId(1)]);
    // second snap; the client sends garbage (invalid snapc): ignored, not EINVAL
    pool_snaps(&mut pg, 2, &[2, 1]);
    let mut w = mk(vec![OsdOp::writefull(b"v3".to_vec())]);
    w.snap_seq = 99;
    w.snaps = vec![5, 99];
    assert_eq!(go(&mut pg, &mut eng, 3, w).result, 0);
    let ss = snapset(&pg);
    assert_eq!((ss.seq, ss.clones.clone()), (2, vec![SnapId(1), SnapId(2)]));
    // reads at the pool snap ids and at the head
    assert_eq!(read_at(&mut pg, &mut eng, 4, 1).ops[0].outdata, &b"v1"[..]);
    assert_eq!(read_at(&mut pg, &mut eng, 5, 2).ops[0].outdata, &b"v2"[..]);
    assert_eq!(
        read_at(&mut pg, &mut eng, 6, NOSNAP).ops[0].outdata,
        &b"v3"[..]
    );
    // list-snaps shows both clones
    let r = go(&mut pg, &mut eng, 7, at(SNAPDIR, vec![OsdOp::list_snaps()]));
    let l: opwire::ObjListSnapResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert_eq!(
        l.clones.iter().map(|c| c.cloneid).collect::<Vec<_>>(),
        vec![1, 2, u64::MAX - 1]
    );
}

#[test]
fn without_pool_snap_mode_a_garbage_client_snapc_is_rejected() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut w = mk(vec![OsdOp::writefull(b"v".to_vec())]);
    w.snap_seq = 1;
    w.snaps = vec![5];
    assert_eq!(go(&mut pg, &mut eng, 1, w).result, -errno::EINVAL);
}

#[test]
fn enforce_snapc_makes_the_clients_context_win() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pool_snaps(&mut pg, 0, &[]);
    go(
        &mut pg,
        &mut eng,
        1,
        mk(vec![OsdOp::writefull(b"v1".to_vec())]),
    );
    pool_snaps(&mut pg, 1, &[1]);
    // the client says "no snaps" and insists: no clone
    let mut w = mk(vec![OsdOp::writefull(b"v2".to_vec())]);
    w.flags |= mflag::ENFORCE_SNAPC;
    assert_eq!(go(&mut pg, &mut eng, 2, w).result, 0);
    assert!(snapset(&pg).clones.is_empty());
    // ORDERSNAP sees the pool's seq: a client snapc older than the object's SnapSet is refused
    pool_snaps(&mut pg, 5, &[5]);
    go(
        &mut pg,
        &mut eng,
        3,
        mk(vec![OsdOp::writefull(b"v3".to_vec())]),
    );
    assert_eq!(snapset(&pg).seq, 5);
    pool_snaps(&mut pg, 3, &[3]);
    let mut w = mk(vec![OsdOp::writefull(b"v4".to_vec())]);
    w.flags |= mflag::ORDERSNAP;
    assert_eq!(go(&mut pg, &mut eng, 4, w).result, -errno::EOLDSNAPC);
}

#[test]
fn rollback_to_a_pool_snap() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pool_snaps(&mut pg, 0, &[]);
    go(
        &mut pg,
        &mut eng,
        1,
        mk(vec![OsdOp::writefull(b"before".to_vec())]),
    );
    pool_snaps(&mut pg, 1, &[1]);
    go(
        &mut pg,
        &mut eng,
        2,
        mk(vec![OsdOp::writefull(b"after!".to_vec())]),
    );
    assert_eq!(
        go(&mut pg, &mut eng, 3, mk(vec![OsdOp::rollback(1)])).result,
        0
    );
    assert_eq!(
        read_at(&mut pg, &mut eng, 4, NOSNAP).ops[0].outdata,
        &b"before"[..]
    );
}

#[test]
fn a_removed_pool_snap_is_hidden_and_no_longer_cloned_for() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pool_snaps(&mut pg, 0, &[]);
    go(
        &mut pg,
        &mut eng,
        1,
        mk(vec![OsdOp::writefull(b"v1".to_vec())]),
    );
    pool_snaps(&mut pg, 1, &[1]);
    go(
        &mut pg,
        &mut eng,
        2,
        mk(vec![OsdOp::writefull(b"v2".to_vec())]),
    );
    assert_eq!(read_at(&mut pg, &mut eng, 3, 1).ops[0].outdata, &b"v1"[..]);
    // rmsnap 1: the pool context loses it (seq stays), the mon queues it for trimming: reads no longer see it
    pool_snaps(&mut pg, 1, &[]);
    pg.removed = vec![(1, 1)];
    assert_eq!(read_at(&mut pg, &mut eng, 4, 1).result, -errno::ENOENT);
    // a later write makes no clone (no live snap newer than the SnapSet)
    go(
        &mut pg,
        &mut eng,
        5,
        mk(vec![OsdOp::writefull(b"v3".to_vec())]),
    );
    assert_eq!(
        snapset(&pg).clones,
        vec![SnapId(1)],
        "the old clone stays until the trimmer runs"
    );
}
