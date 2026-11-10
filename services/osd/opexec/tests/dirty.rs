// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! ISDIRTY / UNDIRTY and the DIRTY flag (spec client-ops-misc.md 2).
mod common;
use common::*;
use denc::types::{Hobject, SnapId};
use opexec::Engine;
use opwire::{MOSDOp, MOSDOpReply, NOSNAP, OsdOp, errno, op};
use replwire::{ObjectInfo, oi::flag as oif};

fn go(pg: &mut TPg, eng: &mut Engine, tid: u64, mut m: MOSDOp) -> MOSDOpReply {
    m.flags |= opwire::flag::RETURNVEC;
    let mut out = run(pg, eng, 1, tid, client(7), m);
    reply_of(&mut out, 1, tid).expect("reply")
}
fn head(name: &str, snap: u64) -> Hobject {
    let mut h = Hobject::new(name.as_bytes(), SnapId(snap), 0x1234_5678, POOL as i64, b"");
    h.set_key(b"");
    h
}
fn oi(pg: &TPg, name: &str, snap: u64) -> ObjectInfo {
    let objs = pg.store.objects(pg.spg);
    let o = objs.get(&head(name, snap)).expect("object");
    denc::from_slice(o.xattrs.get(b"_".as_slice()).expect("oi")).unwrap()
}
fn dirty(pg: &TPg, name: &str, snap: u64) -> bool {
    oi(pg, name, snap).flags & oif::DIRTY != 0
}
fn isdirty() -> OsdOp {
    OsdOp::new(op::ISDIRTY)
}
fn undirty() -> OsdOp {
    OsdOp::new(op::UNDIRTY)
}
fn w(name: &str, ops: Vec<OsdOp>) -> MOSDOp {
    mkop(name.as_bytes(), ops)
}
fn snapc(mut m: MOSDOp, seq: u64, snaps: &[u64]) -> MOSDOp {
    m.snap_seq = seq;
    m.snaps = snaps.to_vec();
    m
}

fn clear_and_flag_lifecycle(ec: bool) {
    let mut pg = TPg::new();
    pg.ec = ec;
    let mut eng = engine(&pg);
    // missing object: read-only message -> message ENOENT; write message answers the default state (0)
    assert_eq!(
        go(&mut pg, &mut eng, 1, w("o", vec![isdirty()])).result,
        -errno::ENOENT
    );
    let r = go(
        &mut pg,
        &mut eng,
        2,
        w("o", vec![isdirty(), OsdOp::create(false)]),
    );
    assert_eq!((r.result, r.ops[0].outdata.as_ref()), (0, &[0u8][..]));
    // every committed write leaves the object dirty; isdirty reports one byte
    assert!(dirty(&pg, "o", NOSNAP));
    let r = go(&mut pg, &mut eng, 3, w("o", vec![isdirty()]));
    assert_eq!((r.result, r.ops[0].outdata.as_ref()), (0, &[1u8][..]));
    // undirty: flag cleared with a new version, same user_version, one MODIFY entry
    let before = oi(&pg, "o", NOSNAP);
    let n = pg.entries.len();
    let r = go(&mut pg, &mut eng, 4, w("o", vec![undirty()]));
    assert_eq!(r.result, 0);
    assert!(r.ops[0].outdata.is_empty());
    let after = oi(&pg, "o", NOSNAP);
    assert_eq!(after.flags & oif::DIRTY, 0);
    assert!(after.version > before.version);
    assert_eq!(after.prior_version, before.version);
    assert_eq!(after.user_version, before.user_version);
    assert_eq!(pg.entries.len(), n + 1);
    assert_eq!(pg.entries[n].op, pgwire::LogOp::MODIFY);
    let r = go(&mut pg, &mut eng, 5, w("o", vec![isdirty()]));
    assert_eq!(r.ops[0].outdata.as_ref(), &[0u8][..]);
    // clean object: no-op write, object info untouched
    let r = go(&mut pg, &mut eng, 6, w("o", vec![undirty()]));
    assert_eq!(r.result, 0);
    assert_eq!(oi(&pg, "o", NOSNAP).version, after.version);
    // missing object: no-op, nothing created
    let r = go(&mut pg, &mut eng, 7, w("none", vec![undirty()]));
    assert_eq!(r.result, 0);
    assert!(!pg.store.objects(pg.spg).contains_key(&head("none", NOSNAP)));
    // write + isdirty reports the flag at message start, write + undirty ends clean but bumps user_version
    let r = go(
        &mut pg,
        &mut eng,
        8,
        w("o", vec![OsdOp::write(0, vec![1; 8]), isdirty()]),
    );
    assert_eq!(r.ops[1].outdata.as_ref(), &[0u8][..]);
    assert!(dirty(&pg, "o", NOSNAP));
    let uv = oi(&pg, "o", NOSNAP).user_version;
    let r = go(
        &mut pg,
        &mut eng,
        9,
        w("o", vec![undirty(), OsdOp::write(0, vec![2; 8])]),
    );
    assert_eq!(r.result, 0);
    let o = oi(&pg, "o", NOSNAP);
    assert_eq!(o.flags & oif::DIRTY, 0);
    assert_eq!(o.user_version, uv + 1);
    assert_eq!(o.size, 8);
}

#[test]
fn undirty_and_isdirty_replicated() {
    clear_and_flag_lifecycle(false);
}

#[test]
fn undirty_and_isdirty_ec_same_code_path() {
    clear_and_flag_lifecycle(true);
}

#[test]
fn clone_inherits_pre_clear_flag_and_snap_reads_see_the_clone_flag() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        w("c", vec![OsdOp::write(0, vec![1; 8])]),
    );
    assert!(dirty(&pg, "c", NOSNAP));
    let r = go(
        &mut pg,
        &mut eng,
        2,
        snapc(
            w("c", vec![undirty(), OsdOp::write(0, vec![2; 8])]),
            3,
            &[3],
        ),
    );
    assert_eq!(r.result, 0);
    assert!(!dirty(&pg, "c", NOSNAP), "head ends clean");
    assert!(dirty(&pg, "c", 3), "clone copied the flag before the clear");
    let mut m = w("c", vec![isdirty()]);
    m.snapid = 3;
    assert_eq!(
        go(&mut pg, &mut eng, 3, m).ops[0].outdata.as_ref(),
        &[1u8][..]
    );
    let r = go(&mut pg, &mut eng, 4, w("c", vec![isdirty()]));
    assert_eq!(r.ops[0].outdata.as_ref(), &[0u8][..]);
    // undirty at a snapid is refused like any write
    let mut m = w("c", vec![undirty()]);
    m.snapid = 3;
    assert!(go(&mut pg, &mut eng, 5, m).result < 0);
}

#[test]
fn whiteout_delete_is_dirty_and_undirty_clears_it() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        w("d", vec![OsdOp::write(0, vec![1; 8])]),
    );
    go(&mut pg, &mut eng, 2, w("d", vec![undirty()]));
    assert!(!dirty(&pg, "d", NOSNAP));
    // delete under a snap context leaves a whiteout, which is dirty
    let r = go(
        &mut pg,
        &mut eng,
        3,
        snapc(w("d", vec![OsdOp::delete()]), 5, &[5]),
    );
    assert_eq!(r.result, 0);
    assert!(oi(&pg, "d", NOSNAP).is_whiteout() && dirty(&pg, "d", NOSNAP));
    // undirty on the whiteout head: cleared, still a whiteout
    assert_eq!(go(&mut pg, &mut eng, 5, w("d", vec![undirty()])).result, 0);
    assert!(oi(&pg, "d", NOSNAP).is_whiteout() && !dirty(&pg, "d", NOSNAP));
}
