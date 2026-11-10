// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! `list-snaps` on an inconsistent SnapSet (client-ops 16.10): every clone needs `clone_snaps`, `clone_overlap` and
//! `clone_size`; a missing one answers -EINVAL instead of a silently empty list.
mod common;
use common::*;
use denc::types::{Hobject, SnapId};
use opwire::{OsdOp, SNAPDIR, errno};

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

fn list_snaps(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64) -> opwire::MOSDOpReply {
    let mut m = mkop(b"s", vec![OsdOp::list_snaps()]);
    m.snapid = SNAPDIR;
    let mut outs = run(pg, eng, 1, tid, client(7), m);
    reply_of(&mut outs, 1, tid).expect("reply")
}

/// Rewrite the stored SnapSet of the head with `f` and drop the engine's object cache.
fn edit_ss(pg: &mut TPg, f: impl FnOnce(&mut replwire::SnapSet)) {
    let h = head("s");
    let o = pg
        .store
        .pgs
        .get_mut(&pg.spg)
        .expect("pg")
        .objects
        .get_mut(&h)
        .expect("head");
    let mut ss: replwire::SnapSet =
        denc::from_slice(o.xattrs.get(b"snapset".as_slice()).expect("snapset")).unwrap();
    f(&mut ss);
    o.xattrs
        .insert(b"snapset".to_vec(), denc::to_vec(&ss).unwrap());
    pg.foreign();
}

#[test]
fn list_snaps_refuses_an_inconsistent_snapset() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        list_snaps(&mut pg, &mut eng, 0).result,
        -errno::ENOENT,
        "no object yet"
    );
    assert_eq!(
        run(
            &mut pg,
            &mut eng,
            1,
            1,
            client(7),
            mkop(b"s", vec![OsdOp::write(0, b"abcdefgh".to_vec())])
        )
        .len(),
        1
    );
    // snap 3 + delete: clone 3 + whiteout head, a consistent SnapSet
    let mut d = mkop(b"s", vec![OsdOp::delete()]);
    d.snap_seq = 3;
    d.snaps = vec![3];
    assert_eq!(
        run(&mut pg, &mut eng, 1, 2, client(7), d).len(),
        1,
        "delete replies"
    );
    let r = list_snaps(&mut pg, &mut eng, 3);
    assert_eq!(r.result, 0);
    let resp: opwire::ObjListSnapResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert_eq!(resp.clones.len(), 1);
    assert_eq!(resp.clones[0].cloneid, 3);

    for (what, edit) in [
        (
            "clone_snaps",
            Box::new(|ss: &mut replwire::SnapSet| {
                ss.clone_snaps.clear();
            }) as Box<dyn FnOnce(&mut replwire::SnapSet)>,
        ),
        (
            "clone_overlap",
            Box::new(|ss: &mut replwire::SnapSet| {
                ss.clone_overlap.clear();
            }),
        ),
        (
            "clone_size",
            Box::new(|ss: &mut replwire::SnapSet| {
                ss.clone_size.clear();
            }),
        ),
    ] {
        // start from a consistent snapset each round
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        run(
            &mut pg,
            &mut eng,
            1,
            1,
            client(7),
            mkop(b"s", vec![OsdOp::write(0, b"abcdefgh".to_vec())]),
        );
        let mut d = mkop(b"s", vec![OsdOp::delete()]);
        d.snap_seq = 3;
        d.snaps = vec![3];
        run(&mut pg, &mut eng, 1, 2, client(7), d);
        assert_eq!(list_snaps(&mut pg, &mut eng, 3).result, 0);
        edit_ss(&mut pg, edit);
        let r = list_snaps(&mut pg, &mut eng, 4);
        assert_eq!(r.result, -errno::EINVAL, "missing {what}");
        assert!(r.ops[0].outdata.is_empty(), "no outdata on {what}");
    }
}

#[test]
fn map_snap_clone_requires_snapset_membership() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    run(
        &mut pg,
        &mut eng,
        1,
        1,
        client(7),
        mkop(b"s", vec![OsdOp::writefull(b"before".to_vec())]),
    );
    let mut w = mkop(b"s", vec![OsdOp::writefull(b"after".to_vec())]);
    w.snap_seq = 3;
    w.snaps = vec![3];
    run(&mut pg, &mut eng, 1, 2, client(7), w);
    let mut read = mkop(b"s", vec![OsdOp::read(0, 100)]);
    read.snapid = 3;
    read.flags |= opwire::flag::MAP_SNAP_CLONE;
    let mut outs = run(&mut pg, &mut eng, 1, 3, client(7), read.clone());
    assert_eq!(
        reply_of(&mut outs, 1, 3).unwrap().ops[0].outdata,
        &b"before"[..]
    );
    // A stale physical clone must not become visible through MAP_SNAP_CLONE
    // once the authoritative SnapSet no longer references it.
    edit_ss(&mut pg, |ss| {
        ss.clones.clear();
    });
    let mut outs = run(&mut pg, &mut eng, 1, 4, client(7), read.clone());
    let reply = reply_of(&mut outs, 1, 4).expect("reply");
    assert_eq!(reply.result, -errno::ENOENT);
    assert!(reply.ops[0].outdata.is_empty());
    read.snapid = 4;
    let mut outs = run(&mut pg, &mut eng, 1, 5, client(7), read);
    let reply = reply_of(&mut outs, 1, 5).expect("newer snap resolves head");
    assert_eq!(reply.result, 0);
    assert_eq!(reply.ops[0].outdata, &b"after"[..]);
}
