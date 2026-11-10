// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! A client op that hits a damaged local object waits for its repair from a peer instead of failing with EIO
//! (classic semantics for replicated pools, adr 0065); where no repair is possible the EIO is answered as before.
mod common;
use common::*;
use denc::types::{EntityAddr, Hobject, SnapId};
use opexec::{ClientReq, Engine};
use opwire::{OsdOp, errno};

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

fn read_req(tid: u64, oid: &str) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mkop(oid.as_bytes(), vec![OsdOp::read(0, 100)])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

fn put(pg: &mut TPg, eng: &mut Engine, oid: &str, data: &[u8]) {
    let mut outs = run(
        pg,
        eng,
        1,
        1,
        client(7),
        mkop(oid.as_bytes(), vec![OsdOp::writefull(data.to_vec())]),
    );
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
}

fn oi_slot<'a>(pg: &'a mut TPg, oid: &str) -> &'a mut Vec<u8> {
    pg.store
        .pgs
        .get_mut(&pg.spg)
        .unwrap()
        .objects
        .get_mut(&head(oid))
        .unwrap()
        .xattrs
        .get_mut(b"_".as_slice())
        .unwrap()
}

#[test]
fn read_of_a_damaged_object_waits_for_the_repair() {
    let mut pg = TPg::new();
    pg.repair = true;
    let mut eng = engine(&pg);
    put(&mut pg, &mut eng, "x", b"hello");
    let good = oi_slot(&mut pg, "x").clone();
    *oi_slot(&mut pg, "x") = vec![0xff; 3]; // object_info does not decode
    pg.foreign(); // the damage is found on a load: a cold object (no object-state cache entry)
    eng.on_op(&mut pg, read_req(2, "x"));
    assert!(settle(&mut pg, &mut eng).is_empty(), "no EIO, no reply");
    assert!(eng.has_parked());
    assert_eq!(pg.damaged, vec![head("x")]);
    assert_eq!(eng.c.parked_repair, 1);
    // still missing: the op stays parked, the PG is not asked again
    eng.retry(&mut pg);
    assert!(settle(&mut pg, &mut eng).is_empty());
    assert_eq!(pg.damaged.len(), 1);
    // the repair arrived: the op is served
    *oi_slot(&mut pg, "x") = good;
    pg.missing.clear();
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    let r = reply_of(&mut outs, 1, 2).expect("served after the repair");
    assert_eq!(r.result, 0);
    assert_eq!(&r.ops[0].outdata[..], b"hello");
}

#[test]
fn no_repair_possible_answers_eio() {
    let mut pg = TPg::new(); // repair = false: EC pool, not active, ...
    let mut eng = engine(&pg);
    put(&mut pg, &mut eng, "x", b"hello");
    *oi_slot(&mut pg, "x") = vec![0xff; 3];
    pg.foreign(); // the damage is found on a load: a cold object (no object-state cache entry)
    eng.on_op(&mut pg, read_req(2, "x"));
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, -errno::EIO);
    assert!(!eng.has_parked());
}

fn req(tid: u64, op: opwire::MOSDOp) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(op),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

/// `oid` written, snapshot 3 taken, `oid` overwritten: clone `oid@3` holds `before`.
fn with_clone(pg: &mut TPg, eng: &mut Engine, oid: &str, before: &[u8]) -> Hobject {
    put(pg, eng, oid, before);
    let mut w = mkop(oid.as_bytes(), vec![OsdOp::write(0, b"NEW".to_vec())]);
    w.snap_seq = 3;
    w.snaps = vec![3];
    let mut outs = run(pg, eng, 1, 10, client(7), w);
    assert_eq!(reply_of(&mut outs, 1, 10).unwrap().result, 0);
    let mut c = head(oid);
    c.snap = SnapId(3);
    assert!(pg.store.objects(pg.spg).contains_key(&c), "clone exists");
    c
}

fn clone_oi_slot<'a>(pg: &'a mut TPg, c: &Hobject) -> &'a mut Vec<u8> {
    pg.store
        .pgs
        .get_mut(&pg.spg)
        .unwrap()
        .objects
        .get_mut(c)
        .unwrap()
        .xattrs
        .get_mut(b"_".as_slice())
        .unwrap()
}

/// A snap read whose clone has an unreadable object_info repairs THE CLONE (not the head) and waits; a head op
/// behind it keeps its order; both are served after the repair.
#[test]
fn snap_read_of_a_damaged_clone_waits_for_the_clone_repair() {
    let mut pg = TPg::new();
    pg.repair = true;
    let mut eng = engine(&pg);
    let c = with_clone(&mut pg, &mut eng, "s", b"OLDDATA");
    let good = clone_oi_slot(&mut pg, &c).clone();
    *clone_oi_slot(&mut pg, &c) = vec![0xff; 3];
    let mut rd = mkop(b"s", vec![OsdOp::read(0, 100)]);
    rd.snapid = 3;
    eng.on_op(&mut pg, req(20, rd));
    assert!(settle(&mut pg, &mut eng).is_empty(), "no EIO, no ENOENT");
    assert_eq!(
        pg.damaged,
        vec![c.clone()],
        "the clone is repaired, not the head"
    );
    // a head write arriving meanwhile waits behind the parked snap read (per-object order)
    eng.on_op(
        &mut pg,
        req(21, mkop(b"s", vec![OsdOp::writefull(b"LATEST".to_vec())])),
    );
    assert!(settle(&mut pg, &mut eng).is_empty());
    *clone_oi_slot(&mut pg, &c) = good;
    pg.missing.clear();
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    let pos = |o: &Vec<opexec::Out>, tid: u64| {
        o.iter()
            .position(|x| matches!(x, opexec::Out::Reply { tid: t, .. } if *t == tid))
    };
    let (p20, p21) = (pos(&outs, 20), pos(&outs, 21));
    let r = reply_of(&mut outs, 1, 20).expect("snap read served");
    assert_eq!(r.result, 0);
    assert_eq!(&r.ops[0].outdata[..], b"OLDDATA");
    if let (Some(a), Some(b)) = (p20, p21) {
        assert!(a < b, "the snap read is answered before the later write");
    }
}

/// Rollback to a snapshot whose clone is damaged: the clone is the object to repair. Repairing the head (the op
/// target) would never cure the EIO: the op would be re-run and the head re-pulled forever.
#[test]
fn rollback_to_a_damaged_clone_repairs_the_clone() {
    let mut pg = TPg::new();
    pg.repair = true;
    let mut eng = engine(&pg);
    let c = with_clone(&mut pg, &mut eng, "r", b"OLDDATA");
    *clone_oi_slot(&mut pg, &c) = vec![0xff; 3];
    let mut rb = mkop(b"r", vec![OsdOp::rollback(3)]);
    rb.snap_seq = 3;
    rb.snaps = vec![3];
    eng.on_op(&mut pg, req(30, rb));
    assert!(settle(&mut pg, &mut eng).is_empty());
    assert_eq!(pg.damaged, vec![c]);
}

/// A write that arrives while a read of the same object waits for its repair is applied after the read is
/// answered: the read sees the old content.
#[test]
fn ops_behind_a_parked_repair_keep_their_order() {
    let mut pg = TPg::new();
    pg.repair = true;
    let mut eng = engine(&pg);
    put(&mut pg, &mut eng, "o", b"hello");
    let good = oi_slot(&mut pg, "o").clone();
    *oi_slot(&mut pg, "o") = vec![0xff; 3];
    pg.foreign(); // the damage is found on a load: a cold object (no object-state cache entry)
    eng.on_op(&mut pg, read_req(2, "o"));
    assert!(settle(&mut pg, &mut eng).is_empty());
    eng.on_op(
        &mut pg,
        req(3, mkop(b"o", vec![OsdOp::writefull(b"world".to_vec())])),
    );
    assert!(settle(&mut pg, &mut eng).is_empty(), "the write waits too");
    *oi_slot(&mut pg, "o") = good;
    pg.missing.clear();
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    let r = reply_of(&mut outs, 1, 2).expect("read");
    assert_eq!(&r.ops[0].outdata[..], b"hello");
    assert_eq!(reply_of(&mut outs, 1, 3).expect("write").result, 0);
}

/// FAILOK changes the reply contract, not the need to repair a damaged local data source.
#[test]
fn failok_data_error_still_waits_for_repair() {
    for sparse in [false, true] {
        let mut pg = TPg::new();
        pg.repair = true;
        let mut eng = engine(&pg);
        put(&mut pg, &mut eng, "f", b"hello");
        pg.store
            .pgs
            .get_mut(&pg.spg)
            .unwrap()
            .objects
            .get_mut(&head("f"))
            .unwrap()
            .data
            .truncate(2);
        let mut rd = if sparse {
            OsdOp::sparse_read(0, 5)
        } else {
            OsdOp::read(0, 5)
        };
        rd.flags |= opwire::opflag::FAILOK;
        eng.on_op(&mut pg, req(2, mkop(b"f", vec![rd, OsdOp::stat()])));
        assert!(
            settle(&mut pg, &mut eng).is_empty(),
            "FAILOK must not bypass repair"
        );
        assert_eq!(pg.damaged, vec![head("f")]);
        pg.store
            .pgs
            .get_mut(&pg.spg)
            .unwrap()
            .objects
            .get_mut(&head("f"))
            .unwrap()
            .data = b"hello".to_vec();
        pg.missing.clear();
        eng.retry(&mut pg);
        let mut outs = settle(&mut pg, &mut eng);
        let r = reply_of(&mut outs, 1, 2).expect("reply after repair");
        assert_eq!(r.result, 0);
        assert_eq!(r.ops[0].rval, 0);
        if sparse {
            let out: opwire::SparseReadOut = denc::from_slice(&r.ops[0].outdata).unwrap();
            assert_eq!(out.data, b"hello");
        } else {
            assert_eq!(r.ops[0].outdata, b"hello".as_slice());
        }
    }
}

#[test]
fn failok_data_error_without_repair_preserves_per_op_error() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    put(&mut pg, &mut eng, "f", b"hello");
    pg.store
        .pgs
        .get_mut(&pg.spg)
        .unwrap()
        .objects
        .get_mut(&head("f"))
        .unwrap()
        .data
        .truncate(2);
    let mut rd = OsdOp::read(0, 5);
    rd.flags |= opwire::opflag::FAILOK;
    eng.on_op(&mut pg, req(2, mkop(b"f", vec![rd, OsdOp::stat()])));
    let mut outs = settle(&mut pg, &mut eng);
    let r = reply_of(&mut outs, 1, 2).expect("reply when repair unavailable");
    assert_eq!(r.result, 0);
    assert_eq!(r.ops[0].rval, -errno::EIO);
    assert!(r.ops[0].outdata.is_empty());
    assert_eq!(r.ops[1].rval, 0);
    assert!(pg.damaged.is_empty());
}
