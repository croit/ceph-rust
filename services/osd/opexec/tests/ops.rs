// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Engine behaviour beyond the golden transcripts: versions, dups, snapshots/clones, whiteouts, rollback, ordering,
//! parking, watch/notify, pgnls.
mod common;
use common::*;
use denc::types::{EntityAddr, Hobject, OsdReqId, SnapId};
use opexec::{ClientReq, Engine, Out};
use opwire::{
    MOSDOpReply, NOSNAP, OsdOp, PgNlsResponse, SNAPDIR,
    consts::{notify as nop, watch_op},
    errno, flag as mflag,
};
use replwire::{ObjectInfo, SnapSet};

fn go(pg: &mut TPg, eng: &mut Engine, tid: u64, op: opwire::MOSDOp) -> MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    reply_of(&mut outs, 1, tid).expect("reply")
}

fn mk(oid: &str, ops: Vec<OsdOp>) -> opwire::MOSDOp {
    mkop(oid.as_bytes(), ops)
}

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

fn state(pg: &TPg, oid: &str) -> (ObjectInfo, SnapSet) {
    let objs = pg.store.objects(pg.spg);
    let o = objs.get(&head(oid)).expect("head exists");
    let oi = denc::from_slice(o.xattrs.get(b"_".as_slice()).expect("oi")).unwrap();
    let ss = denc::from_slice(o.xattrs.get(b"snapset".as_slice()).expect("ss")).unwrap();
    (oi, ss)
}

fn data(pg: &TPg, oid: &str) -> Vec<u8> {
    pg.store
        .objects(pg.spg)
        .get(&head(oid))
        .unwrap()
        .data
        .clone()
}

#[test]
fn write_versions_and_flags() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let r = go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::write(0, b"hello".to_vec())]),
    );
    assert_eq!(r.result, 0);
    assert_eq!(r.replay_version, denc::types::Eversion::new(10, 1));
    assert_eq!(r.user_version, 1);
    assert_eq!(r.bad_replay_version, denc::types::Eversion::new(10, 1));
    assert_eq!(
        r.flags & u64::from(mflag::ACK | mflag::ONDISK),
        u64::from(mflag::ACK | mflag::ONDISK)
    );
    let r2 = go(
        &mut pg,
        &mut eng,
        2,
        mk("a", vec![OsdOp::write(5, b"!".to_vec())]),
    );
    assert_eq!(r2.replay_version.version, 2);
    assert_eq!(r2.user_version, 2);
    let (oi, ss) = state(&pg, "a");
    assert_eq!(oi.size, 6);
    assert_eq!(oi.version.version, 2);
    assert_eq!(oi.prior_version.version, 1);
    assert_eq!(oi.user_version, 2);
    assert!(oi.flags & replwire::flag::DIRTY != 0);
    assert_eq!(ss.seq, 0);
    // read reply versions
    let r3 = go(&mut pg, &mut eng, 3, mk("a", vec![OsdOp::read(0, 100)]));
    assert_eq!(r3.ops[0].outdata, &b"hello!"[..]);
    assert_eq!(r3.user_version, 2);
    assert_eq!(r3.replay_version, denc::types::Eversion::default());
}

#[test]
fn placement_read_keeps_verified_block_crcs_in_reply() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let payload: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let written = go(
        &mut pg,
        &mut eng,
        1,
        mk("placed", vec![OsdOp::write(0, payload.clone())]),
    );
    assert_eq!(written.result, 0);

    let normal = go(
        &mut pg,
        &mut eng,
        2,
        mk("placed", vec![OsdOp::read(0, payload.len() as u64)]),
    );
    assert_eq!(normal.ops[0].outdata_block_crcs, None);

    let short = ClientReq {
        placement_read: Some(0),
        conn: 1,
        caps: None,
        tid: 4,
        op: Box::new(mk("placed", vec![OsdOp::read(0, 4096)])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, short);
    let short_rep = settle(&mut pg, &mut eng)
        .into_iter()
        .find_map(|out| match out {
            Out::Reply {
                conn: 1,
                tid: 4,
                placement_read: Some(0),
                reply,
                ..
            } => Some(reply),
            _ => None,
        })
        .expect("short reply");
    assert_eq!(short_rep.ops[0].outdata_block_crcs, None);

    let req = ClientReq {
        placement_read: Some(0),
        conn: 1,
        caps: None,
        tid: 3,
        op: Box::new(mk("placed", vec![OsdOp::read(0, payload.len() as u64)])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req);
    let outs = settle(&mut pg, &mut eng);
    let rep = outs
        .into_iter()
        .find_map(|out| match out {
            Out::Reply {
                conn: 1,
                tid: 3,
                placement_read: Some(0),
                reply,
                ..
            } => Some(reply),
            _ => None,
        })
        .expect("placed reply");
    assert_eq!(rep.result, 0);
    assert_eq!(rep.ops[0].outdata_len(), payload.len());
    assert_eq!(&rep.ops[0].outdata[..], &payload[..]);
    assert_eq!(
        rep.ops[0].outdata_block_crcs,
        Some(payload.chunks(4096).map(|b| crc::crc32c(0, b)).collect())
    );
}

#[test]
fn dup_in_flight_and_committed() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let op = mk("d", vec![OsdOp::write(0, b"x".to_vec())]);
    // first send: complete only after the dup arrived
    let req = |tid| ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(op.clone()),
        who: client(9),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req(77));
    assert_eq!(pg.entries.len(), 1);
    let mut r2 = req(77);
    r2.conn = 2;
    eng.on_op(&mut pg, r2);
    assert_eq!(pg.entries.len(), 1, "dup must not re-execute");
    let mut outs = settle(&mut pg, &mut eng);
    let a = reply_of(&mut outs, 1, 77).unwrap();
    let b = reply_of(&mut outs, 2, 77).unwrap();
    assert_eq!(a.replay_version, b.replay_version);
    assert_eq!(a.user_version, b.user_version);
    // committed dup (resend after reply)
    let mut outs = run(&mut pg, &mut eng, 1, 77, client(9), op.clone());
    let c = reply_of(&mut outs, 1, 77).unwrap();
    assert_eq!(pg.entries.len(), 1);
    assert_eq!(c.replay_version, a.replay_version);
    assert_eq!(c.result, 0);
    let _ = OsdReqId::default();
}

#[test]
fn failed_write_logs_error_entry_and_dup_repeats_error() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let op = mk("e", vec![OsdOp::stat(), OsdOp::write(0, b"x".to_vec())]);
    let r = go(&mut pg, &mut eng, 5, op.clone());
    assert_eq!(r.result, -errno::ENOENT);
    assert_eq!(pg.entries.len(), 1);
    assert!(pg.entries[0].is_error());
    assert_eq!(pg.entries[0].return_code, -errno::ENOENT);
    assert!(r.replay_version.version >= 1);
    // resend: same failure, no new entry
    let r2 = go(&mut pg, &mut eng, 5, op);
    assert_eq!(r2.result, -errno::ENOENT);
    assert_eq!(pg.entries.len(), 1);
    // object was not created
    assert!(pg.store.objects(pg.spg).is_empty());
}

fn with_snapc(mut op: opwire::MOSDOp, seq: u64, snaps: &[u64]) -> opwire::MOSDOp {
    op.snap_seq = seq;
    op.snaps = snaps.to_vec();
    op
}

#[test]
fn clone_on_write_and_snap_reads() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mk("s", vec![OsdOp::write(0, b"AAAAAAAA".to_vec())]),
    );
    // snapshot 3 exists now: first write after it clones
    let w = with_snapc(mk("s", vec![OsdOp::write(0, b"BB".to_vec())]), 3, &[3]);
    let r = go(&mut pg, &mut eng, 2, w);
    assert_eq!(r.result, 0);
    let (oi, ss) = state(&pg, "s");
    assert_eq!(ss.seq, 3);
    assert_eq!(ss.clones, vec![SnapId(3)]);
    assert_eq!(ss.clone_size[&SnapId(3)], 8);
    assert_eq!(ss.clone_snaps[&SnapId(3)], vec![SnapId(3)]);
    // overlap shrinks by the modified range [0,2)
    assert_eq!(ss.clone_overlap[&SnapId(3)].get(&2), Some(&6));
    assert_eq!(oi.version.version, 3, "clone consumed version 2");
    // log: CLONE then MODIFY, consecutive
    let n = pg.entries.len();
    assert_eq!(pg.entries[n - 2].op, pgwire::LogOp::CLONE);
    assert_eq!(pg.entries[n - 1].op, pgwire::LogOp::MODIFY);
    assert_eq!(
        pg.entries[n - 2].version.version + 1,
        pg.entries[n - 1].version.version
    );
    assert_eq!(pg.entries[n - 2].snaps, {
        let mut b = 1u32.to_le_bytes().to_vec();
        b.extend_from_slice(&3u64.to_le_bytes());
        b
    });
    // clone object content = old data, with its own oi without snapset attr
    let mut coid = head("s");
    coid.snap = SnapId(3);
    let objs = pg.store.objects(pg.spg);
    let c = objs.get(&coid).expect("clone");
    assert_eq!(c.data, b"AAAAAAAA");
    assert!(!c.xattrs.contains_key(b"snapset".as_slice()));
    // head content
    assert_eq!(&data(&pg, "s")[..2], b"BB");
    // snap read at 3 -> clone content; at 4 -> head
    let mut rd = mk("s", vec![OsdOp::read(0, 8)]);
    rd.snapid = 3;
    let r = go(&mut pg, &mut eng, 3, rd);
    assert_eq!(r.ops[0].outdata, &b"AAAAAAAA"[..]);
    let mut rd = mk("s", vec![OsdOp::read(0, 8)]);
    rd.snapid = 4;
    let r = go(&mut pg, &mut eng, 4, rd);
    assert_eq!(r.ops[0].outdata, &b"BBAAAAAA"[..]);
    // snap 2 predates the clone's snaps list: no content
    let mut rd = mk("s", vec![OsdOp::read(0, 8)]);
    rd.snapid = 2;
    assert_eq!(go(&mut pg, &mut eng, 5, rd).result, -errno::ENOENT);
    // list-snaps
    let mut ls = mk("s", vec![OsdOp::list_snaps()]);
    ls.snapid = SNAPDIR;
    let r = go(&mut pg, &mut eng, 6, ls);
    let resp: opwire::ObjListSnapResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert_eq!(resp.seq, 3);
    assert_eq!(resp.clones.len(), 2);
    assert_eq!(resp.clones[0].cloneid, 3);
    assert_eq!(resp.clones[0].size, 8);
    assert_eq!(resp.clones[1].cloneid, NOSNAP);
    // a second write with the same snapc does not clone again
    let w = with_snapc(mk("s", vec![OsdOp::write(6, b"CC".to_vec())]), 3, &[3]);
    go(&mut pg, &mut eng, 7, w);
    let (_, ss) = state(&pg, "s");
    assert_eq!(ss.clones.len(), 1);
    assert!(
        !ss.clone_overlap[&SnapId(3)].contains_key(&6),
        "overlap shrank"
    );
    // writes to a snapid != NOSNAP are invalid
    let mut w = mk("s", vec![OsdOp::write(0, b"x".to_vec())]);
    w.snapid = 3;
    assert_eq!(go(&mut pg, &mut eng, 8, w).result, -errno::EINVAL);
}

#[test]
fn replace_log_entry_gated_by_require_osd_release() {
    // client-ops 16.5: REPLACE only where every peer can replay it (umbrella+); a pre-umbrella cluster gets MODIFY
    // for the whiteout head (it still exists; a pre-umbrella peer has no is_update() for REPLACE).
    let mut pg = TPg::new();
    pg.release = cls::release::TENTACLE;
    let mut eng = engine(&pg);
    for (oid, rel) in [
        ("old", cls::release::TENTACLE),
        ("new", cls::release::UMBRELLA),
    ] {
        pg.release = rel;
        let tid = if oid == "old" { 1 } else { 3 };
        go(
            &mut pg,
            &mut eng,
            tid,
            mk(oid, vec![OsdOp::write(0, b"one".to_vec())]),
        );
        let d = with_snapc(mk(oid, vec![OsdOp::delete()]), 5, &[5]);
        assert_eq!(go(&mut pg, &mut eng, tid + 1, d).result, 0);
        let want = if rel >= cls::release::UMBRELLA {
            pgwire::LogOp::REPLACE
        } else {
            pgwire::LogOp::MODIFY
        };
        assert_eq!(pg.entries.last().unwrap().op, want, "{oid}");
        assert!(state(&pg, oid).0.is_whiteout(), "{oid}");
    }
}

#[test]
fn delete_with_clones_whiteouts_and_rollback() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mk(
            "w",
            vec![
                OsdOp::write(0, b"one".to_vec()),
                OsdOp::setxattr(b"k", b"v"),
            ],
        ),
    );
    // snap 5, then delete: clone + whiteout
    let d = with_snapc(mk("w", vec![OsdOp::delete()]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 2, d).result, 0);
    let (oi, ss) = state(&pg, "w");
    assert!(oi.is_whiteout());
    assert_eq!(oi.size, 0);
    assert_eq!(ss.clones, vec![SnapId(5)]);
    assert_eq!(pg.entries.last().unwrap().op, pgwire::LogOp::REPLACE);
    // head reads ENOENT, snap read works
    assert_eq!(
        go(&mut pg, &mut eng, 3, mk("w", vec![OsdOp::stat()])).result,
        -errno::ENOENT
    );
    let mut rd = mk("w", vec![OsdOp::read(0, 10)]);
    rd.snapid = 5;
    assert_eq!(go(&mut pg, &mut eng, 4, rd).ops[0].outdata, &b"one"[..]);
    // deleting again: ENOENT
    let d = with_snapc(mk("w", vec![OsdOp::delete()]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 5, d).result, -errno::ENOENT);
    // recreate over the whiteout
    let w = with_snapc(mk("w", vec![OsdOp::write(0, b"two".to_vec())]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 6, w).result, 0);
    let (oi, _) = state(&pg, "w");
    assert!(!oi.is_whiteout());
    assert_eq!(data(&pg, "w"), b"two");
    // rollback to snap 5 restores content and xattrs
    let rb = with_snapc(mk("w", vec![OsdOp::rollback(5)]), 5, &[5]);
    assert_eq!(go(&mut pg, &mut eng, 7, rb).result, 0);
    assert_eq!(data(&pg, "w"), b"one");
    let r = go(&mut pg, &mut eng, 8, mk("w", vec![OsdOp::getxattr(b"k")]));
    assert_eq!(r.ops[0].outdata, &b"v"[..]);
    // pgnls shows the head once, no clones
    let cur = Hobject::MIN();
    let r = go(&mut pg, &mut eng, 9, {
        let mut o = mk("", vec![OsdOp::pgnls(10, &cur)]);
        o.flags = mflag::READ | mflag::ONDISK;
        o
    });
    let resp: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert_eq!(resp.entries.len(), 1);
    assert_eq!(r.result, 1);
}

#[test]
fn plain_delete_drops_object_and_snapset() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mk("p", vec![OsdOp::write(0, b"x".to_vec())]),
    );
    assert_eq!(
        go(&mut pg, &mut eng, 2, mk("p", vec![OsdOp::delete()])).result,
        0
    );
    assert!(pg.store.objects(pg.spg).is_empty());
    assert_eq!(pg.entries.last().unwrap().op, pgwire::LogOp::DELETE);
    assert_eq!(
        go(&mut pg, &mut eng, 3, mk("p", vec![OsdOp::stat()])).result,
        -errno::ENOENT
    );
}

#[test]
fn reads_wait_for_inflight_writes_of_their_object_only() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mk("o1", vec![OsdOp::write(0, b"old".to_vec())]),
    );
    go(
        &mut pg,
        &mut eng,
        2,
        mk("o2", vec![OsdOp::write(0, b"zzz".to_vec())]),
    );
    let req = |tid, op: opwire::MOSDOp| ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(op),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    // write in flight (not completed)
    eng.on_op(
        &mut pg,
        req(10, mk("o1", vec![OsdOp::write(0, b"new".to_vec())])),
    );
    assert!(eng.take_out().is_empty());
    // read of the same object waits; read of another object is served
    eng.on_op(&mut pg, req(11, mk("o1", vec![OsdOp::read(0, 3)])));
    eng.on_op(&mut pg, req(12, mk("o2", vec![OsdOp::read(0, 3)])));
    let mut outs = eng.take_out();
    assert!(reply_of(&mut outs, 1, 11).is_none());
    assert_eq!(
        reply_of(&mut outs, 1, 12).unwrap().ops[0].outdata,
        &b"zzz"[..]
    );
    // a write arriving behind a queued read queues too (FIFO per object)
    eng.on_op(
        &mut pg,
        req(13, mk("o1", vec![OsdOp::write(3, b"!".to_vec())])),
    );
    assert!(eng.take_out().is_empty());
    assert_eq!(pg.entries.len(), 3);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 10).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 13).unwrap().result, 0);
    let r = reply_of(&mut outs, 1, 11).unwrap();
    assert_eq!(r.ops[0].outdata, &b"new"[..]);
    assert_eq!(data(&pg, "o1"), b"new!");
}

#[test]
fn parked_until_active_and_degraded_until_recovered() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.active = false;
    let req = ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid: 1,
        op: Box::new(mk("q", vec![OsdOp::write(0, b"x".to_vec())])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req);
    assert!(eng.take_out().is_empty());
    assert!(eng.has_parked());
    pg.active = true;
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    // degraded object
    pg.missing.insert(head("q"));
    let req = ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid: 2,
        op: Box::new(mk("q", vec![OsdOp::write(1, b"y".to_vec())])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req);
    assert!(settle(&mut pg, &mut eng).is_empty());
    pg.missing.clear();
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    // not readable: reads park too
    pg.readable = false;
    let req = ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid: 3,
        op: Box::new(mk("q", vec![OsdOp::read(0, 2)])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req);
    assert!(eng.take_out().is_empty());
    pg.readable = true;
    eng.retry(&mut pg);
    let mut outs = eng.take_out();
    assert_eq!(
        reply_of(&mut outs, 1, 3).unwrap().ops[0].outdata,
        &b"xy"[..]
    );
    // interval change keeps the same primary: parked ops are re-queued, not dropped (the client does not resend)
    pg.active = false;
    let req = ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid: 4,
        op: Box::new(mk("q", vec![OsdOp::read(0, 2)])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req);
    eng.reset();
    assert!(eng.take_out().is_empty());
    pg.active = true;
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(
        reply_of(&mut outs, 1, 4).unwrap().ops[0].outdata,
        &b"xy"[..]
    );
}

/// Regression: kill -9 of a replica leaves writes in flight at the primary (never acked by the dead replica); the
/// interval change must re-run them (same primary = client does not resend) instead of dropping them.
#[test]
fn interval_change_requeues_inflight_writes() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    for (tid, oid) in [(1, "a"), (2, "b")] {
        let req = ClientReq {
            placement_read: None,
            conn: 1,
            caps: None,
            tid,
            op: Box::new(mk(oid, vec![OsdOp::write(0, b"zz".to_vec())])),
            who: client(7),
            addr: EntityAddr::default(),
            peer_addr: EntityAddr::default(),
            features: 0,
        };
        eng.on_op(&mut pg, req);
    }
    // submitted, never completed: the replica died
    assert_eq!(eng.in_flight(), 2);
    assert!(eng.take_out().is_empty());
    pg.done.clear();
    eng.reset();
    assert_eq!(eng.in_flight(), 0);
    assert!(eng.has_parked());
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    assert_eq!(data(&pg, "a"), b"zz");
}

fn watch_msg(oid: &str, cookie: u64, sub: u8) -> opwire::MOSDOp {
    mk(oid, vec![OsdOp::watch_op(cookie, sub, 0)])
}

fn notifies(outs: &[Out]) -> Vec<(u64, u8, u64, u64, i32)> {
    outs.iter()
        .filter_map(|o| match o {
            Out::Notify { conn, msg } => Some((
                *conn,
                msg.opcode,
                msg.cookie,
                msg.notify_id,
                msg.return_code,
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn watch_notify_ack_and_timeouts() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(&mut pg, &mut eng, 1, mk("h", vec![OsdOp::create(false)]));
    // missing object: ENOENT
    assert_eq!(
        go(&mut pg, &mut eng, 2, watch_msg("nope", 1, watch_op::WATCH)).result,
        -errno::ENOENT
    );
    // two watchers on two connections
    let mut o = run(
        &mut pg,
        &mut eng,
        11,
        1,
        client(100),
        watch_msg("h", 0xAA, watch_op::WATCH),
    );
    assert_eq!(reply_of(&mut o, 11, 1).unwrap().result, 0);
    let mut o = run(
        &mut pg,
        &mut eng,
        12,
        1,
        client(101),
        watch_msg("h", 0xBB, watch_op::WATCH),
    );
    assert_eq!(reply_of(&mut o, 12, 1).unwrap().result, 0);
    let (oi, _) = state(&pg, "h");
    assert_eq!(oi.watchers.len(), 2);
    // list-watchers
    let r = go(&mut pg, &mut eng, 3, mk("h", vec![OsdOp::list_watchers()]));
    let lw: opwire::ObjListWatchResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert_eq!(lw.entries.len(), 2);
    // ping
    let mut o = run(
        &mut pg,
        &mut eng,
        11,
        2,
        client(100),
        watch_msg("h", 0xAA, watch_op::PING),
    );
    assert_eq!(reply_of(&mut o, 11, 2).unwrap().result, 0);
    let mut o = run(
        &mut pg,
        &mut eng,
        11,
        3,
        client(100),
        watch_msg("h", 0xDEAD, watch_op::PING),
    );
    assert_eq!(reply_of(&mut o, 11, 3).unwrap().result, -errno::ENOTCONN);
    // notify from conn 13
    let nm = mk("h", vec![OsdOp::notify_op(0x77, 5, b"payload")]);
    let mut o = run(&mut pg, &mut eng, 13, 1, client(102), nm);
    let n = notifies(&o);
    assert_eq!(n.len(), 2);
    assert!(n.iter().all(|x| x.1 == nop::NOTIFY));
    let rep = reply_of(&mut o, 13, 1).unwrap();
    let nid = u64::from_le_bytes(rep.ops[0].outdata[..8].try_into().unwrap());
    assert_eq!(nid >> 32, 10);
    // acks
    let ack = |c: u64, cookie: u64, who: i64, tid| {
        let m = mk("h", vec![OsdOp::notify_ack(nid, cookie, b"rep")]);
        run_conn(c, tid, who, m)
    };
    fn run_conn(_c: u64, _t: u64, _w: i64, _m: opwire::MOSDOp) -> Vec<Out> {
        Vec::new()
    }
    let _ = ack;
    let mut o = run(
        &mut pg,
        &mut eng,
        11,
        4,
        client(100),
        mk("h", vec![OsdOp::notify_ack(nid, 0xAA, b"r1")]),
    );
    assert_eq!(reply_of(&mut o, 11, 4).unwrap().result, 0);
    assert!(notifies(&o).is_empty(), "not complete yet");
    let mut o = run(
        &mut pg,
        &mut eng,
        12,
        4,
        client(101),
        mk("h", vec![OsdOp::notify_ack(nid, 0xBB, b"r2")]),
    );
    let n = notifies(&o);
    assert_eq!(n.len(), 1);
    assert_eq!(
        (n[0].0, n[0].1, n[0].2, n[0].4),
        (13, nop::NOTIFY_COMPLETE, 0x77, 0)
    );
    let msg = o
        .iter()
        .find_map(|x| match x {
            Out::Notify { msg, .. } => Some(msg.clone()),
            _ => None,
        })
        .unwrap();
    let d: opwire::NotifyCompleteData = denc::from_slice(&msg.data).unwrap();
    assert_eq!(d.replies.len(), 2);
    assert!(d.missed.is_empty());
    let _ = reply_of(&mut o, 12, 4);
    // notify with an unresponsive watcher times out with ETIMEDOUT
    let nm = mk("h", vec![OsdOp::notify_op(0x78, 2, b"x")]);
    let mut o = run(&mut pg, &mut eng, 13, 2, client(102), nm);
    let _ = reply_of(&mut o, 13, 2);
    pg.now += 3_000_000_000;
    let now = pg.now;
    eng.tick(&mut pg, now);
    let o = settle(&mut pg, &mut eng);
    let n = notifies(&o);
    let c = n
        .iter()
        .find(|x| x.1 == nop::NOTIFY_COMPLETE)
        .expect("complete");
    assert_eq!(c.4, -errno::ETIMEDOUT);
    // watchers time out without pings (30 s default): removed from oi, DISCONNECT sent
    pg.now += 40_000_000_000;
    let now = pg.now;
    eng.tick(&mut pg, now);
    let o = settle(&mut pg, &mut eng);
    let n = notifies(&o);
    assert_eq!(n.iter().filter(|x| x.1 == nop::DISCONNECT).count(), 2);
    let (oi, _) = state(&pg, "h");
    assert!(oi.watchers.is_empty());
    // unwatch of an absent watch succeeds
    let r = go(
        &mut pg,
        &mut eng,
        20,
        watch_msg("h", 0xAA, watch_op::UNWATCH),
    );
    assert_eq!(r.result, 0);
}

#[test]
fn pgnls_paging() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    for i in 0..5 {
        go(
            &mut pg,
            &mut eng,
            100 + i,
            mk(&format!("obj{i}"), vec![OsdOp::create(false)]),
        );
    }
    // objects share one hash in this test; list them page by page
    let mut cursor = Hobject::MIN();
    let mut seen = 0;
    let mut tid = 200;
    loop {
        tid += 1;
        let mut o = mk("", vec![OsdOp::pgnls(2, &cursor)]);
        o.flags = mflag::READ | mflag::ONDISK;
        let r = go(&mut pg, &mut eng, tid, o);
        let resp: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
        assert!(resp.entries.len() <= 2);
        seen += resp.entries.len();
        if r.result == 1 {
            break;
        }
        cursor = resp.handle;
        assert!(tid < 220, "no progress");
    }
    assert_eq!(seen, 5);
}

#[test]
fn pg_listing_rejects_cursor_below_pg_start() {
    use opexec::pgop::{PgLsRun, pg_ops};
    use opwire::op as code;

    let pg = TPg::new();
    let mut spg = pg.spg;
    spg.pgid.seed = 1;
    // PG 1 of two covers the upper half of bitwise hash order. A stale
    // cursor from PG 0 must be rejected by PGNLS, including filtered ops.
    for opcode in [
        code::PGLS,
        code::PGLS_FILTER,
        code::PGNLS,
        code::PGNLS_FILTER,
    ] {
        for (cursor, expected) in [
            (
                Hobject::new(b"old", SnapId::NOSNAP, 0, POOL as i64, b""),
                -errno::EINVAL,
            ),
            (Hobject::MIN(), 1),
            // A cursor may name a clone: the lower boundary has snap 0.
            (Hobject::new(b"", SnapId(0), 1, POOL as i64, b""), 1),
        ] {
            let mut op = OsdOp::pgnls(1, &cursor);
            if matches!(opcode, code::PGLS_FILTER | code::PGNLS_FILTER) {
                use denc::Encode;
                let mut e = denc::Encoder::new();
                e.bytes(b"pg").unwrap();
                e.bytes(b"filter").unwrap();
                e.bytes(b"plain").unwrap();
                e.bytes(b"").unwrap();
                e.bytes(b"").unwrap();
                cursor.encode(&mut e).unwrap();
                op.indata = bytes::Bytes::from(e.into_vec());
            }
            op.op = opcode;
            let result = pg_ops(
                &pg,
                spg,
                2,
                b"",
                NOSNAP,
                1024,
                std::slice::from_mut(&mut op),
                &mut PgLsRun::default(),
            );
            let expected = if matches!(opcode, code::PGLS | code::PGLS_FILTER) {
                1
            } else {
                expected
            };
            assert_eq!(
                result,
                Some(expected),
                "opcode {opcode:#x}, cursor {cursor:?}"
            );
        }
    }
}

#[test]
fn pgnls_missing_listing_work_is_bounded_by_page() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let n = 2048usize;
    let expected: Vec<_> = (0..n)
        .map(|i| format!("missing{i:08}").into_bytes())
        .collect();
    for name in &expected {
        pg.missing.insert(head(std::str::from_utf8(name).unwrap()));
    }
    let mut cursor = Hobject::MIN();
    let mut names = Vec::new();
    for tid in 1..=n as u64 + 1 {
        let r = go(
            &mut pg,
            &mut eng,
            tid,
            mk("", vec![OsdOp::pgnls(128, &cursor)]),
        );
        let page: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
        names.extend(page.entries.into_iter().map(|o| o.oid));
        cursor = page.handle;
        if r.result == 1 {
            break;
        }
    }
    assert_eq!(names, expected);
    let cloned = pg.missing_listed.get();
    eprintln!("missing listing: {n} entries, {cloned} cloned missing handles");
    assert!(
        cloned <= n * 2,
        "small output pages must not clone every remaining missing object: {cloned}"
    );
}

#[test]
fn legacy_pgls_keeps_exact_namespace_and_max_end() {
    use opexec::pgop::{PgLsRun, pg_ops};
    use opwire::{PgLsResponse, op as code};

    let mut pg = TPg::new();
    for ns in [b"".as_slice(), b"\x01", b".ceph-internal", b"other"] {
        pg.missing
            .insert(Hobject::new(b"obj", SnapId::NOSNAP, 0, POOL as i64, ns));
    }
    for opcode in [code::PGLS, code::PGLS_FILTER] {
        for ns in [b"".as_slice(), b"\x01", b".ceph-internal", b"absent"] {
            let mut op = if opcode == code::PGLS_FILTER {
                pgnls_filter_op(b"plain", |e| {
                    e.bytes(b"").unwrap();
                    e.bytes(b"").unwrap();
                })
            } else {
                OsdOp::pgnls(10, &Hobject::MIN())
            };
            op.op = opcode;
            let result = pg_ops(
                &pg,
                pg.spg,
                2,
                ns,
                NOSNAP,
                1024,
                std::slice::from_mut(&mut op),
                &mut PgLsRun::default(),
            );
            assert_eq!(result, Some(1));
            let page: PgLsResponse = denc::from_slice(&op.outdata).unwrap();
            assert_eq!(
                page.entries.len(),
                usize::from(ns != b"absent"),
                "namespace {ns:?}"
            );
            assert_eq!(page.handle, Hobject::MAX());
        }
    }
}

#[test]
fn pgnls_missing_batches_preserve_local_delete_and_clone_boundaries() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut expected = Vec::new();
    for i in 0..768u64 {
        let name = format!("mixed{i:08}");
        let mut o = head(&name);
        if i % 7 == 0 {
            o.snap = SnapId(7);
        } else if i % 3 == 0 {
            go(
                &mut pg,
                &mut eng,
                i + 1,
                mk(&name, vec![OsdOp::create(false)]),
            );
        }
        if i % 5 == 0 {
            pg.missing_del.insert(o);
        } else {
            if o.snap == SnapId::NOSNAP {
                expected.push(name.into_bytes());
            }
            pg.missing.insert(o);
        }
    }
    for page_size in [1, 128] {
        let mut cursor = Hobject::MIN();
        let mut names = Vec::new();
        for tid in 1000..3000 {
            let r = go(
                &mut pg,
                &mut eng,
                tid,
                mk("", vec![OsdOp::pgnls(page_size, &cursor)]),
            );
            let page: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
            names.extend(page.entries.into_iter().map(|o| o.oid));
            cursor = page.handle;
            if r.result == 1 {
                break;
            }
        }
        assert_eq!(names, expected, "page size {page_size}");
    }
}

/// Regression: an aborted write (`WriteDone` with -EAGAIN from the interval change) must be re-run, not dropped,
/// independent of whether `reset()` ran before; the op still gets exactly one reply.
#[test]
fn aborted_write_done_requeues_op() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let req = ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid: 1,
        op: Box::new(mk("a", vec![OsdOp::write(0, b"zz".to_vec())])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req);
    let done = std::mem::take(&mut pg.done);
    assert_eq!(done.len(), 1);
    eng.on_write_done(&mut pg, done[0].0, done[0].1, -11);
    assert!(eng.take_out().is_empty(), "no reply for an aborted write");
    assert!(eng.has_parked());
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
}

/// Regression: ops re-queued by a reset are never dropped, and new ops are not starved by the cap afterwards.
#[test]
fn reset_requeue_exceeds_cap_without_dropping() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.active = false;
    let n = 5000u64; // above MAX_PARKED (4096)
    for t in 1..=n {
        let req = ClientReq {
            placement_read: None,
            conn: 1,
            caps: None,
            tid: t,
            op: Box::new(mk("q", vec![OsdOp::read(0, 1)])),
            who: client(7),
            addr: EntityAddr::default(),
            peer_addr: EntityAddr::default(),
            features: 0,
        };
        // fill the gate directly through reset: park via on_op up to the cap, rest via a second engine round
        eng.on_op(&mut pg, req);
    }
    eng.reset();
    pg.active = true;
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    let replies = outs
        .drain(..)
        .filter(|o| matches!(o, Out::Reply { .. }))
        .count();
    assert!(replies >= 4096, "re-queued ops answered: {replies}");
}

#[test]
fn parked_ops_older_than_a_split_are_dropped_not_executed() {
    // an op parked while the PG peered must not run after the PG split: its object may belong to a child now
    // (the client re-sends against the new map)
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.active = false;
    let req = |tid, epoch| {
        let mut op = mk("split-victim", vec![OsdOp::write(0, b"x".to_vec())]);
        op.osdmap_epoch = epoch;
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
    };
    eng.on_op(&mut pg, req(1, 10));
    eng.on_op(&mut pg, req(2, 12));
    assert!(eng.has_parked());
    pg.split_epoch = 11; // split at epoch 11, PG active again
    pg.active = true;
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert!(reply_of(&mut outs, 1, 1).is_none(), "stale op got a reply");
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    assert_eq!(pg.entries.len(), 1, "only the post-split op was executed");
}

#[test]
fn store_without_room_answers_enospc_but_shrinks_pass() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            1,
            mk("a", vec![OsdOp::write(0, b"hello".to_vec())])
        )
        .result,
        0
    );
    let n = pg.entries.len();
    pg.room = false;
    // any flags, incl. FULL_TRY / FULL_FORCE: plain -ENOSPC, no log entry, nothing applied
    for (tid, fl) in [(2, 0), (3, mflag::FULL_TRY), (4, mflag::FULL_FORCE)] {
        let mut op = mk("a", vec![OsdOp::write(5, b"!".to_vec())]);
        op.flags |= fl;
        let r = go(&mut pg, &mut eng, tid, op);
        assert_eq!(r.result, -errno::ENOSPC, "flags {fl:#x}");
    }
    // omap-only write too (grows metadata without growing bytes)
    let r = go(
        &mut pg,
        &mut eng,
        5,
        mk(
            "a",
            vec![OsdOp::omap_set_vals(&std::collections::BTreeMap::from([(
                b"k".to_vec(),
                b"v".to_vec(),
            )]))],
        ),
    );
    assert_eq!(r.result, -errno::ENOSPC);
    assert_eq!(pg.entries.len(), n);
    assert_eq!(data(&pg, "a"), b"hello");
    // reads work, a delete frees space and must be admitted
    let r = go(&mut pg, &mut eng, 6, mk("a", vec![OsdOp::read(0, 100)]));
    assert_eq!(r.ops[0].outdata, &b"hello"[..]);
    let r = go(&mut pg, &mut eng, 7, mk("a", vec![OsdOp::delete()]));
    assert_eq!(r.result, 0);
    assert!(pg.store.objects(pg.spg).is_empty());
    pg.room = true;
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            8,
            mk("b", vec![OsdOp::write(0, b"x".to_vec())])
        )
        .result,
        0
    );
}

#[test]
fn cold_pages_park_ops_in_arrival_order() {
    // ADR 0021 am. 8: an op whose store pages are not resident waits at the gate (the core never blocks on the
    // miss); later ops of the SAME object queue behind it even if their pages are resident.
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let rq = |tid: u64, oid: &str, data: &[u8]| ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mk(oid, vec![OsdOp::write(0, data.to_vec())])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    pg.cold.set(1000);
    eng.on_op(&mut pg, rq(1, "a", b"A"));
    eng.on_op(&mut pg, rq(2, "a", b"B"));
    assert!(settle(&mut pg, &mut eng).is_empty(), "ran on cold pages");
    assert!(eng.has_parked());
    assert!(pg.entries.is_empty());
    // a re-probe while still cold changes nothing
    eng.retry(&mut pg);
    assert!(pg.entries.is_empty());
    pg.cold.set(0);
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    let order: Vec<_> = pg.entries.iter().map(|e| e.soid.clone()).collect();
    assert_eq!(order, vec![head("a"), head("a")]);
    assert!(!eng.has_parked());
    // warm pages: executed at once, no parking
    eng.on_op(&mut pg, rq(3, "c", b"C"));
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, 0);
}

/// Per-item store limits are enforced per op before anything is logged as a mutation (client-ops.md rule 9a): a key
/// the store can never hold used to fail the whole txn after the log append and exit the OSD.
#[test]
fn store_item_limits_give_enametoolong_not_a_store_failure() {
    let mut pg = TPg::new();
    pg.max_item_key = 500;
    let mut eng = engine(&pg);
    let long = vec![b'k'; 600];
    let kv = std::collections::BTreeMap::from([(long.clone(), b"v".to_vec())]);
    let r = go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::omap_set_vals(&kv)]),
    );
    assert_eq!(r.result, -errno::ENAMETOOLONG);
    assert!(
        pg.store.objects(pg.spg).is_empty(),
        "nothing applied, object not created"
    );
    // xattr name over the store limit (but also over the classic 100: classic rule wins first)
    let r = go(
        &mut pg,
        &mut eng,
        2,
        mk("a", vec![OsdOp::setxattr(&long, b"v")]),
    );
    assert_eq!(r.result, -errno::ENAMETOOLONG);
    // object name the store cannot hold
    let r = go(
        &mut pg,
        &mut eng,
        3,
        mk(&"o".repeat(600), vec![OsdOp::write(0, b"x".to_vec())]),
    );
    assert_eq!(r.result, -errno::ENAMETOOLONG);
    // limits are inclusive: a 500-byte omap key is fine
    let ok = std::collections::BTreeMap::from([(vec![b'k'; 500], b"v".to_vec())]);
    let r = go(
        &mut pg,
        &mut eng,
        4,
        mk("a", vec![OsdOp::omap_set_vals(&ok)]),
    );
    assert_eq!(r.result, 0);
}

fn wreq(tid: u64, oid: &str, data: &[u8]) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mk(oid, vec![OsdOp::write(0, data.to_vec())])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

#[test]
fn a_cold_op_does_not_hold_ops_of_other_objects() {
    // Ordering is per object: "b" and "c" run while "a" waits for its store pages; a later op of "a" stays behind it.
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.cold_objs.borrow_mut().push(b"a".to_vec());
    eng.on_op(&mut pg, wreq(1, "a", b"A1"));
    eng.on_op(&mut pg, wreq(2, "b", b"B"));
    eng.on_op(&mut pg, wreq(3, "a", b"A2"));
    eng.on_op(&mut pg, wreq(4, "c", b"C"));
    let mut outs = settle(&mut pg, &mut eng);
    assert!(reply_of(&mut outs, 1, 1).is_none(), "cold op ran");
    assert!(
        reply_of(&mut outs, 1, 3).is_none(),
        "overtook its object's cold op"
    );
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 4).unwrap().result, 0);
    assert!(eng.has_parked());
    // a woken retry while still cold changes nothing
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    assert!(settle(&mut pg, &mut eng).is_empty());
    // the pages arrive: without a store wake nothing is probed, with one the "a" ops run in arrival order
    pg.cold_objs.borrow_mut().clear();
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::default());
    assert!(settle(&mut pg, &mut eng).is_empty(), "no wake, no probe");
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, 0);
    let order: Vec<_> = pg.entries.iter().map(|e| e.soid.clone()).collect();
    assert_eq!(order, vec![head("b"), head("c"), head("a"), head("a")]);
    assert!(!eng.has_parked());
}

/// The op trace names why an op waits in the gate on arrival (`Env::gate_in`, doc/ops/op-trace.md `pg_gate`): the store
/// refusal of its own probe, the ops ahead of it, shard admission, an inactive PG; an op that runs at once is not named.
#[test]
fn a_gated_op_names_why_it_waits() {
    use opexec::view::gate_why;
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.cold_objs.borrow_mut().push(b"a".to_vec());
    eng.on_op(&mut pg, wreq(1, "a", b"A"));
    eng.on_op(&mut pg, wreq(2, "b", b"B"));
    pg.cold_objs.borrow_mut().clear();
    eng.on_op(&mut pg, wreq(3, "a", b"A2"));
    assert_eq!(pg.gated, [gate_why::OBJ, gate_why::BEHIND]);
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    settle(&mut pg, &mut eng);
    assert!(!eng.has_parked());
    pg.admission_paused = true;
    eng.on_op(&mut pg, wreq(4, "c", b"C"));
    pg.admission_paused = false;
    pg.active = false;
    eng.on_op(&mut pg, wreq(5, "d", b"D"));
    assert_eq!(
        pg.gated,
        [
            gate_why::OBJ,
            gate_why::BEHIND,
            gate_why::ADMISSION,
            gate_why::INACTIVE
        ]
    );
}

#[test]
fn a_warm_op_passes_cold_ones_on_arrival_but_not_its_own_object() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.cold_objs.borrow_mut().push(b"a".to_vec());
    eng.on_op(&mut pg, wreq(1, "a", b"A"));
    let before = eng.c.parked_gate;
    eng.on_op(&mut pg, wreq(2, "b", b"B"));
    assert_eq!(
        eng.c.parked_gate, before,
        "warm op of another object parked"
    );
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    // pages of "a" look warm now, but its first op is still ahead (not yet retried): the new one queues behind it
    pg.cold_objs.borrow_mut().clear();
    eng.on_op(&mut pg, wreq(3, "a", b"A2"));
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, 0);
    let order: Vec<_> = pg.entries.iter().map(|e| e.soid.clone()).collect();
    assert_eq!(order, vec![head("b"), head("a"), head("a")]);
}

#[test]
fn a_locator_key_equal_to_the_oid_is_the_same_object_at_the_gate() {
    // key == oid names the same object as the empty key: the later op must not bypass the cold earlier one
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.cold_objs.borrow_mut().push(b"a".to_vec());
    eng.on_op(&mut pg, wreq(1, "a", b"A1"));
    assert!(settle(&mut pg, &mut eng).is_empty());
    pg.cold_objs.borrow_mut().clear();
    let mut r2 = wreq(2, "a", b"A2");
    r2.op.oloc.key = b"a".to_vec();
    eng.on_op(&mut pg, r2);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    assert_eq!(data(&pg, "a"), b"A2", "the later write ran first");
}

#[test]
fn locator_aliases_cannot_read_past_a_write_waiting_for_the_pg_log() {
    for writer_alias in [false, true] {
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        assert_eq!(
            go(
                &mut pg,
                &mut eng,
                1,
                mk("a", vec![OsdOp::write(0, b"old".to_vec())])
            )
            .result,
            0
        );
        pg.cold_log.set(100);
        let mut writer = wreq(2, "a", b"new");
        if writer_alias {
            writer.op.oloc.key = b"a".to_vec();
        }
        eng.on_op(&mut pg, writer);
        assert!(settle(&mut pg, &mut eng).is_empty());
        let mut reader = wreq(3, "a", b"");
        reader.op.ops = vec![OsdOp::read(0, 3)];
        if !writer_alias {
            reader.op.oloc.key = b"a".to_vec();
        }
        eng.on_op(&mut pg, reader);
        assert!(
            settle(&mut pg, &mut eng).is_empty(),
            "locator alias read passed an earlier write whose PG log is still cold (writer_alias={writer_alias})"
        );
        pg.cold_log.set(0);
        eng.retry(&mut pg);
        let mut outs = settle(&mut pg, &mut eng);
        assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
        let read = reply_of(&mut outs, 1, 3).unwrap();
        assert_eq!(read.result, 0);
        assert_eq!(read.ops[0].outdata, &b"new"[..]);
    }
}

#[test]
fn an_op_parked_on_a_degraded_object_after_bypassing_cold_ones_runs_without_a_store_wake() {
    // "b" bypasses the cold "a" and parks on its degraded object: its recovery (no store wake) must retry it
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.cold_objs.borrow_mut().push(b"a".to_vec());
    eng.on_op(&mut pg, wreq(1, "a", b"A"));
    pg.missing.insert(head("b"));
    eng.on_op(&mut pg, wreq(2, "b", b"B"));
    assert!(settle(&mut pg, &mut eng).is_empty());
    pg.missing.clear();
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::default());
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    assert!(reply_of(&mut outs, 1, 1).is_none(), "cold op ran");
}

fn scan_req(tid: u64, oid: &str) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mk(oid, vec![OsdOp::omap_get_vals(b"", 100, b"")])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

#[test]
fn cold_omap_scan_parks_the_op_and_reruns_after_the_load() {
    // ADR 0021 am. 11: a read refused by a cold store page (non-blocking run) drops the whole run, parks the op at the
    // gate and repeats it after the next store wake; nothing is sent or logged by the refused runs
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = std::collections::BTreeMap::from([
        (b"k1".to_vec(), b"v1".to_vec()),
        (b"k2".to_vec(), b"v2".to_vec()),
    ]);
    let r = go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::omap_set_vals(&kv)]),
    );
    assert_eq!(r.result, 0);
    let want = go(
        &mut pg,
        &mut eng,
        2,
        mk("a", vec![OsdOp::omap_get_vals(b"", 100, b"")]),
    );
    assert_eq!(want.result, 0);
    assert!(!want.ops[0].outdata.is_empty());
    pg.cold_scan.set(2);
    let runs0 = pg.scan_runs.get();
    eng.on_op(&mut pg, scan_req(10, "a"));
    assert!(
        settle(&mut pg, &mut eng).is_empty(),
        "replied on a refused read"
    );
    assert!(eng.has_parked());
    assert_eq!(pg.scan_runs.get() - runs0, 1);
    // no store wake: the refused op is not run again
    eng.retry(&mut pg);
    assert_eq!(pg.scan_runs.get() - runs0, 1);
    // a different, warm object is not held up by the parked scan
    let r = go(
        &mut pg,
        &mut eng,
        11,
        mk("b", vec![OsdOp::write(0, b"x".to_vec())]),
    );
    assert_eq!(r.result, 0);
    // a wake while more page loads are still in flight: the op sits it out (one re-run per batch of loads)
    pg.pending.set(true);
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    assert_eq!(pg.scan_runs.get() - runs0, 1);
    pg.pending.set(false);
    // wake -> second run is refused again, wake -> third passes
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    assert_eq!(pg.scan_runs.get() - runs0, 2);
    assert!(settle(&mut pg, &mut eng).is_empty());
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::default());
    assert_eq!(pg.scan_runs.get() - runs0, 2);
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    let r = reply_of(&mut outs, 1, 10).expect("reply after the loads");
    assert_eq!(r.result, 0);
    assert_eq!(r.ops[0].outdata, want.ops[0].outdata);
    assert!(!eng.has_parked());
    assert_eq!(eng.c.parked_scan, 2);
    // no log entry was written by the refused runs (one omap set + the write to "b")
    assert_eq!(pg.entries.len(), 2);
}

#[test]
fn immutable_listing_view_reaches_executor_reply_without_mutation_or_copy() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = std::collections::BTreeMap::from([(b"k".to_vec(), b"v".to_vec())]);
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            1,
            mk("a", vec![OsdOp::omap_set_vals(&kv)])
        )
        .result,
        0
    );
    for (i, (op, wire)) in [
        (
            OsdOp::omap_get_vals(b"", 1, b""),
            b"\x01\0\0\0\x01\0\0\0k\x01\0\0\0v\0".as_slice(),
        ),
        (
            OsdOp::omap_get_keys(b"", 1),
            b"\x01\0\0\0\x01\0\0\0k\0".as_slice(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let data = bytes::Bytes::from(wire.to_vec().into_boxed_slice());
        let pointer = data.as_ptr();
        pg.immutable_listing = Some(data);
        let result = go(&mut pg, &mut eng, i as u64 + 2, mk("a", vec![op]));
        assert_eq!(result.result, 0);
        assert_eq!(result.ops[0].outdata.as_ptr(), pointer);
        assert_eq!(result.ops[0].outdata.as_ref(), wire);
        assert!(result.ops[0].outdata_more.is_empty());
        assert_eq!(pg.immutable_listing.as_ref().unwrap().as_ref(), wire);
        pg.immutable_listing = None;
        assert_eq!(result.ops[0].outdata.as_ref(), wire);
    }
}

#[test]
fn cold_omap_scan_falls_back_to_blocking_after_the_try_bound() {
    // a working set the cache cannot hold must still finish: after MAX_SCAN_TRIES refused runs the op runs blocking
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = std::collections::BTreeMap::from([(b"k".to_vec(), b"v".to_vec())]);
    go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::omap_set_vals(&kv)]),
    );
    pg.cold_scan.set(u32::MAX);
    eng.on_op(&mut pg, scan_req(10, "a"));
    let mut woken = 0;
    let reply = loop {
        let mut outs = settle(&mut pg, &mut eng);
        if let Some(r) = reply_of(&mut outs, 1, 10) {
            break r;
        }
        woken += 1;
        assert!(woken < 1000, "never finished");
        eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    };
    assert_eq!(reply.result, 0);
    assert!(!reply.ops[0].outdata.is_empty());
    assert_eq!(eng.c.parked_scan, 64);
    assert_eq!(woken, 64);
}

#[test]
fn listing_refusals_with_progress_never_run_blocking_and_skip_the_load_batch_wait() {
    // adr 0021 S8: a listing continues where its refused run stopped (scan memo): such a refusal is not charged against
    // MAX_SCAN_TRIES (no blocking fallback even after hundreds of slices) and the op runs again on its next wake, even
    // while other page loads are still in flight (its re-run repeats nothing)
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = std::collections::BTreeMap::from([(b"k".to_vec(), b"v".to_vec())]);
    go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::omap_set_vals(&kv)]),
    );
    pg.cold_scan.set(300);
    pg.scan_progress.set(true);
    pg.pending.set(true);
    let runs0 = pg.scan_runs.get();
    eng.on_op(&mut pg, scan_req(10, "a"));
    let mut woken = 0;
    let reply = loop {
        let mut outs = settle(&mut pg, &mut eng);
        if let Some(r) = reply_of(&mut outs, 1, 10) {
            break r;
        }
        woken += 1;
        assert!(woken < 1000, "never finished");
        eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    };
    assert_eq!(reply.result, 0);
    assert!(!reply.ops[0].outdata.is_empty());
    assert_eq!(
        eng.c.parked_scan, 300,
        "every refusal re-gated, none ran blocking"
    );
    assert_eq!(
        woken, 300,
        "one wake per re-run, no wait for the pending loads"
    );
    assert_eq!(pg.scan_runs.get() - runs0, 301);
}

fn op_req(tid: u64, op: opwire::MOSDOp) -> ClientReq {
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

fn kv1(k: &[u8], v: &[u8]) -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    std::collections::BTreeMap::from([(k.to_vec(), v.to_vec())])
}

/// Reply of (1, tid) from `outs` with the value of key `k1` in its omap_get_vals outdata.
fn scan_saw(outs: &mut Vec<Out>, tid: u64, val: &[u8]) -> bool {
    let r = reply_of(outs, 1, tid).expect("scan reply");
    assert_eq!(r.result, 0);
    let d = &r.ops[0].outdata;
    d.windows(val.len()).any(|w| w == val)
}

#[test]
fn cold_scan_refused_while_draining_object_waiters_keeps_the_order() {
    // review G21: a read queued behind an in-flight write (object waiters) is refused by a cold page when the write
    // completes; the write queued behind it must not overtake it (the read would see the later write)
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::omap_set_vals(&kv1(b"k1", b"old-value"))]),
    );
    // W1 in flight (not completed)
    eng.on_op(
        &mut pg,
        op_req(2, mk("a", vec![OsdOp::omap_set_vals(&kv1(b"k0", b"x"))])),
    );
    let w1 = std::mem::take(&mut pg.done);
    assert_eq!(w1.len(), 1);
    // R (read) and W2 (write) wait behind W1
    eng.on_op(
        &mut pg,
        op_req(10, mk("a", vec![OsdOp::omap_get_vals(b"", 100, b"")])),
    );
    eng.on_op(
        &mut pg,
        op_req(
            11,
            mk("a", vec![OsdOp::omap_set_vals(&kv1(b"k1", b"new-value"))]),
        ),
    );
    assert!(pg.done.is_empty());
    let entries = pg.entries.len();
    pg.cold_scan.set(1);
    for (tid, v) in w1 {
        eng.on_write_done(&mut pg, tid, v, 0);
    }
    let mut outs = eng.take_out();
    assert!(reply_of(&mut outs, 1, 2).is_some());
    assert!(reply_of(&mut outs, 1, 10).is_none(), "refused read replied");
    assert_eq!(pg.entries.len(), entries, "W2 overtook the refused read");
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    assert!(
        scan_saw(&mut outs, 10, b"old-value"),
        "read saw the later write"
    );
    assert_eq!(reply_of(&mut outs, 1, 11).unwrap().result, 0);
    assert!(!eng.has_parked());
}

#[test]
fn cold_scan_refused_after_recovery_keeps_the_order_of_parked_ops() {
    // review G21: ops parked on a degraded object run in order once it is recovered; one refused by a cold page must
    // keep the later ops of the object behind it
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::omap_set_vals(&kv1(b"k1", b"old-value"))]),
    );
    pg.missing.insert(head("a"));
    eng.on_op(
        &mut pg,
        op_req(10, mk("a", vec![OsdOp::omap_get_vals(b"", 100, b"")])),
    );
    eng.on_op(
        &mut pg,
        op_req(
            11,
            mk("a", vec![OsdOp::omap_set_vals(&kv1(b"k1", b"new-value"))]),
        ),
    );
    assert!(settle(&mut pg, &mut eng).is_empty());
    let entries = pg.entries.len();
    pg.missing.clear();
    pg.cold_scan.set(1);
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert!(reply_of(&mut outs, 1, 10).is_none(), "refused read replied");
    assert!(
        reply_of(&mut outs, 1, 11).is_none(),
        "W2 overtook the refused read"
    );
    assert_eq!(pg.entries.len(), entries);
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    assert!(
        scan_saw(&mut outs, 10, b"old-value"),
        "read saw the later write"
    );
    assert_eq!(reply_of(&mut outs, 1, 11).unwrap().result, 0);
    assert!(!eng.has_parked());
}

/// Regression (EC primary): a write the backend fails for good (`WriteDone` with -EIO, nothing logged or applied) must
/// not leave its projected object state cached: ops queued behind it see the stored state, not a size / existence that
/// never happened.
#[test]
fn failed_write_drops_projected_state() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.deferred = true;
    let req = |tid, op| ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(op),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(
        &mut pg,
        req(1, mk("f", vec![OsdOp::write(0, b"xx".to_vec())])),
    );
    eng.on_op(
        &mut pg,
        req(2, mk("f", vec![OsdOp::write(2, b"yy".to_vec())])),
    );
    eng.on_op(&mut pg, req(3, mk("f", vec![OsdOp::stat()])));
    let done = std::mem::take(&mut pg.done);
    assert_eq!(done.len(), 2, "both writes submitted (pipelined)");
    eng.on_write_done(&mut pg, done[0].0, done[0].1, -errno::EIO);
    // the second write was planned on the first one: the backend fails it too
    eng.on_write_done(&mut pg, done[1].0, done[1].1, -errno::EIO);
    pg.deferred = false;
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, -errno::EIO);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, -errno::EIO);
    assert_eq!(
        reply_of(&mut outs, 1, 3).unwrap().result,
        -errno::ENOENT,
        "stat sees the stored state"
    );
}

#[test]
fn omap_rm_range_removes_the_half_open_range() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = std::collections::BTreeMap::from([
        (b"k1".to_vec(), b"v1".to_vec()),
        (b"k2".to_vec(), b"v2".to_vec()),
        (b"k3".to_vec(), b"v3".to_vec()),
    ]);
    go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::omap_set_vals(&kv)]),
    );
    let mut rm = opwire::OsdOp::new(opwire::consts::op::OMAP_RM_KEY_RANGE);
    rm.indata = denc::Encode::encode_to_vec(&opwire::OmapRmKeyRangeIn {
        begin: b"k1".to_vec(),
        end: b"k3".to_vec(),
    })
    .unwrap()
    .into();
    assert_eq!(go(&mut pg, &mut eng, 10, mk("a", vec![rm])).result, 0);
    let r = go(
        &mut pg,
        &mut eng,
        11,
        mk("a", vec![OsdOp::omap_get_vals(b"", 100, b"")]),
    );
    let has = |k: &[u8]| r.ops[0].outdata.windows(2).any(|w| w == k);
    assert!(!has(b"k1") && !has(b"k2"), "the range [k1, k3) is gone");
    assert!(has(b"k3"), "the end of the range stays");
}

fn pgnls_filter_op(ty: &[u8], args: impl FnOnce(&mut denc::Encoder)) -> OsdOp {
    use denc::Encode;
    let mut e = denc::Encoder::new();
    e.bytes(b"pg").unwrap();
    e.bytes(b"filter").unwrap();
    e.bytes(ty).unwrap();
    args(&mut e);
    Hobject::MIN().encode(&mut e).unwrap();
    let mut o = OsdOp::new(opwire::op::PGNLS_FILTER);
    o.set_pgls(opwire::Pgls {
        count: 10,
        start_epoch: 0,
    });
    o.indata = e.into_vec().into();
    o
}

/// `plain` = raw attribute equality (not an oid prefix); cephfs.inode_tag = `.00000000` names with another tag.
#[test]
fn pgnls_filters() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut tid = 100;
    let mut put = |pg: &mut TPg, eng: &mut _, name: &str, attr: Option<(&[u8], &[u8])>| {
        tid += 1;
        let mut ops = vec![OsdOp::create(false)];
        if let Some((k, v)) = attr {
            ops.push(OsdOp::setxattr(k, v));
        }
        go(pg, eng, tid, mk(name, ops));
    };
    put(&mut pg, &mut eng, "a", Some((b"k", b"yes")));
    put(&mut pg, &mut eng, "b", Some((b"k", b"no")));
    put(&mut pg, &mut eng, "c", None);
    put(&mut pg, &mut eng, "10000000000.00000000", None);
    // scrub_tag is stored encoded (u32 len + bytes)
    let enc = |s: &[u8]| [&(s.len() as u32).to_le_bytes()[..], s].concat();
    put(
        &mut pg,
        &mut eng,
        "10000000001.00000000",
        Some((b"scrub_tag", &enc(b"t1"))),
    );
    put(
        &mut pg,
        &mut eng,
        "10000000002.00000000",
        Some((b"scrub_tag", &enc(b"t2"))),
    );
    put(&mut pg, &mut eng, "10000000003.00000001", None);
    let mut list = |op: OsdOp| -> Vec<Vec<u8>> {
        let mut o = mk("", vec![op]);
        o.flags = mflag::READ | mflag::ONDISK;
        tid += 1;
        let r = go(&mut pg, &mut eng, tid, o);
        assert!(r.result >= 0, "result {}", r.result);
        let resp: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
        let mut v: Vec<Vec<u8>> = resp.entries.into_iter().map(|e| e.oid).collect();
        v.sort();
        v
    };
    // raw key of user xattr `k` is `_k`
    let got = list(pgnls_filter_op(b"plain", |e| {
        e.bytes(b"_k").unwrap();
        e.bytes(b"yes").unwrap();
    }));
    assert_eq!(got, vec![b"a".to_vec()]);
    let got = list(pgnls_filter_op(b"hello.hello", |e| {
        e.bytes(b"_k").unwrap();
        e.bytes(b"no").unwrap();
    }));
    assert_eq!(got, vec![b"b".to_vec()]);
    // empty attribute name + empty value keeps everything
    assert_eq!(
        list(pgnls_filter_op(b"plain", |e| {
            e.bytes(b"").unwrap();
            e.bytes(b"").unwrap();
        }))
        .len(),
        7
    );
    let tag = |t: &[u8]| {
        pgnls_filter_op(b"cephfs.inode_tag", |e| {
            e.versioned(1, 1, |e| e.bytes(t)).unwrap();
        })
    };
    assert_eq!(list(tag(b"")).len(), 3);
    assert_eq!(
        list(tag(b"t1")),
        vec![
            b"10000000000.00000000".to_vec(),
            b"10000000002.00000000".to_vec()
        ]
    );
}

/// Run one PG-op message to its reply through refused runs (one store wake per refusal); returns the reply and the
/// number of wakes it needed.
fn pg_op_to_reply(pg: &mut TPg, eng: &mut Engine, tid: u64, op: OsdOp) -> (MOSDOpReply, u32) {
    let mut o = mk("", vec![op]);
    o.flags = mflag::READ | mflag::ONDISK;
    eng.on_op(pg, op_req(tid, o));
    let mut woken = 0;
    loop {
        let mut outs = settle(pg, eng);
        if let Some(r) = reply_of(&mut outs, 1, tid) {
            return (r, woken);
        }
        woken += 1;
        assert!(woken < 10_000, "never finished");
        eng.retry_woken(pg, &peering::wake::WakeSet::ALL);
    }
}

#[test]
fn pgnls_cold_listing_resumes_without_blocking_and_matches() {
    // adr 0021 S8: PGLS runs non-blocking; a run refused by a cold leaf (after it listed a batch) keeps its position and
    // continues there: every page equals the uninterrupted one and nothing is listed twice
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let n = 5_000u64;
    for i in 0..n {
        go(
            &mut pg,
            &mut eng,
            1 + i,
            mk(&format!("o{i:06}"), vec![OsdOp::create(false)]),
        );
    }
    let mut tid = 100_000;
    let mut page = |pg: &mut TPg, eng: &mut Engine, cursor: &Hobject| {
        tid += 1;
        pg_op_to_reply(pg, eng, tid, OsdOp::pgnls(1_000_000, cursor))
    };
    let (mut cursor, mut warm) = (Hobject::MIN(), Vec::new());
    loop {
        let (r, woken) = page(&mut pg, &mut eng, &cursor);
        assert_eq!(woken, 0);
        let resp: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
        cursor = resp.handle;
        warm.push(r);
        if warm.last().unwrap().result == 1 {
            break;
        }
    }
    pg.cold_list.set(u32::MAX);
    let (calls0, parked0) = (pg.list_calls.get(), eng.c.parked_scan);
    let (mut cursor, mut wakes, mut listed) = (Hobject::MIN(), 0, 0usize);
    for w in &warm {
        let (r, woken) = page(&mut pg, &mut eng, &cursor);
        wakes += woken;
        assert_eq!(r.result, w.result);
        assert_eq!(
            r.ops[0].outdata, w.ops[0].outdata,
            "page differs from the uninterrupted run"
        );
        let resp: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
        listed += resp.entries.len();
        cursor = resp.handle;
    }
    assert_eq!(listed as u64, n);
    assert!(wakes >= 15, "{wakes} refusals: not cold");
    assert_eq!(eng.c.parked_scan - parked0, u64::from(wakes));
    // per run one listed batch, then one refused call; the last run of a page lists and finishes
    assert!(pg.list_calls.get() - calls0 <= 2 * wakes + 2 * warm.len() as u32);
}

#[test]
fn reads_pass_a_refused_read_but_writes_and_the_reads_after_them_stay_behind() {
    // a cold listing page of a hot object must not hold any later read of that object, of another session or of its
    // own (they only read: either order gives the same replies, and replies of different ops are not ordered, spec
    // client-ops 5.5 / 5.7 step 9); a write of the object keeps its place behind the refused read, and a read after the
    // write waits for it (it sees the write, the read before it does not)
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = std::collections::BTreeMap::from([(b"k".to_vec(), b"v".to_vec())]);
    go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::omap_set_vals(&kv)]),
    );
    pg.cold_scan.set(1);
    eng.on_op(&mut pg, scan_req(10, "a"));
    assert!(
        settle(&mut pg, &mut eng).is_empty(),
        "replied on a refused read"
    );
    eng.on_op(&mut pg, op_req(13, mk("a", vec![OsdOp::stat()])));
    let mut other = op_req(11, mk("a", vec![OsdOp::stat()]));
    other.conn = 2;
    eng.on_op(&mut pg, other);
    let mut outs = settle(&mut pg, &mut eng);
    assert!(
        reply_of(&mut outs, 2, 11).is_some(),
        "another session's read waited behind a refused read"
    );
    assert!(
        reply_of(&mut outs, 1, 13).is_some(),
        "a read waited behind its own session's refused read"
    );
    let entries = pg.entries.len();
    eng.on_op(
        &mut pg,
        op_req(12, mk("a", vec![OsdOp::omap_set_vals(&kv1(b"k", b"w"))])),
    );
    eng.on_op(&mut pg, scan_req(14, "a"));
    let mut outs = settle(&mut pg, &mut eng);
    assert!(
        reply_of(&mut outs, 1, 12).is_none(),
        "a write overtook a refused read"
    );
    assert!(
        reply_of(&mut outs, 1, 14).is_none(),
        "a read overtook a write queued before it"
    );
    assert_eq!(pg.entries.len(), entries);
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    assert!(
        scan_saw(&mut outs, 10, b"v"),
        "the read saw the later write"
    );
    assert_eq!(reply_of(&mut outs, 1, 12).unwrap().result, 0);
    assert!(
        scan_saw(&mut outs, 14, b"w"),
        "the read after the write missed it"
    );
}

#[test]
fn refused_pgnls_is_not_starved_by_ops_regated_in_front_of_it() {
    // a PGLS refused by a cold leaf, then an object op refused again and again (re-gated at the front each time): the
    // listing already ran, so it is no longer ordered behind those later ops and finishes on its next wake
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    for i in 0..300u64 {
        go(
            &mut pg,
            &mut eng,
            1 + i,
            mk(&format!("o{i:04}"), vec![OsdOp::create(false)]),
        );
    }
    let kv = std::collections::BTreeMap::from([(b"k".to_vec(), b"v".to_vec())]);
    go(
        &mut pg,
        &mut eng,
        500,
        mk("x", vec![OsdOp::omap_set_vals(&kv)]),
    );
    pg.cold_list.set(1);
    let mut o = mk("", vec![OsdOp::pgnls(1000, &Hobject::MIN())]);
    o.flags = mflag::READ | mflag::ONDISK;
    eng.on_op(&mut pg, op_req(600, o));
    assert!(
        settle(&mut pg, &mut eng).is_empty(),
        "replied on a refused run"
    );
    pg.cold_scan.set(u32::MAX);
    eng.on_op(&mut pg, scan_req(601, "x"));
    let mut outs = settle(&mut pg, &mut eng);
    assert!(reply_of(&mut outs, 1, 601).is_none());
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    let r = reply_of(&mut outs, 1, 600).expect("the refused listing finished");
    assert!(r.result >= 0);
    assert!(
        reply_of(&mut outs, 1, 601).is_none(),
        "the cold op is still refused"
    );
    pg.cold_scan.set(0);
}

#[test]
fn pgnls_filter_with_cold_attributes_matches() {
    // a cold filter attribute refuses the run at that object (after asking for the next candidates' too); the re-run
    // continues at that object: same entries as with everything warm
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    for i in 0..300u64 {
        let mut ops = vec![OsdOp::create(false)];
        if i % 3 == 0 {
            ops.push(OsdOp::setxattr(b"k", b"yes"));
        }
        go(&mut pg, &mut eng, 1 + i, mk(&format!("o{i:04}"), ops));
    }
    let filter = || {
        pgnls_filter_op(b"plain", |e| {
            e.bytes(b"_k").unwrap();
            e.bytes(b"yes").unwrap();
        })
    };
    let (want, w0) = pg_op_to_reply(&mut pg, &mut eng, 1000, filter());
    assert_eq!(w0, 0);
    pg.cold_attr.set(500);
    let (r, woken) = pg_op_to_reply(&mut pg, &mut eng, 1001, filter());
    assert!(woken >= 5, "{woken} refusals");
    assert_eq!(r.result, want.result);
    assert_eq!(r.ops[0].outdata, want.ops[0].outdata);
    let resp: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert!(!resp.entries.is_empty());
}

fn opreq(tid: u64, oid: &str, ops: Vec<OsdOp>) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mk(oid, ops)),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

#[test]
fn partial_block_writes_probe_their_boundary_blocks_only() {
    let probes = |ops: Vec<OsdOp>| {
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        eng.on_op(&mut pg, opreq(1, "a", ops));
        pg.probes.borrow().clone()
    };
    // aligned: no read-modify-write, no probe
    assert!(probes(vec![OsdOp::write(4096, vec![1; 8192])]).is_empty());
    // unaligned head, tail in another block: both boundary blocks
    assert_eq!(
        probes(vec![OsdOp::write(100, vec![1; 5000])]),
        [(100, 1), (5099, 1)]
    );
    // head and tail in the same block: one probe
    assert_eq!(probes(vec![OsdOp::write(100, vec![1; 50])]), [(100, 1)]);
    // aligned start, partial tail
    assert_eq!(probes(vec![OsdOp::write(0, vec![1; 5000])]), [(4999, 1)]);
    assert_eq!(probes(vec![OsdOp::zero(10, 20)]), [(10, 1)]);
    assert_eq!(probes(vec![OsdOp::truncate(100)]), [(100, 1)]);
    assert!(probes(vec![OsdOp::truncate(8192)]).is_empty());
    // reads and cmpext probe their range (read-only ops: the merged range)
    assert_eq!(probes(vec![OsdOp::read(0, 4096)]), [(0, 4096)]);
    assert_eq!(probes(vec![OsdOp::cmpext(512, vec![0; 100])]), [(512, 100)]);
}

#[test]
fn a_write_parks_until_its_boundary_block_is_read_and_probes_both_blocks_at_once() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.cold_data.set(1000);
    eng.on_op(
        &mut pg,
        opreq(1, "a", vec![OsdOp::write(100, vec![7; 5000])]),
    );
    // head and tail submitted in the same pass (no short circuit after the first refusal)
    assert_eq!(pg.probes.borrow()[..2], [(100, 1), (5099, 1)]);
    assert!(settle(&mut pg, &mut eng).is_empty(), "parked");
    assert!(eng.has_parked());
    // a later op of the same object stays behind it
    eng.on_op(&mut pg, opreq(2, "a", vec![OsdOp::read(0, 100)]));
    assert!(settle(&mut pg, &mut eng).is_empty());
    // loads complete (no more refusals): the write runs first, then the read, in arrival order
    pg.cold_data.set(0);
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    assert!(!eng.has_parked());
}

#[test]
fn interval_change_while_parked_on_cold_data_requeues_the_op_and_runs_it_once() {
    // adr 0043 am. 4: an op parked on its data probe (boundary block / read range) when the interval changes stays
    // queued (same primary: the client does not resend), runs once the data is in, gets exactly one reply
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.cold_data.set(1000);
    eng.on_op(&mut pg, opreq(1, "a", vec![OsdOp::write(100, vec![7; 50])]));
    eng.on_op(&mut pg, opreq(2, "b", vec![OsdOp::read(0, 10)]));
    assert!(settle(&mut pg, &mut eng).is_empty(), "parked");
    eng.reset();
    assert!(eng.take_out().is_empty());
    assert!(eng.has_parked());
    // still cold after the new interval: parked again, nothing answered
    eng.retry(&mut pg);
    assert!(settle(&mut pg, &mut eng).is_empty());
    pg.cold_data.set(0);
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    assert_eq!(
        reply_of(&mut outs, 1, 2).unwrap().result,
        -2,
        "absent object: ENOENT, once"
    );
    assert!(reply_of(&mut outs, 1, 1).is_none(), "second reply");
    assert!(!eng.has_parked());
    eng.on_op(&mut pg, opreq(3, "a", vec![OsdOp::read(100, 50)]));
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(
        reply_of(&mut outs, 1, 3).unwrap().ops[0].outdata,
        vec![7u8; 50]
    );
}

#[test]
fn a_read_parked_on_cold_data_is_not_starved_by_later_writes() {
    // a read refused by its data probe (device read in flight, or the object's newest write not durable yet) keeps
    // its place: writes of the same object arriving later queue behind it, so its wait is bounded by what was
    // ahead of it, and it returns the content before them
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    eng.on_op(
        &mut pg,
        opreq(1, "a", vec![OsdOp::write(0, b"zz".to_vec())]),
    );
    assert_eq!(
        reply_of(&mut settle(&mut pg, &mut eng), 1, 1)
            .unwrap()
            .result,
        0
    );
    pg.cold_data.set(1000);
    eng.on_op(&mut pg, opreq(2, "a", vec![OsdOp::read(0, 2)]));
    for tid in 3..53 {
        eng.on_op(
            &mut pg,
            opreq(tid, "a", vec![OsdOp::write(0, b"ww".to_vec())]),
        );
    }
    assert!(
        settle(&mut pg, &mut eng).is_empty(),
        "the writes passed the parked read"
    );
    pg.cold_data.set(0);
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(
        reply_of(&mut outs, 1, 2).unwrap().ops[0].outdata,
        &b"zz"[..]
    );
    for tid in 3..53 {
        assert_eq!(reply_of(&mut outs, 1, tid).unwrap().result, 0);
    }
    assert!(!eng.has_parked());
}

#[test]
fn ec_pool_writes_issue_no_local_data_probes() {
    // EC: the local shard holds chunks, logical-offset probes would read blocks nothing consumes
    let mut pg = TPg::new();
    pg.ec = true;
    let mut eng = engine(&pg);
    eng.on_op(
        &mut pg,
        opreq(1, "a", vec![OsdOp::write(100, vec![1; 5000])]),
    );
    eng.on_op(&mut pg, opreq(2, "a", vec![OsdOp::truncate(100)]));
    assert!(pg.probes.borrow().is_empty(), "{:?}", pg.probes.borrow());
}

/// adr 0021 am. 30 / OQ 29: a name that needs the long-name index is accepted for WRITES only when every replica
/// stores it; reads of such an object and short names are never gated.
#[test]
fn long_name_write_needs_every_replica_to_store_it() {
    let long = "o".repeat(600);
    let w = |pg: &mut TPg, eng: &mut Engine, tid: u64, oid: &str| {
        go(pg, eng, tid, mk(oid, vec![OsdOp::write(0, b"x".to_vec())])).result
    };
    let mut pg = TPg::new();
    pg.max_item_key = 500;
    let mut eng = engine(&pg);
    // the primary's own store takes it, a replica does not: refused before any log entry
    pg.long_names = 1;
    assert_eq!(w(&mut pg, &mut eng, 1, &long), -errno::ENAMETOOLONG);
    assert!(pg.store.objects(pg.spg).is_empty(), "nothing applied");
    assert_eq!(
        w(&mut pg, &mut eng, 2, "short"),
        0,
        "short names unaffected"
    );
    // every member has the bit: accepted
    pg.long_names = 2;
    assert_eq!(w(&mut pg, &mut eng, 3, &long), 0);
    // a member without it joined: reads of the existing object still work, writes are refused
    pg.long_names = 1;
    let r = go(&mut pg, &mut eng, 4, mk(&long, vec![OsdOp::read(0, 1)]));
    assert_eq!(r.result, 0);
    assert_eq!(w(&mut pg, &mut eng, 5, &long), -errno::ENAMETOOLONG);
}

#[test]
fn warm_cache_skips_the_metadata_probe() {
    // the gate probes `Env::warm` only while the store reports page loads (adaptive, `Env::probe_meta`): a quiet cache runs
    // the op at once (a cold page then blocks inside the op, once), a loading one parks it as before
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let rq = |tid: u64, oid: &str| ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mk(oid, vec![OsdOp::write(0, b"A".to_vec())])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    pg.cold.set(1000);
    pg.quiet_cache = true;
    eng.on_op(&mut pg, rq(1, "a"));
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    assert!(!eng.has_parked(), "a quiet cache must not probe");
    assert_eq!(pg.cold.get(), 1000, "warm() was not asked");
    pg.quiet_cache = false;
    eng.on_op(&mut pg, rq(2, "b"));
    assert!(
        settle(&mut pg, &mut eng).is_empty(),
        "a loading cache parks"
    );
    assert!(eng.has_parked());
}

#[test]
fn a_cold_log_head_parks_writes_but_not_reads() {
    // `Env::warm_log` (adr 0021 am. 30): a write appends to the PG log, so its gate also probes the log head page; a read
    // never touches the log
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let wr = |tid: u64, oid: &str| ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mk(oid, vec![OsdOp::write(0, b"A".to_vec())])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    let rd = |tid: u64, oid: &str| ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mk(oid, vec![OsdOp::read(0, 1)])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    pg.cold_log.set(1000);
    eng.on_op(&mut pg, rd(1, "a"));
    let mut outs = settle(&mut pg, &mut eng);
    assert!(
        reply_of(&mut outs, 1, 1).is_some(),
        "a read does not wait for the log head"
    );
    eng.on_op(&mut pg, wr(2, "a"));
    assert!(
        settle(&mut pg, &mut eng).is_empty(),
        "a write parks on a cold log head"
    );
    assert!(eng.has_parked());
    pg.cold_log.set(0);
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    assert!(!eng.has_parked());
}

/// EC: a read queued behind a write (per-object waiters) was warmed before that write ran; the write's completion
/// dropped the decoded cache, so the read is warmed again at the gate instead of running cold (live: EIO on the
/// racing read of ceph_test_rados).
#[test]
fn ec_read_queued_behind_a_write_is_warmed_again() {
    let mut pg = TPg::new();
    pg.ec = true;
    pg.deferred = true;
    let mut eng = engine(&pg);
    eng.on_op(&mut pg, opreq(1, "a", vec![OsdOp::write(0, vec![1; 100])]));
    eng.on_op(&mut pg, opreq(2, "a", vec![OsdOp::read(0, 1)])); // warm now, waits for the write
    eng.on_op(&mut pg, opreq(3, "a", vec![OsdOp::write(0, vec![2; 10])])); // behind the read
    assert_eq!(pg.done.len(), 1, "only the first write submitted");
    pg.ec_cold.set(1); // the write's completion drops the cache
    let before = pg.ec_waits.get();
    let mut outs = settle(&mut pg, &mut eng);
    assert!(
        pg.ec_waits.get() > before,
        "read warmed again after the write"
    );
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    assert!(
        reply_of(&mut outs, 1, 2).is_none(),
        "read waits for its warm"
    );
    assert!(
        reply_of(&mut outs, 1, 3).is_none(),
        "later write stays behind the read"
    );
    assert!(eng.has_parked());
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    // (deferred test writes are never applied: the read answers from the empty store)
    assert!(
        reply_of(&mut outs, 1, 2).is_some(),
        "read ran after its warm"
    );
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, 0);
    assert!(!eng.has_parked());
}

/// EC: a read of an object missing on the primary's own shard parks; `Env::ec_wait` fills nothing while it is missing
/// (stale local size). Once recovered, the parked read is warmed at the gate before it runs (live, 20.2.4 release
/// smoke: ceph_test_rados EIO after an croit-flashstore-osd primary restart = cache miss of the recovered object).
#[test]
fn ec_read_parked_on_missing_object_is_warmed_after_recovery() {
    let mut pg = TPg::new();
    pg.ec = true;
    let mut eng = engine(&pg);
    eng.on_op(&mut pg, opreq(1, "a", vec![OsdOp::write(0, vec![1; 100])]));
    let _ = settle(&mut pg, &mut eng);
    pg.missing.insert(head("a"));
    eng.on_op(&mut pg, opreq(2, "a", vec![OsdOp::read(0, 100)]));
    assert!(
        settle(&mut pg, &mut eng).is_empty(),
        "read parks on the missing object"
    );
    assert!(eng.has_parked());
    // recovered: the decoded cache is cold
    pg.missing.clear();
    pg.ec_cold.set(1);
    let before = pg.ec_waits.get();
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert!(pg.ec_waits.get() > before, "parked read warmed again");
    assert!(
        reply_of(&mut outs, 1, 2).is_none(),
        "read waits for its warm"
    );
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    assert!(!eng.has_parked());
}

/// EC: copy-get (source of a copy-from) reads its chunk through the decoded cache: it is warmed like a read (live:
/// copy_from on EC pools answered EIO = cache miss).
#[test]
fn ec_copy_get_is_warmed() {
    let mut pg = TPg::new();
    pg.ec = true;
    let mut eng = engine(&pg);
    eng.on_op(&mut pg, opreq(1, "s", vec![OsdOp::write(0, vec![7; 300])]));
    let _ = settle(&mut pg, &mut eng);
    let cur = opwire::CopyCursor::default();
    pg.ec_cold.set(100);
    let before = pg.ec_waits.get();
    eng.on_op(
        &mut pg,
        opreq(2, "s", vec![OsdOp::copy_get_req(&cur, 1 << 20)]),
    );
    assert!(pg.ec_waits.get() > before, "copy-get warms the EC cache");
    let mut outs = settle(&mut pg, &mut eng);
    assert!(reply_of(&mut outs, 1, 2).is_none(), "parked until warm");
    pg.ec_cold.set(0);
    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
}

/// EC with omap (optimized pool, FLAG_OMAP): ops that read the omap or run a cls method wait at the gate for the
/// in-flight writes of their object (the stored omap lags the EC_OMAP records of those writes); omap writes pipeline.
#[test]
fn ec_omap_reads_and_cls_calls_wait_for_the_in_flight_writes() {
    let mut pg = TPg::new();
    pg.ec = true;
    pg.deferred = true;
    let mut eng = engine(&pg);
    let m = std::collections::BTreeMap::from([(b"k".to_vec(), b"v".to_vec())]);
    eng.on_op(&mut pg, opreq(1, "a", vec![OsdOp::omap_set_vals(&m)]));
    assert_eq!(pg.done.len(), 1);
    for (tid, op) in [
        (2, OsdOp::omap_get_vals(b"", 10, b"")),
        (3, OsdOp::omap_get_header()),
        (4, OsdOp::call(b"version", b"read", b"")),
    ] {
        // the EC write gate says "not yet" once (the op names its object's EC token: no probe until a wake), then
        // lets the op through
        pg.ec_cold.set(1);
        let before = pg.ec_waits.get();
        eng.on_op(&mut pg, opreq(tid, "a", vec![op]));
        assert!(pg.ec_waits.get() > before, "tid {tid} asked the EC gate");
        let mut outs = eng.take_out();
        assert!(reply_of(&mut outs, 1, tid).is_none(), "tid {tid} waits");
        // the write completes (or the shards answer): the op runs
        eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
        let mut outs = settle(&mut pg, &mut eng);
        assert!(reply_of(&mut outs, 1, tid).is_some(), "tid {tid} ran");
    }
    // an omap WRITE does not wait: it pipelines behind the first one
    pg.ec_cold.set(5);
    let n = pg.done.len();
    eng.on_op(&mut pg, opreq(5, "a", vec![OsdOp::omap_set_vals(&m)]));
    assert_eq!(pg.done.len(), n + 1, "omap write submitted at once");
}

#[test]
fn core_backpressure_parks_without_logging_or_using_cold_fallback() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.admission_paused = true;
    let req = ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid: 891,
        op: Box::new(mk("paused", vec![OsdOp::write(0, b"A".to_vec())])),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req);
    for _ in 0..1000 {
        eng.retry(&mut pg);
    }
    assert!(eng.has_parked());
    assert!(pg.entries.is_empty());
    assert!(pg.txns.is_empty());
    pg.admission_paused = false;
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert!(reply_of(&mut outs, 1, 891).is_some());
    assert_eq!(pg.entries.len(), 1);
}

#[test]
fn pg_plain_filter_raw_key_nul_prefix_and_binary_value_match_classic() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    for (index, (name, value)) in [
        ("binary", Some(vec![0, 255, 65])),
        ("empty", Some(vec![])),
        ("missing", None),
    ]
    .into_iter()
    .enumerate()
    {
        let mut ops = vec![OsdOp::create(false)];
        if let Some(value) = value {
            ops.push(OsdOp::setxattr(b"tag", &value));
        }
        assert_eq!(
            go(&mut pg, &mut eng, 2000 + index as u64, mk(name, ops)).result,
            0
        );
    }
    let object = pg
        .store
        .pgs
        .get_mut(&pg.spg)
        .unwrap()
        .objects
        .iter_mut()
        .find(|(h, _)| h.oid == b"binary")
        .unwrap()
        .1;
    object
        .xattrs
        .insert(b"_tag\0ignored".to_vec(), b"decoy".to_vec());
    {
        let mut tid = 2100;
        let mut listed = |ty: &[u8], key: &[u8], value: &[u8]| {
            let op = pgnls_filter_op(ty, |e| {
                e.bytes(key).unwrap();
                e.bytes(value).unwrap();
            });
            let mut req = mk("", vec![op]);
            req.flags = mflag::READ | mflag::ONDISK;
            tid += 1;
            let r = go(&mut pg, &mut eng, tid, req);
            assert!(r.result >= 0);
            let reply: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
            let mut names: Vec<_> = reply.entries.into_iter().map(|o| o.oid).collect();
            names.sort();
            names
        };
        for ty in [b"plain".as_slice(), b"hello.hello"] {
            assert_eq!(listed(ty, b"_tag", &[0, 255, 65]), vec![b"binary".to_vec()]);
            assert_eq!(
                listed(ty, b"_tag\0ignored", &[0, 255, 65]),
                vec![b"binary".to_vec()]
            );
            assert_eq!(listed(ty, b"_tag\0ignored", b""), vec![b"empty".to_vec()]);
            assert!(listed(ty, b"_tag\0ignored", b"decoy").is_empty());
            assert!(listed(ty, b"_absent\0_tag", b"").is_empty());
            assert!(listed(ty, b"\0ignored", b"").is_empty());
            assert_eq!(
                listed(ty, b"", b""),
                vec![b"binary".to_vec(), b"empty".to_vec(), b"missing".to_vec()]
            );
            assert!(listed(ty, b"", &[0]).is_empty());
        }
    }
    let object = pg
        .store
        .pgs
        .get_mut(&pg.spg)
        .unwrap()
        .objects
        .iter_mut()
        .find(|(h, _)| h.oid == b"binary")
        .unwrap()
        .1;
    object.xattrs.insert(vec![], b"literal".to_vec());
    for (i, (key, value, want)) in [
        (b"\0ignored".as_slice(), b"literal".as_slice(), 1),
        (b"".as_slice(), b"literal".as_slice(), 0),
        (b"\0ignored".as_slice(), b"".as_slice(), 0),
        (b"".as_slice(), b"".as_slice(), 3),
    ]
    .into_iter()
    .enumerate()
    {
        let op = pgnls_filter_op(b"plain", |e| {
            e.bytes(key).unwrap();
            e.bytes(value).unwrap();
        });
        let mut req = mk("", vec![op]);
        req.flags = mflag::READ | mflag::ONDISK;
        let r = go(&mut pg, &mut eng, 2200 + i as u64, req);
        assert!(r.result >= 0);
        let reply: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
        assert_eq!(reply.entries.len(), want);
        if want == 1 {
            assert_eq!(reply.entries[0].oid, b"binary");
        }
    }
}

/// Register watcher client.100 / 0xAA on "h" and let it time out (no pings).
fn watch_and_expire(pg: &mut TPg, eng: &mut Engine, tid: u64) {
    let mut o = run(
        pg,
        eng,
        11,
        tid,
        client(100),
        watch_msg("h", 0xAA, watch_op::WATCH),
    );
    assert_eq!(reply_of(&mut o, 11, tid).unwrap().result, 0);
    assert_eq!(state(pg, "h").0.watchers.len(), 1);
    pg.now += 40_000_000_000;
    let now = pg.now;
    eng.tick(pg, now);
}

/// The watch-timeout UNWATCH is internal: a PG that is not active (intake would BLOCK a client session) or a full gate
/// never drops it; it runs once the PG is active again.
#[test]
fn watch_timeout_unwatch_survives_a_blocked_pg() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(&mut pg, &mut eng, 1, mk("h", vec![OsdOp::create(false)]));
    let mut o = run(
        &mut pg,
        &mut eng,
        11,
        2,
        client(100),
        watch_msg("h", 0xAA, watch_op::WATCH),
    );
    assert_eq!(reply_of(&mut o, 11, 2).unwrap().result, 0);
    pg.active = false;
    pg.blocked = true;
    pg.now += 40_000_000_000;
    let now = pg.now;
    eng.tick(&mut pg, now);
    settle(&mut pg, &mut eng);
    assert_eq!(state(&pg, "h").0.watchers.len(), 1, "not active: waits");
    pg.active = true;
    pg.blocked = false;
    eng.retry(&mut pg);
    settle(&mut pg, &mut eng);
    assert!(state(&pg, "h").0.watchers.is_empty(), "unwatch ran");
}

/// Internal ops are logged with the empty reqid: a later engine (OSD restart, primary back) whose internal tids
/// restart must not find the earlier watch-timeout entry and answer its UNWATCH as a dup.
#[test]
fn watch_timeout_unwatch_is_never_a_dup() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(&mut pg, &mut eng, 1, mk("h", vec![OsdOp::create(false)]));
    watch_and_expire(&mut pg, &mut eng, 1);
    settle(&mut pg, &mut eng);
    assert!(state(&pg, "h").0.watchers.is_empty());
    assert_eq!(
        pg.entries.last().unwrap().reqid,
        denc::types::OsdReqId::default(),
        "internal op logged without reqid"
    );
    let mut eng = engine(&pg);
    watch_and_expire(&mut pg, &mut eng, 2);
    settle(&mut pg, &mut eng);
    assert!(
        state(&pg, "h").0.watchers.is_empty(),
        "second timeout executed"
    );
}

/// A listing during recovery is the PG's object set: objects missing on the primary are listed, objects whose
/// recovery is a delete (still in the local store) are not; paging over the merged set loses or repeats nothing.
#[test]
fn pgnls_lists_missing_and_hides_pending_deletes() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    for i in [0, 2, 4] {
        go(
            &mut pg,
            &mut eng,
            100 + i,
            mk(&format!("obj{i}"), vec![OsdOp::create(false)]),
        );
    }
    // obj1 / obj3 exist in the PG but not here yet; obj2 was deleted meanwhile (recovery deletes it here)
    pg.missing.insert(head("obj1"));
    pg.missing.insert(head("obj3"));
    pg.missing_del.insert(head("obj2"));
    for page in [2u64, 10] {
        let mut cursor = Hobject::MIN();
        let mut names = Vec::new();
        let mut tid = 200 + page * 100;
        loop {
            tid += 1;
            let mut o = mk("", vec![OsdOp::pgnls(page, &cursor)]);
            o.flags = mflag::READ | mflag::ONDISK;
            let r = go(&mut pg, &mut eng, tid, o);
            let resp: PgNlsResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
            names.extend(resp.entries.into_iter().map(|e| e.oid));
            if r.result == 1 {
                break;
            }
            cursor = resp.handle;
            assert!(tid < 200 + page * 100 + 20, "no progress");
        }
        names.sort();
        let want: Vec<Vec<u8>> = ["obj0", "obj1", "obj3", "obj4"]
            .iter()
            .map(|n| n.as_bytes().to_vec())
            .collect();
        assert_eq!(names, want, "page size {page}");
    }
}

/// omap get-by-keys on an object created earlier in the same message: rval 0 with an EMPTY MAP encoded (the
/// committed view has no object yet), never empty outdata (librados fails to decode that).
#[test]
fn omap_get_by_keys_on_object_created_in_the_message_returns_empty_map() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = std::collections::BTreeMap::from([(b"k".to_vec(), b"v".to_vec())]);
    let mut get = OsdOp::omap_rm_keys(&std::collections::BTreeSet::from([b"k".to_vec()]));
    get.op = opwire::consts::op::OMAP_GET_VALS_BY_KEYS;
    let mut m = mk(
        "fresh",
        vec![OsdOp::create(false), OsdOp::omap_set_vals(&kv), get],
    );
    m.flags |= mflag::RETURNVEC;
    let r = go(&mut pg, &mut eng, 1, m);
    assert_eq!(r.result, 0);
    assert_eq!(r.ops[2].rval, 0);
    let got: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
        denc::from_slice(&r.ops[2].outdata).expect("an encoded map");
    assert!(got.is_empty());
}

/// omap-cls F5: a class point read sees the message's working view, so after an `omap_clear` earlier in the same
/// message `numops.add` starts from 0 instead of the committed value.
#[test]
fn cls_point_read_sees_omap_clear_earlier_in_the_message() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = std::collections::BTreeMap::from([(b"x".to_vec(), b"5".to_vec())]);
    let r = go(
        &mut pg,
        &mut eng,
        1,
        mk("a", vec![OsdOp::omap_set_vals(&kv)]),
    );
    assert_eq!(r.result, 0);
    let mut e = denc::Encoder::new();
    e.bytes(b"x").unwrap();
    e.bytes(b"1").unwrap();
    let add = OsdOp::call(b"numops", b"add", &e.into_vec());
    let r = go(
        &mut pg,
        &mut eng,
        2,
        mk("a", vec![OsdOp::omap_clear(), add]),
    );
    assert_eq!(r.result, 0);
    let mut get = OsdOp::omap_rm_keys(&std::collections::BTreeSet::from([b"x".to_vec()]));
    get.op = opwire::consts::op::OMAP_GET_VALS_BY_KEYS;
    let mut m = mk("a", vec![get]);
    m.flags |= mflag::RETURNVEC;
    let r = go(&mut pg, &mut eng, 3, m);
    assert_eq!(r.result, 0);
    let got: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
        denc::from_slice(&r.ops[0].outdata).expect("an encoded map");
    assert_eq!(
        got.get(b"x".as_slice()).map(Vec::as_slice),
        Some(b"1".as_slice())
    );
}

/// Sibling of omap-cls F5: `delete` keeps the omap flag, so a listing later in the same message still sees the
/// committed omap (classic; golden 35_vis_cls pins the cls point read); `omap_clear` hides it.
#[test]
fn omap_listing_after_delete_sees_committed_omap_after_clear_none() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let kv = std::collections::BTreeMap::from([(b"x".to_vec(), b"5".to_vec())]);
    for (tid, oid) in [(1, "d"), (2, "c")] {
        let r = go(
            &mut pg,
            &mut eng,
            tid,
            mk(oid, vec![OsdOp::omap_set_vals(&kv)]),
        );
        assert_eq!(r.result, 0);
    }
    for (tid, oid, first, want) in [
        (3, "d", OsdOp::delete(), 1usize),
        (4, "c", OsdOp::omap_clear(), 0),
    ] {
        let mut m = mk(oid, vec![first, OsdOp::omap_get_vals(b"", 10, b"")]);
        m.flags |= mflag::RETURNVEC;
        let r = go(&mut pg, &mut eng, tid, m);
        assert_eq!(r.result, 0, "{oid}");
        let mut d = denc::Decoder::new(&r.ops[1].outdata);
        let got =
            <std::collections::BTreeMap<Vec<u8>, Vec<u8>> as denc::Decode>::decode(&mut d).unwrap();
        assert_eq!(got.len(), want, "{oid}");
    }
}

#[test]
fn notify_ack_is_scoped_to_its_object() {
    for legacy in [false, true] {
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        go(
            &mut pg,
            &mut eng,
            1,
            mk("watched", vec![OsdOp::create(false)]),
        );
        go(
            &mut pg,
            &mut eng,
            2,
            mk("other", vec![OsdOp::create(false)]),
        );
        let mut outs = run(
            &mut pg,
            &mut eng,
            11,
            1,
            client(100),
            watch_msg("watched", 0xAA, watch_op::WATCH),
        );
        assert_eq!(reply_of(&mut outs, 11, 1).unwrap().result, 0);
        let mut outs = run(
            &mut pg,
            &mut eng,
            13,
            1,
            client(102),
            mk("watched", vec![OsdOp::notify_op(0x77, 5, b"payload")]),
        );
        let rep = reply_of(&mut outs, 13, 1).unwrap();
        let id = u64::from_le_bytes(rep.ops[0].outdata[..8].try_into().unwrap());
        let ack = || {
            if legacy {
                let mut op = OsdOp::new(opwire::op::NOTIFY_ACK);
                op.u[..8].copy_from_slice(&id.to_le_bytes());
                op
            } else {
                OsdOp::notify_ack(id, 0xAA, b"reply")
            }
        };
        let mut outs = run(
            &mut pg,
            &mut eng,
            11,
            2,
            client(100),
            mk("other", vec![ack()]),
        );
        assert_eq!(reply_of(&mut outs, 11, 2).unwrap().result, 0);
        assert!(
            notifies(&outs).is_empty(),
            "wrong-object ACK completed notify (legacy={legacy})"
        );
        let mut outs = run(
            &mut pg,
            &mut eng,
            11,
            3,
            client(100),
            mk("watched", vec![ack()]),
        );
        assert_eq!(reply_of(&mut outs, 11, 3).unwrap().result, 0);
        assert_eq!(notifies(&outs).len(), 1);
        assert_eq!(notifies(&outs)[0].1, nop::NOTIFY_COMPLETE);
    }
}

#[test]
fn notify_expiry_reports_its_timeout() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "watch_notify_ack_and_timeouts", "--nocapture"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "timeout scenario failed: {output:?}"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("WARNING TIMEOUT notify exceeded 2s (")
            && stderr.contains("notify_id=")
            && stderr.contains("object=")
            && stderr.contains("pending=2"),
        "missing notify timeout context: {stderr}"
    );
    assert_eq!(stderr.matches("WARNING TIMEOUT").count(), 1);
}
