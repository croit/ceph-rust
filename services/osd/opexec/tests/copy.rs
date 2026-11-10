// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! copy-from / copy-from2 / copy-get (spec copy.md): same-PG loopback, cross-PG routing, chunking, ordering, failures.
mod common;
use common::*;
use denc::types::{EntityAddr, EntityName, Hobject, ObjectLocator, SnapId};
use opexec::{ClientReq, Engine, Out};
use opwire::{CopyCursor, CopyData, MOSDOp, MOSDOpReply, OsdOp, errno, op as code};
use replwire::ObjectInfo;
use std::collections::BTreeMap;

fn oloc(pool: u64) -> ObjectLocator {
    ObjectLocator {
        pool: pool as i64,
        key: vec![],
        nspace: vec![],
        hash: -1,
    }
}

fn head(pool: u64, oid: &str) -> Hobject {
    let mut h = Hobject::new(
        oid.as_bytes(),
        SnapId::NOSNAP,
        0x1234_5678,
        pool as i64,
        b"",
    );
    h.set_key(b"");
    h
}

fn go(pg: &mut TPg, eng: &mut Engine, tid: u64, op: MOSDOp) -> MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    reply_of(&mut outs, 1, tid).expect("reply")
}

fn copy_op(src: &str, pool: u64) -> OsdOp {
    OsdOp::copy_from_req(
        code::COPY_FROM2,
        src.as_bytes(),
        &oloc(pool),
        opwire::NOSNAP,
        0,
        0,
        None,
    )
}

fn cp(dst: &str, src: &str, pool: u64) -> MOSDOp {
    mkop_in(pool_of_dst(), dst.as_bytes(), vec![copy_op(src, pool)])
}

fn pool_of_dst() -> u64 {
    POOL
}

fn kv(k: &str, v: &str) -> OsdOp {
    OsdOp::omap_set_vals(&BTreeMap::from([(
        k.as_bytes().to_vec(),
        v.as_bytes().to_vec(),
    )]))
}

/// Source "s" in pool 1: data, xattr, omap + header.
fn seed(pg: &mut TPg, eng: &mut Engine) {
    let r = go(
        pg,
        eng,
        1,
        mkop(
            b"s",
            vec![
                OsdOp::write(0, b"hello world".to_vec()),
                OsdOp::setxattr(b"color", b"red"),
                kv("k1", "v1"),
                kv("k2", "v2"),
                OsdOp::omap_set_header(b"HDR".to_vec()),
            ],
        ),
    );
    assert_eq!(r.result, 0);
}

fn obj(pg: &TPg, oid: &str) -> peering::store::MemObj {
    pg.store
        .objects(pg.spg)
        .get(&head(pg.spg.pgid.pool, oid))
        .cloned()
        .unwrap_or_else(|| panic!("{oid} missing"))
}

fn exists(pg: &TPg, oid: &str) -> bool {
    pg.store
        .objects(pg.spg)
        .contains_key(&head(pg.spg.pgid.pool, oid))
}

fn oi(pg: &TPg, oid: &str) -> ObjectInfo {
    denc::from_slice(obj(pg, oid).xattrs.get(b"_".as_slice()).expect("oi")).unwrap()
}

#[test]
fn same_pg_copy_replaces_destination() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    let n = pg.entries.len();
    let r = go(&mut pg, &mut eng, 2, cp("d", "s", POOL));
    assert_eq!(r.result, 0, "{r:?}");
    assert_eq!(pg.entries.len(), n + 1, "one log entry for the destination");
    let (s, d) = (obj(&pg, "s"), obj(&pg, "d"));
    assert_eq!(d.data, s.data);
    assert_eq!(d.xattrs.get(b"_color".as_slice()), Some(&b"red".to_vec()));
    assert_eq!(d.omap, s.omap);
    assert_eq!(d.omap_header, b"HDR");
    let (soi, doi) = (oi(&pg, "s"), oi(&pg, "d"));
    assert_eq!(doi.size, 11);
    assert_eq!(doi.mtime, soi.mtime, "mtime comes from the source");
    assert!(doi.is_omap());
    // classic finish_copyfrom: a pure copy-from gives the destination the SOURCE user_version (reply too)
    assert_eq!(doi.user_version, soi.user_version);
    assert_eq!(r.user_version, soi.user_version);
    assert_eq!(oi(&pg, "s"), soi, "source untouched");
}

#[test]
fn copy_over_existing_object_drops_old_content() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    let r = go(
        &mut pg,
        &mut eng,
        2,
        mkop(
            b"d",
            vec![
                OsdOp::write(0, b"a much longer old destination body".to_vec()),
                OsdOp::setxattr(b"old", b"x"),
                kv("oldkey", "x"),
            ],
        ),
    );
    assert_eq!(r.result, 0);
    assert_eq!(go(&mut pg, &mut eng, 3, cp("d", "s", POOL)).result, 0);
    let d = obj(&pg, "d");
    assert_eq!(d.data, b"hello world");
    assert!(!d.xattrs.contains_key(b"_old".as_slice()));
    assert!(!d.omap.contains_key(b"oldkey".as_slice()));
    assert_eq!(d.omap.len(), 2);
}

#[test]
fn copy_entry_replace_gated_by_require_osd_release() {
    // client-ops 16.5: copy-from over a live destination removes and recreates it -> REPLACE at umbrella+, MODIFY
    // before (a pre-umbrella peer would abort replaying a REPLACE entry).
    let mut pg = TPg::new();
    pg.release = cls::release::TENTACLE;
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    for (dst, rel, tid) in [
        ("d1", cls::release::TENTACLE, 10u64),
        ("d2", cls::release::UMBRELLA, 20),
    ] {
        pg.release = rel;
        assert_eq!(
            go(
                &mut pg,
                &mut eng,
                tid,
                mkop(dst.as_bytes(), vec![OsdOp::write(0, b"old".to_vec())])
            )
            .result,
            0
        );
        assert_eq!(go(&mut pg, &mut eng, tid + 1, cp(dst, "s", POOL)).result, 0);
        let want = if rel >= cls::release::UMBRELLA {
            pgwire::LogOp::REPLACE
        } else {
            pgwire::LogOp::MODIFY
        };
        assert_eq!(pg.entries.last().unwrap().op, want, "{dst}");
        assert_eq!(obj(&pg, dst).data, b"hello world");
    }
}

#[test]
fn copy_of_plain_object_clears_destination_omap_flag() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mkop(b"p", vec![OsdOp::write(0, b"plain".to_vec())]),
    );
    go(&mut pg, &mut eng, 2, mkop(b"d", vec![kv("a", "b")]));
    assert!(oi(&pg, "d").is_omap());
    assert_eq!(go(&mut pg, &mut eng, 3, cp("d", "p", POOL)).result, 0);
    assert!(!oi(&pg, "d").is_omap());
    assert!(obj(&pg, "d").omap.is_empty());
    assert_eq!(obj(&pg, "d").data, b"plain");
}

#[test]
fn copy_of_empty_object() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(&mut pg, &mut eng, 1, mkop(b"e", vec![OsdOp::create(false)]));
    assert_eq!(go(&mut pg, &mut eng, 2, cp("d", "e", POOL)).result, 0);
    assert_eq!(oi(&pg, "d").size, 0);
    assert!(obj(&pg, "d").data.is_empty());
}

#[test]
fn errors_leave_no_destination_and_local_errors_are_logged() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    let n = pg.entries.len();
    // missing source
    assert_eq!(
        go(&mut pg, &mut eng, 2, cp("d", "nope", POOL)).result,
        -errno::ENOENT
    );
    // unknown source pool
    assert_eq!(
        go(&mut pg, &mut eng, 3, cp("d", "s", 9)).result,
        -errno::ENOENT
    );
    // copy onto itself
    assert_eq!(
        go(&mut pg, &mut eng, 4, cp("s", "s", POOL)).result,
        -errno::EINVAL
    );
    // flag bits copy-from2 does not know
    let bad = OsdOp::copy_from_req(
        code::COPY_FROM2,
        b"s",
        &oloc(POOL),
        opwire::NOSNAP,
        0,
        0x80,
        None,
    );
    assert_eq!(
        go(&mut pg, &mut eng, 5, mkop(b"d", vec![bad])).result,
        -errno::EINVAL
    );
    // empty source name / garbage indata
    let mut g = copy_op("s", POOL);
    g.indata = vec![1, 2, 3].into();
    assert_eq!(
        go(&mut pg, &mut eng, 6, mkop(b"d", vec![g])).result,
        -errno::EINVAL
    );
    // two copy ops in one message
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            7,
            mkop(b"d", vec![copy_op("s", POOL), copy_op("s", POOL)])
        )
        .result,
        -errno::EINVAL
    );
    assert_eq!(
        pg.entries.len(),
        n + 3,
        "local validation failures are logged for replay"
    );
    assert!(!exists(&pg, "d"));
    assert!(eng.is_idle(), "nothing left blocked");
}

/// A failing guard prevents the later copy from starting, even if its source is missing.
#[test]
fn guards_before_copy_run_before_source_fetch() {
    for ec in [false, true] {
        let mut pg = TPg::new();
        pg.ec = ec;
        let mut eng = engine(&pg);
        seed(&mut pg, &mut eng);
        let before = obj(&pg, "s");
        for (tid, guard, expected) in [
            (2, OsdOp::create(true), -errno::EEXIST),
            (3, OsdOp::assert_version(0), -errno::EINVAL),
            (4, OsdOp::cmpext(0, b"wrong".to_vec()), -4095),
        ] {
            let r = go(
                &mut pg,
                &mut eng,
                tid,
                mkop(b"s", vec![guard, copy_op("missing", POOL)]),
            );
            assert_eq!(r.result, expected, "EC={ec}, tid={tid}");
            assert_eq!(r.ops[0].rval, expected);
            assert_eq!(r.ops[1].rval, 0, "copy never executed");
            assert_eq!(obj(&pg, "s").data, before.data);
        }
    }
}

#[test]
fn failing_copy_prefix_is_atomic_and_its_error_replays() {
    for ec in [false, true] {
        let mut pg = TPg::new();
        pg.ec = ec;
        let mut eng = engine(&pg);
        seed(&mut pg, &mut eng);
        let before = obj(&pg, "s");
        let uv = oi(&pg, "s").user_version;
        let request = mkop(
            b"s",
            vec![
                OsdOp::writefull(b"uncommitted".to_vec()),
                OsdOp::assert_version(uv + 1),
                copy_op("missing", POOL),
            ],
        );
        let r = go(&mut pg, &mut eng, 2, request.clone());
        assert_eq!(r.result, -errno::EOVERFLOW);
        assert_eq!(r.ops[1].rval, -errno::EOVERFLOW);
        assert_eq!(obj(&pg, "s").data, before.data);
        assert_eq!(oi(&pg, "s").user_version, uv);
        // A resend must retain the guard's error, even after its copy source appears.
        assert_eq!(
            go(
                &mut pg,
                &mut eng,
                3,
                mkop(b"missing", vec![OsdOp::writefull(b"source".to_vec())])
            )
            .result,
            0
        );
        let replay = go(&mut pg, &mut eng, 2, request);
        assert_eq!(replay.result, -errno::EOVERFLOW);
        assert_eq!(replay.ops[1].rval, -errno::EOVERFLOW);
        assert_eq!(obj(&pg, "s").data, before.data);
        assert_eq!(oi(&pg, "s").user_version, uv);
    }
}

#[test]
fn local_copy_validation_respects_failok() {
    for ec in [false, true] {
        let mut pg = TPg::new();
        pg.ec = ec;
        let mut eng = engine(&pg);
        let mut flags = copy_op("missing", POOL);
        let mut cf = flags.copy_from();
        cf.flags = 0x80;
        flags.set_copy_from(cf);
        let mut malformed = copy_op("missing", POOL);
        malformed.indata = vec![1, 2, 3].into();
        for (i, mut bad) in [flags, malformed, copy_op("d", POOL)]
            .into_iter()
            .enumerate()
        {
            bad.flags |= opwire::opflag::FAILOK;
            let mut request = mkop(b"d", vec![bad, OsdOp::writefull(vec![i as u8; i + 1])]);
            request.flags |= opwire::flag::RETURNVEC;
            let r = go(&mut pg, &mut eng, i as u64 + 1, request);
            assert_eq!(r.result, 0, "EC={ec}, case={i}");
            assert_eq!(r.ops[0].rval, -errno::EINVAL);
            assert_eq!(r.ops[1].rval, 0);
            assert_eq!(obj(&pg, "d").data, vec![i as u8; i + 1]);
        }
    }
}

#[test]
fn copy_self_check_uses_resolved_source_hash() {
    for ec in [false, true] {
        let mut pg = TPg::new();
        pg.ec = ec;
        let mut eng = engine(&pg);
        let mut source = mkop(b"d", vec![OsdOp::writefull(b"source".to_vec())]);
        source.hash = 0x2345_6789;
        assert_eq!(go(&mut pg, &mut eng, 1, source).result, 0);
        let mut loc = oloc(POOL);
        loc.hash = 0x2345_6789;
        let copy = OsdOp::copy_from_req(code::COPY_FROM2, b"d", &loc, opwire::NOSNAP, 0, 0, None);
        assert_eq!(go(&mut pg, &mut eng, 2, mkop(b"d", vec![copy])).result, 0);
        assert_eq!(obj(&pg, "d").data, b"source");
    }
}

#[test]
fn copy_is_atomic_with_the_rest_of_the_message() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    // a write before the copy and an xattr after it: all land in one entry, the copy replaces what came before
    let m = mkop(
        b"d",
        vec![
            OsdOp::write(0, b"zzzzzzzzzzzzzzzzzz".to_vec()),
            copy_op("s", POOL),
            OsdOp::setxattr(b"after", b"1"),
        ],
    );
    let n = pg.entries.len();
    assert_eq!(go(&mut pg, &mut eng, 2, m).result, 0);
    assert_eq!(pg.entries.len(), n + 1);
    let d = obj(&pg, "d");
    assert_eq!(d.data, b"hello world");
    assert_eq!(d.xattrs.get(b"_after".as_slice()), Some(&b"1".to_vec()));
    // other modifying ops in the message: the normal bump (classic finish_ctx with user_modify)
    assert!(oi(&pg, "d").user_version > oi(&pg, "s").user_version);
    // a failing op after the copy discards everything, the copy included
    let m = mkop(
        b"d2",
        vec![
            copy_op("s", POOL),
            OsdOp::cmpxattr(
                b"nope",
                b"x",
                opwire::consts::cmp::EQ,
                opwire::consts::cmp::MODE_STRING,
            ),
        ],
    );
    assert!(go(&mut pg, &mut eng, 3, m).result < 0);
    assert!(!exists(&pg, "d2"));
}

#[test]
fn resend_of_a_committed_copy_is_a_dup() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    let a = go(&mut pg, &mut eng, 2, cp("d", "s", POOL));
    let n = pg.entries.len();
    let b = go(&mut pg, &mut eng, 2, cp("d", "s", POOL));
    assert_eq!(pg.entries.len(), n, "no second copy");
    assert_eq!(b.replay_version, a.replay_version);
    assert!(eng.is_idle());
}

#[test]
fn chunked_copy_of_a_large_object_with_omap() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    // 20 MiB of data (5 chunks of 4 MiB) + 10 MiB of omap (more chunks)
    let body: Vec<u8> = (0..20u32 << 20).map(|i| (i % 251) as u8).collect();
    let mut ops = vec![OsdOp::write(0, body.clone()), OsdOp::setxattr(b"x", b"y")];
    let mut sets = BTreeMap::new();
    for i in 0..2500u32 {
        sets.insert(
            format!("key{i:06}").into_bytes(),
            vec![(i % 200) as u8; 4096],
        );
    }
    ops.push(OsdOp::omap_set_vals(&sets));
    assert_eq!(go(&mut pg, &mut eng, 1, mkop(b"big", ops)).result, 0);
    let r = go(&mut pg, &mut eng, 2, cp("big2", "big", POOL));
    assert_eq!(r.result, 0);
    let (s, d) = (obj(&pg, "big"), obj(&pg, "big2"));
    assert!(d.data == s.data, "data differs");
    assert!(d.omap == s.omap, "omap differs");
    assert_eq!(d.omap.len(), 2500);
}

#[test]
fn copy_get_chunks_follow_the_cursor() {
    // the source side alone: ask with small budgets and walk the cursor
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    let mut cur = CopyCursor::default();
    let (mut data, mut keys, mut hdr) = (Vec::new(), Vec::new(), Vec::new());
    let mut steps = 0;
    loop {
        let m = mkop(b"s", vec![OsdOp::copy_get_req(&cur, 5)]);
        let r = go(&mut pg, &mut eng, 10 + steps, m);
        assert_eq!(r.result, 0);
        let d: CopyData = denc::from_slice(&r.ops[0].outdata).unwrap();
        assert_eq!(d.size, 11);
        if !cur.attr_complete {
            assert_eq!(d.attrs.get(b"color".as_slice()), Some(&b"red".to_vec()));
        } else {
            assert!(d.attrs.is_empty());
        }
        data.extend_from_slice(&d.data);
        if !d.omap_header.is_empty() {
            hdr = d.omap_header.clone();
        }
        keys.extend(opwire::parse_omap_section(&d.omap_data).unwrap());
        cur = d.cursor;
        steps += 1;
        if cur.is_complete() {
            break;
        }
        assert!(steps < 20, "cursor does not advance");
    }
    assert_eq!(data, b"hello world");
    assert_eq!(hdr, b"HDR");
    assert_eq!(
        keys,
        vec![
            (b"k1".to_vec(), b"v1".to_vec()),
            (b"k2".to_vec(), b"v2".to_vec())
        ]
    );
    assert!(steps >= 3, "small budget must need several chunks");
    // missing object
    let r = go(
        &mut pg,
        &mut eng,
        99,
        mkop(
            b"zz",
            vec![OsdOp::copy_get_req(&CopyCursor::default(), 100)],
        ),
    );
    assert_eq!(r.result, -errno::ENOENT);
}

#[test]
fn source_read_waits_for_an_inflight_write_of_the_source() {
    // per-object ordering: the source read of a copy must not overtake a write to the source that is not yet durable
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    let req = |tid: u64, op: MOSDOp| ClientReq {
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
        req(
            2,
            mkop(b"s", vec![OsdOp::writefull(b"NEW CONTENT".to_vec())]),
        ),
    );
    eng.on_op(&mut pg, req(3, cp("d", "s", POOL)));
    assert!(
        !exists(&pg, "d"),
        "copy must not run before the write is durable"
    );
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, 0);
    assert_eq!(obj(&pg, "d").data, b"NEW CONTENT");
}

#[test]
fn destination_is_blocked_while_the_copy_runs() {
    let mut a = TPg::in_pool(1);
    let mut b = TPg::in_pool(2);
    a.remote = Some(b.spg);
    let (mut ea, mut eb) = (engine(&a), engine(&b));
    go(
        &mut b,
        &mut eb,
        1,
        mkop_in(2, b"s", vec![OsdOp::write(0, b"remote data".to_vec())]),
    );
    go(
        &mut a,
        &mut ea,
        1,
        mkop(b"d", vec![OsdOp::write(0, b"old".to_vec())]),
    );
    let req = |conn: u64, tid: u64, op: MOSDOp| ClientReq {
        placement_read: None,
        conn,
        caps: None,
        tid,
        op: Box::new(op),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    ea.on_op(&mut a, req(1, 10, cp("d", "s", 2)));
    let mut outs = settle(&mut a, &mut ea);
    let reads: Vec<(u64, Box<MOSDOp>)> = outs
        .iter()
        .filter_map(|o| match o {
            Out::CopyRead { step, op, .. } => Some((*step, op.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(reads.len(), 1, "one source read to the other PG");
    outs.clear();
    // a read and a write of the destination queue behind the running copy
    ea.on_op(&mut a, req(2, 11, mkop(b"d", vec![OsdOp::read(0, 100)])));
    ea.on_op(
        &mut a,
        req(3, 12, mkop(b"d", vec![OsdOp::append(b"+tail".to_vec())])),
    );
    let mut outs = settle(&mut a, &mut ea);
    assert!(reply_of(&mut outs, 2, 11).is_none() && reply_of(&mut outs, 3, 12).is_none());
    // the other PG answers the source read
    let (step, op) = reads.into_iter().next().unwrap();
    let mut bo = run(&mut b, &mut eb, 99, step, osd(0), *op);
    let rep = reply_of(&mut bo, 99, step).unwrap();
    ea.on_copy_reply(&mut a, step, Ok(rep));
    let mut outs = settle(&mut a, &mut ea);
    assert_eq!(reply_of(&mut outs, 1, 10).unwrap().result, 0);
    assert_eq!(
        reply_of(&mut outs, 2, 11).unwrap().ops[0].outdata,
        &b"remote data"[..]
    );
    assert_eq!(reply_of(&mut outs, 3, 12).unwrap().result, 0);
    assert_eq!(obj(&a, "d").data, b"remote data+tail");
    assert!(ea.is_idle());
}

fn osd(n: i64) -> EntityName {
    EntityName {
        ty: EntityName::OSD,
        num: n,
    }
}

/// Two PGs (pools 1 and 2) with their engines; source reads of pool 1 go to pool 2.
struct Two {
    a: TPg,
    ea: Engine,
    b: TPg,
    eb: Engine,
}

impl Two {
    fn new() -> Two {
        let mut a = TPg::in_pool(1);
        let b = TPg::in_pool(2);
        a.remote = Some(b.spg);
        let (ea, eb) = (engine(&a), engine(&b));
        Two { a, ea, b, eb }
    }

    /// Feed a client op into A and route every source read to B until A is quiet.
    fn send(&mut self, tid: u64, op: MOSDOp) -> Option<MOSDOpReply> {
        let mut outs = run(&mut self.a, &mut self.ea, 1, tid, client(7), op);
        self.route(&mut outs);
        reply_of(&mut outs, 1, tid)
    }

    fn route(&mut self, outs: &mut Vec<Out>) {
        while let Some(i) = outs.iter().position(|o| matches!(o, Out::CopyRead { .. })) {
            let Out::CopyRead { step, op, .. } = outs.remove(i) else {
                unreachable!()
            };
            let mut bo = run(&mut self.b, &mut self.eb, 99, step, osd(0), *op);
            let rep = reply_of(&mut bo, 99, step).expect("source reply");
            self.ea.on_copy_reply(&mut self.a, step, Ok(rep));
            outs.extend(settle(&mut self.a, &mut self.ea));
        }
    }
}

#[test]
fn cross_pg_copy_with_everything() {
    let mut t = Two::new();
    let body: Vec<u8> = (0..9u32 << 20).map(|i| (i % 253) as u8).collect();
    let r = run(
        &mut t.b,
        &mut t.eb,
        1,
        1,
        client(7),
        mkop_in(
            2,
            b"s",
            vec![
                OsdOp::write(0, body.clone()),
                OsdOp::setxattr(b"a", b"1"),
                OsdOp::setxattr(b"b", b"2"),
                kv("k", "v"),
                OsdOp::omap_set_header(b"H".to_vec()),
            ],
        ),
    );
    drop(r);
    let r = t.send(5, cp("d", "s", 2)).expect("reply");
    assert_eq!(r.result, 0);
    let (s, d) = (obj(&t.b, "s"), obj(&t.a, "d"));
    assert!(s.data == d.data && s.omap == d.omap);
    assert_eq!(d.omap_header, b"H");
    assert_eq!(d.xattrs.get(b"_a".as_slice()), Some(&b"1".to_vec()));
    assert_eq!(oi(&t.a, "d").mtime, oi(&t.b, "s").mtime);
    assert!(t.ea.is_idle());
}

#[test]
fn cross_pg_missing_source_and_failed_reads() {
    let mut t = Two::new();
    assert_eq!(
        t.send(1, cp("d", "ghost", 2)).unwrap().result,
        -errno::ENOENT
    );
    assert!(!exists(&t.a, "d"));
    // delivery failure of the source read: errno through, nothing written, destination released
    let mut outs = run(&mut t.a, &mut t.ea, 1, 2, client(7), cp("d", "s", 2));
    let Some(Out::CopyRead { step, .. }) = outs.pop() else {
        panic!("no source read")
    };
    t.ea.on_copy_reply(&mut t.a, step, Err(errno::EIO));
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, -errno::EIO);
    assert!(t.ea.is_idle());
    // a reply that is not a copy-get answer
    let mut outs = run(&mut t.a, &mut t.ea, 1, 3, client(7), cp("d", "s", 2));
    let Some(Out::CopyRead { step, op, .. }) = outs.pop() else {
        panic!("no source read")
    };
    let mut rep = MOSDOpReply::for_request(&op, 10);
    rep.ops[0].outdata = vec![1, 2, 3].into();
    t.ea.on_copy_reply(&mut t.a, step, Ok(rep));
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, -errno::EIO);
    assert!(!exists(&t.a, "d"));
}

#[test]
fn new_interval_restarts_a_running_copy() {
    let mut t = Two::new();
    run(
        &mut t.b,
        &mut t.eb,
        1,
        1,
        client(7),
        mkop_in(2, b"s", vec![OsdOp::write(0, b"xyz".to_vec())]),
    );
    let mut outs = run(&mut t.a, &mut t.ea, 1, 7, client(7), cp("d", "s", 2));
    let Some(Out::CopyRead { step: old, .. }) = outs.pop() else {
        panic!("no source read")
    };
    t.ea.reset();
    assert!(t.ea.has_parked(), "the copy request is re-queued");
    // the stale answer of the first attempt is ignored
    let mut outs = run(
        &mut t.b,
        &mut t.eb,
        99,
        1,
        osd(0),
        mkop_in(
            2,
            b"s",
            vec![OsdOp::copy_get_req(&CopyCursor::default(), 100)],
        ),
    );
    let rep = reply_of(&mut outs, 99, 1).unwrap();
    t.ea.on_copy_reply(&mut t.a, old, Ok(rep));
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert!(reply_of(&mut outs, 1, 7).is_none());
    // the PG is active again: the request runs from scratch
    t.ea.retry(&mut t.a);
    let mut outs = settle(&mut t.a, &mut t.ea);
    t.route(&mut outs);
    assert_eq!(reply_of(&mut outs, 1, 7).unwrap().result, 0);
    assert_eq!(obj(&t.a, "d").data, b"xyz");
}

#[test]
fn a_source_that_never_answers_times_out() {
    let mut t = Two::new();
    run(
        &mut t.b,
        &mut t.eb,
        1,
        1,
        client(7),
        mkop_in(2, b"s", vec![OsdOp::write(0, b"xyz".to_vec())]),
    );
    let mut outs = run(&mut t.a, &mut t.ea, 1, 7, client(7), cp("d", "s", 2));
    assert!(outs.iter().any(|o| matches!(o, Out::CopyRead { .. })));
    outs.clear();
    let now = t.a.now;
    t.ea.tick(&mut t.a, now + 10_000_000_000);
    assert!(
        reply_of(&mut settle(&mut t.a, &mut t.ea), 1, 7).is_none(),
        "still waiting"
    );
    t.ea.tick(&mut t.a, now + 130_000_000_000);
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(reply_of(&mut outs, 1, 7).unwrap().result, -errno::ETIMEDOUT);
    assert!(t.ea.is_idle());
}

#[test]
fn source_version_assertion() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    go(
        &mut pg,
        &mut eng,
        9,
        mkop(b"s", vec![OsdOp::append(b"!".to_vec())]),
    );
    let uv = oi(&pg, "s").user_version;
    let with = |v: u64| {
        mkop(
            b"d",
            vec![OsdOp::copy_from_req(
                code::COPY_FROM2,
                b"s",
                &oloc(POOL),
                opwire::NOSNAP,
                v,
                0,
                None,
            )],
        )
    };
    assert_eq!(go(&mut pg, &mut eng, 2, with(uv)).result, 0);
    // the source is newer than the caller thinks
    assert_eq!(
        go(&mut pg, &mut eng, 3, with(uv - 1)).result,
        -errno::ERANGE
    );
    assert_eq!(
        go(&mut pg, &mut eng, 4, with(uv + 5)).result,
        -errno::EOVERFLOW
    );
}

#[test]
fn copy_from2_truncate_seq_and_old_copy_from_ignore_it() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    let m = mkop(
        b"d",
        vec![OsdOp::copy_from_req(
            code::COPY_FROM2,
            b"s",
            &oloc(POOL),
            opwire::NOSNAP,
            0,
            0,
            Some((7, 4096)),
        )],
    );
    assert_eq!(go(&mut pg, &mut eng, 2, m).result, 0);
    let o = oi(&pg, "d");
    assert_eq!((o.truncate_seq, o.truncate_size), (7, 4096));
    // old copy-from: no truncate fields on the wire, the source's own (0, 0) are kept
    let m = mkop(
        b"d2",
        vec![OsdOp::copy_from_req(
            code::COPY_FROM,
            b"s",
            &oloc(POOL),
            opwire::NOSNAP,
            0,
            0,
            None,
        )],
    );
    assert_eq!(go(&mut pg, &mut eng, 3, m).result, 0);
    assert_eq!(oi(&pg, "d2").truncate_seq, 0);
}

#[test]
fn copy_from_a_snapshot_clone() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let with_snapc = |mut op: MOSDOp, seq: u64, snaps: &[u64]| {
        op.snap_seq = seq;
        op.snaps = snaps.to_vec();
        op
    };
    go(
        &mut pg,
        &mut eng,
        1,
        with_snapc(
            mkop(b"s", vec![OsdOp::write(0, b"version one".to_vec())]),
            0,
            &[],
        ),
    );
    // snap 3 exists: the next write clones "version one"
    go(
        &mut pg,
        &mut eng,
        2,
        with_snapc(
            mkop(b"s", vec![OsdOp::writefull(b"version two!".to_vec())]),
            3,
            &[3],
        ),
    );
    let from_snap = |snap: u64| {
        mkop(
            b"d",
            vec![OsdOp::copy_from_req(
                code::COPY_FROM2,
                b"s",
                &oloc(POOL),
                snap,
                0,
                0,
                None,
            )],
        )
    };
    assert_eq!(go(&mut pg, &mut eng, 3, from_snap(3)).result, 0);
    assert_eq!(obj(&pg, "d").data, b"version one");
    assert_eq!(
        go(&mut pg, &mut eng, 4, from_snap(opwire::NOSNAP)).result,
        0
    );
    assert_eq!(obj(&pg, "d").data, b"version two!");
    // a snap the object does not have
    assert_eq!(
        go(&mut pg, &mut eng, 5, from_snap(1)).result,
        -errno::ENOENT
    );
}

#[test]
fn copy_onto_an_object_with_clones_clones_first() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    go(
        &mut pg,
        &mut eng,
        2,
        mkop(b"d", vec![OsdOp::write(0, b"old dest".to_vec())]),
    );
    let mut m = cp("d", "s", POOL);
    m.snap_seq = 5;
    m.snaps = vec![5];
    assert_eq!(go(&mut pg, &mut eng, 3, m).result, 0);
    assert_eq!(obj(&pg, "d").data, b"hello world");
    let clone = pg
        .store
        .objects(pg.spg)
        .into_iter()
        .find(|(h, _)| h.oid == b"d" && h.snap == SnapId(5))
        .expect("clone of the old destination");
    assert_eq!(clone.1.data, b"old dest");
}

#[test]
fn full_pool_refuses_a_growing_copy_but_not_with_full_force() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed(&mut pg, &mut eng);
    pg.full = (true, false);
    // plain client: dropped without a reply (full.rs)
    let mut outs = run(&mut pg, &mut eng, 1, 2, client(7), cp("d", "s", POOL));
    assert!(reply_of(&mut outs, 1, 2).is_none());
    assert_eq!(eng.take_dropped().len(), 1);
    assert!(!exists(&pg, "d"));
    let mut m = cp("d", "s", POOL);
    m.flags |= opwire::flag::FULL_FORCE;
    assert_eq!(go(&mut pg, &mut eng, 3, m).result, 0);
}

fn creq(conn: u64, tid: u64, op: MOSDOp) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn,
        caps: None,
        tid,
        op: Box::new(op),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

/// Source reads `Out::CopyRead` in `outs` (taken out).
fn reads(outs: &mut Vec<Out>) -> Vec<(u64, Box<MOSDOp>)> {
    let mut v = Vec::new();
    outs.retain(|o| match o {
        Out::CopyRead { step, op, .. } => {
            v.push((*step, op.clone()));
            false
        }
        _ => true,
    });
    v
}

#[test]
fn a_queued_copy_that_cannot_start_releases_its_destination() {
    // regression: a copy over the per-PG cap that failed when it finally started kept its destination blocked
    let mut t = Two::new();
    run(
        &mut t.b,
        &mut t.eb,
        1,
        1,
        client(7),
        mkop_in(2, b"s", vec![OsdOp::write(0, b"xyz".to_vec())]),
    );
    let mut pend = Vec::new();
    for i in 0..16u64 {
        let d = format!("d{i}");
        t.ea.on_op(&mut t.a, creq(1, 100 + i, cp(&d, "s", 2)));
        pend.extend(reads(&mut settle(&mut t.a, &mut t.ea)));
    }
    assert_eq!(pend.len(), 16);
    // 17th copy: queued; its source pool does not exist, which only shows when it starts
    t.ea.on_op(&mut t.a, creq(1, 200, cp("x", "s", 77)));
    t.ea.on_op(
        &mut t.a,
        creq(1, 201, mkop(b"x", vec![OsdOp::write(0, b"w".to_vec())])),
    );
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert!(reply_of(&mut outs, 1, 200).is_none() && reply_of(&mut outs, 1, 201).is_none());
    // one running copy ends: the queued one starts, fails, and the write behind it runs
    let (step, op) = pend.remove(0);
    let mut bo = run(&mut t.b, &mut t.eb, 99, step, osd(0), *op);
    let rep = reply_of(&mut bo, 99, step).unwrap();
    t.ea.on_copy_reply(&mut t.a, step, Ok(rep));
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(reply_of(&mut outs, 1, 100).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 200).unwrap().result, -errno::ENOENT);
    assert_eq!(reply_of(&mut outs, 1, 201).unwrap().result, 0);
    assert_eq!(obj(&t.a, "x").data, b"w");
}

#[test]
fn copy_from_own_clone_does_not_wait_behind_the_ops_it_blocks() {
    // regression: the 2nd chunk read of the object's own clone queued behind a client op the copy blocked (deadlock
    // until the copy timeout)
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let one: Vec<u8> = (0..9u32 << 20).map(|i| (i % 251) as u8).collect();
    go(
        &mut pg,
        &mut eng,
        1,
        mkop(b"s", vec![OsdOp::write(0, one.clone())]),
    );
    let mut w = mkop(b"s", vec![OsdOp::writefull(b"two".to_vec())]);
    w.snap_seq = 3;
    w.snaps = vec![3];
    go(&mut pg, &mut eng, 2, w);
    // a write of the head is in flight, then the copy of clone 3 onto the head, then a reader
    eng.on_op(
        &mut pg,
        creq(1, 3, mkop(b"s", vec![OsdOp::append(b"!".to_vec())])),
    );
    let back = mkop(
        b"s",
        vec![OsdOp::copy_from_req(
            code::COPY_FROM2,
            b"s",
            &oloc(POOL),
            3,
            0,
            0,
            None,
        )],
    );
    eng.on_op(&mut pg, creq(1, 4, back));
    eng.on_op(&mut pg, creq(1, 5, mkop(b"s", vec![OsdOp::read(0, 16)])));
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 4).unwrap().result, 0);
    assert_eq!(
        reply_of(&mut outs, 1, 5).unwrap().ops[0].outdata,
        &one[..16]
    );
    assert_eq!(obj(&pg, "s").data, one);
    assert!(eng.is_idle());
}

#[test]
fn copies_wait_for_the_osd_wide_memory_budget() {
    let mut t = Two::new();
    let budget = opexec::engine::CopyBudget::new(12 << 20);
    t.ea.set_copy_budget(budget.clone());
    let body: Vec<u8> = (0..9u32 << 20).map(|i| (i % 249) as u8).collect();
    run(
        &mut t.b,
        &mut t.eb,
        1,
        1,
        client(7),
        mkop_in(2, b"s", vec![OsdOp::write(0, body.clone())]),
    );
    // the first copy reserves a chunk, the second does not fit and waits (no source read)
    t.ea.on_op(&mut t.a, creq(1, 10, cp("d1", "s", 2)));
    t.ea.on_op(&mut t.a, creq(1, 11, cp("d2", "s", 2)));
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(
        outs.iter()
            .filter(|o| matches!(o, Out::CopyRead { .. }))
            .count(),
        1
    );
    assert!(budget.used() > 0);
    // alone, the first may hold all of its 9 MiB (+ slack) although that is past the limit; when it ends the second runs
    t.route(&mut outs);
    assert_eq!(reply_of(&mut outs, 1, 10).unwrap().result, 0);
    assert_eq!(reply_of(&mut outs, 1, 11).unwrap().result, 0);
    assert_eq!(obj(&t.a, "d2").data, body);
    assert_eq!(budget.used(), 0, "every reservation is given back");
    assert_eq!(
        t.ea.c.copy_waits, 1,
        "the copy that queued for the OSD-wide budget is counted"
    );
    assert!(t.ea.is_idle());
}

#[test]
fn a_copy_waiting_for_budget_held_by_another_pg_retries_on_its_timer() {
    let mut t = Two::new();
    let budget = opexec::engine::CopyBudget::new(12 << 20);
    t.ea.set_copy_budget(budget.clone());
    // a second destination PG of the same OSD, same budget
    let mut c = TPg::in_pool(1);
    c.remote = Some(t.b.spg);
    let mut ec = engine(&c);
    ec.set_copy_budget(budget.clone());
    let body: Vec<u8> = (0..9u32 << 20).map(|i| (i % 247) as u8).collect();
    run(
        &mut t.b,
        &mut t.eb,
        1,
        1,
        client(7),
        mkop_in(2, b"s", vec![OsdOp::write(0, body.clone())]),
    );
    let mut outs = run(&mut t.a, &mut t.ea, 1, 10, client(7), cp("d", "s", 2));
    let mut a_reads = reads(&mut outs);
    assert_eq!(a_reads.len(), 1);
    // C reserves a chunk (8 + 8 <= 12 fails: A holds 8): waits
    let mut outs = run(&mut c, &mut ec, 1, 20, client(7), cp("e", "s", 2));
    assert!(reads(&mut outs).is_empty());
    let wake = ec.next_deadline().expect("budget retry timer");
    // A's copy completes and gives its memory back; C is not told, its timer brings it back
    let (step, op) = a_reads.remove(0);
    let mut bo = run(&mut t.b, &mut t.eb, 99, step, osd(0), *op);
    let rep = reply_of(&mut bo, 99, step).unwrap();
    t.ea.on_copy_reply(&mut t.a, step, Ok(rep));
    let mut outs = settle(&mut t.a, &mut t.ea);
    t.route(&mut outs);
    assert_eq!(reply_of(&mut outs, 1, 10).unwrap().result, 0);
    assert_eq!(budget.used(), 0);
    ec.tick(&mut c, wake);
    let mut outs = settle(&mut c, &mut ec);
    let r = reads(&mut outs);
    assert_eq!(r.len(), 1, "C started on its timer");
    // C pulls the 9 MiB object in two chunks
    let mut r = r;
    while let Some((step, op)) = r.pop() {
        let mut bo = run(&mut t.b, &mut t.eb, 99, step, osd(0), *op);
        let rep = reply_of(&mut bo, 99, step).unwrap();
        ec.on_copy_reply(&mut c, step, Ok(rep));
        outs.extend(settle(&mut c, &mut ec));
        r.extend(reads(&mut outs));
    }
    assert_eq!(reply_of(&mut outs, 1, 20).unwrap().result, 0);
    assert_eq!(obj(&c, "e").data, body);
    assert_eq!(budget.used(), 0);
}

// ---- staged copies (adr 0057 am. 1): sources bigger than one chunk go through a temp object

fn big_source(
    pg: &mut TPg,
    eng: &mut Engine,
    pool: u64,
    name: &[u8],
    mb: u32,
    keys: u32,
) -> Vec<u8> {
    let body: Vec<u8> = (0..mb << 20).map(|i| (i % 251) as u8).collect();
    let mut ops = vec![OsdOp::write(0, body.clone()), OsdOp::setxattr(b"x", b"y")];
    let mut sets = BTreeMap::new();
    for i in 0..keys {
        sets.insert(
            format!("key{i:06}").into_bytes(),
            vec![(i % 200) as u8; 4096],
        );
    }
    if keys > 0 {
        ops.push(OsdOp::omap_set_vals(&sets));
        ops.push(OsdOp::omap_set_header(b"HDR".to_vec()));
    }
    assert_eq!(go(pg, eng, 1, mkop_in(pool, name, ops)).result, 0);
    body
}

/// Virtual 1 ms source-read latency and 1 ms durable-write latency. Uses the real engine and
/// store model; event count/time bounded, no wall-clock sleeps or network.
fn timed_staged_copy() -> u64 {
    use denc::types::Eversion;
    enum Event {
        Read(u64, Box<MOSDOp>),
        Durable(u64, Eversion),
    }
    let mut t = Two::new();
    let body = big_source(&mut t.b, &mut t.eb, 2, b"s", 20, 0);
    t.ea.on_op(&mut t.a, creq(1, 10, cp("d", "s", 2)));
    let mut schedule: BTreeMap<u64, Vec<Event>> = BTreeMap::new();
    let mut now = 0;
    for _ in 0..100 {
        for out in t.ea.take_out() {
            match out {
                Out::CopyRead { step, op, .. } => schedule
                    .entry(now + 1)
                    .or_default()
                    .push(Event::Read(step, op)),
                Out::Reply {
                    conn: 1,
                    tid: 10,
                    reply,
                    ..
                } => {
                    assert_eq!(reply.result, 0);
                    assert_eq!(obj(&t.a, "d").data, body);
                    assert_eq!(t.a.store.temp_objects(t.a.spg), 0);
                    assert!(t.ea.is_idle());
                    return now;
                }
                _ => {}
            }
        }
        for (tid, version) in std::mem::take(&mut t.a.done) {
            schedule
                .entry(now + 1)
                .or_default()
                .push(Event::Durable(tid, version));
        }
        let (at, events) = schedule.pop_first().expect("copy must make progress");
        now = at;
        assert!(now <= 100, "virtual copy deadline");
        t.a.now = 1_000_000_000 + now * 1_000_000;
        t.b.now = t.a.now;
        for event in events {
            match event {
                Event::Read(step, op) => {
                    let mut outs = run(&mut t.b, &mut t.eb, 99, step, osd(0), *op);
                    let reply = reply_of(&mut outs, 99, step).unwrap();
                    t.ea.on_copy_reply(&mut t.a, step, Ok(reply));
                }
                Event::Durable(tid, version) => t.ea.on_write_done(&mut t.a, tid, version, 0),
            }
        }
    }
    panic!("copy event limit");
}

#[test]
#[ignore = "virtual copy-overlap microbenchmark, no devices"]
fn staged_copy_overlap_bench() {
    eprintln!(
        "staged_copy 20MiB virtual_ms={} (read=1ms write=1ms)",
        timed_staged_copy()
    );
}

#[test]
fn staged_copy_overlaps_read_latency_without_overlapping_chunk_writes() {
    assert_eq!(
        timed_staged_copy(),
        7,
        "five reads/writes must overlap, followed by durable rename"
    );
}

fn next_source_reply(t: &mut Two) -> (u64, MOSDOpReply) {
    let mut outs = t.ea.take_out();
    let mut pending = reads(&mut outs);
    assert_eq!(
        pending.len(),
        1,
        "exactly one source read may be outstanding"
    );
    let (step, op) = pending.remove(0);
    let mut source = run(&mut t.b, &mut t.eb, 99, step, osd(0), *op);
    (step, reply_of(&mut source, 99, step).unwrap())
}

#[test]
fn prefetched_chunk_waits_for_previous_durability_and_keeps_destination_atomic() {
    let mut t = Two::new();
    let body = big_source(&mut t.b, &mut t.eb, 2, b"s", 9, 0);
    go(
        &mut t.a,
        &mut t.ea,
        1,
        mkop(b"d", vec![OsdOp::write(0, b"old".to_vec())]),
    );
    let budget = opexec::engine::CopyBudget::new(8 << 20);
    t.ea.set_copy_budget(budget.clone());
    t.ea.on_op(&mut t.a, creq(1, 10, cp("d", "s", 2)));
    let (step, first) = next_source_reply(&mut t);
    t.ea.on_copy_reply(&mut t.a, step, Ok(first));
    let first_write = std::mem::take(&mut t.a.done);
    assert_eq!(first_write.len(), 1);
    let (step, second) = next_source_reply(&mut t);
    t.ea.on_copy_reply(&mut t.a, step, Ok(second));
    t.ea.on_copy_reply(&mut t.a, step, Err(errno::EIO)); // duplicate/late reply must be ignored
    assert!(
        t.a.done.is_empty(),
        "second chunk must not be written before the first is durable"
    );
    assert!(
        t.ea.take_out().is_empty(),
        "no third read or client reply while two chunks are outstanding"
    );
    assert_eq!(obj(&t.a, "d").data, b"old");
    assert_eq!(budget.used(), 8 << 20, "reservation remains two chunks");
    let (tid, version) = first_write[0];
    t.ea.on_write_done(&mut t.a, tid, version, 0);
    assert_eq!(
        t.a.done.len(),
        1,
        "second chunk begins only after the first durability barrier"
    );
    assert_eq!(obj(&t.a, "d").data, b"old");
    let mut outs = settle(&mut t.a, &mut t.ea);
    t.route(&mut outs);
    assert_eq!(reply_of(&mut outs, 1, 10).unwrap().result, 0);
    assert_eq!(obj(&t.a, "d").data, body);
    assert_eq!(t.a.store.temp_objects(t.a.spg), 0);
    assert_eq!(budget.used(), 0);
}

#[test]
fn prefetched_error_waits_for_durability_and_cleans_up() {
    let mut t = Two::new();
    big_source(&mut t.b, &mut t.eb, 2, b"s", 9, 0);
    t.ea.on_op(&mut t.a, creq(1, 10, cp("d", "s", 2)));
    let (step, first) = next_source_reply(&mut t);
    t.ea.on_copy_reply(&mut t.a, step, Ok(first));
    let first_write = std::mem::take(&mut t.a.done);
    let (step, _) = next_source_reply(&mut t);
    t.ea.on_copy_reply(&mut t.a, step, Err(errno::EIO));
    assert!(
        t.a.done.is_empty(),
        "cleanup cannot overtake the undurable write"
    );
    assert!(t.ea.take_out().is_empty());
    let (tid, version) = first_write[0];
    t.ea.on_write_done(&mut t.a, tid, version, 0);
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(reply_of(&mut outs, 1, 10).unwrap().result, -errno::EIO);
    assert!(!exists(&t.a, "d"));
    assert_eq!(t.a.store.temp_objects(t.a.spg), 0);
    assert!(t.ea.is_idle());
}

#[test]
fn resetting_with_a_prefetched_reply_drops_budget_and_ignores_late_completions() {
    let mut t = Two::new();
    big_source(&mut t.b, &mut t.eb, 2, b"s", 9, 0);
    let budget = opexec::engine::CopyBudget::new(8 << 20);
    t.ea.set_copy_budget(budget.clone());
    t.ea.on_op(&mut t.a, creq(1, 10, cp("d", "s", 2)));
    let (step, first) = next_source_reply(&mut t);
    t.ea.on_copy_reply(&mut t.a, step, Ok(first));
    let first_write = std::mem::take(&mut t.a.done);
    let (step, second) = next_source_reply(&mut t);
    t.ea.on_copy_reply(&mut t.a, step, Ok(second));
    t.ea.reset();
    assert_eq!(budget.used(), 0);
    let (tid, version) = first_write[0];
    t.ea.on_write_done(&mut t.a, tid, version, 0);
    t.ea.on_copy_reply(&mut t.a, step, Err(errno::EIO));
    assert!(t.a.done.is_empty());
    assert!(!exists(&t.a, "d"));
}

#[test]
fn a_copy_bigger_than_one_chunk_is_staged_and_stays_atomic() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let body = big_source(&mut pg, &mut eng, POOL, b"big", 20, 2500);
    // the store would refuse a single txn this big (20 MiB data + 10 MiB omap): chunk writes and the rename are small
    pg.max_txn = Some(12 << 20);
    let n = pg.entries.len();
    let r = go(&mut pg, &mut eng, 2, cp("big2", "big", POOL));
    assert_eq!(r.result, 0, "{r:?}");
    assert_eq!(pg.entries.len(), n + 1, "one log entry for the whole copy");
    assert_eq!(pg.entries.last().unwrap().soid, head(POOL, "big2"));
    let d = obj(&pg, "big2");
    assert!(d.data == body, "data");
    assert!(d.omap == obj(&pg, "big").omap, "omap");
    assert_eq!(d.omap_header, b"HDR");
    assert_eq!(d.xattrs.get(b"_x".as_slice()), Some(&b"y".to_vec()));
    assert!(oi(&pg, "big2").is_omap());
    assert_eq!(oi(&pg, "big2").size, 20 << 20);
    assert_eq!(
        pg.store.temp_objects(pg.spg),
        0,
        "the temp object was renamed"
    );
    assert!(eng.is_idle());
    // replacing an existing destination (with its own omap) leaves nothing of it
    let r = go(&mut pg, &mut eng, 3, cp("big2", "big", POOL));
    assert_eq!(r.result, 0);
    assert_eq!(obj(&pg, "big2").omap.len(), 2500);
    assert_eq!(pg.store.temp_objects(pg.spg), 0);
}

#[test]
fn a_staged_copy_without_omap_clears_the_omap_flag() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    big_source(&mut pg, &mut eng, POOL, b"big", 9, 0);
    go(&mut pg, &mut eng, 2, mkop(b"d", vec![kv("old", "1")]));
    assert_eq!(go(&mut pg, &mut eng, 3, cp("d", "big", POOL)).result, 0);
    assert!(obj(&pg, "d").omap.is_empty());
    assert!(!oi(&pg, "d").is_omap());
    assert_eq!(oi(&pg, "d").size, 9 << 20);
}

#[test]
fn a_failing_chunk_removes_the_temp_object_and_changes_nothing() {
    let mut t = Two::new();
    big_source(&mut t.b, &mut t.eb, 2, b"s", 20, 0);
    let n = t.a.entries.len();
    let mut outs = run(&mut t.a, &mut t.ea, 1, 2, client(7), cp("d", "s", 2));
    // chunk 1 arrives and is staged
    let Some(Out::CopyRead { step, op, .. }) = outs.pop() else {
        panic!("no source read")
    };
    let mut bo = run(&mut t.b, &mut t.eb, 99, step, osd(0), *op);
    let rep = reply_of(&mut bo, 99, step).expect("source reply");
    t.ea.on_copy_reply(&mut t.a, step, Ok(rep));
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(t.a.store.temp_objects(t.a.spg), 1, "first chunk staged");
    assert_eq!(t.a.entries.len(), n, "staging is not logged");
    // chunk 2 fails
    let Some(Out::CopyRead { step, .. }) = outs.pop() else {
        panic!("no second source read")
    };
    t.ea.on_copy_reply(&mut t.a, step, Err(errno::EIO));
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, -errno::EIO);
    assert_eq!(t.a.store.temp_objects(t.a.spg), 0, "temp object removed");
    assert!(!exists(&t.a, "d"));
    assert_eq!(t.a.entries.len(), n);
    assert!(t.ea.is_idle());
}

#[test]
fn a_shard_that_fills_during_a_staged_copy_fails_it_with_enospc_and_no_trace() {
    // parallel copies into one PG share one store shard: room runs out between two chunks of a running copy
    // (mixed lab case 12, 1-PG pool). ENOSPC to the client, the temp removed although the shard is full, no destination.
    let mut t = Two::new();
    big_source(&mut t.b, &mut t.eb, 2, b"s", 20, 0);
    let n = t.a.entries.len();
    let mut outs = run(&mut t.a, &mut t.ea, 1, 2, client(7), cp("d", "s", 2));
    let Some(Out::CopyRead { step, op, .. }) = outs.pop() else {
        panic!("no source read")
    };
    let mut bo = run(&mut t.b, &mut t.eb, 99, step, osd(0), *op);
    let rep = reply_of(&mut bo, 99, step).expect("source reply");
    t.ea.on_copy_reply(&mut t.a, step, Ok(rep));
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(t.a.store.temp_objects(t.a.spg), 1, "first chunk staged");
    t.a.room = false;
    let Some(Out::CopyRead { step, op, .. }) = outs.pop() else {
        panic!("no second source read")
    };
    let mut bo = run(&mut t.b, &mut t.eb, 99, step, osd(0), *op);
    let rep = reply_of(&mut bo, 99, step).expect("source reply");
    t.ea.on_copy_reply(&mut t.a, step, Ok(rep));
    let mut outs = settle(&mut t.a, &mut t.ea);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, -errno::ENOSPC);
    assert_eq!(t.a.store.temp_objects(t.a.spg), 0, "temp object removed");
    assert!(!exists(&t.a, "d"));
    assert_eq!(t.a.entries.len(), n, "nothing logged");
    assert!(t.ea.is_idle());
}

#[test]
fn a_digest_mismatch_after_staging_cleans_up() {
    // the source lies about its data digest on the last chunk: EIO, nothing left behind
    let mut t = Two::new();
    big_source(&mut t.b, &mut t.eb, 2, b"s", 20, 0);
    let mut outs = run(&mut t.a, &mut t.ea, 1, 2, client(7), cp("d", "s", 2));
    let mut last = 0;
    while let Some(i) = outs.iter().position(|o| matches!(o, Out::CopyRead { .. })) {
        let Out::CopyRead { step, op, .. } = outs.remove(i) else {
            unreachable!()
        };
        let mut bo = run(&mut t.b, &mut t.eb, 99, step, osd(0), *op);
        let mut rep = reply_of(&mut bo, 99, step).expect("source reply");
        let mut d: CopyData = denc::from_slice(&rep.ops.last().unwrap().outdata).unwrap();
        if d.cursor.is_complete() {
            d.flags |= opwire::COPY_FLAG_DATA_DIGEST;
            d.data_digest ^= 1;
            rep.ops.last_mut().unwrap().outdata = denc::to_vec(&d).unwrap().into();
            last += 1;
        }
        t.ea.on_copy_reply(&mut t.a, step, Ok(rep));
        outs.extend(settle(&mut t.a, &mut t.ea));
    }
    assert_eq!(last, 1);
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, -errno::EIO);
    assert_eq!(t.a.store.temp_objects(t.a.spg), 0);
    assert!(!exists(&t.a, "d"));
}

#[test]
fn a_message_that_fails_after_a_staged_copy_removes_the_temp_object() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    big_source(&mut pg, &mut eng, POOL, b"big", 12, 0);
    let m = mkop(
        b"d",
        vec![
            copy_op("big", POOL),
            OsdOp::cmpxattr(
                b"nope",
                b"x",
                opwire::consts::cmp::EQ,
                opwire::consts::cmp::MODE_STRING,
            ),
        ],
    );
    assert!(go(&mut pg, &mut eng, 2, m).result < 0);
    assert!(!exists(&pg, "d"));
    assert_eq!(pg.store.temp_objects(pg.spg), 0, "temp object removed");
    // the same message without the failing op still works afterwards
    assert_eq!(go(&mut pg, &mut eng, 3, cp("d", "big", POOL)).result, 0);
    assert_eq!(obj(&pg, "d").data.len(), 12 << 20);
}

#[test]
fn a_refused_temp_discard_is_counted() {
    // best effort (the next interval change clears the temp), but a store refusal must not be silent
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    big_source(&mut pg, &mut eng, POOL, b"big", 12, 0);
    pg.discard_blocks = 1;
    let m = mkop(
        b"d",
        vec![
            copy_op("big", POOL),
            OsdOp::cmpxattr(
                b"nope",
                b"x",
                opwire::consts::cmp::EQ,
                opwire::consts::cmp::MODE_STRING,
            ),
        ],
    );
    assert!(go(&mut pg, &mut eng, 2, m).result < 0);
    assert!(!exists(&pg, "d"));
    assert_eq!(
        pg.store.temp_objects(pg.spg),
        1,
        "the refused discard leaves the temp object"
    );
    assert_eq!(eng.c.copy_discard_errors, 1);
    // the engine keeps running: a later message does not trip over the leftover temp
    assert_eq!(go(&mut pg, &mut eng, 3, cp("d", "big", POOL)).result, 0);
    assert_eq!(eng.c.copy_discard_errors, 1);
}

#[test]
fn a_staged_copy_of_a_full_device_fails_with_enospc_before_writing_more() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    big_source(&mut pg, &mut eng, POOL, b"big", 12, 0);
    pg.room = false;
    let r = go(&mut pg, &mut eng, 2, cp("d", "big", POOL));
    // admission (write_room on the message) refuses first; either way: no object, no temp
    assert!(r.result < 0);
    assert!(!exists(&pg, "d"));
    assert_eq!(pg.store.temp_objects(pg.spg), 0);
}

#[test]
fn staged_copy_into_an_ec_pool_is_atomic_and_cleans_its_temp() {
    // Both staged and single-chunk paths preserve data and leave no temp.
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    big_source(&mut pg, &mut eng, POOL, b"big", 9, 0);
    go(
        &mut pg,
        &mut eng,
        2,
        mkop(b"small", vec![OsdOp::writefull(vec![3u8; 4096])]),
    );
    pg.ec = true;
    let n = pg.entries.len();
    let r = go(&mut pg, &mut eng, 3, cp("d", "big", POOL));
    assert_eq!(r.result, 0);
    assert_eq!(obj(&pg, "d").data, obj(&pg, "big").data);
    assert_eq!(pg.store.temp_objects(pg.spg), 0);
    assert_eq!(pg.entries.len(), n + 1);
    assert!(eng.is_idle());
    assert_eq!(go(&mut pg, &mut eng, 4, cp("d2", "small", POOL)).result, 0);
    assert_eq!(obj(&pg, "d2").data, vec![3u8; 4096]);
}

#[test]
fn a_received_copy_chunk_parks_before_preflight_while_the_shard_log_is_blocked() {
    let mut t = Two::new();
    big_source(&mut t.b, &mut t.eb, 2, b"s", 9, 0);
    let budget = opexec::engine::CopyBudget::new(8 << 20);
    t.ea.set_copy_budget(budget.clone());
    t.ea.on_op(&mut t.a, creq(1, 10, cp("d", "s", 2)));
    let (step, first) = next_source_reply(&mut t);
    t.a.cold_log.set(1_000_000);
    t.ea.on_copy_reply(&mut t.a, step, Ok(first));
    assert!(t.ea.has_parked(), "store wake must revisit this copy");
    assert!(
        t.a.done.is_empty(),
        "no staging or preflight before the shard FIFO clears"
    );
    assert!(
        t.ea.take_out().is_empty(),
        "no third chunk while input is retained"
    );
    assert_eq!(budget.used(), 8 << 20);
    t.a.cold_log.set(0);
    t.ea.retry(&mut t.a);
    assert_eq!(t.a.done.len(), 1);
    assert_eq!(reads(&mut t.ea.take_out()).len(), 1);
    t.ea.reset();
    assert_eq!(budget.used(), 0);
}

/// A chunk write the store's size check refuses while its pages load (`WriteErr::Blocked`, adr 0021 S8) is submitted
/// again after the store wake: the copy completes, no EAGAIN.
#[test]
fn a_blocked_chunk_write_is_submitted_again_after_the_wake() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let body = big_source(&mut pg, &mut eng, POOL, b"big", 9, 0);
    // more refusals than the engine passes of the copy's own message: it must wait for a wake
    pg.check_blocks = 4;
    let mut outs = run(&mut pg, &mut eng, 1, 2, client(7), cp("big2", "big", POOL));
    assert!(
        reply_of(&mut outs, 1, 2).is_none(),
        "the copy waits for the store"
    );
    let mut reply = None;
    for _ in 0..8 {
        eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
        let mut outs = settle(&mut pg, &mut eng);
        reply = reply_of(&mut outs, 1, 2);
        if reply.is_some() {
            break;
        }
    }
    assert_eq!(reply.expect("reply after the wakes").result, 0);
    assert_eq!(pg.check_blocks, 0);
    assert!(obj(&pg, "big2").data == body, "data");
    assert_eq!(pg.store.temp_objects(pg.spg), 0);
    assert!(eng.is_idle());
}
